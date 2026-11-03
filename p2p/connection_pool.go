// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package p2p

/* this file implements the connection pool manager, keeping a list of active connections etc
 * this will also ensure that a single IP is connected only once
 *
 */
import (
	"context"
	"fmt"
	"math"
	"net"
	"os"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/rpc2"
	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/transaction"
	"github.com/dustin/go-humanize"
	"github.com/go-logr/logr"
)

// any connection incoming/outgoing can only be in this state
//type Conn_State uint32

const (
	HANDSHAKE_PENDING uint32 = 0 // "Pending"
	IDLE                     = 1 // "Idle"
	ACTIVE                   = 2 // "Active"
)

const MAX_CLOCK_DATA_SET = 16

// This structure is used to do book keeping for the connection and keeps other DATA related to peer
// golang restricts 64 bit uint64/int atomic on a 64 bit boundary
// therefore all atomics are on the top, As suggested by Slixe
type Connection struct {
	// the counters below are read and written from many goroutines (rpc2 handlers, pings, broadcasts, the console);
	// typed atomics make every access atomic by construction (a plain read no longer compiles) and keep the 64-bit
	// ones 8-byte aligned on 32-bit targets (linux/arm7 is built by build_package.sh), whatever the field order
	Height                atomic.Int64  // last height sent by peer
	StableHeight          atomic.Int64  // last stable height
	TopoHeight            atomic.Int64  // topo height, current topo height, this is the only thing we require for syncing
	Pruned                int64         // till where chain has been pruned on this node (set once during the handshake)
	LastObjectRequestTime atomic.Int64  // when was the last item placed in object list
	Latency               atomic.Int64  // time.Duration, latency to this node when sending timed sync
	BytesIn               atomic.Uint64 // total bytes in
	BytesOut              atomic.Uint64 // total bytes out
	Top_Version           atomic.Uint64 // current hard fork version supported by peer
	Peer_ID               uint64        // Remote peer id
	ping_count            atomic.Int64  // pings may overlap (a slow one is still in flight when the next tick fires)
	clock_offset          atomic.Int64  // duration updated on every miniblock
	mbl_first             atomic.Uint64 // miniblocks this peer delivered to us FIRST (not yet known to our node)
	mbl_dup               atomic.Uint64 // miniblocks this peer delivered after another peer already had

	Port    uint32        // port advertised by other end as its server,if it's 0 server cannot accept connections
	State   atomic.Uint32 // state of the connection
	Syncing atomic.Int32  // denotes whether we are syncing and thus stop pinging

	Client  *rpc2.Client
	Conn    net.Conn // actual object to talk
	ConnTls net.Conn // tls layered conn

	StateHash crypto.Hash // statehash at the top

	Created time.Time // when was object created

	Incoming        bool     // is connection incoming or outgoing
	Addr            net.Addr // endpoint on the other end
	SyncNode        bool     // whether the peer has been added to command line as sync node
	ProtocolVersion string
	Tag             string // tag for the other end
	DaemonVersion   string
	Top_ID          crypto.Hash // top block id of the connection

	logger logr.Logger // connection specific logger

	Requested_Objects [][32]byte // currently unused as we sync up with a single peer at a time

	peer_sent_time     time.Time     // contains last time when peerlist was sent
	update_received_ns atomic.Int64  // last time an update was received, UnixNano; written by concurrent handlers
	ping_in_progress   atomic.Int32  // contains ping pending against this connection
	tx_fetch_failures  atomic.Int32  // consecutive transaction-only GetObject failures (see object_errors.go)
	tx_asked           tx_ask_set    // txids recently requested from this peer (tx_ask.go)
	tx_known           tx_known_set  // txids this peer announced to us; broadcast_Tx skips it for them (tx_known.go)
	inv_budget         inv_budget    // r22: announced-txid budget of NotifyINV (inv_budget.go)
	traffic            *conn_traffic // payload bytes read/written by the codec (traffic.go)

	clock_index   int
	clock_offsets [MAX_CLOCK_DATA_SET]time.Duration
	delays        [MAX_CLOCK_DATA_SET]time.Duration
	onceexit      sync.Once
	state_mu      sync.Mutex    // guards StateHash and the clock samples: update() runs on many goroutines at once
	heavy         chan struct{} // concurrency cap for heavy handlers (call.go)
	exited        atomic.Int32  // set by exit() before it leaves the pool (Connection_Add checks it)
	heavy_once    sync.Once

	Mutex sync.Mutex // used only by connection go routine
}

func Address(c *Connection) string {
	if c.Addr == nil {
		return ""
	}
	return ParseIPNoError(c.Addr.String())
}

func (c *Connection) exit() {
	defer globals.Recover(0)
	c.onceexit.Do(func() {
		// leave the pool first: upstream relied on the 5 s idle sweep (20 s threshold), so a dead connection kept
		// counting as connected — blocking redials to that IP and satisfying the --min-peers check — for up to ~25 s.
		// Remove only this exact connection (a newer one from the same IP must stay), and do it before the Close
		// calls, so a panic in one of them (recovered above) cannot leave the entry behind.
		c.exited.Store(1)
		connection_map.CompareAndDelete(Address(c), c) // atomic and identity-based
		c.ConnTls.Close()
		c.Conn.Close()
		c.Client.Close()
	})

}

// add connection to  map
func Connection_Delete(c *Connection) {
	connection_map.CompareAndDelete(Address(c), c) // this connection only, never a newer one for the same IP
}

func Connection_Pending_Clear() {
	connection_map.Range(func(k, value interface{}) bool {
		v := value.(*Connection)
		if v.State.Load() == HANDSHAKE_PENDING && time.Now().Sub(v.Created) > 10*time.Second { //and skip ourselves
			v.exit()
			v.logger.V(3).Info("Cleaning pending connection")
		}

		if time.Since(time.Unix(0, v.update_received_ns.Load())).Round(time.Second).Seconds() > 20 {
			v.exit()
			Connection_Delete(v)
			v.logger.V(1).Info("Purging connection due since idle")
		}

		if IsAddressInBanList(Address(v)) {
			v.exit()
			Connection_Delete(v)
			v.logger.V(1).Info("Purging connection due to ban list")
		}
		return true
	})
}

var connection_map sync.Map    // map[string]*Connection{}
var outbound_add_mu sync.Mutex // serialises the netgroup check with the insert for outgoing connections

// check whether an IP is in the map already
func IsAddressConnected(address string) bool {
	if _, ok := connection_map.Load(strings.TrimSpace(address)); ok {
		return true
	}
	return false
}

// add connection to  map, only if we are not connected already
// we also check for limits for incoming connections
// same ip max 8 ip ( considering NAT)
// same Peer ID   4
func Connection_Add(c *Connection) bool {
	if !c.Incoming && !c.SyncNode { // eclipse resistance: refuse an outgoing connection beyond the netgroup cap (diversity.go)
		outbound_add_mu.Lock()
		defer outbound_add_mu.Unlock()
		if outbound_group_full(Address(c), outbound_group_counts(time.Now(), c)) {
			metrics.Set.GetOrCreateCounter("p2p_outbound_netgroup_refused_total").Inc()
			c.logger.V(2).Info("outgoing connection refused: netgroup already has its share", "ip", Address(c), "netgroup", netgroup(Address(c)))
			defer_peer_after_diversity_refusal(Address(c), time.Now())
			c.exit()
			return false
		}
	}
	if dup, ok := connection_map.LoadOrStore(Address(c), c); !ok {
		if c.exited.Load() == 1 { // it exited before it was added (e.g. during the handshake): do not keep it
			connection_map.CompareAndDelete(Address(c), c)
			return false
		}
		c.Created = time.Now()
		c.logger.V(3).Info("IP address being added", "ip", c.Addr.String())
		return true
	} else {
		c.logger.V(3).Info("IP address already has one connection, exiting this connection", "ip", c.Addr.String(), "pre", dup.(*Connection).Addr.String())
		c.exit()
		return false
	}
}

// unique connection list
// since 2 nodes may be connected in both directions, we need to deliver new blocks/tx to only one
// thereby saving NW/computing costs
// we find duplicates using peer id
func UniqueConnections() map[uint64]*Connection {
	unique_map := map[uint64]*Connection{}
	connection_map.Range(func(k, value interface{}) bool {
		v := value.(*Connection)
		if v.State.Load() != HANDSHAKE_PENDING && GetPeerID() != v.Peer_ID { //and skip ourselves
			unique_map[v.Peer_ID] = v // map will automatically deduplicate/overwrite previous
		}
		return true
	})
	return unique_map
}

// this function has infinite loop to keep ping every few sec
func ping_loop() {
	connection_map.Range(func(k, value interface{}) bool {
		c := value.(*Connection)
		if c.State.Load() != HANDSHAKE_PENDING && GetPeerID() != c.Peer_ID /*&& c.ping_in_progress.Load() == 0*/ {
			if c.Syncing.Load() >= 1 {
				return true
			}
			go func() {
				defer globals.Recover(3)
				c.ping_in_progress.Add(1)
				defer c.ping_in_progress.Add(-1)

				var request, response Dummy
				fill_common(&request.Common) // fill common info

				if c.ping_count.Add(1)%10 == 1 {
					request.Common.PeerList = get_peer_list_specific(Address(c))
				}

				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				if err := c.Client.CallWithContext(ctx, "Peer.Ping", request, &response); err != nil {
					c.logger.V(2).Info("ping failed", "error", err.Error())
					c.exit()
					return
				}
				c.update(&response.Common) // update common information
			}()
		}
		return true
	})
}

// prints all the connection info to screen
func Connection_Print() {
	var clist []*Connection

	connection_map.Range(func(k, value interface{}) bool {
		v := value.(*Connection)
		clist = append(clist, v)
		return true
	})

	version, err := chain.ReadBlockSnapshotVersion(chain.Get_Top_ID())
	if err != nil {
		panic(err)
	}

	StateHash, err := chain.Load_Merkle_Hash(version)

	if err != nil {
		panic(err)
	}

	logger.Info("Connection info for peers", "count", len(clist), "our Statehash", StateHash)

	fmt.Printf("%-30s %-16s %-5s %-7s %-7s %-7s %23s %3s %5s %s %s %16s %16s\n", "Remote Addr", "PEER ID", "PORT", " State", "Latency", "Offset", "S/H/T", "DIR", "QUEUE", "     IN", "    OUT", "Version", "Statehash")

	// sort the list
	sort.Slice(clist, func(i, j int) bool { return clist[i].Addr.String() < clist[j].Addr.String() })

	our_topo_height := chain.Load_TOPO_HEIGHT()

	for i := range clist {

		// skip pending  handshakes and skip ourselves
		if clist[i].State.Load() == HANDSHAKE_PENDING || GetPeerID() == clist[i].Peer_ID {
			//	continue
		}

		dir := "OUT"
		if clist[i].Incoming {
			dir = "INC"
		}
		state := "PENDING"
		if clist[i].State.Load() == IDLE {
			state = "IDLE"
		} else if clist[i].State.Load() == ACTIVE {
			state = "ACTIVE"
		}

		version := clist[i].DaemonVersion

		if len(version) > 20 {
			version = version[:20]
		}

		tag := clist[i].Tag
		if len(tag) > 20 {
			tag = tag[:20]
		}

		var color_yellow = "\033[33m"
		var color_normal = "\033[0m"

		//if our_height is more than
		if our_topo_height > clist[i].TopoHeight.Load() {
			fmt.Print(color_yellow)
		}

		ctime := time.Now().Sub(clist[i].Created).Round(time.Second)

		hstring := fmt.Sprintf("%d/%d/%d", clist[i].StableHeight.Load(), clist[i].Height.Load(), clist[i].TopoHeight.Load())
		fmt.Printf("%-30s %16x %5d %7s %7s %7s %23s %s %5d %7s %7s     %16s %s %x\n", Address(clist[i])+" ("+ctime.String()+")", clist[i].Peer_ID, clist[i].Port, state, time.Duration(clist[i].Latency.Load()).Round(time.Millisecond).String(), time.Duration(clist[i].clock_offset.Load()).Round(time.Millisecond).String(), hstring, dir, 0, humanize.Bytes(clist[i].bytes_in()), humanize.Bytes(clist[i].bytes_out()), version, tag, clist[i].state_hash())

		fmt.Print(color_normal)
	}
	logger.Info("Connection info for peers", "count", len(clist), "our Statehash", StateHash)

}

// for continuos update on command line, get the maximum height of all peers
// show the average network status
func Best_Peer_Height() (best_height, best_topo_height int64) {

	var heights []uint64
	var topoheights []uint64

	connection_map.Range(func(k, value interface{}) bool {
		v := value.(*Connection)
		if v.State.Load() != HANDSHAKE_PENDING && GetPeerID() != v.Peer_ID { // same self filter as Peer_Count
			height := v.Height.Load()
			heights = append(heights, uint64(height))
			topoheights = append(topoheights, uint64(v.TopoHeight.Load()))
		}
		return true
	})

	best_height = int64(Median(heights))
	best_topo_height = int64(Median(topoheights))

	return
}

// this function return peer count which have successful handshake
func Peer_Count() (Count uint64) {
	connection_map.Range(func(k, value interface{}) bool {
		v := value.(*Connection)
		if v.State.Load() != HANDSHAKE_PENDING && GetPeerID() != v.Peer_ID {
			Count++
		}
		return true
	})
	return
}

// this returns count of peers in both directions
func Peer_Direction_Count() (Incoming uint64, Outgoing uint64) {
	connection_map.Range(func(k, value interface{}) bool {
		v := value.(*Connection)
		if v.State.Load() != HANDSHAKE_PENDING && GetPeerID() != v.Peer_ID {
			if v.Incoming {
				Incoming++
			} else {
				Outgoing++
			}
		}
		return true
	})
	return
}

func Broadcast_Block(cbl *block.Complete_Block, PeerID uint64) {
	Broadcast_Block_Coded(cbl, PeerID)
}

// broad cast a block to all connected peers in cut up in chunks with erasure coding
// we can only broadcast a block which is in our db
// this function is trigger from 2 points, one when we receive a unknown block which can be successfully added to chain
// second from the blockchain which has to relay locally  mined blocks as soon as possible
func Broadcast_Block_Coded(cbl *block.Complete_Block, PeerID uint64) { // if peerid is provided it is skipped
	broadcast_Block_Coded(cbl, PeerID, globals.Time().UTC().UnixMicro())
}

func broadcast_Block_Coded(cbl *block.Complete_Block, PeerID uint64, first_seen int64) {

	defer globals.Recover(3)

	/*if IsSyncing() { // if we are syncing, do NOT broadcast the block
		return
	}*/

	blid := cbl.Bl.GetHash()

	logger.V(1).Info("Will broadcast block", "blid", blid, "tx_count", len(cbl.Bl.Tx_hashes), "txs", len(cbl.Txs))

	hhash, chunk_count := convert_block_to_chunks(cbl, 16, 32)

	our_height := chain.Get_Height()
	// build the request once and dispatch it to all possible peers
	tries := 0
	count := 0
	unique_map := UniqueConnections()

	connections := sort_by_latency(unique_map)

	bw_factor, _ := strconv.Atoi(os.Getenv("BW_FACTOR"))
	if bw_factor < 1 {
		bw_factor = 1
	}

	for { // we must send all blocks atleast once, once we are done, break ut

		if len(connections) < 1 {
			globals.Logger.Error(nil, "we want to broadcast block, but donot have peers, most possibly block will go stale")
			return
		}
		for _, v := range connections {
			select {
			case <-Exit_Event:
				return
			default:
			}

			if tries > 1024 {
				return
			}
			tries++
			if v.State.Load() != HANDSHAKE_PENDING && PeerID != v.Peer_ID && v.Peer_ID != GetPeerID() { // skip pre-handshake connections

				// if the other end is > 2 blocks behind, do not broadcast block to him
				// this is an optimisation, since if the other end is syncing
				// every peer will keep on broadcasting and thus making it more lagging
				// due to overheads
				// if the other end is > 2 blocks forwards, do not broadcast block to him
				peer_height := v.Height.Load()
				if (our_height-peer_height) > 2 || (peer_height-our_height) > 2 {
					continue
				}

				if count > len(unique_map) && count > bw_factor*chunk_count { // every connected peer shuld get ateleast one chunk
					goto done
				}

				go func(connection *Connection, cid int) {
					defer globals.Recover(3)
					var peer_specific_list ObjectList

					var chunkid [32 + 1 + 32]byte
					copy(chunkid[:], blid[:])
					chunkid[32] = byte(cid % chunk_count)
					copy(chunkid[33:], hhash[:])
					peer_specific_list.Sent = first_seen
					peer_specific_list.Chunk_list = append(peer_specific_list.Chunk_list, chunkid)
					connection.logger.V(3).Info("Sending erasure coded chunk to peer ", "cid", cid)
					var dummy Dummy
					fill_common(&peer_specific_list.Common) // fill common info
					if err := connection.call("Peer.NotifyINV", peer_specific_list, &dummy); err != nil {
						return
					}
					connection.update(&dummy.Common) // update common information

				}(v, count)
				count++
			}
		}
	}

done:

	//rlog.Infof("Broadcasted block %s to %d peers", cbl.Bl.GetHash(), count)

}

// broad cast a block to all connected peers in cut up in chunks with erasure coding
// we can only broadcast a block which is in our db
// this function is triggerred from 2 points, one when we receive a unknown block which can be successfully added to chain
// second from the blockchain which has to relay locally  mined blocks as soon as possible
func broadcast_Chunk(chunk *Block_Chunk, PeerID uint64, first_seen int64) { // if peerid is provided it is skipped
	defer globals.Recover(3)

	our_height := chain.Get_Height()

	count := 0
	unique_map := UniqueConnections()

	hhash := chunk.HHash

	for _, v := range unique_map {
		select {
		case <-Exit_Event:
			return
		default:
		}
		if v.State.Load() != HANDSHAKE_PENDING && PeerID != v.Peer_ID && v.Peer_ID != GetPeerID() { // skip pre-handshake connections

			// if the other end is > 50 blocks behind, do not broadcast block to hime
			// this is an optimisation, since if the other end is syncing
			// every peer will keep on broadcasting and thus making it more lagging
			// due to overheads
			peer_height := v.Height.Load()
			if (our_height-peer_height) > 3 || (peer_height-our_height) > 3 {
				continue
			}

			count++

			go func(connection *Connection) {
				defer globals.Recover(3)
				var peer_specific_list ObjectList

				var chunkid [33 + 32]byte
				copy(chunkid[:], chunk.BLID[:])
				chunkid[32] = byte(chunk.CHUNK_ID)
				copy(chunkid[33:], hhash[:])
				peer_specific_list.Sent = first_seen

				peer_specific_list.Chunk_list = append(peer_specific_list.Chunk_list, chunkid)
				connection.logger.V(3).Info("Sending erasure coded chunk INV to peer ", "raw", fmt.Sprintf("%x", chunkid), "blid", fmt.Sprintf("%x", chunk.BLID), "cid", chunk.CHUNK_ID, "hhash", fmt.Sprintf("%x", hhash), "exists", nil != is_chunk_exist(hhash, uint8(chunk.CHUNK_ID)))
				var dummy Dummy
				fill_common(&peer_specific_list.Common) // fill common info
				if err := connection.call("Peer.NotifyINV", peer_specific_list, &dummy); err != nil {
					return
				}
				connection.update(&dummy.Common) // update common information
			}(v)

		}
	}
}

// broad cast a block to all connected peers
// we can only broadcast a block which is in our db
// this function is trigger from 2 points, one when we receive a unknown block which can be successfully added to chain
// second from the blockchain which has to relay locally  mined blocks as soon as possible
// miniblock_ack_metric names the per-peer send->reply histogram: own finds and relays are kept apart.
func miniblock_ack_metric(PeerID uint64) string {
	if PeerID == 0 {
		return `p2p_miniblock_send_ack_seconds{origin="own"}`
	}
	return `p2p_miniblock_send_ack_seconds{origin="relay"}`
}

// note_miniblock_delivery records whether this peer was the first to bring us a miniblock. Peers that are first
// most often sit closest to the miners whose nodes build blocks, so they are the paths our own miniblocks should
// keep (input for peer retention; exposed by MiniblockDeliveryStats).
func (c *Connection) note_miniblock_delivery(first bool) {
	if first {
		c.mbl_first.Add(1)
		metrics.Set.GetOrCreateCounter(`p2p_miniblock_deliveries_total{first="true"}`).Inc()
	} else {
		c.mbl_dup.Add(1)
		metrics.Set.GetOrCreateCounter(`p2p_miniblock_deliveries_total{first="false"}`).Inc()
	}
}

type MiniblockDeliveryStat struct {
	Addr    string
	First   uint64
	Total   uint64
	Latency time.Duration
}

// MiniblockDeliveryStats lists connected peers by how many miniblocks each delivered first, most first.
func MiniblockDeliveryStats() (out []MiniblockDeliveryStat) {
	for _, c := range UniqueConnections() {
		first, dup := c.mbl_first.Load(), c.mbl_dup.Load()
		out = append(out, MiniblockDeliveryStat{Addr: Address(c), First: first, Total: first + dup, Latency: time.Duration(c.Latency.Load())})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].First != out[j].First {
			return out[i].First > out[j].First
		}
		return out[i].Latency < out[j].Latency
	})
	return
}

// sort_by_latency returns the peers lowest latency first. Latency is rewritten by every update() while we sort, so
// each value is loaded once up front: a comparator that loads it live can see a peer's latency change mid-sort (an
// inconsistent ordering), and the Broadcast_Block comparator read it with no atomic load at all (a data race).
// Ties keep a stable but arbitrary order, as before (the input is a map).
func sort_by_latency(unique_map map[uint64]*Connection) []*Connection {
	s := latency_order{c: make([]*Connection, 0, len(unique_map)), l: make([]int64, 0, len(unique_map))}
	for _, v := range unique_map {
		s.c, s.l = append(s.c, v), append(s.l, v.Latency.Load())
	}
	sort.Stable(s) // a concrete sort.Interface: no reflection swapper (slices.SortStableFunc needs go.mod >= 1.18)
	return s.c
}

// latency_order sorts peers by latencies loaded once, before the sort starts
type latency_order struct {
	c []*Connection
	l []int64
}

func (s latency_order) Len() int           { return len(s.c) }
func (s latency_order) Less(i, j int) bool { return s.l[i] < s.l[j] }
func (s latency_order) Swap(i, j int) {
	s.c[i], s.c[j] = s.c[j], s.c[i]
	s.l[i], s.l[j] = s.l[j], s.l[i]
}

func Broadcast_MiniBlock(mbl block.MiniBlock, PeerID uint64) { // if peerid is provided it is skipped
	broadcast_MiniBlock(mbl, PeerID, globals.Time().UTC().UnixMicro())
}
func broadcast_MiniBlock(mbl block.MiniBlock, PeerID uint64, first_seen int64) { // if peerid is provided it is skipped

	defer globals.Recover(3)

	var peer_specific_block Objects
	peer_specific_block.MiniBlocks = append(peer_specific_block.MiniBlocks, mbl.Serialize())
	fill_common(&peer_specific_block.Common) // fill common info
	peer_specific_block.Sent = first_seen

	our_height := chain.Get_Height()
	// build the request once and dispatch it to all possible peers
	count := 0
	unique_map := UniqueConnections()

	// Dispatch to the LOWEST-LATENCY peers first. The miniblock is the reward-critical object:
	// it is orphaned (no reward) if it reaches the integrator that finds the final block AFTER
	// that block's first-9 normal-miniblock slots fill (arrival-order cap; no freshness gate).
	// Front-loading the fastest propagation paths minimises that orphan window. This mirrors
	// Broadcast_Block (already latency-sorted, line ~407). Order-only change: same peers, same
	// bytes, no consensus impact. Latency is written via atomic.StoreInt64 (common.go), read atomically.
	connections := sort_by_latency(unique_map)

	// our own share (PeerID 0): record when each peer has verified+inserted it (observability only)
	var acks *own_ack_tracker
	if PeerID == 0 {
		height := mbl.Height
		acks = new_own_ack_tracker(time.Now(), func(s ack_summary) { report_own_miniblock_broadcast(height, s) })
	}

	//connection.logger.V(4).Info("Sending mini block to peer ")

	for _, v := range connections {
		select {
		case <-Exit_Event:
			return
		default:
		}
		if v.State.Load() != HANDSHAKE_PENDING && PeerID != v.Peer_ID && v.Peer_ID != GetPeerID() { // skip pre-handshake connections

			// if the other end is > 50 blocks behind, do not broadcast block to hime
			// this is an optimisation, since if the other end is syncing
			// every peer will keep on broadcasting and thus making it more lagging
			// due to overheads
			peer_height := v.Height.Load()
			if (our_height - peer_height) > 25 {
				continue
			}

			count++
			go func(connection *Connection) {
				defer globals.Recover(3)

				start := time.Now()
				var dummy Dummy
				err := connection.call("Peer.NotifyMiniBlock", peer_specific_block, &dummy)
				if acks != nil {
					acks.done(err, time.Now())
				}
				if err != nil {
					return
				}
				// the reply comes after the peer has decoded, PoW-verified and inserted the miniblock and dispatched its
				// own relay, so this is our OUTBOUND delivery+acceptance time per peer, which the inbound
				// miniblock_propagation histogram cannot show. Own finds (PeerID 0) are the reward-critical series.
				metrics.Set.GetOrCreateHistogram(miniblock_ack_metric(PeerID)).Update(time.Since(start).Seconds())
				connection.update(&dummy.Common) // update common information
			}(v)
		}

	}
	if acks != nil {
		acks.launched(count)
	}
	//rlog.Infof("Broadcasted block %s to %d peers", cbl.Bl.GetHash(), count)
}

// broadcast a new transaction, return to how many peers the transaction has been broadcasted
// this function is trigger from 2 points, one when we receive a unknown tx
// second from the mempool which may want to relay local ot soon going to expire transactions

func Broadcast_Tx(tx *transaction.Transaction, PeerID uint64) (relayed_count int32) {
	track_announced_tx(tx, globals.Time()) // RPC-submitted; tracked exactly like relayed txs (tx_flow.go)
	return broadcast_Tx(tx, PeerID, globals.Time().UTC().UnixMicro())

}
func broadcast_Tx(tx *transaction.Transaction, PeerID uint64, sent int64) (relayed_count int32) {
	defer globals.Recover(3)

	var request ObjectList
	fill_common_skip_topoheight(&request.Common) // fill common info, but skip topo height
	txhash := tx.GetHash()

	request.Tx_list = append(request.Tx_list, txhash)
	request.Sent = sent

	our_height := chain.Get_Height()

	var conns []*Connection
	for _, v := range UniqueConnections() {
		conns = append(conns, v)
	}
	// handshaken peers within the height window (if we are lagging or the peer is lagging, do not broadcast
	// transactions), minus the peers that announced this tx to us: they hold it already (tx_known.go)
	targets, _ := tx_announce_targets(conns, txhash, PeerID, our_height, time.Now())

	for _, v := range targets {
		select {
		case <-Exit_Event:
			return
		default:
		}
		go func(connection *Connection) {
			defer func() {
				if r := recover(); r != nil {
					connection.logger.V(1).Error(nil, "Recovere3d while sending tx", "r", r, "stack", debug.Stack())
				}
			}()

			var dummy Dummy
			fill_common(&dummy.Common) // fill common info
			if err := connection.call("Peer.NotifyINV", request, &dummy); err != nil {
				return
			}
			connection.update(&dummy.Common) // update common information
			atomic.AddInt32(&relayed_count, 1)

		}(v)
	}
	if relayed_count > 0 {
		//rlog.Debugf("Broadcasted tx %s to %d peers", txhash, relayed_count)
	}
	return
}

// trigger a sync with a random peer
func trigger_sync() {
	defer globals.Recover(3)

	unique_map := UniqueConnections()

	var clist []*Connection

	for _, value := range unique_map {
		clist = append(clist, value)
	}

	// sort the list random
	// do random shuffling, can we get away with len/2 random shuffling
	globals.Global_Random.Shuffle(len(clist), func(i, j int) {
		clist[i], clist[j] = clist[j], clist[i]
	})

	for _, connection := range clist {

		height := chain.Get_Height()

		//connection.Lock()   recursive mutex are not suported
		// only choose highest available peers for syncing
		if connection.State.Load() != HANDSHAKE_PENDING && (height < connection.Height.Load() || (connection.SyncNode && height > (connection.Height.Load()+2))) { // skip pre-handshake connections
			// check whether we are lagging with this connection
			//connection.Lock()
			islagging := (height < connection.Height.Load() || (connection.SyncNode && height > (connection.Height.Load()+2)))

			//fmt.Printf("checking cdiff is lagging %+v  topoheight %d peer topoheight %d \n", islagging, topoheight, connection.TopoHeight)

			// islagging := true
			//connection.Unlock()
			if islagging {
				if connection.Pruned > chain.Load_Block_Topological_order(chain.Get_Top_ID()) && chain.Get_Height() != 0 {
					connection.logger.V(1).Info("We cannot resync with the peer, since peer chain is pruned", "height", connection.Height.Load(), "pruned", connection.Pruned)
					continue
				}

				time.Sleep(time.Second)
				height := chain.Get_Height()
				islagging = (height < connection.Height.Load() || (connection.SyncNode && height > (connection.Height.Load()+2)))

				if islagging {
					//connection.Lock()

					connection.logger.V(1).Info("We need to resync with the peer", "our_height", height, "height", connection.Height.Load(), "pruned", connection.Pruned)

					//connection.Unlock()
					// set mode to syncronising

					metrics.Set.GetOrCreateCounter("blockchain_sync_total").Inc() // tracks number of syncs

					if chain.Sync {
						//fmt.Printf("chain send chain request disabled\n")
						for round := 1; ; round++ { // one chain request covers at most ~512 blocks: keep going (sync_continue.go)
							before := chain.Get_Height()
							connection.sync_chain()
							connection.logger.V(1).Info("sync done")
							if !sync_should_continue(round, before, chain.Get_Height(), connection.Height.Load(), connection.exited.Load() == 1) {
								break
							}
							metrics.Set.GetOrCreateCounter("p2p_sync_continued_rounds_total").Inc()
						}

					} else { // we need a state only sync, bootstrap without history but verified chain
						if err := connection.bootstrap_chain(); err != nil {
							connection.bootstrap_fail(err)
						}
					}
					break
				}

			}
		}

	}
}

//go:noinline
func Abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

// detect whether we are behind any of the connected peers and trigger sync ASAP
// randomly with one of the peers

var single_sync int32

func syncroniser() {

	defer atomic.AddInt32(&single_sync, -1)

	if atomic.AddInt32(&single_sync, 1) != 1 {
		return
	}
	calculate_network_time() // calculate time every sec
	trigger_sync()           // check whether we are out of sync
}

// update P2P time
func calculate_network_time() {
	var total, count, mean int64
	unique_map := UniqueConnections()

	for _, v := range unique_map {
		if Abs(v.clock_offset.Load()) < 100*1000000000 { //  this is 100 sec
			total += v.clock_offset.Load()
			count++
		}
	}
	if count == 0 {
		return
	}
	mean = total / count
	total, count = 0, 0

	var total_float float64
	for _, v := range unique_map {
		if Abs(v.clock_offset.Load()) < 100*1000000000 { //  this is 100 sec
			total_float += math.Pow(float64(v.clock_offset.Load()-mean), 2)
			count++
		}
	}
	if count == 0 {
		return
	}

	variance := total_float / float64(count)
	std_deviation := int64(math.Trunc(math.Sqrt(variance)))

	//		fmt.Printf("\n1 mean %d std_deviation %d variance %f  total_float %f count %d",mean, std_deviation, variance, total_float,count)

	total, count = 0, 0
	for _, v := range unique_map {
		poffset := v.clock_offset.Load()
		if poffset >= (mean-std_deviation) && poffset <= (mean+std_deviation) {
			total += v.clock_offset.Load()
			count++
		}
	}
	//		fmt.Printf("\n2 mean %d std_deviation %d variance %f  total_float %f count %d totaloffset %d\n",mean, std_deviation, variance, total_float,count,total)

	if count == 0 {
		return
	}

	globals.SetClockOffsetP2P(time.Duration(total / count)) // atomic (r20)
}
