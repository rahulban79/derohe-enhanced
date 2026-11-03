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

/* this file implements the peer manager, keeping a list of peers which can be tried for connection etc
 *
 */
import "os"
import "fmt"

import "errors"
import "sync"
import "time"
import "sort"
import "path/filepath"
import "encoding/json"

//import "encoding/binary"
//import "container/list"

//import log "github.com/sirupsen/logrus"

import "github.com/deroproject/derohe/globals"

//import "github.com/deroproject/derosuite/crypto"

// This structure is used to do book keeping for the peer list and keeps other DATA related to peer
// all peers are servers, means they have exposed a port for connections
// all peers are identified by their endpoint tcp address
// all clients are identified by ther peer id ( however ip-address is used to control amount )
// the following daemon commands interact with the list
// peer_list := print the peer list
// ban address  time  // ban this address for spcific time
// unban address
// enableban address  // by default all addresses are bannable
// disableban address  // this address will never be banned
type Peer struct {
	Address string `json:"address"` // pairs in the ip:port or dns:port, basically  endpoint
	ID      uint64 `json:"peerid"`  // peer id
	Miner   bool   `json:"miner"`   // miner
	//NeverBlacklist    bool    // this address will never be blacklisted
	LastConnected   uint64 `json:"lastconnected"`   // epoch time when it was connected , 0 if never connected
	FailCount       uint64 `json:"failcount"`       // how many times have we failed  (tcp errors)
	ConnectAfter    uint64 `json:"connectafter"`    // we should connect when the following timestamp passes
	BlacklistBefore uint64 `json:"blacklistbefore"` // peer blacklisted till epoch , priority nodes are never blacklisted, 0 if not blacklist
	GoodCount       uint64 `json:"goodcount"`       // how many times peer has been shared with us
	Version         int    `json:"version"`         // version 1 is original C daemon peer, version 2 is golang p2p version
	Whitelist       bool   `json:"whitelist"`
	sync.Mutex
}

var peer_map = map[string]*Peer{}
var peer_mutex sync.Mutex

// loads peers list from disk
func load_peer_list() {
	defer clean_up()
	peer_mutex.Lock()
	defer peer_mutex.Unlock()

	peer_file := filepath.Join(globals.GetDataDirectory(), "peers.json")
	if _, err := os.Stat(peer_file); errors.Is(err, os.ErrNotExist) {
		return // since file doesn't exist , we cannot load it
	}
	file, err := os.Open(peer_file)
	if err != nil {
		logger.Error(err, "opening peer file")
	} else {
		defer file.Close()
		decoder := json.NewDecoder(file)
		err = decoder.Decode(&peer_map)
		if err != nil {
			logger.Error(err, "Error unmarshalling peer data")
		} else { // successfully unmarshalled data
			logger.V(1).Info("Successfully loaded peers from file", "peer_count", (len(peer_map)))
		}
	}

}

// save peer list to disk
func save_peer_list() {

	clean_up()
	peer_mutex.Lock()
	defer peer_mutex.Unlock()

	// LastConnected is written only when a connection is made, so a peer that has stayed connected for hours
	// was saved with a stale stamp and the load-time clean_up purged it as "not seen for an hour" — the
	// long-lived peers the 5-minute snapshot exists to keep (14 of 22 on 2026-10-22). Stamp the ones that are
	// connected right now.
	stamp_connected(peer_map, uint64(time.Now().UTC().Unix()), func(a string) bool { return IsAddressConnected(ParseIPNoError(a)) })

	peer_file := filepath.Join(globals.GetDataDirectory(), "peers.json")
	if err := write_json_atomic(peer_file, &peer_map); err != nil {
		logger.Error(err, "saving peer file")
	} else {
		logger.V(1).Info("Successfully saved peers to file", "peer_count", (len(peer_map)))
	}
}

// clean up by discarding entries which are too much into future
func clean_up() {
	peer_mutex.Lock()
	defer peer_mutex.Unlock()
	for k, v := range peer_map {
		if IsAddressConnected(ParseIPNoError(v.Address)) {
			continue
		}
		if v.FailCount >= 8 && !v.Whitelist { // roughly 8 tries before we discard a grey peer; proven peers age out by retention_seconds
			delete(peer_map, k)
			quarantine_grey(k, time.Now()) // r21: gossip may not re-admit it at FailCount 0 (grey_quarantine.go)
			continue
		}
		if v.LastConnected == 0 { // if never connected, purge the peer
			delete(peer_map, k)
		}

		if uint64(time.Now().UTC().Unix()) > (v.LastConnected + retention_seconds(v)) { // purge peers not connected recently
			delete(peer_map, k)
		}
	}
}

// check whether an IP is in the map already
func IsPeerInList(address string) bool {
	peer_mutex.Lock()
	defer peer_mutex.Unlock()

	if _, ok := peer_map[ParseIPNoError(address)]; ok {
		return true
	}
	return false
}
func GetPeerInList(address string) *Peer {
	peer_mutex.Lock()
	defer peer_mutex.Unlock()

	if v, ok := peer_map[ParseIPNoError(address)]; ok {
		return v
	}
	return nil
}

// add connection to  map
func Peer_Add(p *Peer) {
	clean_up()
	peer_mutex.Lock()
	defer peer_mutex.Unlock()

	if p.ID == GetPeerID() { // if peer is self do not connect
		// logger.Infof("Peer is ourselves, discard")
		return

	}

	if v, ok := peer_map[ParseIPNoError(p.Address)]; ok {
		v.Lock()
		// logger.Infof("Peer already in list adding good count")
		v.GoodCount++
		v.Unlock()
	} else {
		// logger.Infof("Peer adding to list")
		peer_map[ParseIPNoError(p.Address)] = p
	}
}

// a peer marked as fail, will only be connected  based on exponential back-off based on powers of 2
func Peer_SetFail(address string) {
	p := GetPeerInList(ParseIPNoError(address))
	if p == nil {
		return
	}
	peer_mutex.Lock()
	defer peer_mutex.Unlock()
	p.FailCount++ //  increase fail count, and mark for delayed connect
	p.ConnectAfter = uint64(time.Now().UTC().Unix()) + fail_backoff_seconds(p.FailCount)
}

// fail_backoff_seconds: 1, 2, 4 ... 512 s. Upstream shifted by FailCount-1 without a cap, which overflows once a
// whitelisted peer (no longer purged at 8 failures) keeps failing.
func fail_backoff_seconds(fails uint64) uint64 {
	if fails == 0 {
		return 0
	}
	if fails > 10 {
		fails = 10
	}
	return 1 << (fails - 1)
}

// set peer as successfully connected
// we will only distribute peers which have been successfully connected by us
func Peer_SetSuccess(address string) {
	//logger.Infof("Setting peer as success")
	p := GetPeerInList(ParseIPNoError(address))
	if p == nil {
		return
	}
	peer_mutex.Lock()
	defer peer_mutex.Unlock()
	p.FailCount = 0 //  fail count is zero again
	p.ConnectAfter = 0
	p.Whitelist = true
	p.LastConnected = uint64(time.Now().UTC().Unix()) // set time when last connected
	grey_quarantine_clear(ParseIPNoError(address))

	// logger.Infof("Setting peer as white listed")
}

/*
 //TODO do we need a functionality so some peers are never banned
func Peer_DisableBan(address string) (err error){
    p := GetPeerInList(address)
    if p == nil {
     return fmt.Errorf("Peer \"%s\" not found in list")
    }
    p.Lock()
    defer p.Unlock()
    p.NeverBlacklist = true
}

func Peer_EnableBan(address string) (err error){
    p := GetPeerInList(address)
    if p == nil {
     return fmt.Errorf("Peer \"%s\" not found in list")
    }
    p.Lock()
    defer p.Unlock()
    p.NeverBlacklist = false
}
*/

// add connection to  map
func Peer_Delete(p *Peer) {
	peer_mutex.Lock()
	defer peer_mutex.Unlock()
	delete(peer_map, ParseIPNoError(p.Address))
}

// prints all the connection info to screen
func PeerList_Print() {
	peer_mutex.Lock()
	defer peer_mutex.Unlock()
	fmt.Printf("Peer List\n")
	fmt.Printf("%-22s %-6s %-4s   %-5s %-7s %9s %3s\n", "Remote Addr", "Active", "Good", "Fail", " State", "Height", "DIR")

	var list []*Peer
	greycount := 0
	for _, v := range peer_map {
		if v.Whitelist { // only display white listed peer
			list = append(list, v)
		} else {
			greycount++
		}
	}

	// sort the list
	sort.Slice(list, func(i, j int) bool { return list[i].Address < list[j].Address })

	for i := range list {
		connected := ""
		if IsAddressConnected(ParseIPNoError(list[i].Address)) {
			connected = "ACTIVE"
		}
		fmt.Printf("%-22s %-6s %4d %5d \n", list[i].Address, connected, list[i].GoodCount, list[i].FailCount)
	}

	fmt.Printf("\nWhitelist size %d\n", len(peer_map)-greycount)
	fmt.Printf("Greylist size %d\n", greycount)

}

// this function return peer count which are in our list
func Peer_Counts() (Count uint64) {
	peer_mutex.Lock()
	defer peer_mutex.Unlock()
	return uint64(len(peer_map))
}

// Peer_List_Counts returns the white (connected to successfully at least once) and grey (only heard of) sizes of the
// peer list, the same split PeerList_Print shows. GetInfo's white_peerlist_size / grey_peerlist_size were never
// assigned upstream and always read 0.
func Peer_List_Counts() (white, grey uint64) {
	peer_mutex.Lock()
	defer peer_mutex.Unlock()
	for _, v := range peer_map {
		if v.Whitelist {
			white++
		} else {
			grey++
		}
	}
	return
}

// retention_seconds: how long a peer that is not connected stays a dial candidate. A peer we have connected to
// ourselves (whitelisted) is proven reachable, so keep it a day instead of upstream's hour; the network has only
// ~two dozen reachable nodes (peers.json held 21-24 entries all through 2026-10-23 07:27-08:27) and losing one
// costs an outgoing slot until gossip happens to mention it again.
func retention_seconds(v *Peer) uint64 {
	if v.Whitelist {
		return 86400
	}
	return 3600
}

// this function finds a possible peer to connect to keeping blacklist and already existing connections into picture
// it must not be already connected using outgoing connection
// we do allow loops such as both  incoming/outgoing simultaneously
// this will return atmost 1 address, empty address if peer list is empty
func find_peer_to_connect(version int) *Peer {
	defer clean_up()
	groups := outbound_group_counts(time.Now(), nil) // eclipse resistance: at most MAX_OUTBOUND_PER_NETGROUP per /16 (diversity.go)
	peer_mutex.Lock()
	defer peer_mutex.Unlock()

	// first search the whitelisted ones; among them prefer the peer that most often delivered new blocks to us
	// first (first_relay.go), i.e. the one closest to the block builders. With no ranking data every score is 0
	// and the first eligible peer in (random) map order wins, exactly as upstream.
	var best *Peer
	var best_score uint64
	for _, v := range peer_map {
		if uint64(time.Now().Unix()) > v.BlacklistBefore && //  if ip is blacklisted skip it
			uint64(time.Now().Unix()) > v.ConnectAfter &&
			!IsAddressConnected(ParseIPNoError(v.Address)) && v.Whitelist && !IsAddressInBanList(ParseIPNoError(v.Address)) &&
			!outbound_group_full(v.Address, groups) {
			if sc := first_relay.score(ParseIPNoError(v.Address)); best == nil || sc > best_score {
				best, best_score = v, sc
			}
		}
	}
	if best != nil {
		best.ConnectAfter = uint64(time.Now().UTC().Unix()) + 10 // minimum 10 secs gap
		return best
	}
	// if we donot have any white listed, choose from the greylist
	for _, v := range peer_map {
		if uint64(time.Now().Unix()) > v.BlacklistBefore && //  if ip is blacklisted skip it
			uint64(time.Now().Unix()) > v.ConnectAfter &&
			!IsAddressConnected(ParseIPNoError(v.Address)) && !v.Whitelist && !IsAddressInBanList(ParseIPNoError(v.Address)) &&
			!outbound_group_full(v.Address, groups) {
			v.ConnectAfter = uint64(time.Now().UTC().Unix()) + 10 // minimum 10 secs gap
			return v
		}
	}

	return nil // if no peer found, return nil
}

// return white listed peer list
// for use in handshake
func get_peer_list() (peers []Peer_Info) {
	peer_mutex.Lock()
	defer peer_mutex.Unlock()

	// Upstream deleted every whitelisted peer that was not connected at this instant, on every handshake and
	// every 10th ping: a proven peer that dropped for a moment lost its whitelist flag and fail history and was
	// gone as a dial candidate until gossip re-added it as grey. Share exactly the same set (whitelisted AND
	// connected) but keep the others for find_peer_to_connect; clean_up still ages them out.
	for _, v := range peer_map {
		if v.Whitelist && IsAddressConnected(ParseIPNoError(v.Address)) {
			peers = append(peers, Peer_Info{Addr: v.Address})
		}
	}
	return
}

func get_peer_list_specific(addr string) (peers []Peer_Info) {
	plist := get_peer_list()
	sort.SliceStable(plist, func(i, j int) bool { return plist[i].Addr < plist[j].Addr })

	if len(plist) <= 31 {
		peers = plist
	} else {
		index := sort.Search(len(plist), func(i int) bool { return plist[i].Addr < addr })
		for i := range plist {
			peers = append(peers, plist[(i+index)%len(plist)])
			if len(peers) >= 31 {
				break
			}
		}
	}
	return peers
}
