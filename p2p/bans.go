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
import "net"
import "sync"
import "time"
import "errors"

//import "sort"
import "path/filepath"
import "encoding/json"

//import "encoding/binary"
//import "container/list"

//import log "github.com/sirupsen/logrus"

import "github.com/deroproject/derohe/globals"
import "github.com/deroproject/derohe/metrics"

//import "github.com/deroproject/derosuite/crypto"

// This structure is used to do book keeping for the peer list and keeps other DATA related to peer
// all peers are servers, means they have exposed a port for connections
// all peers are identified by their endpoint tcp address
// all clients are identified by ther peer id ( however ip-address is used to control amount )
// the following daemon commands interact with the list
// bans := print current ban list
// ban address  time  // ban this address for specific time, if time not provided , default ban for 10 minutes
// unban address
// enableban address  // by default all addresses are bannable
// disableban address  // this address will never be banned

var ban_map = map[string]uint64{} // keeps ban maps
var ban_mutex sync.Mutex

// loads peers list from disk
func load_ban_list() {
	go ban_clean_up_goroutine() // start routine to clean up ban list
	defer ban_clean_up()        // cleanup list after loading it
	ban_mutex.Lock()
	defer ban_mutex.Unlock()

	ban_file := filepath.Join(globals.GetDataDirectory(), "ban_list.json")

	if _, err := os.Stat(ban_file); errors.Is(err, os.ErrNotExist) {
		return // since file doesn't exist , we cannot load it
	}
	file, err := os.Open(ban_file)
	if err != nil {
		logger.Error(err, "opening ban data file")
	} else {
		defer file.Close()
		decoder := json.NewDecoder(file)
		err = decoder.Decode(&ban_map)
		if err != nil {
			logger.Error(err, "Error unmarshalling ban data")
		} else { // successfully unmarshalled data
			ban_gen++ // r23c: the subnet index follows the loaded map
			logger.V(1).Info("Successfully loaded bans from file", "ban_count", (len(ban_map)))
		}
	}
}

// save ban list to disk
func save_ban_list() {

	ban_clean_up() // cleanup before saving
	ban_mutex.Lock()
	defer ban_mutex.Unlock()

	ban_file := filepath.Join(globals.GetDataDirectory(), "ban_list.json")
	if err := write_json_atomic(ban_file, &ban_map); err != nil { // tmp + fsync + rename (persist.go)
		logger.Error(err, "creating ban data file")
	} else {
		logger.V(1).Info("Successfully saved bans to file", "count", (len(ban_map)))
	}
}

// clean up ban list every 20 seconds
func ban_clean_up_goroutine() {

	delay := time.NewTicker(20 * time.Second)
	for {
		select {
		case <-Exit_Event:
			return
		case <-delay.C:
		}
		ban_clean_up()
	}

}

/*  used for manual simulation once to track a hard to find bug
func init() {
	load_ban_list()
	Ban_Address("188.191.128.64/24",600)

	IsAddressInBanList("35.185.240.198")
}
*/

// clean up by discarding entries which are  in the past
func ban_clean_up() {
	ban_mutex.Lock()
	defer ban_mutex.Unlock()

	current_time := uint64(time.Now().UTC().Unix())
	for k, v := range ban_map {
		if v < current_time {
			delete(ban_map, k)
			ban_gen++ // r23c
		}
	}
}

// convert address to subnet form
// address is an IP address or ipnet in string form
func ParseAddress(address string) (ipnet *net.IPNet, result string, err error) {
	var ip net.IP
	ip, ipnet, err = net.ParseCIDR(address)
	if err != nil { // other check whether the the IP is an IP
		ip = net.ParseIP(address)
		if ip == nil {
			err = fmt.Errorf("IP address could not be parsed")
			return
		} else {
			err = nil
			result = ip.String()
		}

	} else {
		result = ipnet.String()
	}
	return
}

// check whether an IP is in the map already
//
//	we should loop and search in subnets also
//
// TODO make it fast, however we are not expecting millions of bans, so this may be okay for time being
func IsAddressInBanList(address string) bool {
	ban_mutex.Lock()
	defer ban_mutex.Unlock()

	// any i which cannot be banned should never be banned
	// this list contains any seed nodes/exclusive nodes/proirity nodes
	// these are never banned
	// (upstream returned true here, i.e. reported a never-ban entry as BANNED: --add-priority-node=1.2.3.4 given
	// without a port made every inbound connection from that node be refused. Seeds are listed as ip:port while
	// callers pass a bare IP, so the inversion only bit entries written without a port.)
	for i := range nonbanlist {
		if address == nonbanlist[i] {
			return false
		}
	}

	// if it's a subnet or direct ip, do instant check
	if _, ok := ban_map[address]; ok {
		return true
	}

	ip := net.ParseIP(address) // user provided a valid ip parse and check subnet
	if ip != nil {
		return ban_index_contains_locked(ip)
	}
	return false
}

// r23c (p2psec): the subnet check is an index, not a scan.
//
// Before r23c every lookup of an address that is not itself a key walked the WHOLE ban map and ran ParseCIDR (and
// on failure ParseIP) on every entry, under ban_mutex. admit_inbound runs it for every accepted KCP session, and KCP
// accepts a session from ONE datagram, so a stream of datagrams (spoofed sources included) cost O(bans) parses each
// on the single accept loop; find_peer_to_connect ran it for every peer in the table, also O(bans) each. Score bans
// (penalty.go) are created by misbehaving peers, so the attacker chooses the number of bans.
// The index holds each parsed CIDR entry once, bucketed by (address length, mask): a lookup masks the IP once per
// distinct bucket (bare IPv4 keys use the exact map, IPv6 /64 score bans form one bucket, manual CIDRs a few more) and
// tests set membership. It answers exactly what the scan answered (net.IPNet.Contains rules, bare-IP string
// equality, unparsable keys ignored); TestR23cBanIndexMatchesScan checks that on random and edge-case ban sets.
// The index is rebuilt lazily after any change to ban_map (generation counter, plus a length check that also catches
// direct writes by tests or the JSON loader).
type ban_bucket struct {
	mask net.IPMask          // the network mask, of the same length as the network numbers
	nets map[string]struct{} // masked network numbers (string of the raw bytes)
}

var ban_gen uint64 // bumped by every write to ban_map in this file
var ban_index struct {
	gen     uint64
	n       int
	buckets []*ban_bucket
	ip_keys map[string]struct{} // 16-byte forms of the CANONICAL bare-IP keys (see ban_index_add_ip_locked)
}

// ban_index_add_ip_locked: the scan matched a bare-IP key k when ip.String() == k. That holds exactly when k is the
// canonical text of an address and that address equals ip, so the index keeps the 16-byte form of canonical keys
// only, and a lookup compares bytes without formatting ip (ip.String() allocated on every lookup).
func ban_index_add_ip_locked(k string) {
	if p := net.ParseIP(k); p != nil && p.String() == k {
		ban_index.ip_keys[string(p.To16())] = struct{}{}
	}
}

// ban_network returns the network number and mask exactly as net.IPNet.Contains derives them (networkNumberAndMask).
func ban_network(n *net.IPNet) (net.IP, net.IPMask, bool) {
	ip := n.IP.To4()
	if ip == nil {
		ip = n.IP
		if len(ip) != net.IPv6len {
			return nil, nil, false
		}
	}
	m := n.Mask
	switch len(m) {
	case net.IPv4len:
		if len(ip) != net.IPv4len {
			return nil, nil, false
		}
	case net.IPv6len:
		if len(ip) == net.IPv4len {
			m = m[12:]
		}
	default:
		return nil, nil, false
	}
	return ip, m, true
}

func ban_masked(ip net.IP, m net.IPMask) string {
	var b [net.IPv6len]byte
	for i := range ip {
		b[i] = ip[i] & m[i]
	}
	return string(b[:len(ip)])
}

func ban_index_rebuild_locked() {
	ban_index.buckets = ban_index.buckets[:0]
	ban_index.ip_keys = map[string]struct{}{}
	by_mask := map[string]*ban_bucket{}
	for k := range ban_map {
		ipnet, _, err := ParseAddress(k)
		if err != nil {
			continue
		}
		if ipnet == nil { // a bare IP: the scan compared ip.String() == k
			ban_index_add_ip_locked(k)
			continue
		}
		nn, m, ok := ban_network(ipnet)
		if !ok {
			continue
		}
		bk := string(m)
		b := by_mask[bk]
		if b == nil {
			b = &ban_bucket{mask: m, nets: map[string]struct{}{}}
			by_mask[bk] = b
			ban_index.buckets = append(ban_index.buckets, b)
		}
		b.nets[ban_masked(nn, m)] = struct{}{}
	}
	ban_index.gen, ban_index.n = ban_gen, len(ban_map)
	ban_index_rebuilds++
}

var ban_index_rebuilds uint64 // tests: the index is rebuilt only after a change

// ban_index_add_locked records new key k (already in ban_map) in a current index, or marks the index stale.
func ban_index_add_locked(k string) {
	if ban_index.ip_keys == nil || ban_index.gen != ban_gen || ban_index.n != len(ban_map)-1 {
		ban_gen++
		return
	}
	ban_index.n = len(ban_map)
	ipnet, _, err := ParseAddress(k)
	if err != nil {
		return
	}
	if ipnet == nil {
		ban_index_add_ip_locked(k)
		return
	}
	nn, m, ok := ban_network(ipnet)
	if !ok {
		return
	}
	for _, b := range ban_index.buckets {
		if string(b.mask) == string(m) {
			b.nets[ban_masked(nn, m)] = struct{}{}
			return
		}
	}
	ban_index.buckets = append(ban_index.buckets, &ban_bucket{mask: m, nets: map[string]struct{}{ban_masked(nn, m): {}}})
}

// ban_index_contains_locked: is ip, or a network containing it, a key of ban_map? Caller holds ban_mutex.
func ban_index_contains_locked(ip net.IP) bool {
	if ban_index.ip_keys == nil || ban_index.gen != ban_gen || ban_index.n != len(ban_map) {
		ban_index_rebuild_locked()
	}
	if len(ban_index.ip_keys) > 0 {
		if _, ok := ban_index.ip_keys[string(ip.To16())]; ok {
			return true
		}
	}
	x := ip.To4()
	if x == nil {
		x = ip
	}
	for _, b := range ban_index.buckets {
		if len(b.mask) != len(x) {
			continue
		}
		if _, ok := b.nets[ban_masked(x, b.mask)]; ok {
			return true
		}
	}
	return false
}

// ban a peer for specific time
// manual bans are always placed
// address can be an address or a subnet

func Ban_Address(address string, ban_seconds uint64) (err error) {
	ban_mutex.Lock()
	defer ban_mutex.Unlock()

	// make sure we are not banning seed nodes/exclusive node/priority nodes on command line
	_, address, err = ParseAddress(address)
	if err != nil {
		return
	}

	//logger.Warnf("%s banned for %d secs", address, ban_seconds)
	_, existed := ban_map[address]
	ban_map[address] = uint64(time.Now().UTC().Unix()) + ban_seconds
	if !existed { // r23c: the index depends on the keys only; a new key is added in place (no O(bans) rebuild)
		ban_index_add_locked(address)
	}
	metrics.Set.GetOrCreateCounter("p2p_bans_total").Inc() // bans were visible only as a count in the 5-minute save line
	return
}

/*
/// ban a peer only if it can be banned
func Peer_Ban_Internal(address string, ban_seconds uint64) (err error){
    p := GetPeerInList(address)
    if p == nil {
     return fmt.Errorf("Peer \"%s\" not found in list")
    }
    p.Lock()
    defer p.Unlock()
    if p.NeverBlacklist == false {
        p.BlacklistBefore = uint64(time.Now().Unix()) + ban_seconds
    }
}
*/

// unban a peer for specific time
func UnBan_Address(address string) (err error) {
	if !IsAddressInBanList(address) {
		return fmt.Errorf("Address \"%s\" not found in ban list", address)
	}
	ban_mutex.Lock()
	defer ban_mutex.Unlock()
	logger.Info("unbanned", "address", address)
	delete(ban_map, address)
	ban_gen++ // r23c
	return
}

/*
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

// prints all the connection info to screen
func BanList_Print() {
	ban_clean_up() // clean up before printing
	ban_mutex.Lock()
	defer ban_mutex.Unlock()
	logger.Info(fmt.Sprintf("Ban List contains %d \n", len(ban_map)))
	logger.Info(fmt.Sprintf("%-22s %-6s\n", "Addr", "Seconds to unban"))

	for k, v := range ban_map {
		logger.Info(fmt.Sprintf("%-22s %6d\n", k, v-uint64(time.Now().UTC().Unix())))
	}

}

// this function return peer count which have successful handshake
func Ban_Count() (Count uint64) {
	ban_mutex.Lock()
	defer ban_mutex.Unlock()
	return uint64(len(ban_map))
}
