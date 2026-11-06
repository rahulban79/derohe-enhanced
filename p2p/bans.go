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

// r25 (peers, CO24-N4 / §7 B66): why each ban exists. ban_list.json maps address -> expiry only, so a ban placed by
// the v2-chain filter (common.go), a misbehaviour-score ban (penalty.go) and an operator's console ban looked the
// same on disk, in BanList_Print and to the observatory. The reason lives in a SIDECAR map with the same keys
// (persisted to ban_reasons.json), not in ban_list.json: older binaries decode ban_list.json as map[string]uint64
// and would drop the whole list on a format change. Same keys, same lifetime: every delete from ban_map deletes the
// entry here too, so it is bounded by the ban list. Local bookkeeping only; who is banned and for how long is
// exactly as before.
type ban_info struct {
	Source string `json:"source"`           // BAN_SOURCE_*
	Reason string `json:"reason,omitempty"` // the score's last reason, or a short fixed text
	At     int64  `json:"at"`               // unix seconds the ban was (last) placed
}

const BAN_SOURCE_V2 = "v2_chain"               // common.go: a peer on the pre-HF3 remnant chain
const BAN_SOURCE_SCORE = "score"               // penalty.go: misbehaviour score reached PENALTY_BAN_SCORE
const BAN_SOURCE_OPERATOR = "operator"         // the console "ban" command
const BAN_SOURCE_UNATTRIBUTED = "unattributed" // Ban_Address without a source (any other caller)

var ban_meta = map[string]ban_info{} // guarded by ban_mutex; keys = ban_map keys

// r27 (§7 sweep): p2p_bans_total counts bans PLACED since start, so a ban reloaded from ban_list.json was invisible
// on /metrics (live r26: ban_list.json held 1 running ban while p2p_bans_total read 0). The running bans and the ones
// reloaded at start are exposed separately; who is banned and for how long is unchanged.
var bans_loaded_total = metrics.Set.GetOrCreateCounter("p2p_bans_loaded_total")
var _ = metrics.Set.GetOrCreateGauge("p2p_bans_active", func() float64 { return float64(Ban_Count()) })

// BansLoaded is the number of running bans reloaded from ban_list.json at start (r27).
func BansLoaded() uint64 { return bans_loaded_total.Get() }

const BAN_CLEAN_UP_EVERY = 20 * time.Second

// loads peers list from disk
func load_ban_list() {
	go ban_clean_up_goroutine() // start routine to clean up ban list
	load_ban_list_from(globals.GetDataDirectory())
}

// load_ban_list_from loads ban_list.json and its ban_reasons.json sidecar from dir, drops the expired entries and
// counts the running ones it loaded (r27: split from load_ban_list so the reload is tested without the goroutine).
func load_ban_list_from(dir string) {
	pre := 0       // bans present before the load (none at start)
	defer func() { // runs after the cleanup below: only bans still running count as loaded
		ban_mutex.Lock()
		n := len(ban_map) - pre
		ban_mutex.Unlock()
		if n > 0 {
			bans_loaded_total.Add(n)
		}
	}()
	defer ban_clean_up() // cleanup list after loading it
	ban_mutex.Lock()
	defer ban_mutex.Unlock()
	pre = len(ban_map)

	ban_file := filepath.Join(dir, "ban_list.json")

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
	load_ban_meta_locked(filepath.Join(dir, "ban_reasons.json")) // r25 (CO24-N4)
}

// load_ban_meta_locked reads the ban_reasons.json sidecar and keeps only entries whose key is banned (r25). A missing
// or undecodable file leaves every ban "unattributed": the bans themselves are unaffected.
func load_ban_meta_locked(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	m := map[string]ban_info{}
	if json.Unmarshal(b, &m) != nil {
		return
	}
	for k, v := range m {
		if _, ok := ban_map[k]; ok {
			ban_meta[k] = v
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
	// r25 (CO24-N4): the reasons sidecar, same keys (ban_clean_up above dropped the expired ones from both)
	if err := write_json_atomic(filepath.Join(globals.GetDataDirectory(), "ban_reasons.json"), &ban_meta); err != nil {
		logger.V(1).Info("could not save ban reasons", "err", err.Error())
	}
}

// clean up ban list every 20 seconds
func ban_clean_up_goroutine() {
	ban_clean_up_loop(BAN_CLEAN_UP_EVERY, Exit_Event)
}

// ban_clean_up_loop is the goroutine's body with its period and exit channel as arguments (r27: testable).
func ban_clean_up_loop(every time.Duration, exit <-chan bool) {
	delay := time.NewTicker(every)
	defer delay.Stop()
	for {
		select {
		case <-exit:
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
			delete(ban_meta, k) // r25: same keys, same lifetime
			ban_gen++           // r23c
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
	return Ban_Address_Reason(address, ban_seconds, BAN_SOURCE_UNATTRIBUTED, "")
}

// Ban_Address_Reason is Ban_Address that also records who placed the ban and why (r25, CO24-N4). The ban itself is
// placed exactly as Ban_Address placed it before.
func Ban_Address_Reason(address string, ban_seconds uint64, source, reason string) (err error) {
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
	ban_meta[address] = ban_info{Source: source, Reason: trim64(reason), At: time.Now().Unix()} // r25
	metrics.Set.GetOrCreateCounter(fmt.Sprintf(`p2p_bans_by_source_total{source="%s"}`, ban_source_label(source))).Inc()
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
	delete(ban_meta, address) // r25
	ban_gen++                 // r23c
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
	logger.Info(fmt.Sprintf("%-22s %-6s %s\n", "Addr", "Seconds to unban", "Source (reason)"))

	for k, v := range ban_map {
		mi := ban_meta[k] // r25 (CO24-N4): an entry from before r25 has none
		src := mi.Source
		if src == "" {
			src = BAN_SOURCE_UNATTRIBUTED
		}
		logger.Info(fmt.Sprintf("%-22s %6d %s (%s)\n", k, v-uint64(time.Now().UTC().Unix()), src, mi.Reason))
	}

}

// this function return peer count which have successful handshake
func Ban_Count() (Count uint64) {
	ban_mutex.Lock()
	defer ban_mutex.Unlock()
	return uint64(len(ban_map))
}
