package p2p

// First-relay telemetry: which peer delivers each new block to us FIRST.
//
// A normal miniblock is paid only if it reaches the node that finds the block's final miniblock (the builder)
// before nine others do (blockchain/miner_block.go: GetAllMiniBlocks(key)[:9], arrival order at the builder).
// The builder is the first node to broadcast its block, so the peer that hands us the first chunk of a new block
// is the builder itself or the peer with the shortest path to it. Counting first deliveries per peer therefore
// ranks our connections by how close they are to the nodes that decide whether our shares are paid — which
// round-trip ping latency (the current broadcast order key) does not measure.
//
// Uses: (1) find_peer_to_connect dials the best-ranked known peer first instead of a random one, (2)
// maintain_builder_adjacent_connections keeps the top-ranked peers connected like --add-priority-node, and
// (3) operators read the ranking from the p2p_first_relay_* metrics and first_relay.json.
// Observation and dial order only: no message is changed, nothing is accepted or rejected differently.

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/metrics"
)

const FIRST_RELAY_HALVE_AFTER = 2000 // blocks (~10 h): halve every counter so the ranking follows topology changes
const FIRST_RELAY_STICKY = 8         // keep this many top-ranked peers connected
const FIRST_RELAY_MIN_FIRSTS = 5     // a peer must have delivered this many blocks first before it is sticky
const FIRST_RELAY_FORGET = 7 * 86400 // seconds: a saved entry whose last first delivery is older is not restored

type RelayStat struct {
	Address     string            `json:"address"`  // dialable ip:port, "" if the peer never told us a port
	Firsts      uint64            `json:"firsts"`   // new blocks this peer delivered to us before anyone else
	Builders    map[string]uint64 `json:"builders"` // integrator (first 8 bytes, hex) -> firsts
	DelaySumUs  int64             `json:"delay_sum_us"`
	DelayN      uint64            `json:"delay_n"`
	LastFirstTS int64             `json:"last_first"`
}

type first_relay_table struct {
	sync.Mutex
	Peers  map[string]*RelayStat `json:"peers"` // key: IP
	Blocks uint64                `json:"blocks"`
}

var first_relay = first_relay_table{Peers: map[string]*RelayStat{}}

// dial_address is the address we can connect back to for this connection: the dialed address for an outgoing
// one, the IP plus the advertised listening port for an incoming one, "" if the peer advertises no port.
func dial_address(c *Connection) string {
	if c == nil || c.Addr == nil {
		return ""
	}
	if !c.Incoming {
		return c.Addr.String()
	}
	if c.Port == 0 || c.Port > 65535 {
		return ""
	}
	return net.JoinHostPort(Address(c), strconv.Itoa(int(c.Port)))
}

// record notes that ip delivered a block built by integrator first, delay_us after its builder sent it.
func (t *first_relay_table) record(ip, dial string, integrator []byte, delay_us int64, now time.Time) {
	if ip == "" {
		return
	}
	t.Lock()
	defer t.Unlock()
	t.Blocks++
	if t.Blocks%FIRST_RELAY_HALVE_AFTER == 0 {
		t.halve()
	}
	s := t.Peers[ip]
	if s == nil {
		s = &RelayStat{Builders: map[string]uint64{}}
		t.Peers[ip] = s
	}
	if dial != "" {
		s.Address = dial
	}
	s.Firsts++
	if len(integrator) >= 8 {
		s.Builders[hex.EncodeToString(integrator[:8])]++
	}
	if delay_us > 0 && delay_us < 60_000_000 { // ignore clock-skew garbage
		s.DelaySumUs += delay_us
		s.DelayN++
	}
	s.LastFirstTS = now.Unix()
}

func (t *first_relay_table) halve() { // caller holds the lock
	for ip, s := range t.Peers {
		s.Firsts /= 2
		for b := range s.Builders {
			if s.Builders[b] /= 2; s.Builders[b] == 0 {
				delete(s.Builders, b)
			}
		}
		s.DelaySumUs /= 2
		s.DelayN /= 2
		if s.Firsts == 0 {
			delete(t.Peers, ip)
		}
	}
}

func (t *first_relay_table) score(ip string) uint64 {
	t.Lock()
	defer t.Unlock()
	if s := t.Peers[ip]; s != nil {
		return s.Firsts
	}
	return 0
}

// top returns up to n dialable addresses with at least min_firsts first deliveries, best first.
func (t *first_relay_table) top(n int, min_firsts uint64) (out []string) {
	t.Lock()
	defer t.Unlock()
	type kv struct {
		addr string
		f    uint64
	}
	var l []kv
	for _, s := range t.Peers {
		if s.Address != "" && s.Firsts >= min_firsts {
			l = append(l, kv{s.Address, s.Firsts})
		}
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].f != l[j].f {
			return l[i].f > l[j].f
		}
		return l[i].addr < l[j].addr
	})
	for i := 0; i < len(l) && i < n; i++ {
		out = append(out, l[i].addr)
	}
	return
}

// record_first_relay is called once per new block, for the connection that delivered its first chunk.
func record_first_relay(c *Connection, integrator []byte, sent_us int64) {
	defer globals.Recover(3)
	now := globals.Time().UTC()
	var delay int64
	if sent_us != 0 {
		delay = now.UnixMicro() - sent_us
	}
	ip := Address(c)
	first_relay.record(ip, dial_address(c), integrator, delay, now)
	metrics.Set.GetOrCreateCounter(`p2p_first_relay_total{peer="` + ip + `"}`).Inc()
	if delay > 0 && delay < 60_000_000 {
		metrics.Set.GetOrCreateHistogram("p2p_first_relay_delay_seconds").Update(float64(delay) / 1e6)
	}
}

const FIRST_RELAY_FILE = "first_relay.json"

func save_first_relay() {
	save_first_relay_to(filepath.Join(globals.GetDataDirectory(), FIRST_RELAY_FILE))
}

func save_first_relay_to(path string) error {
	first_relay.Lock()
	defer first_relay.Unlock()
	err := write_json_atomic(path, &first_relay)
	if err != nil {
		logger.V(1).Error(err, "saving first_relay.json")
	}
	return err
}

// load_first_relay restores the ranking at startup. r17 wrote first_relay.json every 5 minutes but never read it,
// so every restart emptied the table and maintain_builder_adjacent_connections had nothing sticky until 5 new
// blocks had arrived first through the same peer (FIRST_RELAY_MIN_FIRSTS).
func load_first_relay() {
	load_first_relay_from(filepath.Join(globals.GetDataDirectory(), FIRST_RELAY_FILE), time.Now().Unix())
}

// load_first_relay_from merges the file into the table, keeping the larger counter for a peer already present.
// Entries whose last first delivery is older than FIRST_RELAY_FORGET are dropped (topology moves on), and so are
// malformed ones. A missing or unreadable file leaves the table as it is: the ranking is a dial-order hint only.
func load_first_relay_from(path string, now int64) (loaded int) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var t first_relay_table
	if err := json.Unmarshal(data, &t); err != nil {
		logger.V(1).Error(err, "Error unmarshalling first_relay.json")
		return 0
	}
	first_relay.Lock()
	defer first_relay.Unlock()
	if first_relay.Peers == nil {
		first_relay.Peers = map[string]*RelayStat{}
	}
	for ip, s := range t.Peers {
		if s == nil || s.Firsts == 0 || net.ParseIP(ip) == nil || now-s.LastFirstTS > FIRST_RELAY_FORGET || s.LastFirstTS > now+86400 {
			continue
		}
		if s.Builders == nil {
			s.Builders = map[string]uint64{}
		}
		if cur, ok := first_relay.Peers[ip]; !ok || s.Firsts > cur.Firsts {
			first_relay.Peers[ip] = s
			loaded++
		}
	}
	if t.Blocks > first_relay.Blocks {
		first_relay.Blocks = t.Blocks
	}
	logger.V(1).Info("Successfully loaded first-relay ranking from file", "count", loaded)
	return
}

// maintain_builder_adjacent_connections keeps the FIRST_RELAY_STICKY best-ranked peers connected, the way
// maintain_outgoing_priority_connection keeps --add-priority-node peers connected. connect_with_endpoint
// already skips banned and already-connected addresses and backs off 10 s per address.
func maintain_builder_adjacent_connections() {
	delay := time.NewTicker(4 * time.Second)
	for {
		select {
		case <-Exit_Event:
			return
		case <-delay.C:
		}
		for _, addr := range sticky_dial_targets(time.Now()) {
			go connect_with_endpoint(addr, false)
		}
	}
}

// sticky_dial_targets: the top-ranked first-relay addresses that are neither connected nor backing off.
func sticky_dial_targets(now time.Time) (out []string) {
	for _, addr := range first_relay.top(FIRST_RELAY_STICKY, FIRST_RELAY_MIN_FIRSTS) {
		if !IsAddressConnected(ParseIPNoError(addr)) && relay_dial_allowed(addr, now) {
			out = append(out, addr)
		}
	}
	return
}

// relay_dial_allowed applies the handshake back-off to the sticky loop, which bypassed it (Round 20 forensics). A
// ranked address can go stale: 203.0.113.23:42151 (a random listening port advertised by a peer in an earlier run)
// stayed in first_relay.json with 5 firsts and was redialled every 12 s on the live r19 node (2026-10-27 05:48-08:19:
// 1,512 "backing off" lines, ~750 dials, each ending in a failed handshake) until the ranking halved it out. A listed
// peer now waits for its ConnectAfter (Peer_SetFail: 1, 2, 4 ... 512 s), an unlisted one for its unlisted back-off.
func relay_dial_allowed(addr string, now time.Time) bool {
	ip := ParseIPNoError(addr)
	if p := GetPeerInList(ip); p != nil {
		peer_mutex.Lock()
		after := p.ConnectAfter
		peer_mutex.Unlock()
		return uint64(now.Unix()) >= after
	}
	return unlisted_dial_allowed(ip, now)
}

// ---- inbound reachability that cannot be fooled by local nodes

var public_inbound_opens uint64

// is_public reports whether ip is routable on the internet: not loopback, RFC1918, link-local, CGNAT or unspecified.
func is_public(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 { // 100.64.0.0/10 carrier-grade NAT
		return false
	}
	return true
}

// PublicInboundOpens counts accepted inbound connections from public addresses since start. The kcp
// PassiveOpens counter it complements also counts loopback/LAN nodes (e.g. a local shadow node), which made
// GetSyncInfo report "reachable" on a node whose UDP port is not forwarded.
func PublicInboundOpens() uint64 {
	return atomic.LoadUint64(&public_inbound_opens)
}
