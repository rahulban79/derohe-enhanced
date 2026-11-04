package p2p

// r25 (peers): CO24-N1..N7 (§7 B63-B69), B47 and B70. Every address below is a documentation address (RFC 5737).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/rpc2"
	"github.com/go-logr/logr"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/metrics"
)

func reset_bans_r25(t testing.TB) {
	ban_mutex.Lock()
	saved_map, saved_meta := ban_map, ban_meta
	ban_map, ban_meta = map[string]uint64{}, map[string]ban_info{}
	ban_gen++
	ban_mutex.Unlock()
	t.Cleanup(func() {
		ban_mutex.Lock()
		ban_map, ban_meta = saved_map, saved_meta
		ban_gen++
		ban_mutex.Unlock()
	})
}

func pipe_conn_r25(ip string) *Connection {
	a, _ := net.Pipe()
	return &Connection{Addr: &net.UDPAddr{IP: net.ParseIP(ip), Port: 11011}, Conn: a, ConnTls: a, logger: globals.Logger}
}

func prom_r25() string {
	var buf bytes.Buffer
	metrics.Set.WritePrometheus(&buf)
	return buf.String()
}

func prom_value_r25(t *testing.T, name string) float64 {
	m := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + ` (\S+)$`).FindStringSubmatch(prom_r25())
	if m == nil {
		t.Fatalf("%s is not on /metrics", name)
	}
	var v float64
	fmt.Sscan(m[1], &v)
	return v
}

// CO24-N1: every offence below the ban score is kept (newest first, bounded) with the decayed score.
func TestR25PenaltyLastReasonsAndScore(t *testing.T) {
	reset_penalty(t)
	now := time.Unix(2_000_000_000, 0)
	reasons := []string{"busy", "timeout", "malformed_request", "busy", "timeout"} // 2+10+20+2+10 = 44 < 100
	for i, r := range reasons {
		if secs := add_penalty("192.0.2.71", r, now.Add(time.Duration(i)*time.Second)); secs != 0 {
			t.Fatalf("banned at %d points", i)
		}
	}
	score, bans, events, last := penalty_view("192.0.2.71", now.Add(4*time.Second))
	if events != 5 || bans != 0 || len(last) != PENALTY_LAST_REASONS {
		t.Fatalf("events %d bans %d last %v", events, bans, last)
	}
	if last[0].Reason != "timeout" || last[1].Reason != "busy" || last[3].Reason != "timeout" || last[0].At != now.Unix()+4 {
		t.Fatalf("not newest first: %v", last)
	}
	if score < 43 || score > 44.01 {
		t.Fatalf("score %v, want ~44 (a few seconds of decay)", score)
	}
	if s, _, _, _ := penalty_view("192.0.2.71", now.Add(4*time.Second+PENALTY_HALF_LIFE)); s < 21.5 || s > 22.01 {
		t.Fatalf("score after one half-life %v, want ~22", s)
	}
	// reaching the ban score: one ban, the score restarts at 0, the reason ring keeps the ban's reason first
	add_penalty("192.0.2.71", "invalid_pow", now.Add(5*time.Second))
	if secs := add_penalty("192.0.2.71", "invalid_pow", now.Add(6*time.Second)); secs == 0 {
		t.Fatal("not banned at >= 100 points")
	}
	score, bans, events, last = penalty_view("192.0.2.71", now.Add(6*time.Second))
	if score != 0 || bans != 1 || events != 7 || last[0].Reason != "invalid_pow" {
		t.Fatalf("after ban: score %v bans %d events %d last %v", score, bans, events, last)
	}
	if _, _, ev, l := penalty_view("192.0.2.72", now); ev != 0 || l == nil || len(l) != 0 {
		t.Fatalf("unknown scope: %d %v (want 0 and an empty, non-nil list)", ev, l)
	}
}

// CO24-N1: GetPeerInfo carries the score of the connection's penalty scope.
func TestR25PeerInfoCarriesPenaltyAndCounters(t *testing.T) {
	reset_penalty(t)
	c := out_conn("192.0.2.73")
	c.Peer_ID = 0x7325
	c.Created = time.Now()
	connection_map.Store(Address(c), c)
	defer connection_map.Delete(Address(c))
	add_penalty("192.0.2.73", "malformed_request", time.Now())
	c.obs.objects_unserved.Add(3)
	c.obs.short_answers.Add(2)
	c.obs.inv_clipped.Add(7)
	c.note_chain_served(5)
	var got *PeerInfo
	for _, p := range PeerInfos(-1) {
		if p.Address == "192.0.2.73" {
			p := p
			got = &p
		}
	}
	if got == nil {
		t.Fatal("peer not listed")
	}
	if got.PenaltyScore < 19.9 || got.PenaltyEvents != 1 || len(got.LastOffences) != 1 || got.LastOffences[0].Reason != "malformed_request" {
		t.Fatalf("penalty fields %+v", got)
	}
	if got.ObjectsUnserved != 3 || got.ShortAnswers != 2 || got.InvTxidsClipped != 7 || got.ChainRequestsServed != 1 || got.ChainBlocksServed != 5 {
		t.Fatalf("counters %+v", got)
	}
	b, _ := json.Marshal(got)
	for _, k := range []string{`"penalty_score"`, `"last_offences"`, `"chain_requests_served"`, `"inv_txids_clipped"`, `"objects_unserved"`, `"short_answers"`, `"sync_hold_seconds"`} {
		if !strings.Contains(string(b), k) {
			t.Fatalf("%s missing from %s", k, b)
		}
	}
}

// CO24-N2: the per-reason series exist before the first event (absent must not look like zero).
func TestR25PenaltySeriesRegisteredEagerly(t *testing.T) {
	out := prom_r25()
	for reason := range PENALTY_POINTS {
		for _, n := range []string{"p2p_penalty_events_total", "p2p_penalty_bans_by_reason_total"} {
			if !strings.Contains(out, fmt.Sprintf(`%s{reason="%s"} `, n, reason)) {
				t.Fatalf(`%s{reason="%s"} is not on /metrics before it fires`, n, reason)
			}
		}
	}
	for _, s := range ban_sources {
		if !strings.Contains(out, fmt.Sprintf(`p2p_bans_by_source_total{source="%s"} `, s)) {
			t.Fatalf("ban source %s is not on /metrics", s)
		}
	}
}

// CO24-N2/N4: a score ban is recorded with its source and reason, and counted per reason.
func TestR25ScoreBanCarriesSourceAndReason(t *testing.T) {
	reset_penalty(t)
	reset_bans_r25(t)
	saved := nonbanlist
	defer func() { nonbanlist = saved }()
	nonbanlist = nil
	before := prom_value_r25(t, `p2p_penalty_bans_by_reason_total{reason="invalid_pow"}`)
	c := pipe_conn_r25("192.0.2.74")
	for i := 0; i < 3; i++ { // 50 + 50*decay < 100: two invalid_pow a moment apart do NOT ban (see TestR25TwoInvalidPowDoNotBan)
		c.penalize("invalid_pow")
	}
	list, total, by := BanInfos(-1, time.Now())
	if total != 1 || by[BAN_SOURCE_SCORE] != 1 || list[0].Address != "192.0.2.74" || list[0].Source != BAN_SOURCE_SCORE || list[0].Reason != "invalid_pow" {
		t.Fatalf("ban list %v %d %v", list, total, by)
	}
	if d := prom_value_r25(t, `p2p_penalty_bans_by_reason_total{reason="invalid_pow"}`) - before; d != 1 {
		t.Fatalf("bans_by_reason{invalid_pow} moved by %v", d)
	}
}

// CO24-N4: plain Ban_Address is unattributed; the sidecar follows every delete; loading keeps only banned keys.
func TestR25BanMetaLifetimeAndLoad(t *testing.T) {
	reset_bans_r25(t)
	Ban_Address("192.0.2.75", 600)
	Ban_Address_Reason("198.51.100.75/24", 600, BAN_SOURCE_OPERATOR, "console")
	Ban_Address_Reason("192.0.2.76", 600, BAN_SOURCE_V2, "top_version<3 past HF3")
	list, total, by := BanInfos(2, time.Now())
	if total != 3 || len(list) != 2 || by[BAN_SOURCE_UNATTRIBUTED] != 1 || by[BAN_SOURCE_OPERATOR] != 1 || by[BAN_SOURCE_V2] != 1 {
		t.Fatalf("list %v total %d by %v", list, total, by)
	}
	if err := UnBan_Address("192.0.2.76"); err != nil {
		t.Fatal(err)
	}
	ban_mutex.Lock()
	ban_map["192.0.2.75"] = uint64(time.Now().Unix()) - 1 // expired
	ban_mutex.Unlock()
	ban_clean_up()
	ban_mutex.Lock()
	_, a := ban_meta["192.0.2.75"]
	_, b := ban_meta["192.0.2.76"]
	_, c := ban_meta["198.51.100.0/24"]
	n := len(ban_meta)
	ban_mutex.Unlock()
	if a || b || !c || n != 1 {
		t.Fatalf("sidecar after unban/expiry: expired %v unbanned %v kept %v len %d", a, b, c, n)
	}
	// load: an entry whose key is not banned is dropped (the sidecar never outlives the ban list)
	f := filepath.Join(t.TempDir(), "ban_reasons.json")
	os.WriteFile(f, []byte(`{"198.51.100.0/24":{"source":"operator","reason":"console","at":5},"203.0.113.77":{"source":"score","at":6}}`), 0600)
	ban_mutex.Lock()
	ban_meta = map[string]ban_info{}
	load_ban_meta_locked(f)
	_, kept := ban_meta["198.51.100.0/24"]
	_, ghost := ban_meta["203.0.113.77"]
	ban_mutex.Unlock()
	if !kept || ghost {
		t.Fatalf("load: kept %v ghost %v", kept, ghost)
	}
}

// CO24-N3: a refused Chain request is counted as refused, an answered one as served (with its block ids).
func TestR25ChainRequestsCounted(t *testing.T) {
	reset_penalty(t)
	r0 := prom_value_r25(t, "p2p_chain_requests_refused_total")
	c := pipe_conn_r25("192.0.2.77")
	var resp Chain_Response_Struct
	c.Chain(Chain_Request_Struct{}, &resp) // no block ids: malformed
	if d := prom_value_r25(t, "p2p_chain_requests_refused_total") - r0; d != 1 || c.obs.chain_served.Load() != 0 {
		t.Fatalf("refused moved by %v, served %d", d, c.obs.chain_served.Load())
	}
	s0, b0 := prom_value_r25(t, "p2p_chain_requests_served_total"), prom_value_r25(t, "p2p_chain_request_blocks_total")
	c.note_chain_served(513)
	if prom_value_r25(t, "p2p_chain_requests_served_total")-s0 != 1 || prom_value_r25(t, "p2p_chain_request_blocks_total")-b0 != 513 || c.obs.chain_blocks.Load() != 513 {
		t.Fatal("served counters")
	}
	src, _ := os.ReadFile("rpc_chain_request.go")
	s := string(src)
	i, j := strings.Index(s, "c.note_chain_served(len(response.Block_list))"), strings.Index(s, "response.Start_topoheight = start_topoheight")
	if i < 0 || j < 0 || i < j {
		t.Fatal("Chain does not count the answer it built")
	}
}

// CO24-N5: the INV budget's clips are attributed to the connection.
func TestR25InvClipsPerConnection(t *testing.T) {
	c := out_conn("192.0.2.78")
	now := time.Now()
	list := make([][32]byte, INV_TX_BURST+300)
	if got := c.clip_inv_txs(list, now); len(got) != INV_TX_BURST {
		t.Fatalf("kept %d", len(got))
	}
	c.clip_inv_txs(make([][32]byte, 10), now) // the bucket is empty: all 10 clipped
	if n := c.obs.inv_clipped.Load(); n != 310 {
		t.Fatalf("inv_clipped %d, want 310", n)
	}
}

// CO24-N6: a short sync answer is typed (same text), logged at V(1) and counted; a remote error is counted as unserved.
func TestR25ShortAnswerTypedLoggedCounted(t *testing.T) {
	ids := []crypto.Hash{{1}, {2}, {3}, {4}}
	_, err := fetch_pipelined(ids, 4, 1, func(ids []crypto.Hash) (Objects, error) { return Objects{}, nil },
		func(Objects) error { return nil })
	if err == nil || err.Error() != "peer answered 0 blocks for 4 requested" || !is_short_answer(err) {
		t.Fatalf("err %v", err)
	}
	if k := classify_call_error(err); k != call_failure_short {
		t.Fatalf("classified %v", k)
	}
	if k := classify_call_error(fmt.Errorf("wrapped: %w", err)); k != call_failure_short {
		t.Fatalf("wrapped classified %v", k)
	}
	s := &level_sink{}
	log_call_failure(logr.New(s), err, "Call failed GetObject")
	if s.errors != 0 || len(s.infos) != 1 || s.infos[0] != 1 {
		t.Fatalf("a short answer is the peer's: want one V(1) info, got infos %v errors %d", s.infos, s.errors)
	}
	c := out_conn("192.0.2.79")
	c.logger = logr.New(&level_sink{})
	u0, s0 := prom_value_r25(t, "p2p_objects_unserved_total"), prom_value_r25(t, "p2p_sync_short_answers_total")
	c.call_failed(err, "Call failed GetObject")
	c.call_failed(rpc2.ServerError("open /x: no such file or directory"), "Call failed GetObject")
	c.call_failed(fmt.Errorf("i/o timeout"), "Call failed GetObject")
	if c.obs.short_answers.Load() != 1 || c.obs.objects_unserved.Load() != 1 {
		t.Fatalf("per connection: short %d unserved %d", c.obs.short_answers.Load(), c.obs.objects_unserved.Load())
	}
	if prom_value_r25(t, "p2p_objects_unserved_total")-u0 != 1 || prom_value_r25(t, "p2p_sync_short_answers_total")-s0 != 1 {
		t.Fatal("node-wide counters")
	}
}

// B47: the peer's own failure holds sync with it (30 s doubling to 10 min); ours does not; a --sync-node never is.
func TestR25SyncHoldEscalatesAndForgives(t *testing.T) {
	c := out_conn("192.0.2.80")
	now := time.Unix(2_000_000_000, 0)
	c.sync_failed(call_failure_closed, now)
	c.sync_failed(call_failure_other, now)
	if c.sync_held(now) || c.obs.sync_strikes.Load() != 0 {
		t.Fatal("a closed pipe or our own error must not hold the peer")
	}
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 10 * time.Minute, 10 * time.Minute}
	for i, w := range want {
		kind := call_failure_short
		if i%2 == 1 {
			kind = call_failure_remote
		}
		c.sync_failed(kind, now)
		if !c.sync_held(now.Add(w-time.Second)) || c.sync_held(now.Add(w)) {
			t.Fatalf("strike %d: hold is not %v", i+1, w)
		}
	}
	c.sync_succeeded()
	if c.sync_held(now) || c.obs.sync_strikes.Load() != 0 {
		t.Fatal("a sync that added blocks must forgive")
	}
	s := out_conn("192.0.2.81")
	s.SyncNode = true
	s.sync_failed(call_failure_short, now)
	if s.sync_held(now) {
		t.Fatal("a --sync-node is never held")
	}
}

// B47 wiring: trigger_sync skips a held connection and forgives one that served blocks; both sync fetch sites hold.
func TestR25SyncHoldWiring(t *testing.T) {
	pool, _ := os.ReadFile("connection_pool.go")
	p := string(pool)
	ts := p[strings.Index(p, "func trigger_sync() {"):]
	ts = ts[:strings.Index(ts, "\n}\n")]
	if i, j := strings.Index(ts, "if connection.sync_held(time.Now()) {"), strings.Index(ts, "connection.sync_chain()"); i < 0 || j < 0 || i > j {
		t.Fatal("trigger_sync does not skip held connections before syncing")
	}
	if !strings.Contains(ts, "if chain.Get_Height() > before {") || !strings.Contains(ts, "connection.sync_succeeded()") {
		t.Fatal("trigger_sync does not forgive a peer that served blocks")
	}
	cs, _ := os.ReadFile("chain_sync.go")
	if n := strings.Count(string(cs), `connection.sync_failed(connection.call_failed(err, "Call failed GetObject"), time.Now())`); n != 2 {
		t.Fatalf("%d of the 2 sync fetch sites hold the peer", n)
	}
	cm, _ := os.ReadFile("common.go")
	if !strings.Contains(string(cm), "Ban_Address_Reason(Address(connection), secs, BAN_SOURCE_V2,") {
		t.Fatal("the v2-chain ban carries no source (CO24-N4)")
	}
	mg, _ := os.ReadFile("../cmd/derod/main.go")
	if strings.Count(string(mg), "p2p.BAN_SOURCE_OPERATOR, \"console\")") != 2 {
		t.Fatal("the console bans carry no operator source (CO24-N4)")
	}
	rn, _ := os.ReadFile("rpc_notifications.go")
	if !strings.Contains(string(rn), `kind := c.call_failed(err, "Call failed GetObject", "need_objects", need)`) {
		t.Fatal("the INV fetch is not counted per connection")
	}
}

// CO24-N7: running stuck holds are listed, soonest first; ended ones are not.
func TestR25StuckHoldsListed(t *testing.T) {
	stuck.Lock()
	saved := stuck.hold
	stuck.hold = map[string]*stuck_hold_entry{}
	stuck.Unlock()
	defer func() { stuck.Lock(); stuck.hold = saved; stuck.Unlock() }()
	now := time.Now()
	stuck_hold_add("192.0.2.82", 7_472_150, now)
	stuck_hold_add("192.0.2.83", 7_537_830, now)
	stuck_hold_add("192.0.2.83", 7_537_830, now) // second strike: 60 min
	stuck.Lock()
	stuck.hold["192.0.2.84"] = &stuck_hold_entry{strikes: 1, until: now.Add(-time.Second)}
	stuck.Unlock()
	h := StuckHolds(now)
	if len(h) != 2 || h[0].Address != "192.0.2.82" || h[1].Address != "192.0.2.83" || h[1].Strikes != 2 || h[1].Height != 7_537_830 ||
		h[0].HeldSeconds != int64(STUCK_HOLD/time.Second) || h[1].HeldSeconds != int64(2*STUCK_HOLD/time.Second) {
		t.Fatalf("holds %+v", h)
	}
	if n := stuck_held_count(now); n != len(h) {
		t.Fatalf("list %d vs gauge %d", len(h), n)
	}
}

// CO24-N1: the offender list is bounded, newest offence first, and shows a running ban.
func TestR25OffendersListed(t *testing.T) {
	reset_penalty(t)
	saved := nonbanlist
	defer func() { nonbanlist = saved }()
	nonbanlist = nil
	now := time.Now()
	add_penalty("192.0.2.85", "busy", now.Add(-time.Minute))
	add_penalty("192.0.2.86", "invalid_pow", now)
	add_penalty("192.0.2.86", "invalid_pow", now) // same instant: exactly 100
	penalty_mu.Lock()
	penalty_map["192.0.2.87"] = &misbehaviour{score: 0.5, at: now} // a record with no offence is not an offender
	penalty_mu.Unlock()
	o := Offenders(-1, now)
	if len(o) != 2 || o[0].Scope != "192.0.2.86" || o[0].Bans != 1 || o[0].BannedFor < 599 || o[1].Scope != "192.0.2.85" || o[1].Events != 1 {
		t.Fatalf("offenders %+v", o)
	}
	if len(Offenders(1, now)) != 1 {
		t.Fatal("max not honoured")
	}
}

// B70: the IPv4 literals of the p2p and derod sources are the seed nodes (public configuration), the documentation and
// reserved ranges, and the fixed set below (upstream literals and synthetic fixtures that name no observed peer). An
// address this node observed must not be written into the source again: use an RFC 5737 address.
var r25_known_literals = map[string]bool{
	"1.1.1.1": true, "1.2.3.4": true, "2.2.2.2": true, "3.3.3.3": true, "4.4.4.4": true, "5.5.5.5": true, "5.6.7.8": true,
	"8.8.4.4": true, "8.8.8.8": true, "9.9.9.9": true, "35.185.240.198": true, "45.1.1.1": true, "45.2.2.2": true,
	"45.3.3.3": true, "45.4.4.4": true, "47.0.0.1": true, "51.222.86.52": true, "89.38.99.117": true, "100.128.0.1": true,
	"188.191.128.64": true, "192.0.3.1": true, "192.0.4.1": true, "192.0.7.1": true, "192.0.9.9": true, "203.0.0.1": true,
	"203.0.1.1": true, "203.0.2.2": true, "203.0.3.3": true, "203.0.4.4": true, "203.0.5.5": true, "203.0.7.7": true,
	"203.0.9.9": true, "203.0.114.77": true, "203.0.200.9": true, "208.67.222.222": true, "224.0.0.1": true,
}

func TestR25NoObservedPeerAddressInSources(t *testing.T) {
	ipv4 := regexp.MustCompile(`(?:^|[^\w.])((?:\d{1,3}\.){3}\d{1,3})(?:[^\w.]|$|\.[^\d])`)
	allowed := map[string]bool{}
	for _, s := range config.Mainnet_seed_nodes {
		if h, _, err := net.SplitHostPort(s); err == nil {
			allowed[h] = true
		}
	}
	doc := []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15", "240.0.0.0/4"}
	reserved := func(ip net.IP) bool {
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return true
		}
		if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 { // CGNAT
			return true
		}
		for _, n := range doc {
			if _, nw, _ := net.ParseCIDR(n); nw.Contains(ip) {
				return true
			}
		}
		return false
	}
	var files []string
	for _, g := range []string{"*.go", "../cmd/derod/*.go"} {
		m, _ := filepath.Glob(g)
		files = append(files, m...)
	}
	if len(files) < 50 {
		t.Fatalf("only %d sources", len(files))
	}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range ipv4.FindAllStringSubmatch(string(src), -1) {
			ip := net.ParseIP(m[1])
			if ip == nil || reserved(ip) || allowed[m[1]] || r25_known_literals[m[1]] {
				continue
			}
			t.Errorf("%s: IPv4 %s is neither a seed node, a documentation address nor a known fixture (B70)", f, m[1])
		}
	}
}

// Report-only fact (r25): PENALTY_POINTS says "two in a short time ban" for invalid_pow, but the score decays
// continuously, so 50 + 50*0.5^(dt/600 s) < 100 for any dt > 0: two invalid-PoW blocks ban only if scored at the same
// instant, and a third is needed in practice. Pinned here so a change of the policy is a decision, not an accident.
func TestR25TwoInvalidPowDoNotBan(t *testing.T) {
	reset_penalty(t)
	now := time.Unix(2_000_000_000, 0)
	add_penalty("192.0.2.88", "invalid_pow", now)
	if secs := add_penalty("192.0.2.88", "invalid_pow", now.Add(time.Millisecond)); secs != 0 {
		t.Fatal("two invalid_pow 1 ms apart banned")
	}
	if secs := add_penalty("192.0.2.88", "invalid_pow", now.Add(2*time.Millisecond)); secs == 0 {
		t.Fatal("three invalid_pow did not ban")
	}
}

// CO24-N1: the ring stays newest-first however many offences a record collects (also past the uint32 counter).
func TestR25OffenceRingOrderAndSaturation(t *testing.T) {
	m := &misbehaviour{}
	now := time.Unix(2_000_000_000, 0)
	for i := 0; i < 11; i++ {
		m.note(fmt.Sprintf("r%d", i), now.Add(time.Duration(i)*time.Second))
	}
	r := m.recent()
	if len(r) != PENALTY_LAST_REASONS || r[0].Reason != "r10" || r[1].Reason != "r9" || r[3].Reason != "r7" || m.events != 11 {
		t.Fatalf("ring %v events %d", r, m.events)
	}
	m.events = ^uint32(0) - 1
	m.note("x", now)
	m.note("y", now)
	if r := m.recent(); m.events != ^uint32(0) || r[0].Reason != "y" || r[1].Reason != "x" || r[2].Reason != "r10" {
		t.Fatalf("saturated: events %d ring %v", m.events, r)
	}
	if r := (&misbehaviour{}).recent(); r == nil || len(r) != 0 {
		t.Fatalf("empty ring %v", r)
	}
}

// CO24-N1: a peer that keeps tripping a cheap rule gets 8 lines, then one per 64 offences (no log flood).
func TestR25OffenceLogBounded(t *testing.T) {
	reset_penalty(t)
	saved := nonbanlist
	defer func() { nonbanlist = saved }()
	nonbanlist = []string{"192.0.2.89:11011"} // never banned, so all 200 offences are below-ban offences
	s := &level_sink{}
	c := out_conn("192.0.2.89")
	c.logger = logr.New(s)
	for i := 0; i < 200; i++ {
		c.penalize("busy")
	}
	if len(s.infos) != PENALTY_LOG_FIRST+200/PENALTY_LOG_EVERY || s.errors != 0 {
		t.Fatalf("%d offence lines for 200 offences, want %d", len(s.infos), PENALTY_LOG_FIRST+200/PENALTY_LOG_EVERY)
	}
	for _, lv := range s.infos {
		if lv != 1 {
			t.Fatalf("offence line at V(%d), want V(1) (file log only)", lv)
		}
	}
}
