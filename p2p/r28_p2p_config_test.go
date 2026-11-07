package p2p

// r28 (group p2p-config; dero-rft §7 B57, B48, L24-21): deterministic reproductions of the events the live r27 node
// never had (0 block rejections, 0 inbound), each recorded with the same /metrics series the live node exports, and
// the chunk-path PoW census (r28_chunk_pow.go). Simulator chain in a temp dir and in-process connections only: never
// the live store, never port 11011, never the live derod. Each scenario writes its steps as JSON when
// R28_EVENT_OUT_DIR is set (harness/intel/event_scenarios.py reads them and checks the rules).

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/time/rate"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/rpc"
)

// r28_metric_values reads every series of /metrics whose name starts with prefix (labels included), as the live
// scrape would see it.
func r28_metric_values(prefix string) map[string]float64 {
	var b strings.Builder
	metrics.Set.WritePrometheus(&b)
	out := map[string]float64{}
	for _, l := range strings.Split(b.String(), "\n") {
		if !strings.HasPrefix(l, prefix) {
			continue
		}
		i := strings.LastIndexByte(l, ' ')
		if i < 0 {
			continue
		}
		if v, err := strconv.ParseFloat(l[i+1:], 64); err == nil {
			out[l[:i]] = v
		}
	}
	return out
}

func r28_write_record(t *testing.T, name string, rec interface{}) {
	t.Helper()
	dir := os.Getenv("R28_EVENT_OUT_DIR")
	if dir == "" {
		return
	}
	b, _ := json.MarshalIndent(rec, "", " ")
	if err := os.WriteFile(filepath.Join(dir, name+".json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// ---- L24-21: chunk_pow_valid counts, keeps the order and stops at the first invalid PoW ----------------------------

type r28_clock struct{ t time.Time }

func (c *r28_clock) now() time.Time { return c.t }

func TestR28ChunkPowValidCountsAndStops(t *testing.T) {
	mbls := make([]block.MiniBlock, 10)
	for i := range mbls {
		mbls[i].Height = uint64(i)
	}
	clk := &r28_clock{t: time.Unix(1_800_000_000, 0)}
	var order []uint64
	b0, c0, p0, s0, sec0 := chunk_pow_blocks.Get(), chunk_pow_checks.Get(), chunk_pow_pool_seen.Get(), chunk_pow_slow.Get(), chunk_pow_seconds.Get()
	seen := func(m block.MiniBlock) bool { return m.Height < 9 } // 9 regular ones arrived as miniblocks first
	verify := func(m block.MiniBlock) bool {
		order = append(order, m.Height)
		if m.Height == 9 { // the final one: computed, 3 ms
			clk.t = clk.t.Add(3 * time.Millisecond)
		} else {
			clk.t = clk.t.Add(20 * time.Microsecond)
		}
		return true
	}
	if !chunk_pow_valid(mbls, seen, verify, clk.now) {
		t.Fatal("all valid, reported invalid")
	}
	if fmt.Sprint(order) != "[0 1 2 3 4 5 6 7 8 9]" {
		t.Fatalf("order %v", order)
	}
	if chunk_pow_blocks.Get()-b0 != 1 || chunk_pow_checks.Get()-c0 != 10 || chunk_pow_pool_seen.Get()-p0 != 9 || chunk_pow_slow.Get()-s0 != 1 {
		t.Fatalf("blocks +%d checks +%d pool_seen +%d slow +%d (want 1, 10, 9, 1)", chunk_pow_blocks.Get()-b0,
			chunk_pow_checks.Get()-c0, chunk_pow_pool_seen.Get()-p0, chunk_pow_slow.Get()-s0)
	}
	if d := chunk_pow_seconds.Get() - sec0; d < 0.00317 || d > 0.00319 {
		t.Fatalf("loop seconds +%v, want 0.00318", d)
	}
	// the first invalid PoW stops the loop (the caller penalizes and returns ErrInvalidPoW, as before)
	order = nil
	c1 := chunk_pow_checks.Get()
	bad := func(m block.MiniBlock) bool { order = append(order, m.Height); return m.Height != 3 }
	if chunk_pow_valid(mbls, nil, bad, clk.now) {
		t.Fatal("miniblock 3 invalid, reported valid")
	}
	if fmt.Sprint(order) != "[0 1 2 3]" || chunk_pow_checks.Get()-c1 != 4 {
		t.Fatalf("after an invalid PoW: order %v checks +%d (want [0 1 2 3], 4)", order, chunk_pow_checks.Get()-c1)
	}
	// exactly at the threshold counts as slow; one tick below does not
	s1 := chunk_pow_slow.Get()
	step := []time.Duration{CHUNK_POW_SLOW, CHUNK_POW_SLOW - time.Nanosecond}
	k := 0
	tick := func(m block.MiniBlock) bool { clk.t = clk.t.Add(step[k]); k++; return true }
	chunk_pow_valid(mbls[:2], nil, tick, clk.now)
	if chunk_pow_slow.Get()-s1 != 1 {
		t.Fatalf("threshold: slow +%d, want 1", chunk_pow_slow.Get()-s1)
	}
}

func TestR28ChunkPowCountersOnMetricsFromStart(t *testing.T) {
	names := metrics.Set.ListMetricNames()
	for _, n := range []string{"p2p_chunk_pow_blocks_total", "p2p_chunk_pow_checks_total", "p2p_chunk_pow_pool_seen_total",
		"p2p_chunk_pow_slow_total", "p2p_chunk_pow_verify_seconds_total"} {
		found := false
		for _, m := range names {
			found = found || m == n
		}
		if !found {
			t.Fatalf("%s is not registered from start", n)
		}
	}
	s := Chunk_Pow_Stats()
	if s.Checks != chunk_pow_checks.Get() || s.PoolSeen != chunk_pow_pool_seen.Get() || s.Slow != chunk_pow_slow.Get() {
		t.Fatalf("Chunk_Pow_Stats %+v disagrees with the counters", s)
	}
}

// ---- the chunk loopback scenario: warm / cold PoW census (L24-21) and an attributed rejection (B57) --------------

// r28_block builds the next block of ch with 9 regular miniblocks and a final one whose PoW passes at simulator
// difficulty (×9 for the final: about 1 in 9 nonces). ts, when non-zero, replaces the block timestamp first.
func r28_block(t *testing.T, ch *blockchain.Blockchain, miner rpc.Address, ts uint64) *block.Complete_Block {
	t.Helper()
	cbl, _, err := ch.Create_new_miner_block(miner)
	if err != nil {
		t.Fatal(err)
	}
	if ts != 0 {
		cbl.Bl.Timestamp = ts
	}
	for i := 0; i < 9; i++ {
		cbl.Bl.MiniBlocks = append(cbl.Bl.MiniBlocks, blockchain.ConvertBlockToMiniblock(*cbl.Bl, miner))
	}
	for i := 0; ; i++ {
		f := blockchain.ConvertBlockToMiniblock(*cbl.Bl, miner)
		var probe block.Block = *cbl.Bl
		probe.MiniBlocks = append(append([]block.MiniBlock{}, cbl.Bl.MiniBlocks...), f)
		if r28_final_ok(ch, &probe, f) {
			cbl.Bl.MiniBlocks = append(cbl.Bl.MiniBlocks, f)
			return cbl
		}
		if i > 400 {
			t.Fatal("no final miniblock nonce passed in 400 tries")
		}
	}
}

// r28_final_ok checks a candidate final miniblock WITHOUT leaving a cached verdict that the scenario would then count
// as a hit: VerifyMiniblockPoW caches true verdicts under (tips, miniblock), so the grind is done on a copy whose
// tips differ (one extra tip byte flipped), which has the same difficulty in simulator mode (always 1, ×9 final).
func r28_final_ok(ch *blockchain.Blockchain, bl *block.Block, f block.MiniBlock) bool {
	var other block.Block = *bl
	other.Tips = append([]crypto.Hash(nil), bl.Tips...)
	other.Tips[0][31] ^= 0xff
	return ch.VerifyMiniblockPoW(&other, f)
}

// r28_chunks returns the chunks of cbl as a peer would send them (built by our own encoder, then forgotten so that
// feed_chunk sees them as new).
func r28_chunks(t *testing.T, cbl *block.Complete_Block) []*Block_Chunk {
	t.Helper()
	hh, n := convert_block_to_chunks(cbl, 10, 10)
	key := fmt.Sprintf("%x", hh)
	v, ok := chunk_map.Load(key)
	if !ok || n != 20 {
		t.Fatalf("chunks not built (%d)", n)
	}
	var out []*Block_Chunk
	for _, c := range v.(*Chunks_Per_Block_Data).ChunkCollection {
		if c != nil {
			out = append(out, c)
		}
	}
	chunk_map.Delete(key)
	return out
}

type r28_chunk_step struct {
	Step             string             `json:"step"`
	Item             string             `json:"item"`
	Blocks           uint64             `json:"p2p_chunk_pow_blocks_total"`
	Checks           uint64             `json:"p2p_chunk_pow_checks_total"`
	PoolSeen         uint64             `json:"p2p_chunk_pow_pool_seen_total"`
	Slow             uint64             `json:"p2p_chunk_pow_slow_total"`
	LoopMs           float64            `json:"loop_ms"`
	HeightBefore     int64              `json:"height_before"`
	HeightAfter      int64              `json:"height_after"`
	Rejected         map[string]float64 `json:"blockchain_block_rejected_total"`
	StatsRejected    map[string]uint64  `json:"getconsensusstats_block_rejected"`
	RejectLines      int                `json:"block_rejected_lines"`
	RejectLinePeerID string             `json:"reject_line_peer_id"`
	RejectLineReason string             `json:"reject_line_reason"`
	RejectLineLevel  int                `json:"reject_line_level"`
	LineHasAddress   bool               `json:"reject_line_has_address"`
}

func TestR28ChunkLoopbackScenario(t *testing.T) {
	r25_reset(t)
	ch := r26_sim_chain(t, 4)
	miner := r25_genesis_miner(t)
	connection_map.Range(func(k, v interface{}) bool { connection_map.Delete(k); return true })
	defer connection_map.Range(func(k, v interface{}) bool { connection_map.Delete(k); return true })
	sink := &r25_sink{}
	logger = logr.New(sink)
	const peer_ip = "192.0.2.201"
	c := &Connection{Peer_ID: 0x2801, logger: logr.New(&r25_sink{}), Addr: &net.UDPAddr{IP: net.ParseIP(peer_ip), Port: 11011}}
	c.State.Store(ACTIVE)

	var steps []r28_chunk_step
	run := func(step, item string, cbl *block.Complete_Block) r28_chunk_step {
		b0, c0, p0, s0, sec0 := chunk_pow_blocks.Get(), chunk_pow_checks.Get(), chunk_pow_pool_seen.Get(), chunk_pow_slow.Get(), chunk_pow_seconds.Get()
		rj0 := r28_metric_values("blockchain_block_rejected_total")
		lines0 := len(sink.find("Block rejected"))
		h0 := ch.Get_Height()
		for _, x := range r28_chunks(t, cbl) {
			c.feed_chunk(x, 0)
		}
		s := r28_chunk_step{Step: step, Item: item, Blocks: chunk_pow_blocks.Get() - b0, Checks: chunk_pow_checks.Get() - c0,
			PoolSeen: chunk_pow_pool_seen.Get() - p0, Slow: chunk_pow_slow.Get() - s0, LoopMs: (chunk_pow_seconds.Get() - sec0) * 1000,
			HeightBefore: h0, HeightAfter: ch.Get_Height(), Rejected: map[string]float64{}}
		for k, v := range r28_metric_values("blockchain_block_rejected_total") {
			if d := v - rj0[k]; d != 0 {
				s.Rejected[k] = d
			}
		}
		s.StatsRejected = Consensus_Counters_Snapshot().BlockRejected
		lines := sink.find("Block rejected")
		s.RejectLines = len(lines) - lines0
		if s.RejectLines > 0 {
			l := lines[len(lines)-1]
			s.RejectLinePeerID, s.RejectLineReason, s.RejectLineLevel = fmt.Sprint(l.kv["peer_id"]), fmt.Sprint(l.kv["reason"]), l.level
			for _, v := range l.kv {
				s.LineHasAddress = s.LineHasAddress || strings.Contains(fmt.Sprint(v), peer_ip)
			}
		}
		steps = append(steps, s)
		return s
	}

	// 1. warm (the live order): the 9 regular miniblocks reach us first through NotifyMiniBlock, which verifies and
	//    pools them; the chunks follow. The 9 checks find their miniblock in the pool, only the final one computes.
	warm := r28_block(t, ch, miner, 0)
	for i := 0; i < 9; i += 3 {
		var req Objects
		for _, m := range warm.Bl.MiniBlocks[i : i+3] {
			req.MiniBlocks = append(req.MiniBlocks, m.Serialize())
		}
		if err := c.NotifyMiniBlock(req, &Dummy{}); err != nil {
			t.Fatalf("NotifyMiniBlock: %v", err)
		}
	}
	s := run("warm", "L24-21", warm)
	if s.Blocks != 1 || s.Checks != 10 || s.PoolSeen != 9 || s.HeightAfter != s.HeightBefore+1 {
		t.Fatalf("warm %+v", s)
	}
	// 2. cold: the same block shape, but no miniblock was notified: no check finds its miniblock in the pool
	cold := r28_block(t, ch, miner, 0)
	s = run("cold", "L24-21", cold)
	if s.Blocks != 1 || s.Checks != 10 || s.PoolSeen != 0 || s.HeightAfter != s.HeightBefore+1 {
		t.Fatalf("cold %+v", s)
	}
	// 3. B57: a relayed block one hour in the future passes the chunk checks and is rejected by the chain: counted by
	//    reason on /metrics and in GetConsensusStats, logged on the console level naming the sender's peer_id only
	future := r28_block(t, ch, miner, uint64(time.Now().Add(time.Hour).UnixMilli()))
	s = run("rejected-future", "B57", future)
	if s.HeightAfter != s.HeightBefore || s.Rejected[`blockchain_block_rejected_total{reason="future_timestamp"}`] != 1 || len(s.Rejected) != 1 ||
		s.StatsRejected["future_timestamp"] != 1 || s.RejectLines != 1 || s.RejectLinePeerID != "0000000000002801" ||
		s.RejectLineReason != "future_timestamp" || s.RejectLineLevel != 0 || s.LineHasAddress {
		t.Fatalf("rejected %+v", s)
	}
	r28_write_record(t, "chunk_scenario", map[string]interface{}{"scenario": "r28 chunk loopback (L24-21, B57)",
		"chunk_pow_slow_ms": CHUNK_POW_SLOW.Seconds() * 1000, "steps": steps})
	for _, x := range steps {
		t.Logf("R28-CHUNK %+v", x)
	}
}

// ---- B48: the proven-lane quota and the lane itself, through the real admission entry point -----------------------

type r28_proven_step struct {
	Step      string             `json:"step"`
	Admitted  int                `json:"admitted"`
	Refused   int                `json:"refused"`
	Survivors int                `json:"honest_survivors"`
	Groups    int                `json:"netgroups_held"`
	Metrics   map[string]float64 `json:"metrics_delta"`
}

func TestR28ProvenLaneAdmissionScenario(t *testing.T) {
	reset_proven(t)
	connection_map.Range(func(k, v interface{}) bool { connection_map.Delete(k); return true })
	defer connection_map.Range(func(k, v interface{}) bool { connection_map.Delete(k); return true })
	base := r28_metric_values("p2p_inbound_")
	var steps []r28_proven_step
	read := func(step string, admitted, refused int, honest []string) r28_proven_step {
		s := r28_proven_step{Step: step, Admitted: admitted, Refused: refused, Survivors: r25_survivors(honest), Metrics: map[string]float64{}}
		proven_mu.Lock()
		s.Groups = len(proven_groups)
		proven_mu.Unlock()
		for k, v := range r28_metric_values("p2p_inbound_") {
			if strings.Contains(k, "proven") || strings.Contains(k, "netgroup_refusals") {
				s.Metrics[k] = v - base[k]
			}
		}
		steps = append(steps, s)
		return s
	}
	now := time.Now()
	// 1. 100 honest peers in 100 /16s complete a handshake; then one operator completes PROVEN_MAX handshakes from one /16
	honest := r25_honest_proofs(100, now.Add(-time.Hour))
	r25_operator(1, PROVEN_MAX, now.Add(-30*time.Minute))
	s := read("operator-flood", 0, 0, honest)
	if s.Survivors != 100 || s.Metrics["p2p_inbound_proven_quota_evictions_total"] != float64(PROVEN_MAX-PROVEN_PER_NETGROUP) || s.Groups != 101 {
		t.Fatalf("flood %+v", s)
	}
	// 2. the shared accept bucket is drained (a spoofed flood, B30): an honest returning peer still gets in through
	//    the lane, once per PROVEN_PER_IP_INTERVAL; a stranger does not
	drained := rate.NewLimiter(0, 0)
	adm, ref := 0, 0
	for _, ip := range []string{honest[0], honest[0], "203.0.113.250"} {
		if admit_inbound(ip, drained) {
			adm++
		} else {
			ref++
		}
	}
	s = read("lane", adm, ref, honest)
	if adm != 1 || ref != 2 || s.Metrics["p2p_inbound_proven_lane_admits_total"] != 1 || s.Metrics["p2p_inbound_proven_lane_refusals_total"] != 1 {
		t.Fatalf("lane %+v", s)
	}
	// 3. the netgroup cap: a /16 already holding its inbound share is refused before any bucket, and counted
	g := netgroup(honest[1])
	for i := 0; i < inbound_group_cap(g); i++ {
		ic := out_conn(fmt.Sprintf("%s.9.%d", g, i+1))
		ic.Incoming = true
		connection_map.Store(Address(ic), ic)
	}
	open := rate.NewLimiter(rate.Inf, 1)
	ok := admit_inbound(honest[1], open)
	s = read("netgroup-cap", map[bool]int{true: 1}[ok], map[bool]int{false: 1}[ok], honest)
	if ok || s.Metrics["p2p_inbound_netgroup_refusals_total"] != 1 {
		t.Fatalf("cap %+v", s)
	}
	// 4. loopback and LAN proofs are exempt from the quota (why a loopback reproduction cannot exercise it)
	note_proven("127.0.0.1", now)
	note_proven("10.1.2.3", now)
	proven_mu.Lock()
	exempt := proven_map["127.0.0.1"] != nil && proven_map["127.0.0.1"].gn == nil && proven_map["10.1.2.3"] != nil && proven_map["10.1.2.3"].gn == nil
	proven_mu.Unlock()
	s = read("exempt", 0, 0, honest)
	if !exempt || s.Groups != 101 {
		t.Fatalf("exempt %v %+v", exempt, s)
	}
	r28_write_record(t, "proven_scenario", map[string]interface{}{"scenario": "r28 proven lane admission (B48)",
		"proven_max": PROVEN_MAX, "proven_per_netgroup": PROVEN_PER_NETGROUP, "steps": steps})
	for _, x := range steps {
		t.Logf("R28-B48 %+v", x)
	}
}
