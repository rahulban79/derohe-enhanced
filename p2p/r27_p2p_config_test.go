package p2p

// r27 (group p2p-config; dero-rft §7 B99, B47, sweep gaps): the B99 rules made observable, a loopback scenario that
// drives the real sync path into a hold, its decay and its forgiveness, and the 0 % paths of the r26 sweep
// (load_ban_list, ban_clean_up_goroutine, Consensus_Counters_Snapshot, sync_chain / fetch_blocks /
// process_object_response). Simulator chain in a temp dir and a fake peer on 127.0.0.1:<ephemeral> only: never the
// live store, never port 11011.

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cenkalti/rpc2"
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/metrics"
	"github.com/go-logr/logr"
)

// ---- B99 observability: decay and served-forgiveness are counted ------------------------------------------------

func TestR27StrikeDecayIsCounted(t *testing.T) {
	c := out_conn("192.0.2.170")
	now := time.Unix(2_000_000_000, 0)
	before := sync_strike_decays_total.Get()
	c.sync_failed(call_failure_short, now) // first ever: nothing to decay
	c.sync_failed(call_failure_short, now.Add(31*time.Second))
	if got := sync_strike_decays_total.Get() - before; got != 0 {
		t.Fatalf("no decay happened, counted %d", got)
	}
	end := time.Unix(0, c.obs.sync_hold_until.Load())
	c.sync_failed(call_failure_remote, end.Add(SYNC_STRIKE_FORGET+time.Second))
	if got := sync_strike_decays_total.Get() - before; got != 1 || c.obs.sync_strikes.Load() != 1 {
		t.Fatalf("a decay must be counted once and restart at strike 1: counted %d strikes %d", got, c.obs.sync_strikes.Load())
	}
}

func TestR27SyncSucceededReportsCleared(t *testing.T) {
	c := out_conn("192.0.2.171")
	if c.sync_succeeded() {
		t.Fatal("nothing to clear, reported cleared")
	}
	c.sync_failed(call_failure_short, time.Now())
	if !c.sync_succeeded() || c.obs.sync_strikes.Load() != 0 || c.obs.sync_hold_until.Load() != 0 {
		t.Fatal("a held peer must be reported cleared and be cleared")
	}
}

// a block accepted while sync_chain runs on the connection is a sync that served, not a relay (r26 counted relay)
func TestR27ForgivenessCountedByPath(t *testing.T) {
	c := out_conn("192.0.2.172")
	c.Height.Store(10)
	r0, s0 := sync_relay_forgiven_total.Get(), sync_served_forgiven_total.Get()
	c.sync_failed(call_failure_short, time.Now())
	c.Syncing.Add(1)
	c.sync_relay_served(10)
	c.Syncing.Add(-1)
	if sync_relay_forgiven_total.Get() != r0 || sync_served_forgiven_total.Get() != s0+1 {
		t.Fatalf("during a sync: relay +%d served +%d (want 0, 1)", sync_relay_forgiven_total.Get()-r0, sync_served_forgiven_total.Get()-s0)
	}
	c.sync_failed(call_failure_short, time.Now())
	c.sync_relay_served(10)
	if sync_relay_forgiven_total.Get() != r0+1 || sync_served_forgiven_total.Get() != s0+1 {
		t.Fatalf("a relay: relay +%d served +%d (want 1, 1)", sync_relay_forgiven_total.Get()-r0, sync_served_forgiven_total.Get()-s0)
	}
}

func TestR27B99CountersOnMetricsFromStart(t *testing.T) {
	for _, n := range []string{"p2p_sync_strike_decays_total", "p2p_sync_served_forgiven_total", "p2p_sync_relay_forgiven_total",
		"p2p_sync_peer_holds_total", "p2p_sync_held_fallbacks_total", "p2p_bans_loaded_total", "p2p_bans_active"} {
		found := false
		for _, m := range metrics.Set.ListMetricNames() {
			if m == n {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s is not registered from start", n)
		}
	}
}

// ---- the loopback scenario: hold -> held -> decay -> forgiven, on the real trigger_sync / sync_chain path --------

// r27_fake_peer answers Peer.Chain with one block id we do not have and Peer.GetObject either with no block (a short
// answer, the B47 class) or with that block.
type r27_fake_peer struct {
	serve  atomic.Bool
	chains atomic.Int32
	gets   atomic.Int32
	mu     sync.Mutex
	blid   [32]byte
	cb     Complete_Block
	height int64
	topo   int64
}

func (p *r27_fake_peer) set(blid [32]byte, cb Complete_Block, height, topo int64) {
	p.mu.Lock()
	p.blid, p.cb, p.height, p.topo = blid, cb, height, topo
	p.mu.Unlock()
}

func (p *r27_fake_peer) start(t *testing.T) net.Conn {
	srv := rpc2.NewServer()
	srv.Handle("Peer.Chain", func(_ *rpc2.Client, _ Chain_Request_Struct, r *Chain_Response_Struct) error {
		p.chains.Add(1)
		p.mu.Lock()
		defer p.mu.Unlock()
		r.Common.Height, r.Common.TopoHeight = p.height, p.topo
		r.Start_height, r.Start_topoheight = p.height, p.topo
		r.Block_list = [][32]byte{p.blid}
		return nil
	})
	srv.Handle("Peer.GetObject", func(_ *rpc2.Client, req ObjectList, r *Objects) error {
		p.gets.Add(1)
		if p.serve.Load() && len(req.Block_list) == 1 {
			p.mu.Lock()
			r.CBlocks = []Complete_Block{p.cb}
			p.mu.Unlock()
		}
		return nil // no block = fewer blocks than asked
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.ServeCodec(NewCBORCodec(c))
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

type r27_scenario_step struct {
	Step          string `json:"step"`
	ChainCalls    int32  `json:"chain_calls"`
	GetObjects    int32  `json:"getobject_calls"`
	Strikes       int32  `json:"strikes"`
	HoldSeconds   int64  `json:"hold_seconds"`
	Holds         uint64 `json:"p2p_sync_peer_holds_total"`
	Short         uint64 `json:"p2p_sync_short_answers_total"`
	Decays        uint64 `json:"p2p_sync_strike_decays_total"`
	Served        uint64 `json:"p2p_sync_served_forgiven_total"`
	Relay         uint64 `json:"p2p_sync_relay_forgiven_total"`
	Fallbacks     uint64 `json:"p2p_sync_held_fallbacks_total"`
	OurHeight     int64  `json:"our_height"`
	PeerAdvHeight int64  `json:"peer_height"`
}

func TestR27SyncHoldLoopbackScenario(t *testing.T) {
	r25_reset(t)
	ch := r26_sim_chain(t, 4)
	miner := r25_genesis_miner(t)
	saved_last := sync_fallback_last.Load()
	defer sync_fallback_last.Store(saved_last)
	connection_map.Range(func(k, v interface{}) bool { connection_map.Delete(k); return true })
	defer connection_map.Range(func(k, v interface{}) bool { connection_map.Delete(k); return true })

	peer := &r27_fake_peer{}
	conn := peer.start(t)
	cl := rpc2.NewClientWithCodec(NewCBORCodec(conn))
	go cl.Run()
	defer cl.Close()
	sink := &r25_sink{}
	c := &Connection{Peer_ID: 0x2701, Client: cl, logger: logr.New(sink), Addr: &net.UDPAddr{IP: net.ParseIP("192.0.2.173"), Port: 11011}}
	c.State.Store(ACTIVE)
	connection_map.Store(Address(c), c)

	// the block the peer advertises: a valid next block of OUR chain, not yet added
	next := func() {
		cbl, _, err := ch.Create_new_miner_block(miner)
		if err != nil {
			t.Fatal(err)
		}
		cbl.Bl.MiniBlocks = append(cbl.Bl.MiniBlocks, blockchain.ConvertBlockToMiniblock(*cbl.Bl, miner))
		peer.set(cbl.Bl.GetHash(), Complete_Block{Block: cbl.Bl.Serialize()}, int64(cbl.Bl.Height), ch.Load_TOPO_HEIGHT()+1)
		c.Height.Store(int64(cbl.Bl.Height))
	}
	next()
	h0 := ch.Get_Height()
	base := r27_scenario_step{Holds: sync_peer_holds_total.Get(), Short: sync_short_answers_total.Get(), Decays: sync_strike_decays_total.Get(),
		Served: sync_served_forgiven_total.Get(), Relay: sync_relay_forgiven_total.Get(), Fallbacks: sync_held_fallbacks_total.Get()}
	var steps []r27_scenario_step
	read := func(step string) r27_scenario_step {
		hold := int64(0)
		if u := c.obs.sync_hold_until.Load(); u > time.Now().UnixNano() {
			hold = (u - time.Now().UnixNano()) / int64(time.Second)
		}
		s := r27_scenario_step{Step: step, ChainCalls: peer.chains.Load(), GetObjects: peer.gets.Load(), Strikes: c.obs.sync_strikes.Load(),
			HoldSeconds: hold, Holds: sync_peer_holds_total.Get() - base.Holds, Short: sync_short_answers_total.Get() - base.Short,
			Decays: sync_strike_decays_total.Get() - base.Decays, Served: sync_served_forgiven_total.Get() - base.Served,
			Relay: sync_relay_forgiven_total.Get() - base.Relay, Fallbacks: sync_held_fallbacks_total.Get() - base.Fallbacks,
			OurHeight: ch.Get_Height(), PeerAdvHeight: c.Height.Load()}
		steps = append(steps, s)
		return s
	}

	// 1. the peer answers the sync fetch with no block: a short answer holds it (strike 1, 30 s)
	trigger_sync()
	s := read("short-answer")
	if s.ChainCalls != 1 || s.GetObjects != 1 || s.Strikes != 1 || s.Holds != 1 || s.Short != 1 || s.HoldSeconds < 28 {
		t.Fatalf("step 1 %+v", s)
	}
	// 2. inside its hold, with the fallback slot just used, the held peer is not asked again
	sync_fallback_last.Store(time.Now().UnixNano())
	trigger_sync()
	s = read("held")
	if s.ChainCalls != 1 || s.Strikes != 1 {
		t.Fatalf("step 2: a held peer was asked %+v", s)
	}
	// 3. the fallback slot opens (B99 rule 3): the only peer ahead is held, so pass 1 tries it; it fails again
	sync_fallback_last.Store(0)
	trigger_sync()
	s = read("fallback")
	if s.ChainCalls != 2 || s.Strikes != 2 || s.Fallbacks != 1 || s.HoldSeconds < 58 {
		t.Fatalf("step 3 %+v", s)
	}
	// 4. the hold ended more than SYNC_STRIKE_FORGET ago (rewound, the only forged state): the next short answer
	//    decays the strike to 1 instead of escalating to 2, and the decay is counted
	c.obs.sync_hold_until.Store(time.Now().Add(-SYNC_STRIKE_FORGET - time.Minute).UnixNano())
	trigger_sync()
	s = read("decayed")
	if s.ChainCalls != 3 || s.Strikes != 1 || s.Decays != 1 || s.Holds != 3 || s.HoldSeconds < 28 {
		t.Fatalf("step 4 %+v", s)
	}
	// 5. a failure inside the window escalates (strike 2, 60 s) and is not a decay
	c.obs.sync_hold_until.Store(time.Now().Add(-time.Second).UnixNano())
	trigger_sync()
	s = read("escalated")
	if s.ChainCalls != 4 || s.Strikes != 2 || s.Decays != 1 || s.HoldSeconds < 58 {
		t.Fatalf("step 5 %+v", s)
	}
	// 6. hold over; now the peer serves the block: our height reaches its claim, the peer is forgiven by the sync
	//    path (served), not counted as a relay
	c.obs.sync_hold_until.Store(time.Now().Add(-time.Second).UnixNano())
	peer.serve.Store(true)
	trigger_sync()
	s = read("served")
	if s.OurHeight != h0+1 || s.Strikes != 0 || s.HoldSeconds != 0 || s.Served != 1 || s.Relay != 0 {
		t.Fatalf("step 6 %+v (lines %d)", s, len(sink.lines))
	}
	// 7. the next block: the peer fails again (strike 1)
	peer.serve.Store(false)
	next()
	h1 := ch.Get_Height()
	trigger_sync()
	s = read("short-again")
	if s.Strikes != 1 || s.Holds != 5 || s.OurHeight != h1 {
		t.Fatalf("step 7 %+v", s)
	}
	// 8. it serves that block but claims one more: the block leaves us below its claim, so the relay rule does not
	//    forgive; the sync round added blocks, so trigger_sync forgives it (r25 rule) and counts it as served
	c.obs.sync_hold_until.Store(time.Now().Add(-time.Second).UnixNano())
	peer.serve.Store(true)
	c.Height.Store(c.Height.Load() + 1)
	trigger_sync()
	s = read("served-partial")
	if s.OurHeight != h1+1 || s.Strikes != 0 || s.Served != 2 || s.Relay != 0 {
		t.Fatalf("step 8 %+v", s)
	}
	if out := os.Getenv("R27_B99_SCENARIO_OUT"); out != "" {
		b, _ := json.MarshalIndent(map[string]interface{}{"scenario": "r27 B99 loopback", "steps": steps}, "", " ")
		if err := os.WriteFile(out, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, x := range steps {
		t.Logf("R27-B99 %+v", x)
	}
}

// ---- sweep gaps: the persisted ban list reload and the cleanup loop ----------------------------------------------

func r27_reset_bans(t *testing.T) {
	ban_mutex.Lock()
	om, ox := ban_map, ban_meta
	ban_map, ban_meta = map[string]uint64{}, map[string]ban_info{}
	ban_gen++
	ban_mutex.Unlock()
	t.Cleanup(func() {
		ban_mutex.Lock()
		ban_map, ban_meta = om, ox
		ban_gen++
		ban_mutex.Unlock()
	})
}

func TestR27LoadBanListWithReasons(t *testing.T) {
	r27_reset_bans(t)
	dir := t.TempDir()
	now := uint64(time.Now().Unix())
	list := map[string]uint64{"192.0.2.180": now + 3600, "198.51.100.0/24": now + 600, "203.0.113.9": now - 5}
	reasons := map[string]ban_info{"192.0.2.180": {Source: BAN_SOURCE_V2, Reason: "v2 chain", At: 7},
		"203.0.113.9": {Source: BAN_SOURCE_SCORE, At: 8}, "203.0.113.77": {Source: BAN_SOURCE_OPERATOR, At: 9}}
	for f, v := range map[string]interface{}{"ban_list.json": list, "ban_reasons.json": reasons} {
		b, _ := json.Marshal(v)
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	l0 := bans_loaded_total.Get()
	load_ban_list_from(dir)
	if Ban_Count() != 2 || bans_loaded_total.Get()-l0 != 2 {
		t.Fatalf("running bans %d loaded +%d (want 2, 2: the expired one is dropped)", Ban_Count(), bans_loaded_total.Get()-l0)
	}
	if !IsAddressInBanList("192.0.2.180") || !IsAddressInBanList("198.51.100.44") || IsAddressInBanList("203.0.113.9") {
		t.Fatal("the reloaded list (and its subnet) must be enforced, the expired entry not")
	}
	got, total, by := BanInfos(-1, time.Now())
	if total != 2 || by[BAN_SOURCE_V2] != 1 || by[BAN_SOURCE_UNATTRIBUTED] != 1 {
		t.Fatalf("sources %v total %d", by, total)
	}
	ban_mutex.Lock()
	_, stray := ban_meta["203.0.113.77"]
	_, expired := ban_meta["203.0.113.9"]
	ban_mutex.Unlock()
	if stray || expired {
		t.Fatal("a reason without a running ban was kept")
	}
	_ = got
	if v := r27_metric(t, "p2p_bans_active"); v != "2" {
		t.Fatalf("p2p_bans_active = %q", v)
	}
	// no file: nothing loaded, nothing counted
	l1 := bans_loaded_total.Get()
	load_ban_list_from(t.TempDir())
	if bans_loaded_total.Get() != l1 {
		t.Fatal("a missing ban_list.json counted loaded bans")
	}
}

func TestR27BanCleanUpLoopDropsExpiredAndExits(t *testing.T) {
	r27_reset_bans(t)
	ban_mutex.Lock()
	ban_map["192.0.2.181"] = uint64(time.Now().Unix()) - 1
	ban_meta["192.0.2.181"] = ban_info{Source: BAN_SOURCE_SCORE}
	ban_map["192.0.2.182"] = uint64(time.Now().Unix()) + 3600
	ban_mutex.Unlock()
	exit := make(chan bool)
	done := make(chan struct{})
	go func() { ban_clean_up_loop(10*time.Millisecond, exit); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for Ban_Count() != 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	ban_mutex.Lock()
	_, meta := ban_meta["192.0.2.181"]
	ban_mutex.Unlock()
	if Ban_Count() != 1 || meta {
		t.Fatalf("the loop did not drop the expired ban (count %d, meta kept %v)", Ban_Count(), meta)
	}
	close(exit)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not exit on the exit channel")
	}
}

// ---- sweep gap: Consensus_Counters_Snapshot (the source of GetConsensusStats counters) ---------------------------

func TestR27ConsensusCountersSnapshot(t *testing.T) {
	r25_reset(t)
	c := &Connection{Peer_ID: 0x2702, logger: logr.Discard()}
	c.refuse_miniblock(MBL_REFUSED_STALE, 1, fmt.Errorf("x"))
	c.refuse_miniblock(MBL_REFUSED_DUPLICATE, 2, fmt.Errorf("x"))
	c.refuse_miniblock(MBL_REFUSED_DUPLICATE, 3, fmt.Errorf("x"))
	d0 := block_duplicates.Get()
	block_duplicates.Inc()
	s := Consensus_Counters_Snapshot()
	if s.MiniblockRefusedTotal != 3 || s.MiniblockRefused[MBL_REFUSED_DUPLICATE] != 2 || s.MiniblockRefused[MBL_REFUSED_STALE] != 1 {
		t.Fatalf("miniblock refusals %+v", s)
	}
	if s.BlockRejectedTotal != 0 || s.BlockOfferDuplicates != d0+1 {
		t.Fatalf("blocks %+v (dups want %d)", s, d0+1)
	}
}

func r27_metric(t *testing.T, name string) string {
	t.Helper()
	var b strings.Builder
	metrics.Set.WritePrometheus(&b)
	for _, l := range strings.Split(b.String(), "\n") {
		if len(l) > len(name) && l[:len(name)+1] == name+" " {
			return l[len(name)+1:]
		}
	}
	return ""
}
