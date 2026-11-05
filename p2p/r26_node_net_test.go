package p2p

// r26 (node-net dimension; dero-rft §7 B99, B102, B103): tests with forged inputs and a throw-away simulator chain.
//
//   B103  a duplicate delivered by two peers inside the PoW-verify window is "duplicate_race", not "insert_failed",
//         and every refusal line carries the error text.
//   B99   sync-hold strikes decay, a relayed block that meets the peer's claim forgives it, trigger_sync falls back to
//         held peers (rate-limited) when no unheld peer ahead could sync, Offenders() picks the newest N under the lock.
//   B102  policy pinned: three invalid_pow within one half-life always ban.

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/globals"
	"github.com/go-logr/logr"
)

// r26_sim_chain starts a simulator chain with n blocks mined and makes it the package chain for the test.
func r26_sim_chain(t *testing.T, n int) *blockchain.Blockchain {
	t.Helper()
	if testing.Short() {
		t.Skip("starts a simulator chain")
	}
	old_args := globals.Arguments
	globals.Arguments = map[string]interface{}{"--data-dir": t.TempDir(), "--testnet": true, "--simulator": true}
	globals.Initialize()
	ch, err := blockchain.Blockchain_Start(map[string]interface{}{"--simulator": true})
	if err != nil {
		t.Fatal(err)
	}
	old_chain := chain
	chain = ch
	t.Cleanup(func() {
		chain = old_chain
		ch.Shutdown()
		globals.Arguments = old_args
	})
	miner := r25_genesis_miner(t)
	var c *Connection
	for i := 0; i < n; i++ {
		cbl, _, err := ch.Create_new_miner_block(miner)
		if err != nil {
			t.Fatal(err)
		}
		cbl.Bl.MiniBlocks = append(cbl.Bl.MiniBlocks, blockchain.ConvertBlockToMiniblock(*cbl.Bl, miner))
		if err, ok := c.add_block(cbl); !ok {
			t.Fatalf("block %d: %v", i, err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	return ch
}

// B103: two peers deliver the same valid miniblock; both pass the IsCollision pre-check before either inserts (the
// test hook holds each delivery between VerifyMiniblockPoW and InsertMiniBlock until both are there). One is
// accepted; the other is refused as duplicate_race (r25: insert_failed), returns the collision error unchanged
// (a sender's failure_reason reads it as "duplicate"), is counted as a non-first delivery, and its line names the error.
func TestR26DuplicateRaceCountedNotInsertFailed(t *testing.T) {
	r25_reset(t)
	sink := &r25_sink{}
	logger = logr.New(sink)
	ch := r26_sim_chain(t, 6)
	miner := r25_genesis_miner(t)
	tmpl, _, err := ch.Create_new_miner_block(miner)
	if err != nil {
		t.Fatal(err)
	}
	mbl := blockchain.ConvertBlockToMiniblock(*tmpl.Bl, miner)
	req := Objects{MiniBlocks: [][]byte{mbl.Serialize()}}

	var arrived sync.WaitGroup
	arrived.Add(2)
	both := make(chan struct{})
	go func() { arrived.Wait(); close(both) }()
	mbl_pre_insert_hook = func(block.MiniBlock) {
		arrived.Done()
		select {
		case <-both:
		case <-time.After(10 * time.Second): // a delivery that never reaches the hook must not hang the test
		}
	}
	defer func() { mbl_pre_insert_hook = nil }()

	peers := []*Connection{{Peer_ID: 0x501, logger: logr.Discard()}, {Peer_ID: 0x502, logger: logr.Discard()}}
	errs := make([]error, 2)
	var done sync.WaitGroup
	for i := range peers {
		done.Add(1)
		go func(i int) { defer done.Done(); errs[i] = peers[i].NotifyMiniBlock(req, &Dummy{}) }(i)
	}
	done.Wait()

	accepted, refused := -1, -1
	for i, e := range errs {
		if e == nil {
			accepted = i
		} else {
			refused = i
		}
	}
	if accepted < 0 || refused < 0 {
		t.Fatalf("want one accepted and one refused delivery, got %v", errs)
	}
	if !strings.Contains(errs[refused].Error(), "collision") || failure_reason(errs[refused]) != "duplicate" {
		t.Fatalf("the refused delivery must return the collision error unchanged, got %v", errs[refused])
	}
	m, total := miniblock_refused.snapshot()
	if m[MBL_REFUSED_DUPLICATE] != 1 || m[MBL_REFUSED_INSERT] != 0 || total != 1 {
		t.Fatalf("refusals %v: a duplicate race must not count as insert_failed", m)
	}
	if peers[accepted].mbl_first.Load() != 1 || peers[refused].mbl_dup.Load() != 1 || peers[refused].mbl_first.Load() != 0 {
		t.Fatalf("deliveries: accepted first=%d, refused first=%d dup=%d", peers[accepted].mbl_first.Load(),
			peers[refused].mbl_first.Load(), peers[refused].mbl_dup.Load())
	}
	lines := sink.find("Miniblock refused")
	if len(lines) != 1 || lines[0].kv["reason"] != MBL_REFUSED_DUPLICATE || !strings.HasPrefix(fmt.Sprint(lines[0].kv["error"]), "collision ") {
		t.Fatalf("refusal line %+v", lines)
	}
}

// B103: the classification itself, with forged collision answers.
func TestR26InsertRefusalReason(t *testing.T) {
	c := &Connection{Peer_ID: 1, logger: logr.Discard()}
	var mbl block.MiniBlock
	if r := c.insert_refusal_reason(mbl, func(block.MiniBlock) bool { return false }); r != MBL_REFUSED_INSERT {
		t.Fatalf("no collision after the refusal: %q", r)
	}
	if r := c.insert_refusal_reason(mbl, nil); r != MBL_REFUSED_INSERT || c.mbl_dup.Load() != 0 {
		t.Fatalf("no collision check: %q dup %d", r, c.mbl_dup.Load())
	}
	if r := c.insert_refusal_reason(mbl, func(block.MiniBlock) bool { return true }); r != MBL_REFUSED_DUPLICATE || c.mbl_dup.Load() != 1 {
		t.Fatalf("collision after the refusal: %q dup %d", r, c.mbl_dup.Load())
	}
	found := false
	for _, r := range miniblock_refusal_reasons {
		found = found || r == MBL_REFUSED_DUPLICATE
	}
	if !found {
		t.Fatal("duplicate_race is not pre-registered on /metrics")
	}
}

// B103: every refusal line carries the error text, bounded.
func TestR26RefusalLineCarriesErrorText(t *testing.T) {
	r25_reset(t)
	sink := &r25_sink{}
	logger = logr.New(sink)
	c := &Connection{Peer_ID: 0xabd, logger: logr.Discard()}
	c.refuse_miniblock(MBL_REFUSED_INSERT, 5, fmt.Errorf("Invalid miner address"))
	c.refuse_miniblock(MBL_REFUSED_DUPLICATE, 5, fmt.Errorf("collision %s", strings.Repeat("ab", 400)))
	c.refuse_miniblock(MBL_REFUSED_TIP, 5, nil)
	lines := sink.find("Miniblock refused")
	if len(lines) != 3 || lines[0].kv["error"] != "Invalid miner address" || lines[2].kv["error"] != "" {
		t.Fatalf("lines %+v", lines)
	}
	if e := fmt.Sprint(lines[1].kv["error"]); len(e) != MBL_REFUSAL_ERR_MAX+3 || !strings.HasPrefix(e, "collision abab") {
		t.Fatalf("a long error text must be cut to %d bytes, got %d", MBL_REFUSAL_ERR_MAX, len(e))
	}
}

// B99 (1): a failure long after the previous hold ended starts again at strike 1; one inside the window escalates.
func TestR26SyncStrikesDecay(t *testing.T) {
	c := out_conn("192.0.2.90")
	now := time.Unix(2_000_000_000, 0)
	c.sync_failed(call_failure_short, now)
	c.sync_failed(call_failure_short, now) // strike 2: 60 s
	end := now.Add(time.Minute)
	c.sync_failed(call_failure_remote, end.Add(SYNC_STRIKE_FORGET-time.Second)) // inside the window: strike 3
	if n := c.obs.sync_strikes.Load(); n != 3 {
		t.Fatalf("a failure inside the window must escalate, strikes %d", n)
	}
	last := end.Add(SYNC_STRIKE_FORGET - time.Second).Add(2 * time.Minute) // strike 3 held 2 min
	later := last.Add(SYNC_STRIKE_FORGET + time.Second)
	c.sync_failed(call_failure_short, later)
	if n := c.obs.sync_strikes.Load(); n != 1 || !c.sync_held(later.Add(SYNC_HOLD_BASE-time.Second)) || c.sync_held(later.Add(SYNC_HOLD_BASE)) {
		t.Fatalf("a failure %v after the hold ended must start at strike 1 (30 s), strikes %d", SYNC_STRIKE_FORGET, n)
	}
}

// B99 (2): a relayed block forgives the peer only when it brings us level with what the peer advertises.
func TestR26RelayedBlockForgives(t *testing.T) {
	c := out_conn("192.0.2.91")
	now := time.Now()
	c.sync_failed(call_failure_short, now)
	c.Height.Store(100)
	before := sync_relay_forgiven_total.Get()
	c.sync_relay_served(99)
	if c.obs.sync_strikes.Load() != 1 || !c.sync_held(now) {
		t.Fatal("a peer still claiming more than it delivered must stay held")
	}
	c.sync_relay_served(100)
	if c.obs.sync_strikes.Load() != 0 || c.sync_held(now) || sync_relay_forgiven_total.Get() != before+1 {
		t.Fatal("a relayed block that meets the peer's claim must forgive it (and count)")
	}
	c.sync_relay_served(100) // nothing to forgive: not counted again
	if sync_relay_forgiven_total.Get() != before+1 {
		t.Fatal("a peer with no strikes was counted as forgiven")
	}
	var nilc *Connection
	nilc.sync_relay_served(100) // this node's own block: no connection
}

// B99 (2), wired: note_block_result of an accepted block from a peer forgives it on the real chain height.
func TestR26AcceptedRelayForgivesOnChain(t *testing.T) {
	r25_reset(t)
	ch := r26_sim_chain(t, 3)
	miner := r25_genesis_miner(t)
	p := out_conn("192.0.2.92")
	p.sync_failed(call_failure_remote, time.Now())
	p.Height.Store(ch.Get_Height() + 50) // claims far more than the next block
	cbl, _, err := ch.Create_new_miner_block(miner)
	if err != nil {
		t.Fatal(err)
	}
	cbl.Bl.MiniBlocks = append(cbl.Bl.MiniBlocks, blockchain.ConvertBlockToMiniblock(*cbl.Bl, miner))
	if err, ok := p.add_block(cbl); !ok {
		t.Fatal(err)
	}
	if p.obs.sync_strikes.Load() != 1 {
		t.Fatal("a block that leaves us below the peer's claim must not forgive it")
	}
	cbl2, _, err := ch.Create_new_miner_block(miner)
	if err != nil {
		t.Fatal(err)
	}
	cbl2.Bl.MiniBlocks = append(cbl2.Bl.MiniBlocks, blockchain.ConvertBlockToMiniblock(*cbl2.Bl, miner))
	p.Height.Store(int64(cbl2.Bl.Height))
	if err, ok := p.add_block(cbl2); !ok {
		t.Fatal(err)
	}
	if p.obs.sync_strikes.Load() != 0 || p.sync_held(time.Now()) {
		t.Fatal("an accepted relayed block that meets the claim must forgive the peer")
	}
}

// B99 (3): every peer ahead is held. r25 synced with nobody; now trigger_sync tries the held ones (the hold ending
// soonest first), at most once per SYNC_FALLBACK_EVERY. The peers are forged with a prune height past our tip, so
// each considered peer logs "We cannot resync ..." and no network call is made: the lines show who was considered.
func TestR26TriggerSyncFallsBackToHeldPeers(t *testing.T) {
	ch := r26_sim_chain(t, 2)
	saved_last := sync_fallback_last.Load()
	sync_fallback_last.Store(0)
	defer sync_fallback_last.Store(saved_last)
	connection_map.Range(func(k, v interface{}) bool { connection_map.Delete(k); return true })
	sink := &r25_sink{}
	now := time.Now()
	mk := func(ip string, id uint64, hold time.Duration) *Connection {
		c := &Connection{Peer_ID: id, logger: logr.New(sink).WithValues("peer", ip), Addr: &net.UDPAddr{IP: net.ParseIP(ip), Port: 11011}}
		c.State.Store(ACTIVE)
		c.Height.Store(ch.Get_Height() + 10)
		c.Pruned = 1 << 40
		if hold > 0 {
			c.obs.sync_strikes.Store(1)
			c.obs.sync_hold_until.Store(now.Add(hold).UnixNano())
		}
		connection_map.Store(Address(c), c)
		return c
	}
	defer connection_map.Range(func(k, v interface{}) bool { connection_map.Delete(k); return true })
	a := mk("192.0.2.93", 0x931, 5*time.Minute)
	b := mk("192.0.2.94", 0x941, time.Minute)
	considered := func() int { return len(sink.find("We cannot resync with the peer, since peer chain is pruned")) }

	before := sync_held_fallbacks_total.Get()
	trigger_sync()
	if considered() != 2 || sync_held_fallbacks_total.Get() != before+1 {
		t.Fatalf("all held: %d peers considered, fallbacks %d (want 2, 1)", considered(), sync_held_fallbacks_total.Get()-before)
	}
	trigger_sync() // inside SYNC_FALLBACK_EVERY: no second fallback
	if considered() != 2 || sync_held_fallbacks_total.Get() != before+1 {
		t.Fatalf("the fallback is not rate-limited: %d considered", considered())
	}
	_ = a
	_ = b
	// one unheld peer ahead: pass 0 considers it; the held one is not tried again inside the window
	c := mk("192.0.2.95", 0x951, 0)
	trigger_sync()
	if considered() != 3 {
		t.Fatalf("the unheld peer was not considered (%d)", considered())
	}
	c.State.Store(HANDSHAKE_PENDING)
	// no held peer ahead at all: no fallback even when it would be allowed
	sync_fallback_last.Store(0)
	a.Height.Store(0)
	b.Height.Store(0)
	trigger_sync()
	if sync_held_fallbacks_total.Get() != before+1 {
		t.Fatal("a fallback ran with no held peer ahead")
	}
}

// B99 (3): the fallback order is the hold that ends soonest first.
func TestR26TriggerSyncFallbackOrder(t *testing.T) {
	ch := r26_sim_chain(t, 2)
	saved_last := sync_fallback_last.Load()
	sync_fallback_last.Store(0)
	defer sync_fallback_last.Store(saved_last)
	connection_map.Range(func(k, v interface{}) bool { connection_map.Delete(k); return true })
	defer connection_map.Range(func(k, v interface{}) bool { connection_map.Delete(k); return true })
	sink := &r25_sink{}
	now := time.Now()
	holds := []time.Duration{9 * time.Minute, 2 * time.Minute, 7 * time.Minute, 30 * time.Second, 4 * time.Minute}
	for i, h := range holds {
		ip := fmt.Sprintf("192.0.2.%d", 100+i)
		c := &Connection{Peer_ID: uint64(0x1000 + i), Addr: &net.UDPAddr{IP: net.ParseIP(ip), Port: 11011}}
		c.State.Store(ACTIVE)
		c.Height.Store(ch.Get_Height() + 10)
		c.Pruned = 1 << 40
		c.obs.sync_strikes.Store(1)
		c.obs.sync_hold_until.Store(now.Add(h).UnixNano())
		c.logger = logr.New(&r26_order_sink{r25_sink: sink, id: c.Peer_ID})
		connection_map.Store(Address(c), c)
	}
	trigger_sync()
	got := r26_order
	r26_order = nil
	want := []uint64{0x1003, 0x1001, 0x1004, 0x1002, 0x1000}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("fallback order %x, want %x (soonest hold end first)", got, want)
	}
}

var r26_order []uint64

type r26_order_sink struct {
	*r25_sink
	id uint64
}

func (s *r26_order_sink) Info(level int, msg string, kv ...interface{}) {
	if msg == "We cannot resync with the peer, since peer chain is pruned" {
		r26_order = append(r26_order, s.id)
	}
	s.r25_sink.Info(level, msg, kv...)
}
func (s *r26_order_sink) WithValues(kv ...interface{}) logr.LogSink { return s }
func (s *r26_order_sink) WithName(name string) logr.LogSink         { return s }

// B99 (4): Offenders with a bound returns exactly the newest max records of the full list, in the same order.
func TestR26OffendersTopNMatchesFullSort(t *testing.T) {
	reset_penalty(t)
	saved := nonbanlist
	defer func() { nonbanlist = saved }()
	nonbanlist = nil
	now := time.Unix(2_000_000_000, 0)
	rng := rand.New(rand.NewSource(26))
	penalty_mu.Lock()
	for i := 0; i < 3000; i++ {
		m := &misbehaviour{at: now}
		if i%7 != 0 { // every 7th record has no offence and is never listed
			for j := 0; j <= rng.Intn(6); j++ {
				m.note("busy", now.Add(-time.Duration(rng.Intn(400))*time.Second)) // many equal times: the scope breaks ties
			}
		}
		penalty_map[fmt.Sprintf("198.51.%d.%d", i/250, i%250)] = m
	}
	penalty_mu.Unlock()
	full := Offenders(-1, now)
	if len(full) != 3000-3000/7-1 {
		t.Fatalf("full list %d", len(full))
	}
	for _, max := range []int{0, 1, 5, 32, 2999, 5000} {
		got := Offenders(max, now)
		want := full
		if max < len(want) {
			want = want[:max]
		}
		if len(got) != len(want) {
			t.Fatalf("max %d: %d records, want %d", max, len(got), len(want))
		}
		for i := range want {
			if got[i].Scope != want[i].Scope || got[i].Events != want[i].Events || got[i].LastOffences[0].At != want[i].LastOffences[0].At {
				t.Fatalf("max %d row %d: %+v, want %+v", max, i, got[i], want[i])
			}
		}
	}
}

// B99 (4): the work done under penalty_mu no longer grows with views built per record: a 65,536-record table, bound
// 32. It times the whole Offenders call (an upper bound on the lock hold time, which is not measured separately); the
// r25 verifier measured 22.6-23.4 ms for the whole walk before the bounded heap. Run it only via benchlock.py.
func BenchmarkR26OffendersFullTable(b *testing.B) {
	reset_penalty(b)
	now := time.Unix(2_000_000_000, 0)
	penalty_mu.Lock()
	for i := 0; i < PENALTY_MAX_ENTRIES; i++ {
		m := &misbehaviour{at: now}
		m.note("busy", now.Add(-time.Duration(i%600)*time.Second))
		penalty_map[fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255)] = m
	}
	penalty_mu.Unlock()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(Offenders(32, now)) != 32 {
			b.Fatal("want 32")
		}
	}
}

// B102 (decision: policy kept): three invalid_pow within one half-life always ban, however they are spread; two
// never do once any time passes between them.
func TestR26ThreeInvalidPowWithinHalfLifeBan(t *testing.T) {
	reset_penalty(t)
	saved := nonbanlist
	defer func() { nonbanlist = saved }()
	nonbanlist = nil
	now := time.Unix(2_000_000_000, 0)
	for i, gaps := range [][2]time.Duration{{0, PENALTY_HALF_LIFE}, {PENALTY_HALF_LIFE / 2, PENALTY_HALF_LIFE / 2}, {time.Second, time.Second},
		{PENALTY_HALF_LIFE - time.Second, time.Second}} {
		ip := fmt.Sprintf("192.0.2.%d", 120+i)
		add_penalty(ip, "invalid_pow", now)
		if secs := add_penalty(ip, "invalid_pow", now.Add(gaps[0]+time.Millisecond)); secs != 0 {
			t.Fatalf("case %d: two invalid_pow %v apart banned", i, gaps[0]+time.Millisecond)
		}
		third := now.Add(gaps[0] + gaps[1])
		if third.Sub(now) > PENALTY_HALF_LIFE {
			third = now.Add(PENALTY_HALF_LIFE)
		}
		if secs := add_penalty(ip, "invalid_pow", third); secs == 0 {
			t.Fatalf("case %d: three invalid_pow within %v did not ban", i, third.Sub(now))
		}
	}
	ip := "192.0.2.130" // spread past one half-life: no ban (the score is below 100 at the third)
	add_penalty(ip, "invalid_pow", now)
	add_penalty(ip, "invalid_pow", now.Add(PENALTY_HALF_LIFE))
	if secs := add_penalty(ip, "invalid_pow", now.Add(2*PENALTY_HALF_LIFE)); secs != 0 {
		t.Fatal("three invalid_pow spread over two half-lives banned")
	}
}
