package p2p

// r25 (consensus dimension): tests of p2p/consensus_obs_r25.go — miniblock refusals by reason (CO24-C1), block
// rejections by reason with the sender named by peer_id (CO24-C3), the alt-block verdict behind GetInfo
// alt_blocks_count (CO24-C4) and the first-seen tables (CO24-C5). Unit tests use forged inputs; the simulator test
// drives the real NotifyMiniBlock and add_block paths on a throw-away chain.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/errormsg"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
	"github.com/go-logr/logr"
)

type r25_line struct {
	level int
	msg   string
	kv    map[string]interface{}
}

type r25_sink struct {
	sync.Mutex
	lines  []r25_line
	errors int
}

func (s *r25_sink) Init(logr.RuntimeInfo) {}
func (s *r25_sink) Enabled(int) bool      { return true }
func (s *r25_sink) Info(level int, msg string, kv ...interface{}) {
	s.Lock()
	defer s.Unlock()
	m := map[string]interface{}{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[fmt.Sprint(kv[i])] = kv[i+1]
	}
	s.lines = append(s.lines, r25_line{level, msg, m})
}
func (s *r25_sink) Error(err error, msg string, kv ...interface{}) { s.Lock(); s.errors++; s.Unlock() }
func (s *r25_sink) WithValues(kv ...interface{}) logr.LogSink      { return s }
func (s *r25_sink) WithName(name string) logr.LogSink              { return s }
func (s *r25_sink) find(msg string) []r25_line {
	s.Lock()
	defer s.Unlock()
	var out []r25_line
	for _, l := range s.lines {
		if l.msg == msg {
			out = append(out, l)
		}
	}
	return out
}

// fresh counters and tables for one test; restored afterwards
func r25_reset(t *testing.T) {
	om, ob, obs, oms, oa, ol := miniblock_refused, block_rejected, block_seen, miniblock_seen, alt_track, logger
	miniblock_refused = new_reason_counter("p2p_miniblock_refused_total")
	block_rejected = new_reason_counter("blockchain_block_rejected_total")
	block_seen, miniblock_seen = new_seen_table(BLOCK_SEEN_KEEP), new_seen_table(MINIBLOCK_SEEN_KEEP)
	alt_track = new_alt_tracker()
	t.Cleanup(func() {
		miniblock_refused, block_rejected, block_seen, miniblock_seen, alt_track, logger = om, ob, obs, oms, oa, ol
	})
}

// CO24-C1: a refusal is counted by reason, returns the caller's error unchanged, and logs one V(1) line per reason per
// minute naming the peer by its peer_id (never its address); the suppressed ones are reported on the next line.
func TestR25MiniblockRefusalCountedAndRateLimited(t *testing.T) {
	r25_reset(t)
	s := &r25_sink{}
	logger = logr.New(s) // the package logger: the lines must not use the connection's ip-named logger
	c := &Connection{Peer_ID: 0xabc, logger: logr.New(&r25_sink{})}
	want := fmt.Errorf("Stale Miniblock")
	if got := c.refuse_miniblock(MBL_REFUSED_STALE, 7, want); got != want {
		t.Fatalf("the caller's error must come back unchanged, got %v", got)
	}
	c.refuse_miniblock(MBL_REFUSED_STALE, 8, want)
	c.refuse_miniblock(MBL_REFUSED_TIP, 9, want)
	m, total := miniblock_refused.snapshot()
	if m[MBL_REFUSED_STALE] != 2 || m[MBL_REFUSED_TIP] != 1 || total != 3 {
		t.Fatalf("counts %v total %d", m, total)
	}
	lines := s.find("Miniblock refused")
	if len(lines) != 2 || lines[0].level != 1 || lines[0].kv["peer_id"] != "0000000000000abc" || lines[0].kv["reason"] != MBL_REFUSED_STALE ||
		lines[1].kv["reason"] != MBL_REFUSED_TIP {
		t.Fatalf("lines %+v", lines)
	}
	if ok, held := miniblock_refused.add(MBL_REFUSED_STALE, time.Now().Add(OBS_LOG_EVERY+time.Second)); !ok || held != 1 {
		t.Fatalf("after the window: log %v suppressed %d, want true 1", ok, held)
	}
	for _, l := range s.lines {
		for _, v := range l.kv {
			if strings.Contains(fmt.Sprint(v), ".") && strings.Count(fmt.Sprint(v), ".") == 3 {
				t.Fatalf("an address-like value reached a log line: %v", l)
			}
		}
	}
}

// CO24-C3: every error value Add_Complete_Block returns (blockchain/blockchain.go) gets its reason; an accepted or
// already-known block is not a rejection.
func TestR25BlockRejectReason(t *testing.T) {
	cases := []struct {
		err  error
		ok   bool
		want string
	}{
		{nil, true, ""}, {errormsg.ErrAlreadyExists, false, ""}, {errormsg.ErrPastMissing, false, "past_missing"},
		{errormsg.ErrFutureTimestamp, false, "future_timestamp"}, {errormsg.ErrInvalidTimestamp, false, "timestamp_not_after_parent"},
		{errormsg.ErrInvalidPoW, false, "invalid_pow"}, {fmt.Errorf("wrapped: %w", errormsg.ErrInvalidPoW), false, "invalid_pow"},
		{errormsg.ErrInvalidSize, false, "invalid_size"}, {errormsg.ErrTXDoubleSpend, false, "tx_double_spend"},
		{errormsg.ErrInvalidTX, false, "invalid_tx"}, {errormsg.ErrInvalidBlock, false, "invalid_block"}, {errormsg.ErrPanic, false, "panic"},
		{fmt.Errorf("advance Block"), false, "advance_block"}, {fmt.Errorf("previous Block"), false, "previous_block"},
		{errors.New("something new"), false, "other"}, {nil, false, "unknown"},
	}
	for _, c := range cases {
		if got := block_reject_reason(c.err, c.ok); got != c.want {
			t.Errorf("%v ok=%v: reason %q, want %q", c.err, c.ok, got, c.want)
		}
		// every reason the function can name is on /metrics before it fires (0 until then)
		if c.want != "" {
			var buf bytes.Buffer
			metrics.Set.WritePrometheus(&buf)
			if !strings.Contains(buf.String(), `blockchain_block_rejected_total{reason="`+c.want+`"}`) {
				t.Errorf("reason %q is not pre-registered on /metrics", c.want)
			}
		}
	}
	var buf bytes.Buffer
	metrics.Set.WritePrometheus(&buf)
	for _, r := range miniblock_refusal_reasons {
		if !strings.Contains(buf.String(), `p2p_miniblock_refused_total{reason="`+r+`"}`) {
			t.Errorf("miniblock reason %q is not pre-registered on /metrics", r)
		}
	}
}

// CO24-C3: a rejection is counted and logged with the sender's peer_id (console level for a rule refusal, file level
// for past_missing); a duplicate is counted apart and never logged as a rejection.
func TestR25BlockRejectionAttributed(t *testing.T) {
	r25_reset(t)
	s := &r25_sink{}
	logger = logr.New(s)
	c := &Connection{Peer_ID: 0x1234, logger: logr.New(&r25_sink{})}
	bl := &block.Block{Height: 77, Timestamp: 1}
	cbl := &block.Complete_Block{Bl: bl}
	dup0 := block_duplicates.Get()
	note_block_result(c, cbl, errormsg.ErrFutureTimestamp, false)
	note_block_result(c, cbl, errormsg.ErrPastMissing, false)
	note_block_result(c, cbl, errormsg.ErrAlreadyExists, false)
	m, total := block_rejected.snapshot()
	if m["future_timestamp"] != 1 || m["past_missing"] != 1 || total != 2 || block_duplicates.Get() != dup0+1 {
		t.Fatalf("counts %v total %d duplicates +%d", m, total, block_duplicates.Get()-dup0)
	}
	lines := s.find("Block rejected")
	if len(lines) != 2 || lines[0].level != 0 || lines[0].kv["reason"] != "future_timestamp" || lines[0].kv["peer_id"] != "0000000000001234" ||
		lines[0].kv["blid"] != bl.GetHash().String() || lines[1].level != 1 {
		t.Fatalf("lines %+v", lines)
	}
	// accepted: tracked for the alt verdict, never counted as a rejection
	note_block_result(nil, cbl, nil, true)
	if _, total2 := block_rejected.snapshot(); total2 != 2 || len(alt_track.entries) != 1 {
		t.Fatalf("accepted block: rejections %d tracked %d", total2, len(alt_track.entries))
	}
	if peer_label(0) != "local" {
		t.Fatal("peer 0 is this node")
	}
}

// CO24-C5: the first sighting wins, later ones never move it; the table is a bounded FIFO.
func TestR25SeenTableFirstWinsAndBounded(t *testing.T) {
	tb := new_seen_table(3)
	h := func(i int) crypto.Hash { return crypto.Keccak256([]byte(fmt.Sprint(i))) }
	if !tb.note(h(1), FirstSeen{Ms: 100}) || tb.note(h(1), FirstSeen{Ms: 50}) {
		t.Fatal("first note must win, the second must report false")
	}
	if fs, _ := tb.get(h(1)); fs.Ms != 100 {
		t.Fatalf("first-seen moved to %d", fs.Ms)
	}
	for i := 2; i <= 5; i++ {
		tb.note(h(i), FirstSeen{Ms: int64(i)})
	}
	if tb.len() != 3 {
		t.Fatalf("table holds %d, keep is 3", tb.len())
	}
	if _, ok := tb.get(h(1)); ok {
		t.Fatal("the oldest entry was not evicted")
	}
	if _, ok := tb.get(h(2)); ok {
		t.Fatal("the second oldest entry was not evicted")
	}
	if fs, ok := tb.get(h(5)); !ok || fs.Ms != 5 {
		t.Fatal("the newest entry is missing")
	}
}

// CO24-C4 (forged topo index): an accepted block deeper than STABLE_LIMIT is main when its id is at its height in
// the topo index and alt otherwise; one within STABLE_LIMIT, or whose index read panics, stays unsettled.
func TestR25AltTrackerSettles(t *testing.T) {
	a := new_alt_tracker()
	id := func(s string) crypto.Hash { return crypto.Keccak256([]byte(s)) }
	a.note(id("main10"), 10)
	a.note(id("side10"), 10)
	a.note(id("main12"), 12)
	a.note(id("main11"), 11)
	a.note(id("side10"), 10) // a second offer of the same block is not a second entry
	main := map[int64][]crypto.Hash{10: {id("main10")}, 12: {id("main12")}}
	at := func(h int64) []crypto.Hash {
		if h == 11 {
			panic("clean topo record")
		}
		return main[h]
	}
	st := a.settle(10+config.STABLE_LIMIT+1, at)
	if st.Count != 1 || st.Settled != 2 || st.Unsettled != 2 || st.Tracked != 4 || len(st.Blocks) != 1 || st.Blocks[0].Hash != id("side10").String() ||
		st.Blocks[0].Height != 10 || st.TrackedFrom != 10 {
		t.Fatalf("first settle %+v", st)
	}
	st = a.settle(12+config.STABLE_LIMIT+1, at)
	if st.Count != 1 || st.Settled != 3 || st.Unsettled != 1 {
		t.Fatalf("second settle %+v", st)
	}
	// bounded: the oldest entries leave the tracker
	b := new_alt_tracker()
	for i := 0; i < ALT_TRACK_KEEP+5; i++ {
		b.note(id(fmt.Sprint(i)), int64(i))
	}
	if len(b.entries) != ALT_TRACK_KEEP || len(b.index) != ALT_TRACK_KEEP {
		t.Fatalf("tracker holds %d/%d, keep is %d", len(b.entries), len(b.index), ALT_TRACK_KEEP)
	}
	// the alt list keeps the newest ALT_LIST_KEEP
	c := new_alt_tracker()
	for i := 0; i < ALT_LIST_KEEP+3; i++ {
		c.note(id(fmt.Sprint("x", i)), 5)
	}
	st = c.settle(100, func(int64) []crypto.Hash { return nil })
	if st.Count != uint64(ALT_LIST_KEEP+3) || len(st.Blocks) != ALT_LIST_KEEP || st.Blocks[len(st.Blocks)-1].Hash != id(fmt.Sprint("x", ALT_LIST_KEEP+2)).String() {
		t.Fatalf("alt list: count %d listed %d", st.Count, len(st.Blocks))
	}
}

func r25_genesis_miner(t *testing.T) rpc.Address {
	raw, _ := hex.DecodeString(config.Testnet.Genesis_Tx)
	var tx transaction.Transaction
	if err := tx.Deserialize(raw); err != nil {
		t.Fatal(err)
	}
	a, err := rpc.NewAddressFromCompressedKeys(tx.MinerAddress[:])
	if err != nil {
		t.Fatal(err)
	}
	return *a
}

// The real paths on a simulator chain: NotifyMiniBlock counts stale, final and unregistered refusals and records the
// first-seen time of an accepted miniblock; add_block counts a future-timestamp rejection and a duplicate, tracks
// accepted blocks, and the alt verdict reads the chain's own topo index.
func TestR25ConsensusObsOnSimulatorChain(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a simulator chain")
	}
	r25_reset(t)
	old_args := globals.Arguments
	globals.Arguments = map[string]interface{}{"--data-dir": t.TempDir(), "--testnet": true, "--simulator": true}
	defer func() { globals.Arguments = old_args }()
	globals.Initialize()
	ch, err := blockchain.Blockchain_Start(map[string]interface{}{"--simulator": true})
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Shutdown()
	old_chain := chain
	chain = ch
	defer func() { chain = old_chain }()

	miner := r25_genesis_miner(t)
	var c *Connection // nil: blocks offered by this node
	for i := 0; i < 14; i++ {
		cbl, _, err := ch.Create_new_miner_block(miner)
		if err != nil {
			t.Fatal(err)
		}
		cbl.Bl.MiniBlocks = append(cbl.Bl.MiniBlocks, blockchain.ConvertBlockToMiniblock(*cbl.Bl, miner))
		if err, ok := c.add_block(cbl); !ok {
			t.Fatalf("block %d: %v", i, err)
		}
		if i == 0 {
			if err, ok := c.add_block(cbl); ok || !errors.Is(err, errormsg.ErrAlreadyExists) {
				t.Fatalf("second offer of the same block: %v %v", err, ok)
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	// a block stamped a minute into the future is refused by the chain's own rule and counted
	fut, _, err := ch.Create_new_miner_block(miner)
	if err != nil {
		t.Fatal(err)
	}
	fut.Bl.Timestamp = uint64(globals.Time().UTC().UnixMilli()) + 60_000
	fut.Bl.MiniBlocks = append(fut.Bl.MiniBlocks, blockchain.ConvertBlockToMiniblock(*fut.Bl, miner))
	if err, ok := c.add_block(fut); ok || !errors.Is(err, errormsg.ErrFutureTimestamp) {
		t.Fatalf("future block: %v %v", err, ok)
	}
	if m, _ := block_rejected.snapshot(); m["future_timestamp"] != 1 {
		t.Fatalf("rejections %v", m)
	}
	// alt verdict against the real topo index: every mined block is main; a forged accepted block is alt
	st := Alt_Blocks(ch.Get_Height(), ch.Get_Blocks_At_Height)
	if st.Count != 0 || st.Settled == 0 || st.Tracked != 14 {
		t.Fatalf("alt stats after 14 main blocks %+v (height %d)", st, ch.Get_Height())
	}
	ghost := &block.Block{Height: 3, Timestamp: 42}
	alt_track.note(ghost.GetHash(), 3)
	st = Alt_Blocks(ch.Get_Height(), ch.Get_Blocks_At_Height)
	if st.Count != 1 || st.Blocks[0].Hash != ghost.GetHash().String() {
		t.Fatalf("a block that is not at its height in the topo index must settle as alt: %+v", st)
	}
	// first-seen of a block offered here
	if fs, ok := Block_First_Seen(fut.Bl.GetHash()); !ok || !fs.Local || fs.Ms == 0 {
		t.Fatalf("first-seen of an offered block %+v %v", fs, ok)
	}

	// NotifyMiniBlock refusals, from a peer
	peer := &Connection{Peer_ID: 0x77, logger: logr.Discard()}
	h := uint64(ch.Get_Height())
	tmpl, _, err := ch.Create_new_miner_block(miner)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(edit func(*block.MiniBlock)) Objects {
		mbl := blockchain.ConvertBlockToMiniblock(*tmpl.Bl, miner)
		edit(&mbl)
		return Objects{MiniBlocks: [][]byte{mbl.Serialize()}}
	}
	if err := peer.NotifyMiniBlock(mk(func(m *block.MiniBlock) { m.Height = 1 }), &Dummy{}); err == nil || err.Error() != "Stale Miniblock" {
		t.Fatalf("stale: %v", err)
	}
	if err := peer.NotifyMiniBlock(mk(func(m *block.MiniBlock) { m.Final = true }), &Dummy{}); err == nil {
		t.Fatal("a final miniblock must be refused")
	}
	if err := peer.NotifyMiniBlock(mk(func(m *block.MiniBlock) { m.KeyHash = crypto.Keccak256([]byte("nobody")) }), &Dummy{}); err == nil ||
		err.Error() != "unregistered miner" {
		t.Fatalf("unregistered: %v", err)
	}
	m, total := miniblock_refused.snapshot()
	if m[MBL_REFUSED_STALE] != 1 || m[MBL_REFUSED_FINAL] != 1 || m[MBL_REFUSED_UNREGISTERED] != 1 || total != 3 {
		t.Fatalf("refusals %v", m)
	}
	good := blockchain.ConvertBlockToMiniblock(*tmpl.Bl, miner)
	if err := peer.NotifyMiniBlock(Objects{MiniBlocks: [][]byte{good.Serialize()}}, &Dummy{}); err != nil {
		t.Logf("a valid miniblock at height %d was not accepted (%v): first-seen not checked", h, err)
		return
	}
	if fs, ok := MiniBlock_First_Seen(good.GetHash()); !ok || fs.Local || fs.Peer != 0x77 {
		t.Fatalf("first-seen of an accepted miniblock %+v %v", fs, ok)
	}
}
