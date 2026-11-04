package rpc

// r25 (consensus dimension): tests of the RPC side of the chain-observatory fixes — header miners[] slot alignment
// (CO24-C7), block fees in GetBlockHeadersRange (CO24-C2), GetInfo alt_blocks_count (CO24-C4), first-seen fields
// (CO24-C5), the reorg monitor's lifetime record and INFO line (CO24-C6) and DERO.GetConsensusStats.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/p2p"
	"github.com/go-logr/logr"
)

// CO24-C7: an unresolved key stays "unknown" in its own slot; slot 9 is the integrator; upstream's skip-and-pad
// shifted every later slot by one.
func TestR25HeaderMinersKeepSlots(t *testing.T) {
	names := func(skip map[int]bool) func(int) (string, bool) {
		return func(i int) (string, bool) {
			if skip[i] {
				return "", false
			}
			return fmt.Sprintf("m%d", i), true
		}
	}
	got := header_miners(10, names(map[int]bool{3: true}), "integ", true)
	want := []string{"m0", "m1", "m2", "unknown", "m4", "m5", "m6", "m7", "m8", "integ"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("slots %v, want %v", got, want)
	}
	if got := header_miners(10, names(nil), "", false); got[9] != "m9" {
		t.Fatalf("no integrator: slot 9 %q", got[9])
	}
	if got := header_miners(3, names(map[int]bool{0: true}), "integ", true); strings.Join(got, ",") != "unknown,m1,m2" {
		t.Fatalf("a 3-miniblock block (no slot 9): %v", got)
	}
	if got := header_miners(0, names(nil), "integ", true); got != nil {
		t.Fatalf("no miniblocks must give nil, got %v", got)
	}
}

// CO24-C2: the fee sum covers every tx; an unreadable or undecodable tx makes it unknown (nil), never partial.
func TestR25BlockFees(t *testing.T) {
	if f := block_fees(nil, nil, tx_fee); f == nil || *f != 0 {
		t.Fatalf("no txs: %v", f)
	}
	h := crypto.Keccak256([]byte("tx"))
	if f := block_fees([]crypto.Hash{h}, func(crypto.Hash) ([]byte, error) { return nil, os.ErrNotExist }, tx_fee); f != nil {
		t.Fatalf("unreadable tx gave %d", *f)
	}
	if f := block_fees([]crypto.Hash{h}, func(crypto.Hash) ([]byte, error) { return []byte{0xff, 0x01}, nil }, tx_fee); f != nil {
		t.Fatalf("undecodable tx gave %d", *f)
	}
	// forged decoder: the sum covers every tx, and one failing tx voids the whole sum (never a partial one)
	hs := []crypto.Hash{crypto.Keccak256([]byte("a")), crypto.Keccak256([]byte("b")), crypto.Keccak256([]byte("c"))}
	fee := map[byte]uint64{'a': 120, 'b': 7, 'c': 0}
	read := func(x crypto.Hash) ([]byte, error) {
		for i, y := range hs {
			if x == y {
				return []byte{"abc"[i]}, nil
			}
		}
		return nil, os.ErrNotExist
	}
	of := func(raw []byte) (uint64, error) {
		if raw[0] == 'x' {
			return 0, fmt.Errorf("bad")
		}
		return fee[raw[0]], nil
	}
	if f := block_fees(hs, read, of); f == nil || *f != 127 {
		t.Fatalf("sum %v, want 127", f)
	}
	if f := block_fees(append(hs, crypto.Keccak256([]byte("missing"))), read, of); f != nil {
		t.Fatalf("a missing 4th tx must void the sum, got %d", *f)
	}
}

type r25_rpc_sink struct {
	sync.Mutex
	infos map[string][]int
}

func (s *r25_rpc_sink) Init(logr.RuntimeInfo) {}
func (s *r25_rpc_sink) Enabled(int) bool      { return true }
func (s *r25_rpc_sink) Info(level int, msg string, kv ...interface{}) {
	s.Lock()
	defer s.Unlock()
	s.infos[msg] = append(s.infos[msg], level)
}
func (s *r25_rpc_sink) Error(err error, msg string, kv ...interface{}) {}
func (s *r25_rpc_sink) WithValues(kv ...interface{}) logr.LogSink      { return s }
func (s *r25_rpc_sink) WithName(name string) logr.LogSink              { return s }

// CO24-C6: the lifetime record sums every run of the datadir, survives a restart (a new tracker on the same file),
// counts the starts, sets a corrupt file aside, and every reorganisation is one V(0) INFO line.
func TestR25ReorgLifetimePersistsAcrossRestarts(t *testing.T) {
	s := &r25_rpc_sink{infos: map[string][]int{}}
	old := logger
	logger = logr.New(s)
	defer func() { logger = old }()
	path := filepath.Join(t.TempDir(), REORG_MONITOR_FILE)

	run := func(r *reorg_tracker) {
		f := new_fake_topo(100)
		r.observe(100, f.at, f.h, 90, 100)
		for t2 := int64(97); t2 <= 101; t2++ {
			f.set(t2, fmt.Sprintf("b%d", t2), t2)
		}
		if ev := r.observe(101, f.at, f.h, 91, 101); ev == nil || ev.Replaced != 4 {
			t.Fatalf("reorg event %+v", ev)
		}
	}
	r1 := new_reorg_tracker()
	if err := r1.enable_persist(path); err != nil {
		t.Fatal(err)
	}
	run(r1)
	st := r1.stats()
	if st.Lifetime == nil || st.Lifetime.Reorgs != 1 || st.Lifetime.ReplacedTotal != 4 || st.Lifetime.Starts != 1 || st.Lifetime.Observed != 2 ||
		st.Lifetime.LastForkTopo != 97 || st.Lifetime.File != REORG_MONITOR_FILE {
		t.Fatalf("first run lifetime %+v", st.Lifetime)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("persisted file %v %v", fi, err)
	}
	// the restart: a fresh tracker (all run counters 0) loads the same file
	r2 := new_reorg_tracker()
	if err := r2.enable_persist(path); err != nil {
		t.Fatal(err)
	}
	if st := r2.stats(); st.Reorgs != 0 || st.Lifetime.Reorgs != 1 || st.Lifetime.Starts != 2 {
		t.Fatalf("after restart: run %d lifetime %+v", st.Reorgs, st.Lifetime)
	}
	run(r2)
	if st := r2.stats(); st.Reorgs != 1 || st.Lifetime.Reorgs != 2 || st.Lifetime.ReplacedTotal != 8 || st.Lifetime.Observed != 4 {
		t.Fatalf("second run: run %d lifetime %+v", st.Reorgs, st.Lifetime)
	}
	raw, _ := os.ReadFile(path)
	var disk Reorg_Lifetime
	if json.Unmarshal(raw, &disk) != nil || disk.Reorgs != 2 {
		t.Fatalf("on disk %s", raw)
	}
	// a quiet observation is saved only every REORG_SAVE_EVERY; flush (RPCServer_Stop) writes it at shutdown
	f := new_fake_topo(200)
	r2.observe(200, f.at, f.h, 190, 200)
	r2.flush()
	raw, _ = os.ReadFile(path)
	if json.Unmarshal(raw, &disk) != nil || disk.Observed != 5 {
		t.Fatalf("after flush on disk observed %d, want 5: %s", disk.Observed, raw)
	}
	if l := s.infos["Reorganisation"]; len(l) != 2 || l[0] != 0 || l[1] != 0 {
		t.Fatalf("INFO lines %v, want two at V(0)", l)
	}
	// a corrupt file is set aside, a new record starts, the node keeps running
	os.WriteFile(path, []byte("{not json"), 0600)
	r3 := new_reorg_tracker()
	if err := r3.enable_persist(path); err != nil {
		t.Fatal(err)
	}
	if st := r3.stats(); st.Lifetime.Reorgs != 0 || st.Lifetime.Starts != 1 {
		t.Fatalf("after corrupt file %+v", st.Lifetime)
	}
	if _, err := os.Stat(path + ".corrupt"); err != nil {
		t.Fatalf("corrupt file not kept aside: %v", err)
	}
	// persistence off: no lifetime field
	if st := new_reorg_tracker().stats(); st.Lifetime != nil {
		t.Fatal("an unpersisted tracker must not report a lifetime")
	}
}

func TestR25ConsensusStatsParams(t *testing.T) {
	if _, err := parse_hash_list([]string{"zz"}, "block"); err == nil {
		t.Fatal("bad hex accepted")
	}
	if _, err := parse_hash_list([]string{strings.Repeat("ab", 31)}, "block"); err == nil {
		t.Fatal("short hash accepted")
	}
	long := make([]string, CONSENSUS_STATS_MAX_HASHES+1)
	for i := range long {
		long[i] = strings.Repeat("00", 32)
	}
	if _, err := parse_hash_list(long, "block"); err == nil {
		t.Fatal("over-limit list accepted")
	}
	if l, err := parse_hash_list(long[:CONSENSUS_STATS_MAX_HASHES], "block"); err != nil || len(l) != CONSENSUS_STATS_MAX_HASHES {
		t.Fatalf("at the limit: %d %v", len(l), err)
	}
	if foreign_cost("DERO.GetConsensusStats") != 4 {
		t.Fatal("GetConsensusStats must cost 4 tokens on a foreign socket")
	}
}

// The live wiring on a simulator chain: GetInfo alt_blocks_count reads the settled alt count (it was never assigned),
// GetBlockHeadersRange carries fees and first_seen_ms with the upstream fields unchanged at the top level of each
// header, and GetConsensusStats answers first-seen lookups.
func TestR25ConsensusRPCOnSimulatorChain(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a simulator chain")
	}
	old_args := globals.Arguments
	globals.Arguments = map[string]interface{}{"--data-dir": t.TempDir(), "--testnet": true, "--simulator": true}
	defer func() { globals.Arguments = old_args }()
	globals.Initialize()
	c, err := blockchain.Blockchain_Start(map[string]interface{}{"--simulator": true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Shutdown()
	defer swap_global_chain(c)() // r25 merge (B41): under chain_swap_mu, like every other test swap

	miner := genesis_miner(t)
	var last *block.Complete_Block
	for i := 0; i < 12; i++ {
		cbl, _, err := c.Create_new_miner_block(miner)
		if err != nil {
			t.Fatal(err)
		}
		cbl.Bl.MiniBlocks = append(cbl.Bl.MiniBlocks, blockchain.ConvertBlockToMiniblock(*cbl.Bl, miner))
		if err, ok := c.Add_Complete_Block(cbl); !ok {
			t.Fatalf("block %d: %v", i, err)
		}
		p2p.Note_Local_Block(cbl) // as the derod main.go relayer does for a block mined here
		last = cbl
		time.Sleep(2 * time.Millisecond)
	}
	ctx := context.Background()
	gi, err := GetInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	base := gi.Alt_Blocks_Count
	// an accepted block that never entered the topo index (a lost race): settles as alt
	// r25 pipeline run 1 fix: a fresh hash per run; the alt tracker is package-global and dedupes by hash, so a fixed
	// ghost was already settled on -count>1 (S3a flaky 1/3) and the count did not move
	ghost := &block.Block{Height: 2, Timestamp: uint64(time.Now().UnixNano())}
	p2p.Note_Local_Block(&block.Complete_Block{Bl: ghost})
	if gi, err = GetInfo(ctx); err != nil || gi.Alt_Blocks_Count != base+1 {
		t.Fatalf("alt_blocks_count %d (before %d) err %v", gi.Alt_Blocks_Count, base, err)
	}
	top := c.Load_TOPO_HEIGHT()
	hr, err := GetBlockHeadersRange(ctx, GetBlockHeadersRange_Params{Start: top - 2, End: top})
	if err != nil || len(hr.Headers) != 3 {
		t.Fatalf("range %v %d", err, len(hr.Headers))
	}
	lh := hr.Headers[len(hr.Headers)-1]
	if lh.Fees == nil || *lh.Fees != 0 || lh.FirstSeenMs == 0 || !lh.FirstSeenLocal || lh.Hash != last.Bl.GetHash().String() {
		t.Fatalf("last header fees %v first_seen %d local %v hash %s", lh.Fees, lh.FirstSeenMs, lh.FirstSeenLocal, lh.Hash)
	}
	raw, _ := json.Marshal(lh)
	var flat map[string]interface{}
	json.Unmarshal(raw, &flat)
	for _, k := range []string{"hash", "height", "topoheight", "miners", "txcount", "fees", "first_seen_ms", "first_seen_local"} {
		if _, ok := flat[k]; !ok {
			t.Fatalf("header JSON lacks %q at the top level: %s", k, raw)
		}
	}
	cs, err := GetConsensusStats(ctx, GetConsensusStats_Params{BlockHashes: []string{last.Bl.GetHash().String(), strings.Repeat("00", 32)}})
	if err != nil || cs.Status != "OK" || len(cs.FirstSeen) != 2 || !cs.FirstSeen[0].Known || !cs.FirstSeen[0].Local || cs.FirstSeen[1].Known ||
		cs.AltBlocks.Count != gi.Alt_Blocks_Count || cs.StableLimit != 8 {
		t.Fatalf("GetConsensusStats %+v err %v", cs, err)
	}
	mb, err := GetMiniBlocks(ctx, GetMiniBlocks_Params{TopoHeight: top})
	if err != nil || len(mb.MiniBlocks) != 1 {
		t.Fatalf("GetMiniBlocks %v", err)
	}
	raw, _ = json.Marshal(mb.MiniBlocks[0])
	if !strings.Contains(string(raw), `"first_seen_ms":`) {
		t.Fatalf("miniblock JSON lacks first_seen_ms: %s", raw)
	}
}
