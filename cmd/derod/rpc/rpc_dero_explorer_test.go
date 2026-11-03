package rpc

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

func TestClampTopoRange(t *testing.T) {
	cases := []struct {
		s, e, top, lim int64
		ws, we         int64
		bad            bool
	}{
		{0, 9, 100, 10, 0, 9, false},
		{0, 10, 100, 10, 0, 0, true},       // 11 blocks > limit
		{95, 200, 100, 10, 95, 100, false}, // end clipped to top
		{101, 105, 100, 10, 0, 0, true},    // start above top
		{5, 4, 100, 10, 0, 0, true},        // inverted
		{-1, 4, 100, 10, 0, 0, true},       // negative
		{7, 7, 100, 1, 7, 7, false},
	}
	for i, c := range cases {
		s, e, err := clamp_topo_range(c.s, c.e, c.top, c.lim)
		if (err != nil) != c.bad || (!c.bad && (s != c.ws || e != c.we)) {
			t.Fatalf("case %d: got %d..%d err=%v, want %d..%d bad=%v", i, s, e, err, c.ws, c.we, c.bad)
		}
	}
}

func TestMiniblockTimeReconstruction(t *testing.T) {
	block := uint64(1761300000000) // block timestamp, ms
	for _, before := range []uint64{0, 1, 999, 17_000, 60_000} {
		m := block - before
		if got := mbl_time_ms(block, uint16(m)); got != m {
			t.Fatalf("miniblock %d ms before the block: reconstructed %d, want %d", before, got, m)
		}
	}
	// a template stamped slightly AFTER the block timestamp (fresh clock read) stays in the same window
	if got := mbl_time_ms(block, uint16(block+1200)); got != block+1200 {
		t.Fatalf("1.2 s after the block: got %d want %d", got, block+1200)
	}
	// verifier F3: the block's low 16 bits near the top (0xFF00) and a miniblock 1.2 s later: its 16-bit stamp wrapped
	wrap := (block &^ 0xFFFF) | 0xFF00
	if got := mbl_time_ms(wrap, uint16(wrap+1200)); got != wrap+1200 {
		t.Fatalf("1.2 s after a block at low bits 0xFF00: got %d want %d", got, wrap+1200)
	}
	if got := mbl_time_ms(wrap, uint16(wrap-17_000)); got != wrap-17_000 {
		t.Fatalf("17 s before a block at low bits 0xFF00: got %d want %d", got, wrap-17_000)
	}
	if got := mbl_time_ms(100, 50); got != 50 { // near epoch: never underflows
		t.Fatalf("got %d", got)
	}
}

func TestClassifyFingerprint(t *testing.T) {
	if v, f := classify_fingerprint(true, 8_000_000, 7_504_640, []string{HF3_V3_HASH}); !strings.HasPrefix(v, "v3") || !f {
		t.Fatalf("v3 hash: %q final=%v", v, f)
	}
	if v, f := classify_fingerprint(true, 8_000_000, 7_504_640, []string{HF3_V2_PREFIX + strings.Repeat("0", 56)}); !strings.HasPrefix(v, "v2-remnant") || !f {
		t.Fatalf("v2 hash: %q final=%v", v, f)
	}
	if v, f := classify_fingerprint(true, 7_000_000, 7_504_640, nil); !strings.HasPrefix(v, "not reached") || f {
		t.Fatalf("below fork: %q final=%v", v, f)
	}
	if v, f := classify_fingerprint(true, 8_000_000, 7_504_640, []string{strings.Repeat("ab", 32)}); !strings.HasPrefix(v, "unknown") || f {
		t.Fatalf("foreign hash: %q final=%v", v, f)
	}
	if v, _ := classify_fingerprint(false, 8_000_000, 0, nil); !strings.HasPrefix(v, "n/a") {
		t.Fatalf("testnet: %q", v)
	}
}

func TestDifficultySummary(t *testing.T) {
	pts := []DifficultyPoint{{Height: 10, Timestamp: 1_000_000}, {Height: 11, Timestamp: 1_018_000}, {Height: 13, Timestamp: 1_054_000}}
	md, bt := difficulty_summary(pts, []float64{100, 200, 300})
	if md != 200 || bt != 18 {
		t.Fatalf("mean difficulty %v block time %v, want 200 and 18", md, bt)
	}
	if md, bt := difficulty_summary(nil, nil); md != 0 || bt != 0 {
		t.Fatal("empty input must give zeros")
	}
}

// (features F1 supply-audit cache tests moved to supply_audit_cache_test.go: one implementation, r19 merge)

func TestRangeSlotHonoursContext(t *testing.T) {
	var releases []func()
	for i := 0; i < RANGE_CONCURRENCY; i++ {
		r, err := acquire_range_slot(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, r)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := acquire_range_slot(ctx); err == nil {
		t.Fatal("a full semaphore must make the caller wait and then fail with its context")
	}
	for _, r := range releases {
		r()
	}
	r, err := acquire_range_slot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r()
}

// ------------------------------------------------------------ integration: a real simulator chain

func genesis_miner(t *testing.T) rpc.Address {
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

func TestR19MethodsOnSimulatorChain(t *testing.T) {
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
	old_chain := chain
	chain = c
	defer func() { chain = old_chain }()

	miner := genesis_miner(t)
	for i := 0; i < 6; i++ {
		cbl, _, err := c.Create_new_miner_block(miner)
		if err != nil {
			t.Fatal(err)
		}
		cbl.Bl.MiniBlocks = append(cbl.Bl.MiniBlocks, blockchain.ConvertBlockToMiniblock(*cbl.Bl, miner))
		if err, ok := c.Add_Complete_Block(cbl); !ok {
			t.Fatalf("block %d: %v", i, err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	top := c.Load_TOPO_HEIGHT()
	if top < 6 {
		t.Fatalf("topoheight %d after mining 6 blocks", top)
	}
	ctx := context.Background()

	hr, err := GetBlockHeadersRange(ctx, GetBlockHeadersRange_Params{Start: 1, End: top + 50})
	if err != nil || int64(len(hr.Headers)) != top || hr.Headers[0].TopoHeight != 1 || hr.Headers[len(hr.Headers)-1].TopoHeight != top {
		t.Fatalf("headers range: err %v, %d headers", err, len(hr.Headers))
	}
	for _, h := range hr.Headers {
		single, err := GetBlockHeaderByTopoHeight(ctx, rpc.GetBlockHeaderByTopoHeight_Params{TopoHeight: uint64(h.TopoHeight)})
		if err != nil || single.Block_Header.Hash != h.Hash {
			t.Fatalf("range header %d differs from GetBlockHeaderByTopoHeight", h.TopoHeight)
		}
	}
	if _, err := GetBlockHeadersRange(ctx, GetBlockHeadersRange_Params{Start: 0, End: MAX_HEADERS_RANGE}); err == nil && top >= MAX_HEADERS_RANGE {
		t.Fatal("limit not enforced")
	}

	mb, err := GetMiniBlocks(ctx, GetMiniBlocks_Params{TopoHeight: top})
	if err != nil || len(mb.MiniBlocks) != 1 || mb.BlockHash != hr.Headers[len(hr.Headers)-1].Hash {
		t.Fatalf("miniblocks: err %v %+v", err, mb)
	}
	m := mb.MiniBlocks[0]
	if m.Miner == "" || m.Miner == "unknown" || m.BeforeMs < -MBL_FUTURE_SLACK_MS || m.BeforeMs > 65_536 {
		t.Fatalf("miniblock miner %q before_ms %d", m.Miner, m.BeforeMs)
	}
	if _, err := GetMiniBlocks(ctx, GetMiniBlocks_Params{Hash: "zz"}); err == nil {
		t.Fatal("bad hash accepted")
	}
	mb2, err := GetMiniBlocks(ctx, GetMiniBlocks_Params{Hash: mb.BlockHash})
	if err != nil || mb2.TopoHeight != top {
		t.Fatalf("by hash: %v %d", err, mb2.TopoHeight)
	}

	dh, err := GetDifficultyHistory(ctx, GetDifficultyHistory_Params{Count: 4})
	if err != nil || len(dh.Points) != 4 || dh.Points[3].TopoHeight != top || dh.MeanDifficulty <= 0 {
		t.Fatalf("difficulty history: %v %+v", err, dh)
	}
	if _, err := GetDifficultyHistory(ctx, GetDifficultyHistory_Params{Count: MAX_DIFFICULTY_HISTORY + 1, End: MAX_DIFFICULTY_HISTORY + 5}); err == nil {
		t.Fatal("count limit not enforced")
	}

	tp, err := GetTxPoolDetail(ctx, GetTxPoolDetail_Params{})
	if err != nil || tp.Status != "OK" {
		t.Fatalf("txpool: %v", err)
	}
	if _, err := GetTxPoolDetail(ctx, GetTxPoolDetail_Params{Limit: MAX_TXPOOL_DETAIL + 1}); err == nil {
		t.Fatal("txpool limit not enforced")
	}
	if pi, err := GetPeerInfo(ctx); err != nil || pi.OurTopoHeight != top {
		t.Fatalf("peer info: %v", err)
	}
	if ts, err := GetTxStatus(ctx, GetTxStatus_Params{TxIDs: []string{hr.Headers[0].Hash, "bad"}}); err != nil || ts.TopoHeight != top || len(ts.Txs) != 2 || ts.Txs[0].State != "unknown" || ts.Txs[1].State != "invalid_txid" {
		t.Fatalf("tx status (r20): %v %+v", err, ts)
	}
	if fp := chain_fingerprint(); !strings.HasPrefix(fp, "n/a") {
		t.Fatalf("testnet fingerprint %q", fp)
	}
}

func TestTxPoolEntryRegistration(t *testing.T) {
	var tx transaction.Transaction
	tx.Version = 1
	tx.TransactionType = transaction.REGISTRATION
	e := tx_pool_entry(&tx, "regpool")
	if e.Pool != "regpool" || e.Type != "REGISTRATION" || e.Fee != 0 || e.Size == 0 || e.TXID == "" {
		t.Fatalf("%+v", e)
	}
}

// verifier F6: peer addresses only on a loopback bind unless explicitly opted in
func TestPeerInfoGate(t *testing.T) {
	none := func(string) string { return "" }
	optin := func(k string) string {
		if k == "ENABLE_PUBLIC_PEER_INFO" {
			return "1"
		}
		return ""
	}
	if !peerinfo_allowed("127.0.0.1:10102", none) || peerinfo_allowed("0.0.0.0:10102", none) || !peerinfo_allowed("0.0.0.0:10102", optin) {
		t.Fatal("peerinfo_allowed policy")
	}
	saved := rpc_bind_address
	defer func() { rpc_bind_address = saved }()
	rpc_bind_address = "0.0.0.0:10102"
	if _, err := GetPeerInfo(context.Background()); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("GetPeerInfo on a public bind: %v", err)
	}
}

// verifier F5: the limit is validated, and the call takes a range slot (an expired ctx gives up while both are held)
func TestTxPoolDetailLimitsAndSlot(t *testing.T) {
	for _, l := range []int{-1, MAX_TXPOOL_DETAIL + 1} {
		if _, err := GetTxPoolDetail(context.Background(), GetTxPoolDetail_Params{Limit: l}); err == nil || !strings.Contains(err.Error(), "limit must be") {
			t.Fatalf("limit %d: %v", l, err)
		}
	}
	var releases []func()
	for i := 0; i < RANGE_CONCURRENCY; i++ {
		r, _ := acquire_range_slot(context.Background())
		releases = append(releases, r)
	}
	defer func() {
		for _, r := range releases {
			r()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := GetTxPoolDetail(ctx, GetTxPoolDetail_Params{}); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("GetTxPoolDetail ran without a range slot: %v", err)
	}
}
