package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/walletapi"
)

// fake_topo is a topo index the tests rewrite to simulate reorgs.
type fake_topo struct {
	blid   map[int64]crypto.Hash
	height map[crypto.Hash]int64
	broken map[int64]bool
}

func new_fake_topo(n int64) *fake_topo {
	f := &fake_topo{blid: map[int64]crypto.Hash{}, height: map[crypto.Hash]int64{}, broken: map[int64]bool{}}
	for t := int64(0); t <= n; t++ {
		f.set(t, fmt.Sprintf("a%d", t), t)
	}
	return f
}
func (f *fake_topo) set(t int64, name string, h int64) {
	b := crypto.Keccak256([]byte(name))
	f.blid[t] = b
	f.height[b] = h
}
func (f *fake_topo) at(t int64) (crypto.Hash, error) {
	if b, ok := f.blid[t]; ok && !f.broken[t] {
		return b, nil
	}
	return crypto.Hash{}, fmt.Errorf("no topo %d", t)
}
func (f *fake_topo) h(b crypto.Hash) int64 { return f.height[b] }

// The tracker names the lowest replaced topoheight, counts vanished ones, leaves unreadable ones unjudged and flags a
// replacement at or below the final height announced at the previous block.
func TestR23bReorgTracker(t *testing.T) {
	r := new_reorg_tracker()
	f := new_fake_topo(100)
	if ev := r.observe(100, f.at, f.h, 90, 100); ev != nil {
		t.Fatalf("baseline produced an event: %+v", ev)
	}
	f.set(101, "a101", 101)
	if ev := r.observe(101, f.at, f.h, 91, 101); ev != nil {
		t.Fatalf("a plain extension produced an event: %+v", ev)
	}
	// replace topo 97..101 with a sibling branch that is one topoheight longer
	for t2 := int64(97); t2 <= 102; t2++ {
		f.set(t2, fmt.Sprintf("b%d", t2), t2)
	}
	ev := r.observe(102, f.at, f.h, 92, 102)
	if ev == nil || ev.ForkTopoHeight != 97 || ev.Replaced != 5 || ev.LowestReplacedHeight != 97 || ev.OldTopoHeight != 101 ||
		ev.NewTopoHeight != 102 || ev.Seq != 1 || len(ev.OldHashes) != 5 || ev.FinalViolated || ev.FinalHeightBefore != 91 {
		t.Fatalf("reorg event %+v", ev)
	}
	if ev.OldHashes[0] != crypto.Keccak256([]byte("a97")).String() || ev.NewTopHash != crypto.Keccak256([]byte("b102")).String() {
		t.Fatalf("hashes %+v", ev)
	}
	// the tip shrinks: 101 and 102 vanish, 100 changes
	delete(f.blid, 101)
	delete(f.blid, 102)
	f.set(100, "c100", 100)
	ev = r.observe(100, f.at, f.h, 92, 100)
	if ev == nil || ev.ForkTopoHeight != 100 || ev.Replaced != 3 || ev.Seq != 2 || ev.LocalRewind { // 100 changed: a network reorg
		t.Fatalf("shrink event %+v", ev)
	}
	// an unreadable topoheight is not a replacement
	f.broken[99] = true
	if ev := r.observe(100, f.at, f.h, 92, 100); ev != nil {
		t.Fatalf("unreadable topo judged as replaced: %+v", ev)
	}
	delete(f.broken, 99)
	r.observe(100, f.at, f.h, 92, 100)
	// a block at height 92 (= final announced before) replaced: violation
	f.set(92, "d92", 92)
	ev = r.observe(100, f.at, f.h, 92, 100)
	if ev == nil || !ev.FinalViolated || ev.LowestReplacedHeight != 92 {
		t.Fatalf("violation not flagged: %+v", ev)
	}
	st := r.stats()
	if st.Reorgs != 3 || st.Violations != 1 || st.Deepest != 5 || st.ReplacedTotal != 9 || st.Last == nil || st.Last.Seq != 3 ||
		st.DeepestHeights != 8 || st.Window != REORG_WINDOW {
		t.Fatalf("stats %+v", st)
	}
	// replacement just above the final height is not a violation
	f.set(93, "e93", 93)
	if ev := r.observe(100, f.at, f.h, 92, 100); ev == nil || ev.FinalViolated {
		t.Fatalf("above-final replacement: %+v", ev)
	}
	// stats are a copy
	st.Last.OldHashes[0] = "x"
	if r.stats().Last.OldHashes[0] == "x" {
		t.Fatal("stats share the event's slice")
	}
}

// r23b merge (RPCWS23B-B fix): a local pop of 19 topoheights below the announced final height, then regrowth on the
// same blocks, is a local rewind, never a finality violation
func TestR23bReorgLocalRewindIsNotViolation(t *testing.T) {
	r := new_reorg_tracker()
	f := new_fake_topo(100)
	r.observe(100, f.at, f.h, 91, 100)
	for t2 := int64(82); t2 <= 100; t2++ {
		delete(f.blid, t2)
	}
	ev := r.observe(81, f.at, f.h, 72, 81)
	if ev == nil || !ev.LocalRewind || ev.FinalViolated || ev.Replaced != 19 || ev.FinalHeightBefore != 91 {
		t.Fatalf("pop event %+v", ev)
	}
	for t2 := int64(82); t2 <= 100; t2++ {
		f.set(t2, fmt.Sprintf("r%d", t2), t2)
	}
	if ev := r.observe(100, f.at, f.h, 91, 100); ev != nil {
		t.Fatalf("regrowth after the pop produced an event: %+v", ev)
	}
	st := r.stats()
	if st.Violations != 0 || st.LocalRewinds != 1 || st.Reorgs != 1 {
		t.Fatalf("stats after pop+regrow %+v", st)
	}
	// a network reorg (a slot at or below the new top changed) at the final height is still a violation
	f.set(91, "x91", 91)
	if ev := r.observe(100, f.at, f.h, 91, 100); ev == nil || ev.LocalRewind || !ev.FinalViolated {
		t.Fatalf("network replacement at the final height not flagged: %+v", ev)
	}
}

// Reorg goes to Reorg subscribers only, before Block; BlockInfo carries reorg_seq once there was one.
func TestR23bReorgPush(t *testing.T) {
	addr := test_server(t)
	before := ws_count()
	sub := dial_ws(t, addr, true)
	plain := dial_ws(t, addr, true)
	wait_ws_count(t, before+2)
	if r := sub.call(t, 1, "DERO.Subscribe", `{"events":["Reorg","BlockInfo"]}`); string(r["result"]) != `{"events":["BlockInfo","Reorg"],"status":"OK"}` {
		t.Fatalf("Subscribe: %s", r["result"])
	}
	ev := &Reorg_Event{Seq: 4, ForkTopoHeight: 97, Replaced: 2, LowestReplacedHeight: 97, OldHashes: []string{"aa", "bb"}, FinalHeightBefore: 90}
	push_block_ev(func() BlockInfo_Event { return BlockInfo_Event{Height: 9, ReorgSeq: 4} }, ev)
	bi := sub.wait(t, "method", `"BlockInfo"`, 3*time.Second) // last of the bundle
	if !strings.Contains(string(bi["params"]), `"reorg_seq":4`) {
		t.Fatalf("BlockInfo %s", bi["params"])
	}
	sub.mu.Lock() // what is left is in arrival order: Reorg, Block, Height
	order := []string{}
	for _, x := range sub.got {
		order = append(order, string(x["method"]))
	}
	sub.mu.Unlock()
	if strings.Join(order, ",") != `"Reorg","Block","Height"` {
		t.Fatalf("push order %v", order)
	}
	m := sub.wait(t, "method", `"Reorg"`, time.Second)
	var got Reorg_Event
	if err := json.Unmarshal(m["params"], &got); err != nil || got.ForkTopoHeight != 97 || got.Seq != 4 || len(got.OldHashes) != 2 {
		t.Fatalf("Reorg params %s (%v)", m["params"], err)
	}
	plain.wait(t, "method", `"Block"`, 3*time.Second)
	time.Sleep(100 * time.Millisecond)
	plain.mu.Lock()
	for _, x := range plain.got {
		if string(x["method"]) == `"Reorg"` {
			t.Errorf("Reorg sent to an unsubscribed socket")
		}
	}
	plain.mu.Unlock()
}

// The facts of the real table: 75 entries, all built before HF3, Parity never set, window long closed.
func TestR23bHF3Facts(t *testing.T) {
	f := hf3_facts(blockchain.HF3_Affected_Txs, 7504640)
	if f.Entries != 75 || !f.AllBelowHF3 || f.ParityTrue != 0 || f.MaxHeight >= 7504640 || f.MinHeight == 0 || f.MinHeight > f.MaxHeight {
		t.Fatalf("facts %+v", f)
	}
	if f.LastIncludableHeight != f.MaxHeight+blockchain.TX_VALIDITY_HEIGHT-1 || len(f.List) != 75 || len(f.Digest) != 64 {
		t.Fatalf("window/list/digest %+v", f)
	}
	for i := 1; i < len(f.List); i++ {
		if f.List[i-1].TxID >= f.List[i].TxID {
			t.Fatal("list not sorted by txid")
		}
	}
	if again := hf3_facts(blockchain.HF3_Affected_Txs, 7504640); again.Digest != f.Digest {
		t.Fatal("digest not deterministic")
	}
	// one changed bit changes the digest; an entry at HF3 breaks all_below_hf3 and the status
	tbl := map[string]*blockchain.HF3_Tx_Data{}
	for k, v := range blockchain.HF3_Affected_Txs {
		c := *v
		tbl[k] = &c
	}
	for _, v := range tbl {
		v.Parity = true
		break
	}
	g := hf3_facts(tbl, 7504640)
	if g.Digest == f.Digest || g.ParityTrue != 1 {
		t.Fatalf("a changed entry kept the digest: %+v", g)
	}
	tbl["ff"] = &blockchain.HF3_Tx_Data{Height: 7504640}
	g = hf3_facts(tbl, 7504640)
	if g.AllBelowHF3 || g.Entries != 76 {
		t.Fatalf("entry at HF3 not seen: %+v", g)
	}
	em := GetEmissionAudit_Result{Enabled: true, Status: "OK", Verdicts: map[string]uint64{"ok": 3}}
	if res := monetary_integrity(GetMonetaryIntegrity_Params{}, em, g, Reorg_Stats{}, 7834099); res.Status != "ALERT" || res.HF3Exemption.List != nil {
		t.Fatalf("status with an HF3+ entry: %s", res.Status)
	}
	// testnet (HF3 at genesis): every tx gets the full-tx cache key, so no alert
	if res := monetary_integrity(GetMonetaryIntegrity_Params{}, em, hf3_facts(blockchain.HF3_Affected_Txs, 0), Reorg_Stats{}, 10); res.Status != "OK" {
		t.Fatalf("testnet status %s", res.Status)
	}
	res := monetary_integrity(GetMonetaryIntegrity_Params{List: true}, em, f, Reorg_Stats{}, 7834099)
	if res.Status != "OK" || !res.HF3Exemption.WindowClosed || len(res.HF3Exemption.List) != 75 || len(res.Limits) < 3 || res.Emission.Verdicts["ok"] != 3 {
		t.Fatalf("result %+v", res)
	}
	if res := monetary_integrity(GetMonetaryIntegrity_Params{}, em, f, Reorg_Stats{}, int64(f.LastIncludableHeight)); res.HF3Exemption.WindowClosed {
		t.Fatal("window closed at the last includable height itself")
	}
	if res := monetary_integrity(GetMonetaryIntegrity_Params{}, em, f, Reorg_Stats{Violations: 1}, 7834099); res.Status != "ALERT" {
		t.Fatal("a finality violation must alert")
	}
	em.Alerts = 1
	if res := monetary_integrity(GetMonetaryIntegrity_Params{}, em, f, Reorg_Stats{}, 7834099); res.Status != "ALERT" {
		t.Fatal("an emission alert must alert")
	}
}

// On a real simulator chain: the per-block observation sees no reorg on a single-miner chain, and the RPC answers.
func TestR23bReorgObserverOnSimulatorChain(t *testing.T) {
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
	old_chain, old_state := chain, reorg_state
	chain, reorg_state = c, new_reorg_tracker()
	defer func() { chain, reorg_state = old_chain, old_state }()
	miner := genesis_miner(t)
	var cost time.Duration
	for i := 0; i < 24; i++ {
		r22_mine(t, c, miner)
		s := time.Now()
		if ev := observe_chain_reorg(); ev != nil {
			t.Fatalf("reorg on a single-miner chain: %+v", ev)
		}
		cost += time.Since(s)
	}
	st := reorg_state.stats()
	if st.Observed != 24 || st.Reorgs != 0 || st.Violations != 0 {
		t.Fatalf("stats %+v", st)
	}
	t.Logf("observe_chain_reorg: %v per block (window %d)", cost/24, REORG_WINDOW)
	res, err := GetMonetaryIntegrity(context.Background(), GetMonetaryIntegrity_Params{})
	if err != nil || res.HF3Exemption.Entries != 75 || res.Finality.Observed != 24 || res.HF3Exemption.ChainHeight != c.Get_Height() {
		t.Fatalf("GetMonetaryIntegrity: %v %+v", err, res)
	}
}

// The settled-tx cache stores only answers whose whole IS_TX_Valid window is at or below the final height, drops an
// entry whose block left its topoheight, rotates when full, and is emptied by a finality violation.
func TestR23bFinalTxCache(t *testing.T) {
	if final_tx_settled(100, 100+2*blockchain.TX_VALIDITY_HEIGHT-1) || !final_tx_settled(100, 100+2*blockchain.TX_VALIDITY_HEIGHT) ||
		final_tx_settled(0, 1000) || final_tx_settled(100, -1) {
		t.Fatal("settled rule")
	}
	c := new_final_tx_cache(true)
	f := new_fake_topo(50)
	tx := crypto.Keccak256([]byte("tx1"))
	e := final_tx_entry{blid: f.blid[10], topo: 10, height: 10}
	c.store(tx, e)
	if got, ok := c.lookup(tx, f.at); !ok || got != e {
		t.Fatalf("hit %v %+v", ok, got)
	}
	if b, ok := c.block(e.blid); !ok || b.topo != 10 {
		t.Fatal("block index")
	}
	f.set(10, "other", 10) // the block left topoheight 10
	if _, ok := c.lookup(tx, f.at); ok {
		t.Fatal("stale entry served")
	}
	if _, ok := c.block(e.blid); ok || c.size() != 0 {
		t.Fatal("stale entry kept")
	}
	off := new_final_tx_cache(false)
	off.store(tx, e)
	if _, ok := off.lookup(tx, f.at); ok || off.size() != 0 {
		t.Fatal("disabled cache answered")
	}
	// rotation: the size stays bounded and recent entries survive
	for i := 0; i < FINAL_TX_CACHE_MAX+10; i++ {
		c.store(crypto.Keccak256([]byte(fmt.Sprint("r", i))), final_tx_entry{blid: f.blid[5], topo: 5, height: 5})
	}
	if n := c.size(); n > FINAL_TX_CACHE_MAX || n < FINAL_TX_CACHE_MAX/2 {
		t.Fatalf("size %d", n)
	}
	last := crypto.Keccak256([]byte(fmt.Sprint("r", FINAL_TX_CACHE_MAX+9)))
	if _, ok := c.lookup(last, f.at); !ok {
		t.Fatal("newest entry rotated out")
	}
	// a finality violation flushes the package cache
	old := final_txs
	final_txs = new_final_tx_cache(true)
	defer func() { final_txs = old }()
	final_txs.store(tx, final_tx_entry{blid: f.blid[20], topo: 20, height: 20})
	r := new_reorg_tracker()
	r.observe(50, f.at, f.h, 45, 50)
	f.set(40, "z40", 40)
	if ev := r.observe(50, f.at, f.h, 45, 50); ev == nil || !ev.FinalViolated || final_txs.size() != 0 {
		t.Fatalf("violation did not flush: %+v size %d", ev, final_txs.size())
	}
}

// On a simulator chain: a settled registration tx is cached on its first GetTxStatus, served from the cache (same
// answer, confirmations still counted) and re-verified when the entry is wrong.
func TestR23bFinalTxCacheOnSimulatorChain(t *testing.T) {
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
	old_chain, old_cache := chain, final_txs
	chain, final_txs = c, new_final_tx_cache(true)
	defer func() { chain, final_txs = old_chain, old_cache }()

	walletapi.Initialize_LookupTable(1, 1<<12)
	w, err := walletapi.Create_Encrypted_Wallet_Memory("", new(crypto.BNRed).SetBytes(big.NewInt(4000039).Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	reg := w.GetRegistrationTX()
	if err := c.Add_TX_To_Pool(reg); err != nil {
		t.Fatal(err)
	}
	txid := reg.GetHash().String()
	miner := genesis_miner(t)
	ctx := context.Background()
	for i := 0; i < 12; i++ {
		r22_mine(t, c, miner)
	}
	ts, _ := GetTxStatus(ctx, GetTxStatus_Params{TxIDs: []string{txid}})
	if ts.Txs[0].State != "mined" || !ts.Txs[0].Final || final_txs.size() != 0 {
		t.Fatalf("final but not yet settled must not be cached: %+v size %d (final_height %d)", ts.Txs[0], final_txs.size(), ts.FinalHeight)
	}
	for i := 0; i < 2*int(blockchain.TX_VALIDITY_HEIGHT)+2; i++ {
		r22_mine(t, c, miner)
	}
	t0 := time.Now()
	a, _ := GetTxStatus(ctx, GetTxStatus_Params{TxIDs: []string{txid}})
	miss := time.Since(t0)
	if final_txs.size() != 1 {
		t.Fatalf("settled tx not cached: %+v (final_height %d)", a.Txs[0], a.FinalHeight)
	}
	r22_mine(t, c, miner)
	t0 = time.Now()
	b, _ := GetTxStatus(ctx, GetTxStatus_Params{TxIDs: []string{txid}})
	hit := time.Since(t0)
	if b.Txs[0].BlockHash != a.Txs[0].BlockHash || b.Txs[0].TopoHeight != a.Txs[0].TopoHeight || b.Txs[0].Height != a.Txs[0].Height ||
		!b.Txs[0].Final || b.Txs[0].Confirmations != a.Txs[0].Confirmations+1 {
		t.Fatalf("cached answer differs: %+v vs %+v", b.Txs[0], a.Txs[0])
	}
	t.Logf("GetTxStatus settled tx: miss %v, hit %v", miss, hit)
	// a wrong entry (block not at that topoheight) is detected and the full lookup answers
	h := crypto.HashHexToHash(txid)
	final_txs.flush()
	final_txs.store(h, final_tx_entry{blid: crypto.Keccak256([]byte("bogus")), topo: a.Txs[0].TopoHeight, height: a.Txs[0].Height})
	d, _ := GetTxStatus(ctx, GetTxStatus_Params{TxIDs: []string{txid}})
	if d.Txs[0].BlockHash != a.Txs[0].BlockHash {
		t.Fatalf("bogus cache entry served: %+v", d.Txs[0])
	}
}
