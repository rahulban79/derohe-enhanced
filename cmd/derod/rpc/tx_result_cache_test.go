package rpc

import (
	"context"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/derohe/walletapi"
)

func r22_mine(t *testing.T, c *blockchain.Blockchain, miner rpc.Address) {
	cbl, _, err := c.Create_new_miner_block(miner)
	if err != nil {
		t.Fatal(err)
	}
	cbl.Bl.MiniBlocks = append(cbl.Bl.MiniBlocks, blockchain.ConvertBlockToMiniblock(*cbl.Bl, miner))
	if err, ok := c.Add_Complete_Block(cbl); !ok {
		t.Fatalf("block: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
}

func r22_json(t *testing.T, v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func r22_reset_tx_cache() {
	tx_cache.Lock()
	tx_cache.m = map[crypto.Hash]*tx_result_entry{}
	tx_cache.bytes = 0
	tx_cache.hits, tx_cache.verified = 0, 0
	tx_cache.Unlock()
}

// r22: GetTransaction's verify-on-hit cache returns exactly the uncached answer, re-proves every hit, and drops an
// entry whose inputs changed (a block joining the tx's search range; a different topo record).
func TestR22TxResultCacheOnSimulatorChain(t *testing.T) {
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
	SetTxResultCache(true) // r22 merge: off by default (timing oracle); this test exercises the enabled cache
	defer SetTxResultCache(false)
	r22_reset_tx_cache()
	defer r22_reset_tx_cache()

	walletapi.Initialize_LookupTable(1, 1<<12)
	var txids []string
	var hashes []crypto.Hash
	for i := 0; i < 3; i++ {
		w, err := walletapi.Create_Encrypted_Wallet_Memory("", new(crypto.BNRed).SetBytes(big.NewInt(int64(3000017+i*104729)).Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		reg := w.GetRegistrationTX()
		if err := c.Add_TX_To_Pool(reg); err != nil {
			t.Fatal(err)
		}
		txids = append(txids, reg.GetHash().String())
		hashes = append(hashes, reg.GetHash())
	}
	miner := genesis_miner(t)
	r22_mine(t, c, miner)

	ctx := context.Background()
	p := rpc.GetTransaction_Params{Tx_Hashes: append(append([]string{}, txids...), "00000000000000000000000000000000000000000000000000000000000000ab")}
	uncached := func() string {
		r22_reset_tx_cache()
		r, err := get_transaction(c, ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		return r22_json(t, r)
	}

	// IS_TX_Valid equivalence: tx_validity must give the chain's answer for every tx
	for _, h := range hashes {
		var tx_bytes []byte
		if tx_bytes, err = c.Store.Block_tx_store.ReadTX(h); err != nil {
			t.Fatal(err)
		}
		var tx = new_tx_from(t, tx_bytes)
		vb, ib, v := c.IS_TX_Valid(h)
		vb2, ib2, v2, blids, ok := tx_validity(c, h, tx)
		if vb != vb2 || v != v2 || len(ib) != len(ib2) || !ok || len(blids) == 0 || !v {
			t.Fatalf("tx_validity %x: (%x %v %v) vs chain (%x %v %v), ok %v, %d blids", h, vb2, ib2, v2, vb, ib, v, ok, len(blids))
		}
	}

	for round := 0; round < 4; round++ { // the tx's range [h+1, h+23] gains a block each round: every proof must fail
		want := uncached()
		r22_reset_tx_cache()
		r1, _ := get_transaction(c, ctx, p) // fills
		if got := r22_json(t, r1); got != want {
			t.Fatalf("round %d fill differs:\n%s\n%s", round, got, want)
		}
		if n := len(tx_cache.m); n != len(txids) {
			t.Fatalf("round %d: %d entries cached, want %d (not-found answers are never cached)", round, n, len(txids))
		}
		r2, _ := get_transaction(c, ctx, p) // hits
		if got := r22_json(t, r2); got != want {
			t.Fatalf("round %d hit differs:\n%s\n%s", round, got, want)
		}
		if tx_cache.hits != uint64(len(txids)) || tx_cache.verified != uint64(len(txids)) { // r1 found nothing, r2 hit all
			t.Fatalf("round %d: hits %d verified %d, want %d proven hits", round, tx_cache.hits, tx_cache.verified, len(txids))
		}
		r22_mine(t, c, miner)
		r3, _ := get_transaction(c, ctx, p) // range changed: proof fails, recompute
		if got := r22_json(t, r3); got != uncached() {
			t.Fatalf("round %d answer after a new block differs from an uncached one", round)
		}
	}

	// a changed topo record (what a rewind + different state would leave) must fail the proof
	get_transaction(c, ctx, p)
	tx_cache.Lock()
	for _, e := range tx_cache.m {
		e.record.State_Version++
		e.related.Signer = "poisoned"
	}
	tx_cache.hits, tx_cache.verified = 0, 0
	tx_cache.Unlock()
	r4, _ := get_transaction(c, ctx, p)
	if got := r22_json(t, r4); got != uncached() || tx_cache.hits != 0 {
		t.Fatalf("a poisoned entry with a different topo record was served (hits %d)", tx_cache.hits)
	}

	// a changed block set must fail the proof as well
	get_transaction(c, ctx, p)
	tx_cache.Lock()
	for _, e := range tx_cache.m {
		e.blids = append(e.blids[1:], crypto.Hash{1})
		e.related.Signer = "poisoned"
	}
	tx_cache.hits, tx_cache.verified = 0, 0
	tx_cache.Unlock()
	r5, _ := get_transaction(c, ctx, p)
	if got := r22_json(t, r5); got != uncached() || tx_cache.hits != 0 {
		t.Fatalf("a poisoned entry with a different block set was served (hits %d)", tx_cache.hits)
	}
}

func TestR22SameHashSet(t *testing.T) {
	a, b, c := crypto.Hash{1}, crypto.Hash{2}, crypto.Hash{3}
	cases := []struct {
		x, y []crypto.Hash
		want bool
	}{
		{nil, nil, true},
		{[]crypto.Hash{a, b}, []crypto.Hash{b, a}, true},
		{[]crypto.Hash{a, b}, []crypto.Hash{a, c}, false},
		{[]crypto.Hash{a, a}, []crypto.Hash{a, b}, false},
		{[]crypto.Hash{a, b}, []crypto.Hash{a, a}, false},
		{[]crypto.Hash{a}, []crypto.Hash{a, b}, false},
	}
	for i, k := range cases {
		if same_hash_set(k.x, k.y) != k.want {
			t.Fatalf("case %d", i)
		}
	}
}

// r22 merge: the cache is opt-in. Off (the default), put keeps nothing and lookup never serves, so a reply's timing
// says nothing about other clients' queries; SetTxResultCache(false) also empties it.
func TestR22TxCacheOffByDefault(t *testing.T) {
	if TxResultCacheOn() {
		t.Fatal("GetTransaction's result cache is on by default")
	}
	r22_reset_tx_cache()
	defer r22_reset_tx_cache()
	tx_cache.put(crypto.Hash{7}, &tx_result_entry{hex: "ab"})
	if len(tx_cache.m) != 0 {
		t.Fatal("put cached an answer while the cache is off")
	}
	tx_cache.Lock()
	tx_cache.m[crypto.Hash{7}] = &tx_result_entry{hex: "ab"}
	tx_cache.Unlock()
	if e := tx_cache.lookup(nil, crypto.Hash{7}, nil); e != nil {
		t.Fatal("lookup served an entry while the cache is off")
	}
	SetTxResultCache(true)
	SetTxResultCache(false)
	if len(tx_cache.m) != 0 {
		t.Fatal("turning the cache off did not empty it")
	}
}

func TestR22TxCacheBounded(t *testing.T) {
	SetTxResultCache(true)
	defer SetTxResultCache(false)
	r22_reset_tx_cache()
	defer r22_reset_tx_cache()
	for i := 0; i < tx_result_cache_max+5; i++ {
		var h crypto.Hash
		h[0], h[1], h[2] = byte(i), byte(i>>8), byte(i>>16)
		tx_cache.put(h, &tx_result_entry{})
	}
	if n := len(tx_cache.m); n > tx_result_cache_max {
		t.Fatalf("cache grew to %d > %d", n, tx_result_cache_max)
	}

	// byte bound: 100 KB answers fill at most tx_result_cache_max_bytes; an oversized answer is not kept at all
	r22_reset_tx_cache()
	blob := strings.Repeat("ab", 50<<10)
	for i := 0; i < 2*tx_result_cache_max_bytes/len(blob); i++ {
		var h crypto.Hash
		h[0], h[1] = byte(i), byte(i>>8)
		tx_cache.put(h, &tx_result_entry{hex: blob})
		if tx_cache.bytes > tx_result_cache_max_bytes {
			t.Fatalf("byte bound exceeded: %d > %d after %d puts", tx_cache.bytes, tx_result_cache_max_bytes, i+1)
		}
	}
	sum := 0
	for _, e := range tx_cache.m {
		sum += e.size()
	}
	if sum != tx_cache.bytes || len(tx_cache.m) == 0 {
		t.Fatalf("byte accounting %d, entries sum to %d (%d entries)", tx_cache.bytes, sum, len(tx_cache.m))
	}
	n := len(tx_cache.m)
	tx_cache.put(crypto.Hash{0xff, 0xfe}, &tx_result_entry{hex: strings.Repeat("x", tx_result_cache_max_bytes/64+1)})
	if len(tx_cache.m) != n {
		t.Fatal("an answer larger than 1/64 of the budget was cached")
	}
	var present crypto.Hash
	for h := range tx_cache.m {
		present = h
		break
	}
	tx_cache.put(present, &tx_result_entry{hex: "x"}) // replace a present key: accounting must not double count
	if len(tx_cache.m) != n {
		t.Fatalf("replacing a key changed the entry count %d -> %d", n, len(tx_cache.m))
	}
	tx_cache.drop(present)
	sum = 0
	for _, e := range tx_cache.m {
		sum += e.size()
	}
	if sum != tx_cache.bytes {
		t.Fatalf("after replace+drop: accounting %d, entries sum to %d", tx_cache.bytes, sum)
	}
}

func new_tx_from(t *testing.T, b []byte) *transaction.Transaction {
	var tx transaction.Transaction
	if err := tx.Deserialize(b); err != nil {
		t.Fatal(err)
	}
	return &tx
}
