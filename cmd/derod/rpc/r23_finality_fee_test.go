package rpc

import (
	"context"
	"math/big"
	"testing"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/walletapi"
)

// final_height_scan: the highest height <= H-STABLE_LIMIT-1 with exactly one block; never H-STABLE_LIMIT itself
// (consensus still accepts a block there, blockchain.go:481-484), -1 when the scanned window has none.
func TestR23FinalHeightScan(t *testing.T) {
	one := func(int64) int { return 1 }
	if got := final_height_scan(100, 8, one); got != 91 {
		t.Fatalf("all single: got %d want 91 (= 100-8-1)", got)
	}
	two_at := func(xs ...int64) func(int64) int {
		return func(h int64) int {
			for _, x := range xs {
				if h == x {
					return 2
				}
			}
			return 1
		}
	}
	if got := final_height_scan(100, 8, two_at(91, 90)); got != 89 {
		t.Fatalf("side blocks at 91 and 90: got %d want 89", got)
	}
	none := func(int64) int { return 2 }
	if got := final_height_scan(100, 8, none); got != -1 {
		t.Fatalf("no sync height in the window: got %d", got)
	}
	if got := final_height_scan(5, 8, one); got != -1 {
		t.Fatalf("a chain shorter than the stable limit has nothing final: got %d", got)
	}
	calls := 0
	final_height_scan(1000000, 8, func(int64) int { calls++; return 0 })
	if calls != FINAL_SCAN {
		t.Fatalf("scan is bounded: %d lookups, want %d", calls, FINAL_SCAN)
	}
}

type fake_final_src struct {
	fake_tx_src
	heights       map[crypto.Hash]int64
	final, stable int64
	h             int64
}

func (f fake_final_src) height_of(b crypto.Hash) int64 { return f.heights[b] }
func (f fake_final_src) final_height() (int64, int64)  { return f.final, f.stable }
func (f fake_final_src) chain_height() int64           { return f.h }

func TestR23FinalityApply(t *testing.T) {
	blk := crypto.HashHexToHash("bb00000000000000000000000000000000000000000000000000000000000001")
	src := fake_final_src{heights: map[crypto.Hash]int64{blk: 80}, final: 91, stable: 92, h: 100}
	apply, final, stable, ok := finality(src, 100)
	if !ok || final != 91 || stable != 92 {
		t.Fatalf("heights: %d %d %v", final, stable, ok)
	}
	s := TxStatus{State: "mined", BlockHash: blk.String()}
	apply(&s)
	if s.Height != 80 || !s.Final || s.BlocksToFinal != 0 {
		t.Fatalf("deep tx: %+v", s)
	}
	src.heights[blk] = 95
	s = TxStatus{State: "mined", BlockHash: blk.String()}
	apply(&s)
	if s.Final || s.BlocksToFinal != 95+config.STABLE_LIMIT+1-100 {
		t.Fatalf("recent tx: %+v", s)
	}
	src.heights[blk] = 91 // at the final height itself
	s = TxStatus{State: "mined", BlockHash: blk.String()}
	apply(&s)
	if !s.Final {
		t.Fatalf("a tx at final_height is final: %+v", s)
	}
	p := TxStatus{State: "pool"}
	apply(&p)
	if p.Final || p.Height != 0 || p.BlocksToFinal != 0 {
		t.Fatalf("pool entries get no finality: %+v", p)
	}
	// sources without finality support: no-op
	apply2, f2, s2, ok2 := finality(fake_tx_src{}, 100)
	q := TxStatus{State: "mined", BlockHash: blk.String()}
	apply2(&q)
	if ok2 || f2 != -1 || s2 != -1 || q.Final || q.Height != 0 {
		t.Fatalf("no finality source: %+v", q)
	}
}

// End to end on a simulator chain: a registration tx is mined, is not final while consensus can still accept blocks
// that change the order around it, and becomes final exactly when its height reaches H-STABLE_LIMIT-1.
func TestR23TxFinalityOnSimulatorChain(t *testing.T) {
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

	walletapi.Initialize_LookupTable(1, 1<<12)
	w, err := walletapi.Create_Encrypted_Wallet_Memory("", new(crypto.BNRed).SetBytes(big.NewInt(4000037).Bytes()))
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
	r22_mine(t, c, miner)
	mined_at := int64(-1)
	for i := 0; i < 20; i++ {
		ts, err := GetTxStatus(ctx, GetTxStatus_Params{TxIDs: []string{txid}})
		if err != nil || len(ts.Txs) != 1 {
			t.Fatalf("GetTxStatus: %v", err)
		}
		s := ts.Txs[0]
		h := c.Get_Height()
		if ts.StableHeight != h-config.STABLE_LIMIT {
			t.Fatalf("stable_height %d at height %d", ts.StableHeight, h)
		}
		if s.State == "mined" {
			if mined_at < 0 {
				mined_at = s.Height
			}
			if s.Height != mined_at {
				t.Fatalf("block height moved: %d -> %d", mined_at, s.Height)
			}
			want_final := s.Height <= h-config.STABLE_LIMIT-1
			if s.Final != want_final {
				t.Fatalf("height %d, tx at %d: final=%v want %v (final_height %d)", h, s.Height, s.Final, want_final, ts.FinalHeight)
			}
			if !s.Final && s.BlocksToFinal != s.Height+config.STABLE_LIMIT+1-h {
				t.Fatalf("blocks_to_final %d at height %d (tx at %d)", s.BlocksToFinal, h, s.Height)
			}
			if s.Final && s.BlocksToFinal != 0 {
				t.Fatalf("final with blocks_to_final %d", s.BlocksToFinal)
			}
		}
		r22_mine(t, c, miner)
	}
	if mined_at < 0 {
		t.Fatal("the registration tx was never mined")
	}
	ts, _ := GetTxStatus(ctx, GetTxStatus_Params{TxIDs: []string{txid}})
	if !ts.Txs[0].Final {
		t.Fatalf("after 20 blocks the tx must be final: %+v (final_height %d)", ts.Txs[0], ts.FinalHeight)
	}
	// fee estimate on an empty pool: the floor, nothing to clear
	fe, err := GetFeeEstimate(ctx, GetFeeEstimate_Params{Size: 2500})
	if err != nil || fe.Status != "OK" || fe.PoolTxs != 0 || fe.NextBlockFeePerByte != 0 || fe.FeeForSize != 3*config.FEE_PER_KB || fe.MinFeePerKB != config.FEE_PER_KB {
		t.Fatalf("fee estimate: %v %+v", err, fe)
	}
	if _, err := GetFeeEstimate(ctx, GetFeeEstimate_Params{Size: config.STARGATE_HE_MAX_TX_SIZE + 1}); err == nil {
		t.Fatal("an impossible tx size is refused")
	}
}

func TestR23FeeSummary(t *testing.T) {
	// pool fits: the floor is enough
	r := fee_summary([]fee_pool_entry{{size: 2000, fee: 100, per_byte: 0}, {size: 3000, fee: 6000, per_byte: 2}}, 10000)
	if r.NextBlockFeePerByte != 0 || r.BlocksToClear != 1 || r.PoolBytes != 5000 || r.PoolTxs != 2 || r.PoolFeePerByteZero != 1 {
		t.Fatalf("fits: %+v", r)
	}
	if r.PoolFeePerKBP10 != 100*1024/2000 || r.PoolFeePerKBP90 != 6000*1024/3000 {
		t.Fatalf("percentiles: %+v", r)
	}
	// congested: selection order 5,3,3,1 per byte; capacity 2 txs of 4000; the cutoff tx ranks 3 -> pay 4 per byte
	es := []fee_pool_entry{{4000, 20000, 5}, {4000, 12000, 3}, {4000, 12000, 3}, {4000, 4000, 1}}
	r = fee_summary(es, 8000)
	if r.NextBlockFeePerByte != 4 || r.BlocksToClear != 2 {
		t.Fatalf("congested: %+v", r)
	}
	if got := fee_for_size(r.NextBlockFeePerByte, 2500); got != 10000 {
		t.Fatalf("fee_for_size congested: %d", got)
	}
	if got := fee_for_size(0, 2500); got != 3*config.FEE_PER_KB {
		t.Fatalf("fee_for_size floor: %d", got)
	}
	if got := floor_fee(1024); got != config.FEE_PER_KB {
		t.Fatalf("floor of exactly 1 KB: %d", got)
	}
	if r := fee_summary(nil, 8000); r.PoolTxs != 0 || r.NextBlockFeePerByte != 0 || r.BlocksToClear != 0 {
		t.Fatalf("empty: %+v", r)
	}
}
