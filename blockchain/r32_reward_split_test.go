package blockchain

// r32 (block-reward / DAG analysis): pins the DERO HE reward formulas by calling the chain's own functions with fixed
// inputs. Tests only: no non-test Go file is changed (consensus guard S1). Every expected number is derived from the
// code, cited at file:line (the same anchors as harness/gametheory/reward_anchors.json):
//
//   config/config.go:34                  BLOCK_TIME = 18
//   config/config.go:36                  MINIBLOCK_HIGHDIFF = 9
//   config/config.go:49                  FEE_PER_KB = 20
//   config/config.go:61                  PREMINE = 1228125400000
//   blockchain/transaction_execute.go:44 RewardReductionInterval = 210000 * 600 / 18 = 7,000,000
//   blockchain/transaction_execute.go:45 BaseReward = 41 * 100000 * 18 / 600 = 123,000
//   blockchain/transaction_execute.go:61 CalcBlockReward(h) = 123000 >> ((h + 7e6) / 7e6)
//   blockchain/transaction_execute.go:127-157 process_miner_transaction: full = base + fees; share = full / len(mbls);
//                                        leftover = full - share*len(mbls); integrator += share + leftover; every
//                                        non-final miniblock's key += share (the final one is skipped, :148)
//   blockchain/supply.go:5-26            CalcSupply = PREMINE + 271739600 + sum of epoch emissions
//   blockchain/tx_fees.go:35-45          Calculate_TX_fee = ceil(size / 1024) * FEE_PER_KB (hard-fork version unused)
//   blockchain/difficulty.go:113-122     DiffBig = prev * floor(e^((1 - solve/blocktime)/M) * 10000) / 10000
//
// The balances are in-memory graviton trees; each account's ElGamal balance is decrypted with the test's own secret
// key (Left - sk*Right == v*G), as blockchain/r31_value_sites_test.go does. No datadir, no network.

import (
	"math/big"
	"testing"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/graviton"
)

type r32Acct struct {
	sk  *big.Int
	pub *bn256.G1
	c   [33]byte
}

func r32NewAcct() r32Acct {
	sk := crypto.RandomScalar()
	pub := new(bn256.G1).ScalarMult(crypto.G, sk)
	var a r32Acct
	a.sk, a.pub = sk, pub
	copy(a.c[:], pub.EncodeCompressed())
	return a
}

func r32Tree(t *testing.T) *graviton.Tree {
	t.Helper()
	store, err := graviton.NewMemStore()
	if err != nil {
		t.Fatal(err)
	}
	ss, err := store.LoadSnapshot(0)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := ss.GetTree(config.BALANCE_TREE)
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

// registers a with a zero balance the way REGISTRATION does (transaction_execute.go:184)
func r32Register(t *testing.T, tree *graviton.Tree, a r32Acct) {
	t.Helper()
	nb := crypto.NonceBalance{NonceHeight: 0, Balance: crypto.ConstructElGamal(a.pub, crypto.ElGamal_BASE_G)}
	if err := tree.Put(a.c[:], nb.Serialize()); err != nil {
		t.Fatal(err)
	}
}

// the decrypted balance of a, searched in 0..max (rewards here are <= 61500 atomic per account)
func r32Balance(t *testing.T, tree *graviton.Tree, a r32Acct, max int64) int64 {
	t.Helper()
	raw, err := tree.Get(a.c[:])
	if err != nil {
		t.Fatalf("account not in tree: %s", err)
	}
	nb := new(crypto.NonceBalance).Deserialize(raw)
	got := string(new(bn256.G1).Add(nb.Balance.Left, new(bn256.G1).Neg(new(bn256.G1).ScalarMult(nb.Balance.Right, a.sk))).EncodeCompressed())
	acc := new(bn256.G1).ScalarMult(crypto.G, big.NewInt(0))
	for v := int64(0); v <= max; v++ {
		if string(acc.EncodeCompressed()) == got {
			return v
		}
		acc = new(bn256.G1).Add(acc, crypto.G)
	}
	t.Fatalf("balance not in 0..%d", max)
	return -1
}

// a block whose miniblocks are mined by owners[i] (nil = a final miniblock), integrated by integ
func r32Block(height uint64, integ r32Acct, owners []*r32Acct) *block.Block {
	bl := &block.Block{Height: height}
	bl.Miner_TX.TransactionType = transaction.COINBASE
	copy(bl.Miner_TX.MinerAddress[:], integ.c[:])
	for i, o := range owners {
		var mbl block.MiniBlock
		mbl.Version, mbl.Height, mbl.PastCount = 1, height, 1
		mbl.Nonce[0] = uint32(i + 1)
		if o == nil {
			mbl.Final, mbl.HighDiff = true, true
			mbl.KeyHash[0] = 0xee // a final carries the block header hash, not a key (miner_block.go:366-371)
		} else {
			kh := graviton.Sum(o.c[:]) // the tree's key hash: GetKeyValueFromHash(mbl.KeyHash[:16]) (transaction_execute.go:151)
			copy(mbl.KeyHash[:], kh[:])
		}
		bl.MiniBlocks = append(bl.MiniBlocks, mbl)
	}
	return bl
}

func TestR32_RewardConstants(t *testing.T) {
	if RewardReductionInterval != 7000000 { // 210000 * 600 / 18 (transaction_execute.go:44)
		t.Fatalf("RewardReductionInterval %d", RewardReductionInterval)
	}
	if BaseReward != 123000 { // 41 * 100000 * 18 / 600 (transaction_execute.go:45)
		t.Fatalf("BaseReward %d", BaseReward)
	}
	if n := config.BLOCK_TIME - config.MINIBLOCK_HIGHDIFF + 1; n != 10 { // miniblocks_consensus.go:80
		t.Fatalf("miniblocks per block %d", n)
	}
}

func TestR32_CalcBlockReward(t *testing.T) {
	// 123000 >> 1 = 61500 below 7e6; >> 2 = 30750 in [7e6, 14e6); >> 3 = 15375 from 14e6 (transaction_execute.go:61)
	for _, c := range []struct{ h, want uint64 }{
		{0, 61500}, {481600, 61500}, {6999999, 61500}, {7000000, 30750}, {7504640, 30750}, // HF2, HF3 change nothing
		{7905240, 30750}, {13999999, 30750}, {14000000, 15375}, {21000000, 7687},
	} {
		if got := CalcBlockReward(c.h); got != c.want {
			t.Errorf("CalcBlockReward(%d) = %d, want %d", c.h, got, c.want)
		}
	}
}

func TestR32_CalcSupply(t *testing.T) {
	// PREMINE + 271739600 + 61500*7e6 + 30750*(h - 7e6) (supply.go:6-19); h = 7,905,240 was the live top on
	// 2026-11-15 and GetInfo total_supply read 16867332 = this / 100000 (harness/runtime/gt_reward_live.json)
	h := uint64(7905240)
	want := config.PREMINE + 271739600 + 61500*7000000 + 30750*(h-7000000)
	if want != 1686733269600 {
		t.Fatalf("hand formula %d", want)
	}
	if got := CalcSupply(h); got != want {
		t.Fatalf("CalcSupply(%d) = %d, want %d", h, got, want)
	}
	if CalcSupply(h)/100000 != 16867332 {
		t.Fatalf("GetInfo whole-DERO value %d", CalcSupply(h)/100000)
	}
}

func r32Run(t *testing.T, height, fees uint64, integ r32Acct, owners []*r32Acct, accts []r32Acct) map[[33]byte]int64 {
	t.Helper()
	tree := r32Tree(t)
	r32Register(t, tree, integ)
	for _, a := range accts {
		if a.c != integ.c {
			r32Register(t, tree, a)
		}
	}
	chain := &Blockchain{}
	chain.process_miner_transaction(r32Block(height, integ, owners), false, tree, fees, height)
	out := map[[33]byte]int64{}
	out[integ.c] = r32Balance(t, tree, integ, 62000)
	for _, a := range accts {
		out[a.c] = r32Balance(t, tree, a, 62000)
	}
	return out
}

func TestR32_SplitNoFees(t *testing.T) {
	// 9 distinct normal miners + 1 final, fees 0, h = 7,905,240: full 30750, share 3075, leftover 0
	integ := r32NewAcct()
	var accts []r32Acct
	var owners []*r32Acct
	for i := 0; i < 9; i++ {
		accts = append(accts, r32NewAcct())
	}
	for i := range accts {
		owners = append(owners, &accts[i])
	}
	owners = append(owners, nil)
	got := r32Run(t, 7905240, 0, integ, owners, accts)
	if got[integ.c] != 3075 {
		t.Errorf("integrator %d, want 3075", got[integ.c])
	}
	sum := got[integ.c]
	for _, a := range accts {
		if got[a.c] != 3075 {
			t.Errorf("normal miner %d, want 3075", got[a.c])
		}
		sum += got[a.c]
	}
	if sum != 30750 {
		t.Errorf("credited %d, want the full reward 30750", sum)
	}
}

func TestR32_SplitFeesLeftoverToIntegrator(t *testing.T) {
	// fees 37: full 30787, share 3078, leftover 7 -> integrator 3085 (transaction_execute.go:133-142)
	integ := r32NewAcct()
	m := r32NewAcct()
	owners := []*r32Acct{}
	for i := 0; i < 9; i++ {
		owners = append(owners, &m) // one key mined all 9 normal miniblocks: 9 shares (:146-157 credits per miniblock)
	}
	owners = append(owners, nil)
	got := r32Run(t, 7905240, 37, integ, owners, []r32Acct{m})
	if got[integ.c] != 3085 || got[m.c] != 9*3078 {
		t.Errorf("integrator %d (want 3085), miner %d (want %d)", got[integ.c], got[m.c], 9*3078)
	}
	if got[integ.c]+got[m.c] != 30787 {
		t.Errorf("credited %d, want 30787", got[integ.c]+got[m.c])
	}
}

func TestR32_IntegratorAlsoMines(t *testing.T) {
	// the integrator's own key mines 3 normal miniblocks: 3 shares + its integrator share (fees 120 -> share 3087)
	integ := r32NewAcct()
	other := r32NewAcct()
	owners := []*r32Acct{&integ, &integ, &integ}
	for i := 0; i < 6; i++ {
		owners = append(owners, &other)
	}
	owners = append(owners, nil)
	got := r32Run(t, 7905240, 120, integ, owners, []r32Acct{other})
	if got[integ.c] != 4*3087 || got[other.c] != 6*3087 {
		t.Errorf("integrator %d (want %d), other %d (want %d)", got[integ.c], 4*3087, got[other.c], 6*3087)
	}
}

func TestR32_SplitPreHF2Era(t *testing.T) {
	// h = 100,000 (era 1, 61500): share 6150; two finals (only possible below 399,000, miniblocks_consensus.go:120)
	// leave one share un-credited: credited = full - share (the r25 B22 window), pinned as code behaviour
	integ := r32NewAcct()
	m := r32NewAcct()
	owners := []*r32Acct{}
	for i := 0; i < 8; i++ {
		owners = append(owners, &m)
	}
	owners = append(owners, nil, nil)
	got := r32Run(t, 100000, 0, integ, owners, []r32Acct{m})
	if got[integ.c] != 6150 || got[m.c] != 8*6150 || got[integ.c]+got[m.c] != 61500-6150 {
		t.Errorf("integrator %d, miner %d", got[integ.c], got[m.c])
	}
}

func TestR32_FeeFloor(t *testing.T) {
	// ceil(size/1024) * 20, the hard-fork version argument is unused (tx_fees.go:35-45)
	chain := &Blockchain{}
	for _, c := range []struct{ size, want uint64 }{{1, 20}, {1024, 20}, {1025, 40}, {2048, 40}, {2049, 60}, {10 * 1024, 200}} {
		for _, hf := range []int64{1, 2, 3} {
			if got := chain.Calculate_TX_fee(hf, c.size); got != c.want {
				t.Errorf("Calculate_TX_fee(%d, %d) = %d, want %d", hf, c.size, got, c.want)
			}
		}
	}
}

func TestR32_DifficultyLiveTriple(t *testing.T) {
	// live mainnet headers (2026-11-15, harness/runtime/gt_reward_live.json): heights 7905189..7905192
	// ts 1794732743901, 1794732755726, 1794732763475; difficulty 2074825 (7905190) -> 2165702 (7905191) -> 2325314
	// (7905192). Get_Difficulty_At_Tips uses solve = ts(tip) - ts(parent), clamp 2*18000, M = 8 (difficulty.go:244-252)
	bt := int64(config.BLOCK_TIME_MILLISECS)
	if got := DiffBig(1794732755726-1794732743901, bt, 8, big.NewInt(2074825)); got.Int64() != 2165702 {
		t.Errorf("DiffBig -> %s, want 2165702", got)
	}
	if got := DiffBig(1794732763475-1794732755726, bt, 8, big.NewInt(2165702)); got.Int64() != 2325314 {
		t.Errorf("DiffBig -> %s, want 2325314", got)
	}
	if got := DiffBig(bt, bt, 8, big.NewInt(2000000)); got.Int64() != 2000000 { // on target: e^0 = 1
		t.Errorf("on-target DiffBig -> %s", got)
	}
}
