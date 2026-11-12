package blockchain_test

// Round 28 (dvm-blockchain, B146): the chain's own SC execution path, end to end, on a simulator chain.
//
// Before r28 process_transaction_sc (blockchain/transaction_execute.go) was 0.0 % covered in every test package: no
// test ever mined an SC_TX. This test starts a throw-away simulator chain in t.TempDir() (never a real datadir),
// registers two accounts, and mines real, fully verified SC transactions built by the wallet's own builder
// (walletapi BuildTransaction, ring size 2, so the signer is extractable through the chain's ring expansion). Each
// step reads the committed state back from the chain's store and compares it with a known answer:
//
//   install  -> code + meta stored, Initialize ran with SIGNER() = the sender, the burn deposit credited to the SC
//   call     -> an entrypoint changes stored state; the sender's balance drops by the fee only (burn 0)
//   withdraw -> SEND_DERO_TO_ADDRESS debits the SC (SanityCheckExternalTransfers) and credits the signer
//   revert   -> an entrypoint that returns 1 changes nothing and the burnt value is refunded (ErrorRevert)
//   unknown  -> a call to an SCID that is not installed changes nothing and keeps the fee
//
// Consensus code is not changed; this is a test (package blockchain_test, so it can use walletapi without an import
// cycle). The process globals it needs (globals.Arguments / Config, config.Testnet) are restored afterwards.

import (
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/dvm"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/derohe/walletapi"
	"github.com/deroproject/graviton"
)

const r28_sc = `
Function Initialize() Uint64
10 STORE("owner", SIGNER())
20 STORE("counter", 5)
30 STORE("init_value", DEROVALUE())
40 RETURN 0
End Function

Function Bump(n Uint64) Uint64
10 STORE("counter", LOAD("counter") + n)
20 RETURN 0
End Function

Function Withdraw(amount Uint64) Uint64
10 SEND_DERO_TO_ADDRESS(SIGNER(), amount)
20 STORE("withdrawn", amount)
30 RETURN 0
End Function

Function Fail() Uint64
10 STORE("counter", 999)
20 RETURN 1
End Function

Function Brick(code String) Uint64
10 UPDATE_SC_CODE(code)
20 RETURN 0
End Function
`

const r28_fee = uint64(5000)               // explicit fee = storage gas limit (walletapi passes gasstorage as fees)
const r28_registration_grant = 100_000_000 // simulator grant per registration (process_transaction REGISTRATION)

type r28_env struct {
	t       *testing.T
	chain   *blockchain.Blockchain
	miner   rpc.Address
	sc_txs  int // SC txs mined
	stopped bool
}

func r28_start(t *testing.T) *r28_env { return r28_start_at(t, t.TempDir()) }

// starts (or re-opens) a simulator chain whose datadir parent is dir
func r28_start_at(t *testing.T, dir string) *r28_env {
	old_args, old_cfg := globals.Arguments, globals.Config
	globals.InitializeLog(io.Discard, io.Discard)
	globals.Arguments = map[string]interface{}{"--data-dir": dir, "--testnet": true, "--simulator": true}
	globals.Initialize()

	chain, err := blockchain.Blockchain_Start(map[string]interface{}{"--simulator": true})
	if err != nil {
		globals.Arguments, globals.Config = old_args, old_cfg
		t.Fatalf("simulator chain start: %s", err)
	}
	e := &r28_env{t: t, chain: chain}
	t.Cleanup(func() {
		e.shutdown() // Shutdown keeps the chain lock: a second call would deadlock, so it runs once
		globals.Arguments, globals.Config = old_args, old_cfg
	})

	// the genesis miner key is registered by the genesis block, so blocks can be mined to it from height 1
	gbl := blockchain.Generate_Genesis_Block()
	var p crypto.Point
	if err := p.DecodeCompressed(gbl.Miner_TX.MinerAddress[:]); err != nil {
		t.Fatal(err)
	}
	e.miner = *rpc.NewAddressFromKeys(&p)
	return e
}

func (e *r28_env) shutdown() {
	if !e.stopped {
		e.stopped = true
		e.chain.Shutdown()
	}
}

func (e *r28_env) mine() {
	e.t.Helper()
	cbl, _, err := e.chain.Create_new_miner_block(e.miner)
	if err != nil {
		e.t.Fatalf("create block: %s", err)
	}
	mbl := blockchain.ConvertBlockToMiniblock(*cbl.Bl, e.miner)
	cbl.Bl.MiniBlocks = append(cbl.Bl.MiniBlocks, mbl)
	if err, _ = e.chain.Add_Complete_Block(cbl); err != nil {
		e.t.Fatalf("add block: %s", err)
	}
}

// the committed state at the tip: snapshot, balance tree, SC meta tree, the block it belongs to
type r28_tip struct {
	ss       *graviton.Snapshot
	balance  *graviton.Tree
	meta     *graviton.Tree
	blid     crypto.Hash
	height   uint64
	roothash crypto.Hash
}

func (e *r28_env) tip() r28_tip {
	e.t.Helper()
	topo := e.chain.Load_TOPO_HEIGHT()
	rec, err := e.chain.Store.Topo_store.Read(topo)
	if err != nil {
		e.t.Fatal(err)
	}
	ss, err := e.chain.Store.Balance_store.LoadSnapshot(rec.State_Version)
	if err != nil {
		e.t.Fatal(err)
	}
	bt, err := ss.GetTree(config.BALANCE_TREE)
	if err != nil {
		e.t.Fatal(err)
	}
	mt, err := ss.GetTree(config.SC_META)
	if err != nil {
		e.t.Fatal(err)
	}
	version, err := e.chain.ReadBlockSnapshotVersion(rec.BLOCK_ID)
	if err != nil {
		e.t.Fatal(err)
	}
	root, err := e.chain.Load_Merkle_Hash(version)
	if err != nil {
		e.t.Fatal(err)
	}
	return r28_tip{ss: ss, balance: bt, meta: mt, blid: crypto.Hash(rec.BLOCK_ID), height: uint64(rec.Height), roothash: root}
}

// the DERO balance of w at the tip, decrypted with w's key and checked against `want` (no lookup table needed)
func (e *r28_env) balance_is(w *walletapi.Wallet_Memory, want uint64) bool {
	e.t.Helper()
	tip := e.tip()
	raw, err := tip.balance.Get(w.GetAddress().PublicKey.EncodeCompressed())
	if err != nil {
		e.t.Fatalf("balance of %s: %s", w.GetAddress(), err)
	}
	nb := new(crypto.NonceBalance).Deserialize(raw)
	var point bn256.G1
	point.Add(nb.Balance.Left, new(bn256.G1).Neg(new(bn256.G1).ScalarMult(nb.Balance.Right, w.Get_Keys().Secret.BigInt())))
	expect := new(bn256.G1).ScalarMult(crypto.G, new(big.Int).SetUint64(want))
	return point.String() == expect.String()
}

// builds, pools and mines one SC tx from ring[0] to ring[1]; ring[2:] are decoys. Ring size 2 makes the signer
// extractable (blockchain Extract_signer); any larger ring makes the tx anonymous (signer = 33 zero bytes).
func (e *r28_env) sc_tx(ring_w []*walletapi.Wallet_Memory, burn uint64, scdata rpc.Arguments) *transaction.Transaction {
	e.t.Helper()
	dtx := e.build_tx(ring_w, burn, scdata)
	if dtx.TransactionType != transaction.SC_TX {
		e.t.Fatalf("tx type %s, want SC", dtx.TransactionType)
	}
	if err := e.chain.Add_TX_To_Pool(dtx); err != nil {
		e.t.Fatalf("SC tx refused by the pool: %s", err)
	}
	before := e.chain.Load_TOPO_HEIGHT()
	e.mine()
	if e.chain.Load_TOPO_HEIGHT() != before+1 {
		e.t.Fatal("the block carrying the SC tx did not extend the chain")
	}
	bl, err := e.chain.Load_BL_FROM_ID(e.tip().blid)
	if err != nil || len(bl.Tx_hashes) != 1 || bl.Tx_hashes[0] != dtx.GetHash() {
		e.t.Fatalf("the tip block does not carry exactly this SC tx (err %v)", err)
	}
	e.sc_txs++
	return dtx
}

// builds one tx (wallet builder, real proof) at the tip and returns its wire form, as a peer would deliver it
func (e *r28_env) build_tx(ring_w []*walletapi.Wallet_Memory, burn uint64, scdata rpc.Arguments) *transaction.Transaction {
	e.t.Helper()
	tip := e.tip()
	var emap [][]byte
	var ring []*bn256.G1
	max_bits := 0
	for _, w := range ring_w {
		bits, _, raw, err := tip.balance.GetKeyValueFromKey(w.GetAddress().PublicKey.EncodeCompressed())
		if err != nil {
			e.t.Fatalf("ring member %s unregistered: %s", w.GetAddress(), err)
		}
		if bits > max_bits {
			max_bits = bits
		}
		emap = append(emap, new(crypto.NonceBalance).Deserialize(raw).Balance.Serialize())
		ring = append(ring, w.GetAddress().PublicKey.G1())
	}
	transfers := []rpc.Transfer{{Destination: ring_w[1].GetAddress().String(), Amount: 0, Burn: burn}}
	// r30 (closed-loop run 5 race FAIL): an SC install txid must start and end with a byte >= 0x80, so the wallet
	// builder rebuilds (1/4 per try) and raises max_bits by 3 every len(ring) tries; with a deep balance tree it can pass
	// 240 bits and panic (upstream walletapi/transaction_build.go:60). A fresh build starts the count again.
	tx := r30_build_retry(5, func() *transaction.Transaction {
		return ring_w[0].BuildTransaction(transfers, [][][]byte{emap}, [][]*bn256.G1{ring}, tip.blid, tip.height, scdata, tip.roothash[:], max_bits+6, r28_fee)
	})
	if tx == nil {
		e.t.Fatal("BuildTransaction returned nil")
	}
	var dtx transaction.Transaction // the pool gets the wire form, as from a peer
	if err := dtx.Deserialize(tx.Serialize()); err != nil {
		e.t.Fatal(err)
	}
	if dtx.Payloads[0].Statement.RingSize != uint64(len(ring_w)) {
		e.t.Fatalf("ring %d, want %d", dtx.Payloads[0].Statement.RingSize, len(ring_w))
	}
	return &dtx
}

// the committed SC data tree at the tip, wrapped for the dvm readers
func (e *r28_env) sc_data(scid crypto.Hash) (*dvm.Tree_Wrapper, bool) {
	tip := e.tip()
	if _, err := tip.meta.Get(dvm.SC_Meta_Key(scid)); err != nil {
		return nil, false
	}
	tree, err := tip.ss.GetTree(string(scid[:]))
	if err != nil {
		e.t.Fatal(err)
	}
	return &dvm.Tree_Wrapper{Tree: tree, Entries: map[string][]byte{}}, true
}

func r28_wallet(t *testing.T) *walletapi.Wallet_Memory {
	w, err := walletapi.Create_Encrypted_Wallet_Random_Memory("")
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func r28_sc_value(t *testing.T, d *dvm.Tree_Wrapper, scid crypto.Hash, key string) interface{} {
	t.Helper()
	return dvm.ReadSCValue(d, scid, key)
}

func r28_args(kv ...interface{}) rpc.Arguments {
	var a rpc.Arguments
	for i := 0; i+1 < len(kv); i += 2 {
		name := kv[i].(string)
		switch v := kv[i+1].(type) {
		case uint64:
			a = append(a, rpc.Argument{Name: name, DataType: rpc.DataUint64, Value: v})
		case string:
			a = append(a, rpc.Argument{Name: name, DataType: rpc.DataString, Value: v})
		case crypto.Hash:
			a = append(a, rpc.Argument{Name: name, DataType: rpc.DataHash, Value: v})
		default:
			panic("r28_args: unsupported type")
		}
	}
	return a
}

func r28_install(code string) rpc.Arguments {
	return r28_args(rpc.SCACTION, uint64(rpc.SC_INSTALL), rpc.SCCODE, code)
}

func r28_call(scid crypto.Hash, entry string, kv ...interface{}) rpc.Arguments {
	return append(r28_args(rpc.SCACTION, uint64(rpc.SC_CALL), rpc.SCID, scid, "entrypoint", entry), r28_args(kv...)...)
}

const r28_private_sc = `
Function InitializePrivate() Uint64
10 STORE("private_init", 1)
20 RETURN 0
End Function
`

const r28_init_fails_sc = `
Function Initialize() Uint64
10 STORE("x", 1)
20 RETURN 1
End Function
`

// The chain's SC execution (process_transaction_sc), every reachable branch, with the value conservation of each:
// where the burnt value of the tx ends (the SC, a refund to the signer, or destroyed) and that the fee is always
// kept. The destroyed cases are consensus behaviour (B33 / B145 family), pinned as they are, never changed.
func TestR28SimulatorChainSCInstallCallKAT(t *testing.T) {
	e := r28_start(t)
	alice, bob, carol, dave := r28_wallet(t), r28_wallet(t), r28_wallet(t), r28_wallet(t)
	for _, w := range []*walletapi.Wallet_Memory{alice, bob, carol, dave} {
		if err := e.chain.Add_TX_To_Pool(w.GetRegistrationTX()); err != nil {
			t.Fatalf("registration refused: %s", err)
		}
	}
	e.mine()
	e.mine()
	pair := []*walletapi.Wallet_Memory{alice, bob}
	alice_bal := uint64(r28_registration_grant)
	for _, w := range []*walletapi.Wallet_Memory{alice, bob, carol, dave} {
		if !e.balance_is(w, r28_registration_grant) {
			t.Fatal("premise: a registered simulator account holds the registration grant")
		}
	}
	expect_alice := func(step string) {
		t.Helper()
		if !e.balance_is(alice, alice_bal) {
			t.Fatalf("%s: sender balance is not the expected %d", step, alice_bal)
		}
	}
	not_installed := func(step string, scid crypto.Hash) {
		t.Helper()
		if _, ok := e.sc_data(scid); ok {
			t.Fatalf("%s: SC %s is in the meta tree", step, scid)
		}
	}

	// 1. install with a 30,000 burn deposit: code, meta, Initialize with SIGNER(), deposit credited to the SC
	const deposit = 30_000
	scid := e.sc_tx(pair, deposit, r28_install(r28_sc)).GetHash()
	alice_bal -= r28_fee + deposit
	d, ok := e.sc_data(scid)
	if !ok {
		t.Fatalf("install: SC %s not in the meta tree", scid)
	}
	meta_raw, _ := e.tip().meta.Get(dvm.SC_Meta_Key(scid))
	if bal, sc, found := dvm.ReadSC(&dvm.Tree_Wrapper{Tree: e.tip().meta, Entries: map[string][]byte{}}, d, scid); !found || bal != deposit || len(sc.Functions) != 5 || meta_raw[0] != 0 {
		t.Fatalf("install: ReadSC found %v balance %d functions %d type %d, want true %d 5 0", found, bal, len(sc.Functions), meta_raw[0], deposit)
	}
	if got := r28_sc_value(t, d, scid, "owner"); got != string(alice.GetAddress().PublicKey.EncodeCompressed()) {
		t.Fatalf("install: owner = %x, want the sender's key (signer extracted from the ring-2 statement)", got)
	}
	if got := r28_sc_value(t, d, scid, "counter"); got != uint64(5) {
		t.Fatalf("install: counter = %v, want 5 (Initialize ran)", got)
	}
	if got := r28_sc_value(t, d, scid, "init_value"); got != uint64(deposit) {
		t.Fatalf("install: DEROVALUE() = %v, want %d (burn of the base payload)", got, deposit)
	}
	expect_alice("install")

	sc_balance := func(step string, want uint64) {
		t.Helper()
		d, _ := e.sc_data(scid)
		if bal, _ := dvm.LoadSCAssetValue(d, scid, crypto.Hash{}); bal != want {
			t.Fatalf("%s: SC balance %d, want %d", step, bal, want)
		}
	}
	counter := func(step string, want uint64) {
		t.Helper()
		d, _ := e.sc_data(scid)
		if got := r28_sc_value(t, d, scid, "counter"); got != want {
			t.Fatalf("%s: counter = %v, want %d", step, got, want)
		}
	}

	// 2. call Bump(7): state changes, the sender pays the fee only
	e.sc_tx(pair, 0, r28_call(scid, "Bump", "n", uint64(7)))
	alice_bal -= r28_fee
	counter("call", 12)
	expect_alice("call")

	// 3. Withdraw(10,000): the SC is debited (SanityCheckExternalTransfers), the signer credited (ProcessExternal)
	e.sc_tx(pair, 0, r28_call(scid, "Withdraw", "amount", uint64(10_000)))
	alice_bal = alice_bal - r28_fee + 10_000
	sc_balance("withdraw", deposit-10_000)
	d, _ = e.sc_data(scid)
	if got := r28_sc_value(t, d, scid, "withdrawn"); got != uint64(10_000) {
		t.Fatalf("withdraw: withdrawn = %v", got)
	}
	expect_alice("withdraw")

	// 4. Withdraw more than the SC holds with a 2,000 burn: underflow refused, nothing moves, the burn is refunded, fee kept
	e.sc_tx(pair, 2_000, r28_call(scid, "Withdraw", "amount", uint64(deposit)))
	alice_bal -= r28_fee
	sc_balance("overdraw", deposit-10_000)
	expect_alice("overdraw")

	// 5. Fail() with a 4,000 burn: the STORE is discarded, the burn is refunded (ErrorRevert), the fee is kept
	e.sc_tx(pair, 4_000, r28_call(scid, "Fail"))
	alice_bal -= r28_fee
	counter("revert", 12)
	sc_balance("revert", deposit-10_000)
	expect_alice("revert")

	// 6. call without an SCID / without an entrypoint: error before the SC runs, burn refunded
	e.sc_tx(pair, 1_000, r28_args(rpc.SCACTION, uint64(rpc.SC_CALL), "entrypoint", "Bump"))
	alice_bal -= r28_fee
	expect_alice("call without scid")
	e.sc_tx(pair, 1_000, r28_args(rpc.SCACTION, uint64(rpc.SC_CALL), rpc.SCID, scid))
	alice_bal -= r28_fee
	expect_alice("call without entrypoint")
	counter("call without entrypoint", 12)

	// 7. install with empty code / unparseable code: refused, burn refunded, nothing installed
	empty := e.sc_tx(pair, 2_000, r28_install("")).GetHash()
	alice_bal -= r28_fee
	expect_alice("install empty code")
	not_installed("install empty code", empty)
	bad := e.sc_tx(pair, 2_000, r28_install("Function Initialize( Uint64\n10 RETURN 0\n")).GetHash()
	alice_bal -= r28_fee
	expect_alice("install unparseable code")
	not_installed("install unparseable code", bad)

	// 8. private SC: meta type 1, InitializePrivate is the entrypoint
	priv := e.sc_tx(pair, 0, r28_install(r28_private_sc)).GetHash()
	alice_bal -= r28_fee
	pd, ok := e.sc_data(priv)
	if !ok {
		t.Fatal("private install: not in the meta tree")
	}
	if praw, _ := e.tip().meta.Get(dvm.SC_Meta_Key(priv)); praw[0] != 1 {
		t.Fatalf("private install: meta type %d, want 1", praw[0])
	}
	if got := r28_sc_value(t, pd, priv, "private_init"); got != uint64(1) {
		t.Fatalf("private install: InitializePrivate did not run (%v)", got)
	}
	expect_alice("private install")

	// ---- the destroyed-burn paths (consensus behaviour, pinned as is) ----

	// 9. an install whose Initialize returns 1: returns before the revert block, so the burn is NOT refunded
	failed := e.sc_tx(pair, 3_000, r28_install(r28_init_fails_sc)).GetHash()
	alice_bal -= r28_fee + 3_000
	expect_alice("install whose Initialize fails (burn destroyed)")
	not_installed("install whose Initialize fails", failed)

	// 10. a call to an SCID that is not installed: returns early, the burn is destroyed
	e.sc_tx(pair, 3_000, r28_call(crypto.HashHexToHash("00000000000000000000000000000000000000000000000000000000000000aa"), "Bump", "n", uint64(1)))
	alice_bal -= r28_fee + 3_000
	expect_alice("call to an unknown scid (burn destroyed)")

	// 11. an unknown SC action: returns early, the burn is destroyed
	e.sc_tx(pair, 3_000, r28_args(rpc.SCACTION, uint64(77)))
	alice_bal -= r28_fee + 3_000
	expect_alice("unknown action (burn destroyed)")

	// 12. SCDATA without an SC action: not an SC operation at all, the burn is destroyed
	e.sc_tx(pair, 3_000, r28_args("note", uint64(1)))
	alice_bal -= r28_fee + 3_000
	expect_alice("no SC action (burn destroyed)")

	// 13. install without an SCCODE argument: breaks out with no data tree, the sanity check panics on it and the
	// recover keeps fee and err=nil; the burn is destroyed
	nocode := e.sc_tx(pair, 3_000, r28_args(rpc.SCACTION, uint64(rpc.SC_INSTALL))).GetHash()
	alice_bal -= r28_fee + 3_000
	expect_alice("install without SCCODE (burn destroyed)")
	not_installed("install without SCCODE", nocode)

	// 14. anonymous (ring 4): Bump still runs with signer = zero bytes; a failing anonymous call cannot be refunded
	// (ErrorRevert panics on the zero signer; sc_revert_log.go), so its burn is destroyed and the fee kept
	ring4 := []*walletapi.Wallet_Memory{alice, bob, carol, dave}
	e.sc_tx(ring4, 0, r28_call(scid, "Bump", "n", uint64(100)))
	alice_bal -= r28_fee
	counter("anonymous call", 112)
	expect_alice("anonymous call")
	e.sc_tx(ring4, 2_500, r28_call(scid, "Fail"))
	alice_bal -= r28_fee + 2_500
	counter("anonymous revert", 112)
	sc_balance("anonymous revert", deposit-10_000)
	expect_alice("anonymous revert (burn destroyed)")

	// 15. UPDATE_SC_CODE with unparseable source (B145) at chain level: the call succeeds, the stored code no longer
	// parses, so every later call takes the 'SC not found' branch (refund) and the SC is bricked; data stays
	e.sc_tx(pair, 0, r28_call(scid, "Brick", "code", "Function Broken( Uint64"))
	alice_bal -= r28_fee
	expect_alice("brick")
	e.sc_tx(pair, 1_500, r28_call(scid, "Bump", "n", uint64(1)))
	alice_bal -= r28_fee
	counter("call into a bricked SC", 112)
	sc_balance("call into a bricked SC", deposit-10_000)
	expect_alice("call into a bricked SC (burn refunded)")
	d, _ = e.sc_data(scid)
	if _, _, found := dvm.ReadSC(&dvm.Tree_Wrapper{Tree: e.tip().meta, Entries: map[string][]byte{}}, d, scid); found {
		t.Fatal("brick: the stored code still parses")
	}

	for _, w := range []*walletapi.Wallet_Memory{bob, carol, dave} {
		if !e.balance_is(w, r28_registration_grant) {
			t.Fatal("a ring partner's balance changed (it only ever received 0)")
		}
	}
	t.Logf("r28 sc flow: %d SC txs mined, final sender balance %d, SC balance %d", e.sc_txs, alice_bal, deposit-10_000)
}

// the merkle root (balance tree XOR SC meta tree, Load_Merkle_Hash) of every topoheight in [from, to]
func (e *r28_env) roots(from, to int64) map[int64]crypto.Hash {
	e.t.Helper()
	out := map[int64]crypto.Hash{}
	for topo := from; topo <= to; topo++ {
		rec, err := e.chain.Store.Topo_store.Read(topo)
		if err != nil {
			e.t.Fatalf("topo %d: %s", topo, err)
		}
		h, err := e.chain.Load_Merkle_Hash(rec.State_Version)
		if err != nil {
			e.t.Fatalf("topo %d root: %s", topo, err)
		}
		out[topo] = h
	}
	return out
}

// Prune_Blockchain (blockchain/prune_history.go, 0/245 statements covered before r28) on a throw-away simulator
// datadir: the state root of every topoheight from the prune point to the tip must be identical after the rewrite,
// every topoheight below it must map to the prune point's state, the blocks below prune-20 are gone, the SC state
// (installed below the prune point, changed above it) reads back the same, and the pruned chain keeps working:
// a new SC call executes on it. The live node is never pruned by this (its datadir is not involved).
func TestR28PruneHistoryPreservesStateKAT(t *testing.T) {
	dir := t.TempDir()
	e := r28_start_at(t, dir)
	alice, bob := r28_wallet(t), r28_wallet(t)
	for _, w := range []*walletapi.Wallet_Memory{alice, bob} {
		if err := e.chain.Add_TX_To_Pool(w.GetRegistrationTX()); err != nil {
			t.Fatal(err)
		}
	}
	e.mine()
	e.mine()
	pair := []*walletapi.Wallet_Memory{alice, bob}
	scid := e.sc_tx(pair, 9_000, r28_install(r28_sc)).GetHash() // below the prune point: cloned by clone_snapshot
	const prune_topo = 30                                       // > 20: the blocks below prune_topo-20 are discarded
	for e.chain.Load_TOPO_HEIGHT() < prune_topo+5 {
		e.mine()
	}
	e.sc_tx(pair, 0, r28_call(scid, "Bump", "n", uint64(3)))          // above it: replayed by diff_snapshot (modified SC)
	second := e.sc_tx(pair, 0, r28_install(r28_private_sc)).GetHash() // above it: a NEW SC in the diff
	for e.chain.Load_TOPO_HEIGHT() < prune_topo+52 {
		e.mine()
	}
	e.sc_tx(pair, 0, r28_call(scid, "Withdraw", "amount", uint64(4_000)))
	top := e.chain.Load_TOPO_HEIGHT()
	before := e.roots(0, top)
	alice_bal := uint64(r28_registration_grant) - 4*r28_fee - 9_000 + 4_000
	if !e.balance_is(alice, alice_bal) {
		t.Fatal("premise: sender balance before the prune")
	}
	low, err := e.chain.Store.Topo_store.Read(1)
	if err != nil || !e.chain.Block_Exists(crypto.Hash(low.BLOCK_ID)) {
		t.Fatal("premise: topo 1's block is stored before the prune")
	}
	e.shutdown()

	if err := blockchain.Prune_Blockchain(prune_topo); err != nil {
		t.Fatalf("Prune_Blockchain: %s", err)
	}

	p := r28_start_at(t, dir)
	p.t = t
	if p.chain.Load_TOPO_HEIGHT() != top {
		t.Fatalf("pruned chain top %d, want %d", p.chain.Load_TOPO_HEIGHT(), top)
	}
	after := p.roots(0, top)
	for topo := int64(0); topo <= top; topo++ {
		want := before[topo]
		if topo < prune_topo {
			want = before[prune_topo] // below the prune point every record maps to the prune point's state
		}
		if after[topo] != want {
			t.Fatalf("topo %d: state root %x after the prune, want %x", topo, after[topo], want)
		}
	}
	if p.chain.Block_Exists(crypto.Hash(low.BLOCK_ID)) {
		t.Fatal("topo 1's block survived the prune (blocks below prune-20 are discarded)")
	}
	d, ok := p.sc_data(scid)
	if !ok {
		t.Fatal("pruned chain: SC lost from the meta tree")
	}
	if got := dvm.ReadSCValue(d, scid, "counter"); got != uint64(8) {
		t.Fatalf("pruned chain: counter %v, want 8", got)
	}
	if bal, _ := dvm.LoadSCAssetValue(d, scid, crypto.Hash{}); bal != 5_000 {
		t.Fatalf("pruned chain: SC balance %d, want 5000", bal)
	}
	if pd, ok := p.sc_data(second); !ok || dvm.ReadSCValue(pd, second, "private_init") != uint64(1) {
		t.Fatal("pruned chain: the SC installed above the prune point is missing")
	}
	if !p.balance_is(alice, alice_bal) {
		t.Fatal("pruned chain: sender balance changed")
	}
	// the pruned chain keeps working
	p.sc_tx(pair, 0, r28_call(scid, "Bump", "n", uint64(10)))
	d, _ = p.sc_data(scid)
	if got := dvm.ReadSCValue(d, scid, "counter"); got != uint64(18) {
		t.Fatalf("pruned chain: a new call did not execute (counter %v, want 18)", got)
	}
	if err := blockchain.Prune_Blockchain(top - 10); err == nil {
		t.Fatal("Prune_Blockchain accepted a prune point fewer than 50 blocks below the top")
	}
}

// B33: a BURN_TX can never be accepted. transaction.Serialize writes Value only for PREMINE and SC_TX
// (transaction/transaction.go), so a BURN_TX's Value is 0 after the wire, and the verifier refuses a zero burn
// value first ("Burn Value cannot be zero", blockchain/transaction_verify.go). Consensus behaviour, pinned as is.
// A NORMAL tx of the same build is accepted (the control).
func TestR28BurnTxNeverVerifiesKAT(t *testing.T) {
	e := r28_start(t)
	alice, bob := r28_wallet(t), r28_wallet(t)
	for _, w := range []*walletapi.Wallet_Memory{alice, bob} {
		if err := e.chain.Add_TX_To_Pool(w.GetRegistrationTX()); err != nil {
			t.Fatal(err)
		}
	}
	e.mine()
	e.mine()
	pair := []*walletapi.Wallet_Memory{alice, bob}

	burn := e.build_tx(pair, 0, nil)
	if burn.TransactionType != transaction.NORMAL {
		t.Fatalf("premise: a build without SC data is NORMAL, got %s", burn.TransactionType)
	}
	burn.TransactionType, burn.Value = transaction.BURN_TX, 12_345
	var wire transaction.Transaction
	if err := wire.Deserialize(burn.Serialize()); err != nil {
		t.Fatal(err)
	}
	if wire.TransactionType != transaction.BURN_TX || wire.Value != 0 {
		t.Fatalf("BURN_TX after the wire: type %s value %d, want BURN_TX 0 (Value not serialised)", wire.TransactionType, wire.Value)
	}
	if err := e.chain.Add_TX_To_Pool(&wire); err == nil || !strings.Contains(err.Error(), "Burn Value cannot be zero") {
		t.Fatalf("BURN_TX: pool said %v, want 'Burn Value cannot be zero'", err)
	}
	if err := e.chain.Add_TX_To_Pool(burn); err == nil { // the in-memory form (Value 12,345) fails as well: its hash
		t.Fatal("the in-memory BURN_TX (Value set) was accepted") // is not the hash the proof was built for
	}

	control := e.build_tx(pair, 0, nil)
	if err := e.chain.Add_TX_To_Pool(control); err != nil {
		t.Fatalf("control NORMAL tx refused: %s", err)
	}
	e.mine()
	if !e.balance_is(alice, r28_registration_grant-control.Fees()) {
		t.Fatal("control: the NORMAL tx did not execute")
	}
}

// r30: calls build up to n times while it panics with the wallet builder's 240-bit limit (a retry-count artefact of the
// SC-install txid rule, not a property of the tx); any other panic, and the last attempt's, propagates.
func r30_build_retry(n int, build func() *transaction.Transaction) (tx *transaction.Transaction) {
	for i := 1; ; i++ {
		done := func() (ok bool) {
			defer func() {
				if r := recover(); r != nil {
					if i >= n || fmt.Sprint(r) != "currently we cannot use more than 240 bits" {
						panic(r)
					}
					ok = false
				}
			}()
			tx = build()
			return true
		}()
		if done {
			return tx
		}
	}
}

func TestR30BuildRetry240Bits(t *testing.T) {
	calls := 0
	want := &transaction.Transaction{}
	got := r30_build_retry(5, func() *transaction.Transaction {
		calls++
		if calls < 3 {
			panic("currently we cannot use more than 240 bits")
		}
		return want
	})
	if got != want || calls != 3 {
		t.Fatalf("retry: got %p calls %d, want the third build", got, calls)
	}
	for _, c := range []struct {
		msg  string
		n, k int
	}{{"some other failure", 5, 1}, {"currently we cannot use more than 240 bits", 2, 2}} {
		calls = 0
		func() {
			defer func() {
				if r := recover(); r == nil || fmt.Sprint(r) != c.msg || calls != c.k {
					t.Fatalf("%q: recovered %v after %d calls, want a re-panic after %d", c.msg, r, calls, c.k)
				}
			}()
			r30_build_retry(c.n, func() *transaction.Transaction { calls++; panic(c.msg) })
		}()
	}
}
