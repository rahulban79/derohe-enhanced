package blockchain

// R31 dimension 6 (rft §7 B284 observation): the 9 value sites of blockchain/transaction_execute.go that the emission
// auditor checks but no test named (detector value-paths census, harness/runtime/detector_value-paths.json). Each test
// below calls the chain's own execution function on in-memory graviton trees (never a datadir, never the network) and
// reads the moved value back by decrypting the stored ElGamal balance with the test's own secret key.
//
//   process_transaction     REGISTRATION grant (simulator/testnet 100000000, mainnet below 144000 +200), the
//                           homomorphic transfer add (ring member i gets C[i], D), the parity rule for NonceHeight,
//                           the returned fee
//   process_transaction_sc  the returned fee on each exit (no SCDATA, no SCACTION, an install that succeeds, an
//                           install that reverts), the burn value handed to the SC (DEROVALUE and the SC balance),
//                           and the refund of the burn to the extractable signer on revert
//
// Consensus code is not changed: this is a test file. The honest proof is built like
// cryptography/crypto/r25_scalar_reencode_test.go (a true statement; nothing here constructs an invalid proof).

import (
	"math/big"
	"strconv"
	"testing"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/dvm"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/graviton"
)

type r31vsAccount struct {
	sk  *big.Int
	pub *bn256.G1
	c   [33]byte
}

func r31vsNewAccount() r31vsAccount {
	sk := crypto.RandomScalar()
	pub := new(bn256.G1).ScalarMult(crypto.G, sk)
	var a r31vsAccount
	a.sk, a.pub = sk, pub
	copy(a.c[:], pub.EncodeCompressed())
	return a
}

type r31vsState struct {
	ss      *graviton.Snapshot
	balance *graviton.Tree
	meta    *graviton.Tree
}

func r31vsMem(t *testing.T) r31vsState {
	t.Helper()
	store, err := graviton.NewMemStore()
	if err != nil {
		t.Fatal(err)
	}
	ss, err := store.LoadSnapshot(0)
	if err != nil {
		t.Fatal(err)
	}
	var s r31vsState
	s.ss = ss
	if s.balance, err = ss.GetTree(config.BALANCE_TREE); err != nil {
		t.Fatal(err)
	}
	if s.meta, err = ss.GetTree(config.SC_META); err != nil {
		t.Fatal(err)
	}
	return s
}

// put an account with encrypted balance bal (randomness k) the way the chain stores one
func r31vsPut(t *testing.T, tree *graviton.Tree, a r31vsAccount, bal uint64) {
	t.Helper()
	k := crypto.RandomScalar()
	left := new(bn256.G1).Add(new(bn256.G1).ScalarMult(crypto.G, new(big.Int).SetUint64(bal)), new(bn256.G1).ScalarMult(a.pub, k))
	right := new(bn256.G1).ScalarMult(crypto.G, k)
	nb := crypto.NonceBalance{NonceHeight: 0, Balance: crypto.ConstructElGamal(left, right)}
	if err := tree.Put(a.c[:], nb.Serialize()); err != nil {
		t.Fatal(err)
	}
}

// the stored balance of a decrypts to want (Left - sk*Right == want*G), and its nonce height
func r31vsBalance(t *testing.T, tree *graviton.Tree, a r31vsAccount, want int64) uint64 {
	t.Helper()
	raw, err := tree.Get(a.c[:])
	if err != nil {
		t.Fatalf("account not in tree: %s", err)
	}
	nb := new(crypto.NonceBalance).Deserialize(raw)
	got := new(bn256.G1).Add(nb.Balance.Left, new(bn256.G1).Neg(new(bn256.G1).ScalarMult(nb.Balance.Right, a.sk)))
	exp := new(bn256.G1).ScalarMult(crypto.G, big.NewInt(want))
	if string(got.EncodeCompressed()) != string(exp.EncodeCompressed()) {
		t.Fatalf("balance does not decrypt to %d", want)
	}
	return nb.NonceHeight
}

// an honest ring-2 transfer statement (sender index 0 pays value+fees, receiver index 1 gets value) and its proof
type r31vsTransfer struct {
	s     crypto.Statement
	proof *crypto.Proof
}

func r31vsHonest(t *testing.T, ring []r31vsAccount, balance, value, fees uint64) r31vsTransfer {
	t.Helper()
	r := crypto.RandomScalar()
	D := new(bn256.G1).ScalarMult(crypto.G, r)
	var keys, C, CLn, CRn []*bn256.G1
	var secrets []*big.Int
	for i, a := range ring {
		keys = append(keys, a.pub)
		secrets = append(secrets, a.sk)
		amount := new(big.Int)
		switch i {
		case 0:
			amount.SetInt64(0 - int64(value) - int64(fees))
		case 1:
			amount.SetInt64(int64(value))
		}
		x := new(bn256.G1).Add(new(bn256.G1).ScalarMult(crypto.G, amount), new(bn256.G1).ScalarMult(a.pub, r))
		C = append(C, x)
		bal := uint64(0)
		if i == 0 {
			bal = balance
		}
		k := crypto.RandomScalar()
		left := new(bn256.G1).Add(new(bn256.G1).ScalarMult(crypto.G, new(big.Int).SetUint64(bal)), new(bn256.G1).ScalarMult(a.pub, k))
		CLn = append(CLn, new(bn256.G1).Add(left, x))
		CRn = append(CRn, new(bn256.G1).Add(new(bn256.G1).ScalarMult(crypto.G, k), D))
	}
	var h r31vsTransfer
	h.s = crypto.Statement{CLn: CLn, CRn: CRn, Publickeylist: keys, C: C, D: D, Fees: fees}
	copy(h.s.Roothash[:], []byte("r31 value sites statement root.."))
	w := crypto.Witness{SecretKey: secrets[0], R: r, TransferAmount: value, Balance: balance - value - fees, Index: []int{0, 1}}
	var scid crypto.Hash
	uinput := append([]byte(crypto.PROTOCOL_CONSTANT), h.s.Roothash[:]...)
	uinput = append(uinput, scid[:]...)
	uinput = append(uinput, strconv.Itoa(0)...)
	u := new(bn256.G1).ScalarMult(crypto.HashToPoint(crypto.HashtoNumber(uinput)), secrets[0])
	h.proof = crypto.GenerateProof(scid, 0, &h.s, &w, u, crypto.Keccak256([]byte("r31 value sites txid")), 0)

	// the chain-side (deserialized and expanded) form of the statement
	h.s.RingSize = uint64(len(ring))
	h.s.Bytes_per_publickey = 32
	h.s.Publickeylist_pointers = nil
	h.s.Publickeylist_compressed = nil
	for _, a := range ring {
		kh := graviton.Sum(a.c[:])
		h.s.Publickeylist_pointers = append(h.s.Publickeylist_pointers, kh[:]...)
		h.s.Publickeylist_compressed = append(h.s.Publickeylist_compressed, a.c)
	}
	return h
}

func r31vsWithNet(t *testing.T, mainnet bool) {
	old := globals.Config
	if mainnet {
		globals.Config = config.Mainnet
	} else {
		globals.Config = config.Testnet
	}
	t.Cleanup(func() { globals.Config = old })
}

// process_transaction REGISTRATION: transaction_execute.go:188 (simulator / non-mainnet grant) and :195 (mainnet
// height < 144000 grant); a registration returns no fee.
func TestR31ValueSiteRegistrationGrant(t *testing.T) {
	cases := []struct {
		name      string
		mainnet   bool
		simulator bool
		height    uint64
		want      int64
	}{
		{"testnet-simulator", false, true, 10, 100000000},
		{"testnet-node", false, false, 10, 100000000},
		{"mainnet-early", true, false, 143999, 200},
		{"mainnet-late", true, false, 144000, 0},
		{"mainnet-simulator-early", true, true, 5, 100000200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r31vsWithNet(t, c.mainnet)
			st := r31vsMem(t)
			a := r31vsNewAccount()
			chain := &Blockchain{simulator: c.simulator}
			tx := transaction.Transaction{}
			tx.Version = 1
			tx.TransactionType = transaction.REGISTRATION
			tx.MinerAddress = a.c
			fees := chain.process_transaction(map[crypto.Hash]*graviton.Tree{}, tx, st.balance, c.height)
			if fees != 0 {
				t.Fatalf("registration returned fee %d, want 0", fees)
			}
			if nh := r31vsBalance(t, st.balance, a, c.want); nh != 0 {
				t.Fatalf("registration nonce height %d, want 0", nh)
			}
		})
	}
}

// process_transaction NORMAL: transaction_execute.go:241 (each ring member's balance += (C[i], D)), the parity rule
// that moves the sender's NonceHeight, and :256 (the fee returned to the miner). Value is conserved: the ring's
// decrypted deltas sum to -fees.
func TestR31ValueSiteTransferAddsCommitments(t *testing.T) {
	r31vsWithNet(t, false)
	const balance, value, fees, height = uint64(1000), uint64(7), uint64(3), uint64(77)
	st := r31vsMem(t)
	ring := []r31vsAccount{r31vsNewAccount(), r31vsNewAccount()}
	r31vsPut(t, st.balance, ring[0], balance)
	r31vsPut(t, st.balance, ring[1], 0)
	h := r31vsHonest(t, ring, balance, value, fees)

	tx := transaction.Transaction{}
	tx.Version = 1
	tx.TransactionType = transaction.NORMAL
	tx.Payloads = []transaction.AssetPayload{{RPCPayload: make([]byte, transaction.PAYLOAD_LIMIT), Statement: h.s, Proof: h.proof}}
	chain := &Blockchain{}
	got := chain.process_transaction(map[crypto.Hash]*graviton.Tree{}, tx, st.balance, height)
	if got != fees {
		t.Fatalf("process_transaction returned fee %d, want %d", got, fees)
	}
	nh0 := r31vsBalance(t, st.balance, ring[0], int64(balance-value-fees))
	nh1 := r31vsBalance(t, st.balance, ring[1], int64(value))
	// the proof's parity names the sender's index parity (sender 0 is even): only the sender's nonce moves
	if !h.proof.Parity() {
		t.Fatalf("honest proof with the sender at index 0 must have parity true")
	}
	if nh0 != height || nh1 != 0 {
		t.Fatalf("nonce heights %d/%d, want %d/0", nh0, nh1, height)
	}
}

const r31vsSC = `
Function Initialize() Uint64
10 STORE("deposit", DEROVALUE())
20 RETURN 0
End Function
`

const r31vsSCFail = `
Function Initialize() Uint64
10 STORE("deposit", DEROVALUE())
20 RETURN 1
End Function
`

const r31vsSCCall = `
Function Initialize() Uint64
10 RETURN 0
End Function

Function Fail() Uint64
10 STORE("deposit", DEROVALUE())
20 RETURN 1
End Function
`

// r31 closed loop (B327): an SC tx whose txid (= the SCID of an install) starts with 0x3a (':') cannot name a graviton
// tree (snapshot.go check_tree_name; the upstream simulator rerolls it, dvm/simulator.go:97-100), so its install never
// commits: 1 in 256 random statements. The 3-in-1,000 failures of install-deposit (and once the race stage of run 7,
// pipeline_20261113T163055) were all SCIDs 3a…; the builder rerolls like the simulator, and
// TestR31ValueSiteColonSCIDInstallNeverCommits pins the chain's behaviour for such an SCID (documented, never changed).
func r31vsSCTx(t *testing.T, ring []r31vsAccount, burn, fees uint64, scdata rpc.Arguments) transaction.Transaction {
	t.Helper()
	tx := r31vsSCTxOnce(t, ring, burn, fees, scdata)
	for n := 0; tx.GetHash()[0] == 0x3a; n++ { // execution does not verify the proof: vary the payload bytes only
		tx.Payloads[0].RPCPayload[0], tx.Payloads[0].RPCPayload[1] = byte(n), byte(n>>8)
	}
	return tx
}

func r31vsSCTxOnce(t *testing.T, ring []r31vsAccount, burn, fees uint64, scdata rpc.Arguments) transaction.Transaction {
	t.Helper()
	h := r31vsHonest(t, ring, 100000, 0, fees)
	tx := transaction.Transaction{}
	tx.Version = 1
	tx.TransactionType = transaction.SC_TX
	tx.SCDATA = scdata
	tx.Payloads = []transaction.AssetPayload{{BurnValue: burn, RPCPayload: make([]byte, transaction.PAYLOAD_LIMIT), Statement: h.s, Proof: h.proof}}
	return tx
}

func r31vsChain(t *testing.T) *Blockchain {
	chain := &Blockchain{}
	chain.Store.Block_tx_store.basedir = t.TempDir() // the expansion inside finds no block there and returns an error
	return chain
}

func r31vsRunSC(t *testing.T, chain *Blockchain, st r31vsState, tx transaction.Transaction) (map[crypto.Hash]*graviton.Tree, uint64, error) {
	t.Helper()
	return r31vsRunSCIn(t, chain, st, map[crypto.Hash]*graviton.Tree{}, tx)
}

func r31vsRunSCIn(t *testing.T, chain *Blockchain, st r31vsState, cache map[crypto.Hash]*graviton.Tree, tx transaction.Transaction) (map[crypto.Hash]*graviton.Tree, uint64, error) {
	t.Helper()
	var blid crypto.Hash
	gas, err := chain.process_transaction_sc(cache, st.ss, 10, 10, 1700000000, blid, tx, st.balance, st.meta)
	return cache, gas, err
}

// process_transaction_sc: transaction_execute.go:268 (no SCDATA), :271 + :298 (SCDATA without an action), :303 (the
// burn value is the SC's incoming value), :432 (success returns the fee); and the revert exit (the named gas set at
// :271 is returned with the error, the burn goes back to the signer).
func TestR31ValueSiteSCFeesAndBurn(t *testing.T) {
	r31vsWithNet(t, false)
	const burn, fees = uint64(4321), uint64(20000) // fees = the storage gas limit (walletapi passes gasstorage as fees)

	t.Run("no-scdata", func(t *testing.T) {
		st := r31vsMem(t)
		ring := []r31vsAccount{r31vsNewAccount(), r31vsNewAccount()}
		tx := r31vsSCTx(t, ring, burn, fees, nil)
		_, gas, err := r31vsRunSC(t, r31vsChain(t), st, tx)
		if err != nil || gas != fees {
			t.Fatalf("no SCDATA: gas %d err %v, want %d nil", gas, err, fees)
		}
	})

	t.Run("no-action", func(t *testing.T) {
		st := r31vsMem(t)
		ring := []r31vsAccount{r31vsNewAccount(), r31vsNewAccount()}
		tx := r31vsSCTx(t, ring, burn, fees, rpc.Arguments{{Name: "x", DataType: rpc.DataUint64, Value: uint64(1)}})
		_, gas, err := r31vsRunSC(t, r31vsChain(t), st, tx)
		if err != nil || gas != fees {
			t.Fatalf("no SCACTION: gas %d err %v, want %d nil", gas, err, fees)
		}
	})

	install := func(code string) rpc.Arguments {
		return rpc.Arguments{{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_INSTALL)},
			{Name: rpc.SCCODE, DataType: rpc.DataString, Value: code}}
	}

	t.Run("install-deposit", func(t *testing.T) {
		st := r31vsMem(t)
		ring := []r31vsAccount{r31vsNewAccount(), r31vsNewAccount()}
		r31vsPut(t, st.balance, ring[0], 0)
		r31vsPut(t, st.balance, ring[1], 0)
		tx := r31vsSCTx(t, ring, burn, fees, install(r31vsSC))
		cache, gas, err := r31vsRunSC(t, r31vsChain(t), st, tx)
		if err != nil || gas != fees {
			t.Fatalf("install: gas %d err %v, want %d nil", gas, err, fees)
		}
		scid := tx.GetHash()
		tree, ok := cache[scid]
		if !ok {
			t.Fatalf("install: SC data tree not committed to the cache")
		}
		w := &dvm.Tree_Wrapper{Tree: tree, Entries: map[string][]byte{}}
		if v, ok := dvm.ReadSCValue(w, scid, "deposit").(uint64); !ok || v != burn {
			t.Fatalf("install: DEROVALUE() stored %v, want %d", dvm.ReadSCValue(w, scid, "deposit"), burn)
		}
		meta := &dvm.Tree_Wrapper{Tree: st.meta, Entries: map[string][]byte{}}
		if bal, _, found := dvm.ReadSC(meta, w, scid); !found || bal != burn {
			t.Fatalf("install: SC balance %d (found %v), want %d", bal, found, burn)
		}
		// the signer's DERO balance is untouched by a successful install (the burn left with the tx)
		r31vsBalance(t, st.balance, ring[0], 0)
	})

	// an install whose Initialize fails returns the fee and the error at the early return of the SC_INSTALL case:
	// nothing is committed and the burn is NOT refunded (no ErrorRevert on this exit; pinned as it is today)
	t.Run("install-fail-no-refund", func(t *testing.T) {
		st := r31vsMem(t)
		ring := []r31vsAccount{r31vsNewAccount(), r31vsNewAccount()}
		r31vsPut(t, st.balance, ring[0], 0)
		r31vsPut(t, st.balance, ring[1], 0)
		tx := r31vsSCTx(t, ring, burn, fees, install(r31vsSCFail))
		cache, gas, err := r31vsRunSC(t, r31vsChain(t), st, tx)
		if err == nil || gas != fees {
			t.Fatalf("install fail: gas %d err %v, want %d and an error", gas, err, fees)
		}
		if _, ok := cache[tx.GetHash()]; ok {
			t.Fatalf("install fail: SC data tree committed")
		}
		r31vsBalance(t, st.balance, ring[0], 0)
		r31vsBalance(t, st.balance, ring[1], 0)
	})

	// a call whose entrypoint fails: ErrorRevert hands the burn back to the extractable signer (parity: index 0) and
	// the named gas set at :271 comes back with the error
	t.Run("call-revert-refund", func(t *testing.T) {
		st := r31vsMem(t)
		ring := []r31vsAccount{r31vsNewAccount(), r31vsNewAccount()}
		r31vsPut(t, st.balance, ring[0], 0)
		r31vsPut(t, st.balance, ring[1], 0)
		chain := r31vsChain(t)
		cache := map[crypto.Hash]*graviton.Tree{}
		itx := r31vsSCTx(t, ring, 0, fees, install(r31vsSCCall))
		if _, gas, err := r31vsRunSCIn(t, chain, st, cache, itx); err != nil || gas != fees {
			t.Fatalf("install: gas %d err %v", gas, err)
		}
		scid := itx.GetHash()
		call := rpc.Arguments{{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
			{Name: rpc.SCID, DataType: rpc.DataHash, Value: scid},
			{Name: "entrypoint", DataType: rpc.DataString, Value: "Fail"}}
		ctx := r31vsSCTx(t, ring, burn, fees, call)
		_, gas, err := r31vsRunSCIn(t, chain, st, cache, ctx)
		if err == nil || gas != fees {
			t.Fatalf("call revert: gas %d err %v, want %d and an error", gas, err, fees)
		}
		r31vsBalance(t, st.balance, ring[0], int64(burn))
		r31vsBalance(t, st.balance, ring[1], 0)
		w := &dvm.Tree_Wrapper{Tree: cache[scid], Entries: map[string][]byte{}}
		meta := &dvm.Tree_Wrapper{Tree: st.meta, Entries: map[string][]byte{}}
		if bal, _, found := dvm.ReadSC(meta, w, scid); !found || bal != 0 {
			t.Fatalf("call revert: SC balance %d (found %v), want 0", bal, found)
		}
	})
}

// B327: an install whose SCID starts with ':' (0x3a) never commits its data tree (graviton refuses the tree name); the
// chain's behaviour is pinned here, documented, never changed (consensus-visible; disclosure-style row)
func TestR31ValueSiteColonSCIDInstallNeverCommits(t *testing.T) {
	r31vsWithNet(t, false)
	const burn, fees = uint64(4321), uint64(20000)
	code := rpc.Arguments{{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_INSTALL)},
		{Name: rpc.SCCODE, DataType: rpc.DataString, Value: r31vsSC}}
	st := r31vsMem(t)
	ring := []r31vsAccount{r31vsNewAccount(), r31vsNewAccount()}
	r31vsPut(t, st.balance, ring[0], 0)
	r31vsPut(t, st.balance, ring[1], 0)
	tx := r31vsSCTxOnce(t, ring, burn, fees, code)
	for n := 0; tx.GetHash()[0] != 0x3a; n++ { // execution does not verify the proof: vary the payload bytes only
		if n > 1<<16 {
			t.Fatal("no 0x3a txid in 65,536 payload variants")
		}
		tx.Payloads[0].RPCPayload[0], tx.Payloads[0].RPCPayload[1] = byte(n), byte(n>>8)
	}
	cache, _, _ := r31vsRunSC(t, r31vsChain(t), st, tx)
	if _, ok := cache[tx.GetHash()]; ok {
		t.Fatal("an install whose SCID starts with 0x3a committed a data tree: the graviton tree-name rule changed")
	}
}
