// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package emission

import (
	"encoding/binary"
	"testing"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/dvm"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/graviton"
)

// Round 27 (dvm-blockchain, B110 class): the auditor's SC path exercised by a REAL contract. The other SC tests of
// this package fake the payout with c.plus; no live SC payout has occurred in any measured window (census: 1 SC_TX
// body in 100,000 blocks, sc_payouts 0), so this is the only evidence that what the DVM actually writes is booked.
// The contract runs through the chain's own sequence (blockchain/transaction_execute.go process_transaction_sc,
// SC_CALL branch): ReadSC -> Execute_sc_function -> SanityCheckExternalTransfers -> ProcessExternal, or ErrorRevert
// on any error, on the block's balance tree and the SC's data tree, then the block is committed and audited.

const r27_pay_sc = `
Function Pay(dest String, amount Uint64, asset String) Uint64
10 SEND_ASSET_TO_ADDRESS(dest, amount, asset)
20 RETURN 0
End Function

Function PayDero(dest String, amount Uint64) Uint64
10 SEND_DERO_TO_ADDRESS(dest, amount)
20 RETURN 0
End Function
`

const r27_fee = 1000 // covers the SCDATA bytes charged as storage gas (sc.go ConsumeStorageGas(len(SCDATA)))

var r27_token = func() crypto.Hash { h := hashOf("token"); h[0] = 0x81; return h }()

// newWorld + the contract installed at scid the way SC_INSTALL stores it (code under SC_Code_Key in the SC's data
// tree, SC_META_DATA under its scid), and 1,000 units of r27_token held by the SC
func r27_dvm_world(t *testing.T) *world {
	w := newWorld(t)
	ss, err := w.f.State(w.parent)
	if err != nil {
		t.Fatal(err)
	}
	bt, _ := ss.GetTree(config.BALANCE_TREE)
	meta, _ := ss.GetTree(config.SC_META)
	sct, _ := ss.GetTree(string(scid[:]))
	meta.Put(dvm.SC_Meta_Key(scid), dvm.SC_META_DATA{}.MarshalBinary())
	sct.Put(dvm.SC_Code_Key(scid), dvm.Variable{Type: dvm.String, ValueString: r27_pay_sc}.MarshalBinaryPanic())
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], 1000)
	sct.Put(r27_token[:], v[:])
	ver, err := graviton.Commit(bt, meta, sct)
	if err != nil {
		t.Fatal(err)
	}
	w.parent = hashOf("parent-dvm")
	w.f.versions[w.parent] = ver
	return w
}

// r27_exec runs the call like consensus does and returns the extra trees it touched (token trees) for the commit
func r27_exec(t *testing.T, c *child, txid crypto.Hash, signer acct, deposit uint64, args rpc.Arguments) (err error, extra []*graviton.Tree) {
	t.Helper()
	cache := map[crypto.Hash]*graviton.Tree{scid: c.sct}
	w_sc_tree := &dvm.Tree_Wrapper{Tree: c.meta, Entries: map[string][]byte{}}
	w_data := dvm.Wrapped_tree(cache, c.ss, scid)
	var sig [33]byte
	copy(sig[:], signer.key)
	incoming := map[crypto.Hash]uint64{crypto.ZEROHASH: deposit}
	balance, sc, found := dvm.ReadSC(w_sc_tree, w_data, scid)
	if !found {
		t.Fatal("contract not found")
	}
	entry := args.Value("entrypoint", rpc.DataString).(string)
	_, _, err = dvm.Execute_sc_function(w_sc_tree, w_data, scid, c.bl.Height, c.bl.Height, 0, c.id, txid, sc, entry, 1, balance, sig, incoming, args, r27_fee, false) // the chain passes tx.Fees() as the storage-gas budget
	if err == nil {
		err = dvm.SanityCheckExternalTransfers(w_data, c.bt, scid)
	}
	if err != nil {
		dvm.ErrorRevert(c.ss, cache, c.bt, sig, scid, incoming)
	} else {
		dvm.ProcessExternal(c.ss, cache, c.bt, sig, scid, w_data, w_sc_tree)
	}
	for id, tr := range cache {
		if id != scid {
			extra = append(extra, tr)
		}
	}
	return
}

func r27_args(entry string, extra ...rpc.Argument) rpc.Arguments {
	return append(append(scCall(), rpc.Argument{Name: "entrypoint", DataType: rpc.DataString, Value: entry}), extra...)
}

func r27_block(t *testing.T, w *world, name string, deposit uint64, args rpc.Arguments) (Report, error, []*graviton.Tree) {
	c := w.child(name)
	h := c.transfer(name+"-call", transaction.SC_TX, []acct{w.B, w.C}, r27_fee, deposit, args)
	err, extra := r27_exec(t, c, h, w.B, deposit, args)
	c.coinbase(0)
	c.commit(append([]*graviton.Tree{c.sct}, extra...)...)
	return c.audit(mainnet), err, extra
}

func TestR27AuditBooksRealSendAssetToAddress(t *testing.T) {
	for _, tc := range []struct {
		name string
		args func(w *world) rpc.Arguments
	}{
		{"send_asset_dero", func(w *world) rpc.Arguments {
			return r27_args("Pay", rpc.Argument{Name: "dest", DataType: rpc.DataString, Value: string(w.Pay.key)},
				rpc.Argument{Name: "amount", DataType: rpc.DataUint64, Value: uint64(300)},
				rpc.Argument{Name: "asset", DataType: rpc.DataHash, Value: crypto.ZEROHASH})
		}},
		{"send_dero", func(w *world) rpc.Arguments {
			return r27_args("PayDero", rpc.Argument{Name: "dest", DataType: rpc.DataString, Value: string(w.Pay.key)},
				rpc.Argument{Name: "amount", DataType: rpc.DataUint64, Value: uint64(300)})
		}},
	} {
		w := r27_dvm_world(t)
		r, err, _ := r27_block(t, w, tc.name, 700, tc.args(w))
		if err != nil {
			t.Fatalf("%s: contract failed: %v", tc.name, err)
		}
		wantVerdict(t, r, VerdictOKSC, "")
		if r.SCPayout != 300 || r.SCDeposits != 700 || r.SCDelta != "400" || r.SCCalls != 1 {
			t.Fatalf("%s: booked payout %d deposits %d delta %s calls %d, want 300 700 400 1", tc.name, r.SCPayout, r.SCDeposits, r.SCDelta, r.SCCalls)
		}
		if r.PerAccount != "right_only" {
			t.Fatalf("%s: per-account %q, want right_only (SC payouts are not published per account)", tc.name, r.PerAccount)
		}
	}
}

func r27_pay_args(dest acct, amount uint64) rpc.Arguments {
	return r27_args("Pay", rpc.Argument{Name: "dest", DataType: rpc.DataString, Value: string(dest.key)},
		rpc.Argument{Name: "amount", DataType: rpc.DataUint64, Value: amount},
		rpc.Argument{Name: "asset", DataType: rpc.DataHash, Value: crypto.ZEROHASH})
}

func TestR27AuditBooksRealOverdraftRefund(t *testing.T) {
	w := r27_dvm_world(t)
	r, err, _ := r27_block(t, w, "overdraft", 700, r27_pay_args(w.Pay, 5701)) // held 5,000 + deposit 700 = 5,700
	if err == nil {
		t.Fatal("an overdraft by one unit was accepted")
	}
	// the deposit goes back to the signer (ErrorRevert): booked as a payout of exactly the deposit, SC unchanged
	wantVerdict(t, r, VerdictOKSC, "")
	if r.SCPayout != 700 || r.SCDelta != "0" {
		t.Fatalf("refund booked as payout %d delta %s, want 700 0", r.SCPayout, r.SCDelta)
	}
	// control: exactly what it holds is allowed and booked
	w = r27_dvm_world(t)
	if r, err, _ = r27_block(t, w, "drain", 700, r27_pay_args(w.Pay, 5700)); err != nil || r.Verdict != VerdictOKSC || r.SCPayout != 5700 || r.SCDelta != "-5000" {
		t.Fatalf("draining the SC: err %v verdict %s payout %d delta %s, want ok_sc 5700 -5000", err, r.Verdict, r.SCPayout, r.SCDelta)
	}
	// an unregistered destination as the LAST transfer is refused by SanityCheckExternalTransfers (R23
	// TestR23ExternalTransferToUnregisteredBurns): refunded and booked like the overdraft
	w = r27_dvm_world(t)
	if r, err, _ = r27_block(t, w, "unregistered", 700, r27_pay_args(newAcct(), 300)); err == nil || r.Verdict != VerdictOKSC || r.SCPayout != 700 || r.SCDelta != "0" {
		t.Fatalf("unregistered destination: err %v verdict %s payout %d delta %s, want refused, ok_sc 700 0", err, r.Verdict, r.SCPayout, r.SCDelta)
	}
}

// Scope, pinned: a payout in a token (asset != DERO) moves a token tree, never the balance tree, so the DERO auditor
// books 0 for it and its Report has no token field. The emission segment's sc_payouts is a DERO-only figure.
func TestR27AuditTokenPayoutOutsideScope(t *testing.T) {
	w := r27_dvm_world(t)
	args := r27_pay_args(w.Pay, 300)
	args[len(args)-1].Value = r27_token
	r, err, extra := r27_block(t, w, "token", 0, args)
	if err != nil {
		t.Fatalf("token payout failed: %v", err)
	}
	if len(extra) != 1 {
		t.Fatalf("token payout touched %d token trees, want 1", len(extra))
	}
	post, _ := w.f.State(hashOf("token"))
	tt, _ := post.GetTree(string(r27_token[:]))
	if _, e := tt.Get(w.Pay.key); e != nil {
		t.Fatalf("premise: the token tree holds no balance for the payee (%v)", e)
	}
	wantVerdict(t, r, VerdictOKSC, "")
	if r.SCPayout != 0 || r.SCDelta != "0" {
		t.Fatalf("token payout booked as DERO: payout %d delta %s", r.SCPayout, r.SCDelta)
	}
}
