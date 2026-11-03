// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package dvm

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/graviton"
)

// Characterization (Round 23 crypto audit; dvm/ is consensus code and nothing here is changed).
//
// SanityCheckExternalTransfers (dvm/simulator.go) is documented as also checking "whether all destinations are
// registered", but its condition `err == nil || ErrNotFound` treats an UNREGISTERED destination as fine and only
// leaves the not-found error in the named return when the LAST transfer's destination is the unregistered one. So
// [unregistered, registered] passes while [registered, unregistered] is refused. ProcessExternal then commits the
// SC's data writes (including the debited SC balance) BEFORE it walks the transfers, and panics at the first
// unregistered destination. The caller (blockchain process_transaction_sc) recovers and keeps the tx: the SC is
// debited, transfers before the bad one are credited, the bad one and all later ones are lost. Value is destroyed,
// never created (debit precedes every credit), and every node behaves the same, so this is a funds-loss footgun for
// SC authors, not a supply or consensus-split issue. A fix would change consensus state, so it is documented only.
func TestR23ExternalTransferToUnregisteredBurns(t *testing.T) {
	store, err := graviton.NewMemStore()
	if err != nil {
		t.Fatal(err)
	}
	ss, err := store.LoadSnapshot(0)
	if err != nil {
		t.Fatal(err)
	}
	balance_tree, err := ss.GetTree(config.BALANCE_TREE)
	if err != nil {
		t.Fatal(err)
	}
	reg := new(bn256.G1).ScalarMult(crypto.G, big.NewInt(11)).EncodeCompressed()
	unreg := new(bn256.G1).ScalarMult(crypto.G, big.NewInt(12)).EncodeCompressed() // valid point, never registered
	nb := crypto.NonceBalance{Balance: crypto.ConstructElGamal(new(bn256.G1).ScalarMult(crypto.G, big.NewInt(11)), crypto.ElGamal_BASE_G)}
	if err = balance_tree.Put(reg, nb.Serialize()); err != nil {
		t.Fatal(err)
	}

	var scid, zero crypto.Hash
	scid[0], scid[31] = 0x42, 0x24
	cache := map[crypto.Hash]*graviton.Tree{}
	w := Wrapped_tree(cache, ss, scid)
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], 100)
	w.Put(zero[:], v[:]) // SC holds 100
	// order dependence: unregistered destination LAST is refused ...
	w.Transfere = []TransferExternal{{Address: string(reg), Amount: 10}, {Address: string(unreg), Amount: 30}}
	if err := SanityCheckExternalTransfers(w, balance_tree, scid); err == nil {
		t.Fatal("premise changed: [registered, unregistered] now passes the sanity check")
	}
	w = Wrapped_tree(cache, ss, scid)
	w.Put(zero[:], v[:])
	// ... while the same transfers in the other order pass
	w.Transfere = []TransferExternal{{Address: string(unreg), Amount: 30}, {Address: string(reg), Amount: 10}}
	if err := SanityCheckExternalTransfers(w, balance_tree, scid); err != nil {
		t.Fatalf("premise changed: the sanity check now refuses an unregistered destination (%v)", err)
	}
	if left, _ := LoadSCAssetValue(w, scid, zero); left != 60 {
		t.Fatalf("SC balance after the sanity check = %d, want 60 (debited for both transfers)", left)
	}
	w_sc := &Tree_Wrapper{Tree: w.Tree, Entries: map[string][]byte{}}

	panicked := func() (p bool) {
		defer func() { p = recover() != nil }()
		ProcessExternal(ss, cache, balance_tree, [33]byte{}, scid, w, w_sc)
		return
	}()
	if !panicked {
		t.Fatal("premise changed: ProcessExternal no longer panics on an unregistered destination")
	}
	// the debit was committed before the panic
	raw, err := w.Tree.Get(zero[:])
	if err != nil || binary.BigEndian.Uint64(raw) != 60 {
		t.Fatalf("committed SC balance = %x (%v), want 60", raw, err)
	}
	// the unregistered destination got nothing, and the registered one (after it) got nothing either
	if _, err := balance_tree.Get(unreg); err == nil {
		t.Fatal("unregistered destination was created")
	}
	if after, err := balance_tree.Get(reg); err != nil || string(after) != string(nb.Serialize()) {
		t.Fatal("registered destination after the unregistered one was credited")
	}
}
