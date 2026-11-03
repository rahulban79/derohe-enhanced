package blockchain

import (
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/deroproject/graviton"
	"golang.org/x/xerrors"
)

// The recogniser must fire on exactly the error graviton produces for the all-zero signer, and
// on nothing else. The error is produced by a real graviton tree, not typed in.
func TestZeroSignerRevertIsRecognised(t *testing.T) {
	store, err := graviton.NewMemStore()
	if err != nil {
		t.Fatal(err)
	}
	ss, err := store.LoadSnapshot(0)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := ss.GetTree("balances")
	if err != nil {
		t.Fatal(err)
	}
	// one real account so that a lookup of a different key lands on a leaf ("collision")
	real_key := make([]byte, 33)
	real_key[0], real_key[32] = 2, 7
	if err := tree.Put(real_key, []byte("balance")); err != nil {
		t.Fatal(err)
	}

	var zero [33]byte
	_, zerr := tree.Get(zero[:])
	if zerr == nil {
		t.Fatal("expected graviton to fail on the zero signer")
	}
	if !is_zero_signer_revert(zerr) {
		t.Fatalf("zero-signer lookup not recognised: %v (want keyhash %s)", zerr, zero_signer_keyhash)
	}

	other := make([]byte, 33)
	other[5] = 9
	_, oerr := tree.Get(other)
	if oerr == nil || !errors.Is(oerr, graviton.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for another missing key, got %v", oerr)
	}
	if is_zero_signer_revert(oerr) {
		t.Fatalf("a different missing key must not be recognised: %v", oerr)
	}

	// the leaf form, exactly as the live node printed it (node_leaf.go:108's format string)
	var live, in_ram [32]byte
	hex.Decode(live[:], []byte(zero_signer_keyhash))
	hex.Decode(in_ram[:], []byte("02dc1ac7dce21f646800c7d40769ecdad67ea7094ab9d3a420ace07e8b498f0d"))
	collision := xerrors.Errorf("%w: collision, keyhash %x not found, keyhash in ram %x", graviton.ErrNotFound, live, in_ram)
	if collision.Error() != "leaf not found: collision, keyhash 02dc1cbdfa9a150e0fc02f1e098f6f8ccdb676b95bd96704072bf52a9d93a23e not found, keyhash in ram 02dc1ac7dce21f646800c7d40769ecdad67ea7094ab9d3a420ace07e8b498f0d: leaf not found" {
		t.Fatalf("collision text differs from the live log: %q", collision.Error())
	}
	if !is_zero_signer_revert(collision) {
		t.Fatal("the live collision error must be recognised")
	}
	// the zero signer appearing only as the leaf that was hit, not as the key looked up
	swapped := xerrors.Errorf("%w: collision, keyhash %x not found, keyhash in ram %x", graviton.ErrNotFound, in_ram, live)
	if is_zero_signer_revert(swapped) {
		t.Fatal("must match only the looked-up key, not the leaf in ram")
	}

	for _, r := range []interface{}{"tree cannot be nil at this point in time", fmt.Errorf("keyhash %s not found", zero_signer_keyhash), 42, nil} {
		if is_zero_signer_revert(r) {
			t.Fatalf("non-graviton panic value %v must not be recognised", r)
		}
	}
}

// The value the console printed on 2026-10-20/21 (harness/runtime/derod_console_20261021.log).
func TestZeroSignerKeyhashMatchesTheLiveLog(t *testing.T) {
	if zero_signer_keyhash != "02dc1cbdfa9a150e0fc02f1e098f6f8ccdb676b95bd96704072bf52a9d93a23e" {
		t.Fatalf("zero_signer_keyhash = %s", zero_signer_keyhash)
	}
}

// Go semantics the fix relies on, reproduced in the exact shape of process_transaction_sc: named
// results assigned before a panic survive a deferred recover that does not touch them. This is
// why the fee of a reverted anonymous SC tx is kept (gas = tx.Fees() is set first).
func TestRecoverKeepsNamedResults(t *testing.T) {
	sc_error := errors.New("sc failed")
	f := func() (gas uint64, err error) {
		defer func() {
			if r := recover(); r != nil {
				return
			}
		}()
		gas = 1234
		err = sc_error
		panic("ErrorRevert on the zero signer")
	}
	gas, err := f()
	if gas != 1234 || err != sc_error {
		t.Fatalf("got gas=%d err=%v, want 1234 and the SC error", gas, err)
	}
}
