package main

// R31 B111: the set diff on an in-memory graviton store (never a datadir). Known answer: three registered keys plus
// one key without a registration (the genesis-premine shape) leave exactly that key's digest; a registration whose
// key is absent is counted on the other side.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/graviton"
)

func r31key(b byte) []byte {
	k := make([]byte, 33)
	for i := range k {
		k[i] = b
	}
	return k
}

func TestR31KeyDiffLeavesTheUnregisteredKey(t *testing.T) {
	store, err := graviton.NewMemStore()
	if err != nil {
		t.Fatal(err)
	}
	ss, _ := store.LoadSnapshot(0)
	bt, _ := ss.GetTree(config.BALANCE_TREE)
	mt, _ := ss.GetTree(config.SC_META)
	for _, b := range []byte{1, 2, 3, 9} { // 9 = the key with no registration
		if err := bt.Put(r31key(b), []byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := graviton.Commit(bt, mt); err != nil {
		t.Fatal(err)
	}
	ss, _ = store.LoadSnapshot(0)
	keys, lens, root, err := keyDigests(ss)
	if err != nil || len(keys) != 4 || lens[33] != 4 || len(root) != 64 {
		t.Fatalf("walk: %d keys lens %v root %q err %v", len(keys), lens, root, err)
	}
	regs := map[[32]byte]struct{}{}
	for _, b := range []byte{1, 2, 3, 7} { // 7 = a registration whose key is not in this tree
		regs[sha256.Sum256(r31key(b))] = struct{}{}
	}
	r := diff(keys, regs, 16)
	g := sha256.Sum256(r31key(9))
	if r.BalanceKeys != 4 || r.KeysInRegs != 3 || r.KeysNotInRegs != 1 || r.RegsNotInKeys != 1 ||
		len(r.KeysNotInRegsDigests) != 1 || r.KeysNotInRegsDigests[0] != hex.EncodeToString(g[:]) {
		t.Fatalf("diff %+v", r)
	}
}

func TestR31KeyDiffReadsRegkeysAndRefusesALiveStore(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "regkeys.bin")
	a, b := sha256.Sum256([]byte("a")), sha256.Sum256([]byte("b"))
	if err := os.WriteFile(p, append(append(append([]byte{}, a[:]...), b[:]...), a[:]...), 0600); err != nil {
		t.Fatal(err)
	}
	all, set, err := readRegs(p)
	if err != nil || all != 3 || len(set) != 2 {
		t.Fatalf("readRegs: %d %d %v", all, len(set), err)
	}
	if err := os.WriteFile(filepath.Join(d, "version_root.bin"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FORENSICS_STORE_COPY_OK", "")
	if _, err := openCopy(d); err == nil {
		t.Fatalf("opened a store not named by FORENSICS_STORE_COPY_OK")
	}
	if err := os.WriteFile(filepath.Join(d, "short.bin"), make([]byte, 33), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readRegs(filepath.Join(d, "short.bin")); err == nil {
		t.Fatalf("a sidecar of 33 bytes was read")
	}
}
