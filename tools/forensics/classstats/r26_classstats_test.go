package main

// R26 forensics-classes: tests of the structural-statistics helper (rft §0.8.9; B110 FQ3, B111 Q-CS1). They read a
// RAW body committed in forensics/r25/raw/blobs and an in-memory graviton store; nothing touches a datadir.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/graviton"
)

// the 1,703 B body of table TXID 0045a6d4… (dataset v1, derived/hf3.json body_sha256)
const r26Body = "../../../forensics/r25/raw/blobs/dac0126145be6c04c4765be9d04753d28eb4ff0facce0263fad0bc220c23d853"
const r26TXID = "0045a6d4c51a8578b6c97f2b376415653583505f21032eb6a808cd1643a300a7"

func TestR26StructStatsDigestsEveryPayload(t *testing.T) {
	buf, err := os.ReadFile(r26Body)
	if err != nil {
		t.Skipf("dataset v1 blob not present: %v", err)
	}
	o := structStats(r26Body, buf)
	if !o.OK || o.TXID != r26TXID {
		t.Fatalf("decode: ok=%v txid=%s err=%s", o.OK, o.TXID, o.Error)
	}
	if len(o.Payloads) != 1 || o.Payloads[0].RingSize != 2 {
		t.Fatalf("payloads %+v", o.Payloads)
	}
	d, err := hex.DecodeString(o.Payloads[0].DSHA256)
	if err != nil || len(d) != 32 {
		t.Fatalf("D digest is not a SHA-256: %q", o.Payloads[0].DSHA256)
	}
	if o.Payloads[0].Roothash == "" || len(o.Payloads[0].Roothash) != 64 {
		t.Fatalf("roothash %q", o.Payloads[0].Roothash)
	}
	// the digest is of the statement's D as the node decodes it (not of another field)
	var tx transaction.Transaction
	if err := tx.Deserialize(buf); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(tx.Payloads[0].Statement.D.EncodeCompressed())
	if o.Payloads[0].DSHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("D digest %s, want %x", o.Payloads[0].DSHA256, want)
	}
	if o.Payloads[0].Roothash != hex.EncodeToString(tx.Payloads[0].Statement.Roothash[:]) {
		t.Fatal("roothash is not the statement's")
	}
	// deterministic: the same bytes give the same digest; a truncated body is an error, never a guess
	if o2 := structStats(r26Body, buf); o2.Payloads[0].DSHA256 != o.Payloads[0].DSHA256 {
		t.Fatal("digest not deterministic")
	}
	if o3 := structStats(r26Body, buf[:len(buf)/2]); o3.OK {
		t.Fatal("a truncated body decoded OK")
	}
}

func TestR26CensusCountsEveryTree(t *testing.T) {
	s, err := graviton.NewMemStore()
	if err != nil {
		t.Fatal(err)
	}
	ss, _ := s.LoadSnapshot(0)
	bt, _ := ss.GetTree(config.BALANCE_TREE)
	mt, _ := ss.GetTree(config.SC_META)
	for _, k := range []string{"a-key-0000000000000000000000000001", "a-key-0000000000000000000000000002", "a-key-0000000000000000000000000003"} {
		bt.Put([]byte(k), []byte("v"))
	}
	scid := "0123456789abcdef0123456789abcdef"
	mt.Put([]byte(scid), []byte("meta"))
	st, _ := ss.GetTree(scid)
	st.Put([]byte("k1"), []byte("x"))
	st.Put([]byte("k22"), []byte("y"))
	if _, err := graviton.Commit(bt, mt, st); err != nil {
		t.Fatal(err)
	}
	ss2, _ := s.LoadSnapshot(0)
	o, err := census(ss2)
	if err != nil || !o.OK {
		t.Fatalf("census: %v %+v", err, o)
	}
	if o.BalanceKeys != 3 || o.SCMetaKeys != 1 || o.SCTreeKeys != 2 || o.SCTreesWithKeys != 1 {
		t.Fatalf("counts %+v", o)
	}
	if o.BalanceKeyLens[34] != 3 || o.SCTreeKeyLens[2] != 1 || o.SCTreeKeyLens[3] != 1 {
		t.Fatalf("key lengths %+v %+v", o.BalanceKeyLens, o.SCTreeKeyLens)
	}
	b2, _ := ss2.GetTree(config.BALANCE_TREE)
	m2, _ := ss2.GetTree(config.SC_META)
	bh, _ := b2.Hash()
	mh, _ := m2.Hash()
	var want [32]byte
	for i := range want {
		want[i] = bh[i] ^ mh[i]
	}
	if o.Root != hex.EncodeToString(want[:]) {
		t.Fatalf("root %s want %x", o.Root, want)
	}
}

func TestR26CensusRefusesAnUnnamedStore(t *testing.T) {
	dir := t.TempDir()
	s, err := graviton.NewDiskStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ss, _ := s.LoadSnapshot(0)
	bt, _ := ss.GetTree(config.BALANCE_TREE)
	mt, _ := ss.GetTree(config.SC_META)
	bt.Put([]byte("k"), []byte("v"))
	v, err := graviton.Commit(bt, mt)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	abs, _ := filepath.Abs(dir)
	t.Setenv("FORENSICS_STORE_COPY_OK", "")
	if o := runCensus(dir, v); o.OK || o.Error == "" {
		t.Fatalf("opened a store not named by FORENSICS_STORE_COPY_OK: %+v", o)
	}
	t.Setenv("FORENSICS_STORE_COPY_OK", abs) // positive control: the named copy opens and counts
	if o := runCensus(dir, v); !o.OK || o.BalanceKeys != 1 {
		t.Fatalf("the named copy did not open: %+v", o)
	}
	if o := runCensus(t.TempDir(), 1); o.OK {
		t.Fatal("opened a directory without version_root.bin")
	}
}
