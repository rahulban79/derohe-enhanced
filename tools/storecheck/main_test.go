package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
)

type fixture struct {
	store string
	ids   [][32]byte
	paths []string
	txid  crypto.Hash
	txp   string
}

// a 3-block store laid out exactly as storefs/storetopofs write it; block 2 carries one tx
func make_store(t *testing.T) *fixture {
	fx := &fixture{store: filepath.Join(t.TempDir(), "mainnet")}
	var tx transaction.Transaction
	tx.Version, tx.TransactionType, tx.Value = 1, transaction.PREMINE, 5
	traw := tx.Serialize()
	fx.txid = tx.GetHash()
	var topo []byte
	for h := uint64(0); h < 3; h++ {
		var bl block.Block
		bl.Major_Version, bl.Height, bl.Timestamp = 1, h, 1000+h
		bl.Miner_TX.Version, bl.Miner_TX.TransactionType = 1, transaction.PREMINE
		if h == 2 {
			bl.Tx_hashes = []crypto.Hash{fx.txid}
		}
		id := bl.GetHash()
		dir := filepath.Join(fx.store, "bltx_store", fmt.Sprintf("%02x", id[0]), fmt.Sprintf("%02x", id[1]))
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, fmt.Sprintf("%x.block_%d_%d_%d", id[:], 100+h, 10+h, h))
		if err := os.WriteFile(p, bl.Serialize(), 0600); err != nil {
			t.Fatal(err)
		}
		fx.ids, fx.paths = append(fx.ids, id), append(fx.paths, p)
		var rec [toporecord_size]byte
		copy(rec[:], id[:])
		binary.LittleEndian.PutUint64(rec[32:], 10+h)
		binary.LittleEndian.PutUint64(rec[40:], h)
		topo = append(topo, rec[:]...)
	}
	topo = append(topo, make([]byte, 2*toporecord_size)...) // two clean trailing records (a pop leaves these)
	if err := os.WriteFile(filepath.Join(fx.store, "topo.map"), topo, 0600); err != nil {
		t.Fatal(err)
	}
	tdir := filepath.Join(fx.store, "bltx_store", fmt.Sprintf("%02x", fx.txid[16]), fmt.Sprintf("%02x", fx.txid[17]))
	os.MkdirAll(tdir, 0700)
	fx.txp = filepath.Join(tdir, fmt.Sprintf("%x.tx", fx.txid[:]))
	if err := os.WriteFile(fx.txp, traw, 0600); err != nil {
		t.Fatal(err)
	}
	return fx
}

func kinds(r report) (k []string) {
	for _, p := range r.Problems {
		k = append(k, p.Kind)
	}
	return
}

func want_one(t *testing.T, r report, kind string) {
	t.Helper()
	if len(r.Problems) != 1 || r.Problems[0].Kind != kind {
		t.Fatalf("want exactly one %s, got %v", kind, kinds(r))
	}
}

func TestR23cStorecheckCleanStoreAndReadOnly(t *testing.T) {
	fx := make_store(t)
	// read-only: the scan must work on a store nobody may write to
	filepath.Walk(fx.store, func(p string, fi os.FileInfo, err error) error {
		if fi.IsDir() {
			return nil
		}
		return os.Chmod(p, 0400)
	})
	r, err := check(fx.store, 100)
	if err != nil {
		t.Fatal(err)
	}
	if r.Records != 3 || r.Checked != 3 || r.TxsSeen != 1 || len(r.Problems) != 0 {
		t.Fatalf("clean store: %+v", r)
	}
}

func TestR23cStorecheckTornBlock(t *testing.T) {
	for _, keep := range []int{0, 10} { // an empty body (crash right after create) and a partial one
		fx := make_store(t)
		b, _ := os.ReadFile(fx.paths[1])
		os.WriteFile(fx.paths[1], b[:keep], 0600)
		r, _ := check(fx.store, 100)
		want_one(t, r, "block_torn")
		if r.Problems[0].Topo != 1 {
			t.Fatalf("wrong topo %d", r.Problems[0].Topo)
		}
	}
}

func TestR23cStorecheckNameAndRecordMismatch(t *testing.T) {
	fx := make_store(t)
	os.Rename(fx.paths[0], fx.paths[0][:len(fx.paths[0])-1]+"9") // name height 0 -> 9
	r, _ := check(fx.store, 100)
	want_one(t, r, "height_mismatch")

	fx = make_store(t)
	np := fx.paths[2][:len(fx.paths[2])-len("_12_2")] + "_99_2"
	os.Rename(fx.paths[2], np)
	r, _ = check(fx.store, 100)
	want_one(t, r, "version_mismatch")

	fx = make_store(t)
	os.WriteFile(fx.paths[2]+"x", []byte{1}, 0600) // a second entry for the same id
	r, _ = check(fx.store, 100)
	if len(r.Problems) == 0 || r.Problems[0].Kind != "block_duplicate_entries" {
		t.Fatalf("duplicate entry not reported: %v", kinds(r))
	}
}

func TestR23cStorecheckMissingAndHashMismatch(t *testing.T) {
	fx := make_store(t)
	os.Remove(fx.paths[0])
	r, _ := check(fx.store, 100)
	want_one(t, r, "block_missing")

	fx = make_store(t)
	var other block.Block
	other.Major_Version, other.Height, other.Timestamp = 1, 1, 4242 // a different block under block 1's name
	other.Miner_TX.Version, other.Miner_TX.TransactionType = 1, transaction.PREMINE
	os.WriteFile(fx.paths[1], other.Serialize(), 0600)
	r, _ = check(fx.store, 100)
	want_one(t, r, "block_hash_mismatch")
}

func TestR23cStorecheckTxs(t *testing.T) {
	fx := make_store(t)
	os.Remove(fx.txp)
	r, _ := check(fx.store, 100)
	want_one(t, r, "tx_missing")

	fx = make_store(t)
	b, _ := os.ReadFile(fx.txp)
	os.WriteFile(fx.txp, b[:3], 0600)
	r, _ = check(fx.store, 100)
	want_one(t, r, "tx_torn")

	fx = make_store(t)
	var other transaction.Transaction
	other.Version, other.TransactionType, other.Value = 1, transaction.PREMINE, 6 // another tx under this txid
	os.WriteFile(fx.txp, other.Serialize(), 0600)
	r, _ = check(fx.store, 100)
	want_one(t, r, "tx_hash_mismatch")
}

func TestR23cStorecheckLastWindow(t *testing.T) {
	fx := make_store(t)
	b, _ := os.ReadFile(fx.paths[0])
	os.WriteFile(fx.paths[0], b[:5], 0600) // damage outside the window
	r, _ := check(fx.store, 2)
	if r.From != 1 || r.Checked != 2 || len(r.Problems) != 0 {
		t.Fatalf("window: %+v", r)
	}
}
