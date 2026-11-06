// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package emission

// r27 (tools-kats; R27 Part A sweep): the -archive reader behind the B36 24 h read (DirSource: dir, BlockFile, Block,
// TxBytes, Tx, State; TopoMap.Len; CountSeries) was 0.0% covered by this package's tests. These run it on a FORGED
// datadir layout (blockchain/storefs.go shapes) in a temp dir: no datadir, no network.

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/graviton"
)

func r27Hash(b0, b1, b16, b17 byte) (h crypto.Hash) {
	for i := range h {
		h[i] = byte(i + 1)
	}
	h[0], h[1], h[16], h[17] = b0, b1, b16, b17
	return
}

func r27Write(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// BlockFile picks the file with the HIGHEST state version among <hash>.block_<x>_<version>_<y>, ignores other hashes'
// files in the same directory, and an absent directory or file is ErrUnavailable (pruned), not an I/O error.
func TestR27DirSourceBlockFileNewestVersion(t *testing.T) {
	d := t.TempDir()
	s := &DirSource{BLTX: d}
	h := r27Hash(0xab, 0xcd, 0x01, 0x02)
	other := r27Hash(0xab, 0xcd, 0x09, 0x09)
	other[5] = 0xff
	dir := filepath.Join(d, "ab", "cd")
	for _, n := range []string{h.String() + ".block_x_3_y", h.String() + ".block_x_11_y", h.String() + ".block_x_7_y",
		other.String() + ".block_x_99_y"} {
		r27Write(t, filepath.Join(dir, n), []byte("x"))
	}
	name, v, err := s.BlockFile(h)
	if err != nil || v != 11 || filepath.Base(name) != h.String()+".block_x_11_y" {
		t.Fatalf("BlockFile = %q v%d %v, want the version-11 file", name, v, err)
	}
	if _, _, err := s.BlockFile(r27Hash(0x00, 0x00, 0, 0)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("absent directory: %v, want ErrUnavailable", err)
	}
	lone := r27Hash(0xab, 0xcd, 0x05, 0x05)
	lone[9] = 0xee
	if _, _, err := s.BlockFile(lone); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("directory without the block: %v, want ErrUnavailable", err)
	}
}

// Block deserialises the newest file; State is unavailable without a store and for a version-0 file, and otherwise
// loads the snapshot the file name records.
func TestR27DirSourceBlockAndState(t *testing.T) {
	d := t.TempDir()
	h := r27Hash(0x10, 0x20, 0, 0)
	bl := block.Block{Major_Version: 1, Height: 4242, Timestamp: 1700000000123}
	bl.Miner_TX.Version, bl.Miner_TX.TransactionType = 1, transaction.COINBASE
	r27Write(t, filepath.Join(d, "10", "20", h.String()+".block_x_1_y"), bl.Serialize())
	s := &DirSource{BLTX: d}
	got, err := s.Block(h)
	if err != nil || got.Height != 4242 || got.Timestamp != bl.Timestamp {
		t.Fatalf("Block = %+v %v, want height 4242", got, err)
	}
	if _, err := s.State(h); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("State without a store: %v, want ErrUnavailable", err)
	}
	store, err := graviton.NewMemStore()
	if err != nil {
		t.Fatal(err)
	}
	ss, _ := store.LoadSnapshot(0)
	tr, _ := ss.GetTree("r27")
	tr.Put([]byte("k"), []byte("v"))
	ver, err := graviton.Commit(tr)
	if err != nil || ver != 1 {
		t.Fatalf("commit version %d %v", ver, err)
	}
	s.Store = store
	snap, err := s.State(h)
	if err != nil || snap.GetVersion() != 1 {
		t.Fatalf("State = %v, want the version-1 snapshot", err)
	}
	h0 := r27Hash(0x10, 0x21, 0, 0)
	r27Write(t, filepath.Join(d, "10", "21", h0.String()+".block_x_0_y"), bl.Serialize())
	if _, err := s.State(h0); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("State of a version-0 block: %v, want ErrUnavailable", err)
	}
	r27Write(t, filepath.Join(d, "10", "22", r27Hash(0x10, 0x22, 0, 0).String()+".block_x_1_y"), []byte{0xff})
	if _, err := s.Block(r27Hash(0x10, 0x22, 0, 0)); err == nil {
		t.Fatal("a one-byte block file deserialised without an error")
	}
}

// TxBytes finds a body at either directory storefs.go uses (h[0]/h[1] or h[16]/h[17]); Tx turns an undecodable body
// into an error (never a panic); an absent body is ErrUnavailable.
func TestR27DirSourceTxBothDirsAndErrors(t *testing.T) {
	d := t.TempDir()
	s := &DirSource{BLTX: d}
	a := r27Hash(0x01, 0x02, 0x03, 0x04)
	b := r27Hash(0x05, 0x06, 0x07, 0x08)
	r27Write(t, filepath.Join(d, "01", "02", a.String()+".tx"), []byte("first"))
	r27Write(t, filepath.Join(d, "07", "08", b.String()+".tx"), []byte("second"))
	if got, err := s.TxBytes(a); err != nil || string(got) != "first" {
		t.Fatalf("TxBytes(a) = %q %v", got, err)
	}
	if got, err := s.TxBytes(b); err != nil || string(got) != "second" {
		t.Fatalf("TxBytes(b) via h[16]/h[17] = %q %v", got, err)
	}
	if _, err := s.TxBytes(r27Hash(9, 9, 9, 9)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("absent tx: %v, want ErrUnavailable", err)
	}
	if _, err := s.Tx(a); err == nil {
		t.Fatal("an undecodable tx body returned no error")
	}
	if _, err := s.Tx(r27Hash(9, 9, 9, 9)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Tx of an absent body: %v, want ErrUnavailable", err)
	}
}

func r27Topo(t *testing.T, recs [][3]uint64, zeroFirst int) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "topo.map")
	var buf []byte
	for i := 0; i < zeroFirst; i++ {
		buf = append(buf, make([]byte, 48)...)
	}
	for _, r := range recs {
		var b [48]byte
		b[0], b[1] = byte(r[0]), byte(r[0]>>8)
		b[31] = 0x5a
		binary.LittleEndian.PutUint64(b[32:], r[1])
		binary.LittleEndian.PutUint64(b[40:], r[2])
		buf = append(buf, b[:]...)
	}
	buf = append(buf, make([]byte, 48)...) // a preallocated slot at the end
	r27Write(t, p, buf)
	return p
}

// A fastsynced topo.map: unwritten slots below the bootstrap and one at the end. Len counts every slot; FirstWritten /
// LastWritten bound the written run; FindHeight is the first topo at or above a height; Record past the end is EOF.
func TestR27TopoMapFastsyncShape(t *testing.T) {
	tm, err := OpenTopo(r27Topo(t, [][3]uint64{{1, 10, 100}, {2, 11, 101}, {3, 12, 101}, {4, 13, 103}}, 5))
	if err != nil {
		t.Fatal(err)
	}
	defer tm.Close()
	if tm.Len() != 10 || tm.FirstWritten() != 5 || tm.LastWritten() != 8 {
		t.Fatalf("Len %d first %d last %d, want 10/5/8", tm.Len(), tm.FirstWritten(), tm.LastWritten())
	}
	if tm.FindHeight(101) != 6 || tm.FindHeight(102) != 8 || tm.FindHeight(50) != 5 || tm.FindHeight(999) != 9 {
		t.Fatalf("FindHeight 101->%d 102->%d 50->%d 999->%d, want 6/8/5/9", tm.FindHeight(101), tm.FindHeight(102),
			tm.FindHeight(50), tm.FindHeight(999))
	}
	if _, v, h, err := tm.Record(7); err != nil || v != 12 || h != 101 {
		t.Fatalf("Record(7) = v%d h%d %v", v, h, err)
	}
	if _, _, _, err := tm.Record(2); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("an unwritten slot: %v, want ErrUnavailable", err)
	}
	if _, _, _, err := tm.Record(10); err != io.EOF {
		t.Fatalf("past the end: %v, want io.EOF", err)
	}
}

// CountSeries counts intact and torn lines over the whole file (blank lines skipped); a missing file is an error.
func TestR27CountSeriesIntactAndTorn(t *testing.T) {
	p := filepath.Join(t.TempDir(), "series.jsonl")
	for i := 0; i < 3; i++ {
		if err := AppendSeries(p, SeriesRecord{Kind: SeriesCheckpoint, Height: uint64(100 + i), SegmentTo: uint64(100 + i)}); err != nil {
			t.Fatal(err)
		}
	}
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString("{\"kind\":\"checkpoint\"} deadbeef\n\n{\"torn")
	f.Close()
	intact, bad, err := CountSeries(p)
	if err != nil || intact != 3 || bad != 2 {
		t.Fatalf("CountSeries = %d intact %d bad %v, want 3/2", intact, bad, err)
	}
	if _, _, err := CountSeries(p + ".absent"); err == nil {
		t.Fatal("a missing series file counted without an error")
	}
}
