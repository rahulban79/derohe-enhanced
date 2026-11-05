package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const topoRecordSize = 48 // blockchain/storetopo.go TOPORECORD_SIZE: blid 32 + state version 8 + height 8

type archiveSummary struct {
	Kind         string `json:"kind"`
	Class        string `json:"class"`
	Archive      string `json:"archive"`
	SliceFirst   int64  `json:"slice_first_topo"`
	SliceRecords int64  `json:"slice_records"`
	Top          int64  `json:"top_topo"`
	TopBLID      string `json:"top_blid"`
	TopVersion   uint64 `json:"top_state_version"`
	TopRoot      string `json:"top_root"`
	ChainTop     int64  `json:"chain_topoheight_after_open"`
	Error        string `json:"error,omitempty"`
}

// seedArchive builds a replay datadir from a COPY of our own replaywall archive (rft §0.8.4: the archive is read
// only through an APFS clone or a copy, never in place). The balances and bltx_store directories are APFS-cloned
// (cp -c: copy-on-write, the copy is never written) into the new datadir; topo.map is rebuilt from the archive's
// topo slice: records 0..first-1 as a fastsync prefill (zero id, the first committed version), then the slice's
// committed records first..top. The record at top must be the block we expect there.
func seedArchive(archiveDir, topoSlice string, sliceFirst, top int64, expect, datadir string, sum *archiveSummary) error {
	slice, err := os.ReadFile(topoSlice)
	if err != nil {
		return err
	}
	if len(slice)%topoRecordSize != 0 {
		return fmt.Errorf("topo slice is not a whole number of records")
	}
	n := int64(len(slice) / topoRecordSize)
	sum.SliceFirst, sum.SliceRecords, sum.Top = sliceFirst, n, top
	if top < sliceFirst || top >= sliceFirst+n {
		return fmt.Errorf("top %d outside the slice %d..%d", top, sliceFirst, sliceFirst+n-1)
	}
	rec := func(t int64) []byte { o := (t - sliceFirst) * topoRecordSize; return slice[o : o+topoRecordSize] }
	topRec := rec(top)
	sum.TopBLID = hex.EncodeToString(topRec[:32])
	if sum.TopBLID != expect {
		return fmt.Errorf("archive record at %d is not the expected block", top)
	}
	var zero [32]byte
	for t := sliceFirst; t <= top; t++ {
		if string(rec(t)[:32]) == string(zero[:]) {
			return fmt.Errorf("archive record %d is clean (no block): the committed range is shorter", t)
		}
	}
	mainnet := filepath.Join(datadir, "mainnet")
	if err := os.MkdirAll(mainnet, 0700); err != nil {
		return err
	}
	for _, p := range [][2]string{{"replaywall_balances", "balances"}, {"replaywall_bltx_store", "bltx_store"}} {
		if out, err := exec.Command("cp", "-c", "-R", filepath.Join(archiveDir, p[0]), filepath.Join(mainnet, p[1])).CombinedOutput(); err != nil {
			return fmt.Errorf("clone %s: %v %s", p[0], err, out)
		}
	}
	f, err := os.OpenFile(filepath.Join(mainnet, "topo.map"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	prefill := make([]byte, topoRecordSize)
	copy(prefill[32:40], rec(sliceFirst)[32:40]) // the first committed state version; height 0
	const batch = 65536
	buf := make([]byte, 0, batch*topoRecordSize)
	for i := 0; i < batch; i++ {
		buf = append(buf, prefill...)
	}
	for off := int64(0); off < sliceFirst; off += batch {
		k := sliceFirst - off
		if k > batch {
			k = batch
		}
		if _, err := f.WriteAt(buf[:k*topoRecordSize], off*topoRecordSize); err != nil {
			return err
		}
	}
	if _, err := f.WriteAt(slice[:(top-sliceFirst+1)*topoRecordSize], sliceFirst*topoRecordSize); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	sum.TopVersion = binary.LittleEndian.Uint64(topRec[32:40])
	return os.WriteFile(filepath.Join(datadir, markerName), []byte("seeded by tools/forensics/a2 seed-archive from a copy of the replaywall archive\n"), 0600)
}
