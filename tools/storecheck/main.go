// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

// Command storecheck is a READ-ONLY integrity scan of a derod block/tx store (r23c chainperf).
//
// Why: blockchain/storefs.go writes every block and tx with ioutil.WriteFile straight into its final name (no temp
// file, no fsync, no rename), and the block's difficulty, snapshot version and height live in that NAME. A crash or
// power cut during a write can leave a complete-looking name over an empty or partial body. derod then fails on
// the next read of that block (Load_BL_FROM_ID errors -> Load_Block_Timestamp panics) far from the cause. The
// write path is consensus code (blockchain/ is under harness/consensus_guard.py), so it is not changed here; this
// tool finds the damage instead, without writing anything (every file is opened O_RDONLY).
//
// For each of the last --last topo records it checks: the record's block has exactly one store entry whose name
// parses; the body deserializes and hashes to its name; name height == body height == record height; the entry's
// snapshot version == the record's State_Version; every tx the block lists has a body that deserializes and hashes
// to its txid.
//
//	go run ./tools/storecheck --data-dir=<COPY of the datadir parent> [--last 2000] [--json]
//	exit 0 = clean, 3 = problems found, 2 = cannot read the store
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/transaction"
)

const toporecord_size = 48 // blockchain/storetopo.go TOPORECORD_SIZE: 32 id + 8 state version + 8 height

type problem struct {
	Kind string `json:"kind"`
	Topo int64  `json:"topo"`
	ID   string `json:"id"`
	Info string `json:"info,omitempty"`
}

type report struct {
	Store    string    `json:"store"`
	Records  int64     `json:"topo_records"`
	From     int64     `json:"from_topo"`
	Checked  int       `json:"blocks_checked"`
	TxsSeen  int       `json:"txs_checked"`
	Problems []problem `json:"problems"`
}

type record struct {
	id      [32]byte
	version uint64
	height  int64
}

func read_record(f *os.File, i int64) (r record, err error) {
	var b [toporecord_size]byte
	if _, err = f.ReadAt(b[:], i*toporecord_size); err != nil {
		return
	}
	copy(r.id[:], b[:32])
	r.version = binary.LittleEndian.Uint64(b[32:])
	r.height = int64(binary.LittleEndian.Uint64(b[40:]))
	return
}

func (r record) clean() bool { return r.version == 0 && r.id == [32]byte{} }

// block_entries lists bltx_store/<h0>/<h1>/<hex>.block_<difficulty>_<version>_<height> names (storefs.getpath)
func block_entries(store string, id [32]byte) ([]string, error) {
	dir := filepath.Join(store, "bltx_store", fmt.Sprintf("%02x", id[0]), fmt.Sprintf("%02x", id[1]))
	d, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	prefix := fmt.Sprintf("%x.block", id[:])
	var out []string
	for {
		names, err := d.Readdirnames(1024)
		for _, n := range names {
			if strings.HasPrefix(n, prefix) {
				out = append(out, filepath.Join(dir, n))
			}
		}
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
	}
}

// parse_name returns (difficulty, version, height) from a block entry name; storefs panics on anything else
func parse_name(path string) (diff string, version uint64, height uint64, err error) {
	parts := strings.Split(filepath.Base(path), "_")
	if len(parts) != 4 {
		return "", 0, 0, fmt.Errorf("name has %d parts, want 4", len(parts))
	}
	if version, err = strconv.ParseUint(parts[2], 10, 64); err != nil {
		return
	}
	if height, err = strconv.ParseUint(parts[3], 10, 64); err != nil {
		return
	}
	return parts[1], version, height, nil
}

func read_tx(store string, h [32]byte) ([]byte, error) {
	legacy := filepath.Join(store, "bltx_store", fmt.Sprintf("%02x", h[0]), fmt.Sprintf("%02x", h[1]), fmt.Sprintf("%x.tx", h[:]))
	if b, err := os.ReadFile(legacy); err == nil {
		return b, nil
	}
	return os.ReadFile(filepath.Join(store, "bltx_store", fmt.Sprintf("%02x", h[16]), fmt.Sprintf("%02x", h[17]), fmt.Sprintf("%x.tx", h[:])))
}

// check scans the newest `last` non-clean topo records of the store directory (the one holding topo.map)
func check(store string, last int64) (rep report, err error) {
	rep.Store = store
	f, err := os.Open(filepath.Join(store, "topo.map")) // O_RDONLY
	if err != nil {
		return rep, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return rep, err
	}
	n := st.Size() / toporecord_size
	for n > 0 { // the same trailing-clean rule as storetopofs.Count
		r, err := read_record(f, n-1)
		if err != nil {
			return rep, err
		}
		if !r.clean() {
			break
		}
		n--
	}
	rep.Records = n
	from := n - last
	if from < 0 {
		from = 0
	}
	rep.From = from
	add := func(kind string, topo int64, id []byte, info string) {
		rep.Problems = append(rep.Problems, problem{Kind: kind, Topo: topo, ID: hex.EncodeToString(id), Info: info})
	}
	for topo := from; topo < n; topo++ {
		r, err := read_record(f, topo)
		if err != nil {
			return rep, err
		}
		if r.clean() {
			continue // pruned or not yet written: nothing to check
		}
		rep.Checked++
		entries, err := block_entries(store, r.id)
		if err != nil || len(entries) == 0 {
			add("block_missing", topo, r.id[:], fmt.Sprint(err))
			continue
		}
		if len(entries) > 1 {
			add("block_duplicate_entries", topo, r.id[:], strconv.Itoa(len(entries)))
		}
		_, version, height, err := parse_name(entries[0])
		if err != nil {
			add("block_bad_name", topo, r.id[:], err.Error())
			continue
		}
		body, err := os.ReadFile(entries[0])
		if err != nil {
			add("block_unreadable", topo, r.id[:], err.Error())
			continue
		}
		var bl block.Block
		if err := bl.Deserialize(body); err != nil {
			add("block_torn", topo, r.id[:], fmt.Sprintf("%d bytes: %s", len(body), err))
			continue
		}
		if h := bl.GetHash(); h != r.id {
			add("block_hash_mismatch", topo, r.id[:], h.String())
			continue
		}
		if height != bl.Height || int64(bl.Height) != r.height {
			add("height_mismatch", topo, r.id[:], fmt.Sprintf("name %d body %d record %d", height, bl.Height, r.height))
		}
		if version != r.version {
			add("version_mismatch", topo, r.id[:], fmt.Sprintf("entry %d record %d", version, r.version))
		}
		for _, txid := range bl.Tx_hashes {
			rep.TxsSeen++
			raw, err := read_tx(store, txid)
			if err != nil {
				add("tx_missing", topo, txid[:], err.Error())
				continue
			}
			var tx transaction.Transaction
			if err := tx.Deserialize(raw); err != nil {
				add("tx_torn", topo, txid[:], fmt.Sprintf("%d bytes: %s", len(raw), err))
				continue
			}
			if h := tx.GetHash(); h != txid {
				add("tx_hash_mismatch", topo, txid[:], h.String())
			}
		}
	}
	return rep, nil
}

func main() {
	dir := flag.String("data-dir", "", "datadir parent (the one derod's --data-dir names); use a COPY of a live node's")
	net := flag.String("network", "mainnet", "store subdirectory")
	last := flag.Int64("last", 2000, "how many of the newest topo records to check")
	asjson := flag.Bool("json", false, "print the full JSON report")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "storecheck: --data-dir is required")
		os.Exit(2)
	}
	rep, err := check(filepath.Join(*dir, *net), *last)
	if err != nil {
		fmt.Fprintln(os.Stderr, "storecheck:", err)
		os.Exit(2)
	}
	if *asjson {
		b, _ := json.MarshalIndent(rep, "", " ")
		fmt.Println(string(b))
	} else {
		fmt.Printf("storecheck: %d topo records, checked %d blocks (from topo %d) and %d txs: %d problem(s)\n",
			rep.Records, rep.Checked, rep.From, rep.TxsSeen, len(rep.Problems))
		for _, p := range rep.Problems {
			fmt.Printf("  %s topo=%d id=%s %s\n", p.Kind, p.Topo, p.ID, p.Info)
		}
	}
	if len(rep.Problems) > 0 {
		os.Exit(3)
	}
}
