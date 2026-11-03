// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package emission

// The audited-emission series (Round 23b): a small append-only file of checkpoints, so that a third party can
// compare what this node's auditor proved with the formula supply over time.
//
// One record per line: <json> <crc32-ieee of the json, 8 hex>\n. Each record is appended with one write(2) on an
// O_APPEND descriptor and fsynced. A crash can leave at most a torn last line; the reader drops any line whose
// checksum does not match, and the next append first terminates a torn line, so a torn record never corrupts the
// one after it. The file never changes in place. It is capped at SeriesMaxBytes (an append past it is refused).

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"strconv"
)

const SeriesMaxBytes = 64 << 20 // ~150k records of ~450 bytes: at ~48 checkpoints a day, about 8 years

const (
	SeriesCheckpoint = "checkpoint" // the emission segment as it stood when its top crossed a multiple of the interval
	SeriesNotable    = "notable"    // a single plaintext flow over the notable threshold (informational)
)

type SeriesRecord struct {
	Kind          string `json:"kind"`
	Time          int64  `json:"time"`      // unix seconds
	SegStart      int64  `json:"seg_start"` // unix seconds the segment began (auditor start, or after a skip)
	Topo          int64  `json:"topo"`
	Height        uint64 `json:"height"`
	BLID          string `json:"blid,omitempty"`
	SegmentFrom   uint64 `json:"segment_from"`
	SegmentTo     uint64 `json:"segment_to"`
	Verified      uint64 `json:"verified_heights"`
	Unverified    uint64 `json:"unverified_heights"`
	Observed      uint64 `json:"observed_emission"`
	Issued        uint64 `json:"issued_emission"` // sum of Paid - Fees over the verified heights (proven issuance)
	Formula       uint64 `json:"formula_emission"`
	Consistent    bool   `json:"emission_consistent"`
	FormulaSupply uint64 `json:"formula_supply"`
	Alerts        uint64 `json:"alerts"`
	Fees          uint64 `json:"fees"`
	SCDeposits    uint64 `json:"sc_deposits"`
	SCPayouts     uint64 `json:"sc_payouts"`
	Burns         uint64 `json:"burns"`
	Flow          uint64 `json:"flow,omitempty"` // notable: the block's largest single plaintext flow
}

// EncodeSeriesLine renders one record with its checksum and the line end.
func EncodeSeriesLine(r SeriesRecord) []byte {
	j, _ := json.Marshal(r)
	return []byte(fmt.Sprintf("%s %08x\n", j, crc32.ChecksumIEEE(j)))
}

// ParseSeriesLine checks the checksum and decodes one line (without its line end).
func ParseSeriesLine(l []byte) (r SeriesRecord, ok bool) {
	i := bytes.LastIndexByte(l, ' ')
	if i < 0 || len(l)-i-1 != 8 {
		return r, false
	}
	want, err := strconv.ParseUint(string(l[i+1:]), 16, 32)
	if err != nil || uint32(want) != crc32.ChecksumIEEE(l[:i]) {
		return r, false
	}
	if json.Unmarshal(l[:i], &r) != nil {
		return r, false
	}
	return r, true
}

// ParseSeries reads every intact record; bad counts the lines dropped (torn or corrupted).
func ParseSeries(rd io.Reader) (out []SeriesRecord, bad int, err error) {
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := sc.Bytes()
		if len(l) == 0 {
			continue
		}
		if r, ok := ParseSeriesLine(l); ok {
			out = append(out, r)
		} else {
			bad++
		}
	}
	return out, bad, sc.Err()
}

// CountSeries streams the whole file once and counts its intact and dropped lines (no records kept).
func CountSeries(path string) (intact, bad int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := sc.Bytes()
		if len(l) == 0 {
			continue
		}
		if _, ok := ParseSeriesLine(l); ok {
			intact++
		} else {
			bad++
		}
	}
	return intact, bad, sc.Err()
}

// ReadSeriesTail parses the last maxBytes of the file (the first, partial line of the window is skipped).
func ReadSeriesTail(path string, maxBytes int64) (out []SeriesRecord, bad int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	off := int64(0)
	if st.Size() > maxBytes {
		off = st.Size() - maxBytes
	}
	b := make([]byte, st.Size()-off)
	if _, err = f.ReadAt(b, off); err != nil && err != io.EOF {
		return nil, 0, err
	}
	if off > 0 {
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		} else {
			b = nil
		}
	}
	return ParseSeries(bytes.NewReader(b))
}

// AppendSeries appends one record crash-safely (see the package comment above).
func AppendSeries(path string, r SeriesRecord) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	line := EncodeSeriesLine(r)
	if st.Size()+int64(len(line))+1 > SeriesMaxBytes {
		return fmt.Errorf("emission series %s is full (%d bytes)", path, st.Size())
	}
	if st.Size() > 0 {
		var last [1]byte
		if _, err := f.ReadAt(last[:], st.Size()-1); err != nil {
			return err
		}
		if last[0] != '\n' { // a torn record from a crash: end it, so it cannot swallow this one
			line = append([]byte{'\n'}, line...)
		}
	}
	if _, err = f.Write(line); err != nil {
		return err
	}
	return f.Sync()
}
