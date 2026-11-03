// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package emission

// Archive mode (Round 23b): audit any topoheight range of a datadir COPY offline, and keep a cumulative account of
// what the audit proved. A fastsynced node holds blocks and balance snapshots only from its bootstrap height on (ours:
// 7,498,540), so a range that reaches below it reports those heights as `unavailable`, never as audit errors; a full
// archive node (synced from genesis without --fastsync) can audit any height.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/graviton"
)

// ErrUnavailable marks a block, transaction or state the store does not hold (pruned, or never synced).
var ErrUnavailable = errors.New("not in this store")

// DirSource reads a datadir laid out like blockchain/storefs.go (bltx_store/xx/yy/<hash>.block_*_<version>_*,
// <hash>.tx) plus a graviton balance store. It opens block and transaction files read-only; graviton opens its store
// read-write, so Store must be a COPY of balances/ (an APFS clone), never a live datadir.
type DirSource struct {
	BLTX  string
	Store *graviton.Store // nil: State is unavailable (forensic reads need no state)
}

func (s *DirSource) dir(a, b byte) string {
	return filepath.Join(s.BLTX, fmt.Sprintf("%02x", a), fmt.Sprintf("%02x", b))
}

// BlockFile returns the newest file for block h (the name carries the state version: hex.block_x_version_y).
func (s *DirSource) BlockFile(h crypto.Hash) (name string, version uint64, err error) {
	d := s.dir(h[0], h[1])
	fd, err := os.Open(d)
	if err != nil {
		if os.IsNotExist(err) {
			return "", 0, ErrUnavailable
		}
		return "", 0, err
	}
	defer fd.Close()
	prefix := fmt.Sprintf("%x.block", h[:])
	for {
		names, e := fd.Readdirnames(1024)
		for _, n := range names {
			if !strings.HasPrefix(n, prefix) {
				continue
			}
			parts := strings.Split(n, "_")
			var v uint64
			if len(parts) == 4 {
				fmt.Sscan(parts[2], &v)
			}
			if name == "" || v > version {
				name, version = filepath.Join(d, n), v
			}
		}
		if e != nil {
			break
		}
	}
	if name == "" {
		return "", 0, ErrUnavailable
	}
	return name, version, nil
}

func (s *DirSource) Block(h crypto.Hash) (*block.Block, error) {
	n, _, err := s.BlockFile(h)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(n)
	if err != nil {
		return nil, err
	}
	var bl block.Block
	return &bl, bl.Deserialize(b)
}

// TxBytes returns the stored body of txid (storefs.go keeps one file per TXID, at either of two directories).
func (s *DirSource) TxBytes(h crypto.Hash) ([]byte, error) {
	for _, d := range []string{s.dir(h[0], h[1]), s.dir(h[16], h[17])} {
		b, err := os.ReadFile(filepath.Join(d, fmt.Sprintf("%x.tx", h[:])))
		if err == nil {
			return b, nil
		}
		if !os.IsNotExist(err) {
			return nil, err
		}
	}
	return nil, ErrUnavailable
}

func (s *DirSource) Tx(h crypto.Hash) (tx *transaction.Transaction, err error) {
	b, err := s.TxBytes(h)
	if err != nil {
		return nil, err
	}
	return DecodeTx(b)
}

// DecodeTx is Transaction.Deserialize with its panics turned into errors.
func DecodeTx(b []byte) (tx *transaction.Transaction, err error) {
	defer func() {
		if r := recover(); r != nil {
			tx, err = nil, fmt.Errorf("tx does not decode: %v", r)
		}
	}()
	tx = new(transaction.Transaction)
	if err = tx.Deserialize(b); err != nil {
		return nil, err
	}
	return tx, nil
}

func (s *DirSource) State(h crypto.Hash) (*graviton.Snapshot, error) {
	if s.Store == nil {
		return nil, ErrUnavailable
	}
	_, v, err := s.BlockFile(h)
	if err != nil {
		return nil, err
	}
	if v == 0 {
		return nil, ErrUnavailable
	}
	return s.Store.LoadSnapshot(v)
}

// TopoMap reads topo.map: 48-byte records of blid[32], state version (LE u64), height (LE i64).
type TopoMap struct {
	f *os.File
	n int64
}

func OpenTopo(path string) (*TopoMap, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &TopoMap{f: f, n: st.Size() / 48}, nil
}

func (t *TopoMap) Close() error { return t.f.Close() }
func (t *TopoMap) Len() int64   { return t.n }

// Record returns topoheight i. An all-zero blid is an unwritten (preallocated) slot: ErrUnavailable.
func (t *TopoMap) Record(i int64) (blid crypto.Hash, version uint64, height int64, err error) {
	if i < 0 || i >= t.n {
		return blid, 0, 0, io.EOF
	}
	var b [48]byte
	if _, err = t.f.ReadAt(b[:], i*48); err != nil {
		return
	}
	copy(blid[:], b[:32])
	if blid.IsZero() {
		return blid, 0, 0, ErrUnavailable
	}
	return blid, binary.LittleEndian.Uint64(b[32:]), int64(binary.LittleEndian.Uint64(b[40:])), nil
}

// LastWritten is the highest topoheight with a record (unwritten slots at the end are skipped).
func (t *TopoMap) LastWritten() int64 {
	for i := t.n - 1; i >= 0; i-- {
		if _, _, _, err := t.Record(i); err == nil {
			return i
		}
	}
	return -1
}

// FirstWritten is the lowest topoheight with a record. A fastsynced store leaves every slot below its bootstrap
// height unwritten (zero blid), so the written records form one contiguous run [FirstWritten, LastWritten].
func (t *TopoMap) FirstWritten() int64 {
	last := t.LastWritten()
	lo, hi := int64(0), last
	for lo < hi {
		m := (lo + hi) / 2
		if _, _, _, err := t.Record(m); err == nil {
			hi = m
		} else {
			lo = m + 1
		}
	}
	if last < 0 {
		return -1
	}
	return lo
}

// FindHeight returns the first written topoheight whose block height is >= h (heights never decrease along the
// topo order); LastWritten()+1 when there is none.
func (t *TopoMap) FindHeight(h int64) int64 {
	lo, hi := t.FirstWritten(), t.LastWritten()+1
	if lo < 0 {
		return 0
	}
	for lo < hi {
		m := (lo + hi) / 2
		_, _, mh, err := t.Record(m)
		if err == nil && mh < h {
			lo = m + 1
		} else {
			hi = m
		}
	}
	return lo
}

// Cumulative is the running account of a contiguous audited height range: what the audit proved about emission.
//
// Gross vs net, honestly: Issued is the NEW plaintext value the coinbases provably created (Paid - Fees: fees only
// move value from senders to miners). Burns are plaintext value provably destroyed (payload BurnValue). Value
// destroyed by an SC that panicked part-way (sc_unexplained) and value created inside encrypted transfer amounts
// (the range-proof soundness class) are not measurable by any node, so the true supply is bounded by neither
// Issued nor Issued - Burns: these are the plaintext-visible parts only.
type Cumulative struct {
	From            uint64 `json:"from"`
	To              uint64 `json:"to"`
	Blocks          uint64 `json:"blocks"`
	Verified        uint64 `json:"verified_heights"`   // coinbase proven to land exactly
	Unverified      uint64 `json:"unverified_heights"` // sc_unexplained, errors, protocol-skipped heights
	Observed        uint64 `json:"observed_emission"`  // formula base reward of the verified heights
	Excused         uint64 `json:"excused_emission"`   // formula base reward of the unverified heights
	Formula         uint64 `json:"formula_emission"`   // FormulaSupply(To) - FormulaSupply(From-1)
	Issued          uint64 `json:"issued"`             // sum(Paid - Fees) over verified heights
	Fees            uint64 `json:"fees"`
	SCDeposits      uint64 `json:"sc_deposits"`
	SCPayouts       uint64 `json:"sc_payouts"`
	Burns           uint64 `json:"burns"`
	Alerts          uint64 `json:"alerts"`
	Gaps            uint64 `json:"gap_heights"`      // heights missing inside the range
	RepeatedHeights uint64 `json:"repeated_heights"` // a height audited twice (not expected on the main chain)
	Consistent      bool   `json:"emission_consistent"`
	// Issued == Observed: the coinbases created exactly the formula reward (mainnet since height 399000: 10
	// miniblocks, one final). The simulator's single non-final miniblock is credited on top of the integrator share,
	// so a simulator chain issues 2x base + fees per block and this is false there.
	IssuedMatchesFormula bool `json:"issued_matches_formula"`
}

func sat(a, b uint64) uint64 {
	if a+b < a {
		return ^uint64(0)
	}
	return a + b
}

// Add accounts one audited block (in topo order). err != nil or a non-OK verdict makes the height unverified.
func (c *Cumulative) Add(r Report, err error) {
	if r.Height == 0 && err != nil {
		return // could not even read the block: the caller counts it
	}
	if c.Blocks == 0 {
		c.From, c.To = r.Height, r.Height
	} else if r.Height <= c.To {
		c.RepeatedHeights++
	} else {
		c.Gaps += r.Height - c.To - 1
		c.To = r.Height
	}
	c.Blocks++
	formula := FormulaSupply(r.Height) - FormulaSupply(r.Height-1)
	switch {
	case err == nil && (r.Verdict == VerdictOK || r.Verdict == VerdictOKSC):
		c.Verified++
		c.Observed = sat(c.Observed, r.BaseReward)
		if r.Paid >= r.Fees {
			c.Issued = sat(c.Issued, r.Paid-r.Fees)
		}
	default:
		c.Unverified++
		c.Excused = sat(c.Excused, formula)
	}
	if err == nil {
		c.Fees = sat(c.Fees, r.Fees)
		c.SCDeposits = sat(c.SCDeposits, r.SCDeposits)
		c.SCPayouts = sat(c.SCPayouts, r.SCPayout)
		c.Burns = sat(c.Burns, r.Burns)
	}
	if r.Verdict == VerdictAlert {
		c.Alerts++
	}
	c.Formula = FormulaSupply(c.To) - FormulaSupply(c.From-1)
	c.IssuedMatchesFormula = c.Issued == c.Observed
	c.Consistent = c.Gaps == 0 && c.RepeatedHeights == 0 && c.Alerts == 0 &&
		c.Verified+c.Unverified == c.To-c.From+1 && c.Observed+c.Excused == c.Formula
}

// TopoSource maps a topoheight to its block id.
type TopoSource interface {
	Record(i int64) (blid crypto.Hash, version uint64, height int64, err error)
}

type ArchiveSummary struct {
	FromTopo    int64            `json:"from_topo"`
	ToTopo      int64            `json:"to_topo"`
	Requested   int64            `json:"requested"`
	Audited     int64            `json:"audited"`
	Unavailable int64            `json:"unavailable"` // pruned / never synced: no block or no state
	Errors      int64            `json:"errors"`
	Verdicts    map[string]int64 `json:"verdicts"`
	Cumulative  Cumulative       `json:"cumulative"`
	FirstError  string           `json:"first_error,omitempty"`
	Flagged     []Report         `json:"flagged,omitempty"` // ALERT / error / sc_unexplained reports (capped)
	MicrosTotal int64            `json:"micros_total"`
	Segments    []Cumulative     `json:"segments,omitempty"` // one per contiguous available range
	Available   [][2]int64       `json:"available_topo,omitempty"`
}

const archiveFlaggedKept = 64

// ArchiveRange audits topoheights from..to. Missing blocks or states are `unavailable` (a pruned range is not an
// audit failure) and close the current segment; each callback (may be nil) sees every report in order.
func ArchiveRange(src Source, topo TopoSource, from, to int64, p Params, each func(t int64, r Report, err error)) ArchiveSummary {
	s := ArchiveSummary{FromTopo: from, ToTopo: to, Verdicts: map[string]int64{}}
	var seg Cumulative
	var segFrom int64 = -1
	closeSeg := func(last int64) {
		if seg.Blocks > 0 {
			s.Segments = append(s.Segments, seg)
			s.Available = append(s.Available, [2]int64{segFrom, last})
		}
		seg, segFrom = Cumulative{}, -1
	}
	for t := from; t <= to; t++ {
		s.Requested++
		blid, _, _, err := topo.Record(t)
		if err != nil {
			s.Unavailable++
			closeSeg(t - 1)
			continue
		}
		r, err := AuditBlock(src, blid, p)
		if each != nil {
			each(t, r, err)
		}
		if err != nil && errors.Is(err, ErrUnavailable) {
			s.Unavailable++
			closeSeg(t - 1)
			continue
		}
		s.Audited++
		s.MicrosTotal += r.Micros
		if err != nil {
			s.Errors++
			if s.FirstError == "" {
				s.FirstError = fmt.Sprintf("topo %d: %v", t, err)
			}
		}
		s.Verdicts[r.Verdict]++
		if (err != nil || r.Verdict == VerdictAlert || r.Verdict == VerdictSCUnexplained) && len(s.Flagged) < archiveFlaggedKept {
			if err != nil {
				r.Notes = append(r.Notes, err.Error())
			}
			s.Flagged = append(s.Flagged, r)
		}
		if segFrom < 0 {
			segFrom = t
		}
		seg.Add(r, err)
		s.Cumulative.Add(r, err)
	}
	closeSeg(to)
	return s
}
