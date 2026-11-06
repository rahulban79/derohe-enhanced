// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package rpc

// DERO.GetEmissionAudit and the per-block emission auditor (Round 23, glue/emission).
//
// Every block that takes a topological position is audited once, shortly after it arrives: the change it made to
// the balance tree must be exactly its published transfer deltas plus the formula coinbase plus registrations plus
// plaintext SC payouts (glue/emission package doc). Exact violations are logged at ERROR ("EMISSION AUDIT ALERT"),
// counted (dero_emission_audit_alerts_total) and kept for the RPC. The auditor only reads committed snapshots; it
// cannot change what this node accepts, and a failure to audit is a counted error, never a node fault.
//
// Cost: one graviton diff of the balance tree and a few point decompressions per changed account (measured offline
// in the Round 23 record). DERO_EMISSION_AUDIT=0 turns it off. While the node is far behind (more than
// EMISSION_CATCHUP_MAX topoheights) the auditor skips ahead instead of re-executing the backlog, so a resync never
// queues work; the skipped range is counted in `gaps` and resets the emission segment.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/glue/emission"
	"github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/graviton"
)

const EMISSION_BACKFILL = 16     // topoheights audited at start (and after a skip)
const EMISSION_REORG_WINDOW = 8  // recent topoheights re-read each pass: a replaced block is audited again
const EMISSION_CATCHUP_MAX = 256 // further behind than this: skip ahead, do not re-audit the backlog
const EMISSION_TICK = 3 * time.Second
const EMISSION_RECENT = 16
const EMISSION_ALERTS_KEPT = 64
const EMISSION_NOTABLE_PPM = 100 // a single plaintext flow >= 100 ppm of formula supply is listed as notable
const EMISSION_ERROR_RETRIES = 3 // an errored topoheight is audited again up to this many times (r23 merge)

// r23c: audited topoheights remembered below the tip (was 4*EMISSION_REORG_WINDOW = 32). A pass after a rewind of
// depth d re-reads from d+EMISSION_REORG_WINDOW-1 below the old tip, so with 32 a console pop of 26 or more blocks
// re-counted the heights it re-read. ~150 bytes an entry: 4096 entries (~20 h of chain) is ~0.6 MB.
const EMISSION_WINDOW_KEEP = 4096

// r23b: the audited-emission series (glue/emission/series.go) is appended to <datadir>/emission_series.jsonl: one
// checkpoint each time the segment top crosses a multiple of EMISSION_SERIES_EVERY heights (~48 a day, ~450 bytes
// each) plus one record per notable plaintext flow. DERO_EMISSION_SERIES=0 turns it off.
const EMISSION_SERIES_EVERY = 100
const EMISSION_SERIES_FILE = "emission_series.jsonl"
const EMISSION_SERIES_SHOWN = 4
const EMISSION_SERIES_TAIL = 1 << 20 // bytes read back at start

// chain_emission_source reads blocks, transactions and committed states from the running chain.
type chain_emission_source struct{}

func (chain_emission_source) Block(h crypto.Hash) (*block.Block, error) {
	return chain.Load_BL_FROM_ID(h)
}
func (chain_emission_source) Tx(h crypto.Hash) (tx *transaction.Transaction, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("tx %s does not decode: %v", h, r)
		}
	}()
	b, err := chain.Store.Block_tx_store.ReadTX(h)
	if err != nil {
		return nil, err
	}
	tx = new(transaction.Transaction)
	return tx, tx.Deserialize(b)
}
func (chain_emission_source) State(h crypto.Hash) (*graviton.Snapshot, error) {
	v, err := chain.ReadBlockSnapshotVersion(h)
	if err != nil {
		return nil, err
	}
	return chain.Store.Balance_store.LoadSnapshot(v)
}

func emission_params() emission.Params {
	return emission.Params{
		Mainnet:     globals.IsMainnet(),
		Simulator:   globals.IsSimulator(),
		SkipHeights: map[uint64]bool{0: true, uint64(globals.Config.HF1_HEIGHT): true}, // protocol-installed contracts
		HF3Height:   uint64(globals.Config.MAJOR_HF3_HEIGHT),
	}
}

// seams for tests
var emission_topo = func() int64 { return chain.Load_TOPO_HEIGHT() }
var emission_topo_blid = func(t int64) (crypto.Hash, error) {
	r, err := chain.Store.Topo_store.Read(t)
	return r.BLOCK_ID, err
}
var emission_audit_block = func(blid crypto.Hash) (emission.Report, error) {
	return emission.AuditBlock(chain_emission_source{}, blid, emission_params())
}

type emission_contrib struct {
	blid     crypto.Hash
	verified bool
	excused  bool   // r23 merge: sc_unexplained or error: outside the verified set, its formula reward excused
	formula  uint64 // formula base reward at height (excused heights)
	errored  bool
	tries    int // errored audits of this blid so far
	base     uint64
	issued   uint64 // r23b: Paid - Fees of a verified block (new plaintext value its coinbase provably created)
	height   uint64

	// r23b forensics: the flow totals this audit added to the result, taken back when the topoheight is re-audited.
	// Before, a replaced block kept the first-seen block's fees, SC deposits/payouts and payees in the totals and the
	// replacing (canonical) block's were never added (record skipped them when replaced): 26 live reorgs by
	// 2026-10-30 19:15, so fees_redistributed and sc_payouts described the first-seen chain, not the canonical one.
	flows emission_flows
}

// emission_flows are the per-block contributions to the result's flow totals.
type emission_flows struct {
	fees, sc_deposits, sc_payouts, burns, payees, payees_verified uint64
	payees_explained                                              uint64 // r23c
}

func flows_of(r emission.Report) (f emission_flows) {
	f.fees, f.sc_deposits, f.sc_payouts, f.burns = r.Fees, r.SCDeposits, r.SCPayout, r.Burns
	for _, p := range r.Payees {
		f.payees++
		if p.Verified {
			f.payees_verified++
		}
		if p.Explained {
			f.payees_explained++
		}
	}
	return
}

// flows_total is the result's flow totals as one emission_flows (r23c).
func (res *GetEmissionAudit_Result) flows_total() emission_flows {
	return emission_flows{fees: res.FeesRedistributed, sc_deposits: res.SCDeposits, sc_payouts: res.SCPayouts, burns: res.Burns,
		payees: res.Payees, payees_verified: res.PayeesVerified, payees_explained: res.PayeesExplained}
}

// add_flows adds f to the result's totals (sign +1) or takes it back (sign -1).
func (res *GetEmissionAudit_Result) add_flows(f emission_flows, sign int) {
	if sign < 0 {
		res.FeesRedistributed -= f.fees
		res.SCDeposits -= f.sc_deposits
		res.SCPayouts -= f.sc_payouts
		res.Burns -= f.burns
		res.Payees -= f.payees
		res.PayeesVerified -= f.payees_verified
		res.PayeesExplained -= f.payees_explained
		return
	}
	res.FeesRedistributed += f.fees
	res.SCDeposits += f.sc_deposits
	res.SCPayouts += f.sc_payouts
	res.Burns += f.burns
	res.Payees += f.payees
	res.PayeesVerified += f.payees_verified
	res.PayeesExplained += f.payees_explained
}

type GetEmissionAudit_Result struct {
	Enabled  bool              `json:"enabled"`
	Status   string            `json:"status"`
	Audited  uint64            `json:"audited"`
	Verdicts map[string]uint64 `json:"verdicts"`
	Alerts   uint64            `json:"alerts"`

	// the emission segment: contiguous heights audited since start (or since the last skip)
	SegmentFrom     uint64 `json:"segment_from"`
	SegmentTo       uint64 `json:"segment_to"`
	VerifiedHeights uint64 `json:"verified_heights"` // heights whose coinbase was proven to land exactly
	// r23 merge: heights in the segment that could not be verified (sc_unexplained, or an audit error): consistency is
	// judged over the verified heights only, so one benign unexplained SC block no longer flips it false for good
	UnverifiedHeights  uint64 `json:"unverified_heights"`
	ObservedEmission   uint64 `json:"observed_emission"`
	FormulaEmission    uint64 `json:"formula_emission"`
	EmissionConsistent bool   `json:"emission_consistent"`
	FormulaSupply      uint64 `json:"formula_supply"` // at segment_to, what GetInfo reports (atomic units)
	// r23b: the audited emission proper. observed_emission restates the formula for the verified heights; issued is
	// what their coinbases provably credited beyond the fees they recirculate (sum of Paid - Fees). On mainnet (10
	// miniblocks, exactly one final, since height 399000) it equals observed_emission exactly.
	IssuedEmission       uint64 `json:"issued_emission"`
	IssuedMatchesFormula bool   `json:"issued_matches_formula"`

	FeesRedistributed uint64 `json:"fees_redistributed"`
	SCDeposits        uint64 `json:"sc_deposits"`
	SCPayouts         uint64 `json:"sc_payouts"`
	Burns             uint64 `json:"burns"` // r23b: plaintext DERO burned (payload BurnValue outside SC calls)
	PayeesVerified    uint64 `json:"payees_verified"`
	Payees            uint64 `json:"payees"`
	// r23c: payees whose account moved by exactly their coinbase share plus the deltas of the rings they sat in
	// (glue/emission per-account check); payees - payees_explained are the ones no check could account for
	PayeesExplained uint64 `json:"payees_explained"`

	CPUMicrosTotal int64   `json:"cpu_micros_total"` // wall time spent auditing (the auditor is single-threaded)
	MeanMicros     float64 `json:"mean_micros"`
	MaxMicros      int64   `json:"max_micros"`
	Gaps           uint64  `json:"gaps"`
	DeepRewinds    uint64  `json:"deep_rewinds"` // r23c: segment restarts after a rewind deeper than the reorg window remembers
	Reorgs         uint64  `json:"reorgs"`
	LastError      string  `json:"last_error,omitempty"`

	LastAlerts []emission.Report `json:"last_alerts"`
	Notable    []emission.Report `json:"notable"`
	Recent     []emission.Report `json:"recent"`
	Limit      string            `json:"limit"`

	Series GetEmissionAudit_Series `json:"series"`
}

// GetEmissionAudit_Series describes the persisted audited-emission series (r23b).
type GetEmissionAudit_Series struct {
	Enabled   bool                    `json:"enabled"`
	Path      string                  `json:"path,omitempty"`
	Records   uint64                  `json:"records"` // intact records in the file (read at start + appended since)
	Dropped   uint64                  `json:"dropped"` // torn/corrupt lines found at start (a crash mid-append)
	Written   uint64                  `json:"written"`
	Errors    uint64                  `json:"errors"`
	LastError string                  `json:"last_error,omitempty"`
	Every     uint64                  `json:"every_heights"`
	Last      []emission.SeriesRecord `json:"last"`
}

type emission_auditor struct {
	sync.Mutex
	last    int64
	pruned  int64 // r23c: highest topoheight whose window entry was dropped (-1: none); its contribution stays counted
	window  map[int64]emission_contrib
	res     GetEmissionAudit_Result
	segFrom uint64
	segTo   uint64

	excused_emission uint64 // formula base reward of the unverified heights in the segment

	// r23b series
	seg_start      int64  // unix seconds this segment began
	series_mark    uint64 // segment top at the last checkpoint (0: none in this segment)
	series_pending []emission.SeriesRecord
}

// seam for tests
var emission_series_append = emission.AppendSeries

var emission_state = new_emission_auditor()

func new_emission_auditor() *emission_auditor {
	return &emission_auditor{last: -1, pruned: -1, window: map[int64]emission_contrib{}, res: GetEmissionAudit_Result{Verdicts: map[string]uint64{}}}
}

var (
	emission_alerts_total = metrics.Set.NewCounter("dero_emission_audit_alerts_total")
	emission_errors_total = metrics.Set.NewCounter("dero_emission_audit_errors_total")
	emission_seconds      = metrics.Set.NewFloatCounter("dero_emission_audit_seconds_total")
)

func init() {
	metrics.Set.NewGauge("dero_emission_audit_consistent", func() float64 {
		emission_state.Lock()
		defer emission_state.Unlock()
		if emission_state.res.EmissionConsistent && emission_state.res.Alerts == 0 {
			return 1
		}
		return 0
	})
	metrics.Set.NewGauge("dero_emission_audit_verified_heights", func() float64 {
		emission_state.Lock()
		defer emission_state.Unlock()
		return float64(emission_state.res.VerifiedHeights)
	})
}

var emission_kick = make(chan struct{}, 1)

// kick_emission_audit asks for a pass now (a block arrived); it never blocks.
func kick_emission_audit() {
	select {
	case emission_kick <- struct{}{}:
	default:
	}
}

func emission_audit_enabled(getenv func(string) string) bool {
	return getenv("DERO_EMISSION_AUDIT") != "0"
}

func emission_audit_loop(exit chan bool) {
	if !emission_audit_enabled(os.Getenv) {
		logger.Info("emission audit disabled (DERO_EMISSION_AUDIT=0)")
		return
	}
	emission_state.Lock()
	emission_state.res.Enabled = true
	emission_state.seg_start = time.Now().Unix()
	emission_state.Unlock()
	if emission_series_enabled(os.Getenv) {
		emission_state.open_series(filepath.Join(globals.GetDataDirectory(), EMISSION_SERIES_FILE))
	}
	t := time.NewTicker(EMISSION_TICK)
	defer t.Stop()
	for {
		select {
		case <-exit:
			return
		case <-t.C:
		case <-emission_kick:
		}
		func() {
			defer globals.Recover(2)
			emission_state.step()
		}()
	}
}

// step audits every topoheight not yet audited (and re-reads the reorg window). It returns how many blocks it audited.
func (a *emission_auditor) step() (n int) {
	topo := emission_topo()
	if topo < 1 {
		return 0
	}
	a.Lock()
	from := a.last + 1 - EMISSION_REORG_WINDOW
	// r23c: after a local rewind deeper than the window remembers, the pass would re-read topoheights whose entries
	// were already dropped and count them again as new (verified_heights and the flow totals twice, and
	// emission_consistent false for an honest chain). Such a pass starts a new segment, as a skip does.
	deep := a.last >= 0 && from <= a.pruned
	if a.last < 0 || topo-a.last > EMISSION_CATCHUP_MAX || deep {
		if a.last >= 0 {
			a.res.Gaps++
		}
		if deep { // the dropped entries' flows cannot be taken back: the flow totals restart with the segment
			a.res.DeepRewinds++
			a.res.add_flows(a.res.flows_total(), -1)
		}
		a.pruned = -1
		a.window = map[int64]emission_contrib{}
		a.segFrom, a.segTo = 0, 0
		a.seg_start, a.series_mark = time.Now().Unix(), 0
		a.res.VerifiedHeights, a.res.ObservedEmission, a.res.UnverifiedHeights, a.excused_emission = 0, 0, 0, 0
		// r23c (verifier): issued_emission restarts with observed_emission; before, any gap or deep rewind left the old
		// segment's issued in place and issued_matches_formula read false for an honest chain
		a.res.IssuedEmission, a.res.IssuedMatchesFormula = 0, true
		from = topo - EMISSION_BACKFILL + 1
	}
	a.Unlock()
	if from < 1 {
		from = 1
	}
	for t := from; t <= topo; t++ {
		blid, err := emission_topo_blid(t)
		if err != nil {
			continue
		}
		a.Lock()
		prev, seen := a.window[t]
		a.Unlock()
		if seen && prev.blid == blid && !(prev.errored && prev.tries < EMISSION_ERROR_RETRIES) {
			continue // audited (an errored one is retried a few times: r23 merge)
		}
		r, err := emission_audit_block(blid)
		a.record(t, blid, r, err, seen && prev.blid != blid)
		n++
	}
	a.Lock()
	a.last = topo
	for k := range a.window {
		if k < topo-EMISSION_WINDOW_KEEP {
			delete(a.window, k)
			if k > a.pruned {
				a.pruned = k
			}
		}
	}
	pending, path := a.series_pending, a.res.Series.Path
	a.series_pending = nil
	a.Unlock()
	a.write_series(path, pending) // file I/O outside the lock: RPC readers never wait on an fsync
	return n
}

// write_series appends the pending records; a failure is counted and reported, never fatal.
func (a *emission_auditor) write_series(path string, recs []emission.SeriesRecord) {
	if path == "" || len(recs) == 0 {
		return
	}
	for _, r := range recs {
		err := emission_series_append(path, r)
		a.Lock()
		if err != nil {
			a.res.Series.Errors++
			a.res.Series.LastError = err.Error()
		} else {
			a.res.Series.Written++
			a.res.Series.Records++
			a.res.Series.Last = append(a.res.Series.Last, r)
			if len(a.res.Series.Last) > EMISSION_SERIES_SHOWN {
				a.res.Series.Last = a.res.Series.Last[len(a.res.Series.Last)-EMISSION_SERIES_SHOWN:]
			}
		}
		a.Unlock()
	}
}

// open_series points the auditor at its series file and reads back what an earlier run left there.
func (a *emission_auditor) open_series(path string) {
	recs, bad, err := emission.ReadSeriesTail(path, EMISSION_SERIES_TAIL)
	a.Lock()
	defer a.Unlock()
	s := &a.res.Series
	s.Enabled, s.Path, s.Every = true, path, EMISSION_SERIES_EVERY
	if err != nil && !os.IsNotExist(err) {
		s.LastError = err.Error()
	}
	s.Records, s.Dropped = uint64(len(recs)), uint64(bad)
	if n, nb, cerr := emission.CountSeries(path); cerr == nil { // r23b merge (SND-3 fix): the whole file, not the 1 MiB tail
		s.Records, s.Dropped = uint64(n), uint64(nb)
	}
	if len(recs) > EMISSION_SERIES_SHOWN {
		recs = recs[len(recs)-EMISSION_SERIES_SHOWN:]
	}
	s.Last = recs
}

func emission_series_enabled(getenv func(string) string) bool {
	return getenv("DERO_EMISSION_SERIES") != "0"
}

// series_record builds a record of the segment as it stands (caller holds the lock).
func (a *emission_auditor) series_record(kind string, topo int64, r emission.Report) emission.SeriesRecord {
	res := &a.res
	return emission.SeriesRecord{Kind: kind, Time: time.Now().Unix(), SegStart: a.seg_start, Topo: topo, Height: r.Height,
		BLID: r.BLID, SegmentFrom: a.segFrom, SegmentTo: a.segTo, Verified: res.VerifiedHeights, Unverified: res.UnverifiedHeights,
		Observed: res.ObservedEmission, Issued: res.IssuedEmission, Formula: res.FormulaEmission, Consistent: res.EmissionConsistent,
		FormulaSupply: res.FormulaSupply, Alerts: res.Alerts, Fees: res.FeesRedistributed, SCDeposits: res.SCDeposits,
		SCPayouts: res.SCPayouts, Burns: res.Burns,
		// r27 (B36): the payee totals too, so a stopped process's checkpoints keep them
		V: emission.SeriesV2, Payees: res.Payees, PayeesVerified: res.PayeesVerified, PayeesExplained: res.PayeesExplained}
}

func (a *emission_auditor) record(topo int64, blid crypto.Hash, r emission.Report, err error, replaced bool) {
	a.Lock()
	defer a.Unlock()
	res := &a.res
	res.Audited++
	if err != nil {
		r.Verdict = emission.VerdictError
		res.LastError = err.Error()
		emission_errors_total.Inc()
	}
	res.Verdicts[r.Verdict]++
	metrics.Set.GetOrCreateCounter(fmt.Sprintf(`dero_emission_audit_blocks_total{verdict=%q}`, r.Verdict)).Inc()
	res.CPUMicrosTotal += r.Micros
	emission_seconds.Add(float64(r.Micros) / 1e6)
	if r.Micros > res.MaxMicros {
		res.MaxMicros = r.Micros
	}
	res.MeanMicros = float64(res.CPUMicrosTotal) / float64(res.Audited)

	// the emission segment
	old, had := a.window[topo]
	if replaced {
		res.Reorgs++
	}
	if had && old.verified {
		res.VerifiedHeights--
		res.ObservedEmission -= old.base
		res.IssuedEmission -= old.issued
	}
	if had && old.excused {
		res.UnverifiedHeights--
		a.excused_emission -= old.formula
	}
	if had {
		res.add_flows(old.flows, -1) // zero for an audit that errored
	}
	c := emission_contrib{blid: blid, height: r.Height, base: r.BaseReward}
	if err != nil {
		c.errored = true
		if had && old.blid == blid {
			c.tries = old.tries
		}
		c.tries++
	}
	if err == nil && (r.Verdict == emission.VerdictOK || r.Verdict == emission.VerdictOKSC) {
		c.verified = true
		res.VerifiedHeights++
		res.ObservedEmission += r.BaseReward
		if r.Paid >= r.Fees {
			c.issued = r.Paid - r.Fees
		}
		res.IssuedEmission += c.issued
	} else if r.Height > 0 && (err != nil || r.Verdict == emission.VerdictSCUnexplained) {
		c.excused, c.formula = true, emission.FormulaSupply(r.Height)-emission.FormulaSupply(r.Height-1)
		res.UnverifiedHeights++
		a.excused_emission += c.formula
	}
	if err == nil {
		c.flows = flows_of(r)
	}
	a.window[topo] = c
	if (err == nil || c.excused) && r.Verdict != emission.VerdictSkipped && r.Height > 0 {
		if a.segFrom == 0 || r.Height < a.segFrom {
			a.segFrom = r.Height
		}
		if r.Height > a.segTo {
			a.segTo = r.Height
		}
	}
	res.SegmentFrom, res.SegmentTo = a.segFrom, a.segTo
	if a.segFrom > 0 {
		res.FormulaEmission = emission.FormulaSupply(a.segTo) - emission.FormulaSupply(a.segFrom-1)
		res.FormulaSupply = emission.FormulaSupply(a.segTo)
		res.EmissionConsistent = res.VerifiedHeights+res.UnverifiedHeights == a.segTo-a.segFrom+1 &&
			res.ObservedEmission+a.excused_emission == res.FormulaEmission
	}
	res.IssuedMatchesFormula = res.IssuedEmission == res.ObservedEmission

	res.add_flows(c.flows, +1) // a replacing block's flows replace the replaced one's (r23b forensics)

	res.Recent = append(res.Recent, r)
	if len(res.Recent) > EMISSION_RECENT {
		res.Recent = res.Recent[len(res.Recent)-EMISSION_RECENT:]
	}
	if r.Verdict == emission.VerdictAlert {
		res.Alerts++
		emission_alerts_total.Inc()
		res.LastAlerts = append(res.LastAlerts, r)
		if len(res.LastAlerts) > EMISSION_ALERTS_KEPT {
			res.LastAlerts = res.LastAlerts[len(res.LastAlerts)-EMISSION_ALERTS_KEPT:]
		}
		logger.Error(nil, "EMISSION AUDIT ALERT", "height", r.Height, "topoheight", topo, "blid", r.BLID, "alerts", r.Alerts)
	} else if r.Verdict == emission.VerdictSCUnexplained {
		logger.V(1).Info("emission audit: SC block not explained exactly", "height", r.Height, "blid", r.BLID, "notes", r.Notes)
	}
	if res.FormulaSupply > 0 && r.MaxPlainFlow >= res.FormulaSupply/1000000*EMISSION_NOTABLE_PPM && r.MaxPlainFlow > 0 {
		res.Notable = append(res.Notable, r)
		if len(res.Notable) > EMISSION_RECENT {
			res.Notable = res.Notable[len(res.Notable)-EMISSION_RECENT:]
		}
		logger.Info("emission audit: notable plaintext DERO flow", "height", r.Height, "blid", r.BLID, "atomic", r.MaxPlainFlow)
		if res.Series.Enabled && !replaced {
			n := a.series_record(emission.SeriesNotable, topo, r)
			n.Flow = r.MaxPlainFlow
			a.series_pending = append(a.series_pending, n)
		}
	}
	// r23b: a checkpoint each time the segment top crosses a multiple of EMISSION_SERIES_EVERY
	if res.Series.Enabled && a.segTo > 0 && a.segTo/EMISSION_SERIES_EVERY > a.series_mark/EMISSION_SERIES_EVERY && a.segTo > a.segFrom {
		a.series_mark = a.segTo
		a.series_pending = append(a.series_pending, a.series_record(emission.SeriesCheckpoint, topo, r))
	}
}

func (a *emission_auditor) snapshot() GetEmissionAudit_Result {
	a.Lock()
	defer a.Unlock()
	r := a.res
	r.Verdicts = map[string]uint64{}
	for k, v := range a.res.Verdicts {
		r.Verdicts[k] = v
	}
	r.LastAlerts = append([]emission.Report(nil), a.res.LastAlerts...)
	r.Notable = append([]emission.Report(nil), a.res.Notable...)
	r.Recent = append([]emission.Report(nil), a.res.Recent...)
	r.Series.Last = append([]emission.SeriesRecord(nil), a.res.Series.Last...)
	r.Status = emission_status(r.Enabled, r.Alerts, r.Audited)
	r.Limit = "proves only that no plaintext value moved outside published deltas, the emission formula and SC accounting; value created inside encrypted transfer amounts (range-proof soundness class) is invisible to any node"
	return r
}

func emission_status(enabled bool, alerts, audited uint64) string {
	switch {
	case !enabled:
		return "disabled"
	case alerts > 0:
		return "ALERT"
	case audited == 0:
		return "starting"
	}
	return "OK"
}

// summary is the GetMonetaryIntegrity view of the auditor (r23c, RPCWS23B-C): the totals only, under the lock, without
// copying the report and series lists that snapshot copies for GetEmissionAudit and the caller then dropped.
// r24 (cryptoinfl CI24-1): the r23c version listed the fields by hand and missed the seven that r23c CI-4 added to
// MonetaryIntegrity_Emission (issued_emission, issued_matches_formula, burns, payees, payees_verified,
// payees_explained, deep_rewinds), so the live r23c node published issued_matches_formula=false and payees=0 next to
// a GetEmissionAudit that said true and 7,117. It now copies the result struct (slice headers only, no list copy) and
// goes through emission_summary, the one field mapping both paths share.
func (a *emission_auditor) summary() MonetaryIntegrity_Emission {
	a.Lock()
	r := a.res
	v := make(map[string]uint64, len(a.res.Verdicts))
	for k, n := range a.res.Verdicts {
		v[k] = n
	}
	a.Unlock()
	r.Verdicts = v
	r.LastAlerts, r.Notable, r.Recent, r.Series.Last = nil, nil, nil, nil
	r.Status = emission_status(r.Enabled, r.Alerts, r.Audited)
	return emission_summary(r)
}

func GetEmissionAudit(ctx context.Context) (result GetEmissionAudit_Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = rpc_internal_error(r) // r27: counted + logged like every other handler (was an untyped, uncounted text)
		}
	}()
	return emission_state.snapshot(), nil
}
