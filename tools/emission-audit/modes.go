// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/glue/emission"
)

const txValidityHeight = 11 // blockchain.TX_VALIDITY_HEIGHT: a tx is mined within 11 heights of its reference

// payeeTally counts the coinbase payees of audited reports: verified (the ciphertext moved by exactly the reward) and
// explained (r23c per-account check). r27 (tools-kats): the live mode printed these and -archive did not, so the B36
// 24 h archive read could not say how many payees it proved.
type payeeTally struct{ payees, verified, explained int }

func (p *payeeTally) add(r emission.Report) {
	for _, py := range r.Payees {
		p.payees++
		if py.Verified {
			p.verified++
		}
		if py.Explained {
			p.explained++
		}
	}
}

func (p payeeTally) String() string {
	return fmt.Sprintf("payees %d verified %d explained %d", p.payees, p.verified, p.explained)
}

// archiveRun is the per-report state of archiveMain: the current segment (reset at every unavailable height), its
// series checkpoints, and the payee tally of every audited report.
type archiveRun struct {
	seg           emission.Cumulative
	segStart      int64
	seriesOut     string
	every         uint64
	written, werr int
	payees        payeeTally
	now           func() int64
}

func (a *archiveRun) each(t int64, r emission.Report, err error) {
	if err != nil && errors.Is(err, emission.ErrUnavailable) {
		a.seg, a.segStart = emission.Cumulative{}, a.now()
		return
	}
	a.payees.add(r)
	prevTo := a.seg.To
	a.seg.Add(r, err)
	seg := a.seg
	if a.seriesOut != "" && seg.Blocks > 1 && seg.To/a.every > prevTo/a.every {
		rec := emission.SeriesRecord{Kind: emission.SeriesCheckpoint, Time: a.now(), SegStart: a.segStart, Topo: t,
			Height: r.Height, BLID: r.BLID, SegmentFrom: seg.From, SegmentTo: seg.To, Verified: seg.Verified,
			Unverified: seg.Unverified, Observed: seg.Observed, Issued: seg.Issued, Formula: seg.Formula, Consistent: seg.Consistent,
			FormulaSupply: emission.FormulaSupply(seg.To), Alerts: seg.Alerts, Fees: seg.Fees, SCDeposits: seg.SCDeposits,
			SCPayouts: seg.SCPayouts, Burns: seg.Burns, V: emission.SeriesV2, Payees: seg.Payees,
			PayeesVerified: seg.PayeesVerified, PayeesExplained: seg.PayeesExplained} // r27 (B36): v2 checkpoint
		if e := emission.AppendSeries(a.seriesOut, rec); e != nil {
			a.werr++
		} else {
			a.written++
		}
	}
}

func archiveMain(src *fsSource, tm *emission.TopoMap, fromH, toH int64, p emission.Params, jsonOut, seriesOut string, every uint64) int {
	last := tm.LastWritten() - 3
	from := tm.FindHeight(fromH)
	if fw := tm.FirstWritten(); fw >= 0 {
		if _, _, fh, err := tm.Record(fw); err == nil && fromH < fh {
			fmt.Printf("heights %d..%d are not in this store: its first topo record is height %d (a fastsync bootstrap prunes everything below)\n", fromH, fh-1, fh)
		}
	}
	to := last
	if toH > 0 {
		to = tm.FindHeight(toH+1) - 1
	}
	if to > last {
		to = last
	}
	if every == 0 {
		every = 100
	}
	unix := func() int64 { return time.Now().Unix() }
	run := &archiveRun{segStart: unix(), seriesOut: seriesOut, every: every, now: unix}
	cpu0, wall0 := cpuTime(), time.Now()
	sum := emission.ArchiveRange(src, tm, from, to, p, run.each)
	written, werr := run.written, run.werr
	cpu, wall := cpuTime()-cpu0, time.Since(wall0)
	fmt.Printf("archive topo %d..%d (heights %d..%d requested): audited %d unavailable %d errors %d verdicts %v\n",
		from, to, fromH, toH, sum.Audited, sum.Unavailable, sum.Errors, sum.Verdicts)
	fmt.Printf("archive %s (over %d audited blocks)\n", run.payees, sum.Audited) // r27: the live mode's payee line
	for i, c := range sum.Segments {
		fmt.Printf("segment %d topo %d..%d heights %d..%d: verified %d unverified %d observed %d formula %d issued %d fees %d burns %d sc_deposits %d sc_payouts %d payees %d payees_verified %d payees_explained %d consistent %v issued_matches_formula %v\n",
			i, sum.Available[i][0], sum.Available[i][1], c.From, c.To, c.Verified, c.Unverified, c.Observed, c.Formula, c.Issued,
			c.Fees, c.Burns, c.SCDeposits, c.SCPayouts, c.Payees, c.PayeesVerified, c.PayeesExplained, c.Consistent, c.IssuedMatchesFormula)
	}
	for _, r := range sum.Flagged {
		fmt.Printf("flagged height %d %s alerts=%v notes=%v\n", r.Height, r.Verdict, r.Alerts, r.Notes)
	}
	if sum.Audited > 0 {
		fmt.Printf("cost: process cpu %.3f s for %.3f s wall over %d audited blocks (%.2f ms cpu/block, audit wall mean %d us)\n",
			cpu.Seconds(), wall.Seconds(), sum.Audited, cpu.Seconds()*1000/float64(sum.Audited), sum.MicrosTotal/sum.Audited)
	}
	if seriesOut != "" {
		fmt.Printf("series: %d checkpoints appended to %s (%d write errors)\n", written, seriesOut, werr)
	}
	if jsonOut != "" {
		b, _ := json.MarshalIndent(sum, "", " ")
		os.WriteFile(jsonOut, b, 0600)
	}
	if sum.Cumulative.Alerts > 0 {
		return 3
	}
	return 0
}

type hf3Dir struct {
	name string
	src  *emission.DirSource
	tm   *emission.TopoMap
}

func hf3Main(datadirs, jsonOut string) int {
	var dirs []hf3Dir
	for _, d := range strings.Split(datadirs, ",") {
		if d == "" {
			continue
		}
		hd := hf3Dir{name: d, src: &emission.DirSource{BLTX: filepath.Join(d, "bltx_store")}}
		if tm, err := emission.OpenTopo(filepath.Join(d, "topo.map")); err == nil {
			hd.tm = tm
		}
		dirs = append(dirs, hd)
	}
	if len(dirs) == 0 {
		fmt.Fprintln(os.Stderr, "-hf3 needs -datadirs")
		return 2
	}
	cpu0 := cpuTime()
	var keys []string
	for k := range blockchain.HF3_Affected_Txs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var recs []emission.HF3Record
	for _, k := range keys {
		e := blockchain.HF3_Affected_Txs[k]
		var id crypto.Hash
		if b, err := hex.DecodeString(k); err != nil || len(b) != 32 {
			fmt.Fprintln(os.Stderr, "bad table txid", k)
			return 1
		} else {
			copy(id[:], b)
		}
		var bodies []emission.Body
		var blocks []emission.BlockRef
		var searched []string
		for _, d := range dirs {
			if b, err := d.src.TxBytes(id); err == nil {
				bodies = append(bodies, emission.Body{Source: d.name, Bytes: b})
			}
			if d.tm == nil {
				continue
			}
			lastW := d.tm.LastWritten()
			t0 := d.tm.FindHeight(int64(e.Height))
			n := 0
			for t := t0; t <= lastW; t++ {
				blid, _, h, err := d.tm.Record(t)
				if err != nil || h > int64(e.Height)+txValidityHeight+1 {
					break
				}
				n++
				bl, err := d.src.Block(blid)
				if err != nil {
					continue
				}
				for _, th := range bl.Tx_hashes {
					if th == id {
						br := emission.BlockRef{Source: d.name, Topo: t, Height: bl.Height, BLID: blid.String()}
						for _, tip := range bl.Tips {
							br.Tips = append(br.Tips, tip.String())
						}
						blocks = append(blocks, br)
					}
				}
			}
			searched = append(searched, fmt.Sprintf("%s: %d topo records from height %d", d.name, n, e.Height))
		}
		recs = append(recs, emission.HF3Forensic(emission.HF3Entry{TXID: k, BlTips: e.Bl_Tips, Height: e.Height, TxParity: e.Tx_Parity},
			bodies, blocks, strings.Join(searched, "; ")))
	}
	sum := emission.SummarizeHF3(recs)
	cpu := cpuTime() - cpu0
	fmt.Printf("hf3: %d entries (%d duplicates, %d false parity) heights %d..%d; in store %d; bodies differ %d; foreign %d; blocks found %d (table-tips blocks %d, txids in >1 block %d); fees known %d burn known %d; cpu %.3f s\n",
		sum.Entries, sum.Duplicates, sum.FalseParity, sum.HeightFrom, sum.HeightTo, sum.InStore, sum.BodiesDiffer, sum.ForeignBodies,
		sum.BlocksFound, sum.TableBlocksFound, sum.MultiBlockTxids, sum.FeesKnown, sum.BurnKnown, cpu.Seconds())
	for _, r := range recs {
		if r.InStore || len(r.Blocks) > 0 {
			b, _ := json.Marshal(r)
			fmt.Printf("%s\n", b)
		}
	}
	fmt.Println("limit:", sum.Limit)
	if jsonOut != "" {
		b, _ := json.MarshalIndent(struct {
			Summary emission.HF3Summary  `json:"summary"`
			Records []emission.HF3Record `json:"records"`
		}{sum, recs}, "", " ")
		os.WriteFile(jsonOut, b, 0600)
	}
	return 0
}

func seriesMain(path string) int {
	recs, bad, err := emission.ReadSeriesTail(path, emission.SeriesMaxBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	segs := map[int64]emission.SeriesRecord{} // the newest checkpoint of each segment
	var notable int
	for _, r := range recs {
		switch r.Kind {
		case emission.SeriesCheckpoint:
			if old, ok := segs[r.SegStart]; !ok || r.SegmentTo >= old.SegmentTo {
				segs[r.SegStart] = r
			}
		case emission.SeriesNotable:
			notable++
		}
	}
	var starts []int64
	for k := range segs {
		starts = append(starts, k)
	}
	sort.Slice(starts, func(i, j int) bool { return starts[i] < starts[j] })
	var heights, verified uint64
	allOK := true
	for _, k := range starts {
		r := segs[k]
		fmt.Printf("segment started %s: heights %d..%d verified %d unverified %d observed %d issued %d formula %d consistent %v alerts %d payees %s\n",
			time.Unix(k, 0).UTC().Format(time.RFC3339), r.SegmentFrom, r.SegmentTo, r.Verified, r.Unverified, r.Observed, r.Issued, r.Formula, r.Consistent, r.Alerts,
			SeriesPayees(r))
		heights += r.SegmentTo - r.SegmentFrom + 1
		verified += r.Verified
		allOK = allOK && r.Consistent && r.Alerts == 0 && r.Issued == r.Observed
	}
	fmt.Printf("series %s: %d records (%d dropped as torn/corrupt), %d segments, %d notable; heights covered %d (segments may overlap), verified %d, all consistent %v\n",
		path, len(recs), bad, len(segs), notable, heights, verified, allOK)
	return 0
}

// SeriesPayees renders a checkpoint's payee counts for -series-read; a pre-r27 record (no V) says "pending (not
// recorded before r27)" instead of a 0 that would read as "no payees" (r27, B36).
func SeriesPayees(r emission.SeriesRecord) string {
	if !r.PayeesKnown() {
		return "pending (not recorded before r27)"
	}
	return fmt.Sprintf("%d verified %d explained %d", r.Payees, r.PayeesVerified, r.PayeesExplained)
}
