// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

// emission-audit runs the glue/emission auditor over a range of main-chain blocks of a datadir COPY, offline, and
// reports verdicts and the cost per block (Round 23 measurement tool).
//
//	emission-audit -state <dir with balances/ and topo.map (an APFS clone)> -bltx <bltx_store dir> [-n 500] [-end T]
//
// It never writes to -bltx (block and tx files are only opened for reading). graviton opens the -state copy
// read-write, so -state must be a copy, never a live datadir. With -probe-nonce it also times the state reads that
// Add_TX_To_Pool's nonce check performs for each audited transaction (the work txprecheck saves on a refused tx).
//
// Round 23b modes (modes.go):
//
//	-archive -from-height A -to-height B   audit a height range; pruned heights are reported as unavailable
//	                                        [-series-out f -every 100] writes the cumulative checkpoints
//	-hf3 -datadirs d1,d2,...               forensic report of the 75 HF3-exempt transactions (read-only, no state)
//	-series-read f                         check and summarise an audited-emission series file
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/glue/emission"
	"github.com/deroproject/derohe/glue/txprecheck"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/graviton"
)

type fsSource = emission.DirSource

// probeNonce performs the state reads of Verify_Transaction_NonCoinbase_CheckNonce_Tips for one tip.
func probeNonce(s *fsSource, tx *transaction.Transaction, tip crypto.Hash) (time.Duration, error) {
	t0 := time.Now()
	_, v, err := s.BlockFile(tx.BLID)
	if err != nil {
		return 0, err
	}
	ss, err := s.Store.LoadSnapshot(v)
	if err != nil {
		return 0, err
	}
	txt, _ := ss.GetTree(config.BALANCE_TREE)
	_, tv, err := s.BlockFile(tip)
	if err != nil {
		return 0, err
	}
	ts, err := s.Store.LoadSnapshot(tv)
	if err != nil {
		return 0, err
	}
	tipt, _ := ts.GetTree(config.BALANCE_TREE)
	for t := range tx.Payloads {
		if !tx.Payloads[t].SCID.IsZero() {
			continue
		}
		st := tx.Payloads[t].Statement
		bpp := int(st.Bytes_per_publickey)
		for i := 0; i < int(st.RingSize); i += 2 { // half the ring (parity)
			_, k, _, e := txt.GetKeyValueFromHash(st.Publickeylist_pointers[i*bpp : (i+1)*bpp])
			if e == nil {
				tipt.GetKeyValueFromKey(k)
			}
		}
	}
	return time.Since(t0), nil
}

func main() {
	state := flag.String("state", "", "directory holding a COPY of balances/ and topo.map")
	bltx := flag.String("bltx", "", "bltx_store directory (read only)")
	n := flag.Int64("n", 200, "blocks to audit")
	end := flag.Int64("end", 0, "last topoheight (default: newest minus 3)")
	mainnet := flag.Bool("mainnet", true, "mainnet parameters")
	jsonOut := flag.String("json", "", "write per-block reports here")
	probe := flag.Bool("probe-nonce", false, "time the nonce-check state reads per audited tx")
	archive := flag.Bool("archive", false, "audit -from-height..-to-height (r23b)")
	fromH := flag.Int64("from-height", 0, "archive: first height")
	toH := flag.Int64("to-height", 0, "archive: last height (default: newest minus 3 topoheights)")
	seriesOut := flag.String("series-out", "", "archive: append cumulative checkpoints to this file")
	every := flag.Uint64("every", 100, "archive: checkpoint interval in heights")
	hf3 := flag.Bool("hf3", false, "HF3 forensic report (r23b)")
	datadirs := flag.String("datadirs", "", "hf3: comma-separated datadirs (each with bltx_store/ and topo.map), read only")
	seriesRead := flag.String("series-read", "", "check and summarise a series file")
	flag.Parse()
	switch {
	case *hf3:
		os.Exit(hf3Main(*datadirs, *jsonOut))
	case *seriesRead != "":
		os.Exit(seriesMain(*seriesRead))
	}
	if *state == "" || *bltx == "" {
		flag.Usage()
		os.Exit(2)
	}
	store, err := graviton.NewDiskStore(filepath.Join(*state, "balances"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	tm, err := emission.OpenTopo(filepath.Join(*state, "topo.map"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *end == 0 {
		*end = tm.LastWritten() - 3
	}
	src := &fsSource{BLTX: *bltx, Store: store}
	p := emission.Params{Mainnet: *mainnet, SkipHeights: map[uint64]bool{0: true, uint64(config.Mainnet.HF1_HEIGHT): true}}
	if *mainnet {
		p.HF3Height = uint64(config.Mainnet.MAJOR_HF3_HEIGHT) // re-registration is consensus-legal below it
	}
	if *archive {
		os.Exit(archiveMain(src, tm, *fromH, *toH, p, *jsonOut, *seriesOut, *every))
	}
	var reports []emission.Report
	var micros []int64
	verdicts := map[string]int{}
	var txs, changed, payees, verified int
	var explained, exactAccts, accts int // r23c per-account check
	var probeTotal, precheckTotal time.Duration
	var probes int
	cpu0 := cpuTime()
	wall0 := time.Now()
	for t := *end - *n + 1; t <= *end; t++ {
		blid, _, _, err := tm.Record(t)
		if err != nil {
			fmt.Fprintln(os.Stderr, "topo", t, err)
			continue
		}
		r, err := emission.AuditBlock(src, blid, p)
		if err != nil {
			r.Notes = append(r.Notes, err.Error())
		}
		verdicts[r.Verdict]++
		micros = append(micros, r.Micros)
		txs += r.Txs
		changed += r.Changed
		for _, py := range r.Payees {
			payees++
			if py.Verified {
				verified++
			}
			if py.Explained {
				explained++
			}
		}
		exactAccts += r.AccountsExact
		accts += r.Changed + r.Inserted
		if r.Verdict == emission.VerdictAlert || r.Verdict == emission.VerdictError || r.Verdict == emission.VerdictSCUnexplained {
			fmt.Printf("topo %d height %d %s alerts=%v notes=%v\n", t, r.Height, r.Verdict, r.Alerts, r.Notes)
		}
		reports = append(reports, r)
		if *probe && r.Txs > 0 {
			bl, _ := src.Block(blid)
			for _, h := range bl.Tx_hashes {
				tx, e := src.Tx(h)
				if e != nil || tx.TransactionType == transaction.REGISTRATION {
					continue
				}
				t1 := time.Now()
				txprecheck.Check(tx)
				precheckTotal += time.Since(t1)
				if d, e := probeNonce(src, tx, bl.Tips[0]); e == nil {
					probeTotal += d
					probes++
				}
			}
		}
	}
	wall := time.Since(wall0)
	cpu := cpuTime() - cpu0
	sort.Slice(micros, func(i, j int) bool { return micros[i] < micros[j] })
	pct := func(q float64) int64 {
		if len(micros) == 0 {
			return 0
		}
		return micros[int(q*float64(len(micros)-1))]
	}
	var sum int64
	for _, m := range micros {
		sum += m
	}
	fmt.Printf("blocks %d (topo %d..%d) verdicts %v\n", len(micros), *end-*n+1, *end, verdicts)
	fmt.Printf("txs %d changed accounts %d payees %d verified %d\n", txs, changed, payees, verified)
	fmt.Printf("r23c per-account: accounts exact %d of %d changed+inserted; payees explained %d\n", exactAccts, accts, explained)
	if len(micros) > 0 {
		fmt.Printf("per block wall us: mean %d p50 %d p95 %d max %d; process cpu %.3f s for %.3f s wall (%.1f ms cpu/block)\n",
			sum/int64(len(micros)), pct(0.5), pct(0.95), pct(1), cpu.Seconds(), wall.Seconds(), cpu.Seconds()*1000/float64(len(micros)))
	}
	if probes > 0 {
		fmt.Printf("nonce-check state reads: %d txs, mean %d us; txprecheck.Check mean %d ns\n", probes,
			probeTotal.Microseconds()/int64(probes), precheckTotal.Nanoseconds()/int64(probes))
	}
	if *jsonOut != "" {
		b, _ := json.MarshalIndent(reports, "", " ")
		os.WriteFile(*jsonOut, b, 0600)
	}
}
