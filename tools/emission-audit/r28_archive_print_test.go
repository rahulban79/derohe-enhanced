// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package main

// r28 (tools-kats, B139 residual): the -archive payee line was printed by archiveMain, which had no test (0.0 %). The
// report is now printArchive(w, ...); these tests read the printed lines on a forged summary and run archiveMain end
// to end on a forged topo.map whose blocks the (empty) store does not hold. Forged inputs only; no datadir is read.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deroproject/derohe/glue/emission"
)

func TestR28PrintArchivePayeeAndSeriesLines(t *testing.T) {
	sum := emission.ArchiveSummary{Audited: 3, Unavailable: 1, Verdicts: map[string]int64{emission.VerdictOK: 3},
		Segments:  []emission.Cumulative{{From: 7600010, To: 7600012, Verified: 3, Payees: 5, PayeesVerified: 4, PayeesExplained: 2, Consistent: true}},
		Available: [][2]int64{{10, 12}}, MicrosTotal: 3000}
	run := &archiveRun{payees: payeeTally{payees: 5, verified: 4, explained: 2}, written: 2, werr: 1}
	var b bytes.Buffer
	printArchive(&b, 9, 12, 7600009, 7600012, sum, run, "series.jsonl", 30*time.Millisecond, time.Second)
	out := b.String()
	for _, want := range []string{
		"archive topo 9..12 (heights 7600009..7600012 requested): audited 3 unavailable 1 errors 0 verdicts map[ok:3]\n",
		"archive payees 5 verified 4 explained 2 (over 3 audited blocks)\n",
		"segment 0 topo 10..12 heights 7600010..7600012: verified 3 ",
		" payees 5 payees_verified 4 payees_explained 2 consistent true ",
		"cost: process cpu 0.030 s for 1.000 s wall over 3 audited blocks (10.00 ms cpu/block, audit wall mean 1000 us)\n",
		"series: 2 checkpoints appended to series.jsonl (1 write errors)\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the -archive report lacks %q:\n%s", want, out)
		}
	}
	b.Reset()
	printArchive(&b, 0, -1, 1, 2, emission.ArchiveSummary{}, &archiveRun{}, "", 0, 0)
	if strings.Contains(b.String(), "cost:") || strings.Contains(b.String(), "series:") ||
		!strings.Contains(b.String(), "archive payees 0 verified 0 explained 0 (over 0 audited blocks)\n") {
		t.Fatalf("an empty run prints the payee line and no cost or series line:\n%s", b.String())
	}
}

// archiveMain end to end: a fastsync-shaped topo.map (slots 0..1 unwritten, 2..9 written at heights 100..107) over an
// empty block directory. Every requested block is unavailable, never an audit error, the payee line still prints, the
// first-record note names the bootstrap height, the -json file is written and the exit code is 0 (no alert).
func TestR28ArchiveMainPrintsPayeeLineEndToEnd(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	for i := 0; i < 10; i++ {
		var x [48]byte
		if i >= 2 {
			x[0] = byte(i)
			binary.LittleEndian.PutUint64(x[32:], uint64(i))
			binary.LittleEndian.PutUint64(x[40:], uint64(98+i))
		}
		buf.Write(x[:])
	}
	tp := filepath.Join(dir, "topo.map")
	if err := os.WriteFile(tp, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	tm, err := emission.OpenTopo(tp)
	if err != nil {
		t.Fatal(err)
	}
	defer tm.Close()
	jsonOut := filepath.Join(dir, "sum.json")
	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w
	rc := archiveMain(&emission.DirSource{BLTX: filepath.Join(dir, "bltx_store")}, tm, 50, 0, emission.Params{}, jsonOut, "", "", 0)
	w.Close()
	os.Stdout = stdout
	got, _ := io.ReadAll(r)
	out := string(got)
	if rc != 0 {
		t.Fatalf("archiveMain = %d, want 0 (no alert):\n%s", rc, out)
	}
	for _, want := range []string{
		"heights 50..99 are not in this store: its first topo record is height 100",
		"archive topo 2..6 (heights 50..0 requested): audited 0 unavailable 5 errors 0",
		"archive payees 0 verified 0 explained 0 (over 0 audited blocks)\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("archiveMain output lacks %q:\n%s", want, out)
		}
	}
	var sum emission.ArchiveSummary
	if b, err := os.ReadFile(jsonOut); err != nil || json.Unmarshal(b, &sum) != nil || sum.Unavailable != 5 || sum.Audited != 0 {
		t.Fatalf("-json summary %+v (%v)", sum, err)
	}
}
