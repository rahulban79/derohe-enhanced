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
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/deroproject/derohe/glue/emission"
)

// r29 (B110): -sc-blocks-out writes one line per audited block WITH SC calls (no other block), carries the plaintext
// SC figures and the verdict as the auditor computed them, and scrubs every hex key out of notes, alerts and errors.
func TestR29SCBlockExport(t *testing.T) {
	var b bytes.Buffer
	a := &archiveRun{sc: &b, now: func() int64 { return 0 }}
	key := strings.Repeat("ab", 16)
	a.each(10, emission.Report{Height: 10, BLID: "x", SCCalls: 0, Verdict: emission.VerdictOK}, nil)
	a.each(11, emission.Report{Height: 11, BLID: "y", Txs: 2, SCCalls: 1, SCDeposits: 400, SCDelta: "100", SCPayout: 300,
		Verdict: emission.VerdictOKSC, Notes: []string{"account " + key + " note"}, Alerts: []string{"alert " + key}}, nil)
	a.each(12, emission.Report{Height: 12, SCCalls: 2, Verdict: emission.VerdictError}, errors.New("tx "+key+" failed"))
	a.each(13, emission.Report{Height: 13, SCCalls: 1}, emission.ErrUnavailable)
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 SC lines (blocks 11, 12), got %d: %q", len(lines), b.String())
	}
	var x scBlock
	if err := json.Unmarshal([]byte(lines[0]), &x); err != nil {
		t.Fatal(err)
	}
	if x.Topo != 11 || x.Height != 11 || x.SCCalls != 1 || x.SCDeposits != 400 || x.SCDelta != "100" || x.SCPayout != 300 ||
		x.Verdict != emission.VerdictOKSC || x.Txs != 2 {
		t.Fatalf("block 11 exported as %+v", x)
	}
	if strings.Contains(b.String(), key) || len(x.Notes) != 1 || x.Notes[0] != "account <key> note" || x.Alerts[0] != "alert <key>" {
		t.Fatalf("a hex key reached the export: %s", b.String())
	}
	var y scBlock
	json.Unmarshal([]byte(lines[1]), &y)
	if y.Topo != 12 || y.Error != "tx <key> failed" {
		t.Fatalf("block 12 exported as %+v", y)
	}
}
