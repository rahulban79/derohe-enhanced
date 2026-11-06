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
	"testing"

	"github.com/deroproject/derohe/glue/emission"
)

// r27 (B36): -series-read prints the payee counts of an r27 checkpoint and 'pending' for a pre-r27 one (never 0).
func TestR27SeriesReadPayees(t *testing.T) {
	if s := SeriesPayees(emission.SeriesRecord{Payees: 0}); s != "pending (not recorded before r27)" {
		t.Fatalf("pre-r27 record: %q", s)
	}
	if s := SeriesPayees(emission.SeriesRecord{V: emission.SeriesV2, Payees: 7, PayeesVerified: 5, PayeesExplained: 6}); s != "7 verified 5 explained 6" {
		t.Fatalf("r27 record: %q", s)
	}
}
