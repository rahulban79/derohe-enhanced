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
	"time"
)

func contention_map(f []interface{}) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(f); i += 2 {
		m[f[i].(string)] = f[i+1].(string)
	}
	return m
}

// r23 forensics: a starved window (same H/cpu-s, fewer cores) and an inefficient one (same cores, lower H/cpu-s) read
// differently; windows (no CPU time) reads "-".
func TestContentionFields(t *testing.T) {
	// 15 s at 86k H/s on 16 cores: 1,290,000 hashes, 240 CPU s
	a := contention_map(contention_fields(1290000, 240*time.Second, 15))
	if a["cpu_cores"] != "16.00" || a["H/cpu-s"] != "5375" {
		t.Fatalf("healthy window: %v", a)
	}
	// starved: 15 s at 59k H/s on 11 cores, same efficiency band
	b := contention_map(contention_fields(885000, 165*time.Second, 15))
	if b["cpu_cores"] != "11.00" || b["H/cpu-s"] != "5364" {
		t.Fatalf("starved window: %v", b)
	}
	// inefficient: 16 cores but half the hashes
	c := contention_map(contention_fields(645000, 240*time.Second, 15))
	if c["cpu_cores"] != "16.00" || c["H/cpu-s"] != "2688" {
		t.Fatalf("inefficient window: %v", c)
	}
	for _, f := range [][]interface{}{contention_fields(1000, 0, 15), contention_fields(1000, time.Second, 0)} {
		if m := contention_map(f); m["cpu_cores"] != "-" || m["H/cpu-s"] != "-" {
			t.Fatalf("unmeasured window: %v", m)
		}
	}
}
