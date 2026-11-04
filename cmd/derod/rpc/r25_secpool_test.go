// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package rpc

// r25 (secpool, B48): a fresh remote key holds a quarter of the burst until it is trusted; honest clients unaffected.

import (
	"fmt"
	"testing"
	"time"
)

// full_calls admits 256-txid GetTransaction calls (34 tokens each) for key at now until one is refused.
func r25_full_calls(tb *abuse_table, key string, now time.Time) (n int) {
	for ; n < 1000; n++ {
		if v, _ := tb.admit_items(key, "DERO.GetTransaction", false, item_cost(MAX_REMOTE_TX_HASHES), now); v != abuse_ok {
			return
		}
	}
	return
}

// B48: base 17da0dc admitted 58 full calls from a fresh key at once (2,000 tokens); now 14 (500 tokens). Once the
// key is trusted, its bucket refills to the full burst again.
func TestR25FreshKeyBurstQuarter(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	fresh := r25_full_calls(tb, "192.0.2.90", now)
	if want := int(ABUSE_DEFAULT_BURST*ABUSE_FRESH_BURST_FRAC) / 34; fresh != want {
		t.Fatalf("fresh key: %d full calls at once, want %d", fresh, want)
	}
	// an idle fresh key refills only to the fresh burst: one call, a minute of silence, then the same 14
	tb.admit("198.18.0.92", "DERO.GetInfo", false, now)
	if idle := r25_full_calls(tb, "198.18.0.92", now.Add(time.Minute)); idle != fresh {
		t.Fatalf("idle untrusted key: %d full calls after a minute, want %d", idle, fresh)
	}
	// earn trust: ABUSE_TRUST_CALLS served calls spread over ABUSE_TRUST_AGE
	for i := 0; i < ABUSE_TRUST_CALLS; i++ {
		tb.admit("192.0.2.91", "DERO.GetInfo", false, now.Add(time.Duration(i)*(ABUSE_TRUST_AGE/ABUSE_TRUST_CALLS)))
	}
	later := now.Add(ABUSE_TRUST_AGE + time.Minute)
	tb.admit("192.0.2.91", "DERO.GetInfo", false, later)
	tb.mu.Lock()
	tr := trusted_locked(tb.m["192.0.2.91"], later)
	tb.mu.Unlock()
	if !tr {
		t.Fatal("setup: key not trusted")
	}
	trusted := r25_full_calls(tb, "192.0.2.91", later.Add(time.Minute)) // a minute of refill: full bucket
	t.Logf("SECPOOL fresh-burst full_calls fresh=%d trusted=%d (r24: 58 each)", fresh, trusted)
	if trusted != int(ABUSE_DEFAULT_BURST)/34 {
		t.Fatalf("trusted key: %d full calls at once, want %d", trusted, int(ABUSE_DEFAULT_BURST)/34)
	}
}

// B48: one fresh key in each of 256 aggregates (/24s): the aggregate bucket does not bound them, the fresh burst does.
// Tokens admitted at once: base 256 x 58 x 34 = 504,832; now 256 x 14 x 34 = 121,856.
func TestR25FreshKeysAcrossAggregates(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	calls := 0
	for i := 0; i < 256; i++ {
		calls += r25_full_calls(tb, fmt.Sprintf("198.51.%d.9", i), now)
	}
	t.Logf("SECPOOL fresh-burst keys=256 aggregates=256 full_calls=%d tokens=%d (r24: %d)", calls, calls*34, 256*58*34)
	if calls > 256*int(ABUSE_DEFAULT_BURST*ABUSE_FRESH_BURST_FRAC)/34 {
		t.Fatalf("256 fresh keys got %d full calls at once", calls)
	}
}

// Honest clients never notice: an explorer page of 50 calls every 10 s, a wallet's 20 calls per block (18 s), a wallet
// first sync of 90 GetBlock/s (2 tokens each: 180 of the 200 tokens/s) for 30 s, all from fresh keys, each in its own
// /24 (each client's calls are in time order; the table refills by elapsed time): 0 refusals.
func TestR25FreshBurstHonestClientsUnaffected(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	refused, total := 0, 0
	call := func(key, m string, at time.Time) {
		total++
		if v, _ := tb.admit(key, m, false, at); v != abuse_ok {
			refused++
		}
	}
	for s := 0; s < 3600; s += 10 {
		for i := 0; i < 50; i++ {
			call("203.0.110.10", "DERO.GetBlockHeaderByTopoHeight", now.Add(time.Duration(s)*time.Second))
		}
	}
	for s := 0; s < 3600; s += 18 {
		for i := 0; i < 20; i++ {
			call("203.0.111.11", "DERO.GetEncryptedBalance", now.Add(time.Duration(s)*time.Second))
		}
	}
	for ms := 0; ms < 30000; ms += 11 { // ~90 calls/s
		call("203.0.113.12", "DERO.GetBlock", now.Add(time.Duration(ms)*time.Millisecond))
	}
	t.Logf("SECPOOL fresh-burst honest refused=%d of %d", refused, total)
	if refused != 0 {
		t.Fatalf("honest clients refused %d of %d calls", refused, total)
	}
}
