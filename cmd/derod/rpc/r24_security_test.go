// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package rpc

// r24 (security, B28): forged-input tests for trust revocation, trusted probing scored into the aggregate, the
// aggregate-shortfall refusal no longer scored, and trust earned only by calls to served names (rpc_abuse.go).

import (
	"fmt"
	"testing"
	"time"

	"github.com/creachadair/jrpc2/code"
)

// r24_make_trusted gives every key the make_trusted history, interleaved in time (one table clock moving forward:
// make_trusted per key would replay times backwards into the shared aggregate bucket).
func r24_make_trusted(t *testing.T, tb *abuse_table, keys []string, end time.Time) {
	start := end.Add(-ABUSE_TRUST_AGE - time.Second)
	for i := 0; i < ABUSE_TRUST_CALLS; i++ {
		for k, key := range keys {
			at := start.Add(time.Duration(i)*(ABUSE_TRUST_AGE/ABUSE_TRUST_CALLS) + time.Duration(k)*time.Millisecond)
			if v, _ := tb.admit(key, "DERO.GetInfo", false, at); v != abuse_ok {
				t.Fatalf("honest history call %d of %s refused: %v", i, key, v)
			}
		}
	}
	for _, key := range keys {
		if !r24_trusted(tb, key, end) {
			t.Fatalf("%s is not trusted after its history", key)
		}
	}
}

func r24_keys(f string, n int) (r []string) {
	for k := 0; k < n; k++ {
		r = append(r, fmt.Sprintf(f, k+1))
	}
	return
}

func r24_trusted(tb *abuse_table, key string, now time.Time) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	e := tb.m[key]
	return e != nil && trusted_locked(e, now)
}

// The pre-warm escape: 16 keys of one /24 each made trusted (64 cheap calls over 10 min), then 10 unknown names/min
// each for 30 min. r23c admitted 4,800/4,800 (the same probes from fresh keys: 572). Now the pre-warmed fleet gets no
// more than a fresh one plus the revocation allowance.
func TestR24PrewarmedFleetBannedLikeFresh(t *testing.T) {
	run := func(prewarm bool) (through int) {
		tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
		now := time.Unix(1700000000, 0)
		start := now.Add(ABUSE_TRUST_AGE + time.Minute)
		keys := r24_keys("203.0.113.%d", 16)
		if prewarm {
			r24_make_trusted(t, tb, keys, start)
		}
		for step := 0; step < 300; step++ {
			for k, key := range keys {
				if v, _ := tb.admit(key, "Probe.N", true, start.Add(time.Duration(step)*6*time.Second+time.Duration(k)*10*time.Millisecond)); v == abuse_ok {
					through++
				}
			}
		}
		return
	}
	fresh, warm := run(false), run(true)
	t.Logf("probes admitted in 30 min: fresh keys %d, pre-warmed keys %d (of 4800)", fresh, warm)
	if warm > fresh+16*int(ABUSE_TRUST_PROBE_MAX/ABUSE_PTS_UNKNOWN_METHOD) {
		t.Fatalf("pre-warmed keys passed %d probes, fresh keys %d: trust still buys a probing budget", warm, fresh)
	}
}

// A trusted key outside any shared aggregate (its own /24) that probes loses its trust after at most
// ABUSE_TRUST_PROBE_MAX points, and must earn it again (age and calls restart).
func TestR24TrustRevokedByProbing(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	key := "192.0.2.40"
	make_trusted(t, tb, key, now)
	revoked_after := -1
	for i := 0; i < 20; i++ {
		at := now // one instant: no decay, so the line is exact
		tb.admit(key, "Probe.N", true, at)
		if !r24_trusted(tb, key, at) {
			revoked_after = i + 1
			break
		}
	}
	if revoked_after < 0 {
		t.Fatal("a trusted key sent 20 unknown names in 20 s and is still trusted")
	}
	if max := int(ABUSE_TRUST_PROBE_MAX / ABUSE_PTS_UNKNOWN_METHOD); revoked_after > max {
		t.Fatalf("trust revoked only after %d unknown names (line %d)", revoked_after, max)
	}
	// earned again only after a full new history
	for i := 0; i < ABUSE_TRUST_CALLS; i++ {
		tb.admit(key, "DERO.GetInfo", false, now.Add(time.Minute+time.Duration(i)*time.Second))
	}
	if r24_trusted(tb, key, now.Add(3*time.Minute)) {
		t.Fatal("trust came back before ABUSE_TRUST_AGE")
	}
	if !r24_trusted(tb, key, now.Add(ABUSE_TRUST_AGE+2*time.Minute)) {
		t.Fatal("trust never comes back after an honest history")
	}
}

// A trusted key that sends an unknown name while its /24 aggregate is banned is refused; it loses its trust once its
// probe score reaches ABUSE_TRUST_PROBE_MAX (r24 verify: not on the first name). Its known calls before that are served.
func TestR24TrustedProbeInBannedAggregateRefused(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	key := "203.0.113.250"
	make_trusted(t, tb, key, now)
	banned := false
	for i := 0; i < 400 && !banned; i++ { // fresh keys of the same /24 ban the aggregate
		v, _ := tb.admit(fmt.Sprintf("203.0.113.%d", 1+i%200), "Probe.N", true, now.Add(time.Duration(i)*time.Millisecond))
		banned = v == abuse_banned
	}
	at := now.Add(time.Second)
	if d := tb.banned_for("203.0.113.201", at); d <= 0 {
		t.Fatal("the scenario did not ban the aggregate")
	}
	if v, _ := tb.admit(key, "DERO.GetInfo", false, at); v != abuse_ok {
		t.Fatalf("a trusted key's known call inside a banned /24 was refused: %v", v)
	}
	if v, _ := tb.admit(key, "Probe.N", true, at); v == abuse_ok {
		t.Fatalf("a trusted key probing inside a banned /24 was admitted: %v", v)
	}
	// r24 verify: one refused probe does not cost an honest trusted key its trust; probing on does
	if !r24_trusted(tb, key, at) {
		t.Fatal("one unknown name inside a banned /24 revoked trust (a neighbour can then deny the key)")
	}
	for i := 0; i < int(ABUSE_TRUST_PROBE_MAX/ABUSE_PTS_UNKNOWN_METHOD); i++ {
		if v, _ := tb.admit(key, "Probe.N", true, at); v == abuse_ok {
			t.Fatalf("probe %d of a trusted key inside a banned /24 was admitted", i)
		}
	}
	if r24_trusted(tb, key, at) {
		t.Fatal("a key that kept probing inside a banned /24 kept its trust")
	}
	if v, _ := tb.admit(key, "DERO.GetInfo", false, at); v != abuse_banned {
		t.Fatalf("after losing trust the key still bypasses its aggregate's ban: %v", v)
	}
}

// Trusted keys' unknown names score into their aggregate: 16 trusted keys at 10/min each ban the /24 (for its
// untrusted keys) within minutes, as 16 fresh keys do.
func TestR24TrustedProbesScoreAggregate(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	r24_make_trusted(t, tb, r24_keys("198.51.100.%d", 16), now)
	// 3 unknown names each (15 points: far under the per-key revocation line), 48 in all
	for i := 0; i < 3; i++ {
		for k := 0; k < 16; k++ {
			tb.admit(fmt.Sprintf("198.51.100.%d", k+1), "Probe.N", true, now.Add(time.Duration(i)*time.Second))
		}
	}
	tb.mu.Lock()
	g := tb.m[ABUSE_AGG_PREFIX+"198.51.100.0/24"]
	var score float64
	if g != nil {
		score = decayed(g.score, g.score_at, now.Add(3*time.Second))
	}
	tb.mu.Unlock()
	if score < 48*ABUSE_PTS_UNKNOWN_METHOD*0.9 {
		t.Fatalf("aggregate score %.1f after 48 unknown names from its trusted keys", score)
	}
	for k := 0; k < 16; k++ {
		if !r24_trusted(tb, fmt.Sprintf("198.51.100.%d", k+1), now.Add(3*time.Second)) {
			t.Fatalf("key %d lost trust after only 3 unknown names", k+1)
		}
	}
}

// An honest established wallet polling ONE method this node lacks once per block (18 s), plus one bad-params reply a
// minute, for 2 h, twelve of them in one /24: never refused, never loses trust.
func TestR24HonestPollingKeepsTrust(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	r24_make_trusted(t, tb, r24_keys("192.0.2.%d", 12), now)
	for s := 0; s < 7200; s += 18 {
		for k := 0; k < 12; k++ {
			key := fmt.Sprintf("192.0.2.%d", k+1)
			at := now.Add(time.Duration(s)*time.Second + time.Duration(k)*time.Millisecond)
			if v, _ := tb.admit(key, "DERO.GetInfo", false, at); v != abuse_ok {
				t.Fatalf("t=%ds key %s known call refused: %v", s, key, v)
			}
			if v, _ := tb.admit(key, "DERO.NewMethod", true, at); v != abuse_ok {
				t.Fatalf("t=%ds key %s refused for polling a missing method: %v", s, key, v)
			}
			if s%54 == 0 && tb.observe(key, code.InvalidParams, at) > 0 {
				t.Fatalf("t=%ds key %s banned for one bad-params reply a minute", s, key)
			}
			if !r24_trusted(tb, key, at) {
				t.Fatalf("t=%ds key %s lost trust", s, key)
			}
		}
	}
}

// 12 fresh honest keys of one /24 at 150 known calls/s each (each under its own 200/s, together over the /24's
// 1,600/s): r23c scored every aggregate-only refusal and banned the /24 (134,916 calls refused as banned in 15 min).
// Now they are only rate-limited, and no ban is ever reached.
func TestR24AggregateShortfallNotScored(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	ok, limited := 0, 0
	for ms := 0; ms < 120000; ms += 100 {
		for k := 0; k < 12; k++ {
			for c := 0; c < 15; c++ {
				v, _ := tb.admit(fmt.Sprintf("100.64.7.%d", k+1), "DERO.GetInfo", false, now.Add(time.Duration(ms)*time.Millisecond))
				switch v {
				case abuse_ok:
					ok++
				case abuse_rate_limited:
					limited++
				default:
					t.Fatalf("ms=%d: an honest key under its own rate was BANNED", ms)
				}
			}
		}
	}
	if limited == 0 {
		t.Fatal("the scenario never reached the aggregate bucket: it does not test the shortfall")
	}
	tb.mu.Lock()
	g := tb.m[ABUSE_AGG_PREFIX+"100.64.7.0/24"]
	tb.mu.Unlock()
	if g == nil || g.score != 0 {
		t.Fatalf("aggregate-only refusals were scored: %+v", g)
	}
	t.Logf("2 min: %d admitted, %d rate-limited (%.1f%%), 0 banned", ok, limited, 100*float64(limited)/float64(ok+limited))
	// a key over ITS OWN bucket is still scored for hammering and ends banned
	banned := false
	for i := 0; i < 5000 && !banned; i++ {
		v, _ := tb.admit("100.64.9.1", "DERO.GetInfo", false, now.Add(200*time.Second))
		banned = v == abuse_banned
	}
	if !banned {
		t.Fatal("a key hammering past its own bucket is no longer banned")
	}
}

// Trust is earned by calls to names the node serves: 64 admitted unknown names over 10 min earn nothing.
func TestR24ProbesDoNotEarnTrust(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	key := "192.0.2.77"
	tb.admit(key, "DERO.GetInfo", false, now)
	for i := 1; i <= ABUSE_TRUST_CALLS+8; i++ { // 7.5/min, all inside the first 10 min (no revocation can fire)
		if v, _ := tb.admit(key, "Probe.N", true, now.Add(time.Duration(i)*8*time.Second)); v != abuse_ok {
			t.Fatalf("probe %d refused (%v): the scenario must stay under the ban line", i, v)
		}
	}
	if r24_trusted(tb, key, now.Add(ABUSE_TRUST_AGE+time.Minute)) {
		t.Fatal("a key earned trust with probes")
	}
}

// A ban (here from bad-params replies, which never revoke trust by themselves) still ends a key's trust through the
// strike memory: r24 revocation masks this rule for unknown names, so it is tested on its own path.
func TestR24StrikeEndsTrust(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	key := "192.0.2.12"
	make_trusted(t, tb, key, now)
	banned := false
	for i := 0; i < 60 && !banned; i++ {
		banned = tb.observe(key, code.InvalidParams, now.Add(time.Duration(i)*10*time.Millisecond)) > 0
	}
	if !banned {
		t.Fatal("60 bad-params replies in 0.6 s did not ban a trusted key")
	}
	if r24_trusted(tb, key, now.Add(ABUSE_BAN_BASE+time.Minute)) {
		t.Fatal("a key banned a minute ago is trusted again")
	}
}
