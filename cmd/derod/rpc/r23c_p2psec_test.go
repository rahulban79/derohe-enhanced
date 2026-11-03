// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package rpc

// r23c (p2psec): adversarial tests for the remote-RPC trust / aggregate / surge-ordering rules (rpc_abuse.go).

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/jrpc2/code"
)

func aggregate_records(t *abuse_table) (n int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k := range t.m {
		if strings.HasPrefix(k, ABUSE_AGG_PREFIX) {
			n++
		}
	}
	return
}

// make_trusted gives key a history of ABUSE_TRUST_CALLS honest calls spread over ABUSE_TRUST_AGE, ending at end.
func make_trusted(t *testing.T, tb *abuse_table, key string, end time.Time) {
	start := end.Add(-ABUSE_TRUST_AGE - time.Second)
	for i := 0; i < ABUSE_TRUST_CALLS; i++ {
		at := start.Add(time.Duration(i) * (ABUSE_TRUST_AGE / ABUSE_TRUST_CALLS))
		if v, _ := tb.admit(key, "DERO.GetInfo", false, at); v != abuse_ok {
			t.Fatalf("honest history call %d refused: %v", i, v)
		}
	}
	tb.mu.Lock()
	ok := trusted_locked(tb.m[key], end)
	tb.mu.Unlock()
	if !ok {
		t.Fatalf("%s is not trusted after its history", key)
	}
}

// drain_global empties the global anomaly bucket from many fresh keys, each in its own /16, as an attacker would.
func drain_global(tb *abuse_table, salt int, at time.Time) {
	for i := 0; i < int(ABUSE_GLOBAL_ANOMALY_BURST)+20; i++ { // fresh keys every round: banned keys no longer drain it
		tb.admit(fmt.Sprintf("%d.%d.%d.9", 20+salt, i/250, i%250), "Probe.Unknown", true, at)
	}
}

// The surge was triggerable on purpose: an attacker drains the global bucket and an honest, established wallet that
// sends a few malformed calls a minute is then banned at x4. Trusted keys now score x1 during a surge; a fresh key
// with the same pattern is still banned (the surge keeps working against new identities).
func TestR23cSurgeSparesTrustedKeys(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	make_trusted(t, tb, "192.0.2.10", now)
	fresh_banned, trusted_banned := false, false
	// 12 invalid-params replies 5 s apart (12/min): x1 the score peaks near 3*12*~0.9 < 100, x4 it passes 100
	for i := 0; i < 12; i++ {
		at := now.Add(time.Duration(i) * 5 * time.Second)
		drain_global(tb, i, at) // the attacker keeps the surge on
		if tb.surge_gauge(at) != 1 {
			t.Fatal("the surge is not on: the test does not test the surge")
		}
		if tb.observe("192.0.2.10", code.InvalidParams, at) > 0 {
			trusted_banned = true
		}
		if tb.observe("198.51.100.20", code.InvalidParams, at) > 0 {
			fresh_banned = true
		}
	}
	if trusted_banned {
		t.Fatal("an established wallet was banned by someone else's surge (r23b SEC: surge triggerable on purpose)")
	}
	if !fresh_banned {
		t.Fatal("a fresh key at 12 invalid calls/min during a surge was not banned: the surge no longer works")
	}
	if v, _ := tb.admit("192.0.2.10", "DERO.GetInfo", false, now.Add(61*time.Second)); v != abuse_ok {
		t.Fatalf("trusted key refused after the surge: %v", v)
	}
}

// A trusted key still has its own per-key line: trust is not immunity.
func TestR23cTrustedKeyStillBannedByOwnLine(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	make_trusted(t, tb, "192.0.2.11", now)
	banned := false
	for i := 0; i < 25 && !banned; i++ {
		if v, _ := tb.admit("192.0.2.11", "Probe.N", true, now.Add(time.Duration(i)*100*time.Millisecond)); v == abuse_banned {
			banned = true
		}
	}
	if !banned {
		t.Fatal("25 unknown names in 2.5 s from a trusted key were not banned")
	}
	tb.mu.Lock()
	tr := trusted_locked(tb.m["192.0.2.11"], now.Add(3*time.Second))
	tb.mu.Unlock()
	if tr {
		t.Fatal("a key that was just banned is still trusted")
	}
}

// Rotating identities inside one IPv4 /24: 16 keys, each 10 unknown names/min (alone a key settles at ~72 of 100, so
// a per-key line never fires) and 2.7 anomalies/s in total (under the 10/s global rate, so no surge either). Before
// r23c nothing ever banned them; now the /24 aggregate does, for its untrusted keys only.
func TestR23cAggregateBansRotatingSlash24(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	make_trusted(t, tb, "203.0.113.250", now) // an honest established client in the same /24
	agg_banned_at := -1
	for step := 0; step < 30 && agg_banned_at < 0; step++ { // 6 s steps: 10/min per key
		for k := 0; k < 16; k++ {
			at := now.Add(time.Duration(step)*6*time.Second + time.Duration(k)*10*time.Millisecond)
			key := fmt.Sprintf("203.0.113.%d", k+1)
			v, _ := tb.admit(key, "Probe.N", true, at)
			tb.mu.Lock()
			own := tb.m[key].banned_until.After(at)
			tb.mu.Unlock()
			if own {
				t.Fatalf("step %d: key %s reached its own line at 10/min: the scenario is wrong", step, key)
			}
			if v == abuse_banned {
				agg_banned_at = step
				break
			}
		}
	}
	if agg_banned_at < 0 {
		t.Fatal("16 rotating keys of one /24 probed 480 unknown names in 3 min and nothing banned them")
	}
	t.Logf("aggregate ban after %d s", agg_banned_at*6)
	at := now.Add(time.Duration(agg_banned_at)*6*time.Second + time.Second)
	if v, _ := tb.admit("203.0.113.77", "DERO.GetInfo", false, at); v != abuse_banned {
		t.Fatalf("a NEW key of the banned /24 was admitted: %v", v)
	}
	if d := tb.banned_for("203.0.113.78", at); d <= 0 {
		t.Fatal("banned_for (websocket upgrade check) does not see the aggregate ban")
	}
	if v, _ := tb.admit("203.0.113.250", "DERO.GetInfo", false, at); v != abuse_ok {
		t.Fatalf("an established client inside the banned /24 was refused: %v", v)
	}
	if d := tb.banned_for("203.0.113.250", at); d != 0 {
		t.Fatal("banned_for refuses the trusted key's websocket")
	}
	if v, _ := tb.admit("203.0.114.5", "DERO.GetInfo", false, at); v != abuse_ok {
		t.Fatalf("a key of the neighbouring /24 was refused: %v", v)
	}
}

// Same for IPv6: 16 /64 keys inside one /48.
func TestR23cAggregateBansRotatingSlash48(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	var banned_at time.Time
	for step := 0; step < 30 && banned_at.IsZero(); step++ {
		for k := 0; k < 16; k++ {
			at := now.Add(time.Duration(step)*6*time.Second + time.Duration(k)*10*time.Millisecond)
			key := abuse_key(fmt.Sprintf("2001:db8:4242:%x::1", k))
			if v, _ := tb.admit(key, "Probe.N", true, at); v == abuse_banned {
				banned_at = at
				break
			}
		}
	}
	if banned_at.IsZero() {
		t.Fatal("16 rotating /64s of one /48 were never banned")
	}
	at := banned_at.Add(time.Second)
	if v, _ := tb.admit(abuse_key("2001:db8:4242:ffff::9"), "DERO.GetInfo", false, at); v != abuse_banned {
		t.Fatalf("a new /64 of the banned /48 was admitted: %v", v)
	}
	if v, _ := tb.admit(abuse_key("2001:db8:4243::1"), "DERO.GetInfo", false, at); v != abuse_ok {
		t.Fatalf("a neighbouring /48 was refused: %v", v)
	}
}

// Ordinary handler errors ("not found") are honest-client noise: they never reach the aggregate.
func TestR23cHandlerErrorsDoNotBanAggregate(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	for i := 0; i < 2000; i++ {
		key := fmt.Sprintf("192.0.2.%d", 1+i%200)
		if tb.observe(key, code.Code(-32098), now.Add(time.Duration(i)*10*time.Millisecond)) > 0 {
			t.Fatalf("call %d: handler errors spread over 200 keys banned something", i)
		}
	}
	tb.mu.Lock()
	g := tb.m[ABUSE_AGG_PREFIX+"192.0.2.0/24"]
	tb.mu.Unlock()
	if g == nil || g.score != 0 {
		t.Fatalf("aggregate scored ordinary handler errors: %+v", g)
	}
}

// Rotating identities could multiply the per-key bucket: 64 fresh keys of one /24 each with a 2000-call burst. The
// untrusted keys now share the aggregate bucket (ABUSE_AGG_SCALE x a key's); a trusted key keeps its own.
func TestR23cAggregateBucketBoundsRotatingFlood(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	make_trusted(t, tb, "198.51.100.250", now)
	admitted := 0
	for k := 0; k < 64; k++ {
		for i := 0; i < 2000; i++ {
			if v, _ := tb.admit(fmt.Sprintf("198.51.100.%d", k+1), "DERO.GetInfo", false, now); v == abuse_ok {
				admitted++
			}
		}
	}
	limit := int(ABUSE_DEFAULT_BURST * ABUSE_AGG_SCALE)
	t.Logf("64 rotating keys: %d calls admitted at one instant (aggregate burst %d, per-key bursts would give %d)", admitted, limit, 64*2000)
	if admitted > limit {
		t.Fatalf("rotating keys got %d calls past an aggregate burst of %d", admitted, limit)
	}
	if v, _ := tb.admit("198.51.100.250", "DERO.GetInfo", false, now); v != abuse_ok {
		t.Fatalf("the trusted key of the flooded /24 was refused: %v", v)
	}
}

// SEC23b-2: a banned key's anomalies must not draw on the global budget (they are refused anyway), or a banned
// flooder alone keeps the surge on for everyone.
func TestR23cBannedKeyDoesNotDrainGlobal(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	for i := 0; i < 40; i++ { // ban the key (unknown names, 5 pts each)
		tb.admit("192.0.2.99", "Probe.N", true, now)
	}
	if tb.banned_for("192.0.2.99", now) <= 0 {
		t.Fatal("setup: key not banned")
	}
	tb.mu.Lock()
	before := tb.g_tokens
	tb.mu.Unlock()
	for i := 0; i < 5000; i++ {
		tb.observe("192.0.2.99", code.InvalidParams, now)
	}
	tb.mu.Lock()
	after := tb.g_tokens
	tb.mu.Unlock()
	if after != before {
		t.Fatalf("a banned key drew %.0f global anomaly tokens", before-after)
	}
	if tb.surge_gauge(now) != 0 {
		t.Fatal("a single banned key put the node into a surge")
	}
}

func TestR23cAggKey(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":           ABUSE_AGG_PREFIX + "203.0.113.0/24",
		"2001:db8:1:2::/64":     ABUSE_AGG_PREFIX + "2001:db8:1::/48",
		"127.0.0.1":             "",
		"::1":                   "",
		"not-an-ip":             "",
		FOREIGN_LIMIT_KEY:       "",
		ABUSE_OVERFLOW_KEY:      "",
		"10.0.0.0/8":            "",
		"2001:db8::/32":         "", // wider than /48: never aggregated upwards
		"::ffff:198.51.100.200": ABUSE_AGG_PREFIX + "198.51.100.0/24",
	} {
		if got := abuse_agg_key(in); got != want {
			t.Errorf("abuse_agg_key(%q) = %q, want %q", in, got, want)
		}
	}
}

// aggregate records share the bounded table: a spray of /24s cannot grow memory past max_entries.
func TestR23cAggregateRecordsBounded(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, 256)
	now := time.Unix(1700000000, 0)
	for i := 0; i < 5000; i++ {
		tb.admit(fmt.Sprintf("%d.%d.%d.1", 11+i/65536, (i/256)%256, i%256), "Probe.N", true, now)
	}
	if n := tb.size(); n > 256+1 {
		t.Fatalf("table grew to %d records (bound 256 + overflow)", n)
	}
}

// A key caches its aggregate record; when a prune drops that record, the key must look the aggregate up again, or
// its points go to a detached record that no other key of the /24 (and no admission check) ever sees.
func TestR23cAggregateCacheFollowsPrune(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, 64)
	now := time.Unix(1700000000, 0)
	for i := 0; i < 40; i++ { // A is banned once: its strike memory keeps it in the table, its aggregate is idle
		tb.admit("203.0.113.5", "Probe.N", true, now)
	}
	later := now.Add(2 * time.Hour) // A's ban ended; the aggregate's score decayed to nothing
	for i := 0; i < 200; i++ {      // fill the table with other keys: a prune runs and drops the idle aggregate
		tb.admit(fmt.Sprintf("10.%d.%d.1", i/250, i%250), "DERO.GetInfo", false, later.Add(time.Duration(i)*time.Millisecond))
	}
	tb.mu.Lock()
	_, kept := tb.m["203.0.113.5"]
	_, agg := tb.m[ABUSE_AGG_PREFIX+"203.0.113.0/24"]
	tb.mu.Unlock()
	if !kept || agg {
		t.Fatalf("setup: key kept %v, aggregate kept %v (want true, false)", kept, agg)
	}
	at := later.Add(2 * time.Minute) // the fillers are idle now: the next new record's prune makes room again
	tb.observe("203.0.113.5", code.InvalidParams, at)
	tb.observe("203.0.113.6", code.InvalidParams, at)
	tb.mu.Lock()
	g := tb.m[ABUSE_AGG_PREFIX+"203.0.113.0/24"]
	tb.mu.Unlock()
	if g == nil || g.score < 2*ABUSE_PTS_BAD_REQUEST-0.01 {
		t.Fatalf("after a prune the key scored into a detached aggregate: live record %+v", g)
	}
}
