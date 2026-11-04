package rpc

// r24 verify (security): forged-input test for SEC24-2. Once the /24 aggregate bucket is drained, a key whose OWN bucket
// is full must not be able to retry forever unscored (on a websocket only a ban closes the socket).

import (
	"fmt"
	"testing"
	"time"
)

func TestR24VerifyAggShortRetryFloodEndsBanned(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	// keys drain the aggregate (burst 8 x 2000) within one instant; r25 (B48): a fresh key holds 500 tokens, so 33 keys
	// spend their fresh bursts (16,500 >= 16,000) instead of 9 spending 2,000
	per_key := int(ABUSE_DEFAULT_BURST * ABUSE_FRESH_BURST_FRAC)
	for k := 0; k < int(ABUSE_DEFAULT_BURST*ABUSE_AGG_SCALE)/per_key+1; k++ {
		for c := 0; c < per_key; c++ {
			tb.admit(fmt.Sprintf("198.18.5.%d", k+1), "DERO.GetInfo", false, now)
		}
	}
	// one more key, own bucket full, floods at 100x its own 200/s rate. r25 (B48): for 0.25 s (5,000 calls), because a
	// fresh key's own bucket is 500 tokens: within 0.25 s the aggregate's own refill (1,600/s) cannot empty it, so only
	// the debit of refused calls can make the key own_short (before r25: 20,000 calls in 1 s against 2,000 tokens)
	limited, banned := 0, 0
	for i := 0; i < 5000; i++ {
		v, _ := tb.admit("198.18.5.200", "DERO.GetInfo", false, now.Add(time.Duration(i)*50*time.Microsecond))
		switch v {
		case abuse_rate_limited:
			limited++
		case abuse_banned:
			banned++
		}
	}
	t.Logf("flooding key: %d rate-limited, %d banned of 5000", limited, banned)
	if banned == 0 {
		t.Fatalf("a key retrying at 100x its own rate against a drained aggregate was never banned (%d unscored refusals)", limited)
	}
}

// A neighbour in the same /24 keeps the aggregate banned (rotating fresh keys, 10 unknown names/s). An honest TRUSTED
// wallet that polls one missing method per block (3.3/min) and calls GetInfo every 2 s keeps its service: base 04ceb55
// refused 0 of 1,800; the first r24 build refused 1,767 (trust revoked on its first missing-method poll).
func TestR24VerifyNeighbourCannotRevokeHonestTrust(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	honest := "203.0.113.10"
	make_trusted(t, tb, honest, now)
	refused, total, aggbanned := 0, 0, 0
	for ms := 0; ms < 3600*1000; ms += 100 {
		at := now.Add(time.Duration(ms) * time.Millisecond)
		tb.admit(fmt.Sprintf("203.0.113.%d", 100+(ms/100)%150), "Probe.X", true, at)
		if ms%60000 == 0 {
			tb.mu.Lock()
			if g := tb.m[ABUSE_AGG_PREFIX+"203.0.113.0/24"]; g != nil && at.Before(g.banned_until) {
				aggbanned++
			}
			tb.mu.Unlock()
		}
		if ms%18000 == 0 {
			tb.admit(honest, "DERO.MissingOnThisNode", true, at)
		}
		if ms%2000 == 0 {
			total++
			if v, _ := tb.admit(honest, "DERO.GetInfo", false, at); v != abuse_ok {
				refused++
			}
		}
	}
	t.Logf("aggregate banned at %d of 60 minute marks; honest trusted key: %d of %d GetInfo refused", aggbanned, refused, total)
	if aggbanned < 30 {
		t.Fatalf("the neighbour did not keep the /24 banned (%d/60): the scenario tests nothing", aggbanned)
	}
	if refused > 0 {
		t.Fatalf("a neighbour's /24 ban denied an honest trusted wallet: %d of %d calls refused", refused, total)
	}
	if !r24_trusted(tb, honest, now.Add(time.Hour)) {
		t.Fatal("the honest wallet lost its trust")
	}
}
