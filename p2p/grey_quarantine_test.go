package p2p

import (
	"fmt"
	"testing"
	"time"
)

func with_clean_quarantine() func() {
	grey_quarantine.Lock()
	saved := grey_quarantine.m
	grey_quarantine.m = map[string]*grey_quarantine_entry{}
	grey_quarantine.Unlock()
	return func() {
		grey_quarantine.Lock()
		grey_quarantine.m = saved
		grey_quarantine.Unlock()
	}
}

// The live r20 cycle: a dead gossiped address fails 8 handshakes, clean_up purges it, and the next gossip used to
// re-add it at FailCount 0. Now the purge quarantines it and gossip is refused.
func TestGreyPurgeQuarantinesAgainstRegossip(t *testing.T) {
	defer with_clean_tables(t)()
	defer with_clean_quarantine()()
	from, dead := "198.51.100.7", "89.38.99.117:8443"
	if !peer_add_gossip(dead, from) {
		t.Fatal("first gossip must admit the address")
	}
	for i := 0; i < 8; i++ {
		Peer_SetFail(dead)
	}
	clean_up()
	if IsPeerInList(dead) {
		t.Fatal("grey peer with 8 failures must be purged")
	}
	if !grey_quarantined("89.38.99.117", time.Now()) {
		t.Fatal("purge must quarantine the address")
	}
	if peer_add_gossip(dead, from) || IsPeerInList(dead) {
		t.Fatal("gossip re-admitted a quarantined dead address (the live 10 failures/min cycle)")
	}
	// other addresses are unaffected
	if !peer_add_gossip("192.0.2.10:11011", from) {
		t.Fatal("unrelated gossip refused")
	}
}

func TestGreyQuarantineSparesWhitelisted(t *testing.T) {
	defer with_clean_tables(t)()
	defer with_clean_quarantine()()
	addr := "203.0.113.5:11011"
	Peer_Add(&Peer{Address: addr, LastConnected: uint64(time.Now().Unix()), Whitelist: true})
	for i := 0; i < 12; i++ {
		Peer_SetFail(addr)
	}
	clean_up()
	if !IsPeerInList(addr) || grey_quarantined("203.0.113.5", time.Now()) {
		t.Fatal("a proven (whitelisted) peer must keep its back-off, not be purged or quarantined")
	}
}

func TestGreyQuarantineExpiresAndEscalates(t *testing.T) {
	defer with_clean_quarantine()()
	now := time.Unix(1793219000, 0)
	quarantine_grey("192.0.2.1", now)
	if !grey_quarantined("192.0.2.1", now.Add(GREY_QUARANTINE-time.Second)) {
		t.Fatal("quarantine ended early")
	}
	if grey_quarantined("192.0.2.1", now.Add(GREY_QUARANTINE)) {
		t.Fatal("quarantine did not expire")
	}
	later := now.Add(GREY_QUARANTINE)
	quarantine_grey("192.0.2.1", later) // second strike doubles
	if !grey_quarantined("192.0.2.1", later.Add(2*GREY_QUARANTINE-time.Second)) || grey_quarantined("192.0.2.1", later.Add(2*GREY_QUARANTINE)) {
		t.Fatal("second strike must quarantine for 2x")
	}
	if d := grey_quarantine_duration(10); d != GREY_QUARANTINE_MAX {
		t.Fatalf("duration not capped: %v", d)
	}
	grey_quarantine_clear("192.0.2.1")
	if grey_quarantined("192.0.2.1", later) {
		t.Fatal("clear did not forget the address")
	}
}

func TestGreyQuarantineClearedOnSuccess(t *testing.T) {
	defer with_clean_tables(t)()
	defer with_clean_quarantine()()
	addr := "192.0.2.44:11011"
	Peer_Add(&Peer{Address: addr, LastConnected: uint64(time.Now().Unix())})
	quarantine_grey("192.0.2.44", time.Now())
	Peer_SetSuccess(addr)
	if grey_quarantined("192.0.2.44", time.Now()) {
		t.Fatal("a peer that completed a handshake must leave quarantine")
	}
}

func TestGreyQuarantineBoundedFailOpen(t *testing.T) {
	defer with_clean_quarantine()()
	now := time.Unix(1793219000, 0)
	for i := 0; i < GREY_QUARANTINE_ENTRIES; i++ {
		quarantine_grey(fmt.Sprintf("10.%d.%d.1", i/250, i%250), now)
	}
	quarantine_grey("192.0.2.200", now)
	if grey_quarantine_size() > GREY_QUARANTINE_ENTRIES {
		t.Fatalf("table grew past its bound: %d", grey_quarantine_size())
	}
	if grey_quarantined("192.0.2.200", now) {
		t.Fatal("full table of live entries must fail open (not record)")
	}
	// expired entries make room
	quarantine_grey("192.0.2.201", now.Add(GREY_QUARANTINE))
	if !grey_quarantined("192.0.2.201", now.Add(GREY_QUARANTINE)) {
		t.Fatal("expired entries were not pruned to admit a new one")
	}
}

// grey_dials_per_hour models the dialer for one dead gossiped address: pick -> 4 s handshake timeout -> Peer_SetFail
// back-off, purge at 8 failures, re-gossip within regossip; with the quarantine the purge blocks re-gossip.
func grey_dials_per_hour(quarantine bool, hours int) float64 {
	defer with_clean_quarantine()()
	t := time.Unix(1793219000, 0)
	end := t.Add(time.Duration(hours) * time.Hour)
	const timeout, regossip = 4 * time.Second, 7 * time.Second
	dials := 0
	for t.Before(end) {
		if quarantine && grey_quarantined("89.38.99.117", t) {
			t = t.Add(regossip)
			continue
		}
		for fails := uint64(1); fails <= 8; fails++ { // one admission: 8 failed dials
			dials++
			t = t.Add(timeout + time.Duration(fail_backoff_seconds(fails))*time.Second)
		}
		if quarantine {
			quarantine_grey("89.38.99.117", t)
		}
		t = t.Add(regossip)
	}
	return float64(dials) / float64(hours)
}

func TestGreyQuarantineDialRateModel(t *testing.T) {
	before, after := grey_dials_per_hour(false, 24), grey_dials_per_hour(true, 24)
	t.Logf("dead grey address: %.1f dials/h before, %.2f dials/h after", before, after)
	if before < 50 || after > 2 {
		t.Fatalf("model: before %.1f/h after %.2f/h", before, after)
	}
}

func TestHandshakeFailureKind(t *testing.T) {
	if handshake_failure_kind(nil) != "unlisted" || handshake_failure_kind(&Peer{}) != "grey" || handshake_failure_kind(&Peer{Whitelist: true}) != "white" {
		t.Fatal("handshake failure kinds misclassified")
	}
}

// r21 merge (SP21-2 verifier probe): the first gossip of a dead address after its 8th failure, with no clean_up in
// between (the ping-path gossip batch, common.go), must not re-admit it at FailCount 0.
func TestGreyQuarantineNoBypassViaKnownEntry(t *testing.T) {
	defer with_clean_tables(t)()
	defer with_clean_quarantine()()
	from, dead := "198.51.100.7", "89.38.99.117:8443"
	if !peer_add_gossip(dead, from) {
		t.Fatal("first gossip must admit the address")
	}
	for i := 0; i < 8; i++ {
		Peer_SetFail(dead)
	}
	// no explicit clean_up here
	peer_add_gossip(dead, from)
	if IsPeerInList(dead) {
		peer_mutex.Lock()
		fc := peer_map[ParseIPNoError(dead)].FailCount
		peer_mutex.Unlock()
		t.Fatalf("dead grey address re-admitted (FailCount=%d) on the gossip right after its 8th failure", fc)
	}
	if !grey_quarantined("89.38.99.117", time.Now()) {
		t.Fatal("the purge must quarantine the address")
	}
}
