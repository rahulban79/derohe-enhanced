package p2p

import (
	"testing"
	"time"

	"github.com/deroproject/derohe/cryptography/crypto"
)

func txid_n(n int) (h crypto.Hash) {
	h[0], h[1] = byte(n), byte(n>>8)
	return
}

// The live r19 sequence from one peer (derod.log 2026-10-27/28): announcements of 10 distinct txids, each failing;
// offsets in ms within each burst. Before r20 every announcement became a GetObject and a counted failure.
func TestTxAskReplayLiveFailureBursts(t *testing.T) {
	type ev struct {
		at time.Duration
		tx int
	}
	base := time.Unix(1793126737, 0)
	var seq []ev
	burst := func(start time.Duration, tx int, offs ...int) {
		for _, o := range offs {
			seq = append(seq, ev{start + time.Duration(o)*time.Millisecond, tx})
		}
	}
	burst(0, 1, 0, 257)                  // 11:45:37.987, .244
	burst(53*time.Second, 2, 0, 39, 126) // 11:46:31
	burst(116*time.Second, 3, 0, 47, 143)
	burst(223*time.Second, 4, 0)
	burst(256*time.Second, 5, 0)
	burst(526*time.Second, 6, 0, 79)
	burst(605*time.Second, 7, 0)
	burst(12*time.Hour, 8, 0, 171)
	burst(15*time.Hour, 9, 0, 10, 35, 35, 63, 95)
	burst(15*time.Hour+137*time.Second, 10, 0, 26)
	if len(seq) != 23 {
		t.Fatalf("replay has %d announcements, live log has 23", len(seq))
	}
	var c Connection
	asked := 0
	for _, e := range seq {
		if c.tx_asked.claim(txid_n(e.tx), base.Add(e.at)) {
			asked++
		}
	}
	if asked != 10 {
		t.Fatalf("requests issued = %d, want 10 (one per distinct txid)", asked)
	}
}

func TestTxAskHoldExpires(t *testing.T) {
	var s tx_ask_set
	now := time.Unix(1000, 0)
	if !s.claim(txid_n(1), now) {
		t.Fatal("first ask must be allowed")
	}
	if s.claim(txid_n(1), now.Add(TX_ASK_HOLD-time.Millisecond)) {
		t.Fatal("repeat inside the hold must be skipped")
	}
	if !s.claim(txid_n(2), now) {
		t.Fatal("a different txid is not affected")
	}
	if !s.claim(txid_n(1), now.Add(TX_ASK_HOLD)) {
		t.Fatal("after the hold the peer may be asked again")
	}
	var other Connection // the record is per connection: another peer is asked at once
	if !other.tx_asked.claim(txid_n(1), now) {
		t.Fatal("another connection must be able to ask for the same txid")
	}
}

func TestTxAskBounded(t *testing.T) {
	var s tx_ask_set
	now := time.Unix(1000, 0)
	for i := 0; i < 3*TX_ASK_MAX; i++ {
		if !s.claim(txid_n(i), now) {
			t.Fatalf("new txid %d refused while full (must fail open)", i)
		}
	}
	if n := s.size(); n > TX_ASK_MAX {
		t.Fatalf("record grew to %d entries, bound is %d", n, TX_ASK_MAX)
	}
	// expired entries are pruned to make room for new records
	later := now.Add(TX_ASK_HOLD)
	s.claim(txid_n(1<<15), later)
	if s.claim(txid_n(1<<15), later) {
		t.Fatal("after pruning, a new txid must be recorded again")
	}
}

// NotifyINV's selection: a burst of announcements of one missing txid from one peer yields one request; txids in a
// pool or on disk are never requested.
func TestTxsToFetchAsksOncePerPeer(t *testing.T) {
	var c Connection
	pool := map[crypto.Hash]bool{txid_n(2): true}
	disk := map[crypto.Hash]bool{txid_n(3): true}
	have := func(h crypto.Hash) bool { return pool[h] }
	on_disk := func(h crypto.Hash) bool { return disk[h] }
	list := [][32]byte{txid_n(1), txid_n(2), txid_n(3)}
	got := c.txs_to_fetch(list, 0, have, on_disk)
	if len(got) != 1 || crypto.Hash(got[0]) != txid_n(1) {
		t.Fatalf("first INV: fetch %x, want only txid 1", got)
	}
	for i := 0; i < 5; i++ { // the live burst: the same txid re-announced 5 more times within 100 ms
		if got := c.txs_to_fetch([][32]byte{txid_n(1)}, 0, have, on_disk); len(got) != 0 {
			t.Fatalf("repeat %d of the same txid was requested again", i)
		}
	}
	var other Connection
	if got := other.txs_to_fetch([][32]byte{txid_n(1)}, 0, have, on_disk); len(got) != 1 {
		t.Fatal("another peer announcing the same txid must still be asked")
	}
}
