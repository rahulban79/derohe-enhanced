package p2p

import "errors"
import "sync"
import "testing"
import "time"

func TestSummarizeAcks(t *testing.T) {
	s := summarize_acks(5, []time.Duration{300 * time.Millisecond, 100 * time.Millisecond, 200 * time.Millisecond}, 2)
	if s.Peers != 5 || s.Acked != 3 || s.Failed != 2 || s.First != 100*time.Millisecond || s.Median != 200*time.Millisecond || s.Last != 300*time.Millisecond {
		t.Fatalf("bad summary %+v", s)
	}
	if z := summarize_acks(4, nil, 4); z.Acked != 0 || z.First != 0 || z.Failed != 4 {
		t.Fatalf("all-failed summary %+v", z)
	}
}

// acks may complete before the dispatch loop reports how many it launched; exactly one report must follow either way.
func TestOwnAckTrackerReportsOnceRegardlessOfOrder(t *testing.T) {
	start := time.Unix(1000, 0)
	for _, early := range []int{0, 2, 3} {
		var got []ack_summary
		tr := new_own_ack_tracker(start, func(s ack_summary) { got = append(got, s) })
		for i := 0; i < early; i++ {
			tr.done(nil, start.Add(time.Duration(i+1)*time.Millisecond))
		}
		if len(got) != 0 {
			t.Fatalf("reported before launch count known (early=%d)", early)
		}
		tr.launched(3)
		for i := early; i < 3; i++ {
			var err error
			if i == 2 {
				err = errors.New("timeout")
			}
			tr.done(err, start.Add(time.Duration(i+1)*time.Millisecond))
		}
		if len(got) != 1 || got[0].Peers != 3 || got[0].Acked+got[0].Failed != 3 {
			t.Fatalf("early=%d: want exactly one complete report, got %+v", early, got)
		}
	}
	// zero peers: report immediately on launch
	n := 0
	new_own_ack_tracker(start, func(ack_summary) { n++ }).launched(0)
	if n != 1 {
		t.Fatalf("zero-peer broadcast must still report once, got %d", n)
	}
}

func TestOwnAckTrackerConcurrent(t *testing.T) {
	var mu sync.Mutex
	reports := 0
	tr := new_own_ack_tracker(time.Now(), func(ack_summary) { mu.Lock(); reports++; mu.Unlock() })
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); tr.done(nil, time.Now()) }()
	}
	tr.launched(64)
	wg.Wait()
	if reports != 1 {
		t.Fatalf("want 1 report, got %d", reports)
	}
}

func TestFailureReason(t *testing.T) {
	cases := map[string]string{
		"collision 0a1b2c": "duplicate",
		"Peer.NotifyMiniBlock: no answer within 10s: context deadline exceeded": "timeout",
		"tip could not be expanded":      "peer_behind",
		"Stale Miniblock":                "peer_behind",
		"unregistered miner":             "peer_unregistered",
		"connection is shut down":        "connection",
		"io: read/write on closed pipe":  "connection",
		"final blocks are not propagted": "other",
	}
	for m, want := range cases {
		if got := failure_reason(errors.New(m)); got != want {
			t.Errorf("failure_reason(%q)=%q want %q", m, got, want)
		}
	}
	if failure_reason(nil) != "" {
		t.Fatal("nil error must have no reason")
	}
}

func TestOwnAckTrackerCarriesReasons(t *testing.T) {
	var got ack_summary
	tr := new_own_ack_tracker(time.Unix(0, 0), func(s ack_summary) { got = s })
	tr.done(errors.New("collision ff"), time.Unix(0, 1))
	tr.done(errors.New("collision ee"), time.Unix(0, 2))
	tr.done(errors.New("tip could not be expanded"), time.Unix(0, 3))
	tr.done(nil, time.Unix(0, 4))
	tr.launched(4)
	if got.Failed != 3 || got.Reasons["duplicate"] != 2 || got.Reasons["peer_behind"] != 1 || len(got.Reasons) != 2 {
		t.Fatalf("reasons not carried into the report: %+v", got)
	}
}
