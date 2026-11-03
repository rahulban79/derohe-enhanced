package rpc

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/lesismal/nbio/nbhttp/websocket"
)

func reset_absence(t *testing.T) {
	atomic.StoreInt32(&getwork_miner_seen, 0)
	atomic.StoreInt64(&getwork_absent_since_unix, 0)
	t.Cleanup(func() {
		atomic.StoreInt32(&getwork_miner_seen, 0)
		atomic.StoreInt64(&getwork_absent_since_unix, 0)
	})
}

func TestMinerAbsentSeconds(t *testing.T) {
	if got := miner_absent_seconds(false, 0, 100); got != -1 {
		t.Fatalf("never seen: %v, want -1", got)
	}
	if got := miner_absent_seconds(true, 0, 100); got != 0 {
		t.Fatalf("connected: %v, want 0", got)
	}
	if got := miner_absent_seconds(true, 40, 100); got != 60 {
		t.Fatalf("absent: %v, want 60", got)
	}
	if got := miner_absent_seconds(true, 200, 100); got != 0 {
		t.Fatalf("clock step back: %v, want 0", got)
	}
}

// the r23 pattern: miner connects, leaves by console exit, comes back hours later
func TestAbsenceClockFollowsRegisterUnregister(t *testing.T) {
	with_clients(t, nil)
	reset_absence(t)
	a, b := new(websocket.Conn), new(websocket.Conn)
	if _, _, n := getwork_unregister(a); n != 0 || atomic.LoadInt64(&getwork_absent_since_unix) != 0 {
		t.Fatal("an unregistered close before any miner started the absence clock")
	}
	getwork_register(a, &user_session{})
	getwork_register(b, &user_session{})
	if atomic.LoadInt32(&getwork_miner_seen) != 1 || atomic.LoadInt64(&getwork_absent_since_unix) != 0 {
		t.Fatal("register did not mark the miner present")
	}
	getwork_unregister(a)
	if atomic.LoadInt64(&getwork_absent_since_unix) != 0 {
		t.Fatal("one of two miners left: the node is not without a miner")
	}
	before := time.Now().Unix()
	getwork_unregister(b)
	since := atomic.LoadInt64(&getwork_absent_since_unix)
	if since < before || since > time.Now().Unix() {
		t.Fatalf("last miner left: absent since %d, want ~%d", since, before)
	}
	getwork_unregister(b) // duplicate close must not restart the clock
	if atomic.LoadInt64(&getwork_absent_since_unix) != since {
		t.Fatal("duplicate close moved the absence clock")
	}
	getwork_register(a, &user_session{})
	if atomic.LoadInt64(&getwork_absent_since_unix) != 0 {
		t.Fatal("a returning miner did not clear the absence")
	}
}

func TestMinerAbsentWarnAfter(t *testing.T) {
	cases := map[string]time.Duration{"": MINER_ABSENT_WARN_DEFAULT, "x": MINER_ABSENT_WARN_DEFAULT, "-3": MINER_ABSENT_WARN_DEFAULT,
		"0": 0, "25": 25 * time.Minute, " 5 ": 5 * time.Minute}
	for in, want := range cases {
		if got := miner_absent_warn_after(in); got != want {
			t.Fatalf("%q: %v, want %v", in, got, want)
		}
	}
}

func TestAbsenceWarnDue(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	if absence_warn_due(9*time.Minute, 10*time.Minute, time.Hour, time.Time{}, now) {
		t.Fatal("warned before the threshold")
	}
	if !absence_warn_due(10*time.Minute, 10*time.Minute, time.Hour, time.Time{}, now) {
		t.Fatal("no first warning at the threshold")
	}
	if absence_warn_due(30*time.Minute, 10*time.Minute, time.Hour, now.Add(-59*time.Minute), now) {
		t.Fatal("repeated inside the repeat interval")
	}
	if !absence_warn_due(70*time.Minute, 10*time.Minute, time.Hour, now.Add(-time.Hour), now) {
		t.Fatal("no repeat after the interval")
	}
	if absence_warn_due(10*time.Hour, 0, time.Hour, time.Time{}, now) {
		t.Fatal("warned while disabled")
	}
}

// the watcher: one warning at the threshold, none while a miner is back, a fresh one for a new absence
func TestRunAbsenceWatch(t *testing.T) {
	reset_absence(t)
	atomic.StoreInt32(&getwork_miner_seen, 1)
	t0 := time.Unix(2_000_000, 0)
	atomic.StoreInt64(&getwork_absent_since_unix, t0.Unix())
	tick := make(chan time.Time)
	warns := make(chan time.Duration, 16)
	done := make(chan struct{})
	go func() {
		run_absence_watch(10*time.Minute, tick, func(a time.Duration, _ time.Time) { warns <- a })
		close(done)
	}()
	step := func(at time.Time) { tick <- at }
	for m := 1; m <= 20; m++ {
		step(t0.Add(time.Duration(m) * time.Minute))
	}
	atomic.StoreInt64(&getwork_absent_since_unix, 0) // miner back
	step(t0.Add(21 * time.Minute))
	t1 := t0.Add(25 * time.Minute)                           // left again 15 min after the first warning: a new absence warns on its own clock
	atomic.StoreInt64(&getwork_absent_since_unix, t1.Unix()) // left again
	step(t1.Add(10 * time.Minute))
	close(tick)
	<-done
	close(warns)
	var got []time.Duration
	for a := range warns {
		got = append(got, a)
	}
	if len(got) != 2 || got[0] != 10*time.Minute || got[1] != 10*time.Minute {
		t.Fatalf("warnings %v, want [10m 10m] (one per absence, at the threshold)", got)
	}
}
