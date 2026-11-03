package gsplit

import (
	"sync/atomic"
	"testing"
	"time"
)

// r22 forensics: a busy span costs busy*100/cap of wall time; --gpu-max=100 (or an out-of-range value) costs nothing.
func TestDutyChargeCost(t *testing.T) {
	for _, c := range []struct {
		busy int64
		cap  int
		want int64
	}{{1000, 50, 2000}, {900, 90, 1000}, {1000, 100, 0}, {1000, 0, 0}, {1000, 101, 0}} {
		if got := dutyCharge(c.busy, c.cap); got != c.want {
			t.Fatalf("dutyCharge(%d, %d) = %d, want %d", c.busy, c.cap, got, c.want)
		}
	}
}

// The bucket credits the wall clock: 2 ms of charge is paid off by 2 ms of elapsed time.
func TestDutyCreditsWallTime(t *testing.T) {
	e := &Engine{}
	e.settleDuty(0)
	e.debt.Add(2_000_000)
	if d := e.settleDuty(1_000_000); d != 1_000_000 {
		t.Fatalf("owed after 1 ms = %d, want 1000000", d)
	}
	if d := e.settleDuty(2_000_000); d != 0 {
		t.Fatalf("owed after 2 ms = %d, want 0", d)
	}
}

// A long idle period banks at most dutyBurstNs of credit.
func TestDutyBurstBounded(t *testing.T) {
	e := &Engine{}
	e.settleDuty(0)
	if d := e.settleDuty(int64(10 * time.Second)); d != -dutyBurstNs {
		t.Fatalf("credit after 10 s idle = %d, want -%d", d, dutyBurstNs)
	}
	if d := e.debt.Load(); d != -dutyBurstNs {
		t.Fatalf("stored credit = %d, want -%d", d, dutyBurstNs)
	}
}

// The live r21 regime: a GPU that would run at 95% duty on its own. With the bucket gating the staging of work, the
// achieved duty over 20 simulated seconds stays at the cap (not above it, and not throttled far below it).
func TestDutyBucketHoldsCap(t *testing.T) {
	const step = int64(time.Millisecond)
	const natural = 950_000 // ns busy per ms when the feeder is not held
	for _, capPct := range []int{50, 75, 90} {
		e := &Engine{}
		e.settleDuty(0)
		var busy int64
		const T = int64(20 * time.Second)
		for now := int64(0); now < T; now += step {
			if e.settleDuty(now) > 0 {
				continue // the feeder holds: the GPU drains and idles this step
			}
			busy += natural
			e.debt.Add(dutyCharge(natural, capPct))
		}
		duty := float64(busy) * 100 / float64(T)
		if duty > float64(capPct)+1 || duty < float64(capPct)-2 {
			t.Fatalf("cap %d%%: achieved duty %.2f%% (natural 95%%)", capPct, duty)
		}
	}
}

// The feeder stages nothing while the bucket is in debt and a stop request is honoured while it waits (r21's
// time.Sleep(debt) ignored quit); once the debt is paid it resumes.
func TestFeederPaysDuty(t *testing.T) {
	rig := func(nexts *atomic.Int64) *rig {
		return newRigCfg(t, true, 8, 3, 0, func(c *Config) {
			c.GPUMax = 50
			next := c.Next
			c.Next = func() (Work, bool) { nexts.Add(1); return next() }
		})
	}
	closeWithin := func(e *Engine) {
		done := make(chan struct{})
		go func() { e.Close(); close(done) }()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Fatal("Close blocked behind the feeder's duty wait")
		}
	}
	var held, resumed atomic.Int64
	r := rig(&held)
	r.e.debt.Store(int64(time.Hour))
	r.e.Start()
	time.Sleep(200 * time.Millisecond)
	n := held.Load()
	closeWithin(r.e)
	if n != 0 {
		t.Fatalf("feeder staged %d batches while owing an hour of GPU duty", n)
	}

	r = rig(&resumed)
	r.e.debt.Store(int64(time.Hour))
	r.e.Start()
	time.Sleep(50 * time.Millisecond)
	r.e.debt.Store(0)
	deadline := time.Now().Add(20 * time.Second)
	for resumed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	closeWithin(r.e)
	if resumed.Load() == 0 {
		t.Fatal("feeder never resumed after the debt was paid")
	}
}
