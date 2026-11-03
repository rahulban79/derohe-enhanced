package main

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// simBox is a simulated miner for the duty tuner: hashes accrue at rate(cpu, gpu, t) H/s on a fake clock.
type simBox struct {
	t        time.Time
	t0       time.Time
	hashes   float64
	cpu, gpu int
	maxSet   int
	minSet   int
	rate     func(cpu, gpu int, el time.Duration) float64
	ep       uint64
	bumpAt   int // bump the epoch during this wait call (0 = never)
	waits    int
	stopAt   int // wait returns false at this call (0 = never)
	log      []string
	stopOnCv bool // stop at the first "converged"
}

func newSimBox(rate func(cpu, gpu int, el time.Duration) float64) *simBox {
	t := time.Unix(1700000000, 0)
	return &simBox{t: t, t0: t, cpu: 90, gpu: 90, maxSet: 0, minSet: 101, rate: rate}
}

func (b *simBox) tuner(floor int, knobs ...string) *duty_tuner {
	tu := &duty_tuner{count: func() uint64 { return uint64(b.hashes) }, epoch: func() uint64 { return b.ep },
		valid: func() bool { return true }, window: 60 * time.Second, settle: 10 * time.Second, hold: 30 * time.Minute,
		step: 5, margin: 0.005, z: duty_tune_z, now: func() time.Time { return b.t }}
	tu.wait = func(d time.Duration) bool {
		b.waits++
		if b.stopAt != 0 && b.waits >= b.stopAt {
			return false
		}
		if b.bumpAt != 0 && b.waits == b.bumpAt {
			b.ep++
		}
		// integrate in 1 s steps (the rate may depend on time: drift)
		for s := time.Duration(0); s < d; s += time.Second {
			b.hashes += b.rate(b.cpu, b.gpu, b.t.Sub(b.t0))
			b.t = b.t.Add(time.Second)
		}
		return true
	}
	tu.logf = func(msg string, kv ...interface{}) {
		line := fmt.Sprint(append([]interface{}{msg}, kv...)...)
		b.log = append(b.log, line)
		if b.stopOnCv && strings.Contains(line, "converged") {
			b.stopAt = b.waits + 1 // the hold wait returns false
		}
	}
	set := func(p *int) func(int) int {
		return func(v int) int {
			v = clamp_duty(v, 1)
			if v > b.maxSet {
				b.maxSet = v
			}
			if v < b.minSet {
				b.minSet = v
			}
			*p = v
			return v
		}
	}
	for _, k := range knobs {
		switch k {
		case "cpu":
			tu.knobs = append(tu.knobs, &duty_knob{name: "cpu", get: func() int { return b.cpu }, set: set(&b.cpu), floor: floor, dir: 1})
		case "gpu":
			tu.knobs = append(tu.knobs, &duty_knob{name: "gpu", get: func() int { return b.gpu }, set: set(&b.gpu), floor: floor, dir: 1})
		}
	}
	return tu
}

func (b *simBox) logs() string { return strings.Join(b.log, "\n") }

// More duty, more hashes: the tuner climbs 90 -> 95 -> 100, never sets more than 100, and converges there.
func TestDutyTunerClimbsToHundredNeverAbove(t *testing.T) {
	b := newSimBox(func(cpu, gpu int, _ time.Duration) float64 { return 800*float64(cpu) + 100*float64(gpu) })
	b.stopOnCv = true
	tu := b.tuner(50, "cpu", "gpu")
	tu.run()
	if b.cpu != 100 || b.gpu != 100 {
		t.Fatalf("converged at cpu %d gpu %d, want 100/100\n%s", b.cpu, b.gpu, b.logs())
	}
	if b.maxSet > 100 {
		t.Fatalf("a cap above 100 was set (%d)", b.maxSet)
	}
	if atomic.LoadUint64(&tu.kept) != 4 || !strings.Contains(b.logs(), "converged") {
		t.Fatalf("kept %d steps, want 4 (cpu 90->95->100, gpu 90->95->100)\n%s", tu.kept, b.logs())
	}
}

// A thermal peak at 95: kept 90 -> 95, rejected 95 -> 100 and 95 -> 90: converged at 95.
func TestDutyTunerFindsPeak(t *testing.T) {
	b := newSimBox(func(cpu, gpu int, _ time.Duration) float64 {
		d := cpu - 95
		if d < 0 {
			d = -d
		}
		return 100000 - 1000*float64(d)
	})
	b.stopOnCv = true
	b.tuner(50, "cpu").run()
	if b.cpu != 95 {
		t.Fatalf("converged at %d, want 95\n%s", b.cpu, b.logs())
	}
}

// No gain beyond the margin (flat rate): the cap stays where it was.
func TestDutyTunerFlatStays(t *testing.T) {
	b := newSimBox(func(cpu, gpu int, _ time.Duration) float64 { return 80000 + float64(cpu) }) // +0.006% per step
	b.stopOnCv = true
	tu := b.tuner(50, "cpu")
	tu.run()
	if b.cpu != 90 || tu.kept != 0 || tu.reverted != 2 {
		t.Fatalf("cpu %d kept %d reverted %d, want 90/0/2\n%s", b.cpu, tu.kept, tu.reverted, b.logs())
	}
}

// Less duty is better (a hot box): the tuner goes down, but never below the floor.
func TestDutyTunerFloor(t *testing.T) {
	b := newSimBox(func(cpu, gpu int, _ time.Duration) float64 { return 200000 - 1000*float64(cpu) })
	b.stopOnCv = true
	b.tuner(80, "cpu").run()
	if b.cpu != 80 || b.minSet < 80 {
		t.Fatalf("cpu %d, lowest set %d: want 80 and never below the floor 80\n%s", b.cpu, b.minSet, b.logs())
	}
}

// ABBA: a load drift of +2% per window with no real effect of the cap is not mistaken for a gain.
func TestDutyTunerABBACancelsDrift(t *testing.T) {
	b := newSimBox(func(cpu, gpu int, el time.Duration) float64 { return 80000 * (1 + 0.02*el.Minutes()) })
	b.stopOnCv = true
	tu := b.tuner(50, "cpu")
	tu.z = 0 // r23 merge: the ABBA averaging alone must cancel the drift (the r23 noise gate would mask a broken average)
	tu.run()
	if tu.kept != 0 || b.cpu != 90 {
		t.Fatalf("a pure drift was kept as a gain (kept %d, cpu %d)\n%s", tu.kept, b.cpu, b.logs())
	}
}

// A window in which the epoch moved (reconnect, GPU restart) voids the round and restores the cap.
func TestDutyTunerVoidRestores(t *testing.T) {
	b := newSimBox(func(cpu, gpu int, _ time.Duration) float64 { return 1000 * float64(cpu) })
	b.bumpAt = 4 // the candidate's (95) first measuring window
	tu := b.tuner(50, "cpu")
	if v := tu.probe(tu.knobs[0]); v != duty_void {
		t.Fatalf("verdict %v, want void\n%s", v, b.logs())
	}
	if b.cpu != 90 || tu.void != 1 {
		t.Fatalf("cap %d after a void round, want 90 restored", b.cpu)
	}
	// a stop mid-round restores the cap too
	b.stopAt = b.waits + 2
	if v := tu.probe(tu.knobs[0]); v != duty_stop || b.cpu != 90 {
		t.Fatalf("verdict %v cap %d after a stop, want stop/90", v, b.cpu)
	}
}

func TestParseDutyFlag(t *testing.T) {
	for _, c := range []struct {
		in    string
		pct   int
		auto  bool
		floor int
		err   bool
	}{
		{"90", 90, false, 0, false}, {"100", 100, false, 0, false}, {"150", 100, false, 0, false}, {"0", 1, false, 0, false},
		{"auto", 90, true, 50, false}, {"AUTO", 90, true, 50, false}, {"auto:70", 90, true, 70, false}, {"auto:95", 95, true, 95, false},
		{"auto:", 90, false, 0, true}, {"auto:0", 90, false, 0, true}, {"auto:101", 90, false, 0, true}, {"autox", 90, false, 0, true}, {"x", 90, false, 0, true},
	} {
		p, a, f, err := parse_duty_flag(c.in, 90)
		if p != c.pct || a != c.auto || f != c.floor || (err != nil) != c.err {
			t.Errorf("%q: got %d %v %d %v, want %d %v %d err=%v", c.in, p, a, f, err, c.pct, c.auto, c.floor, c.err)
		}
	}
	if _, _, _, _, err := duty_tune_config("5,10,5,30"); err == nil {
		t.Error("a 5 s window was accepted")
	}
	if w, s, st, h, err := duty_tune_config("120,15,10,60"); err != nil || w != 120*time.Second || s != 15*time.Second || st != 10 || h != time.Hour {
		t.Errorf("duty_tune_config: %v %v %v %v %v", w, s, st, h, err)
	}
}

// The mining threads' throttle sleeps at the cap in force, and not at all at 100.
func TestCPUThrottleUsesLiveDuty(t *testing.T) {
	defer set_cpu_duty(set_cpu_duty(100))
	start := time.Now().Add(-cpu_throttle_window)
	t0 := time.Now()
	cpu_throttle(&start)
	if el := time.Since(t0); el > 20*time.Millisecond {
		t.Fatalf("slept %v at 100%%", el)
	}
	set_cpu_duty(50) // 50%: sleep as long as it worked (>= 40 ms)
	start = time.Now().Add(-cpu_throttle_window)
	t0 = time.Now()
	cpu_throttle(&start)
	if el := time.Since(t0); el < cpu_throttle_window {
		t.Fatalf("slept %v at 50%%, want >= %v", el, cpu_throttle_window)
	}
	if time.Since(start) > 10*time.Millisecond {
		t.Fatal("the throttle window did not restart")
	}
}
