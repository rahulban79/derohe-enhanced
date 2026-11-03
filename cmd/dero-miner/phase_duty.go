package main

// r23b payouts: phase-aware duty (--phase-duty), and per-phase hash accounting.
//
// A DERO block is 9 regular miniblocks at difficulty D, each paying 1/10 of the block reward to its finder, then one
// final miniblock at 9 x D whose 1/10 goes to the integrator of the node that built the block
// (blockchain/transaction_execute.go:132-160, miner_block.go:337-373). A hash spent on regular work therefore earns
// 9 x what a hash spent on final work earns. Measured over 400 mainnet blocks (heights ~7,833,700-7,834,100, the
// miniblock timestamps in GetBlock): regular phase 8.96 s mean, final phase 9.37 s mean = 51.1% of the wall time,
// and that final half earns 10% of a miner's expected reward.
//
// The job tells the phase: the miniblock's first byte carries Final (0x20) for a final template. With
// --phase-duty the CPU duty cap (and the GPU cap, never above --gpu-max) follows the phase:
//   - R:F   regular phase R percent, final phase F percent (1..100);
//   - balanced  CPU: R = 100 and F chosen so the time-weighted mean CPU duty stays at --cpu-max (same average
//     heat/power, more of it where it pays 9x): F = (cpu_max - f x 100) / (1 - f), f = the measured regular share of
//     the wall time (prior 0.489 until 30 min of own phase data). GPU: stays at --gpu-max in both phases (r23b merge:
//     the first draft lowered it to F in the final phase, a mean GPU duty of 87.8 instead of 96).
// Arithmetic (expected reward per block ~ 9 x s_regular + 1 x s_final, s = our share of the network rate), ESTIMATE:
//   balanced at --cpu-max=90 runs between -1.7% (GPU-bound split) and +8.9% (CPU-bound and the hash rate scaling with
//   the duty from 90 to 100); r23 measured 90 vs 100 within noise on a contended box, so expect the low end until a
//   live A/B. 90:10: reward 9 x 0.9 + 0.1 = 8.2 (-8.9%), CPU energy ~0.49 of full at the cap, but the cap is
//   achieved only to within the 40 ms window granularity.
// The throttle sleep (cpu_throttle) is cut short only by a final->regular phase change, and only with --phase-duty
// (phase_wake_sleep): keepalive/refresh jobs (~1 per second live) neither skip nor shorten it.
// Off by default. The PoW is unchanged: a duty cap only decides how long a thread sleeps between hashes. Not combined
// with --cpu-max=auto / --gpu-max=auto (the tuner's A/B windows would measure the phase, not the cap).

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const phase_regular_prior = 0.489           // measured, 400 blocks (see above)
const phase_prior_weight = 30 * time.Minute // own phase data needed before it replaces the prior

type phase_duty_cfg struct {
	on       bool
	balanced bool
	regular  int // percent
	final    int // percent (balanced: recomputed)
}

// parse_phase_duty parses --phase-duty: off, balanced, or R:F.
func parse_phase_duty(s string) (phase_duty_cfg, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "", "off":
		return phase_duty_cfg{}, nil
	case "balanced":
		return phase_duty_cfg{on: true, balanced: true, regular: 100}, nil
	}
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return phase_duty_cfg{}, fmt.Errorf("--phase-duty: want off, balanced or R:F, got %q", s)
	}
	r, e1 := strconv.Atoi(parts[0])
	f, e2 := strconv.Atoi(parts[1])
	if e1 != nil || e2 != nil || r < 1 || r > 100 || f < 1 || f > 100 {
		return phase_duty_cfg{}, fmt.Errorf("--phase-duty: R and F must be percents 1..100, got %q", s)
	}
	return phase_duty_cfg{on: true, regular: r, final: f}, nil
}

// balanced_final_duty keeps the time-weighted mean duty at avg with the regular phase at regular percent.
func balanced_final_duty(avg, regular int, regFrac float64) int {
	if regFrac <= 0 || regFrac >= 1 {
		regFrac = phase_regular_prior
	}
	f := (float64(avg) - regFrac*float64(regular)) / (1 - regFrac)
	p := int(f + 0.5)
	return clamp_duty(p, 1)
}

// job_is_final reads the Final flag of a job's miniblock blob (hex) without decoding the rest.
func job_is_final(blob string) bool {
	if len(blob) < 2 {
		return false
	}
	var b [1]byte
	if _, err := hex.Decode(b[:], []byte(blob[:2])); err != nil {
		return false
	}
	return b[0]&0x20 != 0
}

// phase_clock accumulates wall time and hashes per phase (index 0 regular, 1 final).
type phase_clock struct {
	mu      sync.Mutex
	started bool
	final   bool
	since   time.Time
	at      uint64 // hash counter at since
	secs    [2]float64
	hashes  [2]uint64
}

func phase_index(final bool) int {
	if final {
		return 1
	}
	return 0
}

// observe closes the running phase interval at now/count and starts final's; it reports whether the phase changed.
func (p *phase_clock) observe(final bool, now time.Time, count uint64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started {
		p.started, p.final, p.since, p.at = true, final, now, count
		return true
	}
	i := phase_index(p.final)
	if d := now.Sub(p.since); d > 0 {
		p.secs[i] += d.Seconds()
	}
	if count >= p.at {
		p.hashes[i] += count - p.at
	}
	changed := final != p.final
	p.final, p.since, p.at = final, now, count
	return changed
}

// snapshot returns the totals including the running interval up to now/count.
func (p *phase_clock) snapshot(now time.Time, count uint64) (secs [2]float64, hashes [2]uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	secs, hashes = p.secs, p.hashes
	if p.started {
		i := phase_index(p.final)
		if d := now.Sub(p.since); d > 0 {
			secs[i] += d.Seconds()
		}
		if count >= p.at {
			hashes[i] += count - p.at
		}
	}
	return
}

// regular_fraction is the measured regular share of the wall time, or the prior until enough data.
func regular_fraction(secs [2]float64) float64 {
	t := secs[0] + secs[1]
	if t < phase_prior_weight.Seconds() {
		return phase_regular_prior
	}
	return secs[0] / t
}

// phase_caps: the CPU and GPU caps for a phase. The GPU never goes above its own start cap.
func phase_caps(c phase_duty_cfg, final bool, cpuMax, gpuMax int, regFrac float64) (cpu, gpu int) {
	if !final {
		return c.regular, gpuMax
	}
	f := c.final
	if c.balanced {
		f = balanced_final_duty(cpuMax, c.regular, regFrac)
	}
	g := gpuMax
	if !c.balanced && f < g { // R:F lowers the GPU too; balanced keeps it at --gpu-max (mean GPU duty = --gpu-max)
		g = f
	}
	return f, g
}

var phases phase_clock
var phase_cfg phase_duty_cfg

// phase_note is called for every job taken: it books the phase time/hashes and, with --phase-duty, moves the caps.
func phase_note(blob string) {
	final := job_is_final(blob)
	now := time.Now()
	count := atomic.LoadUint64(&counter)
	was_final := phases.is_final()
	if !phases.observe(final, now, count) || !phase_cfg.on {
		return
	}
	if was_final && !final {
		atomic.StoreInt64(&phase_wake_ns, now.UnixNano()) // ends a low final-phase duty sleep (phase_wake_sleep)
	}
	secs, _ := phases.snapshot(now, count)
	c, g := phase_caps(phase_cfg, final, cpu_max, gpu_max, regular_fraction(secs))
	set_cpu_duty(c)
	set_gpu_duty(g)
}

// phase_wake_sleep sleeps d in short slices and returns early once changed() reports a phase change stamped AFTER
// the sleep began, so a low final-phase cap never keeps a thread asleep into the next (regular) phase. It returns
// the time actually slept. Only used with --phase-duty; without it cpu_throttle is a plain time.Sleep.
const throttle_slice = 5 * time.Millisecond

var job_change_ns int64 // atomic: unix ns of the last job taken (take_job); informational, never wakes the throttle
var phase_wake_ns int64 // atomic: unix ns of the last final->regular phase change under --phase-duty
var phase_wake_on int32 // atomic: 1 with --phase-duty on

func last_job_change() int64   { return atomic.LoadInt64(&job_change_ns) }
func last_phase_wake() int64   { return atomic.LoadInt64(&phase_wake_ns) }
func phase_wake_enabled() bool { return atomic.LoadInt32(&phase_wake_on) == 1 }

// set_phase_duty installs the --phase-duty config (main, tests).
func set_phase_duty(c phase_duty_cfg) {
	phase_cfg = c
	v := int32(0)
	if c.on {
		v = 1
	}
	atomic.StoreInt32(&phase_wake_on, v)
}

func (p *phase_clock) is_final() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.started && p.final
}

func phase_wake_sleep(d time.Duration, changed func() int64) time.Duration {
	start := time.Now()
	since := start.UnixNano()
	for changed() <= since {
		left := d - time.Since(start)
		if left <= 0 {
			break
		}
		if left > throttle_slice {
			left = throttle_slice
		}
		time.Sleep(left)
	}
	return time.Since(start)
}
