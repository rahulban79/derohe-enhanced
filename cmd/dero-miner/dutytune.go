package main

// Round 22 splitpipe: --cpu-max / --gpu-max set while mining, and an opt-in self-tuning mode (--cpu-max=auto,
// --gpu-max=auto).
//
// Why: in --gpu-mode=split the CPU threads (sort) and the GPU (stage 1 + SHA) are both near binding (r21 live:
// gpu_busy 94.6% of the wall clock, feeder_cpu_backlog 74%), so whether a 90% duty cap costs hashes, or saves heat
// for nothing, can only be measured on the live box. Restarting the miner for an A/B loses the GPU self-test,
// the warm-up and the job, and the rate drifts with the box's load between runs. The tuner does the A/B in place:
//
//   - one knob at a time, a candidate one step (5 points) away from the current cap, toward 100 first;
//   - four windows in ABBA order (current, candidate, candidate, current), each measured on the miner's TOTAL hash
//     counter per wall second after a settle period, so a linear drift of the box's load cancels;
//   - the candidate is kept only if its mean rate beats the current one by more than the margin (0.5%); otherwise
//     the cap goes back and the other direction is tried next; both directions rejected = converged, re-probed after
//     the hold time (30 min);
//   - guard rails: never above 100 or below the floor (auto = floor 50, auto:<floor> sets it), a window during which
//     the getwork connection dropped or the GPU server restarted (or split mode was disabled) voids the round and
//     restores the cap; every step is logged ("duty tuner": knob, from, to, both rates, gain, verdict).
// The PoW is unchanged: a duty cap only decides how long a thread or the GPU feeder sleeps between hashes.

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// cpu_duty / gpu_duty are the duty caps in force (percent); --cpu-max / --gpu-max set them at start, the tuner moves
// them while mining. cpu_max / gpu_max keep the start values.
var cpu_duty int32 = 90
var gpu_duty int32 = 90

func cpu_duty_pct() int { return int(atomic.LoadInt32(&cpu_duty)) }
func gpu_duty_pct() int { return int(atomic.LoadInt32(&gpu_duty)) }

func clamp_duty(p, floor int) int {
	if floor < 1 {
		floor = 1
	}
	if p < floor {
		p = floor
	}
	if p > 100 {
		p = 100
	}
	return p
}

func set_cpu_duty(p int) int {
	p = clamp_duty(p, 1)
	atomic.StoreInt32(&cpu_duty, int32(p))
	return p
}

// set_gpu_duty also moves the running split engine's cap (full mode reads gpu_duty per batch).
func set_gpu_duty(p int) int {
	p = clamp_duty(p, 1)
	atomic.StoreInt32(&gpu_duty, int32(p))
	if e := current_split(); e != nil {
		e.SetGPUMax(p)
	}
	return p
}

// cpu_throttle_window: a mining thread works this long, then sleeps so that busy/(busy+sleep) == the CPU duty cap.
const cpu_throttle_window = 40 * time.Millisecond

// cpu_throttle is the mining threads' duty-cycle sleep, at the cap in force now (only between hashes).
//
// r23 hashrate: the window is WALL time. A first contended bench (load 42-50, 4 threads, nice 15) showed the 90% cap
// ahead of no cap, but an independent re-run of the same bench did NOT reproduce it (ratios 1.017 and 0.926, 90 won
// 4 of 8 pairs): on the contended box 90 vs 100 is within noise. No scheduler-priority effect is claimed; the cap's
// cost is visible as dero_miner_cpu_throttle_seconds_total. Decide 90 vs 100 only by a live A/B on a quiet box.
// r23b: re-measured with this function on the contended box (6 threads, nice 15) the wall-clock 90% cap ran at
// x0.861 and x0.960 of no cap in two runs (r23: 0.926-1.017); the sleep is now charged on the measured CPU share
// (cpushare.go). At share 1 that is the r22 sleep; on this box "quiet" is a share of ~0.96, so the cap there lets
// the threads take ~4% more CPU than the wall-clock rule did (more heat, and harder competition with derod).
var cpu_throttle_sleep_ns int64 // atomic: r23: wall time all mining threads spent in the duty sleep (metrics)

func cpu_throttle(start *time.Time) {
	busy := time.Since(*start)
	if busy < cpu_throttle_window {
		return
	}
	if s := throttle_sleep(busy, cpu_duty_pct(), cpu_share()); s > 0 { // r23b: charged on the CPU share (cpushare.go)
		if phase_wake_enabled() {
			s = phase_wake_sleep(s, last_phase_wake) // r23b --phase-duty: a final->regular phase change ends the sleep
		} else {
			time.Sleep(s)
		}
		atomic.AddInt64(&cpu_throttle_sleep_ns, int64(s))
	}
	*start = time.Now()
}

// duty_tune_z: a kept step must beat 3 x the round's own noise estimate (2 degrees of freedom: about 5% false keeps
// with no real effect, against 43-50% with the margin alone on the live r22 box). The price is power: at the live
// window noise of 3.6-5.4% a real +8% step is kept only about 24-40% of the time and a real +17% step about 58-84%,
// so on a loaded box the tuner mostly returns to its start value (safe, but not tuning).
const duty_tune_z = 3.0

// duty_auto_start is where an auto cap starts: the fixed default, so the first probe is exactly the 90-vs-95 A/B.
const duty_auto_start = 90
const duty_auto_floor = 50

// parse_duty_flag parses --cpu-max / --gpu-max: a percent (clamped to 1..100), "auto" or "auto:<floor>".
func parse_duty_flag(s string, def int) (pct int, auto bool, floor int, err error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "auto" || strings.HasPrefix(s, "auto:") {
		floor = duty_auto_floor
		if f := strings.TrimPrefix(s, "auto"); f != "" {
			v, e := strconv.Atoi(f[1:])
			if e != nil || v < 1 || v > 100 {
				return def, false, 0, fmt.Errorf("auto floor must be 1..100, got %q", f[1:])
			}
			floor = v
		}
		return clamp_duty(duty_auto_start, floor), true, floor, nil
	}
	v, e := strconv.Atoi(s)
	if e != nil {
		return def, false, 0, e
	}
	return clamp_duty(v, 1), false, 0, nil
}

type duty_knob struct {
	name  string
	get   func() int
	set   func(int) int
	floor int
	dir   int // the next probe's direction (+1 toward 100 first)
	nope  int // directions rejected in a row at the current cap (2 = converged)
}

type duty_tuner struct {
	knobs                []*duty_knob
	count                func() uint64 // the miner's TOTAL hash counter
	epoch                func() uint64 // changes whenever a window must be voided (reconnect, GPU restart, split disabled)
	valid                func() bool   // mining at all (connected)
	window, settle, hold time.Duration
	step                 int
	margin               float64 // relative gain the candidate must beat (0.005 = 0.5%)
	z                    float64 // r23: and the gain must beat z x the round's own window noise (0 = no noise test)
	wait                 func(d time.Duration) bool
	now                  func() time.Time
	logf                 func(msg string, kv ...interface{})
	kept, reverted, void uint64 // atomic: verdicts (metrics)
	noisy                uint64 // atomic: r23: reverted rounds whose gain beat the margin but not the noise
}

type duty_verdict int

const (
	duty_kept duty_verdict = iota
	duty_reverted
	duty_void
	duty_stop
	duty_edge // no candidate in this direction (at 100 or at the floor)
)

// probe runs one ABBA round of knob k. The knob's cap is the kept value afterwards, whatever happens.
func (t *duty_tuner) probe(k *duty_knob) duty_verdict {
	cur := k.get()
	cand := clamp_duty(cur+k.dir*t.step, k.floor)
	if cand == cur {
		k.dir, k.nope = -k.dir, k.nope+1
		return duty_edge
	}
	var rates [4]float64
	for i, v := range [4]int{cur, cand, cand, cur} {
		k.set(v)
		ep := t.epoch()
		if !t.wait(t.settle) {
			k.set(cur)
			return duty_stop
		}
		c0, t0 := t.count(), t.now()
		if !t.wait(t.window) {
			k.set(cur)
			return duty_stop
		}
		c1, t1 := t.count(), t.now()
		el := t1.Sub(t0).Seconds()
		if t.epoch() != ep || !t.valid() || el <= 0 || c1 < c0 {
			k.set(cur)
			atomic.AddUint64(&t.void, 1)
			t.logf("duty tuner", "knob", k.name, "from", cur, "to", cand, "verdict", "void (reconnect, GPU restart or no work in a window; cap restored)", "window", i)
			return duty_void
		}
		rates[i] = float64(c1-c0) / el
	}
	a, b := (rates[0]+rates[3])/2, (rates[1]+rates[2])/2
	gain := 0.0
	if a > 0 {
		gain = b/a - 1
	}
	sigma := abba_noise(rates)
	noisy := t.z > 0 && b-a <= t.z*sigma
	kv := []interface{}{"knob", k.name, "from", cur, "to", cand, "A_H/s", fmt.Sprintf("%.0f", a), "B_H/s", fmt.Sprintf("%.0f", b),
		"gain_pct", fmt.Sprintf("%+.2f", gain*100), "windows_H/s", fmt.Sprintf("%.0f/%.0f/%.0f/%.0f", rates[0], rates[1], rates[2], rates[3])}
	if a > 0 {
		kv = append(kv, "noise_pct", fmt.Sprintf("%.2f", 100*sigma/a))
	}
	if noisy && a > 0 && gain > t.margin {
		atomic.AddUint64(&t.noisy, 1)
		kv = append(kv, "why", fmt.Sprintf("gain within %.0f x the window noise (box load drifting): not measurable", t.z))
	}
	if a > 0 && gain > t.margin && !noisy {
		k.set(cand)
		k.nope = 0 // keep going this way
		atomic.AddUint64(&t.kept, 1)
		t.logf("duty tuner", append(kv, "verdict", "kept")...)
		return duty_kept
	}
	k.set(cur)
	k.dir, k.nope = -k.dir, k.nope+1
	atomic.AddUint64(&t.reverted, 1)
	t.logf("duty tuner", append(kv, "verdict", "reverted")...)
	return duty_reverted
}

// abba_noise estimates the standard deviation of the ABBA gain b-a (H/s) from the round itself: the two windows of
// each arm should agree, so (r0-r3) and (r1-r2) each have variance 2 s^2 for a per-window noise s, and b-a, the
// difference of two 2-window means, has variance s^2. A linear load drift also shows up in those differences, which
// only makes the test stricter. r23: the live r22 per-minute rates under foreign load (miner log 01:29-02:00) gave
// an ABBA null-gain spread of 3.6-5.4%, so a 0.5% margin alone kept a random step in 43-50% of rounds.
func abba_noise(r [4]float64) float64 {
	d1, d2 := r[0]-r[3], r[1]-r[2]
	return math.Sqrt((d1*d1 + d2*d2) / 4)
}

// run probes the knobs in turn until every one is converged, holds, and starts again (toward 100 first).
func (t *duty_tuner) run() {
	for {
		busy := false
		for _, k := range t.knobs {
			if k.nope >= 2 {
				continue
			}
			busy = true
			if t.probe(k) == duty_stop {
				return
			}
		}
		if busy {
			continue
		}
		caps := []interface{}{}
		for _, k := range t.knobs {
			caps = append(caps, k.name, k.get())
			k.nope, k.dir = 0, 1
		}
		t.logf("duty tuner", append(caps, "verdict", "converged", "next_probe_in", t.hold.String())...)
		if !t.wait(t.hold) {
			return
		}
	}
}

// duty_tune_config: DERO_DUTY_TUNE=window_s,settle_s,step,hold_min (defaults 60,10,5,30).
func duty_tune_config(s string) (window, settle time.Duration, step int, hold time.Duration, err error) {
	v := [4]int{60, 10, 5, 30}
	if s = strings.TrimSpace(s); s != "" {
		p := strings.Split(s, ",")
		if len(p) != 4 {
			return 60 * time.Second, 10 * time.Second, 5, 30 * time.Minute, fmt.Errorf("want window_s,settle_s,step,hold_min")
		}
		var w [4]int
		for i := range p {
			x, e := strconv.Atoi(strings.TrimSpace(p[i]))
			if e != nil {
				return 60 * time.Second, 10 * time.Second, 5, 30 * time.Minute, e
			}
			w[i] = x
		}
		if w[0] < 10 || w[0] > 3600 || w[1] < 0 || w[1] > 600 || w[2] < 1 || w[2] > 50 || w[3] < 1 || w[3] > 24*60 {
			return 60 * time.Second, 10 * time.Second, 5, 30 * time.Minute, fmt.Errorf("out of range: %q", s)
		}
		v = w
	}
	return time.Duration(v[0]) * time.Second, time.Duration(v[1]) * time.Second, v[2], time.Duration(v[3]) * time.Minute, nil
}

var duty_tuner_live atomic.Value // *duty_tuner, for /metrics

// duty_tune_epoch: anything that makes a window's rate meaningless bumps it.
func duty_tune_epoch() uint64 {
	n := atomic.LoadUint64(&getwork_reconnects) + atomic.LoadUint64(&gpu_restarts)
	if e := current_split(); e != nil {
		s := e.Stats()
		n += s.Restarts
		if s.Disabled != "" {
			n += 1 << 32
		}
	}
	return n
}

// start_duty_tuner starts the tuner when --cpu-max=auto or --gpu-max=auto was given (after the mining threads and
// the GPU have started). gpuRunning: a GPU worker (split or full) is mining, so the GPU cap has an effect.
func start_duty_tuner(cpuAuto bool, cpuFloor int, gpuAuto bool, gpuFloor int, gpuRunning bool) {
	t := &duty_tuner{count: func() uint64 { return atomic.LoadUint64(&counter) }, epoch: duty_tune_epoch,
		valid: func() bool { return atomic.LoadInt32(&getwork_connected) == 1 }, margin: 0.005, z: duty_tune_z,
		wait: func(d time.Duration) bool {
			select {
			case <-Exit_In_Progress:
				return false
			case <-time.After(d):
				return true
			}
		},
		now:  time.Now,
		logf: func(msg string, kv ...interface{}) { logger.Info(msg, kv...) }}
	var err error
	if t.window, t.settle, t.step, t.hold, err = duty_tune_config(os.Getenv("DERO_DUTY_TUNE")); err != nil {
		logger.Error(err, "DERO_DUTY_TUNE ignored (defaults 60,10,5,30)")
	}
	if cpuAuto {
		t.knobs = append(t.knobs, &duty_knob{name: "cpu", get: cpu_duty_pct, set: set_cpu_duty, floor: cpuFloor, dir: 1})
	}
	if gpuAuto {
		if gpuRunning {
			t.knobs = append(t.knobs, &duty_knob{name: "gpu", get: gpu_duty_pct, set: set_gpu_duty, floor: gpuFloor, dir: 1})
		} else {
			logger.Info("--gpu-max=auto has no effect: no GPU worker is mining")
		}
	}
	if len(t.knobs) == 0 {
		return
	}
	duty_tuner_live.Store(t)
	logger.Info("duty tuner ON", "cpu_auto", cpuAuto, "cpu_floor", cpuFloor, "gpu_auto", gpuAuto && gpuRunning, "gpu_floor", gpuFloor,
		"window", t.window.String(), "settle", t.settle.String(), "step", t.step, "hold", t.hold.String(), "margin_pct", t.margin*100)
	go func() {
		if !t.wait(2 * time.Minute) { // warm-up: the first job, the GPU self-test, the ring filling
			return
		}
		t.run()
	}()
}
