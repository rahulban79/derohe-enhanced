package main

import (
	"bytes"
	"math/rand"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// r23: every duty sleep of the mining threads is counted (dero_miner_cpu_throttle_seconds_total), and a 100% cap
// never sleeps.
func TestCPUThrottleSleepCounted(t *testing.T) {
	defer set_cpu_duty(set_cpu_duty(50))
	s0 := atomic.LoadInt64(&cpu_throttle_sleep_ns)
	start := time.Now().Add(-cpu_throttle_window)
	cpu_throttle(&start)
	if d := atomic.LoadInt64(&cpu_throttle_sleep_ns) - s0; d < int64(cpu_throttle_window) {
		t.Fatalf("a 50%% duty sleep after %v of work counted %v", cpu_throttle_window, time.Duration(d))
	}
	set_cpu_duty(100)
	s1 := atomic.LoadInt64(&cpu_throttle_sleep_ns)
	start = time.Now().Add(-cpu_throttle_window)
	cpu_throttle(&start)
	if d := atomic.LoadInt64(&cpu_throttle_sleep_ns) - s1; d != 0 {
		t.Fatalf("100%% cap counted %v of sleep", time.Duration(d))
	}
}

// r23: under load drift as large as the live r22 box's (per-window rate noise 5%, no real effect of the cap) the
// noise test keeps few random steps, while the margin alone keeps about half of them.
func TestDutyTunerNoiseRejectsRandomSteps(t *testing.T) {
	keptWith := func(z float64, sigma float64, gainPerPoint float64) (kept, rounds int) {
		rng := rand.New(rand.NewSource(23))
		levels := make([]float64, 4096)
		for i := range levels {
			levels[i] = 1 + sigma*rng.NormFloat64()
		}
		b := newSimBox(func(cpu, gpu int, el time.Duration) float64 {
			return 60000 * levels[int(el/time.Second)/70%len(levels)] * (1 + gainPerPoint*float64(cpu-90))
		})
		tu := b.tuner(50, "cpu")
		tu.z = z
		k := tu.knobs[0]
		for rounds = 0; rounds < 200; rounds++ {
			b.cpu, k.dir = 90, 1
			if tu.probe(k) == duty_kept {
				kept++
			}
		}
		return
	}
	k0, n := keptWith(0, 0.05, 0)
	k3, _ := keptWith(duty_tune_z, 0.05, 0)
	kg, _ := keptWith(duty_tune_z, 0.01, 0.016)
	kp, _ := keptWith(duty_tune_z, 0.05, 0.016)
	t.Logf("random steps kept under 5%% window noise: margin alone %d/%d, margin+noise test %d/%d; real +8%% step kept %d/%d at 1%% noise, %d/%d at 5%% noise", k0, n, k3, n, kg, n, kp, n)
	if k0*100 < 30*n {
		t.Fatalf("margin alone kept %d/%d random steps; the simulated drift is too small to test anything", k0, n)
	}
	if k3*100 > 10*n {
		t.Fatalf("noise test kept %d/%d random steps (margin alone %d), want <= 10%%", k3, n, k0)
	}
	// a real +1.6%/point effect (+8% per 5-point step) with 1% noise is still found
	if kg*100 < 90*n {
		t.Fatalf("noise test kept only %d/%d steps of a real +8%% gain", kg, n)
	}
	// the same real +8% step under the live 5% noise is NOT reliably found: the 1%-noise power above is not the
	// tuner's power on a loaded box (r23 verifier Monte Carlo: 24-27% at 5-5.4% noise)
	if kp >= kg || kp*100 > 80*n {
		t.Fatalf("real +8%% step kept %d/%d at 5%% noise (vs %d/%d at 1%%): the documented power limit no longer holds", kp, n, kg, n)
	}
}

func TestAbbaNoise(t *testing.T) {
	if s := abba_noise([4]float64{100, 120, 120, 100}); s != 0 {
		t.Fatalf("steady arms: %v", s)
	}
	if s := abba_noise([4]float64{100, 110, 106, 104}); s*s < 7.999 || s*s > 8.001 { // ((100-104)^2 + (110-106)^2) / 4
		t.Fatalf("abba_noise^2 = %v, want 8", s*s)
	}
}

func TestMetricsR23DutyTuner(t *testing.T) {
	var m miner_metrics
	m.throttle_sleep_ns, m.tuner_on, m.tuner_noisy = 2500000000, true, 4
	var b bytes.Buffer
	write_miner_metrics(&b, m)
	s := b.String()
	for _, want := range []string{"dero_miner_cpu_throttle_seconds_total 2.500", "dero_miner_duty_tuner_noisy_total 4"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
}
