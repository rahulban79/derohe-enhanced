// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package main

import (
	"bytes"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// r23b: with the threads fully on-CPU (share 1000) the sleep is exactly the r22 wall-clock sleep, for every cap, so a
// quiet box keeps its heat cap bit for bit.
func TestR23bThrottleSleepQuietIsR22(t *testing.T) {
	for d := 1; d < 100; d++ {
		for _, busy := range []time.Duration{0, 1, 999, 40 * time.Millisecond, 40*time.Millisecond + 7, time.Second} {
			want := time.Duration(0)
			if busy > 0 {
				want = busy * time.Duration(100-d) / time.Duration(d)
			}
			if got := throttle_sleep(busy, d, 1000); got != want {
				t.Fatalf("cap %d busy %v: sleep %v, r22 slept %v", d, busy, got, want)
			}
		}
	}
	if s := throttle_sleep(time.Second, 100, 1000); s != 0 {
		t.Fatalf("cap 100 sleeps %v", s)
	}
}

// r23b: a thread the box already holds at or below the cap does not sleep; above it, it sleeps only the excess.
func TestR23bThrottleSleepContended(t *testing.T) {
	busy := 40 * time.Millisecond
	for _, share := range []int64{0, 500, 899, 900} {
		if s := throttle_sleep(busy, 90, share); s != 0 {
			t.Fatalf("share %d at cap 90 slept %v", share, s)
		}
	}
	// share 0.95: sleep = busy*(95-90)/90; then cpu/(busy+sleep) = 0.95*busy/(busy*95/90) = 0.90
	if s, want := throttle_sleep(busy, 90, 950), busy*5000/90000; s != want {
		t.Fatalf("share 950: sleep %v, want %v", s, want)
	}
	if s, q := throttle_sleep(busy, 90, 1500), throttle_sleep(busy, 90, 1000); s != q {
		t.Fatalf("share above 1000 not clamped: %v vs %v", s, q)
	}
	if s := throttle_sleep(busy, 50, 400); s != 0 {
		t.Fatalf("share 0.4 at cap 50 slept %v", s)
	}
}

// r23b: the share is CPU over the threads' awake wall time; the duty sleep is not awake time, so a quiet box that
// sleeps its 10% still reads 1000 (otherwise the cap would switch itself off every other window).
func TestR23bCPUShareSample(t *testing.T) {
	for _, c := range []struct {
		cpu, wall, sleep time.Duration
		threads          int
		want             int64
	}{
		{10 * time.Second, time.Second, 0, 20, 500},
		{9 * time.Second, time.Second, 2 * time.Second, 20, 500},
		{1800 * time.Millisecond, time.Second, 200 * time.Millisecond, 2, 1000}, // quiet box at a 90% cap
		{1620 * time.Millisecond, time.Second, 200 * time.Millisecond, 2, 900},
		{30 * time.Second, time.Second, 0, 20, 1000}, // other goroutines' CPU: clamped
		{0, time.Second, 0, 20, 1000},                // unmeasured (windows): the wall-clock rule
		{time.Second, 0, 0, 20, 1000},
		{time.Second, time.Second, 0, 0, 1000},
		{time.Second, time.Second, 3 * time.Second, 2, 1000}, // no awake time
	} {
		if got := cpu_share_sample(c.cpu, c.wall, c.sleep, c.threads); got != c.want {
			t.Errorf("cpu %v wall %v sleep %v threads %d: share %d, want %d", c.cpu, c.wall, c.sleep, c.threads, got, c.want)
		}
	}
}

// r23b: the sampler publishes the share of each window from its clocks and the duty-sleep counter, and stops on quit.
func TestR23bCPUShareSamplerDriven(t *testing.T) {
	defer atomic.StoreInt64(&cpu_share_milli, 1000)
	var mu sync.Mutex
	var w time.Time
	var c time.Duration
	base := time.Unix(1700000000, 0)
	now := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		w = w.Add(time.Second)
		return base.Add(w.Sub(time.Time{}))
	}
	clock := func() time.Duration { mu.Lock(); defer mu.Unlock(); c += 5 * time.Second; return c } // 5 CPU-s per 1 s
	quit := make(chan struct{})
	done := make(chan struct{})
	go func() { cpu_share_sampler(10, time.Millisecond, quit, now, clock); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for cpu_share() != 500 {
		if time.Now().After(deadline) {
			t.Fatalf("share %d, want 500 (5 CPU-s over 10 threads x 1 s)", cpu_share())
		}
		time.Sleep(time.Millisecond)
	}
	close(quit)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sampler did not stop on quit")
	}
}

// r23b: cpu_throttle reads the share: held off-CPU below the cap it does not sleep; fully on-CPU it sleeps the r22 sleep.
func TestR23bCPUThrottleUsesShare(t *testing.T) {
	defer set_cpu_duty(set_cpu_duty(90))
	defer atomic.StoreInt64(&cpu_share_milli, 1000)
	atomic.StoreInt64(&cpu_share_milli, 500)
	s0 := atomic.LoadInt64(&cpu_throttle_sleep_ns)
	start := time.Now().Add(-cpu_throttle_window)
	cpu_throttle(&start)
	if d := atomic.LoadInt64(&cpu_throttle_sleep_ns) - s0; d != 0 {
		t.Fatalf("share 0.5 at cap 90 slept %v", time.Duration(d))
	}
	atomic.StoreInt64(&cpu_share_milli, 1000)
	s1 := atomic.LoadInt64(&cpu_throttle_sleep_ns)
	start = time.Now().Add(-cpu_throttle_window)
	cpu_throttle(&start)
	if d := atomic.LoadInt64(&cpu_throttle_sleep_ns) - s1; d < int64(cpu_throttle_window)/9 {
		t.Fatalf("share 1 at cap 90 slept %v, want >= %v", time.Duration(d), cpu_throttle_window/9)
	}
}

// r23b: the sampler starts unless DERO_CPU_DUTY_CLOCK=wall (any case) asks for the r22 wall-clock cap.
func TestR23bStartCPUShareSampler(t *testing.T) {
	for _, c := range []struct {
		env  string
		want bool
	}{{"", true}, {"cpu", true}, {"wall", false}, {" WALL ", false}} {
		spawned := 0
		got := start_cpu_share_sampler(4, func(k string) string {
			if k == "DERO_CPU_DUTY_CLOCK" {
				return c.env
			}
			return ""
		}, func(func()) { spawned++ })
		if got != c.want || (spawned == 1) != c.want {
			t.Errorf("env %q: started %v spawned %d, want %v", c.env, got, spawned, c.want)
		}
	}
}

func TestR23bMetricsCPUShare(t *testing.T) {
	var m miner_metrics
	m.cpu_share_milli = 512
	var b bytes.Buffer
	write_miner_metrics(&b, m)
	if !strings.Contains(b.String(), "dero_miner_cpu_share 0.512\n") {
		t.Fatalf("no dero_miner_cpu_share 0.512 in\n%s", b.String())
	}
}
