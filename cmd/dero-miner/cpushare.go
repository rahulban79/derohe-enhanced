// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package main

// r23b hashrate: the --cpu-max duty cap charged on the CPU the mining threads actually got, not on the wall clock.
//
// The r22/r23 cpu_throttle slept busy*(100-d)/d after every 40 ms window of WALL time. On a box where other processes
// hold cores, a mining thread is descheduled for part of that window, so its real CPU duty is already below the cap,
// and the sleep then gives away even more of its share: after the sleep it has to win a core back from a long run
// queue. Measured with the miner's own cpu_throttle (TestDutyContentionAB, 6 threads, nice 15, load 82-90, 6 rotated
// rounds): cap 90 = 16,128 sorts/wall-s against 18,724 with no cap (ratio 0.861, 90 lost 6 of 6 pairs) while its sleep
// was only 9.4% of thread-wall.
//
// Now a sampler measures cpu_share, the mining threads' CPU over the wall time they were not in the duty sleep
// (process CPU / (threads x wall - duty sleep), clamped to [0, 1]), and the sleep is the one that brings
// cpu_share*busy / (busy + sleep) down to the cap:
//
//	sleep = busy * (cpu_share*100 - d) / d,  never negative
//
// On a quiet box cpu_share = 1 and this is exactly the r22 sleep, busy*(100-d)/d, so the heat cap is unchanged; a
// thread that already gets less than d% of the wall does not sleep at all. The cap then holds for the process MEAN
// (one share for all threads). Unmeasured CPU (windows: process_cpu_time is 0) keeps cpu_share = 1, the r22 rule.
// DERO_CPU_DUTY_CLOCK=wall restores the r22 wall-clock cap (for an in-place A/B). The PoW is unchanged.

import (
	"strings"
	"sync/atomic"
	"time"
)

// cpu_share_period: how often the sampler re-measures cpu_share.
const cpu_share_period = 500 * time.Millisecond

// cpu_share_milli is the mining threads' measured on-CPU share of their non-sleeping wall time, in 1/1000 (atomic).
// 1000 until the first sample, and for good where the process CPU is not measured.
var cpu_share_milli int64 = 1000

func cpu_share() int64 { return atomic.LoadInt64(&cpu_share_milli) }

// cpu_share_wall_clock: DERO_CPU_DUTY_CLOCK=wall keeps the r22 wall-clock duty cap (no sampler).
func cpu_share_wall_clock(getenv func(string) string) bool {
	return strings.EqualFold(strings.TrimSpace(getenv("DERO_CPU_DUTY_CLOCK")), "wall")
}

// cpu_share_sample turns one sampler window into a share (1/1000): cpu is the process CPU spent in the window, wall
// its length, sleep the mining threads' summed duty sleep in it. Nothing measured (cpu <= 0, or no awake thread
// time) = 1000, the wall-clock rule.
func cpu_share_sample(cpu, wall, sleep time.Duration, threads int) int64 {
	if threads < 1 || cpu <= 0 || wall <= 0 {
		return 1000
	}
	awake := wall*time.Duration(threads) - sleep
	if awake <= 0 {
		return 1000
	}
	f := int64(cpu) * 1000 / int64(awake)
	if f > 1000 {
		f = 1000
	}
	if f < 0 {
		f = 0
	}
	return f
}

// throttle_sleep: the duty sleep after busy wall time at cap duty (percent) for a thread that was on a CPU for
// share/1000 of it. share 1000 gives busy*(100-duty)/duty exactly (the r22 sleep).
func throttle_sleep(busy time.Duration, duty int, share int64) time.Duration {
	if duty >= 100 || duty < 1 || busy <= 0 {
		return 0
	}
	if share > 1000 {
		share = 1000
	}
	num := share*100 - 1000*int64(duty)
	if num <= 0 {
		return 0
	}
	return time.Duration(int64(busy) * num / (1000 * int64(duty)))
}

// cpu_share_sampler measures cpu_share every period until quit closes (nil: never). clock is the process CPU clock
// (process_cpu_time), now the wall clock; both are parameters so the tests can drive it.
func cpu_share_sampler(threads int, period time.Duration, quit <-chan struct{}, now func() time.Time, clock func() time.Duration) {
	tk := time.NewTicker(period)
	defer tk.Stop()
	w0, c0, s0 := now(), clock(), atomic.LoadInt64(&cpu_throttle_sleep_ns)
	for {
		select {
		case <-quit:
			return
		case <-tk.C:
		}
		w, c, s := now(), clock(), atomic.LoadInt64(&cpu_throttle_sleep_ns)
		atomic.StoreInt64(&cpu_share_milli, cpu_share_sample(c-c0, w.Sub(w0), time.Duration(s-s0), threads))
		w0, c0, s0 = w, c, s
	}
}

// start_cpu_share_sampler starts the sampler for the mining threads (spawn runs it, normally as a goroutine) unless
// DERO_CPU_DUTY_CLOCK=wall; true = started.
func start_cpu_share_sampler(threads int, getenv func(string) string, spawn func(func())) bool {
	if cpu_share_wall_clock(getenv) {
		logger.Info("--cpu-max charged on the wall clock (DERO_CPU_DUTY_CLOCK=wall)")
		return false
	}
	spawn(func() { cpu_share_sampler(threads, cpu_share_period, nil, time.Now, process_cpu_time) })
	return true
}
