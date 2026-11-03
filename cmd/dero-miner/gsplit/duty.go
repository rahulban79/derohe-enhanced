package gsplit

// --gpu-max as a duty bucket (Round 22 forensics).
//
// Live r21 (dero-miner pid 58002, --gpu-max=90, 2026-10-29 06:26-06:39): gpu_busy_pct 94.7-96.0 in every 60 s window
// after the first, and 94.6% over the run (dero_miner_split_gpu_busy_seconds_total 827.6 of 875 s uptime). The old
// throttle added busy*(100-cap)/cap to a debt that the FEEDER slept off before staging its next batch, but in GPUSHA
// mode the ring is full ~87.5% of each minute (feeder_ring_full_ms ~52.5 s/min): the feeder's sleep overlapped time
// it would have spent blocked anyway, and op 2 (GPU SHA) commands are issued by the CPU threads, never by the feeder.
// The GPU kept working through the sleep, so the cap was not met.
//
// The bucket charges each busy span at its cost under the cap (busy*100/cap of wall time) and credits the wall clock
// as it passes; the feeder stages nothing while the balance is positive. Over any interval W the GPU is then busy at
// most cap/100*(W + dutyBurstNs): idle time banks at most dutyBurstNs of credit. --gpu-max=100 charges nothing.
//
// NOTE for operators: the live box ran at ~95% with --gpu-max=90 and 0 GPU watchdog retries
// (dero_miner_split_gpu_retries_total 0). With this fix --gpu-max=90 really caps at 90%, about -5% staged H/s on that
// host; pass --gpu-max=96 (or 100) to keep the r21 throughput.

import "time"

// dutyBurstNs: the most GPU idle time the bucket banks (a long pause cannot buy an unbounded full-duty burst).
const dutyBurstNs = int64(100 * time.Millisecond)

// dutyMaxSleep bounds one feeder sleep so a stop request is seen quickly.
const dutyMaxSleep = 20 * time.Millisecond

// dutyCharge is the wall time a busy span of busyNs costs under a cap% duty cycle.
func dutyCharge(busyNs int64, cap int) int64 {
	if cap < 1 || cap >= 100 {
		return 0
	}
	return busyNs * 100 / int64(cap)
}

// settleDuty credits the wall time since the previous settle (feeder goroutine only: dutyLast is not shared) and
// returns the ns still owed (<= 0: the feeder may stage). The credit is clamped at dutyBurstNs.
func (e *Engine) settleDuty(now int64) int64 {
	el := now - e.dutyLast
	if el < 0 {
		el = 0
	}
	e.dutyLast = now
	d := e.debt.Add(-el)
	if d < -dutyBurstNs {
		d = e.debt.Add(-dutyBurstNs - d) // charges racing in from the reply loop are kept
	}
	return d
}

// payDuty blocks the feeder while the bucket is in debt; false: the engine or this generation is stopping. The cap is
// the one in force now (SetGPUMax, r22 merge: the splitpipe duty tuner changes it while mining); the time spent
// waiting is counted in Stats.ThrottleUs.
func (e *Engine) payDuty(gq chan struct{}) bool {
	if e.GPUMax() >= 100 {
		return true
	}
	if e.settleDuty(e.clock()) <= 0 {
		return true
	}
	t0 := time.Now()
	defer func() { e.sThrottleUs.Add(uint64(time.Since(t0).Microseconds())) }()
	for {
		d := e.settleDuty(e.clock())
		if d <= 0 || e.GPUMax() >= 100 { // paid, or raised to 100 while waiting (SetGPUMax also forgives the debt)
			return true
		}
		s := time.Duration(d)
		if s > dutyMaxSleep {
			s = dutyMaxSleep
		}
		select {
		case <-e.quit:
			return false
		case <-gq:
			return false
		case <-time.After(s):
		}
	}
}
