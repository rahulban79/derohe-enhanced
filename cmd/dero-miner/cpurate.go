package main

import (
	"fmt"
	"time"
)

// cpu_rate_string: hashes per CPU-second of a bench stage. On a shared machine the wall-clock H/s of a short stage
// swings ~2x with the load (Round 18: 5,880-12,771 H/s for the same binary at 10 threads), while the hashes per
// CPU-second of the same runs stay within 2,275-2,360. Off-CPU waiting (another process holds the core, a thread
// handoff) costs wall time but no CPU time, so this column is the load-invariant one; the wall H/s column stays last.
func cpu_rate_string(hashes int, cpu time.Duration) string {
	if hashes <= 0 || cpu <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f", float64(hashes)/cpu.Seconds())
}

// cpu_max_message is the startup line about --cpu-max. --bench runs random_execution at full speed (the duty-cycle
// throttle lives in the mining loop only), so under --bench the cap must not be announced as applied (r18 F6).
func cpu_max_message(bench bool, cpu_max int) string {
	if bench {
		return fmt.Sprintf("--bench runs at full speed: --cpu-max (%d%%) applies to mining only", cpu_max)
	}
	return fmt.Sprintf("CPU duty cycle capped at %d%% per thread (use --cpu-max=100 for full speed)", cpu_max)
}
