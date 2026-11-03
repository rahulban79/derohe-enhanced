package main

import (
	"strings"
	"testing"
	"time"
)

func TestCPURateString(t *testing.T) {
	cases := []struct {
		h    int
		cpu  time.Duration
		want string
	}{
		{1000, 500 * time.Millisecond, "2000.0"},
		{2300, time.Second, "2300.0"},
		{0, time.Second, "-"},
		{1000, 0, "-"}, // windows: no CPU time
		{1000, -time.Millisecond, "-"},
	}
	for _, c := range cases {
		if got := cpu_rate_string(c.h, c.cpu); got != c.want {
			t.Fatalf("cpu_rate_string(%d, %v) = %q, want %q", c.h, c.cpu, got, c.want)
		}
	}
}

// the process clock must advance while this goroutine burns CPU (it is what the bench column divides by).
// r23 forensics: the burn is bounded by CPU time, not wall time. On the live box (load average 41, the test at nice 15)
// 50 ms of wall clock bought this goroutine only 13.7 ms of CPU, so the old fixed 50 ms loop failed 2 runs in 3 while
// the clock itself was fine; a broken clock still fails, after the 5 s wall bound.
func TestProcessCPUTimeAdvances(t *testing.T) {
	a := process_cpu_time()
	b := a
	x := uint64(1)
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end) && b-a < 20*time.Millisecond; b = process_cpu_time() {
		for i := 0; i < 100000; i++ {
			x = x*6364136223846793005 + 1442695040888963407
		}
	}
	if b-a < 20*time.Millisecond {
		t.Fatalf("process CPU time advanced %v over 5 s of busy loop (x=%d)", b-a, x)
	}
}

// Fix G (r18 merge, F6): --bench ignores --cpu-max, so it must not announce a duty-cycle cap.
func TestCPUMaxMessageBench(t *testing.T) {
	if m := cpu_max_message(true, 90); strings.Contains(m, "capped") || !strings.Contains(m, "full speed") {
		t.Fatalf("bench message claims a cap: %q", m)
	}
	if m := cpu_max_message(false, 90); !strings.Contains(m, "capped at 90%") {
		t.Fatalf("mining message lost the cap: %q", m)
	}
}
