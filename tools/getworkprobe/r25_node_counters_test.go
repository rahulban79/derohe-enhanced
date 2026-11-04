package main

// r25 perfops (B39): the node-side flip-counter deltas printed by --metrics. Forged /metrics pages.

import (
	"errors"
	"math"
	"strings"
	"testing"
)

const page_before = `# a comment
getwork_final_flips_total 30
getwork_dead_normal_jobs_total 5
getwork_final_flip_slow_total 0
getwork_final_flip_delay_seconds_bucket{vmrange="1.896e-02...2.154e-02"} 1
getwork_final_flip_delay_seconds_sum 0.232
getwork_final_flip_delay_seconds_count 5
getwork_final_flip_l9_seconds_sum 0.327
getwork_final_flip_l9_seconds_count 30
getwork_jobs_sent_total 100
`

const page_after = `getwork_final_flips_total 130
getwork_dead_normal_jobs_total 20
getwork_final_flip_slow_total 1
getwork_final_flip_delay_seconds_sum 0.832
getwork_final_flip_delay_seconds_count 15
getwork_final_flip_l9_seconds_sum 1.327
getwork_final_flip_l9_seconds_count 129
getwork_jobs_sent_total 900
`

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestR25ProbeParseProm(t *testing.T) {
	m := parse_prom(page_before + "bad line here x\ngetwork_x notanumber\n")
	if m["getwork_final_flips_total"] != 30 || m["getwork_final_flip_l9_seconds_sum"] != 0.327 || len(m) != 8 {
		t.Fatalf("%v", m)
	}
	for k := range m {
		if strings.Contains(k, "{") {
			t.Fatalf("labelled sample kept: %s", k)
		}
	}
}

func TestR25ProbeFlipDelta(t *testing.T) {
	d, err := flip_delta(parse_prom(page_before), parse_prom(page_after))
	if err != nil {
		t.Fatal(err)
	}
	// window: 100 flips, 10 dead windows holding 0.6 s, 15 dead jobs, 99 L9 samples holding 1.0 s, 1 slow
	if d.Flips != 100 || d.DeadWindows != 10 || d.DeadJobs != 15 || d.Slow != 1 || d.L9N != 99 || d.Jobs != 800 ||
		!near(d.CondMeanMs, 60) || !near(d.DeadMsPerFlip, 6) || !near(d.L9MeanMs, 1000.0/99) {
		t.Fatalf("%+v", d)
	}
	s := d.String()
	for _, w := range []string{"flips 100", "dead_windows 10", "conditional mean 60.00 ms", "dead ms/flip 6.00", "L9 mean 10.10 ms (n=99)", "slow(>150ms) 1"} {
		if !strings.Contains(s, w) {
			t.Fatalf("%q lacks %q", s, w)
		}
	}
	// a histogram that never fired: means are 0, not NaN
	d, err = flip_delta(map[string]float64{"getwork_final_flips_total": 1}, map[string]float64{"getwork_final_flips_total": 1})
	if err != nil || d.CondMeanMs != 0 || d.L9MeanMs != 0 || d.DeadMsPerFlip != 0 || strings.Contains(d.String(), "NaN") {
		t.Fatalf("%+v %v", d, err)
	}
	// a counter that went down = derod restarted inside the window: refused, never a negative delta
	if _, err := flip_delta(parse_prom(page_after), parse_prom(page_before)); err == nil || !strings.Contains(err.Error(), "restarted") {
		t.Fatalf("restart not refused: %v", err)
	}
}

func TestR25ProbeReadCounters(t *testing.T) {
	saved := http_get
	defer func() { http_get = saved }()
	http_get = func(string) (string, error) { return page_before, nil }
	if m, err := read_counters("u"); err != nil || m["getwork_dead_normal_jobs_total"] != 5 {
		t.Fatalf("%v %v", m, err)
	}
	http_get = func(string) (string, error) { return "go_goroutines 10\n", nil } // not a derod with flip counters
	if _, err := read_counters("u"); err == nil {
		t.Fatal("page without flip counters accepted")
	}
	http_get = func(string) (string, error) { return "", errors.New("refused") }
	if _, err := read_counters("u"); err == nil {
		t.Fatal("transport error swallowed")
	}
}
