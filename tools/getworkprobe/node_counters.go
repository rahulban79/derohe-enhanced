// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package main

// r25 perfops (B39): --metrics reads derod's getwork flip counters before and after the run and prints their DELTAS,
// so one probe run is the node-side B39 read (the client-side flip above cannot see dead work, r24 verify). Read-only:
// one GET of derod's /metrics at each end.

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// flip_names are the counters a B39 read needs (cmd/derod/rpc/getwork_flip.go).
var flip_names = []string{"getwork_final_flips_total", "getwork_dead_normal_jobs_total", "getwork_final_flip_slow_total",
	"getwork_final_flip_delay_seconds_sum", "getwork_final_flip_delay_seconds_count",
	"getwork_final_flip_l9_seconds_sum", "getwork_final_flip_l9_seconds_count", "getwork_jobs_sent_total"}

// parse_prom reads the unlabelled samples of a Prometheus text page. A histogram's _sum/_count appear only after its
// first sample (VictoriaMetrics), so a missing name reads as 0. Pure.
func parse_prom(text string) map[string]float64 {
	m := map[string]float64{}
	for _, l := range strings.Split(text, "\n") {
		if l == "" || l[0] == '#' || strings.ContainsRune(l, '{') {
			continue
		}
		f := strings.Fields(l)
		if len(f) != 2 {
			continue
		}
		if v, err := strconv.ParseFloat(f[1], 64); err == nil {
			m[f[0]] = v
		}
	}
	return m
}

// FlipDelta is the node's view of the probe window.
type FlipDelta struct {
	Flips, DeadJobs, Slow, DeadWindows, L9N, Jobs float64
	CondMeanMs, L9MeanMs, DeadMsPerFlip           float64 // NaN-free: 0 when the denominator is 0
}

// flip_delta is after - before. A counter that went DOWN means derod restarted inside the window: refused.
func flip_delta(before, after map[string]float64) (d FlipDelta, err error) {
	g := func(n string) float64 { return after[n] - before[n] }
	for _, n := range flip_names {
		if g(n) < 0 {
			return d, fmt.Errorf("%s went down (%v -> %v): derod restarted during the window", n, before[n], after[n])
		}
	}
	d.Flips, d.DeadJobs, d.Slow = g("getwork_final_flips_total"), g("getwork_dead_normal_jobs_total"), g("getwork_final_flip_slow_total")
	d.DeadWindows, d.L9N, d.Jobs = g("getwork_final_flip_delay_seconds_count"), g("getwork_final_flip_l9_seconds_count"), g("getwork_jobs_sent_total")
	if d.DeadWindows > 0 {
		d.CondMeanMs = 1000 * g("getwork_final_flip_delay_seconds_sum") / d.DeadWindows
	}
	if d.L9N > 0 {
		d.L9MeanMs = 1000 * g("getwork_final_flip_l9_seconds_sum") / d.L9N
	}
	if d.Flips > 0 {
		d.DeadMsPerFlip = 1000 * g("getwork_final_flip_delay_seconds_sum") / d.Flips
	}
	return
}

func (d FlipDelta) String() string {
	return fmt.Sprintf("node: flips %.0f dead_windows %.0f dead_jobs %.0f slow(>150ms) %.0f | conditional mean %.2f ms | "+
		"dead ms/flip %.2f | L9 mean %.2f ms (n=%.0f) | jobs_sent %.0f", d.Flips, d.DeadWindows, d.DeadJobs, d.Slow,
		d.CondMeanMs, d.DeadMsPerFlip, d.L9MeanMs, d.L9N, d.Jobs)
}

var http_get = func(url string) (string, error) {
	c := http.Client{Timeout: 10 * time.Second}
	r, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return "", fmt.Errorf("%s: HTTP %d", url, r.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	return string(b), err
}

func read_counters(url string) (map[string]float64, error) {
	t, err := http_get(url)
	if err != nil {
		return nil, err
	}
	m := parse_prom(t)
	if _, ok := m["getwork_final_flips_total"]; !ok {
		return nil, fmt.Errorf("%s has no getwork_final_flips_total (not a derod with the r23c+ flip counters)", url)
	}
	return m, nil
}
