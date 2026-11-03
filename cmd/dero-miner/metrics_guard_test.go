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
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// r20: the miner's loopback /metrics answered Host rebind.evil.example (live probe, HTTP 200). Now a rebinding Host
// and a cross-site Origin get 403 and are counted; the dashboard's own poll and curl on 127.0.0.1 still get 200.
func TestMetricsServerHostOriginGuard(t *testing.T) {
	srv, addr, err := start_metrics_server_any_port(t)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	get := func(path, host, origin string) (int, string) {
		req, _ := http.NewRequest("GET", "http://"+addr+path, nil)
		if host != "" {
			req.Host = host
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	before := atomic.LoadUint64(&metrics_guard_refused)
	if c, _ := get("/metrics", "rebind.evil.example:10110", ""); c != http.StatusForbidden {
		t.Fatalf("rebinding Host: HTTP %d, want 403", c)
	}
	if c, _ := get("/dashboard", "", "https://evil.example"); c != http.StatusForbidden {
		t.Fatalf("foreign Origin: HTTP %d, want 403", c)
	}
	if got := atomic.LoadUint64(&metrics_guard_refused) - before; got != 2 {
		t.Fatalf("guard counted %d refusals, want 2", got)
	}
	c, body := get("/metrics", "", "")
	if c != http.StatusOK || !strings.Contains(body, "dero_miner_guard_refused_total ") {
		t.Fatalf("local /metrics: HTTP %d, guard counter present %v", c, strings.Contains(body, "dero_miner_guard_refused_total"))
	}
	if c, _ := get("/metrics", "localhost:10110", "http://127.0.0.1:10110"); c != http.StatusOK {
		t.Fatalf("same-origin poll: HTTP %d", c)
	}
	if metrics_bind_is_loopback("0.0.0.0:10110") || !metrics_bind_is_loopback("[::1]:10110") || !metrics_bind_is_loopback("localhost:1") {
		t.Fatal("metrics_bind_is_loopback")
	}
}
