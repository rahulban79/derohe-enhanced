// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package httpguard

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHostAllowed(t *testing.T) {
	ok := []string{"", "127.0.0.1:10102", "127.0.0.1", "127.8.9.1:1", "localhost:10102", "LOCALHOST", "localhost.",
		"[::1]:10102", "[::1]", "::1", "app.localhost:3000", "node.lan:10102"}
	bad := []string{"rebind.evil.example:10102", "evil.example", "10.0.0.5:10102", "[2001:db8::1]:10102",
		"localhost.evil.example", "127.0.0.1.evil.example", "0.0.0.0:10102", "node.lan.evil:1", "127.0.0.1:1.evil.example", "localhost:"}
	extra := ParseList(" Node.LAN:10102 , ,")
	for _, h := range ok {
		if !HostAllowed(h, extra) {
			t.Errorf("Host %q refused", h)
		}
	}
	for _, h := range bad {
		if HostAllowed(h, extra) {
			t.Errorf("Host %q accepted", h)
		}
	}
}

func TestForeignOrigin(t *testing.T) {
	cases := map[string]bool{"": false, "http://127.0.0.1:10102": false, "http://localhost:3000": false,
		"http://[::1]:10102": false, "https://wallet.localhost": false,
		"https://evil.example": true, "null": true, "http://10.0.0.5": true, "file://": true, "%zz": true}
	for o, want := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		if o != "" {
			r.Header.Set("Origin", o)
		}
		if got := ForeignOrigin(r); got != want {
			t.Errorf("ForeignOrigin(%q) = %v, want %v", o, got, want)
		}
	}
}

// The guard: a rebinding Host is refused on a loopback bind only; a foreign Origin reaches only ForeignOK paths;
// every refusal is reported once; local clients pass untouched.
func TestGuard(t *testing.T) {
	reasons := map[string]int{}
	served := 0
	h := Guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { served++ }),
		Policy{LoopbackBind: true, ForeignOK: func(p string) bool { return p == "/ws" }, OnReject: func(r string) { reasons[r]++ }})
	do := func(h http.Handler, host, origin, path string) int {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = host
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if c := do(h, "127.0.0.1:10102", "", "/json_rpc"); c != 200 {
		t.Fatalf("local request: %d", c)
	}
	if c := do(h, "rebind.evil.example:10102", "", "/debug/pprof/cmdline"); c != http.StatusForbidden {
		t.Fatalf("rebinding Host: %d", c)
	}
	if c := do(h, "127.0.0.1:10102", "https://evil.example", "/metrics"); c != http.StatusForbidden {
		t.Fatalf("foreign Origin on /metrics: %d", c)
	}
	if c := do(h, "127.0.0.1:10102", "https://evil.example", "/ws"); c != 200 {
		t.Fatalf("foreign Origin on /ws: %d", c)
	}
	if c := do(h, "127.0.0.1:10102", "http://127.0.0.1:10102", "/metrics"); c != 200 {
		t.Fatalf("same-origin dashboard poll: %d", c)
	}
	if served != 3 || reasons[REASON_HOST] != 1 || reasons[REASON_ORIGIN] != 1 {
		t.Fatalf("served %d, reasons %v", served, reasons)
	}
	public := Guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), Policy{LoopbackBind: false})
	if c := do(public, "node.example.org:10102", "", "/json_rpc"); c != 200 {
		t.Fatalf("public bind refused a named Host: %d", c)
	}
	if c := do(public, "node.example.org:10102", "https://evil.example", "/json_rpc"); c != http.StatusForbidden {
		t.Fatalf("public bind, nil ForeignOK, foreign Origin: %d", c)
	}
}

// FuzzHostOrigin: the parsers never panic, a loopback literal with a numeric port is always allowed, and appending a
// public label to any Host never yields an allowed Host (the rebinding shape).
func FuzzHostOrigin(f *testing.F) {
	for _, s := range []string{"127.0.0.1:1", "[::1]:1", "localhost", "a.localhost.", "evil.example:1", "[", "]:", "%", "null", "http://[::1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		HostAllowed(s, ParseList(s))
		if HostAllowed(s+".evil-example-test", nil) {
			t.Fatalf("Host %q + .evil-example-test allowed", s)
		}
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Origin", s)
		ForeignOrigin(r)
		if !HostAllowed("127.0.0.1:10102", ParseList(s)) || !HostAllowed("[::1]:10102", ParseList(s)) {
			t.Fatal("a loopback literal was refused")
		}
	})
}

// r20 merge (SEC20-02 review): an operator-listed Origin is local; nothing else changes.
func TestForeignOriginExcept(t *testing.T) {
	allow := ParseOrigins(" chrome-extension://AbC/ , file://, ,null, NULL ")
	cases := map[string]bool{"chrome-extension://abc": false, "CHROME-EXTENSION://ABC/": false, "file://": false,
		"null": true, "chrome-extension://other": true, "https://evil.example": true, "": false,
		"http://localhost:3000": false}
	for o, want := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		if o != "" {
			r.Header.Set("Origin", o)
		}
		if got := ForeignOriginExcept(r, allow); got != want {
			t.Errorf("ForeignOriginExcept(%q) = %v, want %v", o, got, want)
		}
		if o == "chrome-extension://abc" && !ForeignOriginExcept(r, nil) {
			t.Error("without the list an extension Origin must stay foreign")
		}
	}
	served := 0
	h := Guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { served++ }), Policy{LoopbackBind: true, AllowOrigins: allow})
	r := httptest.NewRequest("POST", "/json_rpc", nil)
	r.Host = "127.0.0.1:10102"
	r.Header.Set("Origin", "chrome-extension://abc")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || served != 1 {
		t.Fatalf("listed extension Origin: HTTP %d served=%d, want 200/1", w.Code, served)
	}
}

// r21: "null" is the Origin of every sandboxed iframe on the web; listing it must not make those callers local.
func TestParseOriginsNeverListsNull(t *testing.T) {
	for _, s := range []string{"null", " NULL ", "file://,null", "null/"} {
		for _, o := range ParseOrigins(s) {
			if o == "null" {
				t.Fatalf("ParseOrigins(%q) kept \"null\"", s)
			}
		}
	}
	r := httptest.NewRequest("GET", "/metrics", nil)
	r.Host = "127.0.0.1:10102"
	r.Header.Set("Origin", "null")
	w := httptest.NewRecorder()
	Guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), Policy{LoopbackBind: true, AllowOrigins: ParseOrigins("null")}).ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("Origin null with DERO_RPC_ALLOWED_ORIGINS=null: HTTP %d, want 403", w.Code)
	}
}

// r21 bypass catalogue, sent as raw bytes through net/http's real parser: the Host the guard sees is the one Go
// derives (absolute-form request targets override the Host header; HTTP/1.1 without Host or with two is a 400 before
// the guard). Only an HTTP/1.0 request without Host passes unchecked, and no browser sends one.
func TestGuardRawRequests(t *testing.T) {
	srv := httptest.NewServer(Guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		Policy{LoopbackBind: true, ForeignOK: func(p string) bool { return p == "/ws" }}))
	defer srv.Close()
	cases := []struct {
		raw  string
		want int // 0 = anything but 200
	}{
		{"GET http://evil.example/x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", 403},
		{"GET http://127.0.0.1/x HTTP/1.1\r\nHost: evil.example\r\n\r\n", 200}, // what Go routes on; browsers never send absolute-form
		{"GET / HTTP/1.0\r\n\r\n", 200},
		{"GET / HTTP/1.1\r\n\r\n", 400},
		{"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nHost: evil.example\r\n\r\n", 400},
		{"GET / HTTP/1.1\r\nHost: LOCALHOST.:10102\r\n\r\n", 200},
		{"GET / HTTP/1.1\r\nHost: [::1]:10102\r\n\r\n", 200},
		{"GET / HTTP/1.1\r\nHost: [::ffff:127.0.0.1]:10102\r\n\r\n", 200},
		{"GET / HTTP/1.1\r\nHost: 2130706433:10102\r\n\r\n", 403}, // decimal 127.0.0.1: refused (fail closed)
		{"GET / HTTP/1.1\r\nHost: [::1%25lo0]:10102\r\n\r\n", 0},
		{"GET / HTTP/1.1\r\nHost: evil.example.:10102\r\n\r\n", 403},
		{"GET / HTTP/1.1\r\nHost: 127.0.0.1:10102\r\nOrigin: https://evil.example\r\n\r\n", 403},
		{"GET /ws/ HTTP/1.1\r\nHost: 127.0.0.1:10102\r\nOrigin: https://evil.example\r\n\r\n", 403},  // only exactly /ws
		{"GET /%77s HTTP/1.1\r\nHost: 127.0.0.1:10102\r\nOrigin: https://evil.example\r\n\r\n", 200}, // decodes to /ws
	}
	for _, c := range cases {
		conn, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		conn.Write([]byte(c.raw))
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		conn.Close()
		if err != nil {
			t.Fatalf("%q: %v", c.raw, err)
		}
		if (c.want == 0 && resp.StatusCode == 200) || (c.want != 0 && resp.StatusCode != c.want) {
			t.Errorf("%q: HTTP %d, want %d", c.raw, resp.StatusCode, c.want)
		}
	}
}
