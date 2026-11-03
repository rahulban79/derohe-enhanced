// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package rpc

// r20 security: Host/Origin guard of the RPC listener and the cross-site websocket restrictions.

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func guarded_test_server(t *testing.T) (addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/json_rpc", json_rpc_handler)
	mux.HandleFunc("/ws", ws_handler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("/", hello)
	none := func(string) string { return "" }
	srv := new_rpc_http_server("127.0.0.1:0", rpc_guard("127.0.0.1:10102", mux, none))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func dial_ws_with(t *testing.T, addr string, hdr http.Header) (*ws_test_client, *http.Response, error) {
	c, resp, err := websocket.DefaultDialer.Dial("ws://"+addr+"/ws", hdr)
	if err != nil {
		return nil, resp, err
	}
	t.Cleanup(func() { c.Close() })
	w := &ws_test_client{c: c}
	go func() {
		for {
			_, b, err := c.ReadMessage()
			if err != nil {
				return
			}
			var m map[string]json.RawMessage
			json.Unmarshal(b, &m)
			w.mu.Lock()
			w.got = append(w.got, m)
			w.mu.Unlock()
		}
	}()
	return w, resp, nil
}

func raw_post(t *testing.T, addr, host, origin string) int {
	req, _ := http.NewRequest("POST", "http://"+addr+"/json_rpc", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"DERO.Ping"}`))
	req.Header.Set("Content-Type", "application/json")
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
	resp.Body.Close()
	return resp.StatusCode
}

// DNS rebinding: the live r19 node answered DERO.GetPeerInfo and /debug/pprof/cmdline to Host rebind.evil.example.
func TestRPCGuardRefusesRebindingHost(t *testing.T) {
	addr := guarded_test_server(t)
	before := rpc_guard_refused["host"].Get()
	if c := raw_post(t, addr, "rebind.evil.example:10102", ""); c != http.StatusForbidden {
		t.Fatalf("rebinding Host on /json_rpc: HTTP %d, want 403", c)
	}
	if _, resp, err := dial_ws_with(t, addr, http.Header{"Host": {"rebind.evil.example:10102"}}); err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("rebinding Host on /ws: err %v resp %v", err, resp)
	}
	if c := raw_post(t, addr, "", ""); c != http.StatusOK { // Host = 127.0.0.1:port
		t.Fatalf("local /json_rpc: HTTP %d", c)
	}
	if c := raw_post(t, addr, "localhost:10102", ""); c != http.StatusOK {
		t.Fatalf("Host localhost: HTTP %d", c)
	}
	if got := rpc_guard_refused["host"].Get() - before; got < 2 {
		t.Fatalf("rpc_guard_refused_total{reason=host} grew by %d, want >= 2", got)
	}
	// operator opt-in
	allow := func(k string) string {
		if k == "DERO_RPC_ALLOWED_HOSTS" {
			return "node.lan"
		}
		return ""
	}
	h := rpc_guard("127.0.0.1:10102", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), allow)
	r := httptest.NewRequest("GET", "/health", nil)
	r.Host = "node.lan:10102"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("DERO_RPC_ALLOWED_HOSTS not honoured: %d", w.Code)
	}
}

// Cross-site pages: /ws stays open (web wallets) but the socket is foreign; everything else is refused.
func TestRPCGuardCrossSiteWebsocket(t *testing.T) {
	addr := guarded_test_server(t)
	if c := raw_post(t, addr, "", "https://evil.example"); c != http.StatusForbidden {
		t.Fatalf("foreign Origin on /json_rpc: HTTP %d, want 403", c)
	}
	foreign, _, err := dial_ws_with(t, addr, http.Header{"Origin": {"https://evil.example"}})
	if err != nil {
		t.Fatalf("foreign-Origin websocket refused (web wallets need it): %v", err)
	}
	if r := foreign.call(t, 1, "DERO.Ping", ""); string(r["result"]) != `"Pong "` {
		t.Fatalf("Ping over a foreign websocket: %v", r)
	}
	for i, m := range []string{"DERO.GetPeerInfo", "DERO.GetMiningOutcome"} {
		r := foreign.call(t, 10+i, m, "")
		if r["error"] == nil || !strings.Contains(string(r["error"]), "cross-site") {
			t.Fatalf("%s over a foreign websocket: %v", m, r)
		}
	}
	local, _, err := dial_ws_with(t, addr, http.Header{"Origin": {"http://127.0.0.1:10102"}})
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range []string{"DERO.GetPeerInfo", "DERO.GetMiningOutcome"} {
		r := local.call(t, 20+i, m, "")
		if strings.Contains(string(r["error"]), "cross-site") {
			t.Fatalf("%s refused to a same-machine websocket: %v", m, r)
		}
	}
}

// A foreign page on loopback is limited like a remote client; all foreign Origins share one node-wide key.
func TestRemoteIPForeignOrigin(t *testing.T) {
	r := httptest.NewRequest("GET", "/ws", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	if ip, lo := remote_ip(r); !lo || ip != "127.0.0.1" {
		t.Fatalf("plain loopback: %q %v", ip, lo)
	}
	r.Header.Set("Origin", "https://evil.example")
	if ip, lo := remote_ip(r); lo || ip != FOREIGN_LIMIT_KEY {
		t.Fatalf("foreign loopback: %q %v", ip, lo)
	}
	r.Header.Set("Origin", "https://b.evil.example") // r20 merge: another subdomain does not get its own 64 sockets
	if ip, lo := remote_ip(r); lo || ip != FOREIGN_LIMIT_KEY {
		t.Fatalf("second foreign Origin: %q %v, want the shared key", ip, lo)
	}
	r.Header.Set("Origin", "http://localhost:3000")
	if _, lo := remote_ip(r); !lo {
		t.Fatal("a localhost page lost the loopback exemption")
	}
	key := FOREIGN_LIMIT_KEY
	// r24 (rpcws, B21 class): the previous test's cross-site socket releases its slot only after its ws_handler
	// returns, which can be after that test ended; a slot released while this test holds the rest let the 65th
	// socket in (HTTP 400, measured 6 of 100 -race runs on base 04ceb55, evidence/remoteip_flake_pair.txt).
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		ws_conn_limit.mu.Lock()
		held := ws_conn_limit.n[key]
		ws_conn_limit.mu.Unlock()
		if held == 0 {
			break
		}
	}
	for i := 0; i < WS_MAX_CONNS_PER_IP; i++ {
		ws_conn_limit.acquire(key)
	}
	defer func() {
		for i := 0; i < WS_MAX_CONNS_PER_IP; i++ {
			ws_conn_limit.release(key)
		}
	}()
	r.Header.Set("Origin", "https://c.evil.example")
	w := httptest.NewRecorder()
	ws_handler(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("65th foreign websocket (any Origin): HTTP %d, want 429", w.Code)
	}
}

// r20 merge (SEC20-02 review): DERO_RPC_ALLOWED_ORIGINS lets an operator trust an extension or Electron Origin;
// unset, the same Origin stays foreign.
func TestRPCGuardAllowedOrigins(t *testing.T) {
	none := func(string) string { return "" }
	defer rpc_guard("127.0.0.1:10102", http.NotFoundHandler(), none) // restore the default (no listed Origins)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	req := func(h http.Handler) int {
		r := httptest.NewRequest("POST", "/json_rpc", nil)
		r.Host = "127.0.0.1:10102"
		r.Header.Set("Origin", "chrome-extension://abc")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if c := req(rpc_guard("127.0.0.1:10102", ok, none)); c != http.StatusForbidden {
		t.Fatalf("unlisted extension Origin: HTTP %d, want 403", c)
	}
	env := func(k string) string {
		if k == "DERO_RPC_ALLOWED_ORIGINS" {
			return "chrome-extension://abc"
		}
		return ""
	}
	if c := req(rpc_guard("127.0.0.1:10102", ok, env)); c != http.StatusOK {
		t.Fatalf("listed extension Origin: HTTP %d, want 200", c)
	}
	r := httptest.NewRequest("GET", "/ws", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set("Origin", "chrome-extension://abc")
	if ip, lo := remote_ip(r); !lo || ip != "127.0.0.1" {
		t.Fatalf("listed Origin limited like a web page: %q %v", ip, lo)
	}
}
