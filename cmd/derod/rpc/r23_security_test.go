package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/code"

	"github.com/deroproject/derohe/errormsg"
)

// fresh_abuse swaps in a fresh global table for one test (handlers read rpc_abuse).
func fresh_abuse(t *testing.T) *abuse_table {
	old := rpc_abuse
	rpc_abuse = new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	t.Cleanup(func() { rpc_abuse = old })
	return rpc_abuse
}

func TestR23AbuseKeyIPv6Slash64(t *testing.T) {
	a, b := abuse_key("2001:db8:1:2:aaaa::1"), abuse_key("2001:db8:1:2:bbbb:cc::9")
	if a != b || a != "2001:db8:1:2::/64" {
		t.Fatalf("IPv6 hosts of one /64 must share a key: %q %q", a, b)
	}
	if abuse_key("2001:db8:1:3::1") == a {
		t.Fatal("another /64 must have its own key")
	}
	if abuse_key("203.0.113.9") != "203.0.113.9" || abuse_key("::1") != "::1" {
		t.Fatal("IPv4 and loopback keys must be the address itself")
	}
	req := httptest.NewRequest("POST", "/json_rpc", nil)
	req.RemoteAddr = "[2001:db8:1:2:dead::7]:5555"
	if ip, lb := remote_ip(req); ip != a || lb {
		t.Fatalf("remote_ip must key IPv6 callers by /64: %q %v", ip, lb)
	}
}

func TestR23RateBucketWeighted(t *testing.T) {
	tb := new_abuse_table(10, 20, 100)
	now := time.Unix(1000, 0)
	for i := 0; i < 2; i++ { // cost 8 each: 16 of 20 tokens
		if v, _ := tb.admit("k", "DERO.GetBlockHeadersRange", false, now); v != abuse_ok {
			t.Fatalf("call %d: %v", i, v)
		}
	}
	v, d := tb.admit("k", "DERO.GetBlockHeadersRange", false, now)
	if v != abuse_rate_limited || d <= 0 || d > time.Second {
		t.Fatalf("3rd expensive call: %v retry %v, want rate_limited with a retry hint <= 1s", v, d)
	}
	if v, _ := tb.admit("k", "DERO.Ping", false, now); v != abuse_ok { // 4 tokens left, Ping costs 1
		t.Fatalf("cheap call must still pass: %v", v)
	}
	if v, _ := tb.admit("k", "DERO.GetBlockHeadersRange", false, now.Add(time.Second)); v != abuse_ok {
		t.Fatalf("after refill: %v", v)
	}
	if v, _ := tb.admit("other", "DERO.GetBlockHeadersRange", false, now); v != abuse_ok {
		t.Fatal("keys must not share a bucket")
	}
}

func TestR23UnknownMethodsBanEscalates(t *testing.T) {
	tb := new_abuse_table(1000, 1000, 100)
	now := time.Unix(2000, 0)
	n := int(ABUSE_SCORE_BAN / ABUSE_PTS_UNKNOWN_METHOD)
	for i := 1; i < n; i++ {
		if v, _ := tb.admit("s", "X.Probe", true, now); v != abuse_ok {
			t.Fatalf("unknown call %d banned early: %v", i, v)
		}
	}
	v, d := tb.admit("s", "X.Probe", true, now)
	if v != abuse_banned || d != ABUSE_BAN_BASE {
		t.Fatalf("unknown call %d: %v %v, want banned %v", n, v, d, ABUSE_BAN_BASE)
	}
	if v, _ := tb.admit("s", "DERO.Ping", false, now.Add(time.Second)); v != abuse_banned {
		t.Fatal("a banned key must be refused even for known methods")
	}
	if tb.banned_for("s", now.Add(time.Second)) <= 0 {
		t.Fatal("banned_for must report the ban")
	}
	now = now.Add(ABUSE_BAN_BASE + time.Second)
	if v, _ := tb.admit("s", "DERO.Ping", false, now); v != abuse_ok {
		t.Fatalf("ban must end: %v", v)
	}
	for i := 1; i < n; i++ {
		tb.admit("s", "X.Probe", true, now)
	}
	if v, d := tb.admit("s", "X.Probe", true, now); v != abuse_banned || d != 2*ABUSE_BAN_BASE {
		t.Fatalf("second ban: %v %v, want %v", v, d, 2*ABUSE_BAN_BASE)
	}
	if tb.banned_for("s2", now) != 0 {
		t.Fatal("another key must not be banned")
	}
}

// an honest client that sees a handler error every second, or a bad-param error every 5 s, for an hour is never banned
func TestR23HonestErrorRatesNeverBan(t *testing.T) {
	tb := new_abuse_table(1000, 1000, 100)
	now := time.Unix(3000, 0)
	for i := 0; i < 3600; i++ {
		if tb.observe("h", code.SystemError, now) > 0 {
			t.Fatalf("handler errors at 1/s banned after %d s", i)
		}
		if i%5 == 0 && tb.observe("h", code.InvalidParams, now) > 0 {
			t.Fatalf("bad params at 1/5s banned after %d s", i)
		}
		now = now.Add(time.Second)
	}
}

func TestR23ObserveCodes(t *testing.T) {
	tb := new_abuse_table(1000, 1000, 100)
	now := time.Unix(4000, 0)
	for i := 0; i < 1000; i++ { // charged at admission (or our own refusals): never scored twice
		for _, c := range []code.Code{0, code.MethodNotFound, RPC_CODE_RATE_LIMITED, RPC_CODE_BANNED} {
			if tb.observe("o", c, now) > 0 {
				t.Fatalf("code %d must not score", c)
			}
		}
	}
	n := int(math.Ceil(ABUSE_SCORE_BAN / ABUSE_PTS_BAD_REQUEST))
	banned := 0
	for i := 0; i < n; i++ {
		if tb.observe("o", code.InvalidParams, now) > 0 {
			banned = i + 1
		}
	}
	if banned != n {
		t.Fatalf("param fuzzing: banned at %d, want %d", banned, n)
	}
}

func TestR23RefusalsHammeringEndsInBan(t *testing.T) {
	tb := new_abuse_table(1, 1, 100)
	now := time.Unix(5000, 0)
	tb.admit("f", "DERO.Ping", false, now)
	var last abuse_verdict
	for i := 0; i < int(ABUSE_SCORE_BAN/ABUSE_PTS_REFUSED); i++ {
		last, _ = tb.admit("f", "DERO.Ping", false, now)
	}
	if last != abuse_banned {
		t.Fatalf("a client hammering on after refusals: %v, want banned", last)
	}
}

func TestR23TableBounded(t *testing.T) {
	tb := new_abuse_table(10, 10, 4)
	now := time.Unix(6000, 0)
	for i := 0; i < 50; i++ {
		tb.admit(fmt.Sprintf("10.0.0.%d", i), "DERO.Ping", false, now)
	}
	if n := tb.size(); n != 5 {
		t.Fatalf("table size %d, want max_entries+overflow = 5", n)
	}
	if tb.m[ABUSE_OVERFLOW_KEY] == nil {
		t.Fatal("keys past the bound must share the overflow key")
	}
	later := now.Add(10 * time.Minute) // idle, unscored entries are dropped for new keys
	tb.admit("10.9.9.9", "DERO.Ping", false, later)
	if tb.m["10.9.9.9"] == nil || tb.size() > 4 {
		t.Fatalf("idle entries must be evicted: size %d", tb.size())
	}
}

func TestR23ConfigureAbuse(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, 10)
	env := map[string]string{"DERO_RPC_REMOTE_RATE": "5", "DERO_RPC_REMOTE_BURST": "7"}
	configure_abuse(tb, func(k string) string { return env[k] })
	if tb.rate != 5 || tb.burst != 7 || !tb.enabled {
		t.Fatalf("env not applied: %v %v %v", tb.rate, tb.burst, tb.enabled)
	}
	configure_abuse(tb, func(k string) string { return map[string]string{"DERO_RPC_ABUSE_GUARD": "0"}[k] })
	for i := 0; i < 100; i++ {
		if v, _ := tb.admit("x", "X.Y", true, time.Unix(1, 0)); v != abuse_ok {
			t.Fatal("a disabled guard must admit everything")
		}
	}
}

func decode_rpc_error(t *testing.T, body string) (c int, retry int64) {
	t.Helper()
	var r struct {
		Error struct {
			Code int `json:"code"`
			Data struct {
				RetryAfterMS int64 `json:"retry_after_ms"`
			} `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("refusal is not JSON-RPC: %v %q", err, body)
	}
	return r.Error.Code, r.Error.Data.RetryAfterMS
}

// remote HTTP clients that probe unknown names are banned with a machine-readable reply; loopback never is
func TestR23RemoteHTTPProbeBanLoopbackExempt(t *testing.T) {
	fresh_abuse(t)
	probe := `{"jsonrpc":"2.0","id":1,"method":"Admin.DumpKeys"}`
	n := int(ABUSE_SCORE_BAN / ABUSE_PTS_UNKNOWN_METHOD)
	for i := 0; i < n-1; i++ {
		if w := post_from("198.51.100.7:1000", probe); w.Code != http.StatusOK {
			t.Fatalf("probe %d: HTTP %d", i, w.Code)
		}
	}
	w := post_from("198.51.100.7:1000", probe)
	if w.Code == http.StatusOK { // real-time decay between the calls can leave the score a hair under the line
		w = post_from("198.51.100.7:1000", probe)
	}
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("probe %d: HTTP %d Retry-After %q, want 429 with Retry-After", n, w.Code, w.Header().Get("Retry-After"))
	}
	if c, r := decode_rpc_error(t, w.Body.String()); c != int(RPC_CODE_BANNED) || r <= 0 {
		t.Fatalf("refusal code %d retry %d", c, r)
	}
	if strings.Contains(w.Body.String(), "Admin") || strings.Contains(w.Body.String(), ".go") {
		t.Fatalf("refusal must carry no request echo or internal detail: %s", w.Body.String())
	}
	if w := post_from("198.51.100.7:1001", `{"jsonrpc":"2.0","id":2,"method":"DERO.Ping"}`); w.Code != http.StatusTooManyRequests {
		t.Fatalf("banned key, known method: HTTP %d", w.Code)
	}
	if w := post_from("198.51.100.8:1000", `{"jsonrpc":"2.0","id":2,"method":"DERO.Ping"}`); w.Code != http.StatusOK {
		t.Fatalf("neighbour address must not be banned: HTTP %d", w.Code)
	}
	for i := 0; i < 3*n; i++ {
		if w := post_from("127.0.0.1:1000", probe); w.Code != http.StatusOK {
			t.Fatalf("loopback probe %d: HTTP %d (loopback must be exempt)", i, w.Code)
		}
	}
	if n := rpc_abuse.size() - aggregate_records(rpc_abuse); n != 2 { // r23c: plus the /24 aggregate record of the two
		t.Fatalf("loopback must not be tracked: %d keys", n)
	}
}

// param fuzzing is scored from the bridge's reply (InvalidParams), not from the request
func TestR23RemoteHTTPParamFuzzScoredFromReply(t *testing.T) {
	fresh_abuse(t)
	fuzz := `{"jsonrpc":"2.0","id":1,"method":"DERO.Echo","params":{"x":[1,{"y":2}]}}`
	n := int(math.Ceil(ABUSE_SCORE_BAN / ABUSE_PTS_BAD_REQUEST))
	for i := 0; i < n; i++ {
		w := post_from("198.51.100.9:1000", fuzz)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), fmt.Sprint(int(code.InvalidParams))) {
			t.Fatalf("fuzz %d: HTTP %d %s", i, w.Code, w.Body.String())
		}
	}
	if w := post_from("198.51.100.9:1000", fuzz); w.Code != http.StatusTooManyRequests {
		t.Fatalf("after %d invalid-params replies: HTTP %d, want 429", n, w.Code)
	}
}

func TestR23RemoteHTTPRateLimited(t *testing.T) {
	tb := fresh_abuse(t)
	tb.rate, tb.burst = 1, 16
	batch := `[` + strings.Repeat(`{"jsonrpc":"2.0","id":1,"method":"DERO.GetBlockHeadersRange","params":{}},`, 2) +
		`{"jsonrpc":"2.0","id":3,"method":"DERO.Ping"}]` // 8+8+1 = 17 > 16
	w := post_from("198.51.100.10:1000", batch)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over-budget batch: HTTP %d", w.Code)
	}
	if c, r := decode_rpc_error(t, w.Body.String()); c != int(RPC_CODE_RATE_LIMITED) || r <= 0 {
		t.Fatalf("rate refusal code %d retry %d", c, r)
	}
}

func TestR23WSAssignerAndBannedUpgrade(t *testing.T) {
	fresh_abuse(t)
	c := &ws_client{abuse_key: "198.51.100.11"}
	a := remote_assigner{c: c, next: d}
	if h := a.Assign(context.Background(), "DERO.Ping"); h == nil {
		t.Fatal("known method must keep its handler")
	}
	n := int(ABUSE_SCORE_BAN / ABUSE_PTS_UNKNOWN_METHOD)
	var h jrpc2.Handler
	for i := 0; i < n+1; i++ { // n+1: real-time decay between the calls (see the HTTP probe test)
		h = a.Assign(context.Background(), "Nope.Nope")
	}
	if h == nil {
		t.Fatal("a banned call must get the refusal handler")
	}
	reqs, _ := jrpc2.ParseRequests([]byte(`{"jsonrpc":"2.0","id":1,"method":"Nope.Nope"}`))
	_, err := h.Handle(context.Background(), reqs[0])
	if e, ok := err.(*jrpc2.Error); !ok || e.Code != RPC_CODE_BANNED {
		t.Fatalf("banned socket call: %v", err)
	}
	req := httptest.NewRequest("GET", "/ws", nil)
	req.RemoteAddr = "198.51.100.11:777"
	w := httptest.NewRecorder()
	ws_handler(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("banned key opening /ws: HTTP %d", w.Code)
	}
	req.RemoteAddr = "127.0.0.1:777"
	w = httptest.NewRecorder()
	ws_handler(w, req)
	if w.Code == http.StatusTooManyRequests {
		t.Fatal("loopback /ws must never be refused by the abuse guard")
	}
}

// ---- getwork ----

func TestR23GetworkPerIPCap(t *testing.T) {
	old := getwork_conn_limit
	getwork_conn_limit = new_ip_limiter(3)
	defer func() { getwork_conn_limit = old }()
	for i := 0; i < 3; i++ {
		if _, _, ok := getwork_admit(httptest.NewRecorder(), "192.0.2.50:1"); !ok {
			t.Fatalf("session %d refused", i)
		}
	}
	w := httptest.NewRecorder()
	if _, _, ok := getwork_admit(w, "192.0.2.50:2"); ok || w.Code != http.StatusTooManyRequests {
		t.Fatalf("4th session: ok=%v HTTP %d", ok, w.Code)
	}
	for i := 0; i < 10; i++ {
		if _, lb, ok := getwork_admit(httptest.NewRecorder(), "127.0.0.1:9"); !ok || !lb {
			t.Fatal("loopback miners must be unlimited")
		}
	}
	s := &user_session{limit_key: "192.0.2.50"}
	s.release_slot()
	s.release_slot() // once only
	if _, _, ok := getwork_admit(httptest.NewRecorder(), "192.0.2.50:3"); !ok {
		t.Fatal("a released slot must be reusable")
	}
	if _, _, ok := getwork_admit(httptest.NewRecorder(), "192.0.2.50:4"); ok {
		t.Fatal("release_slot must free exactly one slot")
	}
}

func TestR23GetworkBadShareBan(t *testing.T) {
	old := getwork_bans
	getwork_bans = new_abuse_table(1, 1, 100)
	defer func() { getwork_bans = old }()
	if !share_is_bad(false, errormsg.ErrInvalidPoW) || !share_is_bad(false, err_share_undecodable) {
		t.Fatal("invalid PoW and undecodable shares are bad")
	}
	if share_is_bad(false, fmt.Errorf("job not found in cache")) || share_is_bad(true, nil) || share_is_bad(true, errormsg.ErrInvalidPoW) {
		t.Fatal("stale jobs and accepted shares are not bad")
	}
	s := &user_session{limit_key: "192.0.2.60"}
	for i := 0; i < GETWORK_BAD_SHARE_LIMIT-1; i++ {
		getwork_note_share(nil, s, false, errormsg.ErrInvalidPoW)
	}
	getwork_note_share(nil, s, true, nil) // one good share resets the run
	for i := 0; i < GETWORK_BAD_SHARE_LIMIT-1; i++ {
		getwork_note_share(nil, s, false, errormsg.ErrInvalidPoW)
	}
	if s.guard.is_closed() || getwork_ban_left("192.0.2.60", time.Now()) > 0 {
		t.Fatal("a run shorter than the limit must not ban")
	}
	getwork_note_share(nil, s, false, errormsg.ErrInvalidPoW)
	if !s.guard.is_closed() {
		t.Fatal("the limit-th consecutive bad share must close the session")
	}
	if d := getwork_ban_left("192.0.2.60", time.Now()); d <= 0 || d > GETWORK_BAN_BASE {
		t.Fatalf("ban %v", d)
	}
	w := httptest.NewRecorder()
	if _, _, ok := getwork_admit(w, "192.0.2.60:5"); ok || w.Code != http.StatusTooManyRequests {
		t.Fatal("a banned key must not open a getwork session")
	}
	if d := getwork_ban("192.0.2.60", time.Now()); d != 2*GETWORK_BAN_BASE {
		t.Fatalf("second ban %v, want %v", d, 2*GETWORK_BAN_BASE)
	}
	lb := &user_session{limit_key: "127.0.0.1", loopback: true}
	for i := 0; i < 5*GETWORK_BAD_SHARE_LIMIT; i++ {
		getwork_note_share(nil, lb, false, errormsg.ErrInvalidPoW)
	}
	if lb.guard.is_closed() {
		t.Fatal("loopback sessions are never closed by the guard")
	}
}

// a local share queued behind a remote flood waits for at most 2 remote verifications (the running one and the one
// remote that may hold the gate)
func TestR23LocalShareNotStarvedByRemoteFlood(t *testing.T) {
	const remotes = 8
	var mu sync.Mutex
	var order []string
	var wg sync.WaitGroup
	var started int32
	for i := 0; i < remotes; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			atomic.AddInt32(&started, 1)
			verify_share_from(false, func() {
				time.Sleep(15 * time.Millisecond)
				mu.Lock()
				order = append(order, "r")
				mu.Unlock()
			})
		}()
	}
	for atomic.LoadInt32(&started) < remotes {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(5 * time.Millisecond) // the first remote is verifying, the rest are queued
	mu.Lock()
	before := len(order)
	mu.Unlock()
	verify_share_from(true, func() {
		mu.Lock()
		order = append(order, "L")
		mu.Unlock()
	})
	wg.Wait()
	pos := -1
	for i, o := range order {
		if o == "L" {
			pos = i
		}
	}
	if waited := pos - before; waited > 2 {
		t.Fatalf("local share waited for %d remote verifications (order %v), want <= 2", waited, order)
	}
}

func BenchmarkR23AdmitRemote(b *testing.B) {
	tb := new_abuse_table(1e12, 1e12, ABUSE_MAX_ENTRIES)
	now := time.Now()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tb.admit("198.51.100.20", "DERO.GetInfo", false, now)
	}
}

func bench_post(b *testing.B, from string) {
	body := `{"jsonrpc":"2.0","id":1,"method":"DERO.Ping"}`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/json_rpc", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = from
		json_rpc_handler(httptest.NewRecorder(), req)
	}
}

func BenchmarkR23PingLoopback(b *testing.B) { bench_post(b, "127.0.0.1:1") }

func BenchmarkR23PingRemoteGuarded(b *testing.B) {
	old := rpc_abuse
	rpc_abuse = new_abuse_table(1e12, 1e12, ABUSE_MAX_ENTRIES)
	defer func() { rpc_abuse = old }()
	bench_post(b, "198.51.100.21:1")
}

func BenchmarkR23PingRemoteUnguarded(b *testing.B) {
	old := rpc_abuse
	rpc_abuse = new_abuse_table(1e12, 1e12, ABUSE_MAX_ENTRIES)
	rpc_abuse.enabled = false
	defer func() { rpc_abuse = old }()
	bench_post(b, "198.51.100.22:1")
}

// attack path: a banned prober's call is refused before the bridge (no handler, no jrpc2 server round trip)
func BenchmarkR23ProbeBanned(b *testing.B) {
	old := rpc_abuse
	rpc_abuse = new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	defer func() { rpc_abuse = old }()
	rpc_abuse.admit("198.51.100.23", "x", true, time.Now())
	rpc_abuse.m["198.51.100.23"].banned_until = time.Now().Add(time.Hour)
	bench_post(b, "198.51.100.23:1")
}

// a refused call that carries params must get the refusal code, not -32602 (handler.New's no-params check)
func TestR23RefusalCodeSurvivesParams(t *testing.T) {
	reqs, err := jrpc2.ParseRequests([]byte(`{"jsonrpc":"2.0","id":1,"method":"DERO.GetBlock","params":{"hash":"00"}}`))
	if err != nil || len(reqs) != 1 {
		t.Fatal(err)
	}
	fresh_abuse(t)
	a := remote_assigner{c: &ws_client{abuse_key: "198.51.100.30"}, next: d}
	var banned jrpc2.Handler
	for i := 0; i < 2*int(ABUSE_SCORE_BAN/ABUSE_PTS_UNKNOWN_METHOD); i++ {
		banned = a.Assign(context.Background(), "Nope.Nope")
	}
	for i, h := range []jrpc2.Handler{rate_limited_handler, banned} {
		_, err := h.Handle(context.Background(), reqs[0])
		e, ok := err.(*jrpc2.Error)
		if !ok || (e.Code != RPC_CODE_RATE_LIMITED && e.Code != RPC_CODE_BANNED) {
			t.Fatalf("refusal %d with params answered %v", i, err)
		}
	}
}

// the remote pre-parse never panics, agrees with batch_len on how many requests a body holds, and the reply scan
// never panics on arbitrary bytes
func FuzzR23RequestMethods(f *testing.F) {
	for _, s := range []string{`{"method":"DERO.Ping"}`, `[{"method":"a"},{"method":"b"}]`, `[]`, `{`, `[1,2]`, ` [{"method":1}]`, `{"error":{"code":-32602}}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		m, err := request_methods(body)
		n, berr := batch_len(body)
		if err == nil && berr == nil && len(m) != n {
			t.Fatalf("request_methods %d vs batch_len %d for %q", len(m), n, body)
		}
		response_error_codes(body)
	})
}

// r23 merge: with the table full, admitting new keys costs O(1): the idle-record scan runs at most once per
// ABUSE_PRUNE_INTERVAL, not once per request (it held t.mu ~0.5 ms per call at 16384 records).
func TestR23FullTableAdmitBounded(t *testing.T) {
	const max = 256
	tb := new_abuse_table(1000, 1000, max)
	now := time.Unix(7000, 0)
	for i := 0; i < max; i++ { // scored keys: none of them can be pruned
		tb.admit(fmt.Sprintf("10.1.%d.%d", i/256, i%256), "X.Unknown", true, now)
	}
	s0 := tb.scanned
	for i := 0; i < 1000; i++ {
		tb.admit(fmt.Sprintf("10.2.%d.%d", i/256, i%256), "DERO.Ping", false, now.Add(time.Duration(i)*time.Millisecond/4))
	}
	if d := tb.scanned - s0; d > 2*(max+1) {
		t.Fatalf("1000 new-key admissions within 250 ms scanned %d records (want at most 2 scans of %d)", d, max+1)
	}
}

// r23 merge: the shared overflow record is rate-limited only: unknown-method probes from keys that did not fit the
// table can never ban it (which would lock every new honest client out).
func TestR23OverflowKeyNeverBanned(t *testing.T) {
	const max = 8
	tb := new_abuse_table(1000, 1000, max)
	now := time.Unix(8000, 0)
	for i := 0; i < max; i++ {
		tb.admit(fmt.Sprintf("10.3.0.%d", i), "X.Unknown", true, now)
	}
	for i := 0; i < 500; i++ {
		if v, _ := tb.admit(fmt.Sprintf("10.4.%d.%d", i/256, i%256), "X.Unknown", true, now); v == abuse_banned {
			t.Fatalf("overflow key banned after %d unknown-method probes", i+1)
		}
	}
	if e := tb.m[ABUSE_OVERFLOW_KEY]; e == nil || !e.overflow || now.Before(e.banned_until) {
		t.Fatalf("overflow record missing or banned: %+v", e)
	}
	if d := tb.banned_for("10.5.0.1", now); d != 0 {
		t.Fatalf("a new honest key is banned for %v", d)
	}
}
