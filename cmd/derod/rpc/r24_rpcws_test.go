package rpc

// r24 (rpcws): B29 per-body item total + item-weighted cost, B38 /json_rpc request shape (r24_rpcws.go).

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/creachadair/jrpc2/code"
	"golang.org/x/time/rate"
)

// r24_body builds a /json_rpc body of calls GetTransaction requests naming per txids each (a single object for 1).
func r24_body(calls, per int) string {
	var b strings.Builder
	if calls > 1 {
		b.WriteByte('[')
	}
	for c := 0; c < calls; c++ {
		if c > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"jsonrpc":"2.0","id":%d,"method":"DERO.GetTransaction","params":%s}`, c, r23c_hashes(per))
	}
	if calls > 1 {
		b.WriteByte(']')
	}
	return b.String()
}

func r24_post(body, addr, ctype string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/json_rpc", strings.NewReader(body))
	req.RemoteAddr = addr
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	rec := httptest.NewRecorder()
	json_rpc_handler(rec, req)
	return rec
}

// B29: the per-body total. 4 full calls pass, a fifth item over the total is refused, per-request counts line up.
func TestR24RemoteBodyItemsTotal(t *testing.T) {
	items, err := remote_body_items([]byte(r24_body(4, MAX_REMOTE_TX_HASHES)))
	if err != nil {
		t.Fatalf("%d items in 4 calls refused: %v", MAX_REMOTE_BODY_ITEMS, err)
	}
	if len(items) != 4 || items[0] != MAX_REMOTE_TX_HASHES || items[3] != MAX_REMOTE_TX_HASHES {
		t.Fatalf("per-request item counts: %v", items)
	}
	refused0, body0 := param_bound_refused.Get(), body_items_refused.Get()
	over := `[` + r24_body(1, MAX_REMOTE_TX_HASHES) + `,` + r24_body(1, MAX_REMOTE_TX_HASHES) + `,` + r24_body(1, MAX_REMOTE_TX_HASHES) + `,` +
		r24_body(1, MAX_REMOTE_TX_HASHES) + `,` + r24_body(1, 1) + `]`
	if _, err := remote_body_items([]byte(over)); err == nil || !strings.Contains(err.Error(), "per body") {
		t.Fatalf("%d items in one body admitted: %v", MAX_REMOTE_BODY_ITEMS+1, err)
	}
	if param_bound_refused.Get() != refused0+1 || body_items_refused.Get() != body0+1 {
		t.Fatal("body refusal not counted once in both counters")
	}
	// GetSC keys count toward the same total
	keys := `{"jsonrpc":"2.0","id":9,"method":"DERO.GetSC","params":{"scid":"00","keysstring":[` + strings.TrimSuffix(strings.Repeat(`"a",`, 200), ",") + `]}}`
	mixed := `[` + strings.TrimSuffix(strings.TrimPrefix(r24_body(4, 207), "["), "]") + `,` + keys + `]`
	if _, err := remote_body_items([]byte(mixed)); err == nil {
		t.Fatal("828 txids + 200 SC keys in one body admitted")
	}
	if items, err := remote_body_items([]byte(`{"jsonrpc":"2.0","id":1,"method":"DERO.GetInfo"}`)); err != nil || items != nil {
		t.Fatalf("a body naming no items: %v %v", items, err)
	}
}

// B29 end to end: the measured 256 x 256 batch is refused before the bridge for a remote caller; loopback is not.
func TestR24RemoteHTTPBatchOfFullCallsRefused(t *testing.T) {
	fresh_abuse(t)
	body := r24_body(HTTP_MAX_BATCH_REMOTE, MAX_REMOTE_TX_HASHES)
	rec := r24_post(body, "192.0.2.81:4444", "application/json")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"code":-32602`) || !strings.Contains(rec.Body.String(), "per body") {
		t.Fatalf("remote 65,536-txid batch: %d %.200s", rec.Code, rec.Body.String())
	}
	rec = r24_post(r24_body(2, 4), "127.0.0.1:4444", "application/json")
	if strings.Contains(rec.Body.String(), "per body") || strings.Contains(rec.Body.String(), "rate limited") {
		t.Fatalf("loopback body bounded: %.200s", rec.Body.String())
	}
}

// B29: item-weighted admission. A full call costs base + 32 tokens, so a 2,000-token burst admits 58 of them instead
// of 1,000; a wallet-sized call (32 txids) costs 2 + 4.
func TestR24ItemWeightedAdmission(t *testing.T) {
	tab := fresh_abuse(t)
	if item_cost(0) != 0 || item_cost(1) != 1 || item_cost(8) != 1 || item_cost(9) != 2 || item_cost(256) != 32 {
		t.Fatal("item_cost table")
	}
	now := time.Now()
	n := 0
	for ; n < 2000; n++ {
		if v, _ := admit_http("192.0.2.82", []string{"DERO.GetTransaction"}, []int{MAX_REMOTE_TX_HASHES}, now); v != abuse_ok {
			break
		}
	}
	want := int(ABUSE_DEFAULT_BURST) / (foreign_cost("DERO.GetTransaction") + item_cost(MAX_REMOTE_TX_HASHES))
	if n != want {
		t.Fatalf("full calls admitted from one burst: %d, want %d", n, want)
	}
	// the refusal carries a retry hint sized for the item cost: 2,000 - 58 x 34 = 28 tokens left, 6 short at 200/s
	if v, d := admit_http("192.0.2.82", []string{"DERO.GetTransaction"}, []int{MAX_REMOTE_TX_HASHES}, now); v != abuse_rate_limited || d != 30*time.Millisecond {
		t.Fatalf("after the burst: %v %v", v, d)
	}
	// a body with no item counts is charged as before
	n = 0
	for ; n < 2000; n++ {
		if v, _ := tab.admit_items("192.0.2.83", "DERO.GetTransaction", false, item_cost(32), now); v != abuse_ok {
			break
		}
	}
	if n != int(ABUSE_DEFAULT_BURST)/6 {
		t.Fatalf("wallet-sized calls from one burst: %d, want %d", n, int(ABUSE_DEFAULT_BURST)/6)
	}
}

// B29 websocket side: a remote socket pays item_cost from its key's bucket and holds at most MAX_REMOTE_BODY_ITEMS
// items in running calls; release returns them; a loopback socket is never charged.
func TestR24SocketItemsChargedAndBounded(t *testing.T) {
	tab := fresh_abuse(t)
	c := &ws_client{abuse_key: "192.0.2.84"}
	var rel []func()
	for i := 0; i < MAX_REMOTE_BODY_ITEMS/MAX_REMOTE_TX_HASHES; i++ {
		r, err := admit_client_items(c, MAX_REMOTE_TX_HASHES, MAX_REMOTE_TX_HASHES, tx_hashes_bound_error)
		if err != nil {
			t.Fatalf("call %d refused: %v", i, err)
		}
		rel = append(rel, r)
	}
	inflight0 := ws_items_inflight_refused.Get()
	if _, err := admit_client_items(c, 1, MAX_REMOTE_TX_HASHES, tx_hashes_bound_error); err == nil || !strings.Contains(err.Error(), "at once") {
		t.Fatalf("item over the in-flight total admitted: %v", err)
	}
	if ws_items_inflight_refused.Get() != inflight0+1 || c.items_held.Load() != MAX_REMOTE_BODY_ITEMS {
		t.Fatalf("in-flight refusal: counter %d->%d, inflight %d", inflight0, ws_items_inflight_refused.Get(), c.items_held.Load())
	}
	for _, r := range rel {
		r()
	}
	if c.items_held.Load() != 0 {
		t.Fatalf("released items still in flight: %d", c.items_held.Load())
	}
	tab.mu.Lock()
	e := tab.m["192.0.2.84"]
	left := e.tokens
	tab.mu.Unlock()
	if spent := ABUSE_DEFAULT_BURST - left; spent < 4*float64(item_cost(MAX_REMOTE_TX_HASHES))-1 {
		t.Fatalf("items not charged to the key's bucket: spent %.1f tokens", spent)
	}
	if _, err := admit_client_items(c, MAX_REMOTE_TX_HASHES+1, MAX_REMOTE_TX_HASHES, tx_hashes_bound_error); err == nil || !strings.Contains(err.Error(), "at most 256") {
		t.Fatalf("per-call bound lost: %v", err)
	}
	local := &ws_client{}
	r, err := admit_client_items(local, 1<<20, MAX_REMOTE_TX_HASHES, tx_hashes_bound_error)
	if err != nil || local.items_held.Load() != 0 {
		t.Fatalf("loopback socket charged or bounded: %v %d", err, local.items_held.Load())
	}
	r()
	// an exhausted bucket refuses the items with the rate-limit code and returns the in-flight reservation
	for i := 0; i < 100; i++ {
		if _, err := admit_client_items(c, MAX_REMOTE_TX_HASHES, MAX_REMOTE_TX_HASHES, tx_hashes_bound_error); err != nil {
			if !strings.Contains(err.Error(), "rate limited") {
				t.Fatalf("bucket refusal: %v", err)
			}
			if c.items_held.Load() != 0 {
				t.Fatalf("refused call kept its reservation: %d", c.items_held.Load())
			}
			return
		}
		c.items_held.Store(0) // the call finished
	}
	t.Fatal("100 full calls on one remote socket never hit the bucket")
}

// B29 cross-site websocket: two full calls in a row exceed the socket's 40-token burst (2 + 32 each); before r24
// they cost 2 tokens each, 20 per burst.
func TestR24ForeignSocketPaysItems(t *testing.T) {
	r24_fresh_node_bucket(t)
	addr := test_server(t)
	foreign, _, err := dial_ws_with(t, addr, http.Header{"Origin": {"http://evil.example"}})
	if err != nil {
		t.Fatal(err)
	}
	r := foreign.call(t, 41, "DERO.GetTransaction", r23c_hashes(MAX_REMOTE_TX_HASHES))
	if strings.Contains(string(r["error"]), "rate limited") {
		t.Fatalf("first full call refused: %s", r["error"])
	}
	r = foreign.call(t, 42, "DERO.GetTransaction", r23c_hashes(MAX_REMOTE_TX_HASHES))
	if !strings.Contains(string(r["error"]), fmt.Sprint(int(RPC_CODE_RATE_LIMITED))) {
		t.Fatalf("second full call within the burst served: %s", r["error"])
	}
	local := dial_ws(t, addr, true)
	for i := 0; i < 4; i++ {
		if r := local.call(t, 50+i, "DERO.GetTransaction", r23c_hashes(MAX_REMOTE_TX_HASHES)); strings.Contains(string(r["error"]), "rate limited") {
			t.Fatalf("loopback socket charged: %s", r["error"])
		}
	}
}

// r24_fresh_node_bucket gives the test its own node-wide cross-site bucket (other tests' foreign sockets drain the
// shared one); set before test_server starts, so the server's goroutines see it. Registered first, its cleanup runs
// last: after the sockets and the server are closed it waits until the cross-site sockets' per-key connection slots
// are released again (ws_handler releases them after it returns), so a later test that counts those slots
// (TestRemoteIPForeignOrigin) does not see this test's sockets go away under it.
func r24_fresh_node_bucket(t *testing.T) {
	old := foreign_node_limiter
	foreign_node_limiter = rate.NewLimiter(FOREIGN_NODE_RATE, FOREIGN_NODE_BURST)
	slots := func() int {
		ws_conn_limit.mu.Lock()
		defer ws_conn_limit.mu.Unlock()
		return ws_conn_limit.n[FOREIGN_LIMIT_KEY]
	}
	n0 := slots()
	t.Cleanup(func() {
		for deadline := time.Now().Add(5 * time.Second); slots() > n0 && time.Now().Before(deadline); {
			time.Sleep(5 * time.Millisecond)
		}
		if n := slots(); n > n0 {
			t.Errorf("cross-site socket slots still held after the test: %d > %d", n, n0)
		}
		foreign_node_limiter = old
	})
}

// B38: application/json variants are served; anything else gets 415/405 WITH a JSON-RPC error body.
func TestR24ContentTypeShape(t *testing.T) {
	ping := `{"jsonrpc":"2.0","id":1,"method":"DERO.Ping"}`
	for _, ct := range []string{"application/json", "application/json; charset=utf-8", "Application/JSON", "application/json;charset=UTF-8", "application/json; charset=\"utf-8\""} {
		rec := r24_post(ping, "127.0.0.1:5000", ct)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Pong") {
			t.Fatalf("Content-Type %q: %d %q", ct, rec.Code, rec.Body.String())
		}
	}
	for _, ct := range []string{"", "text/plain", "text/plain;charset=UTF-8", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "application/json; charset=latin1", "application/json; foo=bar", "application/jsonx", "application/json;;"} {
		rec := r24_post(ping, "127.0.0.1:5000", ct)
		if rec.Code != http.StatusUnsupportedMediaType || !strings.Contains(rec.Body.String(), `"code":-32600`) || !strings.Contains(rec.Body.String(), "application/json") {
			t.Fatalf("Content-Type %q: %d %q", ct, rec.Code, rec.Body.String())
		}
		if rec.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("415 body not labelled JSON: %q", rec.Header().Get("Content-Type"))
		}
	}
	req := httptest.NewRequest("GET", "/json_rpc", nil)
	req.RemoteAddr = "127.0.0.1:5000"
	rec := httptest.NewRecorder()
	json_rpc_handler(rec, req)
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST" || !strings.Contains(rec.Body.String(), `"code":-32600`) {
		t.Fatalf("GET: %d %q %q", rec.Code, rec.Header().Get("Allow"), rec.Body.String())
	}
}

// B38: a remote key's shape refusals are scored as invalid requests (a scanner ends banned); loopback never is.
func TestR24ContentTypeRefusalScoredRemoteOnly(t *testing.T) {
	fresh_abuse(t)
	ping := `{"jsonrpc":"2.0","id":1,"method":"DERO.Ping"}`
	banned := false
	for i := 0; i < 100; i++ {
		if rec := r24_post(ping, "192.0.2.85:1", "text/plain"); rec.Code == http.StatusTooManyRequests {
			if !strings.Contains(rec.Body.String(), fmt.Sprint(int(RPC_CODE_BANNED))) {
				t.Fatalf("429 without the ban code: %s", rec.Body.String())
			}
			banned = true
			if float64(i+1) < ABUSE_SCORE_BAN/ABUSE_PTS_BAD_REQUEST-1 {
				t.Fatalf("banned after only %d refusals", i+1)
			}
			break
		}
	}
	if !banned {
		t.Fatal("100 wrong-type requests from one remote key never led to a ban")
	}
	for i := 0; i < 100; i++ {
		if rec := r24_post(ping, "127.0.0.1:1", "text/plain"); rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("loopback refusal %d: %d", i, rec.Code)
		}
	}
	_ = code.InvalidRequest
}

// B29: GetTransaction and GetSC return their in-flight items when the call ends (a lost release would wedge the socket
// after MAX_REMOTE_BODY_ITEMS items). The in-flight max is lowered to one full call, so a second call finds the first
// one's items still reserved unless it released them. Cross-site socket: 34 of its 40 tokens per call, 20 tokens/s.
func TestR24HandlersReleaseItems(t *testing.T) {
	old := atomic.SwapInt64(&ws_items_inflight_max, MAX_REMOTE_TX_HASHES)
	t.Cleanup(func() { atomic.StoreInt64(&ws_items_inflight_max, old) })
	r24_fresh_node_bucket(t)
	addr := test_server(t)
	foreign, _, err := dial_ws_with(t, addr, http.Header{"Origin": {"http://evil.example"}})
	if err != nil {
		t.Fatal(err)
	}
	keys := `{"scid":"00","keysstring":[` + strings.TrimSuffix(strings.Repeat(`"a",`, MAX_REMOTE_SC_KEYS), ",") + `]}`
	calls := []struct{ m, p string }{{"DERO.GetTransaction", r23c_hashes(MAX_REMOTE_TX_HASHES)}, {"DERO.GetSC", keys}, {"DERO.GetTransaction", r23c_hashes(MAX_REMOTE_TX_HASHES)}}
	for i, c := range calls {
		if i > 0 {
			time.Sleep(1700 * time.Millisecond) // refill the socket's bucket to >= 34 tokens
		}
		r := foreign.call(t, 60+i, c.m, c.p)
		if strings.Contains(string(r["error"]), "at once") || strings.Contains(string(r["error"]), "rate limited") {
			t.Fatalf("call %d (%s) after the previous one ended: %s", i, c.m, r["error"])
		}
	}
}

// B29 end to end on /json_rpc: a remote key's full 256-txid calls are charged their items (34 tokens), so the 59th
// of one burst is refused with the rate-limit code; without the item charge 1,000 would pass.
func TestR24RemoteHTTPItemsCharged(t *testing.T) {
	tab := fresh_abuse(t)
	tab.rate = 1e-6 // no refill while the loop runs (-race is ~10x slower), so the count is exact
	body := r24_body(1, MAX_REMOTE_TX_HASHES)
	want := int(ABUSE_DEFAULT_BURST) / (foreign_cost("DERO.GetTransaction") + item_cost(MAX_REMOTE_TX_HASHES))
	for i := 0; i < 100; i++ {
		rec := r24_post(body, "192.0.2.86:1", "application/json")
		if rec.Code == http.StatusTooManyRequests {
			if !strings.Contains(rec.Body.String(), fmt.Sprint(int(RPC_CODE_RATE_LIMITED))) {
				t.Fatalf("429 without the rate-limit code: %s", rec.Body.String())
			}
			if i != want {
				t.Fatalf("first refusal at call %d, want %d", i+1, want+1)
			}
			return
		}
	}
	t.Fatalf("100 full 256-txid calls from one remote key all admitted (want a refusal near %d)", want+1)
}
