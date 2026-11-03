package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/creachadair/jrpc2/server"
	"github.com/gorilla/websocket"

	dmetrics "github.com/deroproject/derohe/metrics"
)

// test_server runs the daemon's mux pieces that need no chain on a loopback listener built like the real one.
func test_server(t *testing.T) (base string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/json_rpc", json_rpc_handler)
	mux.HandleFunc("/ws", ws_handler)
	mux.HandleFunc("/", hello)
	srv := new_rpc_http_server("127.0.0.1:0", mux)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func set_timeouts(t *testing.T, header, write time.Duration) {
	oh, ow := RPC_READ_HEADER_TIMEOUT, WS_WRITE_TIMEOUT
	RPC_READ_HEADER_TIMEOUT, WS_WRITE_TIMEOUT = header, write
	t.Cleanup(func() { RPC_READ_HEADER_TIMEOUT, WS_WRITE_TIMEOUT = oh, ow })
}

func TestSlowHeaderIsCut(t *testing.T) {
	set_timeouts(t, 200*time.Millisecond, WS_WRITE_TIMEOUT)
	addr := test_server(t)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n")) // header never finished
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	for {
		if _, err = c.Read(buf); err != nil {
			break
		}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("server kept a half-sent header open for %v", time.Since(start))
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("connection closed only after %v", el)
	}
}

type ws_test_client struct {
	c   *websocket.Conn
	mu  sync.Mutex
	got []map[string]json.RawMessage
}

func dial_ws(t *testing.T, addr string, read bool) *ws_test_client {
	c, _, err := websocket.DefaultDialer.Dial("ws://"+addr+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	w := &ws_test_client{c: c}
	if read {
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
	}
	return w
}

// wait returns the first message that has field key equal to val (raw JSON), or fails after d.
func (w *ws_test_client) wait(t *testing.T, key, val string, d time.Duration) map[string]json.RawMessage {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		w.mu.Lock()
		for i, m := range w.got {
			if string(m[key]) == val {
				w.got = append(w.got[:i:i], w.got[i+1:]...)
				w.mu.Unlock()
				return m
			}
		}
		w.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no message with %s=%s within %v", key, val, d)
	return nil
}

// try_wait is wait without failing: it reports whether a matching message arrived within d (and consumes it).
func (w *ws_test_client) try_wait(key, val string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		w.mu.Lock()
		for i, m := range w.got {
			if string(m[key]) == val {
				w.got = append(w.got[:i:i], w.got[i+1:]...)
				w.mu.Unlock()
				return true
			}
		}
		w.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

func (w *ws_test_client) call(t *testing.T, id int, method, params string) map[string]json.RawMessage {
	t.Helper()
	req := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q`, id, method)
	if params != "" {
		req += `,"params":` + params
	}
	if err := w.c.WriteMessage(websocket.TextMessage, []byte(req+"}")); err != nil {
		t.Fatal(err)
	}
	return w.wait(t, "id", fmt.Sprint(id), 3*time.Second)
}

func ws_count() (n int) {
	client_connections.Range(func(k, v interface{}) bool { n++; return true })
	return
}

func wait_ws_count(t *testing.T, want int) {
	t.Helper()
	for i := 0; i < 600 && ws_count() != want; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if n := ws_count(); n != want {
		t.Fatalf("%d websocket clients registered, want %d", n, want)
	}
}

// A hijacked websocket must outlive ReadHeaderTimeout; DERO.Subscribe adds BlockInfo after the unchanged Block/Height.
func TestWebsocketSubscribeAndHeaderTimeout(t *testing.T) {
	set_timeouts(t, 200*time.Millisecond, WS_WRITE_TIMEOUT)
	addr := test_server(t)
	before := ws_count()
	cl := dial_ws(t, addr, true)
	plain := dial_ws(t, addr, true)
	wait_ws_count(t, before+2)
	time.Sleep(500 * time.Millisecond) // > header timeout
	if r := cl.call(t, 1, "DERO.Ping", ""); string(r["result"]) != `"Pong "` {
		t.Fatalf("Ping after idle: %s", r["result"])
	}
	if r := cl.call(t, 2, "DERO.Subscribe", `{"events":["BlockInfo","BlockInfo"]}`); string(r["result"]) != `{"events":["BlockInfo"],"status":"OK"}` {
		t.Fatalf("Subscribe: %v", r)
	}
	if r := cl.call(t, 3, "DERO.Subscribe", `{"events":["Nope"]}`); r["error"] == nil {
		t.Fatalf("unknown event accepted: %v", r)
	}
	push_block(func() BlockInfo_Event { return BlockInfo_Event{Height: 7, TopoHeight: 8, Hash: "ab"} })
	for _, c := range []*ws_test_client{cl, plain} {
		c.wait(t, "method", `"Block"`, 3*time.Second)
		c.wait(t, "method", `"Height"`, 3*time.Second)
	}
	ev := cl.wait(t, "method", `"BlockInfo"`, 3*time.Second)
	if string(ev["params"]) != `{"height":7,"topoheight":8,"hash":"ab","tip_timestamp_ms":0}` {
		t.Fatalf("BlockInfo params %s", ev["params"])
	}
	push_miniblock(func() MiniBlock_Event { return MiniBlock_Event{Height: 7, MiniBlocks: 3} })
	time.Sleep(200 * time.Millisecond)
	for _, c := range []*ws_test_client{cl, plain} {
		c.mu.Lock()
		for _, m := range c.got {
			if string(m["method"]) == `"BlockInfo"` || string(m["method"]) == `"MiniBlock"` {
				t.Errorf("unsubscribed event delivered: %v", m)
			}
		}
		c.mu.Unlock()
	}
}

func TestSubscribeOverHTTPIsRejected(t *testing.T) {
	addr := test_server(t)
	resp, err := http.Post("http://"+addr+"/json_rpc", "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"DERO.Subscribe","params":{"events":["BlockInfo"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var r map[string]json.RawMessage
	json.NewDecoder(resp.Body).Decode(&r)
	if r["error"] == nil {
		t.Fatalf("Subscribe over HTTP succeeded: %v", r)
	}
}

// One client that stops reading must neither block pushes to the others nor stay connected forever.
func TestStalledClientDoesNotBlockPushes(t *testing.T) {
	set_timeouts(t, RPC_READ_HEADER_TIMEOUT, 2*time.Second)
	addr := test_server(t)
	before := ws_count()
	stalled := dial_ws(t, addr, false) // never reads
	healthy := dial_ws(t, addr, true)
	wait_ws_count(t, before+2)
	// subscribe only the stalled client to a fat BlockInfo so its socket buffers fill quickly
	stalled.c.WriteMessage(websocket.TextMessage, []byte(`{"jsonrpc":"2.0","id":1,"method":"DERO.Subscribe","params":{"events":["BlockInfo"]}}`))
	time.Sleep(200 * time.Millisecond)
	fat := strings.Repeat("f", 1<<20)
	for i := 0; i < 40; i++ {
		// r19-r23b skipped a push to a client still writing its previous bundle, so the healthy client could miss one and
		// this loop re-pushed; r23c queues it (push_queue). The re-push stays: it only bounds the test, not the push.
		got := false
		for try := 0; try < 6 && !got; try++ {
			start := time.Now()
			push_block(func() BlockInfo_Event { return BlockInfo_Event{Height: int64(i), Hash: fat} })
			if el := time.Since(start); el > 500*time.Millisecond {
				t.Fatalf("push %d took %v: a stalled client is blocking the fan-out", i, el)
			}
			got = healthy.try_wait("method", `"Block"`, time.Second)
		}
		if !got {
			t.Fatalf("push %d: the healthy client received no Block in 6 pushes", i)
		}
	}
	wait_ws_count(t, before+1) // the stalled client is closed by its write deadline
}

func TestIPLimiter(t *testing.T) {
	l := new_ip_limiter(2)
	if !l.acquire("a") || !l.acquire("a") || l.acquire("a") {
		t.Fatal("limit 2 not enforced")
	}
	if !l.acquire("b") {
		t.Fatal("limit is per address")
	}
	l.release("a")
	if !l.acquire("a") {
		t.Fatal("release did not free a slot")
	}
	l.release("a")
	l.release("a")
	l.release("b")
	if len(l.n) != 0 {
		t.Fatalf("map not emptied: %v", l.n)
	}
}

func post_from(remote, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/json_rpc", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remote
	w := httptest.NewRecorder()
	json_rpc_handler(w, req)
	return w
}

func ping_batch(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"DERO.Ping"}`, i)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func TestRemoteBatchLimitSparesLoopback(t *testing.T) {
	big := ping_batch(HTTP_MAX_BATCH_REMOTE + 1)
	if w := post_from("203.0.113.5:4000", big); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("remote oversized batch: HTTP %d", w.Code)
	}
	if w := post_from("203.0.113.5:4000", ping_batch(3)); w.Code != http.StatusOK || strings.Count(w.Body.String(), "Pong") != 3 {
		t.Fatalf("remote small batch: HTTP %d %s", w.Code, w.Body.String())
	}
	if w := post_from("127.0.0.1:4000", big); w.Code != http.StatusOK || strings.Count(w.Body.String(), "Pong") != HTTP_MAX_BATCH_REMOTE+1 {
		t.Fatalf("loopback batch must be unlimited: HTTP %d", w.Code)
	}
	if w := post_from("[::1]:4000", big); w.Code != http.StatusOK {
		t.Fatalf("IPv6 loopback batch must be unlimited: HTTP %d", w.Code)
	}
}

func metric_text() string {
	var b bytes.Buffer
	dmetrics.Set.WritePrometheus(&b)
	return b.String()
}

// /json_rpc requests are counted like websocket ones, and a made-up method name creates no series.
func TestHTTPMetricsAndUnknownMethods(t *testing.T) {
	c := dmetrics.Set.GetOrCreateCounter(`rpc_requests_total{method="DERO.Echo"}`)
	before := c.Get()
	if w := post_from("127.0.0.1:1", `{"jsonrpc":"2.0","id":1,"method":"DERO.Echo","params":["x"]}`); w.Code != 200 {
		t.Fatalf("HTTP %d", w.Code)
	}
	if got := c.Get(); got != before+1 {
		t.Fatalf("rpc_requests_total{method=DERO.Echo} %d -> %d over /json_rpc, want +1", before, got)
	}
	post_from("127.0.0.1:1", `{"jsonrpc":"2.0","id":1,"method":"Bogus.r19probe"}`)
	if strings.Contains(metric_text(), "Bogus.r19probe") {
		t.Fatal("an unknown method name created a metrics series")
	}
}

type capture_log struct {
	mu   sync.Mutex
	rsps []*jrpc2.Response
}

func (c *capture_log) LogRequest(context.Context, *jrpc2.Request) {}
func (c *capture_log) LogResponse(_ context.Context, r *jrpc2.Response) {
	c.mu.Lock()
	c.rsps = append(c.rsps, r)
	c.mu.Unlock()
}

func captured_responses(t testing.TB) []*jrpc2.Response {
	logc := &capture_log{}
	loc := server.NewLocal(handler.Map{
		"Big": handler.New(func(ctx context.Context) (string, error) { return strings.Repeat("ab", 50_000), nil }),
		"Obj": handler.New(func(ctx context.Context) (map[string]int, error) { return map[string]int{"a": 1}, nil }),
		"Err": handler.New(func(ctx context.Context) (string, error) { return "", errors.New(`bad "thing"`) }),
	}, &server.LocalOptions{Server: &jrpc2.ServerOptions{RPCLog: logc}})
	defer loc.Close()
	for _, m := range []string{"Big", "Obj", "Err", "Missing"} {
		loc.Client.Call(context.Background(), m, nil)
	}
	logc.mu.Lock()
	defer logc.mu.Unlock()
	if len(logc.rsps) != 4 {
		t.Fatalf("captured %d responses", len(logc.rsps))
	}
	return logc.rsps
}

func TestResponseSizeMatchesMarshal(t *testing.T) {
	for _, r := range captured_responses(t) {
		b, err := r.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		if got := response_size(r); got != len(b) {
			t.Errorf("response_size=%d, len(MarshalJSON)=%d for %.80s", got, len(b), b)
		}
	}
}

func BenchmarkResponseMetrics(b *testing.B) {
	big := captured_responses(b)[0]
	b.Run("old_marshal_and_getorcreate", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			method := "DERO.GetBlock"
			dmetrics.Set.GetOrCreateHistogram(method + "_duration_histogram_seconds").UpdateDuration(time.Now())
			dmetrics.Set.GetOrCreateCounter(method + "_total").Inc()
			if output, err := big.MarshalJSON(); err == nil {
				dmetrics.Set.GetOrCreateCounter(method + "_total_out_bytes").Add(len(output))
			}
		}
	})
	b.Run("new_cached_and_size", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			m := metrics_for("DERO.GetBlock")
			m.duration.UpdateDuration(time.Now())
			m.total.Inc()
			m.out.Add(response_size(big))
		}
	})
}

func TestHealthHTTPCode(t *testing.T) {
	for status, want := range map[string]int{"synced": 200, "syncing": 503, "stalled": 503, "isolated": 503} {
		if got := health_http_code(status); got != want {
			t.Errorf("%s -> %d, want %d", status, got, want)
		}
	}
}

// RPCWS-7: the handlers themselves enforce the per-IP limits; loopback stays unlimited
func TestHandlerPerIPLimits(t *testing.T) {
	remote := "203.0.113.61"
	for i := 0; i < HTTP_MAX_INFLIGHT_PER_IP; i++ { // 32 requests from this address in flight
		http_inflight_limit.acquire(remote)
	}
	for i := 0; i < WS_MAX_CONNS_PER_IP; i++ { // 64 websockets open from this address
		ws_conn_limit.acquire(remote)
	}
	defer func() {
		for i := 0; i < HTTP_MAX_INFLIGHT_PER_IP; i++ {
			http_inflight_limit.release(remote)
		}
		for i := 0; i < WS_MAX_CONNS_PER_IP; i++ {
			ws_conn_limit.release(remote)
		}
	}()
	ping := `{"jsonrpc":"2.0","id":1,"method":"DERO.Ping"}`
	if w := post_from(remote+":5000", ping); w.Code != http.StatusTooManyRequests {
		t.Fatalf("33rd concurrent remote /json_rpc: HTTP %d, want 429", w.Code)
	}
	if w := post_from("127.0.0.1:5000", ping); w.Code != http.StatusOK {
		t.Fatalf("loopback /json_rpc: HTTP %d, want 200", w.Code)
	}
	ws := func(from string) int {
		req := httptest.NewRequest("GET", "/ws", nil)
		req.RemoteAddr = from
		w := httptest.NewRecorder()
		ws_handler(w, req)
		return w.Code
	}
	if c := ws(remote + ":5001"); c != http.StatusTooManyRequests {
		t.Fatalf("65th remote websocket: HTTP %d, want 429", c)
	}
	if c := ws("127.0.0.1:5001"); c == http.StatusTooManyRequests {
		t.Fatal("loopback websocket refused by the per-IP limit")
	}
}

// RPCWS-5: a stalled client never has more than one push of a class in flight, however many pushes are made, and an
// in-flight MiniBlock push does not suppress a Block bundle (separate busy flags; r23c: separate push queues)
func TestPushBusyFlags(t *testing.T) {
	key := jrpc2.NewServer(d, nil)
	c := &ws_client{}
	client_connections.Store(key, c)
	defer client_connections.Delete(key)
	release := make(chan struct{})
	var inflight, maxin int32
	stalled := func(s *jrpc2.Server, cl *ws_client) error {
		if s != key {
			return nil // another test's client
		}
		n := atomic.AddInt32(&inflight, 1)
		for {
			m := atomic.LoadInt32(&maxin)
			if n <= m || atomic.CompareAndSwapInt32(&maxin, m, n) {
				break
			}
		}
		<-release
		atomic.AddInt32(&inflight, -1)
		return nil
	}
	skipped0 := ws_push_skipped.Get()
	for i := 0; i < 50; i++ {
		notify_clients(0, true, stalled) // MiniBlock pushes to a client that does not read
	}
	time.Sleep(50 * time.Millisecond)
	if m := atomic.LoadInt32(&maxin); m != 1 {
		t.Fatalf("%d MiniBlock pushes in flight to one stalled client, want 1", m)
	}
	// r23c: one push is written, up to WS_PUSH_QUEUE wait in order (push_queue), the oldest of the rest are dropped
	if got := ws_push_skipped.Get() - skipped0; got < uint64(50-1-WS_PUSH_QUEUE) {
		t.Fatalf("skipped %d pushes, want >= %d", got, 50-1-WS_PUSH_QUEUE)
	}
	block := make(chan struct{}, 1)
	notify_clients(0, false, func(s *jrpc2.Server, cl *ws_client) error {
		if s == key {
			block <- struct{}{}
		}
		return nil
	})
	select {
	case <-block:
	case <-time.After(2 * time.Second):
		t.Fatal("a pending MiniBlock push suppressed the Block bundle")
	}
	close(release)
}
