package rpc

// r23c rpcws tests.

import (
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/creachadair/jrpc2"
	"github.com/deroproject/derohe/cryptography/crypto"

	"github.com/deroproject/derohe/glue/emission"
)

func r23c_populated_auditor() *emission_auditor {
	a := new_emission_auditor()
	a.res.Enabled, a.res.Audited, a.res.Alerts = true, 1234, 0
	a.res.Verdicts["ok"], a.res.Verdicts["unverified"] = 1200, 34
	a.res.SegmentFrom, a.res.SegmentTo, a.res.VerifiedHeights, a.res.UnverifiedHeights = 100, 1333, 1200, 34
	a.res.ObservedEmission, a.res.FormulaEmission, a.res.EmissionConsistent, a.res.FormulaSupply = 77, 77, true, 999
	a.res.FeesRedistributed, a.res.SCDeposits, a.res.SCPayouts, a.res.Gaps, a.res.Reorgs = 5, 6, 7, 8, 9
	for i := 0; i < EMISSION_RECENT; i++ {
		a.res.Recent = append(a.res.Recent, emission.Report{})
		a.res.Notable = append(a.res.Notable, emission.Report{})
	}
	return a
}

// RPCWS23B-C: the totals-only view equals the old snapshot-then-summarise path, field for field, in every status.
func TestR23cEmissionSummaryEqualsSnapshotView(t *testing.T) {
	a := r23c_populated_auditor()
	for _, mut := range []func(){func() {}, func() { a.res.Alerts = 2 }, func() { a.res.Audited = 0; a.res.Alerts = 0 }, func() { a.res.Enabled = false }} {
		mut()
		got, want := a.summary(), emission_summary(a.snapshot())
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("summary %+v\nwant     %+v", got, want)
		}
	}
	s := a.summary()
	s.Verdicts["ok"] = 1 // a copy: the caller cannot write the auditor's map
	if a.res.Verdicts["ok"] != 1200 {
		t.Fatalf("summary shares the auditor's Verdicts map")
	}
}

func BenchmarkR23cMonetaryEmissionView(b *testing.B) {
	a := r23c_populated_auditor()
	b.Run("snapshot", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = emission_summary(a.snapshot())
		}
	})
	b.Run("summary", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = a.summary()
		}
	})
}

// ---- push_queue (r23c) -------------------------------------------------------------------------------------------

type pq_rec struct {
	mu   sync.Mutex
	got  []int
	lost []bool
}

func (r *pq_rec) add(i int, lost bool) {
	r.mu.Lock()
	r.got, r.lost = append(r.got, i), append(r.lost, lost)
	r.mu.Unlock()
}

func (r *pq_rec) snapshot() ([]int, []bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int(nil), r.got...), append([]bool(nil), r.lost...)
}

func pq_wait(t *testing.T, pq *push_queue) {
	t.Helper()
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(2 * time.Millisecond) {
		pq.mu.Lock()
		r := pq.running
		pq.mu.Unlock()
		if !r {
			return
		}
	}
	t.Fatal("push queue writer did not finish")
}

// The r19-r23b skip dropped the second of two back-to-back pushes to a client that was still writing the first: here
// a writer busy 20 ms (a slow but reading wallet) must get both, in order.
func TestR23cBusyClientGetsBothPushes(t *testing.T) {
	c := &ws_client{}
	var rec pq_rec
	for i := 0; i < 2; i++ {
		i := i
		if c.q_block.push(nil, func(_ *jrpc2.Server, _ *ws_client, lost bool) error {
			time.Sleep(20 * time.Millisecond)
			rec.add(i, lost)
			return nil
		}) {
			go c.q_block.drain(c)
		}
	}
	pq_wait(t, &c.q_block)
	if got, _ := rec.snapshot(); !reflect.DeepEqual(got, []int{0, 1}) {
		t.Fatalf("delivered %v, want [0 1]", got)
	}
}

// Past WS_PUSH_QUEUE the OLDEST waiting push is dropped: delivery stays ordered, the newest push always arrives, and a
// push written right after a gap (a dropped push) is told lost=true, every other one lost=false.
func TestR23cPushQueueKeepsNewestInOrder(t *testing.T) {
	c := &ws_client{}
	var rec pq_rec
	release := make(chan struct{})
	const n = 30
	skipped0 := ws_push_skipped.Get()
	var first int32 = 1
	for i := 0; i < n; i++ {
		i := i
		if c.q_mini.push(nil, func(_ *jrpc2.Server, _ *ws_client, lost bool) error {
			if atomic.CompareAndSwapInt32(&first, 1, 0) {
				<-release // the first push written stalls while the rest arrive
			}
			rec.add(i, lost)
			return nil
		}) {
			go c.q_mini.drain(c)
		}
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	pq_wait(t, &c.q_mini)
	got, lost := rec.snapshot()
	if len(got) < 2 || got[len(got)-1] != n-1 {
		t.Fatalf("delivered %v: want the newest (%d) last", got, n-1)
	}
	if len(got) > 1+WS_PUSH_QUEUE {
		t.Fatalf("delivered %d pushes behind a stalled write, queue bound %d", len(got), WS_PUSH_QUEUE)
	}
	if dropped := ws_push_skipped.Get() - skipped0; int(dropped) != n-len(got) {
		t.Fatalf("dropped counter %d, want %d", dropped, n-len(got))
	}
	prev := -1
	for k, g := range got {
		if g <= prev {
			t.Fatalf("out of order: %v", got)
		}
		if gap := g != prev+1; lost[k] != gap {
			t.Fatalf("delivered %v lost %v: lost must be true exactly after a gap", got, lost)
		}
		prev = g
	}
}

// A failed write drops the rest and frees the writer, so a later push starts a new one.
func TestR23cPushQueueFailureResets(t *testing.T) {
	c := &ws_client{}
	var calls int32
	release := make(chan struct{})
	for i := 0; i < 4; i++ {
		i := i
		if c.q_block.push(nil, func(*jrpc2.Server, *ws_client, bool) error {
			atomic.AddInt32(&calls, 1)
			if i == 0 {
				<-release
				return errors.New("write deadline")
			}
			return nil
		}) {
			go c.q_block.drain(c)
		}
	}
	close(release)
	pq_wait(t, &c.q_block)
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("%d writes after a failed one, want only the failed one", n)
	}
	if !c.q_block.push(nil, func(*jrpc2.Server, *ws_client, bool) error { return nil }) {
		t.Fatal("the writer was not freed after a failure")
	}
	go c.q_block.drain(c)
	pq_wait(t, &c.q_block)
}

// TxPool diffs are queued behind a busy write (before, the diff was dropped and its txids never reached that client),
// and the diff written after dropped ones carries truncated=true, so the client knows to re-read the pool.
func TestR23cTxPoolDiffNotLostBehindBusyWrite(t *testing.T) {
	c, rec := push_pair(t, SUB_TXPOOL)
	release, started0 := make(chan struct{}), make(chan struct{})
	if c.q_pool.push(nil, func(*jrpc2.Server, *ws_client, bool) error { close(started0); <-release; return nil }) { // a TxPool write in progress
		go c.q_pool.drain(c)
	}
	<-started0
	var te tx_events
	var pool []crypto.Hash
	list := func() []crypto.Hash { return pool }
	te.tick(false, fake_tx_src{}, func() int64 { return 0 }, list) // baseline (empty pool)
	pool = []crypto.Hash{hh(1)}
	te.tick(false, fake_tx_src{}, func() int64 { return 0 }, list) // one diff while busy: +1
	time.Sleep(20 * time.Millisecond)
	close(release)
	ev := rec.wait(t, "TxPool", 1)
	var e TxPool_Event
	json.Unmarshal(ev[0], &e)
	if len(e.Added) != 1 || e.Added[0] != hh(1).String() || e.Truncated {
		t.Fatalf("diff behind a busy write: %s", ev[0])
	}
	pq_wait(t, &c.q_pool)

	// now overflow the queue: the oldest diffs are dropped and the first written after them says truncated
	release2, started := make(chan struct{}), make(chan struct{})
	if c.q_pool.push(nil, func(*jrpc2.Server, *ws_client, bool) error { close(started); <-release2; return nil }) {
		go c.q_pool.drain(c)
	}
	<-started // the blocker is being written, not waiting in the queue
	for i := 0; i < WS_PUSH_QUEUE+3; i++ {
		pool = []crypto.Hash{hh(byte(10 + i))}
		te.tick(false, fake_tx_src{}, func() int64 { return 0 }, list)
	}
	time.Sleep(20 * time.Millisecond)
	close(release2)
	// the in-order writes may reach the recorder out of order (jrpc2 runs OnNotify callbacks concurrently): judge the
	// set, keyed by the txid each diff added
	want_last := byte(10 + WS_PUSH_QUEUE + 2)
	got := map[byte]bool{} // added txid byte -> truncated
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end) && !(len(got) > 0 && has_key(got, want_last)); time.Sleep(5 * time.Millisecond) {
		got = map[byte]bool{}
		for _, raw := range rec.get("TxPool")[1:] {
			var e TxPool_Event
			json.Unmarshal(raw, &e)
			if len(e.Added) == 1 {
				h := e.Added[0]
				got[byte(hex_nibble(h[0])<<4|hex_nibble(h[1]))] = e.Truncated
			}
		}
	}
	if !has_key(got, want_last) || got[want_last] {
		t.Fatalf("newest diff missing or truncated: %v", got)
	}
	if len(got) > WS_PUSH_QUEUE {
		t.Fatalf("%d diffs delivered behind a stalled write, queue %d", len(got), WS_PUSH_QUEUE)
	}
	min := want_last
	for k := range got {
		if k < min {
			min = k
		}
	}
	for k, tr := range got {
		if tr != (k == min) {
			t.Fatalf("truncated flags %v: exactly the first diff written after the dropped ones (%d) must say truncated", got, min)
		}
	}
}

func has_key(m map[byte]bool, k byte) bool { _, ok := m[k]; return ok }

func hex_nibble(c byte) byte {
	if c >= 'a' {
		return c - 'a' + 10
	}
	return c - '0'
}

// Block/MiniBlock events reach the client queues in the order the notify loops posted them (one worker).
func TestR23cPostPushInOrder(t *testing.T) {
	var mu sync.Mutex
	var got []int
	done := make(chan struct{})
	const n = 200
	for i := 0; i < n; i++ {
		i := i
		post_push(func() {
			time.Sleep(time.Duration(i%3) * 50 * time.Microsecond)
			mu.Lock()
			got = append(got, i)
			if len(got) == n {
				close(done)
			}
			mu.Unlock()
		})
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("posted pushes did not all run")
	}
	for k := range got {
		if got[k] != k {
			t.Fatalf("push %d ran at position %d: posts must run in order", got[k], k)
		}
	}
}

// ---- per-call item bounds (r23c, param_bounds.go) ------------------------------------------------------------------

func r23c_hashes(n int) string {
	var b strings.Builder
	b.WriteString(`{"txs_hashes":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"%064x"`, i+1)
	}
	b.WriteString(`]}`)
	return b.String()
}

func TestR23cRemoteBodyBounds(t *testing.T) {
	one := func(method, params string) []byte {
		return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":%s}`, method, params))
	}
	if err := remote_body_over_bounds(one("DERO.GetTransaction", r23c_hashes(MAX_REMOTE_TX_HASHES))); err != nil {
		t.Fatalf("%d txids refused: %v", MAX_REMOTE_TX_HASHES, err)
	}
	for _, m := range []string{"DERO.GetTransaction", "gettransactions"} {
		if err := remote_body_over_bounds(one(m, r23c_hashes(MAX_REMOTE_TX_HASHES+1))); err == nil {
			t.Fatalf("%s with %d txids admitted", m, MAX_REMOTE_TX_HASHES+1)
		}
	}
	batch := []byte(`[` + string(one("DERO.Ping", `{}`)) + `,` + string(one("DERO.GetTransaction", r23c_hashes(MAX_REMOTE_TX_HASHES+1))) + `]`)
	if err := remote_body_over_bounds(batch); err == nil {
		t.Fatal("over-bound request inside a batch admitted")
	}
	keys := `{"scid":"00","keysuint64":[` + strings.TrimSuffix(strings.Repeat("1,", 200), ",") + `],"keysstring":[` + strings.TrimSuffix(strings.Repeat(`"a",`, 57), ",") + `]}`
	if err := remote_body_over_bounds(one("DERO.GetSC", keys)); err == nil {
		t.Fatal("GetSC with 257 keys (200 + 57) admitted")
	}
	if err := remote_body_over_bounds(one("DERO.GetInfo", r23c_hashes(MAX_REMOTE_TX_HASHES+1))); err != nil {
		t.Fatal("a method without item lists was bounded")
	}
	if err := remote_body_over_bounds([]byte(`{"method":"DERO.GetTransaction","params":[1,2`)); err != nil {
		t.Fatal("malformed JSON must be left to the bridge")
	}
}

// remote /json_rpc: the bound answers -32602 before the bridge; loopback is never bounded
func TestR23cRemoteHTTPTxHashesBound(t *testing.T) {
	big := `{"jsonrpc":"2.0","id":7,"method":"DERO.GetTransaction","params":` + r23c_hashes(MAX_REMOTE_TX_HASHES+1) + `}`
	refused0 := param_bound_refused.Get()
	req := httptest.NewRequest("POST", "/json_rpc", strings.NewReader(big))
	req.RemoteAddr = "192.0.2.77:4444"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	json_rpc_handler(rec, req)
	if !strings.Contains(rec.Body.String(), `"code":-32602`) || !strings.Contains(rec.Body.String(), "at most 256") {
		t.Fatalf("remote over-bound body: %d %s", rec.Code, rec.Body.String())
	}
	if param_bound_refused.Get() != refused0+1 {
		t.Fatal("rpc_param_bound_refused_total not counted")
	}
	req = httptest.NewRequest("POST", "/json_rpc", strings.NewReader(big))
	req.RemoteAddr = "127.0.0.1:4444"
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	json_rpc_handler(rec, req)
	if strings.Contains(rec.Body.String(), "at most 256") {
		t.Fatalf("loopback body was bounded: %s", rec.Body.String())
	}
}

// cross-site websocket: bounded in the handler; a same-machine websocket is not
func TestR23cForeignWebsocketTxHashesBound(t *testing.T) {
	addr := test_server(t)
	foreign, _, err := dial_ws_with(t, addr, http.Header{"Origin": {"http://evil.example"}})
	if err != nil {
		t.Fatal(err)
	}
	r := foreign.call(t, 31, "DERO.GetTransaction", r23c_hashes(MAX_REMOTE_TX_HASHES+1))
	if !strings.Contains(string(r["error"]), "at most 256") {
		t.Fatalf("foreign socket, %d txids: %s", MAX_REMOTE_TX_HASHES+1, r["error"])
	}
	keys := `{"scid":"00","keysstring":[` + strings.TrimSuffix(strings.Repeat(`"a",`, MAX_REMOTE_SC_KEYS+1), ",") + `]}`
	if r := foreign.call(t, 32, "DERO.GetSC", keys); !strings.Contains(string(r["error"]), "at most 256") {
		t.Fatalf("foreign socket, GetSC keys: %s", r["error"])
	}
	local := dial_ws(t, addr, true)
	if r := local.call(t, 33, "DERO.GetTransaction", r23c_hashes(MAX_REMOTE_TX_HASHES+1)); strings.Contains(string(r["error"]), "at most 256") {
		t.Fatalf("loopback socket was bounded: %s", r["error"])
	}
}

// r23c verify: a refused over-bound remote body is scored like a -32602 reply, so repeating it ends in a ban
// (before, the refusal happened ahead of the abuse table and was never charged or scored)
func TestR23cRemoteBoundRefusalIsScored(t *testing.T) {
	fresh_abuse(t)
	big := `{"jsonrpc":"2.0","id":7,"method":"DERO.GetTransaction","params":` + r23c_hashes(MAX_REMOTE_TX_HASHES+1) + `}`
	send := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/json_rpc", strings.NewReader(big))
		req.RemoteAddr = "192.0.2.78:4444"
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		json_rpc_handler(rec, req)
		return rec
	}
	if rec := send(); rec.Code != 200 || !strings.Contains(rec.Body.String(), "at most 256") {
		t.Fatalf("first refusal: %d %s", rec.Code, rec.Body.String())
	}
	for i := 0; i < 200; i++ {
		if rec := send(); rec.Code == 429 {
			if !strings.Contains(rec.Body.String(), fmt.Sprint(int(RPC_CODE_BANNED))) {
				t.Fatalf("429 without the ban code: %s", rec.Body.String())
			}
			return
		}
	}
	t.Fatal("200 refused over-bound bodies from one remote key never led to a ban")
}

// r23c verify: the precheck fast path never skips a body that can reach GetTransaction/GetSC, escaped names included
func TestR23cBoundFastPathKeepsEscapedNames(t *testing.T) {
	big := r23c_hashes(MAX_REMOTE_TX_HASHES + 1)
	for _, m := range []string{`DERO.\u0047etTransaction`, `gettransaction\u0073`, `DERO.GetS\u0043`} {
		body := []byte(`{"jsonrpc":"2.0","id":1,"method":"` + m + `","params":` + big + `}`)
		if remote_body_over_bounds(body) == nil {
			t.Fatalf("escaped method %s with %d txids admitted", m, MAX_REMOTE_TX_HASHES+1)
		}
	}
	if body_may_name_bounded([]byte(`{"jsonrpc":"2.0","id":1,"method":"DERO.SendRawTransaction","params":{"tx_as_hex":"abcdef0123"}}`)) {
		t.Fatal("a SendRawTransaction body took the slow path")
	}
}
