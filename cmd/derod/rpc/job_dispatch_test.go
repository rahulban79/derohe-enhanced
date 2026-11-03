package rpc

import (
	"os"
	"strings"
	"sync"

	"github.com/lesismal/nbio/nbhttp/websocket"
	"sync/atomic"
	"testing"
	"time"
)

func new_core(keepalive int64) (*dispatch_core, *int64) {
	due := new(int64)
	return &dispatch_core{keepalive_ms: keepalive, due: due}, due
}

// One state change is one send, whoever noticed it first: the miniblock kick and the fallback poll used to send twice
// (and the second send scheduled a spurious template refresh).
func TestDispatchDecideOneSendPerChange(t *testing.T) {
	d, _ := new_core(2000)
	st := dispatch_state{height: 10, minis: 3}
	if r, tr := d.decide(st, 1000); r != "change" || tr != 1000 {
		t.Fatalf("first look: %q %d", r, tr)
	}
	d.sent(1000, true)
	for now := int64(1001); now < 1100; now += 10 { // poll ticks with the same state
		if r, _ := d.decide(st, now); r != "" {
			t.Fatalf("unchanged state sent again at %d: %q", now, r)
		}
	}
	st.minis = 4
	if r, tr := d.decide(st, 1200); r != "change" || tr != 1200 {
		t.Fatalf("miniblock: %q %d", r, tr)
	}
	d.sent(1200, true)
	st.events++ // a block at the same height or a miner connect
	if r, _ := d.decide(st, 1201); r != "change" {
		t.Fatalf("event not sent: %q", r)
	}
}

// A refresh fires at its due time with the trigger of the change it refreshes, exactly once.
func TestDispatchDecideRefresh(t *testing.T) {
	d, due := new_core(2000)
	st := dispatch_state{height: 10, minis: 8}
	d.decide(st, 1000)
	d.sent(1000, true)
	atomic.StoreInt64(due, 1101) // send_job got a template cached at 1000
	if r, _ := d.decide(st, 1100); r != "" {
		t.Fatalf("refresh before due: %q", r)
	}
	if r, tr := d.decide(st, 1101); r != "refresh" || tr != 1000 {
		t.Fatalf("refresh: %q %d", r, tr)
	}
	if atomic.LoadInt64(due) != 0 {
		t.Fatal("due not cleared")
	}
	d.sent(1101, true)
	if r, _ := d.decide(st, 1102); r != "" {
		t.Fatalf("refresh fired twice: %q", r)
	}
}

// An unchanged job is resent only at the keepalive interval, with no refresh trigger.
func TestDispatchDecideKeepalive(t *testing.T) {
	d, _ := new_core(2000)
	st := dispatch_state{height: 10}
	d.decide(st, 1000)
	d.sent(1000, true)
	if r, _ := d.decide(st, 2999); r != "" {
		t.Fatalf("keepalive early: %q", r)
	}
	if r, tr := d.decide(st, 3000); r != "keepalive" || tr != 0 {
		t.Fatalf("keepalive: %q %d", r, tr)
	}
	if refresh_due(2999, 0) != 0 { // trigger 0: send_job never schedules a refresh for a keepalive
		t.Fatal("keepalive scheduled a refresh")
	}
}

func TestDispatchWaitMs(t *testing.T) {
	d, due := new_core(2000)
	d.sent(1000, true)
	if w := d.wait_ms(1000, 10); w != 10 {
		t.Fatalf("poll: %d", w)
	}
	atomic.StoreInt64(due, 1004)
	if w := d.wait_ms(1000, 10); w != 4 {
		t.Fatalf("due sooner than poll: %d", w)
	}
	atomic.StoreInt64(due, 0)
	if w := d.wait_ms(2995, 10); w != 5 {
		t.Fatalf("keepalive sooner than poll: %d", w)
	}
	atomic.StoreInt64(due, 900)
	if w := d.wait_ms(1000, 10); w != 1 {
		t.Fatalf("overdue must not spin: %d", w)
	}
}

func TestJobKeepaliveEnv(t *testing.T) {
	cases := map[string]int64{"": 2000, "500ms": 500, "10ms": 2000, "bogus": 2000, "3s": 3000}
	for in, want := range cases {
		if got := job_keepalive_ms(in); got != want {
			t.Fatalf("%q: %d want %d", in, got, want)
		}
	}
}

type fake_dispatch struct {
	fail  int // the next fail sends report "not current"
	mu    sync.Mutex
	st    dispatch_state
	sends []time.Time
	trig  []int64
}

func (f *fake_dispatch) state() dispatch_state { f.mu.Lock(); defer f.mu.Unlock(); return f.st }
func (f *fake_dispatch) send(tr int64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sends = append(f.sends, time.Now())
	f.trig = append(f.trig, tr)
	ok := f.fail == 0
	if f.fail > 0 {
		f.fail--
	}
	return ok
}
func (f *fake_dispatch) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.sends) }

func wait_count(f *fake_dispatch, n int, limit time.Duration) time.Duration {
	t0 := time.Now()
	for time.Since(t0) < limit {
		if f.count() >= n {
			return time.Since(t0)
		}
		time.Sleep(200 * time.Microsecond)
	}
	return -1
}

func now_ms() int64 { return time.Now().UnixMilli() }

// The loop answers a kick at once: with a 1 s poll, a send within 200 ms can only have come from the kick.
func TestRunJobDispatcherKickLatency(t *testing.T) {
	f := &fake_dispatch{}
	d, _ := new_core(60000)
	kick := make(chan struct{}, 1)
	quit := make(chan struct{})
	defer close(quit)
	go run_job_dispatcher(d, 1000, func() bool { return true }, f.state, now_ms, f.send, kick, quit)
	send_kick(t, kick)
	if wait_count(f, 1, 2*time.Second) < 0 {
		t.Fatal("no first send")
	}
	f.mu.Lock()
	f.st.height++
	f.mu.Unlock()
	t0 := time.Now()
	send_kick(t, kick)
	if lat := wait_count(f, 2, 2*time.Second); lat < 0 || time.Since(t0) > 200*time.Millisecond {
		t.Fatalf("kick answered after %v (poll is 1 s)", time.Since(t0))
	}
	time.Sleep(30 * time.Millisecond)
	if n := f.count(); n != 2 {
		t.Fatalf("%d sends for 2 state changes", n)
	}
}

// A refresh due 30 ms ahead fires near its due time, not at the next 1 s poll.
func TestRunJobDispatcherRefreshOnTime(t *testing.T) {
	f := &fake_dispatch{}
	d, due := new_core(60000)
	kick := make(chan struct{}, 1)
	quit := make(chan struct{})
	defer close(quit)
	go run_job_dispatcher(d, 1000, func() bool { return true }, f.state, now_ms, f.send, kick, quit)
	atomic.StoreInt64(due, now_ms()+30) // set before the first kick, as send_job would
	send_kick(t, kick)
	if wait_count(f, 1, 2*time.Second) < 0 {
		t.Fatal("no first send")
	}
	t0 := time.Now()
	if wait_count(f, 2, 2*time.Second) < 0 || time.Since(t0) > 300*time.Millisecond {
		t.Fatalf("refresh sent after %v (due in 30 ms, poll 1 s)", time.Since(t0))
	}
}

// No miner, no send; a connect event (state change) sends at once.
func TestRunJobDispatcherInactive(t *testing.T) {
	f := &fake_dispatch{}
	d, _ := new_core(60000)
	var on int32
	kick := make(chan struct{}, 1)
	quit := make(chan struct{})
	defer close(quit)
	go run_job_dispatcher(d, 2, func() bool { return atomic.LoadInt32(&on) == 1 }, f.state, now_ms, f.send, kick, quit)
	time.Sleep(30 * time.Millisecond)
	if f.count() != 0 {
		t.Fatal("sent with no miner")
	}
	atomic.StoreInt32(&on, 1)
	f.mu.Lock()
	f.st.events++
	f.mu.Unlock()
	send_kick(t, kick)
	if wait_count(f, 1, time.Second) < 0 {
		t.Fatal("connect did not send")
	}
}

// getwork_session_count follows the session map (the dispatcher's "any miner?" test).
func TestGetworkSessionCount(t *testing.T) {
	with_clients(t, nil)
	c1, c2 := new(websocket.Conn), new(websocket.Conn)
	getwork_register(c1, &user_session{})
	getwork_register(c2, &user_session{})
	if n := atomic.LoadInt64(&getwork_session_count); n != 2 {
		t.Fatalf("after 2 registers: %d", n)
	}
	getwork_unregister(c1)
	getwork_unregister(c2)
	if n := atomic.LoadInt64(&getwork_session_count); n != 0 {
		t.Fatalf("after unregister: %d", n)
	}
}

// A connecting miner's first job goes to that miner only (job_target_for), never to an unregistered connection.
func TestJobTargetFor(t *testing.T) {
	with_clients(t, nil)
	c, other := new(websocket.Conn), new(websocket.Conn)
	s := &user_session{miniblocks: 4, valid_address: true}
	s.address_sum[0] = 9
	getwork_register(c, s)
	defer getwork_unregister(c)
	tg, ok := job_target_for(c)
	if !ok || tg.conn != c || tg.sess != s || tg.address_sum[0] != 9 || tg.miniblocks != 4 || !tg.valid {
		t.Fatalf("target: %+v %v", tg, ok)
	}
	if _, ok := job_target_for(other); ok {
		t.Fatal("an unregistered connection got a target")
	}
}

func func_body(t *testing.T, file, sig string) string {
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, sig)
	if i < 0 {
		t.Fatalf("%s: %q not found", file, sig)
	}
	body := src[i:]
	if j := strings.Index(body[1:], "\nfunc "); j > 0 {
		body = body[:j+1]
	}
	return body
}

// The wiring: miniblocks kick the dispatcher instead of sending on their own, blocks are events, the loop runs, and a
// connect answers only its own miner.
func TestJobDispatchWiring(t *testing.T) {
	if b := func_body(t, "websocket_server.go", "func Notify_MiniBlock_Addition() {"); !strings.Contains(b, "kick_jobs()") || strings.Contains(b, "SendJob()") {
		t.Fatal("Notify_MiniBlock_Addition must kick the dispatcher, not send a second job itself")
	}
	g := func_body(t, "websocket_getwork_server.go", "func Getwork_server() {")
	if !strings.Contains(g, "go run_job_dispatcher(") || !strings.Contains(g, "chain.RPC_NotifyNewBlock.Wait()\n\t\t\tchain.RPC_NotifyNewBlock.L.Unlock()\n\t\t\tnote_job_event()") {
		t.Fatal("Getwork_server must run the dispatcher and turn block additions into events")
	}
	if w := func_body(t, "websocket_getwork_server.go", "func onWebsocket("); !strings.Contains(w, "go send_job_to(0, []job_target{t})") {
		t.Fatal("a connect must send that miner its first job")
	}
	if j := func_body(t, "websocket_getwork_server.go", "func send_job_to("); !strings.Contains(j, "\tcurrent = template_is_current(int64(bl.Height), chain.Get_Height())\n") ||
		!strings.Contains(j, "\treturn current\n}") {
		t.Fatal("send_job_to must report a job for a finished height as not current, so the dispatcher retries it")
	}
}

// A send that could not be current (a half-added block, no template) is retried soon with the change's trigger, but
// only inside JOB_RETRY_WINDOW of that change.
func TestDispatchDecideRetry(t *testing.T) {
	d, _ := new_core(60000)
	st := dispatch_state{height: 10}
	d.decide(st, 1000)
	d.sent(1001, false)
	if w := d.wait_ms(1001, 10); w != 2 {
		t.Fatalf("first retry wait %d ms, want 2", w)
	}
	if r, tr := d.decide(st, 1003); r != "retry" || tr != 1000 {
		t.Fatalf("retry: %q %d", r, tr)
	}
	d.sent(1004, true)
	if r, _ := d.decide(st, 1006); r != "" {
		t.Fatalf("retried after a current send: %q", r)
	}
	st.height++
	d.decide(st, 5000)
	d.sent(5000, false)
	if r, _ := d.decide(st, 5000+JOB_RETRY_WINDOW); r != "" {
		t.Fatalf("retried past the window: %q", r)
	}
	// a node that cannot build a current template retries at most JOB_RETRY_MAX times per change, backing off
	st.height++
	d.decide(st, 9000)
	d.sent(9000, false)
	n := 0
	for now := int64(9001); now < 9500; now++ {
		if r, _ := d.decide(st, now); r == "retry" {
			n++
			d.sent(now, false)
		}
	}
	if n != JOB_RETRY_MAX {
		t.Fatalf("%d retries, want %d", n, JOB_RETRY_MAX)
	}
	d2, _ := new_core(60000)
	d2.decide(st, 0)
	d2.sent(0, false)
	d2.retries = 3
	if w := d2.wait_ms(0, 1000); w != 16 {
		t.Fatalf("4th retry waits %d ms, want 16", w)
	}
}

// End to end: the first job after a block is not current (built between the topo write and the tips update); the loop
// sends again within milliseconds, not at the next poll (1 s here) or keepalive.
func TestRunJobDispatcherRetriesStaleJob(t *testing.T) {
	f := &fake_dispatch{fail: 1}
	d, _ := new_core(60000)
	kick := make(chan struct{}, 1)
	quit := make(chan struct{})
	defer close(quit)
	go run_job_dispatcher(d, 1000, func() bool { return true }, f.state, now_ms, f.send, kick, quit)
	t0 := time.Now()
	send_kick(t, kick)
	if wait_count(f, 2, 2*time.Second) < 0 || time.Since(t0) > 300*time.Millisecond {
		t.Fatalf("stale job not retried promptly: %d sends after %v", f.count(), time.Since(t0))
	}
	time.Sleep(30 * time.Millisecond)
	if n := f.count(); n != 2 {
		t.Fatalf("%d sends, want the stale one and one retry", n)
	}
}

func TestTemplateIsCurrent(t *testing.T) {
	if !template_is_current(101, 100) || template_is_current(100, 100) || template_is_current(99, 100) {
		t.Fatal("a template is current only for the height after the chain top")
	}
}

// send_kick hands the dispatcher a kick without blocking the test: a dispatcher that no longer drains kicks (a broken
// select) fails here at once instead of hanging until the go test timeout.
func send_kick(t *testing.T, kick chan struct{}) {
	t.Helper()
	select {
	case kick <- struct{}{}:
	case <-time.After(time.Second):
		t.Fatal("the dispatcher did not take a kick within 1 s")
	}
}

// Only broadcasts are counted as stale-height jobs: a reconnecting miner's first job must not inflate the counter.
func TestStaleCountedBroadcastOnly(t *testing.T) {
	if !stale_counted(false, nil) {
		t.Fatal("a stale broadcast must be counted")
	}
	if stale_counted(false, []job_target{{}}) {
		t.Fatal("a stale first job to one connecting miner must not be counted")
	}
	if stale_counted(true, nil) {
		t.Fatal("a current job is not stale")
	}
}
