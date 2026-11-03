package rpc

// Getwork job fan-out over real sockets (Round 23, rpcws): an nbio TLS websocket server configured like
// Getwork_server, N gorilla clients like dero-miner, and dispatch_targets, the code SendJob runs per job. The short
// test always runs (3 miners: every miner gets every job, newest last). The measurement is opt-in:
//
//	GETWORK_FANOUT=1 GETWORK_FANOUT_PORT=26951 go test -run TestR23GetworkFanoutBench -v ./cmd/derod/rpc
//
// It prints, per miner count, the time from the start of a dispatch until every miner has read the job (p50/p99),
// until every server-side write returned, and the process CPU per job (clients are in the same process, so this
// includes their TLS reads). A last phase adds one miner that never reads and reports when the server closed it.

import (
	stdtls "crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	gws "github.com/gorilla/websocket"
	"github.com/lesismal/llib/std/crypto/tls"
	"github.com/lesismal/nbio/nbhttp"
	"github.com/lesismal/nbio/nbhttp/websocket"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/rpc"
)

type fanout_server struct {
	svr    *nbhttp.Server
	addr   string
	closed int64 // connections the server saw close
}

var shared_fanout struct {
	once sync.Once
	fs   *fanout_server
}

// fanout_server_for_test: one server per test process, never stopped: nbio's Stop closes connections from its timer
// goroutine while the pollers still read them (a data race inside vendor/nbio, seen under -race), and the process
// exit ends it anyway.
func fanout_server_for_test(t testing.TB, port int) *fanout_server {
	shared_fanout.once.Do(func() { shared_fanout.fs = start_fanout_server(t, port) })
	return shared_fanout.fs
}

// start_fanout_server: same nbhttp settings as Getwork_server; every upgraded connection is registered as a valid
// miner (no chain lookups).
func start_fanout_server(t testing.TB, port int) *fanout_server {
	fs := &fanout_server{addr: fmt.Sprintf("127.0.0.1:%d", port)}
	mux := &http.ServeMux{}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		u := websocket.NewUpgrader()
		u.ReadLimit = GETWORK_READ_LIMIT
		u.OnClose(func(c *websocket.Conn, err error) {
			atomic.AddInt64(&fs.closed, 1)
			getwork_unregister(c)
		})
		conn, err := u.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c := conn.(*websocket.Conn)
		s := &user_session{valid_address: true, checked_topo: -1, since: time.Now(), remote: r.RemoteAddr}
		c.SetSession(s)
		getwork_register(c, s)
	})
	fs.svr = nbhttp.NewServer(nbhttp.Config{
		Name: "GETWORK-TEST", Network: "tcp", AddrsTLS: []string{fs.addr},
		TLSConfig:               &tls.Config{Certificates: []tls.Certificate{generate_random_tls_cert()}, InsecureSkipVerify: true},
		Handler:                 mux,
		MaxLoad:                 10 * 1024,
		MaxWriteBufferSize:      32 * 1024,
		ReleaseWebsocketPayload: true,
		KeepaliveTime:           240 * time.Hour,
		NPoller:                 2,
	})
	if err := fs.svr.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	return fs
}

type fanout_client struct {
	c       *gws.Conn
	last    uint64 // seq of the newest job read (from jobid)
	reads   int64
	ordered bool
}

func dial_fanout(t testing.TB, addr string, read bool, onjob func(seq uint64)) *fanout_client {
	d := gws.Dialer{TLSClientConfig: &stdtls.Config{InsecureSkipVerify: true}, HandshakeTimeout: 5 * time.Second}
	c, _, err := d.Dial("wss://"+addr+"/ws/x", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	fc := &fanout_client{c: c, ordered: true}
	if read {
		go func() {
			for {
				_, b, err := c.ReadMessage()
				if err != nil {
					return
				}
				var j rpc.GetBlockTemplate_Result
				if json.Unmarshal(b, &j) != nil {
					continue
				}
				seq, _ := strconv.ParseUint(j.JobID, 10, 64)
				if seq <= atomic.LoadUint64(&fc.last) {
					fc.ordered = false
				}
				atomic.StoreUint64(&fc.last, seq)
				atomic.AddInt64(&fc.reads, 1)
				if onjob != nil {
					onjob(seq)
				}
			}
		}()
	}
	return fc
}

func wait_miners(t testing.TB, n int64) {
	deadline := time.Now().Add(10 * time.Second)
	for atomic.LoadInt64(&getwork_session_count) < n {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d miners registered", atomic.LoadInt64(&getwork_session_count), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func fanout_job(seq uint64) (rpc.GetBlockTemplate_Result, block.MiniBlock) {
	var base rpc.GetBlockTemplate_Result
	base.JobID = strconv.FormatUint(seq, 10)
	base.Height = 7830000
	base.Prev_Hash = "00"
	base.Difficultyuint64 = 2900000
	base.Difficulty = "2900000"
	var mbl block.MiniBlock
	mbl.Version, mbl.PastCount, mbl.Past[0], mbl.Height = 1, 1, 0x1234, 7830000
	mbl.Timestamp = uint16(seq)
	return base, mbl
}

func cpu_seconds() float64 {
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return float64(ru.Utime.Sec+ru.Stime.Sec) + float64(ru.Utime.Usec+ru.Stime.Usec)/1e6
}

func pct(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[int(p*float64(len(s)-1))]
}

// Three real miners over TLS: each gets every job exactly once and in order, including when two dispatches overlap
// with the older one started last (the r23 ordering guard), and a job is never written twice to one miner.
//
// Skipped under -race: vendor/nbio's poller keeps its fd -> conn table without a lock (poller_kqueue.go addConn from
// the listener goroutine, deleteConn from a poller goroutine), which the detector reports in about 1 of 3 runs whatever
// this package does. The mechanism itself is covered under -race by TestR23DeliverJob* with an in-memory writer.
func TestR23GetworkFanoutOrderedOverSockets(t *testing.T) {
	if race_enabled {
		t.Skip("vendor/nbio poller fd table race (pre-existing, outside this package); covered by TestR23DeliverJob*")
	}
	fs := fanout_server_for_test(t, fanout_port())
	drain_miners(t)
	var cl []*fanout_client
	for i := 0; i < 3; i++ {
		cl = append(cl, dial_fanout(t, fs.addr, true, nil))
	}
	defer func() {
		for _, c := range cl {
			c.c.Close()
		}
	}()
	wait_miners(t, 3)
	targets := job_targets()
	dispatch := func(seq uint64) {
		base, mbl := fanout_job(seq)
		var wg sync.WaitGroup
		wg.Add(len(targets))
		dispatch_targets(targets, base, mbl, nil, -1, seq, wg.Done)
		wg.Wait()
	}
	// 1. deterministic: every older job arrives after the newer one went out, and is dropped
	for seq := uint64(1); seq <= 20; seq += 2 {
		dispatch(seq + 1)
		dispatch(seq)
	}
	// 2. overlapping dispatches in either order: a miner never reads an older job after a newer one
	for seq := uint64(21); seq <= 60; seq += 2 {
		newer, nm := fanout_job(seq + 1)
		older, om := fanout_job(seq)
		var wg sync.WaitGroup
		wg.Add(2 * len(targets))
		dispatch_targets(targets, newer, nm, nil, -1, seq+1, wg.Done)
		dispatch_targets(targets, older, om, nil, -1, seq, wg.Done)
		wg.Wait()
	}
	deadline := time.Now().Add(5 * time.Second)
	for _, c := range cl {
		for atomic.LoadUint64(&c.last) != 60 && time.Now().Before(deadline) {
			time.Sleep(2 * time.Millisecond)
		}
		if got := atomic.LoadUint64(&c.last); got != 60 {
			t.Fatalf("miner ends on job %d, want 60", got)
		}
		if !c.ordered {
			t.Fatal("a miner read an older job after a newer one")
		}
		if r := atomic.LoadInt64(&c.reads); r < 30 || r > 50 {
			t.Fatalf("miner read %d jobs, want 10 (phase 1) + 20..40 (phase 2)", r)
		}
	}
}

// drain_miners waits until no session is registered (connections of an earlier test or -count run have closed).
func drain_miners(t testing.TB) {
	deadline := time.Now().Add(10 * time.Second)
	for atomic.LoadInt64(&getwork_session_count) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d sessions still registered", atomic.LoadInt64(&getwork_session_count))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// fanout_port: GETWORK_FANOUT_PORT, else a loopback port in 26900..26989.
func fanout_port() int {
	if p, err := strconv.Atoi(os.Getenv("GETWORK_FANOUT_PORT")); err == nil {
		return p
	}
	return 26900 + int(time.Now().UnixNano()%90)
}

func TestR23GetworkFanoutBench(t *testing.T) {
	if os.Getenv("GETWORK_FANOUT") != "1" {
		t.Skip("opt-in measurement; set GETWORK_FANOUT=1")
	}
	jobs := 200
	fs := fanout_server_for_test(t, fanout_port())
	var all []*fanout_client
	defer func() {
		for _, c := range all {
			c.c.Close()
		}
	}()
	seq := uint64(1000)
	for _, n := range []int{1, 10, 100, 1000} {
		var got int64
		var want int64
		done := make(chan struct{}, 1)
		onjob := func(s uint64) {
			if atomic.AddInt64(&got, 1) == atomic.LoadInt64(&want) {
				done <- struct{}{}
			}
		}
		for _, c := range all { // earlier phases' miners stop counting; close them
			c.c.Close()
		}
		all = all[:0]
		drain_miners(t)
		for i := 0; i < n; i++ {
			all = append(all, dial_fanout(t, fs.addr, true, onjob))
		}
		wait_miners(t, int64(n))
		targets := job_targets()
		var e2e, writes []time.Duration
		c0 := cpu_seconds()
		for j := 0; j < jobs; j++ {
			seq++
			atomic.StoreInt64(&got, 0)
			atomic.StoreInt64(&want, int64(n))
			base, mbl := fanout_job(seq)
			var wg sync.WaitGroup
			wg.Add(len(targets))
			t0 := time.Now()
			dispatch_targets(targets, base, mbl, nil, -1, seq, wg.Done)
			wg.Wait()
			writes = append(writes, time.Since(t0))
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("n=%d job %d: only %d of %d miners read it", n, j, atomic.LoadInt64(&got), n)
			}
			e2e = append(e2e, time.Since(t0))
		}
		cpu := cpu_seconds() - c0
		t.Logf("FANOUT n=%d jobs=%d all_read_p50=%v all_read_p99=%v writes_done_p50=%v writes_done_p99=%v cpu_ms_per_job=%.3f cpu_us_per_miner_job=%.1f",
			n, jobs, pct(e2e, 0.5), pct(e2e, 0.99), pct(writes, 0.5), pct(writes, 0.99), 1000*cpu/float64(jobs), 1e6*cpu/float64(jobs*n))
	}
	// slow consumer: 10 reading miners plus one that never reads
	for _, c := range all {
		c.c.Close()
	}
	all = all[:0]
	drain_miners(t)
	var got int64
	for i := 0; i < 10; i++ {
		all = append(all, dial_fanout(t, fs.addr, true, func(uint64) { atomic.AddInt64(&got, 1) }))
	}
	stuck := dial_fanout(t, fs.addr, false, nil)
	all = append(all, stuck)
	wait_miners(t, 11)
	closed0 := atomic.LoadInt64(&fs.closed)
	t0 := time.Now()
	sent := 0
	var lat []time.Duration
	for time.Since(t0) < 30*time.Second && atomic.LoadInt64(&fs.closed) == closed0 {
		seq++
		sent++
		atomic.StoreInt64(&got, 0)
		base, mbl := fanout_job(seq)
		targets := job_targets()
		var wg sync.WaitGroup
		wg.Add(len(targets))
		t1 := time.Now()
		dispatch_targets(targets, base, mbl, nil, -1, seq, wg.Done)
		wg.Wait()
		for atomic.LoadInt64(&got) < 10 && time.Since(t1) < 2*time.Second {
			time.Sleep(50 * time.Microsecond)
		}
		lat = append(lat, time.Since(t1))
	}
	t.Logf("SLOW_CONSUMER evicted=%v after_jobs=%d after=%v job_bytes~%d reading_miners_all_read_p50=%v p99=%v",
		atomic.LoadInt64(&fs.closed) > closed0, sent, time.Since(t0).Round(time.Millisecond), 330, pct(lat, 0.5), pct(lat, 0.99))
}
