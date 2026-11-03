package main

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/deroproject/derohe/cmd/dero-miner/gsplit"
)

func TestMetricsBindAllowed(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for _, c := range []struct {
		bind string
		env  map[string]string
		ok   bool
	}{
		{"127.0.0.1:10109", nil, true},
		{"[::1]:10109", nil, true},
		{"localhost:10109", nil, true},
		{"0.0.0.0:10109", nil, false},
		{":10109", nil, false}, // empty host listens on every interface
		{"192.168.1.9:10109", nil, false},
		{"0.0.0.0:10109", map[string]string{"ENABLE_PUBLIC_METRICS": "1"}, true},
		{"127.0.0.1:0", nil, false},
		{"127.0.0.1", nil, false},
	} {
		if err := metrics_bind_allowed(c.bind, env(c.env)); (err == nil) != c.ok {
			t.Errorf("metrics_bind_allowed(%q, %v) = %v, want ok=%v", c.bind, c.env, err, c.ok)
		}
	}
}

func TestWriteMinerMetrics(t *testing.T) {
	var b bytes.Buffer
	write_miner_metrics(&b, miner_metrics{hashes: 123456789, hashrate15: 31000.5, threads: 20, cpu_found: 7, gpu_found: 3,
		status: miner_status{height: 7805178, accepted_minis: 10, rejected: 1}, connected: true})
	s := b.String()
	for _, want := range []string{"dero_miner_up 1", "dero_miner_hashes_total 123456789", "dero_miner_hashrate_15s 31000.5",
		"dero_miner_height 7805178", `dero_miner_found_total{source="gpu"} 3`, "dero_miner_connected 1", "dero_miner_rejected_total 1"} {
		if !strings.Contains(s, want+"\n") {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "dero_miner_paid_total") || strings.Contains(s, "dero_miner_split_") {
		t.Errorf("paid/split series must be absent until known:\n%s", s)
	}
	if strings.Contains(s, "dero1") || strings.Contains(s, "deto1") {
		t.Errorf("wallet address leaked into metrics")
	}
	b.Reset()
	write_miner_metrics(&b, miner_metrics{outcome_ok: true, cpu_paid: 5, gpu_orph: 2, split_on: true, split_hashed: 99, split_idle_tries: 7, split_feed_wait_us: 2500000, split_feed_backlog_us: 1250000, split_gpu_busy_us: 4500000})
	if s := b.String(); !strings.Contains(s, `dero_miner_paid_total{source="cpu"} 5`) || !strings.Contains(s, `dero_miner_orphaned_total{source="gpu"} 2`) ||
		!strings.Contains(s, "dero_miner_split_hashed_total 99") || !strings.Contains(s, "dero_miner_split_cpu_idle_tries_total 7") ||
		!strings.Contains(s, "dero_miner_split_feeder_ring_full_seconds_total 2.500") ||
		!strings.Contains(s, "dero_miner_split_feeder_cpu_backlog_seconds_total 1.250") ||
		!strings.Contains(s, "dero_miner_split_gpu_busy_seconds_total 4.500") {
		t.Errorf("outcome/split series:\n%s", s)
	}
}

// end to end on a loopback port: /metrics answers with the live counter, /dashboard serves the page, and a public
// bind is refused before anything listens
func TestMetricsServerLoopback(t *testing.T) {
	if _, _, err := start_metrics_server("0.0.0.0:0", func(string) string { return "" }); err == nil {
		t.Fatal("public bind accepted without opt-in")
	}
	wallet_address = "deto1qyyawp87a3ckr9f2j5hnqmxevq3czrr83prc58ylc5889qdt0zf6cqg26e27g"
	defer func() { wallet_address = "" }()
	if _, _, err := start_metrics_server("127.0.0.1:0", func(string) string { return "" }); err == nil {
		t.Fatal("port 0 must be refused (a random port nobody can find)")
	}
	srv, addr, _ := start_metrics_server_any_port(t)
	defer srv.Close()
	atomic.AddUint64(&counter, 42)
	r, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if !strings.Contains(string(body), "dero_miner_hashes_total ") || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("/metrics: %q %s", r.Header.Get("Content-Type"), body)
	}
	if strings.Contains(string(body), wallet_address) {
		t.Fatal("wallet address in /metrics")
	}
	r, err = http.Get("http://" + addr + "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if !strings.Contains(string(page), "<title>DERO Live Dashboard</title>") || !strings.Contains(r.Header.Get("Content-Security-Policy"), "connect-src 'self'") {
		t.Fatalf("/dashboard: %q", r.Header.Get("Content-Security-Policy"))
	}
}

// start_metrics_server refuses port 0, so the test picks a free loopback port first
func start_metrics_server_any_port(t *testing.T) (*http.Server, string, error) {
	for i := 0; i < 20; i++ {
		port := 20000 + int(time.Now().UnixNano()%20000)
		srv, addr, err := start_metrics_server("127.0.0.1:"+strconv.Itoa(port), func(string) string { return "" })
		if err == nil {
			return srv, addr, nil
		}
	}
	t.Fatal("no free loopback port")
	return nil, "", nil
}

// a second request must not panic (it did: three bare close(Exit_In_Progress) sites)
func TestCloseOnceTwice(t *testing.T) {
	var once sync.Once
	ch := make(chan bool)
	close_once(&once, ch)
	close_once(&once, ch)
	select {
	case <-ch:
	default:
		t.Fatal("channel not closed")
	}
}

type closeCounter struct{ n int32 }

func (c *closeCounter) Close() error { atomic.AddInt32(&c.n, 1); return nil }

// two SIGINTs and a SIGTERM: exit requested once (no panic), the console closed so Readline unblocks
func TestExitOnSignalRepeated(t *testing.T) {
	sigs := make(chan os.Signal, 3)
	sigs <- os.Interrupt
	sigs <- os.Interrupt
	sigs <- syscall.SIGTERM
	close(sigs)
	var c closeCounter
	var once sync.Once
	exit := make(chan bool)
	exit_on_signal(sigs, &c, func() { close_once(&once, exit) })
	select {
	case <-exit:
	case <-time.After(time.Second):
		t.Fatal("Exit_In_Progress not closed")
	}
	if atomic.LoadInt32(&c.n) == 0 {
		t.Fatal("console not closed: the blocked Readline would never return")
	}
}

func BenchmarkMinerMetricsScrape(b *testing.B) {
	var buf bytes.Buffer
	for i := 0; i < b.N; i++ {
		buf.Reset()
		write_miner_metrics(&buf, collect_miner_metrics())
	}
}

// r19 splitcpu-2: the regime counters reach the snapshot that /metrics writes
func TestSetSplitCopiesRegimeCounters(t *testing.T) {
	var m miner_metrics
	m.set_split(gsplit.Stats{Hashed: 3, IdleTries: 7, FeedWaitUs: 2500000, FeedWaitBacklogUs: 1250000, GPUBusyUs: 99})
	if !m.split_on || m.split_hashed != 3 || m.split_idle_tries != 7 || m.split_feed_wait_us != 2500000 || m.split_feed_backlog_us != 1250000 ||
		m.split_gpu_busy_us != 99 {
		t.Fatalf("snapshot %+v", m)
	}
}

// r21 forensics: the split_stale verdicts by reason reach /metrics while split mode runs.
func TestMetricsSplitStaleDropsByReason(t *testing.T) {
	var m miner_metrics
	m.set_split(gsplit.Stats{Hashed: 1})
	m.split_stale_height, m.split_stale_final = 5, 3
	var buf bytes.Buffer
	write_miner_metrics(&buf, m)
	out := buf.String()
	for _, want := range []string{`dero_miner_split_stale_drops_total{reason="height"} 5`, `dero_miner_split_stale_drops_total{reason="final"} 3`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in\n%s", want, out)
		}
	}
}

// r22 gpukernels: the per-kernel command-buffer spans and counts reach /metrics while split mode runs.
func TestMetricsSplitPerKernelSpans(t *testing.T) {
	var m miner_metrics
	m.set_split(gsplit.Stats{Hashed: 1, S1us: 1500000, S1Cmds: 40, SHAus: 2250000, SHACmds: 39})
	var buf bytes.Buffer
	write_miner_metrics(&buf, m)
	out := buf.String()
	for _, want := range []string{`dero_miner_split_gpu_op_seconds_total{op="stage1"} 1.500`, `dero_miner_split_gpu_op_seconds_total{op="sha"} 2.250`,
		`dero_miner_split_gpu_op_commands_total{op="stage1"} 40`, `dero_miner_split_gpu_op_commands_total{op="sha"} 39`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in\n%s", want, out)
		}
	}
}
