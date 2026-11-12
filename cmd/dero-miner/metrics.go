package main

// Opt-in Prometheus endpoint (--metrics-bind=127.0.0.1:<port>): /metrics in text format and /dashboard (the shared
// page in tools/dashboard). Off by default; a non-loopback bind is refused unless ENABLE_PUBLIC_METRICS=1, the same
// rule derod applies to its /metrics.
//
// Nothing here is on the hashing path. The handler reads only atomics, the snapshot the 1 Hz status goroutine
// publishes (status_snapshot), and the ledger/outcome copies that are already mutex-guarded. The plain globals the
// getwork goroutine writes (our_height, hash_rate, block_counter, ...) are read by the status goroutine as before and
// reach the handler only through that snapshot, so the endpoint adds no new unsynchronised reads.

import (
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/deroproject/derohe/cmd/dero-miner/gsplit"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/glue/httpguard"
	"github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/tools/dashboard"
)

type miner_status struct {
	height                          int64
	nw_estimate, difficulty         uint64
	accepted_blocks, accepted_minis uint64
	rejected                        uint64
}

var status_snapshot atomic.Value // miner_status, stored by the status goroutine
var hashrate_15s_bits uint64     // math.Float64bits of the prompt's 15 s hashrate
var getwork_reconnects uint64    // dial failures + dropped connections
var getwork_connected int32      // 1 while a getwork websocket is up
var miner_start = time.Now()

func publish_status() {
	status_snapshot.Store(miner_status{height: our_height, nw_estimate: hash_rate, difficulty: Difficulty,
		accepted_blocks: block_counter, accepted_minis: mini_block_counter, rejected: rejected})
}

func metrics_bind_allowed(bind string, getenv func(string) string) error {
	host, port, err := net.SplitHostPort(bind)
	if err != nil {
		return err
	}
	if port == "" || port == "0" {
		return fmt.Errorf("--metrics-bind needs a port")
	}
	ip := net.ParseIP(host)
	if strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback()) || getenv("ENABLE_PUBLIC_METRICS") == "1" {
		return nil
	}
	return fmt.Errorf("--metrics-bind %s is not loopback; set ENABLE_PUBLIC_METRICS=1 to expose miner metrics on the network", bind)
}

type miner_metrics struct {
	status                                    miner_status
	hashes                                    uint64
	stale_sha_skipped                         uint64        // r30 B26: miner-level, monotonic across engine restarts
	pe_ok                                     bool          // r30 B27: the kernel reported the P/E split
	cpu_p, cpu_e                              time.Duration // r30 B27: process CPU time on P-cores / E-cores
	hashrate15                                float64
	threads                                   int
	cpu_found, gpu_found                      uint64
	gpu_mismatch, gpu_stale, gpu_restarts     uint64
	split_on                                  bool
	split_hashed, split_dropped, split_cpu    uint64
	split_audited, split_batches, split_retry uint64
	split_restarts                            uint64
	split_idle_tries, split_feed_wait_us      uint64 // r19 splitcpu-2 regime signal (gsplit.Stats IdleTries/FeedWaitUs)
	split_feed_backlog_us                     uint64 // r20: the CPU-bound part of split_feed_wait_us (FeedWaitBacklogUs)
	split_stale_height, split_stale_final     uint64 // r21: split_stale verdicts by reason (gpu_split.go)
	split_gpu_busy_us                         uint64 // r21: wall-clock GPU busy time (union of the command buffers' spans)
	split_throttle_us, split_collect_us       uint64 // r22: feeder --gpu-max sleeps; reply-loop time reporting GPU-SHA batches
	split_stale_sha_skipped                   uint64 // r22: hashes whose GPU SHA was skipped (job stale mid-sort)
	cpu_duty, gpu_duty                        int    // r22: duty caps in force (the tuner may move them)
	tuner_on                                  bool
	tuner_kept, tuner_reverted, tuner_void    uint64     // r22: duty tuner verdicts
	tuner_noisy                               uint64     // r23: reverted because the gain was within the window noise
	throttle_sleep_ns                         int64      // r23: summed --cpu-max duty sleep of the mining threads
	phase_secs                                [2]float64 // r23b: wall seconds per phase (regular, final)
	phase_hashes                              [2]uint64  // r23b: hashes per phase
	cpu_share_milli                           int64      // r23b: mining threads' measured CPU share of their awake wall time
	split_s1_us, split_s1_cmds                uint64     // r22: summed stage-1 (op 1) command-buffer spans and their count
	split_sha_us, split_sha_cmds              uint64     // r22: the same for the final SHA (op 2)
	split_disabled                            bool
	sort_calls, sort_checked, sort_fallbacks  uint64
	submits, submit_ns_total, submit_ns_max   uint64
	reconnects                                uint64
	connected                                 bool
	outcome_ok                                bool
	cpu_paid, cpu_orph, gpu_paid, gpu_orph    int
	unresolved                                int
	node_paid_fraction                        float64
	uptime                                    float64
	gpu_binary_stale                          int // r21: GPU server binaries that are not the recorded build of their source
}

func collect_miner_metrics() (m miner_metrics) {
	m.status, _ = status_snapshot.Load().(miner_status)
	m.hashes = atomic.LoadUint64(&counter)
	m.stale_sha_skipped = stale_sha_now()
	if pe := pe_now(); pe.ok && pe.p <= pe.total {
		m.pe_ok, m.cpu_p, m.cpu_e = true, pe.p, pe.total-pe.p
	}
	m.hashrate15 = math.Float64frombits(atomic.LoadUint64(&hashrate_15s_bits))
	m.threads = threads
	m.cpu_found, m.gpu_found = atomic.LoadUint64(&cpu_minis), atomic.LoadUint64(&gpu_minis)
	m.gpu_mismatch, m.gpu_stale, m.gpu_restarts = atomic.LoadUint64(&gpu_mismatch), atomic.LoadUint64(&gpu_stale), atomic.LoadUint64(&gpu_restarts)
	if e := current_split(); e != nil {
		m.set_split(e.Stats())
		m.split_stale_height, m.split_stale_final = atomic.LoadUint64(&split_stale_height), atomic.LoadUint64(&split_stale_final)
	}
	m.sort_calls, m.sort_checked, m.sort_fallbacks = atomic.LoadUint64(&fast_sort_calls), atomic.LoadUint64(&fast_sort_checked), atomic.LoadUint64(&fast_sort_fallbacks)
	m.submits, m.submit_ns_total, m.submit_ns_max = atomic.LoadUint64(&submit_count), atomic.LoadUint64(&submit_ns_total), atomic.LoadUint64(&submit_ns_max)
	m.reconnects = atomic.LoadUint64(&getwork_reconnects)
	m.connected = atomic.LoadInt32(&getwork_connected) == 1
	if o, ok := outcomeSnapshot(); ok {
		t := ledger.tally()
		m.outcome_ok = true
		m.cpu_paid, m.cpu_orph, m.gpu_paid, m.gpu_orph, m.unresolved = t.cpuPaid, t.cpuOrphaned, t.gpuPaid, t.gpuOrphaned, t.unresolved
		m.node_paid_fraction = o.PaidFraction
	}
	m.uptime = time.Since(miner_start).Seconds()
	m.gpu_binary_stale = int(atomic.LoadInt32(&gpu_binaries_stale))
	m.cpu_duty, m.gpu_duty = cpu_duty_pct(), gpu_duty_pct()
	m.throttle_sleep_ns = atomic.LoadInt64(&cpu_throttle_sleep_ns)
	m.phase_secs, m.phase_hashes = phases.snapshot(time.Now(), atomic.LoadUint64(&counter))
	m.cpu_share_milli = cpu_share()
	if t, _ := duty_tuner_live.Load().(*duty_tuner); t != nil {
		m.tuner_on = true
		m.tuner_kept, m.tuner_reverted, m.tuner_void = atomic.LoadUint64(&t.kept), atomic.LoadUint64(&t.reverted), atomic.LoadUint64(&t.void)
		m.tuner_noisy = atomic.LoadUint64(&t.noisy)
	}
	return
}

// set_split copies the GPU split engine's counters into the snapshot (pure, unit-tested)
func (m *miner_metrics) set_split(s gsplit.Stats) {
	m.split_on = true
	m.split_hashed, m.split_dropped, m.split_cpu, m.split_audited = s.Hashed, s.Dropped, s.CPUFinished, s.Audited
	m.split_batches, m.split_retry, m.split_restarts, m.split_disabled = s.Batches, s.GPURetries, s.Restarts, s.Disabled != ""
	m.split_idle_tries, m.split_feed_wait_us, m.split_feed_backlog_us = s.IdleTries, s.FeedWaitUs, s.FeedWaitBacklogUs
	m.split_gpu_busy_us = s.GPUBusyUs
	m.split_throttle_us, m.split_collect_us, m.split_stale_sha_skipped = s.ThrottleUs, s.CollectUs, s.StaleSHASkipped
	m.split_s1_us, m.split_s1_cmds, m.split_sha_us, m.split_sha_cmds = s.S1us, s.S1Cmds, s.SHAus, s.SHACmds
}

func b01(b bool) int {
	if b {
		return 1
	}
	return 0
}

// write_miner_metrics is pure so the format is unit-tested (metrics_test.go). Never the wallet address.
func write_miner_metrics(w io.Writer, m miner_metrics) {
	p := func(format string, a ...interface{}) { fmt.Fprintf(w, format+"\n", a...) }
	p("# TYPE dero_miner_up gauge")
	p("dero_miner_up 1")
	p("dero_miner_info{version=%q} 1", config.Version.String())
	p("dero_miner_uptime_seconds %.0f", m.uptime)
	p("dero_miner_threads %d", m.threads)
	p("dero_miner_connected %d", b01(m.connected))
	p("dero_miner_getwork_reconnects_total %d", m.reconnects)
	p("# TYPE dero_miner_hashes_total counter")
	p("dero_miner_hashes_total %d", m.hashes)
	// r30 B26: texts counted in hashes_total whose final SHA was skipped (job stale mid-sort): never hashed, no share
	p("# TYPE dero_miner_stale_sha_skipped_total counter")
	p("dero_miner_stale_sha_skipped_total %d", m.stale_sha_skipped)
	p("dero_miner_hashes_effective_total %d", effective_hashes(m.hashes, m.stale_sha_skipped))
	p("# HELP dero_miner_hashrate_15s hashes per second over 15 s, excluding stale_sha_skipped (r30 B26)")
	p("dero_miner_hashrate_15s %.1f", m.hashrate15)
	if m.pe_ok { // r30 B27: proc_pid_rusage v6 P-core time; rate() per kind = cores of that kind the miner used
		p("# TYPE dero_miner_cpu_seconds_total counter")
		p(`dero_miner_cpu_seconds_total{core="p"} %.3f`, m.cpu_p.Seconds())
		p(`dero_miner_cpu_seconds_total{core="e"} %.3f`, m.cpu_e.Seconds())
	}
	p("dero_miner_height %d", m.status.height)
	p("dero_miner_difficulty %d", m.status.difficulty)
	p("dero_miner_network_hashrate_estimate %d", m.status.nw_estimate)
	p("dero_miner_accepted_blocks_total %d", m.status.accepted_blocks)
	p("dero_miner_accepted_miniblocks_total %d", m.status.accepted_minis)
	p("dero_miner_rejected_total %d", m.status.rejected)
	p(`dero_miner_found_total{source="cpu"} %d`, m.cpu_found)
	p(`dero_miner_found_total{source="gpu"} %d`, m.gpu_found)
	p("dero_miner_gpu_mismatch_total %d", m.gpu_mismatch)
	p("dero_miner_gpu_stale_total %d", m.gpu_stale)
	p("dero_miner_gpu_restarts_total %d", m.gpu_restarts)
	p("dero_miner_gpu_binary_stale %d", m.gpu_binary_stale)
	p("dero_miner_cpu_duty_percent %d", m.cpu_duty)                                   // r22: the --cpu-max cap in force
	p("dero_miner_gpu_duty_percent %d", m.gpu_duty)                                   // r22: the --gpu-max cap in force
	p("dero_miner_cpu_throttle_seconds_total %.3f", float64(m.throttle_sleep_ns)/1e9) // r23: mining threads' duty sleep
	for i, ph := range [2]string{"regular", "final"} {                                // r23b phase_duty.go: a final-phase hash earns 1/9 of a regular one
		p("dero_miner_phase_seconds_total{phase=%q} %.3f", ph, m.phase_secs[i])
		p("dero_miner_phase_hashes_total{phase=%q} %d", ph, m.phase_hashes[i])
	}
	p("dero_miner_cpu_share %.3f", float64(m.cpu_share_milli)/1000) // r23b: < 1 = the box holds the threads off-CPU
	if m.tuner_on {
		p(`dero_miner_duty_tuner_verdicts_total{verdict="kept"} %d`, m.tuner_kept)
		p(`dero_miner_duty_tuner_verdicts_total{verdict="reverted"} %d`, m.tuner_reverted)
		p(`dero_miner_duty_tuner_verdicts_total{verdict="void"} %d`, m.tuner_void)
		p("dero_miner_duty_tuner_noisy_total %d", m.tuner_noisy) // r23: of the reverted, gain within the window noise
	}
	if m.split_on {
		p("dero_miner_split_hashed_total %d", m.split_hashed)
		p("dero_miner_split_dropped_total %d", m.split_dropped)
		p(`dero_miner_split_stale_drops_total{reason="height"} %d`, m.split_stale_height) // r21: a newer height is mined
		p(`dero_miner_split_stale_drops_total{reason="final"} %d`, m.split_stale_final)   // r21: same height flipped to final work
		p("dero_miner_split_cpu_finished_total %d", m.split_cpu)
		p("dero_miner_split_audited_total %d", m.split_audited)
		p("dero_miner_split_batches_total %d", m.split_batches)
		p("dero_miner_split_gpu_retries_total %d", m.split_retry)
		p("dero_miner_split_restarts_total %d", m.split_restarts)
		p("dero_miner_split_cpu_idle_tries_total %d", m.split_idle_tries)                                 // TryWork found nothing staged (GPU-bound)
		p("dero_miner_split_feeder_ring_full_seconds_total %.3f", float64(m.split_feed_wait_us)/1e6)      // feeder blocked on a full ring (GPU- or CPU-held)
		p("dero_miner_split_feeder_cpu_backlog_seconds_total %.3f", float64(m.split_feed_backlog_us)/1e6) // ...while staged texts waited for the CPU (CPU-bound)
		p("dero_miner_split_gpu_busy_seconds_total %.3f", float64(m.split_gpu_busy_us)/1e6)               // wall GPU duty: rate() = busy fraction
		p("dero_miner_split_feeder_throttle_seconds_total %.3f", float64(m.split_throttle_us)/1e6)        // r22: --gpu-max sleeps of the feeder
		p("dero_miner_split_collect_seconds_total %.3f", float64(m.split_collect_us)/1e6)                 // r22: reply loop reporting GPU-SHA batches
		p("dero_miner_split_stale_sha_skipped_total %d", m.split_stale_sha_skipped)                       // r22: GPU SHA skipped, job stale mid-sort
		// r22: per-kernel command-buffer spans; rate(seconds)/rate(commands) = mean span of one stage-1 / final-SHA buffer
		p(`dero_miner_split_gpu_op_seconds_total{op="stage1"} %.3f`, float64(m.split_s1_us)/1e6)
		p(`dero_miner_split_gpu_op_seconds_total{op="sha"} %.3f`, float64(m.split_sha_us)/1e6)
		p(`dero_miner_split_gpu_op_commands_total{op="stage1"} %d`, m.split_s1_cmds)
		p(`dero_miner_split_gpu_op_commands_total{op="sha"} %d`, m.split_sha_cmds)
		p("dero_miner_split_disabled %d", b01(m.split_disabled))
	}
	p("dero_miner_sort_calls_total %d", m.sort_calls)
	p("dero_miner_sort_checked_total %d", m.sort_checked)
	p("dero_miner_sort_fallbacks_total %d", m.sort_fallbacks)
	p("dero_miner_submit_seconds_sum %.6f", float64(m.submit_ns_total)/1e9)
	p("dero_miner_submit_seconds_count %d", m.submits)
	p("dero_miner_submit_seconds_max %.6f", float64(m.submit_ns_max)/1e9)
	if m.outcome_ok { // absent until derod's GetMiningOutcome has answered once
		p(`dero_miner_paid_total{source="cpu"} %d`, m.cpu_paid)
		p(`dero_miner_paid_total{source="gpu"} %d`, m.gpu_paid)
		p(`dero_miner_orphaned_total{source="cpu"} %d`, m.cpu_orph)
		p(`dero_miner_orphaned_total{source="gpu"} %d`, m.gpu_orph)
		p("dero_miner_unresolved %d", m.unresolved)
		p("dero_miner_node_paid_fraction %.4f", m.node_paid_fraction)
	}
}

func miner_metrics_handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	write_miner_metrics(w, collect_miner_metrics())
	fmt.Fprintf(w, "dero_miner_guard_refused_total %d\n", atomic.LoadUint64(&metrics_guard_refused))
	fmt.Fprintf(w, "dero_miner_jobs_rejected_total %d\n", atomic.LoadUint64(&jobs_rejected))         // r21 job_guard.go
	fmt.Fprintf(w, "dero_miner_jobs_foreign_key_total %d\n", atomic.LoadUint64(&jobs_foreign_key))   // r21 job_guard.go
	fmt.Fprintf(w, "dero_miner_submits_throttled_total %d\n", atomic.LoadUint64(&submits_throttled)) // r22 job_guard.go
	write_job_latency_metrics(w)                                                                     // r23 job_latency.go
	metrics.WriteProcessMetrics(w)                                                                   // r21: go_* and process_* (RSS, CPU, fds); the miner exported none
}

// metrics_guard_refused counts requests refused by the Host/Origin guard (r20), exposed as
// dero_miner_guard_refused_total.
var metrics_guard_refused uint64

// metrics_bind_is_loopback mirrors metrics_bind_allowed's loopback test.
func metrics_bind_is_loopback(bind string) bool {
	host, _, err := net.SplitHostPort(bind)
	if err != nil {
		return false
	}
	return strings.EqualFold(host, "localhost") || net.ParseIP(host).IsLoopback() // a nil IP is not loopback
}

// new_metrics_server serves /metrics and /dashboard. r20: behind httpguard, so on a loopback bind a DNS-rebinding
// page (Host: attacker.example) and any cross-site request (foreign Origin) are refused; the dashboard's own
// same-origin poll and Prometheus/curl on 127.0.0.1 are unaffected. DERO_METRICS_ALLOWED_HOSTS adds Host names.
func new_metrics_server(bind string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", miner_metrics_handler)
	mux.HandleFunc("/dashboard", dashboard.Handler)
	h := httpguard.Guard(mux, httpguard.Policy{LoopbackBind: metrics_bind_is_loopback(bind),
		AllowHosts: httpguard.ParseList(os.Getenv("DERO_METRICS_ALLOWED_HOSTS")),
		OnReject:   func(string) { atomic.AddUint64(&metrics_guard_refused, 1) }})
	return &http.Server{Addr: bind, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, MaxHeaderBytes: 16 << 10}
}

// start_metrics_server listens synchronously (so a bad bind is reported at start) and serves in the background.
func start_metrics_server(bind string, getenv func(string) string) (*http.Server, string, error) {
	if err := metrics_bind_allowed(bind, getenv); err != nil {
		return nil, "", err
	}
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return nil, "", err
	}
	srv := new_metrics_server(bind)
	go srv.Serve(ln)
	return srv, ln.Addr().String(), nil
}
