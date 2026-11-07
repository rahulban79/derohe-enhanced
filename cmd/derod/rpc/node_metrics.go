// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package rpc

// node_metrics.go — what /metrics on the RPC server exposes beyond the counters other packages register, and who
// may read it.
//
//  1. RPC method label. metrics_generator.LogResponse built series names from the CLIENT's method string, and jrpc2
//     calls it for unknown methods too (server.go setContext runs before assign). So every distinct bogus method
//     created three series forever (500 names -> 2,501 lines, 133 KB per scrape), and a name that is not a valid
//     metric identifier ("a b") made VictoriaMetrics panic inside LogResponse, which globals.Recover counted as a
//     recovered panic — a remote, unauthenticated way to inflate the health counter GetSyncInfo reports. Only
//     registered methods now get per-method series; the rest share rpc_unknown_method_total.
//  2. Node-state gauges. Height, tip age, lag behind the peers' median and the sync status were only in GetSyncInfo;
//     a scraper had to speak JSON-RPC. They are computed per scrape (not per block), so they cost nothing between
//     scrapes.
//  3. Exposure. /metrics carries peer IP addresses (p2p_first_relay_total{peer=...}), the version and free disk. The
//     same rule as pprof (bind_policy.go): served on a loopback bind; a public bind needs ENABLE_PUBLIC_METRICS=1;
//     DISABLE_METRICS=1 turns it off everywhere. /dashboard follows /metrics.

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/p2p"
	"github.com/deroproject/derohe/tools/dashboard"
)

func metrics_allowed(bind string, getenv func(string) string) bool {
	if getenv("DISABLE_METRICS") == "1" {
		return false
	}
	return bind_is_loopback(bind) || getenv("ENABLE_PUBLIC_METRICS") == "1"
}

var known_methods_once sync.Once
var known_methods map[string]bool

// rpc_method_label returns method when it names a registered handler, else "" (the caller then counts it as unknown).
func rpc_method_label(method string) string {
	known_methods_once.Do(func() {
		known_methods = map[string]bool{}
		for _, n := range d.Names() {
			known_methods[n] = true
		}
	})
	if known_methods[method] {
		return method
	}
	return ""
}

var rpc_unknown_methods = metrics.Set.NewCounter("rpc_unknown_method_total")

// getwork job fan-out (websocket_getwork_server.go SendJob): one per miner per job; a failed write is a miner that
// did not get the new job (it keeps hashing the stale one until the next).
var getwork_jobs_sent = metrics.Set.NewCounter("getwork_jobs_sent_total")
var getwork_job_write_errors = metrics.Set.NewCounter("getwork_job_write_errors_total")

type node_snapshot struct {
	ok                   bool // false: the chain is not up yet (or a read panicked); only "up" is written
	height, topo, stable int64
	tip_age_s            float64
	peer_median, lag     int64
	peers_in, peers_out  uint64
	status               string
	getwork_miners       int
	jobs_held            bool
	ban_list_entries     uint64 // r27: entries in the ban list now, persisted ones included (p2p.Ban_Count)
	collect_seconds      float64
}

var sync_statuses = []string{"synced", "syncing", "stalled", "isolated"}

func collect_node_snapshot() (s node_snapshot) {
	t0 := time.Now()
	defer func() {
		if r := recover(); r != nil {
			s = node_snapshot{}
		}
		s.collect_seconds = time.Since(t0).Seconds()
	}()
	// chain is nil until RPCServer_Start; the recover above turns that (and any read panic) into dero_node_up 0
	s.height = chain.Get_Height()
	s.topo = chain.Load_TOPO_HEIGHT()
	s.stable = chain.Get_Stable_Height()
	top := chain.Get_Top_ID()
	s.tip_age_s = float64(time.Now().UnixMilli()-int64(chain.Load_Block_Timestamp(top))) / 1000
	s.peer_median, _ = p2p.Best_Peer_Height()
	s.peers_in, s.peers_out = p2p.Peer_Direction_Count()
	if s.peer_median > 0 {
		s.lag = s.peer_median - s.height
	}
	s.status, _ = classify_sync(s.peers_in+s.peers_out, s.lag, s.tip_age_s)
	client_list_mutex.Lock()
	s.getwork_miners = len(client_list)
	client_list_mutex.Unlock()
	s.jobs_held, _ = jobs_held()
	s.ban_list_entries = p2p.Ban_Count()
	s.ok = true
	return
}

func b2f(b bool) int {
	if b {
		return 1
	}
	return 0
}

// write_node_metrics is pure so the exposition format is unit-tested (node_metrics_test.go).
func write_node_metrics(w io.Writer, s node_snapshot) {
	fmt.Fprintf(w, "# TYPE dero_node_up gauge\ndero_node_up %d\n", b2f(s.ok))
	fmt.Fprintf(w, "dero_metrics_collect_seconds %g\n", s.collect_seconds)
	if !s.ok {
		return
	}
	fmt.Fprintf(w, "# TYPE dero_chain_height gauge\ndero_chain_height %d\n", s.height)
	fmt.Fprintf(w, "dero_chain_topoheight %d\n", s.topo)
	fmt.Fprintf(w, "dero_chain_stableheight %d\n", s.stable)
	fmt.Fprintf(w, "# HELP dero_tip_age_seconds wall clock minus the tip block's timestamp; GetInfo cannot show lag\n")
	fmt.Fprintf(w, "dero_tip_age_seconds %.3f\n", s.tip_age_s)
	fmt.Fprintf(w, "dero_peer_median_height %d\n", s.peer_median)
	fmt.Fprintf(w, "dero_sync_lag_blocks %d\n", s.lag)
	for _, st := range sync_statuses {
		fmt.Fprintf(w, "dero_sync_status{status=%q} %d\n", st, b2f(st == s.status))
	}
	fmt.Fprintf(w, "dero_getwork_miners %d\n", s.getwork_miners)
	fmt.Fprintf(w, "dero_mining_work_would_be_stale %d\n", b2f(s.jobs_held))
	// r27 (R26 metrics gap): p2p_bans_total counts bans made since the start, so it read 0 while the ban list held a
	// ban loaded from ban_list.json; the gauge is the list itself.
	fmt.Fprintf(w, "# HELP dero_p2p_ban_list_entries entries in the ban list now, persisted ones included; p2p_bans_total counts only bans made since start\n")
	fmt.Fprintf(w, "# TYPE dero_p2p_ban_list_entries gauge\ndero_p2p_ban_list_entries %d\n", s.ban_list_entries)
}

// metrics_handler: everything metrics.WritePrometheus wrote before, then the node-state block.
// r28: the whole page is annotated once with the metric registry's HELP/TYPE (metrics/registry_r28.go), node block
// included; the sample lines are unchanged.
func metrics_handler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	var buf bytes.Buffer
	metrics.WritePrometheusRaw(&buf)
	write_node_metrics(&buf, collect_node_snapshot())
	metrics.WriteAnnotated(w, buf.Bytes())
}

// register_metrics_routes is called with the address the server will listen on.
func register_metrics_routes(mux *http.ServeMux, bind string, getenv func(string) string) bool {
	if !metrics_allowed(bind, getenv) {
		return false
	}
	mux.HandleFunc("/metrics", metrics_handler)
	mux.HandleFunc("/dashboard", dashboard.Handler)
	return true
}

// sorted_known_methods is for tests and the startup log.
func sorted_known_methods() []string {
	rpc_method_label("")
	r := make([]string, 0, len(known_methods))
	for k := range known_methods {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}
