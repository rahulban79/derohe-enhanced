package rpc

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/creachadair/jrpc2/server"
	"github.com/deroproject/derohe/metrics"
)

func series_count() (int, string) {
	var b bytes.Buffer
	metrics.Set.WritePrometheus(&b)
	return strings.Count(b.String(), "\n"), b.String()
}

// a client-chosen method name must never become a series: before the fix 500 bogus names made 2,501 lines and an
// invalid name ("bad name{") panicked inside LogResponse (counted as a recovered panic)
func TestRPCMetricsUnknownMethodsBounded(t *testing.T) {
	loc := server.NewLocal(d, &server.LocalOptions{Server: options})
	defer loc.Close()
	before, _ := series_count()
	unknown0 := rpc_unknown_methods.Get()
	panics0 := metrics.Set.GetOrCreateCounter(`recovered_panics_total{level="2"}`).Get()
	for i := 0; i < 500; i++ {
		loc.Client.Call(context.Background(), fmt.Sprintf("Attacker.Method%d", i), nil)
	}
	loc.Client.Call(context.Background(), "bad name{", nil)
	after, text := series_count()
	if after-before > 2 { // rpc_unknown_method_total already exists; at most the panic counter may appear
		t.Fatalf("501 unknown methods added %d series lines:\n%s", after-before, text)
	}
	if got := rpc_unknown_methods.Get() - unknown0; got != 501 {
		t.Fatalf("rpc_unknown_method_total grew by %d, want 501", got)
	}
	if p := metrics.Set.GetOrCreateCounter(`recovered_panics_total{level="2"}`).Get(); p != panics0 {
		t.Fatalf("an unknown method name caused %d recovered panic(s)", p-panics0)
	}
}

// a registered method is counted under a label, with a Prometheus-valid metric NAME (no '.')
func TestRPCMetricsKnownMethodLabelled(t *testing.T) {
	loc := server.NewLocal(d, &server.LocalOptions{Server: options})
	defer loc.Close()
	c := metrics.Set.GetOrCreateCounter(`rpc_requests_total{method="DERO.Ping"}`)
	n0 := c.Get()
	if _, err := loc.Client.Call(context.Background(), "DERO.Ping", nil); err != nil {
		t.Fatal(err)
	}
	if c.Get() != n0+1 {
		t.Fatalf("DERO.Ping not counted: %d -> %d", n0, c.Get())
	}
	_, text := series_count()
	name := regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		n := line
		if i := strings.IndexAny(n, "{ "); i >= 0 {
			n = n[:i]
		}
		if !name.MatchString(n) {
			t.Errorf("metric name %q is not valid Prometheus text format (line %q)", n, line)
		}
	}
}

// /json_rpc goes through the jhttp bridge; it used to have no RPCLog at all
func TestRPCMetricsHTTPBridgeCounted(t *testing.T) {
	c := metrics.Set.GetOrCreateCounter(`rpc_requests_total{method="DERO.Echo"}`)
	n0 := c.Get()
	req := httptest.NewRequest("POST", "/json_rpc", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"DERO.Echo","params":["x"]}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	translate_http_to_jsonrpc_and_vice_versa(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "DERO x") {
		t.Fatalf("bridge answer %d %q", w.Code, w.Body.String())
	}
	if c.Get() != n0+1 {
		t.Fatalf("HTTP /json_rpc call not counted: %d -> %d", n0, c.Get())
	}
}

func TestRPCMethodLabel(t *testing.T) {
	for m, want := range map[string]string{"DERO.GetInfo": "DERO.GetInfo", "getinfo": "getinfo", "DERO.GetInfo2": "", "": "", `x{a="b"}`: ""} {
		if got := rpc_method_label(m); got != want {
			t.Errorf("rpc_method_label(%q) = %q want %q", m, got, want)
		}
	}
	if n := len(sorted_known_methods()); n < 30 {
		t.Fatalf("only %d registered methods", n)
	}
}

func TestMetricsAllowed(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for _, c := range []struct {
		bind string
		env  map[string]string
		want bool
	}{
		{"127.0.0.1:10102", nil, true},
		{"[::1]:10102", nil, true},
		{"localhost:10102", nil, true},
		{"0.0.0.0:10102", nil, false}, // carries peer IPs: not public by default
		{"192.168.1.5:10102", nil, false},
		{"0.0.0.0:10102", map[string]string{"ENABLE_PUBLIC_METRICS": "1"}, true},
		{"127.0.0.1:10102", map[string]string{"DISABLE_METRICS": "1"}, false},
		{"0.0.0.0:10102", map[string]string{"DISABLE_METRICS": "1", "ENABLE_PUBLIC_METRICS": "1"}, false},
	} {
		if got := metrics_allowed(c.bind, env(c.env)); got != c.want {
			t.Errorf("metrics_allowed(%q, %v) = %v want %v", c.bind, c.env, got, c.want)
		}
	}
	mux := http.NewServeMux()
	if register_metrics_routes(mux, "0.0.0.0:1", env(nil)) {
		t.Fatal("public bind registered /metrics without opt-in")
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("/metrics on a public bind answered %d", w.Code)
	}
}

func TestWriteNodeMetrics(t *testing.T) {
	var b bytes.Buffer
	write_node_metrics(&b, node_snapshot{})
	if s := b.String(); !strings.Contains(s, "dero_node_up 0") || strings.Contains(s, "dero_chain_height") {
		t.Fatalf("not-ready snapshot:\n%s", s)
	}
	b.Reset()
	write_node_metrics(&b, node_snapshot{ok: true, height: 7805178, topo: 7805180, stable: 7805170, tip_age_s: 12.5, peer_median: 7805179,
		lag: 1, peers_out: 15, status: "synced", getwork_miners: 1})
	s := b.String()
	for _, want := range []string{"dero_node_up 1", "dero_chain_height 7805178", "dero_tip_age_seconds 12.500", "dero_sync_lag_blocks 1",
		`dero_sync_status{status="synced"} 1`, `dero_sync_status{status="stalled"} 0`, "dero_getwork_miners 1"} {
		if !strings.Contains(s, want+"\n") {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Count(s, "dero_sync_status{") != len(sync_statuses) {
		t.Errorf("want one dero_sync_status series per status")
	}
}

// with no chain the handler must still answer (dero_node_up 0), never panic
func TestMetricsHandlerWithoutChain(t *testing.T) {
	w := httptest.NewRecorder()
	metrics_handler(w, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(w.Body.String(), "dero_node_up 0\n") || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("handler without chain: %q %q", w.Header().Get("Content-Type"), w.Body.String()[:80])
	}
}

func BenchmarkMetricsScrape(b *testing.B) {
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		metrics_handler(w, httptest.NewRequest("GET", "/metrics", nil))
	}
}

func BenchmarkRPCLogResponse(b *testing.B) {
	loc := server.NewLocal(d, &server.LocalOptions{Server: options})
	defer loc.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		loc.Client.Call(context.Background(), "DERO.Ping", nil)
	}
}
