package metrics

// r28 (rpc-metrics): the metric registry (registry_r28.go, metric_registry.json) and the push loop
// Dump_metrics_data_directly (0.0 % covered in the R28 sweep).

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
)

func TestR28RegistryLoads(t *testing.T) {
	reg := Registry()
	if len(reg) < 250 {
		t.Fatalf("registry has %d families; metric_registry.json unreadable or truncated", len(reg))
	}
	for n, f := range reg {
		if n != f.Name || f.Help == "" || strings.Contains(f.Help, "\n") || f.Area == "" || f.Unit == "" {
			t.Fatalf("bad entry %+v", f)
		}
		switch f.Type {
		case "counter", "gauge", "histogram", "vmhistogram", "summary", "untyped":
		default:
			t.Fatalf("%s: type %q", n, f.Type)
		}
	}
	for _, n := range []string{"rpc_error_responses_total", "rpc_requests_total", "dero_tip_age_seconds", "KCP_InPkts", "metrics_dump_posts_total"} {
		if _, ok := reg[n]; !ok {
			t.Fatalf("%s is not registered", n)
		}
	}
}

var r28_reg = map[string]Family{
	"a_total":  {Name: "a_total", Type: "counter", Help: `events \ of a`},
	"g":        {Name: "g", Type: "gauge", Help: "a gauge"},
	"h_sec":    {Name: "h_sec", Type: "vmhistogram", Help: "vm histogram"},
	"p_sec":    {Name: "p_sec", Type: "histogram", Help: "le histogram"},
	"KCP_X":    {Name: "KCP_X", Type: "counter", Help: "kcp x"},
	"own_help": {Name: "own_help", Type: "gauge", Help: "registry help"},
}

const r28_in = `a_total{k="1"} 1
a_total{k="2"} 2
g 3
h_sec_bucket{vmrange="1.000e+00...1.136e+00"} 1
h_sec_sum 1.1
h_sec_count 1
p_sec_bucket{le="1"} 1
p_sec_bucket{le="+Inf"} 1
p_sec_sum 0.5
p_sec_count 1
# TYPE KCP_X counter
KCP_X 7
# HELP own_help written by the code
own_help 1
unreg_total 4
`

func strip_comments(s string) string {
	var b strings.Builder
	for _, l := range strings.Split(s, "\n") {
		if !strings.HasPrefix(l, "#") {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}

func TestR28AnnotateAddsHelpAndType(t *testing.T) {
	var out bytes.Buffer
	unreg := annotate(&out, r28_reg, []byte(r28_in))
	got := out.String()
	if strip_comments(got) != strip_comments(r28_in) {
		t.Fatalf("sample lines changed:\n%s", got)
	}
	if len(unreg) != 1 || unreg[0] != "unreg_total" {
		t.Fatalf("unregistered %v", unreg)
	}
	want := map[string]int{
		"# HELP a_total events \\\\ of a\n# TYPE a_total counter\na_total{k=\"1\"} 1\n": 1, // once, before the first sample
		"# HELP g a gauge\n# TYPE g gauge\ng 3\n":                                       1,
		"# HELP h_sec vm histogram\nh_sec_bucket":                                       1, // HELP only: vmrange is not le
		"# HELP p_sec le histogram\n# TYPE p_sec histogram\np_sec_bucket{le=\"1\"}":     1,
		"# HELP KCP_X kcp x\n# TYPE KCP_X counter\nKCP_X 7\n":                           1, // HELP added, TYPE not doubled
		"# HELP own_help written by the code\n# TYPE own_help gauge\nown_help 1\n":      1, // its own HELP is kept; r29 B176: the missing TYPE is added
	}
	for frag, n := range want {
		if c := strings.Count(got, frag); c != n {
			t.Fatalf("%d x %q in:\n%s", c, frag, got)
		}
	}
	for _, fam := range []string{"a_total", "g", "h_sec", "p_sec", "KCP_X", "own_help"} {
		if c := strings.Count(got, "# HELP "+fam+" "); c != 1 {
			t.Fatalf("%s: %d HELP lines", fam, c)
		}
		if c := strings.Count(got, "# TYPE "+fam+" "); c > 1 {
			t.Fatalf("%s: %d TYPE lines", fam, c)
		}
	}
	if strings.Contains(got, "# TYPE h_sec") || strings.Contains(got, "HELP unreg_total") {
		t.Fatalf("vmhistogram typed or unregistered family annotated:\n%s", got)
	}
}

// family_seen returns, for each registered family with samples in text, whether its HELP precedes its first sample
func help_before_first_sample(t *testing.T, text string) (families int) {
	t.Helper()
	helped := map[string]bool{}
	sampled := map[string]bool{}
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, "# HELP ") {
			f := strings.Fields(l)[2]
			if helped[f] {
				t.Fatalf("second HELP for %s", f)
			}
			helped[f] = true
			continue
		}
		if l == "" || l[0] == '#' {
			continue
		}
		if f, ok := family_of(registry, sample_name(l)); ok && !sampled[f.Name] {
			sampled[f.Name] = true
			if !helped[f.Name] {
				t.Fatalf("%s: first sample before its HELP", f.Name)
			}
		}
	}
	return len(sampled)
}

func TestR28WritePrometheusAnnotated(t *testing.T) {
	rec := httptest.NewRecorder()
	WritePrometheus(rec, httptest.NewRequest("GET", "/metrics", nil))
	text := rec.Body.String()
	if p, n := r27_check_exposition(text); len(p) > 0 || n < 20 {
		t.Fatalf("exposition problems %v (%d samples)", p, n)
	}
	if n := help_before_first_sample(t, text); n < 20 {
		t.Fatalf("only %d registered families annotated", n)
	}
	var unreg []string
	for _, l := range strings.Split(text, "\n") {
		if l == "" || l[0] == '#' {
			continue
		}
		name := sample_name(l)
		if _, ok := family_of(registry, name); !ok && !strings.HasPrefix(name, "r27_test_") && !strings.HasPrefix(name, "r28_test_") {
			unreg = append(unreg, name)
		}
	}
	if len(unreg) > 0 {
		t.Fatalf("families on /metrics missing from metric_registry.json (run harness/intel/metric_registry.py build): %v", unreg)
	}
	os.Setenv("DERO_METRICS_METADATA", "0")
	defer os.Unsetenv("DERO_METRICS_METADATA")
	rec = httptest.NewRecorder()
	WritePrometheus(rec, httptest.NewRequest("GET", "/metrics", nil))
	if strings.Contains(rec.Body.String(), "# HELP ") {
		t.Fatal("DERO_METRICS_METADATA=0 must write the unannotated exposition")
	}
}

func BenchmarkR28Annotate(b *testing.B) {
	var buf bytes.Buffer
	writePrometheusMetrics(&buf)
	text := buf.Bytes()
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		annotate(io.Discard, registry, text)
	}
}

func TestR28DumpImportURLAndJob(t *testing.T) {
	u, err := dump_import_url("http://127.0.0.1:8428/some/path?x=1#frag", "a b&c", 42)
	if err != nil {
		t.Fatal(err)
	}
	if want := "http://127.0.0.1:8428/api/v1/import/prometheus?extra_label=job%3Da+b%26c&extra_label=instance%3D42"; u != want {
		t.Fatalf("url %q\nwant %q", u, want)
	}
	if _, err := dump_import_url("http://[::1", "j", 1); err == nil {
		t.Fatal("an unparsable server must be refused")
	}
	exe, _ := os.Executable()
	j := dump_job_name("node1")
	if !strings.HasSuffix(j, "_"+filepathBase(exe)+"_node1") {
		t.Fatalf("job %q", j)
	}
	if j2 := dump_job_name(1234); strings.Contains(j2, "1234") || !strings.HasSuffix(j2, filepathBase(exe)) { // upstream panicked here
		t.Fatalf("job for a non-string name %q", j2)
	}
}

func filepathBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func TestR28DumpMetricsLoop(t *testing.T) {
	os.Unsetenv("METRICS_SERVER")
	Dump_metrics_data_directly(logr.Discard(), "x") // no server configured: returns at once (else this test hangs)

	var mu sync.Mutex
	var paths, bodies []string
	got := make(chan struct{}, 64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		paths = append(paths, r.URL.Path+"?"+r.URL.RawQuery)
		bodies = append(bodies, string(b))
		mu.Unlock()
		got <- struct{}{}
	}))
	old := dump_interval
	dump_interval = 5 * time.Millisecond
	defer func() { dump_interval = old }()
	ok0, err0 := dump_posts_ok.Get(), dump_posts_err.Get()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { dump_metrics_loop(logr.Discard(), srv.URL+"/ignored", "r28", stop); close(done) }()
	select {
	case <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("no push reached the server")
	}
	mu.Lock()
	p0, b0 := paths[0], bodies[0]
	mu.Unlock()
	if !strings.HasPrefix(p0, "/api/v1/import/prometheus?extra_label=job%3D") || !strings.Contains(p0, "_r28&extra_label=instance%3D") {
		t.Fatalf("push path %q", p0)
	}
	if prob, n := r27_check_exposition(b0); len(prob) > 0 || n < 20 {
		t.Fatalf("pushed body problems %v (%d samples)", prob, n)
	}
	srv.Close() // the next pushes fail: counted, not silently dropped
	deadline := time.Now().Add(10 * time.Second)
	for dump_posts_err.Get() == err0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if dump_posts_ok.Get() <= ok0 || dump_posts_err.Get() <= err0 {
		t.Fatalf("posts ok %d->%d err %d->%d", ok0, dump_posts_ok.Get(), err0, dump_posts_err.Get())
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the push loop did not stop")
	}
}
