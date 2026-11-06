package metrics

// r27 (rpc-metrics): WritePrometheus (the /metrics writer) and the disk-usage accessors were 0.0 % covered (R27
// sweep). One bad line fails a whole Prometheus scrape (the r19 '.'-in-a-name lesson), so the writer's output is
// checked line by line: every sample is name{labels} value with a valid metric name and a number, no series twice.

import (
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var r27_sample = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})? (\S+)$`)
var r27_label = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\]|\\.)*"$`)

// r27_check_exposition returns the problems of a Prometheus text exposition (pure, so it is tested on bad input too).
func r27_check_exposition(text string) (problems []string, samples int) {
	seen := map[string]bool{}
	for i, l := range strings.Split(text, "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		m := r27_sample.FindStringSubmatch(l)
		if m == nil {
			problems = append(problems, "line "+strconv.Itoa(i+1)+": not name{labels} value: "+l)
			continue
		}
		if _, err := strconv.ParseFloat(m[3], 64); err != nil {
			problems = append(problems, "line "+strconv.Itoa(i+1)+": value "+m[3])
		}
		if m[2] != "" {
			for _, kv := range strings.Split(strings.Trim(m[2], "{}"), ",") {
				if kv = strings.TrimSpace(kv); kv != "" && !r27_label.MatchString(kv) {
					problems = append(problems, "line "+strconv.Itoa(i+1)+": label "+kv)
				}
			}
		}
		key := m[1] + m[2]
		if seen[key] {
			problems = append(problems, "line "+strconv.Itoa(i+1)+": duplicate series "+key)
		}
		seen[key] = true
		samples++
	}
	return
}

func TestR27ExpositionChecker(t *testing.T) {
	for _, bad := range []string{"DERO.GetInfo_total 1", "a_total{method=x} 1", "a_total one", "a 1\na 1", "a{b=\"c\"}1"} {
		if p, _ := r27_check_exposition(bad); len(p) == 0 {
			t.Fatalf("checker accepted %q", bad)
		}
	}
	if p, n := r27_check_exposition("# HELP a x\na 1\nb{c=\"d\", e=\"f\"} 2.5e-3\n"); len(p) != 0 || n != 2 {
		t.Fatalf("checker refused a valid exposition: %v (%d samples)", p, n)
	}
}

func TestR27WritePrometheusIsValid(t *testing.T) {
	c := Set.GetOrCreateCounter(`r27_test_events_total{kind="a"}`)
	c.Inc()
	rec := httptest.NewRecorder()
	WritePrometheus(rec, httptest.NewRequest("GET", "/metrics", nil))
	text := rec.Body.String()
	problems, samples := r27_check_exposition(text)
	if len(problems) > 0 {
		t.Fatalf("%d problems, first: %s", len(problems), problems[0])
	}
	if samples < 20 {
		t.Fatalf("only %d samples", samples)
	}
	for _, want := range []string{"\nr27_test_events_total{kind=\"a\"} " + strconv.FormatUint(c.Get(), 10) + "\n", "\napp_uptime_seconds ", "\nfree_disk_space_bytes ", "\napp_start_timestamp "} {
		if !strings.Contains("\n"+text, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestR27DiskUsageAccessors(t *testing.T) {
	d := NewDiskUsage(os.TempDir())
	size, free, avail, used := d.Size(), d.Free(), d.Available(), d.Used()
	if size == 0 || free > size || avail > free || used != size-free {
		t.Fatalf("size %d free %d available %d used %d", size, free, avail, used)
	}
	if u := d.Usage(); u < 0 || u > 1 {
		t.Fatalf("usage %v", u)
	}
}
