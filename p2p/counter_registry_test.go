package p2p

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/deroproject/derohe/metrics"
)

// r21 forensics: every p2p counter is on /metrics from the start (0 until it fires), and the eager list covers every
// GetOrCreateCounter("p2p_...") literal in the package, so a new counter cannot silently go back to lazy-only.
func TestP2PCountersRegisteredEagerly(t *testing.T) {
	var buf bytes.Buffer
	metrics.Set.WritePrometheus(&buf)
	out := buf.String()
	listed := map[string]bool{}
	for _, name := range p2p_counters {
		listed[name] = true
		if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + ` `).MatchString(out) {
			t.Fatalf("%s is not on /metrics before it fires", name)
		}
	}
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatal("no sources", err)
	}
	lit := regexp.MustCompile(`GetOrCreateCounter\("(p2p_[a-z0-9_]+)"\)`)
	found := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range lit.FindAllStringSubmatch(string(src), -1) {
			found++
			if !listed[m[1]] {
				t.Fatalf("%s (%s) is created lazily but missing from p2p_counters", m[1], f)
			}
		}
	}
	if found < len(p2p_counters) {
		t.Fatalf("source scan found %d counter literals, fewer than the %d listed", found, len(p2p_counters))
	}
}
