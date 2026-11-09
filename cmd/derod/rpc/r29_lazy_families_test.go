package rpc

// r29 (live-observability, dero-rft §7 B152): every registry family the R28 registry build found absent from a live
// page (in_scrape=false) is on a fresh node's page at 0 now, except the VictoriaMetrics histograms, which by the
// library's design write no line before their first observation (vendor/github.com/VictoriaMetrics/metrics/
// histogram.go marshalTo: "if countTotal == 0 { return }"); the orphaned-reason labels are resolve_fate's closed set.

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestR29LazyFamiliesOnAFreshPage(t *testing.T) {
	_, _, done := r25_sim(t, 2)
	defer done()
	rec := httptest.NewRecorder()
	metrics_handler(rec, httptest.NewRequest("GET", "/metrics", nil))
	page := rec.Body.String()
	raw, err := os.ReadFile("../../../metrics/metric_registry.json")
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		Families []struct {
			Name      string `json:"name"`
			Type      string `json:"type"`
			In_scrape *bool  `json:"in_scrape"`
		} `json:"families"`
	}
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatal(err)
	}
	lazy, missing := 0, []string{}
	for _, f := range reg.Families {
		if f.In_scrape == nil || *f.In_scrape {
			continue
		}
		lazy++
		if f.Type == "vmhistogram" || f.Type == "histogram" {
			continue // empty histograms print nothing (library design)
		}
		if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(f.Name) + `[{ ]`).MatchString(page) {
			missing = append(missing, f.Name)
		}
	}
	if lazy < 20 {
		t.Fatalf("only %d in_scrape=false families in the registry", lazy)
	}
	if len(missing) > 0 {
		t.Fatalf("absent from a fresh /metrics page (not created at start): %v", missing)
	}
}

func TestR29OrphanedReasonsAreResolveFates(t *testing.T) {
	src, err := os.ReadFile("mining_outcome.go")
	if err != nil {
		t.Fatal(err)
	}
	var lit []string
	for _, m := range regexp.MustCompile(`return "orphaned", "([a-z_]+)"`).FindAllStringSubmatch(string(src), -1) {
		lit = append(lit, m[1])
	}
	have := append([]string(nil), orphaned_reasons...)
	sort.Strings(lit)
	sort.Strings(have)
	if len(lit) == 0 || strings.Join(lit, ",") != strings.Join(have, ",") {
		t.Fatalf("resolve_fate orphaned reasons %v, preregistered %v", lit, have)
	}
}
