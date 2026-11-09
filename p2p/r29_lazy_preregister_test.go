package p2p

// r29 (live-observability, dero-rft §7 B152): the p2p families that existed only after their first event are created
// at start, and their label lists are the closed sets of their call sites (so a new literal fails this test).

import (
	"bytes"
	"errors"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/deroproject/derohe/metrics"
)

func TestR29LazyP2PFamiliesVisibleAtZero(t *testing.T) {
	var buf bytes.Buffer
	metrics.Set.WritePrometheus(&buf)
	page := buf.String()
	for _, name := range []string{
		"miniblock_ours_broadcast_peers_total", "p2p_bootstrap_wait_seconds_total", "p2p_bootstrap_process_seconds_total",
		`p2p_busy_rejections_total{method="Peer.Chain"}`, `p2p_busy_rejections_total{method="Peer.GetObject"}`,
		`miniblock_ours_broadcast_failed_by_reason_total{reason="timeout"}`,
		`miniblock_ours_broadcast_failed_by_reason_total{reason="other"}`,
	} {
		if !strings.Contains(page, name+" ") {
			t.Errorf("%s missing from /metrics before its first event", name)
		}
	}
}

// the heavy() method literals of controller.go are exactly busy_methods
func TestR29BusyMethodsAreTheHeavyCallSites(t *testing.T) {
	src, err := os.ReadFile("controller.go")
	if err != nil {
		t.Fatal(err)
	}
	var lit []string
	for _, m := range regexp.MustCompile(`heavy\(c, "([^"]+)"`).FindAllStringSubmatch(string(src), -1) {
		lit = append(lit, m[1])
	}
	have := append([]string(nil), busy_methods...)
	sort.Strings(lit)
	sort.Strings(have)
	if strings.Join(lit, ",") != strings.Join(have, ",") || len(lit) == 0 {
		t.Fatalf("heavy() call sites %v, busy_methods %v", lit, have)
	}
}

// every value failure_reason can return for a non-nil error is in broadcast_fail_reasons, and every listed one occurs
func TestR29BroadcastFailReasonsClosedSet(t *testing.T) {
	got := map[string]bool{}
	for _, e := range []error{errors.New("collision 1"), errors.New("no answer within 3s"), errors.New("tip could not be expanded"),
		errors.New("Stale Miniblock"), errors.New("unregistered miner"), errors.New("Invalid miner address"),
		errors.New("shut down"), errors.New("closed"), errors.New("EOF"), errors.New("anything else")} {
		got[failure_reason(e)] = true
	}
	want := map[string]bool{}
	for _, r := range broadcast_fail_reasons {
		want[r] = true
	}
	for r := range got {
		if !want[r] {
			t.Fatalf("failure_reason %q not preregistered", r)
		}
	}
	for r := range want {
		if !got[r] {
			t.Fatalf("preregistered reason %q is never returned", r)
		}
	}
	src, _ := os.ReadFile("own_broadcast.go")
	body := string(src)
	if i := strings.Index(body, "func failure_reason"); i >= 0 {
		body = body[i:]
		body = body[:strings.Index(body, "\n}\n")]
	}
	n := len(regexp.MustCompile(`return "[a-z_]+"`).FindAllString(body, -1))
	if n != 7 { // 6 distinct reasons; "timeout" is returned twice
		t.Fatalf("failure_reason has %d return literals, the reason list was derived from 7", n)
	}
}
