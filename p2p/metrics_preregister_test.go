package p2p

import (
	"bytes"
	"strings"
	"testing"

	"github.com/deroproject/derohe/metrics"
)

func TestLazyP2PCountersVisibleAtZero(t *testing.T) {
	var buf bytes.Buffer
	metrics.Set.WritePrometheus(&buf)
	page := buf.String()
	for _, name := range append(preregistered_p2p_counters, "p2p_grey_quarantined_total", "p2p_tx_inv_known_skipped_total", "p2p_peer_lagging_count") {
		if !strings.Contains(page, name+" ") {
			t.Errorf("%s missing from /metrics before its first event", name)
		}
	}
}

func TestLaggingPeerCount(t *testing.T) {
	ok, edge, behind, pending := known_conn(1, 1000), known_conn(2, 1000-LAGGING_PEER_BLOCKS), known_conn(3, 100), known_conn(4, 0)
	pending.State.Store(HANDSHAKE_PENDING)
	if n := lagging_peer_count([]*Connection{ok, edge, behind, pending}, 1000); n != 1 {
		t.Fatalf("lagging = %d, want 1 (only the peer beyond the relay window; pending ignored)", n)
	}
	if n := lagging_peer_count([]*Connection{known_conn(5, 7472150), known_conn(6, 7537830), known_conn(7, 7823636)}, 7823636); n != 2 {
		t.Fatalf("live r20 shape: lagging = %d, want 2", n)
	}
}
