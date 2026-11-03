package p2p

// Own-miniblock delivery tracker (r17, observability only; no consensus or wire change).
//
// A normal miniblock is paid only if it reaches the node that builds the block before the builder's 9 normal slots
// fill (block/miniblockdag.go appends in arrival order; blockchain/miner_block.go takes GetAllMiniBlocks(key)[:9]).
// The r16 audit showed both orphans lost that race by under a second, yet broadcast_MiniBlock logged nothing, so the
// delivery time of OUR share to peers was unmeasurable. Peer.NotifyMiniBlock returns only after the peer has verified
// and inserted the miniblock (p2p/rpc_notifications.go), so the reply time is when that peer holds our share.

import "context"
import "errors"
import "sort"
import "strings"
import "sync"
import "time"

import "github.com/deroproject/derohe/metrics"

type ack_summary struct {
	Peers  int           // NotifyMiniBlock calls launched
	Acked  int           // calls that returned without error
	Failed int           // calls that errored or timed out
	First  time.Duration // fastest successful ack
	Median time.Duration // median successful ack
	Last   time.Duration // slowest successful ack
	// Reasons splits Failed (r18). Live r17 showed 37 of 420 own sends (8.8%) "failed" with no p2p_call_timeouts at
	// all, i.e. the peers ANSWERED with an error, and the cause was never recorded.
	Reasons map[string]int
}

// failure_reason classifies a NotifyMiniBlock error for our own share. The common benign case is "duplicate": the
// peer verified our miniblock while the same miniblock reached it through another peer's relay, so its
// InsertMiniBlock reported a collision (block/miniblockdag.go). That peer HOLDS our share; it is not a lost delivery.
func failure_reason(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	m := err.Error()
	switch {
	case strings.Contains(m, "collision"):
		return "duplicate"
	case strings.Contains(m, "no answer within"):
		return "timeout"
	case strings.Contains(m, "tip could not be expanded"), strings.Contains(m, "Stale Miniblock"):
		return "peer_behind"
	case strings.Contains(m, "unregistered miner"), strings.Contains(m, "Invalid miner address"):
		return "peer_unregistered"
	case strings.Contains(m, "shut down"), strings.Contains(m, "closed"), strings.Contains(m, "EOF"):
		return "connection"
	}
	return "other"
}

// summarize_acks is pure so the arithmetic is unit-tested.
func summarize_acks(peers int, ok []time.Duration, failed int) (s ack_summary) {
	s.Peers, s.Acked, s.Failed = peers, len(ok), failed
	s.Reasons = map[string]int{}
	if len(ok) == 0 {
		return
	}
	d := append([]time.Duration(nil), ok...)
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	s.First, s.Median, s.Last = d[0], d[len(d)/2], d[len(d)-1]
	return
}

type own_ack_tracker struct {
	sync.Mutex
	start    time.Time
	expected int // -1 until the dispatch loop has finished launching
	ok       []time.Duration
	failed   int
	reasons  map[string]int
	report   func(ack_summary)
	reported bool
}

func new_own_ack_tracker(start time.Time, report func(ack_summary)) *own_ack_tracker {
	return &own_ack_tracker{start: start, expected: -1, report: report}
}

// done is called by each per-peer goroutine when its call returns.
func (t *own_ack_tracker) done(err error, now time.Time) {
	t.Lock()
	defer t.Unlock()
	if err != nil {
		t.failed++
		if t.reasons == nil {
			t.reasons = map[string]int{}
		}
		t.reasons[failure_reason(err)]++
	} else {
		t.ok = append(t.ok, now.Sub(t.start))
	}
	t.maybe_report()
}

// launched is called once, after the loop, with the number of calls started (acks may already have arrived).
func (t *own_ack_tracker) launched(n int) {
	t.Lock()
	defer t.Unlock()
	t.expected = n
	t.maybe_report()
}

func (t *own_ack_tracker) maybe_report() {
	if t.reported || t.expected < 0 || len(t.ok)+t.failed < t.expected {
		return
	}
	t.reported = true
	if t.report != nil {
		s := summarize_acks(t.expected, t.ok, t.failed)
		for k, v := range t.reasons {
			s.Reasons[k] = v
		}
		t.report(s)
	}
}

func report_own_miniblock_broadcast(height uint64, s ack_summary) {
	metrics.Set.GetOrCreateCounter("miniblock_ours_broadcast_peers_total").Add(s.Peers)
	metrics.Set.GetOrCreateCounter("miniblock_ours_broadcast_failed_total").Add(s.Failed)
	for reason, n := range s.Reasons {
		metrics.Set.GetOrCreateCounter(`miniblock_ours_broadcast_failed_by_reason_total{reason="` + reason + `"}`).Add(n)
	}
	if s.Acked > 0 {
		metrics.Set.GetOrCreateHistogram("miniblock_ours_first_ack_seconds").Update(s.First.Seconds())
		metrics.Set.GetOrCreateHistogram("miniblock_ours_median_ack_seconds").Update(s.Median.Seconds())
		metrics.Set.GetOrCreateHistogram("miniblock_ours_last_ack_seconds").Update(s.Last.Seconds())
	}
	logger.V(1).Info("Own miniblock delivered", "height", height, "peers", s.Peers, "acked", s.Acked, "failed", s.Failed,
		"first_ms", s.First.Milliseconds(), "median_ms", s.Median.Milliseconds(), "last_ms", s.Last.Milliseconds(),
		"failed_by_reason", s.Reasons)
}
