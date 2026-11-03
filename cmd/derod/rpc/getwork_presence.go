package rpc

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/deroproject/derohe/metrics"
	"github.com/lesismal/nbio/nbhttp/websocket"
)

// Round 20 forensics: derod logged nothing when a miner connected or left. On the r19 node (2026-10-27 05:48 ->
// 2026-10-28 08:32) the ledger showed 41 shares in 26.7 h, and only the job counter (getwork_jobs_sent_total ~305/h
// against ~11,300/h with one miner connected) and the miner's 60 s GetMiningOutcome polls (~42 in 26.7 h) showed that
// the miner had been connected for about 40 minutes in total. The node now logs the moments it gains its first miner
// and loses its last one, counts every connect and disconnect, and exports when the last share was accepted.
// The getwork port binds 0.0.0.0:10100 by default with no auth: while no miner is connected every attacker
// connect/close is a 0 -> 1 -> 0 transition, so the INFO lines are rate-limited (presence_log_allowed: at most one
// per event kind per PRESENCE_LOG_WINDOW, with the suppressed count on the next one); the rest go to V(1).

var getwork_connects = metrics.Set.NewCounter("getwork_connects_total")
var getwork_disconnects = metrics.Set.NewCounter("getwork_disconnects_total")

var getwork_last_share_unix int64 // unix seconds of the last share accepted from any miner, 0 = none since start

var _ = metrics.Set.NewGauge("getwork_last_share_timestamp_seconds", func() float64 {
	return float64(atomic.LoadInt64(&getwork_last_share_unix))
})

// presence_event names a change in how many miners are connected that is worth a log line: none -> some, some -> none.
func presence_event(before, after int) string {
	switch {
	case before == 0 && after > 0:
		return "first miner connected"
	case before > 0 && after == 0:
		return "last miner disconnected"
	}
	return ""
}

// getwork_register adds a session; it returns the presence event and the number of miners now connected.
func getwork_register(c *websocket.Conn, s *user_session) (string, int) {
	client_list_mutex.Lock()
	defer client_list_mutex.Unlock()
	before := len(client_list)
	client_list[c] = s
	atomic.StoreInt64(&getwork_session_count, int64(len(client_list)))
	getwork_connects.Inc()
	note_presence(len(client_list), time.Now()) // r23b: the absence clock (getwork_absence.go)
	return presence_event(before, len(client_list)), len(client_list)
}

// getwork_unregister removes a session; s is nil when c was not registered (an upgrade that never completed).
func getwork_unregister(c *websocket.Conn) (s *user_session, ev string, left int) {
	client_list_mutex.Lock()
	defer client_list_mutex.Unlock()
	before := len(client_list)
	s = client_list[c]
	delete(client_list, c)
	atomic.StoreInt64(&getwork_session_count, int64(len(client_list)))
	if s != nil {
		getwork_disconnects.Inc()
		note_presence(len(client_list), time.Now())
	}
	return s, presence_event(before, len(client_list)), len(client_list)
}

func note_share_accepted(now time.Time) { atomic.StoreInt64(&getwork_last_share_unix, now.Unix()) }

// PRESENCE_LOG_WINDOW bounds the presence INFO lines to 2 per window (one per event kind) whatever the connect rate.
const PRESENCE_LOG_WINDOW = 60 * time.Second

type presence_limiter struct {
	mu         sync.Mutex
	last       map[string]time.Time
	suppressed map[string]int
}

var presence_log = presence_limiter{last: map[string]time.Time{}, suppressed: map[string]int{}}

// allow reports whether event ev may be logged at INFO now and, if so, how many were suppressed since the last one.
func (p *presence_limiter) allow(ev string, now time.Time) (bool, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if last, ok := p.last[ev]; ok && now.Sub(last) < PRESENCE_LOG_WINDOW {
		p.suppressed[ev]++
		return false, 0
	}
	p.last[ev] = now
	n := p.suppressed[ev]
	p.suppressed[ev] = 0
	return true, n
}

// log_presence writes a presence event at INFO when the limiter allows it, else at V(1).
func log_presence(ev string, kv ...interface{}) {
	if ok, suppressed := presence_log.allow(ev, time.Now()); ok {
		logger_getwork.Info(ev, append(kv, "suppressed", suppressed)...)
	} else {
		logger_getwork.V(1).Info(ev, kv...)
	}
}
