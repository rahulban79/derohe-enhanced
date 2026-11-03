package rpc

import (
	"strings"
	"testing"
)

// r22 (security dim): DERO.WatchTx's id parser and the foreign-socket cost table take attacker-chosen strings from
// any websocket client. parse_watch_ids must never panic, must return only non-zero distinct ids, at most
// WATCH_MAX_PER_SOCKET of them, and foreign_cost must charge every method at least one token.
func FuzzWatchTxParams(f *testing.F) {
	f.Add(strings.Repeat("ab", 32)+","+strings.Repeat("00", 32), int64(0), "DERO.WatchTx")
	f.Add(strings.Repeat("zz", 32), int64(-1), "")
	f.Add(strings.Repeat(","+strings.Repeat("1", 64), 70), int64(129), "DERO.GetBlockHeadersRange")
	f.Fuzz(func(t *testing.T, ids string, conf int64, method string) {
		list := strings.Split(ids, ",")
		out, err := parse_watch_ids(list)
		if err == nil {
			if len(out) == 0 || len(out) > WATCH_MAX_PER_SOCKET || len(list) > WATCH_MAX_PER_SOCKET {
				t.Fatalf("accepted %d ids from %d", len(out), len(list))
			}
			seen := map[string]bool{}
			for _, h := range out {
				if h.IsZero() || seen[h.String()] {
					t.Fatalf("zero or repeated id %s", h)
				}
				seen[h.String()] = true
			}
		}
		if tgt, err := watch_target(conf); err == nil && (tgt < 1 || tgt > WATCH_MAX_CONFIRMATIONS) {
			t.Fatalf("confirmations %d -> target %d", conf, tgt)
		}
		if foreign_cost(method) < 1 {
			t.Fatalf("method %q is free for foreign sockets", method)
		}
	})
}
