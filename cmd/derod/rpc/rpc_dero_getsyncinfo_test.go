package rpc

import "testing"

func TestClassifySync(t *testing.T) {
	for _, c := range []struct {
		peers  uint64
		lag    int64
		age    float64
		status string
	}{
		{0, 0, 5, "isolated"},
		{0, 500, 5000, "isolated"},      // no peers wins: nothing to compare against
		{18, 3, 10, "syncing"},          // just past the propagation slack
		{18, 2, 10, "synced"},           // at the slack
		{18, 83414, 1501560, "syncing"}, // 2026-10-20: 40 days behind while GetInfo said OK
		{18, 0, 301, "stalled"},         // no peer ahead, tip older than 300 s
		{18, 0, 300, "synced"},
		{18, -1, 20, "synced"}, // a slow peer reports below us
	} {
		if got, _ := classify_sync(c.peers, c.lag, c.age); got != c.status {
			t.Errorf("peers=%d lag=%d age=%.0f: got %s want %s", c.peers, c.lag, c.age, got, c.status)
		}
	}
}
