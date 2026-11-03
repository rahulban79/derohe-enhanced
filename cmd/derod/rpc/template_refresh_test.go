package rpc

import "testing"

func TestRefreshDue(t *testing.T) {
	cases := []struct{ tmpl, trig, want int64 }{
		{1000, 1000, 1101}, // same millisecond: may be the pre-miniblock cache, so resend once it expires
		{1001, 1000, 0},    // timestamp bumped past a future tip (miner_block.go:310)
		{999, 1000, 1100},  // cached 1 ms before the trigger: resend once the cache expires
		{950, 1040, 1051},  // cached 90 ms before
		{900, 1000, 1001},  // 100 ms old: the cache has just expired (now > tmpl+100)
	}
	for _, c := range cases {
		if got := refresh_due(c.tmpl, c.trig); got != c.want {
			t.Fatalf("refresh_due(%d,%d)=%d want %d", c.tmpl, c.trig, got, c.want)
		}
	}
}
