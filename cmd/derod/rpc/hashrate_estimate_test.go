package rpc

import "testing"

func TestHashrateEstimateClipsToUptime(t *testing.T) {
	// 30 minutes up, 10 finds: the 7-day window must not divide 30 minutes of finds by 7 days
	week := hashrate_estimate_percent(10, 7*86400, 1800)
	half := hashrate_estimate_percent(10, 1800, 1800)
	if week != half || week <= 0 {
		t.Fatalf("7-day estimate %.4f%% after 30 min of uptime, want the 30-min figure %.4f%%", week, half)
	}
	// 1800 s / 18 s * 10 paid miniblocks = 1000 slots; 10 finds = 1%
	if half < 0.999 || half > 1.001 {
		t.Fatalf("10 of 1000 miniblock slots = %.4f%%, want 1%%", half)
	}
	if hashrate_estimate_percent(5, 3600, 0) != 0 {
		t.Fatal("zero uptime must give 0, not a division by zero")
	}
}
