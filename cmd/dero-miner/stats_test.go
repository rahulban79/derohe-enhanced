package main

import "testing"

func TestSessionCounterSurvivesReconnect(t *testing.T) {
	var s session_counter
	var got uint64
	for _, v := range []uint64{0, 3, 4, 0, 1} { // 4 found, reconnect, 1 more
		got = s.observe(v)
	}
	if got != 5 {
		t.Fatalf("total %d across a reconnect, want 5", got)
	}
}

func TestNWFromJob(t *testing.T) {
	if got := nw_from_job("51ab", 27_000_000); got != 3_000_000 { // 0x51 = PastCount 1 | HighDiff | version 1
		t.Fatalf("final job: %d, want D = 3000000", got)
	}
	if got := nw_from_job("01ab", 3_000_000); got != 3_000_000 {
		t.Fatalf("normal job: %d, want 3000000", got)
	}
	if got := nw_from_job("zz", 5); got != 5 {
		t.Fatalf("undecodable blob: %d, want the difficulty unchanged", got)
	}
}

func TestBenchDoesNotTouchTheLiveLog(t *testing.T) {
	if got := log_path("/x/dero-miner", []string{"--bench", "--mining-threads=2"}); got != "/x/dero-miner.bench.log" {
		t.Fatalf("bench log %q would truncate the live miner's log", got)
	}
	if got := log_path("/x/dero-miner", []string{"--wallet-address=a"}); got != "/x/dero-miner.log" {
		t.Fatalf("mining log %q", got)
	}
}
