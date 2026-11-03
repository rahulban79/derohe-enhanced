package rpc

import (
	"strings"
	"testing"
	"time"

	"github.com/deroproject/derohe/block"
)

func TestResolveFate(t *testing.T) {
	blocks := []fate_block{
		{id: "main", main: true, minis: []string{"a", "b"}},
		{id: "side", main: false, minis: []string{"c"}},
	}
	for _, c := range []struct{ hash, fate, reason, blid string }{
		{"a", "paid", "", "main"},
		{"c", "orphaned", "not_included", ""}, // only main-chain blocks pay
		{"z", "orphaned", "not_included", ""},
	} {
		f, r, b := resolve_fate(c.hash, false, blocks)
		if f != c.fate || r != c.reason || b != c.blid {
			t.Errorf("%s: got %s/%s/%s want %s/%s/%s", c.hash, f, r, b, c.fate, c.reason, c.blid)
		}
	}
}

// the r16 orphans: the main block at the height carried 9 regular miniblocks + the final, none of them ours
func TestResolveFateSlotsFull(t *testing.T) {
	full := []fate_block{{id: "main", main: true, minis: []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "f"}, regular: 9}}
	if f, r, _ := resolve_fate("ours", false, full); f != "orphaned" || r != "slots_full" {
		t.Fatalf("full block: %s/%s, want orphaned/slots_full", f, r)
	}
	if f, r, b := resolve_fate("5", false, full); f != "paid" || r != "" || b != "main" {
		t.Fatalf("a carried miniblock in a full block: %s/%s/%s", f, r, b)
	}
	short := []fate_block{{id: "main", main: true, minis: []string{"1", "f"}, regular: 1}, {id: "side", main: false, regular: 9}}
	if _, r, _ := resolve_fate("ours", false, short); r != "not_included" {
		t.Fatalf("a block with free slots (and a full SIDE block): reason %s, want not_included", r)
	}
}

func TestShouldHoldJobs(t *testing.T) {
	for _, c := range []struct {
		peers uint64
		lag   int64
		want  bool
	}{
		{18, 3, true},    // behind the median of enough peers
		{18, 2, false},   // within the propagation slack
		{2, 50, false},   // too few peers to trust the median
		{18, -4, false},  // ahead of the peers
		{18, 5100, true}, // the 2026-08 restart: ~5,100 blocks behind
	} {
		if got := should_hold_jobs(c.peers, c.lag); got != c.want {
			t.Errorf("peers=%d lag=%d: got %v want %v", c.peers, c.lag, got, c.want)
		}
	}
}

func TestReachability(t *testing.T) {
	if r := reachability(0, 0, 10*time.Minute); r[:7] != "unknown" {
		t.Errorf("short uptime: %s", r)
	}
	if r := reachability(0, 0, 2*time.Hour); r[:11] != "unreachable" {
		t.Errorf("no inbound in 2 h: %s", r)
	}
	if r := reachability(3, 3, time.Minute); r[:9] != "reachable" {
		t.Errorf("inbound seen: %s", r)
	}
	// 2026-10-23: two local shadow nodes connected in, no public peer did -> must NOT say reachable
	if r := reachability(0, 2, 2*time.Hour); !strings.HasPrefix(r, "unreachable from the internet") {
		t.Errorf("local-only inbound: %s", r)
	}
}

func TestRecordSubmissionAndOutcome(t *testing.T) {
	fate_mu.Lock()
	fates = nil
	fate_mu.Unlock()
	mbl := block.MiniBlock{Version: 1, PastCount: 1, Height: 7795123} // a miniblock must name at least one tip
	record_submission(mbl.Serialize())
	record_submission([]byte{1, 2}) // an undecodable blob is ignored
	r, err := GetMiningOutcome(nil)
	if err != nil || r.Submitted != 1 || r.Pending != 1 || r.Recent[0].Height != 7795123 || r.Recent[0].Hash != mbl.GetHash().String() {
		t.Fatalf("outcome %+v err %v", r, err)
	}
}

func TestSubmittedMsMatchesSeconds(t *testing.T) {
	fate_mu.Lock()
	fates = nil
	fate_mu.Unlock()
	var mbl block.MiniBlock
	mbl.Version, mbl.Height, mbl.PastCount = 1, 7799270, 1
	record_submission(mbl.Serialize())
	fate_mu.Lock()
	f := fates[len(fates)-1]
	fate_mu.Unlock()
	if f.SubmittedMs/1000 != f.Submitted || f.SubmittedMs <= 0 {
		t.Fatalf("submitted_unix_ms %d must be the same instant as submitted_unix %d", f.SubmittedMs, f.Submitted)
	}
}

// r18 height 7806145 (2026-10-24): our FINAL miniblock built block b1b34c8a, which lost to 1e3ceffc (lower block id)
// at the same height. The main block carried 9 regular miniblocks, so the old rule called it "slots_full".
func TestResolveFateFinalLostIsBlockRace(t *testing.T) {
	full := []fate_block{{id: "1e3ceffc", main: true, minis: []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "theirs"}, regular: 9}}
	if f, r, _ := resolve_fate("ours_final", true, full); f != "orphaned" || r != "block_race" {
		t.Fatalf("lost final: %s/%s, want orphaned/block_race", f, r)
	}
	won := []fate_block{{id: "b1b34c8a", main: true, minis: []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "ours_final"}, regular: 9}}
	if f, r, b := resolve_fate("ours_final", true, won); f != "paid" || r != "" || b != "b1b34c8a" {
		t.Fatalf("won final: %s/%s/%s, want paid", f, r, b)
	}
	if f, r, _ := resolve_fate("ours_regular", false, full); f != "orphaned" || r != "slots_full" {
		t.Fatalf("regular share in a full block: %s/%s, want orphaned/slots_full", f, r)
	}
}

func TestRecordSubmissionKeepsFinalAndBuilt(t *testing.T) {
	fate_mu.Lock()
	saved := fates
	fates = nil
	fate_mu.Unlock()
	defer func() { fate_mu.Lock(); fates = saved; fate_mu.Unlock() }()
	var mbl block.MiniBlock
	mbl.Version = 1
	mbl.Final = true
	mbl.HighDiff = true
	mbl.Height = 7806145
	mbl.PastCount = 1
	record_submission_built(mbl.Serialize(), "b1b34c8a")
	fate_mu.Lock()
	defer fate_mu.Unlock()
	if len(fates) != 1 || !fates[0].Final || fates[0].Built != "b1b34c8a" {
		t.Fatalf("final submission not recorded as final/built: %+v", fates)
	}
}
