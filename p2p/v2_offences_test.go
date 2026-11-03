package p2p

import "os"
import "path/filepath"
import "testing"

// the escalation survives a restart: offences recorded, saved, the map wiped (a new process), loaded back
func TestV2OffencesSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), V2_OFFENCES_FILE)
	ip := "198.51.100.90"
	now := int64(1_800_000_000)
	penalty_mu.Lock()
	v2_offences = map[string]v2_record{}
	penalty_mu.Unlock()

	if got := v2_ban_seconds_at(ip, now); got != 3600 {
		t.Fatalf("first drop %d", got)
	}
	if got := v2_ban_seconds_at(ip, now+3700); got != 7200 {
		t.Fatalf("second drop %d", got)
	}
	if err := save_v2_offences_to(path, now+3700); err != nil {
		t.Fatal(err)
	}

	penalty_mu.Lock()
	v2_offences = map[string]v2_record{} // the restart
	penalty_mu.Unlock()
	if n := load_v2_offences_from(path, now+7400); n != 1 {
		t.Fatalf("loaded %d entries, want 1", n)
	}
	// the live case of 2026-10-23: third drop after a restart must be 4 h, not 1 h again
	if got := v2_ban_seconds_at(ip, now+11000); got != 14400 {
		t.Fatalf("third drop after restart: ban %d s, want 14400", got)
	}
}

// a week without a drop forgets the peer, both in memory and on load
func TestV2OffencesForgetAfterAWeek(t *testing.T) {
	path := filepath.Join(t.TempDir(), V2_OFFENCES_FILE)
	ip := "198.51.100.91"
	now := int64(1_800_000_000)
	penalty_mu.Lock()
	v2_offences = map[string]v2_record{}
	penalty_mu.Unlock()
	for i := 0; i < 4; i++ {
		v2_ban_seconds_at(ip, now)
	}
	if got := v2_ban_seconds_at(ip, now+V2_FORGET+1); got != V2_BAN_BASE {
		t.Fatalf("drop after a quiet week: %d s, want %d", got, V2_BAN_BASE)
	}
	if err := save_v2_offences_to(path, now+V2_FORGET+1); err != nil {
		t.Fatal(err)
	}
	penalty_mu.Lock()
	v2_offences = map[string]v2_record{}
	penalty_mu.Unlock()
	if n := load_v2_offences_from(path, now+3*V2_FORGET); n != 0 {
		t.Fatalf("a stale file loaded %d entries", n)
	}
}

// a missing or corrupt file changes nothing and does not panic; a larger in-memory count is kept
func TestV2OffencesBadFile(t *testing.T) {
	dir := t.TempDir()
	now := int64(1_800_000_000)
	penalty_mu.Lock()
	v2_offences = map[string]v2_record{"198.51.100.92": {N: 3, Last: now}}
	penalty_mu.Unlock()
	if n := load_v2_offences_from(filepath.Join(dir, "missing.json"), now); n != 0 {
		t.Fatalf("missing file loaded %d", n)
	}
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte("{not json"), 0600)
	if n := load_v2_offences_from(bad, now); n != 0 {
		t.Fatalf("corrupt file loaded %d", n)
	}
	lower := filepath.Join(dir, "lower.json")
	os.WriteFile(lower, []byte(`{"198.51.100.92":{"n":1,"last":1800000000},"198.51.100.93":{"n":2,"last":9999999999}}`), 0600)
	if n := load_v2_offences_from(lower, now); n != 0 { // lower count ignored, future timestamp rejected
		t.Fatalf("loaded %d", n)
	}
	if r := v2_offences["198.51.100.92"]; r.N != 3 {
		t.Fatalf("in-memory count overwritten: %+v", r)
	}
}
