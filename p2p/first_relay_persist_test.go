package p2p

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// r18: first_relay.json was written but never read, so a restart emptied the builder-adjacency ranking.
func TestFirstRelayPersistRoundTrip(t *testing.T) {
	defer reset_first_relay()()
	now := time.Unix(1792850000, 0)
	first_relay.Peers, first_relay.Blocks = map[string]*RelayStat{}, 0
	for i := 0; i < 7; i++ {
		first_relay.record("203.0.113.161", "203.0.113.161:11011", []byte{0x2d, 0xa7, 0xf0, 0x63, 0xca, 0xa4, 0x63, 0xcd}, 131000, now)
	}
	first_relay.record("203.0.113.162", "203.0.113.162:11011", nil, 351000, now)
	path := filepath.Join(t.TempDir(), FIRST_RELAY_FILE)
	if err := save_first_relay_to(path); err != nil {
		t.Fatal(err)
	}
	first_relay.Peers, first_relay.Blocks = map[string]*RelayStat{}, 0 // a restart
	if got := first_relay.top(FIRST_RELAY_STICKY, FIRST_RELAY_MIN_FIRSTS); len(got) != 0 {
		t.Fatalf("fresh table must be empty, got %v", got)
	}
	if n := load_first_relay_from(path, now.Unix()+60); n != 2 {
		t.Fatalf("loaded %d entries, want 2", n)
	}
	top := first_relay.top(FIRST_RELAY_STICKY, FIRST_RELAY_MIN_FIRSTS)
	if len(top) != 1 || top[0] != "203.0.113.161:11011" {
		t.Fatalf("sticky set after restart = %v, want [203.0.113.161:11011]", top)
	}
	if first_relay.score("203.0.113.161") != 7 || first_relay.Blocks != 8 {
		t.Fatalf("score/blocks not restored: %d %d", first_relay.score("203.0.113.161"), first_relay.Blocks)
	}
	if first_relay.Peers["203.0.113.161"].Builders["2da7f063caa463cd"] != 7 {
		t.Fatalf("builders map not restored: %v", first_relay.Peers["203.0.113.161"].Builders)
	}
}

func TestFirstRelayLoadRejectsStaleAndGarbage(t *testing.T) {
	defer reset_first_relay()()
	first_relay.Peers, first_relay.Blocks = map[string]*RelayStat{}, 0
	now := int64(1792850000)
	path := filepath.Join(t.TempDir(), FIRST_RELAY_FILE)
	body := `{"peers":{
	  "1.2.3.4":{"address":"1.2.3.4:11011","firsts":9,"last_first":` + itoa(now-FIRST_RELAY_FORGET-1) + `},
	  "not-an-ip":{"address":"x:1","firsts":9,"last_first":` + itoa(now) + `},
	  "5.6.7.8":{"address":"5.6.7.8:11011","firsts":0,"last_first":` + itoa(now) + `},
	  "9.9.9.9":{"address":"9.9.9.9:11011","firsts":6,"last_first":` + itoa(now+3*86400) + `},
	  "8.8.4.4":{"address":"8.8.4.4:11011","firsts":6,"last_first":` + itoa(now-10) + `}
	},"blocks":40}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if n := load_first_relay_from(path, now); n != 1 {
		t.Fatalf("loaded %d, want only 8.8.4.4", n)
	}
	if first_relay.Peers["8.8.4.4"] == nil || first_relay.Peers["8.8.4.4"].Builders == nil {
		t.Fatal("valid entry missing or nil Builders map (record() would panic on it)")
	}
	if n := load_first_relay_from(filepath.Join(t.TempDir(), "missing.json"), now); n != 0 {
		t.Fatal("missing file must load nothing")
	}
}

func itoa(v int64) string { return formatInt(v) }

func formatInt(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// reset_first_relay empties the global table and returns a func restoring the previous contents (no lock copy).
func reset_first_relay() func() {
	first_relay.Lock()
	peers, blocks := first_relay.Peers, first_relay.Blocks
	first_relay.Peers, first_relay.Blocks = map[string]*RelayStat{}, 0
	first_relay.Unlock()
	return func() {
		first_relay.Lock()
		first_relay.Peers, first_relay.Blocks = peers, blocks
		first_relay.Unlock()
	}
}
