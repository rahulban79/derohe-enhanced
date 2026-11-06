package rpc

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/deroproject/derohe/p2p"
)

// r27 (§7 sweep): GetSyncInfo carries the running bans and the ones reloaded at start next to p2p_bans_total (bans
// placed since start), so a reloaded ban is no longer invisible (live r26: 1 running, p2p_bans_total 0).
func TestR27SyncInfoBanFields(t *testing.T) {
	b, err := json.Marshal(GetSyncInfo_Result{Bans: 0, BansActive: 1, BansLoaded: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"p2p_bans_total":0`, `"p2p_bans_active":1`, `"p2p_bans_loaded_total":1`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("%s missing in %s", want, b)
		}
	}
}

// r27 verify: GetSyncInfo fills the two fields from the ban list (the JSON test above passes with the fill removed)
func TestR27SyncInfoBanFieldsFilled(t *testing.T) {
	_, _, done := r25_sim(t, 3)
	defer done()
	const addr = "192.0.2.190" // TEST-NET-1; the ban lives only in this process
	if err := p2p.Ban_Address(addr, 3600); err != nil {
		t.Fatal(err)
	}
	defer p2p.UnBan_Address(addr)
	r, err := GetSyncInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.BansActive == 0 || r.BansActive != p2p.Ban_Count() || r.BansLoaded != p2p.BansLoaded() {
		t.Fatalf("p2p_bans_active %d (ban count %d), p2p_bans_loaded_total %d (want %d)", r.BansActive, p2p.Ban_Count(), r.BansLoaded, p2p.BansLoaded())
	}
}
