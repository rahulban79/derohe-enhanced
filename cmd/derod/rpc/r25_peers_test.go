package rpc

// r25 (peers, CO24-N1/N4/N7): DERO.GetPeerInfo carries the offence records, the ban list with sources and the stuck
// holds, bounded. Documentation addresses only (RFC 5737).

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/deroproject/derohe/p2p"
)

func TestR25GetPeerInfoObservatoryLists(t *testing.T) {
	now := time.Now()
	for i := 0; i < MAX_PEER_BANS+6; i++ {
		p2p.Ban_Address_Reason(fmt.Sprintf("198.51.100.%d", 100+i), 600, p2p.BAN_SOURCE_OPERATOR, "console")
	}
	defer func() {
		for i := 0; i < MAX_PEER_BANS+6; i++ {
			p2p.UnBan_Address(fmt.Sprintf("198.51.100.%d", 100+i))
		}
	}()
	var r GetPeerInfo_Result
	fill_peer_observatory(&r, now)
	if len(r.Bans) != MAX_PEER_BANS || r.BanCount < MAX_PEER_BANS+6 || r.BanSources[p2p.BAN_SOURCE_OPERATOR] < MAX_PEER_BANS+6 {
		t.Fatalf("bans %d count %d sources %v", len(r.Bans), r.BanCount, r.BanSources)
	}
	if r.Bans[0].Source != p2p.BAN_SOURCE_OPERATOR || r.Bans[0].Reason != "console" || r.Bans[0].Remaining < 590 {
		t.Fatalf("entry %+v", r.Bans[0])
	}
	if r.Offenders == nil || r.StuckHeld == nil {
		t.Fatal("empty lists must be [] not null (absent is not zero)")
	}
	b, _ := json.Marshal(r)
	for _, k := range []string{`"offenders":[`, `"bans":[`, `"ban_count":`, `"ban_sources":{`, `"stuck_held":[`} {
		if !strings.Contains(string(b), k) {
			t.Fatalf("%s missing", k)
		}
	}
	raw, err := os.ReadFile("rpc_dero_explorer.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	if i, j := strings.Index(src, "fill_peer_observatory(&result, time.Now())"), strings.Index(src, "result.Peers = p2p.PeerInfos(MAX_PEER_INFO)"); i < 0 || j < 0 || i < j {
		t.Fatal("GetPeerInfo does not fill the r25 lists")
	}
}
