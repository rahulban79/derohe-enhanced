package p2p

import (
	"net"
	"testing"
	"time"
)

// Round 18 forensics: KCP dial back-off. The gossip-validation half of the forensics patch was superseded by the
// security patch's diversity.go (peer_add_gossip); only the back-off fix and its tests are kept here.

func save_peer_map() func() {
	peer_mutex.Lock()
	old := peer_map
	peer_map = map[string]*Peer{}
	peer_mutex.Unlock()
	return func() {
		peer_mutex.Lock()
		peer_map = old
		peer_mutex.Unlock()
	}
}

func TestFailBackoffCapped(t *testing.T) {
	want := []uint64{0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 512, 512}
	for f, w := range want {
		if got := fail_backoff_seconds(uint64(f)); got != w {
			t.Fatalf("fail_backoff_seconds(%d)=%d want %d", f, got, w)
		}
	}
	if fail_backoff_seconds(70) != 512 {
		t.Fatal("no cap: 1<<69 overflow")
	}
}

func TestHandshakeFailureBacksOffAndPurgesGreyOnly(t *testing.T) {
	defer save_peer_map()()
	now := uint64(time.Now().Unix())
	peer_mutex.Lock()
	peer_map["45.1.1.1"] = &Peer{Address: "45.1.1.1:11011", LastConnected: now}                  // grey
	peer_map["45.2.2.2"] = &Peer{Address: "45.2.2.2:11011", LastConnected: now, Whitelist: true} // proven
	peer_mutex.Unlock()
	for _, a := range []string{"45.1.1.1:11011", "45.2.2.2:11011"} {
		addr, _ := net.ResolveUDPAddr("udp", a)
		c := &Connection{Addr: addr}
		for i := 0; i < 8; i++ {
			c.note_handshake_failure()
		}
	}
	p := GetPeerInList("45.2.2.2")
	if p == nil || p.FailCount != 8 || p.ConnectAfter < now+100 {
		t.Fatalf("whitelisted peer not backed off: %+v", p)
	}
	clean_up()
	if IsPeerInList("45.1.1.1:11011") {
		t.Fatal("grey peer with 8 handshake failures not purged")
	}
	if !IsPeerInList("45.2.2.2:11011") {
		t.Fatal("whitelisted peer purged by fail count; retention_seconds must decide")
	}
	// incoming connections never touch the dial back-off
	addr, _ := net.ResolveUDPAddr("udp", "45.2.2.2:11011")
	before := GetPeerInList("45.2.2.2").FailCount
	(&Connection{Addr: addr, Incoming: true}).note_handshake_failure()
	if GetPeerInList("45.2.2.2").FailCount != before {
		t.Fatal("incoming failure changed outgoing back-off")
	}
}
