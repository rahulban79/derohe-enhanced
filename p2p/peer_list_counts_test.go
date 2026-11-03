package p2p

import "testing"

func TestPeerListCounts(t *testing.T) {
	peer_mutex.Lock()
	saved := peer_map
	peer_map = map[string]*Peer{
		"203.0.113.1": {Address: "203.0.113.1:11011", Whitelist: true},
		"203.0.113.2": {Address: "203.0.113.2:11011", Whitelist: true},
		"203.0.113.3": {Address: "203.0.113.3:11011"},
	}
	peer_mutex.Unlock()
	defer func() { peer_mutex.Lock(); peer_map = saved; peer_mutex.Unlock() }()

	white, grey := Peer_List_Counts()
	if white != 2 || grey != 1 {
		t.Fatalf("white %d grey %d, want 2 and 1", white, grey)
	}
	if white+grey != Peer_Counts() {
		t.Fatalf("white+grey %d != Peer_Counts %d", white+grey, Peer_Counts())
	}
}
