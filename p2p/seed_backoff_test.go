package p2p

import (
	"net"
	"testing"
	"time"
)

func reset_unlisted() func() {
	unlisted_mu.Lock()
	saved := unlisted_fail
	unlisted_fail = map[string]*unlisted_backoff{}
	unlisted_mu.Unlock()
	return func() { unlisted_mu.Lock(); unlisted_fail = saved; unlisted_mu.Unlock() }
}

// live r18: 548 handshake failures in 2,161 s, from seeds that are not in the peer list (Peer_SetFail no-op).
func TestUnlistedSeedHandshakeFailureBacksOff(t *testing.T) {
	defer save_peer_map()()
	defer reset_unlisted()()
	seed := "203.0.113.11:11011" // a config.Mainnet_seed_nodes entry absent from the live peers.json
	if !seed_should_dial(seed, time.Now()) {
		t.Fatal("a fresh seed must be dialable")
	}
	addr, _ := net.ResolveUDPAddr("udp", seed)
	c := &Connection{Addr: addr}
	for i := 0; i < 10; i++ {
		c.note_handshake_failure()
	}
	now := time.Now()
	if seed_should_dial(seed, now) {
		t.Fatal("unlisted seed redialled right after 10 failed handshakes")
	}
	if seed_should_dial(seed, now.Add(500*time.Second)) {
		t.Fatal("back-off after 10 failures must be 512 s")
	}
	if !seed_should_dial(seed, now.Add(513*time.Second)) {
		t.Fatal("back-off must be capped at 512 s so a seed that comes back is found again")
	}
	note_unlisted_success("203.0.113.11")
	if !seed_should_dial(seed, now) {
		t.Fatal("a successful handshake must clear the back-off")
	}
	if seed_should_dial("", now) {
		t.Fatal("empty endpoint dialled")
	}
}

func TestListedPeerFailureUsesPeerListNotUnlisted(t *testing.T) {
	defer save_peer_map()()
	defer reset_unlisted()()
	peer_mutex.Lock()
	peer_map["45.3.3.3"] = &Peer{Address: "45.3.3.3:11011", LastConnected: uint64(time.Now().Unix()), Whitelist: true}
	peer_mutex.Unlock()
	addr, _ := net.ResolveUDPAddr("udp", "45.3.3.3:11011")
	(&Connection{Addr: addr}).note_handshake_failure()
	if GetPeerInList("45.3.3.3").FailCount != 1 {
		t.Fatal("listed peer failure not counted in the peer list")
	}
	unlisted_mu.Lock()
	n := len(unlisted_fail)
	unlisted_mu.Unlock()
	if n != 0 {
		t.Fatalf("listed peer leaked into the unlisted back-off map (%d entries)", n)
	}
	(&Connection{Addr: addr, Incoming: true}).note_handshake_failure()
	unlisted_mu.Lock()
	n = len(unlisted_fail)
	unlisted_mu.Unlock()
	if n != 0 {
		t.Fatal("incoming failure touched the dial back-off")
	}
}

func TestUnlistedBackoffBounded(t *testing.T) {
	defer reset_unlisted()()
	now := time.Now()
	for i := 0; i < MAX_UNLISTED_BACKOFF_ENTRIES+50; i++ {
		note_unlisted_failure(net.IPv4(46, byte(i>>8), byte(i), 1).String(), now)
	}
	unlisted_mu.Lock()
	n := len(unlisted_fail)
	unlisted_mu.Unlock()
	if n > MAX_UNLISTED_BACKOFF_ENTRIES {
		t.Fatalf("unlisted back-off map grew to %d", n)
	}
	// expired entries make room again
	note_unlisted_failure("47.0.0.1", now.Add(10*time.Minute))
	if unlisted_dial_allowed("47.0.0.1", now.Add(10*time.Minute)) {
		t.Fatal("new entry not recorded after expired ones were evicted")
	}
}

// the success path of dispatch_test_handshake (handshake_accepted) clears the unlisted back-off (verifier F3)
func TestHandshakeAcceptedClearsUnlistedBackoff(t *testing.T) {
	defer reset_unlisted()()
	seed := "51.222.86.52:11011"
	addr, _ := net.ResolveUDPAddr("udp", seed)
	c := &Connection{Addr: addr}
	now := time.Now()
	note_unlisted_failure(Address(c), now)
	if seed_should_dial(seed, now) {
		t.Fatal("failure not recorded")
	}
	c.handshake_accepted(&Handshake_Struct{DaemonVersion: "3.6.0-153", Local_Port: 11011, Peer_ID: 7, Pruned: 5})
	if !seed_should_dial(seed, now) {
		t.Fatal("a successful handshake left the seed backed off")
	}
	if c.Port != 11011 || c.Peer_ID != 7 || c.Pruned != 5 || c.DaemonVersion != "3.6.0-153" {
		t.Fatalf("handshake fields not copied: %+v", c)
	}
}

// r20: the sticky first-relay loop redialled a stale ranked address every 12 s, ignoring both back-offs
func TestRelayDialHonoursBackoff(t *testing.T) {
	defer save_peer_map()()
	defer reset_unlisted()()
	now := time.Now()

	stale := "203.0.113.23:42151" // not in the peer list: the unlisted back-off applies
	if !relay_dial_allowed(stale, now) {
		t.Fatal("a fresh ranked address must be dialable")
	}
	addr, _ := net.ResolveUDPAddr("udp", stale)
	for i := 0; i < 4; i++ {
		(&Connection{Addr: addr}).note_handshake_failure()
	}
	if relay_dial_allowed(stale, time.Now()) {
		t.Fatal("unlisted ranked address redialled right after 4 failed handshakes")
	}
	if !relay_dial_allowed(stale, time.Now().Add(9*time.Second)) {
		t.Fatal("back-off after 4 failures is 8 s; it must end")
	}

	peer_mutex.Lock()
	peer_map["45.4.4.4"] = &Peer{Address: "45.4.4.4:11011", LastConnected: uint64(now.Unix()), Whitelist: true}
	peer_mutex.Unlock()
	listed := "45.4.4.4:11011"
	if !relay_dial_allowed(listed, now) {
		t.Fatal("a listed peer without failures must be dialable")
	}
	Peer_SetFail("45.4.4.4")
	Peer_SetFail("45.4.4.4") // ConnectAfter = now + 2 s
	if relay_dial_allowed(listed, time.Now()) {
		t.Fatal("listed ranked peer redialled inside its ConnectAfter back-off")
	}
	if !relay_dial_allowed(listed, time.Now().Add(3*time.Second)) {
		t.Fatal("listed peer back-off must end")
	}
}

func TestStickyDialTargetsSkipBackingOff(t *testing.T) {
	defer save_peer_map()()
	defer reset_unlisted()()
	first_relay.Lock()
	saved := first_relay.Peers
	first_relay.Peers = map[string]*RelayStat{"203.0.113.23": {Address: "203.0.113.23:42151", Firsts: 10, Builders: map[string]uint64{}}}
	first_relay.Unlock()
	defer func() { first_relay.Lock(); first_relay.Peers = saved; first_relay.Unlock() }()

	if got := sticky_dial_targets(time.Now()); len(got) != 1 {
		t.Fatalf("targets %v, want the ranked address", got)
	}
	addr, _ := net.ResolveUDPAddr("udp", "203.0.113.23:42151")
	for i := 0; i < 4; i++ {
		(&Connection{Addr: addr}).note_handshake_failure()
	}
	if got := sticky_dial_targets(time.Now()); len(got) != 0 {
		t.Fatalf("targets %v: a ranked address that keeps failing its handshake is still dialled every round", got)
	}
}
