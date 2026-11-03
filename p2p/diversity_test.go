package p2p

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/deroproject/derohe/globals"
)

func TestNetgroup(t *testing.T) {
	cases := map[string]string{
		"203.0.113.5:11011":       "203.0",
		"203.0.200.9":             "203.0",
		"198.51.100.1:1":          "198.51",
		"10.1.2.3:11011":          "", // private: exempt
		"127.0.0.1:11011":         "", // loopback shadow: exempt
		"100.64.1.1:11011":        "", // CGNAT: exempt
		"[2001:db8:1:2::1]:11011": "2001:db8::/32",
		"[2001:db8:ffff::1]:1":    "2001:db8::/32",
		"[fe80::1]:11011":         "",
		"seed.example.com:11011":  "", // names are never a bucket
		"garbage":                 "",
	}
	for in, want := range cases {
		if got := netgroup(in); got != want {
			t.Errorf("netgroup(%q)=%q want %q", in, got, want)
		}
	}
}

func TestGossipAddressAcceptable(t *testing.T) {
	pub, lan := "198.51.100.7", "192.168.1.20"
	type c struct {
		addr, from string
		ok         bool
	}
	for _, x := range []c{
		{"203.0.113.5:11011", pub, true},
		{"[2001:db8::1]:11011", pub, true},
		{"10.0.0.5:11011", pub, false},         // a stranger's LAN is not ours
		{"127.0.0.1:10102", pub, false},        // never let a public peer point us at our own RPC port
		{"192.168.1.30:11011", lan, true},      // a LAN peer may still teach LAN peers
		{"evil.example.com:11011", pub, false}, // names: resolved on every dial, bypass IP-keyed state
		{"203.0.113.5:0", pub, false},
		{"203.0.113.5:70000", pub, false},
		{"203.0.113.5", pub, false},
		{"0.0.0.0:11011", lan, false},
		{"224.0.0.1:11011", lan, false},
		{"255.255.255.255:11011", lan, false},
	} {
		if got := gossip_address_acceptable(x.addr, x.from); got != x.ok {
			t.Errorf("gossip_address_acceptable(%q from %s)=%v want %v", x.addr, x.from, got, x.ok)
		}
	}
}

func with_clean_tables(t *testing.T) func() {
	peer_mutex.Lock()
	saved := peer_map
	peer_map = map[string]*Peer{}
	peer_mutex.Unlock()
	saved_nb := nonbanlist
	nonbanlist = nil
	diversity_mu.Lock()
	dial_pending = map[string]time.Time{}
	diversity_mu.Unlock()
	return func() {
		connection_map.Range(func(k, v interface{}) bool { connection_map.Delete(k); return true })
		peer_mutex.Lock()
		peer_map = saved
		peer_mutex.Unlock()
		nonbanlist = saved_nb
		diversity_mu.Lock()
		dial_pending = map[string]time.Time{}
		diversity_mu.Unlock()
	}
}

func out_conn(ip string) *Connection {
	c := &Connection{logger: globals.Logger, Addr: &net.UDPAddr{IP: net.ParseIP(ip), Port: 11011}}
	c.State.Store(ACTIVE)
	return c
}

func TestGreyTableCaps(t *testing.T) {
	defer with_clean_tables(t)()
	from := "198.51.100.7"
	added := 0
	for i := 0; i < 50; i++ { // one sybil /16 cannot flood the table
		if peer_add_gossip(fmt.Sprintf("203.0.%d.%d:11011", i/250, 1+i%250), from) {
			added++
		}
	}
	if added != MAX_GREY_PER_NETGROUP {
		t.Fatalf("one /16 got %d grey entries, want %d", added, MAX_GREY_PER_NETGROUP)
	}
	// re-gossiping a known entry is fine (it only bumps GoodCount) even when the group is full
	if !peer_add_gossip("203.0.0.1:11011", from) {
		t.Fatalf("known entry refused")
	}
	// many distinct /16s: the global cap holds
	for a := 1; a < 200; a++ {
		for b := 0; b < 8; b++ {
			peer_add_gossip(fmt.Sprintf("%d.%d.1.1:11011", 11+a%200, b), from)
		}
	}
	white, grey := Peer_List_Counts()
	if grey > MAX_GREY_TOTAL || white != 0 {
		t.Fatalf("grey table %d exceeds cap %d (white %d)", grey, MAX_GREY_TOTAL, white)
	}
	// whitelisted (proven) peers never count against the grey caps
	peer_mutex.Lock()
	for _, v := range peer_map {
		v.Whitelist = true
	}
	peer_mutex.Unlock()
	if !peer_add_gossip("192.0.2.77:11011", from) {
		t.Fatalf("grey cap counted whitelisted peers")
	}
}

func TestOutboundDiversity(t *testing.T) {
	defer with_clean_tables(t)()
	now := time.Now()
	// two outgoing in 203.0/16 already
	for _, ip := range []string{"203.0.1.1", "203.0.2.2"} {
		if !Connection_Add(out_conn(ip)) {
			t.Fatalf("first two in a /16 refused (%s)", ip)
		}
	}
	third := out_conn("203.0.3.3")
	if Connection_Add(third) {
		t.Fatalf("third outgoing connection in one /16 accepted")
	}
	if IsAddressConnected("203.0.3.3") {
		t.Fatalf("refused connection still in the pool")
	}
	// incoming connections are not limited by the outbound cap and do not count toward it
	in := out_conn("203.0.4.4")
	in.Incoming = true
	if !Connection_Add(in) {
		t.Fatalf("incoming refused")
	}
	// another /16, a LAN node and a priority node are fine
	for _, ip := range []string{"198.51.100.1", "192.168.1.5", "127.0.0.1"} {
		if !Connection_Add(out_conn(ip)) {
			t.Fatalf("%s refused", ip)
		}
	}
	nonbanlist = []string{"203.0.9.9:11011"}
	if !Connection_Add(out_conn("203.0.9.9")) {
		t.Fatalf("priority node refused by the netgroup cap")
	}
	// the dialer skips a full group but still picks a candidate elsewhere
	peer_mutex.Lock()
	peer_map["203.0.5.5"] = &Peer{Address: "203.0.5.5:11011", Whitelist: true, LastConnected: uint64(now.Unix())}
	peer_mutex.Unlock()
	if p := find_peer_to_connect(1); p != nil {
		t.Fatalf("dialer picked %s in a full /16", p.Address)
	}
	peer_mutex.Lock()
	peer_map["192.0.2.5"] = &Peer{Address: "192.0.2.5:11011", Whitelist: true, LastConnected: uint64(now.Unix())}
	peer_mutex.Unlock()
	if p := find_peer_to_connect(1); p == nil || p.Address != "192.0.2.5:11011" {
		t.Fatalf("dialer did not pick the diverse candidate: %+v", p)
	}
	// in-flight dials count: two pending dials into a fresh /16 fill it
	note_dial("192.0.3.1:11011", now)
	note_dial("192.0.4.1:11011", now)
	if !outbound_group_full("192.0.9.9:11011", outbound_group_counts(now, nil)) {
		t.Fatalf("pending dials not counted")
	}
	if outbound_group_full("192.0.9.9:11011", outbound_group_counts(now.Add(2*DIAL_PENDING_TTL), nil)) {
		t.Fatalf("stale pending dials still counted")
	}
}

func TestINVBounds(t *testing.T) {
	ok := ObjectList{}
	ok.Tx_list = make([][32]byte, 1)
	if !inv_within_bounds(&ok) {
		t.Fatalf("a one-tx INV rejected")
	}
	ok.Chunk_list = make([][33 + 32]byte, MAX_INV_CHUNKS)
	if !inv_within_bounds(&ok) {
		t.Fatalf("chunk cap INV rejected")
	}
	for name, r := range map[string]ObjectList{
		"txs":    {Tx_list: make([][32]byte, MAX_INV_TXS+1)},
		"blocks": {Block_list: make([][32]byte, MAX_INV_BLOCKS+1)},
		"chunks": {Chunk_list: make([][33 + 32]byte, MAX_INV_CHUNKS+1)},
		"total":  {Tx_list: make([][32]byte, 3000), Block_list: make([][32]byte, 1097)},
	} {
		if inv_within_bounds(&r) {
			t.Errorf("oversized INV (%s) accepted", name)
		}
	}
}

// The handler itself: an oversized INV is refused before any lookup, scored, and the connection dropped.
func TestNotifyINVOversizedRejected(t *testing.T) {
	penalty_mu.Lock()
	penalty_map = map[string]*misbehaviour{}
	penalty_mu.Unlock()
	c := &Connection{logger: globals.Logger, Addr: &net.UDPAddr{IP: net.ParseIP("198.51.100.99"), Port: 11011}}
	req := ObjectList{Tx_list: make([][32]byte, MAX_INV_TXS+1)}
	if err := c.NotifyINV(req, &Dummy{}); err == nil {
		t.Fatalf("oversized INV accepted")
	}
	penalty_mu.Lock()
	m := penalty_map["198.51.100.99"]
	penalty_mu.Unlock()
	if m == nil || m.score < PENALTY_POINTS["malformed_request"] {
		t.Fatalf("oversized INV not penalised: %+v", m)
	}
}

func TestTxVerificationFailureClassification(t *testing.T) {
	if !is_tx_verification_failure(fmt.Errorf("Incoming TX %s could not be verified, err %s", "ab", "x")) {
		t.Fatalf("proof failure not scored")
	}
	for _, e := range []error{nil,
		fmt.Errorf("TX %s rejected Already mined in some block", "ab"),
		fmt.Errorf("TX %s rejected height(%d) reference not found", "ab", 1),
		fmt.Errorf("Incoming TX %s nonce verification failed, err %s", "ab", "x"),
		fmt.Errorf("TX  %s rejected due to low fees  provided fee %d calculated fee %d", "ab", 1, 2),
		fmt.Errorf("TX %s rejected by pool by mempool", "ab"),
	} {
		if is_tx_verification_failure(e) {
			t.Errorf("timing-dependent rejection scored: %v", e)
		}
	}
	if _, ok := PENALTY_POINTS["invalid_tx"]; !ok {
		t.Fatalf("invalid_tx reason missing")
	}
}

// Fix A (r18 merge): the dialer notes a pending dial BEFORE connect_with_endpoint, so when that connection reaches
// Connection_Add its own pending dial must not count against its /16 (the effective cap was 1, not 2), and a peer
// refused by the cap is backed off instead of being redialled on the next tick.
func TestOutboundDiversityOwnPendingDialExcluded(t *testing.T) {
	defer with_clean_tables(t)()
	now := time.Now()
	peer_mutex.Lock()
	for _, ip := range []string{"203.0.1.1", "203.0.2.2", "203.0.3.3"} {
		peer_map[ip] = &Peer{Address: ip + ":11011", Whitelist: true, LastConnected: uint64(now.Unix())}
	}
	peer_mutex.Unlock()
	note_dial("203.0.1.1:11011", now)
	if !Connection_Add(out_conn("203.0.1.1")) {
		t.Fatalf("first outgoing in a /16 refused")
	}
	note_dial("203.0.2.2:11011", now) // exactly what maintain_connection_to_peers does
	if !Connection_Add(out_conn("203.0.2.2")) {
		t.Fatalf("second outgoing in a /16 refused: its own pending dial was counted (effective cap 1)")
	}
	note_dial("203.0.3.3:11011", now)
	if Connection_Add(out_conn("203.0.3.3")) {
		t.Fatalf("third outgoing in a /16 accepted")
	}
	p := GetPeerInList("203.0.3.3")
	if p == nil || p.ConnectAfter < uint64(now.Add(DIVERSITY_REFUSAL_BACKOFF).Unix())-1 {
		t.Fatalf("refused peer not backed off: %+v", p)
	}
	if p.FailCount != 0 {
		t.Fatalf("diversity refusal counted as a failure: %+v", p)
	}
	diversity_mu.Lock()
	_, pending := dial_pending["203.0.3.3"]
	diversity_mu.Unlock()
	if pending {
		t.Fatalf("refused dial still pending (would hold a slot for DIAL_PENDING_TTL)")
	}
}

// Fix D (r18 merge): the sync/relay path really scores a peer for a transaction that fails proof verification, and
// only for that rejection class.
func TestChainSyncPenalizesInvalidTx(t *testing.T) {
	penalty_mu.Lock()
	penalty_map = map[string]*misbehaviour{}
	penalty_mu.Unlock()
	defer func() {
		penalty_mu.Lock()
		penalty_map = map[string]*misbehaviour{}
		penalty_mu.Unlock()
	}()
	c := &Connection{logger: globals.Logger, Addr: &net.UDPAddr{IP: net.ParseIP("198.51.100.42"), Port: 11011}}
	if c.score_pool_rejection(fmt.Errorf("TX already in pool")) || c.score_pool_rejection(nil) {
		t.Fatalf("a non-verification rejection was scored")
	}
	penalty_mu.Lock()
	m := penalty_map["198.51.100.42"]
	penalty_mu.Unlock()
	if m != nil && m.score > 0 {
		t.Fatalf("benign rejection penalised: %+v", m)
	}
	if !c.score_pool_rejection(fmt.Errorf("Incoming TX %s could not be verified, err %s", "ab", "x")) {
		t.Fatalf("verification failure not recognised")
	}
	penalty_mu.Lock()
	m = penalty_map["198.51.100.42"]
	penalty_mu.Unlock()
	if m == nil || m.score < PENALTY_POINTS["invalid_tx"] {
		t.Fatalf("invalid_tx not penalised: %+v", m)
	}
}
