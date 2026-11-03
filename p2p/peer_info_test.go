package p2p

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestPeerInfosOnlyActiveAndOrdered(t *testing.T) {
	mk := func(ip string, id uint64, lat time.Duration, active bool) *Connection {
		c := &Connection{Peer_ID: id, Addr: &net.UDPAddr{IP: net.ParseIP(ip), Port: 11011}, Created: time.Now().Add(-time.Minute)}
		if active {
			c.State.Store(ACTIVE)
		}
		c.Latency.Store(int64(lat))
		c.Height.Store(100)
		c.DaemonVersion = strings.Repeat("v", 120) // peer-supplied: must come back bounded
		connection_map.Store(Address(c), c)
		return c
	}
	far := mk("10.19.0.1", 19001, 200*time.Millisecond, true)
	near := mk("10.19.0.2", 19002, 20*time.Millisecond, true)
	pending := mk("10.19.0.3", 19003, 1*time.Millisecond, false) // handshake not finished: plain fields still being written
	defer func() {
		for _, c := range []*Connection{far, near, pending} {
			connection_map.Delete(Address(c))
		}
	}()
	first_relay.record("10.19.0.1", "", nil, 0, time.Now()) // far delivered a block first: ranks above near

	var mine []PeerInfo
	for _, p := range PeerInfos(-1) {
		if strings.HasPrefix(p.Address, "10.19.0.") {
			mine = append(mine, p)
		}
	}
	if len(mine) != 2 {
		t.Fatalf("got %d peers, want the 2 ACTIVE ones: %+v", len(mine), mine)
	}
	if mine[0].Address != "10.19.0.1" || mine[1].Address != "10.19.0.2" {
		t.Fatalf("order %s, %s: first-relay score must rank first", mine[0].Address, mine[1].Address)
	}
	if mine[1].LatencyMs != 20 || mine[0].Height != 100 || len(mine[0].DaemonVersion) > 64 || mine[0].ConnectedSecs < 59 {
		t.Fatalf("fields: %+v", mine[1])
	}
	if got := PeerInfos(1); len(got) > 1 {
		t.Fatalf("max not honoured: %d", len(got))
	}
}

func TestV2OffendersSeenWindow(t *testing.T) {
	now := int64(2_000_000_000)
	penalty_mu.Lock()
	saved := v2_offences
	v2_offences = map[string]v2_record{"a": {N: 1, Last: now - 10}, "b": {N: 3, Last: now - V2_FORGET}, "c": {N: 1, Last: now - V2_FORGET - 1}}
	penalty_mu.Unlock()
	defer func() { penalty_mu.Lock(); v2_offences = saved; penalty_mu.Unlock() }()
	if n := V2OffendersSeen(now); n != 2 {
		t.Fatalf("%d v2 peers in the window, want 2 (a week-old entry has expired)", n)
	}
}
