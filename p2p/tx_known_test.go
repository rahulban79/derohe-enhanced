package p2p

import (
	"container/heap"
	"math/rand"
	"testing"
	"time"

	"github.com/deroproject/derohe/cryptography/crypto"
)

func known_conn(id uint64, height int64) *Connection {
	c := &Connection{Peer_ID: id}
	c.State.Store(ACTIVE)
	c.Height.Store(height)
	return c
}

func TestTxAnnounceSkipsPeersThatAnnounced(t *testing.T) {
	now := time.Unix(1793219000, 0)
	tx := txid_n(7)
	var conns []*Connection
	for id := uint64(1); id <= 5; id++ {
		conns = append(conns, known_conn(id+1000, 100))
	}
	conns[1].tx_known.note(tx, now) // peer 1002 served/announced it
	conns[3].tx_known.note(tx, now) // peer 1004 announced it too
	pending := known_conn(2000, 100)
	pending.State.Store(HANDSHAKE_PENDING)
	behind := known_conn(2001, 50)
	conns = append(conns, pending, behind)

	targets, skipped := tx_announce_targets(conns, tx, 1005, 100, now)
	got := map[uint64]bool{}
	for _, c := range targets {
		got[c.Peer_ID] = true
	}
	if len(targets) != 2 || !got[1001] || !got[1003] || skipped != 2 {
		t.Fatalf("targets %v skipped %d; want 1001,1003 and 2 skipped (1005 excluded by id, pending and lagging peers skipped)", got, skipped)
	}
	// a different tx still goes to every eligible peer (the r19 rebroadcast path is unaffected)
	if targets, _ := tx_announce_targets(conns, txid_n(8), 0, 100, now); len(targets) != 5 {
		t.Fatalf("unrelated tx reached %d peers, want 5", len(targets))
	}
	// knowledge expires
	if targets, _ := tx_announce_targets(conns, tx, 0, 100, now.Add(TX_KNOWN_TTL)); len(targets) != 5 {
		t.Fatalf("after TTL the tx reached %d peers, want 5", len(targets))
	}
}

func TestTxsToFetchRecordsAnnouncements(t *testing.T) {
	c := known_conn(1, 1)
	have := func(crypto.Hash) bool { return true } // already in our pool: nothing to fetch, but the peer holds it
	if f := c.txs_to_fetch([][32]byte{txid_n(1), txid_n(2)}, 0, have, func(crypto.Hash) bool { return false }); len(f) != 0 {
		t.Fatalf("fetched %d", len(f))
	}
	if !c.tx_known.has(txid_n(1), time.Now()) || !c.tx_known.has(txid_n(2), time.Now()) {
		t.Fatal("announced txids were not recorded as known to the peer")
	}
}

func TestTxKnownBoundedFailOpen(t *testing.T) {
	var s tx_known_set
	now := time.Unix(1000, 0)
	for i := 0; i < TX_KNOWN_MAX; i++ {
		s.note(txid_n(i), now)
	}
	s.note(txid_n(TX_KNOWN_MAX+1), now)
	if s.size() > TX_KNOWN_MAX || s.has(txid_n(TX_KNOWN_MAX+1), now) {
		t.Fatalf("full set of live entries must not grow or record (size %d)", s.size())
	}
	later := now.Add(TX_KNOWN_TTL)
	s.note(txid_n(TX_KNOWN_MAX+2), later)
	if !s.has(txid_n(TX_KNOWN_MAX+2), later) || s.size() != 1 {
		t.Fatalf("expired entries were not pruned (size %d)", s.size())
	}
}

// flood simulation: n fully meshed nodes (DERO's reachable network is ~two dozen nodes, live outgoing 14), one tx
// injected at node 0. A node that learns of a tx it lacks asks the announcer (one fetch per node), admits it after
// verify, then announces it to its targets. Returns the number of NotifyINV messages sent network-wide.
type flood_ev struct {
	at       time.Duration
	to, from int
	kind     int // 0 INV arrives, 1 tx admitted
}
type flood_q []flood_ev

func (q flood_q) Len() int            { return len(q) }
func (q flood_q) Less(i, j int) bool  { return q[i].at < q[j].at }
func (q flood_q) Swap(i, j int)       { q[i], q[j] = q[j], q[i] }
func (q *flood_q) Push(x interface{}) { *q = append(*q, x.(flood_ev)) }
func (q *flood_q) Pop() interface{}   { o := *q; x := o[len(o)-1]; *q = o[:len(o)-1]; return x }

// only >= 0 runs the filter on that one node (an upgraded node among old ones); mine counts that node's sends.
func flood_invs(n int, filter bool, seed int64) int {
	all, _ := flood_invs_at(n, filter, -1, seed)
	return all
}

func flood_invs_at(n int, filter bool, only int, seed int64) (invs, mine int) {
	rng := rand.New(rand.NewSource(seed))
	lat := make([][]time.Duration, n)
	for i := range lat {
		lat[i] = make([]time.Duration, n)
	}
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			d := time.Duration(30+rng.Intn(170)) * time.Millisecond // one-way 30-200 ms
			lat[i][j], lat[j][i] = d, d
		}
	}
	// conn[i][j] is node i's connection to node j
	conn := make([][]*Connection, n)
	for i := range conn {
		for j := 0; j < n; j++ {
			conn[i] = append(conn[i], known_conn(uint64(j+1), 100))
		}
	}
	tx := txid_n(42)
	base := time.Unix(1793219000, 0)
	have, asked := make([]bool, n), make([]bool, n)
	q := &flood_q{{0, 0, -1, 1}}
	for q.Len() > 0 {
		e := heap.Pop(q).(flood_ev)
		switch e.kind {
		case 0: // INV from e.from arrives at e.to
			if filter && (only < 0 || e.to == only) {
				conn[e.to][e.from].tx_known.note(tx, base.Add(e.at))
			}
			if !have[e.to] && !asked[e.to] {
				asked[e.to] = true // fetch round trip + 5 ms verify
				heap.Push(q, flood_ev{e.at + 2*lat[e.to][e.from] + 5*time.Millisecond, e.to, e.from, 1})
			}
		case 1: // admitted: relay with PeerID 0, as chain_sync.go does
			have[e.to] = true
			var peers []*Connection
			for j := 0; j < n; j++ {
				if j != e.to {
					peers = append(peers, conn[e.to][j])
				}
			}
			targets, _ := tx_announce_targets(peers, tx, 0, 100, base.Add(e.at))
			for _, c := range targets {
				j := int(c.Peer_ID) - 1
				invs++
				if e.to == only {
					mine++
				}
				heap.Push(q, flood_ev{e.at + lat[e.to][j], j, e.to, 0})
			}
		}
	}
	return
}

func TestTxKnownFloodSavesAnnouncements(t *testing.T) {
	for _, n := range []int{14, 24} {
		without, with := 0, 0
		for seed := int64(1); seed <= 20; seed++ {
			without += flood_invs(n, false, seed)
			with += flood_invs(n, true, seed)
		}
		t.Logf("n=%d: NotifyINV per tx %.1f -> %.1f (%.0f%% fewer)", n, float64(without)/20, float64(with)/20, 100*(1-float64(with)/float64(without)))
		if without != 20*n*(n-1) || with >= without*3/4 {
			t.Fatalf("n=%d: without %d (want %d), with %d", n, without, 20*n*(n-1), with)
		}
	}
}

func TestTxKnownSingleUpgradedNode(t *testing.T) {
	const n = 15 // our node + 14 outgoing peers, as live
	without, with := 0, 0
	for seed := int64(1); seed <= 40; seed++ {
		_, a := flood_invs_at(n, false, 5, seed)
		_, b := flood_invs_at(n, true, 5, seed)
		without, with = without+a, with+b
	}
	t.Logf("one upgraded node, n=%d: its NotifyINV per tx %.1f -> %.1f (%.0f%% fewer)", n, float64(without)/40, float64(with)/40, 100*(1-float64(with)/float64(without)))
	if without != 40*(n-1) || with >= without {
		t.Fatalf("without %d with %d", without, with)
	}
}
