package p2p

// r28 (group p2p-config, sweep gap "p2p package: 99 of 438 functions at 0.0 %"): tests for the 0 % paths that can be
// driven without a network: the in-RAM difficulty source, the p2p block encodings, the connection-pool counts, the NTP
// math, the malformed-request refusals of the object/changeset/tree-section servers, the handshake fill and the
// small accessors. Each test asserts a behaviour (a count, a refusal, a round trip), not only that the code runs.
// Simulator chain in a temp dir and in-process connections only.

import (
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/metrics"
)

func r28_panics(f func()) (p bool) {
	defer func() { p = recover() != nil }()
	f()
	return
}

func r28_clean_conns(t *testing.T) {
	connection_map.Range(func(k, v interface{}) bool { connection_map.Delete(k); return true })
	t.Cleanup(func() { connection_map.Range(func(k, v interface{}) bool { connection_map.Delete(k); return true }) })
}

// ---- MemorySource: the in-RAM DiffProvider the bootstrap path uses ------------------------------------------------

func TestR28MemorySourceAccessors(t *testing.T) {
	x := &MemorySource{Blocks: map[crypto.Hash]*block.Complete_Block{}, Difficulty: map[crypto.Hash]*big.Int{}}
	tip := crypto.Keccak256([]byte("tip"))
	bl := &block.Block{Height: 12, Timestamp: 3456, Tips: []crypto.Hash{tip}}
	cbl := &block.Complete_Block{Bl: bl}
	x.insert_block_noprecheck(cbl, big.NewInt(77))
	id := bl.GetHash()
	if x.Load_Block_Height(id) != 12 || x.Load_Block_Timestamp(id) != 3456 || len(x.Get_Block_Past(id)) != 1 ||
		x.Get_Block_Past(id)[0] != tip || x.Load_Block_Difficulty(id).Int64() != 77 {
		t.Fatal("accessors do not return the inserted block")
	}
	unknown := crypto.Keccak256([]byte("unknown"))
	if !r28_panics(func() { x.Load_Block_Height(unknown) }) || !r28_panics(func() { x.Load_Block_Difficulty(unknown) }) {
		t.Fatal("an unknown block id must panic (the bootstrap recovers it)")
	}
	if !r28_panics(func() { x.insert_block(&block.Complete_Block{Bl: &block.Block{}}) }) {
		t.Fatal("a block without tips (genesis) must be refused by insert_block")
	}
}

// ---- p2p block encodings round-trip; a tx-count mismatch is refused ------------------------------------------------

func TestR28BlockEncodingsRoundTrip(t *testing.T) {
	r25_reset(t)
	ch := r26_sim_chain(t, 2)
	cbl, _, err := ch.Create_new_miner_block(r25_genesis_miner(t))
	if err != nil {
		t.Fatal(err)
	}
	raw := Convert_CBL_TO_P2PCBL(cbl, true)
	back := Convert_P2PCBL_TO_CBL(raw)
	if back.Bl.GetHash() != cbl.Bl.GetHash() || len(back.Txs) != 0 {
		t.Fatalf("Convert_CBL_TO_P2PCBL/Convert_P2PCBL_TO_CBL changed the block")
	}
	c2, _ := ConvertCBlock_To_CompleteBlock(Complete_Block{Block: cbl.Bl.Serialize()})
	if c2.Bl.GetHash() != cbl.Bl.GetHash() {
		t.Fatal("ConvertCBlock_To_CompleteBlock changed the block")
	}
	bad := *cbl.Bl
	bad.Tx_hashes = []crypto.Hash{crypto.Keccak256([]byte("missing tx"))}
	if !r28_panics(func() { ConvertCBlock_To_CompleteBlock(Complete_Block{Block: bad.Serialize()}) }) {
		t.Fatal("a block whose txs are missing must be refused")
	}
	if !r28_panics(func() { Convert_P2PCBL_TO_CBL([]byte{0xff, 0x00}) }) {
		t.Fatal("undecodable p2p block bytes must be refused")
	}
	// the chunk builder: 10 data + 10 parity shards, each chunk names the same header hash, and our own block is
	// found as already chunked
	hh, n := convert_block_to_chunks(cbl, 10, 10)
	if n != 20 || is_chunk_exist(hh, 0) == nil || is_chunk_exist(hh, 19) == nil || is_chunk_exist(hh, 0).HeaderHash() != hh {
		t.Fatal("convert_block_to_chunks did not store 20 consistent chunks")
	}
	if h2, n2 := is_already_chunked_by_us(cbl.Bl.GetHash(), 10, 10); n2 != 20 || h2 != hh {
		t.Fatalf("is_already_chunked_by_us: %d", n2)
	}
	// chunks_clean_up keeps a fresh entry and drops one older than 180 s
	v, _ := chunk_map.Load(strings.ToLower(hexs(hh)))
	chunks_clean_up()
	if is_chunk_exist(hh, 0) == nil {
		t.Fatal("a fresh chunk set was cleaned up")
	}
	v.(*Chunks_Per_Block_Data).Created = time.Now().Add(-181 * time.Second)
	chunks_clean_up()
	if is_chunk_exist(hh, 0) != nil {
		t.Fatal("a chunk set older than 180 s was kept")
	}
}

func hexs(h [32]byte) string {
	const d = "0123456789abcdef"
	b := make([]byte, 64)
	for i, x := range h {
		b[2*i], b[2*i+1] = d[x>>4], d[x&15]
	}
	return string(b)
}

// ---- connection pool counts: pending and self are never counted --------------------------------------------------

func TestR28ConnectionPoolCounts(t *testing.T) {
	r28_clean_conns(t)
	mk := func(ip string, in bool, h int64, state uint32, id uint64) *Connection {
		c := out_conn(ip)
		c.Incoming, c.Peer_ID = in, id
		c.Height.Store(h)
		c.TopoHeight.Store(h + 1)
		c.State.Store(state)
		connection_map.Store(Address(c), c)
		return c
	}
	mk("192.0.2.10", false, 100, ACTIVE, 1)
	mk("192.0.2.11", false, 102, ACTIVE, 2)
	in := mk("192.0.2.12", true, 104, ACTIVE, 3)
	mk("192.0.2.13", false, 999, HANDSHAKE_PENDING, 4) // pending: never counted
	mk("192.0.2.14", false, 999, ACTIVE, GetPeerID())  // ourselves: never counted
	if Peer_Count() != 3 {
		t.Fatalf("Peer_Count %d, want 3", Peer_Count())
	}
	if i, o := Peer_Direction_Count(); i != 1 || o != 2 {
		t.Fatalf("Peer_Direction_Count %d in %d out", i, o)
	}
	if h, topo := Best_Peer_Height(); h != 102 || topo != 103 {
		t.Fatalf("Best_Peer_Height %d/%d, want the median 102/103", h, topo)
	}
	if v := stuck_peer_views(); len(v) != 3 {
		t.Fatalf("stuck_peer_views %d, want 3 (pending and self excluded)", len(v))
	}
	// Connection_Delete removes only this connection, never a newer one for the same address
	newer := out_conn("192.0.2.12")
	newer.State.Store(ACTIVE)
	connection_map.Store(Address(newer), newer)
	Connection_Delete(in)
	if _, ok := connection_map.Load(Address(newer)); !ok {
		t.Fatal("Connection_Delete removed the newer connection of the same address")
	}
	Connection_Delete(newer)
	if _, ok := connection_map.Load(Address(newer)); ok {
		t.Fatal("Connection_Delete did not remove the connection")
	}
}

// Connection_Pending_Clear: a handshake pending > 10 s, an idle (> 20 s) and a banned connection leave the pool
func TestR28ConnectionPendingClear(t *testing.T) {
	r28_clean_conns(t)
	r27_reset_bans(t)
	now := time.Now()
	mk := func(ip string, state uint32, created, upd time.Time) *Connection {
		c := out_conn(ip)
		c.logger = logr.Discard()
		c.State.Store(state)
		c.Created = created
		c.update_received_ns.Store(upd.UnixNano())
		connection_map.Store(Address(c), c)
		return c
	}
	pend := mk("192.0.2.20", HANDSHAKE_PENDING, now.Add(-11*time.Second), now)
	idle := mk("192.0.2.21", ACTIVE, now, now.Add(-time.Minute))
	ban := mk("192.0.2.22", ACTIVE, now, now)
	keep := mk("192.0.2.23", ACTIVE, now, now)
	Ban_Address("192.0.2.22", 600)
	Connection_Pending_Clear()
	for _, c := range []*Connection{pend, idle, ban} {
		if _, ok := connection_map.Load(Address(c)); ok {
			t.Fatalf("%s stayed in the pool", Address(c))
		}
	}
	if _, ok := connection_map.Load(Address(keep)); !ok || keep.exited.Load() != 0 {
		t.Fatal("a fresh active connection was removed")
	}
}

// ---- NTP math (p2p/time.go) and small helpers ----------------------------------------------------------------------

func TestR28RttOffsetMath(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	// org 0, the peer receives at +60 ms and answers at +61 ms on its clock (10 ms ahead), we receive at +102 ms
	org, rec, xmt, dst := t0, t0.Add(60*time.Millisecond), t0.Add(61*time.Millisecond), t0.Add(102*time.Millisecond)
	if r := rtt(org, rec, xmt, dst); r != 101*time.Millisecond {
		t.Fatalf("rtt %v, want 101ms", r)
	}
	if o := offset(org, rec, xmt, dst); o != 9500*time.Microsecond {
		t.Fatalf("offset %v, want 9.5ms", o)
	}
	if r := rtt(org, rec, rec.Add(time.Second), dst); r != 0 {
		t.Fatalf("a negative rtt must clamp to 0, got %v", r)
	}
	if Abs(-5) != 5 || Abs(5) != 5 || Abs(0) != 0 {
		t.Fatal("Abs")
	}
}

func TestR28BackoffExpires(t *testing.T) {
	backoff_mutex.Lock()
	saved := backoff
	backoff = map[string]int64{"192.0.2.30": time.Now().Unix() + 60, "192.0.2.31": time.Now().Unix() - 1}
	backoff_mutex.Unlock()
	defer func() { backoff_mutex.Lock(); backoff = saved; backoff_mutex.Unlock() }()
	if !shouldwebackoff("192.0.2.30") || shouldwebackoff("192.0.2.31") || shouldwebackoff("192.0.2.32") {
		t.Fatal("a running back-off must hold, an expired or absent one not")
	}
	backoff_mutex.Lock()
	_, left := backoff["192.0.2.31"]
	backoff_mutex.Unlock()
	if left {
		t.Fatal("an expired back-off entry was kept")
	}
}

func TestR28HandleConnectionPanicExits(t *testing.T) {
	c := out_conn("192.0.2.40")
	c.logger = logr.Discard()
	func() {
		defer handle_connection_panic(c)
		panic("handler bug")
	}()
	if c.exited.Load() != 1 {
		t.Fatal("a panicking handler must close its connection")
	}
}

func TestR28SafeLocatePruneTopoWithoutChain(t *testing.T) {
	old := chain
	chain = nil
	defer func() { chain = old }()
	if safeLocatePruneTopo() != 0 {
		t.Fatal("no chain: the prune topo must read 0, not panic")
	}
	var cs Common_Struct
	cs.Height, cs.TopoHeight = 9, 9
	fill_common_empty(&cs)
	if cs.Height != 0 || cs.TopoHeight != 0 || cs.T0 == 0 {
		t.Fatalf("fill_common_empty %+v", cs)
	}
}

// ---- the object, changeset and tree-section servers refuse malformed requests and penalise the sender -------------

func TestR28MalformedObjectRequestsRefused(t *testing.T) {
	reset_penalty(t)
	r := func(ip string) *Connection { c := out_conn(ip); c.logger = logr.Discard(); return c }
	score := func(ip string) float64 {
		for _, o := range Offenders(1000, time.Now()) {
			if o.Scope == ip {
				return o.Score
			}
		}
		return 0
	}
	c1 := r("192.0.2.50")
	if err := c1.GetObject(ObjectList{}, &Objects{}); err != nil || c1.exited.Load() != 1 || score("192.0.2.50") <= 0 {
		t.Fatalf("an empty object request: err %v exited %d score %v", err, c1.exited.Load(), score("192.0.2.50"))
	}
	c2 := r("192.0.2.51")
	if c2.GetObject(ObjectList{Chunk_list: make([][65]byte, 129)}, &Objects{}); c2.exited.Load() != 1 || score("192.0.2.51") <= 0 {
		t.Fatal("more than 128 chunks must be refused and penalised")
	}
	c3 := r("192.0.2.52")
	if c3.ChangeSet(ChangeList{}, &Changes{}); c3.exited.Load() != 1 || score("192.0.2.52") <= 0 {
		t.Fatal("an empty changeset request must be refused and penalised")
	}
	c4 := r("192.0.2.53")
	if err := c4.TreeSection(Request_Tree_Section_Struct{Topo: 1}, &Response_Tree_Section_Struct{}); err == nil || c4.exited.Load() != 1 ||
		score("192.0.2.53") <= 0 {
		t.Fatalf("a tree section below topo 2 must be refused with an error (upstream served it): %v", err)
	}
}

// ---- the handshake fill, Ping, and the chain-backed helpers on a simulator chain ------------------------------------

func TestR28HandshakeFillAndChainHelpers(t *testing.T) {
	r25_reset(t)
	ch := r26_sim_chain(t, 3)
	var h Handshake_Struct
	h.Fill()
	if h.ProtocolVersion != "1.0.0" || h.DaemonVersion != config.Version.String() || h.Peer_ID != GetPeerID() ||
		h.Common.Height != ch.Get_Height() || h.Pruned != safeLocatePruneTopo() {
		t.Fatalf("Fill %+v", h)
	}
	var nid [16]byte
	copy(nid[:], globals.Config.Network_ID[:])
	if h.Network_ID != nid {
		t.Fatal("the handshake must carry this network's id")
	}
	c := out_conn("192.0.2.60")
	c.logger = logr.Discard()
	var resp Dummy
	if err := c.Ping(Dummy{}, &resp); err != nil || resp.Common.Height != ch.Get_Height() || resp.Common.T1 == 0 {
		t.Fatalf("Ping %v %+v", err, resp.Common)
	}
	var cs Common_Struct
	fill_common_skip_topoheight(&cs)
	if cs.Height != ch.Get_Height() {
		t.Fatal("fill_common_skip_topoheight")
	}
	if id, ok := topo_id_at(ch.Load_TOPO_HEIGHT()); !ok || id != ch.Get_Top_ID() {
		t.Fatal("topo_id_at(top) is not the top block")
	}
	if _, ok := topo_id_at(ch.Load_TOPO_HEIGHT() + 100); ok {
		t.Fatal("topo_id_at beyond the chain must report false")
	}
	nx := crypto.Keccak256([]byte("no such tx"))
	if tx_on_disk(nx) || have_pool_tx(nx) || pool_tx(nx) != nil {
		t.Fatal("an unknown tx is not on disk or in a pool")
	}
	// eligible_tx_peers: within 25 behind / 5 ahead of us, never pending
	r28_clean_conns(t)
	for i, d := range []int64{0, -25, -26, 5, 6} {
		p := out_conn("192.0.2." + string(rune('a'+i)))
		p.Addr = &net.UDPAddr{IP: net.IPv4(192, 0, 2, byte(70+i)), Port: 11011}
		p.Peer_ID = uint64(700 + i)
		p.Height.Store(ch.Get_Height() + d)
		connection_map.Store(Address(p), p)
	}
	if n := eligible_tx_peers(); n != 3 {
		t.Fatalf("eligible_tx_peers %d, want 3 (0, -25, +5)", n)
	}
	stuck_peer_sweep() // runs on the real views; the sweep's rules are tested in stuck_peer_test.go
}

// ---- peers.json, first_relay.json, v2_offences.json reach the data directory --------------------------------------

func TestR28PeerListPersistAndRotate(t *testing.T) {
	r25_reset(t)
	r26_sim_chain(t, 1) // --data-dir = a temp dir
	peer_mutex.Lock()
	saved := peer_map
	peer_map = map[string]*Peer{}
	peer_mutex.Unlock()
	defer func() { peer_mutex.Lock(); peer_map = saved; peer_mutex.Unlock() }()
	now := uint64(time.Now().Unix())
	peer_mutex.Lock()
	for i := 0; i < 3; i++ {
		a := "192.0.2." + []string{"80", "81", "82"}[i] + ":11011"
		peer_map[ParseIPNoError(a)] = &Peer{Address: a, LastConnected: now, Whitelist: true}
	}
	peer_mutex.Unlock()
	save_peer_list()
	if _, err := os.Stat(filepath.Join(globals.GetDataDirectory(), "peers.json")); err != nil {
		t.Fatalf("peers.json not written: %v", err)
	}
	peer_mutex.Lock()
	peer_map = map[string]*Peer{}
	peer_mutex.Unlock()
	load_peer_list()
	peer_mutex.Lock()
	n := len(peer_map)
	peer_mutex.Unlock()
	if n != 3 {
		t.Fatalf("load_peer_list read %d peers, want 3", n)
	}
	Peer_Delete(&Peer{Address: "192.0.2.80:11011"})
	peer_mutex.Lock()
	n = len(peer_map)
	peer_mutex.Unlock()
	if n != 2 {
		t.Fatalf("Peer_Delete left %d", n)
	}
	PeerList_Print()
	// first_relay and v2 offences use the same data directory
	save_first_relay()
	if _, err := os.Stat(filepath.Join(globals.GetDataDirectory(), FIRST_RELAY_FILE)); err != nil {
		t.Fatalf("%s not written: %v", FIRST_RELAY_FILE, err)
	}
	load_first_relay()
	load_v2_offences()
}

// ---- small accessors -------------------------------------------------------------------------------------------------

func TestR28AccessorsAndOwnBroadcastReport(t *testing.T) {
	r25_reset(t)
	b0, m0 := First_Seen_Table_Sizes()
	tip := crypto.Keccak256([]byte("r28 tip"))
	Note_Local_Block(&block.Complete_Block{Bl: &block.Block{Height: 5, Tips: []crypto.Hash{tip}}})
	Note_Local_Block(nil)
	Note_Local_MiniBlock(block.MiniBlock{Height: 5, PastCount: 1})
	if b1, m1 := First_Seen_Table_Sizes(); b1 != b0+1 || m1 != m0+1 {
		t.Fatalf("first-seen tables %d/%d -> %d/%d", b0, m0, b1, m1)
	}
	if BansLoaded() != bans_loaded_total.Get() || PublicInboundOpens() != public_inbound_opens {
		t.Fatal("accessors disagree with their counters")
	}
	p0 := metrics.Set.GetOrCreateCounter("miniblock_ours_broadcast_peers_total").Get()
	f0 := metrics.Set.GetOrCreateCounter(`miniblock_ours_broadcast_failed_by_reason_total{reason="r28_test"}`).Get()
	report_own_miniblock_broadcast(5, ack_summary{Peers: 4, Acked: 3, Failed: 1, Reasons: map[string]int{"r28_test": 1},
		First: 10 * time.Millisecond, Median: 20 * time.Millisecond, Last: 30 * time.Millisecond})
	if metrics.Set.GetOrCreateCounter("miniblock_ours_broadcast_peers_total").Get() != p0+4 ||
		metrics.Set.GetOrCreateCounter(`miniblock_ours_broadcast_failed_by_reason_total{reason="r28_test"}`).Get() != f0+1 {
		t.Fatal("report_own_miniblock_broadcast did not count")
	}
	saved := mined_source.Load()
	SetMinedSource(func() map[crypto.Hash]bool { return map[crypto.Hash]bool{tip: true} })
	if f, ok := mined_source.Load().(func() map[crypto.Hash]bool); !ok || !f()[tip] {
		t.Fatal("SetMinedSource did not install the source")
	}
	if saved != nil {
		mined_source.Store(saved)
	}
}
