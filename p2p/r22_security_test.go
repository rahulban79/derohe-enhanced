package p2p

import (
	"crypto/tls"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/deroproject/derohe/cryptography/crypto"
)

// r22: once the known-tx set is full of live entries, a sweep that frees nothing is not repeated until the oldest
// entry can have expired (one INV of 4096 new txids used to run 2048 full sweeps).
func TestTxKnownFullSetSweepsOnce(t *testing.T) {
	var s tx_known_set
	t0 := time.Unix(1000, 0)
	for i := 0; i < TX_KNOWN_MAX; i++ {
		s.note(txid_n(i), t0.Add(time.Duration(i)*time.Millisecond))
	}
	now := t0.Add(time.Minute)
	for i := 0; i < 500; i++ {
		s.note(txid_n(TX_KNOWN_MAX+1+i), now)
	}
	if s.sweeps != 1 {
		t.Fatalf("%d sweeps of a full live set for 500 new txids; want 1", s.sweeps)
	}
	if want := t0.Add(TX_KNOWN_TTL); !s.next_sweep.Equal(want) {
		t.Fatalf("next_sweep %v, want the oldest entry's expiry %v", s.next_sweep, want)
	}
	// at the oldest entry's expiry the sweep runs again and makes room
	at := t0.Add(TX_KNOWN_TTL)
	s.note(txid_n(9999), at)
	if s.sweeps != 2 || !s.has(txid_n(9999), at) {
		t.Fatalf("sweeps %d, recorded %v: the expired entry was not replaced", s.sweeps, s.has(txid_n(9999), at))
	}
}

// BenchmarkTxKnownFullSetFlood: the cost of one INV's worth (4096) of new txids noted into a full live set.
func BenchmarkTxKnownFullSetFlood(b *testing.B) {
	now := time.Unix(5000, 0)
	for i := 0; i < b.N; i++ {
		var s tx_known_set
		for j := 0; j < TX_KNOWN_MAX; j++ {
			s.note(txid_n(j), now)
		}
		for j := 0; j < MAX_INV_TXS; j++ {
			var h crypto.Hash
			h[0], h[1], h[2] = byte(j), byte(j>>8), 0xee
			s.note(h, now)
		}
	}
}

func TestInvBudget(t *testing.T) {
	var b inv_budget
	now := time.Unix(2000, 0)
	if n := b.take(MAX_INV_TXS, now); n != INV_TX_BURST {
		t.Fatalf("first INV of %d txids: %d allowed, want the burst %d", MAX_INV_TXS, n, INV_TX_BURST)
	}
	if n := b.take(10, now); n != 0 {
		t.Fatalf("empty bucket allowed %d", n)
	}
	if n := b.take(1000, now.Add(time.Second)); n != INV_TX_RATE {
		t.Fatalf("after 1 s %d allowed, want %d", n, INV_TX_RATE)
	}
	if n := b.take(5000, now.Add(time.Hour)); n != INV_TX_BURST {
		t.Fatalf("refill is not capped at the burst: %d", n)
	}
	// the honest pattern (one tx per INV, many per second) is never clipped
	var h inv_budget
	for i := 0; i < 600; i++ {
		if h.take(1, now.Add(time.Duration(i)*100*time.Millisecond)) != 1 {
			t.Fatalf("honest single-tx INV %d clipped", i)
		}
	}
}

func TestClipInvTxs(t *testing.T) {
	c := &Connection{}
	list := make([][32]byte, MAX_INV_TXS)
	before := inv_txids_over_budget.Get()
	got := c.clip_inv_txs(list, time.Unix(3000, 0))
	if len(got) != INV_TX_BURST {
		t.Fatalf("clipped to %d, want %d", len(got), INV_TX_BURST)
	}
	if d := inv_txids_over_budget.Get() - before; d != uint64(MAX_INV_TXS-INV_TX_BURST) {
		t.Fatalf("over-budget counter +%d", d)
	}
}

// r22: an honest GetObject answers every asked txid or errors; a successful short reply is a failed fetch.
func TestShortTxReplyCountsAsFailure(t *testing.T) {
	need := ObjectList{Tx_list: [][32]byte{txid_n(1), txid_n(2)}}
	c := &Connection{}
	for i := 1; i < MAX_TX_FETCH_FAILURES; i++ {
		if !c.note_tx_fetch_reply(need, 1, 2) {
			t.Fatalf("dropped after %d short replies", i)
		}
	}
	if c.note_tx_fetch_reply(need, 0, 2) {
		t.Fatalf("connection kept after %d short replies", MAX_TX_FETCH_FAILURES)
	}
	c2 := &Connection{}
	for i := 0; i < 3*MAX_TX_FETCH_FAILURES; i++ {
		if !c2.note_tx_fetch_reply(need, 2, 2) {
			t.Fatal("complete replies must never be counted")
		}
	}
	blocks := ObjectList{Block_list: [][32]byte{txid_n(3)}}
	if !c.note_tx_fetch_reply(blocks, 0, 0) {
		t.Fatal("a block fetch is not scored here")
	}
}

func TestTxWantCountsDelivered(t *testing.T) {
	w := new_tx_want([][32]byte{txid_n(1), txid_n(2), txid_n(1)})
	w.take(txid_n(1))
	w.take(txid_n(1))
	w.take(txid_n(9))
	if w.got != 1 || len(w.m) != 2 {
		t.Fatalf("got %d of %d", w.got, len(w.m))
	}
}

// The INV path must clip announced txids and score short replies (a source check: NotifyINV needs a live chain).
func TestNotifyINVWiresR22Guards(t *testing.T) {
	src, err := os.ReadFile("rpc_notifications.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"request.Tx_list = c.clip_inv_txs(request.Tx_list, time.Now())",
		"if !c.note_tx_fetch_reply(need, want.got, len(want.m)) {",
	} {
		if !strings.Contains(string(src), want) {
			t.Fatalf("NotifyINV lost %q", want)
		}
	}
	i := strings.Index(string(src), "clip_inv_txs(request.Tx_list")
	j := strings.Index(string(src), "c.txs_to_fetch(request.Tx_list")
	if i < 0 || j < 0 || i > j {
		t.Fatal("the txid budget must apply before txs_to_fetch")
	}
}

// r22: the p2p TLS 1.2 suites are ECDHE+AEAD only and the curves X25519/P-256; peers (Go, TLS 1.3) are unaffected.
func TestP2PTLSCipherCurveFloor(t *testing.T) {
	srvcfg := p2p_tls_server_config(generate_random_tls_cert())
	try := func(client *tls.Config) (tls.ConnectionState, error) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		errc := make(chan error, 1)
		go func() { errc <- tls.Server(a, srvcfg).Handshake() }()
		cc := tls.Client(b, client)
		cerr := cc.Handshake()
		if cerr != nil {
			a.Close()
		}
		serr := <-errc
		if cerr != nil {
			return tls.ConnectionState{}, cerr
		}
		return cc.ConnectionState(), serr
	}
	cbc := &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA}}
	if _, err := try(cbc); err == nil {
		t.Fatal("a TLS 1.2 client offering only CBC-SHA1 suites completed a handshake")
	}
	p384 := &tls.Config{InsecureSkipVerify: true, CurvePreferences: []tls.CurveID{tls.CurveP384}}
	if _, err := try(p384); err == nil {
		t.Fatal("a client offering only P-384 completed a handshake")
	}
	st, err := try(&tls.Config{InsecureSkipVerify: true}) // an upstream peer's dialer
	if err != nil || st.Version != tls.VersionTLS13 {
		t.Fatalf("upstream peer: version %x err %v", st.Version, err)
	}
	tls12 := p2p_tls_client_config()
	tls12.MaxVersion = tls.VersionTLS12
	if st, err := try(tls12); err != nil || st.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 && st.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 && st.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 {
		t.Fatalf("TLS 1.2 with the p2p client: suite %x err %v", st.CipherSuite, err)
	}
	if cfg := p2p_tls_client_config(); len(cfg.CurvePreferences) != 2 || len(cfg.CipherSuites) != len(P2P_TLS12_SUITES) {
		t.Fatal("client config lost the floor")
	}
	// the r20 version floor stays (with AEAD-only suites a TLS 1.1 handshake fails anyway, so check the field)
	if srvcfg.MinVersion != tls.VersionTLS12 || p2p_tls_client_config().MinVersion != tls.VersionTLS12 {
		t.Fatal("TLS 1.2 floor lost")
	}
}

// BenchmarkInvFloodPerINV: our side of one INV of MAX_INV_TXS random txids before any GetObject (pool miss, two
// failed tx-store opens per txid as storefs.ReadTX does, tx_asked claim, tx_known record). r22 caps a connection
// at INV_TX_RATE such txids per second after an INV_TX_BURST burst.
func BenchmarkInvFloodPerINV(b *testing.B) {
	dir := b.TempDir()
	on_disk := func(h crypto.Hash) bool {
		_, e1 := os.ReadFile(dir + "/a/" + h.String() + ".tx")
		_, e2 := os.ReadFile(dir + "/b/" + h.String() + ".tx")
		return e1 == nil || e2 == nil
	}
	have := func(crypto.Hash) bool { return false }
	list := make([][32]byte, MAX_INV_TXS)
	for i := 0; i < b.N; i++ {
		c := &Connection{}
		for j := range list {
			list[j][0], list[j][1], list[j][2], list[j][3] = byte(j), byte(j>>8), byte(i), byte(i>>8)
		}
		c.txs_to_fetch(list, 0, have, on_disk)
	}
}
