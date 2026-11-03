package p2p

// r19 inbound-path guards: the TLS handshake deadline (UDP reflection), ban-before-token admission, and IPv6 /64
// penalty scope. TestAmplificationProbe is the measuring tool behind the numbers in controller.go; it is skipped
// unless DERO_AMP_PROBE_SECS is set.

import (
	"crypto/sha1"
	"crypto/tls"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cenkalti/rpc2"
	"github.com/deroproject/derohe/globals"
	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/time/rate"
)

// capturePC is a PacketConn that records what a KCP client sends and delivers nothing back.
type capturePC struct {
	mu   sync.Mutex
	pkts [][]byte
	die  chan struct{}
}

func (c *capturePC) ReadFrom(b []byte) (int, net.Addr, error) { <-c.die; return 0, nil, net.ErrClosed }
func (c *capturePC) WriteTo(b []byte, a net.Addr) (int, error) {
	c.mu.Lock()
	c.pkts = append(c.pkts, append([]byte(nil), b...))
	c.mu.Unlock()
	return len(b), nil
}
func (c *capturePC) Close() error                     { return nil }
func (c *capturePC) LocalAddr() net.Addr              { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }
func (c *capturePC) SetDeadline(time.Time) error      { return nil }
func (c *capturePC) SetReadDeadline(time.Time) error  { return nil }
func (c *capturePC) SetWriteDeadline(time.Time) error { return nil }

func test_block() kcp.BlockCrypt {
	key := pbkdf2.Key([]byte("n"), []byte("n"), 1024, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(key)
	return block
}

// start_inbound_listener runs the production accept path (serve_inbound) on a loopback KCP listener.
func start_inbound_listener(t *testing.T, srv *rpc2.Server, old_path bool) *kcp.Listener {
	l, err := kcp.ListenWithOptions("127.0.0.1:0", test_block(), 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	tune_listener(l)
	tlsconfig := &tls.Config{Certificates: []tls.Certificate{generate_random_tls_cert()}}
	go func() {
		for {
			conn, err := l.AcceptKCP()
			if err != nil {
				return
			}
			if old_path { // upstream: no handshake deadline, the codec's READ_TIMEOUT (20 s) ends the session
				tunekcp(conn)
				go srv.ServeCodecWithState(NewCBORCodec(tls.Server(conn, tlsconfig)), rpc2.NewState())
				continue
			}
			go serve_inbound(srv, conn, tlsconfig, conn.RemoteAddr().(*net.UDPAddr))
		}
	}()
	return l
}

// client_hello_datagram returns the first datagram a real KCP+TLS client sends: one KCP segment holding a ClientHello.
func client_hello_datagram(t *testing.T, to string) []byte {
	cpc := &capturePC{die: make(chan struct{})}
	cs, err := kcp.NewConn(to, test_block(), 10, 3, cpc)
	if err != nil {
		t.Fatal(err)
	}
	tunekcp(cs)
	go tls.Client(cs, &tls.Config{InsecureSkipVerify: true}).Handshake()
	defer func() { close(cpc.die); cs.Close() }()
	for i := 0; i < 100; i++ {
		time.Sleep(20 * time.Millisecond)
		cpc.mu.Lock()
		n := len(cpc.pkts)
		cpc.mu.Unlock()
		if n > 0 {
			break
		}
	}
	cpc.mu.Lock()
	defer cpc.mu.Unlock()
	if len(cpc.pkts) == 0 {
		t.Fatal("client sent nothing")
	}
	return cpc.pkts[0]
}

// reflect sends one ClientHello datagram as a spoofer would (never acknowledging anything) and returns the time of
// every datagram that came back within d, and the total bytes.
func reflect(t *testing.T, l *kcp.Listener, d time.Duration) (times []time.Duration, total int, sent int) {
	first := client_hello_datagram(t, l.Addr().String())
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if _, err := u.WriteTo(first, l.Addr()); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	buf := make([]byte, 65536)
	for time.Since(start) < d {
		u.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := u.ReadFrom(buf)
		if err != nil {
			continue
		}
		total += n
		times = append(times, time.Since(start))
	}
	return times, total, len(first)
}

// One spoofed ClientHello must stop drawing retransmissions once the handshake deadline has passed.
func TestInboundHandshakeDeadlineEndsReflection(t *testing.T) {
	saved_timeout, saved_low := INBOUND_TLS_HANDSHAKE_TIMEOUT, P2PLowLatency
	defer func() { INBOUND_TLS_HANDSHAKE_TIMEOUT, P2PLowLatency = saved_timeout, saved_low }()
	INBOUND_TLS_HANDSHAKE_TIMEOUT = time.Second
	P2PLowLatency = true // the live profile
	l := start_inbound_listener(t, rpc2.NewServer(), false)
	defer l.Close()
	before := atomic.LoadUint64(&inbound_handshake_failures)
	times, total, sent := reflect(t, l, 4*time.Second)
	if len(times) == 0 {
		t.Fatal("the server never answered the ClientHello: the probe is not exercising the TLS path")
	}
	for _, at := range times {
		if at > INBOUND_TLS_HANDSHAKE_TIMEOUT+700*time.Millisecond {
			t.Fatalf("server still retransmitting to an unverified address at %v (deadline %v): %v", at, INBOUND_TLS_HANDSHAKE_TIMEOUT, times)
		}
	}
	if atomic.LoadUint64(&inbound_handshake_failures) == before {
		t.Fatal("the failed handshake was not counted")
	}
	t.Logf("1 datagram of %d bytes drew %d datagrams, %d bytes (x%.1f) before the 1 s deadline", sent, len(times), total, float64(total)/float64(sent))
}

// An honest peer completes the handshake within the deadline and keeps working after it has passed.
func TestInboundHonestPeerOutlivesHandshakeDeadline(t *testing.T) {
	saved := INBOUND_TLS_HANDSHAKE_TIMEOUT
	defer func() { INBOUND_TLS_HANDSHAKE_TIMEOUT = saved }()
	INBOUND_TLS_HANDSHAKE_TIMEOUT = time.Second
	srv := rpc2.NewServer()
	srv.Handle("T.Echo", func(client *rpc2.Client, args int, reply *int) error { *reply = args; return nil })
	l := start_inbound_listener(t, srv, false)
	defer l.Close()
	for _, low := range []bool{true, false} {
		P2PLowLatency = low
		cs, err := kcp.DialWithOptions(l.Addr().String(), test_block(), 10, 3)
		if err != nil {
			t.Fatal(err)
		}
		tunekcp(cs)
		client := rpc2.NewClientWithCodec(NewCBORCodec(tls.Client(cs, &tls.Config{InsecureSkipVerify: true})))
		go client.Run()
		var r int
		if err := client.Call("T.Echo", 7, &r); err != nil || r != 7 {
			t.Fatalf("lowlatency=%v first call: %v %d", low, err, r)
		}
		time.Sleep(INBOUND_TLS_HANDSHAKE_TIMEOUT + 500*time.Millisecond)
		if err := client.Call("T.Echo", 8, &r); err != nil || r != 8 {
			t.Fatalf("lowlatency=%v call after the handshake deadline: %v %d", low, err, r)
		}
		client.Close()
	}
}

// A banned IP must not consume the accept token an honest peer needs.
func TestAdmitInboundChecksBanBeforeToken(t *testing.T) {
	banned := "198.51.100.201"
	Ban_Address(banned, 60)
	defer UnBan_Address(banned)
	limiter := rate.NewLimiter(rate.Every(time.Hour), 1) // exactly one token within the test
	for i := 0; i < 5; i++ {
		if admit_inbound(banned, limiter) {
			t.Fatal("a banned IP was admitted")
		}
	}
	if !admit_inbound("198.51.100.202", limiter) {
		t.Fatal("the banned IP spent the honest peer's token")
	}
}

func TestPenaltyScope(t *testing.T) {
	saved := nonbanlist
	defer func() { nonbanlist = saved }()
	nonbanlist = nil
	cases := map[string]string{
		"203.0.113.9":           "203.0.113.9",
		"2001:db8:1:2::5":       "2001:db8:1:2::/64",
		"2001:db8:1:2:aaaa::ff": "2001:db8:1:2::/64",
		"":                      "",
		"not-an-ip":             "not-an-ip",
	}
	for in, want := range cases {
		if got := penalty_scope(in); got != want {
			t.Fatalf("penalty_scope(%q) = %q, want %q", in, got, want)
		}
	}
	nonbanlist = []string{"[2001:db8:1:2::77]:11011"} // a priority node shares the /64: score the /128 only
	if got := penalty_scope("2001:db8:1:2::5"); got != "2001:db8:1:2::5" {
		t.Fatalf("a /64 holding a never-ban node was scoped to %q", got)
	}
}

// An IPv6 peer banned by score must not get back in from the next address of its /64.
func TestPenaltyBanCoversIPv6Slash64(t *testing.T) {
	saved := nonbanlist
	defer func() { nonbanlist = saved }()
	nonbanlist = nil
	a, b := net.Pipe()
	defer b.Close()
	c := &Connection{Addr: &net.UDPAddr{IP: net.ParseIP("2001:db8:77:88::1"), Port: 11011}, Conn: a, ConnTls: a, logger: globals.Logger}
	for i := 0; i < 3; i++ {
		c.penalize("invalid_pow") // 2 x 50 reaches the ban score less a hair of decay between the calls; 3 always do
	}
	defer UnBan_Address("2001:db8:77:88::/64")
	if !IsAddressInBanList("2001:db8:77:88::1") {
		t.Fatal("the offending address is not banned")
	}
	if !IsAddressInBanList("2001:db8:77:88:ffff::9") {
		t.Fatal("ban evaded by moving to another address of the same /64")
	}
	if IsAddressInBanList("2001:db8:77:89::1") {
		t.Fatal("the ban spilled into the neighbouring /64")
	}
}

// TestAmplificationProbe measures bytes reflected per spoofed datagram: DERO_AMP_PROBE_SECS=40, DERO_AMP_OLD=1 for
// the upstream path, DERO_AMP_LOW=0 for the default KCP profile.
func TestAmplificationProbe(t *testing.T) {
	secs, _ := strconv.Atoi(os.Getenv("DERO_AMP_PROBE_SECS"))
	if secs == 0 {
		t.Skip("set DERO_AMP_PROBE_SECS to measure")
	}
	saved := P2PLowLatency
	defer func() { P2PLowLatency = saved }()
	P2PLowLatency = os.Getenv("DERO_AMP_LOW") != "0"
	l := start_inbound_listener(t, rpc2.NewServer(), os.Getenv("DERO_AMP_OLD") == "1")
	defer l.Close()
	times, total, sent := reflect(t, l, time.Duration(secs)*time.Second)
	var last time.Duration
	if len(times) > 0 {
		last = times[len(times)-1]
	}
	t.Logf("old_path=%v lowlatency=%v: 1 datagram of %d bytes drew %d datagrams, %d bytes in %ds (last at %v): x%.1f",
		os.Getenv("DERO_AMP_OLD") == "1", P2PLowLatency, sent, len(times), total, secs, last.Round(time.Millisecond), float64(total)/float64(sent))
}

// SEC-1: during the TLS handshake an accepted session retransmits with the default profile's doubling RTO, not the
// low-latency one: one spoofed ClientHello draws 6 datagrams within a 3 s deadline (8 without the switch; measured
// under -race in the r19 merge, 6/6/6 vs 8/8/8).
func TestInboundHandshakeUsesDefaultProfile(t *testing.T) {
	saved_timeout, saved_low := INBOUND_TLS_HANDSHAKE_TIMEOUT, P2PLowLatency
	defer func() { INBOUND_TLS_HANDSHAKE_TIMEOUT, P2PLowLatency = saved_timeout, saved_low }()
	INBOUND_TLS_HANDSHAKE_TIMEOUT = 3 * time.Second
	P2PLowLatency = true
	var default_profiles int32
	kcp_profile_hook = func(_ *kcp.UDPSession, lowlatency bool) {
		if !lowlatency {
			atomic.AddInt32(&default_profiles, 1)
		}
	}
	defer func() { kcp_profile_hook = nil }()
	l := start_inbound_listener(t, rpc2.NewServer(), false)
	defer l.Close()
	times, total, _ := reflect(t, l, 4*time.Second)
	// the datagram count alone is load-sensitive (6 vs 8 copies); the hook proves the inbound path chose the default
	// profile even with --lowlatency on
	if atomic.LoadInt32(&default_profiles) == 0 {
		t.Fatalf("the inbound handshake did not switch to the default KCP profile")
	}
	if len(times) == 0 || len(times) > 7 {
		t.Fatalf("one ClientHello drew %d datagrams (%d bytes) within the 3 s deadline, want 1..7: %v", len(times), total, times)
	}
}

// SEC-2: the accept loop's own code refuses a banned IP before the limiter is asked (the token stays for others)
func TestAcceptInboundRefusesBannedBeforeToken(t *testing.T) {
	l, err := kcp.ListenWithOptions("127.0.0.1:0", test_block(), 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	Ban_Address("127.0.0.1", 60)
	defer UnBan_Address("127.0.0.1")
	cs, err := kcp.DialWithOptions(l.Addr().String(), test_block(), 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	cs.Write([]byte("x")) // the listener creates the session on the first datagram
	l.SetDeadline(time.Now().Add(5 * time.Second))
	conn, err := l.AcceptKCP()
	if err != nil {
		t.Fatal(err)
	}
	limiter := rate.NewLimiter(rate.Every(time.Hour), 1)
	tlsconfig := &tls.Config{Certificates: []tls.Certificate{generate_random_tls_cert()}}
	if accept_inbound(rpc2.NewServer(), conn, tlsconfig, limiter) {
		t.Fatal("a banned IP was served")
	}
	if !limiter.Allow() {
		t.Fatal("the banned IP spent the accept token")
	}
}

// SEC-8: a complete chunked block carrying an undecodable tx (unknown type: decoder panic) scores "undecodable"
func TestChunkedBlockUndecodableTxPenalized(t *testing.T) {
	saved := nonbanlist
	defer func() { nonbanlist = saved }()
	nonbanlist = nil
	a, b := net.Pipe()
	defer b.Close()
	ip := "198.51.100.77"
	c := &Connection{Addr: &net.UDPAddr{IP: net.ParseIP(ip), Port: 11011}, Conn: a, ConnTls: a, logger: globals.Logger}
	penalty_mu.Lock()
	delete(penalty_map, ip)
	penalty_mu.Unlock()
	if _, err := c.decode_chunked_txs([][]byte{{0x01, 0x30, 0x30, 0x30, 0x30}}); err == nil {
		t.Fatal("an unknown-type tx decoded")
	}
	penalty_mu.Lock()
	m := penalty_map[ip]
	penalty_mu.Unlock()
	if m == nil || m.score < float64(PENALTY_POINTS["undecodable"])-1 {
		t.Fatalf("no undecodable penalty recorded: %+v", m)
	}
}
