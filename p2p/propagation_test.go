package p2p

// r17 propagation tests: one Write per RPC message (codec coalescing), byte-identical wire format, and the
// miniblock delivery/ack instrumentation.

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cenkalti/rpc2"
	"github.com/deroproject/derohe/block"
	"github.com/fxamacker/cbor/v2"
	"github.com/xtaci/kcp-go/v5"
)

// recordConn counts Writes and keeps the bytes; every other net.Conn method is a no-op.
type recordConn struct {
	net.Conn
	mu     sync.Mutex
	writes int
	buf    bytes.Buffer
}

func (r *recordConn) Write(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writes++
	return r.buf.Write(b)
}
func (r *recordConn) SetWriteDeadline(time.Time) error { return nil }
func (r *recordConn) Close() error                     { return nil }

// legacy_write_frame is the upstream Write_Data_Frame (two Writes per frame), kept here as the wire-format oracle.
func legacy_write_frame(w io.Writer, obj interface{}) error {
	data, err := cbor.Marshal(obj)
	if err != nil {
		return err
	}
	var l [4]byte
	binary.LittleEndian.PutUint32(l[:], uint32(len(data)))
	if _, err = w.Write(l[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func sample_miniblock_request() Objects {
	var mbl block.MiniBlock
	mbl.Version = 1
	mbl.Height = 7799408
	mbl.PastCount = 1
	mbl.Past[0] = 0x7ddab053
	mbl.Timestamp = 46643
	mbl.Nonce = [3]uint32{1, 2, 3}
	var o Objects
	o.MiniBlocks = append(o.MiniBlocks, mbl.Serialize())
	o.Sent = 1792769357430000
	o.Common.Height = 7799408
	o.Common.TopoHeight = 7799408
	o.Common.T0 = 1792769357430000
	return o
}

func TestWriteRequestIsOneWriteAndByteIdentical(t *testing.T) {
	obj := sample_miniblock_request()
	rc := &recordConn{}
	codec := NewCBORCodec(rc)
	req := &rpc2.Request{Method: "Peer.NotifyMiniBlock", Seq: 42}
	if err := codec.WriteRequest(req, obj); err != nil {
		t.Fatal(err)
	}
	if rc.writes != 1 {
		t.Fatalf("WriteRequest made %d Writes, want 1 (each Write is a TLS record and a KCP segment)", rc.writes)
	}
	var want bytes.Buffer
	legacy_write_frame(&want, RequestResponse{Method: req.Method, Seq: req.Seq})
	legacy_write_frame(&want, obj)
	if !bytes.Equal(rc.buf.Bytes(), want.Bytes()) {
		t.Fatalf("wire bytes changed:\n got %x\nwant %x", rc.buf.Bytes(), want.Bytes())
	}
	t.Logf("NotifyMiniBlock request: %d bytes in 1 Write (upstream: same bytes in 4 Writes)", rc.buf.Len())
}

func TestWriteResponseIsOneWriteAndByteIdentical(t *testing.T) {
	for _, tc := range []struct {
		name string
		resp rpc2.Response
		obj  interface{}
	}{
		{"ok", rpc2.Response{Seq: 7}, Dummy{}},
		{"error", rpc2.Response{Seq: 8, Error: "busy"}, Dummy{}}, // body is not sent on error, as upstream
	} {
		rc := &recordConn{}
		if err := NewCBORCodec(rc).WriteResponse(&tc.resp, tc.obj); err != nil {
			t.Fatal(err)
		}
		if rc.writes != 1 {
			t.Fatalf("%s: %d Writes, want 1", tc.name, rc.writes)
		}
		var want bytes.Buffer
		legacy_write_frame(&want, RequestResponse{Seq: tc.resp.Seq, Error: tc.resp.Error})
		if tc.resp.Error == "" {
			legacy_write_frame(&want, tc.obj)
		}
		if !bytes.Equal(rc.buf.Bytes(), want.Bytes()) {
			t.Fatalf("%s: wire bytes changed", tc.name)
		}
	}
}

// the coalesced message must decode with the unchanged reader, frame by frame
func TestCoalescedFramesDecodeWithUpstreamReader(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	obj := sample_miniblock_request()
	go write_frames(b, RequestResponse{Method: "Peer.NotifyMiniBlock", Seq: 9}, obj)
	var h RequestResponse
	if err := Read_Data_Frame(a, &h); err != nil || h.Method != "Peer.NotifyMiniBlock" || h.Seq != 9 {
		t.Fatalf("header: %+v %v", h, err)
	}
	var got Objects
	if err := Read_Data_Frame(a, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.MiniBlocks) != 1 || !bytes.Equal(got.MiniBlocks[0], obj.MiniBlocks[0]) || got.Sent != obj.Sent {
		t.Fatalf("body mismatch: %+v", got)
	}
}

// Over the production transport (KCP with FEC 10/3, low-latency tuning, TLS on top) count the KCP segments one
// NotifyMiniBlock request costs: upstream's 4 Writes vs the coalesced single Write.
func TestKCPSegmentsPerMiniblockRequest(t *testing.T) {
	saved := P2PLowLatency
	P2PLowLatency = true
	defer func() { P2PLowLatency = saved }()

	l, err := kcp.ListenWithOptions("127.0.0.1:0", nil, 10, 3)
	if err != nil {
		t.Skip("cannot listen on loopback UDP:", err)
	}
	defer l.Close()
	cert := generate_random_tls_cert()

	server_done := make(chan error, 1)
	var received int64
	go func() {
		conn, err := l.AcceptKCP()
		if err != nil {
			server_done <- err
			return
		}
		tunekcp(conn)
		s := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		buf := make([]byte, 64*1024)
		for {
			n, err := s.Read(buf)
			atomic.AddInt64(&received, int64(n))
			if err != nil {
				server_done <- nil
				return
			}
		}
	}()

	conn, err := kcp.DialWithOptions(l.Addr().String(), nil, 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tunekcp(conn)
	c := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // let handshake ACKs settle

	obj := sample_miniblock_request()
	header := RequestResponse{Method: "Peer.NotifyMiniBlock", Seq: 1}

	// kcp-go's DefaultSnmp is process-wide and counts BOTH ends here: OutSegs includes the server's ACK segments
	// (kcp.go segment.encode counts every segment it encodes) and OutPkts every UDP datagram. On loopback there is
	// no loss, so each data segment costs one data packet plus one ACK packet; compare the totals as ratios.
	type cost struct{ segs, pkts, retrans uint64 }
	measure := func(send func()) cost {
		s0, p0, r0 := atomic.LoadUint64(&kcp.DefaultSnmp.OutSegs), atomic.LoadUint64(&kcp.DefaultSnmp.OutPkts), atomic.LoadUint64(&kcp.DefaultSnmp.RetransSegs)
		send()
		time.Sleep(200 * time.Millisecond)
		return cost{atomic.LoadUint64(&kcp.DefaultSnmp.OutSegs) - s0, atomic.LoadUint64(&kcp.DefaultSnmp.OutPkts) - p0, atomic.LoadUint64(&kcp.DefaultSnmp.RetransSegs) - r0}
	}
	// DefaultSnmp is process-wide: KCP sessions of earlier tests (or a loaded box) can retransmit inside the window,
	// so re-measure a few times and only skip when every attempt saw a retransmission.
	var legacy, coalesced cost
	for attempt := 0; attempt < 5; attempt++ {
		legacy = measure(func() {
			legacy_write_frame(c, header)
			legacy_write_frame(c, obj)
		})
		coalesced = measure(func() {
			write_frames(c, header, obj)
		})
		if legacy.retrans == 0 && coalesced.retrans == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Logf("one NotifyMiniBlock request incl. peer ACKs: upstream %d segments/%d UDP packets, coalesced %d segments/%d UDP packets (retrans %d/%d)",
		legacy.segs, legacy.pkts, coalesced.segs, coalesced.pkts, legacy.retrans, coalesced.retrans)
	if legacy.retrans != 0 || coalesced.retrans != 0 {
		t.Skip("retransmission on loopback; counts not comparable")
	}
	if coalesced.segs != 2 { // 1 data segment + 1 ACK
		t.Fatalf("coalesced request: %d segments, want 2 (1 data + 1 ACK)", coalesced.segs)
	}
	if legacy.segs != 4*coalesced.segs {
		t.Fatalf("upstream framing: %d segments, want 4x coalesced (%d)", legacy.segs, 4*coalesced.segs)
	}
}

func TestMiniblockAckMetricSeparatesOwnFromRelay(t *testing.T) {
	if miniblock_ack_metric(0) == miniblock_ack_metric(5) {
		t.Fatal("own and relayed miniblocks must be measured apart")
	}
}

func TestMiniblockDeliveryStatsOrdersByFirstDeliveries(t *testing.T) {
	mk := func(ip string, id uint64, lat time.Duration) *Connection {
		c := &Connection{Peer_ID: id, Addr: &net.UDPAddr{IP: net.ParseIP(ip), Port: 11011}}
		c.State.Store(ACTIVE)
		c.Latency.Store(int64(lat))
		connection_map.Store(Address(c), c)
		return c
	}
	slow_first := mk("10.9.0.1", 9001, 200*time.Millisecond)
	fast_dup := mk("10.9.0.2", 9002, 20*time.Millisecond)
	idle := mk("10.9.0.3", 9003, 5*time.Millisecond)
	defer func() {
		for _, c := range []*Connection{slow_first, fast_dup, idle} {
			connection_map.Delete(Address(c))
		}
	}()
	for i := 0; i < 5; i++ {
		slow_first.note_miniblock_delivery(true)
		fast_dup.note_miniblock_delivery(false)
	}
	fast_dup.note_miniblock_delivery(true)

	stats := MiniblockDeliveryStats()
	var mine []MiniblockDeliveryStat
	for _, s := range stats {
		if s.Addr == "10.9.0.1" || s.Addr == "10.9.0.2" || s.Addr == "10.9.0.3" {
			mine = append(mine, s)
		}
	}
	if len(mine) != 3 || mine[0].Addr != "10.9.0.1" || mine[0].First != 5 || mine[0].Total != 5 ||
		mine[1].Addr != "10.9.0.2" || mine[1].First != 1 || mine[1].Total != 6 || mine[2].Addr != "10.9.0.3" {
		t.Fatalf("unexpected order/counts: %+v", mine)
	}
}

// lossyProxy relays UDP between one client and a server, dropping each datagram with probability loss and
// delaying each by oneway, in both directions. It models the measured live path (6.9% segment retransmission).
type lossyProxy struct {
	pc      net.PacketConn
	server  *net.UDPAddr
	loss    float64
	oneway  time.Duration
	mu      sync.Mutex
	client  net.Addr
	up      *net.UDPConn
	rng     uint64
	dropped int64
}

func (p *lossyProxy) drop() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rng ^= p.rng << 13 // xorshift64: deterministic, so both framings face the same loss process
	p.rng ^= p.rng >> 7
	p.rng ^= p.rng << 17
	return float64(p.rng%1000000)/1000000 < p.loss
}

func (p *lossyProxy) run() {
	go func() { // server -> client
		buf := make([]byte, 65536)
		for {
			n, err := p.up.Read(buf)
			if err != nil {
				return
			}
			if p.drop() {
				atomic.AddInt64(&p.dropped, 1)
				continue
			}
			pkt := append([]byte(nil), buf[:n]...)
			p.mu.Lock()
			c := p.client
			p.mu.Unlock()
			time.AfterFunc(p.oneway, func() { p.pc.WriteTo(pkt, c) })
		}
	}()
	buf := make([]byte, 65536)
	for { // client -> server
		n, addr, err := p.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		p.mu.Lock()
		p.client = addr
		p.mu.Unlock()
		if p.drop() {
			atomic.AddInt64(&p.dropped, 1)
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		time.AfterFunc(p.oneway, func() { p.up.Write(pkt) })
	}
}

// Delivery time of one NotifyMiniBlock request (first Write -> body decoded by the peer's unchanged reader) over
// KCP+FEC+TLS through a lossy, delayed path: upstream 4-Write framing vs the coalesced single Write.
// Long-running; enable with R17_LOSSY=1.
func TestLossyPathMiniblockDeliveryLatency(t *testing.T) {
	if os.Getenv("R17_LOSSY") == "" {
		t.Skip("set R17_LOSSY=1 to run the lossy-path simulation")
	}
	saved := P2PLowLatency
	P2PLowLatency = true
	defer func() { P2PLowLatency = saved }()

	loss := 0.069
	if v, err := strconv.ParseFloat(os.Getenv("R17_LOSS"), 64); err == nil {
		loss = v
	}
	oneway := 40 * time.Millisecond
	trials := 300

	l, err := kcp.ListenWithOptions("127.0.0.1:0", nil, 10, 3)
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer pc.Close()
	saddr := l.Addr().(*net.UDPAddr)
	up, err := net.DialUDP("udp", nil, saddr)
	if err != nil {
		t.Fatal(err)
	}
	px := &lossyProxy{pc: pc, server: saddr, loss: loss, oneway: oneway, up: up, rng: 0x9E3779B97F4A7C15}
	go px.run()

	cert := generate_random_tls_cert()
	delivered := make(chan time.Time, 1)
	go func() {
		conn, err := l.AcceptKCP()
		if err != nil {
			return
		}
		tunekcp(conn)
		s := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		for {
			var h RequestResponse
			if err := Read_Data_Frame(s, &h); err != nil {
				return
			}
			var o Objects
			if err := Read_Data_Frame(s, &o); err != nil {
				return
			}
			delivered <- time.Now()
		}
	}()

	conn, err := kcp.DialWithOptions(pc.LocalAddr().String(), nil, 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tunekcp(conn)
	c := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	obj := sample_miniblock_request()
	header := RequestResponse{Method: "Peer.NotifyMiniBlock", Seq: 1}

	run := func(name string, send func()) []time.Duration {
		var d []time.Duration
		for i := 0; i < trials; i++ {
			start := time.Now()
			send()
			select {
			case at := <-delivered:
				d = append(d, at.Sub(start))
			case <-time.After(10 * time.Second):
				t.Fatalf("%s: trial %d not delivered", name, i)
			}
			time.Sleep(5 * time.Millisecond) // ACKs drain; a miniblock is an isolated burst on a quiet link
		}
		sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
		return d
	}
	summary := func(d []time.Duration) (mean, p50, p90, p99 time.Duration, late int) {
		var sum time.Duration
		for _, x := range d {
			sum += x
			if x > oneway+15*time.Millisecond { // anything beyond one clean one-way trip needed a retransmission
				late++
			}
		}
		return sum / time.Duration(len(d)), d[len(d)/2], d[len(d)*9/10], d[len(d)*99/100], late
	}
	// interleave blocks of trials so both framings see the same RTO state and loss sequence statistics
	var leg, coa []time.Duration
	for round := 0; round < 3; round++ {
		leg = append(leg, run("upstream", func() { legacy_write_frame(c, header); legacy_write_frame(c, obj) })...)
		coa = append(coa, run("coalesced", func() { write_frames(c, header, obj) })...)
	}
	sort.Slice(leg, func(i, j int) bool { return leg[i] < leg[j] })
	sort.Slice(coa, func(i, j int) bool { return coa[i] < coa[j] })
	lm, l50, l90, l99, llate := summary(leg)
	cm, c50, c90, c99, clate := summary(coa)
	t.Logf("path: one-way %s, loss %.1f%% each way, %d trials each (dropped %d datagrams)", oneway, loss*100, len(leg), atomic.LoadInt64(&px.dropped))
	t.Logf("upstream 4-Write : mean %v p50 %v p90 %v p99 %v late %.1f%%", lm.Round(100*time.Microsecond), l50.Round(100*time.Microsecond), l90.Round(100*time.Microsecond), l99.Round(100*time.Microsecond), 100*float64(llate)/float64(len(leg)))
	t.Logf("coalesced 1-Write: mean %v p50 %v p90 %v p99 %v late %.1f%%", cm.Round(100*time.Microsecond), c50.Round(100*time.Microsecond), c90.Round(100*time.Microsecond), c99.Round(100*time.Microsecond), 100*float64(clate)/float64(len(coa)))
	if cm > lm {
		t.Fatalf("coalesced framing slower on average (%v > %v)", cm, lm)
	}
}
