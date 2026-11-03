package p2p

import (
	"bytes"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func large_frame(t *testing.T, size int) []byte {
	var buf bytes.Buffer
	if err := append_frame(&buf, bytes.Repeat([]byte{7}, size)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// r21 (R-4): bytes of large frames in flight on all connections together are bounded; a frame that would exceed the
// budget fails, a frame that completes releases its bytes, and small frames are never charged.
func TestFrameBudgetBoundsLargeFramesInFlight(t *testing.T) {
	saved := P2P_FRAME_BUDGET
	P2P_FRAME_BUDGET = 3 << 20
	defer func() { P2P_FRAME_BUDGET = saved }()
	if atomic.LoadInt64(&frame_budget_used) != 0 {
		t.Fatalf("budget not idle at start: %d", frame_budget_used)
	}

	// connection A: a 2 MiB frame of which only 2 MiB minus 64 KiB has arrived yet
	fa := large_frame(t, 2<<20)
	ra, wa := net.Pipe()
	defer ra.Close()
	defer wa.Close()
	cut := len(fa) - 64<<10
	go wa.Write(fa[:cut])
	resa := make(chan error, 1)
	var obja []byte
	go func() { resa <- Read_Data_Frame(ra, &obja) }()
	deadline := time.Now().Add(5 * time.Second)
	for atomic.LoadInt64(&frame_budget_used) < int64(cut-8) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	// connection B: another 2 MiB frame would take the total past 3 MiB
	fb := large_frame(t, 2<<20)
	rb, wb := net.Pipe()
	defer rb.Close()
	go func() { wb.Write(fb); wb.Close() }()
	var objb []byte
	before := frame_budget_refusals.Get()
	if err := Read_Data_Frame(rb, &objb); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("second large frame while the budget is held: err %v", err)
	}
	if frame_budget_refusals.Get() != before+1 {
		t.Fatal("refusal not counted")
	}

	// A completes and releases; then a new large frame fits again
	go wa.Write(fa[cut:])
	if err := <-resa; err != nil || len(obja) != 2<<20 {
		t.Fatalf("frame A: err %v len %d", err, len(obja))
	}
	if u := atomic.LoadInt64(&frame_budget_used); u != 0 {
		t.Fatalf("%d bytes still charged after both frames ended", u)
	}
	rc, wc := net.Pipe()
	defer rc.Close()
	fc := large_frame(t, 2<<20)
	go func() { wc.Write(fc); wc.Close() }()
	var objc []byte
	if err := Read_Data_Frame(rc, &objc); err != nil {
		t.Fatalf("large frame after release: %v", err)
	}
	// small frames never touch the budget
	P2P_FRAME_BUDGET = 1
	rd, wd := net.Pipe()
	defer rd.Close()
	fd := large_frame(t, 100<<10)
	go func() { wd.Write(fd); wd.Close() }()
	var objd []byte
	if err := Read_Data_Frame(rd, &objd); err != nil || len(objd) != 100<<10 {
		t.Fatalf("small frame charged against the budget: %v", err)
	}
}

type plain_reader struct{ r *bytes.Reader }

func (p plain_reader) Read(b []byte) (int, error) { return p.r.Read(b) }

// Honest-path cost of the budget on a 2 MiB frame body: the same ReadFrom through budget_reader vs a plain reader.
func benchmark_frame_body(b *testing.B, budget bool) {
	body := bytes.Repeat([]byte{7}, 2<<20)
	var buf bytes.Buffer
	b.SetBytes(int64(len(body)))
	for i := 0; i < b.N; i++ {
		buf.Reset()
		var src interface{ Read([]byte) (int, error) } = plain_reader{bytes.NewReader(body)}
		if budget {
			br := &budget_reader{r: src}
			src = br
			buf.ReadFrom(src)
			br.release()
		} else {
			buf.ReadFrom(src)
		}
	}
}

func BenchmarkFrameBodyPlain(b *testing.B)  { benchmark_frame_body(b, false) }
func BenchmarkFrameBodyBudget(b *testing.B) { benchmark_frame_body(b, true) }

// r21 merge (SEC21-05 fairness fix): inbound peers holding the whole inbound pool cannot starve connections we dialed.
// With the inbound pool full, a large frame on an outbound (self-dialed) codec is still read, while one on an inbound
// codec is refused; the outbound pool is released afterwards.
func TestFrameBudgetOutboundPoolNotStarvedByInbound(t *testing.T) {
	saved := P2P_FRAME_BUDGET
	defer func() { P2P_FRAME_BUDGET = saved }()
	P2P_FRAME_BUDGET = 4 << 20
	atomic.AddInt64(&frame_budget_used, P2P_FRAME_BUDGET) // ~10 inbound attackers hold the inbound pool
	defer atomic.AddInt64(&frame_budget_used, -P2P_FRAME_BUDGET)

	read := func(outbound bool) error {
		a, b := net.Pipe()
		defer a.Close()
		f := large_frame(t, 2<<20)
		go func() { b.Write(f); b.Close() }()
		codec, _ := counted_codec(a, outbound)
		var obj []byte
		return Read_Data_Frame(codec.r, &obj)
	}
	if err := read(true); err != nil {
		t.Fatalf("outbound large frame refused while only the inbound pool is full: %v", err)
	}
	if u := atomic.LoadInt64(&frame_budget_used_outbound); u != 0 {
		t.Fatalf("outbound pool not released: %d", u)
	}
	if err := read(false); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("inbound large frame read past a full inbound pool: %v", err)
	}
	// the outbound path (the only caller with a dialed connection) must build its codec as outbound
	src, err := os.ReadFile("controller.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "codec, traffic := counted_codec(tlsconn, !incoming)") ||
		!strings.Contains(string(src), "codec, traffic := counted_codec(tlsconn, false)") {
		t.Fatal("process_outgoing_connection / serve_inbound do not mark the codec direction")
	}
}
