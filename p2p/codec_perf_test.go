package p2p

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// append_frame_marshal is the pre-r18 append_frame (cbor.Marshal into a fresh slice, then copied into buf). It is kept
// here only as the reference the byte-identity test and the benchmarks compare append_frame against.
func append_frame_marshal(buf *bytes.Buffer, obj interface{}) error {
	data_bytes, err := cbor.Marshal(obj)
	if err != nil {
		return err
	}
	var frame_length_buf [4]byte
	binary.LittleEndian.PutUint32(frame_length_buf[:], uint32(len(data_bytes)))
	buf.Write(frame_length_buf[:])
	buf.Write(data_bytes)
	return nil
}

func perf_sample_mini() (RequestResponse, Objects) {
	var o Objects
	o.Common.Height = 7_600_000
	o.Common.TopoHeight = 7_650_000
	o.Common.StateHash[3] = 0xab
	o.Common.T0 = time.Now().UnixMicro()
	o.Common.Top_Version = 3
	o.Sent = time.Now().UnixMicro()
	o.MiniBlocks = [][]byte{bytes.Repeat([]byte{0x5a}, 48)}
	return RequestResponse{Method: "Peer.NotifyMiniBlock", Seq: 123456}, o
}

func perf_sample_block() (RequestResponse, Objects) {
	var o Objects
	o.Common.Height = 7_600_000
	o.Common.Top_Version = 3
	cb := Complete_Block{Block: bytes.Repeat([]byte{1}, 1200), Difficulty: "123456789012"}
	for i := 0; i < 20; i++ {
		cb.Txs = append(cb.Txs, bytes.Repeat([]byte{byte(i)}, 2500))
	}
	o.CBlocks = []Complete_Block{cb}
	return RequestResponse{Seq: 99}, o
}

func perf_sample_peers() (RequestResponse, Dummy) {
	var d Dummy
	d.Common.Height = 7_600_000
	for i := 0; i < 31; i++ {
		d.Common.PeerList = append(d.Common.PeerList, Peer_Info{Addr: "203.0.113.45:11011", Miner: i%3 == 0})
	}
	return RequestResponse{Seq: 7}, d
}

// TestAppendFrameByteIdentical proves the r18 encoder path puts exactly the bytes the Marshal path did on the wire,
// for every message shape the node sends (small notification, large block, peer list, error header, nil body).
func TestAppendFrameByteIdentical(t *testing.T) {
	h1, b1 := perf_sample_mini()
	h2, b2 := perf_sample_block()
	h3, b3 := perf_sample_peers()
	cases := [][]interface{}{{h1, b1}, {h2, b2}, {h3, b3}, {RequestResponse{Seq: 5, Error: "boom"}}, {h1, nil}, {h1, &b1}}
	for i, objs := range cases {
		var want, got bytes.Buffer
		got.WriteString("prefix") // append_frame must patch its own length field, not offset 0
		want.WriteString("prefix")
		for _, o := range objs {
			if err := append_frame_marshal(&want, o); err != nil {
				t.Fatal(err)
			}
			if err := append_frame(&got, o); err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(want.Bytes(), got.Bytes()) {
			t.Fatalf("case %d: frames differ\nwant %x\n got %x", i, want.Bytes(), got.Bytes())
		}
	}
	// an encode error must leave buf exactly as it was (no dangling length prefix)
	var buf bytes.Buffer
	buf.WriteString("keep")
	if err := append_frame(&buf, make(chan int)); err == nil {
		t.Fatal("expected unsupported-type error")
	}
	if buf.String() != "keep" {
		t.Fatalf("buffer not rolled back on error: %q", buf.String())
	}
}

type frameConn struct {
	net.Conn
	r *bytes.Reader
}

func (c *frameConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c *frameConn) SetReadDeadline(time.Time) error  { return nil }
func (c *frameConn) SetWriteDeadline(time.Time) error { return nil }
func (c *frameConn) Write(p []byte) (int, error)      { return len(p), nil }

func bench_encode(b *testing.B, f func(*bytes.Buffer, interface{}) error, h, body interface{}) {
	var buf bytes.Buffer
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := f(&buf, h); err != nil {
			b.Fatal(err)
		}
		if err := f(&buf, body); err != nil {
			b.Fatal(err)
		}
	}
	b.SetBytes(int64(buf.Len()))
}

func BenchmarkFrameEncodeMini_Marshal(b *testing.B) {
	h, o := perf_sample_mini()
	bench_encode(b, append_frame_marshal, h, o)
}
func BenchmarkFrameEncodeMini_Encoder(b *testing.B) {
	h, o := perf_sample_mini()
	bench_encode(b, append_frame, h, o)
}
func BenchmarkFrameEncodeBlock_Marshal(b *testing.B) {
	h, o := perf_sample_block()
	bench_encode(b, append_frame_marshal, h, o)
}
func BenchmarkFrameEncodeBlock_Encoder(b *testing.B) {
	h, o := perf_sample_block()
	bench_encode(b, append_frame, h, o)
}

func bench_decode(b *testing.B, h RequestResponse, body Objects) {
	var buf bytes.Buffer
	if err := append_frame(&buf, h); err != nil {
		b.Fatal(err)
	}
	if err := append_frame(&buf, body); err != nil {
		b.Fatal(err)
	}
	wire := buf.Bytes()
	c := &frameConn{r: bytes.NewReader(wire)}
	b.SetBytes(int64(len(wire)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.r.Reset(wire)
		var hh RequestResponse
		var oo Objects
		if err := Read_Data_Frame(c, &hh); err != nil {
			b.Fatal(err)
		}
		if err := Read_Data_Frame(c, &oo); err != nil && err != io.EOF {
			b.Fatal(err)
		}
	}
}

func BenchmarkFrameDecodeMini(b *testing.B) {
	h, o := perf_sample_mini()
	bench_decode(b, h, o)
}
func BenchmarkFrameDecodeBlock(b *testing.B) {
	h, o := perf_sample_block()
	bench_decode(b, h, o)
}
