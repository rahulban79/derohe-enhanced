package p2p

// this file implements CBOR codec to prevent from certain attacks
import "fmt"
import "bytes"
import "io"
import "net"
import "sync"
import "time"
import "github.com/cenkalti/rpc2"
import "encoding/binary"
import "github.com/fxamacker/cbor/v2"

import "github.com/deroproject/derohe/config" // only used get constants such as max data per frame
import "github.com/deroproject/derohe/metrics"
import "errors"
import "sync/atomic"

// Node-wide byte budget for large inbound frames (r21, security; r20 residual R-4). A frame may be up to
// 5*STARGATE_HE_MAX_BLOCK_SIZE (51.25 MiB) and every connection reads its own, so ~101 peers streaming maximum frames
// at once could make the node hold ~5.2 GB of frame buffers (estimate, r20 SEC20-11). Bytes of frames larger than
// MAX_POOLED_FRAME are now charged, as they arrive, against P2P_FRAME_BUDGET shared by all connections; a frame that
// would push the total past it fails (and its connection closes, as for any read error) and its bytes are released.
// Honest traffic is far below it: chunked blocks travel in frames under 1 MiB, and only sync replies carrying whole
// large blocks exceed that. Cost on the honest path: one atomic add per Read of a large frame, none for small frames.
var P2P_FRAME_BUDGET = int64(env_int("DERO_P2P_FRAME_BUDGET_MB", 512, 64, 1<<16)) << 20

var frame_budget_used int64 // bytes of large frames being read right now, all inbound connections

// frame_budget_used_outbound is a separate pool of the same size for connections WE dialed (r21 merge, SEC21-05
// fairness fix). With one shared pool ~10 inbound attackers (512 MiB / 51.25 MiB frames held for READ_TIMEOUT) could
// keep it full and every honest large sync reply would be refused. Inbound peers cannot draw on this pool, so they
// cannot starve the outbound peers the node syncs from. Worst case is now 2 x P2P_FRAME_BUDGET of frames being read
// (in-flight reads only; decoded objects still being processed after Read_Data_Frame returns are not bounded here).
var frame_budget_used_outbound int64

var err_frame_budget = errors.New("node-wide large-frame budget exhausted (DERO_P2P_FRAME_BUDGET_MB)")

var frame_budget_refusals = metrics.Set.NewCounter("p2p_frame_budget_refusals_total")

var _ = metrics.Set.NewGauge("p2p_frame_budget_used_bytes", func() float64 { return float64(atomic.LoadInt64(&frame_budget_used)) })

var _ = metrics.Set.NewGauge("p2p_frame_budget_outbound_used_bytes", func() float64 {
	return float64(atomic.LoadInt64(&frame_budget_used_outbound))
})

// frame_budget_pool picks the pool a connection's large frames are charged to: the outbound pool for a codec built
// by process_outgoing_connection (counted_codec(.., true)), the inbound pool for everything else.
func frame_budget_pool(r net.Conn) *int64 {
	if cc, ok := r.(counting_conn); ok && cc.t != nil && cc.t.outbound {
		return &frame_budget_used_outbound
	}
	return &frame_budget_used
}

// budget_reader charges every byte it reads to frame_budget_used; release returns them.
type budget_reader struct {
	r       io.Reader
	charged int64
	pool    *int64 // nil: the inbound pool
}

func (b *budget_reader) used() *int64 {
	if b.pool == nil {
		return &frame_budget_used
	}
	return b.pool
}

func (b *budget_reader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if n > 0 {
		if atomic.AddInt64(b.used(), int64(n)) > P2P_FRAME_BUDGET {
			atomic.AddInt64(b.used(), -int64(n))
			frame_budget_refusals.Inc()
			return 0, err_frame_budget
		}
		b.charged += int64(n)
	}
	return n, err
}

func (b *budget_reader) release() {
	atomic.AddInt64(b.used(), -b.charged)
	b.charged = 0
}

// it processes both
type RequestResponse struct {
	Method string `cbor:"M"` // format: "Service.Method"
	Seq    uint64 `cbor:"S"` // echoes that of the request
	Error  string `cbor:"E"` // error, if any.
}

const READ_TIMEOUT = 20 * time.Second

const MAX_POOLED_FRAME = 1 << 20 // frame buffers larger than this are left to the GC instead of the pool
const WRITE_TIMEOUT = 20 * time.Second

var bufPool = &sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// reads our data, length prefix blocks
func Read_Data_Frame(r net.Conn, obj interface{}) error {
	var frame_length_buf [4]byte

	//connection.set_timeout()
	r.SetReadDeadline(time.Now().Add(READ_TIMEOUT))
	nbyte, err := io.ReadFull(r, frame_length_buf[:])
	if err != nil {
		return err
	}
	if nbyte != 4 {
		return fmt.Errorf("needed 4 bytes, but got %d bytes", nbyte)
	}

	//  time to ban
	frame_length := binary.LittleEndian.Uint32(frame_length_buf[:])
	if frame_length == 0 {
		return nil
	}
	// most probably memory DDOS attack, kill the connection
	if uint64(frame_length) > (5 * config.STARGATE_HE_MAX_BLOCK_SIZE) {
		return fmt.Errorf("Frame length is too big Expected %d Actual %d", 5*config.STARGATE_HE_MAX_BLOCK_SIZE, frame_length)
	}

	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer func() {
		if buf.Cap() <= MAX_POOLED_FRAME { // a pooled 50 MB buffer would stay resident for the life of the process
			bufPool.Put(buf)
		}
	}()

	// The length prefix is the peer's claim. Upstream grew the buffer to it before reading, so a prefix of ~51 MB
	// reserved ~51 MB while the bytes could trickle in for READ_TIMEOUT (discovery p2p-security-04). Read through a
	// LimitReader instead: memory grows only with bytes that actually arrive.
	var src io.Reader = r
	if frame_length > MAX_POOLED_FRAME { // r21: large frames draw on the node-wide budget as their bytes arrive
		br := &budget_reader{r: r, pool: frame_budget_pool(r)}
		defer br.release()
		src = br
	}
	n, err := buf.ReadFrom(io.LimitReader(src, int64(frame_length)))
	data_size := int(n)
	if err == nil && uint32(data_size) != frame_length {
		err = io.ErrUnexpectedEOF // the connection ended early; LimitReader reports that as a clean EOF
		if data_size == 0 {
			err = io.EOF // what upstream's io.ReadFull said when no body byte arrived: keep the log text identical
		}
	}
	if err != nil || data_size <= 0 || uint32(data_size) != frame_length {
		return fmt.Errorf("Could not read data size  read %d, frame length %d err %s", data_size, frame_length, err)
	}
	data_buf := buf.Bytes()[:frame_length]
	err = cbor.Unmarshal(data_buf, obj)

	//fmt.Printf("Read object %+v raw %s\n",obj, data_buf)
	return err
}

// Write_Data_Frame writes one length-prefixed CBOR frame with a single Write.
func Write_Data_Frame(w net.Conn, obj interface{}) error {
	return write_frames(w, obj)
}

// append_frame appends obj as one frame (4-byte little-endian length, then CBOR bytes) to buf.
//
// r18: the body is encoded straight into buf behind a reserved length field, which is patched afterwards. Upstream
// called cbor.Marshal, which encodes into the library's pooled buffer, copies that into a NEW slice of exactly the
// body's size (vendor/github.com/fxamacker/cbor/v2/encode.go Marshal: make+copy), and append_frame then copied it a
// second time into buf: one heap allocation and one copy of every body per frame (a whole block for a GetObject
// response). (*Encoder).Encode runs the same encode() with the same default EncMode and Writes its pooled buffer once
// (stream.go Encode), so the wire bytes are identical (TestAppendFrameByteIdentical).
func append_frame(buf *bytes.Buffer, obj interface{}) error {
	start := buf.Len()
	var frame_length_buf [4]byte
	buf.Write(frame_length_buf[:])
	if err := cbor.NewEncoder(buf).Encode(obj); err != nil {
		buf.Truncate(start) // no half frame: callers return the error and never send buf
		return err
	}
	binary.LittleEndian.PutUint32(buf.Bytes()[start:start+4], uint32(buf.Len()-start-4))
	return nil
}

// write_frames encodes every object as a frame and hands the whole message to the connection in ONE Write.
//
// Why (propagation latency, r17): the connection is TLS over KCP. Each Write on a tls.Conn becomes one TLS record and
// each record one kcp Write, which kcp-go flushes as its own segment and UDP packet when write-delay is off (the
// default; sess.go WriteBuffers flushes on !s.writeDelay). Upstream wrote a request as four Writes (header length,
// header, body length, body), so a ~200-byte NotifyMiniBlock left as four packets, and the peer could act on it only
// when all four had arrived. Live KCP counters show ~6.9% of segments retransmitted, almost all by RTO, and a lost
// tail segment can never be fast-retransmitted (nothing follows it), so P(miniblock RPC delayed by >= 1 RTO) fell
// from 1-(1-p)^4 ~ 25% to p ~ 7%. The byte stream is IDENTICAL; only its packetisation changes, and kcp-go's Read
// returns a message across several reads (sess.go bufptr), so upstream peers decode it unchanged.
func write_frames(w net.Conn, objs ...interface{}) error {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer func() {
		if buf.Cap() <= MAX_POOLED_FRAME {
			bufPool.Put(buf)
		}
	}()
	for _, obj := range objs {
		if err := append_frame(buf, obj); err != nil {
			return err
		}
	}
	w.SetWriteDeadline(time.Now().Add(WRITE_TIMEOUT))
	_, err := w.Write(buf.Bytes())
	return err
}

// ClientCodec implements the rpc.ClientCodec interface for generic golang objects.
type ClientCodec struct {
	r net.Conn
	sync.Mutex
}

// NewClientCodec returns a ClientCodec for communicating with the ServerCodec
// on the other end of the conn.
// to support deadlines we use net.conn
func NewCBORCodec(conn net.Conn) *ClientCodec {
	return &ClientCodec{r: conn}
}

// ReadResponseHeader reads a 4 byte length from the connection and decodes that many
// subsequent bytes into the given object, decodes it, and stores the fields
// in the given request.
func (c *ClientCodec) ReadResponseHeader(resp *rpc2.Response) error {
	var header RequestResponse
	if err := Read_Data_Frame(c.r, &header); err != nil {
		return err
	}
	//if header.Method == "" {
	//	return fmt.Errorf("header missing method: %s", "no Method")
	//}
	//resp.Method = header.Method
	resp.Seq = header.Seq
	resp.Error = header.Error

	return nil
}

// Close closes the underlying connection.
func (c *ClientCodec) Close() error {
	return c.r.Close()
}

// ReadRequestHeader reads the header (which is prefixed by a 4 byte lil endian length
// indicating its size) from the connection, decodes it, and stores the fields
// in the given request.
func (s *ClientCodec) ReadHeader(req *rpc2.Request, resp *rpc2.Response) error {
	var header RequestResponse
	if err := Read_Data_Frame(s.r, &header); err != nil {
		return err
	}

	if header.Method != "" {
		req.Seq = header.Seq
		req.Method = header.Method
	} else {
		resp.Seq = header.Seq
		resp.Error = header.Error
	}
	return nil
}

// ReadRequestBody reads a 4 byte length from the connection and decodes that many
// subsequent bytes into the object
func (s *ClientCodec) ReadRequestBody(obj interface{}) error {
	if obj == nil {
		return nil
	}
	return Read_Data_Frame(s.r, obj)
}

// ReadResponseBody reads a 4 byte length from the connection and decodes that many
// subsequent bytes into the given object (which should be a pointer to a
// struct).
func (c *ClientCodec) ReadResponseBody(obj interface{}) error {
	if obj == nil {
		return nil
	}
	return Read_Data_Frame(c.r, obj)
}

// WriteRequest writes the 4 byte length from the connection and encodes that many
// subsequent bytes into the given object.
func (c *ClientCodec) WriteRequest(req *rpc2.Request, obj interface{}) error {
	c.Lock()
	defer c.Unlock()

	header := RequestResponse{Method: req.Method, Seq: req.Seq}
	return write_frames(c.r, header, obj) // header and body in one Write: one TLS record, one KCP segment when small
}

// WriteResponse writes the appropriate header. If
// the response was invalid, the size of the body of the resp is reported as
// having size zero and is not sent.
func (c *ClientCodec) WriteResponse(resp *rpc2.Response, obj interface{}) error {
	c.Lock()
	defer c.Unlock()
	header := RequestResponse{Seq: resp.Seq, Error: resp.Error}
	if resp.Error == "" { // only write response object if error is nil
		return write_frames(c.r, header, obj)
	}
	return write_frames(c.r, header)
}
