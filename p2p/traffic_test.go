package p2p

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"testing"
	"time"

	"github.com/cenkalti/rpc2"
)

// Frames written and read through the codec's counting_conn show up in both peers' counters and in GetPeerInfo.
func TestCodecTrafficCounted(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ta, tb := new(conn_traffic), new(conn_traffic)
	ca, cb := new_counting_conn(a, ta), new_counting_conn(b, tb)

	obj := ObjectList{Sent: 12345, Tx_list: [][32]byte{{1}, {2}, {3}}}
	var frame bytes.Buffer
	if err := append_frame(&frame, obj); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Write_Data_Frame(ca, obj) }()
	var got ObjectList
	if err := Read_Data_Frame(cb, &got); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got.Sent != obj.Sent || len(got.Tx_list) != 3 {
		t.Fatalf("frame did not round-trip: %+v", got)
	}
	n := uint64(frame.Len())
	if ta.out.Load() != n || tb.in.Load() != n || ta.in.Load() != 0 || tb.out.Load() != 0 {
		t.Fatalf("counters out=%d in=%d (want %d), reverse in=%d out=%d", ta.out.Load(), tb.in.Load(), n, ta.in.Load(), tb.out.Load())
	}

	c := &Connection{traffic: ta, Created: time.Now()}
	if pi := peer_info_of(c, time.Now()); pi.BytesOut != n || pi.BytesIn != 0 {
		t.Fatalf("GetPeerInfo shows in=%d out=%d, want 0/%d", pi.BytesIn, pi.BytesOut, n)
	}
	var none Connection // a connection built without a codec (tests, console) still reads 0, not a nil dereference
	if none.bytes_in() != 0 || none.bytes_out() != 0 {
		t.Fatal("nil traffic must read as 0")
	}
}

// r20 review (SP-5): the counters must be wired on BOTH connection paths. counted_codec counts what its codec
// carries, traffic_of hands an inbound session's counters to its Connection, and controller.go uses them in
// serve_inbound, the inbound OnConnect handler and process_outgoing_connection.
func TestTrafficWiredOnBothPaths(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	codec, tr := counted_codec(a, false)
	if codec == nil || tr == nil {
		t.Fatal("counted_codec returned nil")
	}
	go func() { buf := make([]byte, 64); b.Read(buf) }()
	if _, err := codec.r.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if tr.out.Load() != 5 {
		t.Fatalf("codec writes not counted: out=%d", tr.out.Load())
	}
	st := rpc2.NewState()
	st.Set(TRAFFIC_STATE_KEY, tr)
	if traffic_of(st) != tr || traffic_of(rpc2.NewState()) != nil || traffic_of(nil) != nil {
		t.Fatal("traffic_of does not return the session's counters")
	}

	f, err := parser.ParseFile(token.NewFileSet(), "controller.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string]map[string]int{}
	lit_traffic := map[string]bool{}
	assign_traffic := map[string]bool{}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := fd.Name.Name
		calls[name] = map[string]int{}
		ast.Inspect(fd, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				if id, ok := x.Fun.(*ast.Ident); ok {
					calls[name][id.Name]++
				}
			case *ast.CompositeLit:
				if id, ok := x.Type.(*ast.Ident); ok && id.Name == "Connection" {
					for _, e := range x.Elts {
						if kv, ok := e.(*ast.KeyValueExpr); ok {
							if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "traffic" {
								lit_traffic[name] = true
							}
						}
					}
				}
			case *ast.AssignStmt:
				for _, l := range x.Lhs {
					if s, ok := l.(*ast.SelectorExpr); ok && s.Sel.Name == "traffic" {
						assign_traffic[name] = true
					}
				}
			}
			return true
		})
	}
	if calls["serve_inbound"]["counted_codec"] != 1 || calls["process_outgoing_connection"]["counted_codec"] != 1 {
		t.Fatalf("both codec construction sites must use counted_codec: inbound=%d outbound=%d",
			calls["serve_inbound"]["counted_codec"], calls["process_outgoing_connection"]["counted_codec"])
	}
	if !lit_traffic["process_outgoing_connection"] {
		t.Fatal("outbound Connection is built without its traffic counters: GetPeerInfo would show 0 bytes")
	}
	if !assign_traffic["P2P_Server_v2"] || calls["P2P_Server_v2"]["traffic_of"] != 1 {
		t.Fatal("inbound Connection does not take its counters from the session state")
	}
}
