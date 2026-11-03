package p2p

// r19 fuzz targets for everything a peer's bytes reach before any consensus check: the frame reader and CBOR decode
// of every wire struct, Verify_Handshake, and the block / miniblock / transaction decoders the handlers call. Seeds
// run in every `go test`; `go test -fuzz=FuzzX -fuzztime=60s ./p2p/` explores further.

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/transaction"
	"github.com/fxamacker/cbor/v2"
)

// bytesConn serves a fixed byte string as a net.Conn read side.
type bytesConn struct {
	net.Conn
	r *bytes.Reader
}

func (b *bytesConn) Read(p []byte) (int, error)       { return b.r.Read(p) }
func (b *bytesConn) SetReadDeadline(time.Time) error  { return nil }
func (b *bytesConn) SetWriteDeadline(time.Time) error { return nil }
func (b *bytesConn) Close() error                     { return nil }

func frame(body []byte) []byte {
	var l [4]byte
	binary.LittleEndian.PutUint32(l[:], uint32(len(body)))
	return append(l[:], body...)
}

func FuzzWireFrames(f *testing.F) {
	h := Handshake_Struct{ProtocolVersion: "1.0.0", DaemonVersion: "3.6.0-153.DEROHE.STARGATE+22102026.r18", Local_Port: 11011,
		PeerList: []Peer_Info{{Addr: "198.51.100.1:11011"}}}
	seed, _ := cbor.Marshal(h)
	f.Add(seed)
	o := sample_miniblock_request()
	seed2, _ := cbor.Marshal(o)
	f.Add(seed2)
	f.Add([]byte{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // array claiming 2^64-1 elements
	f.Add([]byte{0xbf, 0x61, 0x41, 0xff})
	f.Fuzz(func(t *testing.T, body []byte) {
		targets := []interface{}{&Handshake_Struct{}, &Chain_Request_Struct{}, &Chain_Response_Struct{}, &ObjectList{},
			&Objects{}, &ChangeList{}, &Changes{}, &Request_Tree_Section_Struct{}, &Response_Tree_Section_Struct{},
			&RequestResponse{}, &Dummy{}}
		for _, obj := range targets {
			if err := Read_Data_Frame(&bytesConn{r: bytes.NewReader(frame(body))}, obj); err != nil {
				continue
			}
			if hs, ok := obj.(*Handshake_Struct); ok {
				Verify_Handshake(hs)
			}
		}
	})
}

func FuzzChainDecoders(f *testing.F) {
	o := sample_miniblock_request()
	f.Add(o.MiniBlocks[0])
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, 96))
	f.Fuzz(func(t *testing.T, data []byte) {
		var mbl block.MiniBlock
		mbl.Deserialize(data)
		var bl block.Block
		bl.Deserialize(data)
		var tx transaction.Transaction
		deserialize_tx(&tx, data) // the raw decoder panics on an unknown tx type (consensus code, left alone)
	})
}

// the p2p wrapper must turn the decoder's panic into an error the callers' error branches handle
func TestDeserializeTxPanicBecomesError(t *testing.T) {
	var tx transaction.Transaction
	if err := deserialize_tx(&tx, []byte("\x010000")); err == nil {
		t.Fatal("an unknown transaction type decoded without error")
	}
}
