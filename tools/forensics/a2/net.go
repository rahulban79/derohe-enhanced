package main

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/bits"
	"os"
	"sync/atomic"
	"time"

	"github.com/cenkalti/rpc2"
	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/pbkdf2"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/p2p"
)

// peerFile is the PRIVATE file naming the source (never tracked, never printed): {"src-N": {"p2p": "host:port"}}.
type peerEntry struct {
	P2P string `json:"p2p"`
}

func loadPeer(path, name string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	m := map[string]peerEntry{}
	if err := json.Unmarshal(b, &m); err != nil {
		return "", err
	}
	e, ok := m[name]
	if !ok || e.P2P == "" {
		return "", fmt.Errorf("peer %s not in the peer file", name)
	}
	return e.P2P, nil
}

// limiter spaces calls at least 1/rate apart (one request in flight: calls are sequential).
type limiter struct {
	gap  time.Duration
	next time.Time
}

func newLimiter(rate float64) *limiter {
	if rate <= 0 || rate > 4 {
		rate = 4 // hard cap: one source, <= 4 req/s (rft §8 forensics-data: rate-limited)
	}
	return &limiter{gap: time.Duration(float64(time.Second) / rate)}
}

func (l *limiter) wait() {
	now := time.Now()
	if l.next.After(now) {
		time.Sleep(l.next.Sub(now))
		now = l.next
	}
	l.next = now.Add(l.gap)
}

type peerClient struct {
	name     string
	client   *rpc2.Client
	conn     *kcp.UDPSession
	lim      *limiter
	requests int64
	failures int64

	peerTopo    int64 // the source's own handshake claims (EXT)
	peerPruned  int64
	peerVersion string
}

// dialPeer opens ONE outgoing session the way derod does (p2p/controller.go:375-478: KCP with the network-id
// derived AES block cipher, TLS client, CBOR rpc2 codec) and performs the handshake (rpc_handshake.go:78-136).
// We advertise no port (Local_Port 0: we accept no inbound), no tag, no peer list, height 0.
func dialPeer(name, addr string, rate float64) (*peerClient, error) {
	masterkey := pbkdf2.Key(globals.Config.Network_ID.Bytes(), globals.Config.Network_ID.Bytes(), 1024, 32, sha1.New)
	blockcipher, err := kcp.NewAESBlockCrypt(masterkey)
	if err != nil {
		return nil, err
	}
	conn, err := kcp.DialWithOptions(addr, blockcipher, 10, 3)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed", name) // never the address
	}
	conn.SetACKNoDelay(true)
	conn.SetNoDelay(0, 40, 0, 0)
	conn.SetWindowSize(256, 256)
	conn.SetReadBuffer(1 << 20)
	conn.SetWriteBuffer(1 << 20)
	tlsconn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	tlsconn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tlsconn.Handshake(); err != nil { // explicit, so a dead source fails here with a clear stage name
		conn.Close()
		return nil, fmt.Errorf("tls handshake with %s failed: %v", name, err)
	}
	tlsconn.SetDeadline(time.Time{})
	client := rpc2.NewClientWithCodec(p2p.NewCBORCodec(tlsconn))
	// a peer may call us; answer the harmless ones, everything else gets rpc2's "method not found"
	client.Handle("Peer.Ping", func(_ *rpc2.Client, req p2p.Dummy, resp *p2p.Dummy) error {
		resp.Common.T0, resp.Common.T1 = req.Common.T0, req.Common.T1
		resp.Common.T2 = time.Now().UTC().UnixMicro()
		return nil
	})
	client.Handle("Peer.Handshake", func(_ *rpc2.Client, req p2p.Handshake_Struct, resp *p2p.Handshake_Struct) error {
		fillHandshake(resp)
		return nil
	})
	client.Handle("Peer.NotifyINV", func(_ *rpc2.Client, req p2p.ObjectList, resp *p2p.Dummy) error { return nil })
	client.Handle("Peer.NotifyMiniBlock", func(_ *rpc2.Client, req p2p.Objects, resp *p2p.Dummy) error { return nil })
	go client.Run()

	var hreq, hresp p2p.Handshake_Struct
	pc := &peerClient{name: name, client: client, conn: conn, lim: newLimiter(rate)}
	defer func() {
		if pc != nil {
			pc.peerTopo, pc.peerPruned, pc.peerVersion = hresp.Common.TopoHeight, hresp.Pruned, hresp.DaemonVersion
		}
	}()
	fillHandshake(&hreq)
	if err := pc.call("Peer.Handshake", hreq, &hresp, 10*time.Second); err != nil {
		pc.close()
		return nil, fmt.Errorf("handshake with %s failed: %v", name, err)
	}
	if hresp.Network_ID != hreq.Network_ID {
		pc.close()
		return nil, fmt.Errorf("handshake with %s: network id mismatch", name)
	}
	return pc, nil
}

var ourPeerID = func() uint64 {
	var b [8]byte
	rand.Read(b[:])
	return binary.LittleEndian.Uint64(b[:])
}()

func fillHandshake(h *p2p.Handshake_Struct) {
	h.ProtocolVersion = "1.0.0"
	h.DaemonVersion = config.Version.String()
	h.UTC_Time = time.Now().UTC().Unix()
	h.Peer_ID = ourPeerID
	h.Request = true
	copy(h.Network_ID[:], globals.Config.Network_ID[:])
}

func (pc *peerClient) call(method string, req, resp interface{}, timeout time.Duration) error {
	pc.lim.wait()
	atomic.AddInt64(&pc.requests, 1)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := pc.client.CallWithContext(ctx, method, req, resp)
	if err != nil {
		atomic.AddInt64(&pc.failures, 1)
	}
	return err
}

func (pc *peerClient) close() {
	pc.client.Close()
	pc.conn.Close()
}

// ---- the section arithmetic of p2p/bootstrap_pipeline.go:202-250 (copied: those helpers are unexported) ----

// sectionPath is chunk i's request path: the bit-reversed index (bootstrap_pipeline.go:214).
func sectionPath(i int64) []byte {
	var section [8]byte
	binary.BigEndian.PutUint64(section[:], bits.Reverse64(uint64(i)))
	return section[:]
}

func isbit(b []byte, index uint64) bool { return b[index/8]&(1<<(7-index%8)) != 0 }

// maxSectionKeys is the TreeSection handler's reply cap: it breaks after appending key 10,001
// (p2p/rpc_treesection.go: `if len(response.Keys) > 10000 { break }`). A reply that long may be truncated.
const maxSectionKeys = 10000

// sectionCheck: keys and values pair up, every key's blake2s key-hash starts with the section path
// (bootstrap_pipeline.go:225), and the reply is not at the handler's cap (a capped reply may be incomplete;
// derod's bootstrap does not check this, we refuse it).
func sectionCheck(section []byte, pathLength uint64, resp *p2p.Response_Tree_Section_Struct) error {
	if len(resp.Keys) != len(resp.Values) {
		return fmt.Errorf("mismatched key and value count")
	}
	if len(resp.Keys) > maxSectionKeys {
		return fmt.Errorf("reply has %d keys: at the handler's cap, possibly truncated", len(resp.Keys))
	}
	if pathLength == 0 {
		return nil
	}
	if pathLength > uint64(len(section))*8 {
		return fmt.Errorf("section path too short")
	}
	for _, k := range resp.Keys {
		h := blake2s.Sum256(k)
		for b := uint64(0); b < pathLength; b++ {
			if isbit(h[:], b) != isbit(section, b) {
				return fmt.Errorf("key %x outside the requested tree section", k)
			}
		}
	}
	return nil
}

// chunksFor is bootstrap_chain's chunk count (chain_bootstrap.go:91-104): the smallest power of two >= keys/640,
// at least 2.
func chunksFor(keyCount int64) (chunks int64, pathLength int) {
	est := keyCount / 640
	chunks = 1
	for chunks < est {
		chunks *= 2
		pathLength++
	}
	if chunks < 2 {
		chunks, pathLength = 2, 1
	}
	return
}
