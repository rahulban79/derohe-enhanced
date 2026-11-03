package p2p

// Read-only peer snapshot for the DERO.GetPeerInfo RPC (Round 19). Connection_Print writes the same facts to the
// console only; explorers, dashboards and operators had no machine-readable way to see who we are connected to,
// how far ahead/behind each peer is, its latency, or how often it delivers new blocks first.
//
// Data-race note: Peer_ID, DaemonVersion, Tag and Port are plain fields written by the handshake AFTER
// Connection_Add (rpc_handshake.go), and the last write of the handshake is State.Store(ACTIVE). Only connections
// whose State loads as ACTIVE are read here, so the atomic load orders those plain writes before our reads.

import (
	"sort"
	"time"
)

type PeerInfo struct {
	Address         string  `json:"address"`
	Incoming        bool    `json:"incoming"`
	PeerID          string  `json:"peer_id"`
	Height          int64   `json:"height"`
	TopoHeight      int64   `json:"topoheight"`
	StableHeight    int64   `json:"stableheight"`
	TopVersion      uint64  `json:"top_version"`
	LatencyMs       float64 `json:"latency_ms"`
	ClockOffsetMs   float64 `json:"clock_offset_ms"`
	ConnectedSecs   int64   `json:"connected_seconds"`
	BytesIn         uint64  `json:"bytes_in"`
	BytesOut        uint64  `json:"bytes_out"`
	FirstRelays     uint64  `json:"first_relays"`     // new blocks this peer delivered to us first (decaying counter)
	MiniblocksFirst uint64  `json:"miniblocks_first"` // miniblocks it delivered first on this connection
	MiniblocksTotal uint64  `json:"miniblocks_total"`
	DaemonVersion   string  `json:"daemon_version"`
	Tag             string  `json:"tag"`
	Pruned          int64   `json:"pruned"`
}

// trim64 bounds peer-supplied strings (the handshake already caps them at 128 bytes).
func trim64(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}

// peer_info_of builds the snapshot of one ACTIVE connection.
func peer_info_of(c *Connection, now time.Time) PeerInfo {
	first, dup := c.mbl_first.Load(), c.mbl_dup.Load()
	ip := Address(c)
	return PeerInfo{
		Address:         ip,
		Incoming:        c.Incoming,
		PeerID:          formatPeerID(c.Peer_ID),
		Height:          c.Height.Load(),
		TopoHeight:      c.TopoHeight.Load(),
		StableHeight:    c.StableHeight.Load(),
		TopVersion:      c.Top_Version.Load(),
		LatencyMs:       float64(c.Latency.Load()) / 1e6,
		ClockOffsetMs:   float64(c.clock_offset.Load()) / 1e6,
		ConnectedSecs:   int64(now.Sub(c.Created).Seconds()),
		BytesIn:         c.bytes_in(),
		BytesOut:        c.bytes_out(),
		FirstRelays:     first_relay.score(ip),
		MiniblocksFirst: first,
		MiniblocksTotal: first + dup,
		DaemonVersion:   trim64(c.DaemonVersion),
		Tag:             trim64(c.Tag),
		Pruned:          c.Pruned,
	}
}

func formatPeerID(id uint64) string {
	const hexdigits = "0123456789abcdef"
	var b [16]byte
	for i := 15; i >= 0; i-- {
		b[i] = hexdigits[id&0xf]
		id >>= 4
	}
	return string(b[:])
}

// PeerInfos returns up to max ACTIVE connections (handshake complete, not ourselves), best first-relay first, then
// lowest latency.
func PeerInfos(max int) (out []PeerInfo) {
	now := time.Now()
	our := GetPeerID()
	connection_map.Range(func(k, value interface{}) bool {
		c := value.(*Connection)
		if c.State.Load() != ACTIVE { // see the data-race note above: this load must come first
			return true
		}
		if c.Peer_ID == our {
			return true
		}
		out = append(out, peer_info_of(c, now))
		return true
	})
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].FirstRelays != out[j].FirstRelays {
			return out[i].FirstRelays > out[j].FirstRelays
		}
		if out[i].LatencyMs != out[j].LatencyMs {
			return out[i].LatencyMs < out[j].LatencyMs
		}
		return out[i].Address < out[j].Address
	})
	if max >= 0 && len(out) > max {
		out = out[:max]
	}
	return
}

// V2OffendersSeen counts distinct IPs dropped within the last V2_FORGET seconds for following the pre-HF3 (v2)
// remnant chain. Non-zero means the chain split is still live in this node's neighbourhood.
func V2OffendersSeen(now int64) (n int) {
	penalty_mu.Lock()
	defer penalty_mu.Unlock()
	for _, r := range v2_offences {
		if now-r.Last <= V2_FORGET {
			n++
		}
	}
	return
}
