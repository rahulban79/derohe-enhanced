package p2p

import "time"

import "github.com/deroproject/derohe/config"
import "github.com/deroproject/derohe/globals"
import "github.com/deroproject/derohe/cryptography/crypto"

// fill the common part from our chain
func fill_common(common *Common_Struct) {
	var err error
	common.Height = chain.Get_Height()
	//common.StableHeight = chain.Get_Stable_Height()
	common.TopoHeight = chain.Load_TOPO_HEIGHT()

	version, err := chain.ReadBlockSnapshotVersion(chain.Get_Top_ID())
	if err != nil {
		fill_common_empty(common)
		return
	}

	if common.StateHash, err = chain.Load_Merkle_Hash(version); err != nil {
		fill_common_empty(common)
		return
	}

	common.Top_Version = uint64(chain.Get_Current_Version_at_Height(int64(common.Height))) // this must be taken from the hardfork
	common.T0 = globals.TimeSkipP2P().UTC().UnixMicro()
}

// During a fastsync bootstrap, topo/state records are committed before the corresponding
// block data reaches bltx_store, so reading the top block can fail transiently. Panicking
// here (the old behavior) killed every connection whose handshake/ping fired in that window,
// leaving the node with only zombie peers when the bootstrap finished. Report a genesis-empty
// view instead — the same story a brand-new node tells — and let the next exchange after
// bootstrap completion carry the real values.
// Mid-bootstrap the topo store is written non-contiguously and LocatePruneTopo can
// panic("invalid prune detected") (storetopo.go:178). A handshake must never lose the
// connection over that transient — report unpruned (0) and let later exchanges carry
// the real value. Guarded here at the p2p call site so blockchain semantics are untouched.
func safeLocatePruneTopo() (pruned int64) {
	defer func() {
		if r := recover(); r != nil {
			pruned = 0
		}
	}()
	return chain.LocatePruneTopo()
}

func fill_common_empty(common *Common_Struct) {
	common.Height = 0
	common.TopoHeight = 0
	common.StateHash = crypto.Hash{}
	common.Top_Version = 0
	common.T0 = globals.TimeSkipP2P().UTC().UnixMicro()
}

func fill_common_T1(common *Common_Struct) {
	common.T1 = globals.TimeSkipP2P().UTC().UnixMicro()
}

// sets up data for ntp style processing
func fill_common_T0T1T2(request, response *Common_Struct) {
	response.T0 = request.T0
	response.T1 = request.T1
	response.T2 = globals.TimeSkipP2P().UTC().UnixMicro()
}

// used while sendint TX ASAP
// this also skips statehash
func fill_common_skip_topoheight(common *Common_Struct) {
	fill_common(common)
	return

}

// update some common properties quickly
func (connection *Connection) update(common *Common_Struct) {
	connection.update_received_ns.Store(time.Now().UnixNano())
	var hash crypto.Hash

	// HF3 chain-split guard: a peer whose chain is past the HF3 activation height but
	// still reports Top_Version < 3 is following the non-upgraded v2 remnant chain.
	// Its blocks can never be accepted here ("invalid fork version") and its sync
	// offers only produce "deviated too much" churn — and would trigger a deep
	// Rewind_Chain if --sync-node were ever set. Drop it. The STABLE_LIMIT margin
	// avoids flapping on peers that are legitimately mid-sync near the boundary.
	if common.Height >= globals.Config.MAJOR_HF3_HEIGHT+config.STABLE_LIMIT && common.Top_Version < 3 {
		secs := v2_ban_seconds(Address(connection))
		connection.logger.V(1).Info("dropping peer on pre-HF3 (v2) chain", "peer_height", common.Height, "peer_top_version", common.Top_Version, "ban_seconds", secs)
		Ban_Address_Reason(Address(connection), secs, BAN_SOURCE_V2, "top_version<3 past HF3") // escalates 1 h -> 24 h so the same v2 peer stops costing a dial every hour; r25: with its source
		connection.exit()
		return
	}

	connection.Height.Store(common.Height) // satify race detector GOD
	if common.StableHeight != 0 {
		connection.StableHeight.Store(common.StableHeight) // satify race detector GOD
	}
	connection.TopoHeight.Store(common.TopoHeight) // satify race detector GOD

	//connection.Top_ID = common.Top_ID

	if connection.Top_Version.Load() != common.Top_Version { // typed atomic: every access is atomic
		connection.Top_Version.Store(common.Top_Version) // satify race detector GOD
	}
	T3 := globals.TimeSkipP2P().UTC().UnixMicro()

	// rpc2 runs every request on its own goroutine, and pings and broadcasts call update() too: the hash and the
	// clock ring were plain read-modify-writes (a -race probe tore them, discovery concurrency-01)
	connection.state_mu.Lock()
	if common.StateHash != hash {
		connection.StateHash = common.StateHash
	}
	if common.T0 != 0 && common.T1 != 0 && common.T2 != 0 {
		connection.Latency.Store(int64(rtt_micro(common.T0, common.T1, common.T2, T3)))

		connection.clock_offsets[connection.clock_index] = offset_micro(common.T0, common.T1, common.T2, T3)
		connection.delays[connection.clock_index] = rtt_micro(common.T0, common.T1, common.T2, T3)
		connection.clock_index = (connection.clock_index + 1) % MAX_CLOCK_DATA_SET
		connection.calculate_avg_offset()
	}
	connection.state_mu.Unlock()

	// parse delivered peer list as grey list
	if len(common.PeerList) > 1 {
		connection.logger.V(4).Info("Peer provides peers", "count", len(common.PeerList))
		for i := range common.PeerList {
			if i < 31 {
				peer_add_gossip(common.PeerList[i].Addr, Address(connection))
			}
		}
	}
}

// calculate avg offset
func (connection *Connection) calculate_avg_offset() {
	var total, count time.Duration
	for i := 0; i < MAX_CLOCK_DATA_SET; i++ {
		if connection.clock_offsets[i] != 0 {
			total += connection.clock_offsets[i]
			count++
		}
	}
	if count == 0 { // every stored sample is exactly 0: there is nothing to average (upstream divided by zero)
		connection.clock_offset.Store(0)
		return
	}
	connection.clock_offset.Store(int64(total / count)) // readers load it atomically (connection_pool.go)
}
