// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package rpc

// DERO.GetSyncInfo — is this node at the tip, answered from state the daemon already holds.
//
// GetInfo cannot answer it: averageblocktime50 is computed from block TIMESTAMPS (it reads ~18 s at any height),
// target_height was commented out, and status is the constant "OK". On 2026-10-20 the node was 40 days behind while
// every GetInfo field looked healthy. The two readings that do decide it are the age of the tip block (wall clock
// minus its own timestamp) and how far the peers' median height is ahead. Read-only: nothing here touches chain
// state, so it is not consensus-visible.

import "context"
import "fmt"
import "strings"
import "time"

import "github.com/deroproject/derohe/config"
import "github.com/deroproject/derohe/metrics"
import "github.com/deroproject/derohe/p2p"
import "github.com/deroproject/derohe/p2p/nat"

type GetSyncInfo_Result struct {
	Status             string     `json:"status"` // synced | syncing | stalled | isolated
	Reason             string     `json:"reason"`
	Height             int64      `json:"height"`
	TopoHeight         int64      `json:"topoheight"`
	StableHeight       int64      `json:"stableheight"`
	PrunedTopo         int64      `json:"pruned_topoheight"`
	TopBlockHash       string     `json:"top_block_hash"`
	TipTimestampMs     uint64     `json:"tip_timestamp_ms"`
	TipAgeSeconds      float64    `json:"tip_age_seconds"`
	TargetBlockTime    uint64     `json:"target_block_time"`
	PeerMedianHeight   int64      `json:"peer_median_height"`
	PeerMedianTopo     int64      `json:"peer_median_topoheight"`
	LagBlocks          int64      `json:"lag_blocks"`
	PeersIncoming      uint64     `json:"peers_incoming"`
	PeersOutgoing      uint64     `json:"peers_outgoing"`
	RecoveredPanics    uint64     `json:"recovered_panics_total"`
	RPCRecoveredPanics uint64     `json:"rpc_recovered_panics_total"`
	TxFetchFailures    uint64     `json:"p2p_tx_fetch_failures_total"`
	Bans               uint64     `json:"p2p_bans_total"`        // bans PLACED since start
	BansActive         uint64     `json:"p2p_bans_active"`       // r27: running bans now, reloaded ones included
	BansLoaded         uint64     `json:"p2p_bans_loaded_total"` // r27: running bans reloaded from ban_list.json at start
	ChunksUnknownTip   uint64     `json:"p2p_chunks_unknown_tip_total"`
	InboundOpens       uint64     `json:"inbound_connections_since_start"`
	Inbound            string     `json:"inbound"`
	NAT                nat.Status `json:"p2p_nat"` // --p2p-nat port mapping (p2p/netlayers.go)
	JobsHeld           bool       `json:"mining_work_would_be_stale"`
	JobsHeldReason     string     `json:"mining_work_would_be_stale_reason,omitempty"`
	UptimeSeconds      int64      `json:"uptime_seconds"`
	Version            string     `json:"version"`
	ChainFingerprint   string     `json:"chain_fingerprint"`      // which side of the HF3 chain split this node is on
	V2PeersSeen7d      int        `json:"v2_chain_peers_seen_7d"` // distinct IPs dropped for following the v2 remnant
}

// thresholds and why:
//
//	SYNC_LAG_BLOCKS: a peer's height runs up to ~2 ahead while a block propagates (p2p uses the same +2 slack
//	  for sync nodes, connection_pool.go islagging), so more than 2 behind the peers' median means syncing.
//	STALL_TIP_AGE_S: with an 18 s mean and exponential-ish gaps, a 300 s gap has probability ~e^-16.7; a tip
//	  that old while no peer is ahead means the whole visible network (or this node's view of it) has stalled.
const SYNC_LAG_BLOCKS = 2
const STALL_TIP_AGE_S = 300

// classify_sync is a pure function so the thresholds are unit-tested (rpc_dero_getsyncinfo_test.go).
func classify_sync(peers uint64, lag int64, tip_age_s float64) (status, reason string) {
	switch {
	case peers == 0:
		return "isolated", "no handshaken peers; height cannot be compared with the network"
	case lag > SYNC_LAG_BLOCKS:
		return "syncing", fmt.Sprintf("%d block(s) behind the peers' median height", lag)
	case tip_age_s > STALL_TIP_AGE_S:
		return "stalled", fmt.Sprintf("tip block is %.0f s old and no peer is ahead", tip_age_s)
	}
	return "synced", fmt.Sprintf("within %d block(s) of the peers' median and the tip is %.0f s old", SYNC_LAG_BLOCKS, tip_age_s)
}

func sum_recovered() (n uint64) {
	for level := 0; level <= 4; level++ {
		n += metrics.Set.GetOrCreateCounter(fmt.Sprintf(`recovered_panics_total{level="%d"}`, level)).Get()
	}
	return
}

func GetSyncInfo(ctx context.Context) (result GetSyncInfo_Result, err error) {
	defer func() { // safety so if anything wrong happens, we return error
		if r := recover(); r != nil {
			err = rpc_internal_error(r)
		}
	}()

	result.Height = chain.Get_Height()
	result.TopoHeight = chain.Load_TOPO_HEIGHT()
	result.StableHeight = chain.Get_Stable_Height()
	result.PrunedTopo = chain.LocatePruneTopo()
	top := chain.Get_Top_ID()
	result.TopBlockHash = top.String()
	result.TipTimestampMs = chain.Load_Block_Timestamp(top)
	result.TipAgeSeconds = float64(time.Now().UnixMilli()-int64(result.TipTimestampMs)) / 1000
	result.TargetBlockTime = chain.Get_Current_BlockTime()
	result.PeerMedianHeight, result.PeerMedianTopo = p2p.Best_Peer_Height()
	result.PeersIncoming, result.PeersOutgoing = p2p.Peer_Direction_Count()
	if result.PeerMedianHeight > 0 {
		result.LagBlocks = result.PeerMedianHeight - result.Height
	}
	result.Status, result.Reason = classify_sync(result.PeersIncoming+result.PeersOutgoing, result.LagBlocks, result.TipAgeSeconds)
	result.RecoveredPanics = sum_recovered()
	result.RPCRecoveredPanics = metrics.Set.GetOrCreateCounter("rpc_recovered_panics_total").Get()
	result.TxFetchFailures = metrics.Set.GetOrCreateCounter("p2p_tx_fetch_failures_total").Get()
	result.Bans = metrics.Set.GetOrCreateCounter("p2p_bans_total").Get()
	result.BansActive, result.BansLoaded = p2p.Ban_Count(), p2p.BansLoaded()
	result.ChunksUnknownTip = metrics.Set.GetOrCreateCounter("p2p_chunks_unknown_tip_total").Get()
	result.InboundOpens, result.Inbound = inbound_status()
	result.NAT = p2p.NAT_Status()
	result.Inbound = nat_hint(result.Inbound, result.NAT)
	result.JobsHeld, result.JobsHeldReason = jobs_held()
	result.UptimeSeconds = int64(time.Since(process_start).Seconds())
	result.Version = config.Version.String()
	result.ChainFingerprint = chain_fingerprint()
	result.V2PeersSeen7d = p2p.V2OffendersSeen(time.Now().Unix())
	return result, nil
}

// nat_hint extends an "unreachable" verdict with what the port mapping says: an active mapping that still brings
// no inbound peer points at a second NAT (or a gateway that accepted but ignores it); no mapping points at the flag.
func nat_hint(inbound string, st nat.Status) string {
	if !strings.HasPrefix(inbound, "unreachable") {
		return inbound
	}
	switch {
	case st.Active && st.Warning != "":
		return inbound + "; NAT mapping is active but " + st.Warning
	case st.Active:
		return inbound + fmt.Sprintf("; NAT mapping via %s is active (external %s:%d): if peers still cannot connect in, another NAT or a firewall is upstream", st.Protocol, st.ExternalIP, st.ExternalPort)
	case st.Mode == nat.ModeProbe && st.Verdict != "": // read-only gateway probe (p2p/nat/probe.go)
		return inbound + "; NAT probe: " + st.Verdict
	case st.Mode == nat.ModeProbe:
		return inbound + "; NAT probe still running"
	case st.Mode == nat.ModeOff || st.Mode == "":
		return inbound + "; or start derod with --p2p-nat=auto if the router supports UPnP/NAT-PMP/PCP (--p2p-nat=probe checks that without mapping anything)"
	case st.Error != "":
		return inbound + "; --p2p-nat=" + st.Mode + " could not map the port: " + st.Error
	}
	return inbound
}
