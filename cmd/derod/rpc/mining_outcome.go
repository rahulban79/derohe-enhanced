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

// Mining-facing intelligence, all local and read-only with respect to the chain:
//
//   - the miniblock FATE tracker: realised reward is shares found x the fraction of them that end up in the block
//     that wins their height (memory: dero-reward-luck-mechanics). The daemon counted only PoW-valid submissions
//     ("chain may still ignore them", CountMinisAccepted). Every accepted submission is recorded here and resolved
//     once its height is stable: PAID if a main-chain block at that height carries it, otherwise ORPHANED (in a side
//     block, or not included at all). Exposed as DERO.GetMiningOutcome and as metrics.
//   - STALE-WORK signal while behind: work built on a stale tip is rejected by peers (window [h-2, h+1]). Reported,
//     not enforced: withholding new jobs does not stop a miner hashing its last one, and starves a miner that connects
//     meanwhile (review 2026-10-22), so GetSyncInfo/GetMiningOutcome say so and the operator decides.
//   - INBOUND reachability: the p2p listener is UDP; when nothing has ever connected in, the UDP port is not forwarded.

import "context"
import "fmt"
import "sync"
import "sync/atomic"
import "time"

import "github.com/deroproject/derohe/block"
import "github.com/deroproject/derohe/config"
import "github.com/deroproject/derohe/metrics"
import "github.com/deroproject/derohe/p2p"
import "github.com/xtaci/kcp-go/v5"

const FATE_RING = 4096

type MiniblockFate struct {
	Hash      string `json:"hash"`
	Height    uint64 `json:"height"`
	Submitted int64  `json:"submitted_unix"`
	// SubmittedMs: the r16 audit found the paid/orphan race at the 9th slot is decided in under a second, which
	// second resolution cannot resolve (r17). Same instant as Submitted, in milliseconds.
	SubmittedMs int64  `json:"submitted_unix_ms"`
	Fate        string `json:"fate"` // pending | paid | orphaned
	Reason      string `json:"reason,omitempty"`
	Block       string `json:"block,omitempty"`
	// Final: the miniblock was a final (HighDiff) one, i.e. this node built a whole block from it. An unpaid final
	// lost a same-height block race (reason "block_race"), not the 9-slot race: r18 height 7806145 (2026-10-24) was
	// reported "slots_full" although our block b1b34c8a was built and lost to 1e3ceffc, the lower block id
	// (blockchain/miner_block.go sort_descending_by_height_blid). Built is that block's id.
	Final bool   `json:"final,omitempty"`
	Built string `json:"built,omitempty"`
}

var fate_mu sync.Mutex
var fates []*MiniblockFate

// record_submission is called for every miniblock the chain accepted from a miner on this node.
func record_submission(blob []byte) { record_submission_built(blob, "") }

// record_submission_built also keeps the id of the block a final miniblock produced ("" for a regular one).
func record_submission_built(blob []byte, built string) {
	var mbl block.MiniBlock
	if err := mbl.Deserialize(blob); err != nil {
		return
	}
	now := time.Now()
	f := &MiniblockFate{Hash: mbl.GetHash().String(), Height: mbl.Height, Submitted: now.Unix(), SubmittedMs: now.UnixMilli(), Fate: "pending",
		Final: mbl.Final, Built: built}
	fate_mu.Lock()
	fates = append(fates, f)
	if len(fates) > FATE_RING {
		fates = fates[len(fates)-FATE_RING:]
	}
	fate_mu.Unlock()
	metrics.Set.GetOrCreateCounter("miniblock_ours_submitted_total").Inc()
	start_fate_resolver() // resolution is only needed once something was submitted
}

// resolve_fate decides one miniblock from the main-chain blocks at its height. Pure, so the rule is unit-tested.
// Side blocks cannot be enumerated from the topo store (Get_Blocks_At_Height returns topo-ordered blocks only), so an
// orphan is one that no main-chain block at its height carries. Its reason says why when the block shows it:
// "slots_full" when that block already carries the most regular miniblocks a block can (BLOCK_TIME-MINIBLOCK_HIGHDIFF
// = 9, blockchain/miner_block.go), i.e. ours reached the block's producer after nine others; "not_included" otherwise.
// Both r16 orphans (heights 7799233 and 7799270, 2026-10-23) were slots_full: fresh shares, lost the 9-slot race.
// A FINAL miniblock never competes for a regular slot: this node built a block from it, so an unpaid final is
// "block_race" (a competing block at the same height won; equal heights are ordered by block id in consensus).
func resolve_fate(hash string, final bool, blocks []fate_block) (fate, reason, blid string) {
	for _, b := range blocks {
		if !b.main {
			continue
		}
		for _, h := range b.minis {
			if h == hash {
				return "paid", "", b.id
			}
		}
	}
	if final {
		return "orphaned", "block_race", ""
	}
	for _, b := range blocks {
		if b.main && uint64(b.regular) >= config.BLOCK_TIME-config.MINIBLOCK_HIGHDIFF {
			return "orphaned", "slots_full", ""
		}
	}
	return "orphaned", "not_included", ""
}

type fate_block struct {
	id      string
	main    bool
	minis   []string
	regular int // miniblocks that are not the final one
}

// chain_swap_mu orders the fate resolver's reads of the package-global chain against a test that swaps it
// (r25 B41: TestR19MethodsOnSimulatorChain wrote `chain = c` while the resolver goroutine, started by an earlier
// test's record_submission, read it at mining_outcome.go:127: a -race report in 1 of 12 full runs). In derod the
// chain is set once at start-up (websocket_server.go RPCServer_Start), so the read lock is uncontended.
var chain_swap_mu sync.RWMutex

func resolve_pending() {
	defer func() { recover() }() // a missing block on a pruned node must not take the resolver down
	chain_swap_mu.RLock()
	defer chain_swap_mu.RUnlock()
	st := chain.Get_Stable_Height()
	if st < 0 {
		return
	}
	stable := uint64(st)
	fate_mu.Lock()
	var todo []*MiniblockFate
	for _, f := range fates {
		if f.Fate == "pending" && f.Height <= stable {
			todo = append(todo, f)
		}
	}
	fate_mu.Unlock()
	cache := map[uint64][]fate_block{}
	for _, f := range todo {
		blocks, ok := cache[f.Height]
		if !ok {
			ids := chain.Get_Blocks_At_Height(int64(f.Height))
			complete := len(ids) > 0
			for _, blid := range ids {
				bl, err := chain.Load_BL_FROM_ID(blid)
				if err != nil {
					complete = false // a load failure is not evidence of an orphan: stay pending, retry next tick
					break
				}
				fb := fate_block{id: blid.String(), main: chain.Is_Block_Topological_order(blid)}
				for i := range bl.MiniBlocks {
					fb.minis = append(fb.minis, bl.MiniBlocks[i].GetHash().String())
					if !bl.MiniBlocks[i].Final {
						fb.regular++
					}
				}
				blocks = append(blocks, fb)
			}
			if !complete {
				continue // not cached: the next tick tries this height again
			}
			cache[f.Height] = blocks
		}
		fate, reason, blid := resolve_fate(f.Hash, f.Final, blocks)
		fate_mu.Lock()
		if f.Fate != "pending" { // the RPC and the ticker can resolve concurrently: count each miniblock once
			fate_mu.Unlock()
			continue
		}
		f.Fate, f.Reason, f.Block = fate, reason, blid
		fate_mu.Unlock()
		if fate == "paid" {
			metrics.Set.GetOrCreateCounter("miniblock_ours_paid_total").Inc()
		} else {
			metrics.Set.GetOrCreateCounter(fmt.Sprintf(`miniblock_ours_orphaned_total{reason="%s"}`, reason)).Inc()
		}
	}
}

var fate_once sync.Once

// fate_tick_pass is one periodic resolver pass (the ticker body of start_fate_resolver). r25 (B41, merge of
// rpcrobust + harnesstool verify): resolve_pending itself holds chain_swap_mu.RLock, which the test-side swap
// (swap_global_chain) takes for writing, so the ticker body and every direct caller share one lock. It is a function
// of its own so the -race test drives it directly: a tick period set before start_fate_resolver is a no-op once an
// earlier test in the package has fired fate_once, so a ticker-driven test proved nothing in the full-package run.
func fate_tick_pass() {
	resolve_pending()
}

func start_fate_resolver() {
	fate_once.Do(func() {
		go func() {
			for range time.Tick(18 * time.Second) { // one block time
				fate_tick_pass()
			}
		}()
	})
}

type GetMiningOutcome_Result struct {
	Submitted    int             `json:"submitted"`
	Paid         int             `json:"paid"`
	Orphaned     map[string]int  `json:"orphaned"`
	Pending      int             `json:"pending"`
	PaidFraction float64         `json:"paid_fraction"` // paid / (paid + orphaned)
	JobsHeld     bool            `json:"work_would_be_stale"`
	JobsHeldWhy  string          `json:"work_would_be_stale_reason,omitempty"`
	Recent       []MiniblockFate `json:"recent"`
}

func GetMiningOutcome(ctx context.Context) (result GetMiningOutcome_Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = rpc_internal_error(r)
		}
	}()
	if err = refuse_foreign(ctx, "DERO.GetMiningOutcome"); err != nil { // r20: that this machine mines is private
		return
	}
	resolve_pending()
	result.Orphaned = map[string]int{}
	fate_mu.Lock()
	defer fate_mu.Unlock()
	for _, f := range fates {
		result.Submitted++
		switch f.Fate {
		case "paid":
			result.Paid++
		case "orphaned":
			result.Orphaned[f.Reason]++
		default:
			result.Pending++
		}
	}
	if resolved := result.Submitted - result.Pending; resolved > 0 { // paid / (paid + orphaned)
		result.PaidFraction = float64(result.Paid) / float64(resolved)
	}
	for i := len(fates) - 1; i >= 0 && len(result.Recent) < 50; i-- {
		result.Recent = append(result.Recent, *fates[i])
	}
	result.JobsHeld, result.JobsHeldWhy = jobs_held()
	return
}

// ---- stale-work signal while behind (reported, not enforced: see the header)

const JOB_HOLD_MIN_PEERS = 3

// should_hold_jobs is the pure rule: work would be stale while this node is more than SYNC_LAG_BLOCKS behind the
// median of at least JOB_HOLD_MIN_PEERS peers (fewer peers are not trusted to define "behind").
func should_hold_jobs(peers uint64, lag int64) bool {
	return peers >= JOB_HOLD_MIN_PEERS && lag > SYNC_LAG_BLOCKS
}

// jobs_held reports, from the current lag and peers, whether a miner's work would be stale right now.
func jobs_held() (held bool, why string) {
	defer func() { recover() }()
	best, _ := p2p.Best_Peer_Height()
	in, out := p2p.Peer_Direction_Count()
	lag := best - chain.Get_Height()
	if should_hold_jobs(in+out, lag) {
		return true, fmt.Sprintf("node is %d block(s) behind the median of %d peers: mined work would be stale", lag, in+out)
	}
	return false, ""
}

// ---- inbound reachability

var process_start = time.Now()

const REACHABILITY_AFTER = 30 * time.Minute

// reachability is the pure rule behind GetSyncInfo's "inbound" field. Only inbound connections from PUBLIC
// addresses prove the --p2p-bind port is reachable from the internet: on 2026-10-23 two local shadow nodes
// (127.0.0.1 and the host's own LAN address) made the all-sources counter 2 and the field said "reachable"
// on a node whose UDP 11011 was not forwarded.
func reachability(public_opens, all_opens uint64, up time.Duration) string {
	switch {
	case public_opens > 0:
		return "reachable: peers have connected in"
	case up < REACHABILITY_AFTER:
		return "unknown: up for less than 30 min"
	case all_opens > 0:
		return "unreachable from the internet: only local/LAN nodes have connected in; forward UDP (not TCP) for the --p2p-bind port to this host"
	}
	return "unreachable: no inbound connection since start; forward UDP (not TCP) for the --p2p-bind port to this host"
}

func inbound_status() (uint64, string) {
	p := atomic.LoadUint64(&kcp.DefaultSnmp.PassiveOpens)
	return p, reachability(p2p.PublicInboundOpens(), p, time.Since(process_start))
}
