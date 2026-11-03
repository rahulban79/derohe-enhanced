// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package rpc

// Reorg observation and the "Reorg" websocket event (Round 23b, rpcws).
//
// derod does not log a reorganisation at the default level and GetInfo does not show one, so a wallet that cached
// per-topoheight state had no signal to rewind (the emission auditor counts replaced topoheights, 22-26 live by
// 2026-10-30, but nothing told clients). At each new block the RPC layer now compares the block ids of the last
// REORG_WINDOW topoheights with what it saw at the previous block. A topoheight whose block id changed, or that no
// longer exists, was replaced: one Reorg event names the lowest such topoheight (fork_topoheight), from which a
// client re-reads. The check also tests the r23 finality rule live: a replaced block whose height is at or below the
// final height announced before it (GetTxStatus final_height) is a finality violation, counted in
// rpc_reorg_final_violations_total and flagged in the event. It must stay 0; it is a monitor, it changes nothing.
//
// Cost: REORG_WINDOW topo-index reads per block, one height lookup per newly seen block id, one final-height scan
// (as one GetTxStatus call). Node-local and read-only: nothing here affects what the node accepts or relays.

import (
	"fmt"
	"sync"

	"github.com/deroproject/derohe/cryptography/crypto"
	dmetrics "github.com/deroproject/derohe/metrics"
)

const REORG_WINDOW = 32      // topoheights compared at each block (consensus refuses blocks 8+ heights back)
const REORG_HASHES_KEPT = 32 // replaced block ids listed per event

type reorg_slot struct {
	blid   crypto.Hash
	height int64
}

type Reorg_Event struct {
	Seq                  uint64   `json:"seq"`                    // 1, 2, ... per node run; BlockInfo carries the latest as reorg_seq
	ForkTopoHeight       int64    `json:"fork_topoheight"`        // lowest replaced topoheight: re-read from here
	Replaced             int      `json:"replaced"`               // topoheights whose block changed or vanished
	LowestReplacedHeight int64    `json:"lowest_replaced_height"` // chain height of the lowest replaced block
	OldTopoHeight        int64    `json:"old_topoheight"`
	NewTopoHeight        int64    `json:"new_topoheight"`
	NewTopHash           string   `json:"new_top_hash"`
	OldHashes            []string `json:"old_hashes"`          // replaced block ids, ascending topoheight
	FinalHeightBefore    int64    `json:"final_height_before"` // final_height announced at the previous block (-1 unknown)
	FinalViolated        bool     `json:"final_violated"`      // a replaced block was at or below it: must never be true
	LocalRewind          bool     `json:"local_rewind"`        // r23b merge: the node's own chain was rewound (pop/Rewind_Chain), not judged
}

type Reorg_Stats struct {
	Observed       uint64       `json:"observed"`        // blocks compared
	Reorgs         uint64       `json:"reorgs"`          // events (one per block that replaced something)
	ReplacedTotal  uint64       `json:"replaced_total"`  // replaced topoheights, all events
	Deepest        int          `json:"deepest"`         // most topoheights replaced by one event
	DeepestHeights int64        `json:"deepest_heights"` // most chain heights between a replaced block and the old tip
	Violations     uint64       `json:"final_violations"`
	LocalRewinds   uint64       `json:"local_rewinds"` // r23b merge: events from a local pop/Rewind_Chain (never violations)
	Window         int          `json:"window"`
	Last           *Reorg_Event `json:"last,omitempty"`
}

type reorg_tracker struct {
	sync.Mutex
	slots map[int64]reorg_slot
	top   int64 // -1: no baseline yet
	tiph  int64 // chain height at the last observation
	final int64
	st    Reorg_Stats
}

func new_reorg_tracker() *reorg_tracker {
	return &reorg_tracker{slots: map[int64]reorg_slot{}, top: -1, final: -1, st: Reorg_Stats{Window: REORG_WINDOW}}
}

var reorg_state = new_reorg_tracker()

var (
	reorg_events_total     = dmetrics.Set.GetOrCreateCounter("rpc_reorgs_observed_total")
	reorg_replaced_total   = dmetrics.Set.GetOrCreateCounter("rpc_reorg_replaced_topoheights_total")
	reorg_violations_total = dmetrics.Set.GetOrCreateCounter("rpc_reorg_final_violations_total")
	reorg_rewinds_total    = dmetrics.Set.GetOrCreateCounter("rpc_reorg_local_rewinds_total")
)

// observe compares the window ending at top with the previous observation. blid_at reads the block at a topoheight
// (an error = not judged), height_of the height of a block id, final the final height now (it becomes the bound the
// NEXT observation is checked against), tiph the chain height now. Returns the event, or nil.
func (r *reorg_tracker) observe(top int64, blid_at func(int64) (crypto.Hash, error), height_of func(crypto.Hash) int64, final, tiph int64) (ev *Reorg_Event) {
	r.Lock()
	defer r.Unlock()
	from := top - REORG_WINDOW + 1
	if from < 0 {
		from = 0
	}
	cur := make(map[int64]reorg_slot, REORG_WINDOW)
	for t := from; t <= top; t++ {
		b, err := blid_at(t)
		if err != nil {
			continue
		}
		if p, ok := r.slots[t]; ok && p.blid == b {
			cur[t] = p
		} else {
			cur[t] = reorg_slot{blid: b, height: height_of(b)}
		}
	}
	r.st.Observed++
	vanish_only := true // every replaced slot lies above the new top (nothing at or below it changed)
	if r.top >= 0 {
		end := top
		if r.top > end {
			end = r.top
		}
		for t := from; t <= end; t++ {
			p, had := r.slots[t]
			if !had {
				continue
			}
			c, ok := cur[t]
			if t <= top && !ok {
				continue // unreadable now: not judged
			}
			if t <= top && c.blid == p.blid {
				continue
			}
			if t <= top {
				vanish_only = false
			}
			if ev == nil {
				ev = &Reorg_Event{ForkTopoHeight: t, LowestReplacedHeight: -1, OldTopoHeight: r.top, NewTopoHeight: top,
					FinalHeightBefore: r.final}
			}
			ev.Replaced++
			if p.height >= 0 && (ev.LowestReplacedHeight < 0 || p.height < ev.LowestReplacedHeight) { // -1 = unknown height
				ev.LowestReplacedHeight = p.height
			}
			if len(ev.OldHashes) < REORG_HASHES_KEPT {
				ev.OldHashes = append(ev.OldHashes, p.blid.String())
			}
		}
	}
	if ev != nil {
		if c, ok := cur[top]; ok {
			ev.NewTopHash = c.blid.String()
		}
		// r23b merge (RPCWS23B-B fix): a local Rewind_Chain (console pop, SyncNode resync) drops the chain height and only
		// removes topoheights above the new top, or drops the height below the final height announced before; the
		// network cannot do either (a heavier branch never is a prefix of ours). Such an event still tells clients to
		// re-read, but it is never judged against the finality rule.
		ev.LocalRewind = tiph < r.tiph && (vanish_only || (r.final >= 0 && tiph <= r.final))
		ev.FinalViolated = !ev.LocalRewind && ev.FinalHeightBefore >= 0 && ev.LowestReplacedHeight >= 0 && ev.LowestReplacedHeight <= ev.FinalHeightBefore
		if ev.LocalRewind {
			final_txs.flush() // cheap; verify-on-hit would catch the popped entries anyway
			r.st.LocalRewinds++
			reorg_rewinds_total.Inc()
		}
		r.st.Reorgs++
		ev.Seq = r.st.Reorgs
		r.st.ReplacedTotal += uint64(ev.Replaced)
		if ev.Replaced > r.st.Deepest {
			r.st.Deepest = ev.Replaced
		}
		if d := r.tiph - ev.LowestReplacedHeight; ev.LowestReplacedHeight >= 0 && d > r.st.DeepestHeights {
			r.st.DeepestHeights = d
		}
		reorg_events_total.Inc()
		reorg_replaced_total.Add(ev.Replaced)
		if ev.FinalViolated {
			final_txs.flush() // the settled-tx cache rests on the same rule (tx_status_final_cache.go)
			r.st.Violations++
			reorg_violations_total.Inc()
			logger.Error(nil, "FINALITY VIOLATION: a block at or below the announced final height was replaced",
				"fork_topoheight", ev.ForkTopoHeight, "replaced_height", ev.LowestReplacedHeight, "final_before", ev.FinalHeightBefore)
		}
		cp := *ev
		cp.OldHashes = append([]string(nil), ev.OldHashes...)
		r.st.Last = &cp
	}
	r.slots = cur
	r.top, r.final, r.tiph = top, final, tiph
	return ev
}

func (r *reorg_tracker) stats() Reorg_Stats {
	r.Lock()
	defer r.Unlock()
	s := r.st
	if s.Last != nil {
		cp := *s.Last
		cp.OldHashes = append([]string(nil), s.Last.OldHashes...)
		s.Last = &cp
	}
	return s
}

func (r *reorg_tracker) seq() uint64 {
	r.Lock()
	defer r.Unlock()
	return r.st.Reorgs
}

// observe_chain_reorg runs at each new block (Notify_Block_Addition) before the pushes go out. The chain readers
// can panic (a clean topo record, a missing block); either is "not judged", never a fault.
func observe_chain_reorg() *Reorg_Event {
	blid_at := func(t int64) (h crypto.Hash, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("topo %d: %v", t, r)
			}
		}()
		return chain.Load_Block_Topological_order_at_index(t)
	}
	height_of := func(b crypto.Hash) (h int64) {
		defer func() {
			if r := recover(); r != nil {
				h = -1
			}
		}()
		return chain.Load_Height_for_BL_ID(b)
	}
	final, _ := chain_tx_status{}.final_height()
	return reorg_state.observe(chain.Load_TOPO_HEIGHT(), blid_at, height_of, final, chain.Get_Height())
}
