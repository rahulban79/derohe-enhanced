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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

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
	// r25 (CO24-C6, dero-rft §7 B60): the counts above reset at every start; Lifetime carries them across restarts
	// (persisted in the datadir, REORG_MONITOR_FILE). nil when persistence is off (tests, or the file unwritable).
	Lifetime *Reorg_Lifetime `json:"lifetime,omitempty"`
}

// Reorg_Lifetime is the reorg monitor summed over every run of this datadir since Since (r25, CO24-C6).
type Reorg_Lifetime struct {
	Since          string `json:"since"`  // RFC 3339 time the file was created
	Starts         uint64 `json:"starts"` // node runs that loaded or created it (this one included)
	Observed       uint64 `json:"observed"`
	Reorgs         uint64 `json:"reorgs"`
	ReplacedTotal  uint64 `json:"replaced_total"`
	Deepest        int    `json:"deepest"`
	DeepestHeights int64  `json:"deepest_heights"`
	Violations     uint64 `json:"final_violations"`
	LocalRewinds   uint64 `json:"local_rewinds"`
	LastForkTopo   int64  `json:"last_fork_topoheight"` // -1 none
	LastAt         string `json:"last_at,omitempty"`    // RFC 3339 time of the newest reorganisation
	File           string `json:"file"`                 // base name inside the datadir
	SaveErrors     uint64 `json:"save_errors"`
}

const REORG_MONITOR_FILE = "reorg_monitor.json" // r25 (CO24-C6)
const REORG_SAVE_EVERY = 100                    // observations between saves when nothing happened (an event saves at once)

type reorg_tracker struct {
	sync.Mutex
	slots map[int64]reorg_slot
	top   int64 // -1: no baseline yet
	tiph  int64 // chain height at the last observation
	final int64
	st    Reorg_Stats
	life  *Reorg_Lifetime // r25 (CO24-C6): nil = not persisted
	path  string
	dirty int // observations since the last save
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
	if r.life != nil { // r25 (CO24-C6): the same increments, summed across runs
		r.life.Observed++
		r.dirty++
		if ev != nil {
			r.life.Reorgs++
			r.life.ReplacedTotal += uint64(ev.Replaced)
			if ev.Replaced > r.life.Deepest {
				r.life.Deepest = ev.Replaced
			}
			if r.st.DeepestHeights > r.life.DeepestHeights {
				r.life.DeepestHeights = r.st.DeepestHeights
			}
			if ev.FinalViolated {
				r.life.Violations++
			}
			if ev.LocalRewind {
				r.life.LocalRewinds++
			}
			r.life.LastForkTopo = ev.ForkTopoHeight
			r.life.LastAt = time.Now().UTC().Format(time.RFC3339)
		}
		if ev != nil || r.dirty >= REORG_SAVE_EVERY {
			r.save_locked()
		}
	}
	if ev != nil {
		log_reorg(ev)
	}
	return ev
}

// log_reorg writes one INFO line per reorganisation (r25, CO24-C6): upstream logged none at the default level.
func log_reorg(ev *Reorg_Event) {
	defer func() { recover() }() // the logger is unset in unit tests that never started the RPC server
	logger.Info("Reorganisation", "seq", ev.Seq, "fork_topoheight", ev.ForkTopoHeight, "replaced", ev.Replaced,
		"lowest_replaced_height", ev.LowestReplacedHeight, "old_topoheight", ev.OldTopoHeight, "new_topoheight", ev.NewTopoHeight,
		"final_violated", ev.FinalViolated, "local_rewind", ev.LocalRewind)
}

// enable_persist loads (or creates) the lifetime record at path and counts this start (r25, CO24-C6). A missing file
// starts a new record; an unreadable or corrupt one is kept aside as <path>.corrupt and a new record started, so a
// bad file never stops the node.
func (r *reorg_tracker) enable_persist(path string) error {
	r.Lock()
	defer r.Unlock()
	life := &Reorg_Lifetime{LastForkTopo: -1}
	if raw, err := os.ReadFile(path); err == nil {
		if json.Unmarshal(raw, life) != nil || life.Since == "" {
			_ = os.Rename(path, path+".corrupt")
			life = &Reorg_Lifetime{LastForkTopo: -1}
		}
	}
	if life.Since == "" {
		life.Since = time.Now().UTC().Format(time.RFC3339)
	}
	life.Starts++
	life.File = filepath.Base(path)
	r.life, r.path = life, path
	return r.save_locked()
}

// flush saves the lifetime record now (r25, CO24-C6): at shutdown, so up to REORG_SAVE_EVERY-1 observations since the
// last periodic save are not lost (the shadow run of 2026-11-03 read observed 37 by RPC and 0 on disk after a stop).
func (r *reorg_tracker) flush() error {
	r.Lock()
	defer r.Unlock()
	return r.save_locked()
}

// save_locked writes the lifetime record atomically (tmp + rename, mode 0600). Caller holds r.
func (r *reorg_tracker) save_locked() error {
	r.dirty = 0
	if r.life == nil || r.path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(r.life, "", " ")
	if err == nil {
		tmp := r.path + ".tmp"
		if err = os.WriteFile(tmp, raw, 0600); err == nil {
			err = os.Rename(tmp, r.path)
		}
	}
	if err != nil {
		r.life.SaveErrors++
	}
	return err
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
	if r.life != nil { // r25: a copy, never the tracker's own record
		lt := *r.life
		s.Lifetime = &lt
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
