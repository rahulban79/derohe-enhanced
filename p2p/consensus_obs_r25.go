// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package p2p

// r25 (consensus dimension, CO24-C1/C3/C4/C5; dero-rft §7 B55, B57, B58, B59): what the chain observatory
// (harness/intel/consensus_intel.py) could only reconstruct from DEBUG log lines, or not at all, counted here.
//
//   CO24-C1  miniblock refusals by reason (NotifyMiniBlock returned an error with no log line and no series):
//            p2p_miniblock_refused_total{reason}, a rate-limited V(1) line naming the peer by its peer_id.
//   CO24-C3  block rejections by reason, attributed: blockchain_block_rejected_total{reason}, and a rate-limited
//            line naming the sending peer by its self-chosen peer_id (a pseudonym, never its address). The
//            blockchain package is consensus-guarded (harness/consensus_guard.py), so this is done at the p2p call
//            sites, from the error value Add_Complete_Block returns.
//   CO24-C4  alt (side) blocks: every block this node accepted is tracked with its height; once it is deeper than
//            STABLE_LIMIT below the tip it is settled as main (its id is at its height in the topo index) or alt.
//            GetInfo alt_blocks_count reads the settled alt count (it was declared and never assigned).
//   CO24-C5  first-seen time of each block (first chunk or first complete offer) and each miniblock (first accepted
//            notification), with where it came from (a peer or this node), kept in bounded FIFO tables and served by
//            the RPC (GetBlockHeadersRange first_seen_ms, GetMiniBlocks first_seen_ms, GetConsensusStats).
//
// Observation only: every function here runs AFTER the chain's own decision (or before it, recording a time) and
// changes nothing the node accepts, rejects or relays. Memory is bounded by the *_KEEP constants.

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/errormsg"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/metrics"
)

const BLOCK_SEEN_KEEP = 20000     // r25: ~4 days of blocks
const MINIBLOCK_SEEN_KEEP = 40000 // r25: ~20 h of miniblocks (9 regular + own finals per block)
const ALT_TRACK_KEEP = 20000      // r25: accepted blocks tracked for the main/alt verdict
const ALT_LIST_KEEP = 256         // r25: newest settled alt blocks listed by GetConsensusStats
const OBS_LOG_EVERY = time.Minute // r25: at most one line per reason per minute (the rest are counted as suppressed)

// Miniblock refusal reasons (CO24-C1), in NotifyMiniBlock order.
const (
	MBL_REFUSED_TOO_MANY     = "too_many"           // >= 5 miniblocks in one notification (the peer is also penalised)
	MBL_REFUSED_UNDECODABLE  = "undecodable"        // mbl.Deserialize failed
	MBL_REFUSED_STALE        = "stale_height"       // outside [height-2, height+1]
	MBL_REFUSED_FINAL        = "final_propagated"   // finals are never propagated alone
	MBL_REFUSED_UNREGISTERED = "unregistered_miner" // key hash not registered (IsAddressHashValid)
	MBL_REFUSED_TIP          = "tip_unexpanded"     // a 4-byte tip that matches no known block
	MBL_REFUSED_POW          = "invalid_pow"        // VerifyMiniblockPoW failed (the peer is also penalised)
	MBL_REFUSED_INSERT       = "insert_failed"      // InsertMiniBlock refused it
)

// FirstSeen is when this node first saw an object and from whom (Peer 0 = this node: mined here or submitted by RPC).
type FirstSeen struct {
	Ms     int64  `json:"first_seen_ms"`
	Peer   uint64 `json:"-"` // the peer's self-chosen id; only its hex form is ever logged, never its address
	Local  bool   `json:"local"`
	Height int64  `json:"height"`
}

type seen_table struct {
	sync.Mutex
	keep  int
	m     map[crypto.Hash]FirstSeen
	order []crypto.Hash // FIFO ring of the keys, oldest at head
	head  int
}

func new_seen_table(keep int) *seen_table {
	return &seen_table{keep: keep, m: map[crypto.Hash]FirstSeen{}}
}

// note records the first sighting only; a later one never moves the time. Returns true when it was the first.
func (t *seen_table) note(h crypto.Hash, fs FirstSeen) bool {
	t.Lock()
	defer t.Unlock()
	if _, ok := t.m[h]; ok {
		return false
	}
	if len(t.order) < t.keep {
		t.order = append(t.order, h)
	} else {
		delete(t.m, t.order[t.head])
		t.order[t.head] = h
		t.head = (t.head + 1) % t.keep
	}
	t.m[h] = fs
	return true
}

func (t *seen_table) get(h crypto.Hash) (FirstSeen, bool) {
	t.Lock()
	defer t.Unlock()
	fs, ok := t.m[h]
	return fs, ok
}

func (t *seen_table) len() int {
	t.Lock()
	defer t.Unlock()
	return len(t.m)
}

var block_seen = new_seen_table(BLOCK_SEEN_KEEP)
var miniblock_seen = new_seen_table(MINIBLOCK_SEEN_KEEP)

func seen_now(peer uint64, height int64) FirstSeen {
	return FirstSeen{Ms: globals.Time().UTC().UnixMilli(), Peer: peer, Local: peer == 0, Height: height}
}

// note_block_seen / note_miniblock_seen: c == nil means this node (own mined block, RPC submit).
func note_block_seen(c *Connection, blid crypto.Hash, height int64) {
	block_seen.note(blid, seen_now(conn_peer(c), height))
}

func note_miniblock_seen(c *Connection, mbl block.MiniBlock) {
	miniblock_seen.note(mbl.GetHash(), seen_now(conn_peer(c), int64(mbl.Height)))
}

func conn_peer(c *Connection) uint64 {
	if c == nil {
		return 0
	}
	return c.Peer_ID
}

// peer_label is the pseudonymous name a log line uses for the sender: its peer_id in hex, or "local".
func peer_label(peer uint64) string {
	if peer == 0 {
		return "local"
	}
	return fmt.Sprintf("%016x", peer)
}

// Block_First_Seen / MiniBlock_First_Seen serve the RPC (cmd/derod/rpc).
func Block_First_Seen(blid crypto.Hash) (FirstSeen, bool)  { return block_seen.get(blid) }
func MiniBlock_First_Seen(h crypto.Hash) (FirstSeen, bool) { return miniblock_seen.get(h) }
func First_Seen_Table_Sizes() (blocks, miniblocks int)     { return block_seen.len(), miniblock_seen.len() }
func Note_Local_Block(cbl *block.Complete_Block)           { note_local_block(cbl) }
func Note_Local_MiniBlock(mbl block.MiniBlock)             { note_miniblock_seen(nil, mbl) }
func note_local_block(cbl *block.Complete_Block) {
	if cbl == nil || cbl.Bl == nil {
		return
	}
	blid := cbl.Bl.GetHash()
	note_block_seen(nil, blid, int64(cbl.Bl.Height))
	alt_track.note(blid, int64(cbl.Bl.Height))
}

// ------------------------------------------------------------------ refusal / rejection counters

type reason_counter struct {
	sync.Mutex
	metric   string // e.g. p2p_miniblock_refused_total
	counts   map[string]uint64
	last_log map[string]time.Time
	held     map[string]uint64 // suppressed lines since the last one logged
}

func new_reason_counter(metric string) *reason_counter {
	return &reason_counter{metric: metric, counts: map[string]uint64{}, last_log: map[string]time.Time{}, held: map[string]uint64{}}
}

// add counts one event and says whether a line may be logged now (and how many were suppressed before it).
func (r *reason_counter) add(reason string, now time.Time) (log_it bool, suppressed uint64) {
	metrics.Set.GetOrCreateCounter(fmt.Sprintf(`%s{reason="%s"}`, r.metric, reason)).Inc()
	r.Lock()
	defer r.Unlock()
	r.counts[reason]++
	if t, ok := r.last_log[reason]; ok && now.Sub(t) < OBS_LOG_EVERY {
		r.held[reason]++
		return false, 0
	}
	r.last_log[reason] = now
	suppressed = r.held[reason]
	r.held[reason] = 0
	return true, suppressed
}

func (r *reason_counter) snapshot() (m map[string]uint64, total uint64) {
	r.Lock()
	defer r.Unlock()
	m = make(map[string]uint64, len(r.counts))
	for k, v := range r.counts {
		m[k] = v
		total += v
	}
	return
}

var miniblock_refused = new_reason_counter("p2p_miniblock_refused_total")
var block_rejected = new_reason_counter("blockchain_block_rejected_total")
var block_duplicates = metrics.Set.GetOrCreateCounter("p2p_block_offer_duplicate_total")

// every reason is on /metrics from the start (0 until it fires), as the p2p_counters list does for plain counters
var miniblock_refusal_reasons = []string{MBL_REFUSED_TOO_MANY, MBL_REFUSED_UNDECODABLE, MBL_REFUSED_STALE, MBL_REFUSED_FINAL,
	MBL_REFUSED_UNREGISTERED, MBL_REFUSED_TIP, MBL_REFUSED_POW, MBL_REFUSED_INSERT}
var block_reject_reasons = []string{"past_missing", "future_timestamp", "timestamp_not_after_parent", "invalid_pow", "invalid_size",
	"tx_double_spend", "invalid_tx", "invalid_block", "panic", "advance_block", "previous_block", "other", "unknown"}

func init() {
	for _, r := range miniblock_refusal_reasons {
		metrics.Set.GetOrCreateCounter(fmt.Sprintf(`p2p_miniblock_refused_total{reason="%s"}`, r))
	}
	for _, r := range block_reject_reasons {
		metrics.Set.GetOrCreateCounter(fmt.Sprintf(`blockchain_block_rejected_total{reason="%s"}`, r))
	}
}

// refuse_miniblock counts a refusal (CO24-C1) and returns err unchanged, so a call site reads
// `return c.refuse_miniblock(MBL_REFUSED_STALE, height, fmt.Errorf("Stale Miniblock"))`.
func (c *Connection) refuse_miniblock(reason string, height uint64, err error) error {
	if log_it, held := miniblock_refused.add(reason, time.Now()); log_it {
		// the package logger, never c.logger: a connection's logger is named after the peer's ip:port, and these lines
		// name the sender only by its self-chosen peer_id (a pseudonym)
		logger.V(1).Info("Miniblock refused", "reason", reason, "height", height, "peer_id", peer_label(conn_peer(c)), "suppressed", held)
	}
	return err
}

// block_reject_reason names the error value Add_Complete_Block returned (blockchain/blockchain.go). "" = not a
// rejection (accepted, or the block was already known).
func block_reject_reason(err error, ok bool) string {
	if ok {
		return ""
	}
	switch {
	case err == nil:
		return "unknown"
	case errors.Is(err, errormsg.ErrAlreadyExists):
		return ""
	case errors.Is(err, errormsg.ErrPastMissing):
		return "past_missing"
	case errors.Is(err, errormsg.ErrFutureTimestamp):
		return "future_timestamp"
	case errors.Is(err, errormsg.ErrInvalidTimestamp):
		return "timestamp_not_after_parent"
	case errors.Is(err, errormsg.ErrInvalidPoW):
		return "invalid_pow"
	case errors.Is(err, errormsg.ErrInvalidSize):
		return "invalid_size"
	case errors.Is(err, errormsg.ErrTXDoubleSpend):
		return "tx_double_spend"
	case errors.Is(err, errormsg.ErrInvalidTX):
		return "invalid_tx"
	case errors.Is(err, errormsg.ErrInvalidBlock):
		return "invalid_block"
	case errors.Is(err, errormsg.ErrPanic):
		return "panic"
	case err.Error() == "advance Block":
		return "advance_block"
	case err.Error() == "previous Block":
		return "previous_block"
	}
	return "other"
}

// note_block_result runs after every Add_Complete_Block of a block offered by a peer (c) or by this node (nil).
func note_block_result(c *Connection, cbl *block.Complete_Block, err error, ok bool) {
	if cbl == nil || cbl.Bl == nil {
		return
	}
	blid := cbl.Bl.GetHash()
	if ok {
		alt_track.note(blid, int64(cbl.Bl.Height))
		return
	}
	reason := block_reject_reason(err, ok)
	if reason == "" {
		block_duplicates.Inc()
		return
	}
	log_it, held := block_rejected.add(reason, time.Now())
	if !log_it {
		return
	}
	// routine skips (past_missing, advance_block, previous_block: block_reject_routine) go to the file log only. Every
	// other reason is a consensus rule refusing a block and shows on the console (rate-limited per reason).
	v := 0
	if block_reject_routine(reason) {
		v = 1
	}
	logger.V(v).Info("Block rejected", "blid", blid.String(), "height", cbl.Bl.Height, "reason", reason, "peer_id", peer_label(conn_peer(c)),
		"err", fmt.Sprint(err), "suppressed", held)
}

// block_reject_routine: reasons that are not a consensus rule refusing a block but the node skipping one it cannot use
// yet or any more, file log only (V(1)). r25 (verify): besides past_missing (a block ahead of its parent) this covers
// "advance Block" (height > our height+2, blockchain.go:477: every block a peer relays while this node is still
// catching up) and "previous Block" (height < our height-STABLE_LIMIT, blockchain.go:481: a late relay of an old
// block). Upstream logged neither, so the r24 census could not count them; they would have put one console line per
// reason per minute on the screen for the whole of a catch-up. The counters are unchanged.
func block_reject_routine(reason string) bool {
	switch reason {
	case "past_missing", "advance_block", "previous_block":
		return true
	}
	return false
}

// add_block is the attributed form of Add_Complete_Block_HF3 used by every p2p path that offers a block: it records
// the first-seen time before the add and the verdict after it. c may be nil (no connection).
func (c *Connection) add_block(cbl *block.Complete_Block) (error, bool) {
	if cbl != nil && cbl.Bl != nil {
		note_block_seen(c, cbl.Bl.GetHash(), int64(cbl.Bl.Height))
	}
	err, ok := Add_Complete_Block_HF3(chain, cbl)
	note_block_result(c, cbl, err, ok)
	return err, ok
}

// Consensus_Counters is the GetConsensusStats view of the counters above.
type Consensus_Counters struct {
	MiniblockRefused      map[string]uint64 `json:"miniblock_refused"`
	MiniblockRefusedTotal uint64            `json:"miniblock_refused_total"`
	BlockRejected         map[string]uint64 `json:"block_rejected"`
	BlockRejectedTotal    uint64            `json:"block_rejected_total"`
	BlockOfferDuplicates  uint64            `json:"block_offer_duplicates"`
}

func Consensus_Counters_Snapshot() (s Consensus_Counters) {
	s.MiniblockRefused, s.MiniblockRefusedTotal = miniblock_refused.snapshot()
	s.BlockRejected, s.BlockRejectedTotal = block_rejected.snapshot()
	s.BlockOfferDuplicates = block_duplicates.Get()
	return
}

// ------------------------------------------------------------------ alt (side) blocks, CO24-C4

type alt_entry struct {
	blid    crypto.Hash
	height  int64
	settled bool
	alt     bool
}

// AltBlock is one settled alt block (newest last).
type AltBlock struct {
	Hash        string `json:"hash"`
	Height      int64  `json:"height"`
	FirstSeenMs int64  `json:"first_seen_ms"`
	Local       bool   `json:"local"`
}

type Alt_Stats struct {
	Count       uint64     `json:"count"`               // settled alt blocks among the tracked ones (= GetInfo alt_blocks_count)
	Unsettled   int        `json:"unsettled"`           // accepted blocks still within STABLE_LIMIT of the tip
	Tracked     int        `json:"tracked"`             // accepted blocks tracked (bounded by ALT_TRACK_KEEP)
	Settled     uint64     `json:"settled"`             // settled as main or alt
	TrackedFrom int64      `json:"tracked_from_height"` // lowest height still tracked (-1 none)
	SettleDepth int64      `json:"settle_depth"`        // a block is settled once tip height - its height > this
	Blocks      []AltBlock `json:"blocks"`              // newest ALT_LIST_KEEP settled alt blocks
}

type alt_tracker struct {
	sync.Mutex
	entries []*alt_entry // FIFO, oldest first
	index   map[crypto.Hash]*alt_entry
	alts    []AltBlock
	count   uint64
	settled uint64
}

func new_alt_tracker() *alt_tracker { return &alt_tracker{index: map[crypto.Hash]*alt_entry{}} }

var alt_track = new_alt_tracker()

func (a *alt_tracker) note(blid crypto.Hash, height int64) {
	a.Lock()
	defer a.Unlock()
	if _, ok := a.index[blid]; ok {
		return
	}
	e := &alt_entry{blid: blid, height: height}
	a.entries = append(a.entries, e)
	a.index[blid] = e
	if len(a.entries) > ALT_TRACK_KEEP {
		old := a.entries[0]
		a.entries[0] = nil
		a.entries = a.entries[1:]
		delete(a.index, old.blid)
	}
}

// settle judges every unsettled entry deeper than STABLE_LIMIT below tip_height: main when main_at(height) lists its
// id (the topo index at that height), alt otherwise. main_at may panic (a clean record): that entry stays unsettled.
//
// r25 (verify): the topo-index reads run OUTSIDE the tracker lock. note() runs on the p2p add paths before the block is
// relayed (processChunkedBlock: note_block_result, then Broadcast_Block), and one Get_Blocks_At_Height costs ~96 us on
// the live 7.85M-record topo.map (~223 record reads), so a first GetInfo after >=20,000 unsettled blocks (a catch-up,
// or ~4 days with no RPC poller) held the lock ~1.9 s and stalled every relay behind it. Now the lock is held only to
// pick the due entries and to apply the verdicts; an entry a concurrent settle already judged is skipped.
func (a *alt_tracker) settle(tip_height int64, main_at func(int64) []crypto.Hash) Alt_Stats {
	a.Lock()
	var due []*alt_entry // blid and height never change after note(), so they are read unlocked below
	for _, e := range a.entries {
		if !e.settled && tip_height-e.height > config.STABLE_LIMIT {
			due = append(due, e)
		}
	}
	a.Unlock()

	type verdict struct {
		e   *alt_entry
		alt bool
	}
	verdicts := make([]verdict, 0, len(due))
	for _, e := range due {
		ids, ok := safe_main_at(main_at, e.height)
		if !ok {
			continue // stays unsettled
		}
		v := verdict{e: e, alt: true}
		for _, id := range ids {
			if id == e.blid {
				v.alt = false
				break
			}
		}
		verdicts = append(verdicts, v)
	}

	a.Lock()
	defer a.Unlock()
	for _, v := range verdicts {
		e := v.e
		if e.settled {
			continue // a concurrent settle judged it first
		}
		e.settled, e.alt = true, v.alt
		a.settled++
		if e.alt {
			a.count++
			ab := AltBlock{Hash: e.blid.String(), Height: e.height}
			if fs, ok := block_seen.get(e.blid); ok {
				ab.FirstSeenMs, ab.Local = fs.Ms, fs.Local
			}
			a.alts = append(a.alts, ab)
			if len(a.alts) > ALT_LIST_KEEP {
				a.alts = append([]AltBlock(nil), a.alts[len(a.alts)-ALT_LIST_KEEP:]...)
			}
		}
	}
	st := Alt_Stats{SettleDepth: config.STABLE_LIMIT, TrackedFrom: -1}
	for _, e := range a.entries {
		if !e.settled {
			st.Unsettled++
		}
	}
	st.Count, st.Settled, st.Tracked = a.count, a.settled, len(a.entries)
	if len(a.entries) > 0 {
		st.TrackedFrom = a.entries[0].height
	}
	st.Blocks = append(make([]AltBlock, 0, len(a.alts)), a.alts...) // [] not null in JSON
	return st
}

func safe_main_at(f func(int64) []crypto.Hash, h int64) (ids []crypto.Hash, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			ids, ok = nil, false
		}
	}()
	return f(h), true
}

// Alt_Blocks settles and reports against a chain (GetInfo, GetConsensusStats pass the RPC layer's chain: its
// height and its topo index by height).
func Alt_Blocks(tip_height int64, main_at func(int64) []crypto.Hash) Alt_Stats {
	return alt_track.settle(tip_height, main_at)
}
