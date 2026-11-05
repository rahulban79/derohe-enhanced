// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package p2p

// r25 (peers): what the network-peer observatory (harness/intel/peer_intel.py, artifacts/dero-rft.md §0.7.2) could
// only reconstruct from log lines, as counters and DERO.GetPeerInfo fields (CO24-N1..N7, §7 B63-B69), plus the B47
// sync hold. Logging, counters and RPC fields only: nothing here changes which blocks, miniblocks or transactions
// are valid, who is banned or for how long; the one behaviour change is local sync-peer choice (B47, below).
//
//   CO24-N1 per-peer offence score, ban count and last reasons      PeerInfo penalty_*, last_offences; Offenders()
//   CO24-N2 per-reason offence and ban counters, zero from start     p2p_penalty_events_total{reason} (existed since
//           r13 but was created on first use, so "never happened" looked like "not this build"; now pre-registered),
//           p2p_penalty_bans_by_reason_total{reason}
//   CO24-N3 Chain requests served                                    p2p_chain_requests_served_total,
//           p2p_chain_request_blocks_total, p2p_chain_requests_refused_total; PeerInfo chain_requests_served
//   CO24-N4 ban source and reason                                    bans.go ban_meta (ban_reasons.json); BanInfos()
//   CO24-N5 INV budget clips per connection                          PeerInfo inv_txids_clipped
//   CO24-N6 objects a peer could not serve, short sync answers       p2p_objects_unserved_total,
//           p2p_sync_short_answers_total; PeerInfo objects_unserved, short_answers
//   CO24-N7 stuck-peer holds, listed                                 StuckHolds()
//
// B47 (§7): a peer that advertises a height above ours but answers the sync's GetObject with its own error or with
// fewer blocks than asked (live r24 derod.log since 2026-10-22: 22 "peer answered 0 blocks for 4 requested" lines
// from 3 peers, 15-25 s apart within a burst) was picked again at the next sync tick, without end, while it stayed
// ahead (the R24 syncp2p shadow clone saw it every 4 s). After such a failure the connection is now skipped by
// trigger_sync for SYNC_HOLD_BASE, doubling per consecutive failure up to SYNC_HOLD_MAX; one sync round that adds
// blocks forgives it. The connection is kept and nothing is scored or banned: relays, INVs and the other peers'
// syncs are unaffected, and a --sync-node is never held (operator choice, like the stuck-peer exemption).

import (
	"container/heap"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync/atomic"
	"time"

	"github.com/deroproject/derohe/metrics"
)

type conn_observe struct {
	chain_served     atomic.Uint64 // Chain requests from this peer that we answered (CO24-N3)
	chain_blocks     atomic.Uint64 // block ids in those answers
	inv_clipped      atomic.Uint64 // announced txids beyond its INV budget (CO24-N5)
	objects_unserved atomic.Uint64 // our GetObject calls it answered with its own error (CO24-N6)
	short_answers    atomic.Uint64 // sync GetObject replies with fewer blocks than asked (CO24-N6)
	sync_strikes     atomic.Int32  // consecutive failed syncs (B47)
	sync_hold_until  atomic.Int64  // unix nanos; trigger_sync skips the connection until then (B47)
}

var chain_requests_served = metrics.Set.GetOrCreateCounter("p2p_chain_requests_served_total")
var chain_request_blocks = metrics.Set.GetOrCreateCounter("p2p_chain_request_blocks_total")
var chain_requests_refused = metrics.Set.GetOrCreateCounter("p2p_chain_requests_refused_total")
var objects_unserved_total = metrics.Set.GetOrCreateCounter("p2p_objects_unserved_total")
var sync_short_answers_total = metrics.Set.GetOrCreateCounter("p2p_sync_short_answers_total")
var sync_peer_holds_total = metrics.Set.GetOrCreateCounter("p2p_sync_peer_holds_total")

// the labelled series exist from the start (0 until they fire): every reason of PENALTY_POINTS, every ban source
var ban_sources = []string{BAN_SOURCE_V2, BAN_SOURCE_SCORE, BAN_SOURCE_OPERATOR, BAN_SOURCE_UNATTRIBUTED}

func init() {
	for reason := range PENALTY_POINTS {
		metrics.Set.GetOrCreateCounter(fmt.Sprintf(`p2p_penalty_events_total{reason="%s"}`, reason))
		metrics.Set.GetOrCreateCounter(fmt.Sprintf(`p2p_penalty_bans_by_reason_total{reason="%s"}`, reason))
	}
	for _, s := range ban_sources {
		metrics.Set.GetOrCreateCounter(fmt.Sprintf(`p2p_bans_by_source_total{source="%s"}`, s))
	}
}

// ban_source_label keeps the metric's label set fixed.
func ban_source_label(s string) string {
	for _, k := range ban_sources {
		if s == k {
			return s
		}
	}
	return BAN_SOURCE_UNATTRIBUTED
}

// ---- CO24-N6: whose failure, counted per connection ---------------------------------------------------------------

// short_answer_error: a sync GetObject reply with fewer blocks than requested. Its text is the r24 error text, so the
// log line and every reader of it are unchanged; its type lets classify_call_error tell it from a local failure.
type short_answer_error struct{ got, want int }

func (e short_answer_error) Error() string {
	return fmt.Sprintf("peer answered %d blocks for %d requested", e.got, e.want)
}

func is_short_answer(err error) bool {
	var s short_answer_error
	return errors.As(err, &s)
}

// call_failed logs a failed GetObject at its level (log_call_failure) and counts it against this connection.
func (c *Connection) call_failed(err error, msg string, keysAndValues ...interface{}) call_failure {
	kind := log_call_failure(c.logger, err, msg, keysAndValues...)
	c.note_call_failure(kind)
	return kind
}

func (c *Connection) note_call_failure(kind call_failure) {
	switch kind {
	case call_failure_remote:
		c.obs.objects_unserved.Add(1)
		objects_unserved_total.Inc()
	case call_failure_short:
		c.obs.short_answers.Add(1)
		sync_short_answers_total.Inc()
	}
}

// ---- B47: sync hold ------------------------------------------------------------------------------------------------

const SYNC_HOLD_BASE = 30 * time.Second // one failed sync: the next sync goes to another peer for 30 s ...
const SYNC_HOLD_MAX = 10 * time.Minute  // ... doubling per consecutive failure, at most 10 min

// r26 (B99, §7): the r25 verifier found three gaps in the hold. (1) Strikes never decayed: a peer's failures a day
// apart escalated as if consecutive. (2) A peer that relays a block we accept was never forgiven, only one that a
// sync round got blocks from. (3) When every peer ahead of us was held, trigger_sync synced with nobody until a hold
// ran out (up to SYNC_HOLD_MAX). Now: (1) a failure more than SYNC_STRIKE_FORGET after the previous hold ended starts
// again at strike 1; (2) an accepted relayed block that brings us level with the height the peer advertises clears
// its strikes and hold (sync_relay_served: its claim matched what it delivered); (3) if no unheld peer ahead could
// sync (all held, or the rest pruned past our tip), trigger_sync tries the held ones, the hold that ends soonest
// first, at most once per SYNC_FALLBACK_EVERY node-wide (counted in p2p_sync_held_fallbacks_total). So a peer that
// cannot serve is asked at most once per 30 s even when it is the only one ahead (before r25: every 4 s), and with a
// held peer ahead a sync is attempted at least once per 30 s.
const SYNC_STRIKE_FORGET = SYNC_HOLD_MAX
const SYNC_FALLBACK_EVERY = SYNC_HOLD_BASE

var sync_held_fallbacks_total = metrics.Set.GetOrCreateCounter("p2p_sync_held_fallbacks_total")
var sync_relay_forgiven_total = metrics.Set.GetOrCreateCounter("p2p_sync_relay_forgiven_total")
var sync_fallback_last atomic.Int64 // unix nanos of the latest fallback (0 = never)

// sync_fallback_open reports, without claiming it, whether the fallback slot is free now (B99).
func sync_fallback_open(now time.Time) bool {
	return sync_fallback_due(sync_fallback_last.Load(), now)
}

// sync_fallback_due is the rate rule: never before, or at least SYNC_FALLBACK_EVERY since the latest fallback.
func sync_fallback_due(last int64, now time.Time) bool {
	return last == 0 || now.UnixNano()-last >= int64(SYNC_FALLBACK_EVERY)
}

// sync_held_ahead counts the held, handshaken connections that advertise a height above ours (B99).
func sync_held_ahead(clist []*Connection, our_height int64) (n int) {
	now := time.Now()
	for _, c := range clist {
		if c.sync_held(now) && c.State.Load() != HANDSHAKE_PENDING && our_height < c.Height.Load() {
			n++
		}
	}
	return
}

// sync_fallback_allowed reports whether trigger_sync may try a held peer now, and if so claims the slot (B99).
func sync_fallback_allowed(now time.Time) bool {
	for {
		last := sync_fallback_last.Load()
		if !sync_fallback_due(last, now) {
			return false
		}
		if sync_fallback_last.CompareAndSwap(last, now.UnixNano()) {
			return true
		}
	}
}

// sync_relay_served runs when this node accepted a block the peer relayed (note_block_result, B99). If our height
// now reaches what the peer advertises, the peer delivered what it claimed: its strikes and any hold are cleared.
// A peer still claiming more than it delivered keeps its hold.
func (c *Connection) sync_relay_served(our_height int64) {
	if c == nil || c.obs.sync_strikes.Load() == 0 && c.obs.sync_hold_until.Load() == 0 {
		return
	}
	if our_height < c.Height.Load() {
		return
	}
	c.sync_succeeded()
	sync_relay_forgiven_total.Inc()
}

func sync_hold_duration(strikes int32) time.Duration {
	d := SYNC_HOLD_BASE
	for i := int32(1); i < strikes && d < SYNC_HOLD_MAX; i++ {
		d *= 2
	}
	if d > SYNC_HOLD_MAX {
		d = SYNC_HOLD_MAX
	}
	return d
}

// sync_failed records the outcome of a failed sync fetch. Only a failure that is the PEER's (it answered with its own
// error, or with fewer blocks than it advertised) holds it; a timeout, a closed pipe or our own error does not.
func (c *Connection) sync_failed(kind call_failure, now time.Time) {
	if kind != call_failure_remote && kind != call_failure_short {
		return
	}
	// r26 (B99): strikes decay. A failure more than SYNC_STRIKE_FORGET after the previous hold ended starts again at
	// strike 1: in r25 one short answer a day apart from the last still escalated, so strikes only ever grew.
	if until := c.obs.sync_hold_until.Load(); until != 0 && now.UnixNano()-until > int64(SYNC_STRIKE_FORGET) {
		c.obs.sync_strikes.Store(0)
	}
	n := c.obs.sync_strikes.Add(1) // a --sync-node counts too (GetPeerInfo shows it) but is never skipped: sync_held
	d := sync_hold_duration(n)
	c.obs.sync_hold_until.Store(now.Add(d).UnixNano())
	sync_peer_holds_total.Inc()
	c.logger.V(1).Info("holding sync with this peer", "failures", n, "hold", d.String(), "kind", kind.String())
}

// sync_held: trigger_sync skips this connection now (B47).
func (c *Connection) sync_held(now time.Time) bool {
	if c.SyncNode {
		return false
	}
	return now.UnixNano() < c.obs.sync_hold_until.Load()
}

func (c *Connection) sync_succeeded() {
	c.obs.sync_strikes.Store(0)
	c.obs.sync_hold_until.Store(0)
}

// ---- CO24-N1: offence view of one scope ----------------------------------------------------------------------------

// penalty_view returns the decayed score, the score bans so far, the offences scored and the newest reasons of scope.
func penalty_view(scope string, now time.Time) (score float64, bans int, events uint32, last []OffenceMark) {
	last = []OffenceMark{}
	penalty_mu.Lock()
	defer penalty_mu.Unlock()
	m := penalty_map[scope]
	if m == nil {
		return
	}
	return penalty_view_locked(m, now)
}

func penalty_view_locked(m *misbehaviour, now time.Time) (score float64, bans int, events uint32, last []OffenceMark) {
	score = m.score * math.Pow(0.5, now.Sub(m.at).Seconds()/PENALTY_HALF_LIFE.Seconds())
	score = math.Round(score*100) / 100
	return score, m.offences, m.events, m.recent()
}

// OffenderInfo is one penalty record (an IPv4 address or an IPv6 /64) that has scored at least one offence.
type OffenderInfo struct {
	Scope        string        `json:"scope"`
	Score        float64       `json:"score"`
	Bans         int           `json:"bans"`
	Events       uint32        `json:"events"`
	BannedFor    int64         `json:"banned_for_seconds"` // remaining seconds of its latest score ban (0 = none)
	LastOffences []OffenceMark `json:"last_offences"`
}

// Offenders lists up to max penalty records with offences, newest offence first (connected or not); max < 0 = all.
//
// r26 (B99): r25 built the view of EVERY record (math.Pow, a slice per record) under penalty_mu, then sorted and cut
// to max: 22.6-23.4 ms per GetPeerInfo on a full 65,536-record table (r25 verifier), with add_penalty blocked all that
// time. Now the walk under the lock only reads each record's newest offence time and keeps the max newest in a
// bounded heap; the views (and their allocations) are built for those max records only. Same order, same records.
func Offenders(max int, now time.Time) (out []OffenderInfo) {
	out = []OffenderInfo{}
	if max == 0 {
		return
	}
	var h offender_heap
	penalty_mu.Lock()
	for k, m := range penalty_map {
		if m.events == 0 {
			continue
		}
		p := offender_pick{scope: k, m: m, at: m.newest_at()}
		switch {
		case max < 0 || len(h) < max:
			heap.Push(&h, p)
		case offender_newer(p, h[0]):
			h[0] = p
			heap.Fix(&h, 0)
		}
	}
	for _, p := range h {
		m := p.m
		s, b, e, l := penalty_view_locked(m, now)
		bf := int64(0)
		if now.Before(m.banned_until) {
			bf = int64(m.banned_until.Sub(now) / time.Second)
		}
		out = append(out, OffenderInfo{Scope: p.scope, Score: s, Bans: b, Events: e, BannedFor: bf, LastOffences: l})
	}
	penalty_mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		ai, aj := int64(0), int64(0)
		if len(out[i].LastOffences) > 0 {
			ai = out[i].LastOffences[0].At
		}
		if len(out[j].LastOffences) > 0 {
			aj = out[j].LastOffences[0].At
		}
		if ai != aj {
			return ai > aj
		}
		return out[i].Scope < out[j].Scope
	})
	return
}

// offender_pick is one candidate of Offenders; offender_heap keeps the max newest with the OLDEST at the root.
type offender_pick struct {
	scope string
	m     *misbehaviour
	at    int64 // its newest offence (unix seconds), as LastOffences[0].At reports it
}

// offender_newer is the Offenders order: newer offence first, then scope ascending.
func offender_newer(a, b offender_pick) bool {
	if a.at != b.at {
		return a.at > b.at
	}
	return a.scope < b.scope
}

type offender_heap []offender_pick

func (h offender_heap) Len() int            { return len(h) }
func (h offender_heap) Less(i, j int) bool  { return offender_newer(h[j], h[i]) } // root = the one every other is newer than
func (h offender_heap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *offender_heap) Push(x interface{}) { *h = append(*h, x.(offender_pick)) }
func (h *offender_heap) Pop() interface{} {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

// ---- CO24-N4: the ban list with its sources ------------------------------------------------------------------------

type BanEntry struct {
	Address   string `json:"address"`
	Until     uint64 `json:"until"`
	Remaining int64  `json:"remaining_seconds"`
	Source    string `json:"source"`
	Reason    string `json:"reason"`
	At        int64  `json:"at"`
}

// BanInfos returns up to max running bans, most recently placed first, the total, and the count per source (all bans).
func BanInfos(max int, now time.Time) (list []BanEntry, total int, by_source map[string]int) {
	list, by_source = []BanEntry{}, map[string]int{}
	ban_mutex.Lock()
	for k, until := range ban_map {
		if until < uint64(now.Unix()) {
			continue // expired, not yet cleaned up
		}
		mi := ban_meta[k]
		src := mi.Source
		if src == "" {
			src = BAN_SOURCE_UNATTRIBUTED // placed before r25, or loaded without its sidecar
		}
		by_source[src]++
		total++
		list = append(list, BanEntry{Address: k, Until: until, Remaining: int64(until) - now.Unix(), Source: src, Reason: mi.Reason, At: mi.At})
	}
	ban_mutex.Unlock()
	sort.Slice(list, func(i, j int) bool {
		if list[i].At != list[j].At {
			return list[i].At > list[j].At
		}
		return list[i].Address < list[j].Address
	})
	if max >= 0 && len(list) > max {
		list = list[:max]
	}
	return
}

// ---- CO24-N7: the stuck-peer holds, listed -------------------------------------------------------------------------

type StuckHold struct {
	Address     string `json:"address"`
	Strikes     uint   `json:"strikes"`
	HeldSeconds int64  `json:"held_seconds"` // remaining
	Height      int64  `json:"height"`       // the height it reported when it was last evicted
}

// StuckHolds lists the running stuck-peer holds (stuck_peer.go), the soonest to end first.
func StuckHolds(now time.Time) (out []StuckHold) {
	out = []StuckHold{}
	stuck.Lock()
	for ip, e := range stuck.hold {
		if now.Before(e.until) {
			out = append(out, StuckHold{Address: ip, Strikes: e.strikes, HeldSeconds: int64(e.until.Sub(now) / time.Second), Height: e.height})
		}
	}
	stuck.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].HeldSeconds != out[j].HeldSeconds {
			return out[i].HeldSeconds < out[j].HeldSeconds
		}
		return out[i].Address < out[j].Address
	})
	return
}

// note_chain_served counts one answered Chain request and the block ids it carried (CO24-N3).
func (c *Connection) note_chain_served(blocks int) {
	c.obs.chain_served.Add(1)
	c.obs.chain_blocks.Add(uint64(blocks))
	chain_requests_served.Inc()
	chain_request_blocks.Add(blocks)
}
