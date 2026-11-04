// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package p2p

// Stuck-peer eviction (Round 22, r21 deferred F4). Local connection policy only: nothing about validity changes,
// and no peer is banned (a ban would also refuse it inbound and score it as hostile; a stuck node is just broken).
//
// Evidence (live r21 derod, DERO.GetPeerInfo 2026-10-29 06:40 and 06:47, 15 outgoing peers, 0 inbound): two of the
// 15 outgoing slots were held for the whole 7.4 h run by peers that never moved:
//   - one at height 7,472,150 with top_version 2 (a pre-HF3 3.5.5-142 node, 354,875 blocks behind). The v2-chain
//     guard in common.go does not fire for it: it only drops v2 peers ABOVE MAJOR_HF3_HEIGHT+STABLE_LIMIT;
//   - one at height 7,537,830 (a 3.6.0-152 node, 289,195 blocks behind, i.e. frozen at a replay wall).
// Both had first_relays 0 and miniblocks_total 0 for the whole run, and neither can ever serve sync (trigger_sync
// only syncs from peers AHEAD of us) or receive relays (broadcasts skip peers outside LAGGING_PEER_BLOCKS). The
// second one still cost upload: bytes_out 5,577,639 -> 5,922,254 in ~7 min while it kept asking us for chain.
// Ping and the 20 s idle purge cannot catch this: both peers answer pings.
//
// Rule (stuck_select, pure and unit-tested): an OUTGOING, non-exempt connection is stuck when its reported height
// is more than STUCK_PEER_BLOCKS below ours AND has not changed for STUCK_PEER_WINDOW. A peer that is catching up
// (height moving at all) is never stuck. Safety: nothing is evicted unless at least STUCK_MIN_HEALTHY peers are
// within the window of our height (so our own view of the tip is corroborated) and the stuck set is no larger than
// the healthy set; at most one eviction per sweep. Exempt: --sync-node connections and never_ban addresses (seed,
// priority and exclusive nodes). An evicted address is not redialled for STUCK_HOLD (doubling per repeat, at most
// STUCK_HOLD_MAX); it may still connect IN.
//
// Round 23, fast re-eviction. Live r22 derod (pid 30565, derod.log 2026-10-29 14:55 -> 2026-10-30 00:08): the same two
// peers were evicted 7 times each over the log (4 each since the 19:55 restart), always at the very same heights
// [r25 B70: RFC 5737 stand-ins for the observed addresses]
// (203.0.113.166 at 7,472,150; 203.0.113.167 at 7,537,830). After every hold they were redialled and held a connection
// for the full STUCK_PEER_WINDOW again, e.g.
// hold end 20:35:38 -> evicted 20:46:35, hold end 21:46:38 -> evicted 21:57:05: about 10.5 min connected per cycle,
// each minute costing ~49 KB of upload (the r21 GetPeerInfo above) plus their chain requests. The hold entry now keeps
// the height the peer was evicted at; a redialled peer that reports exactly that height again (it has not moved for at
// least the whole hold) is a candidate at once, still subject to every safety rule above (outgoing, not exempt,
// beyond the relay window, corroborated, one per sweep). A peer that moved at all is judged by the normal window.

import (
	"sort"
	"sync"
	"time"

	"github.com/deroproject/derohe/metrics"
)

const STUCK_PEER_BLOCKS = LAGGING_PEER_BLOCKS // the relay window: beyond it a peer gets no blocks/miniblocks/txs
const STUCK_PEER_WINDOW = 10 * time.Minute    // ~33 blocks at 18 s: a live peer's height changes many times
const STUCK_MIN_HEALTHY = 2
const STUCK_HOLD = 30 * time.Minute
const STUCK_HOLD_MAX = 6 * time.Hour
const STUCK_HOLD_ENTRIES = 256

var _ = metrics.Set.GetOrCreateCounter("p2p_stuck_peer_evictions_total")
var _ = metrics.Set.GetOrCreateCounter("p2p_stuck_peer_fast_evictions_total") // r23: re-evicted at the height recorded before

type stuck_view struct {
	c        *Connection
	ip       string
	height   int64
	outgoing bool
	exempt   bool
	since    time.Time // filled by stuck_select for returned views: when this height was first seen
}

type stuck_track struct {
	height int64
	since  time.Time // when this height was first seen
}

type stuck_hold_entry struct {
	strikes uint
	until   time.Time
	height  int64 // the height the peer reported when it was last evicted
}

var stuck = struct {
	sync.Mutex
	track map[*Connection]*stuck_track
	hold  map[string]*stuck_hold_entry
}{track: map[*Connection]*stuck_track{}, hold: map[string]*stuck_hold_entry{}}

// stuck_select updates track with views (dropping connections that are gone) and returns at most one view to evict.
// hold (may be nil) is the eviction record: a view whose ip was evicted before at exactly its current height skips the
// window (fast re-eviction).
func stuck_select(views []stuck_view, our_height int64, now time.Time, track map[*Connection]*stuck_track,
	hold map[string]*stuck_hold_entry) []stuck_view {
	present := make(map[*Connection]bool, len(views))
	for _, v := range views {
		present[v.c] = true
		if t := track[v.c]; t == nil || t.height != v.height {
			track[v.c] = &stuck_track{height: v.height, since: now}
		}
	}
	for c := range track {
		if !present[c] {
			delete(track, c)
		}
	}
	healthy := 0
	var cands []stuck_view
	for _, v := range views {
		if our_height-v.height <= STUCK_PEER_BLOCKS {
			healthy++
			continue
		}
		if !v.outgoing || v.exempt {
			continue
		}
		if now.Sub(track[v.c].since) >= STUCK_PEER_WINDOW || stuck_known_at(hold, v.ip, v.height) {
			cands = append(cands, v)
		}
	}
	if len(cands) == 0 || healthy < STUCK_MIN_HEALTHY || len(cands) > healthy {
		return nil
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].height < cands[j].height })
	cands[0].since = track[cands[0].c].since
	return cands[:1]
}

// stuck_known_at: ip was evicted as stuck before, and it reports the very height it had then.
func stuck_known_at(hold map[string]*stuck_hold_entry, ip string, height int64) bool {
	e := hold[ip]
	return e != nil && e.strikes > 0 && e.height == height
}

func stuck_hold_duration(strikes uint) time.Duration {
	d := STUCK_HOLD
	for i := uint(1); i < strikes && d < STUCK_HOLD_MAX; i++ {
		d *= 2
	}
	if d > STUCK_HOLD_MAX {
		d = STUCK_HOLD_MAX
	}
	return d
}

// stuck_hold_add records that ip was evicted as stuck at height; returns the hold end.
func stuck_hold_add(ip string, height int64, now time.Time) time.Time {
	stuck.Lock()
	defer stuck.Unlock()
	e := stuck.hold[ip]
	if e == nil {
		if len(stuck.hold) >= STUCK_HOLD_ENTRIES {
			for k, v := range stuck.hold {
				if !now.Before(v.until) {
					delete(stuck.hold, k)
				}
			}
			if len(stuck.hold) >= STUCK_HOLD_ENTRIES {
				return now // fail open: not recorded, the address is dialed as before
			}
		}
		e = &stuck_hold_entry{}
		stuck.hold[ip] = e
	}
	e.strikes++
	e.until = now.Add(stuck_hold_duration(e.strikes))
	e.height = height
	return e.until
}

// stuck_held reports whether an outgoing dial to ip must wait (it was evicted as stuck recently).
func stuck_held(ip string, now time.Time) bool {
	stuck.Lock()
	defer stuck.Unlock()
	e := stuck.hold[ip]
	return e != nil && now.Before(e.until)
}

func stuck_held_count(now time.Time) (n int) {
	stuck.Lock()
	defer stuck.Unlock()
	for _, e := range stuck.hold {
		if now.Before(e.until) {
			n++
		}
	}
	return
}

var _ = metrics.Set.GetOrCreateGauge("p2p_stuck_peer_held", func() float64 { return float64(stuck_held_count(time.Now())) })

// stuck_peer_views snapshots the handshaken connections.
func stuck_peer_views() (views []stuck_view) {
	self := GetPeerID()
	connection_map.Range(func(k, value interface{}) bool {
		c := value.(*Connection)
		if c.State.Load() == HANDSHAKE_PENDING || c.Peer_ID == self {
			return true
		}
		ip := Address(c)
		views = append(views, stuck_view{c: c, ip: ip, height: c.Height.Load(), outgoing: !c.Incoming,
			exempt: c.SyncNode || never_ban(ip)})
		return true
	})
	return
}

// stuck_peer_sweep runs from the cron (every 30 s).
func stuck_peer_sweep() {
	if chain == nil {
		return
	}
	stuck_peer_sweep_with(stuck_peer_views(), chain.Get_Height(), time.Now())
}

// stuck_peer_sweep_with selects and evicts; it returns what it evicted (tests drive it with fixed views and times).
func stuck_peer_sweep_with(views []stuck_view, our int64, now time.Time) []stuck_view {
	stuck.Lock()
	evict := stuck_select(views, our, now, stuck.track, stuck.hold)
	stuck.Unlock()
	for _, v := range evict {
		fast := now.Sub(v.since) < STUCK_PEER_WINDOW
		until := stuck_hold_add(v.ip, v.height, now)
		if fast {
			metrics.Set.GetOrCreateCounter("p2p_stuck_peer_fast_evictions_total").Inc()
		}
		if p := GetPeerInList(v.ip); p != nil { // find_peer_to_connect skips it until then
			peer_mutex.Lock()
			if u := uint64(until.Unix()); p.ConnectAfter < u {
				p.ConnectAfter = u
			}
			peer_mutex.Unlock()
		}
		metrics.Set.GetOrCreateCounter("p2p_stuck_peer_evictions_total").Inc()
		v.c.logger.V(1).Info("evicting stuck peer", "peer_height", v.height, "our_height", our, "hold", until.Sub(now).String())
		v.c.exit()
	}
	return evict
}
