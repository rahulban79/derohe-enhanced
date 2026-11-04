// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package p2p

// r24 (security, B30): a returning-peer accept lane, the node-local part of the spoofed-source fix.
//
// KCP accepts a session from ONE datagram and the source address of a UDP datagram is not authenticated, so a sender
// that forges sources from many netgroups passes every per-address and per-netgroup check (each forged /16 has a full
// bucket) and empties the shared pre-TLS accept bucket (10/s, burst 40, controller.go). From then on every honest
// inbound session is refused at random, returning peers included (r23c p2psec OPEN-SPOOF, rft B30). The real fix is
// a return-routability cookie before any session state, which is a p2p wire change and stays report-only.
//
// What a node CAN do alone: remember the addresses that have PROVED they receive our packets — every connection that
// completed the TLS handshake and a verified Peer.Handshake (handshake_accepted, rpc_handshake.go), inbound or outbound — and give
// them a separate small accept lane when the shared bucket (or their netgroup's bucket) refuses. A forger that does
// not know which addresses are proven drains only the shared bucket; one that forges proven addresses (peer lists are
// gossiped) gets at most one lane session per proven address per PROVEN_PER_IP_INTERVAL and PROVEN_LANE_RATE in all,
// and each such session still has to complete TLS within INBOUND_TLS_HANDSHAKE_TIMEOUT. The netgroup inbound CAP
// (eclipse bound) and the ban checks still run first and are never bypassed. Nothing here changes the wire or what
// is valid; the normal path (the shared bucket allows) is unchanged and never touches this file.
//
// Live effect today: none (inbound is 0 until UDP 11011 is forwarded, rft B1).
//
// r25 (secpool, B48): a per-netgroup quota on the proven set. r24 kept the newest PROVEN_MAX addresses whatever their
// netgroup, so one operator who completed PROVEN_MAX real handshakes from one address block (a /16 holds 65,536
// addresses) evicted every honest proof and owned the lane. Now a netgroup (IPv4 /16, IPv6 /32: the buckets of the
// inbound cap, diversity.go netgroup) holds at most PROVEN_PER_NETGROUP proofs: a new proof in a full netgroup
// replaces that netgroup's OLDEST proof, never another netgroup's. When the whole set is full, the oldest proof of the
// LARGEST netgroup goes. So filling the set takes PROVEN_MAX/PROVEN_PER_NETGROUP (64) netgroups, and evicting an honest
// netgroup that holds h proofs takes more than (PROVEN_MAX-h)/h netgroups each holding more than h. Non-public
// addresses (loopback, LAN: netgroup "") are exempt from the quota, as everywhere else in the inbound guard.

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/deroproject/derohe/metrics"
)

const PROVEN_TTL = 7 * 24 * time.Hour           // a proof is good for a week (peers reconnect after restarts)
const PROVEN_MAX = 4096                         // bound on remembered addresses (memory, and the eviction scan)
const PROVEN_LANE_RATE = 2.0                    // lane sessions per second in all ...
const PROVEN_LANE_BURST = 8                     // ... with this burst
const PROVEN_PER_IP_INTERVAL = 10 * time.Second // and at most one lane session per proven address per interval
const PROVEN_PER_NETGROUP = 64                  // r25 (B48): proofs one netgroup may hold (honest: a handful per /16)

type proven_rec struct {
	at      time.Time // latest proof
	lane_at time.Time // latest lane admission
	group   string    // r25: netgroup(ip), "" = exempt
	gn      *int      // r25: that netgroup's proof count (proven_groups[group]; nil = exempt), no map lookup in scans
}

var proven_mu sync.Mutex
var proven_map = map[string]*proven_rec{}
var proven_groups = map[string]*int{} // r25: netgroup -> proofs it holds in proven_map (exempt "" not counted)
var proven_quota_evictions uint64     // r25: proofs replaced because their netgroup was at its quota
var proven_lane = rate.NewLimiter(PROVEN_LANE_RATE, PROVEN_LANE_BURST)
var proven_lane_admits, proven_lane_refusals uint64

var _ = metrics.Set.GetOrCreateGauge("p2p_inbound_proven_lane_admits_total", func() float64 { return float64(atomic.LoadUint64(&proven_lane_admits)) })
var _ = metrics.Set.GetOrCreateGauge("p2p_inbound_proven_lane_refusals_total", func() float64 { return float64(atomic.LoadUint64(&proven_lane_refusals)) })
var _ = metrics.Set.GetOrCreateGauge("p2p_inbound_proven_quota_evictions_total", func() float64 { return float64(atomic.LoadUint64(&proven_quota_evictions)) })

// proven_delete_locked removes ip's proof and its netgroup count. Caller holds proven_mu.
func proven_delete_locked(ip string) {
	r := proven_map[ip]
	if r == nil {
		return
	}
	delete(proven_map, ip)
	if r.gn != nil {
		if *r.gn--; *r.gn <= 0 {
			delete(proven_groups, r.group)
		}
	}
}

// proven_oldest_locked returns the oldest proof whose record satisfies pick. Caller holds proven_mu; one scan of at
// most PROVEN_MAX records, only when a quota or the bound is reached.
func proven_oldest_locked(pick func(*proven_rec) bool, now time.Time) (oldest string) {
	oldest_at := now.Add(time.Hour)
	for k, r := range proven_map {
		if pick(r) && r.at.Before(oldest_at) {
			oldest, oldest_at = k, r.at
		}
	}
	return
}

// note_proven records that ip completed a handshake (it receives our packets).
func note_proven(ip string, now time.Time) {
	if net.ParseIP(ip) == nil {
		return
	}
	proven_mu.Lock()
	defer proven_mu.Unlock()
	if r := proven_map[ip]; r != nil {
		r.at = now
		return
	}
	g := netgroup(ip)
	if gn := proven_groups[g]; g != "" && gn != nil && *gn >= PROVEN_PER_NETGROUP { // r25 (B48): a full netgroup replaces its own oldest proof
		if old := proven_oldest_locked(func(r *proven_rec) bool { return r.group == g }, now); old != "" {
			proven_delete_locked(old)
			atomic.AddUint64(&proven_quota_evictions, 1)
		}
	}
	if len(proven_map) >= PROVEN_MAX { // drop expired proofs, else the oldest proof of the largest netgroup (r25)
		big_n := 0 // the size of the largest netgroup; its oldest proof (among all netgroups of that size) goes
		for _, n := range proven_groups {
			if *n > big_n {
				big_n = *n
			}
		}
		// one scan (as r24): expired proofs go; remember the oldest proof of a largest netgroup, and the oldest of all
		// (used when no public proof is left to pick: only exempt ones, or the largest netgroup just expired)
		pick, pick_at, any, any_at := "", now.Add(time.Hour), "", now.Add(time.Hour)
		for k, r := range proven_map {
			if now.Sub(r.at) > PROVEN_TTL {
				proven_delete_locked(k)
				continue
			}
			if r.at.Before(any_at) {
				any, any_at = k, r.at
			}
			if r.gn != nil && *r.gn == big_n && r.at.Before(pick_at) {
				pick, pick_at = k, r.at
			}
		}
		if len(proven_map) >= PROVEN_MAX {
			if pick == "" {
				pick = any
			}
			if pick != "" {
				proven_delete_locked(pick)
			}
		}
	}
	rec := &proven_rec{at: now, group: g}
	if g != "" {
		if proven_groups[g] == nil {
			proven_groups[g] = new(int)
		}
		rec.gn = proven_groups[g]
		*rec.gn++
	}
	proven_map[ip] = rec
}

// proven_lane_allow admits one session from ip through the returning-peer lane, or refuses it.
func proven_lane_allow(ip string, now time.Time) bool {
	proven_mu.Lock()
	defer proven_mu.Unlock()
	r := proven_map[ip]
	if r == nil || now.Sub(r.at) > PROVEN_TTL {
		return false
	}
	if !r.lane_at.IsZero() && now.Sub(r.lane_at) < PROVEN_PER_IP_INTERVAL {
		atomic.AddUint64(&proven_lane_refusals, 1)
		return false
	}
	if !proven_lane.AllowN(now, 1) {
		atomic.AddUint64(&proven_lane_refusals, 1)
		return false
	}
	r.lane_at = now
	atomic.AddUint64(&proven_lane_admits, 1)
	return true
}
