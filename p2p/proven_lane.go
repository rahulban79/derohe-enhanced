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

type proven_rec struct {
	at      time.Time // latest proof
	lane_at time.Time // latest lane admission
}

var proven_mu sync.Mutex
var proven_map = map[string]*proven_rec{}
var proven_lane = rate.NewLimiter(PROVEN_LANE_RATE, PROVEN_LANE_BURST)
var proven_lane_admits, proven_lane_refusals uint64

var _ = metrics.Set.GetOrCreateGauge("p2p_inbound_proven_lane_admits_total", func() float64 { return float64(atomic.LoadUint64(&proven_lane_admits)) })
var _ = metrics.Set.GetOrCreateGauge("p2p_inbound_proven_lane_refusals_total", func() float64 { return float64(atomic.LoadUint64(&proven_lane_refusals)) })

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
	if len(proven_map) >= PROVEN_MAX { // drop expired proofs, else the oldest one (bounded: one scan per new address)
		oldest, oldest_at := "", now
		for k, r := range proven_map {
			if now.Sub(r.at) > PROVEN_TTL {
				delete(proven_map, k)
				continue
			}
			if r.at.Before(oldest_at) {
				oldest, oldest_at = k, r.at
			}
		}
		if len(proven_map) >= PROVEN_MAX && oldest != "" {
			delete(proven_map, oldest)
		}
	}
	proven_map[ip] = &proven_rec{at: now}
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
