// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package rpc

// r23 (security): call-cost accounting and behavioural scoring for REMOTE RPC clients.
//
// Before r23 a client reaching a non-loopback --rpc-bind was bounded only in concurrency (32 HTTP requests in flight
// and 64 websockets per address, ws_hardening.go): it could send calls as fast as the node answered them, choose the
// most expensive methods (GetBlockHeadersRange, GetGasEstimate runs the DVM), and probe every method name and
// parameter shape for free. Automated scanners and LLM-driven fuzzers do exactly that: many methods, many malformed
// params, many unknown names, quickly.
//
// Now every remote key (an IPv4 address, or an IPv6 /64, which one end site controls) has
//   - a weighted call bucket (abuse_rate tokens/s, burst abuse_burst; cost per method from foreign_method_cost plus
//     the write/DVM methods below): an honest wallet or explorer stays far inside it, a flooder is refused with a
//     machine-readable error (RPC_CODE_RATE_LIMITED, data {"retry_after_ms":N}) that costs no handler work;
//   - a behavioural score that halves every ABUSE_HALF_LIFE: unknown method names, invalid params/requests and parse
//     errors add points, refusals add a little; a score reaching ABUSE_SCORE_BAN bans the key for ABUSE_BAN_BASE,
//     doubling per repeat up to ABUSE_BAN_MAX. A banned key gets RPC_CODE_BANNED (HTTP 429 + Retry-After) and its
//     websocket is closed; it cannot open a new one until the ban ends.
//
// Loopback (wallet CLI, miner, explorer, a local reverse proxy) is never scored or limited, so the live node and every
// local tool pay nothing: the guard is one map lookup on the remote path only. Cross-site browser sockets that arrive
// over loopback (FOREIGN_LIMIT_KEY) keep their own r21 limiter and are not banned here, so one malicious page cannot
// ban the user's own web wallet. Error replies carry a code, a fixed message and a retry hint, never internal detail.
//
// Environment (read once at RPC start): DERO_RPC_ABUSE_GUARD=0 turns the guard off; DERO_RPC_REMOTE_RATE and
// DERO_RPC_REMOTE_BURST set the bucket. Nothing here is consensus-visible.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/code"
	"github.com/creachadair/jrpc2/handler"

	dmetrics "github.com/deroproject/derohe/metrics"
)

// RPC_CODE_BANNED: the caller's key is temporarily banned for abusive behaviour (JSON-RPC server-error range).
const RPC_CODE_BANNED = code.Code(-32030)

const ABUSE_SCORE_BAN = 100.0
const ABUSE_HALF_LIFE = 60 * time.Second
const ABUSE_BAN_BASE = 30 * time.Second
const ABUSE_BAN_MAX = time.Hour
const ABUSE_STRIKE_FORGET = 24 * time.Hour // a key not banned for a day starts again at ABUSE_BAN_BASE
const ABUSE_MAX_ENTRIES = 16384            // bound on tracked keys (memory); see abuse_table.entry
const ABUSE_OVERFLOW_KEY = "abuse-overflow"

// ABUSE_PRUNE_INTERVAL: a full table is scanned for idle records at most this often (r23 merge). Before, every request
// from an untracked key scanned all 16384 records under t.mu (~0.5 ms measured), so a filled table capped all remote
// RPC at ~2,000 admissions/s.
const ABUSE_PRUNE_INTERVAL = time.Second

// ABUSE_OVERFLOW_SCALE: the shared overflow record's bucket is this many times a key's bucket, and it is never scored
// or banned: keys that did not fit the table must not be able to ban every new honest client at once (r23 merge).
const ABUSE_OVERFLOW_SCALE = 8.0

// default remote bucket: 200 weighted calls/s, burst 2000 (a wallet refresh is ~5-20 calls; a full explorer page ~50)
const ABUSE_DEFAULT_RATE = 200.0
const ABUSE_DEFAULT_BURST = 2000.0

// r23b: global (all remote keys together) anomaly budget. Per-key scoring alone lets a fleet of N addresses each
// stay just under its ban line: at ABUSE_HALF_LIFE 60 s a key settles at score = rate*pts*86.6 s, so a key sending
// fewer than 0.23 unknown names/s (13.9/min) is never banned, and N keys probe 13.9*N names/min. Anomalies (unknown
// names, invalid params/requests, parse errors) from every remote key draw on one bucket; while it is empty the node
// is in a probing surge and every anomaly scores ABUSE_SURGE_FACTOR times its points, so the per-key line drops to
// 3.5/min. An honest client is unaffected unless it ITSELF sends several invalid calls a minute during a surge;
// loopback and the foreign key never reach this code; successes and ordinary handler errors never draw on it.
const ABUSE_GLOBAL_ANOMALY_RATE = 10.0   // anomalies/s across all remote keys before a surge
const ABUSE_GLOBAL_ANOMALY_BURST = 600.0 // a minute of the rate
const ABUSE_SURGE_FACTOR = 4.0

// r23c (p2psec): collective measures target fresh identities only.
//
// The r23b surge can be triggered on purpose: ~10 anomalies/s from anywhere empty the global bucket, and from then on
// EVERY remote key's anomalies score x4, so an honest wallet that sends a few malformed calls a minute (an outdated
// client, a typo in a script) is banned four times sooner, by someone else's traffic. And a per-key line alone lets
// one operator rotate through its addresses: 256 IPv4 keys in a /24 (or 65,536 /64s in a /48) each probe just under
// the line.
// A key is TRUSTED once it has been seen for ABUSE_TRUST_AGE and has had ABUSE_TRUST_CALLS calls admitted (r24: to served names), with no
// ban in the strike memory (ABUSE_STRIKE_FORGET). Trusted keys keep their own per-key bucket and ban line but are
// exempt from the surge factor and from their aggregate's bucket and ban. Untrusted keys also draw on, and score
// into, an AGGREGATE record (IPv4 /24, IPv6 /48): its bucket is ABUSE_AGG_SCALE times a key's, and anomaly and
// refusal points (not ordinary handler errors) ban the whole aggregate for its untrusted keys at ABUSE_AGG_SCORE_BAN.
// So the surge and the /24 ban hit exactly the identities an adaptive attacker can mint cheaply, and an attacker who
// wants to escape them must first spend ABUSE_TRUST_AGE and ABUSE_TRUST_CALLS of honest calls PER identity.
const ABUSE_TRUST_AGE = 10 * time.Minute
const ABUSE_TRUST_CALLS = 64
const ABUSE_AGG_SCORE_BAN = 4 * ABUSE_SCORE_BAN // ~55 unknown names/min across one /24 (vs 13.9/min per key x 256)
const ABUSE_AGG_SCALE = 8.0
const ABUSE_AGG_PREFIX = "agg:"

// r24 (security, B28): trust is earned by honest calls and LOST by probing.
//
// r23c trust was permanent while a key was not banned: 16 keys pre-warmed with 70 cheap GetInfo calls each over
// 10.5 min were then exempt from the /24 aggregate and from the surge, and probed 4,800 unknown names in 30 min with
// none refused (fresh keys: 572), and 64 pre-warmed keys in 64 /24s probed 19,200/19,200 through a held surge
// (fresh: 1,920). Two rules close that, both on the unknown-method branch only (the known-method path is unchanged):
//   - every unknown name of a trusted key still scores into its aggregate (trusted keys stay exempt from the
//     aggregate's ban and bucket), so a pre-warmed fleet in one /24 bans the /24 like a fresh one;
//   - a trusted key loses its trust (and must earn it again: ABUSE_TRUST_AGE and ABUSE_TRUST_CALLS from now) when its
//     own decayed unknown-name score reaches ABUSE_TRUST_PROBE_MAX. An unknown name it sends while its aggregate is
//     banned is refused (r24 verify: rate_limited, trust kept until the probe line; see admit).
//
// Bad params / invalid requests (an outdated client) never revoke trust: the R23c B12 guarantee is kept as tested.
// An honest wallet polling ONE method this node lacks once per block (3.3/min) settles at ~24 points, under the line.
const ABUSE_TRUST_PROBE_MAX = 10 * ABUSE_PTS_UNKNOWN_METHOD // 10 unknown names at once, or ~6.9/min sustained

// r25 (secpool, B48): a fresh key's burst is a quarter of a trusted key's.
//
// Every new remote key started with the full ABUSE_DEFAULT_BURST (2,000 tokens) at once: a fresh websocket could spend
// it on 58 full GetTransaction calls (256 txids = 34 tokens each, ~14.8k txids) before the rate applied (r24 rpcws
// residual), and an operator with one key in each of N aggregates (/24, /48) got N full bursts at once, because the
// aggregate bucket only bounds keys that share an aggregate. An untrusted key now holds at most
// ABUSE_FRESH_BURST_FRAC of the burst (500 tokens at the default: still ten explorer pages or a wallet refresh 25 times
// over); the RATE is unchanged, so a client that stays under 200 weighted calls/s never notices, and a key earns the
// full burst with its trust (ABUSE_TRUST_AGE and ABUSE_TRUST_CALLS of served calls). Loopback never reaches this code.
const ABUSE_FRESH_BURST_FRAC = 0.25

// behaviour points
const (
	ABUSE_PTS_UNKNOWN_METHOD = 5.0 // a name no handler serves: 20 within a minute ban
	ABUSE_PTS_BAD_REQUEST    = 3.0 // invalid params / invalid request / parse error: ~34 within a minute ban
	ABUSE_PTS_OTHER_ERROR    = 0.5 // a handler error (e.g. "not found"): honest clients see these; 200+/min to ban
	ABUSE_PTS_REFUSED        = 1.0 // a call refused by the bucket: hammering on after refusals ends in a ban
)

// remote costs beyond foreign_method_cost: write paths and methods that run the DVM or scan the pool
var remote_method_cost = map[string]int{
	"DERO.GetGasEstimate":     16,
	"getgasestimate":          16,
	"DERO.SendRawTransaction": 4,
	"sendrawtransaction":      4,
	"DERO.GetSupplyAudit":     8,
	"DERO.GetBlockTemplate":   2,
	"getblocktemplate":        2,
	"DERO.SubmitBlock":        4,
	"submitblock":             4,
	// r24 (cryptoinfl CI24-3): ~18 ms CPU per call with the depth-corrected sampler (~8.6 ms before; ~400 tree
	// draws + proofs on mainnet, capped at R24_DECOY_DRAW_BUDGET): at weight 1 one remote key could spend ~3.6 cores
	"DERO.GetRandomAddress": 8,
	"getrandomaddress":      8,
}

func remote_cost(method string) int {
	if n, ok := remote_method_cost[method]; ok {
		return n
	}
	return foreign_cost(method)
}

type abuse_verdict int

const (
	abuse_ok abuse_verdict = iota
	abuse_rate_limited
	abuse_banned
)

type abuse_entry struct {
	tokens       float64
	tok_at       time.Time
	score        float64
	score_at     time.Time
	strikes      uint
	banned_until time.Time
	last_ban     time.Time
	last_seen    time.Time
	overflow     bool         // the shared ABUSE_OVERFLOW_KEY record: rate-limited only, never scored or banned
	first_seen   time.Time    // r23c: trust age
	served       uint32       // r23c: calls admitted (saturating)
	aggregate    bool         // r23c: an ABUSE_AGG_PREFIX record (ban line ABUSE_AGG_SCORE_BAN)
	agg          string       // r23c: this key's aggregate record key ("" = none), computed once
	agg_rec      *abuse_entry // r23c: cached aggregate record (valid while !agg_rec.dead)
	dead         bool         // r23c: pruned from the table (a cached pointer to it must be looked up again)
	probe        float64      // r24: decayed unknown-name points while trusted (x1, ABUSE_HALF_LIFE): trust revocation
	probe_at     time.Time    // r24
}

type abuse_table struct {
	mu          sync.Mutex
	m           map[string]*abuse_entry
	enabled     bool
	rate, burst float64
	max_entries int
	last_prune  time.Time
	scanned     uint64    // records examined by prune scans (tests: the full-table cost per admission is bounded)
	g_tokens    float64   // r23b: global anomaly bucket
	g_at        time.Time // last refill of g_tokens
	g_init      bool
}

func new_abuse_table(rate, burst float64, max_entries int) *abuse_table {
	return &abuse_table{m: map[string]*abuse_entry{}, enabled: true, rate: rate, burst: burst, max_entries: max_entries}
}

var rpc_abuse = new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)

var (
	abuse_refused_rate   = dmetrics.Set.GetOrCreateCounter(`rpc_abuse_refused_total{reason="rate"}`)
	abuse_refused_banned = dmetrics.Set.GetOrCreateCounter(`rpc_abuse_refused_total{reason="banned"}`)
	abuse_bans           = dmetrics.Set.GetOrCreateCounter("rpc_abuse_bans_total")
	abuse_unknown        = dmetrics.Set.GetOrCreateCounter("rpc_abuse_unknown_method_total")
	abuse_bad_request    = dmetrics.Set.GetOrCreateCounter("rpc_abuse_bad_request_total")
	abuse_surge_scored   = dmetrics.Set.GetOrCreateCounter("rpc_abuse_surge_scored_total")                // anomalies scored at the surge factor
	abuse_refused_agg    = dmetrics.Set.GetOrCreateCounter(`rpc_abuse_refused_total{reason="aggregate"}`) // r23c
	abuse_agg_bans       = dmetrics.Set.GetOrCreateCounter("rpc_abuse_aggregate_bans_total")              // r23c
	abuse_surge_trusted  = dmetrics.Set.GetOrCreateCounter("rpc_abuse_surge_trusted_total")               // r23c: surge anomalies of trusted keys, scored x1
	abuse_trust_revoked  = dmetrics.Set.GetOrCreateCounter("rpc_abuse_trust_revoked_total")               // r24: trusted keys that probed
	abuse_agg_short      = dmetrics.Set.GetOrCreateCounter("rpc_abuse_aggregate_short_total")             // r24: refusals by the aggregate bucket alone (never scored)
	_                    = dmetrics.Set.GetOrCreateGauge("rpc_abuse_global_surge", func() float64 { return rpc_abuse.surge_gauge(time.Now()) })
	_                    = dmetrics.Set.GetOrCreateGauge("rpc_abuse_tracked_keys", func() float64 { return float64(rpc_abuse.size()) })
)

// configure_abuse applies the environment (RPC start).
func configure_abuse(t *abuse_table, getenv func(string) string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if getenv("DERO_RPC_ABUSE_GUARD") == "0" {
		t.enabled = false
	}
	if v, err := strconv.ParseFloat(getenv("DERO_RPC_REMOTE_RATE"), 64); err == nil && v > 0 {
		t.rate = v
	}
	if v, err := strconv.ParseFloat(getenv("DERO_RPC_REMOTE_BURST"), 64); err == nil && v >= 1 {
		t.burst = v
	}
}

// abuse_key: the address itself for IPv4 (and anything that is not an IP), the /64 for IPv6.
func abuse_key(host string) string {
	p := net.ParseIP(host)
	if p == nil || p.To4() != nil || p.IsLoopback() {
		return host
	}
	return (&net.IPNet{IP: p.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}).String()
}

// abuse_agg_key: the aggregate record of a key: the /24 of an IPv4 address, the /48 of an IPv6 /64 key; "" otherwise.
func abuse_agg_key(key string) string {
	if p := net.ParseIP(key); p != nil {
		if v4 := p.To4(); v4 != nil && !p.IsLoopback() {
			return ABUSE_AGG_PREFIX + (&net.IPNet{IP: v4.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}).String()
		}
		return ""
	}
	if ip, n, err := net.ParseCIDR(key); err == nil && ip.To4() == nil {
		if ones, bits := n.Mask.Size(); bits == 128 && ones >= 48 {
			return ABUSE_AGG_PREFIX + (&net.IPNet{IP: n.IP.Mask(net.CIDRMask(48, 128)), Mask: net.CIDRMask(48, 128)}).String()
		}
	}
	return ""
}

// trusted_locked: an established, never-recently-banned key (see ABUSE_TRUST_AGE). Caller holds t.mu.
func trusted_locked(e *abuse_entry, now time.Time) bool {
	return !e.overflow && !e.aggregate && e.served >= ABUSE_TRUST_CALLS && now.Sub(e.first_seen) >= ABUSE_TRUST_AGE &&
		(e.strikes == 0 || now.Sub(e.last_ban) > ABUSE_STRIKE_FORGET)
}

// agg_locked returns the aggregate record an untrusted key e draws on, or nil (none, or the table is full).
// e.last_seen must already be now, so a prune triggered here cannot drop e. Caller holds t.mu.
func (t *abuse_table) agg_locked(e *abuse_entry, now time.Time) *abuse_entry {
	if e.overflow || e.aggregate || e.agg == "" {
		return nil
	}
	if g := e.agg_rec; g != nil && !g.dead { // no map lookup on the normal path
		g.last_seen = now
		return g
	}
	g := t.entry(e.agg, now)
	if g.overflow {
		return nil
	}
	g.aggregate = true
	g.last_seen = now
	e.agg_rec = g
	return g
}

// score_locked adds pts to key e and agg_pts to its aggregate g (nil = none); returns the longer new ban (0 = none).
func (t *abuse_table) score_locked(e, g *abuse_entry, pts, agg_pts float64, now time.Time) time.Duration {
	d := t.add_locked(e, pts, now)
	if g != nil && agg_pts > 0 {
		if gd := t.add_locked(g, agg_pts, now); gd > 0 {
			abuse_agg_bans.Inc()
			if gd > d {
				d = gd
			}
		}
	}
	return d
}

func (t *abuse_table) is_enabled() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.enabled
}

func (t *abuse_table) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m)
}

// entry returns key's record, creating it. When the table is full, idle records that are neither banned nor scored
// are dropped (at most one scan per ABUSE_PRUNE_INTERVAL); if it is still full the new key shares ABUSE_OVERFLOW_KEY
// (so a spray of source addresses costs bounded memory and CPU, and shares one bucket). Caller holds t.mu.
func (t *abuse_table) entry(key string, now time.Time) *abuse_entry {
	if e := t.m[key]; e != nil {
		return e
	}
	if len(t.m) >= t.max_entries && now.Sub(t.last_prune) >= ABUSE_PRUNE_INTERVAL {
		t.last_prune = now
		for k, e := range t.m {
			t.scanned++
			if now.After(e.banned_until) && decayed(e.score, e.score_at, now) < 1 && now.Sub(e.last_seen) > ABUSE_HALF_LIFE &&
				(e.strikes == 0 || now.Sub(e.last_ban) > ABUSE_STRIKE_FORGET) {
				e.dead = true
				delete(t.m, k)
			}
		}
	}
	if len(t.m) >= t.max_entries {
		if e := t.m[ABUSE_OVERFLOW_KEY]; e != nil {
			return e
		}
		e := &abuse_entry{tokens: t.burst * ABUSE_OVERFLOW_SCALE, tok_at: now, score_at: now, last_seen: now, overflow: true}
		t.m[ABUSE_OVERFLOW_KEY] = e
		return e
	}
	e := &abuse_entry{tokens: t.burst, tok_at: now, score_at: now, last_seen: now, first_seen: now} // r25 (B48): admit_items clamps an untrusted key to its fresh burst
	if strings.HasPrefix(key, ABUSE_AGG_PREFIX) {
		e.aggregate = true
		e.tokens = t.burst * ABUSE_AGG_SCALE
	} else {
		e.agg = abuse_agg_key(key)
	}
	t.m[key] = e
	return e
}

func decayed(score float64, at, now time.Time) float64 {
	if score == 0 {
		return 0
	}
	return score * math.Pow(0.5, now.Sub(at).Seconds()/ABUSE_HALF_LIFE.Seconds())
}

// anomaly_factor draws one anomaly from the global bucket and returns the points multiplier (1, or
// ABUSE_SURGE_FACTOR while the bucket is empty). Caller holds t.mu.
func (t *abuse_table) anomaly_factor(now time.Time) float64 {
	t.refill_global_locked(now)
	if t.g_tokens >= 1 {
		t.g_tokens--
		return 1
	}
	abuse_surge_scored.Inc()
	return ABUSE_SURGE_FACTOR
}

func (t *abuse_table) refill_global_locked(now time.Time) {
	if !t.g_init {
		t.g_init, t.g_tokens, t.g_at = true, ABUSE_GLOBAL_ANOMALY_BURST, now
		return
	}
	if dt := now.Sub(t.g_at).Seconds(); dt > 0 {
		t.g_tokens += dt * ABUSE_GLOBAL_ANOMALY_RATE
		if t.g_tokens > ABUSE_GLOBAL_ANOMALY_BURST {
			t.g_tokens = ABUSE_GLOBAL_ANOMALY_BURST
		}
		t.g_at = now
	}
}

// surge_gauge: 1 while the global anomaly bucket is empty (metrics).
func (t *abuse_table) surge_gauge(now time.Time) float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.refill_global_locked(now)
	if t.g_tokens < 1 {
		return 1
	}
	return 0
}

// add_locked adds behaviour points and bans when the score is reached; returns the ban length (0 = not banned now).
func (t *abuse_table) add_locked(e *abuse_entry, pts float64, now time.Time) time.Duration {
	if e.overflow { // shared by many keys: scoring it would let attackers ban every new honest client (r23 merge)
		return 0
	}
	e.score = decayed(e.score, e.score_at, now) + pts
	e.score_at = now
	line := ABUSE_SCORE_BAN
	if e.aggregate {
		line = ABUSE_AGG_SCORE_BAN
	}
	if e.score < line {
		return 0
	}
	if e.strikes > 0 && now.Sub(e.last_ban) > ABUSE_STRIKE_FORGET {
		e.strikes = 0
	}
	e.strikes++
	d := ABUSE_BAN_BASE
	for i := uint(1); i < e.strikes && d < ABUSE_BAN_MAX; i++ {
		d *= 2
	}
	if d > ABUSE_BAN_MAX {
		d = ABUSE_BAN_MAX
	}
	e.score = 0
	e.banned_until = now.Add(d)
	e.last_ban = now
	abuse_bans.Inc()
	return d
}

// admit charges one call of method to key. unknown marks a method name no handler serves.
func (t *abuse_table) admit(key, method string, unknown bool, now time.Time) (abuse_verdict, time.Duration) {
	return t.admit_items(key, method, unknown, 0, now)
}

// admit_items is admit with item_tokens added to the method's cost (r24 rpcws B29: a call naming many txids or SC
// keys pays for them, item_tokens = item_cost(n), r24_rpcws.go).
func (t *abuse_table) admit_items(key, method string, unknown bool, item_tokens int, now time.Time) (abuse_verdict, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.enabled {
		return abuse_ok, 0
	}
	e := t.entry(key, now)
	e.last_seen = now
	if now.Before(e.banned_until) {
		abuse_refused_banned.Inc()
		return abuse_banned, e.banned_until.Sub(now)
	}
	trusted := trusted_locked(e, now)
	var g *abuse_entry // r23c: the aggregate of an untrusted key
	if !trusted {
		if g = t.agg_locked(e, now); g != nil && now.Before(g.banned_until) {
			abuse_refused_agg.Inc()
			return abuse_banned, g.banned_until.Sub(now)
		}
	}
	if unknown {
		abuse_unknown.Inc()
		sg := g      // the aggregate this unknown name scores into
		if trusted { // r24 (B28): a trusted key's probing still counts against its /24, and can cost it its trust
			e.probe = decayed(e.probe, e.probe_at, now) + ABUSE_PTS_UNKNOWN_METHOD // counted while trusted only
			e.probe_at = now
			sg = t.agg_locked(e, now)
			agg_banned := sg != nil && now.Before(sg.banned_until)
			if e.probe >= ABUSE_TRUST_PROBE_MAX {
				e.first_seen, e.served, e.probe = now, 0, 0 // trust is earned again from here
				trusted, g = false, sg
				abuse_trust_revoked.Inc()
			}
			if agg_banned { // a probe from a banned /24 is never admitted
				abuse_refused_agg.Inc()
				if !trusted {
					return abuse_banned, sg.banned_until.Sub(now)
				}
				// r24 verify: a key still trusted is refused THIS name only and keeps its trust (and its socket:
				// rate_limited, not banned). Revoking on any unknown name in a banned /24 let a neighbour who keeps the
				// /24 banned deny an honest trusted wallet that polls one missing method per block: 1,767 of its 1,800
				// GetInfo calls refused in 60 min, base 04ceb55 0 (TestR24VerifyNeighbourCannotRevokeHonestTrust).
				return abuse_rate_limited, sg.banned_until.Sub(now)
			}
		}
		pts := ABUSE_PTS_UNKNOWN_METHOD
		if f := t.anomaly_factor(now); f != 1 { // r23b budget (drawn by every key); r23c: the factor spares trusted keys
			if trusted {
				abuse_surge_trusted.Inc()
			} else {
				pts *= f
			}
		}
		var d time.Duration
		if trusted { // still trusted: its aggregate's ban does not refuse it (r23c), so only its own line can
			d = t.score_locked(e, nil, pts, 0, now)
			if sg != nil && t.add_locked(sg, ABUSE_PTS_UNKNOWN_METHOD, now) > 0 {
				abuse_agg_bans.Inc()
			}
		} else {
			d = t.score_locked(e, sg, pts, ABUSE_PTS_UNKNOWN_METHOD, now)
		}
		if d > 0 {
			abuse_refused_banned.Inc()
			return abuse_banned, d
		}
	}
	rate, burst := t.rate, t.burst
	if e.overflow {
		rate, burst = rate*ABUSE_OVERFLOW_SCALE, burst*ABUSE_OVERFLOW_SCALE
	} else if !trusted { // r25 (B48): a fresh key holds a quarter of the burst until it is trusted
		burst *= ABUSE_FRESH_BURST_FRAC
	}
	refill(e, rate, burst, now)
	cost := float64(remote_cost(method) + item_tokens)
	short, short_rate := cost-e.tokens, rate
	own_short := short > 0 // r24: the key itself is over its own bucket
	if g != nil {
		grate := t.rate * ABUSE_AGG_SCALE
		refill(g, grate, t.burst*ABUSE_AGG_SCALE, now)
		if gs := cost - g.tokens; gs > 0 && gs/grate > short/short_rate {
			short, short_rate = gs, grate
		}
	}
	if short > 0 {
		abuse_refused_rate.Inc()
		// r24 (B28): a key within its own bucket, refused only because its /24 shares the aggregate bucket, is not
		// hammering: r23c scored that refusal into the key and the aggregate, so 12 fresh honest keys of one /24 at
		// 150 calls/s banned their own /24 (51,747 + 71,709 + 11,460 calls refused as BANNED in the first three 5-min
		// windows). It is now only rate-limited (retry-after); the aggregate bucket still bounds the /24's calls.
		if !own_short {
			// r24 verify: the refused call still costs the key its own tokens, so a key that retries against a drained
			// aggregate faster than its own rate becomes own_short and is scored and banned as before (without this a
			// key with a full bucket retried forever unscored: 18,401 of 20,000 calls in 1 s, 0 banned; base 04ceb55
			// banned it, TestR24VerifyAggShortRetryFloodEndsBanned). An honest key under its own rate never notices.
			e.tokens -= cost
			abuse_agg_short.Inc()
			return abuse_rate_limited, time.Duration(short / short_rate * float64(time.Second))
		}
		if d := t.score_locked(e, g, ABUSE_PTS_REFUSED, ABUSE_PTS_REFUSED, now); d > 0 {
			abuse_refused_banned.Inc()
			return abuse_banned, d
		}
		return abuse_rate_limited, time.Duration(short / short_rate * float64(time.Second))
	}
	e.tokens -= cost
	if g != nil {
		g.tokens -= cost
	}
	if !unknown && e.served < math.MaxUint32 { // r24: only calls to served names earn trust (probes never do)
		e.served++
	}
	return abuse_ok, 0
}

func refill(e *abuse_entry, rate, burst float64, now time.Time) {
	e.tokens += now.Sub(e.tok_at).Seconds() * rate
	if e.tokens > burst {
		e.tokens = burst
	}
	e.tok_at = now
}

// observe scores the outcome of a served call (its JSON-RPC error code, 0 = success). Codes already charged at
// admission (unknown method, our own refusals) are not counted twice.
func (t *abuse_table) observe(key string, c code.Code, now time.Time) time.Duration {
	var pts, agg_pts float64
	anomaly := false
	switch c {
	case 0, code.MethodNotFound, RPC_CODE_RATE_LIMITED, RPC_CODE_BANNED:
		return 0
	case code.InvalidParams, code.InvalidRequest, code.ParseError:
		abuse_bad_request.Inc()
		pts, anomaly = ABUSE_PTS_BAD_REQUEST, true
		agg_pts = pts
	default:
		pts = ABUSE_PTS_OTHER_ERROR // honest clients see these: never scored into the aggregate (r23c)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.enabled {
		return 0
	}
	e := t.entry(key, now)
	e.last_seen = now
	if now.Before(e.banned_until) { // r23c (SEC23b-2): a banned key no longer draws on the global budget
		return 0
	}
	trusted := trusted_locked(e, now)
	var g *abuse_entry
	if !trusted {
		if g = t.agg_locked(e, now); g != nil && now.Before(g.banned_until) {
			return 0 // refused at its next admission anyway
		}
	}
	if anomaly {
		if f := t.anomaly_factor(now); f != 1 {
			if trusted {
				abuse_surge_trusted.Inc()
			} else {
				pts *= f
			}
		}
	}
	return t.score_locked(e, g, pts, agg_pts, now)
}

// banned_for reports how long key stays banned (0 = not banned).
func (t *abuse_table) banned_for(key string, now time.Time) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.enabled {
		return 0
	}
	e := t.m[key]
	if e != nil && now.Before(e.banned_until) {
		return e.banned_until.Sub(now)
	}
	if e != nil && trusted_locked(e, now) {
		return 0
	}
	ak := abuse_agg_key(key) // r23c: an untrusted (or new) key of a banned aggregate cannot open a socket either
	if e != nil {
		ak = e.agg
	}
	if g := t.m[ak]; ak != "" && g != nil && now.Before(g.banned_until) {
		return g.banned_until.Sub(now)
	}
	return 0
}

// abuse_exempt: loopback is never scored; neither is the shared key of cross-site loopback pages (r21 limiter).
func abuse_exempt(key string, loopback bool) bool { return loopback || key == FOREIGN_LIMIT_KEY }

// ---- method table ----------------------------------------------------------------------------------------------

// method_known reuses the registered-name table of the per-method metrics (node_metrics.go rpc_method_label).
func method_known(method string) bool { return method != "" && rpc_method_label(method) == method }

// ---- jrpc2 built-in methods (r23b) ------------------------------------------------------------------------------

// jrpc2 serves the reserved "rpc." names itself, before any assigner sees them, unless DisableBuiltin is set. Its
// rpc.serverInfo returned to ANY caller, remote included: the full method list, the node's start time (restart
// detection) and the server's request and byte counters, which on the shared /json_rpc bridge count loopback calls
// too, so a remote poller could watch the local wallet's and miner's RPC activity (measured: a remote request read
// rpc.requests 4 after 3 loopback pings). On a remote websocket the call also bypassed remote_assigner, so it was
// neither charged nor scored. Remote callers now get the method-not-found answer of any unknown name (and its score);
// loopback keeps the built-ins.
var remote_options = remote_server_options(options)

func remote_server_options(o *jrpc2.ServerOptions) *jrpc2.ServerOptions {
	c := *o
	c.DisableBuiltin = true
	return &c
}

// ws_server_options: a remote socket, and a cross-site page's socket over loopback (a web page must not watch the
// local wallet's RPC activity either), get no built-ins; the user's own loopback tools keep them.
func ws_server_options(c *ws_client) *jrpc2.ServerOptions {
	if c.abuse_key != "" || c.foreign {
		return remote_options
	}
	return options
}

func reserved_method(method string) bool { return strings.HasPrefix(method, "rpc.") }

func any_reserved(methods []string) bool {
	for _, m := range methods {
		if reserved_method(m) {
			return true
		}
	}
	return false
}

// write_method_not_found answers a remote /json_rpc body that names a reserved method, without dispatching any of it.
func write_method_not_found(w http.ResponseWriter) {
	e := &jrpc2.Error{Code: code.MethodNotFound, Message: "method not found"}
	count_error_code(e) // r28 verify: a reserved rpc.* name is answered outside jrpc2 too (rpc_error_responses_total{code="-32601"})
	body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": nil, "error": e})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// ---- machine-readable refusals -----------------------------------------------------------------------------------

type retry_data struct {
	RetryAfterMS int64 `json:"retry_after_ms"`
}

func retry_ms(d time.Duration) int64 {
	ms := int64(d / time.Millisecond)
	if ms < 1 {
		ms = 1
	}
	return ms
}

func abuse_error(v abuse_verdict, d time.Duration) *jrpc2.Error {
	e := &jrpc2.Error{Code: RPC_CODE_RATE_LIMITED, Message: "rate limited"}
	if v == abuse_banned {
		e = &jrpc2.Error{Code: RPC_CODE_BANNED, Message: "temporarily banned"}
	}
	return e.WithData(retry_data{retry_ms(d)})
}

// write_abuse_http answers a refused /json_rpc request: HTTP 429, Retry-After, and a JSON-RPC error body.
func write_abuse_http(w http.ResponseWriter, v abuse_verdict, d time.Duration) {
	secs := int64(math.Ceil(d.Seconds()))
	if secs < 1 {
		secs = 1
	}
	e := abuse_error(v, d)
	count_error_code(e) // r28: written outside jrpc2, so LogResponse never counted it in rpc_error_responses_total
	body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": nil, "error": e})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", strconv.FormatInt(secs, 10))
	w.WriteHeader(http.StatusTooManyRequests)
	w.Write(body)
}

// ---- websocket path ------------------------------------------------------------------------------------------------

// remote_assigner is the method table of one remote socket: every call is charged before its handler runs. jrpc2
// calls Assign once per request (each element of a batch too).
type remote_assigner struct {
	c    *ws_client
	next jrpc2.Assigner
}

func (r remote_assigner) Assign(ctx context.Context, method string) jrpc2.Handler {
	h := r.next.Assign(ctx, method)
	v, d := rpc_abuse.admit(r.c.abuse_key, method, h == nil, time.Now())
	if v == abuse_ok {
		return h
	}
	if v == abuse_banned {
		r.c.close_banned()
	}
	err := abuse_error(v, d)
	// a raw Func: handler.New would answer a refused call that has params with -32602 instead of err
	return handler.Func(func(context.Context, *jrpc2.Request) (interface{}, error) { return nil, err })
}

func (r remote_assigner) Names() []string { return d.Names() }

// close_banned closes a banned socket shortly after its refusal is written (once).
func (c *ws_client) close_banned() {
	c.ban_once.Do(func() {
		time.AfterFunc(100*time.Millisecond, func() {
			if c.conn != nil {
				c.conn.Close()
			}
		})
	})
}

// remote_ws_sockets counts open scored (remote) websockets.
var remote_ws_sockets int32

// observe_ws scores one websocket response (LogResponse). Free for loopback sockets (abuse_key empty).
func observe_ws(ctx context.Context, resp *jrpc2.Response) {
	if atomic.LoadInt32(&remote_ws_sockets) == 0 { // a loopback-only node never looks a client up here
		return
	}
	c := ws_client_of(ctx)
	if c == nil || c.abuse_key == "" {
		return
	}
	var ec code.Code
	if e := resp.Error(); e != nil {
		ec = e.Code
	}
	if rpc_abuse.observe(c.abuse_key, ec, time.Now()) > 0 {
		c.close_banned()
	}
}

// ---- HTTP path ----------------------------------------------------------------------------------------------------

type method_only struct {
	Method string `json:"method"`
}

// request_methods returns the method of each request in a /json_rpc body (single object or batch). r24 verify: a
// batch is split per element (decode_requests); an element that is not an object, or whose method is not a string,
// has method "" (jrpc2 answers that element with an error and runs the others, so it is charged as unknown). Before,
// one such element (`[0,{...},...]`) failed the whole decode and serve_remote_json_rpc passed the body to the bridge as
// "malformed JSON" with no call cost, no reserved-method refusal (rpc.serverInfo answered remotely again) and no item
// cost (evidence/verify_malformed_batch_admission.txt, base 04ceb55 too).
func request_methods(body []byte) ([]string, error) {
	var out []string
	err := decode_requests(body, func(n int) { out = make([]string, n) }, func(i int, el []byte) error {
		var m method_only
		if err := json.Unmarshal(el, &m); err != nil {
			return err
		}
		out[i] = m.Method
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// decode_requests (r24 verify) splits a /json_rpc body the way jrpc2 does (vendor/github.com/creachadair/jrpc2/
// json.go parseJSON: a body starting with '[' is a batch of raw elements, each parsed alone) and runs one(i, element)
// for each. A single request costs one decode as before; a batch costs one extra scan (measured in
// evidence/verify_ab_precheck.txt). A body that is not JSON, or a single request that one refuses, is an error (the bridge runs
// nothing of it); in a batch an element one refuses is left at its zero value.
func decode_requests(body []byte, size func(int), one func(int, []byte) error) error {
	b := bytes.TrimLeft(body, " \t\r\n")
	if len(b) == 0 || b[0] != '[' {
		size(1)
		return one(0, b)
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(b, &elems); err != nil {
		return err
	}
	size(len(elems))
	for i, el := range elems {
		one(i, el) // a refused element keeps its zero value (method "", no items)
	}
	return nil
}

// admit_http charges every request of a remote body; the worst verdict wins (a batch is refused whole). items[i] is
// the number of txids / SC keys request i names (r24: nil or short = none), charged at item_cost each.
func admit_http(key string, methods []string, items []int, now time.Time) (abuse_verdict, time.Duration) {
	for i, m := range methods {
		n := 0
		if i < len(items) {
			n = items[i]
		}
		if v, d := rpc_abuse.admit_items(key, m, !method_known(m), item_cost(n), now); v != abuse_ok {
			return v, d
		}
	}
	return abuse_ok, 0
}

// ABUSE_TEE_MAX: responses longer than this are not inspected for errors (error replies are small).
const ABUSE_TEE_MAX = 64 << 10

type tee_writer struct {
	http.ResponseWriter
	buf  bytes.Buffer
	over bool
}

func (t *tee_writer) Write(p []byte) (int, error) {
	if !t.over {
		if t.buf.Len()+len(p) > ABUSE_TEE_MAX {
			t.over = true
			t.buf = bytes.Buffer{}
		} else {
			t.buf.Write(p)
		}
	}
	return t.ResponseWriter.Write(p)
}

type error_only struct {
	Error *struct {
		Code code.Code `json:"code"`
	} `json:"error"`
}

// response_error_codes returns the JSON-RPC error codes in a response body (none for successes).
func response_error_codes(body []byte) (codes []code.Code) {
	if !bytes.Contains(body, []byte(`"error"`)) {
		return nil
	}
	b := bytes.TrimLeft(body, " \t\r\n")
	var list []error_only
	if len(b) > 0 && b[0] == '[' {
		if json.Unmarshal(b, &list) != nil {
			return nil
		}
	} else {
		var one error_only
		if json.Unmarshal(b, &one) != nil {
			return nil
		}
		list = append(list, one)
	}
	for _, r := range list {
		if r.Error != nil {
			codes = append(codes, r.Error.Code)
		}
	}
	return codes
}

// serve_remote_json_rpc runs a remote /json_rpc body through the guard and the bridge, then scores the reply.
func serve_remote_json_rpc(w http.ResponseWriter, req *http.Request, key string, body []byte, items []int) {
	now := time.Now()
	methods, err := request_methods(body)
	if err != nil { // malformed JSON: the bridge answers it as before; it scores as a bad request
		if d := rpc_abuse.observe(key, code.ParseError, now); d > 0 {
			write_abuse_http(w, abuse_banned, d)
			return
		}
		translate_http_to_jsonrpc_and_vice_versa(w, req)
		return
	}
	if v, d := admit_http(key, methods, items, now); v != abuse_ok { // r24: item-weighted (B29)
		write_abuse_http(w, v, d)
		return
	}
	if any_reserved(methods) { // charged and scored as unknown by admit_http; never reaches the bridge's built-ins
		write_method_not_found(w)
		return
	}
	tw := &tee_writer{ResponseWriter: w}
	translate_http_to_jsonrpc_and_vice_versa(tw, req)
	if tw.over {
		return
	}
	for _, c := range response_error_codes(tw.buf.Bytes()) {
		rpc_abuse.observe(key, c, now)
	}
}

func (v abuse_verdict) String() string {
	switch v {
	case abuse_ok:
		return "ok"
	case abuse_rate_limited:
		return "rate_limited"
	case abuse_banned:
		return "banned"
	}
	return fmt.Sprintf("verdict(%d)", int(v))
}
