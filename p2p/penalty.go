// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
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
package p2p

// Misbehaviour score per peer IP, decaying, with escalating temporary bans.
//
// Upstream logs "should be banned" at a dozen sites (invalid PoW, undecodable blocks and txs, malformed requests)
// and at most disconnects; the only automatic Ban_Address is the local v2-chain guard, so a misbehaving peer could
// reconnect at once (discovery p2p-security-03). This is local policy only: nothing here changes which blocks,
// miniblocks or transactions are valid — those checks are untouched and still reject what they rejected.
//
// Seed, priority and exclusive nodes are never banned by score. NB: upstream IsAddressInBanList compares a bare IP
// with nonbanlist entries that are "ip:port" and returns TRUE (banned) on a match; the match never happens, so the
// inversion is dormant. It is deliberately left alone — "fixing" the comparison would make the node refuse its own
// seed and priority nodes. never_ban below compares hosts and is used only by the score.

import "fmt"
import "math"
import "net"
import "sort"
import "sync"
import "sync/atomic"
import "time"

import "github.com/deroproject/derohe/metrics"

const PENALTY_BAN_SCORE = 100.0            // a score reaching this bans the IP
const PENALTY_HALF_LIFE = 10 * time.Minute // scores halve every 10 minutes: occasional faults never add up to a ban
const PENALTY_BAN_BASE = 600               // first ban 10 minutes; each further ban doubles
const PENALTY_BAN_MAX = 86400              // up to 24 hours

// points per kind of fault; the reasons are a fixed set so the metric stays bounded
var PENALTY_POINTS = map[string]float64{
	"invalid_pow":           50, // a block whose proof of work fails: two in a short time ban
	"invalid_pow_miniblock": 25, // a miniblock judged against our view of its tips: weaker evidence while we catch up
	"undecodable":           50, // a block or tx that does not deserialize
	"malformed_request":     20, // a request outside the protocol's bounds
	"timeout":               10, // a call the peer never answered
	"busy":                  2,  // a heavy request beyond the concurrency cap
	"invalid_tx":            25, // a transaction whose proof fails against its own reference block (deterministic)
}

type misbehaviour struct {
	score        float64
	at           time.Time
	offences     int
	banned_until time.Time // r23c: end of the latest score ban (prune keeps a record while its ban runs)
	// r25 (peers, CO24-N1): offences scored on this record (saturating), and the newest PENALTY_LAST_REASONS of them
	// in a ring whose next slot is head (the newest is last[(head+PENALTY_LAST_REASONS-1)%PENALTY_LAST_REASONS])
	events uint32
	head   uint8
	kept   uint8
	last   [PENALTY_LAST_REASONS]OffenceMark
}

// r25 (peers, CO24-N1 / §7 B63): the latest offences of a scope, for DERO.GetPeerInfo. Before r25 an offence below
// the ban score left no trace outside the decaying number: GetPeerInfo had no score field and only the ban itself was
// logged ("peer banned for misbehaviour"), so which rule a peer was breaking was invisible until it was banned. A
// fixed ring of PENALTY_LAST_REASONS marks per record (24 B each): at the PENALTY_MAX_ENTRIES bound that is at most
// 65,536 x 96 B = 6.3 MB (ESTIMATE, upper bound; live r24 /metrics: 0 offences since the 2026-11-03 restart).
const PENALTY_LAST_REASONS = 4

type OffenceMark struct {
	Reason string `json:"reason"`
	At     int64  `json:"at"` // unix seconds
}

// note records one offence: one slot of the ring is written, nothing is shifted.
func (m *misbehaviour) note(reason string, now time.Time) {
	m.last[m.head] = OffenceMark{Reason: reason, At: now.Unix()}
	m.head = (m.head + 1) % PENALTY_LAST_REASONS
	if m.kept < PENALTY_LAST_REASONS {
		m.kept++
	}
	if m.events < math.MaxUint32 {
		m.events++
	}
}

// recent returns the ring newest first (at most PENALTY_LAST_REASONS marks).
func (m *misbehaviour) recent() []OffenceMark {
	out := make([]OffenceMark, 0, m.kept)
	for i := 1; i <= int(m.kept); i++ {
		out = append(out, m.last[(int(m.head)+PENALTY_LAST_REASONS-i)%PENALTY_LAST_REASONS])
	}
	return out
}

// PENALTY_LOG_FIRST: the first offences of a record are each logged; after that one line per PENALTY_LOG_EVERY, so a
// peer that keeps tripping a cheap rule ("busy", 2 points) cannot turn the file log into its own channel (r25).
const PENALTY_LOG_FIRST = 8
const PENALTY_LOG_EVERY = 64

func penalty_should_log(events uint32) bool {
	return events <= PENALTY_LOG_FIRST || events%PENALTY_LOG_EVERY == 0
}

// r23c (p2psec): the penalty table is pruned at most once per PENALTY_PRUNE_INTERVAL, and records of banned peers
// are forgotten PENALTY_OFFENCE_FORGET after their last fault.
//
// Before r23c a record with offences > 0 was never deleted, and once the map held more than 4096 records EVERY
// add_penalty scanned all of them (math.Pow per record) under penalty_mu. Bans are earned by misbehaving, so a peer
// fleet that gets itself banned (IPv6: one /64 per ban, 65,536 per /48) grew the map without bound and made every
// later fault from anyone (a "busy" heavy request is 2 points) pay the full scan: measured in
// BenchmarkR23cAddPenaltyFullTable. A week is 7x the 24 h ban cap, so an escalating peer still escalates.
const PENALTY_PRUNE_INTERVAL = time.Second
const PENALTY_OFFENCE_FORGET = 7 * 24 * time.Hour
const PENALTY_PRUNE_AT = 4096       // the table is pruned when it holds more than this (as before)
const PENALTY_MAX_ENTRIES = 1 << 16 // hard bound (r24: really hard, see penalty_evict_locked)

// r24 (security, B28): the bound is HARD. Past PENALTY_MAX_ENTRIES r23c dropped only records whose ban had ended, so
// with every record under a running ban the table kept growing: 85,536 records after 85,536 distinct banned /64s
// (TestZZR24ScenarioPenaltyAllBanned, base 04ceb55; the r23c verifier saw 68,537). A new record now never takes the
// table past PENALTY_MAX_ENTRIES: penalty_evict_locked first drops what carries no running ban (ended bans: their
// escalation; score-only records: a partial score), then the running bans that end soonest, down to
// PENALTY_EVICT_TO, so the O(n log n) eviction runs at most once per PENALTY_MAX_ENTRIES/16 new records. Evicting a
// banned record never unbans anyone: the ban itself lives in the ban list (Ban_Address); only its escalation memory
// is lost (the next ban of that scope starts again at PENALTY_BAN_BASE).
const PENALTY_EVICT_TO = PENALTY_MAX_ENTRIES - PENALTY_MAX_ENTRIES/16

var penalty_evictions uint64 // records dropped by penalty_evict_locked (tests, metrics)

var _ = metrics.Set.GetOrCreateGauge("p2p_penalty_evictions_total", func() float64 { return float64(atomic.LoadUint64(&penalty_evictions)) })

func penalty_evict_locked(now time.Time) {
	type cand struct {
		k    string
		rank int64 // 0 = no running ban (dropped first), else the ban's end
	}
	c := make([]cand, 0, len(penalty_map))
	for k, v := range penalty_map {
		r := int64(0)
		if now.Before(v.banned_until) {
			r = v.banned_until.UnixNano()
		}
		c = append(c, cand{k, r})
	}
	sort.Slice(c, func(i, j int) bool { return c[i].rank < c[j].rank })
	n := len(c) - PENALTY_EVICT_TO
	for i := 0; i < n; i++ {
		delete(penalty_map, c[i].k)
	}
	if n > 0 {
		atomic.AddUint64(&penalty_evictions, uint64(n))
	}
}

var penalty_last_prune time.Time
var penalty_scanned uint64 // records examined by prune scans (tests)

func penalty_prune_locked(now time.Time) {
	if len(penalty_map) <= PENALTY_PRUNE_AT || now.Sub(penalty_last_prune) < PENALTY_PRUNE_INTERVAL {
		return
	}
	penalty_last_prune = now
	for k, v := range penalty_map {
		penalty_scanned++
		decayed := v.score * math.Pow(0.5, now.Sub(v.at).Seconds()/PENALTY_HALF_LIFE.Seconds())
		if (v.offences == 0 && decayed < 1) || (v.offences > 0 && now.Sub(v.at) > PENALTY_OFFENCE_FORGET) {
			delete(penalty_map, k)
		}
	}
	// r24: the r23c second pass (past PENALTY_MAX_ENTRIES, drop ended bans) is gone: add_penalty never lets the table
	// pass the bound any more (penalty_evict_locked, which drops ended bans first).
}

var penalty_mu sync.Mutex
var penalty_map = map[string]*misbehaviour{}

var never_ban_resolved sync.Map // hostname -> []string of its IPs, resolved once (priority nodes may be names)

// never_ban reports whether ip is a seed, priority or exclusive node (nonbanlist holds "host:port" strings as typed).
func never_ban(ip string) bool {
	for _, e := range nonbanlist {
		host, _, err := net.SplitHostPort(e)
		if err != nil {
			host = e
		}
		if host == ip {
			return true
		}
		if net.ParseIP(host) == nil { // a name: compare with what it resolves to
			v, ok := never_ban_resolved.Load(host)
			if !ok {
				addrs, _ := net.LookupHost(host)
				never_ban_resolved.Store(host, addrs)
				v = addrs
			}
			for _, a := range v.([]string) {
				if a == ip {
					return true
				}
			}
		}
	}
	return false
}

// add_penalty records a fault against ip and returns the ban length in seconds (0 when the peer is not banned).
func add_penalty(ip string, reason string, now time.Time) (ban_seconds uint64) {
	ban_seconds, _, _ = add_penalty_scored(ip, reason, now)
	return
}

// add_penalty_scored is add_penalty that also returns the score after this fault (0 after a ban resets it) and the
// offences scored on the record so far. r25.
func add_penalty_scored(ip string, reason string, now time.Time) (ban_seconds uint64, score float64, events uint32) {
	points, ok := PENALTY_POINTS[reason]
	if !ok {
		panic(fmt.Sprintf("unknown penalty reason %q", reason)) // a typo must fail the tests, not score 0
	}
	metrics.Set.GetOrCreateCounter(fmt.Sprintf(`p2p_penalty_events_total{reason="%s"}`, reason)).Inc()
	penalty_mu.Lock()
	defer penalty_mu.Unlock()
	penalty_prune_locked(now) // r23c: at most one scan per second (was: one per call once past 4096 records)
	m := penalty_map[ip]
	if m == nil {
		if len(penalty_map) >= PENALTY_MAX_ENTRIES { // r24: hard bound (see PENALTY_EVICT_TO)
			penalty_evict_locked(now)
		}
		m = &misbehaviour{at: now}
		penalty_map[ip] = m
	}
	m.score = m.score*math.Pow(0.5, now.Sub(m.at).Seconds()/PENALTY_HALF_LIFE.Seconds()) + points
	m.at = now
	m.note(reason, now) // r25 (CO24-N1)
	if m.score < PENALTY_BAN_SCORE || never_ban(ip) {
		return 0, m.score, m.events
	}
	m.offences++
	m.score = 0
	ban_seconds = uint64(PENALTY_BAN_BASE) << uint(m.offences-1)
	if ban_seconds > PENALTY_BAN_MAX || m.offences > 8 {
		ban_seconds = PENALTY_BAN_MAX
	}
	m.banned_until = now.Add(time.Duration(ban_seconds) * time.Second)
	return ban_seconds, 0, m.events
}

const V2_BAN_BASE = 3600             // first drop of a v2-remnant peer: an hour, in case it upgrades
const V2_FORGET = 7 * 24 * 3600      // a peer not dropped for a week starts again at an hour (it may have upgraded)
const V2_OFFENCES_MAX_ENTRIES = 4096 // bound on the map (and on v2_offences.json)

// v2_record is one peer's v2-drop history. It is persisted (v2_offences.go) because the ban list cannot carry it:
// ban_clean_up deletes a ban the moment it expires, and a banned peer can only re-offend after that, so at every
// re-offence the ban list holds nothing about it. Before this, every derod restart reset the escalation
// [r25 B70: RFC 5737 stand-ins for the observed addresses]
// (203.0.113.168: 3600 s at 05:12, 7200 s at 06:12 under r15, then 3600 s again at 08:12 after the r16 restart).
type v2_record struct {
	N    int   `json:"n"`    // drops so far
	Last int64 `json:"last"` // unix seconds of the latest drop
}

var v2_offences = map[string]v2_record{}

// v2_ban_seconds is the ban for the n-th time ip is dropped for following the pre-HF3 (v2) chain: 1 h, doubling, to
// 24 h. A flat hour re-dialled and re-banned the same peer 23 times in one log (2026-10-22); a peer that upgrades
// still gets back in within a day.
func v2_ban_seconds(ip string) uint64 {
	return v2_ban_seconds_at(ip, time.Now().Unix())
}

func v2_ban_seconds_at(ip string, now int64) uint64 {
	penalty_mu.Lock()
	defer penalty_mu.Unlock()
	v2_forget_locked(now)
	r := v2_offences[ip]
	if r.N > 0 && now-r.Last > V2_FORGET {
		r = v2_record{}
	}
	r.N++
	r.Last = now
	v2_offences[ip] = r
	return v2_ban_for(r.N)
}

// v2_forget_locked drops week-old entries and, if the map is still over its bound, empties it (the old behaviour).
func v2_forget_locked(now int64) {
	if len(v2_offences) <= V2_OFFENCES_MAX_ENTRIES {
		return
	}
	for k, r := range v2_offences {
		if now-r.Last > V2_FORGET {
			delete(v2_offences, k)
		}
	}
	if len(v2_offences) > V2_OFFENCES_MAX_ENTRIES {
		v2_offences = map[string]v2_record{}
	}
}

func v2_ban_for(n int) uint64 {
	if n > 6 {
		return PENALTY_BAN_MAX
	}
	if s := uint64(V2_BAN_BASE) << uint(n-1); s < PENALTY_BAN_MAX {
		return s
	}
	return PENALTY_BAN_MAX
}

// penalty_scope is the unit a misbehaviour score and its ban apply to: the IP itself for IPv4, the /64 for IPv6.
//
// Why (r19): an IPv6 subscriber is routinely given a whole /64 (2^64 addresses), so a score and a ban keyed by the
// /128 were evaded by moving to the next address: every new source started at score 0 and outside the ban. The /64
// is the smallest prefix one end site controls (RFC 6177 assigns /48../64 per site). Ban_Address stores the CIDR
// and IsAddressInBanList already matches every address inside a banned subnet. If a seed, priority or exclusive node
// lies inside that /64, the /128 is kept so the score can never ban it (never_ban compares single hosts).
func penalty_scope(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return ip
	}
	subnet := &net.IPNet{IP: parsed.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}
	for _, e := range nonbanlist {
		host, _, err := net.SplitHostPort(e)
		if err != nil {
			host = e
		}
		if h := net.ParseIP(host); h != nil && subnet.Contains(h) {
			return ip
		}
	}
	return subnet.String()
}

// penalize scores a fault by this connection's peer and bans it (and drops the connection) when the score is reached.
func (c *Connection) penalize(reason string) {
	ip := penalty_scope(Address(c))
	if ip == "" {
		return
	}
	secs, score, events := add_penalty_scored(ip, reason, time.Now())
	// r25 (CO24-N1): an offence below the ban score leaves a line with its reason (file log only; bounded per record)
	if secs == 0 && penalty_should_log(events) {
		c.logger.V(1).Info("peer offence", "reason", reason, "score", math.Round(score*10)/10, "ban_score", PENALTY_BAN_SCORE, "offences", events)
	}
	if secs > 0 {
		c.logger.Info("peer banned for misbehaviour", "ip", ip, "last_reason", reason, "seconds", secs)
		Ban_Address_Reason(ip, secs, BAN_SOURCE_SCORE, reason) // r25 (CO24-N4): the ban list knows why
		metrics.Set.GetOrCreateCounter("p2p_penalty_bans_total").Inc()
		// r25 (CO24-N2): which rule the banned peer broke last, per reason
		metrics.Set.GetOrCreateCounter(fmt.Sprintf(`p2p_penalty_bans_by_reason_total{reason="%s"}`, reason)).Inc()
		if d := note_score_ban(ip, time.Now()); d > 0 { // r23c: rotating identities inside one /24 or /48
			c.logger.Info("inbound sessions from this address block refused", "aggregate", penalty_aggregate(ip), "seconds", int64(d/time.Second))
		}
		c.exit()
	}
}

// ---- r23c (p2psec): aggregate inbound bans for rotating identities ------------------------------------------------
//
// A score ban covers one IPv4 address or one IPv6 /64 (penalty_scope). An operator holding a /24 (256 addresses) or a
// /48 (65,536 /64s) gets a fresh score for every address it moves to, so misbehaviour was bounded per address, never
// per operator. When PENALTY_AGG_MEMBERS distinct scopes of one aggregate (IPv4 /24, IPv6 /48) are score-banned
// within PENALTY_AGG_WINDOW, new INBOUND sessions from the whole aggregate are refused for PENALTY_AGG_BAN_BASE,
// doubling per repeat up to PENALTY_BAN_MAX.
// It is inbound-only on purpose: the aggregate may also hold honest nodes, and an attacker must not be able to make
// us drop or stop dialling OUR chosen outbound peers (that would help an eclipse); connections already established
// are kept, and the ban list (ban_list.json, outbound dialling) is untouched. Seed/priority/exclusive nodes inside an
// aggregate exempt it. Nothing here changes which blocks or transactions are valid.
const PENALTY_AGG_MEMBERS = 4
const PENALTY_AGG_WINDOW = time.Hour
const PENALTY_AGG_BAN_BASE = 600 * time.Second
const PENALTY_AGG_MAX_ENTRIES = 4096
const PENALTY_AGG_MAX_MEMBERS = 16

type agg_record struct {
	members  map[string]time.Time // scope -> time of its latest score ban
	offences int
	until    time.Time
	last     time.Time
}

var agg_mu sync.Mutex
var agg_map = map[string]*agg_record{}
var agg_active int32 // aggregates currently banned (admission fast path: 0 = nothing to look up)

var agg_bans_total = metrics.Set.GetOrCreateCounter("p2p_penalty_aggregate_bans_total")
var agg_refusals_total = metrics.Set.GetOrCreateCounter("p2p_inbound_aggregate_refusals_total")

// penalty_aggregate is the aggregate of an IP or a penalty scope: the /24 of an IPv4 address, the /48 of an IPv6
// address or /64; "" for anything else, for non-public addresses, and when a never-ban node lies inside it.
func penalty_aggregate(scope string) string {
	var ip net.IP
	if _, n, err := net.ParseCIDR(scope); err == nil {
		ip = n.IP
	} else if ip = net.ParseIP(scope); ip == nil {
		return ""
	}
	if !is_public(ip) {
		return ""
	}
	bits, total := 48, 128
	if x := ip.To4(); x != nil {
		ip, bits, total = x, 24, 32
	}
	agg := &net.IPNet{IP: ip.Mask(net.CIDRMask(bits, total)), Mask: net.CIDRMask(bits, total)}
	for _, e := range nonbanlist {
		host, _, err := net.SplitHostPort(e)
		if err != nil {
			host = e
		}
		if h := net.ParseIP(host); h != nil && agg.Contains(h) {
			return ""
		}
	}
	return agg.String()
}

// note_score_ban records that scope was score-banned and returns the aggregate ban it triggers (0 = none).
func note_score_ban(scope string, now time.Time) time.Duration {
	g := penalty_aggregate(scope)
	if g == "" {
		return 0
	}
	agg_mu.Lock()
	defer agg_mu.Unlock()
	r := agg_map[g]
	if r == nil {
		if len(agg_map) >= PENALTY_AGG_MAX_ENTRIES {
			agg_prune_locked(now)
			if len(agg_map) >= PENALTY_AGG_MAX_ENTRIES {
				return 0 // bounded memory; per-scope bans still apply
			}
		}
		r = &agg_record{members: map[string]time.Time{}}
		agg_map[g] = r
	}
	r.last = now
	if now.Before(r.until) {
		return 0 // already banned
	}
	for k, at := range r.members {
		if now.Sub(at) > PENALTY_AGG_WINDOW {
			delete(r.members, k)
		}
	}
	if len(r.members) < PENALTY_AGG_MAX_MEMBERS {
		r.members[scope] = now
	}
	if len(r.members) < PENALTY_AGG_MEMBERS {
		return 0
	}
	if r.offences > 0 && now.Sub(r.until) > PENALTY_OFFENCE_FORGET {
		r.offences = 0
	}
	r.offences++
	d := PENALTY_AGG_BAN_BASE
	for i := 1; i < r.offences && d < PENALTY_BAN_MAX*time.Second; i++ {
		d *= 2
	}
	if d > PENALTY_BAN_MAX*time.Second {
		d = PENALTY_BAN_MAX * time.Second
	}
	r.until = now.Add(d)
	r.members = map[string]time.Time{}
	agg_active_recount_locked(now)
	agg_bans_total.Inc()
	return d
}

func agg_prune_locked(now time.Time) {
	for k, r := range agg_map {
		if !now.Before(r.until) && now.Sub(r.last) > PENALTY_AGG_WINDOW && (r.offences == 0 || now.Sub(r.until) > PENALTY_OFFENCE_FORGET) {
			delete(agg_map, k)
		}
	}
}

func agg_active_recount_locked(now time.Time) {
	n := int32(0)
	soonest := int64(0)
	for _, r := range agg_map {
		if now.Before(r.until) {
			n++
			if u := r.until.UnixNano(); soonest == 0 || u < soonest {
				soonest = u
			}
		}
	}
	atomic.StoreInt64(&agg_soonest, soonest)
	atomic.StoreInt32(&agg_active, n)
}

// agg_soonest (r23c verify): unix nanos at which the earliest running aggregate ban ends (0 = none). Without it
// agg_active stayed non-zero after a ban ended until someone from THAT aggregate connected again, so every inbound
// session paid the slow path (penalty_aggregate parse + agg_mu) indefinitely: measured 1.89x admit_inbound CPU.
var agg_soonest int64

// inbound_aggregate_banned reports whether new inbound sessions from ip are refused by an aggregate ban. With no
// aggregate banned (the normal case) it is one atomic load.
func inbound_aggregate_banned(ip string, now time.Time) bool {
	if atomic.LoadInt32(&agg_active) == 0 {
		return false
	}
	if s := atomic.LoadInt64(&agg_soonest); s != 0 && now.UnixNano() >= s { // r23c verify: a ban ended, recount
		agg_mu.Lock()
		agg_active_recount_locked(now)
		agg_mu.Unlock()
		if atomic.LoadInt32(&agg_active) == 0 {
			return false
		}
	}
	g := penalty_aggregate(ip)
	if g == "" {
		return false
	}
	agg_mu.Lock()
	defer agg_mu.Unlock()
	r := agg_map[g]
	if r == nil {
		return false
	}
	return now.Before(r.until) // an ended ban was already recounted above (agg_soonest)
}
