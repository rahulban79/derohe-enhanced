// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package p2p

// r23c (p2psec): adversarial tests for the ban-list index, the bounded penalty table and aggregate inbound bans.

import (
	"fmt"
	"math/rand"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/deroproject/derohe/globals"
)

// ban_scan_reference is the pre-r23c IsAddressInBanList, verbatim in effect (the oracle for the index). The tests
// run single-threaded on ban_map, so it reads the map without the lock.
func ban_scan_reference(address string) bool {
	for i := range nonbanlist {
		if address == nonbanlist[i] {
			return false
		}
	}
	if _, ok := ban_map[address]; ok {
		return true
	}
	ip := net.ParseIP(address)
	if ip != nil {
		for k := range ban_map {
			ipnet, _, err := ParseAddress(k)
			if ip.String() == k || (err == nil && ipnet != nil && ipnet.Contains(ip)) {
				return true
			}
		}
	}
	return false
}

func with_ban_map(t testing.TB, m map[string]uint64) {
	ban_mutex.Lock()
	saved := ban_map
	ban_map = m
	ban_gen++
	ban_mutex.Unlock()
	t.Cleanup(func() {
		ban_mutex.Lock()
		ban_map = saved
		ban_gen++
		ban_mutex.Unlock()
	})
}

func rand_ip(r *rand.Rand, v6 bool) net.IP {
	if v6 {
		b := make([]byte, 16)
		r.Read(b)
		b[0], b[1], b[2], b[3] = 0x20, 0x01, 0x0d, byte(0xb8+r.Intn(2)) // two /32s so hits are frequent
		return b
	}
	return net.IPv4(198, byte(18+r.Intn(2)), byte(r.Intn(4)), byte(r.Intn(256)))
}

// The index must answer exactly what the scan answered, on random ban sets including the odd keys a console user or
// an old ban_list.json can hold (v4-mapped CIDRs, /0, wide and narrow masks, non-canonical and unparsable keys).
func TestR23cBanIndexMatchesScan(t *testing.T) {
	saved := nonbanlist
	defer func() { nonbanlist = saved }()
	nonbanlist = []string{"198.18.0.5", "89.38.99.117:10101"}
	r := rand.New(rand.NewSource(23))
	exp := uint64(time.Now().Unix()) + 3600
	for round := 0; round < 40; round++ {
		m := map[string]uint64{}
		for i := 0; i < r.Intn(300); i++ {
			v6 := r.Intn(2) == 0
			ip := rand_ip(r, v6)
			switch r.Intn(6) {
			case 0, 1:
				m[ip.String()] = exp // a bare address (score bans of IPv4)
			case 2:
				m[(&net.IPNet{IP: ip.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}).String()] = exp
			case 3:
				bits := 128
				if !v6 {
					bits = 32
				}
				ones := r.Intn(bits + 1)
				m[(&net.IPNet{IP: ip.Mask(net.CIDRMask(ones, bits)), Mask: net.CIDRMask(ones, bits)}).String()] = exp
			case 4:
				m[fmt.Sprintf("::ffff:198.18.%d.0/%d", r.Intn(4), 96+r.Intn(33))] = exp // v4-mapped CIDR
			case 5:
				m[[]string{"garbage", "", "0.0.0.0/0", "::/0", "198.18.1.1/33", "::ffff:198.18.2.9", "198.018.1.1"}[r.Intn(7)]] = exp
			}
		}
		if round%4 == 0 {
			m["::ffff:198.18.2.9"] = exp // a non-canonical bare key: the scan never matched it by string
		}
		with_ban_map(t, m)
		for q := 0; q < 2000; q++ {
			var addr string
			switch r.Intn(5) {
			case 0:
				addr = rand_ip(r, true).String()
			case 1:
				addr = "::ffff:" + rand_ip(r, false).String()
			case 2:
				for k := range m { // an existing key, verbatim
					addr = k
					break
				}
			case 3:
				addr = []string{"garbage", "", "198.18.0.5", "89.38.99.117:10101", "::1", "0.0.0.0", "198.18.2.9", "::ffff:198.18.2.9"}[r.Intn(8)]
			default:
				addr = rand_ip(r, false).String()
			}
			got := IsAddressInBanList(addr)
			if want := ban_scan_reference(addr); got != want {
				t.Fatalf("round %d: IsAddressInBanList(%q) = %v, the scan said %v (ban set %v)", round, addr, got, want, m)
			}
		}
		// writes through the API keep the index current
		Ban_Address(rand_ip(r, false).String(), 60)
		Ban_Address((&net.IPNet{IP: rand_ip(r, true).Mask(net.CIDRMask(48, 128)), Mask: net.CIDRMask(48, 128)}).String(), 60)
		for k := range m {
			UnBan_Address(k)
			break
		}
		for q := 0; q < 500; q++ {
			addr := rand_ip(r, q%2 == 0).String()
			got := IsAddressInBanList(addr)
			if want := ban_scan_reference(addr); got != want {
				t.Fatalf("round %d after writes: IsAddressInBanList(%q) = %v, the scan said %v", round, addr, got, want)
			}
		}
	}
}

// A lookup must not cost O(bans): with 20,000 score bans the index is built once, a new ban is added in place, and
// lookups never rebuild.
func TestR23cBanLookupDoesNotScan(t *testing.T) {
	m := map[string]uint64{}
	exp := uint64(time.Now().Unix()) + 3600
	for i := 0; i < 20000; i++ {
		if i%2 == 0 {
			m[fmt.Sprintf("198.%d.%d.%d", 18+i/65536, (i/256)%256, i%256)] = exp
		} else {
			m[fmt.Sprintf("2001:db8:%x:%x::/64", i/65536, i%65536)] = exp
		}
	}
	with_ban_map(t, m)
	IsAddressInBanList("192.0.2.1")
	r0 := ban_index_rebuilds
	for i := 0; i < 5000; i++ {
		IsAddressInBanList(fmt.Sprintf("192.0.%d.%d", 2+i/256%8, i%256))
	}
	Ban_Address("203.0.113.9", 60)
	Ban_Address("2001:db8:ffff:1::/64", 60)
	if !IsAddressInBanList("203.0.113.9") || !IsAddressInBanList("2001:db8:ffff:1::abcd") {
		t.Fatal("a ban added after the index was built is not seen")
	}
	if IsAddressInBanList("2001:db8:ffff:2::1") {
		t.Fatal("false positive in the next /64")
	}
	if n := ban_index_rebuilds - r0; n != 0 {
		t.Fatalf("%d index rebuilds during lookups and in-place adds", n)
	}
	if ban_index.n != len(ban_map) {
		t.Fatalf("index covers %d keys, map has %d", ban_index.n, len(ban_map))
	}
}

func reset_penalty(t testing.TB) {
	penalty_mu.Lock()
	saved, saved_prune := penalty_map, penalty_last_prune
	penalty_map, penalty_last_prune = map[string]*misbehaviour{}, time.Time{}
	penalty_mu.Unlock()
	t.Cleanup(func() {
		penalty_mu.Lock()
		penalty_map, penalty_last_prune = saved, saved_prune
		penalty_mu.Unlock()
	})
}

// A fleet that gets each of its addresses banned grew the penalty table without bound, and past 4096 records every
// fault from anyone paid a full scan. Now: at most one scan per PENALTY_PRUNE_INTERVAL, banned records are forgotten
// after PENALTY_OFFENCE_FORGET, and the table has a hard bound.
func TestR23cPenaltyTableBounded(t *testing.T) {
	reset_penalty(t)
	saved := nonbanlist
	defer func() { nonbanlist = saved }()
	nonbanlist = nil
	now := time.Unix(1700000000, 0)
	const fleet = 20000
	for i := 0; i < fleet; i++ {
		ip := fmt.Sprintf("2001:db8:%x:%x::/64", i/65536, i%65536)
		add_penalty(ip, "invalid_pow", now)
		if add_penalty(ip, "undecodable", now) == 0 {
			t.Fatalf("fleet member %d not banned: setup", i)
		}
	}
	s0 := penalty_scanned
	for i := 0; i < 10000; i++ { // 10,000 "busy" faults within one second
		add_penalty("192.0.2.1", "busy", now.Add(time.Duration(i)*50*time.Microsecond))
	}
	scanned := penalty_scanned - s0
	t.Logf("10,000 faults with %d banned records: %d records scanned", fleet, scanned)
	if scanned > fleet+16 {
		t.Fatalf("%d records scanned for 10,000 faults in 0.5 s (one scan is %d)", scanned, fleet)
	}
	// a week after their last fault, banned records are forgotten
	later := now.Add(PENALTY_OFFENCE_FORGET + time.Hour)
	add_penalty("192.0.2.2", "busy", later)
	penalty_mu.Lock()
	n := len(penalty_map)
	penalty_mu.Unlock()
	if n > 16 {
		t.Fatalf("%d records left a week after the fleet's last fault", n)
	}
}

// hard bound: records of bans that ended are dropped first when the table is past PENALTY_MAX_ENTRIES
func TestR23cPenaltyHardBound(t *testing.T) {
	reset_penalty(t)
	saved := nonbanlist
	defer func() { nonbanlist = saved }()
	nonbanlist = nil
	now := time.Unix(1700000000, 0)
	for i := 0; i < PENALTY_MAX_ENTRIES+5000; i++ {
		ip := fmt.Sprintf("2001:db8:%x:%x::/64", i/65536, i%65536)
		add_penalty(ip, "invalid_pow", now)
		add_penalty(ip, "undecodable", now)
	}
	later := now.Add(PENALTY_BAN_BASE*time.Second + time.Minute) // first bans (600 s) ended, records not a week old
	add_penalty("192.0.2.3", "busy", later)
	penalty_mu.Lock()
	n := len(penalty_map)
	penalty_mu.Unlock()
	if n > PENALTY_MAX_ENTRIES {
		t.Fatalf("table holds %d records past its bound %d", n, PENALTY_MAX_ENTRIES)
	}
}

func reset_agg(t testing.TB) {
	agg_mu.Lock()
	saved := agg_map
	agg_map = map[string]*agg_record{}
	atomic.StoreInt32(&agg_active, 0)
	agg_mu.Unlock()
	t.Cleanup(func() {
		agg_mu.Lock()
		agg_map = saved
		agg_active_recount_locked(time.Now())
		agg_mu.Unlock()
	})
}

// Rotating identities: four distinct score-banned addresses of one /24 refuse new inbound sessions from the /24;
// the same address banned four times does not; the neighbouring /24 and a never-ban node's aggregate are untouched.
func TestR23cAggregateInboundBan(t *testing.T) {
	reset_agg(t)
	saved := nonbanlist
	defer func() { nonbanlist = saved }()
	nonbanlist = []string{"198.51.100.200:11011"}
	now := time.Now()
	for i := 0; i < 8; i++ {
		if d := note_score_ban("203.0.113.9", now); d != 0 {
			t.Fatal("one address banned repeatedly triggered an aggregate ban")
		}
	}
	var d time.Duration
	for i := 1; i <= PENALTY_AGG_MEMBERS-1; i++ {
		if d = note_score_ban(fmt.Sprintf("203.0.113.%d", 9+i), now); d != 0 && i < PENALTY_AGG_MEMBERS-1 {
			t.Fatalf("aggregate ban after %d members", i+1)
		}
	}
	if d != PENALTY_AGG_BAN_BASE {
		t.Fatalf("aggregate ban %v after %d distinct members, want %v", d, PENALTY_AGG_MEMBERS, PENALTY_AGG_BAN_BASE)
	}
	if !inbound_aggregate_banned("203.0.113.77", now) {
		t.Fatal("a new address of the banned /24 is admitted")
	}
	if inbound_aggregate_banned("203.0.114.77", now) {
		t.Fatal("the neighbouring /24 is refused")
	}
	limiter := rate.NewLimiter(rate.Every(time.Hour), 1) // one token, no refill within the test
	if admit_inbound("203.0.113.78", limiter) {
		t.Fatal("admit_inbound let a session of a banned aggregate in")
	}
	if !limiter.Allow() {
		t.Fatal("the refused session spent the shared accept token")
	}
	if IsAddressInBanList("203.0.113.78") {
		t.Fatal("the aggregate ban leaked into the ban list (it must stay inbound-only)")
	}
	// expiry: the fast path returns to a single atomic load
	if inbound_aggregate_banned("203.0.113.77", now.Add(PENALTY_AGG_BAN_BASE+time.Second)) {
		t.Fatal("aggregate ban did not end")
	}
	if atomic.LoadInt32(&agg_active) != 0 {
		t.Fatal("agg_active not cleared after the last ban ended")
	}
	// a repeat escalates
	later := now.Add(PENALTY_AGG_BAN_BASE + 2*time.Second)
	for i := 0; i < PENALTY_AGG_MEMBERS; i++ {
		d = note_score_ban(fmt.Sprintf("203.0.113.%d", 100+i), later)
	}
	if d != 2*PENALTY_AGG_BAN_BASE {
		t.Fatalf("second aggregate ban %v, want %v", d, 2*PENALTY_AGG_BAN_BASE)
	}
	// a never-ban node inside the aggregate exempts it
	for i := 0; i < 2*PENALTY_AGG_MEMBERS; i++ {
		if note_score_ban(fmt.Sprintf("198.51.100.%d", i+1), now) != 0 {
			t.Fatal("the aggregate of a priority node was banned")
		}
	}
}

func TestR23cAggregateIPv6Slash48(t *testing.T) {
	reset_agg(t)
	saved := nonbanlist
	defer func() { nonbanlist = saved }()
	nonbanlist = nil
	now := time.Now()
	var d time.Duration
	for i := 0; i < PENALTY_AGG_MEMBERS; i++ {
		d = note_score_ban(fmt.Sprintf("2001:db8:5:%x::/64", i), now)
	}
	if d == 0 {
		t.Fatal("four banned /64s of one /48 did not ban the /48")
	}
	if !inbound_aggregate_banned("2001:db8:5:ffff::1", now) || inbound_aggregate_banned("2001:db8:6::1", now) {
		t.Fatal("/48 aggregate ban covers the wrong addresses")
	}
	if g := penalty_aggregate("10.1.2.3"); g != "" {
		t.Fatalf("a private address has aggregate %q", g)
	}
}

// the wiring: a connection banned by score feeds the aggregate
func TestR23cPenalizeFeedsAggregate(t *testing.T) {
	reset_agg(t)
	reset_penalty(t)
	saved := nonbanlist
	defer func() { nonbanlist = saved }()
	nonbanlist = nil
	for i := 0; i < PENALTY_AGG_MEMBERS; i++ {
		a, b := net.Pipe()
		c := &Connection{Addr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, byte(40+i)), Port: 11011}, Conn: a, ConnTls: a, logger: globals.Logger}
		for j := 0; j < 3; j++ {
			c.penalize("invalid_pow")
		}
		b.Close()
		defer UnBan_Address(fmt.Sprintf("192.0.2.%d", 40+i))
	}
	if !inbound_aggregate_banned("192.0.2.200", time.Now()) {
		t.Fatal("four score bans in one /24 via penalize did not ban the /24 for inbound")
	}
}

// bounded memory of the aggregate table
func TestR23cAggregateTableBounded(t *testing.T) {
	reset_agg(t)
	saved := nonbanlist
	defer func() { nonbanlist = saved }()
	nonbanlist = nil
	now := time.Now()
	for i := 0; i < 3*PENALTY_AGG_MAX_ENTRIES; i++ {
		note_score_ban(fmt.Sprintf("%d.%d.%d.1", 11+i/65536, (i/256)%256, i%256), now)
	}
	agg_mu.Lock()
	n := len(agg_map)
	agg_mu.Unlock()
	if n > PENALTY_AGG_MAX_ENTRIES {
		t.Fatalf("aggregate table %d > bound %d", n, PENALTY_AGG_MAX_ENTRIES)
	}
}
