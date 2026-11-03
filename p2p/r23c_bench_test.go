package p2p

// r23c (p2psec) cost A/B: compiles on the base (cd1be86) and on the patched tree.

import (
	"fmt"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func bench_bans(b *testing.B, n int) {
	m := map[string]uint64{}
	exp := uint64(time.Now().Unix()) + 3600
	for i := 0; i < n; i++ {
		if i%2 == 0 {
			m[fmt.Sprintf("198.%d.%d.%d", 18+i/65536, (i/256)%256, i%256)] = exp
		} else {
			m[fmt.Sprintf("2001:db8:%x:%x::/64", i/65536, i%65536)] = exp
		}
	}
	ban_mutex.Lock()
	saved := ban_map
	ban_map = m
	ban_mutex.Unlock()
	defer func() { ban_mutex.Lock(); ban_map = saved; ban_mutex.Unlock() }()
	IsAddressInBanList("192.0.2.1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsAddressInBanList("192.0.2.1") // a miss: the path every honest inbound session and dial candidate takes
	}
}

func BenchmarkR23cBanLookup1(b *testing.B)     { bench_bans(b, 1) }
func BenchmarkR23cBanLookup1000(b *testing.B)  { bench_bans(b, 1000) }
func BenchmarkR23cBanLookup20000(b *testing.B) { bench_bans(b, 20000) }

// the inbound admission decision with no bans (the live node's case: 1 ban)
func BenchmarkR23cAdmitInbound(b *testing.B) {
	lim := rate.NewLimiter(rate.Inf, 1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		admit_inbound("10.1.2.3", lim) // non-public: skips the netgroup checks, so the bench isolates ban + aggregate
	}
}

// one "busy" fault with 5,000 banned records in the table
func BenchmarkR23cAddPenaltyFullTable(b *testing.B) {
	penalty_mu.Lock()
	saved := penalty_map
	penalty_map = map[string]*misbehaviour{}
	for i := 0; i < 5000; i++ {
		penalty_map[fmt.Sprintf("2001:db8:%x::/64", i)] = &misbehaviour{offences: 1, at: time.Now()}
	}
	penalty_mu.Unlock()
	defer func() { penalty_mu.Lock(); penalty_map = saved; penalty_mu.Unlock() }()
	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		add_penalty("192.0.2.1", "busy", now.Add(time.Duration(i)*time.Microsecond))
	}
}
