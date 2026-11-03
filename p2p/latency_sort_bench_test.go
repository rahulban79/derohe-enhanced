package p2p

import (
	"sort"
	"testing"
)

func bench_peers(n int) map[uint64]*Connection {
	m := map[uint64]*Connection{}
	for i := 1; i <= n; i++ {
		c := &Connection{Peer_ID: uint64(i)}
		c.Latency.Store(int64((7919 * i) % 1000))
		m[uint64(i)] = c
	}
	return m
}

// the pre-patch shape (Broadcast_MiniBlock): collect, then sort with two atomic loads per comparison
func old_sort_by_latency(unique_map map[uint64]*Connection) []*Connection {
	connections := make([]*Connection, 0, len(unique_map))
	for _, v := range unique_map {
		connections = append(connections, v)
	}
	sort.SliceStable(connections, func(i, j int) bool { return connections[i].Latency.Load() < connections[j].Latency.Load() })
	return connections
}

func BenchmarkLatencySortOld32(b *testing.B) {
	m := bench_peers(32)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = old_sort_by_latency(m)
	}
}

func BenchmarkLatencySortNew32(b *testing.B) {
	m := bench_peers(32)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = sort_by_latency(m)
	}
}
