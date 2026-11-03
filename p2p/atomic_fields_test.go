package p2p

import (
	"sync"
	"testing"
	"unsafe"

	"github.com/deroproject/derohe/globals"
)

// sort_by_latency must return every peer exactly once, lowest latency first, and stay race-free while update()
// rewrites the latencies it reads (the old Broadcast_Block comparator read Latency with no atomic load at all).
func TestSortByLatencyOrderAndConcurrency(t *testing.T) {
	peers := map[uint64]*Connection{}
	for i := uint64(1); i <= 32; i++ {
		c := &Connection{Peer_ID: i, logger: globals.Logger}
		c.Latency.Store(int64((37 * i) % 32)) // a permutation of 0..31
		peers[i] = c
	}
	got := sort_by_latency(peers)
	if len(got) != len(peers) {
		t.Fatalf("got %d peers, want %d", len(got), len(peers))
	}
	seen := map[uint64]bool{}
	for i, c := range got {
		if seen[c.Peer_ID] {
			t.Fatalf("peer %d returned twice", c.Peer_ID)
		}
		seen[c.Peer_ID] = true
		if i > 0 && got[i-1].Latency.Load() > c.Latency.Load() {
			t.Fatalf("not sorted at %d: %d > %d", i, got[i-1].Latency.Load(), c.Latency.Load())
		}
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for _, c := range peers {
		wg.Add(1)
		go func(c *Connection) {
			defer wg.Done()
			for i := int64(0); ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				var common Common_Struct
				common.Height, common.TopoHeight, common.Top_Version = i, i, 3
				common.T0, common.T1, common.T2 = 1000, 1500+i%7, 1600+i%11
				c.update(&common) // stores Latency, Height, TopoHeight, clock_offset atomically
			}
		}(c)
	}
	for r := 0; r < 200; r++ {
		if out := sort_by_latency(peers); len(out) != len(peers) {
			t.Fatalf("round %d: got %d peers", r, len(out))
		}
	}
	close(stop)
	wg.Wait()
}

// pings overlap when one is slower than the ping interval, so the every-10th-ping peer-list counter is shared
func TestPingCountIsSharedSafely(t *testing.T) {
	c := &Connection{}
	var wg sync.WaitGroup
	var mu sync.Mutex
	with_list := 0
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if c.ping_count.Add(1)%10 == 1 { // the expression ping_loop uses
					mu.Lock()
					with_list++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if c.ping_count.Load() != 1000 || with_list != 100 {
		t.Fatalf("ping_count=%d with_list=%d, want 1000 and 100", c.ping_count.Load(), with_list)
	}
}

// the typed atomics carry their own 8-byte alignment; this pins it for the fields 32-bit builds used to depend on
// field order for (go vet with GOARCH=arm also passes)
func TestConnectionAtomicFieldsAligned(t *testing.T) {
	var c Connection
	for name, off := range map[string]uintptr{
		"Height": unsafe.Offsetof(c.Height), "Latency": unsafe.Offsetof(c.Latency), "clock_offset": unsafe.Offsetof(c.clock_offset),
		"mbl_dup": unsafe.Offsetof(c.mbl_dup), "update_received_ns": unsafe.Offsetof(c.update_received_ns),
	} {
		if off%8 != 0 {
			t.Fatalf("%s at offset %d is not 8-byte aligned", name, off)
		}
	}
}
