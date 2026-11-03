package main

import (
	"encoding/binary"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"

	"github.com/deroproject/derohe/cmd/dero-miner/astropair"
)

// BenchmarkMinePair (Round 17 profile source): the exact r16 mining step: guarded native sort (verified_sort, 1/1024 Verify) + astropair.Hash2,
// two sequential nonces per op, as mineblock does.
func BenchmarkMinePair(b *testing.B) {
	reset_fast_sort(b)
	reset_pair(b)
	install_fast_sort("auto")
	if s := install_pair_hash("auto"); s[:2] != "on" {
		b.Fatal(s)
	}
	var w, w2 [48]byte
	w[0] = 1
	rand.New(rand.NewSource(3)).Read(w[1:43])
	ps := astropair.NewScratch()
	n := uint32(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n++
		binary.BigEndian.PutUint32(w[43:], n)
		w2 = w
		n++
		binary.BigEndian.PutUint32(w2[43:], n)
		_, _ = hash_pair(w[:], w2[:], ps)
	}
}

// BenchmarkMineThreads: K mining-like threads (env R17_THREADS, default 2), each LockOSThread'd with its own
// astropair scratch and the guarded native sort, sharing b.N pairs. GOMAXPROCS comes from -test.cpu, so
// -test.cpu=K reproduces the live miner's saturation (threads == GOMAXPROCS) and -test.cpu=K+1 leaves an idle P.
func BenchmarkMineThreads(b *testing.B) {
	reset_fast_sort(b)
	reset_pair(b)
	install_fast_sort("auto")
	if s := install_pair_hash("auto"); s[:2] != "on" {
		b.Fatal(s)
	}
	k := 2
	if v := os.Getenv("R17_THREADS"); v != "" {
		k, _ = strconv.Atoi(v)
	}
	var left int64 = int64(b.N)
	var wg sync.WaitGroup
	b.ResetTimer()
	for t := 0; t < k; t++ {
		wg.Add(1)
		go func(t int) {
			defer wg.Done()
			if os.Getenv("R17_NOLOCK") == "" {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
			}
			var w, w2 [48]byte
			w[0] = 1
			rand.New(rand.NewSource(int64(t + 3))).Read(w[1:43])
			ps := astropair.NewScratch()
			n := uint32(0)
			for atomic.AddInt64(&left, -1) >= 0 {
				n++
				binary.BigEndian.PutUint32(w[43:], n)
				w2 = w
				n++
				binary.BigEndian.PutUint32(w2[43:], n)
				_, _ = hash_pair(w[:], w2[:], ps)
			}
		}(t)
	}
	wg.Wait()
}

// TestUnlockedThreadsBitExact: mining goroutines that are NOT locked to OS threads (darwin default since Round 17)
// migrate between Ms, and the C sort keeps one __thread scratch per M. More goroutines than Ps forces migrations
// and P retakes during cgo calls; every pair must still equal the consensus hash.
func TestUnlockedThreadsBitExact(t *testing.T) {
	reset_fast_sort(t)
	reset_pair(t)
	install_fast_sort("auto")
	if s := install_pair_hash("auto"); s[:2] != "on" {
		t.Fatal(s)
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(2))
	const goroutines, pairs = 6, 12
	type res struct {
		in [2][48]byte
		h  [2][32]byte
	}
	out := make(chan res, goroutines*pairs)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			var w [48]byte
			w[0] = 1
			rand.New(rand.NewSource(int64(g + 100))).Read(w[1:43])
			ps := astropair.NewScratch()
			for p := 0; p < pairs; p++ {
				var r res
				r.in[0], r.in[1] = w, w
				binary.BigEndian.PutUint32(r.in[0][43:], uint32(2*p+1))
				binary.BigEndian.PutUint32(r.in[1][43:], uint32(2*p+2))
				r.h[0], r.h[1] = hash_pair(r.in[0][:], r.in[1][:], ps)
				out <- r
			}
		}(g)
	}
	wg.Wait()
	close(out)
	astrobwtv3.SuffixSort = nil // reference: the consensus code path with the built-in SA-IS
	n := 0
	for r := range out {
		for k := 0; k < 2; k++ {
			if want := astrobwtv3.AstroBWTv3(r.in[k][:]); r.h[k] != want {
				t.Fatalf("lane %d of an unlocked pair differs from AstroBWTv3", k)
			}
			n++
		}
	}
	if atomic.LoadInt32(&pair_enabled) != 1 || atomic.LoadInt32(&fast_sort_disabled) != 0 {
		t.Fatalf("a guard tripped: pair=%d sort_disabled=%d", pair_enabled, fast_sort_disabled)
	}
	t.Logf("%d hashes from %d unlocked goroutines on GOMAXPROCS=2 match AstroBWTv3", n, goroutines)
}

func TestShouldLockMiningThread(t *testing.T) {
	cases := []struct {
		goos string
		qos  int
		want bool
	}{
		{"darwin", 0, false}, // nothing to keep: locking cost 16-23% (Round 17)
		{"darwin", 2, true},  // the QoS class lives on the thread
		{"linux", 0, true},   // affinity lives on the thread
		{"windows", 0, true},
	}
	for _, c := range cases {
		if got := should_lock_mining_thread(c.goos, c.qos); got != c.want {
			t.Fatalf("%s qos=%d: lock=%v want %v", c.goos, c.qos, got, c.want)
		}
	}
}
