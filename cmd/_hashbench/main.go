package main

// Fixed-wall-clock AstroBWTv3 hashrate harness (throwaway).
// Measures true H/s at various goroutine counts to find the optimal and test oversubscription.
import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
)

func run(threads int, dur time.Duration) float64 {
	var total uint64
	var wg sync.WaitGroup
	stop := int32(0)
	for t := 0; t < threads; t++ {
		wg.Add(1)
		go func(tid int) {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			var work [48]byte
			work[0] = 1
			work[47] = byte(tid)
			var local uint64
			i := uint32(0)
			for atomic.LoadInt32(&stop) == 0 {
				i++
				work[43] = byte(i)
				work[44] = byte(i >> 8)
				work[45] = byte(i >> 16)
				work[46] = byte(i >> 24)
				_ = astrobwtv3.AstroBWTv3(work[:])
				local++
			}
			atomic.AddUint64(&total, local)
		}(t)
	}
	start := time.Now()
	time.Sleep(dur)
	atomic.StoreInt32(&stop, 1)
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	return float64(total) / elapsed
}

func main() {
	dur := 5 * time.Second
	if len(os.Args) > 1 {
		if d, err := strconv.Atoi(os.Args[1]); err == nil {
			dur = time.Duration(d) * time.Second
		}
	}
	configs := []int{1, 8, 14, 15, 16, 17, 18, 19, 20, 21, 22, 24, 26, 28, 32}
	fmt.Printf("GOMAXPROCS=%d  duration=%s per config\n", runtime.GOMAXPROCS(0), dur)
	// warmup
	run(16, 1*time.Second)
	fmt.Printf("%8s %14s %14s\n", "threads", "H/s", "H/s/thread")
	for _, n := range configs {
		hs := run(n, dur)
		fmt.Printf("%8d %14.1f %14.1f\n", n, hs, hs/float64(n))
	}
}
