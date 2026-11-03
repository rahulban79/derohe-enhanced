package main

// --bench --gpu-mode=split (Round 19): the CPU side of split mode, measured WITHOUT the GPU.
//
// In split mode a CPU thread's whole job per hash is astropair.SortOnly on a stage-1 text the GPU staged (the GPU
// also does the final SHA-256, gsplit Config.GPUSHA). This bench builds those texts on the CPU beforehand
// (astropair.Stage1Text, the software reference of the k_s1tg kernel, outside the timed and CPU-metered section) and
// then times only the sorts. It never starts gpu_split_server and never touches Metal, so it is safe to run while
// the live split server owns the GPU. Its Hash/CPU-Sec column is the split ceiling per CPU-second: the GPU side is
// measured live (the "GPU split" staged_H/s line), not here.

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
	"github.com/deroproject/derohe/cmd/dero-miner/astropair"
	"github.com/deroproject/derohe/cmd/dero-miner/gsplit"
)

// split_bench_texts: distinct stage-1 texts per thread; the sort cost depends on the text, so one text would
// measure a single point of the cost distribution (the same reason random_execution varies its input per hash)
const split_bench_texts = 64

// split_bench_inputs makes n stage-1 texts from n different 48-byte inputs (seed with nonce i, split_bench_blob).
func split_bench_inputs(n int) (seed [48]byte, texts [][]byte) {
	rand.Read(seed[:])
	return seed, split_bench_texts_of(seed, n)
}

// split_bench_blob is the 48-byte input of text i: seed with nonce bytes 39..42 set to i (what the GPU would stage)
func split_bench_blob(seed [48]byte, i int) [48]byte {
	binary.BigEndian.PutUint32(seed[39:43], uint32(i))
	return seed
}

// split_bench_texts_of: text i is the stage-1 text of split_bench_blob(in, i)
func split_bench_texts_of(in [48]byte, n int) [][]byte {
	s := astropair.NewScratch()
	out := make([][]byte, n)
	buf := make([]byte, gsplit.DStride)
	for i := range out {
		b := split_bench_blob(in, i)
		l := astropair.Stage1Text(b[:], buf, s)
		out[i] = append([]byte(nil), buf[:l]...)
	}
	return out
}

// split_sort_texts sorts iterations texts (cycling through texts) the way gsplit.Engine.pair does with GPUSHA. A
// declined sort calls finish with the text's index: the caller charges what gsplit's cpuFinish costs while mining,
// a full astrobwtv3.AstroBWTv3 of the 48-byte input (verifier H2). It returns how many were declined.
func split_sort_texts(texts [][]byte, iterations int, sa []int32, finish func(i int)) (declined int) {
	yield := new_cgo_yielder() // as mineblock does around TryWork (r21)
	for i := 0; i < iterations; i++ {
		k := i % len(texts)
		if !astropair.SortOnly(texts[k], sa) {
			declined++
			finish(k)
		}
		yield.sorted(1)
	}
	return
}

// split_bench_requested: --bench --gpu-mode=split runs split_bench instead of the full-hash bench (verifier H2)
func split_bench_requested(args map[string]interface{}) bool {
	mode, _ := args["--gpu-mode"].(string)
	return mode == "split"
}

// split_bench prints the same table as --bench for the split CPU path, one row per thread count. false: split mode
// cannot run on this build/CPU (it needs paired hashing, exactly as start_gpu_split does) and nothing was measured.
func split_bench(threads, iterations int) bool {
	if atomic.LoadInt32(&pair_enabled) != 1 {
		fmt.Printf("split: off (gpu split mode needs paired hashing; %s)\n", pair_status())
		return false
	}
	fmt.Printf("split: CPU side only (GPU stage 1 + SHA not run; texts prepared on the CPU, untimed) · sort: %s\n", fast_sort_status())
	fmt.Printf("%20s %20s %20s %20s %20s %20s \n", "Threads", "Total Time", "Total Iterations", "Time/PoW ", "Hash/CPU-Sec", "Hash Rate/Sec")
	inputs := make([][][]byte, threads)
	seeds := make([][48]byte, threads)
	for i := range inputs {
		seeds[i], inputs[i] = split_bench_inputs(split_bench_texts)
	}
	var declined int64
	for bench := 1; bench <= threads; bench++ {
		var wg sync.WaitGroup
		cpu0 := process_cpu_time()
		now := time.Now()
		for i := 0; i < bench; i++ {
			wg.Add(1)
			go func(seed [48]byte, texts [][]byte) {
				defer wg.Done()
				lock_mining_thread()
				defer runtime.UnlockOSThread()
				sa := make([]int32, gsplit.MaxText+1)
				d := split_sort_texts(texts, iterations, sa, func(k int) {
					b := split_bench_blob(seed, k)
					_ = astrobwtv3.AstroBWTv3(b[:]) // what cpuFinish does with a declined sort
				})
				atomic.AddInt64(&declined, int64(d))
			}(seeds[i], inputs[i])
		}
		wg.Wait()
		duration := time.Since(now)
		cpu := process_cpu_time() - cpu0
		fmt.Printf("%20s %20s %20s %20s %20s %20s \n", fmt.Sprintf("%d", bench), fmt.Sprintf("%s", duration), fmt.Sprintf("%d", bench*iterations),
			fmt.Sprintf("%s", duration/time.Duration(bench*iterations)), cpu_rate_string(bench*iterations, cpu),
			fmt.Sprintf("%.1f", float32(time.Second)/(float32(duration/time.Duration(bench*iterations)))))
	}
	fmt.Printf("split: declined sorts %d (each would be re-hashed in full on the CPU while mining)\n", declined)
	return true
}
