package gsplit

// A/B harness (skipped unless GSPLIT_HARNESS is set). Arms, each run for a fixed wall window on T CPU threads:
//
//	cpu    : T threads of astropair.Hash2 (the r16/r17 CPU path) only
//	full   : cpu + the r17 full-hash GPU worker (gpu_hash_sais "server", 4096-nonce batches, back to back)
//	split  : T threads that take GPU-staged texts first (TryWork) and hash on the CPU when nothing is staged;
//	         GPU stage 1 + GPU final SHA (GSPLIT_SHA=cpu: CPU paired SHA)
//
// Rounds interleave the arms and reverse the order every round. Env: GSPLIT_HARNESS=1, GSPLIT_T=1,2,4,
// GSPLIT_PAIRS=6, GSPLIT_WIN=10s, GSPLIT_ARMS=cpu,full,split, GSPLIT_GEOM=batch,depth,inflight (2048,6,3),
// GSPLIT_FULLBIN=path to a COPY of gpu_hash_sais.

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deroproject/derohe/cmd/dero-miner/astropair"
)

func envInts(k, def string) []int {
	v := os.Getenv(k)
	if v == "" {
		v = def
	}
	var r []int
	for _, s := range strings.Split(v, ",") {
		x, err := strconv.Atoi(strings.TrimSpace(s))
		if err == nil {
			r = append(r, x)
		}
	}
	return r
}

func gpuMaxEnv() int { return envInts("GSPLIT_GPUMAX", "100")[0] }

func median(a []float64) float64 {
	s := append([]float64(nil), a...)
	sort.Float64s(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

// fullGPU drives the r17 full-hash server exactly as mineblock_gpu does (stdin [n][n*48] -> stdout [n*32]).
type fullGPU struct {
	bin    string
	fails  int // batches the macOS GPU watchdog killed (the server is restarted; live mineblock_gpu would stop instead)
	in     io.WriteCloser
	out    *bufio.Reader
	cmd    *exec.Cmd
	blobs  []byte
	batchD time.Duration // EWMA batch duration, for pro-rating the batch in progress at the window end
}

func startFull(t *testing.T, bin string) *fullGPU {
	f := &fullGPU{bin: bin, cmd: exec.Command(bin, "server"), blobs: make([]byte, 4096*48)}
	f.cmd.Dir = filepath.Dir(bin)
	f.cmd.Stderr = os.Stderr
	f.in, _ = f.cmd.StdinPipe()
	o, _ := f.cmd.StdoutPipe()
	f.out = bufio.NewReaderSize(o, 4096*32+64)
	if err := f.cmd.Start(); err != nil {
		panic(err)
	}
	return f
}

func (f *fullGPU) batch(nonce uint32) error {
	for j := 0; j < 4096; j++ {
		b := f.blobs[j*48 : j*48+48]
		b[0] = 0x41
		binary.BigEndian.PutUint32(b[43:], nonce+uint32(j))
	}
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], 4096)
	if _, err := f.in.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := f.in.Write(f.blobs); err != nil {
		return err
	}
	res := make([]byte, 4096*32)
	_, err := io.ReadFull(f.out, res)
	return err
}

// run hashes back to back until stop; returns hashes, pro-rating the batch in flight at stop by elapsed/EWMA.
func (f *fullGPU) run(stop *int32, done chan float64) {
	var h float64
	nonce := rand.Uint32()
	for atomic.LoadInt32(stop) == 0 {
		t0 := time.Now()
		ch := make(chan error, 1)
		go func(n uint32) { ch <- f.batch(n) }(nonce)
		nonce += 4096
		var fin bool
		for !fin {
			select {
			case err := <-ch:
				if err != nil { // watchdog kill: restart the server; the lost time stays in the window
					f.fails++
					f.in.Close()
					f.cmd.Wait()
					nf := startFull(nil, f.bin)
					f.in, f.out, f.cmd = nf.in, nf.out, nf.cmd
					fin = true
					continue
				}
				d := time.Since(t0)
				if f.batchD == 0 {
					f.batchD = d
				} else {
					f.batchD = (f.batchD*3 + d) / 4
				}
				h += 4096
				fin = true
			case <-time.After(5 * time.Millisecond):
				if atomic.LoadInt32(stop) != 0 && f.batchD > 0 {
					frac := math.Min(1, float64(time.Since(t0))/float64(f.batchD))
					<-ch // finish the batch before reporting, so it never overlaps the next arm's window
					done <- h + frac*4096
					return
				}
			}
		}
	}
	done <- h
}

func TestHarnessAB(t *testing.T) {
	if os.Getenv("GSPLIT_HARNESS") == "" {
		t.Skip("set GSPLIT_HARNESS=1")
	}
	Ts := envInts("GSPLIT_T", "1,2,4")
	pairs := envInts("GSPLIT_PAIRS", "6")[0]
	win, _ := time.ParseDuration(os.Getenv("GSPLIT_WIN"))
	if win == 0 {
		win = 10 * time.Second
	}
	arms := strings.Split(os.Getenv("GSPLIT_ARMS"), ",")
	if arms[0] == "" {
		arms = []string{"cpu", "full", "split"}
	}
	g := envInts("GSPLIT_GEOM", "2048,6,3")
	gpuSHA := os.Getenv("GSPLIT_SHA") != "cpu"
	maxT := 0
	for _, x := range Ts {
		if x > maxT {
			maxT = x
		}
	}
	scr := make([]*astropair.Scratch, maxT)
	for i := range scr {
		scr[i] = astropair.NewScratch()
	}

	var full *fullGPU
	for _, a := range arms {
		if a == "full" {
			full = startFull(t, os.Getenv("GSPLIT_FULLBIN"))
			defer func() { full.in.Close(); full.cmd.Wait() }()
			var err error
			for try := 0; try < 3; try++ { // warm-up (MSL compile); a contended GPU can fail a first batch
				if err = full.batch(1); err == nil {
					break
				}
				full.in.Close()
				full.cmd.Wait()
				full = startFull(t, os.Getenv("GSPLIT_FULLBIN"))
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	}

	// split engine (paused between its windows: Next returns false, and staged texts of an old window are stale)
	var epoch, active atomic.Int64
	var tpl [MsgLen]byte
	rand.Read(tpl[:])
	tpl[0] = 0x41
	var e *Engine
	for _, a := range arms {
		if a == "split" {
			var err error
			e, err = New(Config{Bin: realBin(t), Batch: g[0], Depth: g[1], Inflight: g[2], GPUSHA: gpuSHA, GPUMax: gpuMaxEnv(), AuditEvery: 4096,
				Next: func() (Work, bool) {
					if active.Load() == 0 {
						return Work{}, false
					}
					return Work{Blob: tpl, Tag: epoch.Load()}, true
				},
				Stale: func(tag interface{}) bool { return tag.(int64) != epoch.Load() },
				Found: func(tag interface{}, blob []byte, h [32]byte) {},
				Logf:  t.Logf})
			if err != nil {
				t.Fatal(err)
			}
			if err := e.SelfTest(256, scr[0]); err != nil {
				t.Fatal(err)
			}
			e.Start()
			defer e.Close()
		}
	}
	for _, T := range Ts {
		res := map[string][]float64{}
		for r := 0; r < pairs; r++ {
			order := append([]string(nil), arms...)
			if r%2 == 1 {
				for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
					order[i], order[j] = order[j], order[i]
				}
			}
			for _, a := range order {
				var stop int32
				var cpuH, gpuH, staged atomic.Int64
				var fullDone chan float64
				if a == "split" {
					epoch.Add(1)
					active.Store(1)
					// drain the previous window's (now stale) batches so the ring refills on the new epoch; texts
					// staged here are hashed outside the window and not counted
					for t1 := time.Now(); time.Since(t1) < 400*time.Millisecond; {
						if e.TryWork(scr[0]) == 0 {
							time.Sleep(time.Millisecond)
						}
					}
				}
				if a == "full" {
					fullDone = make(chan float64, 1)
					go full.run(&stop, fullDone)
				}
				var wg sync.WaitGroup
				t0 := time.Now()
				for w := 0; w < T; w++ {
					wg.Add(1)
					go func(w int) {
						defer wg.Done()
						s := scr[w]
						var a2, b2 [MsgLen]byte
						copy(a2[:], tpl[:])
						a2[44] = byte(w)
						n := rand.Uint32()
						for atomic.LoadInt32(&stop) == 0 {
							if a == "split" {
								if k := e.TryWork(s); k > 0 {
									staged.Add(int64(k))
									continue
								}
							}
							binary.BigEndian.PutUint32(a2[40:], n)
							b2 = a2
							binary.BigEndian.PutUint32(b2[40:], n+1)
							n += 2
							astropair.Hash2(a2[:], b2[:], s)
							cpuH.Add(2)
						}
					}(w)
				}
				time.Sleep(win)
				atomic.StoreInt32(&stop, 1)
				el := time.Since(t0).Seconds()
				wg.Wait()
				if a == "full" {
					gpuH.Store(int64(<-fullDone))
				}
				if a == "split" {
					active.Store(0)
				}
				tot := float64(cpuH.Load()+gpuH.Load()+staged.Load()) / el
				res[a] = append(res[a], tot)
				res[a+".gpu"] = append(res[a+".gpu"], float64(gpuH.Load()+staged.Load())/el)
				time.Sleep(500 * time.Millisecond)
			}
		}
		mode := "gpuSHA"
		if !gpuSHA {
			mode = "cpuSHA"
		}
		fmt.Printf("T=%d CONTENDED (live derod + live 20-thread CPU miner + other agents' jobs on this host; the live GPU worker died 07:40:25); %d interleaved rounds x %s; split geom batch=%d depth=%d inflight=%d %s\n",
			T, pairs, win, g[0], g[1], g[2], mode)
		base := res[arms[0]]
		for _, a := range arms {
			v := res[a]
			s := append([]float64(nil), v...)
			sort.Float64s(s)
			gp := median(res[a+".gpu"])
			fmt.Printf("  %-6s median %8.0f H/s  range %8.0f..%8.0f  (GPU-fed part median %7.0f)", a, median(v), s[0], s[len(s)-1], gp)
			if a != arms[0] {
				var rr []float64
				for i := range v {
					rr = append(rr, v[i]/base[i])
				}
				sort.Float64s(rr)
				fmt.Printf("  paired %s/%s median x%.3f range %.3f..%.3f", a, arms[0], median(rr), rr[0], rr[len(rr)-1])
			}
			fmt.Println()
		}
		if e != nil {
			fmt.Printf("  split engine: %+v\n", e.Stats())
		}
		if full != nil {
			fmt.Printf("  full-hash server: watchdog-killed batches so far %d\n", full.fails)
		}
	}
}

// TestGPUCapacity (GSPLIT_HARNESS=1): the split pipeline's GPU throughput with the CPU side made free (a fake,
// instant sort; no audit, no self-test), i.e. the most staged hashes/s the GPU can feed. GSPLIT_GEOMS=b,d,i;b,d,i
func TestGPUCapacity(t *testing.T) {
	if os.Getenv("GSPLIT_HARNESS") == "" {
		t.Skip("set GSPLIT_HARNESS=1")
	}
	old := astropair.SuffixSort
	astropair.SuffixSort = func(text []byte, sa []int32) bool { return true }
	defer func() { astropair.SuffixSort = old }()
	geoms := os.Getenv("GSPLIT_GEOMS")
	if geoms == "" {
		geoms = "2048,6,3"
	}
	win := 8 * time.Second
	for _, gs := range strings.Split(geoms, ";") {
		var g []int
		for _, x := range strings.Split(gs, ",") {
			v, _ := strconv.Atoi(x)
			g = append(g, v)
		}
		var tpl [MsgLen]byte
		tpl[0] = 0x41
		e, err := New(Config{Bin: realBin(t), Batch: g[0], Depth: g[1], Inflight: g[2], GPUSHA: true, GPUMax: gpuMaxEnv(), noAudit: true,
			Next:  func() (Work, bool) { return Work{Blob: tpl, Tag: 0}, true },
			Found: func(tag interface{}, blob []byte, h [32]byte) {}, Logf: t.Logf})
		if err != nil {
			t.Fatal(err)
		}
		e.Start()
		var rates []float64
		for r := 0; r < 4; r++ {
			var stop int32
			var n atomic.Int64
			var wg sync.WaitGroup
			for w := 0; w < 4; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					s := astropair.NewScratch()
					for atomic.LoadInt32(&stop) == 0 {
						if k := e.TryWork(s); k > 0 {
							n.Add(int64(k))
						} else {
							time.Sleep(50 * time.Microsecond)
						}
					}
				}()
			}
			t0 := time.Now()
			time.Sleep(win)
			atomic.StoreInt32(&stop, 1)
			wg.Wait()
			rates = append(rates, float64(n.Load())/time.Since(t0).Seconds())
		}
		e.Close()
		s := append([]float64(nil), rates...)
		sort.Float64s(s)
		fmt.Printf("GPU CAPACITY geom %s gpu-max %d (stage 1 + GPU SHA, CPU side free; GPU shared with other host jobs): median %.0f staged H/s range %.0f..%.0f (4 x %s) %+v\n",
			gs, gpuMaxEnv(), median(rates), s[0], s[len(s)-1], win, e.Stats())
		if median(rates) <= 0 { // r22 merge (H22-8 review): a capacity run that staged nothing is a failure, not a 0 H/s pass
			t.Fatalf("GPU CAPACITY geom %s: median 0 staged H/s (the engine staged nothing; stats %+v)", gs, e.Stats())
		}
	}
}
