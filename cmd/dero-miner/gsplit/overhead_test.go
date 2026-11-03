//go:build !windows
// +build !windows

package gsplit

// Round 21 splitpipe: the CPU cost of the split pipeline OUTSIDE the suffix sort, measured without a GPU. A replay
// transport answers every command at once over texts that were staged into the shared region beforehand, so the CPU
// threads run the real TryWork/claim/finish/collect/Found path; the control runs only astropair.SortOnly over the same
// texts. Both are metered in process CPU time (H/cpu-s), interleaved A/B, because wall rates on the live box are
// polluted by the running miner. Gated: GSPLIT_OVERHEAD=1 (threads GSPLIT_OVERHEAD_T, default 6; seconds per leg
// GSPLIT_OVERHEAD_S, default 8; rounds GSPLIT_OVERHEAD_R, default 3; GOMAXPROCS GSPLIT_OVERHEAD_PROCS, default T).
//
// derohe r23c cpupath: both legs now run as mineblock does — a Gosched every cgo_yield_every (8) sorts
// (cmd/dero-miner/cgoyield.go) at GOMAXPROCS == threads (the live --mining-threads default). The r21 control looped
// SortOnly with no yield at the machine's GOMAXPROCS, so ~17% of its CPU went to the exitsyscall slow path
// (pprof: pthread_cond_signal 13.9% + sched.lock 3.8%) and 'engine/sort' read 1.03-1.04 — the pipeline looked
// cheaper than the bare sort it wraps. With matching yields it reads ~1.00.

import (
	"encoding/binary"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/deroproject/derohe/cmd/dero-miner/astropair"
)

func cpuNow() time.Duration {
	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// replayGPU answers op 1 and op 2 immediately: the texts (and their lengths) in the shared region never change.
type replayGPU struct {
	ch   chan reply
	mu   sync.Mutex
	done bool
	us   uint32
}

func (g *replayGPU) issue(op, first, n, tag uint32) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.done {
		g.ch <- reply{tag: tag, op: op, us: g.us}
	}
	return nil
}
func (g *replayGPU) replies() <-chan reply { return g.ch }
func (g *replayGPU) kill()                 { g.close() }
func (g *replayGPU) close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.done {
		g.done = true
		close(g.ch)
	}
}

// overheadTexts: n distinct stage-1 texts of random version-1 blobs.
func overheadTexts(n int) [][]byte {
	s := astropair.NewScratch()
	rng := rand.New(rand.NewSource(21))
	buf := make([]byte, DStride)
	out := make([][]byte, n)
	for i := range out {
		var m [MsgLen]byte
		rng.Read(m[:])
		m[0] = m[0]&0xf0 | 1
		l := astropair.Stage1Text(m[:], buf, s)
		out[i] = append([]byte(nil), buf[:l]...)
	}
	return out
}

func newReplayEngine(t testing.TB, texts [][]byte, batch, depth int, found func(tag interface{}, blob []byte, h [32]byte)) *Engine {
	var tpl [MsgLen]byte
	tpl[0] = 0x41
	cfg := Config{Batch: batch, Depth: depth, Inflight: 2, GPUSHA: true, GPUMax: 100, noAudit: true, // the replayed texts do not hash to their blobs; 1 audit per batch is ~0.1 us/hash
		Next:  func() (Work, bool) { return Work{Blob: tpl, Tag: 1}, true },
		Stale: func(interface{}) bool { return false },
		Found: found,
	}
	cfg.transport = func(e *Engine) (transport, error) {
		if e.mem == nil {
			e.mem = make([]byte, e.lay.Size)
			for o := 0; o < len(e.mem); o += 4096 { // touch every page now: the live shm is resident, first-touch faults are not pipeline cost
				e.mem[o] = 1
			}
			for j := 0; j < e.lay.Slots; j++ {
				tx := texts[j%len(texts)]
				copy(e.mem[e.lay.OffDatas+j*DStride:], tx)
				binary.LittleEndian.PutUint32(e.mem[e.lay.OffLens+4*j:], uint32(len(tx)))
			}
		}
		return &replayGPU{ch: make(chan reply, 4*depth), us: 7}, nil
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// overheadYieldEvery mirrors cmd/dero-miner cgo_yield_every: mineblock yields after this many cgo sorts (r21).
const overheadYieldEvery = 8

// legYielder is mineblock's cgo_yielder for the overhead legs: yield (runtime.Gosched) once per overheadYieldEvery
// sorts, counting the k hashes each call returned (0 = an idle try, nothing sorted).
type legYielder struct {
	n     int
	yield func()
}

func (y *legYielder) sorted(k int) bool {
	if k <= 0 {
		return false
	}
	if y.n += k; y.n < overheadYieldEvery {
		return false
	}
	y.n = 0
	y.yield()
	return true
}

// runLegYield is runLeg with each worker yielding like a mining thread (legYielder).
func runLegYield(T int, d time.Duration, work func(s *astropair.Scratch, sa []int32, k int) int) (uint64, time.Duration) {
	return runLegWith(T, d, true, work)
}

// runLeg runs T threads for d and returns hashes and process CPU time.
func runLeg(T int, d time.Duration, work func(s *astropair.Scratch, sa []int32, k int) int) (uint64, time.Duration) {
	return runLegWith(T, d, false, work)
}

func runLegWith(T int, d time.Duration, yield bool, work func(s *astropair.Scratch, sa []int32, k int) int) (uint64, time.Duration) {
	var n atomic.Uint64
	var wg sync.WaitGroup
	stop := make(chan struct{})
	c0 := cpuNow()
	for w := 0; w < T; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			s := astropair.NewScratch()
			sa := make([]int32, SStride)
			y := legYielder{yield: runtime.Gosched}
			for k := w; ; k++ {
				select {
				case <-stop:
					return
				default:
				}
				got := work(s, sa, k)
				if yield {
					y.sorted(got)
				}
				n.Add(uint64(got))
			}
		}(w)
	}
	time.Sleep(d)
	close(stop)
	wg.Wait()
	return n.Load(), cpuNow() - c0
}

func TestSplitOverheadAB(t *testing.T) {
	if os.Getenv("GSPLIT_OVERHEAD") != "1" {
		t.Skip("set GSPLIT_OVERHEAD=1 (run under benchlock): CPU-side overhead of the split pipeline vs the bare sort")
	}
	T := envInts("GSPLIT_OVERHEAD_T", "6")[0]
	S := envInts("GSPLIT_OVERHEAD_S", "8")[0]
	R := envInts("GSPLIT_OVERHEAD_R", "3")[0]
	geo := envInts("GSPLIT_OVERHEAD_GEOM", "512,4")
	procs := envInts("GSPLIT_OVERHEAD_PROCS", strconv.Itoa(T))[0]
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(procs)) // live: --mining-threads == GOMAXPROCS (no idle P)
	texts := overheadTexts(64)
	var foundN atomic.Uint64
	for r := 0; r < R; r++ {
		hs, cs := runLegYield(T, time.Duration(S)*time.Second, func(s *astropair.Scratch, sa []int32, k int) int {
			if !astropair.SortOnly(texts[k%len(texts)], sa) {
				t.Error("sort declined")
			}
			return 1
		})
		e := newReplayEngine(t, texts, geo[0], geo[1], func(tag interface{}, blob []byte, h [32]byte) { foundN.Add(1) })
		e.Start()
		he, ce := runLegYield(T, time.Duration(S)*time.Second, func(s *astropair.Scratch, sa []int32, k int) int { return e.TryWork(s) })
		st := e.Stats()
		e.Close()
		rs, re := float64(hs)/cs.Seconds(), float64(he)/ce.Seconds()
		t.Logf("round %d: sort-only %.0f H/cpu-s (%d in %.1f cpu-s) | engine %.0f H/cpu-s (%d in %.1f cpu-s, idle %d) | engine/sort %.3f",
			r, rs, hs, cs.Seconds(), re, he, ce.Seconds(), st.IdleTries, re/rs)
	}
}

// derohe r23c cpupath: the overhead legs yield exactly as mineblock's cgo_yielder does — once per 8 sorted hashes,
// never on an idle try (k=0) — so the bare-sort control is not charged the exitsyscall slow path the miner avoids.
func TestLegYielderCadence(t *testing.T) {
	var yields int
	y := legYielder{yield: func() { yields++ }}
	for i := 0; i < 8; i++ { // eight engine pairs = 16 sorts
		y.sorted(2)
	}
	if yields != 2 {
		t.Fatalf("16 sorts gave %d yields, want 2 (one per %d sorts)", yields, overheadYieldEvery)
	}
	for i := 0; i < 100; i++ {
		if y.sorted(0) {
			t.Fatal("an idle try (0 hashes) yielded")
		}
	}
	yields = 0
	for i := 0; i < 7; i++ {
		y.sorted(1)
	}
	if yields != 0 {
		t.Fatalf("7 sorts yielded %d times", yields)
	}
	if !y.sorted(1) || yields != 1 {
		t.Fatalf("the 8th sort did not yield (yields %d)", yields)
	}
}
