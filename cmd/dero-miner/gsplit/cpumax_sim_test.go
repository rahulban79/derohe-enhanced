//go:build !windows
// +build !windows

package gsplit

// Round 22 cpusort: the r21 open item "live A/B of --cpu-max=100", answered WITHOUT touching the live miner. A
// simulated GPU (one serial queue that sleeps n x GSPLIT_SIM_US1 us for op 1 and n x GSPLIT_SIM_US2 us for op 2, so it
// costs no CPU) feeds the real Engine over real stage-1 texts; T threads run the mining loop's split branch as miner.go
// does (not modelled: miner.go's cgo yield.sorted call, and the CPU the real gpu_split_server spends encoding and
// submitting command buffers - this simulated GPU costs zero CPU, so a live --cpu-max=100 gain may be smaller or
// negative; r22 merge, CS22-4 review): TryWork, and on 0 a paired full CPU hash of their own nonces (astropair.Hash2), with the same 40 ms
// duty-cycle throttle. Legs at each --cpu-max in GSPLIT_SIM_DUTY run interleaved; each reports staged and own hashes
// per wall second and per process CPU-second, idle tries, and the simulated GPU's busy fraction. With
// GSPLIT_SIM_MUTEX=<file> the run also records a mutex-contention profile (runtime.SetMutexProfileFraction, the r21
// open item F6). Gated: GSPLIT_CPUMAX=1, run under benchlock.

import (
	"encoding/binary"
	"math/rand"
	"os"
	"runtime"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deroproject/derohe/cmd/dero-miner/astropair"
)

// simGPU executes commands one at a time in issue order; a command "runs" for n x per-hash us of wall time.
type simGPU struct {
	cmds     chan [4]uint32
	ch       chan reply
	us1, us2 float64
	busyNs   atomic.Int64
	mu       sync.Mutex
	done     bool
	quit     chan struct{}
	sending  sync.WaitGroup // r22 merge: a reply send in flight (close waits for it before closing ch)
	chOnce   sync.Once
}

func newSimGPU(us1, us2 float64) *simGPU {
	g := &simGPU{cmds: make(chan [4]uint32, 64), ch: make(chan reply, 64), us1: us1, us2: us2, quit: make(chan struct{})}
	go g.run()
	return g
}

func (g *simGPU) run() {
	for {
		select {
		case c := <-g.cmds:
			per := g.us1
			if c[0] == 2 {
				per = g.us2
			}
			d := time.Duration(float64(c[2]) * per * float64(time.Microsecond))
			time.Sleep(d)
			g.busyNs.Add(int64(d))
			g.mu.Lock() // r22 merge (CS22-4 review): never send while holding mu, so close cannot deadlock on a full ch
			if g.done {
				g.mu.Unlock()
				return
			}
			g.sending.Add(1)
			g.mu.Unlock()
			select {
			case g.ch <- reply{tag: c[3], op: c[0], us: uint32(d / time.Microsecond)}:
			case <-g.quit:
			}
			g.sending.Done()
		case <-g.quit:
			return
		}
	}
}

func (g *simGPU) issue(op, first, n, tag uint32) error {
	select {
	case g.cmds <- [4]uint32{op, first, n, tag}:
	case <-g.quit:
	}
	return nil
}
func (g *simGPU) replies() <-chan reply { return g.ch }
func (g *simGPU) kill()                 { g.close() }
func (g *simGPU) close() {
	g.mu.Lock()
	if !g.done {
		g.done = true
		close(g.quit)
	}
	g.mu.Unlock()
	g.sending.Wait() // the in-flight send (if any) returned through quit
	g.chOnce.Do(func() { close(g.ch) })
}

type simLeg struct {
	staged, own, idle uint64
	cpu, wall         time.Duration
	gpuBusy           float64
}

// simDutyLeg runs T mining-loop threads at duty cpuMax for d against a fresh engine on a fresh simulated GPU.
func simDutyLeg(t testing.TB, texts [][]byte, T, cpuMax int, d time.Duration, us1, us2 float64, geo []int) simLeg {
	var g *simGPU
	var tpl [MsgLen]byte
	tpl[0] = 0x41
	cfg := Config{Batch: geo[0], Depth: geo[1], Inflight: 2, GPUSHA: true, GPUMax: 100, noAudit: true,
		Next:  func() (Work, bool) { return Work{Blob: tpl, Tag: 1}, true },
		Stale: func(interface{}) bool { return false },
		Found: func(tag interface{}, blob []byte, h [32]byte) {},
	}
	cfg.transport = func(e *Engine) (transport, error) {
		if e.mem == nil { // the replay engine's staging: texts are written once, the simulated GPU only takes time
			e.mem = make([]byte, e.lay.Size)
			for j := 0; j < e.lay.Slots; j++ {
				tx := texts[j%len(texts)]
				copy(e.mem[e.lay.OffDatas+j*DStride:], tx)
				binary.LittleEndian.PutUint32(e.mem[e.lay.OffLens+4*j:], uint32(len(tx)))
			}
		}
		g = newSimGPU(us1, us2)
		return g, nil
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var staged, own atomic.Uint64
	var wg sync.WaitGroup
	stop := make(chan struct{})
	e.Start()
	c0, w0 := cpuNow(), time.Now()
	for w := 0; w < T; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			s := astropair.NewScratch()
			rng := rand.New(rand.NewSource(int64(w) + 1))
			var a, b [MsgLen]byte
			rng.Read(a[:])
			a[0] = a[0]&0xf0 | 1
			const window = 40 * time.Millisecond // miner.go throttle_window
			start := time.Now()
			throttle := func() {
				if cpuMax < 100 {
					if busy := time.Since(start); busy >= window {
						time.Sleep(busy * time.Duration(100-cpuMax) / time.Duration(cpuMax))
						start = time.Now()
					}
				}
			}
			for n := uint32(0); ; n += 2 {
				select {
				case <-stop:
					return
				default:
				}
				if k := e.TryWork(s); k > 0 {
					staged.Add(uint64(k))
					throttle()
					continue
				}
				a[40], a[41], a[42] = byte(n), byte(n>>8), byte(n>>16)
				b = a
				b[39] ^= 0x80
				astropair.Hash2(a[:], b[:], s)
				own.Add(2)
				throttle()
			}
		}(w)
	}
	time.Sleep(d)
	close(stop)
	wg.Wait()
	leg := simLeg{staged: staged.Load(), own: own.Load(), cpu: cpuNow() - c0, wall: time.Since(w0)}
	st := e.Stats()
	e.Close()
	leg.idle = st.IdleTries
	if g != nil {
		leg.gpuBusy = float64(g.busyNs.Load()) / float64(leg.wall)
	}
	return leg
}

func TestCPUMaxSimAB(t *testing.T) {
	if os.Getenv("GSPLIT_CPUMAX") != "1" {
		t.Skip("set GSPLIT_CPUMAX=1 (run under benchlock): --cpu-max duty A/B against a simulated co-binding GPU")
	}
	T := envInts("GSPLIT_SIM_T", "6")[0]
	S := envInts("GSPLIT_SIM_S", "10")[0]
	R := envInts("GSPLIT_SIM_R", "3")[0]
	duties := envInts("GSPLIT_SIM_DUTY", "90,100")
	geo := envInts("GSPLIT_SIM_GEOM", "1024,4")
	us := envInts("GSPLIT_SIM_US", "25,5") // per-hash GPU us for op 1 and op 2
	texts := overheadTexts(64)
	if p := os.Getenv("GSPLIT_SIM_MUTEX"); p != "" {
		runtime.SetMutexProfileFraction(1)
		defer func() {
			f, err := os.Create(p)
			if err == nil {
				pprof.Lookup("mutex").WriteTo(f, 0)
				f.Close()
			}
			runtime.SetMutexProfileFraction(0)
		}()
	}
	for r := 0; r < R; r++ {
		for _, duty := range duties {
			l := simDutyLeg(t, texts, T, duty, time.Duration(S)*time.Second, float64(us[0]), float64(us[1]), geo)
			ws := l.wall.Seconds()
			t.Logf("round %d duty %3d: staged %.0f/s own %.0f/s total %.0f/s | %.0f H/cpu-s (%.1f cores) | idle %d | simGPU busy %.3f",
				r, duty, float64(l.staged)/ws, float64(l.own)/ws, float64(l.staged+l.own)/ws,
				float64(l.staged+l.own)/l.cpu.Seconds(), l.cpu.Seconds()/ws, l.idle, l.gpuBusy)
		}
	}
}

// The simulated GPU itself must behave like a GPU queue (one command at a time, n x per-hash time, replies in
// order, no reply after close): a mechanism test, no timing assertions beyond "it took at least the modelled time".
func TestSimGPUQueue(t *testing.T) {
	g := newSimGPU(100, 10)
	t0 := time.Now()
	g.issue(1, 0, 20, 7)
	g.issue(2, 0, 20, 8)
	r1, r2 := <-g.replies(), <-g.replies()
	if r1.tag != 7 || r1.op != 1 || r2.tag != 8 || r2.op != 2 {
		t.Fatalf("replies out of order: %+v %+v", r1, r2)
	}
	if el := time.Since(t0); el < 2200*time.Microsecond {
		t.Fatalf("two commands took %v, want >= 2.2 ms of modelled GPU time", el)
	}
	if b := g.busyNs.Load(); b != int64(2200*time.Microsecond) {
		t.Fatalf("busy %d ns, want 2.2 ms", b)
	}
	g.close()
	g.close()
	if _, ok := <-g.replies(); ok {
		t.Fatal("reply channel still open after close")
	}
}
