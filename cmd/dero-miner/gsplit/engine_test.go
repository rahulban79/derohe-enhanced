package gsplit

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
	"github.com/deroproject/derohe/cmd/dero-miner/astropair"
	"github.com/deroproject/derohe/cmd/dero-miner/dsac"
)

func init() { astropair.SuffixSort = dsac.SuffixArray } // the native sort, as the miner installs it (behind verified_sort)

// softGPU is a software stand-in for gpu_split_server: op 1 runs the CPU reference stage 1 into the shared region,
// op 2 hashes the suffix arrays. Faults can be injected after the self-test.
type softGPU struct {
	e       *Engine
	ch      chan reply
	cmds    chan [4]uint32
	once    sync.Once
	mu      sync.Mutex // orders issue/kill sends against close
	closed  bool
	scr     *astropair.Scratch
	corrupt atomic.Int32 // 1: flip a text byte of every slot; 2: write length 0; 3: fail every command; 4: flip an op-2 hash;
	//                      5: op 3 writes a wrong suffix array; 6: op 3 fails (status 3); 7: no sort lanes (op 3 refused)
	failN  atomic.Int32 // fail the next failN commands (a transient watchdog kill), then work
	exit   atomic.Int32 // 1: the server "crashes" on the next command
	hold   atomic.Int32 // 1: op 1 waits for releaseHold (the GPU is busy: batches stay in flight)
	unhold chan struct{}
	unOnce sync.Once
	sorts  atomic.Int32 // op 3 commands received
}

func (g *softGPU) releaseHold() { g.unOnce.Do(func() { close(g.unhold) }) }

func newSoft(e *Engine) (*softGPU, error) {
	if e.mem == nil { // a respawned server reuses the shared region, like procTransport
		e.mem = make([]byte, e.lay.Size)
	}
	g := &softGPU{e: e, ch: make(chan reply, 64), cmds: make(chan [4]uint32, 64), scr: astropair.NewScratch(), unhold: make(chan struct{})}
	go g.loop()
	return g, nil
}

func (g *softGPU) loop() {
	for c := range g.cmds {
		if g.exit.Load() == 1 {
			close(g.ch)
			for range g.cmds {
			}
			return
		}
		op, first, n, tag := c[0], int(c[1]), int(c[2]), c[3]
		if op == 1 && g.hold.Load() == 1 {
			<-g.unhold
		}
		e := g.e
		st := uint32(0)
		if g.corrupt.Load() == 3 {
			st = 2
		}
		if g.failN.Load() > 0 {
			g.failN.Add(-1)
			st = 2
		}
		if op == 3 {
			switch g.corrupt.Load() {
			case 6:
				st = 3
			case 7:
				st = 1
			}
			g.sorts.Add(1)
		}
		for j := first; j < first+n && st == 0; j++ {
			switch op {
			case 3: // the GPU sort: same contract as the Metal sg_p0/sg_rounds kernels (texts read, suffix arrays written)
				l := e.dlen(j)
				sa := e.sa(j)
				if !astropair.SortOnly(e.text(j, l), sa) {
					st = 3
					break
				}
				if g.corrupt.Load() == 5 && l > 1 {
					sa[0], sa[1] = sa[1], sa[0]
				}
			case 1:
				o := e.lay.OffDatas + j*DStride
				l := astropair.Stage1Text(e.msg(j), e.mem[o:o+DStride], g.scr)
				switch g.corrupt.Load() {
				case 1:
					e.mem[o+l/2] ^= 0x40
				case 2:
					l = 0
				}
				binary.LittleEndian.PutUint32(e.mem[e.lay.OffLens+4*j:], uint32(l))
			case 2:
				l := e.dlen(j)
				sa := e.sa(j)[:l]
				h := sha256.Sum256(unsafe.Slice((*byte)(unsafe.Pointer(&sa[0])), 4*l))
				if g.corrupt.Load() == 4 {
					h[5] ^= 1
				}
				copy(e.mem[e.lay.OffOuts+32*j:], h[:])
			}
		}
		g.ch <- reply{status: st, us: 7, tag: tag, op: op}
	}
	close(g.ch)
}

func (g *softGPU) issue(op, first, n, tag uint32) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return errors.New("softGPU: closed")
	}
	g.cmds <- [4]uint32{op, first, n, tag}
	return nil
}
func (g *softGPU) replies() <-chan reply { return g.ch }
func (g *softGPU) kill() {
	g.exit.Store(1)
	go func() { // wake the loop so it notices
		g.mu.Lock()
		defer g.mu.Unlock()
		if !g.closed {
			select {
			case g.cmds <- [4]uint32{0, 0, 0, 0xfffffffe}:
			default:
			}
		}
	}()
}
func (g *softGPU) close() {
	g.once.Do(func() {
		g.mu.Lock()
		g.closed = true
		close(g.cmds)
		g.mu.Unlock()
	})
	for range g.ch {
	}
}

type found struct {
	blob [MsgLen]byte
	h    [32]byte
	tag  interface{}
}

type rig struct {
	e           *Engine
	g           *softGPU // the first server
	mu          sync.Mutex
	got         []found
	epoch       atomic.Int64
	gens        atomic.Int32  // servers started
	nextCorrupt atomic.Int32  // fault injected into every server started from now on
	failMk      atomic.Int32  // the next failMk server starts fail
	slowCPU     time.Duration // extra time per TryWork pair: a CPU slower than the GPU, so staged batches queue up
}

func newRig(t *testing.T, gpuSHA bool, batch, depth int, audit uint64) *rig {
	return newRigCfg(t, gpuSHA, batch, depth, audit, nil)
}

func newRigCfg(t *testing.T, gpuSHA bool, batch, depth int, audit uint64, mod func(*Config)) *rig {
	r := &rig{}
	var tpl [MsgLen]byte
	for i := range tpl {
		tpl[i] = byte(i*13 + 5)
	}
	tpl[0] = 0x41
	cfg := Config{Batch: batch, Depth: depth, Inflight: 2, GPUSHA: gpuSHA, GPUMax: 100, AuditEvery: audit,
		Next: func() (Work, bool) {
			w := Work{Blob: tpl, Tag: r.epoch.Load()}
			w.Blob[10] = byte(r.epoch.Load())
			return w, true
		},
		Stale: func(tag interface{}) bool { return tag.(int64) != r.epoch.Load() },
		Found: func(tag interface{}, blob []byte, h [32]byte) {
			var f found
			copy(f.blob[:], blob)
			f.h, f.tag = h, tag
			r.mu.Lock()
			r.got = append(r.got, f)
			r.mu.Unlock()
		},
		Logf:       t.Logf,
		RespawnMin: time.Millisecond, RespawnMax: 4 * time.Millisecond,
	}
	if mod != nil {
		mod(&cfg)
	}
	cfg.transport = func(e *Engine) (transport, error) {
		if r.failMk.Load() > 0 {
			r.failMk.Add(-1)
			return nil, errors.New("exec: server failed to start")
		}
		g, err := newSoft(e)
		g.corrupt.Store(r.nextCorrupt.Load())
		if r.gens.Add(1) == 1 {
			r.g = g
		}
		return g, err
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.e = e
	return r
}

func (r *rig) ngot() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

// mine runs T CPU threads on TryWork until want hashes were produced (or the engine stops producing).
func (r *rig) mine(T, want int) int {
	var total atomic.Int64
	var wg sync.WaitGroup
	deadline := time.Now().Add(60 * time.Second)
	for w := 0; w < T; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := astropair.NewScratch()
			idle := 0
			for total.Load() < int64(want) && time.Now().Before(deadline) {
				if k := r.e.TryWork(s); k > 0 {
					total.Add(int64(k))
					idle = 0
					time.Sleep(r.slowCPU)
					continue
				}
				if r.e.Disabled() {
					if idle++; idle > 200 {
						return
					}
				}
				time.Sleep(200 * time.Microsecond)
			}
		}()
	}
	wg.Wait()
	return int(total.Load())
}

func TestLayout(t *testing.T) {
	for _, sha := range []bool{false, true} {
		l := NewLayout(4096, sha)
		regs := [][2]int{{l.OffMsgs, 4096 * MsgLen}, {l.OffLens, 4096 * 4}, {l.OffOuts, 4096 * 32}, {l.OffDatas, 4096 * DStride}}
		if sha {
			regs = append(regs, [2]int{l.OffSas, 4096 * SStride * 4})
		}
		end := 0
		for i, r := range regs {
			if r[0]%align != 0 || r[0] < end {
				t.Fatalf("sha=%v region %d at %d overlaps or is unaligned (prev end %d)", sha, i, r[0], end)
			}
			end = r[0] + r[1]
		}
		if l.Size < end || l.Size%align != 0 {
			t.Fatalf("sha=%v size %d < end %d or unaligned", sha, l.Size, end)
		}
	}
	if DStride < 273*256+1023 || SStride < 273*256+1023 || MaxText > DStride {
		t.Fatal("slot strides below the longest stage-1 text")
	}
	if _, err := New(Config{Batch: 3, Depth: 2, Inflight: 1}); err == nil {
		t.Fatal("odd batch accepted")
	}
}

func TestSelfTestBitExact(t *testing.T) {
	for _, sha := range []bool{false, true} {
		r := newRig(t, sha, 32, 2, 0)
		if err := r.e.SelfTest(32, astropair.NewScratch()); err != nil {
			t.Fatalf("gpuSHA=%v: %v", sha, err)
		}
		r.e.Close()
	}
}

// Mutations: a GPU that corrupts one byte of a text, reports a bad length, fails, or corrupts the GPU SHA must fail
// the self-test.
func TestSelfTestRejectsFaultyGPU(t *testing.T) {
	cases := []struct {
		sha   bool
		fault int32
	}{{false, 1}, {true, 1}, {false, 2}, {true, 3}, {true, 4}}
	for _, c := range cases {
		r := newRig(t, c.sha, 16, 2, 0)
		r.g.corrupt.Store(c.fault)
		if err := r.e.SelfTest(16, astropair.NewScratch()); err == nil {
			t.Fatalf("gpuSHA=%v fault=%d: self-test passed a faulty GPU", c.sha, c.fault)
		} else {
			t.Logf("gpuSHA=%v fault=%d rejected: %v", c.sha, c.fault, err)
		}
		r.e.Close()
	}
}

// Every hash the engine reports, in both modes and with several threads racing over a small ring (so batches are
// reused many times), equals astrobwtv3.AstroBWTv3 of the reported blob, and no nonce is reported twice.
func TestMiningBitExact(t *testing.T) {
	for _, sha := range []bool{false, true} {
		r := newRig(t, sha, 8, 3, 0)
		r.e.Start()
		n := r.mine(4, 120)
		r.e.Close()
		if n < 120 {
			t.Fatalf("gpuSHA=%v: only %d hashes", sha, n)
		}
		seen := map[[MsgLen]byte]bool{}
		for _, f := range r.got {
			if seen[f.blob] {
				t.Fatalf("gpuSHA=%v: nonce reported twice", sha)
			}
			seen[f.blob] = true
			if want := astrobwtv3.AstroBWTv3(f.blob[:]); want != f.h {
				t.Fatalf("gpuSHA=%v: hash mismatch %x vs %x", sha, f.h[:8], want[:8])
			}
		}
		st := r.e.Stats()
		if st.Batches < 10 || st.Disabled != "" {
			t.Fatalf("gpuSHA=%v: ring did not turn over (%+v)", sha, st)
		}
		t.Logf("gpuSHA=%v: %d hashes reported, %+v", sha, len(r.got), st)
	}
}

// A job change makes the rest of the staged batches worthless: they are dropped, never reported, and mining
// continues on the new job.
func TestStaleBatchesDropped(t *testing.T) {
	for _, sha := range []bool{false, true} {
		r := newRig(t, sha, 16, 4, 0)
		r.e.Start()
		time.Sleep(300 * time.Millisecond) // let the ring fill with epoch-0 texts
		r.epoch.Store(1)
		r.mine(2, 96)
		r.e.Close()
		st := r.e.Stats()
		if st.Dropped == 0 {
			t.Fatalf("gpuSHA=%v: nothing dropped after the job change (%+v)", sha, st)
		}
		for _, f := range r.got {
			if f.tag.(int64) != 1 {
				t.Fatalf("gpuSHA=%v: a stale (epoch 0) hash was reported", sha)
			}
		}
		t.Logf("gpuSHA=%v: %+v", sha, st)
	}
}

// After the self-test passed, a GPU that starts producing wrong texts (or wrong GPU SHAs) is caught by the audit
// and the engine disables itself; a bad length disables it at once and that hash is still computed correctly.
func TestRuntimeFaultsDisable(t *testing.T) {
	cases := []struct {
		name  string
		sha   bool
		fault int32
		audit uint64
	}{{"text-cpusha", false, 1, 4}, {"text-gpusha", true, 1, 0}, {"sha-gpusha", true, 4, 0}, {"len0", false, 2, 0}}
	for _, c := range cases {
		r := newRig(t, c.sha, 8, 3, c.audit)
		if err := r.e.SelfTest(8, astropair.NewScratch()); err != nil {
			t.Fatal(err)
		}
		r.g.corrupt.Store(c.fault)
		r.nextCorrupt.Store(c.fault) // a persistent fault: the restarted server is faulty too, so its self-test disables
		r.e.Start()
		r.mine(2, 400)
		deadline := time.Now().Add(10 * time.Second)
		for !r.e.Disabled() && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		r.e.Close()
		st := r.e.Stats()
		if st.Disabled == "" {
			t.Fatalf("%s: engine still enabled (%+v)", c.name, st)
		}
		if c.fault == 2 {
			for _, f := range r.got {
				if want := astrobwtv3.AstroBWTv3(f.blob[:]); want != f.h {
					t.Fatalf("%s: a bad-length slot was reported with a wrong hash", c.name)
				}
			}
		}
		t.Logf("%s: disabled: %s", c.name, st.Disabled)
	}
}

// A transient audit difference (r19: the live r18 miner disabled split mode for good after one difference in 15,830
// audits) restarts the server; the clean server passes the self-test and mining continues bit-exact.
func TestTransientAuditFaultRespawns(t *testing.T) {
	cases := []struct {
		name  string
		sha   bool
		fault int32
		audit uint64
	}{{"text-cpusha", false, 1, 4}, {"text-gpusha", true, 1, 0}, {"sha-gpusha", true, 4, 0}}
	for _, c := range cases {
		r := newRig(t, c.sha, 8, 3, c.audit)
		if err := r.e.SelfTest(8, astropair.NewScratch()); err != nil {
			t.Fatal(err)
		}
		r.g.corrupt.Store(c.fault) // only the running server is faulty
		r.e.Start()
		if !waitFor(func() bool { return r.e.Stats().Restarts >= 1 }, 10*time.Second) {
			r.mine(2, 64)
		}
		if !waitFor(func() bool { return r.e.Stats().Restarts >= 1 }, 10*time.Second) {
			t.Fatalf("%s: no restart after an audit difference: %+v", c.name, r.e.Stats())
		}
		before := r.ngot() // locked: the reply loop appends to r.got while the engine runs (r20: -race caught it)
		n := r.mine(2, 64)
		r.e.Close()
		st := r.e.Stats()
		if st.Disabled != "" || st.AuditFaults < 1 || n < 64 {
			t.Fatalf("%s: engine disabled or no audit fault counted (n=%d): %+v", c.name, n, st)
		}
		for _, f := range r.got[before:] {
			if want := astrobwtv3.AstroBWTv3(f.blob[:]); want != f.h {
				t.Fatalf("%s: hash mismatch after the restart", c.name)
			}
		}
		t.Logf("%s: %+v", c.name, st)
	}
}

type killCounter struct{ n atomic.Int32 }

func (k *killCounter) issue(op, first, n, tag uint32) error { return nil }
func (k *killCounter) replies() <-chan reply                { return nil }
func (k *killCounter) close()                               {}
func (k *killCounter) kill()                                { k.n.Add(1) }

func TestAuditFaultStrikes(t *testing.T) {
	e := &Engine{cfg: Config{AuditStrikes: 3, AuditStrikeWindow: time.Hour, Logf: t.Logf}}
	k := &killCounter{}
	e.live.Store(transport(k))
	now := time.Now()
	e.auditFault("audit: a", now.Add(-2*time.Hour), 1) // outside the window by the time of the next ones
	e.auditFault("audit: b", now, 2)
	e.auditFault("audit: b-same-server", now, 2) // queued hashes of the struck server: counted, no new strike
	if e.Disabled() || k.n.Load() != 2 {         // a (then alone in its window) and b each restarted the server
		t.Fatalf("one strike in the window must restart, not disable")
	}
	e.auditFault("audit: c", now.Add(time.Minute), 3)
	if e.Disabled() || k.n.Load() != 3 {
		t.Fatalf("two strikes in the window must restart, not disable")
	}
	e.auditFault("audit: d", now.Add(2*time.Minute), 4)
	if !e.Disabled() || !strings.Contains(e.Stats().Disabled, "3 audit differences") {
		t.Fatalf("three strikes in the window must disable: %+v", e.Stats())
	}
	if e.Stats().AuditFaults != 5 {
		t.Fatalf("audit faults counted %d, want 5", e.Stats().AuditFaults)
	}
}

// Transient GPU command failures (the macOS watchdog) are retried and mining stays bit-exact; the engine stays on.
func TestTransientGPUFailuresRetried(t *testing.T) {
	for _, sha := range []bool{false, true} {
		r := newRig(t, sha, 8, 3, 0)
		r.g.failN.Store(5)
		r.e.Start()
		n := r.mine(2, 64)
		r.e.Close()
		st := r.e.Stats()
		if n < 64 || st.Disabled != "" || st.GPURetries != 5 {
			t.Fatalf("gpuSHA=%v: n=%d %+v", sha, n, st)
		}
		for _, f := range r.got {
			if want := astrobwtv3.AstroBWTv3(f.blob[:]); want != f.h {
				t.Fatalf("gpuSHA=%v: mismatch after retries", sha)
			}
		}
	}
}

func waitFor(cond func() bool, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
	return true
}

func checkBitExact(t *testing.T, r *rig) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range r.got {
		if want := astrobwtv3.AstroBWTv3(f.blob[:]); want != f.h {
			t.Fatalf("hash mismatch %x vs %x", f.h[:8], want[:8])
		}
	}
}

// Fix F (r18 merge): a server that exits (EOF: the macOS GPU watchdog under contention) is reaped, relaunched after a
// back-off and re-self-tested; staging resumes and the engine is never disabled for a transport failure.
func TestServerExitRespawns(t *testing.T) {
	for _, sha := range []bool{false, true} {
		r := newRig(t, sha, 8, 2, 0)
		r.e.Start()
		if n := r.mine(1, 16); n < 16 {
			t.Fatalf("gpuSHA=%v: no work before the crash", sha)
		}
		r.g.kill() // exit and wake the loop: a bare exit flag waits for a next command that may never come (flaky)
		if !waitFor(func() bool { return r.e.Stats().Restarts >= 1 && r.gens.Load() >= 2 && r.e.paused.Load() == 0 }, 10*time.Second) {
			t.Fatalf("gpuSHA=%v: server not respawned (%+v)", sha, r.e.Stats())
		}
		r.mu.Lock()
		before := len(r.got)
		r.mu.Unlock()
		if n := r.mine(2, 64); n < 64 {
			t.Fatalf("gpuSHA=%v: only %d hashes after the respawn (%+v)", sha, n, r.e.Stats())
		}
		r.mu.Lock()
		after := len(r.got)
		r.mu.Unlock()
		st := r.e.Stats()
		r.e.Close()
		if st.Disabled != "" || after <= before {
			t.Fatalf("gpuSHA=%v: disabled or idle after a server exit: %+v", sha, st)
		}
		checkBitExact(t, r)
	}
}

// MaxGPUFailures failed commands in a row restart the server instead of disabling the engine.
func TestPersistentCommandFailuresRespawn(t *testing.T) {
	r := newRig(t, true, 8, 3, 0)
	r.e.Start()
	r.g.corrupt.Store(3) // the first server now fails every command
	if !waitFor(func() bool { return r.e.Stats().Restarts >= 1 && r.e.paused.Load() == 0 }, 15*time.Second) {
		t.Fatalf("no respawn after persistent command failures: %+v", r.e.Stats())
	}
	if n := r.mine(2, 64); n < 64 {
		t.Fatalf("only %d hashes after the respawn", n)
	}
	st := r.e.Stats()
	r.e.Close()
	if st.Disabled != "" {
		t.Fatalf("disabled on a transport failure: %+v", st)
	}
	checkBitExact(t, r)
}

// A server that cannot be started is retried with back-off, never given up on.
func TestRespawnRetriesFailedStarts(t *testing.T) {
	r := newRig(t, false, 8, 2, 0)
	r.e.Start()
	r.mine(1, 8)
	r.failMk.Store(3)
	r.g.kill() // exit and wake the loop: a bare exit flag waits for a next command that may never come (flaky)
	if !waitFor(func() bool { return r.gens.Load() >= 2 && r.e.paused.Load() == 0 }, 10*time.Second) {
		t.Fatalf("not restarted after failed starts: %+v", r.e.Stats())
	}
	st := r.e.Stats()
	if st.Restarts < 4 || st.Disabled != "" {
		t.Fatalf("want >= 4 restart attempts and enabled: %+v", st)
	}
	if n := r.mine(1, 16); n < 16 {
		t.Fatalf("no work after the restart")
	}
	r.e.Close()
	checkBitExact(t, r)
}

// A respawned server whose self-test is not bit-exact disables the engine for good (wrong results, not transport).
func TestRespawnSelfTestMismatchDisables(t *testing.T) {
	r := newRig(t, false, 8, 2, 0)
	r.e.Start()
	r.mine(1, 8)
	r.nextCorrupt.Store(1) // every new server corrupts its texts
	r.g.kill()             // exit and wake the loop: a bare exit flag waits for a next command that may never come (flaky)
	if !waitFor(r.e.Disabled, 10*time.Second) {
		t.Fatalf("engine still enabled after a non-bit-exact respawn: %+v", r.e.Stats())
	}
	st := r.e.Stats()
	if !strings.Contains(st.Disabled, "self-test after a server restart") || st.Restarts != 1 {
		t.Fatalf("wrong disable reason / restarts: %+v", st)
	}
	if k := r.e.TryWork(astropair.NewScratch()); k != 0 {
		t.Fatal("TryWork produced work after disable")
	}
	r.e.Close()
	checkBitExact(t, r)
}

func TestRespawnBackoff(t *testing.T) {
	e := &Engine{cfg: Config{RespawnMin: time.Second, RespawnMax: 60 * time.Second, HealthyReset: 5 * time.Minute}, backoff: time.Second}
	now := time.Now()
	e.lastStart = now
	var got []time.Duration
	for i := 0; i < 9; i++ {
		got = append(got, e.nextBackoff(now))
	}
	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60, 60}
	for i := range want {
		if got[i] != want[i]*time.Second {
			t.Fatalf("back-off sequence %v", got)
		}
	}
	e.lastStart = now.Add(-6 * time.Minute) // the restarted server then ran healthily for 6 minutes
	if d := e.nextBackoff(now); d != time.Second {
		t.Fatalf("back-off not reset after a healthy period: %s", d)
	}
	if d := e.nextBackoff(now); d != 2*time.Second {
		t.Fatalf("back-off did not grow again within one outage: %s", d)
	}
}

// ---- the real Metal server (skipped unless gpu-miner-poc/gpu_split_server is built) ----

func realBin(t *testing.T) string {
	if runtime.GOOS != "darwin" {
		t.Skip("Metal only")
	}
	if os.Getenv("GSPLIT_REAL") != "1" { // never touch the GPU from a routine/pipeline run on the live mining box
		t.Skip("set GSPLIT_REAL=1 to run against the real Metal server")
	}
	b, _ := filepath.Abs("../../../gpu-miner-poc/gpu_split_server")
	if o := os.Getenv("GSPLIT_BIN"); o != "" { // a freshly built server (the committed binary may predate op 3)
		b = o
	}
	if _, err := os.Stat(b); err != nil {
		t.Skip("gpu_split_server not built")
	}
	return b
}

func TestRealGPUBitExact(t *testing.T) {
	bin := realBin(t)
	for _, sha := range []bool{false, true} {
		var mu sync.Mutex
		var got []found
		var tpl [MsgLen]byte
		for i := range tpl {
			tpl[i] = byte(i*29 + 3)
		}
		tpl[0] = 0x41
		e, err := New(Config{Bin: bin, Batch: 256, Depth: 3, Inflight: 3, GPUSHA: sha, GPUMax: 100, AuditEvery: 64,
			Next: func() (Work, bool) { return Work{Blob: tpl, Tag: 0}, true },
			Found: func(tag interface{}, blob []byte, h [32]byte) {
				var f found
				copy(f.blob[:], blob)
				f.h = h
				mu.Lock()
				got = append(got, f)
				mu.Unlock()
			}, Logf: t.Logf})
		if err != nil {
			t.Fatal(err)
		}
		if err := e.SelfTest(256, astropair.NewScratch()); err != nil {
			e.Close()
			t.Fatalf("gpuSHA=%v: %v", sha, err)
		}
		r := &rig{e: e}
		e.Start()
		n := r.mine(4, 2048)
		time.Sleep(200 * time.Millisecond)
		e.Close()
		mu.Lock()
		for _, f := range got {
			if want := astrobwtv3.AstroBWTv3(f.blob[:]); want != f.h {
				t.Fatalf("gpuSHA=%v: real GPU hash mismatch", sha)
			}
		}
		t.Logf("gpuSHA=%v: %d produced, %d reported and verified against AstroBWTv3, %+v", sha, n, len(got), e.Stats())
		if len(got) < 1024 || e.Stats().Disabled != "" {
			t.Fatalf("gpuSHA=%v: too few verified hashes or disabled", sha)
		}
		mu.Unlock()
	}
}

// r19 gpusort-5: a fully claimed batch that the feeder re-stages may still be some thread's e.cur; its slots must not
// become claimable until stage 1 finished (makeReady).
func TestRestagedBatchNotClaimableUntilReady(t *testing.T) {
	r := newRig(t, true, 4, 2, 0)
	e := r.e
	defer e.Close()
	b := e.batches[0]
	b.next.Store(int64(b.n)) // fully claimed and finished
	atomic.StorePointer(&e.cur, unsafe.Pointer(b))
	e.prepare(b, 1) // the feeder re-stages it; its stage 1 is now running on the GPU
	if k := e.TryWork(astropair.NewScratch()); k != 0 || b.done.Load() != 0 {
		t.Fatalf("claimed %d hashes from a batch whose stage 1 has not finished", k)
	}
	if e.ready != nil || atomic.LoadPointer(&e.cur) != nil {
		t.Fatal("a re-staged batch was published before its texts were ready")
	}
}

// r19 splitcpu-2 regime signal: TryWork on an empty ring counts an idle try; a feeder facing a full ring accumulates
// blocked time.
func TestRegimeCounters(t *testing.T) {
	r := newRig(t, true, 4, 2, 0)
	e := r.e
	defer e.Close()
	s := astropair.NewScratch()
	if k := e.TryWork(s); k != 0 { // not started: nothing staged
		t.Fatalf("TryWork on an empty ring returned %d", k)
	}
	if st := e.Stats(); st.IdleTries != 1 {
		t.Fatalf("IdleTries = %d after one empty TryWork, want 1", st.IdleTries)
	}
	e.Start()
	// nobody claims: both batches get staged, the feeder then blocks on the full ring until we drain it
	if !waitFor(func() bool { e.mu.Lock(); defer e.mu.Unlock(); return len(e.ready) == 2 }, 10*time.Second) {
		t.Fatal("ring never filled")
	}
	time.Sleep(30 * time.Millisecond)
	if n := r.mine(1, 32); n < 32 {
		t.Fatalf("mined %d", n)
	}
	if !waitFor(func() bool { return e.Stats().FeedWaitUs >= 20000 }, 10*time.Second) {
		t.Fatalf("FeedWaitUs = %d after the feeder waited >= 30 ms on a full ring", e.Stats().FeedWaitUs)
	}
}

// r20 cpuminer: a full ring is not a CPU-bound regime by itself. While every batch is on the GPU (op 1 held) the feeder
// waits with no CPU backlog and FeedWaitBacklogUs stays 0; once the batches are staged and nobody claims them, the
// same wait is CPU-bound and FeedWaitBacklogUs grows.
func TestRegimeBacklogSplit(t *testing.T) {
	r := newRig(t, true, 4, 2, 0)
	e := r.e
	defer e.Close()
	defer r.g.releaseHold()
	r.g.hold.Store(1)
	e.Start()
	// both batches are issued and held on the "GPU": the ring is empty, the feeder blocks, nothing is staged
	if !waitFor(func() bool { return len(e.free) == 0 }, 10*time.Second) {
		t.Fatal("feeder never took both batches")
	}
	time.Sleep(10 * FeedSample)
	if st := e.Stats(); st.FeedWaitBacklogUs != 0 {
		t.Fatalf("FeedWaitBacklogUs = %d while every batch was on the GPU, want 0", st.FeedWaitBacklogUs)
	}
	if e.cpuBacklog() {
		t.Fatal("cpuBacklog true with nothing staged")
	}
	r.g.releaseHold()
	if !waitFor(func() bool { e.mu.Lock(); defer e.mu.Unlock(); return len(e.ready) == 2 }, 10*time.Second) {
		t.Fatal("ring never filled")
	}
	if !e.cpuBacklog() {
		t.Fatal("cpuBacklog false with two staged batches")
	}
	if !waitFor(func() bool { return e.Stats().FeedWaitBacklogUs >= uint64(4*FeedSample/time.Microsecond) }, 10*time.Second) {
		t.Fatalf("FeedWaitBacklogUs = %d with two staged batches unclaimed", e.Stats().FeedWaitBacklogUs)
	}
	if n := r.mine(1, 32); n < 32 {
		t.Fatalf("mined %d", n)
	}
}

// r20 cpuminer: unclaimed indices in the current batch are a CPU backlog too (the ready queue can be empty while the
// threads are still working through e.cur).
func TestCPUBacklogCurrentBatch(t *testing.T) {
	r := newRig(t, true, 4, 2, 0)
	e := r.e
	defer e.Close()
	b := e.batches[0]
	b.next.Store(int64(b.n))
	atomic.StorePointer(&e.cur, unsafe.Pointer(b))
	if e.cpuBacklog() {
		t.Fatal("cpuBacklog true for a fully claimed current batch")
	}
	b.next.Store(2)
	if !e.cpuBacklog() {
		t.Fatal("cpuBacklog false with unclaimed indices in the current batch")
	}
	b.next.Store(int64(b.n))
	atomic.StorePointer(&e.cur, nil)
}

// ---- GPU sort (op 3; r19 design, ported in r21) ----

func sortRig(t *testing.T, batch, depth int) *rig {
	return newRigCfg(t, true, batch, depth, 0, func(c *Config) { c.GPUSort = true })
}

// The self-test sorts half of its slots on the GPU; a correct GPU sort leaves it on.
func TestSelfTestGPUSort(t *testing.T) {
	r := sortRig(t, 16, 4)
	if err := r.e.SelfTest(16, astropair.NewScratch()); err != nil {
		t.Fatal(err)
	}
	if !r.e.Sorting() || r.g.sorts.Load() != 1 {
		t.Fatalf("GPU sort not exercised/on after a good self-test: sorting=%v sorts=%d %+v", r.e.Sorting(), r.g.sorts.Load(), r.e.Stats())
	}
	r.e.Close()
}

// A wrong GPU sort fails only the GPU-sorted half: the GPU sort turns off, split staging (CPU sort) stays usable; a
// server without sort lanes (op 3 refused) does the same.
func TestSelfTestGPUSortFaultsTurnSortOff(t *testing.T) {
	for _, fault := range []int32{5, 6, 7} {
		r := sortRig(t, 16, 4)
		r.g.corrupt.Store(fault)
		if err := r.e.SelfTest(16, astropair.NewScratch()); err != nil {
			t.Fatalf("fault %d: the whole engine failed instead of only the sort: %v", fault, err)
		}
		st := r.e.Stats()
		if r.e.Sorting() || st.SortOff == "" || r.e.Disabled() {
			t.Fatalf("fault %d: sorting=%v %+v", fault, r.e.Sorting(), st)
		}
		if fault == 5 && !strings.Contains(st.SortOff, "MISMATCH") {
			t.Fatalf("wrong reason: %s", st.SortOff)
		}
		t.Logf("fault %d: %s", fault, st.SortOff)
		r.g.corrupt.Store(0)
		r.e.Start()
		if n := r.mine(2, 64); n < 64 {
			t.Fatalf("fault %d: CPU-sort staging did not continue (%d)", fault, n)
		}
		r.e.Close()
		checkBitExact(t, r)
	}
}

// Mining with the GPU sort: some batches are GPU-sorted, every reported hash is bit-exact, no nonce twice.
func TestMiningGPUSortBitExact(t *testing.T) {
	r := sortRig(t, 8, 5)
	r.slowCPU = 20 * time.Millisecond // slower than the soft GPU even under -race
	if err := r.e.SelfTest(8, astropair.NewScratch()); err != nil {
		t.Fatal(err)
	}
	r.e.Start()
	n := r.mine(2, 160)
	r.e.Close()
	st := r.e.Stats()
	if n < 160 || st.GPUSorted == 0 || st.Disabled != "" || st.SortOff != "" {
		t.Fatalf("n=%d %+v", n, st)
	}
	seen := map[[MsgLen]byte]bool{}
	for _, f := range r.got {
		if seen[f.blob] {
			t.Fatal("nonce reported twice")
		}
		seen[f.blob] = true
	}
	checkBitExact(t, r)
	if uint64(len(r.got)) < st.GPUSorted {
		t.Fatalf("GPU-sorted hashes not all reported: got %d sorted %d", len(r.got), st.GPUSorted)
	}
	t.Logf("%d reported, %+v", len(r.got), st)
}

// A failing op 3 (watchdog) hands the batch to the CPU threads: nothing lost, nothing wrong, the sort stays on.
func TestGPUSortFailureFallsBackToCPU(t *testing.T) {
	r := sortRig(t, 8, 5)
	if err := r.e.SelfTest(8, astropair.NewScratch()); err != nil {
		t.Fatal(err)
	}
	r.slowCPU = 20 * time.Millisecond // slower than the soft GPU even under -race
	r.g.corrupt.Store(6)
	r.e.Start()
	n := r.mine(2, 100)
	r.e.Close()
	st := r.e.Stats()
	if n < 100 || st.SortFails == 0 || st.GPUSorted != 0 || st.Dropped != 0 || st.Disabled != "" || st.SortOff != "" { // nothing may be lost
		t.Fatalf("n=%d %+v", n, st)
	}
	checkBitExact(t, r)
}

// A GPU sort that goes wrong after the self-test is caught by the per-batch audit: the GPU sort turns off, staging
// with the CPU sort continues and the engine stays enabled.
func TestGPUSortRuntimeMismatchDisablesSort(t *testing.T) {
	r := sortRig(t, 8, 5)
	if err := r.e.SelfTest(8, astropair.NewScratch()); err != nil {
		t.Fatal(err)
	}
	r.slowCPU = 20 * time.Millisecond // slower than the soft GPU even under -race
	r.g.corrupt.Store(5)
	r.e.Start()
	r.mine(2, 200)
	if !waitFor(func() bool { return !r.e.Sorting() }, 10*time.Second) {
		t.Fatalf("GPU sort still on after wrong sorts: %+v", r.e.Stats())
	}
	r.g.corrupt.Store(0)
	r.slowCPU = 0
	r.mu.Lock()
	before := len(r.got)
	r.mu.Unlock()
	if n := r.mine(2, 64); n < 64 {
		t.Fatalf("staging stopped after the sort was turned off")
	}
	st := r.e.Stats()
	r.e.Close()
	if st.Disabled != "" || !strings.Contains(st.SortOff, "audit") {
		t.Fatalf("%+v", st)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range r.got[before:] {
		if want := astrobwtv3.AstroBWTv3(f.blob[:]); want != f.h {
			t.Fatal("a wrong hash after the GPU sort was turned off")
		}
	}
}

// divert: never while the CPU threads have fewer than SortMinReady staged batches waiting, never above SortInflight,
// never for a batch with an out-of-range GPU text length.
func TestDivertKeepsCPUFed(t *testing.T) {
	r := newRigCfg(t, true, 4, 6, 0, func(c *Config) { c.GPUSort = true; c.SortMinReady = 2; c.SortInflight = 1 })
	e := r.e
	defer e.Close()
	b, other := e.batches[0], e.batches[1]
	for j := 0; j < e.lay.Slots; j++ {
		binary.LittleEndian.PutUint32(e.mem[e.lay.OffLens+4*j:], 1000)
	}
	if e.divert(b) {
		t.Fatal("diverted with no staged batch waiting for the CPU")
	}
	e.ready = []*batch{other}
	if e.divert(b) {
		t.Fatal("diverted with 1 < SortMinReady=2 waiting")
	}
	e.ready = []*batch{other, e.batches[2]}
	binary.LittleEndian.PutUint32(e.mem[e.lay.OffLens+4*(b.first+3):], MaxText+1)
	if e.divert(b) {
		t.Fatal("diverted a batch with an out-of-range text length")
	}
	binary.LittleEndian.PutUint32(e.mem[e.lay.OffLens+4*(b.first+3):], 1000)
	if !e.divert(b) || !b.sorted || e.sortInflight.Load() != 1 {
		t.Fatal("not diverted although the CPU is fed")
	}
	if e.divert(e.batches[3]) {
		t.Fatal("diverted above SortInflight")
	}
	e.SortDisable("test")
	e.sortInflight.Store(0)
	if e.divert(e.batches[3]) {
		t.Fatal("diverted with the sort off")
	}
	e.ready = nil
}

// GPUSort without the GPU SHA, or with a ring too small to keep the CPU fed, is refused at New (sort off, engine on).
func TestGPUSortConfigGuards(t *testing.T) {
	r := newRigCfg(t, false, 8, 5, 0, func(c *Config) { c.GPUSort = true })
	if r.e.Sorting() {
		t.Fatal("GPU sort on without the suffix-array region")
	}
	r.e.Close()
	r = newRigCfg(t, true, 8, 3, 0, func(c *Config) { c.GPUSort = true })
	if r.e.Sorting() {
		t.Fatal("GPU sort on with depth 3 (< inflight 1 + min ready 1 + 2)")
	}
	r.e.Close()
}

// TestRealGPUSortOnly drives ONLY op 3 of the real Metal server (no op 1 / op 2, whose single-thread-per-hash command
// buffers last tens of ms): stage-1 texts are computed on the CPU (astropair.Stage1Text, the k_s1tg reference), the GPU
// sorts them into the suffix-array slots in short resumable command buffers, and every suffix array is hashed on the
// CPU and compared with astrobwtv3.AstroBWTv3 of its input. GSPLIT_SORT_N texts (default 2048); GSPLIT_SORT_SECS > 0
// then repeats op 3 over all slots for that long and reports the sort throughput (re-verifying the last pass).
// GSPLIT_SORT_LANES / GSPLIT_SORT_CHUNK set the server's sort geometry.
func TestRealGPUSortOnly(t *testing.T) {
	bin := realBin(t)
	N := envInts("GSPLIT_SORT_N", "2048")[0] &^ 7
	secs := envInts("GSPLIT_SORT_SECS", "0")[0]
	lanes := envInts("GSPLIT_SORT_LANES", "2")[0]
	chunk := envInts("GSPLIT_SORT_CHUNK", "32")[0]
	e, err := New(Config{Bin: bin, Batch: N / 4, Depth: 4, Inflight: 1, GPUSHA: true, GPUSort: true, SortLanes: lanes, SortChunk: chunk,
		SortMinReady: 1, SortInflight: 1, GPUMax: 100,
		Next: func() (Work, bool) { return Work{}, false }, Found: func(interface{}, []byte, [32]byte) {}, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if !e.Sorting() {
		t.Fatalf("sort off: %+v", e.Stats())
	}
	rng := rand.New(rand.NewSource(19))
	for j := 0; j < N; j++ {
		m := e.msg(j)
		rng.Read(m)
		m[0] = m[0]&0xf0 | 1 // version 1, as mining requires
	}
	ref := make([][32]byte, N)
	var wg sync.WaitGroup
	for w := 0; w < 6; w++ { // <= 6 CPU threads (live-box rule): stage 1 into the text slots + the reference hash
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			s := astropair.NewScratch()
			for j := w; j < N; j += 6 {
				m := e.msg(j)
				o := e.lay.OffDatas + j*DStride
				l := astropair.Stage1Text(m, e.mem[o:o+DStride], s)
				binary.LittleEndian.PutUint32(e.mem[e.lay.OffLens+4*j:], uint32(l))
				ref[j] = astrobwtv3.AstroBWTv3(m)
			}
		}(w)
	}
	wg.Wait()
	verify := func(pass string) {
		bad := 0
		for j := 0; j < N; j++ {
			l := e.dlen(j)
			sa := e.sa(j)[:l]
			if h := sha256.Sum256(unsafe.Slice((*byte)(unsafe.Pointer(&sa[0])), 4*l)); h != ref[j] {
				if bad < 3 {
					t.Errorf("%s: slot %d (n=%d) GPU-sorted hash %x != AstroBWTv3 %x", pass, j, l, h[:8], ref[j][:8])
				}
				bad++
			}
		}
		t.Logf("%s: %d/%d GPU-sorted hashes bit-exact vs astrobwtv3.AstroBWTv3", pass, N-bad, N)
		if bad != 0 {
			t.FailNow()
		}
	}
	for j := 0; j < N; j++ { // poison the suffix-array slots so a skipped sort cannot pass
		sa := e.sa(j)
		for i := range sa[:e.dlen(j)] {
			sa[i] = -1
		}
	}
	t0 := time.Now()
	if err := e.syncCmd1(3, 0, N); err != nil {
		t.Fatal(err)
	}
	t.Logf("first pass: %d texts in %s wall", N, time.Since(t0))
	verify("pass 1")
	if secs <= 0 {
		return
	}
	var texts, gpuUs uint64
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	t0 = time.Now()
	for time.Now().Before(deadline) {
		if err := e.tr.issue(3, 0, uint32(N), 7); err != nil {
			t.Fatal(err)
		}
		r, ok := <-e.tr.replies()
		if !ok || r.status != 0 || r.op != 3 {
			t.Fatalf("op 3 failed: %+v ok=%v", r, ok)
		}
		texts += uint64(N)
		gpuUs += uint64(r.us)
	}
	wall := time.Since(t0).Seconds()
	t.Logf("throughput: %d texts in %.1f s wall = %.0f SA/s (sum of command-buffer GPU time %.1f s = %.0f SA/s per GPU-second)",
		texts, wall, float64(texts)/wall, float64(gpuUs)/1e6, float64(texts)/(float64(gpuUs)/1e6))
	verify("last pass")
}

// A GPU-sorted batch whose job went stale while it was being sorted is dropped, never hashed or reported.
func TestGPUSortStaleDropped(t *testing.T) {
	r := sortRig(t, 8, 5)
	e := r.e
	defer e.Close()
	b := e.batches[0]
	b.work = Work{Tag: int64(0)}
	b.sorted = true
	e.sortInflight.Store(1)
	r.epoch.Store(1) // the job moved on during the sort
	e.sortDone(b, reply{status: 0, us: 5, tag: b.id, op: 3})
	st := e.Stats()
	if st.Dropped != uint64(b.n) || st.GPUSorted != 0 || b.done.Load() != int64(b.n) || len(e.free) != 1 || e.sortInflight.Load() != 0 {
		t.Fatalf("stale GPU-sorted batch not dropped/released: %+v done=%d free=%d", st, b.done.Load(), len(e.free))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.got) != 0 {
		t.Fatal("a stale GPU-sorted hash was reported")
	}
}

// ---- r21 gpusort: closed-loop A/B probe of the GPU sort ----

func TestSortProbeKeepRule(t *testing.T) {
	if !sortProbeKeep(101, 100) || sortProbeKeep(100, 100) || sortProbeKeep(99, 100) || sortProbeKeep(0, 0) {
		t.Fatal("the GPU sort must be kept only on a strict gain")
	}
}

// probeRig: a GPU-sort engine whose ProbeCount is driven by a fake producer that is faster while the sort is paused
// (pausedRate) or allowed (allowedRate); returns the engine after one probe round.
func probeRound(t *testing.T, pausedRate, allowedRate uint64) (*rig, bool) {
	var cnt atomic.Uint64
	r := newRigCfg(t, true, 8, 5, 0, func(c *Config) {
		c.GPUSort = true
		c.SortProbe = 40 * time.Millisecond
		c.SortProbePairs = 2
		c.ProbeCount = cnt.Load
	})
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		tk := time.NewTicker(time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				if r.e.SortPaused() {
					cnt.Add(pausedRate)
				} else {
					cnt.Add(allowedRate)
				}
			}
		}
	}()
	ok := r.e.sortProbeRound(r.e.quit)
	close(stop)
	<-done
	return r, ok
}

// A GPU sort that costs more staged hashes than it adds (the r19/r21 live regime) is paused by the probe, and a paused
// sort is never diverted to; one that adds hashes stays allowed.
func TestSortProbePausesNetLossKeepsGain(t *testing.T) {
	r, ok := probeRound(t, 100, 10)
	if !ok || !r.e.SortPaused() || !strings.Contains(r.e.Stats().SortProbe, "PAUSED") {
		t.Fatalf("net-loss sort not paused: ok=%v paused=%v %q", ok, r.e.SortPaused(), r.e.Stats().SortProbe)
	}
	if !r.e.Sorting() {
		t.Fatal("the probe must pause the sort, not disable it for good")
	}
	e := r.e
	other := e.batches[1]
	e.ready = []*batch{other, e.batches[2]}
	for j := 0; j < e.lay.Slots; j++ {
		binary.LittleEndian.PutUint32(e.mem[e.lay.OffLens+4*j:], 1000)
	}
	if e.divert(e.batches[0]) {
		t.Fatal("diverted to the GPU sort while the probe holds it paused")
	}
	e.ready = nil
	r.e.Close()

	r, ok = probeRound(t, 10, 100)
	if !ok || r.e.SortPaused() || !strings.Contains(r.e.Stats().SortProbe, "KEPT") {
		t.Fatalf("net-gain sort not kept: ok=%v paused=%v %q", ok, r.e.SortPaused(), r.e.Stats().SortProbe)
	}
	r.e.Close()
}

// The probe stops (and leaves no pause behind) once the sort is off for good or the engine closes.
func TestSortProbeStopsWhenSortOff(t *testing.T) {
	r := newRigCfg(t, true, 8, 5, 0, func(c *Config) { c.GPUSort = true; c.SortProbe = time.Hour })
	defer r.e.Close()
	r.e.SortDisable("test")
	if r.e.sortProbeRound(r.e.quit) {
		t.Fatal("probe ran with the sort off for good")
	}
	q := make(chan struct{})
	close(q)
	r2 := newRigCfg(t, true, 8, 5, 0, func(c *Config) { c.GPUSort = true; c.SortProbe = time.Hour })
	defer r2.e.Close()
	if r2.e.sortProbeRound(q) || r2.e.SortPaused() {
		t.Fatal("a closed probe must stop and un-pause")
	}
}

// r21 merge (gpusort-4 fix): a GPU-sorted batch is hashed without any TryWork, so the engine hands its count to
// Config.Counted. Wired as the miner does it (one TOTAL counter fed by TryWork's k and by Counted, read back as
// ProbeCount), the probe's counter includes every GPU-sorted hash; without Counted the allowed windows would miss
// the GPU's own output and the probe would pause a sort that pays.
func TestGPUSortedHashesCounted(t *testing.T) {
	var total, counted atomic.Uint64
	r := newRigCfg(t, true, 8, 5, 0, func(c *Config) {
		c.GPUSort = true
		c.Counted = func(n int) { counted.Add(uint64(n)); total.Add(uint64(n)) }
		c.ProbeCount = total.Load
	})
	r.slowCPU = 20 * time.Millisecond // slower than the soft GPU even under -race, so batches are diverted to op 3
	if err := r.e.SelfTest(8, astropair.NewScratch()); err != nil {
		t.Fatal(err)
	}
	r.e.Start()
	n := r.mine(2, 160)
	total.Add(uint64(n)) // the miner adds TryWork's k to the same counter
	r.e.Close()
	st := r.e.Stats()
	if st.GPUSorted == 0 {
		t.Fatalf("no batch was GPU-sorted: %+v", st)
	}
	if counted.Load() != st.GPUSorted {
		t.Fatalf("Counted got %d hashes, the engine GPU-sorted %d", counted.Load(), st.GPUSorted)
	}
	if got := r.e.probeCount(); got != uint64(n)+st.GPUSorted {
		t.Fatalf("probe counter %d != TryWork %d + GPU-sorted %d", got, n, st.GPUSorted)
	}
}
