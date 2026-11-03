// Package gsplit is the CPU half of dero-miner --gpu-mode=split: the Metal GPU computes AstroBWTv3 stage 1 (and,
// optionally, the final SHA-256) for batches of nonces, writing the ~70 KB stage-1 texts straight into POSIX shared
// memory; interface{} CPU mining thread pulls staged texts zero-copy and runs only the descriptor sort (Engine.TryWork).
//
// Pipeline (per batch of Batch nonces, Depth batches in the ring, no per-batch barrier interface{}where):
//
//	free --feeder: msgs+op1--> stage-1 in flight --reply--> ready --TryWork claims pairs--> sorted
//	  ^                                                                                    |
//	  +---- collect hashes <--reply-- op2 (GPU SHA) in flight <----------------------------+  (GPUSHA)
//	  +---- (CPU SHA: the claiming thread already hashed the pair) <-----------------------+  (!GPUSHA)
//
// It is MINER-ONLY: nothing in derod imports it and no consensus package changes. Correctness guards:
//  1. SelfTest: every hash of a test batch, through the real GPU kernels and the real CPU path, must equal the
//     reference (astrobwtv3.AstroBWTv3 on the consensus code path) or the engine never starts;
//  2. a GPU-reported text length outside [1, MAX_LENGTH] is a GPU fault: that hash is computed from the blob on the
//     CPU and the engine disables itself;
//  3. sampled audit: 1 staged hash in AuditEvery (and at least one per GPU-SHA batch) is re-hashed in full on the
//     CPU; a difference restarts the server and re-runs the SelfTest (AuditStrikes differences within
//     AuditStrikeWindow disable the engine; the audited hash is replaced by the CPU's);
//  4. the sort goes through astropair.SuffixSort, i.e. the miner's verified_sort with its own sampling/kill switch;
//  5. a recovered panic in the sort/SHA re-hashes that pair from the blobs and disables the engine;
//  6. the miner re-hashes every winning share on the CPU before submitting it (cmd/dero-miner/gpu_split.go).
//
// GPU sort (Round 19, Config.GPUSort, off by default): when the CPU threads already have SortMinReady staged batches
// waiting and fewer than SortInflight batches are being GPU-sorted, a batch whose stage 1 just finished is sent to the
// server's op 3 (a clean-room block-per-hash Metal suffix sort run in short, resumable command buffers) instead of to
// the CPU, then to op 2 (GPU SHA) as usual. The GPU therefore takes sorting work only while the CPU is fed, at the rate
// its measured completions allow, so the CPU threads are never starved by it. Guards: the self-test (start and every
// respawn) sorts half of its batch on the GPU and compares every hash with the reference; a failed op 3 (watchdog,
// refused text, a server without sort lanes) returns the batch to the CPU path (texts are never modified by the sort);
// every GPU-sorted batch gets a CPU audit (blocking, never dropped) and a mismatch turns the GPU sort off for good;
// winning shares are re-hashed on the CPU (gpu_split.go) as before.
//
// Transport failures are never fatal (r18 merge): when the server exits (macOS GPU watchdog under contention, EOF),
// a write to it fails, or MaxGPUFailures commands in a row fail, the engine pauses staging (the CPU threads hash on
// their own), reaps the server, backs off (RespawnMin doubling to RespawnMax, reset after HealthyReset of healthy
// running), relaunches it, and re-runs the bit-exact SelfTest before staging again. Only wrong RESULTS (a self-test
// mismatch or a bad GPU length on respawn, repeated audit differences, an out-of-range length while mining) disable it.
// A single audit difference (r19: the live r18 miner hit one after 15,830 clean audits, the stale-e.cur re-staging
// race fixed by prepare/makeReady) restarts the server through the same respawn path, so the SelfTest decides.
package gsplit

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
	"github.com/deroproject/derohe/cmd/dero-miner/astropair"
)

const (
	MsgLen   = 48         // block.MINIBLOCK_SIZE
	NonceOff = MsgLen - 5 // big-endian uint32 nonce, as the CPU threads place it
	DStride  = 278 * 256  // bytes per text slot: >= the longest stage-1 text (273*256+1023 = 70911) + slack
	SStride  = 72000      // int32 per suffix-array slot
	// MaxText is the longest stage-1 text: the loop stops at tries <= 277 (pow.go:2436) and data_len =
	// (tries-4)*256 + (x & 0x3ff) (pow.go:2447). A GPU length above it is a fault, never sliced.
	MaxText = 273*256 + 0x3ff
	align   = 16384
	// MaxGPUFailures consecutive failed GPU commands (each retried with a growing backoff) restart the server
	MaxGPUFailures = 8
	// respawn back-off defaults (Config.RespawnMin / RespawnMax / HealthyReset)
	DefaultRespawnMin        = time.Second
	DefaultRespawnMax        = 60 * time.Second
	DefaultHealthyReset      = 5 * time.Minute
	DefaultAuditStrikes      = 3
	DefaultAuditStrikeWindow = time.Hour
)

// ErrNotBitExact marks a self-test failure caused by the GPU's RESULTS (a hash mismatch, a bad text length, a sort the
// texts made fail), as opposed to a transport failure (the server died, timed out or failed the command). Only the
// former is a reason to stop using the GPU for good.
var ErrNotBitExact = errors.New("gsplit: GPU results are not bit-exact")

func imin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func al(x int) int { return (x + align - 1) &^ (align - 1) }

// Layout is the shared-memory map; the Go side owns it and passes every offset to the server.
type Layout struct {
	Slots                                       int
	OffMsgs, OffLens, OffOuts, OffDatas, OffSas int
	Size                                        int
}

// NewLayout lays out slots slots, each region 16 KB aligned; the suffix-array region exists only for the GPU SHA.
func NewLayout(slots int, gpuSHA bool) Layout {
	l := Layout{Slots: slots}
	l.OffMsgs = 0
	l.OffLens = al(slots * MsgLen)
	l.OffOuts = l.OffLens + al(slots*4)
	l.OffDatas = l.OffOuts + al(slots*32)
	l.OffSas = l.OffDatas + al(slots*DStride)
	l.Size = l.OffSas
	if gpuSHA {
		l.Size += al(slots * SStride * 4)
	}
	return l
}

// Work is one job template: Blob carries the job's blockhashing blob with the miner's randomisation; the engine
// writes the nonce at NonceOff. Tag is handed back to Stale and Found.
type Work struct {
	Blob [MsgLen]byte
	Tag  interface{}
}

type Config struct {
	Bin                    string // gpu_split_server binary (its directory must hold loop_ops.metal.inc)
	Batch, Depth, Inflight int    // nonces per GPU command (even), batches in the ring, GPU command buffers in flight
	GPUSHA                 bool   // final SHA-256 on the GPU (op 2) instead of the paired CPU SHA
	GPUMax                 int    // GPU duty-cycle cap, percent (1..100); SetGPUMax changes it while mining (r22)
	AuditEvery             uint64 // re-hash 1 staged hash in this many on the CPU (0 = only the per-batch GPU-SHA audit)
	Next                   func() (Work, bool)
	Stale                  func(tag interface{}) bool                     // true: drop this batch's unclaimed nonces
	StaleQuiet             func(tag interface{}) bool                     // r22: Stale without side effects (counters), for finish()'s re-check; nil = Stale
	Found                  func(tag interface{}, blob []byte, h [32]byte) // every hash (blob is only valid during the call)
	Reference              func(blob []byte) [32]byte                     // consensus hash for SelfTest (default AstroBWTv3)
	Logf                   func(format string, args ...interface{})
	RespawnMin, RespawnMax time.Duration // server restart back-off (defaults 1 s doubling to 60 s)
	HealthyReset           time.Duration // running this long without a restart resets the back-off (default 5 min)
	AuditStrikes           int           // audit differences within AuditStrikeWindow that disable the engine (default 3)
	AuditStrikeWindow      time.Duration // default 1 h
	GPUSort                bool          // Round 19: the GPU also suffix-sorts staged batches (op 3; needs GPUSHA)
	SortLanes, SortChunk   int           // server sort lanes (default 2) and texts per sort chunk (default 64)
	SortInflight           int           // batches being GPU-sorted at once (default 1)
	SortMinReady           int           // divert only while >= this many staged batches wait for the CPU (default 1)
	// r21 gpusort: closed-loop A/B probe. With SortProbe > 0 the engine alternates SortProbePairs ABBA pairs of windows
	// with the GPU sort paused / allowed, counts ProbeCount (default Stats().Hashed: staged + GPU-sorted hashes) in each,
	// and keeps the sort allowed only if the allowed windows produced strictly more; it re-probes every SortProbeEvery.
	// A GPU that has no time to spare (stage 1 + SHA binding) loses more staged hashes than it sorts: the probe pauses.
	SortProbe      time.Duration
	SortProbePairs int           // default 2 (even: each pair of pairs is one full ABBA)
	SortProbeEvery time.Duration // default 1 h
	ProbeCount     func() uint64
	// Counted (r21 merge, gpusort-4 fix) receives the hashes the engine finished without TryWork: a GPU-sorted batch is
	// sorted and SHA'd on the GPU, so no CPU thread returns its count. The miner adds them to its TOTAL counter, which is
	// also ProbeCount, so the probe's allowed windows (and the hashrate display and /metrics) include the GPU's output.
	Counted   func(n int)
	transport func(e *Engine) (transport, error) // tests: a software GPU
	noAudit   bool                               // tests: GPU-capacity probe with a fake sort
}

// reply is one server answer; at is its arrival on the engine's monotonic clock (Engine.clock, ns), stamped by the
// transport's reader as it comes off the pipe (0: the reply loop stamps it on receipt).
type reply struct {
	status, us, tag, op uint32
	at                  int64
}

type transport interface {
	issue(op, first, n, tag uint32) error
	replies() <-chan reply
	close()
	kill() // make the server exit now (its replies channel then closes); safe to call concurrently and repeatedly
}

type batch struct {
	id      uint32
	first   int
	n       int
	work    Work
	next    atomic.Int64 // next unclaimed index (claimed in pairs)
	done    atomic.Int64 // indices finished on the CPU side (hashed, sorted or dropped)
	skip    []uint32     // GPUSHA: 1 = slot already reported (CPU-finished) or dropped; the GPU result is ignored
	dropped atomic.Int64
	sorted  bool // this staging was suffix-sorted on the GPU (op 3); written by the reply loop only
}

// Stats are cumulative counters.
type Stats struct {
	Hashed, Dropped, CPUFinished, Audited, Batches, GPUus, GPURetries uint64
	// GPUBusyUs (r21) is the wall-clock time the GPU had at least one of our command buffers executing: the union of
	// the reported spans, where GPUus is their sum (overlapping op 1/op 2 buffers make the sum exceed the wall clock).
	// The --gpu-max duty debt is charged on GPUBusyUs.
	GPUBusyUs uint64
	// S1us/SHAus (r22 gpukernels) split GPUus by kernel: the summed spans of the successful op 1 (stage 1) and op 2
	// (final SHA) command buffers, with S1Cmds/SHACmds their counts. S1us/S1Cmds is the mean stage-1 buffer span, the
	// live per-kernel GPU profile (a span includes the time it shared the GPU with the other op's buffer).
	S1us, S1Cmds, SHAus, SHACmds uint64
	Restarts                     uint64 // server respawns after a transport failure
	// regime signal (r19 splitcpu-2): IdleTries counts TryWork calls that found no staged batch (the CPU threads outrun
	// the GPU: GPU-bound); FeedWaitUs is the time the feeder spent blocked on a full ring. A full ring is NOT by itself
	// CPU-bound: with GPUSHA a batch is only freed after its op 2 (GPU SHA), so the ring is also full while every batch
	// is on the GPU. FeedWaitBacklogUs (r20 cpuminer) is the part of FeedWaitUs during which a staged batch was still
	// waiting for CPU threads (sampled every FeedSample): that part, and only that part, is CPU-bound.
	IdleTries, FeedWaitUs, FeedWaitBacklogUs uint64
	AuditFaults                              uint64 // audit differences (each restarts the server; AuditStrikes in a window disable)
	GPUSorted, SortFails, SortUs             uint64 // GPU sort (op 3): texts sorted, failed op 3 commands, GPU us
	Disabled                                 string
	SortOff                                  string // why the GPU sort is off ("" = on, or never enabled)
	SortProbe                                string // r21: the last A/B probe verdict ("" = never probed)
	// r22 splitpipe. ThrottleUs: time the feeder slept paying the --gpu-max debt (the throttle's whole cost on the feed
	// side). CollectUs: time the reply loop spent reporting GPU-SHA batches (collect: one Found per hash), during which
	// no reply is handled and the batch's ring slot is not yet free. StaleSHASkipped: hashes whose GPU SHA (op 2) was
	// not run because their job went stale while the batch was being sorted (every share they could make is an orphan).
	ThrottleUs, CollectUs, StaleSHASkipped uint64
	GPUMax                                 int // the duty cap in force now (percent)
}

type Engine struct {
	cfg  Config
	lay  Layout
	mem  []byte
	shmF *os.File
	tr   transport

	batches []*batch
	free    chan *batch

	mu    sync.Mutex
	ready []*batch
	cur   unsafe.Pointer // *batch: the batch TryWork claims from (atomic)

	disabled atomic.Int32
	reason   atomic.Value
	quit     chan struct{}
	wg       sync.WaitGroup // auditor: stopped by quit, before the transport closes
	wgFeed   sync.WaitGroup // this generation's feeder + command retries: stopped by genQuit or quit
	wgReply  sync.WaitGroup // replyLoop: stops when the transport's reply channel closes
	genQuit  chan struct{}  // closed when the current server generation is being torn down

	// respawn (transport failures): lifeMu orders Close against a respawn installing a new server
	lifeMu      sync.Mutex
	wgRespawn   sync.WaitGroup
	paused      atomic.Int32 // 1 while the server is being replaced: TryWork claims nothing
	active      atomic.Int64 // TryWork calls in progress (respawn waits for 0 after pausing)
	backoff     time.Duration
	lastStart   time.Time
	selfTestN   int
	sRestarts   atomic.Uint64
	respawnHook func()       // tests: called after each respawn attempt
	debt        atomic.Int64 // --gpu-max bucket: ns of wall time owed (charged busy*100/cap, credited by the feeder; duty.go)
	dutyLast    int64        // feeder only: e.clock() at the last settleDuty
	gpuMax      atomic.Int32 // GPU duty cap in force (percent, 1..100): cfg.GPUMax at New, then SetGPUMax (r22)
	auditN      atomic.Uint64
	auditCh     chan auditReq

	sortOff      atomic.Int32 // 1: GPU sort off (not configured, unsupported by the server, or a wrong result)
	sortReason   atomic.Value
	sortInflight atomic.Int32 // batches in op 3
	sortPaused   atomic.Int32 // 1: the A/B probe paused the GPU sort (it stays configured and is re-probed)
	sortVerdict  atomic.Value // string: the last probe verdict

	sGPUSorted, sSortFails, sSortUs                                       atomic.Uint64
	sHashed, sDropped, sCPUFinished, sAudited, sBatches, sGPUus, sRetries atomic.Uint64
	sIdleTries, sFeedWaitUs, sAuditFaults                                 atomic.Uint64
	sFeedWaitBacklogUs                                                    atomic.Uint64
	sGPUBusyUs                                                            atomic.Uint64
	sThrottleUs, sCollectNs, sStaleSHASkipped                             atomic.Uint64
	sS1us, sS1n, sSHAus, sSHAn                                            atomic.Uint64 // per-kernel spans and buffer counts (op 1 / op 2)
	t0                                                                    time.Time     // the monotonic clock replies are stamped on
	busy                                                                  busyUnion     // replyLoop only (generations run one after another)
	live                                                                  atomic.Value  // transport: the running server, for auditFault's kill
	gen                                                                   atomic.Uint64 // bumped per server (re)start
	struckGen                                                             uint64        // under strikeMu: last server generation that took a strike
	strikeMu                                                              sync.Mutex
	strikes                                                               []time.Time  // audit differences inside AuditStrikeWindow
	failRun                                                               atomic.Int64 // consecutive failed GPU commands
}

type auditReq struct {
	blob   [MsgLen]byte
	h      [32]byte
	gen    uint64 // server generation that produced h
	sorted bool   // the hash came from a GPU-sorted batch
}

// New maps the shared memory and starts the GPU server; it does not stage interface{}thing until Start.
func New(cfg Config) (*Engine, error) {
	if cfg.Batch < 2 || cfg.Batch%2 != 0 || cfg.Depth < 2 || cfg.Inflight < 1 || cfg.Inflight > 16 {
		return nil, fmt.Errorf("gsplit: bad geometry batch=%d depth=%d inflight=%d", cfg.Batch, cfg.Depth, cfg.Inflight)
	}
	if cfg.Next == nil || cfg.Found == nil {
		return nil, errors.New("gsplit: Next and Found are required")
	}
	if cfg.GPUMax < 1 || cfg.GPUMax > 100 {
		cfg.GPUMax = 100
	}
	if cfg.Reference == nil {
		cfg.Reference = astrobwtv3.AstroBWTv3
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...interface{}) {}
	}
	if cfg.RespawnMin <= 0 {
		cfg.RespawnMin = DefaultRespawnMin
	}
	if cfg.RespawnMax < cfg.RespawnMin {
		cfg.RespawnMax = DefaultRespawnMax
		if cfg.RespawnMax < cfg.RespawnMin {
			cfg.RespawnMax = cfg.RespawnMin
		}
	}
	if cfg.HealthyReset <= 0 {
		cfg.HealthyReset = DefaultHealthyReset
	}
	if cfg.AuditStrikes <= 0 {
		cfg.AuditStrikes = DefaultAuditStrikes
	}
	if cfg.AuditStrikeWindow <= 0 {
		cfg.AuditStrikeWindow = DefaultAuditStrikeWindow
	}
	if cfg.SortLanes <= 0 {
		cfg.SortLanes = 2
	}
	if cfg.SortLanes > 8 {
		cfg.SortLanes = 8
	}
	if cfg.SortChunk < 8 || cfg.SortChunk > 512 {
		cfg.SortChunk = 64
	}
	if cfg.SortInflight <= 0 {
		cfg.SortInflight = 1
	}
	if cfg.SortMinReady <= 0 {
		cfg.SortMinReady = 1
	}
	if cfg.SortProbePairs <= 0 {
		cfg.SortProbePairs = 2 // r21 merge: an even count (P A A P, P A A P) so a linear drift cancels fully
	}
	if cfg.SortProbeEvery <= 0 {
		cfg.SortProbeEvery = time.Hour
	}
	e := &Engine{cfg: cfg, lay: NewLayout(cfg.Batch*cfg.Depth, cfg.GPUSHA), quit: make(chan struct{}), auditCh: make(chan auditReq, 4),
		genQuit: make(chan struct{}), backoff: cfg.RespawnMin, selfTestN: 256, t0: time.Now()}
	e.gpuMax.Store(int32(cfg.GPUMax))
	switch {
	case !cfg.GPUSort:
		e.sortOff.Store(1)
	case !cfg.GPUSHA:
		e.SortDisable("the GPU sort needs the GPU final SHA (suffix-array region)")
	case cfg.Depth < cfg.SortInflight+cfg.SortMinReady+2:
		e.SortDisable(fmt.Sprintf("depth %d too small for sort inflight %d + min ready %d + 2", cfg.Depth, cfg.SortInflight, cfg.SortMinReady))
	}
	mk := cfg.transport
	if mk == nil {
		mk = procTransport
	}
	tr, err := mk(e)
	if err != nil {
		e.unmap()
		return nil, err
	}
	e.tr = tr
	e.live.Store(tr)
	e.gen.Add(1)
	e.free = make(chan *batch, cfg.Depth)
	for i := 0; i < cfg.Depth; i++ {
		b := &batch{id: uint32(i), first: i * cfg.Batch, n: cfg.Batch}
		b.next.Store(int64(b.n)) // claimable only once makeReady publishes it
		if cfg.GPUSHA {
			b.skip = make([]uint32, cfg.Batch)
		}
		e.batches = append(e.batches, b)
	}
	return e, nil
}

// clock is the engine's monotonic clock in ns (reply arrival stamps).
func (e *Engine) clock() int64 { return int64(time.Since(e.t0)) }

func (e *Engine) unmap() {
	if e.mem != nil {
		freeShm(e.mem)
		e.mem = nil
	}
	if e.shmF != nil {
		e.shmF.Close()
		e.shmF = nil
	}
}

// ---- shared-memory accessors ----

func (e *Engine) msg(j int) []byte { return e.mem[j*MsgLen : j*MsgLen+MsgLen] }
func (e *Engine) dlen(j int) int {
	return int(binary.LittleEndian.Uint32(e.mem[e.lay.OffLens+4*j:]))
}
func (e *Engine) text(j, n int) []byte {
	o := e.lay.OffDatas + j*DStride
	return e.mem[o : o+n : o+DStride]
}
func (e *Engine) sa(j int) []int32 {
	o := e.lay.OffSas + j*SStride*4
	return unsafe.Slice((*int32)(unsafe.Pointer(&e.mem[o])), SStride)
}
func (e *Engine) out(j int) (h [32]byte) { copy(h[:], e.mem[e.lay.OffOuts+32*j:]); return }

// ---- self-test ----

// SelfTest pushes n test blobs (n <= Batch, even) through the GPU kernels and the CPU path the mining uses and
// compares every hash with cfg.Reference. Call it before Start, with no other user of the engine.
func (e *Engine) SelfTest(n int, s *astropair.Scratch) error {
	if n > e.cfg.Batch {
		n = e.cfg.Batch
	}
	n &^= 1
	if n < 2 {
		return errors.New("gsplit self-test: n < 2")
	}
	e.selfTestN = n
	rng := rand.New(rand.NewSource(18))
	ref := make([][32]byte, n)
	for j := 0; j < n; j++ {
		m := e.msg(j)
		rng.Read(m)
		m[0] = m[0]&0xf0 | 1 // version 1, as mining requires
		ref[j] = e.cfg.Reference(m)
	}
	if err := e.syncCmd(1, 0, n); err != nil {
		return err
	}
	for j := 0; j < n; j++ {
		if l := e.dlen(j); l < 1 || l > MaxText {
			return fmt.Errorf("%w: GPU text length %d out of range at %d", ErrNotBitExact, l, j)
		}
	}
	got := make([][32]byte, n)
	gs := 0 // slots [0, gs) are suffix-sorted on the GPU (op 3)
	if e.cfg.GPUSHA && e.sortOff.Load() == 0 {
		gs = n / 2
		if err := e.syncCmd(3, 0, gs); err != nil {
			if err == errServerGone {
				return err
			}
			e.SortDisable("self-test: the server did not sort (" + err.Error() + "; rebuild gpu_split_server with sort_ops.metal.inc)")
			gs = 0
		}
	}
	for j := 0; j < n; j += 2 {
		ta, tb := e.text(j, e.dlen(j)), e.text(j+1, e.dlen(j+1))
		if e.cfg.GPUSHA {
			for _, k := range [2]int{j, j + 1} {
				if k < gs {
					continue
				}
				t := e.text(k, e.dlen(k))
				if !astropair.SortOnly(t, e.sa(k)) {
					return fmt.Errorf("%w: sort declined at %d (is the descriptor sort installed?)", ErrNotBitExact, k)
				}
			}
			continue
		}
		ha, hb, ok := astropair.SortSum2(ta, tb, s)
		if !ok {
			return fmt.Errorf("%w: the sort/SHA panicked", ErrNotBitExact)
		}
		got[j], got[j+1] = ha, hb
	}
	if e.cfg.GPUSHA {
		if err := e.syncCmd(2, 0, n); err != nil {
			return err
		}
		for j := 0; j < n; j++ {
			got[j] = e.out(j)
		}
	}
	sortBad := -1
	for j := 0; j < n; j++ {
		if got[j] != ref[j] {
			if j < gs {
				if sortBad < 0 {
					sortBad = j
				}
				continue
			}
			return fmt.Errorf("%w: HASH MISMATCH at %d: split %x reference %x", ErrNotBitExact, j, got[j][:8], ref[j][:8])
		}
	}
	if sortBad >= 0 { // stage 1 and the SHA were right (the CPU-sorted half): only the GPU sort is wrong
		e.SortDisable(fmt.Sprintf("self-test: GPU-sorted hash MISMATCH at %d: %x reference %x", sortBad, got[sortBad][:8], ref[sortBad][:8]))
	}
	return nil
}

// syncCmd runs one command and waits for it; a failed command (the transient macOS GPU watchdog) is retried twice.
func (e *Engine) syncCmd(op uint32, first, n int) (err error) {
	for try := 0; try < 3; try++ {
		if err = e.syncCmd1(op, first, n); err == nil || err == errServerGone {
			return err
		}
		time.Sleep(200 * time.Millisecond)
	}
	return err
}

var errServerGone = errors.New("gsplit: GPU server exited")

func (e *Engine) syncCmd1(op uint32, first, n int) error {
	if err := e.tr.issue(op, uint32(first), uint32(n), 0xffffffff); err != nil {
		return err
	}
	select {
	case r, ok := <-e.tr.replies():
		if !ok {
			return errServerGone
		}
		if r.status != 0 || r.tag != 0xffffffff || r.op != op {
			return fmt.Errorf("gsplit: GPU command failed status=%d", r.status)
		}
		return nil
	case <-time.After(120 * time.Second):
		return errors.New("gsplit: GPU server timed out")
	}
}

// ---- mining ----

// Start launches the feeder, the reply loop and the auditor.
func (e *Engine) Start() {
	for _, b := range e.batches {
		e.free <- b
	}
	e.wg.Add(1)
	go e.auditor()
	if e.cfg.GPUSort && e.cfg.SortProbe > 0 && e.sortOff.Load() == 0 {
		e.wg.Add(1)
		go e.sortProber()
	}
	e.lifeMu.Lock()
	e.lastStart = time.Now()
	e.startGeneration()
	e.lifeMu.Unlock()
}

// startGeneration starts the feeder and the reply loop for the current server (caller holds lifeMu).
func (e *Engine) startGeneration() {
	e.genQuit = make(chan struct{})
	e.dutyLast = e.clock() // the feeder credits wall time from here (a respawn's pause is not banked past dutyBurstNs)
	e.wgFeed.Add(1)
	e.wgReply.Add(1)
	go e.feeder(e.genQuit)
	go e.replyLoop(e.tr)
}

// serverFailed: a write to the server failed. Kill it so its reply channel closes and the reply loop respawns it.
func (e *Engine) serverFailed(tr transport, err error) {
	e.cfg.Logf("GPU split server write failed (%v); restarting it", err)
	tr.kill()
}

func (e *Engine) feeder(gq chan struct{}) {
	defer e.wgFeed.Done()
	tr := e.tr
	for {
		var b *batch
		select {
		case b = <-e.free:
		default:
			// the ring is full: every batch is staged (waiting for the CPU threads) or on the GPU (op 1 or op 2)
			if b = e.waitFree(gq); b == nil {
				return
			}
		}
		for {
			if e.disabled.Load() != 0 {
				return
			}
			if !e.payDuty(gq) { // --gpu-max (duty.go)
				return
			}
			w, ok := e.cfg.Next()
			if ok {
				b.work = w
				break
			}
			select {
			case <-e.quit:
				return
			case <-gq:
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
		e.prepare(b, rand.Uint32())
		if err := tr.issue(1, uint32(b.first), uint32(b.n), b.id); err != nil {
			e.serverFailed(tr, err)
			return
		}
	}
}

// charge adds the --gpu-max bucket cost (duty.go dutyCharge: busy*100/cap of wall time) for busy ns of new wall-clock
// GPU time, at the duty cap in force now.
func (e *Engine) charge(busy int64) {
	if c := dutyCharge(busy, int(e.gpuMax.Load())); c > 0 {
		e.debt.Add(c)
	}
}

// SetGPUMax changes the GPU duty cap while mining (clamped to 1..100) and returns the cap now in force. Raising it to
// 100 also forgives the debt not yet slept.
func (e *Engine) SetGPUMax(p int) int {
	if p < 1 {
		p = 1
	}
	if p > 100 {
		p = 100
	}
	e.gpuMax.Store(int32(p))
	if p == 100 {
		e.debt.Store(0)
	}
	return p
}

// GPUMax is the GPU duty cap in force (percent).
func (e *Engine) GPUMax() int { return int(e.gpuMax.Load()) }

// FeedSample is how often a blocked feeder samples whether the CPU threads have a staged backlog.
const FeedSample = 5 * time.Millisecond

// waitFree blocks until a batch is free (nil: the engine or this generation is stopping). The whole wait goes to
// FeedWaitUs; each FeedSample interval that ends with a staged batch still unclaimed also goes to FeedWaitBacklogUs.
func (e *Engine) waitFree(gq chan struct{}) *batch {
	t0 := time.Now()
	tk := time.NewTicker(FeedSample)
	defer tk.Stop()
	last := t0
	for {
		select {
		case b := <-e.free:
			e.sFeedWaitUs.Add(uint64(time.Since(t0).Microseconds()))
			return b
		case <-e.quit:
			return nil
		case <-gq:
			return nil
		case now := <-tk.C:
			if e.cpuBacklog() {
				e.sFeedWaitBacklogUs.Add(uint64(now.Sub(last).Microseconds()))
			}
			last = now
		}
	}
}

// cpuBacklog reports whether staged texts are waiting for the CPU threads: a ready batch nobody has started, or
// unclaimed indices left in the current one.
func (e *Engine) cpuBacklog() bool {
	e.mu.Lock()
	n := len(e.ready)
	e.mu.Unlock()
	if n > 0 {
		return true
	}
	b := (*batch)(atomic.LoadPointer(&e.cur))
	return b != nil && b.next.Load() < int64(b.n)
}

// prepare writes b's nonces and resets its counters for a new staging. b.next is NOT reset here: it stays >= b.n (every
// index claimed) until the batch's texts are ready (makeReady), so a CPU thread still holding b as its stale current
// batch (e.cur is only moved on by the next TryWork) cannot claim a slot whose text the GPU is rewriting (r19 gpusort-5).
func (e *Engine) prepare(b *batch, nonce uint32) {
	for j := 0; j < b.n; j++ {
		m := e.msg(b.first + j)
		copy(m, b.work.Blob[:])
		binary.BigEndian.PutUint32(m[NonceOff:], nonce+uint32(j))
	}
	b.sorted = false
	b.done.Store(0)
	b.dropped.Store(0)
	for i := range b.skip {
		b.skip[i] = 0
	}
}

// makeReady hands b's staged texts to the CPU threads: only now do its indices become claimable.
func (e *Engine) makeReady(b *batch) {
	e.mu.Lock()
	b.next.Store(0)
	e.ready = append(e.ready, b)
	e.mu.Unlock()
}

func (e *Engine) replyLoop(tr transport) {
	defer e.wgReply.Done()
	gq := e.genQuit
	for r := range tr.replies() {
		if int(r.tag) >= len(e.batches) {
			continue
		}
		b := e.batches[r.tag]
		if r.op == 3 {
			e.sortDone(b, r)
			continue
		}
		if r.status != 0 {
			// macOS kills command buffers that hog a busy GPU (kIOGPUCommandBufferCallbackErrorImpactingInteractivity)
			// or that share a GPU recovery (InnocentVictim): transient. The command wrote nothing we trust, so it is
			// re-issued after a backoff; MaxGPUFailures consecutive failures restart the server (a transport problem,
			// never a reason to stop using the GPU).
			n := e.failRun.Add(1)
			e.sRetries.Add(1)
			if n > MaxGPUFailures {
				e.cfg.Logf("GPU command op=%d failed %d times in a row (status %d); restarting the server", r.op, n, r.status)
				tr.kill()
				continue
			}
			e.wgFeed.Add(1)
			go func(op uint32, b *batch, n int64) {
				defer e.wgFeed.Done()
				select {
				case <-time.After(time.Duration(n) * 100 * time.Millisecond):
				case <-e.quit:
					return
				case <-gq:
					return
				}
				if err := tr.issue(op, uint32(b.first), uint32(b.n), b.id); err != nil {
					e.serverFailed(tr, err)
				}
			}(r.op, b, n)
			continue
		}
		e.failRun.Store(0)
		e.sGPUus.Add(uint64(r.us))
		switch r.op {
		case 1:
			e.sS1us.Add(uint64(r.us))
			e.sS1n.Add(1)
		case 2:
			e.sSHAus.Add(uint64(r.us))
			e.sSHAn.Add(1)
		}
		at := r.at
		if at == 0 {
			at = e.clock()
		}
		busy := e.busy.add(at-int64(r.us)*1000, at) // wall GPU time this buffer added (not its overlapped span)
		e.sGPUBusyUs.Add(uint64(busy / 1000))
		e.charge(busy)
		switch r.op {
		case 1:
			if e.divert(b) {
				if err := tr.issue(3, uint32(b.first), uint32(b.n), b.id); err != nil {
					e.serverFailed(tr, err)
				}
				continue
			}
			e.makeReady(b)
		case 2:
			e.collect(b)
			e.release(b)
		}
	}
	// the server is gone: respawn it unless the engine is closing or disabled for wrong results
	e.lifeMu.Lock()
	defer e.lifeMu.Unlock()
	select {
	case <-e.quit:
		return
	default:
	}
	if e.disabled.Load() == 0 {
		e.wgRespawn.Add(1)
		go e.respawn(tr)
	}
}

// nextBackoff returns the delay before the next restart attempt and doubles the stored one (capped). A server that
// ran HealthyReset since its last (re)start begins again at RespawnMin.
func (e *Engine) nextBackoff(now time.Time) time.Duration {
	if !e.lastStart.IsZero() && now.Sub(e.lastStart) >= e.cfg.HealthyReset {
		e.backoff = e.cfg.RespawnMin
	}
	e.lastStart = time.Time{} // further attempts of this outage keep doubling
	d := e.backoff
	e.backoff *= 2
	if e.backoff > e.cfg.RespawnMax {
		e.backoff = e.cfg.RespawnMax
	}
	return d
}

// quiesce pauses TryWork and waits until no CPU thread is inside it (no thread reads a slot the respawn rewrites).
func (e *Engine) quiesce() {
	e.paused.Store(1)
	for e.active.Load() != 0 {
		time.Sleep(time.Millisecond)
	}
}

// resetRing returns every batch to the free list: whatever the dead server was doing is discarded.
func (e *Engine) resetRing() {
	e.mu.Lock()
	e.ready = nil
	atomic.StorePointer(&e.cur, nil)
	e.mu.Unlock()
	for len(e.free) > 0 {
		<-e.free
	}
	for _, b := range e.batches {
		b.next.Store(int64(b.n)) // nothing to claim until the feeder re-stages it
		e.free <- b
	}
	e.sortInflight.Store(0) // the dead server's op 3 commands are discarded with their batches
}

// divert decides, when stage 1 of b finished, whether the GPU also sorts it (op 3). The CPU threads must keep at least
// SortMinReady staged batches waiting (so the GPU sort never starves them), at most SortInflight batches are in op 3
// (so the sorted fraction follows the GPU's measured completion rate), and every GPU text length must be in range.
func (e *Engine) divert(b *batch) bool {
	if e.sortOff.Load() != 0 || e.sortPaused.Load() != 0 || e.disabled.Load() != 0 || int(e.sortInflight.Load()) >= e.cfg.SortInflight {
		return false
	}
	e.mu.Lock()
	nready := len(e.ready)
	e.mu.Unlock()
	if nready < e.cfg.SortMinReady {
		return false
	}
	for j := b.first; j < b.first+b.n; j++ {
		if l := e.dlen(j); l < 1 || l > MaxText {
			return false // the CPU path finds and handles the bad length
		}
	}
	e.sortInflight.Add(1)
	b.sorted = true
	return true
}

// sortDone handles an op 3 reply: success sends the batch to the GPU SHA (op 2); failure hands it to the CPU threads.
func (e *Engine) sortDone(b *batch, r reply) {
	if !b.sorted {
		return // not an op 3 of the current staging (cannot happen: the ring is reset on respawn)
	}
	e.sortInflight.Add(-1)
	e.sSortUs.Add(uint64(r.us))
	at := r.at
	if at == 0 {
		at = e.clock()
	}
	busy := e.busy.add(at-int64(r.us)*1000, at) // r21 merge: op 3 is charged on the wall-clock union too (gpukernels-8)
	e.sGPUBusyUs.Add(uint64(busy / 1000))
	e.charge(busy)
	if r.status != 0 { // watchdog-killed buffer or a refused text: the texts are intact, the CPU sorts them
		e.sSortFails.Add(1)
		b.sorted = false
		e.makeReady(b)
		return
	}
	b.next.Store(int64(b.n)) // nothing for TryWork to claim
	if e.cfg.Stale != nil && e.cfg.Stale(b.work.Tag) {
		e.dropRange(b, 0, b.n)
		return
	}
	e.sGPUSorted.Add(uint64(b.n))
	e.sHashed.Add(uint64(b.n))
	if e.cfg.Counted != nil {
		e.cfg.Counted(b.n) // no TryWork returns these: count them in the miner's TOTAL (and so in the probe)
	}
	e.finish(b, b.n) // every slot sorted: op 2 (GPU SHA), then collect
}

// respawn replaces a dead server: pause, tear the generation down, back off, relaunch, self-test, resume.
func (e *Engine) respawn(old transport) {
	defer e.wgRespawn.Done()
	e.quiesce()
	e.lifeMu.Lock()
	close(e.genQuit)
	e.lifeMu.Unlock()
	e.wgFeed.Wait()
	old.kill()
	old.close()
	e.resetRing()
	mk := e.cfg.transport
	if mk == nil {
		mk = procTransport
	}
	for {
		if e.disabled.Load() != 0 {
			return
		}
		e.lifeMu.Lock()
		d := e.nextBackoff(time.Now())
		e.lifeMu.Unlock()
		n := e.sRestarts.Add(1)
		e.cfg.Logf("GPU split server exited; restart #%d in %s", n, d)
		select {
		case <-e.quit:
			return
		case <-time.After(d):
		}
		tr, err := mk(e)
		if err == nil {
			e.tr = tr // nothing else uses e.tr while paused with the generation stopped
			e.live.Store(tr)
			e.gen.Add(1)
			e.failRun.Store(0)
			err = e.SelfTest(e.selfTestN, astropair.NewScratch())
			if err != nil {
				tr.kill()
				tr.close()
			}
		}
		if e.respawnHook != nil {
			e.respawnHook()
		}
		if errors.Is(err, ErrNotBitExact) {
			e.Disable("self-test after a server restart: " + err.Error())
			return
		}
		if err != nil {
			e.cfg.Logf("GPU split server restart #%d failed: %v", n, err)
			continue
		}
		e.lifeMu.Lock()
		select {
		case <-e.quit:
			e.lifeMu.Unlock()
			tr.kill()
			tr.close()
			return
		default:
		}
		e.lastStart = time.Now()
		e.startGeneration()
		e.paused.Store(0)
		e.lifeMu.Unlock()
		e.cfg.Logf("GPU split server restarted (#%d); self-test passed, staging resumed", n)
		return
	}
}

func (e *Engine) release(b *batch) {
	e.sBatches.Add(1)
	select {
	case e.free <- b:
	default: // cannot happen: the ring holds exactly Depth batches
	}
}

// collect reports the GPU-SHA hashes of a sorted batch and queues one of them for the audit.
func (e *Engine) collect(b *batch) {
	t0 := time.Now()
	defer func() { e.sCollectNs.Add(uint64(time.Since(t0))) }() // ns: a ~15 us collect would lose ~7% to us truncation
	audit := -1
	for i := 0; i < b.n; i++ {
		if atomic.LoadUint32(&b.skip[i]) != 0 {
			continue
		}
		j := b.first + i
		h := e.out(j)
		if audit < 0 && !e.cfg.noAudit {
			audit = j
			var a auditReq
			copy(a.blob[:], e.msg(j))
			a.h, a.gen, a.sorted = h, e.gen.Load(), b.sorted
			if b.sorted { // a GPU-sorted batch is always audited
				select {
				case e.auditCh <- a:
				case <-e.quit:
				}
			} else {
				select {
				case e.auditCh <- a:
				default:
				}
			}
		}
		e.cfg.Found(b.work.Tag, e.msg(j), h)
	}
}

func (e *Engine) auditor() {
	defer e.wg.Done()
	for {
		select {
		case a := <-e.auditCh:
			e.sAudited.Add(1)
			if ref := e.cfg.Reference(a.blob[:]); ref != a.h {
				if a.sorted {
					e.SortDisable(fmt.Sprintf("audit: GPU-sorted hash %x != CPU %x", a.h[:8], ref[:8]))
				} else {
					e.auditFault(fmt.Sprintf("audit: split hash %x != CPU %x", a.h[:8], ref[:8]), time.Now(), a.gen)
				}
			}
		case <-e.quit:
			return
		}
	}
}

// TryWork claims two staged nonces and finishes them (sort, plus the paired SHA when the GPU does not do it). It
// returns how many hashes it produced (0: nothing staged, or the engine is disabled — hash on the CPU instead).
func (e *Engine) TryWork(s *astropair.Scratch) int {
	e.active.Add(1) // before the paused check: respawn sets paused, then waits for active == 0
	defer e.active.Add(-1)
	if e.paused.Load() != 0 {
		return 0
	}
	for spins := 0; spins < 64; spins++ {
		if e.disabled.Load() != 0 {
			return 0
		}
		b := (*batch)(atomic.LoadPointer(&e.cur))
		if b != nil {
			if i := int(b.next.Add(2) - 2); i < b.n {
				if e.cfg.Stale != nil && e.cfg.Stale(b.work.Tag) {
					e.drop(b, i) // the job moved on: the rest of this batch is worthless
					continue
				}
				return e.pair(b, i, s)
			}
		}
		if !e.advance(b) {
			e.sIdleTries.Add(1) // nothing staged: the CPU thread hashes on its own
			return 0
		}
	}
	return 0
}

// drop: the thread holding [i, i+2) found the job stale. It drops its pair and claims and drops everything not yet
// claimed; pairs other threads already hold finish (or drop) on their own.
func (e *Engine) drop(b *batch, i int) {
	e.dropRange(b, i, imin(i+2, b.n))
	for {
		cur := int(b.next.Load())
		if cur >= b.n {
			return
		}
		if b.next.CompareAndSwap(int64(cur), int64(b.n)) {
			e.dropRange(b, cur, b.n)
			return
		}
	}
}

func (e *Engine) dropRange(b *batch, from, to int) {
	if b.skip != nil {
		for x := from; x < to; x++ {
			atomic.StoreUint32(&b.skip[x], 1)
		}
	}
	b.dropped.Add(int64(to - from))
	e.sDropped.Add(uint64(to - from))
	e.finish(b, to-from)
}

func (e *Engine) advance(old *batch) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if (*batch)(atomic.LoadPointer(&e.cur)) != old {
		return true // someone else advanced; retry
	}
	if len(e.ready) == 0 {
		if old != nil {
			atomic.StorePointer(&e.cur, nil)
		}
		return false
	}
	atomic.StorePointer(&e.cur, unsafe.Pointer(e.ready[0]))
	e.ready = e.ready[1:]
	return true
}

func (e *Engine) pair(b *batch, i int, s *astropair.Scratch) int {
	ja, jb := b.first+i, b.first+i+1
	tag := b.work.Tag
	la, lb := e.dlen(ja), e.dlen(jb)
	if la < 1 || la > MaxText || lb < 1 || lb > MaxText {
		e.Disable(fmt.Sprintf("GPU text length out of range (%d, %d)", la, lb))
		e.cpuFinish(b, ja, tag)
		e.cpuFinish(b, jb, tag)
		e.finish(b, 2)
		return 2
	}
	if e.cfg.GPUSHA {
		for _, j := range [2]int{ja, jb} {
			if !astropair.SortOnly(e.text(j, e.dlen(j)), e.sa(j)) {
				e.cpuFinish(b, j, tag)
			}
		}
		e.sHashed.Add(2)
		e.finish(b, 2)
		return 2
	}
	ha, hb, ok := astropair.SortSum2(e.text(ja, la), e.text(jb, lb), s)
	if !ok {
		e.Disable("the split sort/SHA recovered a panic; the pair was re-hashed on the CPU")
		ha, hb = astrobwtv3.AstroBWTv3(e.msg(ja)), astrobwtv3.AstroBWTv3(e.msg(jb))
	} else if ae := e.cfg.AuditEvery; ae > 0 && e.auditN.Add(2)%ae < 2 {
		e.sAudited.Add(1)
		if ref := e.cfg.Reference(e.msg(ja)); ref != ha {
			e.auditFault(fmt.Sprintf("audit: split hash %x != CPU %x", ha[:8], ref[:8]), time.Now(), e.gen.Load())
			ha, hb = ref, e.cfg.Reference(e.msg(jb))
		}
	}
	e.sHashed.Add(2)
	e.cfg.Found(tag, e.msg(ja), ha)
	e.cfg.Found(tag, e.msg(jb), hb)
	e.finish(b, 2)
	return 2
}

// cpuFinish hashes slot j on the CPU from its blob (the GPU text is not used) and reports it.
func (e *Engine) cpuFinish(b *batch, j int, tag interface{}) {
	h := astrobwtv3.AstroBWTv3(e.msg(j))
	if b.skip != nil {
		atomic.StoreUint32(&b.skip[j-b.first], 1)
	}
	e.sCPUFinished.Add(1)
	e.cfg.Found(tag, e.msg(j), h)
}

// staleQuiet is finish()'s verdict: Config.StaleQuiet when set (the miner's counters see each drop once, in TryWork),
// else Stale.
func (e *Engine) staleQuiet(tag interface{}) bool {
	if e.cfg.StaleQuiet != nil {
		return e.cfg.StaleQuiet(tag)
	}
	return e.cfg.Stale != nil && e.cfg.Stale(tag)
}

func (e *Engine) finish(b *batch, k int) {
	if b.done.Add(int64(k)) != int64(b.n) {
		return
	}
	if e.cfg.GPUSHA && b.dropped.Load() < int64(b.n) {
		// r22 splitpipe: the job went stale while this batch was being sorted (normally the thread that found it so
		// dropped the unclaimed rest): every hash op 2 would produce belongs to a job whose shares are orphans or
		// rejected, the verdict that drops staged texts. Skip the GPU SHA (op 2 always runs over the whole batch, dropped
		// slots included) and free the slot. Stale is two atomic loads while the job is unchanged.
		if e.staleQuiet(b.work.Tag) {
			e.sStaleSHASkipped.Add(uint64(int64(b.n) - b.dropped.Load()))
			e.release(b)
			return
		}
		if err := e.tr.issue(2, uint32(b.first), uint32(b.n), b.id); err != nil {
			e.serverFailed(e.tr, err)
		}
		return
	}
	e.release(b)
}

// auditFault handles one audited hash that differs from the CPU reference. AuditStrikes of them inside
// AuditStrikeWindow disable the engine; fewer restart the server so the bit-exact SelfTest decides (a mismatch there
// disables it). Winning shares are re-hashed on the CPU before submission either way (gpu_split.go).
//
// One server takes at most one strike: hashes it produced before its restart (already queued for the audit) are
// counted in AuditFaults but do not strike again.
func (e *Engine) auditFault(why string, now time.Time, gen uint64) {
	e.sAuditFaults.Add(1)
	e.strikeMu.Lock()
	if gen != 0 && gen <= e.struckGen {
		e.strikeMu.Unlock()
		return
	}
	if gen > e.struckGen {
		e.struckGen = gen
	}
	keep := e.strikes[:0]
	for _, t := range e.strikes {
		if now.Sub(t) < e.cfg.AuditStrikeWindow {
			keep = append(keep, t)
		}
	}
	e.strikes = append(keep, now)
	n := len(e.strikes)
	e.strikeMu.Unlock()
	if n >= e.cfg.AuditStrikes {
		e.Disable(fmt.Sprintf("%s (%d audit differences within %s)", why, n, e.cfg.AuditStrikeWindow))
		return
	}
	e.cfg.Logf("GPU split %s: restarting the GPU server and re-running the bit-exact self-test (strike %d of %d)", why, n, e.cfg.AuditStrikes)
	if tr, ok := e.live.Load().(transport); ok {
		tr.kill() // the reply loop sees the server exit and respawns it; the respawn re-runs the SelfTest
	}
}

// Disable stops staging for good; TryWork returns 0 from now on and the miner hashes on the CPU alone.
func (e *Engine) Disable(why string) {
	if e.disabled.CompareAndSwap(0, 1) {
		e.reason.Store(why)
		e.cfg.Logf("GPU split mode DISABLED: %s", why)
	}
}

func (e *Engine) Disabled() bool { return e.disabled.Load() != 0 }

// SortDisable turns the GPU sort off for good; staging and the CPU sort carry on.
func (e *Engine) SortDisable(why string) {
	if e.sortOff.CompareAndSwap(0, 1) || e.sortReason.Load() == nil {
		e.sortReason.Store(why)
		e.cfg.Logf("GPU sort DISABLED: %s", why)
	}
}

// sortProber runs sortProbeRound now and then every SortProbeEvery until Close or a permanent SortDisable.
func (e *Engine) sortProber() {
	defer e.wg.Done()
	for {
		if !e.sortProbeRound(e.quit) {
			return
		}
		select {
		case <-e.quit:
			return
		case <-time.After(e.cfg.SortProbeEvery):
		}
	}
}

// probeCount is the production counter the A/B probe compares.
func (e *Engine) probeCount() uint64 {
	if e.cfg.ProbeCount != nil {
		return e.cfg.ProbeCount()
	}
	return e.sHashed.Load()
}

// sortProbeRound measures SortProbePairs ABBA pairs (paused, allowed, allowed, paused, ...) of SortProbe windows and
// leaves the GPU sort allowed only if sortProbeKeep says so. false: stop probing (closed, or the sort is off for good).
func (e *Engine) sortProbeRound(quit <-chan struct{}) bool {
	var on, off uint64
	for i := 0; i < 2*e.cfg.SortProbePairs; i++ {
		if e.sortOff.Load() != 0 {
			return false
		}
		allowed := i%4 == 1 || i%4 == 2 // ABBA cancels a linear drift in the base rate
		if allowed {
			e.sortPaused.Store(0)
		} else {
			e.sortPaused.Store(1)
		}
		c0 := e.probeCount()
		select {
		case <-quit:
			e.sortPaused.Store(0)
			return false
		case <-time.After(e.cfg.SortProbe):
		}
		d := e.probeCount() - c0
		if allowed {
			on += d
		} else {
			off += d
		}
	}
	keep := sortProbeKeep(on, off)
	v := fmt.Sprintf("allowed %d vs paused %d hashes over %d x %s window pairs: GPU sort ", on, off, e.cfg.SortProbePairs, e.cfg.SortProbe)
	if keep {
		e.sortPaused.Store(0)
		v += "KEPT"
	} else {
		e.sortPaused.Store(1)
		v += "PAUSED (net loss: the GPU has no time to spare for it)"
	}
	e.sortVerdict.Store(v)
	e.cfg.Logf("GPU sort probe: %s", v)
	return true
}

// sortProbeKeep: allow the GPU sort only if it strictly increased production (ties pause it: the sort costs GPU power
// and an audit queue for nothing).
func sortProbeKeep(on, off uint64) bool { return on > off }

// SortPaused reports whether the A/B probe currently holds the GPU sort paused.
func (e *Engine) SortPaused() bool { return e.sortPaused.Load() != 0 }

// Sorting reports whether the GPU sort is on.
func (e *Engine) Sorting() bool { return e.sortOff.Load() == 0 }

func (e *Engine) Stats() Stats {
	s := Stats{Hashed: e.sHashed.Load(), Dropped: e.sDropped.Load(), CPUFinished: e.sCPUFinished.Load(), Audited: e.sAudited.Load(),
		Batches: e.sBatches.Load(), GPUus: e.sGPUus.Load(), GPUBusyUs: e.sGPUBusyUs.Load(), GPURetries: e.sRetries.Load(), Restarts: e.sRestarts.Load(),
		S1us: e.sS1us.Load(), S1Cmds: e.sS1n.Load(), SHAus: e.sSHAus.Load(), SHACmds: e.sSHAn.Load(),
		IdleTries: e.sIdleTries.Load(), FeedWaitUs: e.sFeedWaitUs.Load(), FeedWaitBacklogUs: e.sFeedWaitBacklogUs.Load(),
		AuditFaults: e.sAuditFaults.Load(),
		GPUSorted:   e.sGPUSorted.Load(), SortFails: e.sSortFails.Load(), SortUs: e.sSortUs.Load(),
		ThrottleUs: e.sThrottleUs.Load(), CollectUs: e.sCollectNs.Load() / 1000, StaleSHASkipped: e.sStaleSHASkipped.Load(), GPUMax: e.GPUMax()}
	if r, _ := e.reason.Load().(string); r != "" {
		s.Disabled = r
	}
	if r, _ := e.sortReason.Load().(string); r != "" {
		s.SortOff = r
	}
	if v, _ := e.sortVerdict.Load().(string); v != "" {
		s.SortProbe = v
	}
	return s
}

// Close stops the engine and the server. Callers must not use TryWork afterwards.
func (e *Engine) Close() {
	e.lifeMu.Lock()
	select {
	case <-e.quit:
		e.lifeMu.Unlock()
		return
	default:
	}
	e.disabled.CompareAndSwap(0, 1)
	close(e.quit) // under lifeMu: no respawn starts after this, a running one aborts before installing a server
	e.lifeMu.Unlock()
	e.wgRespawn.Wait()
	e.wgFeed.Wait() // the feeder and retries no longer issue commands
	e.wg.Wait()
	e.tr.close()
	e.wgReply.Wait()
	e.unmap()
}

// ---- the real transport: gpu_split_server over two pipes, texts in shared memory ----

type proc struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	mu  sync.Mutex
	ch  chan reply
}

func procTransport(e *Engine) (transport, error) {
	bin, err := filepath.Abs(e.cfg.Bin)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(bin); err != nil {
		return nil, fmt.Errorf("gpu split server not found (cd gpu-miner-poc && xcrun swiftc -O gpu_split_server.swift -o gpu_split_server): %w", err)
	}
	if e.mem == nil { // a respawned server maps the same shared memory
		mem, f, err := newShm(e.lay.Size)
		if err != nil {
			return nil, err
		}
		e.mem, e.shmF = mem, f
	}
	f := e.shmF
	l := e.lay
	sstride := 0 // no suffix-array region: the server refuses op 2
	if e.cfg.GPUSHA {
		sstride = SStride
	}
	p := &proc{ch: make(chan reply, 4*e.cfg.Depth)}
	args := []string{fmt.Sprint(l.OffMsgs), fmt.Sprint(l.OffLens), fmt.Sprint(l.OffOuts), fmt.Sprint(l.OffDatas),
		fmt.Sprint(l.OffSas), fmt.Sprint(DStride), fmt.Sprint(sstride), fmt.Sprint(l.Slots), fmt.Sprint(e.cfg.Inflight)}
	if e.sortOff.Load() == 0 { // op 3 lanes; a server that predates them ignores the extra arguments and refuses op 3
		args = append(args, fmt.Sprint(e.cfg.SortLanes), fmt.Sprint(e.cfg.SortChunk))
	}
	p.cmd = exec.Command(bin, args...)
	p.cmd.Dir = filepath.Dir(bin)
	p.cmd.Stderr = os.Stderr
	p.cmd.ExtraFiles = []*os.File{f} // fd 3 in the server
	if p.in, err = p.cmd.StdinPipe(); err != nil {
		return nil, err
	}
	out, err := p.cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := p.cmd.Start(); err != nil {
		return nil, err
	}
	go func() {
		r := bufio.NewReaderSize(out, 4096)
		var b [16]byte
		for {
			if _, err := io.ReadFull(r, b[:]); err != nil {
				close(p.ch)
				p.cmd.Wait()
				return
			}
			p.ch <- reply{binary.LittleEndian.Uint32(b[0:]), binary.LittleEndian.Uint32(b[4:]), binary.LittleEndian.Uint32(b[8:]), binary.LittleEndian.Uint32(b[12:]), e.clock()}
		}
	}()
	return p, nil
}

func (p *proc) issue(op, first, n, tag uint32) error {
	var b [16]byte
	binary.LittleEndian.PutUint32(b[0:], op)
	binary.LittleEndian.PutUint32(b[4:], first)
	binary.LittleEndian.PutUint32(b[8:], n)
	binary.LittleEndian.PutUint32(b[12:], tag)
	p.mu.Lock()
	defer p.mu.Unlock()
	_, err := p.in.Write(b[:])
	return err
}

func (p *proc) replies() <-chan reply { return p.ch }

// kill ends the server at once; the reader goroutine then sees EOF, closes the channel and reaps the process.
func (p *proc) kill() {
	if p.cmd.Process != nil {
		p.cmd.Process.Kill()
	}
}

// close: EOF on stdin makes the server drain its in-flight buffers and exit; the reader then closes the channel.
func (p *proc) close() {
	p.mu.Lock()
	p.in.Close()
	p.mu.Unlock()
	done := make(chan struct{})
	go func() {
		for range p.ch {
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		p.cmd.Process.Kill()
		<-done
	}
}
