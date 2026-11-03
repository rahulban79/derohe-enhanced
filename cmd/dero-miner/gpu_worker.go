package main

// GPU mining worker (Apple Metal). Drives a persistent GPU hash-server subprocess
// (gpu-miner-poc/gpu_hash_sais built via `xcrun swiftc -O gpu_hash_sais.swift -o gpu_hash_sais`)
// that computes bit-exact AstroBWTv3 on the M1 GPU, mining batches of nonces ALONGSIDE the CPU threads.
//
// Protocol to the server: stdin [uint32 count][count*48 blob bytes] -> stdout [count*32 hash bytes].
// SAFETY: a startup self-test refuses to mine unless the GPU reproduces astrobwtv3.AstroBWTv3 exactly —
// a non-exact kernel would only submit rejected/orphaned shares (net-negative), so it stays OFF on mismatch.
//
// RESPAWN (r18 merge): the server can die while mining (EOF: the macOS GPU watchdog kills it under contention). r17
// logged "gpu: batch failed — GPU mining stopping" and never mined on the GPU again (the live hashrate dropped). Now a
// transport failure (EOF, write error, start failure, self-test IPC failure) reaps the old server, backs off (1 s
// doubling to 60 s, reset after 5 min of healthy mining), relaunches it and re-runs the bit-exact self-test before
// mining resumes. Only a self-test MISMATCH (wrong results) stops GPU mining for good.

import (
	"bufio"
	rand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/rpc"
)

// gpuBatch nonces per GPU dispatch. 4096 is the measured sweet spot (~1,167 H/s, ~3.5s/batch <<
// the ~18s job-validity window, so shares stay fresh). Larger batches hit memory pressure.
const gpuBatch = 4096

var gpu_mismatch uint64 // GPU wins the CPU re-hash rejected
var gpu_stale uint64    // GPU wins whose job was superseded (new height, or normal->final) before the batch returned
var gpu_restarts uint64 // GPU hash-server restarts after a transport failure (full and split mode report their own)

// respawn back-off for the full-hash server
const (
	gpuRespawnMin   = time.Second
	gpuRespawnMax   = 60 * time.Second
	gpuHealthyReset = 5 * time.Minute
)

// jobIsFinal reports whether a getwork blob is a FINAL miniblock job (version byte bit 5, block/miniblock.go Serialize).
func jobIsFinal(blobHex string) bool {
	if len(blobHex) < 2 {
		return false
	}
	var b [1]byte
	if _, err := hex.Decode(b[:], []byte(blobHex[:2])); err != nil {
		return false
	}
	return b[0]&0x20 != 0
}

// shareLikelyStale: a share found on job `mine` while `cur` is the daemon's current job. Stale when the height moved on
// (the block at mine.Height exists) or when the same height flipped from normal to final work (the daemon already holds
// the 9 normal miniblocks that get included first, blockchain/miner_block.go:337-339). Accounting only: the share is
// still submitted, because the final miner's node may order arrivals differently.
func shareLikelyStale(mine, cur rpc.GetBlockTemplate_Result) bool {
	if cur.Height != mine.Height {
		return cur.Height > mine.Height
	}
	return jobIsFinal(cur.Blockhashing_blob) && !jobIsFinal(mine.Blockhashing_blob)
}

// gpuHasher is one running hash server: hashBatch sends n blobs and reads n hashes; stop kills and reaps it.
type gpuHasher interface {
	hashBatch(blobs []byte, n int) ([]byte, error)
	stop()
}

// gpuProc is the real full-hash server subprocess (protocol in the file comment).
type gpuProc struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
}

func startGPUProc(bin string, batch int) (gpuHasher, error) {
	cmd := exec.Command(bin, "server")
	cmd.Dir = filepath.Dir(bin) // so the server finds loop_ops.metal.inc next to it
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("gpu: stdin pipe: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("gpu: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("gpu: cannot start server %s: %w", bin, err)
	}
	return &gpuProc{cmd: cmd, stdin: stdin, stdout: bufio.NewReaderSize(stdoutPipe, batch*32+64)}, nil
}

func (g *gpuProc) hashBatch(blobs []byte, n int) ([]byte, error) {
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(n))
	if _, err := g.stdin.Write(hdr[:]); err != nil {
		return nil, err
	}
	if _, err := g.stdin.Write(blobs[:n*block.MINIBLOCK_SIZE]); err != nil {
		return nil, err
	}
	res := make([]byte, n*32)
	if _, err := io.ReadFull(g.stdout, res); err != nil {
		return nil, err
	}
	return res, nil
}

// stop kills the server and reaps it (r17 never waited, leaving a zombie behind a dead server).
func (g *gpuProc) stop() {
	g.stdin.Close()
	if g.cmd.Process != nil {
		g.cmd.Process.Kill()
	}
	g.cmd.Wait()
}

// errGPUNotBitExact: the server answered, but with a hash that is not AstroBWTv3 — the only permanent failure.
var errGPUNotBitExact = errors.New("gpu: self-test HASH MISMATCH (would submit rejected shares)")

// gpuSelfTest: the GPU must reproduce AstroBWTv3 exactly. A transport error is returned as is (retryable).
func gpuSelfTest(h gpuHasher) error {
	var tblob [block.MINIBLOCK_SIZE]byte
	for i := range tblob {
		tblob[i] = byte(i*7 + 1)
	}
	tblob[0] = 1 // version nibble
	res, err := h.hashBatch(tblob[:], 1)
	if err != nil {
		return fmt.Errorf("gpu: self-test IPC failed: %w", err)
	}
	want := astrobwtv3.AstroBWTv3(tblob[:])
	for k := 0; k < 32; k++ {
		if res[k] != want[k] {
			return fmt.Errorf("%w: gpu %x cpu %x", errGPUNotBitExact, res[:8], want[:8])
		}
	}
	return nil
}

// gpuBackoff: restart delays doubling from min to max; a server that ran healthy for `healthy` starts again at min.
type gpuBackoff struct {
	min, max, healthy time.Duration
	cur               time.Duration
	lastStart         time.Time
}

func (b *gpuBackoff) started(now time.Time) { b.lastStart = now }

func (b *gpuBackoff) next(now time.Time) time.Duration {
	if b.cur < b.min {
		b.cur = b.min
	}
	if !b.lastStart.IsZero() && now.Sub(b.lastStart) >= b.healthy {
		b.cur = b.min
	}
	b.lastStart = time.Time{} // further attempts of this outage keep doubling
	d := b.cur
	b.cur *= 2
	if b.cur > b.max {
		b.cur = b.max
	}
	return d
}

// gpuWorker supervises the full-hash server and mines with it; start and sleep are replaceable for tests.
type gpuWorker struct {
	bin   string
	batch int
	start func() (gpuHasher, error)
	sleep func(time.Duration) bool // false: stop requested
	quit  chan struct{}
	bo    gpuBackoff

	// mining state, kept across server restarts
	random_buf [12]byte
	nonce      uint32
	gpuHashes  uint64
	rateStart  time.Time
}

func newGPUWorker(bin string, batch int) *gpuWorker {
	w := &gpuWorker{bin: bin, batch: batch, quit: make(chan struct{}),
		bo: gpuBackoff{min: gpuRespawnMin, max: gpuRespawnMax, healthy: gpuHealthyReset}}
	w.start = func() (gpuHasher, error) { return startGPUProc(w.bin, w.batch) }
	w.sleep = func(d time.Duration) bool {
		select {
		case <-time.After(d):
			return true
		case <-w.quit:
			return false
		}
	}
	rand.Read(w.random_buf[:])
	w.rateStart = time.Now()
	return w
}

func (w *gpuWorker) stopping() bool {
	select {
	case <-w.quit:
		return true
	default:
		return false
	}
}

// run starts, self-tests and mines with the server until a self-test mismatch (permanent) or quit.
func (w *gpuWorker) run() {
	for {
		h, err := w.start()
		if err == nil {
			if err = gpuSelfTest(h); errors.Is(err, errGPUNotBitExact) {
				logger.Error(err, "gpu: GPU mining DISABLED", "restarts", atomic.LoadUint64(&gpu_restarts))
				h.stop()
				return
			}
		}
		if err == nil {
			if n := atomic.LoadUint64(&gpu_restarts); n == 0 {
				logger.Info("GPU mining ACTIVE — self-test passed (bit-exact AstroBWTv3)", "batch", w.batch, "bin", w.bin)
			} else {
				logger.Info("GPU mining RESUMED — restarted server passed the bit-exact self-test", "restarts", n, "bin", w.bin)
			}
			w.bo.started(time.Now())
			err = w.mine(h)
			h.stop()
			if err == nil {
				return // quit
			}
			logger.Error(err, "gpu: hash server failed — restarting it")
		} else {
			if h != nil {
				h.stop()
			}
			logger.Error(err, "gpu: hash server start/self-test failed — retrying")
		}
		d := w.bo.next(time.Now())
		n := atomic.AddUint64(&gpu_restarts, 1)
		logger.Info("gpu: restarting hash server", "restart", n, "backoff", d.String())
		if !w.sleep(d) {
			return
		}
	}
}

func mineblock_gpu(gpuBin string) {
	bin, err := filepath.Abs(gpuBin)
	if err != nil {
		logger.Error(err, "gpu: bad --gpu binary path", "path", gpuBin)
		return
	}
	if _, err := os.Stat(bin); err != nil {
		logger.Error(err, "gpu: binary not found (build it: cd gpu-miner-poc && xcrun swiftc -O gpu_hash_sais.swift -o gpu_hash_sais)", "path", bin)
		return
	}
	check_gpu_binary(bin)
	atomic.StoreInt32(&gpu_full_active, 1)
	defer atomic.StoreInt32(&gpu_full_active, 0)
	newGPUWorker(bin, gpuBatch).run()
}

var gpu_full_active int32 // 1 while the full-hash GPU worker runs (run ledger gpu_mode)

func gpu_full_running() bool { return atomic.LoadInt32(&gpu_full_active) == 1 }

// mine hashes batches with h until h fails (the error is returned; run restarts the server) or quit (nil).
func (w *gpuWorker) mine(h gpuHasher) error {
	gpuBatch := w.batch
	var work [block.MINIBLOCK_SIZE]byte
	nonce_off := block.MINIBLOCK_SIZE - 5
	blobs := make([]byte, gpuBatch*block.MINIBLOCK_SIZE)
	var diff big.Int
	var local_job_counter int64

	// DEBUG (env GPU_FINDTEST=1): count GPU hashes beating an EASY target to prove the find-path works,
	// + track job-change rate (staleness) + real batch duration. Zero cost when the env is unset.
	findtest := os.Getenv("GPU_FINDTEST") != ""
	var easyDiff big.Int
	easyDiff.SetString("2000", 10)
	var easyHits, jobChanges, batchCount uint64
	var batchDurSum time.Duration
	prevJC := local_job_counter

	for {
		if w.stopping() {
			return nil
		}
		mutex.RLock()
		myjob := job
		local_job_counter = job_counter
		mutex.RUnlock()
		if findtest && local_job_counter != prevJC {
			jobChanges += uint64(local_job_counter - prevJC)
			prevJC = local_job_counter
		}

		if !decode_job_blob(&work, myjob.Blockhashing_blob) { // r21: no panic on a long blob (job_guard.go)
			if !w.sleep(time.Second) {
				return nil
			}
			continue
		}
		if work[0]&0xf != 1 { // version check, same as CPU path
			if !w.sleep(time.Second) {
				return nil
			}
			continue
		}
		diff.SetString(myjob.Difficulty, 10)
		copy(work[block.MINIBLOCK_SIZE-12:], w.random_buf[:])
		work[block.MINIBLOCK_SIZE-1] = 0xff // GPU marker (CPU tids are 0..threads-1 < 255)

		for local_job_counter == atomic.LoadInt64(&job_counter) {
			if w.stopping() {
				return nil
			}
			batchStart := time.Now()
			for j := 0; j < gpuBatch; j++ {
				copy(blobs[j*block.MINIBLOCK_SIZE:], work[:])
				binary.BigEndian.PutUint32(blobs[j*block.MINIBLOCK_SIZE+nonce_off:], w.nonce+uint32(j))
			}
			w.nonce += uint32(gpuBatch)

			res, err := h.hashBatch(blobs, gpuBatch)
			if err != nil {
				return fmt.Errorf("gpu: batch failed: %w", err)
			}
			atomic.AddUint64(&counter, uint64(gpuBatch))
			w.gpuHashes += uint64(gpuBatch)
			if findtest {
				batchDurSum += time.Since(batchStart)
				batchCount++
			}
			if el := time.Since(w.rateStart); el >= 15*time.Second {
				if findtest {
					avgMs := 0.0
					if batchCount > 0 {
						avgMs = float64(batchDurSum.Milliseconds()) / float64(batchCount)
					}
					logger.Info("GPU FINDTEST", "H/s", fmt.Sprintf("%.0f", float64(w.gpuHashes)/el.Seconds()),
						"easy_hits_diff2000", easyHits, "expected_easy", w.gpuHashes/2000,
						"job_changes_15s", jobChanges, "avg_batch_ms", fmt.Sprintf("%.0f", avgMs))
					easyHits, jobChanges, batchDurSum, batchCount = 0, 0, 0, 0
				} else {
					logger.Info("GPU hashrate", "H/s", fmt.Sprintf("%.0f", float64(w.gpuHashes)/el.Seconds()), "batches", w.gpuHashes/uint64(gpuBatch),
						"gpu_cpu_mismatch", atomic.LoadUint64(&gpu_mismatch), "gpu_stale_wins", atomic.LoadUint64(&gpu_stale),
						"restarts", atomic.LoadUint64(&gpu_restarts), "cpu", fast_sort_status())
				}
				w.gpuHashes = 0
				w.rateStart = time.Now()
			}

			for j := 0; j < gpuBatch; j++ {
				var h [32]byte
				copy(h[:], res[j*32:j*32+32])
				if findtest && CheckPowHashBig(h, &easyDiff) {
					easyHits++
				}
				if CheckPowHashBig(h, &diff) {
					blob := make([]byte, block.MINIBLOCK_SIZE)
					copy(blob, blobs[j*block.MINIBLOCK_SIZE:(j+1)*block.MINIBLOCK_SIZE])
					// re-hash every GPU win on the CPU before submitting: a GPU result that
					// disagrees would be a rejected share at best. Wins are rare, so the cost is negligible.
					if cpu := astrobwtv3.AstroBWTv3(blob); cpu != h || !CheckPowHashBig(cpu, &diff) {
						atomic.AddUint64(&gpu_mismatch, 1)
						logger.Error(nil, "GPU hash disagrees with the CPU; not submitting", "gpu", fmt.Sprintf("%x", h), "cpu", fmt.Sprintf("%x", cpu))
						continue
					}
					atomic.AddUint64(&gpu_minis, 1)
					mutex.RLock()
					cur := job
					mutex.RUnlock()
					stale := shareLikelyStale(myjob, cur)
					if stale {
						atomic.AddUint64(&gpu_stale, 1)
					}
					logger.V(1).Info("GPU found DERO miniblock (submitting)", "difficulty", myjob.Difficulty, "height", myjob.Height,
						"job_age_ms", time.Since(batchStart).Milliseconds(), "likely_stale", stale)
					submitShare(myjob.JobID, fmt.Sprintf("%x", blob), 'G')
				}
			}
			if gm := gpu_duty_pct(); gm < 100 { // GPU duty-cycle throttle (parity with --cpu-max; r22: the cap in force)
				if busy := time.Since(batchStart); busy > 0 {
					if !w.sleep(busy * time.Duration(100-gm) / time.Duration(gm)) {
						return nil
					}
				}
			}
		}
	}
}
