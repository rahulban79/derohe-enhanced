package main

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/rpc"
)

// The test binary doubles as a fake full-hash server (no Metal): with DERO_FAKE_GPU_SERVER=1 it speaks the server
// protocol on stdin/stdout, hashing with astrobwtv3.AstroBWTv3, and can be told to exit after N requests or to answer
// with wrong hashes. FAKE_GPU_STATE names a file counting server starts (FAKE_GPU_WRONG_FROM: wrong from that start on).
func TestMain(m *testing.M) {
	if os.Getenv("DERO_FAKE_GPU_SERVER") == "1" {
		fakeGPUServer()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fakeGPUServer() {
	gen := 1
	if st := os.Getenv("FAKE_GPU_STATE"); st != "" {
		b, _ := os.ReadFile(st)
		gen, _ = strconv.Atoi(string(b))
		gen++
		os.WriteFile(st, []byte(strconv.Itoa(gen)), 0600)
	}
	exitAfter, _ := strconv.Atoi(os.Getenv("FAKE_GPU_EXIT_AFTER"))
	wrong := os.Getenv("FAKE_GPU_WRONG") == "1"
	if from, err := strconv.Atoi(os.Getenv("FAKE_GPU_WRONG_FROM")); err == nil && gen >= from {
		wrong = true
	}
	for req := 0; ; req++ {
		if exitAfter > 0 && req >= exitAfter {
			os.Exit(3) // the "watchdog" kills the server: the miner sees EOF
		}
		var hdr [4]byte
		if _, err := io.ReadFull(os.Stdin, hdr[:]); err != nil {
			return
		}
		n := int(binary.LittleEndian.Uint32(hdr[:]))
		blobs := make([]byte, n*block.MINIBLOCK_SIZE)
		if _, err := io.ReadFull(os.Stdin, blobs); err != nil {
			return
		}
		out := make([]byte, 0, n*32)
		for j := 0; j < n; j++ {
			h := astrobwtv3.AstroBWTv3(blobs[j*block.MINIBLOCK_SIZE : (j+1)*block.MINIBLOCK_SIZE])
			if wrong {
				h[3] ^= 0x10
			}
			out = append(out, h[:]...)
		}
		if _, err := os.Stdout.Write(out); err != nil {
			return
		}
	}
}

func setGPUTestJob() {
	blob := make([]byte, block.MINIBLOCK_SIZE)
	for i := range blob {
		blob[i] = byte(i*3 + 7)
	}
	blob[0] = 0x41 // version 1
	mutex.Lock()
	job = rpc.GetBlockTemplate_Result{Height: 100, Blockhashing_blob: hex.EncodeToString(blob), Difficulty: "1000000000000000000000000000000000000", JobID: "gpu-test"}
	mutex.Unlock()
	atomic.AddInt64(&job_counter, 1)
}

func fakeWorker(t *testing.T) (*gpuWorker, chan struct{}) {
	t.Helper()
	t.Setenv("DERO_FAKE_GPU_SERVER", "1")
	setGPUTestJob()
	w := newGPUWorker(os.Args[0], 4)
	w.sleep = func(d time.Duration) bool { // real back-off is seconds; keep the policy, shrink the clock
		select {
		case <-time.After(time.Millisecond):
			return true
		case <-w.quit:
			return false
		}
	}
	done := make(chan struct{})
	go func() { w.run(); close(done) }()
	return w, done
}

// Fix F (r18 merge): a server that dies (EOF) is reaped, relaunched and re-self-tested; mining continues.
func TestGPUWorkerRestartsDeadServer(t *testing.T) {
	t.Setenv("FAKE_GPU_EXIT_AFTER", "3") // self-test + 2 batches, then the server exits
	r0, c0 := atomic.LoadUint64(&gpu_restarts), atomic.LoadUint64(&counter)
	w, done := fakeWorker(t)
	deadline := time.Now().Add(60 * time.Second)
	for atomic.LoadUint64(&gpu_restarts)-r0 < 3 || atomic.LoadUint64(&counter)-c0 < 3*2*4 {
		select {
		case <-done:
			t.Fatalf("worker gave up after a transport failure (restarts %d)", atomic.LoadUint64(&gpu_restarts)-r0)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("restarts %d hashes %d", atomic.LoadUint64(&gpu_restarts)-r0, atomic.LoadUint64(&counter)-c0)
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(w.quit)
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("worker did not stop")
	}
	t.Logf("restarts %d, GPU hashes %d", atomic.LoadUint64(&gpu_restarts)-r0, atomic.LoadUint64(&counter)-c0)
}

// A server that answers with wrong hashes fails the self-test: GPU mining stops for good, with no restart.
func TestGPUWorkerDisablesOnMismatch(t *testing.T) {
	t.Setenv("FAKE_GPU_WRONG", "1")
	r0, c0 := atomic.LoadUint64(&gpu_restarts), atomic.LoadUint64(&counter)
	_, done := fakeWorker(t)
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("worker kept going with a non-bit-exact GPU")
	}
	if atomic.LoadUint64(&gpu_restarts) != r0 || atomic.LoadUint64(&counter) != c0 {
		t.Fatalf("restarted or mined with a wrong GPU (restarts +%d, hashes +%d)", atomic.LoadUint64(&gpu_restarts)-r0, atomic.LoadUint64(&counter)-c0)
	}
}

// A restarted server that comes back with wrong results is also caught by the re-run self-test.
func TestGPUWorkerDisablesOnMismatchAfterRestart(t *testing.T) {
	t.Setenv("FAKE_GPU_EXIT_AFTER", "3")
	t.Setenv("FAKE_GPU_WRONG_FROM", "2")
	t.Setenv("FAKE_GPU_STATE", filepath.Join(t.TempDir(), "gen"))
	r0, c0 := atomic.LoadUint64(&gpu_restarts), atomic.LoadUint64(&counter)
	_, done := fakeWorker(t)
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("worker kept going after a non-bit-exact restart")
	}
	if r := atomic.LoadUint64(&gpu_restarts) - r0; r != 1 {
		t.Fatalf("want exactly one restart, got %d", r)
	}
	if c := atomic.LoadUint64(&counter) - c0; c != 2*4 {
		t.Fatalf("want the 2 batches of the first server only, got %d hashes", c)
	}
}

func TestGPUBackoff(t *testing.T) {
	b := gpuBackoff{min: gpuRespawnMin, max: gpuRespawnMax, healthy: gpuHealthyReset}
	now := time.Now()
	b.started(now)
	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60}
	for i, w := range want {
		if d := b.next(now); d != w*time.Second {
			t.Fatalf("attempt %d: back-off %s want %s", i, d, w*time.Second)
		}
	}
	b.started(now.Add(-6 * time.Minute)) // the server then mined healthily for 6 minutes
	if d := b.next(now); d != time.Second {
		t.Fatalf("back-off not reset after a healthy period: %s", d)
	}
	if d := b.next(now); d != 2*time.Second {
		t.Fatalf("back-off did not grow within one outage: %s", d)
	}
}
