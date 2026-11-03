package gsplit

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deroproject/derohe/cmd/dero-miner/astropair"
)

// server_footprint_mb reads the physical footprint (top's MEM, whole MB) of pid without attaching to it.
func server_footprint_mb(t *testing.T, pid int) float64 {
	out, err := exec.Command("top", "-l", "1", "-pid", strconv.Itoa(pid), "-stats", "mem").Output()
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(out))
	v := f[len(f)-1]
	mult := 1.0
	switch {
	case strings.HasSuffix(v, "K"):
		mult = 1.0 / 1024
	case strings.HasSuffix(v, "G"):
		mult = 1024
	}
	n, err := strconv.ParseFloat(strings.TrimRight(v, "KMGB+-"), 64)
	if err != nil {
		t.Fatalf("top MEM %q: %v", v, err)
	}
	return n * mult
}

// r21 (storageops): the live gpu_split_server's footprint grew ~21 MB/h because its command loop never drained the
// main thread's autorelease pool. Issue many tiny commands (op 2 on 64 slots: microseconds of GPU time each) and
// require the footprint to stay flat. GSPLIT_BIN overrides the binary for an A/B against an older build.
func TestRealServerFootprintFlat(t *testing.T) {
	bin := realBin(t)
	if b := os.Getenv("GSPLIT_BIN"); b != "" {
		bin = b
	}
	e, err := New(Config{Bin: bin, Batch: 256, Depth: 2, Inflight: 2, GPUSHA: true, GPUMax: 100, AuditEvery: 64,
		Next: func() (Work, bool) { return Work{Tag: 0}, true }, Found: func(interface{}, []byte, [32]byte) {}, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := e.SelfTest(64, astropair.NewScratch()); err != nil { // bit-exact through the real kernels first
		t.Fatal(err)
	}
	p, ok := e.tr.(*proc)
	if !ok {
		t.Skip("not a process transport")
	}
	pid := p.cmd.Process.Pid
	budget := 30 * time.Second
	if v := os.Getenv("GSPLIT_LEAK_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			budget = time.Duration(n) * time.Second
		}
	}
	// pipelined: keep Inflight commands outstanding; the live miner shares the GPU, so the count is what fits in budget
	run := func(d time.Duration) int {
		n, out := 0, 0
		end := time.Now().Add(d)
		for time.Now().Before(end) || out > 0 {
			for out < e.cfg.Inflight && time.Now().Before(end) {
				if err := p.issue(2, 0, 64, uint32(n)); err != nil {
					t.Fatal(err)
				}
				out++
				n++
			}
			r, ok := <-p.replies()
			if !ok || r.status != 0 {
				t.Fatalf("server reply %+v ok=%v", r, ok)
			}
			out--
		}
		return n
	}
	run(3 * time.Second) // warm-up: pipeline caches, first allocations
	before := server_footprint_mb(t, pid)
	n := run(budget)
	after := server_footprint_mb(t, pid)
	per := (after - before) * 1048576 / float64(n)
	t.Logf("%s: footprint %.1f -> %.1f MB over %d commands in %v (%.0f B/command)", bin, before, after, n, budget, per)
	if n < 20000 {
		t.Skipf("only %d commands in %v (GPU shared with the live miner): 1 MB footprint resolution is too coarse", n, budget)
	}
	if per > 32 {
		t.Fatalf("footprint grows %.0f B per command: %s", per, fmt.Sprint(bin))
	}
}
