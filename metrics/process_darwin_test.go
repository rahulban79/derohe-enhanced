// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//go:build darwin
// +build darwin

package metrics

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
)

func metric_value(t *testing.T, out, name string) (v float64) {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, name+" ") {
			fmt.Sscan(strings.TrimPrefix(l, name+" "), &v)
			return v
		}
	}
	t.Fatalf("%s missing", name)
	return 0
}

// r21: the CURRENT resident size follows an allocation up (the peak alone could never show a leak shrinking back or
// a steady state), and is never above the virtual size.
func TestProcessCurrentRSSDarwin(t *testing.T) {
	var b bytes.Buffer
	write_os_process_metrics(&b)
	rss0 := metric_value(t, b.String(), "process_resident_memory_bytes")
	if rss0 < 1<<20 || rss0 > metric_value(t, b.String(), "process_virtual_memory_bytes") {
		t.Fatalf("rss %v", rss0)
	}
	// a fresh anonymous mapping, not the Go heap: freed heap pages of an earlier -count run stay resident and would
	// be reused without moving RSS
	buf, err := syscall.Mmap(-1, 0, 128<<20, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Munmap(buf)
	for i := 0; i < len(buf); i += 4096 {
		buf[i] = 1
	}
	b.Reset()
	write_os_process_metrics(&b)
	rss1 := metric_value(t, b.String(), "process_resident_memory_bytes")
	if rss1-rss0 < 64<<20 { // a lower bound only: the GC and the race runtime move RSS too
		t.Fatalf("rss %v -> %v after touching 128 MiB", rss0, rss1)
	}
}

func TestParseTaskinfo(t *testing.T) {
	buf := make([]byte, proc_taskinfo_size)
	binary.LittleEndian.PutUint64(buf[0:], 7)
	binary.LittleEndian.PutUint64(buf[8:], 5)
	if v, r, ok := parse_taskinfo(buf, proc_taskinfo_size, 0); !ok || v != 7 || r != 5 {
		t.Fatal(v, r, ok)
	}
	if _, _, ok := parse_taskinfo(buf, 8, 0); ok {
		t.Fatal("a short reply must not be reported")
	}
	if _, _, ok := parse_taskinfo(buf, proc_taskinfo_size, syscall.ESRCH); ok {
		t.Fatal("a failed call must not be reported")
	}
	if _, _, ok := task_memory(os.Getpid()); !ok {
		t.Fatal("proc_pidinfo(PROC_PIDTASKINFO) failed for this process")
	}
}

// WriteProcessMetrics (used by dero-miner) has go_* and process_* and no duplicate series.
func TestWriteProcessMetricsForMiner(t *testing.T) {
	var b bytes.Buffer
	WriteProcessMetrics(&b)
	seen := map[string]int{}
	for _, l := range strings.Split(b.String(), "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		seen[strings.Fields(l)[0]]++
	}
	for _, need := range []string{"go_goroutines", "go_memstats_sys_bytes", "process_resident_memory_bytes", "process_open_fds", "process_cpu_seconds_total"} {
		if seen[need] != 1 {
			t.Errorf("%s written %d times", need, seen[need])
		}
	}
	for name, n := range seen {
		if n > 1 {
			t.Errorf("series %s written %d times", name, n)
		}
	}
}
