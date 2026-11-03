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

package metrics

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDiskPathDefaultsToCwdAndFollowsSet(t *testing.T) {
	old := disk_usage_path()
	defer SetDiskPath(old)
	SetDiskPath("")
	if p := disk_usage_path(); p != "." {
		t.Fatalf("unset disk path = %q, want .", p)
	}
	dir := t.TempDir()
	SetDiskPath(dir)
	if p := disk_usage_path(); p != dir {
		t.Fatalf("disk path = %q, want %q", p, dir)
	}
}

func TestWatchFileReportsSizeAndIsBounded(t *testing.T) {
	watched_mu.Lock()
	saved := watched
	watched = nil
	watched_mu.Unlock()
	defer func() { watched_mu.Lock(); watched = saved; watched_mu.Unlock() }()

	dir := t.TempDir()
	p := filepath.Join(dir, "x.log")
	if err := os.WriteFile(p, make([]byte, 123), 0600); err != nil {
		t.Fatal(err)
	}
	if !WatchFile("x.log", p) || !WatchFile("missing", filepath.Join(dir, "nope")) {
		t.Fatal("WatchFile refused below the cap")
	}
	var b bytes.Buffer
	write_file_sizes(&b)
	if !strings.Contains(b.String(), "file_size_bytes{file=\"x.log\"} 123\n") {
		t.Fatalf("missing size line: %q", b.String())
	}
	if strings.Contains(b.String(), "missing") {
		t.Fatalf("a missing file was exported: %q", b.String())
	}
	if err := os.WriteFile(p, make([]byte, 456), 0600); err != nil {
		t.Fatal(err)
	}
	b.Reset()
	write_file_sizes(&b)
	if !strings.Contains(b.String(), "file_size_bytes{file=\"x.log\"} 456\n") {
		t.Fatalf("size not re-read on scrape: %q", b.String())
	}
	WatchFile("x.log", p) // same label: replaces, does not grow
	for i := 0; len(watched) < MAX_WATCHED_FILES; i++ {
		WatchFile(fmt.Sprintf("f%d", i), p)
	}
	if WatchFile("one-too-many", p) {
		t.Fatalf("WatchFile accepted entry %d", MAX_WATCHED_FILES+1)
	}
	if len(watched) != MAX_WATCHED_FILES {
		t.Fatalf("watched = %d, want %d", len(watched), MAX_WATCHED_FILES)
	}
}

// TestProcessMetricsDarwin: the darwin exporter writes the CPU split, peak RSS and a live descriptor count, and
// the full metrics page has no duplicated series names.
func TestProcessMetricsDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin only; Linux/Windows use the vendored exporter")
	}
	value := func(out, name string) (v float64) {
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, name+" ") {
				fmt.Sscan(strings.TrimPrefix(l, name+" "), &v)
				return v
			}
		}
		t.Fatalf("%s missing from %q", name, out)
		return 0
	}
	var b bytes.Buffer
	write_os_process_metrics(&b)
	out := b.String()
	if rss := value(out, "process_resident_memory_peak_bytes"); rss < 1<<20 {
		t.Fatalf("peak RSS %v bytes is below 1 MiB (KiB/bytes unit mix-up?)", rss)
	}
	if value(out, "process_cpu_seconds_total") < value(out, "process_cpu_seconds_user_total") {
		t.Fatal("cpu total < user")
	}
	fds0 := value(out, "process_open_fds")
	var files []*os.File
	for i := 0; i < 10; i++ {
		f, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	b.Reset()
	write_os_process_metrics(&b)
	fds1 := value(b.String(), "process_open_fds")
	for _, f := range files {
		f.Close()
	}
	if fds1-fds0 < 10 {
		t.Fatalf("open_fds %v -> %v after opening 10 files", fds0, fds1)
	}
	if value(out, "process_max_fds") <= 0 {
		t.Fatal("max fds")
	}
	b.Reset()
	writePrometheusMetrics(&b)
	seen := map[string]int{}
	for _, l := range strings.Split(b.String(), "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		seen[strings.Fields(l)[0]]++
	}
	for name, n := range seen {
		if n > 1 {
			t.Fatalf("series %s written %d times", name, n)
		}
	}
	if seen["process_cpu_seconds_total"] != 1 {
		t.Fatal("process metrics not on the full page")
	}
}

// r20 merge (STOROPS-2 review): the scrape itself measures the SetDiskPath directory (replacing it with "." left the
// getter test green), and watched file sizes appear on the full /metrics page.
func TestScrapeUsesDiskPathAndFileSizes(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "derod.log")
	if err := os.WriteFile(f, []byte("12345"), 0600); err != nil {
		t.Fatal(err)
	}
	saved := new_disk_usage
	defer func() { new_disk_usage = saved; SetDiskPath("") }()
	var measured []string
	new_disk_usage = func(p string) *DiskUsage { measured = append(measured, p); return saved(p) }
	SetDiskPath(dir)
	WatchFile("r20-merge-test.log", f)
	var page bytes.Buffer
	writePrometheusMetrics(&page)
	if len(measured) != 1 || measured[0] != dir {
		t.Fatalf("free_disk_space_bytes measured %q, want [%q]", measured, dir)
	}
	if !strings.Contains(page.String(), `file_size_bytes{file="r20-merge-test.log"} 5`) {
		t.Fatal("watched file size missing from the /metrics page")
	}
}
