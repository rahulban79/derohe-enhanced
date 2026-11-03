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

// r20 storage observability.
//
// free_disk_space_bytes was measured on "." (the daemon's working directory), not on the volume that holds the
// chain, so a node started from a different directory, or with --data-dir on another disk, reported the wrong
// volume. SetDiskPath points it at the datadir. WatchFile exports the size of a few named files (the log, topo.map,
// the graviton version root) on every scrape, so log and store growth can be read from /metrics instead of by
// listing the datadir. Each watched file costs one stat per scrape; the list is capped at MAX_WATCHED_FILES.

import (
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
)

var disk_path atomic.Value // string

// new_disk_usage is NewDiskUsage; a variable so a test can see which path the scrape measured (r20 merge review).
var new_disk_usage = NewDiskUsage

// SetDiskPath sets the directory whose volume free_disk_space_bytes reports.
func SetDiskPath(path string) { disk_path.Store(path) }

func disk_usage_path() string {
	if p, ok := disk_path.Load().(string); ok && p != "" {
		return p
	}
	return "."
}

// MAX_WATCHED_FILES bounds WatchFile (one stat per watched file per scrape).
const MAX_WATCHED_FILES = 32

type watched_file struct{ label, path string }

var watched_mu sync.Mutex
var watched []watched_file

// WatchFile exports file_size_bytes{file="label"} for path. A repeated label replaces the path. It returns false
// when the list is full.
func WatchFile(label, path string) bool {
	watched_mu.Lock()
	defer watched_mu.Unlock()
	for i := range watched {
		if watched[i].label == label {
			watched[i].path = path
			return true
		}
	}
	if len(watched) >= MAX_WATCHED_FILES {
		return false
	}
	watched = append(watched, watched_file{label, path})
	return true
}

// write_file_sizes writes one file_size_bytes line per watched file that exists.
func write_file_sizes(w io.Writer) {
	watched_mu.Lock()
	list := append([]watched_file(nil), watched...)
	watched_mu.Unlock()
	for _, f := range list {
		if fi, err := os.Stat(f.path); err == nil && fi.Mode().IsRegular() {
			fmt.Fprintf(w, "file_size_bytes{file=%q} %d\n", f.label, fi.Size())
		}
	}
}
