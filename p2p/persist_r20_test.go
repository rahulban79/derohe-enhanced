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

package p2p

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestPersistSyncsDirAfterRename: write_json_atomic_with must fsync the file's own directory, once, after the
// rename (the new content is already in place when the hook runs).
func TestPersistSyncsDirAfterRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers.json")
	var synced []string
	err := write_json_atomic_with(path, map[string]int{"a": 1}, func(d string) error {
		if b, err := os.ReadFile(path); err != nil || len(b) == 0 {
			t.Fatalf("dir synced before the rename: %v", err)
		}
		synced = append(synced, d)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(synced) != 1 || synced[0] != dir {
		t.Fatalf("directory sync calls = %v, want exactly [%s]", synced, dir)
	}
	if err := sync_dir(dir); err != nil {
		t.Fatalf("sync_dir on a real directory: %v", err)
	}
	if err := sync_dir(filepath.Join(dir, "missing")); err == nil && !windows_like() {
		t.Fatalf("sync_dir on a missing directory returned nil")
	}
}

func windows_like() bool { return filepath.Separator == '\\' }

// TestSweepStaleTmp: only old <name>.tmp-* files of the persisted lists are removed; fresh ones (a save in flight),
// the lists themselves and unrelated files stay.
func TestSweepStaleTmp(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	old := now.Add(-10 * time.Minute)
	mk := func(name string, mtime time.Time) {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	mk("peers.json", old)
	mk("peers.json.tmp-111", old)       // stale: removed
	mk("ban_list.json.tmp-222", old)    // stale: removed
	mk("first_relay.json.tmp-333", old) // stale: removed
	mk("v2_offences.json.tmp-444", old) // stale: removed
	mk("peers.json.tmp-555", now)       // in flight: kept
	mk("other.json.tmp-666", old)       // not ours: kept
	mk("peers.jsonX.tmp-777", old)      // prefix mismatch: kept
	if n := sweep_persist_tmp(dir, now); n != 4 {
		t.Fatalf("removed %d, want 4", n)
	}
	for _, keep := range []string{"peers.json", "peers.json.tmp-555", "other.json.tmp-666", "peers.jsonX.tmp-777"} {
		if _, err := os.Stat(filepath.Join(dir, keep)); err != nil {
			t.Fatalf("%s was removed: %v", keep, err)
		}
	}
	if n := sweep_persist_tmp(dir, now); n != 0 {
		t.Fatalf("second sweep removed %d", n)
	}
}
