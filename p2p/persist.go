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

// Crash-safe persistence of the peer and ban lists.
//
// Upstream rewrote peers.json and ban_list.json in place (os.Create truncates, then the encoder writes), so a
// kill between the two left an empty or partial file. Since the 5-minute snapshot (controller.go persist ticker)
// writes them 288 times a day, write to a temporary file, fsync it, and rename it over the original instead:
// a reader sees either the old list or the new one, never half of one.

//
// r20: the rename is now followed by an fsync of the directory (the rename itself is only durable once the directory
// entry is on disk; without it a power loss shortly after a save can bring back the previous list), and a kill -9
// between CreateTemp and Rename no longer leaves <name>.tmp-* files in the datadir forever: P2P_Init sweeps them
// (sweep_stale_tmp, only files older than STALE_TMP_AGE, so a save in flight in another process is never touched).

import "bytes"
import "encoding/json"
import "os"
import "path/filepath"
import "runtime"
import "strings"
import "time"

// STALE_TMP_AGE: a temp file younger than this may belong to a save that is still running.
const STALE_TMP_AGE = 2 * time.Minute

// PERSISTED_FILES are the datadir files written through write_json_atomic.
var PERSISTED_FILES = []string{"peers.json", "ban_list.json", V2_OFFENCES_FILE, FIRST_RELAY_FILE}

func write_json_atomic(path string, v interface{}) error {
	return write_json_atomic_with(path, v, sync_dir)
}

// sync_dir fsyncs a directory so a completed rename inside it survives a power loss. Windows cannot open a
// directory for sync (and NTFS journals the rename), so it is a no-op there.
func sync_dir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

// sweep_stale_tmp removes <base>.tmp-* files next to path whose modification time is older than age, and returns
// how many it removed. Only the exact prefix write_json_atomic uses is matched.
func sweep_stale_tmp(path string, age time.Duration, now time.Time) (removed int) {
	dir, prefix := filepath.Dir(path), filepath.Base(path)+".tmp-"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		info, err := e.Info()
		if err != nil || now.Sub(info.ModTime()) < age {
			continue
		}
		if os.Remove(filepath.Join(dir, e.Name())) == nil {
			removed++
		}
	}
	return removed
}

// sweep_persist_tmp runs sweep_stale_tmp for every file in PERSISTED_FILES under datadir.
func sweep_persist_tmp(datadir string, now time.Time) (removed int) {
	for _, name := range PERSISTED_FILES {
		removed += sweep_stale_tmp(filepath.Join(datadir, name), STALE_TMP_AGE, now)
	}
	return removed
}

func write_json_atomic_with(path string, v interface{}, syncdir func(string) error) error {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetIndent("", "\t")
	if err := encoder.Encode(v); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once the rename has happened
	if _, err = tmp.Write(buf.Bytes()); err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	_ = syncdir(filepath.Dir(path)) // best effort: the new list is already visible; this only makes it durable
	return nil
}

// stamp_connected sets LastConnected = now on every peer that is connected at this moment (see save_peer_list).
func stamp_connected(peers map[string]*Peer, now uint64, connected func(address string) bool) (n int) {
	for _, v := range peers {
		if connected(v.Address) {
			v.LastConnected = now
			n++
		}
	}
	return
}

// state_hash reads StateHash under the lock update() writes it with.
func (c *Connection) state_hash() []byte {
	c.state_mu.Lock()
	defer c.state_mu.Unlock()
	h := c.StateHash
	return h[:]
}
