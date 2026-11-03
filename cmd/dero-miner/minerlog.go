package main

import (
	"fmt"
	"os"
	"sync"
)

// Round 20 forensics: the miner opened its log with os.Create, which truncates. The 2026-10-28 08:32 restart wiped the
// previous ~27 h r19 run, so why that miner had stopped submitting (derod: 41 shares in 26.7 h, all inside two windows
// of 25 and 9 minutes) could no longer be read from the miner side. The log is now appended to, and rotated by size
// (<log>.1 ... <log>.N, newest first), so the previous run survives a restart and the file stays bounded.
// O_APPEND also keeps a second writer (a stray benchmark of the installed binary) from leaving NUL holes.
// The file is kept 0600 (it carries the payout address; older builds created it 0644). Rotation by size, not per
// start, so a crash loop or a few mistyped restarts cannot rotate a long run's record out of the kept files.
// Merged r20 (one implementation for the forensics, cpuminer, rpcwallet and harness proposals); the rotated names
// <log>.1 .. <log>.3 are what harness/intel/miner_intel.py log_chain() reads, oldest first.

const MINER_LOG_MAX_BYTES = 32 << 20 // rotate past 32 MiB (r19 live: ~5 KB per 2 minutes, i.e. ~3.6 MB/day)
const MINER_LOG_BACKUPS = 3          // keep <log>.1 .. <log>.3: the previous runs, ~4 x 32 MiB at most

type rotating_log struct {
	mu      sync.Mutex
	path    string
	max     int64
	backups int
	f       *os.File
	size    int64
	closed  bool // Close was called: no reopen
}

// open_rotating_log opens path for appending, creating it if needed. A file already at max is rotated by the first
// write, so the previous run is then kept whole as <path>.1.
func open_rotating_log(path string, max int64, backups int) (*rotating_log, error) {
	r := &rotating_log{path: path, max: max, backups: backups}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *rotating_log) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	f.Chmod(0600) // best effort: an existing file keeps its mode on open (no-op on Windows)
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, fi.Size()
	return nil
}

// shift renames <path>.(i) to <path>.(i+1) from the oldest down, then <path> to <path>.1. The oldest backup is
// overwritten (os.Rename replaces), so at most `backups` old files exist. With backups == 0 the log is truncated.
func (r *rotating_log) shift() {
	if r.backups <= 0 {
		os.Truncate(r.path, 0)
		return
	}
	for i := r.backups - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1))
	}
	os.Rename(r.path, r.path+".1")
}

func (r *rotating_log) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, os.ErrClosed
	}
	if r.f == nil { // the reopen after a rotation failed (r20 review): retry on every write, never stay silent
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	if r.max > 0 && r.size > 0 && r.size+int64(len(p)) > r.max {
		r.f.Close() // close before renaming: Windows cannot rename an open file
		r.f = nil
		r.shift()
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotating_log) Sync() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	return r.f.Sync()
}

func (r *rotating_log) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}
