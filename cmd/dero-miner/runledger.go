package main

// Round 21 (storageops): a per-run summary ledger for long-term evidence.
//
// The miner log is size-rotated (32 MiB x 4, ~35 days at the r19 rate of ~3.6 MB/day), and every question of the
// form "did r19 really pay less than r20 per hour?" had to be answered by re-parsing whatever logs were still on
// disk; the r19 run's numbers survived only in derod's log. The run ledger keeps ONE JSON line per miner run, forever
// (a few hundred bytes a run), next to the log: <log without .log>.runs.jsonl.
//
// Crash safety: the line is not written only at exit (kill -9, a panic or a power cut would lose it). Every 60 s the
// running totals replace <base>.run.json atomically (temp file, fsync, rename, directory fsync). At the next start a
// checkpoint that is still there is a run that never reached its exit path: it is appended to the ledger with
// end="unclean: ..." and its counters as of the last checkpoint (at most 60 s old). A clean exit appends the final
// line with its reason and removes the checkpoint. Appends are single O_APPEND writes followed by fsync; a reader
// skips a torn last line (parse_run_ledger). The ledger is rotated once (to .1) past RUN_LEDGER_MAX_BYTES.
// Never the wallet address: the ledger is evidence that may be shared.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deroproject/derohe/config"
)

const RUN_LEDGER_MAX_BYTES = 4 << 20 // ~5,000 runs at ~800 B
const RUN_CHECKPOINT_EVERY = 60 * time.Second

type run_record struct {
	Kind      string  `json:"kind"` // always "run"
	RunID     string  `json:"run_id"`
	Version   string  `json:"version"`
	Start     string  `json:"start"`
	Last      string  `json:"last"` // time of these counters
	End       string  `json:"end"`  // "running" in a checkpoint; the exit reason, or "unclean: ..." when recovered
	UptimeS   float64 `json:"uptime_s"`
	Threads   int     `json:"threads"`
	CPUMax    int     `json:"cpu_max"`
	GPUMax    int     `json:"gpu_max"`
	GPUMode   string  `json:"gpu_mode"` // "", "full" or "split" (the split engine actually running)
	Hashes    uint64  `json:"hashes"`
	AvgHs     float64 `json:"avg_hs"`
	Height    int64   `json:"height"`
	Blocks    uint64  `json:"accepted_blocks"`
	Minis     uint64  `json:"accepted_miniblocks"`
	Rejected  uint64  `json:"rejected"`
	FoundCPU  uint64  `json:"found_cpu"`
	FoundGPU  uint64  `json:"found_gpu"`
	ExpShares float64 `json:"expected_shares"`
	Outcome   bool    `json:"outcome_known"` // derod's GetMiningOutcome answered at least once
	PaidCPU   int     `json:"paid_cpu"`
	PaidGPU   int     `json:"paid_gpu"`
	OrphCPU   int     `json:"orphaned_cpu"`
	OrphGPU   int     `json:"orphaned_gpu"`
	Unresolv  int     `json:"unresolved"`
	PaidFrac  float64 `json:"node_paid_fraction"`
	Reconnect uint64  `json:"getwork_reconnects"`
	GPUMism   uint64  `json:"gpu_mismatch"`
	GPURest   uint64  `json:"gpu_restarts"`
	SplitDrop uint64  `json:"split_dropped"`
	SplitAud  uint64  `json:"split_audited"`
	SplitRest uint64  `json:"split_restarts"`
	SplitOff  bool    `json:"split_disabled"`
	SortFall  uint64  `json:"sort_fallbacks"`
	GPUStale  int     `json:"gpu_binary_stale"`
	PID       int     `json:"pid,omitempty"` // the process that wrote a checkpoint (r21 merge: liveness, STOROPS21-7)
}

// run_record_from is pure (unit-tested): the counters of one metrics snapshot.
func run_record_from(m miner_metrics, start, now time.Time, exp float64) run_record {
	r := run_record{Kind: "run", RunID: fmt.Sprintf("%x", start.UnixNano()), Version: config.Version.String(),
		Start: start.Format(time.RFC3339), Last: now.Format(time.RFC3339), End: "running", UptimeS: math.Round(m.uptime),
		Threads: m.threads, CPUMax: cpu_duty_pct(), GPUMax: gpu_duty_pct(), // r22: the caps in force (the tuner may move them)
		Hashes: m.hashes, Height: m.status.height, // r23 forensics: the r22 merge had pushed these two into the comment above (every r22 ledger row read hashes 0, height 0)
		Blocks: m.status.accepted_blocks, Minis: m.status.accepted_minis, Rejected: m.status.rejected,
		FoundCPU: m.cpu_found, FoundGPU: m.gpu_found, ExpShares: math.Round(exp*100) / 100,
		Outcome: m.outcome_ok, PaidCPU: m.cpu_paid, PaidGPU: m.gpu_paid, OrphCPU: m.cpu_orph, OrphGPU: m.gpu_orph,
		Unresolv: m.unresolved, PaidFrac: m.node_paid_fraction, Reconnect: m.reconnects, GPUMism: m.gpu_mismatch,
		GPURest: m.gpu_restarts, SplitDrop: m.split_dropped, SplitAud: m.split_audited, SplitRest: m.split_restarts,
		SplitOff: m.split_disabled, SortFall: m.sort_fallbacks, GPUStale: m.gpu_binary_stale}
	if m.uptime > 0 {
		r.AvgHs = math.Round(float64(m.hashes) / m.uptime)
	}
	if m.split_on {
		r.GPUMode = "split"
	} else if gpu_full_running() {
		r.GPUMode = "full"
	}
	return r
}

type run_ledger struct {
	mu         sync.Mutex
	ledger     string // <base>.runs.jsonl
	checkpoint string // <base>.run.json
	start      time.Time
	finished   bool
	max        int64
}

// run_ledger_paths: bin/dero-miner.log -> bin/dero-miner.runs.jsonl, bin/dero-miner.run.json
func run_ledger_paths(logfile string) (ledger, checkpoint string) {
	base := strings.TrimSuffix(logfile, ".log")
	return base + ".runs.jsonl", base + ".run.json"
}

// open_run_ledger recovers a checkpoint an earlier run left behind (it never reached its exit path), then returns
// the ledger for this run. recovered is that earlier run's record, if there was one.
func open_run_ledger(logfile string, start time.Time) (l *run_ledger, recovered *run_record, err error) {
	l = &run_ledger{start: start, max: RUN_LEDGER_MAX_BYTES}
	l.ledger, l.checkpoint = run_ledger_paths(logfile)
	data, rerr := os.ReadFile(l.checkpoint)
	switch {
	case rerr == nil:
		var r run_record
		if jerr := json.Unmarshal(data, &r); jerr != nil || r.Kind != "run" {
			// keep the bytes for a human; never let a damaged checkpoint block mining
			os.Rename(l.checkpoint, l.checkpoint+".bad")
			return l, nil, fmt.Errorf("unreadable run checkpoint moved to %s.bad", l.checkpoint)
		}
		// r21 merge (STOROPS21-7 fix): a checkpoint that another LIVE miner is still refreshing is not a dead run.
		// Every run of one binary shares <base>.run.json, so a second miner started from the same path used to
		// record the running one as unclean and delete its checkpoint. Such a second run gets no ledger.
		if fi, serr := os.Stat(l.checkpoint); serr == nil && checkpoint_owner_alive(r.PID, fi.ModTime(), time.Now()) {
			return nil, nil, fmt.Errorf("run ledger: dero-miner pid %d is running and owns %s; this run is not recorded", r.PID, l.checkpoint)
		}
		r.End = "unclean: no exit record (kill -9, crash or power loss); counters as of last"
		if err = l.append(r); err != nil {
			return l, nil, err // the checkpoint stays for the next start
		}
		os.Remove(l.checkpoint)
		recovered = &r
	case !os.IsNotExist(rerr):
		return l, nil, rerr
	}
	return l, recovered, nil
}

// checkpoint_owner_alive: the checkpoint was written by another process that still exists (pid_alive; never on
// Windows) and was refreshed within 3 checkpoint periods, so it belongs to a running miner. A checkpoint of this
// process, without a pid (older builds), or stale (its writer died and the pid may be reused) is a dead run.
func checkpoint_owner_alive(pid int, mtime, now time.Time) bool {
	if pid <= 0 || pid == os.Getpid() || now.Sub(mtime) > 3*RUN_CHECKPOINT_EVERY {
		return false
	}
	return pid_alive(pid)
}

// Checkpoint replaces the checkpoint atomically with r (End "running"). After Finish it does nothing, so a
// checkpoint racing the exit path cannot resurrect a cleanly ended run as "unclean" at the next start.
func (l *run_ledger) Checkpoint(r run_record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.finished {
		return nil
	}
	r.End = "running"
	r.PID = os.Getpid()
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return write_file_atomic(l.checkpoint, data, 0600)
}

// Finish appends the run's final line once and removes the checkpoint; later calls are no-ops.
func (l *run_ledger) Finish(r run_record, reason string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.finished {
		return nil
	}
	l.finished = true
	r.End = reason
	if err := l.append(r); err != nil {
		return err // the checkpoint stays: the next start records this run as unclean rather than not at all
	}
	os.Remove(l.checkpoint)
	return nil
}

// append writes one line with a single O_APPEND write and fsyncs it; past max the ledger is first rotated to .1.
func (l *run_ledger) append(r run_record) error {
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if fi, err := os.Stat(l.ledger); err == nil && l.max > 0 && fi.Size()+int64(len(line)) > l.max {
		os.Rename(l.ledger, l.ledger+".1")
	}
	f, err := os.OpenFile(l.ledger, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	_, werr := f.Write(line)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if serr != nil {
		return serr
	}
	return cerr
}

// write_file_atomic: temp file in the same directory, fsync, rename over path, directory fsync (best effort; not
// supported on Windows). A crash leaves either the old or the new content, never a torn file.
func write_file_atomic(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.Remove(tmp.Name())
		}
	}()
	if err = tmp.Chmod(mode); err != nil && !os.IsPermission(err) {
		tmp.Close()
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if d, derr := os.Open(dir); derr == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// parse_run_ledger reads a ledger, skipping lines that do not parse (a torn last line after a crash mid-append).
func parse_run_ledger(rd io.Reader) (runs []run_record, skipped int) {
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var r run_record
		if json.Unmarshal(b, &r) != nil || r.Kind != "run" {
			skipped++
			continue
		}
		runs = append(runs, r)
	}
	return
}

// the process-wide ledger (nil for --bench and when it cannot be opened) and the status goroutine's expected shares
var the_run_ledger *run_ledger
var exp_shares_bits uint64 // math.Float64bits(exp_shares), stored by the status goroutine

func current_run_record() run_record {
	return run_record_from(collect_miner_metrics(), miner_start, time.Now(), math.Float64frombits(atomic.LoadUint64(&exp_shares_bits)))
}

// finish_run is called on every exit path the miner controls (signal, console exit/quit/bye, Ctrl-C).
func finish_run(reason string) {
	if l := the_run_ledger; l != nil {
		if err := l.Finish(current_run_record(), reason); err != nil {
			logger.Error(err, "run ledger: final line not written (the checkpoint is kept for the next start)")
		}
	}
}

// run_checkpointer replaces the checkpoint every period until quit closes.
func run_checkpointer(l *run_ledger, period time.Duration, quit <-chan bool) {
	t := time.NewTicker(period)
	defer t.Stop()
	failed := false
	for {
		select {
		case <-quit:
			return
		case <-t.C:
			if err := l.Checkpoint(current_run_record()); err != nil && !failed {
				failed = true // once: a full disk must not flood the log
				logger.Error(err, "run ledger: checkpoint not written")
			} else if err == nil {
				failed = false
			}
		}
	}
}
