package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func ledger_runs(t *testing.T, path string) []run_record {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	runs, skipped := parse_run_ledger(bytes.NewReader(data))
	if skipped != 0 {
		t.Fatalf("%d unparsable ledger lines", skipped)
	}
	return runs
}

func TestRunLedgerPaths(t *testing.T) {
	l, c := run_ledger_paths("/x/bin/dero-miner.log")
	if l != "/x/bin/dero-miner.runs.jsonl" || c != "/x/bin/dero-miner.run.json" {
		t.Fatal(l, c)
	}
}

// A clean run: checkpoints never reach the ledger, Finish appends exactly one line with the reason and removes the
// checkpoint, and a Checkpoint after Finish cannot resurrect it (the next start would call it unclean).
func TestRunLedgerCleanRun(t *testing.T) {
	dir := t.TempDir()
	logfile := filepath.Join(dir, "m.log")
	l, rec, err := open_run_ledger(logfile, time.Unix(1000, 0))
	if err != nil || rec != nil {
		t.Fatal(err, rec)
	}
	r := run_record{Kind: "run", RunID: "a", Hashes: 10}
	if err := l.Checkpoint(r); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(l.checkpoint); err != nil {
		t.Fatal("no checkpoint written", err)
	}
	if _, err := os.Stat(l.ledger); !os.IsNotExist(err) {
		t.Fatal("a checkpoint must not append to the ledger")
	}
	r.Hashes = 20
	if err := l.Finish(r, "signal terminated"); err != nil {
		t.Fatal(err)
	}
	if err := l.Finish(r, "again"); err != nil { // second exit path: no second line
		t.Fatal(err)
	}
	if err := l.Checkpoint(r); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(l.checkpoint); !os.IsNotExist(err) {
		t.Fatal("checkpoint must be gone after Finish (and not rewritten by a late Checkpoint)")
	}
	runs := ledger_runs(t, l.ledger)
	if len(runs) != 1 || runs[0].End != "signal terminated" || runs[0].Hashes != 20 {
		t.Fatalf("%+v", runs)
	}
	if fi, _ := os.Stat(l.ledger); fi.Mode().Perm()&0077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("ledger mode %v", fi.Mode())
	}
	// the next start finds no checkpoint and appends nothing
	if _, rec, err := open_run_ledger(logfile, time.Unix(2000, 0)); err != nil || rec != nil {
		t.Fatal(err, rec)
	}
	if n := len(ledger_runs(t, l.ledger)); n != 1 {
		t.Fatal(n)
	}
}

// A run killed after a checkpoint (no Finish) is recorded at the next start as unclean, with its last counters.
func TestRunLedgerRecoversUncleanRun(t *testing.T) {
	dir := t.TempDir()
	logfile := filepath.Join(dir, "m.log")
	l, _, err := open_run_ledger(logfile, time.Unix(1000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Checkpoint(run_record{Kind: "run", RunID: "dead", Hashes: 77}); err != nil {
		t.Fatal(err)
	}
	// kill -9 here: no Finish
	l2, rec, err := open_run_ledger(logfile, time.Unix(2000, 0))
	if err != nil || rec == nil || rec.RunID != "dead" || rec.Hashes != 77 || !strings.HasPrefix(rec.End, "unclean") {
		t.Fatalf("%v %+v", err, rec)
	}
	if _, err := os.Stat(l2.checkpoint); !os.IsNotExist(err) {
		t.Fatal("recovered checkpoint must be removed")
	}
	runs := ledger_runs(t, l2.ledger)
	if len(runs) != 1 || runs[0].RunID != "dead" {
		t.Fatalf("%+v", runs)
	}
	// and the recovery is not repeated
	if _, rec, _ := open_run_ledger(logfile, time.Unix(3000, 0)); rec != nil {
		t.Fatal("recovered twice")
	}
}

// A damaged checkpoint never blocks mining: it is moved aside and the ledger opens.
func TestRunLedgerDamagedCheckpoint(t *testing.T) {
	dir := t.TempDir()
	logfile := filepath.Join(dir, "m.log")
	_, cp := run_ledger_paths(logfile)
	os.WriteFile(cp, []byte("{\"kind\":\"ru"), 0600)
	l, rec, err := open_run_ledger(logfile, time.Now())
	if l == nil || rec != nil || err == nil {
		t.Fatal(l, rec, err)
	}
	if _, err := os.Stat(cp + ".bad"); err != nil {
		t.Fatal("damaged checkpoint not kept for a human", err)
	}
	if _, err := os.Stat(cp); !os.IsNotExist(err) {
		t.Fatal("damaged checkpoint still in place")
	}
}

// A torn last line (crash mid-append) is skipped, the lines before it survive.
func TestParseRunLedgerSkipsTornLine(t *testing.T) {
	a, _ := json.Marshal(run_record{Kind: "run", RunID: "1"})
	b, _ := json.Marshal(run_record{Kind: "run", RunID: "2"})
	in := string(a) + "\n" + `{"kind":"other"}` + "\n" + string(b) + "\n" + `{"kind":"run","run_id":"3","has` // torn
	runs, skipped := parse_run_ledger(strings.NewReader(in))
	if len(runs) != 2 || skipped != 2 || runs[1].RunID != "2" {
		t.Fatal(runs, skipped)
	}
}

// Past the cap the ledger is rotated to .1 before the append, so it stays bounded and the old runs are kept once.
func TestRunLedgerRotates(t *testing.T) {
	dir := t.TempDir()
	l, _, err := open_run_ledger(filepath.Join(dir, "m.log"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	l.max = 2000 // a full record is ~580 B
	for i := 0; i < 12; i++ {
		if err := l.append(run_record{Kind: "run", RunID: strings.Repeat("x", 10)}); err != nil {
			t.Fatal(err)
		}
	}
	fi, err := os.Stat(l.ledger)
	if err != nil || fi.Size() > 2000 {
		t.Fatal(err, fi.Size())
	}
	if _, err := os.Stat(l.ledger + ".1"); err != nil {
		t.Fatal("no rotated ledger", err)
	}
}

// write_file_atomic leaves no temp file behind and replaces the content whole.
func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.json")
	for _, s := range []string{"first", "second"} {
		if err := write_file_atomic(p, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if b, _ := os.ReadFile(p); string(b) != "second" {
		t.Fatal(string(b))
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("temp files left: %v", ents)
	}
	if err := write_file_atomic(filepath.Join(dir, "missing", "f"), []byte("x"), 0600); err == nil {
		t.Fatal("write into a missing dir must fail")
	}
}

// The record never carries the wallet address, and its averages come from the snapshot.
// R22: the address is set BEFORE the record is built. It used to be set after run_record_from returned, so a record
// that copied the address could never be seen; the mutation guarding this was "caught" only because it did not compile.
func TestRunRecordFrom(t *testing.T) {
	wallet_address = "dero1qytestaddressxxxxxxxxxxxxxxxxxxxxxxxxx"
	defer func() { wallet_address = "" }()
	m := miner_metrics{hashes: 1000, uptime: 10, threads: 4, split_on: true, cpu_found: 1, gpu_found: 2, gpu_binary_stale: 1}
	m.status.height = 7830303
	r := run_record_from(m, time.Unix(100, 0), time.Unix(110, 0), 1.234)
	if r.AvgHs != 100 || r.GPUMode != "split" || r.FoundGPU != 2 || r.ExpShares != 1.23 || r.GPUStale != 1 || r.Kind != "run" {
		t.Fatalf("%+v", r)
	}
	// r23 forensics: every r22 ledger row read "hashes":0,"height":0 (the two fields had slid into a comment)
	if r.Hashes != 1000 || r.Height != 7830303 {
		t.Fatalf("hashes %d height %d, want 1000 7830303", r.Hashes, r.Height)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "dero1") {
		t.Fatal("wallet address in the run ledger")
	}
}

// A SIGTERM run end reaches the ledger with its reason (exit_on_signal -> finish_run) and the checkpoint is removed.
func TestSignalExitWritesRunLedger(t *testing.T) {
	dir := t.TempDir()
	l, _, err := open_run_ledger(filepath.Join(dir, "m.log"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Checkpoint(current_run_record()); err != nil {
		t.Fatal(err)
	}
	the_run_ledger = l
	defer func() { the_run_ledger = nil }()
	sigs := make(chan os.Signal, 1)
	sigs <- syscall.SIGTERM
	close(sigs)
	exit_on_signal(sigs, nil, func() {})
	runs := ledger_runs(t, l.ledger)
	if len(runs) != 1 || runs[0].End != "signal "+syscall.SIGTERM.String() {
		t.Fatalf("%+v", runs)
	}
	if _, err := os.Stat(l.checkpoint); !os.IsNotExist(err) {
		t.Fatal("checkpoint left after a clean signal exit: the next start would record an unclean run")
	}
}

// The miner's /metrics now carries process_* and go_* (r21) and the stale-binary gauge.
func TestMinerMetricsHandlerProcessSeries(t *testing.T) {
	rec := httptest.NewRecorder()
	miner_metrics_handler(rec, httptest.NewRequest("GET", "/metrics", nil))
	out := rec.Body.String()
	for _, need := range []string{"\ngo_goroutines ", "\nprocess_cpu_seconds_total ", "\ndero_miner_gpu_binary_stale 0\n"} {
		if !strings.Contains(out, need) {
			t.Errorf("%q missing from /metrics", strings.TrimSpace(need))
		}
	}
}

// r21 merge (STOROPS21-7 fix): a second miner started from the same binary path while the first one still refreshes
// the shared checkpoint must not record the running miner as unclean or delete its checkpoint; a stale checkpoint of
// the same (still existing) pid is a dead run and is recovered.
func TestRunLedgerSkipsLiveOwnersCheckpoint(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no pid liveness probe on Windows")
	}
	dir := t.TempDir()
	logfile := filepath.Join(dir, "m.log")
	_, cp := run_ledger_paths(logfile)
	other := os.Getppid() // a live process that is not this one (the go test driver)
	data, _ := json.Marshal(run_record{Kind: "run", RunID: "live", End: "running", PID: other})
	if err := os.WriteFile(cp, data, 0600); err != nil {
		t.Fatal(err)
	}
	l, rec, err := open_run_ledger(logfile, time.Unix(2000, 0))
	if err == nil || l != nil || rec != nil {
		t.Fatalf("a live owner's checkpoint was taken over: l=%v rec=%+v err=%v", l, rec, err)
	}
	if _, err := os.Stat(cp); err != nil {
		t.Fatal("the running miner's checkpoint was removed")
	}
	old := time.Now().Add(-4 * RUN_CHECKPOINT_EVERY) // not refreshed for 4 periods: its writer is gone
	os.Chtimes(cp, old, old)
	if _, rec, err := open_run_ledger(logfile, time.Unix(3000, 0)); err != nil || rec == nil || rec.RunID != "live" {
		t.Fatalf("stale checkpoint not recovered: %+v %v", rec, err)
	}
	// this process's own checkpoints carry its pid (what a second miner compares against)
	l3, _, _ := open_run_ledger(filepath.Join(t.TempDir(), "n.log"), time.Unix(4000, 0))
	if err := l3.Checkpoint(run_record{Kind: "run"}); err != nil {
		t.Fatal(err)
	}
	var mine run_record
	if b, err := os.ReadFile(l3.checkpoint); err != nil || json.Unmarshal(b, &mine) != nil || mine.PID != os.Getpid() {
		t.Fatalf("checkpoint pid %d, want %d (%v)", mine.PID, os.Getpid(), err)
	}
	if !checkpoint_owner_alive(other, time.Now(), time.Now()) || checkpoint_owner_alive(os.Getpid(), time.Now(), time.Now()) ||
		checkpoint_owner_alive(0, time.Now(), time.Now()) {
		t.Fatal("checkpoint_owner_alive rule")
	}
}
