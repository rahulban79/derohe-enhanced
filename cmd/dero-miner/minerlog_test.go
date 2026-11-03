package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func write_run(t *testing.T, path string, max int64, backups int, text string) {
	t.Helper()
	r, err := open_rotating_log(path, max, backups)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Write([]byte(text)); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

func read_file(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// r20: os.Create truncated the log on every start, so the 08:32 restart erased the previous 27 h run
func TestMinerLogKeepsPreviousRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dero-miner.log")
	write_run(t, path, 1<<20, 2, "run1 start\nrun1 last line\n")
	write_run(t, path, 1<<20, 2, "run2 start\n")
	got := read_file(t, path)
	if got != "run1 start\nrun1 last line\nrun2 start\n" {
		t.Fatalf("restart lost the previous run: %q", got)
	}
}

func TestMinerLogRotatesBySize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dero-miner.log")
	r, err := open_rotating_log(path, 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"aaaaaaaa\n", "bbbbbbbb\n", "cccccccc\n", "dddddddd\n"} {
		if _, err := r.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	r.Close()
	if got := read_file(t, path); got != "dddddddd\n" {
		t.Fatalf("current log %q, want only the newest write", got)
	}
	if got := read_file(t, path+".1"); got != "cccccccc\n" {
		t.Fatalf(".1 = %q, want the previous file", got)
	}
	if got := read_file(t, path+".2"); got != "bbbbbbbb\n" {
		t.Fatalf(".2 = %q", got)
	}
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Fatalf("more backups than configured: the log is not bounded")
	}
}

// a log already at its limit is rotated at start, so the previous run is kept whole as .1 and the new run starts empty
func TestMinerLogFullFileRotatedAtStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dero-miner.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 20)), 0644); err != nil {
		t.Fatal(err)
	}
	write_run(t, path, 20, 1, "new\n")
	if got := read_file(t, path); got != "new\n" {
		t.Fatalf("current %q", got)
	}
	if got := read_file(t, path+".1"); got != strings.Repeat("x", 20) {
		t.Fatalf("previous run not kept: %q", got)
	}
}

func has_signal(sigs []os.Signal, s os.Signal) bool {
	for _, x := range sigs {
		if x == s {
			return true
		}
	}
	return false
}

func TestMinerExitSignalsIncludeSIGHUP(t *testing.T) {
	sigs := miner_exit_signals(func(os.Signal) bool { return false })
	if !has_signal(sigs, syscall.SIGHUP) || !has_signal(sigs, syscall.SIGTERM) || !has_signal(sigs, os.Interrupt) {
		t.Fatalf("exit signals %v: want SIGINT, SIGTERM and SIGHUP", sigs)
	}
}

// r20 review: under `nohup` SIGHUP starts ignored; registering it would undo nohup and kill the miner on hangup.
func TestMinerExitSignalsKeepNohup(t *testing.T) {
	sigs := miner_exit_signals(func(s os.Signal) bool { return s == syscall.SIGHUP })
	if has_signal(sigs, syscall.SIGHUP) {
		t.Fatalf("exit signals %v include SIGHUP although it was ignored at start (nohup)", sigs)
	}
	if !has_signal(sigs, syscall.SIGTERM) || !has_signal(sigs, os.Interrupt) {
		t.Fatalf("exit signals %v lost SIGINT/SIGTERM", sigs)
	}
}

// r20: a getwork connection that goes silent must end in an error (and a reconnect), not block ReadJSON for ever
func TestReadJobTimesOutOnSilentDaemon(t *testing.T) {
	up := websocket.Upgrader{}
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		<-release // connected, but never sends a job
		c.Close()
	}))
	defer srv.Close()
	defer close(release)

	d := websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, HandshakeTimeout: 5 * time.Second}
	conn, _, err := d.Dial("wss://"+srv.Listener.Addr().String()+"/ws/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	done := make(chan error, 1)
	go func() {
		var v map[string]interface{}
		done <- read_job(conn, 100*time.Millisecond, &v)
	}()
	select {
	case err := <-done:
		ne, ok := err.(net.Error)
		if !ok || !ne.Timeout() {
			t.Fatalf("read ended with %v, want a timeout", err)
		}
	case <-time.After(10 * time.Second):
		conn.Close()
		t.Fatal("read_job still blocked 10 s after a 100 ms deadline: a silent daemon wedges the miner")
	}
}

// r20 (rpcwallet OBS-09): the log carries the payout address; it is 0600 even when an older build created it 0644
func TestMinerLogIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	path := filepath.Join(t.TempDir(), "dero-miner.log")
	if err := os.WriteFile(path, []byte("old\n"), 0644); err != nil {
		t.Fatal(err)
	}
	write_run(t, path, 1<<20, 2, "new\n")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("log mode %v, want 0600", fi.Mode().Perm())
	}
	if got := read_file(t, path); got != "old\nnew\n" {
		t.Fatalf("content %q", got)
	}
}

// r20 review of F3: when the reopen after a rotation fails, later writes retry it instead of failing for ever
func TestMinerLogReopensAfterFailedOpen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "dero-miner.log")
	r, err := open_rotating_log(path, 1<<20, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.mu.Lock()
	r.f.Close()
	r.f = nil // the state a failed reopen leaves behind
	r.mu.Unlock()
	if _, err := r.Write([]byte("after\n")); err != nil {
		t.Fatalf("write after a failed reopen: %v", err)
	}
	if got := read_file(t, path); got != "after\n" {
		t.Fatalf("content %q", got)
	}
	r.Close()
	if _, err := r.Write([]byte("x")); err != os.ErrClosed {
		t.Fatalf("write after Close = %v, want os.ErrClosed", err)
	}
}

// r20 (harness HR20-2): a --bench start appends to and rotates only <exe>.bench.log; the live <exe>.log is untouched
func TestOpenLogBenchKeepsLiveLog(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "dero-miner")
	if err := os.WriteFile(exe+".log", []byte("live"), 0600); err != nil {
		t.Fatal(err)
	}
	write_run(t, log_path(exe, []string{"--bench"}), 4, 3, "bench run\n")
	if got := read_file(t, exe+".log"); got != "live" {
		t.Fatalf("live log = %q after a bench start", got)
	}
	if _, err := os.Stat(exe + ".log.1"); err == nil {
		t.Fatal("live log was rotated by a bench start")
	}
	if got := read_file(t, exe+".bench.log"); got != "bench run\n" {
		t.Fatalf("bench log = %q", got)
	}
}
