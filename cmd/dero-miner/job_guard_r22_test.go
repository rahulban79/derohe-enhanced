package main

import (
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// r22: a hostile daemon's difficulty-1 job cannot make the miner submit every hash.
func TestSubmitBucketCapsFlood(t *testing.T) {
	l := new_submit_limiter(false, "")
	if l == nil {
		t.Fatal("mainnet miner has no submit limit")
	}
	now := time.Unix(10000, 0)
	before := atomic.LoadUint64(&submits_throttled)
	ok := 0
	for i := 0; i < 84000; i++ { // one second of the live hashrate, every hash a "share"
		if submit_allowed(l, now.Add(time.Duration(i)*time.Second/84000)) {
			ok++
		}
	}
	if ok > SUBMIT_BURST+SUBMIT_RATE+1 || ok < SUBMIT_BURST {
		t.Fatalf("%d of 84000 shares sent in 1 s, want ~%d", ok, SUBMIT_BURST+SUBMIT_RATE)
	}
	if d := atomic.LoadUint64(&submits_throttled) - before; d != uint64(84000-ok) {
		t.Fatalf("throttled counter +%d, want %d", d, 84000-ok)
	}
	// the honest rate (far below 1/s on mainnet) is never throttled, even in a lucky burst of 50 shares in a second
	h := new_submit_limiter(false, "")
	for i := 0; i < 50; i++ {
		if !submit_allowed(h, now.Add(time.Duration(i)*20*time.Millisecond)) {
			t.Fatalf("honest share %d throttled", i)
		}
	}
}

func TestSubmitLimiterConfig(t *testing.T) {
	if new_submit_limiter(true, "") != nil {
		t.Fatal("--testnet (low difficulty by design) must not be limited by default")
	}
	if new_submit_limiter(false, "0") != nil {
		t.Fatal("DERO_MINER_SUBMIT_RATE=0 must disable the limit")
	}
	if l := new_submit_limiter(true, "500"); l == nil || l.Limit() != 500 || l.Burst() != 500 {
		t.Fatalf("DERO_MINER_SUBMIT_RATE=500: %v", l)
	}
	if l := new_submit_limiter(false, "junk"); l == nil || l.Limit() != SUBMIT_RATE {
		t.Fatal("a bad DERO_MINER_SUBMIT_RATE must keep the default")
	}
	if !submit_allowed(nil, time.Now()) {
		t.Fatal("nil limiter means unlimited")
	}
}

// submitShare must consult the bucket before doing any work (a source check: the function needs a live socket).
func TestSubmitShareChecksBucketFirst(t *testing.T) {
	src, err := os.ReadFile("miner.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	i := strings.Index(s, "func submitShare(")
	j := strings.Index(s, "if !submit_allowed(submit_bucket, time.Now()) {")
	k := strings.Index(s, "json.Marshal(rpc.SubmitBlock_Params")
	if i < 0 || j < i || k < j {
		t.Fatal("submitShare does not check submit_bucket before encoding the share")
	}
	if !strings.Contains(s, `submit_bucket = new_submit_limiter(globals.Arguments["--testnet"].(bool), os.Getenv("DERO_MINER_SUBMIT_RATE"))`) {
		t.Fatal("main no longer installs the submit limiter")
	}
}

// r22: a job's LastError is logged on change or once a minute, clipped; a hostile 64 KiB error per job cannot fill
// the miner log, and an honest "unregistered" error is not repeated every job.
func TestJobErrorLogGated(t *testing.T) {
	job_error_mu.Lock()
	job_error_last, job_error_at = "", time.Time{} // -count=N: start from a fresh gate
	job_error_mu.Unlock()
	now := time.Unix(20000, 0)
	big := strings.Repeat("x", 60<<10)
	if e := job_error_to_log(big, now); len(e) > JOB_ERROR_LOG_MAX+20 || !strings.HasSuffix(e, "(clipped)") {
		t.Fatalf("logged %d bytes", len(e))
	}
	n := 0
	for i := 1; i <= 120; i++ { // the next 60 s of jobs, one every 0.5 s: only the one at +60 s is logged
		if job_error_to_log(big, now.Add(time.Duration(i)*500*time.Millisecond)) != "" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the same error was logged %d more times in 60 s of jobs, want 1 (once a minute)", n)
	}
	if job_error_to_log("unregistered miner or you need to wait 15 mins", now.Add(61*time.Second)) == "" {
		t.Fatal("a changed error must be logged at once")
	}
	if job_error_to_log("", now) != "" {
		t.Fatal("no error, no log")
	}
}

func TestTakeJobUsesErrorGate(t *testing.T) {
	src, err := os.ReadFile("miner.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `if e := job_error_to_log(job.LastError, time.Now()); e != "" {`) ||
		strings.Contains(string(src), `logger.Error(nil, "received error", "err", job.LastError)`) {
		t.Fatal("take_job logs LastError without the gate")
	}
}

// r22 (found by FuzzMinerParsers): BUILD_STAMPS digests must be hex; a non-hex 64-byte field is not a stamp.
func TestParseGPUStampsRequiresHex(t *testing.T) {
	good := strings.Repeat("ab", 32)
	bad := "\xff" + strings.Repeat("0", 63) // 64 bytes, one of them not hex
	m := parse_gpu_stamps(strings.NewReader("x " + bad + " " + good + "\ny " + good + " " + strings.ToUpper(good) + "\n"))
	if _, ok := m["x"]; ok {
		t.Fatal("a non-hex digest was accepted")
	}
	if st, ok := m["y"]; !ok || st.bin != good {
		t.Fatalf("a valid (upper-case) stamp was refused or not lower-cased: %+v", st)
	}
}
