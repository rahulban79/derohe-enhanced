package main

import (
	"bytes"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deroproject/derohe/rpc"
)

func TestJobIDMs(t *testing.T) {
	cases := map[string]int64{"1793349666674.0.notified": 1793349666674, "": 0, "x.1": 0, "12": 12,
		"99999999999999999999999.0": 0} // more than an int64 holds: 0, never a panic
	for in, want := range cases {
		if got := job_id_ms(in); got != want {
			t.Fatalf("%q: %d want %d", in, got, want)
		}
	}
}

// take_job counts the job and the age of its template (receipt time minus the ms timestamp the job id starts with)
func TestTakeJobRecordsTemplateAge(t *testing.T) {
	mutex.Lock()
	saved, saved_counter := job, job_counter
	mutex.Unlock()
	defer func() { mutex.Lock(); job, job_counter = saved, saved_counter; mutex.Unlock() }()
	n0, c0, s0 := atomic.LoadUint64(&jobs_received), atomic.LoadUint64(&job_age_count), atomic.LoadUint64(&job_age_us_sum)
	id := strconv_ms(time.Now().Add(-250*time.Millisecond).UnixMilli()) + ".0.notified"
	if !take_job(rpc.GetBlockTemplate_Result{JobID: id, Blockhashing_blob: test_blob(false, 7), Difficulty: "1000", Height: 5}) {
		t.Fatal("valid job dropped")
	}
	if atomic.LoadUint64(&jobs_received) != n0+1 || atomic.LoadUint64(&job_age_count) != c0+1 {
		t.Fatal("job or age not counted")
	}
	if age := atomic.LoadUint64(&job_age_us_sum) - s0; age < 240000 || age > 5000000 {
		t.Fatalf("template age %d us, want ~250 ms", age)
	}
	note_job_received(strconv_ms(time.Now().Add(time.Hour).UnixMilli())+".0", time.Now()) // future: not an age
	if atomic.LoadUint64(&job_age_count) != c0+1 {
		t.Fatal("a future timestamp was counted as an age")
	}
	var b bytes.Buffer
	write_job_latency_metrics(&b)
	if s := b.String(); !strings.Contains(s, "dero_miner_jobs_received_total ") || !strings.Contains(s, "dero_miner_job_template_age_seconds_count ") {
		t.Fatalf("metrics: %s", s)
	}
}

func strconv_ms(v int64) string {
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// Threads start when the first job is in, not after a fixed 5 s; with no job they still give up at the limit.
func TestWaitFirstJob(t *testing.T) {
	var c int64
	go func() { time.Sleep(20 * time.Millisecond); atomic.StoreInt64(&c, 1) }()
	if d := wait_first_job(&c, 5*time.Second, time.Millisecond); d > time.Second {
		t.Fatalf("waited %v after the job arrived at 20 ms", d)
	}
	var none int64
	if d := wait_first_job(&none, 50*time.Millisecond, time.Millisecond); d < 50*time.Millisecond || d > 2*time.Second {
		t.Fatalf("no job: returned after %v, want the 50 ms limit", d)
	}
}

// mineblock must use wait_first_job, not the old fixed sleep
func TestMineblockWaitsForJobNotFixedSleep(t *testing.T) {
	b, err := os.ReadFile("miner.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, "func mineblock(tid int) {")
	if i < 0 {
		t.Fatal("mineblock not found")
	}
	body := src[i:]
	if j := strings.Index(body, "\nfunc "); j > 0 {
		body = body[:j]
	}
	if strings.Contains(body, "time.Sleep(5 * time.Second)") || !strings.Contains(body, "wait_first_job(&job_counter,") {
		t.Fatal("mineblock still sleeps a fixed 5 s before its first hash")
	}
}
