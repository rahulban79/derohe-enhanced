package rpc

import (
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/lesismal/nbio/nbhttp/websocket"
)

// fake_job_conn records every job written to it, in write order.
type fake_job_conn struct {
	mu        sync.Mutex
	got       []string
	deadlines int
}

func (f *fake_job_conn) SetWriteDeadline(t time.Time) error {
	f.mu.Lock()
	f.deadlines++
	f.mu.Unlock()
	return nil
}
func (f *fake_job_conn) WriteMessage(mt websocket.MessageType, b []byte) error {
	f.mu.Lock()
	f.got = append(f.got, string(b))
	f.mu.Unlock()
	return nil
}

// An older job that arrives after a newer one went out is dropped and counted; the next newer job still goes out.
func TestR23DeliverJobOrdering(t *testing.T) {
	var s user_session
	w := &fake_job_conn{}
	before := getwork_jobs_superseded.Get()
	if sent, err := deliver_job(&s, w, 2, []byte("job2")); !sent || err != nil {
		t.Fatalf("job 2: sent=%v err=%v", sent, err)
	}
	if sent, err := deliver_job(&s, w, 1, []byte("job1")); sent || err != nil {
		t.Fatalf("older job 1 after job 2 must be dropped: sent=%v err=%v", sent, err)
	}
	if sent, _ := deliver_job(&s, w, 2, []byte("job2-again")); sent {
		t.Fatalf("the same job number twice must be dropped")
	}
	if sent, _ := deliver_job(&s, w, 3, []byte("job3")); !sent {
		t.Fatalf("job 3 must go out")
	}
	if got := getwork_jobs_superseded.Get() - before; got != 2 {
		t.Fatalf("superseded counter: got %d want 2", got)
	}
	if len(w.got) != 2 || w.got[0] != "job2" || w.got[1] != "job3" {
		t.Fatalf("writes: %q", w.got)
	}
	if w.deadlines != 2 {
		t.Fatalf("a write deadline per written job: got %d", w.deadlines)
	}
}

// Many overlapping dispatches: whatever the interleaving, a miner's writes are strictly increasing and it ends on the
// newest job.
func TestR23DeliverJobConcurrentNewestLast(t *testing.T) {
	for round := 0; round < 20; round++ {
		var s user_session
		w := &fake_job_conn{}
		seqs := rand.Perm(64)
		var wg sync.WaitGroup
		for _, q := range seqs {
			wg.Add(1)
			go func(q uint64) {
				defer wg.Done()
				deliver_job(&s, w, q, []byte{byte(q)})
			}(uint64(q + 1))
		}
		wg.Wait()
		if len(w.got) == 0 || w.got[len(w.got)-1][0] != 64 {
			t.Fatalf("round %d: last job written is not the newest: %v", round, w.got)
		}
		for i := 1; i < len(w.got); i++ {
			if w.got[i][0] <= w.got[i-1][0] {
				t.Fatalf("round %d: writes not increasing: %v", round, w.got)
			}
		}
	}
}

// Job numbers follow the order of template fetches; a failed fetch uses no number.
func TestR23NextJobSeq(t *testing.T) {
	a, ok := next_job_seq(func() bool { return true })
	if !ok {
		t.Fatal("fetch ok")
	}
	if _, ok := next_job_seq(func() bool { return false }); ok {
		t.Fatal("failed fetch must not hand out a number")
	}
	b, _ := next_job_seq(func() bool { return true })
	if b != a+1 {
		t.Fatalf("numbers: %d then %d", a, b)
	}
}
