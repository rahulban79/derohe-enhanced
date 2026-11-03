package rpc

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lesismal/nbio/nbhttp/websocket"
)

// with_clients swaps in a private client_list for one test.
func with_clients(t *testing.T, sessions []*user_session) {
	client_list_mutex.Lock()
	saved := client_list
	client_list = map[*websocket.Conn]*user_session{}
	for _, s := range sessions {
		client_list[new(websocket.Conn)] = s
	}
	client_list_mutex.Unlock()
	t.Cleanup(func() {
		client_list_mutex.Lock()
		client_list = saved
		atomic.StoreInt64(&getwork_session_count, int64(len(client_list))) // r23b: the mirror too, or drain_miners waits on a ghost
		client_list_mutex.Unlock()
	})
}

func run_job(targets []job_target, reg *reg_lookups, topo int64) (registered int64) {
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(t job_target) {
			defer wg.Done()
			if t.registered(reg, topo) {
				atomic.AddInt64(&registered, 1)
			}
		}(t)
	}
	wg.Wait()
	return
}

// 1000 connections mining to one unregistered address used to cost 1000 balance-tree reads per push (85% of derod's
// CPU in the r19 shadow profile). Now: one read per address per job, and none until the topoheight moves.
func TestRegistrationLookupOncePerTopo(t *testing.T) {
	unreg, late, reg_ok := [32]byte{1}, [32]byte{2}, [32]byte{3}
	var sessions []*user_session
	for i := 0; i < 1000; i++ {
		sessions = append(sessions, &user_session{address_sum: unreg, checked_topo: -1})
	}
	sessions = append(sessions, &user_session{address_sum: late, checked_topo: -1})                        // registered, not yet confirmed
	sessions = append(sessions, &user_session{address_sum: reg_ok, valid_address: true, checked_topo: -1}) // confirmed earlier
	with_clients(t, sessions)

	var lookups int64
	lookup := func(a [32]byte) bool { atomic.AddInt64(&lookups, 1); return a != unreg }

	if got := run_job(job_targets(), new_reg_lookups(lookup), 100); got != 2 {
		t.Fatalf("job 1: %d sessions registered, want 2", got)
	}
	if lookups != 2 {
		t.Fatalf("job 1: %d lookups, want 2 (one per unconfirmed address)", lookups)
	}
	if got := run_job(job_targets(), new_reg_lookups(lookup), 100); got != 2 || lookups != 2 {
		t.Fatalf("job 2 at the same topoheight: registered=%d lookups=%d, want 2 and still 2", got, lookups)
	}
	if got := run_job(job_targets(), new_reg_lookups(lookup), 101); got != 2 || lookups != 3 {
		t.Fatalf("job 3 at a new topoheight: registered=%d lookups=%d, want 2 and 3 (only the unregistered address again)", got, lookups)
	}
}

func TestNeedsRegistrationCheck(t *testing.T) {
	cases := []struct {
		valid         bool
		checked, topo int64
		want          bool
	}{{true, -1, 5, false}, {false, -1, 0, true}, {false, 5, 5, false}, {false, 5, 6, true}}
	for _, c := range cases {
		if got := needs_registration_check(c.valid, c.checked, c.topo); got != c.want {
			t.Errorf("needs_registration_check(%v,%d,%d)=%v want %v", c.valid, c.checked, c.topo, got, c.want)
		}
	}
}

// Run with -race: per-miner job goroutines and OnMessage touch the same sessions; every access must hold the lock.
func TestJobTargetsRaceFree(t *testing.T) {
	var sessions []*user_session
	for i := 0; i < 8; i++ {
		sessions = append(sessions, &user_session{address_sum: [32]byte{byte(i)}, checked_topo: -1})
	}
	with_clients(t, sessions)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for _, s := range sessions {
		wg.Add(1)
		go func(s *user_session) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				record_share(s, i%3 != 0, nil, i%2 == 0)
				if i%5 == 0 {
					record_share(s, false, errors.New("bad"), true)
				}
			}
		}(s)
	}
	var sum uint64
	for topo := int64(0); topo < 200; topo++ {
		targets := job_targets()
		run_job(targets, new_reg_lookups(func(a [32]byte) bool { return a[0]%2 == 0 }), topo)
		for _, tg := range targets {
			sum += tg.blocks + tg.miniblocks + tg.rejected
		}
	}
	close(stop)
	wg.Wait()
	_ = sum
}

// A share being verified must not hold up job dispatch: SendJob only needs client_list_mutex, verification has its
// own slot.
func TestVerifyDoesNotBlockJobDispatch(t *testing.T) {
	with_clients(t, []*user_session{{checked_topo: -1}})
	inside, release := make(chan struct{}), make(chan struct{})
	go verify_share(func() { close(inside); <-release })
	<-inside
	defer close(release)
	done := make(chan int)
	go func() { done <- len(job_targets()) }()
	select {
	case n := <-done:
		if n != 1 {
			t.Fatalf("job_targets returned %d targets, want 1", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("job dispatch blocked while a share was being verified")
	}
}
