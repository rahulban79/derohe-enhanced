package rpc

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/lesismal/nbio/nbhttp/websocket"
)

func TestPresenceEvent(t *testing.T) {
	cases := []struct {
		before, after int
		want          string
	}{
		{0, 1, "first miner connected"}, {1, 0, "last miner disconnected"},
		{1, 2, ""}, {2, 1, ""}, {0, 0, ""}, {3, 3, ""},
	}
	for _, c := range cases {
		if got := presence_event(c.before, c.after); got != c.want {
			t.Fatalf("presence_event(%d,%d) = %q, want %q", c.before, c.after, got, c.want)
		}
	}
}

// r20: connects and disconnects are counted and the 0 <-> some transitions are reported, which is what the r19
// forensics needed to see that the miner was away for 26 of 26.7 hours
func TestGetworkRegisterUnregister(t *testing.T) {
	with_clients(t, nil)
	c0, d0 := getwork_connects.Get(), getwork_disconnects.Get()
	a, b := new(websocket.Conn), new(websocket.Conn)
	if ev, n := getwork_register(a, &user_session{}); ev != "first miner connected" || n != 1 {
		t.Fatalf("first register: %q %d", ev, n)
	}
	if ev, n := getwork_register(b, &user_session{}); ev != "" || n != 2 {
		t.Fatalf("second register: %q %d", ev, n)
	}
	if s, ev, n := getwork_unregister(a); s == nil || ev != "" || n != 1 {
		t.Fatalf("first unregister: %v %q %d", s, ev, n)
	}
	if s, ev, n := getwork_unregister(b); s == nil || ev != "last miner disconnected" || n != 0 {
		t.Fatalf("last unregister: %v %q %d", s, ev, n)
	}
	if s, ev, _ := getwork_unregister(b); s != nil || ev != "" { // a close for a connection already gone
		t.Fatalf("double unregister: %v %q", s, ev)
	}
	if got := getwork_connects.Get() - c0; got != 2 {
		t.Fatalf("connects counted %d, want 2", got)
	}
	if got := getwork_disconnects.Get() - d0; got != 2 {
		t.Fatalf("disconnects counted %d, want 2 (the duplicate close must not count)", got)
	}
}

func TestRecordShareStampsLastShare(t *testing.T) {
	atomic.StoreInt64(&getwork_last_share_unix, 0)
	s := &user_session{}
	record_share(s, false, nil, true)
	if atomic.LoadInt64(&getwork_last_share_unix) != 0 {
		t.Fatal("a rejected share moved the last-share time")
	}
	before := time.Now().Unix()
	record_share(s, true, nil, true)
	if got := atomic.LoadInt64(&getwork_last_share_unix); got < before {
		t.Fatalf("accepted share not stamped: %d < %d", got, before)
	}
}

// r20 (F4 review): with no miner connected every connect/close of a public getwork port is a 0 -> 1 -> 0
// transition; rapid cycling must give a bounded number of INFO lines, and the next allowed line carries the count.
func TestPresenceLogRateLimited(t *testing.T) {
	p := presence_limiter{last: map[string]time.Time{}, suppressed: map[string]int{}}
	now := time.Unix(1_800_000_000, 0)
	info := 0
	for i := 0; i < 1000; i++ {
		for _, ev := range []string{"first miner connected", "last miner disconnected"} {
			if ok, _ := p.allow(ev, now.Add(time.Duration(i)*time.Millisecond)); ok {
				info++
			}
		}
	}
	if info != 2 {
		t.Fatalf("1000 connect/close cycles in 1 s gave %d INFO lines, want 2 (one per event kind)", info)
	}
	ok, suppressed := p.allow("first miner connected", now.Add(PRESENCE_LOG_WINDOW+time.Second))
	if !ok || suppressed != 999 {
		t.Fatalf("after the window: allowed=%v suppressed=%d, want true 999", ok, suppressed)
	}
	if ok, _ := p.allow("first miner connected", now.Add(PRESENCE_LOG_WINDOW+2*time.Second)); ok {
		t.Fatal("a second line inside the new window was allowed")
	}
}
