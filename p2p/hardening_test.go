package p2p

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/rpc2"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
)

func TestPenaltyDecayEscalationAndExemption(t *testing.T) {
	penalty_mu.Lock()
	penalty_map = map[string]*misbehaviour{}
	penalty_mu.Unlock()
	t0 := time.Unix(1_800_000_000, 0)
	ip := "198.51.100.9"
	if s := add_penalty(ip, "invalid_pow", t0); s != 0 {
		t.Fatalf("one invalid PoW banned (%d s)", s)
	}
	if s := add_penalty(ip, "invalid_pow", t0); s != PENALTY_BAN_BASE {
		t.Fatalf("second invalid PoW: ban %d s, want %d", s, PENALTY_BAN_BASE)
	}
	add_penalty(ip, "invalid_pow", t0.Add(time.Second))
	if s := add_penalty(ip, "invalid_pow", t0.Add(time.Second)); s != 2*PENALTY_BAN_BASE {
		t.Fatalf("second offence: ban %d s, want doubled %d", s, 2*PENALTY_BAN_BASE)
	}
	// decay: 50 points, one half-life later, plus 50 is 75 — no ban
	ip2 := "198.51.100.10"
	add_penalty(ip2, "invalid_pow", t0)
	if s := add_penalty(ip2, "invalid_pow", t0.Add(PENALTY_HALF_LIFE)); s != 0 {
		t.Fatalf("a decayed score banned (%d s)", s)
	}
	// escalation is capped
	ip3 := "198.51.100.11"
	var last uint64
	for i := 0; i < 40; i++ {
		if s := add_penalty(ip3, "invalid_pow", t0); s > 0 {
			last = s
		}
	}
	if last != PENALTY_BAN_MAX {
		t.Fatalf("ban length not capped: %d", last)
	}
	// seed/priority/exclusive nodes are never banned by score
	saved := nonbanlist
	defer func() { nonbanlist = saved }()
	nonbanlist = []string{"203.0.113.5:11011"}
	for i := 0; i < 10; i++ {
		if s := add_penalty("203.0.113.5", "invalid_pow", t0); s != 0 {
			t.Fatalf("a never-ban node was banned")
		}
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("an unknown reason must panic, not score 0")
			}
		}()
		add_penalty(ip, "no-such-reason", t0)
	}()
}

func TestHeavyCaps(t *testing.T) {
	c := &Connection{logger: globals.Logger}
	var rel []func()
	for i := 0; i < MAX_HEAVY_PER_CONNECTION; i++ {
		r, ok, _ := c.acquire_heavy()
		if !ok {
			t.Fatalf("slot %d refused", i)
		}
		rel = append(rel, r)
	}
	if _, ok, _ := c.acquire_heavy(); ok {
		t.Fatalf("connection cap %d not enforced", MAX_HEAVY_PER_CONNECTION)
	}
	if err := heavy(c, "Peer.GetObject", func() error { return nil }); !errors.Is(err, ErrBusy) {
		t.Fatalf("heavy() beyond the cap: %v", err)
	}
	rel[0]()
	if r, ok, _ := c.acquire_heavy(); !ok {
		t.Fatal("a released slot was not reusable")
	} else {
		r()
	}
	for _, r := range rel[1:] {
		r()
	}
	if len(heavy_global) != 0 {
		t.Fatalf("global slots leaked: %d", len(heavy_global))
	}
}

// a peer that reads our request and never answers: the call must end at its deadline
func TestCallTimesOut(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go io.Copy(io.Discard, b)
	CALL_TIMEOUTS["Peer.NeverAnswered"] = 100 * time.Millisecond
	defer delete(CALL_TIMEOUTS, "Peer.NeverAnswered")
	c := &Connection{Client: rpc2.NewClientWithCodec(NewCBORCodec(a)), logger: globals.Logger, Addr: fake_addr("198.51.100.20:11011")}
	start := time.Now()
	err := c.call("Peer.NeverAnswered", Dummy{}, &Dummy{})
	if err == nil || !strings.Contains(err.Error(), "no answer within") {
		t.Fatalf("err = %v", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("call took %s", el)
	}
}

// review 2026-10-22: a request that arrives before OnConnect attached the connection reaches heavy() with nil; rpc2's
// request goroutine has no recover, so a panic there would end the process.
func TestHeavyNilConnectionDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("heavy(nil) panicked: %v", r)
		}
	}()
	if err := heavy(nil, "Peer.GetObject", func() error { return nil }); !errors.Is(err, ErrNoConnection) {
		t.Fatalf("err = %v", err)
	}
}

// a full GLOBAL pool is other peers' load: the asking peer must not be scored for it
func TestGlobalBusyIsNotScored(t *testing.T) {
	penalty_mu.Lock()
	penalty_map = map[string]*misbehaviour{}
	penalty_mu.Unlock()
	for i := 0; i < MAX_HEAVY_GLOBAL; i++ {
		heavy_global <- struct{}{}
	}
	defer func() {
		for i := 0; i < MAX_HEAVY_GLOBAL; i++ {
			<-heavy_global
		}
	}()
	c := &Connection{logger: globals.Logger, Addr: fake_addr("198.51.100.30:11011")}
	if err := heavy(c, "Peer.GetObject", func() error { return nil }); !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v", err)
	}
	penalty_mu.Lock()
	m := penalty_map["198.51.100.30"]
	penalty_mu.Unlock()
	if m != nil {
		t.Fatalf("the peer was scored for a full global pool: %+v", *m)
	}
}

// a timed-out notification is not scored; a timed-out fetch is
func TestNotificationTimeoutsAreNotScored(t *testing.T) {
	for _, method := range []string{"Peer.NotifyINV", "Peer.NotifyMiniBlock"} {
		if !NOTIFICATIONS[method] {
			t.Fatalf("%s must be in NOTIFICATIONS", method)
		}
	}
	if NOTIFICATIONS["Peer.GetObject"] {
		t.Fatal("GetObject is a fetch, its timeouts must be scored")
	}
}

// a connection that exited before Connection_Add must not be left in the pool
func TestExitedConnectionIsNotAdded(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c := &Connection{Addr: fake_addr("203.0.113.44:11011"), Conn: a, ConnTls: a, logger: globals.Logger}
	c.exit()
	if Connection_Add(c) {
		t.Fatal("an exited connection was added")
	}
	if _, ok := connection_map.Load(Address(c)); ok {
		t.Fatal("an exited connection is in the pool")
	}
}

func TestV2BanEscalates(t *testing.T) {
	ip := "198.51.100.77"
	want := []uint64{3600, 7200, 14400, 28800, 57600, PENALTY_BAN_MAX, PENALTY_BAN_MAX, PENALTY_BAN_MAX}
	for i, w := range want {
		if got := v2_ban_seconds(ip); got != w {
			t.Fatalf("v2 drop %d: ban %d s, want %d", i+1, got, w)
		}
	}
	if got := v2_ban_seconds("198.51.100.78"); got != V2_BAN_BASE {
		t.Fatalf("a different peer's first drop: %d s, want %d", got, V2_BAN_BASE)
	}
}

func TestUnknownTipSkipsVerification(t *testing.T) {
	known := crypto.Hash{1}
	height := func(h crypto.Hash) int64 {
		if h == known {
			return 7797456
		}
		return -1
	}
	if unknown_tip(height, []crypto.Hash{known}) {
		t.Fatal("a known tip was reported unknown")
	}
	if !unknown_tip(height, []crypto.Hash{known, {2}}) {
		t.Fatal("a block building on an unknown tip would reach VerifyMiniblockPoW and panic")
	}
}
