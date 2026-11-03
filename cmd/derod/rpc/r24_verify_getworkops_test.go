package rpc

import "testing"

// r24 (verify-getworkops): adversarial checks of flip_watch's L9 booking.

// A dead window opened by a change-triggered send: L9 starts at the trigger (the dispatcher's observation of the 9th),
// the conditional delay at the first dead SEND; the two differ by the build time.
func TestR24VerifyL9DeadSeenFromTrigger(t *testing.T) {
	var f flip_watch
	if dead, _, _, _, l9 := f.note(200, false, 9, 990, 1000); !dead || l9 != -1 {
		t.Fatalf("dead job: dead %v l9 %d", dead, l9)
	}
	f.note(200, false, 9, 0, 1040) // a second dead job (keepalive) must not move the start
	_, first, closed, delay, l9 := f.note(200, true, 0, 1090, 1100)
	if !first || !closed || delay != 100 || l9 != 110 {
		t.Fatalf("final: first %v closed %v delay %d l9 %d (want 100 / 110)", first, closed, delay, l9)
	}
	// second final of the same height: no second sample
	if _, first, _, _, l9 := f.note(200, true, 0, 1500, 1600); first || l9 != -1 {
		t.Fatalf("second final booked: first %v l9 %d", first, l9)
	}
}

// A first final with no trigger (connecting miner / keepalive) books the flip but no L9 sample; a trigger in the future
// (clock step) is never booked as a negative or as a start.
func TestR24VerifyL9NoOrFutureTrigger(t *testing.T) {
	var f flip_watch
	if _, first, _, _, l9 := f.note(300, true, 0, 0, 5000); !first || l9 != -1 {
		t.Fatalf("trigger 0: first %v l9 %d", first, l9)
	}
	if _, first, _, _, l9 := f.note(301, true, 0, 6001, 6000); !first || l9 != -1 {
		t.Fatalf("future trigger: first %v l9 %d", first, l9)
	}
	f.note(302, false, 9, 7005, 7000) // future trigger on the dead job: start falls back to the send time
	if _, _, closed, delay, l9 := f.note(302, true, 0, 0, 7050); !closed || delay != 50 || l9 != 50 {
		t.Fatalf("future dead trigger: closed %v delay %d l9 %d", closed, delay, l9)
	}
	// a dead window of a height that ended: the next height's L9 starts at its own trigger, not the stale window
	f.note(303, false, 9, 7990, 8000)
	if _, _, closed, _, l9 := f.note(304, true, 0, 8400, 8410); closed || l9 != 10 {
		t.Fatalf("stale window leaked: closed %v l9 %d", closed, l9)
	}
}
