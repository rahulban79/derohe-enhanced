package p2p

import (
	"testing"
	"time"
)

func TestNTPCorrectionResistsForgedAnswers(t *testing.T) {
	var w [128]time.Duration
	// one forged answer right after startup must not move the clock at all
	w[0] = -1000 * time.Second
	if got := ntp_correction(w[:]); got != 0 {
		t.Fatalf("one forged answer moved the clock by %v", got)
	}
	// a full window of honest ~2 ms answers plus one forged answer: the system clock stays trusted
	for i := range w {
		w[i] = 2 * time.Millisecond
	}
	w[7] = -1000 * time.Second
	if got := ntp_correction(w[:]); got != 0 {
		t.Fatalf("a forged minority answer moved the clock by %v", got)
	}
	// an odd number of answers, one forged: the middle one decides
	if got := ntp_correction([]time.Duration{-1000 * time.Second, 2 * time.Millisecond, 3 * time.Millisecond}); got != 0 {
		t.Fatalf("a forged minority among three answers moved the clock by %v", got)
	}
	// a genuinely wrong system clock (+3 s by every server) is still corrected
	for i := range w {
		w[i] = 3 * time.Second
	}
	w[9] = -1000 * time.Second
	if got := ntp_correction(w[:]); got != 3*time.Second {
		t.Fatalf("correction %v, want 3s", got)
	}
	// small offsets are left to the system clock, as upstream did
	if got := ntp_correction([]time.Duration{10 * time.Millisecond, 20 * time.Millisecond, -5 * time.Millisecond}); got != 0 {
		t.Fatalf("small offset applied: %v", got)
	}
	if got := ntp_correction([]time.Duration{time.Second, 2 * time.Second, 3 * time.Second, 4 * time.Second}); got != 2500*time.Millisecond {
		t.Fatalf("even-count median %v", got)
	}
}
