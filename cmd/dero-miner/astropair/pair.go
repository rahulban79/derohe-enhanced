// Package astropair computes two AstroBWTv3 hashes per call for the miner, so that the two final SHA-256 passes
// (about 280 KB each, roughly a fifth of a hash after the descriptor sort) run interleaved on the SHA unit.
//
// It is MINER-ONLY. Nothing in derod imports it, and astrobwt/ is untouched: stage 1 is a generated copy of
// AstroBWTv3's (stage_gen.go, checked against pow.go by TestStageIsCurrent), the suffix array is the unique suffix
// array of the same text, and the SHA-256 is the GOROOT block function (sha_arm64.s). TestBitExact compares every
// result with astrobwtv3.AstroBWTv3, and the miner repeats that comparison at startup before it pairs anything.
package astropair

import (
	"sync/atomic"
	"unsafe"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
)

// lane is one hash's scratch: the stage-1 text and its suffix array (the same sizes as astrobwtv3.ScratchData's).
type lane struct {
	data [astrobwtv3.MAX_LENGTH + 64]byte
	sa   [astrobwtv3.MAX_LENGTH]int32
}

// Scratch holds the two scratch sets of one mining thread. It is not safe for concurrent use.
type Scratch struct {
	a, b lane
}

func NewScratch() *Scratch { return new(Scratch) }

// SuffixSort is the sorter both lanes use; the miner sets it to its guarded descriptor sort. It has the semantics of
// astrobwtv3.SuffixSort: false declines, and that lane is then finished by astrobwtv3.FinishHashFromData, i.e. the
// built-in SA-IS and a plain SHA-256, exactly what AstroBWTv3 does when its hook declines. Nil declines every text.
var SuffixSort func(text []byte, sa []int32) bool

// RecoveredPanics counts calls of Hash2 that panicked. Such a call returns ok=false and no hash for either nonce.
var RecoveredPanics uint64

// FailHash is what Hash2 puts in both results when it returns ok=false: the largest 256-bit value, which no
// difficulty above 1 accepts. Callers must still check ok and re-hash both nonces another way.
var FailHash = [32]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// testHook, when set by a test, runs after each lane's stage 1 (lane 0 = a, 1 = b); tests make it panic.
var testHook func(lane int)

// Hash2 returns AstroBWTv3(ina) and AstroBWTv3(inb). If anything panics, neither hash is produced: ok is false and
// both results are FailHash. (AstroBWTv3 itself turns a panic into a random failing hash; here the caller is told.)
func Hash2(ina, inb []byte, s *Scratch) (ha, hb [32]byte, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			atomic.AddUint64(&RecoveredPanics, 1)
			ha, hb, ok = FailHash, FailHash, false
		}
	}()
	na := stage1(ina, &s.a)
	if testHook != nil {
		testHook(0)
	}
	okA := sortLane(&s.a, na)
	nb := stage1(inb, &s.b)
	if testHook != nil {
		testHook(1)
	}
	okB := sortLane(&s.b, nb)

	switch {
	case okA && okB:
		sum2(saBytes(&s.a, na), saBytes(&s.b, nb), &ha, &hb)
	case okA:
		ha = sum1(saBytes(&s.a, na))
		hb = astrobwtv3.FinishHashFromData(s.b.data[:nb], nb)
	case okB:
		ha = astrobwtv3.FinishHashFromData(s.a.data[:na], na)
		hb = sum1(saBytes(&s.b, nb))
	default:
		ha = astrobwtv3.FinishHashFromData(s.a.data[:na], na)
		hb = astrobwtv3.FinishHashFromData(s.b.data[:nb], nb)
	}
	return ha, hb, true
}

// Hash1 is the single-nonce path of this package (same stage, sort and SHA code, one lane); for tests and benches.
func Hash1(in []byte, s *Scratch) (h [32]byte, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			atomic.AddUint64(&RecoveredPanics, 1)
			h, ok = FailHash, false
		}
	}()
	n := stage1(in, &s.a)
	if !sortLane(&s.a, n) {
		return astrobwtv3.FinishHashFromData(s.a.data[:n], n), true
	}
	return sum1(saBytes(&s.a, n)), true
}

func sortLane(l *lane, n uint32) bool {
	f := SuffixSort
	return f != nil && f(l.data[:n], l.sa[:n])
}

// saBytes is the little-endian byte image of sa[:n], which is what AstroBWTv3 hashes (pow.go, LittleEndian branch).
// Every target with the asm is little-endian; sha_other.go serves the rest.
func saBytes(l *lane, n uint32) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&l.sa[0])), int(n)*4)
}
