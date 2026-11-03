package astropair

// Entry points for dero-miner --gpu-mode=split (cmd/dero-miner/gsplit): the stage-1 text is computed elsewhere (the
// Metal k_s1tg kernel) and handed in; the CPU runs only the descriptor sort and, optionally, the paired final SHA-256.

import (
	"sync/atomic"
	"unsafe"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
)

// SortSum2 returns the AstroBWTv3 hashes whose stage-1 texts are ta and tb, sorting into s's lanes and hashing both
// suffix arrays with the interleaved SHA. A declined sort finishes that text with astrobwtv3.FinishHashFromData (the
// built-in SA-IS), exactly as Hash2 does. ok=false (both FailHash) after a recovered panic.
func SortSum2(ta, tb []byte, s *Scratch) (ha, hb [32]byte, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			atomic.AddUint64(&RecoveredPanics, 1)
			ha, hb, ok = FailHash, FailHash, false
		}
	}()
	na, nb := len(ta), len(tb)
	f := SuffixSort
	okA := f != nil && f(ta, s.a.sa[:na])
	okB := f != nil && f(tb, s.b.sa[:nb])
	pa := unsafe.Slice((*byte)(unsafe.Pointer(&s.a.sa[0])), na*4)
	pb := unsafe.Slice((*byte)(unsafe.Pointer(&s.b.sa[0])), nb*4)
	switch {
	case okA && okB:
		sum2(pa, pb, &ha, &hb)
	case okA:
		ha = sum1(pa)
		hb = astrobwtv3.FinishHashFromData(tb, uint32(nb))
	case okB:
		ha = astrobwtv3.FinishHashFromData(ta, uint32(na))
		hb = sum1(pb)
	default:
		ha = astrobwtv3.FinishHashFromData(ta, uint32(na))
		hb = astrobwtv3.FinishHashFromData(tb, uint32(nb))
	}
	return ha, hb, true
}

// SortOnly builds the suffix array of text into sa (a GPU-shared buffer, for the GPU final SHA). false = declined or
// panicked; the caller must then finish that hash on the CPU (astrobwtv3.FinishHashFromData).
func SortOnly(text []byte, sa []int32) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			atomic.AddUint64(&RecoveredPanics, 1)
			ok = false
		}
	}()
	f := SuffixSort
	return f != nil && f(text, sa[:len(text)])
}

// Stage1Text writes AstroBWTv3's stage-1 text of input into dst and returns its length: the CPU reference of the GPU
// k_s1tg kernel (tests use it as a software GPU). dst must hold astrobwtv3.MAX_LENGTH+64 bytes.
func Stage1Text(input []byte, dst []byte, s *Scratch) int {
	n := stage1(input, &s.a)
	return copy(dst, s.a.data[:n])
}
