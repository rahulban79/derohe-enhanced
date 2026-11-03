package astrobwtv3

// Non-consensus helper for validating a GPU AstroBWTv3 port. Given the pre-SAIS buffer
// (scratch.data) and data_len that the 256-op loop produces, finish the hash exactly as
// AstroBWTv3 does (SAIS + final SHA256, mirroring pow.go:2444-2461). This lets an external
// program feed a GPU-computed (data, data_len) and check the full hash == AstroBWTv3(input),
// proving the GPU loop is byte-correct. Adds NO new behavior to AstroBWTv3 itself.

import "encoding/binary"

// GpuDebugHook, when non-nil, is called by AstroBWTv3 with the pre-SAIS (scratch.data, data_len)
// so a GPU port can be diffed against the CPU. Nil in production/tests => zero behavior change.
var GpuDebugHook func(data []byte, data_len uint32)

// SuffixSort, when non-nil, builds the suffix array of the stage-1 text in place of the built-in SA-IS. It returns
// false to decline, and the built-in sort then runs. A suffix array is unique, so any correct sorter yields the same
// sa[] and the same hash. Set ONLY by the miner (cmd/dero-miner, after a startup equivalence self-test); derod leaves
// it nil, so block and PoW verification always use the built-in sort.
var SuffixSort func(text []byte, sa []int32) bool

// RecoveredPanics counts recoveries in AstroBWTv3. A recovery returns a random (failing) hash; the miner treats any
// increase as a broken sorter or hasher and stops using the fast path.
var RecoveredPanics uint64

// GpuIterHook, when non-nil, is called every loop iteration with (tries, op, pos1, pos2, lhash,
// prev_lhash) — for tracing a GPU port against the CPU. Nil in production/tests.
var GpuIterHook func(tries, op, pos1, pos2, lhash, prev_lhash uint64)

// SaisRecurseHook, when non-nil, is called once per sais_8_32 with (recursed, numLMS, maxID) —
// to measure how often the recursive path is taken for AstroBWT data. Nil in production.
var SaisRecurseHook func(recursed bool, numLMS, maxID int)

// SaisDepthHook, when non-nil, is called at each sais_32 entry (recursion level ≥1) with (textLen, textMax).
var SaisDepthHook func(textLen, textMax int)

// Sais32Hash finishes a hash but builds the suffix array via sais_32 on the byte data PROMOTED
// to int32 (textMax=256), instead of sais_8_32. If this == AstroBWTv3, then porting ONLY the
// int32 SA-IS variant (sais_32 + its helpers) to GPU suffices — the byte variant is redundant.
func Sais32Hash(data []byte, data_len uint32) (outputhash [32]byte) {
	scratch := Pool.Get().(*ScratchData)
	defer Pool.Put(scratch)

	itext := make([]int32, data_len)
	for i := uint32(0); i < data_len; i++ {
		itext[i] = int32(data[i])
	}
	sa := scratch.sa[:data_len]
	for i := range sa {
		sa[i] = 0
	}
	tmp := make([]int32, 2*256)
	sais_32(itext, 256, sa, tmp)

	// hash sa as int32 LE (same as pow.go:2447-2461, LittleEndian path)
	sb := make([]byte, int(data_len)*4)
	for i, v := range sa {
		binary.LittleEndian.PutUint32(sb[i*4:], uint32(v))
	}
	scratch.hasher.Reset()
	scratch.hasher.Write(sb)
	_ = scratch.hasher.Sum(outputhash[:0])
	return
}

// FinishHashFromData completes an AstroBWTv3 hash from a pre-SAIS data buffer + data_len.
func FinishHashFromData(data []byte, data_len uint32) (outputhash [32]byte) {
	scratch := Pool.Get().(*ScratchData)
	defer Pool.Put(scratch)

	copy(scratch.data[:data_len], data[:data_len])
	text_32_0alloc(scratch.data[:data_len], scratch.sa[:data_len])

	if LittleEndian {
		scratch.hasher.Reset()
		scratch.hasher.Write(scratch.sa_bytes[:data_len*4])
	} else {
		var s [MAX_LENGTH * 4]byte
		for i, c := range scratch.sa[:data_len] {
			binary.LittleEndian.PutUint32(s[i<<1:], uint32(c))
		}
		scratch.hasher.Reset()
		scratch.hasher.Write(s[:data_len*4])
	}
	_ = scratch.hasher.Sum(outputhash[:0])
	return
}
