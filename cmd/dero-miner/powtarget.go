package main

// Round 22 splitpipe: the per-hash difficulty check without big.Int.
//
// CheckPowHashBig (difficulty.go) divides 2^256 by the difficulty and allocates three big.Ints for EVERY hash. In
// --gpu-mode=split the GPU-SHA hashes of a whole 4096-nonce batch are checked one after another on the engine's single
// reply goroutine (gsplit collect -> split_found), and the ring slot is only released to the feeder (the next stage-1
// command) after the last one, so that per-hash cost sits on the GPU's critical path. powTarget does the division once
// per job and compares the 256-bit little-endian hash with the precomputed target word by word: the verdict is exactly
// CheckPowHashBig's (hash <= floor(2^256 / difficulty)), see TestPowTargetMatchesCheckPowHashBig.

import (
	"encoding/binary"
	"math/big"

	"github.com/deroproject/derohe/cryptography/crypto"
)

type powTarget struct {
	w    [4]uint64 // floor(2^256 / difficulty), least significant word first
	all  bool      // the target is >= 2^256 (difficulty 1): every hash meets it
	slow *big.Int  // difficulty <= 0: defer to CheckPowHashBig (it panics on zero, as before)
	set  bool      // made by newPowTarget (the zero value is not a target)
}

// newPowTarget precomputes the target of a difficulty (the caller keeps d unchanged while the target is in use).
func newPowTarget(d *big.Int) (t powTarget) {
	t.set = true
	if d.Sign() <= 0 {
		t.slow = d
		return
	}
	q := new(big.Int).Div(oneLsh256, d)
	if q.BitLen() > 256 {
		t.all = true
		return
	}
	var b [32]byte
	q.FillBytes(b[:]) // big-endian
	for i := 0; i < 4; i++ {
		t.w[i] = binary.BigEndian.Uint64(b[24-8*i:])
	}
	return
}

// meets reports CheckPowHashBig(h, d) for the difficulty the target was made from.
func (t *powTarget) meets(h crypto.Hash) bool {
	if t.all {
		return true
	}
	if t.slow != nil {
		return CheckPowHashBig(h, t.slow)
	}
	for i := 3; i >= 0; i-- { // the hash is a little-endian 256-bit integer (HashToBig reverses it)
		hw := binary.LittleEndian.Uint64(h[8*i:])
		if hw != t.w[i] {
			return hw < t.w[i]
		}
	}
	return true // equal: CheckPowHashBig accepts hash == target
}
