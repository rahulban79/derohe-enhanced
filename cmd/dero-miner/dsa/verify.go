package dsa

// Verify is NOT part of the third-party code: it is this miner's independent check that sa is THE suffix array of
// text: every entry lies in 0..n-1 and every adjacent pair of suffixes is strictly increasing. Strict order makes the
// n entries distinct, so they are a permutation of 0..n-1 with no separate duplicate check (a duplicate bitmap was
// dropped when its go mutation proved it could never decide the result, 2026-10-22). A sorter that passes cannot
// have produced a wrong hash. Cost is O(n + total LCP); the miner runs it on a sample of calls
// (cmd/dero-miner/fastsort.go).

import "bytes"

func Verify(text []byte, sa []int32) bool {
	n := len(text)
	if len(sa) < n {
		return false
	}
	for i := 0; i < n; i++ {
		if sa[i] < 0 || int(sa[i]) >= n {
			return false
		}
	}
	for i := 1; i < n; i++ {
		if bytes.Compare(text[sa[i-1]:n], text[sa[i]:n]) >= 0 {
			return false
		}
	}
	return true
}
