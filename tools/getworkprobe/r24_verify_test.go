package main

import "testing"

// r24 (verify-getworkops): the client-side "last normal -> first final" is NOT an upper bound of the node's dead window:
// two dead normal jobs at 0 and 50 ms and the final at 100 ms give the node 100 ms (from the FIRST dead send) and the
// client 50 ms (from the LAST normal job).
func TestR24VerifyProbeFlipIsNotAnUpperBound(t *testing.T) {
	s := summarize([]Job{{RecvMs: 1000, Height: 5}, {RecvMs: 1050, Height: 5}, {RecvMs: 1100, Height: 5, Final: true}})
	if len(s.Flips) != 1 || s.Flips[0] != 50 {
		t.Fatalf("flips %v", s.Flips)
	}
}
