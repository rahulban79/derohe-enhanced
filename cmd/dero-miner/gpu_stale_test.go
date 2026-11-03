package main

import (
	"testing"

	"github.com/deroproject/derohe/rpc"
)

func TestShareLikelyStale(t *testing.T) {
	normal := "41" + "00" // version 1, pastcount 1, no flags
	final := "71" + "00"  // + HighDiff(0x10) + Final(0x20)
	j := func(h uint64, b string) rpc.GetBlockTemplate_Result {
		return rpc.GetBlockTemplate_Result{Height: h, Blockhashing_blob: b}
	}
	cases := []struct {
		mine, cur rpc.GetBlockTemplate_Result
		want      bool
	}{
		{j(10, normal), j(10, normal), false}, // template refresh only (every <=500ms): still good
		{j(10, normal), j(10, final), true},   // 9 normal already held: the e45b92e8 case at 7798792
		{j(10, final), j(10, final), false},
		{j(10, normal), j(11, normal), true}, // block 10 exists
		{j(10, final), j(11, normal), true},
		{j(11, normal), j(10, normal), false}, // daemon reorg/odd order: do not claim stale
	}
	for i, c := range cases {
		if got := shareLikelyStale(c.mine, c.cur); got != c.want {
			t.Fatalf("case %d: got %v want %v", i, got, c.want)
		}
	}
	if !jobIsFinal(final) || jobIsFinal(normal) || jobIsFinal("") {
		t.Fatal("jobIsFinal")
	}
}
