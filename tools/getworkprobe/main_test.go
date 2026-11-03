package main

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/rpc"
)

func frame(t *testing.T, height uint64, final bool) []byte {
	var m block.MiniBlock
	m.Version, m.Height, m.PastCount, m.Final, m.HighDiff = 1, height, 1, final, final
	b, _ := json.Marshal(rpc.GetBlockTemplate_Result{JobID: "1.0.notified", Blockhashing_blob: hex.EncodeToString(m.Serialize())})
	return b
}

func TestR24ProbeParse(t *testing.T) {
	j, err := parse(frame(t, 77, true), 5)
	if err != nil || j.Height != 77 || !j.Final || j.RecvMs != 5 || j.JobID != "1.0.notified" {
		t.Fatalf("%+v %v", j, err)
	}
	if _, err := parse([]byte(`{"blockhashing_blob":"zz"}`), 0); err == nil {
		t.Fatal("bad hex accepted")
	}
}

func TestR24ProbeSummary(t *testing.T) {
	s := summarize([]Job{{1000, 10, false, ""}, {1500, 10, false, ""}, {1560, 10, true, ""}, {3000, 10, true, ""},
		{4000, 11, false, ""}, {4002, 11, true, ""}, {5000, 12, false, ""}})
	if s.Jobs != 7 || s.Finals != 3 || s.Heights != 3 || len(s.Flips) != 2 || s.Flips[0] != 2 || s.Flips[1] != 60 {
		t.Fatalf("%+v", s)
	}
}
