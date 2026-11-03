package main

import (
	"bytes"
	"testing"
	"time"
)

// r22 (security dim): the miner's r21 text parsers read files any process of the user can write (BUILD_STAMPS next
// to the GPU binary, the run ledger). They must never panic, and what they return must respect their own format.
func FuzzMinerParsers(f *testing.F) {
	f.Add([]byte("gpu_split_server " + string(bytes.Repeat([]byte("a"), 64)) + " " + string(bytes.Repeat([]byte("b"), 64)) + " # c\n"))
	f.Add([]byte(`{"kind":"run","run_id":"x","pid":1}` + "\n{\"kind\":\"run\"\n\x00\xff"))
	f.Fuzz(func(t *testing.T, data []byte) {
		for name, st := range parse_gpu_stamps(bytes.NewReader(data)) {
			if name == "" || len(st.src) != 64 || len(st.bin) != 64 {
				t.Fatalf("bad stamp %q %+v", name, st)
			}
		}
		runs, skipped := parse_run_ledger(bytes.NewReader(data))
		if skipped < 0 || len(runs) > bytes.Count(data, []byte("\n"))+1 {
			t.Fatalf("%d runs from %d lines", len(runs), bytes.Count(data, []byte("\n"))+1)
		}
		var b [48]byte
		decode_job_blob(&b, string(data))
		job_error_to_log(string(data), testNow)
	})
}

var testNow = time.Unix(1793300000, 0)
