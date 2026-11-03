package main

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/rpc"
	"github.com/gorilla/websocket"
)

// test_blob builds a 48-byte hashing blob: version 1, final flag as asked, key hash bytes 16..31 = key.
func test_blob(final bool, key byte) string {
	var b [block.MINIBLOCK_SIZE]byte
	b[0] = 1
	if final {
		b[0] |= 0x20
	}
	for i := 16; i < 32; i++ {
		b[i] = key
	}
	return hex.EncodeToString(b[:])
}

func own_key(k byte) *[16]byte {
	var o [16]byte
	for i := range o {
		o[i] = k
	}
	return &o
}

// The crash: hex.Decode into a [48]byte panics for a blob longer than 96 hex characters; decode_job_blob must not.
func TestDecodeJobBlobNeverPanics(t *testing.T) {
	var dst [block.MINIBLOCK_SIZE]byte
	for _, s := range []string{"", "00", strings.Repeat("00", 47), strings.Repeat("00", 49), strings.Repeat("ab", 5000), strings.Repeat("zz", 48)} {
		if decode_job_blob(&dst, s) {
			t.Fatalf("blob of %d hex chars accepted", len(s))
		}
	}
	if !decode_job_blob(&dst, test_blob(false, 7)) || dst[0] != 1 || dst[16] != 7 {
		t.Fatalf("a valid blob was refused or mis-decoded: %x", dst)
	}
}

func TestJobVerdict(t *testing.T) {
	good := rpc.GetBlockTemplate_Result{Blockhashing_blob: test_blob(false, 7), Difficulty: "1000"}
	cases := []struct {
		name    string
		mut     func(*rpc.GetBlockTemplate_Result)
		own     *[16]byte
		strict  bool
		reason  string
		foreign bool
	}{
		{"valid", func(j *rpc.GetBlockTemplate_Result) {}, own_key(7), false, "", false},
		{"valid, no own key", func(j *rpc.GetBlockTemplate_Result) {}, nil, true, "", false},
		{"long blob", func(j *rpc.GetBlockTemplate_Result) { j.Blockhashing_blob += "00" }, nil, false, "blob", false},
		{"huge blob", func(j *rpc.GetBlockTemplate_Result) { j.Blockhashing_blob = strings.Repeat("ab", 40000) }, nil, false, "blob", false},
		{"bad version", func(j *rpc.GetBlockTemplate_Result) { j.Blockhashing_blob = "02" + j.Blockhashing_blob[2:] }, nil, false, "version", false},
		{"zero difficulty", func(j *rpc.GetBlockTemplate_Result) { j.Difficulty = "0" }, nil, false, "difficulty", false},
		{"negative difficulty", func(j *rpc.GetBlockTemplate_Result) { j.Difficulty = "-5" }, nil, false, "difficulty", false},
		{"garbage difficulty", func(j *rpc.GetBlockTemplate_Result) { j.Difficulty = "x" }, nil, false, "difficulty", false},
		{"huge difficulty", func(j *rpc.GetBlockTemplate_Result) { j.Difficulty = "1" + strings.Repeat("0", 90) }, nil, false, "difficulty", false},
		{"foreign key, lenient", func(j *rpc.GetBlockTemplate_Result) {}, own_key(9), false, "", true},
		{"foreign key, strict", func(j *rpc.GetBlockTemplate_Result) {}, own_key(9), true, "foreign_key", true},
		{"final job, other key", func(j *rpc.GetBlockTemplate_Result) { j.Blockhashing_blob = test_blob(true, 3) }, own_key(9), true, "", false},
	}
	for _, c := range cases {
		j := good
		c.mut(&j)
		reason, foreign := job_verdict(&j, c.own, c.strict)
		if reason != c.reason || foreign != c.foreign {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", c.name, reason, foreign, c.reason, c.foreign)
		}
	}
}

// take_job must keep the previous job when the next one is malformed, and count the drop.
func TestTakeJobDropsMalformed(t *testing.T) {
	mutex.Lock()
	saved, saved_counter := job, job_counter
	mutex.Unlock()
	defer func() { mutex.Lock(); job, job_counter = saved, saved_counter; mutex.Unlock() }()

	good := rpc.GetBlockTemplate_Result{Blockhashing_blob: test_blob(false, 7), Difficulty: "1000", Height: 5}
	if !take_job(good) {
		t.Fatal("a valid job was dropped")
	}
	c0, r0 := atomic.LoadInt64(&job_counter), atomic.LoadUint64(&jobs_rejected)
	bad := good
	bad.Blockhashing_blob = strings.Repeat("00", 49)
	bad.Height = 6
	if take_job(bad) {
		t.Fatal("a job with a 98-hex-char blob was taken: every mining thread would panic on it")
	}
	mutex.RLock()
	cur := job
	mutex.RUnlock()
	if cur.Height != 5 || atomic.LoadInt64(&job_counter) != c0 {
		t.Fatalf("previous job replaced: height %d, counter %d -> %d", cur.Height, c0, atomic.LoadInt64(&job_counter))
	}
	if atomic.LoadUint64(&jobs_rejected) != r0+1 {
		t.Fatalf("drop not counted")
	}
}

// dial_getwork must bound one message: a daemon (or a man in the middle; TLS is not verified) sending 1 MiB is
// refused with a read-limit error instead of being buffered.
func TestDialGetworkReadLimit(t *testing.T) {
	up := websocket.Upgrader{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		c.WriteMessage(websocket.TextMessage, []byte(`{"jobid":"`+strings.Repeat("a", 1<<20)+`"}`))
		c.ReadMessage() // hold until the client goes
	}))
	defer srv.Close()
	conn, err := dial_getwork("wss" + strings.TrimPrefix(srv.URL, "https") + "/ws/x")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var res rpc.GetBlockTemplate_Result
	err = read_job(conn, 0, &res)
	if err != websocket.ErrReadLimit {
		t.Fatalf("1 MiB job: got %v, want websocket.ErrReadLimit", err)
	}
}

func FuzzJobVerdict(f *testing.F) {
	f.Add(test_blob(false, 7), "1000", false)
	f.Add(strings.Repeat("00", 49), "1", true)
	f.Add("zz", "-1", false)
	own := own_key(7)
	f.Fuzz(func(t *testing.T, blob, diff string, strict bool) {
		j := rpc.GetBlockTemplate_Result{Blockhashing_blob: blob, Difficulty: diff}
		reason, _ := job_verdict(&j, own, strict)
		if reason == "" { // anything accepted must decode into the fixed buffer every consumer uses
			var w [block.MINIBLOCK_SIZE]byte
			if !decode_job_blob(&w, blob) || w[0]&0xf != 1 {
				t.Fatalf("accepted a job the miner cannot decode: %q", blob)
			}
		}
	})
}
