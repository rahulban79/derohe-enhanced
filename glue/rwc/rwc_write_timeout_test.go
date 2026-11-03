//go:build !wasm
// +build !wasm

package rwc

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// r19: a peer that stops reading must make Write fail within the timeout and close the socket, so the goroutine
// that writes (a jrpc2 push) and the one that reads (the server loop) are both released.
func TestWriteTimeoutReleasesStuckPeer(t *testing.T) {
	base := runtime.NumGoroutine()
	type res struct {
		write_err error
		read_err  error
		took      time.Duration
	}
	done := make(chan res, 1)
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		rw := NewLimited(c, MaxMessageSize).WithWriteTimeout(200 * time.Millisecond)
		big := bytes.Repeat([]byte("x"), 1<<20)
		t0 := time.Now()
		var werr error
		for i := 0; i < 4096 && werr == nil; i++ { // the client never reads: the socket buffers fill, then Write must time out
			_, werr = rw.Write(big)
		}
		took := time.Since(t0)
		buf := make([]byte, 16)
		_, rerr := rw.Read(buf) // socket closed by the failed write: the reader is released too
		done <- res{werr, rerr, took}
	}))
	defer srv.Close()
	cl, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.write_err == nil {
			t.Fatalf("4 GiB written to a peer that never reads")
		}
		if r.read_err == nil {
			t.Fatalf("socket still readable after a failed write")
		}
		if r.took > 10*time.Second {
			t.Fatalf("write took %s to fail", r.took)
		}
	case <-time.After(15 * time.Second):
		cl.Close()
		t.Fatalf("write to a stuck peer never returned (no write deadline)")
	}
	cl.Close()
	srv.Close()
	for i := 0; i < 200 && runtime.NumGoroutine() > base; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > base {
		t.Fatalf("goroutines: %d before, %d after", base, n)
	}
}

func TestNoWriteTimeoutByDefault(t *testing.T) {
	if (&ReadWriteCloser{}).WriteTimeout != 0 || New(nil).WriteTimeout != 0 {
		t.Fatalf("callers that did not opt in must keep upstream behaviour")
	}
}
