//go:build !wasm
// +build !wasm

package rwc

// r27 (glue-global): the coder/websocket (nhooyr) adapter, the wasm wallet's RPC transport, was 0.0% covered.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestR27NhooyrWriteHandlesShortWrites(t *testing.T) {
	sw := &short_writer{}
	r := &ReadWriteCloserNhooyr{w: sw}
	msg := []byte(`{"jsonrpc":"2.0","id":1,"result":"Pong "}`)
	if n, err := r.Write(msg); err != nil || n != len(msg) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if got := sw.String(); got != string(msg) { // was p, not p[n:]: "{"j{"j{"j..."
		t.Fatalf("wrote %q, want %q", got, msg)
	}
	if r.w != nil {
		t.Fatalf("a complete message must close (flush) the writer")
	}
}

type failing_writer struct{ closed bool }

func (f *failing_writer) Write(p []byte) (int, error) { return 1, errors.New("broken pipe") }
func (f *failing_writer) Close() error                { f.closed = true; return nil }

// a failed write must return its error even when the writer then closes cleanly (both adapters returned Close's nil)
func TestR27WriteErrorSurvivesClose(t *testing.T) {
	fw := &failing_writer{}
	r := &ReadWriteCloserNhooyr{w: fw}
	if n, err := r.Write([]byte("abcdef")); n != 1 || err == nil || !fw.closed || r.w != nil {
		t.Fatalf("nhooyr: n=%d err=%v closed=%v", n, err, fw.closed)
	}
	if err := r.Close(); err != nil { // idempotent: nothing open
		t.Fatalf("second Close: %v", err)
	}
	fg := &failing_writer{}
	g := &ReadWriteCloser{w: fg}
	if n, err := g.Write([]byte("abcdef")); n != 1 || err == nil || !fg.closed || g.w != nil {
		t.Fatalf("gorilla: n=%d err=%v closed=%v", n, err, fg.closed)
	}
}

// a real socket pair: the server writes two messages through the adapter, the client reads them through the adapter.
func nhooyr_pair(t *testing.T, msgs ...[]byte) *ReadWriteCloserNhooyr {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		rw := NewNhooyr(c)
		for _, m := range msgs {
			if _, err := rw.Write(m); err != nil {
				return
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c.Read(ctx) // until the client closes
	}))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(websocket.StatusNormalClosure, "") })
	return NewNhooyr(c)
}

func read_message(r io.Reader, buf []byte) ([]byte, error) {
	var out []byte
	for {
		n, err := r.Read(buf)
		out = append(out, buf[:n]...)
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
	}
}

func TestR27NhooyrRoundTripMessages(t *testing.T) {
	a, b := []byte(`{"jsonrpc":"2.0","id":1,"result":"Pong "}`), bytes.Repeat([]byte("y"), 70000)
	rw := nhooyr_pair(t, a, b)
	buf := make([]byte, 4096) // smaller than b: one message spans many Reads, EOF marks its end
	for i, want := range [][]byte{a, b} {
		got, err := read_message(rw, buf)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("message %d: %d bytes, err %v; want %d bytes", i, len(got), err, len(want))
		}
	}
}

func TestR27NhooyrReadLimitMatchesServers(t *testing.T) {
	if NhooyrReadLimit != MaxMessageSize {
		t.Fatalf("nhooyr read limit %d, servers %d", NhooyrReadLimit, MaxMessageSize)
	}
	big := bytes.Repeat([]byte("z"), 3<<20) // over the old 2 MiB literal, well under MaxMessageSize
	rw := nhooyr_pair(t, big)
	got, err := read_message(rw, make([]byte, 1<<16))
	if err != nil || len(got) != len(big) {
		t.Fatalf("3 MiB reply: read %d bytes, err %v", len(got), err)
	}
}
