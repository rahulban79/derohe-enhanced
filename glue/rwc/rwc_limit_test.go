//go:build !wasm
// +build !wasm

package rwc

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/deroproject/derohe/config"
	"github.com/gorilla/websocket"
)

// serve upgrades one connection, wraps it with mk and reports what a full read of the first message returned.
func serve(t *testing.T, mk func(*websocket.Conn) *ReadWriteCloser, payload []byte) (int, error) {
	type res struct {
		n   int
		err error
	}
	done := make(chan res, 1)
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			done <- res{0, err}
			return
		}
		defer c.Close()
		buf := make([]byte, len(payload)+16)
		n, err := io.ReadAtLeast(mk(c), buf, len(payload))
		done <- res{n, err}
	}))
	defer srv.Close()
	cl, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	_ = cl.WriteMessage(websocket.TextMessage, payload)
	r := <-done
	return r.n, r.err
}

func TestDefaultReadIsUnlimited(t *testing.T) { // documents why NewLimited exists
	big := bytes.Repeat([]byte("a"), 4<<20)
	if n, err := serve(t, New, big); err != nil || n != len(big) {
		t.Fatalf("expected the unlimited default to accept %d bytes, got n=%d err=%v", len(big), n, err)
	}
}

func TestNewLimitedRejectsOversizedMessage(t *testing.T) {
	big := bytes.Repeat([]byte("a"), 4<<20)
	_, err := serve(t, func(c *websocket.Conn) *ReadWriteCloser { return NewLimited(c, 1<<20) }, big)
	if err != websocket.ErrReadLimit {
		t.Fatalf("want websocket.ErrReadLimit, got %v", err)
	}
}

func TestNewLimitedPassesNormalRequest(t *testing.T) {
	req := []byte(`{"jsonrpc":"2.0","id":1,"method":"DERO.GetInfo"}`)
	n, err := serve(t, func(c *websocket.Conn) *ReadWriteCloser { return NewLimited(c, MaxMessageSize) }, req)
	if err != nil && err != io.EOF || n != len(req) {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestMaxMessageSizeFitsLargestSubmitBlock(t *testing.T) {
	if uint64(MaxMessageSize) < 2*config.STARGATE_HE_MAX_BLOCK_SIZE+64*1024 {
		t.Fatalf("MaxMessageSize %d cannot carry a hex-encoded max-size block", MaxMessageSize)
	}
}
