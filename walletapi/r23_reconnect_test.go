//go:build !wasm
// +build !wasm

package walletapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// refusing_daemon accepts /ws and answers every JSON-RPC call with an error, like a daemon that is up but fails the
// wallet's handshake (DERO.Echo / DERO.GetInfo). open counts the websockets the server still holds.
type refusing_daemon struct {
	srv    *httptest.Server
	open   int64
	seen   int64
	silent bool // never answer (a daemon that is connected but too slow, or a half-open path)
}

func new_refusing_daemon(t *testing.T) *refusing_daemon {
	return new_test_daemon(t, false)
}

func new_test_daemon(t *testing.T, silent bool) *refusing_daemon {
	d := &refusing_daemon{silent: silent}
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		atomic.AddInt64(&d.open, 1)
		atomic.AddInt64(&d.seen, 1)
		defer atomic.AddInt64(&d.open, -1)
		defer c.Close()
		for {
			_, b, err := c.ReadMessage()
			if err != nil {
				return
			}
			var req struct {
				ID json.RawMessage `json:"id"`
			}
			if json.Unmarshal(b, &req) != nil || len(req.ID) == 0 || d.silent {
				continue
			}
			resp := `{"jsonrpc":"2.0","id":` + string(req.ID) + `,"error":{"code":-32603,"message":"not ready"}}`
			if c.WriteMessage(websocket.TextMessage, []byte(resp)) != nil {
				return
			}
		}
	}))
	return d
}

func wait_open(d *refusing_daemon, want int64) int64 {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&d.open) <= want {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	return atomic.LoadInt64(&d.open)
}

// Keep_Connectivity retries Connect every 5 s while not Connected. A daemon that accepts the websocket but fails the
// handshake calls used to keep every one of those sockets open (and IsDaemonOnline true): one leaked socket and jrpc2
// client per retry. Now a failed handshake closes and clears the connection.
func TestR23ConnectFailedHandshakeDoesNotLeak(t *testing.T) {
	d := new_refusing_daemon(t)
	defer d.srv.Close()
	old_timeout := daemon_call_timeout
	daemon_call_timeout = 2 * time.Second
	defer func() { daemon_call_timeout = old_timeout }()
	defer drop_rpc_client()

	ep := "ws://" + strings.TrimPrefix(d.srv.URL, "http://")
	for i := 0; i < 10; i++ {
		if err := Connect(ep); err == nil {
			t.Fatal("handshake against a refusing daemon must fail")
		}
		if IsDaemonOnline() {
			t.Fatalf("attempt %d: a connection that failed its handshake must not be installed", i)
		}
	}
	if got := atomic.LoadInt64(&d.seen); got != 10 {
		t.Fatalf("daemon saw %d connects, want 10", got)
	}
	if got := wait_open(d, 0); got != 0 {
		t.Fatalf("%d websockets still open after 10 failed handshakes (want 0)", got)
	}
}

// A call after the client was cleared returns an error instead of panicking with a nil jrpc2 client.
func TestR23CallWithoutConnectionIsAnError(t *testing.T) {
	drop_rpc_client()
	var out string
	if err := rpc_client.Call("DERO.Ping", nil, &out); err != errDaemonOffline {
		t.Fatalf("got %v, want errDaemonOffline", err)
	}
}

// Reconnects racing with calls: no panic, no data race on the client fields (run with -race).
func TestR23ReconnectRacesWithCalls(t *testing.T) {
	d := new_refusing_daemon(t)
	defer d.srv.Close()
	old_timeout := daemon_call_timeout
	daemon_call_timeout = 500 * time.Millisecond
	defer func() { daemon_call_timeout = old_timeout }()
	defer drop_rpc_client()
	ep := "ws://" + strings.TrimPrefix(d.srv.URL, "http://")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				var out string
				rpc_client.Call("DERO.Ping", nil, &out)
				IsDaemonOnline()
			}
		}()
	}
	for i := 0; i < 10; i++ {
		Connect(ep)
	}
	close(stop)
	wg.Wait()
	if got := wait_open(d, 0); got != 0 {
		t.Fatalf("%d websockets still open", got)
	}
}

// A call that times out against a connected daemon that never answers: dropping the client returns at once and frees
// the socket. Closing the jrpc2 client first (the old ping-failure path) blocks until the daemon closes the socket.
func TestR23DropDoesNotHangOnSilentDaemon(t *testing.T) {
	d := new_test_daemon(t, true)
	defer d.srv.Close()
	old_timeout := daemon_call_timeout
	daemon_call_timeout = 200 * time.Millisecond
	defer func() { daemon_call_timeout = old_timeout }()
	ep := "ws://" + strings.TrimPrefix(d.srv.URL, "http://")
	done := make(chan error, 1)
	go func() { done <- Connect(ep) }() // Echo times out, then the failed handshake drops the client
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("handshake against a silent daemon must fail")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Connect hung closing a connection whose daemon never answers")
	}
	if got := wait_open(d, 0); got != 0 {
		t.Fatalf("%d websockets still open", got)
	}
	if IsDaemonOnline() {
		t.Fatal("not installed after a failed handshake")
	}
}

// r23 merge: dropping the client also marks the wallet offline, so code gated only on Connected (xswd's proxy) never
// sees Connected=true with a nil client while Connect redials.
func TestR23DropClearsConnected(t *testing.T) {
	saved := Connected
	defer func() { Connected = saved }()
	Connected = true
	drop_rpc_client()
	if Connected {
		t.Fatal("drop_rpc_client left Connected=true with no client")
	}
}
