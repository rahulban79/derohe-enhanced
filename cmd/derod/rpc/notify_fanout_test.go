package rpc

import "context"
import "net/http"
import "net/http/httptest"
import "strings"
import "testing"
import "time"

import "github.com/creachadair/jrpc2"
import "github.com/gorilla/websocket"

// From goparallel GP-04 (its per-client fan-out is superseded by rpcws's busy-flag pushes, ws_hardening.go).
// r19: the daemon's /ws handler really uses the write timeout: a client that never reads is dropped from
// client_connections (so it stops costing a goroutine per block) instead of blocking forever.
func TestWSHandlerDropsClientThatNeverReads(t *testing.T) {
	old := WS_WRITE_TIMEOUT
	WS_WRITE_TIMEOUT = 200 * time.Millisecond
	defer func() { WS_WRITE_TIMEOUT = old }()

	srv := httptest.NewServer(http.HandlerFunc(ws_handler))
	defer srv.Close()
	cl, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	var server *jrpc2.Server
	for i := 0; i < 200 && server == nil; i++ {
		client_connections.Range(func(k, v interface{}) bool { server, _ = k.(*jrpc2.Server); return server == nil })
		time.Sleep(5 * time.Millisecond)
	}
	if server == nil {
		t.Fatal("ws client never registered")
	}
	payload := strings.Repeat("p", 64<<10)
	start := time.Now()
	pushed := make(chan error, 1)
	go func() {
		var nerr error
		for i := 0; i < 8192 && nerr == nil; i++ { // 512 MiB at most; the client reads nothing
			nerr = server.Notify(context.Background(), "Height", payload)
		}
		pushed <- nerr
	}()
	select {
	case nerr := <-pushed:
		if nerr == nil {
			t.Fatalf("pushes to a client that never reads kept succeeding")
		}
	case <-time.After(15 * time.Second):
		cl.Close() // release the blocked writer before failing
		t.Fatalf("push to a client that never reads blocked for 15 s (no write deadline on /ws)")
	}
	for time.Since(start) < 10*time.Second {
		present := false
		client_connections.Range(func(k, v interface{}) bool { present = present || k == server; return true })
		if !present {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("stuck client still registered %s after its write failed", time.Since(start))
}
