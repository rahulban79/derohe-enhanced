//go:build js && wasm
// +build js,wasm

package rwc

// r28 (glue-global, N28-07): the wasm wallet's transport as walletapi/daemon_connectivity_wasm.go builds it, compiled
// for js/wasm and run under node: coder/websocket's browser implementation (ws_js.go, read limit 32,768 bytes unless
// SetReadLimit raises it) + ReadWriteCloserNhooyr + channel.RawJSON + a jrpc2 client. Opt-in by design: it needs the
// server URL that TestR28WasmWalletTransportLargeReply (r28_wasm_outer_test.go) starts and passes in; that native
// test is the registered one.

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
)

func TestR28WasmInnerLargeReply(t *testing.T) {
	url := os.Getenv("R28_NHOOYR_WS_URL")
	if url == "" {
		t.Skip("opt-in: run through TestR28WasmWalletTransportLargeReply")
	}
	want, _ := strconv.Atoi(os.Getenv("R28_NHOOYR_REPLY_BYTES"))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial %s: %v", url, err)
	}
	io := NewNhooyr(ws) // the same two lines as walletapi/daemon_connectivity_wasm.go
	cli := jrpc2.NewClient(channel.RawJSON(io, io), nil)
	defer func() { // the order of walletapi's drop_rpc_client: jrpc2's Close waits for its reader, which returns only
		ws.Close(websocket.StatusNormalClosure, "") // once the socket is closed (closing the client first hangs)
		cli.Close()
	}()
	for i := 0; i < 2; i++ { // two calls: the adapter must start a new message reader after the first reply's EOF
		var got string
		if err := cli.CallResult(ctx, "R28.Big", nil, &got); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if len(got) != want {
			t.Fatalf("call %d: reply %d bytes, want %d", i, len(got), want)
		}
	}
	t.Logf("R28WASM_OK %d bytes x2", want)
}
