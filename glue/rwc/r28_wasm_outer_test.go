//go:build !wasm
// +build !wasm

package rwc

// r28 (glue-global, N28-07): the wasm wallet over the nhooyr adapter with a reply above 2 MiB (rft §8 R28 carry).
// The r27 TestR27NhooyrReadLimitMatchesServers drives the adapter over the NATIVE coder/websocket; the wasm wallet
// runs the browser implementation (ws_js.go), whose own default read limit is 32,768 bytes. This test serves a
// JSON-RPC reply of 3 MiB from a loopback server it starts, compiles r28_wasm_inner_test.go for js/wasm and runs it
// under node (the Go toolchain's go_js_wasm_exec), so the reply crosses the real wasm stack: browser WebSocket,
// ws_js.Conn, ReadWriteCloserNhooyr, channel.RawJSON, jrpc2. No derod is involved. Without node it skips with the
// reason (the result is then 'pending', never a pass).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

const r28_wasm_reply_bytes = 3 << 20 // over the old 2 MiB literal and far over ws_js's 32,768 default

// r28_rpc_server answers every JSON-RPC request it reads (through the adapter) with a string result of n bytes.
func r28_rpc_server(t *testing.T, n int) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("r", n)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		rw := NewNhooyr(c)
		dec := json.NewDecoder(rw)
		for {
			var req struct {
				ID json.RawMessage `json:"id"`
			}
			if err := dec.Decode(&req); err != nil {
				return
			}
			reply := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":"%s"}`, req.ID, big)
			if _, err := rw.Write([]byte(reply)); err != nil {
				return
			}
		}
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return "ws://" + ln.Addr().String() + "/ws"
}

func wasm_exec() (string, error) {
	if _, err := exec.LookPath("node"); err != nil {
		return "", fmt.Errorf("node not found")
	}
	for _, p := range []string{filepath.Join(runtime.GOROOT(), "lib", "wasm", "go_js_wasm_exec"),
		filepath.Join(runtime.GOROOT(), "misc", "wasm", "go_js_wasm_exec")} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("go_js_wasm_exec not in GOROOT")
}

func TestR28WasmWalletTransportLargeReply(t *testing.T) {
	if testing.Short() {
		t.Skip("pending: -short (compiles a js/wasm test binary)")
	}
	execp, err := wasm_exec()
	if err != nil {
		t.Skipf("pending: %v", err)
	}
	url := r28_rpc_server(t, r28_wasm_reply_bytes)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-v", "-run", "^TestR28WasmInnerLargeReply$", "-exec", execp, ".")
	cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm", "CGO_ENABLED=0",
		"R28_NHOOYR_WS_URL="+url, "R28_NHOOYR_REPLY_BYTES="+strconv.Itoa(r28_wasm_reply_bytes))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	text := out.String()
	if err != nil || !strings.Contains(text, "R28WASM_OK") || strings.Contains(text, "SKIP") {
		t.Fatalf("js/wasm run: err %v\n%s", err, text)
	}
	t.Logf("%s", strings.TrimSpace(text))
}
