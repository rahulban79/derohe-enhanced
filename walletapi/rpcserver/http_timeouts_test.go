package rpcserver

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func serve_wallet_test_server(t *testing.T, h http.Handler) (string, func()) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewWalletHTTPServer(l.Addr().String(), h)
	go srv.Serve(l)
	return l.Addr().String(), func() { srv.Close() }
}

// TestWalletServerCutsSlowHeader: a client that never finishes its headers is disconnected after the header timeout,
// while a hijacked (websocket-style) connection that idles longer than that is NOT cut.
func TestWalletServerCutsSlowHeader(t *testing.T) {
	old := wallet_read_header_timeout
	wallet_read_header_timeout = 300 * time.Millisecond
	defer func() { wallet_read_header_timeout = old }()

	addr, stop := serve_wallet_test_server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hijack" {
			io.WriteString(w, "ok")
			return
		}
		c, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		line, err := rw.ReadString('\n') // a long-lived session: wait for the client, however long it idles
		if err == nil {
			rw.WriteString("echo " + line)
			rw.Flush()
		}
	}))
	defer stop()

	slow, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	io.WriteString(slow, "GET / HTTP/1.1\r\nHost: x\r\n") // headers never finished
	slow.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(slow); err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatalf("slow-header client was not disconnected within 5 s (header timeout not applied)")
		}
	}

	ws, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	io.WriteString(ws, "GET /hijack HTTP/1.1\r\nHost: x\r\n\r\n")
	time.Sleep(3 * wallet_read_header_timeout) // idle well past the header timeout
	io.WriteString(ws, "ping\n")
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := bufio.NewReader(ws).ReadString('\n')
	if err != nil || got != "echo ping\n" {
		t.Fatalf("hijacked session was cut by the header timeout: %q %v", got, err)
	}

	s := NewWalletHTTPServer("x", nil)
	if s.IdleTimeout != WALLET_IDLE_TIMEOUT || s.MaxHeaderBytes != WALLET_MAX_HEADER_BYTES || s.ReadTimeout != 0 || s.WriteTimeout != 0 {
		t.Fatalf("unexpected limits %+v", s)
	}
}

// TestWalletRPCServerUsesTimeouts pins the call site: the wallet RPC server is built by NewWalletHTTPServer.
func TestWalletRPCServerUsesTimeouts(t *testing.T) {
	src, err := os.ReadFile("rpc_websocket_server.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "rpcserver.srv = NewWalletHTTPServer(") || strings.Contains(string(src), "&http.Server{") {
		t.Fatalf("wallet RPC server must be built with NewWalletHTTPServer")
	}
}
