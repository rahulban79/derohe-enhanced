package rpcserver

// r25 B40: the wallet /json_rpc request shape, through the real jhttp bridge (forged requests).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/creachadair/jrpc2/handler"
	"github.com/creachadair/jrpc2/jhttp"
)

func r25_wallet_handler() http.HandlerFunc {
	bridge := jhttp.NewBridge(handler.Map{"Echo": handler.New(func(ctx context.Context) string { return "pong" })}, nil)
	return wallet_json_rpc_handler(&RPCServer{}, bridge)
}

func r25_post(t *testing.T, h http.HandlerFunc, method, ctype string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "http://127.0.0.1:10103/json_rpc", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"Echo"}`))
	req.Host = "127.0.0.1:10103"
	if ctype != "-" {
		req.Header.Set("Content-Type", ctype)
	}
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

func TestR25WalletContentTypeVariantsServed(t *testing.T) {
	h := r25_wallet_handler()
	for _, ct := range []string{"application/json", "application/json; charset=utf-8", "Application/JSON", "application/json;charset=UTF-8"} {
		w := r25_post(t, h, http.MethodPost, ct)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"pong"`) {
			t.Fatalf("%q: %d %q (the bridge alone answers 415 with an empty body)", ct, w.Code, w.Body.String())
		}
	}
}

func TestR25WalletRefusalsCarryJSONRPCBody(t *testing.T) {
	h := r25_wallet_handler()
	for _, tc := range []struct {
		method, ct string
		status     int
	}{{http.MethodPost, "-", 415}, {http.MethodPost, "text/plain", 415}, {http.MethodPost, "application/json; charset=latin1", 415},
		{http.MethodPost, "application/x-www-form-urlencoded", 415}, {http.MethodGet, "application/json", 405}} {
		w := r25_post(t, h, tc.method, tc.ct)
		var body struct {
			Error struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if w.Code != tc.status || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Error.Code != -32600 || body.Error.Message == "" {
			t.Fatalf("%s %q: %d %q", tc.method, tc.ct, w.Code, w.Body.String())
		}
		if tc.status == 405 && w.Header().Get("Allow") != http.MethodPost {
			t.Fatalf("405 without Allow: POST")
		}
	}
}

// the server's /json_rpc route goes through wallet_json_rpc_handler (source wiring; Start needs a live wallet)
func TestR25WalletJSONRPCWired(t *testing.T) {
	src, err := os.ReadFile("rpc_websocket_server.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	if !strings.Contains(s, "translate_http_to_jsonrpc_and_vice_versa := wallet_json_rpc_handler(rpcserver, bridge)") ||
		!strings.Contains(s, `rpcserver.mux.HandleFunc("/json_rpc", translate_http_to_jsonrpc_and_vice_versa)`) {
		t.Fatal("/json_rpc no longer goes through wallet_json_rpc_handler")
	}
}
