package rpc

// r29 (live-observability, dero-rft §7 B175): live r28 answered a malformed /json_rpc body with HTTP 500 and the
// plain text "[-32700] invalid request value" from the jhttp bridge, and rpc_error_responses_total{code="-32700"}
// stayed 0. The bridge's own error answer is now a JSON-RPC error body (status 500 kept) and counted by its code.

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestR29BridgeParseErrorCountedAsJSONRPC(t *testing.T) {
	_, _, done := r25_sim(t, 2)
	defer done()
	before, other := r27_error_code_count("-32700"), r27_error_code_count("other")
	req := httptest.NewRequest("POST", "/json_rpc", strings.NewReader(`{"jsonrpc":"2.0","id":3,`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	translate_http_to_jsonrpc_and_vice_versa(rec, req)
	if rec.Code != 500 {
		t.Fatalf("status %d, want the bridge's 500", rec.Code)
	}
	var body struct {
		Jsonrpc string           `json:"jsonrpc"`
		ID      *json.RawMessage `json:"id"`
		Error   *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Error == nil || body.Error.Code != -32700 ||
		body.Jsonrpc != "2.0" || body.Error.Message != "invalid request value" {
		t.Fatalf("body %q (err %v), want a JSON-RPC -32700 error", rec.Body.String(), err)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type %q", ct)
	}
	if got := r27_error_code_count("-32700"); got != before+1 {
		t.Fatalf("-32700 counted %d -> %d, want +1", before, got)
	}
	if got := r27_error_code_count("other"); got != other {
		t.Fatalf("other counted %d -> %d, want unchanged", other, got)
	}

	// a valid call is untouched: 200, the result body, nothing counted
	before = r27_error_code_count("-32700")
	req = httptest.NewRequest("POST", "/json_rpc", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"DERO.Ping"}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	translate_http_to_jsonrpc_and_vice_versa(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"result"`) || r27_error_code_count("-32700") != before {
		t.Fatalf("valid call: %d %q", rec.Code, rec.Body.String())
	}
}

// the rewrite parses the bridge text exactly; anything else is forwarded verbatim and counted "other"
func TestR29BridgeErrorText(t *testing.T) {
	for in, want := range map[string]int{"[-32700] invalid request value\n": -32700, "[-32600] invalid request\n": -32600,
		"no code here\n": 0, "[x] y\n": 0, "": 0} {
		c, _, ok := bridge_error_code(in)
		if (want != 0) != ok || (ok && int(c) != want) {
			t.Fatalf("%q -> %d %v, want %d", in, c, ok, want)
		}
	}
}
