package xswd

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsLoopbackRemote(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:5000": true, "[::1]:5000": true, "127.9.9.9:1": true,
		"192.168.1.20:5000": false, "[fe80::1]:5000": false, "garbage": false, "": false,
	} {
		if got := isLoopbackRemote(addr); got != want {
			t.Fatalf("%q: got %v want %v", addr, got, want)
		}
	}
}

// a LAN host must be refused before the websocket upgrade
func TestRemoteConnectionRejected(t *testing.T) {
	x := &XSWD{}
	x.logger = x.logger.WithName("t")
	r := httptest.NewRequest("GET", "http://wallet:44326/xswd", nil)
	r.RemoteAddr = "192.168.1.20:40000"
	w := httptest.NewRecorder()
	x.handleWebSocket(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("remote connection got status %d, want 403", w.Code)
	}
}

func TestPermissionAliasDeny(t *testing.T) {
	if permissionKey("transfer_split") != permissionKey("Transfer") || permissionKey("get_transfers") != permissionKey("GetTransfers") {
		t.Fatalf("aliases do not share a key")
	}
	if permissionKey("GetBalance") == permissionKey("GetAddress") {
		t.Fatalf("different methods share a key")
	}
	app := &ApplicationData{Permissions: map[string]Permission{"Transfer": AlwaysDeny, "GetAddress": AlwaysAllow}}
	if !aliasAlwaysDenied(app, "transfer_split") || !aliasAlwaysDenied(app, "transfer") {
		t.Fatalf("AlwaysDeny not applied to aliases")
	}
	if aliasAlwaysDenied(app, "getaddress") || aliasAlwaysDenied(app, "GetBalance") {
		t.Fatalf("deny leaked to other methods")
	}
}
