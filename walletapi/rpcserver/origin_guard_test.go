package rpcserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
)

func req(host, origin string) *http.Request {
	r := httptest.NewRequest("GET", "http://"+host+"/ws", nil)
	r.Host = host
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	return r
}

func TestUnauthenticatedWalletRPCOriginGuard(t *testing.T) {
	s := &RPCServer{logger: logr.Discard()} // no --rpc-login
	for _, c := range []struct {
		host, origin string
		refused      bool
	}{
		{"127.0.0.1:10103", "", false}, // curl / scripts
		{"localhost:10103", "", false},
		{"[::1]:10103", "", false},
		{"192.168.1.10:10103", "", false},                   // LAN client by IP (bind decides reachability)
		{"127.0.0.1:10103", "http://localhost:3000", false}, // a local dev page
		{"127.0.0.1:10103", "http://127.0.0.1:8080", false},
		{"127.0.0.1:10103", "https://evil.example", true},                       // cross-site websocket hijacking
		{"127.0.0.1:10103", "null", true},                                       // sandboxed iframe / file:
		{"rebind.evil.example:10103", "http://rebind.evil.example:10103", true}, // DNS rebinding
		{"rebind.evil.example:10103", "", true},
	} {
		w := httptest.NewRecorder()
		got := hasbasicauthfailed(s, w, req(c.host, c.origin))
		if got != c.refused {
			t.Errorf("host %q origin %q: refused=%v want %v", c.host, c.origin, got, c.refused)
		}
		if got && w.Code != 403 {
			t.Errorf("refusal code %d, want 403", w.Code)
		}
	}
}

func TestAuthenticatedWalletRPCUnchanged(t *testing.T) {
	s := &RPCServer{logger: logr.Discard(), user: "u", password: "p"}
	r := req("rebind.evil.example:10103", "https://evil.example")
	r.SetBasicAuth("u", "p")
	if hasbasicauthfailed(s, httptest.NewRecorder(), r) {
		t.Fatalf("authenticated request refused: with --rpc-login the behaviour must stay upstream's")
	}
	r.SetBasicAuth("u", "wrong")
	w := httptest.NewRecorder()
	if !hasbasicauthfailed(s, w, r) || w.Code != 401 {
		t.Fatalf("wrong password accepted (code %d)", w.Code)
	}
}

func TestBindIsLoopback(t *testing.T) {
	for a, want := range map[string]bool{"127.0.0.1:10103": true, "[::1]:1": true, "localhost:1": true,
		"0.0.0.0:10103": false, "192.168.1.2:10103": false, "[::]:1": false, "bad": false} {
		if bind_is_loopback(a) != want {
			t.Errorf("bind_is_loopback(%q) != %v", a, want)
		}
	}
}
