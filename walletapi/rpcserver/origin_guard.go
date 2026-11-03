package rpcserver

// Browser-origin guard for an UNAUTHENTICATED wallet RPC (Round 18).
//
// Without --rpc-login, hasbasicauthfailed() lets every request through, and the websocket upgrader accepts any
// Origin (CheckOrigin returns true). A web page open in the user's browser can therefore open
// ws://127.0.0.1:<wallet-rpc-port>/ws and call Transfer: cross-site websocket hijacking (browsers apply no CORS to
// websockets). /json_rpc is protected from plain cross-site POSTs only by jhttp's Content-Type check (a JSON POST
// needs a CORS preflight this server never answers), and DNS rebinding defeats that: after rebinding, the page is
// same-origin with a Host header naming the attacker's domain.
//
// Rule, applied only when no --rpc-login is configured:
//   - a request that carries an Origin header (only browsers send one) must come from a loopback origin;
//   - the Host header must be an IP literal or "localhost" (rebinding needs a DNS name).
// Non-browser clients (curl, scripts, other DERO tools) send no Origin and use an IP or localhost, so they are
// unaffected. With --rpc-login set the behaviour is exactly upstream's.

import "net"
import "net/http"
import "net/url"
import "strings"

func host_is_local_literal(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	return net.ParseIP(host) != nil
}

func origin_is_loopback(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// unauthenticated_request_allowed reports whether a request may reach an unauthenticated wallet RPC.
func unauthenticated_request_allowed(r *http.Request) bool {
	if !host_is_local_literal(r.Host) {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" && !origin_is_loopback(o) {
		return false
	}
	return true
}

// bind_is_loopback reports whether a listen address is reachable only from this machine.
func bind_is_loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
