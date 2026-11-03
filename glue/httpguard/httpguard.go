// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

// Package httpguard protects HTTP listeners bound to loopback from the browser on the same machine (Round 20).
//
// A loopback bind keeps other hosts out, but not web pages the user opens: the browser runs on this machine.
//
//   - DNS rebinding: a page on attacker.example re-resolves its own name to 127.0.0.1 and then reads
//     http://attacker.example:10102/... as same-origin. Every such request carries "Host: attacker.example:10102".
//     Measured on the live r19 node: /json_rpc DERO.GetPeerInfo and /debug/pprof/cmdline (which prints the payout
//     address) answered 200 to that Host. On a loopback bind only loopback IP literals, "localhost", "*.localhost"
//     and names an operator lists (DERO_RPC_ALLOWED_HOSTS / DERO_METRICS_ALLOWED_HOSTS) are accepted as Host.
//   - Cross-site requests: a browser marks them with an Origin header naming the page. ForeignOrigin reports an
//     Origin that is not this machine; the listener decides per path what such a caller may do.
//
// Clients that are not browsers (wallets, miners, curl, the harness) send a loopback Host and no Origin, so they
// see no change.
package httpguard

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Reject reasons passed to Policy.OnReject (also the metric label).
const (
	REASON_HOST   = "host"
	REASON_ORIGIN = "origin"
)

// Policy configures Guard.
type Policy struct {
	LoopbackBind bool                   // the listener is bound to loopback: enforce the Host check
	AllowHosts   []string               // extra Host names accepted on a loopback bind (lower case, no port)
	ForeignOK    func(path string) bool // paths a foreign-Origin (cross-site browser) request may reach; nil = none
	AllowOrigins []string               // Origins the operator trusts as local (ParseOrigins of DERO_RPC_ALLOWED_ORIGINS)
	OnReject     func(reason string)    // optional, called once per refused request
}

// is_local_name reports whether a host name (no port) means this machine.
func is_local_name(h string) bool {
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	if h == "localhost" || strings.HasSuffix(h, ".localhost") { // RFC 6761 6.3: always loopback
		return true
	}
	ip := net.ParseIP(strings.Trim(h, "[]"))
	return ip != nil && ip.IsLoopback()
}

// split_host returns the host part of a Host header value ("a:1" -> "a", "[::1]:1" -> "::1", "[::1]" -> "::1").
func split_host(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.Trim(hostport, "[]")
}

// HostAllowed reports whether a Host header value is acceptable on a loopback listener. An empty Host (HTTP/1.0
// without one) is accepted: no browser sends that.
func HostAllowed(hostport string, extra []string) bool {
	if strings.TrimSpace(hostport) == "" {
		return true
	}
	if _, port, err := net.SplitHostPort(hostport); err == nil && !all_digits(port) {
		return false // "127.0.0.1:x.evil": no browser sends a non-numeric port; refuse rather than guess
	}
	h := split_host(hostport)
	if is_local_name(h) {
		return true
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	for _, e := range extra {
		if e != "" && h == e {
			return true
		}
	}
	return false
}

func all_digits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ForeignOrigin reports whether r carries an Origin header naming something other than this machine. "null"
// (sandboxed frames, file:// pages, some redirects) is foreign: such a page could be anything.
func ForeignOrigin(r *http.Request) bool {
	o := strings.TrimSpace(r.Header.Get("Origin"))
	if o == "" {
		return false
	}
	u, err := url.Parse(o)
	if err != nil || u.Host == "" {
		return true
	}
	return !is_local_name(u.Hostname())
}

// ParseOrigins splits a comma-separated Origin list (as in DERO_RPC_ALLOWED_ORIGINS: a browser extension's
// "chrome-extension://<id>", an Electron app's "file://") into lower-case values without a trailing "/".
// r21 (security): "null" is never accepted. It is not one origin: every sandboxed iframe of every web site
// (<iframe sandbox="allow-scripts">), data: URLs and some redirects send "Origin: null", so listing it (as the r20
// comment here suggested for Electron) turned off the cross-site guard for the whole web, local-only methods,
// /json_rpc, /metrics and /debug/pprof included. Such an app must send a real Origin (a custom scheme, or file://).
func ParseOrigins(s string) (out []string) {
	for _, f := range strings.Split(s, ",") {
		if f = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(f), "/")); f != "" && f != "null" {
			out = append(out, f)
		}
	}
	return
}

// ForeignOriginExcept is ForeignOrigin, except that an Origin the operator listed (exact match after ParseOrigins'
// normalisation) counts as this machine (r20 merge, SEC20-02 review: extensions and Electron/file:// apps that send
// an Origin had no escape hatch; DERO_RPC_ALLOWED_HOSTS covers only Host).
func ForeignOriginExcept(r *http.Request, allow []string) bool {
	if len(allow) > 0 {
		o := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.Header.Get("Origin")), "/"))
		for _, a := range allow {
			if o != "" && o == a {
				return false
			}
		}
	}
	return ForeignOrigin(r)
}

// ParseList splits a comma-separated host list (as in DERO_RPC_ALLOWED_HOSTS) into lower-case names without ports.
func ParseList(s string) (out []string) {
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, strings.ToLower(strings.TrimSuffix(split_host(f), ".")))
		}
	}
	return
}

// Guard wraps next with the Host check (loopback binds only) and the foreign-Origin path rule.
func Guard(next http.Handler, p Policy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.LoopbackBind && !HostAllowed(r.Host, p.AllowHosts) {
			if p.OnReject != nil {
				p.OnReject(REASON_HOST)
			}
			http.Error(w, "Host not allowed on a loopback listener (DNS rebinding guard); list it in DERO_RPC_ALLOWED_HOSTS / DERO_METRICS_ALLOWED_HOSTS", http.StatusForbidden)
			return
		}
		if ForeignOriginExcept(r, p.AllowOrigins) && (p.ForeignOK == nil || !p.ForeignOK(r.URL.Path)) {
			if p.OnReject != nil {
				p.OnReject(REASON_ORIGIN)
			}
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
