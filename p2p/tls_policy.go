// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package p2p

// P2P TLS version floor (Round 20, r19 SEC-10 residual 7). go.mod says go 1.17, so the toolchain builds with the
// go 1.20-compatible GODEBUG set; `go version -m bin/derod` on the live r19 binary shows
// DefaultGODEBUG=...,tls10server=1,tls3des=1,...,tlsrsakex=1: the p2p TLS server accepted TLS 1.0 and 1.1. Every DERO
// peer is a Go program whose client offers TLS 1.3 (Go >= 1.12) and whose default floor is already TLS 1.2 (Go >=
// 1.18), so pinning MinVersion to TLS 1.2 on both ends removes the legacy versions without refusing any peer. Peer
// authentication is unchanged (random self-signed certificates, InsecureSkipVerify): that needs a protocol change.

//
// Cipher and curve floor (Round 22). The same go 1.17 GODEBUG set (DefaultGODEBUG of the live r21 derod: tls3des=1,
// tlsrsakex=1, tlssha1=1) leaves the CBC-SHA1 suites in Go's TLS 1.2 list, so a TLS 1.2 handshake could still settle
// on AES-CBC with HMAC-SHA1. CipherSuites now lists only the forward-secret AEAD suites (it applies to TLS 1.2 only;
// TLS 1.3 suites are all AEAD and not configurable), and CurvePreferences pins X25519 and P-256, the groups every Go
// client offers first. Every DERO peer is a Go program that negotiates TLS 1.3 with X25519, so no peer is refused and
// the handshake is unchanged on the honest path. RSA suites stay for a peer that ever serves an RSA certificate.
//
// r22 merge (SEC22-4 review): go.mod is go 1.17, so the toolchain's default GODEBUG has tlsmlkem=0 and pinning
// CurvePreferences gives up no post-quantum hybrid today. If go.mod is ever raised to a version whose default is
// tlsmlkem=1, P2P_TLS_CURVES must gain tls.X25519MLKEM768 first, or this list silently removes the PQ hybrid.

import "crypto/tls"

const P2P_TLS_MIN_VERSION = tls.VersionTLS12

// P2P_TLS12_SUITES: ECDHE + AEAD only (r22).
var P2P_TLS12_SUITES = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
}

// P2P_TLS_CURVES: X25519 and P-256 (r22).
var P2P_TLS_CURVES = []tls.CurveID{tls.X25519, tls.CurveP256}

func p2p_tls_server_config(cert tls.Certificate) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: P2P_TLS_MIN_VERSION,
		CipherSuites: P2P_TLS12_SUITES, CurvePreferences: P2P_TLS_CURVES}
}

func p2p_tls_client_config() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, MinVersion: P2P_TLS_MIN_VERSION,
		CipherSuites: P2P_TLS12_SUITES, CurvePreferences: P2P_TLS_CURVES}
}
