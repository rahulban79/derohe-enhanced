// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package rpc

import (
	"crypto/tls"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	ltls "github.com/lesismal/llib/std/crypto/tls"
)

// getwork_tls_server serves blocking server-side handshakes of the llib TLS fork Getwork_server's nbhttp server uses
// (ltls.NewConn, the constructor nbhttp calls), with getwork_tls_config and the getwork server's own certificate
// generator, on a free loopback port. (The nbhttp server itself is not started here: its Start races with its own
// accept goroutine under -race, a vendor issue unrelated to the TLS policy.)
func getwork_tls_server(t *testing.T) (addr string, stop func()) {
	t.Helper()
	cfg := getwork_server_tls_config()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.SetDeadline(time.Now().Add(5 * time.Second))
			ltls.NewConn(c, cfg, false, false).Handshake()
			c.Close()
		}
	}()
	return ln.Addr().String(), func() { ln.Close(); <-done }
}

// getwork_handshake runs one handshake from a standard crypto/tls client (dero-miner's side) against addr.
func getwork_handshake(t *testing.T, addr string, client *tls.Config) (tls.ConnectionState, error) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	client.InsecureSkipVerify = true
	c := tls.Client(raw, client)
	err = c.Handshake()
	return c.ConnectionState(), err
}

// r23 forensics: the getwork listener refuses TLS 1.0/1.1 and the non-AEAD TLS 1.2 suites (the go 1.17 GODEBUG set
// would otherwise accept them), and a default Go client (what dero-miner uses) still negotiates TLS 1.3.
func TestGetworkTLSFloor(t *testing.T) {
	if cfg := getwork_server_tls_config(); cfg.MinVersion < ltls.VersionTLS12 {
		t.Fatalf("MinVersion %#x: with no AEAD suite below TLS 1.2 the handshake would still fail, but the floor is explicit", cfg.MinVersion)
	}
	addr, stop := getwork_tls_server(t)
	defer stop()
	if _, err := getwork_handshake(t, addr, &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}); err == nil {
		t.Fatal("getwork TLS server accepted TLS 1.1")
	}
	cbc := &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}}
	if st, err := getwork_handshake(t, addr, cbc); err == nil {
		t.Fatalf("getwork TLS server accepted a CBC/RSA-kex suite %#x", st.CipherSuite)
	}
	st, err := getwork_handshake(t, addr, &tls.Config{})
	if err != nil || st.Version != tls.VersionTLS13 {
		t.Fatalf("default client: version %#x err %v", st.Version, err)
	}
	st, err = getwork_handshake(t, addr, &tls.Config{MaxVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("TLS 1.2 AEAD client refused: %v", err)
	}
	aead := false
	for _, s := range getwork_tls_config(ltls.Certificate{}).CipherSuites {
		aead = aead || s == st.CipherSuite
	}
	if !aead {
		t.Fatalf("TLS 1.2 settled on %#x, not one of the AEAD suites", st.CipherSuite)
	}
}

// The getwork server must serve getwork_server_tls_config (a source binding: Getwork_server opens real ports, so the
// test reads the one line that builds its config instead of starting it).
func TestGetworkServerUsesTLSFloor(t *testing.T) {
	src, err := os.ReadFile("websocket_getwork_server.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	i := strings.Index(body, "func Getwork_server()")
	if i < 0 {
		t.Fatal("Getwork_server not found")
	}
	j := strings.Index(body[i:], "nbhttp.NewServer(")
	if j < 0 || !strings.Contains(body[i:i+j], "tlsConfig := getwork_server_tls_config()") ||
		!strings.Contains(body[i+j:], "TLSConfig:               tlsConfig,") {
		t.Fatal("Getwork_server does not serve getwork_server_tls_config()")
	}
}
