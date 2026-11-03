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
	"github.com/deroproject/derohe/p2p"
	"github.com/lesismal/llib/std/crypto/tls"
)

// getwork_tls_config (r23 forensics): the getwork wss server gets the same TLS floor the p2p layer has had since r20/r22
// (p2p/tls_policy.go). The r22 floor covered only p2p. The getwork server does not use crypto/tls at all but the
// vendored llib fork (vendor/github.com/lesismal/llib/std/crypto/tls), whose Config with MinVersion 0 offers TLS 1.0
// and 1.1 (common.go supportedVersions) and whose default TLS 1.2 list still carries the CBC-SHA1, 3DES and RSA
// key-exchange suites; Getwork_server set neither MinVersion nor CipherSuites, so the getwork listener
// (0.0.0.0:10100 unless --getwork-bind says otherwise) accepted all of them. The suite and curve ids are the IANA
// numbers, identical in both packages. Miners connect with Go's
// default client (TLS 1.3) or any TLS 1.2 library, so no honest miner is refused. The miner is still not authenticated
// (random self-signed certificate): that is unchanged.
func getwork_tls_config(cert tls.Certificate) *tls.Config {
	curves := make([]tls.CurveID, 0, len(p2p.P2P_TLS_CURVES))
	for _, c := range p2p.P2P_TLS_CURVES {
		curves = append(curves, tls.CurveID(c))
	}
	suites := append([]uint16(nil), p2p.P2P_TLS12_SUITES...)
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: p2p.P2P_TLS_MIN_VERSION,
		CipherSuites: suites, CurvePreferences: curves}
}

// getwork_server_tls_config is the config Getwork_server serves: the floor above with a fresh random certificate.
func getwork_server_tls_config() *tls.Config { return getwork_tls_config(generate_random_tls_cert()) }
