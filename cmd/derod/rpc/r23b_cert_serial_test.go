// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package rpc

import (
	"crypto/x509"
	"testing"
	"time"
)

// The getwork TLS certificate serial was time.Now().UnixNano(): every miner (and anyone who opened a TLS session to
// the getwork port) learned derod's start time to the nanosecond and could link restarts. It is random now.
func TestR23bGetworkCertSerialIsRandom(t *testing.T) {
	now := time.Now().UnixNano()
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		c := generate_random_tls_cert()
		x, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		s := x.SerialNumber
		if s.Sign() <= 0 || s.BitLen() < 100 || s.BitLen() > 127 {
			t.Fatalf("serial %s (%d bits) is not a random positive 127-bit value", s, s.BitLen())
		}
		if d := s.Int64() - now; s.IsInt64() && d > -int64(time.Hour) && d < int64(time.Hour) {
			t.Fatalf("serial %s is the current UnixNano", s)
		}
		if seen[s.String()] {
			t.Fatalf("serial %s repeated", s)
		}
		seen[s.String()] = true
	}
}
