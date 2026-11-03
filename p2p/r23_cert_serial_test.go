// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package p2p

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

// The self-signed p2p certificate must not encode peer_id XOR start time (Round 23): serials are positive, distinct,
// and XORing them with our peer id does not land within a day of the current UnixNano.
func TestR23CertSerialCarriesNoPeerIDOrTime(t *testing.T) {
	seen := map[string]bool{}
	pid := new(big.Int).SetUint64(GetPeerID())
	for i := 0; i < 4; i++ {
		c := generate_random_tls_cert()
		cert, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		sn := cert.SerialNumber
		if sn.Sign() <= 0 {
			t.Fatalf("serial not positive: %v", sn)
		}
		if seen[sn.String()] {
			t.Fatalf("serial repeated: %v", sn)
		}
		seen[sn.String()] = true
		if sn.BitLen() < 72 { // 127 random bits: < 72 bits has probability 2^-55
			t.Fatalf("serial too short to be random: %d bits", sn.BitLen())
		}
		x := new(big.Int).Xor(sn, pid)
		d := new(big.Int).Sub(x, big.NewInt(time.Now().UnixNano()))
		if d.CmpAbs(big.NewInt(int64(24*time.Hour))) < 0 {
			t.Fatalf("serial XOR peer id is the current time: %v", x)
		}
	}
}
