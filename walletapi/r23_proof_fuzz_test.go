// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package walletapi

import (
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
)

// FuzzReceivedProofParse (Round 23): any proof string must parse or fail without a panic, and a parsed proof run
// against a synthetic payment with a random blinder/amount must never authenticate (only sk*D does).
func FuzzReceivedProofParse(f *testing.F) {
	f.Add("deroproof1qyzlkv8x5cp7tgh3eeqjuu6nenaf0vfjcpm3fl784tkaa6tqpz2jsqdzvfyyskpq0kjaju7h2lw6h48g7fjsmgamxex0szh65f59tk7k82g3f39yt46ky4j4rgqqrp4q0wqa3c")
	f.Add("deroproof1")
	f.Add("dero1qyx7qyvrtrhvaszeej487k2g689fav7h38ay37fja9qf40ycgl0m2qg8ap2y9")
	tx, ring, sk, _ := synthetic_payment(1000)
	f.Fuzz(func(t *testing.T, s string) {
		b, amount, err := parse_payment_proof(s)
		if err != nil {
			return
		}
		if _, _, err := verify_received_proof(b, amount, tx, ring, sk); err == nil {
			t.Fatalf("a fuzzed proof authenticated against an unrelated payment: %q", s)
		}
		_ = crypto.G
	})
}
