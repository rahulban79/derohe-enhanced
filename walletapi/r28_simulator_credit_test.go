// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package walletapi

// r28 (tools-kats, dero-rft §7 B21): Test_Payload_TX and Test_Creation_TX_morecheck were red on the pristine upstream
// base too ('expected 1520000 actual 100720000', 'expected 1500000 actual 100700000'): upstream 39569dee (2026-02-05,
// "increase dummy balance for testnet and mainnet users in simulator mode") raised the credit every new account gets
// in the simulator from 800000 to 100000000 and left both fixtures at 800000 (each is off by 99200000 exactly). The
// fixtures now state their balances relative to these constants, and this test fails, naming the line, the day the
// chain's credit changes again. Test-only: the consensus code is read, never changed.

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

const (
	simulatorRegistrationCredit = 100000000 // blockchain/transaction_execute.go, process_transaction (registration)
	upstreamFixtureCredit       = 800000    // the credit the upstream fixtures were written against (before 39569dee)
)

var r28CreditRx = regexp.MustCompile(`(?m)^\s*if !globals\.IsMainnet\(\) \|\| chain\.simulator \{[^\n]*\n\s*zerobalance = zerobalance\.Plus\(new\(big\.Int\)\.SetUint64\((\d+)\)\)`)

func TestR28SimulatorCreditMatchesChain(t *testing.T) {
	src, err := os.ReadFile("../blockchain/transaction_execute.go")
	if err != nil {
		t.Fatal(err)
	}
	m := r28CreditRx.FindAllSubmatch(src, -1)
	if len(m) != 1 {
		t.Fatalf("the simulator registration credit line is not found exactly once in blockchain/transaction_execute.go (%d)", len(m))
	}
	got, _ := strconv.ParseUint(string(m[0][1]), 10, 64)
	if got != simulatorRegistrationCredit {
		t.Fatalf("the chain credits %d to a new simulator account, the walletapi fixtures assume %d: update simulatorRegistrationCredit", got, uint64(simulatorRegistrationCredit))
	}
}
