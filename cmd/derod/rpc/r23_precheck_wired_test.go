// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package rpc

import (
	"os"
	"strings"
	"testing"
)

// SendRawTransaction must admit through txprecheck then txcanon (r23)
func TestSendRawTransactionPrecheckWired(t *testing.T) {
	src, err := os.ReadFile("rpc_dero_sendrawtransaction.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "txprecheck.AdmitAt(&tx, txid, tip_height, func(tx *transaction.Transaction) error { return txcanon.Admit(tx_bytes, tx, chain.Add_TX_To_Pool) })") {
		t.Fatal("SendRawTransaction must admit through txprecheck (window, HF3, structure) and txcanon")
	}
}

// the emission auditor must be started with the RPC server, kicked per block and reachable as DERO.GetEmissionAudit
func TestEmissionAuditWired(t *testing.T) {
	src, err := os.ReadFile("websocket_server.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"go emission_audit_loop(r.Exit_Event)", "kick_emission_audit()", `"GetEmissionAudit":           handler.New(GetEmissionAudit)`} {
		if !strings.Contains(string(src), want) {
			t.Fatalf("websocket_server.go lacks %q", want)
		}
	}
}
