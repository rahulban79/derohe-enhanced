// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package blockchain

import (
	"os"
	"strings"
	"testing"
)

// r29 (decisions, dero-rft §7 B157, user decision 2026-11-08 (a); DB28-2): the recover in process_transaction_sc logs
// at V(2) Info, not through logr's Error (which ignores V and prints an ERROR with a stack on every node). Logging only:
// consensus guard S1 strips logger statements that assign nothing, so the verdict of the deferred recover is unchanged.
func TestR29SCRecoverLogIsVerbosityGated(t *testing.T) {
	src, err := os.ReadFile("transaction_execute.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	if strings.Contains(s, `logger.V(2).Error(nil, "Recover while executing SC "`) {
		t.Fatal("the SC recover still logs through Error (prints at ERROR level whatever V says)")
	}
	if !strings.Contains(s, `logger.V(2).Info("Recover while executing SC ", "txid", txhash, "error", r,`) {
		t.Fatal("the SC recover no longer logs the txid and the recovered value at V(2)")
	}
}
