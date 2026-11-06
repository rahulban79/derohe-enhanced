// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8

package txprecheck

import (
	"errors"
	"testing"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/transaction"
)

// r27 (glue-global): PeekWindow is SendRawTransaction's first gate (before Deserialize) and was 0.0% covered.
func TestR27PeekWindowGatesRawBodies(t *testing.T) {
	raw := (&synth{}).bytes() // height 1000
	for _, c := range []struct {
		tip  int64
		want error
	}{
		{-1, nil}, // no chain yet: the window is not applied
		{1000, nil}, {1000 + int64(blockchain.TX_VALIDITY_HEIGHT), nil},
		{999, ErrWindow}, // too new: tx height above our tip
		{1001 + int64(blockchain.TX_VALIDITY_HEIGHT), ErrWindow}, // too old
	} {
		if err := PeekWindow(raw, c.tip); !errors.Is(err, c.want) && !(err == nil && c.want == nil) {
			t.Fatalf("tip %d: %v, want %v", c.tip, err, c.want)
		}
	}
	reg := (&transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, TransactionType: transaction.REGISTRATION}}).Serialize()
	if err := PeekWindow(reg, 5); err != nil { // no height: passes to the full checks
		t.Fatalf("registration: %v", err)
	}
	if err := PeekWindow([]byte{2, 0, 0, 0}, 5); !errors.Is(err, ErrHeader) {
		t.Fatalf("bad header: %v, want ErrHeader", err)
	}
}
