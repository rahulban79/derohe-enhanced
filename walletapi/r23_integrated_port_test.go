// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package walletapi

import (
	"strings"
	"testing"

	"github.com/deroproject/derohe/transaction"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

func integrated(port uint64, extra ...rpc.Argument) *rpc.Address {
	a := rpc.NewAddressFromKeys(&crypto.GPoint)
	a.Arguments = append(rpc.Arguments{{Name: rpc.RPC_DESTINATION_PORT, DataType: rpc.DataUint64, Value: port}}, extra...)
	return a
}

// The mechanism: a caller payload (a comment) used to make the address's destination port disappear.
func TestR23IntegratedPortKeptWithPayload(t *testing.T) {
	comment := rpc.Arguments{{Name: rpc.RPC_COMMENT, DataType: rpc.DataString, Value: "invoice 42"}}
	got, err := integrated_payload(integrated(0xdeadbeef), comment)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Has(rpc.RPC_DESTINATION_PORT, rpc.DataUint64) || got.Value(rpc.RPC_DESTINATION_PORT, rpc.DataUint64).(uint64) != 0xdeadbeef {
		t.Fatalf("destination port lost: %v", got)
	}
	if !got.Has(rpc.RPC_COMMENT, rpc.DataString) || len(comment) != 1 {
		t.Fatalf("comment lost or caller slice modified: %v / %v", got, comment)
	}
}

func TestR23IntegratedPortConflictRefused(t *testing.T) {
	pl := rpc.Arguments{{Name: rpc.RPC_DESTINATION_PORT, DataType: rpc.DataUint64, Value: uint64(7)}}
	if _, err := integrated_payload(integrated(8), pl); err == nil {
		t.Fatal("conflicting destination port accepted")
	}
	if got, err := integrated_payload(integrated(7), pl); err != nil || len(got) != 1 {
		t.Fatalf("matching port: %v %v", got, err)
	}
	wrongtype := rpc.Arguments{{Name: rpc.RPC_DESTINATION_PORT, DataType: rpc.DataString, Value: "7"}}
	if _, err := integrated_payload(integrated(7), wrongtype); err == nil {
		t.Fatal("string-typed port silently doubled")
	}
}

// Unchanged behaviour: an empty payload is filled from the address, unknown address arguments are refused.
func TestR23IntegratedEmptyPayloadUnchanged(t *testing.T) {
	got, err := integrated_payload(integrated(5), nil)
	if err != nil || len(got) != 1 || got.Value(rpc.RPC_DESTINATION_PORT, rpc.DataUint64).(uint64) != 5 {
		t.Fatalf("empty payload: %v %v", got, err)
	}
	if _, err := integrated_payload(integrated(5, rpc.Argument{Name: rpc.RPC_COMMENT, DataType: rpc.DataString, Value: "x"}), nil); err == nil {
		t.Fatal("unknown integrated argument accepted with empty payload")
	}
}

// r23 merge: a comment that fits alone but not with the address's port appended is refused with an error, never
// passed on to the builder (which ignores CheckPack's error and panics on the short payload).
func TestR23IntegratedPortOverflowRefused(t *testing.T) {
	long := rpc.Arguments{{Name: rpc.RPC_COMMENT, DataType: rpc.DataString, Value: strings.Repeat("c", 100)}}
	if _, err := long.CheckPack(transaction.PAYLOAD0_LIMIT); err != nil {
		t.Fatalf("premise: the comment alone must fit: %v", err)
	}
	if got, err := integrated_payload(integrated(0xdeadbeef), long); err == nil {
		t.Fatalf("payload of %d args accepted although it no longer fits %d bytes", len(got), transaction.PAYLOAD0_LIMIT)
	}
	short := rpc.Arguments{{Name: rpc.RPC_COMMENT, DataType: rpc.DataString, Value: "ok"}}
	if _, err := integrated_payload(integrated(0xdeadbeef), short); err != nil {
		t.Fatalf("a short comment with the port must still fit: %v", err)
	}
}
