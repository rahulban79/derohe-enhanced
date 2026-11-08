package rpcserver

// r28d (rft §7 B178; first seen upstream in DEROFDN community-dev commit 9d7a4c70): scinvoke takes an optional "fees" and passes it to the transfer builder
// (Transfer -> TransferPayload0 gasstorage -> BuildTransaction fees; 0 keeps the automatic fee).

import (
	"encoding/json"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
)

func TestR28dScInvokeFeesReachTransferParams(t *testing.T) {
	var p SC_Invoke_Fees_Params
	if err := json.Unmarshal([]byte(`{"scid":"aa","ringsize":2,"fees":12345,"sc_rpc":[]}`), &p); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(p)
	var back map[string]interface{}
	json.Unmarshal(raw, &back)
	if v, ok := back["fees"]; !ok || v.(float64) != 12345 {
		t.Fatalf("scinvoke params do not carry \"fees\": %s", raw)
	}
	ring := func(crypto.Hash) []string { return []string{"a", "b", "c"} }
	tp, err := scinvoke_transfer_params(p, ring)
	if err != nil {
		t.Fatal(err)
	}
	if tp.Fees != 12345 {
		t.Fatalf("Transfer_Params.Fees = %d, want the 12345 given to scinvoke", tp.Fees)
	}
	p.Fees = 0
	if tp, _ = scinvoke_transfer_params(p, ring); tp.Fees != 0 {
		t.Fatalf("fees omitted: Transfer_Params.Fees = %d, want 0 (automatic fee)", tp.Fees)
	}
}
