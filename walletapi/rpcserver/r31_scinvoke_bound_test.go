package rpcserver

import (
	"context"
	"strings"
	"testing"

	"github.com/deroproject/derohe/rpc"
)

// r31 (dero-rft §7 B287, detector dvm-builtins finding DF-dvm-builtins-5503b8f444; wallet RPC only, D-21): scinvoke
// refuses SC arguments that encode to more than a transaction may carry, before it touches the wallet.
func TestR31ScInvokeSCDATABound(t *testing.T) {
	arg := func(n int) rpc.Arguments {
		return rpc.Arguments{{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
			{Name: "entrypoint", DataType: rpc.DataString, Value: "X"}, {Name: "s", DataType: rpc.DataString, Value: strings.Repeat("a", n)}}
	}
	if err := scinvoke_scdata_budget(arg(1000)); err != nil {
		t.Fatalf("small sc_rpc refused: %v", err)
	}
	big := arg(int(SCINVOKE_MAX_SCDATA))
	if err := scinvoke_scdata_budget(big); err == nil || !strings.Contains(err.Error(), "more than a transaction may carry") {
		t.Fatalf("oversized sc_rpc: %v", err)
	}
	bad := rpc.Arguments{{Name: "x", DataType: rpc.DataUint64, Value: "not a uint64"}}
	if err := scinvoke_scdata_budget(bad); err != nil {
		t.Fatalf("an argument list that does not encode is the transfer path's to refuse, as before: %v", err)
	}
	// through the handler: refused before FromContext (no wallet in this context)
	p := SC_Invoke_Fees_Params{}
	p.SC_ID = "00"
	p.SC_RPC = big
	if _, err := ScInvoke(context.Background(), p); err == nil || !strings.Contains(err.Error(), "more than a transaction may carry") {
		t.Fatalf("ScInvoke with oversized sc_rpc: %v", err)
	}
	p.SC_RPC = arg(10)
	if _, err := ScInvoke(context.Background(), p); err == nil || strings.Contains(err.Error(), "more than a transaction may carry") {
		t.Fatalf("ScInvoke with small sc_rpc must reach the wallet (here: no wallet in the context): %v", err)
	}
	if SCINVOKE_MAX_SCDATA != 300*1024 {
		t.Fatalf("bound %d, want the chain's max tx size 307200", SCINVOKE_MAX_SCDATA)
	}
}
