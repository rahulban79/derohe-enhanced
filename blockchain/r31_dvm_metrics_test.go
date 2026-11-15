package blockchain_test

// R31 (dero-rft §7 B288; D-21 non-consensus): the sc_* /metrics families, end to end on a simulator chain. The chain's
// execute path (process_transaction_sc) only gained logger statements; derod wraps the logger Blockchain_Start takes
// (glue/dvmobs.Wrap). This test does the same on a throw-away simulator chain (t.TempDir(), r28 helpers), mines one SC
// tx per execution class and checks the exact counter deltas each one produced.

import (
	"fmt"
	"io"
	"testing"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/glue/dvmobs"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/walletapi"
)

const r31_loop_sc = `
Function Initialize() Uint64
10 RETURN 0
End Function

Function Spin() Uint64
10 GOTO 10
End Function
`

// r28_start_at with the dvm observer wrapped around the logger the chain derives its CORE logger from
func r31_start(t *testing.T) *r28_env {
	old_args, old_cfg := globals.Arguments, globals.Config
	globals.InitializeLog(io.Discard, io.Discard)
	globals.Arguments = map[string]interface{}{"--data-dir": t.TempDir(), "--testnet": true, "--simulator": true}
	globals.Initialize()
	plain := globals.Logger
	globals.Logger = dvmobs.Wrap(plain, nil)
	chain, err := blockchain.Blockchain_Start(map[string]interface{}{"--simulator": true})
	globals.Logger = plain
	if err != nil {
		globals.Arguments, globals.Config = old_args, old_cfg
		t.Fatalf("simulator chain start: %s", err)
	}
	e := &r28_env{t: t, chain: chain}
	t.Cleanup(func() {
		e.shutdown()
		globals.Arguments, globals.Config = old_args, old_cfg
	})
	gbl := blockchain.Generate_Genesis_Block()
	var p crypto.Point
	if err := p.DecodeCompressed(gbl.Miner_TX.MinerAddress[:]); err != nil {
		t.Fatal(err)
	}
	e.miner = *rpc.NewAddressFromKeys(&p)
	return e
}

type r31_snap map[string]uint64

func r31_take() r31_snap {
	s := r31_snap{"install_ok": dvmobs.InstallOK.Get(), "install_err": dvmobs.InstallErr.Get(), "invoke_ok": dvmobs.InvokeOK.Get(),
		"invoke_err": dvmobs.InvokeErr.Get(), "oog": dvmobs.OutOfGas.Get(), "panic": dvmobs.PanicRecovered.Get(),
		"handler_panic": dvmobs.HandlerPanics.Get()}
	for _, r := range dvmobs.Reasons {
		s["revert_"+r] = dvmobs.Revert[r].Get()
	}
	return s
}

func r31_delta(a, b r31_snap) string {
	d := map[string]uint64{}
	for k, v := range b {
		if v != a[k] {
			d[k] = v - a[k]
		}
	}
	return fmt.Sprint(d)
}

func TestR31DVMMetricsChainFlow(t *testing.T) {
	e := r31_start(t)
	alice, bob, carol, dave := r28_wallet(t), r28_wallet(t), r28_wallet(t), r28_wallet(t)
	for _, w := range []*walletapi.Wallet_Memory{alice, bob, carol, dave} {
		if err := e.chain.Add_TX_To_Pool(w.GetRegistrationTX()); err != nil {
			t.Fatalf("registration refused: %s", err)
		}
	}
	e.mine()
	e.mine()
	pair := []*walletapi.Wallet_Memory{alice, bob}
	ring4 := []*walletapi.Wallet_Memory{alice, bob, carol, dave}

	var scid, loop crypto.Hash
	steps := []struct {
		what string
		run  func()
		want string
	}{
		{"install", func() { scid = e.sc_tx(pair, 30_000, r28_install(r28_sc)).GetHash() }, "map[install_ok:1]"},
		{"invoke ok", func() { e.sc_tx(pair, 0, r28_call(scid, "Bump", "n", uint64(7))) }, "map[invoke_ok:1]"},
		{"invoke returns 1", func() { e.sc_tx(pair, 4_000, r28_call(scid, "Fail")) }, "map[invoke_err:1 revert_discarded:1]"},
		{"overdraw", func() { e.sc_tx(pair, 0, r28_call(scid, "Withdraw", "amount", uint64(1_000_000))) },
			"map[invoke_err:1 revert_transfer_check:1]"},
		{"no scid", func() { e.sc_tx(pair, 1_000, r28_args(rpc.SCACTION, uint64(rpc.SC_CALL), "entrypoint", "Bump")) },
			"map[invoke_err:1 revert_bad_request:1]"},
		{"unknown scid", func() {
			e.sc_tx(pair, 0, r28_call(crypto.HashHexToHash("00000000000000000000000000000000000000000000000000000000000000aa"), "Bump", "n", uint64(1)))
		}, "map[invoke_err:1 revert_not_installed:1]"},
		{"install empty", func() { e.sc_tx(pair, 0, r28_install("")) }, "map[install_err:1 revert_bad_request:1]"},
		{"install unparseable", func() { e.sc_tx(pair, 0, r28_install("Function Initialize( Uint64\n10 RETURN 0\n")) },
			"map[install_err:1 revert_parse:1]"},
		{"install without SCCODE", func() { e.sc_tx(pair, 0, r28_args(rpc.SCACTION, uint64(rpc.SC_INSTALL))) },
			"map[install_err:1 panic:1 revert_exec_panic:1]"},
		{"no SC action", func() { e.sc_tx(pair, 0, r28_args("note", uint64(1))) }, "map[]"},
		{"install loop SC", func() { loop = e.sc_tx(pair, 0, r28_install(r31_loop_sc)).GetHash() }, "map[install_ok:1]"},
		{"out of gas", func() { e.sc_tx(pair, 0, r28_call(loop, "Spin")) }, "map[invoke_err:1 oog:1 revert_out_of_gas:1]"},
		{"anonymous revert", func() { e.sc_tx(ring4, 2_500, r28_call(scid, "Fail")) }, "map[invoke_err:1 revert_discarded:1]"},
	}
	for _, s := range steps {
		before := r31_take()
		s.run()
		if got := r31_delta(before, r31_take()); got != s.want {
			t.Errorf("%s: counter deltas %s, want %s", s.what, got, s.want)
		}
	}
}
