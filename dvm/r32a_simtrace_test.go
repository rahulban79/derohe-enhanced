package dvm

// r32a (the user, 2026-11-16: "i am observing lot of smart contract execution errors" on the derod console): every
// DERO.GetGasEstimate printed each interpreted DVM line plus "sc execution error %!s(<nil>)" although every call
// succeeded (RETURN 0). Two upstream causes: docopt stores an absent --debug as false, and `!= nil` turned the
// simulator trace on anyway (sc.go); simulator.go printed the error line unconditionally. Both are printing only.

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
)

const r32aTraceSC = `Function Initialize() Uint64
	10 STORE("x", 1)
	20 RETURN 0
	End Function
	Function Ping() Uint64
	10 STORE("x", LOAD("x") + 1)
	20 RETURN 0
	End Function
	`

// stdout of fn
func r32aCapture(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		var b bytes.Buffer
		io.Copy(&b, r)
		done <- b.String()
	}()
	fn()
	w.Close()
	os.Stdout = old
	return <-done
}

func r32aSimRun(t *testing.T) {
	s := SimulatorInitialize(nil, 0)
	addr, err := rpc.NewAddress(strings.TrimSpace("deto1qy0ehnqjpr0wxqnknyc66du2fsxyktppkr8m8e6jvplp954klfjz2qqdzcd8p"))
	if err != nil {
		t.Fatal(err)
	}
	var zerohash crypto.Hash
	s.AccountAddBalance(*addr, zerohash, 500)
	scid, _, _, err := s.SCInstall(r32aTraceSC, map[crypto.Hash]uint64{}, rpc.Arguments{}, addr, 0)
	if err != nil {
		t.Fatalf("install: %s", err)
	}
	if _, _, err = s.RunSC(map[crypto.Hash]uint64{}, rpc.Arguments{{rpc.SCACTION, rpc.DataUint64, uint64(rpc.SC_CALL)},
		{rpc.SCID, rpc.DataHash, scid}, rpc.Argument{"entrypoint", rpc.DataString, "Ping"}}, addr, 0); err != nil {
		t.Fatalf("run: %s", err)
	}
}

func TestR32aSimulatorQuietWithoutDebug(t *testing.T) {
	keep := globals.Arguments
	defer func() { globals.Arguments = keep }()

	globals.Arguments = map[string]interface{}{"--debug": false} // what docopt stores when --debug is not given
	out := r32aCapture(t, func() { r32aSimRun(t) })
	if strings.Contains(out, "interpreting line") || strings.Contains(out, "sc execution error") {
		t.Fatalf("an absent --debug must print nothing; got %d bytes: %.200q", len(out), out)
	}

	globals.Arguments = map[string]interface{}{"--debug": true}
	out = r32aCapture(t, func() { r32aSimRun(t) })
	if !strings.Contains(out, "interpreting line") {
		t.Fatalf("--debug true must keep the simulator trace; got %.200q", out)
	}
	if strings.Contains(out, "sc execution error") {
		t.Fatalf("a successful simulated call must not print an error line; got %.200q", out)
	}
}
