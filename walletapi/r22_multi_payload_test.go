// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

//go:build !race
// +build !race

// r22 merge (crypto C3/C9 review fix): this end-to-end test is excluded from -race builds. It starts the walletapi
// simulator harness, whose connectivity goroutines race at 5385d1d already (Test_Payload_TX fails under -race there
// with 58 DATA RACE reports); under -race it is SKIPPED, and the mechanism is covered race-clean by
// r22_ring_order_test.go and r22m_ring_space_test.go. Run it with a plain go test.

package walletapi

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/deroproject/derohe/blockchain"
	derodrpc "github.com/deroproject/derohe/cmd/derod/rpc"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

// End to end (simulator chain, own port and data dir): a ringsize-2 transaction with two transfers to the same
// destination must give each payload its own blinding scalar r (D = r*G) and its own payload key (the ephemeral
// public key), and the result must still be accepted and mined. Before r22 the two payloads shared r and the
// keystream whenever the random shuffle repeated the order (probability 1/2 per transaction): with 10 builds the
// old code passes this test with probability 2^-10.
func Test_R22_MultiPayload_Distinct_Blinders(t *testing.T) {
	const port = "127.0.0.1:26222"
	Initialize_LookupTable(1, 1<<17)
	dir := t.TempDir()

	wsrc, err := Create_Encrypted_Wallet_From_Recovery_Words(filepath.Join(dir, "src.db"), "QWER", "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly")
	if err != nil {
		t.Fatal(err)
	}
	wdst, err := Create_Encrypted_Wallet_From_Recovery_Words(filepath.Join(dir, "dst.db"), "QWER", "Dekade Spagat Bereich Radclub Yeti Dialekt Unimog Nomade Anlage Hirte Besitz Märzluft Krabbe Nabel Halsader Chefarzt Hering tauchen Neuerung Reifen Umgang Hürde Alchimie Amnesie Reifen")
	if err != nil {
		t.Fatal(err)
	}
	wgenesis, err := Create_Encrypted_Wallet_From_Recovery_Words(filepath.Join(dir, "gen.db"), "QWER", "perfil lujo faja puma favor pedir detalle doble carbón neón paella cuarto ánimo cuento conga correr dental moneda león donar entero logro realidad acceso doble")
	if err != nil {
		t.Fatal(err)
	}

	genesis_tx := transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, Value: 2012345}}
	copy(genesis_tx.MinerAddress[:], wgenesis.account.Keys.Public.EncodeCompressed())
	config.Testnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())
	config.Mainnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())
	genesis_block := blockchain.Generate_Genesis_Block()
	config.Testnet.Genesis_Block_Hash = genesis_block.GetHash()
	config.Mainnet.Genesis_Block_Hash = genesis_block.GetHash()

	chain, rpcserver := r22_chain_start_with_daemon_address(filepath.Join(dir, "chain"), port)
	defer func() {
		simulator_chain_stop(chain, rpcserver)
		wsrc.Close_Encrypted_Wallet()
		wdst.Close_Encrypted_Wallet()
		wgenesis.Close_Encrypted_Wallet()
	}()
	go Keep_Connectivity()

	if err := chain.Add_TX_To_Pool(wsrc.GetRegistrationTX()); err != nil {
		t.Fatal(err)
	}
	if err := chain.Add_TX_To_Pool(wdst.GetRegistrationTX()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	}
	for _, w := range []*Wallet_Disk{wgenesis, wsrc, wdst} {
		w.SetDaemonAddress(port)
		w.SetOnlineMode()
	}
	// r22 merge: wait for the connection (a fixed 2 s sleep flaked with "Daemon is offline" on -count=3, where the
	// previous iteration's connection is being torn down and Keep_Connectivity redials on its own schedule)
	for deadline := time.Now().Add(30 * time.Second); !IsDaemonOnline(); {
		if time.Now().After(deadline) {
			t.Fatal("daemon never came online")
		}
		if err := Connect(port); err != nil {
			time.Sleep(250 * time.Millisecond)
		}
	}
	if err = wsrc.Sync_Wallet_Memory_With_Daemon(); err != nil {
		t.Fatal(err)
	}
	if err = wdst.Sync_Wallet_Memory_With_Daemon(); err != nil {
		t.Fatal(err)
	}
	wsrc.account.Ringsize = 2
	before := wdst.account.Balance_Mature

	dst := wdst.GetAddress().String()
	var last *transaction.Transaction
	for i := 0; i < 10; i++ {
		tx, err := wsrc.TransferPayload0([]rpc.Transfer{{Destination: dst, Amount: 1000}, {Destination: dst, Amount: 2000}}, 2, false, rpc.Arguments{}, 10000, false)
		if err != nil {
			t.Fatalf("build %d: %v", i, err)
		}
		if len(tx.Payloads) != 2 {
			t.Fatalf("build %d: %d payloads", i, len(tx.Payloads))
		}
		p0, p1 := tx.Payloads[0], tx.Payloads[1]
		if bytes.Equal(p0.Statement.D.EncodeCompressed(), p1.Statement.D.EncodeCompressed()) {
			t.Fatalf("build %d: both payloads use the same blinding scalar r (equal D)", i)
		}
		if bytes.Equal(p0.RPCPayload[:33], p1.RPCPayload[:33]) {
			t.Fatalf("build %d: both payloads use the same payload key (equal ephemeral public key)", i)
		}
		last = tx
	}

	var dtx transaction.Transaction
	if err := dtx.Deserialize(last.Serialize()); err != nil {
		t.Fatal(err)
	}
	if err := chain.Add_TX_To_Pool(&dtx); err != nil {
		t.Fatalf("the two-payload transaction was refused: %v", err)
	}
	// r28 (tools-kats, dero-rft §7 B21): the test mined exactly two blocks and then read the receiver once; it failed 1
	// of 8 under load ('receiver got 0, want 3000', 2026-11-02) without saying whether the tx was not mined or the
	// wallet had not caught up. It now mines until the chain holds the tx as valid (at most r22MinedWithin blocks, two
	// suffice unloaded), then re-syncs the receiver until the amount shows (at most 10 s); each failure names its side.
	// The property under test (distinct blinders, accepted, mined, paid) is unchanged.
	mined := 0
	for ; mined < r22MinedWithin; mined++ {
		if _, _, valid := chain.IS_TX_Valid(dtx.GetHash()); valid && mined >= 2 {
			break
		}
		simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	}
	if _, _, valid := chain.IS_TX_Valid(dtx.GetHash()); !valid {
		t.Fatalf("the two-payload transaction was not mined in %d blocks (mempool %d): the pool/miner side, not the wallet",
			mined, len(chain.Mempool.Mempool_List_TX_SortedInfo()))
	}
	got := uint64(0)
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(250 * time.Millisecond) {
		if err = wdst.Sync_Wallet_Memory_With_Daemon(); err != nil {
			t.Fatal(err)
		}
		if got = wdst.account.Balance_Mature - before; got == 3000 || time.Now().After(deadline) {
			break
		}
	}
	if got != 3000 {
		t.Fatalf("receiver got %d, want 3000 (the tx is mined after %d blocks: the wallet side)", got, mined)
	}
	t.Logf("the two-payload transaction paid 3000 after %d mined blocks", mined)
}

// r22MinedWithin bounds the blocks mined while waiting for the two-payload tx (r28, B21)
const r22MinedWithin = 6

// r22_chain_start_with_daemon_address is simulator_chain_start_at with --daemon-address set in globals.Arguments
// BEFORE the RPC server starts (r22 merge: the server reads that map, websocket_server.go; writing it afterwards races).
func r22_chain_start_with_daemon_address(dir, port string) (*blockchain.Blockchain, *derodrpc.RPCServer) {
	params := map[string]interface{}{"--simulator": true}
	parser := &docopt.Parser{HelpHandler: docopt.PrintHelpOnly, OptionsFirst: true}
	var err error
	globals.Arguments, err = parser.ParseArgs(command_line, []string{"--data-dir", dir, "--rpc-bind", port, "--testnet"}, config.Version.String())
	if err != nil {
		panic(err)
	}
	globals.Arguments["--daemon-address"] = port
	os.RemoveAll(dir)
	globals.Initialize()
	chain, err := blockchain.Blockchain_Start(params)
	if err != nil {
		panic(err)
	}
	params["chain"] = chain
	rpcserver, _ := derodrpc.RPCServer_Start(params)
	return chain, rpcserver
}
