// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

//go:build !race
// +build !race

// R23b (admission window): end to end on the simulator chain, excluded from -race for the same reason as
// r23_hf3_replay_test.go. Proves that every transaction the relay/SendRawTransaction window refuses is one the
// consensus rules refuse inside any block on top of our tip, so the node-local policy can never cost a mineable fee
// nor make this node disagree with the network about a block (blocks never pass through it).

package walletapi

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/blockchain"
	derodrpc "github.com/deroproject/derohe/cmd/derod/rpc"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/errormsg"
	"github.com/deroproject/derohe/glue/txprecheck"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

// force_block mines one block on the current tips holding tx (whether or not the template would select it) and
// returns Add_Complete_Block's verdict.
func force_block(chain *blockchain.Blockchain, miner rpc.Address, tx *transaction.Transaction) (error, bool) {
	cbl, _, err := chain.Create_new_miner_block(miner)
	if err != nil {
		return err, false
	}
	nbl := *cbl.Bl
	nbl.MiniBlocks = nil
	nbl.Tx_hashes = append(append([]crypto.Hash(nil), cbl.Bl.Tx_hashes...), tx.GetHash())
	ncbl := &block.Complete_Block{Bl: &nbl, Txs: append(append([]*transaction.Transaction(nil), cbl.Txs...), tx)}
	nbl.MiniBlocks = append(nbl.MiniBlocks, blockchain.ConvertBlockToMiniblock(nbl, miner))
	return chain.Add_Complete_Block(ncbl)
}

func Test_R23b_Admission_Window_Is_Consensus_Subset(t *testing.T) {
	const port = "127.0.0.1:26232" // r23b merge: 26230/26231 are the soundness simulator tests
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
	for deadline := time.Now().Add(30 * time.Second); !IsDaemonOnline(); {
		if time.Now().After(deadline) {
			t.Fatal("daemon never came online")
		}
		if err := Connect(port); err != nil {
			time.Sleep(250 * time.Millisecond)
		}
	}
	build := func() *transaction.Transaction {
		if err := wsrc.Sync_Wallet_Memory_With_Daemon(); err != nil {
			t.Fatal(err)
		}
		wsrc.account.Ringsize = 2
		built, err := wsrc.TransferPayload0([]rpc.Transfer{{Destination: wdst.GetAddress().String(), Amount: 1000}}, 2, false, rpc.Arguments{}, 10000, false)
		if err != nil {
			t.Fatal(err)
		}
		var tx transaction.Transaction
		if err := tx.Deserialize(built.Serialize()); err != nil {
			t.Fatal(err)
		}
		return &tx
	}
	send := func(tx *transaction.Transaction) error {
		_, err := derodrpc.SendRawTransaction(context.Background(), rpc.SendRawTransaction_Params{Tx_as_hex: hex.EncodeToString(tx.Serialize())})
		return err
	}
	window := func(tx *transaction.Transaction) error {
		return txprecheck.Window(tx.Height, chain.Get_Height())
	}

	// 1. a valid transfer held back until our tip is TX_VALIDITY_HEIGHT+1 past it
	stale := build()
	for chain.Get_Height() <= int64(stale.Height)+blockchain.TX_VALIDITY_HEIGHT {
		simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	}
	if err := window(stale); !errors.Is(err, txprecheck.ErrWindow) {
		t.Fatalf("policy: tip %d tx height %d not refused: %v", chain.Get_Height(), stale.Height, err)
	}
	if err := send(stale); err == nil || !strings.Contains(err.Error(), txprecheck.ErrWindow.Error()) {
		t.Fatalf("SendRawTransaction accepted a stale transfer: %v", err)
	}
	if chain.Mempool.Mempool_TX_Exist(stale.GetHash()) {
		t.Fatal("refused stale transfer reached the mempool")
	}
	// consensus: the template never selects it even when the pool holds it, and a block forced to hold it is refused
	pool_err := chain.Add_TX_To_Pool(stale)
	t.Logf("unpatched pool admission of the stale transfer: %v (nil = it would sit in the pool, never mineable)", pool_err)
	cbl, _, err := chain.Create_new_miner_block(wgenesis.GetAddress())
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range cbl.Bl.Tx_hashes {
		if h == stale.GetHash() {
			t.Fatal("the template selected a transfer outside the validity window")
		}
	}
	if err, ok := force_block(chain, wgenesis.GetAddress(), stale); ok || err != errormsg.ErrTXDoubleSpend {
		t.Fatalf("a block holding the stale transfer: ok %v err %v (consensus must refuse it)", ok, err)
	}
	chain.Mempool.Mempool_Delete_TX(stale.GetHash())

	// 2. a height past our tip: the pool refuses it too (no topo record there)
	future := build()
	future.Height = uint64(chain.Get_Height()) + 1
	if err := window(future); !errors.Is(err, txprecheck.ErrWindow) {
		t.Fatalf("policy: future height not refused: %v", err)
	}
	if err := chain.Add_TX_To_Pool(future); err == nil {
		t.Fatal("pool accepted a height past our tip")
	}

	// 3. an HF3-table TXID inside the window is refused before verification (no exemption cache entry is seeded)
	fresh := build()
	key := fresh.GetHash().String()
	if _, clash := blockchain.HF3_Affected_Txs[key]; clash {
		t.Fatal("test txid collides with a real HF3 entry")
	}
	blockchain.HF3_Affected_Txs[key] = &blockchain.HF3_Tx_Data{Bl_Tips: "00", Height: fresh.Height}
	err = send(fresh)
	delete(blockchain.HF3_Affected_Txs, key)
	if err == nil || !strings.Contains(err.Error(), txprecheck.ErrHF3.Error()) {
		t.Fatalf("SendRawTransaction accepted an HF3-table TXID: %v", err)
	}

	// 4. control (honest path and harness): the same fresh transfer is accepted by SendRawTransaction and a block
	// holding it is accepted, so the refusal in 1 is the window and not the harness
	if err := window(fresh); err != nil {
		t.Fatalf("fresh transfer outside the window: %v", err)
	}
	if err := send(fresh); err != nil {
		t.Fatalf("honest SendRawTransaction refused: %v", err)
	}
	chain.Mempool.Mempool_Delete_TX(fresh.GetHash())
	if err, ok := force_block(chain, wgenesis.GetAddress(), fresh); !ok {
		t.Fatalf("control: a block holding the fresh transfer was refused: %v", err)
	}
	if _, _, ok := chain.IS_TX_Valid(fresh.GetHash()); !ok {
		t.Fatal("control: fresh transfer not mined")
	}

	// cost of the policy's tip read on a real store vs the GetHash the relay path no longer repeats (logged only):
	// one warm-up pass, then three interleaved passes, minimum of each
	const n = 2000
	per := func(f func()) time.Duration {
		t0 := time.Now()
		for i := 0; i < n; i++ {
			f()
		}
		return time.Since(t0) / n
	}
	window_cost, height_cost, topo_cost, hash_cost := time.Hour, time.Hour, time.Hour, time.Hour
	keep := func(d *time.Duration, v time.Duration) {
		if v < *d {
			*d = v
		}
	}
	per(func() { _ = chain.Get_Height() })
	for pass := 0; pass < 3; pass++ {
		keep(&window_cost, per(func() { _ = txprecheck.Window(fresh.Height, chain.Get_Height()) }))
		keep(&height_cost, per(func() { _ = chain.Get_Height() }))
		keep(&topo_cost, per(func() { _ = chain.Load_TOPO_HEIGHT() }))
		keep(&hash_cost, per(func() { _ = fresh.GetHash() }))
	}
	t.Logf("per relayed tx: Get_Height+Window %v (Get_Height alone, the upstream check, %v; Load_TOPO_HEIGHT, not used, %v); one GetHash %v", window_cost, height_cost, topo_cost, hash_cost)
}
