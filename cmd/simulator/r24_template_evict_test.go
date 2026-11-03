// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package main

// r24 (verify-txpool): a pool-full eviction must never remove a tx that a block template already handed to miners
// carries. Accept_new_block completes a final miniblock by looking each template txid up in the mempool, regpool or
// block store (blockchain/miner_block.go:529-547): an evicted tx makes the submitted final miniblock fail with
// "Tx not found in pool or DB, rejecting submitted block", i.e. the found block is lost. Opt-in (wallet setup ~30 s):
//
//	R24_EVICT=1 go test -run TestR24EvictionSparesTemplateTxs -v ./cmd/simulator

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/glue/txcanon"
	"github.com/deroproject/derohe/glue/txpolicy"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/derohe/walletapi"
	"github.com/docopt/docopt-go"

	derodrpc "github.com/deroproject/derohe/cmd/derod/rpc"
)

func TestR24EvictionSparesTemplateTxs(t *testing.T) {
	if os.Getenv("R24_EVICT") != "1" {
		t.Skip("opt-in; set R24_EVICT=1")
	}
	dir := os.Getenv("R24_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	port := txflow_env_int("R24_PORT", 26971)
	const senders, accounts = 3, 6

	walletapi.Initialize_LookupTable(1, 1<<20)
	mk := func(i int) *walletapi.Wallet_Memory {
		w, err := walletapi.Create_Encrypted_Wallet_Memory("", new(crypto.BNRed).SetBytes(big.NewInt(int64(3000017+i*7919)).Bytes()))
		if err != nil {
			t.Fatalf("wallet %d: %s", i, err)
		}
		return w
	}
	genesis := mk(0)
	genesis_tx := transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, Value: 112345}}
	copy(genesis_tx.MinerAddress[:], genesis.GetAddress().PublicKey.EncodeCompressed())
	config.Testnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())
	config.Mainnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())
	gb := blockchain.Generate_Genesis_Block()
	config.Testnet.Genesis_Block_Hash = gb.GetHash()
	config.Mainnet.Genesis_Block_Hash = gb.GetHash()

	params := map[string]interface{}{"--simulator": true}
	parser := &docopt.Parser{HelpHandler: docopt.PrintHelpOnly, OptionsFirst: true}
	rpcaddr := fmt.Sprintf("127.0.0.1:%d", port)
	var err error
	globals.Arguments, err = parser.ParseArgs(command_line_test, []string{"--data-dir", dir, "--rpc-bind", rpcaddr, "--testnet"}, config.Version.String())
	if err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(filepath.Join(dir, "testnet"))
	globals.Initialize()
	chain, err := blockchain.Blockchain_Start(params)
	if err != nil {
		t.Fatal(err)
	}
	params["chain"] = chain
	rpcserver, _ := derodrpc.RPCServer_Start(params)
	defer simulator_chain_stop(chain, rpcserver)
	defer txpolicy.Detach()
	globals.Arguments["--daemon-address"] = rpcaddr

	ws := make([]*walletapi.Wallet_Memory, accounts)
	for i := range ws {
		ws[i] = mk(i + 1)
		if err := chain.Add_TX_To_Pool(ws[i].GetRegistrationTX()); err != nil {
			t.Fatalf("reg %d: %s", i, err)
		}
	}
	txflow_mine(t, chain, genesis.GetAddress())
	for i := 0; i < senders; i++ {
		txflow_mine(t, chain, ws[i].GetAddress())
	}
	txflow_mine(t, chain, genesis.GetAddress())
	txflow_mine(t, chain, genesis.GetAddress())
	time.Sleep(300 * time.Millisecond)
	if err := walletapi.Connect(rpcaddr); err != nil {
		t.Fatalf("connect: %s", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < senders; i++ {
		wg.Add(1)
		go func(w *walletapi.Wallet_Memory) {
			defer wg.Done()
			w.SetOnlineMode()
			if err := w.Sync_Wallet_Memory_With_Daemon(); err != nil {
				t.Logf("sync: %s", err)
			}
		}(ws[i])
	}
	wg.Wait()
	build := func(i int, mult float32) []byte {
		ws[i].SetFeeMultiplier(mult)
		tx, err := ws[i].TransferPayload0([]rpc.Transfer{{Destination: ws[i+senders].GetAddress().String(), Amount: 1}}, 16, false, rpc.Arguments{}, 0, false)
		if err != nil {
			t.Fatalf("build %d: %s", i, err)
		}
		return tx.Serialize()
	}
	admit := func(raw []byte) error {
		var tx transaction.Transaction
		if err := tx.Deserialize(raw); err != nil {
			t.Fatalf("decode: %s", err)
		}
		return txcanon.Admit(raw, &tx, chain.Add_TX_To_Pool)
	}
	txid := func(raw []byte) crypto.Hash {
		var tx transaction.Transaction
		tx.Deserialize(raw)
		return tx.GetHash()
	}

	a, b := build(0, 1), build(1, 1)
	txpolicy.Attach(chain.Mempool, uint64(len(a)+len(b))) // room for exactly the two floor txs
	txpolicy.SetMinedSource(derodrpc.RecentlyMined)
	if os.Getenv("R24_EVICT_NOPROTECT") != "1" {
		txpolicy.SetProtectedSource(derodrpc.TemplateTxs) // as cmd/derod/main.go does
	}
	if err := admit(a); err != nil {
		t.Fatalf("admit a: %s", err)
	}
	if err := admit(b); err != nil {
		t.Fatalf("admit b: %s", err)
	}

	// mine the 9 normal miniblocks of the next block; stop at the first final template, which carries a and b
	miner := genesis.GetAddress()
	var final_bl struct {
		bl  block.Block
		mbl block.MiniBlock
	}
	for k := 0; k < 40; k++ {
		time.Sleep(110 * time.Millisecond) // past the 100 ms template cache, as a live job refresh is
		bl, mbl, _, _, err := chain.Create_new_block_template_mining(miner)
		if err != nil {
			t.Fatalf("template: %s", err)
		}
		derodrpc.NoteTemplate(&bl) // what the getwork server does for every template it hands out
		if mbl.Final {
			final_bl.bl, final_bl.mbl = bl, mbl
			break
		}
		if _, _, _, err := chain.Accept_new_block(bl.Timestamp, mbl.Serialize()); err != nil {
			t.Fatalf("miniblock %d: %s", k, err)
		}
	}
	if final_bl.bl.Timestamp == 0 {
		t.Fatalf("no final template reached")
	}
	carried := map[crypto.Hash]bool{}
	for _, h := range final_bl.bl.Tx_hashes {
		carried[h] = true
	}
	if !carried[txid(a)] || !carried[txid(b)] {
		t.Fatalf("final template does not carry both floor txs: %v", final_bl.bl.Tx_hashes)
	}

	// a better-paying tx arrives while the miner works on the final miniblock: the pool is full
	hi := build(2, 3)
	herr := admit(hi)
	in_pool := chain.Mempool.Mempool_TX_Exist(txid(a)) && chain.Mempool.Mempool_TX_Exist(txid(b))
	_, blid, ok, aerr := chain.Accept_new_block(final_bl.bl.Timestamp, final_bl.mbl.Serialize())
	t.Logf("VERIFY high-fee admit err=%v; template txs still pooled=%v; final miniblock: blid=%s ok=%v err=%v", herr, in_pool, blid, ok, aerr)
	if blid.IsZero() || !ok {
		t.Fatalf("the found block was lost: a template tx was evicted (pooled=%v, final err %v)", in_pool, aerr)
	}
}
