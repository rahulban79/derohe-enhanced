// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

//go:build !race
// +build !race

// R23 (HF3 exemption audit): end to end on the simulator chain. Excluded from -race builds for the same reason as
// r22_multi_payload_test.go (the simulator's connectivity goroutines race upstream); the pipeline runs it without -race.

package walletapi

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

// Replay test for the 75 HF3 grandfathered txids (blockchain/hardfork_fixes.go). A TXID excludes the proof, so a
// copy of a real transfer with one proof byte changed keeps the TXID. That TXID is put into HF3_Affected_Txs
// (test-only, restored on exit) and the forged copy is verified:
//   - at a post-HF3 height the exemption must NOT skip the proof (cache key is Keccak256 of the full bytes);
//   - at a pre-HF3 height the exemption DOES skip it (the historical behaviour the table exists for), which proves the
//     test reaches the real bypass rather than failing for an unrelated reason;
//   - the nonce bypass is pinned to the entry's Bl_Tips: against the live tips a replay of a mined transfer is refused;
//   - an entry's Parity override decides which ring slot's nonce advances (so chain_sync.go must set it); a replay is
//     still refused by the already-mined guard and the 11-block validity window.
//
// r28d (rft §7 B181; ported from the DEROFDN community-dev evaluation CD3, CD-24, 2026-11-06): the R23 HF3-exemption
// replay controls re-run at ring 16 (the ring size of the 14 two-inclusion RPCType-1 DC1 txs, rft B180). A copy of Test_R23_HF3_Exemption_Is_Height_Bound with three changes only:
// 14 extra registered accounts, Ringsize 16 in both transfers, and an assertion that the built ring has 16 members.
// Offline: a loopback simulator daemon on a test port, temp dirs.
func Test_R28d_HF3_Exemption_Ring16(t *testing.T) {
	const port = "127.0.0.1:26233" // r28d: 26230-26232 are the r23b simulator tests
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
	hf3 := globals.Config.MAJOR_HF3_HEIGHT
	defer func() {
		globals.Config.MAJOR_HF3_HEIGHT = hf3
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
	// r28d (B181): 14 more registered accounts, so a ring of 16 can be filled (src, dst, genesis + 14 = 17)
	for i := 0; i < 14; i++ {
		wx, err := Create_Encrypted_Wallet_Random_Memory("QWER")
		if err != nil {
			t.Fatal(err)
		}
		if err := chain.Add_TX_To_Pool(wx.GetRegistrationTX()); err != nil {
			t.Fatal(err)
		}
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
	if err = wsrc.Sync_Wallet_Memory_With_Daemon(); err != nil {
		t.Fatal(err)
	}
	wsrc.account.Ringsize = 16

	built, err := wsrc.TransferPayload0([]rpc.Transfer{{Destination: wdst.GetAddress().String(), Amount: 1000}}, 16, false, rpc.Arguments{}, 10000, false)
	if err != nil {
		t.Fatal(err)
	}
	raw := built.Serialize()
	fresh := func(b []byte) *transaction.Transaction {
		var tx transaction.Transaction
		if err := tx.Deserialize(b); err != nil {
			t.Fatalf("deserialize: %v", err)
		}
		return &tx
	}
	txid := fresh(raw).GetHash()
	if got := fresh(raw).Payloads[0].Statement.RingSize; got != 16 || len(built.Payloads[0].Statement.Publickeylist) != 16 {
		t.Fatalf("ring size %d (%d keys), want 16", got, len(built.Payloads[0].Statement.Publickeylist))
	}

	// a forged body: same TXID, one proof byte changed, still decodable
	var forged []byte
	for off := len(raw) - 1; off > len(raw)-200 && forged == nil; off-- {
		b := append([]byte(nil), raw...)
		b[off] ^= 0x01
		var tx transaction.Transaction
		if tx.Deserialize(b) == nil && tx.GetHash() == txid && !bytes.Equal(b, raw) {
			forged = b
		}
	}
	if forged == nil {
		t.Fatal("could not build a decodable same-TXID body with a changed proof byte")
	}

	if globals.Config.MAJOR_HF3_HEIGHT != 0 {
		t.Fatalf("simulator HF3 height %d, want 0 (testnet applies HF3 at genesis)", globals.Config.MAJOR_HF3_HEIGHT)
	}
	if err := chain.Verify_Transaction_NonCoinbase(fresh(raw)); err != nil {
		t.Fatalf("control: the honest transfer must verify: %v", err)
	}
	if err := chain.Verify_Transaction_NonCoinbase(fresh(forged)); err == nil {
		t.Fatal("control: the forged body must fail verification without any exemption")
	}

	key := txid.String()
	if _, clash := blockchain.HF3_Affected_Txs[key]; clash {
		t.Fatal("test txid collides with a real HF3 entry")
	}
	pinned := crypto.Hash{0xde, 0xad, 0xbe, 0xef}
	blockchain.HF3_Affected_Txs[key] = &blockchain.HF3_Tx_Data{Bl_Tips: pinned.String(), Height: built.Height}
	defer delete(blockchain.HF3_Affected_Txs, key)

	// 1. post-HF3: the exemption does not reach the proof
	if err := chain.Verify_Transaction_NonCoinbase(fresh(forged)); err == nil {
		t.Fatal("post-HF3: an HF3-table TXID let a forged proof verify (exemption is not height-bound)")
	}

	// 2. pre-HF3: the same entry does skip the proof (the historical bypass exists and this test reaches it)
	globals.Config.MAJOR_HF3_HEIGHT = int64(built.Height) + 1
	err = chain.Verify_Transaction_NonCoinbase(fresh(forged))
	globals.Config.MAJOR_HF3_HEIGHT = hf3
	if err != nil {
		t.Fatalf("pre-HF3: the table entry should skip the proof (historical behaviour), got %v", err)
	}

	// 3. back at post-HF3 the TXID-keyed cache entry the exemption left behind is unreachable
	if err := chain.Verify_Transaction_NonCoinbase(fresh(forged)); err == nil {
		t.Fatal("post-HF3: the TXID-keyed cache entry from the exemption let a forged proof verify")
	}

	// 4. nonce bypass is pinned to the entry's tips. Execution swaps in the entry's Parity (transaction_execute.go:244),
	// so the entry is removed before mining: with it, an entry whose Parity disagrees with the proof would advance the
	// other ring slot's nonce (case 5).
	delete(blockchain.HF3_Affected_Txs, key)
	if err := chain.Add_TX_To_Pool(fresh(raw)); err != nil {
		t.Fatalf("honest transfer refused by the pool: %v", err)
	}
	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	if _, _, ok := chain.IS_TX_Valid(txid); !ok {
		t.Fatal("the honest transfer was not mined")
	}
	if err := chain.Verify_Transaction_NonCoinbase_CheckNonce_Tips(3, fresh(raw), []crypto.Hash{pinned}); err != nil {
		t.Fatalf("the nonce bypass should answer for the entry's own tips (it exists and is pinned), got %v", err)
	}
	if err := chain.Verify_Transaction_NonCoinbase_CheckNonce_Tips(3, fresh(raw), chain.Get_TIPS()); err == nil {
		t.Fatal("replay of a mined transfer passed the nonce check against the live tips")
	}
	if err := chain.Add_TX_To_Pool(fresh(raw)); err == nil {
		t.Fatal("the pool accepted a replay of a mined transfer")
	}

	// 5. why chain_sync.go:397 must set Parity before executing a table tx: an entry whose Parity disagrees with the
	// proof advances the wrong ring slot, and the nonce check alone then lets a replay through. The pool's
	// already-mined guard (blockchain.go:1300) and the block's 11-block validity window still refuse it.
	if err = wsrc.Sync_Wallet_Memory_With_Daemon(); err != nil {
		t.Fatal(err)
	}
	built2, err := wsrc.TransferPayload0([]rpc.Transfer{{Destination: wdst.GetAddress().String(), Amount: 1000}}, 16, false, rpc.Arguments{}, 10000, false)
	if err != nil {
		t.Fatal(err)
	}
	raw2 := built2.Serialize()
	key2 := fresh(raw2).GetHash().String()
	blockchain.HF3_Affected_Txs[key2] = &blockchain.HF3_Tx_Data{Bl_Tips: pinned.String(), Height: built2.Height, Parity: !fresh(raw2).Payloads[0].Proof.Parity()}
	defer delete(blockchain.HF3_Affected_Txs, key2)
	if err := chain.Add_TX_To_Pool(fresh(raw2)); err != nil {
		t.Fatalf("second transfer refused by the pool: %v", err)
	}
	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	if err := chain.Verify_Transaction_NonCoinbase_CheckNonce_Tips(3, fresh(raw2), chain.Get_TIPS()); err != nil {
		t.Fatalf("expected the mismatched-Parity entry to leave the checked nonce slot unadvanced, got %v", err)
	}
	if err := chain.Add_TX_To_Pool(fresh(raw2)); err == nil {
		t.Fatal("the pool accepted a replay of a mined transfer (already-mined guard)")
	}
	if blockchain.TX_VALIDITY_HEIGHT != 11 {
		t.Fatalf("TX_VALIDITY_HEIGHT %d, want 11 (a table tx at <= 7497942 is far outside it)", blockchain.TX_VALIDITY_HEIGHT)
	}
}
