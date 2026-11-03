// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

//go:build !race
// +build !race

// R23b soundness tests on the simulator chain (excluded from -race builds like r23_hf3_replay_test.go; the pipeline
// runs them without -race). Defensive only: the second body below carries a broken proof and is only used to show
// that it is refused.

package walletapi

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/errormsg"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/glue/emission"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

type r23b_env struct {
	chain                *blockchain.Blockchain
	dir                  string
	wsrc, wdst, wgenesis *Wallet_Disk
	stop                 func()
}

func r23b_start(t *testing.T, port string) *r23b_env {
	Initialize_LookupTable(1, 1<<17)
	dir := t.TempDir()
	open := func(name, seed string) *Wallet_Disk {
		w, err := Create_Encrypted_Wallet_From_Recovery_Words(filepath.Join(dir, name), "QWER", seed)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	e := &r23b_env{dir: dir}
	e.wsrc = open("src.db", "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly")
	e.wdst = open("dst.db", "Dekade Spagat Bereich Radclub Yeti Dialekt Unimog Nomade Anlage Hirte Besitz Märzluft Krabbe Nabel Halsader Chefarzt Hering tauchen Neuerung Reifen Umgang Hürde Alchimie Amnesie Reifen")
	e.wgenesis = open("gen.db", "perfil lujo faja puma favor pedir detalle doble carbón neón paella cuarto ánimo cuento conga correr dental moneda león donar entero logro realidad acceso doble")

	genesis_tx := transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, Value: 2012345}}
	copy(genesis_tx.MinerAddress[:], e.wgenesis.account.Keys.Public.EncodeCompressed())
	config.Testnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())
	config.Mainnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())
	genesis_block := blockchain.Generate_Genesis_Block()
	config.Testnet.Genesis_Block_Hash = genesis_block.GetHash()
	config.Mainnet.Genesis_Block_Hash = genesis_block.GetHash()

	chain, rpcserver := r22_chain_start_with_daemon_address(filepath.Join(dir, "chain"), port)
	e.chain = chain
	e.stop = func() {
		simulator_chain_stop(chain, rpcserver)
		e.wsrc.Close_Encrypted_Wallet()
		e.wdst.Close_Encrypted_Wallet()
		e.wgenesis.Close_Encrypted_Wallet()
	}
	go Keep_Connectivity()
	if err := chain.Add_TX_To_Pool(e.wsrc.GetRegistrationTX()); err != nil {
		t.Fatal(err)
	}
	if err := chain.Add_TX_To_Pool(e.wdst.GetRegistrationTX()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		simulator_chain_mineblock(chain, e.wgenesis.GetAddress(), t)
	}
	for _, w := range []*Wallet_Disk{e.wgenesis, e.wsrc, e.wdst} {
		w.SetDaemonAddress(port)
		w.SetOnlineMode()
	}
	// connect to THIS daemon even when an earlier test left the package's global connection marked online
	for deadline := time.Now().Add(30 * time.Second); ; {
		if err := Connect(port); err == nil && IsDaemonOnline() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon never came online")
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err := e.wsrc.Sync_Wallet_Memory_With_Daemon(); err != nil {
		t.Fatal(err)
	}
	e.wsrc.account.Ringsize = 2
	return e
}

func r23b_decode(t *testing.T, b []byte) *transaction.Transaction {
	var tx transaction.Transaction
	if err := tx.Deserialize(b); err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	return &tx
}

// r23b_add mines a prepared template the way simulator_chain_mineblock does.
func r23b_add(chain *blockchain.Blockchain, cbl *block.Complete_Block, miner rpc.Address) (error, bool) {
	cbl.Bl.MiniBlocks = append(cbl.Bl.MiniBlocks, blockchain.ConvertBlockToMiniblock(*cbl.Bl, miner))
	return chain.Add_Complete_Block(cbl)
}

// Double-spend damage, post-HF3: once a body of a TXID is stored, a block carrying a DIFFERENT body of that TXID is
// refused by the byte-mismatch rule (blockchain.go:665-671, ErrInvalidBlock, before any proof work), the stored body
// is not replaced, and the transfer is executed exactly once. A sibling block with the byte-identical body passes the
// same rule, so the refusal is the byte comparison, not the TXID.
func Test_R23b_Same_TXID_Second_Body_Never_Executes(t *testing.T) {
	e := r23b_start(t, "127.0.0.1:26230")
	defer e.stop()
	chain := e.chain
	if globals.Config.MAJOR_HF3_HEIGHT != 0 {
		t.Fatalf("simulator HF3 height %d, want 0", globals.Config.MAJOR_HF3_HEIGHT)
	}

	built, err := e.wsrc.TransferPayload0([]rpc.Transfer{{Destination: e.wdst.GetAddress().String(), Amount: 1000}}, 2, false, rpc.Arguments{}, 10000, false)
	if err != nil {
		t.Fatal(err)
	}
	raw := built.Serialize()
	txid := r23b_decode(t, raw).GetHash()
	var forged []byte
	for off := len(raw) - 1; off > len(raw)-200 && forged == nil; off-- {
		b := append([]byte(nil), raw...)
		b[off] ^= 0x01
		var tx transaction.Transaction
		if tx.Deserialize(b) == nil && tx.GetHash() == txid && !bytes.Equal(b, raw) && !bytes.Equal(tx.Serialize(), raw) {
			forged = b
		}
	}
	if forged == nil {
		t.Fatal("could not build a decodable same-TXID body")
	}
	if err := chain.Verify_Transaction_NonCoinbase(r23b_decode(t, forged)); err == nil {
		t.Fatal("control: the second body must not verify on its own")
	}

	if err := chain.Add_TX_To_Pool(r23b_decode(t, raw)); err != nil {
		t.Fatalf("honest transfer refused: %v", err)
	}
	// three templates on the same tips: the honest one, a sibling with the second body, a sibling with the honest body
	swap := func(cbl *block.Complete_Block, body []byte) {
		for i := range cbl.Txs {
			if cbl.Txs[i].GetHash() == txid {
				cbl.Txs[i] = r23b_decode(t, body)
				return
			}
		}
		t.Fatal("template does not carry the transfer")
	}
	cbl1, _, err := chain.Create_new_miner_block(e.wgenesis.GetAddress())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.wdst.Sync_Wallet_Memory_With_Daemon(); err != nil {
		t.Fatal(err)
	}
	before, _ := e.wdst.Get_Balance()
	cbl2, _, err := chain.Create_new_miner_block(e.wdst.GetAddress()) // refused below: its miner earns nothing
	if err != nil {
		t.Fatal(err)
	}
	swap(cbl2, forged)
	cbl3, _, err := chain.Create_new_miner_block(e.wsrc.GetAddress())
	if err != nil {
		t.Fatal(err)
	}
	swap(cbl3, raw)

	if err, ok := r23b_add(chain, cbl1, e.wgenesis.GetAddress()); !ok {
		t.Fatalf("honest block refused: %v", err)
	}
	stored, err := chain.Store.Block_tx_store.ReadTX(txid)
	if err != nil || !bytes.Equal(stored, raw) {
		t.Fatalf("stored body after the honest block: %v", err)
	}

	err, ok := r23b_add(chain, cbl2, e.wdst.GetAddress())
	if ok || err != errormsg.ErrInvalidBlock {
		t.Fatalf("a block with a second body of a stored TXID: ok=%v err=%v, want the HF3 byte-mismatch refusal (%v)", ok, err, errormsg.ErrInvalidBlock)
	}
	if stored, _ = chain.Store.Block_tx_store.ReadTX(txid); !bytes.Equal(stored, raw) {
		t.Fatal("the refused block replaced the stored body")
	}

	// the byte-identical body passes the same rule: whatever happens to this sibling, it is not the mismatch refusal
	err3, ok3 := r23b_add(chain, cbl3, e.wsrc.GetAddress())
	if err3 == errormsg.ErrInvalidBlock {
		t.Fatalf("a sibling with the identical body was refused as a byte mismatch")
	}
	t.Logf("sibling with the identical body: ok=%v err=%v", ok3, err3)

	// later blocks: the second body is still refused, at any height inside its validity window
	for i := 0; i < 3; i++ {
		cbl, _, err := chain.Create_new_miner_block(e.wgenesis.GetAddress())
		if err != nil {
			t.Fatal(err)
		}
		cbl.Txs = append(cbl.Txs, r23b_decode(t, forged))
		cbl.Bl.Tx_hashes = append(cbl.Bl.Tx_hashes, txid)
		if err, ok := r23b_add(chain, cbl, e.wgenesis.GetAddress()); ok || err != errormsg.ErrInvalidBlock {
			t.Fatalf("round %d: the second body in a later block: ok=%v err=%v", i, ok, err)
		}
		simulator_chain_mineblock(chain, e.wgenesis.GetAddress(), t)
	}
	if stored, _ = chain.Store.Block_tx_store.ReadTX(txid); !bytes.Equal(stored, raw) {
		t.Fatal("the stored body changed")
	}

	// executed once: the receiver holds exactly one transfer
	if err := e.wdst.Sync_Wallet_Memory_With_Daemon(); err != nil {
		t.Fatal(err)
	}
	if bal, _ := e.wdst.Get_Balance(); bal != before+1000 {
		t.Fatalf("receiver balance %d -> %d, want exactly one execution (+1000)", before, bal)
	}
}

// Archive mode on a simulator datadir: the file-based reader (emission.DirSource + TopoMap, the same code the
// offline tool runs on a mainnet copy) audits every block of a chain with registrations, transfers and a burn; the
// cumulative account is consistent and the burn surfaces as plaintext.
func Test_R23b_Archive_Audit_Simulator_Chain(t *testing.T) {
	e := r23b_start(t, "127.0.0.1:26231")
	defer e.stop()
	chain := e.chain
	const burn = 4321
	for i, tr := range [][]rpc.Transfer{
		{{Destination: e.wdst.GetAddress().String(), Amount: 1000}},
		{{Destination: e.wdst.GetAddress().String(), Amount: 7, Burn: burn}},
	} {
		if err := e.wsrc.Sync_Wallet_Memory_With_Daemon(); err != nil {
			t.Fatal(err)
		}
		tx, err := e.wsrc.TransferPayload0(tr, 2, false, rpc.Arguments{}, 10000, false)
		if err != nil {
			t.Fatalf("transfer %d: %v", i, err)
		}
		if err := chain.Add_TX_To_Pool(r23b_decode(t, tx.Serialize())); err != nil { // as a peer would send it
			t.Fatalf("transfer %d refused: %v", i, err)
		}
		simulator_chain_mineblock(chain, e.wgenesis.GetAddress(), t)
		simulator_chain_mineblock(chain, e.wgenesis.GetAddress(), t)
	}

	datadir := globals.GetDataDirectory()
	tm, err := emission.OpenTopo(filepath.Join(datadir, "topo.map"))
	if err != nil {
		t.Fatal(err)
	}
	defer tm.Close()
	src := &emission.DirSource{BLTX: filepath.Join(datadir, "bltx_store"), Store: chain.Store.Balance_store}
	p := emission.Params{Simulator: true, SkipHeights: map[uint64]bool{0: true, uint64(globals.Config.HF1_HEIGHT): true}, HF3Height: uint64(globals.Config.MAJOR_HF3_HEIGHT)}
	last := chain.Load_TOPO_HEIGHT()
	if tm.LastWritten() != last {
		t.Fatalf("topo.map last record %d, chain topoheight %d", tm.LastWritten(), last)
	}
	s := emission.ArchiveRange(src, tm, 1, last, p, nil)
	if s.Audited != last || s.Errors != 0 || s.Unavailable != 0 || s.Verdicts[emission.VerdictOK] != last || s.Cumulative.Alerts != 0 {
		t.Fatalf("archive %+v (first error %s)", s, s.FirstError)
	}
	c := s.Cumulative
	t.Logf("archive: %d blocks audited, verdicts %v, cumulative %+v, %d us total", s.Audited, s.Verdicts, c, s.MicrosTotal)
	if !c.Consistent || c.From != 1 || c.To != uint64(last) || c.Burns != burn || c.Verified != uint64(last) {
		t.Fatalf("cumulative %+v", c)
	}
	if c.Observed != c.Formula {
		t.Fatalf("observed %d formula %d", c.Observed, c.Formula)
	}
	// the simulator's one miniblock is non-final, so consensus credits it a share on top of the integrator's: proven
	// issuance is 2x base + fees per block, and the issued-vs-formula comparison must say so
	if c.IssuedMatchesFormula || c.Issued != 2*c.Observed+c.Fees {
		t.Fatalf("issued %d, observed %d, fees %d: want issued = 2*observed + fees on the simulator", c.Issued, c.Observed, c.Fees)
	}
	// a block missing from the store is unavailable, not an error (what a pruned range looks like)
	s = emission.ArchiveRange(&emission.DirSource{BLTX: filepath.Join(e.dir, "nowhere"), Store: chain.Store.Balance_store}, tm, 1, 3, p, nil)
	if s.Unavailable != 3 || s.Errors != 0 || s.Audited != 0 {
		t.Fatalf("missing store: %+v", s)
	}
}
