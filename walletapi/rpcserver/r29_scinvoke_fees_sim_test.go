//go:build !race

package rpcserver

// R29 wallet-glue (rft §7 B178): end to end on a throw-away simulator chain. The scinvoke handler is called through a
// real WalletContext (online wallet synced with a local simulator daemon); the transaction it builds and submits must
// sit in the chain's pool with exactly the "fees" given to scinvoke, and an omitted "fees" must keep the automatic fee.
// The SC id is not installed: the chain keeps the fee of such a call (blockchain/r28_sc_flow_test.go "unknown").
// Not run under -race: the online wallet's own sync loop races its balance cache (walletapi sync_loop vs
// GetEncryptedBalanceAtTopoHeight, upstream), as for the other simulator wallet tests (NORACE_NEW_TESTS).

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deroproject/derohe/blockchain"
	derodrpc "github.com/deroproject/derohe/cmd/derod/rpc"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/derohe/walletapi"
	"github.com/docopt/docopt-go"
	"github.com/go-logr/logr"
)

const r29_sim_rpc = "127.0.0.1:26291"

const r29_cmdline = `derod
Usage:
  derod [--testnet] [--data-dir=<directory>] [--rpc-bind=<127.0.0.1:9999>]
`

func r29_mine(t *testing.T, chain *blockchain.Blockchain, miner rpc.Address) {
	cbl, _, err := chain.Create_new_miner_block(miner)
	if err != nil {
		t.Fatalf("create miner block: %s", err)
	}
	cbl.Bl.MiniBlocks = append(cbl.Bl.MiniBlocks, blockchain.ConvertBlockToMiniblock(*cbl.Bl, miner))
	if err, _ = chain.Add_Complete_Block(cbl); err != nil {
		t.Fatalf("add block: %s", err)
	}
}

func r29_pool_tx_for(chain *blockchain.Blockchain, txid string) *transaction.Transaction {
	for _, h := range chain.Mempool.Mempool_List_TX() {
		if h.String() == txid {
			return chain.Mempool.Mempool_Get_TX(h)
		}
	}
	return nil
}

func TestR29ScInvokeFeesReachThePoolOnASimulatorChain(t *testing.T) {
	globals.InitializeLog(io.Discard, io.Discard)
	walletapi.Initialize_LookupTable(1, 1<<17)
	dir := t.TempDir()

	wsrc, err := walletapi.Create_Encrypted_Wallet_From_Recovery_Words(filepath.Join(dir, "src.db"), "QWER", "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly")
	if err != nil {
		t.Fatal(err)
	}
	wdst, err := walletapi.Create_Encrypted_Wallet_From_Recovery_Words(filepath.Join(dir, "dst.db"), "QWER", "Dekade Spagat Bereich Radclub Yeti Dialekt Unimog Nomade Anlage Hirte Besitz Märzluft Krabbe Nabel Halsader Chefarzt Hering tauchen Neuerung Reifen Umgang Hürde Alchimie Amnesie Reifen")
	if err != nil {
		t.Fatal(err)
	}
	wgen, err := walletapi.Create_Encrypted_Wallet_From_Recovery_Words(filepath.Join(dir, "gen.db"), "QWER", "perfil lujo faja puma favor pedir detalle doble carbón neón paella cuarto ánimo cuento conga correr dental moneda león donar entero logro realidad acceso doble")
	if err != nil {
		t.Fatal(err)
	}

	// process globals this test changes, restored afterwards
	old_tn_tx, old_tn_hash, old_mn_tx, old_mn_hash := config.Testnet.Genesis_Tx, config.Testnet.Genesis_Block_Hash, config.Mainnet.Genesis_Tx, config.Mainnet.Genesis_Block_Hash
	old_args := globals.Arguments
	defer func() {
		config.Testnet.Genesis_Tx, config.Testnet.Genesis_Block_Hash, config.Mainnet.Genesis_Tx, config.Mainnet.Genesis_Block_Hash = old_tn_tx, old_tn_hash, old_mn_tx, old_mn_hash
		globals.Arguments = old_args
	}()

	genesis_tx := transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, Value: 2012345}}
	copy(genesis_tx.MinerAddress[:], wgen.GetAddress().PublicKey.EncodeCompressed())
	config.Testnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())
	config.Mainnet.Genesis_Tx = config.Testnet.Genesis_Tx
	gb := blockchain.Generate_Genesis_Block()
	config.Testnet.Genesis_Block_Hash = gb.GetHash()
	config.Mainnet.Genesis_Block_Hash = gb.GetHash()

	parser := &docopt.Parser{HelpHandler: docopt.PrintHelpOnly, OptionsFirst: true}
	globals.Arguments, err = parser.ParseArgs(r29_cmdline, []string{"--data-dir", filepath.Join(dir, "chain"), "--rpc-bind", r29_sim_rpc, "--testnet"}, config.Version.String())
	if err != nil {
		t.Fatal(err)
	}
	globals.Arguments["--daemon-address"] = r29_sim_rpc // before the RPC server starts reading the map
	os.MkdirAll(filepath.Join(dir, "chain"), 0700)
	globals.Initialize()
	params := map[string]interface{}{"--simulator": true}
	chain, err := blockchain.Blockchain_Start(params)
	if err != nil {
		t.Fatal(err)
	}
	params["chain"] = chain
	rpcs, _ := derodrpc.RPCServer_Start(params)
	defer func() { rpcs.RPCServer_Stop(); chain.Shutdown() }()

	go walletapi.Keep_Connectivity()

	for _, w := range []*walletapi.Wallet_Disk{wsrc, wdst} {
		if err := chain.Add_TX_To_Pool(w.GetRegistrationTX()); err != nil {
			t.Fatalf("registration: %s", err)
		}
	}
	r29_mine(t, chain, wgen.GetAddress())
	for _, w := range []*walletapi.Wallet_Disk{wsrc, wdst, wgen} {
		w.SetDaemonAddress(r29_sim_rpc)
		w.SetOnlineMode()
	}
	time.Sleep(time.Second)
	if err := wsrc.Sync_Wallet_Memory_With_Daemon(); err != nil {
		t.Fatalf("sync: %s", err)
	}

	ctx := context.WithValue(context.Background(), "wallet_context", NewWalletContext(logr.Discard(), wsrc))
	scid := crypto.HashHexToHash("a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90").String() // not installed

	call := func(fees uint64) *transaction.Transaction {
		var p SC_Invoke_Fees_Params
		p.SC_ID = scid
		p.Ringsize = 2
		p.SC_RPC = rpc.Arguments{{Name: "entrypoint", DataType: rpc.DataString, Value: "Bump"}}
		p.Fees = fees
		res, err := ScInvoke(ctx, p)
		if err != nil {
			t.Fatalf("scinvoke fees %d: %s", fees, err)
		}
		tx := r29_pool_tx_for(chain, res.TXID)
		if tx == nil {
			t.Fatalf("scinvoke fees %d: tx %s is not in the pool", fees, res.TXID)
		}
		return tx
	}

	const given = 77777
	tx := call(given)
	if !tx.IsSC() {
		t.Fatalf("scinvoke built a tx of type %s, want an SC call", tx.TransactionType)
	}
	if got := tx.Fees(); got != given {
		t.Fatalf("the pooled scinvoke tx pays %d, want the %d given to scinvoke", got, given)
	}
	r29_mine(t, chain, wgen.GetAddress())
	time.Sleep(time.Second)
	if err := wsrc.Sync_Wallet_Memory_With_Daemon(); err != nil {
		t.Fatalf("sync: %s", err)
	}
	auto := call(0)
	if got := auto.Fees(); got == given || got == 0 {
		t.Fatalf("fees omitted: the pooled tx pays %d, want the automatic fee (not 0, not %d)", got, given)
	}
	t.Logf("given fee %d reached the pool; automatic fee %d", given, auto.Fees())
}
