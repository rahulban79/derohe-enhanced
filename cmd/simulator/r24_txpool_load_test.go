// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package main

// r24 txpool load harness (opt-in: R24_TXPOOL_LOAD=1). A private simulator chain on loopback, real wallet-built
// transactions, admitted through the production entry point glue/txcanon.Admit (what SendRawTransaction and the p2p
// relay call) with glue/txpolicy detached (upstream behaviour) or attached (r24). One JSON line per measurement:
//   ab        interleaved pairs of fresh txs, policy off / on, pool below its cap: CPU ms per admission
//   dup       6 concurrent copies of one fresh tx: CPU ms in total, off / on
//   replay    a fresh tx with one proof byte changed (the proof no longer verifies), presented R24_REPLAYS times
//   flood     pool cap of 10 txs: floor-fee txs beyond the cap, then the same senders at 3x the fee
//   heap      heap bytes per pooled tx
//
//	R24_TXPOOL_LOAD=1 R24_DIR=/scratch/dir R24_PORT=26951 go test -run TestR24TxpoolLoad -v ./cmd/simulator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestR24TxpoolLoad(t *testing.T) {
	if os.Getenv("R24_TXPOOL_LOAD") != "1" {
		t.Skip("opt-in load harness; set R24_TXPOOL_LOAD=1")
	}
	dir := os.Getenv("R24_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	port := txflow_env_int("R24_PORT", 26951)
	accounts := txflow_env_int("R24_ACCOUNTS", 60)
	senders := txflow_env_int("R24_SENDERS", 24)
	workers := txflow_env_int("R24_WORKERS", 6)
	ring := txflow_env_int("R24_RING", 16)
	rounds := txflow_env_int("R24_AB_ROUNDS", 2)
	replays := txflow_env_int("R24_REPLAYS", 10)

	walletapi.Initialize_LookupTable(1, 1<<20)
	mk := func(i int) *walletapi.Wallet_Memory {
		w, err := walletapi.Create_Encrypted_Wallet_Memory("", new(crypto.BNRed).SetBytes(big.NewInt(int64(2000003+i*7919)).Bytes()))
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
	time.Sleep(300 * time.Millisecond)
	if err := walletapi.Connect(rpcaddr); err != nil {
		t.Fatalf("connect: %s", err)
	}
	sync_all := func() {
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
	}
	enc := json.NewEncoder(os.Stdout)
	next_block := func() { // mine what is in the pool (two blocks: a tx referencing the tip waits one), then resync
		// (never flush: a wallet counts its own pooled send as spent, and its next proof would then fail)
		before := len(chain.Mempool.Mempool_List_TX())
		s1, _, _ := txflow_mine(t, chain, genesis.GetAddress())
		s2, _, _ := txflow_mine(t, chain, genesis.GetAddress())
		enc.Encode(map[string]interface{}{"m": "next_block", "pool_before": before, "selected": s1 + s2, "pool_after": len(chain.Mempool.Mempool_List_TX()), "height": chain.Get_Height()})
		sync_all()
	}
	sync_all()
	build_set := func(idx []int, mult float32) [][]byte {
		raws := make([][]byte, len(idx))
		pos := map[int]int{}
		for k, i := range idx {
			pos[i] = k
		}
		jobs := make(chan int)
		var wg sync.WaitGroup
		for k := 0; k < workers; k++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					ws[i].SetFeeMultiplier(mult)
					dst := ws[(i+senders)%accounts].GetAddress().String()
					tx, err := ws[i].TransferPayload0([]rpc.Transfer{{Destination: dst, Amount: 1}}, uint64(ring), false, rpc.Arguments{}, 0, false)
					if err != nil {
						t.Errorf("build sender %d: %s", i, err)
						continue
					}
					raws[pos[i]] = tx.Serialize()
				}
			}()
		}
		for _, i := range idx {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
		return raws
	}
	build := func(from, to int, mult float32) [][]byte {
		var idx []int
		for i := from; i < to; i++ {
			idx = append(idx, i)
		}
		return build_set(idx, mult)
	}
	decode := func(raw []byte) *transaction.Transaction {
		var tx transaction.Transaction
		if err := tx.Deserialize(raw); err != nil {
			t.Fatalf("decode: %s", err)
		}
		return &tx
	}
	admit := func(raw []byte) error { return txcanon.Admit(raw, decode(raw), chain.Add_TX_To_Pool) }
	set := func(on bool, cap uint64) {
		if on {
			txpolicy.Attach(chain.Mempool, cap)
			txpolicy.SetMinedSource(derodrpc.RecentlyMined) // as cmd/derod/main.go does
		} else {
			txpolicy.Detach()
		}
	}
	// ab: interleaved pairs (order alternates per pair), pool far below the default cap
	var off_ms, on_ms []float64
	for r := 0; r < rounds; r++ {
		raws := build(0, senders, 1)
		for k := 0; k+1 < len(raws); k += 2 {
			first_on := (k/2)%2 == 1
			for j, on := range []bool{first_on, !first_on} {
				set(on, 0)
				c0 := cpu_seconds()
				if err := admit(raws[k+j]); err != nil {
					// diagnose: the same bytes again, straight into Add_TX_To_Pool with the policy off
					txpolicy.Detach()
					again := chain.Add_TX_To_Pool(decode(raws[k+j]))
					t.Errorf("ab admit (policy on=%v, round %d, sender %d): %s; again with the policy off: %v", on, r, k+j, err, again)
				}
				ms := (cpu_seconds() - c0) * 1000
				if on {
					on_ms = append(on_ms, ms)
				} else {
					off_ms = append(off_ms, ms)
				}
			}
		}
		next_block()
	}
	mean := func(x []float64) float64 {
		s := 0.0
		for _, v := range x {
			s += v
		}
		return s / float64(len(x))
	}
	enc.Encode(map[string]interface{}{"m": "ab", "ring": ring, "pairs": len(on_ms), "off_cpu_ms_per_tx": mean(off_ms), "on_cpu_ms_per_tx": mean(on_ms), "ratio_on_off": mean(on_ms) / mean(off_ms), "off": off_ms, "on": on_ms})

	// dup: 6 concurrent copies, off then on (two fresh txs)
	{
		raws := build(0, 2, 1)
		row := map[string]interface{}{"m": "dup", "ring": ring, "copies": 6}
		for j, on := range []bool{false, true} {
			set(on, 0)
			var wg sync.WaitGroup
			var mu sync.Mutex
			ok := 0
			c0, t0 := cpu_seconds(), time.Now()
			for c := 0; c < 6; c++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if admit(raws[j]) == nil {
						mu.Lock()
						ok++
						mu.Unlock()
					}
				}()
			}
			wg.Wait()
			row[fmt.Sprintf("%v_cpu_ms", map[bool]string{false: "off", true: "on"}[on])] = (cpu_seconds() - c0) * 1000
			row[fmt.Sprintf("%v_wall_ms", map[bool]string{false: "off", true: "on"}[on])] = time.Since(t0).Milliseconds()
			row[fmt.Sprintf("%v_accepted", map[bool]string{false: "off", true: "on"}[on])] = ok
		}
		enc.Encode(row)
		next_block()
	}

	// replay: one proof byte changed; find a position whose change still decodes and re-serializes identically
	{
		raws := build(0, 2, 1)
		row := map[string]interface{}{"m": "replay", "ring": ring, "replays": replays}
		for j, on := range []bool{false, true} {
			set(on, 0)
			var bad []byte
			var first error
			outcomes := map[string]int{}
			for pos := len(raws[j]) - 1; pos > 0 && bad == nil; pos-- {
				b := append([]byte(nil), raws[j]...)
				b[pos] ^= 0x01
				var tx transaction.Transaction
				if !func() (ok bool) { // a changed byte can make Deserialize panic
					defer func() { recover() }()
					return tx.Deserialize(b) == nil && string(tx.Serialize()) == string(b)
				}() {
					outcomes["no_roundtrip"]++
					continue
				}
				err := txcanon.Admit(b, &tx, chain.Add_TX_To_Pool)
				if err != nil && strings.Contains(err.Error(), "verification failed") && strings.Contains(err.Error(), "statement") {
					bad, first = b, err
					row["byte_from_end"] = len(b) - pos
				} else if err == nil {
					outcomes["admitted"]++
					chain.Mempool.Mempool_Delete_TX(tx.GetHash())
				} else {
					k := err.Error()
					if i := strings.Index(k, ", err "); i >= 0 {
						k = k[i+6:]
					}
					if len(k) > 60 {
						k = k[:60]
					}
					outcomes[k]++
				}
			}
			row["search_outcomes"] = outcomes
			if bad == nil {
				enc.Encode(row)
				t.Fatalf("no single-byte proof change found that still decodes")
			}
			c0 := cpu_seconds()
			for i := 0; i < replays; i++ {
				err := admit(bad)
				if err == nil || err.Error() != first.Error() {
					t.Errorf("replay %d: %v, want the same refusal", i, err)
				}
			}
			row[map[bool]string{false: "off_cpu_ms_per_replay", true: "on_cpu_ms_per_replay"}[on]] = (cpu_seconds() - c0) * 1000 / float64(replays)
			// the same replays through the production RPC handler (decode included; r24 refuses before decoding)
			hx := fmt.Sprintf("%x", bad)
			c0 = cpu_seconds()
			for i := 0; i < replays; i++ {
				if _, err := derodrpc.SendRawTransaction(context.Background(), rpc.SendRawTransaction_Params{Tx_as_hex: hx}); err == nil || !strings.Contains(err.Error(), "verification failed") {
					t.Errorf("rpc replay %d: %v", i, err)
				}
			}
			row[map[bool]string{false: "off_rpc_cpu_ms_per_replay", true: "on_rpc_cpu_ms_per_replay"}[on]] = (cpu_seconds() - c0) * 1000 / float64(replays)
		}
		enc.Encode(row)
		next_block()
	}

	// flood: a cap of 10 txs, floor-fee txs from every sender, then the refused senders again at 3x the fee
	{
		// the pool still holds the txs mined by the earlier steps (nothing removes a mined tx before HouseKeeping):
		// with the mined source they do not count toward the cap (recent_mined.go)
		left_before := len(chain.Mempool.Mempool_List_TX())
		raws := build(0, senders, 1)
		cap := uint64(0)
		for i := 0; i < 10; i++ {
			cap += uint64(len(raws[i]))
		}
		set(true, cap)
		row := map[string]interface{}{"m": "flood", "ring": ring, "cap_bytes": cap, "pool_left_before": left_before}
		admitted, refused := 0, 0
		var refused_ms []float64
		var refused_idx []int
		for i := range raws {
			c0 := cpu_seconds()
			err := admit(raws[i])
			ms := (cpu_seconds() - c0) * 1000
			switch {
			case err == nil:
				admitted++
			case errors.Is(err, txpolicy.ErrPoolFull):
				refused++
				refused_ms = append(refused_ms, ms)
				refused_idx = append(refused_idx, i)
			default:
				t.Errorf("flood admit %d: %s", i, err)
			}
		}
		row["floor_admitted"], row["floor_refused"], row["floor_refused_cpu_ms_mean"] = admitted, refused, mean(refused_ms)
		hi := build_set(refused_idx, 3) // the refused senders again, at 3x the fee
		hi_ok, hi_refused := 0, 0
		var hi_ms []float64
		for i := range hi {
			c0 := cpu_seconds()
			err := admit(hi[i])
			hi_ms = append(hi_ms, (cpu_seconds()-c0)*1000)
			if err == nil {
				hi_ok++
			} else if errors.Is(err, txpolicy.ErrPoolFull) {
				hi_refused++
			} else {
				t.Errorf("3x admit %d: %s", i, err)
			}
		}
		left := 0
		for i := range raws {
			if chain.Mempool.Mempool_TX_Exist(decode(raws[i]).GetHash()) {
				left++
			}
		}
		s := txpolicy.Snapshot()
		row["x3_admitted"], row["x3_refused"], row["x3_cpu_ms_mean"] = hi_ok, hi_refused, mean(hi_ms)
		row["floor_left_in_pool"], row["pending_bytes"], row["pending_txs"], row["pool_txs_incl_mined"] = left, s.PoolBytes, s.PoolTxs, len(chain.Mempool.Mempool_List_TX())
		sel, _, _ := txflow_mine(t, chain, genesis.GetAddress())
		sel2, _, _ := txflow_mine(t, chain, genesis.GetAddress())
		row["mined_next_two_blocks"] = sel + sel2
		enc.Encode(row)
		set(false, 0)
		next_block()
	}

	// heap per pooled tx
	{
		raws := build(0, senders, 1)
		runtime.GC()
		var a, b runtime.MemStats
		runtime.ReadMemStats(&a)
		for i := range raws {
			if err := admit(raws[i]); err != nil {
				t.Errorf("heap admit: %s", err)
			}
		}
		runtime.GC()
		runtime.ReadMemStats(&b)
		enc.Encode(map[string]interface{}{"m": "heap", "ring": ring, "txs": len(raws), "tx_bytes": len(raws[0]), "heap_bytes_per_tx": (float64(b.HeapAlloc) - float64(a.HeapAlloc)) / float64(len(raws))})
	}
}
