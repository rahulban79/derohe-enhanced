// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package main

// rpc contention/throughput harness (opt-in: RPCLOAD=1). r22 (rpcws F6): a private simulator chain on loopback keeps
// producing blocks (miniblock path, so Block/Height/MiniBlock pushes fire) while RPCLOAD_HTTP concurrent HTTP clients
// call the hot read RPCs over /json_rpc and RPCLOAD_WS websockets subscribe to every push. With RPCLOAD_PROFILE=1
// the mutex and block profiles are switched on and written to RPCLOAD_DIR/{mutex,block}.pprof. Prints one JSON line:
// calls/s, CPU per call and per-method latency percentiles.
//
//	RPCLOAD=1 RPCLOAD_DIR=/scratch/dir RPCLOAD_PORT=26931 go test -run TestRPCLoad -v ./cmd/simulator
//
// Run it ALONE (-run TestRPCLoad, its own process): it rewrites process globals (config.Testnet/Mainnet.Genesis_Tx,
// globals.Arguments) for the simulator chain. The simulator package's other tests fail under -race at 5385d1d
// already (blockchain_sim_test.go races); this file adds none. RPCLOAD_TXCACHE=1 turns on GetTransaction's result
// cache (r22 merge: off by default, as derod without --rpc-tx-cache) for the cached arm of an A/B.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/derohe/walletapi"
	"github.com/docopt/docopt-go"
	"github.com/gorilla/websocket"

	derodrpc "github.com/deroproject/derohe/cmd/derod/rpc"
)

func TestRPCLoad(t *testing.T) {
	if os.Getenv("RPCLOAD") != "1" {
		t.Skip("opt-in load harness; set RPCLOAD=1")
	}
	dir := os.Getenv("RPCLOAD_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	port := txflow_env_int("RPCLOAD_PORT", 26931)
	nhttp := txflow_env_int("RPCLOAD_HTTP", 32)
	nws := txflow_env_int("RPCLOAD_WS", 16)
	secs := txflow_env_int("RPCLOAD_SECS", 20)
	block_ms := txflow_env_int("RPCLOAD_BLOCK_MS", 1000)
	accounts := 24

	walletapi.Initialize_LookupTable(1, 1<<16)
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
	logger = globals.Logger
	chain, err := blockchain.Blockchain_Start(params)
	if err != nil {
		t.Fatal(err)
	}
	params["chain"] = chain
	derodrpc.SetTxResultCache(os.Getenv("RPCLOAD_TXCACHE") == "1")
	rpcserver, _ := derodrpc.RPCServer_Start(params)
	defer simulator_chain_stop(chain, rpcserver)

	ws := make([]*walletapi.Wallet_Memory, accounts)
	for i := range ws {
		ws[i] = mk(i + 1)
		if err := chain.Add_TX_To_Pool(ws[i].GetRegistrationTX()); err != nil {
			t.Fatalf("reg %d: %s", i, err)
		}
	}
	txflow_mine(t, chain, genesis.GetAddress())
	for i := 0; i < 4; i++ {
		txflow_mine(t, chain, ws[i].GetAddress())
	}
	var txids []string
	if blid, err := chain.Load_Block_Topological_order_at_index(1); err == nil { // its registration txs are real txids
		if bl, err := chain.Load_BL_FROM_ID(blid); err == nil {
			for _, h := range bl.Tx_hashes {
				txids = append(txids, h.String())
			}
		}
	}
	if len(txids) == 0 {
		t.Fatalf("no txids to query")
	}
	time.Sleep(300 * time.Millisecond)

	if os.Getenv("RPCLOAD_PROFILE") == "1" {
		runtime.SetMutexProfileFraction(1)
		runtime.SetBlockProfileRate(10000)
	}

	addr := ws[1].GetAddress().String()
	calls := []struct{ name, body string }{
		{"GetInfo", `{"jsonrpc":"2.0","id":1,"method":"DERO.GetInfo"}`},
		{"GetHeight", `{"jsonrpc":"2.0","id":1,"method":"DERO.GetHeight"}`},
		{"GetSyncInfo", `{"jsonrpc":"2.0","id":1,"method":"DERO.GetSyncInfo"}`},
		{"GetMiningOutcome", `{"jsonrpc":"2.0","id":1,"method":"DERO.GetMiningOutcome"}`},
		{"GetBlockTemplate", `{"jsonrpc":"2.0","id":1,"method":"DERO.GetBlockTemplate","params":{"wallet_address":"` + addr + `"}}`},
		{"GetEncryptedBalance", `{"jsonrpc":"2.0","id":1,"method":"DERO.GetEncryptedBalance","params":{"address":"` + addr + `","topoheight":-1}}`},
		{"GetTransaction", `{"jsonrpc":"2.0","id":1,"method":"DERO.GetTransaction","params":{"txs_hashes":["` + txids[0] + `"]}}`},
		{"GetLastBlockHeader", `{"jsonrpc":"2.0","id":1,"method":"DERO.GetLastBlockHeader"}`},
	}
	// r23: opt-in only (not in the default mix, so r22 default-mix numbers stay comparable): name them in RPCLOAD_METHODS
	extra := []struct{ name, body string }{
		{"GetTxStatus", `{"jsonrpc":"2.0","id":1,"method":"DERO.GetTxStatus","params":{"txids":["` + txids[0] + `"]}}`},
		{"GetFeeEstimate", `{"jsonrpc":"2.0","id":1,"method":"DERO.GetFeeEstimate","params":{"size":2500}}`},
	}

	if only := os.Getenv("RPCLOAD_METHODS"); only != "" { // comma-separated subset, e.g. GetHeight,GetTransaction
		keep := calls[:0]
		for _, c := range append(calls, extra...) {
			if strings.Contains(","+only+",", ","+c.name+",") {
				keep = append(keep, c)
			}
		}
		calls = keep
	}
	if len(calls) == 0 {
		t.Fatalf("RPCLOAD_METHODS selects no method")
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	var blocks int64
	wg.Add(1)
	go func() { // block producer: miniblock path, like a node receiving work from its miners
		defer wg.Done()
		tk := time.NewTicker(time.Duration(block_ms) * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				if Mine_block_single(chain, genesis.GetAddress()) == nil {
					atomic.AddInt64(&blocks, 1)
				}
			}
		}
	}()

	var pushes int64
	var push_mu sync.Mutex
	push_by := map[string]int64{}
	for i := 0; i < nws; i++ {
		c, _, err := websocket.DefaultDialer.Dial("ws://"+rpcaddr+"/ws", nil)
		if err != nil {
			t.Fatalf("ws dial: %s", err)
		}
		c.WriteMessage(websocket.TextMessage, []byte(`{"jsonrpc":"2.0","id":1,"method":"DERO.Subscribe","params":{"events":["BlockInfo","MiniBlock","TxPool"]}}`))
		wg.Add(1)
		go func(c *websocket.Conn) {
			defer wg.Done()
			defer c.Close()
			go func() { <-stop; c.Close() }()
			for {
				_, msg, err := c.ReadMessage()
				if err != nil {
					return
				}
				atomic.AddInt64(&pushes, 1)
				var m struct {
					Method string `json:"method"`
				}
				if json.Unmarshal(msg, &m) == nil {
					push_mu.Lock()
					push_by[m.Method]++
					push_mu.Unlock()
				}
			}
		}(c)
	}

	tr := &http.Transport{MaxIdleConns: nhttp * 2, MaxIdleConnsPerHost: nhttp * 2}
	cl := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	lat := make([][]time.Duration, len(calls))
	var latmu sync.Mutex
	var total, fails int64
	c0, t0 := cpu_seconds(), time.Now()
	deadline := t0.Add(time.Duration(secs) * time.Second)
	var cwg sync.WaitGroup
	for k := 0; k < nhttp; k++ {
		cwg.Add(1)
		go func(k int) {
			defer cwg.Done()
			local := make([][]time.Duration, len(calls))
			for i := k; time.Now().Before(deadline); i++ {
				m := i % len(calls)
				s := time.Now()
				resp, err := cl.Post("http://"+rpcaddr+"/json_rpc", "application/json", bytes.NewBufferString(calls[m].body))
				if err == nil {
					b, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					if resp.StatusCode != 200 || !bytes.Contains(b, []byte(`"result"`)) {
						if atomic.AddInt64(&fails, 1) < 4 {
							t.Logf("%s: %d %.200s", calls[m].name, resp.StatusCode, b)
						}
					}
				} else {
					atomic.AddInt64(&fails, 1)
				}
				local[m] = append(local[m], time.Since(s))
				atomic.AddInt64(&total, 1)
			}
			latmu.Lock()
			for m := range local {
				lat[m] = append(lat[m], local[m]...)
			}
			latmu.Unlock()
		}(k)
	}
	cwg.Wait()
	wall := time.Since(t0)
	cpu := cpu_seconds() - c0
	close(stop)
	wg.Wait()
	tr.CloseIdleConnections()

	if os.Getenv("RPCLOAD_PROFILE") == "1" {
		for _, p := range []string{"mutex", "block"} {
			f, err := os.Create(filepath.Join(dir, p+".pprof"))
			if err == nil {
				pprof.Lookup(p).WriteTo(f, 0)
				f.Close()
			}
		}
		runtime.SetMutexProfileFraction(0)
		runtime.SetBlockProfileRate(0)
	}
	row := map[string]interface{}{"http_clients": nhttp, "ws_clients": nws, "secs": wall.Seconds(), "calls": total,
		"fails": fails, "calls_per_s": float64(total) / wall.Seconds(), "cpu_us_per_call": cpu * 1e6 / float64(total),
		"blocks": blocks, "ws_pushes": pushes, "ws_push_by_method": push_by, "gomaxprocs": runtime.GOMAXPROCS(0)}
	for m := range calls {
		row[calls[m].name] = summarize(lat[m])
	}
	json.NewEncoder(os.Stdout).Encode(row)
}
