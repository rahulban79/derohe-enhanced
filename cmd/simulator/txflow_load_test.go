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

// txflow load harness (opt-in: TXFLOW_LOAD=1). Builds a private simulator chain on loopback, registers
// TXFLOW_ACCOUNTS accounts, funds TXFLOW_SENDERS of them by mining, then per ring size measures: wallet build time,
// serial and parallel mempool admission (Add_TX_To_Pool = the RPC SendRawTransaction / p2p relay entry point),
// concurrent duplicate admission of one tx (what a node pays when several peers relay the same tx at once),
// template fill and block-add time. Results are printed as one JSON line per ring size.
//
//	TXFLOW_LOAD=1 TXFLOW_DIR=/scratch/dir TXFLOW_PORT=26911 go test -run TestTxflowLoad -v ./cmd/simulator

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime/pprof"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/derohe/walletapi"
	"github.com/docopt/docopt-go"

	derodrpc "github.com/deroproject/derohe/cmd/derod/rpc"
)

func txflow_env_int(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

func cpu_seconds() float64 {
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return float64(ru.Utime.Sec+ru.Stime.Sec) + float64(ru.Utime.Usec+ru.Stime.Usec)/1e6
}

func summarize(d []time.Duration) map[string]float64 {
	if len(d) == 0 {
		return nil
	}
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	ms := func(x time.Duration) float64 { return float64(x.Microseconds()) / 1000 }
	return map[string]float64{"n": float64(len(s)), "min_ms": ms(s[0]), "p50_ms": ms(s[len(s)/2]), "p90_ms": ms(s[len(s)*9/10]), "max_ms": ms(s[len(s)-1])}
}

func copy_tx(t *testing.T, tx *transaction.Transaction) *transaction.Transaction {
	var d transaction.Transaction
	if err := d.Deserialize(tx.Serialize()); err != nil {
		t.Fatalf("deserialize: %s", err)
	}
	return &d
}

var last_block_add_cpu_ms float64

func txflow_mine(t *testing.T, chain *blockchain.Blockchain, miner rpc.Address) (selected int, tmpl, add time.Duration) {
	t0 := time.Now()
	cbl, _, err := chain.Create_new_miner_block(miner)
	if err != nil {
		t.Fatalf("template: %s", err)
	}
	tmpl = time.Since(t0)
	for i := range cbl.Txs {
		if !cbl.Txs[i].IsRegistration() {
			selected++
		}
	}
	mbl := blockchain.ConvertBlockToMiniblock(*cbl.Bl, miner)
	cbl.Bl.MiniBlocks = append(cbl.Bl.MiniBlocks, mbl)
	t1, c1 := time.Now(), cpu_seconds()
	if err, _ = chain.Add_Complete_Block(cbl); err != nil {
		t.Fatalf("add block: %s", err)
	}
	add = time.Since(t1)
	last_block_add_cpu_ms = (cpu_seconds() - c1) * 1000
	return
}

// latency_proxy forwards loopback TCP to target adding one_way delay to every chunk in each direction (pure
// latency, no bandwidth cap: chunks are stamped on read and released at stamp+delay, so concurrent requests overlap).
func latency_proxy(t *testing.T, listen, target string, one_way time.Duration) net.Listener {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatalf("proxy listen: %s", err)
	}
	pipe := func(dst, src net.Conn) {
		type chunk struct {
			at time.Time
			b  []byte
		}
		q := make(chan chunk, 4096)
		go func() {
			for c := range q {
				time.Sleep(time.Until(c.at))
				if _, err := dst.Write(c.b); err != nil {
					break
				}
			}
			dst.Close()
		}()
		buf := make([]byte, 64*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				q <- chunk{time.Now().Add(one_way), append([]byte(nil), buf[:n]...)}
			}
			if err != nil {
				close(q)
				return
			}
		}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			d, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			go pipe(d, c)
			go pipe(c, d)
		}
	}()
	return ln
}

func TestTxflowLoad(t *testing.T) {
	if os.Getenv("TXFLOW_LOAD") != "1" {
		t.Skip("opt-in load harness; set TXFLOW_LOAD=1")
	}
	dir := os.Getenv("TXFLOW_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	port := txflow_env_int("TXFLOW_PORT", 26911)
	accounts := txflow_env_int("TXFLOW_ACCOUNTS", 140)
	senders := txflow_env_int("TXFLOW_SENDERS", 24)
	workers := txflow_env_int("TXFLOW_WORKERS", 6)
	dups := txflow_env_int("TXFLOW_DUPS", 6)
	rings := []int{2, 8, 16, 32, 64, 128}
	if v := os.Getenv("TXFLOW_RINGS"); v != "" {
		rings = nil
		for _, f := range filepath.SplitList(v) {
			if n, err := strconv.Atoi(f); err == nil {
				rings = append(rings, n)
			}
		}
	}

	walletapi.Initialize_LookupTable(1, 1<<20)

	mk := func(i int) *walletapi.Wallet_Memory {
		w, err := walletapi.Create_Encrypted_Wallet_Memory("", new(crypto.BNRed).SetBytes(big.NewInt(int64(1000003+i*7919)).Bytes()))
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
	globals.Arguments["--daemon-address"] = rpcaddr

	ws := make([]*walletapi.Wallet_Memory, accounts)
	for i := range ws {
		ws[i] = mk(i + 1)
		if err := chain.Add_TX_To_Pool(ws[i].GetRegistrationTX()); err != nil {
			t.Fatalf("reg %d: %s", i, err)
		}
	}
	txflow_mine(t, chain, genesis.GetAddress())
	for i := 0; i < senders; i++ { // each sender is funded by the block it mines
		txflow_mine(t, chain, ws[i].GetAddress())
	}
	txflow_mine(t, chain, genesis.GetAddress())
	time.Sleep(300 * time.Millisecond)
	wallet_endpoint := rpcaddr
	if rtt := txflow_env_int("TXFLOW_RTT_MS", 0); rtt > 0 { // wallets talk to the daemon through a WAN-like link
		wallet_endpoint = fmt.Sprintf("127.0.0.1:%d", port+1)
		ln := latency_proxy(t, wallet_endpoint, rpcaddr, time.Duration(rtt)*time.Millisecond/2)
		defer ln.Close()
	}
	if err := walletapi.Connect(wallet_endpoint); err != nil {
		t.Fatalf("connect: %s", err)
	}
	sync_senders := func() {
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
	sync_senders()
	bal, _ := ws[0].Get_Balance()
	t.Logf("sender0 balance %d height %d", bal, chain.Get_Height())
	if bal == 0 {
		t.Fatalf("sender not funded")
	}

	build := func(ring int) ([]*transaction.Transaction, []time.Duration, time.Duration) {
		txs := make([]*transaction.Transaction, senders)
		lat := make([]time.Duration, senders)
		jobs := make(chan int)
		var wg sync.WaitGroup
		t0 := time.Now()
		for k := 0; k < workers; k++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					dst := ws[(i+senders)%accounts].GetAddress().String()
					s := time.Now()
					tx, err := ws[i].TransferPayload0([]rpc.Transfer{{Destination: dst, Amount: 1}}, uint64(ring), false, rpc.Arguments{}, 0, false)
					lat[i] = time.Since(s)
					if err != nil {
						t.Errorf("build ring %d sender %d: %s", ring, i, err)
						continue
					}
					txs[i] = tx
				}
			}()
		}
		for i := 0; i < senders; i++ {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
		return txs, lat, time.Since(t0)
	}

	enc := json.NewEncoder(os.Stdout)
	for _, ring := range rings {
		row := map[string]interface{}{"ring": ring, "senders": senders, "workers": workers}

		// round A: serial admission
		txs, blat, bwall := build(ring)
		row["build"] = summarize(blat)
		row["build_tps_parallel"] = float64(senders) / bwall.Seconds()
		row["tx_bytes"] = len(txs[0].Serialize())
		if os.Getenv("TXFLOW_BUILD_ONLY") == "1" { // wallet-side only: nothing is submitted, so no block is needed
			enc.Encode(row)
			continue
		}

		// same-sender second tx in the same block (exchange hot-wallet case)
		if second, err := ws[0].TransferPayload0([]rpc.Transfer{{Destination: ws[senders].GetAddress().String(), Amount: 2}}, uint64(ring), false, rpc.Arguments{}, 0, false); err == nil {
			defer func(tx *transaction.Transaction) { _ = tx }(second)
			row["_second_tx_same_sender"] = second
		}

		var alat []time.Duration
		c0, t0 := cpu_seconds(), time.Now()
		for i := range txs {
			s := time.Now()
			if err := chain.Add_TX_To_Pool(copy_tx(t, txs[i])); err != nil {
				t.Errorf("admit ring %d tx %d: %s", ring, i, err)
			}
			alat = append(alat, time.Since(s))
		}
		wall := time.Since(t0)
		row["admit_serial"] = summarize(alat)
		row["admit_serial_tps"] = float64(len(txs)) / wall.Seconds()
		row["admit_serial_cpu_per_tx_ms"] = (cpu_seconds() - c0) * 1000 / float64(len(txs))
		if second, ok := row["_second_tx_same_sender"].(*transaction.Transaction); ok {
			err := chain.Add_TX_To_Pool(copy_tx(t, second))
			row["second_tx_same_sender_admit"] = fmt.Sprintf("%v", err)
		}
		delete(row, "_second_tx_same_sender")
		sel, tmpl, add := txflow_mine(t, chain, genesis.GetAddress())
		row["serial_block"] = map[string]interface{}{"mempool": len(txs), "selected": sel, "template_ms": tmpl.Milliseconds(), "add_ms": add.Milliseconds(), "add_cpu_ms": last_block_add_cpu_ms}
		if sel == 0 { // a tx that references the tip is deferred one block (miner_block.go collision rule)
			sel2, tmpl2, add2 := txflow_mine(t, chain, genesis.GetAddress())
			row["serial_block_next"] = map[string]interface{}{"selected": sel2, "template_ms": tmpl2.Milliseconds(), "add_ms": add2.Milliseconds()}
		}
		txflow_mine(t, chain, genesis.GetAddress())
		sync_senders()

		// round B: duplicate concurrent admission, then parallel admission
		txs, _, _ = build(ring)
		{
			copies := make([]*transaction.Transaction, dups)
			for i := range copies {
				copies[i] = copy_tx(t, txs[0])
			}
			c0, t0 := cpu_seconds(), time.Now()
			var wg sync.WaitGroup
			var mu sync.Mutex
			ok := 0
			for i := range copies {
				wg.Add(1)
				go func(tx *transaction.Transaction) {
					defer wg.Done()
					if chain.Add_TX_To_Pool(tx) == nil {
						mu.Lock()
						ok++
						mu.Unlock()
					}
				}(copies[i])
			}
			wg.Wait()
			row["dup_concurrent"] = map[string]interface{}{"copies": dups, "accepted": ok, "wall_ms": time.Since(t0).Milliseconds(), "cpu_ms": (cpu_seconds() - c0) * 1000}
		}
		{
			var prof *os.File
			if ring == 16 && os.Getenv("TXFLOW_PPROF") != "" {
				prof, _ = os.Create(os.Getenv("TXFLOW_PPROF"))
				pprof.StartCPUProfile(prof)
			}
			jobs := make(chan int)
			lat := make([]time.Duration, len(txs))
			expanded := make([]*transaction.Transaction, len(txs))
			var wg sync.WaitGroup
			c0, t0 := cpu_seconds(), time.Now()
			for k := 0; k < workers; k++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := range jobs {
						s := time.Now()
						expanded[i] = copy_tx(t, txs[i])
						if err := chain.Add_TX_To_Pool(expanded[i]); err != nil {
							t.Errorf("padmit ring %d tx %d: %s", ring, i, err)
						}
						lat[i] = time.Since(s)
					}
				}()
			}
			for i := 1; i < len(txs); i++ {
				jobs <- i
			}
			close(jobs)
			wg.Wait()
			wall := time.Since(t0)
			if prof != nil {
				pprof.StopCPUProfile()
				prof.Close()
			}
			row["admit_parallel"] = summarize(lat[1:])
			row["admit_parallel_tps"] = float64(len(txs)-1) / wall.Seconds()
			row["admit_parallel_cpu_per_tx_ms"] = (cpu_seconds() - c0) * 1000 / float64(len(txs)-1)

			// pure proof verification throughput (statements already expanded by the admissions above)
			verify_rate := func(threads int) float64 {
				var n int64
				var mu sync.Mutex
				var wg sync.WaitGroup
				deadline := time.Now().Add(2 * time.Second)
				t0 := time.Now()
				for k := 0; k < threads; k++ {
					wg.Add(1)
					go func(k int) {
						defer wg.Done()
						local := int64(0)
						for j := k; time.Now().Before(deadline); j++ {
							tx := expanded[1+j%(len(expanded)-1)]
							if !tx.Payloads[0].Proof.Verify(tx.Payloads[0].SCID, 0, &tx.Payloads[0].Statement, tx.GetHash(), tx.Payloads[0].BurnValue) {
								t.Errorf("verify failed")
								return
							}
							local++
						}
						mu.Lock()
						n += local
						mu.Unlock()
					}(k)
				}
				wg.Wait()
				return float64(n) / time.Since(t0).Seconds()
			}
			// statement expansion only (balance-tree reads + point decompression), the non-proof part of admission
			{
				c0, t0 := cpu_seconds(), time.Now()
				for i := 1; i < len(txs); i++ {
					if err := chain.Expand_Transaction_NonCoinbase(copy_tx(t, txs[i])); err != nil {
						t.Errorf("expand: %s", err)
					}
				}
				row["expand_only_ms_per_tx"] = time.Since(t0).Seconds() * 1000 / float64(len(txs)-1)
				row["expand_only_cpu_ms_per_tx"] = (cpu_seconds() - c0) * 1000 / float64(len(txs)-1)
			}
			v1 := verify_rate(1)
			vw := verify_rate(workers)
			row["proof_verify_per_s_1thread"] = v1
			row["proof_verify_per_s_workers"] = vw
			row["proof_verify_scaling"] = vw / v1
		}
		sel, tmpl, add = txflow_mine(t, chain, genesis.GetAddress())
		row["parallel_block"] = map[string]interface{}{"mempool": len(txs), "selected": sel, "template_ms": tmpl.Milliseconds(), "add_ms": add.Milliseconds(), "add_cpu_ms": last_block_add_cpu_ms}
		if sel == 0 {
			sel2, tmpl2, add2 := txflow_mine(t, chain, genesis.GetAddress())
			row["parallel_block_next"] = map[string]interface{}{"selected": sel2, "template_ms": tmpl2.Milliseconds(), "add_ms": add2.Milliseconds()}
		}
		txflow_mine(t, chain, genesis.GetAddress())
		sync_senders()
		enc.Encode(row)
	}
}
