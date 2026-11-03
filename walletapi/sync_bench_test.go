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

package walletapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/docopt/docopt-go"

	derodrpc "github.com/deroproject/derohe/cmd/derod/rpc"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

// simulator_chain_start_at is simulator_chain_start with a caller-chosen data
// directory and loopback RPC port (so it never collides with Test_Creation_TX).
func simulator_chain_start_at(dir, port string) (*blockchain.Blockchain, *derodrpc.RPCServer) {
	params := map[string]interface{}{"--simulator": true}
	parser := &docopt.Parser{HelpHandler: docopt.PrintHelpOnly, OptionsFirst: true}
	var err error
	globals.Arguments, err = parser.ParseArgs(command_line, []string{"--data-dir", dir, "--rpc-bind", port, "--testnet"}, config.Version.String())
	if err != nil {
		panic(err)
	}
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

// rtt_proxy forwards TCP connections to target and delays every chunk by rtt/2 in each direction (order kept), so a
// loopback daemon looks like a remote one with that round-trip time. stop closes the listener and all connections.
func rtt_proxy(target string, rtt time.Duration) (addr string, stop func()) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	var conns []net.Conn
	done := make(chan struct{})
	pipe := func(dst, src net.Conn) {
		type chunk struct {
			due time.Time
			b   []byte
		}
		q := make(chan chunk, 4096)
		go func() {
			for c := range q {
				time.Sleep(time.Until(c.due))
				if _, err := dst.Write(c.b); err != nil {
					break
				}
			}
			dst.Close()
		}()
		buf := make([]byte, 64<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				q <- chunk{time.Now().Add(rtt / 2), append([]byte(nil), buf[:n]...)}
			}
			if err != nil {
				if err != io.EOF {
					src.Close()
				}
				close(q)
				return
			}
		}
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			u, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			select {
			case <-done:
				c.Close()
				u.Close()
				return
			default:
			}
			conns = append(conns, c, u)
			go pipe(u, c)
			go pipe(c, u)
		}
	}()
	return l.Addr().String(), func() {
		close(done)
		l.Close()
		for _, c := range conns {
			c.Close()
		}
	}
}

// Test_Sync_Bench builds a simulator chain where the "src" wallet mines every
// block (one coinbase entry per block, i.e. a miner's wallet) and sends a
// transfer to "dst" every 10 blocks. It then restores both wallets from seed
// and times a full-history sync, checking the result equals the history the
// same wallets built incrementally. Gated: DERO_WALLET_SYNC_BENCH=1.
// DERO_WALLET_SYNC_BLOCKS sets the chain length (default 300).
// DERO_WALLET_SYNC_TWO_TX=1 (r20 merge, RW-01 review): the genesis wallet also sends to "dst" in the same block, so
// those blocks carry 2 txs and the prefetcher's batched GetTransaction path is exercised end to end.
func Test_Sync_Bench(t *testing.T) {
	if os.Getenv("DERO_WALLET_SYNC_BENCH") == "" {
		t.Skip("set DERO_WALLET_SYNC_BENCH=1 to run the wallet sync benchmark")
	}
	blocks := 300
	if v, err := strconv.Atoi(os.Getenv("DERO_WALLET_SYNC_BLOCKS")); err == nil && v > 0 {
		blocks = v
	}
	port := "127.0.0.1:26917"
	if v := os.Getenv("DERO_WALLET_SYNC_PORT"); v != "" {
		port = v
	}

	Initialize_LookupTable(1, 1<<17)
	dir := t.TempDir()

	const src_seed = "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly"
	const dst_seed = "Dekade Spagat Bereich Radclub Yeti Dialekt Unimog Nomade Anlage Hirte Besitz Märzluft Krabbe Nabel Halsader Chefarzt Hering tauchen Neuerung Reifen Umgang Hürde Alchimie Amnesie Reifen"
	const gen_seed = "perfil lujo faja puma favor pedir detalle doble carbón neón paella cuarto ánimo cuento conga correr dental moneda león donar entero logro realidad acceso doble"

	mk := func(name, seed string) *Wallet_Disk {
		w, err := Create_Encrypted_Wallet_From_Recovery_Words(filepath.Join(dir, name), "QWER", seed)
		if err != nil {
			t.Fatalf("create wallet %s: %s", name, err)
		}
		return w
	}
	wsrc, wdst, wgenesis := mk("src.db", src_seed), mk("dst.db", dst_seed), mk("gen.db", gen_seed)

	genesis_tx := transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, Value: 2012345}}
	copy(genesis_tx.MinerAddress[:], wgenesis.account.Keys.Public.EncodeCompressed())
	config.Testnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())
	config.Mainnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())
	genesis_block := blockchain.Generate_Genesis_Block()
	config.Testnet.Genesis_Block_Hash = genesis_block.GetHash()
	config.Mainnet.Genesis_Block_Hash = genesis_block.GetHash()

	chain, rpcserver := simulator_chain_start_at(filepath.Join(dir, "chain"), port)
	defer simulator_chain_stop(chain, rpcserver)
	globals.Arguments["--daemon-address"] = port
	time.Sleep(200 * time.Millisecond)
	if err := Connect(port); err != nil {
		t.Fatalf("connect: %s", err)
	}

	for _, w := range []*Wallet_Disk{wsrc, wdst} {
		if err := chain.Add_TX_To_Pool(w.GetRegistrationTX()); err != nil {
			t.Fatalf("regtx: %s", err)
		}
	}
	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	for _, w := range []*Wallet_Disk{wsrc, wdst, wgenesis} {
		w.SetDaemonAddress(port)
		w.SetOnlineMode()
		w.account.Ringsize = 2
	}
	if err := wsrc.Sync_Wallet_Memory_With_Daemon(); err != nil {
		t.Fatalf("sync: %s", err)
	}

	sent := 0
	for i := 0; i < blocks; i++ {
		if i%10 == 5 {
			wsrc.Sync_Wallet_Memory_With_Daemon()
			tx, err := wsrc.TransferPayload0([]rpc.Transfer{{Destination: wdst.GetAddress().String(), Amount: uint64(1 + i)}}, 0, false, rpc.Arguments{}, 0, false)
			if err != nil {
				t.Fatalf("transfer at %d: %s", i, err)
			}
			var dtx transaction.Transaction
			dtx.Deserialize(tx.Serialize())
			if err := chain.Add_TX_To_Pool(&dtx); err != nil {
				t.Fatalf("pool at %d: %s", i, err)
			}
			sent++
			if os.Getenv("DERO_WALLET_SYNC_TWO_TX") == "1" {
				wgenesis.Sync_Wallet_Memory_With_Daemon()
				tx2, err := wgenesis.TransferPayload0([]rpc.Transfer{{Destination: wdst.GetAddress().String(), Amount: uint64(100 + i)}}, 0, false, rpc.Arguments{}, 0, false)
				if err != nil {
					t.Fatalf("second transfer at %d: %s", i, err)
				}
				var dtx2 transaction.Transaction
				dtx2.Deserialize(tx2.Serialize())
				if err := chain.Add_TX_To_Pool(&dtx2); err != nil {
					t.Fatalf("pool (second tx) at %d: %s", i, err)
				}
				sent++
			}
		}
		simulator_chain_mineblock(chain, wsrc.GetAddress(), t)
	}
	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)

	// reference: histories the wallets built incrementally
	wsrc.Sync_Wallet_Memory_With_Daemon()
	wdst.Sync_Wallet_Memory_With_Daemon()

	// DERO_WALLET_SYNC_RTT_MS=n: the timed full syncs talk to the daemon through rtt_proxy (a remote-daemon model)
	daemon := port
	rtt_ms, _ := strconv.Atoi(os.Getenv("DERO_WALLET_SYNC_RTT_MS"))
	if rtt_ms > 0 {
		paddr, stop := rtt_proxy(port, time.Duration(rtt_ms)*time.Millisecond)
		defer stop()
		daemon = paddr
		if err := Connect(daemon); err != nil {
			t.Fatalf("connect via rtt proxy: %s", err)
		}
	}

	var zero crypto.Hash
	for _, c := range []struct {
		name, seed string
		ref        *Wallet_Disk
	}{{"src", src_seed, wsrc}, {"dst", dst_seed, wdst}} {
		w := mk("restored_"+c.name+".db", c.seed)
		w.SetDaemonAddress(daemon)
		w.SetOnlineMode()
		rpc0 := RPCCallCount()
		t0 := time.Now()
		if err := w.Sync_Wallet_Memory_With_Daemon(); err != nil {
			t.Fatalf("full sync %s: %s", c.name, err)
		}
		el := time.Since(t0)
		rpcs := RPCCallCount() - rpc0
		got, _ := json.Marshal(w.account.EntriesNative[zero])
		want, _ := json.Marshal(c.ref.account.EntriesNative[zero])
		equal := string(got) == string(want)
		fmt.Printf("SYNCBENCH wallet=%s rtt_ms=%d parallel_env=%q blocks=%d transfers=%d entries=%d balance=%d ms=%.1f rpc_calls=%d equal_to_incremental=%v\n",
			c.name, rtt_ms, os.Getenv("DERO_WALLET_SYNC_PARALLEL"), blocks, sent, len(w.account.EntriesNative[zero]), w.account.Balance_Mature, float64(el.Microseconds())/1000, rpcs, equal)
		if w.account.Balance_Mature != c.ref.account.Balance_Mature {
			t.Fatalf("%s balance mismatch full=%d incremental=%d", c.name, w.account.Balance_Mature, c.ref.account.Balance_Mature)
		}
		if !equal {
			os.WriteFile(filepath.Join(os.TempDir(), "syncbench_"+c.name+"_full.json"), got, 0600)
			os.WriteFile(filepath.Join(os.TempDir(), "syncbench_"+c.name+"_incr.json"), want, 0600)
			t.Errorf("%s: full-sync history differs from incremental history", c.name)
		}
	}
}
