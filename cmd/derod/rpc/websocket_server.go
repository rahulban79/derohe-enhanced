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

package rpc

import "io"
import "os"
import "path/filepath"
import "net"
import "fmt"
import "net/http"
import "net/http/pprof"
import "time"
import "sort"
import "sync"
import "sync/atomic"
import "context"
import "strings"
import "runtime/debug"
import "encoding/json"

import "github.com/deroproject/derohe/config"
import "github.com/deroproject/derohe/globals"
import "github.com/deroproject/derohe/blockchain"
import "github.com/deroproject/derohe/glue/rwc"
import "github.com/deroproject/derohe/metrics"

import "github.com/go-logr/logr"
import "github.com/gorilla/websocket"

import "github.com/creachadair/jrpc2"
import "github.com/creachadair/jrpc2/handler"
import "github.com/creachadair/jrpc2/channel"

//import "github.com/creachadair/jrpc2/server"
import "github.com/creachadair/jrpc2/jhttp"

/* this file implements the rpcserver api, so as wallet and block explorer tools can work without migration */

// all components requiring access to blockchain must use , this struct to communicate
// this structure must be update while mutex
type RPCServer struct {
	srv        *http.Server
	mux        *http.ServeMux
	Exit_Event chan bool              // blockchain is shutting down and we must quit ASAP
	tx_chain   *blockchain.Blockchain // r21: the chain tx_events_loop reads (captured once, not the global)
	sync.RWMutex
}

// var Exit_In_Progress bool
var chain *blockchain.Blockchain
var logger logr.Logger

var client_connections sync.Map

var options = &jrpc2.ServerOptions{AllowPush: true, RPCLog: metrics_generator{}, DecodeContext: func(ctx context.Context, method string, param json.RawMessage) (context.Context, json.RawMessage, error) {
	t := time.Now()
	return context.WithValue(ctx, "start_time", &t), param, nil
}}

type metrics_generator struct{}

func (metrics_generator) LogRequest(ctx context.Context, req *jrpc2.Request) {}
func (metrics_generator) LogResponse(ctx context.Context, resp *jrpc2.Response) {
	defer globals.Recover(2)
	req := jrpc2.InboundRequest(ctx) // we cannot do anything here
	if req == nil {
		return
	}
	observe_ws(ctx, resp) // r23: behaviour score of a remote socket; free for loopback (rpc_abuse.go)
	// r27: rpc_error_responses_total{code} (r27_rpcmetrics.go), unknown methods included
	count_error_code(resp.Error())
	start_time, ok := ctx.Value("start_time").(*time.Time)
	if !ok {
		return //panic("cannot find time in context")
	}

	m := metrics_for(req.Method()) // nil for a name no handler serves: counted once, never a client-chosen series (r19)
	if m == nil {
		rpc_unknown_methods.Inc()
		return
	}
	m.duration.UpdateDuration(*start_time)
	m.total.Inc()
	if resp.Error() != nil {
		m.errors.Inc()
	}
	m.out.Add(response_size(resp)) // was resp.MarshalJSON(), a second copy of every response just to count it
}

// this function triggers notification to all clients that they should repoll
// r19: also sends Height. Notify_Height_Changes waited on the same condition variable and walked the clients a second
// time; one bundle per client now carries Block, Height and (for subscribers) BlockInfo, in that order.
func Notify_Block_Addition() {

	for {
		chain.RPC_NotifyNewBlock.L.Lock()
		chain.RPC_NotifyNewBlock.Wait()
		chain.RPC_NotifyNewBlock.L.Unlock()
		reorg := func() (ev *Reorg_Event) { // r23b: compare the last REORG_WINDOW topoheights (reorg_events.go)
			defer globals.Recover(2)
			return observe_chain_reorg()
		}()
		// r23c: one ordered push worker (post_push)
		post_push(func() { push_block_ev(chain_block_info, reorg) })
		kick_tx_events()      // r21: re-check watched txids now, not at the next 1 s tick
		kick_emission_audit() // r23: audit the new block's plaintext supply effect (emission_audit.go)
	}
}

// this function triggers notification to all clients that they should repoll
func Notify_MiniBlock_Addition() {

	for {
		chain.RPC_NotifyNewMiniBlock.L.Lock()
		chain.RPC_NotifyNewMiniBlock.Wait()
		chain.RPC_NotifyNewMiniBlock.L.Unlock()

		if globals.Arguments["--simulator"] == nil || (globals.Arguments["--simulator"] != nil && globals.Arguments["--simulator"].(bool) == false) {
			kick_jobs() // r23: the dispatcher sends one job per state change (job_dispatch.go)
		}
		post_push(func() { push_miniblock(chain_miniblock_info) }) // only to DERO.Subscribe'd websockets; free when there are none
	}
}

// r23c: the block and miniblock notify loops hand their pushes to ONE worker, in order. Before, each event started its
// own goroutine, so two blocks a few milliseconds apart (a reorg, or catching up) could reach the client queues in
// either order and a client could be left showing the older tip as the newest BlockInfo until the next block.
// Posting never blocks a notify loop: past PUSH_POST_BUFFER pending events one is dropped and counted (a client
// still sees every later state; BlockInfo carries reorg_seq for a missed Reorg).
const PUSH_POST_BUFFER = 256

var push_posts = make(chan func(), PUSH_POST_BUFFER)
var push_post_dropped = metrics.Set.GetOrCreateCounter("rpc_ws_push_post_dropped_total")
var push_worker_once sync.Once

func post_push(f func()) {
	push_worker_once.Do(func() { go push_worker(push_posts) })
	select {
	case push_posts <- f:
	default:
		push_post_dropped.Inc()
	}
}

func push_worker(posts <-chan func()) {
	for f := range posts {
		func() {
			defer globals.Recover(2)
			f()
		}()
	}
}

func RPCServer_Start(params map[string]interface{}) (*RPCServer, error) {
	var r RPCServer

	metrics.Set.GetOrCreateGauge("rpc_client_count", func() float64 { // set a new gauge
		count := float64(0)
		client_connections.Range(func(k, value interface{}) bool {
			count++
			return true
		})
		return count
	})

	r.Exit_Event = make(chan bool)

	logger = globals.Logger.WithName("RPC") // all components must use this logger
	chain = params["chain"].(*blockchain.Blockchain)
	r.tx_chain = chain

	// r25 (CO24-C6): the reorg monitor's lifetime counts survive restarts (reorg_events.go)
	if err := reorg_state.enable_persist(filepath.Join(globals.GetDataDirectory(), REORG_MONITOR_FILE)); err != nil {
		logger.V(1).Info("reorg monitor not persisted", "err", err.Error())
	}

	go r.Run()
	logger.Info("RPC/Websocket server started")
	atomic.AddUint32(&globals.Subsystem_Active, 1) // increment subsystem

	return &r, nil
}

// shutdown the rpc server component
func (r *RPCServer) RPCServer_Stop() {
	r.Lock()
	defer r.Unlock()

	close(r.Exit_Event) // send signal to all connections to exit

	if r.srv != nil {
		r.srv.Shutdown(context.Background()) // shutdown the server
	}
	// TODO we  must wait for connections to kill themselves
	time.Sleep(1 * time.Second)
	reorg_state.flush() // r25 (CO24-C6): the observations since the last periodic save
	logger.Info("RPC Shutdown")
	atomic.AddUint32(&globals.Subsystem_Active, ^uint32(0)) // this decrement 1 fom subsystem
}

// setup handlers
func (r *RPCServer) Run() {

	// create a new mux
	r.mux = http.NewServeMux()

	default_address := "127.0.0.1:" + fmt.Sprintf("%d", config.Mainnet.RPC_Default_Port)
	if !globals.IsMainnet() {
		default_address = "127.0.0.1:" + fmt.Sprintf("%d", config.Testnet.RPC_Default_Port)
	}

	if _, ok := globals.Arguments["--rpc-bind"]; ok && globals.Arguments["--rpc-bind"] != nil {
		addr, err := net.ResolveTCPAddr("tcp", globals.Arguments["--rpc-bind"].(string))
		if err != nil {
			logger.Error(err, "--rpc-bind address is invalid")
		} else {
			if addr.Port == 0 {
				logger.Info("RPC server is disabled, No ports will be opened for RPC")
				return
			} else {
				default_address = addr.String()
			}
		}
	}

	logger.Info("RPC will listen", "address", default_address)
	rpc_bind_address = default_address    // GetPeerInfo's bind gate (rpc_dero_explorer.go)
	configure_abuse(rpc_abuse, os.Getenv) // r23: DERO_RPC_ABUSE_GUARD / DERO_RPC_REMOTE_RATE / _BURST (rpc_abuse.go)
	if !bind_is_loopback(default_address) {
		logger.Info("WARNING: daemon RPC is reachable from the network; it has no authentication (SubmitBlock, SendRawTransaction, GetBlockTemplate are open)", "address", default_address)
	}
	r.Lock()
	r.srv = new_rpc_http_server(default_address, rpc_guard(default_address, r.mux, os.Getenv)) // header/idle timeouts; Host/Origin guard (ws_hardening.go)
	r.Unlock()

	r.mux.HandleFunc("/json_rpc", json_rpc_handler) // body limit, and per-IP limits off loopback (ws_hardening.go)
	r.mux.HandleFunc("/ws", ws_handler)
	r.mux.HandleFunc("/health", health)
	r.mux.HandleFunc("/", hello)
	if !register_metrics_routes(r.mux, default_address, os.Getenv) { // loopback, or ENABLE_PUBLIC_METRICS=1 (node_metrics.go)
		logger.Info("/metrics and /dashboard are disabled", "address", default_address, "public_opt_in", "ENABLE_PUBLIC_METRICS=1")
	}

	//if DEBUG_MODE {
	// r.mux.HandleFunc("/debug/pprof/", pprof.Index)

	// Register pprof handlers individually if required
	// we should provide a way to disable these

	if !pprof_allowed(default_address, os.Getenv) { // DISABLE_RUNTIME_PROFILE=1, or a non-loopback bind without opt-in (bind_policy.go)
		logger.Info("runtime profiling is disabled", "address", default_address, "public_opt_in", "ENABLE_PUBLIC_RUNTIME_PROFILE=1")
	} else { // Register pprof handlers individually if required

		r.mux.HandleFunc("/debug/pprof/", pprof.Index)
		r.mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		r.mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		r.mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		r.mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	go Notify_Block_Addition()                  // process all blocks
	go Notify_MiniBlock_Addition()              // process all blocks
	go tx_events_loop(r.tx_chain, r.Exit_Event) // r21: TxPool / TxStatus pushes (ws_tx_events.go); idle without subscribers
	go emission_audit_loop(r.Exit_Event)        // r23: per-block emission/reward auditor (emission_audit.go)
	if err := r.srv.ListenAndServe(); err != http.ErrServerClosed {
		logger.Error(err, "ListenAndServe failed")
	}

}

func hello(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "DERO BLOCKCHAIN Hello world!")
}

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }} // use default options

func ws_handler(w http.ResponseWriter, r *http.Request) {

	ip, loopback := remote_ip(r)
	if !loopback {
		if d := rpc_abuse.banned_for(ip, time.Now()); d > 0 && !abuse_exempt(ip, loopback) { // r23 (rpc_abuse.go)
			write_abuse_http(w, abuse_banned, d)
			return
		}
		if !ws_conn_limit.acquire(ip) {
			metrics.Set.GetOrCreateCounter("rpc_limited_total").Inc()
			http.Error(w, "too many websocket connections from this address", http.StatusTooManyRequests)
			return
		}
		defer ws_conn_limit.release(ip)
	}

	var ws_server *jrpc2.Server
	defer func() {

		// safety so if anything wrong happens, verification fails
		if r := recover(); r != nil {
			logger.V(2).Error(nil, "Recovered while processing websocket request", "r", r, "stack", debug.Stack())
		}
		if ws_server != nil {
			if v, ok := client_connections.Load(ws_server); ok {
				v.(*ws_client).drop_watches() // r21: frees its share of WATCH_MAX_TOTAL
			}
			client_connections.Delete(ws_server)
		}

	}()

	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	defer c.Close()
	input_output := rwc.NewLimited(c, RPC_READ_LIMIT) // gorilla's default is no limit; one ceiling for /json_rpc and /ws
	input_output.WriteTimeout = WS_WRITE_TIMEOUT      // a client that stops reading no longer blocks its server forever
	client := new_ws_client(c, foreign_origin(r), ip)
	assigner := assigner_for(client) // r21: a foreign socket's calls pass its rate gate
	if !abuse_exempt(ip, loopback) {
		client.abuse_key = ip
		assigner = remote_assigner{c: client, next: assigner} // r23: remote calls are charged and scored (rpc_abuse.go)
		atomic.AddInt32(&remote_ws_sockets, 1)
		defer atomic.AddInt32(&remote_ws_sockets, -1)
	}
	ws_server = jrpc2.NewServer(assigner, ws_server_options(client))
	// r20: stored BEFORE Start, so the first request of a cross-site client already finds foreign=true (fail closed)
	client_connections.Store(ws_server, client)
	ws_server.Start(channel.RawJSON(input_output, input_output))
	ws_server.Wait()

}

func DAEMON_Echo(ctx context.Context, args []string) string {
	return "DAEMON " + strings.Join(args, " ")
}

// used to verify whether the connection is alive
func Ping(ctx context.Context) string {
	return "Pong "
}

func Echo(ctx context.Context, args []string) string {
	return "DERO " + strings.Join(args, " ")
}

/*
//var internal_server = server.NewLocal(assigner,nil) // Use DERO.GetInfo names
var internal_server = server.NewLocal(historical_apis, nil) // uses traditional "getinfo" for compatibility reasons
// Bridge HTTP to the JSON-RPC server.
var bridge = jhttp.NewBridge(internal_server.Client)
*/
var historical_apis = handler.Map{"getinfo": typed_new(GetInfoR25), // r25 BD6: + total_supply_basis (r25_rpcrobust.go)
	"get_info":                   typed_new(GetInfoR25), // this is just an alias to above
	"getblock":                   typed_new(GetBlock),
	"getblockheaderbytopoheight": typed_new(GetBlockHeaderByTopoHeight),
	"getblockheaderbyhash":       typed_new(GetBlockHeaderByHash),
	"gettxpool":                  typed_new(GetTxPool),
	"getrandomaddress":           typed_new(GetRandomAddress),
	"gettransactions":            typed_new(GetTransactionR25), // r25: + txs_status
	"sendrawtransaction":         typed_new(SendRawTransaction),
	"submitblock":                typed_new(SubmitBlock),
	"getheight":                  typed_new(GetHeight),
	"getblockcount":              typed_new(GetBlockCount),
	"getlastblockheader":         typed_new(GetLastBlockHeader),
	"getblocktemplate":           typed_new(GetBlockTemplate),
	"getencryptedbalance":        typed_new(GetEncryptedBalance),
	"getsc":                      typed_new(GetSC),
	"getgasestimate":             typed_new(GetGasEstimate),
	"nametoaddress":              typed_new(NameToAddress)}

var servicemux = handler.ServiceMap{
	"DERO": handler.Map{
		"Echo":                       typed_new(Echo),
		"Ping":                       typed_new(Ping),
		"GetInfo":                    typed_new(GetInfoR25), // r25 BD6
		"GetSyncInfo":                typed_new(GetSyncInfo),
		"Subscribe":                  typed_new(Subscribe),
		"WatchTx":                    typed_new(WatchTx),
		"GetMiningOutcome":           typed_new(GetMiningOutcome),
		"GetSupplyAudit":             typed_new(GetSupplyAudit),
		"GetEmissionAudit":           typed_new(GetEmissionAudit),
		"GetBlockHeadersRange":       typed_new(GetBlockHeadersRange),
		"GetMiniBlocks":              typed_new(GetMiniBlocks),
		"GetDifficultyHistory":       typed_new(GetDifficultyHistory),
		"GetTxPoolDetail":            typed_new(GetTxPoolDetail),
		"GetPeerInfo":                typed_new(GetPeerInfo),
		"GetTxStatus":                typed_new(GetTxStatus),
		"GetFeeEstimate":             typed_new(GetFeeEstimate),       // r23
		"GetMonetaryIntegrity":       typed_new(GetMonetaryIntegrity), // r23b
		"GetConsensusStats":          typed_new(GetConsensusStats),    // r25 (consensus observatory)
		"GetBlock":                   typed_new(GetBlock),
		"GetBlockHeaderByTopoHeight": typed_new(GetBlockHeaderByTopoHeight),
		"GetBlockHeaderByHash":       typed_new(GetBlockHeaderByHash),
		"GetTxPool":                  typed_new(GetTxPool),
		"GetRandomAddress":           typed_new(GetRandomAddress),
		"GetTransaction":             typed_new(GetTransactionR25), // r25: + txs_status
		"SendRawTransaction":         typed_new(SendRawTransaction),
		"SubmitBlock":                typed_new(SubmitBlock),
		"GetHeight":                  typed_new(GetHeight),
		"GetBlockCount":              typed_new(GetBlockCount),
		"GetLastBlockHeader":         typed_new(GetLastBlockHeader),
		"GetBlockTemplate":           typed_new(GetBlockTemplate),
		"GetEncryptedBalance":        typed_new(GetEncryptedBalance),
		"GetSC":                      typed_new(GetSC),
		"GetGasEstimate":             typed_new(GetGasEstimate),
		"NameToAddress":              typed_new(NameToAddress),
	},
	"DAEMON": handler.Map{
		"Echo": typed_new(DAEMON_Echo),
	},
}

type dummyassigner int

var d dummyassigner

func (d dummyassigner) Assign(ctx context.Context, method string) (handler jrpc2.Handler) {
	if handler = servicemux.Assign(ctx, method); handler != nil {
		return
	}
	if handler = historical_apis.Assign(ctx, method); handler != nil {
		return
	}
	return nil
}

func (d dummyassigner) Names() []string {
	names := servicemux.Names()
	hist_names := historical_apis.Names()

	names = append(names, hist_names...)
	sort.Strings(names)
	return names
}

// r19 (rpcws RPCWS-4 + observability OBS-01): the bridge shares the websocket's server options. With nil options no
// HTTP request reached LogResponse, so /metrics showed nothing for the /json_rpc traffic of wallets, explorers and the
// miner's outcome poll.
var bridge = jhttp.NewBridge(d, &jhttp.BridgeOptions{Server: options})

func translate_http_to_jsonrpc_and_vice_versa(w http.ResponseWriter, r *http.Request) {
	bw := &bridge_writer{ResponseWriter: w} // r29 B175: the bridge's own error answers become counted JSON-RPC bodies
	bridge.ServeHTTP(bw, r)
	bw.finish()
}
