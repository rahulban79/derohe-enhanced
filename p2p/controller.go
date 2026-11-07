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

package p2p

import "fmt"
import "net"

import "os"
import "time"
import "sort"
import "sync"
import "strings"
import "math/big"
import "strconv"

import "crypto/sha1"
import "crypto/ecdsa"
import "crypto/elliptic"

import "crypto/tls"
import "crypto/rand"
import "crypto/x509"
import "encoding/pem"
import "sync/atomic"
import "runtime/debug"

import "github.com/go-logr/logr"

import "github.com/deroproject/derohe/config"
import "github.com/deroproject/derohe/globals"
import "github.com/deroproject/derohe/metrics"
import "github.com/deroproject/derohe/blockchain"

import "github.com/xtaci/kcp-go/v5"
import "golang.org/x/crypto/pbkdf2"
import "golang.org/x/time/rate"

import "github.com/cenkalti/rpc2"

//import "github.com/txthinking/socks5"

var chain *blockchain.Blockchain // external reference to chain

var P2P_Port int // this will be exported while doing handshake

var Exit_Event = make(chan bool) // causes all threads to exit
var Exit_In_Progress bool        // marks we are doing exit
var logger logr.Logger           // global logger, every logger in this package is a child of this
var sync_node bool               // whether sync mode is activated

var nonbanlist []string // any ips in this list will never be banned
// the list will include seed nodes, any nodes provided at command prompt

var ClockOffset time.Duration //Clock Offset related to all the peer2 connected

// also backoff is used if we have initiated a connect we will not connect to it again for another 10 secs
var backoff = map[string]int64{} // if server receives a connection, then it will not initiate connection to that ip for another 60 secs
var backoff_mutex = sync.Mutex{}

var Min_Peers = int64(31) // we need to expose this to be modifieable at runtime without taking daemon offline
var Max_Peers = int64(101)

// P2PLowLatency selects the aggressive low-latency KCP profile in tunekcp (fast 10ms flush +
// fast-retransmit, congestion-control off) instead of the default 40ms/congestion-controlled
// profile. Set once at startup from --lowlatency or env TURBO=0. Transport-only: it changes how
// fast identical bytes are flushed, never what is sent — no consensus impact. Reduces per-hop
// miniblock propagation latency (the reward-critical path). Read after startup, so no lock needed.
var P2PLowLatency bool

// return true if we should back off else we can connect
func shouldwebackoff(ip string) bool {
	backoff_mutex.Lock()
	defer backoff_mutex.Unlock()

	now := time.Now().Unix()
	for k, v := range backoff { // random backing off
		if v < now {
			delete(backoff, k)
		}
	}

	if backoff[ip] != 0 { // now lets do the test
		return true
	}
	return false
}

// Initialize P2P subsystem
func P2P_Init(params map[string]interface{}) error {
	logger = globals.Logger.WithName("P2P") // all components must use this logger

	// register_handlers()

	GetPeerID() // Initialize peer id once

	// parse node tag if availble
	if _, ok := globals.Arguments["--node-tag"]; ok {
		if globals.Arguments["--node-tag"] != nil {
			node_tag = globals.Arguments["--node-tag"].(string)
		}
	}
	// Select KCP transport profile. NOTE: historically "turbo mode" (the default) was actually the
	// HIGHER-latency profile (40ms flush, congestion-controlled); the low-latency profile required the
	// counter-intuitive TURBO=0. --lowlatency now selects the fast profile with a truthful log message.
	if os.Getenv("TURBO") == "0" || (globals.Arguments["--lowlatency"] != nil && globals.Arguments["--lowlatency"].(bool)) {
		P2PLowLatency = true
		logger.Info("P2P KCP profile: LOW-LATENCY (10ms flush + fast-retransmit, CC off) — miniblock propagation optimized")
	} else {
		logger.Info("P2P KCP profile: DEFAULT (40ms flush, congestion-controlled) — pass --lowlatency for faster miniblock propagation")
	}

	if os.Getenv("BW_FACTOR") != "" {
		bw_factor, _ := strconv.Atoi(os.Getenv("BW_FACTOR"))
		if bw_factor <= 0 {
			bw_factor = 1
		}
		logger.Info("", "BW_FACTOR", bw_factor)
	}

	if os.Getenv("UDP_READ_BUF_CONN") != "" {
		size, _ := strconv.Atoi(os.Getenv("UDP_READ_BUF_CONN"))
		if size <= 64*1024 {
			size = 64 * 1024
		}
		logger.Info("", "UDP_READ_BUF_CONN", size)
	}

	// permanently unban any seed nodes
	if globals.IsMainnet() {
		for i := range config.Mainnet_seed_nodes {
			nonbanlist = append(nonbanlist, strings.ToLower(config.Mainnet_seed_nodes[i]))
		}
	} else { // initial bootstrap
		for i := range config.Testnet_seed_nodes {
			nonbanlist = append(nonbanlist, strings.ToLower(config.Testnet_seed_nodes[i]))
		}
	}

	chain = params["chain"].(*blockchain.Blockchain)
	if n := sweep_persist_tmp(globals.GetDataDirectory(), time.Now()); n > 0 { // r20: leftovers of a killed save
		logger.Info("removed stale temp files of peer/ban lists", "count", n)
	}
	load_ban_list()    // load ban list
	load_v2_offences() // v2-chain drop history, so a restart does not reset the escalation
	load_peer_list()   // load old list if availble
	load_first_relay() // builder-adjacency ranking, so dial preference and sticky peers survive a restart

	// if user provided a sync node, connect with it
	if _, ok := globals.Arguments["--sync-node"]; ok { // check if parameter is supported
		if globals.Arguments["--sync-node"].(bool) {
			sync_node = true
			// disable p2p port
			globals.Arguments["--p2p-bind"] = ":0"

			// disable all connections except seed nodes
			globals.Arguments["--add-exclusive-node"] = []string{"0.0.0.0:0"}
			globals.Arguments["--add-priority-node"] = []string{"0.0.0.0:0"}

			go maintain_seed_node_connection()

			logger.Info("Sync mode is enabled. Please remove this option after chain syncs successfully")
		}
	}

	go P2P_Server_v2()                                            // start accepting connections
	go P2P_engine()                                               // start outgoing engine
	globals.Cron.AddFunc("@every 4s", syncroniser)                // start sync engine
	globals.Cron.AddFunc("@every 5s", Connection_Pending_Clear)   // clean dead connections
	globals.Cron.AddFunc("@every 10s", ping_loop)                 // ping every one
	globals.Cron.AddFunc("@every 30s", stuck_peer_sweep)          // evict outgoing peers frozen far below us (stuck_peer.go)
	globals.Cron.AddFunc("@every 10s", chunks_clean_up)           // clean chunks
	globals.Cron.AddFunc("@every 12s", rebroadcast_announced_txs) // re-announce unmined txs, local or relayed alike (tx_flow.go)

	go time_check_routine() // check whether server time is in sync using ntp

	metrics.Set.NewGauge("p2p_peer_count", func() float64 { // set a new gauge
		count := float64(0)
		connection_map.Range(func(k, value interface{}) bool {
			if v := value.(*Connection); v.State.Load() != HANDSHAKE_PENDING {
				count++
			}
			return true
		})
		return count
	})
	metrics.Set.NewGauge("p2p_peer_incoming_count", func() float64 { // set a new gauge
		count := float64(0)
		connection_map.Range(func(k, value interface{}) bool {
			if v := value.(*Connection); v.State.Load() != HANDSHAKE_PENDING && v.Incoming {
				count++
			}
			return true
		})
		return count
	})
	metrics.Set.NewGauge("p2p_peer_outgoing_count", func() float64 { // set a new gauge
		count := float64(0)
		connection_map.Range(func(k, value interface{}) bool {
			if v := value.(*Connection); v.State.Load() != HANDSHAKE_PENDING && !v.Incoming {
				count++
			}
			return true
		})
		return count
	})

	logger.Info("P2P started")
	atomic.AddUint32(&globals.Subsystem_Active, 1) // increment subsystem
	return nil
}

// TODO we need to make sure that exclusive/priority nodes are never banned
func P2P_engine() {

	var end_point_list []string
	if _, ok := globals.Arguments["--add-exclusive-node"]; ok { // check if parameter is supported
		if globals.Arguments["--add-exclusive-node"] != nil {
			tmp_list := globals.Arguments["--add-exclusive-node"].([]string)
			for i := range tmp_list {
				end_point_list = append(end_point_list, tmp_list[i])
				nonbanlist = append(nonbanlist, tmp_list[i])
			}
		}
	}

	// all prority nodes will be always connected
	if _, ok := globals.Arguments["--add-priority-node"]; ok { // check if parameter is supported
		if globals.Arguments["--add-priority-node"] != nil {
			tmp_list := globals.Arguments["--add-priority-node"].([]string)
			for i := range tmp_list {
				end_point_list = append(end_point_list, tmp_list[i])
				nonbanlist = append(nonbanlist, tmp_list[i])
			}
		}
	}

	{ // remove duplicates if any
		sort.Strings(end_point_list)
	start_again: // this list is expected to be less  than 100
		for i := range end_point_list {
			if i > 0 && end_point_list[i-1] == end_point_list[i] {
				end_point_list = append(end_point_list[:i-1], end_point_list[i:]...)
				goto start_again
			}
		}
	}

	//logger.Debugf("Priority list %+v", end_point_list)

	// maintain connection to exclusive/priority nodes
	for i := range end_point_list {
		go maintain_outgoing_priority_connection(end_point_list[i], false)
	}

	// do not create connections to peers , if requested
	if _, ok := globals.Arguments["--add-exclusive-node"]; ok && len(globals.Arguments["--add-exclusive-node"].([]string)) == 0 { // check if parameter is supported
		go maintain_connection_to_peers()          // maintain certain number of connections for peer to peers
		go maintain_builder_adjacent_connections() // keep the peers closest to block builders connected

		// skip any connections, to allow more testing in closed environments
		if os.Getenv("SKIP_SEED_NODES") != "" {
			return
		}
		go maintain_seed_node_connection() // maintain connection with atleast 1 seed node

		// this code only triggers when we do not have peer list
		if find_peer_to_connect(1) == nil { // either we donot have a peer list or everyone is banned
			// trigger connection to all seed nodes hoping some will be up
			if globals.IsMainnet() { // initial boot strap should be quick
				for i := range config.Mainnet_seed_nodes {
					go connect_with_endpoint(config.Mainnet_seed_nodes[i], sync_node)
				}
			} else { // initial bootstrap
				for i := range config.Testnet_seed_nodes {
					go connect_with_endpoint(config.Testnet_seed_nodes[i], sync_node)
				}
			}

		}

	}

}

func tunekcp(conn *kcp.UDPSession) {
	conn.SetACKNoDelay(KCP_ACK_NODELAY)
	set_kcp_profile(conn, P2PLowLatency)

	// KCP's default window is 32 segments each way (kcp-go IKCP_WND_SND/RCV), i.e. ~43 KB in flight: at a 170 ms
	// RTT that caps one peer at ~145 KB/s however fast the link is (cmd/r18kcpbench, Round 18). The window is a local
	// setting: a sender uses min(own snd_wnd, peer's advertised rcv_wnd), so a larger one is safe with old peers
	// (no gain, no harm) and lifts bulk transfers (bootstrap ChangeSet/TreeSection, big blocks) between upgraded ones.
	conn.SetWindowSize(KCP_WINDOW, KCP_WINDOW)

	size := 1 * 1024 * 1024 // set the buffer size max possible upto 1 MB, default is 1 MB
	if os.Getenv("UDP_READ_BUF_CONN") != "" {
		size, _ = strconv.Atoi(os.Getenv("UDP_READ_BUF_CONN"))
		if size <= 64*1024 {
			size = 64 * 1024
		}
	}
	for size >= 64*1024 {
		if err := conn.SetReadBuffer(size); err == nil {
			break
		}
		size = size - (64 * 1024)
	}
	conn.SetWriteBuffer(1 * 1024 * 1024) // dialed sessions own their socket; accepted ones share the listener's

	if mtu := kcp_mtu_for(conn.RemoteAddr()); mtu != KCP_MTU_DEFAULT { // netlayers.go: no 1448-byte IPv6 packets
		conn.SetMtu(mtu)
	}
	if P2P_DSCP > 0 {
		note_dscp(conn.SetDSCP(P2P_DSCP)) // dialed sessions; accepted ones are marked through the listener socket
	}
}

// set_kcp_profile selects the retransmission/flush profile of one session.
// kcp_profile_hook (tests only, nil in production) observes every profile choice.
var kcp_profile_hook func(conn *kcp.UDPSession, lowlatency bool)

func set_kcp_profile(conn *kcp.UDPSession, lowlatency bool) {
	if h := kcp_profile_hook; h != nil {
		h(conn, lowlatency)
	}
	if lowlatency {
		conn.SetNoDelay(1, 10, 2, 1) // low-latency: nodelay on, 10ms flush, fast-retransmit(2), CC off — fastest miniblock propagation
	} else {
		conn.SetNoDelay(0, 40, 0, 0) // default: nodelay off, 40ms flush, no fast-retransmit, CC on
	}
}

// KCP_WINDOW is the per-session send/receive window in segments (env DERO_KCP_WND, 32..1024, default 256).
var KCP_WINDOW = env_int("DERO_KCP_WND", 256, 32, 1024)

// KCP_ACK_NODELAY=true sends one ACK datagram per received segment; false (env DERO_KCP_ACKNODELAY=0) lets ACKs ride
// the next flush (10 ms in --lowlatency): half the datagrams, same small-message RTT in cmd/r18kcpbench. Default kept
// as before until a live shadow confirms miniblock propagation is unaffected.
var KCP_ACK_NODELAY = os.Getenv("DERO_KCP_ACKNODELAY") != "0"

// every inbound peer shares the listener's one UDP socket, and it was left at the OS default (macOS
// net.inet.udp.recvspace = 786896 bytes for up to --max-peers sessions); size it like a dialed session's, times a few
func tune_listener(l *kcp.Listener) {
	for size := 4 * 1024 * 1024; size >= 256*1024; size /= 2 {
		if l.SetReadBuffer(size) == nil {
			break
		}
	}
	for size := 4 * 1024 * 1024; size >= 256*1024; size /= 2 {
		if l.SetWriteBuffer(size) == nil {
			break
		}
	}
	if P2P_DSCP > 0 {
		note_dscp(l.SetDSCP(P2P_DSCP))
	}
}

// will try to connect with given endpoint
// will block until the connection dies or is killed
func connect_with_endpoint(endpoint string, sync_node bool) {

	defer globals.Recover(2)

	remote_ip, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		logger.V(3).Error(err, "Resolve address failed:", "endpoint", endpoint)
		return
	}

	if IsAddressInBanList(ParseIPNoError(remote_ip.IP.String())) {
		logger.V(2).Info("Connecting to banned IP is prohibited", "IP", remote_ip.IP.String())
		return
	}

	// check whether are already connected to this address if yes, return
	if ip := ParseIPNoError(remote_ip.String()); !never_ban(ip) && stuck_held(ip, time.Now()) { // stuck_peer.go
		logger.V(2).Info("not redialling a peer evicted as stuck", "ip", remote_ip.String())
		return
	}

	if IsAddressConnected(ParseIPNoError(remote_ip.String())) {
		logger.V(4).Info("outgoing address is already connected", "ip", remote_ip.String())
		return //nil, fmt.Errorf("Already connected")
	}

	if shouldwebackoff(ParseIPNoError(remote_ip.String())) {
		logger.V(1).Info("backing off from this connection", "ip", remote_ip.String())
		return
	} else {
		backoff_mutex.Lock()
		backoff[ParseIPNoError(remote_ip.String())] = time.Now().Unix() + 10
		backoff_mutex.Unlock()
	}

	var masterkey = pbkdf2.Key(globals.Config.Network_ID.Bytes(), globals.Config.Network_ID.Bytes(), 1024, 32, sha1.New)
	var blockcipher, _ = kcp.NewAESBlockCrypt(masterkey)

	var conn *kcp.UDPSession

	// since we may be connecting through socks, grab the remote ip for our purpose rightnow
	//conn, err := globals.Dialer.Dial("tcp", remote_ip.String())
	if globals.Arguments["--socks-proxy"] == nil {
		conn, err = kcp.DialWithOptions(remote_ip.String(), blockcipher, 10, 3)
	} else { // we must move through a socks 5 UDP ASSOCIATE supporting proxy, ssh implementation is partial
		err = fmt.Errorf("socks proxying is not supported")
		logger.V(0).Error(err, "Not suported", "server", globals.Arguments["--socks-proxy"])
		return
		/*uri, err := url.Parse("socks5://" + globals.Arguments["--socks-proxy"].(string)) // "socks5://demo:demo@192.168.99.100:1080"
		if err != nil {
			logger.V(0).Error(err, "Error parsing socks proxy", "server", globals.Arguments["--socks-proxy"])
			return
		}
		_ = uri
		sserver := uri.Host
		if uri.Port() != "" {

			host, _, err := net.SplitHostPort(uri.Host)
			if err != nil {
				logger.V(0).Error(err, "Error parsing socks proxy", "server", globals.Arguments["--socks-proxy"])
				return
			}
			sserver = host  + ":"+ uri.Port()
		}

		fmt.Printf("sserver %s   host %s port %s\n", sserver, uri.Host, uri.Port())
		username := ""
		password := ""
		if uri.User != nil {
			username = uri.User.Username()
			password,_ = uri.User.Password()
		}
		tcpTimeout := 10
		udpTimeout := 10
		c, err := socks5.NewClient(sserver, username, password, tcpTimeout, udpTimeout)
		if err != nil {
			logger.V(0).Error(err, "Error connecting to socks proxy", "server", globals.Arguments["--socks-proxy"])
			return
		}
		udpconn, err := c.Dial("udp", remote_ip.String())
		if err != nil {
			logger.V(0).Error(err, "Error connecting to remote host using socks proxy", "socks", globals.Arguments["--socks-proxy"],"remote",remote_ip.String())
			return
		}
		conn,err = kcp.NewConn(remote_ip.String(),blockcipher,10,3,udpconn)
		*/
	}

	if err != nil {
		logger.V(3).Error(err, "Dial failed", "endpoint", endpoint)
		Peer_SetFail(ParseIPNoError(remote_ip.String())) // update peer list as we see
		if conn != nil {
			conn.Close()
		}
		return //nil, fmt.Errorf("Dial failed err %s", err.Error())
	}

	tunekcp(conn) // set tunings for low latency

	// TODO we need to choose fastest cipher here ( so both clients/servers are not loaded)
	conntls := tls.Client(conn, p2p_tls_client_config())
	process_outgoing_connection(conn, conntls, remote_ip, false, sync_node)

}

// maintains a persistant connection to endpoint
// if connection drops, tries again after 4 secs
func maintain_outgoing_priority_connection(endpoint string, sync_node bool) {
	delay := time.NewTicker(4 * time.Second)
	for {
		select {
		case <-Exit_Event:
			return
		case <-delay.C:
		}
		connect_with_endpoint(endpoint, sync_node)
	}
}

// this will maintain connection to 1 seed node randomly
func maintain_seed_node_connection() {

	delay := time.NewTicker(2 * time.Second)

	for {
		select {
		case <-Exit_Event:
			return
		case <-delay.C:
		}
		endpoint := ""
		if globals.IsMainnet() { // choose mainnet seed node
			r, _ := rand.Int(rand.Reader, big.NewInt(10240))
			endpoint = config.Mainnet_seed_nodes[r.Int64()%int64(len(config.Mainnet_seed_nodes))]
		} else { // choose testnet peer node
			r, _ := rand.Int(rand.Reader, big.NewInt(10240))
			endpoint = config.Testnet_seed_nodes[r.Int64()%int64(len(config.Testnet_seed_nodes))]
		}
		if seed_should_dial(endpoint, time.Now()) { // a seed that failed its recent handshakes waits out its back-off
			connect_with_endpoint(endpoint, sync_node)
			//connect_with_endpoint(endpoint, true) // seed nodes always have sync mode
		}
	}
}

// keep building connections to network, we are talking outgoing connections
func maintain_connection_to_peers() {

	// check how many connections are active
	if _, ok := globals.Arguments["--min-peers"]; ok && globals.Arguments["--min-peers"] != nil { // user specified a limit, use it if possible
		i, err := strconv.ParseInt(globals.Arguments["--min-peers"].(string), 10, 64)
		if err != nil {
			logger.Error(err, "Error Parsing --min-peers")
		} else {
			if i <= 1 {
				logger.Error(fmt.Errorf("--min-peers should be positive and more than 1"), "")
			} else {
				Min_Peers = i
			}
		}
		logger.Info("Min peers", "min-peers", Min_Peers)
	}

	if _, ok := globals.Arguments["--max-peers"]; ok && globals.Arguments["--max-peers"] != nil { // user specified a limit, use it if possible
		i, err := strconv.ParseInt(globals.Arguments["--max-peers"].(string), 10, 64)
		if err != nil {
			logger.Error(err, "Error Parsing --max-peers")
		} else {
			if i < Min_Peers {
				logger.Error(fmt.Errorf("--max-peers should be positive and more than --min-peers"), "")
			} else {
				Max_Peers = i
			}
		}
		logger.Info("Max peers", "max-peers", Max_Peers)
	}

	delay := time.NewTicker(200 * time.Millisecond)

	// Upstream writes peers.json / ban_list.json only from P2P_Shutdown(), so any exit that is
	// not a clean SIGINT — SIGKILL, OOM, power loss, a duplicate instance losing its port binds —
	// discards every peer the node learned since startup and it cold-starts from the seed list.
	// Snapshot both lists periodically so a hard kill costs at most one interval of peer knowledge.
	// Two small JSON writes; the mutexes taken here are the same ones shutdown already uses.
	persist := time.NewTicker(5 * time.Minute)

	for {
		select {
		case <-Exit_Event:
			return
		case <-persist.C:
			save_peer_list()
			save_ban_list()
			save_v2_offences()
			save_first_relay()
			continue
		case <-delay.C:
		}

		// check number of connections, if limit is reached, trigger new connections if we have peers
		// if we have more do nothing
		_, out := Peer_Direction_Count()
		if out >= uint64(Min_Peers) { // we already have required number of peers, donot connect to more peers
			continue
		}

		peer := find_peer_to_connect(1)
		if peer != nil && !IsAddressConnected(ParseIPNoError(peer.Address)) {
			note_dial(peer.Address, time.Now()) // in-flight dials count against their netgroup (diversity.go)
			go connect_with_endpoint(peer.Address, false)
		}
	}
}

// P2P_BIND_DEFAULT is where the p2p server listens when --p2p-bind is absent: every interface, a random port at each
// start (r28: named so derod's help text can be checked against it; a router forward needs an explicit --p2p-bind).
const P2P_BIND_DEFAULT = "0.0.0.0:0"

// the shared pre-TLS accept budget of every unknown inbound session (upstream literals, named in r28 so the documented
// "~10/s all unknown inbound" of rft §7 B30 is checked against them: harness/intel/config_truth.py)
const INBOUND_ACCEPT_RATE = 10.0
const INBOUND_ACCEPT_BURST = 40

func P2P_Server_v2() {

	var accept_limiter = rate.NewLimiter(INBOUND_ACCEPT_RATE, INBOUND_ACCEPT_BURST) // 10 incoming per sec, burst of 40 is okay

	default_address := P2P_BIND_DEFAULT // be default choose a random port
	if _, ok := globals.Arguments["--p2p-bind"]; ok && globals.Arguments["--p2p-bind"] != nil {
		addr, err := net.ResolveTCPAddr("tcp", globals.Arguments["--p2p-bind"].(string))
		if err != nil {
			logger.Error(err, "--p2p-bind address is invalid")
		} else {
			if addr.Port == 0 {
				logger.Info("P2P server is disabled, No ports will be opened for P2P activity")
				return
			} else {
				default_address = addr.String()
				P2P_Port = addr.Port
			}
		}
	}

	srv := rpc2.NewServer()
	srv.OnConnect(func(c *rpc2.Client) {
		remote_addr_interface, _ := c.State.Get("addr")
		remote_addr := remote_addr_interface.(net.Addr)

		conn_interface, _ := c.State.Get("conn")
		conn := conn_interface.(net.Conn)

		tlsconn_interface, _ := c.State.Get("tlsconn")
		tlsconn := tlsconn_interface.(net.Conn)

		connection := &Connection{Client: c, Conn: conn, ConnTls: tlsconn, Addr: remote_addr, Incoming: true} // State starts at its zero value, HANDSHAKE_PENDING
		// serve_inbound's codec counters (traffic.go)
		connection.traffic = traffic_of(c.State)
		connection.logger = logger.WithName("incoming").WithName(remote_addr.String())

		in, out := Peer_Direction_Count()

		if int64(in+out) > Max_Peers { // do not allow incoming ddos
			connection.exit()
			return
		}

		c.State.Set("c", connection) // set pointer to connection

		//connection.logger.Info("connected  OnConnect")
		go func() {
			time.Sleep(2 * time.Second)
			connection.dispatch_test_handshake()
		}()

	})

	set_handlers(srv)

	tlsconfig := p2p_tls_server_config(generate_random_tls_cert())
	//l, err := tls.Listen("tcp", default_address, tlsconfig) // listen as TLS server

	_ = tlsconfig

	var masterkey = pbkdf2.Key(globals.Config.Network_ID.Bytes(), globals.Config.Network_ID.Bytes(), 1024, 32, sha1.New)
	var blockcipher, _ = kcp.NewAESBlockCrypt(masterkey)

	// listen to incoming tcp connections tls style
	l, err := kcp.ListenWithOptions(default_address, blockcipher, 10, 3)
	if err != nil {
		logger.Error(err, "Could not listen", "address", default_address)
		return
	}
	defer l.Close()
	tune_listener(l)

	_, P2P_Port_str, _ := net.SplitHostPort(l.Addr().String())
	P2P_Port, _ = strconv.Atoi(P2P_Port_str)

	logger.Info("P2P is listening", "address", l.Addr().String())
	start_nat(P2P_Port) // --p2p-nat: ask the gateway to forward this UDP port (netlayers.go)

	// A common pattern is to start a loop to continously accept connections
	for {
		conn, err := l.AcceptKCP() //accept connections using Listener.Accept()
		if err != nil {
			select {
			case <-Exit_Event:
				l.Close() // p2p is shutting down, close the listening socket
				return
			default:
			}
			logger.V(1).Error(err, "Err while accepting incoming connection")
			continue
		}

		accept_inbound(srv, conn, tlsconfig, accept_limiter)
	}

}

// accept_inbound runs the accept loop's checks for one fresh session and starts serving it; false = refused and
// closed. Factored out of P2P_Server_v2 so a test drives the production path (security SEC-2).
func accept_inbound(srv *rpc2.Server, conn *kcp.UDPSession, tlsconfig *tls.Config, limiter *rate.Limiter) bool {
	raddr := conn.RemoteAddr().(*net.UDPAddr)
	if is_public(raddr.IP) { // reachability evidence: counted before any refusal, as upstream counted it
		atomic.AddUint64(&public_inbound_opens, 1)
	}

	if !admit_inbound(ParseIPNoError(raddr.IP.String()), limiter) {
		conn.Close()
		return false
	}

	backoff_mutex.Lock()
	backoff[ParseIPNoError(raddr.String())] = time.Now().Unix() + globals.Global_Random.Int63n(200) // random backing of upto 200 secs
	backoff_mutex.Unlock()

	logger.V(3).Info("accepting incoming connection", "raddr", raddr.String())

	if IsAddressConnected(ParseIPNoError(raddr.String())) {
		logger.V(4).Info("incoming address is already connected", "ip", raddr.String())
		conn.Close()
		return false // upstream closed the socket and then still started serving it
	}

	go serve_inbound(srv, conn, tlsconfig, raddr)
	return true
}

// admit_inbound decides whether a freshly accepted session may proceed.
//
// r19: a banned IP is refused before it can spend an accept token. Upstream asked the limiter (10/s, burst 40) first,
// so a banned flooder above 10 sessions/s kept the shared bucket empty and honest inbound peers were dropped at
// random; the ban-list check (a scan of the exact and CIDR entries, IsAddressInBanList) costs no token.
//
// r20 (r19 SEC-2 next step + SEC-3 optional item): before the shared bucket, two per-netgroup checks (IPv4 /16, IPv6
// /32, the buckets of the r18 outbound cap; non-public addresses and seed/priority/exclusive nodes are exempt):
//   - a netgroup already holding inbound_group_cap(g) handshaken inbound peers is refused, so one operator's
//     address block cannot fill our inbound slots (eclipse) once UDP 11011 is forwarded;
//   - each netgroup has its own small accept bucket (INBOUND_GROUP_RATE/s, burst INBOUND_GROUP_BURST), so one
//     prefix flooding sessions cannot drain the shared 10/s bucket that honest peers from everywhere else need.
//
// Neither check touches the shared bucket when it refuses.
func admit_inbound(ip string, limiter *rate.Limiter) bool {
	if IsAddressInBanList(ip) {
		logger.V(2).Info("Incoming IP is banned, disconnecting now", "IP", ip)
		return false
	}
	if atomic.LoadInt32(&agg_active) != 0 && inbound_aggregate_banned(ip, time.Now()) { // r23c: several identities of this /24 or /48 were score-banned
		agg_refusals_total.Inc()
		return false
	}
	if g := inbound_group(ip); g != "" {
		if inbound_group_count(g) >= inbound_group_cap(g) {
			atomic.AddUint64(&inbound_group_refusals, 1)
			logger.V(2).Info("Incoming netgroup already holds its inbound share", "IP", ip, "netgroup", g)
			return false
		}
		if !inbound_group_limiters.allow(g) {
			if proven_lane_allow(ip, time.Now()) { // r24 (B30): a returning peer is not starved by forged neighbours
				return true
			}
			atomic.AddUint64(&inbound_group_refusals, 1)
			return false
		}
	}
	if limiter.Allow() { // if rate limiter allows, then only add else drop the connection
		return true
	}
	return proven_lane_allow(ip, time.Now()) // r24 (B30): the shared bucket was drained (proven_lane.go)
}

const MAX_INBOUND_PER_NETGROUP = 4      // floor of the handshaken inbound peers per IPv4 /16 (see inbound_group_cap)
const INBOUND_GROUP_RATE = 1.0          // accepted sessions per second per netgroup ...
const INBOUND_GROUP_BURST = 8           // ... with this burst (a peer reconnecting a few times never notices)
const INBOUND_GROUP_LIMITERS_MAX = 4096 // the limiter map is reset when it grows past this (bounded memory)

// inbound_group_refusals counts sessions refused by the per-netgroup checks (InboundGroupRefusals, and /metrics
// p2p_inbound_netgroup_refusals_total).
var inbound_group_refusals uint64

var _ = metrics.Set.GetOrCreateGauge("p2p_inbound_netgroup_refusals_total", func() float64 {
	return float64(atomic.LoadUint64(&inbound_group_refusals))
})

var _ = metrics.Set.GetOrCreateGauge("p2p_inbound_handshake_failures_total", func() float64 { // r19 SEC-1 counter, unexported until r20
	return float64(atomic.LoadUint64(&inbound_handshake_failures))
})

func InboundGroupRefusals() uint64 { return atomic.LoadUint64(&inbound_group_refusals) }

// inbound_group_cap_env: DERO_P2P_INBOUND_PER_NETGROUP overrides the computed per-netgroup inbound cap (0 = computed).
var inbound_group_cap_env = env_int("DERO_P2P_INBOUND_PER_NETGROUP", 0, 0, 1<<16)

// inbound_group_cap is the inbound cap of netgroup g (r20 merge, SEC20-03 review: a fixed 4 per /16, and per IPv6
// /32 = a whole ISP or hoster allocation, could refuse honest peers in popular hosting ranges on a public node).
// It scales with inbound capacity, max(MAX_INBOUND_PER_NETGROUP, max_peers/10) (101 -> 10), an operator override
// replaces that, and an IPv6 /32 group gets twice the cap.
func inbound_group_cap(g string) int {
	return inbound_group_cap_for(g, Max_Peers, inbound_group_cap_env)
}

func inbound_group_cap_for(g string, max_peers int64, override int) int {
	c := MAX_INBOUND_PER_NETGROUP
	if s := int(max_peers / 10); s > c {
		c = s
	}
	if override > 0 {
		c = override
	}
	if strings.HasSuffix(g, "/32") {
		c *= 2
	}
	return c
}

// inbound_group is the netgroup of an inbound IP, "" when exempt (non-public, or a seed/priority/exclusive node).
func inbound_group(ip string) string {
	g := netgroup(ip)
	if g == "" || never_ban(ip) {
		return ""
	}
	return g
}

// inbound_group_count counts handshaken inbound connections in netgroup g.
func inbound_group_count(g string) (n int) {
	connection_map.Range(func(k, value interface{}) bool {
		if c := value.(*Connection); c.Incoming && netgroup(Address(c)) == g {
			n++
		}
		return true
	})
	return
}

type group_limiters struct {
	sync.Mutex
	m map[string]*rate.Limiter
}

var inbound_group_limiters = &group_limiters{m: map[string]*rate.Limiter{}}

func (l *group_limiters) allow(g string) bool {
	l.Lock()
	defer l.Unlock()
	lim, ok := l.m[g]
	if !ok {
		if len(l.m) >= INBOUND_GROUP_LIMITERS_MAX {
			l.m = map[string]*rate.Limiter{} // a spoofer rotating through prefixes only resets buckets to full
		}
		lim = rate.NewLimiter(INBOUND_GROUP_RATE, INBOUND_GROUP_BURST)
		l.m[g] = lim
	}
	return lim.Allow()
}

// INBOUND_TLS_HANDSHAKE_TIMEOUT bounds how long an accepted KCP session may stay before its TLS handshake completes.
//
// Why (r19, UDP reflection): KCP accepts a session from ONE datagram (kcp-go Listener.packetInput creates it for any
// unseen source address, and the AES key is derived from the public network id), and the TLS server answers a
// ClientHello carried in that datagram with its whole first flight. KCP then retransmits that unacknowledged flight
// (kcp-go marks a dead link after 20 sends but nothing acts on kcp.state), and upstream closed the session only when
// the codec's READ_TIMEOUT (20 s) fired. Measured on loopback (zz probe, --lowlatency profile): one spoofed 325-byte
// datagram drew 12,535 bytes over 18.9 s, x38.6, towards whatever address the attacker wrote as the source.
// An honest handshake already has to finish within 6 s: the server dispatches Peer.Handshake 2 s after connect with a
// 4 s context (rpc_handshake.go dispatch_test_handshake), and a reply after that ends the connection anyway.
var INBOUND_TLS_HANDSHAKE_TIMEOUT = 6 * time.Second

// serve_inbound completes the TLS handshake under a deadline, then serves the peer's RPCs exactly as before.
func serve_inbound(srv *rpc2.Server, conn *kcp.UDPSession, tlsconfig *tls.Config, raddr *net.UDPAddr) {
	defer globals.Recover(2)
	tunekcp(conn) // tuning paramters for local stack
	// Until the peer has proved it receives our packets, retransmit with the default profile's doubling RTO, not the
	// low-latency +50% one: 9 instead of 11 copies of the flight inside the deadline (zz probe). One-time cost to an
	// honest peer: the handshake is flushed every 40 ms instead of 10 ms.
	set_kcp_profile(conn, false)
	tlsconn := tls.Server(conn, tlsconfig)
	conn.SetDeadline(time.Now().Add(INBOUND_TLS_HANDSHAKE_TIMEOUT))
	if err := tlsconn.Handshake(); err != nil {
		atomic.AddUint64(&inbound_handshake_failures, 1)
		logger.V(3).Info("inbound TLS handshake failed", "raddr", raddr.String(), "error", err.Error())
		conn.Close() // stops KCP retransmitting our flight to an address that never answered
		return
	}
	conn.SetDeadline(time.Time{}) // the codec sets its own per-frame deadlines from here on
	set_kcp_profile(conn, P2PLowLatency)
	state := rpc2.NewState()
	state.Set("addr", raddr)
	state.Set("conn", conn)
	state.Set("tlsconn", tlsconn)
	codec, traffic := counted_codec(tlsconn, false)
	state.Set(TRAFFIC_STATE_KEY, traffic)
	srv.ServeCodecWithState(codec, state)
}

// inbound_handshake_failures counts accepted sessions closed because their TLS handshake failed or never completed.
var inbound_handshake_failures uint64

func handle_connection_panic(c *Connection) {
	defer globals.Recover(2)
	if r := recover(); r != nil {
		logger.V(2).Error(nil, "Recovered while handling connection", "r", r, "stack", string(debug.Stack()))
		c.exit()
	}
}

func set_handler(base interface{}, methodname string, handler interface{}) {
	switch o := base.(type) {
	case *rpc2.Client:
		o.Handle(methodname, handler)
		//fmt.Printf("setting client handler %s\n", methodname)
	case *rpc2.Server:
		o.Handle(methodname, handler)
		//fmt.Printf("setting server handler %s\n", methodname)
	default:
		panic(fmt.Sprintf("object cannot handle such handler %T", base))

	}
}

func getc(client *rpc2.Client) *Connection {
	if ci, found := client.State.Get("c"); found {
		return ci.(*Connection)
	} else {
		//panic("no connection attached") // automatically handled by higher layers
		return nil
	}
}

// we need the following RPCS to work
func set_handlers(o interface{}) {
	set_handler(o, "Peer.Handshake", func(client *rpc2.Client, args Handshake_Struct, reply *Handshake_Struct) error {
		return getc(client).Handshake(args, reply)
	})
	set_handler(o, "Peer.Chain", func(client *rpc2.Client, args Chain_Request_Struct, reply *Chain_Response_Struct) error {
		c := getc(client)
		return heavy(c, "Peer.Chain", func() error { return c.Chain(args, reply) })
	})
	set_handler(o, "Peer.ChangeSet", func(client *rpc2.Client, args ChangeList, reply *Changes) error {
		c := getc(client)
		return heavy(c, "Peer.ChangeSet", func() error { return c.ChangeSet(args, reply) })
	})
	set_handler(o, "Peer.NotifyINV", func(client *rpc2.Client, args ObjectList, reply *Dummy) error {
		return getc(client).NotifyINV(args, reply)
	})
	set_handler(o, "Peer.GetObject", func(client *rpc2.Client, args ObjectList, reply *Objects) error {
		c := getc(client)
		return heavy(c, "Peer.GetObject", func() error { return c.GetObject(args, reply) })
	})
	set_handler(o, "Peer.TreeSection", func(client *rpc2.Client, args Request_Tree_Section_Struct, reply *Response_Tree_Section_Struct) error {
		c := getc(client)
		return heavy(c, "Peer.TreeSection", func() error { return c.TreeSection(args, reply) })
	})
	set_handler(o, "Peer.NotifyMiniBlock", func(client *rpc2.Client, args Objects, reply *Dummy) error {
		return getc(client).NotifyMiniBlock(args, reply)
	})
	set_handler(o, "Peer.Ping", func(client *rpc2.Client, args Dummy, reply *Dummy) error {
		return getc(client).Ping(args, reply)
	})

}

func process_outgoing_connection(conn net.Conn, tlsconn net.Conn, remote_addr net.Addr, incoming, sync_node bool) {
	defer globals.Recover(0)

	codec, traffic := counted_codec(tlsconn, !incoming)
	client := rpc2.NewClientWithCodec(codec)

	c := &Connection{Client: client, Conn: conn, ConnTls: tlsconn, Addr: remote_addr, Incoming: incoming, SyncNode: sync_node, traffic: traffic} // State starts at HANDSHAKE_PENDING (zero)
	defer c.exit()
	c.logger = logger.WithName("outgoing").WithName(remote_addr.String())
	set_handlers(client)

	client.State = rpc2.NewState()
	client.State.Set("c", c)

	go func() {
		time.Sleep(2 * time.Second)
		c.dispatch_test_handshake()
	}()

	//	c.logger.V(4).Info("client running loop")
	client.Run() // see the original

	c.logger.V(4).Info("process_connection finished")
}

// shutdown the p2p component
func P2P_Shutdown() {
	close(Exit_Event) // send signal to all connections to exit
	save_peer_list()  // save peer list
	save_ban_list()   // save ban list
	save_v2_offences()
	save_first_relay()
	stop_nat() // delete the gateway port mapping (bounded wait)

	// TODO we  must wait for connections to kill themselves
	logger.Info("P2P Shutdown")
	atomic.AddUint32(&globals.Subsystem_Active, ^uint32(0)) // this decrement 1 fom subsystem

}

// generate default tls cert to encrypt everything
// NOTE: this does NOT protect from individual active man-in-the-middle attacks
func generate_random_tls_cert() tls.Certificate {

	/* RSA can do only 500 exchange per second, we need to be faster
	     * reference https://github.com/golang/go/issues/20058
	    key, err := rsa.GenerateKey(rand.Reader, 512) // current using minimum size
	if err != nil {
	    log.Fatal("Private key cannot be created.", err.Error())
	}

	// Generate a pem block with the private key
	keyPem := pem.EncodeToMemory(&pem.Block{
	    Type:  "RSA PRIVATE KEY",
	    Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	*/
	// EC256 does roughly 20000 exchanges per second
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		logger.Error(err, "Unable to marshal ECDSA private key")
		panic(err)
	}
	// Generate a pem block with the private key
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})

	tml := x509.Certificate{
		SerialNumber: random_cert_serial(),

		// TODO do we need to add more parameters to make our certificate more authentic
		// and thwart traffic identification as a mass scale
		/*
		   // you can add any attr that you need
		   NotBefore:    time.Now(),
		   NotAfter:     time.Now().AddDate(5, 0, 0),
		   // you have to generate a different serial number each execution

		   Subject: pkix.Name{
		       CommonName:   "New Name",
		       Organization: []string{"New Org."},
		   },
		   BasicConstraintsValid: true,   // even basic constraints are not required
		*/
	}
	cert, err := x509.CreateCertificate(rand.Reader, &tml, &tml, &key.PublicKey, key)
	if err != nil {
		logger.Error(err, "Certificate cannot be created.")
		panic(err)
	}

	// Generate a pem block with the certificate
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	tlsCert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		logger.Error(err, "Certificate cannot be loaded.")
		panic(err)
	}
	return tlsCert
}

func ParseIP(s string) (string, error) {
	ip, _, err := net.SplitHostPort(s)
	if err == nil {
		return ip, nil
	}

	ip2 := net.ParseIP(s)
	if ip2 == nil {
		return "", fmt.Errorf("invalid IP")
	}

	return ip2.String(), nil
}

func ParseIPNoError(s string) string {
	ip, _ := ParseIP(s)
	return ip
}

// random_cert_serial returns a positive 127-bit serial from crypto/rand (Round 23). The serial used to be
// peer_id XOR UnixNano: anyone who completed a TLS handshake (the peer id is sent right after it) could recover the
// process start time to the nanosecond, a stable fingerprint that links one node across IP changes and reconnects.
func random_cert_serial() *big.Int {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[0] &= 0x7f
	b[15] |= 1 // never zero
	return new(big.Int).SetBytes(b[:])
}
