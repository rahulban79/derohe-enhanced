//go:build !wasm
// +build !wasm

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

// this file needs  serious improvements but have extremely limited time
/* this file handles communication with the daemon
 * this includes receiving output information
 *
 * *
 */
//import "io"
//import "os"
//import "fmt"

//import "net/url"
import (
	"strings"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/deroproject/derohe/glue/rwc"
	"github.com/gorilla/websocket"
)

// there should be no global variables, so multiple wallets can run at the same time with different assset

type Client struct {
	WS  *websocket.Conn
	RPC *jrpc2.Client
}

var rpc_client = &Client{}

// drop_rpc_client closes the current daemon connection, if any, and clears it (r23). Connect used to dial a new
// websocket over the old one without closing it, and a connection whose handshake calls failed (DERO.Echo/GetInfo
// error, mainnet/testnet mismatch) stayed open and installed, so IsDaemonOnline kept answering true and every 5 s
// retry of Keep_Connectivity leaked one more socket and jrpc2 client goroutine. The socket is closed BEFORE the jrpc2
// client: rwc's Close only ends the current write, and jrpc2's Close waits for its reader goroutine, which sits in a
// websocket read until the peer sends or the socket closes. Keep_Connectivity's old ping-failure path called
// RPC.Close() with the socket still open, so a daemon that was slow but connected (or a half-open TCP connection) froze
// the connectivity loop inside Close and the wallet never reconnected.
func drop_rpc_client() {
	rpc_client_mu.Lock()
	r, ws := rpc_client.RPC, rpc_client.WS
	rpc_client.RPC, rpc_client.WS = nil, nil
	rpc_client_mu.Unlock()
	// r23 merge: no client means offline. Callers gated only on Connected (xswd's DERO.* proxy) would otherwise
	// dereference the cleared client while Connect redials.
	Connected = false
	if ws != nil { // first: jrpc2's Close waits for its reader, which only returns once the socket is closed
		ws.Close()
	}
	if r != nil {
		r.Close()
	}
}

// this is as simple as it gets
// single threaded communication to get the daemon status and height
// this will tell whether the wallet can connection successfully to  daemon or not
func Connect(endpoint string) (err error) {

	var daemon_uri string
	var ws *websocket.Conn
	drop_rpc_client() // r23: never dial over a live or half-open connection

	// Take globals arg configured daemon if endpoint param is not defined
	if endpoint == "" {
		Daemon_Endpoint_Active = get_daemon_address()
	} else {
		Daemon_Endpoint_Active = endpoint
	}

	logger.V(1).Info("Daemon endpoint ", "address", Daemon_Endpoint_Active)

	// Trim off http, https, wss, ws to get endpoint to use for connecting
	if strings.HasPrefix(Daemon_Endpoint_Active, "https") {
		ld := strings.TrimPrefix(strings.ToLower(Daemon_Endpoint_Active), "https://")
		daemon_uri = "wss://" + ld + "/ws"

		ws, _, err = websocket.DefaultDialer.Dial(daemon_uri, nil)
	} else if strings.HasPrefix(Daemon_Endpoint_Active, "http") {
		ld := strings.TrimPrefix(strings.ToLower(Daemon_Endpoint_Active), "http://")
		daemon_uri = "ws://" + ld + "/ws"

		ws, _, err = websocket.DefaultDialer.Dial(daemon_uri, nil)
	} else if strings.HasPrefix(Daemon_Endpoint_Active, "wss") {
		ld := strings.TrimPrefix(strings.ToLower(Daemon_Endpoint_Active), "wss://")
		daemon_uri = "wss://" + ld + "/ws"

		ws, _, err = websocket.DefaultDialer.Dial(daemon_uri, nil)
	} else if strings.HasPrefix(Daemon_Endpoint_Active, "ws") {
		ld := strings.TrimPrefix(strings.ToLower(Daemon_Endpoint_Active), "ws://")
		daemon_uri = "ws://" + ld + "/ws"

		ws, _, err = websocket.DefaultDialer.Dial(daemon_uri, nil)
	} else {
		daemon_uri = "ws://" + Daemon_Endpoint_Active + "/ws"

		ws, _, err = websocket.DefaultDialer.Dial(daemon_uri, nil)
	}

	// notify user of any state change
	// if daemon connection breaks or comes live again
	if err == nil {
		if !Connected {
			logger.V(1).Info("Connection to RPC server successful", "address", daemon_uri)
			Connected = true
		}
	} else {

		if Connected {
			logger.V(1).Error(err, "Connection to RPC server Failed", "endpoint", daemon_uri)
		}
		Connected = false
		return
	}

	input_output := rwc.New(ws)
	rpc_client_mu.Lock()
	rpc_client.WS = ws
	rpc_client.RPC = jrpc2.NewClient(channel.RawJSON(input_output, input_output), &jrpc2.ClientOptions{OnNotify: Notify_broadcaster})
	rpc_client_mu.Unlock()

	if err = test_connectivity(); err != nil {
		Connected = false
		drop_rpc_client() // r23: a connection that failed its handshake calls is not left installed (or open)
		return err
	}
	return nil
}

func GetRPCClient() *Client {
	return rpc_client
}
