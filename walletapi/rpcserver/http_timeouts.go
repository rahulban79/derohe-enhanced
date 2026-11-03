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

package rpcserver

// Wallet HTTP server timeouts (r20, RPCWS-13).
//
// The wallet RPC server and XSWD were plain http.Server{Addr, Handler}: no header timeout and no idle timeout, so a
// client that opens connections and sends a header byte at a time (slowloris) holds a goroutine and a socket each
// for ever. derod's RPC got ReadHeaderTimeout/IdleTimeout in r19 (cmd/derod/rpc/ws_hardening.go); this applies the
// same limits to both wallet servers.
//
// Only the header phase and idle keep-alive connections are limited. There is deliberately no ReadTimeout or
// WriteTimeout: after the headers net/http clears the read deadline, so long-lived websocket sessions (/ws, /xswd)
// and slow Transfer calls are unaffected.

import (
	"net/http"
	"time"
)

// WALLET_READ_HEADER_TIMEOUT is how long a client may take to send its request headers.
const WALLET_READ_HEADER_TIMEOUT = 10 * time.Second

// WALLET_IDLE_TIMEOUT closes keep-alive HTTP connections that sit idle between requests.
const WALLET_IDLE_TIMEOUT = 120 * time.Second

// WALLET_MAX_HEADER_BYTES bounds request headers (net/http's default is 1 MiB).
const WALLET_MAX_HEADER_BYTES = 64 << 10

var wallet_read_header_timeout = WALLET_READ_HEADER_TIMEOUT // tests shorten it

// NewWalletHTTPServer is the http.Server for a wallet-side listener (wallet RPC, XSWD).
func NewWalletHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: h,
		ReadHeaderTimeout: wallet_read_header_timeout,
		IdleTimeout:       WALLET_IDLE_TIMEOUT,
		MaxHeaderBytes:    WALLET_MAX_HEADER_BYTES}
}
