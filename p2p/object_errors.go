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

// Classifying a failed Peer.GetObject call. None of this changes what the node accepts or
// computes; it decides only how loudly a failure is logged and whether one failed transaction
// fetch is worth the whole connection.
//
// Evidence (harness/runtime/derod_console_20261021.log, triaged by harness/miners/mine_triage.py):
//   - rpc2 hands a remote handler's error back verbatim as rpc2.ServerError, so text such as
//     "Invalid Major Version in Block" or "open /root/daemon2/.../bltx_store/...: no such file"
//     was produced on the peer, about the peer's own disk, and is not a fault of this node.
//   - "closed pipe" means the connection was already torn down under the call; on an outgoing
//     KCP session only our own Close fires the session's die channel.
//   - NotifyINV used to c.exit() on any failure, so a peer that lost one mempool entry cost the
//     whole connection plus every other call pending on it (one miss at 19:25:43 produced two
//     extra closed-pipe errors).

import "errors"
import "fmt"
import "io"
import "strings"

import "github.com/cenkalti/rpc2"
import "github.com/go-logr/logr"

import "github.com/deroproject/derohe/glue/txcanon"
import "github.com/deroproject/derohe/metrics"
import "github.com/deroproject/derohe/transaction"

type call_failure int

const (
	call_failure_other  call_failure = iota // anything else, logged as before
	call_failure_remote                     // the peer answered with its own error
	call_failure_closed                     // the connection was already closed under the call
)

func (k call_failure) String() string {
	switch k {
	case call_failure_remote:
		return "remote"
	case call_failure_closed:
		return "closed"
	}
	return "other"
}

// classify_call_error decides which side a GetObject failure belongs to.
func classify_call_error(err error) call_failure {
	if err == nil {
		return call_failure_other
	}
	var server_err rpc2.ServerError
	if errors.As(err, &server_err) {
		return call_failure_remote
	}
	if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, rpc2.ErrShutdown) {
		return call_failure_closed
	}
	// Read_Data_Frame formats the underlying error with %s, which drops the chain; and kcp-go
	// wraps io.ErrClosedPipe with pkg/errors, so match the text as a fallback
	if strings.Contains(err.Error(), "closed pipe") {
		return call_failure_closed
	}
	return call_failure_other
}

// log_call_failure logs a failed call at a level that matches whose problem it is.
// Remote and closed failures become V(1) INFO: kept in the file log (default level -1, globals.go) and off
// the console (default level 0). Everything else stays an ERROR. (go-logr's Error ignores V, so the old
// V(2).Error always printed; V(2).Info would have dropped these from both logs.)
func log_call_failure(logger logr.Logger, err error, msg string, keysAndValues ...interface{}) call_failure {
	kind := classify_call_error(err)
	switch kind {
	case call_failure_remote:
		logger.V(1).Info(msg+": peer could not serve the object", append([]interface{}{"peer_error", err.Error()}, keysAndValues...)...)
	case call_failure_closed:
		logger.V(1).Info(msg+": connection closed during the call", append([]interface{}{"error", err.Error()}, keysAndValues...)...)
	default:
		logger.V(2).Error(err, msg, keysAndValues...)
	}
	return kind
}

// is_tx_only is true when an object request asks for transactions and nothing else.
func is_tx_only(need ObjectList) bool {
	return len(need.Tx_list) > 0 && len(need.Block_list) == 0 && len(need.Chunk_list) == 0
}

// MAX_TX_FETCH_FAILURES bounds how many consecutive transaction fetches a peer may fail before
// the connection is dropped after all; a peer that keeps announcing what it cannot serve is
// wasting round trips, a peer that lost one mempool entry is not.
const MAX_TX_FETCH_FAILURES = 8

// keep_after_tx_fetch_failure records one failed transaction-only fetch and reports whether the
// connection should be kept.
func (c *Connection) keep_after_tx_fetch_failure() bool {
	metrics.Set.GetOrCreateCounter("p2p_tx_fetch_failures_total").Inc()
	keep := c.tx_fetch_failures.Add(1) < MAX_TX_FETCH_FAILURES
	if !keep {
		metrics.Set.GetOrCreateCounter("p2p_tx_fetch_budget_drops_total").Inc()
	}
	return keep
}

func (c *Connection) tx_fetch_succeeded() {
	c.tx_fetch_failures.Store(0)
}

// note_tx_fetch_reply scores a successful reply to a transaction-only fetch that asked for `asked` distinct txids and
// got `delivered` of them, and reports whether the connection should be kept. Only a complete reply resets the
// failure budget; a peer cannot earn it back with an empty reply.
//
// r22 (security): a reply that leaves out asked-for txs now also counts as a failed fetch. An honest GetObject
// answers every asked txid or returns an error (rpc_object_request.go: the first missing tx returns err), so a
// successful short reply never comes from an honest peer. Upstream neither counted nor penalised it: a peer could
// announce thousands of random txids per INV and answer every GetObject with nothing, forever.
func (c *Connection) note_tx_fetch_reply(need ObjectList, delivered, asked int) bool {
	if !is_tx_only(need) {
		return true
	}
	if delivered > 0 && delivered >= asked {
		c.tx_fetch_succeeded()
		return true
	}
	tx_fetch_short_replies.Inc()
	return c.keep_after_tx_fetch_failure()
}

// deserialize_tx decodes a peer's transaction bytes, turning a decoder panic into an error (r19).
//
// transaction.Deserialize panics on an unknown transaction type ("unknown transaction type", transaction.go; found by
// FuzzChainDecoders from the 5-byte input 01 30 30 30 30). Every p2p caller runs under a recover, so the node never
// crashed, but the panic skipped the caller's error branch: the peer was dropped through handle_connection_panic
// without its penalty (rpc_notifications.go scores "undecodable" only on the error path) and a stack trace was logged.
// The decoder itself is consensus code and stays as it is; what is accepted is unchanged (a panicking tx never was).
func deserialize_tx(tx *transaction.Transaction, buf []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("transaction could not be decoded: %v", r)
		}
	}()
	return tx.Deserialize(buf)
}

// decode_block_tx decodes a transaction that arrived inside a block (sync and chunk/notify paths). It does NOT observe
// the bytes: at this point the block is unvalidated peer input (no PoW checked), so counting here would let any peer
// raise block_tx_roundtrip_broken_total with a garbage block and cost a second decode before the PoW check (r23 merge).
func decode_block_tx(tx *transaction.Transaction, buf []byte) error { return deserialize_tx(tx, buf) }

// observe_block_txs feeds the txs of a block this node has just ACCEPTED (Add_Complete_Block ok) to txcanon.Observe
// (Round 23): a counter only, never a refusal. A block is accepted once, so a block relayed by several peers is
// counted once. raws[j] are the received bytes of txs[j].
func observe_block_txs(raws [][]byte, txs []*transaction.Transaction) {
	for j := range txs {
		if j >= len(raws) || txs[j] == nil {
			break
		}
		if err := txcanon.Observe(raws[j], txs[j]); err != nil {
			logger.V(1).Info("accepted block tx does not survive re-serialization (counted only)", "txid", txs[j].GetHash().String(), "err", err.Error())
		}
	}
}
