// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
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

// Bounded outgoing calls and bounded concurrent heavy requests.
//
// Outgoing: rpc2's Client.Call is CallWithContext(context.Background()), so a peer that keeps answering pings but
// never answers one request left our goroutine (and the decoded request) waiting for the life of the connection,
// and the LastObjectRequestTime watchdog meant for that is written but never read (discovery p2p-security-05).
//
// Incoming: rpc2 runs every request on its own goroutine with no limit, and GetObject, ChangeSet, TreeSection and
// Chain do expensive work for a cheap request (discovery p2p-security-01). Cap them per connection and globally;
// beyond the cap answer "busy" at once instead of queueing, and score it lightly.

import "context"
import "errors"
import "fmt"
import "time"

import "github.com/deroproject/derohe/metrics"

// per-method timeouts; bootstrap calls get the longest (a slow peer was measured at 38 s per tree-section chunk)
var CALL_TIMEOUTS = map[string]time.Duration{
	"Peer.NotifyINV":       10 * time.Second,
	"Peer.NotifyMiniBlock": 10 * time.Second,
	"Peer.GetObject":       30 * time.Second,
	"Peer.Chain":           60 * time.Second,
	"Peer.ChangeSet":       120 * time.Second,
	"Peer.TreeSection":     120 * time.Second,
}

const DEFAULT_CALL_TIMEOUT = 60 * time.Second

var NOTIFICATIONS = map[string]bool{"Peer.NotifyINV": true, "Peer.NotifyMiniBlock": true}

func call_timeout(method string) time.Duration {
	if d, ok := CALL_TIMEOUTS[method]; ok {
		return d
	}
	return DEFAULT_CALL_TIMEOUT
}

// call is Client.Call with a deadline. A timeout is counted and scored; what to do with the connection stays with
// the caller, exactly as for any other error.
func (c *Connection) call(method string, args interface{}, reply interface{}) error {
	return c.call_timeout(method, call_timeout(method), args, reply)
}

// call_timeout is call with an explicit deadline (pipelined bootstrap requests: bootstrap_pipeline.go)
func (c *Connection) call_timeout(method string, timeout time.Duration, args interface{}, reply interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := c.Client.CallWithContext(ctx, method, args, reply)
	if errors.Is(err, context.DeadlineExceeded) {
		metrics.Set.GetOrCreateCounter(fmt.Sprintf(`p2p_call_timeouts_total{method="%s"}`, method)).Inc()
		// a notification's reply waits for the peer to fetch and VALIDATE what we announced (its NotifyINV handler
		// calls GetObject back and adds the block before answering): slowness there is not misbehaviour, and the
		// timeouts of one block's chunk INVs arrive together. Score only fetches, where a missing answer is the peer's.
		if !NOTIFICATIONS[method] {
			c.penalize("timeout")
		}
		return fmt.Errorf("%s: no answer within %s: %w", method, timeout, err)
	}
	return err
}

const MAX_HEAVY_PER_CONNECTION = 8 // concurrent GetObject/ChangeSet/TreeSection/Chain handlers one peer may run
const MAX_HEAVY_GLOBAL = 64        // across all peers

var heavy_global = make(chan struct{}, MAX_HEAVY_GLOBAL)

var ErrBusy = errors.New("busy: too many concurrent requests, retry later")

// acquire_heavy takes a slot for a heavy handler without waiting; release with the returned func. own_cap reports
// which limit refused: this peer's own (its fault) or the global one (other peers' load, not its fault).
func (c *Connection) acquire_heavy() (release func(), ok bool, own_cap bool) {
	c.heavy_once.Do(func() { c.heavy = make(chan struct{}, MAX_HEAVY_PER_CONNECTION) })
	select {
	case c.heavy <- struct{}{}:
	default:
		return nil, false, true
	}
	select {
	case heavy_global <- struct{}{}:
	default:
		<-c.heavy
		return nil, false, false
	}
	return func() { <-heavy_global; <-c.heavy }, true, false
}

var ErrNoConnection = errors.New("connection not ready")

// heavy wraps a heavy handler with the caps. It runs BEFORE the handler's own `defer handle_connection_panic(c)`, and
// rpc2's request goroutine has no recover, so it must not dereference a nil connection: getc() returns nil until the
// OnConnect callback has attached it, and never attaches it when the node is full (review 2026-10-22: upstream's
// direct call survived this only because the handler's first statement recovers).
func heavy(c *Connection, method string, f func() error) error {
	if c == nil {
		return ErrNoConnection
	}
	release, ok, own := c.acquire_heavy()
	if !ok {
		metrics.Set.GetOrCreateCounter(fmt.Sprintf(`p2p_busy_rejections_total{method="%s"}`, method)).Inc()
		if own { // only this peer's own excess is its fault; a full global pool is everyone's load
			c.penalize("busy")
		}
		return ErrBusy
	}
	defer release()
	return f()
}
