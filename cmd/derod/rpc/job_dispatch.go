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

// r23 (payouts): one job dispatcher, driven by chain events, coalesced.
//
// Before, two independent paths sent jobs. Notify_MiniBlock_Addition ran SendJob on every new miniblock, and a 10 ms
// poll loop sent again when it saw the same miniblock count change, on a height change, at a template-refresh due
// time, and every 500 ms when nothing changed. Live r22 (2026-10-30, ~4,000 miner-connected seconds): 12,604 jobs,
// 3.1 per second, 1,452 of them template-refresh resends. Two costs:
//
//   - A height change (a block arrived) was seen only by the poll: 0-10 ms late.
//   - Every send after the 100 ms template cache expired built a new template (blockchain/miner_block.go
//     Create_new_block_template_mining). The 500 ms keepalive alone kept the cache "fresh" ~20% of the time, and a
//     miniblock that arrives while the cache is fresh is answered with the template from BEFORE it. When that
//     miniblock is the 9th normal one, the miner keeps hashing normal work that can no longer be paid until the
//     refresh resend at cache expiry (refresh_due). The duplicate poll send also scheduled a spurious refresh.
//
// Now every chain source only signals: a miniblock or block addition kicks the dispatcher, which sends
// at most one job per observed state change (height, miniblock count, event sequence). A refresh fires exactly at its
// due time instead of on the next 10 ms tick. When nothing changes, a job is resent only every keepalive interval
// (JOB_SEND_TIME_DELAY, default JOB_KEEPALIVE): an unchanged job is still valid work, and fewer template builds leave
// fewer stale-cache windows. The 10 ms poll stays as a fallback for a missed condition-variable wakeup.
//
// A block is added in two visible steps (the topo record, then chain.Tips), and a template built between them is for
// the height just finished. The old loop consumed the height change on that dead job and then often sent nothing
// better until its 500 ms resend: on a loopback testnet node (2026-10-30, interleaved runs) the time from a final
// share to the first job of the next height was 254 ms mean (p90 537 ms) before, 30 ms (p90 46 ms) with this
// dispatcher. Now send_job reports such a job as not current and the dispatcher retries 2, 4, 8 ... ms later (at most
// JOB_RETRY_MAX times), and the block-added event forces a send once the block is complete.
// Nothing here is consensus-visible: it only decides WHEN this node sends work to its own miners.

import (
	"sync/atomic"
	"time"

	"github.com/deroproject/derohe/metrics"
)

// JOB_KEEPALIVE is the resend interval of an unchanged job. The job stays valid until the chain moves (and every
// chain move is an event), so the resend only refreshes the template timestamp and the mempool selection.
const JOB_KEEPALIVE = 2 * time.Second

// JOB_POLL is the fallback poll period (as before): a sync.Cond Broadcast that finds no waiter is lost.
const JOB_POLL = 10 * time.Millisecond

// job_events counts block additions; it is part of the dispatch state, so each one forces a send. A miner connect
// does not bump it: onWebsocket sends that miner its first job directly (send_job_to with one target).
var job_events uint64

// job_kick wakes the dispatcher; one pending kick is enough because the dispatcher reads the current state.
var job_kick = make(chan struct{}, 1)

// getwork_session_count mirrors len(client_list) for the dispatcher (miners_count was only refreshed by CountMiners,
// i.e. by the console prompt or GetInfo, and read without a lock).
var getwork_session_count int64

func kick_jobs() {
	select {
	case job_kick <- struct{}{}:
	default:
	}
}

// note_job_event records an event that must produce a new job even if height and miniblock count are unchanged.
func note_job_event() {
	atomic.AddUint64(&job_events, 1)
	kick_jobs()
}

var dispatch_change = metrics.Set.NewCounter(`getwork_job_dispatch_total{reason="change"}`)
var dispatch_refresh = metrics.Set.NewCounter(`getwork_job_dispatch_total{reason="refresh"}`)
var dispatch_retry = metrics.Set.NewCounter(`getwork_job_dispatch_total{reason="retry"}`)
var dispatch_keepalive = metrics.Set.NewCounter(`getwork_job_dispatch_total{reason="keepalive"}`)

// dispatch_state is everything a miner's job depends on that the dispatcher can observe cheaply.
type dispatch_state struct {
	height int64
	minis  int
	events uint64
}

// dispatch_core is the decision part of the dispatcher, pure apart from the shared refresh-due word, so the policy is
// unit-tested and simulated without a chain.
type dispatch_core struct {
	keepalive_ms int64
	due          *int64 // template_refresh_due_ms (set by send_job, cleared here when it fires)
	last         dispatch_state
	primed       bool
	last_send_ms int64
	changed_ms   int64 // when the current state was first observed
	failed       bool  // the last send could not be current (no template, or a half-added block): retry
	retries      int   // retries since the last state change
}

// JOB_RETRY_WINDOW and JOB_RETRY_MAX bound the retries after a state change whose job could not be current: a block is
// half added for milliseconds (the block-added event follows), so a few retries 2, 4, 8 ... ms apart suffice; a node
// that cannot build templates at all (syncing) costs at most JOB_RETRY_MAX extra sends per change.
const JOB_RETRY_WINDOW = 1000 // ms
const JOB_RETRY_MAX = 6

// decide says whether to send a job now. trigger is the time handed to send_job for refresh_due: the moment the state
// changed (a template stamped at or before it may predate the change), or 0 for a keepalive (no change to miss).
func (d *dispatch_core) decide(st dispatch_state, now int64) (reason string, trigger int64) {
	if !d.primed || st != d.last {
		d.primed, d.last, d.changed_ms, d.retries = true, st, now, 0
		return "change", now
	}
	if d.failed && d.retries < JOB_RETRY_MAX && now-d.changed_ms < JOB_RETRY_WINDOW {
		d.retries++
		return "retry", d.changed_ms
	}
	if due := atomic.LoadInt64(d.due); due != 0 && now >= due && atomic.CompareAndSwapInt64(d.due, due, 0) {
		return "refresh", d.changed_ms
	}
	if now-d.last_send_ms >= d.keepalive_ms {
		return "keepalive", 0
	}
	return "", 0
}

// sent records a send at now; current is false when it could not be current and must be retried.
func (d *dispatch_core) sent(now int64, current bool) { d.last_send_ms, d.failed = now, !current }

// wait_ms is how long to sleep before looking again: the poll period, or less when a refresh or keepalive is due
// sooner. Never below 1 ms, so a due time that cannot fire (lost CAS) cannot spin.
func (d *dispatch_core) wait_ms(now, poll int64) int64 {
	w := poll
	if d.failed && d.retries < JOB_RETRY_MAX { // a block is half added for milliseconds: look again soon, backing off
		if rw := int64(2) << uint(d.retries); rw < w {
			w = rw
		}
	}
	if due := atomic.LoadInt64(d.due); due != 0 && due-now < w {
		w = due - now
	}
	if t := d.last_send_ms + d.keepalive_ms - now; t < w {
		w = t
	}
	if w < 1 {
		w = 1
	}
	return w
}

// job_keepalive_ms reads JOB_SEND_TIME_DELAY (a Go duration, as before; values under 40 ms are ignored).
func job_keepalive_ms(env string) int64 {
	if d, err := time.ParseDuration(env); err == nil && d >= 40*time.Millisecond {
		return d.Milliseconds()
	}
	return JOB_KEEPALIVE.Milliseconds()
}

// run_job_dispatcher is the dispatch loop. Every dependency is a parameter so tests drive it with fakes.
func run_job_dispatcher(d *dispatch_core, poll int64, active func() bool, state func() dispatch_state, now func() int64,
	send func(trigger int64) bool, kick <-chan struct{}, quit <-chan struct{}) {
	timer := time.NewTimer(time.Duration(poll) * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-quit:
			return
		case <-kick:
		case <-timer.C:
		}
		if active() {
			if reason, trigger := d.decide(state(), now()); reason != "" {
				ok := send(trigger)
				d.sent(now(), ok)
				switch reason {
				case "change":
					dispatch_change.Inc()
				case "retry":
					dispatch_retry.Inc()
				case "refresh":
					dispatch_refresh.Inc()
					// r18 counter kept for continuity (harness/intel/log_intel.py reads it)
					metrics.Set.GetOrCreateCounter("getwork_template_refresh_resends_total").Inc()
				default:
					dispatch_keepalive.Inc()
				}
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(time.Duration(d.wait_ms(now(), poll)) * time.Millisecond)
	}
}
