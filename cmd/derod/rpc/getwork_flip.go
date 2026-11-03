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

// r23c (payouts): a live measure of the node's share of the normal->final flip delay.
//
// Once this node holds 9 normal miniblocks for the tips being mined (BLOCK_TIME - MINIBLOCK_HIGHDIFF), only FINAL work
// can still be paid at that height (blockchain/miner_block.go keeps the first 9). A normal job sent after that point
// is dead work. It happens when the 9th miniblock lands while Create_new_block_template_mining still serves its 100 ms
// cached template (refresh_due then resends at cache expiry). The cache lives in blockchain/ (a consensus package the
// guard keeps logging-only), so it is measured here, not changed:
//
//   getwork_dead_normal_jobs_total      normal jobs sent while the chain already held 9 normal miniblocks for them
//   getwork_final_flips_total           heights whose first final job this node sent
//   getwork_final_flip_delay_seconds    first dead normal job -> first final job at that height (dead normal time)
//
// ESTIMATE before a live read: the virtual-time model of the shipped dispatcher (job_dispatch_sim_test.go, "keepalive
// 2 s (shipped)") gives L9 (9th miniblock -> first final job) mean 10.4 ms, p90 21, p99 96; live 2026-11-01 there were
// 0.89 sends/s, so ~9 % of flips land in a fresh cache. 10 ms of a ~8.3 s regular phase is ~0.1 % of regular hashing.
// The counters verify or refute it; only a blockchain/ change could close the window.
// Nothing here is consensus-visible: it reads the miniblock pool and counts.
//
// r24 (getworkops, B39): the live read (2026-11-02, n=30, mean 61.2 ms) was compared with the simulated L9 mean
// (10.36 ms), but the two are not the same quantity. getwork_final_flip_delay_seconds is CONDITIONAL: it is booked
// only for the flips that had a dead window (30 of 238), and it starts at the first dead SEND. L9 is booked for EVERY
// flip and starts at the 9th miniblock. Computed the live way on the simulated trace, the shipped dispatcher gives a
// conditional mean of about 50 ms (r24_getworkops_test.go), and live sum/flips is 1.836 s / 238 = 7.7 ms per flip
// against 6.3 ms replayed (same definition). r24 verify: sum/flips is only a LOWER bound of L9 (it starts at the first
// dead send, and clean flips add 0), so it says nothing about L9 vs 10.36 ms; a shadow L9 read was 14.2 ms (n=130). getwork_final_flip_l9_seconds below is booked the L9 way (every first final job, from
// the dispatcher's first observation of the state it answers), so the next live read compares like with like.

import (
	"encoding/binary"
	"sync"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/metrics"
)

var getwork_dead_normal_jobs = metrics.Set.NewCounter("getwork_dead_normal_jobs_total")
var getwork_final_flips = metrics.Set.NewCounter("getwork_final_flips_total")
var getwork_final_flip_delay = metrics.Set.NewHistogram("getwork_final_flip_delay_seconds")

// r24: L9 as job_dispatch_sim_test.go defines it, one sample per first final job (n ~ flips, not ~ dead windows).
var getwork_final_flip_l9 = metrics.Set.NewHistogram("getwork_final_flip_l9_seconds")

// r24: dead windows longer than the template cache can explain (expiry at +101 ms, plus a build and a timer wake).
// The model never exceeds 104 ms (r24_getworkops_test.go); a shadow run (2026-11-02, nice 15 on a contended box) had
// 1 of 16 at 278-316 ms, the live r23c node 0 of 30 above 113.6 ms. This counts them so a live read can tell a
// scheduling stall from a dispatcher defect without a histogram walk.
var getwork_final_flip_slow = metrics.Set.NewCounter("getwork_final_flip_slow_total")

const FLIP_SLOW_MS = 150

func flip_is_slow(delay_ms int64) bool { return delay_ms > FLIP_SLOW_MS }

// normal_slots is how many normal miniblocks a block carries (9).
const normal_slots = int(config.BLOCK_TIME - config.MINIBLOCK_HIGHDIFF)

// held_normal counts the normal miniblocks the pool holds for a template's height and tips (the key
// Create_new_miner_block reads).
func held_normal(pool *block.MiniBlocksCollection, height uint64, tips []crypto.Hash) int {
	if pool == nil || len(tips) == 0 {
		return 0
	}
	var key block.MiniBlockKey
	key.Height = height
	key.Past0 = binary.BigEndian.Uint32(tips[0][:])
	if len(tips) == 2 {
		key.Past1 = binary.BigEndian.Uint32(tips[1][:])
	}
	n := 0
	for _, m := range pool.GetAllMiniBlocks(key) {
		if !m.Final {
			n++
		}
	}
	return n
}

// flip_watch follows one height's flip. dead_since is when the first dead normal job of height was sent (0: none open).
type flip_watch struct {
	mu          sync.Mutex
	height      uint64
	dead_since  int64
	dead_seen   int64  // r24: when the dispatcher first observed the state of the first dead job (its trigger)
	flip_height uint64 // the last height whose first final job was counted
}

// note books one CURRENT job (template height, final or not, normal miniblocks held for its tips) sent at now_ms.
// dead: a normal job that can no longer be paid. closed/delay_ms: this final job ends an open dead window.
// first_final: the first final job of this height.
// r24: trigger_ms is the time the dispatcher first observed the state this job answers (send_job's trigger; 0 for a
// keepalive or a connecting miner's first job, which answer no change). l9_ms is the L9 sample of a first final job:
// from the observation that opened its dead window (or, with no dead window, its own trigger) to now; -1 = none.
func (f *flip_watch) note(height uint64, final bool, held int, trigger_ms, now_ms int64) (dead, first_final, closed bool, delay_ms, l9_ms int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l9_ms = -1
	if f.dead_since != 0 && f.height != height { // the height ended while the window was open: nothing to close
		f.dead_since, f.dead_seen = 0, 0
	}
	if final {
		if f.flip_height != height {
			f.flip_height, first_final = height, true
			start := trigger_ms
			if f.dead_since != 0 {
				start = f.dead_seen
			}
			if start > 0 && start <= now_ms {
				l9_ms = now_ms - start
			}
		}
		if f.dead_since != 0 {
			closed, delay_ms = true, now_ms-f.dead_since
			if delay_ms < 0 {
				delay_ms = 0
			}
			f.dead_since, f.dead_seen = 0, 0
		}
		return
	}
	if held >= normal_slots {
		dead = true
		if f.dead_since == 0 {
			f.height, f.dead_since, f.dead_seen = height, now_ms, now_ms
			if trigger_ms > 0 && trigger_ms <= now_ms {
				f.dead_seen = trigger_ms
			}
		}
	}
	return
}

var flips flip_watch

// note_flip is send_job_to's hook (current jobs only).
func note_flip(pool *block.MiniBlocksCollection, bl *block.Block, final bool, trigger_ms, now_ms int64) {
	held := 0
	if !final {
		held = held_normal(pool, bl.Height, bl.Tips)
	}
	dead, first, closed, delay, l9 := flips.note(bl.Height, final, held, trigger_ms, now_ms)
	if dead {
		getwork_dead_normal_jobs.Inc()
	}
	if first {
		getwork_final_flips.Inc()
	}
	if closed {
		getwork_final_flip_delay.Update(float64(delay) / 1000)
		if flip_is_slow(delay) {
			getwork_final_flip_slow.Inc()
		}
	}
	if l9 >= 0 {
		getwork_final_flip_l9.Update(float64(l9) / 1000)
	}
}
