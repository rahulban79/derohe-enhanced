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

// Getwork job ordering (Round 23, rpcws; merged onto the payouts dispatcher in job_dispatch.go).
//
// Each job is written to every miner from one goroutine per miner, and jobs can be sent close together: a change
// followed by a retry 2 ms later, a template refresh, or a connecting miner's first job (send_job_to with one target)
// racing a broadcast. Two such writes can reach a miner in either order. When they carry different templates the
// OLDER one could land last, and the miner kept hashing it until the next send. The worst case is the 9th normal
// miniblock: the newer job is FINAL work (the only work that can still be paid at that height) and the older one is
// NORMAL work that can no longer be paid.
//
// Templates are fetched under sendjob_mu and numbered in that order (job_seq), so a larger number never carries an
// older template (Create_new_block_template_mining returns the cached template or a newer one). deliver_job writes a
// job to a miner only when no larger number went to that miner already, under a per-session lock, so the last job a
// miner receives is always the newest one sent to it. Skipped writes are counted in getwork_jobs_superseded_total.
//
// Nothing here is consensus-visible: it changes when and to whom derod writes jobs, never what a job contains.

import (
	"sync"
	"time"

	"github.com/deroproject/derohe/metrics"
	"github.com/lesismal/nbio/nbhttp/websocket"
)

var sendjob_mu sync.Mutex // orders template fetches with the job numbers handed out
var job_seq uint64        // last job number handed out (under sendjob_mu); 0 = none

var getwork_jobs_superseded = metrics.Set.NewCounter("getwork_jobs_superseded_total")
var getwork_first_jobs = metrics.Set.NewCounter("getwork_first_jobs_total")

// JOB_WRITE_DEADLINE: an nbio write deadline closes the connection when it fires with data still buffered (a slow or
// stuck miner is evicted); a completed write clears it.
const JOB_WRITE_DEADLINE = 100 * time.Millisecond

type job_writer interface {
	SetWriteDeadline(t time.Time) error
	WriteMessage(messageType websocket.MessageType, data []byte) error
}

// next_job_seq numbers one template fetch; fetch runs under sendjob_mu so numbers follow template age. ok=false when
// fetch failed (no number is used).
func next_job_seq(fetch func() bool) (seq uint64, ok bool) {
	sendjob_mu.Lock()
	defer sendjob_mu.Unlock()
	if !fetch() {
		return 0, false
	}
	job_seq++
	return job_seq, true
}

// deliver_job writes msg to w unless this session already got job seq or a newer one. sent=false, err=nil: superseded.
func deliver_job(sess *user_session, w job_writer, seq uint64, msg []byte) (sent bool, err error) {
	sess.send_mu.Lock()
	defer sess.send_mu.Unlock()
	if seq <= sess.sent_seq {
		getwork_jobs_superseded.Inc()
		return false, nil
	}
	sess.sent_seq = seq
	w.SetWriteDeadline(time.Now().Add(JOB_WRITE_DEADLINE))
	if err = w.WriteMessage(websocket.TextMessage, msg); err != nil {
		return false, err
	}
	return true, nil
}
