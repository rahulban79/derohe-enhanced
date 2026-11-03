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

package main

// r23 (payouts): job latency as the miner sees it, and no fixed start-up stall.
//
//   - Every mining thread slept 5 s before its first hash, whatever the job's arrival time. The r22 run of
//     2026-10-30 01:29:50 averaged 20,330 H/s over its first 15 s against ~60k steady: about 10 s of mining lost per
//     start. Threads now start as soon as the first job is in (wait_first_job), still at most 5 s.
//   - dero_miner_jobs_received_total and dero_miner_job_template_age_seconds_{sum,count,max}: how old a job's template
//     is when it reaches the miner (receipt time minus the template timestamp the job id starts with; derod and the
//     miner share a clock on one box). A cached template (up to 100 ms, blockchain/miner_block.go) shows here.

import (
	"fmt"
	"io"
	"strconv"
	"sync/atomic"
	"time"
)

var jobs_received uint64
var job_age_us_sum, job_age_us_max, job_age_count uint64

// job_id_ms is the template timestamp in milliseconds a job id starts with ("<ms>.<n>.<tag>"), 0 when it has none.
func job_id_ms(id string) int64 {
	end := 0
	for end < len(id) && end < 19 && id[end] >= '0' && id[end] <= '9' {
		end++
	}
	v, err := strconv.ParseInt(id[:end], 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// note_job_received counts a taken job and its template age; ages that are negative (clock skew, remote daemon) or
// over a minute (not a timestamp) are counted as jobs but not as ages.
func note_job_received(id string, now time.Time) {
	atomic.AddUint64(&jobs_received, 1)
	ms := job_id_ms(id)
	if ms <= 0 {
		return
	}
	age := now.UnixNano()/1000 - ms*1000
	if age < 0 || age > 60e6 {
		return
	}
	atomic.AddUint64(&job_age_us_sum, uint64(age))
	atomic.AddUint64(&job_age_count, 1)
	for {
		m := atomic.LoadUint64(&job_age_us_max)
		if uint64(age) <= m || atomic.CompareAndSwapUint64(&job_age_us_max, m, uint64(age)) {
			break
		}
	}
}

// wait_first_job returns once *counter is non-zero (a job was taken) or after limit, polling every poll.
func wait_first_job(counter *int64, limit, poll time.Duration) time.Duration {
	t0 := time.Now()
	for atomic.LoadInt64(counter) == 0 && time.Since(t0) < limit {
		time.Sleep(poll)
	}
	return time.Since(t0)
}

func write_job_latency_metrics(w io.Writer) {
	fmt.Fprintf(w, "dero_miner_jobs_received_total %d\n", atomic.LoadUint64(&jobs_received))
	fmt.Fprintf(w, "dero_miner_job_template_age_seconds_sum %.6f\n", float64(atomic.LoadUint64(&job_age_us_sum))/1e6)
	fmt.Fprintf(w, "dero_miner_job_template_age_seconds_count %d\n", atomic.LoadUint64(&job_age_count))
	fmt.Fprintf(w, "dero_miner_job_template_age_seconds_max %.6f\n", float64(atomic.LoadUint64(&job_age_us_max))/1e6)
}
