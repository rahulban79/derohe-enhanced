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

// Getwork job validation (Round 21, security). The miner trusts whatever its daemon pushes, over a websocket whose
// TLS is not verified (minerDialer: InsecureSkipVerify), so a malicious or compromised node, or anyone on the path to
// a remote node, controls every job field.
//
//   - Crash: every consumer decodes the job with hex.Decode into a fixed [48]byte. hex.Decode writes len(src)/2 bytes
//     and PANICS when that exceeds the destination ("index out of range [48] with length 48", reproduced on go1.26).
//     mineblock, the GPU worker and the split feeder run without recover, so ONE job with a blob longer than 96 hex
//     characters killed the whole miner, and it reconnected into the same job. Now a job is checked once, in getwork,
//     before it is published; a bad one is counted and dropped (the previous job stays), and the three decode sites go
//     through decode_job_blob, which never panics.
//   - Memory: ReadJSON had no read limit (gorilla's default is unlimited), so one message could be as large as the
//     peer liked. A job is ~400 bytes of JSON; GETWORK_READ_LIMIT allows 64 KiB.
//   - Hashrate theft: a normal (non-final) miniblock pays the key hash at blob[16:32], which derod sets to this miner's
//     address (websocket_getwork_server.go: copy(mbl.KeyHash[:], t.address_sum[:])). A job that names another key
//     mines for someone else. Counted and logged by default (getwork proxies such as derohe-proxy hand every miner the
//     proxy's own key, so refusing would break them); DERO_MINER_STRICT_JOBS=1 refuses such jobs. Final miniblocks
//     carry the block header hash there and are not checked.

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/rpc"
)

// GETWORK_READ_LIMIT bounds one getwork message from the daemon (a job is ~400 bytes).
const GETWORK_READ_LIMIT = 64 << 10

// job_blob_hex_len is the hex length of a miniblock hashing blob.
const job_blob_hex_len = 2 * block.MINIBLOCK_SIZE

var jobs_rejected uint64    // jobs dropped by accept_job (dero_miner_jobs_rejected_total)
var jobs_foreign_key uint64 // non-final jobs whose key hash is not this miner's (dero_miner_jobs_foreign_key_total)
var own_key_hash [16]byte   // graviton.Sum(own public key)[:16], set once from --wallet-address
var own_key_hash_set int32  // 1 once own_key_hash is valid
var strict_jobs = os.Getenv("DERO_MINER_STRICT_JOBS") == "1"

// set_own_key_hash records the key hash this miner's jobs must name (sum = graviton.Sum(compressed public key)).
func set_own_key_hash(sum [32]byte) {
	copy(own_key_hash[:], sum[:16])
	atomic.StoreInt32(&own_key_hash_set, 1)
}

// decode_job_blob decodes a job's hashing blob into dst; false for anything that is not exactly 96 hex characters.
// Unlike a bare hex.Decode into a [48]byte it cannot panic on a longer blob.
func decode_job_blob(dst *[block.MINIBLOCK_SIZE]byte, s string) bool {
	if len(s) != job_blob_hex_len {
		return false
	}
	n, err := hex.Decode(dst[:], []byte(s))
	return err == nil && n == block.MINIBLOCK_SIZE
}

// job_verdict classifies a job: "" = mine it, anything else = the reason it is dropped. foreign reports a non-final
// job whose key hash is not own (checked only when own is non-nil); strict turns that into a rejection.
func job_verdict(j *rpc.GetBlockTemplate_Result, own *[16]byte, strict bool) (reason string, foreign bool) {
	var b [block.MINIBLOCK_SIZE]byte
	if !decode_job_blob(&b, j.Blockhashing_blob) {
		return "blob", false
	}
	if b[0]&0xf != 1 {
		return "version", false
	}
	d, ok := new(big.Int).SetString(j.Difficulty, 10)
	if !ok || d.Sign() <= 0 || d.BitLen() > 256 {
		return "difficulty", false
	}
	if own != nil && b[0]&0x20 == 0 && !bytes.Equal(b[16:32], own[:]) {
		foreign = true
		if strict {
			return "foreign_key", true
		}
	}
	return "", foreign
}

var job_log_mu sync.Mutex
var job_log_last = map[string]time.Time{}

// job_log_allowed rate-limits the job warnings to one per reason per minute (a bad node pushes every 500 ms).
func job_log_allowed(reason string, now time.Time) bool {
	job_log_mu.Lock()
	defer job_log_mu.Unlock()
	if t, ok := job_log_last[reason]; ok && now.Sub(t) < time.Minute {
		return false
	}
	job_log_last[reason] = now
	return true
}

// accept_job reports whether a job read from the daemon may replace the current one, counting and logging (rate
// limited) the ones it drops or flags. The blob is never logged: it is attacker-sized.
func accept_job(j *rpc.GetBlockTemplate_Result) bool {
	var own *[16]byte
	if atomic.LoadInt32(&own_key_hash_set) == 1 {
		own = &own_key_hash
	}
	reason, foreign := job_verdict(j, own, strict_jobs)
	if foreign {
		atomic.AddUint64(&jobs_foreign_key, 1)
	}
	if reason != "" {
		atomic.AddUint64(&jobs_rejected, 1)
		if job_log_allowed(reason, time.Now()) && logger.GetSink() != nil {
			logger.Error(fmt.Errorf("invalid job from daemon"), "job dropped, keeping the previous one", "reason", reason,
				"blob_len", len(j.Blockhashing_blob), "height", j.Height)
		}
		return false
	}
	if foreign && job_log_allowed("foreign_key", time.Now()) && logger.GetSink() != nil {
		logger.Error(nil, "the daemon's job pays a key hash that is not this wallet's (a getwork proxy does this; a hijacked node would too). Set DERO_MINER_STRICT_JOBS=1 to refuse such jobs", "height", j.Height)
	}
	return true
}

// ---- r22 (security): what a compromised daemon can still make the miner do with well-formed jobs -----------------
//
//   - Submit flood: the share target is the job's Difficulty, which the daemon chooses. A job with difficulty 1 makes
//     every hash a "share": at the live ~84k H/s that is ~84k submitShare calls per second (JSON encode, a websocket
//     write under connection_mutex that every mining thread contends on, a miniblock decode and hash for the share
//     ledger). Honest mainnet shares arrive at hashrate/difficulty: 84,000 / 21.6M ~ 0.004/s live, and below
//     1/s even at the mainnet minimum difficulty (config.go MAINNET_MINIMUM_DIFFICULTY 100000). On mainnet,
//     submissions now pass a token bucket of SUBMIT_RATE per second (burst SUBMIT_BURST); the excess is counted
//     (dero_miner_submits_throttled_total) and dropped before the JSON encoding and the websocket write (the
//     callers' hex formatting, mini counters and V(1) log line still run; r22 merge wording fix). --testnet (low difficulty by design) and
//     DERO_MINER_SUBMIT_RATE=0 turn it off; DERO_MINER_SUBMIT_RATE=<n> sets another rate.
//   - Log flood: take_job logged the job's LastError with logger.Error on every job (one per ~0.5-2 s), unbounded in
//     length up to GETWORK_READ_LIMIT (64 KiB): a hostile daemon could append ~64 KiB per job to the appending miner
//     log, and an honest node that has not yet seen the wallet's registration repeats the same line every job. A
//     LastError is now logged when it changes or once a minute, clipped to JOB_ERROR_LOG_MAX bytes.

const SUBMIT_RATE = 50
const SUBMIT_BURST = 200
const JOB_ERROR_LOG_MAX = 200

var submits_throttled uint64    // dero_miner_submits_throttled_total
var submit_bucket *rate.Limiter // nil: unlimited (testnet, DERO_MINER_SUBMIT_RATE=0)

// new_submit_limiter: the bucket for a mainnet (testnet=false) miner, env = DERO_MINER_SUBMIT_RATE ("" = default).
func new_submit_limiter(testnet bool, env string) *rate.Limiter {
	r := SUBMIT_RATE
	if env != "" {
		n, err := strconv.Atoi(env)
		if err != nil || n < 0 {
			n = SUBMIT_RATE
		}
		r = n
	} else if testnet {
		r = 0
	}
	if r == 0 {
		return nil
	}
	b := SUBMIT_BURST
	if r > b {
		b = r
	}
	return rate.NewLimiter(rate.Limit(r), b)
}

// submit_allowed reports whether one more share may be sent at now.
func submit_allowed(l *rate.Limiter, now time.Time) bool {
	if l == nil || l.AllowN(now, 1) {
		return true
	}
	atomic.AddUint64(&submits_throttled, 1)
	return false
}

var job_error_mu sync.Mutex
var job_error_last string
var job_error_at time.Time
var job_errors_logged uint64

// job_error_to_log returns the (clipped) LastError to log at now, or "" when it repeats the last logged one within a
// minute.
func job_error_to_log(lasterr string, now time.Time) string {
	if lasterr == "" {
		return ""
	}
	if len(lasterr) > JOB_ERROR_LOG_MAX {
		lasterr = lasterr[:JOB_ERROR_LOG_MAX] + "...(clipped)"
	}
	job_error_mu.Lock()
	defer job_error_mu.Unlock()
	if lasterr == job_error_last && now.Sub(job_error_at) < time.Minute {
		return ""
	}
	job_error_last, job_error_at = lasterr, now
	atomic.AddUint64(&job_errors_logged, 1)
	return lasterr
}
