package main

// Paid vs accepted. derod counts a share "accepted" when its PoW is valid and the chain takes it (the getwork job's
// blocks/miniblocks/rejected counters, the miner's accepted_* fields). Whether it is PAID is only known once its height
// is stable: a block carries 9 normal miniblocks + 1 final, and a normal share that reaches the network after the 9th
// normal one at its height is accepted but never included (Round 17: 2 of the first 15 r16 shares, both CPU).
// derod resolves every accepted share in DERO.GetMiningOutcome (cmd/derod/rpc/mining_outcome.go) on its JSON-RPC port,
// which is not the getwork port. The miner polls it read-only, matches the `recent` rows to the hashes it submitted
// (so the CPU/GPU split of orphans is exact, and other miners on the same node are not counted as ours), and reports
// both. Nothing here changes what is mined or submitted, and no consensus-guarded package is touched.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/globals"
)

// the subset of cmd/derod/rpc.GetMiningOutcome_Result the miner reads (a local mirror: importing derod's rpc package
// would pull the blockchain into the miner)
type outcomeRow struct {
	Hash   string `json:"hash"`
	Height uint64 `json:"height"`
	Fate   string `json:"fate"`
	Reason string `json:"reason"`
}

type outcomeResult struct {
	Submitted    int            `json:"submitted"`
	Paid         int            `json:"paid"`
	Orphaned     map[string]int `json:"orphaned"`
	Pending      int            `json:"pending"`
	PaidFraction float64        `json:"paid_fraction"`
	Recent       []outcomeRow   `json:"recent"`
}

func (o outcomeResult) orphanedTotal() (n int) {
	for _, v := range o.Orphaned {
		n += v
	}
	return
}

const LEDGER_MAX = 4096 // same ring size as derod's FATE_RING

// shareLedger remembers which source found each submitted miniblock, by the hash derod records for it
// (block.MiniBlock.GetHash of the submitted bytes, as record_submission computes it).
type shareLedger struct {
	sync.Mutex
	src   map[string]byte   // hash -> 'C' | 'G'
	fate  map[string]string // hash -> paid | orphaned (absent: not resolved or not seen)
	order []string
}

var ledger = shareLedger{src: map[string]byte{}, fate: map[string]string{}}

func miniblockHash(blob []byte) (string, bool) {
	var mbl block.MiniBlock
	if err := mbl.Deserialize(blob); err != nil {
		return "", false
	}
	return mbl.GetHash().String(), true
}

func (l *shareLedger) add(blobHex string, source byte) {
	blob, err := hex.DecodeString(blobHex)
	if err != nil {
		return
	}
	h, ok := miniblockHash(blob)
	if !ok {
		return
	}
	l.Lock()
	defer l.Unlock()
	if _, dup := l.src[h]; dup {
		return
	}
	l.src[h] = source
	l.order = append(l.order, h)
	if len(l.order) > LEDGER_MAX {
		old := l.order[0]
		l.order = l.order[1:]
		delete(l.src, old)
		delete(l.fate, old)
	}
}

// apply takes derod's resolved rows; rows for hashes this miner did not submit (other miners on the node) are ignored.
func (l *shareLedger) apply(rows []outcomeRow) {
	l.Lock()
	defer l.Unlock()
	for _, r := range rows {
		if _, ours := l.src[r.Hash]; ours && (r.Fate == "paid" || r.Fate == "orphaned") {
			l.fate[r.Hash] = r.Fate
		}
	}
}

type sourceTally struct{ cpuPaid, cpuOrphaned, gpuPaid, gpuOrphaned, unresolved int }

func (l *shareLedger) tally() (t sourceTally) {
	l.Lock()
	defer l.Unlock()
	for h, s := range l.src {
		switch f := l.fate[h]; {
		case f == "paid" && s == 'G':
			t.gpuPaid++
		case f == "paid":
			t.cpuPaid++
		case f == "orphaned" && s == 'G':
			t.gpuOrphaned++
		case f == "orphaned":
			t.cpuOrphaned++
		default:
			t.unresolved++
		}
	}
	return
}

// outcomeAddress picks derod's JSON-RPC address. An explicit --node-rpc-address wins ("off" disables). Otherwise it is
// derived only for a loopback getwork daemon (same host, the network's default RPC port: 10102 mainnet): a public
// getwork node's RPC is not assumed, and its outcome would count every miner on it.
func outcomeAddress(flag interface{}, daemon string, rpcPort int) string {
	if s, ok := flag.(string); ok {
		if s == "off" {
			return ""
		}
		return s
	}
	host, _, err := net.SplitHostPort(daemon)
	if err != nil {
		return ""
	}
	if host == "localhost" || host == "::1" {
		return net.JoinHostPort(host, strconv.Itoa(rpcPort))
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return net.JoinHostPort(host, strconv.Itoa(rpcPort))
	}
	return ""
}

var outcomeClient = &http.Client{Timeout: 3 * time.Second}

func fetchOutcome(addr string) (r outcomeResult, err error) {
	req := []byte(`{"jsonrpc":"2.0","id":"1","method":"DERO.GetMiningOutcome"}`)
	resp, err := outcomeClient.Post("http://"+addr+"/json_rpc", "application/json", bytes.NewReader(req))
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var env struct {
		Result *outcomeResult `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err = json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&env); err != nil {
		return
	}
	if env.Error != nil {
		return r, fmt.Errorf("GetMiningOutcome: %s", env.Error.Message)
	}
	if env.Result == nil {
		return r, fmt.Errorf("GetMiningOutcome: empty result (derod older than r13?)")
	}
	return *env.Result, nil
}

var outcome_mu sync.Mutex
var outcome_last outcomeResult
var outcome_ok bool

func outcomeSnapshot() (outcomeResult, bool) {
	outcome_mu.Lock()
	defer outcome_mu.Unlock()
	return outcome_last, outcome_ok
}

// pollOutcome runs off the status goroutine so a slow or absent RPC never stalls the prompt or the hashing.
func pollOutcome(addr string, every time.Duration) {
	warned := false
	for {
		r, err := fetchOutcome(addr)
		if err != nil {
			if !warned { // once: the outcome fields are then simply absent
				logger.Info("paid/orphaned not available (derod JSON-RPC); set --node-rpc-address or =off", "addr", addr, "err", err.Error())
				warned = true
			}
		} else {
			ledger.apply(r.Recent)
			r.Recent = nil
			outcome_mu.Lock()
			outcome_last, outcome_ok = r, true
			outcome_mu.Unlock()
		}
		select {
		case <-Exit_In_Progress:
			return
		case <-time.After(every):
		}
	}
}

// ---- expectation (ARCHITECTURE 31.2): a block is 9 normal miniblocks at D + 1 final at 9D, 18·D network hashes per
// 18 s, i.e. 10 shares per 18·D hashes. A hash of ours is therefore worth 10/(18·D) = 5/(9·D) shares on average, and
// DERO/day = H·86400·R/(18·D) with R the full block reward (10 shares). D is the NORMAL difficulty (nw_from_job).

func expectedShares(hashes uint64, d uint64) float64 {
	if d == 0 {
		return 0
	}
	return float64(hashes) * 5 / (9 * float64(d))
}

// expectedSharesPhased (r23c payouts): the expectation from the hashes this miner actually did in each phase. A hash on
// a regular job wins a share with probability 1/D, a hash on a final job (difficulty 9D, MINIBLOCK_HIGHDIFF) with
// 1/(9D); both shares pay one miniblock reward. expectedShares assumes the network's 50/50 time split (5/(9 D) per
// hash), but the live r23b run (2026-11-01 09:18-09:57, dero_miner_phase_hashes_total) spent 54.2 % of its hashes on
// final jobs, so 5/(9 D) over-stated its expectation by 7.2 % and the "luck" it reported (0.78) was partly that bias.
// other: hashes the phase clock did not book (none once the first job is taken); they keep the 5/(9 D) rate.
func expectedSharesPhased(regular, final, other uint64, d uint64) float64 {
	if d == 0 {
		return 0
	}
	return (float64(regular)+float64(final)/float64(config.MINIBLOCK_HIGHDIFF))/float64(d) + expectedShares(other, d)
}

// phase_expect_window: the per-phase hash totals at the previous expectation update (status goroutine only). slack is
// how many hashes the phase clock has booked beyond the deltas handed to step so far: the clock can read the counter a
// moment after the caller did (a job taken in between), and those hashes then arrive in a later delta.
type phase_expect_window struct {
	last  [2]uint64
	slack uint64
}

// step returns the phase-exact expected shares for the hashes done since the previous call: delta is the miner's total
// hash count since then, now the phase clock's totals (phases.snapshot). Over any number of calls every hash is priced
// exactly once: at its phase's rate when the clock booked it, else (no job taken yet) at 5/(9 D).
func (w *phase_expect_window) step(delta uint64, now [2]uint64, d uint64) float64 {
	var ph [2]uint64
	for i := range ph {
		if now[i] >= w.last[i] { // the clock only adds; a smaller total books nothing
			ph[i] = now[i] - w.last[i]
		}
	}
	w.last = now
	var other uint64
	if have := w.slack + ph[0] + ph[1]; have >= delta {
		w.slack = have - delta
	} else {
		other, w.slack = delta-have, 0
	}
	return expectedSharesPhased(ph[0], ph[1], other, d)
}

var exp_window phase_expect_window

func expectedDEROPerDay(h float64, d uint64, blockReward uint64) float64 {
	if d == 0 {
		return 0
	}
	return h * 86400 * float64(blockReward) / (18 * float64(d)) / 100000 // atomic units -> DERO (5 decimals)
}

// run-level accumulators; only the status goroutine writes and reads them (it also calls logRewardStats)
var exp_shares float64
var run_hashes uint64
var run_seconds float64

// rewardOutcomeFields: the REWARD STATS fields that need derod's resolution or the run's expectation. accepted is
// what the miner's est_earned_DERO counts; paid is what the chain actually paid. Absent until the first poll succeeds.
func rewardOutcomeFields(perMB uint64, found uint64) (kv []interface{}) {
	if run_seconds > 0 && hash_rate > 0 {
		h := float64(run_hashes) / run_seconds
		kv = append(kv, "expected_DERO_per_day", fmt.Sprintf("%.2f", expectedDEROPerDay(h, hash_rate, 10*perMB)),
			"run_H/s", fmt.Sprintf("%.0f", h), "expected_shares", fmt.Sprintf("%.1f", exp_shares))
		if exp_shares > 0 {
			kv = append(kv, "luck", fmt.Sprintf("%.2f", float64(found)/exp_shares))
		}
		if _, ph := phases.snapshot(time.Now(), atomic.LoadUint64(&counter)); ph[0]+ph[1] > 0 { // r23c: the split behind it
			kv = append(kv, "final_hash_fraction", fmt.Sprintf("%.3f", float64(ph[1])/float64(ph[0]+ph[1])))
		}
	}
	o, ok := outcomeSnapshot()
	if !ok {
		return
	}
	t := ledger.tally()
	paid := uint64(t.cpuPaid + t.gpuPaid)
	kv = append(kv,
		"node_submitted", o.Submitted, "node_paid", o.Paid, "node_orphaned", o.orphanedTotal(), "node_pending", o.Pending,
		"paid_fraction", fmt.Sprintf("%.3f", o.PaidFraction),
		"paid_CPU", t.cpuPaid, "orphaned_CPU", t.cpuOrphaned, "paid_GPU", t.gpuPaid, "orphaned_GPU", t.gpuOrphaned,
		"unresolved", t.unresolved,
		"paid_DERO", globals.FormatMoney(paid*perMB)) // ours only, matched by hash
	return
}

// paid_string: the prompt's "Paid p/r" (paid of resolved), only once derod has answered.
func paid_string() string {
	if _, ok := outcomeSnapshot(); !ok {
		return ""
	}
	t := ledger.tally()
	p := t.cpuPaid + t.gpuPaid
	return fmt.Sprintf("Paid %d/%d ", p, p+t.cpuOrphaned+t.gpuOrphaned)
}
