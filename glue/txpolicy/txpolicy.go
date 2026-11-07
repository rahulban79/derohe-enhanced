// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

// Package txpolicy is the node-local mempool admission policy of Round 24 (r24). It wraps the unchanged
// blockchain.Add_TX_To_Pool for every transaction that arrives by relay or by SendRawTransaction (glue/txcanon.Admit
// calls Admit; the r23 census test proves those are the only admission entry points). Blocks never pass through
// here: a block's transactions are verified by the unchanged consensus code, so nothing in this package can make
// this node reject a block the network accepts, or accept one it refuses. Which transaction is VALID is unchanged;
// this package only decides how much CPU and memory the node spends on transactions before and after they are valid.
//
// Three rules, each active only after Attach (derod calls it; tests and the simulator see upstream behaviour):
//
//  1. Shared verification of identical bytes (flight). Add_TX_To_Pool caches a positive verdict only AFTER the proofs
//     verify (transaction_verify.go:466), so N concurrent submissions of the same bytes verified N times: measured
//     6 copies = 454 ms CPU for one 75 ms ring-16 tx (r24 evidence txflow_base_ring16.txt, dup_concurrent). p2p
//     already collapsed concurrent RELAYS (p2p/tx_flow.go, r19); SendRawTransaction did not, and an RPC copy never
//     shared with a relayed copy. Now every admission of the same Keccak256(raw bytes) shares one Add_TX_To_Pool
//     call. A follower gets the leader's error, or ErrDuplicate when the leader's admission succeeded (before r24 a
//     follower that verified second got "rejected by pool by mempool": an error, never a second relay).
//  2. Known-invalid bytes (negative verdict cache). A transaction whose PROOF failed (Add_TX_To_Pool: "could not be
//     verified, err transaction statement N verification failed") fails again for the same bytes: the statement is
//     expanded from the balance snapshot of tx.BLID, and transaction_verify.go:336 refuses it unless that
//     snapshot's merkle root equals the Roothash inside the tx, so the inputs of Proof.Verify are fixed by the bytes.
//     Upstream re-verified every replay (~75 ms at ring 16, ~1 s at ring 128). The verdict is remembered by
//     Keccak256(raw) for NEG_TTL (NEG_MAX entries) and the same error text is returned, so p2p still scores the peer
//     exactly as before (p2p is_tx_verification_failure matches "could not be verified"). Only that one error class is
//     remembered; any other refusal (nonce, height, missing reference, pool) is re-evaluated every time.
//  3. Pool cap with fee-rate eviction. The mempool had no size bound: it only purges txs whose reference height falls
//     below the stable height (HouseKeeping, every 60 s), so its size was bounded by verification throughput alone.
//     When the pool's bytes plus the new tx exceed the cap, the new tx is admitted only if lower-paying txs (exact
//     fee/size, compared by cross multiplication, not the mempool's integer FeesPerByte) can be evicted to make room;
//     otherwise it is refused with ErrPoolFull BEFORE any proof is verified. The default cap, POOL_CAP_BLOCKS block
//     templates of transactions, is the most the pool can ever clear before HouseKeeping purges a tx: a tx built at
//     tip T has reference height ~T, HouseKeeping (blockchain.go:284, mempool.go:106) drops it once the stable height
//     (chain height - STABLE_LIMIT) reaches T, i.e. after at most STABLE_LIMIT more blocks, and each block takes at
//     most BLOCK_TX_CAPACITY bytes. So at the default a tx is refused only when at least that many better-paying
//     bytes are already waiting. Not scored against a relaying peer (honest peers relay low fees).
//
// r25 (secpool, B44): two holes in rule 3 closed.
//   - The cap was soft under concurrency: the gate counted only admitted bytes, so admissions still verifying were
//     invisible to each other. With the pool 3,000 B under a 30,000 B cap, six concurrent 3,000 B floor-fee txs all
//     passed the gate and none could evict anyone (equal rates), leaving 45,000 B (r24 verifier). Now a leader
//     RESERVES its bytes from the gate until it leaves (inflight); the gate and FeeToEnter count them.
//   - The fee-rate summary was reused for SUMMARY_TTL even when the set of mined txs had changed: right after a block
//     carried the pooled txs, a newcomer could be refused for up to 250 ms against bytes that were no longer
//     pending. The summary now also records WHICH mined set it was built from (the map RecentlyMined returns is
//     rebuilt only when the topoheight moves) and is rebuilt when that changes.

package txpolicy

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"reflect"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/deroproject/derohe/blockchain/mempool"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/transaction"
)

// BLOCK_TX_CAPACITY is the byte budget a block template fills with transactions (miner_block.go:247).
const BLOCK_TX_CAPACITY = config.STARGATE_HE_MAX_BLOCK_SIZE - 102400

// POOL_CAP_BLOCKS: block templates of transactions the pool may hold (config.STABLE_LIMIT blocks pass between
// admission and HouseKeeping's purge of a tx built at the tip).
const POOL_CAP_BLOCKS = uint64(config.STABLE_LIMIT)

// DEFAULT_POOL_CAP is the default byte cap (8 x 10,645,504 = 85,164,032 bytes).
const DEFAULT_POOL_CAP = POOL_CAP_BLOCKS * BLOCK_TX_CAPACITY

const NEG_MAX = 4096             // remembered invalid byte strings
const NEG_TTL = 10 * time.Minute // > the 11-block validity window; older txs are refused by the window anyway
const SUMMARY_TTL = 250 * time.Millisecond

var ErrPoolFull = errors.New("transaction refused: mempool full and its fee rate does not beat the lowest-paying transactions in it")
var ErrDuplicate = errors.New("transaction already admitted to the mempool by a concurrent submission of the same bytes")

var (
	m_shared      = metrics.Set.NewCounter("tx_policy_shared_admissions_total")
	m_neg_hit     = metrics.Set.NewCounter("tx_policy_known_invalid_total")
	m_pool_full   = metrics.Set.NewCounter("tx_policy_pool_full_refused_total")
	m_evicted     = metrics.Set.NewCounter("tx_policy_evicted_total")
	m_evicted_b   = metrics.Set.NewCounter("tx_policy_evicted_bytes_total")
	proof_failure = regexp.MustCompile(`could not be verified, err transaction statement \d+ verification failed`)
)

// Pool is what the policy needs from the mempool; *mempool.Mempool satisfies it.
type Pool interface {
	Mempool_List_TX_SortedInfo() []mempool.TX_Sorting_struct
	Mempool_Get_TX(txid crypto.Hash) *transaction.Transaction
	Mempool_Delete_TX(txid crypto.Hash) *transaction.Transaction
}

type entry struct {
	hash      crypto.Hash
	fee, size uint64
}

// less_rate: a pays strictly less per byte than b (exact: a.fee*b.size < b.fee*a.size, 128-bit products).
func less_rate(afee, asize, bfee, bsize uint64) bool {
	ah, al := bits.Mul64(afee, bsize)
	bh, bl := bits.Mul64(bfee, asize)
	return ah < bh || (ah == bh && al < bl)
}

type policy struct {
	sync.Mutex
	pool      Pool
	mined     func() map[crypto.Hash]bool // txids the recent blocks carry (nil: none known)
	protect   func() map[crypto.Hash]bool // r24 (verify-txpool): txids of block templates handed to miners
	cap       uint64
	now       func() time.Time
	sum_at    time.Time
	sum       []entry // the pool, lowest exact fee rate first
	sum_size  uint64
	sum_mined uintptr // r25 (B44): identity of the mined set the summary was built from (0: none)
	inflight  uint64  // r25 (B44): bytes reserved by admissions between the gate and leave

	flights map[crypto.Hash]*flight
	neg     map[crypto.Hash]neg_entry
	neg_q   []crypto.Hash // insertion order, for the NEG_MAX bound
}

type flight struct {
	done chan struct{}
	err  error
	size uint64 // r25 (B44): bytes this leader reserved in p.inflight
}

type neg_entry struct {
	err error
	at  time.Time
}

var p = &policy{now: time.Now}

// Attach turns the policy on for pool with a byte cap (0 = DEFAULT_POOL_CAP).
func Attach(pool Pool, cap uint64) {
	if cap == 0 {
		cap = DEFAULT_POOL_CAP
	}
	p.Lock()
	defer p.Unlock()
	p.pool, p.cap, p.sum, p.sum_size, p.sum_at = pool, cap, nil, 0, time.Time{}
	p.sum_mined, p.inflight = 0, 0
	p.flights = map[crypto.Hash]*flight{}
	p.neg = map[crypto.Hash]neg_entry{}
	p.neg_q = nil
}

// SetMinedSource names the txids the recent blocks already carry. They stay in the mempool until HouseKeeping (nothing
// removes a mined tx on block add) and the template never selects them again, so they neither count toward the cap
// nor serve as eviction victims (HouseKeeping drops them on its own; p2p compact-block reconstruction can still read
// them). derod passes cmd/derod/rpc.RecentlyMined.
func SetMinedSource(f func() map[crypto.Hash]bool) {
	p.Lock()
	defer p.Unlock()
	p.mined = f
	p.sum_at = time.Time{}
}

// SetProtectedSource names the txids carried by the block templates this node handed to miners (r24 verify-txpool).
// They are never evicted: Accept_new_block completes a submitted final miniblock by looking every template txid up in
// the mempool, regpool or block store (blockchain/miner_block.go:529-547), so evicting one of them makes the found
// block fail with "Tx not found in pool or DB". The template ranks by the integer FeesPerByte (every mainnet tx ranks
// 0, B19) while eviction ranks by exact fee rate, so the lowest exact payers are as likely as any to be in a
// template. They still count toward the cap. derod passes cmd/derod/rpc.TemplateTxs.
func SetProtectedSource(f func() map[crypto.Hash]bool) {
	p.Lock()
	defer p.Unlock()
	p.protect = f
}

// protected returns the current protected set (nil: none). Caller holds p.
func (p *policy) protected() map[crypto.Hash]bool {
	if p.protect == nil {
		return nil
	}
	return p.protect()
}

// Detach turns the policy off (Admit calls add directly, as before r24).
func Detach() {
	p.Lock()
	defer p.Unlock()
	p.pool = nil
}

// Status is a snapshot for RPC introspection.
type Status struct {
	Attached     bool   `json:"attached"`
	CapBytes     uint64 `json:"cap_bytes"`
	PoolBytes    uint64 `json:"pool_bytes"`
	PoolTxs      int    `json:"pool_txs"`
	Full         bool   `json:"full"`
	MinFeePerKB  uint64 `json:"min_fee_per_kb"` // exact fee*1024/size of the lowest-paying pool tx (0: empty)
	KnownInvalid int    `json:"known_invalid"`
}

// FeeToEnter is the smallest fee a tx of size bytes needs to pass the pool-full gate: 0 while the pool has room for
// it (or the policy is off), else one unit more than the highest rate among the lowest-paying txs it would have to
// evict, scaled to size (fee*v.size > v.fee*size for every victim v). MaxUint64: no fee is enough (the pool holds
// fewer evictable bytes than size).
func FeeToEnter(size uint64) uint64 {
	p.Lock()
	defer p.Unlock()
	if p.pool == nil {
		return 0
	}
	p.refresh(false)
	if p.sum_size+p.inflight+size <= p.cap { // r25 (B44): bytes still verifying count, as in gate
		return 0
	}
	need, got := p.sum_size+p.inflight+size-p.cap, uint64(0)
	var top entry
	prot := p.protected()
	for _, e := range p.sum {
		if got >= need {
			break
		}
		if prot[e.hash] { // r24 verify-txpool: never a victim (SetProtectedSource)
			continue
		}
		top, got = e, got+e.size
	}
	if got < need || top.size == 0 {
		return math.MaxUint64
	}
	hi, lo := bits.Mul64(top.fee, size)
	if hi >= top.size { // the quotient does not fit in 64 bits
		return math.MaxUint64
	}
	q, _ := bits.Div64(hi, lo, top.size)
	return q + 1
}

func Snapshot() (s Status) {
	p.Lock()
	defer p.Unlock()
	if p.pool == nil {
		return
	}
	p.refresh(false)
	s.Attached, s.CapBytes, s.PoolBytes, s.PoolTxs, s.KnownInvalid = true, p.cap, p.sum_size, len(p.sum), len(p.neg)
	s.Full = p.sum_size >= p.cap
	if len(p.sum) > 0 && p.sum[0].size > 0 {
		s.MinFeePerKB = p.sum[0].fee * 1024 / p.sum[0].size
	}
	return
}

// map_id is the identity of a map value (0 for nil): RecentlyMined returns the same map until the topoheight moves.
func map_id(m map[crypto.Hash]bool) uintptr {
	if m == nil {
		return 0
	}
	return reflect.ValueOf(m).Pointer()
}

// refresh rebuilds the fee-rate summary when it is older than SUMMARY_TTL, when the mined set changed since it was
// built (r25, B44), or when forced. Caller holds p.
func (p *policy) refresh(force bool) {
	var mined map[crypto.Hash]bool
	if p.mined != nil {
		mined = p.mined()
	}
	if !force && !p.sum_at.IsZero() && p.now().Sub(p.sum_at) < SUMMARY_TTL && map_id(mined) == p.sum_mined {
		return
	}
	listed := p.pool.Mempool_List_TX_SortedInfo()
	s := make([]entry, 0, len(listed))
	size := uint64(0)
	for _, l := range listed {
		if mined[l.Hash] { // already in a recent block: not pending (see SetMinedSource)
			continue
		}
		tx := p.pool.Mempool_Get_TX(l.Hash)
		if tx == nil { // left the pool since the listing
			continue
		}
		s = append(s, entry{hash: l.Hash, fee: tx.Fees(), size: l.Size})
		size += l.Size
	}
	sort.SliceStable(s, func(i, j int) bool { return less_rate(s[i].fee, s[i].size, s[j].fee, s[j].size) })
	p.sum, p.sum_size, p.sum_at, p.sum_mined = s, size, p.now(), map_id(mined)
}

// victims: the lowest-paying entries, each paying strictly less per byte than (fee, size), whose sizes add up to at
// least need bytes; ok is false when they do not. Entries in a template handed to miners are skipped (r24
// verify-txpool, SetProtectedSource). Caller holds p.
func (p *policy) victims(fee, size, need uint64) (v []entry, ok bool) {
	got := uint64(0)
	prot := p.protected()
	for _, e := range p.sum {
		if got >= need {
			break
		}
		if !less_rate(e.fee, e.size, fee, size) {
			break // sorted ascending: nobody after e pays less either
		}
		if prot[e.hash] {
			continue
		}
		v = append(v, e)
		got += e.size
	}
	return v, got >= need
}

func (p *policy) known_invalid(key crypto.Hash) (error, bool) {
	p.Lock()
	defer p.Unlock()
	e, ok := p.neg[key]
	if ok && p.now().Sub(e.at) > NEG_TTL {
		delete(p.neg, key)
		return nil, false
	}
	return e.err, ok
}

func (p *policy) remember_invalid(key crypto.Hash, err error) {
	p.Lock()
	defer p.Unlock()
	if _, ok := p.neg[key]; ok {
		return
	}
	for len(p.neg_q) >= NEG_MAX { // drop the oldest (it may already have expired and been deleted)
		delete(p.neg, p.neg_q[0])
		p.neg_q = p.neg_q[1:]
	}
	p.neg[key] = neg_entry{err: err, at: p.now()}
	p.neg_q = append(p.neg_q, key)
}

// gate decides, before verification, whether tx may be verified at all. Caller holds p.
func (p *policy) gate(fee, size uint64) error {
	p.refresh(false)
	if p.sum_size+p.inflight+size <= p.cap { // r25 (B44): admissions still verifying hold their bytes
		return nil
	}
	if _, ok := p.victims(fee, size, p.sum_size+p.inflight+size-p.cap); !ok {
		return ErrPoolFull
	}
	return nil
}

// make_room evicts lower-paying txs after txid (fee, size) was admitted, until the pool fits the cap again or no
// lower-paying tx is left. Caller holds p.
func (p *policy) make_room(txid crypto.Hash, fee, size uint64) {
	p.refresh(false)
	// account the new tx in the summary (a refresh after the add may already list it)
	present := false
	for _, e := range p.sum {
		if e.hash == txid {
			present = true
			break
		}
	}
	if !present {
		i := sort.Search(len(p.sum), func(i int) bool { return !less_rate(p.sum[i].fee, p.sum[i].size, fee, size) })
		p.sum = append(p.sum, entry{})
		copy(p.sum[i+1:], p.sum[i:])
		p.sum[i] = entry{hash: txid, fee: fee, size: size}
		p.sum_size += size
	}
	if p.sum_size <= p.cap {
		return
	}
	v, _ := p.victims(fee, size, p.sum_size-p.cap)
	gone := map[crypto.Hash]bool{}
	for _, e := range v {
		if e.hash == txid {
			continue
		}
		if p.pool.Mempool_Delete_TX(e.hash) != nil {
			m_evicted.Inc()
			m_evicted_b.Add(int(e.size))
		}
		gone[e.hash] = true // evicted now, or had already left the pool
	}
	kept := p.sum[:0]
	for _, e := range p.sum {
		if gone[e.hash] {
			p.sum_size -= e.size
			continue
		}
		kept = append(kept, e)
	}
	p.sum = kept
}

// txid_of is tx.GetHash (tests replace it: a forged transaction without proofs cannot be serialized).
var txid_of = func(tx *transaction.Transaction) crypto.Hash { return tx.GetHash() }

// enter is the locked part of Admit before verification: the flight of key if one is running, else the gate and a
// new flight. Every locked section is a function with a deferred Unlock, so a panic can never leave p locked (the
// RPC and p2p callers recover panics and would otherwise deadlock every later admission).
func (p *policy) enter(key crypto.Hash, fee, size uint64) (leader *flight, follow *flight, err error) {
	p.Lock()
	defer p.Unlock()
	if f, ok := p.flights[key]; ok {
		return nil, f, nil
	}
	if err = p.gate(fee, size); err != nil {
		return nil, nil, err
	}
	leader = &flight{done: make(chan struct{}), err: errFlightAborted, size: size}
	p.flights[key] = leader
	p.inflight += size // r25 (B44): reserved until leave
	return leader, nil, nil
}

func (p *policy) leave(key crypto.Hash) {
	p.Lock()
	defer p.Unlock()
	if f := p.flights[key]; f != nil {
		if f.size <= p.inflight { // r25 (B44); a re-Attach while this flight ran reset inflight to 0
			p.inflight -= f.size
		} else {
			p.inflight = 0
		}
	}
	delete(p.flights, key)
}

func (p *policy) admitted(txid crypto.Hash, fee, size uint64) {
	p.Lock()
	defer p.Unlock()
	if p.pool != nil {
		p.make_room(txid, fee, size)
	}
}

func (p *policy) attached() bool {
	p.Lock()
	defer p.Unlock()
	return p.pool != nil
}

// KnownInvalid returns the remembered refusal of raw when its proof already failed here (rule 2), before raw is even
// decoded (SendRawTransaction: a decode of a ring-16 tx costs ~2.6 ms of the ~46 ms a failing verification costs,
// r24 evidence r24_load_run2). nil when the policy is off or the bytes are not known to be invalid.
func KnownInvalid(raw []byte) error {
	if !p.attached() {
		return nil
	}
	if err, ok := p.known_invalid(crypto.Keccak256(raw)); ok {
		m_neg_hit.Inc()
		return err
	}
	return nil
}

// Admit runs add(tx) under the r24 policy (see the package comment). raw is the exact byte string received.
func Admit(raw []byte, tx *transaction.Transaction, add func(*transaction.Transaction) error) error {
	if !p.attached() || tx.IsRegistration() || tx.IsCoinbase() || tx.IsPremine() {
		return add(tx)
	}
	key := crypto.Keccak256(raw)
	if err, ok := p.known_invalid(key); ok {
		m_neg_hit.Inc()
		return err
	}
	size, fee := uint64(len(raw)), tx.Fees()
	f, follow, err := p.enter(key, fee, size)
	if err != nil {
		m_pool_full.Inc()
		return fmt.Errorf("%w (fee %d, size %d bytes)", err, fee, size)
	}
	if follow != nil { // the same bytes are being admitted right now: share that verdict
		<-follow.done
		m_shared.Inc()
		if follow.err == nil {
			return ErrDuplicate
		}
		return follow.err
	}
	defer func() {
		p.leave(key)
		close(f.done)
	}()

	err = add(tx)
	f.err = err
	if err != nil {
		if proof_failure.MatchString(err.Error()) {
			p.remember_invalid(key, err)
		}
		return err
	}
	p.admitted(txid_of(tx), fee, size)
	return nil
}

var errFlightAborted = errors.New("tx admission aborted")
