package rpc

// DERO.GetSupplyAudit — an independent, one-sided supply sanity check (Round 18).
//
// GetInfo's total_supply is blockchain.CalcSupply(height): the emission formula, not a count of coins, so it prints
// the same number on a chain inflated through the disclosed range-proof defect (ARCHITECTURE.md §25.4). Account
// balances are ElGamal ciphertexts under different keys and cannot be summed by a node. The only DERO a node can
// count in plaintext is what smart contracts hold: each SC tree stores its DERO balance under the zero-hash key
// (the same read GetSC does). So: sum of plaintext SC-held DERO must never exceed formula supply. A violation is
// PROOF of inflation; passing proves nothing about coins that stay in encrypted accounts. The per-SC list lets an
// operator alert on sudden jumps of the largest holders (where laundered value would surface in DeFi contracts).

import "context"
import "encoding/binary"
import "fmt"
import "sort"
import "time"

import "github.com/deroproject/derohe/blockchain"
import "github.com/deroproject/derohe/config"
import "github.com/deroproject/derohe/cryptography/crypto"
import "github.com/deroproject/graviton"

type SupplyAudit_SC struct {
	SCID    string `json:"scid"`
	Balance uint64 `json:"balance"` // atomic units (1 DERO = 100000)
}

type GetSupplyAudit_Result struct {
	Height         int64            `json:"height"`
	TopoHeight     int64            `json:"topoheight"`
	FormulaSupply  uint64           `json:"formula_supply"` // atomic units, what GetInfo reports (÷100000)
	SCCount        int              `json:"sc_count"`
	SCHeld         uint64           `json:"sc_held"` // atomic units, plaintext DERO inside all SCs
	SCHeldOverflow bool             `json:"sc_held_overflow"`
	SCHeldPPM      uint64           `json:"sc_held_ppm"` // sc_held / formula_supply, parts per million
	Verdict        string           `json:"verdict"`
	Limit          string           `json:"limit"`
	Top            []SupplyAudit_SC `json:"top"`
	Status         string           `json:"status"`

	// r19: Cached = served from the per-tip cache (no walk); ComputeMs = how long the walk that produced it took
	Cached    bool  `json:"cached"`
	ComputeMs int64 `json:"compute_ms"`
}

// audit_sc_balances sums the plaintext DERO balance of every SC listed in the meta tree of ss.
func audit_sc_balances(ss *graviton.Snapshot, top_n int) (count int, total uint64, overflow bool, top []SupplyAudit_SC, err error) {
	return audit_sc_balances_ctx(context.Background(), ss, top_n)
}

// audit_sc_balances_ctx stops (with ctx.Err()) once the caller has gone away.
func audit_sc_balances_ctx(ctx context.Context, ss *graviton.Snapshot, top_n int) (count int, total uint64, overflow bool, top []SupplyAudit_SC, err error) {
	meta, err := ss.GetTree(config.SC_META)
	if err != nil {
		return
	}
	var zerohash crypto.Hash
	c := meta.Cursor()
	for k, _, e := c.First(); e == nil; k, _, e = c.Next() {
		if count&1023 == 0 && ctx.Err() != nil {
			err = ctx.Err()
			return
		}
		if len(k) != 32 {
			continue
		}
		t, e2 := ss.GetTree(string(k))
		if e2 != nil {
			continue
		}
		count++
		b, e3 := t.Get(zerohash[:])
		if e3 != nil || len(b) != 8 {
			continue
		}
		v := binary.BigEndian.Uint64(b)
		if total+v < total {
			overflow = true
		}
		total += v
		top = append(top, SupplyAudit_SC{SCID: fmt.Sprintf("%x", k), Balance: v})
	}
	sort.Slice(top, func(i, j int) bool { return top[i].Balance > top[j].Balance })
	if len(top) > top_n {
		top = top[:top_n]
	}
	return
}

func supply_verdict(sc_held, formula uint64, overflow bool) string {
	if overflow || sc_held > formula {
		return "VIOLATION: plaintext DERO held by smart contracts exceeds the emission-formula supply — inflation is proven"
	}
	return "consistent (one-sided: cannot detect inflation that stays in encrypted accounts)"
}

// Cost control (r19 merge of forensics F5, security SEC-7 and features F1). The audit opens every SC tree: 50,425 of
// them, 1.6 s warm and 23-25 s cold on the live node (2026-10-24), and the method needs no authentication. So:
//   - single flight: one walk at a time; a caller that arrives during a walk waits for it (or for its own ctx) and
//     then reads the cache instead of starting its own walk;
//   - cache per chain tip: an answer is reused while the tip is the same (topoheight, block id) - exactly the state it
//     audited, so a rewind or reorg to a different block at the same topoheight recomputes (verifier SEC-7). The
//     answer audits the tip read when the call started; "cached" and "compute_ms" say how it was made;
//   - cancellation: a caller that goes away stops its walk (audit_sc_balances_ctx); failures are never cached.
//
// The method stays unauthenticated and keeps its loopback/no-auth semantics (security review): only its cost is bounded.
type supply_audit_key struct {
	topo int64
	blid crypto.Hash
}

var supply_audit_cache struct {
	slot   chan struct{} // capacity 1: the single walker; waiters select on it with their ctx
	valid  bool
	key    supply_audit_key
	result GetSupplyAudit_Result
}

func init() { supply_audit_cache.slot = make(chan struct{}, 1) }

// supply_audit_compute and supply_audit_tip are variables so tests can count walks without a chain.
var supply_audit_compute = compute_supply_audit
var supply_audit_tip = func() (supply_audit_key, error) {
	topo := chain.Load_TOPO_HEIGHT()
	r, err := chain.Store.Topo_store.Read(topo)
	return supply_audit_key{topo: topo, blid: r.BLOCK_ID}, err
}

// copy_supply_audit gives each caller its own Top slice, so no caller can alter the cached one.
func copy_supply_audit(r GetSupplyAudit_Result) GetSupplyAudit_Result {
	r.Top = append([]SupplyAudit_SC(nil), r.Top...)
	return r
}

// supply_audit_for returns the audit of the state at key, walking at most once per key.
func supply_audit_for(ctx context.Context, key supply_audit_key, compute func(context.Context, int64) (GetSupplyAudit_Result, error)) (result GetSupplyAudit_Result, err error) {
	select {
	case supply_audit_cache.slot <- struct{}{}:
	case <-ctx.Done():
		return result, fmt.Errorf("supply audit busy: %w", ctx.Err())
	}
	defer func() { <-supply_audit_cache.slot }()
	if supply_audit_cache.valid && supply_audit_cache.key == key {
		result = copy_supply_audit(supply_audit_cache.result)
		result.Cached = true
		return result, nil
	}
	start := time.Now()
	if result, err = compute(ctx, key.topo); err != nil {
		return result, err
	}
	result.ComputeMs = time.Since(start).Milliseconds()
	supply_audit_cache.valid, supply_audit_cache.key, supply_audit_cache.result = true, key, copy_supply_audit(result)
	return copy_supply_audit(result), nil
}

func GetSupplyAudit(ctx context.Context) (result GetSupplyAudit_Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic occured. stack trace r %s", r)
		}
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	key, err := supply_audit_tip()
	if err != nil {
		return
	}
	return supply_audit_for(ctx, key, supply_audit_compute)
}

func compute_supply_audit(ctx context.Context, topo int64) (result GetSupplyAudit_Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic occured. stack trace r %s", r)
		}
	}()
	toporecord, err := chain.Store.Topo_store.Read(topo)
	if err != nil {
		return
	}
	ss, err := chain.Store.Balance_store.LoadSnapshot(toporecord.State_Version)
	if err != nil {
		return
	}
	result.TopoHeight = topo
	result.Height = toporecord.Height
	result.FormulaSupply = blockchain.CalcSupply(uint64(toporecord.Height))
	result.SCCount, result.SCHeld, result.SCHeldOverflow, result.Top, err = audit_sc_balances_ctx(ctx, ss, 10)
	if err != nil {
		return
	}
	if result.FormulaSupply > 0 {
		result.SCHeldPPM = uint64(float64(result.SCHeld) / float64(result.FormulaSupply) * 1e6)
	}
	result.Verdict = supply_verdict(result.SCHeld, result.FormulaSupply, result.SCHeldOverflow)
	result.Limit = "account balances are ElGamal ciphertexts; no node can sum them, so this check is necessary-not-sufficient"
	result.Status = "OK"
	return
}
