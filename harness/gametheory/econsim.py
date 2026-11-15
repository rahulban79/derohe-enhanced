#!/usr/bin/env python3
"""econsim.py — r32 (artifacts/dero-game-theory-rft.md §4, D-GT-3): the equilibrium and sustainability analysis of the
R32 mechanisms. Each model mirrors the rules of its DVM-BASIC contract (gametheory/contracts/*.bas; parameter names are
the contract's STORE keys) and is checked against the in-DVM tests (dvm/r32_gametheory_test.go) by the KAT.

  M1 gt_attest   optimistic miner-attested token: deterrence bound on the bond, replicator dynamics of honest vs
                 inflating miners, juror (Schelling) payoffs, the P+epsilon bribe cost
  M2 gt_service  fee rebate: the no-wash bound rho*(100+boost) <= 10000, the Tullock equilibrium of a sponsor subsidy
  M3 gt_prize    no-loss prize pool: entry EV with and without the MAT boost, the withholding bounds (revealer, miner)
  HR             what an SC incentive can do to hashrate: free-entry H ~ (R_block + I_sc) / cost
  PONZI          the stop-inflow test: every payout is tagged with its funding source; a payout funded by a LATER
                 participant's deposit marks the scheme Ponzi-shaped (child rft NO-GO ledger); M-NOGO-1 (a referral
                 pyramid) is the planted positive
All numbers are atomic units (1 DERO = 100000) unless named otherwise. Deterministic: random.Random(seed).

  python3 -I harness/gametheory/econsim.py [--seed 32] [--json OUT] [--params FILE]   exit 0 · 4 a check failed
"""
import argparse, json, math, random, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
DERO = 100000

# contract defaults (gametheory/contracts/*.bas Initialize); the KAT re-reads them from the .bas files
M1_DEFAULTS = {'bond': 100000, 'reward': 100, 'window': 20, 'commitw': 10, 'revealw': 10, 'maxmb': 10, 'slash': 10,
               'minstake': 100000}
M2_DEFAULTS = {'fee': 1000, 'rho': 50, 'boost': 100, 'epoch': 100, 'minmat': 100}
M3_DEFAULTS = {'rbond': 10000, 'commitw': 10, 'revealw': 10, 'maxn': 32, 'boost': 100, 'minmat': 100}


def contract_defaults(bas_text):
    """The numeric STORE("k", n) defaults of a contract's Initialize (the KAT compares them with the models)."""
    import re
    init = bas_text.split('Function Initialize()', 1)[1].split('End Function', 1)[0]
    return {k: int(v) for k, v in re.findall(r'STORE\("([a-z0-9]+)",\s*(\d+)\)', init)}


# ---------------------------------------------------------------- M1: optimistic attestation
def m1_payoffs(p, k, delta, mat_value, q_challenge, q_jury_correct):
    """Expected DERO-equivalent payoff of one claim of k true miniblocks, inflated by delta (0 = honest).
    q_challenge: probability a false claim is challenged (a verifier reads the public block headers); an honest
    claim is challenged only by a griefer (here 0: a griefer loses its bond when the jury is correct).
    q_jury_correct: probability the jury decides correctly. Returns the EV relative to not claiming."""
    bond = (k + delta) * p['bond']
    tokens = (k + delta) * p['reward'] * mat_value
    if delta == 0:
        return tokens
    caught = q_challenge * q_jury_correct
    # caught: the miner loses its whole bond (half to the challenger, half to coherent jurors) and mints nothing
    return (1 - caught) * tokens - caught * bond


def m1_critical_bond(p, k, delta, mat_value, caught):
    """The bond per miniblock above which inflating by delta has negative EV:
    (1-c)(k+d) r v - c (k+d) B < 0  ->  B > (1-c) r v / c  (independent of k and d)."""
    if caught <= 0:
        return math.inf
    return (1 - caught) * p['reward'] * mat_value / caught


def m1_replicator(p, mat_value, q_challenge, q_jury_correct, n=1000, steps=200, seed=32, delta_frac=0.5):
    """Replicator dynamics over a population of miners choosing honest or inflate (delta = delta_frac * k).
    Returns the honest share trajectory endpoints and whether honesty is the attractor."""
    rng = random.Random(seed)
    ks = [max(1, int(rng.expovariate(1 / 20))) for _ in range(n)]       # miniblocks per epoch, heterogeneous
    x = 0.5                                                              # honest share
    for _ in range(steps):
        ph = sum(m1_payoffs(p, k, 0, mat_value, q_challenge, q_jury_correct) for k in ks) / n
        pc = sum(m1_payoffs(p, k, max(1, int(delta_frac * k)), mat_value, q_challenge, q_jury_correct) for k in ks) / n
        avg = x * ph + (1 - x) * pc
        scale = max(abs(ph), abs(pc), 1e-9)
        x = min(1.0, max(0.0, x + 0.5 * x * (ph - avg) / scale))
    return {'honest_share_end': round(x, 4), 'ev_honest': round(ph, 2), 'ev_inflate': round(pc, 2),
            'honest_attractor': x > 0.99}


def m1_juror(p, stake, others_coherent_weight, pool):
    """One juror's payoff (gt_attest ClaimJuror): coherent = (pool) * w / cwin; incoherent or unrevealed = -ceil(w*slash/100)."""
    cwin = stake + others_coherent_weight
    return {'coherent': pool * stake // cwin, 'incoherent': -((stake * p['slash'] + 99) // 100)}


def m1_bribe_cost(p, juror_stakes, pool):
    """P+epsilon (Buterin 2015): a briber who promises to pay a juror its loss if the bribed vote loses needs to pay
    nothing when the attack succeeds; a credible-commitment bribe must cover each bribed juror's slash + its forgone
    coherent share. Cost of flipping a strict majority when every juror is coherent-by-default:"""
    s = sorted(juror_stakes, reverse=True)
    need, got, cost = sum(s) / 2, 0, 0.0
    for w in s:
        if got > need:
            break
        got += w
        cost += math.ceil(w * p['slash'] / 100) + pool * w / sum(s)
    return {'bribe_cost_if_paid': round(cost, 2), 'bribe_cost_p_epsilon_success': 0}


# ---------------------------------------------------------------- M2: fee rebate
def m2_rebate_share(p, fees, boosted, sponsor=0):
    """Rebates per payer for one epoch, exactly as gt_service ClaimRebate: pay = P * w / W (integer floor)."""
    w = [f * (100 + p['boost']) // 100 if b else f for f, b in zip(fees, boosted)]
    P = sum(f * p['rho'] // 100 for f in fees) + sponsor
    W = sum(w)
    return [P * wi // W if W else 0 for wi in w]


def m2_wash_profitable(p, organic_fees, sponsor=0, step=None):
    """Does a boosted washer gain by adding fee volume x on top of organic, unboosted users? Returns the best x and
    its net gain (rebate - x) over a grid. With sponsor 0 and rho*(100+boost) <= 10000 the best x is 0."""
    step = step or p['fee']
    best = (0, 0.0)
    for x in range(0, 50 * step + 1, step):
        if x == 0:
            continue
        fees = organic_fees + [x]
        boosted = [False] * len(organic_fees) + [True]
        reb = m2_rebate_share(p, fees, boosted, sponsor)[-1]
        gain = reb - x
        if gain > best[1]:
            best = (x, gain)
    return {'best_wash': best[0], 'net_gain': best[1]}


def m2_tullock(sponsor, n, rho=0.5, boost_shares=None):
    """Symmetric Tullock contest for a sponsor subsidy S among n identical unboosted washers who pay fees x_i and
    receive (rho * sum x + S) * x_i / sum x. Net: S x_i / X - (1 - rho) x_i. Equilibrium X* = S (n - 1) / (n (1 - rho)),
    total fee spend X*, of which the treasury keeps (1-rho) X* = S (n-1)/n: the subsidy is competed away."""
    if n < 2:
        return {'X_star': 0.0, 'treasury_take': 0.0, 'washers_net': sponsor}
    X = sponsor * (n - 1) / (n * (1 - rho))
    return {'X_star': round(X, 2), 'treasury_take': round((1 - rho) * X, 2),
            'washers_net_total': round(sponsor + rho * X - X, 2), 'subsidy_dissipated_frac': round((n - 1) / n, 4)}


def m2_tullock_numeric(sponsor, n, rho=0.5, iters=400):
    """Best-response iteration of the same contest (checks the closed form)."""
    x = [sponsor / n] * n
    for _ in range(iters):
        for i in range(n):
            others = sum(x) - x[i]
            # maximise S x/(x+o) - (1-rho) x  ->  x = sqrt(S o / (1-rho)) - o
            xi = max(0.0, math.sqrt(sponsor * others / (1 - rho)) - others) if others > 0 else sponsor
            x[i] = 0.5 * x[i] + 0.5 * xi
    return round(sum(x), 2)


# ---------------------------------------------------------------- M3: prize pool
def m3_entry_ev(p, principal, others_weight, prize, boosted, fee_cost=0):
    w = principal * (100 + p['boost']) // 100 if boosted else principal
    return round(prize * w / (w + others_weight) - fee_cost, 2)


def m3_withholding(p, prize, n_revealed, block_reward_forgone, uses_random=False):
    """The last revealer may withhold (forfeit rbond, lose its own chance): profitable only if prize > rbond * (n-1).
    v1 of gt_prize mixed RANDOM (keyed by the block id) into the pick, so the INTEGRATOR of the Draw block could withhold
    that block to re-roll, forfeiting one integrator share (block_reward_forgone; reward_analysis 3 and 4: the final
    miniblock's share + leftover go to the integrator). v2 (D-GT-10) uses the revealed seed only: no re-roll exists."""
    rev = p['rbond'] * max(n_revealed - 1, 1)
    miner_safe = (prize <= block_reward_forgone) if uses_random else True
    cap = min(rev, block_reward_forgone) if uses_random else rev
    return {'revealer_safe': prize <= rev, 'miner_safe': miner_safe, 'max_safe_prize': cap}


# ---------------------------------------------------------------- HR: hashrate under free entry
def hashrate_gain(block_reward, sc_incentive_per_block):
    """Free entry: miners enter until revenue per hash = cost per hash, so total hashrate H is proportional to the
    real value paid per block. An SC incentive I (real DERO per block routed to miners, NOT token issuance) raises H
    by I / R. Token issuance without a buyer adds nothing: its market value is what someone pays for it."""
    return round(sc_incentive_per_block / block_reward, 6)


# ---------------------------------------------------------------- PONZI: the stop-inflow test
SOURCES_OK = {'own_principal', 'own_bond', 'counterparty_bond_same_dispute', 'slash_same_dispute', 'sponsor',
              'fees_same_epoch', 'forfeit_same_round', 'token_issuance'}


def ledger_m1(rounds=20, seed=32):
    rng = random.Random(seed)
    out = []
    for r in range(rounds):
        honest = rng.random() < 0.8
        out.append({'t': r, 'payee': f'miner{r}', 'source': 'own_bond'})
        out.append({'t': r, 'payee': f'miner{r}', 'source': 'token_issuance' if honest else 'none'})
        if not honest:
            out.append({'t': r, 'payee': f'chal{r}', 'source': 'counterparty_bond_same_dispute'})
            out.append({'t': r, 'payee': f'jur{r}', 'source': 'slash_same_dispute'})
    return out


def ledger_m2(epochs=10):
    return [{'t': e, 'payee': f'user{e}', 'source': s} for e in range(epochs) for s in ('fees_same_epoch', 'sponsor')]


def ledger_m3(rounds=10):
    return [{'t': r, 'payee': f'p{r}', 'source': s} for r in range(rounds)
            for s in ('own_principal', 'own_bond', 'sponsor', 'forfeit_same_round')]


def ledger_nogo_pyramid(n=12, rate=0.5):
    """M-NOGO-1 (planted positive): each entrant pays 1 DERO, earlier entrants are paid `rate` of every later
    deposit. Every return payout is funded by a later participant's deposit."""
    out = []
    for t in range(n):
        for j in range(t):
            out.append({'t': t, 'payee': f'early{j}', 'source': 'later_deposit', 'amount': rate / max(t, 1)})
    return out


def stop_inflow_check(ledger):
    """Ponzi-shaped iff any payout is funded by a later participant's deposit, or by a source not on the allowed list."""
    bad = [x for x in ledger if x['source'] not in SOURCES_OK and x['source'] != 'none']
    return {'ponzi_shaped': bool(bad), 'bad_payouts': len(bad), 'sources': sorted({x['source'] for x in ledger})}


# ---------------------------------------------------------------- the checks
def analyse(seed=32, params=None):
    params = params or {}
    p1 = dict(M1_DEFAULTS, **params.get('M1', {}))
    p2 = dict(M2_DEFAULTS, **params.get('M2', {}))
    p3 = dict(M3_DEFAULTS, **params.get('M3', {}))
    mat_value = params.get('mat_value_atomic', 1000)          # assumed MAT price in atomic DERO (sensitivity swept)
    res, checks = {}, []

    # M1: the bond deters inflation iff bond > (1-c) r v / c
    sweep = []
    for c in (0.1, 0.25, 0.5, 0.75, 0.9):
        crit = m1_critical_bond(p1, 10, 5, mat_value, c)
        sweep.append({'caught': c, 'critical_bond': round(crit, 2), 'default_bond_deters': p1['bond'] > crit})
    res['m1_bond_sweep'] = sweep
    rep_hi = m1_replicator(p1, mat_value, 0.9, 0.95, seed=seed)
    rep_lo = m1_replicator(dict(p1, bond=1), mat_value * 1000, 0.05, 0.6, seed=seed)
    res['m1_replicator'] = {'deterrent': rep_hi, 'weak': rep_lo}
    checks.append(('M1 honesty is the attractor when the bond deters (c=0.855)', rep_hi['honest_attractor']))
    checks.append(('M1 inflation spreads when the bond is tiny and detection rare', not rep_lo['honest_attractor']))
    crit = m1_critical_bond(p1, 10, 5, mat_value, 0.5)
    ev_above = m1_payoffs(dict(p1, bond=int(crit) + 1), 10, 5, mat_value, 1.0, 0.5)
    ev_below = m1_payoffs(dict(p1, bond=max(1, int(crit) - 1)), 10, 5, mat_value, 1.0, 0.5)
    checks.append(('M1 critical bond is the sign change of the inflation EV', ev_above < 0 < ev_below))
    res['m1_bribe'] = m1_bribe_cost(p1, [300000, 200000, 100000], 200000)

    # M2: the no-wash bound
    organic = [p2['fee']] * 10
    nowash = m2_wash_profitable(p2, organic)
    over = m2_wash_profitable(dict(p2, rho=60, boost=100), organic)
    res['m2_wash'] = {'at_defaults': nowash, 'rho60_boost100': over}
    checks.append(('M2 no profitable wash at rho*(100+boost) <= 10000', nowash['net_gain'] <= 0))
    checks.append(('M2 wash becomes profitable past the bound (rho 60, boost 100)', over['net_gain'] > 0))
    border = []
    for rho in (10, 25, 50, 75, 100):
        for boost in (0, 50, 100, 200, 300):
            g = m2_wash_profitable(dict(p2, rho=rho, boost=boost), organic)['net_gain']
            border.append({'rho': rho, 'boost': boost, 'bound_ok': rho * (100 + boost) <= 10000, 'wash_gain': g})
    res['m2_bound_grid'] = border
    checks.append(('M2 no wash gain anywhere inside the bound, a gain somewhere outside it',
                   all(x['wash_gain'] <= 0 for x in border if x['bound_ok'])
                   and any(x['wash_gain'] > 0 for x in border if not x['bound_ok'])))
    S = 100 * DERO
    tul = m2_tullock(S, 10)
    num = m2_tullock_numeric(S, 10)
    res['m2_tullock'] = dict(tul, X_numeric=num)
    checks.append(('M2 Tullock closed form matches best-response iteration (1 %)', abs(num - tul['X_star']) <= 0.01 * tul['X_star']))
    # the exact contract rule on one epoch (dvm test TestR32GTServiceRebate: 3 fees of 1000, one boosted, sponsor 3000)
    reb = m2_rebate_share(p2, [1000, 1000, 1000], [True, False, False], 3000)
    res['m2_dvm_crosscheck'] = reb
    checks.append(('M2 model = contract on the DVM test epoch (miner 2250; u1 1125 + 1125)', reb == [2250, 1125, 1125]))
    res['m1_juror'] = m1_juror(p1, 300000, 100000, 200000 + 20000)
    checks.append(('M1 juror: coherent pays, incoherent is slashed (dvm test: j1 share of b/2 + slash)',
                   res['m1_juror']['coherent'] == 165000 and res['m1_juror']['incoherent'] == -30000))

    # M3: boost doubles the weight; withholding bounds
    ev_b = m3_entry_ev(p3, 15000, 30000, 7000, True)
    ev_u = m3_entry_ev(p3, 15000, 30000, 7000, False)
    res['m3_entry_ev'] = {'boosted': ev_b, 'unboosted': ev_u}
    checks.append(('M3 the MAT boost raises a miner entrant\'s EV', ev_b > ev_u))
    share = 30750 // 10                       # mainnet integrator share today (reward_anchors RW14/RW16, live 30,750)
    res['m3_withholding'] = {'v2': m3_withholding(p3, 17000, 3, share),
                             'v1_random': m3_withholding(p3, 17000, 3, share, uses_random=True)}
    checks.append(('M3 v2: the DVM-test prize (17000) is below the revealer bound and no miner re-roll exists',
                   res['m3_withholding']['v2']['revealer_safe'] and res['m3_withholding']['v2']['miner_safe']))
    checks.append(('M3 v1 (RANDOM in the pick) would let the Draw integrator re-roll a prize above one share (3,075)',
                   not res['m3_withholding']['v1_random']['miner_safe']))

    # HR: hashrate gain = real incentive / block reward
    res['hr'] = {'gain_1pct_needs_per_block': round(0.01 * 61500), 'gain_if_100_atomic_per_block': hashrate_gain(61500, 100)}

    # PONZI
    pz = {'M1': stop_inflow_check(ledger_m1(seed=seed)), 'M2': stop_inflow_check(ledger_m2()),
          'M3': stop_inflow_check(ledger_m3()), 'M-NOGO-1': stop_inflow_check(ledger_nogo_pyramid())}
    res['ponzi'] = pz
    checks.append(('PONZI M1/M2/M3 pass the stop-inflow test', not any(pz[k]['ponzi_shaped'] for k in ('M1', 'M2', 'M3'))))
    checks.append(('PONZI the planted pyramid M-NOGO-1 is flagged', pz['M-NOGO-1']['ponzi_shaped']))
    res['checks'] = [{'check': c, 'ok': bool(ok)} for c, ok in checks]
    res['ok'] = all(ok for _, ok in checks)
    res['seed'] = seed
    res['params'] = {'M1': p1, 'M2': p2, 'M3': p3, 'mat_value_atomic': mat_value}
    return res


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--seed', type=int, default=32)
    ap.add_argument('--json', default=None)
    ap.add_argument('--params', default=None)
    a = ap.parse_args(argv)
    params = json.loads(Path(a.params).read_text()) if a.params else None
    res = analyse(a.seed, params)
    for c in res['checks']:
        print(f"{'ok  ' if c['ok'] else 'FAIL'} {c['check']}")
    if a.json:
        Path(a.json).write_text(json.dumps(res, indent=1, sort_keys=True))
    print(f"econsim: {sum(c['ok'] for c in res['checks'])}/{len(res['checks'])} checks ok")
    return 0 if res['ok'] else 4


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
