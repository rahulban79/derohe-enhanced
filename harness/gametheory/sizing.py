#!/usr/bin/env python3
"""sizing.py — r32 (artifacts/dero-game-theory-rft.md D-GT-7, amending D-GT-6): how many mainnet wallets, and what
balance per role, from the harness's own evidence. LLM-free and reproducible: inputs in, one JSON decision out.

Inputs (each named in the record with its file):
  measured earn   ~/derohe-persist/gt-sim/runs/r32-mainnet-earn/events.jsonl (or --earn FILE): earn_tick / earn_balances
                  -> measured DERO/day (chain-credited); absent = no measured mainnet mining yet
  estimate        harness/runtime/gt_time_to_coins.json (the live-difficulty estimate; reported, never decides alone)
  gas             harness/runtime/gt_gas_census.json (DVM compute/storage gas per entrypoint, from the DVM tests)
  mechanisms      gametheory/mechanisms.json + playbooks/params_r32.json 'mainnet' (deposits, bonds, stakes)
  fees            config FEE_PER_KB = 20 atomic per KB (config/config.go:49), storage gas cap 20,000 per tx
                  (MAX_STORAGE_GAS_ATOMIC_UNITS, config/config.go:46); a tx's fee must cover its storage gas
Rules (D-GT-7):
  R1 the default is D-GT-6: 2 wallets (m1 deployer + player, m2 player) x 4.00000 DERO.
  R2 the cost of the first cycle per role = its deposits + its calls x fee_per_call (+ the deploys for m1), times the
     safety margin 2; a role whose cost exceeds its target raises the target to that cost (rounded up to 0.1 DERO).
  R3 only MEASURED mining may change the wallet count: a third wallet (a juror, so an M1 dispute can settle) is added
     when the measured DERO/day earns every target, the third's included, within MAX_HOURS of mining.
  R4 the success criterion (one full measured mainnet cycle, G36) needs a settled game: N >= 2 always.
  python3 -I harness/gametheory/sizing.py [--earn FILE] [--write]      exit 0 · 2 an input unreadable
"""
import argparse, datetime, json, math, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
DERO = 100000
DEFAULT_N, DEFAULT_TARGET = 2, 4 * DERO          # D-GT-6 (the user's start)
MARGIN = 2.0
MAX_HOURS = 24.0
FEE_PER_KB = 20                                  # config/config.go:49
STORAGE_CAP = 20000                              # config/config.go:46
TX_KB = 3                                        # an SC call tx is a few KB at ring size 2 (size floor, rounded up)
DEFAULT_EARN = Path.home() / 'derohe-persist/gt-sim/runs/r32-mainnet-earn/events.jsonl'


def measured_rate(rows):
    """DERO/day from chain-credited miniblocks between the first and last earn_tick (None when < 2 ticks or < 30 min)."""
    ticks = [r for r in rows if r.get('kind') == 'earn_tick']
    if len(ticks) < 2:
        return None, 0.0
    def total(r):
        c = r.get('chain_credited')
        return sum(c.values()) if isinstance(c, dict) else int(c or 0)
    t0 = datetime.datetime.fromisoformat(ticks[0]['ts'])
    t1 = datetime.datetime.fromisoformat(ticks[-1]['ts'])
    hours = (t1 - t0).total_seconds() / 3600
    if hours < 0.5:
        return None, hours
    return (total(ticks[-1]) - total(ticks[0])) / DERO / hours * 24, hours


def fee_per_call(gas):
    st = max((v[1] for v in gas.values()), default=0)
    return min(STORAGE_CAP, st) + TX_KB * FEE_PER_KB


def deploy_fee(gas):
    return sum(min(STORAGE_CAP, v[1]) + 10 * FEE_PER_KB for k, v in gas.items() if k.endswith(':Initialize'))


def decide(params, gas, rate, est_rate, rows_src):
    fpc = fee_per_call(gas)
    a, z, s = params['attest'], params['prize'], params['service']
    # the first cycle: m1 deploys 3 contracts + 6 setup calls, plays M3 (enter, reveal, withdraw), M2 (2 notarize + claim)
    # and claims M1 (k = 10 miniblocks, unchallenged); m2 plays M3 and M2. Principal stays the user's default 1 DERO.
    principal = 1 * DERO
    cost = {
        'm1': deploy_fee(gas) + 6 * fpc + (principal + z['rbond'] + 3 * fpc) + (2 * s['fee'] + 3 * fpc) + (10 * a['bond'] + 2 * fpc),
        'm2': (principal + z['rbond'] + 3 * fpc) + (2 * s['fee'] + 3 * fpc),
    }
    reasons = [f'R1 default: {DEFAULT_N} wallets x {DEFAULT_TARGET / DERO:.5f} DERO (D-GT-6)',
               f'R2 fee per call {fpc} atomic (max storage gas {max((v[1] for v in gas.values()), default=0)} + {TX_KB} KB x {FEE_PER_KB}); deploy fees {deploy_fee(gas)}']
    roles = {'m1': DEFAULT_TARGET, 'm2': DEFAULT_TARGET}
    for r, c in cost.items():
        need = math.ceil(c * MARGIN / (DERO // 10)) * (DERO // 10)
        if need > roles[r]:
            reasons.append(f'R2 {r}: first-cycle cost {c} x {MARGIN} = {need} > target -> raised')
            roles[r] = need
        else:
            reasons.append(f'R2 {r}: first-cycle cost {c} x {MARGIN} fits the {roles[r] / DERO:.5f} DERO target')
    if rate is None:
        reasons.append('R3 no measured mainnet mining yet: the wallet count stays at the default (an estimate never decides)')
    else:
        juror = math.ceil((a['minstake'] + 3 * fpc) * MARGIN / (DERO // 10)) * (DERO // 10)
        hours = (sum(roles.values()) + juror) / DERO / rate * 24
        if hours <= MAX_HOURS:
            roles['j1'] = juror
            reasons.append(f'R3 measured {rate:.3f} DERO/day earns {len(roles)} targets in {hours:.1f} h <= {MAX_HOURS} h: add juror j1 (an M1 dispute can settle)')
        else:
            reasons.append(f'R3 measured {rate:.3f} DERO/day needs {hours:.1f} h for a third wallet > {MAX_HOURS} h: stay at {len(roles)}')
    reasons.append(f'R4 the success criterion needs a settled game: N = {len(roles)} >= 2')
    return {'n_wallets': len(roles), 'targets_atomic': roles, 'targets_dero': {k: f'{v / DERO:.5f}' for k, v in roles.items()},
            'first_cycle_cost_atomic': cost, 'fee_per_call_atomic': fpc, 'measured_dero_per_day': rate,
            'estimated_dero_per_day': est_rate, 'reasons': reasons, 'earn_source': rows_src}


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--earn', default=str(DEFAULT_EARN))
    ap.add_argument('--write', action='store_true')
    a = ap.parse_args(argv)
    try:
        gas = json.loads((ROOT / 'harness/runtime/gt_gas_census.json').read_text())
        params = json.loads((ROOT / 'playbooks/params_r32.json').read_text())['params']['mainnet']
    except (OSError, ValueError, KeyError) as e:
        print(f'sizing: input unreadable ({type(e).__name__}: {e})')
        return 2
    try:
        est = json.loads((ROOT / 'harness/runtime/gt_time_to_coins.json').read_text()).get('dero_per_day')
    except (OSError, ValueError):
        est = None
    rows = []
    ep = Path(a.earn)
    if ep.exists():
        rows = [json.loads(l) for l in ep.read_text().splitlines() if l.strip()]
    rate, hours = measured_rate(rows)
    d = decide(params, gas, rate, est, 'measured earn log' if rows else 'none (no mainnet mining yet)')
    d.update({'decided_at': datetime.datetime.now().astimezone().isoformat(timespec='seconds'), 'measured_hours': round(hours, 2),
              'inputs': ['harness/runtime/gt_gas_census.json', 'playbooks/params_r32.json', 'harness/runtime/gt_time_to_coins.json',
                         'the mainnet earn log (private run dir)']})
    print(json.dumps({k: d[k] for k in ('n_wallets', 'targets_dero', 'measured_dero_per_day', 'estimated_dero_per_day', 'reasons')}, indent=1))
    if a.write:
        (ROOT / 'harness/runtime/gt_sizing_last.json').write_text(json.dumps(d, indent=1, sort_keys=True) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))


# ---------------------------------------------------------------- D-GT-8: the two-wallet mainnet game, viability gate
# The user (2026-11-15): start the m1-m2 game at 1 DERO each; stakes may be fractions of a DERO; the game must be
# economically viable. In a CLOSED two-wallet game the payoffs sum to -fees (every transfer is between the two players
# and the contracts pay out only what they hold, D-GT-3), so both players cannot gain at once. The gate therefore
# evaluates roles: each PARTICIPANT must expect a non-negative net (its share of the sponsor-funded prize minus its own
# recurring fees); the SPONSOR (m1) buys activity with a budget, recorded as the price of the activity (DERO per call),
# the R32 lever (econsim hashrate_gain: real value routed to miners per block).
FEE_FRACTION_MAX = 0.10   # (a) recurring fees per round <= 10 % of the participant's stake: a no-loss pool must return
#                           at least 90 % of principal to a player who never wins (the design bound; stated, not measured)
SAFETY = 0.25             # (e) keep 25 % of each wallet's balance unspent for fee variance and a second attempt


def viability(plan, fee_call, fee_install, budget_each, ponzi_shaped=False):
    """the five D-GT-8 checks for one plan {'principal', 'rbond', 'sponsor', 'rounds', 'boost', 'bond', 'k'} -> dict."""
    p, rb, S, R, boost = plan['principal'], plan['rbond'], plan['sponsor'], plan['rounds'], plan['boost']
    setup_calls = 8 + 2                                   # SetParams x3, SetMAT x2, Freeze x3, Claim + Finalize
    setup = 3 * fee_install + setup_calls * fee_call
    per_round = {'m1': 5 * fee_call, 'm2': 3 * fee_call}  # m1: Fund, Enter, Reveal, Draw, Withdraw · m2: Enter, Reveal, Withdraw
    w1 = p * (100 + boost) // 100                        # m1 mined to its address and claimed MAT: boosted
    w2 = p                                               # m2 unboosted in the base case (it may claim too: then equal)
    W = w1 + w2
    ev = {'m1': S * w1 / W - per_round['m1'], 'm2': S * w2 / W - per_round['m2']}
    ev_boost_gain = S * (w1 / W - p / (p + w2))          # (c) what the MAT boost adds for the same stake
    fee_frac = max(per_round[r] + (setup / R if r == 'm1' else 0) for r in per_round) / p
    spend = {'m1': setup + R * (per_round['m1'] + S) + plan['k'] * plan['bond'] + p + rb,
             'm2': R * per_round['m2'] + p + rb}
    checks = {
        'a_fees_bounded': fee_frac <= FEE_FRACTION_MAX,
        'b_participants_gain': ev['m2'] >= 0 and S * w1 / W - per_round['m1'] >= 0,
        'c_same_address_incentive': ev_boost_gain > 0,
        'd_no_ponzi': not ponzi_shaped,
        'e_budget': all(spend[r] <= budget_each * (1 - SAFETY) for r in spend),
    }
    return {'ok': all(checks.values()), 'checks': checks, 'fee_fraction': round(fee_frac, 4), 'setup_atomic': setup,
            'per_round_fees': per_round, 'ev_atomic': {k: round(v, 1) for k, v in ev.items()},
            'boost_gain_atomic': round(ev_boost_gain, 1), 'spend_atomic': spend,
            'sponsor_price_per_call_atomic': round(S / (per_round['m1'] / fee_call + per_round['m2'] / fee_call), 1)}


def plan_two_wallet(fee_call, fee_install, budget_each, rounds=None, rbond=1000, boost=100, bond=615, k=10):
    """the cheapest viable plan on a grid (rounds 1-5, principal, sponsor) for the budget, or the refusal with the
    smallest budget at which one passes. More rounds amortise the one-off setup fees (deploy + parameters). Deterministic."""
    grid_p = [int(x * 1000) for x in (5, 10, 20, 30, 40, 50, 75, 100, 150, 200, 300, 500)]
    best = None
    for R in ([rounds] if rounds else range(1, 6)):
        for p in grid_p:
            for S in range(1000, p + 1, 1000):
                plan = {'principal': p, 'rbond': rbond, 'sponsor': S, 'rounds': R, 'boost': boost, 'bond': bond, 'k': k}
                v = viability(plan, fee_call, fee_install, budget_each)
                if v['ok']:
                    cost = v['spend_atomic']['m1'] + v['spend_atomic']['m2'] - 2 * p - 2 * rbond   # money not returned
                    if best is None or (cost / R, cost) < (best[0] / best[1]['rounds'], best[0]):
                        best = (cost, plan, v)
                    break
    if best:
        return {'viable': True, 'plan': best[1], 'viability': best[2]}
    for b in range(budget_each, 50 * budget_each + 1, budget_each // 4 or 1):
        r = plan_two_wallet(fee_call, fee_install, b, rounds, rbond, boost, bond, k) if b != budget_each else None   # noqa: E501
        if r and r['viable']:
            return {'viable': False, 'reason': f'no plan passes at {budget_each} atomic each', 'min_budget_each_atomic': b}
    return {'viable': False, 'reason': 'no plan passes up to 50x the budget', 'min_budget_each_atomic': None}
