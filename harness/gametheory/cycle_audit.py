#!/usr/bin/env python3
"""r32 run-9: audit one mainnet game-theory cycle record against the chain (read-only RPC 10102) and the earn log.

Why: the first full mainnet cycle (2026-11-15 08:58-10:26) was recorded by a cycle build that (a) counted a drawn
round as a settled game even when only one wallet had entered (rounds 3-5: m2's Enter missed the commit window), and
(b) reported payoffs that include the mining credited to the same wallets during the cycle. This tool re-derives both
from evidence, without trusting the record's own verdict:
  entrants per round  DERO.GetSC(prize).n<r>                       (the contract's own counter)
  mined in the window the earn log's chain_credited at the last tick before cycle_start and the first after the record
  net game payoff     payoff_atomic - mined                         (a closed game sums to -fees; the check is printed)
  game_settled        gt_cycle.game_settled(rounds + entrants, players)

usage: python3 -I harness/gametheory/cycle_audit.py --record harness/runtime/gt_cycle_mainnet_<ts>.json [--write]
  without --write it prints the audit and writes nothing (lesson 14: a live job never rewrites tracked records);
  --write stores harness/runtime/gt_cycle_audit_mainnet.json, which G36 requires for game_settled.
"""
import argparse, json, sys, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent


def _lib():
    """the playbook modules, imported on use (r32 pipeline run 8, TK1: --help runs in a sandboxed clone without them)"""
    sys.path.insert(0, str(ROOT / 'playbooks'))
    import gt_cycle, gtlib  # noqa: E401
    return gt_cycle, gtlib

OUT = ROOT / 'harness/runtime/gt_cycle_audit_mainnet.json'
SUM_TOL = 100   # atomic: mining ticks are one minute apart, so the window edges may differ by a fraction of a share


def rpc(m, p):
    gtlib = _lib()[1]
    r = urllib.request.Request(f"http://{gtlib.NETWORKS['mainnet']['daemon']}/json_rpc",
                               json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': m, 'params': p}).encode(),
                               {'Content-Type': 'application/json'})
    return json.load(urllib.request.urlopen(r, timeout=60))['result']


def mined_window(earn_rows, t_start, t_end):
    ticks = [r for r in earn_rows if r.get('kind') == 'earn_tick' and isinstance(r.get('chain_credited'), dict)]
    a = [r for r in ticks if r['ts'] <= t_start]
    b = [r for r in ticks if r['ts'] >= t_end]
    if not a or not b:
        return None, None
    a, b = a[-1], b[0]
    return {w: int(b['chain_credited'].get(w, 0)) - int(a['chain_credited'].get(w, 0)) for w in b['chain_credited']}, (a['height'], b['height'])


def audit(rec, cycle_events, earn_rows, prize_vars):
    t_start = next((e['ts'] for e in reversed(cycle_events) if e.get('kind') == 'cycle_start' and e['ts'] <= rec['measured_at']), None)
    rounds = []
    for x in rec['results'].get('m3_rounds') or []:
        rounds.append(dict(x, entrants=int(prize_vars.get(f"n{x['round']}", 0))))
    players = len(rec['wallets'])
    mined, heights = mined_window(earn_rows, t_start or '', rec['measured_at'])
    net = {w: rec['payoff_atomic'][w] - mined[w] for w in rec['wallets']} if mined else None
    fees = int(rec['fees_total_atomic'])
    return {'record': rec.get('_path'), 'measured_at': rec['measured_at'], 'players': players, 'rounds': rounds,
            'genuine_rounds': [x['round'] for x in rounds if x['entrants'] >= players and x.get('drawn') == 1],
            'solo_rounds': [x['round'] for x in rounds if x['entrants'] < players],
            'game_settled': _lib()[0].game_settled(rounds, players),
            'payoff_atomic': rec['payoff_atomic'], 'mined_in_window_atomic': mined, 'window_heights': heights,
            'net_game_payoff_atomic': net, 'fees_total_atomic': fees,
            'sum_check': None if net is None else {'sum_net': sum(net.values()), 'minus_fees': -fees,
                                                   'ok': abs(sum(net.values()) + fees) <= SUM_TOL}}


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--record', required=True)
    ap.add_argument('--run', default='r32-mainnet-cycle')
    ap.add_argument('--earn-run', default='r32-mainnet-earn')
    ap.add_argument('--write', action='store_true')
    a = ap.parse_args(argv)
    gtlib = _lib()[1]
    rp = Path(a.record)
    rec = json.loads((rp if rp.is_absolute() else ROOT / rp).read_text())
    rec['_path'] = str(rp)
    rdir = gtlib.GT_HOME / 'runs' / a.run
    scid = json.loads((rdir / 'state.json').read_text())['scids']['prize']
    ev = [json.loads(l) for l in (rdir / 'events.jsonl').read_text().splitlines() if l.strip()]
    earn = [json.loads(l) for l in (gtlib.GT_HOME / 'runs' / a.earn_run / 'events.jsonl').read_text().splitlines() if l.strip()]
    pv = rpc('DERO.GetSC', {'scid': scid, 'variables': True, 'code': False}).get('stringkeys') or {}
    out = audit(rec, ev, earn, pv)
    text = json.dumps(out, indent=1, sort_keys=True)
    if gtlib.banguard.scan_text(text):
        print('refused: the audit would carry a banned address')
        return 6
    print(text)
    if a.write:
        OUT.write_text(text + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
