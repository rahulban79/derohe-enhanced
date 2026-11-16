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
    """mining credited per wallet between the last earn tick at/before t_start and the first at/after t_end. The earn
    counters (chain_credited) are cumulative SINCE EACH LAUNCH of the earn job: r32a (2026-11-15 23:09) restarted it
    mid-cycle and the single subtraction went wrong. Now consecutive ticks are summed; a counter that went DOWN marks a
    relaunch and that tick's value counts from 0 (credits between the old job's last tick and the relaunch's start are
    not seen: `resets` says how often that happened). (None, None) when no tick bounds the window yet."""
    ticks = sorted((r for r in earn_rows if r.get('kind') == 'earn_tick' and isinstance(r.get('chain_credited'), dict)),
                   key=lambda r: r['ts'])
    a = [i for i, r in enumerate(ticks) if r['ts'] <= t_start]
    b = [i for i, r in enumerate(ticks) if r['ts'] >= t_end]
    if not a or not b:
        return None, None
    seg = ticks[a[-1]:b[0] + 1]
    mined, resets = {}, 0
    for p, q in zip(seg, seg[1:]):
        reset = any(int(q['chain_credited'].get(w, 0)) < int(p['chain_credited'].get(w, 0)) for w in p['chain_credited'])
        resets += reset
        for w, v in q['chain_credited'].items():
            d = int(v) - (0 if reset else int(p['chain_credited'].get(w, 0)))
            mined[w] = mined.get(w, 0) + max(0, d)
    return mined, (seg[0]['height'], seg[-1]['height'], resets)


def chain_mined(rpc_fn, lo, hi, addrs):
    """normal miniblocks per wallet over heights [lo, hi] read from the block headers (DERO.GetBlock miners; the final
    share of a 10-miniblock block is the integrator's), at reward // 10 each — the same rule the earn job uses, but
    independent of its counters (r32a step 3: an earn relaunch hid two shares from the counter-based window). Addresses
    stay in memory. Pure apart from rpc_fn."""
    by_addr = {a: w for w, a in addrs.items()}
    out = {w: 0 for w in addrs}
    for h in range(lo, hi + 1):
        bh = rpc_fn('DERO.GetBlock', {'height': h})['block_header']
        ms = bh.get('miners') or []
        for m in (ms[:-1] if len(ms) == 10 else ms):
            if m in by_addr:
                out[by_addr[m]] += int(bh.get('reward', 0)) // 10
    return out


def wallet_addresses(names, network='mainnet'):
    """{wallet: address} via `gt-wallet address` (its own ban guard runs; never printed or written). {} on any failure."""
    import os, subprocess
    gtlib = _lib()[1]
    out = {}
    for n in names:
        db, pf = gtlib.WALLETS / network / f'{n}.db', gtlib.WALLETS / network / f'{n}.pass'
        if not (db.exists() and pf.exists()):
            return {}
        r = subprocess.run([str(gtlib.BIN / 'gt-wallet'), 'address', '--file', str(db), '--mainnet-confirm'], capture_output=True,
                           text=True, env=dict(os.environ, GT_WALLET_PASSWORD=pf.read_text().strip()), timeout=300)
        if r.returncode != 0:
            return {}
        out[n] = json.loads(r.stdout.strip().splitlines()[-1])['address']
    return out


def audit(rec, cycle_events, earn_rows, prize_vars, chain=None):
    t_start = next((e['ts'] for e in reversed(cycle_events) if e.get('kind') == 'cycle_start' and e['ts'] <= rec['measured_at']), None)
    rounds = []
    for x in rec['results'].get('m3_rounds') or []:
        rounds.append(dict(x, entrants=int(prize_vars.get(f"n{x['round']}", 0))))
    players = len(rec['wallets'])
    mined, heights = mined_window(earn_rows, t_start or '', rec['measured_at'])
    src = 'earn-log'
    if chain is not None:          # chain(lo, hi) -> {wallet: atomic}: the headers decide, the earn ticks only bound it
        lo = rec.get('start_height') or (heights[0] if heights else None)
        hi = rec.get('end_height') or (heights[1] if heights else None)
        if lo and hi:
            mined, src = chain(int(lo), int(hi)), 'chain'
            heights = (int(lo), int(hi), heights[2] if heights else 0)
    net = {w: rec['payoff_atomic'][w] - mined.get(w, 0) for w in rec['wallets']} if mined is not None else None
    fees = int(rec['fees_total_atomic'])
    return {'record': rec.get('_path'), 'measured_at': rec['measured_at'], 'players': players, 'rounds': rounds,
            'genuine_rounds': [x['round'] for x in rounds if x['entrants'] >= players and x.get('drawn') == 1],
            'solo_rounds': [x['round'] for x in rounds if x['entrants'] < players],
            'game_settled': _lib()[0].game_settled(rounds, players),
            'payoff_atomic': rec['payoff_atomic'], 'mined_in_window_atomic': mined, 'window_heights': heights, 'mined_source': src,
            'net_game_payoff_atomic': net, 'fees_total_atomic': fees,
            'sum_check': None if net is None else {'sum_net': sum(net.values()), 'minus_fees': -fees,
                                                   'ok': abs(sum(net.values()) + fees) <= SUM_TOL}}


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--record', required=True)
    ap.add_argument('--run', default=None, help='the cycle run (default: the record\'s own "run"; r32a: the pipeline passed none and the R32 run was read for a ladder record)')
    ap.add_argument('--earn-run', default='r32-mainnet-earn')
    ap.add_argument('--write', action='store_true')
    a = ap.parse_args(argv)
    gtlib = _lib()[1]
    rp = Path(a.record)
    rec = json.loads((rp if rp.is_absolute() else ROOT / rp).read_text())
    rec['_path'] = str(rp)
    rdir = gtlib.GT_HOME / 'runs' / (a.run or rec.get('run') or 'r32-mainnet-cycle')
    scid = json.loads((rdir / 'state.json').read_text())['scids']['prize']
    ev = [json.loads(l) for l in (rdir / 'events.jsonl').read_text().splitlines() if l.strip()]
    earn = [json.loads(l) for l in (gtlib.GT_HOME / 'runs' / a.earn_run / 'events.jsonl').read_text().splitlines() if l.strip()]
    pv = rpc('DERO.GetSC', {'scid': scid, 'variables': True, 'code': False}).get('stringkeys') or {}
    addrs = wallet_addresses(rec['wallets'])
    chain = (lambda lo, hi: chain_mined(rpc, lo, hi, addrs)) if addrs else None
    out = audit(rec, ev, earn, pv, chain=chain)
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
