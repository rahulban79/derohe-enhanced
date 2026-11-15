#!/usr/bin/env python3
"""cycle_from_earn.py — r32 (gate G36, D-GT-5/6): turn the private mainnet earn log into the public, scrubbed record
of the first two cycle steps. Read-only on local files; no RPC.

  in : ~/derohe-persist/gt-sim/runs/r32-mainnet-earn/events.jsonl (private; written by playbooks/gt_earn.py)
  out: harness/runtime/gt_earn_mainnet.json   wallets by NAME only: registration sent/confirmed, chain-credited atomic
                                              and wallet balances in DERO (5 decimals), measured DERO/day, ticks
       harness/runtime/gt_mainnet_cycle.json  steps 'registered' and 'mined_credited' set to measured with that evidence
                                              when the log proves them (mined_credited needs the wallet balance AND the
                                              chain scan to agree within one miniblock share per wallet)
  python3 -I harness/gametheory/cycle_from_earn.py [--events FILE] [--write]   exit 0 · 2 no log (records only on --write)
"""
import argparse, datetime, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import banguard  # noqa: E402
import sizing  # noqa: E402

DEFAULT = Path.home() / 'derohe-persist/gt-sim/runs/r32-mainnet-earn/events.jsonl'
SHARE_TOL = 3075 + 10        # one miniblock share at the current reward (reward_anchors RW14) + rounding


def summarise(rows):
    live = [r for r in rows if not r.get('dry_run')]
    reg_sent = sorted({r['wallet'] for r in live if r.get('kind') == 'registered_sent'})
    reg_ok = sorted({w for r in live if r.get('kind') == 'registered' for w in r.get('wallets', [])})
    bals = [r for r in live if r.get('kind') == 'earn_balances']
    ticks = [r for r in live if r.get('kind') == 'earn_tick']
    last_bal = bals[-1]['wallet_balance'] if bals else {}
    last_cred = (bals[-1].get('chain_credited') if bals else None) or (ticks[-1].get('chain_credited') if ticks else {}) or {}
    if not isinstance(last_cred, dict):
        last_cred = {}
    rate, hours = sizing.measured_rate(ticks)
    agree = {w: (last_bal.get(w) is not None and abs(int(last_bal[w]) - int(last_cred.get(w, 0))) <= SHARE_TOL)
             for w in last_bal}
    return {'registered_sent': reg_sent, 'registered_confirmed': reg_ok,
            'wallet_balance_dero': {w: (f'{int(v) / 1e5:.5f}' if v is not None else None) for w, v in last_bal.items()},
            'chain_credited_dero': {w: f'{int(v) / 1e5:.5f}' for w, v in last_cred.items()},
            'balance_matches_chain': agree, 'measured_dero_per_day': rate, 'measured_hours': round(hours, 2),
            'ticks': len(ticks), 'balance_reads': len(bals),
            'first_ts': live[0]['ts'] if live else None, 'last_ts': live[-1]['ts'] if live else None}


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--events', default=str(DEFAULT))
    # r32 pipeline run 5 (G3 + page STALE): the live mainnet trigger called this every minute and rewrote the two
    # tracked records under harness/runtime while the pipeline hashed the corpus and checked the page, so both checks
    # raced the miner. The records are now written only on --write (the pipeline's snapshot, gt_pipeline.py); without
    # it the summary is printed and nothing under the repo changes (the running trigger needs no restart)
    ap.add_argument('--write', action='store_true', help='write harness/runtime/gt_earn_mainnet.json + gt_mainnet_cycle.json')
    a = ap.parse_args(argv)
    p = Path(a.events)
    if not p.exists():
        print('cycle_from_earn: no earn log')
        return 2
    rows = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
    s = summarise(rows)
    s['written'] = datetime.datetime.now().astimezone().isoformat(timespec='seconds')
    text = json.dumps(s, indent=1, sort_keys=True)
    if re.search(r'\b(?:dero|deto)1[0-9a-z]{50,}', text) or (banguard.banned_file().exists() and banguard.scan_text(text)):
        print('cycle_from_earn: an address would reach the record; refused')
        return 6
    if not a.write:
        print(json.dumps({k: s[k] for k in ('registered_confirmed', 'wallet_balance_dero', 'chain_credited_dero',
                                            'balance_matches_chain', 'measured_dero_per_day')}))
        return 0
    ev = 'harness/runtime/gt_earn_mainnet.json'
    (ROOT / ev).write_text(text + '\n')
    cp = ROOT / 'harness/runtime/gt_mainnet_cycle.json'
    cyc = json.loads(cp.read_text())
    st = cyc.setdefault('steps', {})
    if s['registered_confirmed']:
        st['registered'] = {'status': 'measured', 'evidence': ev, 'at': s['last_ts'], 'wallets': s['registered_confirmed']}
    if s['wallet_balance_dero'] and all(s['balance_matches_chain'].values()) and any(
            float(v or 0) > 0 for v in s['wallet_balance_dero'].values()):
        st['mined_credited'] = {'status': 'measured', 'evidence': ev, 'at': s['last_ts'],
                                'wallet_balance_dero': s['wallet_balance_dero']}
    cp.write_text(json.dumps(cyc, indent=1) + '\n')
    print(json.dumps({k: s[k] for k in ('registered_confirmed', 'wallet_balance_dero', 'chain_credited_dero',
                                        'balance_matches_chain', 'measured_dero_per_day')}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
