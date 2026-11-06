#!/usr/bin/env python3
"""b99_scenario.py (r27, dero-rft §7 B99/B47) — the sync-hold life cycle reproduced on a loopback control node.

The live r26 derod had no hold in 62 min (p2p_sync_peer_holds_total 0 in 11/11 scrapes), so B99's decay and
forgiveness rules were 'pending-no-event'. This runs p2p TestR27SyncHoldLoopbackScenario: a throw-away SIMULATOR chain
in a temp dir (never the live store) and a fake peer on 127.0.0.1:<ephemeral> (never port 11011, never the live
derod) that answers Peer.Chain with one block we lack and Peer.GetObject with no block (a short answer) or with that
block. The real trigger_sync -> sync_chain -> fetch_blocks path runs; the only forged state is the stored hold end,
rewound to stand for elapsed time. It records each step's counters and checks the B99 rules on them:

  short-answer    strike 1, hold ~30 s, holds +1, short answers +1
  held            a held peer is not asked while the fallback slot is closed
  fallback        the slot open and the only peer ahead held: tried in pass 1 (fallbacks +1), strike 2
  decayed         a failure > SYNC_STRIKE_FORGET after the hold ended restarts at strike 1, decays +1
  escalated       a failure inside the window escalates (strike 2), no decay
  served          it serves the block it claimed: strikes 0, counted served (not relay)
  short-again / served-partial   it serves less than it claims: trigger_sync forgives, counted served

  python3 -I harness/intel/b99_scenario.py [--json OUT]      # exit 0 all rules hold · 3 a rule failed · 2 no run
Writes harness/runtime/b99_scenario_<ts>.json (the steps, the go test command, its exit code, the verdicts).
"""
import argparse, datetime, json, os, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TEST = 'TestR27SyncHoldLoopbackScenario'
STEPS = ('short-answer', 'held', 'fallback', 'decayed', 'escalated', 'served', 'short-again', 'served-partial')


def verify(steps):
    """[(rule, ok, detail)] for the recorded steps. Pure."""
    s = {x['step']: x for x in steps}
    out = []

    def rule(name, cond, detail):
        out.append((name, bool(cond), detail))
    missing = [k for k in STEPS if k not in s]
    rule('all steps recorded', not missing, f'missing {missing}' if missing else f'{len(steps)} steps')
    if missing:
        return out
    a, h, f, d, e, sv, sa, sp = (s[k] for k in STEPS)
    rule('short answer holds (strike 1, ~30 s)', a['strikes'] == 1 and a['hold_seconds'] >= 28 and a['p2p_sync_peer_holds_total'] == 1
         and a['p2p_sync_short_answers_total'] == 1, a)
    rule('held peer not asked', h['chain_calls'] == a['chain_calls'] and h['strikes'] == 1, h)
    rule('fallback tries the held peer', f['chain_calls'] == h['chain_calls'] + 1 and f['p2p_sync_held_fallbacks_total'] == 1 and f['strikes'] == 2, f)
    rule('decay restarts at strike 1 and is counted', d['strikes'] == 1 and d['p2p_sync_strike_decays_total'] == 1, d)
    rule('inside the window escalates, no decay', e['strikes'] == 2 and e['p2p_sync_strike_decays_total'] == 1 and e['hold_seconds'] >= 58, e)
    rule('served claim forgives, counted served not relay', sv['strikes'] == 0 and sv['our_height'] == sv['peer_height']
         and sv['p2p_sync_served_forgiven_total'] == 1 and sv['p2p_sync_relay_forgiven_total'] == 0, sv)
    rule('partial serve forgiven by trigger_sync, counted served', sa['strikes'] == 1 and sp['strikes'] == 0
         and sp['our_height'] == sa['our_height'] + 1 and sp['our_height'] < sp['peer_height']
         and sp['p2p_sync_served_forgiven_total'] == 2 and sp['p2p_sync_relay_forgiven_total'] == 0, sp)
    return out


def run_scenario(root=ROOT):
    with tempfile.TemporaryDirectory(prefix='r27b99-') as td:
        out = Path(td) / 'steps.json'
        cmd = ['nice', '-n', '15', 'go', 'test', '-count=1', '-run', f'^{TEST}$', './p2p/']
        env = dict(os.environ, R27_B99_SCENARIO_OUT=str(out))
        r = subprocess.run(cmd, cwd=root, env=env, capture_output=True, text=True, timeout=600)
        steps = json.loads(out.read_text())['steps'] if out.exists() else None
    return cmd, r.returncode, (r.stdout + r.stderr)[-2000:], steps


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--json', help='also write the record here')
    a = ap.parse_args()
    cmd, rc, tail, steps = run_scenario()
    if steps is None:
        print(f'b99_scenario: no steps recorded (go test exit {rc})\n{tail}')
        return 2
    ver = verify(steps)
    rec = {'tool': 'harness/intel/b99_scenario.py', 'test': TEST, 'command': ' '.join(cmd), 'go_test_exit': rc,
           'when': datetime.datetime.now().astimezone().isoformat(timespec='seconds'), 'steps': steps,
           'rules': [{'rule': n, 'ok': ok} for n, ok, _ in ver], 'ok': rc == 0 and all(ok for _, ok, _ in ver)}
    stamp = datetime.datetime.now().strftime('%Y%m%dT%H%M%S')
    dest = ROOT / 'harness' / 'runtime' / f'b99_scenario_{stamp}.json'
    dest.write_text(json.dumps(rec, indent=1) + '\n')
    if a.json:
        Path(a.json).write_text(json.dumps(rec, indent=1) + '\n')
    for n, ok, _ in ver:
        print(f"  {'ok  ' if ok else 'FAIL'} {n}")
    print(f"b99_scenario: {'PASS' if rec['ok'] else 'FAIL'} ({sum(ok for _, ok, _ in ver)}/{len(ver)} rules, go test exit {rc}) -> harness/runtime/{dest.name}")
    return 0 if rec['ok'] else 3


if __name__ == '__main__':
    sys.exit(main())
