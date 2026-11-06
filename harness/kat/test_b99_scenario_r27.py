#!/usr/bin/env python3
"""KATs + mutation proofs for harness/intel/b99_scenario.py verify() (r27, dero-rft §7 B99): the rules it checks on
the recorded steps of p2p TestR27SyncHoldLoopbackScenario. Synthetic step lists only (no go test run here).

  BS1 the recorded life cycle (hold, held, fallback, decay, escalate, served, partial serve) passes every rule
  BS2 a decay that is not counted (strike back to 1, p2p_sync_strike_decays_total 0) fails the decay rule
  BS3 a served forgiveness counted as a relay fails the served rule; a missing step fails 'all steps recorded'

  python3 -I harness/kat/test_b99_scenario_r27.py   # exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught
"""
import copy, importlib.util, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
F = 'intel/b99_scenario.py'


def st(step, cc, strikes, hold, holds, short, decays, served, relay, fb, oh, ph):
    return {'step': step, 'chain_calls': cc, 'getobject_calls': cc, 'strikes': strikes, 'hold_seconds': hold,
            'p2p_sync_peer_holds_total': holds, 'p2p_sync_short_answers_total': short, 'p2p_sync_strike_decays_total': decays,
            'p2p_sync_served_forgiven_total': served, 'p2p_sync_relay_forgiven_total': relay,
            'p2p_sync_held_fallbacks_total': fb, 'our_height': oh, 'peer_height': ph}


GOOD = [st('short-answer', 1, 1, 29, 1, 1, 0, 0, 0, 0, 4, 5), st('held', 1, 1, 29, 1, 1, 0, 0, 0, 0, 4, 5),
        st('fallback', 2, 2, 59, 2, 2, 0, 0, 0, 1, 4, 5), st('decayed', 3, 1, 29, 3, 3, 1, 0, 0, 1, 4, 5),
        st('escalated', 4, 2, 59, 4, 4, 1, 0, 0, 1, 4, 5), st('served', 5, 0, 0, 4, 4, 1, 1, 0, 1, 5, 5),
        st('short-again', 6, 1, 29, 5, 5, 1, 1, 0, 1, 5, 6), st('served-partial', 7, 0, 0, 5, 5, 1, 2, 0, 1, 6, 7)]


def load(base):
    sp = importlib.util.spec_from_file_location(f'b99s_{id(base)}', base / F)
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


def failed(m, steps):
    return {n for n, ok, _ in m.verify(steps) if not ok}


def bs1(base):
    f = failed(load(base), GOOD)
    return not f, f'failed {sorted(f)}'


def bs2(base):
    s = copy.deepcopy(GOOD)
    for x in s[3:]:
        x['p2p_sync_strike_decays_total'] = 0
    f = failed(load(base), s)
    return 'decay restarts at strike 1 and is counted' in f, f'failed {sorted(f)}'


def bs3(base):
    m = load(base)
    s = copy.deepcopy(GOOD)
    s[5]['p2p_sync_served_forgiven_total'], s[5]['p2p_sync_relay_forgiven_total'] = 0, 1
    f1 = failed(m, s)
    f2 = failed(m, [x for x in GOOD if x['step'] != 'fallback'])
    return 'served claim forgives, counted served not relay' in f1 and 'all steps recorded' in f2, f'{sorted(f1)} / {sorted(f2)}'


KATS = [('BS1', bs1), ('BS2', bs2), ('BS3', bs3)]
MUTATIONS = [
    ('BS2', "d['strikes'] == 1 and d['p2p_sync_strike_decays_total'] == 1", "d['strikes'] == 1", 'an uncounted decay passes'),
    ('BS3', "and sv['p2p_sync_served_forgiven_total'] == 1 and sv['p2p_sync_relay_forgiven_total'] == 0", "and True", 'a served forgiveness may be counted as a relay'),
    ('BS3', "rule('all steps recorded', not missing,", "rule('all steps recorded', True,", 'a missing step passes'),
    ('BS1', "f['chain_calls'] == h['chain_calls'] + 1 and", "f['chain_calls'] == h['chain_calls'] and", 'the fallback rule rejects a real fallback'),
]


def copy_base():
    d = Path(tempfile.mkdtemp(prefix='r27bs-'))
    (d / F).parent.mkdir(parents=True)
    shutil.copy2(HARNESS / F, d / F)
    return d


def main():
    fails, base = 0, copy_base()
    for n, fn in KATS:
        try:
            ok, det = fn(base)
        except Exception as e:                                      # noqa: BLE001
            ok, det = False, f'{type(e).__name__}: {e}'
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {n} {det[:200]}")
    shutil.rmtree(base, ignore_errors=True)
    missed, by = 0, dict(KATS)
    for k, find, repl, why in MUTATIONS:
        d = copy_base()
        t = (d / F).read_text()
        if t.count(find) != 1:
            print(f'  ??      {k}: {why} — find text occurs {t.count(find)} times')
            missed += 1
            continue
        (d / F).write_text(t.replace(find, repl))
        try:
            ok2, _ = by[k](d)
            v = 'MISSED ' if ok2 else 'proved '
        except Exception as e:                                       # noqa: BLE001
            ok2, v = True, f'INVALID ({type(e).__name__})'
        print(f'  {v} {k}: {why}')
        missed += ok2
        shutil.rmtree(d, ignore_errors=True)
    print(f'\nR27 B99 scenario KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
