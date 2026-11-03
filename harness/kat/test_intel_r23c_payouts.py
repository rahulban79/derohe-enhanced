#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the R23c payouts harness layer (no network, no live file written).

  IK23cP1 payout_census.classify: a synthetic census of 6 heights puts every found share in exactly one class: a paid
          regular share, a stale-flagged loss, a slot-race loss (all 9 block-normal jobs created before our find), an
          'other' loss, a paid final, a final lost after the winner existed (margin > 0) and one lost on propagation
          (margin <= 0); a 2nd final at a height is never paid twice; a share at a height with no block is unknown;
          near misses count only paid shares that were the block's 9th with the latest OTHER job within W ms.
  IK23cP2 payout_census.parse_found / u16_delta / anonymise: the miner log's found lines (CPU and GPU-split text) with
          job difficulty and likely_stale, a since filter, the uint16 ms unwrap across the 65,536 ms wrap, and builders
          named us / B00 / B01 in order of first sight (no address survives).

  python3 -I harness/kat/test_intel_r23c_payouts.py   # KATs, then each mutation on a temp copy must flip its KAT
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught.
"""
import importlib.util, json, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
MODS = {'census': 'intel/payout_census.py'}
EXTRA = ['intel/miner_runs.py', 'intel/miner_intel.py']   # payout_census loads miner_runs lazily (main only)


def load(base, name):
    spec = importlib.util.spec_from_file_location(f'{name}_{id(base)}_{len(sys.modules)}', base / MODS[name])
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


D = 3_000_000


def block(normal_ts, final_ts, ours_idx, final_ours=False, ts=10_000_000, builder='B00'):
    return {'diff': D, 'ts': ts, 'ours_normal': len(ours_idx), 'ours_idx': ours_idx, 'final_ours': final_ours,
            'mbl_ts': [t % 65536 for t in normal_ts] + [final_ts % 65536], 'builder': builder}


def ik_classify(base, tmp):
    C = load(base, 'census')
    T = 10_000_000                           # epoch ms of the synthetic heights (block template times near it)
    nine = [T - 9000 + 1000 * i for i in range(9)]  # 9 normal jobs, the latest at T-1000
    found = [
        {'ms': T - 1100, 'h': 1, 'diff': D, 'stale': False, 'gpu': True},   # paid: ours is index 8, latest other T-2000
        {'ms': T + 50, 'h': 2, 'diff': D, 'stale': True, 'gpu': True},      # lost, stale-flagged
        {'ms': T + 400, 'h': 3, 'diff': D, 'stale': False, 'gpu': True},    # lost, all 9 jobs before -> slot race
        {'ms': T - 5000, 'h': 4, 'diff': D, 'stale': False, 'gpu': True},   # lost, jobs after ours -> other
        {'ms': T + 300, 'h': 5, 'diff': 9 * D, 'stale': False, 'gpu': True},  # final paid
        {'ms': T + 900, 'h': 5, 'diff': 9 * D, 'stale': False, 'gpu': True},  # 2nd final at h5: lost after winner
        {'ms': T - 200, 'h': 6, 'diff': 9 * D, 'stale': False, 'gpu': True},  # final lost on propagation (margin -200)
        {'ms': T, 'h': 7, 'diff': D, 'stale': False, 'gpu': True},          # no block known: unknown
    ]
    census = {
        1: block(nine[:8] + [T - 1150], T + 5000, [8]),           # ours at index 8 (its job T-1150, found T-1100)
        2: block(nine, T + 5000, []),
        3: block(nine, T + 5000, []),
        4: block(nine, T + 5000, []),
        5: block(nine, T + 300, [], final_ours=True, ts=T, builder='us'),
        6: block(nine, T + 500, [], ts=T, builder='B01'),
        7: {'err': 'URLError'},
    }
    r = C.classify(found, census, near_ms=(500, 1000, 2000))
    c = r['counts']
    want = {'found_regular': 4, 'paid_regular': 1, 'lost_regular_stale_flagged': 1, 'lost_regular_slot_race': 1,
            'lost_regular_other': 1, 'found_final': 3, 'paid_final': 1, 'lost_final_after_winner': 1,
            'lost_final_propagation': 1, 'unknown_height': 1}
    bad = {k: (c.get(k, 0), v) for k, v in want.items() if c.get(k, 0) != v}
    near = r['near_miss_paid']                 # h1: latest OTHER job T-2000, found T-1100 -> 900 ms: in W1000, W2000
    margins = sorted(x['margin_ms'] for x in r['lost_final'])
    ok = (not bad and near == {'500': 0, '1000': 1, '2000': 1} and margins == [-200, 900]
          and r['slot_race_late_ms'] == [1400] and r['paid_fraction'] == round(2 / 7, 4)
          and r['regular_paid_fraction'] == 0.25 and r['final_paid_fraction'] == round(1 / 3, 4))
    return ok, f'bad={bad} near={near} margins={margins} race={r["slot_race_late_ms"]} pf={r["paid_fraction"]}'


def ik_parse(base, tmp):
    C = load(base, 'census')
    lines = [
        json.dumps({'L': 'DEBUG', 'T': '2026-11-01T09:50:43.331-0800', 'M': 'GPU-split found DERO miniblock (submitting)',
                    'difficulty': '3168218', 'height': 7841758, 'likely_stale': True}),
        json.dumps({'L': 'DEBUG', 'T': '2026-10-28T08:33:11.067-0700', 'M': 'Successfully found DERO miniblock (going to submit)',
                    'difficulty': '3164648', 'height': 7822685}),
        json.dumps({'L': 'INFO', 'T': '2026-11-01T09:47:48.702-0800', 'M': 'SUBMIT STATS', 'submits': 25}),
        'not json found DERO miniblock',
    ]
    rows = C.parse_found(lines)
    since = C.parse_found(lines, since_ms=C.ms_of('2026-11-01T00:00:00.000-0800'))
    g, cpu = (rows + [{}, {}])[:2]
    ok_rows = (len(rows) == 2 and g.get('gpu') is True and g.get('stale') is True and g.get('diff') == 3168218
               and g.get('h') == 7841758 and cpu.get('gpu') is False and cpu.get('stale') is None
               and g.get('ms') == 1793555443331 and len(since) == 1)
    wrap = (C.u16_delta(65536 * 10 + 5, 65530) == 11 and C.u16_delta(65536 * 10 + 65530, 5) == -11
            and C.u16_delta(1000, 400) == 600)
    names = C.anonymise(['a', 'me', 'b', 'a', None], 'me')
    ok = ok_rows and wrap and names == ['B00', 'us', 'B01', 'B00', 'B02']
    return ok, f'rows={rows} since={len(since)} wrap={wrap} names={names}'


KATS = [('IK23cP1', ik_classify), ('IK23cP2', ik_parse)]

# (kat, module, find, replace, why) — each must flip its KAT to FAIL on a temp copy
MUTATIONS = [
    ('IK23cP1', 'census', "FINAL_DIFF_RATIO = 2 ", "FINAL_DIFF_RATIO = 10 ", 'a final job (9x) is counted as a regular share'),
    ('IK23cP1', 'census', "        paid = min(len(reg), b['ours_normal'])", "        paid = len(reg)",
     'every found regular share is paid (the chain is not consulted)'),
    ('IK23cP1', 'census', "            if r['stale']:\n", "            if False:\n",
     'stale-flagged losses are filed as slot races'),
    ('IK23cP1', 'census', "            elif normal_ts and all(d > 0 for d in before):", "            elif normal_ts:",
     'a loss whose block jobs came after our find is a slot race'),
    ('IK23cP1', 'census', "            if b['final_ours'] and k == 0:", "            if b['final_ours']:",
     'two finals at one height are both paid'),
    ('IK23cP1', 'census', "'lost_final_after_winner' if m > 0 else", "'lost_final_after_winner' if m > -10**9 else",
     'a final lost on propagation is blamed on inbound latency'),
    ('IK23cP1', 'census', "        other_ts = [t for j, t in enumerate(normal_ts) if j not in mine]",
     "        other_ts = list(normal_ts)", 'our own job counts as the latest other normal job (near misses inflated)'),
    ('IK23cP1', 'census', "            c['unknown_height'] += len(rs)\n            continue",
     "            continue", 'a share at an unreadable height vanishes from the budget'),
    ('IK23cP2', 'census', "    return ((a_ms % U16 - b_u16 + 32768) % U16) - 32768", "    return a_ms % U16 - b_u16",
     'the uint16 ms difference does not unwrap at 65,536'),
    ('IK23cP2', 'census', "'gpu': 'GPU' in str(d.get('M'))}", "'gpu': True}", 'CPU finds are filed as GPU finds'),
    ('IK23cP2', 'census', "    return [('us' if a == ours else ids.setdefault(a, 'B%02d' % len(ids))) for a in addresses]",
     "    return [('us' if a == ours else a) for a in addresses]", 'builder addresses are written un-anonymised'),
]


def copy_tree():
    d = Path(tempfile.mkdtemp(prefix='r23ckat-'))
    for rel in list(MODS.values()) + EXTRA:
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HARNESS / rel, d / rel)
    return d


def main():
    fails = 0
    base = copy_tree()
    for name, fn in KATS:
        tmp = Path(tempfile.mkdtemp(prefix='r23cfx-'))
        try:
            ok, det = fn(base, tmp)
        except Exception as e:                                    # noqa: BLE001
            ok, det = False, f'{type(e).__name__}: {e}'
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:400]}")
        shutil.rmtree(tmp, ignore_errors=True)
    shutil.rmtree(base, ignore_errors=True)
    missed = 0
    byname = dict(KATS)
    for kat, mod, find, repl, why in MUTATIONS:
        d = copy_tree()
        p = d / MODS[mod]
        text = p.read_text()
        if text.count(find) != 1:
            print(f'  ??      {kat}: {why} — find text occurs {text.count(find)} times')
            missed += 1
            shutil.rmtree(d, ignore_errors=True)
            continue
        p.write_text(text.replace(find, repl))
        t2 = Path(tempfile.mkdtemp(prefix='r23cfx-m-'))
        try:
            ok2 = byname[kat](d, t2)[0]
        except Exception:                                          # noqa: BLE001 — a crash is a detection
            ok2 = False
        print(f"  {'proved ' if not ok2 else 'MISSED '} {kat}: {why}")
        missed += ok2
        shutil.rmtree(d, ignore_errors=True)
        shutil.rmtree(t2, ignore_errors=True)
    print(f'\nR23c payouts harness KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
