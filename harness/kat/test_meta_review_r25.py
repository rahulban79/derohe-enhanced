#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for harness/loop/meta_review.py (r25, dero-rft §0.9 rule 6, §6 step 19a).

  MR1 a complete record on a forged tree passes check.
  MR2 each defect is named: an unknown round, a missing pipeline record, a §7 id that does not exist, an item with both
      backlog and closed and one with neither, an anchor whose quote is gone, an empty section without its _none reason,
      a 'pending' left in an item, and a FAIL record that no 'broke' item cites.
  MR3 template(): lists the round's records only, files a 'broke' item per FAIL stage and 'slowed' items per slow step,
      and never passes check unfilled; filled in, it passes.

  python3 -I harness/kat/test_meta_review_r25.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import copy, importlib.util, json, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
SRC = HARNESS / 'loop' / 'meta_review.py'


def load(path):
    spec = importlib.util.spec_from_file_location(f'mr_{abs(hash(str(path)))}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def tree(d):
    r = Path(d)
    (r / 'harness/loop/runs').mkdir(parents=True)
    (r / 'artifacts').mkdir()
    (r / 'harness/round.json').write_text(json.dumps({'current': 'r25', 'rounds': [{'id': 'r24'}, {'id': 'r25'}]}))
    (r / 'artifacts/dero-rft.md').write_text('| # | Item |\n|---|---|\n| B85 | probe below prune | x | y | OPEN |\n| B90 | order | x | y | OPEN |\n')
    ev = [{'t': '2026-11-03T09:00:00-08:00', 'stage': 'run', 'status': 'BEGIN', 'round': 'r25'},
          {'t': '2026-11-03T09:00:05-08:00', 'stage': 'project', 'status': 'START'},
          {'t': '2026-11-03T09:02:05-08:00', 'stage': 'project', 'status': 'INFO', 'step': 'harness/kat/verify_deroarch.py --mutations'},
          {'t': '2026-11-03T09:02:10-08:00', 'stage': 'project', 'status': 'FAIL', 'failing': ['G15 log health']}]
    (r / 'harness/loop/runs/pipeline_20261103T090000.jsonl').write_text('\n'.join(json.dumps(o) for o in ev) + '\n')
    (r / 'harness/loop/runs/pipeline_20261102T090000.jsonl').write_text(json.dumps(
        {'t': '2026-11-02T09:00:00-08:00', 'stage': 'run', 'status': 'BEGIN', 'round': 'r24'}) + '\n')
    return r


def good():
    rec = 'harness/loop/runs/pipeline_20261103T090000.jsonl'
    return {'round': 'r25', 'written': '2026-11-03', 'pipeline_records': ['pipeline_20261103T090000'],
            'slowed': [{'what': 'verify_deroarch mutations 120 s', 'measured': '120 s',
                        'anchor': {'file': rec, 'quote': '"step": "harness/kat/verify_deroarch.py --mutations"'}, 'closed': 'expected cost'}],
            'broke': [{'what': 'G15 FAIL: our own probe below the prune point', 'anchor': {'file': rec, 'quote': '"status": "FAIL"'},
                       'backlog': 'B85'}],
            'missed': [], 'missed_none': 'nothing found by hand this round',
            'self_inflicted': [{'what': 'probe below prunedheight', 'anchor': {'file': rec, 'quote': '"failing": ["G15 log health"]'},
                                'backlog': 'B85'}]}


def mr1(M, r):
    p = M.check(good(), r)
    return p == [], f'{p}'


def mr2(M, r):
    def bad(f):
        d = copy.deepcopy(good())
        f(d)
        return len(M.check(d, r)) >= 1
    cases = {
        'round': bad(lambda d: d.update(round='r99')),
        'record': bad(lambda d: d['pipeline_records'].append('pipeline_29990101T000000')),
        'unknown_b': bad(lambda d: d['broke'][0].update(backlog='B9999')),
        'both': bad(lambda d: d['broke'][0].update(closed='also closed')),
        'neither': bad(lambda d: d['slowed'][0].pop('closed')),
        'anchor': bad(lambda d: d['slowed'][0]['anchor'].update(quote='a quote that is in no file')),
        'empty': bad(lambda d: d.pop('missed_none')),
        'pending': bad(lambda d: d['slowed'][0].update(closed='pending')),
        'fail_unexplained': bad(lambda d: d.update(broke=[], broke_none='none broke')),
    }
    return all(cases.values()), f'{cases}'


def mr3(M, r):
    t = M.template(r, 'r25')
    unfilled = M.check(t, r)
    ok = t['pipeline_records'] == ['pipeline_20261103T090000'] and len(t['broke']) == 1 and t['slowed'] and bool(unfilled)
    t['broke'][0]['backlog'] = 'B85'
    t['broke'][0]['what'] = 'G15 FAIL: our own probe'
    for s in t['slowed']:
        s['closed'] = 'expected cost'
        s['what'] = s['what'].replace('; cause pending', '; cause: mutations')
    t['missed_none'] = 'none'
    t['self_inflicted_none'] = 'none'
    filled = M.check(t, r)
    return ok and filled == [], f'unfilled {len(unfilled)} problems; filled {filled}'


KATS = [('MR1', mr1), ('MR2', mr2), ('MR3', mr3)]
MUTATIONS = [
    ("    if doc.get('round') not in rounds:", "    if False:", 'an unknown round passes'),
    ("        if not (Path(root) / 'harness/loop/runs' / f'{r}.jsonl').exists():", "        if False:", 'a missing record passes'),
    ("            elif has_b and it['backlog'] not in bl:", "            elif False:", 'a backlog id that is not a §7 row passes'),
    ("            if has_b == has_c:", "            if has_b and has_c:", 'an item with neither a row nor a reason passes'),
    ("            if not anchor_ok(root, it.get('anchor')):", "            if False:", 'an unresolving anchor passes'),
    ("        if not items and not str(doc.get(f'{s}_none', '')).strip():", "        if False:", 'an empty section passes without a reason'),
    ("            if PENDING in json.dumps(it).lower():", "            if False:", 'an unfilled template passes'),
    ("    for r in failed_records(root, recs):", "    for r in []:", 'a FAIL record without a broke item passes'),
    ("        if not ev or ev[0].get('round') != rid:", "        if not ev:", "the template lists another round's records"),
]


def main():
    M = load(SRC)
    ok = True
    with tempfile.TemporaryDirectory() as d:
        r = tree(d)
        for name, fn in KATS:
            try:
                o, det = fn(M, r)
            except Exception as e:                                # noqa: BLE001
                o, det = False, f'{type(e).__name__}: {e}'
            print(f"{'ok  ' if o else 'FAIL'} {name} {det[:300]}")
            ok &= o
        if not ok:
            return 3
        src, missed = SRC.read_text(), 0
        for find, repl, why in MUTATIONS:
            if src.count(find) != 1:
                print(f'  ??      {why}: find text occurs {src.count(find)} times')
                missed += 1
                continue
            with tempfile.TemporaryDirectory() as td:
                p = Path(td) / 'meta_review.py'
                p.write_text(src.replace(find, repl, 1))
                try:
                    m = load(p)
                except Exception as e:                            # noqa: BLE001
                    print(f'  INVALID {why}: mutant does not load ({type(e).__name__})')
                    missed += 1
                    continue
                survived = True
                for _, fn in KATS:
                    try:
                        survived &= fn(m, r)[0]
                    except Exception:                             # noqa: BLE001 — a crash is a detection
                        survived = False
            print(f"  {'MISSED ' if survived else 'proved '} {why}")
            missed += survived
    print(f'\nr25 meta-review KATs: {len(KATS)}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
