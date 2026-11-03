#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the evolution miner's round axis (r24 pipeline run 1: ORDER ended at R23c,
so the first 'R24 ...' commit crashed harness/miners/mine_evolution.py with KeyError: 'R24' and S7 FAILED).

  EV1 every harness/round.json round that is not 'planned' names an ORDER key (round_of('<id>: x') is in ORDER).
  EV2 every commit since the base tag is assigned to an ORDER round or 'pending' (unknown_rounds of the live git log
      is empty), i.e. the miner can never KeyError on this checkout.
  EV3 unknown_rounds on forged shapes: an unlisted round ('R99') is named, 'pending' and listed rounds are not.

  python3 -I harness/kat/test_evolution_order_r24.py   # KATs, then each mutation on a temp copy must flip a KAT
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import importlib.util, json, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
SRC = HARNESS / 'miners' / 'mine_evolution.py'


def load(path):
    sys.path.insert(0, str(Path(path).parent))
    try:
        spec = importlib.util.spec_from_file_location(f'mev_{abs(hash(str(path)))}', path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    finally:
        sys.path.pop(0)


def commits(ev):
    base = subprocess.run(['git', 'rev-parse', f'{ev.BASE_TAG}^{{commit}}'], cwd=ROOT, capture_output=True,
                          text=True).stdout.strip()
    out = subprocess.run(['git', 'log', '--reverse', '--format=%h\t%s', f'{base}..HEAD'], cwd=ROOT, capture_output=True,
                         text=True).stdout
    return [tuple(l.split('\t', 1)) for l in out.splitlines() if '\t' in l]


def kats(ev):
    bad = []
    reg = json.loads((HARNESS / 'round.json').read_text(encoding='utf-8'))
    for r in reg['rounds']:
        if r.get('status') == 'planned':
            continue
        k = ev.round_of(f"{r['id']}: x")
        if k not in ev.ORDER:
            bad.append(f"EV1 registry round {r['id']} -> {k!r} not in ORDER")
    cs = commits(ev)
    if not cs:
        bad.append('EV2 no commits read from git')
    unk = ev.unknown_rounds(ev.assign(cs))
    if unk:
        bad.append(f'EV2 git names rounds ORDER does not list: {unk}')
    if ev.unknown_rounds({'a': 'R99', 'b': 'pending', 'c': ev.ORDER[-1]}) != ['R99']:
        bad.append('EV3 unknown_rounds must name R99 only')
    if ev.unknown_rounds({'b': 'pending'}) != []:
        bad.append("EV3 'pending' is always known")
    return bad


MUTATIONS = [
    ('R24 dropped from ORDER', "+ ['R23b', 'R23c', 'R24']\n", "+ ['R23b', 'R23c']\n"),
    ('unknown_rounds names nothing', "    return sorted({r for r in rnd.values() if r != 'pending' and r not in ORDER})",
     "    return []"),
    ('pending counted as unknown', "if r != 'pending' and r not in ORDER", "if r not in ORDER"),
]


def main():
    ev = load(SRC)
    bad = kats(ev)
    for b in bad:
        print('FAIL', b)
    if bad:
        return 3
    print('ok   EV1-EV3')
    src = SRC.read_text(encoding='utf-8')
    missed = 0
    for name, a, b in MUTATIONS:
        if src.count(a) != 1:
            print('INVALID', name, '(find text count', src.count(a), ')')
            missed += 1
            continue
        with tempfile.TemporaryDirectory() as d:
            dm = Path(d) / 'miners'
            dm.mkdir()
            for f in (HARNESS / 'miners').glob('*.py'):
                shutil.copy2(f, dm / f.name)
            (dm / 'mine_evolution.py').write_text(src.replace(a, b, 1), encoding='utf-8')
            try:
                r = kats(load(dm / 'mine_evolution.py'))
            except Exception as e:
                print('INVALID', name, type(e).__name__, e)
                missed += 1
                continue
        print('CAUGHT' if r else 'MISSED', name, (r[:1] if r else ''))
        missed += 0 if r else 1
    print(f'r24 evolution-order KATs: 3/3 ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
