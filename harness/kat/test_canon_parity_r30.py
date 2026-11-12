#!/usr/bin/env python3
"""test_canon_parity_r30.py — r30 merge (rft §7 B208; tooling_intel kat_coverage found it without a KAT): the Go ==
Python canonicality parity tool harness/forensics/canon_parity_r30.py, and its committed record.

  CP1 B208  compare(): equal views PASS; one Go error, one differing body, or no bodies at all FAIL; totals add up
  CP2 B208  the committed record harness/runtime/r30_genesis_canon_parity.json is PASS over 1,796 bodies, all equal,
            0 Go errors, differ empty

  python3 -I harness/kat/test_canon_parity_r30.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, importlib.util, io, json, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'cp': 'harness/forensics/canon_parity_r30.py'}
RECORD = ROOT / 'harness/runtime/r30_genesis_canon_parity.json'


def load(over):
    sys.path.insert(0, str(ROOT / 'harness/forensics'))
    spec = importlib.util.spec_from_file_location('cp30', Path(over.get('cp') or (ROOT / PATHS['cp'])))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def kat_cp1(over):
    C = load(over)
    views = {b'a': (3, 2, {}), b'b': (0, 0, {}), b'c': (5, 1, {'scalar_ge_order': 1})}
    C.A2 = type('A2', (), {'struct_tx': staticmethod(lambda b, P, N: dict(zip(('points', 'scalars', 'checks'), views[b])))})
    bodies = [('t1', b'a'), ('t2', b'b'), ('t3', b'c')]
    go = lambda b: {'ok': True, 'cp': views[b][0], 'cs': views[b][1], 'cf': views[b][2]}
    good = C.compare(bodies, [go(b) for _, b in bodies], 0, 0)
    err = C.compare(bodies, [go(b'a'), {'ok': False}, go(b'c')], 0, 0)
    bad = C.compare(bodies, [go(b'a'), go(b'b'), {**go(b'c'), 'cs': 2}], 0, 0)
    empty = C.compare([], [], 0, 0)
    ok = (good['verdict'] == 'PASS' and good['equal'] == 3 and good['proof_carrying'] == 2 and good['points'] == 8
          and good['scalars'] == 3 and good['failed'] == {'scalar_ge_order': 1}
          and err['verdict'] == 'FAIL' and err['go_errors'] == 1 and err['differ'] == ['t2'] and bad['verdict'] == 'FAIL' and bad['differ'] == ['t3']
          and empty['verdict'] == 'FAIL')
    return ok, (good['verdict'], err['verdict'], bad['verdict'], empty['verdict'])


def kat_cp2(over):
    r = json.loads(RECORD.read_text())
    ok = (r.get('verdict') == 'PASS' and r.get('bodies') == 1796 == r.get('equal') and r.get('go_errors') == 0
          and not r.get('differ') and r.get('proof_carrying') == 1560)
    return ok, {k: r.get(k) for k in ('verdict', 'bodies', 'equal', 'go_errors', 'proof_carrying')}


KATS = [('CP1', kat_cp1), ('CP2', kat_cp2)]
OWNERS = {'B208': ['CP1', 'CP2']}
MUTATIONS = [
    ('cp', "        if g == p:\n", "        if True:\n", 'B208: a differing body counted equal'),
    ('cp', "            res['go_errors'] += 1\n            res['differ'].append(t[:8])\n", "            res['go_errors'] += 1\n",
     'B208: a Go error is not a difference'),
    ('cp', "and res['equal'] == res['bodies'] and res['bodies'] else 'FAIL'", "else 'FAIL'", 'B208: no bodies (or unequal counts) PASS'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_cp30', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run_kats(over):
    res = []
    for name, fn in KATS:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                ok, det = fn(over)
        except (Exception, SystemExit) as e:                      # noqa: BLE001 — a crash is a failure
            ok, det = False, f'{type(e).__name__}: {e}'
        res.append((name, ok, str(det)))
    return res


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr30 canon-parity KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='cp30-mut-') as d:
            mut = Path(d) / Path(PATHS[key]).name
            mut.write_text(text.replace(find, repl), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, _ = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r30 canon-parity KATs', len(KATS), len(MUTATIONS), missed, 0))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
