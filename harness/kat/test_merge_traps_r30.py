#!/usr/bin/env python3
"""test_merge_traps_r30.py — r30 merge (rft §7 B246, B247): two operator traps the v5 registration hit, closed at their cause.

  MT1 B246  audit2.stage_dirs fails CLOSED: an unexpanded '~' (bash leaves '~' after a colon: 'A:~/x'), a missing dir and
            a dir without txs/ each raise; good dirs pass in order; an empty --stage is []
  MT2 B246  audit2 run returns 'FAIL: ...' (CLI exit 3) for a bad --stage before reading any store
  MT3 B247  regen_round STEPS runs `soundpage.py --write-known` after --write-gen and before gen_index / --check-measured
            (G30/G31 fail on dero-soundness-r<N>.html without the dataset section)

  python3 -I harness/kat/test_merge_traps_r30.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, importlib.util, io, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'a2': 'harness/forensics/audit2.py', 'regen': 'harness/pipeline/regen_round.py'}


def load(over, key, name):
    p = Path(over.get(key) or (ROOT / PATHS[key]))
    if key == 'a2':
        sys.path.insert(0, str(ROOT / 'harness/forensics'))   # audit2 imports its sibling audit_check
    spec = importlib.util.spec_from_file_location(name, p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def raises(f, *a):
    try:
        f(*a)
    except ValueError:
        return True
    return False


def kat_mt1(over):
    A = load(over, 'a2', 'a2_mt1')
    with tempfile.TemporaryDirectory() as d:
        g1, g2, bare = Path(d, 'g1'), Path(d, 'g2'), Path(d, 'bare')
        for p in (g1 / 'txs', g2 / 'txs', bare):
            p.mkdir(parents=True)
        ok = (A.stage_dirs(f'{g1}:{g2}') == [str(g1), str(g2)] and A.stage_dirs(None) == [] and A.stage_dirs('') == []
              and raises(A.stage_dirs, f'{g1}:~/forensics_raw_r29/stage_b97') and raises(A.stage_dirs, f'{g1}:{d}/nope')
              and raises(A.stage_dirs, str(bare)))
        # a literal '~' directory in the cwd (what 'A:~/x' names when bash leaves it) must still be refused
        Path(d, '~', 'x', 'txs').mkdir(parents=True)
        cwd = Path.cwd()
        try:
            import os
            os.chdir(d)
            ok = ok and raises(A.stage_dirs, f'{g1}:~/x')
        finally:
            os.chdir(cwd)
        return ok, 'stage_dirs'


def kat_mt2(over):
    A = load(over, 'a2', 'a2_mt2')
    with tempfile.TemporaryDirectory() as d:
        R = A.run(d, ROOT, d, d, None, '~/stage', None, None, 1)
        return str(R.get('result', '')).startswith('FAIL: --stage'), R.get('result')


def kat_mt3(over):
    R = load(over, 'regen', 'regen_mt3')
    names = [' '.join(s) for s in R.STEPS]
    try:
        i = names.index('harness/kit/soundpage.py --write-known')
    except ValueError:
        return False, 'no --write-known step'
    return (names.index('harness/kit/soundpage.py --write-gen') < i < names.index('harness/gen_index.py')
            and i < names.index('harness/kit/soundpage.py --check-measured')), names[i - 1:i + 2]


KATS = [('MT1', kat_mt1), ('MT2', kat_mt2), ('MT3', kat_mt3)]
OWNERS = {'B246': ['MT1', 'MT2'], 'B247': ['MT3']}
MUTATIONS = [
    ('a2', "        if sd.startswith('~'):\n            raise ValueError(f'--stage {sd!r}: unexpanded ~ (write an absolute path)')\n", "",
     'B246: an unexpanded ~ is accepted'),
    ('a2', "        if not Path(sd, 'txs').is_dir():\n            raise ValueError(f'--stage {sd!r}: no such stage dir (or no txs/ in it)')\n",
     "        if not Path(sd, 'txs').is_dir():\n            continue\n", 'B246: a missing stage dir is skipped silently'),
    ('a2', "    except ValueError as e:\n        R['result'] = f'FAIL: {e}'\n        return R\n", "    except ValueError as e:\n        sds = []\n",
     'B246: run goes on after a bad --stage'),
    ('regen', "            ['harness/kit/soundpage.py', '--write-known'],", "", 'B247: regen_round without the --write-known step'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_mt30', HARNESS / 'kit' / 'katmut.py')
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
        print(f'\nr30 merge-traps KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='mt30-mut-') as d:
            mut = Path(d) / Path(PATHS[key]).name
            mut.write_text(text.replace(find, repl), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, _ = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r30 merge-traps KATs', len(KATS), len(MUTATIONS), missed, 0))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
