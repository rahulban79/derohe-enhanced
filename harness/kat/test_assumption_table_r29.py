#!/usr/bin/env python3
"""test_assumption_table_r29.py — r29 (rft §7 B190; found at the R29 merge by TK1/TK21: the builder had no --help and
no KAT): harness/model/evidence/r29_assumption_table_build.py stays the source of the committed r29 assumption table.

  AT1 the builder, run in a sandbox copy (itself + the r28d table), writes r29_assumption_table.{json,md} byte-equal to
      the committed files, with counts 16 DISCHARGED / 3 VIOLATED / 2 UNCLEAR
  AT2 --help prints its usage and writes nothing

  python3 -I harness/kat/test_assumption_table_r29.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 missed
"""
import contextlib, importlib.util, io, json, shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
EV = 'harness/model/evidence'
PATHS = {'builder': f'{EV}/r29_assumption_table_build.py'}


def sandbox(over, d):
    d = Path(d)
    shutil.copy(Path(over.get('builder') or (ROOT / PATHS['builder'])), d / 'r29_assumption_table_build.py')
    shutil.copy(ROOT / EV / 'r28d_assumption_table.json', d / 'r28d_assumption_table.json')
    return d / 'r29_assumption_table_build.py'


def kat_at1(over):
    with tempfile.TemporaryDirectory() as d:
        b = sandbox(over, d)
        r = subprocess.run([sys.executable, '-I', str(b)], capture_output=True, text=True, timeout=60)
        j, m = Path(d) / 'r29_assumption_table.json', Path(d) / 'r29_assumption_table.md'
        if r.returncode != 0 or not j.exists():
            return False, f'rc {r.returncode} {r.stderr[-200:]}'
        same = (j.read_bytes() == (ROOT / EV / 'r29_assumption_table.json').read_bytes(),
                m.read_bytes() == (ROOT / EV / 'r29_assumption_table.md').read_bytes())
        counts = json.loads(j.read_text())['counts']
    return same == (True, True) and counts == {'DISCHARGED': 16, 'VIOLATED': 3, 'UNCLEAR': 2}, (same, counts)


def kat_at2(over):
    with tempfile.TemporaryDirectory() as d:
        b = sandbox(over, d)
        r = subprocess.run([sys.executable, '-I', str(b), '--help'], capture_output=True, text=True, timeout=60)
        wrote = sorted(p.name for p in Path(d).iterdir() if p.name.startswith('r29_assumption_table.'))
    return r.returncode == 0 and 'r29 (rft §7 B190)' in r.stdout and not wrote, (r.returncode, wrote)


KATS = [('AT1', kat_at1), ('AT2', kat_at2)]
OWNERS = {'B190': ['AT1', 'AT2']}
MUTATIONS = [
    ('builder', "        elif r['id'] == 'A18':\n            r = A18", "        elif False:\n            r = A18",
     'B190: the A18 re-grade is not applied'),
    ('builder', "if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:2]):",
     "if False:", 'B190: --help builds and writes the table'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_at29', HARNESS / 'kit' / 'katmut.py')
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
        print(f'\nr29 assumption-table KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='at29-mut-') as d:
            mut = Path(d) / 'r29_assumption_table_build.py'
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, _ = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r29 assumption-table KATs', len(KATS), len(MUTATIONS), missed, 0))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
