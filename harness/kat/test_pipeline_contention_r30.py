#!/usr/bin/env python3
"""test_pipeline_contention_r30.py — r30 post-close (B252f; user §2.29 "make sure to tweak your harness for this change
for this round alone - so that you can give the verdict"): the S3k/S7 liveness hard limit scales by the CPU contention
the pipeline measures at the stage start. pipeline_20261113T003909 FAILED HUNG at 544 s of 540 on a 180 s row with the
lever-run miner on 18 of 20 cores; the same KAT passed standalone in 633 s. No gate, KAT threshold or STEP_BUDGETS row
changes: only the hard limit stretches, capped at x3, and an unknown census never stretches it.

  PC1 contention_factor: quiet box (0.8 cores busy) 1.04; 18.83 of 20 cores busy -> 3.0 (cap); 10 of 20 -> 2.0; failed census / no ncpu /
      garbage -> 1.0; never below 1.0
  PC2 step_timeout(row 180, factor 2.0) = 2 x 540; factor 1.0 keeps the r29 values; factor < 1 never shortens the limit
  PC3 S3k and S7 take one census (ab_census), derive _cf with contention_factor, record it in an INFO event, and pass
      _cf to step_timeout

  python3 -I harness/kat/test_pipeline_contention_r30.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 missed
"""
import ast, contextlib, importlib.util, io, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'fbv': 'harness/pipeline/fix_build_verify.py'}
NAMES = ['contention_factor', 'step_timeout']


def P(over):
    return Path(over.get('fbv') or (ROOT / PATHS['fbv']))


def extract(over):
    tree = ast.parse(P(over).read_text(encoding='utf-8'))
    body = [n for n in tree.body if (isinstance(n, ast.FunctionDef) and n.name in NAMES) or
            (isinstance(n, ast.Assign) and any(getattr(t, 'id', '') == 'CONTENTION_FACTOR_MAX' for t in n.targets))]
    ns = {}
    exec(compile(ast.Module(body=body, type_ignores=[]), str(P(over)), 'exec'), ns)   # noqa: S102 — this repo's own code
    return ns


def HK():
    spec = importlib.util.spec_from_file_location('hangkit_pc30', HARNESS / 'kit/hangkit.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def kat_pc1(over):
    f = extract(over)['contention_factor']
    v = (f({'ncpu': 20, 'miner_cores': 0.2, 'foreign_cores': 0.5, 'node_cores': 0.1}),
         f({'ncpu': 20, 'miner_cores': 18.02, 'foreign_cores': 0.63, 'node_cores': 0.18}),
         f({'ncpu': 20, 'miner_cores': 9.0, 'foreign_cores': 0.5, 'node_cores': 0.5}),
         f({'contended': None, 'why': 'census failed'}), f({}), f(None), f({'ncpu': 'x'}),
         f({'ncpu': 20, 'miner_cores': -40}))
    return v == (1.04, 3.0, 2.0, 1.0, 1.0, 1.0, 1.0, 1.0), v


def kat_pc2(over):
    st, hk = extract(over)['step_timeout'], HK()
    b = {'default_s': 60, 'steps': {'harness/kat/test_resource_hygiene_r27.py': 180}}
    k = 'harness/kat/test_resource_hygiene_r27.py'
    v = (st(k, b, hk, 2.0), st(k, b, hk), st(k, b, hk, 1.0), st(k, b, hk, 0.5), st('harness/other.py', b, hk, 3.0))
    return v == (1080, 540, 540, 540, 1080), v


def kat_pc3(over):
    tree = ast.parse(P(over).read_text(encoding='utf-8'))
    miss = []
    for fn, call in (('s7_project', "step_timeout(' '.join(st[1:3]), _budgets, _HK, _cf)"),
                     ('s3k_kats', 'step_timeout(str(p.relative_to(ROOT)), _budgets, _HK, _cf)')):
        src = ast.unparse(next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == fn))
        for need in ('_census = ab_census()', '_cf = contention_factor(_census)', 'contention_factor=_cf', call):
            if need not in src:
                miss.append(f'{fn}: {need}')
    return not miss, miss


KATS = [('PC1', kat_pc1), ('PC2', kat_pc2), ('PC3', kat_pc3)]
OWNERS = {'r30 pipeline-contention': [k for k, _ in KATS]}
MUTATIONS = [
    ('fbv', "    return round(min(CONTENTION_FACTOR_MAX, max(1.0, n / max(1.0, n - busy))), 2)",
     "    return round(max(1.0, n / max(1.0, n - busy)), 2)", 'r30 pipeline-contention: the factor is not capped'),
    ('fbv', "    return round(min(CONTENTION_FACTOR_MAX, max(1.0, n / max(1.0, n - busy))), 2)",
     "    return round(min(CONTENTION_FACTOR_MAX, n / max(1.0, n - busy)), 2)", 'r30 pipeline-contention: the factor can shorten a limit'),
    ('fbv', "    except (AttributeError, TypeError, ValueError):\n        return 1.0\n    if n <= 0:",
     "    except (AttributeError, TypeError, ValueError):\n        return CONTENTION_FACTOR_MAX\n    if n <= 0:",
     'r30 pipeline-contention: a failed census stretches the limit on a guess'),
    ('fbv', "    return round(hk.budget_timeout(b) * max(1.0, float(factor)), 1)", "    return hk.budget_timeout(b)",
     'r30 pipeline-contention: step_timeout ignores the factor'),
    ('fbv', "    return round(hk.budget_timeout(b) * max(1.0, float(factor)), 1)",
     "    return round(hk.budget_timeout(b) * float(factor), 1)", 'r30 pipeline-contention: a factor < 1 shortens the limit'),
    ('fbv', "        limit = step_timeout(' '.join(st[1:3]), _budgets, _HK, _cf)",
     "        limit = step_timeout(' '.join(st[1:3]), _budgets, _HK)", 'r30 pipeline-contention: S7 does not pass the factor'),
    ('fbv', "        limit = step_timeout(str(p.relative_to(ROOT)), _budgets, _HK, _cf)",
     "        limit = step_timeout(str(p.relative_to(ROOT)), _budgets, _HK)", 'r30 pipeline-contention: S3k does not pass the factor'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_pc30', HARNESS / 'kit' / 'katmut.py')
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
        print(f'\nr30 pipeline contention KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = 0
    for key, find, repl, why in MUTATIONS:
        src = ROOT / PATHS[key]
        text = src.read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='pc30-mut-') as d:
            mut = Path(d) / PATHS[key]
            mut.parent.mkdir(parents=True, exist_ok=True)
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, _ = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r30 pipeline contention KATs', len(KATS), len(MUTATIONS), missed, 0))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
