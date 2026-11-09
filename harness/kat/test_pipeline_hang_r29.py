#!/usr/bin/env python3
"""test_pipeline_hang_r29.py — r29 (rft §5 long-job liveness; user 2026-11-08 "... make sure to further enhance the
harness, tools, skills, pipeline"): fix_build_verify bounds every command (sh -> kit/hangkit.run_bounded) and every S7
step (a hard limit derived from its STEP_BUDGETS row), and a step past its limit is reported HUNG with a diagnosis
instead of a pipeline that waits without end.

  PH1 step_timeout = max(3 x row, row + 300); the default row for an unlisted step; run ids normalised; 2400 without kit
  PH2 run_step on a fake hanging step (its grandchild inherited stdout) returns hung {timeout, diagnosis, tail} within
      the bound, the 'hang' event is recorded, and no process of the step's group is left (bounded by hangkit.within)
  PH3 run_step passes a normal step's (rc, out, err) through and re-raises an error that is not a hang
  PH5 _hangkit is loaded once: sh()'s Hung is the class S7's run_step checks (two loads = two classes = a traceback)
  PH4 S7 and S3k wire it: the limit comes from step_timeout, the step runs through run_step, a hung step FAILs why=HUNG

  python3 -I harness/kat/test_pipeline_hang_r29.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 missed
"""
import ast, contextlib, importlib, importlib.util, io, os, signal, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'fbv': 'harness/pipeline/fix_build_verify.py'}
NAMES = ['_hangkit', 'sh', 'step_timeout', 'run_step']


def P(over):
    return Path(over.get('fbv') or (ROOT / PATHS['fbv']))


def extract(over, events):
    tree = ast.parse(P(over).read_text(encoding='utf-8'))
    body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in NAMES]
    ns = {'Path': Path, 'sys': sys, 'os': os, 'subprocess': subprocess, 'importlib': importlib, 'HARNESS': HARNESS,
          'ROOT': ROOT, 'event': lambda *a, **k: events.append((a, k))}
    exec(compile(ast.Module(body=body, type_ignores=[]), str(P(over)), 'exec'), ns)   # noqa: S102 — this repo's own code
    return ns


def HK():
    spec = importlib.util.spec_from_file_location('hangkit_ph29', HARNESS / 'kit/hangkit.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def kat_ph1(over):
    F, hk = extract(over, []), HK()
    b = {'default_s': 60, 'steps': {'harness/x.py': 100, 'harness/run_gates.py pipeline-<TS>': 50}}
    v = (F['step_timeout']('harness/x.py', b, hk), F['step_timeout']('harness/other.py', b, hk),
         F['step_timeout']('harness/run_gates.py pipeline-20261108T010203', b, hk), F['step_timeout']('harness/x.py', b, None))
    return v == (400, 360, 350, 2400), v


def kat_ph2(over):
    ev = []
    F = extract(over, ev)
    hk = F['_hangkit']()                                 # the pipeline's own (cached) kit, as S7 uses it
    with tempfile.TemporaryDirectory() as d:
        s = Path(d) / 'hangstep.py'
        s.write_text("import subprocess, sys, time\nprint('fake step running', flush=True)\n"
                     "g = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(120)'])\n"
                     f"open({str(Path(d) / 'gpid')!r}, 'w').write(str(g.pid))\ntime.sleep(120)\n")
        t0 = time.monotonic()
        done, r, e = hk.within(lambda: F['run_step']([sys.executable, '-I', str(s)], 2, F['sh'], hk), 45)
        took = time.monotonic() - t0
        time.sleep(0.5)
        try:
            g = int((Path(d) / 'gpid').read_text())
            try:
                os.kill(g, 0)
                left = True
                os.kill(g, signal.SIGKILL)
            except ProcessLookupError:
                left = False
        except (OSError, ValueError):
            left = None
    hung = r[3] if done and r else None
    ok = (done and e is None and r[0] is None and hung and hung['timeout'] == 2 and hung['diagnosis']
          and 'fake step running' in hung['tail'] and any(a[0][:2] == ('hang', 'INFO') for a in ev) and left is False)
    return bool(ok), (done, e, hung and {k: str(v)[:60] for k, v in hung.items()}, len(ev), left, round(took, 1))


def kat_ph3(over):
    F = extract(over, [])
    hk = F['_hangkit']()
    a = F['run_step']([sys.executable, '-I', '-c', 'print(5)'], 30, F['sh'], hk)

    def boom(st, timeout):
        raise ValueError('not a hang')
    try:
        F['run_step'](['x'], 30, boom, hk)
        b = 'swallowed'
    except ValueError:
        b = 'raised'
    return a[0] == 0 and a[1].strip() == '5' and a[3] is None and b == 'raised', (a, b)


def kat_ph4(over):
    tree = ast.parse(P(over).read_text(encoding='utf-8'))
    s7 = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 's7_project')
    src = ast.unparse(s7)
    need = ["limit = step_timeout(' '.join(st[1:3]), _budgets, _HK)", 'run_step(st, limit, sh, _HK)', "why='HUNG'"]
    miss = [n for n in need if n not in src]
    s3k = ast.unparse(next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 's3k_kats'))
    miss += [f's3k: {n}' for n in ('limit = step_timeout(str(p.relative_to(ROOT)), _budgets, _HK)',
                                   "run_step([sys.executable, '-I', str(p)], limit, sh, _HK)", "why='HUNG'") if n not in s3k]
    return not miss, miss


def kat_ph5(over):
    F = extract(over, [])
    a, b = F['_hangkit'](), F['_hangkit']()
    return a is b and a is not None, (a is b)


KATS = [('PH1', kat_ph1), ('PH2', kat_ph2), ('PH3', kat_ph3), ('PH4', kat_ph4), ('PH5', kat_ph5)]
OWNERS = {'r29 pipeline-hang': [k for k, _ in KATS]}
MUTATIONS = [
    ('fbv', "        return HK.run_bounded(cmd, timeout, cwd=cwd, env=env, shell=isinstance(cmd, str))",
     "        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, shell=isinstance(cmd, str), env=env)\n"
     "        return r.returncode, r.stdout, r.stderr", 'r29 pipeline-hang: sh is plain subprocess.run again'),
    ('fbv', "    if hasattr(_hangkit, 'mod'):\n        return _hangkit.mod", "    if False:\n        return _hangkit.mod",
     'r29 pipeline-hang: the kit is loaded per call (sh and S7 hold different Hung classes)'),
    ('fbv', "    return hk.budget_timeout(b)", "    return 2400", 'r29 pipeline-hang: the step limit ignores STEP_BUDGETS'),
    ('fbv', "        if hk is None or not isinstance(e, hk.Hung):\n            raise", "        if True:\n            raise",
     'r29 pipeline-hang: a hung step is a traceback, not a verdict'),
    ('fbv', "        limit = step_timeout(' '.join(st[1:3]), _budgets, _HK)", "        limit = 2400",
     'r29 pipeline-hang: S7 keeps the fixed 2400 s limit'),
    ('fbv', "        limit = step_timeout(str(p.relative_to(ROOT)), _budgets, _HK)", "        limit = 1800",
     'r29 pipeline-hang: S3k keeps the fixed 1800 s limit'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_ph29', HARNESS / 'kit' / 'katmut.py')
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
        print(f'\nr29 pipeline hang KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
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
        with tempfile.TemporaryDirectory(prefix='ph29-mut-') as d:
            mut = Path(d) / PATHS[key]
            mut.parent.mkdir(parents=True, exist_ok=True)
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, _ = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r29 pipeline hang KATs', len(KATS), len(MUTATIONS), missed, 0))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
