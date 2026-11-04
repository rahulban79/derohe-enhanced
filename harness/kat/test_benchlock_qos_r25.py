#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for benchlock --qos (r25 perfops, backlog B20: agent QoS). No live file is
written: the lock file and a fake `taskpolicy` live in a temp dir; the command runs only `python3 -c` children.

  BQ1 parse_opts: leading --gpu and --qos=X in either order, then '--'; a command that itself starts with '--x' is
      left alone (as before r25); $DERO_BENCH_QOS is the default and --qos overrides it; no option = ('none').
  BQ2 child_argv: none = exactly the pre-r25 ['nice','-n','15', cmd...] (also without taskpolicy); utility =
      taskpolicy -c utility around nice 15; background = taskpolicy -b around nice 15; an unknown value and a clamp on
      a system without taskpolicy are refused (None), never silently dropped.
  BQ3 main end to end (temp lock, a fake taskpolicy first on PATH that logs its argv then execs the rest): --qos=utility
      reaches taskpolicy with '-c utility' and the command runs at nice 15; the default never calls taskpolicy and
      still runs at nice 15; an unknown --qos exits 2 before the lock is opened and never runs the command; the
      command's exit code is returned.

  python3 -I harness/kat/test_benchlock_qos_r25.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import importlib.util, os, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
SRC = HARNESS / 'pipeline/benchlock.py'


def load(path):
    spec = importlib.util.spec_from_file_location(f'benchlock_{abs(hash(str(path)))}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def bq1(path):
    b = load(path)
    saved = os.environ.pop('DERO_BENCH_QOS', None)
    try:
        cases = [
            (['--gpu', '--qos=utility', '--', 'echo', 'x'], (True, 'utility', ['echo', 'x'])),
            (['--qos=background', '--gpu', 'cmd'], (True, 'background', ['cmd'])),
            (['--', '--x', 'y'], (False, 'none', ['--x', 'y'])),
            (['--x', 'y'], (False, 'none', ['--x', 'y'])),
            (['cmd', '--qos=utility'], (False, 'none', ['cmd', '--qos=utility'])),
            ([], (False, 'none', [])),
        ]
        bad = [(a, b.parse_opts(list(a)), w) for a, w in cases if b.parse_opts(list(a)) != w]
        os.environ['DERO_BENCH_QOS'] = 'utility'
        env = b.parse_opts(['cmd'])
        over = b.parse_opts(['--qos=none', 'cmd'])
    finally:
        os.environ.pop('DERO_BENCH_QOS', None)
        if saved is not None:
            os.environ['DERO_BENCH_QOS'] = saved
    ok = not bad and env == (False, 'utility', ['cmd']) and over == (False, 'none', ['cmd'])
    return ok, f'bad={bad} env={env} over={over}'


def bq2(path):
    b = load(path)
    got = {
        'none': b.child_argv(['c', 'a'], 'none', have_taskpolicy=True),
        'none-no-tp': b.child_argv(['c'], 'none', have_taskpolicy=False),
        'utility': b.child_argv(['c'], 'utility', have_taskpolicy=True),
        'background': b.child_argv(['c'], 'background', have_taskpolicy=True),
        'utility-no-tp': b.child_argv(['c'], 'utility', have_taskpolicy=False),
        'bogus': b.child_argv(['c'], 'Utility', have_taskpolicy=True),
    }
    want = {
        'none': ['nice', '-n', '15', 'c', 'a'], 'none-no-tp': ['nice', '-n', '15', 'c'],
        'utility': ['taskpolicy', '-c', 'utility', 'nice', '-n', '15', 'c'],
        'background': ['taskpolicy', '-b', 'nice', '-n', '15', 'c'], 'utility-no-tp': None, 'bogus': None,
    }
    diff = {k: got[k] for k in want if got[k] != want[k]}
    return not diff, f'diff={diff}'


FAKE_TP = '''#!/bin/sh
echo "$@" >> "$TP_LOG"
shift
[ "$1" = utility ] && shift
exec "$@"
'''


def bq3(path):
    d = Path(tempfile.mkdtemp(prefix='bq3_'))
    try:
        (d / 'bin').mkdir()
        tp = d / 'bin/taskpolicy'
        tp.write_text(FAKE_TP)
        tp.chmod(0o755)
        env = dict(os.environ, DERO_BENCHLOCK=str(d / 'lock'), TP_LOG=str(d / 'tp.log'), PATH=f"{d / 'bin'}:{os.environ['PATH']}")
        env.pop('DERO_BENCH_QOS', None)
        child = [sys.executable, '-c', 'import os,sys; open(sys.argv[1],"a").write(str(os.getpriority(os.PRIO_PROCESS,0))+"\\n"); sys.exit(int(sys.argv[2]))']

        def run(opts, marker, code):
            return subprocess.run([sys.executable, '-I', str(path), *opts, '--', *child, str(d / marker), str(code)],
                                  env=env, capture_output=True, text=True, timeout=60)
        # the niceness nice -n 15 gives a child of this process (the cap differs by OS)
        want_nice = subprocess.run(['nice', '-n', '15', sys.executable, '-c', 'import os; print(os.getpriority(os.PRIO_PROCESS, 0))'],
                                   capture_output=True, text=True).stdout.strip()
        r1 = run(['--qos=utility'], 'm1', 0)
        tp1 = (d / 'tp.log').read_text() if (d / 'tp.log').exists() else ''
        n1 = (d / 'm1').read_text().strip() if (d / 'm1').exists() else ''
        r2 = run([], 'm2', 5)
        tp2 = (d / 'tp.log').read_text() if (d / 'tp.log').exists() else ''
        n2 = (d / 'm2').read_text().strip() if (d / 'm2').exists() else ''
        (d / 'lock').unlink(missing_ok=True)
        r3 = run(['--qos=bogus'], 'm3', 0)
        ok = (r1.returncode == 0 and tp1.startswith('-c utility nice -n 15 ') and n1 == want_nice
              and r2.returncode == 5 and tp2 == tp1 and n2 == want_nice
              and r3.returncode == 2 and not (d / 'm3').exists() and not (d / 'lock').exists())
        return ok, (f'rc={r1.returncode},{r2.returncode},{r3.returncode} tp1={tp1!r} nice={n1},{n2} want={want_nice} '
                    f'm3={(d / "m3").exists()} lock3={(d / "lock").exists()} err={r1.stderr[-200:]!r}')
    finally:
        shutil.rmtree(d, ignore_errors=True)


KATS = [('BQ1', bq1), ('BQ2', bq2), ('BQ3', bq3)]

MUTATIONS = [
    ('BQ1', "        elif argv[0].startswith('--qos='):\n            qos = argv[0][len('--qos='):]\n",
     "        elif argv[0].startswith('--qos='):\n            pass\n", '--qos ignored'),
    ('BQ1', "    gpu, qos = False, os.environ.get('DERO_BENCH_QOS') or 'none'\n",
     "    gpu, qos = False, 'none'\n", 'env default ignored'),
    ('BQ1', "        else:\n            break\n", "        else:\n            pass\n", 'unknown leading --x swallowed'),
    ('BQ2', "    if qos not in QOS:\n        return None\n", "    if qos not in QOS:\n        qos = 'none'\n",
     'unknown qos silently dropped'),
    ('BQ2', "        if not have_taskpolicy:\n            return None\n", "        if not have_taskpolicy:\n            return ['nice', '-n', '15'] + list(cmd)\n",
     'missing taskpolicy silently drops the clamp'),
    ('BQ2', "'utility': ['taskpolicy', '-c', 'utility']", "'utility': ['taskpolicy', '-b']", 'utility mapped to background'),
    ('BQ2', "    return QOS[qos] + ['nice', '-n', '15'] + list(cmd)\n", "    return QOS[qos] + list(cmd)\n", 'nice 15 dropped'),
    ('BQ3', "        rc = subprocess.call(child)\n", "        rc = subprocess.call(['nice', '-n', '15'] + argv)\n",
     'main ignores the clamp'),
    ('BQ3', "    child = child_argv(argv, qos)\n    if child is None:\n",
     "    child = child_argv(argv, qos) or ['nice', '-n', '15'] + argv\n    if child is None:\n", 'refusal bypassed in main'),
]


def main():
    fails = 0
    for name, fn in KATS:
        try:
            ok, det = fn(SRC)
        except Exception as e:                                      # noqa: BLE001
            ok, det = False, f'{type(e).__name__}: {e}'
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:500]}")
    missed, byname = 0, dict(KATS)
    text = SRC.read_text()
    for kat, find, repl, why in MUTATIONS:
        d = Path(tempfile.mkdtemp(prefix='bqmut_'))
        p = d / 'benchlock.py'
        try:
            if text.count(find) != 1:
                print(f'  ??      {kat}: {why} — find text occurs {text.count(find)} times')
                missed += 1
                continue
            p.write_text(text.replace(find, repl))
            try:
                load(p)
            except Exception as e:                                  # noqa: BLE001
                print(f'  INVALID {kat}: {why} — mutant does not load ({type(e).__name__})')
                missed += 1
                continue
            try:
                ok2 = byname[kat](p)[0]
            except Exception:                                      # noqa: BLE001 — a crash is a detection
                ok2 = False
            print(f"  {'proved ' if not ok2 else 'MISSED '} {kat}: {why}")
            missed += ok2
        finally:
            shutil.rmtree(d, ignore_errors=True)
    print(f'\nr25 benchlock-qos KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
