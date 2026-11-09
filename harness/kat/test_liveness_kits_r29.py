#!/usr/bin/env python3
"""test_liveness_kits_r29.py — r29 (rft §5 long-job liveness; user 2026-11-08 "make sure to fix anything you find
tasks are stuck at ... further enhance the harness, tools, skills, pipeline"): the shared kits harness/kit/hangkit.py
and harness/kit/coproc.py turn every hang class seen in the B182 run into a bounded, diagnosed failure.

  HK1 within: a fast fn -> (True, result); a 3 s fn under a 0.5 s limit -> not finished; an exception is handed back
  HK2 run_bounded: a normal command returns (rc, out, err)
  HK3 run_bounded on a step whose grandchild inherited stdout raises Hung within the limit and leaves no process of
      the group alive — while the OLD shape (subprocess.run(capture_output=True, timeout=2)) leaves the grandchild
      running (the control; on Python 3.14 run() kills the direct child only and waits for it alone)
  HK4 the Hung diagnosis names leaf frames (macOS `sample`) and keeps the step's last output line
  HK5 budget_timeout = max(3 x budget, budget + 300)
  CP1 coproc: 200 x 64 KB in and 200 x 64 KB out in one roundtrip completes (pipe-deadlock class 1)
  CP2 coproc: a co-process that never answers raises CoProcTimeout; one that exits raises CoProcEOF

  python3 -I harness/kat/test_liveness_kits_r29.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 missed
"""
import contextlib, importlib.util, io, os, signal, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'hangkit': 'harness/kit/hangkit.py', 'coproc': 'harness/kit/coproc.py'}


def mod(over, key):
    spec = importlib.util.spec_from_file_location(f'{key}_lk29_{len(sys.modules)}', Path(over.get(key) or (ROOT / PATHS[key])))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def kat_hk1(over):
    HK = mod(over, 'hangkit')
    a = HK.within(lambda: 7, 5)
    t0 = time.monotonic()
    b = HK.within(lambda: time.sleep(3), 0.5)
    fast = time.monotonic() - t0 < 2
    c = HK.within(lambda: 1 / 0, 5)
    return a == (True, 7, None) and b[0] is False and fast and isinstance(c[2], ZeroDivisionError), (a, b, fast, c[2])


def kat_hk2(over):
    HK = mod(over, 'hangkit')
    r = HK.run_bounded([sys.executable, '-I', '-c', 'import sys; print("hi"); sys.exit(3)'], 30)
    return r[0] == 3 and r[1].strip() == 'hi', r


def hanging_step(d):
    """a step that prints, starts a grandchild holding stdout (writes its pid), then sleeps."""
    s = Path(d) / 'hangstep.py'
    s.write_text("import subprocess, sys, time\nprint('step started', flush=True)\n"
                 f"g = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(120)'])\n"
                 f"open({str(Path(d) / 'gpid')!r}, 'w').write(str(g.pid))\ntime.sleep(120)\n")
    return [sys.executable, '-I', str(s)]


def kat_hk3(over):
    HK = mod(over, 'hangkit')
    with tempfile.TemporaryDirectory() as d:
        t0 = time.monotonic()
        try:
            HK.run_bounded(hanging_step(d), 2)
            raised = None
        except HK.Hung as e:
            raised = e
        took = time.monotonic() - t0
        time.sleep(0.5)
        g = int((Path(d) / 'gpid').read_text())
        g_alive = alive(g)
        if g_alive:
            os.kill(g, signal.SIGKILL)
    with tempfile.TemporaryDirectory() as d2:            # the control: the old shape is still waiting
        HK.within(lambda: subprocess.run(hanging_step(d2), capture_output=True, text=True, timeout=2), 12)
        time.sleep(0.5)
        try:
            g2 = int((Path(d2) / 'gpid').read_text())
            old_left = alive(g2)
            os.kill(g2, signal.SIGKILL)
        except (OSError, ValueError):
            old_left = False
    return raised is not None and took < 40 and not g_alive and old_left, (bool(raised), round(took, 1), g_alive, old_left)


def kat_hk4(over):
    HK = mod(over, 'hangkit')
    with tempfile.TemporaryDirectory() as d:
        try:
            HK.run_bounded(hanging_step(d), 2)
            return False, 'no Hung'
        except HK.Hung as e:
            ok = bool(e.diagnosis) and 'step started' in e.tail
            det = (e.diagnosis[:120], e.tail[-40:])
        finally:
            try:
                os.kill(int((Path(d) / 'gpid').read_text()), signal.SIGKILL)
            except (OSError, ValueError):
                pass
    return ok, det


def kat_hk5(over):
    HK = mod(over, 'hangkit')
    v = (HK.budget_timeout(100), HK.budget_timeout(1000), HK.budget_timeout(30))
    return v == (400, 3000, 330), v


def kat_cp1(over):
    CP, HK = mod(over, 'coproc'), mod({}, 'hangkit')
    with tempfile.TemporaryDirectory() as d:
        child = Path(d) / 'echo64k'
        child.write_text(f"#!{sys.executable} -I\nimport sys\nfor line in sys.stdin:\n"
                         "    sys.stdout.write('y' * 65536 + '\\n')\n    sys.stdout.flush()\n")
        os.chmod(child, 0o700)
        cp = CP.CoProc([str(child)])
        try:
            done, r, e = HK.within(lambda: cp.roundtrip(['x' * 65536] * 200, 200, timeout=60), 20)
        finally:
            cp.kill()
    return done and e is None and len(r) == 200, (done, e, len(r or []))


def kat_cp2(over):
    CP, HK = mod(over, 'coproc'), mod({}, 'hangkit')
    got = []
    with tempfile.TemporaryDirectory() as d:
        mute, gone = Path(d) / 'mute', Path(d) / 'gone'
        mute.write_text(f"#!{sys.executable} -I\nimport sys\nfor line in sys.stdin:\n    pass\n")
        gone.write_text(f"#!{sys.executable} -I\nimport sys\nsys.exit(0)\n")
        for f in (mute, gone):
            os.chmod(f, 0o700)
            cp = CP.CoProc([str(f)])
            try:
                done, r, e = HK.within(lambda: cp.roundtrip(['a', 'b'], 2, timeout=1), 10)
                got.append(type(e).__name__ if done and e else ('returned' if done else 'HUNG'))
            finally:
                cp.kill()
    return got == ['CoProcTimeout', 'CoProcEOF'], got


KATS = [('HK1', kat_hk1), ('HK2', kat_hk2), ('HK3', kat_hk3), ('HK4', kat_hk4), ('HK5', kat_hk5), ('CP1', kat_cp1),
        ('CP2', kat_cp2)]
OWNERS = {'r29 liveness': [k for k, _ in KATS]}
MUTATIONS = [
    ('hangkit', "    t.join(limit)\n", "    t.join()\n", 'r29 liveness: within waits for ever'),
    ('hangkit', "stderr=subprocess.PIPE, start_new_session=True)", "stderr=subprocess.PIPE, start_new_session=False)",
     'r29 liveness: the bounded step shares our process group (its grandchildren survive)'),
    ('hangkit', "        diag = leaf_frames(p.pid)\n        _stop_group(p)\n", "        diag = leaf_frames(p.pid)\n        p.kill()\n",
     'r29 liveness: only the direct child is stopped'),
    ('hangkit', "        diag = leaf_frames(p.pid)\n", "        diag = ''\n", 'r29 liveness: a hang is reported without frames'),
    ('hangkit', "    return max(3 * b, b + 300)", "    return b", 'r29 liveness: the hard limit is the budget itself'),
    ('coproc', "        w.start()\n", "        w.run()\n", 'r29 liveness: the co-process input is written before its output is read'),
    ('coproc', "                line = self.q.get(timeout=left)", "                line = self.q.get()",
     'r29 liveness: a silent co-process is waited on for ever'),
    ('coproc', "        self.q.put(None)                                   # EOF marker", "        pass",
     'r29 liveness: an exited co-process is waited on instead of raising EOF'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_lk29', HARNESS / 'kit' / 'katmut.py')
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
        print(f'\nr29 liveness kit KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
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
        with tempfile.TemporaryDirectory(prefix='lk29-mut-') as d:
            mut = Path(d) / PATHS[key]
            mut.parent.mkdir(parents=True, exist_ok=True)
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, _ = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r29 liveness kit KATs', len(KATS), len(MUTATIONS), missed, 0))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
