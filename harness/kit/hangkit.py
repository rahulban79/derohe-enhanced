#!/usr/bin/env python3
"""hangkit.py — r29 (rft §5 long-job liveness; user 2026-11-08 "make sure to fix anything you find tasks are stuck at
... make sure to further enhance the harness, tools, skills, pipeline"): bounded execution, so a hang is a reported
failure with a diagnosis instead of a wait without end.

  within(fn, limit)        run fn in a daemon thread; (finished, result, exc) after at most `limit` s — the KATs' hang
                           probe (a test of a hang fix must make the OLD code fail, not hang the test run)
  run_bounded(cmd, timeout, cwd=None, env=None, shell=False)
                           run a command in its own process group; (rc, out, err) — or raise Hung after `timeout` s with
                           the leaf frames of the child (`sample`, macOS) and its last output lines, having stopped the
                           WHOLE group (TERM, then KILL). subprocess.run(capture_output=True, timeout=...) kills only the
                           direct child: its grandchildren (go test's test binaries, a shell's background job) keep
                           running after the step "timed out" (measured on Python 3.14, KAT HK3), and Pythons that
                           re-read the pipes after the kill wait on them for as long as a grandchild holds them.
  leaf_frames(pid)         'Nx frame; ...' of a live process (one `sample` second), '' when sample is unavailable
  budget_timeout(budget_s) max(3 x budget, budget + 300) — the hard limit derived from a step's STEP_BUDGETS row

Library only (no command).
"""
import os, signal, subprocess, threading, time


class Hung(subprocess.TimeoutExpired):
    """a bounded command ran past its limit; .diagnosis (leaf frames) and .tail (last output) say where it was."""

    def __init__(self, cmd, timeout, diagnosis='', tail=''):
        super().__init__(cmd, timeout, output=tail)
        self.diagnosis, self.tail = diagnosis, tail

    def __str__(self):
        return f'HUNG after {self.timeout:g} s: {self.diagnosis or "no frames"}'


def within(fn, limit):
    box = {}

    def run():
        try:
            box['r'] = fn()
        except BaseException as e:                 # noqa: BLE001 — reported to the caller, never swallowed
            box['e'] = e
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(limit)
    if t.is_alive():
        return False, None, None
    return True, box.get('r'), box.get('e')


def budget_timeout(budget_s):
    b = float(budget_s)
    return max(3 * b, b + 300)


def leaf_frames(pid, secs=1):
    try:
        r = subprocess.run(['sample', str(pid), str(secs)], capture_output=True, text=True, timeout=secs + 30)
    except (OSError, subprocess.TimeoutExpired):
        return ''
    leaf, cur = [], None
    for ln in r.stdout.splitlines():
        if 'Thread_' in ln:
            if cur:
                leaf.append(cur)
            cur = None
        elif '(in ' in ln:
            cur = ln.strip().lstrip('+!:| 0123456789').split('[')[0].strip()
    if cur:
        leaf.append(cur)
    counts = {}
    for x in leaf:
        counts[x] = counts.get(x, 0) + 1
    return '; '.join(f'{n}x {k}' for k, n in sorted(counts.items(), key=lambda kv: -kv[1])[:6])


def _stop_group(p):
    for sig, wait in ((signal.SIGTERM, 5), (signal.SIGKILL, 5)):
        try:
            os.killpg(p.pid, sig)
        except (ProcessLookupError, PermissionError):
            return
        t0 = time.monotonic()
        while time.monotonic() - t0 < wait:
            try:
                os.killpg(p.pid, 0)
            except (ProcessLookupError, PermissionError):
                return
            time.sleep(0.1)


def run_bounded(cmd, timeout, cwd=None, env=None, shell=False):
    p = subprocess.Popen(cmd, cwd=cwd, env=env, shell=shell, text=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        out, err = p.communicate(timeout=timeout)
        return p.returncode, out, err
    except subprocess.TimeoutExpired:
        diag = leaf_frames(p.pid)
        _stop_group(p)
        try:
            out, err = p.communicate(timeout=10)        # the group is gone, so the pipes reach EOF
        except subprocess.TimeoutExpired:
            out, err = '', ''
        tail = '\n'.join(((out or '') + (err or '')).strip().splitlines()[-5:])
        raise Hung(cmd, timeout, diag, tail) from None
