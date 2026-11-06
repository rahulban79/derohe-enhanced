#!/usr/bin/env python3
"""pidwait.py — wait for a process to end by its PID, never by a pattern (r27 tools-kats; dero-rft §5 'wait on a pid').

R26 waited three times with `until ! pgrep -f PATTERN; do sleep 5; done`: `pgrep -f` matches the full command line of
every process, and the shell running that loop carries PATTERN in its own command line, so the loop matched itself and
never ended. A PID names one process and cannot match its waiter.

  alive(pid)                 True while the PID exists: os.kill(pid, 0) succeeds, or fails with EPERM (it exists but
                             belongs to another user: alive, never 'gone'); a zombie child is reaped and reads gone
  wait_pid(pid, timeout, poll) True when the process ended within `timeout` seconds (None = no limit), else False;
                             it never signals the process (os.kill(pid, 0) delivers nothing)

  python3 -I harness/kit/pidwait.py PID [--timeout SECONDS] [--poll SECONDS]
Exit 0 the process ended (or never existed) · 1 timeout, still running · 2 bad invocation.
"""
import argparse, errno, os, sys, time


def alive(pid):
    pid = int(pid)
    if pid <= 0:
        raise ValueError(f'not a single process id: {pid}')   # 0 / -1 / negative address process groups
    try:
        done, _ = os.waitpid(pid, os.WNOHANG)                  # our own child: reap it, so a zombie is not 'alive'
        if done == pid:
            return False
    except ChildProcessError:
        pass                                                   # not our child: ask the kernel below
    try:
        os.kill(pid, 0)
    except OSError as e:
        if e.errno == errno.ESRCH:
            return False
        if e.errno == errno.EPERM:
            return True
        raise
    return True


def wait_pid(pid, timeout=None, poll=0.5):
    """True when `pid` ended within `timeout` seconds (None: wait for ever). Pure apart from os.kill(pid, 0)/waitpid."""
    end = None if timeout is None else time.monotonic() + float(timeout)
    while alive(pid):
        if end is not None and time.monotonic() >= end:
            return False
        time.sleep(poll if end is None else max(0.0, min(poll, end - time.monotonic())))
    return True


def main(argv):
    ap = argparse.ArgumentParser(prog='pidwait.py', description=__doc__.split('\n\n')[0])
    ap.add_argument('pid', type=int)
    ap.add_argument('--timeout', type=float, default=None, help='seconds (default: no limit)')
    ap.add_argument('--poll', type=float, default=0.5, help='seconds between checks')
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 2
    if a.pid <= 0:
        print('pidwait: a single positive PID is required', file=sys.stderr)
        return 2
    ok = wait_pid(a.pid, a.timeout, a.poll)
    print(f'pid {a.pid} ' + ('ended' if ok else f'still running after {a.timeout} s'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
