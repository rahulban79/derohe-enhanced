#!/usr/bin/env python3
"""benchlock.py — run a command under one machine-wide exclusive lock, so agent benchmarks never overlap each other.

r23c: until R23c the only copy lived in one session's scratchpad with that session's absolute paths typed in, so a new
session had no bench lock to share with the pipeline's --benchlock. This copy takes the lock file from $DERO_BENCHLOCK,
else from harness/round.json "benchlock", and REFUSES to run without one (a lock nobody else holds excludes nothing).
Every bench of a round (pipeline S4b/S4c and every agent) must name the SAME lock file.

  python3 -I harness/pipeline/benchlock.py [--gpu] -- cmd args...

The command runs at nice 15 (R21: yield the CPU to the live, CPU-bound miner). --gpu also reads the live miner's
GPU-split 'restarts' counter before and after, waits one stats period (65 s), and exits 99 if the live GPU worker
restarted (whatever the command returned): STOP ALL GPU EXPERIMENTS. r23c: --gpu FAILS (exit 98) when the counter cannot be read before the run,
because a check that cannot see the live GPU cannot say it was left alone. The log is $DERO_MINER_LOG, else bin/dero-miner.log of
this checkout.

r25 (perfops, B20): --qos=utility|background|none (default none, or $DERO_BENCH_QOS) also runs the command under macOS
`taskpolicy` (`-c utility` / `-b`) on top of nice 15. Measured 2026-11-03 (20 spinning threads, 6 interleaved windows
per arm, a nice-0 10 ms sleep probe standing in for derod's timers; evidence in the r25 perfops dimension): nice 15 alone
let the probe's p99 overshoot rise 1.95 -> 5.60 ms (max 12.4 ms) while the load got 0.789 of 20 cores; utility kept
p99 at 1.13 ms with 0.769 of 20 cores; background starved the load (0.052). The default stays none: a CPU-time A/B
under a QoS clamp may run on E-cores, so the bench numbers would change meaning. An unknown value, or a clamp on a
system without taskpolicy, is refused (exit 2), never silently dropped.

  python3 -I harness/pipeline/benchlock.py [--gpu] [--qos=utility] -- cmd args...
"""
import fcntl, json, os, shutil, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PENDING = 'pending'


def lock_path():
    """the lock file: $DERO_BENCHLOCK, else round.json "benchlock" unless it is 'pending'; None when neither names one"""
    env = os.environ.get('DERO_BENCHLOCK')
    if env:
        return os.path.expanduser(env)
    try:
        v = json.loads((ROOT / 'harness/round.json').read_text()).get('benchlock')
    except (OSError, ValueError):
        v = None
    return os.path.expanduser(v) if v and v != PENDING else None


def restarts(log):
    """the last GPU split 'restarts' value in the miner's JSON log, or None"""
    last = None
    try:
        with open(log) as f:
            for l in f:
                if '"GPU split"' in l:
                    try:
                        last = json.loads(l).get('restarts')
                    except ValueError:
                        pass
    except OSError:
        return None
    return last


QOS = {'none': [], 'utility': ['taskpolicy', '-c', 'utility'], 'background': ['taskpolicy', '-b']}   # r25 (B20)


def parse_opts(argv):
    """r25: leading --gpu / --qos=X options, then an optional '--'. Returns (gpu, qos, cmd). Pure."""
    gpu, qos = False, os.environ.get('DERO_BENCH_QOS') or 'none'
    while argv and argv[0] != '--' and argv[0].startswith('--'):
        if argv[0] == '--gpu':
            gpu = True
        elif argv[0].startswith('--qos='):
            qos = argv[0][len('--qos='):]
        else:
            break
        argv = argv[1:]
    if argv and argv[0] == '--':
        argv = argv[1:]
    return gpu, qos, argv


def child_argv(cmd, qos, have_taskpolicy=None):
    """r25: the argv benchlock runs: the QoS clamp (if any) around nice 15 around cmd; None = refuse. Pure apart from
    the taskpolicy lookup (injected by tests)."""
    if qos not in QOS:
        return None
    if QOS[qos]:
        if have_taskpolicy is None:
            have_taskpolicy = shutil.which('taskpolicy') is not None
        if not have_taskpolicy:
            return None
    return QOS[qos] + ['nice', '-n', '15'] + list(cmd)


def main(argv):
    gpu, qos, argv = parse_opts(argv)
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    child = child_argv(argv, qos)
    if child is None:
        print(f'[benchlock] --qos={qos}: unknown (use {"|".join(QOS)}) or taskpolicy is missing: refusing', file=sys.stderr)
        return 2
    lp = lock_path()
    if not lp:
        print('[benchlock] no lock file: export DERO_BENCHLOCK=<file> or set "benchlock" in harness/round.json', file=sys.stderr)
        return 2
    log = os.environ.get('DERO_MINER_LOG') or str(ROOT / 'bin/dero-miner.log')
    with open(lp, 'a') as f:
        t0 = time.time()
        fcntl.flock(f, fcntl.LOCK_EX)
        print(f'[benchlock] acquired after {time.time() - t0:.1f}s', file=sys.stderr, flush=True)
        r0 = restarts(log) if gpu else None
        if gpu and r0 is None:
            print(f'[benchlock] --gpu: no GPU split restarts counter in {log}: refusing (set DERO_MINER_LOG)', file=sys.stderr, flush=True)
            return 98
        rc = subprocess.call(child)
        if gpu:
            time.sleep(65)                       # one GPU split stats period
            r1 = restarts(log)
            print(f'[benchlock] live GPU restarts before={r0} after={r1}', file=sys.stderr, flush=True)
            if r1 is None or r1 > r0:
                print('[benchlock] LIVE GPU WORKER RESTARTED (or unreadable) - STOP ALL GPU EXPERIMENTS', file=sys.stderr, flush=True)
                rc = 99                          # r23c review: the STOP signal wins over the command's own exit code
    return rc


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
