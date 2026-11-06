#!/usr/bin/env python3
"""gpu_watch.py — did an experiment disturb the LIVE GPU split? Read from the miner's /metrics, before and after.

The session's benchlock.py --gpu reads the 'restarts' field of the LAST "GPU split" line in bin/dero-miner.log
before and after a command and flags only an increase. Two disturbances pass that check unseen:
  * split turns itself OFF: report_split (cmd/dero-miner/gpu_split.go) returns after the first line with
    disabled != "", so no later line exists and 'restarts' never moves;
  * the MINER restarts (crash, operator, launchd): r20 appends to the log, the new run's counters start at 0, and
    after < before reads as "no restart".
This tool compares two GET /metrics readings (127.0.0.1:10110, read-only) instead: uptime went backwards (the
miner restarted), gpu/split restarts grew, split_disabled became 1, a GPU/CPU mismatch appeared, the split
stopped hashing, or the endpoint went away.

  python3 -I harness/intel/gpu_watch.py run [--settle 65] -- <cmd ...>   # before, cmd, wait one split period, after
  python3 -I harness/intel/gpu_watch.py snap                              # one reading as JSON
Exit: the command's exit code, or 99 when the live GPU split was disturbed (STOP all GPU work).
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):   # r27 B120: usage, exit 0, nothing run or written
    print(__doc__ or 'usage: see the header of this file')
    raise SystemExit(0)
import json, subprocess, sys, time, urllib.request

MINER = 'http://127.0.0.1:10110/metrics'
KEYS = ('dero_miner_uptime_seconds', 'dero_miner_gpu_restarts_total', 'dero_miner_split_restarts_total',
        'dero_miner_split_disabled', 'dero_miner_gpu_mismatch_total', 'dero_miner_split_hashed_total')


def parse(text):
    out = {}
    for l in text.splitlines():
        if l.startswith('#') or ' ' not in l:
            continue
        name, v = l.split('{')[0].split(' ')[0], l.rsplit(' ', 1)[-1]
        if name in KEYS:
            try:
                out[name] = out.get(name, 0.0) + float(v)
            except ValueError:
                pass
    return out


def snap(url=MINER, get=None):
    """one reading {key: value}, or None when the endpoint does not answer"""
    try:
        text = get(url) if get else urllib.request.urlopen(urllib.request.Request(url, method='GET'), timeout=8).read().decode()
    except Exception:                                           # noqa: BLE001 — down is a reading
        return None
    return parse(text)


RESTART_SLACK_S = 30.0   # uptime is whole seconds and a reading takes up to the 8 s timeout


def disturbed(a, b, elapsed=None):
    """the reasons the live split was disturbed between readings a and b ([] = undisturbed). Pure. elapsed: wall
    seconds between the readings (r21 merge, HR21-4): a miner restarted during a command that outlasted its previous
    uptime has a LARGER uptime afterwards, so 'uptime went backwards' alone misses it."""
    if a is None:
        return ['no reading before the command (the miner /metrics did not answer): nothing can be judged']
    if b is None:
        return ['the miner /metrics stopped answering']
    why = []
    if b.get('dero_miner_uptime_seconds', 0) < a.get('dero_miner_uptime_seconds', 0):
        why.append(f"the miner restarted (uptime {a.get('dero_miner_uptime_seconds')} -> {b.get('dero_miner_uptime_seconds')} s)")
    elif elapsed is not None and b.get('dero_miner_uptime_seconds', 0) < a.get('dero_miner_uptime_seconds', 0) + elapsed - RESTART_SLACK_S:
        why.append(f"the miner restarted (uptime {a.get('dero_miner_uptime_seconds')} -> {b.get('dero_miner_uptime_seconds')} s "
                   f"over {elapsed:.0f} s of wall time)")
    for k in ('dero_miner_gpu_restarts_total', 'dero_miner_split_restarts_total', 'dero_miner_gpu_mismatch_total'):
        if b.get(k, 0) > a.get(k, 0):
            why.append(f'{k} {a.get(k, 0):.0f} -> {b.get(k, 0):.0f}')
    if b.get('dero_miner_split_disabled', 0) > 0:
        why.append('the GPU split is disabled')
    if 'dero_miner_split_hashed_total' in a and b.get('dero_miner_split_hashed_total', 0) <= a['dero_miner_split_hashed_total'] \
            and not why:
        why.append('the GPU split hashed nothing between the readings')
    return why


def main(argv):
    if argv[:1] == ['snap']:
        print(json.dumps(snap()))
        return 0
    if argv[:1] != ['run'] or '--' not in argv:
        print(__doc__)
        return 2
    i = argv.index('--')
    settle = 65.0
    if '--settle' in argv[:i]:
        settle = float(argv[argv.index('--settle') + 1])
    a = snap()
    t0 = time.monotonic()
    rc = subprocess.call(argv[i + 1:])
    time.sleep(settle)                     # one 60 s split stats period, as benchlock --gpu waits
    b = snap()
    why = disturbed(a, b, time.monotonic() - t0)
    print(f'[gpu_watch] before={a} after={b}', file=sys.stderr, flush=True)
    if why:
        print('[gpu_watch] LIVE GPU SPLIT DISTURBED - STOP ALL GPU EXPERIMENTS: ' + '; '.join(why), file=sys.stderr, flush=True)
        return 99
    return rc


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
