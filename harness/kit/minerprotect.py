#!/usr/bin/env python3
"""minerprotect.py — r30 (coordinator 2026-11-09, the user's 24 h miner window): heavy agent jobs run clamped while a
live miner mines.

Measured: nice-15 agent jobs (Go builds/tests, KAT mutation loops) cut the user's live miner from ~96k to ~50k H/s;
`nice` does not protect it (R23b: nice-15 agents still took ~2.6 cores). `taskpolicy -c utility` (darwin) moves a job
to the utility QoS clamp (E-cores first, throttled), and Go runs one package at a time with `-p 1 -parallel 2`.

OPT-IN, DEFAULT OFF (the user's decision, coordinator 2026-11-09: agents are not throttled when that slows the round
or degrades quality). Nothing in the pipeline or the agent preflight calls it on its own; resource_intel only REPORTS
the live miner as a contention consumer. When the user opts in (DERO_MINERPROTECT_OPTIN=1, or `run --optin`), then
while harness/round.json rounds[current].tracks.miner is 'active' AND a dero-miner process is running, the wrapped job
runs clamped and marked in the environment (DERO_MINERPROTECT=utility), which `check` reads.

  python3 -I harness/kit/minerprotect.py status                  # active? live miner? clamped? (exit 0)
  python3 -I harness/kit/minerprotect.py check [--optin] [--root DIR] [--names a,b]       # exit 0 ok (always when not opted in) · 6 opted in,
                                                                 # required and not clamped
  python3 -I harness/kit/minerprotect.py run [--optin] -- CMD    # opted in + required: clamped (go: -p 1 -parallel 2);
                                                                 # otherwise CMD runs unchanged
Library: required(root), parse_run(args), wrap(cmd, root), go_args(cmd, protect), clamped(env), live_miner(rows).
"""
import json, os, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
MARK = 'DERO_MINERPROTECT'
CLAMP = 'utility'
TASKPOLICY = '/usr/sbin/taskpolicy'
MINER_NAMES = ('dero-miner',)
OPTIN = 'DERO_MINERPROTECT_OPTIN'


def opted_in(env=None, argv=()):
    """True only when the user opted in (env DERO_MINERPROTECT_OPTIN=1 exactly, or --optin). Default off; any other
    value (0, empty, 'no') is not opted in. Pure."""
    return '--optin' in argv or (env if env is not None else os.environ).get(OPTIN) == '1'


def parse_run(rest):
    """(opted in by flag, CMD) of `run`'s arguments: `[--optin] -- CMD` or `[--optin] CMD` (r30 verify D5: without
    `--` the leading --optin was dropped from CMD and NOT honoured). Only leading flags are the wrapper's; an --optin
    after CMD's first word belongs to CMD. Pure."""
    rest = list(rest)
    if '--' in rest:
        k = rest.index('--')
        return '--optin' in rest[:k], rest[k + 1:]
    k = 0
    while k < len(rest) and rest[k] == '--optin':
        k += 1
    return k > 0, rest[k:]


def miner_track_active(root=ROOT):
    """True when the registry's current round has tracks.miner == 'active'."""
    try:
        reg = json.loads((Path(root) / 'harness/round.json').read_text())
    except (OSError, ValueError):
        return False
    cur = next((r for r in reg.get('rounds', []) if r.get('id') == reg.get('current')), {})
    return (cur.get('tracks') or {}).get('miner') == 'active'


def proc_names():
    """basenames of every running process ([] when ps fails)."""
    try:
        out = subprocess.run(['ps', '-axo', 'comm='], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return [l.strip().rsplit('/', 1)[-1] for l in out.splitlines() if l.strip()]


def live_miner(names):
    """the number of live miner processes in a list of process basenames. Pure."""
    return sum(1 for n in names if n in MINER_NAMES)


def required(root=ROOT, names=None):
    """True when heavy jobs must run clamped: the miner track is active and a miner is mining."""
    return miner_track_active(root) and live_miner(proc_names() if names is None else names) > 0


def clamped(env=None):
    return (env if env is not None else os.environ).get(MARK) == CLAMP


def go_args(cmd, protect):
    """`cmd` with `-p 1 -parallel 2` for a go build/test when `protect` (an existing -p N is replaced). Pure."""
    cmd = list(cmd)
    if not protect or len(cmd) < 2 or Path(str(cmd[0])).name != 'go' or cmd[1] not in ('test', 'build', 'vet'):
        return cmd
    rest, i = [], 2
    while i < len(cmd):
        if cmd[i] == '-p' and i + 1 < len(cmd):
            i += 2
            continue
        if str(cmd[i]).startswith('-p='):
            i += 1
            continue
        if cmd[1] == 'test' and (cmd[i] == '-parallel' and i + 1 < len(cmd)):
            i += 2
            continue
        rest.append(cmd[i])
        i += 1
    extra = ['-p', '1'] + (['-parallel', '2'] if cmd[1] == 'test' else [])
    return cmd[:2] + extra + rest


def wrap(cmd, protect, env=None):
    """(argv, env) to run `cmd`: under `taskpolicy -c utility` with the mark set when `protect` and not yet clamped
    (a clamped parent's children inherit the clamp), Go flags reduced. Pure."""
    env = dict(os.environ if env is None else env)
    cmd = go_args(cmd, protect)
    if not protect:
        return cmd, env
    if clamped(env):
        return cmd, env
    env[MARK] = CLAMP
    return [TASKPOLICY, '-c', CLAMP, *cmd], env


def main(argv):
    if not argv or argv[0] in ('-h', '--help'):
        print(__doc__)
        return 0
    if argv[0] == 'status':
        names = proc_names()
        print(f"minerprotect: opted in {opted_in(argv=argv)} · miner track active {miner_track_active()} · live miner "
              f"{live_miner(names)} · would clamp {miner_track_active() and live_miner(names) > 0} · clamped {clamped()}")
        return 0
    if argv[0] == 'check':
        # --root DIR / --names a,b: another registry / a fixture process list (KAT)
        root = Path(argv[argv.index('--root') + 1]) if '--root' in argv else ROOT
        names = argv[argv.index('--names') + 1].split(',') if '--names' in argv else None
        if opted_in(argv=argv) and required(root, names) and not clamped():
            print('minerprotect: a live miner is mining (tracks.miner active): run heavy jobs under '
                  '`python3 -I harness/kit/minerprotect.py run -- CMD` (taskpolicy -c utility; go -p 1 -parallel 2)')
            return 6
        print('minerprotect: ok')
        return 0
    if argv[0] == 'run':
        rest = argv[1:]
        flag, cmd = parse_run(rest)
        optin = opted_in(argv=['--optin'] if flag else [])
        if not cmd:
            print('minerprotect: run [--optin] -- CMD')
            return 2
        argv2, env = wrap(cmd, optin and required())
        return subprocess.run(argv2, env=env).returncode
    print(f'minerprotect: unknown command {argv[0]!r}')
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
