#!/usr/bin/env python3
"""KAT + mutation proofs for harness/kit/minerprotect.py (opt-in miner protection) and the resource_intel contention
report (r30, coordinator 2026-11-09; the user chose NOT to throttle agents by default). No process is clamped, no live
file is written: the registry is a temp file and the process lists are fixtures.

  MP1  opt-in, default off: opted_in() is False without DERO_MINERPROTECT_OPTIN=1 / --optin; wrap() of an unprotected
       command is the command itself; `check` exits 0 when not opted in (even with a live miner on an active track).
       r30 verify D5: DERO_MINERPROTECT_OPTIN=0 (or empty) is NOT opted in (pinned; `check` exits 0 under it), and
       `run --optin CMD` without `--` honours --optin (parse_run); an --optin after CMD's first word stays CMD's.
  MP2  required(): tracks.miner active AND a dero-miner process; a paused track or no miner process is not required.
  MP3  wrap(protect=True): `taskpolicy -c utility` + DERO_MINERPROTECT=utility, never twice (a clamped parent);
       go test gets `-p 1 -parallel 2` (an existing -p N replaced), go build `-p 1`, other commands keep their argv.
  MP4  resource_intel REPORTS a live dero-miner as a contention consumer in preflight, and the level and the
       recommended concurrency are the same as without it (never forced).

  python3 -I harness/kat/test_minerprotect_r30.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not proved (MISSED / WRONG-KAT / INVALID) or was coupled.
"""
import contextlib, importlib.util, io, json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
PATHS = {'mp': 'harness/kit/minerprotect.py', 'ri': 'harness/intel/resource_intel.py'}


def P(over, key):
    return Path(over.get(key) or ROOT / PATHS[key])


def load(over, key):
    path = P(over, key)
    spec = importlib.util.spec_from_file_location(f'mp30_{key}_{abs(hash(str(path)))}_{len(sys.modules)}', path)
    m = importlib.util.module_from_spec(spec)
    with contextlib.redirect_stdout(io.StringIO()):
        spec.loader.exec_module(m)
    return m


def reg_root(miner):
    d = Path(tempfile.mkdtemp(prefix='mp30-'))
    (d / 'harness').mkdir()
    (d / 'harness/round.json').write_text(json.dumps({'current': 'r30', 'rounds': [
        {'id': 'r30', 'tracks': {'miner': miner, 'node': 'active'}}]}))
    return d


def kat_mp1(over):
    mp = load(over, 'mp')
    a = mp.opted_in({}) is False and mp.opted_in({'DERO_MINERPROTECT_OPTIN': '1'}) is True and mp.opted_in({}, ['--optin'])
    # r30 verify D5: OPTIN=0 / empty is NOT opted in; `run --optin CMD` (no `--`) honours the flag
    a0 = mp.opted_in({'DERO_MINERPROTECT_OPTIN': '0'}) is False and mp.opted_in({'DERO_MINERPROTECT_OPTIN': ''}) is False
    pr = (mp.parse_run(['--optin', 'go', 'test', './p2p/']) == (True, ['go', 'test', './p2p/'])
          and mp.parse_run(['--optin', '--', 'echo', '--optin']) == (True, ['echo', '--optin'])
          and mp.parse_run(['echo', '--optin']) == (False, ['echo', '--optin'])
          and mp.parse_run(['--', 'echo']) == (False, ['echo']))
    cmd = ['go', 'test', './p2p/', '-p', '4']
    b = mp.wrap(cmd, False, {})[0] == cmd
    env = {k: v for k, v in os.environ.items() if k not in ('DERO_MINERPROTECT_OPTIN', 'DERO_MINERPROTECT')}
    d = reg_root('active')
    try:
        base = [sys.executable, '-I', str(P(over, 'mp')), 'check', '--root', str(d), '--names', 'derod,dero-miner']
        r = subprocess.run(base, capture_output=True, text=True, timeout=60, env=env)
        r2 = subprocess.run(base + ['--optin'], capture_output=True, text=True, timeout=60, env=env)
        r3 = subprocess.run(base, capture_output=True, text=True, timeout=60, env={**env, 'DERO_MINERPROTECT_OPTIN': '0'})
    finally:
        shutil.rmtree(d, ignore_errors=True)
    ok = a and a0 and pr and b and r.returncode == 0 and r2.returncode == 6 and r3.returncode == 0
    return bool(ok), (f'opted_in default/env/flag ok {bool(a)}, OPTIN=0 off {a0}, run --optin CMD {pr}, unprotected wrap {b}, '
                      f'check rc {r.returncode} (opted in {r2.returncode}, OPTIN=0 {r3.returncode})')


def kat_mp2(over):
    mp = load(over, 'mp')
    act, pau = reg_root('active'), reg_root('paused')
    try:
        r1 = mp.required(act, ['launchd', 'dero-miner', 'derod'])
        r2 = mp.required(pau, ['dero-miner'])
        r3 = mp.required(act, ['derod', 'python3'])
    finally:
        shutil.rmtree(act, ignore_errors=True)
        shutil.rmtree(pau, ignore_errors=True)
    return (r1, r2, r3) == (True, False, False), f'active+miner {r1}, paused+miner {r2}, active no miner {r3}'


def kat_mp3(over):
    mp = load(over, 'mp')
    argv, env = mp.wrap(['go', 'test', './p2p/', '-p', '4', '-run', 'X'], True, {})
    argv2, _ = mp.wrap(['go', 'test', './p2p/'], True, {'DERO_MINERPROTECT': 'utility'})
    b = mp.go_args(['go', 'build', '-o', 'x', './cmd/derod'], True)
    o = mp.go_args(['python3', 'x.py', '-p', '4'], True)
    ok = (argv[:3] == ['/usr/sbin/taskpolicy', '-c', 'utility'] and env.get('DERO_MINERPROTECT') == 'utility'
          and argv[3:] == ['go', 'test', '-p', '1', '-parallel', '2', './p2p/', '-run', 'X']
          and argv2 == ['go', 'test', '-p', '1', '-parallel', '2', './p2p/']
          and b == ['go', 'build', '-p', '1', '-o', 'x', './cmd/derod'] and o == ['python3', 'x.py', '-p', '4'])
    return ok, f'wrap {argv}; clamped parent {argv2}; build {b}; other {o}'


def readings(rows, ri):
    return {'swap': {'used_mb': 100, 'free_mb': 5000, 'total_mb': 6144}, 'memory_free_pct': 90, 'ram_mb': 131072,
            'procs': ri.classify(rows), 'scratchpad': {'clone_trees': 3}}


def kat_mp4(over):
    ri = load(over, 'ri')
    base = [(10, 2048, 'derod', '/x/derod'), (11, 1024, 'python3', 'python3 /x/derohe/harness/a.py')]
    miner = base + [(12, 5918720, '/Users/u/derohe/bin/dero-miner', '/Users/u/derohe/bin/dero-miner --supervised')]
    a, b = ri.preflight(readings(base, ri), 8), ri.preflight(readings(miner, ri), 8)
    cont = b.get('contention') or []
    ok = (not a.get('contention') and len(cont) == 1 and 'dero-miner' in cont[0]
          and (a['level'], a['recommended']) == (b['level'], b['recommended']) and 'contention' in ri.note_line('s', b))
    return ok, f"without {a['level']}/{a['recommended']}, with {b['level']}/{b['recommended']} contention {cont}"


KATS = [('MP1', kat_mp1), ('MP2', kat_mp2), ('MP3', kat_mp3), ('MP4', kat_mp4)]
OWNERS = {'r30 MP1': ['MP1'], 'r30 MP2': ['MP2'], 'r30 MP3': ['MP3'], 'r30 MP4': ['MP4']}

MUTATIONS = [   # (key, find, replace, why)
    ('mp', "    return '--optin' in argv or (env if env is not None else os.environ).get(OPTIN) == '1'", "    return True",
     'r30 MP1: the protection is on by default (forces the clamp the user declined)'),
    ('mp', "get(OPTIN) == '1'", "get(OPTIN) is not None", 'r30 MP1: verify D5 DERO_MINERPROTECT_OPTIN=0 opts in'),
    ('mp', "    while k < len(rest) and rest[k] == '--optin':\n        k += 1\n    return k > 0, rest[k:]",
     "    return False, [a for a in rest if a != '--optin']", 'r30 MP1: verify D5 run --optin CMD (no --) ignores --optin'),
    ('mp', "        if opted_in(argv=argv) and required(root, names) and not clamped():", "        if required(root, names) and not clamped():",
     'r30 MP1: check enforces without opt-in'),
    ('mp', "    return miner_track_active(root) and live_miner(proc_names() if names is None else names) > 0",
     "    return live_miner(proc_names() if names is None else names) > 0", 'r30 MP2: the paused track is ignored'),
    ('mp', "    return sum(1 for n in names if n in MINER_NAMES)", "    return 1", 'r30 MP2: no live miner check'),
    ('mp', "    return [TASKPOLICY, '-c', CLAMP, *cmd], env", "    return cmd, env", 'r30 MP3: an opted-in job is not clamped'),
    ('mp', "    if clamped(env):\n        return cmd, env\n", "", 'r30 MP3: a clamped parent clamps its child twice'),
    ('mp', "    extra = ['-p', '1'] + (['-parallel', '2'] if cmd[1] == 'test' else [])", "    extra = []",
     'r30 MP3: Go keeps its full parallelism under the clamp'),
    ('ri', "        if name in CONSUMERS:", "        if False:", 'r30 MP4: the live miner is not reported'),
    ('ri', "    cons = ((r.get('procs') or {}).get('consumers') or {})\n",
     "    cons = ((r.get('procs') or {}).get('consumers') or {})\n    rec = 1 if cons else rec\n",
     'r30 MP4: the preflight forces one job while a miner runs'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_r30mp', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run_kats(over):
    out = []
    for name, fn in KATS:
        try:
            ok, det = fn(over)
        except Exception as e:                                    # noqa: BLE001 — a crash is a failure
            ok, det = False, f'{type(e).__name__}: {e}'
        out.append((name, ok, det))
    return out


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    K = katmut()
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    fails = sum(1 for _, ok, _ in res if not ok)
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        src = P({}, key)
        text = src.read_text()
        if text.count(find) != 1:
            print(f'  INVALID  {why} — find text occurs {text.count(find)} time(s)')
            missed += 1
            continue
        d = Path(tempfile.mkdtemp(prefix='mp30-mut-'))
        sub = d / Path(PATHS[key]).parent
        sub.mkdir(parents=True)
        mp_ = sub / src.name
        mp_.write_text(text.replace(find, repl, 1))
        if key == 'ri':                                         # resource_intel imports nothing local but keep kit beside
            (d / 'harness/kit').mkdir(parents=True, exist_ok=True)
        try:
            failed = [n for n, ok, _ in run_kats({key: mp_}) if not ok]
        finally:
            shutil.rmtree(d, ignore_errors=True)
        verdict, extra = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:9s} {why}  {failed}')
        missed += verdict != 'proved'
        coupled += bool(extra) and verdict == 'proved'
    print('\n' + K.summary('r30 minerprotect KATs', len(KATS) - fails if fails else len(KATS), len(MUTATIONS), missed, coupled))
    return 3 if fails else (4 if missed or coupled else 0)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
