#!/usr/bin/env python3
"""test_levers_read_r30.py — the R30 post-close lever verdict (harness/intel/levers_read.py; rft §2.29, D-22/D-23, B291).

  LR1 runs and config: two runs cut at the start-up line; each run's version, CPU duty cap, split geometry and gpu_max
      come from its own lines
  LR2 the hash verdict: AFTER 8192,3,2 / 100 / cap 100 at a higher mean over a full G34 window on the same build is GAIN;
      the same means are WITHIN-NOISE; a lower one is LOSS
  LR3 refusals: an AFTER window under 240 lines / 3,600 s, a different build, or AFTER without the expected levers is
      PARTIAL (the ratio printed, never a verdict)
  LR4 rewards are PARTIAL under 24 h and carry a per-10^9-hash ratio with its Poisson interval

  python3 -I harness/kat/test_levers_read_r30.py      # exit 0 · 3 a KAT failed · 4 a mutation was missed
"""
import contextlib, datetime, importlib.util, io, json, random, sys, tempfile, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'tool': 'harness/intel/levers_read.py'}
SIBLINGS = ('harness/intel/levers_read.py', 'harness/intel/hashrate_objective.py', 'harness/intel/miner_intel.py')
TZ = datetime.timezone(datetime.timedelta(hours=-8))


def load(over):
    root = Path(over.get('root') or ROOT)
    spec = importlib.util.spec_from_file_location(f'lr30_{uuid.uuid4().hex[:6]}', root / PATHS['tool'])
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def J(t, msg, **f):
    d = {'L': 'INFO', 'T': datetime.datetime.fromtimestamp(t, TZ).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + '-0800', 'N': 'miner', 'M': msg}
    d.update(f)
    return json.dumps(d)


def run(t0, version, geom, gmax, cap, hs, n, seed, miniblocks):
    r = random.Random(seed)
    b, dp, inf = geom.split(',')
    L = [J(t0, 'DERO Stargate HE AstroBWT miner : It is an alpha version'), J(t0, '', Version=version)]
    if cap != 100:
        L.append(J(t0, f'CPU duty cycle capped at {cap}% per thread (use --cpu-max=100 for full speed)'))
    L.append(J(t0 + 1, 'GPU split mode ACTIVE — self-test passed', batch=int(b), depth=int(dp), inflight=int(inf)))
    for i in range(n):
        t = t0 + 15 * (i + 1)
        L.append(J(t, 'TOTAL hashrate', **{'H/s': str(round(hs * (1 + r.uniform(-0.01, 0.01)))), 'cpu_cores': '18.0', 'H/cpu-s': '5300'}))
        if i % 4 == 0:
            L.append(J(t, 'GPU split', **{'staged_H/s': str(round(hs * 0.93)), 'gpu_busy_us_per_hash': '10.5', 'gpu_busy_pct': '96.0', 'gpu_max': gmax}))
        if i % 4 == 2:
            L.append(J(t, 'REWARD STATS', accepted_miniblocks=round(miniblocks * (i + 1) / n), accepted_blocks=1, rejected=0))
    return L


def analyse(m, before, after):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / 'dero-miner.log'
        p.write_text('\n'.join(before + after) + '\n')
        with contextlib.redirect_stdout(io.StringIO()):
            return m.analyse(p, None)


T0 = 1794000000.0
B = lambda **k: run(T0, k.get('v', 'r30'), '4096,4,2', 96, 90, k.get('hs', 94000), k.get('n', 400), 1, 400)
A = lambda **k: run(T0 + 20000, k.get('v', 'r30'), k.get('geom', '8192,3,2'), k.get('gmax', 100), k.get('cap', 100),
                    k.get('hs', 101000), k.get('n', 300), 2, k.get('mb', 70))


def kat_lr1(over):
    m = load(over)
    rep = analyse(m, B(), A())
    ok = (rep['after']['config'] == {'version': 'r30', 'cpu_cap': 100, 'geometry': '8192,3,2', 'gpu_max': 100}
          and rep['before']['config'] == {'version': 'r30', 'cpu_cap': 90, 'geometry': '4096,4,2', 'gpu_max': 96}
          and rep['after']['n'] == 300 and rep['before']['n'] == 400 and rep['levers_applied'] and rep['same_build'])
    return ok, (rep['after']['config'], rep['before']['config'], rep['after']['n'])


def kat_lr2(over):
    m = load(over)
    gain = analyse(m, B(), A())['hash']['verdict']
    same = analyse(m, B(), A(hs=94000))['hash']['verdict']
    loss = analyse(m, B(), A(hs=88000))['hash']['verdict']
    return (gain, same, loss) == ('GAIN', 'WITHIN-NOISE', 'LOSS'), (gain, same, loss)


def kat_lr3(over):
    m = load(over)
    short = analyse(m, B(), A(n=120))['hash']
    build = analyse(m, B(), A(v='r31'))['hash']
    nolev = analyse(m, B(), A(geom='4096,4,2'))
    ok = (short['verdict'] == 'PARTIAL' and 'full G34 window' in short['detail'] and build['verdict'] == 'PARTIAL'
          and 'different builds' in build['detail'] and nolev['hash']['verdict'] == 'PARTIAL' and not nolev['levers_applied'])
    return ok, (short, build['verdict'], nolev['hash']['verdict'])


def kat_lr4(over):
    m = load(over)
    r = analyse(m, B(), A())['rewards']
    lo, hi = r.get('per_ghash_ratio_95') or (None, None)
    ok = r['label'].startswith('PARTIAL') and r.get('per_ghash_ratio') is not None and lo < r['per_ghash_ratio'] < hi
    return ok, r


KATS = [('LR1', kat_lr1), ('LR2', kat_lr2), ('LR3', kat_lr3), ('LR4', kat_lr4)]
OWNERS = {'B291 cfg': ['LR1', 'LR2'], 'B291 verdict': ['LR2'], 'B291 refuse': ['LR3'], 'B291 rewards': ['LR4']}
MUTATIONS = [
    ('tool', "        if r['M'].startswith(GEOM_M) and c['geometry'] is None and f.get('batch'):", "        if False:",
     'B291 cfg: the split geometry is not read'),
    ('tool', "    if ratio - 1 > 2 * se:\n        return 'GAIN', det", "    if ratio - 1 > 0:\n        return 'GAIN', det",
     'B291 verdict: any higher mean is a GAIN (no noise bound)'),
    ('tool', "    if 1 - ratio > 2 * se:\n        return 'LOSS', det", "    if False:\n        return 'LOSS', det",
     'B291 verdict: a slower run is never a LOSS'),
    ('tool', "    if not same_build:\n        return 'PARTIAL'", "    if False:\n        return 'PARTIAL'",
     'B291 refuse: runs of different builds give a lever verdict'),
    ('tool', "    if not full:\n        return 'PARTIAL'", "    if False:\n        return 'PARTIAL'",
     'B291 refuse: a short AFTER window gives a verdict'),
    ('tool', "           'hash': {'verdict': word if applied else", "           'hash': {'verdict': word if True else",
     'B291 refuse: a run without the levers gives a lever verdict'),
    ('tool', "    out['label'] = 'PARTIAL (< 24 h of AFTER: luck decides nothing shorter)' if after['seconds'] < 86400 else 'FULL (>= 24 h)'",
     "    out['label'] = 'FULL (>= 24 h)'", 'B291 rewards: a short reward read is labelled FULL'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_lr30', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def defect(why):
    return ' '.join(why.split(':')[0].split()[:2])


def run_kats(over):
    res = []
    for name, fn in KATS:
        try:
            ok, det = fn(over)
        except (Exception, SystemExit) as e:                      # noqa: BLE001 — a crash is a failure
            ok, det = False, f'{type(e).__name__}: {e}'
        res.append((name, bool(ok), str(det)))
    return res


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr30 levers-read KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='lr30-mut-') as d:
            for rel in SIBLINGS:
                (Path(d) / rel).parent.mkdir(parents=True, exist_ok=True)
                (Path(d) / rel).write_text((ROOT / rel).read_text(encoding='utf-8'), encoding='utf-8')
            (Path(d) / PATHS[key]).write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({'root': d}) if not ok]
        verdict, cpl = K.classify(failed, OWNERS.get(defect(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
        coupled += bool(cpl)
    print('\n' + K.summary('r30 levers-read KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
