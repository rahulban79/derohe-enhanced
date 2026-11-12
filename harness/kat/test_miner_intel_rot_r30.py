#!/usr/bin/env python3
"""test_miner_intel_rot_r30.py — r30 (rft §7 B254, user 2026-11-11 "make sure to fix such issues"): miner_intel reads
derod's ROTATED log chain and never raises a share drought from a log that is not there.

Found at the R30 resume: closed-loop run 8 (pipeline_20261109T170816) failed S7 on G17 "the live miner is healthy",
because minerintel_20261109T204102 said "no accepted own miniblock for 16.00 h from 2026-11-08T21:19:22" while derod's
own counters showed 3,376 paid miniblocks in that window. Cause: derod rotated its log at 100 MB (2026-11-09 13:17:18,
lumberjack backup derod-2026-11-09T21-17-18.376.log) and miner_intel read the live derod.log only, so every own
miniblock before the rotation was invisible and the run's start-to-first-visible stretch looked like a drought.

  MR1 the derod chain is the lumberjack backups (derod-<time>.log, oldest first) then the live file; own miniblocks in a
      backup count, and a run whose shares are split across the rotation has no share_drought
  MR2 when the oldest available derod log begins after the run started (a backup rotated away), the drought window
      starts where the evidence starts: no share_drought ALERT, a derod_head_missing WARN with the missing hours
  MR3 a real share-free stretch INSIDE the covered window still raises share_drought ALERT (the guard hides nothing)

All inputs are forged in a temporary directory; nothing outside it is read or written.
  python3 -I harness/kat/test_miner_intel_rot_r30.py      # exit 0 · 3 a KAT failed · 4 a mutation was missed
"""
import contextlib, importlib.util, io, json, shutil, sys, tempfile, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'tool': 'harness/intel/miner_intel.py'}


def load(over):
    root = Path(over.get('root') or ROOT)
    spec = importlib.util.spec_from_file_location(f'mi_rot_{uuid.uuid4().hex[:6]}', root / PATHS['tool'])
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def J(**kv):
    return json.dumps(kv)


def T(h, m=0):
    return f'2026-10-28T{h:02d}:{m:02d}:00.000-0700'


def miner_log(hours=10):
    L = [J(L='INFO', T=T(0), N='miner', M='DERO Stargate HE AstroBWT miner : It is an alpha version, use it for testing/evaluations purpose only.'),
         J(L='INFO', T=T(0), N='miner', M='', Version='v-r30'),
         J(L='INFO', T=T(0), N='miner', M='', Arguments={'--mining-threads': '20', '--gpu-mode': 'split'})]
    for k in range(hours * 4 + 1):
        h, m = divmod(k * 15, 60)
        L.append(J(L='INFO', T=T(h, m), N='miner', M='TOTAL hashrate', **{'H/s': '100000'}))
        L.append(J(L='DEBUG', T=T(h, m), N='miner', M='GPU-split found DERO miniblock (submitting)', difficulty='3000000'))
    return '\n'.join(L) + '\n'


def derod_lines(h0, h1, own_every_min=10, skip=None):
    """Chain extended every 5 min and an own miniblock every own_every_min over [h0, h1) hours; skip = (ha, hb) has no
    own miniblock (a real drought)"""
    L = []
    for mins in range(h0 * 60, h1 * 60, 5):
        h, m = divmod(mins, 60)
        L.append(J(L='DEBUG', T=T(h, m), N='CORE', M='Chain extended', **{'new height': 1000 + mins}))
        if mins % own_every_min == 0 and not (skip and skip[0] * 60 <= mins < skip[1] * 60):
            L.append(J(L='DEBUG', T=T(h, m), N='P2P', M='Own miniblock delivered', height=1000 + mins))
    return '\n'.join(L) + '\n'


def setup(d, parts):
    """parts = [(file name, h0, h1, skip)] in the derod log dir; returns (miner log, derod live log, root)"""
    root = Path(d) / 'root'
    (root / 'config').mkdir(parents=True)
    (root / 'config/version.go').write_text('var Version = semver.MustParse("v-r30")\n')
    ml = Path(d) / 'bin' / 'dero-miner.log'
    ml.parent.mkdir()
    ml.write_text(miner_log())
    logs = Path(d) / 'logs'
    logs.mkdir()
    for name, h0, h1, skip in parts:
        (logs / name).write_text(derod_lines(h0, h1, skip=skip))
    return ml, logs / 'derod.log', root


def analyse(m, ml, dl, root):
    with contextlib.redirect_stdout(io.StringIO()):
        rep = m.analyse(str(ml), str(dl), use_rpc=False, now=m.ts(T(10)) + 60, root=root)
    run = rep['runs'][-1]
    return rep, run, {a['rule']: a['level'] for a in run['alerts']}


def kat_mr1(over):
    m = load(over)
    with tempfile.TemporaryDirectory() as d:
        ml, dl, root = setup(d, [('derod-2026-10-28T05-00-00.000.log', 0, 3, None),
                                 ('derod-2026-10-28T09-00-00.000.log', 3, 6, None), ('derod.log', 6, 11, None)])
        rep, run, rules = analyse(m, ml, dl, root)
        names = [Path(x).name for x in rep.get('derod_logs') or []]
        sub = (run.get('shares') or {}).get('submissions')
        ok = (names == ['derod-2026-10-28T05-00-00.000.log', 'derod-2026-10-28T09-00-00.000.log', 'derod.log']
              and 'share_drought' not in rules and sub == 61 and 'derod_head_missing' not in rules)
        return ok, (names, sub, rules)


def kat_mr2(over):
    m = load(over)
    with tempfile.TemporaryDirectory() as d:
        ml, dl, root = setup(d, [('derod.log', 6, 11, None)])            # the backups rotated away: first 6 h unseen
        rep, run, rules = analyse(m, ml, dl, root)
        sh = run.get('shares') or {}
        ok = ('share_drought' not in rules and rules.get('derod_head_missing') == 'WARN'
              and sh.get('derod_head_missing_h') == 6.0)
        return ok, (rules, sh)


def kat_mr3(over):
    m = load(over)
    with tempfile.TemporaryDirectory() as d:
        ml, dl, root = setup(d, [('derod-2026-10-28T06-00-00.000.log', 0, 5, None), ('derod.log', 5, 11, (6, 9))])
        rep, run, rules = analyse(m, ml, dl, root)
        sh = run.get('shares') or {}
        ok = rules.get('share_drought') == 'ALERT' and 'derod_head_missing' not in rules and sh.get('longest_gap_s', 0) >= 3 * 3600
        return ok, (rules, sh.get('longest_gap_s'))


KATS = [('MR1', kat_mr1), ('MR2', kat_mr2), ('MR3', kat_mr3)]
OWNERS = {'B254': ['MR1', 'MR2', 'MR3']}
MUTATIONS = [
    ('tool', "    return backups + ([live] if live.exists() else [])", "    return [live] if live.exists() else []",
     'B254: only the live derod.log is read (the rotated backups are lost)'),
    ('tool', "    backups = sorted(p for p in live.parent.glob('derod-*.log') if p.is_file() and p != live)",
     "    backups = sorted((p for p in live.parent.glob('derod-*.log') if p.is_file() and p != live), reverse=True)",
     'B254: the backups are read newest first'),
    ('tool', "        start = max(t0, cov) if cov is not None else t0", "        start = t0",
     'B254: the drought window starts before the derod evidence starts'),
    ('tool', "    if sh.get('derod_head_missing_h'):", "    if False:", 'B254: a missing derod head is not reported'),
    ('tool', "        derod_recs = [d for f in derod_chain(derod_log) for d in records(f) if d.get('M') in ('Chain extended', OWN_MB)]",
     "        derod_recs = [d for d in records(derod_log) if d.get('M') in ('Chain extended', OWN_MB)]",
     'B254: analyse reads the live derod.log only'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_mr30', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


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
        print(f'\nr30 miner-intel rotation KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='mr30-mut-') as d:
            mut = Path(d) / PATHS[key]
            mut.parent.mkdir(parents=True)
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({'root': d}) if not ok]
        verdict, cpl = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r30 miner-intel rotation KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
