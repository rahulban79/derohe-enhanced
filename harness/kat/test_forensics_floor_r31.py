#!/usr/bin/env python3
"""test_forensics_floor_r31.py — r31 dimension 6 (rft §7 B293; area_intel high AP-forensics-metric-regression-62601b):
forensics `replay_full_runs` is a FLOOR, not a higher-is-better trend. G28 needs two full byte-exact replays of the
newest manifest; r28 had 3 and r30 has 2, which the trend rule raised as a regression with 0 % noise. The metric is
now `better: none` with `alert_if < 2`, so the count can move between versions without a proposal and a version with
fewer than two full replays raises a live alert.

  FF1 the registry (harness/areas.json): forensics.replay_full_runs has better 'none' and alert_if {op '<', value 2}
  FF2 area_intel.metric_trend on the registry's own spec: 3 (r28) -> 2 (r31) is no regression; the same series under
      'higher' would be one (the KAT's control, so FF2 cannot pass vacuously)
  FF3 area_intel.alert on the registry's own rule: 1 trips it; 2 and 3 do not

  python3 -I harness/kat/test_forensics_floor_r31.py      # exit 0 · 3 a KAT failed · 4 a mutation was missed
"""
import contextlib, importlib.util, io, json, sys, tempfile, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'tool': 'harness/intel/area_intel.py', 'reg': 'harness/areas.json'}
SIBLINGS = ('harness/intel/area_intel.py', 'harness/intel/coherence.py', 'harness/intel/backlog_truth.py', 'harness/areas.json')


def load(over):
    root = Path(over.get('root') or ROOT)
    spec = importlib.util.spec_from_file_location(f'ff31_{uuid.uuid4().hex[:6]}', root / PATHS['tool'])
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def metric(over):
    root = Path(over.get('root') or ROOT)
    reg = json.loads((root / PATHS['reg']).read_text(encoding='utf-8'))
    area = next(a for a in reg['areas'] if a.get('id') == 'forensics')
    return next(x for x in area['metrics'] if x['id'] == 'replay_full_runs'), root


def series(*vals):
    return [{'round': r, 'value': v, 'display': str(v)} for r, v in zip(('r28', 'r31', 'r32'), vals)]


def kat_ff1(over):
    m, _ = metric(over)
    ok = m.get('better') == 'none' and m.get('alert_if') == {'op': '<', 'value': 2}
    return ok, {'better': m.get('better'), 'alert_if': m.get('alert_if')}


def kat_ff2(over):
    ai = load(over)
    m, root = metric(over)
    _, d, reg_ = ai.metric_trend(m, series(3, 2), root)
    _, dc, regc = ai.metric_trend({**m, 'better': 'higher'}, series(3, 2), root)   # control: the old rule regresses
    return (reg_ is False and regc is True), {'floor': (d, reg_), 'control_higher': (dc, regc)}


def kat_ff3(over):
    ai = load(over)
    m, _ = metric(over)
    got = {v: bool(ai.alert(m.get('alert_if'), v)) for v in (1, 2, 3)}
    return got == {1: True, 2: False, 3: False}, got


KATS = [('FF1', kat_ff1), ('FF2', kat_ff2), ('FF3', kat_ff3)]
OWNERS = {'B293': ['FF1', 'FF2', 'FF3']}
I = ' ' * 5
MUTATIONS = [
    ('reg', f'{I}"unit": "runs",\n{I}"better": "none",', f'{I}"unit": "runs",\n{I}"better": "higher",',
     'B293: replay_full_runs is a higher-is-better trend again (3 -> 2 is a regression)'),
    ('reg', f'{I}"alert_if": {{\n{I} "op": "<",\n{I} "value": 2\n{I}}}\n    }},\n    {{\n{I}"id": "audit_holds"',
     f'{I}"alert_if": {{\n{I} "op": "<",\n{I} "value": 1\n{I}}}\n    }},\n    {{\n{I}"id": "audit_holds"',
     'B293: the floor is 1, so a version with one full replay raises no alert'),
    ('reg', f'{I}"alert_if": {{\n{I} "op": "<",\n{I} "value": 2\n{I}}}\n    }},\n    {{\n{I}"id": "audit_holds"',
     f'{I}"alert_if_off": {{\n{I} "op": "<",\n{I} "value": 2\n{I}}}\n    }},\n    {{\n{I}"id": "audit_holds"',
     'B293: no floor alert at all'),
    ('tool', "    return {'>': v > x, '<': v < x,", "    return {'>': v > x, '<': v <= x,",
     'B293: the floor fires at exactly two replays'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_ff31', HARNESS / 'kit' / 'katmut.py')
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
        print(f'\nr31 forensics-floor KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='ff31-mut-') as d:
            for rel in SIBLINGS:                                   # the mutant tree: the tool loads its siblings
                (Path(d) / rel).parent.mkdir(parents=True, exist_ok=True)
                (Path(d) / rel).write_text((ROOT / rel).read_text(encoding='utf-8'), encoding='utf-8')
            (Path(d) / PATHS[key]).write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({'root': d}) if not ok]
        verdict, cpl = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
        coupled += bool(cpl)
    print('\n' + K.summary('r31 forensics-floor KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
