#!/usr/bin/env python3
"""test_stepbudget_r29.py — r29 (rft §7 B192): the S7 step budgets follow their rule and every step has a row.

B192: the r28d project stage ran 2,384-2,390 s against its 1,840 s budget. The overrun was two R28 KATs
(test_miners_r28.py 441 s, test_tools_kats_r28.py 377 s) with no row of their own (12 R28/R28d steps ran on the 60 s
default); without them the stage was 1,566 s. harness/kit/stepbudget.py now has unbudgeted() and derive() (the `_doc`
rule as code), and harness/loop/STEP_BUDGETS.json is re-derived from the three newest project-only PASS records.

  SB1  unbudgeted() names the steps with no row (run ids folded); report() carries them; a row covers its step
  SB2  derive() on forged records: max(30, 1.5 x slowest, up to 10 s) per step, wall 1.25 x the slowest wall (+ landed
       steps), up to 10 s; a landed step takes its measured seconds
  SB3  the tree's STEP_BUDGETS.json equals derive() of the three records its _doc names (plus its landed steps)
  SB4  the newest project-only PASS record has no step without a row, and stays inside its wall budget
  SB5  the r26 regression record (frontend2 KAT 858 s) is still flagged at step level under the re-derived budgets

  python3 -I harness/kat/test_stepbudget_r29.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, importlib.util, io, json, re, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'sb': 'harness/kit/stepbudget.py', 'budgets': 'harness/loop/STEP_BUDGETS.json'}
R26_RECORD = 'harness/loop/runs/pipeline_20261105T090420.jsonl'


def P(over, key):
    return Path(over.get(key) or (ROOT / PATHS[key]))


def load(over):
    spec = importlib.util.spec_from_file_location(f'sb29_{len(sys.modules)}', P(over, 'sb'))
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


def ev_of(steps, t0='2026-11-08T00:00:00-08:00'):
    return [{'t': t0, 'stage': 'project', 'status': 'START'}] + \
        [{'t': t0, 'stage': 'project', 'status': 'INFO', 'step': s, 'secs': n} for s, n in steps] + \
        [{'t': t0, 'stage': 'project', 'status': 'PASS'}]


def records(rel):
    return [json.loads(l) for l in (ROOT / rel).read_text().splitlines() if l.strip()]


def kat_sb1(over):
    SB = load(over)
    doc = {'default_s': 60, 'project_wall_s': 100, 'steps': {'a.py': 40, 'harness/run_gates.py pipeline-<TS>': 90}}
    st = [('a.py', 10.0), ('b.py', 5.0), ('harness/run_gates.py pipeline-20261108T000000', 80.0), ('b.py', 1.0)]
    bad = []
    if SB.unbudgeted(st, doc) != ['b.py']:
        bad.append(f'unbudgeted {SB.unbudgeted(st, doc)}')
    if SB.unbudgeted([('a.py', 1.0)], doc) != []:
        bad.append('a row does not cover its step')
    if SB.report(ev_of(st), doc).get('unbudgeted') != ['b.py']:
        bad.append('report() lacks unbudgeted')
    return not bad, '; '.join(bad) or 'b.py named, run ids folded, report carries it'


def kat_sb2(over):
    SB = load(over)
    r1 = ev_of([('a.py', 10.0), ('b.py', 100.0)])
    r2 = ev_of([('a.py', 25.0), ('b.py', 90.0)])
    r3 = ev_of([('a.py', 5.0), ('b.py', 101.0), ('c.py', 0.5)])
    d = SB.derive([r1, r2, r3], {'new.py': 12.0}, 60)
    want = {'default_s': 60, 'project_wall_s': 160, 'steps': {'a.py': 40, 'b.py': 160, 'c.py': 30, 'new.py': 30}}
    # a: 1.5 x 25 = 37.5 -> 40; b: 1.5 x 101 = 151.5 -> 160; c: max(30, 0.75 -> 10); new: 18 -> 20 -> 30;
    # wall: 1.25 x (115 + 12) = 158.75 -> 160 (the slowest wall is r2's 115 s; r3 is 106.5 s)
    return d == want, f'{d}' if d != want else 'rule arithmetic exact (max 30, 1.5x, 1.25x wall + landed, up to 10 s)'


def kat_sb3(over):
    SB = load(over)
    doc = json.loads(P(over, 'budgets').read_text())
    names = re.findall(r'pipeline_\d{8}T\d{6}\.jsonl', doc.get('_doc', ''))
    # r30 post-close (D-26): a landed step may live under artifacts/ (artifacts/src/gen_enhancements.py --check)
    # r30: a landed S7 step may carry its arguments ('harness/intel/hashrate_objective.py --write 1 s'), as derive() keys do
    landed = dict((k, float(v)) for k, v in re.findall(r'((?:harness|artifacts)/\S+\.py(?: --?[\w-]+| [a-z]+)*) ([\d.]+) s',
                                                        doc.get('_doc', '').split('landed:')[-1]))
    if len(names) != 3:
        return False, f'_doc names {len(names)} records'
    got = SB.derive([records(f'harness/loop/runs/{n}') for n in names], landed, doc.get('default_s', 60))
    body = {k: v for k, v in doc.items() if k != '_doc'}
    if got != body:
        diff = [k for k in set(got['steps']) | set(body.get('steps', {})) if got['steps'].get(k) != body.get('steps', {}).get(k)]
        return False, f"file differs from its rule: wall {body.get('project_wall_s')} vs {got['project_wall_s']}, rows {diff[:4]}"
    return True, f"{len(body['steps'])} rows and wall {body['project_wall_s']} s = derive({', '.join(names)}; landed {len(landed)})"


def kat_sb4(over):
    SB = load(over)
    doc = json.loads(P(over, 'budgets').read_text())
    recs = sorted((ROOT / 'harness/loop/runs').glob('pipeline_*.jsonl'))
    evs = [[json.loads(l) for l in p.read_text().splitlines() if l.strip()] for p in recs]
    i = SB.project_only_pass(evs)                       # r30 B262: the newest PROJECT-ONLY PASS record
    if i is None:
        return False, 'no project-only PASS record'
    p, ev = recs[i], evs[i]
    r = SB.report(ev, doc)
    ok = not r['unbudgeted'] and not r['wall_over']
    return ok, (f"{p.name}: {r['steps']} steps, no row {r['unbudgeted'][:3]}, wall {r['wall_s']:g}/{r['wall_budget_s']:g}"
                f" over {r['wall_over']}")


def kat_sb6(over):
    """r30 B262: a full run (build stage) with a project PASS is never the project-only record SB4 judges"""
    SB = load(over)
    proj = [{'stage': 'project', 'status': 'PASS'}]
    full = [{'stage': 'build', 'status': 'PASS'}, {'stage': 'project', 'status': 'PASS'}]
    fail = [{'stage': 'project', 'status': 'FAIL'}]
    got = (SB.project_only_pass([proj, full]), SB.project_only_pass([proj, fail]), SB.project_only_pass([full]))
    return got == (0, 0, None), got


def kat_sb5(over):
    SB = load(over)
    doc = json.loads(P(over, 'budgets').read_text())
    r = SB.report(records(R26_RECORD), doc)
    ok = any('test_forensics_frontend2_r26.py' in x for x in r['over'])
    return ok, f"r26 record over: {r['over'][:2]}"


KATS = [('SB1', kat_sb1), ('SB2', kat_sb2), ('SB3', kat_sb3), ('SB4', kat_sb4), ('SB5', kat_sb5), ('SB6', kat_sb6)]
OWNERS = {'B192': ['SB1', 'SB2', 'SB3', 'SB4', 'SB5'], 'B262': ['SB4', 'SB6']}
# r29 merge: the hand-edit mutation reads the file's current wall (it pinned 2990 and went stale when the merge re-derived)
_WALL = json.loads((ROOT / 'harness/loop/STEP_BUDGETS.json').read_text())['project_wall_s']
MUTATIONS = [
    ('sb', "    return sorted({norm(s) for s, _ in steps} - set(b))", "    return []", 'B192: a step without a row goes unnamed'),
    ('sb', "            'steps': {k: max(30, _up10(1.5 * n)) for k, n in sorted(slow.items())}}",
     "            'steps': {k: max(30, _up10(1.4 * n)) for k, n in sorted(slow.items())}}", 'B192: the step factor drifts from the rule'),
    ('sb', "            'steps': {k: max(30, _up10(1.5 * n)) for k, n in sorted(slow.items())}}",
     "            'steps': {k: max(0, _up10(1.5 * n)) for k, n in sorted(slow.items())}}", 'B192: the 30 s floor is lost'),
    ('sb', "        if k not in slow:\n            extra += float(n)", "        if False:\n            extra += float(n)",
     'B192: a landed step is left out of the wall budget'),
    ('sb', "            'over': [f'{k} {n:g}s > {b:g}s' for k, n, b in over(st, doc)], 'unbudgeted': unbudgeted(st, doc)}",
     "            'over': [f'{k} {n:g}s > {b:g}s' for k, n, b in over(st, doc)], 'unbudgeted': []}", 'B192: report() drops the steps without a row'),
    ('budgets', f'"project_wall_s": {_WALL}', f'"project_wall_s": {_WALL + 10}', 'B192: the wall budget is edited by hand'),
    ('sb', "        if any(o.get('stage') == 'build' for o in ev):\n            continue", "        if False:\n            continue",
     'B262: a full run is judged as the project-only record'),
    ('sb', "        if any(o.get('stage') == 'project' and o.get('status') == 'PASS' for o in ev):\n            return i",
     "        if any(o.get('stage') == 'project' for o in ev):\n            return i", 'B262: a FAIL record is judged as a PASS'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_sb29', HARNESS / 'kit' / 'katmut.py')
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
        res.append((name, ok, det))
    return res


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:500]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr29 stepbudget KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        src = ROOT / PATHS[key]
        text = src.read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='sb29-mut-') as d:
            mut = Path(d) / PATHS[key]
            mut.parent.mkdir(parents=True, exist_ok=True)
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            try:
                if mut.suffix == '.py':
                    compile(mut.read_text(encoding='utf-8'), str(mut), 'exec')
                else:
                    json.loads(mut.read_text(encoding='utf-8'))
            except (SyntaxError, ValueError) as e:
                print(f'  INVALID   {why}: mutant does not load ({type(e).__name__})')
                missed += 1
                continue
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, extra = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r29 stepbudget KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
