#!/usr/bin/env python3
"""stepbudget.py — r28 (rft §7 B133, §0.9 rule 2): a wall-time budget per S7 step of the pipeline.

B133: tooling.project_wall_s went 512 s (r25) -> 1,901 s (r26) -> 1,469 s (r27) and the cause was found by hand, step
by step, a round late. The budget file harness/loop/STEP_BUDGETS.json holds, per S7 step (the step text as the
pipeline record writes it, run ids normalised to 'pipeline-<TS>'), the seconds it may take, derived from measured
records (its `_doc` names them and the rule), a default for a step it does not list, and a budget for the whole
project stage. The pipeline writes each step's `secs` into its record and the step list that went over budget into
the project PASS/FAIL event (`over_budget`, report-only: wall time under load is not a correctness failure);
tooling_intel reads the same function for the KPI steps_over_budget (target 0).

  python3 -I harness/kit/stepbudget.py [--record harness/loop/runs/pipeline_<ts>.jsonl]
      # the steps of a record (default: the newest) against the budgets; exit 0 within budget · 5 over (or a step with
      # no row of its own) · 2 unreadable
  python3 -I harness/kit/stepbudget.py --derive <rec1.jsonl> <rec2.jsonl> <rec3.jsonl> [--landed key=secs ...] [--write]
      # r29 (B192): the budget document the `_doc` rule gives for those records (print, or --write it); a step newer
      # than every record (a KAT that lands this round) takes its measured seconds from --landed

r29 (B192): the r28d project stage ran 2,384-2,390 s against 1,840 s. stepbudget found the two R28 KATs over budget
(test_miners_r28.py 441 s, test_tools_kats_r28.py 377 s); both had no row of their own and ran on the 60 s default,
because the rule's "a new KAT gets a row the round it lands" was never done for them. Without them the stage is 1,566 s,
inside 1,840 s. unbudgeted() now names such steps (the root cause) and derive() is the rule as code, so a re-derivation
is one command instead of hand work.
"""
import datetime, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
BUDGETS = 'harness/loop/STEP_BUDGETS.json'
TS_RX = re.compile(r'pipeline-\d{8}T\d{6}')


def norm(step):
    """the budget key of a step text: run ids become 'pipeline-<TS>'. Pure."""
    return TS_RX.sub('pipeline-<TS>', str(step or '').strip())


def load(root=ROOT):
    """the budget document ({'default_s', 'project_wall_s', 'steps': {key: s}}); raises OSError/ValueError."""
    return json.loads((Path(root) / BUDGETS).read_text())


def _ts(o):
    try:
        return datetime.datetime.fromisoformat(o['t'])
    except (KeyError, TypeError, ValueError):
        return None


def step_secs(events):
    """[(step, seconds)] of the project stage of one record: the event's own `secs` when the pipeline wrote it (r28),
    else the time since the previous event (records before r28; the pipeline runs S7 steps one after another). Pure."""
    out, prev = [], None
    for o in events:
        t = _ts(o)
        if o.get('stage') == 'project' and o.get('step') and o.get('status') == 'INFO' and not o.get('skipped'):
            if isinstance(o.get('secs'), (int, float)):
                out.append((o['step'], float(o['secs'])))
            elif t and prev:
                out.append((o['step'], (t - prev).total_seconds()))
        if t:
            prev = t
    return out


def over(steps, doc):
    """[(key, seconds, budget)] of the steps over their budget, slowest overrun first. Pure."""
    default = float(doc.get('default_s', 60))
    b = doc.get('steps') or {}
    res = []
    for s, n in steps:
        k = norm(s)
        lim = float(b.get(k, default))
        if n > lim:
            res.append((k, round(n, 1), lim))
    return sorted(res, key=lambda x: -(x[1] - x[2]))


def wall_over(steps, doc):
    """(total seconds, budget, over?) of the project stage. Pure."""
    tot = round(sum(n for _, n in steps), 1)
    lim = float(doc.get('project_wall_s', 0) or 0)
    return tot, lim, bool(lim and tot > lim)


def unbudgeted(steps, doc):
    """[key] of the steps that have no row of their own and run on default_s: a KAT that landed without its budget row
    (r29 B192). Pure."""
    b = doc.get('steps') or {}
    return sorted({norm(s) for s, _ in steps} - set(b))


def _up10(x):
    return int(-(-float(x) // 10) * 10)


def derive(records, landed=None, default_s=60):
    """the budget document the `_doc` rule gives (r29 B192): `records` = event lists of project-only PASS runs; each
    step's budget = max(30, 1.5 x its slowest time over the records, rounded up to 10 s); `landed` = {key: measured s}
    for steps newer than every record (their measured time joins the slowest wall too); project_wall_s = 1.25 x the
    slowest project wall, rounded up to 10 s. Pure."""
    slow, walls = {}, []
    for ev in records:
        st = step_secs(ev)
        walls.append(sum(n for _, n in st))
        for s, n in st:
            k = norm(s)
            slow[k] = max(slow.get(k, 0.0), n)
    extra = 0.0
    for k, n in (landed or {}).items():
        k = norm(k)
        if k not in slow:
            extra += float(n)
        slow[k] = max(slow.get(k, 0.0), float(n))
    return {'default_s': default_s, 'project_wall_s': _up10(1.25 * (max(walls or [0.0]) + extra)),
            'steps': {k: max(30, _up10(1.5 * n)) for k, n in sorted(slow.items())}}


def project_only_pass(event_lists):
    """r30 B262: the index of the newest PROJECT-ONLY PASS record among `event_lists` (oldest first): a record with a
    project PASS event and NO build stage (a full run's S7 is not a project-only record: its wall includes the full
    run's S1-S5 load; the rule budgets project-only records); None when there is none. Pure."""
    for i in range(len(event_lists) - 1, -1, -1):
        ev = event_lists[i]
        if any(o.get('stage') == 'build' for o in ev):
            continue
        if any(o.get('stage') == 'project' and o.get('status') == 'PASS' for o in ev):
            return i
    return None


def report(events, doc):
    """the `over_budget` field the pipeline writes into its project PASS/FAIL event. Pure."""
    st = step_secs(events)
    tot, lim, wo = wall_over(st, doc)
    return {'steps': len(st), 'wall_s': tot, 'wall_budget_s': lim, 'wall_over': wo,
            'over': [f'{k} {n:g}s > {b:g}s' for k, n, b in over(st, doc)], 'unbudgeted': unbudgeted(st, doc)}


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    if '--derive' in argv:
        return derive_main(argv)
    try:
        doc = load(ROOT)
        rec = Path(argv[argv.index('--record') + 1]) if '--record' in argv else \
            sorted((ROOT / 'harness/loop/runs').glob('pipeline_*.jsonl'))[-1]
        ev = [json.loads(l) for l in rec.read_text().splitlines() if l.strip()]
    except (OSError, ValueError, IndexError) as e:
        print(f'stepbudget: unreadable ({type(e).__name__}: {e})')
        return 2
    r = report(ev, doc)
    for x in r['over']:
        print('OVER', x)
    for x in r['unbudgeted']:
        print('NO ROW', x)
    print(f"stepbudget {rec.name}: {r['steps']} steps · wall {r['wall_s']:g} s (budget {r['wall_budget_s']:g}"
          f"{', OVER' if r['wall_over'] else ''}) · over budget {len(r['over'])} · no row {len(r['unbudgeted'])}")
    return 5 if r['over'] or r['wall_over'] or r['unbudgeted'] else 0


def derive_main(argv):
    """--derive rec... [--landed key=secs ...] [--write]: print (or write) the rule's budget document; the _doc names
    the records. exit 0 · 2 unreadable"""
    i = argv.index('--derive')
    recs, landed, k = [], {}, i + 1
    while k < len(argv) and not argv[k].startswith('--'):
        recs.append(Path(argv[k]))
        k += 1
    for j, a in enumerate(argv):
        if a == '--landed':
            for kv in argv[j + 1:]:
                if kv.startswith('--'):
                    break
                key, _, secs = kv.rpartition('=')
                landed[key] = float(secs)
    try:
        evs = [[json.loads(l) for l in (p if p.is_absolute() else ROOT / p).read_text().splitlines() if l.strip()] for p in recs]
        old = load(ROOT)
    except (OSError, ValueError) as e:
        print(f'stepbudget: unreadable ({type(e).__name__}: {e})')
        return 2
    if len(evs) != 3:
        print('stepbudget: --derive takes exactly three records (the rule)')
        return 2
    doc = derive(evs, landed, old.get('default_s', 60))
    walls = [round(sum(n for _, n in step_secs(ev))) for ev in evs]
    doc = {'_doc': RULE_DOC.format(recs=', '.join(p.name for p in recs), walls=' / '.join(map(str, walls)),
                                   landed=', '.join(f'{norm(a)} {b:g} s' for a, b in landed.items()) or 'none'), **doc}
    text = json.dumps(doc, indent=1, sort_keys=False) + '\n'
    if '--write' in argv:
        (ROOT / BUDGETS).write_text(text)
        print(f'stepbudget: wrote {BUDGETS}: {len(doc["steps"])} rows, project_wall_s {doc["project_wall_s"]}')
    else:
        print(text, end='')
    return 0


RULE_DOC = ('r29 (rft §7 B133, B192; harness/kit/stepbudget.py derive()): seconds each S7 step of the pipeline may take. '
            'Rule: budget = max(30, 1.5 x the slowest of three project-only records, rounded up to 10 s); default_s for a step '
            'not listed (a new KAT gets a row the round it lands: --landed, its measured seconds); project_wall_s = 1.25 x the '
            'slowest project wall (plus the landed steps), rounded up to 10 s. Measured records: {recs} (project walls {walls} s); '
            'landed: {landed}. Report-only: the pipeline writes over_budget into its project event; tooling_intel KPI '
            'steps_over_budget (target 0). Re-derive with the same rule when a step is cut or a step is added, never to hide '
            'an overrun; unbudgeted() names a step without its row.')


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
