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
      # the steps of a record (default: the newest) against the budgets; exit 0 within budget · 5 over · 2 unreadable
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


def report(events, doc):
    """the `over_budget` field the pipeline writes into its project PASS/FAIL event. Pure."""
    st = step_secs(events)
    tot, lim, wo = wall_over(st, doc)
    return {'steps': len(st), 'wall_s': tot, 'wall_budget_s': lim, 'wall_over': wo,
            'over': [f'{k} {n:g}s > {b:g}s' for k, n, b in over(st, doc)]}


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
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
    print(f"stepbudget {rec.name}: {r['steps']} steps · wall {r['wall_s']:g} s (budget {r['wall_budget_s']:g}"
          f"{', OVER' if r['wall_over'] else ''}) · over budget {len(r['over'])}")
    return 5 if r['over'] or r['wall_over'] else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
