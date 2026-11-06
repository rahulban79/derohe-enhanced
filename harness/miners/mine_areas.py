#!/usr/bin/env python3
"""mine_areas.py (r24) — the per-area scorecards of harness/intel/area_intel.py, as page rows.

One row per area of harness/areas.json. Each row anchors on the lines of harness/runtime/area_intel.json that state
it (its title line, and the display line of each metric shown), so its class is HARNESS: the row proves what the
scorecard run measured. The scorecard's own anchors (pipeline records, go_mutate records, the gate ledger, /metrics
captures, the R24 dimension digest) are re-checked by gate G23, not here. A missing or unreadable scorecard yields no
rows and one 'unverified' entry: never a row without an anchor.
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):   # r27 B120: usage, exit 0, nothing run or written
    print(__doc__ or 'usage: see the header of this file')
    raise SystemExit(0)
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import minelib as M

SRC = 'harness/runtime/area_intel.json'


def last_display_line(raw, lo, hi, mid, display):
    """r24 verify-areaintel: the 1-based line of metric `mid`'s "last" display inside the area block raw[lo-1:hi-1].
    A display such as "3/3" or "0" repeats across areas, so the first hit in the file is usually another area's."""
    idq = f'"id": {json.dumps(mid, ensure_ascii=False)},'
    dq = f'"display": {json.dumps(display, ensure_ascii=False)},'
    i = next((k for k in range(lo, hi) if raw[k - 1].strip() == idq), None)
    if i is None:
        return None
    j = next((k for k in range(i + 1, hi) if raw[k - 1].strip() == '"last": {'), None)
    if j is None:
        return None
    for k in range(j + 1, hi):
        s = raw[k - 1].strip()
        if s == dq:
            return k
        if s.startswith('"prev":'):
            return None
    return None


def main():
    p = M.ROOT / SRC
    if not p.exists():
        M.emit('areacards', [], [{'title': 'area scorecards', 'why': f'{SRC} not written yet: run harness/intel/area_intel.py'}], 'mine_areas.py')
        return
    try:
        doc = json.loads(p.read_text())
    except ValueError as e:
        M.emit('areacards', [], [{'title': 'area scorecards', 'why': f'{SRC} unreadable: {e}'}], 'mine_areas.py')
        return
    rows, unv = [], []
    raw = p.read_text().splitlines()
    cards = doc.get('areas', [])
    heads = [M.anchor(SRC, f'"title": {json.dumps(c["title"], ensure_ascii=False)},') for c in cards]
    for ci, c in enumerate(cards):
        head = heads[ci]
        if not head:
            unv.append({'title': c['id'], 'why': 'the area title line is not in the scorecard'})
            continue
        nxt = [h['line'] for h in heads[ci + 1:] if h]
        lo, hi = head['line'], (nxt[0] if nxt else len(raw) + 1)
        ev, shown = [head], []
        for m in c.get('metrics', []):
            last = m.get('last')
            if not last:
                continue
            k = last_display_line(raw, lo, hi, m['id'], last['display'])
            a = M.anchor(SRC, f'"display": {json.dumps(last["display"], ensure_ascii=False)},', hint=k) if k else None
            if a and a['line'] != k:
                a = None
            if a:
                shown.append({'id': m['id'], 'what': m.get('what'), 'display': last['display'], 'round': last['round'],
                              'trend': m.get('trend'), 'regression': m.get('regression'),
                              'prev': (m.get('prev') or {}).get('display'), 'prev_round': (m.get('prev') or {}).get('round'),
                              'cites': f"{last['anchor']['file']}:{last['anchor'].get('line')}"})
                if len(ev) < 6:
                    ev.append(a)
        mn = c.get('mutations_now') or {}
        g = (c.get('gates_now') or {}).get('state') or {}
        gp = sum(1 for v in g.values() if v == 'PASS')
        claim = (f"{c['title']}: {c['state']}" + (f" ({c.get('paused_why')})" if c.get('state') == 'PAUSED' else '') +
                 f"; owner {c['owner_dim']}; go_mutate {mn.get('caught')}/{mn.get('total')} in {mn.get('record')}; "
                 f"gates {gp}/{len(g)} PASS; open backlog {len(c['backlog']['open'])}; proposals {len(c.get('proposals', []))}.")
        rows.append({'id': f"area-{c['id']}", 'section': 'areas', 'title': c['title'], 'class': 'HARNESS', 'claim': claim,
                     'area': c['id'], 'state': c['state'], 'owner': c['owner_dim'], 'mut': f"{mn.get('caught')}/{mn.get('total')}",
                     'gates': f'{gp}/{len(g)}', 'gate_state': g, 'backlog_open': c['backlog']['open'],
                     'proposals': len(c.get('proposals', [])), 'held': len(c.get('held', [])), 'shown': shown,
                     'captured': doc.get('captured'), 'run_id': doc.get('run_id'), 'evidence': ev})
    M.emit('areacards', rows, unv, 'mine_areas.py')


if __name__ == '__main__':
    main()
