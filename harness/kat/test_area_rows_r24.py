#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the src-arch Areas rows (harness/miners/mine_areas.py), r24 verify-areaintel.

mine_areas.py turns harness/runtime/area_intel.json into page rows whose evidence cites the scorecard line of each
metric shown. A display such as "3/3" or "0" repeats across areas, so the cited line must be the one inside the
area's own block and inside the metric's "last" object, not the first hit in the file.

  AR1 two areas share a metric id and a display (series and last alike): each row cites its own area's "last"
      display line, found by an independent walk of the file.

Each KAT runs mine_areas.py on a synthetic scorecard in a temp tree (no real file is read or written).
  python3 -I harness/kat/test_area_rows_r24.py   # exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught
A mutation that crashes the KAT is INVALID, not caught.
"""
import json, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
FILES = ('miners/mine_areas.py', 'miners/minelib.py', 'kit/privkit.py')   # r24: minelib.emit pseudonymises through privkit


def metric(mid, display, series_display=None):
    pt = lambda d: {'round': 'r1', 'value': 3, 'display': d, 'anchor': {'file': 'x.txt', 'quote': 'some quote here', 'line': 1},
                    'source': 'computed'}
    return {'id': mid, 'what': mid, 'unit': '', 'better': 'higher', 'series': [pt(series_display or display)],
            'last': pt(display), 'prev': None, 'trend': 'new', 'regression': False}


def card(aid, metrics):
    return {'id': aid, 'title': f'Area {aid} title', 'owner_dim': aid, 'status': 'active', 'state': 'OK',
            'mutations_now': {'caught': 1, 'total': 1, 'record': 'gomut_x.json'}, 'gates_now': {'state': {'G1': 'PASS'}},
            'backlog': {'open': []}, 'metrics': metrics, 'proposals': [], 'held': []}


def run_tree(base, doc):
    t = Path(tempfile.mkdtemp(prefix='r24ar-'))
    for f in FILES:
        (t / 'harness' / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(base / f, t / 'harness' / f)
    p = t / 'harness/runtime/area_intel.json'
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + '\n')
    r = subprocess.run([sys.executable, '-I', str(t / 'harness/miners/mine_areas.py')], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        shutil.rmtree(t, ignore_errors=True)
        raise RuntimeError(f'mine_areas rc={r.returncode}: {r.stderr[-300:]}')
    rows = json.loads((t / 'harness/model/raw/areacards.json').read_text())['rows']
    raw = p.read_text().splitlines()
    shutil.rmtree(t, ignore_errors=True)
    return rows, raw


def owner_last_line(raw, title, mid, display):
    """Ground truth by a different walk: the "display" line right after the "last": { that follows metric mid in title's block."""
    h = next(i for i, l in enumerate(raw) if l.strip() == f'"title": {json.dumps(title)},')
    i = next(i for i in range(h, len(raw)) if raw[i].strip() == f'"id": {json.dumps(mid)},')
    j = next(i for i in range(i, len(raw)) if raw[i].strip() == '"last": {')
    k = next(i for i in range(j, len(raw)) if raw[i].strip().startswith('"display":'))
    return k + 1 if raw[k].strip() == f'"display": {json.dumps(display)},' else None


def ar1(base):
    doc = {'run_id': 'x', 'captured': 'now', 'areas': [card('a', [metric('mutations', '3/3')]), card('b', [metric('mutations', '3/3')]),
                                                       card('c', [metric('gates', '1/1'), metric('mutations', '3/3')])]}
    rows, raw = run_tree(base, doc)
    got, want = {}, {}
    for r in rows:
        got[r['area']] = [e['line'] for e in r['evidence'][1:] if '3/3' in e['quote']]
        want[r['area']] = [owner_last_line(raw, r['title'], 'mutations', '3/3')]
    return got == want and len(rows) == 3 and all(len(v) == 1 for v in got.values()), f'cited {got} want {want}'


KATS = [('AR1', ar1)]

MUTATIONS = [
    ('AR1', "    i = next((k for k in range(lo, hi) if raw[k - 1].strip() == idq), None)",
     "    i = next((k for k in range(1, hi) if raw[k - 1].strip() == idq), None)", "the area block's start is ignored"),
    ('AR1', "    j = next((k for k in range(i + 1, hi) if raw[k - 1].strip() == '\"last\": {'), None)",
     "    j = i", 'the series display is cited instead of the last one'),
]


def copy_base():
    d = Path(tempfile.mkdtemp(prefix='r24arm-'))
    for f in FILES:
        (d / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HARNESS / f, d / f)
    return d


def main():
    fails = 0
    base = copy_base()
    for name, fn in KATS:
        try:
            ok, det = fn(base)
        except Exception as e:                                    # noqa: BLE001
            ok, det = False, f'{type(e).__name__}: {e}'
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:420]}")
    shutil.rmtree(base, ignore_errors=True)
    missed, byname = 0, dict(KATS)
    for kat, find, repl, why in MUTATIONS:
        d = copy_base()
        p = d / FILES[0]
        text = p.read_text()
        if text.count(find) != 1:
            print(f'  ??      {kat}: {why} — find text occurs {text.count(find)} times')
            missed += 1
            shutil.rmtree(d, ignore_errors=True)
            continue
        p.write_text(text.replace(find, repl))
        try:
            ok2, _ = byname[kat](d)
            verdict = 'MISSED ' if ok2 else 'proved '
        except Exception as e:                                     # noqa: BLE001 — a crash proves nothing: INVALID
            ok2, verdict = True, f'INVALID ({type(e).__name__})'
        print(f'  {verdict} {kat}: {why}')
        missed += ok2
        shutil.rmtree(d, ignore_errors=True)
    print(f'\nR24 area-rows KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
