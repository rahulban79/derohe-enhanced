#!/usr/bin/env python3
"""R30 B215 coverage map: `derived/coverage.json` = segments x checks over 0..tip, each cell done / pending /
undecidable with the record (path + SHA-256) that makes it so. Generators read this map; nothing here is typed in:
the tile boundaries come from the R29 B182 deep record (S2), audit2.WALLS / audit2.WINDOW (wall 1, wall 2, the HF3
window), the census `to` and the tip read record.

Rules (fail closed):
  * the tiles cover 0..tip exactly: no gap, no overlap, increasing (check() FAILs otherwise);
  * a cell is `done` only with a record path that exists and whose SHA-256 is stated; a `done` without a record FAILs;
  * `pending` is never rendered as 0 (render() prints the word);
  * DC2 is `undecidable` in every tile (BDU: separating the cases needs an accepted-invalid proof, rft §9); the state of
    wall 1 .. wall 2 - 1 is `undecidable` (no held state, B95/B76).

  python3 -I harness/forensics/coverage.py [--census harness/runtime/r30_genesis_census.json]
         [--tip harness/runtime/r30_genesis_tip.json] [--out harness/runtime/r30_genesis_coverage.json]
"""
import argparse, hashlib, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))

CHECKS = ('chain', 'txid', 'types', 'reg_lz', 'dup', 'emission', 'fees_burns', 'sc_payouts', 'canonicality', 'version',
          'state_root', 'dc2')
STATES = ('done', 'pending', 'undecidable')


def fsha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def tiles(s2_hi, to, tip, walls, window):
    """the tile list [(id, lo, hi)] (pure)."""
    w1, w2 = walls['wall1'], walls['wall2']
    return [('A', 0, s2_hi), ('B1', s2_hi + 1, w1 - 1), ('B2', w1, window[0] - 1), ('C1', window[0], w2 - 1),
            ('C2', w2, window[1]), ('D', window[1] + 1, to), ('E', to + 1, tip)]


def check(tl, cells, tip, root=ROOT):
    """list of failures (pure apart from the record files)."""
    f = []
    if not tl or tl[0][1] != 0:
        f.append('tiles do not start at 0')
    for (a, alo, ahi), (b, blo, bhi) in zip(tl, tl[1:]):
        if blo != ahi + 1:
            f.append(f'{a}/{b}: ' + ('gap' if blo > ahi + 1 else 'overlap') + f' at {ahi}/{blo}')
    for t, lo, hi in tl:
        if hi < lo:
            f.append(f'{t}: empty or reversed {lo}..{hi}')
    if tl and tl[-1][2] != tip:
        f.append(f'tiles end at {tl[-1][2]}, tip is {tip}')
    for (t, _, _), row in zip(tl, cells):
        for c in CHECKS:
            cell = row.get(c)
            if not cell or cell.get('state') not in STATES:
                f.append(f'{t}.{c}: no state')
                continue
            if cell['state'] == 'done':
                rec = cell.get('record')
                if not rec or not (Path(root) / rec).exists() or not cell.get('sha256'):
                    f.append(f'{t}.{c}: done without a record')
    return f


def cell(state, record=None, why=None, root=ROOT):
    c = {'state': state}
    if record:
        c['record'] = record
        p = Path(root) / record
        if p.exists():
            c['sha256'] = fsha(p)
    if why:
        c['why'] = why
    return c


def build(census_rel, tip_rel, root=ROOT):
    import audit2
    C = json.loads((Path(root) / census_rel).read_text())
    tipr = json.loads((Path(root) / tip_rel).read_text())
    r29 = json.loads((Path(root) / 'harness/runtime/r29_b182_deep_census.json').read_text())
    (_, s2_hi), = r29['ranges']
    tl = tiles(s2_hi, C['to'], tipr['tip'], audit2.WALLS, audit2.WINDOW)
    clo, chi = C['range'] if C.get('range') else (None, None)
    win = C.get('window', {})
    rows = []
    for t, lo, hi in tl:
        cov = C.get('complete') and clo is not None and clo <= lo and hi <= chi
        em = next((e for e in C.get('tile_emission', []) if e['id'] == t), None)
        row = {}
        for c in ('chain', 'txid', 'types', 'reg_lz', 'dup', 'canonicality', 'version'):
            row[c] = cell('done', census_rel, root=root) if cov else cell('pending', why='above the census top' if lo > (chi or -1) else 'census not complete')
        if cov and em and em['verdict'] == 'HOLDS':
            row['emission'] = cell('done', census_rel, root=root)
        elif cov and em and em['verdict'] == 'FAILS':
            row['emission'] = cell('done', census_rel, why='identity FAILS (see the census emission rows)', root=root)
        else:
            row['emission'] = cell('pending', why='no census cover' if not cov else 'no emission row')
        row['fees_burns'] = cell('done', census_rel, root=root) if cov else cell('pending', why='no census cover')
        if cov and window_inside(lo, hi, audit2.WINDOW) and win.get('verdict') != 'EQUAL':
            row['fees_burns'] = cell('pending', why=f"window re-derivation {win.get('verdict')}")
        row['sc_payouts'] = cell('pending', why='needs execution: the S7 replay below the window; run C partial (B110); live audit S4 above')
        if hi < audit2.WALLS['wall1'] or lo > audit2.WINDOW[1]:
            row['state_root'] = cell('pending', why='S7 replay (below wall 1) or S4 clone audit (above the window)')
        elif lo >= audit2.WALLS['wall1'] and hi < audit2.WALLS['wall2']:
            row['state_root'] = cell('undecidable', why='no held state for wall 1 .. wall 2 - 1 (B95, B76)')
        else:
            row['state_root'] = cell('pending', why='v4 roots_window class pending (run C, B213)')
        row['dc2'] = cell('undecidable', why='BDU: separating the cases needs an accepted-invalid proof (rft §9, B113)')
        rows.append(row)
    out = {'schema': 'r30 coverage map v1 (rft §7 B215)', 'checks': list(CHECKS), 'states': list(STATES),
           'tiles': [{'id': t, 'lo': lo, 'hi': hi, 'cells': r} for (t, lo, hi), r in zip(tl, rows)],
           'tip': tipr['tip'], 'inputs': {census_rel: fsha(Path(root) / census_rel), tip_rel: fsha(Path(root) / tip_rel)},
           'boundaries_from': {'S2': 'harness/runtime/r29_b182_deep_census.json ranges', 'walls/window': 'harness/forensics/audit2.py WALLS, WINDOW',
                               'to': census_rel + ' to', 'tip': tip_rel}}
    out['summary'] = {s: sum(1 for r in rows for c in CHECKS if r[c]['state'] == s) for s in STATES}
    out['failures'] = check(tl, rows, tipr['tip'], root)
    out['verdict'] = 'PASS' if not out['failures'] else 'FAIL'
    return out


def window_inside(lo, hi, w):
    return lo <= w[1] and hi >= w[0]


def render(cov):
    """one text line per tile; `pending` / `undecidable` are words, never 0 (pure)."""
    lines = []
    for t in cov['tiles']:
        lines.append(f"{t['id']} {t['lo']:,}..{t['hi']:,}: " + ' '.join(f"{c}={t['cells'][c]['state']}" for c in cov['checks']))
    return lines


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--census', default='harness/runtime/r30_genesis_census.json')
    ap.add_argument('--tip', default='harness/runtime/r30_genesis_tip.json')
    ap.add_argument('--out', default='harness/runtime/r30_genesis_coverage.json')
    a = ap.parse_args(argv)
    cov = build(a.census, a.tip)
    (ROOT / a.out).write_text(json.dumps(cov, indent=1, sort_keys=True) + '\n')
    print('\n'.join(render(cov)))
    print(json.dumps({'summary': cov['summary'], 'verdict': cov['verdict'], 'failures': cov['failures'][:5]}))
    return 0 if cov['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
