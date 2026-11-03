"""consensuskit (r24): the 'Consensus observatory — chain' block of dero-src-arch.html, drawn from model rows of
section 'consensus' (miners/mine_consensus.py <- intel/consensus_intel.py).

render(by, A, H, h) appends the section; `h` carries the page helpers (E, md, proof, table, ak, cls_of, kpis, note,
fig, chip, dk, tk) so this module holds no page state. Every cell is a value a row carries and every row cites the
capture line it was read from (and, for a detector, log kind or proposal, the tree line of its rule, printer or gap).
Grades: OBSERVED = a consensus rule was violated (rule line cited), ANOMALY = statistically unusual (test and
threshold stated), NORMAL, NO-DATA. Participants are salted pseudonyms; this node is 'this-node'.
"""
import json

GRADE_COL = {'OBSERVED': 'var(--gap)', 'ANOMALY': 'var(--warn)', 'NORMAL': 'var(--ok)', 'NO-DATA': 'var(--mut)'}
TILES = ['window_blocks', 'block_time_mean_s', 'participants', 'nakamoto_regular', 'nakamoto_final', 'top1_final_share',
         'difficulty_rule_mismatches', 'finality_reorgs']


def _spark(row, idx, title, unit, h, fmt):
    """One series, one axis: a 2 px line over per-100-block bins, a dot per bin with its value as the hover title."""
    E, dk, tk, fig, ak, cls_of = h['E'], h['dk'], h['tk'], h['fig'], h['ak'], h['cls_of']
    pts = [(b[0], b[idx]) for b in row['bins'] if b[idx] is not None]
    if len(pts) < 2:
        return ''
    W, Hh, L, R, T, B = 560, 150, 58, 14, 26, 26
    lo, hi = min(v for _, v in pts), max(v for _, v in pts)
    if hi == lo:
        hi = lo + 1
    X = lambda i: L + (W - L - R) * i / (len(pts) - 1)
    Y = lambda v: T + (Hh - T - B) * (1 - (v - lo) / (hi - lo))
    pill, pw = ak.svg_ctag(W - 8, 12, cls_of(row))      # the class pill: the series is HARNESS evidence (assetkit audit)
    o = [f'<svg class="dk" viewBox="0 0 {W} {Hh}" xmlns="http://www.w3.org/2000/svg"><g class="as">',
         dk.text(8, 16, tk.fit(title, W - pw - 24, 11.5, True), 11.5, weight='700'), pill]
    for v in (lo, (lo + hi) / 2, hi):
        o.append(f'<line x1="{L}" x2="{W - R}" y1="{Y(v):.1f}" y2="{Y(v):.1f}" stroke="var(--rule)"/>'
                 + dk.text(L - 6, Y(v) + 3, tk.fit(fmt(v), L - 10, 9), 9, 'end', fill='var(--mut)'))
    o.append(dk.text(L, Hh - 8, tk.fit(f'height {pts[0][0]:,}', 200, 9), 9, fill='var(--mut)'))
    o.append(dk.text(W - R, Hh - 8, tk.fit(f'{pts[-1][0]:,}', 120, 9), 9, 'end', fill='var(--mut)'))
    o.append(f'<polyline points="{" ".join(f"{X(i):.1f},{Y(v):.1f}" for i, (_, v) in enumerate(pts))}" fill="none" stroke="var(--accent)" stroke-width="2"/>')
    for i, (hgt, v) in enumerate(pts):
        o.append(f'<g><title>{E(f"blocks from height {hgt:,}: {fmt(v)} {unit}")}</title><circle cx="{X(i):.1f}" cy="{Y(v):.1f}" r="7" fill="transparent"/>'
                 f'<circle cx="{X(i):.1f}" cy="{Y(v):.1f}" r="2.4" fill="var(--accent)"/></g>')
    o.append(f'<title>{E(title)}</title></g></svg>')
    return fig(''.join(o), f'{title}. One point per 100 blocks; hover a point for its value.', title)


def _ev_short(d, E):
    out = []
    for e in (d.get('det_evidence') or [])[:3]:
        if isinstance(e, dict):
            s = ', '.join(f'{k} {v}' for k, v in e.items() if not isinstance(v, (dict, list)))[:150]
            out.append(E(s))
    return '<br>'.join(out) or '—'


def render(by, A, H, h):
    rows = by.get('chainobs') or []
    if not rows:
        return
    E, md, proof, table, ak, cls_of, kpis, note, chip = (h['E'], h['md'], h['proof'], h['table'], h['ak'], h['cls_of'], h['kpis'],
                                                         h['note'], h['chip'])
    K = {r['key']: r for r in rows if r['kind'] == 'kpi'}
    summ = next((r for r in rows if r['kind'] == 'summary'), {})
    win = summ.get('window') or {}
    r0 = rows[0]
    A(H('chainobs', 'Consensus observatory — chain',
        'Who makes this chain, and whether they make it by the rules. `harness/intel/consensus_intel.py` reads the last '
        f"{win.get('window_blocks', '?')} blocks (topoheight {win.get('window_topo_first', '?')} to {win.get('window_topo_last', '?')}, "
        f"{win.get('window_hours', '?')} h) from the running node over read-only JSON-RPC, plus the daemon's own log, and checks them "
        'against the consensus rules read from the lines of this tree that declare them. Miners and integrators appear only as salted '
        'pseudonyms; this node is `this-node`. A detector is **OBSERVED** only when a rule line is violated (the rule is cited), '
        '**ANOMALY** when a stated statistical test crosses its threshold, otherwise **NORMAL** or **NO-DATA**. '
        f"Capture {E(r0.get('captured'))}, binary {E(r0.get('version'))} ({E(r0.get('binary_round'))}). Gate **G26** re-checks it."))
    t = [(str(K[x]['value']), K[x]['title']) for x in TILES if x in K]
    g = summ.get('grades') or {}
    t += [(str(g.get('OBSERVED', 0)), 'detectors OBSERVED'), (str(g.get('ANOMALY', 0)), 'detectors ANOMALY')]
    A(kpis(t))
    bins = next((r for r in rows if r['kind'] == 'bins'), None)
    if bins:
        A('<div class="cards">')
        A(_spark(bins, 1, 'Mean block time per 100 blocks (target 18 s)', 's', h, lambda v: f'{v:.1f}'))
        A(_spark(bins, 2, 'Mean difficulty per 100 blocks', '', h, lambda v: f'{v / 1e6:.2f}M'))
        A('</div>')
        A(f'<p class="mut">Series source: {proof(bins, 1)}</p>')
    dets = [r for r in rows if r['kind'] == 'detector']
    if dets:
        A('<h3>Detectors: rule violations, anomalies, normal</h3>')
        order = {'OBSERVED': 0, 'ANOMALY': 1, 'NO-DATA': 2, 'NORMAL': 3}
        dets = sorted(dets, key=lambda r: (order.get(r['grade'], 4), r['det']))
        tr = [[f"<span class=\"mono\">{E(r['det'])}</span><br><b>{E(r['title'])}</b>", chip(r['grade'].lower(), GRADE_COL.get(r['grade'], 'var(--mut)')),
               E(str(r['value'])), md(r['test'][:260]), _ev_short(r, E) + (f"<br><span class=\"mut\">{E(r['note'][:220])}</span>" if r.get('note') else ''),
               proof(r, 2)] for r in dets]
        A(table(['Detector', 'Grade', 'Value', 'Rule or test', 'Evidence', 'proof'],
                ak.tag_rows(tr, dets, ['', '', '', '', '', None], cls_of), 't-cons-det', filt=True))
        A(note('An **ANOMALY** is a statistical signal, never an accusation: each states the test, the threshold (family-wise '
               'alpha 0.001 over the participants tested) and the reading that crossed it. The finals-versus-regular test flags '
               'integrators that assemble blocks for miners they serve (the final pays the template builder\'s integrator), which is '
               'pooling by design, not a broken rule.', 'warn'))
    parts = [r for r in rows if r['kind'] == 'participant']
    if parts:
        A('<h3>Participants (salted pseudonyms)</h3>')
        tr = [[f"<span class=\"mono\">{E(r['title'])}</span>", E(r.get('role')), E(r['regular']), E(r['regular_share']), E(r['final']),
               E(r['final_share']) + (f" <span class=\"mut\">[{E(r['final_ci95'][0])}, {E(r['final_ci95'][1])}]</span>" if r.get('final_ci95') else ''),
               E(r['longest_final_run']), E('—' if r.get('final_vs_regular_p') is None else r['final_vs_regular_p']), proof(r, 1)] for r in parts]
        A(table(['Participant', 'Role', 'Regular miniblocks', 'Share', 'Finals', 'Share [95 % CI]', 'Longest final run', 'p (finals vs regular)', 'proof'],
                ak.tag_rows(tr, parts, ['', '', '', '', '', '', '', '', None], cls_of), 't-cons-part', filt=True))
    kp = [r for r in rows if r['kind'] == 'kpi']
    if kp:
        A('<h3>Consensus state and statistics</h3>')
        tr = [[f"<b>{E(r['title'])}</b>", f"<span class=\"mono\">{E(json.dumps(r['value']) if isinstance(r['value'], dict) else r['value'])}</span>",
               md(r.get('how') or ''), proof(r, 1)] for r in kp]
        A(table(['Reading', 'Value', 'What it means', 'proof'], ak.tag_rows(tr, kp, ['', '', '', None], cls_of), 't-cons-kpi', filt=True))
    lk = [r for r in rows if r['kind'] == 'logkind']
    if lk:
        A('<h3>Consensus log census (derod.log, by kind)</h3>')
        lk = sorted(lk, key=lambda r: (-r['lines'], r['title']))
        tr = [[f"<span class=\"mono\">{E(r['title'][:90])}</span>", E(r['lines']), E((r.get('first') or ['', '', '—'])[2]),
               E((r.get('last') or ['', '', '—'])[2]),
               E(f"{(r.get('printed_by') or {}).get('file')}:{(r.get('printed_by') or {}).get('line')}" if r.get('printed_by') else 'ERROR level, other packages'),
               proof(r, 2)] for r in lk]
        A(table(['Kind', 'Lines', 'First', 'Last', 'Printed by', 'proof'], ak.tag_rows(tr, lk, ['', '', '', '', '', None], cls_of), 't-cons-log', filt=True))
    runs = [r for r in rows if r['kind'] == 'run']
    if runs:
        A('<h3>Rolling series (one line per observatory run)</h3>')
        tr = [[f"<span class=\"mono\">{E(r['title'])}</span>", E(r['run'].get('window_height_last')), E(r['run'].get('block_time_mean_s')),
               E(r['run'].get('participants')), E(r['run'].get('nakamoto_regular')), E(r['run'].get('top1_final_share')),
               E(r['run'].get('side_block_lines_window')), E(', '.join(f'{k} {v}' for k, v in (r['run'].get('grades') or {}).items() if v)), proof(r, 1)]
              for r in runs]
        A(table(['Run', 'Tip height', 'Mean block s', 'Participants', 'Nakamoto (regular)', 'Top-1 finals', 'Side blocks', 'Grades', 'proof'],
                ak.tag_rows(tr, runs, ['', '', '', '', '', '', '', '', None], cls_of), 't-cons-runs'))
    props = [r for r in rows if r['kind'] == 'proposal']
    if props:
        A('<h3>Node-side gaps found by the observatory (R25 backlog, CO24-*)</h3>')
        tr = [[f"<span class=\"mono\">{E(r['pid'])}</span>", E(r['severity']), f"<b>{E(r['title'])}</b><br>{md(r['why'][:260])}", proof(r, 3)] for r in props]
        A(table(['Id', 'Severity', 'Gap and why it matters', 'proof'], ak.tag_rows(tr, props, ['', '', '', None], cls_of), 't-cons-prop'))
    A('</section>')
