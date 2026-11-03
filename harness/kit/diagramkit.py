#!/usr/bin/env python3
"""diagramkit — kit-native SVG diagrams from a declarative spec, for ANY artifact page (born 2026-10-19 with the ClusterDOS ARD/PRD).

Before this, every page drew its own boxes and arrows (clusterdos-archv1 svg_spec / svg_steps, the twins' hand SVG), and each
re-implemented the kit contract. diagramkit draws them ONCE, already satisfying every kit gate:
  * every box / step / bar is ONE <g class="as"> with its class pill (assetkit.svg_ctag) — G10;
  * every text that must fit goes through textkit (fit / fit_lines / wrap with a line budget) — a cut keeps its sentence as a
    <title> + ⓘ — G11 (and the AK16 lesson: wrap is always given its line budget, never sliced afterwards);
  * a SEQUENCE numbers its connectors in the spec's step order (connectorkit g.cx + g.nb), an un-numbered connector inside a
    sequence carries data-cxwhy, and a RELATIONS diagram is declared data-cxkind="relations" with its reason — G7;
  * every connector carries data-ct (its class) so the hover pill shows how the arrow is known.

SPEC (a dict; the page's model)
  {id, kind: 'sequence'|'relations', why_kind: str, lanes: [lane names, optional order],
   nodes: [{id, label, sub, lane, status?}], edges: [{from, to, label, step: int|None, why_not_step?}]}

USE
  import diagramkit as dk
  svg = dk.lanes(spec, cls_fn)                  # cls_fn(obj) → assetkit class tuple (classes, how, why, cites)
  svg = dk.steps(rows, cls_fn, states)          # rows: [{n, where, what, object, state, note}]; states: {state: (word, colour)}
  svg = dk.bars(items, cls_fn)                  # items: [{label, value, colour?, note?}] — horizontal bars, one asset each
  rows = dk.edge_rows(spec)                     # one dict per connector (n, from, to, label) for the page's legend table
  page: <style>{dk.CSS}</style> next to the kit CSS; no JS of its own (connectorkit's JS animates it)

Status words (node.status / step.state) are drawn as a chip; STATUS maps the closed ClusterDOS-status vocabulary to colours,
and a page may pass its own map.
"""
import html as _html
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import assetkit as ak  # noqa: E402
import textkit as tk  # noqa: E402

E = lambda s: _html.escape(str(s), quote=True)
CW = tk.CW
STATUS = {   # word, colour token (falls back to a literal)
    'SHIPPED-ON': ('ships, on', 'var(--ok,#1d7a4a)'), 'SHIPPED-OFF': ('ships, off', 'var(--warn,#a86400)'),
    'PARTIAL': ('partly', 'var(--warn,#a86400)'), 'NOT-SHIPPED': ('not shipped', 'var(--gap,#c0392b)'),
    'UNKNOWN': ('unknown', 'var(--mut,#667)'), 'PROPOSED': ('proposal', 'var(--l4,#2563a8)'),
    'RAN-PASS': ('lab: pass', 'var(--ok,#1d7a4a)'), 'RAN-FAIL': ('lab: fail', 'var(--gap,#c0392b)'),
    'NOT-RUN': ('not run', 'var(--mut,#667)'),
}
CSS = ('svg.dk text{font-family:var(--sans,system-ui,sans-serif)}svg.dk .dk-sub{fill:var(--mut,#667)}'
       'svg.dk .dk-lane{font-family:var(--mono,ui-monospace,monospace);letter-spacing:.06em}')


def _pill(xr, y, cl):
    """(svg, width) of the class pill, or ('', 0) when cls_fn returned None — a BARE diagram for a hand page, whose pills
    retrofit adds from the page's evidence file (box key = its label text)"""
    return ('', 0) if cl is None else ak.svg_ctag(xr, y, cl)


def _pw(cl):
    return 0 if cl is None else ak.svg_ctag_width(cl)


def text(x, y, s, size=12, anchor='start', weight='400', fill='currentColor', cls=''):
    inner, tc = tk.svg_inner(s)
    return (f'<text x="{x:.0f}" y="{y:.0f}" font-size="{size}" text-anchor="{anchor}" font-weight="{weight}" fill="{fill}"'
            f' class="{(cls + " " + tc).strip()}">{inner}</text>')


def textw(s, size, bold=False):
    return len(str(s)) * size * CW * (1.06 if bold else 1)


def cxn(conn, n, x, y, tip='', ct=''):
    """a numbered connector (connectorkit contract): the arrow and its badge in ONE g.cx; the badge's title says the step"""
    c = f' data-ct="{E(ct)}"' if ct else ''
    return (f'<g class="cx"{c}>{conn}<g class="nb"><title>{E(f"step {n} — {tip}" if tip else f"step {n}")}</title>'
            f'<circle cx="{x:.0f}" cy="{y:.0f}" r="8" fill="var(--panel,#fff)" stroke="currentColor" stroke-width="1.1"/>'
            + text(x, y + 3, str(n), 8 if len(str(n)) < 3 else 6.5, 'middle', '700') + '</g></g>')


def chip(x, y, word, col, size=9.2, anchor='start'):
    """a status chip (a decoration INSIDE an asset's g.as, never an asset of its own)"""
    w = textw(word, size, True) + 10
    x0 = x if anchor == 'start' else x - w
    return (f'<rect x="{x0:.0f}" y="{y - size - 1:.0f}" width="{w:.0f}" height="{size + 6:.0f}" rx="{(size + 6) / 2:.0f}" fill="{col}"'
            f' fill-opacity=".14" stroke="{col}" stroke-width=".9"/>' + text(x0 + w / 2, y + 1.5, word, size, 'middle', '700', col)), w


def _clip(cx, cy, w, h, dx, dy):
    """the point where a ray from a box centre leaves the box (w, h = box size incl. margin)"""
    if dx == 0 and dy == 0:
        return cx, cy
    tx = (w / 2) / abs(dx) if dx else 1e9
    ty = (h / 2) / abs(dy) if dy else 1e9
    t = min(tx, ty)
    return cx + dx * t, cy + dy * t


def layout(spec, maxc=4):
    """lanes → rows: each lane gets ceil(n / maxc) rows in lane order; nodes keep spec order inside their lane"""
    order = list(spec.get('lanes') or [])
    for n in spec['nodes']:
        if (n.get('lane') or '-') not in order:
            order.append(n.get('lane') or '-')
    rows, lane_rows, r = {}, [], 0
    cols = 1
    for ln in order:
        ns = [n for n in spec['nodes'] if (n.get('lane') or '-') == ln]
        if not ns:
            continue
        nr = (len(ns) + maxc - 1) // maxc
        for j, n in enumerate(ns):
            rows[n['id']] = (r + j // maxc, j % maxc, min(maxc, len(ns) - (j // maxc) * maxc))
        cols = max(cols, min(maxc, len(ns)))
        lane_rows.append((ln, r, r + nr - 1))
        r += nr
    return rows, lane_rows, cols, r


def lanes(spec, cls_fn, W=980, maxc=4, status=None):
    """the lane diagram for spec (see module doc). Every node is an asset; every connector is classed and, in a sequence,
    numbered by its declared step."""
    status = status or STATUS
    pos_rc, lane_rows, cols, nrows = layout(spec, maxc)
    lw = 118                                       # left band: lane names
    cw = (W - lw - 12) / cols
    bw, bh, rh, top = min(208, cw - 22), 64, 112, 18
    H = top + nrows * rh + 4
    aid = 'dk' + re.sub(r'[^a-z0-9]', '', str(spec['id']).lower())[:12]
    seq = spec.get('kind') == 'sequence'
    o = [f'<svg class="dk" viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg">'
         f'<defs><marker id="{aid}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
         f'<path d="M0,0 L10,5 L0,10 z" fill="currentColor"/></marker></defs>']
    for i, (ln, r0, r1) in enumerate(lane_rows):
        y0, y1 = top + r0 * rh - 10, top + r1 * rh + bh + 14
        o.append(f'<rect class="notag" x="4" y="{y0}" width="{W - 8}" height="{y1 - y0}" rx="8" fill="currentColor" fill-opacity="{.025 if i % 2 else .055}"'
                 f' stroke="currentColor" stroke-opacity=".18"/>')
        for j, l in enumerate(tk.fit_lines(str(ln).upper(), lw - 18, 9.5, True, 3)):
            o.append(text(14, y0 + 18 + j * 12, l, 9.5, weight='700', fill='var(--mut,#667)', cls='dk-lane'))
    pos = {}
    for n in spec['nodes']:
        r, c, k = pos_rc[n['id']]
        x = lw + (cols - k) * cw / 2 + c * cw + (cw - bw) / 2      # a short row is centred
        y = top + r * rh
        pos[n['id']] = (x, y)
        cl = cls_fn(n)
        st = n.get('status')
        word, col = status.get(st, (str(st).lower(), 'var(--mut,#667)')) if st else ('', '')
        dash = ' stroke-dasharray="5 3"' if (cl and 'PLAN' in cl[0]) or st == 'PROPOSED' else ''
        stroke = col if st in ('NOT-SHIPPED',) else 'var(--line,#c8d0cc)'
        lab = tk.fit_lines(n['label'], bw - 16 - _pw(cl), 11.4, True, 2)
        g = [f'<g class="as"><rect x="{x:.0f}" y="{y:.0f}" width="{bw:.0f}" height="{bh}" rx="7" fill="var(--panel2,#f3f5f4)" stroke="{stroke}" stroke-width="1.3"{dash}/>']
        g += [text(x + 8, y + 17 + j * 13.5, l, 11.4, weight='700') for j, l in enumerate(lab)]
        g.append(_pill(x + bw - 5, y + 12, cl)[0])
        budget = 3 - len(lab) - (1 if word else 0)
        if n.get('sub') and budget > 0:
            for j, l in enumerate(tk.wrap(n['sub'], int((bw - 14) / (9.8 * CW)), budget)):
                g.append(text(x + 8, y + 19 + 13.5 * len(lab) + j * 12.5, l, 9.8, cls='dk-sub', fill='var(--mut,#667)'))
        elif n.get('sub'):
            g.append(f'<title>{E(n["label"])} — {E(n["sub"])}</title>')
        if word:
            g.append(chip(x + 8, y + bh - 7, word, col, 8.6)[0])
        o.append(''.join(g) + '</g>')
    boxes = {k: (x, y) for k, (x, y) in pos.items()}

    def hits(x1, y1, x2, y2, skip):
        for k, (bx, by) in boxes.items():
            if k in skip:
                continue
            for t in [i / 30 for i in range(1, 30)]:
                px, py = x1 + (x2 - x1) * t, y1 + (y2 - y1) * t
                if bx - 4 <= px <= bx + bw + 4 and by - 4 <= py <= by + bh + 4:
                    return True
        return False
    row_of = {k: v[0] for k, v in pos_rc.items()}
    pair, seen, lane_slot = {}, {}, {}
    for e in spec.get('edges') or []:
        kk = tuple(sorted((e['from'], e['to'])))
        pair[kk] = pair.get(kk, 0) + 1
    for i, e in enumerate(spec.get('edges') or []):
        if e['from'] not in pos or e['to'] not in pos:
            continue
        (ax, ay), (bx, by) = pos[e['from']], pos[e['to']]
        acx, acy, bcx, bcy = ax + bw / 2, ay + bh / 2, bx + bw / 2, by + bh / 2
        kk = tuple(sorted((e['from'], e['to'])))
        seen[kk] = seen.get(kk, 0) + 1
        side = seen[kk] - (pair[kk] + 1) / 2
        cl = cls_fn(e)
        ct = '/'.join(c for c in cl[0] if c in ak.CLASSES) if cl else ''
        title = f'<title>{E(e.get("label") or "")}</title>'
        dashed = ' stroke-dasharray="5 4"' if (cl and 'PLAN' in cl[0]) or (seq and e.get('step') is None) else ''
        if e['from'] == e['to']:
            geo = f'<path fill="none" d="M{ax + bw - 40:.0f} {ay:.0f} C{ax + bw - 40:.0f} {ay - 26:.0f} {ax + bw - 10:.0f} {ay - 26:.0f} {ax + bw - 10:.0f} {ay - 2:.0f}"'
            mx, my, tag = ax + bw - 25, ay - 20, 'path'
        else:
            dx, dy = bcx - acx, bcy - acy
            L = max((dx * dx + dy * dy) ** .5, 1)
            off = side * 22
            px, py = -dy / L * off, dx / L * off
            x1, y1 = _clip(acx, acy, bw + 6, bh + 6, dx, dy)
            x2, y2 = _clip(bcx, bcy, bw + 12, bh + 12, -dx, -dy)
            x1, y1, x2, y2 = x1 + px, y1 + py, x2 + px, y2 + py
            if not hits(x1, y1, x2, y2, {e['from'], e['to']}):
                geo, tag = f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}"', 'line'
                mx, my = (x1 + x2) / 2, (y1 + y2) / 2
            else:                                   # orthogonal: out of the source's bottom/top, along the gap band, into the target
                ra, rb = row_of[e['from']], row_of[e['to']]
                n_ = lane_slot.get((min(ra, rb), max(ra, rb)), 0)
                lane_slot[(min(ra, rb), max(ra, rb))] = n_ + 1
                jig = (n_ % 5) * 6 - 12
                if rb >= ra:
                    ys, yt = ay + bh, by
                    gy = (top + (rb if rb > ra else ra + 1) * rh - (rh - bh) / 2) + jig
                    if rb == ra:
                        ys = yt = ay + bh
                else:
                    ys, yt = ay, by + bh
                    gy = top + ra * rh - (rh - bh) / 2 + jig
                sx, tx = acx + side * 18, bcx + side * 18
                pts = [(sx, ys), (sx, gy), (tx, gy), (tx, yt)]
                geo, tag = 'M' + ' L'.join(f'{p:.0f} {q:.0f}' for p, q in pts), 'path'
                geo = f'<path fill="none" d="{geo}"'
                mx, my = (pts[1][0] + pts[2][0]) / 2, gy
        line = f'{geo} stroke="currentColor" stroke-width="1.3"{dashed} marker-end="url(#{aid})"'
        if seq and e.get('step') is not None:
            o.append(cxn(f'{line}>{title}</{tag}>', e['step'], mx, my, tip=e.get('label') or '', ct=ct))
        elif seq:
            o.append(f'{line} data-ct="{E(ct)}" data-cxwhy="{E(e.get("why_not_step") or "not a step of this flow")}">{title}</{tag}>')
        else:
            o.append(f'{line} data-ct="{E(ct)}">{title}</{tag}>')
    o.append('</svg>')
    s = ''.join(o)
    if not seq:
        s = s.replace('<svg ', f'<svg data-cxkind="relations" data-cxwhy="{E(spec.get("why_kind") or "relations, not an execution order")}" ', 1)
    return s


def edge_rows(spec):
    """the connectors in reading order: numbered steps first (by step), then the relations, for a legend table"""
    es = list(spec.get('edges') or [])
    lab = {n['id']: n['label'] for n in spec['nodes']}
    es.sort(key=lambda e: (e.get('step') is None, e.get('step') or 0))
    return [dict(e, n=e.get('step') if e.get('step') is not None else '·', from_label=lab.get(e['from'], e['from']),
                 to_label=lab.get(e['to'], e['to'])) for e in es]


def steps(rows, cls_fn, states=None, W=980):
    """a stepper: one asset row per step in execution order — number, where it runs, what happens, the object, a state chip"""
    states = states or STATUS
    rh, top = 54, 6
    H = top + len(rows) * rh + 4
    o = [f'<svg class="dk" viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg">']
    for i, x in enumerate(rows):
        y = top + i * rh
        cl = cls_fn(x)
        word, col = states.get(x.get('state'), (str(x.get('state') or '').lower(), 'var(--mut,#667)'))
        cw_ = _pw(cl)
        tw_ = W - 208 - 190 - cw_
        what = tk.fit_lines(x['what'], tw_, 11.2, True, 2)       # 2026-10-19: the action wraps to 2 lines before it is cut
        g = [f'<g class="as"><rect x="4" y="{y}" width="{W - 8}" height="{rh - 7}" rx="7" fill="var(--panel2,#f3f5f4)" stroke="var(--line,#c8d0cc)"/>',
             f'<circle cx="26" cy="{y + 23}" r="12" fill="none" stroke="currentColor" stroke-width="1.3"/>',
             text(26, y + 27, x['n'], 10.5, 'middle', '700'),
             text(48, y + 20, tk.fit(x.get('where') or '', 150, 9.6, True), 9.6, weight='700', fill='var(--mut,#667)', cls='dk-lane')]
        g += [text(208, y + 18 + j * 14, l, 11.2, weight='700') for j, l in enumerate(what)]
        if x.get('object') and len(what) == 1:                    # the object line only when the action left room (line budget)
            g.append(text(208, y + 34, tk.fit(x['object'], tw_, 9.8), 9.8, fill='var(--mut,#667)', cls='dk-sub'))
        if word:
            g.append(chip(W - 18 - cw_ - 8, y + 25, word, col, 9.2, 'end')[0])
        g.append(_pill(W - 12, y + 21, cl)[0])
        g.append(f'<title>{E(x["n"])} · {E(x["what"])}{(" — " + E(x["note"])) if x.get("note") else ""}</title></g>')
        o.append(''.join(g))
    o.append('</svg>')
    return ''.join(o)


def bars(items, cls_fn, W=980, label_w=300, unit=''):
    """horizontal bars, one asset each (label, bar, value, pill); bar length ∝ value / max"""
    rh, top = 26, 6
    H = top + len(items) * rh + 4
    mx = max([float(i['value']) for i in items] + [1])
    o = [f'<svg class="dk" viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg">']
    for k, it in enumerate(items):
        y = top + k * rh
        cl = cls_fn(it)
        cw_ = _pw(cl)
        span = W - label_w - 70 - cw_
        bl = max(2, span * float(it['value']) / mx)
        col = it.get('colour') or 'var(--l4,#2563a8)'
        o.append(f'<g class="as">' + text(8, y + 15, tk.fit(it['label'], label_w - 14, 10.8, True), 10.8, weight='700')
                 + f'<rect x="{label_w}" y="{y + 4}" width="{bl:.0f}" height="{rh - 10}" rx="3" fill="{col}" fill-opacity=".75"/>'
                 + text(label_w + bl + 6, y + 15, f'{it["value"]}{unit}', 10.4, weight='700')
                 + _pill(W - 8, y + 11, cl)[0]
                 + (f'<title>{E(it["label"])} — {E(it["note"])}</title>' if it.get('note') else '') + '</g>')
    o.append('</svg>')
    return ''.join(o)
