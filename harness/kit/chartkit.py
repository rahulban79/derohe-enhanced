#!/usr/bin/env python3
"""chartkit — accessible inline-SVG charts for any artifact page, and the gate that every chart has a text alternative.

r33 (artifacts/dero-game-theory-rft.md §8.2, the game-theory page): a generator draws its record figures as charts
without an external library or image. Every chart is a <figure> holding
  * <svg class="chart" role="img" aria-labelledby="<title id> <desc id>" data-table="<table id>" data-n="<bars>">
    with a <title> (what is shown) and a <desc> that lists EVERY value in words (a screen reader reads the chart);
    axes with ticks, the unit on the value axis, a label on every category, the value at the end of every bar, and
    a native hover tooltip (<title>) on every bar;
  * a <details class="chart-data"> with the same figures as a <table id="<table id>"> (the table view; one row per
    bar) — the page's own cell tags (assetkit pills) go in the cells through `cell_tag`;
  * optional: a reference line (`marker`, e.g. an alarm threshold) and a second encoding per bar (`ticks`, e.g. a
    median drawn as a tick on the fee bar), each named in a legend and in the <desc>.
The plot is drawn inside one <g class="as"> so the page's evidence pill (`pill_svg`, assetkit.svg_ctag) tags it as
one asset (gate G10); a chart has no connector (gate G7 ignores it).

  import chartkit as chk
  chk.bar_chart(cid, title, desc, cats, vals, unit='atomic', fmt=chk.grouped, pill_svg='', cell_tag=None, cols=(..))
  chk.hbar_chart(cid, title, desc, cats, vals, unit='%', marker=(40, 'alarm 40 %'), ticks=[..], tick_name='..')
  chk.matrix_chart(cid, title, desc, rows, cols, vals, unit='hops', row_tag=None)   r33 src-arch: a heat grid (one
                                                  row per category, one column per series; the value in every cell,
                                                  the cell's shade relative to the largest; data-n = rows;
                                                  its styles are chk.MATRIX_CSS)
  chk.CHART_CSS                                   put in <style> (theme tokens: --fg --muted --line --surface
                                                  --series-1 --series-2 --alert, each with a literal fallback)
  chk.audit(html) -> {'charts', 'bad', 'ok'}      gate: every svg.chart has role=img, a non-empty <title> and
                                                  <desc>, aria-labelledby naming both, and a data-table whose
                                                  <table> exists with exactly data-n body rows
  python3 -I harness/kit/chartkit.py PAGE.html    the gate on a page: exit 0 ok · 3 a chart without its text
                                                  alternative (kitgate G13 runs the same check)
KAT harness/kat/test_gt_page_r33.py (GP4). Library + one read-only command; stdlib only.
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):
    print(__doc__)
    raise SystemExit(0)
import html as _html
import math, re, sys
from pathlib import Path

E = lambda s: _html.escape(str(s), quote=True)

CHART_CSS = r'''
figure.chart{margin:12px 0;background:var(--surface,#fff);border:1px solid var(--line,#d8dee5);border-radius:10px;padding:12px 14px 8px;min-width:0}
figure.chart figcaption{font:600 13px/1.35 var(--body,system-ui,sans-serif);margin:0 0 6px;color:var(--fg,#18212b)}
figure.chart figcaption small{display:block;font:400 11.5px/1.4 var(--mono,ui-monospace,monospace);color:var(--muted,#5a6876);margin-top:2px}
svg.chart{width:100%;height:auto;display:block;color:var(--fg,#18212b);overflow:visible}
svg.chart .ax{stroke:var(--line,#d8dee5);stroke-width:1}
svg.chart .grid{stroke:var(--line,#d8dee5);stroke-width:1;stroke-dasharray:2 3;opacity:.8}
svg.chart .tk{font:400 10.5px var(--mono,ui-monospace,monospace);fill:var(--muted,#5a6876)}
svg.chart .cat{font:500 11px var(--body,system-ui,sans-serif);fill:var(--fg,#18212b)}
svg.chart .val{font:600 11px var(--mono,ui-monospace,monospace);fill:var(--fg,#18212b)}
svg.chart .unit{font:600 10px var(--mono,ui-monospace,monospace);fill:var(--muted,#5a6876);letter-spacing:.04em}
svg.chart .bar path{fill:var(--series-1,#2a78d6);transition:opacity .12s}
svg.chart .bar:hover path{opacity:.78}
svg.chart .bar.dim path{fill:var(--series-2,#8a96a3)}
svg.chart .tick2{stroke:var(--fg,#18212b);stroke-width:2.5;stroke-linecap:round}
svg.chart .mark{stroke:var(--alert,#b3412f);stroke-width:1.6;stroke-dasharray:5 4}
svg.chart .markl{font:600 10.5px var(--mono,ui-monospace,monospace);fill:var(--alert,#b3412f)}
.chart-legend{display:flex;flex-wrap:wrap;gap:4px 14px;font:400 11.5px var(--mono,ui-monospace,monospace);color:var(--muted,#5a6876);margin:4px 0 2px}
.chart-legend i{display:inline-block;width:12px;height:8px;border-radius:2px;margin-right:5px;vertical-align:0;background:var(--series-1,#2a78d6)}
.chart-legend i.t{width:3px;height:11px;background:var(--fg,#18212b)}.chart-legend i.m{height:0;border-top:2px dashed var(--alert,#b3412f);background:none}
details.chart-data{margin-top:4px}details.chart-data summary{cursor:pointer;font:600 11.5px var(--mono,ui-monospace,monospace);color:var(--muted,#5a6876)}
details.chart-data .tablebox{margin-top:6px}
@media (prefers-reduced-motion:reduce){svg.chart .bar path{transition:none}}
'''

# r33: the heat-grid cells of matrix_chart (kept out of CHART_CSS so a page without a matrix is byte-identical)
MATRIX_CSS = r'''
svg.chart .cell{fill:var(--series-1,#2a78d6)}svg.chart .cell0{fill:none;stroke:var(--line,#d8dee5);stroke-dasharray:2 2}
svg.chart .cellv{font:600 11px var(--mono,ui-monospace,monospace);fill:var(--fg,#18212b)}
svg.chart .colh{font:600 10.5px var(--mono,ui-monospace,monospace);fill:var(--muted,#5a6876)}
'''


def grouped(v):
    """1234567 -> '1,234,567'; a float keeps one decimal. Pure."""
    if isinstance(v, float) and not v.is_integer():
        return f'{v:,.1f}'
    return f'{int(v):,}'


def nice_ticks(vmax, n=4):
    """[0, step, .., top] with a 1/2/2.5/5 x 10^k step and top >= vmax. Pure."""
    vmax = float(vmax or 0)
    if vmax <= 0:
        return [0, 1]
    raw = vmax / n
    k = 10 ** math.floor(math.log10(raw))
    step = next(m * k for m in (1, 2, 2.5, 5, 10) if m * k >= raw)
    top = math.ceil(vmax / step - 1e-9) * step
    out, t = [], 0.0
    while t <= top + 1e-9:
        out.append(int(t) if float(t).is_integer() else round(t, 6))
        t += step
    return out


def _table(cid, cats, vals, cols, fmt, cell_tag, ticks=None):
    head = ''.join(f'<th>{E(c)}</th>' for c in cols)
    rows = []
    for i, (c, v) in enumerate(zip(cats, vals)):
        tg = cell_tag(i) if cell_tag else ''
        cells = [f'<td>{E(c)}{" " + tg if tg else ""}</td>', f'<td>{E(fmt(v))}{" " + tg if tg else ""}</td>']
        if ticks is not None:
            cells.append(f'<td>{E(fmt(ticks[i]))}{" " + tg if tg else ""}</td>')
        rows.append('<tr>' + ''.join(cells) + '</tr>')
    return (f'<details class="chart-data"><summary>Data table ({len(cats)} rows)</summary><div class="tablebox">'
            f'<table id="{cid}-tbl" data-chart="{cid}"><thead><tr>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table></div></details>')


def _desc(desc, cats, vals, unit, fmt, ticks=None, tick_name='', marker=None):
    parts = [f'{c}: {fmt(v)}{(" " + unit) if unit else ""}' + (f' ({tick_name} {fmt(ticks[i])})' if ticks is not None else '')
             for i, (c, v) in enumerate(zip(cats, vals))]
    m = f' Reference line: {marker[1]}.' if marker else ''
    return f'{desc} Values: ' + '; '.join(parts) + '.' + m


def _legend(series, tick_name, marker):
    if not tick_name and not marker:
        return ''
    out = [f'<span><i></i>{E(series)}</span>']
    if tick_name:
        out.append(f'<span><i class="t"></i>{E(tick_name)}</span>')
    if marker:
        out.append(f'<span><i class="m"></i>{E(marker[1])}</span>')
    return '<div class="chart-legend">' + ''.join(out) + '</div>'


def bar_chart(cid, title, desc, cats, vals, unit='', fmt=grouped, pill_svg='', cell_tag=None, cols=None, note='',
              W=340, H=210, series=None):
    """a vertical bar chart (one series, few categories: small multiples). Returns the <figure> HTML."""
    cols = cols or ('category', unit or 'value')
    L, R, T, B = 54, 12, 26, 34
    pw, ph = W - L - R, H - T - B
    tk = nice_ticks(max(vals) if vals else 0)
    top = tk[-1] or 1
    n = max(1, len(cats))
    slot = pw / n
    bw = min(46, slot * 0.56)
    o = [f'<svg class="chart" viewBox="0 0 {W} {H}" style="max-width:{W}px" role="img" aria-labelledby="{cid}-t {cid}-d" data-table="{cid}-tbl" data-n="{len(cats)}">'
         f'<title id="{cid}-t">{E(title)}</title><desc id="{cid}-d">{E(_desc(desc, cats, vals, unit, fmt))}</desc><g class="as">']
    if pill_svg:
        o.append(pill_svg)
    o.append(f'<text class="unit" x="{L - 6}" y="{T - 12}" text-anchor="end">{E(unit)}</text>')
    for t in tk:
        y = T + ph - ph * t / top
        o.append(f'<line class="grid" x1="{L}" x2="{L + pw}" y1="{y:.1f}" y2="{y:.1f}"/>'
                 f'<text class="tk" x="{L - 6}" y="{y + 3.5:.1f}" text-anchor="end">{E(fmt(t))}</text>')
    o.append(f'<line class="ax" x1="{L}" x2="{L + pw}" y1="{T + ph}" y2="{T + ph}"/>')
    for i, (c, v) in enumerate(zip(cats, vals)):
        x = L + slot * i + (slot - bw) / 2
        h = ph * v / top
        y = T + ph - h
        r = min(4, h / 2, bw / 2)
        path = (f'M{x:.1f},{T + ph} L{x:.1f},{y + r:.1f} Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f} L{x + bw - r:.1f},{y:.1f} '
                f'Q{x + bw:.1f},{y:.1f} {x + bw:.1f},{y + r:.1f} L{x + bw:.1f},{T + ph} Z') if h > 0 else ''
        o.append(f'<g class="bar"><title>{E(c)}: {E(fmt(v))} {E(unit)}</title>'
                 + (f'<path d="{path}"/>' if path else '')
                 + f'<text class="val" x="{x + bw / 2:.1f}" y="{y - 5:.1f}" text-anchor="middle">{E(fmt(v))}</text>'
                 f'<text class="cat" x="{x + bw / 2:.1f}" y="{T + ph + 16}" text-anchor="middle">{E(c)}</text></g>')
    o.append('</g></svg>')
    cap = f'<figcaption>{E(title)}' + (f'<small>{note}</small>' if note else '') + '</figcaption>'
    return f'<figure class="chart" id="{cid}">{cap}{"".join(o)}{_table(cid, cats, vals, cols, fmt, cell_tag)}</figure>'


def hbar_chart(cid, title, desc, cats, vals, unit='', fmt=grouped, pill_svg='', cell_tag=None, cols=None, note='',
               W=720, row=24, label_w=190, marker=None, ticks=None, tick_name='', series='value', dim=None, vmax=None):
    """a horizontal bar chart (many or long categories). marker = (value, label): a dashed reference line;
    ticks = one second value per bar drawn as a tick on its row (named tick_name in the legend, the desc and the table);
    dim = indices drawn in the secondary colour. Returns the <figure> HTML."""
    cols = cols or ('category', unit or 'value') + ((tick_name,) if ticks is not None else ())
    L, R, T = label_w, 64, 24
    B = 26
    pw = W - L - R
    H = T + row * len(cats) + B
    hi = max([*vals, *(ticks or []), *([marker[0]] if marker else []), *([vmax] if vmax else [])] or [0])
    tk = nice_ticks(hi)
    top = tk[-1] or 1
    o = [f'<svg class="chart" viewBox="0 0 {W} {H}" style="max-width:{W}px" role="img" aria-labelledby="{cid}-t {cid}-d" data-table="{cid}-tbl" data-n="{len(cats)}">'
         f'<title id="{cid}-t">{E(title)}</title><desc id="{cid}-d">{E(_desc(desc, cats, vals, unit, fmt, ticks, tick_name, marker))}</desc><g class="as">']
    if pill_svg:
        o.append(pill_svg)
    for t in tk:
        x = L + pw * t / top
        o.append(f'<line class="grid" x1="{x:.1f}" x2="{x:.1f}" y1="{T - 4}" y2="{T + row * len(cats)}"/>'
                 f'<text class="tk" x="{x:.1f}" y="{T + row * len(cats) + 15}" text-anchor="middle">{E(fmt(t))}</text>')
    o.append(f'<text class="unit" x="{L + pw}" y="{T - 10}" text-anchor="end">{E(unit)}</text>')
    o.append(f'<line class="ax" x1="{L}" x2="{L}" y1="{T - 4}" y2="{T + row * len(cats)}"/>')
    bh = row * 0.62
    for i, (c, v) in enumerate(zip(cats, vals)):
        y = T + row * i + (row - bh) / 2
        w = pw * v / top
        r = min(4, w / 2, bh / 2)
        path = (f'M{L},{y:.1f} L{L + w - r:.1f},{y:.1f} Q{L + w:.1f},{y:.1f} {L + w:.1f},{y + r:.1f} L{L + w:.1f},{y + bh - r:.1f} '
                f'Q{L + w:.1f},{y + bh:.1f} {L + w - r:.1f},{y + bh:.1f} L{L},{y + bh:.1f} Z') if w > 0 else ''
        tip = f'{c}: {fmt(v)} {unit}' + (f' · {tick_name} {fmt(ticks[i])}' if ticks is not None else '')
        cls = 'bar dim' if dim and i in dim else 'bar'
        o.append(f'<g class="{cls}"><title>{E(tip)}</title>' + (f'<path d="{path}"/>' if path else '')
                 + f'<text class="cat" x="{L - 8}" y="{y + bh / 2 + 4:.1f}" text-anchor="end">{E(c)}</text>'
                 f'<text class="val" x="{L + w + 6:.1f}" y="{y + bh / 2 + 4:.1f}">{E(fmt(v))}</text>')
        if ticks is not None:
            tx = L + pw * ticks[i] / top
            o.append(f'<line class="tick2" x1="{tx:.1f}" x2="{tx:.1f}" y1="{y - 3:.1f}" y2="{y + bh + 3:.1f}"/>')
        o.append('</g>')
    if marker:
        mx = L + pw * marker[0] / top
        o.append(f'<line class="mark" x1="{mx:.1f}" x2="{mx:.1f}" y1="{T - 8}" y2="{T + row * len(cats)}"/>'
                 f'<text class="markl" x="{mx - 4:.1f}" y="{T - 11}" text-anchor="end">{E(marker[1])}</text>')
    o.append('</g></svg>')
    cap = f'<figcaption>{E(title)}' + (f'<small>{note}</small>' if note else '') + '</figcaption>'
    return (f'<figure class="chart" id="{cid}">{cap}{_legend(series, tick_name, marker)}{"".join(o)}'
            f'{_table(cid, cats, vals, cols, fmt, cell_tag, ticks)}</figure>')


def matrix_chart(cid, title, desc, rows, cols, vals, unit='', fmt=grouped, pill_svg='', row_tag=None, note='',
                 W=None, label_w=200, cell_w=64, row_h=26, col_h=34, zero=''):
    """r33 (src-arch page): a heat grid — one row per category, one column per series, vals[i][j] the value of row i in
    column j. Every cell prints its value; its shade is relative to the largest value (a zero cell is an outline and
    prints `zero`). The <desc> names every non-zero cell; the data table has one row per category (data-n = rows),
    a column per series; row_tag(i) tags the category cell. Returns the <figure> HTML."""
    n, m = len(rows), len(cols)
    W = W or label_w + cell_w * m + 12
    cw = (W - label_w - 12) / max(1, m)
    H = col_h + row_h * n + 8
    hi = max([v for r in vals for v in r] or [0]) or 1
    parts = []
    for i, r in enumerate(rows):
        nz = [f'{cols[j]} {fmt(v)}' for j, v in enumerate(vals[i]) if v]
        parts.append(f'{r}: ' + (', '.join(nz) if nz else 'none'))
    d = f'{desc} Values{(" (" + unit + ")") if unit else ""}: ' + '; '.join(parts) + '.'
    o = [f'<svg class="chart" viewBox="0 0 {W:.0f} {H}" style="max-width:{W:.0f}px" role="img" aria-labelledby="{cid}-t {cid}-d" '
         f'data-table="{cid}-tbl" data-n="{n}"><title id="{cid}-t">{E(title)}</title><desc id="{cid}-d">{E(d)}</desc><g class="as">']
    if pill_svg:
        o.append(pill_svg)
    for j, c in enumerate(cols):
        x = label_w + cw * j + cw / 2
        o.append(f'<text class="colh" x="{x - 4:.1f}" y="{col_h - 8}" text-anchor="start" transform="rotate(-38 {x - 4:.1f} {col_h - 8})">{E(c)}</text>')
    for i, r in enumerate(rows):
        y = col_h + row_h * i
        o.append(f'<text class="cat" x="{label_w - 8}" y="{y + row_h / 2 + 4:.1f}" text-anchor="end">{E(r)}</text>')
        for j, v in enumerate(vals[i]):
            x = label_w + cw * j
            tip = f'{r} · {cols[j]}: {fmt(v)}{(" " + unit) if unit else ""}'
            if v:
                op = 0.14 + 0.5 * v / hi
                o.append(f'<g class="bar"><title>{E(tip)}</title><rect class="cell" x="{x + 2:.1f}" y="{y + 2}" width="{cw - 4:.1f}" '
                         f'height="{row_h - 4}" rx="4" fill-opacity="{op:.2f}"/><text class="cellv" x="{x + cw / 2:.1f}" '
                         f'y="{y + row_h / 2 + 4:.1f}" text-anchor="middle">{E(fmt(v))}</text></g>')
            else:
                o.append(f'<g class="bar"><title>{E(tip)}</title><rect class="cell0" x="{x + 2:.1f}" y="{y + 2}" width="{cw - 4:.1f}" '
                         f'height="{row_h - 4}" rx="4"/>' + (f'<text class="tk" x="{x + cw / 2:.1f}" y="{y + row_h / 2 + 4:.1f}" '
                                                              f'text-anchor="middle">{E(zero)}</text>' if zero else '') + '</g>')
    o.append('</g></svg>')
    head = '<th>category</th>' + ''.join(f'<th>{E(c)}</th>' for c in cols)
    body = []
    for i, r in enumerate(rows):
        tg = row_tag(i) if row_tag else ''
        body.append(f'<tr><td>{E(r)}{" " + tg if tg else ""}</td>'
                    + ''.join(f'<td>{E(fmt(v))}{" " + tg if tg else ""}</td>' for v in vals[i]) + '</tr>')
    tbl = (f'<details class="chart-data"><summary>Data table ({n} rows)</summary><div class="tablebox">'
           f'<table id="{cid}-tbl" data-chart="{cid}"><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table></div></details>')
    cap = f'<figcaption>{E(title)}' + (f'<small>{note}</small>' if note else '') + '</figcaption>'
    return f'<figure class="chart" id="{cid}">{cap}{"".join(o)}{tbl}</figure>'


SVG_RX = re.compile(r'<svg\b([^>]*\bclass="chart"[^>]*)>(.*?)</svg>', re.S)


def audit(h):
    """{'charts': n, 'bad': [(chart, why)], 'ok'} — every chart carries its text alternative. Pure."""
    bad, n = [], 0
    for attrs, body in SVG_RX.findall(h or ''):
        n += 1
        a = dict(re.findall(r'([\w:-]+)="([^"]*)"', attrs))
        name = a.get('data-table', f'chart {n}')
        t = re.search(r'<title id="([^"]+)">([^<]*)</title>', body)
        d = re.search(r'<desc id="([^"]+)">([^<]*)</desc>', body)
        if a.get('role') != 'img':
            bad.append((name, 'no role="img"'))
        if not t or not t.group(2).strip():
            bad.append((name, 'no <title>'))
        if not d or not d.group(2).strip():
            bad.append((name, 'no <desc>'))
        lab = a.get('aria-labelledby', '').split()
        if not t or not d or t.group(1) not in lab or d.group(1) not in lab:
            bad.append((name, 'aria-labelledby does not name the title and the desc'))
        tid = a.get('data-table')
        m = re.search(r'<table id="' + re.escape(tid or '\x00') + r'"[^>]*>(.*?)</table>', h, re.S) if tid else None
        if not m:
            bad.append((name, 'no data table'))
            continue
        tb = re.search(r'<tbody>(.*?)</tbody>', m.group(1), re.S)
        rows = len(re.findall(r'<tr\b', tb.group(1))) if tb else 0
        if str(rows) != a.get('data-n'):
            bad.append((name, f'data table has {rows} rows, the chart {a.get("data-n")} bars'))
    return {'charts': n, 'bad': bad, 'ok': not bad}


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    r = audit(Path(sys.argv[1]).read_text(errors='replace'))
    print(f"chartkit: {r['charts']} chart(s), {len(r['bad'])} without a full text alternative" + (f": {r['bad'][:5]}" if r['bad'] else ''))
    raise SystemExit(0 if r['ok'] else 3)
