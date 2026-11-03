#!/usr/bin/env python3
"""textkit — no silently cut sentences on any artifact page.

THE RULE: a text that has to be shortened to fit a drawing or a card ALWAYS
  * keeps its full sentence as a mouse-over tooltip (SVG <title> child / HTML title attribute), and
  * shows a visible ⓘ marker right after the "…", so the reader knows there is more to see (cursor: help).
A "…" without both is a defect: audit() fails on it. A lone "…" glyph (a legend symbol, not a cut sentence) needs only
the title that says what it means: tk.glyph('…', meaning) → <title>meaning</title>…

USE (a generator)
  import textkit as tk
  s = tk.fit(text, max_px, font_px, bold)    # → plain str when it fits, tk.Clipped(short, full) when cut
  s = tk.clip(text, n_chars)                  # same, by character count
  lines = tk.wrap(text, n_chars, max_lines=2) # last line is Clipped when the text did not fit
  tk.svg_inner(s)  → (inner markup for <text>, extra class)   # <title>full</title>short<tspan class="tt-i">ⓘ</tspan>
  tk.html(s)       → '<span class="tt" title="full">short<span class="tt-i">ⓘ</span></span>' (or escaped s)
  browser-drawn: akClipSvg(s, n) / akClipHtml(s, n) from tk.TT_JS
  page: <style>{tk.TT_CSS}</style> · <script>{tk.TT_JS}</script> (before the page's own JS)
  gate: tk.audit(html) → {'ok', 'cut_without_tooltip', 'examples', 'cut_with_tooltip'}

Width model: monospace advance = CW × font-size (× 1.06 bold); a cut text reserves room for "…" + the marker.
"""
import html as _html
import re, sys, json
from html.parser import HTMLParser
from pathlib import Path

CW = 0.61
MARK = 'ⓘ'
E = lambda s: _html.escape(str(s), quote=True)


class Clipped(str):
    """a shortened text that remembers its full sentence"""
    def __new__(cls, short, full):
        o = str.__new__(cls, short)
        o.full = full
        return o


def _norm(s):
    return re.sub(r'\s+', ' ', str(s if s is not None else '')).strip()


def _full(s):
    return s.full if isinstance(s, Clipped) else _norm(s)


def clip(s, n):
    full, t = _full(s), _norm(s)
    if len(t) <= n:
        return s if isinstance(s, Clipped) else t
    return Clipped(t.rstrip('…')[:max(1, n - 2)].rstrip() + '…', full)


def fit(s, maxw, size, bold=False):
    """clip s so its estimated rendered width (plus "…" and the marker when cut) ≤ maxw px"""
    full, t = _full(s), _norm(s)
    per = size * CW * (1.06 if bold else 1)
    n = max(1, int(maxw // per))
    if len(t) <= n:
        return s if isinstance(s, Clipped) else t   # a line already cut keeps its sentence through a second fit
    return Clipped(t.rstrip('…')[:max(1, n - 2)].rstrip() + '…', full)


def wrap(t, n, max_lines=2):
    """word-wrap to lines of ≤ n chars; when the text needs more lines, the last kept line is Clipped(full=t)"""
    t = _norm(t)
    words, out, cur = t.split(), [], ''
    for w in words:
        if cur and len(cur) + len(w) + 1 > n:
            out.append(cur)
            cur = w
        else:
            cur = (cur + ' ' + w).strip()
    if cur:
        out.append(cur)
    out = [x if len(x) <= n else x[:n] for x in out]
    if len(out) > max_lines:
        out = out[:max_lines]
        out[-1] = Clipped(out[-1][:max(1, n - 2)].rstrip() + '…', t)
    elif out and len(' '.join(out)) < len(t):
        out[-1] = Clipped(out[-1][:max(1, n - 2)].rstrip() + '…', t)
    return out


def fit_lines(s, maxw, size, bold=False, max_lines=2):
    """2026-10-19: a title that does not fit maxw wraps onto up to max_lines lines (each ≤ maxw px by the same estimate as fit)
    instead of being cut on line one; only when even max_lines are not enough is the LAST line Clipped(full=s), so a reader
    still gets the whole sentence as the tooltip. A word longer than a line is fitted (cut) like fit()."""
    full, t = _full(s), _norm(s)
    per = size * CW * (1.06 if bold else 1)
    n = max(1, int(maxw // per))
    if len(t) <= n:
        return [s if isinstance(s, Clipped) else t]
    words, out, cur = t.split(), [], ''
    for w in words:
        if cur and len(cur) + 1 + len(w) > n:
            out.append(cur)
            cur = w
        else:
            cur = (cur + ' ' + w).strip()
    if cur:
        out.append(cur)
    lines = out[:max_lines]
    cut = len(out) > max_lines or any(len(x) > n for x in lines)
    lines = [fit(x, maxw, size, bold) if len(x) > n else x for x in lines]
    if cut:
        last = str(lines[-1]).rstrip('…')
        lines[-1] = Clipped(last[:max(1, n - 2)].rstrip() + '…', full)
    return lines


def svg_inner(s):
    """(inner markup, extra class) for an SVG <text> carrying s"""
    if isinstance(s, Clipped):
        return f'<title>{E(s.full)}</title>{E(s)}<tspan class="tt-i" dx="2">{MARK}</tspan>', 'tt'
    return E(s), ''


def html(s):
    if isinstance(s, Clipped):
        return f'<span class="tt" title="{E(s.full)}">{E(s)}<span class="tt-i" aria-hidden="true">{MARK}</span></span>'
    return E(s)


def glyph(sym, meaning):
    """inner markup for an SVG <text> that draws a symbol (e.g. "…" = ran out of tokens): the meaning as its tooltip"""
    return f'<title>{E(meaning)}</title>{E(sym)}'


def html_clip(s, n):
    return html(clip(s, n))


TT_CSS = ('.tt{cursor:help}svg text.tt{cursor:help}'
          'svg .tt-i{fill:var(--ak-accent,var(--cluster,#2a8f7f));font-weight:700}'
          '.tt-i{color:var(--ak-accent,var(--cluster,#2a8f7f));font-weight:700;font-size:.85em;margin-left:2px;font-style:normal}'
          'svg text.tt:hover{text-decoration:underline dotted}')

TT_JS = r'''
window.akClipSvg=function(s,n){s=String(s==null?'':s).replace(/\s+/g,' ').trim();var e=function(x){return x.replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});};
 if(s.length<=n)return e(s);return '<title>'+e(s)+'</title>'+e(s.slice(0,Math.max(1,n-2)).replace(/\s+$/,''))+'…<tspan class="tt-i" dx="2">ⓘ</tspan>';};
window.akClipHtml=function(s,n){s=String(s==null?'':s).replace(/\s+/g,' ').trim();var e=function(x){return x.replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});};
 if(s.length<=n)return e(s);return '<span class="tt" title="'+e(s)+'">'+e(s.slice(0,Math.max(1,n-2)).replace(/\s+$/,''))+'…<span class="tt-i" aria-hidden="true">ⓘ</span></span>';};
'''


class _P(HTMLParser):
    """finds every "…" that a reader sees, and whether it sits in a tooltip-carrying element with the marker"""
    SKIP = {'pre', 'code', 'script', 'style', 'title', 'textarea'}
    # 2026-10-20 (DERO artifact): text that is a VERBATIM quotation of a source line is exempt. Its "…" was
    # typed by whoever wrote that line; it is not a cut this page made, and there is no longer sentence to
    # show. An element opts in with data-verbatim, and the exemption covers its descendants. assetkit's
    # citation panel marks every quoted line this way.
    VERBATIM = 'data-verbatim'

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.st, self.bad, self.good, self.sec = [], [], 0, None

    def handle_starttag(self, t, a):
        a = dict(a)
        if t == 'section' and a.get('id'):
            self.sec = a['id']
        if t in ('br', 'img', 'input', 'meta', 'link', 'hr', 'wbr', 'rect', 'circle', 'path', 'line', 'polyline', 'polygon', 'use', 'stop'):
            return
        self.st.append({'t': t, 'tt': 'tt' in (a.get('class') or '').split() or bool(a.get('title')), 'title_child': False,
                        'mark': False, 'cuts': [], 'verbatim': self.VERBATIM in a})

    def handle_startendtag(self, t, a):
        pass

    def handle_endtag(self, t):
        while self.st:
            el = self.st.pop()
            if el['t'] == 'title' and self.st:
                self.st[-1]['title_child'] = True
            if el['cuts']:
                # a lone "…" is a SYMBOL (e.g. a legend glyph), not a cut sentence: it needs only a title saying what it means
                glyph = all(c == '…' for c in el['cuts']) and (el['tt'] or el['title_child'])
                ok = glyph or ((el['tt'] or el['title_child']) and el['mark'])
                if ok:
                    self.good += len(el['cuts'])
                else:
                    self.bad += [f'{self.sec} · <{el["t"]}> {c!r}' for c in el['cuts']]
            if el['t'] == t:
                break

    def handle_data(self, d):
        if not self.st:
            return
        if any(x['t'] in self.SKIP or x.get('verbatim') for x in self.st):
            return
        top = self.st[-1]
        if MARK in d:
            # the marker may sit in a child (tspan / span): credit the nearest element that holds the cut
            for x in reversed(self.st):
                if x['cuts'] or x['tt'] or x['title_child']:
                    x['mark'] = True
                    break
            else:
                top['mark'] = True
        if '…' in d:
            owner = next((x for x in reversed(self.st) if x['tt'] or x['title_child']), top)
            owner['cuts'].append(d.strip()[-40:])
            if MARK in d:
                owner['mark'] = True


def audit(h):
    p = _P()
    p.feed(h)
    while p.st:
        p.handle_endtag(p.st[-1]['t'])
    return {'ok': not p.bad, 'cut_without_tooltip': len(p.bad), 'cut_with_tooltip': p.good, 'examples': p.bad[:15]}


if __name__ == '__main__':
    r = audit(Path(sys.argv[1]).read_text())
    print(json.dumps(r, indent=1, ensure_ascii=False))
    sys.exit(0 if r['ok'] else 3)
