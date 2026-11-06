#!/usr/bin/env python3
"""assetkit — evidence-class tags on every asset of an artifact page (tables, cards and SVG diagrams).

THE VOCABULARY (closed): SRC | GK | PLAN | HARNESS | EXT
  SRC      proven by a line in the source tree under study
  GK       general / upstream knowledge (behaviour of upstream software, industry terms)
  PLAN     a proposal or design that has not been run
  HARNESS  the owner's own measured system, scripts or files
  EXT      quoted from an external document under audit

HOW A TAG WAS OBTAINED IS PART OF THE TAG (never guessed, and shown by the pill's border):
  own  solid   the asset's own `class`, or an explicit marker in its own text: "(GK)", "— SRC", "class: PLAN"
  inh  dashed  inherited from the row/object the asset belongs to
  der  dashed  derived from where its proof lines point (caller supplies `ev_class`)
  sec  dotted  declared for a whole column/section by the generator, with the reason in the tooltip
  A compound class string such as "SRC (microk8s) / GK (kubeadm option)" yields one pill per class, and the
  full original string goes in the tooltip. Anything else renders a red UNK pill, and audit() fails on it.

USE (a generator)
  import assetkit as ak
  cls_of = functools.partial(ak.cls_of, ev_class=my_ev_class)    # my_ev_class(obj) -> ['SRC', ...] from its proof
  ak.ctag(cls_of(row))                         HTML pill(s) for a row / a field: ak.ctag(cls_of(row, 'image'))
  ak.svg_ctag(x_right, y, cls_of(obj))         SVG pill(s) right-aligned at x_right → (svg, width)
  ak.tag_rows(rows, objs, fields, cls_of)      append a pill to every asset cell of a table's rows
  ak.CT_CSS                                    put in <style>
  ak.audit(html) / python3 assetkit.py page    G10-style gate: exit 3 on any untagged asset cell, UNK pill or untagged g.as
  Tables that record a page's own process (ledgers) opt out with data-notag="<reason>" on <table>.

CITATIONS (2026-10-16): every pill opens a clickable panel of the EXACT places that prove it, filtered to its class
  SRC/HARNESS/PLAN/EXT → file path + line (vscode://file/…:line) · GK → the URL that states it (verified quote shown)
  a class tuple may carry a 4th element: cites = [ak.cite_file(abs, line, quote, cls) | ak.cite_url(url, quote, title)]
  ak.reg_reset() before a build; ak.cites_script() at the end of <body> (the registry the pills point into by data-ci)
  page: <style>{ak.CITE_CSS}</style> · <script>{ak.CITE_JS}</script>; a pill whose class has no citation renders
  .ct-nocite and the panel says so in red — audit() counts them (never invent a citation to fill one)
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):   # r27 B120: usage, exit 0, nothing run or written
    print(__doc__ or 'usage: see the header of this file')
    raise SystemExit(0)
import html.parser, json, re, sys
from pathlib import Path

CLASSES = ('SRC', 'GK', 'PLAN', 'HARNESS', 'EXT')
CT_HOW = {'own': 'its own class', 'inh': 'inherited from the row it belongs to',
          'der': 'derived from where its proof lines point', 'sec': 'declared for this section'}
MARK_RE = re.compile(r'(?:\(\s*|[—–]\s*|\bclass\s*:?\s*)(SRC|GK|PLAN|HARNESS|EXT)\b')
TOKEN_RE = re.compile(r'\b(SRC|GK|PLAN|HARNESS|EXT)\b')
CT_COL = {'SRC': 'var(--ak-src,var(--ok,#1d7a4a))', 'GK': 'var(--ak-gk,var(--queued,#5a46a0))', 'PLAN': 'var(--ak-plan,var(--l4,#2563a8))',
          'HARNESS': 'var(--ak-harness,var(--host,#b0560e))', 'EXT': 'var(--ak-ext,var(--mut,#667))'}
UNK_COL = 'var(--ak-alert,var(--gap,#c0392b))'
E = lambda s: __import__('html').escape(str(s), quote=True)

CT_CSS = ('.ct{display:inline-block;font-family:var(--mono,ui-monospace,monospace);font-size:.56rem;font-weight:700;letter-spacing:.04em;padding:0 4px;'
          'margin-left:4px;border-radius:3px;border:1px solid currentColor;vertical-align:1px;white-space:nowrap;line-height:1.45}'
          '.ct-inh,.ct-der{border-style:dashed}.ct-sec{border-style:dotted}'
          + ''.join(f'.ct-{c}{{color:{v}}}' for c, v in CT_COL.items()) + f'.ct-UNK{{color:{UNK_COL}}}')


# the same pills for content a page draws in the browser: payload items carry ct = ak.ct_json(cls) = [classes, how, why]
CT_JS = r'''
window.akTag=function(t){if(!t)return '';var e=function(s){return String(s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});};
 return t[0].map(function(c,i){var ci=t[3]?t[3][i]:'';return '<span class="ct ct-'+(/^(SRC|GK|PLAN|HARNESS|EXT)$/.test(c)?c:'UNK')+' ct-'+t[1]+(akNoCite(ci)?' ct-nocite':'')+'" data-ci="'+ci+'" tabindex="0" role="button" aria-label="'+e(c)+' — show citations">'+e(c)+'</span>';}).join('');};
window.akPill=function(xr,y,t,size){if(!t)return '';size=size||7.5;var C={SRC:'var(--ak-src,var(--ok,#1d7a4a))',GK:'var(--ak-gk,var(--queued,#5a46a0))',PLAN:'var(--ak-plan,var(--l4,#2563a8))',HARNESS:'var(--ak-harness,var(--host,#b0560e))',EXT:'var(--ak-ext,var(--mut,#667))'};
 var o='',x=xr;t[0].slice().reverse().forEach(function(c){var w=c.length*size*0.66+7,col=C[c]||'var(--ak-alert,var(--gap,#c0392b))';x-=w;
  var ci=t[3]?t[3][t[0].indexOf(c)]:'';o+='<g class="ct ct-'+(C[c]?c:'UNK')+' ct-'+t[1]+(akNoCite(ci)?' ct-nocite':'')+'" data-ci="'+ci+'" tabindex="0" role="button" aria-label="'+c+' — show citations"><rect x="'+x.toFixed(1)+'" y="'+(y-size/2-2).toFixed(1)+'" width="'+w.toFixed(1)+'" height="'+(size+4)+'" rx="2.5" fill="var(--panel,#fff)" stroke="'+col+'" stroke-width=".8"'+(t[1]==='own'?'':' stroke-dasharray="2 1.5"')+'/><text x="'+(x+w/2).toFixed(1)+'" y="'+(y+size*0.36).toFixed(1)+'" font-size="'+size+'" text-anchor="middle" font-weight="700" fill="'+col+'">'+c+'</text></g>';x-=2;});return o;};
window.akReg=function(){if(window.__akCites)return window.__akCites;var el=document.getElementById('ak-cites');if(!el)return [];var d=JSON.parse(el.textContent);
 if(d&&d.v===2){var S=d.S,H=d.H||'';d=d.R.map(function(e){return{c:S[e[0]],h:S[e[1]],w:S[e[2]],x:e[3].map(function(x){var y;
  if(x[0]==='u'){y={c:S[x[6]],k:'u',u:S[x[1]],t:S[x[2]]||S[x[1]],q:S[x[3]]};if(S[x[4]])y.n=S[x[4]];if(x[5])y.x=1;}
  else{var p=S[x[1]],lb=S[x[5]];y={c:S[x[6]],k:'f',p:p,l:x[2],t:lb==='\u0000'?p:(lb||(H&&p.indexOf(H)===0?'~'+p.slice(H.length):p)),q:S[x[3]]};if(S[x[4]])y.n=S[x[4]];}return y;})};});}
 return window.__akCites=d;};
window.akNoCite=function(ci){var r=akReg()[ci];return !r||!r.x||!r.x.length;};
window.akPillW=function(t,size){size=size||7.5;return t?t[0].reduce(function(a,c){return a+c.length*size*0.66+9;},0):0;};
'''


def ct_json(cl):
    """a class tuple as JSON-able [classes, how, why, [registry index per class]] for CT_JS (akTag / akPill)"""
    return [list(cl[0]), cl[1], cl[2], [pill_ci(c, cl) for c in cl[0]]]


# ── citation registry: one entry per distinct (class, how, why, citations) a pill shows ──
_REG, _IDX = [], {}


def lines_of(text):
    """a file's lines as an editor / grep -n / vscode://file:LINE count them: split on \\n ONLY (2026-10-19). str.splitlines()
    also splits on U+2028, U+0085, \\x0b, \\x0c, \\x1c-\\x1e: an RTF snapshot (textutil) carries U+2028 soft breaks, and its
    splitlines() numbering ran 3 lines ahead of the file by line 10, so every citation below that point opened the wrong line."""
    ls = [l[:-1] if l.endswith('\r') else l for l in str(text).split('\n')]
    return ls[:-1] if ls and ls[-1] == '' else ls


def reg_reset():
    _REG.clear()
    _IDX.clear()


def cite_file(path, line=None, quote='', cls='SRC', label=None, note=''):
    """note = what the line shows (e.g. how a matcher found it) — shown under the quote, so a reader knows its scope"""
    q = quote or ''
    if '\ufffd' in q or '\x00' in q or sum(1 for ch in q if ord(ch) < 32 and ch not in '\t') > 2:
        q = '(binary file: no text line to quote)'   # R21: a gzip .pgo put U+FFFD/NULs into the page
    d = {'c': cls, 'k': 'f', 'p': str(path), 'l': line, 't': label or str(path), 'q': q[:220]}
    if note:
        d['n'] = note[:300]
    return d


def cite_url(url, quote='', title='', cls='GK', note='', contra=False):
    """note = what the cited text proves (researcher's words, shown as such); contra=True: the source CONTRADICTS the item"""
    d = {'c': cls, 'k': 'u', 'u': url, 't': title or url, 'q': (quote or '')[:220]}
    if note:
        d['n'] = note[:300]
    if contra:
        d['x'] = 1
    return d


def _cites(cl):
    return list(cl[3]) if len(cl) > 3 and cl[3] else []


def pill_ci(c, cl):
    """registry index for the pill of class c: carries only the citations OF THAT CLASS"""
    xs, seen = [], set()
    for x in _cites(cl):
        if x.get('c') == c:
            k = json.dumps(x, sort_keys=True)
            if k not in seen:
                seen.add(k)
                xs.append(x)
    ent = {'c': c, 'h': cl[1], 'w': cl[2], 'x': xs}
    k = json.dumps(ent, sort_keys=True, ensure_ascii=False)
    if k not in _IDX:
        _IDX[k] = len(_REG)
        _REG.append(ent)
    return _IDX[k]


def has_cite(c, cl):
    return any(x.get('c') == c for x in _cites(cl))


def only_contra(c, cl):
    xs = [x for x in _cites(cl) if x.get('c') == c]
    return bool(xs) and all(x.get('x') for x in xs)


HOME = str(Path.home())


def compact(reg):
    """registry v2: every string once in a table S; entry = [c, h, w, [cite…]], cite = [kind, …] with string indices.
    file cite: ['f', p, l, q, n] · url cite: ['u', u, t, q, n, contra]. A file label is the path with $HOME as ~ (derived
    in the browser, never stored). Expanded by akReg() (CT_JS) and expand() (here) to the v1 objects."""
    S, ix = [], {}

    def si(x):
        x = '' if x is None else str(x)
        if x not in ix:
            ix[x] = len(S)
            S.append(x)
        return ix[x]
    R_ = []
    for e in reg:
        xs = []
        for x in e.get('x', []):
            if x.get('k') == 'u':
                xs.append(['u', si(x.get('u')), si(x.get('t') if x.get('t') != x.get('u') else ''), si(x.get('q')), si(x.get('n')), 1 if x.get('x') else 0, si(x.get('c'))])
            else:
                tl, pp = x.get('t'), str(x.get('p', ''))
                lab = '' if tl == pp.replace(HOME, '~', 1) else ('\x00' if tl == pp else tl)   # '' = ~-form, NUL = the path itself
                xs.append(['f', si(x.get('p')), x.get('l'), si(x.get('q')), si(x.get('n')), si(lab), si(x.get('c'))])
        R_.append([si(e.get('c')), si(e.get('h')), si(e.get('w')), xs])
    return {'v': 2, 'H': HOME, 'S': S, 'R': R_}


def expand(d):
    """a v2 registry back to the v1 list (python side: cite_audit, tests)"""
    if isinstance(d, list):
        return d
    S, H = d['S'], d.get('H', '')
    out = []
    for c, h, w, xs in d['R']:
        ex = []
        for x in xs:
            if x[0] == 'u':
                y = {'c': S[x[6]], 'k': 'u', 'u': S[x[1]], 't': S[x[2]] or S[x[1]], 'q': S[x[3]]}
                if S[x[4]]:
                    y['n'] = S[x[4]]
                if x[5]:
                    y['x'] = 1
            else:
                p = S[x[1]]
                lb = S[x[5]]
                y = {'c': S[x[6]], 'k': 'f', 'p': p, 'l': x[2], 't': p if lb == '\x00' else (lb or (p.replace(H, '~', 1) if H and p.startswith(H) else p)), 'q': S[x[3]]}
                if S[x[4]]:
                    y['n'] = S[x[4]]
            ex.append(y)
        out.append({'c': S[c], 'h': S[h], 'w': S[w], 'x': ex})
    return out


def cites_script(compact_form=True):
    data = compact(_REG) if compact_form else _REG
    return '<script type="application/json" id="ak-cites">' + json.dumps(data, ensure_ascii=False, separators=(',', ':')).replace('</', '<\\/') + '</script>'


def with_cites(cl, cites):
    return (cl[0], cl[1], cl[2], _cites(cl) + list(cites or []))


CITE_CSS = ('svg g.ct rect{fill:var(--panel,#fff);stroke-width:.8}svg g.ct text{font-size:7.5px;text-anchor:middle;font-weight:700}'
            + ''.join(f'svg g.ct-{c} rect{{stroke:{v}}}svg g.ct-{c} text{{fill:{v}}}' for c, v in CT_COL.items())
            + f'svg g.ct-UNK rect{{stroke:{UNK_COL}}}svg g.ct-UNK text{{fill:{UNK_COL}}}'
            '.ct[data-ci]{cursor:pointer}svg g.ct[data-ci]{cursor:pointer}.ct:focus-visible{outline:2px solid var(--ak-accent,var(--cluster,#2a8f7f));outline-offset:1px}'
            '.ct-nocite{box-shadow:inset 0 -2px 0 var(--ak-alert,var(--gap,#c0392b))}svg g.ct-nocite rect{stroke-width:1.4}'
            '#ak-cite{position:fixed;z-index:9999;max-width:min(560px,92vw);max-height:60vh;overflow:auto;background:var(--panel,#fff);color:var(--ink,#123);'
            'border:1px solid var(--line,#ccd);border-radius:8px;box-shadow:0 8px 28px rgba(0,0,0,.28);padding:10px 12px;font:12px/1.45 var(--sans,system-ui,sans-serif);display:none}'
            '#ak-cite.on{display:block}#ak-cite .h{display:flex;gap:8px;align-items:center;margin-bottom:6px}#ak-cite .w{color:var(--mut,#667);font-size:11px}'
            '#ak-cite ol{margin:0;padding-left:18px}#ak-cite li{margin:5px 0;word-break:break-all}#ak-cite a{font-family:var(--mono,ui-monospace,monospace);font-size:11.5px}'
            '#ak-cite .q{display:block;color:var(--mut,#667);font-size:11px;word-break:normal;margin-top:1px}#ak-cite .none{color:var(--ak-alert,var(--gap,#c0392b));font-weight:600}'
            '#ak-cite .cp{font:10px var(--mono,ui-monospace,monospace);padding:0 5px;border:1px solid var(--line,#ccd);border-radius:4px;background:transparent;color:var(--mut,#667);cursor:pointer}'
            '#ak-cite .pin{margin-left:auto;font-size:10px;color:var(--mut,#667)}#ak-cite .n{display:block;font-size:11px;margin-top:1px}'
            '#ak-cite li.x{border-left:3px solid var(--ak-alert,var(--gap,#c0392b));padding-left:6px}#ak-cite li.x b{color:var(--ak-alert,var(--gap,#c0392b))}'
            '.ct-contra{text-decoration:line-through}svg g.ct-contra text{text-decoration:line-through}')

# hover / focus a pill → panel of citations (links stay clickable: the panel stays open while the pointer is on it); click pins
CITE_JS = r'''
if(!window.akReg)window.akReg=function(){if(window.__akCites)return window.__akCites;var el=document.getElementById('ak-cites');if(!el)return [];var d=JSON.parse(el.textContent);
 if(d&&d.v===2){var S=d.S,H=d.H||'';d=d.R.map(function(e){return{c:S[e[0]],h:S[e[1]],w:S[e[2]],x:e[3].map(function(x){var y;
  if(x[0]==='u'){y={c:S[x[6]],k:'u',u:S[x[1]],t:S[x[2]]||S[x[1]],q:S[x[3]]};if(S[x[4]])y.n=S[x[4]];if(x[5])y.x=1;}
  else{var p=S[x[1]],lb=S[x[5]];y={c:S[x[6]],k:'f',p:p,l:x[2],t:lb==='\u0000'?p:(lb||(H&&p.indexOf(H)===0?'~'+p.slice(H.length):p)),q:S[x[3]]};if(S[x[4]])y.n=S[x[4]];}return y;})};});}
 return window.__akCites=d;};
(function(){var R=null,box=null,cur=null,pinned=false,ht=0;
 function reg(){if(!R){R=window.akReg?window.akReg():[];}return R;}
 function e(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
 var HOW={own:'its own class',inh:'inherited from its row',der:'derived from its proof / the parts it counts',sec:'declared for this column or section'};
 function build(r){var h='<div class="h"><span class="ct ct-'+e(r.c)+' ct-'+e(r.h)+'">'+e(r.c)+'</span><span class="w">'+e(r.w||HOW[r.h]||'')+'</span><span class="pin">'+(pinned?'pinned · click the tag or Esc to close':'click the tag to pin')+'</span></div>';
  if(!r.x||!r.x.length)return h+'<div class="none">No '+e(r.c)+' citation recorded for this item yet.</div>';
  h+='<ol>';r.x.forEach(function(x){if(x.k==='u')h+='<li'+(x.x?' class="x"':'')+'>'+(x.x?'<b>Upstream contradicts this item:</b> ':'')+'<a href="'+e(x.u)+'" target="_blank" rel="noopener noreferrer">'+e(x.u)+'</a>'+(x.t&&x.t!==x.u?' <span class="w">'+e(x.t)+'</span>':'')+(x.q?'<span class="q" data-verbatim>“'+e(x.q)+'”</span>':'')+(x.n?'<span class="n"><span class="w">'+(x.x?'why: ':'researcher\'s note: ')+'</span>'+e(x.n)+'</span>':'')+'</li>';
   else{var loc=x.t+(x.l?':'+x.l:''),full=x.p+(x.l?':'+x.l:'');h+='<li><a href="vscode://file'+e(full)+'" title="open in VS Code">'+e(loc)+'</a> <button class="cp" data-copy="'+e(full)+'" title="copy path:line">copy</button>'+(x.q?'<span class="q" data-verbatim>“'+e(x.q)+'”</span>':'')+(x.n?'<span class="n"><span class="w">how it was found: </span>'+e(x.n)+'</span>':'')+'</li>';}});
  return h+'</ol>';}
 function show(el){var r=reg()[+el.getAttribute('data-ci')];if(!r)return;if(!box){box=document.createElement('div');box.id='ak-cite';box.setAttribute('role','dialog');document.body.appendChild(box);
   box.addEventListener('pointerenter',function(){clearTimeout(ht);});box.addEventListener('pointerleave',function(){if(!pinned)hide(200);});}
  cur=el;box.innerHTML=build(r);box.classList.add('on');var b=el.getBoundingClientRect(),W=innerWidth,H=innerHeight,bw=box.offsetWidth,bh=box.offsetHeight;
  var x=Math.min(Math.max(8,b.left),W-bw-8),y=b.bottom+6;if(y+bh>H-8)y=Math.max(8,b.top-bh-6);box.style.left=x+'px';box.style.top=y+'px';}
 function hide(ms){clearTimeout(ht);var f=function(){if(box&&!pinned){box.classList.remove('on');cur=null;}};if(!ms)f();else ht=setTimeout(f,ms);}
 function pill(t){return t&&t.closest?t.closest('.ct[data-ci]'):null;}
 document.addEventListener('pointerover',function(ev){var p=pill(ev.target);if(p&&!pinned){clearTimeout(ht);show(p);}},{passive:true});
 document.addEventListener('pointerout',function(ev){var p=pill(ev.target);if(p&&!pinned)hide(300);},{passive:true});
 document.addEventListener('focusin',function(ev){var p=pill(ev.target);if(p&&!pinned)show(p);});
 document.addEventListener('click',function(ev){var cpb=ev.target.closest&&ev.target.closest('#ak-cite .cp');if(cpb){var v=cpb.getAttribute('data-copy');try{navigator.clipboard.writeText(v);cpb.textContent='copied';}catch(e){cpb.textContent=v;}ev.stopPropagation();return;}
  var p=pill(ev.target);if(p){ev.preventDefault();ev.stopPropagation();if(pinned&&cur===p){pinned=false;hide(0);}else{pinned=true;show(p);}return;}
  if(pinned&&box&&!box.contains(ev.target)){pinned=false;hide(0);}},true);
 document.addEventListener('keydown',function(ev){var p=pill(ev.target);if(p&&(ev.key==='Enter'||ev.key===' ')){ev.preventDefault();pinned=true;show(p);}if(ev.key==='Escape'){pinned=false;hide(0);}});
 window.akShowCite=show;
 // compact pills (retrofit: <i class="ct …" data-ci>) get their keyboard + screen-reader affordances here, once
 function a11y(){[].forEach.call(document.querySelectorAll('.ct[data-ci]:not([tabindex])'),function(p){p.setAttribute('tabindex','0');p.setAttribute('role','button');p.setAttribute('aria-label',p.textContent+' — show citations');});}
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',a11y);else a11y();})();
'''


def text_marks(t):
    """classes explicitly marked inside an asset's own text, in order of appearance"""
    if isinstance(t, (dict, list)):
        t = json.dumps(t, ensure_ascii=False)
    out = []
    for m in MARK_RE.findall(str(t or '')):
        if m not in out:
            out.append(m)
    return out


def norm_class(c):
    """'SRC' → ['SRC']; 'SRC (microk8s) / GK (kubeadm)' → ['SRC', 'GK']; unknown → []"""
    if c in CLASSES:
        return [c]
    out = []
    for m in TOKEN_RE.findall(str(c or '')):
        if m not in out:
            out.append(m)
    return out


def cls_of(o, field=None, parent=None, sec=None, ev_class=None, cites_fn=None):
    """(classes, how, why, cites) for one asset: the field `field` of `o`, or `o` itself. cites_fn(obj) → [cite…]
    (the object's own citations; an inherited tag also carries its parent's)."""
    cl = _cls_of(o, field, parent, sec, ev_class)
    if not cites_fn:
        return cl
    xs = []
    for src in ((o, parent) if cl[1] in ('inh', 'der') else (o,)):
        if isinstance(src, dict):
            xs += cites_fn(src) or []
    if cl[1] == 'sec' and sec and len(sec) > 2:
        xs += list(sec[2] or [])
    return cl[0], cl[1], cl[2], xs


def _cls_of(o, field=None, parent=None, sec=None, ev_class=None):
    if field is not None and isinstance(o, dict):
        mk = text_marks(o.get(field))
        if mk:
            return mk, 'own', f'marked inside its own text ({"/".join(mk)})'
    for src, how in ((o, 'own' if field is None else 'inh'), (parent, 'inh')):
        c = src.get('class') if isinstance(src, dict) else None
        if c:
            cs = norm_class(c)
            if cs:
                return cs, how, CT_HOW[how] + ('' if c in CLASSES else f' — "{c}"')
    if ev_class:
        for src in (o, parent):
            ec = ev_class(src) if isinstance(src, dict) else []
            if ec:
                return ec, 'der', CT_HOW['der']
    if sec:
        return [sec[0]], 'sec', f'{CT_HOW["sec"]}: {sec[1]}'
    return ['?'], 'none', 'unclassified'


def fixed(cls, why, cites=None):
    """a column/asset whose class is fixed by what it IS, e.g. fixed('EXT', 'quoted from the document', [cite…])"""
    return [cls], 'sec', f'{CT_HOW["sec"]}: {why}', list(cites or [])


def ctag(cl):
    cs, how = cl[0], cl[1]
    out = []
    for c in cs:
        nc = (' ct-contra' if only_contra(c, cl) else '') if has_cite(c, cl) else ' ct-nocite'
        out.append(f'<span class="ct ct-{E(c) if c in CLASSES else "UNK"} ct-{how}{nc}" data-ci="{pill_ci(c, cl)}" tabindex="0" role="button" '
                   f'aria-label="{E(c)} — show citations">{E(c)}</span>')
    return ''.join(out)


def svg_ctag(xr, y, cl, size=7.5):
    """right-aligned class pill(s) ending at xr, vertically centred on y; returns (svg, width used)"""
    cs, how = cl[0], cl[1]
    o, x = [], xr
    for c in reversed(cs):
        w = round(len(c) * size * 0.66 + 7, 1)
        x -= w
        col = CT_COL.get(c, UNK_COL)
        dash = '' if how == 'own' else (' stroke-dasharray="1 1.5"' if how == 'sec' else ' stroke-dasharray="2 1.5"')
        nc = (' ct-contra' if only_contra(c, cl) else '') if has_cite(c, cl) else ' ct-nocite'
        o.append(f'<g class="ct ct-{c if c in CLASSES else "UNK"} ct-{how}{nc}" data-ci="{pill_ci(c, cl)}" tabindex="0" role="button" aria-label="{E(c)} — show citations">'
                 f'<rect x="{x:.1f}" y="{y - size / 2 - 2:.1f}" width="{w}" height="{size + 4}" rx="2.5"{dash}/>'
                 f'<text x="{x + w / 2:.1f}" y="{y + size * 0.36:.1f}" font-size="{size}">{E(c)}</text></g>')
        x -= 2
    return ''.join(o), round(xr - x, 1)


def svg_ctag_width(cl, size=7.5):
    return round(sum(len(c) * size * 0.66 + 7 + 2 for c in cl[0]), 1)


def tag_rows(rows, objs, fields, cls_of_fn, sec=None, parents=None):
    """fields: one per column — a field name, '' (the row's own class), a (CLASS, reason) tuple (fixed), or None (no tag).
    Empty cells stay empty."""
    parents = parents or [None] * len(objs)
    out = []
    for r, ob, pa in zip(rows, objs, parents):
        row = []
        for c, f in zip(r, fields):
            if f is None or (isinstance(c, str) and re.sub(r'<[^>]+>', '', c).strip() in ('', '—', '–', '-', 'n/a')):   # nothing there → nothing to tag
                row.append(c)
            elif isinstance(f, tuple):   # (CLASS, why) or (CLASS, why, cites_fn(row_obj) -> [cite…])
                row.append(f'{c} {ctag(fixed(f[0], f[1], f[2](ob) if len(f) > 2 and f[2] else None))}')
            else:
                row.append(f'{c} {ctag(cls_of_fn(ob, field=(f or None), parent=pa, sec=sec))}')
        out.append(row)
    return out


# ── G10 audit ──
SKIP_COLS = {'#', 'proof', 'evidence', 'source', 'line', 'class', 'verdict', 'id'}


class _P(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tables, self.st, self.sec, self.cell, self.asg, self.gs = [], [], None, None, [], []
        self.in_svg, self.pending_rect, self.boxes, self.skip_svg = 0, None, [], 0

    def handle_starttag(self, t, a):
        a = dict(a)
        cls = (a.get('class') or '').split()
        if t == 'section' and a.get('id'):
            self.sec = a['id']
        if t == 'table':
            self.st.append({'sec': self.sec, 'notag': a.get('data-notag'), 'heads': [], 'rows': [], 'in_head': False, 'tr': None})
        elif self.st:
            T = self.st[-1]
            if t == 'thead':
                T['in_head'] = True
            elif t == 'tbody':
                T['in_head'] = False
            elif t == 'tr' and not T['in_head']:
                T['tr'] = []
            elif t in ('td', 'th') and T.get('cell') is None:
                # cells are tracked PER TABLE: a table nested inside a cell has its own rows and cells
                T['cell'] = {'text': '', 'ct': 0, 'unk': 0, 'th': t == 'th' and T['in_head'], 'is_th': t == 'th'}
        if 'ct' in cls:
            if self.st and self.st[-1].get('cell') is not None:
                self.st[-1]['cell']['ct'] += 1
                self.st[-1]['cell']['unk'] += 'ct-UNK' in cls
            for g in self.gs:
                if g:
                    g['ct'] += 1
                    g['unk'] += 'ct-UNK' in cls
        if t == 'svg':
            self.in_svg += 1
            self.skip_svg += 'data-notag' in a
        # a labelled box = a <rect> (or a <circle> dot outside a number badge g.nb) immediately followed by a <text>, drawn outside any asset group (g.as) or tag (g.ct)
        if self.in_svg and not self.skip_svg:
            tagged = any(g for g in self.gs if g) or getattr(self, '_ct_depth', 0)
            if t == 'text' and self.pending_rect is not None:
                if not self.pending_rect:
                    self.boxes.append(self.sec)
                self.pending_rect = None
            elif t == 'rect' or (t == 'circle' and not getattr(self, '_nb', 0)):
                self.pending_rect = bool(tagged) or 'notag' in cls
            elif t not in ('title', 'tspan'):
                self.pending_rect = None
        if t == 'g':
            self._nbst = getattr(self, '_nbst', []) + ['nb' in cls]
            self._nb = getattr(self, '_nb', 0) + ('nb' in cls)
            self.gs.append({'ct': 0, 'unk': 0, 'sec': self.sec} if 'as' in cls else None)
            if 'ct' in cls:
                self._ct_depth = getattr(self, '_ct_depth', 0) + 1
                self._ct_stack = getattr(self, '_ct_stack', []) + [True]
            else:
                self._ct_stack = getattr(self, '_ct_stack', []) + [False]

    def handle_endtag(self, t):
        if t == 'svg':
            self.in_svg -= 1
            self.pending_rect = None
        if t == 'g':
            self.pending_rect = None     # a rect and a text on either side of a group boundary are not one labelled box
        if t == 'g' and self.gs:
            g = self.gs.pop()
            if g:
                self.asg.append(g)
            if getattr(self, '_ct_stack', None) and self._ct_stack.pop():
                self._ct_depth -= 1
            if getattr(self, '_nbst', None) and self._nbst.pop():
                self._nb -= 1
        if not self.st:
            return
        T = self.st[-1]
        if t in ('td', 'th') and T.get('cell') is not None:
            c = T['cell']
            if c['th']:
                T['heads'].append(c['text'].strip().lower())
            elif T['tr'] is not None:
                T['tr'].append(c)
            T['cell'] = None
        elif t == 'tr' and T['tr'] is not None:
            row = T['tr']
            if not T['rows'] and not T['heads'] and row and all(c.get('is_th') for c in row):
                T['heads'] = [c['text'].strip().lower() for c in row]     # a header row written without <thead>
            else:
                T['rows'].append(row)
            T['tr'] = None
        elif t == 'table':
            self.tables.append(self.st.pop())

    def handle_data(self, d):
        for T in self.st:                  # an outer cell's text includes its nested table's text
            if T.get('cell') is not None:
                T['cell']['text'] += d


def audit(h, skip_cols=SKIP_COLS):
    p = _P()
    p.feed(h)
    miss, unk, cells, notag = [], 0, 0, 0
    for T in p.tables:
        if T['notag']:
            notag += 1
            continue
        for r in T['rows']:
            for i, c in enumerate(r):
                head = T['heads'][i] if i < len(T['heads']) else ''
                unk += c['unk']
                if head in skip_cols or not re.sub(r'\s+', '', c['text']) or c['text'].strip() in ('—', '–', '-', 'n/a'):   # same rule as tag_rows
                    continue
                cells += 1
                if not c['ct']:
                    miss.append(f"{T['sec']} · col '{head}' · {c['text'].strip()[:50]!r}")
    unk += sum(g['unk'] for g in p.asg)
    as_miss = [g['sec'] for g in p.asg if not g['ct']] + [f'{sec} (labelled box outside g.as)' for sec in p.boxes]
    return {'tables': len(p.tables), 'notag_tables': notag, 'asset_cells': cells, 'untagged_cells': len(miss), 'unclassified': unk,
            'svg_assets': len(p.asg), 'svg_untagged': len(as_miss), 'examples': miss[:12], 'svg_examples': as_miss[:6],
            'ok': not miss and not unk and not as_miss}


def cite_audit(h):
    """G12: every pill carries data-ci into the page's citation registry; per class: pills with ≥1 citation vs none.
    Also proves every registry citation is well-formed (file → absolute path; url → https)."""
    m = re.search(r'<script type="application/json" id="ak-cites">(.*?)</script>', h, re.S)
    reg = expand(json.loads(m.group(1).replace('<\\/', '</'))) if m else []
    by = {}
    no_ci = len(re.findall(r'class="ct ct-\w+ ct-\w+(?: ct-nocite| ct-contra)?"(?! data-ci)', h))
    for c, nc, ci in re.findall(r'class="ct ct-(\w+) ct-\w+( ct-nocite| ct-contra)?" data-ci="(\d+)"', h):
        d = by.setdefault(c, {'cited': 0, 'nocite': 0, 'contradicted': 0})
        d['nocite' if nc == ' ct-nocite' else ('contradicted' if nc else 'cited')] += 1
    bad = [x for r in reg for x in r.get('x', []) if not ((x.get('k') == 'f' and str(x.get('p', '')).startswith('/')) or (x.get('k') == 'u' and str(x.get('u', '')).startswith('https://')))]
    return {'registry': len(reg), 'pills_without_ci': no_ci, 'by_class': by, 'malformed': len(bad),
            'ok': not no_ci and not bad and all(v['nocite'] == 0 for k, v in by.items())}


if __name__ == '__main__':
    r = audit(Path(sys.argv[1]).read_text())
    print(json.dumps(r, indent=1, ensure_ascii=False))
    sys.exit(0 if r['ok'] else 3)
