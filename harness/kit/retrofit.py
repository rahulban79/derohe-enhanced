#!/usr/bin/env python3
"""retrofit — apply the artifact kit to ANY finished HTML page (hand-written or generated), driven by an evidence file.

WHAT IT DOES (one pass, idempotent, exactly reversible):
  * every table asset cell gets a class pill (SRC · GK · PLAN · HARNESS · EXT) that opens its citations
  * every labelled SVG box (a <rect>/<circle> followed by <text>) is wrapped in g.as and gets an SVG pill
  * a numbered badge (<circle> + <text>N</text>) becomes g.nb and is bound to its nearest arrow, so connectorkit's
    hover glow and ▶ play cover hand-drawn diagrams (runtime grouping via data-cxg, no element is moved in the file)
  * a shortened text listed in the evidence file gets its full sentence as a tooltip plus the ⓘ marker (textkit rule);
    a lone "…" glyph listed as a glyph gets a <title> naming what it means
  * the kit's CSS/JS and the citation registry are appended once, between <!--akr:kit--> markers

WHERE CITATIONS COME FROM (never invented):
  1. researched citations stored in the evidence file ("cites": {asset key: [...]}) — every one is re-verified at
     build time (file: the quote must sit within ±3 lines of the cited line; url: urlcheck's cache verdict) and
     dropped, with a report, when it no longer holds;
  2. the deterministic matcher over the page's declared source files ("sources"): an asset's own text found
     verbatim on a source line (≥ 12 chars and ≥ 2 words, or one identifier of ≥ 8 chars), or ≥ 3 of a row's
     distinctive tokens (identifiers, numbers) on ONE source line (exact whole tokens, never fuzzy);
  3. a path that exists under a declared root ("roots") → that file, line 1.
  The class is where the citation lives ("classes": first matching path prefix wins; a URL is GK unless stated).
  An asset with nothing behind it renders a red UNK pill and fails the gate: research it, never guess it.

ASSET KEYS are content keys, so a citation follows the text it proves, not a position:
  r:<row text>   c:<cell text>   b:<box label>   (normalised: tags stripped, whitespace collapsed, lowercase)

USE
  python3 retrofit.py apply  NAME   rewrite the page in place (atomic); NAME = evidence/<NAME>.json
  python3 retrofit.py check  NAME   exit 3 when the page is not what apply would write, or a static gate fails
  python3 retrofit.py strip  NAME [--out F]   the page without any retrofit markup (exact inverse of apply)
  python3 retrofit.py residue NAME [--out F]  every asset still without a citation, with its context (research input)
  python3 retrofit.py stats  NAME   coverage per class, matcher hit counts, page bytes
  generators: html = retrofit.apply_html(html, 'NAME')   (last step before writing; register the evidence file and
              the kit as page sources)
"""
import hashlib, html as _html, json, os, pickle, re, sys, tempfile, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import assetkit as ak  # noqa: E402
import connectorkit as ck  # noqa: E402
import textkit as tk  # noqa: E402

EVID = HERE / 'evidence'
CACHE = HERE / '.cache'
PRIORITY = ('SRC', 'HARNESS', 'EXT', 'GK', 'PLAN')
MAX_CITES = 3

# ── tokenizer ────────────────────────────────────────────────────────────────────────────────────────────────────────
TOK = re.compile(r'<!--.*?-->|<(script|style|textarea)\b[^>]*>.*?</\1\s*>'
                 r'|<(/?)([a-zA-Z][\w:.-]*)((?:\s+[^\s=>/]+(?:\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]+))?)*)\s*(/?)>', re.S | re.I)
ATTR = re.compile(r'([^\s=/]+)(?:\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]+))?')
SEC_TAGS = {'section', 'article', 'details', 'main'}
SVG_SKIP = {'defs', 'marker', 'clippath', 'pattern', 'symbol', 'mask', 'lineargradient', 'radialgradient', 'filter'}
VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr'}
NUM_BADGE = re.compile(r'^\d{1,2}(?:\.\d{1,2})*$')


def attrs(s):
    out = {}
    for k, v in ATTR.findall(s or ''):
        out[k.lower()] = _html.unescape(v[1:-1] if v[:1] in '"\'' else v)
    return out


def fnum(v, d=None):
    try:
        return float(str(v).strip().rstrip('px'))
    except (TypeError, ValueError):
        return d


def norm(t):
    t = _html.unescape(re.sub(r'<[^>]+>', ' ', str(t or '')))
    t = t.replace('“', '"').replace('”', '"').replace('‘', "'").replace('’', "'").replace('–', '-').replace('—', '-').replace('\xa0', ' ')
    t = re.sub(r'[`*]|(?<!\w)_|_(?!\w)', '', t)
    return re.sub(r'\s+', ' ', t).strip().lower()


BARE_AS = re.compile(r'<g class="as">((?:(?!</?g[\s>]).)*?)</g>', re.S)


def bare_box_key(fragment):
    """the citation key of a BARE asset group (2026-10-19): 'b:' + its visible <text> contents (titles excluded), joined
    ' / ' — the same key form as a rect+text box. Shared with every tool that writes cites for such a group."""
    frag = re.sub(r'(?is)<title[^>]*>.*?</title>', '', fragment)
    parts = [norm(re.sub(r'<[^>]+>', ' ', t)) for t in re.findall(r'(?is)<text[^>]*>(.*?)</text>', frag)]
    parts = [x.replace('ⓘ', '').strip() for x in parts if x.strip()]
    return 'b:' + norm(' / '.join(parts))[:200]


def secs_at(h):
    """[(offset, section id or h2 text)] — which section a byte offset belongs to"""
    out = []
    for m in re.finditer(r'<section[^>]*\bid="([^"]+)"|<h2[^>]*>(.*?)</h2>', h, re.S):
        out.append((m.start(), m.group(1) or norm(re.sub('<[^>]+>', ' ', m.group(2) or ''))))
    return out


def bare_groups(h, svgs, secs):
    """g.as groups WITHOUT a pill (a kit-native drawing made BARE, e.g. diagramkit with cls_fn → None, inserted into a hand
    page): each is ONE asset; its pill goes inside the group before </g> (stripped exactly by the data-akr pill pattern)"""
    out = []
    for m in BARE_AS.finditer(h):
        body = m.group(1)
        if 'class="ct' in body:
            continue
        r = re.search(r'<rect[^>]*>', body)
        if not r:
            continue
        sv = max((i for i, s in enumerate(svgs) if s['a'] < m.start()), default=None)
        if sv is None or svgs[sv]['notag']:
            continue
        sec = max(((a, n) for a, n in secs if a < m.start()), default=(0, None))[1]
        key = bare_box_key(body)
        out.append({'a': m.start(), 'end': m.end(), 'close': m.end() - len('</g>'), 'name': 'rect', 'bare': True,
                    'attrs': dict(re.findall(r'([\w-]+)="([^"]*)"', r.group(0))), 'svg': sv, 'sec': sec, 'head': '',
                    'secs': [sec] if sec else [], 'key': key, 'text': key[2:]})
    return out


def scan(h):
    """one pass over the page → tables, svg boxes, badges, connectors, '…' segments (all with byte offsets)"""
    tables, boxes, badges, conns, ells, svgs = [], [], [], [], [], []
    secs, tstack, gstack = [], [], []
    head, in_head_tag, svg_d, skip_d, pend, box, txt_open = '', None, 0, 0, None, None, None
    stack = []                     # open HTML elements (name, attrs, open_end) for the '…' owner lookup
    pos = 0

    def data(a, b):
        nonlocal head
        d = h[a:b]
        if not d.strip():
            return
        if in_head_tag is not None:
            head += d
        if tstack and tstack[-1]['cell'] is not None:
            tstack[-1]['cell']['text'] += d
        if box is not None and txt_open is not None:
            box['label'].append(d)
        if '…' in d and not any(s[0] in ('pre', 'code', 'title') for s in stack):
            i = d.index('…')
            ells.append({'a': a, 'b': b, 'text': d, 'in_svg': bool(svg_d), 'stack': [(s[0], s[1]) for s in stack[-4:]],
                         'text_open': txt_open, 'sec': secs[-1] if secs else None, 'at': a + i})

    def close_box():
        nonlocal box
        if box is not None:
            lab = norm(' / '.join(x.strip() for x in box['label'] if x.strip()))
            if box['badge']:
                badges.append(box)
            else:
                box['key'] = 'b:' + lab[:200]
                box['text'] = lab
                boxes.append(box)
        box = None

    for m in TOK.finditer(h):
        data(pos, m.start())
        pos = m.end()
        if m.group(1) or m.group(0).startswith('<!--'):
            continue
        close, name, at, selfc = m.group(2) == '/', m.group(3).lower(), m.group(4), m.group(5) == '/'
        if not close:
            a = attrs(at)
            cls = (a.get('class') or '').split()
            if name in SEC_TAGS:
                secs.append(a.get('id') or (secs[-1] if secs else None))
            if name in ('h1', 'h2', 'h3', 'h4'):
                in_head_tag, head = name, ''
            if name == 'svg':
                svg_d += 1
                svgs.append({'a': m.start(), 'open_end': m.end(), 'label': a.get('aria-label', ''), 'notag': 'data-notag' in a, 'sec': secs[-1] if secs else None})
                gstack.append(('svg', cls, a))
                continue
            if svg_d:
                if name in SVG_SKIP and not selfc:
                    skip_d += 1
                if name == 'g' and not selfc:
                    gstack.append(('g', cls, a))
                if skip_d or svgs[-1]['notag']:
                    continue
                in_tagged = any(g[0] == 'g' and ({'nb', 'as', 'ct'} & set(g[1])) for g in gstack)
                if name in ('rect', 'circle'):
                    close_box()
                    pend = None if in_tagged or 'notag' in cls else {'a': m.start(), 'tag_end': m.end(), 'name': name, 'attrs': a, 'sec': secs[-1] if secs else None, 'head': head.strip(), 'svg': len(svgs) - 1, 'secs': [x for x in secs if x]}
                    continue
                if name == 'text':
                    if box is None and pend is not None:
                        box = dict(pend, label=[], badge=False, end=None)
                        pend = None
                    if box is not None:
                        txt_open = m.end()
                        box.setdefault('text_opens', []).append(m.end())
                    else:
                        txt_open = m.end()
                    if selfc:
                        txt_open = None
                    continue
                if name in ('tspan', 'title'):
                    continue
                pend = None
                close_box()
                inherit = any(g[0] == 'g' and ('marker-end' in g[2] or 'marker-start' in g[2]) for g in gstack)
                if name in ('path', 'line', 'polyline') and ('marker-end' in a or 'marker-start' in a or inherit):
                    conns.append({'a': m.start(), 'tag_end': m.end(), 'name': name, 'attrs': a, 'svg': len(svgs) - 1, 'selfc': selfc or name in ('path', 'line', 'polyline')})
                continue
            if name in VOID or selfc:
                continue
            stack.append((name, a, m.end()))
            if name == 'table':
                tstack.append({'a': m.start(), 'open_end': m.end(), 'notag': a.get('data-notag'), 'heads': [], 'rows': [], 'in_head': False,
                               'tr': None, 'cell': None, 'sec': secs[-1] if secs else None, 'head': head.strip(), 'secs': [x for x in secs if x]})
            elif tstack:
                T = tstack[-1]
                if name == 'thead':
                    T['in_head'] = True
                elif name == 'tbody':
                    T['in_head'] = False
                elif name == 'tr':
                    T['tr'] = []
                    T['tr_src'] = a.get('data-ak-src')
                elif name in ('td', 'th') and T['tr'] is not None and T['cell'] is None:
                    T['cell'] = {'open_end': m.end(), 'text': '', 'th': name == 'th', 'name': name, 'colspan': int(fnum(a.get('colspan'), 1) or 1)}
        else:
            if name in SEC_TAGS and secs:
                secs.pop()
            if name == in_head_tag:
                in_head_tag = None
            if svg_d:
                if name == 'svg':
                    close_box()
                    pend = None
                    svg_d -= 1
                    if gstack:
                        gstack.pop()
                    continue
                if name in SVG_SKIP:
                    skip_d = max(0, skip_d - 1)
                if name == 'g' and gstack:
                    gstack.pop()
                    close_box()
                    pend = None
                if name == 'text':
                    txt_open = None
                    if box is not None:
                        box['end'] = m.end()
                        lab = norm(' '.join(box['label']))
                        if box['name'] == 'circle' and len(box.get('text_opens', [])) == 1 and NUM_BADGE.match(lab):
                            box['badge'] = True
                            box['n'] = lab
                            close_box()
                continue
            while stack:
                s = stack.pop()
                if s[0] == name:
                    break
            if tstack:
                T = tstack[-1]
                if name in ('td', 'th') and T['cell'] is not None:
                    c = T['cell']
                    c['close_start'] = m.start()
                    if T['in_head']:
                        T['heads'].append(norm(c['text']))
                    elif T['tr'] is not None:
                        T['tr'].append(c)
                    T['cell'] = None
                elif name == 'tr' and T['tr'] is not None:
                    row = T['tr']
                    if not T['rows'] and not T['heads'] and row and all(c['th'] for c in row):
                        T['heads'] = [norm(c['text']) for c in row]     # a header row written without <thead>
                    else:
                        T['rows'].append(row)
                        T.setdefault('srcs', {})[id(row)] = T.get('tr_src')
                    T['tr'] = None
                elif name == 'thead':
                    T['in_head'] = False
                elif name == 'table':
                    tables.append(tstack.pop())
    data(pos, len(h))
    boxes += bare_groups(h, svgs, secs_at(h))
    return {'tables': tables, 'boxes': boxes, 'badges': badges, 'conns': conns, 'ells': ells, 'svgs': svgs}


# ── geometry (badge → nearest arrow) ─────────────────────────────────────────────────────────────────────────────────
def conn_points(c):
    a = c['attrs']
    if c['name'] == 'line':
        return [(fnum(a.get('x1'), 0), fnum(a.get('y1'), 0)), (fnum(a.get('x2'), 0), fnum(a.get('y2'), 0))]
    if c['name'] == 'polyline':
        n = [float(x) for x in re.findall(r'-?\d*\.?\d+(?:e-?\d+)?', a.get('points', ''))]
        return list(zip(n[0::2], n[1::2]))
    pts, cur, cmd = [], (0.0, 0.0), 'M'
    for tok in re.findall(r'[MmLlHhVvCcSsQqTtAaZz]|-?\d*\.?\d+(?:e-?\d+)?', a.get('d', '')):
        if tok.isalpha():
            cmd = tok
            continue
        pts.append((cmd, float(tok)))
    out, i = [], 0
    nums = pts
    while i < len(nums):
        cmd = nums[i][0]
        rel = cmd.islower()
        C = cmd.upper()
        need = {'M': 2, 'L': 2, 'T': 2, 'H': 1, 'V': 1, 'C': 6, 'S': 4, 'Q': 4, 'A': 7}.get(C, 2)
        vals = [v for _, v in nums[i:i + need]]
        i += need
        if len(vals) < need:
            break
        x, y = cur
        if C in ('M', 'L', 'T'):
            nx, ny = vals[0], vals[1]
        elif C == 'H':
            nx, ny = vals[0], (0 if rel else y)
        elif C == 'V':
            nx, ny = (0 if rel else x), vals[0]
        elif C == 'A':
            nx, ny = vals[5], vals[6]
        else:
            nx, ny = vals[-2], vals[-1]
            if C in ('C', 'S', 'Q'):     # control points also bound the curve
                ctrl = vals[:-2]
                for k in range(0, len(ctrl), 2):
                    out.append((ctrl[k] + (x if rel else 0), ctrl[k + 1] + (y if rel else 0)))
        if rel:
            nx, ny = x + nx, y + ny
        cur = (nx, ny)
        out.append(cur)
    return out


def seg_dist(p, a, b):
    (px, py), (ax, ay), (bx, by) = p, a, b
    dx, dy = bx - ax, by - ay
    L = dx * dx + dy * dy
    t = 0 if not L else max(0, min(1, ((px - ax) * dx + (py - ay) * dy) / L))
    return ((ax + t * dx - px) ** 2 + (ay + t * dy - py) ** 2) ** .5


def dist_to(p, pts):
    if not pts:
        return 1e9
    if len(pts) == 1:
        return seg_dist(p, pts[0], pts[0])
    return min(seg_dist(p, pts[k], pts[k + 1]) for k in range(len(pts) - 1))


# ── evidence: sources index + matcher ───────────────────────────────────────────────────────────────────────────────
WTOK = re.compile(r'[a-z0-9][a-z0-9_.:/+-]*[a-z0-9]|[a-z0-9]')
STOP = set('the a an and or of to in on for with by from at is are was were be been it its this that these those as not no yes '
           'via per vs into than then when what which who how why all any each one two three only also but if so do does did '
           'has have had can will may must should could would more most less few many much new old same other own true false none null '
           'ok warn fail pass n/a na id name type value status note notes yes/no on/off'.split())


def distinctive(tok):
    """a token worth matching on: an identifier (has _ . / : - or mixes letters+digits, ≥ 5 chars) or a number with ≥ 2
    significant digits (12, 3.14, 8005) — never a stop word"""
    if tok in STOP or len(tok) < 2:
        return False
    if re.fullmatch(r'\d+(?:\.\d+)?', tok):
        return len(tok.replace('.', '').lstrip('0')) >= 2
    if re.search(r'[_./:+-]', tok) or (re.search(r'\d', tok) and re.search(r'[a-z]', tok)):
        return len(tok) >= 4
    return len(tok) >= 6


class Index:
    """normalised lines of every declared source file + an inverted token index (cached by path/mtime/size)"""
    MAX_BYTES = 40_000_000

    def __init__(self, files):
        self.files, self.lines, self.post = [], [], {}
        files = sorted({str(Path(f)) for f in files if Path(f).is_file()})
        sig = hashlib.sha256(json.dumps([(f, os.path.getmtime(f), os.path.getsize(f)) for f in files]).encode()).hexdigest()[:20]
        CACHE.mkdir(exist_ok=True)
        cf = CACHE / f'index-{sig}.pkl'
        if cf.exists():
            try:
                self.files, self.lines, self.post = pickle.loads(cf.read_bytes())
                return
            except Exception:  # noqa: BLE001 — a damaged cache is rebuilt
                pass
        for fi, f in enumerate(files):
            self.files.append(f)
            if os.path.getsize(f) > self.MAX_BYTES:
                self.lines.append([])
                continue
            try:
                raw = Path(f).read_text(errors='strict')
            except (UnicodeDecodeError, OSError):
                self.lines.append([])
                continue
            nl = [norm(x) if len(x) < 20000 else norm(x[:20000]) for x in ak.lines_of(raw)]
            self.lines.append(nl)
            for li, x in enumerate(nl):
                for t in set(WTOK.findall(x)):
                    p = self.post.setdefault(t, [])
                    if len(p) <= 4000:
                        p.append((fi, li))
        for old in CACHE.glob('index-*.pkl'):
            if old != cf and time.time() - old.stat().st_mtime > 3600:
                old.unlink(missing_ok=True)
        cf.write_bytes(pickle.dumps((self.files, self.lines, self.post)))

    def rare(self, toks):
        ts = [t for t in toks if t in self.post]
        if len(ts) < len(set(toks)):
            return None              # a token that occurs nowhere → the phrase occurs nowhere
        return min(ts, key=lambda t: len(self.post[t])) if ts else None

    def phrase(self, needle, limit=8):
        toks = WTOK.findall(needle)
        r = self.rare(toks)
        if not r or len(self.post[r]) > 4000:
            return []
        out = []
        for fi, li in self.post[r]:
            if needle in self.lines[fi][li]:
                out.append((fi, li))
                if len(out) >= limit:
                    break
        return out

    def cooccur(self, groups, min_tok=3, min_strong=2, min_groups=2, win=6):
        """windows (±3 lines of a file) holding distinctive tokens from ≥ min_groups of the asset's texts, ≥ min_tok tokens
        in all, ≥ min_strong of them strong → [(n_tokens, fi, li of the rarest matched token)] best first.
        groups: one token list per text (a row's cells / a box's label lines). Exact whole tokens only."""
        hit = {}
        for gi, toks in enumerate(groups):
            for t in sorted(set(toks)):          # sorted: set order follows PYTHONHASHSEED, and the page must not
                p = self.post.get(t)
                if not p or len(p) > 4000:
                    continue
                for fi, li in p:
                    for b in ((fi, li // win, 0), (fi, (li + win // 2) // win, 1)):
                        d = hit.setdefault(b, {})
                        if t not in d or len(p) < d[t][1]:
                            d[t] = (gi, len(p), li)
        out = []
        for (fi, _, _), d in hit.items():
            if len(d) < min_tok or len({v[0] for v in d.values()}) < min_groups or sum(1 for t in d if strong(t)) < min_strong:
                continue
            rare = min(d.values(), key=lambda v: (v[1], v[2]))
            out.append((len(d), fi, rare[2]))
        out.sort(key=lambda x: (-x[0], x[1], x[2]))
        seen, res = set(), []
        for n, fi, li in out:
            if (fi, li) not in seen:
                seen.add((fi, li))
                res.append((n, fi, li))
        return res


def strong(tok):
    """a token that identifies on its own: letters mixed with digits or _ . / : - (≥ 5 chars), or a decimal number with
    ≥ 3 significant digits (39.8 is weak, 45.42 / 137.4 strong), or a 4+ digit integer (a port, a size)"""
    if re.fullmatch(r'\d+\.\d+', tok):
        return len(tok.replace('.', '').lstrip('0')) >= 3
    if re.fullmatch(r'\d+', tok):
        return len(tok) >= 4
    return len(tok) >= 5 and bool(re.search(r'[a-z]', tok)) and bool(re.search(r'[\d_./:-]', tok))


def phrase_ok(t):
    """a sentence long enough to be a claim of its own: ≥ 20 chars and ≥ 3 non-stop words"""
    ws = WTOK.findall(t)
    return len(t) >= 20 and sum(1 for w in ws if w not in STOP) >= 3


FILE_RE = re.compile(r'[\w.+-]+\.(?:py|sh|md|json|jsonl|yaml|yml|toml|go|ts|tsx|js|rs|txt|cfg|ini|mojo|c|cc|cpp|h)\b')


class Evidence:
    def __init__(self, name_or_path, extra_sources=()):
        p = Path(name_or_path)
        self.path = p if p.suffix == '.json' and p.exists() else EVID / f'{name_or_path}.json'
        self.cfg = json.loads(self.path.read_text())
        for inc in self.cfg.get('include', []):          # shared declarations (e.g. an embedded generated block)
            sub = json.loads((self.path.parent / inc).read_text())
            for k in ('sources', 'classes', 'roots', 'sections', 'exclude'):
                self.cfg[k] = list(self.cfg.get(k, [])) + list(sub.get(k, []))
            for k in ('notag_tables', 'notag_svgs', 'clips', 'glyphs', 'excerpts'):
                self.cfg[k] = dict(sub.get(k, {}), **self.cfg.get(k, {}))
        self.name = self.cfg.get('name') or self.path.stem
        self.page = Path(os.path.expanduser(self.cfg['page'])) if self.cfg.get('page') else None
        files = []
        for g in self.cfg.get('sources', []) + list(extra_sources):
            g = os.path.expanduser(str(g))
            if any(ch in g for ch in '*?['):
                import glob
                files += glob.glob(g, recursive=True)
            elif Path(g).is_dir():
                files += [str(x) for x in Path(g).rglob('*') if x.is_file() and x.suffix in ('.md', '.txt', '.json', '.jsonl', '.yaml', '.yml', '.py', '.sh', '.log', '.toml', '.csv', '.html')]
            else:
                files.append(g)
        ex = [re.compile(x) for x in self.cfg.get('exclude', [])]
        files = [f for f in files if not any(e.search(f) for e in ex) and (not self.page or os.path.realpath(f) != os.path.realpath(self.page))]
        self.idx = Index(files)
        self.classes = [(os.path.expanduser(a), c, w) for a, c, w in self.cfg.get('classes', [])]
        self.roots = [(os.path.expanduser(a), c) for a, c in self.cfg.get('roots', [])]
        self.priority = tuple(self.cfg.get('priority', PRIORITY))
        self.skip_cols = set(ak.SKIP_COLS) | set(self.cfg.get('skip_cols', []))
        self.notag_tables = self.cfg.get('notag_tables', {})
        self.notag_svgs = self.cfg.get('notag_svgs', {})
        self.clips = {norm(k): v for k, v in self.cfg.get('clips', {}).items()}
        self.glyphs = self.cfg.get('glyphs', {})
        self.excerpts = self.cfg.get('excerpts', {})
        self.researched, self.dropped = {}, []
        self.stats = {'relocated': 0}
        self._fcache = {}
        for k, xs in self.cfg.get('cites', {}).items():
            good = [x for x in xs if self.verify(x)]
            self.dropped += [(k, x) for x in xs if x not in good]
            if good:
                self.researched[k] = good
        self.stats.update({'researched': 0, 'phrase': 0, 'cooccur': 0, 'root': 0, 'section': 0, 'none': 0})
        self.sections = []
        for sd in self.cfg.get('sections', []):
            xs = [y for y in (self.sec_cite(x, sd.get('cls')) for x in sd.get('cites', [])) if y]
            self.sections.append((sd['match'].lower(), sd['cls'], sd.get('why', ''), xs, len(xs) < len(sd.get('cites', []))))

    def diagram(self, label):
        """the classification declared for the diagram whose aria-label starts with `match`, or None"""
        for d in self.cfg.get('diagrams', []):
            if label and label.lower().startswith(d['match'].lower()):
                return d
        return None

    def provenance(self, v):
        """a generator's own record of where a row was read from: data-ak-src="path:line[|path:line…]" on the <tr>.
        Each must name an existing line; the quote is that line as it reads now."""
        out = []
        for part in str(v).split('|'):
            m = re.match(r'(.+):(\d+)$', part.strip())
            if not m:
                continue
            p, ln = os.path.expanduser(m.group(1)), int(m.group(2))
            if p not in self._fcache:
                try:
                    self._fcache[p] = ak.lines_of(Path(p).read_text(errors='replace'))
                except OSError:
                    self._fcache[p] = []
            L = self._fcache[p]
            c = self.cls_of_path(p)[0]
            if not c or not (1 <= ln <= len(L)):
                continue
            q = L[ln - 1].strip()
            out.append(ak.cite_file(p, ln, q[:217] + ('…' if len(q) > 217 else ''), c, label=p.replace(str(Path.home()), '~'),
                                    note='the generator recorded that it read this row from here'))
        if out:
            self.stats['provenance'] = self.stats.get('provenance', 0) + 1
        return out[:MAX_CITES]

    def sec_cite(self, x, cls):
        """a section citation: {p, def: NAME} → the line of `def NAME(` in p (found at build time, so it never drifts);
        {p, l, q} → verified like any researched citation; {p} → the file itself, line 1"""
        p = os.path.expanduser(x['p'])
        if not os.path.isfile(p):
            return None
        if x.get('def'):
            for i, ln in enumerate(ak.lines_of(Path(p).read_text(errors='replace'))):
                if re.match(r'\s*(?:async\s+)?def\s+' + re.escape(x['def']) + r'\s*\(', ln):
                    return ak.cite_file(p, i + 1, ln.strip()[:220], x.get('c') or self.cls_of_path(p)[0] or cls, label=p.replace(str(Path.home()), '~'),
                                        note=f'the generator function that renders this section ({x["def"]})')
            return None
        if x.get('l') and not self.verify(x):
            return None
        return ak.cite_file(p, x.get('l') or 1, x.get('q', ''), x.get('c') or self.cls_of_path(p)[0] or cls, label=p.replace(str(Path.home()), '~'),
                            note='' if x.get('l') else 'the file this section is read from')

    def section(self, sec, head, *more):
        """the section-level citation declared for this table/figure, or None. A declaration matches the section id, the
        heading, the figure's aria-label or the table's header row (exact, or as a prefix). For GENERATED content only:
        the citation is the function that rendered it and the file it read — never a substitute for research."""
        keys = [(k or '').lower() for k in (sec, head) + more]
        for m, cls, why, xs, _ in sorted(self.sections, key=lambda d: next((i for i, k in enumerate(keys) if k and (k == d[0] or k.startswith(d[0]))), 99)):
            if any(k and (k == m or k.startswith(m)) for k in keys) and xs:
                self.stats['section'] += 1
                cs = list(dict.fromkeys([x['c'] for x in xs]))      # each cited file keeps the class of where it lives
                return (cs, 'sec', f'declared for this section: {why}', xs)
        return None

    def candidates(self, texts, n=6):
        """loose hints for a researcher (NEVER shown as citations): lines sharing the most distinctive tokens"""
        groups = [list(dict.fromkeys(w for w in WTOK.findall(norm(t)) if distinctive(w))) for t in texts]
        groups = [g for g in groups if g]
        hits = self.idx.cooccur(groups, min_tok=2, min_strong=0, min_groups=1) if groups else []
        out = []
        for _, fi, li in hits[:n]:
            f = self.idx.files[fi]
            try:
                q = ak.lines_of(Path(f).read_text(errors='replace'))[li].strip()[:200]
            except (OSError, IndexError):
                q = ''
            out.append({'p': f, 'l': li + 1, 'q': q})
        return out

    # a researched citation holds only while its quote is still at (±3 lines of) its line / still verified by urlcheck
    def verify(self, x):
        if x.get('u'):
            return bool(x.get('verified', True)) and x['u'].startswith('https://')
        p = os.path.expanduser(x.get('p', ''))
        if not p.startswith('/') or not os.path.isfile(p):
            return False
        if p not in self._fcache:
            try:
                self._fcache[p] = ak.lines_of(Path(p).read_text(errors='replace'))
            except OSError:
                self._fcache[p] = []
        L, ln, q = self._fcache[p], int(x.get('l') or 1), norm(x.get('q', ''))
        if not q:
            return ln <= max(1, len(L))
        win = norm(' '.join(L[max(0, ln - 4):ln + 3]))
        if q in win or re.sub(r'\s+', '', q) in re.sub(r'\s+', '', win):
            return True
        # the file was edited above the cited line: follow the quote, but ONLY to a single unambiguous line
        hits = [i for i, t in enumerate(L) if q in norm(t)]
        if len(hits) > 1 and x.get('a'):
            # 2026-10-17: a quote repeated in a file that is rewritten daily (stack-updates.json: '"version": "v0.30.0"' under
            # several stacks) carries an anchor 'a' — a line that occurs ONCE (e.g. '"vl.src.vllm": {'); follow the quote to its
            # first hit below that anchor. An ambiguous or missing anchor still drops the citation.
            an = norm(x['a'])
            ah = [i for i, t in enumerate(L) if an in norm(t)]
            hits = [i for i in hits if len(ah) == 1 and i > ah[0]][:1]
        if len(hits) == 1:
            x['l'] = hits[0] + 1
            self.stats['relocated'] = self.stats.get('relocated', 0) + 1
            return True
        return False

    def cls_of_path(self, p):
        rp = os.path.realpath(p)
        for pre, c, w in self.classes:
            if p.startswith(pre) or rp.startswith(os.path.realpath(pre)):
                return c, w
        return None, None

    def cite(self, fi, li, needle='', note=''):
        f = self.idx.files[fi]
        c, w = self.cls_of_path(f)
        if not c:
            return None
        try:
            raw = ak.lines_of(Path(f).read_text(errors='replace'))[li]
        except (OSError, IndexError):
            raw = ''
        raw = raw.strip()
        if len(raw) > 200:
            j = raw.lower().find(needle[:40]) if needle else -1
            s = max(0, (j if j >= 0 else 0) - 60)
            raw = ('…' if s else '') + raw[s:s + 180] + '…'
        x = ak.cite_file(f, li + 1, raw, c, label=f.replace(str(Path.home()), '~'))
        if note:
            x['n'] = note[:300]
        return x

    def mk(self, x):
        if x.get('u'):
            return ak.cite_url(x['u'], x.get('q', ''), x.get('t', ''), x.get('c', 'GK'), x.get('n', ''), bool(x.get('x')))
        p = os.path.expanduser(x['p'])
        c = x.get('c') or self.cls_of_path(p)[0] or 'UNK'
        return ak.cite_file(p, x.get('l'), x.get('q', ''), c, label=p.replace(str(Path.home()), '~'))

    def best(self, hits, needle='', note=''):
        """≤ MAX_CITES citations from the highest-priority class present, distinct files first"""
        cs = [x for x in (self.cite(fi, li, needle, note) for fi, li in hits) if x]
        if not cs:
            return []
        top = min((PRIORITY.index(x['c']) if x['c'] in PRIORITY else 9) for x in cs)
        cs = [x for x in cs if (PRIORITY.index(x['c']) if x['c'] in PRIORITY else 9) == top]
        out, seen = [], set()
        for x in cs:
            if x['p'] not in seen:
                seen.add(x['p'])
                out.append(x)
        for x in cs:
            if len(out) >= MAX_CITES:
                break
            if x not in out:
                out.append(x)
        return out[:MAX_CITES]

    def basenames(self):
        """basename → [paths] for every code/doc file under the declared roots (cached per root set)"""
        if hasattr(self, '_bn'):
            return self._bn
        sig = hashlib.sha256(json.dumps(self.roots).encode()).hexdigest()[:16]
        cf = CACHE / f'basenames-{sig}.json'
        if cf.exists() and time.time() - cf.stat().st_mtime < 86400:
            self._bn = json.loads(cf.read_text())
            return self._bn
        bn = {}
        for root, c in self.roots:
            for dp, dn, fn in os.walk(root):
                dn[:] = [d for d in dn if not d.startswith('.') and d not in ('node_modules', 'build', 'dist', '__pycache__', 'site-packages')]
                for f in fn:
                    if FILE_RE.fullmatch(f):
                        bn.setdefault(f.lower(), []).append([os.path.join(dp, f), c])
        CACHE.mkdir(exist_ok=True)
        cf.write_text(json.dumps(bn))
        self._bn = bn
        return bn

    def _file_cite(self, fp, c):
        q, ln = '', 1
        try:
            for i, x in enumerate(ak.lines_of(Path(fp).read_text(errors='replace'))[:8]):
                if x.strip() and not x.startswith('#!'):
                    q, ln = x.strip()[:220], i + 1
                    break
        except OSError:
            pass
        x = ak.cite_file(fp, ln, q, c, label=fp.replace(str(Path.home()), '~'))
        x['n'] = 'the file this text names (it exists at this path)'
        return x

    def file_named(self, texts, whole):
        """a text that IS a file reference: a relative path under a root, or a basename unique among all roots.
        whole=True: only when the text is nothing but that reference (a name cell, a file box)."""
        for t in texts:
            n = norm(t)
            for tok in FILE_RE.findall(n) + [x for x in WTOK.findall(n) if '/' in x and FILE_RE.search(x)]:
                if whole and len(n) > len(tok) + 40:
                    continue
                for root, c in self.roots:
                    fp = os.path.join(root, tok.strip('/'))
                    if '/' in tok and os.path.isfile(fp):
                        return [self._file_cite(fp, c)]
                hits = self.basenames().get(tok.rsplit('/', 1)[-1])
                if hits and len(hits) == 1:
                    fp, c = hits[0]
                    if '/' not in tok or fp.endswith(tok):
                        return [self._file_cite(fp, c)]
        return []

    def find_texts(self, texts, kind='row'):
        """citations for an asset whose texts are `texts` (a row: its cells; a box: its label lines; a cell: [text]).
        1. a sentence of it (≥ 20 chars, ≥ 3 content words) found verbatim on a source line
        2. distinctive tokens from ≥ 2 of its texts (≥ 3 tokens, ≥ 2 strong) inside one ±3-line window of a source file
        3. a text that is a file reference → that file (relative path under a root, or a unique basename)"""
        for t in sorted({norm(t) for t in texts}, key=len, reverse=True):
            if phrase_ok(t):
                hits = self.idx.phrase(t)
                if hits:
                    self.stats['phrase'] += 1
                    return self.best(hits, t, 'matched: this text occurs verbatim on the line')
        groups = [list(dict.fromkeys(w for w in WTOK.findall(norm(t)) if distinctive(w))) for t in texts]
        groups = [g for g in groups if g]
        if len(groups) >= 2:
            hits = self.idx.cooccur(groups)
            if hits:
                self.stats['cooccur'] += 1
                xs = self.best([(fi, li) for _, fi, li in hits[:12]], groups[0][0])
                allt = [t for g in groups for t in g]
                for x in xs:          # say exactly which of the asset's tokens sit near this line (±3 lines)
                    try:
                        L = ak.lines_of(Path(x['p']).read_text(errors='replace'))
                    except OSError:
                        L = []
                    win = set(WTOK.findall(norm(' '.join(L[max(0, x['l'] - 4):x['l'] + 3]))))
                    x['n'] = 'found together within ±3 lines: ' + ', '.join(t for t in allt if t in win)[:200] + ' (locates the names, not proof of every number)'
                return xs
        xs = self.file_named(texts, whole=True)
        if xs:
            self.stats['root'] += 1
            return xs
        return []

    def resolve(self, key, texts):
        if key in self.researched:
            self.stats['researched'] += 1
            return [self.mk(x) for x in self.researched[key]]
        xs = self.find_texts(texts)
        if not xs:
            self.stats['none'] += 1
        return xs


def cl_from(cites, how, why):
    if not cites:
        return (['?'], 'none', 'no citation found yet — research it, never guess', [])
    cs = []
    for x in cites:
        if x['c'] not in cs:
            cs.append(x['c'])
    return (cs, how, why, cites)


# ── markup ──────────────────────────────────────────────────────────────────────────────────────────────────────────
def pill(cl):
    out = []
    for c in cl[0]:
        nc = (' ct-contra' if ak.only_contra(c, cl) else '') if ak.has_cite(c, cl) else ' ct-nocite'
        out.append(f'<i class="ct ct-{c if c in ak.CLASSES else "UNK"} ct-{cl[1]}{nc}" data-ci="{ak.pill_ci(c, cl)}">{c if c in ak.CLASSES else "UNK"}</i>')
    return ' ' + ''.join(out)


def svg_pill(xr, y, cl, size=7.5):
    s, _ = ak.svg_ctag(xr, y, cl, size)
    return re.sub(r'(<g class="ct [^"]*" data-ci="\d+") tabindex="0" role="button" aria-label="[^"]*">', r'\1 data-akr>', s)


PILL_RE = re.compile(r' <i class="ct ct-\w+ ct-\w+(?: ct-nocite| ct-contra)?" data-ci="\d+">\w+</i>(?:<i class="ct ct-\w+ ct-\w+(?: ct-nocite| ct-contra)?" data-ci="\d+">\w+</i>)*')
STRIP = [
    (re.compile(r'<!--akr:kit-->.*?<!--/akr:kit-->', re.S), ''),
    (re.compile(r'<!--akrb-->.*?<!--/akrb-->', re.S), ''),
    (re.compile(r' data-cxkind="[^"]*" data-cxwhy="[^"]*" data-akrd'), ''),
    (re.compile(r' data-cxwhy="[^"]*" data-akrw'), ''),
    (PILL_RE, ''),
    (re.compile(r'<g class="ct [^"]*" data-ci="\d+" data-akr>.*?</g>', re.S), ''),
    (re.compile(r'<g class="(?:as|nb)" data-akr(?: data-cxg="[^"]*")?>'), ''),
    (re.compile(r'</g><!--akr-->'), ''),
    (re.compile(r' data-cxg="[^"]*"(?: data-ct="[^"]*")? data-akr'), ''),
    (re.compile(r' data-notag="[^"]*" data-akrn'), ''),
    (re.compile(r'<title data-akr>[^<]*</title>'), ''),
    (re.compile(r'<tspan class="tt-i" dx="2" data-akr>ⓘ</tspan>'), ''),
    (re.compile(r'<span class="tt" title="[^"]*" data-akr>([^<]*)<span class="tt-i" aria-hidden="true">ⓘ</span></span>'), r'\1'),
]


def strip(h, ev=None):
    """the exact inverse of apply_html (also inside the compressed fragments an evidence file declares)"""
    if ev is not None and ev.cfg.get('lazy'):
        h = _lazy_map(h, ev, lambda frag, cid: strip(frag))
    for rx, rep in STRIP:
        h = rx.sub(rep, h)
    return h


RETRO_CSS = ('i.ct{font-style:normal}svg g.ct[data-akr] text{pointer-events:none}'
             'svg g.ct[data-akr]{opacity:.92}svg g.as:hover g.ct[data-akr]{opacity:1}')
A11Y_JS = r'''(function(){function a(){[].forEach.call(document.querySelectorAll('.ct[data-ci]:not([tabindex])'),function(p){p.setAttribute('tabindex','0');p.setAttribute('role','button');p.setAttribute('aria-label',p.textContent+' — show citations');});}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',a);else a();})();'''


def kit_block(extra_css=''):
    return ('<!--akr:kit--><style>' + ak.CT_CSS + ak.CITE_CSS + tk.TT_CSS + ck.CONNECTOR_CSS + RETRO_CSS + extra_css + '</style>'
            '<script>' + ak.CT_JS + tk.TT_JS + ak.CITE_JS + '</script><script>' + ck.CONNECTOR_JS + '</script>'
            + ak.cites_script() + '<!--/akr:kit-->')


def _lazy_re(mime):
    return re.compile(r'(<script type="' + re.escape(mime) + r'" class="lazyz" data-raw-bytes=")(\d+)(">)([A-Za-z0-9+/=\s]*)(</script>)')


def _lazy_map(h, ev, fn):
    """apply fn(fragment_html, context_id) to every compressed fragment the evidence file declares ("lazy"), re-encoding
    it deterministically (gzip mtime=0, level 9) — so a card that inflates in the browser carries its pills too"""
    import base64, gzip
    lz = ev.cfg.get('lazy') if ev else None
    if not lz:
        return h
    rx = _lazy_re(lz['mime'])

    def sub(m):
        body = gzip.decompress(base64.b64decode(m.group(4))).decode('utf-8')
        pre = h[max(0, m.start() - 3000):m.start()]
        ids = re.findall(r'<details[^>]*\bid="([^"]+)"', pre)
        new = fn(body, ids[-1] if ids else None)
        z = base64.b64encode(gzip.compress(new.encode('utf-8'), compresslevel=9, mtime=0)).decode('ascii')
        return m.group(1) + str(len(new.encode('utf-8'))) + m.group(3) + z + m.group(5)
    return rx.sub(sub, h)


def apply_html(h, ev, report=None, want_cand=None):
    """the page with the kit applied (strips any previous application first, so it is idempotent)"""
    if not isinstance(ev, Evidence):
        ev = Evidence(ev)
    ak.reg_reset()
    h = strip(h, ev)
    rep = report if report is not None else {}
    rep.update({'cells': 0, 'cells_cited': 0, 'cells_sec': 0, 'boxes': 0, 'boxes_cited': 0, 'badges': 0, 'bound': 0, 'clips': 0, 'glyphs': 0, 'cuts': []})
    h = _lazy_map(h, ev, lambda frag, cid: tag_fragment(frag, ev, rep, want_cand, (cid,) if cid else ()))
    h2 = tag_fragment(h, ev, rep, want_cand)
    blk = kit_block(ev.cfg.get('css', ''))
    i = h2.rfind('</body>')
    h2 = h2[:i] + blk + h2[i:] if i >= 0 else h2 + blk
    rep['researched_dropped'] = len(ev.dropped)
    rep['matcher'] = dict(ev.stats)
    return h2


def tag_fragment(h, ev, rep, want_cand=None, ctx=()):
    """pills, wrappers and tooltips for one HTML fragment (the page, or one decompressed lazy card); ctx = extra section
    keys (the id of the card a fragment belongs to)"""
    S = scan(h)
    ed = []          # (offset, order, text) insertions
    # svgs opted out by the evidence file (legends, pure charts): matched by an aria-label prefix
    for s in S['svgs']:
        for pre, why in ev.notag_svgs.items():
            if s['label'].startswith(pre) and not s['notag']:
                ed.append((s['open_end'] - 1, 0, f' data-notag="{_html.escape(why, quote=True)}" data-akrn'))
                s['notag'] = True
    skip_svg = {i for i, s in enumerate(S['svgs']) if s['notag']}

    # tables
    for T in S['tables']:
        sig = ' | '.join(T['heads'])
        if T['notag'] or any(sig.startswith(k) for k in ev.notag_tables):
            continue
        for row in T['rows']:
            texts = [c['text'] for c in row]
            live = [t for t in texts if norm(t) and norm(t) not in ('—', '-', 'n/a')]
            if not live:
                continue
            rkey = 'r:' + ' | '.join(norm(t) for t in texts)[:200]
            gsrc = (T.get('srcs') or {}).get(id(row))
            rcites = ev.provenance(gsrc) if gsrc else []
            rcites = rcites or ev.resolve(rkey, live)
            col = 0
            for c in row:
                head = T['heads'][col] if col < len(T['heads']) else ''
                col += c['colspan']
                n = norm(c['text'])
                if head in ev.skip_cols or not n or n in ('—', '-', 'n/a'):
                    continue
                rep['cells'] += 1
                ckey = 'c:' + n[:200]
                own = ev.researched.get(ckey)
                if own:
                    cl = cl_from([ev.mk(x) for x in own], 'der', 'derived from where its proof lines point')
                elif rcites:
                    cl = cl_from(rcites, 'inh', 'inherited from its row: where the row\'s own text was found')
                else:
                    cl = ev.section(T['sec'], T['head'], sig, *reversed(T.get('secs') or []), *ctx) or cl_from([], '', '')
                    rep['cells_sec'] = rep.get('cells_sec', 0) + (cl[1] == 'sec')
                if cl[1] != 'none':
                    rep['cells_cited'] += 1
                elif want_cand is not None and rkey not in want_cand:
                    want_cand[rkey] = {'key': rkey, 'kind': 'row', 'sec': T['sec'], 'heading': T['head'][:120], 'columns': T['heads'],
                                       'cells': [norm(t)[:300] for t in texts], 'candidates': ev.candidates(live)}
                ed.append((c['close_start'], 1, pill(cl)))

    # labelled svg boxes
    for b in S['boxes']:
        if b['svg'] in skip_svg or b.get('end') is None:
            continue
        a = b['attrs']
        rep['boxes'] += 1
        parts = [x for x in b['text'].split(' / ') if x]
        cites = ev.resolve(b['key'], parts)
        cl = cl_from(cites, 'der', 'derived from where its label was found') if cites else (ev.section(b['sec'], b['head'], S['svgs'][b['svg']]['label'], *reversed(b.get('secs') or []), *ctx) or cl_from([], '', ''))
        if cl[1] != 'none':
            rep['boxes_cited'] += 1
        elif want_cand is not None and b['key'] not in want_cand:
            want_cand[b['key']] = {'key': b['key'], 'kind': 'box', 'sec': b['sec'], 'heading': b['head'][:120], 'label': b['text'][:300],
                                   'figure': S['svgs'][b['svg']]['label'][:400], 'candidates': ev.candidates(parts)}
        if b['name'] == 'rect':
            x, y, w = fnum(a.get('x'), 0), fnum(a.get('y'), 0), fnum(a.get('width'), 0)
            xr, ym = (x + w - 2, y) if w else (x + 40, y)
        else:
            cx, cy, r = fnum(a.get('cx'), 0), fnum(a.get('cy'), 0), fnum(a.get('r'), 4)
            xr, ym = cx + r + 30, cy - r
        if b.get('bare'):                      # an existing bare g.as: the pill goes INSIDE it, no wrapper
            ed.append((b['close'], 2, svg_pill(xr - 3, ym + 12, cl)))
            continue
        ed.append((b['a'], 0, '<g class="as" data-akr>'))
        ed.append((b['end'], 2, svg_pill(xr, ym, cl) + '</g><!--akr-->'))

    # diagram declarations (evidence "diagrams"): a SEQUENCE gets a number badge at each arrow's midpoint, in execution
    # order, its tooltip naming the source of the order; an arrow that is not a step gets its reason; a RELATIONS diagram
    # is declared on the <svg> with its reason (connectorkit then plays it top-to-bottom and SAYS it is not an order)
    conns_by_svg = {}
    for c in S['conns']:
        conns_by_svg.setdefault(c['svg'], []).append(c)
    for si, sv in enumerate(S['svgs']):
        d = ev.diagram(sv['label'])
        if not d:
            continue
        rep['diagrams'] = rep.get('diagrams', 0) + 1
        why = d.get('why', '')
        ed.append((sv['open_end'] - 1, 0, f' data-cxkind="{_html.escape(d["kind"], quote=True)}" data-cxwhy="{_html.escape(why, quote=True)}" data-akrd'))
        if d['kind'] != 'sequence':
            continue
        cs = conns_by_svg.get(si, [])
        order, notes = d.get('order', {}), d.get('notes', {})
        for k, c in enumerate(cs):
            tag_end = c['tag_end'] - (2 if h[c['tag_end'] - 2] == '/' else 1)
            n = order.get(str(k))
            if n is None:
                if str(k) in notes:
                    ed.append((tag_end, 0, f' data-cxwhy="{_html.escape(notes[str(k)], quote=True)}" data-akrw'))
                continue
            P = conn_points(c)
            if not P:
                continue
            seg = [((P[i][0] - P[i + 1][0]) ** 2 + (P[i][1] - P[i + 1][1]) ** 2) ** .5 for i in range(len(P) - 1)] or [0]
            half, acc, mx, my = sum(seg) / 2, 0, P[0][0], P[0][1]
            for i, L_ in enumerate(seg):
                if acc + L_ >= half and L_:
                    t = (half - acc) / L_
                    mx, my = P[i][0] + t * (P[i + 1][0] - P[i][0]), P[i][1] + t * (P[i + 1][1] - P[i][1])
                    break
                acc += L_
            gid = f'q{si}-{k}'
            ed.append((tag_end, 0, f' data-cxg="{gid}" data-akr'))
            end = c['tag_end'] if c['selfc'] or h[c['tag_end'] - 2] == '/' else h.find('>', h.find('</' + c['name'], c['tag_end'])) + 1
            tip = f'step {n} — order: {d.get("order_source") or why}'
            ed.append((end, 1, f'<!--akrb--><g class="nb" data-cxg="{gid}"><title>{_html.escape(tip, quote=False)}</title>'
                               f'<circle cx="{mx:.1f}" cy="{my:.1f}" r="8" fill="var(--panel,var(--bg,#fff))" stroke="currentColor" stroke-width="1.1"/>'
                               f'<text x="{mx:.1f}" y="{my + 3.2:.1f}" font-size="{8.5 if len(n) < 3 else 7}" text-anchor="middle" font-weight="700" fill="currentColor">{_html.escape(n)}</text></g><!--/akrb-->'))

    # number badges → g.nb, bound to the nearest arrow of the same svg (≤ 30 px) via data-cxg
    conns_by_svg = {}
    for c in S['conns']:
        conns_by_svg.setdefault(c['svg'], []).append(c)
    for k, b in enumerate(S['badges']):
        if b['svg'] in skip_svg or b.get('end') is None:
            continue
        rep['badges'] += 1
        a = b['attrs']
        p = (fnum(a.get('cx'), 0), fnum(a.get('cy'), 0))
        best = min(((dist_to(p, conn_points(c)), i, c) for i, c in enumerate(conns_by_svg.get(b['svg'], []))), default=None, key=lambda t: t[0])
        g = ''
        if best and best[0] <= 30 and not best[2].get('bound'):
            best[2]['bound'] = True
            gid = f'k{b["svg"]}-{k}'
            g = f' data-cxg="{gid}"'
            ed.append((best[2]['tag_end'] - (2 if h[best[2]['tag_end'] - 2] == '/' else 1), 0, f' data-cxg="{gid}" data-akr'))
            rep['bound'] += 1
        ed.append((b['a'], 0, f'<g class="nb" data-akr{g}>'))
        ed.append((b['end'], 2, '</g><!--akr-->'))

    # shortened texts the evidence file completes, and glyphs it names
    for e in S['ells']:
        seg = norm(e['text'])
        full = ev.clips.get(seg)
        if not full:
            for sub, where in ev.excerpts.items():   # a quoted EXCERPT (model output, a log line): say so, and where it is whole
                if sub in e['text']:
                    full = (_html.unescape(e['text'].strip()) + ' [The "…" marks where a quoted excerpt starts or ends — it is quoted '
                            'this way in ' + where + ', and the full text is in the record that file names.]')
                    break
        glyph = None
        if not full and seg == '…':
            for ctx, meaning in ev.glyphs.items():
                if ctx in h[max(0, e['a'] - 400):e['a']]:
                    glyph = meaning
                    break
        if not full and not glyph:
            if not any(x[0] == 'title' or 'title' in x[1] or 'tt' in (x[1].get('class') or '').split() for x in e['stack']):
                rep['cuts'].append({'clip': e['text'].strip(), 'sec': e['sec'], 'in_svg': e['in_svg'],
                                    'context': norm(h[max(0, e['a'] - 300):e['b'] + 200])[:600]})
            continue
        if e['in_svg'] and e['text_open']:
            ed.append((e['text_open'], 0, f'<title data-akr>{_html.escape(full or glyph, quote=False)}</title>'))
            if full:
                ed.append((e['b'], 3, '<tspan class="tt-i" dx="2" data-akr>ⓘ</tspan>'))
                rep['clips'] += 1
            else:
                rep['glyphs'] += 1
        elif full:
            ed.append((e['a'], 0, f'<span class="tt" title="{_html.escape(full, quote=True)}" data-akr>'))
            ed.append((e['b'], 3, '<span class="tt-i" aria-hidden="true">ⓘ</span></span>'))
            rep['clips'] += 1

    out, last = [], len(h)
    for off, _, txt in sorted(ed, key=lambda t: (t[0], t[1]), reverse=True):
        out.append(h[off:last])
        out.append(txt)
        last = off
    out.append(h[:last])
    return ''.join(reversed(out))


_LINES = {}


def ak_src(path, needle, after=None, exact=False):
    """for generators: ' data-ak-src="path:N"' for the first line of path containing needle ('' when absent) — put it on
    the <tr> rendered from that record, so the row cites the exact line it came from. after: start below the first line
    containing this marker (e.g. 'gitapps:'); exact: the line must equal needle once stripped of trailing whitespace"""
    path = str(path)
    if path not in _LINES:
        try:
            _LINES[path] = ak.lines_of(Path(path).read_text(errors='replace'))
        except OSError:
            _LINES[path] = []
    L = _LINES[path]
    start = 0
    if after:
        start = next((i + 1 for i, ln in enumerate(L) if after in ln), len(L))
    for i in range(start, len(L)):
        ln = L[i]
        if needle and ((ln.rstrip() == needle) if exact else (needle in ln)):
            return f' data-ak-src="{_html.escape(path, quote=True)}:{i + 1}"'
    return ''


class _LazyCfg:
    def __init__(self, mime):
        self.cfg = {'lazy': {'mime': mime, 'codec': 'gzip-b64'}}


def unkit_text(path):
    """a page's text with every artifact-kit retrofit addition removed (compressed lazy cards included) — what the page's
    own generator wrote. KAT suites and block checks that parse a page's markup read it through this."""
    h = Path(path).read_text(errors='replace')
    if 'data-akr' not in h and 'class="ct ' not in h:
        return h
    m = re.search(r'<script type="([^"]+)" class="lazyz"', h)
    return strip(h, _LazyCfg(m.group(1)) if m else None)


def reapply(path):
    """after a block tool rewrote part of a page in place: re-apply the kit if the page has an evidence file (a no-op
    otherwise). Returns the evidence name used, or None. Block writers call this so a page never stays half-kitted."""
    rp = os.path.realpath(os.path.expanduser(str(path)))
    for f in sorted(EVID.glob('*.json')):
        if f.name.startswith('_') or f.name.endswith('.rejected.json'):
            continue
        try:
            pg = json.loads(f.read_text()).get('page')
        except (OSError, ValueError):
            continue
        if pg and os.path.realpath(os.path.expanduser(pg)) == rp:
            h = Path(rp).read_text()
            new = apply_html(h, Evidence(f))
            if new != h:
                atomic_write(rp, new)
            return f.stem
    return None


def kit_sources(name):
    """the files a page that runs apply_html() renders THROUGH — register them in the generator's source set so a kit
    or evidence change makes its --check stale (living-architecture law)"""
    ev = EVID / f'{name}.json'
    cfg = json.loads(ev.read_text()) if ev.exists() else {}
    return [HERE / f for f in ('assetkit.py', 'connectorkit.py', 'textkit.py', 'retrofit.py')] + [ev] + [EVID / i for i in cfg.get('include', [])]


def kit_page(h, name, extra_sources=(), report=None):
    """the one call a generator makes as its last step: its page with the kit applied from evidence/<name>.json,
    searching the generator's own declared sources too"""
    return apply_html(h, Evidence(name, extra_sources), report)


def gates(h):
    a, t, c = ak.audit(h), tk.audit(h), ak.cite_audit(h)
    return {'G10': a, 'G11': t, 'G12': c, 'ok': a['ok'] and t['ok'] and c['ok']}


def atomic_write(p, text):
    p = Path(p)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix='.' + p.name + '.', suffix='.tmp')
    with os.fdopen(fd, 'w') as fh:
        fh.write(text)
    os.replace(tmp, p)


def _summ(rep, g, n):
    by = g['G12']['by_class']
    return (f"cells {rep['cells_cited']}/{rep['cells']} cited · boxes {rep['boxes_cited']}/{rep['boxes']} · badges {rep['badges']} "
            f"({rep['bound']} bound to an arrow) · section-level {rep.get('cells_sec', 0)} cells · clips {rep['clips']} · glyphs {rep['glyphs']} · matcher {rep['matcher']} · "
            f"dropped researched {rep['researched_dropped']} · G10 {'ok' if g['G10']['ok'] else 'FAIL'} G11 {'ok' if g['G11']['ok'] else 'FAIL (' + str(g['G11']['cut_without_tooltip']) + ')'} "
            f"G12 {'ok' if g['G12']['ok'] else 'FAIL'} {by} · {n:,} B")


def clip_ok(seg, full):
    """a completion is accepted only when every visible fragment of the shortened text occurs in it, in order"""
    f, at = norm(full), 0
    for frag in [norm(x) for x in re.split(r'…|\.\.\.', seg) if norm(x)]:
        j = f.find(frag, at)
        if j < 0:
            return False
        at = j + len(frag)
    return len(f) > len(norm(seg).replace('…', ''))


def merge(ev, globs):
    """fold research results into the evidence file — only what re-verifies deterministically:
    file citation → the quote sits within ±3 lines of the cited line; URL → urlcheck re-downloads it and re-finds the
    quote; completion of a cut text → every visible fragment occurs in it, in order. Rejects go to <name>.rejected.json."""
    import glob as _g
    import urlcheck
    rows = []
    for g in globs:
        for f in sorted(_g.glob(os.path.expanduser(g))):
            d = json.loads(Path(f).read_text())
            rows += d if isinstance(d, list) else d.get('results', [])
    cfg = json.loads(ev.path.read_text())
    cites, clips, rej = cfg.setdefault('cites', {}), cfg.setdefault('clips', {}), []
    ucache = EVID / '.urlcache'
    ucache.mkdir(exist_ok=True)
    acc = {'cites': 0, 'assets': 0, 'clips': 0}
    for r in rows:
        if r.get('clip') is not None:
            if r.get('full') and clip_ok(r['clip'], r['full']):
                clips[r['clip']] = r['full']
                acc['clips'] += 1
            elif r.get('full'):
                rej.append({'clip': r['clip'], 'full': r['full'], 'why': 'a visible fragment is missing from the completion'})
            continue
        good = []
        for x in r.get('cites') or []:
            if x.get('u'):
                ok, why, _ = urlcheck.check(x['u'], x.get('q', ''), ucache)
                if ok:
                    good.append({k: x[k] for k in ('u', 'q', 't', 'n', 'c', 'x') if x.get(k)} | {'verified': True})
                else:
                    rej.append({'key': r.get('key'), 'cite': x, 'why': why})
            else:
                x = {k: x[k] for k in ('p', 'l', 'q', 'c') if x.get(k) is not None}
                x['p'] = os.path.expanduser(str(x.get('p', '')))
                if ev.verify(x) and x.get('q'):
                    if x.get('c') and x['c'] not in ak.CLASSES:
                        x.pop('c')
                    good.append(x)
                else:
                    rej.append({'key': r.get('key'), 'cite': x, 'why': 'quote not found within ±3 lines of the cited line' if x.get('q') else 'no quote'})
        if good and r.get('key'):
            old = cites.get(r['key'], [])
            cites[r['key']] = (old + [x for x in good if x not in old])[:MAX_CITES + 2]
            acc['cites'] += len(good)
            acc['assets'] += 1
        elif r.get('key') and r.get('none'):
            rej.append({'key': r['key'], 'why': 'researcher found no evidence', 'note': r['none']})
    atomic_write(ev.path, json.dumps(cfg, indent=1, ensure_ascii=False) + '\n')
    rp = ev.path.with_suffix('.rejected.json')
    old = json.loads(rp.read_text()) if rp.exists() else []
    rp.write_text(json.dumps(old + rej, indent=1, ensure_ascii=False))
    print(f'[retrofit] merge {ev.name}: {len(rows)} results → accepted {acc} · rejected {len(rej)} (→ {rp.name})')
    return 0


def _line_map(old, new):
    import difflib
    m = {}
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=old, b=new, autojunk=False).get_opcodes():
        if tag == 'equal':
            for k in range(i2 - i1):
                m[i1 + k + 1] = j1 + k + 1
    return m


def reanchor(ev, maps=None):
    """a cited FILE was edited and its lines moved (2026-10-20: two cdos.py cites went UNK after the file grew): for every
    citation {p, l, q} whose line l no longer holds q, move l to the ONE line that now holds q. A quote on no line or on
    several lines is reported and left as it is (prune / research decide) — never guessed. Prints every move."""
    norm = lambda x: re.sub(r'\s+', ' ', str(x or '')).strip()
    cfg = json.loads(ev.path.read_text())
    moved, lost, multi, cache = [], [], [], {}
    for key, cites in (cfg.get('cites') or {}).items():
        for c in cites if isinstance(cites, list) else []:
            if not (isinstance(c, dict) and c.get('p') and c.get('q') and isinstance(c.get('l'), int)) or c.get('a'):
                continue        # an anchored cite (a daily-rewritten file) is resolved by its anchor in verify(), not here
            if c['p'] not in cache:
                try:
                    cache[c['p']] = Path(c['p']).read_text(errors='replace').split('\n')
                except OSError:
                    cache[c['p']] = None
            L = cache[c['p']]
            if L is None:
                continue
            q = norm(c['q'])
            if 1 <= c['l'] <= len(L) and q in norm(L[c['l'] - 1]):
                continue
            hits = [i for i, line in enumerate(L, 1) if q in norm(line)]
            if len(hits) > 1 and c['p'] in (maps or {}):
                # several lines hold the quote: map the OLD line through a line diff of the pre-edit copy (--map
                # PATH=OLD_COPY) and take it only when the mapped line holds the quote
                key_m = ('map', c['p'])
                if key_m not in cache:
                    cache[key_m] = _line_map(Path(maps[c['p']]).read_text(errors='replace').split('\n'), L)
                t = cache[key_m].get(c['l'])
                near = [h for h in hits if t and abs(h - t) <= 3]      # the verifier's own ±3-line tolerance
                hits = near if len(near) == 1 else hits
            if len(hits) == 1:
                moved.append((key, c['p'], c['l'], hits[0]))
                c['l'] = hits[0]
            elif not hits:
                lost.append((key, c['p'], c['l']))
            else:
                multi.append((key, c['p'], c['l'], len(hits)))
    if moved:
        atomic_write(ev.path, json.dumps(cfg, indent=1, ensure_ascii=False) + '\n')
    for k, f, a, b in moved:
        print(f'  moved {Path(f).name}:{a} -> :{b}  ({k[:70]})')
    for k, f, a in lost:
        print(f'  LOST  {Path(f).name}:{a} — the quote is on no line now ({k[:70]})')
    for k, f, a, n in multi:
        print(f'  MULTI {Path(f).name}:{a} — the quote is on {n} lines; left as is ({k[:70]})')
    print(f'[retrofit] reanchor {ev.name}: {len(moved)} moved · {len(lost)} lost · {len(multi)} ambiguous')
    return 3 if lost else 0


def rekey(ev, h):
    """after a page edit changed an asset's text, move its researched citations to the asset's new key — only when exactly
    one unused old key matches the new one at ≥ 90 % (difflib) AND both carry the same numbers (a corrected number is a
    corrected fact — its old evidence proves the old value).
    Prints every move; anything ambiguous stays unresolved for research."""
    import difflib
    cand = {}
    apply_html(h, Evidence(ev.path), {}, want_cand=cand)
    cfg = json.loads(ev.path.read_text())
    live = set()
    S = scan(strip(h))
    for T in S['tables']:
        for row in T['rows']:
            live.add('r:' + ' | '.join(norm(c['text']) for c in row)[:200])
            live |= {'c:' + norm(c['text'])[:200] for c in row}
    live |= {b['key'] for b in S['boxes']}
    unused = [k for k in cfg.get('cites', {}) if k not in live]
    moves = []
    for nk in cand:
        sc = sorted(((difflib.SequenceMatcher(None, nk, ok).ratio(), ok) for ok in unused if ok[:2] == nk[:2]), reverse=True)
        nums = lambda k: sorted(re.findall(r'\d+(?:\.\d+)?', k))
        live = lambda k: bool(cfg['cites'].get(k)) and all('computes the count live' in (c.get('n') or '') for c in cfg['cites'][k])
        # 2026-10-17: a LIVE-COUNT row (every citation proves the measurement — the generator line that computes it, or the
        # measured file itself) may carry its citations across a changed number; any other changed number still needs research
        if sc and sc[0][0] >= 0.9 and (len(sc) == 1 or sc[1][0] < sc[0][0] - 0.03) and (nums(sc[0][1]) == nums(nk) or live(sc[0][1])):
            # a changed NUMBER is a changed fact: its old evidence proves the old value — never carry it over
            moves.append((sc[0][1], nk, round(sc[0][0], 3)))
            unused.remove(sc[0][1])
    for ok, nk, r in moves:
        cfg['cites'][nk] = cfg['cites'].pop(ok)
        print(f'  moved ({r}): {ok[:90]!r}\n        → {nk[:90]!r}')
    atomic_write(ev.path, json.dumps(cfg, indent=1, ensure_ascii=False) + '\n')
    print(f'[retrofit] rekey {ev.name}: {len(moves)} moved, {len(cand) - len(moves)} still without a citation, {len(unused)} researched keys unused')
    return 0


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd, name = argv[0], argv[1]
    ev = Evidence(name)
    page = Path(os.path.realpath(ev.page))
    h = page.read_text()
    if cmd == 'strip':
        out = strip(h, ev)
        dst = argv[argv.index('--out') + 1] if '--out' in argv else None
        (Path(dst).write_text(out) if dst else sys.stdout.write(out))
        return 0
    rep = {}
    new = apply_html(h, ev, rep)
    g = gates(new)
    if cmd == 'apply':
        if new != h:
            atomic_write(page, new)
        if ev.stats.get('relocated'):           # write the followed line numbers back, so the evidence file stays exact
            cfg = json.loads(ev.path.read_text())
            cfg['cites'] = {k: v for k, v in ev.researched.items()} | {k: v for k, v in cfg.get('cites', {}).items() if k not in ev.researched}
            atomic_write(ev.path, json.dumps(cfg, indent=1, ensure_ascii=False) + '\n')
        print(f'[retrofit] {ev.name}: {"written" if new != h else "unchanged"} · ' + _summ(rep, g, len(new.encode())))
        return 0
    if cmd == 'check':
        same = new == h
        print(f'[retrofit] {ev.name}: page {"current" if same else "STALE — run: retrofit.py apply " + ev.name} · ' + _summ(rep, g, len(new.encode())))
        return 0 if same and g['ok'] else 3
    if cmd == 'residue':
        cand = {}
        apply_html(h, ev, {}, want_cand=cand)
        out = {'name': ev.name, 'page': str(page), 'assets': list(cand.values()), 'cuts': rep['cuts']}
        dst = argv[argv.index('--out') + 1] if '--out' in argv else None
        js = json.dumps(out, indent=1, ensure_ascii=False)
        (Path(dst).write_text(js) if dst else print(js))
        print(f'[retrofit] {ev.name}: {len(out["assets"])} distinct assets without a citation, {len(rep["cuts"])} cut texts without their sentence', file=sys.stderr)
        return 0
    if cmd == 'merge':
        return merge(ev, argv[2:])
    if cmd == 'rekey':
        return rekey(ev, h)
    if cmd == 'reanchor':
        maps = dict(a.split('=', 1) for a in argv[argv.index('--map') + 1:] if '=' in a) if '--map' in argv else {}
        return reanchor(ev, maps)
    if cmd == 'prune':
        # researched citations that no longer verify (their file changed under them) leave the evidence file — into
        # <name>.rejected.json with the reason and the date, never silently
        cfg = json.loads(ev.path.read_text())
        gone = [(k, x) for k, x in ev.dropped]
        if gone:
            import datetime
            for k, x in gone:
                cfg['cites'][k] = [y for y in cfg['cites'].get(k, []) if y != x]
                if not cfg['cites'][k]:
                    cfg['cites'].pop(k)
            atomic_write(ev.path, json.dumps(cfg, indent=1, ensure_ascii=False) + '\n')
            rp = ev.path.with_suffix('.rejected.json')
            old = json.loads(rp.read_text()) if rp.exists() else []
            day = datetime.date.today().isoformat()
            rp.write_text(json.dumps(old + [{'key': k, 'cite': x, 'why': f'no longer verifies ({day}): its quote left the cited file'} for k, x in gone],
                                     indent=1, ensure_ascii=False))
        print(f'[retrofit] prune {ev.name}: {len(gone)} citation(s) that no longer verify moved to {ev.path.stem}.rejected.json')
        return 0
    if cmd == 'stats':
        print(_summ(rep, g, len(new.encode())))
        print(json.dumps({k: g[k] for k in ('G10', 'G11')}, ensure_ascii=False)[:2000])
        return 0
    print(__doc__)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
