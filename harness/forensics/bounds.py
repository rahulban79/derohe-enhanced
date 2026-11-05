#!/usr/bin/env python3
"""R26 gates G31 (bound honesty) and G32 (class separation and presence) (rft §0.8.9 rules 8-12; B108, B109), and the
page contract the forensics frontend renders the class figures with.

  python3 -I harness/forensics/bounds.py --g31 | --g32 [--root .]
  python3 -I harness/forensics/bounds.py --page artifacts/dero-r1-r26.html     # check one page's class block

Dataset: the newest forensics/r<N>/ that holds derived/classes.json (N >= 26).

Page contract (frontend2 renders it; coherence check `classes` reads it):
  a block <!--classes:begin--> ... <!--classes:end--> on the ledger's forensics sections, the soundness page and the
  src-arch section 10 line; every class figure inside it is
    <span class="fcl" data-fc="ID" data-cls="DC1" data-bound="lower-bound" data-cov="0/75" data-scope="7415466-7497942">TEXT</span>
  with TEXT = shown(figure): an integer as 1,234 (a lower bound prefixed '≥ ', an upper bound '≤ '), `unbounded` for an
  unbounded figure (never 0, never empty), a string value as is. Any other number left in the block FAILS (untraced),
  and the headline <p data-fc-headline="dc2-present">…</p> must be on each of the three pages while DC2 is present.
  r26 (forensics-frontend2): a dataset fact span <span class="fxn" data-fx=…> (harness/forensics/facts.py) inside the
  block is not a class figure; it is skipped here and traced by G30 (facts.g30 checks every fxn span on the three pages
  and runs check_page below on each class block), so every number of the block is checked by exactly one of the two.

G31: every figure has {class, scope, coverage num/den + anchors, bound_type}; `exact` needs num == den and is never DC2;
an `unbounded` figure's value is the word unbounded; a non-exact figure is never called a total; no figure has more
than one class or sums figures of another class; a class grade differs from the historical grade only with dataset
evidence, never because of a fix status; the forbidden phrases appear only negated and never next to a figure;
the class block of each page traces to classes.json; no amount-recovery method text (G24 patterns + METHOD_PATTERNS).
G32: every tagged record and figure has exactly one class in DC0..DC3; the record counts equal the dataset's; every class
with a code path (DC1..DC3) has a presence entry at HEAD whose anchors re-read now; the headline is on the three pages
while DC2 is present (enforced once the ledger page of the dataset's round exists).
"""
import argparse, html, importlib.util, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
BEGIN, END = '<!--classes:begin-->', '<!--classes:end-->'
CLASS_IDS = ('DC0', 'DC1', 'DC2', 'DC3')
BOUND_TYPES = ('exact', 'lower-bound', 'upper-bound', 'unbounded')
FORBIDDEN = ('supply audit', 'audited supply', 'total inflation', 'true supply')
NEGATION = re.compile(r"\b(no|not|never|cannot|can't|impossible|forbidden|without)\b", re.I)
FIX_WORDS = re.compile(r'\b(implemented|fixed|fixed-node-local|closed-by-design|patched|mitigated)\b', re.I)
TOTAL_RX = re.compile(r'\b(total|in total|altogether|overall sum)\b', re.I)
SPAN = re.compile(r'<span class="fcl" data-fc="([^"]+)" data-cls="([^"]*)" data-bound="([^"]*)" data-cov="([^"]*)" '
                  r'data-scope="([^"]*)">(.*?)</span>', re.S)
HEADLINE = re.compile(r'<(\w+)[^>]*\bdata-fc-headline="dc2-present"[^>]*>(.*?)</\1>', re.S)
IDENT = re.compile(r'(?:\bDC\d\b(?:-\w+)?|\bFQ\d\b|\bQ-CS\d\b|\bFX-[NF]\d+\b|\bNF\d+-\d+\b|\bS-R22\b|\bP1\b|\bR\d+[a-z]?\b|\bG\d+\b|'
                   r'\bB\d+\b|\bC\d\b|§[\d.]+|\b[\w./-]+\.(?:json|html|go|py|gz|md)\b(?::\d+(?:[-,]\d+)*)?|SHA3?-256|'
                   r'\b[0-9a-f]{12,64}\b|\bHF3\b|\bRelease\d+\b|\bv\d\b|ElGamal|'
                   r'\bD2-\d+\b|\bV2?-[A-Z][A-Z0-9-]*\b|\bE[12]\b)')   # r26: audit-2 challenge / verdict ids, evidence grades
# amount-recovery METHOD text (rft §0.8.9 rule 13, G24): procedural wording only; the defensive vocabulary stays allowed
METHOD_PATTERNS = [
    ('amount recovery procedure', re.compile(r'\b(how\s+to|steps?\s+to|in\s+order\s+to|we\s+can|one\s+can|you\s+can)\s+'
                                             r'(recover|decrypt|brute[- ]?force|reveal|derive|compute|read)\s+(the\s+|an?\s+)?'
                                             r'(hidden\s+|encrypted\s+)?(amounts?|balances?|values?)\b', re.I)),
    ('discrete-log search', re.compile(r'\b(brute[- ]?forc\w*|baby[- ]?step|giant[- ]?step|discrete[- ]log\s+(search|table))\b', re.I)),
    ('commitment difference recipe', re.compile(r'\b(subtract\w*|differenc\w*)\s+(the\s+|two\s+)?(commitments?|C\[?i?\]?)\b[^.]{0,60}\b(amount|value|b)\b', re.I)),
]


def _load(rel, tag, root=ROOT):
    p = Path(root) / rel
    sp = importlib.util.spec_from_file_location(f'{tag}_{id(root)}_{len(sys.modules)}', p)
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


def classes_dataset(root=ROOT):
    """the newest forensics/r<N>/ (N >= 26) holding derived/classes.json, or None"""
    ds = []
    for d in (Path(root) / 'forensics').glob('r*'):
        m = re.fullmatch(r'r(\d+)', d.name)
        if m and int(m.group(1)) >= 26 and (d / 'derived' / 'classes.json').exists():
            ds.append((int(m.group(1)), d))
    return max(ds)[1] if ds else None


def shown(f):
    v, b = f['value'], f['bound_type']
    if b == 'unbounded':
        return v if isinstance(v, str) and v.startswith('pending') else 'unbounded'
    if isinstance(v, bool):
        return 'yes' if v else 'no'
    if isinstance(v, int):
        return {'lower-bound': '≥ ', 'upper-bound': '≤ '}.get(b, '') + f'{v:,}'
    return str(v)


def cov(f):
    c = f['coverage']
    return f"{c['num']}/{c['den']}"


def scope(f):
    h = f['scope']['heights']
    return f'{h[0]}-{h[1]}' if isinstance(h, list) else str(h)


# ───────────────────────────── G31 dataset half ─────────────────────────────
def check_figures(cl):
    p = []
    ids = set()
    figs = cl.get('figures') or []
    if not figs:
        p.append('no figures in classes.json')
    byid = {f.get('id'): f for f in figs}
    for f in figs:
        fid = f.get('id', '?')
        if fid in ids:
            p.append(f'{fid}: duplicate figure id')
        ids.add(fid)
        c = f.get('class')
        if not isinstance(c, str) or c not in CLASS_IDS:
            p.append(f'{fid}: class must be exactly one of {CLASS_IDS}, found {c!r}')
        sc = f.get('scope')
        if not isinstance(sc, dict) or 'heights' not in sc or not sc.get('text'):
            p.append(f'{fid}: no scope {{heights, text}}')
        cv = f.get('coverage')
        if not isinstance(cv, dict) or not all(k in cv for k in ('num', 'den', 'num_anchor', 'den_anchor')):
            p.append(f'{fid}: coverage needs num, den, num_anchor, den_anchor')
            cv = {}
        b = f.get('bound_type')
        if b not in BOUND_TYPES:
            p.append(f'{fid}: bound_type {b!r} not in {BOUND_TYPES}')
        v = f.get('value')
        if b == 'exact':
            if not (isinstance(cv.get('num'), int) and isinstance(cv.get('den'), int) and cv['num'] == cv['den']):
                p.append(f'{fid}: exact needs coverage num == den (found {cv.get("num")}/{cv.get("den")})')
            if isinstance(v, str) and v.startswith(('pending', 'missing')):
                p.append(f'{fid}: exact with a pending value')
        if c == 'DC2' and b != 'unbounded':   # also: never exact, never a number such as 0, while DC2 is open
            p.append(f'{fid}: a DC2 aggregate must be unbounded (rule 9), found {b}')
        if b == 'unbounded' and v != 'unbounded' and not (isinstance(v, str) and v.startswith('pending')):
            p.append(f'{fid}: an unbounded figure renders as {v!r} (must be the word unbounded, never 0)')
        if v is None or v == '':
            p.append(f'{fid}: empty value (an unknown is pending, never empty)')
        text = ' '.join(str(f.get(k, '')) for k in ('label', 'note'))
        if b != 'exact' and TOTAL_RX.search(str(f.get('label', ''))):
            p.append(f'{fid}: a {b} figure is labelled as a total')
        for ph in FORBIDDEN:
            if ph in text.lower():
                p.append(f'{fid}: forbidden phrase "{ph}" on a figure (bound {b}; no figure is exact over genesis .. now)')
        so = f.get('sum_of')
        if so is not None:
            other = {byid[x]['class'] for x in so if x in byid}
            if other - {c} or len([x for x in so if x not in byid]):
                p.append(f'{fid}: sums figures across classes or unknown figures {so}')
    return p


def check_grades(cl, base_grades=None):
    """rule 10: a class grade moves only with dataset evidence, never because of a fix status"""
    p = []
    hist = (base_grades or {}).get('counts', {})
    hist_nd = hist and all(k.startswith('NOT-DECIDABLE') for k in hist)
    for cid, c in (cl.get('classes') or {}).items():
        g = str(c.get('grade', ''))
        rg = c.get('regrade')
        if rg is not None:
            ev = [e for e in rg.get('evidence', []) if re.match(r'(derived|raw)/', str(e))]
            if not ev:
                p.append(f'{cid}: ' + ('a fix status changes a historical grade' if FIX_WORDS.search(str(rg.get('reason', '')))
                                       else 'regrade without a dataset file as evidence'))
        if cid == 'DC1' and hist_nd and not g.startswith('NOT-DECIDABLE') and not (rg and rg.get('evidence')):
            p.append(f'DC1: grade {g[:40]!r} differs from the historical per-tx grades {sorted(hist)} without dataset evidence')
        if FIX_WORDS.search(g) and 'PROVEN' in g:
            p.append(f'{cid}: a PROVEN grade justified by a fix status ({g[:60]})')
    return p


_PATS = {}


def method_lint(text, root=ROOT):
    """G24 exploit patterns (read from the disclosure track tool) + the amount-recovery METHOD patterns; fails closed
    when the G24 patterns cannot be read (a lint that cannot look must not pass)"""
    hits = []
    key = str(Path(root).resolve())
    if key not in _PATS:
        try:
            A = _load('harness/forensics/audit_check.py', 'audit_for_bounds', root)
            _PATS[key] = list(A.exploit_patterns(Path(root)))
        except Exception as e:                                       # noqa: BLE001
            _PATS[key] = e
    pats = _PATS[key]
    if isinstance(pats, Exception) or not pats:
        return [f'the G24 exploit patterns could not be read ({type(pats).__name__ if isinstance(pats, Exception) else "empty"})']
    pats = list(pats)
    for n, rx in list(pats) + METHOD_PATTERNS:
        if rx.search(text):
            hits.append(n)
    return hits


def json_texts(o, path=''):
    if isinstance(o, dict):
        for k, v in o.items():
            if k in ('quote', 'forbidden_phrases'):   # code quotes; the rule's own list of the phrases
                continue
            yield from json_texts(v, f'{path}.{k}')
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from json_texts(v, f'{path}[{i}]')
    elif isinstance(o, str):
        yield path, o


def check_phrases_json(docs):
    """forbidden phrases in the four files: only negated, never next to a figure"""
    p = []
    for name, d in docs.items():
        for where, s in json_texts(d):
            low = s.lower()
            for ph in FORBIDDEN:
                if ph in low:
                    for sent in re.split(r'(?<=[.;:])\s+', s):
                        if ph in sent.lower() and not NEGATION.search(sent):
                            p.append(f'{name}{where}: "{ph}" un-negated')
    return p


# ───────────────────────────── pages ─────────────────────────────
FXN = re.compile(r'<span class="fxn" data-fx="[^"]+" data-src="[^"]*" data-sha="(?:[0-9a-f]*|missing|unlisted)">(.*?)</span>', re.S)


def _visible(seg):
    seg = re.sub(r'<script\b.*?</script>', ' ', seg, flags=re.S)
    seg = re.sub(r'<style\b.*?</style>', ' ', seg, flags=re.S)
    seg = SPAN.sub(' ', seg)
    seg = FXN.sub(' ', seg)   # r26: a dataset fact span: G30 traces it (module doc)
    seg = re.sub(r'<[^>]+>', ' ', seg)
    return html.unescape(seg)


BLOCK_OPEN = re.compile(r'<(?:p|li|td|th|dd|dt|h[1-6]|figcaption|caption)\b[^>]*>', re.I)
BLOCK_CLOSE = re.compile(r'</(?:p|li|td|th|dd|dt|h[1-6]|figcaption|caption)>', re.I)


def _element(seg, a, b):
    """the text of the block element (p, li, td, heading, caption) that holds seg[a:b]"""
    opens = [m.end() for m in BLOCK_OPEN.finditer(seg, 0, a)]
    start = opens[-1] if opens else max(0, a - 200)
    m = BLOCK_CLOSE.search(seg, b)
    return seg[start:m.start() if m else min(len(seg), b + 200)]


def check_page(text, cl, need=True, root=ROOT):
    """[problems], spans: the class block traces to classes.json"""
    p = []
    if BEGIN not in text or END not in text:
        return ([f'no {BEGIN} … {END} block'] if need else []), 0
    seg = text[text.index(BEGIN):text.index(END)]
    byid = {f['id']: f for f in cl.get('figures', [])}
    n = 0
    for m in SPAN.finditer(seg):
        fid, cls, bnd, cv, sc, txt = m.groups()
        n += 1
        f = byid.get(fid)
        if f is None:
            p.append(f'span {fid}: no such figure')
            continue
        if cls != f['class'] or bnd != f['bound_type'] or cv != cov(f) or sc != scope(f):
            p.append(f'span {fid}: attributes {cls}/{bnd}/{cv}/{sc} differ from classes.json {f["class"]}/{f["bound_type"]}/{cov(f)}/{scope(f)}')
        t = html.unescape(re.sub(r'<[^>]+>', '', txt)).strip()
        if t != shown(f):                     # an unbounded figure shows the word, so a 0 or an empty cell fails here
            p.append(f'span {fid}: shows {t!r}, classes.json says {shown(f)!r}')
        ctx = _visible(seg[max(0, m.start() - 120):m.start()])[-60:]
        if f['bound_type'] != 'exact' and TOTAL_RX.search(ctx):
            p.append(f'span {fid}: a {f["bound_type"]} figure introduced as a total ("{ctx.strip()[-40:]}")')
    vis = _visible(seg)
    # the phrase scan reads the TEXT of every span (class figures and dataset facts alike)
    blocks = _visible(BLOCK_CLOSE.sub(' \u00b6 ', FXN.sub(lambda m: ' ' + m.group(1) + ' ', SPAN.sub(lambda m: ' ' + m.group(6) + ' ', seg))))
    for sent in re.split(r'(?<=[.;!?])\s+|\s*\u00b6\s*', blocks):
        low = sent.lower()
        for ph in FORBIDDEN:
            if ph in low and not NEGATION.search(sent):
                p.append(f'forbidden phrase "{ph}" in: {sent.strip()[:80]}')
    for m in SPAN.finditer(seg):
        whole = _element(seg, m.start(), m.end())
        for ph in FORBIDDEN:
            if ph in _visible(FXN.sub(lambda m: ' ' + m.group(1) + ' ', whole)).lower():
                p.append(f'span {m.group(1)}: forbidden phrase "{ph}" next to a figure')
    left = IDENT.sub(' ', vis)
    for mm in re.finditer(r'\d[\d,.]*', left):
        p.append(f'untraced number {mm.group(0)!r} in the class block: …{left[max(0, mm.start() - 30):mm.end() + 15].strip()}…')
        if len(p) > 40:
            break
    for h in method_lint(vis, root):
        p.append(f'amount-recovery method text in the class block: {h}')
    return p, n


def headline_ok(text):
    m = HEADLINE.search(text)
    if not m:
        return False
    t = _visible(FXN.sub(lambda x: ' ' + x.group(1) + ' ', m.group(2)))   # r26: the headline may be a dataset fact span
    return 'DC2' in t and re.search(r'\bpresent\b', t, re.I) is not None


def pages(root, ds):
    """(ledger page of the dataset's round, soundness page of the current round, src-arch)"""
    root = Path(root)
    led = root / 'artifacts' / f'dero-r1-{ds.name}.html'
    try:
        sp = _load('harness/kit/soundpage.py', 'soundpage_for_bounds', root)
        snd = root / sp.rel(root)
    except Exception:                                                # noqa: BLE001
        snd = root / 'artifacts' / f'dero-soundness-{ds.name}.html'
    return led, snd, root / 'artifacts' / 'dero-src-arch.html'


def _docs(ds):
    out = {}
    for n in ('classes', 'presence', 'invariant', 'fq'):
        p = ds / 'derived' / f'{n}.json'
        out[n] = json.loads(p.read_text()) if p.exists() else None
    return out


def g31(root=ROOT, inv_check=None):
    root = Path(root)
    ds = classes_dataset(root)
    if ds is None:
        return False, 'no forensics/r<N>/derived/classes.json (N >= 26)'
    D = _docs(ds)
    cl = D['classes']
    base = root / 'forensics' / cl.get('base', 'r25') / 'derived' / 'grades.json'
    fails = check_figures(cl)
    fails += check_grades(cl, json.loads(base.read_text()) if base.exists() else None)
    fails += check_phrases_json({k: v for k, v in D.items() if v is not None})
    for k, v in D.items():
        if v is None and k != 'classes':
            fails.append(f'derived/{k}.json missing')
            continue
        for where, s in json_texts(v or {}):
            for h in method_lint(s, root):
                fails.append(f'derived/{k}.json{where}: amount-recovery/exploit text ({h})')
    inv = D['invariant'] or {}
    for q in ('Q-CS2', 'Q-CS3'):
        a = (inv.get(q) or {}).get('answer', 'pending')
        if a != 'pending' and not all(x.get('ok') for x in (inv.get('Q-CS2') or {}).get('anchors', [])):
            fails.append(f'invariant.json {q}: answered but an anchor did not re-read')
    q1 = inv.get('Q-CS1') or {}
    if str(q1.get('status', 'pending')).startswith('answered') and not (q1.get('root_check') or {}).get('equal'):
        fails.append('invariant.json Q-CS1: answered without an equal root check')
    try:
        if inv_check is None:
            inv_check = _load('harness/forensics/invariant.py', 'invariant_for_g31', root).check
        fails += [f'invariant re-read: {x}' for x in inv_check(ds / 'derived' / 'invariant.json', root)]
    except Exception as e:                                           # noqa: BLE001 — a gate that cannot look fails
        fails.append(f'invariant re-read could not run: {type(e).__name__}: {e}')
    npages, nspans = 0, 0
    for pg in pages(root, ds):
        if pg.exists():
            t = pg.read_text()
            if BEGIN in t:
                pf, n = check_page(t, cl, root=root)
                fails += [f'{pg.name}: {x}' for x in pf]
                npages += 1
                nspans += n
    if fails:
        return False, f'{ds.name}: {len(fails)} failure(s): ' + '; '.join(fails[:5])
    return True, (f'{ds.name}: {len(cl["figures"])} figures bounded (' +
                  ', '.join(f'{b} {sum(f["bound_type"] == b for f in cl["figures"])}' for b in BOUND_TYPES) +
                  f'); 0 forbidden phrases; {nspans} class spans on {npages} page(s) trace to classes.json')


def check_records(ds, cl):
    """every v2 record carries one class; counts equal classes.json"""
    p = []
    import gzip, collections
    seen = collections.Counter()
    n_tagged = 0
    for kind in ('tx', 'block'):
        d = ds / 'derived' / kind
        for f in sorted(d.glob('*.json')) if d.is_dir() else []:
            r = json.loads(f.read_text())
            c = r.get('defect_class')
            n_tagged += 1
            if c not in CLASS_IDS:
                p.append(f'derived/{kind}/{f.name}: defect_class {c!r}')
            else:
                seen[(kind, c)] += 1
    w = ds / 'derived' / 'window.jsonl.gz'
    if w.exists():
        for i, l in enumerate(gzip.decompress(w.read_bytes()).decode().splitlines(), 1):
            if l.strip():
                c = json.loads(l).get('defect_class')
                n_tagged += 1
                if c not in CLASS_IDS:
                    p.append(f'derived/window.jsonl.gz:{i}: defect_class {c!r}')
                    break
                seen[('window_rows', c)] += 1
    if n_tagged:
        for kind, m in (cl.get('records') or {}).items():
            for c, n in m.items():
                if seen[(kind, c)] != n:
                    p.append(f'records.{kind}.{c} = {n} but the dataset has {seen[(kind, c)]}')
    for kind, m in (cl.get('records') or {}).items():
        for c in m:
            if c not in CLASS_IDS:
                p.append(f'records.{kind}: unknown class {c}')
    return p, n_tagged


def g32(root=ROOT, pres_check=None):
    root = Path(root)
    ds = classes_dataset(root)
    if ds is None:
        return False, 'no forensics/r<N>/derived/classes.json (N >= 26)'
    D = _docs(ds)
    cl, pr = D['classes'], D['presence']
    fails = []
    for f in cl.get('figures', []):
        if f.get('class') not in CLASS_IDS:
            fails.append(f'figure {f.get("id")}: no class')
    for cid in CLASS_IDS:
        if cid not in (cl.get('classes') or {}):
            fails.append(f'classes.json has no {cid} entry')
    rp, ntag = check_records(ds, cl)
    fails += rp
    if pr is None:
        fails.append('derived/presence.json missing')
    else:
        for cid in ('DC1', 'DC2', 'DC3'):
            row = (pr.get('classes') or {}).get(cid, {}).get('HEAD')
            if not row or not row.get('anchors'):
                fails.append(f'presence: {cid} has no HEAD entry')
        try:
            if pres_check is None:
                pres_check = _load('harness/forensics/presence.py', 'presence_for_g32', root).check
            fails += [f'presence re-read: {x}' for x in pres_check(ds / 'derived' / 'presence.json', root)]
        except Exception as e:                                       # noqa: BLE001 — a gate that cannot look fails
            fails.append(f'presence re-read could not run: {type(e).__name__}: {e}')
        if cl.get('headline', {}).get('dc2_present_now') != pr.get('headline', {}).get('dc2_present_now'):
            fails.append('classes.json headline differs from presence.json')
    present = (pr or {}).get('headline', {}).get('dc2_present_now') is True
    led, snd, sa = pages(root, ds)
    page_note = ''
    if present and led.exists():
        for pg in (led, snd, sa):
            if not pg.exists() or not headline_ok(pg.read_text()):
                fails.append(f'{pg.name}: the DC2-present headline is missing (rule 12)')
        page_note = '; headline on the 3 pages'
    elif present:
        page_note = f'; pages: pending ({led.name} not rendered yet: the headline is enforced from its first render)'
    if fails:
        return False, f'{ds.name}: {len(fails)} failure(s): ' + '; '.join(fails[:5])
    return True, (f'{ds.name}: {len(cl["figures"])} figures and {ntag} tagged records carry one class; presence DC1-DC3 at '
                  f'{len(pr["revs"])} revs re-read unchanged; DC2 present {present}{page_note}')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--root', default=str(ROOT))
    ap.add_argument('--g31', action='store_true')
    ap.add_argument('--g32', action='store_true')
    ap.add_argument('--page')
    a = ap.parse_args(argv)
    rc = 0
    if a.page:
        ds = classes_dataset(a.root)
        cl = json.loads((ds / 'derived' / 'classes.json').read_text())
        pf, n = check_page(Path(a.page).read_text(), cl)
        print(f'{a.page}: {n} spans; ' + ('PASS' if not pf else 'FAIL\n  ' + '\n  '.join(pf[:20])))
        rc = 9 if pf else 0
    for flag, fn, name in ((a.g31, g31, 'G31'), (a.g32, g32, 'G32')):
        if flag:
            ok, det = fn(a.root)
            print(f'{"PASS" if ok else "FAIL"}  {name}: {det}')
            rc = rc or (0 if ok else 9)
    return rc


if __name__ == '__main__':
    sys.exit(main())
