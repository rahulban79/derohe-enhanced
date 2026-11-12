#!/usr/bin/env python3
"""soundness.py — R23b gate G22: every code-behaviour claim on the soundness review page is backed.

The page (artifacts/dero-soundness-<current round>.html, named by harness/kit/soundpage.py from harness/round.json;
r25: one page per round, earlier pages stay as history) makes claims about what the node's code does (the HF3 proof skip is
height-bound, the nonce bypass is pinned, the already-mined guard, the 11-block validity window, the TXID scope, the
CalcSupply formula, the emission auditor's status). A claim is only as good as what re-checks it, so:

  1. the page is cut into CLAIM UNITS (every <p>, <li>, figure tile, verdict tile and code-panel line); every unit must
     be matched by exactly one entry of harness/loop/SOUNDNESS_CLAIMS.json — a sentence added to the page without an
     entry FAILS (no claim slips in unbacked), and an on-page entry that matches no unit FAILS (the registry is stale);
  2. every entry of kind 'code' names at least one backing, and every backing re-checks:
       test    {pkg, name}: the test ran PASS in harness/loop/SOUNDNESS_LAST.json (written by the pipeline's soundness
               stage, S3s) and none of the files that record fingerprinted (the test file and the entry's `watch`
               files) changed since: a pass on other code proves nothing about this code;
       anchor  {file, line, quote}: the quote is still on that line of the tree (re-read, as G2 does);
       derive  a named recomputation from the tree (the HF3 table split, the reward formula) equals the page's number;
       live    a named read-only RPC check of the running node (the emission auditor: status OK, 0 alerts, consistent);
       number  r30 (B226) {file, key, want[, shown]}: the record still carries `want` at `key` and the unit shows it;
               REQUIRED for a record / live-figure unit that carries a digit group, unless the unit names its
               `as_of_round` in its own text or harness/kit/soundpage.py generates it from the records;
  3. entries of kind 'live-figure' / 'record' / 'external' / 'scope' carry a `source` (where the figure or statement
     comes from); they are not code behaviour and are not re-derived, but they must say where they came from.
Entries with on_page false are claims the soundness tests prove that the page does not (yet) state: they are still
re-checked and reported, so the page can cite them.

  python3 -I harness/soundness.py [--json out.json] [--no-live]      exit 0 ok · 3 a check failed
"""
import argparse, hashlib, html, html.parser, json, re, subprocess, sys, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
REGISTRY = HERE / 'loop/SOUNDNESS_CLAIMS.json'
LAST = HERE / 'loop/SOUNDNESS_LAST.json'
RPC = 'http://127.0.0.1:10102/json_rpc'
UNIT_TAGS = {'p', 'li', 'h1', 'h2', 'h3', 'h4', 'td', 'th', 'dd', 'dt', 'figcaption', 'blockquote', 'title', 'caption'}
UNIT_CLASSES = {'fig', 'eyebrow'}


def norm(s):
    return re.sub(r'\s+', ' ', html.unescape(s)).strip()


class Units(html.parser.HTMLParser):
    """claim units: text of every unit tag (UNIT_TAGS), every element whose class is a unit class, every tile's
    <small>, and every line of a .code panel. r23b merge (H23b-1 fix 2): text outside every unit (a bare <div>, <span>,
    <a> ...) is a unit too ('text:<tag>'), so no sentence can sit on the page unregistered. Script/style are ignored."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack, self.units, self.skip, self.top_stray = [], [], 0, []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        cls = set((a.get('class') or '').split())
        if tag in ('script', 'style'):
            self.skip += 1
        kind = None
        if tag in UNIT_TAGS or cls & UNIT_CLASSES:
            kind = tag if tag in UNIT_TAGS else sorted(cls & UNIT_CLASSES)[0]
        elif tag == 'small' and any('tile' in c for _, c, _x, _s in self.stack):
            kind = 'tile'
        elif 'code' in cls:
            kind = 'code'
        if tag in ('br', 'img', 'meta', 'link', 'input', 'hr', 'wbr'):
            return
        self.stack.append((tag, ' '.join(cls), {'kind': kind, 'buf': []} if kind else None, []))

    def handle_endtag(self, tag):
        if tag in ('script', 'style'):
            self.skip -= 1
        while self.stack:
            t, c, u, stray = self.stack.pop()
            if u:
                text = ''.join(u['buf'])
                if u['kind'] == 'code':
                    self.units += [('code', norm(l)) for l in text.splitlines() if norm(l)]
                elif norm(text):
                    self.units.append((u['kind'], norm(text)))
                # the text also belongs to an enclosing unit (a fig's inner spans feed the fig)
            if norm(''.join(stray)):
                self.units.append((f'text:{t}', norm(''.join(stray))))
            if t == tag:
                break

    def close(self):
        super().close()
        while self.stack:
            self.handle_endtag(self.stack[-1][0])
        if norm(''.join(self.top_stray)):
            self.units.append(('text:top', norm(''.join(self.top_stray))))

    def handle_data(self, d):
        if self.skip:
            return
        inside = False
        for t, c, u, _s in self.stack:
            if u:
                inside = True
                u['buf'].append(d)
                if u['kind'] != 'code':
                    u['buf'].append(' ')
        if not inside:
            (self.stack[-1][3] if self.stack else self.top_stray).append(d + ' ')


def uncovered(unit, match):
    """the text of `unit` that `match` does not cover ('' = fully covered: only punctuation/space is left)"""
    rest = unit.replace(norm(match), ' ', 1)
    return norm(rest) if re.sub(r'[\W_]+', '', rest) else ''


def page_units(text):
    p = Units()
    p.feed(text)
    p.close()
    seen, out = set(), []
    for k, u in p.units:
        if u not in seen:
            seen.add(u)
            out.append((k, u))
    return out


def sha(p):
    try:
        return hashlib.sha256(Path(p).read_bytes()).hexdigest()
    except OSError:
        return None


# ───────────────────────────── derive: recomputations from the tree ─────────────────────────────
def derive_hf3_split(root=ROOT):
    """(duplicates, false-parity, lowest height, highest height, total) of blockchain/hardfork_fixes.go, counted by
    the table's own section comments"""
    sec, c, hs = None, {}, []
    for l in (Path(root) / 'blockchain/hardfork_fixes.go').read_text().splitlines():
        s = l.strip()
        if s.startswith('// duplicates'):
            sec = 'dup'
        elif s.startswith('//') and 'parity' in s:
            sec = 'parity'
        m = re.search(r'Bl_Tips: "[0-9a-f]{64}", Height: (\d+)', s)
        if m and sec:
            c[sec] = c.get(sec, 0) + 1
            hs.append(int(m.group(1)))
    return {'dup': c.get('dup', 0), 'parity': c.get('parity', 0), 'lo': min(hs) if hs else None,
            'hi': max(hs) if hs else None, 'total': len(hs)}


def derive_hf3_height(root=ROOT):
    m = re.search(r'MAJOR_HF3_HEIGHT:\s+(\d+),', (Path(root) / 'config/config.go').read_text())
    return {'height': int(m.group(1)) if m else None}


def derive_crypto_changes(root=ROOT, base='bf274e5'):
    """files under cryptography/ that differ from the pristine Release153 content (harness/baseline)"""
    r = subprocess.run(['git', 'diff', '--name-status', base, 'HEAD', '--', 'cryptography/'], cwd=root,
                       capture_output=True, text=True)
    rows = [l.split('\t') for l in r.stdout.splitlines() if '\t' in l]
    return {'rc': r.returncode, 'added_tests': sum(1 for st, f in rows if st == 'A' and f.endswith('_test.go')),
            'other': [f for st, f in rows if not (st == 'A' and f.endswith('_test.go'))]}


def derive_hf3_struct_fields(root=ROOT):
    """the field names of the HF3 table entry struct (r23b merge, H23b-1 fix 4: 'no amount field' is read from the
    struct, not from one anchored line)"""
    t = (Path(root) / 'blockchain/hardfork_fixes.go').read_text()
    m = re.search(r'type HF3_Tx_Data struct \{(.*?)\n\}', t, re.S)
    return {'fields': re.findall(r'^\s*(\w+)\s+\S', m.group(1), re.M) if m else None}


DERIVE = {
    'hf3_struct_fields': (derive_hf3_struct_fields, lambda d, want: d.get('fields') == want.get('fields')
                          and not any(re.search(r'amount|value', f, re.I) for f in d.get('fields') or ['amount'])),
    'hf3_split': (derive_hf3_split, lambda d, want: all(d.get(k) == v for k, v in want.items())),
    'hf3_height': (derive_hf3_height, lambda d, want: d.get('height') == want.get('height')),
    'crypto_changes': (derive_crypto_changes, lambda d, want: d['rc'] == 0 and d['added_tests'] == want.get('added_tests')
                       and not d['other']),
}


# ───────────────────────────── live: read-only RPC checks ─────────────────────────────
def rpc(method, url=RPC):
    req = urllib.request.Request(url, data=json.dumps({'jsonrpc': '2.0', 'id': '1', 'method': method}).encode(),
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=8) as r:
        return json.loads(r.read()).get('result')


def live_emission_audit(get=None):
    r = (get or rpc)('DERO.GetEmissionAudit') or {}
    ok = (r.get('enabled') is True and r.get('status') == 'OK' and r.get('alerts') == 0
          and r.get('emission_consistent') is True and (r.get('audited') or 0) > 0)
    return ok, (f"status {r.get('status')}, audited {r.get('audited')}, alerts {r.get('alerts')}, consistent "
                f"{r.get('emission_consistent')}, observed {r.get('observed_emission')} = formula {r.get('formula_emission')}")


LIVE = {'emission_audit': live_emission_audit}


# ───────────────────────────── the gate ─────────────────────────────
DIGIT_GROUP = re.compile(r'(?<![\w.#/-])\d[\d,]*(?:\.\d+)?(?![\w])')   # r30 (B226): '7 files', '2,196', '6.7 ms'; not 'R28', 'r28d', 'G13'
GENERATED = 'generated by harness/kit/soundpage.py'


def record_value(root, file, key):
    """r30 (B226): the value a `number` backing names. file *.json: dotted key, 'list[k=v]' picks the element whose k is
    v, a trailing '#len' counts; file *.jsonl: 'stage=<s>.<field>' = the field of the last non-START/INFO event of
    stage s; any other text file: '<Prefix>:<dotted key>' = the JSON object after '<Prefix>: ' on its line. Raises
    KeyError / OSError / ValueError when the record does not carry it."""
    p = Path(root) / file
    if file.endswith('.jsonl'):
        st, field = key.split('.', 1)
        ev = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
        xs = [e for e in ev if e.get('stage') == st.split('=', 1)[1] and e.get('status') not in ('START', 'INFO')]
        if not xs:
            raise KeyError(key)
        return xs[-1][field]
    if file.endswith('.json'):
        d = json.loads(p.read_text())
    else:
        pre, key = key.split(':', 1)
        m = re.search(r'^' + re.escape(pre) + r': (\{.*\})\s*$', p.read_text(), re.M)
        if not m:
            raise KeyError(pre)
        d = json.loads(m.group(1))
    count = key.endswith('#len')
    for part in (key[:-4] if count else key).split('.'):
        m = re.fullmatch(r'(\w+)\[(\w+)=([^\]]+)\]', part)
        if m:
            d = next(x for x in d[m.group(1)] if str(x.get(m.group(2))) == m.group(3))
        elif part:
            d = d[int(part)] if isinstance(d, list) else d[part]
    return len(d) if count else d


def shown(v):
    """how a record value reads on the page: ints with thousands separators, the rest as text. Pure."""
    return f'{v:,}' if isinstance(v, int) and not isinstance(v, bool) else str(v)


def check_number(b, entry, root=ROOT):
    """r30 (B226): a `number` backing {file, key, want[, shown]}: the record still carries `want` at `key`, and the
    unit shows it (`shown`, else the value formatted by shown()). A figure left on the page after its record moved
    FAILS."""
    try:
        v = record_value(root, b['file'], b['key'])
    except (OSError, ValueError, KeyError, IndexError, StopIteration, TypeError) as e:
        return False, f"number {b.get('file')}:{b.get('key')} unreadable ({type(e).__name__})"
    if v != b.get('want'):
        return False, f"number {b['file']}:{b['key']} = {v!r}, the page was written for {b.get('want')!r}"
    disp = b.get('shown') or shown(v)
    if disp not in norm(entry.get('match', '')):
        return False, f"number {b['file']}:{b['key']} = {disp}: not shown in the unit"
    return True, f"number {b['file']}:{b['key']} = {disp}"


def needs_number(entry):
    """r30 (B226): a record / live-figure unit with a digit group must be bound to its record by a `number` backing,
    unless it names its `as_of_round` in its own text (a figure stated as of an earlier round) or soundpage.py
    generates it from the records. Pure."""
    if entry.get('kind') not in ('record', 'live-figure') or not entry.get('on_page', True):
        return False
    if str(entry.get('source', '')).startswith(GENERATED):
        return False
    t = norm(entry.get('match', ''))
    if not DIGIT_GROUP.search(t):
        return False
    aor = entry.get('as_of_round')
    if aor and re.search(r'\b(?:R|Round )' + re.escape(str(aor).lstrip('Rr')) + r'\b', t):
        return False
    return not any(x.get('type') == 'number' for x in entry.get('backing') or [])


def check_backing(b, entry, last, root=ROOT, live=True, get=None):
    """(ok, detail) for one backing"""
    k = b.get('type')
    if k == 'number':
        return check_number(b, entry, root)
    if k == 'test':
        key = f"{b['pkg']}::{b['name']}"
        rec = ((last or {}).get('tests') or {}).get(key)
        if not rec:
            return False, f'{key}: not in the soundness record (run fix_build_verify.py --soundness-only)'
        if rec.get('status') != 'PASS':
            return False, f"{key}: {rec.get('status')} in run {last.get('run')}"
        changed = [f for f, h in (rec.get('fingerprint') or {}).items() if sha(Path(root) / f) != h]
        want = set(entry.get('watch') or []) | set(pkg_sources(b['pkg'], root))
        missing = sorted(want - set(rec.get('fingerprint') or {}))
        if changed or missing or not rec.get('fingerprint'):
            return False, (f'{key}: PASS in run {last.get("run")} but on other code: changed since {changed}, '
                           f'not fingerprinted {missing}')
        return True, f"{key} PASS ({last.get('run')}{', no -race' if rec.get('race') is False else ''})"
    if k == 'anchor':
        try:
            lines = (Path(root) / b['file']).read_text(errors='replace').splitlines()
        except OSError:
            return False, f"{b['file']}: unreadable"
        i = int(b.get('line') or 0)
        if not (1 <= i <= len(lines)) or norm(b['quote']) not in norm(lines[i - 1]):
            return False, f"{b['file']}:{i} no longer says {b['quote'][:60]!r}"
        return True, f"{b['file']}:{i}"
    if k == 'derive':
        fn, cmp = DERIVE.get(b.get('name'), (None, None))
        if not fn:
            return False, f"unknown derivation {b.get('name')}"
        d = fn(root)
        return bool(cmp(d, b.get('want') or {})), f"{b['name']} = {d} (page {b.get('want')})"
    if k == 'live':
        if not live:
            return True, f"{b.get('name')}: live check skipped (--no-live)"
        fn = LIVE.get(b.get('name'))
        if not fn:
            return False, f"unknown live check {b.get('name')}"
        try:
            return fn(get)
        except Exception as e:                                       # noqa: BLE001 — a gate that cannot look fails
            return False, f"{b.get('name')}: node not reachable ({type(e).__name__})"
    return False, f'unknown backing type {k!r}'


def evaluate(page_text, registry, last, root=ROOT, live=True, get=None):
    """{ok, units, unregistered, stale, ambiguous, claims: [...]}: the whole gate. Pure but for the reads `root`,
    `live` and `get` direct."""
    units = page_units(page_text)
    claims = registry.get('claims') or []
    byid = {c['id']: c for c in claims}
    out, why = [], []
    hit = {c['id']: [] for c in claims}
    unreg, amb = [], []
    partial = []
    for kind, u in units:
        m = [c['id'] for c in claims if c.get('on_page', True)
             and (norm(c['match']) == u if c.get('exact') else norm(c['match']) in u)]
        if not m:
            unreg.append(f'{kind}: {u[:90]}')
        elif len(m) > 1:
            amb.append(f'{u[:60]} -> {m}')
        elif uncovered(u, byid[m[0]]['match']):
            # r23b merge (H23b-1 fix 1): the entry must cover the WHOLE unit; text next to the matched fragment is an
            # unregistered claim (an appended sentence used to pass on the old fragment's backing)
            partial.append(f"{m[0]}: {uncovered(u, byid[m[0]]['match'])[:80]}")
        for i in m:
            hit[i].append(u)
    stale = [c['id'] for c in claims if c.get('on_page', True) and not hit[c['id']]]
    for c in claims:
        res = []
        if c['kind'] == 'code':
            if not c.get('backing'):
                res.append((False, 'a code claim with no backing'))
            for b in c.get('backing') or []:
                res.append(check_backing(b, c, last, root, live, get))
        elif not c.get('source'):
            res.append((False, f"{c['kind']} entry without a source"))
        else:
            if needs_number(c):
                res.append((False, 'a figure with no number backing and no as_of_round named in its text (B226)'))
            for b in c.get('backing') or []:
                if b.get('type') == 'number':
                    res.append(check_number(b, c, root))
        ok = all(r[0] for r in res)
        out.append({'id': c['id'], 'kind': c['kind'], 'on_page': c.get('on_page', True), 'ok': ok,
                    'backing': [r[1] for r in res]})
        if not ok:
            why.append(f"{c['id']}: " + '; '.join(r[1] for r in res if not r[0]))
    if unreg:
        why.append(f'{len(unreg)} page claim(s) with no registry entry: {unreg[:3]}')
    if stale:
        why.append(f'registry entries the page no longer carries: {stale[:5]}')
    if amb:
        why.append(f'units matched by several entries: {amb[:3]}')
    if partial:
        why.append(f'{len(partial)} unit(s) only partly covered by their entry: {partial[:3]}')
    if registry.get('_want_measured') and registry['_want_measured'] not in page_text:
        # r27: the page states its round's measured status (harness/kit/soundpage.py measured_block); a page without the
        # current line reads as measured when it is not, or the reverse
        why.append('the page lacks the current measured line (python3 -I harness/kit/soundpage.py --write-measured)')
    if registry.get('_want_page') and registry.get('page') != registry['_want_page']:
        why.append(f"the claim registry names {registry.get('page')!r}, the current round's page is {registry['_want_page']!r} (r25)")
    code = [x for x in out if x['kind'] == 'code']
    on = [x for x in code if x['on_page']]
    return {'ok': not why and bool(units) and bool(code), 'units': len(units), 'unregistered': unreg, 'stale': stale,
            'ambiguous': amb, 'partial': partial, 'claims': out, 'why': why,
            'code_claims': len(code), 'code_backed': sum(1 for x in code if x['ok']),
            'code_claims_on_page': len(on), 'code_backed_on_page': sum(1 for x in on if x['ok']),
            'off_page': [x['id'] for x in out if not x['on_page']],
            'tests': sorted({f"{b['pkg']}::{b['name']}" for c in claims for b in c.get('backing') or [] if b.get('type') == 'test'}),
            'record': (last or {}).get('run'),
            'measured': bool(registry.get('_want_measured')) and registry['_want_measured'] in page_text}


def soundpage():
    """r25: harness/kit/soundpage.py, loaded by path (this file is itself loaded by path from run_gates and the pipeline)"""
    import importlib.util
    spec = importlib.util.spec_from_file_location(f'soundpage_for_soundness_{id(HERE)}', HERE / 'kit/soundpage.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def load(root=ROOT):
    """r25: the page is the CURRENT round's soundness page (soundpage.rel), never a name fixed in a file; the registry's
    own 'page' must name the same file, or evaluate() fails (a registry left on an older round is stale)."""
    reg = json.loads((Path(root) / 'harness/loop/SOUNDNESS_CLAIMS.json').read_text())
    lp = Path(root) / 'harness/loop/SOUNDNESS_LAST.json'
    last = json.loads(lp.read_text()) if lp.exists() else None
    sp = soundpage()
    reg['_want_page'] = sp.rel(root)
    reg['_want_measured'] = sp.measured_block(root)
    page = (Path(root) / reg['_want_page']).read_text()
    return page, reg, last


def soundness_tests(registry):
    """{pkg: [(name, race)]} every test the registry names: what the pipeline's soundness stage runs"""
    out = {}
    for c in registry.get('claims') or []:
        for b in c.get('backing') or []:
            if b.get('type') == 'test':
                v = (b['name'], b.get('race', True))
                if v not in out.setdefault(b['pkg'], []):
                    out[b['pkg']].append(v)
    return out


def pkg_sources(pkg, root=ROOT):
    """the non-test .go files of a test's own package (r23b merge, H23b-1 fix 3): a PASS is fingerprinted with the
    code under test even when no entry's watch list names it"""
    d = Path(root) / pkg.strip('./')
    return sorted(str(p.relative_to(root)) for p in d.glob('*.go') if not p.name.endswith('_test.go')) if d.is_dir() else []


def watch_files(registry, pkg, name, root=ROOT):
    """the files a test's PASS is fingerprinted with: its package's non-test sources plus every naming entry's watch"""
    fs = set(pkg_sources(pkg, root))
    for c in registry.get('claims') or []:
        if any(b.get('type') == 'test' and b['pkg'] == pkg and b['name'] == name for b in c.get('backing') or []):
            fs |= set(c.get('watch') or [])
    return sorted(fs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--json')
    ap.add_argument('--no-live', action='store_true')
    a = ap.parse_args()
    page, reg, last = load()
    r = evaluate(page, reg, last, live=not a.no_live)
    for c in r['claims']:
        print(f"{'ok  ' if c['ok'] else 'FAIL'} {c['id']:28s} {c['kind']:11s} {'' if c['on_page'] else '(off page) '}"
              + ' · '.join(c['backing'])[:300])
    for w in r['why']:
        print('  WHY', w[:400])
    print(f"G22 {'PASS' if r['ok'] else 'FAIL'}: {r['units']} page units, every unit fully covered by one entry; code claims "
          f"backed {r['code_backed_on_page']}/{r['code_claims_on_page']} on the page, "
          f"{r['code_backed'] - r['code_backed_on_page']}/{r['code_claims'] - r['code_claims_on_page']} off the page; "
          f"record {r['record']} (implementation), measured line {'current' if r['measured'] else 'MISSING'}, unregistered {len(r['unregistered'])}, partial {len(r['partial'])}, stale {len(r['stale'])}")
    if a.json:
        Path(a.json).write_text(json.dumps(r, indent=1, ensure_ascii=False))
    return 0 if r['ok'] else 3


if __name__ == '__main__':
    sys.exit(main())
