#!/usr/bin/env python3
"""KAT + mutation proofs for the R26 forensics frontend on dataset v2 (rft §0.8.6, §0.8.9 "Where it shows", B114;
gates G30, G31, G32; harness/forensics/facts.py build_v2, artifacts/src/forensics_section.py section_v2 / fx_line_v2,
harness/kit/soundpage.py known_section, harness/forensics/bounds.py, harness/intel/coherence.py manifest_quote_drifts).
No network, no live file written (every tampered page is a temp copy).

  FE1 a v2 fact may name a file of an earlier SEALED version: changed bytes, a v2 pin that differs from that version's
      manifest, or a ledger entry that is not sealed are each a fact problem (G30 fails)
  FE2 the committed pages: G30, G31 and G32 pass on dero-r1-r26.html, the src-arch lines and the soundness section;
      the ledger carries the class block, #fx-classes, #fx-presence, #fx-invariant and the DC2 headline
  FE3 a tampered class figure (fcl span) on the ledger, or a tampered fact span in the soundness section, FAILS G30
  FE4 inside a class block a dataset fact span is G30's (not an untraced number for G31) while a bare number still FAILS
      G31; a forbidden phrase inside a fact span still FAILS G31; the headline may be a fact span (and without DC2 FAILS)
  FE5 the explorer data of v2: the v1 rows with v1-pending fees settled from blocks_fees; a changed fee or replay-root
      range FAILS check_explorer
  FE6 soundpage: the known section splices idempotently, its claim entries cover every unit of it (no unregistered,
      ambiguous or partial unit under the G22 matcher), and a stale page section is detected
  FE7 coherence: a Round 25 section quoting the sealed v1 manifest is no drift; a Round 26 section quoting it is
  FE8 (verify) on a v2 dataset the generated sections are required: a soundness page without its known section, or a
      page (ledger, soundness, src-arch) without its class block, FAILS G30; a number inside an identifier span
      (<span class="fxid">) is an untraced number, not a name
  FE9 (r27, B133) the dataset readers are memoised (key: the dataset dir + size/mtime of every file under forensics/),
      and a changed dataset file is re-read. A mutant facts.py shares the base caches only when the source of every
      reader and reader helper (MEMO_DEPS) is unchanged; a mutation inside one (mutation 7, explorer_rows) reads with
      caches of its own. With facts.explorer_decode's hoisted index sets: 876.83 s -> 237.82 s wall under benchlock
      (pristine cee1d80f vs r27, load average ~30, 2026-11-05); the 17 mutations stay 17/17 CAUGHT.

  python3 -I harness/kat/test_forensics_frontend2_r26.py   # exit 0 ok · 3 a KAT failed · 4 a mutation not caught / INVALID
"""
import importlib.util, json, re, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
FILES = {'facts': 'harness/forensics/facts.py', 'bounds': 'harness/forensics/bounds.py', 'soundpage': 'harness/kit/soundpage.py',
         'coherence': 'harness/intel/coherence.py', 'section': 'artifacts/src/forensics_section.py', 'soundness': 'harness/soundness.py'}


def load(path, tag):
    sp = importlib.util.spec_from_file_location(f'fe2_{tag}_{len(sys.modules)}', path)
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


def kats(mods):
    FX, BD, SP, CO, SN = mods['facts'], mods['bounds'], mods['soundpage'], mods['coherence'], mods['soundness']
    fails = []

    def ok(c, m):
        if not c:
            fails.append(m)
    ds = FX.newest_dataset(ROOT)
    if not FX.is_v2(json.loads((ds / 'manifest.json').read_text())):
        return [f'the newest dataset {ds.name} is not v2: this KAT needs forensics/r26']
    F = FX.build(ds, ROOT)
    ok(not F.problems, f'FE1 the committed v2 dataset has fact problems: {F.problems[:2]}')
    ok(F.facts['window_rows']['class'] == 'prior' and F.facts['window_rows']['file'].startswith('forensics/r25/'),
       'FE1 the window rows are not a prior-version fact')
    # FE1: a forged two-version tree
    tmp = Path(tempfile.mkdtemp(prefix='fe2kat_'))
    try:
        v1 = tmp / 'forensics' / 'r25'
        (v1 / 'derived').mkdir(parents=True)
        (v1 / 'derived' / 'x.json').write_text('{"a": 1}')
        h = FX.sha((v1 / 'derived' / 'x.json').read_bytes())
        (v1 / 'manifest.json').write_text(json.dumps({'version': 1, 'files': {'derived/x.json': h}}))
        v2 = tmp / 'forensics' / 'r26'
        v2.mkdir()

        def tree(sealed=True, pin=h):
            (v2 / 'manifest.json').write_text(json.dumps({'version': 2, 'files': {}, 'inputs': {'forensics/r25/derived/x.json': pin}}))
            (tmp / 'forensics' / 'ledger.json').write_text(json.dumps({'versions': [
                {'version': 'r25', 'sealed': sealed, 'manifest_sha256': FX.sha((v1 / 'manifest.json').read_bytes())},
                {'version': 'r26', 'sealed': False}]}))
            G = FX.Facts(v2, tmp)
            G.j('a', 'forensics/r25/derived/x.json', ['a'], 'prior')
            return G
        G = tree()
        ok(not G.problems and G.facts['a']['value'] == 1 and G.facts['a']['sha256'] == h, f'FE1 a clean prior file fails: {G.problems}')
        ok(tree(sealed=False).problems, 'FE1 an unsealed prior version passes')
        ok(tree(pin='0' * 64).problems, 'FE1 a v2 pin that differs from the v1 manifest passes')
        (v1 / 'derived' / 'x.json').write_text('{"a": 2}')
        ok(tree().problems, 'FE1 changed prior bytes pass')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # FE2: committed pages
    led = ROOT / 'artifacts' / f'dero-r1-{ds.name}.html'
    if not led.exists():   # R28: the newest dataset (v3) precedes its round's ledger page; check the newest page there is
        import re as _re
        have = sorted((q for q in (ROOT / 'artifacts').glob('dero-r1-r*.html') if int(_re.search(r'r(\d+)\.html$', q.name).group(1)) >= 26),
                      key=lambda q: int(_re.search(r'r(\d+)\.html$', q.name).group(1)))
        led = have[-1] if have else led
    sa = ROOT / 'artifacts' / 'dero-src-arch.html'
    snd = ROOT / SP.rel(ROOT)
    okk, det = FX.g30(ROOT, led, sa, snd)
    ok(okk, f'FE2 G30 on the committed pages: {det[:240]}')
    for name, fn in (('G31', BD.g31), ('G32', BD.g32)):
        r, d = fn(ROOT)
        ok(r, f'FE2 {name}: {d[:200]}')
    lt = led.read_text()
    for need in ('<!--classes:begin-->', 'id="fx-classes"', 'id="fx-presence"', 'id="fx-invariant"', 'data-fc-headline="dc2-present"'):
        ok(need in lt, f'FE2 the ledger page lacks {need}')
    ok(BD.headline_ok(lt) and BD.headline_ok(sa.read_text()) and BD.headline_ok(snd.read_text()), 'FE2 a page lacks the DC2 headline')
    # FE3: tampered copies
    tmp = Path(tempfile.mkdtemp(prefix='fe2kat_'))
    try:
        cl = json.loads((ds / 'derived' / 'classes.json').read_text())
        f0 = next(x for x in cl['figures'] if x['id'] == 'dc3-window-emission')
        good = BD.shown(f0)
        i = lt.index('data-fc="dc3-window-emission"')
        j = lt.index('>', i) + 1
        bad = lt[:j] + lt[j:].replace(good, '2,536,167,751', 1)
        bp = tmp / led.name
        bp.write_text(bad)
        okk, det = FX.g30(ROOT, bp, sa, snd)
        ok(not okk and 'class block' in det, f'FE3 a tampered class figure passes G30: {det[:160]}')
        st = snd.read_text()
        k = st.index(FX.KN_BEGIN)
        key = 'data-fx="mr_added"'
        ka = st.index(key, k)
        kb = st.index('>', ka) + 1
        val = st[kb:st.index('<', kb)]
        sbad = st[:kb] + '9' + val + st[st.index('<', kb):]
        spp = tmp / snd.name
        spp.write_text(sbad)
        okk, det = FX.g30(ROOT, led, sa, spp)
        ok(not okk and snd.name in det, f'FE3 a tampered fact in the soundness section passes G30: {det[:160]}')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # FE4: the class-block contract
    fid = 'dc0-window-duplicates'
    f1 = next(x for x in cl['figures'] if x['id'] == fid)
    span = (f'<span class="fcl" data-fc="{fid}" data-cls="{f1["class"]}" data-bound="{f1["bound_type"]}" '
            f'data-cov="{BD.cov(f1)}" data-scope="{BD.scope(f1)}">{BD.shown(f1)}</span>')
    fx = '<span class="fxn" data-fx="cl_figures" data-src="derived/classes.json" data-sha="' + 'a' * 64 + '">12</span>'
    blk = lambda body: BD.BEGIN + body + BD.END
    p1, _ = BD.check_page(blk(f'<p>{span} of {fx} figures</p>'), cl)
    ok(p1 == [], f'FE4 a fact span inside a class block is an untraced number for G31: {p1[:2]}')
    p2, _ = BD.check_page(blk(f'<p>{span} of 12 figures</p>'), cl)
    ok(any('untraced' in x for x in p2), 'FE4 a bare number in a class block passes G31')
    ph = fx.replace('>12<', '>a supply audit<')
    p3, _ = BD.check_page(blk(f'<p>{span} {ph}</p>'), cl)
    ok(any('forbidden phrase' in x for x in p3), 'FE4 a forbidden phrase inside a fact span passes G31')
    hl = '<p data-fc-headline="dc2-present"><span class="fxn" data-fx="cl_headline" data-src="d" data-sha="b">DC2 is present now</span></p>'
    ok(BD.headline_ok(hl) and not BD.headline_ok(hl.replace('DC2 is', 'it is')), 'FE4 the headline as a fact span is misread')
    # FE5: explorer data
    d = FX.explorer_data(ds)
    rows1 = FX.window_rows(FX._v1_dir(ds))
    pend = [i for i, r in enumerate(rows1) if not isinstance(r['fees'], int)]
    dec = FX.explorer_decode(d)
    ok(pend and all(isinstance(dec[i]['fees'], int) for i in pend if i not in set(d['feep'])) and len(pend) > len(d['feep']),
       'FE5 v1-pending fees are not settled in the v2 explorer')
    ok(len(d['feep']) == F.facts['fee_still_pending']['value'], f'FE5 pending fee rows {len(d["feep"])} != fees.json still_pending')
    ok(FX.check_explorer(d, ds) == [], f'FE5 the v2 explorer data fails its own check: {FX.check_explorer(d, ds)[:2]}')
    if pend:
        key0 = next(iter(d['fee']))
        ok(FX.check_explorer(dict(d, fee=dict(d['fee'], **{key0: d['fee'][key0] + 1})), ds) != [], 'FE5 a changed fee passes')
    ok(d.get('rroots') and FX.check_explorer(dict(d, rroots=[0, 0, 0]), ds) != [], 'FE5 a changed replay-root range passes')
    # FE6: soundpage
    sec, ent = SP.known_section(ROOT)
    page = snd.read_text()
    ok(SP.splice(SP.splice(page, sec), sec) == SP.splice(page, sec), 'FE6 the known splice is not idempotent')
    ok(SP.splice(page, sec).count(SP.KN_BEGIN) == 1, 'FE6 the splice duplicates the known block')
    reg = json.loads((ROOT / SP.CLAIMS).read_text())
    reg2 = SP.merge_claims(SP.merge_claims(reg, ent), ent)
    ids = [c['id'] for c in reg2['claims']]
    ok(len(ids) == len(set(ids)), 'FE6 merged claim entries repeat an id')
    r = SN.evaluate(sec, {'claims': ent}, None, ROOT, live=False)
    ok(not r['unregistered'] and not r['ambiguous'] and not r['partial'] and not r['stale'],
       f"FE6 the section's units are not covered one to one: {r['unregistered'][:1]} {r['ambiguous'][:1]} {r['partial'][:1]} {r['stale'][:1]}")
    r = SN.evaluate(SP.splice(page, sec), reg2, None, ROOT, live=False)
    ok(not r['unregistered'] and not r['ambiguous'] and not r['partial'] and not r['stale'],
       f"FE6 the page with the section has uncovered units: {r['unregistered'][:1]} {r['ambiguous'][:1]} {r['partial'][:1]} {r['stale'][:1]}")
    ok(SP.write_known(ROOT, check=True)[0] is False, 'FE6 the committed soundness section is stale (run soundpage.py --write-known)')
    ok(SP.splice(page.replace(SP.KN_BEGIN, '<!--x-->').replace(SP.KN_END, '<!--y-->'), sec).count(SP.KN_BEGIN) == 1,
       'FE6 a page without the block gets none inserted')
    # FE7: coherence per-round manifest quotes
    led_v = {'r25': 'cc80176e' + '0' * 56, 'r26': '857c2146' + '0' * 56}
    t25 = '## Round 25 (x)\nIts forensic dataset manifest `cc80176e` binds files.\n'
    t26 = '## 44. ★ Round 26: y\nThe forensic dataset manifest `cc80176e` binds files.\n'
    ok(CO.manifest_quote_drifts(t25, led_v, led_v['r26'], 'r26') == [], 'FE7 a Round 25 section quoting the v1 manifest drifts')
    ok(len(CO.manifest_quote_drifts(t26, led_v, led_v['r26'], 'r26')) == 1, 'FE7 a Round 26 section quoting the v1 manifest passes')
    ok(len(CO.manifest_quote_drifts('## Round 25\nforensic manifest `deadbeef`\n', led_v, led_v['r26'], 'r26')) == 1,
       'FE7 a wrong quote inside Round 25 passes')
    # FE8 (verify): required sections, identifier spans
    tmp = Path(tempfile.mkdtemp(prefix='fe2kat_'))
    try:
        st = snd.read_text()
        spp = tmp / snd.name
        spp.write_text(st.replace(FX.KN_BEGIN, '<!--x-->', 1))
        okk, det = FX.g30(ROOT, led, sa, spp)
        ok(not okk and 'known' in det, f'FE8 a soundness page without its known section passes G30: {det[:160]}')
        for pg, nm in ((led, 'ledger'), (snd, 'soundness'), (sa, 'src-arch')):
            q = tmp / ('cb_' + pg.name)
            q.write_text(pg.read_text().replace(BD.BEGIN, '<!--x-->', 1))
            args = {'ledger': (q, sa, snd), 'soundness': (led, sa, q), 'src-arch': (led, q, snd)}[nm]
            okk, det = FX.g30(ROOT, *args)
            ok(not okk and 'class block' in det, f'FE8 a {nm} page without its class block passes G30: {det[:160]}')
        bp = tmp / led.name
        # the first identifier span of the section (its heading, outside every class block): only G30's own scan sees it
        # r30 (B265): on the R30 page the FIRST such span sits inside a class block (the R30 section quotes the classes),
        # so the plant goes into the first span OUTSIDE every class block, as this case intends
        _span = '<span class="fxid">v2</span>'
        _regs = [(m.start(), lt.find(BD.END, m.start())) for m in re.finditer(re.escape(BD.BEGIN), lt)]
        _at = next((m.start() for m in re.finditer(re.escape(_span), lt)
                    if not any(a0 <= m.start() <= b0 for a0, b0 in _regs)), -1)
        bp.write_text(lt[:_at] + '<span class="fxid">v2 7,000</span>' + lt[_at + len(_span):] if _at >= 0 else lt)
        okk, det = FX.g30(ROOT, bp, sa, snd)
        ok(not okk and "untraced number '7,000'" in det and 'class block' not in det,
           f'FE8 a number inside an identifier span passes G30: {det[:160]}')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # FE9 (r27, B133): the KAT's reader memo re-reads a changed dataset file and is per module
    tmp = Path(tempfile.mkdtemp(prefix='fe2kat_'))
    try:
        import gzip
        w = tmp / 'forensics' / 'rX' / 'derived'
        w.mkdir(parents=True)

        def wr(n):
            with gzip.open(w / 'window.jsonl.gz', 'wt') as fh:
                fh.write(''.join(json.dumps({'height': i}) + '\n' for i in range(n)))
        wr(2)
        a = len(FX.window_rows(w.parent))
        wr(3)
        b = len(FX.window_rows(w.parent))
        ok(getattr(FX.window_rows, '_r27_memo', False), 'FE9 the dataset readers are not memoised (B133)')
        ok((a, b) == (2, 3), f'FE9 a changed dataset file is served from the memo: {a} then {b} rows')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return fails


MUTATIONS = [
    ('facts', "        if not mb or not ent.get('sealed') or ent.get('manifest_sha256') != sha(mb):", "        if False:"),
    ('facts', "        if pin is not None and pin != h:", "        if False:"),
    ('facts', "        if not b or sha(b) != h:\n            self.problems.append(f'{rel}: bytes differ from the {ver}",
     "        if False:\n            self.problems.append(f'{rel}: bytes differ from the {ver}"),
    ('facts', "    seg = FCL.sub(' ', seg)\n", "\n"),
    ('facts', "            fails += [f'{pg.name} (class block): {x}' for x in bp]", "            pass"),
    ('facts', "                kf, n3 = check_page(st, F, KN_BEGIN, KN_END, need_explorer=False)", "                kf, n3 = [], 0"),
    ('facts', "        if not isinstance(r['fees'], int) and isinstance(bf.get(r['height'], {}).get('fees'), int):",
     "        if False:"),
    ('facts', "+ (('rroots',) if 'rroots' in want else ())", "+ ()"),
    # verify: the required-section and identifier-span fixes
    ('facts', "                fails.append(f'{sp.name}: no {KN_BEGIN} … {KN_END} section (required on a v2 dataset)')", "                pass"),
    ('facts', "            bp, k = BD.check_page(t, clp if pg == Path(page) else cl, need=True, root=root)",
     "            bp, k = BD.check_page(t, clp if pg == Path(page) else cl, need=False, root=root)"),
    ('facts', "    seg = FXID.sub(_fxid_text, seg)", "    seg = FXID.sub(' ', seg)"),
    ('bounds', "    seg = FXN.sub(' ', seg)   # r26", "    seg = seg   # r26"),
    ('bounds', "    blocks = _visible(BLOCK_CLOSE.sub(' \\u00b6 ', FXN.sub(lambda m: ' ' + m.group(1) + ' ', SPAN.sub(",
     "    blocks = _visible(BLOCK_CLOSE.sub(' \\u00b6 ', (lambda x: x)(SPAN.sub("),
    ('bounds', "    t = _visible(FXN.sub(lambda x: ' ' + x.group(1) + ' ', m.group(2)))", "    t = _visible(m.group(2))"),
    ('soundpage', "    reg['claims'] = [c for c in reg.get('claims', []) if not str(c.get('id', '')).startswith(KNOWN_ID)] + entries",
     "    reg['claims'] = list(reg.get('claims', [])) + entries"),
    ('soundpage', "    if KN_BEGIN in page and KN_END in page:", "    if False:"),
    ('coherence', "            want, src = (led[v], f'forensics/{v}/manifest.json (ledger entry)') if v in led else (msha, f'forensics/{newest}/manifest.json')",
     "            want, src = msha, f'forensics/{newest}/manifest.json'"),
]


# r27 (B133): the dataset readers this KAT calls again and again (window_rows 26x, explorer_rows 25x, explorer_data
# 13x per kats() run, cProfile 2026-11-05) memoised PER LOADED MODULE, keyed by the dataset directory and the size and
# mtime of every file under it: a mutant module gets its own cache (its mutated reader runs), a changed dataset file is
# a cache miss, and no reader result is mutated by any caller (they copy: explorer_rows dict(r), FE5 dict(d, ...)).
MEMO = ('window_rows', 'explorer_rows', 'explorer_data', '_replay_roots', '_hf3_rows')


def _ds_key(ds):
    d = Path(ds).resolve()
    top = d.parent if d.parent.name == 'forensics' else d   # a v2 dataset reads its sealed v1 sibling too
    files = sorted(q for q in top.rglob('*') if q.is_file()) if top.is_dir() else []
    return str(d), tuple((str(q), q.stat().st_size, q.stat().st_mtime_ns) for q in files)


# the helpers the memoised readers call: a mutation inside any of them (or inside a reader) makes the mutant read
# with caches of its own; any other mutant shares the base module's caches (same reader source, same dataset bytes ->
# same result), so a mutation of g30 or check_page does not re-parse the 8.6 MB dataset (B133)
MEMO_DEPS = MEMO + ('is_v2', '_manifest', '_v1_dir', 'b64x', '_b36')
SHARED = {}


def reader_source(fx):
    import inspect
    return ''.join(inspect.getsource(getattr(fx, n)) for n in MEMO_DEPS if callable(getattr(fx, n, None)))


def memoize(fx, names=MEMO, share=None):
    """wrap fx's dataset readers with a cache keyed by _ds_key; `share` {name: cache} reuses another module's caches"""
    for name in names:
        fn = getattr(fx, name, None)
        if fn is None or getattr(fn, '_r27_memo', False):
            continue
        cache = share[name] if share is not None and name in share else {}

        def wrapped(ds, _fn=fn, _c=cache):
            k = _ds_key(ds)
            if k not in _c:
                _c[k] = _fn(ds)
            return _c[k]
        wrapped._r27_memo = True
        wrapped.cache = cache
        setattr(fx, name, wrapped)
    return fx


def load_all(base):
    mods = {k: load(Path(base) / v, k) for k, v in FILES.items()}
    if not SHARED:
        SHARED['src'] = reader_source(mods['facts'])
        SHARED['caches'] = {n: {} for n in MEMO}
    memoize(mods['facts'], share=SHARED['caches'])
    return mods


def main():
    f = kats(load_all(ROOT))
    print('FE1-FE9:', 'PASS' if not f else 'FAIL\n  ' + '\n  '.join(f))
    if f:
        return 3
    rc, caught = 0, 0
    for i, (key, old, new) in enumerate(MUTATIONS, 1):
        tmp = Path(tempfile.mkdtemp(prefix='fe2mut_'))
        try:
            src = (ROOT / FILES[key]).read_text()
            if src.count(old) != 1:
                print(f'mutation {i} INVALID: text found {src.count(old)} times'); rc = 4; continue
            mp = tmp / Path(FILES[key]).name
            mp.write_text(src.replace(old, new, 1))
            mods = load_all(ROOT)
            mods[key] = load(mp, key + 'mut')
            if key == 'facts':   # r27 (B133): the mutant's readers are memoised too; shared only when they are unchanged
                same = reader_source(mods[key]) == SHARED['src']
                memoize(mods[key], share=SHARED['caches'] if same else None)
                print(f"mutation {i}: reader caches {'shared' if same else 'own (a reader or helper is mutated)'}")
            if key == 'bounds':   # facts.g30 loads bounds by path from the root: route it to the mutant
                mods['facts']._bounds = lambda root, _m=mods[key]: _m
            try:
                mf = kats(mods)
            except Exception as e:                                   # noqa: BLE001
                print(f'mutation {i} INVALID: {type(e).__name__}: {e}'); rc = 4; continue
            if mf:
                caught += 1
                print(f'mutation {i} CAUGHT: {mf[0][:110]}')
            else:
                print(f'mutation {i} NOT CAUGHT: {old.strip()[:70]}'); rc = 4
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print(f'mutations caught {caught}/{len(MUTATIONS)}')
    return rc


if __name__ == '__main__':
    sys.exit(main())
