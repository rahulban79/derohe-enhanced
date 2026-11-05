#!/usr/bin/env python3
"""KAT + mutation proofs for gate G31 bound honesty (rft §0.8.9 rules 8-10; harness/forensics/bounds.py; B108). No
network, no live file written; every case runs on forged classes.json / pages in a temp dir.

  BH1 a well-formed figure set and page PASS (the negative control of every case below);
  BH2 a lower-bound figure labelled as a total FAILS (in classes.json and on a page);
  BH3 a DC2 figure rendered as 0 FAILS (value 0, an unbounded span showing 0, a DC2 figure graded exact);
  BH4 a sum across classes FAILS (sum_of names another class's figure; a figure with two classes);
  BH5 a fix status that changes a historical grade FAILS (regrade by 'implemented' without dataset evidence; a DC1
      grade moved to PROVEN while the historical per-tx grades are NOT-DECIDABLE);
  BH6 "supply audit" (and the other forbidden phrases) on a non-exact figure FAILS: in a label, un-negated on a page and
      next to a figure; a negated sentence away from any figure PASSES;
  BH7 exact needs num == den; an unbounded figure renders as the word; an empty value FAILS;
  BH8 page tracing: a span whose attributes or text differ from classes.json FAILS; a number outside a span FAILS;
      amount-recovery method text FAILS; an unreadable G24 pattern source FAILS closed;
  BH9 g31 end to end on a forged root: PASS; a planted bad figure, an invariant re-read drift or an answered Q-CS
      with a missing anchor FAILS.
  Committed: g31 passes on this tree.

  python3 -I harness/kat/test_forensics_bounds_r26.py   # exit 0 ok · 3 a KAT failed · 4 a mutation not caught / INVALID
"""
import copy, importlib.util, json, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent


def load(base, rel, tag):
    spec = importlib.util.spec_from_file_location(f'bh_{tag}_{id(base)}_{len(sys.modules)}', base / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


W = {'heights': [100, 200], 'text': 'two hundred blocks'}


def fig(fid, cls, value, bound, num, den, label='a figure', **k):
    f = {'id': fid, 'class': cls, 'label': label, 'value': value, 'unit': 'count', 'scope': dict(W),
         'coverage': {'num': num, 'den': den, 'num_anchor': 'derived/x.json', 'den_anchor': 'derived/y.json'}, 'bound_type': bound}
    f.update(k)
    return f


def good():
    return {'schema': 'kat', 'base': 'rB',
            'figures': [fig('f-exact', 'DC3', 1234, 'exact', 10, 10, 'window emission'),
                        fig('f-low', 'DC1', 5, 'lower-bound', 3, 75, 'observable entries'),
                        fig('f-dc2', 'DC2', 'unbounded', 'unbounded', 0, 'pending', 'created value', scope={'heights': 'genesis..now', 'text': 'genesis .. now'}),
                        fig('f-str', 'DC1', 'pending: two bodies', 'unbounded', 'pending', 75, 'two bodies')],
            'classes': {'DC0': {}, 'DC1': {'grade': 'NOT-DECIDABLE-FROM-PUBLIC-DATA (per tx)'}, 'DC2': {'grade': 'NOT-DECIDABLE-FROM-PUBLIC-DATA'},
                        'DC3': {'grade': 'PROVEN-NO-INFLATION-IN-SCOPE'}},
            'records': {'tx': {'DC1': 1}}, 'headline': {'dc2_present_now': True}}


HIST = {'counts': {'NOT-DECIDABLE-FROM-PUBLIC-DATA/E1': 2, 'NOT-DECIDABLE-FROM-PUBLIC-DATA/E2': 73}}


def text_of(f):
    """the KAT's own rendering rule (independent of bounds.shown)"""
    if f['bound_type'] == 'unbounded':
        return f['value'] if isinstance(f['value'], str) and f['value'].startswith('pending') else 'unbounded'
    if isinstance(f['value'], int):
        return {'lower-bound': '≥ ', 'upper-bound': '≤ '}.get(f['bound_type'], '') + f'{f["value"]:,}'
    return str(f['value'])


def span(f, text=None, **over):
    h = f['scope']['heights']
    a = {'cls': f['class'], 'bound': f['bound_type'], 'cov': f"{f['coverage']['num']}/{f['coverage']['den']}",
         'scope': f'{h[0]}-{h[1]}' if isinstance(h, list) else str(h)}
    a.update(over)
    return (f'<span class="fcl" data-fc="{f["id"]}" data-cls="{a["cls"]}" data-bound="{a["bound"]}" data-cov="{a["cov"]}" '
            f'data-scope="{a["scope"]}">{text if text is not None else text_of(f)}</span>')


def page(cl, extra='', spans=None):
    body = ' '.join(f'<li>{f["label"]}: {span(f)}</li>' for f in cl['figures']) if spans is None else spans
    return (f'<html><body><section><!--classes:begin--><p data-fc-headline="dc2-present">DC2 is present in the current code</p>'
            f'<ul>{body}</ul>{extra}<!--classes:end--></section></body></html>')


def expect(out, name, probs, fail=True):
    if fail and not probs:
        out.append(f'{name}: not refused')
    if not fail and probs:
        out.append(f'{name}: refused a valid input: {probs[:2]}')


def kats(base):
    B = load(base, 'forensics/bounds.py', 'bounds')
    out = []
    g = good()
    # BH1 control
    expect(out, 'BH1 figures', B.check_figures(g), fail=False)
    expect(out, 'BH1 grades', B.check_grades(g, HIST), fail=False)
    pf, n = B.check_page(page(g), g, root=ROOT)
    expect(out, 'BH1 page', pf, fail=False)
    if n != len(g['figures']):
        out.append(f'BH1 spans counted {n}, want {len(g["figures"])}')
    expect(out, 'BH1 negated phrase', B.check_page(page(g, '<p>A complete supply audit is impossible from public data.</p>'), g, root=ROOT)[0], fail=False)
    # BH2 lower bound called a total
    b = copy.deepcopy(g); b['figures'][1]['label'] = 'total observable amount'
    expect(out, 'BH2 json', B.check_figures(b))
    expect(out, 'BH2 page', B.check_page(page(g, spans=f'<li>In total {span(g["figures"][1])}</li>'), g, root=ROOT)[0])
    # BH3 DC2 rendered as 0
    b = copy.deepcopy(g); b['figures'][2]['value'] = 0
    expect(out, 'BH3 value 0', B.check_figures(b))
    expect(out, 'BH3 span 0', B.check_page(page(g, spans=f'<li>{span(g["figures"][2], "0")}</li>'), g, root=ROOT)[0])
    b = copy.deepcopy(g); b['figures'][2]['bound_type'] = 'exact'; b['figures'][2]['coverage']['num'] = b['figures'][2]['coverage']['den'] = 1
    expect(out, 'BH3 DC2 exact', B.check_figures(b))
    b = copy.deepcopy(g); b['figures'][2]['bound_type'] = 'lower-bound'; b['figures'][2]['value'] = 7
    expect(out, 'BH3 DC2 lower bound', B.check_figures(b))
    # BH4 cross-class sum
    b = copy.deepcopy(g); b['figures'][1]['sum_of'] = ['f-exact']
    expect(out, 'BH4 sum_of', B.check_figures(b))
    b = copy.deepcopy(g); b['figures'][1]['class'] = ['DC1', 'DC3']
    expect(out, 'BH4 two classes', B.check_figures(b))
    b = copy.deepcopy(g); b['figures'][1]['sum_of'] = ['f-str']
    expect(out, 'BH4 same-class sum', B.check_figures(b), fail=False)
    # BH5 fix status regrades history
    b = copy.deepcopy(g); b['classes']['DC1']['regrade'] = {'reason': 'path implemented upstream', 'evidence': []}
    expect(out, 'BH5 regrade by fix', B.check_grades(b, HIST))
    b = copy.deepcopy(g); b['classes']['DC1']['grade'] = 'PROVEN-NO-INFLATION-IN-SCOPE'
    expect(out, 'BH5 DC1 proven', B.check_grades(b, HIST))
    b = copy.deepcopy(g); b['classes']['DC3']['grade'] = 'PROVEN-NO-INFLATION-IN-SCOPE (path fixed upstream)'
    expect(out, 'BH5 proven by a fix status', B.check_grades(b, HIST))
    b = copy.deepcopy(g); b['classes']['DC1']['regrade'] = {'reason': 'a new reading', 'evidence': ['RUN_REPORT.md']}
    expect(out, 'BH5 regrade without dataset evidence', B.check_grades(b, HIST))
    b = copy.deepcopy(g); b['classes']['DC1']['regrade'] = {'reason': 'new RAW body', 'evidence': ['derived/tx/aa.json']}
    b['classes']['DC1']['grade'] = 'PROVEN-INFLATION'
    expect(out, 'BH5 regrade with evidence', B.check_grades(b, HIST), fail=False)
    # BH6 forbidden phrases
    for ph in ('supply audit', 'audited supply', 'total inflation', 'true supply'):
        b = copy.deepcopy(g); b['figures'][1]['note'] = f'part of the {ph}'
        expect(out, f'BH6 json {ph}', B.check_figures(b))
        expect(out, f'BH6 page {ph}', B.check_page(page(g, f'<p>This is the {ph} result.</p>'), g, root=ROOT)[0])
    expect(out, 'BH6 next to a figure', B.check_page(page(g, spans=f'<li>{span(g["figures"][0])} is no supply audit</li>'), g, root=ROOT)[0])
    expect(out, 'BH6 json un-negated', B.check_phrases_json({'fq': {'a': 'the supply audit result'}}))
    expect(out, 'BH6 json negated', B.check_phrases_json({'fq': {'a': 'a supply audit is impossible here'}}), fail=False)
    # BH7 exact / unbounded / empty
    b = copy.deepcopy(g); b['figures'][0]['coverage']['num'] = 9
    expect(out, 'BH7 exact partial', B.check_figures(b))
    b = copy.deepcopy(g); b['figures'][3]['value'] = 12
    expect(out, 'BH7 unbounded numeric', B.check_figures(b))
    b = copy.deepcopy(g); b['figures'][1]['value'] = ''
    expect(out, 'BH7 empty', B.check_figures(b))
    b = copy.deepcopy(g); b['figures'][0]['bound_type'] = 'roughly'
    expect(out, 'BH7 bound type', B.check_figures(b))
    b = copy.deepcopy(g); del b['figures'][0]['scope']
    expect(out, 'BH7 no scope', B.check_figures(b))
    # BH8 page tracing
    f0 = g['figures'][0]
    expect(out, 'BH8 wrong text', B.check_page(page(g, spans=f'<li>{span(f0, "1,235")}</li>'), g, root=ROOT)[0])
    expect(out, 'BH8 wrong bound attr', B.check_page(page(g, spans=f'<li>{span(f0, bound="lower-bound")}</li>'), g, root=ROOT)[0])
    expect(out, 'BH8 wrong coverage attr', B.check_page(page(g, spans=f'<li>{span(f0, cov="9/10")}</li>'), g, root=ROOT)[0])
    expect(out, 'BH8 lower bound without ≥', B.check_page(page(g, spans=f'<li>{span(g["figures"][1], "5")}</li>'), g, root=ROOT)[0])
    expect(out, 'BH8 unknown span', B.check_page(page(g, spans=span(dict(f0, id='nope'))), g, root=ROOT)[0])
    expect(out, 'BH8 untraced number', B.check_page(page(g, '<p>about 23,886,517 coins</p>'), g, root=ROOT)[0])
    expect(out, 'BH8 identifiers allowed', B.check_page(page(g, '<p>DC1 FQ2 Q-CS3 G31 R26 B108 §0.8.9 classes.json</p>'), g, root=ROOT)[0], fail=False)
    expect(out, 'BH8 method text', B.check_page(page(g, '<p>One can recover the hidden amounts this way.</p>'), g, root=ROOT)[0])
    expect(out, 'BH8 method text 2', B.check_page(page(g, '<p>A brute-force over small values works.</p>'), g, root=ROOT)[0])
    expect(out, 'BH8 G24 pattern', B.check_page(page(g, '<p>Here is a working proof-of-concept.</p>'), g, root=ROOT)[0])
    with tempfile.TemporaryDirectory() as nr:
        expect(out, 'BH8 fail closed', B.method_lint('harmless words', Path(nr)))
    # BH9 end to end
    out += bh9(B)
    return out


def bh9(B):
    out = []
    with tempfile.TemporaryDirectory(prefix='bh9_') as t:
        t = Path(t)
        shutil.copytree(HARNESS / 'forensics', t / 'harness' / 'forensics')
        (t / 'harness' / 'intel').mkdir(parents=True)
        shutil.copyfile(HARNESS / 'intel' / 'disclosure_track.py', t / 'harness' / 'intel' / 'disclosure_track.py')
        d = t / 'forensics' / 'r26' / 'derived'
        d.mkdir(parents=True)
        (t / 'forensics' / 'rB' / 'derived').mkdir(parents=True)
        (t / 'forensics' / 'rB' / 'derived' / 'grades.json').write_text(json.dumps(HIST))
        g = good()
        inv = {'status': 'partial', 'Q-CS1': {'status': 'pending: none'}, 'Q-CS2': {'answer': 'no', 'anchors': [{'id': 'a', 'anchor': 'x.go:1', 'ok': True}]},
               'Q-CS3': {'answer': 'no'}}
        J = lambda n, o: (d / f'{n}.json').write_text(json.dumps(o))
        J('classes', g); J('presence', {'classes': {}}); J('fq', {'FQ1': {'status': 'answered'}}); J('invariant', inv)
        ok, det = B.g31(t, inv_check=lambda p, r: [])
        if not ok:
            out.append(f'BH9 good root FAILS: {det[:200]}')
        ok, _ = B.g31(t, inv_check=lambda p, r: ['a: recorded x.go:1 now absent'])
        if ok:
            out.append('BH9 an invariant re-read drift PASSES')
        i2 = copy.deepcopy(inv); i2['Q-CS2']['anchors'][0]['ok'] = False
        J('invariant', i2)
        ok, _ = B.g31(t, inv_check=lambda p, r: [])
        if ok:
            out.append('BH9 an answered Q-CS with a missing anchor PASSES')
        i3 = copy.deepcopy(inv); i3['Q-CS1'] = {'status': 'answered (scope x)', 'root_check': {'equal': False}}
        J('invariant', i3)
        ok, _ = B.g31(t, inv_check=lambda p, r: [])
        if ok:
            out.append('BH9 an answered Q-CS1 without an equal root PASSES')
        J('invariant', inv)
        b = copy.deepcopy(g); b['figures'][2]['value'] = 0
        J('classes', b)
        ok, _ = B.g31(t, inv_check=lambda p, r: [])
        if ok:
            out.append('BH9 a DC2 figure of 0 PASSES end to end')
        J('classes', g)
        (t / 'artifacts').mkdir()
        (t / 'artifacts' / 'dero-src-arch.html').write_text(page(g, '<p>the true supply is known</p>'))
        ok, _ = B.g31(t, inv_check=lambda p, r: [])
        if ok:
            out.append('BH9 a page with a forbidden phrase PASSES end to end')
        (t / 'artifacts' / 'dero-src-arch.html').write_text(page(g))
        ok, det = B.g31(t, inv_check=lambda p, r: [])
        if not ok or '4 class spans on 1 page' not in det:
            out.append(f'BH9 a valid page is not traced: {det[:160]}')
        J('fq', {'FQ2': {'note': 'we can recover the encrypted amounts'}})
        ok, _ = B.g31(t, inv_check=lambda p, r: [])
        if ok:
            out.append('BH9 amount-recovery text in fq.json PASSES')
    return out


def committed():
    B = load(HARNESS, 'forensics/bounds.py', 'bc')
    if B.classes_dataset(ROOT) is None:
        return []
    ok, det = B.g31(ROOT)
    return [] if ok else [f'G31 on this tree: {det[:300]}']


MUTATIONS = [
    ("        if b != 'exact' and TOTAL_RX.search(str(f.get('label', ''))):", "        if False:"),
    ("        if f['bound_type'] != 'exact' and TOTAL_RX.search(ctx):", "        if False:"),
    ("        if b == 'unbounded' and v != 'unbounded' and not (isinstance(v, str) and v.startswith('pending')):", "        if False:"),
    ("        if c == 'DC2' and b != 'unbounded':", "        if False:"),
    ("            if other - {c} or len([x for x in so if x not in byid]):", "            if False:"),
    ("        if not isinstance(c, str) or c not in CLASS_IDS:", "        if not isinstance(c, (str, list)):"),
    ("            if not ev:\n                p.append(f'{cid}: ' + ('a fix status", "            if False:\n                p.append(f'{cid}: ' + ('a fix status"),
    ("        if FIX_WORDS.search(g) and 'PROVEN' in g:", "        if False:"),
    ("        if cid == 'DC1' and hist_nd and not g.startswith('NOT-DECIDABLE') and not (rg and rg.get('evidence')):", "        if False:"),
    ("            if ph in text.lower():", "            if False:"),
    ("            if ph in low and not NEGATION.search(sent):", "            if False:"),
    ("            if ph in _visible(FXN.sub(lambda m: ' ' + m.group(1) + ' ', whole)).lower():", "            if False:"),
    ("                        if ph in sent.lower() and not NEGATION.search(sent):", "                        if False:"),
    ("            if not (isinstance(cv.get('num'), int) and isinstance(cv.get('den'), int) and cv['num'] == cv['den']):", "            if False:"),
    ("        if v is None or v == '':", "        if v is None:"),
    ("        if b not in BOUND_TYPES:", "        if False:"),
    ("        if not isinstance(sc, dict) or 'heights' not in sc or not sc.get('text'):", "        if False:"),
    ("        if t != shown(f):", "        if False:"),
    ("        if cls != f['class'] or bnd != f['bound_type'] or cv != cov(f) or sc != scope(f):", "        if cls != f['class']:"),
    ("        if f is None:\n            p.append(f'span {fid}: no such figure')\n            continue", "        if f is None:\n            continue"),
    ("    for mm in re.finditer(r'\\d[\\d,.]*', left):", "    for mm in re.finditer(r'\\d[\\d,.]*', ''):"),
    ("        return {'lower-bound': '≥ ', 'upper-bound': '≤ '}.get(b, '') + f'{v:,}'", "        return f'{v:,}'"),
    ("    for n, rx in list(pats) + METHOD_PATTERNS:", "    for n, rx in list(pats):"),
    ("    for n, rx in list(pats) + METHOD_PATTERNS:", "    for n, rx in METHOD_PATTERNS:"),
    ("        return [f'the G24 exploit patterns could not be read (", "        pats = []\n        return [] or [x for x in [] if f'the G24 exploit patterns could not be read ("),
    ("        fails += [f'invariant re-read: {x}' for x in inv_check(ds / 'derived' / 'invariant.json', root)]", "        pass"),
    ("        if a != 'pending' and not all(x.get('ok') for x in (inv.get('Q-CS2') or {}).get('anchors', [])):", "        if False:"),
    ("    if str(q1.get('status', 'pending')).startswith('answered') and not (q1.get('root_check') or {}).get('equal'):", "    if False:"),
    ("            for h in method_lint(s, root):", "            for h in []:"),
    ("            if BEGIN in t:\n                pf, n = check_page(t, cl, root=root)", "            if False:\n                pf, n = check_page(t, cl, root=root)"),
]


def main():
    f = kats(HARNESS) + committed()
    print('BH1-BH9:', 'PASS' if not f else 'FAIL\n  ' + '\n  '.join(f))
    if f:
        return 3
    rc, caught = 0, 0
    for i, (old, new) in enumerate(MUTATIONS, 1):
        tmp = Path(tempfile.mkdtemp(prefix='bhmut_'))
        try:
            shutil.copytree(HARNESS / 'forensics', tmp / 'forensics')
            src = (tmp / 'forensics' / 'bounds.py').read_text()
            if src.count(old) != 1:
                print(f'mutation {i} INVALID: text found {src.count(old)} times'); rc = 4; continue
            (tmp / 'forensics' / 'bounds.py').write_text(src.replace(old, new, 1))
            try:
                mf = kats(tmp)
            except Exception as e:                                   # noqa: BLE001
                print(f'mutation {i} INVALID: {type(e).__name__}: {e}'); rc = 4; continue
            if mf:
                caught += 1
                print(f'mutation {i} CAUGHT: {mf[0][:110]}')
            else:
                print(f'mutation {i} NOT CAUGHT: {old.strip()[:80]}'); rc = 4
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print(f'mutations caught {caught}/{len(MUTATIONS)}')
    return rc


if __name__ == '__main__':
    sys.exit(main())
