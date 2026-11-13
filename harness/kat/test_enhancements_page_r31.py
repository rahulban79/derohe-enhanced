#!/usr/bin/env python3
"""test_enhancements_page_r31.py — the generated "DERO HE Rounds 28–30" page (artifacts/src/gen_enhancements.py; user
2026-11-12, rft §2.27): no anchor, no figure.

  EP1 numbers() takes the whole numbers a result states ('13.1k' -> 13.1, '8192,3,2' kept whole) and none from an
      identifier ('G17', 'r30')
  EP2 problems(): a figure on a line naming the row's ref is backed; the same figure on a line naming another row is
      not; an absent §7 ref is refused; a row with no refs is refused
  EP3 the real data file is fully backed by the real dero-rft.md and the committed page is exactly what render() makes

  python3 -I harness/kat/test_enhancements_page_r31.py      # exit 0 · 3 a KAT failed · 4 a mutation was missed
"""
import contextlib, importlib.util, io, json, sys, tempfile, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'gen': 'artifacts/src/gen_enhancements.py'}


def load(over):
    root = Path(over.get('root') or ROOT)
    spec = importlib.util.spec_from_file_location(f'enh31_{uuid.uuid4().hex[:6]}', root / PATHS['gen'])
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def kat_ep1(over):
    m = load(over)
    got = (m.numbers('10.6–13.1k H/s → 96–97k'), m.numbers('GSPLIT 8192,3,2 · --gpu-max 100'), m.numbers('G17 ok in r30'),
           m.numbers('542,692 of 2,141,434'))
    ok = got == (['10.6', '13.1', '96', '97'], ['8192,3,2', '100'], [], ['542,692', '2,141,434'])
    return ok, got


RFT = ('| B1 | the miner ran 10.6–13.1k H/s and now 96–97k H/s | miner | a | FIXED |\n'
       '| B2 | another row that says 555 | x | a | OPEN |\n'
       'a §13 line: B1 read live at 42 H/s\n')


def kat_ep2(over):
    m = load(over)
    row = lambda res, refs: {'title': 't', 'result': res, 'refs': refs}
    cases = {
        'backed': m.problems({'rows': [row('10.6–13.1k → 96–97k', ['B1'])]}, RFT),
        'other_line': m.problems({'rows': [row('555 shares', ['B1'])]}, RFT),
        'section13': m.problems({'rows': [row('42 H/s', ['B1'])]}, RFT),
        'missing_ref': m.problems({'rows': [row('no number', ['B9'])]}, RFT),
        'no_refs': m.problems({'rows': [row('x', [])]}, RFT),
    }
    ok = (cases['backed'] == [] and cases['section13'] == [] and len(cases['other_line']) == 1
          and 'B9 is not a §7 row' in str(cases['missing_ref']) and 'no refs' in str(cases['no_refs']))
    return ok, cases


def kat_ep3(over):
    m = load(over)
    doc = json.loads((ROOT / m.DATA).read_text(encoding='utf-8'))
    probs = m.problems(doc, (ROOT / m.RFT).read_text(encoding='utf-8'))
    page = (ROOT / m.OUT).read_text(encoding='utf-8')
    return probs == [] and m.render(doc) == page and len(doc['rows']) >= 20, (probs[:3], len(doc['rows']))


KATS = [('EP1', kat_ep1), ('EP2', kat_ep2), ('EP3', kat_ep3)]
OWNERS = {'r31 EP-num': ['EP1'], 'r31 EP-back': ['EP2'], 'r31 EP-page': ['EP3']}
MUTATIONS = [
    ('gen', "NUM_RX = re.compile(r'(?<![\\w.,])\\d[\\d,]*(?:\\.\\d+)?')", "NUM_RX = re.compile(r'\\d[\\d,]*(?:\\.\\d+)?')",
     'r31 EP-num: numbers are read inside identifiers (G17, r30)'),
    ('gen', "    return [l for l in rft_text.splitlines() if rx and rx.search(l)]", "    return rft_text.splitlines()",
     'r31 EP-back: a figure on any rft line counts as backed'),
    ('gen', "            if b not in rows7:", "            if False:", 'r31 EP-back: a missing §7 ref passes'),
    ('gen', "        if not refs:\n            out.append((r.get('title'), 'no refs'))", "        if False:\n            out.append((r.get('title'), 'no refs'))",
     'r31 EP-back: a row with no refs passes'),
    ('gen', "        for r in [r for r in doc['rows'] if r['layer'] == l['id']]:", "        for r in [r for r in doc['rows'] if r['layer'] == l['id']][:1]:",
     'r31 EP-page: rows are dropped from the page'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_ep31', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def defect(why):
    return ' '.join(why.split(':')[0].split()[:2])


def run_kats(over):
    res = []
    for name, fn in KATS:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                ok, det = fn(over)
        except (Exception, SystemExit) as e:                      # noqa: BLE001 — a crash is a failure
            ok, det = False, f'{type(e).__name__}: {e}'
        res.append((name, bool(ok), str(det)))
    return res


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr31 enhancements-page KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='ep31-mut-') as d:
            mut = Path(d) / PATHS[key]
            mut.parent.mkdir(parents=True)
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({'root': d}) if not ok]
        verdict, cpl = K.classify(failed, OWNERS.get(defect(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
        coupled += bool(cpl)
    print('\n' + K.summary('r31 enhancements-page KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
