#!/usr/bin/env python3
"""test_doc_currency_r31.py — r31 (rft §7 B332): hand-written round summaries must be reviewed for the newest measured
round (harness/intel/doc_currency.py; DOC_CURRENCY.json lists the docs; regen_round runs it as a page gate).

  DC1 newest_measured: the last `measured` registry round (an in-progress or planned one after it does not count)
  DC2 problems: the current marker passes; an older marker, no marker and a missing file are each one problem naming the
      doc and the round; the LAST marker in a doc counts
  DC3 the repo's own listed docs are current (main exit 0) and DOC_CURRENCY.json lists harness/README.md and RPC_METHODS.md

  python3 -I harness/kat/test_doc_currency_r31.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 missed
"""
import contextlib, importlib.util, io, json, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'dc': 'harness/intel/doc_currency.py'}


def load(over):
    p = Path(over.get('dc') or (ROOT / PATHS['dc']))
    spec = importlib.util.spec_from_file_location(f'dc_{abs(hash(str(p)))}', p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def kat_dc1(over):
    m = load(over)
    reg = {'rounds': [{'id': 'r30', 'status': 'measured'}, {'id': 'r31', 'status': 'measured'}, {'id': 'r32', 'status': 'in-progress'}]}
    a, b = m.newest_measured(reg), m.newest_measured({'rounds': [{'id': 'r1', 'status': 'planned'}]})
    return (a, b) == ('r31', None), (a, b)


def kat_dc2(over):
    m = load(over)
    docs = [{'path': 'a'}, {'path': 'b'}, {'path': 'c'}, {'path': 'd'}, {'path': 'e'}]
    texts = {'a': 'x <!-- doc-current-through: r31 -->', 'b': 'x <!-- doc-current-through: r28 -->', 'c': 'no marker',
             'd': None, 'e': '<!-- doc-current-through: r31 --> later <!-- doc-current-through: r30 -->'}
    probs = m.problems(docs, texts, 'r31')
    paths = sorted(p for p, _ in probs)
    good = paths == ['b', 'c', 'd', 'e'] and all('r31' in w or 'missing' in w for _, w in probs)
    return good, probs


def kat_dc3(over):
    m = load(over)
    with contextlib.redirect_stdout(io.StringIO()):
        rc = m.main(ROOT)
    listed = {d['path'] for d in json.loads((ROOT / 'harness/loop/DOC_CURRENCY.json').read_text())['docs']}
    with tempfile.TemporaryDirectory(prefix='dc31-root-') as d:   # a doc behind must fail the tool (exit 5)
        r = Path(d)
        (r / 'harness/loop').mkdir(parents=True)
        (r / 'harness/round.json').write_text(json.dumps({'rounds': [{'id': 'r31', 'status': 'measured'}]}))
        (r / 'harness/loop/DOC_CURRENCY.json').write_text(json.dumps({'docs': [{'path': 'doc.md'}]}))
        (r / 'doc.md').write_text('<!-- doc-current-through: r30 -->')
        with contextlib.redirect_stdout(io.StringIO()):
            rc_behind = m.main(r)
    return rc == 0 and rc_behind == 5 and {'harness/README.md', 'cmd/derod/rpc/RPC_METHODS.md'} <= listed, (rc, rc_behind, sorted(listed))


KATS = [('DC1', kat_dc1), ('DC2', kat_dc2), ('DC3', kat_dc3)]
OWNERS = {'r31 doc-currency': [k for k, _ in KATS]}
MUTATIONS = [
    ('dc', "    ids = [r['id'] for r in reg.get('rounds', []) if r.get('status') == 'measured']",
     "    ids = [r['id'] for r in reg.get('rounds', [])]", 'r31 doc-currency: an unmeasured round counts'),
    ('dc', "        elif marks[-1] != want:", "        elif marks[0] != want:", 'r31 doc-currency: the first marker counts'),
    ('dc', "        if not marks:\n", "        if False:\n", 'r31 doc-currency: a doc without a marker passes'),
    ('dc', "    return 0 if not probs else 5", "    return 0", 'r31 doc-currency: a doc behind exits 0'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_dc31', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run_kats(over):
    res = []
    for name, fn in KATS:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                ok, det = fn(over)
        except (Exception, SystemExit) as e:                      # noqa: BLE001 — a crash is a failure
            ok, det = False, f'{type(e).__name__}: {e}'
        res.append((name, ok, str(det)))
    return res


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr31 doc-currency KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='dc31-mut-') as d:
            mut = Path(d) / 'doc_currency.py'
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, _ = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r31 doc-currency KATs', len(KATS), len(MUTATIONS), missed, 0))
    return 0 if not missed else 4


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
