#!/usr/bin/env python3
"""test_pages_preflight_r30.py — r30 post-close (B271a, D-25): a pipeline run whose COMMITTED generated pages are stale
or uncommitted fails in seconds at a 'pages' stage before S1, instead of 27 min later in S7. pipeline_20261113T022829
FAILED at test_ledger_pages_r30 'the soundness page generated blocks are stale' because rft rows feeding that page were
committed (b1c0131d, ee74da8e) without `regen_round --apply`.

  PP1 page_problems: all checks rc 0 and nothing dirty -> []; a check exit 3 names the check and regen_round; a dirty
      source names the file; both together -> both
  PP2 PAGE_CHECKS covers soundpage --check-gen/--check-known/--check-measured and gen_enhancements --check; PAGE_SOURCES
      names the rft, the round's soundness page and the enhancements page
  PP3 pages_preflight runs before s1_guard in BOTH the --project-only path and the full path, and FAILs with exit 10

  python3 -I harness/kat/test_pages_preflight_r30.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 missed
"""
import ast, contextlib, importlib.util, io, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'fbv': 'harness/pipeline/fix_build_verify.py'}
CONSTS = ('PAGE_CHECKS', 'PAGE_SOURCES')


def P(over):
    return Path(over.get('fbv') or (ROOT / PATHS['fbv']))


def tree(over):
    return ast.parse(P(over).read_text(encoding='utf-8'))


def extract(over):
    body = [n for n in tree(over).body if (isinstance(n, ast.FunctionDef) and n.name == 'page_problems') or
            (isinstance(n, ast.Assign) and any(getattr(t, 'id', '') in CONSTS for t in n.targets))]
    ns = {}
    exec(compile(ast.Module(body=body, type_ignores=[]), str(P(over)), 'exec'), ns)   # noqa: S102 — this repo's own code
    return ns


def kat_pp1(over):
    f = extract(over)['page_problems']
    ok = [(['harness/kit/soundpage.py', '--check-gen'], 0), (['artifacts/src/gen_enhancements.py', '--check'], 0)]
    stale = [(['harness/kit/soundpage.py', '--check-gen'], 3), (['artifacts/src/gen_enhancements.py', '--check'], 0)]
    a, b, c, d = f(ok, []), f(stale, []), f(ok, ['artifacts/dero-rft.md']), f(stale, ['artifacts/dero-rft.md'])
    good = (a == [] and len(b) == 1 and '--check-gen' in b[0] and 'regen_round' in b[0] and
            len(c) == 1 and 'artifacts/dero-rft.md' in c[0] and len(d) == 2)
    return good, (a, b, c, d)


def kat_pp2(over):
    ns = extract(over)
    checks = {' '.join(a) for a in ns['PAGE_CHECKS']}
    need = {'harness/kit/soundpage.py --check-gen', 'harness/kit/soundpage.py --check-known',
            'harness/kit/soundpage.py --check-measured', 'artifacts/src/gen_enhancements.py --check'}
    srcs = set(ns['PAGE_SOURCES'])
    needs = {'artifacts/dero-rft.md', 'artifacts/dero-soundness-{r}.html', 'artifacts/dero-enhancements-r28-r30.html'}
    return need <= checks and needs <= srcs, (sorted(need - checks), sorted(needs - srcs))


def kat_pp3(over):
    t = tree(over)
    fn = {n.name: ast.unparse(n) for n in t.body if isinstance(n, ast.FunctionDef)}
    main, pre = fn.get('main', ''), fn.get('pages_preflight', '')
    miss = []
    po = main.split("SUMMARY['mode'] = 'project-only'", 1)
    if len(po) < 2 or not po[1].split('s1_guard()', 1)[0].count('pages_preflight()'):
        miss.append('project-only: pages_preflight before s1_guard')
    full = main.rsplit('s2_format()', 1)[0].rsplit('s1_guard()', 1)
    if len(full) < 2 or 'pages_preflight()' not in full[0].rsplit('finish(0)', 1)[-1]:
        miss.append('full: pages_preflight before s1_guard')
    for need in ('page_problems(checks, dirty)', "event('pages', 'FAIL'", 'finish(10)', 'PAGE_CHECKS', 'PAGE_SOURCES'):
        if need not in pre:
            miss.append(f'pages_preflight: {need}')
    return not miss, miss


KATS = [('PP1', kat_pp1), ('PP2', kat_pp2), ('PP3', kat_pp3)]
OWNERS = {'r30 pages-preflight': [k for k, _ in KATS]}
MUTATIONS = [
    ('fbv', "           for a, rc in checks if rc != 0]", "           for a, rc in checks if rc not in (0, 3)]",
     'r30 pages-preflight: a stale page (exit 3) passes'),
    ('fbv', "    out += [f'uncommitted: {d} (the KATs read the committed pages: regen_round --apply, then commit)' for d in dirty]\n",
     "", 'r30 pages-preflight: uncommitted page sources pass'),
    ('fbv', "['harness/kit/soundpage.py', '--check-gen'], ['harness/kit/soundpage.py', '--check-known'],",
     "['harness/kit/soundpage.py', '--check-known'],", 'r30 pages-preflight: the generated-blocks check is dropped'),
    ('fbv', "        pages_preflight()                     # r30 post-close (B271a): stale committed pages fail in seconds, not at S7\n",
     "", 'r30 pages-preflight: the project-only path skips it'),
    ('fbv', "    pages_preflight()                         # r30 post-close (B271a)\n", "",
     'r30 pages-preflight: the full path skips it'),
    ('fbv', "        event('pages', 'FAIL', why=probs)\n        finish(10)", "        event('pages', 'WARN', why=probs)",
     'r30 pages-preflight: stale pages only warn'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_pp30', HARNESS / 'kit' / 'katmut.py')
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
        print(f'\nr30 pages-preflight KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='pp30-mut-') as d:
            mut = Path(d) / PATHS[key]
            mut.parent.mkdir(parents=True, exist_ok=True)
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, _ = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r30 pages-preflight KATs', len(KATS), len(MUTATIONS), missed, 0))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
