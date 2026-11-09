#!/usr/bin/env python3
"""test_peerkit_label_r29.py — r29 (found by the closing project-only run, 2026-11-08: S7 gen_deroarch svg_lint 1): with
inbound peers live (B1) a version-2 peer lagged 2,928,280 blocks and peerkit's bar label f'{v:g}' = '2.92828e+06' ran
5 px past the 640 px chart edge. The label is now compact and the tooltip keeps the exact value.

  PL1 a full-width bar of 2,928,280 keeps its label inside the viewBox (gen_deroarch.svg_lint's own measure, textkit CW)
      and its <title> carries 2,928,280 exactly
  PL2 small values keep their plain form (25 -> '25', 3.5 -> '3.5'); 12,345 -> '12,345'; 2,928,280 -> '2.93M'

  python3 -I harness/kat/test_peerkit_label_r29.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 missed
"""
import ast, contextlib, html, importlib.util, io, re, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'peerkit': 'harness/kit/peerkit.py'}


def mod(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def load(over):
    return mod(Path(over.get('peerkit') or (ROOT / PATHS['peerkit'])), 'peerkit_pl29')


def svg_lint(h):
    """gen_deroarch.svg_lint, compiled alone from the page builder (it does work at import)."""
    src = (HARNESS / 'gen_deroarch.py').read_text(encoding='utf-8')
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef) and n.name == 'svg_lint')
    ns = {'re': re, 'tk': mod(HARNESS / 'kit/textkit.py', 'textkit_pl29')}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), 'gen_deroarch.py', 'exec'), ns)   # noqa: S102 — own code
    return ns['svg_lint'](h)


def kat_pl1(over):
    m = load(over)
    h = m._hbar(html.escape, [('peer-a', 2928280), ('peer-b', 3)], 'blocks', 'lag', ref=25)
    bad = svg_lint(h)
    return not bad and 'peer-a: 2,928,280 blocks' in h, (bad, re.findall(r'<title>[^<]*</title>', h)[:1])


def kat_pl2(over):
    m = load(over)
    v = [m._num(x) for x in (25, 3.5, 12345, 2928280)]
    return v == ['25', '3.5', '12,345', '2.93M'], v


KATS = [('PL1', kat_pl1), ('PL2', kat_pl2)]
OWNERS = {'r29 peer-label': ['PL1', 'PL2']}
MUTATIONS = [
    ('peerkit', "def _hbar(E, items, unit, label, fmt=_num,", "def _hbar(E, items, unit, label, fmt=lambda v: f'{v:g}',",
     'r29 peer-label: the bar label is the raw %g form again'),
    ('peerkit', "    if a >= 1e6:\n        return f'{v / 1e6:.2f}M'\n", "",
     'r29 peer-label: millions are written in full'),
    ('peerkit', "{E(f\"{v:,}\" if isinstance(v, int) else fmt(v))} {E(unit)}</title>", "{E(fmt(v))} {E(unit)}</title>",
     'r29 peer-label: the tooltip loses the exact value'),
]


def katmut():
    return mod(HARNESS / 'kit' / 'katmut.py', 'katmut_pl29')


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
        print(f'\nr29 peer-label KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='pl29-mut-') as d:
            mut = Path(d) / 'peerkit.py'
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, _ = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r29 peer-label KATs', len(KATS), len(MUTATIONS), missed, 0))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
