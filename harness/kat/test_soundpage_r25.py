#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the per-round soundness page (harness/kit/soundpage.py, r25, rft §0.6).

From R25 the soundness review is one page per round, like the ledger: artifacts/dero-soundness-<current>.html, where
<current> is harness/round.json `current`; earlier pages stay unchanged as history (old ledger pages link them).

  SP1 name/rel follow the registry's current round in a planted tree (r25 -> dero-soundness-r25.html, r26 ->
      dero-soundness-r26.html); a registry with no usable current round raises (never a silent default)
  SP2 history lists the other dero-soundness-r*.html pages oldest first and never the current one
  SP3 the real tree: the current round's page exists, and the claim registry (harness/loop/SOUNDNESS_CLAIMS.json)
      names exactly that page
  SP4 no stale hard-coded soundness page name: none of the tools that need the page (gen_index, run_gates, soundness,
      intel/coherence, intel/tooling_intel, kat/test_coherence_r24) carries a literal dero-soundness-r<N>.html; the
      scanner itself flags a planted literal (control)
  SP5 the current ledger page (dero-r1-r<current>.html), when it exists, links the current soundness page

  python3 -I harness/kat/test_soundpage_r25.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import importlib.util, json, re, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
SRC = HARNESS / 'kit' / 'soundpage.py'
TOOLS = ['harness/gen_index.py', 'harness/run_gates.py', 'harness/soundness.py', 'harness/intel/coherence.py',
         'harness/intel/tooling_intel.py', 'harness/kat/test_coherence_r24.py']
LITERAL = re.compile(r'dero-soundness-r\d+[a-z]?\.html')


def load(path):
    spec = importlib.util.spec_from_file_location(f'soundpage_kat_{abs(hash(str(path)))}_{len(sys.modules)}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def stale_literals(root, files=TOOLS):
    """[(file, line, literal)] every hard-coded soundness page name in the tools. Pure but for the reads."""
    out = []
    for f in files:
        p = Path(root) / f
        if not p.is_file():
            continue
        for i, l in enumerate(p.read_text(errors='replace').splitlines(), 1):
            for m in LITERAL.finditer(l):
                out.append((f, i, m.group(0)))
    return out


def tree(td, cur, pages=()):
    t = Path(td)
    (t / 'harness').mkdir(parents=True, exist_ok=True)
    (t / 'artifacts').mkdir(exist_ok=True)
    (t / 'harness/round.json').write_text(json.dumps({'current': cur, 'rounds': [{'id': cur}]}))
    for n in pages:
        (t / 'artifacts' / n).write_text('<p>x</p>')
    return t


def kats(sp, real=True):
    bad = []
    with tempfile.TemporaryDirectory() as td:
        for cur in ('r25', 'r26'):
            t = tree(Path(td) / cur, cur, ['dero-soundness-r23.html', 'dero-soundness-r25.html', f'dero-soundness-{cur}.html'])
            if sp.name(t) != f'dero-soundness-{cur}.html' or sp.rel(t) != f'artifacts/dero-soundness-{cur}.html':
                bad.append(f'SP1 {cur}: name {sp.name(t)!r} rel {sp.rel(t)!r}')
            h = sp.history(t)
            want = [n for n in ('dero-soundness-r23.html', 'dero-soundness-r25.html') if n != f'dero-soundness-{cur}.html']
            if h != want:
                bad.append(f'SP2 {cur}: history {h}, want {want}')
        t = tree(Path(td) / 'none', 'r25')
        (t / 'harness/round.json').write_text(json.dumps({'rounds': []}))
        try:
            sp.name(t)
            bad.append('SP1 a registry with no current round gave a page name')
        except ValueError:
            pass
        if sp.page_round('dero-soundness-r23.html') != 'r23' or sp.page_round('dero-r1-r25.html') is not None:
            bad.append('SP1 page_round misreads a name')
        planted = Path(td) / 'planted'
        (planted / 'harness').mkdir(parents=True)
        (planted / 'harness/gen_index.py').write_text("SP = ART / 'dero-soundness-r23.html'\n")
        if not stale_literals(planted):
            bad.append('SP4 control: the scanner missed a planted literal')
    if real:
        cur = sp.rel(ROOT)
        if not (ROOT / cur).is_file():
            bad.append(f'SP3 the current round page {cur} is missing')
        reg = json.loads((HARNESS / 'loop/SOUNDNESS_CLAIMS.json').read_text())
        if reg.get('page') != cur:
            bad.append(f"SP3 SOUNDNESS_CLAIMS.json names {reg.get('page')!r}, the current page is {cur!r}")
        for f, i, lit in stale_literals(ROOT):
            bad.append(f'SP4 {f}:{i} hard-codes {lit}')
        m = re.match(r'r(\d+)', json.loads((HARNESS / 'round.json').read_text())['current'])
        lg = ROOT / 'artifacts' / f'dero-r1-r{m.group(1)}.html'
        if lg.is_file() and sp.name(ROOT) not in lg.read_text(errors='replace'):
            bad.append(f'SP5 {lg.name} does not link {sp.name(ROOT)}')
    return bad


MUTATIONS = [
    ('SP1', "    return f'dero-soundness-{current(root)}.html'", "    return 'dero-soundness-r23.html'", 'the page name is fixed again'),
    ('SP2', "if page_round(p.name) and p.name != cur]", "if page_round(p.name)]", 'history lists the current page'),
    ('SP2', "    return sorted(pages, key=lambda n: _key(page_round(n)))", "    return sorted(pages, reverse=True)", 'history order'),
    ('SP1', "        raise ValueError(f'harness/round.json has no usable current round: {cur!r}')", "        cur = 'r23'", 'a missing current round falls back to r23'),
]


def main():
    sp = load(SRC)
    bad = kats(sp)
    for b in bad:
        print('FAIL', b)
    ok = not bad
    print(f"{'ok  ' if ok else 'FAIL'} SP1-SP5: {len(bad)} failure(s)")
    src = SRC.read_text()
    missed = 0
    with tempfile.TemporaryDirectory() as td:
        for i, (cid, old, new, what) in enumerate(MUTATIONS):
            if old not in src:
                print(f'MISSED {cid}: mutation target not found ({what})')
                missed += 1
                continue
            mp = Path(td) / f'mut{i}.py'
            mp.write_text(src.replace(old, new, 1))
            try:
                caught = any(b.startswith(cid) for b in kats(load(mp), real=False))
                verdict = 'CAUGHT' if caught else 'MISSED'
            except Exception as e:                                     # noqa: BLE001 — a crash proves nothing
                caught, verdict = False, f'INVALID ({type(e).__name__})'
            missed += not caught
            print(f'{verdict} {cid}: {what}')
    print(f'\nr25 soundpage KATs: {"5/5" if ok else "FAIL"} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if not ok else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
