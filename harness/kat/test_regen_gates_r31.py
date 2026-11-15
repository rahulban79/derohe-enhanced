#!/usr/bin/env python3
"""test_regen_gates_r31.py — r31 (rft §7 B271, R31-3): the page-level gates run on the regenerated pages BEFORE any
closing project-only run (harness/pipeline/regen_round.py --apply, or --gates alone). The R30 closing runs 1-4 each
failed on ONE page-level defect (B263, B264, the pdfscan IPv4 false positive, B265) that these checks find in minutes.

  RG1 gate_plan: G30 (facts.py --g30), the FE8 forensics-frontend KAT, pdfscan of every artifacts/*.pdf, a pubscrub dry
      run of the published pages (the current round's ledger and soundness page, src-arch, index, enhancements) into a
      scratch out dir outside the tree, read-only (-B) with DERO_PDFSCAN = the tree's pdfscan, and coherence; no PDF ->
      pdfscan SKIP with its reason; no pubscrub -> SKIP naming it (never a silent PASS)
  RG2 page_gates: rc 0 = PASS, any other = FAIL, a SKIP is never run; gates_rc = 6 on any FAIL, 0 on PASS/SKIP only;
      the scratch out dir is created under REGEN_SCRATCH and removed after the run
  RG3 main: --apply runs the gates after the regeneration (gate FAIL -> 6; coherence drift with gates PASS -> 4); a
      failed step (3) stops before the gates; --gates runs only the gates

All inputs are forged in temporary directories; no gate command is run (the runner is injected).

  python3 -I harness/kat/test_regen_gates_r31.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, importlib.util, io, json, os, sys, tempfile, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'rg': 'harness/pipeline/regen_round.py'}


def load(over):
    path = Path(over.get('rg') or (ROOT / PATHS['rg']))
    spec = importlib.util.spec_from_file_location(f'rg31_{uuid.uuid4().hex[:6]}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def forge(d, cur='r31', pdf=True, pub=True):
    r = Path(d) / 'tree'
    (r / 'harness/kit').mkdir(parents=True, exist_ok=True)
    (r / 'artifacts').mkdir(exist_ok=True)
    (r / 'harness/round.json').write_text(json.dumps({'current': cur}))
    for f in ('dero-r1-r31.html', 'dero-r1-r30.html', 'dero-soundness-r31.html', 'dero-soundness-r30.html', 'dero-src-arch.html',
              'index.html', 'dero-enhancements-r28-r30.html'):
        (r / 'artifacts' / f).write_text('x')
    if pdf:
        (r / 'artifacts/dero-r1-r31.pdf').write_bytes(b'%PDF')
    ps = Path(d) / 'tools/pubscrub.py'
    if pub:
        ps.parent.mkdir(exist_ok=True)
        ps.write_text('pass\n')
    return r, ps


def kat_rg1(over):
    m = load(over)
    bad = []
    with tempfile.TemporaryDirectory() as d:
        r, ps = forge(d)
        g = m.gate_plan(r, ps, Path(d) / 'out')
        names = [x[0] for x in g]
        if names != ['G30 forensics frontend', 'FE8 forensics frontend KAT', 'pdfscan', 'pubscrub dry run', 'coherence']:
            bad.append(f'gates {names}')
        G = {x[0]: x for x in g}
        a = lambda n: ' '.join(str(v) for v in (G.get(n, (0, None))[1] or []))
        if 'harness/forensics/facts.py --g30' not in a('G30 forensics frontend'):
            bad.append('G30 argv')
        if 'harness/kat/test_forensics_frontend2_r26.py' not in a('FE8 forensics frontend KAT'):
            bad.append('FE8 argv')
        if 'harness/kit/pdfscan.py artifacts/dero-r1-r31.pdf' not in a('pdfscan'):
            bad.append(f"pdfscan argv {a('pdfscan')}")
        pa = (G.get('pubscrub dry run') or (0, None, None, {}))
        pv = [str(v) for v in (pa[1] or [])]
        need = ['artifacts/dero-r1-r31.html', 'artifacts/dero-soundness-r31.html', 'artifacts/dero-src-arch.html',
                'artifacts/index.html', 'artifacts/dero-enhancements-r28-r30.html']
        if not pv or '-B' not in pv or str(ps) not in pv or str(Path(d) / 'out') not in pv or [x for x in need if x not in pv]:
            bad.append(f'pubscrub argv {pv}')
        if 'artifacts/dero-r1-r30.html' in pv or 'artifacts/dero-soundness-r30.html' in pv:
            bad.append('pubscrub reads a closed round page')
        if pa[3].get('DERO_PDFSCAN') != str(r / 'harness/kit/pdfscan.py'):
            bad.append(f'DERO_PDFSCAN {pa[3]}')
        if 'harness/intel/coherence.py' not in a('coherence'):
            bad.append('coherence argv')
    with tempfile.TemporaryDirectory() as d:
        r, ps = forge(d, pdf=False, pub=False)
        G = {x[0]: x for x in m.gate_plan(r, ps, Path(d) / 'out')}
        for n, word in (('pdfscan', 'no PDF'), ('pubscrub dry run', 'pubscrub')):
            x = G.get(n)
            if not x or x[1] is not None or not x[2] or word not in x[2]:
                bad.append(f'{n} without its input is not a SKIP with a reason: {x}')
    return not bad, '; '.join(bad) or 'five gates; SKIP with reasons'


def kat_rg2(over):
    m = load(over)
    bad = []
    with tempfile.TemporaryDirectory() as d:
        r, ps = forge(d, pdf=False)
        scratch = Path(d) / 'scratch'
        scratch.mkdir()
        ran, outs = [], []
        # a fixed plan (the plan itself is RG1's): page_gates only runs it, passing the scratch out dir it created
        m.gate_plan = lambda root, pubscrub=None, out_dir=None: (outs.append(Path(out_dir)), [
            ('A', ['a', '--fail'], None, {}), ('B', ['b', str(out_dir)], None, {}), ('C', None, 'no input', {})])[1]

        def run(argv, cwd, env):
            ran.append(argv[0])
            if argv[0] == 'b':
                return (0, ['ok']) if Path(argv[1]).is_dir() else (7, ['out dir missing'])
            return (1, ['FAIL']) if '--fail' in argv else (0, ['ok'])
        res = m.page_gates(r, run=run, log=lambda *a: None, pubscrub=ps, scratch=str(scratch))
        V = {n: v for n, v, _ in res}
        if V != {'A': 'FAIL', 'B': 'PASS', 'C': 'SKIP'}:
            bad.append(f'verdicts {V}')
        if ran != ['a', 'b']:
            bad.append(f'ran {ran} (a SKIP gate is never run)')
        if not outs or outs[0].parent != scratch or outs[0].exists():
            bad.append(f'out dir {outs} not under scratch / not removed')
        if m.gates_rc(res) != 6 or m.gates_rc([(n, 'PASS' if v == 'FAIL' else v, '') for n, v, _ in res]) != 0:
            bad.append('gates_rc')
    return not bad, '; '.join(bad) or 'PASS/FAIL/SKIP; rc 6; out dir removed'


def kat_rg3(over):
    bad = []
    cwd = os.getcwd()
    try:
        for argv, app_rc, gate_v, want, want_calls in ((['--apply'], 0, 'FAIL', 6, ['apply', 'gates']),
                                                       (['--apply'], 4, 'PASS', 4, ['apply', 'gates']),
                                                       (['--apply'], 0, 'PASS', 0, ['apply', 'gates']),
                                                       (['--apply'], 3, 'PASS', 3, ['apply']),
                                                       (['--gates'], 0, 'FAIL', 6, ['gates'])):
            m = load(over)
            calls = []
            with tempfile.TemporaryDirectory() as d:
                m.ROOT = Path(d)
                m.apply = lambda root, run=None, log=print, clock=None, _r=app_rc: (calls.append('apply'), (_r, []))[1]
                m.page_gates = lambda root, _v=gate_v, **k: (calls.append('gates'), [('g', _v, '')])[1]
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = m.main(argv)
            if rc != want or calls != want_calls:
                bad.append(f'{argv} apply {app_rc} gates {gate_v}: rc {rc} calls {calls} (want {want} {want_calls})')
    finally:
        os.chdir(cwd)
    return not bad, '; '.join(bad) or 'gates after --apply; 3 stops; --gates alone'


KATS = [('RG1', kat_rg1), ('RG2', kat_rg2), ('RG3', kat_rg3)]
OWNERS = {'B271 plan': ['RG1'], 'B271 run': ['RG2'], 'B271 rc': ['RG2', 'RG3'], 'B271 main': ['RG3']}  # main exits by gates_rc
MUTATIONS = [   # (file key, find, replace, why — the first two words name the defect, see OWNERS)
    ('rg', "    g = [('G30 forensics frontend', [PY, '-I', 'harness/forensics/facts.py', '--g30'], None, {}),\n         (",
     "    g = [(", 'B271 plan: G30 is not run on the regenerated pages'),
    ('rg', "         ('FE8 forensics frontend KAT', [PY, '-I', 'harness/kat/test_forensics_frontend2_r26.py'], None, {}),\n", "",
     'B271 plan: the FE8 KAT is not run'),
    ('rg', "    g.append(('coherence', [PY, '-I', 'harness/intel/coherence.py'], None, {}))\n", "", 'B271 plan: coherence is not run'),
    ('rg', "[PY, '-I', 'harness/kit/pdfscan.py'] + pdfs if pdfs else None,", "None,", 'B271 plan: a PDF present is never scanned'),
    ('rg', "    if not pubscrub.is_file():", "    if False:", 'B271 plan: a missing pubscrub is not a SKIP'),
    ('rg', "        g.append(('pubscrub dry run', [PY, '-I', '-B', str(pubscrub)", "        g.append(('pubscrub dry run', [PY, '-I', str(pubscrub)",
     'B271 plan: pubscrub may write __pycache__ beside the tool'),
    ('rg', "                  {'DERO_PDFSCAN': str(root / 'harness/kit/pdfscan.py')}))", "                  {}))",
     'B271 plan: pubscrub scans PDFs with another tree\'s pdfscan'),
    ('rg', "        if '{n}' in pat and not m:\n            continue\n        pat = pat.format(n=m.group(1) if m else '', r=r)",
     "        pat = pat.replace('{n}', '*').replace('{r}', '*')", 'B271 plan: pubscrub reads every round\'s pages'),
    ('rg', "                res.append((name, 'PASS' if rc == 0 else 'FAIL',", "                res.append((name, 'PASS',",
     'B271 run: a failing gate is called PASS'),
    ('rg', "    return GATE_FAIL if any(v == 'FAIL' for _, v, _ in results) else 0", "    return 0", 'B271 rc: a FAILED gate exits 0'),
    ('rg', "        shutil.rmtree(out_dir, ignore_errors=True)", "        pass", 'B271 run: the scratch out dir is left behind'),
    ('rg', "    grc = gates_rc(page_gates(ROOT))                       # r31 (B271)", "    grc = 0  # (page_gates(ROOT))                       # r31 (B271)",
     'B271 main: --apply skips the page gates'),
    ('rg', "    if rc == 3:\n        return rc\n    grc", "    grc", 'B271 main: the gates run after a failed step'),
    ('rg', "    if '--gates' in argv and '--apply' not in argv:", "    if False:", 'B271 main: --gates alone does not run the gates'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_rg31', HARNESS / 'kit' / 'katmut.py')
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
        print(f'\nr31 regen-gates KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='rg31-mut-') as d:
            mut = Path(d) / PATHS[key]
            mut.parent.mkdir(parents=True, exist_ok=True)
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            try:
                compile(mut.read_text(encoding='utf-8'), str(mut), 'exec')
            except SyntaxError as e:
                print(f'  INVALID   {why}: mutant does not load ({e})')
                missed += 1
                continue
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, cpl = K.classify(failed, OWNERS.get(defect(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
        coupled += bool(cpl)
    print('\n' + K.summary('r31 regen-gates KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
