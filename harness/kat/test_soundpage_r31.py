#!/usr/bin/env python3
"""test_soundpage_r31.py — r31 (rft §7 B273, R31-5): the soundness page's header and section-0 text follow the registry.
At the R30 publish the r30 page read "(in progress)" though r30 was measured, "Re-verified in R30–R30" / "Rounds 30–30",
and "Round 30 pipeline: pending until its records exist" right after the run-10 line (harness/kit/soundpage.py).

  SP1 the current round IS the newest measured one (r30 measured): the <h1> says '(measured)'; the pill reads
      'Re-verified in R30' and the heading '0 · What Round 30 re-checked' (no 'R30–R30', no 'Rounds 30–30'); no
      'pending until its records exist' line or sentence; the h1 has a claim entry with the same text
  SP2 the current round is open (r31 in-progress, newest measured r30): '(in progress)', 'Re-verified in R30–R31',
      '0 · What Rounds 30–31 re-checked', the 'Round 31 pipeline: pending until its records exist' line and the
      'Round 31 is in progress' sentence are there
  SP3 write_gen on a forged page: the first use replaces the hand-typed <h1> and retires the hand claim whose exact
      match was that heading's text (no stale '(in progress)' claim is left); a second write changes nothing

SP1/SP2 read this tree's records with a forged registry (the module's _reg/current replaced); SP3 is all temp files.

  python3 -I harness/kat/test_soundpage_r31.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, copy, importlib.util, io, json, re, sys, tempfile, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'sp': 'harness/kit/soundpage.py'}


def load(over):
    path = Path(over.get('sp') or (ROOT / PATHS['sp']))
    spec = importlib.util.spec_from_file_location(f'sp31_{uuid.uuid4().hex[:6]}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.ROOT = ROOT
    return m


def registry(cur, add=None):
    reg = copy.deepcopy(json.loads((ROOT / 'harness/round.json').read_text()))
    ids = [r.get('id') for r in reg['rounds']]
    reg['rounds'] = reg['rounds'][:ids.index('r30') + 1]   # r32a: every round after r30 goes (a later measured round broke SP1/SP2)
    for r in reg['rounds']:
        if r.get('id') == 'r30':
            r['status'] = 'measured'
    if add:
        reg['rounds'].append(add)
    reg['current'] = cur
    return reg


def blocks(m, reg):
    m._reg = lambda root, _r=reg: _r
    m.current = lambda root=None, _c=reg['current']: _c
    out = {n: (h, e) for n, h, e in m.gen_blocks(ROOT)}
    txt = lambda n: re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', out.get(n, ('', []))[0]))
    return out, txt


def kat_sp1(over):
    m = load(over)
    out, txt = blocks(m, registry('r30'))
    t, s0 = txt('title'), txt('section0')
    bad = []
    if 'Round 30 soundness review (measured):' not in t:
        bad.append(f'title {t!r}')
    if 'Re-verified in R30 ' not in s0 + ' ' or '0 · What Round 30 re-checked' not in s0:
        bad.append('single-round range text')
    if 'R30–R30' in s0 or '30–30' in s0:
        bad.append('a 30–30 range')
    if 'pending until its records exist' in s0:
        bad.append('a stale pending line/sentence')
    ents = [e['match'] for e in out.get('title', ('', []))[1]]
    if not ents or 'Round 30 soundness review (measured)' not in ents[0]:
        bad.append(f'title claim {ents}')
    return not bad, '; '.join(bad) or 'measured: R30, Round 30, no pending line'


def kat_sp2(over):
    m = load(over)
    _, txt = blocks(m, registry('r31', {'id': 'r31', 'status': 'in-progress', 'pipeline_full': 'pending',
                                         'evidence': 'R31 opened 2026-11-13'}))
    t, s0 = txt('title'), txt('section0')
    bad = []
    if 'Round 31 soundness review (in progress):' not in t:
        bad.append(f'title {t!r}')
    if 'Re-verified in R30–R31' not in s0 or '0 · What Rounds 30–31 re-checked' not in s0:
        bad.append('two-round range text')
    if 'Round 31 pipeline: pending until its records exist' not in s0 or 'Round 31 is in progress' not in s0:
        bad.append('the open round\'s pending line/sentence missing')
    return not bad, '; '.join(bad) or 'open: R30–R31, pending line kept'


def kat_sp3(over):
    m = load(over)
    with tempfile.TemporaryDirectory() as d:
        r = Path(d)
        (r / 'harness/loop').mkdir(parents=True)
        (r / 'artifacts').mkdir()
        (r / 'harness/round.json').write_text(json.dumps({'current': 'r30', 'rounds': []}))
        hand = 'Round 30 soundness review (in progress): inflation, double-spend and range proofs, re-verified'
        (r / 'artifacts/dero-soundness-r30.html').write_text(
            '<header><h1>Round 30 soundness review (in progress): <span>inflation, double-spend and range proofs, re-verified</span></h1>'
            '</header><p>body</p>')
        (r / m.CLAIMS).write_text(json.dumps({'claims': [{'id': 'head-x', 'kind': 'scope', 'match': hand, 'exact': True},
                                                          {'id': 'other', 'kind': 'scope', 'match': 'body', 'exact': True}]}))
        new_h1 = '<h1>Round 30 soundness review (measured): <span>inflation, double-spend and range proofs, re-verified</span></h1>'
        m.gen_blocks = lambda root=None: [('title', new_h1, [m._ent('title', 'Round 30 soundness review (measured): x', 's', [], 'scope')])]
        ch1, _ = m.write_gen(r)
        page = (r / 'artifacts/dero-soundness-r30.html').read_text()
        ids = [c['id'] for c in json.loads((r / m.CLAIMS).read_text())['claims']]
        ch2, _ = m.write_gen(r, check=True)
        bad = []
        if not ch1 or '(in progress)' in page or '<!--gen:title:begin-->' + new_h1 not in page:
            bad.append(f'first use did not replace the hand h1: {page[:200]}')
        if 'head-x' in ids or 'other' not in ids or 'gen-title' not in ids:
            bad.append(f'claims {ids}')
        if ch2:
            bad.append('a second write is not a no-op')
    return not bad, '; '.join(bad) or 'first use replaces + retires; idempotent'


KATS = [('SP1', kat_sp1), ('SP2', kat_sp2), ('SP3', kat_sp3)]
OWNERS = {'B273 status': ['SP1', 'SP2'], 'B273 range': ['SP1'], 'B273 pending': ['SP1', 'SP2'], 'B273 first-use': ['SP3']}
MUTATIONS = [   # (file key, find, replace, why — the first two words name the defect, see OWNERS)
    ('sp', "    return {'in-progress': 'in progress'}.get(st, st)", "    return 'in progress'", 'B273 status: the h1 says in progress for a measured round'),
    ('sp', "    out.append(('title', f'<h1>Round", "    (('title', f'<h1>Round", 'B273 status: the h1 is not generated'),
    ('sp', "    return (one if str(a) == str(b) else many).format(a=a, b=b)", "    return many.format(a=a, b=b)",
     'B273 range: a single round reads R30–R30'),
    ('sp', "    if not own:                            # r31 (B273)", "    if True:                            # r31 (B273)",
     'B273 pending: the pending line follows the measured run line'),
    ('sp', "             + ('' if own else f'Round {n} is {st}: its own figures are pending until its records exist. ')",
     "             + f'Round {n} is {st}: its own figures are pending until its records exist. '", 'B273 pending: the intro keeps the pending sentence'),
    ('sp', "    own = prev == cur ", "    own = True ", 'B273 pending: an open round loses its pending line'),
    ('sp', "\n            and not (c.get('exact') and c.get('match') in first)]", "]", 'B273 first-use: the replaced hand claim is kept'),
    ('sp', "    'title': r'<h1>Round \\d+[a-z]? soundness review \\([^)]*\\):.*?</h1>',\n", "", 'B273 first-use: no place for the h1 block'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_sp31', HARNESS / 'kit' / 'katmut.py')
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
        print(f'\nr31 soundpage KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='sp31-mut-') as d:
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
    print('\n' + K.summary('r31 soundpage KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
