#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the seven harness miners that had no KAT (R28 tools-kats, N28-04:
harness/miners/mine_consts.py, mine_coverage.py, mine_findings.py, mine_flows.py, mine_inventory.py,
mine_logbridge.py, mine_press.py; tooling_intel kat_coverage 61/78 at harness/runtime/tooling_20261105T233116.json).

Every KAT runs on ONE APFS clone of the repository (cp -c, .git left out), after harness/prep_corpus.py has built the
untracked symbol table there (rft §6 step 13 order), under sandbox-exec (no network, no write outside the clone), with
HOME and the pseudonym salt (DERO_PEER_PRIVATE) inside the clone. The live tree, the live node and the user's salt are
never touched. The law each miner is held to is minelib's ('no anchor, no row'):

  L1 the miner exits 0;
  L2 every row has evidence, and every entry names a file, a line and a quote of >= minelib.MIN_Q characters that
     stands on that line of the clone's file (whitespace and typography normalised; a pseudonymised address compares
     through privkit.mask, as gen_deroarch.resolve_ev does);
  L3 a second run writes the same bytes (mine_coverage: once its own per-run snapshot name and capture time are masked);
  L4 it writes only its own raw file(s) (mine_coverage also its runtime/coverage_<ts>.json snapshot);
  L5 (negative) the source line under its first anchored row is blanked in the clone: no row cites that line any more,
     L2 still holds, and the row left `rows` (an 'unverified' entry or fewer rows) or now anchors elsewhere; the line
     is then restored and the miner re-run.

  MK1 mine_consts      L1-L5
  MK2 mine_press       L1-L5
  MK3 mine_findings    L1-L5
  MK4 mine_flows       L1-L5 + a chain is drawn whole or not at all (every flow row has evidence for each of its hops)
  MK5 mine_inventory   L1-L5 + the package rows cover the corpus pkgindex (one row or one unverified entry each)
  MK6 mine_logbridge   L1-L5 + one row per printed console line (overlapping captures are bridged once)
  MK7 mine_coverage    L1-L4 + known answer: a forged raw row citing the first line of an uncovered risk function
       makes exactly that function covered (risk_covered +1, it leaves the uncovered list); the per-package sums equal
       the total; removing the forged row restores the counts

Mutation independence (harness/kit/katmut.py): each mutation's reason starts with 'r28 MK<n>' and is proved only when
that KAT fails; a failure of another KAT is counted as coupled (target 0).

  python3 -I harness/kat/test_miners_r28.py [MK<n> ...]   (names restrict the mutations, never the KATs)
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught by its own KAT, was INVALID, or coupled.
"""
import importlib.util, json, os, re, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
SANDBOX = '/usr/bin/sandbox-exec'
PY = sys.executable
SNAP_RX = re.compile(r'coverage_\d{8}T\d{6}\.json|"captured": "[^"]*"')


def load(path, name):
    for m in ('minelib', 'privkit'):
        sys.modules.pop(m, None)
    spec = importlib.util.spec_from_file_location(f'{name}_{abs(hash(str(path)))}_{len(sys.modules)}', path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


def profile(root):
    return ('(version 1)\n(allow default)\n(deny network*)\n(deny signal (target others))\n'
            f'(deny file-write* (require-not (require-any (subpath "{os.path.realpath(root)}") (literal "/dev/null")'
            ' (literal "/dev/tty") (regex #"^/dev/fd/"))))\n')


def run(root, argv, path=None):
    e = {'PATH': path or os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(root / 'home'), 'TMPDIR': str(root / 'tmp'),
         'PYTHONDONTWRITEBYTECODE': '1', 'DERO_PEER_PRIVATE': str(root / 'home/peer_private')}
    cmd = [PY, '-I', '-B', *argv]
    if os.path.exists(SANDBOX):
        cmd = [SANDBOX, '-p', profile(root), *cmd]
    p = subprocess.run(['nice', '-n', '15', *cmd], cwd=root, capture_output=True, text=True, env=e, timeout=300)
    return p.returncode, p.stdout, p.stderr


def files_of(root, sub):
    d = Path(root) / sub
    return {p.name: p.read_bytes() for p in sorted(d.glob('*')) if p.is_file()} if d.is_dir() else {}


class Ctx:
    def __init__(self, root):
        self.root = Path(root)
        self.M = load(self.root / 'harness/miners/minelib.py', 'mk_minelib')
        sys.path.insert(0, str(self.root / 'harness/kit'))
        sys.modules.pop('privkit', None)
        import privkit
        self.mask = privkit.mask
        sys.path.pop(0)

    def raw(self, key):
        p = self.root / 'harness/model/raw' / f'{key}.json'
        return json.loads(p.read_text()) if p.exists() else {'rows': [], 'unverified': []}

    def line(self, rel, ln):
        p = self.root / rel
        try:
            ls = p.read_text(errors='replace').split('\n')
        except OSError:
            return None
        return ls[ln - 1] if isinstance(ln, int) and 1 <= ln <= len(ls) else None

    def law(self, doc):
        """L2: [(row id, why)] for every row without evidence and every entry whose quote is not on its line"""
        bad, N = [], self.M.norm
        for r in doc.get('rows', []):
            ev = r.get('evidence')
            if not ev:
                bad.append((r.get('id'), 'no evidence'))
            for e in ev or []:
                if not isinstance(e, dict) or not e.get('file') or not e.get('quote') or not e.get('line'):
                    bad.append((r.get('id'), f'malformed {str(e)[:60]}'))
                    continue
                q = N(e['quote'])
                if len(q) < self.M.MIN_Q:
                    bad.append((r.get('id'), f'quote under {self.M.MIN_Q} chars {q!r}'))
                    continue
                t = self.line(e['file'], e['line'])
                if t is None or (q not in N(t) and N(self.mask(e['quote'])) not in N(self.mask(t))):
                    bad.append((r.get('id'), f"not on {e['file']}:{e['line']}: {q[:50]!r}"))
        return bad


def generic(C, miner, key, extra=None, writes=()):
    root = C.root
    snap0 = {**files_of(root, 'harness/model/raw'), **{f'rt/{k}': v for k, v in files_of(root, 'harness/runtime').items()}}
    r1 = run(root, [f'harness/miners/{miner}'])
    d1 = C.raw(key)
    raw1 = (root / f'harness/model/raw/{key}.json').read_bytes() if (root / f'harness/model/raw/{key}.json').exists() else b''
    snap1 = {**files_of(root, 'harness/model/raw'), **{f'rt/{k}': v for k, v in files_of(root, 'harness/runtime').items()}}
    changed = sorted(k for k in set(snap0) | set(snap1) if snap0.get(k) != snap1.get(k))
    allowed = {f'{key}.json', *writes}
    stray = [k for k in changed if k not in allowed and not any(re.fullmatch(w, k) for w in writes)]
    r2 = run(root, [f'harness/miners/{miner}'])
    raw2 = (root / f'harness/model/raw/{key}.json').read_bytes() if (root / f'harness/model/raw/{key}.json').exists() else b''
    det = SNAP_RX.sub('#', raw1.decode('utf-8', 'replace')) == SNAP_RX.sub('#', raw2.decode('utf-8', 'replace'))
    bad = C.law(d1)
    neg = negative(C, miner, key, d1) if extra != 'no-negative' else (True, 'n/a')
    x_ok, x_det = (extra(C, d1) if callable(extra) else (True, ''))
    ok = r1[0] == 0 and r2[0] == 0 and d1['rows'] and not bad and det and not stray and neg[0] and x_ok
    return ok, (f"rc {r1[0]}/{r2[0]} rows {len(d1['rows'])} unverified {len(d1.get('unverified') or [])} · L2 bad {bad[:2]} · "
                f"L3 same {det} · L4 stray {stray[:3]} · L5 {neg[1]} · {x_det} {r1[2][-160:] if r1[0] else ''}")


def negative(C, miner, key, d1):
    """L5: blank the line under the first row's first anchor that is not a harness runtime/model file, re-run, check,
    restore, re-run"""
    root = C.root
    tgt = next(((r, e) for r in d1['rows'] for e in r.get('evidence') or []
                if isinstance(e, dict) and e.get('file') and not e['file'].startswith(('harness/runtime/', 'harness/model/'))
                and C.line(e['file'], e.get('line')) is not None), None)
    if not tgt:
        return False, 'no source anchor to remove'
    row, e = tgt
    p = root / e['file']
    orig = p.read_bytes()
    ls = orig.decode('utf-8', 'replace').split('\n')
    ls[e['line'] - 1] = '// removed by the r28 MK negative check'
    p.write_text('\n'.join(ls))
    try:
        r = run(root, [f'harness/miners/{miner}'])
        d2 = C.raw(key)
    finally:
        p.write_bytes(orig)
    still = [x.get('id') for x in d2['rows'] for y in x.get('evidence') or []
             if isinstance(y, dict) and y.get('file') == e['file'] and y.get('line') == e['line']]
    after = next((x for x in d2['rows'] if x.get('id') == row.get('id')), None)
    moved = after is None or after.get('evidence') != row.get('evidence')
    fewer = len(d2['rows']) < len(d1['rows']) or len(d2.get('unverified') or []) > len(d1.get('unverified') or [])
    bad = C.law(d2)
    run(root, [f'harness/miners/{miner}'])                    # restore the raw file from the restored source
    ok = r[0] == 0 and not still and not bad and moved and (fewer or after is not None)
    return ok, (f"blanked {e['file']}:{e['line']} (row {row.get('id')}): rc {r[0]} still cited by {still[:2]} · L2 bad {bad[:1]} · "
                f"row {'gone' if after is None else 're-anchored' if moved else 'UNCHANGED'} · fewer {fewer}")


def mk1(C):
    return generic(C, 'mine_consts.py', 'consts')


def mk2(C):
    return generic(C, 'mine_press.py', 'press')


def mk3(C):
    return generic(C, 'mine_findings.py', 'findings')


def _flows_whole(C, d):
    bad = [r['id'] for r in d['rows'] if r.get('section') == 'flows' and len(r.get('evidence') or []) != r.get('hops')]
    hops = {}
    for r in d['rows']:
        if r.get('section') == 'hops':
            hops[r['chain']] = hops.get(r['chain'], 0) + 1
    bad += [r['id'] for r in d['rows'] if r.get('section') == 'flows' and hops.get(r['chain']) != r.get('hops')]
    return not bad, f'chains not whole {bad[:3]}'


def mk4(C):
    return generic(C, 'mine_flows.py', 'flows', extra=_flows_whole)


def _inventory_cover(C, d):
    idx = json.loads((C.root / 'harness/corpus/pkgindex.json').read_text())
    pk = set(idx['packages'])
    rowp = {r.get('pkg') for r in d['rows'] if r.get('section') == 'packages'}
    unvp = {u['title'].split(' ', 1)[1] for u in d.get('unverified') or [] if str(u.get('title', '')).startswith('package ')}
    # a forged package with no Go file to anchor on (pkgindex is prep_corpus output; restored after) must become an
    # unverified entry, never a row and never nothing
    pi = C.root / 'harness/corpus/pkgindex.json'
    orig = pi.read_bytes()
    idx2 = json.loads(orig)
    idx2['packages']['ghostpkg'] = {'files': 1, 'loc': 1, 'test_files': 0, 'test_loc': 0, 'dirs': ['ghostpkg'], 'first_file': None}
    pi.write_text(json.dumps(idx2))
    try:
        r = run(C.root, ['harness/miners/mine_inventory.py'])
        d2 = C.raw('inventory')
    finally:
        pi.write_bytes(orig)
    run(C.root, ['harness/miners/mine_inventory.py'])
    ghost = (r[0] == 0 and any(u.get('title') == 'package ghostpkg' for u in d2.get('unverified') or [])
             and not any(x.get('pkg') == 'ghostpkg' for x in d2['rows']))
    return (pk == rowp | unvp and not rowp & unvp and ghost,
            f'packages {len(pk)} rows {len(rowp)} unverified {len(unvp)} · forged ghost package unverified {ghost}')


def mk5(C):
    return generic(C, 'mine_inventory.py', 'inventory', extra=_inventory_cover)


def _logbridge_once(C, d):
    seen, dup = set(), []
    for r in d['rows']:
        e = (r.get('evidence') or [{}])[0]
        q = (C.line(e.get('file'), e.get('line')) or '').strip()      # the whole printed line (quotes stop at 200)
        if q in seen:
            dup.append(r['id'])
        seen.add(q)
    return not dup, f'printed lines bridged twice {dup[:3]}'


def mk6(C):
    return generic(C, 'mine_logbridge.py', 'logbridge', extra=_logbridge_once)


def callers_equal_grep(C, n=4):
    """r28: mine_coverage counts callers in one in-process walk (go_call_lines / callers_of) instead of one recursive
    grep per risk function; for the n risk functions with the most caller files the set equals the old grep pipeline's
    (same filters: vendor/ and harness/ out, _test.go out, comment and declaration lines out)"""
    rows, seen = [], set()
    for r in sorted(C.raw('riskmap')['rows'], key=lambda r: (-r.get('caller_files', 0), r['id'])):
        if r['title'] not in seen and len(rows) < n:
            seen.add(r['title'])
            rows.append(r)
    MC = load(C.root / 'harness/miners/mine_coverage.py', 'mk7cov')
    lines = MC.go_call_lines(C.root)
    bad = []
    for r in rows:
        name = r['title']
        g = subprocess.run(['grep', '-rn', '--include=*.go', rf'\b{name}(', '.'], cwd=C.root, capture_output=True, text=True)
        ref = set()
        for hit in g.stdout.splitlines():
            cf, _, txt = hit.split(':', 2)
            cf = cf.lstrip('./')
            if cf.startswith(('vendor/', 'harness/')) or cf.endswith('_test.go') or txt.strip().startswith('//') \
                    or re.match(r'\s*func ', txt):
                continue
            ref.add(cf)
        got = MC.callers_of(name, lines)
        if got != ref or len(got) != r.get('caller_files'):
            bad.append((name, len(got), len(ref), r.get('caller_files')))
    return not bad and bool(rows), f"callers = grep for {[r['title'] for r in rows]}: mismatches {bad}"


def mk7(C):
    root = C.root
    ok, det = generic(C, 'mine_coverage.py', 'coverage', extra='no-negative',
                      writes=('riskmap.json', r'rt/coverage_\d{8}T\d{6}\.json'))
    tot = lambda: next((r for r in C.raw('coverage')['rows'] if r.get('id') == 'cov-total'), {})
    snaps = lambda: sorted((root / 'harness/runtime').glob('coverage_2*.json'))
    t0 = tot()
    facts = json.loads(snaps()[-1].read_text())['facts'] if snaps() else []
    unc = [f for f in facts if f.startswith('coverage uncovered-risk ')]
    pk = [f for f in facts if f.startswith('coverage pkg ')]
    sums = {k: sum(int(re.search(rf'\b{k}=(\d+)', f).group(1)) for f in pk) for k in ('funcs', 'covered', 'risk', 'risk_covered')}
    sum_ok = all(sums[k] == t0.get(k) for k in sums)
    if not unc:
        return False, det + ' · no uncovered risk function to cover'
    m = re.match(r'coverage uncovered-risk (\S+):(\d+) (\S+)$', unc[0])
    f, ln, name = m.group(1), int(m.group(2)), m.group(3)
    forged = root / 'harness/model/raw/zz_mk7_forged.json'
    forged.write_text(json.dumps({'key': 'zz_mk7_forged', 'rows': [{'id': 'mk7', 'evidence': [{'file': f, 'line': ln, 'quote': 'x'}]}]}))
    try:
        r = run(root, ['harness/miners/mine_coverage.py'])
        t1 = tot()
        facts1 = json.loads(snaps()[-1].read_text())['facts']
    finally:
        forged.unlink(missing_ok=True)
    run(root, ['harness/miners/mine_coverage.py'])
    t2 = tot()
    gone = not any(x == unc[0] for x in facts1)
    eq = callers_equal_grep(C)
    ok2 = (eq[0] and r[0] == 0 and t1.get('risk_covered') == t0.get('risk_covered', -9) + 1 and t1.get('covered') == t0.get('covered', -9) + 1
           and gone and t2.get('risk_covered') == t0.get('risk_covered') and sum_ok)
    return ok and ok2, (f"{det} · forged cite of {f}:{ln} {name}: risk_covered {t0.get('risk_covered')} -> {t1.get('risk_covered')} -> "
                        f"{t2.get('risk_covered')}, left the uncovered list {gone} · package sums {sums} = total {sum_ok} · {eq[1]}")


FAKE_CTAGS = {'fails': "#!/bin/sh\necho \"ctags: error: couldn't create cache file (forged)\" >&2\nexit 1\n",
              'silent': '#!/bin/sh\nexit 0\n',
              'noisy': '#!/bin/sh\necho "ctags: unrecognized option --_xformat (forged)"\nexit 1\n'}


def mk8(C):
    """prep_corpus with a ctags that fails (Xcode's shim on a sandboxed TMPDIR) or prints nothing: exit 2 naming
    universal-ctags, and neither tags.tsv nor manifest.json is rewritten; the real ctags still builds the table"""
    root = C.root
    tags, man = root / 'harness/corpus/tags.tsv', root / 'harness/corpus/manifest.json'
    t0, m0 = tags.read_bytes(), man.read_bytes()
    out = {}
    for k, body in FAKE_CTAGS.items():
        fb = root / f'fakebin_{k}'
        fb.mkdir(exist_ok=True)
        (fb / 'ctags').write_text(body)
        (fb / 'ctags').chmod(0o755)
        r = run(root, ['harness/prep_corpus.py'], path=f"{fb}:{os.environ.get('PATH', '/usr/bin:/bin')}")
        out[k] = (r[0], 'universal-ctags' in r[2], tags.read_bytes() == t0 and man.read_bytes() == m0)
    r = run(root, ['harness/prep_corpus.py'])
    n = len([l for l in tags.read_text().splitlines() if l.strip()])
    ok = all(v == (2, True, True) for v in out.values()) and r[0] == 0 and n > 1000
    return ok, f'forged ctags {out} · real ctags rc {r[0]} symbols {n}'


KATS = [('MK1', mk1), ('MK2', mk2), ('MK3', mk3), ('MK4', mk4), ('MK5', mk5), ('MK6', mk6), ('MK7', mk7), ('MK8', mk8)]
OWNERS = {f'r28 {k}': [k] for k, _ in KATS}

MUTATIONS = [   # (repo-relative file, find, replace, why): applied in the mutant's clone only
    ('harness/miners/mine_consts.py', "        if not a:\n            unv.append({'title': title, 'why': f'needle no longer",
     "        if False:\n            unv.append({'title': title, 'why': f'needle no longer", 'r28 MK1: a lost constant is not routed to unverified'),
    ('harness/miners/mine_consts.py', "                     'evidence': [a]})\n    M.emit('consts'",
     "                     'evidence': [dict(a, line=a['line'] + 1)]})\n    M.emit('consts'", 'r28 MK1: the anchor names the wrong line'),
    ('harness/miners/mine_press.py', "        if not a:\n            unv.append({'title': title, 'why': f'this sentence",
     "        if False:\n            unv.append({'title': title, 'why': f'this sentence", 'r28 MK2: an edited-away claim is not routed to unverified'),
    ('harness/miners/mine_press.py', "                     'evidence': [a]})\n    M.emit('press'",
     "                     'evidence': [dict(a, quote=a['quote'][:8])]})\n    M.emit('press'", 'r28 MK2: the quote is under the anchor floor'),
    ('harness/miners/mine_findings.py', "            if not a:\n                unv.append({'title': title, 'why': f'anchor lost:",
     "            if False:\n                unv.append({'title': title, 'why': f'anchor lost:", 'r28 MK3: a lost finding anchor is not routed to unverified'),
    ('harness/miners/mine_findings.py', "            evs.append(a)\n", "            evs.append(dict(a, line=a['line'] + 1))\n",
     'r28 MK3: the anchor names the wrong line'),
    ('harness/miners/mine_flows.py', "        if missing:\n            unv.append(", "        if False:\n            unv.append(",
     'r28 MK4: a chain with a lost hop is drawn partly'),
    ('harness/miners/mine_flows.py', "                         'where': f'{f}:{a[\"line\"]}', 'evidence': [a]})",
     "                         'where': f'{f}:{a[\"line\"]}', 'evidence': [dict(a, line=a['line'] + 1)]})", 'r28 MK4: a hop anchor names the wrong line'),
    ('harness/miners/mine_inventory.py', "                if len(M.norm(line)) >= M.MIN_Q:\n                    a = {'file': f_",
     "                if True:\n                    a = {'file': f_", 'r28 MK5: a package clause under the anchor floor is used'),
    ('harness/miners/mine_inventory.py', "            unv.append({'title': f'package {pkg}', 'why': 'no package clause found to anchor on'})\n",
     "", 'r28 MK5: an unanchored package vanishes without an unverified entry'),
    ('harness/miners/mine_logbridge.py', "            if not m or l.strip() in bridged:", "            if not m:",
     'r28 MK6: an overlapping console line is bridged twice'),
    ('harness/miners/mine_logbridge.py', "                         'evidence': [{'file': rel, 'quote': l.strip()[:200], 'line': i},",
     "                         'evidence': [{'file': rel, 'quote': l.strip()[:200], 'line': i + 1},", 'r28 MK6: the console anchor names the wrong line'),
    ('harness/miners/mine_coverage.py', "            hit = any(ln <= x < end for x in lines)", "            hit = any(ln < x < end for x in lines)",
     'r28 MK7: a cite of the declaration line does not cover the function'),
    ('harness/miners/mine_coverage.py', "            dn[:] = [d for d in dn if d not in ('vendor', 'harness')]",
     "            dn[:] = [d for d in dn if d not in ('harness',)]", 'r28 MK7: vendored Go files count as callers'),
    ('harness/miners/mine_coverage.py', "if needle in txt and rx.search(txt) and not txt.strip().startswith('//')",
     "if needle in txt and rx.search(txt)", 'r28 MK7: a commented-out call counts as a caller'),
    ('harness/miners/mine_coverage.py', "                if not hit:\n                    uncovered_risk.append((f, ln, name))",
     "                if False:\n                    uncovered_risk.append((f, ln, name))", 'r28 MK7: uncovered risk functions are not listed'),
    ('harness/prep_corpus.py', "    if files and (r.returncode != 0 or not r.stdout.strip()):",
     "    if False and (r.returncode != 0 or not r.stdout.strip()):", 'r28 MK8: an empty ctags run writes an empty symbol table'),
    ('harness/prep_corpus.py', "    if files and (r.returncode != 0 or not r.stdout.strip()):",
     "    if files and not r.stdout.strip():", 'r28 MK8: a failing ctags that prints is accepted'),
]


def clone_tree(dst):
    """an APFS clone (cp -c) of the repository without .git; prep_corpus builds the symbol table in it"""
    dst = Path(dst)
    dst.mkdir(parents=True, exist_ok=True)
    for p in sorted(ROOT.iterdir()):
        if p.name in ('.git',):
            continue
        r = subprocess.run(['cp', '-cR', str(p), str(dst / p.name)], capture_output=True, text=True)
        if r.returncode != 0:
            (shutil.copytree(p, dst / p.name, symlinks=True) if p.is_dir() else shutil.copy2(p, dst / p.name))
    for p in sorted(dst.glob('harness/**/__pycache__'), reverse=True):
        shutil.rmtree(p, ignore_errors=True)
    for d in ('home', 'tmp'):
        (dst / d).mkdir(exist_ok=True)
    rc = run(dst, ['harness/prep_corpus.py'])
    if rc[0] != 0:
        raise RuntimeError(f'prep_corpus in the clone exited {rc[0]}: {rc[2][-200:]}')
    return dst


def run_kats(root):
    """each KAT starts from the same harness/model/raw/ bytes: a KAT's (mutant's) raw output is undone after it, so a
    mutated miner can never reach another KAT through the raw files mine_coverage reads (MK3 -> MK7 coupling, R28)"""
    C = Ctx(root)
    raw = Path(root) / 'harness/model/raw'
    keep = {p.name: p.read_bytes() for p in raw.glob('*.json')}
    res = []
    for name, fn in KATS:
        try:
            o, det = fn(C)
        except Exception as e:                                    # noqa: BLE001
            o, det = False, f'{type(e).__name__}: {e}'
        res.append((name, o, det))
        for p in raw.glob('*.json'):
            if p.name not in keep:
                p.unlink()
        for n, b in keep.items():
            if (raw / n).read_bytes() != b if (raw / n).exists() else True:
                (raw / n).write_bytes(b)
    return res


def run_on(mutation=None):
    with tempfile.TemporaryDirectory(prefix='mk28_') as d:
        root = clone_tree(Path(d) / 'r')
        if mutation:
            rel, find, repl, _ = mutation
            p = root / rel
            p.write_text(p.read_text(encoding='utf-8').replace(find, repl, 1), encoding='utf-8')
            compile(p.read_text(encoding='utf-8'), str(p), 'exec')
        return run_kats(root)


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_mk28', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main(argv=()):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    only = [a for a in argv if not a.startswith('-')]
    res = run_on()
    for name, o, det in res:
        print(f"{'ok  ' if o else 'FAIL'} {name} {det[:700]}")
    if not all(o for _, o, _ in res):
        return 3
    K = katmut()
    missed = coupled = 0
    muts = [m for m in MUTATIONS if not only or any(K.defect_of(m[3]) == f'r28 {x}' for x in only)]
    for mut in muts:
        rel, find, repl, why = mut
        text = (ROOT / rel).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??      {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        try:
            res = run_on(mut)
        except SyntaxError as e:
            print(f'  INVALID {why}: mutant does not compile ({e.msg})')
            missed += 1
            continue
        failed = [n for n, o, _ in res if not o]
        verdict, extra = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f"  {verdict:8} {why}" + (f'  [{",".join(failed)}]' if failed else '')
              + (f'  COUPLED {extra}' if extra and verdict == 'proved' else ''))
        for n, o, det in res:
            if not o and (verdict != 'proved' or n in extra):
                print(f'           {n}: {det[:300]}')
        missed += verdict != 'proved'
        coupled += bool(extra) and verdict == 'proved'
    print('\n' + K.summary('r28 miner KATs', len(KATS), len(muts), missed, coupled))
    return 4 if missed or coupled else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
