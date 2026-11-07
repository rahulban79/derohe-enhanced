#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the R28 tools-kats group (dero-rft §0.9 rules 1-2; §7 B149; R28 Part A
self-detected N28-01, N28-04, N28-05, N28-09; the mine_evolution 'unverified 1' row).

N28-04: 17 of 78 harness tools had no KAT (tooling_intel kat_coverage 61/78, harness/runtime/tooling_20261105T233116.json).
TK7-TK16 give each of the ten non-miner ones a known-answer test on forged inputs (the seven miners are in
harness/kat/test_miners_r28.py); every KAT runs on an APFS clone of harness/ (the mutant's clone under a mutation),
never on the live tree, and none reaches the network, the live node or a path outside its clone.

  TK7  harness/ask.py: on a forged model/verified.json the title weight decides the ranking, --json names file:line,
       a query of stop words only exits 2 ('nothing to search for'), no query exits 2, no match exits 0 and says so.
  TK8  harness/forensics/s7_replay.py (stub replay/verify_dataset beside it): FULL is PASS only when the report hash is
       one the G28 record holds for the SAME manifest; PARTIAL is PASS and labelled; a FAIL replay exits 5; the G28
       record is never written.
  TK9  harness/forensics/write_manifest.py (content-pinned: tested, never edited; stub pins): files exclude the
       manifest, stages accumulate, provenance commits and decoder_sha256 carry over, 'replay' appears only with
       replay/replay.sh, --store counts the blobs.
  TK10 harness/hooks/autosync.py (stub gen_deroarch): a watched edit rebuilds once and reports rows/anchors; the build's
       own outputs, an unwatched file and a path-prefix near miss ('modelX') do not; bad stdin is silent; a failed
       build says FAILED; exit 0 always.
  TK11 harness/kit/cutfix.py: lint finds display slices only (not a comment, not a slice inside an operator
       expression), exit 3; fix rewrites slices >= --min and leaves formats.
  TK12 harness/kit/textkit.py: clip/wrap keep the full sentence; audit fails a cut without tooltip AND ⓘ, passes a
       lone '…' glyph with a title, skips pre/code and data-verbatim; the CLI exits 3 / 0.
  TK13 harness/kit/assetkit.py: audit counts untagged asset cells, skips notag tables, empty cells and skip columns,
       counts UNK; cite_audit counts cited / nocite pills and malformed citations; the CLI exits 3 / 0.
  TK14 harness/kit/retrofit.py: apply tags a sourced cell SRC and an unsourced one UNK; strip(apply(h)) == h; apply is
       idempotent; a researched citation verifies only within ±3 lines (an ambiguous quote is never relocated);
       `check` says STALE before apply and current after.
  TK15 harness/kit/kitgate.py (--no-browser): G5 parses only real JavaScript (a JSON data block is not code), G6
       tolerates optional end tags and names stray / unclosed ones, --ledger appends one row per gate; exit 3 / 0.
  TK16 harness/kit/urlcheck.py (cache only, sandbox without network): a GitHub #L citation is found within ±3 lines,
       'line-mismatch' farther away, 'quote-not-found' absent, http-404 recorded; typographic quotes normalise; inline
       markup does not split words; the CLI summary counts.
  TK17 B149 (lesson #80): tooling_intel.round_list_gaps is empty on the tree and names every round list a forged
       registry round lacks (areas.json rounds, LAST_CHOICES for a numeric id >= its smallest choice, ORDER); planned
       rounds are exempt; the record's targets name a gap. Fails the day a round is opened in round.json alone.
  TK18 N28-01: the HT11 mutation of test_harness_tooling_r26.py is derived from mine_evolution's last 'ORDER += [...]'
       line at run time (drops its last round), still matches after a forged round open, and no literal ORDER list is
       left in its MUTATIONS.
  TK19 N28-05: round_checkpoint.select_derod picks only an exact 'derod' process name, never a command-line match;
       two derods resolve by working directory, ambiguity is ''; no pgrep call is left in the file.
  TK20 mine_evolution: a commit-less round the registry marks planned is pending (its row), not an unverified item; a
       commit-less non-planned round still is one.
  TK21 N28-09 / N28-04 targets: tooling_intel.determinism_last carries the newest record that measured determinism
       (file, age, mismatches) while determinism_mismatches stays 'pending' in a default run; tools_without_kat is a
       target; on the tree every harness tool has a KAT (78/78 at R28).
  TK22 minelib.tags_text: a missing (untracked) corpus/tags.tsv stops mine_inventory and mine_coverage with exit 2
       naming prep_corpus, before they write; a present table parses.

Mutation independence (harness/kit/katmut.py): each mutation's reason starts with its defect id (r28 TK<n>); it is
proved only when that KAT fails; a failure of another KAT is counted as coupled (target 0).

  python3 -I harness/kat/test_tools_kats_r28.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught by its own KAT, was INVALID, or coupled.
"""
import ast, hashlib, importlib.util, json, os, re, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
KIT_MODS = ('assetkit', 'connectorkit', 'textkit', 'diagramkit', 'areakit', 'consensuskit', 'peerkit', 'privkit',
            'prep_corpus', 'minelib', 'roundtracks', 'cutfix', 'kitgate', 'retrofit', 'urlcheck')
SANDBOX = '/usr/bin/sandbox-exec'
PY = sys.executable


def load(path, name):
    for m in KIT_MODS:                       # a kit module imported by name must come from THIS clone
        sys.modules.pop(m, None)
    spec = importlib.util.spec_from_file_location(f'{name}_{abs(hash(str(path)))}_{len(sys.modules)}', path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


def profile(allow):
    paths = ' '.join(f'(subpath "{os.path.realpath(a)}")' for a in allow)
    return ('(version 1)\n(allow default)\n(deny network*)\n(deny signal (target others))\n'
            f'(deny file-write* (require-not (require-any {paths} (literal "/dev/null") (literal "/dev/tty")'
            ' (regex #"^/dev/fd/"))))\n')


def run(root, argv, stdin=None, env=None, sandbox=True):
    """a tool of the clone as a subprocess: nice 15, HOME and TMPDIR inside the clone, no network, no write outside it"""
    for d in ('home', 'tmp'):
        (root / d).mkdir(exist_ok=True)
    e = {'PATH': '/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin', 'HOME': str(root / 'home'), 'TMPDIR': str(root / 'tmp'),
         'PYTHONDONTWRITEBYTECODE': '1', **(env or {})}
    cmd = [PY, '-I', '-B', *argv]
    if sandbox and os.path.exists(SANDBOX):
        cmd = [SANDBOX, '-p', profile([root]), *cmd]
    p = subprocess.run(['nice', '-n', '15', *cmd], cwd=root, capture_output=True, text=True, input=stdin, env=e, timeout=120)
    return p.returncode, p.stdout, p.stderr


def snapshot(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in Path(root).rglob('*')
            if p.is_file() and '__pycache__' not in p.parts and not p.parts[len(Path(root).parts)] in ('home', 'tmp')}


# ───────────────────────────── TK7 ask.py ─────────────────────────────
def tk7(P):
    root = P['root']
    rows = [{'id': 'row-peer', 'title': 'Incoming peers', 'class': 'HARNESS', 'page_section': 'peers',
             'claim': 'no incoming peers; the block reward line is quoted here too',
             'evidence': [{'file': 'p2p/peer.go', 'quote': 'func incoming()', 'line': 9}]},
            {'id': 'row-reward', 'title': 'Block reward', 'class': 'SRC', 'page_section': 'emission',
             'claim': 'the block reward of every block',
             'evidence': [{'file': 'blockchain/reward.go', 'quote': 'func BlockReward(h uint64) uint64 {', 'line': 5}]}]
    (root / 'harness/model').mkdir(parents=True, exist_ok=True)
    (root / 'harness/model/verified.json').write_text(json.dumps(rows))
    rc1, o1, _ = run(root, ['harness/ask.py', '--json', 'block reward'])
    j = json.loads(o1) if rc1 == 0 else []
    rc2, o2, _ = run(root, ['harness/ask.py', 'what is the'])
    rc3, o3, _ = run(root, ['harness/ask.py'])
    rc4, o4, _ = run(root, ['harness/ask.py', 'zzqqxx'])
    ok = (rc1 == 0 and [x['id'] for x in j] == ['row-reward', 'row-peer'] and j[0]['where'] == 'blockchain/reward.go:5'
          and j[0]['class'] == 'SRC' and rc2 == 2 and 'nothing to search for' in o2 and rc3 == 2 and rc4 == 0
          and 'no drawn row matches' in o4)
    return ok, (f"ranking {[x['id'] for x in j]} where {j[0]['where'] if j else None} · stopwords rc {rc2} · no query rc {rc3}"
                f" · no match rc {rc4}")


# ───────────────────────────── TK8 s7_replay.py ─────────────────────────────
STUB_REPLAY = '''import json, os
def replay(ds, store, arch):
    return json.loads(os.environ['STUB_REP'])
def dumps(rep):
    return json.dumps(rep, indent=1, sort_keys=True) + "\\n"
'''
STUB_VD = "RECORD = 'harness/runtime/forensics_replay.json'\n"


def tk8(P):
    root = P['root']
    fd = root / 'harness/forensics'
    (fd / 'replay.py').write_text(STUB_REPLAY)
    (fd / 'verify_dataset.py').write_text(STUB_VD)
    (root / 'forensics/rT').mkdir(parents=True, exist_ok=True)
    (root / 'forensics/ledger.json').write_text(json.dumps({'versions': [{'version': 'rS'}, {'version': 'rT'}]}))
    (root / 'forensics/rT/manifest.json').write_text(json.dumps({'replay_tool': 'harness/forensics/replay.py'}))
    full = {'manifest_sha256': 'M1', 'result': 'PASS', 'rederive': {'mode': 'full', 'equal': 7, 'expected': 7}}
    sha = hashlib.sha256((json.dumps(full, indent=1, sort_keys=True) + '\n').encode()).hexdigest()
    rec = root / 'harness/runtime/forensics_replay.json'
    rec.parent.mkdir(parents=True, exist_ok=True)
    out = root / 'harness/runtime/s7.json'
    env0 = {'FORENSICS_STORE': str(root / 'nostore'), 'FORENSICS_ARCHIVE_COPY': str(root / 'noarch')}

    def go(rep, record):
        rec.write_text(json.dumps(record))
        before = rec.read_bytes()
        rc, o, e = run(root, ['harness/forensics/s7_replay.py', '--out', str(out)], env={**env0, 'STUB_REP': json.dumps(rep)})
        res = json.loads(out.read_text()) if out.exists() else {}
        return rc, o.strip(), res, rec.read_bytes() == before
    a = go(full, {'manifest_sha256': 'M1', 'runs': [{'report_sha256': sha}]})
    b = go(full, {'manifest_sha256': 'M1', 'runs': [{'report_sha256': '0' * 64}]})
    c = go(full, {'manifest_sha256': 'M0', 'runs': [{'report_sha256': sha}]})
    part = {'manifest_sha256': 'M1', 'result': 'PASS', 'rederive': {'mode': 'partial', 'rederived': 3, 'hash_checked_only': ['x', 'y']}}
    d = go(part, {})
    fail = dict(part, result='FAIL', fail_reasons=['derived/x differs'])
    e = go(fail, {})
    ok = (a[0] == 0 and 'FULL: 7/7' in a[1] and 'equal to' in a[1] and a[2].get('result') == 'PASS' and a[2].get('dataset') == 'rT'
          and b[0] == 5 and 'DIFFERENT from' in b[1] and c[0] == 5 and d[0] == 0 and d[1].startswith('PASS PARTIAL (no tier B store')
          and '2 hash-checked only' in d[1] and e[0] == 5 and e[2].get('fail_reasons') == ['derived/x differs']
          and all(x[3] for x in (a, b, c, d, e)))
    return ok, (f'full-recorded rc {a[0]} · full-unrecorded rc {b[0]} · other-manifest rc {c[0]} · partial rc {d[0]} {d[1][:40]!r} · '
                f'fail rc {e[0]} · G28 record untouched {[x[3] for x in (a, b, c, d, e)]}')


# ───────────────────────────── TK9 write_manifest.py ─────────────────────────────
STUB_PINS = '''REPLAY_TOOLS = ['harness/forensics/replay.py']
def compute(root, *a, **k):
    return {'stub': 'pins'}
'''


def tk9(P):
    root = P['root']
    (root / 'harness/forensics/pins.py').write_text(STUB_PINS)
    (root / 'blockchain').mkdir(exist_ok=True)
    (root / 'blockchain/hardfork_fixes.go').write_text('package blockchain\n')
    ds = root / 'forensics/rM'
    (ds / 'sub').mkdir(parents=True, exist_ok=True)
    (ds / 'a.txt').write_text('a\n')
    (ds / 'sub/b.txt').write_text('b\n')
    wm = ['harness/forensics/write_manifest.py', '--dataset', str(ds)]
    r1 = run(root, wm + ['--stage', 'acquire'])
    m1 = json.loads((ds / 'manifest.json').read_text()) if (ds / 'manifest.json').exists() else {}
    m1.setdefault('tool_versions', {})['decoder_sha256'] = 'd' * 64
    m1['provenance_commits'] = {'built': 'c0ffee'}
    (ds / 'manifest.json').write_text(json.dumps(m1))
    (ds / 'c.txt').write_text('c\n')
    r2 = run(root, wm + ['--stage', 'extract'])
    m2 = json.loads((ds / 'manifest.json').read_text())
    (ds / 'replay').mkdir(exist_ok=True)
    (ds / 'replay/replay.sh').write_text('#!/bin/sh\n')
    (root / 'store/blobs').mkdir(parents=True, exist_ok=True)
    for n in ('x1', 'x2'):
        (root / 'store/blobs' / n).write_text(n)
    r3 = run(root, wm + ['--stage', 'replay', '--store', str(root / 'store')])
    m3 = json.loads((ds / 'manifest.json').read_text())
    ok = (r1[0] == 0 and r2[0] == 0 and r3[0] == 0 and sorted(m2['files']) == ['a.txt', 'c.txt', 'sub/b.txt']
          and m2['stages'] == {'acquire': ['a.txt', 'sub/b.txt'], 'extract': ['a.txt', 'c.txt', 'sub/b.txt']}
          and m2['tool_versions'].get('decoder_sha256') == 'd' * 64 and set(m2['provenance_commits']) == {'built', 'extract'}
          and 'replay' not in m2 and 'replay' in m3 and m3['tierB_store']['count'] == 2 and m3['content_pins'] == {'stub': 'pins'}
          and 'manifest.json' not in m3['files'] and m3['hf3_table']['file'] == 'blockchain/hardfork_fixes.go')
    return ok, (f"rc {r1[0]},{r2[0]},{r3[0]} · files {sorted(m2.get('files', {}))} · stages {m2.get('stages')} · decoder "
                f"{str(m2.get('tool_versions', {}).get('decoder_sha256'))[:6]} · replay {'replay' in m2}/{'replay' in m3} · "
                f"tierB {m3.get('tierB_store', {}).get('count')} · {r1[2][-120:]}")


# ───────────────────────────── TK10 autosync.py ─────────────────────────────
STUB_GDA = '''import json, os, sys
from pathlib import Path
H = Path(__file__).resolve().parent
with open(H / 'runtime' / 'stub_calls.txt', 'a') as f:
    f.write(' '.join(sys.argv[1:]) + '\\n')
(H / 'stamp.json').write_text(json.dumps({'stats': {'rows': 3, 'anchors_ok': 2, 'anchors': 2}, 'fingerprint': 'f00d'}))
if os.environ.get('STUB_RC', '0') != '0':
    print('boom: forged build failure', file=sys.stderr)
sys.exit(int(os.environ.get('STUB_RC', '0')))
'''


def tk10(P):
    root = P['root']
    h = root / 'harness'
    (h / 'gen_deroarch.py').write_text(STUB_GDA)
    (h / 'runtime').mkdir(exist_ok=True)
    calls = h / 'runtime/stub_calls.txt'
    for d in ('model/raw', 'modelX'):
        (h / d).mkdir(parents=True, exist_ok=True)

    def hook(path, rc='0', raw=None):
        n0 = len(calls.read_text().splitlines()) if calls.exists() else 0
        payload = raw if raw is not None else json.dumps({'tool_input': {'file_path': str(path)}})
        r = run(root, ['harness/hooks/autosync.py'], stdin=payload, env={'STUB_RC': rc})
        n1 = len(calls.read_text().splitlines()) if calls.exists() else 0
        return r[0], r[1].strip(), n1 - n0
    a = hook(h / 'model/raw/x.json')
    b = hook(h / 'model/verified.json')
    c = hook(root / 'README.md')
    d = hook(h / 'modelX/y.json')
    e = hook(None, raw='{not json')
    f = hook(h / 'miners/mine_x.py', rc='1')
    msg = json.loads(a[1]).get('systemMessage', '') if a[1].startswith('{') else ''
    fmsg = json.loads(f[1]).get('systemMessage', '') if f[1].startswith('{') else ''
    ok = (a == (0, a[1], 1) and 'rebuilt after x.json · 3 rows · 2/2 anchors · fingerprint f00d' in msg
          and b == (0, '', 0) and c == (0, '', 0) and d == (0, '', 0) and e == (0, '', 0)
          and f[0] == 0 and f[2] == 1 and 'build FAILED after mine_x.py (exit 1)' in fmsg and 'boom' in fmsg)
    return ok, (f'watched {a[0]},{a[2]} {msg[:70]!r} · own output {b[2]} · unwatched {c[2]} · near-miss {d[2]} · bad stdin {e[1]!r} · '
                f'failed build {fmsg[:60]!r}')


# ───────────────────────────── TK11 cutfix.py ─────────────────────────────
CUT_SRC = '''def page(x, d, foo, bar, line, fn):
    a = esc(x['claim'][:120])
    b = esc(d[:10])
    c = esc(foo + bar[:50])
    # e = esc(x['commented'][:99])
    e = E(line[:140])
    f = esc(fn(x)[:80])
    return a, b, c, e, f
'''


def tk11(P):
    root = P['root']
    g = root / 'gen_cut.py'
    g.write_text(CUT_SRC)
    C = load(root / 'harness/kit/cutfix.py', 'tk11cut')
    sites = [(e, n) for _, _, e, n in C.sites(CUT_SRC)]
    rc1, o1, _ = run(root, ['harness/kit/cutfix.py', 'lint', str(g)])
    rc2, o2, _ = run(root, ['harness/kit/cutfix.py', 'fix', str(g), '--min', '20'])
    fixed = g.read_text()
    rc3, o3, _ = run(root, ['harness/kit/cutfix.py', 'lint', str(g)])
    want = [("x['claim']", 120), ('d', 10), ('line', 140), ('fn(x)', 80)]
    ok = (sites == want and rc1 == 3 and '4 display slice(s)' in o1 and rc2 == 0 and 'rewrote 3' in o2
          and "_clip(x['claim'], 120)" in fixed and '_clip(line, 140)' in fixed and '_clip(fn(x), 80)' in fixed
          and 'esc(d[:10])' in fixed and 'esc(foo + bar[:50])' in fixed and "# e = esc(x['commented'][:99])" in fixed
          and rc3 == 3 and '1 display slice(s)' in o3)
    return ok, f'sites {sites} · lint rc {rc1} · fix rc {rc2} {o2.strip()[:60]!r} · after {o3.strip()[-30:]!r}'


# ───────────────────────────── TK12 textkit.py ─────────────────────────────
def tk12(P):
    root = P['root']
    T = load(root / 'harness/kit/textkit.py', 'tk12tk')
    c = T.clip('alpha beta gamma delta', 9)
    short = T.clip('alpha', 9)
    w = T.wrap('one two three four five six seven', 9, 2)
    h = T.html(c)
    cases = {
        'cut-with-tooltip': (h, True),
        'cut-bare': ('<p>a sentence that was cut…</p>', False),
        'cut-title-no-mark': ('<span title="the full sentence">the full…</span>', False),
        'glyph-with-title': ('<svg><text><title>ran out of tokens</title>…</text></svg>', True),
        'pre-skipped': ('<pre>log line…</pre>', True),
        'verbatim': ('<div data-verbatim>quoted source line…</div>', True),
        'svg-cut': ('<svg><text>' + T.svg_inner(c)[0] + '</text></svg>', True),
    }
    got = {k: T.audit(v)['ok'] for k, (v, _) in cases.items()}
    bad = root / 'bad.html'
    good = root / 'good.html'
    bad.write_text(cases['cut-bare'][0])
    good.write_text(h)
    rcb = run(root, ['harness/kit/textkit.py', str(bad)])[0]
    rcg = run(root, ['harness/kit/textkit.py', str(good)])[0]
    ok = (isinstance(c, T.Clipped) and c.full == 'alpha beta gamma delta' and str(c).endswith('…') and len(str(c)) <= 9
          and not isinstance(short, T.Clipped) and short == 'alpha' and len(w) == 2 and isinstance(w[-1], T.Clipped)
          and w[-1].full == 'one two three four five six seven' and 'title="alpha beta gamma delta"' in h and 'ⓘ' in h
          and got == {k: v for k, (_, v) in cases.items()} and rcb == 3 and rcg == 0)
    return ok, f'clip {str(c)!r} wrap {[str(x) for x in w]} audit {got} cli {rcb}/{rcg}'


# ───────────────────────────── TK13 assetkit.py ─────────────────────────────
def tk13(P):
    root = P['root']
    A = load(root / 'harness/kit/assetkit.py', 'tk13ak')
    SRC_CL = (['SRC'], 'own', 'its own class', [A.cite_file('/repo/blockchain/x.go', 3, 'func X()')])

    def page_of(*cls):                     # one registry per page, as a generator builds it (reg_reset per build)
        A.reg_reset()
        pills = ''.join(A.ctag(c) for c in cls)
        return f'<p>{pills}</p>' + A.cites_script()
    c1 = A.cite_audit(page_of(SRC_CL))
    c2 = A.cite_audit(page_of(SRC_CL, (['GK'], 'sec', 'declared', [])))
    c3 = A.cite_audit(page_of((['HARNESS'], 'own', 'x', [A.cite_file('relative/path.py', 1, 'q', cls='HARNESS')])))
    A.reg_reset()
    cited = A.ctag(SRC_CL)
    unk = A.ctag((['?'], 'none', 'unclassified'))
    page = ('<section id="s1"><table><thead><tr><th>item</th><th>proof</th><th>value</th></tr></thead><tbody>'
            f'<tr><td>reward {cited}</td><td>no tag needed (skip column)</td><td>—</td></tr>'
            '<tr><td>an untagged asset cell</td><td>x</td><td></td></tr>'
            f'<tr><td>unknown {unk}</td><td>x</td><td>n/a</td></tr></tbody></table>'
            '<table data-notag="a ledger of this page"><tr><td>untagged but opted out</td></tr></table></section>')
    a = A.audit(page)
    f = root / 'page.html'
    f.write_text(page)
    rc_bad = run(root, ['harness/kit/assetkit.py', str(f)])[0]
    f.write_text(f'<table><tr><td>reward {cited}</td></tr></table>')
    rc_good = run(root, ['harness/kit/assetkit.py', str(f)])[0]
    ok = (a['asset_cells'] == 3 and a['untagged_cells'] == 1 and a['unclassified'] == 1 and a['notag_tables'] == 1
          and not a['ok'] and c1['ok'] and c1['by_class'] == {'SRC': {'cited': 1, 'nocite': 0, 'contradicted': 0}}
          and not c2['ok'] and c2['by_class'].get('GK', {}).get('nocite') == 1 and c3['malformed'] == 1 and not c3['ok']
          and rc_bad == 3 and rc_good == 0)
    return ok, (f"audit cells {a['asset_cells']} untagged {a['untagged_cells']} unk {a['unclassified']} notag {a['notag_tables']} · "
                f"cite ok {c1['ok']}/{c2['ok']}/{c3['ok']} malformed {c3['malformed']} · cli {rc_bad}/{rc_good}")


# ───────────────────────────── TK14 retrofit.py ─────────────────────────────
RF_PAGE = ('<!doctype html><html><head><title>t</title></head><body><section id="s1"><table><thead><tr><th>item</th>'
           '<th>value</th></tr></thead><tbody><tr><td>BlockRewardFormula computes the reward</td><td>per block</td></tr>'
           '<tr><td>orphaned words nowhere</td><td>also nothing at all</td></tr></tbody></table></section></body></html>\n')


def tk14(P):
    root = P['root']
    src = root / 'srcdir/reward.go'
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text('package x\n// BlockRewardFormula computes the reward of every block\n' + ''.join(f'// filler {i}\n' for i in range(12))
                   + '// alpha marker line here\n' + ''.join(f'// pad {i}\n' for i in range(12)) + '// alpha marker line here\n')
    page = root / 'page.html'
    page.write_text(RF_PAGE)
    ev = root / 'evid.json'
    ev.write_text(json.dumps({'name': 'kat', 'page': str(page), 'sources': [str(src)],
                              'classes': [[str(src.parent), 'SRC', 'the forged source tree']]}))
    R = load(root / 'harness/kit/retrofit.py', 'tk14rf')
    E = R.Evidence(str(ev))
    rep = {}
    new = R.apply_html(RF_PAGE, E, rep)
    again = R.apply_html(new, R.Evidence(str(ev)))
    back = R.strip(new)
    g = R.gates(new)
    lines = src.read_text().split('\n')
    i1 = lines.index('// alpha marker line here') + 1          # 1-based
    v_near = E.verify({'p': str(src), 'l': i1 + 2, 'q': 'alpha marker line here'})
    v_amb = E.verify({'p': str(src), 'l': i1 + 6, 'q': 'alpha marker line here'})     # neither copy within ±3
    v_gone = E.verify({'p': str(src), 'l': 2, 'q': 'a quote no line carries'})
    rc1, o1, _ = run(root, ['harness/kit/retrofit.py', 'check', str(ev)])
    rc2, o2, _ = run(root, ['harness/kit/retrofit.py', 'apply', str(ev)])
    rc3, o3, _ = run(root, ['harness/kit/retrofit.py', 'check', str(ev)])
    body = new[:new.find('<!--akr:kit-->')]
    ok = ('class="ct ct-SRC' in body and 'class="ct ct-UNK' in body and back == RF_PAGE and again == new and not g['ok']
          and g['G10']['unclassified'] >= 1 and rep['cells'] == 4 and rep['cells_cited'] == 2 and v_near and not v_amb and not v_gone
          and rc1 == 3 and 'STALE' in o1 and rc2 == 0 and 'written' in o2 and rc3 == 3 and 'page current' in o3)
    return ok, (f"SRC {'class=\"ct ct-SRC' in body} UNK {'class=\"ct ct-UNK' in body} inverse {back == RF_PAGE} idempotent {again == new} cells "
                f"{rep.get('cells_cited')}/{rep.get('cells')} · verify near {v_near} ambiguous {v_amb} gone {v_gone} · "
                f"cli check {rc1} apply {rc2} check {rc3} {o3.strip()[:50]!r}")


# ───────────────────────────── TK15 kitgate.py ─────────────────────────────
KG_GOOD = ('<!doctype html><html><head><title>t</title></head><body><section id="a"><div><p>one<p>two</div>'
           '<script type="application/json" id="d">{"a": 1}</script><script>var x = 1;</script></section></body></html>')


def tk15(P):
    root = P['root']
    K = load(root / 'harness/kit/kitgate.py', 'tk15kg')
    pages = {'good': KG_GOOD, 'badjs': KG_GOOD.replace('var x = 1;', 'var x = ;'),
             'stray': KG_GOOD.replace('</section>', '</div></section>'),
             'unclosed': KG_GOOD.replace('<section id="a">', '<section id="a"><span>')}
    res = {}
    for k, h in pages.items():
        f = root / f'kg_{k}.html'
        f.write_text(h)
        res[k] = {n.split()[0]: o for n, o, _ in K.run(str(f), use_browser=False)}
    led = root / 'kg_ledger.md'
    K.run(str(root / 'kg_good.html'), label='kat', ledger=str(led), use_browser=False)
    rows = [l for l in led.read_text().splitlines() if l.startswith('| 20')]
    rcg = run(root, ['harness/kit/kitgate.py', str(root / 'kg_good.html'), '--no-browser'], sandbox=False)[0]
    rcb = run(root, ['harness/kit/kitgate.py', str(root / 'kg_badjs.html'), '--no-browser'], sandbox=False)[0]
    ok = (all(res['good'].values()) and sorted(res['good']) == ['G10', 'G11', 'G12', 'G5', 'G6'] and not res['badjs']['G5']
          and res['badjs']['G6'] and not res['stray']['G6'] and res['stray']['G5'] and not res['unclosed']['G6']
          and len(rows) == 5 and all('| kat |' in r and '| PASS |' in r for r in rows) and rcg == 0 and rcb == 3)
    return ok, f'{res} · ledger rows {len(rows)} · cli {rcg}/{rcb}'


# ───────────────────────────── TK16 urlcheck.py ─────────────────────────────
UC_DRIVER = r'''import json, sys
sys.path.insert(0, sys.argv[1])
import urlcheck as U
from pathlib import Path
cache = Path(sys.argv[2])
out = {}
for k, url, q in json.loads(sys.argv[3]):
    ok, why, h = U.check(url, q, cache)
    out[k] = [ok, why]
print(json.dumps(out))
'''


def tk16(P):
    root = P['root']
    cache = root / 'uc_cache'
    cache.mkdir(exist_ok=True)

    def put(url, status, body):
        (cache / hashlib.sha256(url.encode()).hexdigest()[:24]).write_text(json.dumps({'url': url, 'status': status, 'body': body}))
    raw = 'https://raw.githubusercontent.com/o/r/main/f.go'
    put(raw, 200, '\n'.join(['package f'] + [f'// line {i}' for i in range(2, 7)] + ['const Target = 7 // the quoted line']
                            + [f'// line {i}' for i in range(8, 11)] + ['const Far = 11 // the far line', '']))
    put('https://example.org/page', 200, '<html><body><p>The node said <code>hello</code>world and “quoted words” here</p></body></html>')
    put('https://example.org/gone', 404, '')
    blob = 'https://github.com/o/r/blob/main/f.go'
    cases = [('near', blob + '#L5', 'const Target = 7'), ('far', blob + '#L5', 'const Far = 11'),
             ('absent', blob + '#L5', 'no such text'), ('whole', blob, 'const Far = 11'),
             ('markup', 'https://example.org/page', 'hello world'), ('quotes', 'https://example.org/page', '"quoted words"'),
             ('gone', 'https://example.org/gone', 'x'), ('nourl', '', 'x')]
    d = root / 'uc_driver.py'
    d.write_text(UC_DRIVER)
    rc, o, e = run(root, [str(d), str(root / 'harness/kit'), str(cache), json.dumps(cases)])
    got = json.loads(o) if rc == 0 and o.strip() else {}
    (root / 'uc_in.json').write_text(json.dumps([{'key': k, 'url': u, 'quote': q} for k, u, q in cases[:3]]))
    rc2, o2, _ = run(root, ['harness/kit/urlcheck.py', str(root / 'uc_in.json'), str(root / 'uc_out.json'), '--cache', str(cache)])
    summ = json.loads((root / 'uc_out.json').read_text())['summary'] if (root / 'uc_out.json').exists() else {}
    want = {'near': [True, 'found'], 'far': [False, 'line-mismatch'], 'absent': [False, 'quote-not-found'],
            'whole': [True, 'found'], 'markup': [True, 'found'], 'quotes': [True, 'found'], 'gone': [False, 'http-404'],
            'nourl': [False, 'no-url']}
    ok = got == want and rc2 == 0 and summ.get('items') == 3 and summ.get('verified') == 1 and summ.get('distinct_urls') == 1
    return ok, f'checks {got} · cli rc {rc2} summary {summ} {e[-160:]}'


# ───────────────────────────── TK17 B149 round lists ─────────────────────────────
def tk17(P):
    root = P['root']
    T = load(root / 'harness/intel/tooling_intel.py', 'tk17tool')
    reg = json.loads((ROOT / 'harness/round.json').read_text())
    areas = [r['id'] for r in json.loads((ROOT / 'harness/areas.json').read_text())['rounds']]
    choices = T.ledger_choices(ROOT)
    order = T.evolution_order(ROOT)
    tree = T.round_list_gaps(reg, areas, choices, order)
    forged = {'rounds': [{'id': 'r20', 'status': 'measured'}, {'id': 'r23c', 'status': 'measured'},
                         {'id': 'r28', 'status': 'measured'}, {'id': 'r29', 'status': 'in-progress'},
                         {'id': 'r30', 'status': 'implemented'}, {'id': 'r31', 'status': 'planned'}]}
    g = T.round_list_gaps(forged, ['r20', 'r23c', 'r28'], (21, 28), ['R20', 'R23c', 'R28', 'R29', 'R31'])
    want = ['r29: not in harness/areas.json rounds', 'r29: not in artifacts/src/gen_ledger.py LAST_CHOICES',
            'r30: not in harness/areas.json rounds', 'r30: not in artifacts/src/gen_ledger.py LAST_CHOICES',
            'r30: not in harness/miners/mine_evolution.py ORDER']
    none_read = T.round_list_gaps(forged, None, None, None)
    v = T.targets({'round_list_gaps': want[:1]})
    ok = (tree == [] and choices and order and g == want and none_read == [] and any('B149' in x for x in v)
          and T.targets({'round_list_gaps': []}) == [])
    return ok, f'tree {tree} · forged {g} · unreadable {none_read} · target {v[:1]}'


# ───────────────────────────── TK18 N28-01 HT11 ─────────────────────────────
def tk18(P):
    root = P['root']
    H = load(root / 'harness/kat/test_harness_tooling_r26.py', 'tk18ht')
    src = "ORDER = ['R1']\nORDER += ['R25', 'R26']\nORDER += ['R27', 'R28', 'R31']  # a comment\n"
    m = H.order_tail_mutation(src, 'B90: x')
    evo = (root / 'harness/miners/mine_evolution.py').read_text()
    live = [x for x in H.MUTATIONS if x[0] == 'evo']
    lf, lr = live[-1][1], live[-1][2]
    opened = re.sub(r"^(ORDER \+= \[[^\]]*)\]", r"\1, 'R99']", evo, count=1, flags=re.M)
    m2 = H.order_tail_mutation(opened, 'B90: x')
    tree = ast.parse((root / 'harness/kat/test_harness_tooling_r26.py').read_text())
    mut = next(n for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, 'id', '') == 'MUTATIONS' for t in n.targets))
    lits = [n.value for n in ast.walk(mut) if isinstance(n, ast.Constant) and isinstance(n.value, str) and 'ORDER +=' in n.value]
    ok = (m == ('evo', "ORDER += ['R27', 'R28', 'R31']", "ORDER += ['R27', 'R28']", 'B90: x') and len(live) == 1
          and evo.count(lf) == 1 and lr != lf and lr.rstrip(']') in lf and opened.count(m2[1]) == 1 and m2[1].endswith("'R99']")
          and "'R99'" not in m2[2] and lits == [])
    return ok, f'forged {m[1:3]} · live find {lf!r} -> {lr!r} · after a round open {m2[1][-24:]!r} · literals {lits}'


# ───────────────────────────── TK19 N28-05 round_checkpoint ─────────────────────────────
def tk19(P):
    root = P['root']
    for k in ('ROUND_CKPT_OUT', 'ROUND_CKPT_REPO', 'ROUND_CKPT_PROJ', 'ROUND_CKPT_SCRATCH', 'ROUND_CKPT_PUB'):
        os.environ[k] = str(root / 'ckpt' / k.lower())
    try:
        C = load(root / 'harness/intel/round_checkpoint.py', 'tk19rc')
    finally:
        for k in ('ROUND_CKPT_OUT', 'ROUND_CKPT_REPO', 'ROUND_CKPT_PROJ', 'ROUND_CKPT_SCRATCH', 'ROUND_CKPT_PUB'):
            os.environ.pop(k, None)
    cwd = {'77': '/x/repo', '88': '/x/shadow', '99': '/x/repo'}.get
    s = C.select_derod
    got = {
        'one': s([('101', 'bash'), ('102', 'python3.14'), ('77', 'derod'), ('300', 'tail')], '/x/repo', cwd),
        'near-name': s([('5', 'derod-helper'), ('77', 'derod')], '/x/elsewhere', lambda p: None),
        'two-by-cwd': s([('88', 'derod'), ('77', 'derod')], '/x/repo', cwd),
        'two-same-cwd': s([('77', 'derod'), ('99', 'derod')], '/x/repo', cwd),
        'two-none': s([('88', 'derod'), ('77', 'derod')], '/x/other', cwd),
        'none': s([('1', 'launchd'), ('2', 'bash')], '/x/repo', cwd),
        'junk-pid': s([('pid', 'derod'), (' 66 ', ' derod ')], '/x/repo', cwd),
    }
    want = {'one': '77', 'near-name': '77', 'two-by-cwd': '77', 'two-same-cwd': '', 'two-none': '', 'none': '', 'junk-pid': '66'}
    tree = ast.parse((root / 'harness/intel/round_checkpoint.py').read_text())
    calls = [ast.unparse(n)[:80] for n in ast.walk(tree) if isinstance(n, ast.Call)
             and any(isinstance(a, ast.Constant) and isinstance(a.value, str) and 'pgrep' in a.value for a in n.args)]
    uses = 'select_derod(ps_rows(), REPO, cwd_of)' in (root / 'harness/intel/round_checkpoint.py').read_text()
    ok = got == want and calls == [] and uses
    return ok, f'{got} · pgrep calls {calls} · wired {uses}'


# ───────────────────────────── TK20 mine_evolution planned round ─────────────────────────────
def tk20(P):
    root = P['root']
    E = load(root / 'harness/miners/mine_evolution.py', 'tk20evo')
    a = E.commitless_unverified('R29', [], {'R29'})
    b = E.commitless_unverified('R28', [], {'R29'})
    c = E.commitless_unverified('R27', ['abc1234'], set())
    f = root / 'forged_root/harness'
    f.mkdir(parents=True, exist_ok=True)
    (f / 'round.json').write_text(json.dumps({'rounds': [{'id': 'r28', 'status': 'in-progress'}, {'id': 'r29', 'status': 'planned'},
                                                         {'id': 'r30', 'status': 'planned'}]}))
    pk = E.planned_keys(f.parent)
    none = E.planned_keys(root / 'no_such_root')
    reg = json.loads((ROOT / 'harness/round.json').read_text())
    live = {'R' + r['id'][1:] for r in reg['rounds'] if r.get('status') == 'planned'}
    ok = (a is None and b and b['title'].startswith('R28: no commit') and c is None and pk == {'R29', 'R30'} and none == set()
          and E.planned_keys(ROOT) == live)
    return ok, f'planned {a} · in-progress {(b or {}).get("title")} · committed {c} · keys {sorted(pk)} · unreadable {none}'


# ───────────────────────────── TK21 N28-09 / N28-04 ─────────────────────────────
def tk21(P):
    root = P['root']
    T = load(root / 'harness/intel/tooling_intel.py', 'tk21tool')
    rt = root / 'rt21'
    rt.mkdir(exist_ok=True)
    (rt / 'tooling_20261101T000000.json').write_text(json.dumps({'captured': '2026-11-01T00:00:00+00:00', 'kpis': {
        'determinism': {'artifacts/index.html': 'byte-exact', 'artifacts/x.html': 'DIFFERS'}}}))
    (rt / 'tooling_20261102T000000.json').write_text(json.dumps({'captured': '2026-11-02T00:00:00+00:00', 'kpis': {'determinism': {}}}))
    (rt / 'tooling_20261103T000000.json').write_text('{torn')
    import datetime
    at = datetime.datetime(2026, 11, 1, 1, 0, 0, tzinfo=datetime.timezone.utc)
    d = T.determinism_last(rt, at)
    empty = T.determinism_last(root / 'no_rt')
    os.environ['ROUND_CKPT_OUT'] = str(root / 'ckpt21')
    try:
        k = T.run(root, root / 'no_memory_dir')
    finally:
        os.environ.pop('ROUND_CKPT_OUT', None)
    cov = T.kat_coverage(ROOT)
    v = T.targets({'tools_without_kat': ['harness/x.py']})
    ok = (isinstance(d, dict) and d['file'] == 'harness/runtime/tooling_20261101T000000.json' and d['mismatches'] == 1
          and d['age_s'] == 3600 and empty == 'pending' and k['determinism_mismatches'] == 'pending' and 'determinism_last' in k
          and any('without a KAT' in x for x in v) and T.targets({'tools_without_kat': []}) == []
          and cov['tools_without_kat'] == [] and cov['tools_total'] >= 78)
    return ok, (f"last {d if not isinstance(d, dict) else (d['file'], d['mismatches'], d['age_s'])} · none {empty} · default run "
                f"mismatches {k.get('determinism_mismatches')} · coverage {cov['tools_with_kat']}/{cov['tools_total']} "
                f"missing {cov['tools_without_kat'][:4]}")


# ───────────────────────────── TK22 minelib corpus ─────────────────────────────
def tk22(P):
    root = P['root']
    tags = root / 'harness/corpus/tags.tsv'
    tags.unlink(missing_ok=True)
    raw = root / 'harness/model/raw'
    before = {p.name: p.read_bytes() for p in raw.glob('*.json')}
    r1 = run(root, ['harness/miners/mine_inventory.py'])
    r2 = run(root, ['harness/miners/mine_coverage.py'])
    after = {p.name: p.read_bytes() for p in raw.glob('*.json')}
    tags.write_text('BlockReward\tblockchain/reward.go\t5\tfunc\tblockchain\nbad line\n')
    M = load(root / 'harness/miners/minelib.py', 'tk22ml')
    t = M.tags()
    ok = (r1[0] == 2 and 'prep_corpus.py' in r1[2] and r2[0] == 2 and 'prep_corpus.py' in r2[2] and before == after
          and 'Traceback' not in r2[2] and t == [('BlockReward', 'blockchain/reward.go', 5, 'func', 'blockchain')])
    return ok, (f'inventory rc {r1[0]} {r1[2].strip()[:70]!r} · coverage rc {r2[0]} · raw untouched {before == after} · '
                f'parsed {t}')


KATS = [('TK7', tk7), ('TK8', tk8), ('TK9', tk9), ('TK10', tk10), ('TK11', tk11), ('TK12', tk12), ('TK13', tk13),
        ('TK14', tk14), ('TK15', tk15), ('TK16', tk16), ('TK17', tk17), ('TK18', tk18), ('TK19', tk19), ('TK20', tk20),
        ('TK21', tk21), ('TK22', tk22)]
OWNERS = {f'r28 {k}': [k] for k, _ in KATS}

MUTATIONS = [   # (repo-relative file, find, replace, why): applied in the mutant's clone only
    ('harness/ask.py', "* (2.0 if w in str(r.get('title', '')).lower() else 1.0)", "* 1.0", 'r28 TK7: the title weight is lost'),
    ('harness/ask.py', "if w not in STOP and len(w) > 1]", "if len(w) > 1]", 'r28 TK7: stop words are searched'),
    ('harness/ask.py', """'where': f"{e['file']}:{e.get('line')}",""", """'where': e['file'],""", 'r28 TK7: the answer loses its line'),
    ('harness/forensics/s7_replay.py', "ok = rep['result'] == 'PASS' and (mode != 'full' or rsha in recorded)",
     "ok = rep['result'] == 'PASS'", 'r28 TK8: a full replay passes without a recorded report'),
    ('harness/forensics/s7_replay.py', " if rec.get('manifest_sha256') == rep['manifest_sha256'] else set()", "",
     'r28 TK8: a report recorded for another manifest counts'),
    ('harness/forensics/s7_replay.py', "    Path(a.out).write_text(", "    rec_p.write_text(", 'r28 TK8: the S7 run writes the G28 record'),
    ('harness/forensics/write_manifest.py', " if p.is_file() and p.name != 'manifest.json'}", " if p.is_file()}",
     'r28 TK9: the manifest hashes itself'),
    ('harness/forensics/write_manifest.py', "'stages': dict(old.get('stages', {}), **{a.stage: sorted(files)}),",
     "'stages': {a.stage: sorted(files)},", 'r28 TK9: an earlier stage is forgotten'),
    ('harness/forensics/write_manifest.py', "{k: v for k, v in old.get('tool_versions', {}).items() if k == 'decoder_sha256'}", "{}",
     'r28 TK9: the decoder hash is dropped without --decoder'),
    ('harness/hooks/autosync.py', "    if p in SKIP or not any(", "    if not any(", 'r28 TK10: the build re-triggers on its own output'),
    ('harness/hooks/autosync.py', "any(p == w or w in p.parents for w in WATCH)", "any(str(p).startswith(str(w)) for w in WATCH)",
     'r28 TK10: a path-prefix near miss triggers a build'),
    ('harness/hooks/autosync.py', "        msg = (f\"dero-arch autosync: build FAILED", "        msg = (f\"dero-arch autosync: build failed",
     'r28 TK10: a failed build is not reported as FAILED'),
    ('harness/kit/cutfix.py', "        if src[ls:m.start()].lstrip().startswith('#'):\n            continue",
     "        if False:\n            continue", 'r28 TK11: a commented-out slice is linted'),
    ('harness/kit/cutfix.py', "        elif re.search(r'[\\s+\\-*/%,]', expr):\n            continue",
     "        elif False:\n            continue", 'r28 TK11: a slice inside an operator expression is rewritten'),
    ('harness/kit/cutfix.py', "            if n < mn:\n                continue", "            if False:\n                continue",
     'r28 TK11: a format slice below --min is rewritten'),
    ('harness/kit/textkit.py', "                ok = glyph or ((el['tt'] or el['title_child']) and el['mark'])",
     "                ok = glyph or (el['tt'] or el['title_child'])", 'r28 TK12: a cut with a title but no ⓘ passes'),
    ('harness/kit/textkit.py', "        if any(x['t'] in self.SKIP or x.get('verbatim') for x in self.st):",
     "        if any(x.get('verbatim') for x in self.st):", 'r28 TK12: a log line in <pre> is a cut'),
    ('harness/kit/textkit.py', "    return Clipped(t.rstrip('…')[:max(1, n - 2)].rstrip() + '…', full)\n\n\ndef fit(",
     "    return t[:max(1, n - 2)].rstrip() + '…'\n\n\ndef fit(", 'r28 TK12: clip loses the full sentence'),
    ('harness/kit/assetkit.py', "        if T['notag']:\n            notag += 1\n            continue",
     "        if T['notag']:\n            notag += 1", 'r28 TK13: an opted-out ledger table is audited'),
    ('harness/kit/assetkit.py', "                if not c['ct']:\n                    miss.append(",
     "                if False:\n                    miss.append(", 'r28 TK13: an untagged asset cell passes'),
    ('harness/kit/assetkit.py', "(x.get('k') == 'f' and str(x.get('p', '')).startswith('/'))", "(x.get('k') == 'f')",
     'r28 TK13: a relative citation path is well-formed'),
    ('harness/kit/retrofit.py', "    ak.reg_reset()\n    h = strip(h, ev)\n", "    ak.reg_reset()\n",
     'r28 TK14: apply is not idempotent (no strip first)'),
    ('harness/kit/retrofit.py', "    (re.compile(r'<!--akr:kit-->.*?<!--/akr:kit-->', re.S), ''),\n", "",
     'r28 TK14: strip leaves the kit block behind'),
    ('harness/kit/retrofit.py', "        win = norm(' '.join(L[max(0, ln - 4):ln + 3]))\n        if q in win or",
     "        win = norm(' '.join(L[max(0, ln - 1):ln]))\n        if q in win or", 'r28 TK14: a citation must sit on its exact line'),
    ('harness/kit/retrofit.py', "        if len(hits) == 1:\n            x['l'] = hits[0] + 1",
     "        if hits:\n            x['l'] = hits[0] + 1", 'r28 TK14: an ambiguous quote is relocated'),
    ('harness/kit/kitgate.py', "if not re.search(r'type=\"(?!text/javascript|application/javascript|module)', attrs))",
     "if True)", 'r28 TK15: a JSON data block is parsed as JavaScript'),
    ('harness/kit/kitgate.py', "        elif t not in OPTIONAL:\n            self.err.append(f'stray </{t}>')",
     "        elif False:\n            self.err.append(f'stray </{t}>')", 'r28 TK15: a stray end tag passes'),
    ('harness/kit/kitgate.py', "                if x not in OPTIONAL:\n                    self.err.append(f'unclosed <{x}> before </{t}>')",
     "                self.err.append(f'unclosed <{x}> before </{t}>')", 'r28 TK15: an omitted optional end tag fails'),
    ('harness/kit/urlcheck.py', "            win = norm(' '.join(lines[max(0, line[0] - 4):line[1] + 3]))",
     "            win = norm(' '.join(lines[line[0] - 1:line[1]]))", 'r28 TK16: a #L citation must sit on its exact line'),
    ('harness/kit/urlcheck.py', ".replace('“', '\"').replace('”', '\"')", "", 'r28 TK16: typographic quotes are not normalised'),
    ('harness/kit/urlcheck.py', "            return (False, 'line-mismatch', h) if q in norm(body) else (False, 'quote-not-found', h)",
     "            return (False, 'quote-not-found', h)", 'r28 TK16: a quote elsewhere in the file reads not found'),
    ('harness/intel/tooling_intel.py', "        if not rid or st == 'planned':\n            continue",
     "        if not rid:\n            continue", 'r28 TK17: a planned round must already be in every list'),
    ('harness/intel/tooling_intel.py', "        if areas_rounds is not None and rid not in areas_rounds:",
     "        if False:", 'r28 TK17: areas.json rounds is not checked (B149)'),
    ('harness/intel/tooling_intel.py', "num.isdigit() and int(num) >= min(choices) and int(num) not in choices:",
     "num.isdigit() and int(num) not in choices:", 'r28 TK17: a round older than the ledger pages is required there'),
    ('harness/intel/tooling_intel.py', "    if isinstance(k.get('round_list_gaps'), list) and k['round_list_gaps']:",
     "    if False:", 'r28 TK17: a round-list gap is not a target'),
    ('harness/kat/test_harness_tooling_r26.py', "    m = lines[-1]\n", "    m = lines[0]\n", 'r28 TK18: the first ORDER line is mutated'),
    ('harness/kat/test_harness_tooling_r26.py', "'ORDER += [' + ', '.join(items[:-1]) + ']'", "'ORDER += [' + ', '.join(items) + ']'",
     'r28 TK18: the HT11 mutation is a no-op'),
    ('harness/intel/round_checkpoint.py', "if str(c).strip() == 'derod' and str(p).strip().isdigit()",
     "if 'derod' in str(c) and str(p).strip().isdigit()", 'r28 TK19: a near-name process is a derod'),
    ('harness/intel/round_checkpoint.py', "    return mine[0] if len(mine) == 1 else ''", "    return mine[0] if mine else cands[0]",
     'r28 TK19: an ambiguous pair picks one'),
    ('harness/intel/round_checkpoint.py', "    pid = select_derod(ps_rows(), REPO, cwd_of)",
     "    pid = sh(\"pgrep -f '^./bin/derod|bin/derod --data-dir' | head -1\")", 'r28 TK19: the pattern lookup is back'),
    ('harness/miners/mine_evolution.py', "    if commits or k in planned:\n        return None", "    if commits:\n        return None",
     'r28 TK20: a planned round is an unverified item'),
    ('harness/miners/mine_evolution.py', "for r in reg.get('rounds') or [] if r.get('status') == 'planned'}",
     "for r in reg.get('rounds') or [] if r.get('status') != 'measured'}", 'r28 TK20: non-planned rounds count as planned'),
    ('harness/intel/tooling_intel.py', "        if not isinstance(det, dict) or not det:\n            continue",
     "        if not isinstance(det, dict):\n            continue", 'r28 TK21: a record that did not measure is carried'),
    ('harness/intel/tooling_intel.py', "    if isinstance(k.get('tools_without_kat'), list) and k['tools_without_kat']:",
     "    if False:", 'r28 TK21: a tool without a KAT is not a target'),
    ('harness/intel/tooling_intel.py', "    if not opt_det:\n        k['determinism_last']", "    if opt_det:\n        k['determinism_last']",
     'r28 TK21: the default run carries nothing'),
    ('harness/miners/minelib.py', "        raise SystemExit(2)\n    return p.read_text()", "        return ''\n    return p.read_text()",
     'r28 TK22: a missing symbol table reads as empty'),
    ('harness/miners/mine_coverage.py', "    for l in M.tags_text().splitlines():", "    for l in (M.CORPUS / 'tags.tsv').read_text().splitlines():",
     'r28 TK22: mine_coverage reads the table without the guard'),
]


def clone_tree(dst):
    """an APFS clone (cp -c) of harness/ (+ __pycache__ dropped) under dst; the KATs read and write only there"""
    dst = Path(dst)
    dst.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(['cp', '-cR', str(HARNESS), str(dst / 'harness')], capture_output=True, text=True)
    if r.returncode != 0:
        shutil.copytree(HARNESS, dst / 'harness', symlinks=True)
    for p in sorted((dst / 'harness').rglob('__pycache__'), reverse=True):
        shutil.rmtree(p, ignore_errors=True)
    return dst


def run_kats(P):
    res = []
    for name, fn in KATS:
        try:
            o, det = fn({'root': P['root']})
        except Exception as e:                                    # noqa: BLE001
            o, det = False, f'{type(e).__name__}: {e}'
        res.append((name, o, det))
    return res


def run_on(mutation=None):
    with tempfile.TemporaryDirectory(prefix='tk28_') as d:
        root = clone_tree(Path(d) / 'r')
        if mutation:
            rel, find, repl, _ = mutation
            p = root / rel
            p.write_text(p.read_text(encoding='utf-8').replace(find, repl, 1), encoding='utf-8')
            if p.suffix == '.py':
                compile(p.read_text(encoding='utf-8'), str(p), 'exec')
        return run_kats({'root': root})


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_r28', HARNESS / 'kit' / 'katmut.py')
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
        print(f"{'ok  ' if o else 'FAIL'} {name} {det[:600]}")
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
        missed += verdict != 'proved'
        coupled += bool(extra) and verdict == 'proved'
    print('\n' + K.summary('r28 tools-kats KATs', len(KATS), len(muts), missed, coupled))
    return 4 if missed or coupled else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
