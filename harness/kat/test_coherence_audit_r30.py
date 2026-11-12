#!/usr/bin/env python3
"""KAT + mutation proofs for R30 B205 (rft §6 step 22a, §2.20): harness/intel/coherence_audit.py. No live file is read
or written: the round is a temp git repo built here.

  CA1  a coherent round (a registered KAT, the helper it tests, a module only that helper imports, a Go file whose
       package has NEW_TESTS, a registered Go test, a generator change with no figure, a record its writer names, a
       document) exits 0 with every new file 'ok'.
  CA2  an orphan tool (a new .py nothing reaches) FAILS ('orphan tool').
  CA3  an unregistered KAT FAILS: a test_*.py in no areas.json kat_files, one with no STEP_BUDGETS row, and a
       *_test.go whose test names are not in NEW_TESTS.
  CA4  a hand-typed figure in a generator string literal ("mean 96,205 H/s") FAILS ('literal'); the same line with
       `# literal-ok: <why>` and a computed f-string do not.
  CA6  r30 verify D2: a reach counts only from code (an import, a path string, a registry entry): forged orphans
       harness/intel/census.py and fetch.py, named only in a reached helper's docstring, a comment and a message
       string as bare words, and in a reached shell script's comments, FAIL ('orphan tool'); a path string in the KAT's code (CA1 writer.py) does reach.
       CA4 (verify D3) also: an integer hash rate '94273 H/s', an integer '95 %' and '96k H/s' FAIL; 'width:100%'
       is no figure; a k-suffixed figure marked `# literal-ok:` passes.
  CA5  reach is transitive (a module named only by a reached helper is reached) and --record writes
       harness/runtime/<round>_coherence_audit.txt; a FAIL exits 4.

  python3 -I harness/kat/test_coherence_audit_r30.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not proved (MISSED / WRONG-KAT / INVALID) or was coupled.
"""
import importlib.util, json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
PATHS = {'ca': 'harness/intel/coherence_audit.py'}
ENV = {**{k: v for k, v in os.environ.items() if not k.startswith('GIT_')}, 'GIT_CONFIG_GLOBAL': os.devnull,
       'GIT_CONFIG_NOSYSTEM': '1', 'GIT_AUTHOR_NAME': 'kat', 'GIT_AUTHOR_EMAIL': 'kat@invalid',
       'GIT_COMMITTER_NAME': 'kat', 'GIT_COMMITTER_EMAIL': 'kat@invalid', 'LC_ALL': 'C'}
FIX = {}


def P(over, key):
    return Path(over.get(key) or ROOT / PATHS[key])


def sh(*cmd, cwd):
    r = subprocess.run(list(cmd), cwd=cwd, env=ENV, capture_output=True, text=True, timeout=120)
    if r.returncode:
        raise RuntimeError(f'{cmd[:3]} rc {r.returncode}: {r.stderr[:200]}')
    return r.stdout


def put(root, files):
    for rel, body in files.items():
        p = Path(root) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)


def commit(root, msg):
    sh('git', 'add', '-A', cwd=root)
    sh('git', 'commit', '-q', '-m', msg, cwd=root)
    return sh('git', 'rev-parse', 'HEAD', cwd=root).strip()


def fixture():
    """(repo, base, good, bad) built once per process."""
    if FIX:
        return FIX['v']
    d = Path(tempfile.mkdtemp(prefix='ca30-'))
    sh('git', 'init', '-q', str(d), cwd=d.parent)
    areas = {'areas': [{'id': 'tooling', 'kat_files': ['harness/kat/test_good_r9.py', 'harness/kat/test_nobudget_r9.py']}]}
    put(d, {'harness/round.json': json.dumps({'current': 'r9', 'rounds': [{'id': 'r9', 'new_tests_base': 'pending'}]}),
            'harness/areas.json': json.dumps(areas),
            'harness/loop/STEP_BUDGETS.json': json.dumps({'steps': {'harness/kat/test_good_r9.py': 30,
                                                                    'harness/kat/test_unreg_r9.py': 30}}),
            'harness/pipeline/fix_build_verify.py': "NEW_TESTS = {'./pkg/': 'TestOld|TestBar'}\n",
            'harness/run_gates.py': '# gates\n',
            'artifacts/src/gen_page.py': "def page(v):\n    return f'mean {v} H/s'\n",
            'pkg/old.go': 'package pkg\n'})
    base = commit(d, 'base')
    rj = json.loads((d / 'harness/round.json').read_text())
    rj['rounds'][0]['new_tests_base'] = base
    put(d, {'harness/round.json': json.dumps(rj),
            'harness/kat/test_good_r9.py': "# tests tools/x/helper.py\nimport helper\n",
            'tools/x/helper.py': "import chainmod\n",
            'harness/kit/chainmod.py': "X = 1\n",
            'pkg/lib.go': 'package pkg\n',
            'pkg/y_test.go': 'package pkg\nfunc TestBar(t *T) {}\n',
            'artifacts/src/gen_page.py': "def page(v):\n    return f'mean {v} H/s'\n\n\ndef unit():\n    return 'kH/s'\n",
            'harness/runtime/goodfam_20261108T010203.json': '{}\n',
            'tools/x/writer.py': "# tested by test_good_r9\nOUT = 'harness/runtime/goodfam_'\n",
            'harness/kat/README.md': 'notes\n'})
    # writer.py is reached by a path string in the KAT's code (r30 verify D2: a comment naming it would not count)
    (d / 'harness/kat/test_good_r9.py').write_text("# tests tools/x/helper.py\nimport helper\nWRITER = 'tools/x/writer.py'\n")
    good = commit(d, 'good')
    put(d, {'harness/kit/orphan_tool.py': "print('nobody runs me')\n",
            # r30 verify D2: forged orphans whose stems / file names occur only in prose of a reached file (a docstring,
            # a comment, a bare word in a message string): the pre-fix audit marked both reached
            'harness/intel/census.py': "ROWS = []\n", 'harness/intel/fetch.py': "URL = None\n",
            'tools/x/helper.py': ('"""helper: fetch the census rows (see harness/intel/census.py and fetch.py)."""\n'
                                  "import chainmod\n# runs harness/intel/fetch.py first\n\n\ndef fetch():\n"
                                  "    print('fetch the census before the round')\n"),
            'harness/kat/test_good_r9.py': "# tests tools/x/helper.py\nimport helper\nWRITER = 'tools/x/writer.py'\nRUN = 'tools/x/run.sh'\n",
            'tools/x/run.sh': "#!/bin/sh\n# then: python3 harness/intel/fetch.py --all\necho done  # census.py next\n",
            'harness/kat/test_unreg_r9.py': "# in no kat_files\n",
            'harness/kat/test_nobudget_r9.py': "# in kat_files, no STEP_BUDGETS row\n",
            'pkg/x_test.go': 'package pkg\nfunc TestFoo(t *T) {}\n',
            'artifacts/src/gen_page.py': ("def page(v):\n    return f'mean {v} H/s'\n\n\ndef unit():\n    return 'kH/s'\n"
                                          "\n\nLIVE = 'mean 96,205 H/s at 18.01 cores'\n"
                                          "CONST = 'block reward 0.615 DERO'  # literal-ok: protocol constant\n"
                                          # r30 verify D3: integer H/s, integer %, k-suffixed; a CSS value is no figure
                                          "PEAK = 'peak 94273 H/s'\nDUTY = 'GPU duty 95 %'\nNOW = 'about 96k H/s'\n"
                                          "CSS = 'width:100%'\nCAP = 'cap 96k H/s'  # literal-ok: the flag default\n")})
    bad = commit(d, 'bad')
    FIX['v'] = (d, base, good, bad)
    return FIX['v']


def run(over, *args):
    d, *_ = fixture()
    r = subprocess.run([sys.executable, '-I', str(P(over, 'ca')), '--root', str(d), *args], capture_output=True,
                       text=True, timeout=120, env=ENV)
    return r.returncode, r.stdout


def rows_of(over, head):
    d, base, good, bad = fixture()
    rc, out = run(over, '--base', base, '--head', head, '--json')
    js = out[:out.rfind('}') + 1]
    try:
        return rc, json.loads(js)
    except ValueError:
        return rc, {'rows': {}, 'literals': [], 'raw': out[-200:]}


def kat_ca1(over):
    _, base, good, _ = fixture()
    rc, j = rows_of(over, good)
    bad = {f: v for f, v in j['rows'].items() if v[1] != 'ok'}
    if rc != 0 or bad or len(j['rows']) != 8 or j['literals']:
        return False, f"rc {rc}, not ok {bad}, rows {len(j['rows'])}, literals {j['literals']}"
    return True, f"{len(j['rows'])} new files, all reached, exit 0"


def kat_ca2(over):
    _, _, _, bad = fixture()
    rc, j = rows_of(over, bad)
    v = j['rows'].get('harness/kit/orphan_tool.py')
    ok = v and v[1] == 'FAIL' and 'orphan' in v[2]       # the exit code is CA5's
    return bool(ok), f'orphan row {v}, rc {rc}'


def kat_ca3(over):
    _, _, _, bad = fixture()
    rc, j = rows_of(over, bad)
    want = ['harness/kat/test_unreg_r9.py', 'harness/kat/test_nobudget_r9.py', 'pkg/x_test.go']
    got = {f: j['rows'].get(f) for f in want}
    ok = all(v and v[1] == 'FAIL' and 'unregistered KAT' in v[2] for v in got.values())
    ok = ok and 'STEP_BUDGETS' in got['harness/kat/test_nobudget_r9.py'][2] and 'kat_files' in got['harness/kat/test_unreg_r9.py'][2]
    return bool(ok), f'{got}, rc {rc}'


def kat_ca4(over):
    _, _, _, bad = fixture()
    rc, j = rows_of(over, bad)
    lits = j['literals']
    figs = sorted(x[2] for x in lits)
    ok = all(x[0] == 'artifacts/src/gen_page.py' for x in lits) and figs == sorted(['96,205', '94273 H/s', '95 %', '96k H/s'])
    return ok, f'literals {lits}, rc {rc}'


def kat_ca6(over):
    _, _, _, bad = fixture()
    rc, j = rows_of(over, bad)
    got = {f: j['rows'].get(f) for f in ('harness/intel/census.py', 'harness/intel/fetch.py', 'tools/x/helper.py',
                                         'tools/x/run.sh')}
    ok = (all(got[f] and got[f][1] == 'FAIL' and 'orphan' in got[f][2] for f in list(got)[:2])
          and all(got[f] and got[f][1] == 'ok' for f in list(got)[2:]))
    return bool(ok), f'{got}, rc {rc}'


def kat_ca5(over):
    d, base, good, bad = fixture()
    rc, j = rows_of(over, good)
    v = j['rows'].get('harness/kit/chainmod.py')
    rec = d / 'harness/runtime/r9_coherence_audit.txt'
    rec.unlink(missing_ok=True)
    rc2, _ = run(over, '--base', base, '--head', bad, '--record')
    ok = v and v[1] == 'ok' and 'helper.py' in v[2] and rc2 == 4 and rec.exists() and 'orphan_tool.py' in rec.read_text()
    return bool(ok), f'chainmod {v}; --record rc {rc2}, record {rec.exists()}'


DEC_RFT = '''# rft
## 0. The loop
### 0.11 Decisions without waiting
text
### 0.12 Decision log

| ID | Date (PST) | Question | Options | Choice | Why best for quality | Evidence anchors | Re-check |
|---|---|---|---|---|---|---|---|
| D-1 | 2026-11-11 | q | a/b | a | measured | `harness/run_gates.py`; §0.11 | next run |
| D-2 | 2026-11-11 | q | a/b | b | measured | none given | next run |
| D-3 | 2026-11-11 | q | a/b | b | measured | `harness/no_such_file.json` | next run |
| D-4 | 2026-11-11 | q | a/b | b |  | `harness/run_gates.py` | next run |
| D-5 | 2026-11-11 | q | a/b | b | measured | §9.9 | next run |
| D-6 | 2026-11-11 | q | a/b | b | measured | §0.12 | next run |

### 0.13 Next
| D-9 | 2026-11-11 | q | a/b | b | measured | none | outside the log |
'''


def kat_ca7(over):
    """r30 (§0.12, user §2.23): a decision row without a resolving evidence anchor (none, a missing file, a missing §)
    or without its quality reason FAILs; a row with a file or § anchor passes; rows outside the section are not read;
    the CLI counts each such row in its FAIL total. Judged on the JSON 'fail' DELTA between the two rft variants (not on
    the exit code or the other classes), so the B205 reach/exit mutations stay owned by CA1/CA5/CA6 (coupled 0)"""
    d, base, good, _ = fixture()
    spec = importlib.util.spec_from_file_location('ca7_mod', P(over, 'ca'))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    got = dict(m.decision_problems(DEC_RFT, d))
    pure_ok = (sorted(got) == ['D-1', 'D-2', 'D-3', 'D-4', 'D-5', 'D-6'] and got['D-1'] is None and got['D-6'] is None
               and all(got[x] for x in ('D-2', 'D-3', 'D-4', 'D-5')))
    rp = d / 'artifacts/dero-rft.md'
    try:
        rp.parent.mkdir(parents=True, exist_ok=True)
        rp.write_text(DEC_RFT)
        rc_bad, out_bad = run(over, '--base', base, '--head', good, '--json')
        rp.write_text(DEC_RFT.replace('\n| D-2 ', '\n| X-2 ').replace('\n| D-3 ', '\n| X-3 ')
                      .replace('\n| D-4 ', '\n| X-4 ').replace('\n| D-5 ', '\n| X-5 '))
        rc_ok, out_ok = run(over, '--base', base, '--head', good, '--json')
    finally:
        rp.unlink(missing_ok=True)
    def js(out):
        try:
            return json.loads(out[:out.rfind('}') + 1])
        except ValueError:
            return {}
    jb, jo = js(out_bad), js(out_ok)
    fb, fo = jb.get('fail'), jo.get('fail')
    cli_ok = (isinstance(fb, int) and isinstance(fo, int) and fb - fo == 4
              and sum(1 for _, w in jb.get('decisions', []) if w) == 4 and len(jo.get('decisions', [])) == 2
              and not any(w for _, w in jo.get('decisions', [])) and 'decisions 6 (FAIL 4)' in out_bad
              and 'decisions 2 (FAIL 0)' in out_ok)
    return pure_ok and cli_ok, (got, fb, fo, rc_bad, rc_ok, out_bad.strip().splitlines()[-1:])


KATS = [('CA1', kat_ca1), ('CA2', kat_ca2), ('CA3', kat_ca3), ('CA4', kat_ca4), ('CA5', kat_ca5), ('CA6', kat_ca6),
        ('CA7', kat_ca7)]
OWNERS = {'r30 CA6': ['CA6'], 'r30 CA2': ['CA2', 'CA6'], 'r30 CA3': ['CA3'], 'r30 CA4': ['CA4'], 'r30 CA5': ['CA5', 'CA1', 'CA6'], 'r30 CA1': ['CA1'], 'r30 CA7': ['CA7']}

MUTATIONS = [   # (key, find, replace, why)
    ('ca', "('code', 'FAIL', 'orphan tool: no KAT, gate, pipeline step or generator reaches it')",
     "('code', 'ok', 'orphan tool: no KAT, gate, pipeline step or generator reaches it')", 'r30 CA2: B205 an orphan tool passes'),
    ('ca', "('STEP_BUDGETS row', f in steps)", "('STEP_BUDGETS row', True)", 'r30 CA3: B205 a KAT without a budget row passes'),
    ('ca', "('areas.json kat_files', f in kf)", "('areas.json kat_files', True)", 'r30 CA3: B205 a KAT in no area passes'),
    ('ca', "            rows[f] = (c, 'ok', f'NEW_TESTS {hit[0]}') if hit else (\n                c, 'FAIL',",
     "            rows[f] = (c, 'ok', f'NEW_TESTS {hit[0]}') if hit else (\n                c, 'ok',",
     'r30 CA3: B205 a Go test outside NEW_TESTS passes'),
    ('ca', "    if not gens:\n        return out\n", "    return out\n", 'r30 CA4: B205 generator literals are not read'),
    ('ca', "            if OK_MARK not in code and not code.lstrip().startswith('#'):",
     "            if not code.lstrip().startswith('#'):", 'r30 CA4: B205 the literal-ok marker is ignored'),
    ('ca', "        if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in doc:",
     "        if isinstance(n, ast.Constant) and isinstance(n.value, str):",
     'r30 CA6: verify D2 a docstring counts as a reach'),
    ('ca', "    return re.sub(r'(?m)(^|\\s)#.*$', r'\\1', text)", "    return text",
     'r30 CA6: verify D2 a shell comment counts as a reach'),
    ('ca', "    return any(mentions(t, n) for t in strs for n in names_of(rel) if n != p.stem)",
     "    return any(mentions(t, n) for t in strs for n in names_of(rel))",
     'r30 CA6: verify D2 a module stem as a bare word in a string reaches (the pre-fix match)'),
    ('ca', "\n                       r'''|\\d+(?:\\.\\d+)?\\s?[kM]\\s?(?:H/s|H/cpu-s|DERO|MB|GB)|\\d+\\s?(?:kH/s|H/s|H/cpu-s)|(?<!:)(?<!: )\\d+\\s?%)''')",
     "\n                       r''')''')", 'r30 CA4: verify D3 integer / k-suffixed figures are not read (the pre-fix FIGURE_RX)'),
    ('ca', "|(?<!:)(?<!: )\\d+\\s?%)''')", "|\\d+\\s?%)''')", 'r30 CA4: verify D3 a CSS percentage is read as a figure'),
    ('ca', "    changed = True\n    while changed:", "    changed = False\n    while changed:",
     'r30 CA5: B205 reach is not transitive (only the roots count)'),
    ('ca', "    return 4 if nfail else 0", "    return 0", 'r30 CA5: B205 a FAIL exits 0'),
    # r30 §0.12 / §2.23 decision log (CA7)
    ('ca', "        if not good:\n            out.append((did, 'no evidence anchor resolves'",
     "        if False:\n            out.append((did, 'no evidence anchor resolves'", 'r30 CA7: a decision without evidence passes'),
    ('ca', "            (good if path and f.exists() else bad).append(a)", "            good.append(a)",
     'r30 CA7: an anchor to a missing file counts as evidence'),
    ('ca', "            (good if section_exists(rft, num) else bad).append('§' + num)", "            good.append('§' + num)",
     'r30 CA7: a missing § counts as evidence'),
    ('ca', "        if not why or why in ('-', '—'):", "        if False:", 'r30 CA7: a decision without its quality reason passes'),
    ('ca', "    nfail += len(dfail)", "    nfail += 0", 'r30 CA7: a decision FAIL is not counted in the FAIL total (nor the exit code)'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_r30ca', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run_kats(over):
    out = []
    for name, fn in KATS:
        try:
            ok, det = fn(over)
        except Exception as e:                                    # noqa: BLE001 — a crash is a failure
            ok, det = False, f'{type(e).__name__}: {e}'
        out.append((name, ok, det))
    return out


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    try:
        res = run_kats({})
        for name, ok, det in res:
            print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
        fails = sum(1 for _, ok, _ in res if not ok)
        K = katmut()
        missed = coupled = 0
        for key, find, repl, why in MUTATIONS:
            src = P({}, key)
            text = src.read_text()
            if text.count(find) != 1:
                print(f'  INVALID  {why} — find text occurs {text.count(find)} time(s)')
                missed += 1
                continue
            d = Path(tempfile.mkdtemp(prefix='ca30-mut-'))
            mp = d / src.name
            mp.write_text(text.replace(find, repl, 1))
            try:
                failed = [n for n, ok, _ in run_kats({key: mp}) if not ok]
            finally:
                shutil.rmtree(d, ignore_errors=True)
            verdict, extra = K.classify(failed, OWNERS.get(K.defect_of(why), []))
            print(f'  {verdict:9s} {why}  {failed}')
            missed += verdict != 'proved'
            coupled += bool(extra) and verdict == 'proved'
        print('\n' + K.summary('r30 coherence-audit KATs', len(KATS) - fails if fails else len(KATS), len(MUTATIONS), missed, coupled)
              + (f' · FAIL: {coupled} coupled mutation(s) (the pipeline requires 0)' if coupled else ''))
        return 3 if fails else (4 if missed or coupled else 0)
    finally:
        if FIX:
            shutil.rmtree(FIX['v'][0], ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
