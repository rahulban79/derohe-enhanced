#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the R27 tools-kats fixes (dero-rft §0.9 rules 1-2; §7 B120, B134; the R26
measurement's working-tools and KAT-suite gaps).

Every KAT runs on an APFS clone of harness/ (the mutant's clone under a mutation), never on the live tree: TK2 writes
forged records into it and TK1 runs every tool in it.

  TK1 B120: every harness tool (a __main__ entry, KAT files aside; tooling_intel.harness_tools) run as `--help` in the
      clone under sandbox-exec (no network, no write outside the clone, no signal to another process, HOME inside the
      clone, 60 s) exits 0, prints its usage and writes nothing; the static census tools_without_help is empty on the
      tree and names a forged tool without a parser (and not one with the r27 guard). A tool a committed forensic
      dataset pins by content (tooling_intel.content_pinned: harness/forensics/pins.py) keeps its bytes until the next
      dataset version (G28); it is listed apart and must still write nothing.
  TK2 gen_deroarch lost anchors (R26: a build before the miners printed 6352/6396 anchors and nothing else): on a
      forged raw file (generated_by mine_consensus.py) quoting a forged runtime file, resolve() tallies the MISSING
      quote and the NOFILE anchor per (key, miner, file, status), a second resolve() counts the same (the tally is
      reset), lost_report() names the miner to re-run; build() prints each line as WARN and `--strict` returns 3.
  TK3 KAT independence + coverage map: katmut.classify (proved / MISSED / WRONG-KAT, coupled = failed KATs outside the
      defect's owners), defect_of; tooling_intel.kat_coupled (None when unmeasured) and kat_coverage on a forged tree
      (a tool its KAT names by path segment is covered, a substring near-miss is not); no KAT calls scrub_control()
      without a forged root and scrubber (the HT12 coupling); the r26 runner proves a mutation only by its owner and
      exits 4 on a coupled one.
  TK4 gen_deroarch CLI (KeyError '--help', exit 1): main(['--help']) 0, an unknown command 2, a flag on a command other
      than build 2, an unknown flag on build 2; nothing is resolved or written for any of them.
  TK5 B134 area_intel 'record' class: a recorded-findings KPI's regression / live alert is a low recorded-finding
      whose suggested row is RECORDED and names its record; node and network classes are unchanged; 'record' is a
      valid class, 'bogus' is not; the live registry classes forensics audit_fails and grade_pending 'record' and
      audit_unresolved 'node'.
  TK6 kit/pidwait (R26: three `until ! pgrep -f` loops matched their own command line): a running child is alive and
      wait_pid times out; once it exits it reads gone and is reaped (no zombie left behind); pid 1 (another
      user's: EPERM) is alive; pid 0 is refused; the CLI exits 1 on a live pid after --timeout and 0 on an ended one.

Mutation independence (harness/kit/katmut.py): each mutation's reason starts with its defect id (r27 TK<n>); a
mutation is proved only when that KAT fails, and a failure of another KAT is counted as coupled (target 0).

  python3 -I harness/kat/test_tools_kats_r27.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught by its own KAT, was INVALID, or coupled.
"""
import ast, collections, importlib.util, json, os, shutil, signal, subprocess, sys, tempfile, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
KIT_MODS = ('assetkit', 'connectorkit', 'textkit', 'diagramkit', 'areakit', 'consensuskit', 'peerkit', 'privkit',
            'prep_corpus', 'minelib', 'roundtracks')


def load(path, name):
    for m in KIT_MODS:                       # gen_deroarch imports these by name: never reuse another clone's copy
        sys.modules.pop(m, None)
    spec = importlib.util.spec_from_file_location(f'{name}_{abs(hash(str(path)))}_{len(sys.modules)}', path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


def fn_node(path, name):
    tree = ast.parse(Path(path).read_text(encoding='utf-8'))
    return next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)


def snapshot(root):
    return {str(p.relative_to(root)): (p.stat().st_size, p.stat().st_mtime_ns) for p in Path(root).rglob('*')
            if p.is_file() and '__pycache__' not in p.parts}


SANDBOX = '/usr/bin/sandbox-exec'


def profile(allow):
    paths = ' '.join(f'(subpath "{os.path.realpath(a)}")' for a in allow)
    return ('(version 1)\n(allow default)\n(deny network*)\n(deny signal (target others))\n'
            f'(deny file-write* (require-not (require-any {paths} (literal "/dev/null") (literal "/dev/tty")'
            ' (regex #"^/dev/fd/"))))\n')


# ───────────────────────────── TK1 B120 ─────────────────────────────
def run_help(clone, rel, prof):
    cmd = [sys.executable, '-I', '-B', str(clone / rel), '--help']
    if prof:
        cmd = [SANDBOX, '-p', prof] + cmd
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(clone / 'home'), 'PYTHONDONTWRITEBYTECODE': '1', 'TMPDIR': str(clone / 'tmp')}
    try:
        p = subprocess.run(['nice', '-n', '15'] + cmd, cwd=clone, capture_output=True, text=True, timeout=60, env=env)
        return p.returncode, (p.stdout + p.stderr)
    except subprocess.TimeoutExpired:
        return 'timeout', ''


def tk1(P):
    root = P['root']
    T = load(root / 'harness/intel/tooling_intel.py', 'tk1tool')
    tools = T.harness_tools(root)
    for d in ('home', 'tmp'):
        (root / d).mkdir(exist_ok=True)
    prof = profile([root]) if os.path.exists(SANDBOX) else None
    before = snapshot(root)
    with ThreadPoolExecutor(max_workers=4) as ex:
        res = dict(zip(tools, ex.map(lambda r: run_help(root, r, prof), tools)))
    after = snapshot(root)
    wrote = sorted(k for k in set(after) | set(before) if after.get(k) != before.get(k))
    pinned = T.content_pinned(ROOT)                    # the manifests live outside harness/: read them in the tree
    bad = {r: (rc, out.strip().splitlines()[-1][:120] if out.strip() else '') for r, (rc, out) in res.items()
           if r not in pinned and (rc != 0 or len(out.strip()) < 20)}
    census = T.tools_without_help(root, pinned=pinned)
    held = sorted(set(T.tools_without_help(root, pinned=set())) - set(census))
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / 'harness'
        f.mkdir()
        (f / 'bare.py').write_text('"""a tool"""\nimport sys\n\nif __name__ == \'__main__\':\n    open("x", "w")\n')
        (f / 'guarded.py').write_text('"""a tool"""\nif __name__ == \'__main__\' and {\'-h\', \'--help\'} & set(__import__(\'sys\').argv[1:]):\n'
                                      '    print(__doc__)\n    raise SystemExit(0)\n\nif __name__ == \'__main__\':\n    open("x", "w")\n')
        forged = T.tools_without_help(Path(d))
        # R28 merge (B165): no real pinned tool lacks --help any more, so the pinned exclusion is proved on a forged pin
        forged_pinned = T.tools_without_help(Path(d), pinned={'harness/bare.py'})
    ok = (len(tools) >= 60 and not bad and not wrote and census == [] and forged == ['harness/bare.py'] and prof is not None
          and held == [] and forged_pinned == [])   # R28 merge (B165): pins.py gained --help with dataset v3 (N28-08), so no pinned tool is held
    return ok, (f'{len(tools)} tools --help in the sandboxed clone: bad {dict(list(bad.items())[:4])} wrote {wrote[:4]} · '
                f'census {census[:4]} pinned-held {held} forged {forged} sandbox {prof is not None}')


# ───────────────────────────── TK2 lost anchors ─────────────────────────────
def tk2(P):
    root = P['root']
    G = load(root / 'harness/gen_deroarch.py', 'tk2gda')
    rt = root / 'harness/runtime'
    rt.mkdir(exist_ok=True)
    (rt / 'r27_tk2_forged.json').write_text('{\n "window_hours": 15.49,\n "blocks": 3000\n}\n')
    raw = root / 'harness/model/raw_tk2'
    raw.mkdir(parents=True, exist_ok=True)
    rows = [{'id': 'tk2-a', 'section': 'chainobs', 'title': 'window', 'claim': 'forged',
             'evidence': [{'file': 'harness/runtime/r27_tk2_forged.json', 'quote': '"window_hours": 15.49,'},
                          {'file': 'harness/runtime/r27_tk2_forged.json', 'quote': '"window_hours": 99.99,'}]},
            {'id': 'tk2-b', 'section': 'chainobs', 'title': 'gone', 'claim': 'forged',
             'evidence': [{'file': 'harness/runtime/r27_tk2_gone.json', 'quote': '"blocks": 3000 forged gone'}]}]
    (raw / 'consensus.json').write_text(json.dumps({'key': 'consensus', 'generated_by': 'mine_consensus.py', 'rows': rows}))
    (root / 'harness/model/verify_tk2').mkdir(exist_ok=True)
    G.RAW, G.RAW_KEYS, G.VERIFY = raw, ['consensus'], root / 'harness/model/verify_tk2'
    r1 = G.resolve()
    first = dict(G.LOST)
    r2 = G.resolve()
    second = dict(G.LOST)
    rep = G.lost_report(G.LOST)
    want = {('consensus', 'mine_consensus.py', 'harness/runtime/r27_tk2_forged.json', 'MISSING'): 1,
            ('consensus', 'mine_consensus.py', 'harness/runtime/r27_tk2_gone.json', 'NOFILE'): 1}
    names = all('re-run harness/miners/mine_consensus.py' in l for l in rep) and len(rep) == 2
    fallback = G.lost_report(collections.Counter({('peercards', None, 'x.json', 'MISSING'): 2}))
    bld = fn_node(root / 'harness/gen_deroarch.py', 'build')
    src = ast.unparse(bld)
    strict = ("return 3 if bad or lint or lost and strict else 0" in src or
              "return 3 if bad or lint or (lost and strict) else 0" in src)
    warns = "print('  WARN', l)" in src and 'lost = lost_report(LOST)' in src
    ok = (first == want and second == want and names and strict and warns and r1[3]['anchors_ok'] == 1
          and r2[3]['anchors'] == 3 and fallback and 'mine_peercards.py' in fallback[0] and fallback[0].startswith('2 anchor(s)'))
    return ok, f'lost {first} again {second == want} report {rep} fallback {fallback} strict {strict} warns {warns}'


# ───────────────────────────── TK3 independence + coverage ─────────────────────────────
def tk3(P):
    root = P['root']
    K = load(root / 'harness/kit/katmut.py', 'tk3km')
    T = load(root / 'harness/intel/tooling_intel.py', 'tk3tool')
    c = (K.classify([], ['A']), K.classify(['A'], ['A']), K.classify(['A', 'B'], ['A']), K.classify(['B'], ['A']),
         K.classify(['B'], []))
    want_c = (('MISSED', []), ('proved', []), ('proved', ['B']), ('WRONG-KAT', ['B']), ('WRONG-KAT', ['B']))
    d_ok = (K.defect_of('B98: x') == 'B98' and K.defect_of('B119 class: y') == 'B119' and K.defect_of('r27 TK3: z') == 'r27 TK3'
            and K.defect_of('no id here') is None)
    s = K.summary('x', 3, 10, 1, 2)
    coupled = (T.kat_coupled(['a', 'x: mutations proved 3/3 · mutations coupled 2', 'mutations coupled 1']),
               T.kat_coupled(['mutations proved 3/3']))
    with tempfile.TemporaryDirectory() as d:
        r = Path(d)
        for rel in ('harness/intel/a_tool.py', 'harness/miners/mine_a.py', 'harness/kit/b.py'):
            (r / rel).parent.mkdir(parents=True, exist_ok=True)
            (r / rel).write_text('"""t"""\nif __name__ == \'__main__\':\n    pass\n')
        (r / 'harness/kat').mkdir()
        (r / 'harness/kat/test_x.py').write_text("A = HARNESS / 'intel' / 'a_tool.py'\nB = 'xmine_a.py'\nC = 'harness/kit/b.py'\n")
        cov = T.kat_coverage(r)
    kats = sorted((root / 'harness/kat').glob('test_*.py'))
    bare = [f'{k.name}:{n.lineno}' for k in kats for n in ast.walk(ast.parse(k.read_text(encoding='utf-8')))
            if isinstance(n, ast.Call) and getattr(n.func, 'attr', getattr(n.func, 'id', None)) == 'scrub_control'
            and len(n.args) + len(n.keywords) < 2]
    r26 = ast.unparse(fn_node(root / 'harness/kat/test_harness_tooling_r26.py', 'main'))
    runner = 'K.classify(' in r26 and 'return 4 if missed or coupled else 0' in r26 and 'OWNERS.get(K.defect_of(why)' in r26
    ok = (c == want_c and d_ok and 'mutations proved 9/10' in s and 'mutations coupled 2' in s and coupled == (3, None)
          and cov['tools_without_kat'] == ['harness/miners/mine_a.py'] and cov['tools_total'] == 3 and not bare and runner)
    return ok, (f'classify {c} defect_of {d_ok} summary {s!r} coupled {coupled} coverage {cov["tools_without_kat"]} '
                f'bare scrub_control calls {bare} r26 runner {runner}')


# ───────────────────────────── TK4 gen_deroarch CLI ─────────────────────────────
def tk4(P):
    root = P['root']
    G = load(root / 'harness/gen_deroarch.py', 'tk4gda')
    calls = []
    for f in ('resolve', 'build', 'check', 'selftest', 'sync_skill'):
        setattr(G, f, (lambda name: (lambda *a, **k: calls.append(name) or 0))(f))
    import contextlib, io
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        rc = (G.main(['--help']), G.main(['-h']), G.main(['bogus']), G.main(['check', '--strict']), G.main(['build', '--nope']))
        work = list(calls)
        rb = G.main(['build', '--strict'])
    ok = rc == (0, 0, 2, 2, 2) and work == [] and rb == 0 and calls == ['build'] and 'THE CONTRACT' in out.getvalue()
    return ok, f'rc --help/-h/bogus/check --strict/build --nope {rc} work {work} build --strict -> {rb} {calls}'


# ───────────────────────────── TK5 B134 ─────────────────────────────
def tk5(P):
    root = P['root']
    A = load(root / 'harness/intel/area_intel.py', 'tk5area')
    rec = {'id': 'audit_fails', 'class': 'record', 'record': 'forensics/r<N>/audit/audit_report.json'}
    k1 = A.classed(rec, 'metric-regression', 'high', 'audit_fails: 0 (r25) -> 3 (r26)')
    k2 = A.classed(rec, 'live-alert', 'high', 'audit_fails = 3 trips > 0')
    k3 = A.classed({'id': 'peers_active'}, 'metric-regression', 'high', 'p')
    k4 = A.classed({'id': 'lag_max', 'class': 'network'}, 'metric-regression', 'high', 'l')
    row = A.suggested_row(k1[0], k1[2], 'forensics', 'x:1', 'r27')
    reg = A.load_registry(root)
    # the class errors only: the clone holds harness/ alone, so anchors into the rest of the tree do not resolve there
    e0 = [x for x in A.validate(reg, root)[0] if 'class must be one of' in x]
    bad = json.loads(json.dumps(reg))
    next(a for a in bad['areas'] if a['id'] == 'forensics')['metrics'][0]['class'] = 'bogus'
    e1 = [x for x in A.validate(bad, root)[0] if 'class must be one of' in x]
    cls = {m['id']: m.get('class', 'node') for a in reg['areas'] if a['id'] == 'forensics' for m in a.get('metrics', [])}
    live = (cls.get('audit_fails'), cls.get('grade_pending'), cls.get('audit_unresolved'))
    ok = (k1[:2] == ('recorded-finding', 'low') and k2[:2] == ('recorded-finding', 'low') and 'audit_report.json' in k1[2]
          and k3 == ('metric-regression', 'high', 'p') and k4[:2] == ('network-observation', 'medium')
          and '| RECORDED (self-detected r27' in row and not e0 and any('class must be one of' in x for x in e1)
          and live == ('record', 'record', 'node'))
    return ok, f'{k1[:2]} {k2[:2]} {k3[:2]} {k4[:2]} row {row[-90:]!r} errors {len(e0)}->{len(e1)} live {live}'


# ───────────────────────────── TK6 pidwait ─────────────────────────────
def tk6(P):
    root = P['root']
    W = load(root / 'harness/kit/pidwait.py', 'tk6pw')
    pid = os.posix_spawn('/bin/sleep', ['sleep', '30'], dict(os.environ))   # no Popen object: nothing reaps it for us
    try:
        a = W.alive(pid)
        t0 = time.monotonic()
        timed = W.wait_pid(pid, timeout=0.3, poll=0.05)
        took = time.monotonic() - t0
        cli_live = subprocess.run([sys.executable, '-I', str(root / 'harness/kit/pidwait.py'), str(pid), '--timeout', '0.3'],
                                  capture_output=True, text=True, timeout=30).returncode
        os.kill(pid, signal.SIGTERM)
        time.sleep(0.2)                                  # now an unreaped zombie child of this process
        gone = W.wait_pid(pid, timeout=5, poll=0.05)
        try:                                             # the waiter reaped it: no zombie is left behind (measured on
            reaped = os.waitpid(pid, os.WNOHANG)[0] != pid   # Darwin: kill(zombie, 0) SUCCEEDS, so a waiter that never
        except ChildProcessError:                        # reaps waits for ever; 'gone' and 'reaped' both check that)
            reaped = True
    finally:
        try:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        except (OSError, ChildProcessError):
            pass
    cli_gone = subprocess.run([sys.executable, '-I', str(root / 'harness/kit/pidwait.py'), str(pid), '--timeout', '1'],
                              capture_output=True, text=True, timeout=30).returncode
    one = W.alive(1)
    try:
        W.alive(0)
        zero = 'accepted'
    except ValueError:
        zero = 'refused'
    ok = (a and not timed and 0.25 <= took < 3 and gone and reaped and one and zero == 'refused' and cli_live == 1
          and cli_gone == 0)
    return ok, f'alive {a} timeout {timed} ({took:.2f} s) zombie gone {gone} reaped {reaped} pid1 {one} pid0 {zero} cli live {cli_live} gone {cli_gone}'


KATS = [('TK1', tk1), ('TK2', tk2), ('TK3', tk3), ('TK4', tk4), ('TK5', tk5), ('TK6', tk6)]
OWNERS = {f'r27 TK{i}': [f'TK{i}'] for i in range(1, 7)}
OWNERS['r27 TK4'] = ['TK4', 'TK1']     # gen_deroarch's --help is one of the B120 tools TK1 runs: both own that defect

MUTATIONS = [   # (repo-relative file, find, replace, why: 'r27 TK<n>: ...')
    ('harness/miners/mine_areas.py', "if __name__ == '__main__' and {'-h', '--help'}", "if False and {'-h', '--help'}",
     'r27 TK1: mine_areas --help runs the miner'),
    ('harness/intel/round_checkpoint.py', "if __name__ == '__main__' and {'-h', '--help'}", "if False and {'-h', '--help'}",
     'r27 TK1: round_checkpoint --help writes a checkpoint'),
    ('harness/intel/tooling_intel.py', "        if MAIN_RX.search(t) and not HELP_RX.search(t):", "        if False:",
     'r27 TK1: the --help census reports nothing'),
    ('harness/intel/tooling_intel.py', " or '__pycache__' in p.parts or rel in pinned:", " or '__pycache__' in p.parts:",
     'r27 TK1: a content-pinned tool is counted as one to convert (its bytes are pinned by G28)'),
    ('harness/gen_deroarch.py', "                    LOST[(key, miner, e['file'], e['status'])] += 1", "                    pass",
     'r27 TK2: a lost anchor is not tallied'),
    ('harness/gen_deroarch.py', "    stats = collections.Counter()\n    LOST.clear()\n", "    stats = collections.Counter()\n",
     'r27 TK2: the tally of the previous resolve is kept'),
    ('harness/gen_deroarch.py', "    return 3 if bad or lint or (lost and strict) else 0", "    return 3 if bad or lint else 0",
     'r27 TK2: build --strict passes with lost anchors'),
    ('harness/gen_deroarch.py', "re-run harness/miners/{miner or 'mine_' + key + '.py'} ", "re-run {key} ",
     'r27 TK2: the warning does not name the miner'),
    ('harness/kit/katmut.py', "    if not owners or not failed & owners:", "    if not owners:",
     'r27 TK3: a mutation caught only by another KAT counts as proved'),
    ('harness/kit/katmut.py', "    return 'proved', sorted(failed - owners)", "    return 'proved', []",
     'r27 TK3: coupled KATs are not reported'),
    ('harness/intel/tooling_intel.py', "    return sum(hits) if hits else None", "    return sum(hits)",
     'r27 TK3: an unmeasured coupling reads 0'),
    ('harness/intel/tooling_intel.py', "        hit = sorted(k for k, txt in kats.items() if rx.search(txt) or rel in txt)",
     "        hit = sorted(k for k, txt in kats.items() if name in txt)", 'r27 TK3: a substring near-miss covers a tool'),
    ('harness/kat/test_harness_tooling_r26.py', "        res = {m: T.scrub_control(root, fake_scrubber(d, m, plants)) for m in",
     "        res = {m: T.scrub_control() for m in", 'r27 TK3: HT12 calls the configured scrubber again'),
    ('harness/kat/test_harness_tooling_r26.py', "    return 4 if missed or coupled else 0", "    return 4 if missed else 0",
     'r27 TK3: the r26 runner passes with a coupled mutation'),
    ('harness/gen_deroarch.py', "    if any(a in ('-h', '--help') for a in argv):", "    if False:",
     'r27 TK4: gen_deroarch --help is an unknown command'),
    ('harness/gen_deroarch.py', "    if cmd not in COMMANDS or any(f != '--strict' for f in flags) or (flags and cmd != 'build'):",
     "    if cmd not in COMMANDS:", 'r27 TK4: an unknown flag runs the command'),
    ('harness/intel/area_intel.py', "    if c == 'record':", "    if False:", 'r27 TK5: a recorded finding is a high regression'),
    ('harness/intel/area_intel.py', "              if kind == RECORD_KIND else f'OPEN", "              if False else f'OPEN",
     'r27 TK5: a recorded finding suggests an OPEN row'),
    ('harness/intel/area_intel.py', "METRIC_CLASSES = ('node', 'network', 'record')", "METRIC_CLASSES = ('node', 'network')",
     'r27 TK5: the record class fails validation'),
    ('harness/areas.json', '     "id": "audit_fails",\n     "class": "record",\n', '     "id": "audit_fails",\n',
     'r27 TK5: audit_fails is a node metric again'),
    ('harness/kit/pidwait.py', "        if e.errno == errno.EPERM:\n            return True", "        if e.errno == errno.EPERM:\n            return False",
     'r27 TK6: another user\'s live process reads gone'),
    ('harness/kit/pidwait.py', "        done, _ = os.waitpid(pid, os.WNOHANG)", "        done = None",
     'r27 TK6: the waiter leaves its ended child a zombie'),
    ('harness/kit/pidwait.py', "    return 0 if ok else 1", "    return 0", 'r27 TK6: the CLI exits 0 on a timeout'),
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
            o, det = fn(P)
        except Exception as e:                                    # noqa: BLE001
            o, det = False, f'{type(e).__name__}: {e}'
        res.append((name, o, det))
    return res


def run_on(mutation=None):
    with tempfile.TemporaryDirectory(prefix='tk27_') as d:
        root = clone_tree(Path(d) / 'r')
        if mutation:
            rel, find, repl, _ = mutation
            p = root / rel
            p.write_text(p.read_text(encoding='utf-8').replace(find, repl, 1), encoding='utf-8')
            if p.suffix == '.py':
                compile(p.read_text(encoding='utf-8'), str(p), 'exec')
        return run_kats({'root': root})


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_r27', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    res = run_on()
    for name, o, det in res:
        print(f"{'ok  ' if o else 'FAIL'} {name} {det[:500]}")
    if not all(o for _, o, _ in res):
        return 3
    K = katmut()
    missed = coupled = 0
    for mut in MUTATIONS:
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
    print('\n' + K.summary('r27 tools-kats KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed or coupled else 0


if __name__ == '__main__':
    sys.exit(main())
