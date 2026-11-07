#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the R28 artifacts / memory-control / memory-mirror closures (dero-rft §0.6,
§0.9 rules 4-5, §7 B92/B122/B131/B140, §8 R28 carry N28-06/N28-11; R28 plan group artifacts-memory).

  AM8  r28 N28-06 tooling_intel 'box-proc' private shape and sync_mirror.generalise_procs: the box's process names are
       matched case-insensitively (the export check matched one spelling only and the lower-case daemon name reached the
       in-repo mirror); redact() writes them as '<system process>'; plan() refuses a file that still carries one; the
       mirror drift counts a mirror copy that carries one; near-miss words (launchd, a hyphenated or prefixed name) are
       not process names.
  AM9  B122 tooling_intel.scrub_pages (opt-in --scrub-pages): the publish copies of every artifacts page are made by the
       scrubber into a temporary directory and read back; a page whose final scan reports a residual, a page the
       report does not name, and a copy that keeps a '~/' home form are each reported and are target violations; a
       clean scrubber gives residual {} and home forms {}; no scrubber is 'pending'; the planted control carries a '~/'
       form (HOME_FORM_PLANTS). Forged scrubbers only: the configured one is measured by --scrub-pages (rft §13).
  AM10 B140 tooling_intel.dead_names / dead_symbols: a bare code-file name no tracked file ends with is dead; an
       out-of-repo tool name is not; 'a.go/b.go' names two files; inside one code span a --flag or func() after a code
       file that the file's source lacks is dead; a flag written after the NEXT code file belongs to that file; a
       flag outside a code span is not read.
  AM11 B140 tooling_intel.rft_lesson_ranges: a dero-rft.md line that names the lessons file with a '#a–#b' range ending
       below or above the file's highest '#N' is reported and is a target violation; an equal one is not.
  AM12 B92 coherence.round_skills: the skills that must carry the round's section are those whose '**Track:**' is not a
       paused track (a skill without one serves every round); every skill paused falls back to the miner skill, so a
       missing section is still reported. Real: the tree has a node skill that declares a track the registry does not
       pause, under the size budget, and the miner skill declares the miner track.
  AM13 r28 N28-11 harness/pipeline/fix_build_verify.py: the S7 ledger re-render is the only step that runs gen_ledger.py
       and it runs only when the current round's page already exists, so no step writes dero-r1-r<N>.html before Part D
       adds the round's section; the gen_ledger docstring states the same.
  AM14 B131 the agent-tool path shape: tooling_intel's record names the memory dir '<memory>' (pubscrub's placeholder,
       not the tool's project directory) and the sources of tooling_intel.py, sync_mirror.py, test_harness_tooling_r26.py
       and this file carry no 'b131-tool-path' shape (the split-literal placeholders were the residual of the R27
       publish).

Mutation independence (harness/kit/katmut.py): each mutation's reason starts with its defect id; OWNERS maps the
defect to the KAT that owns it; 'mutations proved P/N · mutations coupled C' is the summary tooling_intel reads.

  python3 -I harness/kat/test_artifacts_memory_r28.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not proved (MISSED / WRONG-KAT / INVALID) or was coupled.
"""
import importlib.util, json, re, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
FILES = {'TI': HARNESS / 'intel/tooling_intel.py', 'SM': ROOT / 'tools/memory-mirror/sync_mirror.py',
         'CO': HARNESS / 'intel/coherence.py', 'FBV': HARNESS / 'pipeline/fix_build_verify.py',
         'GL': ROOT / 'artifacts/src/gen_ledger.py'}
SOURCE_ONLY = ('FBV', 'GL')          # read as source (fix_build_verify / gen_ledger run at import)
# process names built from parts: this published file names none of them
PROC = {'daemon': 'fs' + 'eventsd', 'Daemon': 'FS' + 'Events', 'server': 'Window' + 'Server', 'monitor': 'Activity' + ' Monitor',
        'worker': 'md' + 'worker_shared', 'stores': 'mds' + '_stores'}
B131_RX = re.compile(r'\.' + 'claude/|' + 'claude/' + 'projects')     # pubscrub B131_CHECK 'b131-tool-path', from parts


def load(path, tag):
    spec = importlib.util.spec_from_file_location(f'am28_{tag}_{len(sys.modules)}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def load_all(over=None):
    over = over or {}
    return {k: (Path(over.get(k) or p).read_text() if k in SOURCE_ONLY else load(over.get(k) or p, k))
            for k, p in FILES.items()}


# ───────────────────────────── AM8 r28 N28-06 ─────────────────────────────
def am8(M, bad):
    TI, SM = M['TI'], M['SM']
    for name in PROC.values():
        for form in (name, name.lower(), name.upper()):
            if not TI.private_hits(f'it coincided with {form} at 140 GB'):
                bad.append(f'AM8 private_hits misses {form!r}')
    for near in ('launchd', 'fs-' + 'eventsd', 'my' + PROC['daemon'], PROC['daemon'] + '-like'):
        if any(k == 'box-proc' for k, _n in TI.private_hits(near)):
            bad.append(f'AM8 a near-miss word is a process name: {near!r}')
    out = SM.redact(f"mirroring coincided with {PROC['daemon']} at 140 GB; {PROC['Daemon']}; launchd stays".encode(), TI).decode()
    if PROC['daemon'] in out.lower() or PROC['Daemon'] in out or out.count(SM.PROC_WORD) != 2 or 'launchd stays' not in out:
        bad.append(f'AM8 redact {out!r}')
    files = {'a.md': b'x', 'b.md': b'y'}
    _keep, refused = SM.plan(files, {'a.md': b'clean', 'b.md': f"left {PROC['worker']}".encode()}, TI.private_hits, None)
    if refused != ['b.md']:
        bad.append(f'AM8 plan refused {refused}, want b.md (a process name left after redact)')
    with tempfile.TemporaryDirectory() as td:
        src, mir = Path(td) / 'mem', Path(td) / 'mirror'
        src.mkdir()
        mir.mkdir()
        body = f"a line naming {PROC['daemon']}\n".encode()
        (src / 'a.md').write_bytes(body)
        (mir / 'a.md').write_bytes(body)
        (mir / TI.MANIFEST).write_text(f'{TI.sha256(body)} {TI.sha256(body)} a.md\n')
        n, why = TI.mirror_drift(src, mir)
        if n != 1 or 'box-proc' not in ' '.join(why):
            bad.append(f'AM8 mirror_drift of a copy that names a process: {n} {why}')


# ───────────────────────────── AM9 B122 ─────────────────────────────
FAKE = r'''import json, sys
from pathlib import Path
mode = json.loads(Path(__file__).with_suffix('.json').read_text())
out = Path(sys.argv[1])
for i, src in enumerate(sys.argv[2:]):
    t = Path(src).read_text()
    if mode != 'home':
        t = t.replace('~/', '<home>/')
    (out / Path(src).name).write_text(t)
    found = {'box-model': 1} if mode == 'leaky' and i == 0 else {}
    if mode == 'silent' and i == 0:
        continue
    print(str(out / Path(src).name), len(t), 'rules', [], 'residual', found, 'ips', [])
'''


def fake(d, mode):
    p = Path(d) / f'fake_{mode}.py'
    p.write_text(FAKE)
    p.with_suffix('.json').write_text(json.dumps(mode))
    return p


def am9(M, bad):
    TI = M['TI']
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / 'root'
        (root / 'artifacts').mkdir(parents=True)
        (root / 'artifacts/a.html').write_text('<p>see ~/persist-dir/x and vscode://file/x</p>')
        (root / 'artifacts/b.html').write_text('<p>clean</p>')
        r = {m: TI.scrub_pages(root, fake(td, m)) for m in ('perfect', 'leaky', 'home', 'silent')}
        none = TI.scrub_pages(root, Path(td) / 'absent.py')
    p, lk, hm, sl = r['perfect'], r['leaky'], r['home'], r['silent']
    if p.get('scrub_page_residual') != {} or p.get('scrub_page_home_forms') != {} or p.get('scrub_pages_total') != 2 \
            or p.get('scrub_page_vscode') != {'a.html': 1} or TI.targets(p):
        bad.append(f'AM9 a clean scrubber: {p} targets {TI.targets(p)}')
    if lk.get('scrub_page_residual') != {'a.html': {'box-model': 1}} or not any('residual' in v for v in TI.targets(lk)):
        bad.append(f'AM9 a residual is not reported: {lk}')
    if hm.get('scrub_page_home_forms') != {'a.html': 1} or not any('home forms' in v for v in TI.targets(hm)):
        bad.append(f'AM9 a kept ~/ form is not reported: {hm}')
    if sl.get('scrub_page_residual') != {'a.html': {'unreported': 1}}:
        bad.append(f'AM9 a page the report does not name passes: {sl}')
    if none.get('scrub_page_residual') != TI.PENDING:
        bad.append(f'AM9 no scrubber is not pending: {none}')
    with tempfile.TemporaryDirectory() as td:          # the planted control carries a '~/' form (forged rule table)
        root = Path(td)
        (root / 'harness/loop').mkdir(parents=True)
        (root / 'rules.py').write_text("CHECKS = [('wallet', re.compile(rb'zzplant'))]\n")
        (root / TI.TOOL_PATHS).write_text(json.dumps({'sync_rules': str(root / 'rules.py')}))
        pl = TI.scrub_plants(root) or []
    if not any(x.startswith('~/') and not B131_RX.search(x) for x in pl):
        bad.append(f'AM9 the planted control has no ~/ home form: {pl}')


# ───────────────────────────── AM10 / AM11 B140 ─────────────────────────────
def am10(M, bad):
    TI = M['TI']
    with tempfile.TemporaryDirectory() as td:
        root, md = Path(td) / 'root', Path(td) / 'mem'
        (root / 'harness/intel').mkdir(parents=True)
        (root / 'blockchain').mkdir()
        (root / 'harness/intel/probe.py').write_text("ap.add_argument('--live')\ndef summary(x):\n    pass\n")
        (root / 'harness/intel/other.py').write_text("ap.add_argument('--other')\n")
        (root / 'blockchain/transaction_execute.go').write_text('func (chain *Blockchain) process_miner(x int) {}\n')
        (root / 'blockchain/a.go').write_text('')
        (root / 'blockchain/b.go').write_text('')
        md.mkdir()
        (md / 'm.md').write_text(
            'share = full/len (txn_exec.go:131); real blockchain/transaction_execute.go and `transaction_execute.go:133`;\n'
            'the pair a.go/b.go; out of repo: zz_export.py and backup_scratch.sh; gone: nothere.sh\n'
            'run `python3 -I harness/intel/probe.py --live --gone` and `probe.py --nope`; `other.py --other`\n'
            'call `probe.py:summary()` and `probe.py:missing()`; `transaction_execute.go:process_miner()`\n'
            'two tools: `harness/intel/probe.py --live; python3 harness/intel/other.py --other`\n'
            'one span, two commands: `harness/intel/probe.py --live harness/intel/other.py --other`\n'
            'outside a span: harness/intel/probe.py --absent-flag\n')
        files = sorted(p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file())
        names = TI.dead_names(md, root, files, outside={'zz_export.py', 'backup_scratch.sh'})
        syms = TI.dead_symbols(md, root, files)
    if names != ['m.md: nothere.sh', 'm.md: txn_exec.go']:
        bad.append(f'AM10 dead_names {names}')
    want = ['m.md:3: harness/intel/probe.py --gone', 'm.md:3: harness/intel/probe.py --nope', 'm.md:4: harness/intel/probe.py missing()']
    if syms != want:
        bad.append(f'AM10 dead_symbols {syms}, want {want}')
    v = TI.targets({'memory_dead_names': names, 'memory_dead_symbols': syms})
    if not (any('code files' in x for x in v) and any('flags/functions' in x for x in v)):
        bad.append(f'AM10 dead names/symbols are no target violation: {v}')
    if TI.code_tokens('the pair a.go/b.go and harness/x.py') != ['a.go', 'b.go', 'harness/x.py']:
        bad.append(f"AM10 code_tokens {TI.code_tokens('the pair a.go/b.go and harness/x.py')}")


def am11(M, bad):
    TI = M['TI']
    with tempfile.TemporaryDirectory() as td:
        root, md = Path(td) / 'root', Path(td) / 'mem'
        (root / 'artifacts').mkdir(parents=True)
        md.mkdir()
        (md / TI.LESSONS_FILE).write_text('#1 (R1): a\n#79 (R25): b\n**#80** (R27): c\n')
        rft = root / 'artifacts/dero-rft.md'
        rft.write_text('## 10. Lessons (memory `session-reasoning-patterns` #1–#80; #1–#69, #79 and #80 distilled here)\n'
                       'a line with #1–#99 that names no lessons file\n')
        same = TI.rft_lesson_ranges(root, md)
        rft.write_text('## 10. Lessons (memory `session-reasoning-patterns` #1–#77; #72–77 pinned)\n')
        under = TI.rft_lesson_ranges(root, md)
        gone = TI.rft_lesson_ranges(root, Path(td) / 'none')
    if same != []:
        bad.append(f'AM11 an equal range reported {same}')
    if under != [(1, 77, 80)]:
        bad.append(f'AM11 an under-stated range gave {under}')
    if gone != TI.PENDING:
        bad.append(f'AM11 no lessons file is not pending: {gone}')
    if not any('lesson range' in x for x in TI.targets({'rft_lesson_ranges': under})):
        bad.append('AM11 an rft lesson range mismatch is no target violation')


# ───────────────────────────── AM12 B92 ─────────────────────────────
class _C:
    def __init__(self, root, tracks):
        self.root, self.rcur = Path(root), {'id': 'r9', 'tracks': tracks}

    def text(self, rel):
        try:
            return (self.root / rel).read_text()
        except OSError:
            return None


def am12(M, bad, real):
    CO, TI = M['CO'], M['TI']
    with tempfile.TemporaryDirectory() as td:
        r = Path(td)
        for name, text in (('dero-miner-tuning', '# m\n\n**Track:** miner\n## Round 8 (x)\n'),
                           ('dero-node-operations', '# n\n\n**Track:** node\n## Round 9 (y)\n'),
                           ('plain', '# p\n## Round 9 (z)\n')):
            (r / '.skills' / name).mkdir(parents=True)
            (r / '.skills' / name / 'SKILL.md').write_text(text)
        a = CO.round_skills(_C(r, {'miner': 'paused', 'node': 'active'}))
        b = CO.round_skills(_C(r, {'miner': 'active', 'node': 'active'}))
        c = CO.round_skills(_C(r, {'miner': 'paused', 'node': 'paused'}))
        shutil.rmtree(r / '.skills/plain')
        d = CO.round_skills(_C(r, {'miner': 'paused', 'node': 'paused'}))
    want_a = ['.skills/dero-node-operations/SKILL.md', '.skills/plain/SKILL.md']
    if a != want_a:
        bad.append(f'AM12 paused miner: round_skills {a}, want {want_a}')
    if len(b) != 3:
        bad.append(f'AM12 no paused track: round_skills {b}, want all 3')
    if c != ['.skills/plain/SKILL.md'] or d != [CO.MINER_SKILL]:
        bad.append(f'AM12 every track paused: {c} / {d}, want the plain skill / the miner skill fallback')
    if real:
        reg = json.loads((HARNESS / 'round.json').read_text())
        paused = set(TI.paused_tracks(reg, reg.get('current')))
        sk = {p.parent.name: p.read_text() for p in sorted((ROOT / '.skills').glob('*/SKILL.md'))}
        node = sk.get('dero-node-operations')
        if node is None or TI.skill_track(node) in paused or len(node.splitlines()) > TI.SKILL_MAX_LINES:
            bad.append(f'AM12 real: the node skill is missing, paused or over budget (tracks paused {sorted(paused)})')
        if TI.skill_track(sk.get('dero-miner-tuning', '')) != 'miner':
            bad.append('AM12 real: the miner skill does not declare the miner track')


# ───────────────────────────── AM13 r28 N28-11 ─────────────────────────────
GUARD_RX = re.compile(r"if _lm and \(ROOT / f'artifacts/dero-r1-r\{_lm\.group\(1\)\}\.html'\)\.exists\(\):\n"
                      r"\s+steps \+= \[\[sys\.executable, 'artifacts/src/gen_ledger\.py', '--last', _lm\.group\(1\)")


def am13(M, bad):
    src, gl = M['FBV'], M['GL']
    calls = len(re.findall(r"'artifacts/src/gen_ledger\.py'", src))
    if calls != 1 or not GUARD_RX.search(src):
        bad.append(f'AM13 fix_build_verify: gen_ledger steps {calls}, existence guard {bool(GUARD_RX.search(src))}')
    doc = gl.split('"""')[1]
    if 'no step writes dero-r1-r' not in doc or 'only when the current round' not in doc:
        bad.append('AM13 the gen_ledger docstring no longer states that S7 writes the page only once it exists')


# ───────────────────────────── AM14 B131 ─────────────────────────────
def am14(M, bad, real):
    TI = M['TI']
    if B131_RX.search(TI.MEMORY_SHOWN) or TI.MEMORY_SHOWN != '<memory>':
        bad.append(f'AM14 the record names the memory dir {TI.MEMORY_SHOWN!r}')
    with tempfile.TemporaryDirectory() as td:
        r = Path(td)
        (r / 'harness/runtime').mkdir(parents=True)
        TI.write(r, {'round': 'r9'})
        rec = next((r / 'harness/runtime').glob('tooling_2*.json')).read_text()
    if B131_RX.search(rec):
        bad.append('AM14 a written record carries the agent-tool path shape')
    srcs = [Path(TI.__file__), Path(M['SM'].__file__)]
    if real:
        srcs += [HARNESS / 'kat/test_harness_tooling_r26.py', Path(__file__)]
    for p in srcs:
        n = len(B131_RX.findall(p.read_text()))
        if n:
            bad.append(f'AM14 {p.name} carries the b131-tool-path shape {n}x')


KATS = ['AM8', 'AM9', 'AM10', 'AM11', 'AM12', 'AM13', 'AM14']


def run_kats(M, real=True):
    """{kat id: [failures]}"""
    out = {}
    for k, f in (('AM8', lambda b: am8(M, b)), ('AM9', lambda b: am9(M, b)), ('AM10', lambda b: am10(M, b)),
                 ('AM11', lambda b: am11(M, b)), ('AM12', lambda b: am12(M, b, real)), ('AM13', lambda b: am13(M, b)),
                 ('AM14', lambda b: am14(M, b, real))):
        b = []
        try:
            f(b)
        except Exception as e:                                         # noqa: BLE001 — a crash is a failure
            b.append(f'{k} raised {type(e).__name__}: {str(e)[:120]}')
        out[k] = b
    return out


OWNERS = {'r28 N28-06': ['AM8'], 'B122': ['AM9'], 'B140': ['AM10', 'AM11'], 'B92': ['AM12'], 'r28 N28-11': ['AM13'],
          'B131': ['AM14']}

MUTATIONS = [   # (file key, find, replace, why: the reason starts with the defect id)
    ('TI', "re.compile('(?i)(?<![\\\\w-])(?:'", "re.compile('(?<![\\\\w-])(?:'", 'r28 N28-06: the process shape is case-sensitive again'),
    ('TI', "'fs' + 'events' + 'd?'", "'fs' + 'events'", 'r28 N28-06: the lower-case daemon name is missed'),
    ('SM', "    t = generalise_procs(t, T)\n", "", 'r28 N28-06: redact keeps the process names'),
    ('SM', "    return rx.sub(PROC_WORD, t) if rx is not None else t", "    return t", 'r28 N28-06: generalise_procs is a no-op'),
    ('TI', "    left = {n: f for n, f in sorted(res.items()) if f}", "    left = {}", 'B122: a page residual is dropped'),
    ('TI', "    left.update({n: {'unreported': 1} for n in missing})", "    pass", 'B122: a page the report does not name passes'),
    ('TI', "            if HOME_FORM_RX.search(t):", "            if False:", 'B122: a kept ~/ home form is not counted'),
    ('TI', "    if isinstance(k.get('scrub_page_home_forms'), dict) and k['scrub_page_home_forms']:", "    if False:",
     'B122: home forms are no target violation'),
    ('TI', "        plants += HOME_FORM_PLANTS ", "        plants += [] ", 'B122: the planted control loses its ~/ form'),
    ('TI', "            if tok.split('/')[-1] in outside or resolve_name(tok, files):", "            if True:",
     'B140: dead code-file names never reported'),
    ('TI', "        if any(x.endswith(CODE_EXT) for x in parts[:-1]):", "        if False:", 'B140: a.go/b.go is read as a directory'),
    ('TI', "                    end = ms[j + 1].start() if j + 1 < len(ms) else len(span)", "                    end = len(span)",
     'B140: a flag after the next tool is booked to the first'),
    ('TI', "                        if f not in src:", "                        if False:", 'B140: dead flags never reported'),
    ('TI', "        if rng and max(int(b) for _a, b in rng) != top:", "        if rng and max(int(b) for _a, b in rng) > top:",
     'B140: an under-stated rft lesson range passes'),
    ('TI', "    if isinstance(k.get('rft_lesson_ranges'), list) and k['rft_lesson_ranges']:", "    if False:",
     'B140: an rft lesson range mismatch is no target violation'),
    ('CO', "        if not (m and m.group(1) in paused):", "        if True:", 'B92: a paused-track skill must carry the round'),
    ('CO', "    return out or [MINER_SKILL]", "    return out", 'B92: every skill paused reports nothing'),
    ('FBV', "    if _lm and (ROOT / f'artifacts/dero-r1-r{_lm.group(1)}.html').exists():", "    if _lm:",
     'r28 N28-11: S7 writes the round page before it exists'),
    ('TI', "MEMORY_SHOWN = '<memory>'", "MEMORY_SHOWN = '~/.' + 'claude/' + 'projects/<project>/memory'",
     'B131: the record names the tool project directory again'),
    ('TI', "'~/.' + 'claude/' + 'projects/x/memory/'", "'~/." + "claude/" + "projects/x/memory/'",
     'B131: the plant literal carries the tool-path shape again'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_am28', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main(argv):
    if argv and argv[0] in ('-h', '--help'):
        print(__doc__)
        return 0
    res = run_kats(load_all())
    for k in KATS:
        print(f"{'ok  ' if not res[k] else 'FAIL'} {k}" + ''.join(f'\n      {x}' for x in res[k]))
    if any(res.values()):
        return 3
    K = katmut()
    missed = coupled = 0
    with tempfile.TemporaryDirectory() as td:
        for i, (key, find, repl, why) in enumerate(MUTATIONS):
            text = FILES[key].read_text()
            if text.count(find) != 1:
                print(f'  ??        {why}: find text occurs {text.count(find)} times')
                missed += 1
                continue
            mp = Path(td) / f'mut{i}' / FILES[key].name
            mp.parent.mkdir()
            mp.write_text(text.replace(find, repl, 1))
            try:
                compile(mp.read_text(), str(mp), 'exec')
                r = run_kats(load_all({key: mp}), real=False)
            except Exception as e:                                     # noqa: BLE001 — a mutant that does not load
                print(f'  INVALID   {why}: {type(e).__name__}: {str(e)[:80]}')
                missed += 1
                continue
            failed = [k for k, b in r.items() if b]
            verdict, extra = K.classify(failed, OWNERS.get(K.defect_of(why), []))
            print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else '')
                  + (f'  coupled {extra}' if verdict == 'proved' and extra else ''))
            missed += verdict != 'proved'
            coupled += verdict == 'proved' and bool(extra)
    print('\n' + K.summary('r28 artifacts-memory KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed or coupled else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
