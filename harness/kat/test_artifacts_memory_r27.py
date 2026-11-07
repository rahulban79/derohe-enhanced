#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the R27 artifacts / memory-control / memory-mirror fixes (dero-rft §0.6,
§0.9 rule 5, §7 B88/B131; R27 plan group artifacts-memory).

  AM1 tools/memory-mirror/sync_mirror.redact: the out-of-repo tool names (read from a TOOL_PATHS mapping, never
      written here), the tool-signature trailer and link and the OS version are rewritten after pubscrub; the
      scrubber's own published name and near-miss words are kept.
  AM2 sync_mirror.plan / parse_residual / unexplained: the residual is measured on the FINAL bytes; a file whose final
      residual names a check outside RESIDUAL_ALLOW, or that the final pass did not report, is refused; an allowed
      check is kept; a leaked address in the report is residual. Real (with the configured scrubber): a planted stamp
      built at run time (tool names, trailer, link, OS version) has raw pubscrub rc 1 and mirrors with final rc 0,
      final residual 0, exit 0; a planted unexplained shape is refused (exit 1).
  AM3 harness/intel/tooling_intel.index_ranges: an index line whose stated '#a–#b' range ends below the linked file's
      highest '#N' entry is reported and is a target violation; a quoted sub-range does not lower the bound.
  AM4 tooling_intel.dead_refs: a repo path with an extension that a memory file names and the tree lacks is reported;
      prose ('block/s', 'harness/Nope'), placeholders and paths outside the tree's top-level dirs are not.
  AM5 harness/gen_index.memory_rows: memory rows link the in-repo mirror copy (../memory-mirror/<file>), a file the
      mirror does not hold is text, no row carries vscode:// or the home path; unhome(); the generator source has no
      literal home path.
  AM6 harness/kit/soundpage.measured_text / splice_measured and harness/soundness.evaluate: the page states its round's
      measured status (pending until the registry says measured, then the 'MEASURED live <date>' date); G22 fails
      while the page lacks the current line; real: the current round's page carries it.
  AM7 artifacts/src/gen_ledger.py: the --last default is the largest choice and the docstring names exactly one
      default, the same round.

  python3 -I harness/kat/test_artifacts_memory_r27.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import importlib.util, io, json, os, re, shutil, subprocess, sys, tempfile, contextlib
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
sys.path.insert(0, str(HARNESS / 'kit'))
sys.path.insert(0, str(HARNESS))
FILES = {'SM': ROOT / 'tools/memory-mirror/sync_mirror.py', 'TI': HARNESS / 'intel/tooling_intel.py',
         'GI': HARNESS / 'gen_index.py', 'SP': HARNESS / 'kit/soundpage.py', 'SN': HARNESS / 'soundness.py',
         'GL': ROOT / 'artifacts/src/gen_ledger.py'}
HOME_LIT = '/' + 'Users' + '/'            # built from parts: this file carries no home path


def load(path, tag):
    spec = importlib.util.spec_from_file_location(f'am27_{tag}_{len(sys.modules)}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def load_all(over=None):
    mods = {}
    for k, p in FILES.items():
        if k == 'GL':
            mods[k] = (over or {}).get(k) or p.read_text()       # gen_ledger runs at import: checked as source
        else:
            mods[k] = load((over or {}).get(k) or p, k)
    return mods


# ───────────────────────────── AM1 / AM2 ─────────────────────────────
CFG = {'_doc': 'x', 'pubscrub': '~/zq-export/zq_tools/pubscrub.py', 'sync_rules': '~/zq-export/zq_tools/zq_rules.py'}


def am1(SM, TI, bad):
    terms = SM.tool_terms(CFG)
    if set(terms) != {'zq-export', 'zq_tools', 'zq_rules'}:
        bad.append(f'AM1 tool_terms {terms}')
    trailer = 'Co-Authored-By: ' + 'Claude Opus 9 <x>'
    link = 'claude' + '.ai/artifact/0123abcd'
    osv = 'mac' + 'OS ' + '.'.join(['14', '2', '1']) + ' (' + '23C' + '71)'      # parts: the export rules rewrite the literal
    text = (f'see ~/zq-export/zq_tools/zq_rules.py rule R7; run pubscrub.py first\n'
            f'no "{trailer}" trailer\nnever link {link} here\nthe host runs {osv}, Go 1.20.3\n'
            'a zq-exporter and zq_toolsmith are other words\n')
    out = SM.redact(text.encode(), TI, terms).decode()
    for raw in ('zq-export/', 'zq_tools/', 'zq_rules', trailer.split(' <')[0], link, '14.2.1', '23C71'):
        if raw in out:
            bad.append(f'AM1 redact left {raw!r}')
    for keep in ('pubscrub.py', 'zq-exporter', 'zq_toolsmith', 'Go 1.20.3', 'macOS <version>'):
        if keep not in out:
            bad.append(f'AM1 redact lost {keep!r}')


def am2(SM, TI, bad, real):
    rep = ('/t/a.md 10 rules [] residual {} ips []\n'
           "/t/b.md 10 rules ['R2'] residual {'ext-impl': 1} ips []\n"
           "/t/c.md 10 rules [] residual {'tool-link': 1} ips []\n"
           "/t/d.md 10 rules [] residual {} ips ['" + '.'.join(['198', '18', '0', '9']) + "']\n")
    res = SM.parse_residual(rep)
    if res.get('a.md') != {} or res.get('b.md') != {'ext-impl': 1} or res.get('d.md') != {'ip': 1}:
        bad.append(f'AM2 parse_residual {res}')
    if SM.final_residual(rep) != res or SM.final_residual('a scrubber without the report format\n') is not None:
        bad.append('AM2 final_residual: an unreported final pass must be None (pending), a report its parse')
    if SM.unexplained({'ext-impl': 2, 'tool-link': 1}) != {'tool-link': 1}:
        bad.append('AM2 unexplained does not separate an allowed check')
    files = {n: b'x' for n in ('a.md', 'b.md', 'c.md', 'd.md', 'e.md')}
    keep, refused = SM.plan(files, dict(files), lambda t: [], res)
    if refused != ['c.md', 'd.md', 'e.md']:
        bad.append(f'AM2 plan refused {refused}, want c.md (tool-link), d.md (address), e.md (not reported)')
    keep, refused = SM.plan(files, dict(files), lambda t: [], None)
    if refused:
        bad.append('AM2 plan without a final measurement refused a file')
    if real:
        am2_real(bad)


def am2_real(bad):
    """the configured scrubber, a planted stamp built at run time, a throw-away repo: final residual 0, exit 0; then a
    planted unexplained shape is refused with exit 1. 'pending' (not failed) on a machine without the scrubber."""
    TI = load(FILES['TI'], 'TIreal')
    tool = TI.tool_path('pubscrub', ROOT)
    if tool is None or not tool.is_file():
        print('pending AM2 real: the configured scrubber is not on this machine')
        return
    cfg = json.loads((ROOT / 'harness/loop/TOOL_PATHS.json').read_text())
    names = [x for v in cfg.values() if isinstance(v, str) for x in Path(v).parts if x not in ('~', '/')]
    with tempfile.TemporaryDirectory(prefix='am27-') as td:
        repo, stamp = Path(td) / 'repo', Path(td) / 'stamp'
        (repo / 'harness/intel').mkdir(parents=True)
        (repo / 'harness/loop').mkdir(parents=True)
        shutil.copy(FILES['TI'], repo / 'harness/intel/tooling_intel.py')
        shutil.copy(ROOT / 'harness/loop/TOOL_PATHS.json', repo / 'harness/loop/TOOL_PATHS.json')
        stamp.mkdir()
        (stamp / 'plant.md').write_text(
            'the export lives at ~/' + '/'.join(names[:2]) + ' and its rules are ' + names[-1] + '\n'
            'no "Co-Authored-By: ' + 'Claude" trailer, no claude' + '.ai/artifact links\n'
            'the host runs mac' + 'OS ' + '26' + '.5.1 now\n'
            'an external implementation lib' + 'sais is a public name\n')
        (stamp / 'clean.md').write_text('the node listens on 127.0.0.1:10102\n')
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = load(FILES['SM'], 'SMreal').main(['--stamp', str(stamp), '--repo', str(repo), '--pubscrub', str(tool)])
        # the raw pass (pubscrub's own output) still has residual; the final bytes have none and nothing is refused
        o = out.getvalue()
        if rc != 0 or not (repo / 'memory-mirror/plant.md').is_file() or 'rc raw 1 · final 0' not in o or 'final residual 0' not in o:
            bad.append(f'AM2 real: planted stamp rc {rc}, output {out.getvalue().strip()[:300]}')
        (stamp / 'plant2.md').write_text('a desktop app chat' + 'gpt is named here\n')
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = load(FILES['SM'], 'SMreal2').main(['--stamp', str(stamp), '--repo', str(repo), '--pubscrub', str(tool)])
        if rc != 1 or (repo / 'memory-mirror/plant2.md').exists():
            bad.append(f'AM2 real: an unexplained residual was mirrored (rc {rc})')


# ───────────────────────────── AM3 / AM4 ─────────────────────────────
def am3(TI, bad):
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / 'lessons.md').write_text('---\nname: l\n---\n#1 (R1): measure first\n#76 (R25): x\n**#77** (R25): y\n')
        (d / 'MEMORY.md').write_text('- [Lessons](lessons.md) — numbered lessons #1–#77 (#70–75: a sub-range)\n')
        if TI.index_ranges(d) != []:
            bad.append(f'AM3 an index equal to its file reported {TI.index_ranges(d)}')
        (d / 'lessons.md').write_text((d / 'lessons.md').read_text() + '#78 (R25 live): z\n- #79 (R25 live): w\n')
        got = TI.index_ranges(d)
        if got != [('lessons.md', 77, 79)]:
            bad.append(f'AM3 an under-stated index gave {got}')
        v = TI.targets({'memory_index_ranges': got})
        if not any('memory index ranges' in x for x in v):
            bad.append('AM3 an index range mismatch is not a target violation')


def am4(TI, bad):
    with tempfile.TemporaryDirectory() as td:
        root, md = Path(td) / 'root', Path(td) / 'mem'
        (root / 'harness/runtime').mkdir(parents=True)
        (root / 'artifacts').mkdir()
        (root / 'harness/runtime/r24_live_hour_20261102.txt').write_text('x')
        (root / 'bin').mkdir()
        (root / 'bin/derod.round5-backup').write_text('x')   # r28 B172: an existing '-suffix' name
        md.mkdir()
        (md / 'a.md').write_text('read harness/runtime/r24_live_hour_20261102.txt and harness/runtime/r24_live_first/'
                                 'hour_20261102.txt; 18 s/block, artifacts/GitHub, harness/Nope, harness/runtime/x_<ts>.json, '
                                 'elsewhere/y.txt, `harness/runtime/gone.json`, kept as `bin/derod.round5-backup`.\n')
        got = TI.dead_refs(md, root)
        want = ['a.md: harness/runtime/gone.json', 'a.md: harness/runtime/r24_live_first/hour_20261102.txt']
        if got != want:
            bad.append(f'AM4 dead_refs {got}, want {want}')


# ───────────────────────────── AM5 ─────────────────────────────
def am5(GI, bad, real):
    home = '/home/zq'
    mems = [{'file': 'a.md', 'name': 'A', 'type': 'project', 'desc': f'scratch at {home}/persist, dirs /tmp/x/-home-zq-proj-1',
             'line': 3}, {'file': 'b.md', 'name': 'B', 'type': 'feedback', 'desc': 'b', 'line': 2}]
    rows = GI.memory_rows(mems, {'a.md': True, 'b.md': False}, home=home)
    if 'href="../memory-mirror/a.md"' not in rows:
        bad.append('AM5 a mirrored memory does not link its mirror copy')
    if 'memory-mirror/b.md' in rows or rows.count('href=') != 1:
        bad.append('AM5 a memory the mirror does not hold is linked')
    if 'vscode://' in rows or home in rows or '-home-zq-' in rows:
        bad.append('AM5 a memory row carries vscode:// or the home path')
    if GI.unhome(f'{home}/x', home) != '~/x':
        bad.append('AM5 unhome')
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / 'MANIFEST.sha256').write_text(f"{'a' * 64} {'b' * 64} a.md\n{'c' * 64} - b.md\n")
        if GI.mirror_files(td) != {'a.md': True, 'b.md': False}:
            bad.append(f'AM5 mirror_files {GI.mirror_files(td)}')
    if real and HOME_LIT in FILES['GI'].read_text():
        bad.append('AM5 harness/gen_index.py carries a literal home path')


# ───────────────────────────── AM6 ─────────────────────────────
def am6(SP, SN, bad, real):
    m = SP.measured_text({'id': 'r26', 'status': 'measured', 'pipeline_full': 'pipeline_X',
                          'evidence': 'run4 PASS ... MEASURED live 2026-11-05 on the restarted r26 derod'})
    if 'live on 2026-11-05' not in m or not m.startswith('Measured: R26'):
        bad.append(f'AM6 measured round: {m!r}')
    p = SP.measured_text({'id': 'r27', 'status': 'in-progress', 'pipeline_full': 'pending'})
    if not p.startswith('Measured: pending'):
        bad.append(f'AM6 an in-progress round reads {p!r}')
    q = SP.measured_text({'id': 'r28', 'status': 'measured', 'evidence': 'no date here'})
    if 'pending' not in q:
        bad.append('AM6 a measured round without a date is not pending')
    page = '<html><header><h1>t</h1>\n</header><p>body</p></html>'
    blk = f'{SP.MS_BEGIN}<p class="measured">x</p>{SP.MS_END}'
    s1 = SP.splice_measured(page, blk)
    s2 = SP.splice_measured(s1, blk.replace('x', 'y'))
    if s1.index(blk) > s1.index('</header>') or s2.count(SP.MS_BEGIN) != 1 or '>y<' not in s2:
        bad.append('AM6 splice_measured')
    reg = {'claims': [{'id': 'c1', 'kind': 'record', 'match': 'body', 'exact': True, 'source': 's'},
                      {'id': 'c2', 'kind': 'record', 'match': 't', 'exact': True, 'source': 's'}], '_want_measured': blk}
    r = SN.evaluate(page, reg, None, live=False)
    if not any('measured line' in w for w in r['why']) or r['measured']:
        bad.append('AM6 G22 does not fail a page without the measured line')
    r = SN.evaluate(s1.replace('>x<', '>body2<'), dict(reg, _want_measured=blk.replace('x', 'body2')), None, live=False)
    if any('measured line' in w for w in r['why']):
        bad.append('AM6 G22 fails a page that carries the current measured line')
    with tempfile.TemporaryDirectory() as td:            # write_measured leaves write_known's order unchanged (FE6)
        t = Path(td)
        (t / 'harness/loop').mkdir(parents=True)
        (t / 'artifacts').mkdir()
        (t / 'harness/round.json').write_text(json.dumps({'current': 'r27', 'rounds': [{'id': 'r27', 'status': 'in-progress'}]}))
        (t / 'artifacts/dero-soundness-r27.html').write_text(page)
        (t / SP.CLAIMS).write_text(json.dumps({'claims': [{'id': 'c1'}, {'id': 'known-01'}, {'id': 'known-02'}]}))
        ch, _r = SP.write_measured(t)
        reg2 = json.loads((t / SP.CLAIMS).read_text())
        kn = [c for c in reg2['claims'] if c['id'].startswith('known-')]
        if not ch or SP.measured_block(t) not in (t / 'artifacts/dero-soundness-r27.html').read_text() \
                or SP.merge_claims(reg2, kn) != reg2 or SP.write_measured(t, check=True)[0]:
            bad.append(f"AM6 write_measured on a planted tree: order {[c['id'] for c in reg2['claims']]}")
    if real:
        cur = (ROOT / SP.rel(ROOT)).read_text()
        if SP.measured_block(ROOT) not in cur:
            bad.append(f'AM6 {SP.rel(ROOT)} lacks the current measured line')


# ───────────────────────────── AM7 ─────────────────────────────
def am7(src, bad):
    m = re.search(r'LAST_CHOICES = \(([\d, ]+)\)', src)
    a = re.search(r"add_argument\('--last'[^\n]*\n?[^\n]*default=([^,]+),", src)
    if not m or not a:
        bad.append('AM7 the --last argument is not where AM7 reads it')
        return
    ch = [int(x) for x in m.group(1).split(',') if x.strip()]
    d = a.group(1).strip()
    dv = max(ch) if d == 'max(LAST_CHOICES)' else int(d) if d.isdigit() else None
    if dv != max(ch):
        bad.append(f'AM7 --last default {d} is not the largest choice {max(ch)}')
    doc = src.split('"""')[1]
    named = re.findall(r'--last (\d+) \(the default', doc)
    if named != [str(max(ch))]:
        bad.append(f'AM7 the docstring names the default {named}, want [{max(ch)}]')


def kats(M, real=True):
    bad = []
    am1(M['SM'], M['TI'], bad)
    am2(M['SM'], M['TI'], bad, real)
    am3(M['TI'], bad)
    am4(M['TI'], bad)
    am5(M['GI'], bad, real)
    am6(M['SP'], M['SN'], bad, real)
    am7(M['GL'], bad)
    return bad


MUTATIONS = [
    ('AM1', 'SM', "    t = scrub_tools(t, terms)\n", "", 'redact skips the r27 tool scrub'),
    ('AM1', 'SM', "    for rx, rep in SIG_RULES:\n        t = rx.sub(rep, t)\n", "", 'the trailer/link/OS rules are not applied'),
    ('AM1', 'SM', "        if k != 'pubscrub':\n            out.add(Path(parts[-1]).stem)", "        out.add(Path(parts[-1]).stem)",
     'the scrubber\'s own published name becomes a tool term'),
    ('AM2', 'SM', "or (residual is not None and (n not in residual or unexplained(residual[n])))", "or False",
     'the final residual is ignored'),
    ('AM2', 'SM', "    return {k: v for k, v in (found or {}).items() if k not in RESIDUAL_ALLOW}", "    return {}",
     'every residual check is allowed'),
    ('AM2', 'SM', "            found['ip'] = len(ips)", "            pass", 'a leaked address is not residual'),
    ('AM2', 'SM', "    return parse_residual(stdout) or None", "    return parse_residual(stdout)",
     'a scrubber without a report refuses every file'),
    ('AM3', 'TI', "        if nums and max(nums) != stated:", "        if nums and max(nums) < stated:", 'an under-stated range passes'),
    ('AM3', 'TI', "        stated = max(int(b) for _a, b in rng)", "        stated = int(rng[-1][1])", 'a quoted sub-range sets the bound'),
    ('AM3', 'TI', "    if isinstance(k.get('memory_index_ranges'), list) and k['memory_index_ranges']:", "    if False:",
     'a range mismatch is no target violation'),
    ('AM4', 'TI', "            if m.split('/')[0] in tops and not (root / m).exists():", "            if False:", 'dead refs never reported'),
    ('AM4', 'TI', r"[\w-][\w.-]*\.[A-Za-z]\w{0,5})(?![\w/<*{-])", r"[\w-][\w.-]*(?:\.[A-Za-z]\w{0,5})?)(?![\w/<*{-])",
     'prose without an extension counts as a path'),
    ('AM4', 'TI', r"\w{0,5})(?![\w/<*{-])')", r"\w{0,5})(?![\w/<*{])')", 'B172: a -suffix name is read as its prefix'),
    ('AM5', 'GI', 'href="../memory-mirror/{E(m["file"])}"', 'href="vscode://file{E(str(home or Path.home()))}/{E(m["file"])}"',
     'memory rows link the home path again'),
    ('AM5', 'GI', "if mirrored.get(m['file'])", "if True", 'a file the mirror does not hold is linked'),
    ('AM5', 'GI', "    s = str(s).replace(h, '~')", "    s = str(s)", 'descriptions keep the home path'),
    ('AM6', 'SP', "        when = f'live on {m.group(1)}' if m else", "        when = 'live' if m else", 'the measured date is dropped'),
    ('AM6', 'SP', "    if st == 'measured':", "    if st != 'pending':", 'an in-progress round reads as measured'),
    ('AM6', 'SP', "    return page[:i] + '  ' + block + '\\n' + page[i:]", "    return page + block",
     'the measured line lands outside the header'),
    ('AM6', 'SP', "+ [measured_entry(root)] + kn", "+ kn + [measured_entry(root)]",
     'the measured entry lands after known-* (write_known then reorders: FE6 stale)'),
    ('AM6', 'SN', "    if registry.get('_want_measured') and registry['_want_measured'] not in page_text:", "    if False:",
     'G22 ignores a missing measured line'),
    ('AM7', 'GL', "default=max(LAST_CHOICES)", "default=25", 'the --last default falls behind the choices'),
    ('AM7', 'GL', "--last 25 (R25 after implementation", "--last 25 (the default, R25 after implementation",
     'the docstring names two defaults'),
]


def main():
    M = load_all()
    bad = kats(M)
    for b in bad:
        print('FAIL', b)
    ok = not bad
    print(f"{'ok  ' if ok else 'FAIL'} AM1-AM7: {len(bad)} failure(s)")
    missed = 0
    with tempfile.TemporaryDirectory() as td:
        for i, (cid, key, old, new, what) in enumerate(MUTATIONS):
            src = FILES[key].read_text()
            if old not in src:
                print(f'MISSED {cid}: mutation target not found ({what})')
                missed += 1
                continue
            mut = src.replace(old, new, 1)
            try:
                if key == 'GL':
                    over = {'GL': mut}
                else:
                    mp = Path(td) / f'mut{i}_{FILES[key].name}'
                    mp.write_text(mut)
                    over = {key: mp}
                caught = any(b.startswith(cid) for b in kats(load_all(over), real=False))
                verdict = 'CAUGHT' if caught else 'MISSED'
            except Exception as e:                                     # noqa: BLE001 — a crash proves nothing
                caught, verdict = False, f'INVALID ({type(e).__name__}: {str(e)[:80]})'
            missed += not caught
            print(f'{verdict} {cid}: {what}')
    print(f'\nr27 artifacts-memory KATs: {"7/7" if ok else "FAIL"} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if not ok else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
