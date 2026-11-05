#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for harness/intel/tooling_intel.py and the memory mirror
(tools/memory-mirror/sync_mirror.py, backup_memory.sh) (r25, dero-rft §0.9, B87-B94).

  TI1 memory index hygiene on a forged memory dir: bytes, lines, longest line, lines over 300 chars, a dangling link,
      an unindexed topic file, a duplicate link.
  TI2 mirror drift (B88; tooling class 'partial-page privacy scan': every mirror file is scanned, not only new ones): a
      clean synced mirror = 0; a source changed after the sync, a hand-edited mirror file, a file missing from the
      mirror, a new memory not in the manifest, a refused ('-') file and a private identifier planted in an old mirror
      file each count once; no manifest = every file. An address that ends a sentence is still an address.
  TI3 stale claims (B81): a registered refuted claim still in the memory counts; the same line with a dated correction
      does not.
  TI4 pipeline record (tooling class 'count-regex misread'): KAT mutation counts are read only from 'mutations proved
      X/Y'; 'ANOMALY 7848898 blocks behind us' and 'mutations: 3 INVALID' are never counts; kats, gates (+PAUSED),
      harness mutations, the project wall time and per-step runtimes come from the record.
  TI5 evolution ORDER (B90): a non-planned round missing from ORDER is a gap; a planned one is only the early warning;
      the live tree's ORDER is read from mine_evolution.py and lists every non-planned registry round.
  TI6 duplicate gate ids (lesson #68): two titles under one G<n> is a duplicate; two branches of one gate are not; the
      live run_gates.py has none.
  TI7 tooling defect classes (§0.9 rule 1): every class of the live table names a KAT that exists and carries its
      marker; a forged class with a missing marker is reported.
  TI8 scrub control arithmetic: a plant left in the scrubbed text is a false negative; a changed clean line is a false
      positive. Generator double runs: equal bytes, a build-time/fingerprint-only difference, and a content difference
      are told apart (all but the first are mismatches).
  TI9 skill freshness: the last '## Round <N>' heading against the registry's current round.
  TI10 the memory mirror end to end on forged dirs (bash + a stand-in scrubber): backup_memory.sh writes a stamp with a
      manifest and LATEST, adds no stamp when nothing changed; sync_mirror.py mirrors a clean file, redacts an e-mail
      shape and an address ending a sentence, and refuses a file whose home path survives; the result has drift 0.
  TI11 --determinism runs the generators in an isolated copy: a stand-in generator that rewrites a tracked file leaves
      the measured tree byte-identical, and its page is still hashed (r25 merge).
  TI12 checkpoint age (§0.10): seconds since the resume checkpoint's stamp; a missing or unparsable state is pending.

  python3 -I harness/kat/test_tooling_intel_r25.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import hashlib, importlib.util, json, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
SRC = HARNESS / 'intel' / 'tooling_intel.py'
MIRROR_PY = ROOT / 'tools' / 'memory-mirror' / 'sync_mirror.py'
BACKUP_SH = ROOT / 'tools' / 'memory-mirror' / 'backup_memory.sh'
HOME_PLANT = '/' + 'Users' + '/someone/x'          # a generic home-path shape (no real user)


def load(path, name='ti25'):
    spec = importlib.util.spec_from_file_location(f'{name}_{abs(hash(str(path)))}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def sha(b):
    return hashlib.sha256(b).hexdigest()


def memdir(d):
    m = Path(d) / 'mem'
    m.mkdir()
    (m / 'a.md').write_text('topic a\n')
    (m / 'b.md').write_text('topic b, the table covers all 3 replay walls\n')
    (m / 'c.md').write_text('topic c\n')
    idx = ['# index', '- [A](a.md) short', '- [B](b.md) ' + 'x' * 320, '- [A again](a.md) dup', '- [Gone](gone.md) dangling']
    (m / 'MEMORY.md').write_text('\n'.join(idx) + '\n')
    return m


def ti1(T):
    with tempfile.TemporaryDirectory() as d:
        k = T.memory_index_kpis(memdir(d))
    ok = (k['memory_files'] == 4 and k['memory_index_lines'] == 5 and k['memory_index_over_300'] == 1
          and k['memory_index_longest'] == len('- [B](b.md) ') + 320 and k['memory_index_dangling'] == ['gone.md']
          and k['memory_unindexed'] == ['c.md'] and k['memory_index_duplicates'] == ['a.md'])
    return ok, f"{ {x: k[x] for x in k} }"


def synced(T, m, mir):
    mir.mkdir(exist_ok=True)
    lines = []
    for p in sorted(m.glob('*.md')):
        (mir / p.name).write_bytes(p.read_bytes())
        lines.append(f'{sha(p.read_bytes())} {sha(p.read_bytes())} {p.name}')
    (mir / T.MANIFEST).write_text('\n'.join(lines) + '\n')


def ti2(T):
    out = {}
    with tempfile.TemporaryDirectory() as d:
        m, mir = memdir(d), Path(d) / 'mirror'
        out['none'] = T.mirror_drift(m, mir)[0] == 4
        synced(T, m, mir)
        out['clean'] = T.mirror_drift(m, mir)[0] == 0
        (m / 'a.md').write_text('topic a, edited after the sync\n')
        out['src_changed'] = T.mirror_drift(m, mir)[0] == 1
        synced(T, m, mir)
        (mir / 'c.md').write_text('hand edit\n')
        out['hand_edit'] = T.mirror_drift(m, mir)[0] == 1
        synced(T, m, mir)
        (mir / 'b.md').unlink()
        out['missing'] = T.mirror_drift(m, mir)[0] == 1
        synced(T, m, mir)
        (m / 'new.md').write_text('a new memory\n')
        out['new'] = T.mirror_drift(m, mir)[0] == 1
        (m / 'new.md').unlink()
        synced(T, m, mir)
        man = (mir / T.MANIFEST).read_text().replace(f"{sha(b'topic c' + bytes([10]))} c.md", '- c.md')
        (mir / T.MANIFEST).write_text(man)
        (mir / 'c.md').unlink()
        out['refused'] = T.mirror_drift(m, mir)[0] == 1
        for plant in (HOME_PLANT, 'gateway 192.168.7.1.', 'peer 82.1.2.3', 'mail someone@example.org'):
            synced(T, m, mir)
            (m / 'a.md').write_text(f'old file now carries {plant}\n')
            synced(T, m, mir)
            out[f'private {plant[:12]}'] = T.mirror_drift(m, mir)[0] == 1
        synced(T, m, mir)
        (m / 'a.md').write_text('loopback 127.0.0.1 and docs 203.0.113.10\n')
        synced(T, m, mir)
        out['reserved_ok'] = T.mirror_drift(m, mir)[0] == 0
    return all(out.values()), f'{out}'


def ti3(T):
    with tempfile.TemporaryDirectory() as d:
        m = memdir(d)
        cl = [{'id': 'B81', 'quote': 'covers all 3 replay walls'}]
        a = T.stale_claims(m, cl)
        (m / 'b.md').write_text('topic b, the table covers all 3 replay walls (REVISED 2026-11-03: wall 1 is not in it)\n')
        b = T.stale_claims(m, cl)
    return a == ['B81: b.md:1'] and b == [], f'before {a} after {b}'


def record():
    ev = [{'t': '2026-11-03T09:25:00-08:00', 'stage': 'run', 'status': 'BEGIN'},
          {'t': '2026-11-03T09:25:06-08:00', 'stage': 'project', 'status': 'START'},
          {'t': '2026-11-03T09:25:10-08:00', 'stage': 'project', 'status': 'INFO', 'step': 'harness/intel/peer_intel.py --live',
           'last': ['ANOMALY 7848898 blocks behind us', 'mutations: 3 INVALID']},
          {'t': '2026-11-03T09:25:40-08:00', 'stage': 'project', 'status': 'INFO', 'step': 'harness/kat/test_a.py',
           'last': ['A KATs: 3/3 ok · mutations proved 7/8']},
          {'t': '2026-11-03T09:25:45-08:00', 'stage': 'project', 'status': 'INFO', 'step': 'harness/kat/test_b.py',
           'last': ['B KATs: 1/1 ok · mutations proved 2/2', 'ANOMALY 7848898 blocks behind us']},
          {'t': '2026-11-03T09:32:02-08:00', 'stage': 'project', 'status': 'FAIL', 'kats': '35/35', 'mutations': '34/34',
           'gates': '23/27 (+3 PAUSED, miner)', 'failing': ['G15']}]
    return ev


def ti4(T):
    k = T.project_summary(record(), 'r.jsonl')
    p, t = T.kat_mutations(['ANOMALY 7848898 blocks behind us', 'mutations: 3 INVALID', 'x · mutations proved 5/6'])
    ok = (k['kat_mutations_proved'], k['kat_mutations_total']) == (9, 10) and (p, t) == (5, 6) and k['kats_passed'] == 35 \
        and (k['gates_pass'], k['gates_total'], k['gates_paused']) == (23, 27, 3) and k['harness_mutations_caught'] == 34 \
        and k['project_wall_s'] == 416 and k['slowest_steps'][0] == 'harness/kat/test_a.py 30s'
    return ok, f'{k}'


def ti5(T):
    reg = {'rounds': [{'id': 'r24', 'status': 'measured'}, {'id': 'r25', 'status': 'in-progress'}, {'id': 'r26', 'status': 'planned'}]}
    g1 = T.order_gaps(reg, ['R24'])
    g2 = T.order_gaps(reg, ['R24', 'R25'])
    live_order = T.evolution_order(ROOT)
    live_reg = json.loads((HARNESS / 'round.json').read_text())
    lg, _ = T.order_gaps(live_reg, live_order or [])
    ok = g1 == (['R25'], ['R26']) and g2 == ([], ['R26']) and bool(live_order) and 'R1-3' in live_order and 'R24' in live_order \
        and lg == []
    return ok, f'forged {g1} {g2} live gaps {lg} order[-3:] {(live_order or [])[-3:]}'


def ti6(T):
    src = ("    res.append(('G23 every area is scored', ok, d))\n    res.append(('G23 every area is scored', False, 'x'))\n"
           "    res.append(('G23 the disclosure track is re-tested', ok, d))\n    res.append(('G24 other', ok, d))\n")
    got = T.duplicate_gate_ids(src)
    live = T.duplicate_gate_ids((HARNESS / 'run_gates.py').read_text())
    return got == {'G23': ['every area is scored', 'the disclosure track is re-tested']} and live == {}, f'forged {got} live {live}'


def ti7(T):
    live = T.classes_without_kat(ROOT)
    forged = T.classes_without_kat(ROOT, [('x', 'harness/kat/test_tooling_intel_r25.py', 'NO-SUCH-' + 'MARKER-' + 'r25'),
                                          ('y', 'harness/kat/no_such_file.py', 'TI1')])
    return live == [] and len(forged) == 2, f'live {live} forged {forged}'


def ti8(T):
    fn, fp = T.scrub_counts(['SECRET-A', 'SECRET-B'], 'x SECRET-B y', 'a\nb\nc\n', 'a\nB\nc\n')
    fn0, fp0 = T.scrub_counts(['SECRET-A'], 'clean', 'a\n', 'a\n')
    dk = [T.diff_kind(b'x', b'x'), T.diff_kind(b'built 2026-11-03T10:51:17-08:00 fp bbde3e0b7087b981',
                                                 b'built 2026-11-03T10:51:19-08:00 fp 276f7119e8cff70a'),
          T.diff_kind(b'rows 3', b'rows 4')]
    return (fn, fp, fn0, fp0) == (1, 1, 0, 0) and dk == ['byte-exact', 'DIFFERS: build time/fingerprint only', 'DIFFERS'], \
        f'{(fn, fp, fn0, fp0)} {dk}'


def ti9(T):
    with tempfile.TemporaryDirectory() as d:
        s = Path(d) / '.skills' / 'x'
        s.mkdir(parents=True)
        (s / 'SKILL.md').write_text('# x\n## Round 23c (2026)\n## Round 24 (2026)\n')
        a = T.skill_kpis(d, 'r24')
        b = T.skill_kpis(d, 'r25')
    return a['skill_fresh'] == 1 and b['skill_fresh'] == 0 and b['skill_last_round'] == {'x': 'r24'}, f'{a} {b}'


STAND_IN_SCRUB = '''import sys, re
out = sys.argv[1]
for src in sys.argv[2:]:
    t = open(src).read().replace('WALLETX', '<wallet>')
    open(out + '/' + src.split('/')[-1], 'w').write(t)
'''


def ti10(T, mirror_mod=None):
    if shutil.which('rsync') is None or shutil.which('shasum') is None:
        return False, 'rsync/shasum missing'
    out = {}
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        src, dest, repo = d / 'mem', d / 'priv', d / 'repo'
        src.mkdir()
        (src / 'MEMORY.md').write_text('- [a](a.md) x\n')
        (src / 'a.md').write_text('wallet WALLETX in a sentence; peer 82.1.2.3.\n')
        (src / 'b.md').write_text('mail me at someone@example.org\n')
        (src / 'd.md').write_text('the miner host is this Apple **M1 Ultra Mac' ' Studio** (20 cores); a LAN Mac' 'Book Pro runs a node\n')
        (src / 'c.md').write_text(f'a home path {HOME_PLANT} the stand-in scrubber does not remove\n')
        (repo / 'harness' / 'intel').mkdir(parents=True)
        shutil.copy2(SRC, repo / 'harness' / 'intel' / 'tooling_intel.py')
        scrub = d / 'scrub.py'
        scrub.write_text(STAND_IN_SCRUB)
        tools = d / 'tools'
        tools.mkdir()
        shutil.copy2(BACKUP_SH, tools / 'backup_memory.sh')
        shutil.copy2(mirror_mod or MIRROR_PY, tools / 'sync_mirror.py')
        r1 = subprocess.run(['bash', str(tools / 'backup_memory.sh'), '--src', str(src), '--dest', str(dest), '--repo', str(repo),
                             '--pubscrub', str(scrub)], capture_output=True, text=True, timeout=120)
        stamps = sorted(p.name for p in dest.iterdir() if p.is_dir()) if dest.exists() else []
        out['stamp'] = len(stamps) == 1 and (dest / 'LATEST').read_text().strip() == stamps[0] \
            and len((dest / stamps[0] / 'MANIFEST.sha256').read_text().splitlines()) == 5
        r2 = subprocess.run(['bash', str(tools / 'backup_memory.sh'), '--src', str(src), '--dest', str(dest)],
                            capture_output=True, text=True, timeout=120)
        out['no_churn'] = len([p for p in dest.iterdir() if p.is_dir()]) == 1 and 'unchanged' in r2.stdout
        mir = repo / 'memory-mirror'
        a = (mir / 'a.md').read_text() if (mir / 'a.md').exists() else ''
        b = (mir / 'b.md').read_text() if (mir / 'b.md').exists() else ''
        out['scrubbed_a'] = '<wallet>' in a and '82.1.2.3' not in a and '<ip>' in a
        out['email_b'] = '<e-mail>' in b and '@example.org' not in b
        dd = (mir / 'd.md').read_text() if (mir / 'd.md').exists() else ''
        # r26: machine-model names are generalised in the mirror, the facts (20 cores) stay
        out['models_d'] = bool(dd) and not any(x in dd for x in ('M1', 'Ultra', 'Mac' ' Studio', 'MacBook')) and '20 cores' in dd
        out['refused_c'] = not (mir / 'c.md').exists() and r1.returncode == 1 and ' - c.md' in (mir / 'MANIFEST.sha256').read_text()
        n, why = T.mirror_drift(src, mir)
        out['drift_only_refused'] = n == 1 and why[0].startswith('c.md: refused')
    return all(out.values()), f'{out} rc {r1.returncode} {r1.stderr[-200:]}'


GEN_STANDIN = """import pathlib
p = pathlib.Path('page.html'); n = pathlib.Path('tracked.txt')
n.write_text(n.read_text() + 'touched\\n')          # a generator that also rewrites a tracked file
p.write_text('<html>stable</html>\\n')
"""


def ti11(T):
    """--determinism runs the generators in an isolated copy: the tree it measures is byte-identical afterwards (r25
    merge; harnesstool verify OPEN: it ran in place and left tracked files modified), and the result is still read."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d) / 'root'
        root.mkdir()
        (root / 'gen.py').write_text(GEN_STANDIN)
        (root / 'tracked.txt').write_text('v1\n')
        before = {p.name: sha(p.read_bytes()) for p in root.iterdir()}
        res = T.determinism(root, [(['gen.py'], 'page.html')])
        after = {p.name: sha(p.read_bytes()) for p in root.iterdir()}
    return before == after and res == {'page.html': 'byte-exact'}, f'{res} unchanged={before == after} {sorted(after)}'


def ti12(T):
    """checkpoint age (area tooling metric 'checkpoint age', §0.10): seconds since the state stamp; missing or
    unparsable state = pending, never 0."""
    import datetime
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / 'r25_state.json').write_text(json.dumps({'stamp': '2026-11-03T12:00:00-0800'}))
        (Path(d) / 'r26_state.json').write_text('{"stamp": "soon"}')
        at = datetime.datetime(2026, 11, 3, 20, 10, 0, tzinfo=datetime.timezone.utc)
        a, b, c = T.checkpoint_age(d, 'r25', at), T.checkpoint_age(d, 'r26', at), T.checkpoint_age(d, 'r27', at)
    return (a, b, c) == (600, 'pending', 'pending'), f'{(a, b, c)}'


KATS = [('TI1', ti1), ('TI2', ti2), ('TI3', ti3), ('TI4', ti4), ('TI5', ti5), ('TI6', ti6), ('TI7', ti7), ('TI8', ti8),
        ('TI9', ti9), ('TI10', ti10), ('TI11', ti11), ('TI12', ti12)]

MUTATIONS = [   # (file, find, replace, why)
    (MIRROR_PY, '    t = generalise_models(t)\n', '', 'r26: machine-model names reach the memory mirror'),
    (SRC, "            'memory_index_over_300': sum(1 for l in lines if len(l) > INDEX_MAX_LINE),",
     "            'memory_index_over_300': sum(1 for l in lines if len(l) > INDEX_MAX_LINE * 2),", 'long index lines not counted'),
    (SRC, "            'memory_index_dangling': sorted({x for x in links if x not in files}),",
     "            'memory_index_dangling': [],", 'a dangling index link not reported'),
    (SRC, "        elif src[n] != man[n][0]:\n            why = 'source changed since the sync'\n", "",
     'a source changed after the sync is not drift'),
    (SRC, "        elif sha256(mir[n].read_bytes()) != man[n][1]:", "        elif False:", 'a hand-edited mirror file is not drift'),
    (SRC, "        if why is None and n in mir:\n            ph = private_hits(", "        if False:\n            ph = private_hits(",
     'a private identifier in an OLD mirror file is not scanned (partial scan)'),
    (SRC, "(?!\\d|\\.\\d)')),", "(?![\\d.])')),", 'an address that ends a sentence escapes the IP check'),
    (SRC, "        elif n in man and man[n][1] == '-':\n            why = 'refused by the scrub (private identifier left): not mirrored'\n", "",
     'a refused file is not drift'),
    (SRC, "                    if q in l and not CORRECTION_RX.search(l):", "                    if q in l:",
     'a dated correction does not clear a stale claim'),
    (SRC, "KAT_MUT_RX = re.compile(r'mutations proved (\\d+)\\s*/\\s*(\\d+)')", "KAT_MUT_RX = re.compile(r'(\\d+)\\s*/?\\s*(\\d+)')",
     'any number pair read as a mutation count (count-regex misread)'),
    (SRC, "        (nxt if r.get('status') == 'planned' else gaps).append(key)", "        nxt.append(key)",
     'a non-planned round missing from ORDER is only a warning'),
    (SRC, "    return {g: sorted(t) for g, t in seen.items() if len(t) > 1}", "    return {}",
     'two gates under one id not reported'),
    (SRC, "            if marker not in (Path(root) / f).read_text(errors='replace'):", "            if False:",
     'a defect class whose KAT lacks its marker passes'),
    (SRC, "    fn = sum(1 for p in plants if p and p in scrubbed)", "    fn = 0", 'a planted secret left by the scrub is not counted'),
    (SRC, "    return 'DIFFERS: build time/fingerprint only' if STAMP_RX.sub('#', ta) == STAMP_RX.sub('#', tb) else 'DIFFERS'",
     "    return 'DIFFERS: build time/fingerprint only'", 'a content difference is reported as timestamp-only'),
    (SRC, "        fresh &= bool(last) and last.lower() == str(current).lower()", "        fresh &= bool(last)",
     'a skill that stopped at an older round counts as fresh'),
    (SRC, "        work = isolated_copy(root, Path(tmp) / 'tree')", "        work = Path(root)",
     '--determinism runs the generators in place (tracked files modified)'),
    (SRC, "                    raw.append((work / page).read_bytes())", "                    raw.append((Path(tmp) / page).read_bytes())",
     '--determinism hashes a page the isolated run did not write'),
    (SRC, "    return max(0, int((at - t).total_seconds()))", "    return 0", 'the checkpoint age is always 0 (a stopped loop looks fresh)'),
    (SRC, "    except (OSError, ValueError, TypeError):\n        return PENDING\n    at = at", "    except (OSError, ValueError, TypeError):\n        return 0\n    at = at",
     'a missing checkpoint is booked as age 0'),
    (MIRROR_PY, "    b = EMAIL_RX.sub(b'<e-mail>', b)\n", "", 'an e-mail shape reaches the in-repo mirror'),
    (MIRROR_PY, "        if b is None or hits(b.decode('utf-8', errors='replace')):", "        if b is None:",
     'a file with a surviving home path is mirrored'),
]


def run_kats(T, mirror_mod=None):
    res = []
    for name, fn in KATS:
        try:
            o, det = fn(T, mirror_mod) if name == 'TI10' else fn(T)
        except Exception as e:                                    # noqa: BLE001
            o, det = False, f'{type(e).__name__}: {e}'
        res.append((name, o, det))
    return res


def main():
    T = load(SRC)
    res = run_kats(T)
    for name, o, det in res:
        print(f"{'ok  ' if o else 'FAIL'} {name} {det[:300]}")
    if not all(o for _, o, _ in res):
        return 3
    missed = 0
    for path, find, repl, why in MUTATIONS:
        text = path.read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??      {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / path.name
            p.write_text(text.replace(find, repl, 1), encoding='utf-8')
            try:
                m = load(p) if path == SRC else T
                if path != SRC:
                    load(p, 'mirror')
            except Exception as e:                                # noqa: BLE001
                print(f'  INVALID {why}: mutant does not load ({type(e).__name__})')
                missed += 1
                continue
            survived = all(o for _, o, _ in run_kats(m, p if path == MIRROR_PY else None))
        print(f"  {'MISSED ' if survived else 'proved '} {why}")
        missed += survived
    print(f'\nr25 tooling-intel KATs: {len(KATS)}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
