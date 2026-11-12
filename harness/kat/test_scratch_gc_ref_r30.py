#!/usr/bin/env python3
"""KAT + mutation proof for scratch_gc's repeatable --reference (r30 B148-stash, user decision 2026-11-08 option a:
keep ONE permanent verified copy of every foreign object in ~/derohe-persist/gc_archive/objects.git, then let
scratch_gc delete the hollow trees that held them). No live file is read or written: every repo is a temp dir.

  RH12 r30 B148-stash an object is present when ANY --reference holds it. A hollow tree whose only foreign object (a
            loose blob; in a second tree a pack) lives in the archive alone is DELETE-HOLLOW with
            --reference REF --reference ARCHIVE, and the SAME tree is KEEP 'H3 ... the reference lacks' with REF alone
            (judged after the archive run: a proof cached for the pair must not leak to REF alone), and with no
            --reference at all (env DERO_LIVE_REPO=REF, the CLI default); a tree with an object in neither stays KEEP
            with both. --apply with both removes exactly the two proved trees.
  RH13 r30 B148-stash the other uses of the reference list: C3 a clone tree whose HEAD commit only the archive holds
            passes C3 with both references and is 'C3 HEAD not in the reference repo' with REF alone; C1 a --root
            that holds the SECOND reference (the archive) is refused (exit 2), and a tree inside it is
            'C1 forbidden location'.

  python3 -I harness/kat/test_scratch_gc_ref_r30.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not proved (MISSED / WRONG-KAT / INVALID) or was coupled.
"""
import contextlib, hashlib, importlib.util, io, json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
PATHS = {'gc': 'harness/pipeline/scratch_gc.py'}
ENV = {**{k: v for k, v in os.environ.items() if not k.startswith('GIT_')}, 'GIT_CONFIG_GLOBAL': os.devnull,
       'GIT_CONFIG_NOSYSTEM': '1', 'GIT_AUTHOR_NAME': 'kat', 'GIT_AUTHOR_EMAIL': 'kat@invalid',
       'GIT_COMMITTER_NAME': 'kat', 'GIT_COMMITTER_EMAIL': 'kat@invalid', 'LC_ALL': 'C'}


def P(over, key):
    return Path(over.get(key) or ROOT / PATHS[key])


def load(over, key):
    path = P(over, key)
    spec = importlib.util.spec_from_file_location(f'gcref_{key}_{abs(hash(str(path)))}_{len(sys.modules)}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def sh(*cmd, cwd=None, input_=None):
    r = subprocess.run(list(cmd), cwd=cwd, env=ENV, capture_output=True, timeout=120,
                       input=input_.encode() if input_ else None)
    if r.returncode:
        raise RuntimeError(f'{cmd[:3]} rc {r.returncode}: {r.stderr.decode(errors="replace")[:200]}')
    return r.stdout


def run_main(G, argv, env=None):
    old = {k: os.environ.get(k) for k in (env or {})}
    os.environ.update(env or {})
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            rc = G.main(argv)
    finally:
        for k, v in old.items():
            os.environ.pop(k) if v is None else os.environ.__setitem__(k, v)
    return rc, buf.getvalue()


def fixture(td):
    """ref (a commit), archive (bare: a loose blob + a packed blob + a commit ref/archive lacks), foreign repo fr"""
    ref = td / 'ref'
    ref.mkdir()
    sh('git', 'init', '-q', '-b', 'main', cwd=ref)
    (ref / 'a.txt').write_text('one\n')
    (ref / '.gitignore').write_text('*.patch\n*.md5\n')
    sh('git', 'add', '-A', cwd=ref)
    sh('git', 'commit', '-q', '-m', 'base', cwd=ref)
    sh('git', 'repack', '-q', '-a', '-d', cwd=ref)
    (ref / 'b.txt').write_text('two\n')                 # a second commit stays LOOSE: a hollow copy then holds loose
    sh('git', 'add', '-A', cwd=ref)                      # objects only REF has next to one only the archive has
    sh('git', 'commit', '-q', '-m', 'second', cwd=ref)
    fr = td / 'foreign'
    fr.mkdir()
    sh('git', 'init', '-q', cwd=fr)
    oid = {}
    for n, text in (('loose', 'only in the archive (loose)\n'), ('pack', 'only in the archive (pack)\n'),
                    ('none', 'in no reference\n')):
        (fr / f'{n}.txt').write_text(text)
        oid[n] = sh('git', 'hash-object', '-w', f'{n}.txt', cwd=fr).decode().strip()
    pk = td / 'fpack'
    pk.mkdir()
    name = sh('git', 'pack-objects', '-q', str(pk / 'pack'), cwd=fr, input_=oid['pack'] + '\n').decode().strip()
    arch = td / 'keep' / 'objects.git'
    sh('git', 'init', '-q', '--bare', str(arch))
    for n in ('loose', 'pack'):
        sh('git', 'hash-object', '-w', '--stdin', cwd=arch, input_=(fr / f'{n}.txt').read_text())
    return ref, fr, oid, pk, name, arch


def hollow(ref, dst, extra):
    shutil.copytree(ref / '.git' / 'objects', dst / '.git' / 'objects')
    (dst / '.git' / 'refs' / 'heads').mkdir(parents=True)
    (dst / '.git' / 'refs' / 'stash').write_text(sh('git', 'rev-parse', 'HEAD', cwd=ref).decode())
    for rel, data in extra.items():
        (dst / rel).parent.mkdir(parents=True, exist_ok=True)
        (dst / rel).write_bytes(data)
    return dst


def kat_rh12(over):
    G = load(over, 'gc')
    bad = []
    with tempfile.TemporaryDirectory(prefix='gcref-') as td:
        td = Path(td).resolve()
        ref, fr, oid, pk, name, arch = fixture(td)
        lo = lambda n: {f'.git/objects/{oid[n][:2]}/{oid[n][2:]}': (fr / '.git' / 'objects' / oid[n][:2] / oid[n][2:]).read_bytes()}
        root = td / 'scr'
        tl = hollow(ref, root / 'r29' / 'arch_loose', lo('loose'))
        tp = hollow(ref, root / 'r29' / 'arch_pack', {f'.git/objects/pack/pack-{name}.{x}': (pk / f'pack-{name}.{x}').read_bytes()
                                                       for x in ('pack', 'idx')})
        tn = hollow(ref, root / 'r29' / 'nowhere', lo('none'))
        both, alone = [str(ref), str(arch)], [str(ref)]
        for t, want in ((tl, 'DELETE-HOLLOW'), (tp, 'DELETE-HOLLOW'), (tn, 'KEEP')):
            r = G.judge(t, root, both, [], 0, '')
            if r['verdict'] != want:
                bad.append(f'{t.name} with the archive: want {want}, got {r["verdict"]} {r.get("why", "")[:90]}')
        for t in (tl, tp):                     # after the archive run: no proof may leak to REF alone
            for refs in (alone, str(ref)):
                r = G.judge(t, root, refs, [], 0, '')
                if r['verdict'] != 'KEEP' or 'H3' not in r.get('why', ''):
                    bad.append(f'{t.name} without the archive ({type(refs).__name__}): want KEEP H3, got {r["verdict"]} {r.get("why", "")[:90]}')
        rc, out = run_main(G, ['--root', str(root), '--min-age', '0', '--json'], env={'DERO_LIVE_REPO': str(ref)})
        rows = {r['tree']: r for r in json.loads(out)['rows']} if rc == 0 else {}
        for t in ('r29/arch_loose', 'r29/arch_pack'):
            if rows.get(t, {}).get('verdict') != 'KEEP':
                bad.append(f'CLI with no --reference (DERO_LIVE_REPO=ref): {t} is {rows.get(t, {}).get("verdict")}, want KEEP')
        rc, out = run_main(G, ['--root', str(root), '--reference', str(ref), '--min-age', '0', '--apply', '--json'])
        if not (tl.exists() and tp.exists()):
            bad.append('--apply with REF alone removed a tree whose objects only the archive holds')
        rc, out = run_main(G, ['--root', str(root), '--reference', str(ref), '--reference', str(arch), '--min-age', '0',
                               '--apply', '--json'])
        gone = sorted(t.name for t in (tl, tp, tn) if not t.exists())
        if gone != ['arch_loose', 'arch_pack']:
            bad.append(f'--apply with both removed {gone}, want arch_loose + arch_pack')
        rec = root / 'r29' / 'arch_loose.gc.json'
        if not rec.is_file() or json.loads(rec.read_text()).get('reference') != both:
            bad.append('the arch_loose.gc.json record does not name both references')
        if sh('git', 'cat-file', '-t', oid['loose'], cwd=arch).decode().strip() != 'blob':
            bad.append('the archive lost its object')
    return not bad, '; '.join(bad) or ('archive-only loose + packed object: DELETE-HOLLOW with --reference REF --reference '
                                       'ARCHIVE, KEEP H3 with REF alone (after the archive run) and with no flag; '
                                       'object in neither KEEP; --apply removes exactly the two')


def kat_rh13(over):
    G = load(over, 'gc')
    bad = []
    with tempfile.TemporaryDirectory(prefix='gcref13-') as td:
        td = Path(td).resolve()
        ref, fr, oid, pk, name, arch = fixture(td)
        # a clone whose HEAD commit only the archive holds
        root = td / 'scr'
        t = root / 'dim' / 'tree'
        t.parent.mkdir(parents=True)
        sh('git', 'clone', '-q', '--shared', str(ref), str(t))
        (t / 'c.txt').write_text('new\n')
        sh('git', 'add', 'c.txt', cwd=t)
        sh('git', 'commit', '-q', '-m', 'local', cwd=t)
        head = sh('git', 'rev-parse', 'HEAD', cwd=t).decode().strip()
        sh('git', 'fetch', '-q', str(t), f'{head}:refs/archive/commit/{head}', cwd=arch)
        b = G.judge(t, root, [str(ref), str(arch)], [], 0, '')
        a = G.judge(t, root, [str(ref)], [], 0, '')
        if b.get('why', '').startswith('C3 HEAD not in'):
            bad.append(f'C3 with the archive: HEAD only the archive holds is "{b["why"]}"')
        if not a.get('why', '').startswith('C3 HEAD not in'):
            bad.append(f'C3 with REF alone: want "C3 HEAD not in the reference repo", got {a["verdict"]} {a.get("why")}')
        # C1: a root that holds the archive (the second reference) is refused; a tree inside it is forbidden
        rc, _ = run_main(G, ['--root', str(td / 'keep'), '--reference', str(ref), '--reference', str(arch), '--min-age', '0'])
        rc2, _ = run_main(G, ['--root', str(td), '--reference', str(ref), '--reference', str(arch), '--min-age', '0'])
        if rc != 2 or rc2 != 2:
            bad.append(f'a --root at / above the archive reference: rc {rc}/{rc2}, want 2/2')
        inner = arch / 'scratch' / 'h'
        (inner / '.git' / 'objects').mkdir(parents=True)
        r = G.judge(inner, arch, [str(ref), str(arch)], [], 0, '')
        if r.get('why') != 'C1 forbidden location':
            bad.append(f'a tree inside the archive: {r["verdict"]} {r.get("why")}, want C1 forbidden location')
    return not bad, '; '.join(bad) or ('C3 base present via the archive only with the archive given; a root at / above '
                                       'the archive refused (2/2); a tree in it C1 forbidden')


KATS = [('RH12', kat_rh12), ('RH13', kat_rh13)]
OWNERS = {'r30 RH12': ['RH12'], 'r30 RH13': ['RH13']}

MUTATIONS = [   # (key, find, replace, why)
    ('gc', ", tuple(map(str, refs_of(reference))))   # a proof is per reference set", ")   # a proof is per reference set",
     'r30 RH12: an archive object counted present WITHOUT the archive flag (pack proof cached without its references)'),
    ('gc', "    for r in refs_of(reference):\n        oids = one_ref_missing(r, oids)", "    for r in refs_of(reference)[:1]:\n        oids = one_ref_missing(r, oids)",
     'r30 RH12: only the first --reference is consulted for objects'),
    ('gc', "        oids = one_ref_missing(r, oids)\n        if not oids:\n            return oids\n    return oids",
     "        if one_ref_missing(r, oids) == []:\n            return []\n    return oids",
     'r30 RH12: an object counts present only when ONE reference holds ALL of them (per-object union dropped)'),
    ('gc', "    a.reference = a.reference or [os.environ.get('DERO_LIVE_REPO') or str(ROOT)]",
     "    a.reference = a.reference[-1:] or [os.environ.get('DERO_LIVE_REPO') or str(ROOT)]",
     'r30 RH12: the CLI keeps only the last --reference (the action=append list collapsed)'),
    ('gc', "    if not any(git(r, 'cat-file', '-e', f'{base}^{{commit}}')[0] == 0 for r in refs_of(reference)):",
     "    if not any(git(r, 'cat-file', '-e', f'{base}^{{commit}}')[0] == 0 for r in refs_of(reference)[:1]):",
     'r30 RH13: C3 base commit looked up in the first reference only'),
    ('gc', "*(Path(r) for r in refs_of(reference)), ROOT]", "*(Path(r) for r in refs_of(reference)[:1]), ROOT]",
     'r30 RH13: only the first reference is a forbidden location'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_gcref', HARNESS / 'kit' / 'katmut.py')
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
    K = katmut()
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    fails = sum(1 for _, ok, _ in res if not ok)
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        src = P({}, key)
        text = src.read_text()
        if text.count(find) != 1:
            print(f'  INVALID  {why} — find text occurs {text.count(find)} time(s)')
            missed += 1
            continue
        d = Path(tempfile.mkdtemp(prefix='gcref-mut-'))
        mp = d / 'harness' / src.parent.name / src.name
        mp.parent.mkdir(parents=True)
        mp.write_text(text.replace(find, repl, 1))
        try:
            failed = [n for n, ok, _ in run_kats({key: mp}) if not ok]
        finally:
            shutil.rmtree(d, ignore_errors=True)
        verdict, extra = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:9s} {why}  {failed}')
        missed += verdict != 'proved'
        coupled += bool(extra) and verdict == 'proved'
    print('\n' + K.summary('r30 scratch_gc --reference KATs', len(KATS) - fails if fails else len(KATS), len(MUTATIONS),
                           missed, coupled))
    return 3 if fails else (4 if missed or coupled else 0)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
