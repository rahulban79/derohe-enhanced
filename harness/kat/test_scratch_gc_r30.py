#!/usr/bin/env python3
"""KAT + mutation proof for the R30 scratch_gc fix (rft §5 resource-hygiene rule). No live file is read or written:
every repo, tree and patch is a temp dir.

  GC1  r30  scratch_gc pins git to the tree's own .git (--git-dir/--work-tree). The R30 dry run kept 267 scratch trees
            as 'C3 no HEAD commit': 266 were HOLLOW (.git held objects/ refs/ logs/ but no HEAD; 224 work trees no
            regular file, 42 a few). git does not treat such a .git as a repository and DISCOVERS the nearest enclosing one, so a
            hollow tree inside another clone was judged with THAT clone's HEAD, refs, diff and patch: here a hollow
            tree that kept its index and objects/info/alternates (the shapes of r25/forensics/tree and of a hollowed
            `clone --shared`) and holds an only-copy notes.log (ignored by the enclosing clone) is judged DELETE by
            the pre-r30 code (the enclosing clone's diff matches ITS patch) and --apply removes notes.log unproved. Fixed: KEEP 'C3 no HEAD commit (hollow ...)', an
            unborn HEAD is 'C3 no HEAD commit (unborn ...)', --apply keeps notes.log, and a sound `git clone --shared`
            tree with its patch + .md5 is still DELETE (the fix does not over-keep).

  RH10 r30 B148 DELETE-HOLLOW (user decision 2026-11-08, option a). A hollow tree (no .git/HEAD) whose files all lie
            under .git/objects|refs|logs and whose every object (loose and in every pack) the reference holds is
            DELETE-HOLLOW, and so is a .git with no file at all; KEEP for one foreign loose object, one foreign pack,
            one work-tree file, one other .git file (index), a protected dir, and a real unborn `git init`. --apply
            removes exactly the proved trees (record <tree>.gc.json beside each); an enclosing dirty clone is never
            touched: with the root above it the descent stops at the clone (KEEP, hollow tree inside untouched); with
            the root inside it only the hollow tree goes.
  RH11 r30 B148 resource_intel.walk counts only trees with a HEAD (or a .git file): a hollow .git is no clone tree.

  python3 -I harness/kat/test_scratch_gc_r30.py [--before FILE]   # FILE: another scratch_gc.py (the pre-r30 one FAILS)
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not proved (MISSED / WRONG-KAT / INVALID) or was coupled.
"""
import contextlib, hashlib, importlib.util, io, os, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
PATHS = {'gc': 'harness/pipeline/scratch_gc.py', 'ri': 'harness/intel/resource_intel.py'}
ENV = {**{k: v for k, v in os.environ.items() if not k.startswith('GIT_')}, 'GIT_CONFIG_GLOBAL': os.devnull,
       'GIT_CONFIG_NOSYSTEM': '1', 'GIT_AUTHOR_NAME': 'kat', 'GIT_AUTHOR_EMAIL': 'kat@invalid',
       'GIT_COMMITTER_NAME': 'kat', 'GIT_COMMITTER_EMAIL': 'kat@invalid', 'LC_ALL': 'C'}


def P(over, key):
    return Path(over.get(key) or ROOT / PATHS[key])


def load(over, key):
    path = P(over, key)
    spec = importlib.util.spec_from_file_location(f'gc30_{key}_{abs(hash(str(path)))}_{len(sys.modules)}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def sh(*cmd, cwd=None, input_=None):
    r = subprocess.run(list(cmd), cwd=cwd, env=ENV, capture_output=True, timeout=120,
                       input=input_.encode() if input_ else None)
    if r.returncode:
        raise RuntimeError(f'{cmd[:3]} rc {r.returncode}: {r.stderr.decode(errors="replace")[:200]}')
    return r.stdout


def patch_pair(path, data):
    Path(path).write_bytes(data)
    Path(str(path) + '.md5').write_text(hashlib.md5(data).hexdigest() + '  ' + Path(path).name + '\n')


def kat_gc1(over):
    G = load(over, 'gc')
    bad = []
    with tempfile.TemporaryDirectory(prefix='gc30-') as td:
        td = Path(td).resolve()
        ref = td / 'ref'
        ref.mkdir()
        sh('git', 'init', '-q', '-b', 'main', cwd=ref)
        (ref / 'a.txt').write_text('one\n')
        (ref / '.gitignore').write_text('*.patch\n*.md5\n*.log\n')
        sh('git', 'add', '-A', cwd=ref)
        sh('git', 'commit', '-q', '-m', 'base', cwd=ref)
        # the enclosing clone O (dirty), a scratch root inside it, a hollow tree h in that root
        outer = td / 'outer'
        sh('git', 'clone', '-q', '--shared', str(ref), str(outer))
        (outer / 'a.txt').write_text('one\ntwo\n')
        root = outer / 'scratch'
        h = root / 'h'
        (h / '.git' / 'objects').mkdir(parents=True)
        (h / '.git' / 'refs' / 'heads').mkdir(parents=True)
        (h / '.git' / 'objects' / 'info').mkdir()       # a hollowed `git clone --shared` tree keeps its alternates
        (h / '.git' / 'objects' / 'info' / 'alternates').write_text(str(ref / '.git' / 'objects') + '\n')
        shutil.copyfile(outer / '.git' / 'index', h / '.git' / 'index')   # r25/forensics/tree kept its index
        (h / 'notes.log').write_text('the only copy\n')
        patch_pair(root / 'x.patch', sh('git', 'diff', '--binary', 'HEAD', cwd=outer))
        # an unborn tree and a sound clone tree under a second root
        root2 = td / 'scr2'
        root2.mkdir()
        u = root2 / 'unborn'
        u.mkdir()
        sh('git', 'init', '-q', cwd=u)
        t = root2 / 'dim' / 'tree'
        t.parent.mkdir()
        sh('git', 'clone', '-q', '--shared', str(ref), str(t))
        (t / 'a.txt').write_text('one\nthree\n')
        patch_pair(t.parent / 'dim.patch', sh('git', 'diff', '--binary', 'HEAD', cwd=t))

        rh = G.judge(h, root, str(ref), [], 0, '')
        if rh['verdict'] != 'KEEP' or not rh.get('why', '').startswith('C3 no HEAD commit (hollow'):
            bad.append(f"hollow tree inside a clone: {rh['verdict']} {rh.get('why')} base {rh.get('base')}")
        ru = G.judge(u, root2, str(ref), [], 0, '')
        if ru['verdict'] != 'KEEP' or not ru.get('why', '').startswith('C3 no HEAD commit (unborn'):
            bad.append(f"unborn tree: {ru['verdict']} {ru.get('why')}")
        rt = G.judge(t, root2, str(ref), [], 0, '')
        if rt['verdict'] != 'DELETE':
            bad.append(f"sound clone tree: {rt['verdict']} {rt.get('why')}")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            G.main(['--root', str(root), '--reference', str(ref), '--min-age', '0', '--apply', '--json'])
        if not (h / 'notes.log').is_file():
            bad.append('--apply deleted the hollow tree and its only-copy notes.log')
    return not bad, '; '.join(bad) or 'hollow tree KEEP (no discovery of the enclosing clone), unborn KEEP, sound tree DELETE'


def hollow_copy(ref, dst, extra=None):
    """a hollow tree at dst: ref's object store (loose + packs) copied, a loose ref + a reflog, no HEAD"""
    shutil.copytree(ref / '.git' / 'objects', dst / '.git' / 'objects')
    (dst / '.git' / 'refs' / 'heads').mkdir(parents=True)
    (dst / '.git' / 'refs' / 'heads' / 'main').write_text(sh('git', 'rev-parse', 'HEAD', cwd=ref).decode())
    (dst / '.git' / 'logs').mkdir()
    (dst / '.git' / 'logs' / 'HEAD').write_text('0' * 40 + ' x kat <k@i> 0 +0000\tclone\n')
    for rel, data in (extra or {}).items():
        (dst / rel).parent.mkdir(parents=True, exist_ok=True)
        (dst / rel).write_bytes(data)
    return dst


def kat_rh10(over):
    G = load(over, 'gc')
    bad = []
    with tempfile.TemporaryDirectory(prefix='gc30h-') as td:
        td = Path(td).resolve()
        ref = td / 'ref'
        ref.mkdir()
        sh('git', 'init', '-q', '-b', 'main', cwd=ref)
        (ref / 'a.txt').write_text('one\n')
        (ref / '.gitignore').write_text('*.patch\n*.md5\n')
        sh('git', 'add', '-A', cwd=ref)
        sh('git', 'commit', '-q', '-m', 'base', cwd=ref)
        sh('git', 'repack', '-q', '-a', '-d', cwd=ref)                 # commit 1 in a pack
        (ref / 'b.txt').write_text('two\n')
        sh('git', 'add', '-A', cwd=ref)
        sh('git', 'commit', '-q', '-m', 'second', cwd=ref)            # commit 2 loose
        packs = list((ref / '.git' / 'objects' / 'pack').glob('*.idx'))
        loose = [p for p in (ref / '.git' / 'objects').glob('??/*')]
        if not packs or not loose:
            return False, f'fixture: packs {len(packs)} loose {len(loose)}'
        # foreign objects: a loose blob and a pack the reference never had
        fr = td / 'foreign'
        fr.mkdir()
        sh('git', 'init', '-q', cwd=fr)
        (fr / 'f.txt').write_text('foreign only\n')
        foid = sh('git', 'hash-object', '-w', 'f.txt', cwd=fr).decode().strip()
        floose = fr / '.git' / 'objects' / foid[:2] / foid[2:]
        (fr / 'g.txt').write_text('foreign pack\n')
        goid = sh('git', 'hash-object', '-w', 'g.txt', cwd=fr).decode().strip()
        pk = td / 'fpack'
        pk.mkdir()
        name = sh('git', 'pack-objects', '-q', str(pk / 'pack'), cwd=fr, input_=goid + '\n').decode().strip()
        root = td / 'scr'
        root.mkdir()
        ok_t = hollow_copy(ref, root / 'r29' / 'ok')
        fl_t = hollow_copy(ref, root / 'r29' / 'foreign_loose', {f'.git/objects/{foid[:2]}/{foid[2:]}': floose.read_bytes()})
        fp_t = hollow_copy(ref, root / 'r29' / 'foreign_pack', {f'.git/objects/pack/pack-{name}.{x}': (pk / f'pack-{name}.{x}').read_bytes()
                                                               for x in ('pack', 'idx')})
        wt_t = hollow_copy(ref, root / 'r29' / 'worktree_file', {'bin/miner.log': b'only copy\n'})
        ix_t = hollow_copy(ref, root / 'r29' / 'index_file', {'.git/index': b'DIRC'})
        em_t = root / 'r29' / 'empty'
        for d in ('objects/pack', 'objects/info', 'refs/heads', 'logs', 'hooks', 'info'):
            (em_t / '.git' / d).mkdir(parents=True)
        un_t = root / 'r29' / 'unborn'
        un_t.mkdir()
        sh('git', 'init', '-q', cwd=un_t)
        pr_t = hollow_copy(ref, root / 'r30' / 'ok')
        want = {ok_t: 'DELETE-HOLLOW', em_t: 'DELETE-HOLLOW', fl_t: 'KEEP H3', fp_t: 'KEEP H3', wt_t: 'KEEP H2',
                ix_t: 'KEEP H2', un_t: 'KEEP C3 no HEAD commit (unborn', pr_t: 'KEEP C1 protected'}
        for t, w in want.items():
            r = G.judge(t, root, str(ref), [str(root / 'r30')], 0, '')
            got = r['verdict'] + ' ' + r.get('why', '')
            v, _, why = w.partition(' ')
            if r['verdict'] != v or (why and why not in r.get('why', '')):
                bad.append(f'{t.name}: want {w}, got {got.strip()[:120]}')
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            G.main(['--root', str(root), '--protect', str(root / 'r30'), '--reference', str(ref), '--min-age', '0',
                    '--apply', '--json'])
        gone = {t for t in want if not t.exists()}
        if gone != {ok_t, em_t}:
            bad.append(f"--apply removed {sorted(t.name for t in gone)}, want ['empty', 'ok'] (r29)")
        if not (root / 'r29' / 'ok.gc.json').is_file():
            bad.append('no ok.gc.json record')
        if not (wt_t / 'bin' / 'miner.log').is_file() or not pr_t.exists():
            bad.append('a work-tree file or the protected tree was removed')
        # the enclosing dirty clone
        encl = td / 'encl'
        encl.mkdir()
        outer = encl / 'outer'
        sh('git', 'clone', '-q', '--shared', str(ref), str(outer))
        (outer / 'a.txt').write_text('one\ndirty\n')
        inner = hollow_copy(ref, outer / 'scratch' / 'h')
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            G.main(['--root', str(encl), '--reference', str(ref), '--min-age', '0', '--apply', '--json'])
        if not inner.exists() or not (outer / '.git' / 'HEAD').is_file():
            bad.append('root above the dirty clone: the clone or the hollow tree inside it was removed')
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            G.main(['--root', str(outer / 'scratch'), '--reference', str(ref), '--min-age', '0', '--apply', '--json'])
        if inner.exists():
            bad.append('root inside the dirty clone: the proved hollow tree was kept')
        if (outer / 'a.txt').read_text() != 'one\ndirty\n' or not (outer / '.git' / 'HEAD').is_file():
            bad.append('the enclosing dirty clone was touched')
    return not bad, '; '.join(bad) or ('hollow tree with every object in the reference DELETE-HOLLOW (+ the empty .git); '
                                       'foreign loose/pack object, work-tree file, index file, protected, unborn KEEP; '
                                       'apply removes exactly those two; enclosing dirty clone untouched')


def kat_rh11(over):
    R = load(over, 'ri')
    with tempfile.TemporaryDirectory(prefix='gc30w-') as td:
        td = Path(td)
        (td / 'hollow' / '.git' / 'objects' / 'ab').mkdir(parents=True)
        (td / 'hollow' / '.git' / 'objects' / 'ab' / ('c' * 38)).write_bytes(b'x')
        (td / 'clone' / '.git').mkdir(parents=True)
        (td / 'clone' / '.git' / 'HEAD').write_text('ref: refs/heads/main\n')
        (td / 'wt').mkdir()
        (td / 'wt' / '.git').write_text('gitdir: /elsewhere\n')
        n = R.walk(td, full=False)['clone_trees']
        nf = R.walk(td, full=True)['clone_trees']
    ok = n == 2 and nf == 2
    return ok, f'walk counts {n} (full {nf}) trees of clone + worktree + hollow; want 2'


KATS = [('GC1', kat_gc1), ('RH10', kat_rh10), ('RH11', kat_rh11)]
# GC1 and RH10 own each other's defects by construction: GC1's hollow tree (an index + an only-copy file) is KEEP
# only through check (b), and RH10's hollow tree inside a dirty clone is DELETE-HOLLOW only with git pinned to it.
OWNERS = {'r30 GC1': ['GC1', 'RH10'], 'r30 RH10': ['RH10', 'GC1'], 'r30 RH11': ['RH11']}

MUTATIONS = [   # (key, find, replace, why)
    ('gc', "    pin = ['--git-dir', str(Path(tree) / '.git'), '--work-tree', str(tree)] if own else []", "    pin = []",
     'r30 GC1: git discovers an enclosing repo for a hollow tree (the pre-r30 code)'),
    ('gc', "    if why:\n        return why, 0\n    n = len(loose)", "    n = len(loose)",
     'r30 RH10: check (b) dropped: work-tree / other .git files are not looked at'),
    ('gc', "    if not oids:\n        return []\n", "    return []\n",
     'r30 RH10: check (c) dropped: objects are never looked up in the reference'),
    ('gc', "    for d in protect:\n        if under(tree, d):", "    for d in []:\n        if under(tree, d):",
     'r30 RH10: the --protect check dropped'),
    ('ri', " and is_clone(d)\n", "\n", 'r30 RH11: walk counts a hollow .git as a clone tree (the pre-r30 code)'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_gc30', HARNESS / 'kit' / 'katmut.py')
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
    if argv[:1] == ['--before']:
        res = run_kats({'gc': Path(argv[1])})
        for name, ok, det in res:
            print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
        return 3 if any(not ok for _, ok, _ in res) else 0
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
        d = Path(tempfile.mkdtemp(prefix='gc30-mut-'))
        mp = d / 'harness' / src.parent.name / src.name    # its ROOT (parents[2]) is d, not the temp root that
        mp.parent.mkdir(parents=True)                       # holds the fixtures (C1 would keep every fixture tree)
        mp.write_text(text.replace(find, repl, 1))
        try:
            failed = [n for n, ok, _ in run_kats({key: mp}) if not ok]
        finally:
            shutil.rmtree(d, ignore_errors=True)
        verdict, extra = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:9s} {why}  {failed}')
        missed += verdict != 'proved'
        coupled += bool(extra) and verdict == 'proved'
    print('\n' + K.summary('r30 scratch_gc KATs', len(KATS) - fails if fails else len(KATS), len(MUTATIONS), missed, coupled))
    return 3 if fails else (4 if missed or coupled else 0)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
