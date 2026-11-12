#!/usr/bin/env python3
"""scratch_gc.py — delete a scratchpad repo clone tree ONLY when it is provably reproducible from git + its patch.

r27b (dero-rft §5 resource-hygiene rule, §7 B148). Each round leaves dozens of full repo clones (tree/, verify_tree/,
applycheck/, base/ ...; ~8-9k files and 180-320 MB each) in the session scratchpad, and backup_scratch.sh mirrored them
into ~/derohe-persist/scratchpad. A finished dimension needs only its patch: the tree is that patch applied to a commit.
DRY-RUN by default (nothing is written, not even inside a tree's .git); --apply deletes the trees that pass EVERY check:

  C1 location   the tree is under a --root, not under a --protect dir, not under ~/dero-data, the reference repo or this
                checkout (lexical AND resolved path); its .git is a directory (a worktree's .git file is kept: removing
                it would leave the source repo's worktree record behind).
  C2 quiet      nothing in the tree (file or dir, lstat mtime) changed in the last --min-age minutes (default 60).
  C3 base       git runs pinned to the tree's own .git (r30: never an enclosing repo found by discovery); HEAD of the
                tree is a commit the reference repo has (--reference, default env DERO_LIVE_REPO, else this checkout), and
                every ref of the tree (branches, tags, refs/stash) points at an object the reference has (a local
                commit or a stash would be lost).
  C4 patch      a <name>.patch with a <name>.patch.md5 in the tree's dir or an ancestor up to the --root; the md5 file's
                32-hex value equals the patch's md5.
  C5 diff       `git diff [--binary] <HEAD>` in the tree, untracked files included via `git update-index --add
                --info-only` (hashed, never written) into a TEMPORARY index copy (the tree's own index is never touched),
                equals that patch byte for byte. Not `git add -N`: it writes the empty blob, and when the reference
                already has it in a pack git FRESHENS that pack (utime) instead: the r27b integration dry run moved the
                live repo's pack mtime (one inode, 283 hardlinks) that way. The diff bytes are identical.
  C6 evidence   untracked/ignored files of the tree that any note (*.md / *.txt outside the clone trees under the roots,
                plus --notes files) names by its tree path are copied to <patch dir>/evidence_from_tree/<tree>/<path>
                (sizes re-checked) BEFORE the delete; a failed copy keeps the tree.
  H  hollow     r30 (B148) a tree whose .git has NO HEAD file is not a repository (C3 keeps it) but it can still be
                proved worthless, verdict DELETE-HOLLOW, when ALL hold: H1 no .git/HEAD; H2 every non-directory entry
                of the tree is a regular file under .git/objects, .git/refs or .git/logs (a work-tree file, a symlink or
                any other .git file — index, packed-refs, config — is KEEP); under objects only loose objects
                (xx/38hex), pack-<hex>.{pack,idx,rev,bitmap,keep,mtimes,promisor} with each .pack beside its .idx, and
                objects/info/{alternates,packs,commit-graph,commit-graphs/*} (an unknown object-store file such as
                tmp_obj_* or tmp_pack_* is KEEP); H3 every loose object and every object listed in every .idx is present
                in the reference (`git cat-file --batch-check` there; one missing object is KEEP); C1 and C2 as above.
                A .git with no file at all (no objects either) is hollow too; an unborn `git init` (it has HEAD) is not.
                --apply leaves <tree parent>/<tree>.gc.json and removes the tree.
  R  references r30 (B148-stash) --reference is repeatable: an object or base commit is present when ANY reference holds
                it (e.g. the permanent archive ~/derohe-persist/gc_archive/objects.git that keeps the stash / foreign
                objects of the hollow trees); every reference is a forbidden location. No flag: this checkout (or env
                DERO_LIVE_REPO), as before.
  On --apply each deleted tree leaves <patch dir>/<tree>.gc.json (base, patch, md5, files, bytes, evidence) — the
  recipe: git clone --shared <reference> T && git -C T checkout <base> && git -C T apply --binary <patch>.

  python3 -I harness/pipeline/scratch_gc.py --root DIR [--root DIR]... [--protect DIR]...
                                           [--reference REPO]... [--min-age 60] [--notes FILE]... [--apply] [--json]
Exit 0 done · 2 bad arguments / a forbidden root.
"""
import argparse, hashlib, json, os, re, shutil, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NOTE_SUFFIXES = ('.md', '.txt')
NOTE_MAX_BYTES = 8 * 1024 * 1024
GIT_ENV = {'GIT_OPTIONAL_LOCKS': '0', 'GIT_TERMINAL_PROMPT': '0', 'LC_ALL': 'C'}
GIT_CFG = ['-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false', '-c', 'diff.external=', '-c', 'color.ui=never']


def refs_of(reference):
    """the reference list: --reference is repeatable (r30 B148-stash); a bare str is one reference. Pure."""
    return [reference] if isinstance(reference, (str, Path)) else list(reference)


def forbidden_dirs(reference):
    """dero-data, every reference repo, this checkout (the last entry)"""
    return [Path.home() / 'dero-data', *(Path(r) for r in refs_of(reference)), ROOT]


def under(p, d):
    """p is d or inside d, lexically or after resolving either (symlinks). Pure apart from resolve()."""
    for a in {Path(os.path.abspath(p)), Path(p).resolve()}:
        for b in {Path(os.path.abspath(d)), Path(d).resolve()}:
            if a == b or b in a.parents:
                return True
    return False


def git(tree, *args, env=None, binary=False, own=False):
    """own=True pins git to <tree>/.git and <tree> (--git-dir/--work-tree). Without it a tree whose .git lacks HEAD
    (r30: 266 of 267 'no HEAD commit' scratch trees were hollowed: .git kept objects/ refs/ logs/ but no HEAD; 224
    work trees held no regular file, 42 a few) is not a repository to git, which then DISCOVERS the nearest enclosing
    one: a hollow tree inside another clone took that clone's HEAD, diff and patch, and a file of its own ignored there
    was deleted unproved (KAT harness/kat/test_scratch_gc_r30.py GC1)."""
    e = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    e.update(GIT_ENV)
    e.update(env or {})
    pin = ['--git-dir', str(Path(tree) / '.git'), '--work-tree', str(tree)] if own else []
    r = subprocess.run(['git', *GIT_CFG, '-C', str(tree), *pin, *args], capture_output=True, env=e, timeout=600)
    return r.returncode, (r.stdout if binary else r.stdout.decode('utf-8', 'replace'))


LOOSE_RE = re.compile(r'^[0-9a-f]{2}/[0-9a-f]{38}$')
PACK_RE = re.compile(r'^pack/pack-([0-9a-f]{40}|[0-9a-f]{64})\.(pack|idx|rev|bitmap|keep|mtimes|promisor)$')
INFO_RE = re.compile(r'^info/(alternates|packs|commit-graph|commit-graphs/[^/]+)$')
_IDX_OK = {}          # (sha1 of an .idx file, the reference tuple) already proved fully present -> True (270 trees share one)


def hollow_files(tree):
    """H2: (why-not or None, loose oids, idx paths). Reads names only. Pure apart from the walk."""
    loose, idx, packs = [], set(), set()
    t = str(tree)
    for dp, dns, fns in os.walk(t):
        for n in dns:
            if os.path.islink(os.path.join(dp, n)):
                return f'H2 a symlink: {os.path.relpath(os.path.join(dp, n), t)}', [], []
        for n in fns:
            full = os.path.join(dp, n)
            rel = os.path.relpath(full, t)
            parts = rel.split(os.sep)
            if os.path.islink(full) or not os.path.isfile(full):
                return f'H2 a symlink or special file: {rel}', [], []
            if parts[0] != '.git':
                return f'H2 a work-tree file: {rel}', [], []
            if len(parts) < 3 or parts[1] not in ('objects', 'refs', 'logs'):
                return f'H2 a .git file outside objects/refs/logs: {rel}', [], []
            if parts[1] != 'objects':
                continue
            o = '/'.join(parts[2:])
            if LOOSE_RE.match(o):
                loose.append(o.replace('/', ''))
            elif PACK_RE.match(o):
                stem, ext = o.rsplit('.', 1)
                (idx if ext == 'idx' else packs if ext == 'pack' else set()).add(stem)
            elif not INFO_RE.match(o):
                return f'H2 an unknown object-store file: {rel}', [], []
    if packs - idx:
        return f'H2 a .pack without its .idx: {sorted(packs - idx)[0]}', [], []
    return None, loose, [tree / '.git' / 'objects' / (s + '.idx') for s in sorted(idx)]


def ref_missing(reference, oids):
    """the oids NO reference holds (r30 B148-stash: an object is present when any --reference repo has it, e.g. the
    permanent archive ~/derohe-persist/gc_archive/objects.git; None when a check itself failed)"""
    if not oids:
        return []
    for r in refs_of(reference):
        oids = one_ref_missing(r, oids)
        if not oids:
            return oids
    return oids


def one_ref_missing(reference, oids):
    """the oids one reference's object store lacks (cat-file --batch-check; None when the check itself failed)"""
    if oids is None or not oids:
        return oids
    e = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    e.update(GIT_ENV)
    r = subprocess.run(['git', *GIT_CFG, '-C', str(reference), 'cat-file', '--batch-check=%(objectname)'],
                       input=('\n'.join(oids) + '\n').encode(), capture_output=True, env=e, timeout=1800)
    if r.returncode:
        return None
    lines = r.stdout.decode('utf-8', 'replace').splitlines()
    if len(lines) != len(oids):
        return None
    return [l.split()[0] for l in lines if l.endswith(' missing') or l.split()[0] != l.strip()]


def idx_oids(reference, idx):
    """the object ids an .idx lists (git show-index, run in the reference: it needs no repo of the tree)"""
    e = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    e.update(GIT_ENV)
    with open(idx, 'rb') as f:
        r = subprocess.run(['git', *GIT_CFG, '-C', str(reference), 'show-index'], stdin=f, capture_output=True,
                           env=e, timeout=600)
    if r.returncode:
        return None
    return [l.split()[1] for l in r.stdout.decode('utf-8', 'replace').splitlines() if len(l.split()) >= 2]


def hollow_proof(tree, reference):
    """(None, objects) when H1-H3 hold for the tree, else (why, 0)"""
    if (tree / '.git' / 'HEAD').exists():
        return 'H1 .git/HEAD exists', 0
    why, loose, idxs = hollow_files(tree)
    if why:
        return why, 0
    n = len(loose)
    miss = ref_missing(reference, loose)
    if miss is None:
        return 'H3 the reference check failed (loose objects)', 0
    if miss:
        return f'H3 {len(miss)} loose object(s) the reference lacks, e.g. {miss[0]}', 0
    for i in idxs:
        key = (hashlib.sha1(i.read_bytes()).hexdigest(), tuple(map(str, refs_of(reference))))   # a proof is per reference set
        oids = idx_oids(refs_of(reference)[0], i)
        if oids is None:
            return f'H3 unreadable pack index: {i.name}', 0
        n += len(oids)
        if _IDX_OK.get(key):
            continue
        miss = ref_missing(reference, oids)
        if miss is None:
            return f'H3 the reference check failed ({i.name})', 0
        if miss:
            return f'H3 {len(miss)} object(s) the reference lacks (pack {i.name}), e.g. {miss[0]}', 0
        _IDX_OK[key] = True
    return None, n


def find_trees(root):
    """dirs under root holding a .git entry (the descent stops at a tree)"""
    out, stack = [], [Path(root)]
    while stack:
        d = stack.pop()
        try:
            ents = list(os.scandir(d))
        except OSError:
            continue
        if d != Path(root) and any(e.name == '.git' for e in ents):
            out.append(d)
            continue
        for e in ents:
            if e.is_dir(follow_symlinks=False):
                stack.append(Path(e.path))
    return sorted(out)


def tree_stats(tree, inodes=None):
    """(files, bytes, newest mtime) over the tree, .git included, no symlink followed. The mtime of .git/objects is
    NOT activity: `git clone <path>` HARDLINKS the source repo's packs (link counts of 33 and 297 seen in r26 trees) and
    git freshens a pack's mtime whenever the SOURCE repo rewrites an object it holds, so every hardlinked tree looked
    'modified 4 min ago' (r27b dry run 1). inodes (a dict) collects {(dev, ino): (nlink, bytes)} for the freed-bytes
    count: deleting one link of a hardlinked pack frees nothing."""
    files = size = 0
    newest = os.lstat(tree).st_mtime
    objects = os.path.join(str(tree), '.git', 'objects')
    for dp, dns, fns in os.walk(tree):
        in_obj = dp == objects or dp.startswith(objects + os.sep)
        for n in dns + fns:
            try:
                st = os.lstat(os.path.join(dp, n))
            except OSError:
                continue
            if not in_obj and not (dp == os.path.join(str(tree), '.git') and n == 'objects'):
                newest = max(newest, st.st_mtime)
            if n in fns:
                files += 1
                size += st.st_blocks * 512
                if inodes is not None:
                    inodes[(st.st_dev, st.st_ino)] = (st.st_nlink, st.st_blocks * 512)
    return files, size, newest


def freed_bytes(inode_sets):
    """bytes a delete of these trees returns to the disk: an inode counts only when every one of its links is among
    them. Pure."""
    seen = {}
    for s in inode_sets:
        for k, (nl, b) in s.items():
            c = seen.setdefault(k, [0, nl, b])
            c[0] += 1
    return sum(b for c, nl, b in seen.values() if c >= nl)


def md5_of(path):
    return hashlib.md5(Path(path).read_bytes()).hexdigest()


def md5_claim(md5file):
    m = re.search(r'\b[0-9a-f]{32}\b', Path(md5file).read_text(errors='replace'))
    return m.group(0) if m else None


def candidate_patches(tree, root):
    """[(patch, md5 ok)] from the tree's dir up to root (inclusive), nearest first"""
    out, d = [], tree.parent
    while True:
        for p in sorted(d.glob('*.patch')):
            m = Path(str(p) + '.md5')
            if m.is_file():
                out.append((p, md5_claim(m) == md5_of(p)))
        if d == Path(root) or Path(root) not in d.parents:
            break
        d = d.parent
    return out


def tree_diffs(tree, base):
    """({'binary': bytes, 'text': bytes}, untracked, ignored) with untracked files intent-added into a TEMP index copy"""
    with tempfile.TemporaryDirectory(prefix='scratchgc_') as td:
        idx = Path(td) / 'index'
        src = tree / '.git' / 'index'
        if src.is_file():
            shutil.copyfile(src, idx)
        # `git add -N` writes the empty blob: into the tree (r27b KAT RH5 caught e69de29 in a dry run) or, with a TEMP
        # object dir, as a utime FRESHEN of the reference's pack that already holds it (r27b integration, B148). So
        # untracked files are entered with --info-only (hashed, not written); a temp object dir stays as a backstop.
        (Path(td) / 'objects').mkdir()
        env = {'GIT_INDEX_FILE': str(idx), 'GIT_OBJECT_DIRECTORY': str(Path(td) / 'objects'),
               'GIT_ALTERNATE_OBJECT_DIRECTORIES': str((tree / '.git' / 'objects').resolve())}
        _, unt = git(tree, 'ls-files', '-z', '--others', '--exclude-standard', env=env, own=True)
        unt = [u for u in unt.split('\0') if u]
        for i in range(0, len(unt), 200):
            rc, _ = git(tree, 'update-index', '--add', '--info-only', '--', *unt[i:i + 200], env=env, own=True)
            if rc:
                return None, unt, []
        _, ign = git(tree, 'ls-files', '-z', '--others', '--ignored', '--exclude-standard', env=env, own=True)
        ign = [u for u in ign.split('\0') if u]
        out = {}
        for k, flags in (('binary', ['--binary']), ('text', [])):
            rc, d = git(tree, 'diff', '--no-ext-diff', '--no-color', *flags, base, env=env, binary=True, own=True)
            if rc:
                return None, unt, ign
            out[k] = d
        return out, unt, ign


def notes_corpus(roots, trees, extra):
    """the text of every note (*.md / *.txt <= 8 MB) under the roots outside the clone trees, plus the --notes files"""
    tset = {str(t) for t in trees}
    parts = []
    for r in roots:
        for dp, dns, fns in os.walk(r):
            dns[:] = [n for n in dns if os.path.join(dp, n) not in tset and n != '.git']
            for n in fns:
                if n.endswith(NOTE_SUFFIXES):
                    p = os.path.join(dp, n)
                    try:
                        if os.path.getsize(p) <= NOTE_MAX_BYTES:
                            parts.append(Path(p).read_text(errors='replace'))
                    except OSError:
                        pass
    for p in extra or []:
        try:
            parts.append(Path(p).expanduser().read_text(errors='replace'))
        except OSError:
            pass
    return '\n'.join(parts)


def referenced(rel, tree, root, corpus):
    """a tree-relative path is named by a note: as an absolute path, scratch-relative path, '<tree dir>/<rel>', or (if it
    has a directory part and >= 8 chars) the bare tree-relative path. Pure."""
    toks = {str(tree / rel), str((tree / rel).relative_to(root)) if Path(root) in tree.parents else None, f'{tree.name}/{rel}'}
    if '/' in rel and len(rel) >= 8:
        toks.add(rel)
    return any(t and t in corpus for t in toks)


def judge(tree, root, reference, protect, min_age_s, corpus, now=None):
    """the verdict row for one tree (reads only)"""
    now = now or time.time()
    row = {'root': Path(root).name, 'tree': str(tree.relative_to(root)) if Path(root) in tree.parents else tree.name,
           'verdict': 'KEEP'}
    for d in forbidden_dirs(reference):
        if under(tree, d):
            row['why'] = 'C1 forbidden location'
            return row
    for d in protect:
        if under(tree, d):
            row['why'] = 'C1 protected'
            return row
    if not (tree / '.git').is_dir():
        row['why'] = 'C1 .git is not a directory (worktree or submodule)'
        return row
    inodes = {}
    files, size, newest = tree_stats(tree, inodes)
    row.update(files=files, bytes=size, _inodes=inodes)
    if now - newest < min_age_s:
        row['why'] = f'C2 modified {int((now - newest) // 60)} min ago'
        return row
    rc, base = git(tree, 'rev-parse', '--verify', '-q', 'HEAD^{commit}', own=True)
    base = base.strip()
    if rc or not base:
        hollow = not (tree / '.git' / 'HEAD').exists()
        row['why'] = 'C3 no HEAD commit' + (' (hollow: .git has no HEAD file)' if hollow else ' (unborn or unreadable HEAD)')
        if hollow:
            why, nobj = hollow_proof(tree, reference)
            if why:
                row['why'] += ' ' + why
            else:
                row.pop('why')
                row.update(verdict='DELETE-HOLLOW', objects=nobj, reference=[str(r) for r in refs_of(reference)])
        return row
    row['base'] = base
    if not any(git(r, 'cat-file', '-e', f'{base}^{{commit}}')[0] == 0 for r in refs_of(reference)):
        row['why'] = 'C3 HEAD not in the reference repo'
        return row
    _, refs = git(tree, 'for-each-ref', '--format=%(objectname)', own=True)
    for o in sorted(set(refs.split())):
        if not any(git(r, 'cat-file', '-e', o)[0] == 0 for r in refs_of(reference)):
            row['why'] = 'C3 a ref (branch/tag/stash) points at an object the reference lacks'
            return row
    cands = candidate_patches(tree, root)
    good = [p for p, ok in cands if ok]
    if not good:
        row['why'] = 'C4 no patch with a matching .md5' + (' (md5 mismatch)' if cands else '')
        return row
    diffs, unt, ign = tree_diffs(tree, base)
    if diffs is None:
        row['why'] = 'C5 git diff failed'
        return row
    match = next((p for p in good if p.read_bytes() in (diffs['binary'], diffs['text'])), None)
    if match is None:
        row['why'] = f'C5 diff != patch ({len(good)} candidate(s))'
        return row
    row.update(verdict='DELETE', patch=str(match.relative_to(root)) if Path(root) in match.parents else match.name,
               patch_md5=md5_of(match), untracked=len(unt), ignored=len(ign),
               evidence=[r for r in ign if referenced(r, tree, root, corpus)], _patch_dir=str(match.parent))
    return row


def apply_row(tree, row, min_age_s):
    """copy the evidence out, re-check C2, write the record, delete. Returns the row (verdict DELETED or KEEP+why)."""
    pdir = Path(row.pop('_patch_dir'))
    rel_tree = os.path.relpath(tree, pdir)
    dest = pdir / 'evidence_from_tree' / rel_tree
    for r in row['evidence']:
        s, t = tree / r, dest / r
        try:
            t.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(s, t, follow_symlinks=False)
            if not t.is_symlink() and t.stat().st_size != s.stat().st_size:
                raise OSError('size mismatch')
        except OSError as e:
            row.update(verdict='KEEP', why=f'C6 evidence copy failed ({type(e).__name__})')
            return row
    if time.time() - tree_stats(tree)[2] < min_age_s:
        row.update(verdict='KEEP', why='C2 modified during the run')
        return row
    rec = {k: row[k] for k in ('root', 'tree', 'base', 'patch', 'patch_md5', 'files', 'bytes', 'evidence')}
    rec['evidence_dir'] = os.path.relpath(dest, pdir) if row['evidence'] else None
    rec['deleted'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    rec['recipe'] = 'git clone --shared <reference> T && git -C T checkout <base> && git -C T apply --binary <patch>'
    (pdir / (rel_tree.replace('/', '__') + '.gc.json')).write_text(json.dumps(rec, indent=1) + '\n')
    shutil.rmtree(tree)
    row['verdict'] = 'DELETED'
    return row


def apply_hollow(tree, row, reference, min_age_s):
    """re-prove H1-H3 and C2 at delete time, write <tree parent>/<tree>.gc.json, remove the tree"""
    why, nobj = hollow_proof(tree, reference)
    if why:
        row.update(verdict='KEEP', why='C3 no HEAD commit (hollow: .git has no HEAD file) ' + why + ' (at apply)')
        return row
    if time.time() - tree_stats(tree)[2] < min_age_s:
        row.update(verdict='KEEP', why='C2 modified during the run')
        return row
    rec = {k: row.get(k) for k in ('root', 'tree', 'files', 'bytes', 'objects', 'reference')}
    rec.update(verdict='DELETE-HOLLOW', deleted=time.strftime('%Y-%m-%dT%H:%M:%S%z'),
               why='no .git/HEAD; only object-store/refs/logs files; every object present in the reference')
    (tree.parent / (tree.name + '.gc.json')).write_text(json.dumps(rec, indent=1) + '\n')
    shutil.rmtree(tree)
    row['verdict'] = 'DELETED-HOLLOW'
    return row


DELETE_VERDICTS = ('DELETE', 'DELETED', 'DELETE-HOLLOW', 'DELETED-HOLLOW')


def summarise(rows, inode_sets=()):
    s = {'trees': len(rows), 'delete': 0, 'delete_hollow': 0, 'files': 0, 'bytes': 0,
         'bytes_freed': freed_bytes(inode_sets), 'keep': {}}
    for r in rows:
        if r['verdict'] in DELETE_VERDICTS:
            s['delete'] += 1
            s['delete_hollow'] += 'HOLLOW' in r['verdict']
            s['files'] += r.get('files', 0)
            s['bytes'] += r.get('bytes', 0)
        else:
            k = re.sub(r'\d+', 'N', re.sub(r'(H\d .*?)( \(pack |: |, e\.g\. ).*$', r'\1', r['why']))
            s['keep'][k] = s['keep'].get(k, 0) + 1
    return s


def parse(argv):
    ap = argparse.ArgumentParser(prog='scratch_gc.py', description=__doc__.split('\n\n')[0])
    ap.add_argument('--root', action='append', required=True, help='scratch dir to collect (repeatable)')
    ap.add_argument('--protect', action='append', default=[], help='never touch a tree under this dir (an active round)')
    ap.add_argument('--reference', action='append', default=[],
                    help='repo that holds every base commit / object (repeatable: present = ANY reference has it; '
                         'env DERO_LIVE_REPO; default this checkout)')
    ap.add_argument('--min-age', type=float, default=60, help='minutes a tree must be untouched (default 60)')
    ap.add_argument('--notes', action='append', default=[], help='extra note files whose path mentions keep evidence')
    ap.add_argument('--apply', action='store_true', help='delete (default: dry run, writes nothing)')
    ap.add_argument('--json', action='store_true')
    return ap.parse_args(argv)


def main(argv):
    try:
        a = parse(argv)
    except SystemExit as e:
        return 0 if e.code in (0, None) else 2
    a.reference = a.reference or [os.environ.get('DERO_LIVE_REPO') or str(ROOT)]
    roots = [Path(os.path.abspath(os.path.expanduser(r))) for r in a.root]
    for r in roots:
        hard = forbidden_dirs(a.reference)[:-1]                  # dero-data and every reference repo: never inside a root
        if not r.is_dir() or any(under(r, d) for d in forbidden_dirs(a.reference)) or any(under(d, r) for d in hard):
            print(f'scratch_gc: --root {r.name}: not a dir, or it is / holds a forbidden dir (dero-data, the reference '
                  'repo, this checkout): refusing', file=sys.stderr)
            return 2
    trees = [(t, r) for r in roots for t in find_trees(r)]
    corpus = notes_corpus(roots, [t for t, _ in trees], a.notes)
    rows, inode_sets = [], []
    for t, r in trees:
        row = judge(t, r, a.reference, a.protect, a.min_age * 60, corpus)
        if a.apply and row['verdict'] == 'DELETE':
            row = apply_row(t, row, a.min_age * 60)
        elif a.apply and row['verdict'] == 'DELETE-HOLLOW':
            row = apply_hollow(t, row, a.reference, a.min_age * 60)
        row.pop('_patch_dir', None)
        ino = row.pop('_inodes', {})
        if row['verdict'] in DELETE_VERDICTS:
            inode_sets.append(ino)
        rows.append(row)
    s = summarise(rows, inode_sets)
    s['mode'] = 'apply' if a.apply else 'dry-run'
    if a.json:
        print(json.dumps({'summary': s, 'rows': rows}, indent=1))
    else:
        for row in rows:
            print(f"{row['verdict']:8s} {row['root']}/{row['tree']}  " + (row.get('why') or f"{row.get('files')} files {row.get('bytes')} B "
                                                             + (f"objects {row.get('objects')} all in the reference" if 'HOLLOW' in row['verdict'] else
                                                                f"patch {row.get('patch')} evidence {len(row.get('evidence', []))}")))
        print(f"{s['mode']}: {s['delete']}/{s['trees']} trees ({s['delete_hollow']} hollow), {s['files']} files, {s['bytes']} bytes "
              f"({s['bytes_freed']} freed: hardlinks shared with other trees or the repo stay) · kept {s['keep']}")
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
