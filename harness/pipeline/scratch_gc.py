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
  C3 base       HEAD of the tree is a commit the reference repo has (--reference, default env DERO_LIVE_REPO, else this
                checkout), and every ref of the tree (branches, tags, refs/stash) points at an object the reference has
                (a local commit or a stash would be lost).
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
  On --apply each deleted tree leaves <patch dir>/<tree>.gc.json (base, patch, md5, files, bytes, evidence) — the
  recipe: git clone --shared <reference> T && git -C T checkout <base> && git -C T apply --binary <patch>.

  python3 -I harness/pipeline/scratch_gc.py --root DIR [--root DIR]... [--protect DIR]... [--reference REPO]
                                           [--min-age 60] [--notes FILE]... [--apply] [--json]
Exit 0 done · 2 bad arguments / a forbidden root.
"""
import argparse, hashlib, json, os, re, shutil, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NOTE_SUFFIXES = ('.md', '.txt')
NOTE_MAX_BYTES = 8 * 1024 * 1024
GIT_ENV = {'GIT_OPTIONAL_LOCKS': '0', 'GIT_TERMINAL_PROMPT': '0', 'LC_ALL': 'C'}
GIT_CFG = ['-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false', '-c', 'diff.external=', '-c', 'color.ui=never']


def forbidden_dirs(reference):
    return [Path.home() / 'dero-data', Path(reference), ROOT]


def under(p, d):
    """p is d or inside d, lexically or after resolving either (symlinks). Pure apart from resolve()."""
    for a in {Path(os.path.abspath(p)), Path(p).resolve()}:
        for b in {Path(os.path.abspath(d)), Path(d).resolve()}:
            if a == b or b in a.parents:
                return True
    return False


def git(tree, *args, env=None, binary=False):
    e = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    e.update(GIT_ENV)
    e.update(env or {})
    r = subprocess.run(['git', *GIT_CFG, '-C', str(tree), *args], capture_output=True, env=e, timeout=600)
    return r.returncode, (r.stdout if binary else r.stdout.decode('utf-8', 'replace'))


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
        _, unt = git(tree, 'ls-files', '-z', '--others', '--exclude-standard', env=env)
        unt = [u for u in unt.split('\0') if u]
        for i in range(0, len(unt), 200):
            rc, _ = git(tree, 'update-index', '--add', '--info-only', '--', *unt[i:i + 200], env=env)
            if rc:
                return None, unt, []
        _, ign = git(tree, 'ls-files', '-z', '--others', '--ignored', '--exclude-standard', env=env)
        ign = [u for u in ign.split('\0') if u]
        out = {}
        for k, flags in (('binary', ['--binary']), ('text', [])):
            rc, d = git(tree, 'diff', '--no-ext-diff', '--no-color', *flags, base, env=env, binary=True)
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
    rc, base = git(tree, 'rev-parse', '--verify', '-q', 'HEAD^{commit}')
    base = base.strip()
    if rc or not base:
        row['why'] = 'C3 no HEAD commit'
        return row
    row['base'] = base
    if git(reference, 'cat-file', '-e', f'{base}^{{commit}}')[0]:
        row['why'] = 'C3 HEAD not in the reference repo'
        return row
    _, refs = git(tree, 'for-each-ref', '--format=%(objectname)')
    for o in sorted(set(refs.split())):
        if git(reference, 'cat-file', '-e', o)[0]:
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


def summarise(rows, inode_sets=()):
    s = {'trees': len(rows), 'delete': 0, 'files': 0, 'bytes': 0, 'bytes_freed': freed_bytes(inode_sets), 'keep': {}}
    for r in rows:
        if r['verdict'] in ('DELETE', 'DELETED'):
            s['delete'] += 1
            s['files'] += r.get('files', 0)
            s['bytes'] += r.get('bytes', 0)
        else:
            k = re.sub(r'\d+', 'N', r['why'])
            s['keep'][k] = s['keep'].get(k, 0) + 1
    return s


def parse(argv):
    ap = argparse.ArgumentParser(prog='scratch_gc.py', description=__doc__.split('\n\n')[0])
    ap.add_argument('--root', action='append', required=True, help='scratch dir to collect (repeatable)')
    ap.add_argument('--protect', action='append', default=[], help='never touch a tree under this dir (an active round)')
    ap.add_argument('--reference', default=os.environ.get('DERO_LIVE_REPO') or str(ROOT),
                    help='repo that must hold every base commit (env DERO_LIVE_REPO; default this checkout)')
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
    roots = [Path(os.path.abspath(os.path.expanduser(r))) for r in a.root]
    for r in roots:
        hard = forbidden_dirs(a.reference)[:2]                   # dero-data and the reference repo: never inside a root
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
        row.pop('_patch_dir', None)
        ino = row.pop('_inodes', {})
        if row['verdict'] in ('DELETE', 'DELETED'):
            inode_sets.append(ino)
        rows.append(row)
    s = summarise(rows, inode_sets)
    s['mode'] = 'apply' if a.apply else 'dry-run'
    if a.json:
        print(json.dumps({'summary': s, 'rows': rows}, indent=1))
    else:
        for row in rows:
            print(f"{row['verdict']:8s} {row['root']}/{row['tree']}  " + (row.get('why') or f"{row.get('files')} files {row.get('bytes')} B "
                                                             f"patch {row.get('patch')} evidence {len(row.get('evidence', []))}"))
        print(f"{s['mode']}: {s['delete']}/{s['trees']} trees, {s['files']} files, {s['bytes']} bytes "
              f"({s['bytes_freed']} freed: hardlinks shared with other trees or the repo stay) · kept {s['keep']}")
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
