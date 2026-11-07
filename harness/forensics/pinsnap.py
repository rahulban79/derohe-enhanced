#!/usr/bin/env python3
"""R28 pinned-source snapshots for sealed forensic dataset versions (rft §0.8.1 rule 2 "the pinned script at the pinned
commit", §0.8.8 content pins; backlog B147).

A sealed version (forensics/r25) pins the CONTENT of its replay tools, its decoder build inputs (globals/globals.go among
them), the HF3 table and the code lines it cites (pins.py `content_pins`). Until R28 the only way to replay it was a
working tree in which every pinned byte was still identical, so a correct fix in a pinned decoder input (the R27 globals
fixes, B147) had to be HELD forever. This module removes that coupling WITHOUT relaxing a pin:

  resolve   every pinned file (and every cited line range) is looked up first in the working tree, then in the git object
            store (every commit that touched the path, newest first); a pin RESOLVES only when some byte sequence hashes
            exactly to the pinned SHA-256 (with pins.py's own normalisation of config/version.go). Nothing is ever
            re-pinned or skipped: an unresolvable pin is a failure.
  snapshot  a scratch tree = the working tree's tracked files, overlaid with the resolved bytes of every pinned file that
            differs; pins.check() is then re-run INSIDE the snapshot (including the `go list` decoder input set), so the
            snapshot is exactly the pinned source.
  replay    (optional) runs the snapshot's own replay.py (pinned) on the snapshot's copy of the dataset, so a sealed version
            is replayed by its pinned tools at its pinned content, whatever HEAD looks like.

  python3 -I harness/forensics/pinsnap.py check   forensics/r25/manifest.json      # resolve only; exit 0 PASS, 7 FAIL
  python3 -I harness/forensics/pinsnap.py snapshot forensics/r25/manifest.json --out DIR [--keep]
  python3 -I harness/forensics/pinsnap.py replay  forensics/r25 --out DIR [--store DIR] [--archive-copy DIR]
Read-only towards the repository (git show / ls-files only) and every store; writes only under --out.
"""
import hashlib, json, os, shutil, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import pins as P  # noqa: E402  (pinned by r25; used read-only: file_sha normalisation, check, decoder_input_paths)

GROUPS = ('replay_tools', 'decoder_inputs', 'hf3_table')


def sha(b):
    return hashlib.sha256(b).hexdigest()


def norm_sha(rel, b):
    if rel in P.NORMALIZE:
        rx, rep = P.NORMALIZE[rel]
        b = rx.sub(rep, b)
    return sha(b)


def git(root, *args, text=False):
    p = subprocess.run(['git', '-C', str(root), *args], capture_output=True, text=text)
    return p.returncode, p.stdout


def history(root, rel):
    """commits that touched rel (newest first), across every ref"""
    rc, out = git(root, 'log', '--all', '--format=%H', '--', rel, text=True)
    return [c for c in out.split() if c] if rc == 0 else []


def blob(root, commit, rel):
    rc, out = git(root, 'show', f'{commit}:{rel}')
    return out if rc == 0 else None


def find_bytes(root, rel, want, matcher=None):
    """(source, bytes) for the first version of rel whose hash matches: 'worktree' or the commit id; (None, None)"""
    matcher = matcher or (lambda b: norm_sha(rel, b) == want)
    p = Path(root) / rel
    if p.exists():
        b = p.read_bytes()
        if matcher(b):
            return 'worktree', b
    for c in history(root, rel):
        b = blob(root, c, rel)
        if b is not None and matcher(b):
            return c, b
    return None, None


def _lines(b, a, z):
    ls = b.split(b'\n')
    return None if z > len(ls) or a < 1 else sha(b'\n'.join(ls[a - 1:z]))


def resolve(pins, root=ROOT):
    """{'files': {rel: {'group','source','sha256'}}, 'cited': {key: source}, 'failures': [...]} — a pin that no byte
    sequence in the worktree or the object store matches is a failure (never skipped, never re-pinned)."""
    root = Path(root)
    res, fails, chosen = {}, [], {}
    if not pins:
        return {'files': {}, 'cited': {}, 'failures': ['manifest has no content_pins']}
    for grp in GROUPS:
        for rel, h in sorted((pins.get(grp) or {}).items()):
            src, b = find_bytes(root, rel, h)
            if src is None:
                fails.append(f'unresolvable pin ({grp}): {rel}')
                continue
            res[rel] = {'group': grp, 'source': src, 'sha256': h}
            chosen[rel] = b
    cited = {}
    for key, h in sorted((pins.get('cited_lines') or {}).items()):
        f, _, rng = key.rpartition(':')
        a, _, z = rng.partition('-')
        a, z = int(a), int(z or a)
        if f in chosen:                               # a cited file that is also pinned whole: its lines must match there
            if _lines(chosen[f], a, z) != h:
                fails.append(f'cited lines do not match the resolved pinned file: {key}')
            else:
                cited[key] = res[f]['source']
            continue
        src, b = find_bytes(root, f, h, matcher=lambda b, a=a, z=z, h=h: _lines(b, a, z) == h)
        if src is None:
            fails.append(f'unresolvable cited lines: {key}')
            continue
        if f in chosen and chosen[f] != b:
            fails.append(f'cited lines of {f} need two different versions of the file')
            continue
        chosen[f] = b
        cited[key] = src
        res.setdefault(f, {'group': 'cited_file', 'source': src, 'sha256': sha(b)})
    if pins.get('aggregate_sha256') != P.aggregate(pins):
        fails.append('content_pins aggregate_sha256 does not match its own entries')
    return {'files': res, 'cited': cited, 'failures': fails, '_bytes': chosen}


def resolve_tools(tools, root=ROOT):
    """a manifest's plain `tools` map {rel: sha256} (no normalisation): [failures] — every tool's bytes must exist in the
    worktree or the object store (MF1 committed for a sealed version whose tools moved on, R28)"""
    fails = []
    for rel, h in sorted((tools or {}).items()):
        src, _ = find_bytes(root, rel, h, matcher=lambda b, h=h: sha(b) == h)
        if src is None:
            fails.append(f'unresolvable pinned tool: {rel}')
    return fails


def summary(r):
    srcs = {}
    for v in r['files'].values():
        k = 'worktree' if v['source'] == 'worktree' else 'git'
        srcs[k] = srcs.get(k, 0) + 1
    return {'pinned_files': len(r['files']), 'from_worktree': srcs.get('worktree', 0), 'from_git_objects': srcs.get('git', 0),
            'differ_from_worktree': sorted(k for k, v in r['files'].items() if v['source'] != 'worktree'),
            'cited_ranges': len(r['cited']), 'failures': r['failures']}


def prune_new_inputs(pins, out, lister=None, rounds=4):
    """R28 merge (B165 class, rpc-metrics x forensics-closure): a package the sealed version pins may GAIN a file later
    (R28: metrics/registry_r28.go + metrics/metric_registry.json). Such a file did not exist at pin time, so the pinned
    source never had it: remove every decoder input the snapshot lists that the pins do not name (repeat until the set is
    stable, since a removed file can drop further inputs). Only files under out/ are touched; returns the removed paths."""
    if not pins.get('decoder_inputs'):
        return []
    goos, _, goarch = pins.get('decoder_platform', '/').partition('/')
    pinned, gone = set(pins['decoder_inputs']), []
    for _ in range(rounds):
        try:
            now = (lister or P.decoder_input_paths)(out, goos or None, goarch or None)
        except RuntimeError:
            break                                       # P.check reports the listing failure itself
        extra = [x for x in now if x not in pinned and (Path(out) / x).is_file()]
        if not extra:
            break
        for x in extra:
            (Path(out) / x).unlink()
            gone.append(x)
    return sorted(gone)


def snapshot(pins, out, root=ROOT, lister=None):
    """materialize the pinned source under out/ (tracked worktree files + the resolved pinned bytes) and re-check every
    pin inside it; returns (summary dict, [failures])"""
    root, out = Path(root), Path(out)
    r = resolve(pins, root)
    s = summary(r)
    if r['failures']:
        return s, r['failures']
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    rc, ls = git(root, 'ls-files', '-z')
    for rel in (x.decode() for x in ls.split(b'\0') if x):
        src = root / rel
        if src.is_file() and not src.is_symlink():
            dst = out / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
    for rel, b in r['_bytes'].items():
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(b)
    s['pruned_new_inputs'] = prune_new_inputs(pins, out, lister)
    inside = P.check(pins, out, lister)
    s['snapshot_check'] = 'PASS' if not inside else f'FAIL ({len(inside)})'
    return s, [f'snapshot: {x}' for x in inside]


def replay_snapshot(ds, out, store=None, archive=None, root=ROOT):
    """replay a version with ITS pinned tools inside the snapshot; returns the replay report (dict) or a failure dict"""
    ds, out = Path(ds), Path(out).resolve()   # R28 verifier: a relative --out was joined onto the snapshot cwd twice
    m = json.loads((ds / 'manifest.json').read_text())
    s, f = snapshot(m.get('content_pins'), Path(out) / 'src', root)
    if f:
        return {'result': 'FAIL', 'fail_reasons': f, 'snapshot': s}
    rel = ds.resolve().relative_to(Path(root).resolve())
    cmd = [sys.executable, '-I', str(Path(out) / 'src' / 'harness/forensics/replay.py'), str(Path(out) / 'src' / rel)]
    if store:
        cmd += ['--store', str(store)]
    if archive:
        cmd += ['--archive-copy', str(archive)]
    p = subprocess.run(['nice', '-n', '15', *cmd], capture_output=True, text=True, cwd=str(Path(out) / 'src'))
    try:
        rep = json.loads(p.stdout)
    except ValueError:
        return {'result': 'FAIL', 'fail_reasons': [f'replay produced no report (rc {p.returncode}): '
                                                   + (p.stderr.strip().splitlines() or ['no stderr'])[-1]], 'snapshot': s}
    return {'result': rep.get('result'), 'fail_reasons': rep.get('fail_reasons', []), 'snapshot': s,
            'mode': (rep.get('rederive') or {}).get('mode'), 'report_sha256': sha((json.dumps(rep, indent=1, sort_keys=True) + '\n').encode()),
            'rederive': {k: (rep.get('rederive') or {}).get(k) for k in ('expected', 'equal', 'mismatch', 'missing', 'extra')}}


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest='cmd', required=True)
    p = sp.add_parser('check'); p.add_argument('manifest')
    p = sp.add_parser('snapshot'); p.add_argument('manifest'); p.add_argument('--out', required=True); p.add_argument('--keep', action='store_true')
    p = sp.add_parser('replay'); p.add_argument('dataset'); p.add_argument('--out', required=True)
    p.add_argument('--store'); p.add_argument('--archive-copy')
    a = ap.parse_args(argv)
    if a.cmd == 'check':
        r = resolve(json.loads(Path(a.manifest).read_text()).get('content_pins'))
        s = summary(r)
        print(json.dumps(s, indent=1, sort_keys=True))
        return 0 if not r['failures'] else 7
    if a.cmd == 'snapshot':
        s, f = snapshot(json.loads(Path(a.manifest).read_text()).get('content_pins'), a.out)
        print(json.dumps(dict(s, failures=f), indent=1, sort_keys=True))
        if not a.keep:
            shutil.rmtree(a.out, ignore_errors=True)
        return 0 if not f else 7
    rep = replay_snapshot(a.dataset, a.out, a.store, a.archive_copy)
    print(json.dumps(rep, indent=1, sort_keys=True))
    return 0 if rep.get('result') == 'PASS' else 5


if __name__ == '__main__':
    sys.exit(main())
