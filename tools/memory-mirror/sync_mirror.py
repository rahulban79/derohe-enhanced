#!/usr/bin/env python3
"""r25 (dero-rft §0.9 rule 5, B88): rebuild the scrubbed in-repo memory mirror from one private stamp.

  python3 -I tools/memory-mirror/sync_mirror.py --stamp <private stamp dir> --repo <repo root> [--pubscrub FILE]

Every *.md of the stamp goes through pubscrub.py (the publish scrubber: wallet prefix, e-mail, home paths, IPs, host
and app names) into a temporary directory. A scrubbed file that still carries a private-identifier shape
(harness/intel/tooling_intel.py private_hits: a home path, a scratchpad project dir name, an e-mail, a DERO address, a
non-reserved IPv4) is NOT mirrored: its manifest line says '-' and the run names it (by file name only). One extra
two rules run after pubscrub (redact): an e-mail shape is written '<e-mail>' (pubscrub rewrites the user's name inside
an address but leaves the address shape, so its own residual check failed on one memory file, 2026-11-03), and a
non-reserved IPv4 '<ip>' (pubscrub's IP scan misses an address that ends a sentence, '... 192.0.2.1.'). The mirror
directory is then replaced: files of an older sync that are no longer produced are removed. memory-mirror/MANIFEST.sha256
gets one line per source file: '<source sha256> <mirror sha256 or -> <file>' (the drift check reads it).

Exit 0 mirrored · 1 a file was refused for a private identifier (the others are still mirrored) · 2 bad invocation.
"""
import argparse, hashlib, importlib.util, re, subprocess, sys, tempfile
from pathlib import Path


EMAIL_RX = re.compile(rb'[\w.+-]+@[\w-]+\.[\w.]+')


def redact(b, T):
    """the two rules run after pubscrub: an e-mail shape -> '<e-mail>'; a non-reserved IPv4 (tooling_intel's shape, which
    also reads an address that ends a sentence) -> '<ip>'. Pure."""
    b = EMAIL_RX.sub(b'<e-mail>', b)
    t = b.decode('utf-8', errors='replace')
    rx = dict(T.PRIVATE_RX)['ipv4']
    t = rx.sub(lambda m: m.group(0) if T.IP_OK.match(m.group(0)) or any(int(x) > 255 for x in m.group(0).split('.')) else '<ip>', t)
    return t.encode('utf-8')


def load_tooling(repo):
    spec = importlib.util.spec_from_file_location('tooling_intel_for_mirror', Path(repo) / 'harness/intel/tooling_intel.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def sha(b):
    return hashlib.sha256(b).hexdigest()


def plan(stamp_files, scrubbed, hits):
    """{name: mirror bytes or None} and the refused names: a scrubbed file with a private hit is refused. Pure."""
    keep, refused = {}, []
    for n in sorted(stamp_files):
        b = scrubbed.get(n)
        if b is None or hits(b.decode('utf-8', errors='replace')):
            keep[n] = None
            refused.append(n)
        else:
            keep[n] = b
    return keep, refused


def manifest_lines(stamp_files, keep):
    """'<source sha> <mirror sha or -> <file>' per source file, sorted. Pure."""
    return [f"{sha(stamp_files[n])} {sha(keep[n]) if keep.get(n) is not None else '-'} {n}" for n in sorted(stamp_files)]


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument('--stamp', required=True)
    ap.add_argument('--repo', required=True)
    ap.add_argument('--pubscrub', default=None, help='default: harness/loop/TOOL_PATHS.json "pubscrub" of --repo')
    a = ap.parse_args(argv)
    stamp, repo = Path(a.stamp), Path(a.repo)
    if a.pubscrub is None and (repo / 'harness').is_dir():
        tp = load_tooling(repo).tool_path('pubscrub', repo)
        a.pubscrub = str(tp) if tp else ''
    if not stamp.is_dir() or not (repo / 'harness').is_dir() or not Path(a.pubscrub).is_file():
        print('sync_mirror: --stamp, --repo or --pubscrub not found')
        return 2
    T = load_tooling(repo)
    src = {p.name: p.read_bytes() for p in sorted(stamp.glob('*.md'))}
    scrubbed = {}
    with tempfile.TemporaryDirectory(prefix='r25mirror-') as d:
        r = subprocess.run([sys.executable, '-I', a.pubscrub, d, *[str(stamp / n) for n in src]], capture_output=True, text=True)
        for n in src:
            p = Path(d) / n
            if p.exists():
                scrubbed[n] = redact(p.read_bytes(), T)
    keep, refused = plan(src, scrubbed, T.private_hits)
    out = repo / T.MIRROR
    if out.exists():
        for p in out.iterdir():
            if p.is_file():
                p.unlink()
    out.mkdir(exist_ok=True)
    for n, b in keep.items():
        if b is not None:
            (out / n).write_bytes(b)
    (out / T.MANIFEST).write_text('\n'.join(manifest_lines(src, keep)) + '\n')
    print(f'sync_mirror: {sum(1 for b in keep.values() if b is not None)} mirrored, {len(refused)} refused for a private '
          f'identifier {refused}, pubscrub rc {r.returncode}')
    return 1 if refused else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
