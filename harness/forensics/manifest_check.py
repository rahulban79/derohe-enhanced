#!/usr/bin/env python3
"""Check a dataset against its manifest (rft §0.8.3; KAT MF1). Every file on disk must be listed with its SHA-256,
every listed file must exist and re-hash equal, and the tools and the HF3 table must match their pinned SHA-256s.

  python3 -I harness/forensics/manifest_check.py --dataset forensics/r25 [--root .]
  exit 0 = every hash matches, 7 = a mismatch (each printed)
"""
import argparse, hashlib, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def check(ds, root=ROOT, manifest=None):
    ds, root = Path(ds), Path(root)
    m = manifest if manifest is not None else json.loads((ds / 'manifest.json').read_text())
    fails = []
    listed = m.get('files', {})
    if not listed:
        fails.append('manifest lists no files')
    on_disk = {str(p.relative_to(ds)) for p in ds.rglob('*') if p.is_file() and p.name != 'manifest.json'}
    for rel in sorted(on_disk - set(listed)):
        fails.append(f'unlisted file: {rel}')
    for rel, h in sorted(listed.items()):
        p = ds / rel
        if not p.exists():
            fails.append(f'listed file missing: {rel}')
        elif sha(p) != h:
            fails.append(f'sha256 mismatch: {rel}')
    for rel, h in sorted(m.get('tools', {}).items()):
        p = root / rel
        if not p.exists():
            fails.append(f'pinned tool missing: {rel}')
        elif sha(p) != h:
            fails.append(f'pinned tool changed: {rel}')
    t = m.get('hf3_table')
    if t and (not (root / t['file']).exists() or sha(root / t['file']) != t['sha256']):
        fails.append('HF3 table sha256 differs from the manifest')
    return fails


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--dataset', required=True); ap.add_argument('--root', default=str(ROOT))
    a = ap.parse_args(argv)
    f = check(a.dataset, a.root)
    print('manifest check:', 'PASS' if not f else f'FAIL ({len(f)})')
    for x in f[:50]:
        print(' ', x)
    return 7 if f else 0


if __name__ == '__main__':
    sys.exit(main())
