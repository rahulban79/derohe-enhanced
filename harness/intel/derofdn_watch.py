#!/usr/bin/env python3
"""derofdn_watch.py — r30 (rft §7 B203 (c), B184): the one observable that can move the DC2 value, watched each round.

The DC2 value (value created through the range-proof defect) is NOT-DECIDABLE-FROM-PUBLIC-DATA (FQ5, §9): no public
test separates an accepted-invalid proof from an honest one. Only an upstream change can move it: a fix (a new
release tag, or a moved head carrying a verifier change) or a published detector. Until R30 that watch was a hand
step (the R29 B184 record harness/runtime/r29_b184_watch_20261108.json); this tool makes it a check: it reads the
DEROFDN/derohe heads and tags with `git ls-remote` (read-only: no fetch, no clone, no write anywhere but the record)
and compares them with the newest recorded watch.

  parse(text)              {'heads': {name: sha}, 'tags': {name: sha}} of `git ls-remote --heads --tags` output. Pure.
  compare(now, baseline)   {result UNCHANGED | CHANGED, moved heads, new tags, gone refs}; a CHANGED result is reported
                           to the user at once (rft §8 B184 escalation) and re-tests FQ5 (B203 (b)). Pure.
  baseline_of(rec)         the {heads, tags} a recorded watch states (R29 format: heads 'sha (= baseline)', the three
                           newest tags as short shas). Pure.

  python3 -I harness/intel/derofdn_watch.py [--baseline FILE] [--record] [--from-file LS_REMOTE.txt]
Exit 0 UNCHANGED · 5 CHANGED (report to the user) · 2 the remote or the baseline is unreadable.
"""
import argparse, datetime, glob, json, os, re, subprocess, sys
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
REMOTE = 'https://github.com/DEROFDN/derohe.git'
OBSERVABLE = ('an upstream fix or a published detector for the range-proof defect: a new DEROFDN tag or a moved head '
              '(B203 (c)); MAJOR_HF4_HEIGHT on a release or on main (B184 escalation)')


def parse(text):
    out = {'heads': {}, 'tags': {}}
    for line in str(text or '').splitlines():
        m = re.fullmatch(r'([0-9a-f]{40})\s+refs/(heads|tags)/(\S+?)(\^\{\})?', line.strip())
        if m:
            sha, kind, name, peeled = m.groups()
            if kind == 'tags' and not peeled and name in out['tags']:
                continue              # keep the peeled commit of an annotated tag
            out[kind][name] = sha
    return out


def baseline_of(rec):
    heads = {k: re.match(r'[0-9a-f]+', str(v)).group(0) for k, v in ((rec or {}).get('heads') or {}).items() if re.match(r'[0-9a-f]+', str(v))}
    tags = dict((rec or {}).get('tags_full') or {}) or {k: str(v) for k, v in ((rec or {}).get('newest_tags') or {}).items()}
    return {'heads': heads, 'tags': tags, 'tag_count': (rec or {}).get('tags') if isinstance((rec or {}).get('tags'), int) else len(tags)}


def _same(a, b):
    return bool(a and b) and (a.startswith(b) or b.startswith(a))


def compare(now, base):
    moved = sorted(h for h, s in (base.get('heads') or {}).items() if h in now['heads'] and not _same(now['heads'][h], s))
    gone = sorted(h for h in (base.get('heads') or {}) if h not in now['heads'])
    new_heads = sorted(h for h in now['heads'] if h not in (base.get('heads') or {}))
    known = base.get('tags') or {}
    full = len(known) >= (base.get('tag_count') or 0) and len(known) > 3
    new_tags = (sorted(t for t in now['tags'] if t not in known) if full
                else (['(tag count %d -> %d)' % (base.get('tag_count'), len(now['tags']))] if base.get('tag_count') not in (None, len(now['tags'])) else []))
    moved_tags = sorted(t for t, s in known.items() if t in now['tags'] and not _same(now['tags'][t], s))
    changed = bool(moved or gone or new_heads or new_tags or moved_tags)
    return {'result': 'CHANGED' if changed else 'UNCHANGED', 'moved_heads': moved, 'gone_heads': gone, 'new_heads': new_heads,
            'new_tags': new_tags, 'moved_tags': moved_tags, 'tags': len(now['tags']), 'observable': OBSERVABLE}


def newest_record(root=ROOT):
    fs = sorted(glob.glob(str(Path(root) / 'harness/runtime/r*_b184_watch_*.json')) + glob.glob(str(Path(root) / 'harness/runtime/r*_derofdn_watch_*.json')),
                key=lambda p: os.path.basename(p).split('_')[-1])
    return fs[-1] if fs else None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--baseline', help='a recorded watch (default: the newest harness/runtime/r*_b184_watch_* / r*_derofdn_watch_*)')
    ap.add_argument('--from-file', help='read ls-remote output from a file instead of the network')
    ap.add_argument('--record', action='store_true', help='write harness/runtime/r<round>_derofdn_watch_<ts>.json')
    ap.add_argument('--root', default=str(ROOT))
    a = ap.parse_args(argv)
    bp = a.baseline or newest_record(a.root)
    try:
        base = baseline_of(json.loads(Path(bp).read_text())) if bp else None
    except (OSError, ValueError):
        base = None
    if not base:
        print('derofdn_watch: no readable baseline record'); return 2
    try:
        text = Path(a.from_file).read_text() if a.from_file else subprocess.run(
            ['git', 'ls-remote', '--heads', '--tags', REMOTE], capture_output=True, text=True, timeout=60, check=True).stdout
    except (OSError, subprocess.SubprocessError) as e:
        print(f'derofdn_watch: remote unreadable ({type(e).__name__})'); return 2
    now = parse(text)
    if not now['heads']:
        print('derofdn_watch: the remote listed no heads'); return 2
    r = compare(now, base)
    print(f"derofdn_watch {r['result']}: heads {len(now['heads'])}, tags {r['tags']}; moved {r['moved_heads']} new heads {r['new_heads']} "
          f"new tags {r['new_tags'][:5]} moved tags {r['moved_tags']} (baseline {os.path.relpath(bp, a.root)})")
    if a.record:
        reg = json.loads((Path(a.root) / 'harness/round.json').read_text())
        ts = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        out = Path(a.root) / f"harness/runtime/{reg.get('current', 'r')}_derofdn_watch_{ts}.json"
        out.write_text(json.dumps({'row': 'B203 (c) / B184 (rft §7): the DEROFDN tag and head watch', 'when': ts,
                                   'method': f'git ls-remote --heads --tags {REMOTE} (read-only; no fetch, no clone write)',
                                   'baseline': os.path.relpath(bp, a.root), 'heads': now['heads'], 'tags': len(now['tags']),
                                   'tags_full': now['tags'], **r}, indent=1) + '\n')
        print(f'record {os.path.relpath(out, a.root)}')
    return 5 if r['result'] == 'CHANGED' else 0


if __name__ == '__main__':
    sys.exit(main())
