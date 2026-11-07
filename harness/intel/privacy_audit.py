#!/usr/bin/env python3
"""privacy_audit.py — r28 (rft §7 B135, §5 privacy): which readers and writers put a peer address into a file.

B135 closed the live_window summary (peer-labelled /metrics series summed into name{peer=*}) and, in r28, its raw
scrapes (live_window.scrub_prom); the row still said 'log_intel and ad-hoc scrapes are not audited'. This tool is
that audit, over the tracked tree or any directory, with the one address rule of harness/kit/privkit.py (a
non-reserved IPv4 that is not a literal of a tracked .go file):

  writer      a harness/runtime file family (name_<stamp>.ext) whose NEWEST file carries an address and was written
              in the last --fresh-h hours: a tool that runs today still writes addresses (a finding; exit 5)
  historical  an older file of a family, or a family whose newest file is older than --fresh-h: written before the
              writer was fixed (pre-R25 log_intel / triage captures); private repository only (the public export excludes
              harness/runtime/), report-only
  fixture     harness/kat/*: a planted address a KAT feeds to a scrubber (report-only)
  static      any other tracked file (a page, a tool's text): report-only, listed by path
  file        --dir mode: every file of the directory is judged as a writer (an ad-hoc scrape or capture)

Counts and paths only: an address is never printed (each is shown as its first octet + '.x.x.x').

  python3 -I harness/intel/privacy_audit.py [--fresh-h 72] [--json OUT]       # the tracked tree
  python3 -I harness/intel/privacy_audit.py --dir DIR [--json OUT]           # a capture directory (e.g. a scratchpad)
Exit 0 no writer leaks · 5 a writer (or a --dir file) carries an address · 2 bad invocation.
"""
import datetime, json, re, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parent.parent.parent
sys.path.insert(0, str(HERE.parent.parent / 'kit'))
import privkit                                     # noqa: E402

STAMP_RX = re.compile(r'^(?P<fam>.+?)_(?P<ts>\d{8}(?:T\d{6}Z?)?)(?P<rest>[._].*)?$')
SKIP_SUFFIX = ('.go', '.png', '.jpg', '.gz', '.zst', '.bin', '.ico', '.woff', '.woff2', '.pdf', '.sum', '.mod')
MAX_BYTES = 64 * 1024 * 1024


def family(rel):
    """(family key, stamp) of a harness/runtime file name, or (None, None). 'logintel_20261103T092514.json' ->
    ('harness/runtime/logintel_*.json', '20261103T092514'). Pure."""
    p = Path(rel)
    m = STAMP_RX.match(p.name)
    if not m or not str(rel).startswith('harness/runtime/'):
        return None, None
    return f"harness/runtime/{m.group('fam')}_*{p.suffix}", m.group('ts')


def leaks_of(text, allowed):
    return privkit.page_ip_leaks(text or '', allowed)


def masked(ips):
    return sorted({ip.split('.')[0] + '.x.x.x' for ip in ips})


def stamp_time(ts):
    for fmt in ('%Y%m%dT%H%M%SZ', '%Y%m%dT%H%M%S', '%Y%m%d'):
        try:
            return datetime.datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def classify(files, now=None, fresh_h=72.0):
    """{rel: (class, n_addresses)} from {rel: n_addresses (0 = clean)} over every scanned file. A family's newest
    file decides 'writer' (it leaks and its stamp is within fresh_h of `now`). Pure."""
    fams = {}
    for rel in files:
        f, ts = family(rel)
        if f:
            fams.setdefault(f, []).append((ts, rel))
    newest = {f: max(v)[1] for f, v in fams.items()}
    out = {}
    for rel, n in files.items():
        if not n:
            continue
        f, ts = family(rel)
        if str(rel).startswith('harness/kat/'):
            out[rel] = ('fixture', n)
        elif f:
            t = stamp_time(ts)
            fresh = t is not None and now is not None and (now - t).total_seconds() <= fresh_h * 3600
            out[rel] = ('writer' if newest[f] == rel and fresh else 'historical', n)
        else:
            out[rel] = ('static', n)
    return out


def tracked(root):
    r = subprocess.run(['git', '-C', str(root), 'ls-files'], capture_output=True, text=True, timeout=120)
    return [l for l in r.stdout.splitlines() if l]


def scan(root, rels, allowed):
    """{rel: n_addresses} for every readable text file of `rels` under `root`."""
    res = {}
    for rel in rels:
        p = Path(root) / rel
        if p.suffix in SKIP_SUFFIX or not p.is_file():
            continue
        try:
            if p.stat().st_size > MAX_BYTES:
                continue
            res[rel] = len(leaks_of(p.read_text(errors='replace'), allowed))
        except OSError:
            continue
    return res


def summary(cls):
    by = {}
    for rel, (c, n) in cls.items():
        by.setdefault(c, []).append(rel)
    return {c: {'files': len(v), 'examples': sorted(v)[-5:]} for c, v in sorted(by.items())}


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    def opt(name, default=None):
        return argv[argv.index(name) + 1] if name in argv and argv.index(name) + 1 < len(argv) else default
    try:
        fresh_h = float(opt('--fresh-h', 72))
    except ValueError:
        print('privacy_audit: --fresh-h needs a number')
        return 2
    allowed = privkit.code_literal_ips(ROOT)
    if '--dir' in argv:
        d = Path(opt('--dir') or '')
        if not d.is_dir():
            print(f'privacy_audit: --dir {d} is not a directory')
            return 2
        rels = [str(p.relative_to(d)) for p in sorted(d.rglob('*')) if p.is_file()]
        files = scan(d, rels, allowed)
        cls = {r: ('file', n) for r, n in files.items() if n}
        scope = f'dir {d.name}'
    else:
        files = scan(ROOT, tracked(ROOT), allowed)
        cls = classify(files, datetime.datetime.now(), fresh_h)
        scope = 'tracked tree'
    s = summary(cls)
    bad = sum(1 for c, _ in cls.values() if c in ('writer', 'file'))
    doc = {'scope': scope, 'files_scanned': len(files), 'files_with_addresses': len(cls), 'classes': s,
           'writer_leaks': bad, 'fresh_h': fresh_h}
    if opt('--json'):
        Path(opt('--json')).write_text(json.dumps(doc, indent=1, sort_keys=True) + '\n')
    for c, v in s.items():
        print(f"  {c:<10} {v['files']:>4} file(s)  e.g. {', '.join(v['examples'][-3:])}")
    print(f"privacy_audit {scope}: {len(files)} files scanned · {len(cls)} carry an address · writer leaks {bad}")
    return 5 if bad else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
