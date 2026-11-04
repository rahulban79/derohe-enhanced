#!/usr/bin/env python3
"""Dataset lints (rft §0.8.1 rules 3 and 7; KAT MF7, MF9).

  python3 -I harness/forensics/lint.py --dataset forensics/r25 [--private DIR]
  exit 0 clean, 6 a finding

MF7 (missing values): in derived/, a value that is missing must be a string starting with one of MISSING_PREFIXES.
  null, '', NaN, a placeholder word ('n/a', 'unknown', 'none', '-', '?', 'tbd'), an all-zero 32-byte root, or a
  non-integer in a money/height field all FAIL.
MF9 (privacy): no DERO address, IP address, absolute home or temp path, URL or host name anywhere in the dataset's text
  files; plus the private terms (the source host map and our own address), which are read at run time from the
  private dir (mode 700, outside git) and never written into tracked files.
"""
import argparse, gzip, json, math, re, sys
from pathlib import Path

MISSING_PREFIXES = ('pending', 'missing', 'not reconstructable', 'not decidable', 'not applicable')
PLACEHOLDERS = {'n/a', 'na', 'unknown', 'none', 'null', '-', '--', '?', 'tbd', 'nan', 'undefined'}
NUM_OR_MISSING = {'fees', 'public_burns', 'full_reward', 'miniblock_share', 'integrator_leftover', 'fee',
                  'reward_ext', 'bl_tips_height', 'base_reward', 'supply_before', 'supply_after', 'height', 'topo'}
ROOT_KEYS = re.compile(r'(^|_)root($|_)|roothash')
ZERO32 = '0' * 64

PRIV_PATTERNS = [
    ('dero_address', re.compile(r'\bde[rt]oi?1[02-9ac-hj-np-z]{30,}')),
    ('ipv4', re.compile(r'(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])')),
    ('ipv6_hostport', re.compile(r'\[[0-9a-fA-F:]{3,}\]:\d+')),
    ('home_path', re.compile(r'/(?:Users|home)/[^/\s"\']+')),
    ('temp_path', re.compile(r'/private/(?:tmp|var)/|/var/folders/')),
    ('windows_path', re.compile(r'[A-Za-z]:\\\\?(?:Users|Documents)')),
    ('url', re.compile(r'\b(?:https?|wss?)://')),
    ('hostname', re.compile(r'\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:local|lan|home|internal)\b', re.I)),
]


def _walk(o, path, out):
    if o is None:
        out.append(f'{path}: null (a missing value must be a pending/missing string)')
    elif isinstance(o, float) and (math.isnan(o) or math.isinf(o)):
        out.append(f'{path}: {o} (non-finite number)')
    elif isinstance(o, str):
        s = o.strip()
        if s == '':
            out.append(f'{path}: empty string')
        elif s.lower() in PLACEHOLDERS:
            out.append(f'{path}: placeholder {s!r}')
    elif isinstance(o, dict):
        for k, v in o.items():
            p = f'{path}.{k}'
            if isinstance(k, str) and ROOT_KEYS.search(k) and isinstance(v, str) and v.lower() == ZERO32:
                out.append(f'{p}: all-zero root rendered as a value')
            if k in NUM_OR_MISSING and not (isinstance(v, int) and not isinstance(v, bool)) and not (
                    isinstance(v, str) and v.startswith(MISSING_PREFIXES)) and not isinstance(v, (dict, list)):
                out.append(f'{p}: {v!r} is neither an integer nor a pending/missing string')
            _walk(v, p, out)
    elif isinstance(o, list):
        for i, v in enumerate(o):
            _walk(v, f'{path}[{i}]', out)


def check_missing(obj, where='$'):
    out = []
    _walk(obj, where, out)
    return out


def text_files(ds):
    for p in sorted(Path(ds).rglob('*')):
        if not p.is_file() or 'blobs' in p.relative_to(ds).parts:
            continue
        if p.name.endswith('.gz'):
            yield p, gzip.decompress(p.read_bytes()).decode('utf-8', 'replace')
        elif p.suffix in ('.json', '.jsonl', '.md', '.txt', '.sha256', '.sh', '.csv'):
            yield p, p.read_text('utf-8', 'replace')


def json_docs(p, text):
    if p.name.endswith('.jsonl') or p.name.endswith('.jsonl.gz'):
        for n, l in enumerate(text.splitlines(), 1):
            if l.strip():
                yield f'{p.name}:{n}', json.loads(l)
    elif p.name.endswith('.json'):
        yield p.name, json.loads(text)


def private_terms(priv):
    """Hosts/IPs of the source map and our own address, read from the private dir (never from tracked files)."""
    terms = set()
    if priv is None or not Path(priv).is_dir():
        return terms
    for f in Path(priv).glob('*.json'):
        try:
            txt = f.read_text()
        except OSError:
            continue
        for m in re.finditer(r'(?:https?|wss?)://([^/:"\s]+)', txt):
            terms.add(m.group(1))
        for m in PRIV_PATTERNS[1][1].finditer(txt):
            terms.add(m.group(0))
        for m in PRIV_PATTERNS[0][1].finditer(txt):
            terms.add(m.group(0))
    terms = {t for t in terms if len(t) >= 7 and t not in ('127.0.0.1', '0.0.0.0', 'localhost')}
    return terms


def check_privacy(text, terms=(), where='?'):
    out = []
    for name, rx in PRIV_PATTERNS:
        m = rx.search(text)
        if m:
            out.append(f'{where}: {name} pattern found')
    for t in terms:
        if t in text:
            out.append(f'{where}: a private term (source host or own address) found')
            break
    return out


def scan(ds, priv=None):
    terms = private_terms(priv)
    mf7, mf9 = [], []
    for p, text in text_files(ds):
        rel = str(p.relative_to(ds))
        mf9 += check_privacy(text, terms, rel)
        if rel.startswith('derived/'):
            for where, doc in json_docs(p, text):
                mf7 += check_missing(doc, f'{rel}#{where}')
    return mf7, mf9, len(terms)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--dataset', required=True)
    ap.add_argument('--private', default=str(Path.home() / 'derohe-persist' / 'forensics_private'))
    a = ap.parse_args(argv)
    mf7, mf9, nt = scan(a.dataset, a.private)
    print(f'MF7 missing-value findings: {len(mf7)}; MF9 privacy findings: {len(mf9)} (private terms loaded: {nt})')
    for f in (mf7 + mf9)[:20]:
        print(' ', f)
    return 6 if mf7 or mf9 else 0


if __name__ == '__main__':
    sys.exit(main())
