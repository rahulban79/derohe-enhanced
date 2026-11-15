#!/usr/bin/env python3
"""doc_currency.py — r31 (rft §7 B332, the user 2026-11-14: "make sure such issues for other files are also fixed").

B331 found the public README's highlights frozen at Round 28 because nothing checked hand-written round summaries. This
tool checks every doc listed in harness/loop/DOC_CURRENCY.json: it must carry `<!-- doc-current-through: r<N> -->` and N
must be the newest MEASURED round of harness/round.json. A doc reviewed for an older round, or one without the marker,
fails with the exact update to make. Read-only.

  python3 -I harness/intel/doc_currency.py            # exit 0 all current · 5 a doc is behind · 2 unreadable
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):
    print(__doc__)
    raise SystemExit(0)
import json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
MARK = re.compile(r'<!-- doc-current-through: (r\d+[a-z]?) -->')


def newest_measured(reg):
    """the id of the last registry round with status measured, or None. Pure."""
    ids = [r['id'] for r in reg.get('rounds', []) if r.get('status') == 'measured']
    return ids[-1] if ids else None


def problems(docs, texts, want):
    """[(path, problem)] for every listed doc whose marker is missing or not `want`. Pure."""
    out = []
    for d in docs:
        t = texts.get(d['path'])
        if t is None:
            out.append((d['path'], 'missing file'))
            continue
        marks = MARK.findall(t)
        if not marks:
            out.append((d['path'], f'no doc-current-through marker: review it for {want} and add `<!-- doc-current-through: {want} -->`'))
        elif marks[-1] != want:
            out.append((d['path'], f'reviewed through {marks[-1]}, the newest measured round is {want}: add its changes, then set the marker to {want}'))
    return out


def main(root=ROOT):
    root = Path(root)
    try:
        reg = json.loads((root / 'harness/round.json').read_text())
        docs = json.loads((root / 'harness/loop/DOC_CURRENCY.json').read_text())['docs']
    except (OSError, ValueError, KeyError) as e:
        print(f'doc_currency: unreadable ({type(e).__name__})')
        return 2
    want = newest_measured(reg)
    texts = {d['path']: ((root / d['path']).read_text(encoding='utf-8') if (root / d['path']).is_file() else None) for d in docs}
    probs = problems(docs, texts, want)
    for p, why in probs:
        print(f'BEHIND {p}: {why}')
    print(f'doc_currency: {len(docs)} doc(s), newest measured round {want}, {len(probs)} behind · {"PASS" if not probs else "FAIL"}')
    return 0 if not probs else 5


if __name__ == '__main__':
    sys.exit(main())
