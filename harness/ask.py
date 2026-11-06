#!/usr/bin/env python3
"""ask.py — retrieval over the drawn rows, for the dero-miner-tuning skill and for the command line.

  python3 harness/ask.py "where is the block reward computed"
  python3 harness/ask.py --json "why are there no incoming peers"

It searches model/verified.json ONLY — the rows that survived the evidence contract — so an answer always comes
with the file and line that proves it, and anything the harness refused to claim can never be returned.
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):   # r27 B120: usage, exit 0, nothing run or written
    print(__doc__ or 'usage: see the header of this file')
    raise SystemExit(0)
import json, math, re, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
V = HERE / 'model/verified.json'
STOP = set('a an the of in on to for is are was were be been and or not with by at from it its this that '
           'what where why how which does do did can could should would will when who whom'.split())


def toks(s):
    return [w for w in re.findall(r'[a-z0-9_]+', str(s).lower()) if w not in STOP and len(w) > 1]


def main():
    as_json = '--json' in sys.argv
    q = ' '.join(a for a in sys.argv[1:] if not a.startswith('--'))
    if not q:
        print(__doc__)
        return 2
    rows = json.loads(V.read_text())
    qt = toks(q)
    if not qt:
        print('nothing to search for')
        return 2
    # idf over the corpus of rows, so a rare identifier outweighs a common English word
    df = {}
    docs = []
    for r in rows:
        body = ' '.join([str(r.get('title') or ''), str(r.get('claim') or ''), str(r.get('role') or ''),
                         str(r.get('impact') or ''), str(r.get('action') or ''), str(r.get('where') or ''),
                         ' '.join(f"{e['file']} {e['quote']}" for e in r['evidence'])])
        t = set(toks(body))
        docs.append((r, t, body))
        for w in t:
            df[w] = df.get(w, 0) + 1
    N = len(docs)
    scored = []
    for r, t, body in docs:
        s = sum(math.log(1 + N / df.get(w, N)) * (2.0 if w in str(r.get('title', '')).lower() else 1.0)
                for w in qt if w in t)
        if s > 0:
            scored.append((s, r, body))
    scored.sort(key=lambda x: -x[0])
    out = []
    for s, r, body in scored[:8]:
        e = r['evidence'][0]
        out.append({'score': round(s, 2), 'id': r['id'], 'section': r.get('page_section'), 'class': r['class'],
                    'title': r.get('title'), 'claim': (r.get('claim') or '')[:400],
                    'where': f"{e['file']}:{e.get('line')}", 'quote': (e.get('quote') or '')[:160]})
    if as_json:
        print(json.dumps(out, indent=1))
    elif not out:
        print(f'no drawn row matches {q!r}. The harness may have refused to claim it — see loop/UNVERIFIED.md.')
    else:
        for o in out:
            print(f"[{o['score']:>5}] {o['class']:<8} {o['title']}")
            print(f"         {o['claim'][:200]}")
            print(f"         {o['where']}  —  {o['quote'][:110]}\n")
    return 0


if __name__ == '__main__':
    sys.exit(main())
