#!/usr/bin/env python3
"""minelib.py — shared anchor machinery for the DERO miners.

A miner never writes a claim it cannot anchor. `anchor()` returns an evidence entry only when the needle is
found verbatim on one line of the file (whitespace runs normalised, >= MIN_Q characters after normalisation);
otherwise it returns None and the caller must route the item to `unverified` instead of `rows`.
"""
import json, os, re, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent
ROOT = HARNESS.parent
RAW = HARNESS / 'model/raw'
CORPUS = HARNESS / 'corpus'
MIN_Q = 12
TYPO = str.maketrans({'‘': "'", '’': "'", '“': '"', '”': '"', '–': '-', '—': '-',
                      ' ': ' ', '…': '...'})
_CACHE = {}


def norm(s):
    return re.sub(r'\s+', ' ', str(s or '').translate(TYPO)).strip()


def lines(rel):
    """Raw and normalised lines of a repo-relative (or absolute) path."""
    p = Path(rel) if Path(rel).is_absolute() else ROOT / rel
    if p not in _CACHE:
        try:
            raw = p.read_text(errors='replace').splitlines()
        except OSError:
            raw = None
        _CACHE[p] = (raw, [norm(l) for l in raw] if raw is not None else None)
    return _CACHE[p]


def find(rel, needle, hint=None):
    """Line numbers (1-based) whose normalised text contains the normalised needle."""
    n = norm(needle)
    if len(n) < MIN_Q:
        return []
    raw, nl = lines(rel)
    if nl is None:
        return []
    hits = [i + 1 for i, l in enumerate(nl) if n in l]
    if hint and hint in hits:
        return [hint] + [h for h in hits if h != hint]
    return hits


def anchor(rel, needle, hint=None, full_line=False):
    """One evidence entry, or None when the needle is not on a line of that file."""
    hits = find(rel, needle, hint)
    if not hits:
        return None
    raw, _ = lines(rel)
    q = raw[hits[0] - 1].strip() if full_line else str(needle)
    if len(norm(q)) < MIN_Q:
        q = raw[hits[0] - 1].strip()
    return {'file': str(rel), 'quote': q, 'line': hits[0], 'occ': len(hits)}


def anchor_near(rel, needle, hint, window=400, full_line=True):
    """The occurrence of `needle` nearest to `hint`; used when a symbol repeats across a big file."""
    hits = find(rel, needle)
    if not hits:
        return None
    best = min(hits, key=lambda h: abs(h - hint)) if hint else hits[0]
    if hint and abs(best - hint) > window:
        return None
    raw, _ = lines(rel)
    return {'file': str(rel), 'quote': raw[best - 1].strip() if full_line else str(needle), 'line': best, 'occ': len(hits)}


def grep(rel, pattern, flags=0):
    """[(lineno, raw_line)] for a regex over one file."""
    raw, _ = lines(rel)
    if raw is None:
        return []
    rx = re.compile(pattern, flags)
    return [(i + 1, l) for i, l in enumerate(raw) if rx.search(l)]


def go_files(pkg, tests=False):
    out = []
    for dp, dn, fn in os.walk(ROOT / pkg):
        dn[:] = [d for d in dn if d not in {'.git', 'vendor', '__pycache__'}]
        for f in sorted(fn):
            if f.endswith('.go') and (tests or not f.endswith('_test.go')):
                out.append(str((Path(dp) / f).relative_to(ROOT)))
    return sorted(out)


CORPUS_HINT = 'run `python3 -I harness/prep_corpus.py` first (it writes the untracked symbol table harness/corpus/tags.tsv)'


def tags_text():
    """the text of corpus/tags.tsv. r28 (tools-kats): the file is untracked (.gitignore), so a fresh clone has none.
    tags() used to return [] then: mine_inventory routed 4 packages to unverified with the wrong reason ('no package
    clause found to anchor on': 111 rows / 7 unverified vs 115 / 3 after prep_corpus, the R27 order note blamed the
    tracked pkgindex), and mine_coverage died with a FileNotFoundError traceback. A missing table now stops the miner
    with exit 2 and the fix, before it writes anything."""
    p = CORPUS / 'tags.tsv'
    if not p.exists():
        print(f'{Path(sys.argv[0]).name}: {p.relative_to(ROOT) if ROOT in p.parents else p} is missing: {CORPUS_HINT}',
              file=sys.stderr)
        raise SystemExit(2)
    return p.read_text()


def tags():
    """corpus/tags.tsv → [(name, file, line, kind, pkg)]; exit 2 when the table was never built (tags_text)"""
    out = []
    for l in tags_text().splitlines():
        parts = l.split('\t')
        if len(parts) == 5:
            out.append((parts[0], parts[1], int(parts[2]), parts[3], parts[4]))
    return out


def pkgindex():
    return json.loads((CORPUS / 'pkgindex.json').read_text())


def emit(key, rows, unverified=None, generated_by=None):
    """Write model/raw/<key>.json. r24: every non-reserved IPv4 in every string is pseudonymised first
    (kit/privkit.py: 'peer-' + 8 hex, the peer observatory's salt), so no tracked raw file, verified.json or
    dero-src-arch.html carries a peer address; an anchor quote still resolves through privkit.mask."""
    RAW.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(HARNESS / 'kit'))
    import privkit
    salt = privkit.load_salt()
    rows = privkit.pseudonymise_obj(rows, salt)
    unverified = privkit.pseudonymise_obj(unverified or [], salt)
    doc = {'key': key, 'generated_by': generated_by or Path(sys.argv[0]).name,
           'rows': rows, 'unverified': unverified or []}
    (RAW / f'{key}.json').write_text(json.dumps(doc, indent=1, ensure_ascii=False))
    print(f'{key}.json: {len(rows)} rows, {len(doc["unverified"])} unverified')
    return doc
