#!/usr/bin/env python3
"""mine_localdiff.py — what this tree does that upstream Release153 does not.

`git diff Release153..HEAD` is the ground truth. For every changed first-party Go file the miner takes the
longest added line that is still present in the working tree and anchors on it, so a row disappears the moment
the change is reverted. Doc-only and experiment-only paths are listed separately: they change no behaviour.
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):   # r27 B120: usage, exit 0, nothing run or written
    print(__doc__ or 'usage: see the header of this file')
    raise SystemExit(0)
import re, subprocess, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import minelib as M

BASE = 'Release153'
EXPERIMENT = ('cmd/_', 'gpu-miner-poc/', 'harness/', 'artifacts/')
DOCS = ('.md', '.html', '.svg', '.json', '.txt', '.sh')


def git(*a):
    return subprocess.run(['git', *a], cwd=M.ROOT, capture_output=True, text=True).stdout


SEG_WINDOW = 40          # lines: the working tree may sit a little off HEAD; farther than this is another place


def hunk_segments(diff):
    """[[(new_line, added_text)]]: every hunk of a -U0 diff, split at each added top-level func (R23: a modified file's
    new funcs joined an earlier func's hunk and a longer comment took its only citation). Pure."""
    segs = []
    for m in re.finditer(r'(?m)^@@ -\S+ \+(\d+)(?:,\d+)? @@.*\n((?:(?!@@).*(?:\n|$))*)', diff):
        ln, cur = int(m.group(1)), []
        for l in m.group(2).splitlines():
            if not l.startswith('+') or l.startswith('+++'):
                continue
            if l.startswith('+func ') and cur:
                segs.append(cur)
                cur = []
            cur.append((ln, l[1:].strip()))
            ln += 1
        if cur:
            segs.append(cur)
    return segs


def near_in(f):
    """the resolver cite_segment uses: the occurrence of a candidate nearest its own line, within SEG_WINDOW"""
    return lambda cand, ln: M.anchor_near(f, cand, ln, window=SEG_WINDOW)


def cite_segment(seg, near, long_enough):
    """the citation for one segment: its func declaration first when it starts at one (its longest line may be the
    doc comment of the NEXT func), else its longest lines; each candidate resolved NEAR its own line by `near(text,
    line)` (None when not within the window). Pure."""
    first = [seg[0]] if seg and seg[0][1].startswith('func ') else []
    for ln, cand in first + sorted(seg, key=lambda x: len(x[1]), reverse=True):
        if not long_enough(cand):
            continue
        h = near(cand, ln)
        if h:
            return h
    return None


def main():
    rows, unv = [], []
    changed = [l.split('\t') for l in git('diff', '--name-status', BASE, 'HEAD').splitlines() if '\t' in l]
    go_mod = [(st, f) for st, f in changed if f.endswith('.go') and not f.startswith(EXPERIMENT)]
    other = [(st, f) for st, f in changed if (st, f) not in go_mod]

    for st, f in sorted(go_mod):
        diff = git('diff', '-U0', BASE, 'HEAD', '--', f)
        added = [l[1:] for l in diff.splitlines() if l.startswith('+') and not l.startswith('+++')]
        removed = [l[1:] for l in diff.splitlines() if l.startswith('-') and not l.startswith('---')]
        # anchor on the longest added line that is still in the working tree
        a = None
        for cand in sorted(added, key=len, reverse=True):
            cand = cand.strip()
            if len(M.norm(cand)) < M.MIN_Q:
                continue
            a = M.anchor(f, cand, full_line=True)
            if a:
                break
        if not a:
            unv.append({'title': f, 'why': f'{len(added)} added line(s) in the diff, none of them still present '
                                           f'verbatim in the working tree — the change was later rewritten'})
            continue
        # one more anchor per hunk: with only the file's longest added line, a later, longer comment elsewhere in the
        # file moved the sole citation out of the function an earlier hunk changed (G16 lost feed_chunk, r15)
        ev = [a]
        # R23b: each candidate is cited NEAR its own new-file line (anchor_near, window SEG_WINDOW): anchor() takes the
        # first occurrence in the file, so a repeated added line ('cpu_throttle(&throttle_start)', 'show_page(w, r, 0)')
        # cited a copy outside its own hunk segment: 39 of 2,924 segment citations on c7ded01, each one crediting G16's
        # coverage to a function the hunk did not touch
        for seg in hunk_segments(diff):
            h = cite_segment(seg, near_in(f), lambda s: len(M.norm(s)) >= M.MIN_Q)
            if h and all((h.get('file'), h.get('line')) != (e.get('file'), e.get('line')) for e in ev):
                ev.append(h)
        log = [l for l in git('log', '--format=%h\t%s', f'{BASE}..HEAD', '--', f).splitlines() if l]
        commits = [l.split('\t')[0] for l in log]
        subjects = [l.split('\t', 1)[1] for l in log if '\t' in l]
        rows.append({'id': 'loc-' + re.sub(r'[^a-z0-9]+', '-', f.lower()).strip('-'), 'section': 'local',
                     'title': f, 'class': 'SRC',
                     'claim': (f'{"New file" if st == "A" else "Modified"} relative to upstream {BASE}: '
                               f'+{len(added)} / -{len(removed)} lines across {len(commits)} commit(s). '
                               + (subjects[0] if subjects else '')),
                     'path': f, 'status': 'added' if st == 'A' else 'modified', 'added': len(added),
                     'removed': len(removed), 'commits': commits, 'subject': subjects[0] if subjects else '',
                     'evidence': ev})

    sys.path.insert(0, str(M.HARNESS))
    import prep_corpus as PC
    unplaceable = []
    for st, f in sorted(other):
        if PC.class_of(M.ROOT / f) is None:          # outside every evidence root: it can prove nothing
            unplaceable.append(f)
            continue
        kind = ('external document' if f.startswith('harness/external/') else
                'experiment' if f.startswith(EXPERIMENT) else
                'documentation' if f.endswith(DOCS) else 'other')
        a = M.anchor(f, (Path(M.ROOT / f).read_text(errors='replace').splitlines() or [''])[0].strip(), full_line=True) \
            if (M.ROOT / f).exists() else None
        if not a:
            continue
        rows.append({'id': 'oth-' + re.sub(r'[^a-z0-9]+', '-', f.lower()).strip('-'), 'section': 'local-other',
                     'title': f, 'class': PC.class_of(M.ROOT / f),
                     'claim': (f'Third-party statement quoted under audit: what it says is attributed to its author '
                               f'(the Foundation), never asserted by this tree; added on top of {BASE}, it changes no '
                               f'shipped behaviour.' if kind == 'external document' else
                               f'{kind.capitalize()} added on top of {BASE}; it changes no shipped behaviour.'),
                     'path': f, 'kind': kind, 'evidence': [a]})

    # the commit ledger itself
    for l in git('log', '--format=%h\t%an\t%s', f'{BASE}..HEAD').splitlines():
        h, an, subj = l.split('\t', 2)
        files = [x for x in git('show', '--name-only', '--format=', h).splitlines() if x]
        code = [x for x in files if x.endswith('.go') and not x.startswith(EXPERIMENT)]
        rows.append({'id': f'commit-{h}', 'section': 'commits', 'title': h, 'class': 'HARNESS',
                     'claim': f'{subj} — {len(files)} file(s), {len(code)} of them shipped Go source.',
                     'sha': h, 'subject': subj, 'files': len(files), 'code_files': len(code),
                     'evidence': [M.anchor('RUN_REPORT.md', h) or M.anchor('ARCHITECTURE.md', h)
                                  or {'file': 'RUN_REPORT.md', 'quote': '', 'line': 0}]})
    if unplaceable:
        unv.append({'title': f'{len(unplaceable)} path(s) added on top of {BASE} that sit outside every evidence root',
                    'why': 'the class vocabulary can place a line only under the first-party tree, vendor/, '
                           'harness/runtime/, the project docs, the skills or the memory store; these are the GPU '
                           'proof-of-concept tree and loose session files, which no binary links and no class covers: '
                           + ', '.join(sorted(unplaceable)[:6]) + (' …' if len(unplaceable) > 6 else '')})
    rows = [r for r in rows if r['evidence'][0].get('line')]
    M.emit('localdiff', rows, unv, 'mine_localdiff.py')


if __name__ == '__main__':
    main()
