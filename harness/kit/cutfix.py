#!/usr/bin/env python3
"""cutfix — find and fix SILENT text cuts in a page generator (the textkit rule: never cut a sentence without its tooltip).

A silent cut is a slice of display text — `esc(x[:120])` — that drops the rest with no "…", no tooltip and no marker. The
reader cannot tell anything is missing. textkit's G11 only sees cuts that print "…"; this tool sees the ones that do not.

  python3 cutfix.py lint  FILE.py          list every esc(<expr>[:N]) site (display slices) — exit 3 when any remain
  python3 cutfix.py fix   FILE.py [--fn NAME] [--min N]
        rewrite each esc(<expr>[:N]) into NAME(<expr>, N)   (default NAME = _clip, i.e. textkit.html_clip:
        the full text becomes the title tooltip, the visible text ends "…ⓘ"); slices shorter than --min (default 20)
        are left alone, because they are formats, not cuts (dates [:10], timestamps [:16], hash prefixes [:12])
        — add them by hand where they ARE cuts. The generator must define NAME (e.g. `_clip = textkit.html_clip`).
Only `esc(...)` wrappers are touched, so a slice used for logic (a fingerprint, a comparison) is never rewritten.
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):   # r27 B120: usage, exit 0, nothing run or written
    print(__doc__ or 'usage: see the header of this file')
    raise SystemExit(0)
import re
import sys
from pathlib import Path

# 2026-10-19: every display-escape wrapper used by this repo's generators, not only esc( — the ARD generator's `E(line[:140])`
# was a silent cut this lint could not see (a generator's escape helper is often a one-letter lambda)
WRAPPERS = ('esc', 'E', 'md', 'md_inline', '_esc', 'html.escape', '_html.escape')
ESC = re.compile(r'(?<![\w.])(?:' + '|'.join(re.escape(w) for w in WRAPPERS) + r')\(')


def _match(s, i):
    """index of the bracket closing the one at s[i] (strings and nesting aware)"""
    pair = {'(': ')', '[': ']', '{': '}'}
    st, q, k = [pair[s[i]]], None, i + 1
    while k < len(s) and st:
        c = s[k]
        if q:
            if c == '\\':
                k += 2
                continue
            if c == q:
                q = None
        elif c in '"\'':
            q = c
        elif c in pair:
            st.append(pair[c])
        elif c == st[-1]:
            st.pop()
        k += 1
    return k - 1 if not st else -1


def sites(src):
    """(start, end, expr, n) for every esc(<expr>[:N]) whose argument ENDS in a [:N] slice"""
    out = []
    for m in ESC.finditer(src):
        o = m.end() - 1
        c = _match(src, o)
        if c < 0:
            continue
        arg = src[o + 1:c]
        mm = re.search(r'\[:(\d+)\]\s*$', arg)
        if not mm:
            continue
        expr = arg[:mm.start()].rstrip()
        # the slice must apply to the WHOLE argument expression (not to an inner name inside a larger expression)
        if expr.endswith(')') or expr.endswith(']'):
            ob = {')': '(', ']': '['}[expr[-1]]
            depth, j = 0, len(expr) - 1
            while j >= 0:
                if expr[j] in ')]':
                    depth += 1
                elif expr[j] in '([':
                    depth -= 1
                    if depth == 0:
                        break
                j -= 1
            head = expr[:j]
            if re.search(r'[+\-*/%,]|\bif\b|\bor\b|\band\b', re.sub(r'(["\']).*?\1', '', head)):
                continue
        elif re.search(r'[\s+\-*/%,]', expr):
            continue
        ls = src.rfind('\n', 0, m.start()) + 1
        if src[ls:m.start()].lstrip().startswith('#'):
            continue                                   # inside a comment
        out.append((m.start(), c + 1, expr, int(mm.group(1))))
    return out


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd, f = argv[0], Path(argv[1])
    src = f.read_text()
    found = sites(src)
    if cmd == 'lint':
        for a, b, expr, n in found:
            ln = src.count('\n', 0, a) + 1
            print(f'{f.name}:{ln}: {src[a:src.index("(", a)]}({expr[:70]}[:{n}])')
        print(f'[cutfix] {f.name}: {len(found)} display slice(s)')
        return 3 if found else 0
    if cmd == 'fix':
        fn = argv[argv.index('--fn') + 1] if '--fn' in argv else '_clip'
        mn = int(argv[argv.index('--min') + 1]) if '--min' in argv else 20
        done = 0
        for a, b, expr, n in sorted(found, reverse=True):
            if n < mn:
                continue
            src = src[:a] + f'{fn}({expr}, {n})' + src[b:]
            done += 1
        f.write_text(src)
        left = [x for x in sites(src)]
        print(f'[cutfix] {f.name}: rewrote {done} esc(..[:N]) site(s) to {fn}(.., N); {len(left)} short format slice(s) left for review')
        return 0
    print(__doc__)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
