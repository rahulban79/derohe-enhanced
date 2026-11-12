#!/usr/bin/env python3
"""coherence_audit.py — r30 (rft §6 step 22a, §2.20, §7 B205): every new file of a round is reached by the project's
instruments.

The user's R30 rule (§2.20): "make sure all the project harness, tools, KAT suites, dero-frt, pipelines - everything is
updated and used for all these tasks super cohorently". Until R30 the check was a merge checklist item. This tool lists
every file the round's commits ADD (`git diff --name-only --diff-filter=A <base>..<head>`, base = the current round's
new_tests_base in harness/round.json) and classifies each:

  kat         harness/kat/test_*.py: registered = in some harness/areas.json kat_files AND a STEP_BUDGETS step row
              (the pipeline S7 runs every test_*.py; an unregistered KAT is run but owned by no area and unbudgeted)
  gotest      *_test.go: registered = at least one of its Test*/Fuzz* names is in fix_build_verify.py NEW_TESTS
  code        any other .py / .go / .sh: reached = named IN CODE (r30 verify D2: a Python import of its module stem, or
              its path / file name / Go package directory inside a string literal: path strings, `python3 … path`
              argv, fix_build_verify step lists; a JSON registry entry; shell / Go code outside comments; a docstring,
              a comment or a bare word in prose never counts) by a ROOT (a registered KAT, harness/run_gates.py,
              harness/pipeline/fix_build_verify.py, harness/intel/go_mutations.json, harness/areas.json,
              harness/loop/STEP_BUDGETS.json, a generator: artifacts/src/*.py, harness/gen_*.py, harness/miners/*.py)
              or by another reached code file (fixed point); a Go file of a package with a NEW_TESTS key is reached
  page        artifacts/*.html|*.pdf|*.md: reached when a generator names its stem up to the round digits
  frozen      artifacts/src/frozen/**: reached when a generator names 'frozen'
  record      harness/runtime/**, forensics/**: reached when a tracked tool names its family (the name before the
              _<stamp>) or the record's path; else 'cited' when artifacts/dero-rft.md names it (report-only); else WARN
  doc         *.md elsewhere, .skills/**, memory-mirror/**: no reach needed
  data        anything else: reached when any tracked tool or registry names it; else WARN

Literal figures (§6 step 22a "a hand-typed literal figure on a generated page"): an ADDED line of a generator file
(artifacts/src/*.py, harness/gen_*.py) whose string literal holds a measured-looking figure (a thousands-grouped number,
a decimal with a unit: H/s, kH/s, %, s, ms, MB, GB, DERO, cores; r30 verify D3: an integer hash rate '94273 H/s', an
integer percentage '95 %', a k/M-suffixed figure with a unit '96k H/s') FAILS unless the line carries `# literal-ok: <why>`
(a figure the generator states by definition, e.g. a protocol constant). The dc1-two-bodies literal (B202) was such a
figure: no generator computed it.

Decision log (r30, rft §0.12, user §2.23): every row `| D-<n> | date | question | options | choice | why best for
quality | evidence anchors | re-check |` of artifacts/dero-rft.md §0.12 needs at least one evidence anchor that resolves
(a backticked repo path that exists, a backticked `~/…` path that exists, or a §N[.M] section of the rft) and a
non-empty "why best for quality" cell; an anchor that does not resolve is reported with the row. A decision with no
evidence is a FAIL (the rule: decide from harness, tool and intel evidence, never from conversation memory).

FAIL classes: orphan tool (code not reached), unregistered KAT (kat / gotest), literal figure, decision without an
evidence anchor. WARN: unreferenced record / data (report-only).

  python3 -I harness/intel/coherence_audit.py [--root DIR] [--base REV] [--head REV] [--json] [--record]
      --record writes harness/runtime/<round>_coherence_audit.txt (the §6 step 22a list)
Exit 0 coherent · 4 a FAIL class found · 2 unreadable registry / bad revision.
"""
import argparse, ast, io, json, re, subprocess, sys, tokenize
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
CODE_SUFFIX = ('.py', '.go', '.sh')
# r30 verify D3: also an integer hash rate ('94273 H/s'), an integer percentage ('95 %'; not a CSS value 'w:100%') and
# a k/M-suffixed figure with a unit ('96k H/s', '1.2M DERO')
FIGURE_RX = re.compile(r'''(?<![\w.#/-])(?:\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+\.\d+\s?(?:kH/s|H/s|H/cpu-s|%|ms|s\b|MB|GB|GiB|MiB|DERO|cores?\b)'''
                       r'''|\d+(?:\.\d+)?\s?[kM]\s?(?:H/s|H/cpu-s|DERO|MB|GB)|\d+\s?(?:kH/s|H/s|H/cpu-s)|(?<!:)(?<!: )\d+\s?%)''')
STRING_RX = re.compile(r'''(?:[rbfu]{0,2})("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')''', re.I)
STAMP_RX = re.compile(r'^(?P<fam>.+?)_\d{8}(?:T\d{6}Z?)?')
OK_MARK = 'literal-ok:'


def git(root, *a):
    r = subprocess.run(['git', '-C', str(root), *a], capture_output=True, text=True, timeout=120)
    if r.returncode:
        raise RuntimeError(f"git {' '.join(a[:2])}: {r.stderr.strip()[:160]}")
    return r.stdout


def round_base(root):
    reg = json.loads((Path(root) / 'harness/round.json').read_text())
    cur = next(r for r in reg['rounds'] if r['id'] == reg['current'])
    return reg['current'], cur.get('new_tests_base')


def kat_registry(root):
    """(set of kat_files over every area, set of STEP_BUDGETS step keys)."""
    areas = json.loads((Path(root) / 'harness/areas.json').read_text())
    kf = {f for a in areas.get('areas', []) for f in a.get('kat_files', [])}
    sb = Path(root) / 'harness/loop/STEP_BUDGETS.json'
    steps = set(json.loads(sb.read_text()).get('steps', {})) if sb.exists() else set()
    return kf, steps


def go_test_names(text):
    return re.findall(r'(?m)^func\s+((?:Test|Fuzz)\w+)\s*\(', text)


def new_tests_text(root):
    p = Path(root) / 'harness/pipeline/fix_build_verify.py'
    return p.read_text(errors='replace') if p.exists() else ''


def new_tests_pkgs(text):
    return set(re.findall(r"'(\./[\w./-]*/)'\s*:", text))


def classify(rel):
    p = Path(rel)
    if rel.startswith('harness/kat/') and p.name.startswith('test_') and p.suffix == '.py':
        return 'kat'
    if p.name.endswith('_test.go'):
        return 'gotest'
    if rel.startswith('artifacts/src/frozen/'):
        return 'frozen'
    if rel.startswith(('harness/runtime/', 'forensics/')):
        return 'record'
    if rel.startswith('artifacts/') and p.parent == Path('artifacts') and p.suffix in ('.html', '.pdf', '.md'):
        return 'page'
    if p.suffix in CODE_SUFFIX:
        return 'code'
    if p.suffix == '.md' or rel.startswith(('.skills/', 'memory-mirror/')):
        return 'doc'
    return 'data'


def generators(files):
    return [f for f in files if (f.startswith('artifacts/src/') and f.endswith('.py') and '/frozen/' not in f)
            or re.match(r'harness/gen_\w+\.py$', f) or re.match(r'harness/miners/\w+\.py$', f)]


def names_of(rel):
    """the strings by which a file can be named by another one: its path, file name, Python module stem. Pure."""
    p = Path(rel)
    out = {rel, p.name}
    if p.suffix == '.py' and len(p.stem) > 3:
        out.add(p.stem)
    if p.suffix == '.go':
        out.add(str(p.parent) + '/')
    return out


def mentions(text, name):
    """`name` (a path, file name or package dir) as a whole token of `text`: 'census.py' is not in 'payout_census.py'.
    Pure."""
    return re.search(r'(?<![\w-])' + re.escape(name) + (r'(?![\w])' if not name.endswith('/') else ''), text) is not None


def _json_strings(v, out):
    if isinstance(v, dict):
        for k, x in v.items():
            out.append(str(k))
            _json_strings(x, out)
    elif isinstance(v, list):
        for x in v:
            _json_strings(x, out)
    elif isinstance(v, str):
        out.append(v)
    return out


def _py_refs(text):
    """(string literals, imported module names) of Python source; docstrings (a bare string statement) and comments
    are not code and are left out. None when the source does not parse."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return None
    doc = {id(n.value) for n in ast.walk(tree) if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)}
    strs, mods = [], set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in doc:
            strs.append(n.value)
        elif isinstance(n, ast.Import):
            for a in n.names:
                mods.update(a.name.split('.'))
        elif isinstance(n, ast.ImportFrom):
            mods.update((n.module or '').split('.'))
            mods.update(a.name for a in n.names)
    return strs, mods


def _strip_comments(rel, text):
    """`text` without its comments: '#' comments of a shell / Python file (a '#' that starts a word), '//' and
    '/* */' of a Go file. Pure."""
    if rel.endswith('.go'):
        return re.sub(r'(?m)//.*$', '', re.sub(r'/\*.*?\*/', '', text, flags=re.S))
    if rel.endswith('.py'):
        try:
            toks = [t for t in tokenize.generate_tokens(io.StringIO(text).readline) if t.type != tokenize.COMMENT]
            return tokenize.untokenize(toks)
        except (tokenize.TokenError, IndentationError, SyntaxError):
            pass
    return re.sub(r'(?m)(^|\s)#.*$', r'\1', text)


def code_refs(rel, text):
    """(code texts, imported module names) of one referrer: r30 verify D2, a reach counts only from CODE, never from a
    word in prose. Python: its string literals (path strings, `python3 … path` argv, fix_build_verify step lists)
    and its imports, docstrings and comments left out; JSON registries (areas.json, STEP_BUDGETS.json,
    go_mutations.json): every key and string value; shell / Go: the text without comments; anything else: none.
    Pure."""
    if rel.endswith('.json'):
        try:
            return _json_strings(json.loads(text), []), set()
        except ValueError:
            return [text], set()
    if rel.endswith('.py'):
        r = _py_refs(text)
        if r is not None:
            return r
        return [_strip_comments(rel, text)], set()
    if rel.endswith(('.sh', '.go')):
        return [_strip_comments(rel, text)], set()
    return [], set()


def reaches(refs, rel):
    """True when a referrer's code_refs name `rel`: its path, file name or (Go) package directory in a code string,
    or (Python) its module stem as an import. Pure."""
    strs, mods = refs
    p = Path(rel)
    if p.suffix == '.py' and p.stem in mods:
        return True
    return any(mentions(t, n) for t in strs for n in names_of(rel) if n != p.stem)


def literal_figures(root, base, head, gens):
    """[(file, line no, figure)] of the generator lines the range adds with a figure in a string literal."""
    out = []
    if not gens:
        return out
    diff = git(root, 'diff', '-U0', f'{base}..{head}', '--', *gens)
    cur, ln = None, 0
    for line in diff.splitlines():
        if line.startswith('+++ '):
            cur = line[6:] if line.startswith('+++ b/') else None
        elif line.startswith('@@'):
            m = re.search(r'\+(\d+)', line)
            ln = int(m.group(1)) if m else 0
        elif line.startswith('+') and cur:
            code = line[1:]
            if OK_MARK not in code and not code.lstrip().startswith('#'):
                for s in STRING_RX.findall(code.split('  # ')[0]):
                    m = FIGURE_RX.search(s)
                    if m:
                        out.append((cur, ln, m.group(0)))
                        break
            ln += 1
    return out


def audit(root, base, head='HEAD'):
    root = Path(root)
    added = [l for l in git(root, 'diff', '--name-only', '--diff-filter=A', f'{base}..{head}').splitlines() if l]
    tracked = [l for l in git(root, 'ls-files').splitlines() if l]
    kf, steps = kat_registry(root)
    nt = new_tests_text(root)
    nt_pkgs = new_tests_pkgs(nt)
    gens = generators(tracked)
    read = {}

    def text(f):
        if f not in read:
            try:
                read[f] = (root / f).read_text(errors='replace')
            except OSError:
                read[f] = ''
        return read[f]

    roots = [f for f in tracked if f in kf] + ['harness/run_gates.py', 'harness/pipeline/fix_build_verify.py',
                                              'harness/intel/go_mutations.json', 'harness/areas.json',
                                              'harness/loop/STEP_BUDGETS.json'] + gens
    refs = {}

    def refs_of(r):
        if r not in refs:
            refs[r] = code_refs(r, text(r))
        return refs[r]
    rows = {}
    for f in added:
        c = classify(f)
        if c == 'kat':
            miss = [w for w, ok in (('areas.json kat_files', f in kf), ('STEP_BUDGETS row', f in steps)) if not ok]
            rows[f] = (c, 'FAIL', 'unregistered KAT: no ' + ' / '.join(miss)) if miss else (c, 'ok', 'registered KAT')
        elif c == 'gotest':
            names = go_test_names(text(f))
            hit = [n for n in names if re.search(r'(?<![\w])' + n + r'(?![\w])', nt)]
            rows[f] = (c, 'ok', f'NEW_TESTS {hit[0]}') if hit else (
                c, 'FAIL', f'unregistered KAT: none of {len(names)} test name(s) in NEW_TESTS')
        elif c == 'page':
            stem = re.sub(r'\d+[a-z]?$', '', Path(f).stem)
            g = next((x for x in gens if stem in text(x)), None)
            rows[f] = (c, 'ok', f'generator {g}') if g else (c, 'WARN', 'no generator names it')
        elif c == 'frozen':
            g = next((x for x in gens if 'frozen' in text(x)), None)
            rows[f] = (c, 'ok', f'generator {g}') if g else (c, 'WARN', 'no generator reads frozen inputs')
        elif c == 'doc':
            rows[f] = (c, 'ok', 'document')
        else:
            rows[f] = (c, None, None)
    # code: fixed point from the roots
    reached = {r: 'root' for r in roots if r in tracked or (root / r).exists()}
    pending = [f for f, v in rows.items() if v[0] == 'code']
    for f in pending:
        if f.endswith('.go') and ('./' + str(Path(f).parent) + '/') in nt_pkgs:
            reached[f] = 'NEW_TESTS package ./' + str(Path(f).parent) + '/'
    changed = True
    while changed:
        changed = False
        for f in pending:
            if f in reached:
                continue
            for r in list(reached):
                if r != f and reaches(refs_of(r), f):
                    reached[f] = r
                    changed = True
                    break
    for f in pending:
        rows[f] = ('code', 'ok', f'reached via {reached[f]}') if f in reached else ('code', 'FAIL', 'orphan tool: no KAT, gate, pipeline step or generator reaches it')
    # records and data: named by any tracked tool (records by family), else cited by the rft
    tools = [t for t in tracked if t.endswith(CODE_SUFFIX) or t in ('harness/areas.json', 'harness/round.json')]
    rft = text('artifacts/dero-rft.md')
    for f, v in list(rows.items()):
        if v[1] is not None:
            continue
        p = Path(f)
        m = STAMP_RX.match(p.name)
        keys = [f, p.name] + ([m.group('fam') + '_'] if m and v[0] == 'record' else [])
        w = next((t for t in tools if t != f and any(k in text(t) for k in keys)), None)
        if w:
            rows[f] = (v[0], 'ok', f'named by {w}')
        elif f in rft or p.name in rft:
            rows[f] = (v[0], 'ok', 'cited by artifacts/dero-rft.md')
        else:
            rows[f] = (v[0], 'WARN', 'unreferenced (no tool, registry or rft names it)')
    lits = literal_figures(root, base, head, [g for g in gens if (root / g).exists()])
    return rows, lits


DECISION_HEAD = '### 0.12 Decision log'
DECISION_COLS = 8
ANCHOR_RX = re.compile(r'`([^`]+)`')
SECTION_RX = re.compile(r'§(\d+(?:\.\d+)*[a-z]?)')


def section_exists(rft, num):
    """§N or §N.M names a heading ('## N.', '### N.M') or a bold paragraph ('**N.M ') of the rft. Pure."""
    return bool(re.search(r'^(?:#{2,4} |\*\*)' + re.escape(num) + r'[.\s*]', rft, re.M))


def decision_problems(rft, root):
    """[(id, problem or None)] for each row of the rft §0.12 decision log (r30, user §2.23). A row needs >= 1 resolving
    evidence anchor and a 'why best for quality' cell. Pure apart from file-existence checks under `root` / home."""
    i = rft.find('\n' + DECISION_HEAD)
    if i < 0:
        return []
    body = rft[i + 1:]
    m = re.search(r'^#{2,3} ', body[len(DECISION_HEAD):], re.M)
    body = body[:len(DECISION_HEAD) + m.start()] if m else body
    out = []
    for line in body.splitlines():
        if not line.startswith('| D-'):
            continue
        cells = [c.strip() for c in line.strip().strip('|').split(' | ')]
        did = cells[0]
        if len(cells) != DECISION_COLS:
            out.append((did, f'{len(cells)} cells, want {DECISION_COLS}'))
            continue
        why, anchors = cells[5], cells[6]
        if not why or why in ('-', '—'):
            out.append((did, 'no "why best for quality"'))
            continue
        good, bad = [], []
        for a in ANCHOR_RX.findall(anchors):
            path = a.split(':')[0].split(' ')[0].split('#')[0]
            f = Path(path).expanduser() if path.startswith('~') else Path(root) / path
            (good if path and f.exists() else bad).append(a)
        for num in SECTION_RX.findall(anchors):
            (good if section_exists(rft, num) else bad).append('§' + num)
        if not good:
            out.append((did, 'no evidence anchor resolves' + (f' (unresolved: {", ".join(bad[:3])})' if bad else '')))
        else:
            out.append((did, None))
    return out


def report(rows, lits):
    fails = [(f, v) for f, v in rows.items() if v[1] == 'FAIL']
    warns = [(f, v) for f, v in rows.items() if v[1] == 'WARN']
    lines = [f'{v[1]:4s} {v[0]:7s} {f}  — {v[2]}' for f, v in sorted(rows.items(), key=lambda x: (x[1][1] != 'FAIL', x[0]))]
    lines += [f'FAIL literal {f}:{n}  — figure {fig!r} in a generator string literal (no `# {OK_MARK}`)' for f, n, fig in lits]
    by = {}
    for v in rows.values():
        by[v[0]] = by.get(v[0], 0) + 1
    summ = (f"coherence_audit: {len(rows)} new files ({', '.join(f'{k} {n}' for k, n in sorted(by.items()))}) · "
            f"FAIL {len(fails) + len(lits)} (orphan {sum(1 for _, v in fails if v[0] == 'code')}, unregistered KAT "
            f"{sum(1 for _, v in fails if v[0] in ('kat', 'gotest'))}, literal {len(lits)}) · WARN {len(warns)}")
    return lines, summ, len(fails) + len(lits)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--root', default=str(ROOT))
    ap.add_argument('--base')
    ap.add_argument('--head', default='HEAD')
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--record', action='store_true')
    a = ap.parse_args(argv)
    try:
        rid, base = round_base(a.root)
        base = a.base or base
        if not base or base == 'pending':
            print(f'coherence_audit: round {rid} has no new_tests_base')
            return 2
        rows, lits = audit(a.root, base, a.head)
    except (OSError, ValueError, KeyError, StopIteration, RuntimeError) as e:
        print(f'coherence_audit: {type(e).__name__}: {e}')
        return 2
    lines, summ, nfail = report(rows, lits)
    try:                                                     # r30 (§0.12, §2.23): the decision log
        decs = decision_problems((Path(a.root) / 'artifacts/dero-rft.md').read_text(errors='replace'), a.root)
    except OSError:
        decs = []
    dfail = [(d, w) for d, w in decs if w]
    if decs:
        lines += [f'FAIL decision {d}  — {w}' for d, w in dfail]
        summ += f' · decisions {len(decs)} (FAIL {len(dfail)})'
    nfail += len(dfail)
    if a.json:
        print(json.dumps({'round': rid, 'base': base, 'head': a.head, 'rows': {f: list(v) for f, v in rows.items()},
                          'literals': [list(x) for x in lits], 'decisions': [list(x) for x in decs], 'fail': nfail}, indent=1))
    else:
        print('\n'.join(lines))
    print(summ)
    if a.record:
        out = Path(a.root) / 'harness/runtime' / f'{rid}_coherence_audit.txt'
        out.write_text(f'# rft §6 step 22a coherence audit, round {rid}, {base}..{a.head}\n' + '\n'.join(lines) + '\n' + summ + '\n')
    return 4 if nfail else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
