#!/usr/bin/env python3
"""mine_coverage.py — which first-party functions does the page actually say something about?

A function is COVERED when some mined row cites a line inside it (from its declaration to the next declaration in
the same file, using the ctags symbol table harness/corpus/tags.tsv). Measured from the miners' raw rows, so it does
not depend on the build it feeds. RISK functions are those whose names carry the words that decide money or trust
(verify, valid, proof, pow, difficulty, reward, fee, balance, handshake, ban, prune, sign, revert, ...): an uncovered
risk function is a part of the consensus or security surface the page is silent about (discovery harness-gaps-14).

Writes harness/runtime/coverage_<ts>.json (one fact per line) and coverage rows anchored on it. Gate G16 fails when
risk coverage drops between two snapshots.
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):   # r27 B120: usage, exit 0, nothing run or written
    print(__doc__ or 'usage: see the header of this file')
    raise SystemExit(0)
import collections, datetime, json, os, re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import minelib as M

RISK = re.compile(r'(?i)verif|valid|proof|pow|difficult|reward|fee|balance|handshake|ban|prune|sign|revert|deseriali'
                  r'|mint|supply|nonce|registr|coinbase|integrator|miniblock|hardfork|hf3|rewind|commit')
PKGS_IN_SCOPE = ('blockchain', 'p2p', 'cryptography', 'block', 'transaction', 'dvm', 'cmd/derod', 'config', 'astrobwt', 'proof')


def spans():
    """file -> sorted [(line, name)] of func/method declarations from the corpus symbol table."""
    out = collections.defaultdict(list)
    for l in M.tags_text().splitlines():        # r28: exit 2 naming prep_corpus when the table is missing
        name, f, line, kind, pkg = (l.split('\t') + ['', '', '', '', ''])[:5]
        if kind in ('func', 'method') and f.startswith(PKGS_IN_SCOPE) and not f.endswith('_test.go'):
            out[f].append((int(line), name))
    for f in out:
        out[f].sort()
    return out


def func_end(raw, ln, nxt):
    """The line after a function's closing brace: gofmt puts it alone in column 0. Code between functions (consts,
    types, comments) then covers nothing (review 2026-10-22: spans used to run to the next declaration)."""
    for i in range(ln, min(nxt - 1, len(raw))):
        if raw[i] == '}':
            return i + 2
    return nxt


def cited():
    """file -> set(line) cited by any raw row of any miner (coverage itself excluded)."""
    c = collections.defaultdict(set)
    for p in sorted(M.RAW.glob('*.json')):
        if p.stem in ('coverage', 'riskmap'):   # the register describes structure; it must not inflate coverage
            continue
        for r in json.loads(p.read_text()).get('rows', []):
            for e in r.get('evidence') or []:
                if e.get('file') and e.get('line'):
                    c[e['file']].add(int(e['line']))
    return c


def main():
    S, C = spans(), cited()
    per_pkg = collections.defaultdict(lambda: {'funcs': 0, 'covered': 0, 'risk': 0, 'risk_covered': 0})
    uncovered_risk = []
    risk_state = []
    for f, decls in S.items():
        pkg = f.rsplit('/', 1)[0]
        lines = C.get(f, set())
        raw, _ = M.lines(f)
        nxt = [d[0] for d in decls[1:]] + [10 ** 9]
        for (ln, name), n2 in zip(decls, nxt):
            end = func_end(raw or [], ln, n2)
            hit = any(ln <= x < end for x in lines)
            risky = bool(RISK.search(name))
            p = per_pkg[pkg]
            p['funcs'] += 1
            p['covered'] += hit
            if risky:
                p['risk'] += 1
                p['risk_covered'] += hit
                risk_state.append((f, name, int(hit)))
                if not hit:
                    uncovered_risk.append((f, ln, name))
    tot = {k: sum(p[k] for p in per_pkg.values()) for k in ('funcs', 'covered', 'risk', 'risk_covered')}
    facts = [f"coverage total funcs={tot['funcs']} covered={tot['covered']} risk={tot['risk']} risk_covered={tot['risk_covered']}"]
    for pkg in sorted(per_pkg):
        p = per_pkg[pkg]
        facts.append(f"coverage pkg {pkg} funcs={p['funcs']} covered={p['covered']} risk={p['risk']} risk_covered={p['risk_covered']}")
    for f, ln, name in sorted(uncovered_risk):
        facts.append(f'coverage uncovered-risk {f}:{ln} {name}')
    # keyed by file and name, not line: G16 ratchets on this set, and lines drift with every edit
    for f, name, hit in sorted(set(risk_state)):
        facts.append(f'coverage risk-function {f}::{name} covered={hit}')
    snap = M.HARNESS / f"runtime/coverage_{datetime.datetime.now().strftime('%Y%m%dT%H%M%S')}.json"
    import hashlib
    method = hashlib.sha1(Path(__file__).read_bytes()).hexdigest()[:12]   # G16 compares like with like only
    snap.write_text(json.dumps({'captured': datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
                                'method': method, 'risk_pattern': RISK.pattern, 'total': tot, 'packages': per_pkg,
                                'facts': facts},
                               indent=1, ensure_ascii=False))
    rel = str(snap.relative_to(M.ROOT))
    rows = []
    a = M.anchor(rel, facts[0], full_line=True)
    if a:
        rows.append({'id': 'cov-total', 'section': 'coverage', 'class': 'HARNESS', 'kind': 'total',
                     'title': 'What the page covers', **tot,
                     'claim': (f"{tot['covered']} of {tot['funcs']} first-party functions in scope have at least one row "
                               f"citing a line inside them; of the {tot['risk']} risk-named functions (verification, PoW, "
                               f"difficulty, fees, balances, handshake, bans, pruning, ...), {tot['risk_covered']} are covered "
                               f"and {tot['risk'] - tot['risk_covered']} are not. Measured from the miners' raw rows."),
                     'evidence': [a]})
    for pkg in sorted(per_pkg, key=lambda k: -(per_pkg[k]['risk'] - per_pkg[k]['risk_covered'])):
        p = per_pkg[pkg]
        if not p['risk']:
            continue
        fact = next(x for x in facts if x.startswith(f'coverage pkg {pkg} '))
        a = M.anchor(rel, fact, full_line=True)
        if a:
            unc = [n for f, ln, n in uncovered_risk if f.rsplit('/', 1)[0] == pkg]
            rows.append({'id': f'cov-{pkg.replace("/", "-")}', 'section': 'coverage', 'class': 'HARNESS', 'kind': 'pkg',
                         'title': pkg, 'pkg': pkg, **p, 'uncovered': unc,
                         'claim': (f"{pkg}: {p['risk_covered']}/{p['risk']} risk functions and {p['covered']}/{p['funcs']} "
                                   f"functions covered." + (f" Uncovered risk: {', '.join(unc[:12])}" + (f' and {len(unc) - 12} more' if len(unc) > 12 else '') if unc else '')),
                         'evidence': [a]})
    print(f"  coverage: {tot['covered']}/{tot['funcs']} functions, risk {tot['risk_covered']}/{tot['risk']} · {snap.name}")
    M.emit('coverage', rows, [], 'mine_coverage.py')
    M.emit('riskmap', risk_register(S), [], 'mine_coverage.py')


CONSENSUS_PKGS = ('blockchain/', 'dvm/', 'transaction/', 'cryptography/', 'block/', 'astrobwt/', 'config/', 'proof/')


def go_call_lines(root=None):
    """[(repo-relative path, line text)] of every first-party, non-test .go file under root, read once. r28
    (tools-kats): risk_register ran `grep -rn --include=*.go '\\bNAME(' .` once per risk function, 201 recursive
    greps over the whole checkout (vendor/, harness/ and .git included, then filtered): 110 s of a 125 s run
    (cProfile, 2026-11-06), so the MK7 KAT took 521 s. The same files and filters, one walk: riskmap.json byte-equal.
    Symbolic links are not followed (grep -r does not follow them either)."""
    root = Path(root or M.ROOT)
    out = []
    for dp, dn, fn in os.walk(root):
        rel_d = os.path.relpath(dp, root)
        if rel_d == '.':
            dn[:] = [d for d in dn if d not in ('vendor', 'harness')]
        dn.sort()
        for f in sorted(fn):
            p = os.path.join(dp, f)
            if not f.endswith('.go') or f.endswith('_test.go') or os.path.islink(p):
                continue
            rel = os.path.relpath(p, root)
            try:
                text = Path(p).read_text(errors='replace')
            except OSError:
                continue
            out += [(rel, l) for l in text.split('\n')]
    return out


def callers_of(name, lines):
    """the files with a non-comment, non-declaration `name(` (grep's \\bNAME( on each line). Pure."""
    rx, needle = re.compile(r'\b' + re.escape(name) + r'\('), name + '('
    return {f for f, txt in lines if needle in txt and rx.search(txt) and not txt.strip().startswith('//')
            and not re.match(r'\s*func ', txt)}


def risk_register(S):
    """One row per risk-named function, with measured structure only: size, callers, panics, recovers, and
    whether it lives in a consensus package. No prose is generated — every attribute is counted."""
    rows = []
    call_lines = go_call_lines()
    for f, decls in sorted(S.items()):
        raw, _ = M.lines(f)
        if raw is None:
            continue
        nxt = [d[0] for d in decls[1:]] + [len(raw) + 1]
        for (ln, name), end in zip(decls, nxt):
            if not RISK.search(name):
                continue
            body = raw[ln - 1:end - 1]
            a = M.anchor(f, raw[ln - 1].strip(), hint=ln, full_line=True)
            if not a:
                continue
            callers = callers_of(name, call_lines)       # r28: one in-process walk, not one grep per function
            rows.append({'id': f"risk-{f.replace('/', '-')}-{ln}", 'section': 'riskmap', 'class': 'SRC', 'title': name,
                         'file': f, 'line': ln, 'lines': len(body),
                         'caller_files': len(callers),   # files (incl. its own) with a non-comment, non-declaration `name(`
                         'panics': sum(1 for b in body if 'panic(' in b and not b.strip().startswith('//')),
                         'recovers': sum(1 for b in body if 'recover()' in b),
                         'consensus': f.startswith(CONSENSUS_PKGS),
                         'evidence': [a]})
            r_ = rows[-1]
            r_['claim'] = (f"{name} ({f}:{ln}): {r_['lines']} lines; `{name}(` appears in {r_['caller_files']} file(s) outside its declaration; "
                           f"{r_['panics']} panic() and {r_['recovers']} recover() call(s); "
                           + ('consensus-visible package.' if r_['consensus'] else 'outside the consensus packages.'))
    return rows


if __name__ == '__main__':
    main()
