#!/usr/bin/env python3
"""liveness_lint.py — r29 gate G33 (rft §5 long-job liveness; user 2026-11-08 "make sure to fix anything you find
tasks are stuck at ... further enhance the harness, tools, skills, pipeline"): a static scan of the project's own Python
(harness/**/*.py, tools/**/*.py) for the hang shapes the B182 run hit, so the next one is found before it runs.

  L1 pipe-feed-then-read  one function writes a co-process's stdin in a loop AND reads its stdout, with no feeder thread
                          (threading.Thread) and no communicate(): once input and output both outgrow the pipe buffers
                          each side blocks writing to the other (B182 hang 1, topo 150,600; use kit/coproc.py)
  L2 net-no-timeout       urllib.request.urlopen / socket.create_connection / http.client.HTTP(S)Connection /
                          requests.<verb> without a timeout: one silent server stops the caller for ever
Hang classes 2 (a worker holding a task while it waits on a look-ahead) and 3 (a retry unit larger than the failure
unit) are not static shapes; their guards are the KATs (test_b182_deep_r29 DP13, DP15) and stallwatch at run time.

A hit is accepted only through harness/pipeline/liveness_allow.json ({path, func, rule, reason}); an allow entry that
matches no hit any more is itself a finding (stale), so the list cannot rot.

  python3 -I harness/pipeline/liveness_lint.py [--json]     # exit 0 clean · 5 findings (unallowed hits or stale entries)
"""
import ast, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
ALLOW = 'harness/pipeline/liveness_allow.json'
SCAN = ('harness', 'tools')
SKIP_PARTS = {'__pycache__', 'vendor', 'node_modules', '.git'}


def _attr_chain(n):
    out = []
    while isinstance(n, ast.Attribute):
        out.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        out.append(n.id)
    return '.'.join(reversed(out))


def _calls(node):
    return [n for n in ast.walk(node) if isinstance(n, ast.Call)]


def _in_loop_writes(fn):
    hits = []
    for loop in (n for n in ast.walk(fn) if isinstance(n, (ast.For, ast.While, ast.comprehension))):
        for c in _calls(loop):
            ch = _attr_chain(c.func)
            if ch.endswith('stdin.write'):
                hits.append(c)
    return hits


def _reads_stdout(fn):
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            ch = _attr_chain(n.func)
            if ch.endswith(('stdout.readline', 'stdout.read', 'stdout.readlines')):
                return True
        if isinstance(n, ast.For) and _attr_chain(n.iter).endswith('stdout'):
            return True
    return False


def _has_feeder(fn):
    for c in _calls(fn):
        ch = _attr_chain(c.func)
        if ch.endswith('Thread') or ch.endswith('communicate'):
            return True
    return False


NET = {'urlopen': 3, 'create_connection': 2, 'HTTPConnection': None, 'HTTPSConnection': None}
REQ_VERBS = {'get', 'post', 'put', 'delete', 'head', 'patch', 'request'}


def _net_no_timeout(fn):
    out = []
    for c in _calls(fn):
        ch = _attr_chain(c.func)
        last = ch.rsplit('.', 1)[-1]
        kws = {k.arg for k in c.keywords}
        if 'timeout' in kws or None in kws:            # **kwargs may carry it: not provable either way, not flagged
            continue
        if last in NET:
            npos = NET[last]
            if npos is None or len(c.args) < npos:
                out.append(c)
        elif ch.startswith('requests.') and last in REQ_VERBS:
            out.append(c)
    return out


def scan_source(text, path='<src>'):
    """[(func, rule, line)] of one file. Pure."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    hits = []
    fns = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    mod = ast.Module(body=[n for n in tree.body if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))],
                     type_ignores=[])
    for fn, name in [(f, f.name) for f in fns] + [(mod, '<module>')]:
        w = _in_loop_writes(fn)
        if w and _reads_stdout(fn) and not _has_feeder(fn):
            hits.append((name, 'L1', w[0].lineno))
        own = [c for c in _net_no_timeout(fn)]
        if fn is not mod:                                 # nested functions report their own calls once
            inner = {id(c) for f2 in ast.walk(fn) if f2 is not fn and isinstance(f2, (ast.FunctionDef, ast.AsyncFunctionDef))
                     for c in _calls(f2)}
            own = [c for c in own if id(c) not in inner]
        for c in own:
            hits.append((name, 'L2', c.lineno))
    return hits


def files(root=ROOT):
    for top in SCAN:
        for p in sorted((Path(root) / top).rglob('*.py')):
            if not SKIP_PARTS & set(p.parts):
                yield p


def scan(root=ROOT):
    out = []
    for p in files(root):
        rel = str(p.relative_to(root))
        for func, rule, line in scan_source(p.read_text(encoding='utf-8', errors='replace'), rel):
            out.append({'path': rel, 'func': func, 'rule': rule, 'line': line})
    return out


def judge(hits, allow):
    """(findings, stale): unallowed hits and allow entries that match no hit. Pure."""
    key = lambda d: (d['path'], d['func'], d['rule'])
    allowed = {key(a) for a in allow}
    seen = {key(h) for h in hits}
    findings = [h for h in hits if key(h) not in allowed]
    stale = [a for a in allow if key(a) not in seen or not str(a.get('reason') or '').strip()]
    return findings, stale


def g33(root=ROOT):
    root = Path(root)
    try:
        allow = json.loads((root / ALLOW).read_text())['allow']
    except (OSError, ValueError, KeyError) as e:
        return False, f'{ALLOW} unreadable: {type(e).__name__}'
    hits = scan(root)
    findings, stale = judge(hits, allow)
    ok = not findings and not stale
    det = (f'{len(hits)} hit(s) over {sum(1 for _ in files(root))} files, {len(allow)} allowed with a reason'
           + (f' · UNALLOWED {[(f["path"], f["func"], f["rule"], f["line"]) for f in findings][:4]}' if findings else '')
           + (f' · STALE allow {[(a["path"], a["func"], a["rule"]) for a in stale][:4]}' if stale else ''))
    return ok, det


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    if '--json' in argv:
        print(json.dumps(scan(), indent=1))
        return 0
    ok, det = g33()
    print(f"G33 {'PASS' if ok else 'FAIL'}: {det}")
    return 0 if ok else 5


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
