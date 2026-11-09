#!/usr/bin/env python3
"""test_liveness_lint_r29.py — r29 gate G33 (harness/pipeline/liveness_lint.py; rft §5 long-job liveness): the lint
finds the hang shapes of the B182 run and only those, and its allow-list cannot rot.

  LL1 the pre-fix B182 Decoder (stdin written in a loop, stdout read after, one thread) is flagged L1 at the write
  LL2 the same with a feeder thread, a communicate() caller and kit/coproc.py itself are not flagged
  LL3 urlopen(u) / create_connection(a) / HTTPConnection(h) / requests.get(u) without timeout are flagged L2; with a
      timeout keyword, urlopen's positional timeout or a **kwargs pass-through they are not
  LL4 judge: an unallowed hit is a finding; an allowed one with a reason is not; an entry matching nothing or without a
      reason is stale
  LL5 the tree as it stands passes G33

  python3 -I harness/kat/test_liveness_lint_r29.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 missed
"""
import contextlib, importlib.util, io, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'lint': 'harness/pipeline/liveness_lint.py'}

OLD = '''import subprocess, json
class Decoder:
    def __init__(self, binary):
        self.p = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def run(self, items):
        for k, x in items:
            self.p.stdin.write(json.dumps({'k': k, 'x': x}) + '\\n')
        self.p.stdin.write('{"k":"f"}\\n')
        self.p.stdin.flush()
        return [json.loads(self.p.stdout.readline()) for _ in items]
'''
FIXED = OLD.replace('''        for k, x in items:
            self.p.stdin.write(json.dumps({'k': k, 'x': x}) + '\\n')
        self.p.stdin.write('{"k":"f"}\\n')
        self.p.stdin.flush()
''', '''        def feed():
            for k, x in items:
                self.p.stdin.write(json.dumps({'k': k, 'x': x}) + '\\n')
        w = threading.Thread(target=feed, daemon=True)
        w.start()
''')
COMM = '''import subprocess
def f(lines):
    p = subprocess.Popen(['cat'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    for ln in lines:
        p.stdin.write(ln)
    out, _ = p.communicate()
    return p.stdout.read()
'''
NET_BAD = '''import urllib.request, socket, http.client, requests
def a(u):
    return urllib.request.urlopen(u)
def b(h):
    return socket.create_connection(h)
def c(h):
    return http.client.HTTPConnection(h)
def d(u):
    return requests.get(u)
'''
NET_OK = '''import urllib.request, socket, http.client, requests
def a(u):
    return urllib.request.urlopen(u, timeout=5)
def a2(u):
    return urllib.request.urlopen(u, None, 5)
def b(h):
    return socket.create_connection(h, 5)
def c(h):
    return http.client.HTTPConnection(h, timeout=5)
def d(u, **kw):
    return requests.get(u, **kw)
'''


def load(over):
    spec = importlib.util.spec_from_file_location('ll29', Path(over.get('lint') or (ROOT / PATHS['lint'])))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def kat_ll1(over):
    m = load(over)
    h = m.scan_source(OLD)
    return h == [('run', 'L1', 8)], h


def kat_ll2(over):
    m = load(over)
    a, b = m.scan_source(FIXED), m.scan_source(COMM)
    c = m.scan_source((ROOT / 'harness/kit/coproc.py').read_text())
    return a == [] and b == [] and c == [], (a, b, c)


def kat_ll3(over):
    m = load(over)
    bad, ok = m.scan_source(NET_BAD), m.scan_source(NET_OK)
    return sorted(f for f, r, _ in bad if r == 'L2') == ['a', 'b', 'c', 'd'] and ok == [], (bad, ok)


def kat_ll4(over):
    m = load(over)
    hits = [{'path': 'x.py', 'func': 'f', 'rule': 'L1', 'line': 3}, {'path': 'y.py', 'func': 'g', 'rule': 'L2', 'line': 9}]
    allow = [{'path': 'y.py', 'func': 'g', 'rule': 'L2', 'reason': 'local socket, peer is ours'},
             {'path': 'z.py', 'func': 'h', 'rule': 'L1', 'reason': 'gone'},
             {'path': 'x.py', 'func': 'f', 'rule': 'L2', 'reason': ''}]
    f, s = m.judge(hits, allow)
    return ([x['path'] for x in f], sorted(a['path'] for a in s)) == (['x.py'], ['x.py', 'z.py']), (f, s)


def kat_ll5(over):
    m = load(over)
    return m.g33(ROOT)


KATS = [('LL1', kat_ll1), ('LL2', kat_ll2), ('LL3', kat_ll3), ('LL4', kat_ll4), ('LL5', kat_ll5)]
OWNERS = {'r29 liveness-lint': [k for k, _ in KATS]}
MUTATIONS = [
    ('lint', "        if w and _reads_stdout(fn) and not _has_feeder(fn):", "        if w and _reads_stdout(fn):",
     'r29 liveness-lint: a feeder thread does not clear the shape'),
    ('lint', "        if w and _reads_stdout(fn) and not _has_feeder(fn):", "        if False:",
     'r29 liveness-lint: the pipe-deadlock shape is never flagged'),
    ('lint', "        if 'timeout' in kws or None in kws:", "        if True:", 'r29 liveness-lint: no call is ever checked for a timeout'),
    ('lint', "NET = {'urlopen': 3,", "NET = {'urlopen': 1,", 'r29 liveness-lint: urlopen(u) passes without a timeout'),
    ('lint', "    stale = [a for a in allow if key(a) not in seen or not str(a.get('reason') or '').strip()]",
     "    stale = []", 'r29 liveness-lint: stale or reasonless allow entries pass'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_ll29', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run_kats(over):
    res = []
    for name, fn in KATS:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                ok, det = fn(over)
        except (Exception, SystemExit) as e:                      # noqa: BLE001 — a crash is a failure
            ok, det = False, f'{type(e).__name__}: {e}'
        res.append((name, ok, str(det)))
    return res


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr29 liveness lint KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = 0
    for key, find, repl, why in MUTATIONS:
        src = ROOT / PATHS[key]
        text = src.read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='ll29-mut-') as d:
            mut = Path(d) / PATHS[key]
            mut.parent.mkdir(parents=True, exist_ok=True)
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, _ = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r29 liveness lint KATs', len(KATS), len(MUTATIONS), missed, 0))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
