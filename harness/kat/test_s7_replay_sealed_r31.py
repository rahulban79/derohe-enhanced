#!/usr/bin/env python3
"""test_s7_replay_sealed_r31.py — r31 closed loop (rft §7 B326): S7's forensic replay of a SEALED newest dataset whose
pinned decoder inputs moved on (the R31 logging-only blockchain.go edits) is verified through its pinned source
(pinsnap snapshot, rft §6 step 3a), never re-pinned; an open version or any other failure keeps the strict verdict.

  SR1 use_pinned_snapshot: sealed + only pin-drift reasons -> True; open version, a non-pin reason, no reasons, a PASS
      report, or already inside a snapshot (S7_REPLAY_PINNED=1) -> False
  SR2 main routes a qualifying FAIL through replay_in_snapshot, labels it SEALED and keeps the drift list; the snapshot
      run sets S7_REPLAY_PINNED=1 (no recursion) and is built by pinsnap.snapshot (pins resolved, never rewritten)

  python3 -I harness/kat/test_s7_replay_sealed_r31.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 missed
"""
import ast, contextlib, importlib.util, io, os, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'s7': 'harness/forensics/s7_replay.py'}


def P(over):
    return Path(over.get('s7') or (ROOT / PATHS['s7']))


def extract(over):
    t = ast.parse(P(over).read_text(encoding='utf-8'))
    body = [n for n in t.body if (isinstance(n, ast.FunctionDef) and n.name == 'use_pinned_snapshot') or
            (isinstance(n, ast.Assign) and any(getattr(x, 'id', '') == 'PIN_DRIFT' for x in n.targets))]
    ns = {'os': os}
    exec(compile(ast.Module(body=body, type_ignores=[]), str(P(over)), 'exec'), ns)   # noqa: S102 — this repo's own code
    return ns['use_pinned_snapshot']


def kat_sr1(over):
    f = extract(over)
    drift = ['content pins: pinned file changed (decoder_inputs): blockchain/blockchain.go',
             'mode partial: content pins differ (no re-derivation)']
    fail = {'result': 'FAIL', 'fail_reasons': drift}
    os.environ.pop('S7_REPLAY_PINNED', None)
    a = f(True, fail)
    b = f(False, fail)
    c = f(True, {'result': 'FAIL', 'fail_reasons': drift + ['derived file mismatch: summary.json']})
    d = f(True, {'result': 'FAIL', 'fail_reasons': []})
    e = f(True, {'result': 'PASS', 'fail_reasons': drift})
    g = f(True, {'result': 'FAIL', 'fail_reasons': ['mode partial: content pins differ (no re-derivation)']})
    os.environ['S7_REPLAY_PINNED'] = '1'
    h = f(True, fail)
    os.environ.pop('S7_REPLAY_PINNED', None)
    return (a, b, c, d, e, g, h) == (True, False, False, False, False, False, False), (a, b, c, d, e, g, h)


def kat_sr2(over):
    src = P(over).read_text(encoding='utf-8')
    fn = {n.name: ast.unparse(n) for n in ast.parse(src).body if isinstance(n, ast.FunctionDef)}
    main, snap = fn.get('main', ''), fn.get('replay_in_snapshot', '')
    miss = [n for n in ("use_pinned_snapshot(led['versions'][-1].get('sealed'), rep)", 'replay_in_snapshot(man)',
                        'SEALED, pinned source', "pin_drift=rep.get('fail_reasons', [])") if n not in main]
    miss += [n for n in ("pinsnap.snapshot(man.get('content_pins')", "S7_REPLAY_PINNED='1'") if n not in snap]
    return not miss, miss


KATS = [('SR1', kat_sr1), ('SR2', kat_sr2)]
OWNERS = {'r31 s7-replay-sealed': [k for k, _ in KATS]}
MUTATIONS = [
    ('s7', "    return (bool(sealed) and rep.get('result') != 'PASS'", "    return (True and rep.get('result') != 'PASS'",
     'r31 s7-replay-sealed: an OPEN version is also replayed from a snapshot'),
    ('s7', "            and any(r.startswith(PIN_DRIFT[0]) for r in reasons)\n", "\n",
     'r31 s7-replay-sealed: a partial-mode reason alone qualifies'),
    ('s7', "bool(reasons) and all(r.startswith(PIN_DRIFT) for r in reasons)", "bool(reasons) and any(r.startswith(PIN_DRIFT) for r in reasons)",
     'r31 s7-replay-sealed: a real mismatch next to the drift is hidden'),
    ('s7', "            and os.environ.get('S7_REPLAY_PINNED') != '1')", "            )",
     'r31 s7-replay-sealed: the snapshot run recurses'),
    ('s7', "    if use_pinned_snapshot(led['versions'][-1].get('sealed'), rep):", "    if False:",
     'r31 s7-replay-sealed: main never uses the pinned source'),
    ('s7', "env=dict(os.environ, S7_REPLAY_PINNED='1')", "env=dict(os.environ)",
     'r31 s7-replay-sealed: the snapshot run is not marked'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_sr31', HARNESS / 'kit' / 'katmut.py')
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
        print(f'\nr31 s7-replay-sealed KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='sr31-mut-') as d:
            mut = Path(d) / PATHS[key]
            mut.parent.mkdir(parents=True, exist_ok=True)
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, _ = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r31 s7-replay-sealed KATs', len(KATS), len(MUTATIONS), missed, 0))
    return 0 if not missed else 4


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
