#!/usr/bin/env python3
"""test_sync_readme_r31.py — r31 (rft §7 B331): the public README's newest 'Round N adds' paragraph must name the round
being synced. README_HEADER in the private sync tool (outside both repos) is hand-written; R28d..R31 synced with the R28
paragraph on top because nothing checked it. The tool now refuses such a sync (readme_round_problem, before the privacy
scan and before --apply).

  SR1 readme_round_problem: matching round -> None; an older round on top -> a problem naming both; a sub-round suffix
      (r28d) is matched exactly; a README without a 'Round N adds' paragraph and an unreadable version are problems
  SR2 main runs the check on the staged README before check_dir and exits non-zero before apply_to_public

The tool is read, never written: DERO_SYNC_ROUND names it (default: TOOL_PATHS.json `sync_rules`); mutations run on a
temp copy. Without the tool (another machine) the KAT prints SKIP and exits 0.

  python3 -I harness/kat/test_sync_readme_r31.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 missed
"""
import ast, contextlib, importlib.util, io, os, re, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
def _tool():
    """the private sync tool's path: DERO_SYNC_ROUND, else harness/loop/TOOL_PATHS.json `sync_rules` (a file the public
    copy excludes, so this published KAT never names the private tool); None when neither is set"""
    if os.environ.get('DERO_SYNC_ROUND'):
        return Path(os.environ['DERO_SYNC_ROUND'])
    try:
        import json
        p = json.loads((ROOT / 'harness/loop/TOOL_PATHS.json').read_text()).get('sync_rules')
        return Path(os.path.expanduser(p)) if p else None
    except (OSError, ValueError):
        return None


TOOL = _tool()


def P(over):
    return Path(over.get('tool') or TOOL)


def extract(over):
    t = ast.parse(P(over).read_text(encoding='utf-8'))
    body = [n for n in t.body if (isinstance(n, ast.FunctionDef) and n.name == 'readme_round_problem') or
            (isinstance(n, ast.Assign) and any(getattr(x, 'id', '') == 'README_ROUND_RX' for x in n.targets))]
    ns = {'re': re}
    exec(compile(ast.Module(body=body, type_ignores=[]), str(P(over)), 'exec'), ns)   # noqa: S102 — the user's own tool
    return ns['readme_round_problem']


def kat_sr1(over):
    f = extract(over)
    v31, v28d = '3.6.0-153.DEROHE.STARGATE+22102026.r31', '3.6.0-153.DEROHE.STARGATE+22102026.r28d'
    ok31 = 'x\n\nRound 31 (`+22102026.r31`) adds (node-only):\n\nRound 30 (`+22102026.r30`) adds:\n'
    old = 'x\n\nRound 28 (`+22102026.r28`) adds:\n\nRound 27 (`+22102026.r27`) adds:\n'
    ok28d = 'Round 28d (`+22102026.r28d`) adds:\n'
    r = (f(ok31, v31), f(old, v31), f(ok28d, v28d), f('Round 28 (`+22102026.r28`) adds:\n', v28d), f('no paragraph', v31),
         f(ok31, 'no-version'))
    good = (r[0] is None and r[1] and '28' in r[1] and '31' in r[1] and r[2] is None and r[3] is not None
            and r[4] is not None and r[5] is not None)
    return bool(good), r


def kat_sr2(over):
    fn = {n.name: ast.unparse(n) for n in ast.parse(P(over).read_text(encoding='utf-8')).body if isinstance(n, ast.FunctionDef)}
    m = fn.get('main', '')
    i, j, k = m.find('readme_round_problem('), m.find('hits = check_dir(a.out)'), m.find('apply_to_public(a, a.out)')
    miss = []
    if not (0 <= i < j < k):
        miss.append(f'order check/scan/apply: {i} {j} {k}')
    if 'sys.exit(1)' not in m[i:j]:
        miss.append('a README problem does not exit non-zero before the scan')
    return not miss, miss


KATS = [('SR1', kat_sr1), ('SR2', kat_sr2)]
OWNERS = {'r31 sync-readme': [k for k, _ in KATS]}
MUTATIONS = [
    ('tool', "    if first.group(1) != want:", "    if False:", 'r31 sync-readme: an older round on top passes'),
    ('tool', "    if first is None:\n        return 'README has no \"Round N adds\" paragraph'\n", "    if first is None:\n        return None\n",
     'r31 sync-readme: a README without a round paragraph passes'),
    ('tool', "    m = re.search(r'\\.r(\\w+)$', ver or '')", "    m = re.search(r'\\.r(\\d+)', ver or '')",
     'r31 sync-readme: a sub-round suffix (28d) is read as its parent'),
    ('tool', "        print(f'README check FAILED: {prob}; public repo NOT touched'); sys.exit(1)",
     "        print(f'README check FAILED: {prob}; public repo NOT touched')", 'r31 sync-readme: a README problem only prints'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_sr31r', HARNESS / 'kit' / 'katmut.py')
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
    if TOOL is None or not TOOL.exists():
        print('r31 sync-readme KATs: SKIP (no sync tool on this machine; set DERO_SYNC_ROUND)')
        return 0
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr31 sync-readme KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = 0
    text = TOOL.read_text(encoding='utf-8')
    for key, find, repl, why in MUTATIONS:
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='sr31r-mut-') as d:
            mut = Path(d) / 'tool.py'
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, _ = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r31 sync-readme KATs', len(KATS), len(MUTATIONS), missed, 0))
    return 0 if not missed else 4


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
