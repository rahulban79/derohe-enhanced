#!/usr/bin/env python3
"""test_merge_artifacts_r29.py — r29 (found by the closing project-only run 2, 2026-11-08, verify_deroarch): two classes
a merge round causes and the page builder only caught late.

  TA1 every literal anchor (file, quote) of harness/miners/mine_triage.py resolves at HEAD: B157 changed
      `logger.V(2).Error(nil, "Recover while executing SC "` to a V(2) Info call, the quote was lost, and the
      tri-sc-zerosigner row silently left the page (DK25: 12 triaged vs 15 ERROR lines)
  EV1 mine_evolution.walk on a scratch repo with a --no-ff merge: the merge commit is not in the commit list and is
      counted in `merges` (the R29 merge's 8 merge commits made DK35 294 vs git --no-merges 286)
  EV2 the page claim names the merges when there are any (it said "none of them merges")
  SC1 every SOUNDNESS_CLAIMS `crypto_changes` want equals the cryptography/ test files added since bf274e5 now, and the
      page sentence names that count (r28d and r29 each added crypto tests and G22 failed late, in S7; this runs in S3k)
  EV3 coherence's evolution freshness check reads the same --no-merges history (else it calls the page STALE for merges)

  python3 -I harness/kat/test_merge_artifacts_r29.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 missed
"""
import ast, contextlib, importlib.util, io, os, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'triage': 'harness/miners/mine_triage.py', 'evo': 'harness/miners/mine_evolution.py',
         'coh': 'harness/intel/coherence.py', 'claims': 'harness/loop/SOUNDNESS_CLAIMS.json'}


def P(over, k):
    return Path(over.get(k) or (ROOT / PATHS[k]))


def kat_ta1(over):
    tree = ast.parse(P(over, 'triage').read_text(encoding='utf-8'))
    names = {t.id: n.value.value for n in tree.body if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant)
             and isinstance(n.value.value, str) for t in n.targets if isinstance(t, ast.Name)}
    pairs, lost = [], []
    for n in ast.walk(tree):
        if isinstance(n, ast.Tuple) and len(n.elts) == 2 and isinstance(n.elts[1], ast.Constant) and isinstance(n.elts[1].value, str):
            f = n.elts[0]
            path = names.get(f.id) if isinstance(f, ast.Name) else (f.value if isinstance(f, ast.Constant) else None)
            if isinstance(path, str) and path.endswith('.go') and not path.startswith('harness/'):
                pairs.append((path, n.elts[1].value))
    for path, q in pairs:
        t = (ROOT / path).read_text(errors='replace') if (ROOT / path).exists() else ''
        if q not in t:
            lost.append(f'{path} :: {q[:60]}')
    return bool(pairs) and not lost, (len(pairs), lost[:3])


def evo(over):
    src = P(over, 'evo').read_text(encoding='utf-8')
    fns = [n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef) and n.name in ('walk', 'base_claim')]
    ns = {}
    exec(compile(ast.Module(body=fns, type_ignores=[]), 'mine_evolution.py', 'exec'), ns)   # noqa: S102 — own code
    return ns['walk'], ns['base_claim']


def kat_ev1(over):
    walk, _ = evo(over)
    with tempfile.TemporaryDirectory() as d:
        env = {**os.environ, 'GIT_AUTHOR_NAME': 'k', 'GIT_AUTHOR_EMAIL': 'k@k', 'GIT_COMMITTER_NAME': 'k',
               'GIT_COMMITTER_EMAIL': 'k@k', 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_SYSTEM': os.devnull}
        r = lambda *a: subprocess.run(['git', *a], cwd=d, capture_output=True, text=True, env=env).stdout
        r('init', '-q', '-b', 'main')
        for name, br in (('a', None), ('b', 'side'), ('c', None)):
            if br:
                r('checkout', '-q', '-b', br)
            Path(d, name).write_text(name + '\n')
            r('add', name)
            r('commit', '-q', '-m', f'R29 {name}')
            if br:
                r('checkout', '-q', 'main')
        base = r('rev-list', '--max-parents=0', 'HEAD').strip()
        r('merge', '-q', '--no-ff', '-m', 'R29 merge: side', 'side')
        commits, merges = walk(lambda *a: r(*a), base)
    subj = [c['subject'] for c in commits]
    return sorted(subj) == ['R29 b', 'R29 c'] and merges == 1, (subj, merges)


def kat_ev2(over):
    _, claim = evo(over)
    a, b = claim('Release152', 'a' * 40, 'b' * 40, 286, 8), claim('Release152', 'a' * 40, 'b' * 40, 5, 0)
    return '286 local commits' in a and 'plus 8 merge commit(s)' in a and 'none of them merges' in b, (a[-120:], b[-40:])


def kat_ev3(over):
    src = P(over, 'coh').read_text(encoding='utf-8')
    ok = "log = git(c, 'log', '--no-merges', '--format=%h%x09%s', '-n', '400')" in src
    return ok, 'coherence walks --no-merges' if ok else 'coherence counts merge commits as round commits'


def kat_sc1(over):
    import json, re
    r = subprocess.run(['git', 'diff', '--name-status', '--diff-filter=A', 'bf274e5', '--', 'cryptography/'], cwd=ROOT,
                       capture_output=True, text=True)
    n = sum(1 for l in r.stdout.splitlines() if l.endswith('_test.go'))
    d = json.loads(P(over, 'claims').read_text(encoding='utf-8'))
    wants = [b['want']['added_tests'] for u in d.get('claims', []) for b in u.get('backing', [])
             if b.get('name') == 'crypto_changes' and 'added_tests' in b.get('want', {})]
    words = {7: 'seven', 8: 'eight', 9: 'nine', 10: 'ten', 11: 'eleven', 12: 'twelve'}
    txt = ' '.join(u.get('match', '') for u in d.get('claims', []))
    said = re.search(r'only gained (\w+) test files', txt)
    ok = r.returncode == 0 and wants and set(wants) == {n} and said and said.group(1) == words.get(n, str(n))
    return bool(ok), (n, sorted(set(wants)), said.group(1) if said else None)


KATS = [('TA1', kat_ta1), ('EV1', kat_ev1), ('EV2', kat_ev2), ('EV3', kat_ev3), ('SC1', kat_sc1)]
OWNERS = {'r29 merge-artifacts': ['TA1', 'EV1', 'EV2', 'EV3', 'SC1']}
MUTATIONS = [
    ('triage', """(TE, 'logger.V(2).Info("Recover while executing SC ", "txid", txhash, "error", r')]""",
     """(TE, 'logger.V(2).Error(nil, "Recover while executing SC "')]""", 'r29 merge-artifacts: the zerosigner anchor quotes the pre-B157 line'),
    ('evo', "'--no-merges', '--no-renames'", "'--no-renames'", 'r29 merge-artifacts: the walk counts merge commits'),
    ('evo', "    merges = len(git('rev-list', '--merges', f'{base}..{head}').split())", "    merges = 0",
     'r29 merge-artifacts: merges are not counted'),
    ('evo', "            + (f', plus {merges} merge commit(s)", "            + ('.' if True else f', plus {merges} merge commit(s)",
     'r29 merge-artifacts: the claim drops the merge count'),
    ('coh', "log = git(c, 'log', '--no-merges', '--format=%h%x09%s'", "log = git(c, 'log', '--format=%h%x09%s'",
     'r29 merge-artifacts: coherence expects merge commits on the evolution page'),
    ('claims', 'only gained eight test files', 'only gained seven test files',
     'r29 merge-artifacts: the soundness sentence keeps the old crypto test count'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_ma29', HARNESS / 'kit' / 'katmut.py')
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
        print(f'\nr29 merge-artifacts KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='ma29-mut-') as d:
            mut = Path(d) / Path(PATHS[key]).name
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, _ = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r29 merge-artifacts KATs', len(KATS), len(MUTATIONS), missed, 0))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
