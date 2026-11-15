#!/usr/bin/env python3
"""test_stage_cache_r31.py — r31 (rft §7 B252c): the opt-in stage-result cache of fix_build_verify S1 (guard) and S2
(format). A died pipeline re-ran S1-S7 in full; S1/S2 are pure functions of (HEAD, the work tree incl. untracked files,
the stage argv, the Go env subset, go version), so an identical earlier PASS may be reused — only if the key misses no
input (a key that misses one would PASS a stage that would now FAIL).

  SC1 stage_key: equal inputs give equal keys; a change of ANY one of the five parts (HEAD, tree, argv, env, go version)
      gives a different key
  SC2 worktree_tree on a temp git repo: a tracked edit, an untracked file and an ignored *.go file each change the tree
      id; reverting restores it; a file under KEY_EXCLUDE (the pipeline's own records) and an ignored non-Go file do
      not; the real index and `git status` are unchanged by the computation
  SC3 cache_record / cache_lookup: a PASS is found under its key (with the prior run), not under another key or stage;
      a FAIL is never stored; at most STAGE_CACHE_KEEP entries per stage are kept (the newest)
  SC4 the wiring: cached_pass is off by default (no key, no event); on, a hit emits a PASS event with cached=True
      naming the key and the prior record, a miss an INFO cache=miss; s1_guard and s2_format return on a hit before
      running their commands and record a PASS after it; no other stage uses the cache; --stage-cache sets it
  SC5 provably safe exclusions: harness/consensus_guard.py names none of KEY_EXCLUDE (nor PIPELINE_*): S1 never reads
      the files the key leaves out

  python3 -I harness/kat/test_stage_cache_r31.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import ast, contextlib, hashlib, importlib.util, io, json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'fbv': 'harness/pipeline/fix_build_verify.py'}
FUNCS = ('stage_key', 'worktree_tree', 'cache_lookup', 'cache_record', 'cached_pass')
CONSTS = ('STAGE_CACHE', 'STAGE_CACHE_KEEP', 'KEY_ENV', 'KEY_EXCLUDE')


def P(over):
    return Path(over.get('fbv') or (ROOT / PATHS['fbv']))


def tree_of(over):
    return ast.parse(P(over).read_text(encoding='utf-8'))


def extract(over, extra=None):
    body = [n for n in tree_of(over).body if (isinstance(n, ast.FunctionDef) and n.name in FUNCS) or
            (isinstance(n, ast.Assign) and any(getattr(t, 'id', '') in CONSTS for t in n.targets))]
    ns = {'os': os, 'json': json, 'hashlib': hashlib, 'subprocess': subprocess, 'tempfile': tempfile, 'shutil': shutil,
          'Path': Path, 'sys': sys, 'HARNESS': HARNESS, 'ROOT': ROOT, **(extra or {})}
    exec(compile(ast.Module(body=body, type_ignores=[]), str(P(over)), 'exec'), ns)   # noqa: S102 — this repo's own code
    return ns


def kat_sc1(over):
    k = extract(over)['stage_key']
    base = ('h1', 't1', ['gofmt', '-l', 'a.go'], {'GOFLAGS': '-mod=mod'}, 'go1.24')
    k0 = k(*base)
    bad = []
    if k(*base) != k0:
        bad.append('not deterministic')
    for i, alt in enumerate(('h2', 't2', ['gofmt', '-l', 'b.go'], {'GOFLAGS': '-race'}, 'go1.25')):
        v = list(base)
        v[i] = alt
        if k(*v) == k0:
            bad.append(f'part {i} ({["head", "tree", "argv", "env", "go"][i]}) does not change the key')
    return not bad, '; '.join(bad) or 'five parts, each changes the key'


def git(cwd, *a):
    return subprocess.run(['git', *a], cwd=cwd, capture_output=True, text=True, check=True).stdout


def kat_sc2(over):
    ns = extract(over)
    wt = ns['worktree_tree']
    bad = []
    with tempfile.TemporaryDirectory() as d:
        git(d, 'init', '-q')
        git(d, 'config', 'user.email', 'k@example.invalid')
        git(d, 'config', 'user.name', 'k')
        (Path(d) / '.gitignore').write_text('bin/\n*.log\n')
        (Path(d) / 'a.go').write_text('package a\n')
        (Path(d) / 'harness/loop/runs').mkdir(parents=True)
        git(d, 'add', '-A')
        git(d, 'commit', '-q', '-m', 'base')
        idx = Path(d) / '.git/index'
        sha = lambda: hashlib.sha256(idx.read_bytes()).hexdigest()
        s0, st0 = sha(), git(d, 'status', '--porcelain')
        t0 = wt(d)
        (Path(d) / 'a.go').write_text('package a\n// edit\n')
        t1 = wt(d)
        (Path(d) / 'a.go').write_text('package a\n')
        t2 = wt(d)
        (Path(d) / 'new.go').write_text('package a\n')
        t3 = wt(d)
        (Path(d) / 'new.go').unlink()
        (Path(d) / 'harness/loop/runs/pipeline_x.jsonl').write_text('{}\n')
        (Path(d) / 'run.log').write_text('log\n')
        t4 = wt(d)
        (Path(d) / 'bin').mkdir()
        (Path(d) / 'bin/x.go').write_text('package x\n')
        t5 = wt(d)
        if not t0 or t1 == t0 or t2 != t0 or t3 == t0 or t4 != t0 or t5 == t0:
            bad.append(f'tree ids: base {t0} edit {t1 != t0} revert {t2 == t0} untracked {t3 != t0} excluded/ignored {t4 == t0} ignored-go {t5 != t0}')
        if sha() != s0:
            bad.append('the real index was written')
        st = git(d, 'status', '--porcelain')
        if st0 != '' or 'a.go' in st:
            bad.append(f'git status changed: {st!r}')
    return not bad, '; '.join(bad) or 'tracked/untracked/ignored-go change it; excluded do not; index untouched'


def kat_sc3(over):
    ns = extract(over)
    rec, look, keep = ns['cache_record'], ns['cache_lookup'], ns['STAGE_CACHE_KEEP']
    bad = []
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / 'c.json'
        rec(f, 'guard', 'K1', {'head': 'h'}, 'PASS', {'run': 'R1'})
        if (look(f, 'guard', 'K1') or {}).get('run') != 'R1':
            bad.append('a PASS is not found under its key')
        if look(f, 'guard', 'K2') is not None or look(f, 'format', 'K1') is not None:
            bad.append('found under another key or stage')
        rec(f, 'format', 'K3', {}, 'FAIL', {'run': 'R2'})
        if look(f, 'format', 'K3') is not None:
            bad.append('a FAIL was stored')
        for i in range(keep + 5):
            rec(f, 'guard', f'N{i}', {}, 'PASS', {'run': f'R{i}'})
        doc = json.loads(f.read_text())
        if len(doc['guard']) != keep or f'N{keep + 4}' not in doc['guard']:
            bad.append(f"kept {len(doc['guard'])} (want {keep}, the newest)")
    return not bad, '; '.join(bad) or 'PASS keyed; FAIL never; capped'


def kat_sc4(over):
    bad = []
    evs = []
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / 'c.json'
        ns = extract(over, {'event': lambda st, status, **kv: evs.append((st, status, kv)),
                            'stage_cache_key': lambda argv: ('KEY', {'argv': argv}), 'STAGE_CACHE_FILE': f})
        if ns['STAGE_CACHE'] != [False]:
            bad.append(f"default {ns['STAGE_CACHE']}")
        if ns['cached_pass']('guard', ['x']) != (None, None, None) or evs:
            bad.append('cached_pass acts while off')
        ns['STAGE_CACHE'][0] = True
        k, parts, prior = ns['cached_pass']('guard', ['x'])
        if prior is not None or not evs or evs[-1][1] != 'INFO' or evs[-1][2].get('cache') != 'miss':
            bad.append(f'miss: {evs[-1:]}')
        ns['cache_record'](f, 'guard', 'KEY', parts, 'PASS', {'run': 'R9', 'events': 'e', 't': 't', 'result': {'files': ['f']}})
        k, parts, prior = ns['cached_pass']('guard', ['x'])
        e = evs[-1]
        if not prior or e[:2] != ('guard', 'PASS') or not e[2].get('cached') or e[2].get('key') != 'KEY' or (e[2].get('prior') or {}).get('run') != 'R9':
            bad.append(f'hit: {e}')
    fn = {n.name: n for n in tree_of(over).body if isinstance(n, ast.FunctionDef)}
    for stage, name, cmd in (('guard', 's1_guard', 'sh(S1_ARGV)'), ('format', 's2_format', "sh(['gofmt', '-l', *OWNED])")):
        src = ast.unparse(fn.get(name)) if name in fn else ''
        i_c = src.find(f"cached_pass('{stage}'")
        i_r = src.find('if prior:\n        return')
        i_s = src.find(cmd)
        i_m = src.find(f"remember_pass('{stage}'")
        if min(i_c, i_r, i_s, i_m) < 0 or not (i_c < i_r < i_s < i_m):
            bad.append(f'{name}: lookup -> return on hit -> run -> remember order broken ({i_c},{i_r},{i_s},{i_m})')
    others = [n for n, f_ in fn.items() if n.startswith('s') and n[1:2].isdigit() and n not in ('s1_guard', 's2_format')
              and ('cached_pass' in ast.unparse(f_) or 'remember_pass' in ast.unparse(f_))]
    if others:
        bad.append(f'other stages use the cache: {others}')
    if 'STAGE_CACHE[0] = bool(a.stage_cache)' not in ast.unparse(fn.get('main', ast.Pass())):
        bad.append('--stage-cache does not set STAGE_CACHE')
    return not bad, '; '.join(bad) or 'off by default; hit/miss events; S1/S2 only'


def kat_sc5(over):
    ns = extract(over)
    src = (ROOT / 'harness/consensus_guard.py').read_text()
    hits = [x for x in list(ns['KEY_EXCLUDE']) + ['PIPELINE_', 'loop/runs'] if x in src]
    need = {'harness/loop/runs', 'harness/loop/PIPELINE_LAST.json'}
    return not hits and need <= set(ns['KEY_EXCLUDE']), (hits, sorted(ns['KEY_EXCLUDE']))


KATS = [('SC1', kat_sc1), ('SC2', kat_sc2), ('SC3', kat_sc3), ('SC4', kat_sc4), ('SC5', kat_sc5)]
OWNERS = {'B252c key': ['SC1'], 'B252c tree': ['SC2'], 'B252c store': ['SC3'], 'B252c wiring': ['SC4'], 'B252c exclude': ['SC2', 'SC5']}
MUTATIONS = [   # (file key, find, replace, why — the first two words name the defect, see OWNERS)
    ('fbv', "    doc = {'head': str(head), 'tree'", "    doc = {'head': '', 'tree'", 'B252c key: HEAD is not in the key'),
    ('fbv', "'tree': str(tree), 'argv'", "'tree': '', 'argv'", 'B252c key: the work tree is not in the key'),
    ('fbv', "'tree': str(tree), 'argv': [str(a) for a in argv],", "'tree': str(tree), 'argv': [],", 'B252c key: the stage argv is not in the key'),
    ('fbv', "           'env': sorted((k, str(v)) for k, v in (env or {}).items()), 'go': str(gover)}",
     "           'env': [], 'go': str(gover)}", 'B252c key: the Go env subset is not in the key'),
    ('fbv', "(env or {}).items()), 'go': str(gover)}", "(env or {}).items()), 'go': ''}", 'B252c key: the go version is not in the key'),
    ('fbv', "        if g('add', '-A', '--', '.', env=env)[0] != 0:", "        if g('add', '-u', '--', '.', env=env)[0] != 0:",
     'B252c tree: untracked files are not in the key'),
    ('fbv', "        if ign and g('add', '-f', '--', *ign, env=env)[0] != 0:", "        if False:",
     'B252c tree: ignored *.go files (grepped by the guard) are not in the key'),
    ('fbv', "        env = dict(os.environ, GIT_INDEX_FILE=tmp)", "        env = dict(os.environ)", 'B252c tree: the real index is written'),
    ('fbv', "        g('rm', '-r', '-q', '--cached', '--ignore-unmatch', '--', *exclude, env=env)\n", "",
     'B252c exclude: the pipeline\'s own records change the key (never a hit)'),
    ('fbv', "    if not key or status != 'PASS':\n        return False", "    if not key:\n        return False", 'B252c store: a FAIL is cached'),
    ('fbv', "    hit = ((doc.get(stage) or {}).get(key)) if", "    hit = (list((doc.get(stage) or {}).values()) or [None])[-1] if",
     'B252c store: any prior PASS is reused whatever its key'),
    ('fbv', "    doc[stage] = dict(list(st.items())[-STAGE_CACHE_KEEP:])", "    doc[stage] = st", 'B252c store: the cache grows without bound'),
    ('fbv', "STAGE_CACHE = [False]", "STAGE_CACHE = [True]", 'B252c wiring: the cache is on by default'),
    ('fbv', "    key, parts, prior = cached_pass('guard', S1_ARGV)     # r31 (B252c): opt-in reuse of an identical PASS\n    if prior:\n        return\n",
     "    key, parts, prior = cached_pass('guard', S1_ARGV)     # r31 (B252c): opt-in reuse of an identical PASS\n",
     'B252c wiring: S1 re-runs (and double-records) on a hit'),
    ('fbv', "    remember_pass('format', key, parts,", "    (", 'B252c wiring: an S2 PASS is never remembered'),
    ('fbv', "        event(stage, 'PASS', cached=True, key=key,", "        event(stage, 'PASS', cached=True,", 'B252c wiring: a hit does not name its key'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_sc31', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def defect(why):
    return ' '.join(why.split(':')[0].split()[:2])


def run_kats(over):
    res = []
    for name, fn in KATS:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                ok, det = fn(over)
        except (Exception, SystemExit) as e:                      # noqa: BLE001 — a crash is a failure
            ok, det = False, f'{type(e).__name__}: {e}'
        res.append((name, bool(ok), str(det)))
    return res


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr31 stage-cache KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='sc31-mut-') as d:
            mut = Path(d) / PATHS[key]
            mut.parent.mkdir(parents=True, exist_ok=True)
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            try:
                compile(mut.read_text(encoding='utf-8'), str(mut), 'exec')
            except SyntaxError as e:
                print(f'  INVALID   {why}: mutant does not load ({e})')
                missed += 1
                continue
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, cpl = K.classify(failed, OWNERS.get(defect(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
        coupled += bool(cpl)
    print('\n' + K.summary('r31 stage-cache KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
