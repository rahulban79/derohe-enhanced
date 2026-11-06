#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the R27b resource-hygiene tools (dero-rft §5 resource-hygiene rule, §0.9,
§7 B148): the read-only resource probe, the fan-out preflight (resource_intel, benchlock --heavy, the pipeline's S3b/S3c),
the scratch GC and the backup_scratch.sh excludes.

  RH1 resource_intel parsers: vm.swapusage before/after the 2026-11-05 fseventsd restart, memory_pressure free %; the
      process census keeps BASENAMES and sums only (no pid, args or path: a planted home path and a project arg never
      reach the output); readings() calls memory_pressure with -Q only (without it the tool APPLIES pressure) and runs
      no kill / killall / pkill / renice / launchctl / sudo / taskpolicy command.
  RH2 level(): the measured BEFORE state (swap 64,739 MB used, 797 free, 42 % free, fseventsd 21.5 GB) is HOLD; the
      measured AFTER state (5,014 used, 1,130 free of a 6,144 MB dynamic swap, 90 % free) is OK, and still OK with
      swap free 900 MB (dynamic swap: free alone is not headroom); swap used 40 GB alone is HOLD; 42 % alone, fseventsd
      21 GB alone and 315 clone trees alone are each REDUCE; an unreadable swap is never OK.
  RH3 preflight(): jobs on HOLD is 1 (serial, never 0), clones on HOLD 0; OK keeps the plan; REDUCE halves it under
      the memory cap; a memory cap of 0 is still 1 job; the notes line names stage, level, planned, recommended.
  RH4 --help of resource_intel.py, scratch_gc.py and benchlock.py exits 0 and writes nothing (isolated copies); an
      unknown resource_intel flag exits 2; `preflight --notes F` appends exactly one '[HH:MM] preflight' line to F.
  RH5 scratch_gc on synthetic clone trees (a reference repo, `git clone --shared` trees, patches + .md5): DRY RUN writes
      nothing anywhere (every file and mtime of the scratch root and the reference unchanged); verdicts: good tree
      DELETE (its referenced ignored file listed as evidence, the unreferenced one not); md5 mismatch C4; drift after
      the patch C5; an untracked file the patch lacks C5; a stash C3; a detached local HEAD C3; a protected tree C1; a
      .git FILE C1; a fresh tree C2; a tree whose only fresh mtime is in .git/objects (a hardlinked pack freshened by
      the source repo) DELETE; a back-dated empty blob in the reference keeps its mtime (no `add -N` freshen). --apply deletes exactly the DELETE trees, copies the evidence to
      <dim>/evidence_from_tree/tree/, writes <dim>/tree.gc.json, and its recipe (clone --shared, checkout base, apply)
      reproduces the patch byte for byte. A root holding the reference or under ~/dero-data is refused (exit 2);
      judge() keeps a tree inside the reference (C1 forbidden).
  RH6 scratch_gc.freed_bytes: a hardlinked inode counts only when every link is deleted.
  RH7 backup_scratch.sh (the live script, $DERO_BACKUP_SCRATCH or ~/derohe-persist/backup_scratch.sh, run on planted
      dirs with its source glob and destination rewritten to a temp dir): tree/, verify_tree/, applycheck/ and any
      .git/ are NOT mirrored; the patch, .md5, verify.md, findings.md and a plain base/ file ARE; LAST_BACKUP is
      written. Pending (not failed) on a machine without the script.
  RH8 benchlock --heavy: parse_opts reads --heavy (the r25 3-tuple form unchanged); heavy_slots on HOLD is 1, on OK the
      plan; try_slot refuses a held slot and gives the next; --heavy --gpu is refused (exit 2); a --heavy run in an
      isolated copy runs the command and appends the decision to $DERO_ROUND_NOTES; a '--help' after '--' reaches the
      command (benchlock's own --help is only its leading argument).
  RH9 fix_build_verify: heavy_preflight returns 1 on HOLD and records a 'preflight' event + notes line, returns the plan
      when the probe raises; race_args adds -p and scales the timeout (6 h cap), none at full width; s3c_race passes
      the preflight's -p into `go test -race`, s3b_mutate records a preflight.

  python3 -I harness/kat/test_resource_hygiene_r27.py [--before DIR]
--before DIR runs the KATs against the files of another checkout (DIR/<same path>): the pre-r27b tree FAILS.
Mutation independence (harness/kit/katmut.py): each mutation's reason starts with its defect id (r27b RH<n>); OWNERS maps
it to the KAT(s) that own it; a mutation caught only by another KAT is WRONG-KAT, one that also fails others is coupled.
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not proved (MISSED, WRONG-KAT, INVALID) or was coupled (target 0).
"""
import ast, hashlib, importlib.util, json, os, re, shutil, subprocess, sys, tempfile, threading, time
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
RI = HARNESS / 'intel' / 'resource_intel.py'
GC = HARNESS / 'pipeline' / 'scratch_gc.py'
BL = HARNESS / 'pipeline' / 'benchlock.py'
FBV = HARNESS / 'pipeline' / 'fix_build_verify.py'
HOME_PLANT = '/' + 'Users' + '/someone'


def backup_script():
    p = os.environ.get('DERO_BACKUP_SCRATCH') or str(Path.home() / 'derohe-persist' / 'backup_scratch.sh')
    return Path(p) if Path(p).is_file() else None


def load(path, name='rh27'):
    spec = importlib.util.spec_from_file_location(f'{name}_{abs(hash(str(path)))}_{len(sys.modules)}', path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


def extract(path, names, extra=None):
    """the named top-level functions of a large module, compiled alone (fix_build_verify does work at import)"""
    tree = ast.parse(Path(path).read_text(encoding='utf-8'))
    body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
    ns = {'Path': Path, 'sys': sys, 'os': os, 'json': json, 're': re, 'importlib': importlib, 'HARNESS': HARNESS,
          'ROOT': ROOT, **(extra or {})}
    exec(compile(ast.Module(body=body, type_ignores=[]), str(path), 'exec'), ns)   # noqa: S102 — this repo's own code
    return type('M', (), {n: staticmethod(ns[n]) for n in names})


def fn_src(path, name):
    tree = ast.parse(Path(path).read_text(encoding='utf-8'))
    return ast.unparse(next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name))


BEFORE_SWAP = 'total = 65536.00M  used = 64739.25M  free = 796.75M  (encrypted)'
AFTER_SWAP = 'total = 6144.00M  used = 5014.19M  free = 1129.81M  (encrypted)'


def reading(swap=AFTER_SWAP, free=90, fse=12.6, trees=10, ram=131072, ri=None):
    return {'swap': ri.parse_swap(swap) if swap else None, 'memory_free_pct': free, 'ram_mb': ram,
            'procs': {'watch': {'fseventsd': fse, 'mds_stores': 1500.0, 'mds': 200.0, 'derod': 146.0}, 'project': {}},
            'scratchpad': {'clone_trees': trees}}


# ───────────────────────────── RH1 ─────────────────────────────
def rh1(P):
    R = load(P['ri'], 'ri1')
    sb, sa = R.parse_swap(BEFORE_SWAP), R.parse_swap(AFTER_SWAP)
    fp = R.parse_free_pct('The system has 137438953472 (8388608 pages with a page size of 16384).\n'
                          'System-wide memory free percentage: 42%\n')
    rows = [(101, 22_000_000, '/System/Library/Frameworks/CoreServices.framework/Versions/A/Support/fseventsd', ''),
            (102, 150_000, './bin/derod', f'./bin/derod --data-dir {HOME_PLANT}/dero-data'),
            (103, 50_000, '/opt/homebrew/bin/python3.12', f'python3 {HOME_PLANT}/derohe-Release151/harness/x.py'),
            (104, 1_000, 'python3', 'python3 unrelated.py'),
            (105, 4_800_000, 'rsync', f'rsync -a <scratch> {HOME_PLANT}/derohe-persist')]
    c = R.classify(rows, self_pid=999)
    dump = json.dumps(c)
    private = [s for s in ('someone', '/', '101', '103', 'dero-data', 'harness') if s in dump]
    calls = []

    def fake_run(cmd, timeout=30):
        calls.append(list(cmd))
        return {'sysctl': (0, '137438953472' if 'hw.memsize' in cmd else AFTER_SWAP),
                'memory_pressure': (0, 'System-wide memory free percentage: 90%'),
                'ps': (0, '')}.get(cmd[0], (1, ''))
    R.run = fake_run
    r = R.readings(scratch=[], quick=True)
    mp = [x for x in calls if x[0] == 'memory_pressure']
    bad = [x for x in calls if x[0] in ('kill', 'killall', 'pkill', 'renice', 'launchctl', 'sudo', 'taskpolicy')]
    ok = (sb == {'total_mb': 65536.0, 'used_mb': 64739.25, 'free_mb': 796.75} and sa['used_mb'] == 5014.19 and fp == 42
          and c['watch']['fseventsd'] == round(22_000_000 / 1024, 1) and c['watch']['derod'] == 146.5
          and c['project']['count'] == 2 and not private and mp == [['memory_pressure', '-Q']] and not bad
          and r['memory_free_pct'] == 90 and r['swap']['total_mb'] == 6144.0)
    return ok, f'swap {sb} / {sa} free {fp} census {c} private {private} memory_pressure calls {mp} forbidden {bad}'


# ───────────────────────────── RH2 ─────────────────────────────
def rh2(P):
    R = load(P['ri'], 'ri2')
    cases = {
        'before': (reading(BEFORE_SWAP, 42, 21500.0, 218, ri=R), 'HOLD'),
        'after': (reading(ri=R), 'OK'),
        'after, swap free 900': (reading('total = 6144.00M  used = 5244.00M  free = 900.00M', ri=R), 'OK'),
        'swap used 40 GB alone': (reading('total = 45056.00M  used = 40000.00M  free = 5056.00M', 60, ri=R), 'HOLD'),
        '42 % alone': (reading(free=42, ri=R), 'REDUCE'),
        'fseventsd 21 GB alone': (reading(fse=21000.0, ri=R), 'REDUCE'),
        '315 trees alone': (reading(trees=315, ri=R), 'REDUCE'),
        'swap unreadable': (reading(swap=None, ri=R), 'REDUCE'),
        'free 15 %': (reading(free=15, ri=R), 'HOLD'),
    }
    got = {k: R.level(r)[0] for k, (r, _) in cases.items()}
    bad = {k: (got[k], w) for k, (_, w) in cases.items() if got[k] != w}
    return not bad, f'levels {got} wrong {bad}'


# ───────────────────────────── RH3 ─────────────────────────────
def rh3(P):
    R = load(P['ri'], 'ri3')
    hold = reading(BEFORE_SWAP, 42, 21500.0, 218, ri=R)
    a = R.preflight(hold, 20, 'jobs')['recommended']
    b = R.preflight(hold, 8, 'clones')['recommended']
    c = R.preflight(reading(ri=R), 20, 'jobs')['recommended']
    d = R.preflight(reading(ri=R), 8, 'clones')['recommended']
    e = R.preflight(reading(free=42, ri=R), 20, 'jobs')['recommended']        # mem cap 14, REDUCE half 10
    f = R.preflight(reading(free=21, ri=R), 20, 'jobs')['recommended']        # mem cap 0 -> still 1
    line = R.note_line('race', R.preflight(hold, 20, 'jobs'), when='11:00')
    ok = (a, b, c, d, e, f) == (1, 0, 20, 8, 10, 1) and line.startswith('[11:00] preflight race: HOLD kind=jobs planned=20 recommended=1')
    return ok, f'hold jobs {a} clones {b} · ok jobs {c} clones {d} · reduce {e} · cap0 {f} · {line[:120]!r}'


# ───────────────────────────── RH4 ─────────────────────────────
def run_isolated(src_files, rel_script, args, env=None, pre=None):
    with tempfile.TemporaryDirectory() as d:
        r = Path(d)
        for rel, src in src_files.items():
            (r / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, r / rel)
        (r / 'harness/runtime').mkdir(parents=True, exist_ok=True)
        if pre:
            pre(r)
        before = {p for p in r.rglob('*') if p.is_file()}
        e = {k: v for k, v in os.environ.items() if k not in ('DERO_BENCHLOCK', 'DERO_ROUND_NOTES', 'DERO_HEAVY_SLOTS')}
        e.update({'HOME': str(r), **{k: v.replace('{R}', str(r)) for k, v in (env or {}).items()}})
        p = subprocess.run([sys.executable, '-I', str(r / rel_script), *[x.replace('{R}', str(r)) for x in args]], cwd=r,
                           capture_output=True, text=True, timeout=300, env=e)
        after = {p for p in r.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
        notes = (r / 'notes.md').read_text() if (r / 'notes.md').exists() else ''
        return p.returncode, p.stdout + p.stderr, sorted(str(x.relative_to(r)) for x in after - before), notes


def rh4(P):
    ri = {'harness/intel/resource_intel.py': P['ri']}
    r1 = run_isolated(ri, 'harness/intel/resource_intel.py', ['--help'])
    r2 = run_isolated(ri, 'harness/intel/resource_intel.py', ['--bogus'])
    r3 = run_isolated({'harness/pipeline/scratch_gc.py': P['gc']}, 'harness/pipeline/scratch_gc.py', ['--help'])
    r4 = run_isolated({'harness/pipeline/benchlock.py': P['bl']}, 'harness/pipeline/benchlock.py', ['--help'])
    r5 = run_isolated(ri, 'harness/intel/resource_intel.py', ['preflight', '--planned', '3', '--kind', 'clones',
                                                               '--stage', 'kat', '--scratch', '{R}/harness', '--notes', '{R}/notes.md'])
    lines = r5[3].splitlines()
    ok = (r1[0] == 0 and 'usage' in r1[1] and not r1[2] and r2[0] == 2 and not r2[2] and r3[0] == 0 and 'usage' in r3[1]
          and not r3[2] and r4[0] == 0 and '--heavy' in r4[1] and not r4[2] and r5[0] in (0, 5, 6)
          and len(lines) == 1 and re.match(r'^\[\d\d:\d\d\] preflight kat: (OK|REDUCE|HOLD) kind=clones planned=3', lines[0])
          and r5[2] == ['notes.md'])
    return ok, (f'ri --help rc {r1[0]} wrote {r1[2]} · --bogus rc {r2[0]} · gc --help rc {r3[0]} wrote {r3[2]} · bl --help '
                f'rc {r4[0]} wrote {r4[2]} · preflight rc {r5[0]} wrote {r5[2]} notes {lines}')


# ───────────────────────────── RH5 / RH6 ─────────────────────────────
GENV = {**{k: v for k, v in os.environ.items() if not k.startswith('GIT_')}, 'GIT_AUTHOR_NAME': 'kat', 'GIT_AUTHOR_EMAIL': 'kat@example.invalid',
        'GIT_COMMITTER_NAME': 'kat', 'GIT_COMMITTER_EMAIL': 'kat@example.invalid', 'GIT_CONFIG_GLOBAL': os.devnull,
        'GIT_CONFIG_NOSYSTEM': '1'}


def g(cwd, *a):
    return subprocess.run(['git', '-c', 'init.defaultBranch=main', *a], cwd=cwd, check=True, capture_output=True, env=GENV).stdout


def snapshot(*tops):
    out = {}
    for t in tops:
        for p in Path(t).rglob('*'):
            st = os.lstat(p)
            out[str(p)] = (st.st_mtime_ns, st.st_size, p.is_dir())
    return out


def make_patch(tree, patch, with_untracked=True, bad_md5=False):
    if with_untracked:
        g(tree, 'add', '-N', '.')
    data = g(tree, 'diff', '--binary', 'HEAD')
    Path(patch).write_bytes(data)
    Path(str(patch) + '.md5').write_text(('0' * 32 if bad_md5 else hashlib.md5(data).hexdigest()) + '\n')
    return data


def build_scratch(d):
    ref = d / 'reference'
    ref.mkdir()
    (ref / 'a.txt').write_text('alpha\n')
    (ref / 'b.bin').write_bytes(bytes(range(256)))
    (ref / '.gitignore').write_text('*.log\nbuild/\n')
    g(ref, 'init', '-q')
    g(ref, 'add', '.')
    g(ref, 'commit', '-q', '-m', 'base')
    root = d / 'scratch' / 'r99'
    trees = {}

    def clone(dim, name='tree'):
        (root / dim).mkdir(parents=True, exist_ok=True)
        t = root / dim / name
        g(root / dim, 'clone', '-q', '--shared', str(ref), name)
        trees[f'{dim}/{name}'] = t
        return t
    t = clone('good')
    (t / 'a.txt').write_text('alpha changed\n')
    (t / 'new.txt').write_text('new file\n')
    (t / 'b.bin').write_bytes(bytes(range(255, -1, -1)))
    (t / 'build').mkdir()
    (t / 'build' / 'out.log').write_text('evidence the notes cite\n')
    (t / 'x.log').write_text('scratch nobody cites\n')
    make_patch(t, root / 'good' / 'good.patch')
    (root / 'good' / 'findings.md').write_text('# good\nthe run log is tree/build/out.log (kept)\n')
    t = clone('md5bad')
    (t / 'a.txt').write_text('alpha md5\n')
    make_patch(t, root / 'md5bad' / 'md5bad.patch', bad_md5=True)
    t = clone('drift')
    (t / 'a.txt').write_text('alpha drift\n')
    make_patch(t, root / 'drift' / 'drift.patch')
    (t / 'a.txt').write_text('alpha drift, edited after the patch\n')
    t = clone('untr')
    (t / 'a.txt').write_text('alpha untr\n')
    make_patch(t, root / 'untr' / 'untr.patch', with_untracked=False)
    (t / 'only_here.txt').write_text('not in the patch\n')
    t = clone('stash')
    (t / 'a.txt').write_text('stashed work\n')
    g(t, 'stash', '-q')
    make_patch(t, root / 'stash' / 'stash.patch')
    t = clone('local')
    (t / 'a.txt').write_text('local commit\n')
    g(t, 'commit', '-q', '-am', 'local')
    g(t, 'checkout', '-q', '--detach')
    g(t, 'branch', '-f', 'main', 'origin/main')
    make_patch(t, root / 'local' / 'local.patch')
    t = clone('prot')
    make_patch(t, root / 'prot' / 'prot.patch')
    (root / 'wt' / 'tree').mkdir(parents=True)
    (root / 'wt' / 'tree' / '.git').write_text('gitdir: /nowhere\n')
    t = clone('objfresh')
    (t / 'a.txt').write_text('alpha objfresh\n')
    make_patch(t, root / 'objfresh' / 'objfresh.patch')
    old = time.time() - 7200
    for p in list(root.rglob('*')) + [root]:
        os.utime(p, (old, old), follow_symlinks=False)
    obj = next(p for p in (root / 'objfresh' / 'tree' / '.git' / 'objects').rglob('*') if p.is_file())
    os.utime(obj, None)
    t = clone('fresh')                                  # created after the ageing: fresh
    make_patch(t, root / 'fresh' / 'fresh.patch')
    return ref, root, trees


WANT = {'good/tree': 'DELETE', 'md5bad/tree': 'C4', 'drift/tree': 'C5', 'untr/tree': 'C5', 'stash/tree': 'C3',
        'local/tree': 'C3', 'prot/tree': 'C1', 'wt/tree': 'C1', 'objfresh/tree': 'DELETE', 'fresh/tree': 'C2'}


def gc_run(P, d, ref, root, *extra):
    env = {**os.environ, 'HOME': str(d)}
    p = subprocess.run([sys.executable, '-I', str(P['gc']), '--root', str(root), '--protect', str(root / 'prot'),
                        '--reference', str(ref), '--min-age', '60', '--json', *extra], capture_output=True, text=True,
                       timeout=600, env=env)
    try:
        return p.returncode, json.loads(p.stdout), p.stderr
    except ValueError:
        return p.returncode, None, (p.stdout + p.stderr)[-400:]


def rh5(P):
    with tempfile.TemporaryDirectory() as td:
        d = Path(td).resolve()
        ref, root, trees = build_scratch(d)
        # r27b integration: the reference already holds the empty blob (the live repo does, in a pack); `git add -N`
        # would freshen it (utime), so a back-dated copy must keep its mtime through the dry run
        eb = subprocess.run(['git', 'hash-object', '-w', '--stdin'], cwd=ref, input=b'', capture_output=True, check=True,
                            env=GENV).stdout.decode().strip()
        os.utime(ref / '.git' / 'objects' / eb[:2] / eb[2:], (946684800, 946684800))
        s0 = snapshot(d)
        rc, out, err = gc_run(P, d, ref, root)
        s1 = snapshot(d)
        if out is None:
            return False, f'dry run rc {rc}: {err}'
        rows = {r['tree']: r for r in out['rows']}
        verdict = {k: ('DELETE' if r['verdict'] == 'DELETE' else r.get('why', '')[:2]) for k, r in rows.items()}
        wrong = {k: (verdict.get(k), w) for k, w in WANT.items() if verdict.get(k) != w}
        changed = sorted(k for k in set(s0) | set(s1) if s0.get(k) != s1.get(k))
        ev = rows.get('good/tree', {}).get('evidence')
        rc2, out2, err2 = gc_run(P, d, ref, root, '--apply')
        gone = sorted(k for k, t in trees.items() if not t.exists())
        copied = (root / 'good' / 'evidence_from_tree' / 'tree' / 'build' / 'out.log').is_file()
        uncited = (root / 'good' / 'evidence_from_tree' / 'tree' / 'x.log').exists()
        rec = json.loads((root / 'good' / 'tree.gc.json').read_text()) if (root / 'good' / 'tree.gc.json').is_file() else {}
        repro = False
        if rec:
            t = d / 'repro'
            g(d, 'clone', '-q', '--shared', str(ref), 'repro')
            g(t, 'checkout', '-q', rec['base'])
            g(t, 'apply', '--binary', str(root / 'good' / 'good.patch'))
            g(t, 'add', '-N', '.')
            repro = g(t, 'diff', '--binary', rec['base']) == (root / 'good' / 'good.patch').read_bytes()
        (d / 'home_dd' / 'dero-data' / 'x').mkdir(parents=True)
        rf1 = subprocess.run([sys.executable, '-I', str(P['gc']), '--root', str(d), '--reference', str(ref)],
                             capture_output=True, text=True, env={**os.environ, 'HOME': str(d / 'elsewhere')}).returncode
        rf2 = subprocess.run([sys.executable, '-I', str(P['gc']), '--root', str(d / 'home_dd' / 'dero-data' / 'x'),
                              '--reference', str(ref)], capture_output=True, text=True,
                             env={**os.environ, 'HOME': str(d / 'home_dd')}).returncode
        M = load(P['gc'], 'gc5')
        g(d, 'clone', '-q', '--shared', str(ref), 'reference/inner')
        jf = M.judge(ref / 'inner', d, str(ref), [], 0, '').get('why', '')
        ok = (not wrong and not changed and ev == ['build/out.log'] and rc2 == 0 and gone == ['good/tree', 'objfresh/tree']
              and copied and not uncited and rec.get('patch_md5') == hashlib.md5((root / 'good' / 'good.patch').read_bytes()).hexdigest()
              and repro and rf1 == 2 and rf2 == 2 and jf.startswith('C1 forbidden'))
        return ok, (f'wrong {wrong} · dry-run changed {[os.path.relpath(c, d) for c in changed[:4]]} · evidence {ev} · apply rc {rc2} gone {gone} · copied '
                    f'{copied} uncited {uncited} · repro {repro} · refuse {rf1}/{rf2} · judge-in-reference {jf!r}')


def rh6(P):
    M = load(P['gc'], 'gc6')
    a = {(1, 10): (2, 4096), (1, 11): (1, 100)}
    b = {(1, 10): (2, 4096)}
    return M.freed_bytes([a]) == 100 and M.freed_bytes([a, b]) == 4196, f'one {M.freed_bytes([a])} both {M.freed_bytes([a, b])}'


# ───────────────────────────── RH7 ─────────────────────────────
def rh7(P):
    src = P.get('bk')
    if src is None:
        return True, 'pending: no backup_scratch.sh on this machine'
    text = Path(src).read_text()
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        t, n1 = re.subn(r'(?m)^DST=.*$', f'DST={d}/dst', text)
        t, n2 = re.subn(r'for src in \S+; do', f'for src in {d}/src/-proj-*; do', t)
        if (n1, n2) != (1, 1):
            return False, f'script shape changed (DST lines {n1}, source loops {n2})'
        (d / 'bk.sh').write_text(t)
        dim = d / 'src' / '-proj-x' / 'sess' / 'scratchpad' / 'r99' / 'dim'
        for rel in ('tree/a.go', 'tree/.git/HEAD', 'verify_tree/b.go', 'applycheck/c.go', 'base/.git/HEAD', 'base/plain.txt',
                    'dim.patch', 'dim.patch.md5', 'verify.md', 'findings.md', 'evidence/e.json'):
            (dim / rel).parent.mkdir(parents=True, exist_ok=True)
            (dim / rel).write_text(rel + '\n')
        p = subprocess.run(['bash', str(d / 'bk.sh')], capture_output=True, text=True, timeout=120)
        m = d / 'dst' / '-proj-x' / 'sess' / 'scratchpad' / 'r99' / 'dim'
        absent = ['tree', 'verify_tree', 'applycheck', 'base/.git']
        present = ['dim.patch', 'dim.patch.md5', 'verify.md', 'findings.md', 'evidence/e.json', 'base/plain.txt']
        leaked = [a for a in absent if (m / a).exists()]
        lost = [a for a in present if not (m / a).is_file()]
        last = (d / 'dst' / 'LAST_BACKUP').is_file()
        return p.returncode == 0 and not leaked and not lost and last, f'rc {p.returncode} mirrored-but-excluded {leaked} lost {lost} LAST_BACKUP {last} {p.stderr[-200:]!r}'


# ───────────────────────────── RH8 ─────────────────────────────
def rh8(P):
    B = load(P['bl'], 'bl8')
    R = load(P['ri'], 'ri8')
    po = B.parse_opts(['--heavy', '--qos=utility', '--', 'x'], with_heavy=True)
    old = B.parse_opts(['--gpu', '--', 'x'])
    k_hold = B.heavy_slots(2, R, reading(BEFORE_SWAP, 42, 21500.0, 218, ri=R))[0]
    k_ok = B.heavy_slots(2, R, reading(ri=R))[0]
    with tempfile.TemporaryDirectory() as td:
        lp = str(Path(td) / 'lock')
        f0 = B.try_slot(lp, 1)
        f1 = B.try_slot(lp, 1)
        f2 = B.try_slot(lp, 2)
        slots = (f0 is not None, f1 is None, f2 is not None)
        for f in (f0, f1, f2):
            if f:
                f.close()
    files = {'harness/pipeline/benchlock.py': P['bl'], 'harness/intel/resource_intel.py': P['ri']}
    g1 = run_isolated(files, 'harness/pipeline/benchlock.py', ['--heavy', '--gpu', '--', 'true'], env={'DERO_BENCHLOCK': '{R}/lock'})
    g2 = run_isolated(files, 'harness/pipeline/benchlock.py',
                      ['--heavy', '--', sys.executable, '-c', "open('ran.txt','w').write('1')"],
                      env={'DERO_BENCHLOCK': '{R}/lock', 'DERO_ROUND_NOTES': '{R}/notes.md'})
    g3 = run_isolated(files, 'harness/pipeline/benchlock.py',     # r27b merge: a command's own --help is passed through
                      ['--heavy', '--', sys.executable, '-c', "import sys; open('help.txt','w').write(sys.argv[1])", '--help'],
                      env={'DERO_BENCHLOCK': '{R}/lock'})
    ok = (po == (False, 'utility', True, ['x']) and old == (True, 'none', ['x']) and k_hold == 1 and k_ok == 2
          and slots == (True, True, True) and g1[0] == 2 and g2[0] == 0 and 'ran.txt' in g2[2]
          and re.search(r'preflight benchlock --heavy: (OK|REDUCE|HOLD) kind=jobs planned=2', g2[3])
          and g3[0] == 0 and 'help.txt' in g3[2])
    return bool(ok), (f'opts {po} old {old} K hold {k_hold} ok {k_ok} slots {slots} --gpu rc {g1[0]} run rc {g2[0]} wrote {g2[2]} '
                      f'notes {g2[3][:100]!r} · cmd --help rc {g3[0]} wrote {g3[2]}')


# ───────────────────────────── RH9 ─────────────────────────────
def rh9(P):
    R = load(P['ri'], 'ri9')
    ev = []
    F = extract(P['fbv'], ['heavy_preflight', 'race_args'],
                {'event': lambda *a, **kv: ev.append((a[0], a[1], kv)), 'RESOURCE_INTEL': P['ri']})
    with tempfile.TemporaryDirectory() as td:
        notes = Path(td) / 'n.md'
        os.environ['DERO_ROUND_NOTES'] = str(notes)
        try:
            a = F.heavy_preflight('race', 20, R, reading(BEFORE_SWAP, 42, 21500.0, 218, ri=R))
        finally:
            os.environ.pop('DERO_ROUND_NOTES', None)
        nl = notes.read_text() if notes.exists() else ''

    class Boom:
        @staticmethod
        def preflight(*a, **k):
            raise RuntimeError('probe down')
    b = F.heavy_preflight('mutate', 7, Boom, {})
    ra = (F.race_args(1, 20), F.race_args(20, 20), F.race_args(10, 20))
    s3c, s3b = fn_src(P['fbv'], 's3c_race'), fn_src(P['fbv'], 's3b_mutate')
    src_ok = ("race_args(heavy_preflight('race', cpus), cpus)" in s3c and '*pargs' in s3c and 'timeout=tmo' in s3c
              and "heavy_preflight('mutate'" in s3b)
    ok = (a == 1 and ev[0][0] == 'preflight' and ev[0][2].get('level') == 'HOLD' and 'preflight pipeline race: HOLD' in nl
          and b == 7 and ev[-1][2].get('level') == 'unreadable'
          and ra == ((['-p', '1'], 21600), ([], 3600), (['-p', '10'], 7200)) and src_ok)
    return ok, f'hold -> {a} event {ev[:1]} notes {nl[:80]!r} · probe down -> {b} · race_args {ra} · stages wired {src_ok}'


KATS = [('RH1', rh1), ('RH2', rh2), ('RH3', rh3), ('RH4', rh4), ('RH5', rh5), ('RH6', rh6), ('RH7', rh7), ('RH8', rh8),
        ('RH9', rh9)]
PATHS = {'ri': RI, 'gc': GC, 'bl': BL, 'fbv': FBV, 'bk': backup_script()}

MUTATIONS = [   # (key, find, replace, why)
    ('ri', "        if sw['used_mb'] >= HOLD_SWAP_USED_MB:", "        if False:", 'r27b RH2: a full swap (used) is not HOLD'),
    ('ri', "        if sw['free_mb'] < HOLD_SWAP_FREE_MB and free is not None and free < REDUCE_FREE_PCT:",
     "        if sw['free_mb'] < HOLD_SWAP_FREE_MB:", 'r27b RH2: dynamic swap: a small free swap with RAM free is HOLD'),
    ('ri', "        elif free < REDUCE_FREE_PCT:", "        elif False:", 'r27b RH2-RH3: memory free 42 % is OK'),
    ('ri', "    if fse is not None and fse >= REDUCE_FSEVENTSD_MB:", "    if False:", 'r27b RH2: a 21 GB fseventsd is OK'),
    ('ri', "    if isinstance(trees, int) and trees > REDUCE_CLONE_TREES:", "    if False:", 'r27b RH2: 315 clone trees are OK'),
    ('ri', "    if kind == 'jobs':\n        rec = max(1, rec)", "    if False:\n        rec = max(1, rec)", 'r27b RH3: a heavy gate can be told 0 (skipped)'),
    ('ri', "        rec = 0 if kind == 'clones' else 1", "        rec = 1", 'r27b RH3: HOLD still launches a clone'),
    ('ri', "        rec = min(rec, max(1, planned // 2))", "        rec = rec", 'r27b RH3: REDUCE does not reduce'),
    ('ri', "        top[name] = round(top.get(name, 0) + rss / 1024, 1)", "        top[args] = round(top.get(args, 0) + rss / 1024, 1)",
     'r27b RH1: the census leaks process arguments (paths)'),
    ('ri', "    rc, out = run(['memory_pressure', '-Q'])", "    rc, out = run(['memory_pressure'])",
     'r27b RH1: memory_pressure without -Q (it would APPLY pressure)'),
    ('gc', "                out.append((p, md5_claim(m) == md5_of(p)))", "                out.append((p, True))", 'r27b RH5: C4: the .md5 is not checked'),
    ('gc', "            rc, _ = git(tree, 'update-index', '--add', '--info-only', '--', *unt[i:i + 200], env=env)", "            rc = 0",
     'r27b RH5: C5: untracked files are left out of the diff'),
    ('gc', "'update-index', '--add', '--info-only', '--', *unt", "'add', '-N', '--', *unt",
     'r27b RH5: the dry run enters untracked files with add -N (writes the empty blob: freshens the reference pack)'),
    ('gc', "            if not in_obj and not (dp == os.path.join(str(tree), '.git') and n == 'objects'):", "            if True:",
     'r27b RH5: C2: a source-repo pack freshen keeps every hardlinked tree for ever'),
    ('gc', "    if now - newest < min_age_s:", "    if False:", 'r27b RH5: C2: a fresh tree is deleted'),
    ('gc', "    for d in protect:\n        if under(tree, d):", "    for d in []:\n        if under(tree, d):", 'r27b RH5: C1: --protect ignored'),
    ('gc', "    for d in forbidden_dirs(reference):\n        if under(tree, d):", "    for d in []:\n        if under(tree, d):",
     'r27b RH5: C1: a tree inside the reference repo is judged'),
    ('gc', "        if git(reference, 'cat-file', '-e', o)[0]:", "        if False:", 'r27b RH5: C3: a stash is lost'),
    ('gc', "    if git(reference, 'cat-file', '-e', f'{base}^{{commit}}')[0]:", "    if False:", 'r27b RH5: C3: a local HEAD commit is lost'),
    ('gc', "        if not r.is_dir() or any(under(r, d) for d in forbidden_dirs(a.reference)) or any(under(d, r) for d in hard):",
     "        if not r.is_dir():", 'r27b RH5: a root holding the reference / under dero-data is accepted'),
    ('gc', "            shutil.copy2(s, t, follow_symlinks=False)", "            pass", 'r27b RH5: C6: evidence is not copied out'),
    ('gc', "    return any(t and t in corpus for t in toks)", "    return False", 'r27b RH5: C6: cited evidence is not found'),
    ('gc', "        if a.apply and row['verdict'] == 'DELETE':", "        if row['verdict'] == 'DELETE':", 'r27b RH5: the dry run deletes'),
    ('gc', "    return sum(b for c, nl, b in seen.values() if c >= nl)", "    return sum(b for c, nl, b in seen.values())",
     'r27b RH6: freed bytes count shared hardlinks'),
    ('bk', "--exclude=tree/ ", "", 'r27b RH7: backup mirrors tree/'),
    ('bk', "--exclude=verify_tree/ ", "", 'r27b RH7: backup mirrors verify_tree/'),
    ('bk', " --exclude=.git/", "", 'r27b RH7: backup mirrors .git/'),
    ('bl', "    return max(1, d['recommended']), d, ri", "    return planned, d, ri", 'r27b RH8: heavy slots ignore the preflight'),
    ('bl', "            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)", "            pass", 'r27b RH8: a held heavy slot is handed out again'),
    ('bl', "__import__('sys').argv[1:2] in (['-h'], ['--help'])", "False", 'r27b RH4: benchlock --help runs'),
    ('bl', "__import__('sys').argv[1:2] in (['-h'], ['--help'])", "{'-h', '--help'} & set(__import__('sys').argv[1:])",
     "r27b RH8: a command's own --help after '--' is swallowed by benchlock's usage"),
    ('bl', "        if gpu:\n            print('[benchlock] --heavy with --gpu", "        if False:\n            print('[benchlock] --heavy with --gpu",
     'r27b RH8: --heavy --gpu skips the GPU bench lock'),
    ('fbv', "    return max(1, d['recommended'])\n", "    return planned\n", 'r27b RH9: the pipeline ignores the preflight'),
    ('fbv', "    pargs, tmo = race_args(heavy_preflight('race', cpus), cpus)", "    pargs, tmo = [], 3600", 'r27b RH9: S3c runs no preflight'),
    ('fbv', "    return ['-p', str(p)], min(6 * 3600, int(base_timeout * cpus / max(1, p)))", "    return ['-p', str(p)], base_timeout",
     'r27b RH9: a serial S3c keeps the full-width timeout (it would time out, not run)'),
    ('fbv', "    heavy_preflight('mutate', 1)", "    pass", 'r27b RH9: S3b records no preflight'),
]

# katmut (harness/kit/katmut.py, rft §0.9 rule 1): each mutation's reason starts with its defect id; the KAT(s) that own it
OWNERS = {f'r27b RH{i}': [f'RH{i}'] for i in range(1, 10)}
OWNERS['r27b RH2-RH3'] = ['RH2', 'RH3']      # memory free % decides the level (RH2) and the REDUCE concurrency (RH3)


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_rh27', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run_kats(P):
    res = []
    for name, fn in KATS:
        try:
            o, det = fn(P)
        except Exception as e:                                    # noqa: BLE001
            o, det = False, f'{type(e).__name__}: {e}'
        res.append((name, o, det))
    return res


def main(argv):
    paths = dict(PATHS)
    if argv[:1] == ['--before']:
        other = Path(argv[1])
        for k in ('ri', 'gc', 'bl', 'fbv'):
            paths[k] = other / PATHS[k].relative_to(ROOT)
    res = run_kats(paths)
    for name, o, det in res:
        print(f"{'ok  ' if o else 'FAIL'} {name} {det[:500]}")
    if not all(o for _, o, _ in res):
        return 3
    K = katmut()
    missed = pending = coupled = 0
    for key, find, repl, why in MUTATIONS:
        path = paths[key]
        if path is None:
            print(f'  pending {why}: no {key} file on this machine')
            pending += 1
            continue
        text = Path(path).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??      {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory() as d:
            try:
                rel = Path(path).resolve().relative_to(ROOT)
            except ValueError:
                rel = Path(Path(path).name)
            mut = Path(d) / rel
            mut.parent.mkdir(parents=True, exist_ok=True)
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            if mut.suffix == '.py':
                try:
                    compile(mut.read_text(encoding='utf-8'), str(mut), 'exec')
                except SyntaxError as e:
                    print(f'  INVALID {why}: mutant does not compile ({e.msg})')
                    missed += 1
                    continue
            res = run_kats({**paths, key: mut})
            failed = [n for n, o, _ in res if not o]
        verdict, extra = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else '')
              + (f'  coupled {extra}' if verdict == 'proved' and extra else ''))
        missed += verdict != 'proved'
        coupled += verdict == 'proved' and bool(extra)
    n = len(MUTATIONS) - pending
    print('\n' + K.summary('r27 resource-hygiene KATs', len(KATS), n, missed, coupled)
          + (f' ({pending} pending)' if pending else ''))
    return 4 if missed or coupled else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
