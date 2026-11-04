#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the r25 harness residuals of dero-rft §7 B49.

  HR1 kit/roundtracks.miner_relevant: while the miner track is paused, a node-side change to a package the miner binary
      is built from (rpc/, block/, config/...) runs S4b/S4c like a miner change; a test file, a subdirectory that is not
      a dependency (rpc/sub/ under rpc; cmd/derod/rpc/ is another package), a non-source file and a version-string-only config/version.go do not.
      r25 (verify): go.mod and a non-test vendor/ source do too (the miner imports vendored packages); a vendor test or README does not.
      miner_dep_dirs parses `go list -deps` output; version_only reads a -U0 diff.
  HR2 the live tree: `go list -deps ./cmd/dero-miner` names rpc and config among the dependencies, never cmd/derod/rpc
      (skipped, with the reason, when the go tool is missing).
  HR3 go_mutate.flaky_target_result: a mutation guarded by a listed-flaky test is CAUGHT only when the mutant fails at
      least 2 of 3 re-runs; 1 of 3 is MISSED (the first red run may have been the flake).
  HR4 fix_build_verify.reexec_argv: --root of another checkout re-runs THAT checkout's pipeline with the same arguments
      minus --root (both spellings); --root of this repo, or none, does not re-exec.

  python3 -I harness/kat/test_harness_r25.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import ast, importlib.util, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
RT = HARNESS / 'kit' / 'roundtracks.py'
GM = HARNESS / 'intel' / 'go_mutate.py'
FBV = HARNESS / 'pipeline' / 'fix_build_verify.py'


def load(path):
    spec = importlib.util.spec_from_file_location(f'h25_{abs(hash(str(path)))}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def extract(path, names):
    """the named top-level functions of a large module, compiled alone (fix_build_verify.py does work at import)"""
    tree = ast.parse(Path(path).read_text(encoding='utf-8'))
    body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
    ns = {'Path': Path, 'sys': sys}
    exec(compile(ast.Module(body=body, type_ignores=[]), str(path), 'exec'), ns)   # noqa: S102 — this repo's own code
    return type('M', (), {n: staticmethod(ns[n]) for n in names})


def hr1(R, *_):
    deps = R.miner_dep_dirs('/r/x/rpc\n/r/x/config\n/r/x/block\n/r/x/cmd/dero-miner\n/elsewhere/vendor/x\n', '/r/x')
    vo = R.version_only('--- a/config/version.go\n+++ b/config/version.go\n@@ -23 +23 @@\n'
                        '-var Version = semver.MustParse("3.6.0-153.X+1.r24")\n+var Version = semver.MustParse("3.6.0-153.X+1.r25")\n')
    vno = R.version_only('-var Version = semver.MustParse("a")\n+var Version = semver.MustParse("b")\n+const X = 1\n')
    changed = ['rpc/daemon_rpc.go', 'rpc/daemon_rpc_test.go', 'cmd/derod/rpc/getinfo.go', 'rpc/sub/notadep.go', 'config/version.go', 'block/block.go',
               'block/README.md', 'cmd/dero-miner/miner.go', 'harness/x.py', 'astrobwt/astrobwtv3/pow.go',
               'go.mod', 'vendor/github.com/x/y/y.go', 'vendor/github.com/x/y/y_test.go', 'vendor/github.com/x/y/README.md']
    got = R.miner_relevant(changed, deps, version_is_only=True)
    got2 = R.miner_relevant(['config/version.go'], deps, version_is_only=False)
    want = ['astrobwt/astrobwtv3/pow.go', 'block/block.go', 'cmd/dero-miner/miner.go', 'go.mod', 'rpc/daemon_rpc.go',
            'vendor/github.com/x/y/y.go']   # r25 (verify): module build inputs rebuild the miner
    ok = deps == ['block', 'cmd/dero-miner', 'config', 'rpc'] and vo and not vno and got == want and got2 == ['config/version.go']
    return ok, f'deps {deps} version_only {vo}/{vno} relevant {got} / {got2}'


def hr2(R, *_):
    if shutil.which('go') is None:
        return True, 'SKIP: no go tool on PATH'
    r = subprocess.run(R.MINER_DEPS_CMD, cwd=ROOT, capture_output=True, text=True, timeout=300)
    deps = R.miner_dep_dirs(r.stdout, ROOT.resolve())
    ok = r.returncode == 0 and 'rpc' in deps and 'config' in deps and 'cmd/dero-miner' in deps and 'cmd/derod/rpc' not in deps
    return ok, f'{len(deps)} first-party deps, e.g. {deps[:6]}'


def hr3(_, G, *__):
    got = [G.flaky_target_result({'pass': 0, 'fail': 3}, 'T')[0], G.flaky_target_result({'pass': 1, 'fail': 2}, 'T')[0],
           G.flaky_target_result({'pass': 2, 'fail': 1}, 'T')[0], G.flaky_target_result(None, 'T')[0]]
    return got == ['CAUGHT', 'CAUGHT', 'MISSED', 'MISSED'], f'got {got}'


def hr4(_, __, F):
    with tempfile.TemporaryDirectory() as d:
        a = F.reexec_argv(['--project-only', '--root', d], d, ROOT)
        b = F.reexec_argv([f'--root={d}', '--project-only', '--contended-ok'], d, ROOT)
        c = F.reexec_argv(['--project-only', '--root', str(ROOT)], str(ROOT), ROOT)
        e = F.reexec_argv(['--project-only'], None, ROOT)
        tail = str(Path(d).resolve() / 'harness/pipeline/fix_build_verify.py')
    ok = a is not None and a[2] == tail and a[3:] == ['--project-only'] and b[3:] == ['--project-only', '--contended-ok'] \
        and c is None and e is None
    return ok, f'a {a and a[2:]} b {b and b[3:]} c {c} e {e}'


KATS = [('HR1', hr1), ('HR2', hr2), ('HR3', hr3), ('HR4', hr4)]
MUTATIONS = [   # (file, find, replace, why)
    (RT, "        if p in MODULE_INPUTS or (p.startswith('vendor/')", "        if False and (p.startswith('vendor/')",
     'r25 (verify): a go.mod / vendored-source change rebuilds the miner without the A/B'),
    (RT, "                                  and not p.endswith('_test.go')):", "                                  ):",
     'r25 (verify): a vendored test file runs the miner A/B'),
    (RT, "        if d not in deps or f.endswith('_test.go') or not f.endswith(('.go', '.c', '.h', '.s')):",
     "        if d not in deps or not f.endswith(('.go', '.c', '.h', '.s')):", 'a test file of a dependency runs the miner A/B'),
    (RT, "        if d not in deps or f.endswith('_test.go') or not f.endswith(('.go', '.c', '.h', '.s')):",
     "        if not any(p.startswith(x + '/') for x in deps) or f.endswith('_test.go') or not f.endswith(('.go', '.c', '.h', '.s')):",
     'a subdirectory of a dependency (rpc/sub under rpc) counts as the dependency'),
    (RT, "        if p == VERSION_FILE and version_is_only:\n            continue\n", "",
     'a version-string-only config/version.go runs the miner A/B every round'),
    (RT, "    return bool(ch) and all('semver.MustParse(' in l and 'Version' in l for l in ch)",
     "    return bool(ch)", 'a config/version.go change beyond the version string is exempt'),
    (RT, "            out.add(l[len(root):].strip('/'))\n        elif", "            pass\n        elif",
     'the go list output is not read: node-side dependency changes are missed (B49)'),
    (GM, "    if c.get('fail', 0) >= FLAKY_MIN_PASS:", "    if c.get('fail', 0) >= 1:",
     'one red re-run of a flaky-guarded mutant counts as CAUGHT'),
    (FBV, "        if x == '--root':\n            skip = True\n            continue\n", "", "--root's value passed on to the re-run"),
    (FBV, "    if not root or Path(root).resolve() == Path(here).resolve():", "    if not root:",
     'a --root of this repo re-execs itself'),
]


def mods(rt=RT, gm=GM, fbv=FBV):
    return load(rt), load(gm), extract(fbv, ['reexec_argv'])


def run(R, G, F):
    out = []
    for name, fn in KATS:
        try:
            o, det = fn(R, G, F)
        except Exception as e:                                    # noqa: BLE001
            o, det = False, f'{type(e).__name__}: {e}'
        out.append((name, o, det))
    return out


def main():
    res = run(*mods())
    for n, o, det in res:
        print(f"{'ok  ' if o else 'FAIL'} {n} {det[:300]}")
    if not all(o for _, o, _ in res):
        return 3
    missed = 0
    for path, find, repl, why in MUTATIONS:
        text = path.read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??      {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / path.name
            p.write_text(text.replace(find, repl, 1), encoding='utf-8')
            try:
                M = mods(**{{RT: 'rt', GM: 'gm', FBV: 'fbv'}[path]: p})
            except Exception as e:                                # noqa: BLE001
                print(f'  INVALID {why}: mutant does not load ({type(e).__name__})')
                missed += 1
                continue
            survived = all(o for _, o, _ in run(*M))
        print(f"  {'MISSED ' if survived else 'proved '} {why}")
        missed += survived
    print(f'\nr25 harness KATs: {len(KATS)}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
