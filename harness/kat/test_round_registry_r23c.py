#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the r23c round registry (harness/round.json; no network, no live file written).

  RR1 the committed registry is clean: round_problems finds no error against this checkout's config/version.go and
      git (every commit-like id resolves), and the current round is the one fix_build_verify loaded.
  RR2 round_problems FAILS each forged registry: two rounds with one id, a current round that is not listed, two rounds
      in-progress, an unknown status, a commit id that does not resolve, an absent field (instead of "pending"), a
      planned round carrying a result (a number before the round ran is a guess), a shipped round with no pipeline
      record, an upstream_base the pipeline does not use, a go_mutations value that is not caught/total, a current
      shipped round whose version config/version.go does not carry, an implemented round (r23c: merged, pipeline run,
      not yet measured live) with no pipeline record or whose version config/version.go does not carry. An in-progress round whose version is still the
      previous shipped one only WARNS. r24: a round's `tracks` (artifacts/dero-rft.md §0.3) must map known tracks
      (miner, node) to active|paused: an unknown value ('Paused'), a non-object and an unknown track name each FAIL; a
      valid one ({'miner': 'paused', 'node': 'active'}) passes clean.
  RR3 resolve_new_tests_base: --new-tests-base wins; then the current round's new_tests_base; 'pending' or no registry
      falls back to HEAD (the pre-r23c default), and the source is reported.
  RR4 version_suffix_of reads the +suffix of the MustParse literal; benchlock.lock_path takes $DERO_BENCHLOCK, else the
      registry, and refuses 'pending' (None), so a bench never runs under a lock nobody else holds.

  python3 -I harness/kat/test_round_registry_r23c.py   # KATs, then each mutation on a temp copy must flip its KAT
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import copy, importlib.util, json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
MODS = {'fbv': 'pipeline/fix_build_verify.py', 'bl': 'pipeline/benchlock.py', 'rt': 'kit/roundtracks.py'}   # r24: rt


def load(base, name):
    spec = importlib.util.spec_from_file_location(f'{name}_{id(base)}_{len(sys.modules)}', base / MODS[name])
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def commit_ok(v):
    return subprocess.run(['git', 'rev-parse', '--verify', '-q', f'{v}^{{commit}}'], cwd=ROOT,
                          capture_output=True).returncode == 0


def version_now(m):
    return m.version_suffix_of((ROOT / 'config/version.go').read_text())


def kat_rr1(base):
    m = load(base, 'fbv')
    reg = json.loads((ROOT / 'harness/round.json').read_text())
    err, warn = m.round_problems(reg, version_now(m), commit_ok)
    ok = not err and m.CUR_ROUND.get('id') == reg['current'] or False
    return ok, f'errors={err} warnings={warn} current={m.CUR_ROUND.get("id")}'


def forged(reg):
    """(label, forged registry, must_error) — each forgery must produce an error, the last one only a warning"""
    out = []

    def f(label, fn, must=True):
        r = copy.deepcopy(reg)
        fn(r)
        out.append((label, r, must))
    f('repeated id', lambda r: r['rounds'].append(copy.deepcopy(r['rounds'][0])))
    f('current not listed', lambda r: r.__setitem__('current', 'r99'))
    f('two in-progress', lambda r: r['rounds'][-1].__setitem__('status', 'in-progress'))
    f('unknown status', lambda r: r['rounds'][0].__setitem__('status', 'done'))
    f('unresolvable commit', lambda r: r['rounds'][0].__setitem__('merge_commit', 'deadbee'))
    f('absent field', lambda r: r['rounds'][0].pop('head_after'))
    f('planned with a result', lambda r: r['rounds'][-1].__setitem__('go_mutations', '900/900'))
    f('shipped without pipeline', lambda r: r['rounds'][0].__setitem__('pipeline_full', 'pending'))
    f('other upstream_base', lambda r: r.__setitem__('upstream_base', 'cd1be86'))
    f('go_mutations not caught/total', lambda r: r['rounds'][0].__setitem__('go_mutations', 'all'))
    f('current shipped, version differs', lambda r: (r.__setitem__('current', 'r23b'),
                                                     r['rounds'][0].__setitem__('version_suffix', '22102026.r23x')))
    f('implemented without pipeline', lambda r: (r.__setitem__('current', 'r23b'),                     # r23c: only the
                                                 r['rounds'][1].update(status='implemented',             # missing record
                                                                       version_suffix='22102026.r23c',   # can fail it
                                                                       merge_commit='cd1be86', head_after='cd1be86')))
    f('current implemented, version differs', lambda r: (r['rounds'][1].update(status='implemented', version_suffix='22102026.r23c',
                                                                                merge_commit='cd1be86', head_after='cd1be86',
                                                                                pipeline_full='pipeline_x')))
    f('tracks value not active|paused', lambda r: r['rounds'][1].__setitem__('tracks', {'miner': 'Paused'}))   # r24
    f('tracks not an object', lambda r: r['rounds'][1].__setitem__('tracks', ['miner']))
    f('unknown track name', lambda r: r['rounds'][1].__setitem__('tracks', {'minr': 'paused'}))
    f('valid tracks (clean)', lambda r: r['rounds'][1].__setitem__('tracks', {'miner': 'paused', 'node': 'active'}), must=False)
    f('in-progress on the previous version (warn only)', lambda r: None, must=False)
    return out


BASE_REG = {'current': 'r23c', 'upstream_base': 'bf274e5', 'benchlock': 'pending', 'rounds': [
    {'id': 'r23b', 'status': 'shipped', 'version_suffix': '22102026.r23b', 'new_tests_base': '21cd5b7',
     'merge_commit': '3224c07', 'head_after': 'cd1be86', 'pipeline_full': 'pipeline_20261030T215745',
     'go_mutations': '853/853', 'new_rpc_methods': {}, 'github_sync': {'base': 'c7ded01', 'target': 'cd1be86'}},
    {'id': 'r23c', 'status': 'in-progress', 'version_suffix': 'pending', 'new_tests_base': 'cd1be86',
     'merge_commit': 'pending', 'head_after': 'pending', 'pipeline_full': 'pending', 'go_mutations': 'pending',
     'new_rpc_methods': {}, 'github_sync': {'base': 'cd1be86', 'target': 'pending'}},
    {'id': 'r24', 'status': 'planned', 'version_suffix': 'pending', 'new_tests_base': 'pending',
     'merge_commit': 'pending', 'head_after': 'pending', 'pipeline_full': 'pending', 'go_mutations': 'pending',
     'new_rpc_methods': {}, 'github_sync': {'base': 'pending', 'target': 'pending'}}]}


def kat_rr2(base):
    m = load(base, 'fbv')
    known = {'21cd5b7', '3224c07', 'cd1be86', 'c7ded01'}                 # a fixed commit oracle: no git needed
    e0, w0 = m.round_problems(BASE_REG, '22102026.r23b', known.__contains__)
    if e0 or w0:
        return False, f'clean fixture reported errors={e0} warnings={w0}'
    bad = []
    for label, reg, must in forged(BASE_REG):
        e, w = m.round_problems(reg, '22102026.r23b', known.__contains__)
        if must and not e:
            bad.append(f'{label}: no error')
        if not must and (e or w):
            bad.append(f'{label}: errors={e} warnings={w}')
    e, w = m.round_problems(BASE_REG, '22102026.r23c', known.__contains__)
    if e or not w:
        bad.append(f'in-progress with an unregistered version must warn only: errors={e} warnings={w}')
    return not bad, '; '.join(bad) or f'{len(forged(BASE_REG))} forgeries judged'


def kat_rr3(base):
    m = load(base, 'fbv')
    cur = BASE_REG['rounds'][1]
    got = [m.resolve_new_tests_base('abc1234', cur), m.resolve_new_tests_base(None, cur),
           m.resolve_new_tests_base(None, BASE_REG['rounds'][2]), m.resolve_new_tests_base(None, {})]
    want = [('abc1234', 'cli'), ('cd1be86', 'round.json'), ('HEAD', 'default'), ('HEAD', 'default')]
    return got == want, f'got {got}'


def kat_rr4(base):
    m = load(base, 'fbv')
    bl = load(base, 'bl')
    v = m.version_suffix_of('var Version = semver.MustParse("3.6.0-153.DEROHE.STARGATE+22102026.r23b")')
    old = os.environ.pop('DERO_BENCHLOCK', None)
    try:
        os.environ['DERO_BENCHLOCK'] = '/x/bench.lock'
        a = bl.lock_path()
        del os.environ['DERO_BENCHLOCK']
        b = bl.lock_path()                       # the committed registry (r24: names a lock; earlier rounds 'pending')
        # r24: the 'pending' refusal is checked on its own registry, so the proof holds whatever the live one names
        root0 = bl.ROOT
        with tempfile.TemporaryDirectory(prefix='rr4-') as t:
            (Path(t) / 'harness').mkdir()
            (Path(t) / 'harness/round.json').write_text(json.dumps({'benchlock': 'pending'}))
            bl.ROOT = Path(t)
            try:
                c = bl.lock_path()
            finally:
                bl.ROOT = root0
    finally:
        if old is not None:
            os.environ['DERO_BENCHLOCK'] = old
    reg = json.loads((base / 'round.json').read_text())
    want_b = None if reg.get('benchlock') in (None, 'pending') else os.path.expanduser(reg['benchlock'])
    ok = v == '22102026.r23b' and a == '/x/bench.lock' and b == want_b and c is None
    return ok, f'suffix={v} env={a} registry={b} (want {want_b}) pending-registry={c} (want None)'


KATS = [('RR1', kat_rr1), ('RR2', kat_rr2), ('RR3', kat_rr3), ('RR4', kat_rr4)]

MUTATIONS = [
    ('RR2', 'fbv', "    if sum(1 for r in rounds if isinstance(r, dict) and r.get('status') == 'in-progress') > 1:",
     "    if False:", 'two rounds in-progress pass'),
    ('RR2', 'fbv', "        if st == 'planned':", "        if st == 'never':", 'a planned round may carry results'),
    ('RR2', 'fbv', "            elif known(v) and not commit_ok(v):", "            elif False:", 'commit ids are not resolved'),
    ('RR2', 'fbv', "    if reg.get('upstream_base') != UPSTREAM_BASE:", "    if False:", 'upstream_base is not compared'),
    ('RR2', 'fbv', "        if cur.get('status') in ROUND_DONE and want != version_suffix:",
     "        if False:", 'a shipped current round may disagree with config/version.go'),
    ('RR2', 'fbv', "        if st in ROUND_DONE:\n            err += [f'{rid}: {st} round lacks {f}'",
     "        if st in ('shipped', 'measured'):\n            err += [f'{rid}: {st} round lacks {f}'", 'an implemented round may lack its version, merge or pipeline'),
    ('RR3', 'fbv', "    if known((cur or {}).get('new_tests_base')):", "    if (cur or {}).get('new_tests_base'):",
     "'pending' is used as a revision"),
    ('RR3', 'fbv', "    if cli:\n        return cli, 'cli'", "    if False:\n        return cli, 'cli'", 'the CLI no longer wins'),
    ('RR4', 'bl', "    return os.path.expanduser(v) if v and v != PENDING else None",
     "    return os.path.expanduser(v) if v else None", "'pending' becomes a lock file"),
    # r24: the tracks check is wired into round_problems, and an unknown value is an error
    ('RR2', 'fbv', "    err += track_problems(reg)", "    err += []", 'round_problems ignores the tracks field'),
    ('RR2', 'rt', "            if v not in TRACK_VALUES:", "            if False:", "a tracks value other than active|paused passes"),
    ('RR2', 'rt', "            if k not in TRACKS:", "            if False:", 'an unknown track name passes'),
]


def copy_tree():
    """<tmp>/harness/{pipeline/*, round.json}: the same layout, so both modules find the copy's registry"""
    d = Path(tempfile.mkdtemp(prefix='rr23c-')) / 'harness'
    for rel in MODS.values():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HARNESS / rel, d / rel)
    shutil.copy2(HARNESS / 'round.json', d / 'round.json')
    return d


def main():
    fails = 0
    base = copy_tree()
    for name, fn in KATS:
        try:
            ok, det = fn(base)
        except Exception as e:                                    # noqa: BLE001
            ok, det = False, f'{type(e).__name__}: {e}'
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:400]}")
    shutil.rmtree(base.parent, ignore_errors=True)
    missed, byname = 0, dict(KATS)
    for kat, mod, find, repl, why in MUTATIONS:
        d = copy_tree()
        p = d / MODS[mod]
        text = p.read_text()
        if text.count(find) != 1:
            print(f'  ??      {kat}: {why} — find text occurs {text.count(find)} times')
            missed += 1
            shutil.rmtree(d.parent, ignore_errors=True)
            continue
        p.write_text(text.replace(find, repl))
        try:                                                        # r23c review: a mutant that does not load is
            load(d, mod)                                            # INVALID, never CAUGHT (EVIDENCE_LOOP; R22 lesson)
        except Exception as e:                                      # noqa: BLE001
            print(f'  INVALID {kat}: {why} — mutant does not load ({type(e).__name__})')
            missed += 1
            shutil.rmtree(d.parent, ignore_errors=True)
            continue
        try:
            ok2 = byname[kat](d)[0]
        except Exception:                                          # noqa: BLE001 — a crash is a detection
            ok2 = False
        print(f"  {'proved ' if not ok2 else 'MISSED '} {kat}: {why}")
        missed += ok2
        shutil.rmtree(d.parent, ignore_errors=True)
    print(f'\nr23c round-registry KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
