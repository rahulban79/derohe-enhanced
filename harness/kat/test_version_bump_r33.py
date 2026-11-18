#!/usr/bin/env python3
"""test_version_bump_r33.py — r33 GT-B20 (artifacts/dero-game-theory-rft.md §7, lesson 33): a round that changes a
consensus package ships a node build that names the round.

Lesson 33: the R32a node build ran as `+22102026.r31` because config/version.go was not bumped with the round's first
consensus-package change, so derod could not say which round it was. The rule, over harness/round.json:
  V1 classifier  a consensus-package file is any file under blockchain/, transaction/, cryptography/, block/ or config/
                 (config/version.go itself excluded: the bump is not a change it requires) and any non-test .go file
                 under dvm/
  V2 bump        for every round whose version_suffix is not 'pending': if a consensus-package file changed between
                 the round's new_tests_base and its head commit (head_after; merge_commit when head_after is pending —
                 round.json's merge_commit predates the bump in r26..r31, the head is what the round shipped), then
                 config/version.go AT that commit carries exactly that suffix as its build metadata (`+<suffix>"`)
  V3 own round   when such a change touched a non-test file (the binary changed), the suffix names the round itself
                 (ends with `.<round id>`): a round may only inherit the previous round's suffix (r32 '22102026.r31')
                 when nothing the binary is built from changed
  V4 scope       pending rounds are skipped; a round whose commits are missing from the clone is a failure, not a skip
KAT VB1 runs V1-V4 on the real history; VB2 plants each rule's defect in a temporary git repository and requires the
checker to catch it; the mutation proofs undo each rule in this file's own checker and require VB2 to fail.

  python3 -I harness/kat/test_version_bump_r33.py      # exit 0 PASS · 3 a KAT failed · 4 a mutation missed
"""
import contextlib, importlib.util, io, json, os, re, subprocess, sys, tempfile, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
CONSENSUS_DIRS = ('blockchain/', 'transaction/', 'cryptography/', 'block/', 'config/')
VERSION_FILE = 'config/version.go'
META_RX = re.compile(r'MustParse\("[^"+]*\+([^"]+)"\)')


def is_consensus(path):
    """V1. Pure."""
    if path == VERSION_FILE:
        return False
    if path.startswith('dvm/'):
        return path.endswith('.go') and not path.endswith('_test.go')
    return path.startswith(CONSENSUS_DIRS)


def git(repo, *args):
    p = subprocess.run(['git', '-C', str(repo), *args], capture_output=True, text=True, timeout=120)
    return p.returncode, p.stdout


def head_commit(r):
    """the commit a round shipped (V2): head_after, else merge_commit; None when both are pending. Pure."""
    for k in ('head_after', 'merge_commit'):
        c = r.get(k)
        if c and c != 'pending':
            return c
    return None


def check_round(repo, r):
    """(verdict, detail) for one round: 'skip' (pending), 'ok', 'FAIL'. Reads git only."""
    suf, base, head = r.get('version_suffix'), r.get('new_tests_base'), head_commit(r)
    if not suf or suf == 'pending':
        return 'skip', 'pending suffix'
    if not head and r.get('status') == 'in-progress':
        head = 'HEAD'              # r33: a round in progress is checked up to the current HEAD (its head commit is set at close)
    if not base or base == 'pending' or not head:
        return 'FAIL', 'suffix set but no new_tests_base/head commit'
    rc, out = git(repo, 'diff', '--name-only', base, head)
    if rc != 0:
        return 'FAIL', f'git diff {base}..{head} failed (commit missing?)'
    changed = [p for p in out.split('\n') if p and is_consensus(p)]
    if not changed:
        return 'ok', 'no consensus-package change'
    rc, vtext = git(repo, 'show', f'{head}:{VERSION_FILE}')
    m = META_RX.search(vtext) if rc == 0 else None
    meta = m.group(1) if m else None
    if meta != suf:
        return 'FAIL', f'{len(changed)} consensus file(s) changed ({changed[0]}...) but {VERSION_FILE}@{head} carries {meta!r}, not {suf!r}'
    if any(not p.endswith('_test.go') for p in changed) and not suf.endswith('.' + str(r.get('id'))):
        return 'FAIL', f'a non-test consensus file changed but the suffix {suf!r} does not name the round {r.get("id")}'
    return 'ok', f'{len(changed)} consensus file(s) changed; {VERSION_FILE} carries +{suf}'


def check_all(repo, rounds):
    return [(r.get('id'), *check_round(repo, r)) for r in rounds]


def kat_vb1(chk):
    rounds = json.loads((ROOT / 'harness/round.json').read_text())['rounds']
    res = chk.check_all(ROOT, rounds)
    bad = [x for x in res if x[1] == 'FAIL']
    checked = [x for x in res if x[1] == 'ok']
    return not bad and len(checked) >= 10, bad or f'{len(checked)} rounds ok, {len(res) - len(checked)} skipped'


def _commit(repo, files, msg):
    for rel, text in files.items():
        f = Path(repo) / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    subprocess.run(['git', '-C', str(repo), 'add', '-A'], check=True, capture_output=True)
    subprocess.run(['git', '-C', str(repo), '-c', 'user.name=kat', '-c', 'user.email=kat@localhost', 'commit', '-q', '-m', msg],
                   check=True, capture_output=True)
    return git(repo, 'rev-parse', 'HEAD')[1].strip()


def _ver(meta):
    return f'package config\n\nvar Version = semver.MustParse("3.6.0-153.DEROHE.STARGATE+{meta}")\n'


def kat_vb2(chk):
    """each rule's planted defect is caught; each legitimate case passes"""
    with tempfile.TemporaryDirectory(prefix='vb33-') as d:
        env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
        os.environ.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
        try:
            subprocess.run(['git', 'init', '-q', d], check=True, capture_output=True, env=env)
            c0 = _commit(d, {VERSION_FILE: _ver('22102026.r1'), 'README': 'x', 'dvm/sc.go': 'package dvm', 'blockchain/a.go': 'package b'}, 'base')
            c1 = _commit(d, {'blockchain/a.go': 'package b // change'}, 'consensus change, no bump')
            c2 = _commit(d, {VERSION_FILE: _ver('22102026.r2')}, 'bump')
            c3 = _commit(d, {'README': 'y', 'dvm/sc_test.go': 'package dvm', VERSION_FILE: _ver('22102026.r2x')}, 'no consensus change')
            c4 = _commit(d, {'transaction/t_test.go': 'package t'}, 'test-only consensus change')
            c5 = _commit(d, {'cryptography/c.go': 'package c', VERSION_FILE: _ver('22102026.r2')}, 'non-test change, inherited suffix')
            c6 = _commit(d, {'config/config.go': 'package config'}, 'config change')
            c7 = _commit(d, {'block/b.go': 'package block', VERSION_FILE: _ver('22102026.r7x')}, 'a longer metadata')
            cases = {
                'V2 no bump': ({'id': 'r2', 'version_suffix': '22102026.r2', 'new_tests_base': c0, 'head_after': c1}, 'FAIL'),
                'V2 bumped': ({'id': 'r2', 'version_suffix': '22102026.r2', 'new_tests_base': c0, 'head_after': c2}, 'ok'),
                'V2 merge fallback': ({'id': 'r2', 'version_suffix': '22102026.r2', 'new_tests_base': c0, 'merge_commit': c2,
                                       'head_after': 'pending'}, 'ok'),
                'V2 exact metadata': ({'id': 'r7', 'version_suffix': '22102026.r7', 'new_tests_base': c6, 'head_after': c7}, 'FAIL'),
                'V1 version.go/dvm test/other only': ({'id': 'r3', 'version_suffix': '22102026.r3', 'new_tests_base': c2, 'head_after': c3}, 'ok'),
                'V1 test-only change inherits': ({'id': 'r4', 'version_suffix': '22102026.r2x', 'new_tests_base': c3, 'head_after': c4}, 'ok'),
                'V1 test-only change needs the recorded suffix': ({'id': 'r4', 'version_suffix': '22102026.r4', 'new_tests_base': c3,
                                                                    'head_after': c4}, 'FAIL'),
                'V3 non-test change inherits a suffix': ({'id': 'r5', 'version_suffix': '22102026.r2', 'new_tests_base': c4,
                                                          'head_after': c5}, 'FAIL'),
                'V1 config/ counts': ({'id': 'r6', 'version_suffix': '22102026.r2', 'new_tests_base': c5, 'head_after': c6}, 'FAIL'),
                'V4 pending skipped': ({'id': 'r7', 'version_suffix': 'pending', 'new_tests_base': c0, 'head_after': c1}, 'skip'),
                'V4 missing commit': ({'id': 'r8', 'version_suffix': '22102026.r8', 'new_tests_base': '0' * 40, 'head_after': c1}, 'FAIL'),
            }
            got = {k: chk.check_round(d, r)[0] for k, (r, _) in cases.items()}
        finally:
            for k in ('GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM'):
                os.environ.pop(k, None)
    wrong = {k: (got[k], want) for k, (_, want) in cases.items() if got[k] != want}
    return not wrong, wrong or f'{len(cases)}/{len(cases)} planted and legitimate cases classified'


KATS = [('VB1', kat_vb1), ('VB2', kat_vb2)]
OWNERS = {'r33 classifier': ['VB2'], 'r33 bump': ['VB2'], 'r33 ownround': ['VB2'], 'r33 scope': ['VB2']}
MUTATIONS = [
    ("    if path == VERSION_FILE:\n        return False\n", "", 'r33 classifier: a version.go-only change demands a bump'),
    ("        return path.endswith('.go') and not path.endswith('_test.go')", "        return True", 'r33 classifier: a dvm test file counts'),
    ("CONSENSUS_DIRS = ('blockchain/', 'transaction/', 'cryptography/', 'block/', 'config/')",
     "CONSENSUS_DIRS = ('blockchain/', 'transaction/', 'cryptography/', 'block/')", 'r33 classifier: config/ is not a consensus package'),
    ("    if meta != suf:", "    if suf not in vtext:", 'r33 bump: a suffix prefix matches a longer build metadata'),
    ("    if meta != suf:", "    if False:", 'r33 bump: a missing bump passes'),
    ("    if any(not p.endswith('_test.go') for p in changed) and not suf.endswith('.' + str(r.get('id'))):", "    if False:",
     'r33 ownround: a binary change may inherit the previous round suffix'),
    ("    for k in ('head_after', 'merge_commit'):", "    for k in ('head_after',):", 'r33 scope: a pending head_after skips the merge commit'),
    ("        return 'FAIL', f'git diff {base}..{head} failed (commit missing?)'", "        return 'skip', 'missing'",
     'r33 scope: a missing commit is skipped'),
]


def load(path):
    spec = importlib.util.spec_from_file_location(f'vb33_{uuid.uuid4().hex[:6]}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def katmut():
    return load(ROOT / 'harness/kit/katmut.py')


def run_kats(chk, only=None):
    res = []
    for name, fn in KATS:
        if only and name not in only:
            continue
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                ok, det = fn(chk)
        except Exception as e:                                    # noqa: BLE001 — a crash is a failure
            ok, det = False, f'{type(e).__name__}: {e}'
        res.append((name, bool(ok), str(det)))
    return res


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    me = sys.modules[__name__]
    res = run_kats(me)
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:600]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr33 version-bump KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    text = Path(__file__).read_text(encoding='utf-8')
    cut = text.index('\ndef kat_vb1(')                    # the checker (V1-V4) is everything above the KATs
    missed = coupled = 0
    for find, repl, why in MUTATIONS:
        if text[:cut].count(find) != 1:
            print(f'  ??        {why}: find text occurs {text[:cut].count(find)} times in the checker')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='vb33-mut-') as d:
            f = Path(d) / 'mutant.py'
            f.write_text((text[:cut].replace(find, repl, 1) + text[cut:]).replace("ROOT = Path(__file__).resolve().parent.parent.parent",
                                                              f"ROOT = Path({str(ROOT)!r})", 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats(load(f), only={'VB2'}) if not ok]
        verdict, cpl = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
        coupled += bool(cpl)
    print('\n' + K.summary('r33 version-bump KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
