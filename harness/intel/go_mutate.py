#!/usr/bin/env python3
"""go_mutate.py — mutation coverage of the locally changed Go code.

For each entry of go_mutations.json: apply the source edit (which undoes a fix or weakens a rule), run the one test
that guards it, and restore the file byte-for-byte whatever happens. A mutation that leaves its test green is
MISSED: that fix is not really tested. A mutation whose `find` text is gone is STALE: the spec no longer matches the
code and must be updated, never skipped silently.

The restore-check after the mutations runs only the mutation tests of each package (r19), so an upstream test that
is red on the pristine base cannot break it. That made those failures invisible. --baseline REV (R20) adds a separate
comparison: every mutation package's FULL test run on this tree vs on REV (a detached worktree). A test that fails
on both is UPSTREAM and is recorded, not ignored. A test that fails only on this tree is OURS and fails the run (exit 7).

R22 (harness): two ways a mutation run hid a failure.
  * A mutation whose edited source does not COMPILE made `go test` fail with '[build failed]' and was counted CAUGHT:
    the test never ran, so the fix it claims to guard was never exercised. It is now INVALID (a spec bug, counted
    as a problem like STALE), never CAUGHT.
  * The source was restored in a `finally`, which a SIGKILL, a power cut or an OOM kill skips: the tree was left
    MUTATED (a weakened guard) and the next build shipped it. Before each edit the original bytes and their path go to
    a journal next to the spec (.go_mutate.journal + .go_mutate.orig, fsynced); the restore removes it, and every
    start restores a journal a dead run left behind before anything else.

r24 (B21): harness/loop/KNOWN_TEST_FAILURES.json lists the tests known to fail for reasons this tree did not introduce,
with evidence. The --baseline comparison still decides per run; the list adds two honest labels: an upstream failure
nobody listed is named ('upstream_unlisted'), and an OURS failure of a listed FLAKY test is re-run -count=3 here and
moves to 'known_flaky' only when at least FLAKY_MIN_PASS of FLAKY_RERUNS re-runs pass with no data race; otherwise it
stays OURS (NEWFAIL). Before r24 a load flake of Test_R22_MultiPayload_Distinct_Blinders (1 of 8 on 2026-11-02) failed
the whole S3b as if the change broke it.

  python3 harness/intel/go_mutate.py [--json out.json] [--only id-prefix] [--baseline REV]
  exit 0 all caught · 7 any missed, stale, invalid, broken or a new package-test failure
"""
import argparse, hashlib, json, os, re, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
JOURNAL = HERE / '.go_mutate.journal'
ORIG = HERE / '.go_mutate.orig'
BUILD_FAILED = re.compile(r'\[(build|setup) failed\]|^# \S+\n.*\.go:\d+:\d+: ', re.M)


def mutation_result(rc, text):
    """CAUGHT / MISSED / INVALID from one mutated test run. Pure. A run whose package did not build never ran the
    test: INVALID, not CAUGHT (R22)."""
    if rc == 0:
        return 'MISSED'
    if BUILD_FAILED.search(text or ''):
        return 'INVALID'
    return 'CAUGHT'


def _fsync_write(path, data):
    with open(path, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def journal_begin(path, orig, journal=None, origf=None):
    """record the file about to be mutated and its exact bytes, durably, BEFORE the edit"""
    journal, origf = journal or JOURNAL, origf or ORIG
    _fsync_write(origf, orig)
    _fsync_write(journal, json.dumps({'file': str(path), 'sha256': hashlib.sha256(orig).hexdigest()}).encode())


def journal_end(journal=None, origf=None):
    for p in (journal or JOURNAL, origf or ORIG):
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass


def journal_recover(journal=None, origf=None):
    """a journal left by a killed run: put the original bytes back (verified by hash). Returns the restored path, or
    None. A journal whose saved bytes do not match its hash is an error: the tree must be checked by hand."""
    journal, origf = Path(journal or JOURNAL), Path(origf or ORIG)
    if not journal.exists():
        return None
    j = json.loads(journal.read_text())
    data = origf.read_bytes()
    if hashlib.sha256(data).hexdigest() != j['sha256']:
        raise RuntimeError(f"go_mutate journal for {j['file']}: saved bytes do not match their hash; restore by hand (git)")
    _fsync_write(j['file'], data)
    journal_end(journal, origf)
    return j['file']


def failed_tests(go_test_json):
    """names of the tests that FAILED in `go test -json` output (top-level tests only; a subtest's failure also
    fails its parent). A package that does not build is reported as '<build>'."""
    out = set()
    for l in go_test_json.splitlines():
        try:
            e = json.loads(l)
        except ValueError:
            if re.match(r'^(FAIL\s+\S+\s+\[(build|setup) failed\]|# )', l):
                out.add('<build>')
            continue
        if e.get('Action') == 'fail':
            t = e.get('Test')
            if t is None:
                continue
            out.add(t.split('/')[0])
        elif e.get('Action') == 'output' and '[build failed]' in str(e.get('Output', '')):
            out.add('<build>')
    return out


def compare_failures(tree, base):
    """{pkg: set(failing tests)} on this tree and on the base -> {'ours': {...}, 'upstream': {...}} per package.
    Pure, so a KAT can feed it sets. A package missing on the base (new package) has no upstream failures."""
    res = {}
    for pkg in sorted(tree):
        b = base.get(pkg, set())
        res[pkg] = {'ours': sorted(tree[pkg] - b), 'upstream': sorted(tree[pkg] & b),
                    'fixed_here': sorted(b - tree[pkg])}
    return res


KNOWN = ROOT / 'harness/loop/KNOWN_TEST_FAILURES.json'
KNOWN_CLASSES = ('upstream-red', 'flaky')
FLAKY_RERUNS, FLAKY_MIN_PASS = 3, 2       # r24: a listed flaky test must pass at least 2 of 3 re-runs


def load_known(path=None):
    """{class: {pkg: set(tests)}} from KNOWN_TEST_FAILURES.json; empty when it is missing or unreadable (then nothing
    is relabelled: the pre-r24 behaviour)"""
    out = {c: {} for c in KNOWN_CLASSES}
    try:
        d = json.loads(Path(path or KNOWN).read_text())
    except (OSError, ValueError):
        return out
    for e in d.get('tests') or []:
        if isinstance(e, dict) and e.get('class') in KNOWN_CLASSES and e.get('pkg') and e.get('test'):
            out[e['class']].setdefault(e['pkg'], set()).add(e['test'])
    return out


def rerun_counts(go_test_json):
    """{test: {'pass': n, 'fail': n}} of top-level tests in `go test -count=N -json` output, and whether a data race
    was reported anywhere in it. Pure."""
    res, race = {}, False
    for l in go_test_json.splitlines():
        try:
            e = json.loads(l)
        except ValueError:
            race |= 'WARNING: DATA RACE' in l
            continue
        race |= 'WARNING: DATA RACE' in str(e.get('Output', ''))
        t = e.get('Test')
        if t and '/' not in t and e.get('Action') in ('pass', 'fail'):
            r = res.setdefault(t, {'pass': 0, 'fail': 0})
            r[e['Action']] += 1
    return res, race


def flaky_verdict(counts, race):
    """r24: a listed flaky test's re-runs -> 'known_flaky' (>= FLAKY_MIN_PASS passes, no race) or 'ours'. Pure."""
    return 'known_flaky' if not race and (counts or {}).get('pass', 0) >= FLAKY_MIN_PASS else 'ours'


def relabel(cmp_, known, rerun):
    """r24: compare_failures' result with the known list applied. `rerun(pkg, tests)` -> (counts, race) re-runs the
    listed-flaky OURS tests of one package -count=FLAKY_RERUNS. Adds per package 'known_flaky' {test: counts} and
    'upstream_unlisted'; a listed-flaky test whose re-runs do not clear it stays in 'ours'. Pure given `rerun`."""
    for pkg, c in cmp_.items():
        fl = sorted(set(c['ours']) & (known.get('flaky', {}).get(pkg) or set()))
        c['known_flaky'] = {}
        if fl:
            counts, race = rerun(pkg, fl)
            for tname in fl:
                if flaky_verdict(counts.get(tname), race) == 'known_flaky':
                    c['known_flaky'][tname] = counts.get(tname)
            c['ours'] = [x for x in c['ours'] if x not in c['known_flaky']]
        c['upstream_unlisted'] = sorted(set(c['upstream']) - (known.get('upstream-red', {}).get(pkg) or set()))
    return cmp_


def flaky_target_result(counts, test):
    """r25 (B49): the verdict of a mutation whose guarding test is listed flaky, from its -count=FLAKY_RERUNS re-runs
    UNDER the mutation: CAUGHT only when at least FLAKY_MIN_PASS of them fail (the mirror of the flaky rule: a listed
    flaky test passes 2 of 3 to be excused, a mutant must fail 2 of 3 to count as caught); otherwise MISSED, because
    the first red run may have been the flake. Pure."""
    c = counts or {}
    if c.get('fail', 0) >= FLAKY_MIN_PASS:
        return 'CAUGHT', f"{test} is listed flaky: the mutant failed {c.get('fail', 0)}/{FLAKY_RERUNS} re-runs"
    return 'MISSED', (f"{test} is listed flaky: the mutant failed only {c.get('fail', 0)}/{FLAKY_RERUNS} re-runs, so the "
                      'first failure may have been the flake (harness/loop/KNOWN_TEST_FAILURES.json)')


def rerun_here(pkg, tests, cwd=ROOT, timeout=1800):
    r = subprocess.run(['go', 'test', pkg, '-run', '^(' + '|'.join(tests) + ')$', f'-count={FLAKY_RERUNS}', '-json'],
                       cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return rerun_counts(r.stdout + r.stderr)


def package_result(rc, text):
    """failing tests of one package run; a failing run with no failing test named (timeout panic, TestMain or init
    panic) is '<package>', never OK (r20 merge, HR20-6 review). Pure."""
    if rc == 0:
        return set()
    f = failed_tests(text)
    return f or {'<package>'}


def package_failures(pkgs, cwd, timeout=1800):
    out = {}
    for pkg in pkgs:
        try:
            r = subprocess.run(['go', 'test', pkg, '-count=1', '-json'], cwd=cwd, capture_output=True, text=True,
                               timeout=timeout)
        except subprocess.TimeoutExpired:
            out[pkg] = {'<timeout>'}                       # recorded, not a crash of the whole run
            continue
        out[pkg] = package_result(r.returncode, r.stdout + r.stderr)
    return out


def baseline_compare(pkgs, rev):
    wt = Path(tempfile.mkdtemp(prefix='gomut-base-'))
    subprocess.run(['git', 'worktree', 'add', '--detach', str(wt), rev], cwd=ROOT, capture_output=True, text=True)
    try:
        if not (wt / 'go.mod').exists():
            return None, f'could not check out {rev}'
        base = package_failures([p for p in pkgs if (wt / p).is_dir()], wt)
        tree = package_failures(pkgs, ROOT)
        return relabel(compare_failures(tree, base), load_known(), rerun_here), None   # r24: B21 known list
    finally:
        subprocess.run(['git', 'worktree', 'remove', '--force', str(wt)], cwd=ROOT, capture_output=True, text=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--json')
    ap.add_argument('--only', help='run only the mutations whose id starts with this prefix')
    ap.add_argument('--baseline', help='also compare each mutation package\'s FULL test run with this git revision')
    a = ap.parse_args()
    restored = journal_recover()
    if restored:
        print(f'  RESTORED {restored}: a previous run was killed while it was mutated (journal)')
    spec = json.loads((HERE / 'go_mutations.json').read_text())
    known = load_known()                                  # r25 (B49): mutations that target a listed-flaky test
    if a.only:
        spec['mutations'] = [m for m in spec['mutations'] if m['id'].startswith(a.only)]
    res = []
    for m in spec['mutations']:
        p = ROOT / m['file']
        orig = p.read_bytes()
        text = orig.decode()
        if text.count(m['find']) != 1:
            res.append({**m, 'result': 'STALE', 'why': f"find text occurs {text.count(m['find'])} time(s)"})
            continue
        try:
            journal_begin(p, orig)
            p.write_text(text.replace(m['find'], m['replace'], 1))
            # -timeout: a mutation that removes a deadline would otherwise hang until go test's 10-minute default
            r = subprocess.run(['go', 'test', m['pkg'], '-run', f"^{m['test']}$", '-count=1', '-timeout', '120s']
                               + (['-race'] if m.get('race') else []), cwd=ROOT,
                               capture_output=True, text=True, timeout=900)
            result = mutation_result(r.returncode, r.stdout + r.stderr)
            why = (r.stdout + r.stderr).strip().splitlines()[-1:] if (r.stdout + r.stderr).strip() else ''
            if result == 'CAUGHT' and m['test'] in (known.get('flaky', {}).get(m['pkg']) or set()):
                # r25 (B49): a listed-flaky test can fail by itself, so one red run does not prove the mutation is caught
                rr = subprocess.run(['go', 'test', m['pkg'], '-run', f"^{m['test']}$", f'-count={FLAKY_RERUNS}', '-timeout',
                                     '360s', '-json'] + (['-race'] if m.get('race') else []), cwd=ROOT,
                                    capture_output=True, text=True, timeout=1800)
                result, why = flaky_target_result(rerun_counts(rr.stdout + rr.stderr)[0].get(m['test']), m['test'])
            res.append({**m, 'result': result, 'why': why})
        except subprocess.TimeoutExpired:
            res.append({**m, 'result': 'CAUGHT', 'why': 'the test hung under the mutation (a hang is a failure)'})
        finally:
            p.write_bytes(orig)                           # restore exactly, even on error or interrupt
            journal_end()
        # the restored file must build and pass its test again, or the run itself is invalid
    # r19: run the mutation tests of each package, not the whole package: walletapi and walletapi/xswd carry upstream
    # tests that fail on the pristine base too (Test_Creation_TX, TestXSWDServer, ...), which made this check BROKEN
    # for reasons no mutation touches.
    for pkg in sorted({m['pkg'] for m in spec['mutations']}):
        tests = sorted({m['test'] for m in spec['mutations'] if m['pkg'] == pkg})
        r = subprocess.run(['go', 'test', pkg, '-run', '^(' + '|'.join(tests) + ')$', '-count=1'], cwd=ROOT,
                           capture_output=True, text=True, timeout=1500)
        res.append({'id': f'restore-check {pkg}', 'result': 'OK' if r.returncode == 0 else 'BROKEN',
                    'why': (r.stdout + r.stderr).strip().splitlines()[-1:]})
    upstream, known_flaky = {}, {}
    if a.baseline:
        cmp_, err = baseline_compare(sorted({m['pkg'] for m in spec['mutations']}), a.baseline)
        if err:
            res.append({'id': f'baseline {a.baseline}', 'result': 'BROKEN', 'why': err})
        for pkg, c in (cmp_ or {}).items():
            if c['upstream']:
                upstream[pkg] = c['upstream']
            if c.get('known_flaky'):
                known_flaky[pkg] = c['known_flaky']
            res.append({'id': f'baseline {pkg}', 'result': 'NEWFAIL' if c['ours'] else 'OK',
                        'why': (f"fails only here: {c['ours']}; " if c['ours'] else '')
                               + f"upstream (also red on {a.baseline}): {c['upstream']}"
                               + (f"; known flaky (re-run x{FLAKY_RERUNS}, harness/loop/KNOWN_TEST_FAILURES.json): {c['known_flaky']}"
                                  if c.get('known_flaky') else '')
                               + (f"; upstream NOT in the known list: {c['upstream_unlisted']}" if c.get('upstream_unlisted') else '')})
    bad = [x for x in res if x['result'] in ('MISSED', 'STALE', 'INVALID', 'BROKEN', 'NEWFAIL')]
    for x in res:
        print(f"  {x['result']:7s} {x['id']:28s} {x.get('test', '')}")
    caught = sum(1 for x in res if x['result'] == 'CAUGHT')
    print(f"go mutations: {caught}/{len(spec['mutations'])} caught" + (f" · PROBLEMS {[x['id'] for x in bad]}" if bad else '')
          + (f" · upstream failures recorded {sum(len(v) for v in upstream.values())}" if a.baseline else '')
          + (f" · known flaky re-run clean {sum(len(v) for v in known_flaky.values())}" if known_flaky else ''))
    if a.json:
        Path(a.json).write_text(json.dumps({'caught': caught, 'total': len(spec['mutations']), 'results': res,
                                            'baseline': a.baseline, 'upstream_failures': upstream,
                                            'known_flaky': known_flaky}, indent=1))
    return 0 if not bad else 7


if __name__ == '__main__':
    sys.exit(main())
