#!/usr/bin/env python3
"""test_area_fixes_r31.py — r31 dimension 2 (dero-rft §8 R31 item 2, the area_intel 'kat-gap' proposals of security,
rpcws, wallet, storage, mempool, getworkops and chainperf): one registered harness KAT per area on the area's NEWEST
fix, with a mutation that undoes that fix. Seven areas had Go tests and go_mutate entries but no harness KAT in
harness/areas.json kat_files, so area_intel raised 'no harness KAT is registered for N code path(s)' for each.

Each KAT runs the Go test that guards the area's newest fix on the pristine tree (it must PASS); its mutation is the
go_mutations.json entry named below, applied WITHOUT touching the tree: `go test -overlay` hands the compiler the
mutated copy of the one file (the tree is never edited, so no restore journal is needed and a killed run leaves
nothing behind). A mutant that does not build is INVALID (never proved). Mutation independence (harness/kit/katmut.py
classify): under each mutant every KAT whose Go test lives in the SAME package re-runs (a Go mutation can only reach
tests of the package it is compiled into, plus importers, and no KAT here tests an importer of another KAT's package);
the owning KAT must fail, and any other KAT that fails is counted as coupled.

  KG-security   DERO.Subscribe events cap (r31 d2, B280 budget-census)      gm-r31-d2-subscribe-cap
  KG-rpcws      reorg record keep-aside error reported (r31 d2 error-paths) gm-r31-d2-reorg-aside
  KG-wallet     walletapi FormatMoneyPrecision exact (r29 B144)             gm-r29-wg-b144-walletapi-64bit-quotient
  KG-storage    storecheck opens the store read-only (r23c)                 gm-r23c-storecheck-readonly
  KG-mempool    pool rank by milli-fee per byte, saturating (r29 B19)       gm-r29-dc-b19-no-saturation
  KG-getworkops tools/launchd quiet-window lever defaults (r30b B291)       gm-r30b-launchd-env-block
  KG-chainperf  sync prewarm difficulty once per block (r24 chainperf)      gm-r24-chainperf-diff-dropped
  KG0           every row's go_mutations entry exists, its find text occurs exactly once in its file, and every
                area of the table registers this file in harness/areas.json kat_files

  python3 -I harness/kat/test_area_fixes_r31.py [--only AREA]
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not proved (MISSED, WRONG-KAT or INVALID).
"""
import importlib.util, json, re, subprocess, sys, tempfile, time
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
SELF = 'harness/kat/test_area_fixes_r31.py'
GO_TIMEOUT = 900

# area -> (newest fix, go_mutations id). The package and test come from the entry itself.
TABLE = {
    'security': ('DERO.Subscribe events cap (r31 d2, B280)', 'gm-r31-d2-subscribe-cap'),
    'rpcws': ('reorg record keep-aside error reported (r31 d2)', 'gm-r31-d2-reorg-aside'),
    'wallet': ('walletapi FormatMoneyPrecision exact (r29 B144)', 'gm-r29-wg-b144-walletapi-64bit-quotient'),
    'storage': ('storecheck opens the store read-only (r23c)', 'gm-r23c-storecheck-readonly'),
    'mempool': ('pool rank by milli-fee per byte (r29 B19)', 'gm-r29-dc-b19-no-saturation'),
    'getworkops': ('launchd quiet-window lever defaults (r30b B291)', 'gm-r30b-launchd-env-block'),
    'chainperf': ('sync prewarm difficulty once per block (r24)', 'gm-r24-chainperf-diff-dropped'),
}
RESULT_RX = re.compile(r'^--- (PASS|FAIL|SKIP): (\w+) ', re.M)
BUILD_FAILED = re.compile(r'\[(build|setup) failed\]|^# \S+\n.*\.go:\d+:\d+: ', re.M)


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_af31', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def entries(root=ROOT):
    """{gm id: entry} of harness/intel/go_mutations.json."""
    return {e['id']: e for e in json.loads((root / 'harness/intel/go_mutations.json').read_text())['mutations']}


def rows(only=None, root=ROOT):
    """[(area, fix, entry or None)] of the table."""
    em = entries(root)
    return [(a, fix, em.get(gid)) for a, (fix, gid) in TABLE.items() if not only or a == only]


def go_test(pkg, tests, overlay=None):
    """(rc, {test: PASS/FAIL/SKIP}, output) of one `go test -v -count=1 -run '^(t1|t2)$' pkg` in ROOT."""
    cmd = ['go', 'test', '-count=1', '-v', '-run', '^(' + '|'.join(sorted(tests)) + ')$']
    if overlay:
        cmd.append('-overlay=' + str(overlay))
    cmd.append(pkg)
    try:
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=GO_TIMEOUT)
    except subprocess.TimeoutExpired as e:
        return 124, {}, f'timeout: {e}'
    out = (p.stdout or '') + (p.stderr or '')
    return p.returncode, {m.group(2): m.group(1) for m in RESULT_RX.finditer(out)}, out


def mutant_overlay(entry, tmp):
    """write the mutated copy of entry['file'] and an overlay map under tmp; None when the find text is not there once."""
    src = (ROOT / entry['file']).read_text()
    if src.count(entry['find']) != 1:
        return None
    mut = Path(tmp) / ('m_' + Path(entry['file']).name)
    mut.write_text(src.replace(entry['find'], entry['replace'], 1))
    ov = Path(tmp) / f"overlay_{entry['id']}.json"
    ov.write_text(json.dumps({'Replace': {str((ROOT / entry['file']).resolve()): str(mut)}}))
    return ov


def kg0(rs, root=ROOT):
    """the registry check: every entry present with its find text once, and every table area registers this file."""
    bad = []
    for a, _, e in rs:
        if e is None:
            bad.append(f'{a}: go_mutations entry {TABLE[a][1]} missing')
            continue
        f = root / e['file']
        if not f.exists() or f.read_text().count(e['find']) != 1:
            bad.append(f"{a}: find text of {e['id']} not exactly once in {e['file']}")
    reg = {x['id']: x for x in json.loads((root / 'harness/areas.json').read_text())['areas']}
    for a, _, _ in rs:
        if SELF not in (reg.get(a) or {}).get('kat_files', []):
            bad.append(f'{a}: {SELF} not in its areas.json kat_files')
    return bad


def main():
    only = sys.argv[sys.argv.index('--only') + 1] if '--only' in sys.argv else None
    K = katmut()
    rs = rows(only)
    fails = []
    bad = kg0(rs)
    print(f"KG0 registry: {'ok' if not bad else bad}")
    if bad:
        fails.append('KG0')
    live = [(a, fix, e) for a, fix, e in rs if e is not None]
    by_pkg = {}
    for a, fix, e in live:
        by_pkg.setdefault(e['pkg'], []).append((a, e['test']))
    # pristine: each package once, every KAT test of it
    for pkg, kats in sorted(by_pkg.items()):
        t0 = time.time()
        rc, res, out = go_test(pkg, {t for _, t in kats})
        for a, t in kats:
            ok = rc == 0 and res.get(t) == 'PASS'
            print(f"KG-{a} pristine {pkg} {t}: {res.get(t, 'NOT RUN')} ({time.time() - t0:.1f}s)")
            if not ok:
                fails.append(f'KG-{a}')
                print('   ', out[-800:].replace('\n', '\n    '))
    n_kats = len(rs) + 1
    if fails:
        print('FAIL', fails)
        print(f'area_fixes KATs: {n_kats - len(set(fails))}/{n_kats} ok · mutations proved 0/{len(live)} · mutations coupled 0')
        return 3
    missed = coupled = 0
    with tempfile.TemporaryDirectory(prefix='af31_') as tmp:
        for a, fix, e in live:
            ov = mutant_overlay(e, tmp)
            if ov is None:
                print(f"  INVALID  {e['id']} (find text not exactly once)")
                missed += 1
                continue
            kats = by_pkg[e['pkg']]
            t0 = time.time()
            rc, res, out = go_test(e['pkg'], {t for _, t in kats}, ov)
            if rc != 0 and BUILD_FAILED.search(out):
                print(f"  INVALID  {e['id']}: the mutant does not build")
                missed += 1
                continue
            failed = [f'KG-{b}' for b, t in kats if res.get(t) == 'FAIL' or (rc != 0 and t not in res)]
            verdict, cpl = K.classify(failed, [f'KG-{a}'])
            print(f"  {verdict:9s}{e['id']} -> {failed} ({time.time() - t0:.1f}s){' coupled ' + str(cpl) if cpl else ''}")
            if verdict != 'proved':
                missed += 1
            coupled += 1 if cpl else 0
    print(K.summary('area_fixes KATs', n_kats, len(live), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
