#!/usr/bin/env python3
"""test_crypto_census_r31.py — r31 (rft §7 B278 / B283, area cryptography): the primitives census tool
harness/intel/crypto_census.py.

  CC1 B283  the real tree: every decoder entry resolves (signature + reach anchor) and is pinned by a Go test that
            exists; 23 entries, consensus 10 / wallet 3 / no caller 10; verdict PASS
  CC2 B283  a fixture tree: an entry whose pin test is not defined, or whose signature moved away, is NOT pinned and
            makes the census FAIL; a resolving entry with its test is pinned
  CC3 B278  the randomness scan on a fixture: math/rand imported in cryptography/, a seeded math/rand source and a
            discarded crypto/rand error are found; a generator built on the crypto source is not; an explanation
            matches by file AND quote (a second discard in an explained file stays unexplained)
  CC4 B278  the real tree's randomness findings are all explained (B15 premise; fails-closed scalar)

  python3 -I harness/kat/test_crypto_census_r31.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, importlib.util, io, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'cc': 'harness/intel/crypto_census.py'}


def load(over):
    spec = importlib.util.spec_from_file_location('cc31', Path(over.get('cc') or (ROOT / PATHS['cc'])))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def write(root, rel, text):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def kat_cc1(over):
    C = load(over)
    rec = C.run(ROOT)
    k = rec['kpis']
    ok = (rec['verdict'] == 'PASS' and k['pinned'] == k['listed'] == 23 and (k['consensus'], k['wallet'], k['no_caller']) == (10, 3, 10)
          and all(r['pinned'] and not r['problems'] for r in rec['decoders']))
    return ok, (rec['verdict'], k)


def kat_cc2(over):
    C = load(over)
    with tempfile.TemporaryDirectory(prefix='cc31-') as d:
        write(d, 'pkg/a.go', 'package pkg\nfunc (e *T) Decode(b []byte) error {\n\treturn nil\n}\n')
        write(d, 'pkg/caller.go', 'package pkg\nfunc use() { new(T).Decode(nil) }\n')
        write(d, 'pkg/a_test.go', 'package pkg\nfunc TestPinned(t *testing.T) {}\n')
        base = ('E', 'pkg/a.go', 'func (e *T) Decode(b []byte) error {', 'consensus', ('pkg/caller.go', 'new(T).Decode(nil)'),
                ('pkg', 'TestPinned'), ['DF-x'], 'TRIAGED')
        good = C.census_decoders(d, [base])
        nopin = C.census_decoders(d, [base[:5] + (('pkg', 'TestAbsent'),) + base[6:]])
        moved = C.census_decoders(d, [(base[0], base[1], 'func (e *T) Gone(b []byte) error {') + base[3:]])
        badreach = C.census_decoders(d, [base[:4] + (('pkg/caller.go', 'nowhere()'),) + base[5:]])
        orig = C.ENTRIES
        try:
            C.ENTRIES = [base[:5] + (('pkg', 'TestAbsent'),) + base[6:]]
            fail = C.run(Path(d))['verdict']
            C.ENTRIES = [base]
            ok_run = C.run(Path(d))['verdict']
        finally:
            C.ENTRIES = orig
    ok = (good[0]['pinned'] and good[0]['at'] == 'pkg/a.go:2' and not nopin[0]['pinned'] and not moved[0]['pinned']
          and not badreach[0]['pinned'] and fail == 'FAIL' and ok_run == 'PASS')
    return ok, (good[0]['pinned'], nopin[0]['pinned'], moved[0]['pinned'], badreach[0]['pinned'], fail, ok_run)


def kat_cc3(over):
    C = load(over)
    with tempfile.TemporaryDirectory(prefix='cc31-') as d:
        write(d, 'cryptography/crypto/r.go', 'package crypto\nimport "math/rand"\nfunc f() int { return rand.Int() }\n')
        write(d, 'walletapi/ok.go', 'package walletapi\nimport mathrand "math/rand"\nvar r = mathrand.New(globals.NewCryptoRandSource())\n')
        write(d, 'walletapi/seeded.go', 'package walletapi\nimport mathrand "math/rand"\nvar r = mathrand.New(mathrand.NewSource(1))\n')
        write(d, 'globals/random.go', 'package globals\nimport "crypto/rand"\nfunc a() {\n\trand.Read(b[:])\n}\nfunc c() {\n\t_, _ = rand.Read(x)\n}\n')
        write(d, 'walletapi/ok_test.go', 'package walletapi\nimport "math/rand"\nvar s = rand.NewSource(1)\n')
        moot = [('globals/random.go', 'rand.Read(b[:])', 'B15')]
        found = C.census_randomness(Path(d), moot)
    kinds = sorted((f['file'], f['kind'], bool(f['explained'])) for f in found)
    want = sorted([('cryptography/crypto/r.go', 'math/rand-in-cryptography', False),
                   ('walletapi/seeded.go', 'math/rand-seeded', False),
                   ('globals/random.go', 'crypto/rand-error-discarded', True),
                   ('globals/random.go', 'crypto/rand-error-discarded', False)])
    return kinds == want, kinds


def kat_cc4(over):
    C = load(over)
    found = C.census_randomness(ROOT)
    files = {f['file'] for f in found}
    ok = (found and all(f['explained'] for f in found) and 'globals/random.go' in files
          and not any(f['kind'] == 'math/rand-in-cryptography' for f in found))
    return ok, [(f['file'], f['line'], f['kind'], bool(f['explained'])) for f in found]


KATS = [('CC1', kat_cc1), ('CC2', kat_cc2), ('CC3', kat_cc3), ('CC4', kat_cc4)]
OWNERS = {'B283': ['CC1', 'CC2'], 'B278': ['CC3', 'CC4']}
MUTATIONS = [
    ('cc', "    return any(rx.search(p.read_text(errors='replace')) for p in sorted((Path(root) / pkg).glob('*_test.go')))\n",
     "    return True\n", 'B283: a pin test that does not exist counts as pinned'),
    ('cc', "        if sl is None:\n            problems.append(f'signature not found in {f}')\n", "",
     'B283: a decoder whose signature moved away still counts as pinned'),
    ('cc', "        if rl is None:\n            problems.append(f'reach anchor not found in {rf}')\n", "",
     'B283: a reach claim whose anchor does not resolve is accepted'),
    ('cc', "    verdict = 'PASS' if pinned == len(rows) and rows and not unexplained else 'FAIL'\n",
     "    verdict = 'PASS' if rows else 'FAIL'\n", 'B283: an unpinned entry does not fail the census'),
    ('cc', "        if m and rel.startswith('cryptography/'):\n", "        if False:\n",
     'B278: math/rand imported in cryptography/ is not found'),
    ('cc', "                if s.group(1) == mr:\n", "                if False:\n", 'B278: a seeded math/rand source is not found'),
    ('cc', "            for d in RX_DISCARD.finditer(text):\n", "            for d in []:\n",
     'B278: a discarded crypto/rand error is not found'),
    ('cc', "        why = next((r for mf, q, r in moot if mf == f['file'] and q in f['quote']), None)\n",
     "        why = next((r for mf, q, r in moot if mf == f['file']), None)\n",
     'B278: an explanation covers every finding of its file, not the quoted one'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_cc31', HARNESS / 'kit' / 'katmut.py')
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
        print(f'\nr31 crypto-census KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='cc31-mut-') as d:
            mut = Path(d) / Path(PATHS[key]).name
            mut.write_text(text.replace(find, repl), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, cpl = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
        coupled += bool(cpl)
    print('\n' + K.summary('r31 crypto-census KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
