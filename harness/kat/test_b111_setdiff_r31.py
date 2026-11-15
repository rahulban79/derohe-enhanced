#!/usr/bin/env python3
"""test_b111_setdiff_r31.py — r31 dimension 6 (rft §7 B111 residual): the set diff that decides whether the one
balance-tree key without a registration is the genesis premine key (harness/forensics/b111_setdiff_r31.py over
tools/forensics/keydiff on an APFS clone of the held 7,467,515 archive).

  BS1 the record harness/runtime/r31_b111_setdiff.json: status CONFIRMED with every check true, the recorded root,
      2,141,530 keys of 33 bytes, 1 unregistered key whose digest is the genesis key's, no key written (only digests)
  BS2 verdict() is CONFIRMED on the known answer and NOT CONFIRMED when any one part deviates (another root, another
      key count, two unregistered keys, an unregistered key that is not the genesis key, a registered count that is
      not the registrations through 7,467,515, a failed walk)
  BS3 genesis_digest() hashes the 33 key BYTES of the line marked `miners public key` (not its hex text) and returns
      that line

  python3 -I harness/kat/test_b111_setdiff_r31.py      # exit 0 · 3 a KAT failed · 4 a mutation was missed
"""
import contextlib, hashlib, importlib.util, io, json, re, sys, tempfile, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'tool': 'harness/forensics/b111_setdiff_r31.py'}
SIBLINGS = ('harness/forensics/b111_setdiff_r31.py', 'harness/forensics/s0_checkpoint.py')
REC = 'harness/runtime/r31_b111_setdiff.json'
G = 'a7b04bf54f5d7ec39faa678e9350e688f56df615bd49286e8493f2ff6766405b'
R = 'd3345594b8bb324b60940c0bea625c57567f09ac889704dba57935de407bd324'


def load(over):
    root = Path(over.get('root') or ROOT)
    spec = importlib.util.spec_from_file_location(f'bs31_{uuid.uuid4().hex[:6]}', root / PATHS['tool'])
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def known():
    return {'ok': True, 'root': R, 'balance_keys': 2141530, 'keys_not_in_regs': 1, 'keys_not_in_regs_digests': [G],
            'keys_in_regs': 2141529}


def kat_bs1(over):
    rec = json.loads((ROOT / REC).read_text())
    c = rec['counts']
    text = json.dumps(rec)
    ok = (rec['status'] == 'CONFIRMED' and all(rec['checks'].values()) and rec['root'] == R and c['balance_keys'] == 2141530
          and c['balance_key_lens'] == {'33': 2141530} and c['keys_not_in_regs'] == 1
          and rec['genesis_key']['sha256_of_key_bytes'] == G and not re.search(r'\b[0-9a-f]{66}\b', text))
    return ok, {'status': rec['status'], 'counts': c}


def kat_bs2(over):
    m = load(over)
    args = (G, R, 2141530, 2141529)
    base = m.verdict(known(), *args)[0]
    bad = {'root': {'root': '00' * 32}, 'count': {'balance_keys': 2141531}, 'two': {'keys_not_in_regs': 2},
           'other': {'keys_not_in_regs_digests': ['11' * 32]}, 'regs': {'keys_in_regs': 2141528}, 'walk': {'ok': False}}
    got = {k: m.verdict({**known(), **v}, *args)[0] for k, v in bad.items()}
    return base == 'CONFIRMED' and set(got.values()) == {'NOT CONFIRMED'}, {'base': base, **got}


def kat_bs3(over):
    m = load(over)
    key = '02' + 'ab' * 32
    with tempfile.TemporaryDirectory(prefix='bs3-') as d:
        (Path(d) / 'config').mkdir()
        (Path(d) / 'config' / 'config.go').write_text('package config\n\nvar x = 1\nvar Genesis = "00" +\n'
                                                      f'\t"{key}" + // miners public key\n\t"00"\n')
        got = m.genesis_digest(d)
    want = (hashlib.sha256(bytes.fromhex(key)).hexdigest(), 5)
    return got == want, {'got': got, 'want': want}


KATS = [('BS1', kat_bs1), ('BS2', kat_bs2), ('BS3', kat_bs3)]
OWNERS = {'B111': ['BS2', 'BS3']}
MUTATIONS = [
    ('tool', "        'root_equals_recorded': kd.get('root') == expect_root,", "        'root_equals_recorded': True,",
     'B111: another root is accepted'),
    ('tool', "        'key_count_equals_recorded': kd.get('balance_keys') == expect_keys,", "        'key_count_equals_recorded': True,",
     'B111: another key count is accepted'),
    ('tool', "        'one_key_not_registered': kd.get('keys_not_in_regs') == 1,", "        'one_key_not_registered': True,",
     'B111: two unregistered keys are accepted'),
    ('tool', "        'that_key_is_the_genesis_key': kd.get('keys_not_in_regs_digests') == [gdig],",
     "        'that_key_is_the_genesis_key': len(kd.get('keys_not_in_regs_digests') or []) == 1,",
     'B111: any unregistered key is taken for the genesis key'),
    ('tool', "        'registered_keys_equal_registrations_through_archive': kd.get('keys_in_regs') == regs_thru_archive,",
     "        'registered_keys_equal_registrations_through_archive': True,", 'B111: the registered count is not checked'),
    ('tool', "        'keydiff_ok': kd.get('ok') is True,", "        'keydiff_ok': True,", 'B111: a failed walk is accepted'),
    ('tool', "            return hashlib.sha256(bytes.fromhex(m.group(1))).hexdigest(), i",
     "            return hashlib.sha256(m.group(1).encode()).hexdigest(), i", 'B111: the hex text is hashed, not the key bytes'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_bs31', HARNESS / 'kit' / 'katmut.py')
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
        print(f'\nr31 b111 set-diff KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='bs31-mut-') as d:
            for rel in SIBLINGS:
                (Path(d) / rel).parent.mkdir(parents=True, exist_ok=True)
                (Path(d) / rel).write_text((ROOT / rel).read_text(encoding='utf-8'), encoding='utf-8')
            (Path(d) / PATHS[key]).write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({'root': d}) if not ok]
        verdict, cpl = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
        coupled += bool(cpl)
    print('\n' + K.summary('r31 b111 set-diff KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
