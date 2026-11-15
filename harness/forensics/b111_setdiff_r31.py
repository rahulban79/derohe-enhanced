#!/usr/bin/env python3
"""R31 B111 set diff (rft §7 B111 residual; R30 HYPOTHESIS record harness/runtime/r30_b111_premine.json, which stays
as written): is the one balance-tree key without a registration THE GENESIS PREMINE KEY? Writes a NEW record
harness/runtime/r31_b111_setdiff.json.

Method (S4: never the live store): an APFS clone (`cp -c -R`) of the held replaywall archive balances
(~/derohe-persist/forensics_archive_copy/replaywall_balances, state version 18,960 = topo 7,467,515, root d3345594…
recorded in v1) is opened by tools/forensics/keydiff, which walks the balance tree and compares SHA-256(key) with the
registration-key digests of the R30 genesis census (regkeys.bin, sha256 4458…, pinned by r30_genesis_b111_keys.json).
The clone is removed afterwards. Counts and digests only (rule 13): no key is written; the genesis key appears only as
SHA-256 of its 33 bytes, computed here from config/config.go.

CONFIRMED needs all of: the root equals the recorded archive root; the walk found the recorded key count; exactly one
key is not a registration key; its digest is the genesis key's; the keys that are registration keys number the R30
registrations through 7,467,515 (2,141,529). Anything else is NOT CONFIRMED with the failing parts listed.

  python3 -I harness/forensics/b111_setdiff_r31.py [--archive DIR] [--regkeys FILE] [--keydiff BIN] [--out REC]
"""
import argparse, hashlib, json, os, re, shutil, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import s0_checkpoint as S0  # noqa: E402

ROOT = S0.ROOT
OUT = 'harness/runtime/r31_b111_setdiff.json'
ARCHIVE = Path.home() / 'derohe-persist' / 'forensics_archive_copy' / 'replaywall_balances'
REGKEYS = Path.home() / 'derohe-persist' / 'forensics_raw_r30' / 'genesis' / 'run' / 'regkeys.bin'
VERSION = 18960
ARCHIVE_TOPO = 7467515
EXPECT_ROOT = 'd3345594b8bb324b60940c0bea625c57567f09ac889704dba57935de407bd324'
R30_PREMINE = 'harness/runtime/r30_b111_premine.json'
R30_KEYS = 'harness/runtime/r30_genesis_b111_keys.json'


def genesis_digest(root=ROOT):
    """(SHA-256 of the 33 bytes of the mainnet genesis miner key, its config line); the key itself is not returned"""
    for i, l in enumerate((Path(root) / 'config' / 'config.go').read_text().splitlines(), 1):
        m = re.search(r'"([0-9a-f]{66})"\s*[+,]?\s*//\s*miners public key', l)
        if m:
            return hashlib.sha256(bytes.fromhex(m.group(1))).hexdigest(), i
    return None, None


def verdict(kd, gdig, expect_root, expect_keys, regs_thru_archive):
    """(status, checks) from one keydiff output. Pure."""
    checks = {
        'keydiff_ok': kd.get('ok') is True,
        'root_equals_recorded': kd.get('root') == expect_root,
        'key_count_equals_recorded': kd.get('balance_keys') == expect_keys,
        'one_key_not_registered': kd.get('keys_not_in_regs') == 1,
        'that_key_is_the_genesis_key': kd.get('keys_not_in_regs_digests') == [gdig],
        'registered_keys_equal_registrations_through_archive': kd.get('keys_in_regs') == regs_thru_archive,
    }
    return ('CONFIRMED' if all(checks.values()) else 'NOT CONFIRMED'), checks


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def run_keydiff(binary, archive, regkeys):
    with tempfile.TemporaryDirectory(prefix='b111-clone-', dir=os.environ.get('TMPDIR')) as d:
        clone = Path(d) / 'balances'
        subprocess.run(['cp', '-c', '-R', str(archive), str(clone)], check=True)       # APFS clone: no data copied
        env = {**os.environ, 'FORENSICS_STORE_COPY_OK': str(clone.resolve())}
        p = subprocess.run([str(binary), '-balances', str(clone), '-version', str(VERSION), '-regkeys', str(regkeys)],
                           capture_output=True, text=True, env=env)
        out = json.loads(p.stdout or '{}')
    return out                                                                          # the clone is gone here


def build(kd, root=ROOT, archive=ARCHIVE, regkeys=REGKEYS):
    root = Path(root)
    pre = json.loads((root / R30_PREMINE).read_text())
    keys30 = json.loads((root / R30_KEYS).read_text())
    gdig, gline = genesis_digest(root)
    expect_keys = pre['balance_tree_keys'][str(ARCHIVE_TOPO)]
    regs_thru = pre['registrations_through_7467515']
    st, checks = verdict(kd, gdig, EXPECT_ROOT, expect_keys, regs_thru)
    return {
        'schema': 'r31 b111 set diff v1 (rft §7 B111 residual)', 'row': 'B111', 'class': 'DC3', 'status': st,
        'question': 'is the one balance-tree key without a registration the genesis premine key '
                    '(blockchain/transaction_execute.go:73-81 Puts it with no REGISTRATION tx)?',
        'scope': {'topo': ARCHIVE_TOPO, 'state_version': VERSION, 'store': 'APFS clone of the held replaywall archive '
                  'balances (removed after the run; never the live store)'},
        'checks': checks,
        'counts': {k: kd.get(k) for k in ('balance_keys', 'balance_key_lens', 'reg_digests', 'reg_distinct', 'keys_in_regs',
                                          'keys_not_in_regs', 'regs_not_in_keys')},
        'regs_not_in_keys_note': 'registration keys first registered above topo 7,467,515 (the census runs to 7,876,000)',
        'root': kd.get('root'), 'key_digest_set_sha256': kd.get('key_digest_set_sha256'),
        'genesis_key': {'anchor': f'config/config.go:{gline}', 'sha256_of_key_bytes': gdig,
                        'sha256_of_hex (r30 record)': pre['genesis_key']['sha256_of_hex'],
                        'note': 'the key itself is not written (rule 13)'},
        'supersedes_hypothesis': R30_PREMINE,
        'inputs': {'regkeys.bin': sha(regkeys), 'regkeys.bin (r30_genesis_b111_keys.json)': keys30['inputs']['regkeys_sha256'],
                   'archive version_root.bin': sha(Path(archive) / 'version_root.bin'),
                   R30_PREMINE: sha(root / R30_PREMINE), R30_KEYS: sha(root / R30_KEYS),
                   'tools/forensics/keydiff/main.go': sha(root / 'tools/forensics/keydiff/main.go')},
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--root', default=str(ROOT))
    ap.add_argument('--archive', default=str(ARCHIVE)); ap.add_argument('--regkeys', default=str(REGKEYS))
    ap.add_argument('--keydiff', help='a built tools/forensics/keydiff binary (default: go build into a temp dir)')
    ap.add_argument('--out', default=OUT)
    a = ap.parse_args(argv)
    binary = a.keydiff
    tmp = None
    if not binary:
        tmp = tempfile.mkdtemp(prefix='keydiff-bin-', dir=os.environ.get('TMPDIR'))
        binary = str(Path(tmp) / 'keydiff')
        subprocess.run(['go', 'build', '-mod=vendor', '-trimpath', '-o', binary, './tools/forensics/keydiff/'], cwd=a.root, check=True)
    try:
        kd = run_keydiff(binary, a.archive, a.regkeys)
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    rec = build(kd, a.root, a.archive, a.regkeys)
    if a.out:
        S0.write_record(Path(a.root) / a.out, rec)
    c = rec['counts']
    print(f"b111 set diff @ {ARCHIVE_TOPO:,} (v{VERSION}): keys {c['balance_keys']:,}, registered {c['keys_in_regs']:,}, "
          f"not registered {c['keys_not_in_regs']} (genesis key: {rec['checks']['that_key_is_the_genesis_key']}); "
          f"root equal {rec['checks']['root_equals_recorded']}; status {rec['status']}")
    return 0 if rec['status'] == 'CONFIRMED' else 3


if __name__ == '__main__':
    sys.exit(main())
