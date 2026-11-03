#!/usr/bin/env python3
"""Mutation proofs for consensus_guard's build-input coverage (R18).

Before R18 the guard diffed only '*.go' + go.mod/go.sum, so a changed vendor/**/*.s (e.g. x/crypto sha3
keccakf_amd64.s), cryptography/bn256/*.s, a new vendor/modules.txt or a go.work all PASSED, and a rename
line (R100<TAB>old<TAB>new) crashed the 2-field unpack. Each case below feeds the guard a fake `git`.
  python3 -I harness/kat/test_guard_build_inputs.py   (exit 0 = every case behaves)
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import consensus_guard as G

CASES = [  # (diff --name-status output, untracked, expect_ok)
    ('M\tvendor/golang.org/x/crypto/sha3/keccakf_amd64.s\n', '', False),
    ('M\tcryptography/bn256/gfp_arm64.s\n', '', False),
    ('M\tcryptography/bn256/mul_arm64.h\n', '', False),
    ('', 'vendor/modules.txt\n', False),
    ('', 'go.work\n', False),
    ('R100\tvendor/a/x.go\tvendor/a/y.go\n', '', False),
    ('M\tcmd/dero-miner/astropair/sha_arm64.s\n', '', True),     # miner-only asm is not consensus
    ('M\tvendor/golang.org/x/crypto/sha3/sha3_test.go\n', '', True),
]


def main():
    real = G.git
    bad = []
    try:
        for diff, others, want in CASES:
            G.git = lambda *a, d=diff, o=others: d if a[0] == 'diff' else (o if a[0] == 'ls-files' else '')
            got = G.evaluate()['ok']
            print(f"  {'ok ' if got == want else 'BAD'} expect_ok={want} got={got}  {(diff or others).strip()}")
            if got != want:
                bad.append(diff or others)
    finally:
        G.git = real
    seen = []
    G.git = lambda *a: (seen.append(a), '')[1]
    try:
        G.evaluate()
    finally:
        G.git = real
    diff_calls = [a for a in seen if a[0] == 'diff']
    renames_off = bool(diff_calls) and all('--no-renames' in a for a in diff_calls)
    print(f"  {'ok ' if renames_off else 'BAD'} git diff runs with --no-renames (a deleted consensus file must not pair as a rename)")
    if not renames_off:
        bad.append('--no-renames missing')
    print('guard build-input KAT:', 'PASS' if not bad else f'FAIL {bad}')
    return 0 if not bad else 1


if __name__ == '__main__':
    sys.exit(main())
