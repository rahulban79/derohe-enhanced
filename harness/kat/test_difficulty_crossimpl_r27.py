#!/usr/bin/env python3
"""Known-answer tests + mutation proofs (R27 dvm-blockchain): the observatory's difficulty rule
(harness/intel/consensus_intel.py expected_difficulty, gate G26 "difficulty rule 0 mismatches") and consensus
(blockchain/difficulty.go Get_Difficulty_At_Tips) agree on a fixed vector set. G26 compares the LIVE chain against the
Python rule only; nothing tied that rule to the Go code beyond its quoted constants. The vectors live in
blockchain/testdata/r27_difficulty_vectors.json; the Go side is blockchain/r27_difficulty_kat_test.go
(TestR27DifficultyCrossImpl), which runs Get_Difficulty_At_Tips over the same file with a fake DiffProvider.

  DF1 every vector's `want` equals expected_difficulty(prev, solve_ms, load_rules(tree)) (the rules resolve from the
      tree lines, so a changed constant in config/ or blockchain/difficulty.go shows here)
  DF2 the vector set covers the clamp (solve > 2 x block time), the floor (result below the minimum), solve 1 ms, and
      prev values above 2^64 (big-int path)
  mutations (on the rules the KAT hands expected_difficulty, never on the tree): M 8 -> 7, clamp 2 -> 3, minimum
      100000 -> 1, block time 18 -> 17, e 2.718.. -> 2.7: each must change at least one vector (CAUGHT)

  python3 -I harness/kat/test_difficulty_crossimpl_r27.py [--write]   # --write regenerates the vector file
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught.
"""
import copy, importlib.util, json, random, sys
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
VEC = ROOT / 'blockchain' / 'testdata' / 'r27_difficulty_vectors.json'
PREVS = [100000, 3000000, 1234567891, 98765432101, 2 ** 64 + 7, 2 ** 90 + 12345]
SOLVES = [1, 2, 1000, 9000, 17999, 18000, 18001, 27000, 35999, 36000, 36001, 72000, 10 ** 7]


def intel():
    spec = importlib.util.spec_from_file_location('consensus_intel_df', HARNESS / 'intel' / 'consensus_intel.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def rules(ci):
    R, missing = ci.load_rules(ROOT)
    if missing:
        raise SystemExit(f'rules do not resolve: {missing}')
    return R


def solves():
    rnd = random.Random(27)
    return SOLVES + sorted(rnd.randint(1, 40000) for _ in range(60))


def build(ci, R):
    cases = []
    for p in PREVS:
        for s in solves():
            cases.append({'prev': str(p), 'solve_ms': s, 'want': str(ci.expected_difficulty(p, s, R))})
    return {'_doc': 'R27 difficulty cross-implementation vectors: want = harness/intel/consensus_intel.py '
                    'expected_difficulty(prev, solve_ms, rules of the tree); checked against blockchain/difficulty.go '
                    'by blockchain/r27_difficulty_kat_test.go and against the Python rule by '
                    'harness/kat/test_difficulty_crossimpl_r27.py. Mainnet rules; heights above HF2+2.',
            'rules': {k: R[k]['value'] for k in ('block_time', 'diff_clamp', 'diff_e', 'diff_m', 'min_difficulty')},
            'cases': cases}


def mismatches(ci, R, doc):
    return sum(str(ci.expected_difficulty(int(c['prev']), c['solve_ms'], R)) != c['want'] for c in doc['cases'])


def main():
    ci = intel()
    R = rules(ci)
    if '--write' in sys.argv:
        VEC.write_text(json.dumps(build(ci, R), indent=1) + '\n')
        print(f'wrote {VEC.relative_to(ROOT)}')
    doc = json.loads(VEC.read_text())
    fails = []
    n = mismatches(ci, R, doc)
    print(f"DF1 {len(doc['cases']) - n}/{len(doc['cases'])} vectors equal the Python rule")
    if n:
        fails.append('DF1')
    bt, clamp, mn = R['block_time']['value'] * 1000, R['diff_clamp']['value'], R['min_difficulty']['value']
    have = {'clamp': any(c['solve_ms'] > bt * clamp for c in doc['cases']),
            'floor': any(int(c['want']) == mn and int(c['prev']) * 9999 // 10000 < mn for c in doc['cases']),
            'solve1': any(c['solve_ms'] == 1 for c in doc['cases']),
            'big': any(int(c['prev']) >= 2 ** 64 for c in doc['cases'])}
    print('DF2 coverage', have)
    if not all(have.values()):
        fails.append('DF2')
    missed = []
    for name, key, val in [('M 8->7', 'diff_m', 7), ('clamp 2->3', 'diff_clamp', 3), ('minimum 100000->1', 'min_difficulty', 1),
                           ('block time 18->17', 'block_time', 17), ('e -> 2.7', 'diff_e', 2.7)]:
        Rm = copy.deepcopy(R)
        Rm[key]['value'] = val
        k = mismatches(ci, Rm, doc)
        print(f'  mutation {name}: {k} vectors differ -> {"CAUGHT" if k else "MISSED"}')
        if not k:
            missed.append(name)
    print(f'mutations {5 - len(missed)}/5 caught')
    if fails:
        print('FAIL', fails)
        return 3
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
