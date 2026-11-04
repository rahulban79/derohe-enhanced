#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for harness/kit/stateguard.py (r25; tooling class 'probes hitting pruned
state', dero-rft §7 B85: a discovery probe's GetEncryptedBalance below prunedheight logged 4 recovered-panic ERRORs on
the live node on 2026-11-03 and failed G15).

  SG1 forged requests against prunedheight 7,498,540: GetEncryptedBalance at 7,415,465 and with NO topoheight (the
      handler reads topoheight 0 then, rpc_dero_getencryptedbalance.go:48) are refused; at -1 (the top) and at the prune
      point itself it passes; GetSC at 0 (the top for GetSC, rpc_dero_getsc.go:57) passes, at 7,000,000 is refused.
  SG2 an unknown prune point (GetInfo unread) refuses every explicit state read and still passes the top.
  SG3 block and transaction reads (GetBlock, GetTransaction, GetBlockHeaderByTopoHeight) are never state reads.

  python3 -I harness/kat/test_stateguard_r25.py
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import importlib.util, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
SRC = HARNESS / 'kit' / 'stateguard.py'
P = 7498540


def load(path):
    spec = importlib.util.spec_from_file_location(f'sg_{abs(hash(str(path)))}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def sg1(m):
    cases = [(('DERO.GetEncryptedBalance', {'address': 'a', 'topoheight': 7415465}, P), False),
             (('DERO.GetEncryptedBalance', {'address': 'a'}, P), False),
             (('DERO.GetEncryptedBalance', {'address': 'a', 'topoheight': -1}, P), True),
             (('DERO.GetEncryptedBalance', {'address': 'a', 'topoheight': P}, P), True),
             (('DERO.GetSC', {'scid': 'x', 'topoheight': 0}, P), True),
             (('DERO.GetSC', {'scid': 'x', 'topoheight': 7000000}, P), False),
             (('DERO.NameToAddress', {'name': 'n', 'topoheight': 1}, P), False)]
    got = [m.check(*a)[0] for a, _ in cases]
    return got == [w for _, w in cases], f'got {got}'


def sg2(m):
    got = [m.check('DERO.GetSC', {'topoheight': 7900000}, None)[0], m.check('DERO.GetSC', {}, None)[0]]
    return got == [False, True], f'got {got}'


def sg3(m):
    got = [m.check(x, {'topoheight': 1, 'height': 1}, P)[0] for x in
           ('DERO.GetBlock', 'DERO.GetTransaction', 'DERO.GetBlockHeaderByTopoHeight')]
    return got == [True, True, True], f'got {got}'


KATS = [('SG1', sg1), ('SG2', sg2), ('SG3', sg3)]
MUTATIONS = [
    ("    if t < int(pruned):\n", "    if t < int(pruned) - 10**9:\n", 'a state read below the prune point passes'),
    ("ZERO_IS_TOPO = ('DERO.GetEncryptedBalance',)", "ZERO_IS_TOPO = ()",
     'GetEncryptedBalance without topoheight treated as the top (it reads topoheight 0)'),
    ("    if pruned is None:\n        return False,", "    if pruned is None:\n        return True,",
     'an unknown prune point lets explicit state reads through'),
    ("    if method not in STATE_METHODS:\n        return True, 'not a state read'\n", "",
     'block reads judged as state reads'),
    ("            if v < 0 or (v == 0 and not zero_real):", "            if v < 0:", 'GetSC topoheight 0 (the top) refused'),
]


def main():
    mod = load(SRC)
    ok = True
    for name, fn in KATS:
        o, det = fn(mod)
        print(f"{'ok  ' if o else 'FAIL'} {name} {det}")
        ok &= o
    if not ok:
        return 3
    src, missed = SRC.read_text(), 0
    for find, repl, why in MUTATIONS:
        if src.count(find) != 1:
            print(f'  ??      {why}: find text occurs {src.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'stateguard.py'
            p.write_text(src.replace(find, repl, 1))
            try:
                m = load(p)
            except Exception as e:                                # noqa: BLE001
                print(f'  INVALID {why}: mutant does not load ({type(e).__name__})')
                missed += 1
                continue
            try:
                survived = all(fn(m)[0] for _, fn in KATS)
            except Exception:                                     # noqa: BLE001 — a crash is a detection
                survived = False
        print(f"  {'MISSED ' if survived else 'proved '} {why}")
        missed += survived
    print(f'\nr25 stateguard KATs: {len(KATS)}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
