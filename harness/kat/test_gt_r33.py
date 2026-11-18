#!/usr/bin/env python3
"""R33 game-theory KATs (artifacts/dero-game-theory-rft.md §7 GT-B21, GT-B27, GT-B28; lessons 34-35).

  R33-1 every GO contract (M1..M6) passes the pipeline lint, including the audit regressions (run-once Initialize,
        no anonymous owner, IF ... THEN GOTO only, no ADDRESS_RAW(SIGNER()) in code, no SEND of the burn)
  R33-2 each audit-regression lint rule catches its planted defect in gt_pool.bas (mutation proofs)
  R33-3 mechanisms.json lists M5 gt_pool and M6 gt_beacon with every entrypoint the contracts define
  R33-6 the pool census over epochs (GT-B35): sums every epoch, alarms only with a large enough sample
  R33-5 the contracts README (GT-B22) covers every contract and every M5/M6 entrypoint, with no private value
  R33-8 a call fee the wallet had not indexed is resolved at record time (late lookup, else the fee set in the tx) and
        the cycle chain audit takes an audit-only record (no prize contract; mainnet step 3c, 2026-11-18)
  R33-9 gtlib.pool_tag gives the DVM's tag for every address of dvm/testdata/r33_tagvec.json (TestR33TagVector)
  R33-4 gt_pool has no owner withdrawal and no path that sends "burned", and keeps the research fixes (tag 0/ff refused,
        fixed miniblock count, claim deadline); gt_beacon never sends DERO

  python3 -I harness/kat/test_gt_r33.py          exit 0 PASS · 3 a KAT failed
"""
import json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'harness/gametheory'))
import gt_pipeline as g  # noqa: E402

C = ROOT / 'gametheory/contracts'


def kat1():
    mech = json.loads((ROOT / 'gametheory/mechanisms.json').read_text())
    bad = {}
    for m in mech['mechanisms']:
        if m['status'] != 'GO':
            continue
        _, issues = g.lint_contract((C / m['contract']).read_text(), m['entrypoints'])
        if issues:
            bad[m['id']] = issues
    ids = {m['id'] for m in mech['mechanisms'] if m['status'] == 'GO'}
    return not bad and {'M1', 'M2', 'M3', 'M4', 'M5', 'M6'} <= ids, f'lint issues {bad}; GO {sorted(ids)}'


def kat2():
    t = (C / 'gt_pool.bas').read_text()
    muts = [
        ('GT-A01 run-once guard removed', '10 IF EXISTS("owner") == 1 THEN GOTO 900\n20 IF IS_ADDRESS_VALID', '10 LET x = 0\n20 IF IS_ADDRESS_VALID'),
        ('GT-A12 anonymous owner allowed', '20 IF IS_ADDRESS_VALID(SIGNER()) == 0 THEN GOTO 900\n25 IF DEROVALUE()', '20 LET y = 1\n25 IF DEROVALUE()'),
        ('lesson 34 ADDRESS_RAW(SIGNER()) in code', '10 RETURN HEX(SUBSTR(SHA3256(SIGNER()), 0, 8))', '10 RETURN HEX(SUBSTR(SHA3256(ADDRESS_RAW(SIGNER())), 0, 8))'),
        ('lesson 35 THEN without GOTO', '100 IF s <= 100 THEN GOTO 110', '100 IF s > 100 THEN LET s = 100'),
        ('a SEND of the burn', '330 SEND_DERO_TO_ADDRESS(SIGNER(), pay)', '330 SEND_DERO_TO_ADDRESS(SIGNER(), LOAD("burned"))'),
    ]
    out = []
    for name, a, b in muts:
        if t.count(a) != 1:
            out.append(f'{name}: target not found')
            continue
        if not g.lint_contract(t.replace(a, b, 1), [])[1]:
            out.append(f'{name}: MISSED')
    return not out, '; '.join(out) or f'{len(muts)}/{len(muts)} planted defects caught'


def kat3():
    mech = {m['id']: m for m in json.loads((ROOT / 'gametheory/mechanisms.json').read_text())['mechanisms']}
    out = []
    for mid, f in (('M5', 'gt_pool.bas'), ('M6', 'gt_beacon.bas')):
        m = mech.get(mid)
        if not m or m['contract'] != f:
            out.append(f'{mid} missing')
            continue
        pub = [x for x in re.findall(r'^Function\s+([A-Za-z_]\w*)\s*\(', (C / f).read_text(), re.M) if x[0].isupper()]
        if sorted(pub) != sorted(m['entrypoints']):
            out.append(f'{mid}: entrypoints {sorted(m["entrypoints"])} != contract {sorted(pub)}')
    return not out, '; '.join(out) or 'M5/M6 entrypoints match'


def kat4():
    pool = (C / 'gt_pool.bas').read_text()
    beacon = (C / 'gt_beacon.bas').read_text()
    code = re.sub(r'/\*.*?\*/', '', pool, flags=re.S)
    sends = [l for l in code.splitlines() if 'SEND_DERO_TO_ADDRESS' in l]
    out = []
    if any('LOAD("owner")' in l or '"burned"' in l for l in sends):
        out.append(f'pool sends to the owner or sends the burn: {sends}')
    if any('SIGNER()' not in l for l in sends):
        out.append(f'pool sends to someone other than the caller: {sends}')
    for lit in ('IF t == "0000000000000000" THEN GOTO 900', 'IF t == "ffffffffffffffff" THEN GOTO 900', 'STORE("mcount", 10)',
                'IF BLOCK_HEIGHT() >= (e + 5) * LOAD("epochlen") + LOAD("grace") THEN GOTO 900'):
        if lit not in code:
            out.append(f'pool lacks the R33 research fix: {lit}')
    if 'SEND_DERO_TO_ADDRESS' in re.sub(r'/\*.*?\*/', '', beacon, flags=re.S) or 'UPDATE_SC_CODE' in code:
        out.append('beacon sends DERO or pool updates code')
    return not out, '; '.join(out) or f'pool sends only to the caller ({len(sends)} sites); beacon sends nothing'


def kat5():
    """GT-B22: the contracts README names every .bas, every gt_pool/gt_beacon entrypoint, and no private value."""
    t = (C / 'README.md').read_text()
    out = [f'{f.name} not in the README' for f in sorted(C.glob('*.bas')) if f.name not in t]
    for f in ('gt_pool.bas', 'gt_beacon.bas'):
        for e in re.findall(r'^Function\s+([A-Z]\w*)\s*\(', (C / f).read_text(), re.M):
            if f'`{e}' not in t:
                out.append(f'{f}:{e} not in the README')
    if re.search(r'/Users/|/home/|/private/tmp|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:(?!10102\b)\d+|dero1q[0-9a-z]{20,}', t.replace('127.0.0.1', 'LOOP')):
        out.append('a private path, IP or address in the README')
    return not out, '; '.join(out) or 'README covers 6 contracts and every M5/M6 entrypoint; no private value'


def kat6():
    """GT-B35: the pool census sums every epoch, ignores non-census keys, and alarms only with >= 360 miniblocks."""
    import importlib.util as _iu
    _sp = _iu.spec_from_file_location('pool_census', ROOT / 'harness/gametheory/pool_census.py')
    pc = _iu.module_from_spec(_sp)
    _sp.loader.exec_module(pc)
    kh = lambda i: f'{i:032x}'
    cases = [({f'k1_{kh(1)}': 100, f'k1_{kh(2)}': 50}, 'sample too small'),
             ({f'k1_{kh(1)}': 200, f'k2_{kh(1)}': 100, f'k2_{kh(2)}': 300}, 'ALARM'),
             ({**{f'k1_{kh(i)}': 30 for i in range(1, 13)}, f'k2_{kh(13)}': 40}, 'no alarm'),
             ({'km1': 999, 'kn1': 999, f'k1_{kh(1)}': 400}, 'ALARM')]
    bad = [f'{want} got {pc.verdict(pc.census(c))["state"]}' for c, want in cases if pc.verdict(pc.census(c))['state'] != want]
    if pc.census({'km1': 9, 'kn1': 9})['kn'] != 0:
        bad.append('summary keys counted as miniblocks')
    return not bad, '; '.join(bad) or '4 census cases + key filter'


def kat7():
    """GT-B25/B32: harness/gametheory/r33_flags_preflight.py parses real mainnet blocks: 10 miniblocks, one final,
    8-byte tags (16 hex), a wrong tx count refused."""
    import importlib.util as _iu
    _sp = _iu.spec_from_file_location('r33_flags_preflight', ROOT / 'harness/gametheory/r33_flags_preflight.py')
    fp = _iu.module_from_spec(_sp)
    _sp.loader.exec_module(fp)
    bad = []
    for b in json.loads((ROOT / 'dvm/testdata/r33_mainnet_blocks.json').read_text()):
        mbs = fp.miniblocks(bytes.fromhex(b['blob']), b['txcount'])
        if len(mbs) != 10 or sum(x['final'] for x in mbs) != 1 or any(len(x['flags']) != 16 for x in mbs):
            bad.append(f"block {b['height']}")
        try:
            fp.miniblocks(bytes.fromhex(b['blob']), b['txcount'] + 1)
            bad.append(f"wrong tx count accepted at {b['height']}")
        except ValueError:
            pass
    return not bad, '; '.join(bad) or '4 real blocks: 10 miniblocks, 1 final, 8-byte tags; wrong tx count refused'


def kat8():
    """r33 3c: m1's Settle fee was None (the wallet had not indexed it in 40 s), so fees_total_atomic missed 600 and
    the chain-audit sum was off by exactly 600. resolve_fees must fill it; cycle_audit.audit must take a record without
    m3 rounds."""
    sys.path.insert(0, str(ROOT / 'playbooks'))
    import gt_cycle
    import cycle_audit
    bad = []
    for late, want, src in ((None, 600, 'fees set in the tx'), (612, 612, 'wallet entry (late)')):
        c = gt_cycle.Cycle.__new__(gt_cycle.Cycle)
        rec = {'who': 'm1', 'entry': 'Settle', 'fees_set': 600, 'fee': None}
        c._unresolved, c.fee_of = [(rec, 'm1', 'ab' * 32)], (lambda n, t, v=late: v)
        c.resolve_fees()
        if rec['fee'] != want or rec.get('fee_source') != src or c._unresolved:
            bad.append(f'late {late}: {rec}')
    c = gt_cycle.Cycle.__new__(gt_cycle.Cycle)
    rec = {'who': 'm1', 'entry': 'Settle', 'fees_set': None, 'fee': None}
    c._unresolved, c.fee_of = [(rec, 'm1', 'cd' * 32)], (lambda n, t: None)
    c.resolve_fees()
    if rec['fee'] is not None or len(c._unresolved) != 1:
        bad.append('a fee with no source was invented')
    r = {'measured_at': '2026-11-18T05:03:46-08:00', 'wallets': ['m1', 'm2'], 'results': {'m3_rounds': [], 'audits': [{}]},
         'payoff_atomic': {'m1': -1000, 'm2': 56}, 'fees_total_atomic': 944, 'start_height': 10, 'end_height': 20}
    out = cycle_audit.audit(r, [{'kind': 'cycle_start', 'ts': '2026-11-18T04:39:00-08:00'}], [], {}, chain=lambda lo, hi: {'m1': 0, 'm2': 0})
    if out['rounds'] or not out['sum_check']['ok']:
        bad.append(f'audit-only record: {out["rounds"]} {out["sum_check"]}')
    return not bad, '; '.join(bad) or 'unindexed fee resolved (late lookup / fee set in the tx), none invented; audit-only record audited'


def kat9():
    """GT-B29: the Python member tag (gtlib.pool_tag) equals the DVM test's tag for the four fixed test wallets."""
    sys.path.insert(0, str(ROOT / 'playbooks'))
    import gtlib
    vec = json.loads((ROOT / 'dvm/testdata/r33_tagvec.json').read_text())
    bad = [a[:12] for a, t in vec.items() if gtlib.pool_tag(a) != t]
    return not bad and len(vec) == 4, f'{len(vec)} vector entries, mismatches {bad}' if bad else f'{len(vec)}/4 tags equal the DVM vector'


def main():
    fails = 0
    for name, k in (('R33-1', kat1), ('R33-2', kat2), ('R33-3', kat3), ('R33-4', kat4), ('R33-5', kat5), ('R33-6', kat6), ('R33-7', kat7), ('R33-8', kat8), ('R33-9', kat9)):
        ok, why = k()
        print(f"{'ok  ' if ok else 'FAIL'} {name}: {why}")
        fails += not ok
    print(f'\nr33 game-theory KATs: {9 - fails}/9 ok')
    return 3 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
