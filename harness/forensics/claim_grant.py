#!/usr/bin/env python3
"""R30 B210 (rft §8 S0; finding claim-grant-identity-1358698): the claim-grant identity from public data. Every account
registered below height 144,000 on mainnet got 200 atomic (blockchain/transaction_execute.go:194-196), and CalcSupply
adds the constant 271,739,600 = 1,358,698 x 200 (blockchain/supply.go:7-9). This tool sums the REGISTRATION counts of
the R29 B182 deep checkpoint batches with hi < 144,000 (batches of 100 align with 144,000; check_blocks enforced
height == topo) and compares both numbers with the supply.go constants. DC3 (a public-value identity), never a supply
claim (G31); counts only (rule 13).

Grade: 'exact-under-window-dedup' while the count is the B182 run's distinct TXIDs under its 200,000-tx dedup window
(b182_deep_r29.py:428-429); the 3,603 second listings below 144,000 (dc0_genesis.py) were, by code reading, executed
again pre-HF3 (blockchain.go:995): whether that re-applied the grant stays pending until a replay (S7).

  python3 -I harness/forensics/claim_grant.py [--checkpoint PATH] [--out harness/runtime/r30_claim_grant.json]
"""
import argparse, json, re, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import s0_checkpoint as S0  # noqa: E402

ROOT = S0.ROOT
GRANT_BELOW = 144000            # transaction_execute.go:194 `height < 144000`
GRANT_ATOMIC = 200              # transaction_execute.go:195
OUT = 'harness/runtime/r30_claim_grant.json'


def supply_constants(root=ROOT):
    """(accounts, total, line numbers) parsed from blockchain/supply.go: the comment's account count and the added total"""
    acc = tot = None
    lines = {}
    for i, l in enumerate((Path(root) / 'blockchain' / 'supply.go').read_text().splitlines(), 1):
        m = re.search(r'there were (\d+) such accounts, so total of (\d+)', l)
        if m and acc is None:
            acc, lines['comment'] = int(m.group(1)), i
            lines['comment_total'] = int(m.group(2))
        m = re.match(r'\s*supply \+= (\d+)\s*$', l)
        if m and tot is None:
            tot, lines['add'] = int(m.group(1)), i
    return acc, tot, lines


def grant_census(batches, below=GRANT_BELOW):
    """{types, batches, last_hi, straddling} over the batch records wholly below `below` (hi < below). Pure."""
    ty, n, last, straddle = {}, 0, None, 0
    for r in batches:
        if r['hi'] < below:
            n += 1
            last = r['hi'] if last is None else max(last, r['hi'])
            for k, v in r['types'].items():
                ty[k] = ty.get(k, 0) + v
        elif r['lo'] < below:
            straddle += 1          # a batch across the boundary cannot be split from the record: counted apart
    return {'types': dict(sorted(ty.items())), 'batches': n, 'last_hi': last, 'straddling_batches': straddle}


def relistings_below(batches, below=GRANT_BELOW):
    """second listings (a TXID already verified in an earlier batch) in batches with hi < below. Pure."""
    return sum(len(r.get('dup_txids') or []) for r in batches if r['hi'] < below)


def build(ck, root=ROOT):
    b = S0.batches(ck['records'])
    c = grant_census(b)
    acc, tot, lines = supply_constants(root)
    reg = c['types'].get('REGISTRATION', 0)
    ok = reg == acc and reg * GRANT_ATOMIC == tot and c['straddling_batches'] == 0 and lines.get('comment_total') == tot
    return {
        'schema': 'r30 claim grant v1 (rft §7 B210)', 'class': 'DC3', 'row': 'B210',
        'evidence_class': 'DERIVED (B182 deep checkpoint batch records, decoder-typed, block ids verified)',
        'scope': {'heights': [0, GRANT_BELOW - 1], 'text': 'mainnet heights 0..143,999 (the claim-grant window)'},
        'input': S0.pin(ck),
        'census': c,
        'registrations_below_144000': reg,
        'grant_atomic_each': GRANT_ATOMIC,
        'value_atomic': reg * GRANT_ATOMIC,
        'supply_go': {'accounts': acc, 'total_atomic': tot, 'lines': lines,
                      'anchors': [f"blockchain/supply.go:{lines.get('comment')}", f"blockchain/supply.go:{lines.get('add')}",
                                  'blockchain/transaction_execute.go:194-196']},
        'identity_holds': ok,
        'bound_type': 'exact-under-window-dedup' if ok else 'pending',
        'grade_rule': ("'exact-under-window-dedup': the count is the B182 run's distinct TXIDs under its 200,000-tx dedup "
                       "window; it becomes exact after the exact-dedup recount (B182 report --exact, S2)"),
        'relistings_below_144000': relistings_below(b),
        'pending': ('whether the second listings below 144,000 re-applied the 200-atomic grant (pre-HF3 blockchain.go:995 '
                    'executes every listed tx) needs a replay (S7); the figure is the distinct-registration count only'),
        'moves_when': ('the exact-dedup recount (S2) replaces the window dedup; an S7 replay of 0..143,999 decides the '
                       're-applied grants'),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--checkpoint', default=str(S0.DEFAULT_CHECKPOINT))
    ap.add_argument('--out', default=OUT)
    ap.add_argument('--root', default=str(ROOT))
    a = ap.parse_args(argv)
    rec = build(S0.load(a.checkpoint, a.root), a.root)
    if a.out:
        S0.write_record(Path(a.root) / a.out, rec)
    print(f"claim grant: REGISTRATION below 144,000 = {rec['registrations_below_144000']:,} x 200 = {rec['value_atomic']:,}; "
          f"supply.go {rec['supply_go']['accounts']:,} / {rec['supply_go']['total_atomic']:,}; holds {rec['identity_holds']}; "
          f"relistings below 144k {rec['relistings_below_144000']:,}; pin equal {rec['input']['equal']}")
    return 0 if rec['identity_holds'] and rec['input']['equal'] else 6


if __name__ == '__main__':
    sys.exit(main())
