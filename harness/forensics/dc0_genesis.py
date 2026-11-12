#!/usr/bin/env python3
"""R30 B209 (rft §8 S0; findings dc0-genesis-multiblock-txids, dc0-pre-window-multi-block-txids): TXIDs listed by two
or more blocks below the HF3 window, from the R29 B182 deep checkpoint (0..7,398,264). A batch record's `dup_txids`
names the TXIDs that batch lists again after an earlier verified listing (b182_deep_r29.py:461-475). The figure is the
DISTINCT count (a TXID in three blocks across two later batches is one TXID, listed three times), by class, type
evidence and HF era of the repeat listing. Counts and hashes only (rule 13): the TXID list itself is not written, only
the SHA-256 of the sorted list.

Class rule (rft §0.8.9; inclusions.json class_rules.inclusion_row): a multi-block TXID in the HF3 table is DC1, else DC0
(a duplicate outside the table fits no class). Type evidence: 'decoder' = the TXID is in a decoder-typed REGISTRATION
list of the checkpoint (reg_lt3: registrations with < 3 leading zero bytes); 'inferred-registration' = >= 3 leading
zero bytes (a random TXID has that with p = 2^-24; the registration PoW gives it); 'untyped' otherwise.
"Listed twice" is a LOWER BOUND (R30 D1): only a repeat inside the B182 dedup window (200,000 txs) is seen, and a
batch record's dup set (b182_deep_r29.py:475, a set of dup | dup_in_batch) cannot record a third listing inside one
batch, so `by_times_listed` keys read ">=n" (listed at least n times). "Executed twice / two bodies" stays PENDING (pre-HF3 blockchain.go:665,
716 and 995 neither refuse a stored TXID nor an existing registration; deciding it needs a replay, S7).

  python3 -I harness/forensics/dc0_genesis.py [--checkpoint PATH] [--out harness/runtime/r30_dc0_genesis.json]
"""
import argparse, collections, hashlib, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import s0_checkpoint as S0  # noqa: E402

ROOT = S0.ROOT
OUT = 'harness/runtime/r30_dc0_genesis.json'
LISTED_BOUND = 'lower-bound'     # R30 D1: the 200,000-tx dedup window hides far repeats (never 'exact')
LISTED_MOVES = 'the exact-dedup recount (S2, B182 report --exact) can only add TXIDs and listings (a lower bound)'


def lz(h):
    n = 0
    for x in bytes.fromhex(h):
        if x:
            break
        n += 1
    return n


def hf3_table(root=ROOT):
    """the 75 table TXIDs (blockchain/hardfork_fixes.go Bl_Tips lines), the parse classes.hf3_txids uses"""
    out = set()
    for l in (Path(root) / 'blockchain' / 'hardfork_fixes.go').read_text().splitlines():
        l = l.strip()
        if l.startswith('"') and 'Bl_Tips' in l:
            out.add(l.split('"')[1])
    return out


def era(lo, hi, hf):
    """the HF era of a batch [lo, hi] given the boundaries [(name, height)] in increasing order; 'straddles:<name>' when a
    boundary falls inside the batch. Pure."""
    name = 'pre-' + hf[0][0]
    for n, h in hf:
        if lo < h <= hi:
            return f'straddles:{n}'
        if lo >= h:
            name = n
    return name


def census(batches, table, hf):
    """the distinct multi-block TXID census (pure)."""
    rep = collections.Counter()           # txid -> number of REPEAT listings (listed = repeats + 1)
    first_rep = {}                        # txid -> (lo, hi) of its first repeat listing
    typed = set()
    for r in batches:
        typed.update(r.get('reg_lt3') or [])
        for t in r.get('dup_txids') or []:
            rep[t] += 1
            first_rep.setdefault(t, (r['lo'], r['hi']))
    by_class = collections.Counter('DC1' if t in table else 'DC0' for t in rep)
    by_listed = collections.Counter(f'\u2265{n + 1}' for n in rep.values())   # a lower bound per TXID (D1)
    ev = collections.Counter('decoder' if t in typed else 'inferred-registration' if lz(t) >= 3 else 'untyped' for t in rep)
    by_lz = collections.Counter(str(lz(t)) for t in rep)
    by_era = collections.Counter(era(*first_rep[t], hf) for t in rep)
    below_144k = sum(1 for t in rep if first_rep[t][1] < 144000)
    los = [first_rep[t][0] for t in rep]
    return {'distinct_txids': len(rep), 'repeat_listings': sum(rep.values()),
            'batch_records_with_repeats': sum(1 for r in batches if r.get('dup_txids')),
            'by_class': dict(sorted(by_class.items())), 'by_times_listed': dict(sorted(by_listed.items())),
            'type_evidence': dict(sorted(ev.items())), 'by_leading_zero_bytes': dict(sorted(by_lz.items())),
            'by_hf_era_of_repeat': dict(sorted(by_era.items())), 'repeat_below_144000': below_144k,
            'highest_repeat_batch_lo': max(los) if los else None, 'lowest_repeat_batch_lo': min(los) if los else None,
            'txid_list_sha256': hashlib.sha256('\n'.join(sorted(rep)).encode()).hexdigest()}


def build(ck, root=ROOT):
    b = S0.batches(ck['records'])
    H = S0.config_heights(root)
    hf = [('HF1', H['HF1_HEIGHT'][0]), ('MAJOR_HF2', H['MAJOR_HF2_HEIGHT'][0])]
    c = census(b, hf3_table(root), hf)
    lo, hi = min(r['lo'] for r in b), max(r['hi'] for r in b)
    return {
        'schema': 'r30 dc0 genesis v1 (rft §7 B209)', 'row': 'B209', 'class': 'DC0' if c['by_class'].get('DC0') else 'DC1',
        'evidence_class': 'DERIVED (B182 deep checkpoint dup_txids per batch, block ids and tips chain verified)',
        'scope': {'heights': [lo, hi], 'text': f'heights {lo:,}..{hi:,} (B182 deep census, below the HF3 window)'},
        'input': S0.pin(ck),
        'hf_eras': {n: {'height': h, 'anchor': f"config/config.go:{H[k][1]}"} for (n, h), k in zip(hf, ('HF1_HEIGHT', 'MAJOR_HF2_HEIGHT'))},
        'census': c,
        'figure_listed_twice': {'value': c['by_class'].get('DC0', 0), 'bound_type': LISTED_BOUND,
                                'coverage': {'num': hi - lo + 1, 'den': hi - lo + 1, 'num_anchor': 'checkpoint batch records (blocks verified)',
                                             'den_anchor': f'heights {lo}..{hi}'},
                                'caveat': ('a lower bound: distinct TXIDs whose repeat listing fell inside the B182 dedup '
                                           'window (200,000 txs, b182_deep_r29.py:428-429); a repeat further apart is not '
                                           'seen, and a batch dup set (b182_deep_r29.py:475) records one repeat per batch, '
                                           'until the exact-dedup recount (S2)'),
                                'moves_when': LISTED_MOVES},
        'figure_executed_twice': {'value': 'pending', 'bound_type': 'unbounded',
                                  'why': 'pre-HF3 blockchain.go:665 (no stored-TXID check), :716 (no existing-registration check), '
                                         ':995 (every listed tx executes): deciding the state effect needs a replay (S7)'},
        'rule': 'a multi-block TXID in the HF3 table is DC1, else DC0 (rft §0.8.9; inclusions.json class_rules.inclusion_row)',
        'moves_when': ('listed twice: the exact-dedup recount (S2, B182 report --exact) can only add TXIDs; executed twice: an '
                       'S7 replay of the repeat heights; type: a re-fetch of the bodies from 2+ sources typed by the decoder'),
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
    c = rec['census']
    print(f"dc0 genesis: {c['distinct_txids']:,} distinct multi-block TXIDs ({c['repeat_listings']:,} repeat listings), "
          f"classes {c['by_class']}, listed {c['by_times_listed']}, types {c['type_evidence']}, eras {c['by_hf_era_of_repeat']}, "
          f"below 144k {c['repeat_below_144000']:,}, highest batch {c['highest_repeat_batch_lo']:,}; pin equal {rec['input']['equal']}")
    return 0 if rec['input']['equal'] else 6


if __name__ == '__main__':
    sys.exit(main())
