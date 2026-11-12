#!/usr/bin/env python3
"""R30 B203 (a) (rft §8 S0; finding dc2-created-value-denominator): the DENOMINATOR of the DC2 figure "value created
under the proof-soundness defect": the number of proof-carrying txs since genesis, counted from held records. Only
NORMAL, BURN_TX and SC_TX carry a range proof (one crypto.Proof per payload; transaction/transaction.go:33-38 types,
the payload `Proof`); REGISTRATION, PREMINE and COINBASE carry none and are never counted. The VALUE stays the word
`unbounded` (FQ5, B113: no public-data test separates the cases; G31 refuses any other DC2 bound): this file moves the
denominator only, never the value.

Segments (each from a pinned record; NORMAL + SC + BURN per range):
  0..7,398,264            harness/runtime/r29_b182_deep_census.json types (TXIDs deduplicated within the run's window)
  7,398,265..7,412,664    harness/runtime/r29_b182_fetch_census.json fetched_below_7412665.types
  7,412,665..7,415,463    harness/runtime/r29_b182_fetch_census.json wall1_7412665_7415463.types
  7,415,464..7,415,465    harness/runtime/r29_b182_fetch_census.json gap_7415464_7415465.types
  7,415,466..7,497,942    forensics/<ds>/derived/txs.jsonl.gz rows by carrier height (the window)
  7,497,943..7,498,539    harness/runtime/r29_b182_offline_census.json gap_7497943_7498539.types
  7,498,540..tip          pending (no tx-type census record yet: S3)
Dedup by TXID: where both segments hold the TXID lists (the window rows and the link/gap block tx lists of the v1
dataset), a TXID counted in the window and listed again by a block of another segment is counted once; the segments
held as counts only (deep, fetch) cannot be compared TXID by TXID and say so.

  python3 -I harness/forensics/dc2_den.py [--dataset forensics/r28d] [--out harness/runtime/r30_dc2_den.json]
"""
import argparse, gzip, hashlib, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
PROOF_TYPES = ('NORMAL', 'SC', 'BURN')          # census spelling of NORMAL / SC_TX / BURN_TX
WINDOW = (7415466, 7497942)
CENSUS = {'deep': 'harness/runtime/r29_b182_deep_census.json', 'fetch': 'harness/runtime/r29_b182_fetch_census.json',
          'offline': 'harness/runtime/r29_b182_offline_census.json'}
V1 = 'forensics/r25'
OUT = 'harness/runtime/r30_dc2_den.json'
LAST_COUNTED = 7498539


def sha(b):
    return hashlib.sha256(b).hexdigest()


def proof_txs(types):
    """NORMAL + SC + BURN of one census `types` dict; REGISTRATION is never a proof-carrying tx. Pure."""
    return sum(int(types.get(k, 0)) for k in PROOF_TYPES)


def gz_rows(b):
    return [json.loads(l) for l in gzip.decompress(b).decode().splitlines() if l.strip()]


def window_segment(txs, listings, window=WINDOW):
    """(count, overlap_txids) for the window: proof-carrying rows of derived/txs.jsonl.gz whose carrier height is in the
    window, and those of them that a block OUTSIDE the window lists too (already counted by that block's segment). Pure.
    `listings`: {txid: set(heights)} from the held block tx lists."""
    rows = [r for r in txs if r.get('tx_type') in PROOF_TYPES and window[0] <= r['carrier_height'] <= window[1]]
    over = sorted(r['txid'] for r in rows if any(not window[0] <= h <= window[1] for h in listings.get(r['txid'], ())))
    return len(rows), over


def build(root=ROOT, dataset='forensics/r28d'):
    root = Path(root)
    pins, C = {}, {}
    for k, rel in CENSUS.items():
        b = (root / rel).read_bytes()
        pins[rel] = sha(b)
        C[k] = json.loads(b)
    tb = (root / dataset / 'derived' / 'txs.jsonl.gz').read_bytes()
    pins[f'{dataset}/derived/txs.jsonl.gz'] = sha(tb)
    listings = {}
    for rel in ('derived/window.jsonl.gz', 'derived/link.jsonl.gz'):
        b = (root / V1 / rel).read_bytes()
        pins[f'{V1}/{rel}'] = sha(b)
        for r in gz_rows(b):
            for t in r.get('tx_hashes') or []:
                listings.setdefault(t, set()).add(r['height'])
    d, f, o = C['deep'], C['fetch'], C['offline']
    wn, over = window_segment(gz_rows(tb), listings)
    segs = [
        {'range': d['ranges'][0], 'count': proof_txs(d['types']), 'types': d['types'], 'anchor': CENSUS['deep'] + ' types',
         'txid_lists': 'counts only (TXIDs deduplicated within the run: 200,000-tx window)'},
        {'range': f['fetched_below_7412665']['range'], 'count': proof_txs(f['fetched_below_7412665']['types']),
         'types': f['fetched_below_7412665']['types'], 'anchor': CENSUS['fetch'] + ' fetched_below_7412665.types',
         'txid_lists': 'counts only'},
        {'range': f['wall1_7412665_7415463']['range'], 'count': proof_txs(f['wall1_7412665_7415463']['types']),
         'types': f['wall1_7412665_7415463']['types'], 'anchor': CENSUS['fetch'] + ' wall1_7412665_7415463.types',
         'txid_lists': 'counts only'},
        {'range': f['gap_7415464_7415465']['range'], 'count': proof_txs(f['gap_7415464_7415465']['types']),
         'types': f['gap_7415464_7415465']['types'], 'anchor': CENSUS['fetch'] + ' gap_7415464_7415465.types',
         'txid_lists': f'{V1}/derived/link.jsonl.gz'},
        {'range': list(WINDOW), 'count': wn, 'anchor': f'{dataset}/derived/txs.jsonl.gz tx_type by carrier_height',
         'txid_lists': f'{V1}/derived/window.jsonl.gz'},
        {'range': o['gap_7497943_7498539']['range'], 'count': proof_txs(o['gap_7497943_7498539']['types']),
         'types': o['gap_7497943_7498539']['types'], 'anchor': CENSUS['offline'] + ' gap_7497943_7498539.types',
         'txid_lists': f'{V1}/derived/link.jsonl.gz'},
    ]
    gaps = [(a['range'][1], b['range'][0]) for a, b in zip(segs, segs[1:]) if a['range'][1] + 1 != b['range'][0]]
    raw = sum(s['count'] for s in segs)
    den = raw - len(over)
    return {
        'schema': 'r30 dc2 denominator v1 (rft §7 B203 a)', 'row': 'B203', 'class': 'DC2',
        'figure': 'dc2-created-value', 'value': 'unbounded', 'bound_type': 'unbounded',
        'proof_types': list(PROOF_TYPES), 'proof_types_anchor': 'transaction/transaction.go:33-38 (NORMAL, BURN_TX, SC_TX carry payload proofs)',
        'segments': segs, 'segments_tile': not gaps and segs[0]['range'][0] == 0 and segs[-1]['range'][1] == LAST_COUNTED,
        'segment_gaps': gaps,
        'sum_of_segments': raw, 'overlap_txids_counted_twice': len(over),
        'overlap_txid_prefixes': [t[:8] for t in over],
        'den': den, 'den_scope': [0, LAST_COUNTED],
        'den_pending': {'range': [LAST_COUNTED + 1, 'tip'], 'why': 'no tx-type census record for 7,498,540..tip yet (S3)'},
        'dedup': ('TXIDs counted in the window and listed by a block of another TXID-listed segment are counted once; the '
                  'deep and fetch segments are counts only and cannot be compared TXID by TXID'),
        'inputs': dict(sorted(pins.items())),
        'moves_when': ('the den grows when the S3 census types 7,498,540..tip and may shrink by cross-segment repeats when '
                       'the S2 exact-dedup TXID sets exist; the VALUE moves only with an upstream fix or a published '
                       'detector (FQ5, B113), never from this count'),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--root', default=str(ROOT)); ap.add_argument('--dataset', default='forensics/r28d')
    ap.add_argument('--out', default=OUT)
    a = ap.parse_args(argv)
    rec = build(a.root, a.dataset)
    if a.out:
        Path(a.root, a.out).write_text(json.dumps(rec, indent=1, sort_keys=True) + '\n')
    print(f"dc2 den: segments {[s['count'] for s in rec['segments']]} sum {rec['sum_of_segments']:,}, overlap "
          f"{rec['overlap_txids_counted_twice']} {rec['overlap_txid_prefixes']} -> den {rec['den']:,} over 0..{LAST_COUNTED:,} "
          f"(tile {rec['segments_tile']}); value {rec['value']}")
    return 0 if rec['segments_tile'] else 6


if __name__ == '__main__':
    sys.exit(main())
