#!/usr/bin/env python3
"""R30 B111 (rft §7 B111 residual; findings b111-residual-is-genesis-premine, b111-one-key-residual-genesis-key,
b111-residual-localised-genesis-key): the 1-key residual of Q-CS1 as a HYPOTHESIS record. It writes a NEW record
harness/runtime/r30_b111_premine.json and never edits the R29 record r29_b111_qcs1.json.

Identity under test:  balance-tree keys(h) == distinct registration keys(< h) + premine_keys   (premine_keys = 1)
The genesis block Puts its Miner_TX key into the balance tree with no REGISTRATION tx and returns on mainnet
(blockchain/transaction_execute.go:73-81; the key is config/config.go:118, recorded here only as a SHA-256).

What this record PROVES (arithmetic over pinned records and re-read code anchors):
  * registrations through 7,498,539 = 2,141,703 (deep + fetch + wall-1 + window + gap) and keys at 7,498,540 =
    2,141,704: residual 1;
  * registrations through 7,467,515 = 2,141,529 and keys at 7,467,515 (held archive) = 2,141,530: the residual is
    already there, and the 174 registrations of 7,467,516..7,498,539 match the +174 keys exactly;
  * the code has exactly one mainnet key-creating path without a registration (the genesis Put) at the anchors.
What it does NOT prove (status stays HYPOTHESIS): that the extra key IS the genesis key. That needs the set diff on an
APFS clone of the held 7,467,515 archive (keys minus registration keys == {genesis key}), plus registration counts as
DISTINCT KEYS (a pre-HF3 re-registration of one key, blockchain.go:716, lowers keys against TXIDs; the B182 counts are
distinct TXIDs under a 200,000-tx dedup window). Counts and hashes only (rule 13).

  python3 -I harness/forensics/b111_premine.py [--dataset forensics/r28d] [--out harness/runtime/r30_b111_premine.json]
"""
import argparse, gzip, hashlib, json, re, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import s0_checkpoint as S0  # noqa: E402

ROOT = S0.ROOT
PREMINE_KEYS = 1
OUT = 'harness/runtime/r30_b111_premine.json'
RECS = {'deep': 'harness/runtime/r29_b182_deep_census.json', 'fetch': 'harness/runtime/r29_b182_fetch_census.json',
        'offline': 'harness/runtime/r29_b182_offline_census.json', 'b111': 'harness/runtime/r29_b111_qcs1.json'}
ARCHIVE_TOPO = 7467515
ANCHOR_TOPO = 7498540


def residual(keys, registrations, premine=PREMINE_KEYS):
    """keys not attributed once the premine term is counted (0 = the identity holds). Pure."""
    return keys - registrations - premine


def status(ok):
    """the record status: a HYPOTHESIS either way (the S4 set diff has not run; never CONFIRMED here, R30 D3a). Pure."""
    return 'HYPOTHESIS (arithmetic consistent)' if ok else 'HYPOTHESIS (arithmetic does NOT close: re-check the inputs)'


def genesis_key_sha(root=ROOT):
    """SHA-256 of the genesis miner key hex in config/config.go (the line marked `miners public key`), and its line"""
    for i, l in enumerate((Path(root) / 'config' / 'config.go').read_text().splitlines(), 1):
        m = re.search(r'"([0-9a-f]{64,66})"\s*[+,]?\s*//\s*miners public key', l)
        if m:
            return hashlib.sha256(m.group(1).encode()).hexdigest(), i
    return None, None


def build(root=ROOT, dataset='forensics/r28d'):
    root = Path(root)
    R, pins = {}, {}
    for k, rel in RECS.items():
        b = (root / rel).read_bytes()
        R[k], pins[rel] = json.loads(b), hashlib.sha256(b).hexdigest()
    tb = (root / dataset / 'derived' / 'txs.jsonl.gz').read_bytes()
    pins[f'{dataset}/derived/txs.jsonl.gz'] = hashlib.sha256(tb).hexdigest()
    txs = [json.loads(l) for l in gzip.decompress(tb).decode().splitlines() if l.strip()]
    regs = [r['carrier_height'] for r in txs if r.get('tx_type') == 'REGISTRATION']
    f, o = R['fetch'], R['offline']
    seg = {'0..7398264': R['deep']['types']['REGISTRATION'],
           '7398265..7412664': f['fetched_below_7412665']['registrations'],
           '7412665..7415463': f['wall1_7412665_7415463']['registrations'],
           '7415464..7415465': f['gap_7415464_7415465']['registrations'],
           '7415466..7497942 (window, by carrier height)': sum(1 for h in regs if 7415466 <= h <= 7497942)}
    gap_ds = sum(1 for h in regs if 7497943 <= h <= 7498539)
    seg['7497943..7498539'] = o['gap_7497943_7498539']['registrations']
    thru_anchor = sum(seg.values())
    thru_archive = (seg['0..7398264'] + seg['7398265..7412664'] + seg['7412665..7415463'] + seg['7415464..7415465']
                    + sum(1 for h in regs if 7415466 <= h <= ARCHIVE_TOPO))
    above_archive = thru_anchor - thru_archive
    k_anchor = R['b111']['census'][str(ANCHOR_TOPO)]['balance_tree_keys']
    k_archive = R['b111']['comparisons']['held_archive_7467515']['balance_tree_keys']
    gsha, gline = genesis_key_sha(root)
    anchors = [S0.anchor(root, 'blockchain/transaction_execute.go', 73, 'if genesis == true'),
               S0.anchor(root, 'blockchain/transaction_execute.go', 77, 'balance_tree.Put(tx.MinerAddress[:]'),
               S0.anchor(root, 'blockchain/transaction_execute.go', 79, 'if globals.IsMainnet()'),
               S0.anchor(root, 'blockchain/transaction_execute.go', 200, 'balance_tree.Put(tx.MinerAddress[:]')]
    proven = {
        'residual_at_7498540_without_premine': k_anchor - thru_anchor,
        'residual_at_7498540_with_premine': residual(k_anchor, thru_anchor),
        'residual_at_7467515_without_premine': k_archive - thru_archive,
        'residual_at_7467515_with_premine': residual(k_archive, thru_archive),
        'keys_added_7467516_7498540': k_anchor - k_archive, 'registrations_7467516_7498539': above_archive,
        'keys_added_equal_registrations': k_anchor - k_archive == above_archive,
        'gap_registrations_dataset_vs_census_equal': gap_ds == seg['7497943..7498539'],
        'code_anchors_reread': all(a['ok'] for a in anchors),
    }
    ok = (proven['residual_at_7498540_with_premine'] == 0 and proven['residual_at_7467515_with_premine'] == 0
          and proven['keys_added_equal_registrations'] and proven['code_anchors_reread'])
    return {
        'schema': 'r30 b111 premine v1 (rft §7 B111 residual)', 'row': 'B111', 'class': 'DC3',
        'status': status(ok),
        'identity': 'balance-tree keys == registrations + premine_keys (premine_keys = 1: the genesis Put)',
        'premine_keys': PREMINE_KEYS,
        'registrations_by_segment': seg, 'registrations_through_7498539': thru_anchor,
        'registrations_through_7467515': thru_archive,
        'balance_tree_keys': {str(ANCHOR_TOPO): k_anchor, str(ARCHIVE_TOPO): k_archive},
        'proven': proven, 'code_anchors': anchors,
        'genesis_key': {'sha256_of_hex': gsha, 'anchor': f'config/config.go:{gline}', 'note': 'the key itself is not written (rule 13)'},
        'not_proven': [
            'the extra key IS the genesis key: set diff on an APFS clone of the held 7,467,515 archive (keys minus '
            'registration keys == {genesis key}); never the live store (S4)',
            'registrations as DISTINCT KEYS: the counts are distinct TXIDs (200,000-tx dedup window); a pre-HF3 '
            're-registration of one key (blockchain.go:716) would lower keys against TXIDs (S2 exact recount + key digests, B208)',
        ],
        'closes_when': 'the S4 set diff writes {genesis key} == keys minus registration keys into this record (new version)',
        'inputs': dict(sorted(pins.items())),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--root', default=str(ROOT)); ap.add_argument('--dataset', default='forensics/r28d')
    ap.add_argument('--out', default=OUT)
    a = ap.parse_args(argv)
    rec = build(a.root, a.dataset)
    if a.out:
        S0.write_record(Path(a.root) / a.out, rec)
    p = rec['proven']
    print(f"b111: registrations through 7,498,539 {rec['registrations_through_7498539']:,} vs keys {rec['balance_tree_keys'][str(ANCHOR_TOPO)]:,}; "
          f"through 7,467,515 {rec['registrations_through_7467515']:,} vs {rec['balance_tree_keys'][str(ARCHIVE_TOPO)]:,}; "
          f"residual w/o premine {p['residual_at_7498540_without_premine']}/{p['residual_at_7467515_without_premine']}, with "
          f"{p['residual_at_7498540_with_premine']}/{p['residual_at_7467515_with_premine']}; +keys {p['keys_added_7467516_7498540']} "
          f"== regs {p['registrations_7467516_7498539']}: {p['keys_added_equal_registrations']}; status {rec['status']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
