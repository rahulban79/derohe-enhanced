#!/usr/bin/env python3
"""R29 B110: SC payouts over run C's range, the DC3 figure FQ2/B110 left pending (rft §0.8.9, §7 B110).

The window's 199 SC txs (dataset r28d derived/txs.jsonl.gz, tx_type SC) split at run C's first topo: 89 lie below
7,467,516 (no held state: they stay `pending`), 110 lie in 7,467,516..7,497,942, where the archive replay (tools/forensics/a2
through p2p.Add_Complete_Block_HF3, end root = our recorded treehash) holds the state before and after every block.
The emission auditor (glue/emission, tools/emission-audit -archive -sc-blocks-out) audits those blocks on a clone of
the replayed datadir; SC payouts are the plaintext DERO an SC paid into accounts, matched by the auditor from the
balance-tree diff (emission.go matchPayout). This tool joins the SC txs to the audited SC blocks and writes the figure
with its bound: class DC3, scope, coverage num/den over SC txs and over their carrier blocks, bound_type exact only
when every carrier block is audited with an exact verdict (ok / ok_sc), else lower-bound; unknowns stay `pending`.

  python3 -I harness/forensics/b110_sc_payouts_r29.py --dataset forensics/r28d --sc-blocks FILE --replay-summary FILE --out FILE
Counts and sums only: no TXID-to-account link, no address (the export carries none; rule 13).
"""
import argparse, gzip, hashlib, json, sys
from pathlib import Path

RUN_C = (7467516, 7497942)          # run C's first topo .. the window's last height (topo == height in this range)
EXACT = ('ok', 'ok_sc')


def sc_txs(txs_gz_bytes):
    rows = [json.loads(l) for l in gzip.decompress(txs_gz_bytes).decode().splitlines() if l.strip()]
    return [r for r in rows if r.get('tx_type') == 'SC']


def join(sc, blocks, lo=RUN_C[0], hi=RUN_C[1]):
    """sc: SC tx rows (carrier_height); blocks: exported SC blocks {height: record}. Returns the figure object."""
    inr = [r for r in sc if lo <= r['carrier_height'] <= hi]
    below = [r for r in sc if r['carrier_height'] < lo]
    hs = sorted({r['carrier_height'] for r in inr})
    aud = [h for h in hs if h in blocks]
    exact = [h for h in aud if blocks[h].get('verdict') in EXACT and not blocks[h].get('error')]
    verdicts = {}
    for h in aud:
        v = blocks[h].get('verdict')
        verdicts[v] = verdicts.get(v, 0) + 1
    payout = sum(blocks[h].get('sc_payout', 0) for h in exact)
    deposits = sum(blocks[h].get('sc_deposits', 0) for h in exact)
    txs_exact = sum(1 for r in inr if r['carrier_height'] in set(exact))
    full = len(exact) == len(hs) and len(hs) > 0
    calls_eq = all(blocks[h].get('sc_calls', 0) >= sum(1 for r in inr if r['carrier_height'] == h) for h in aud)
    return {
        'id': 'dc3-runc-sc-payouts', 'class': 'DC3', 'label': 'SC payouts (plaintext DERO paid by SCs into accounts), run C range',
        'scope': {'heights': [lo, hi], 'state': 'run C archive replay (end root = recorded treehash)'},
        'value': payout, 'unit': 'atomic DERO',
        'sc_deposits_same_blocks': deposits,
        'coverage': {'txs': {'num': txs_exact, 'den': len(inr)}, 'blocks': {'num': len(exact), 'den': len(hs)}},
        'bound_type': 'exact' if full else 'lower-bound',
        'verdicts': dict(sorted(verdicts.items())), 'blocks_not_exported': len(hs) - len(aud),
        'sc_calls_cover_txs': calls_eq,
        'below_run_c': {'txs': len(below), 'value': 'pending', 'reason': 'no held state below 7,467,516 (derived/a2.json)'},
        'window_sc_txs': len(sc),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--dataset', default='forensics/r28d'); ap.add_argument('--sc-blocks', required=True)
    ap.add_argument('--replay-summary', required=True); ap.add_argument('--out', required=True)
    a = ap.parse_args(argv)
    txsb = (Path(a.dataset) / 'derived/txs.jsonl.gz').read_bytes()
    blocks = {}
    for l in Path(a.sc_blocks).read_text().splitlines():
        if l.strip():
            o = json.loads(l)
            blocks[o['height']] = o
    rs = json.loads(Path(a.replay_summary).read_text())
    fig = join(sc_txs(txsb), blocks)
    out = {'kind': 'r29_b110_sc_payouts', 'figure': fig,
           'inputs': {'txs_jsonl_sha256': hashlib.sha256(txsb).hexdigest(),
                      'sc_blocks_sha256': hashlib.sha256(Path(a.sc_blocks).read_bytes()).hexdigest(),
                      'replay': {k: rs.get(k) for k in ('from', 'to', 'added', 'last_topo', 'last_root', 'expect_root',
                                                        'end_state_match', 'stopped')}},
           'replay_end_state_match': rs.get('end_state_match') is True}
    if not out['replay_end_state_match']:
        out['figure']['bound_type'] = 'unbounded'
        out['figure']['value'] = 'pending'
    Path(a.out).write_text(json.dumps(out, indent=1, sort_keys=True) + '\n')
    print(json.dumps({k: fig[k] for k in ('value', 'bound_type', 'coverage', 'verdicts')}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
