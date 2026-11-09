#!/usr/bin/env python3
"""R29 (rft §7 B182, user option (a) 2026-11-07): registration census over ranges whose tx bodies were fetched read-only
from archive RPC endpoints (harness/forensics/acquire.py fetch-txs / fetch-blocks; pseudonymised sources).

A fetched body counts only if (i) the node's own decoder re-derives exactly the requested txid (Keccak-256 of the core
statement, transaction/transaction.go:195) and re-serializes byte-exact, and (iii) that txid is listed by a block
already held as RAW in this tree's forensics datasets (or, for fetched blocks, whose decoder id equals the claimed hash
and whose tips chain joins a held block). Anything else is rejected and listed. Also re-checks the upper join of the
7,497,943..7,498,539 range: block 7,498,540's tips, decoded from its held blob, must name 7,498,539.

  python3 -I harness/forensics/b182_fetch_census_r29.py --forensics forensics --stage <dir> --decoder <bin> --out <json>
"""
import argparse, collections, glob, gzip, hashlib, json, os, subprocess
from pathlib import Path


def lz(h):
    n = 0
    for x in bytes.fromhex(h):
        if x:
            break
        n += 1
    return n


def sha(p):
    return hashlib.sha256(open(p, 'rb').read()).hexdigest()


def decode(decoder, reqs):
    if not reqs:
        return []
    p = subprocess.run([decoder], input='\n'.join(json.dumps(r) for r in reqs) + '\n', capture_output=True, text=True,
                       check=True)
    return [json.loads(l) for l in p.stdout.splitlines() if l.strip()]


def accept_tx(txid, d, listed):
    """(ok, why) for one fetched body given its decoder output d: check (i) the decoder re-derives exactly the requested
    txid and re-serializes byte-exact; check (iii) a held block lists the txid. Pure."""
    if not (d.get('ok') and d.get('txid') == txid and d.get('reserialize_equal')):
        return False, 'check (i): decoder txid / reserialize mismatch'
    if txid not in listed:
        return False, 'check (iii): no held block lists this txid'
    return True, ''


def chain_join(first_tips, fetched_ok, start):
    """walk down from height `start` while each fetched block's id is a tip of the block above it; returns (joined
    heights, the first height that breaks the chain or None). Pure."""
    joined, want, h = set(), first_tips, start
    while h in fetched_ok:
        if want is None or fetched_ok[h]['id'] not in want:
            return joined, h
        joined.add(h)
        want = fetched_ok[h]['tips']
        h -= 1
    return joined, None


def tx_hashes(r):
    x = r['tx_hashes']
    return json.loads(x.replace("'", '"')) if isinstance(x, str) else x


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--forensics', required=True)
    ap.add_argument('--stage', required=True)
    ap.add_argument('--decoder', required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    F, S = Path(a.forensics), Path(a.stage)
    typed = {t['txid']: t['tx_type'] for t in map(json.loads, gzip.open(F / 'r28/derived/txs.jsonl.gz', 'rt'))}
    link = {int(r['height']): r for r in map(json.loads, gzip.open(F / 'r25/derived/link.jsonl.gz', 'rt'))}
    wall = {int(r['height']): r for r in map(json.loads, gzip.open(F / 'r28/raw/wall1_blocks.jsonl.gz', 'rt'))}
    held_blocks = {**wall, **{h: r for h, r in link.items() if h in (7415464, 7415465)}}
    out = {'inputs': {p: sha(F / p) for p in ('r28/derived/txs.jsonl.gz', 'r25/derived/link.jsonl.gz',
                                              'r28/raw/wall1_blocks.jsonl.gz')},
           'method': 'read-only RPC fetch from pseudonymised archive endpoints (acquire.py); a body counts only after '
                     'the decoder re-derives the requested txid byte-exact and a held RAW block lists it'}

    # fetched blocks below the held range (fetch-blocks stage): decoder id == claimed hash, tips chain to a held block
    fb = {}
    for p in glob.glob(str(S / 'blocks' / '*' / '*.json')):
        r = json.loads(open(p).read())
        b = S / 'bin' / f"blk_{r['topo_requested']}.bin"
        b.parent.mkdir(parents=True, exist_ok=True)
        b.write_bytes(bytes.fromhex(r['blob']))
        fb[r['topo_requested']] = (r, str(b))
    dec = decode(a.decoder, [{'kind': 'block', 'path': v[1]} for _, v in sorted(fb.items())])
    by_path = {d['path']: d for d in dec}
    fetched_ok, rej_blocks = {}, []
    for h, (r, b) in sorted(fb.items()):
        d = by_path.get(b, {})
        if d.get('ok') and d.get('id') == r['claimed_hash'] and d.get('reserialize_equal') and d.get('height') == h:
            fetched_ok[h] = {'id': d['id'], 'tips': d['tips'], 'tx_hashes': d['tx_hashes'], 'source': r['source']}
        else:
            rej_blocks.append({'height': h, 'why': 'decoder id/height/reserialize mismatch or decode error',
                               'error': d.get('error')})
    # tips chain: walk down from the lowest held block (7,412,665) through fetched blocks
    first_held = min(wall)
    want_tip = wall[first_held].get('tips')
    want_tip = json.loads(want_tip.replace("'", '"')) if isinstance(want_tip, str) else want_tip
    joined, broken_at = chain_join(want_tip, fetched_ok, first_held - 1)
    out['fetched_blocks'] = {'held_range_lowest': first_held, 'fetched': len(fb), 'decoded_ok': len(fetched_ok),
                             'rejected': rej_blocks[:20], 'rejected_count': len(rej_blocks),
                             'tips_chain_joined': len(joined),
                             'joined_range': [min(joined), max(joined)] if joined else None,
                             'chain_broken_at': broken_at,
                             'by_source': dict(collections.Counter(v['source'] for v in fetched_ok.values()))}
    for h in joined:
        held_blocks[h] = {'tx_hashes': fetched_ok[h]['tx_hashes']}

    # fetched tx bodies: (i) the decoder re-derives the requested txid byte-exact; (iii) a held block lists it
    listed = {}
    for h, r in held_blocks.items():
        for t in tx_hashes(r):
            listed[t] = h
    recs = {}
    (S / 'bin').mkdir(parents=True, exist_ok=True)
    for p in glob.glob(str(S / 'txs' / '*.json')):
        r = json.loads(open(p).read())
        if not r.get('as_hex'):
            continue
        b = S / 'bin' / f"{r['txid_requested']}.tx"
        b.write_bytes(bytes.fromhex(r['as_hex']))
        recs[r['txid_requested']] = (r, str(b))
    dec = decode(a.decoder, [{'kind': 'tx', 'path': v[1]} for _, v in sorted(recs.items())])
    by_path = {d['path']: d for d in dec}
    ftype, rejected = {}, []
    for t, (r, b) in sorted(recs.items()):
        d = by_path.get(b, {})
        ok, why = accept_tx(t, d, listed)
        if ok:
            ftype[t] = d['tx_type']
        else:
            rejected.append({'txid': t, 'why': why, 'error': d.get('error')})
    out['fetched_txs'] = {'bodies': len(recs), 'accepted': len(ftype), 'rejected': rejected,
                          'by_source': dict(collections.Counter(recs[t][0]['source'] for t in ftype))}

    def census(name, lo, hi):
        hs = [h for h in range(lo, hi + 1)]
        missing = [h for h in hs if h not in held_blocks]
        txs = [t for h in hs if h in held_blocks for t in tx_hashes(held_blocks[h])]
        ty = {t: typed.get(t) or ftype.get(t) for t in txs}
        untyped = [t for t in txs if not ty[t]]
        regs = [t for t in txs if ty[t] == 'REGISTRATION']
        out[name] = {'range': [lo, hi], 'blocks_expected': len(hs), 'blocks_held': len(hs) - len(missing),
                     'txs': len(txs), 'typed_from_dataset': sum(1 for t in txs if t in typed),
                     'typed_from_fetch': sum(1 for t in txs if t not in typed and t in ftype),
                     'untyped': len(untyped), 'types': dict(collections.Counter(v for v in ty.values() if v)),
                     'registrations': len(regs),
                     'reg_by_leading_zero_bytes': {str(k): v for k, v in sorted(collections.Counter(lz(t) for t in regs).items())},
                     'reg_lt3': [t for t in regs if lz(t) < 3], 'complete': not missing and not untyped}

    census('wall1_7412665_7415463', 7412665, 7415463)
    census('gap_7415464_7415465', 7415464, 7415465)
    if joined:
        census('fetched_below_7412665', min(joined), max(joined))

    # upper join of 7,497,943..7,498,539: block 7,498,540 decoded from its held blob
    anchors = json.load(open(F / 'r25/raw/anchors.json'))
    an = [x for x in anchors if x.get('kind') == 'block' and x.get('height') == 7498540][0]
    blob = F / 'r25/raw/blobs' / an['sha256']
    d = decode(a.decoder, [{'kind': 'block', 'path': str(blob)}])[0]
    want = link[7498539]['blid']
    out['upper_join_7498540'] = {'blob_sha256': sha(blob), 'blob_sha256_eq_recorded': sha(blob) == an['sha256'],
                                 'decoded_ok': d.get('ok'), 'decoded_id': d.get('id'),
                                 'decoded_id_eq_recorded': d.get('id') == an['id'], 'decoded_height': d.get('height'),
                                 'decoded_tips': d.get('tips'), 'blid_7498539': want,
                                 'joins': bool(d.get('ok')) and want in (d.get('tips') or [])}
    Path(a.out).write_text(json.dumps(out, indent=1) + '\n')
    print(json.dumps({k: (v if k in ('upper_join_7498540',) else {kk: vv for kk, vv in v.items() if kk in (
        'registrations', 'reg_by_leading_zero_bytes', 'reg_lt3', 'complete', 'txs', 'untyped', 'blocks_held',
        'accepted', 'bodies', 'tips_chain_joined', 'joined_range', 'chain_broken_at', 'decoded_ok', 'fetched',
        'rejected_count')} if isinstance(v, dict) else v) for k, v in out.items() if k not in ('inputs', 'method')},
                     indent=1))


if __name__ == '__main__':
    main()
