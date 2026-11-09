#!/usr/bin/env python3
# usage: python3 -I harness/forensics/b182_census_r29.py forensics harness/runtime/r29_b182_offline_census.json
# B182 offline registration census for the two ranges CD3 left pending (read-only over Release151 forensics + persist raw)
import gzip, json, sys, collections, hashlib
F = sys.argv[1]  # Release151 forensics dir
def lz(h):
    b = bytes.fromhex(h); n = 0
    for x in b:
        if x: break
        n += 1
    return n
def sha(p): return hashlib.sha256(open(p,'rb').read()).hexdigest()
T = {t['txid']: t for t in map(json.loads, gzip.open(F+'/r28/derived/txs.jsonl.gz','rt'))}
L = {r['height']: r for r in map(json.loads, gzip.open(F+'/r25/derived/link.jsonl.gz','rt'))}
W = {r['height']: r for r in map(json.loads, gzip.open(F+'/r28/raw/wall1_blocks.jsonl.gz','rt'))}
out = {'inputs': {p: sha(F+'/'+p) for p in ('r28/derived/txs.jsonl.gz','r25/derived/link.jsonl.gz','r28/raw/wall1_blocks.jsonl.gz')}}
def census(name, lo, hi, src):
    hs = list(range(lo, hi+1)); missing = [h for h in hs if h not in src]
    txs = [t for h in hs if h in src for t in src[h]['tx_hashes']]
    typed = [t for t in txs if t in T]; untyped = [t for t in txs if t not in T]
    regs = [t for t in typed if T[t]['tx_type'] == 'REGISTRATION']
    out[name] = {'range': [lo, hi], 'blocks_expected': len(hs), 'blocks_held': len(hs)-len(missing), 'blocks_missing': len(missing),
        'txs': len(txs), 'typed': len(typed), 'untyped': len(untyped),
        'types': dict(collections.Counter(T[t]['tx_type'] for t in typed)),
        'registrations': len(regs), 'reg_by_leading_zero_bytes': dict(sorted(collections.Counter(lz(t) for t in regs).items())),
        'reg_lt3': [t for t in regs if lz(t) < 3],
        'untyped_by_leading_zero_bytes': dict(sorted(collections.Counter(lz(t) for t in untyped).items())),
        'complete': not missing and not untyped}
for h in L: L[h]['tx_hashes'] = json.loads(L[h]['tx_hashes'].replace("'",'"')) if isinstance(L[h]['tx_hashes'], str) else L[h]['tx_hashes']
L = {int(h): v for h, v in L.items()}
census('gap_7497943_7498539', 7497943, 7498539, L)
census('gap_7415464_7415465', 7415464, 7415465, L)
census('wall1_7412665_7415463', 7412665, 7415463, {int(h): v for h, v in W.items()})
lows = [h for h in list(L)+list(W) if int(h) < 7412665]
out['below_7412665'] = {'held_blocks': len(lows), 'note': 'no holder: replaywall store 7,453,290..7,467,921, mainnet.zip 7,498,540..7,526,415, mainnet-old.zip ..7,453,822 (534 blocks), live store 7,498,540.. (block file names); only genesis below'}
json.dump(out, open(sys.argv[2], 'w'), indent=1); print(json.dumps(out, indent=1)[:3000])
