#!/usr/bin/env python3
"""pool_census.py — R33 GT-B35 (artifacts/dero-game-theory-rft.md §7): the gt_pool concentration alarm over epochs.

gt_pool stores, for every proven block, a count per miniblock KeyHash and epoch (`k<e>_<keyhash>`, `kn<e>`, `km<e>`;
gametheory/contracts/gt_pool.bas census()). One epoch of follow-mode proving holds too few miniblocks for the alarm
(research gametheory/research/r33_forensics_and_security.md: threshold 0.40 with >= 360 proven normal miniblocks), so
the counts are summed over every epoch the contract holds, read-only with DERO.GetSC, and the alarm is evaluated only
when the sample is large enough. The KeyHash is a miner key hash (public in every block); no address is resolved.

  python3 -I harness/gametheory/pool_census.py --scid <pool scid> [--rpc 127.0.0.1:10102] [--out FILE]
Exit 0 no alarm · 4 alarm · 3 sample too small · 2 bad input.
"""
import argparse, json, re, sys, urllib.request

THRESHOLD, MIN_SAMPLE = 0.40, 360


def census(stringkeys):
    """{'epochs': [...], 'kn': n, 'counts': {keyhash: c}} summed over every epoch in the contract's variables."""
    counts, epochs = {}, set()
    for k, v in stringkeys.items():
        m = re.fullmatch(r'k(\d+)_([0-9a-f]{32})', k)
        if m:
            epochs.add(int(m.group(1)))
            counts[m.group(2)] = counts.get(m.group(2), 0) + int(v)
    return {'epochs': sorted(epochs), 'kn': sum(counts.values()), 'counts': counts}


def verdict(c):
    top = sorted(c['counts'].values(), reverse=True)
    share = top[0] / c['kn'] if c['kn'] else 0.0
    state = 'sample too small' if c['kn'] < MIN_SAMPLE else ('ALARM' if share >= THRESHOLD else 'no alarm')
    return {'epochs': c['epochs'], 'miniblocks': c['kn'], 'keyhashes': len(top), 'top_share': round(share, 4),
            'top5': top[:5], 'threshold': THRESHOLD, 'min_sample': MIN_SAMPLE, 'state': state}


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--scid', required=True)
    ap.add_argument('--rpc', default='127.0.0.1:10102')
    ap.add_argument('--out', default=None)
    a = ap.parse_args(argv)
    if not re.fullmatch(r'[0-9a-f]{64}', a.scid.lower()):
        print('a SCID is 64 hex digits'); return 2
    q = {'jsonrpc': '2.0', 'id': 1, 'method': 'DERO.GetSC', 'params': {'scid': a.scid.lower(), 'variables': True, 'code': False}}
    req = urllib.request.Request(f'http://{a.rpc}/json_rpc', data=json.dumps(q).encode(), headers={'Content-Type': 'application/json'})
    sk = json.load(urllib.request.urlopen(req, timeout=30))['result'].get('stringkeys') or {}
    v = verdict(census(sk))
    if a.out:
        open(a.out, 'w').write(json.dumps(v, indent=1))
    print(f"pool census: epochs {v['epochs']}, {v['miniblocks']} miniblocks, {v['keyhashes']} KeyHashes, top share "
          f"{v['top_share']:.3f} (threshold {THRESHOLD}, sample >= {MIN_SAMPLE}): {v['state']}")
    return {'no alarm': 0, 'ALARM': 4, 'sample too small': 3}[v['state']]


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
