#!/usr/bin/env python3
"""pool_audit.py — R33: an independent, read-only chain audit of one gt_pool epoch (no wallet, no run state).

The contract's own proven heights (`pr<h>` in DERO.GetSC) are the authoritative set (mainnet epoch 19,793: an audit
that trusted the driver's in-memory list missed 6 proofs made before a relaunch). For each proven height the block's
bytes are read again with DERO.GetBlock and parsed (playbooks/gt_pool_cycle.parse_block): credits per member tag =
non-final miniblocks carrying that tag in bytes 32..39, weights with the stake-maturity rule, the total, and every
claim against min(P0 x W / TW, cap % x P0). Tags are given (8-byte hex), or every `tag_<t>` key of the contract.

  python3 -I harness/gametheory/pool_audit.py --scid <pool scid> --epoch E [--tags t1,t2] [--rpc 127.0.0.1:10102]
Exit 0 PASS · 3 FAIL · 2 bad input.
"""
import argparse, json, re, sys, urllib.request
from pathlib import Path



def _g():
    """the playbook's parser, imported only when an audit runs (r33 TK1: --help must work in a sandboxed harness copy)"""
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'playbooks'))
    import gt_pool_cycle
    return gt_pool_cycle


def rpc(url, method, params):
    req = urllib.request.Request(url, data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
                                 headers={'Content-Type': 'application/json'})
    return json.load(urllib.request.urlopen(req, timeout=60))['result']


def audit(url, scid, e, tags=None):
    g = _g()
    r = rpc(url, 'DERO.GetSC', {'scid': scid, 'variables': True, 'code': False})
    v, bal = r.get('stringkeys') or {}, int(r.get('balance', 0))
    epochlen, m, cap, S = int(v.get('epochlen', 400)), int(v.get('mcount', 10)), int(v.get('cap', 30)), int(v.get('S', 100000))
    tagset = set(tags) if tags else {k[4:] for k in v if k.startswith('tag_')}
    stakes = {t: (int(v.get(f's_{t}', 0)), int(v.get(f'since_{t}', 0))) for t in tagset}
    proven = sorted(int(k[2:]) for k in v if k.startswith('pr') and k[2:].isdigit() and int(k[2:]) // epochlen == e)
    blocks, bad = [], []
    for h in proven:
        b = rpc(url, 'DERO.GetBlock', {'height': h})
        _, mbs = g.parse_block(b['blob'], int(b['block_header'].get('txcount', 0) or 0), m)
        if any(x[3] != h for x in mbs):
            bad.append(f'height field at {h}')
        blocks.append((h, mbs))
    w, W, TW = g.expected_epoch(blocks, tagset, stakes, S, epochlen)
    for t in tagset:
        if int(v.get(f'w{e}_{t}', 0)) != w.get(t, 0) or int(v.get(f'W{e}_{t}', 0)) != W.get(t, 0):
            bad.append(f'tag {t}: contract w {v.get(f"w{e}_{t}")} W {v.get(f"W{e}_{t}")} vs chain {w.get(t, 0)} {W.get(t, 0)}')
    if int(v.get(f'TW{e}', 0)) != TW:
        bad.append(f'TW {v.get(f"TW{e}")} vs {TW}')
    P0 = int(v.get(f'P0_{e}', 0))
    for t in tagset:
        if f'c{e}_{t}' in v:
            want = min(P0 * W.get(t, 0) // TW, P0 * cap // 100) if TW else 0
            if int(v[f'c{e}_{t}']) != want:
                bad.append(f'claim {t}: {v[f"c{e}_{t}"]} vs formula {want}')
    liab = int(v.get('burned', 0)) + sum(int(x) for k, x in v.items() if re.fullmatch(r'P\d+', k)) \
        + sum(int(x) for k, x in v.items() if k.startswith('s_'))
    if liab != bal:
        bad.append(f'conservation: balance {bal} vs burned + pools + stakes {liab}')
    return {'ok': not bad, 'problems': bad, 'epoch': e, 'proven': len(proven), 'proven_range': [proven[0], proven[-1]] if proven else [],
            'credits': w, 'weights': W, 'TW': TW, 'P0': P0, 'claims': {t: int(v[f'c{e}_{t}']) for t in tagset if f'c{e}_{t}' in v},
            'balance': bal, 'burned': int(v.get('burned', 0))}


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--scid', required=True)
    ap.add_argument('--epoch', type=int, required=True)
    ap.add_argument('--tags', default=None)
    ap.add_argument('--rpc', default='127.0.0.1:10102')
    ap.add_argument('--out', default=None)
    a = ap.parse_args(argv)
    if not re.fullmatch(r'[0-9a-f]{64}', a.scid.lower()):
        print('a SCID is 64 hex digits'); return 2
    res = audit(f'http://{a.rpc}/json_rpc', a.scid.lower(), a.epoch, a.tags.split(',') if a.tags else None)
    if a.out:
        Path(a.out).write_text(json.dumps(res, indent=1))
    print(f"pool audit epoch {res['epoch']}: {'PASS' if res['ok'] else 'FAIL'} · proven {res['proven']} {res['proven_range']} · "
          f"credits {sum(res['credits'].values())} · TW {res['TW']} · P0 {res['P0']} · claims {res['claims']} · burned {res['burned']}"
          + ('' if res['ok'] else f" · problems {res['problems'][:3]}"))
    return 0 if res['ok'] else 3


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
