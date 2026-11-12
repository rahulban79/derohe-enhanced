#!/usr/bin/env python3
"""R30 B208 canonicality parity: the Go port in tools/forensics/b182deep2 (canon) against the Python structural
verifier audit2.struct_tx (D2-12, B97) on every held proof-carrying body of the v4 store (raw/tx_bodies.jsonl.gz rows,
bodies by SHA-256 in the store). Per body the (points, scalars, failed checks) must be equal; a single difference
FAILs. Offline: no network, no node.

  python3 -I harness/forensics/canon_parity_r30.py --decoder BIN [--dataset forensics/r28d] [--store DIR]
        [--out harness/runtime/r30_genesis_canon_parity.json]
"""
import argparse, gzip, hashlib, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import audit2 as A2  # noqa: E402
import audit_check as AC  # noqa: E402
import b182_deep_r29 as R  # noqa: E402


def go_view(d):
    return {'points': d.get('cp', 0), 'scalars': d.get('cs', 0), 'checks': d.get('cf') or {}}


def py_view(b, P, N):
    r = A2.struct_tx(b, P, N)
    return {'points': r['points'], 'scalars': r['scalars'], 'checks': r['checks']}


def compare(bodies, go_out, P, N):
    """{'bodies','proof_carrying','equal','differ','points','scalars','failed'} (pure apart from struct_tx)."""
    res = {'bodies': len(bodies), 'proof_carrying': 0, 'equal': 0, 'differ': [], 'points': 0, 'scalars': 0,
           'failed': {}, 'go_errors': 0}
    for (t, b), d in zip(bodies, go_out):
        if not d.get('ok'):
            res['go_errors'] += 1
            res['differ'].append(t[:8])
            continue
        g, p = go_view(d), py_view(b, P, N)
        if p['points']:
            res['proof_carrying'] += 1
        res['points'] += p['points']
        res['scalars'] += p['scalars']
        for k, n in p['checks'].items():
            res['failed'][k] = res['failed'].get(k, 0) + n
        if g == p:
            res['equal'] += 1
        else:
            res['differ'].append(t[:8])
    res['verdict'] = 'PASS' if not res['differ'] and res['equal'] == res['bodies'] and res['bodies'] else 'FAIL'
    return res


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--decoder', required=True)
    ap.add_argument('--dataset', default='forensics/r28d')
    ap.add_argument('--store', default=str(Path.home() / 'derohe-persist' / 'forensics_raw_r26' / 'blobs'))
    ap.add_argument('--out', default='harness/runtime/r30_genesis_canon_parity.json')
    a = ap.parse_args(argv)
    rows = [json.loads(l) for l in gzip.decompress((ROOT / a.dataset / 'raw/tx_bodies.jsonl.gz').read_bytes()).decode().splitlines() if l.strip()]
    bodies, seen = [], set()
    for r in rows:
        p = Path(a.store) / r['sha256']
        if r['txid'] in seen or not p.exists():
            continue
        b = p.read_bytes()
        if hashlib.sha256(b).hexdigest() != r['sha256']:
            continue
        seen.add(r['txid'])
        bodies.append((r['txid'], b))
    P, N = A2.bn256_constants(ROOT)
    dec = R.Decoder(a.decoder)
    try:
        out = []
        for i in range(0, len(bodies), 200):
            out += dec.run([('t', b.hex()) for _, b in bodies[i:i + 200]])
    finally:
        dec.close()
    res = compare(bodies, out, P, N)
    res.update({'dataset': a.dataset, 'rows': len(rows), 'constants_from': 'cryptography/bn256/constants.go (P, Order)',
                'go': 'tools/forensics/b182deep2 canon', 'python': 'harness/forensics/audit2.py struct_tx (D2-12)',
                'bodies_sha256': hashlib.sha256(''.join(t for t, _ in bodies).encode()).hexdigest()})
    res['differ'] = res['differ'][:20]
    Path(ROOT / a.out).write_text(json.dumps(res, indent=1, sort_keys=True) + '\n')
    print(json.dumps({k: res[k] for k in ('bodies', 'proof_carrying', 'equal', 'points', 'scalars', 'failed', 'verdict')}))
    return 0 if res['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
