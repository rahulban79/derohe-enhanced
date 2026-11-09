#!/usr/bin/env python3
"""R29 B97: a second independent holder for the multi-block TXIDs (rft §7 B97, §8 R29 forensics; audit2 D2-11).

audit2's duplicate-body census (D2-11) compares every body copy held under each TXID that more than one RAW block
carries; at R28 every one of the 67 was held from ONE pseudonymous source only (with_2plus_sources 0). This tool asks
every archive endpoint of the private endpoint file for those TXIDs (read-only DERO.GetTransaction; polite: one
endpoint at a time, <= --rate requests/s, chunks of 16 txids), keeps a returned body only when audit_check's own
Keccak-256 TXID of its core statement equals the TXID asked for (check iii), and writes each kept copy into a NEW
staging dir in the layout audit2.body_copies reads (txs/<txid>.<src>.json: txid_requested, source, fetch_time, class
EXT, as_hex). Endpoint URLs never leave the private file; only pseudonyms are printed or written.

  python3 -I harness/forensics/b97_holders_r29.py fetch  --priv DIR --stage DIR [--dataset forensics/r28d]
                                                          [--sources src-1,...] [--rate 1] --out FILE
  python3 -I harness/forensics/b97_holders_r29.py census --stage DIR [--stage DIR ...] [--dataset forensics/r28d] --out FILE
Never talks to our own node; nothing here writes outside --stage and --out.
"""
import argparse, datetime, hashlib, json, sys, time, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import audit_check as AC  # noqa: E402  (the auditor's own decoder and Keccak; never the builder's)

CHUNK = 16   # GetTransaction serves at most 16 txids per call (measured by the B182 deep tool, r29)


def multi_block_txids(ds):
    """the TXIDs carried by more than one RAW block (derived/inclusions.json rows with 2+ heights)"""
    inc = json.loads((Path(ds) / 'derived/inclusions.json').read_text())
    return sorted(r['txid'] for r in inc['rows'] if len(r.get('heights') or []) > 1)


def txid_of(b):
    return AC.decode_tx(b)['txid']


def check_copy(txid, hexstr, txid_fn=txid_of):
    """'ok' | 'unserved' | 'bad-hex' | 'txid-mismatch' | 'undecodable' for one returned body"""
    if not hexstr:
        return 'unserved'
    try:
        b = bytes.fromhex(hexstr)
    except ValueError:
        return 'bad-hex'
    try:
        return 'ok' if txid_fn(b) == txid else 'txid-mismatch'
    except (AC.DecodeError, IndexError, ValueError):
        return 'undecodable'


def http_post(url, body, timeout=60):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read(64 << 20))


def fetch_endpoint(name, url, txids, stage, rate, post=http_post, now=None, sleep=time.sleep):
    """ask one endpoint for txids in chunks; write verified copies; return per-endpoint counts"""
    now = now or (lambda: datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
    st = {'asked': len(txids), 'ok': 0, 'unserved': 0, 'bad-hex': 0, 'txid-mismatch': 0, 'undecodable': 0, 'errors': 0, 'calls': 0}
    kept = {}
    for i in range(0, len(txids), CHUNK):
        c = txids[i:i + CHUNK]
        st['calls'] += 1
        try:
            r = post(url, {'jsonrpc': '2.0', 'id': '1', 'method': 'DERO.GetTransaction', 'params': {'txs_hashes': c}})
            res = r.get('result') or {}
            hexes = list(res.get('txs_as_hex') or [])
            infos = list(res.get('txs') or [])
        except Exception:   # noqa: BLE001  (an endpoint error is counted, never fatal)
            st['errors'] += 1
            hexes, infos = [], []
        hexes += [''] * (len(c) - len(hexes))
        infos += [{}] * (len(c) - len(infos))
        for t, h, inf in zip(c, hexes[:len(c)], infos[:len(c)]):
            v = check_copy(t, h)
            st[v] += 1
            if v == 'ok':
                rec = {'txid_requested': t, 'source': name, 'fetch_time': now(), 'class': 'EXT', 'as_hex': h,
                       'info_ext': {k: inf.get(k) for k in ('block_height', 'in_pool', 'valid_block', 'invalid_block', 'ignored')
                                    if isinstance(inf, dict)}}
                p = Path(stage) / 'txs' / f'{t}.{name}.json'
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(json.dumps(rec, sort_keys=True) + '\n')
                kept[t] = hashlib.sha256(bytes.fromhex(h)).hexdigest()
        sleep(1.0 / rate)
    return st, kept


def census(stages, txids, txid_fn=txid_of):
    """per TXID: the verified copies over every staging dir, grouped by holder; holders and distinct bodies"""
    by = {t: {} for t in txids}
    for s in stages:
        for p in sorted((Path(s) / 'txs').glob('*.json')):
            try:
                r = json.loads(p.read_text())
            except ValueError:
                continue
            t = r.get('txid_requested')
            if t in by and check_copy(t, r.get('as_hex'), txid_fn) == 'ok':
                by[t].setdefault(str(r.get('source')), set()).add(hashlib.sha256(bytes.fromhex(r['as_hex'])).hexdigest())
    rows, cnt = [], {'txids': len(txids), 'two_plus_holders': 0, 'equal': 0, 'different': 0, 'single_holder': 0, 'no_copy': 0}
    for t in txids:
        hs = by[t]
        bodies = set().union(*hs.values()) if hs else set()
        if not hs:
            st = 'no_copy'
        elif len(hs) < 2:
            st = 'single_holder'
        else:
            st = 'equal' if len(bodies) == 1 else 'different'
            cnt['two_plus_holders'] += 1
        cnt[st] += 1
        rows.append({'txid': t[:8], 'holders': sorted(hs), 'distinct_bodies': len(bodies), 'status': st})
    return {'counts': cnt, 'rows': rows}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest='cmd', required=True)
    p = sp.add_parser('fetch'); p.add_argument('--priv', required=True); p.add_argument('--stage', required=True)
    p.add_argument('--dataset', default='forensics/r28d'); p.add_argument('--sources', default='')
    p.add_argument('--rate', type=float, default=1.0); p.add_argument('--out', required=True)
    p = sp.add_parser('census'); p.add_argument('--stage', action='append', required=True)
    p.add_argument('--dataset', default='forensics/r28d'); p.add_argument('--out', required=True)
    a = ap.parse_args(argv)
    txids = multi_block_txids(a.dataset)
    if a.cmd == 'fetch':
        if a.rate <= 0 or a.rate > 5:
            raise SystemExit('refused: --rate must be in (0, 5] requests/s (polite cap)')
        E = json.loads((Path(a.priv) / 'endpoints.json').read_text())
        names = [n for n in (a.sources.split(',') if a.sources else sorted(E))]
        out = {'kind': 'r29_b97_fetch', 'txids': len(txids), 'rate_per_s': a.rate, 'chunk': CHUNK, 'endpoints': {}}
        for n in names:
            st, _ = fetch_endpoint(n, E[n]['url'], txids, a.stage, a.rate)
            out['endpoints'][n] = st
            print(n, st, file=sys.stderr)
        Path(a.out).write_text(json.dumps(out, indent=1, sort_keys=True) + '\n')
        return 0
    res = census(a.stage, txids)
    res.update({'kind': 'r29_b97_census', 'dataset': a.dataset, 'stages': len(a.stage)})
    Path(a.out).write_text(json.dumps(res, indent=1, sort_keys=True) + '\n')
    print(json.dumps(res['counts']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
