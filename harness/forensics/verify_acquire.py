#!/usr/bin/env python3
"""R25 forensics: promote staged EXT objects to RAW after checks (i)-(iii) (artifacts/dero-rft.md §0.8.4).

  python3 -I harness/forensics/verify_acquire.py --stage EXT_STAGING --decoder BIN --dataset forensics/r25 \
      --store ~/derohe-persist/forensics_raw [--archive-topo FILE --archive-topo-first N --archive-store DIR]

Reads the staging dir written by acquire.py (blocks/*/<topo>.json, txs/<txid>.json, anchor_live.json), decodes each
blob with the node's own decoder (tools/forensics, read-only), applies provenance.py and writes:
  raw/headerchain.jsonl.gz  one row per verified block (class RAW; topo is the SOURCE's mapping, labelled topo_ext)
  raw/anchors.json          our own anchors (live block at prunedheight; replaywall committed topo records)
  raw/provenance.json       summary + per-object entries for anchors, tier A blocks and txs
  raw/provenance_blocks.jsonl.gz  per-object provenance of every staged block (RAW or EXT, checks, source, time)
  raw/blobs/<sha256>        tier A blobs (blocks carrying an HF3 TXID +-2 heights, their txs, the anchor)
  raw/missing.json          window heights with no RAW row, with the reason
  audit/rejected.jsonl      every staged object that failed a check, with the check
and copies every RAW blob into STORE/blobs/<sha256> (tier B, outside git). gzip is written with mtime 0.
"""
import argparse, gzip, hashlib, io, json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import provenance as P  # noqa: E402

WINDOW = (7415466, 7497942)
ANCHOR_TOPO, ANCHOR_ID = 7498540, 'e18be51e716a746c6a98a32dbc2a0420745945ffb933d1b6582489a33c1e743e'  # disc:118


def gz_write(path, lines):
    buf = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=buf, mtime=0, compresslevel=9) as g:
        for l in lines:
            g.write((l + '\n').encode())
    Path(path).write_bytes(buf.getvalue())


def decode(decoder, items, tmpdir):
    """items: [(kind, key, bytes)] -> {key: decoded dict}. Blobs are written to tmpdir, never into the dataset."""
    req, keys = [], {}
    for kind, key, b in items:
        p = Path(tmpdir) / f'{kind}_{key}.bin'
        p.write_bytes(b)
        req.append(json.dumps({'kind': kind, 'path': str(p)}))
        keys[str(p)] = key
    out = subprocess.run(['nice', '-n', '15', decoder], input='\n'.join(req) + '\n', capture_output=True, text=True,
                         check=True).stdout
    res = {}
    for l in out.splitlines():
        d = json.loads(l)
        res[keys[d['path']]] = d
        d.pop('path', None)
    for p in keys:
        Path(p).unlink(missing_ok=True)
    return res


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--stage', required=True); ap.add_argument('--decoder', required=True)
    ap.add_argument('--dataset', required=True); ap.add_argument('--store', required=True)
    ap.add_argument('--archive-topo'); ap.add_argument('--archive-topo-first', type=int)
    ap.add_argument('--archive-store')
    ap.add_argument('--hf3-table', required=True)
    ap.add_argument('--anchor-id', default=ANCHOR_ID); ap.add_argument('--anchor-topo', type=int, default=ANCHOR_TOPO)  # KAT only
    ap.add_argument('--quiet', action='store_true')
    a = ap.parse_args(argv)
    st, ds, store = Path(a.stage), Path(a.dataset), Path(a.store)
    (ds / 'raw' / 'blobs').mkdir(parents=True, exist_ok=True); (ds / 'audit').mkdir(parents=True, exist_ok=True)
    (store / 'blobs').mkdir(parents=True, exist_ok=True)
    table = {}
    for l in open(a.hf3_table):
        t, tips, h, par = l.split()
        table[t] = {'bl_tips': tips, 'height': int(h), 'tx_parity': par == 'true'}
    tmp = tempfile.mkdtemp(prefix='fx_dec_')

    # ---- anchor (our own: live node at its prunedheight; id cross-checked with the live topo.map record, disc:118)
    an = json.loads((st / 'anchor_live.json').read_text())
    ablob = bytes.fromhex(an['blob'])
    adec = decode(a.decoder, [('block', 'anchor', ablob)], tmp)['anchor']
    ok_i, why = P.check_i(ablob, an['claimed_hash'], adec.get('id'))
    if not ok_i or an['claimed_hash'] != a.anchor_id or an['topo'] != a.anchor_topo:
        sys.exit(f'anchor check failed: {why} claimed {an["claimed_hash"]} topo {an["topo"]}')
    anchor_id = a.anchor_id
    anchors = [{'kind': 'block', 'id': anchor_id, 'topo': a.anchor_topo, 'height': adec['height'], 'source': 'live-rpc',
                'fetch_time': an['fetch_time'], 'sha256': P.sha256_hex(ablob), 'tips': adec['tips'],
                'cross_check': 'live topo.map record 7498540 (discovery line 118) == GetBlock id == sha3-256(blob) == decoder id'}]

    # ---- staged blocks
    staged = sorted((st / 'blocks').glob('*/*.json'), key=lambda p: int(p.stem))
    recs, items = {}, []
    for p in staged:
        r = json.loads(p.read_text())
        b = bytes.fromhex(r['blob'])
        recs[r['topo_requested']] = (r, b)
        items.append(('block', str(r['topo_requested']), b))
    dec = {}
    for i in range(0, len(items), 5000):
        dec.update(decode(a.decoder, items[i:i + 5000], tmp))
    tips_of, passed_i, by_id, rejected = {anchor_id: adec['tips']}, set(), {}, []
    for topo, (r, b) in recs.items():
        d = dec[str(topo)]
        ok, why = P.check_i(b, r['claimed_hash'], d.get('id') if d.get('ok') else 'decode-failed')
        if ok and d.get('ok'):
            passed_i.add(d['id']); tips_of[d['id']] = d['tips']; by_id[d['id']] = (topo, r, b, d)
        else:
            rejected.append({'kind': 'block', 'topo_ext': topo, 'claimed_id': r['claimed_hash'], 'source': r['source'],
                             'fetch_time': r['fetch_time'], 'failed': 'i', 'reason': why if not ok else d.get('error')})
    reached = P.tips_walk(tips_of, {anchor_id}, passed_i)
    for bid in sorted(passed_i - reached):
        topo, r, b, d = by_id[bid]
        rejected.append({'kind': 'block', 'topo_ext': topo, 'claimed_id': bid, 'source': r['source'],
                         'fetch_time': r['fetch_time'], 'failed': 'ii', 'reason': 'not reached from our anchor by tips'})

    # ---- replaywall archive corroboration (our own store, copy only)
    arch = {}
    if a.archive_topo:
        raw = Path(a.archive_topo).read_bytes()
        for k in range(len(raw) // 48):
            rec = raw[k * 48:(k + 1) * 48]
            blid = rec[:32].hex()
            if blid != '00' * 32:
                arch[a.archive_topo_first + k] = {'blid': blid, 'sv': int.from_bytes(rec[32:40], 'little'),
                                                  'height': int.from_bytes(rec[40:48], 'little')}
    arch_files = {}
    if a.archive_store:
        for p in Path(a.archive_store).rglob('*.block_*'):
            arch_files[p.name.split('.')[0]] = p
    corr = {'archive_topo_records': len(arch), 'match_id_at_topo': 0, 'mismatch_id_at_topo': [], 'archive_record_not_fetched': 0,
            'archive_blob_sha256_equal': 0, 'archive_blob_sha256_differs': []}
    id_at_topo = {by_id[i][0]: i for i in reached}
    for topo, rec in arch.items():
        got = id_at_topo.get(topo)
        if got is None:
            corr['archive_record_not_fetched'] += 1
        elif got == rec['blid']:
            corr['match_id_at_topo'] += 1
        else:
            corr['mismatch_id_at_topo'].append({'topo': topo, 'archive': rec['blid'], 'fetched': got})
    for bid in sorted(reached):
        if bid in arch_files:
            if hashlib.sha256(arch_files[bid].read_bytes()).hexdigest() == P.sha256_hex(by_id[bid][2]):
                corr['archive_blob_sha256_equal'] += 1
            else:
                corr['archive_blob_sha256_differs'].append(bid)
    if arch:
        anchors.append({'kind': 'archive_topo_records', 'source': 'archive:replaywall-20260819 (copy)',
                        'topo_range': [min(arch), max(arch)], 'count': len(arch),
                        'first': arch[min(arch)]['blid'], 'last': arch[max(arch)]['blid'],
                        'used_as': 'corroboration of the tips chain (every committed record compared by id at its topo)'})

    # ---- txs (the 75 + tier A bodies)
    verified_lists = {i: by_id[i][3]['tx_hashes'] for i in reached}
    verified_lists[anchor_id] = adec['tx_hashes']
    txrecs, titems = {}, []
    for p in sorted((st / 'txs').glob('*.json')):
        r = json.loads(p.read_text())
        txrecs[r['txid_requested']] = r
        if r['as_hex']:
            titems.append(('tx', r['txid_requested'], bytes.fromhex(r['as_hex'])))
    tdec = decode(a.decoder, titems, tmp) if titems else {}
    # archive tx bodies (our own store copy) for cross-check
    arch_tx = {}
    if a.archive_store:
        for p in Path(a.archive_store).rglob('*.tx'):
            arch_tx[p.stem] = p
    tx_entries = []
    for t, r in sorted(txrecs.items()):
        e = {'kind': 'tx', 'id': t, 'source': r['source'], 'fetch_time': r['fetch_time'], 'hf3': t in table}
        if not r['as_hex']:
            e.update(**{'class': P.EXT, 'checks': {}, 'missing': 'source returned an empty body'})
            rejected.append({'kind': 'tx', 'id': t, 'source': r['source'], 'failed': 'iii', 'reason': 'empty body'})
            tx_entries.append(e); continue
        b = bytes.fromhex(r['as_hex'])
        d = tdec.get(t, {})
        checks, why = P.check_iii(t, d.get('txid') if d.get('ok') else None, verified_lists)
        e['checks'] = {k: v for k, v in checks.items() if k != 'carriers'}
        e['carriers'] = checks.get('carriers', [])
        e['sha256'] = P.sha256_hex(b); e['size'] = len(b)
        e['class'] = P.classify('tx', e['checks'])
        e['reserialize_equal'] = d.get('reserialize_equal')
        if t in arch_tx:
            e['archive_copy_sha256_equal'] = hashlib.sha256(arch_tx[t].read_bytes()).hexdigest() == e['sha256']
        if e['class'] != P.RAW:
            rejected.append({'kind': 'tx', 'id': t, 'source': r['source'], 'failed': 'iii', 'reason': why})
        else:
            (store / 'blobs' / e['sha256']).write_bytes(b)
        e['decoded'] = {k: d.get(k) for k in ('tx_type', 'ref_height', 'ref_blid', 'fees', 'payloads', 'value', 'has_scdata')} if d.get('ok') else {'error': d.get('error')}
        tx_entries.append(e)

    # ---- tier A: blocks carrying an HF3 txid, +-2 heights
    carriers = {}
    for bid in sorted(reached, key=lambda b: (by_id[b][3]['height'], b)):  # deterministic carrier order
        for t in by_id[bid][3]['tx_hashes']:
            if t in table:
                carriers.setdefault(t, []).append(bid)
    carrier_heights = sorted({by_id[b][3]['height'] for l in carriers.values() for b in l})
    tierA_heights = sorted({h + k for h in carrier_heights for k in range(-2, 3)})
    tierA = sorted(b for b in reached if by_id[b][3]['height'] in set(tierA_heights))
    tierA_txids = sorted({t for b in tierA for t in by_id[b][3]['tx_hashes']})
    for e in tx_entries:
        if e['class'] == P.RAW and (e['hf3'] or e['id'] in tierA_txids):
            shutil.copyfile(store / 'blobs' / e['sha256'], ds / 'raw' / 'blobs' / e['sha256'])
    (ds / 'raw' / 'blobs' / anchors[0]['sha256']).write_bytes(ablob)
    (store / 'blobs' / anchors[0]['sha256']).write_bytes(ablob)

    # ---- rows, per-object provenance, blob store
    rows, prov_lines = [], []
    for topo in sorted(recs):
        r, b = recs[topo]
        d = dec[str(topo)]
        bid = d.get('id')
        ch = {'i': bid in passed_i, 'ii': bid in reached}
        cls = P.classify('block', ch)
        sha = P.sha256_hex(b)
        prov_lines.append(json.dumps({'kind': 'block', 'id': bid or r['claimed_hash'], 'topo_ext': topo, 'class': cls,
                                      'checks': ch, 'sha256': sha, 'source': r['source'], 'fetch_time': r['fetch_time']},
                                     sort_keys=True))
        if cls != P.RAW:
            continue
        (store / 'blobs' / sha).write_bytes(b)
        tier = 'A' if bid in set(tierA) else 'B'
        if tier == 'A':
            (ds / 'raw' / 'blobs' / sha).write_bytes(b)
        rows.append({'topo_ext': topo, 'height': d['height'], 'blid': bid, 'tips': d['tips'], 'timestamp_ms': d['timestamp_ms'],
                     'major_version': d['major_version'], 'minor_version': d['minor_version'], 'miniblocks': d['miniblocks'],
                     'tx_count': len(d['tx_hashes']), 'tx_hashes': d['tx_hashes'], 'miner_tx_type': d['miner_tx_type'],
                     'proof_field_nonzero': d['proof_field_nonzero'], 'reserialize_equal': d['reserialize_equal'],
                     'sha3_256': bid, 'sha256': sha, 'size': len(b), 'class': cls, 'checks': ch, 'tier': tier,
                     'source': r['source'], 'fetch_time': r['fetch_time'],
                     'reward_ext': r['header_ext'].get('reward'), 'ext_note': 'reward_ext/topo_ext are the source\'s claims (EXT)',
                     'archive_corroborated': (arch.get(topo, {}).get('blid') == bid) if topo in arch else None})
    gz_write(ds / 'raw' / 'headerchain.jsonl.gz', [json.dumps(x, sort_keys=True) for x in rows])
    gz_write(ds / 'raw' / 'provenance_blocks.jsonl.gz', prov_lines)
    with open(ds / 'audit' / 'rejected.jsonl', 'w') as f:
        for x in rejected:
            f.write(json.dumps(x, sort_keys=True) + '\n')

    heights = {}
    for x in rows:
        heights.setdefault(x['height'], []).append(x['blid'])
    missing = [h for h in range(WINDOW[0], WINDOW[1] + 1) if h not in heights]
    rej_by_h = {}
    for x in rejected:
        if x['kind'] == 'block':
            rej_by_h.setdefault(x['topo_ext'], []).append(x['failed'])
    json.dump({'window': list(WINDOW), 'missing_count': len(missing),
               'reason_lookup': 'rejections are keyed by the source topo; topo_ext == height is assumed for the lookup (see summary rows_topo_ext_ne_height)',
               'missing': [{'height': h, 'reason': ('fetched but failed check ' + ','.join(rej_by_h[h])) if h in rej_by_h
                            else ('not fetched' if h not in recs else 'no verified block decodes to this height')}
                           for h in missing]},
              open(ds / 'raw' / 'missing.json', 'w'), indent=1, sort_keys=True)
    json.dump(anchors, open(ds / 'raw' / 'anchors.json', 'w'), indent=1, sort_keys=True)

    multi = {h: l for h, l in heights.items() if len(l) > 1}
    topo_ne_h = sum(1 for x in rows if x['topo_ext'] != x['height'])
    hf3_rows = []
    for t, info in sorted(table.items(), key=lambda kv: kv[1]['height']):
        cb = carriers.get(t, [])
        e = next((x for x in tx_entries if x['id'] == t), None)
        hf3_rows.append({'txid': t, 'table_height': info['height'], 'table_bl_tips': info['bl_tips'], 'tx_parity': info['tx_parity'],
                         'carriers': [{'blid': b, 'height': by_id[b][3]['height'], 'tips': by_id[b][3]['tips']} for b in cb],
                         'carrier_height_eq_table_height': [by_id[b][3]['height'] == info['height'] for b in cb],
                         'table_bl_tips_in_carrier_tips': [info['bl_tips'] in by_id[b][3]['tips'] for b in cb],
                         'body_class': e['class'] if e else 'missing', 'body_sha256': e.get('sha256') if e else None,
                         'body_ref_height': (e or {}).get('decoded', {}).get('ref_height'),
                         'body_ref_blid_eq_table_bl_tips': ((e or {}).get('decoded', {}).get('ref_blid') == info['bl_tips']) if e else None})
    in_window = sum(1 for x in rows if WINDOW[0] <= x['height'] <= WINDOW[1])
    summary = {
        'stage': 'acquire', 'window': list(WINDOW),
        'blocks_staged': len(recs), 'blocks_raw': len(rows), 'blocks_rejected': sum(1 for x in rejected if x['kind'] == 'block'),
        'window_heights': WINDOW[1] - WINDOW[0] + 1, 'window_heights_verified': len({h for h in heights if WINDOW[0] <= h <= WINDOW[1]}),
        'window_rows': in_window, 'window_heights_missing': len(missing),
        'heights_with_more_than_one_block': len(multi), 'rows_topo_ext_ne_height': topo_ne_h,
        'proof_field_nonzero_rows': sum(1 for x in rows if x['proof_field_nonzero']),
        'reserialize_not_equal_rows': sum(1 for x in rows if not x['reserialize_equal']),
        'tx_bearing_rows_in_window': sum(1 for x in rows if WINDOW[0] <= x['height'] <= WINDOW[1] and x['tx_count']),
        'txs_in_window_blocks': sum(x['tx_count'] for x in rows if WINDOW[0] <= x['height'] <= WINDOW[1]),
        'tierA_heights': len(tierA_heights), 'tierA_blocks': len(tierA), 'tierA_txids': len(tierA_txids),
        'tierA_tx_bodies_raw': sum(1 for e in tx_entries if e['id'] in tierA_txids and e['class'] == P.RAW),
        'hf3_bodies_raw': sum(1 for e in tx_entries if e['hf3'] and e['class'] == P.RAW), 'hf3_total': len(table),
        'hf3_with_verified_carrier': sum(1 for t in table if carriers.get(t)),
        'archive_corroboration': {k: (v if not isinstance(v, list) else len(v)) for k, v in corr.items()},
        'sources_used_blocks': sorted({x['source'] for x in rows}),
    }
    prov = {'summary': summary, 'anchors': anchors, 'hf3': hf3_rows,
            'tx_objects': tx_entries,
            'tierA_blocks': [{'kind': 'block', 'id': b, 'height': by_id[b][3]['height'], 'topo_ext': by_id[b][0],
                              'class': P.RAW, 'checks': {'i': True, 'ii': True}, 'sha256': P.sha256_hex(by_id[b][2]),
                              'source': by_id[b][1]['source'], 'fetch_time': by_id[b][1]['fetch_time']} for b in tierA],
            'tierB_per_object': 'raw/provenance_blocks.jsonl.gz (every staged block: class, checks, sha256, source, fetch_time)',
            'rules': 'harness/forensics/provenance.py: RAW only with (i)+(ii) for blocks and (iii) for txs; EXT otherwise',
            'archive_corroboration_detail': corr}
    probs = P.provenance_problems(anchors[:1] and [dict(anchors[0], **{'class': P.RAW, 'checks': {'i': True, 'ii': True}})] +
                                  prov['tierA_blocks'] + tx_entries)
    if probs:
        sys.exit('provenance invariant violated: ' + '; '.join(probs[:5]))
    json.dump(prov, open(ds / 'raw' / 'provenance.json', 'w'), indent=1, sort_keys=True)
    shutil.rmtree(tmp, ignore_errors=True)
    if not a.quiet:
        print(json.dumps(summary, indent=1))
    (Path(a.stage) / 'tierA_txids.txt').write_text(''.join(t + '\n' for t in tierA_txids))  # fetch list, outside the dataset


if __name__ == '__main__':
    main()
