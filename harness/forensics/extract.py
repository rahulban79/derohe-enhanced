#!/usr/bin/env python3
"""R25 forensics-extract, step 1: re-check every RAW blob and decode it with the node's own code (rft §0.8.3, §0.8.8).

  python3 -I harness/forensics/extract.py --dataset forensics/r25 --store ~/derohe-persist/forensics_raw \
      --decoder BIN [--archive-copy DIR]

Input is raw/ only (headerchain rows, provenance, tier A blobs in raw/blobs, tier B blobs in STORE/blobs), plus, for the
state part, a COPY of our own replaywall archive (DIR holds replaywall_topo_7453290_7467921.bin, replaywall_bltx_store/,
replaywall_balances/; an APFS clone made by cp -c, never the datadir itself). Writes, deterministically (sorted, gzip
mtime 0, no paths, no times):
  derived/extract/blocks.jsonl.gz     node decode (tools/forensics block2) of every RAW block, by height
  derived/extract/txs.jsonl.gz        node decode (tx2) of every RAW tx body, by txid (includes the TXID core bytes)
  derived/extract/integrity.json      blob re-check counts: SHA-256 == content address, SHA3-256 == block id
  derived/archive_state/roots.jsonl.gz      per committed archive topo: block id, state versions, balance-tree root
  derived/archive_state/proof_checks.jsonl  per proof-carrying RAW tx: the current verifier WITHOUT the HF3 cache,
                                            against the archive state of its reference block, or why not decidable
  derived/archive_state/source.json         SHA-256 of the archive inputs, counts, and the class of these values
Any integrity failure exits 2 before anything is written (a hash mismatch never yields a derived row).
"""
import argparse, gzip, hashlib, io, json, os, struct, subprocess, sys, tempfile
from pathlib import Path

ARCH_TOPO_FIRST = 7453290  # replaywall_topo_7453290_7467921.bin: topo.map records from this topo (disc:124)
ARCH_NAME = 'archive:replaywall-20260819 (APFS clone in the scratchpad; the datadir itself is never opened)'
FORBIDDEN_ROOTS = [Path.home() / 'dero-data']  # live and archived datadirs: never opened by this tool


class IntegrityError(Exception):
    pass


def gz_bytes(lines):
    buf = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=buf, mtime=0, compresslevel=9) as g:
        for l in lines:
            g.write((l + '\n').encode())
    return buf.getvalue()


def dump(o):
    return json.dumps(o, sort_keys=True, separators=(',', ':'))


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def read_gz_jsonl(p):
    with gzip.open(p, 'rt') as f:
        return [json.loads(l) for l in f if l.strip()]


def guard_copy(p):
    """Refuse a path inside a node datadir (graviton opens its store O_RDWR)."""
    rp = Path(os.path.realpath(p))
    for f in FORBIDDEN_ROOTS:
        fr = Path(os.path.realpath(f))
        if rp == fr or fr in rp.parents:
            raise IntegrityError(f'refused: {p} lies inside a node datadir; extract reads only copies')
    return rp


def blob_path(ds, store, h):
    a = ds / 'raw' / 'blobs' / h
    if a.exists():
        return a
    if store is not None:
        b = Path(store) / 'blobs' / h
        if b.exists():
            return b
    return None


def check_blobs(ds, store, rows, txs):
    """MF1/MF2 at blob level: content address and block id must re-hash; any miss or mismatch is fatal."""
    bad, n_blocks, n_tierA, n_store, n_tx = [], 0, 0, 0, 0
    for r in rows:
        p = blob_path(ds, store, r['sha256'])
        if p is None:
            bad.append(('missing_blob', r['blid']))
            continue
        b = p.read_bytes()
        if sha256(b) != r['sha256']:
            bad.append(('sha256', r['blid']))
        if hashlib.sha3_256(b).hexdigest() != r['blid'] or r.get('sha3_256', r['blid']) != r['blid']:
            bad.append(('sha3_256', r['blid']))
        n_blocks += 1
        if (ds / 'raw' / 'blobs' / r['sha256']).exists():
            n_tierA += 1
        else:
            n_store += 1
    for t in txs:
        p = ds / 'raw' / 'blobs' / t['sha256']
        if not p.exists():
            bad.append(('missing_tx_blob', t['id']))
            continue
        if sha256(p.read_bytes()) != t['sha256']:
            bad.append(('tx_sha256', t['id']))
        n_tx += 1
    if bad:
        raise IntegrityError(f'{len(bad)} blob integrity failures, first: {bad[:3]}')
    return {'blocks_rechecked': n_blocks, 'blocks_from_dataset_blobs': n_tierA, 'blocks_from_store': n_store,
            'tx_bodies_rechecked': n_tx, 'failures': 0,
            'checks': 'SHA-256(blob) == content address and == headerchain sha256; SHA3-256(blob) == block id'}


def run_helper(decoder, reqs, env=None):
    p = subprocess.run([decoder], input=''.join(json.dumps(r) + '\n' for r in reqs), capture_output=True, text=True,
                       env=env, check=True)
    out = [json.loads(l) for l in p.stdout.splitlines() if l.strip()]
    if len(out) != len(reqs):
        raise IntegrityError(f'decoder answered {len(out)} of {len(reqs)} requests')
    return out


def strip(o):
    o = dict(o)
    o.pop('path', None)
    return o


def archive_state(arch, decoder, raw_by_height, txs, tx_dec):
    arch = guard_copy(arch)
    topo_f, bltx, bal = arch / 'replaywall_topo_7453290_7467921.bin', arch / 'replaywall_bltx_store', arch / 'replaywall_balances'
    for p in (topo_f, bltx, bal):
        guard_copy(p)
        if not p.exists():
            raise IntegrityError(f'archive copy incomplete: {p.name} missing')
    tb = topo_f.read_bytes()
    if len(tb) % 48:
        raise IntegrityError('topo copy is not a whole number of 48-byte records (blockchain/storetopo.go:34)')
    recs = {}
    for i in range(len(tb) // 48):
        r = tb[48 * i:48 * i + 48]
        blid = r[:32].hex()
        sv, h = struct.unpack('<QQ', r[32:])  # storetopo.go:79-80
        if blid != '00' * 32:
            recs[ARCH_TOPO_FIRST + i] = (blid, sv, h)
    files = {}
    for p in bltx.rglob('*.block_*'):
        parts = p.name.split('_')  # storefs.go:203-207: <blid>.block_<x>_<ssversion>_<height>
        if len(parts) == 4:
            files.setdefault(parts[0].split('.')[0], []).append((int(parts[2]), int(parts[3])))
    raw_ids = {r['blid'] for r in raw_by_height.values()}
    above = [(h, k) for k, vs in files.items() for _, h in vs if h > max(ARCH_TOPO_FIRST + i for i in range(len(tb) // 48)
                                                                        if tb[48 * i:48 * i + 32] != bytes(32))]
    bf_vs_raw = {'block_files': sum(len(v) for v in files.values()),
                 'block_file_ids_in_raw_chain': sum(1 for k in files if k in raw_ids),
                 'files_above_last_committed_topo': len(above),
                 'of_those_in_raw_chain': sum(1 for _, k in above if k in raw_ids),
                 'first_height_above': min((h for h, _ in above), default='not applicable: none'),
                 'reading': ('block files the stalled replaywall node held above its last committed topo are not the '
                             'RAW-chain blocks at those heights when of_those_in_raw_chain is 0 (resolves disc:131 '
                             '"canonicality pending" for that store)')}
    versions = sorted({v[1] for v in recs.values()})
    env = dict(os.environ, FORENSICS_STORE_COPY_OK=str(bal))
    rr = run_helper(decoder, [{'kind': 'roots', 'balances': str(bal), 'versions': versions}], env)[0]
    if not rr.get('ok'):
        raise IntegrityError('roots: ' + rr.get('error', '?'))
    root_of = {r['version']: r for r in rr['rows']}
    rows = []
    for topo in sorted(recs):
        blid, sv, h = recs[topo]
        fv = sorted(files.get(blid, []))
        raw = raw_by_height.get(h)
        rv = root_of.get(sv, {})
        row = {'topo': topo, 'height': h, 'blid': blid, 'state_version_topo_record': sv,
               'state_version_block_file': max(v for v, _ in fv) if fv else 'missing: no block file for this id in the copy',
               'blid_equals_raw_headerchain': bool(raw and raw['blid'] == blid)}
        if rv.get('root'):
            row['root'] = rv['root']
        else:
            row['root'] = 'not reconstructable: ' + (rv.get('error') or 'state version not readable from the copy')
        rows.append(row)
    # proof checks: every RAW tx that carries a proof
    checks = []
    for t in sorted(txs, key=lambda x: x['id']):
        d = tx_dec[t['id']]
        row = {'txid': t['id'], 'tx_type': d['tx_type'], 'ref_height': d['ref_height'], 'ref_blid': d['ref_blid']}
        if d['tx_type'] not in ('NORMAL', 'SC', 'BURN', 'SC_TX', 'BURN_TX'):
            row.update(result='not_applicable', reason=f"{d['tx_type']}: no ring proof (transaction_verify.go:240-254)")
            checks.append(row)
            continue
        rec = recs.get(d['ref_height'])  # topo == height for every window row (raw/provenance.json summary)
        if rec is None or rec[0] != d['ref_blid']:
            why = ('not decidable: ring state unavailable: the reference block is outside the held state (archive '
                   f'committed topo {min(recs)}..{max(recs)}; live node state starts at prunedheight 7,498,540, '
                   'disc:108-112)') if rec is None else 'not decidable: archive record at the reference topo is a different block'
            row.update(result='not_decidable', reason=why)
            checks.append(row)
            continue
        out = run_helper(decoder, [{'kind': 'verify', 'path': str(t['_path']), 'balances': str(bal), 'version': rec[1]}],
                         env)[0]
        if not out.get('ok'):
            row.update(result='error', reason=out.get('error', '?'))
        else:
            v = out['verdict']
            row.update(result=v.split(':')[0], reason=v.split(':', 1)[1] if ':' in v else 'not applicable: every check passed',
                       state_version=rec[1], state_root=out.get('state_root'), checks=out['checks'],
                       payloads=out['payloads'], hf3_cache=out['hf3_cache_bypassed'])
        checks.append(row)
    src = {'archive': ARCH_NAME,
           'class': ('DERIVED by tools/forensics (node code: graviton + Load_Merkle_Hash logic, blockchain/store.go:297-327; '
                     'the current verifier without the HF3 cache, tools/forensics/extract.go) from our own archive store; '
                     'that store is NOT in the dataset, so replay re-derives these files only where the copy is present and '
                     'otherwise re-checks their SHA-256'),
           'semantics': ('roots are the replaywall run\'s own node-computed balance-tree roots (base tree from its fastsync '
                         'at topo 7,453,290, not end-state-checked; blocks commit to no checked root, disc:119-120)'),
           'inputs_sha256': {'topo_copy': sha256(tb),
                             'balances_version_root_bin': sha256((bal / 'version_root.bin').read_bytes()),
                             'balances_files': sorted(sha256(p.read_bytes()) for p in bal.rglob('*.dfs')),
                             'bltx_block_file_names': sha256(''.join(sorted(
                                 f'{k}:{v}' for k, vs in files.items() for v in vs)).encode())},
           'topo_records': len(tb) // 48, 'committed_records': len(recs),
           'committed_topo_range': [min(recs), max(recs)], 'versions': len(versions),
           'block_files_vs_raw_chain': bf_vs_raw,
           'roots_ok': sum(1 for r in rows if not r['root'].startswith('not ')),
           'roots_error': sum(1 for r in rows if r['root'].startswith('not '))}
    return rows, checks, src


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--dataset', required=True); ap.add_argument('--store'); ap.add_argument('--decoder', required=True)
    ap.add_argument('--archive-copy'); ap.add_argument('--out', help='write derived/ here instead of DATASET/derived')
    a = ap.parse_args(argv)
    ds = Path(a.dataset)
    out = Path(a.out) if a.out else ds / 'derived'
    rows = read_gz_jsonl(ds / 'raw' / 'headerchain.jsonl.gz')
    prov = json.loads((ds / 'raw' / 'provenance.json').read_text())
    txs = [t for t in prov['tx_objects'] if t.get('class') == 'RAW']
    integ = check_blobs(ds, a.store, rows, txs)
    with tempfile.TemporaryDirectory() as td:
        breq = [{'kind': 'block2', 'path': str(blob_path(ds, a.store, r['sha256']))} for r in rows]
        bdec = run_helper(a.decoder, breq)
        for r, d in zip(rows, bdec):
            if not d.get('ok') or d['id'] != r['blid']:
                raise IntegrityError(f"block2 decode failed or id differs for {r['blid']}: {d.get('error')}")
        for t in txs:
            t['_path'] = ds / 'raw' / 'blobs' / t['sha256']
        tdec = run_helper(a.decoder, [{'kind': 'tx2', 'path': str(t['_path'])} for t in txs])
        tx_dec = {}
        for t, d in zip(txs, tdec):
            if not d.get('ok') or d['txid'] != t['id']:
                raise IntegrityError(f"tx2 decode failed or TXID differs for {t['id']}: {d.get('error')}")
            tx_dec[t['id']] = strip(d)
    blocks = sorted((strip(d) for d in bdec), key=lambda d: (d['height'], d['id']))
    files = {
        'extract/blocks.jsonl.gz': gz_bytes(dump(d) for d in blocks),
        'extract/txs.jsonl.gz': gz_bytes(dump(tx_dec[k]) for k in sorted(tx_dec)),
        'extract/integrity.json': (json.dumps(integ, indent=1, sort_keys=True) + '\n').encode(),
    }
    if a.archive_copy:
        by_h = {r['height']: r for r in rows}
        aroots, achecks, asrc = archive_state(a.archive_copy, a.decoder, by_h, txs, tx_dec)
        files['archive_state/roots.jsonl.gz'] = gz_bytes(dump(r) for r in aroots)
        files['archive_state/proof_checks.jsonl'] = ''.join(dump(c) + '\n' for c in achecks).encode()
        files['archive_state/source.json'] = (json.dumps(asrc, indent=1, sort_keys=True) + '\n').encode()
    for rel, b in files.items():
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b)
        print(f'{rel} {len(b)} {sha256(b)}')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except IntegrityError as e:
        print('INTEGRITY FAIL:', e, file=sys.stderr)
        sys.exit(2)
