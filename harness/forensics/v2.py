#!/usr/bin/env python3
"""R26 forensics-data: dataset v2 `forensics/r26/` (rft §0.8.3, §0.8.7 R26 rung, §7 B95/B96/B76, audit A10c).

v1 (`forensics/r25/`) is never rewritten: v2 reads v1's RAW headerchain and RAW tx bodies by path and SHA-256 (manifest
`inputs`) and adds, with `supersedes: []`:

  raw/tx_bodies.jsonl.gz     every tx body of the window 7,415,466..7,497,942 and of the gap to our anchor
                             (..7,498,540): RAW after check (iii) (node decoder TXID == Python Keccak-256 TXID == the id
                             in a RAW block's tx list), from v1 raw/ first, then the replaywall archive copy, then ONE
                             fetched source; blobs content-addressed in the tier B store (outside git)
  raw/missing_txs.json       bodies still missing, each with its evidence
  raw/wall1_blocks.jsonl.gz  blocks 7,412,665..7,415,463 (the wall-1 window and its tips link to our RAW 7,415,464),
                             RAW after checks (i)-(ii), from ONE fetched source
  raw/a2_attempt.json        the (a2) TreeSection attempt: per probe, pseudonym and outcome only (no address)
  raw/archive_seed.json      the replay base: our replaywall archive copy, APFS-cloned, top 7,467,515
  raw/replay_runs/<run>/     node replay outputs (tools/forensics/a2 replay: the node's own Add_Complete_Block):
                             roots.jsonl.gz + summary.json; class DERIVED by the pinned node build, re-hashed here
  derived/txs.jsonl.gz       per tx: public fields (type, fee, burns, ring sizes, roothash, SC data present)
  derived/blocks_fees.jsonl.gz  per tx-carrying block 7,415,466..7,498,540: fees / burns (int or `pending: <why>`)
  derived/fees.json          v1's 1,575 pending-fee blocks -> settled or explained
  derived/state_roots.json   the end-state check (our replay's root at 7,498,540 vs our own treehash), roothash
                             witnesses, A10c, coverage of pre/post roots over the window
  derived/roots_window.jsonl.gz  per replayed topo: pre/post root (DERIVED)
  derived/walls.json         the windows around the replay walls 7,412,674 / 7,467,516 / 7,497,836
  derived/a2.json            (a2) verdict with its evidence
  derived/summary.json       counts
Every per-tx and per-block record carries `class` (the defect class slot of rft §0.8.9, `pending` until the
forensics-classes stage fills it) and `evidence_class` (RAW / DERIVED / EXT, §0.8.2).

  python3 -I harness/forensics/v2.py bodies   --dataset forensics/r26 --stage DIR --archive-copy DIR --store DIR
      (--store must be v2's own store, never v1's ~/derohe-persist/forensics_raw: v1 replay hashes its listing)
  python3 -I harness/forensics/v2.py runs     --dataset forensics/r26 --run NAME --roots F --summary F
  python3 -I harness/forensics/v2.py plan     --dataset forensics/r26 --store DIR --from T --to T --out F
  python3 -I harness/forensics/v2.py derive   --dataset forensics/r26 --store DIR --out DIR
  python3 -I harness/forensics/v2.py manifest --dataset forensics/r26 --store DIR
  python3 -I harness/forensics/v2.py replay   forensics/r26 [--store DIR] [--record harness/runtime/forensics_replay.json]
Read-only towards every node: the decoder is tools/forensics (blobs only); nothing here talks to a network.
"""
import argparse, gzip, hashlib, io, json, os, platform, shutil, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import keccak  # noqa: E402
import provenance as P  # noqa: E402

WINDOW = (7415466, 7497942)
ANCHOR_TOPO = 7498540
ANCHOR_ID = 'e18be51e716a746c6a98a32dbc2a0420745945ffb933d1b6582489a33c1e743e'   # forensics/r25/raw/anchors.json
OUR_TREEHASH = 'ca11cc2106c86d9db9a92dcd8627eae52ab09bdc27f10abd5a0eebab4d9019f7'  # our node at 7,498,540 (disc:112)
WALLS = {'wall1': 7412675, 'wall2': 7467516, 'wall3': 7497836}   # topo of the tx that stopped the replay (disc:139-140)
WALL_RADIUS = 5
V1 = 'forensics/r25'
V1_INPUTS = ['forensics/r25/raw/headerchain.jsonl.gz', 'forensics/r25/raw/anchors.json', 'forensics/r25/raw/provenance.json',
             'forensics/r25/derived/window.jsonl.gz', 'forensics/r25/derived/emission.json',
             'forensics/r25/derived/archive_state/roots.jsonl.gz', 'forensics/r25/raw/a2_feasibility.json']
TOOLS = ['harness/forensics/v2.py', 'harness/forensics/keccak.py', 'harness/forensics/provenance.py',
         'tools/forensics/main.go', 'tools/forensics/extract.go', 'tools/forensics/a2/main.go', 'tools/forensics/a2/net.go',
         'tools/forensics/a2/seed.go', 'tools/forensics/a2/replay.go', 'tools/forensics/a2/archive.go',
         'tools/forensics/a2/guard.go', 'harness/forensics/classes.py']
HF3 = 'blockchain/hardfork_fixes.go'
FORBIDDEN = [Path.home() / 'dero-data']
V1_STORE = Path.home() / 'derohe-persist' / 'forensics_raw'
PENDING_SC = ('pending: SC payouts are produced by SC execution (blockchain/transaction_execute.go), which a decoder does '
              'not run and the node replay does not export')


def sha(b):
    return hashlib.sha256(b).hexdigest()


def fsha(p):
    return sha(Path(p).read_bytes())


def gz_bytes(lines):
    buf = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=buf, mtime=0, compresslevel=9) as g:
        for l in lines:
            g.write((l + '\n').encode())
    return buf.getvalue()


def jl(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'))


def dump(obj):
    return (json.dumps(obj, indent=1, sort_keys=True) + '\n').encode()


def read_gz(p):
    return [json.loads(l) for l in gzip.open(p)] if Path(p).exists() else []


def guard(p):
    rp = Path(p).resolve()
    for f in FORBIDDEN:
        if rp == f.resolve() or f.resolve() in rp.parents:
            raise SystemExit(f'refused: {p} lies under a node datadir (rft §5)')
    return rp


def build_decoder(work):
    out = Path(work) / 'fxdec'
    env = dict(os.environ, GOFLAGS='-mod=vendor')
    subprocess.run(['nice', '-n', '15', 'go', 'build', '-trimpath', '-buildvcs=false', '-o', str(out), './tools/forensics'],
                   cwd=str(ROOT), env=env, check=True, capture_output=True)
    return out


def decode(decoder, items, work):
    """items [(key, kind, bytes)] -> {key: decoded}; blobs go to a scratch dir only."""
    req, keys = [], {}
    tmp = Path(tempfile.mkdtemp(prefix='v2dec_', dir=work))
    for i, (key, kind, b) in enumerate(items):
        p = tmp / f'{i}.bin'
        p.write_bytes(b)
        req.append(json.dumps({'kind': kind, 'path': str(p)}))
        keys[str(p)] = key
    res = {}
    if req:
        out = subprocess.run(['nice', '-n', '15', str(decoder)], input='\n'.join(req) + '\n', capture_output=True,
                             text=True, check=True).stdout
        for l in out.splitlines():
            d = json.loads(l)
            res[keys[d.pop('path')]] = d
    shutil.rmtree(tmp, ignore_errors=True)
    return res


# ------------------------------------------------------------------------------------------------ RAW inputs
def headerchain(root=ROOT, ds=None):
    """our RAW blocks (v1 checks i-ii) by height, plus the anchor, plus (ds given) v2's RAW wall-1 link blocks"""
    rows = {}
    if ds is not None:
        for r in read_gz(Path(ds) / 'raw/wall1_blocks.jsonl.gz'):
            if r.get('evidence_class') == 'RAW' and r['checks'].get('i') is True and r['checks'].get('ii') is True:
                rows[r['height']] = r
    for r in read_gz(Path(root) / V1 / 'raw/headerchain.jsonl.gz'):
        if r.get('class') == 'RAW' and (r.get('checks') or {}).get('i') is True and r['checks'].get('ii') is True:
            rows[r['height']] = r
    an = [a for a in json.loads((Path(root) / V1 / 'raw/anchors.json').read_text()) if a.get('kind') == 'block'][0]
    rows[an['topo']] = {'height': an['topo'], 'blid': an['id'], 'sha256': an['sha256'], 'tx_hashes': [], 'anchor': True,
                        'tips': an.get('tips', [])}
    return rows


def needed_txs(hc, lo=WINDOW[0], hi=ANCHOR_TOPO):
    """{txid: (height, blid)} for every tx of a RAW block lo..hi (the anchor's own tx list is read from its blob)"""
    need = {}
    for h in range(lo, hi + 1):
        r = hc.get(h)
        if not r:
            continue
        for t in r.get('tx_hashes') or []:
            need.setdefault(t, (h, r['blid']))
    return need


def store_blob(store, b):
    d = Path(store) / 'blobs'
    d.mkdir(parents=True, exist_ok=True)
    h = sha(b)
    p = d / h
    if p.exists():
        if fsha(p) != h:
            raise SystemExit(f'store blob {h[:16]} is corrupt')
    else:
        tmp = p.with_suffix('.tmp')
        tmp.write_bytes(b)
        tmp.rename(p)
    return h


def read_store(stores, h):
    for s in stores:
        p = Path(s) / 'blobs' / h
        if p.exists():
            b = p.read_bytes()
            if sha(b) == h:
                return b
    return None


def check_tx(txid, body, dec, verified_lists):
    """check (iii) with two implementations: node TXID, Python Keccak-256 over the node's core bytes, and the
    carrier list. -> (checks, reason)"""
    checks, why = P.check_iii(txid, dec.get('txid') if dec.get('ok') else None, verified_lists)
    core = bytes.fromhex(dec.get('core_hex') or '') if dec.get('ok') else b''
    checks['py_keccak_eq'] = bool(core) and keccak.keccak256(core).hex() == txid
    checks['reserialize_equal'] = bool(dec.get('reserialize_equal'))
    if checks.get('iii_txid') and checks.get('iii_in_block') and not checks['py_keccak_eq']:
        why = 'iii: Python Keccak-256 of the core statement differs from the TXID'
    return checks, why


def cmd_bodies(a):
    ds = Path(a.dataset)
    guard(a.archive_copy), guard(a.stage), guard(a.store)
    if Path(a.store).resolve() == V1_STORE.resolve():
        raise SystemExit("refused: --store is v1's tier B store; v1 replay hashes its listing (use v2's own store)")
    work = Path(tempfile.mkdtemp(prefix='v2b_'))
    dec_bin = build_decoder(work)
    hc = headerchain()
    hc = headerchain(ds=ds)
    need = needed_txs(hc)
    need.update(needed_txs(hc, WALLS['wall1'] - WALL_RADIUS, WALLS['wall1'] + WALL_RADIUS))
    verified = {}
    for t, (h, blid) in need.items():
        verified.setdefault(blid, []).append(t)
    # candidate sources, in order of trust: v1 RAW, our own archive copy, the fetched source (EXT until checked)
    v1 = {x['id']: x for x in json.loads((ROOT / V1 / 'raw/provenance.json').read_text())['tx_objects'] if x.get('class') == 'RAW'}
    arch = {p.name.split('.')[0]: p for p in Path(a.archive_copy, 'replaywall_bltx_store').rglob('*.tx')}
    staged = {}
    sd = Path(a.stage) / 'txs'
    if sd.is_dir():
        for p in sorted(sd.glob('*.json')):
            r = json.loads(p.read_text())
            staged[r['txid_requested']] = r
    cands = []
    for t in sorted(need):
        if t in v1:
            b = (ROOT / V1 / 'raw/blobs' / v1[t]['sha256']).read_bytes()
            cands.append((t, 'raw:forensics/r25', b, None))
        if t in arch:
            cands.append((t, 'archive:replaywall-20260819 (copy)', arch[t].read_bytes(), None))
        if t in staged and staged[t].get('as_hex'):
            cands.append((t, 'fetched:' + staged[t]['source'], bytes.fromhex(staged[t]['as_hex']), staged[t].get('fetch_time')))
    decs = decode(dec_bin, [(i, 'tx2', c[2]) for i, c in enumerate(cands)], work)
    rows, rejected, done = {}, [], set()
    for i, (t, src, b, ft) in enumerate(cands):
        d = decs.get(i, {})
        checks, why = check_tx(t, b, d, verified)
        ok = all(checks.get(k) is True for k in ('iii_txid', 'iii_in_block', 'py_keccak_eq'))
        if not ok:
            rejected.append({'kind': 'tx', 'id': t, 'source': src, 'failed': why, 'sha256': sha(b)})
            continue
        if t in done:
            # a second RAW body under the same TXID from another source: equal bytes or a duplicate-body finding
            if rows[t]['sha256'] != sha(b):
                rows[t].setdefault('other_bodies', []).append({'source': src, 'sha256': sha(b)})
            else:
                rows[t].setdefault('corroborated_by', []).append(src)
            continue
        h = store_blob(a.store, b)
        height, blid = need[t]
        rows[t] = {'txid': t, 'sha256': h, 'size': len(b), 'source': src, 'checks': checks, 'carrier_height': height,
                   'carrier_blid': blid, 'evidence_class': 'RAW', 'class': 'pending'}
        if ft:
            rows[t]['fetch_time'] = ft
        done.add(t)
    missing = [{'txid': t, 'carrier_height': need[t][0], 'class': 'pending',
                'reason': 'no source returned a body that passes check (iii)' if any(c[0] == t for c in cands) else
                'not held in v1 raw/ or the archive copy, and not fetched'} for t in sorted(need) if t not in rows]
    (ds / 'raw').mkdir(parents=True, exist_ok=True)
    (ds / 'audit').mkdir(parents=True, exist_ok=True)
    (ds / 'raw/tx_bodies.jsonl.gz').write_bytes(gz_bytes(jl(rows[t]) for t in sorted(rows)))
    (ds / 'raw/missing_txs.json').write_bytes(dump({'missing': missing, 'missing_count': len(missing), 'needed': len(need),
                                                     'scope': [WINDOW[0], ANCHOR_TOPO]}))
    (ds / 'audit/rejected.jsonl').write_text(''.join(jl(r) + '\n' for r in sorted(rejected, key=lambda r: (r['id'], r['source']))))
    shutil.rmtree(work, ignore_errors=True)
    by = {}
    for r in rows.values():
        by[r['source']] = by.get(r['source'], 0) + 1
    print(json.dumps({'needed': len(need), 'raw': len(rows), 'missing': len(missing), 'rejected': len(rejected),
                      'by_source': by}, sort_keys=True))


WALL1_LINK = (7412665, 7415463)   # blocks fetched to link the wall-1 window to our RAW block 7,415,464 by tips


def cmd_wall1(a):
    """staged EXT blocks (acquire.py fetch-blocks) WALL1_LINK -> raw/wall1_blocks.jsonl.gz: RAW only after check (i)
    (SHA3-256 of the blob = claimed id = node decoder id) and (ii) (reached by tips from our RAW block 7,415,464)."""
    ds = Path(a.dataset)
    guard(a.stage), guard(a.store)
    if Path(a.store).resolve() == V1_STORE.resolve():
        raise SystemExit("refused: --store is v1's tier B store")
    work = Path(tempfile.mkdtemp(prefix='v2w_'))
    dec_bin = build_decoder(work)
    hc = headerchain()
    staged = {}
    for t in range(WALL1_LINK[0], WALL1_LINK[1] + 1):
        p = Path(a.stage) / 'blocks' / str(t // 1000) / f'{t}.json'
        if p.exists():
            staged[t] = json.loads(p.read_text())
    dec = decode(dec_bin, [(t, 'block', bytes.fromhex(r['blob'])) for t, r in staged.items()], work)
    passed_i, tips_of, rows, rejected = set(), {}, {}, []
    for t, r in sorted(staged.items()):
        b = bytes.fromhex(r['blob'])
        d = dec.get(t, {})
        ok, why = P.check_i(b, r['claimed_hash'], d.get('id') if d.get('ok') else None)
        if not ok:
            rejected.append({'kind': 'block', 'id': r['claimed_hash'], 'topo': t, 'source': r['source'], 'failed': why})
            continue
        passed_i.add(d['id'])
        tips_of[d['id']] = d['tips']
        rows[t] = (b, d, r)
    anchor = hc[WALL1_LINK[1] + 1]
    tips_of[anchor['blid']] = anchor['tips']
    reached = P.tips_walk(tips_of, [anchor['blid']], passed_i)
    out = []
    for t, (b, d, r) in sorted(rows.items()):
        ii = d['id'] in reached and d['height'] == t
        if not ii:
            rejected.append({'kind': 'block', 'id': d['id'], 'topo': t, 'source': r['source'],
                             'failed': 'ii: not reached by tips from our RAW block 7,415,464 (or height != topo)'})
            continue
        h = store_blob(a.store, b)
        out.append({'height': t, 'blid': d['id'], 'sha256': h, 'tips': d['tips'], 'tx_hashes': d['tx_hashes'],
                    'checks': {'i': True, 'ii': True}, 'source': 'fetched:' + r['source'], 'fetch_time': r['fetch_time'],
                    'evidence_class': 'RAW', 'class': 'pending'})
    (ds / 'raw/wall1_blocks.jsonl.gz').write_bytes(gz_bytes(jl(x) for x in out))
    rj = ds / 'audit/rejected.jsonl'
    old = [json.loads(l) for l in rj.read_text().splitlines() if l.strip()] if rj.exists() else []
    old = [x for x in old if x.get('kind') != 'block'] + rejected
    rj.write_text(''.join(jl(x) + '\n' for x in sorted(old, key=lambda x: (x.get('kind', ''), x['id'], x.get('source', '')))))
    shutil.rmtree(work, ignore_errors=True)
    print(json.dumps({'staged': len(staged), 'raw': len(out), 'rejected': len(rejected),
                      'range': [out[0]['height'], out[-1]['height']] if out else None}))


def cmd_runs(a):
    """copy one node replay run (roots + summary) into raw/replay_runs/<run>/ (gzip, mtime 0)."""
    d = Path(a.dataset) / 'raw' / 'replay_runs' / a.run
    d.mkdir(parents=True, exist_ok=True)
    lines = [l.strip() for l in open(a.roots) if l.strip()]
    (d / 'roots.jsonl.gz').write_bytes(gz_bytes(lines))
    s = json.loads(Path(a.summary).read_text())
    for k in ('started', 'finished', 'seconds'):
        s.pop(k, None)  # wall-clock fields: kept in the round notes, not in the dataset (determinism)
    if a.binary:
        s['a2_binary_sha256'] = fsha(a.binary)
    (d / 'summary.json').write_bytes(dump(s))
    print(d, len(lines))


def cmd_plan(a):
    hc = headerchain()
    bodies = {r['txid']: r for r in read_gz(Path(a.dataset) / 'raw/tx_bodies.jsonl.gz')}
    out = []
    for h in range(a.from_, a.to + 1):
        r = hc.get(h)
        if r is None:
            raise SystemExit(f'no RAW block at {h}')
        txs = []
        for t in r.get('tx_hashes') or []:
            if t not in bodies:
                raise SystemExit(f'no RAW body for {t[:16]} at {h}: the plan cannot be complete')
            txs.append([t, bodies[t]['sha256']])
        out.append(jl({'topo': h, 'blid': r['blid'], 'sha256': r['sha256'], 'txs': txs}))
    Path(a.out).write_text('\n'.join(out) + '\n')
    print(a.out, len(out))


# ------------------------------------------------------------------------------------------------ pure rules (KAT MF13-MF18)
def block_fees(txs, txrows):
    """(fees, burns) of a block from its txs' decoded rows; a block with any body missing stays `pending: ...`, never 0
    (rft §0.8.9 rule 10: an unknown is not zero)."""
    have = [t for t in txs if t in txrows]
    if len(have) != len(txs):
        why = f'pending: {len(txs) - len(have)} of {len(txs)} tx bodies have no RAW copy (raw/missing_txs.json)'
        return why, why
    return sum(txrows[t]['fee'] for t in txs), sum(txrows[t]['burn_total'] for t in txs)


SC_TX_TYPE = 'SC'  # transaction.SC_TX.String() (transaction/transaction.go:54-55): the decoder's tx_type is String()


def sc_count(txs, txrows):
    """SC_TX count of a block's txs with a decoded row (R26 verify: comparing with 'SC_TX' counted 0 of 199)."""
    return sum(1 for t in txs if t in txrows and txrows[t]['tx_type'] == SC_TX_TYPE)


def end_state_check(roots, anchor_topo, ours):
    """MATCH only when the run reached the anchor topo with our own treehash; a reached anchor with another root is a
    DIVERGENCE; a run that stopped earlier is `pending` (never assumed)."""
    end = roots.get(anchor_topo)
    if end is None:
        last = max(roots) if roots else None
        return f'pending: the run reached topo {last}, not {anchor_topo:,}'
    return 'MATCH' if end['root'] == ours else 'DIVERGENCE'


def witnesses(txrows, roots, arch_roots, seed_top):
    """payload 0 Statement.Roothash of each RAW tx vs our root at its reference topo: replay roots first (the seed's
    own top is an archive root, not a replay result), else the archive roots."""
    w = {'equal': 0, 'differ': 0, 'archive_equal': 0, 'archive_differ': 0, 'outside_held_roots': 0, 'rows_differ': [],
         'rule': 'payload 0 Statement.Roothash of a RAW tx vs our root at its reference topo (replay roots, else the '
                 'archive roots of v1 derived/archive_state)'}
    for t in sorted(txrows):
        x = txrows[t]
        if not x['payloads']:
            continue
        rh, ref = x['payloads'][0]['roothash'], x['ref_height']
        if ref in roots and ref != seed_top:
            k = 'equal' if roots[ref]['root'] == rh else 'differ'
        elif ref in arch_roots:
            k = 'archive_equal' if arch_roots[ref] == rh else 'archive_differ'
        else:
            w['outside_held_roots'] += 1
            continue
        w[k] += 1
        if k.endswith('differ'):
            w['rows_differ'].append(t)
    return w


def class_slot_problems(rows, where='?'):
    """every per-tx / per-block record of v2 carries the defect-class slot `class` and its `evidence_class`"""
    out = []
    for i, r in enumerate(rows):
        if not isinstance(r, dict) or 'class' not in r or 'evidence_class' not in r:
            out.append(f'{where}[{i}]: record without the class / evidence_class slot')
        elif not isinstance(r['class'], str) or not r['class']:
            out.append(f'{where}[{i}]: empty class (unknown must be `pending`)')
    return out


# ------------------------------------------------------------------------------------------------ derive
def derive(ds, stores, out, work, root=ROOT):
    """raw/ (+ v1 RAW inputs, + store blobs) -> out/derived/*; deterministic; returns {relpath: bytes}"""
    ds, out = Path(ds), Path(out)
    files = {}
    hc = headerchain(root, ds)
    bodies = {r['txid']: r for r in read_gz(ds / 'raw/tx_bodies.jsonl.gz')}
    missing = json.loads((ds / 'raw/missing_txs.json').read_text())
    need = needed_txs(hc)
    need.update(needed_txs(hc, WALLS['wall1'] - WALL_RADIUS, WALLS['wall1'] + WALL_RADIUS))
    dec_bin = build_decoder(work)
    items = []
    for t in sorted(bodies):
        b = read_store(stores, bodies[t]['sha256'])
        if b is None:
            raise SystemExit(f'tx body {t[:16]} not in the store: derive needs the tier B store (mode full)')
        items.append((t, 'tx2', b))
    dec = decode(dec_bin, items, work)
    # ---- per tx
    txrows = {}
    for t in sorted(bodies):
        d = dec[t]
        burns = sum(p['burn_value'] for p in d['payloads'])
        txrows[t] = {'txid': t, 'carrier_height': bodies[t]['carrier_height'], 'tx_type': d['tx_type'], 'fee': d['fees'],
                     'burn_total': burns, 'value_field': d['value'], 'ref_height': d['ref_height'], 'ref_blid': d['ref_blid'],
                     'has_scdata': d['has_scdata'], 'size': d['size'],
                     'payloads': [{'ring_size': p['ring_size'], 'burn_value': p['burn_value'], 'scid_zero': p['scid_zero'],
                                   'roothash': p['statement_roothash']} for p in d['payloads']],
                     'body_sha256': bodies[t]['sha256'], 'evidence_class': 'DERIVED (node decoder over a RAW body)',
                     'class': 'pending'}
    files['derived/txs.jsonl.gz'] = gz_bytes(jl(txrows[t]) for t in sorted(txrows))
    # ---- per tx-carrying block: fees and burns
    v1rows = {r['height']: r for r in read_gz(Path(root) / V1 / 'derived/window.jsonl.gz')}
    brows, em = [], {'v1_pending': 0, 'settled': 0, 'still_pending': 0, 'settled_fee_sum': 0, 'settled_burn_sum': 0,
                     'window_txblocks': 0, 'window_fee_sum': 0, 'window_burn_sum': 0, 'window_fee_pending_blocks': 0,
                     'gap_txblocks': 0, 'gap_fee_sum': 0, 'gap_burn_sum': 0, 'gap_fee_pending_blocks': 0, 'sc_tx_blocks': 0,
                     'sc_txs': 0}
    for h in range(WINDOW[0], ANCHOR_TOPO + 1):
        r = hc.get(h)
        if not r or not r.get('tx_hashes'):
            continue
        txs = r['tx_hashes']
        in_window = h <= WINDOW[1]
        fees, burns = block_fees(txs, txrows)
        sc = sc_count(txs, txrows)
        v1 = v1rows.get(h)
        v1_status = ('outside v1 window' if v1 is None else 'known' if isinstance(v1.get('fees'), int) else 'pending')
        row = {'height': h, 'blid': r['blid'], 'tx_count': len(txs), 'fees': fees, 'public_burns': burns, 'sc_txs': sc,
               'sc_payouts': PENDING_SC if sc else 0, 'v1_fees_status': v1_status,
               'evidence_class': 'DERIVED (sum of the node decoder fees/burns of the RAW bodies)', 'class': 'pending'}
        if v1_status == 'known' and isinstance(fees, int) and v1['fees'] != fees:
            row['v1_disagrees'] = v1['fees']
        brows.append(row)
        if sc:
            em['sc_tx_blocks'] += 1
            em['sc_txs'] += sc
        pre = 'window' if in_window else 'gap'
        em[pre + '_txblocks'] += 1
        if isinstance(fees, int):
            em[pre + '_fee_sum'] += fees
            em[pre + '_burn_sum'] += burns
        else:
            em[pre + '_fee_pending_blocks'] += 1
        if v1_status == 'pending':
            em['v1_pending'] += 1
            if isinstance(fees, int):
                em['settled'] += 1
                em['settled_fee_sum'] += fees
                em['settled_burn_sum'] += burns
            else:
                em['still_pending'] += 1
    files['derived/blocks_fees.jsonl.gz'] = gz_bytes(jl(b) for b in brows)
    v1em = json.loads((Path(root) / V1 / 'derived/emission.json').read_text())
    disagree = [b['height'] for b in brows if 'v1_disagrees' in b]
    fees = {'scope': f'tx-carrying blocks {WINDOW[0]:,}..{ANCHOR_TOPO:,} (window {WINDOW[0]:,}..{WINDOW[1]:,} and the gap '
                     f'to our anchor)',
            'v1': {'pending_blocks': v1em['fees']['pending_blocks'], 'known_blocks': v1em['fees']['known_blocks'],
                   'known_sum_atomic': v1em['fees']['known_sum_atomic']},
            'v2': em, 'v1_known_rows_disagreeing': disagree,
            'rule': 'fee = transaction.Fees(), burn = sum of payload BurnValue (the node decoder, as v1 derive.py); '
                    'public fields only; SC payouts stay pending with the reason',
            'coverage': {'settled_of_v1_pending': [em['v1_pending'] - em['still_pending'], em['v1_pending']],
                         'bound_type': 'pending (set by forensics-classes, rft §0.8.9 rule 9)'},
            'sc_payouts': ('0: no SC_TX in any tx-carrying block of the scope (sc_txs 0), and only an SC_TX runs SC code'
                           if em['sc_txs'] == 0 else PENDING_SC),
            'evidence_class': 'DERIVED', 'class': 'pending'}
    files['derived/fees.json'] = dump(fees)
    # ---- state roots from the node replay run(s)
    runs = {}
    rr = ds / 'raw' / 'replay_runs'
    if rr.is_dir():
        for d in sorted(rr.iterdir()):
            if (d / 'roots.jsonl.gz').exists():
                runs[d.name] = {'roots': read_gz(d / 'roots.jsonl.gz'), 'summary': json.loads((d / 'summary.json').read_text()),
                                'roots_sha256': fsha(d / 'roots.jsonl.gz')}
    seed = json.loads((ds / 'raw/archive_seed.json').read_text())
    arch_roots = {r['topo']: r['root'] for r in read_gz(Path(root) / V1 / 'derived/archive_state/roots.jsonl.gz')}
    sr = {'our_treehash_at_anchor': OUR_TREEHASH, 'anchor_topo': ANCHOR_TOPO, 'runs': {}, 'class': 'pending',
          'evidence_class': 'DERIVED (node replay: tools/forensics/a2 replay -> blockchain.Add_Complete_Block)'}
    best = None
    for name, R in runs.items():
        roots = {x['topo']: x for x in R['roots']}
        topos = sorted(roots)
        chain_ok = all(roots[t]['blid'] == hc[t]['blid'] for t in topos if t in hc)
        res = {'roots_sha256': R['roots_sha256'], 'topo_range': [topos[0], topos[-1]] if topos else None, 'topos': len(topos),
               'blids_equal_raw_headerchain': chain_ok, 'stopped': R['summary'].get('stopped'),
               'fail_topo': R['summary'].get('fail_topo'), 'fail_error': R['summary'].get('fail_error'),
               'base_root_eq_archive_root': roots.get(seed['top_topo'], {}).get('root') == arch_roots.get(seed['top_topo'])}
        res['end_state_check'] = end_state_check(roots, ANCHOR_TOPO, OUR_TREEHASH)
        if ANCHOR_TOPO in roots:
            res['end_root'] = roots[ANCHOR_TOPO]['root']
        sr['runs'][name] = res
        if best is None or len(topos) > len(best[1]):
            best = (name, roots)
    if len(runs) >= 2:
        shas = {r['roots_sha256'] for r in runs.values()}
        sr['runs_byte_identical'] = len(shas) == 1
    # roothash witnesses: a tx's Statement.Roothash is the root its creator's node saw at the reference block
    window_rows = []
    wit = witnesses(txrows, best[1] if best else {}, arch_roots, seed['top_topo'])
    if best:
        name, roots = best
        topos = sorted(roots)
        for t in topos[1:]:
            if t - 1 in roots:
                window_rows.append(jl({'topo': t, 'blid': roots[t]['blid'], 'state_root_pre': roots[t - 1]['root'],
                                       'state_root_post': roots[t]['root'], 'state_version': roots[t]['state_version'],
                                       'in_window': WINDOW[0] <= t <= WINDOW[1], 'run': name,
                                       'evidence_class': 'DERIVED (node replay)', 'class': 'pending'}))
        inw = [t for t in topos[1:] if WINDOW[0] <= t <= WINDOW[1]]
        sr['window_coverage'] = {'topos_with_pre_post_root': len(inw), 'window_topos': WINDOW[1] - WINDOW[0] + 1,
                                 'pending_range': [WINDOW[0], (inw[0] - 1) if inw else WINDOW[1]],
                                 'pending_reason': 'no base state before this range: (a2) TreeSection blocked (derived/a2.json); '
                                                   'our archive starts at 7,453,290 and its replay stopped at 7,467,516'}
    sr['roothash_witnesses'] = wit
    sr['a10c'] = {'question': 'are the archive roots 7,453,290..7,467,515 consistent with what our node accepted later?',
                  'archive_top_root': arch_roots.get(seed['top_topo']), 'seed_top_root': seed.get('top_root'),
                  'answer': ('bound: the replay from the archive top state reaches our own treehash at the anchor'
                             if any(r.get('end_state_check') == 'MATCH' for r in sr['runs'].values()) else
                             'DIVERGENCE: the replay from the archive state does not reach our treehash'
                             if any(r.get('end_state_check') == 'DIVERGENCE' for r in sr['runs'].values()) else
                             'pending: no complete replay run')}
    files['derived/state_roots.json'] = dump(sr)
    files['derived/roots_window.jsonl.gz'] = gz_bytes(window_rows)
    # ---- the replay-wall windows
    walls = {}
    best_roots = best[1] if best else {}
    hf3 = set()
    for l in (Path(root) / HF3).read_text().splitlines():
        l = l.strip()
        if l.startswith('"') and 'Bl_Tips' in l:
            hf3.add(l.split('"')[1])
    for w, topo in WALLS.items():
        rows = []
        for h in range(topo - WALL_RADIUS, topo + WALL_RADIUS + 1):
            r = hc.get(h)
            if r is None:
                rows.append({'height': h, 'raw_block': 'missing: no RAW block at this height (v1 headerchain starts at '
                                                       '7,415,464; raw/wall1_blocks.jsonl.gz does not hold it)',
                             'evidence_class': 'missing', 'class': 'pending'})
                continue
            txs = r.get('tx_hashes') or []
            rows.append({'height': h, 'blid': r['blid'], 'tx_count': len(txs), 'hf3_table_txs': sorted(t for t in txs if t in hf3),
                         'bodies_raw': sum(1 for t in txs if t in bodies),
                         'node_replay': ('not replayable: no held state below 7,453,290 (derived/a2.json)' if h < 7453290 else
                                         'base of the replay: committed by our 2026-08 archive node' if h == seed['top_topo'] else
                                         'accepted (Add_Complete_Block at this commit; root ' + best_roots[h]['root'][:16] + ')'
                                         if h in best_roots else
                                         'committed by our 2026-08 archive node (not re-run)' if h in arch_roots else
                                         'not replayed: pending'), 'evidence_class': 'RAW block; replay outcome DERIVED', 'class': 'pending'})
        walls[w] = {'wall_topo': topo, 'radius': WALL_RADIUS, 'rows': rows}
    # the stop of the node replay, if any: a block of the canonical chain that the node's own checks reject
    stops = {}
    for name in sorted(runs):
        rj = ds / 'raw' / 'replay_runs' / name / 'rejection.json'
        if rj.exists():
            j = json.loads(rj.read_text())
            stops[name] = {k: j[k] for k in ('topo', 'blid', 'txid', 'check', 'tip_nonce_height', 'tx_ref_nonce_height')}
            stops[name]['blid_equals_raw_headerchain'] = hc.get(j['topo'], {}).get('blid') == j['blid']
            stops[name]['txid_in_hf3_table'] = j['txid'] in hf3
    walls['replay_stops'] = {'runs': stops, 'rule': 'a stop is a RAW block (checks i-ii) that blockchain.Add_Complete_Block '
                             'rejects at this commit, replayed from the archive state; it is a fact about the current code '
                             'and that state, not a verdict on the block', 'class': 'pending'}
    files['derived/walls.json'] = dump(walls)
    # ---- a TXID included in more than one RAW block (structural census; the HF3 table names 75 TXIDs)
    seen = {}
    for h in range(WINDOW[0], ANCHOR_TOPO + 1):
        r = hc.get(h)
        for t in (r or {}).get('tx_hashes') or []:
            seen.setdefault(t, []).append(h)
    multi = {t: hs for t, hs in seen.items() if len(hs) > 1}
    seen_w1 = {}
    for h in range(WALL1_LINK[0], WALL1_LINK[1] + 1):
        for t in (hc.get(h) or {}).get('tx_hashes') or []:
            seen_w1.setdefault(t, []).append(h)
    multi_w1 = {t: hs for t, hs in seen_w1.items() if len(hs) > 1}
    files['derived/inclusions.json'] = dump({
        'scope': [WINDOW[0], ANCHOR_TOPO], 'txids': len(seen), 'txids_in_more_than_one_block': len(multi),
        'in_hf3_table': sum(1 for t in multi if t in hf3), 'not_in_hf3_table': sorted(t for t in multi if t not in hf3),
        'rows': [{'txid': t, 'heights': multi[t], 'in_hf3_table': t in hf3, 'class': 'pending'} for t in sorted(multi)],
        'wall1_link_range': {'scope': list(WALL1_LINK), 'raw_blocks': sum(1 for h in range(WALL1_LINK[0], WALL1_LINK[1] + 1) if h in hc),
                             'txids': len(seen_w1), 'txids_in_more_than_one_block': len(multi_w1),
                             'in_hf3_table': sum(1 for t in multi_w1 if t in hf3),
                             'rows': [{'txid': t, 'heights': multi_w1[t], 'in_hf3_table': t in hf3, 'class': 'pending'}
                                      for t in sorted(multi_w1)]},
        'rule': 'tx lists of RAW blocks (v1 headerchain, checks i-ii); the same TXID in two blocks is one body executed '
                'twice (TXID = Keccak256 of the core statement); structural fact only',
        'evidence_class': 'DERIVED', 'class': 'pending'})
    # ---- (a2)
    att = json.loads((ds / 'raw/a2_attempt.json').read_text())
    files['derived/a2.json'] = dump({
        'question': '(a2): can the state at topo 7,415,465 be fetched by TreeSection from ONE archival source?',
        'verdict': att['verdict'], 'evidence': att['evidence_summary'], 'fallback': att['fallback'],
        'evidence_class': 'DERIVED from raw/a2_attempt.json', 'class': 'pending'})
    nb = len(bodies)
    files['derived/summary.json'] = dump({
        'tx_bodies_needed': len(need), 'tx_bodies_raw': nb, 'tx_bodies_missing': missing['missing_count'],
        'txs_decoded': len(txrows), 'txblocks': len(brows), 'v1_pending_fee_blocks': em['v1_pending'],
        'v1_pending_settled': em['settled'], 'v1_pending_still': em['still_pending'],
        'replay_runs': len(runs), 'end_state': {k: v.get('end_state_check') for k, v in sr['runs'].items()},
        'records_with_class_slot': len(txrows) + len(brows) + len(window_rows), 'window': list(WINDOW)})
    # R28 B126: the defect class of every derived record (classes.py rule: a table TXID is DC1, every other tx DC3, every
    # block record DC3); applied here so the G28 re-derivation reproduces the tagged files byte for byte
    import classes  # noqa: E402  (a replay tool of v2 since R28: TOOLS)
    files = classes.tag_v2_files(files, classes.hf3_txids(root))
    for rel, b in files.items():
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b)
    return files


def cmd_derive(a):
    work = Path(tempfile.mkdtemp(prefix='v2d_'))
    files = derive(a.dataset, [a.store], a.out or a.dataset, work)
    shutil.rmtree(work, ignore_errors=True)
    print(json.dumps({k: sha(v)[:16] for k, v in sorted(files.items())}, indent=1))


# ------------------------------------------------------------------------------------------------ manifest / replay
# R26 merge: forensics-classes writes these four files into the v2 dataset (plan: 'classes write only these four files
# + the class tags'); harness/forensics/classes.py, presence.py and invariant.py produce them, not v2.derive. They are
# pinned like every dataset file (listed in `files`, a changed one FAILS) but are not in the v2 re-derivation set; their
# own --check re-reads them (G31/G32). Before this, the merged tree failed G28 with 4 'unlisted file' reasons.
CLASS_FILES = {'derived/classes.json': 'harness/forensics/classes.py', 'derived/fq.json': 'harness/forensics/classes.py',
               'derived/presence.json': 'harness/forensics/presence.py',
               'derived/invariant.json': 'harness/forensics/invariant.py'}


def rederived(files):
    """the manifest entries v2.derive must reproduce: derived/ files that forensics-classes did not write"""
    return {k: h for k, h in files.items() if k.startswith('derived/') and k not in CLASS_FILES}


def dataset_files(ds):
    return {str(p.relative_to(ds)): fsha(p) for p in sorted(Path(ds).rglob('*')) if p.is_file() and p.name != 'manifest.json'}


def store_index(stores, shas):
    have = sorted(h for h in shas if read_store(stores, h) is not None)
    return sha(''.join(h + '\n' for h in have).encode()), len(have)


def cmd_manifest(a):
    ds = Path(a.dataset)
    files = dataset_files(ds)
    (ds / 'replay').mkdir(exist_ok=True)
    exp = ''.join(f'{h}  {k}\n' for k, h in sorted(rederived(files).items()))
    (ds / 'replay/expected.sha256').write_text(exp)
    (ds / 'replay/replay.sh').write_text(REPLAY_SH)
    os.chmod(ds / 'replay/replay.sh', 0o755)
    files = dataset_files(ds)
    shas = [r['sha256'] for r in read_gz(ds / 'raw/tx_bodies.jsonl.gz')]
    idx, n = store_index([a.store], shas)
    git = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
    gov = subprocess.run(['go', 'version'], capture_output=True, text=True).stdout.strip()
    m = {'dataset': ds.name, 'version': 2, 'supersedes': [], 'files': files,
         'tools': {t: fsha(ROOT / t) for t in TOOLS}, 'hf3_table': {'file': HF3, 'sha256': fsha(ROOT / HF3)},
         'inputs': {t: fsha(ROOT / t) for t in V1_INPUTS},
         'inputs_rule': 'v1 files read by path and pinned by SHA-256; v1 is never rewritten (rft §0.8.1 rule 4)',
         'tierB_store': {'location': '~/derohe-persist/forensics_raw_r26/blobs (outside git; v1\'s store is never written)', 'tx_bodies': n,
                         'tx_index_sha256': idx},
         'git_base_commit': git, 'go': gov, 'python': platform.python_version(),
         'replay_tool': 'harness/forensics/v2.py',
         'replay': {'command': f'sh forensics/{ds.name}/replay/replay.sh [--record harness/runtime/forensics_replay.json]',
                    'expected': 'replay/expected.sha256',
                    'node_replay': ('raw/replay_runs/<run>/ are outputs of `tools/forensics/a2 replay` (the node\'s own '
                                    'Add_Complete_Block) over raw inputs; they are re-hashed by v2.py replay and re-run '
                                    'with a2 (hours), not re-derived by Python')},
         'class_files': {k: v for k, v in sorted(CLASS_FILES.items()) if k in files},
         'class_slot': '`class` on every per-tx/per-block record = the defect class of rft §0.8.9 (derived/ records: '
                       'v2.derive applies classes.tag_v2_files; raw/ records: classes.py --tag; R28 B126); '
                       '`evidence_class` = RAW/DERIVED/EXT (§0.8.2)'}
    (ds / 'manifest.json').write_bytes(dump(m))
    print('manifest', sha((ds / 'manifest.json').read_bytes()), len(files), 'files')


REPLAY_SH = '''#!/bin/sh
# forensics/r26 replay (rft §0.8.3, gate G28): ONE command re-derives every derived/ file of dataset v2 from raw/ (and
# the pinned v1 RAW inputs) into a scratch dir and checks every SHA-256 against manifest.json and expected.sha256.
# Tier B blobs (tx bodies) are read from $FORENSICS_R26_STORE (default: $HOME/derohe-persist/forensics_raw_r26): v2 keeps
# its own store, since v1's replay hashes the listing of ITS store (replay.py store_index) and any added blob fails v1.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
store=${FORENSICS_R26_STORE:-$HOME/derohe-persist/forensics_raw_r26}
exec nice -n 15 python3 -I "$root/harness/forensics/v2.py" replay "$root/forensics/r26" --store "$store" "$@"
'''


def replay(ds, store, root=ROOT):
    ds = Path(ds)
    mb = (ds / 'manifest.json').read_bytes()
    m = json.loads(mb)
    rep = {'dataset': ds.name, 'manifest_sha256': sha(mb), 'fail_reasons': [], 'steps': []}
    f = rep['fail_reasons']
    # 1 manifest: every file listed and equal, tools + HF3 table + v1 inputs equal
    for rel, h in sorted(m['files'].items()):
        p = ds / rel
        if not p.exists() or fsha(p) != h:
            f.append(f'manifest: {rel} missing or changed')
    for rel in sorted(set(dataset_files(ds)) - set(m['files'])):
        f.append(f'manifest: unlisted {rel}')
    for t, h in sorted(m['tools'].items()):
        if not (root / t).exists() or fsha(root / t) != h:
            f.append(f'tool changed: {t}')
    for t, h in sorted(m['inputs'].items()):
        if not (root / t).exists() or fsha(root / t) != h:
            f.append(f'v1 input changed: {t}')
    if fsha(root / m['hf3_table']['file']) != m['hf3_table']['sha256']:
        f.append('HF3 table changed')
    rep['steps'].append('manifest')
    # 2 raw: every tx body in the store re-hashes, and re-passes check (iii) is left to derive (decoder) below
    stores = [store] if store else []
    shas = [r['sha256'] for r in read_gz(ds / 'raw/tx_bodies.jsonl.gz')]
    idx, n = store_index(stores, shas)
    full = n == len(shas) and idx == m['tierB_store']['tx_index_sha256']
    rep['store'] = {'tx_bodies_present': n, 'tx_bodies_listed': len(shas), 'index_equal': idx == m['tierB_store']['tx_index_sha256']}
    # check (i) re-run on every RAW wall-1 link block: its stored blob hashes (SHA3-256) to its block id
    w1 = read_gz(ds / 'raw/wall1_blocks.jsonl.gz')
    w1_ok = w1_missing = 0
    for r in w1:
        b = read_store(stores, r['sha256'])
        if b is None:
            w1_missing += 1
        elif hashlib.sha3_256(b).hexdigest() == r['blid']:
            w1_ok += 1
        else:
            f.append(f"raw: wall-1 block {r['height']} blob does not hash to its id (check i)")
    rep['store']['wall1_blocks'] = {'listed': len(w1), 'check_i_ok': w1_ok, 'blob_missing': w1_missing}
    full = full and w1_missing == 0
    rep['steps'].append('store')
    # 3 re-derive into scratch
    exp = rederived(m['files'])
    if (ds / 'replay/expected.sha256').read_text() != ''.join(f'{h}  {k}\n' for k, h in sorted(exp.items())):
        f.append('expected.sha256 differs from the manifest')
    rd = {'expected': len(exp), 'equal': 0, 'mismatch': [], 'missing': [], 'extra': [], 'mode': 'full' if full else 'partial'}
    if full:
        work = Path(tempfile.mkdtemp(prefix='v2r_'))
        try:
            out = derive(ds, stores, work / 'out', work, root)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        for k, h in sorted(exp.items()):
            if k not in out:
                rd['missing'].append(k)
            elif sha(out[k]) != h:
                rd['mismatch'].append(k)
            else:
                rd['equal'] += 1
        rd['extra'] = sorted(set(out) - set(exp))
        rd['rederived'] = len(out)
        if rd['mismatch'] or rd['missing'] or rd['extra']:
            f.append(f"re-derive: {len(rd['mismatch'])} mismatch, {len(rd['missing'])} missing, {len(rd['extra'])} extra")
    else:
        rd['rederived'] = 0
        f.append('mode partial: the tier B store is missing tx bodies (no re-derivation)')
    rep['rederive'] = rd
    rep['steps'].append('rederive')
    rep['tools_sha256'] = {t: fsha(root / t) for t in TOOLS}
    rep['result'] = 'PASS' if not f else 'FAIL'
    return rep


def dumps(rep):
    return json.dumps(rep, indent=1, sort_keys=True) + '\n'


def main(argv=None):
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest='cmd', required=True)
    p = sp.add_parser('bodies'); p.add_argument('--dataset', required=True); p.add_argument('--stage', required=True)
    p.add_argument('--archive-copy', required=True); p.add_argument('--store', required=True)
    p = sp.add_parser('wall1'); p.add_argument('--dataset', required=True); p.add_argument('--stage', required=True)
    p.add_argument('--store', required=True)
    p = sp.add_parser('runs'); p.add_argument('--dataset', required=True); p.add_argument('--run', required=True)
    p.add_argument('--roots', required=True); p.add_argument('--summary', required=True); p.add_argument('--binary')
    p = sp.add_parser('plan'); p.add_argument('--dataset', required=True); p.add_argument('--from', dest='from_', type=int, required=True)
    p.add_argument('--to', type=int, required=True); p.add_argument('--out', required=True)
    p = sp.add_parser('derive'); p.add_argument('--dataset', required=True); p.add_argument('--store', required=True)
    p.add_argument('--out')
    p = sp.add_parser('manifest'); p.add_argument('--dataset', required=True); p.add_argument('--store', required=True)
    p = sp.add_parser('replay'); p.add_argument('dataset'); p.add_argument('--store'); p.add_argument('--record')
    p.add_argument('--report')
    a = ap.parse_args(argv)
    if a.cmd == 'replay':
        rep = replay(a.dataset, a.store)
        txt = dumps(rep)
        if a.report:
            Path(a.report).write_text(txt)
        if a.record:
            sys.path.insert(0, str(HERE))
            import replay as v1replay  # the one record writer (G28 reads it): same schema for every version
            v1replay.record_run(a.record, txt, rep)
        sys.stdout.write(txt)
        print(f"v2 replay {rep['result']} mode={rep['rederive']['mode']} report_sha256={sha(txt.encode())}", file=sys.stderr)
        return 0 if rep['result'] == 'PASS' else 5
    {'bodies': cmd_bodies, 'wall1': cmd_wall1, 'runs': cmd_runs, 'plan': cmd_plan, 'derive': cmd_derive, 'manifest': cmd_manifest}[a.cmd](a)
    return 0


if __name__ == '__main__':
    sys.exit(main())
