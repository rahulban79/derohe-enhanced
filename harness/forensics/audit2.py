#!/usr/bin/env python3
"""Independent audit of dataset v2 `forensics/r26/` (rft §0.8.5 refute by default, §0.8.9 classes, §8 forensics-audit2;
backlog B97, A10c, A11, B123, B126; gate G29; KAT harness/kat/test_forensics_audit2_r26.py AU1-AU12).

The auditor of v1 is `audit_check.py` (`audit-check-1`). This module extends it to v2. It is the SAME second
implementation (it imports audit_check for its own Keccak-f[1600], its own block/tx wire decoders, its own HF3 table
parser and its content scan), and it shares no code with the v2 builder: it does not import v2.py, keccak.py,
provenance.py, classes.py, bounds.py, presence.py, invariant.py or the Go decoder, and it reads the builder's derived/
files only at the END, as CLAIMS. Every check runs from bytes: the v1 tier B store (blocks), the v2 store (tx bodies,
wall-1 blocks), the archive copy (APFS clone), and, for the wall-4 re-check, a node replay that this audit runs itself
on its own APFS clone with its own plan.

New in v2 (B97):
  * a second, independently written STRUCTURAL / public-value verifier of every proof-carrying tx: wire layout per
    ring size, every compressed point and every scalar re-checked for canonical encoding (bn256 constants read from
    the source text), ring shape, the public fields. It never builds, varies or describes a proof. A second SOUNDNESS
    verifier is NO-GO (rft §9): telling two verifiers apart needs a proof that one accepts and the other rejects,
    which is exploit content (§0.8.1 rule 6), and the ring state it would need exists only inside the held archive.
  * the duplicate-body census: every TXID carried by more than one RAW block, every body copy held under it from
    every independent source, compared byte for byte (equal / different / single copy, with counts).

  python3 -I harness/forensics/audit2.py plan    --v1-store DIR --v2-store DIR --from T --to T --out F [--jobs N]
  python3 -I harness/forensics/audit2.py run     forensics/r26 --v1-store DIR --v2-store DIR --archive DIR
                                                 [--stage DIR] [--replay DIR] [--private DIR] [--jobs N] --out DIR
  python3 -I harness/forensics/audit2.py build   forensics/r26 --rerun F [--keep-previous RUN]
  python3 -I harness/forensics/audit2.py selftest
Read-only towards every node and store; nothing here talks to a network. Exploit content: none (§0.8.1 rule 6).
"""
import collections, gzip, hashlib, json, os, re, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import audit_check as AC  # noqa: E402  (the auditor's own second implementation; never the builder's code)

IMPL_VERSION = 'audit2-1'
HF3_ENTRY = 'p2p.Add_Complete_Block_HF3'             # R28 v3: run C's entry point (B123 fix); a summary without `entry`
PRE_FIX_ENTRY = 'blockchain.Add_Complete_Block'      # is a pre-fix run (A/B of v2)
V1 = 'forensics/r25'
WINDOW = (7415466, 7497942)
WALL1_LINK = (7412665, 7415463)
# the replay walls: wall 1..3 from the R25 discovery (topos of the tx that stopped a replay), wall 4 = the stop of the
# v2 node replay runs A/B (raw/replay_runs/*/summary.json fail_topo)
WALLS = {'wall1': 7412675, 'wall2': 7467516, 'wall3': 7497836, 'wall4': 7467546}
TREEHASH_SOURCE = ('harness/runtime/r25_forensics_discovery_20261103.txt', 112)
REQUIRED = ('D2-01', 'D2-02', 'D2-04', 'D2-05', 'D2-11', 'D2-12', 'D2-14')   # G29 for v2 (audit_check.REQUIRED_BY_VERSION)
FORBIDDEN = [Path.home() / 'dero-data']


def sha(b):
    return hashlib.sha256(b).hexdigest()


def fsha(p):
    return sha(Path(p).read_bytes())


def jgz(p):
    return [json.loads(l) for l in gzip.decompress(Path(p).read_bytes()).decode().splitlines() if l.strip()]


def guard(p):
    if p is None:
        return None
    r = Path(p).resolve()
    for f in FORBIDDEN:
        if r == f.resolve() or f.resolve() in r.parents:
            raise SystemExit(f'refused: {p} lies under a live node store (rft §5)')
    return r


# =============================================================================================== structural verifier (B97)
def bn256_constants(repo):
    """P (base field) and Order (group order) read from the source text (cryptography/bn256/constants.go)."""
    t = (Path(repo) / 'cryptography/bn256/constants.go').read_text()
    o = re.search(r'var Order = bigFromBase10\("(\d+)"\)', t)
    p = re.search(r'var P = bigFromBase10\("(\d+)"\)', t)
    if not o or not p:
        raise ValueError('bn256 constants not found in the source')
    return int(p.group(1)), int(o.group(1))


def point_problem(b, P):
    """None for a canonical compressed G1 encoding as Compress() writes it (changes.go:19-35: 32-byte big-endian x,
    then 0x00 / 0x01), else the name of the failed structural check. Identity (x = 0, flag 0) is reported apart."""
    if len(b) != 33:
        return 'point-length'
    x = int.from_bytes(b[:32], 'big')
    if b[32] not in (0, 1):
        return 'point-flag-not-0-or-1'
    if x >= P:
        return 'point-x-not-reduced'
    rhs = (x * x * x + 3) % P
    if rhs and pow(rhs, (P - 1) // 2, P) != 1:
        return 'point-not-on-curve'
    return None


def scalar_problem(b, N):
    if len(b) != 32:
        return 'scalar-length'
    return 'scalar-not-reduced' if int.from_bytes(b, 'big') >= N else None


def proof_layout(power):
    """(kind, count) runs of the proof wire (proof_generate.go:84-140, proof_innerproduct.go:42-52), in order."""
    L = power
    lay = [('P', 4), ('P', 8 * L), ('P', 1), ('S', 2 * L), ('S', 1), ('P', 2), ('S', 2), ('S', 5), ('S', 2), ('P', 14)]
    n = sum(c * (33 if k == 'P' else 32) for k, c in lay)
    if n != AC.proof_len(power):
        raise ValueError('proof layout disagrees with the audit decoder length')
    return lay


def statement_spans(b):
    """Offsets of the statement's compressed points (D, then C[ring]) per payload, re-walking the core statement
    with the audit decoder's primitives (transaction.go:304-411)."""
    i = 0
    _, i, _ = AC.uvarint(b, i)
    _, i, _ = AC.uvarint(b, i)
    _, i, _ = AC.uvarint(b, i)
    typ, i, _ = AC.uvarint(b, i)
    if typ in (AC.PREMINE, AC.SC_TX):
        _, i, _ = AC.uvarint(b, i)
    if typ in (AC.PREMINE, AC.COINBASE, AC.REGISTRATION):
        i += 33
    if typ == AC.REGISTRATION:
        i += 64
    out = []
    if typ in (AC.BURN_TX, AC.NORMAL, AC.SC_TX):
        _, i, _ = AC.uvarint(b, i)
        i += 32
        n, i, _ = AC.uvarint(b, i)
        for _ in range(n):
            _, i, _ = AC.uvarint(b, i)
            i += 32 + 1 + AC.PAYLOAD_LIMIT
            power = b[i]; i += 1
            ring = 1 << power
            bpp = b[i]; i += 1
            _, i, _ = AC.uvarint(b, i)
            pts = [i]
            i += 33
            i += ring * bpp
            pts += [i + 33 * k for k in range(ring)]
            i += 33 * ring + 32
            out.append({'power': power, 'points': pts})
    return out


def struct_tx(b, P, N):
    """The B97 structural verifier for one body: {check_name: problem or None} plus counts. Pass/fail per named check
    only; nothing about how a proof is built (rft §0.8.1 rule 6)."""
    t = AC.decode_tx(b)
    res = {'type': AC.TXTYPES[t['type']], 'checks': {}, 'points': 0, 'scalars': 0}
    if t['type'] not in (AC.BURN_TX, AC.NORMAL, AC.SC_TX):
        return res
    probs = {}
    spans = statement_spans(b)
    if len(spans) != len(t['payloads']):
        probs['statement-walk'] = 1
    i = t['core_len']
    for sp, p in zip(spans, t['payloads']):
        if not 1 <= p['power'] <= 7:
            probs['ring-power-range'] = probs.get('ring-power-range', 0) + 1
        if not p['pointers_distinct']:
            probs['ring-pointers-not-distinct'] = probs.get('ring-pointers-not-distinct', 0) + 1
        for off in sp['points']:
            res['points'] += 1
            q = point_problem(b[off:off + 33], P)
            if q:
                probs['statement-' + q] = probs.get('statement-' + q, 0) + 1
        for kind, cnt in proof_layout(p['power']):
            for _ in range(cnt):
                if kind == 'P':
                    res['points'] += 1
                    q = point_problem(b[i:i + 33], P)
                    i += 33
                else:
                    res['scalars'] += 1
                    q = scalar_problem(b[i:i + 32], N)
                    i += 32
                if q:
                    probs['proof-' + q] = probs.get('proof-' + q, 0) + 1
    if i != len(b):
        probs['proof-wire-length'] = 1
    res['checks'] = probs
    return res


def struct_census(bodies, P, N):
    """bodies: {txid: bytes}. Counts per type and per failed check; anomalous TXIDs by 8-char prefix only."""
    c = {'bodies': len(bodies), 'by_type': {}, 'proof_carrying': 0, 'points_checked': 0, 'scalars_checked': 0,
         'failed_checks': {}, 'txids_with_any_failure': [], 'decode_errors': 0}
    for t, b in sorted(bodies.items()):
        try:
            r = struct_tx(b, P, N)
        except (AC.DecodeError, IndexError, ValueError):
            c['decode_errors'] += 1
            continue
        c['by_type'][r['type']] = c['by_type'].get(r['type'], 0) + 1
        if r['points']:
            c['proof_carrying'] += 1
        c['points_checked'] += r['points']
        c['scalars_checked'] += r['scalars']
        for k, n in r['checks'].items():
            c['failed_checks'][k] = c['failed_checks'].get(k, 0) + n
        if r['checks']:
            c['txids_with_any_failure'].append(t[:8])
    return c


# =============================================================================================== blocks: own decode + walk
def _block_job(path):
    b = Path(path).read_bytes()
    out = {'sha256': sha(b), 'name': Path(path).name}
    try:
        d = AC.decode_block(b)
    except (AC.DecodeError, IndexError):
        out['kind'] = 'not-a-block'
        return out
    out.update({'kind': 'block', 'id': AC.sha3_256(b).hex(), 'height': d['height'], 'tips': d['tips'],
                'tx_hashes': d['tx_hashes'], 'major': d['major'], 'miniblocks': d['miniblocks'],
                'finals': d['miniblocks_final'], 'proof_field_nonzero': d['proof_field_nonzero'],
                'miner_value_field_present': d['miner_value_field_present']})
    return out


def decode_store_blocks(dirs, jobs, names=None):
    paths = []
    for d in dirs:
        for p in sorted(Path(d).iterdir()):
            if names is None or p.name in names:
                paths.append(str(p))
    rows = AC._pool_map(_block_job, paths, jobs)
    return [r for r in rows if r['kind'] == 'block']


def walk(by_id, start_id, stop_height):
    """Tips walk from start_id down to stop_height (inclusive); single-tip chain expected. {height: row}."""
    out, cur, multi = {}, by_id.get(start_id), 0
    while cur is not None and cur['height'] >= stop_height:
        if cur['height'] in out:
            raise ValueError('walk revisits a height')
        out[cur['height']] = cur
        if len(cur['tips']) != 1:
            multi += 1
        if not cur['tips']:
            break
        cur = by_id.get(cur['tips'][0])
    return out, multi


def build_plan(chain, bodies_sha, lo, hi):
    """A replay plan (tools/forensics/a2 readPlan: topo, blid, sha256, txs [[txid, body sha256]]) from the audit's
    own walk; topo == height (A5 of the v1 audit)."""
    rows = []
    for h in range(lo, hi + 1):
        r = chain[h]
        txs = []
        for t in r['tx_hashes']:
            if t not in bodies_sha:
                raise SystemExit(f'plan: no RAW body for {t[:16]} at {h}')
            txs.append([t, bodies_sha[t]])
        rows.append(json.dumps({'topo': h, 'blid': r['id'], 'sha256': r['sha256'], 'txs': txs}, separators=(',', ':')))
    return rows


# =============================================================================================== duplicate-body census
def body_copies(txids, v2rows, v2store, v1ds, archive, stage):
    """Every body copy held under each TXID, one per independent source: v2 store (the builder's chosen body), v1
    tier A raw/blobs, the archive copy's *.tx file, the fetched staging copy (as_hex). {txid: [(source, sha256, bytes)]}."""
    out = {t: [] for t in txids}
    for r in v2rows:
        if r['txid'] in out:
            p = Path(v2store) / r['sha256']
            if p.exists():
                out[r['txid']].append(('v2-store:' + r['source'].split(':')[0], r['sha256'], p.read_bytes()))
    prov = json.loads((Path(v1ds) / 'raw/provenance.json').read_text())
    for x in prov.get('tx_objects', []):
        if x.get('id') in out and x.get('class') == 'RAW':
            p = Path(v1ds) / 'raw/blobs' / x['sha256']
            if p.exists():
                b = p.read_bytes()
                out[x['id']].append(('v1-raw:' + str(x.get('source')), sha(b), b))
    if archive:
        for p in Path(archive, 'replaywall_bltx_store').rglob('*.tx'):
            t = p.name.split('.')[0]
            if t in out:
                b = p.read_bytes()
                out[t].append(('archive-copy', sha(b), b))
    # r29 (B97): --stage may name several staging dirs, colon-separated (the r26 fetch and the r29 second holders)
    for sd in stage_dirs(stage):
        for p in sorted(Path(sd, 'txs').glob('*.json')):
            try:
                r = json.loads(p.read_text())
            except ValueError:
                continue
            t = r.get('txid_requested')
            if t in out and r.get('as_hex'):
                b = bytes.fromhex(r['as_hex'])
                out[t].append(('fetched:' + str(r.get('source')), sha(b), b))
    return out


def dup_census(carriers, copies, table, txid_of=None):
    """carriers {txid: [heights]} of RAW blocks; copies from body_copies. A copy counts only when its own Keccak-256
    TXID equals the TXID (check iii by the audit). Physical copies of one object (the v2 store holding the very
    bytes it took from v1 raw/) are reported as such, not as independent agreement."""
    txid_of = txid_of or (lambda b: AC.decode_tx(b)['txid'])
    multi = sorted(t for t, hs in carriers.items() if len(hs) > 1)
    rows, cnt = [], {'multi_block_txids': len(multi), 'in_hf3_table': sum(t in table for t in multi),
                     'outside_table_dc0': sum(t not in table for t in multi), 'with_2plus_sources': 0,
                     'equal': 0, 'different': 0, 'single_source': 0, 'no_copy': 0, 'copy_txid_mismatch': 0}
    for t in multi:
        good, srcs = [], set()
        for src, h, b in copies.get(t, []):
            try:
                ok = txid_of(b) == t
            except (AC.DecodeError, IndexError):
                ok = False
            if not ok:
                cnt['copy_txid_mismatch'] += 1
                continue
            good.append((src, h))
        indep = {holder(s) for s, _ in good if not s.startswith('v2-store')}
        hashes = {h for _, h in good}
        if not good:
            st = 'no_copy'
        elif len(indep) < 2:
            st = 'single_source'
        elif len(hashes) == 1:
            st = 'equal'
        else:
            st = 'different'
        if len(indep) >= 2:
            cnt['with_2plus_sources'] += 1
        cnt[st] += 1
        rows.append({'txid': t[:8], 'carriers': len(carriers[t]), 'in_table': t in table, 'sources': sorted(indep),
                     'distinct_bodies': len(hashes), 'status': st})
    # the same comparison over every TXID with copies from >= 2 independent sources (not only multi-block ones)
    allc = {'txids_2plus_sources': 0, 'equal': 0, 'different': 0}
    for t, cs in copies.items():
        good = [(holder(s), h) for s, h, b in cs if not s.startswith('v2-store') and _txid_ok(b, t, txid_of)]
        if len({s for s, _ in good}) >= 2:
            allc['txids_2plus_sources'] += 1
            allc['equal' if len({h for _, h in good}) == 1 else 'different'] += 1
    return {'counts': cnt, 'rows': rows, 'all_txids': allc}


def holder(src):
    """The independent holder behind a copy: v1 raw/ and the fetched staging copy from the same pseudonymous source
    are ONE holder (src-N); our archive copy is another; the v2 store holds a copy of one of them."""
    if src.startswith('archive'):
        return 'archive-copy'
    return src.split(':', 1)[1] if ':' in src else src


def _txid_ok(b, t, txid_of):
    try:
        return txid_of(b) == t
    except (AC.DecodeError, IndexError):
        return False


# =============================================================================================== the rerun
def ledger_entry(repo, v):
    led = json.loads((Path(repo) / 'forensics/ledger.json').read_text())
    return next((e for e in led.get('versions', []) if e.get('version') == v), None)


def own_files(ds):
    return {str(p.relative_to(ds)): fsha(p) for p in sorted(Path(ds).rglob('*')) if p.is_file() and p.name != 'manifest.json'}


def wall4_hf3(chain, table, lo, hi):
    """Which HF3 table TXIDs the RAW blocks lo..hi carry, and the Parity the sync path's HF3 step sets for each carrier
    ((height > entry.Height) == entry.Tx_Parity, p2p/hf3_parity.go:76) against the field's zero value (false) when
    the step is skipped. The computation is the source's expression, re-evaluated from RAW heights."""
    rows = []
    for h in range(lo, hi + 1):
        for t in chain[h]['tx_hashes']:
            if t in table:
                e = table[t]
                par = (h > e['height']) == e['tx_parity']
                rows.append({'height': h, 'txid': t[:8], 'table_height': e['height'], 'tx_parity': e['tx_parity'],
                             'parity_with_step': par, 'parity_without_step': False, 'differs': par is not False})
    return rows


def hf3_source_facts(repo):
    src = (Path(repo) / 'p2p/hf3_parity.go').read_text()
    rp = (Path(repo) / 'tools/forensics/a2/replay.go').read_text()
    return {'expression_present': 't.Parity = (height > t.Height) == t.Tx_Parity' in src,
            'replay_calls_hf3_entry': 'p2p.Add_Complete_Block_HF3(chain, cbl)' in rp,
            'replay_calls_bare_add': re.search(r'chain\.Add_Complete_Block\(', rp) is not None}


def read_replay(d):
    """The audit's own node replay outputs (summary.json + roots.jsonl) or None."""
    if not d or not Path(d, 'summary.json').exists():
        return None
    s = json.loads(Path(d, 'summary.json').read_text())
    roots = {}
    rp = Path(d, 'roots.jsonl')
    if rp.exists():
        for l in rp.read_text().splitlines():
            if l.strip():
                o = json.loads(l)
                roots[o['topo']] = o
    seed = json.loads(Path(d, 'seed.json').read_text()) if Path(d, 'seed.json').exists() else {}
    return {'summary': s, 'roots': roots, 'seed': seed,
            'roots_sha256': fsha(rp) if rp.exists() else None}


def stage_dirs(stage):
    """r30 merge (operator trap, v5 run 1): the colon-separated --stage dirs, each an existing directory with a txs/
    subdir. FAILS CLOSED (ValueError) on an unexpanded '~' (bash does not expand '~' after a colon: 'A:~/x' reached
    here as a literal and the stage was skipped silently, a false D2-29 FAIL) and on a missing dir or txs/. Pure but for
    the stat calls."""
    out = []
    for sd in (stage.split(':') if stage else []):
        if not sd:
            continue
        if sd.startswith('~'):
            raise ValueError(f'--stage {sd!r}: unexpanded ~ (write an absolute path)')
        if not Path(sd, 'txs').is_dir():
            raise ValueError(f'--stage {sd!r}: no such stage dir (or no txs/ in it)')
        out.append(sd)
    return out


def run(ds, repo, v1store, v2store, archive, stage, replay_dir, private, jobs):
    ds, repo = Path(ds), Path(repo)
    R = {'impl': IMPL_VERSION, 'dataset': ds.name}
    try:
        sds = stage_dirs(stage)
    except ValueError as e:
        R['result'] = f'FAIL: {e}'
        return R
    for p in (v1store, v2store, archive, replay_dir, *sds):   # r29: every stage dir
        guard(p)
    st = AC.hash_selftest() + selftest_struct(repo)
    R['selftest'] = {'failures': st, 'hash_kats': len(AC.KAT)}
    if st:
        R['result'] = 'FAIL: selftest'
        return R
    # ---------------------------------------------------------------- D2-01/02/03 binding, files, v1 inputs
    mb = (ds / 'manifest.json').read_bytes()
    man = json.loads(mb)
    le = ledger_entry(repo, ds.name) or {}
    files = own_files(ds)
    R['binding'] = dict(AC.binding_of(man), manifest_sha256_at_audit=sha(mb))
    R['ledger'] = {'entry_sha256': le.get('manifest_sha256'), 'manifest_sha256': sha(mb),
                   'equal': le.get('manifest_sha256') == sha(mb), 'sealed': bool(le.get('sealed'))}
    mf = man.get('files', {})
    R['files'] = {'listed': len(mf), 'on_disk': len(files),
                  'mismatch': sorted(k for k in mf if k in files and files[k] != mf[k] and not k.startswith('audit/')),
                  'missing': sorted(k for k in mf if k not in files),
                  'unlisted': sorted(k for k in files if k not in mf and not k.startswith('audit/')),
                  'class_files_listed': all(k in mf for k in man.get('class_files', {}))}
    R['inputs'] = {'pinned': len(man.get('inputs', {})),
                   'changed': sorted(k for k, h in man.get('inputs', {}).items() if not (repo / k).exists() or fsha(repo / k) != h)}
    v1e = ledger_entry(repo, 'r25') or {}
    R['v1'] = {'sealed': bool(v1e.get('sealed')), 'manifest_equal': fsha(repo / V1 / 'manifest.json') == v1e.get('manifest_sha256')}
    # ---------------------------------------------------------------- blocks: own decode + walk
    anchors = json.loads((repo / V1 / 'raw/anchors.json').read_text())
    anchor = next(a for a in anchors if a.get('kind') == 'block')
    v1blocks = decode_store_blocks([v1store], jobs)
    w1rows = jgz(ds / 'raw/wall1_blocks.jsonl.gz')
    v2blocks = decode_store_blocks([v2store], jobs, names={r['sha256'] for r in w1rows})
    by_id = {}
    for r in v1blocks + v2blocks:
        by_id.setdefault(r['id'], r)
    chain, multi = walk(by_id, anchor['id'], WALL1_LINK[0])
    hs = sorted(chain)
    R['walk'] = {'anchor_height': anchor['height'], 'from': hs[-1] if hs else None, 'to': hs[0] if hs else None,
                 'blocks': len(chain), 'contiguous': hs == list(range(hs[0], hs[-1] + 1)) if hs else False,
                 'multi_tip': multi, 'v1_store_blocks': len(v1blocks), 'v2_store_blocks': len(v2blocks)}
    w1 = {'rows': len(w1rows), 'equal': 0, 'differ': []}
    for r in w1rows:
        o = chain.get(r['height'])
        if o and o['id'] == r['blid'] and o['sha256'] == r['sha256'] and o['tips'] == r['tips'] and o['tx_hashes'] == r['tx_hashes']:
            w1['equal'] += 1
        else:
            w1['differ'].append(r['height'])
    R['wall1_blocks'] = w1
    # ---------------------------------------------------------------- txs needed (own) and bodies
    carriers = {}
    for h in range(WINDOW[0], anchor['height'] + 1):
        for t in chain[h]['tx_hashes']:
            carriers.setdefault(t, []).append(h)
    w1need = {}
    for h in range(WALLS['wall1'] - 5, WALLS['wall1'] + 6):
        for t in chain[h]['tx_hashes']:
            w1need.setdefault(t, []).append(h)
    v2rows = jgz(ds / 'raw/tx_bodies.jsonl.gz')
    bodies, bad = {}, {'blob_missing': 0, 'sha_mismatch': 0, 'decode_error': 0, 'txid_mismatch': 0, 'not_carried': 0}
    for r in v2rows:
        p = Path(v2store) / r['sha256']
        if not p.exists():
            bad['blob_missing'] += 1
            continue
        b = p.read_bytes()
        if sha(b) != r['sha256']:
            bad['sha_mismatch'] += 1
            continue
        try:
            d = AC.decode_tx(b)
        except (AC.DecodeError, IndexError):
            bad['decode_error'] += 1
            continue
        if d['txid'] != r['txid']:
            bad['txid_mismatch'] += 1
            continue
        if r['txid'] not in carriers and r['txid'] not in w1need:
            bad['not_carried'] += 1
        bodies[r['txid']] = b
    need = set(carriers) | set(w1need)
    R['bodies'] = dict(bad, rows=len(v2rows), verified=len(bodies), needed_own=len(need),
                       needed_window_gap=len(carriers), needed_wall1=len(w1need),
                       missing_own=len(need - set(bodies)), extra=len(set(bodies) - need),
                       missing_json=json.loads((ds / 'raw/missing_txs.json').read_text()).get('missing_count'))
    dec = {t: AC.decode_tx(b) for t, b in bodies.items()}
    # ---------------------------------------------------------------- D2-06 tx rows vs claims
    txc = {r['txid']: r for r in jgz(ds / 'derived/txs.jsonl.gz')}
    tm = {'rows': len(txc), 'equal': 0, 'differ': [], 'fields': ['tx_type', 'fee', 'burn_total', 'ring sizes', 'roothash',
                                                                  'ref_height', 'ref_blid', 'has_scdata', 'body_sha256']}
    for t, d in sorted(dec.items()):
        c = txc.get(t)
        mine = {'tx_type': AC.TXTYPES[d['type']], 'fee': d['fees_total'], 'burn_total': d['burn_total'],
                'rings': [p['ring'] for p in d['payloads']], 'roothash': [p['roothash'] for p in d['payloads']],
                'ref_height': d.get('height', 0), 'ref_blid': d.get('blid', '0' * 64), 'has_scdata': bool(d.get('scdata_len')),
                'body_sha256': sha(bodies[t])}
        if c is None:
            tm['differ'].append(t[:8])
            continue
        theirs = {'tx_type': c.get('tx_type'), 'fee': c.get('fee'), 'burn_total': c.get('burn_total'),
                  'rings': [p.get('ring_size', p.get('ring')) for p in c.get('payloads', [])],
                  'roothash': [p.get('roothash') for p in c.get('payloads', [])],
                  'ref_height': c.get('ref_height'), 'ref_blid': c.get('ref_blid'), 'has_scdata': c.get('has_scdata'),
                  'body_sha256': c.get('body_sha256')}
        if mine == theirs:
            tm['equal'] += 1
        else:
            tm['differ'].append(t[:8])
            tm.setdefault('first_diff_fields', sorted(k for k in mine if mine[k] != theirs[k]))
    tm['differ_count'] = len(tm['differ'])
    tm['differ'] = tm['differ'][:20]
    R['txrows'] = tm
    # ---------------------------------------------------------------- D2-07/08/09 fees, burns, SC counts
    v1win = {r['height']: r for r in jgz(repo / V1 / 'derived/window.jsonl.gz')}
    v1pending = {h for h, r in v1win.items() if not isinstance(r.get('fees'), int)}
    bf = {r['height']: r for r in jgz(ds / 'derived/blocks_fees.jsonl.gz')}
    fz = {'blocks_claimed': len(bf), 'equal': 0, 'differ': []}
    sums = {'window_fee_sum': 0, 'window_burn_sum': 0, 'window_txblocks': 0, 'gap_fee_sum': 0, 'gap_burn_sum': 0,
            'gap_txblocks': 0, 'sc_txs': 0, 'sc_tx_blocks': 0, 'settled': 0, 'settled_fee_sum': 0, 'settled_burn_sum': 0,
            'v1_known_rows_disagreeing': 0}
    for h in range(WINDOW[0], anchor['height'] + 1):
        tx = chain[h]['tx_hashes']
        if not tx:
            continue
        if any(t not in dec for t in tx):
            fz['differ'].append(h)
            continue
        fee = sum(dec[t]['fees_total'] for t in tx)
        burn = sum(dec[t]['burn_total'] for t in tx)
        nsc = sum(dec[t]['type'] == AC.SC_TX for t in tx)
        c = bf.get(h, {})
        if c.get('fees') == fee and c.get('public_burns') == burn and c.get('tx_count') == len(tx) and c.get('sc_txs') == nsc:
            fz['equal'] += 1
        else:
            fz['differ'].append(h)
        pre = 'window' if h <= WINDOW[1] else 'gap'
        sums[pre + '_fee_sum'] += fee
        sums[pre + '_burn_sum'] += burn
        sums[pre + '_txblocks'] += 1
        sums['sc_txs'] += nsc
        sums['sc_tx_blocks'] += nsc > 0
        if h in v1pending:
            sums['settled'] += 1
            sums['settled_fee_sum'] += fee
            sums['settled_burn_sum'] += burn
        elif h in v1win and v1win[h].get('fees') != fee:
            sums['v1_known_rows_disagreeing'] += 1
    fz['differ_count'] = len(fz['differ'])
    fz['differ'] = fz['differ'][:20]
    fz['own'] = sums
    fz['v1_pending'] = len(v1pending)
    fj = json.loads((ds / 'derived/fees.json').read_text())
    fz['claimed'] = {k: fj.get('v2', {}).get(k) for k in sums if k in fj.get('v2', {})}
    fz['claimed']['v1_known_rows_disagreeing'] = len(fj.get('v1_known_rows_disagreeing', []))
    fz['totals_equal'] = all(fz['claimed'].get(k) == v for k, v in sums.items() if k in fz['claimed'])
    fz['sc_payouts_claim'] = str(fj.get('sc_payouts'))[:60]
    R['fees'] = fz
    # ---------------------------------------------------------------- D2-11 duplicate-body census
    table = AC.parse_hf3((repo / 'blockchain/hardfork_fixes.go').read_text())
    allcar = dict(carriers)
    for h in range(WALL1_LINK[0], WINDOW[0]):
        for t in chain[h]['tx_hashes']:
            allcar.setdefault(t, []).append(h)
    for t in allcar:
        allcar[t] = sorted(set(allcar[t]))
    copies = body_copies(set(allcar), v2rows, v2store, repo / V1, archive, stage)
    dc = dup_census(allcar, copies, table)
    dc['scope'] = [WALL1_LINK[0], anchor['height']]
    dc['tx_lists_with_a_repeated_txid'] = sum(len(r['tx_hashes']) != len(set(r['tx_hashes'])) for r in chain.values())
    dc['observability'] = ('a block commits to the TXID only; the TXID is Keccak-256 of the core statement, which '
                           'excludes the proofs (audit decoder: core_len < body length for every proof-carrying body), '
                           'so the RAW blocks cannot show which body a carrier held; bodies are compared across '
                           'independent holders instead')
    dc['core_excludes_proof_bodies'] = sum(d['core_len'] < len(bodies[t]) for t, d in dec.items()
                                           if d['type'] in (AC.NORMAL, AC.BURN_TX, AC.SC_TX))
    R['dup'] = dc
    # ---------------------------------------------------------------- D2-12 structural verifier (B97)
    P, N = bn256_constants(repo)
    R['struct'] = struct_census(bodies, P, N)
    R['struct']['constants_from'] = 'cryptography/bn256/constants.go (P, Order)'
    # ---------------------------------------------------------------- D2-13/14 replay runs and wall 4
    seed = json.loads((ds / 'raw/archive_seed.json').read_text())
    arch_roots = {r['topo']: r['root'] for r in jgz(repo / V1 / 'derived/archive_state/roots.jsonl.gz')}
    runs = {}
    for d in sorted((ds / 'raw/replay_runs').iterdir()):
        rr = jgz(d / 'roots.jsonl.gz')
        s = json.loads((d / 'summary.json').read_text())
        runs[d.name] = {'roots_sha256': fsha(d / 'roots.jsonl.gz'), 'lines': len(rr),
                        # R28 (v3): the entry point the run used, and its roots as plain JSON lines (comparable with the
                        # audit's own replay output byte for byte)
                        'entry': s.get('entry', PRE_FIX_ENTRY), 'stopped': s.get('stopped'),
                        'roots_jsonl_sha256': sha(gzip.decompress((d / 'roots.jsonl.gz').read_bytes())),
                        'fail_topo': s.get('fail_topo'), 'last_topo': s.get('last_topo'),
                        'base_eq_archive': any(o['topo'] == seed['top_topo'] and o.get('root') == arch_roots.get(seed['top_topo']) for o in rr),
                        'blids_eq_walk': all(chain.get(o['topo'], {}).get('id') == o.get('blid') for o in rr if o['topo'] > seed['top_topo'])}
    rj = json.loads((ds / 'raw/replay_runs/A/rejection.json').read_text())
    by_entry = {}
    for r in runs.values():
        by_entry.setdefault(r['entry'], set()).add(r['roots_sha256'])
    R['runs'] = {'runs': runs, 'identical': all(len(v) == 1 for v in by_entry.values()),
                 'entries': sorted(by_entry), 'hf3_entry_runs': sorted(n for n, r in runs.items() if r['entry'] == HF3_ENTRY),
                 'seed_top_root_eq_v1_archive_root': seed.get('top_root') == arch_roots.get(seed['top_topo']),
                 'seed_top_blid_eq_walk': chain.get(seed['top_topo'], {}).get('id') == seed.get('top_blid'),
                 'rejection_txid_in_table': rj.get('txid') in table,
                 'rejection_txid_carried_at': allcar.get(rj.get('txid')),
                 'rejection_topo': rj.get('topo')}
    lo = seed['top_topo'] + 1
    R['wall4'] = {'hf3_carriers_before_stop': wall4_hf3(chain, table, lo, WALLS['wall4']),
                  'source': hf3_source_facts(repo)}
    R['wall4']['differs'] = sum(r['differs'] for r in R['wall4']['hf3_carriers_before_stop'])
    th = (repo / TREEHASH_SOURCE[0]).read_text().splitlines()[TREEHASH_SOURCE[1] - 1]
    m = re.search(r'topoheight=(\d+) .*treehash=([0-9a-f]{64})', th)
    ours = {'topo': int(m.group(1)), 'root': m.group(2)} if m else {}
    R['treehash_recorded'] = dict(ours, source=f'{TREEHASH_SOURCE[0]}:{TREEHASH_SOURCE[1]}')
    own = read_replay(replay_dir)
    if own:
        s, roots = own['summary'], own['roots']
        top = max(roots) if roots else None
        walls = {k: (v in roots and roots[v].get('blid') == chain.get(v, {}).get('id')) for k, v in WALLS.items() if v >= lo}
        wit = {'equal': 0, 'differ': 0, 'outside': 0}
        for t, d in dec.items():
            for p in d['payloads'][:1]:
                ref = d.get('height')
                if ref is not None and ref in roots:
                    wit['equal' if roots[ref].get('root') == p['roothash'] else 'differ'] += 1
                else:
                    wit['outside'] += 1
        R['own_replay'] = {'stopped': s.get('stopped'), 'added': s.get('added'), 'txs': s.get('txs'),
                           'last_topo': s.get('last_topo'), 'last_root': s.get('last_root'),
                           'end_eq_recorded_treehash': s.get('last_topo') == ours.get('topo') and s.get('last_root') == ours.get('root'),
                           'roots_lines': len(roots), 'roots_top': top, 'roots_sha256': own['roots_sha256'],
                           'walls_accepted': walls, 'witnesses': wit,
                           'blids_eq_walk': all(chain.get(k, {}).get('id') == v.get('blid') for k, v in roots.items() if k > seed['top_topo']),
                           'seed_top_root': own['seed'].get('top_root'),
                           'seed_eq_dataset_seed': own['seed'].get('top_root') == seed.get('top_root'),
                           'a2_binary_sha256': s.get('a2_binary_sha256')}
    else:
        R['own_replay'] = None
    # ---------------------------------------------------------------- D2-15 state roots / A10c claims
    sr = json.loads((ds / 'derived/state_roots.json').read_text())
    R['state_roots_claim'] = {'end_state_check_A': sr['runs']['A'].get('end_state_check'),
                              'a10c_answer': sr.get('a10c', {}).get('answer'),
                              'witness_claim': {k: sr['roothash_witnesses'].get(k) for k in ('equal', 'differ', 'archive_equal', 'archive_differ')}}
    wa = {'archive_equal': 0, 'archive_differ': 0}
    for t, d in dec.items():
        ref = d.get('height')
        if d['payloads'] and ref in arch_roots:
            wa['archive_equal' if arch_roots[ref] == d['payloads'][0]['roothash'] else 'archive_differ'] += 1
    R['state_roots_own'] = wa
    summ = json.loads((ds / 'derived/summary.json').read_text())
    R['summary_claim'] = {k: summ.get(k) for k in ('tx_bodies_raw', 'txs_decoded', 'txblocks', 'records_with_class_slot',
                                                   'v1_pending_settled', 'tx_bodies_missing')}
    # ---------------------------------------------------------------- D2-16..20 classes outputs
    R['classes'] = audit_classes(ds, repo, chain, table, carriers, sums, v1pending)
    # ---------------------------------------------------------------- D2-21 content scan + a2 hygiene
    terms = AC.load_private_terms(private if private is not None else os.environ.get(
        'FORENSICS_PRIVATE', str(Path.home() / 'derohe-persist' / 'forensics_private')))
    sc = AC.scan_dataset(ds, repo, terms, skip_prefix='audit/')
    R['scan'] = {'files_scanned': sc['files_scanned'], 'hits': sc['hits'], 'patterns': sc['patterns'],
                 'private_terms_loaded': sc['private_terms_loaded']}
    a2 = json.loads((ds / 'derived/a2.json').read_text())
    R['a2'] = {'class': a2.get('class'), 'verdict_head': str(a2.get('verdict'))[:40]}
    # ---------------------------------------------------------------- r28d D2-26/D2-27 the DC1 structure (v4, B180)
    if (ds / 'derived/dc1_structure.json').exists():
        R['dc1_structure'] = audit_dc1_structure(ds, repo, table, carriers, dec)
    # ---------------------------------------------------------------- r29 D2-28 walls/inclusions row classes (B107)
    if 'class_rules' in json.loads((ds / 'derived/walls.json').read_text()):
        R['row_classes'] = audit_row_classes(ds, chain, table, carriers)
    # ---------------------------------------------------------------- r30 D2-29..D2-34 dataset v5 (B202, B203, B209, B210, B111, B107)
    if (ds / 'derived/dc2_den.json').exists():
        R['v5'] = audit_v5(ds, repo, R['dup']['counts'], table)
    R['result'] = 'done'
    return R


V5_PROOF_TYPES = {'NORMAL', 'SC', 'BURN'}     # own reading of transaction/transaction.go:33-38: types carrying payload proofs


def _own_checkpoint(path):
    """the auditor's own reader of the B182 checkpoint (own CRC check; never the builder's unseal). (records, sha256)"""
    import zlib
    recs, h = [], hashlib.sha256()
    with open(path, 'rb') as fh:
        for raw in fh:
            h.update(raw)
            ln = raw.decode()
            if not ln.endswith('\n') or ln[8:9] != ' ' or f'{zlib.crc32(ln[9:-1].encode()):08x}' != ln[:8]:
                break
            recs.append(json.loads(ln[9:-1]))
    return recs, h.hexdigest()


def audit_v5(ds, repo, dup_counts, table, checkpoint=None):
    """r30: dataset v5 re-checked by the auditor's own code (refute by default). Every figure is recomputed from the raw
    records (census JSONs, the checkpoint, the holders census, inclusions) and only then compared with the builder's."""
    ds, repo = Path(ds), Path(repo)
    cl = json.loads((ds / 'derived/classes.json').read_text())
    fq = json.loads((ds / 'derived/fq.json').read_text())
    figs = {f['id']: f for f in cl.get('figures', [])}
    out = {}
    # D2-29 two bodies: own value/den from the audit's own duplicate census (D2-11) and own multi-block count
    tb = figs.get('dc1-two-bodies') or {}
    c = tb.get('coverage') or {}
    out['two_bodies'] = {'own_different': dup_counts.get('different'), 'own_multi': dup_counts.get('multi_block_txids'),
                         'own_2plus': dup_counts.get('with_2plus_sources'), 'claimed_value': tb.get('value'),
                         'claimed_num': c.get('num'), 'claimed_den': c.get('den'), 'claimed_bound': tb.get('bound_type')}
    t = out['two_bodies']
    t['holds'] = (t['claimed_value'] == t['own_different'] and t['claimed_den'] == t['own_multi'] and
                  t['claimed_num'] == t['own_2plus'] and t['claimed_bound'] == 'lower-bound')
    # D2-30 DC2 denominator: own sum of the census records' proof-carrying types + own window count from txs.jsonl
    d2 = figs.get('dc2-created-value') or {}
    den_rec = json.loads((ds / 'derived/dc2_den.json').read_text())
    own = 0
    rr = lambda rel: json.loads((repo / rel).read_text())
    try:
        deep, fetch, off = (rr('harness/runtime/r29_b182_deep_census.json'), rr('harness/runtime/r29_b182_fetch_census.json'),
                            rr('harness/runtime/r29_b182_offline_census.json'))
        for ty in (deep['types'], fetch['fetched_below_7412665']['types'], fetch['wall1_7412665_7415463']['types'],
                   fetch['gap_7415464_7415465']['types'], off['gap_7497943_7498539']['types']):
            own += sum(v for k, v in ty.items() if k in V5_PROOF_TYPES)
        rows = [json.loads(l) for l in gzip.decompress((ds / 'derived/txs.jsonl.gz').read_bytes()).decode().splitlines() if l.strip()]
        win = [r for r in rows if r.get('tx_type') in V5_PROOF_TYPES and WINDOW[0] <= r['carrier_height'] <= WINDOW[1]]
        own += len(win)
        census_ok = True
    except (OSError, KeyError, ValueError):
        census_ok = False
    claimed_den = (d2.get('coverage') or {}).get('den')
    over = den_rec.get('overlap_txids_counted_twice')
    out['dc2_den'] = {'own_sum': own, 'claimed_sum': den_rec.get('sum_of_segments'), 'claimed_den': claimed_den,
                      'overlap': over, 'value': d2.get('value'), 'bound': d2.get('bound_type'), 'census_read': census_ok,
                      'registration_counted': 'REGISTRATION' in (den_rec.get('proof_types') or [])}
    x = out['dc2_den']
    x['holds'] = (census_ok and own == x['claimed_sum'] and isinstance(over, int) and claimed_den == own - over
                  and x['value'] == 'unbounded' and x['bound'] == 'unbounded' and not x['registration_counted'])
    # D2-31..D2-32 claim grant and DC0 below the window: own pass over the checkpoint (UNRESOLVED when it is not here)
    ckp = Path(checkpoint) if checkpoint else Path(os.environ.get('FORENSICS_R29_DEEP', str(Path.home() / 'derohe-persist/forensics_raw_r29/deep'))) / 'checkpoint.log'
    cg = json.loads((ds / 'derived/claim_grant.json').read_text())
    dg = json.loads((ds / 'derived/dc0_genesis.json').read_text())
    if ckp.exists():
        recs, csha = _own_checkpoint(ckp)
        bs = [r for r in recs if r.get('kind') == 'batch']
        reg = sum(r['types'].get('REGISTRATION', 0) for r in bs if r['hi'] < 144000)
        sup = (repo / 'blockchain/supply.go').read_text()
        m = re.search(r'there were (\d+) such accounts, so total of (\d+)', sup)
        reps = collections.Counter(t for r in bs for t in (r.get('dup_txids') or []))
        lt3_hi = max((r['hi'] for r in bs if r.get('reg_lt3')), default=-1)
        out['claim_grant'] = {'own_reg': reg, 'supply_accounts': int(m.group(1)) if m else None,
                              'supply_total': int(m.group(2)) if m else None, 'claimed_reg': cg.get('registrations_below_144000'),
                              'claimed_value': cg.get('value_atomic'), 'checkpoint_sha_equal': csha == cg['input']['sha256']}
        g = out['claim_grant']
        g['holds'] = (g['checkpoint_sha_equal'] and reg == g['claimed_reg'] == g['supply_accounts']
                      and g['claimed_value'] == reg * 200 == g['supply_total'])
        out['dc0_genesis'] = {'own_distinct': len(reps), 'own_in_table': sum(1 for t in reps if t in table),
                              'claimed_dc0': (dg['census'].get('by_class') or {}).get('DC0'),
                              'claimed_figure': (figs.get('dc0-genesis-listed-twice') or {}).get('value'),
                              'reg_lt3_last_hi': lt3_hi, 'reg_lt3_within_0_156599': 0 <= lt3_hi <= 156599,
                              'checkpoint_sha_equal': csha == dg['input']['sha256']}
        z = out['dc0_genesis']
        z['holds'] = (z['checkpoint_sha_equal'] and z['own_distinct'] - z['own_in_table'] == z['claimed_dc0'] == z['claimed_figure']
                      and z['reg_lt3_within_0_156599'])
    else:
        out['claim_grant'] = {'unresolved': 'checkpoint not on this machine'}
        out['dc0_genesis'] = {'unresolved': 'checkpoint not on this machine'}
    # D2-33 content consistency (B107): classes.json is this version's own file and agrees with fq.json
    srt = 'S-RT' in ((fq.get('FQ2') or {}).get('criteria') or {})
    note = str((figs.get('dc1-obs-coverage') or {}).get('note', ''))
    out['consistency'] = {'dataset_label': cl.get('dataset'), 'fq_srt': srt, 'note_names_srt': 'S-RT' in note,
                          'note_held_bodies_only': 'held bodies only' in note,
                          'fq1_two_bodies_equal': (fq.get('FQ1') or {}).get('answer', {}).get('two_bodies_under_one_txid', '')[:12]
                          == f"lower bound {t['claimed_value']}"[:12],
                          'dc1_obs': ((fq.get('FQ2') or {}).get('coverage') or {}).get('dc1_obs')}
    k = out['consistency']
    k['holds'] = (k['dataset_label'] == ds.name and k['fq_srt'] == k['note_names_srt'] and not k['note_held_bodies_only']
                  and k['fq1_two_bodies_equal'] and k['dc1_obs'] == (figs.get('dc1-obs-coverage') or {}).get('value'))
    # D2-34 B111 premine: own residual arithmetic; the record must stay a HYPOTHESIS until the set diff exists
    bp = json.loads((ds / 'derived/b111_premine.json').read_text())
    keys = (bp.get('balance_tree_keys') or {}).get('7498540')
    out['b111'] = {'own_residual_no_premine': (keys - bp['registrations_through_7498539']) if isinstance(keys, int) else None,
                   'status': bp.get('status'), 'premine_keys': bp.get('premine_keys')}
    b = out['b111']
    b['holds'] = b['own_residual_no_premine'] == b['premine_keys'] == 1 and str(b['status']).startswith('HYPOTHESIS')
    return out


def audit_row_classes(ds, chain, table, carriers):
    """R29 B107: the class of every walls.json row, replay_stops and every inclusions.json row, derived from the
    audit's OWN walk (the block's own tx list against the own HF3 parse) and own carrier census, never from the row's
    fields; then the builder's classes are read as CLAIMS. Rules = v4.TAG_RULES, re-implemented here."""
    w = json.loads((ds / 'derived/walls.json').read_text())
    inc = json.loads((ds / 'derived/inclusions.json').read_text())
    out = {'wall_rows': 0, 'wall_equal': 0, 'wall_differ': [], 'wall_unwalked': 0, 'stops_equal': False,
           'inclusion_rows': 0, 'inclusion_equal': 0, 'inclusion_differ': [], 'own_multi': 0, 'rows_txids_eq_own_multi': False,
           'file_class_equal': False, 'pending': 0}
    for k in sorted(k for k in w if k.startswith('wall')):
        for r in w[k].get('rows') or []:
            out['wall_rows'] += 1
            out['pending'] += r.get('class') not in ('DC0', 'DC1', 'DC2', 'DC3')
            o = chain.get(r.get('height'))
            if not o or o['id'] != r.get('blid'):
                out['wall_unwalked'] += 1
                continue
            own = 'DC1' if any(t in table for t in o['tx_hashes']) else 'DC3'
            if r.get('class') == own:
                out['wall_equal'] += 1
            else:
                out['wall_differ'].append(r.get('height'))
    st = w.get('replay_stops') or {}
    own = 'DC1' if any((x or {}).get('txid') in table for x in (st.get('runs') or {}).values()) else 'DC3'
    out['stops_equal'] = st.get('class') == own
    out['pending'] += st.get('class') not in ('DC0', 'DC1', 'DC2', 'DC3')
    multi = {t for t, hs in carriers.items() if len(hs) > 1}
    out['own_multi'] = len(multi)
    rows = inc.get('rows') or []
    out['rows_txids_eq_own_multi'] = {r.get('txid') for r in rows} == multi
    owns = []
    for r in rows:
        out['inclusion_rows'] += 1
        out['pending'] += r.get('class') not in ('DC0', 'DC1', 'DC2', 'DC3')
        own = 'DC1' if r.get('txid') in table else 'DC0'
        owns.append(own)
        if r.get('class') == own:
            out['inclusion_equal'] += 1
        else:
            out['inclusion_differ'].append(str(r.get('txid'))[:8])
    out['file_class_equal'] = inc.get('class') == ('DC0' if 'DC0' in owns else 'DC1')
    out['own_classes'] = {c: owns.count(c) for c in sorted(set(owns))}
    return out


def fq_rest_v5(fq, base):
    """r30 (v5, B202/B209): fq.json is RE-DERIVED by classes_r30 (B107), which answers FQ1 two-bodies (B202), adds the
    DC0-genesis count (B209), one anchor (the holders census) and its schema label. Exactly those fields are taken out
    of the rest-equality (restored to the base's values) and returned as v5 claims: D2-27 then requires the anchor list
    to be the base list plus that ONE anchor and the DC0 count to equal the audit's own recount (D2-32); the two-bodies
    text is D2-33's. A pre-v5 fq.json (no schema_r30) is compared as before. (rest less FQ2, v5 changes or None). Pure."""
    rest = {k: v for k, v in fq.items() if k not in ('FQ2', 'schema_r30')}
    if 'schema_r30' not in fq:
        return {k: v for k, v in fq.items() if k != 'FQ2'}, None
    fq1, b1 = dict(fq.get('FQ1') or {}), base.get('FQ1') or {}
    ans = dict(fq1.get('answer') or {})
    v5c = {'anchors_extra': [a for a in fq1.get('anchors', []) if a not in (b1.get('anchors') or [])],
           'anchors_prefix': fq1.get('anchors', [])[:len(b1.get('anchors') or [])] == (b1.get('anchors') or []),
           'dc0_genesis_listed_twice': ans.pop('dc0_genesis_listed_twice', None),
           'two_bodies': ans.get('two_bodies_under_one_txid')}
    ans['two_bodies_under_one_txid'] = (b1.get('answer') or {}).get('two_bodies_under_one_txid')
    rest['FQ1'] = dict(fq1, answer=ans, anchors=b1.get('anchors'), status=b1.get('status'))
    return rest, v5c


def fq_rest_equal(fq, base, q, qb):
    """D2-27's rest-equality: fq.json less FQ2 equals the base's (less the v5 FQ1 additions, fq_rest_v5), and FQ2 is
    the base's plus S-RT and its correction (q, qb: FQ2 with those taken out). v5 builds on r28d, whose FQ2 already
    carries S-RT and the correction, so v5's FQ2 must equal the base's whole. (equal, v5 changes or None). Pure."""
    rest, v5c = fq_rest_v5(fq, base)
    fq2_equal = (fq.get('FQ2') == base.get('FQ2')) if v5c is not None else (q == qb)
    return rest == {k: v for k, v in base.items() if k != 'FQ2'} and fq2_equal, v5c


def v5_fq_ok(c, v5):
    """r30 (v5): the FQ1 fields classes_r30 adds are exactly one appended anchor (the holders census) and a DC0-genesis
    count equal to the audit's own recount (D2-32 own_distinct - own_in_table). None (a pre-v5 fq.json) is fine. Pure."""
    if c is None:
        return True
    z = (v5 or {}).get('dc0_genesis') or {}
    own = (z['own_distinct'] - z['own_in_table']) if 'own_distinct' in z else None
    return (c['anchors_prefix'] and len(c['anchors_extra']) == 1 and 'r29_b97_holders.json' in c['anchors_extra'][0]
            and own is not None and c['dc0_genesis_listed_twice'] == own)


def v5_fq_text(c, v5):
    z = (v5 or {}).get('dc0_genesis') or {}
    own = (z['own_distinct'] - z['own_in_table']) if 'own_distinct' in z else 'unresolved'
    return f"anchor +{len(c['anchors_extra'])} (prefix {c['anchors_prefix']}), DC0 genesis {c['dc0_genesis_listed_twice']} vs own {own}"


def audit_dc1_structure(ds, repo, table, carriers, dec):
    """r28d (v4, rft §7 B180): the DC1 structural census recounted from the audit's OWN parts only: the DC1 set is the
    audit's own HF3 table parse, the one/two-carrier split its own walk, ring size and payload format its own wire
    decoder of the held bodies; then the builder's derived/dc1_structure.json and the FQ2 correction are read as CLAIMS.
    Counts only (no amount, address or TXID leaves this function)."""
    own, n2, decoded = {}, 0, 0
    for t in sorted(table):
        two = len(carriers.get(t, [])) > 1
        n2 += two
        d = dec.get(t)
        if d is None:
            continue
        decoded += 1
        rings = sorted({p['ring'] for p in d['payloads']})
        fmts = sorted({p['rpc_type'] for p in d['payloads']})
        key = '+'.join([f'ring{x}' for x in rings] + [f'rpctype{x}' for x in fmts])
        g = 'two_inclusions' if two else 'single_inclusion'
        for k in (key, f'{g}:{key}'):
            own[k] = own.get(k, 0) + 1
        if rings == [2] and fmts == [0]:
            for k in ('criterion', f'criterion:{g}'):
                own[k] = own.get(k, 0) + 1
    claim = json.loads((ds / 'derived/dc1_structure.json').read_text())
    fq = json.loads((ds / 'derived/fq.json').read_text())
    sup = (json.loads((ds / 'manifest.json').read_text()).get('supersedes') or [None])[0]
    base = json.loads((Path(repo) / 'forensics' / sup / 'derived/fq.json').read_text()) if sup else {}
    q, qb = dict(fq.get('FQ2', {})), dict(base.get('FQ2', {}))
    srt = (q.get('criteria') or {}).get('S-RT') or {}
    q['criteria'] = {k: v for k, v in (q.get('criteria') or {}).items() if k != 'S-RT'}
    q.pop('corrections', None)
    rest_equal, v5c = fq_rest_equal(fq, base, q, qb)   # r30 (v5): only the classes_r30 FQ1 additions differ (D2-27)
    want = f"{own.get('criterion', 0)} of {len(table)}"
    return {'dc1_table': len(table), 'decoded_own': decoded, 'two_carriers_own': n2, 'own_counts': dict(sorted(own.items())),
            'claimed_counts': claim.get('counts'), 'counts_equal': claim.get('counts') == dict(sorted(own.items())),
            'claimed_coverage': claim.get('coverage'), 'class': claim.get('class'),
            'fq2_srt_result': srt.get('result'), 'fq2_srt_agrees': str(srt.get('result', '')).startswith(want + ' '),
            'fq2_dc1_obs': (fq.get('FQ2', {}).get('coverage') or {}).get('dc1_obs'),
            'fq2_dc1_obs_base': (qb.get('coverage') or {}).get('dc1_obs'),
            'fq2_corrections': len(fq.get('FQ2', {}).get('corrections') or []),
            'fq_rest_equal_base': rest_equal, 'base': sup, 'fq_v5_changes': v5c}


# =============================================================================================== classes re-audit
FORBIDDEN_PHRASES = ('supply audit', 'audited supply', 'total inflation', 'true supply')


def anchor_reread(repo, rev, f, line, quote):
    """The text of file:line at rev (git show; rev HEAD = the working tree) contains quote."""
    if rev == 'HEAD':
        p = Path(repo) / f
        lines = p.read_text().splitlines() if p.exists() else []
    else:
        r = subprocess.run(['git', '-C', str(repo), 'show', f'{rev}:{f}'], capture_output=True, text=True)
        if r.returncode:
            return None
        lines = r.stdout.splitlines()
    return bool(line and line <= len(lines) and quote in lines[line - 1])


def g31_problems(figures):
    """G31 bound honesty re-checked by the audit's own rules (rft §0.8.9 rules 9-10), independent of bounds.py."""
    probs = []
    for f in figures:
        fid = f.get('id')
        for k in ('class', 'scope', 'coverage', 'bound_type'):
            if k not in f:
                probs.append(f'{fid}: no {k}')
        bt, cov = f.get('bound_type'), f.get('coverage', {})
        if bt not in ('exact', 'lower-bound', 'upper-bound', 'unbounded'):
            probs.append(f'{fid}: bound_type {bt}')
        if bt == 'exact' and not (isinstance(cov.get('num'), int) and cov.get('num') == cov.get('den')):
            probs.append(f'{fid}: exact without full coverage')
        if bt == 'unbounded' and f.get('value') in (0, '0', '', None):
            probs.append(f'{fid}: unbounded rendered as 0/empty')
        if f.get('class') == 'DC2' and f.get('value') in (0, '0'):
            probs.append(f'{fid}: DC2 figure as 0')
        lab = (f.get('label', '') + ' ' + str(f.get('note', ''))).lower()
        if bt == 'lower-bound' and re.search(r'\btotal\b', lab) and 'not a total' not in lab:
            probs.append(f'{fid}: lower bound labelled as a total')
    return probs


def audit_classes(ds, repo, chain, table, carriers, fees, v1pending):
    cj = json.loads((ds / 'derived/classes.json').read_text())
    pj = json.loads((ds / 'derived/presence.json').read_text())
    ij = json.loads((ds / 'derived/invariant.json').read_text())
    fj = json.loads((ds / 'derived/fq.json').read_text())
    out = {}
    # G31 bound honesty, re-checked by own rules
    g31 = {'figures': len(cj['figures']), 'problems': g31_problems(cj['figures'])}
    txt = ''
    for n in ('classes.json', 'presence.json', 'invariant.json', 'fq.json', 'fees.json', 'summary.json', 'state_roots.json'):
        txt += (ds / 'derived' / n).read_text().lower()
    g31['forbidden_phrases'] = [p for p in FORBIDDEN_PHRASES if p in txt and f'"{p}"' not in txt]
    out['g31'] = g31
    # FQ1 / DC0 numbers from the audit's own walk (window = WINDOW, as classes.json scopes them)
    win = {}
    for h in range(WINDOW[0], WINDOW[1] + 1):
        for t in chain[h]['tx_hashes']:
            win.setdefault(t, []).append(h)
    multi = [t for t, hs in win.items() if len(hs) > 1]
    tc = {}
    for t in table:
        tc[t] = sorted(h for h, r in chain.items() if t in r['tx_hashes'])
    groups = {}
    for t, e in table.items():
        groups.setdefault(e['group'], []).append(len(tc[t]))
    own_fq1 = {'window_tx_carrying_blocks': sum(bool(chain[h]['tx_hashes']) for h in range(WINDOW[0], WINDOW[1] + 1)),
               'window_distinct_txids': len(win), 'window_txids_in_two_or_more_blocks': len(multi),
               'of_which_in_table': sum(t in table for t in multi), 'dc0_window_duplicates': sum(t not in table for t in multi),
               'carriers_total': sum(len(v) for v in tc.values()),
               'tx_parity_true': sum(e['tx_parity'] for e in table.values()),
               'duplicates_two_carriers': sum(n == 2 for n in groups.get('duplicates', [])),
               'false_parity_one_carrier': sum(n == 1 for n in groups.get('no duplicates, but false parity', [])),
               'table_txids_outside_window_carrier': sum(any(h > WINDOW[1] for h in v) for v in tc.values())}
    cl = fj['FQ1']['answer']
    out['fq1'] = {'own': own_fq1, 'claimed': {k: cl.get(k) for k in own_fq1 if k in cl}}
    out['fq1']['equal'] = all(str(cl.get(k)).split(' ')[0] == str(v) for k, v in own_fq1.items() if k in cl)
    figs = {f['id']: f for f in cj['figures']}
    out['dc0'] = {'figure_value': figs.get('dc0-window-duplicates', {}).get('value'), 'own': own_fq1['dc0_window_duplicates']}
    # DC3 figures vs v2 (stale-base check): classes.json is computed from v1 (base r25)
    out['dc3'] = {'base': cj.get('base'),
                  'fees_figure': {k: figs.get('dc3-window-fees', {}).get(k) for k in ('value', 'bound_type')},
                  'fees_coverage': figs.get('dc3-window-fees', {}).get('coverage', {}).get('num'),
                  'burns_figure': {k: figs.get('dc3-window-public-burns', {}).get(k) for k in ('value', 'bound_type')},
                  'v2_own_window_fee_sum': fees['window_fee_sum'], 'v2_own_window_burn_sum': fees['window_burn_sum'],
                  'v2_own_window_coverage': f"{WINDOW[1] - WINDOW[0] + 1 - len(v1pending) + fees['settled']}/{WINDOW[1] - WINDOW[0] + 1}"}
    out['dc3']['reflects_v2'] = (figs.get('dc3-window-fees', {}).get('value') == fees['window_fee_sum'] and
                                 figs.get('dc3-window-public-burns', {}).get('value') == fees['window_burn_sum'])
    # dc1-two-bodies: the census can now fill what was 'pending'
    out['dc1_two_bodies'] = {'value': str(figs.get('dc1-two-bodies', {}).get('value'))[:40],
                             'bound_type': figs.get('dc1-two-bodies', {}).get('bound_type')}
    # G32 records half: v2 per-record class slots
    pend = tagged = 0
    for n in ('derived/txs.jsonl.gz', 'derived/blocks_fees.jsonl.gz', 'derived/roots_window.jsonl.gz', 'raw/tx_bodies.jsonl.gz',
              'raw/wall1_blocks.jsonl.gz'):   # R28: the wall-1 link blocks are block records too
        if not (ds / n).exists():
            continue
        for r in jgz(ds / n):
            if r.get('class') in ('DC0', 'DC1', 'DC2', 'DC3'):
                tagged += 1
            else:
                pend += 1
    out['g32_records'] = {'v2_records': pend + tagged, 'tagged': tagged, 'pending': pend,
                          'classes_records': cj.get('records')}
    # presence: own re-read of every anchor at every rev the file names
    pr = {'anchors': 0, 'reread_equal': 0, 'differ': [], 'revs': {}}
    for cls, by_rev in pj.get('classes', {}).items():
        for rev, ent in by_rev.items():
            if not isinstance(ent, dict):
                continue
            revs = {r.get('rev'): r.get('commit') for r in pj.get('revs', []) if isinstance(r, dict)}
            gitrev = revs.get(rev) or rev          # the commit the builder recorded for that rev
            for a in ent.get('anchors', []):
                pr['anchors'] += 1
                got = anchor_reread(repo, gitrev, a.get('file'), a.get('line'), a.get('quote', '')) if a.get('file') else False
                if rev == 'HEAD' and got is not None and a.get('file'):   # and at this round's head (the working tree)
                    now = anchor_reread(repo, 'HEAD', a.get('file'), a.get('line'), a.get('quote', ''))
                    pr['head_now_equal'] = pr.get('head_now_equal', 0) + (bool(now) == bool(a.get('present')))
                if got is None:
                    pr['revs'][rev] = 'rev not in this clone'
                    continue
                if bool(got) == bool(a.get('present')):
                    pr['reread_equal'] += 1
                else:
                    pr['differ'].append(f'{cls}/{rev}/{a.get("anchor")}')
    pr['dc2_present_head'] = pj.get('headline', {}).get('dc2_present_now', pj.get('headline'))
    pr['headline_present'] = bool(pj.get('headline'))
    out['presence'] = pr
    # invariant: anchors re-read (file:line exists), Q-CS1 root check against v1's archive roots
    inv = {'anchors': 0, 'ok': 0, 'bad': []}
    for q in ('Q-CS2', 'Q-CS3'):
        for a in ij.get(q, {}).get('anchors', []):
            inv['anchors'] += 1
            m = re.match(r'([\w/.-]+\.go):(\d+)', str(a.get('anchor')))
            ok = bool(m) and (Path(repo) / m.group(1)).exists() and int(m.group(2)) <= len((Path(repo) / m.group(1)).read_text().splitlines())
            if ok:
                inv['ok'] += 1
            else:
                inv['bad'].append(a.get('anchor'))
    arch = {r['topo']: r['root'] for r in jgz(Path(repo) / V1 / 'derived/archive_state/roots.jsonl.gz')}
    q1 = ij.get('Q-CS1', {})
    inv['qcs1_root_eq_v1_archive'] = q1.get('root_check', {}).get('census_root') == arch.get(q1.get('scope', {}).get('topo'))
    inv['qcs1_scope_topo'] = q1.get('scope', {}).get('topo')
    inv['status'] = ij.get('status')
    out['invariant'] = inv
    out['fq_status'] = {k: (v.get('status') if isinstance(v, dict) else v) for k, v in fj.items() if k != 'schema'}
    return out


# =============================================================================================== challenges / verdicts
def _res(ok, unresolved=False):
    return 'UNRESOLVED' if unresolved else ('HOLDS' if ok else 'FAILS')


def ch(cid, claim, test, ok, evidence, affects, note='', unresolved=False):
    return {'id': cid, 'claim': claim, 'test': test, 'result': _res(ok, unresolved), 'evidence': evidence,
            'affects': affects if (not ok or unresolved) else [], 'note': note}


def build_challenges(R):
    L, F, W, B = R['ledger'], R['files'], R['walk'], R['bodies']
    out = []
    out.append(ch('D2-01', f"the ledger entry of {R['dataset']} names the manifest the dataset now has",
                  'sha256(manifest.json) vs forensics/ledger.json manifest_sha256 of the open version',
                  L['equal'], [{'class': 'RAW', 'what': f"ledger {str(L['entry_sha256'])[:16]}, manifest {L['manifest_sha256'][:16]}, sealed {L['sealed']}"}],
                  ALL_V,
                  note=('The open version\'s ledger entry was not re-registered after the manifest was re-written (the '
                        'class files were added at the merge); verify_dataset.py checked L2 for sealed versions only, '
                        'so it passed. Fixed at source: rule L9 (an open version\'s manifest equals its ledger entry), '
                        'KAT AU1 + mutation; the ledger re-registered.') if not L['equal'] else ''))
    out.append(ch('D2-02', 'every dataset file re-hashes to the manifest, none missing or unlisted, class files listed',
                  'own SHA-256 of every file under the dataset (audit/ excluded) vs manifest files',
                  not (F['mismatch'] or F['missing'] or F['unlisted']) and F['class_files_listed'],
                  [{'class': 'RAW', 'what': f"listed {F['listed']}, on disk {F['on_disk']}, mismatch {len(F['mismatch'])}, missing {len(F['missing'])}, unlisted {len(F['unlisted'])}, class files listed {F['class_files_listed']}"}],
                  ALL_V))
    out.append(ch('D2-03', 'the v1 inputs v2 reads are pinned and unchanged; v1 is sealed and unchanged',
                  'own SHA-256 of each pinned v1 input; v1 manifest vs its sealed ledger entry',
                  not R['inputs']['changed'] and R['v1']['sealed'] and R['v1']['manifest_equal'],
                  [{'class': 'RAW', 'what': f"{R['inputs']['pinned']} inputs, changed {len(R['inputs']['changed'])}; v1 sealed {R['v1']['sealed']}, manifest equal {R['v1']['manifest_equal']}"}],
                  ALL_V))
    w1 = R['wall1_blocks']
    out.append(ch('D2-04', f"the RAW chain {W['to']:,}..{W['from']:,} is one tips chain from our anchor, and the {w1['rows']:,} wall-1 link blocks are its blocks {WALL1_LINK[0]:,}..{WALL1_LINK[1]:,}",
                  'own decode of every v1 store blob and every v2 wall-1 blob; SHA3-256 ids; tips walk from the anchor',
                  W['contiguous'] and W['multi_tip'] == 0 and W['to'] == WALL1_LINK[0] and W['from'] == W['anchor_height'] and w1['equal'] == w1['rows'],
                  [{'class': 'RAW', 'what': f"walk {W['blocks']:,} blocks {W['from']:,}->{W['to']:,}, contiguous {W['contiguous']}, multi-tip {W['multi_tip']}; wall-1 rows equal {w1['equal']:,}/{w1['rows']:,}"}],
                  ['V2-FEES', 'V2-DUP-BODY']))
    out.append(ch('D2-05', f"the {B['rows']:,} RAW tx bodies are every body the window + gap + wall-1 window need, each passing check (iii), 0 missing",
                  'own tx lists from the walk; own Keccak-256 TXID of each body\'s core statement; blob SHA-256',
                  B['verified'] == B['rows'] and B['missing_own'] == 0 and B['extra'] == 0 and B['missing_json'] == 0 and
                  not any(B[k] for k in ('blob_missing', 'sha_mismatch', 'decode_error', 'txid_mismatch', 'not_carried')),
                  [{'class': 'RAW', 'what': f"needed (own) {B['needed_own']:,} (window+gap {B['needed_window_gap']:,}, wall-1 window {B['needed_wall1']}), verified {B['verified']:,}, missing {B['missing_own']}, extra {B['extra']}, txid mismatch {B['txid_mismatch']}"}],
                  ['V2-FEES', 'V2-DUP-BODY']))
    T = R['txrows']
    out.append(ch('D2-06', f"the {T['rows']:,} derived tx rows (type, fee, burns, ring sizes, roothash, reference, SC data, body hash) equal an independent decode",
                  'own wire decoder over the RAW bodies, compared field by field', T['differ_count'] == 0 and T['equal'] == T['rows'],
                  [{'class': 'DERIVED', 'what': f"equal {T['equal']:,}/{T['rows']:,}, differ {T['differ_count']}" + (f", fields {T.get('first_diff_fields')}" if T['differ_count'] else '')}],
                  ['V2-FEES']))
    Z = R['fees']
    o = Z['own']
    out.append(ch('D2-07', f"the {Z['blocks_claimed']:,} per-block fee/burn/SC rows equal own sums",
                  'per block: sum of own Fees() / BurnValue / SC type over its RAW tx list',
                  Z['differ_count'] == 0 and Z['equal'] == Z['blocks_claimed'],
                  [{'class': 'DERIVED', 'what': f"equal {Z['equal']:,}/{Z['blocks_claimed']:,}, differ {Z['differ_count']}"}], ['V2-FEES']))
    out.append(ch('D2-08', f"fees.json totals: window fees {o['window_fee_sum']:,}, burns {o['window_burn_sum']:,}, v1's {Z['v1_pending']:,} pending-fee blocks all settled, v1 known rows unchanged",
                  'own totals over the walk; v1 pending set from v1 window rows', Z['totals_equal'] and o['settled'] == Z['v1_pending'] and o['v1_known_rows_disagreeing'] == 0,
                  [{'class': 'DERIVED', 'what': f"own {o}; claimed equal {Z['totals_equal']}"}], ['V2-FEES']))
    out.append(ch('D2-09', f"SC: {o['sc_txs']} SC txs in {o['sc_tx_blocks']} blocks; their payouts stay pending (no decoder runs SC execution)",
                  'own type census; the claim text', Z['claimed'].get('sc_txs') == o['sc_txs'] and Z['claimed'].get('sc_tx_blocks') == o['sc_tx_blocks'] and Z['sc_payouts_claim'].startswith('pending'),
                  [{'class': 'DERIVED', 'what': f"own sc_txs {o['sc_txs']}, sc_tx_blocks {o['sc_tx_blocks']}; claimed {Z['claimed'].get('sc_txs')}/{Z['claimed'].get('sc_tx_blocks')}; payouts '{Z['sc_payouts_claim'][:30]}...'"}],
                  ['V2-FEES']))
    sc = R['summary_claim']
    out.append(ch('D2-10', 'summary.json counts equal the audit\'s counts',
                  'own counts vs summary.json', sc.get('tx_bodies_raw') == B['verified'] and sc.get('txblocks') == o['window_txblocks'] + o['gap_txblocks'] and sc.get('tx_bodies_missing') == B['missing_own'],
                  [{'class': 'DERIVED', 'what': f"claimed bodies {sc.get('tx_bodies_raw')}, txblocks {sc.get('txblocks')}; own {B['verified']}, {o['window_txblocks'] + o['gap_txblocks']}"}], ['V2-FEES']))
    D = R['dup']
    c = D['counts']
    out.append(ch('D2-11', f"duplicate-body census (B97): of {c['multi_block_txids']} TXIDs carried by more than one RAW block, none is held with two different bodies, and the rest is unobservable, not zero (dc1-two-bodies stays unbounded)",
                  'every body copy from every independent holder (v1 raw, archive copy, fetched staging), own TXID check, byte comparison',
                  c['different'] == 0 and c['copy_txid_mismatch'] == 0 and D['all_txids']['different'] == 0,
                  [{'class': 'RAW', 'what': f"multi-block {c['multi_block_txids']} (in table {c['in_hf3_table']}, outside {c['outside_table_dc0']}); 2+ sources {c['with_2plus_sources']}: equal {c['equal']}, different {c['different']}; single source {c['single_source']}; no copy {c['no_copy']}"},
                   {'class': 'RAW', 'what': f"all TXIDs with 2+ independent copies: {D['all_txids']['txids_2plus_sources']} (equal {D['all_txids']['equal']}, different {D['all_txids']['different']}); tx lists repeating a TXID {D['tx_lists_with_a_repeated_txid']}"},
                   {'class': 'INTERPRETATION', 'what': D['observability']}],
                  ['V2-DUP-BODY'],
                  note=(f"{c['single_source']} of {c['multi_block_txids']} multi-block TXIDs have one independent copy only: "
                        'a second body under them is not observable from the data held (bound: unbounded for those)')))
    S = R['struct']
    out.append(ch('D2-12', f"structural verifier (B97, second implementation): every proof-carrying body of {S['proof_carrying']:,} is well-formed: wire layout per ring size, every point and scalar canonically encoded, ring shape",
                  'own layout table and own canonicality checks (bn256 P/Order from the source text); never builds or varies a proof',
                  not S['failed_checks'] and S['decode_errors'] == 0,
                  [{'class': 'RAW', 'what': f"bodies {S['bodies']:,} {S['by_type']}; points {S['points_checked']:,}, scalars {S['scalars_checked']:,}; failed checks {S['failed_checks'] or 'none'}; decode errors {S['decode_errors']}"}],
                  ['V-DC2'],
                  note='Structural only: a structurally well-formed proof is not shown sound; soundness stays NOT-DECIDABLE (DC2), and a second soundness verifier is NO-GO (rft §9).'))
    RU = R['runs']
    out.append(ch('D2-13', ('node replay runs A and B are byte-identical, start from the archive seed, and follow the RAW chain'
                            if not RU.get('hf3_entry_runs') else
                            'node replay runs are byte-identical per entry point, start from the archive seed, and follow the RAW chain'),
                  'own SHA-256 of both roots files; base root vs v1 archive root at the seed topo; replay blids vs own walk',
                  RU['identical'] and RU['seed_top_root_eq_v1_archive_root'] and RU['seed_top_blid_eq_walk'] and all(r['base_eq_archive'] and r['blids_eq_walk'] for r in RU['runs'].values()),
                  [{'class': 'DERIVED', 'what': f"runs {sorted(RU['runs'])} identical {RU['identical']}; seed root == v1 archive root {RU['seed_top_root_eq_v1_archive_root']}; seed blid == walk {RU['seed_top_blid_eq_walk']}"}],
                  ['V2-END-STATE']))
    W4, OR = R['wall4'], R.get('own_replay')
    ok14 = bool(OR) and OR['stopped'] == 'completed' and OR['end_eq_recorded_treehash'] and all(OR['walls_accepted'].values())
    hf = [RU['runs'][n] for n in RU.get('hf3_entry_runs', [])]
    if hf:   # R28 v3: the dataset itself carries a run through the HF3 entry; its claim is the completed run, tested here
        c14 = bool(OR) and ok14 and all(r['roots_jsonl_sha256'] == OR['roots_sha256'] and r['stopped'] == 'completed' for r in hf)
        out.append(ch('D2-14', (f"run(s) {RU['hf3_entry_runs']} through the HF3 entry ({HF3_ENTRY}) complete {WALLS['wall2']:,}..{OR['last_topo'] if OR else '?'} "
                                'and end at our own treehash; the pre-fix stop of runs A/B at 7,467,546 is a tool artifact'),
                      ('own re-run of the node replay through the HF3 entry on a fresh APFS clone with the audit\'s own plan; '
                       'its roots compared byte for byte with the dataset run; walls 2-4 accepted'),
                      c14,
                      [{'class': 'DERIVED', 'what': (f"own replay: {OR['stopped']}, {OR['added']:,} blocks, root {str(OR['last_root'])[:8]} == recorded treehash "
                                                     f"{OR['end_eq_recorded_treehash']}; walls accepted {OR['walls_accepted']}; own roots {OR['roots_sha256'][:16]} "
                                                     f"== dataset run roots {[r['roots_jsonl_sha256'][:16] for r in hf]}" if OR else 'own replay: not run')},
                       {'class': 'RAW', 'what': f"HF3 carriers in {WALLS['wall2']:,}..{WALLS['wall4']:,}: {len(W4['hf3_carriers_before_stop'])}, Parity differs with/without the HF3 step on {W4['differs']}"}],
                      ['V2-END-STATE', 'V-STATE-ROOTS']))
    else:
        out.append(ch('D2-14', f"wall 4: the node's own checks reject block {RU['rejection_topo']:,} (tx {'in' if RU['rejection_txid_in_table'] else 'not in'} the HF3 table), so the replay ends at {RU['rejection_topo'] - 1:,} and the end-state check is pending",
                      ('own re-run of the node replay through the sync path\'s HF3 entry (p2p.Add_Complete_Block_HF3), on a fresh APFS clone '
                       'of the archive copy, with the audit\'s own plan; and the HF3 carriers before the stop from own RAW decode against the '
                       'source expression'),
                      not ok14,
                      [{'class': 'RAW', 'what': f"HF3 carriers in {WALLS['wall2']:,}..{WALLS['wall4']:,}: {len(W4['hf3_carriers_before_stop'])}, Parity differs with/without the HF3 step on {W4['differs']}; source: replay calls HF3 entry {W4['source']['replay_calls_hf3_entry']}, bare add {W4['source']['replay_calls_bare_add']}"},
                       {'class': 'DERIVED', 'what': (f"own replay: {OR['stopped']}, {OR['added']:,} blocks, last topo {OR['last_topo']:,}, root {str(OR['last_root'])[:8]} == recorded treehash {OR['end_eq_recorded_treehash']}; walls accepted {OR['walls_accepted']}" if OR else 'own replay: not run')}],
                      ['V2-END-STATE', 'V-STATE-ROOTS'],
                      note=('Overturned: the stop is an artifact of the replay tool, which called Add_Complete_Block without the HF3 table step '
                            '(the merge found it through TestR23bAddCompleteBlockCensus, B123). Through the sync path\'s entry the node accepts '
                            'every block to our anchor and ends at our own treehash. The dataset still carries the pre-fix runs and "pending" '
                            'end-state claims: they are corrected only by a rebuilt v2 (B123), never in place.') if ok14 else ''))
    SR, SO = R['state_roots_claim'], R['state_roots_own']
    out.append(ch('D2-15', f"roothash witnesses: RAW Statement.Roothash equals the held archive root at its reference topo ({SR['witness_claim']})",
                  'own decode of every body\'s reference height and roothash; v1 archive roots', SO['archive_differ'] == 0 and SO['archive_equal'] == SR['witness_claim'].get('archive_equal'),
                  [{'class': 'RAW', 'what': f"own archive witnesses equal {SO['archive_equal']}, differ {SO['archive_differ']}"}] +
                  ([{'class': 'DERIVED', 'what': f"own replay roots as witnesses: equal {OR['witnesses']['equal']}, differ {OR['witnesses']['differ']}, outside {OR['witnesses']['outside']}"}] if OR else []),
                  ['V-STATE-ROOTS']))
    a10c_ok = bool(OR) and OR['end_eq_recorded_treehash'] and OR['seed_eq_dataset_seed'] and OR['witnesses']['differ'] == 0
    in_ds = bool(hf) and a10c_ok and all(r['roots_jsonl_sha256'] == OR['roots_sha256'] for r in hf) and str(SR['a10c_answer']).startswith('bound')
    if in_ds:   # R28 v3: the end-state check that binds the archive base is now a dataset run (run C)
        out.append(ch('D2-16', 'A10c (carried from v1): the archive roots 7,453,290..7,467,515 are the canonical roots of those topos',
                      'the dataset\'s own end-state check (a run from the archive top to our anchor) equals the audit\'s own replay, and every witness agrees',
                      True, [{'class': 'DERIVED', 'what': f"dataset claim: {SR['a10c_answer']}; dataset run roots == own replay roots True; own end-state match True; "
                                                          f"own replay witnesses differ {OR['witnesses']['differ']}"}],
                      ['V-STATE-ROOTS'],
                      note='Bound in the dataset: run C starts from the archive top root (d3345594...) and reaches our own treehash at 7,498,540, '
                           'so the archive state it starts from is the state our node accepted; this is consistency with our chain, '
                           'not a statement about hidden amounts (rft §0.8.9 rule 11).'))
    else:
        out.append(ch('D2-16', 'A10c (carried from v1): the archive roots 7,453,290..7,467,515 are the canonical roots of those topos',
                      'needs an end-state check that binds the archive base: a replay from the archive top to our anchor ending at our treehash, IN THE DATASET',
                      False, [{'class': 'DERIVED', 'what': f"dataset claim: {SR['a10c_answer']}; own replay end-state match {OR['end_eq_recorded_treehash'] if OR else 'not run'} (audit evidence, not a dataset file)"}],
                      ['V-STATE-ROOTS'], unresolved=True,
                      note=('The audit\'s own replay binds the archive top root to our treehash (the replay from it reaches ca11cc21), which is '
                            'the end-state check A10c asked for; it stays UNRESOLVED for this dataset because v2 does not carry that run '
                            '(B123: rebuild v2 with it, then it can HOLD).') if a10c_ok else 'No end-state check binds the archive base.'))
    C = R['classes']
    g31 = C['g31']
    out.append(ch('D2-17', f"G31 bound honesty: the {g31['figures']} figures each carry class, scope, coverage, bound_type, and no forbidden phrase",
                  'own rules over classes.json (exact needs full coverage, unbounded never 0, DC2 never 0, lower bound never a total) + phrase scan of derived/',
                  not g31['problems'] and not g31['forbidden_phrases'],
                  [{'class': 'DERIVED', 'what': f"problems {g31['problems'] or 'none'}; forbidden phrases {g31['forbidden_phrases'] or 'none'}"}], ALL_V))
    f1 = C['fq1']
    out.append(ch('D2-18', 'FQ1 / DC0: the census figures (window distinct TXIDs, multi-block TXIDs, all in the table, carriers, parity) equal an independent count; DC0 = 0',
                  'own walk and own HF3 table parser', f1['equal'] and C['dc0']['own'] == 0 and C['dc0']['figure_value'] == 0,
                  [{'class': 'RAW', 'what': f"own {f1['own']}"}, {'class': 'DERIVED', 'what': f"claimed {f1['claimed']}"}], ['V2-DUP-BODY']))
    d3 = C['dc3']
    out.append(ch('D2-19', 'classes.json DC3 figures reflect dataset v2 (fees and public burns of the window)',
                  'classes.json DC3 figures vs the audit\'s own v2 totals', d3['reflects_v2'],
                  [{'class': 'DERIVED', 'what': f"classes base {d3['base']}: fees {d3['fees_figure']} over {d3['fees_coverage']} blocks, burns {d3['burns_figure']}; v2 own: fees {d3['v2_own_window_fee_sum']:,}, burns {d3['v2_own_window_burn_sum']:,} over {d3['v2_own_window_coverage']}"}],
                  ['V2-FEES'],
                  note=('The figures are honest lower bounds over v1 (G31 holds), but stale: v2 settled every pending block, so the '
                        'window fee and burn figures can be exact; classes.json still reads v1 (base r25, B126).') if not d3['reflects_v2'] else ''))
    g32 = C['g32_records']
    out.append(ch('D2-20', 'G32 records half: every v2 derived/raw record carries its defect class',
                  'own count of the `class` slot over txs, blocks_fees, roots_window, tx_bodies and wall1_blocks', g32['pending'] == 0 and g32['tagged'] > 0,
                  [{'class': 'DERIVED', 'what': f"v2 records {g32['v2_records']:,}: tagged {g32['tagged']:,}, pending {g32['pending']:,}; classes.json records {g32['classes_records']}"}],
                  ALL_V,
                  note='B126: classes.py tags the v1 record layout, so G32\'s record check passes vacuously on v2.' if g32['pending'] else ''))
    pr = C['presence']
    out.append(ch('D2-21', f"presence.json: every anchor re-reads as recorded at its rev ({pr['anchors']} anchors); DC2 present at the head is the headline",
                  'own re-read of file:line at each rev (git show; HEAD = working tree)', not pr['differ'] and pr['headline_present'] and pr['dc2_present_head'] is True,
                  [{'class': 'SRC', 'what': f"re-read equal {pr['reread_equal']}/{pr['anchors']}; differ {pr['differ'][:5] or 'none'}; revs not in clone {pr['revs'] or 'none'}; DC2 present at head {pr['dc2_present_head']}"}],
                  ['V-DC2']))
    iv = C['invariant']
    out.append(ch('D2-22', 'invariant.json: its Q-CS2/Q-CS3 anchors exist at the head, and the Q-CS1 census root is the held archive root',
                  'own file:line existence check; v1 archive roots at the census topo', not iv['bad'] and iv['qcs1_root_eq_v1_archive'],
                  [{'class': 'SRC', 'what': f"anchors ok {iv['ok']}/{iv['anchors']}; Q-CS1 root == v1 archive root at {iv['qcs1_scope_topo']}: {iv['qcs1_root_eq_v1_archive']}"}],
                  ['V-DC2']))
    S2 = R['scan']
    out.append(ch('D2-23', 'the v2 dataset text holds no exploit content and no private information (no address, path, IP, host)',
                  'G24 exploit patterns + privacy patterns + private terms over every text file', not S2['hits'],
                  [{'class': 'DERIVED', 'what': f"files {S2['files_scanned']}, patterns {S2['patterns']}, private terms {S2['private_terms_loaded']}, hits {len(S2['hits'])}"}],
                  ALL_V))
    out.append(ch('D2-24', '(a2) TreeSection from ONE source stays BLOCKED and pending, with evidence, never graded',
                  'derived/a2.json class and the scan above', R['a2']['class'] == 'pending',
                  [{'class': 'DERIVED', 'what': f"class {R['a2']['class']}; verdict '{R['a2']['verdict_head']}...'"}], ['V2-END-STATE']))
    X = R.get('dc1_structure')
    if X:   # r28d (v4, B180)
        out.append(ch('D2-26', f"dc1_structure.json: the ring size / payload format counts of the {X['dc1_table']} DC1 txs equal an independent count (own HF3 parse, own walk, own decoder)",
                      'own wire decoder over the held DC1 bodies, own one/two-carrier split; counts compared key by key',
                      X['counts_equal'] and X['decoded_own'] == X['dc1_table'] and X['class'] == 'DC1'
                      and (X['claimed_coverage'] or {}).get('num') == X['dc1_table'] == (X['claimed_coverage'] or {}).get('den'),
                      [{'class': 'DERIVED', 'what': f"own {X['own_counts']}; decoded {X['decoded_own']}/{X['dc1_table']}, two carriers {X['two_carriers_own']}; claimed equal {X['counts_equal']}"}],
                      ['V2-DUP-BODY']))
        out.append(ch('D2-27', f"fq.json: the FQ2 correction adds only criterion S-RT and a dated note to {X['base']}'s fq.json; S-RT agrees with the own count; DC1-obs unchanged",
                      f"fq.json vs the sealed {X['base']}/derived/fq.json less FQ2 S-RT and corrections; S-RT result vs own criterion count; FQ2 coverage dc1_obs",
                      X['fq_rest_equal_base'] and X['fq2_srt_agrees'] and X['fq2_dc1_obs'] == X['fq2_dc1_obs_base'] == 0 and X['fq2_corrections'] >= 1
                      and v5_fq_ok(X.get('fq_v5_changes'), R.get('v5')),
                      [{'class': 'DERIVED', 'what': f"rest equal {X['fq_rest_equal_base']}; S-RT '{X['fq2_srt_result']}', agrees {X['fq2_srt_agrees']}; dc1_obs {X['fq2_dc1_obs']} (base {X['fq2_dc1_obs_base']}); corrections {X['fq2_corrections']}"
                                                         + (f"; v5 changes {v5_fq_text(X['fq_v5_changes'], R.get('v5'))}" if X.get('fq_v5_changes') is not None else '')}],
                      ['V2-DUP-BODY']))
    Y = R.get('row_classes')
    if Y:   # r29 (B107)
        out.append(ch('D2-28', f"walls.json ({Y['wall_rows']} rows + replay_stops) and inclusions.json ({Y['inclusion_rows']} rows + the file) each carry the defect class its rule gives",
                      'own walk: each wall block\'s own tx list against the own HF3 parse; own carrier census for the multi-block TXIDs; the builder\'s classes read last, as claims',
                      Y['pending'] == 0 and not Y['wall_differ'] and Y['wall_unwalked'] == 0 and Y['wall_equal'] == Y['wall_rows']
                      and Y['stops_equal'] and Y['rows_txids_eq_own_multi'] and Y['inclusion_equal'] == Y['inclusion_rows']
                      and Y['file_class_equal'],
                      [{'class': 'DERIVED', 'what': f"walls equal {Y['wall_equal']}/{Y['wall_rows']} (unwalked {Y['wall_unwalked']}, differ {Y['wall_differ'][:5] or 'none'}); replay_stops equal {Y['stops_equal']}; inclusions equal {Y['inclusion_equal']}/{Y['inclusion_rows']} (own multi-block {Y['own_multi']}, rows == own {Y['rows_txids_eq_own_multi']}, own classes {Y['own_classes']}); file class equal {Y['file_class_equal']}; pending {Y['pending']}"}],
                      ALL_V))
    out += challenges_v5(R.get('v5'))
    return out


def challenges_v5(V):
    """r30 D2-29..D2-34 (dataset v5; refute by default: HOLDS only on the auditor's own equal recount)"""
    if not V:
        return []
    out = []
    t = V['two_bodies']
    out.append(ch('D2-29', f"classes.json dc1-two-bodies is computed: lower bound {t['claimed_value']}, coverage {t['claimed_num']}/{t['claimed_den']} multi-block TXIDs (B202)",
                  'own duplicate-body census (D2-11) and own multi-block count vs the figure', t['holds'],
                  [{'class': 'DERIVED', 'what': f"own different {t['own_different']}, 2+ holders {t['own_2plus']}, multi-block {t['own_multi']}; claimed {t['claimed_value']} {t['claimed_num']}/{t['claimed_den']} {t['claimed_bound']}"}],
                  ['V2-DUP-BODY']))
    x = V['dc2_den']
    out.append(ch('D2-30', f"the DC2 denominator counts proof-carrying txs only (NORMAL+SC+BURN): {x['claimed_den']} over 0..7,498,539; the value stays unbounded (B203 a)",
                  'own sum over the three B182 census records and the window txs, own type set; REGISTRATION excluded', x['holds'],
                  [{'class': 'DERIVED', 'what': f"own sum {x['own_sum']}, claimed sum {x['claimed_sum']}, overlap {x['overlap']}, den {x['claimed_den']}; value {x['value']}, bound {x['bound']}; registration counted {x['registration_counted']}"}],
                  ['V-DC2'], unresolved=not x['census_read']))
    for cid, key, claim, aff in (('D2-31', 'claim_grant', 'registrations below 144,000 x 200 equal blockchain/supply.go:7-9 (B210)', ['V2-FEES']),
                                 ('D2-32', 'dc0_genesis', 'the DC0 multi-block TXIDs below the window equal an own distinct recount, and reg_lt3 all lie within 0..156,599 (B209)', ['V2-DUP-BODY'])):
        y = V[key]
        un = 'unresolved' in y
        out.append(ch(cid, claim, 'own CRC reader over the pinned checkpoint (SHA-256 compared), own sums', (not un) and y.get('holds'),
                      [{'class': 'DERIVED', 'what': y['unresolved'] if un else ', '.join(f'{k} {v}' for k, v in sorted(y.items()) if k != 'holds')}],
                      aff, unresolved=un))
    k = V['consistency']
    out.append(ch('D2-33', 'classes.json is this version\'s own file and agrees with fq.json (S-RT named iff FQ2 has it, FQ1 two bodies, DC1-obs) (B107)',
                  'content checks of classes.json against fq.json; never a dataset-label-only check', k['holds'],
                  [{'class': 'DERIVED', 'what': ', '.join(f'{a} {b}' for a, b in sorted(k.items()) if a != 'holds')}], ALL_V))
    b = V['b111']
    out.append(ch('D2-34', 'the B111 1-key residual is attributed to the premine term only as a HYPOTHESIS (no set diff yet)',
                  'own residual = keys at 7,498,540 minus registrations through 7,498,539; status text', b['holds'],
                  [{'class': 'DERIVED', 'what': f"own residual {b['own_residual_no_premine']}, premine_keys {b['premine_keys']}, status {b['status']}"}],
                  ['V-DC2']))
    return out


ALL_V =['V2-FEES', 'V2-DUP-BODY', 'V2-END-STATE', 'V-STATE-ROOTS', 'V-DC2']
VERDICT_DEFS = [
    ('V2-FEES', 'did the public fees and burns of the window + gap create value beyond the emission formula?',
     'derived/fees.json, blocks_fees.jsonl.gz'),
    ('V2-DUP-BODY', 'is a TXID held with two different bodies (DC1 two-bodies; DC0 outside the table)?',
     'audit duplicate-body census (B97); classes.json dc1-two-bodies'),
    ('V2-END-STATE', 'does a replay of 7,467,516..7,498,540 from the archive seed end at our own treehash?', 'derived/state_roots.json'),
    ('V-STATE-ROOTS', 'what were the pre/post balance-tree roots of the window\'s blocks (A10c)?',
     'derived/state_roots.json, roots_window.jsonl.gz'),
    ('V-DC2', 'did the proof soundness defect (DC2) create value over genesis .. now?', 'derived/classes.json DC2, presence.json'),
]


def build_verdicts(chs, R):
    """Graded questions only (grades of rft §0.8.2). Structural checks (binding, bodies, classes outputs) feed them:
    a challenge that FAILS or stays UNRESOLVED is listed on every verdict it affects and its correction is recorded."""
    by = {c['id']: c for c in chs}
    vs = []
    for vid, q, src in VERDICT_DEFS:
        ids = sorted(c['id'] for c in chs if vid in c['affects'] or vid in AFFECTS_ALWAYS.get(c['id'], []))
        bad = [i for i in ids if by[i]['result'] != 'HOLDS']
        v = {'id': vid, 'question': q, 'source': src, 'challenges': ids, 'downgraded': False}
        v.update(VERDICT_GRADE[vid](R, bad, by))
        if bad:
            v['open_or_failed'] = bad
            v['claim_corrections'] = [f"{i}: {by[i]['note']}" for i in bad if by[i]['note']]
        vs.append(v)
    return vs


# which challenges inform a verdict even when they HOLD (so each verdict lists its evidence)
AFFECTS_ALWAYS = {
    'D2-01': ALL_V, 'D2-02': ALL_V, 'D2-03': ALL_V, 'D2-23': ALL_V, 'D2-04': ['V2-FEES', 'V2-DUP-BODY'],
    'D2-05': ['V2-FEES', 'V2-DUP-BODY'], 'D2-06': ['V2-FEES'], 'D2-07': ['V2-FEES'], 'D2-08': ['V2-FEES'],
    'D2-09': ['V2-FEES'], 'D2-10': ['V2-FEES'], 'D2-11': ['V2-DUP-BODY'], 'D2-12': ['V-DC2'],
    'D2-13': ['V2-END-STATE'], 'D2-14': ['V2-END-STATE', 'V-STATE-ROOTS'], 'D2-24': ['V2-END-STATE'],
    'D2-15': ['V-STATE-ROOTS'], 'D2-16': ['V-STATE-ROOTS'], 'D2-17': ALL_V, 'D2-18': ['V2-DUP-BODY'],
    'D2-19': ['V2-FEES'], 'D2-20': ALL_V, 'D2-21': ['V-DC2'], 'D2-22': ['V-DC2'],
    'D2-26': ['V2-DUP-BODY'], 'D2-27': ['V2-DUP-BODY'],   # r28d (v4, B180): the DC1 structural census and FQ2 S-RT
    'D2-28': ALL_V,                                       # r29 (B107): walls/inclusions row classes (G32 rows half)
    'D2-29': ['V2-DUP-BODY'], 'D2-30': ['V-DC2'], 'D2-31': ['V2-FEES'], 'D2-32': ['V2-DUP-BODY'],   # r30 (v5)
    'D2-33': ALL_V, 'D2-34': ['V-DC2'],
}


def _g_fees(R, bad, by):
    o = R['fees']['own']
    n = WINDOW[1] - WINDOW[0] + 1
    return {'builder_grade': 'not graded (class pending; classes.json DC3 figures read v1)',
            'audit_grade': 'NOT-DECIDABLE-FROM-PUBLIC-DATA',
            'reason': ('the fee and burn fields are public and exact here (figures), but a fee is paid out of a hidden balance '
                       'whose soundness is DC2, so whether fees were funded by real value is not decidable from public data; '
                       'burns remove value; SC payouts of the SC txs stay pending'),
            'figures': [
                {'id': 'v2-window-fees', 'class': 'DC3', 'value': o['window_fee_sum'], 'unit': 'atomic', 'bound_type': 'exact',
                 'scope': {'heights': list(WINDOW)}, 'coverage': {'num': n, 'den': n, 'num_anchor': 'audit D2-07/D2-08',
                                                                  'den_anchor': 'window heights'}},
                {'id': 'v2-window-public-burns', 'class': 'DC3', 'value': o['window_burn_sum'], 'unit': 'atomic', 'bound_type': 'exact',
                 'scope': {'heights': list(WINDOW)}, 'coverage': {'num': n, 'den': n, 'num_anchor': 'audit D2-07/D2-08',
                                                                  'den_anchor': 'window heights'}},
                {'id': 'v2-gap-fees', 'class': 'DC3', 'value': o['gap_fee_sum'], 'unit': 'atomic', 'bound_type': 'exact',
                 'scope': {'heights': [WINDOW[1] + 1, R['walk']['anchor_height']]},
                 'coverage': {'num': o['gap_txblocks'], 'den': o['gap_txblocks'], 'num_anchor': 'audit D2-07',
                              'den_anchor': 'tx-carrying gap blocks (own walk)'}}],
            'inputs': [{'class': 'RAW', 'what': 'the bodies (D2-05)'}, {'class': 'DERIVED', 'what': 'own fee/burn sums (D2-07, D2-08)'}]}


def dup_builder_grade(V):
    """r30 (B202): the builder's grade of V2-DUP-BODY read from the computed classes figure; v4 and earlier datasets
    (no v5 section) keep the text they were audited with"""
    if not V:
        return 'pending (classes.json dc1-two-bodies unbounded; fq.json FQ1)'
    t = V['two_bodies']
    return (f"lower bound {t['claimed_value']} (classes.json dc1-two-bodies {t['claimed_bound']}, coverage "
            f"{t['claimed_num']}/{t['claimed_den']} multi-block TXIDs; fq.json FQ1)")


def _g_dup(R, bad, by):
    c = R['dup']['counts']
    return {'builder_grade': dup_builder_grade(R.get('v5')),
            'audit_grade': 'NOT-DECIDABLE-FROM-PUBLIC-DATA',
            'reason': (f"census: {c['with_2plus_sources']} of {c['multi_block_txids']} multi-block TXIDs are held from 2+ "
                       f"independent holders ({c['equal']} equal, {c['different']} different), {c['single_source']} from one "
                       'holder only, where a second body is not observable from the data held; two-body count: lower bound '
                       f"{c['different']}, coverage {c['with_2plus_sources']}/{c['multi_block_txids']}"),
            'inputs': [{'class': 'RAW', 'what': 'body copies compared byte for byte (D2-11)'}]}


def _g_end(R, bad, by):
    if R['runs'].get('hf3_entry_runs') and 'D2-14' not in bad:   # R28 v3: the dataset carries the completed run
        OR = R.get('own_replay') or {}
        return {'builder_grade': 'MATCH (derived/state_roots.json run C end_state_check)', 'audit_grade': 'NOT-DECIDABLE-FROM-PUBLIC-DATA',
                'reason': (f"end-state check HOLDS in the dataset (D2-14): run(s) {R['runs']['hf3_entry_runs']} through the HF3 entry end at "
                           f"our own treehash at {OR.get('last_topo', 'pending')}, byte-identical to the audit's own replay; this shows our "
                           'state is consistent with the blocks our node accepted and nothing about hidden amounts, so the inflation '
                           'question it feeds stays NOT-DECIDABLE (rft §0.8.9 rule 11)'),
                'inputs': [{'class': 'DERIVED', 'what': 'dataset run C (D2-14) and the audit\'s own run'}]}
    return {'builder_grade': 'pending: the run reached topo 7467545, not 7,498,540', 'audit_grade': 'pending',
            'reason': ('the dataset\'s stop at 7,467,546 is overturned (D2-14): the audit\'s own replay through the HF3 entry '
                       'ends at our treehash; the verdict stays pending until a rebuilt v2 carries such a run (B123)')
            if 'D2-14' in bad else 'no complete run in the dataset',
            'inputs': [{'class': 'DERIVED', 'what': 'node replay runs (D2-13) and the audit\'s own run (D2-14)'}]}


def _g_roots(R, bad, by):
    if R['runs'].get('hf3_entry_runs') and 'D2-16' not in bad and 'D2-14' not in bad:
        return {'builder_grade': 'bound (derived/state_roots.json a10c)', 'audit_grade': 'NOT-DECIDABLE-FROM-PUBLIC-DATA',
                'reason': ('A10c HOLDS in the dataset (D2-16): the archive base is bound by run C\'s end-state check and every witness '
                           'agrees (D2-15); state roots are node-computed, not consensus-committed, and say nothing about hidden amounts '
                           '(rule 11); window topos 7,415,466..7,453,289 have no held state (B95 decided)'),
                'inputs': [{'class': 'DERIVED', 'what': 'replay roots (run C) and archive roots'}]}
    return {'builder_grade': 'pending (30 topos with pre/post roots of 82,477)', 'audit_grade': 'pending',
            'reason': 'A10c stays UNRESOLVED for this dataset (D2-16); every witness agrees (D2-15)',
            'inputs': [{'class': 'DERIVED', 'what': 'replay and archive roots'}]}


def _g_dc2(R, bad, by):
    return {'builder_grade': 'NOT-DECIDABLE-FROM-PUBLIC-DATA (classes.json DC2, once, genesis .. now)',
            'audit_grade': 'NOT-DECIDABLE-FROM-PUBLIC-DATA',
            'reason': ('unbounded (lower bound 0, no upper bound): an accepted proof under the defect and an honest one pass the '
                       'same verifier (FQ5); the structural verifier (D2-12) shows encodings, not soundness; a second soundness '
                       'verifier is NO-GO (rft §9)'),
            'inputs': [{'class': 'INTERPRETATION', 'what': 'FQ5 (no public-data test separates the two)'},
                       {'class': 'SRC', 'what': 'presence.json anchors re-read (D2-21)'}]}


VERDICT_GRADE = {'V2-FEES': _g_fees, 'V2-DUP-BODY': _g_dup, 'V2-END-STATE': _g_end, 'V-STATE-ROOTS': _g_roots, 'V-DC2': _g_dc2}

NOGO = [{'id': 'NOGO-B97-SOUNDNESS',
         'what': 'a second, independent SOUNDNESS verifier of the range proof / inner-product argument',
         'why': ('telling two verifiers apart, or showing the defect class at work, needs a proof that one verifier accepts and an '
                 'honest one rejects: exploit content (rft §0.8.1 rule 6, §5, §9). Re-running honest verification a second time '
                 'adds nothing that D2-12 and the node verifier (v1 A11) do not already show, and needs the ring state, which '
                 'exists only inside the held archive (v1 A11: 2 txs). Recorded as NO-GO; not attempted.'),
         'instead': 'the structural / public-value verifier D2-12 (pass/fail per named check only)'}]


def build_report(R, ds):
    chs = build_challenges(R)
    vs = build_verdicts(chs, R)
    rerun = {k: R[k] for k in sorted(R)}
    hist = AC.audit_history(ds)
    n_fail = sum(c['result'] == 'FAILS' for c in chs)
    n_open = sum(c['result'] == 'UNRESOLVED' for c in chs)
    rep = {'dataset': R['dataset'], 'binding': R['binding'],
           'implementation': {'name': IMPL_VERSION, 'file': 'harness/forensics/audit2.py', 'shares_code_with_builder': False,
                              'own': ['audit_check.py primitives (Keccak-f[1600] from FIPS 202, block/tx decoders, HF3 parser, scan)',
                                      'tips walk incl. the wall-1 link', 'duplicate-body census', 'structural proof verifier (B97)',
                                      'fee/burn/SC sums', 'classes re-checks (G31/G32/FQ1/presence/invariant)', 'replay plan'],
                              'reused': ["the node's own blockchain package through tools/forensics/a2 replay for D2-14/D2-16, by design (rft §0.8.5)"]},
           'counts': {'challenges': len(chs), 'holds': sum(c['result'] == 'HOLDS' for c in chs), 'overturned': n_fail,
                      'unresolved': n_open, 'verdicts': len(vs), 'downgraded': sum(bool(v.get('downgraded')) for v in vs),
                      'claims_corrected': sum(bool(v.get('claim_corrections')) for v in vs)},
           'verdicts': vs, 'nogo': NOGO, 'rerun': rerun, 'history': hist}
    rep['rerun_sha256'] = hashlib.sha256(json.dumps(rerun, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    rep['counts']['overturned_all_runs'] = n_fail + sum(h['counts'].get('overturned', 0) for h in hist)
    # G29's sum counts an overturn again in every run that still carries it; the distinct ids say how many claims fell
    rep['counts']['overturned_distinct_all_runs'] = len({c['id'] for c in chs if c['result'] == 'FAILS'} |
                                                        {i for h in hist for i in h['overturned']})
    for h in hist:
        for vid, notes in h['claim_corrections'].items():
            for v in vs:
                if v['id'] == vid:
                    v.setdefault('correction_history', []).append(f"{h['run']}: {'; '.join(notes)[:300]}")
    return rep, {'note': 'independent audit challenges of dataset v2 (rft §0.8.5): HOLDS / FAILS / UNRESOLVED; every FAILS or '
                         'UNRESOLVED keeps its verdicts off a PROVEN grade (audit_report.json verdicts); overturns stay on record '
                         'in audit/history/', 'binding': R['binding'], 'challenges': chs}


def render_md(rep, chj):
    c = rep['counts']
    L = ['# Independent audit of forensics/' + rep['dataset'], '',
         f"Auditor: a second implementation (`{rep['implementation']['name']}`, `harness/forensics/audit2.py` on the primitives of "
         '`audit_check.py`) that shares no code with the v2 builder. Refute by default (rft §0.8.5).', '',
         f"Bound to the dataset data `{rep['binding']['data_sha256']}` ({rep['binding']['files_bound']} files outside audit/), audited "
         f"from manifest `{rep['binding']['manifest_sha256_at_audit']}`. Rerun block SHA-256 `{rep['rerun_sha256']}`.", '',
         f"**Result: {c['challenges']} challenges, {c['holds']} HOLD, {c['overturned']} FAIL (overturned), {c['unresolved']} UNRESOLVED; "
         f"overturns over all runs of this version: {c['overturned_all_runs']} (distinct claims overturned: "
         f"{c['overturned_distinct_all_runs']}).**", '',
         '## What was re-run', '',
         'Every v1 store block and every v2 wall-1 block was decoded by this implementation and hashed (SHA3-256 under our own '
         'Keccak); the tips walk runs from our anchor through the wall-1 link. Every tx body was re-hashed and its TXID '
         're-computed from the core statement. Fees, burns and SC counts were summed per block. Body copies from every '
         'independent holder were compared byte for byte. Every proof-carrying body went through the structural verifier. '
         'The node replay from the archive seed was re-run through the sync path\'s HF3 entry on a fresh APFS clone with our '
         'own plan. Only after that were the builder\'s derived/ files read, as claims.', '',
         '## Challenges', '', '| id | claim | method | result | evidence |', '|---|---|---|---|---|']
    for x in chj['challenges']:
        ev = '; '.join(f"{e['class']}: {e['what']}" for e in x['evidence'])
        L.append(f"| {x['id']} | {x['claim']} | {x['test']} | **{x['result']}** | {ev.replace('|', '/')} |")
    L += ['', '## Overturned and unresolved', '']
    for x in chj['challenges']:
        if x['result'] != 'HOLDS':
            L.append(f"- **{x['id']} {x['result']}**: {x['claim']}. {x['note']} Affects: {', '.join(x['affects'])}.")
    if rep.get('history'):
        L += ['', '## Audit history (earlier runs, kept unchanged under audit/history/)', '']
        for h in rep['history']:
            hc = h['counts']
            L.append(f"- **{h['run']}** (manifest `{h['binding'].get('manifest_sha256_at_audit', '?')[:16]}…`, report "
                     f"`{h['report_sha256'][:16]}…`): {hc.get('challenges')} challenges, {hc.get('holds')} HOLD, "
                     f"{hc.get('overturned')} FAIL (overturned: {', '.join(h['overturned']) or 'none'}), "
                     f"{hc.get('unresolved')} UNRESOLVED ({', '.join(h['unresolved']) or 'none'}).")
    L += ['', '## Verdicts after the audit', '', '| verdict | builder | audit | note |', '|---|---|---|---|']
    for v in rep['verdicts']:
        note = v.get('note') or v.get('reason') or v.get('scope', '')
        L.append(f"| {v['id']} | {v['builder_grade']} | **{v['audit_grade']}** | {str(note).replace('|', '/')} |")
    L += ['', '## NO-GO (rft §9)', '']
    for n in rep['nogo']:
        L.append(f"- **{n['id']}**: {n['what']}. {n['why']} Instead: {n['instead']}.")
    L += ['', '## Limits', '',
          '- The structural verifier shows encodings and layout, not soundness. Proof soundness (DC2) stays NOT-DECIDABLE.',
          '- The duplicate-body census sees only the copies held; a second body under a single-source TXID is unobservable.',
          '- The audit\'s own replay is audit evidence, not a dataset file; the dataset is corrected only by a new build (B123).',
          '- Hidden amounts are ElGamal ciphertexts. No grade here says anything about them.', '']
    return '\n'.join(L)


# =============================================================================================== selftest (KAT AU-S)
def selftest_struct(repo):
    f = []
    try:
        P, N = bn256_constants(repo)
    except (OSError, ValueError) as e:
        return [f'bn256 constants: {e}']
    g1 = (1).to_bytes(32, 'big') + b'\x00'            # (1, 2) is the bn256 G1 generator: on the curve, canonical
    if point_problem(g1, P) is not None:
        f.append('generator x=1 rejected')
    if point_problem((1).to_bytes(32, 'big') + b'\x02', P) != 'point-flag-not-0-or-1':
        f.append('flag 0x02 accepted')
    if point_problem(P.to_bytes(32, 'big') + b'\x00', P) != 'point-x-not-reduced':
        f.append('x = P accepted')
    nq = next(x for x in range(2, 200) if pow((x ** 3 + 3) % P, (P - 1) // 2, P) == P - 1)
    if point_problem(nq.to_bytes(32, 'big') + b'\x00', P) != 'point-not-on-curve':
        f.append('off-curve x accepted')
    if scalar_problem(N.to_bytes(32, 'big'), N) != 'scalar-not-reduced' or scalar_problem((N - 1).to_bytes(32, 'big'), N):
        f.append('scalar range')
    for pw in range(1, 8):
        try:
            proof_layout(pw)
        except ValueError:
            f.append(f'layout {pw}')
    return f


# =============================================================================================== CLI
def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest='cmd', required=True)
    p = sp.add_parser('plan'); p.add_argument('--dataset', default='forensics/r26'); p.add_argument('--v1-store', required=True)
    p.add_argument('--v2-store', required=True); p.add_argument('--from', dest='from_', type=int, required=True)
    p.add_argument('--to', type=int, required=True); p.add_argument('--out', required=True); p.add_argument('--jobs', type=int, default=4)
    p = sp.add_parser('run'); p.add_argument('dataset'); p.add_argument('--v1-store', required=True); p.add_argument('--v2-store', required=True)
    p.add_argument('--archive'); p.add_argument('--stage'); p.add_argument('--replay'); p.add_argument('--private')
    p.add_argument('--jobs', type=int, default=4); p.add_argument('--out', required=True)
    p = sp.add_parser('build'); p.add_argument('dataset'); p.add_argument('--rerun', required=True); p.add_argument('--keep-previous')
    sp.add_parser('selftest')
    a = ap.parse_args(argv)
    if a.cmd == 'selftest':
        f = AC.hash_selftest() + selftest_struct(ROOT)
        print('selftest', 'PASS' if not f else 'FAIL: ' + '; '.join(f))
        return 0 if not f else 3
    if a.cmd == 'plan':
        guard(a.v1_store), guard(a.v2_store)
        anchors = json.loads((ROOT / V1 / 'raw/anchors.json').read_text())
        anchor = next(x for x in anchors if x.get('kind') == 'block')
        blocks = decode_store_blocks([a.v1_store], a.jobs)
        chain, multi = walk({r['id']: r for r in blocks}, anchor['id'], a.from_)
        rows = jgz(Path(a.dataset) / 'raw/tx_bodies.jsonl.gz')
        bsha = {}
        for r in rows:
            b = (Path(a.v2_store) / r['sha256']).read_bytes()
            if sha(b) == r['sha256'] and AC.decode_tx(b)['txid'] == r['txid']:
                bsha[r['txid']] = r['sha256']
        out = build_plan(chain, bsha, a.from_, a.to)
        Path(a.out).write_text('\n'.join(out) + '\n')
        print('plan', len(out), 'rows', sha(Path(a.out).read_bytes()), 'multi-tip', multi)
        return 0
    if a.cmd == 'run':
        R = run(a.dataset, ROOT, a.v1_store, a.v2_store, a.archive, a.stage, a.replay, a.private, a.jobs)
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        txt = json.dumps(R, indent=1, sort_keys=True, default=sorted) + '\n'
        (out / 'audit2_rerun.json').write_text(txt)
        print('audit2_rerun', sha(txt.encode()), R.get('result'))
        return 0 if R.get('result') == 'done' else 3
    if a.cmd == 'build':
        ds = Path(a.dataset)
        ad = ds / 'audit'
        ad.mkdir(exist_ok=True)
        if a.keep_previous:
            hd = ad / 'history' / a.keep_previous
            if hd.exists():
                raise SystemExit(f'refused: audit/history/{a.keep_previous} exists (history is never rewritten)')
            if not (ad / 'audit_report.json').exists():
                raise SystemExit('refused: no current audit to keep')
            hd.mkdir(parents=True)
            for k in ('audit_report.json', 'challenges.json', 'AUDIT.md'):
                if (ad / k).exists():
                    (hd / k).write_bytes((ad / k).read_bytes())
        R = json.loads(Path(a.rerun).read_text())
        rep, chj = build_report(R, ds)
        (ad / 'audit_report.json').write_text(json.dumps(rep, indent=1, sort_keys=True) + '\n')
        (ad / 'challenges.json').write_text(json.dumps(chj, indent=1, sort_keys=True) + '\n')
        (ad / 'AUDIT.md').write_text(render_md(rep, chj))
        print('audit2', json.dumps(rep['counts'], sort_keys=True))
        return 0


if __name__ == '__main__':
    sys.exit(main())
