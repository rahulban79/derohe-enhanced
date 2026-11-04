#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the R25 monetary-forensics engine (artifacts/dero-rft.md §0.8.8).
No network, no live file read or written (the live RPC is a fake in MF11).

  MF5  provenance (harness/forensics/provenance.py): an unverified / EXT object must never be labelled RAW.
       Forged: a good block (RAW), one altered byte (fails i), a decoder id that disagrees (fails i), a block with a
       valid id that no anchor reaches (fails ii), a block reached only THROUGH a block that failed (i) (fails ii),
       a tx whose recomputed TXID differs (fails iii), a tx with a valid TXID in no verified block, or only in an
       EXT block's list (fails iii); classify accepts only literal True checks; the provenance validator flags a RAW
       label with a failed or missing check or without a SHA-256. Committed data: when forensics/r25/raw exists,
       every RAW entry of provenance.json and of raw/headerchain.jsonl.gz carries its passed checks, and every
       tier A blob's file name is its SHA-256.
       Integration: verify_acquire.py on a forged staging dir (fake decoder) rows only the anchored chain, rejects
       the tampered (i) and unanchored (ii) blocks, keeps a tx carried only by an EXT block and a mis-hashing body EXT,
       and writes no EXT blob to the RAW store.
  MF1  manifest (harness/forensics/manifest_check.py): an altered, unlisted or deleted dataset file, a changed pinned
       tool, a changed HF3 table and an empty manifest each FAIL; the committed dataset matches its manifest.
  MF6  hashes (harness/forensics/keccak.py, pure Python): published Keccak-256 and FIPS 202 SHA3-256 vectors, rate
       boundary lengths against hashlib, the two paddings differ; committed TXIDs recompute from their core bytes and
       committed tier A block ids from their blobs.
  MF7  missing values (harness/forensics/lint.py): null, '', NaN, placeholders, an all-zero root and a non-integer in a
       money/height field FAIL; 'pending:'/'missing:'/'not reconstructable:'/'not decidable:' pass; committed derived/ clean.
  MF9  privacy (lint.py): an address, IPv4/IPv6, home/temp path, URL, .local host and a private source host FAIL; the
       committed dataset is clean against the private term list (read at run time, never stored in tracked files).
  MF2  replay (harness/forensics/replay.py; G28): on a forged dataset (fake extract/derive/build, injected pin check)
       a clean replay is PASS/full and deterministic; a planted altered raw byte FAILS, also when the blob is renamed
       to its new hash and the headerchain + manifest are rewritten to match (check i); an altered or missing store
       blob, an anchor whose blob does not hash to its id, a re-derived file that differs / is missing / is extra, a
       failed extract or derive, a dataset file differing from its manifest, an expected.sha256 differing from the
       manifest, a replay whose content pins differ, and a store index differing from the
       manifest each FAIL; no store or no archive copy is reported partial. The G28 run record (verify_dataset
       check_record) FAILS when bound to another manifest, with < 2 runs, one cwd, differing reports, a FAIL or
       partial run, a changed replay tool or a swapped stored report. Committed: raw/ re-hashes, expected.sha256 equal.
  MF10 build on, never rewrite (harness/forensics/verify_dataset.py): an earlier version's file rewritten (L3), the
       file and its manifest rewritten consistently (L2), a deleted (L1) or unregistered (L1) version, an earlier
       unsealed version (L4), superseding an unknown version (L5), a ledger dropping or changing a committed sealed
       entry (L6), an expected.sha256 differing from its manifest (L7), a manifest naming another version (L8) and a
       missing ledger each FAIL; re-sealing a sealed version is refused. Committed: forensics/ verifies.
  MF3  EXT-only claim graded PROVEN (harness/forensics/audit_check.py verdict_problems; G29): a PROVEN grade resting on an
       EXT or interpretation-only input, on no input, a PROVEN-NO-INFLATION-IN-SCOPE without its scope and an unknown grade
       FAIL; RAW/DERIVED PROVEN with scope and EXT-only SPECULATION pass. Committed: the audit verdicts are clean.
  MF4  open challenge downgrades (audit_check.py verdict_problems + g29_check): a FAILS or UNRESOLVED challenge whose verdict
       stays PROVEN (listed or not), a downgraded verdict not listing it, a challenge naming no verdict, V-HF3-ALL not
       reaching per-TXID verdicts and an unknown result FAIL. G29 on forged datasets FAILS when the data changed after the
       audit, counts hide an open challenge, A1-A4 are missing, an audit file is missing or differs from the manifest, or
       the audit text carries exploit text or an IP; an earlier audit run under audit/history/ that was rewritten,
       deleted or added unrecorded, or an overturned_all_runs that hides an earlier overturn, FAIL (R25 integration).
       Committed: G29 passes on forensics/<newest>.
       MF6 also covers the audit's own Keccak (audit_check.py): the same vectors and committed tier A blobs decode.
  MF11 prune guard (harness/forensics/acquire.py): a request below the live prunedheight (height/topoheight) and a
       state read without an explicit topoheight >= prunedheight are refused BEFORE anything is sent; an unknown
       prunedheight refuses everything but GetInfo; a request at/above it is sent.

  MF12 content pins (harness/forensics/pins.py; replay.py step 1; R25 integration): on a synthetic git tree a later
       UNRELATED commit (a new file, an uncited line of a cited file, the build-suffix line of config/version.go)
       PASSES, while a changed replay tool, a changed decoder input, a changed or shifted cited line, a deleted HF3
       table, a decoder input set that gained a file, an empty pin group, a tampered aggregate and a manifest without
       content_pins each FAIL (also through replay.check_pinned); the citation parser continues ', :n' only after
       a separator and never reads 'disc:n' as code. Committed: the manifest's content pins hold at HEAD.

  python3 -I harness/kat/test_forensics_r25.py   # KATs, then each mutation on a temp copy must flip its KAT
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load or the
mutation text was not found).
"""
import gzip, hashlib, importlib.util, json, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
DATASET = ROOT / 'forensics' / 'r25'


def load(base, rel, tag):
    spec = importlib.util.spec_from_file_location(f'fx_{tag}_{id(base)}_{len(sys.modules)}', base / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def sha3(b):
    return hashlib.sha3_256(b).hexdigest()


# ------------------------------------------------------------------------------------------------- MF5
def mf5(base, committed=True):
    P = load(base, 'forensics/provenance.py', 'prov')
    fails = []

    def ok(cond, msg):
        if not cond:
            fails.append(msg)

    anchor_b, b1, b2, b3, lone = b'anchor-blob', b'block-1', b'block-2', b'block-3', b'lonely'
    A, B1, B2, B3, L = sha3(anchor_b), sha3(b1), sha3(b2), sha3(b3), sha3(lone)
    ok(P.check_i(b1, B1)[0] is True, 'MF5 good block fails (i)')
    ok(P.check_i(b1, B1, B1)[0] is True, 'MF5 good block with agreeing decoder id fails (i)')
    altered = bytearray(b1); altered[0] ^= 1
    ok(P.check_i(bytes(altered), B1)[0] is False, 'MF5 altered byte passes (i)')
    ok(P.check_i(b1, B1, '00' * 32)[0] is False, 'MF5 disagreeing decoder id passes (i)')
    ok(P.check_i(b'', sha3(b''))[0] is False, 'MF5 empty blob passes (i)')
    # chain: A -> B1 -> B2 -> B3 ; L linked by nobody; B2 failed (i) so B3 only reachable through a failed block
    tips_of = {A: [B1], B1: [B2], B2: [B3], L: [B1]}
    passed_i = {B1, B3, L}
    reached = P.tips_walk(tips_of, {A}, passed_i)
    ok(B1 in reached, 'MF5 anchored block not reached (ii)')
    ok(L not in reached, 'MF5 unanchored block reached (ii)')
    ok(B3 not in reached, 'MF5 block reached through a block that failed (i)')
    ok(B2 not in reached, 'MF5 block that failed (i) reached (ii)')
    ok(P.tips_walk(tips_of, set(), passed_i | {B2}) == set(), 'MF5 walk with no anchor reaches something')
    ok(P.classify('block', {'i': True, 'ii': True}) == P.RAW, 'MF5 fully checked block not RAW')
    for ch in ({'i': True, 'ii': False}, {'i': False, 'ii': True}, {'i': True}, {}, {'i': True, 'ii': 'yes'},
               {'i': 1, 'ii': 1}):
        ok(P.classify('block', ch) == P.EXT, f'MF5 block with checks {ch} labelled RAW')
    T = 'ab' * 32
    lists = {B1: [T]}
    c, _ = P.check_iii(T, T, lists)
    ok(P.classify('tx', c) == P.RAW and c.get('carriers') == [B1], 'MF5 good tx not RAW')
    c, _ = P.check_iii(T, 'cd' * 32, lists)
    ok(P.classify('tx', c) == P.EXT, 'MF5 tx with a different recomputed TXID labelled RAW')
    c, _ = P.check_iii(T, None, lists)
    ok(P.classify('tx', c) == P.EXT, 'MF5 tx without a recomputed TXID labelled RAW')
    c, _ = P.check_iii(T, T, {B1: ['ef' * 32]})
    ok(P.classify('tx', c) == P.EXT, 'MF5 tx in no verified block labelled RAW')
    c, _ = P.check_iii(T, T, {})
    ok(P.classify('tx', c) == P.EXT, 'MF5 tx with no verified blocks labelled RAW')
    ok(P.classify('tx', {'iii_txid': True}) == P.EXT, 'MF5 tx with only the TXID check labelled RAW')
    good = [{'kind': 'block', 'id': B1, 'class': 'RAW', 'checks': {'i': True, 'ii': True}, 'sha256': 'x'},
            {'kind': 'tx', 'id': T, 'class': 'RAW', 'checks': {'iii_txid': True, 'iii_in_block': True}, 'sha256': 'y'},
            {'kind': 'block', 'id': L, 'class': 'EXT', 'checks': {'i': True, 'ii': False}}]
    ok(P.provenance_problems(good) == [], 'MF5 validator flags a clean set')
    for bad in ({'kind': 'block', 'id': L, 'class': 'RAW', 'checks': {'i': True, 'ii': False}, 'sha256': 'x'},
                {'kind': 'block', 'id': L, 'class': 'RAW', 'checks': {'i': True}, 'sha256': 'x'},
                {'kind': 'tx', 'id': T, 'class': 'RAW', 'checks': {'iii_txid': True, 'iii_in_block': False}, 'sha256': 'y'},
                {'kind': 'block', 'id': B1, 'class': 'RAW', 'checks': {'i': True, 'ii': True}},
                {'kind': 'block', 'id': B1, 'class': 'raw', 'checks': {'i': True, 'ii': True}, 'sha256': 'x'}):
        ok(P.provenance_problems(good + [bad]) != [], f'MF5 validator passes a forged entry {bad}')
    if committed and (DATASET / 'raw' / 'provenance.json').exists():
        prov = json.loads((DATASET / 'raw' / 'provenance.json').read_text())
        ents = prov.get('tierA_blocks', []) + prov.get('tx_objects', [])
        ok(P.provenance_problems(ents) == [], 'MF5 committed provenance.json has a RAW entry without its checks')
        hc = DATASET / 'raw' / 'headerchain.jsonl.gz'
        if hc.exists():
            n = 0
            for line in gzip.open(hc, 'rt'):
                r = json.loads(line); n += 1
                if r.get('class') != 'RAW' or r.get('checks') != {'i': True, 'ii': True} or r.get('sha3_256') != r.get('blid'):
                    fails.append(f"MF5 committed headerchain row {r.get('height')} not a checked RAW row"); break
            ok(n > 0, 'MF5 committed headerchain is empty')
        for f in (DATASET / 'raw' / 'blobs').glob('*'):
            if hashlib.sha256(f.read_bytes()).hexdigest() != f.name:
                fails.append(f'MF5 committed blob {f.name[:16]} is not content-addressed'); break
    return fails


# ------------------------------------------------------------------------------------------------- MF5 (integration)
FAKE_DECODER = r"""
import hashlib, json, sys
for line in sys.stdin:
    rq = json.loads(line); b = open(rq['path'], 'rb').read()
    try:
        d = json.loads(b.decode())
    except Exception:
        d = {}
    if rq['kind'] == 'block':
        print(json.dumps({'ok': True, 'kind': 'block', 'path': rq['path'], 'id': hashlib.sha3_256(b).hexdigest(),
              'reserialize_equal': True, 'major_version': 2, 'minor_version': 2, 'height': d.get('height', 0),
              'timestamp_ms': 1, 'tips': d.get('tips', []), 'miniblocks': 10, 'tx_hashes': d.get('txs', []),
              'proof_field_nonzero': False, 'miner_tx_type': 'COINBASE', 'miner_tx_height': 0}))
    else:
        print(json.dumps({'ok': True, 'kind': 'tx', 'path': rq['path'], 'txid': d.get('txid'), 'reserialize_equal': True,
              'tx_type': 'NORMAL', 'ref_height': 1, 'ref_blid': '00' * 32, 'fees': 1, 'payloads': [], 'value': 0,
              'has_scdata': False}))
"""


def mf5_integration(base):
    """verify_acquire on a forged staging dir: only (i)+(ii) blocks become rows, (iii) gates txs, the rest is rejected."""
    fails = []
    tmp = Path(tempfile.mkdtemp(prefix='fxint_'))
    try:
        V = load(base, 'forensics/verify_acquire.py', 'va')
        (tmp / 'fake_dec.py').write_text(FAKE_DECODER)
        dec = tmp / 'dec.sh'
        dec.write_text(f'#!/bin/sh\nexec "{sys.executable}" -I "{tmp / "fake_dec.py"}"\n'); dec.chmod(0o755)
        st = tmp / 'stage'
        T_GOOD, T_EXTCARRIER, T_BADBODY = 'a1' * 32, 'b2' * 32, 'c3' * 32

        def blob(h, tips, txs=()):
            return json.dumps({'height': h, 'tips': tips, 'txs': list(txs)}, sort_keys=True).encode()
        b3 = blob(97, [], [])                         # bottom of the good chain
        b2 = blob(98, [sha3(b3)], [T_GOOD, T_BADBODY])
        b1 = blob(99, [sha3(b2)])
        anchor = blob(100, [sha3(b1)])
        lone = blob(96, ['ff' * 32], [T_EXTCARRIER])   # valid id, reached by nobody -> fails (ii)
        tampered_src = blob(95, [], [])
        good_claim = sha3(tampered_src)
        tampered = tampered_src.replace(b'95', b'94')  # one changed byte -> fails (i)
        (st / 'blocks' / '0').mkdir(parents=True)
        (st / 'txs').mkdir(parents=True)
        (st / 'anchor_live.json').write_text(json.dumps({'topo': 100, 'claimed_hash': sha3(anchor), 'blob': anchor.hex(),
                                                         'fetch_time': 't', 'source': 'live-rpc'}))
        for topo, b, claim in ((99, b1, sha3(b1)), (98, b2, sha3(b2)), (97, b3, sha3(b3)), (96, lone, sha3(lone)),
                               (95, tampered, good_claim)):
            (st / 'blocks' / '0' / f'{topo}.json').write_text(json.dumps({
                'topo_requested': topo, 'source': 'src-x', 'fetch_time': 't', 'class': 'EXT', 'claimed_hash': claim,
                'blob': b.hex(), 'header_ext': {'reward': 0}}))
        for t, body in ((T_GOOD, {'txid': T_GOOD}), (T_EXTCARRIER, {'txid': T_EXTCARRIER}), (T_BADBODY, {'txid': 'dd' * 32})):
            (st / 'txs' / f'{t}.json').write_text(json.dumps({'txid_requested': t, 'source': 'src-x', 'fetch_time': 't',
                                                             'class': 'EXT', 'as_hex': json.dumps(body).encode().hex()}))
        table = tmp / 'table.txt'
        table.write_text(''.join(f'{t} {"00" * 32} 98 false\n' for t in (T_GOOD, T_EXTCARRIER, T_BADBODY)))
        ds = tmp / 'ds'
        V.main(['--stage', str(st), '--decoder', str(dec), '--dataset', str(ds), '--store', str(tmp / 'store'),
                '--hf3-table', str(table), '--anchor-id', sha3(anchor), '--anchor-topo', '100', '--quiet'])
        rows = [json.loads(l) for l in gzip.open(ds / 'raw' / 'headerchain.jsonl.gz', 'rt')]
        got = sorted(r['blid'] for r in rows)
        if got != sorted([sha3(b1), sha3(b2), sha3(b3)]):
            fails.append(f'MF5i rows are not exactly the anchored chain: {len(got)} rows')
        rej = [json.loads(l) for l in open(ds / 'audit' / 'rejected.jsonl')]
        if not any(r['kind'] == 'block' and r['failed'] == 'i' and r['topo_ext'] == 95 for r in rej):
            fails.append('MF5i tampered block not rejected with (i)')
        if not any(r['kind'] == 'block' and r['failed'] == 'ii' and r['topo_ext'] == 96 for r in rej):
            fails.append('MF5i unanchored block not rejected with (ii)')
        prov = json.loads((ds / 'raw' / 'provenance.json').read_text())
        cls = {e['id']: e['class'] for e in prov['tx_objects']}
        if cls.get(T_GOOD) != 'RAW':
            fails.append('MF5i good tx not RAW')
        if cls.get(T_EXTCARRIER) != 'EXT':
            fails.append('MF5i tx carried only by an EXT (unanchored) block labelled RAW')
        if cls.get(T_BADBODY) != 'EXT':
            fails.append('MF5i tx whose body recomputes to another TXID labelled RAW')
        raw_shas = {p.name for p in (tmp / 'store' / 'blobs').glob('*')}
        for b in (lone, tampered):
            if hashlib.sha256(b).hexdigest() in raw_shas:
                fails.append('MF5i an EXT block blob was written to the RAW store')
    except SystemExit as e:
        fails.append(f'MF5i verify_acquire exited: {e}')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return fails


# ------------------------------------------------------------------------------------------------- MF11
def mf11(base):
    A = load(base, 'forensics/acquire.py', 'acq')
    fails = []
    sent = []

    def fake_post(url, method, params, timeout=None):
        sent.append((method, params))
        if method == 'DERO.GetInfo':
            return {'result': {'prunedheight': 7498540, 'height': 7851000, 'topoheight': 7851000}}
        return {'result': {'ok': True}}

    live = A.LiveRPC(url='http://fake', post=fake_post)
    A.time.sleep = lambda s: None
    refused = [('DERO.GetBlock', {'height': 7415466}), ('DERO.GetBlockHeaderByTopoHeight', {'topoheight': 7498539}),
               ('DERO.GetEncryptedBalance', {'address': 'x', 'topoheight': 7415465}),
               ('DERO.GetEncryptedBalance', {'address': 'x'}), ('DERO.GetSC', {'scid': 'y'}),
               ('DERO.GetBlock', {'height': '7000000'})]
    for m, p in refused:
        n0 = len(sent)
        try:
            live.call(m, p)
            fails.append(f'MF11 {m} {p} below prunedheight was sent')
        except A.PruneRefused:
            pass
        if len(sent) != n0:
            fails.append(f'MF11 {m} {p} reached the transport')
    for m, p in (('DERO.GetBlock', {'height': 7498540}), ('DERO.GetEncryptedBalance', {'address': 'x', 'topoheight': 7498540}),
                 ('DERO.GetInfo', None)):
        n0 = len(sent)
        try:
            live.call(m, p)
        except A.PruneRefused:
            fails.append(f'MF11 {m} {p} at/above prunedheight refused')
        if len(sent) != n0 + 1:
            fails.append(f'MF11 {m} {p} at/above prunedheight not sent')
    try:
        A.guard_check(None, 'DERO.GetBlock', {'height': 9_000_000})
        fails.append('MF11 unknown prunedheight did not refuse')
    except A.PruneRefused:
        pass
    return fails


# ------------------------------------------------------------------------------------------------- MF1
def mf1(base, committed=True):
    M = load(base, 'forensics/manifest_check.py', 'mfc')
    fails = []
    tmp = Path(tempfile.mkdtemp(prefix='fxmf1_'))
    try:
        ds, root = tmp / 'ds', tmp / 'root'
        (ds / 'derived').mkdir(parents=True); (root / 'harness').mkdir(parents=True); (root / 'blockchain').mkdir()
        (ds / 'derived' / 'a.json').write_text('{"x": 1}\n'); (ds / 'raw.bin').write_bytes(b'\x00\x01')
        (root / 'harness' / 'tool.py').write_text('print(1)\n'); (root / 'blockchain' / 't.go').write_text('package x\n')
        h = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
        man = {'files': {'derived/a.json': h(ds / 'derived' / 'a.json'), 'raw.bin': h(ds / 'raw.bin')},
               'tools': {'harness/tool.py': h(root / 'harness' / 'tool.py')},
               'hf3_table': {'file': 'blockchain/t.go', 'sha256': h(root / 'blockchain' / 't.go')}}
        (ds / 'manifest.json').write_text(json.dumps(man))
        if M.check(ds, root):
            fails.append('MF1 a matching manifest fails: ' + M.check(ds, root)[0])
        (ds / 'derived' / 'a.json').write_text('{"x": 2}\n')
        if not any('mismatch' in f for f in M.check(ds, root)):
            fails.append('MF1 an altered derived file passes')
        (ds / 'derived' / 'a.json').write_text('{"x": 1}\n')
        (ds / 'derived' / 'extra.json').write_text('{}\n')
        if not any('unlisted' in f for f in M.check(ds, root)):
            fails.append('MF1 an unlisted file passes')
        (ds / 'derived' / 'extra.json').unlink(); (ds / 'raw.bin').unlink()
        if not any('missing' in f for f in M.check(ds, root)):
            fails.append('MF1 a deleted listed file passes')
        (ds / 'raw.bin').write_bytes(b'\x00\x01')
        (root / 'harness' / 'tool.py').write_text('print(2)\n')
        if not any('tool changed' in f for f in M.check(ds, root)):
            fails.append('MF1 a changed pinned tool passes')
        (root / 'harness' / 'tool.py').write_text('print(1)\n')
        (root / 'blockchain' / 't.go').write_text('package y\n')
        if not any('HF3 table' in f for f in M.check(ds, root)):
            fails.append('MF1 a changed HF3 table passes')
        (tmp / 'empty').mkdir()
        if M.check(tmp / 'empty', root, manifest={'files': {}}) == []:
            fails.append('MF1 an empty manifest passes')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if committed and (DATASET / 'manifest.json').exists():
        f = M.check(DATASET, ROOT)
        if f:
            fails.append(f'MF1 committed dataset does not match its manifest: {f[0]} (+{len(f) - 1})')
    return fails


# ------------------------------------------------------------------------------------------------- MF6
KECCAK256_KAT = [  # legacy Keccak-256 (pad 0x01), published vectors
    (b'', 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'),
    (b'abc', '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'),
    (b'The quick brown fox jumps over the lazy dog', '4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15'),
]
SHA3_256_KAT = [  # FIPS 202
    (b'', 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'),
    (b'abc', '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532'),
]


def mf6(base, committed=True):
    K = load(base, 'forensics/keccak.py', 'kec')
    fails = []
    for m, want in KECCAK256_KAT:
        if K.keccak256(m).hex() != want:
            fails.append(f'MF6 keccak256({m[:10]!r}) != published vector')
    for m, want in SHA3_256_KAT:
        if K.sha3_256(m).hex() != want:
            fails.append(f'MF6 sha3_256({m[:10]!r}) != FIPS 202 vector')
    for n in (1, 135, 136, 137, 271, 272, 273, 1703):  # rate boundaries (136) and a tx-body length
        b = bytes((i * 7 + n) & 0xff for i in range(n))
        if K.sha3_256(b) != hashlib.sha3_256(b).digest():
            fails.append(f'MF6 sha3_256 differs from hashlib at length {n}')
            break
    if K.keccak256(b'abc') == K.sha3_256(b'abc'):
        fails.append('MF6 keccak256 and sha3_256 agree (padding not distinguished)')
    if committed:
        tx = DATASET / 'derived' / 'extract' / 'txs.jsonl.gz'
        if tx.exists():
            n = bad = 0
            for line in gzip.open(tx, 'rt'):
                d = json.loads(line); n += 1
                if K.keccak256(bytes.fromhex(d['core_hex'])).hex() != d['txid']:
                    bad += 1
            if n == 0 or bad:
                fails.append(f'MF6 committed TXIDs: {bad} of {n} do not recompute with the pinned Keccak-256')
        hc = DATASET / 'raw' / 'headerchain.jsonl.gz'
        if hc.exists():
            seen = 0
            for line in gzip.open(hc, 'rt'):
                r = json.loads(line)
                p = DATASET / 'raw' / 'blobs' / r['sha256']
                if p.exists():
                    seen += 1
                    if K.sha3_256(p.read_bytes()).hex() != r['blid']:
                        fails.append(f"MF6 committed block id {r['blid'][:16]} does not recompute with the pinned SHA3-256"); break
                    if seen >= 25:
                        break
    return fails


# ------------------------------------------------------------------------------------------------- MF7
def mf7(base, committed=True):
    L = load(base, 'forensics/lint.py', 'lint')
    fails = []
    good = {'fees': 'pending: 3 of 4 tx bodies not in raw/', 'state_root_post': 'not reconstructable: no held state',
            'fee': 121, 'root': 'ab' * 32, 'proof': {'result': 'not decidable: ring state unavailable'}, 'height': 7}
    if L.check_missing(good):
        fails.append('MF7 a correct record is flagged: ' + L.check_missing(good)[0])
    bad = [({'fees': None}, 'null'), ({'note': None}, 'null in a text field'), ({'state_root_pre': ''}, 'empty'), ({'note': 'n/a'}, 'placeholder'),
           ({'state_root_post': '0' * 64}, 'zero root'), ({'fees': 0.5}, 'float fee'), ({'x': [{'y': 'unknown'}]}, 'nested'),
           ({'reward_ext': 'none'}, 'placeholder word'), ({'bl_tips_height': '7,415,466?'}, 'non-integer height'),
           ({'v': float('nan')}, 'nan'), ({'fees': True}, 'bool as number')]
    for rec, what in bad:
        if not L.check_missing(rec):
            fails.append(f'MF7 a missing value rendered as {what} passes')
    if committed and (DATASET / 'derived').exists():
        f7, _f9, _n = L.scan(DATASET, None)
        if f7:
            fails.append(f'MF7 committed derived/ has {len(f7)} missing-value findings: {f7[0]}')
    return fails


# ------------------------------------------------------------------------------------------------- MF9
def mf9(base, committed=True):
    L = load(base, 'forensics/lint.py', 'lint9')
    fails = []
    clean = '{"version": "3.6.0-153.DEROHE.STARGATE+22102026.r24", "blid": "' + 'ab' * 32 + '", "source": "src-4"}'
    if L.check_privacy(clean):
        fails.append('MF9 clean text flagged: ' + L.check_privacy(clean)[0])
    addr = 'de' + 'ro1' + 'qy' + 'q' * 58
    leaks = [(addr, 'address'), ('peer ' + '.'.join(['10', '20', '30', '40']) + ':10102', 'ipv4'),
             ('/' + 'Users/someone/x', 'home path'), ('/private/' + 'tmp/x', 'temp path'), ('ht' + 'tp://x', 'url'),
             ('box.' + 'local', 'hostname'), ('[' + 'fe80::1' + ']:11011', 'ipv6')]
    for t, what in leaks:
        if not L.check_privacy('{"x": "' + t + '"}'):
            fails.append(f'MF9 a {what} passes the privacy lint')
    tmp = Path(tempfile.mkdtemp(prefix='fxmf9_'))
    try:
        host = 'node-' + 'seven.example' + '.org'
        (tmp / 'endpoints.json').write_text(json.dumps({'src-1': {'url': 'http' + '://' + host + ':10102/json_rpc'}}))
        terms = L.private_terms(tmp)
        if host not in terms:
            fails.append('MF9 a source host in the private map is not loaded as a private term')
        if not L.check_privacy('{"note": "fetched from ' + host + '"}', terms):
            fails.append('MF9 a private source host in the dataset passes')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if committed and DATASET.exists():
        _f7, f9, n = L.scan(DATASET, Path.home() / 'derohe-persist' / 'forensics_private')
        if f9:
            fails.append(f'MF9 committed dataset has {len(f9)} privacy findings: {f9[0]}')
    return fails


# ------------------------------------------------------------------------------------------------- MF2 / G28
def _h(b):
    return hashlib.sha256(b).hexdigest()


def _gz(lines):
    import io
    buf = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=buf, mtime=0) as g:
        for l in lines:
            g.write((json.dumps(l, sort_keys=True) + '\n').encode())
    return buf.getvalue()


FAKE_DERIVED = {'extract/blocks.jsonl.gz': b'extract-blocks', 'extract/txs.jsonl.gz': b'extract-txs',
                'extract/integrity.json': b'{}\n', 'archive_state/roots.jsonl.gz': b'roots',
                'archive_state/proof_checks.jsonl': b'', 'archive_state/source.json': b'{}\n',
                'tx/aa.json': b'{"tx": 1}\n', 'window.jsonl.gz': b'window'}


def _remanifest(R, ds, store):
    files = {str(p.relative_to(ds)): _h(p.read_bytes()) for p in sorted(ds.rglob('*'))
             if p.is_file() and p.name != 'manifest.json' and not str(p.relative_to(ds)).startswith('replay/')}
    m = {'dataset': ds.name, 'files': files, 'git_base_commit': 'f' * 40, 'supersedes': []}
    if store is not None:
        n, idx = R.store_index(store)
        m['tierB_store'] = {'count': n, 'index_sha256': idx}
    (ds / 'replay').mkdir(exist_ok=True)
    (ds / 'replay' / 'expected.sha256').write_text(R.expected_lines(m))
    m['files']['replay/expected.sha256'] = _h((ds / 'replay' / 'expected.sha256').read_bytes())
    (ds / 'manifest.json').write_text(json.dumps(m, indent=1, sort_keys=True) + '\n')
    return m


def _mini(R, tmp):
    """A forged dataset: one tier A block in raw/blobs, one tier B block in the store, an anchor, derived files."""
    ds, store = tmp / 'fx' / 'r25', tmp / 'store'
    (ds / 'raw' / 'blobs').mkdir(parents=True); (store / 'blobs').mkdir(parents=True)
    a_b, b_b, anc = b'tier-A block blob', b'tier-B block blob', b'anchor block blob'
    for d, b in ((ds / 'raw' / 'blobs', a_b), (store / 'blobs', b_b), (ds / 'raw' / 'blobs', anc)):
        (d / _h(b)).write_bytes(b)
    rows = [{'height': 1, 'blid': sha3(a_b), 'sha256': _h(a_b)}, {'height': 2, 'blid': sha3(b_b), 'sha256': _h(b_b)}]
    (ds / 'raw' / 'headerchain.jsonl.gz').write_bytes(_gz(rows))
    (ds / 'raw' / 'anchors.json').write_text(json.dumps([{'kind': 'block', 'id': sha3(anc), 'sha256': _h(anc)}]))
    for rel, b in FAKE_DERIVED.items():
        (ds / 'derived' / rel).parent.mkdir(parents=True, exist_ok=True)
        (ds / 'derived' / rel).write_bytes(b)
    _remanifest(R, ds, store)
    return ds, store, a_b, b_b


def _fake_run(out_files=None, extract_rc=0, derive_rc=0):
    out_files = dict(FAKE_DERIVED) if out_files is None else out_files

    def run(cmd, env=None):
        if cmd[0] == 'go':
            o = Path(cmd[cmd.index('-o') + 1]); o.parent.mkdir(parents=True, exist_ok=True); o.write_bytes(b'decoder')
            return 0, '', ''
        out = Path(cmd[cmd.index('--out') + 1])
        part = 'extract' if cmd[2].endswith('extract.py') else 'derive'
        for rel, b in out_files.items():
            is_x = rel.startswith(('extract/', 'archive_state/'))
            if (part == 'extract') == is_x and (part == 'derive' or '--archive-copy' in cmd or rel.startswith('extract/')):
                (out / rel).parent.mkdir(parents=True, exist_ok=True)
                (out / rel).write_bytes(b)
        return (extract_rc if part == 'extract' else derive_rc), f'{part} ok\n', ''
    return run


def _pin(ok=True):
    return lambda m: {'pinned_commit': m.get('git_base_commit'), 'content_pins_equal': ok,
                      'content_pin_failures': [] if ok else ['pinned file changed (replay_tools): harness/forensics/derive.py']}


def mf2(base, committed=True):
    R = load(base, 'forensics/replay.py', 'replay')
    V = load(base, 'forensics/verify_dataset.py', 'vds')
    fails = []

    def ok(cond, msg):
        if not cond:
            fails.append(msg)

    def go(tmp, ds, store, arch=True, **kw):
        a = tmp / 'arch'; a.mkdir(exist_ok=True)
        return R.replay(ds, store, a if arch else None, run=kw.pop('run', _fake_run()), pinned=kw.pop('pinned', _pin()),
                        **kw)

    def has(rep, frag):
        return rep['result'] == 'FAIL' and any(frag in x for x in rep['fail_reasons'])

    tmp = Path(tempfile.mkdtemp(prefix='fxmf2_'))
    try:
        ds, store, a_b, b_b = _mini(R, tmp)
        rep = go(tmp, ds, store)
        ok(rep['result'] == 'PASS' and rep['rederive']['mode'] == 'full' and
           rep['rederive']['equal'] == rep['rederive']['expected'] == len(FAKE_DERIVED),
           f"MF2 a clean forged dataset does not replay PASS/full: {rep['fail_reasons'][:2]}")
        ok(R.dumps(rep) == R.dumps(go(tmp, ds, store)), 'MF2 two replays of the same dataset differ')
        # the planted altered byte, manifest untouched
        pa = ds / 'raw' / 'blobs' / _h(a_b)
        pa.write_bytes(b'X' + a_b[1:])
        ok(has(go(tmp, ds, store), 'content != its address'), 'MF2 an altered raw blob passes replay')
        # ... and with the blob renamed to its new hash and the headerchain + manifest rewritten to match
        nb = b'X' + a_b[1:]
        pa.unlink(); (ds / 'raw' / 'blobs' / _h(nb)).write_bytes(nb)
        rows = [{'height': 1, 'blid': sha3(a_b), 'sha256': _h(nb)}, {'height': 2, 'blid': sha3(b_b), 'sha256': _h(b_b)}]
        (ds / 'raw' / 'headerchain.jsonl.gz').write_bytes(_gz(rows))
        _remanifest(R, ds, store)
        r2 = go(tmp, ds, store)
        ok(has(r2, 'SHA3-256 != block id'), 'MF2 an altered blob with a rewritten manifest passes replay')
        ok(not any('manifest:' in x for x in r2['fail_reasons']), 'MF2 control: the rewritten manifest itself mismatches')
        shutil.rmtree(tmp / 'fx'); shutil.rmtree(store)
        ds, store, a_b, b_b = _mini(R, tmp)
        # altered tier B blob in the store
        (store / 'blobs' / _h(b_b)).write_bytes(b_b + b'!')
        ok(has(go(tmp, ds, store), 'sha256 != headerchain row'), 'MF2 an altered store blob passes replay')
        (store / 'blobs' / _h(b_b)).unlink()
        ok(has(go(tmp, ds, store), 'absent from both'), 'MF2 a missing store blob passes replay')
        (store / 'blobs' / _h(b_b)).write_bytes(b_b)
        # anchor with a wrong id
        anc = json.loads((ds / 'raw' / 'anchors.json').read_text())
        good_anc = (ds / 'raw' / 'anchors.json').read_text()
        anc[0]['id'] = '0' * 64
        (ds / 'raw' / 'anchors.json').write_text(json.dumps(anc)); _remanifest(R, ds, store)
        ok(has(go(tmp, ds, store), 'anchor block'), 'MF2 an anchor whose blob does not hash to its id passes')
        (ds / 'raw' / 'anchors.json').write_text(good_anc); _remanifest(R, ds, store)
        ok(go(tmp, ds, store)['result'] == 'PASS', 'MF2 control: restored dataset does not PASS')
        # re-derivation differs from the manifest: altered byte, missing file, extra file
        alt = dict(FAKE_DERIVED, **{'tx/aa.json': b'{"tx": 2}\n'})
        ok(has(go(tmp, ds, store, run=_fake_run(alt)), 're-derive mismatch'), 'MF2 a differing re-derived file passes')
        miss = {k: v for k, v in FAKE_DERIVED.items() if k != 'window.jsonl.gz'}
        ok(has(go(tmp, ds, store, run=_fake_run(miss)), 're-derive missing'), 'MF2 a file replay did not re-derive passes')
        extra = dict(FAKE_DERIVED, **{'tx/bb.json': b'{}\n'})
        ok(has(go(tmp, ds, store, run=_fake_run(extra)), 're-derive extra'), 'MF2 an extra re-derived file passes')
        ok(has(go(tmp, ds, store, run=_fake_run(extract_rc=2)), 'extract.py exit'), 'MF2 an extract failure passes')
        ok(has(go(tmp, ds, store, run=_fake_run(derive_rc=1)), 'derive.py exit'), 'MF2 a derive failure passes')
        # the committed derived file altered while the re-derivation still matches the manifest: manifest check
        dp = ds / 'derived' / 'tx' / 'aa.json'
        dp.write_bytes(b'{"tx": 9}\n')
        ok(has(go(tmp, ds, store), 'manifest:'), 'MF2 a dataset file differing from its manifest passes')
        dp.write_bytes(FAKE_DERIVED['tx/aa.json'])
        # expected.sha256 differs from the manifest (manifest re-listing it)
        ep = ds / 'replay' / 'expected.sha256'
        good_ep = ep.read_text()
        ep.write_text(good_ep.replace(_h(b'window'), '0' * 64))
        m = json.loads((ds / 'manifest.json').read_text()); m['files']['replay/expected.sha256'] = _h(ep.read_bytes())
        (ds / 'manifest.json').write_text(json.dumps(m))
        ok(has(go(tmp, ds, store), 'expected.sha256 differs'), 'MF2 an expected.sha256 differing from the manifest passes')
        _remanifest(R, ds, store)
        # content pins (MF12 tests pins.py itself) / store index
        ok(has(go(tmp, ds, store, pinned=_pin(ok=False)), 'content pins differ'), 'MF2 replay with a changed content pin passes')
        (store / 'blobs' / _h(b'stray')).write_bytes(b'stray')
        ok(has(go(tmp, ds, store), 'store index differs'), 'MF2 a store whose index differs from the manifest passes')
        (store / 'blobs' / _h(b'stray')).unlink()
        # no store / no archive copy: partial (G28 rejects it), never silently full
        ok(go(tmp, ds, None)['rederive']['mode'] == 'partial', 'MF2 a replay without the store is reported full')
        ok(go(tmp, ds, store, arch=False)['rederive']['mode'] == 'partial', 'MF2 a replay without the archive is reported full')
        # G28 replay record (verify_dataset.check_record)
        good = go(tmp, ds, store)
        good['tools_sha256'] = {'harness/forensics/replay.py': 'a' * 64}  # fixed: the mutant copy has no tree around it
        txt = R.dumps(good)
        tools = dict(good['tools_sha256'])
        run1 = {'cwd_tag': 'a', 'report_sha256': _h(txt.encode()), 'result': 'PASS', 'mode': 'full'}
        rec = {'manifest_sha256': good['manifest_sha256'], 'runs': [run1, dict(run1, cwd_tag='b')], 'report': good}
        ok(V.check_record(rec, good['manifest_sha256'], tools) == [], f"G28 a good record fails: "
           f"{V.check_record(rec, good['manifest_sha256'], tools)[:1]}")
        for name, bad, msg in (
                ('other manifest', dict(rec, manifest_sha256='0' * 64), 'another manifest'),
                ('one run', dict(rec, runs=[run1]), 'need 2'),
                ('same cwd', dict(rec, runs=[run1, run1]), 'two different cwds'),
                ('reports differ', dict(rec, runs=[run1, dict(run1, cwd_tag='b', report_sha256='1' * 64)]), 'byte-identical'),
                ('a FAIL run', dict(rec, runs=[run1, dict(run1, cwd_tag='b', result='FAIL')]), 'did not PASS'),
                ('partial', dict(rec, runs=[run1, dict(run1, cwd_tag='b', mode='partial')]), 'partial'),
                ('stored report swapped', dict(rec, report=dict(good, rederive=dict(good['rederive'], equal=0))),
                 'not the one the runs hashed')):
            f = V.check_record(bad, good['manifest_sha256'], tools)
            ok(any(msg in x for x in f), f'G28 a record with {name} passes')
        ok(any('tool changed' in x for x in V.check_record(rec, good['manifest_sha256'],
                                                         {'harness/forensics/replay.py': 'b' * 64})),
           'G28 a record whose replay tool changed passes')
        ok(any('tool changed' in x for x in V.check_record(dict(rec, report=dict(good, tools_sha256={})),
                                                         good['manifest_sha256'], tools)),
           'G28 a record without replay tool hashes passes')
        ok(V.check_record(None, 'x', {}) != [], 'G28 no record passes')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if committed and (DATASET / 'manifest.json').exists():
        f, _ = R.check_raw(DATASET, None)
        if f:
            fails.append(f'MF2 committed raw/ fails its content checks: {f[0]}')
        ef, present = R.check_expected(DATASET, json.loads((DATASET / 'manifest.json').read_text()))
        if not present or ef:
            fails.append('MF2 committed replay/expected.sha256 missing or differs from the manifest')
    return fails


# ------------------------------------------------------------------------------------------------- MF10
def _version(fx, name, files, supersedes=None, dataset=None):
    d = fx / name
    for rel, b in files.items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_bytes(b)
    m = {'dataset': dataset or name, 'files': {rel: _h(b) for rel, b in sorted(files.items())},
         'supersedes': supersedes or []}
    (d / 'manifest.json').write_text(json.dumps(m, indent=1, sort_keys=True) + '\n')
    return d


def mf10(base, committed=True):
    V = load(base, 'forensics/verify_dataset.py', 'vds10')
    fails = []

    def ok(cond, msg):
        if not cond:
            fails.append(msg)

    def bad(fx, frag, msg, committed_l=None):
        f, _ = V.verify(fx, fx, committed_l, check_tools=False)
        ok(any(x.startswith(frag) for x in f), msg + (f' (got {f[:2]})' if f else ' (no failure)'))

    tmp = Path(tempfile.mkdtemp(prefix='fxmf10_'))
    try:
        def fresh():
            fx = tmp / 'fx'
            if fx.exists():
                shutil.rmtree(fx)
            fx.mkdir()
            _version(fx, 'r24', {'derived/a.json': b'{"a": 1}\n', 'raw/blobs/x': b'x'})
            V.write_ledger(fx, 'r24', seal=True)
            _version(fx, 'r25', {'derived/a.json': b'{"a": 2}\n'}, supersedes=['r24'])
            V.write_ledger(fx, 'r25', seal=False)
            return fx
        fx = fresh()
        f, _ = V.verify(fx, fx, None, check_tools=False)
        ok(f == [], f'MF10 a clean two-version tree fails: {f[:2]}')
        (fx / 'r24' / 'derived' / 'a.json').write_bytes(b'{"a": 9}\n')
        bad(fx, 'L3', 'MF10 an earlier version file rewritten in place passes')
        _version(fx, 'r24', {'derived/a.json': b'{"a": 9}\n', 'raw/blobs/x': b'x'})  # manifest rewritten to match
        bad(fx, 'L2', 'MF10 an earlier version rewritten with its manifest passes')
        fx = fresh(); shutil.rmtree(fx / 'r24')
        bad(fx, 'L1', 'MF10 a deleted earlier version passes')
        fx = fresh(); _version(fx, 'r26', {'derived/a.json': b'{}\n'})
        bad(fx, 'L1', 'MF10 an unregistered version directory passes')
        fx = fresh()
        led = json.loads((fx / 'ledger.json').read_text()); led['versions'][0]['sealed'] = False
        (fx / 'ledger.json').write_text(json.dumps(led))
        bad(fx, 'L4', 'MF10 an earlier unsealed version passes')
        fx = fresh(); _version(fx, 'r25', {'derived/a.json': b'{"a": 2}\n'}, supersedes=['r23'])
        V.write_ledger(fx, 'r25', seal=False)
        bad(fx, 'L5', 'MF10 a version superseding an unknown version passes')
        fx = fresh()
        committed_l = json.loads((fx / 'ledger.json').read_text())
        f, _ = V.verify(fx, fx, committed_l, check_tools=False)
        ok(f == [], f'MF10 the ledger equal to the committed one fails: {f[:1]}')
        led = json.loads((fx / 'ledger.json').read_text()); led['versions'] = led['versions'][1:]
        shutil.rmtree(fx / 'r24'); (fx / 'ledger.json').write_text(json.dumps(led))
        bad(fx, 'L6', 'MF10 a ledger that dropped a committed version passes', committed_l)
        fx = fresh()
        led = json.loads((fx / 'ledger.json').read_text()); led['versions'][0]['note'] = 'edited'
        (fx / 'ledger.json').write_text(json.dumps(led))
        bad(fx, 'L6', 'MF10 a changed sealed committed ledger entry passes', committed_l)
        fx = fresh()
        try:
            V.write_ledger(fx, 'r24', seal=True)
            fails.append('MF10 re-registering a sealed version is allowed')
        except SystemExit:
            pass
        fx = fresh()
        (fx / 'r25' / 'replay').mkdir()
        _version(fx, 'r25', {'derived/a.json': b'{"a": 2}\n', 'replay/expected.sha256': b'0  derived/a.json\n'},
                 supersedes=['r24'])
        V.write_ledger(fx, 'r25', seal=False)
        bad(fx, 'L7', 'MF10 an expected.sha256 differing from its manifest passes')
        fx = fresh(); _version(fx, 'r25', {'derived/a.json': b'{"a": 2}\n'}, supersedes=['r24'], dataset='r24')
        V.write_ledger(fx, 'r25', seal=False)
        bad(fx, 'L8', 'MF10 a manifest naming another version passes')
        fx = fresh(); (fx / 'ledger.json').unlink()
        bad(fx, 'L1', 'MF10 a missing ledger passes')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if committed and (DATASET.parent / 'ledger.json').exists():
        f, _ = V.verify(DATASET.parent, ROOT, V.committed_ledger(ROOT))
        if f:
            fails.append(f'MF10 committed forensics/ fails verify_dataset: {f[0]} (+{len(f) - 1})')
    return fails


# ------------------------------------------------------------------------------------------------- MF6 (audit's own)
def mf6a(base, committed=True):
    """The audit's second implementation (audit_check.py) has its own Keccak: same published vectors, rate boundaries
    against hashlib, distinct paddings; committed: its decoder recomputes tier A block ids and TXIDs."""
    A = load(base, 'forensics/audit_check.py', 'aud6')
    fails = ['MF6 audit_check: ' + f for f in A.hash_selftest()]
    for m, want in KECCAK256_KAT:
        if A.keccak256(m).hex() != want:
            fails.append(f'MF6 audit_check keccak256({m[:10]!r}) != published vector')
    for m, want in SHA3_256_KAT:
        if A.sha3_256(m).hex() != want:
            fails.append(f'MF6 audit_check sha3_256({m[:10]!r}) != FIPS 202 vector')
    if committed and (DATASET / 'raw' / 'blobs').exists():
        nb = nt = 0
        for p in sorted((DATASET / 'raw' / 'blobs').iterdir())[:120]:
            o = A._blob_job(str(p))
            if o['kind'] == 'block':
                nb += 1
            elif o['kind'] == 'tx':
                nt += 1
                tr = DATASET / 'derived' / 'tx' / f"{o['d']['txid']}.json"
                if not tr.exists():
                    fails.append(f"MF6 audit_check TXID {o['d']['txid'][:16]} has no committed tx record"); break
            else:
                fails.append(f'MF6 audit_check cannot decode committed blob {p.name[:16]}'); break
        if nb == 0 or nt == 0:
            fails.append('MF6 audit_check decoded no committed block or tx')
    return fails


# ------------------------------------------------------------------------------------------------- MF3 / MF4
def _verdict(i, grade, classes=('RAW', 'DERIVED'), scope='blocks 1..2', challenges=()):
    return {'id': i, 'audit_grade': grade, 'inputs': [{'class': c, 'what': 'x'} for c in classes], 'scope': scope,
            'challenges': list(challenges)}


def _chal(i, result, affects=()):
    return {'id': i, 'result': result, 'affects': list(affects)}


def mf3(base, committed=True):
    """MF3: an EXT-only (or interpretation-only) claim graded PROVEN FAILS (audit_check.verdict_problems)."""
    A = load(base, 'forensics/audit_check.py', 'aud3')
    fails = []
    vp = A.verdict_problems

    def bad(vs, ch, msg):
        if not vp(vs, ch):
            fails.append('MF3 ' + msg)
    if vp([_verdict('V1', 'PROVEN-NO-INFLATION-IN-SCOPE')], []):
        fails.append('MF3 negative control: a RAW/DERIVED PROVEN verdict with its scope is flagged')
    if vp([_verdict('V1', 'SPECULATION', classes=('EXT',))], []):
        fails.append('MF3 negative control: an EXT-only claim graded SPECULATION is flagged')
    bad([_verdict('V1', 'PROVEN-INFLATION', classes=('EXT',))], [], 'EXT-only PROVEN-INFLATION passes')
    bad([_verdict('V1', 'PROVEN-NO-INFLATION-IN-SCOPE', classes=('RAW', 'EXT'))], [], 'PROVEN with an EXT input passes')
    bad([_verdict('V1', 'PROVEN-NO-INFLATION-IN-SCOPE', classes=('INTERPRETATION',))], [], 'interpretation-only PROVEN passes')
    bad([_verdict('V1', 'PROVEN-NO-INFLATION-IN-SCOPE', classes=())], [], 'PROVEN with no inputs passes')
    bad([_verdict('V1', 'PROVEN-NO-INFLATION-IN-SCOPE', scope='')], [], 'PROVEN-NO-INFLATION-IN-SCOPE without a scope passes')
    bad([_verdict('V1', 'PROBABLY-FINE')], [], 'an unknown grade passes')
    if committed and (DATASET / 'audit' / 'audit_report.json').exists():
        rep = json.loads((DATASET / 'audit' / 'audit_report.json').read_text())
        ch = json.loads((DATASET / 'audit' / 'challenges.json').read_text())['challenges']
        f = vp(rep['verdicts'], ch)
        if f:
            fails.append(f'MF3 committed audit verdicts: {f[0]}')
        for v in rep['verdicts']:
            if v['audit_grade'].startswith('PROVEN') and any(i['class'] not in ('RAW', 'DERIVED') for i in v['inputs']):
                fails.append(f"MF3 committed {v['id']} PROVEN on a non-evidence input"); break
    return fails


def _forge_audit(tmp, A, chal, verdicts, counts=None, extra_audit_text='', gz_text=None, history=None, all_runs=None):
    ds = tmp / 'rX'
    (ds / 'audit').mkdir(parents=True, exist_ok=True)
    (ds / 'derived').mkdir(exist_ok=True)
    (ds / 'derived' / 'x.json').write_text('{"a": 1}\n')
    if gz_text is not None:
        (ds / 'derived' / 'y.jsonl.gz').write_bytes(gzip.compress(gz_text.encode(), mtime=0))
    man = {'files': {str(p.relative_to(ds)): _h(p.read_bytes()) for p in sorted((ds / 'derived').iterdir())}, 'hf3_table': {'sha256': 'h'},
           'tierB_store': {'index_sha256': 'i'}, 'git_base_commit': 'c'}
    rerun = {'selftest': {'failures': []}, 'scan': {'hits': []}}
    n_fail = sum(c['result'] == 'FAILS' for c in chal)
    n_open = sum(c['result'] == 'UNRESOLVED' for c in chal)
    rep = {'binding': A.binding_of(man), 'implementation': {'shares_code_with_builder': False},
           'counts': counts or {'overturned': n_fail, 'unresolved': n_open}, 'verdicts': verdicts, 'rerun': rerun,
           'rerun_sha256': hashlib.sha256(json.dumps(rerun, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
    if history is not None:  # earlier audit runs kept under audit/history/<run>/ (R25 integration)
        for run, n_over in history:
            hd = ds / 'audit' / 'history' / run
            hd.mkdir(parents=True, exist_ok=True)
            (hd / 'audit_report.json').write_text(json.dumps({'counts': {'overturned': n_over}, 'verdicts': []}))
            (hd / 'challenges.json').write_text(json.dumps({'challenges': [{'id': f'H{i}', 'result': 'FAILS'} for i in range(n_over)]}))
        rep['history'] = A.audit_history(ds)
        rep['counts']['overturned_all_runs'] = (n_fail + sum(n for _, n in history)) if all_runs is None else all_runs
    (ds / 'audit' / 'audit_report.json').write_text(json.dumps(rep))
    (ds / 'audit' / 'challenges.json').write_text(json.dumps({'challenges': chal}))
    (ds / 'audit' / 'AUDIT.md').write_text('# audit\n' + extra_audit_text)
    for k in ('audit_report.json', 'challenges.json', 'AUDIT.md'):
        man['files']['audit/' + k] = _h((ds / 'audit' / k).read_bytes())
    (ds / 'manifest.json').write_text(json.dumps(man))
    return ds


def mf4(base, committed=True):
    """MF4: a verdict with an OPEN (UNRESOLVED) or FAILS audit challenge is downgraded, or G29 FAILS."""
    A = load(base, 'forensics/audit_check.py', 'aud4')
    fails = []
    vp = A.verdict_problems
    req = [_chal(x, 'HOLDS', ['V1']) for x in ('A1', 'A2', 'A3', 'A4')]
    good_v = [_verdict('V1', 'PROVEN-NO-INFLATION-IN-SCOPE', challenges=['A1', 'A2', 'A3', 'A4'])]
    if vp(good_v, req):
        fails.append('MF4 negative control: all challenges HOLD yet flagged')
    for res in ('UNRESOLVED', 'FAILS'):
        ch = req + [_chal('A5', res, ['V1'])]
        if not vp([_verdict('V1', 'PROVEN-NO-INFLATION-IN-SCOPE', challenges=['A1', 'A5'])], ch):
            fails.append(f'MF4 a PROVEN verdict with a {res} challenge it lists passes')
        if not vp([_verdict('V1', 'PROVEN-NO-INFLATION-IN-SCOPE', challenges=['A1'])], ch):
            fails.append(f'MF4 a PROVEN verdict named by a {res} challenge (not listing it) passes')
        if vp([_verdict('V1', 'NOT-DECIDABLE-FROM-PUBLIC-DATA', challenges=['A1', 'A5'])], ch):
            fails.append(f'MF4 negative control: the downgraded verdict for a {res} challenge is flagged')
        if not vp([_verdict('V1', 'NOT-DECIDABLE-FROM-PUBLIC-DATA', challenges=['A1'])], ch):
            fails.append(f'MF4 a downgraded verdict that does not list its {res} challenge passes')
        if not vp(good_v, req + [_chal('A5', res, [])]):
            fails.append(f'MF4 a {res} challenge naming no verdict passes')
        if not vp([_verdict('V-HF3-aa', 'PROVEN-INFLATION', challenges=['A5'])], req + [_chal('A5', res, ['V-HF3-ALL'])]):
            fails.append(f'MF4 V-HF3-ALL does not reach a per-TXID verdict ({res})')
        if vp([_verdict('V-HF3-aa', 'NOT-DECIDABLE-FROM-PUBLIC-DATA', challenges=['A5'])], req + [_chal('A5', res, ['V-HF3-ALL'])]):
            fails.append(f'MF4 negative control: a downgraded per-TXID verdict under V-HF3-ALL is flagged ({res})')
        if not vp([_verdict('V-HF3-aa', 'NOT-DECIDABLE-FROM-PUBLIC-DATA', challenges=[])], req + [_chal('A5', res, ['V-HF3-ALL'])]):
            fails.append(f'MF4 a per-TXID verdict not listing a V-HF3-ALL {res} challenge passes')
        # a PROVEN verdict that lists a failed challenge aimed at ANOTHER (downgraded) verdict must still be refused
        two = [_verdict('V1', 'PROVEN-NO-INFLATION-IN-SCOPE', challenges=['A1', 'A5']), _verdict('V9', 'pending', challenges=['A5'])]
        if not vp(two, req + [_chal('A5', res, ['V9'])]):
            fails.append(f'MF4 a PROVEN verdict listing a {res} challenge aimed elsewhere passes')
    if not vp(good_v, req + [_chal('A6', 'MAYBE', ['V1'])]):
        fails.append('MF4 a result other than HOLDS/FAILS/UNRESOLVED passes')
    # G29 on forged datasets
    tmp = Path(tempfile.mkdtemp(prefix='fxmf4_'))
    try:
        ok_ch = req + [_chal('A5', 'UNRESOLVED', ['V2'])]
        ok_v = good_v + [_verdict('V2', 'pending', challenges=['A5'])]
        ds = _forge_audit(tmp / 'g', A, ok_ch, ok_v)
        f, _ = A.g29_check(ds, ROOT, '')
        if f:
            fails.append(f'MF4 G29 negative control fails: {f[0]}')
        ds = _forge_audit(tmp / 'p', A, ok_ch, good_v + [_verdict('V2', 'PROVEN-NO-INFLATION-IN-SCOPE', challenges=['A5'])])
        if not A.g29_check(ds, ROOT, '')[0]:
            fails.append('MF4 G29 passes with an UNRESOLVED challenge whose verdict stays PROVEN')
        ds = _forge_audit(tmp / 'b', A, ok_ch, ok_v)
        (ds / 'derived' / 'x.json').write_text('{"a": 2}\n')
        m = json.loads((ds / 'manifest.json').read_text()); m['files']['derived/x.json'] = _h((ds / 'derived' / 'x.json').read_bytes())
        (ds / 'manifest.json').write_text(json.dumps(m))
        if not A.g29_check(ds, ROOT, '')[0]:
            fails.append('MF4 G29 passes when the data changed after the audit (binding)')
        ds = _forge_audit(tmp / 'c', A, ok_ch, ok_v, counts={'overturned': 0, 'unresolved': 0})
        if not A.g29_check(ds, ROOT, '')[0]:
            fails.append('MF4 G29 passes when the report hides an UNRESOLVED challenge in its counts')
        ds = _forge_audit(tmp / 'r', A, [c for c in ok_ch if c['id'] != 'A4'], ok_v)
        if not A.g29_check(ds, ROOT, '')[0]:
            fails.append('MF4 G29 passes without the required challenge A4')
        ds = _forge_audit(tmp / 'm', A, ok_ch, ok_v)
        (ds / 'audit' / 'AUDIT.md').unlink()
        if not A.g29_check(ds, ROOT, '')[0]:
            fails.append('MF4 G29 passes with audit/AUDIT.md missing')
        ds = _forge_audit(tmp / 'x', A, ok_ch, ok_v, extra_audit_text='Here is a working exploit script for it.\n')
        if not A.g29_check(ds, ROOT, '')[0]:
            fails.append('MF4 G29 passes with exploit text in the audit')
        ds = _forge_audit(tmp / 'i', A, ok_ch, ok_v, extra_audit_text='source 8.8.4.4 answered\n')
        if not A.g29_check(ds, ROOT, '')[0]:
            fails.append('MF4 G29 passes with an IP address in the audit')
        ds = _forge_audit(tmp / 'z', A, ok_ch, ok_v, gz_text='{"peer": "8.8.4.4"}\n')
        if not A.g29_check(ds, ROOT, '')[0]:
            fails.append('MF4 G29 passes with an IP address inside a compressed dataset file')
        ds = _forge_audit(tmp / 'h', A, ok_ch, ok_v)
        (ds / 'audit' / 'AUDIT.md').write_text('# edited after the manifest\n')
        if not A.g29_check(ds, ROOT, '')[0]:
            fails.append('MF4 G29 passes with an audit file differing from the manifest')
        # audit history (an overturn stays on record after the builder fixes the claim at its source)
        ds = _forge_audit(tmp / 'hg', A, ok_ch, ok_v, history=[('audit-1', 1)])
        f, s = A.g29_check(ds, ROOT, '')
        if f or s.get('overturned_all_runs') != 1:
            fails.append(f'MF4 G29 fails a good report with one earlier overturn on record: {f[:1]} {s.get("overturned_all_runs")}')
        ds = _forge_audit(tmp / 'hw', A, ok_ch, ok_v, history=[('audit-1', 1)], all_runs=0)
        if not A.g29_check(ds, ROOT, '')[0]:
            fails.append('MF4 G29 passes when overturned_all_runs hides an earlier overturn')
        ds = _forge_audit(tmp / 'he', A, ok_ch, ok_v, history=[('audit-1', 1)])
        (ds / 'audit' / 'history' / 'audit-1' / 'audit_report.json').write_text('{"counts": {"overturned": 0}}')
        if not A.g29_check(ds, ROOT, '')[0]:
            fails.append('MF4 G29 passes when an earlier audit report was rewritten after it was recorded')
        ds = _forge_audit(tmp / 'hd', A, ok_ch, ok_v, history=[('audit-1', 1)])
        shutil.rmtree(ds / 'audit' / 'history' / 'audit-1')
        if not A.g29_check(ds, ROOT, '')[0]:
            fails.append('MF4 G29 passes when an earlier audit run was deleted')
        ds = _forge_audit(tmp / 'ha', A, ok_ch, ok_v, history=[('audit-1', 1)])
        (ds / 'audit' / 'history' / 'audit-9').mkdir()
        if not A.g29_check(ds, ROOT, '')[0]:
            fails.append('MF4 G29 passes when an unrecorded audit history run appears')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if committed and (DATASET.parent / 'ledger.json').exists() and (DATASET / 'audit' / 'audit_report.json').exists():
        ok, det = A.g29(ROOT)
        if not ok:
            fails.append(f'MF4 committed G29 fails: {det}')
    return fails



def mf12(base, committed=True):
    """Content pins: an unrelated commit PASSES, a changed pinned byte FAILS (R25 integration, replay at any commit)."""
    P = load(base, 'forensics/pins.py', 'pins')
    R = load(base, 'forensics/replay.py', 'replay')
    import subprocess
    fails = []

    def ok(cond, msg):
        if not cond:
            fails.append(msg)

    tmp = Path(tempfile.mkdtemp(prefix='fxmf12_'))
    try:
        root = tmp / 'tree'
        files = {t: f'# replay tool {t}\n' for t in P.REPLAY_TOOLS}
        files['harness/forensics/derive.py'] = ("C = {\n    'a': 'blockchain/v.go:2-3',\n"
                                                "    'b': 'p2p/x.go:1 (one), :4 (four); disc:7',\n}\n")
        files['blockchain/v.go'] = 'package v\nvar A = 1\nvar B = 2\nvar C = 3\nvar D = 4\n'
        files['p2p/x.go'] = 'package x\nvar A = 1\nvar B = 2\nvar C = 3\nvar D = 4\n'
        files['config/version.go'] = 'package config\n\nvar Version = semver.MustParse("1.0.0+r25")\n'
        files[P.HF3_TABLE] = 'package blockchain\nvar T = 75\n'
        files['go.mod'] = 'module m\n'
        for rel, txt in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(txt)
        dec = ['blockchain/v.go', 'config/version.go', 'go.mod']
        lister = lambda r, goos=None, goarch=None: sorted(dec)
        g = lambda *a: subprocess.run(['git', '-C', str(root), *a], capture_output=True, text=True)
        g('init', '-q'); g('add', '-A'); g('-c', 'user.email=k@t', '-c', 'user.name=kat', 'commit', '-qm', 'pinned')
        pins = P.compute(root, 'darwin', 'arm64', lister)
        ok(sorted(pins['cited_lines']) == ['blockchain/v.go:2-3', 'p2p/x.go:1-1', 'p2p/x.go:4-4'],
           f"MF12 citation parse: {sorted(pins['cited_lines'])}")
        chk = lambda p=None, lst=lister: P.check(pins if p is None else p, root, lst)
        ok(chk() == [], f'MF12 freshly pinned tree fails: {chk()[:1]}')

        def edit(rel, old, new):
            s = (root / rel).read_text(); assert old in s, (rel, old); (root / rel).write_text(s.replace(old, new, 1))
        # an unrelated commit: new file, an uncited line of a cited file, the build suffix line
        (root / 'README').write_text('unrelated\n')
        edit('p2p/x.go', 'var B = 2', 'var B = 22')
        edit('config/version.go', '1.0.0+r25', '1.0.0+r26')
        g('add', '-A'); g('-c', 'user.email=k@t', '-c', 'user.name=kat', 'commit', '-qm', 'unrelated')
        ok(chk() == [], f'MF12 an unrelated later commit FAILS: {chk()[:1]}')
        m = {'git_base_commit': 'f' * 40, 'content_pins': pins}
        cp = R.check_pinned(m, root, lister)
        ok(cp['content_pins_equal'] is True and cp['pinned_commit'] == 'f' * 40,
           f"MF12 replay.check_pinned fails an unrelated commit: {cp['content_pin_failures'][:1]}")
        ok(R.check_pinned({'git_base_commit': 'x'}, root, lister)['content_pins_equal'] is False,
           'MF12 a manifest without content_pins passes')
        cases = [
            ('a changed replay tool', lambda: edit('harness/forensics/derive.py', 'C = {', 'C = {  # edited'), 'replay_tools'),
            ('a changed decoder input', lambda: edit('blockchain/v.go', 'var D = 4', 'var D = 44'), 'decoder_inputs'),
            ('a changed cited line', lambda: edit('p2p/x.go', 'var C = 3', 'var C = 33'), 'cited lines changed'),
            ('a shifted cited line', lambda: edit('p2p/x.go', 'package x\n', 'package x\n// moved\n'), 'cited lines changed'),
            ('a cited range change', lambda: edit('blockchain/v.go', 'var B = 2', 'var B = 9'), 'cited lines changed'),
            ('a deleted HF3 table', lambda: (root / P.HF3_TABLE).unlink(), 'pinned file missing'),
            ('a changed non-version line of version.go', lambda: edit('config/version.go', 'package config', 'package config2'),
             'decoder_inputs'),
        ]
        snap = {rel: (root / rel).read_bytes() for rel in files if (root / rel).exists()}
        for name, act, frag in cases:
            act()
            f = chk()
            ok(any(frag in x for x in f), f'MF12 {name} passes: {f[:1]}')
            ok(R.check_pinned(m, root, lister)['content_pins_equal'] is False, f'MF12 replay.check_pinned passes {name}')
            for rel, b in snap.items():
                (root / rel).parent.mkdir(parents=True, exist_ok=True); (root / rel).write_bytes(b)
        ok(chk() == [], 'MF12 restore failed')
        more = lambda r, goos=None, goarch=None: sorted(dec + ['blockchain/new.go'])
        ok(any('input set changed' in x for x in chk(lst=more)), 'MF12 a decoder input set that gained a file passes')
        ok(any('is empty' in x for x in chk(dict(pins, replay_tools={}))), 'MF12 an empty pin group passes')
        ok(any('aggregate' in x for x in chk(dict(pins, aggregate_sha256='0' * 64))), 'MF12 a tampered aggregate passes')
        ok(P.citations('a.go:5 disc:9, :7') == [('a.go', 5, 5), ('a.go', 7, 7)], 'MF12 bare continuation parse')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if committed and (DATASET / 'manifest.json').exists():
        m = json.loads((DATASET / 'manifest.json').read_text())
        f = P.check(m.get('content_pins'), ROOT)
        if f:
            fails.append(f'MF12 committed manifest content pins fail at HEAD: {f[0]}')
    return fails


MUTATIONS = [
    ('MF5', 'forensics/provenance.py', "    if got != (claimed_id or '').lower():", "    if False:"),
    ('MF5', 'forensics/provenance.py', "    if decoder_id is not None and decoder_id.lower() != got:", "    if False:"),
    ('MF5', 'forensics/provenance.py', "            if t in passed_i and t not in reached:", "            if t not in reached:"),
    ('MF5', 'forensics/provenance.py', "    reached, stack = set(), [a for a in anchors if a in tips_of]",
     "    reached, stack = set(), [a for a in tips_of]"),
    ('MF5', 'forensics/provenance.py', "    if not carriers:", "    if False:"),
    ('MF5', 'forensics/provenance.py', "    if not txid_recomputed or txid_recomputed.lower() != a:", "    if not txid_recomputed:"),
    ('MF5', 'forensics/provenance.py', "all(checks.get(c) is True for c in need)", "all(checks.get(c) for c in need)"),
    ('MF5', 'forensics/provenance.py', "            if miss:", "            if False:"),
    ('MF5', 'forensics/provenance.py', "            if not e.get('sha256'):", "            if False:"),
    ('MF5', 'forensics/verify_acquire.py', "    verified_lists = {i: by_id[i][3]['tx_hashes'] for i in reached}",
     "    verified_lists = {i: by_id[i][3]['tx_hashes'] for i in passed_i}"),
    ('MF5', 'forensics/verify_acquire.py', "        if cls != P.RAW:\n            continue\n", ""),
    ('MF5', 'forensics/verify_acquire.py', "    reached = P.tips_walk(tips_of, {anchor_id}, passed_i)", "    reached = set(passed_i)"),
    ('MF11', 'forensics/acquire.py', "int(p[k]) < int(prunedheight)", "int(p[k]) < 0"),
    ('MF11', 'forensics/acquire.py', "        if t is None or int(t) < int(prunedheight):", "        if t is not None and int(t) < 0:"),
    ('MF11', 'forensics/acquire.py', "        guard_check(self.prunedheight, method, params)\n", ""),
    ('MF11', 'forensics/acquire.py', "        raise PruneRefused('prunedheight unknown: refusing every live request but GetInfo')", "        return True"),
    ('MF1', 'forensics/manifest_check.py', "    for rel in sorted(on_disk - set(listed)):", "    for rel in []:"),
    ('MF1', 'forensics/manifest_check.py', "        elif sha(p) != h:\n            fails.append(f'sha256 mismatch: {rel}')",
     "        elif False:\n            fails.append(f'sha256 mismatch: {rel}')"),
    ('MF1', 'forensics/manifest_check.py', "            fails.append(f'listed file missing: {rel}')", "            pass"),
    ('MF1', 'forensics/manifest_check.py', "        elif sha(p) != h:\n            fails.append(f'pinned tool changed: {rel}')",
     "        elif False:\n            fails.append(f'pinned tool changed: {rel}')"),
    ('MF1', 'forensics/manifest_check.py', "    if t and (not", "    if False and (not"),
    ('MF1', 'forensics/manifest_check.py', "    if not listed:", "    if False:"),
    ('MF6', 'forensics/keccak.py', "    return _sponge(data, 136, 0x01, 32)", "    return _sponge(data, 136, 0x06, 32)"),
    ('MF6', 'forensics/keccak.py', "    msg[-1] |= 0x80", "    msg[-1] |= 0x00"),
    ('MF6', 'forensics/keccak.py', "0x8000000080008008,", "0x8000000080008009,"),
    ('MF6', 'forensics/keccak.py', "_ROT = [[0, 36, 3, 41, 18]", "_ROT = [[0, 36, 3, 41, 19]"),
    ('MF6', 'forensics/keccak.py', "        A[0][0] ^= rc", "        A[0][0] ^= 0"),
    ('MF7', 'forensics/lint.py', "    if o is None:", "    if False:"),
    ('MF7', 'forensics/lint.py', "        if s == '':", "        if False:"),
    ('MF7', 'forensics/lint.py', "        elif s.lower() in PLACEHOLDERS:", "        elif False:"),
    ('MF7', 'forensics/lint.py', "v.lower() == ZERO32:", "v.lower() == 'x':"),
    ('MF7', 'forensics/lint.py', "            if k in NUM_OR_MISSING and", "            if False and"),
    ('MF7', 'forensics/lint.py', "math.isnan(o) or math.isinf(o)", "False"),
    ('MF9', 'forensics/lint.py', "        m = rx.search(text)\n        if m:", "        m = rx.search(text)\n        if False:"),
    ('MF9', 'forensics/lint.py', "        if t in text:", "        if False:"),
    ('MF9', 'forensics/lint.py', "de[rt]oi?1", "de[rt]oi?9"),
    ('MF9', 'forensics/lint.py', "(?:Users|home)", "(?:Userz|homez)"),
    ('MF9', 'forensics/lint.py', "            terms.add(m.group(1))", "            pass"),
    ('MF9', 'forensics/lint.py', "(?:local|lan|home|internal)", "(?:localx)"),
    ('MF2', 'forensics/replay.py', "        if fsha(p) != p.name:", "        if False:"),
    ('MF2', 'forensics/replay.py', "        if hashlib.sha3_256(b).hexdigest() != r['blid']:", "        if False:"),
    ('MF2', 'forensics/replay.py', "        if sha(b) != r['sha256']:", "        if False:"),
    ('MF2', 'forensics/replay.py', "    if store and n_absent:", "    if False:"),
    ('MF2', 'forensics/replay.py', "        if not p.exists() or hashlib.sha3_256(p.read_bytes()).hexdigest() != a.get('id'):",
     "        if not p.exists():"),
    ('MF2', 'forensics/replay.py', "    mism = sorted(k for k in exp if k in got and got[k] != exp[k])", "    mism = []"),
    ('MF2', 'forensics/replay.py', "'missing': sorted(set(exp) - set(got))", "'missing': []"),
    ('MF2', 'forensics/replay.py', "'extra': sorted(set(got) - set(exp))", "'extra': []"),
    ('MF2', 'forensics/replay.py', "    fails += [f'manifest: {x}' for x in mf[:5]]", "    pass"),
    ('MF2', 'forensics/replay.py', "        if idx != pin.get('index_sha256'):", "        if False:"),
    ('MF2', 'forensics/replay.py', "    ok = p.read_text() == expected_lines(m)", "    ok = True"),
    ('MF2', 'forensics/replay.py', "    if not rep['pinned']['content_pins_equal']:", "    if False:"),
    ('MF12', 'forensics/pins.py', "            elif now != h:\n                fails.append(f'pinned file changed ({grp}): {rel}')",
     "            elif False:\n                fails.append(f'pinned file changed ({grp}): {rel}')"),
    ('MF12', 'forensics/pins.py', "        if now is None or now != h:\n            fails.append(f'cited lines changed: {key}')",
     "        if now is None:\n            fails.append(f'cited lines changed: {key}')"),
    ('MF12', 'forensics/pins.py', "            if now_set != pinned_set:", "            if False:"),
    ('MF12', 'forensics/pins.py', "    if pins.get('aggregate_sha256') != aggregate(pins):", "    if False:"),
    ('MF12', 'forensics/pins.py', "        b = rx.sub(rep, b)", "        pass"),
    ('MF12', 'forensics/pins.py', "        elif not cur or (m.start() and text[m.start() - 1] not in ' ,('):", "        elif not cur:"),
    ('MF12', 'forensics/pins.py', "            if now is None:\n                fails.append(f'pinned file missing ({grp}): {rel}')",
     "            if now is None:\n                pass"),
    ('MF12', 'forensics/pins.py', "            fails.append(f'content pin group {grp} is empty')", "            pass"),
    ('MF12', 'forensics/replay.py', "    f = (pins.check(cp, root, lister) if cp else", "    f = ([] if cp else"),
    ('MF12', 'forensics/replay.py', "         ['manifest has no content_pins (written before the R25 integration: re-pin with write_manifest.py)'])",
     "         [])"),
    ('MF2', 'forensics/replay.py', "            if rc:\n                fails.append(f'extract.py exit {rc}')",
     "            if False:\n                fails.append(f'extract.py exit {rc}')"),
    ('MF2', 'forensics/replay.py', "        if rc:\n            fails.append(f'derive.py exit {rc}')",
     "        if False:\n            fails.append(f'derive.py exit {rc}')"),
    ('MF2', 'forensics/replay.py', "    rep['result'] = 'PASS' if not fails else 'FAIL'", "    rep['result'] = 'PASS'"),
    ('MF2', 'forensics/replay.py', "            if not archive:\n                mode = 'partial'", "            if not archive:\n                pass"),
    ('MF2', 'forensics/replay.py', "            mode = 'partial'\n            steps['extract']", "            steps['extract']"),
    ('MF2', 'forensics/verify_dataset.py', "    if rec.get('manifest_sha256') != manifest_sha:", "    if False:"),
    ('MF2', 'forensics/verify_dataset.py', "    if len(runs) < 2:", "    if False:"),
    ('MF2', 'forensics/verify_dataset.py', "    if len({r.get('cwd_tag') for r in runs}) < 2:", "    if False:"),
    ('MF2', 'forensics/verify_dataset.py', "    if len({r.get('report_sha256') for r in runs}) != 1:", "    if False:"),
    ('MF2', 'forensics/verify_dataset.py', "    if any(r.get('result') != 'PASS' for r in runs) or not runs:", "    if False:"),
    ('MF2', 'forensics/verify_dataset.py', "    if any(r.get('mode') != 'full' for r in runs) or not runs:", "    if False:"),
    ('MF2', 'forensics/verify_dataset.py', "    if not rt or any(tools_now.get(k) != h for k, h in rt.items()):", "    if False:"),
    ('MF2', 'forensics/verify_dataset.py', "    if rep.get('result') != 'PASS' or sha(txt.encode()) not in", "    if False and sha(txt.encode()) not in"),
    ('MF2', 'forensics/verify_dataset.py', "        return ['G28 no replay run record']", "        return []"),
    ('MF10', 'forensics/verify_dataset.py', "            if sha(mb) != e.get('manifest_sha256'):", "            if False:"),
    ('MF10', 'forensics/verify_dataset.py', "        elif v != newest:", "        elif False:"),
    ('MF10', 'forensics/verify_dataset.py', "            fails.append(f'L1 {v} has a directory but no ledger entry')", "            pass"),
    ('MF10', 'forensics/verify_dataset.py', "            fails.append(f'L1 {v} is in the ledger but its directory or manifest is gone')", "            pass"),
    ('MF10', 'forensics/verify_dataset.py', "        fails += [f'L3 {v}: {x}' for x in mf[:20]]", "        pass"),
    ('MF10', 'forensics/verify_dataset.py', "            if sup not in sealed_before:", "            if False:"),
    ('MF10', 'forensics/verify_dataset.py', "            fails.append('L6 the ledger does not extend the committed ledger (an entry was removed or reordered)')",
     "            pass"),
    ('MF10', 'forensics/verify_dataset.py', "                if c.get('sealed') and (c != e):", "                if False:"),
    ('MF10', 'forensics/verify_dataset.py', "            if ex.read_text() != want:", "            if False:"),
    ('MF10', 'forensics/verify_dataset.py', "        if m.get('dataset') != v:", "        if False:"),
    ('MF10', 'forensics/verify_dataset.py', "            if x.get('sealed'):\n                raise SystemExit", "            if False:\n                raise SystemExit"),
    ('MF10', 'forensics/verify_dataset.py', "        return ['L1 forensics/ledger.json missing'], summ", "        return [], summ"),
    ('MF6', 'forensics/audit_check.py', "    return _sponge(b, 136, 0x01, 32)", "    return _sponge(b, 136, 0x06, 32)"),
    ('MF6', 'forensics/audit_check.py', "R[0] ^= R[8]; R[4] ^= R[8]; R[5] ^= R[8]; R[6] ^= R[8]", "R[0] ^= R[8]; R[4] ^= R[8]; R[5] ^= R[8]"),
    ('MF6', 'forensics/audit_check.py', "        rot[(x, y)] = ((t + 1) * (t + 2) // 2) % 64", "        rot[(x, y)] = ((t + 1) * (t + 2) // 2) % 63"),
    ('MF6', 'forensics/audit_check.py', "            A[y] = b0 ^ ((~b1) & b2)", "            A[y] = b0 ^ (b1 & b2)"),
    ('MF6', 'forensics/audit_check.py', "    m[-1] |= 0x80", "    m[-1] |= 0x00"),
    ('MF3', 'forensics/audit_check.py', "            if any(i.get('class') not in EVIDENCE for i in ins):", "            if False:"),
    ('MF3', 'forensics/audit_check.py', "EVIDENCE = ('RAW', 'DERIVED')", "EVIDENCE = ('RAW', 'DERIVED', 'EXT', 'INTERPRETATION')"),
    ('MF3', 'forensics/audit_check.py', "            if not ins:\n", "            if False:\n"),
    ('MF3', 'forensics/audit_check.py', "            if not v.get('scope') and g == 'PROVEN-NO-INFLATION-IN-SCOPE':", "            if False:"),
    ('MF3', 'forensics/audit_check.py', "        if g not in GRADES:", "        if False:"),
    ('MF4', 'forensics/audit_check.py', "            hit = sorted(set(v.get('challenges', [])) & bad)", "            hit = []"),
    ('MF4', 'forensics/audit_check.py', "    bad = {c['id'] for c in challenges if c.get('result') in ('FAILS', 'UNRESOLVED')}", "    bad = set()"),
    ('MF4', 'forensics/audit_check.py', "                    if c['id'] not in v.get('challenges', []):", "                    if False:"),
    ('MF4', 'forensics/audit_check.py', "            if not aff:", "            if False:"),
    ('MF4', 'forensics/audit_check.py', "(a == 'V-HF3-ALL' and", "(False and"),
    ('MF4', 'forensics/audit_check.py', "        if c.get('result') not in ('HOLDS', 'FAILS', 'UNRESOLVED'):", "        if False:"),
    ('MF4', 'forensics/audit_check.py', "    if rep.get('binding', {}).get('data_sha256') != b['data_sha256']:", "    if False:"),
    ('MF4', 'forensics/audit_check.py', "    if rep.get('counts', {}).get('overturned') != n_fail or", "    if False and"),
    ('MF4', 'forensics/audit_check.py', "        if not any(c.get('id', '').startswith(want) for c in chs):", "        if False:"),
    ('MF4', 'forensics/audit_check.py', "    if sc['hits']:", "    if False:"),
    ('MF4', 'forensics/audit_check.py', "        if man.get('files', {}).get('audit/' + k) != got:", "        if False:"),
    ('MF4', 'forensics/audit_check.py', "        if p.suffix == '.gz':", "        if False:"),
    ('MF4', 'forensics/audit_check.py', "rep['counts']['overturned_all_runs'] != n_fail + hist_n:", "False:"),
    ('MF4', 'forensics/audit_check.py', "    if on_disk != [h.get('run') for h in hist]:", "    if False:"),
    ('MF4', 'forensics/audit_check.py', "        if not rp.exists() or hashlib.sha256(rp.read_bytes()).hexdigest() != h.get('report_sha256'):",
     "        if not rp.exists():"),
]


def run(base, which, committed=True):
    if which == 'MF5':
        return mf5(base, committed) + mf5_integration(base)
    if which == 'MF1':
        return mf1(base, committed)
    if which == 'MF6':
        return mf6(base, committed) + mf6a(base, committed)
    if which == 'MF3':
        return mf3(base, committed)
    if which == 'MF4':
        return mf4(base, committed)
    if which == 'MF7':
        return mf7(base, committed)
    if which == 'MF9':
        return mf9(base, committed)
    if which == 'MF2':
        return mf2(base, committed)
    if which == 'MF10':
        return mf10(base, committed)
    if which == 'MF12':
        return mf12(base, committed)
    return mf11(base)


def main():
    rc = 0
    for k in ('MF1', 'MF2', 'MF3', 'MF4', 'MF5', 'MF6', 'MF7', 'MF9', 'MF10', 'MF11', 'MF12'):
        f = run(HARNESS, k)
        print(f"{k}: {'PASS' if not f else 'FAIL'}" + ('' if not f else '\n  ' + '\n  '.join(f)))
        if f:
            rc = 3
    if rc:
        return rc
    caught = 0
    for i, (k, rel, old, new) in enumerate(MUTATIONS, 1):
        tmp = Path(tempfile.mkdtemp(prefix='fxmut_'))
        try:
            shutil.copytree(HARNESS / 'forensics', tmp / 'forensics')
            src = (tmp / rel).read_text()
            if old not in src:
                print(f'mutation {i} ({k}) INVALID: text not found'); rc = 4; continue
            (tmp / rel).write_text(src.replace(old, new, 1))
            try:
                f = run(tmp, k, committed=False)
            except Exception as e:
                print(f'mutation {i} ({k}) INVALID: mutant did not load/run: {type(e).__name__}: {e}'); rc = 4; continue
            if f:
                caught += 1
                print(f'mutation {i} ({k}) CAUGHT: {f[0]}')
            else:
                print(f'mutation {i} ({k}) NOT CAUGHT: {old.strip()[:60]}'); rc = 4
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print(f'mutations caught {caught}/{len(MUTATIONS)}')
    return rc


if __name__ == '__main__':
    sys.exit(main())
