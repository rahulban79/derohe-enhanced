#!/usr/bin/env python3
"""R25 forensics-extract, step 2: per-tx and per-block records from raw/ + derived/extract (rft §0.8.3).

  python3 -I harness/forensics/derive.py --dataset forensics/r25 [--store ~/derohe-persist/forensics_raw] [--out DIR]
      [--table blockchain/hardfork_fixes.go]

Reads only: raw/ (headerchain, provenance, tier A blobs), derived/extract/ and derived/archive_state/ (written by
extract.py from raw/ and our own archive copy), the HF3 table source (SRC) and, when --store is given, the tier B blobs
(for a second SHA3-256 pass over every window block). Writes deterministic files (sorted keys, gzip mtime 0, no
paths, no wall-clock times):
  derived/tx/<txid>.json        every RAW tx body (75 HF3 + the other tier A txs)
  derived/block/<height>.json   every tier A block (HF3 carriers +-2 heights)
  derived/window.jsonl.gz       tier B: one row per window height 7,415,466..7,497,942
  derived/link.jsonl.gz         the RAW blocks outside the window that link it to our anchor (7,415,464..5, 7,497,943..7,498,540)
  derived/emission.json         emission/coinbase vs CalcSupply over the window, fee/burn coverage
  derived/state_roots.json      the state-root chain: what is held, what is not reconstructable, and the evidence
  derived/hf3.json              the 75 in one table, the B82 table semantics, the B83 Proof-field census
  derived/grades.json           per TXID evidence grade and verdict grade (the builder's; audited grades: audit/audit_report.json)
  derived/summary.json          the counts
Missing values are the strings 'pending: <reason>' or 'not reconstructable: <reason>' / 'not decidable: <reason>',
never 0, null or an empty string (KAT MF7).
"""
import argparse, gzip, hashlib, io, json, re, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import keccak  # noqa: E402  pinned pure-Python Keccak-256 / SHA3-256 (MF6)

ROOT = Path(__file__).resolve().parent.parent.parent
WINDOW = (7415466, 7497942)
ANCHOR_HEIGHT = 7498540
HF3_HEIGHT = 7504640              # config/config.go:110
ARCH_RANGE = (7453290, 7467515)   # replaywall committed topo records (derived/archive_state/source.json)
COIN = 100000                     # 5 decimals (globals.FormatMoney)

# blockchain/transaction_execute.go:44-45, config/config.go:34,61, blockchain/supply.go:5-27 (second implementation of
# the formula from its constant lines; compared row by row with the node's own CalcBlockReward/CalcSupply)
BLOCK_TIME = 18
REWARD_REDUCTION_INTERVAL = 210000 * 600 // BLOCK_TIME
BASE_REWARD = (41 * 100000 * BLOCK_TIME) // 600
PREMINE = 1228125400000
CLAIM_GRANT_TOTAL = 271739600


def py_block_reward(h):
    return BASE_REWARD >> ((h + REWARD_REDUCTION_INTERVAL) // REWARD_REDUCTION_INTERVAL)


def py_calc_supply(h):
    s, rem, start = PREMINE + CLAIM_GRANT_TOTAL, h, 0
    while rem > 0:
        n = min(REWARD_REDUCTION_INTERVAL, rem)
        s += py_block_reward(start) * n
        rem -= n
        start += REWARD_REDUCTION_INTERVAL
    return s


C = {  # code citations, written at 17da0dc; the cited LINES are content-pinned (pins.py cited_lines)
    'verify_cache_fill': 'blockchain/transaction_verify.go:232-233',
    'verify_cache_key': 'blockchain/transaction_verify.go:433-436',
    'verify_cache_hit': 'blockchain/transaction_verify.go:438-441',
    'proof_verify': 'blockchain/transaction_verify.go:450-461',
    'checks_before_cache': 'blockchain/transaction_verify.go:256-322, :327-338, :341-431',
    'nonce_cache_fill': 'blockchain/transaction_verify.go:234-237',
    'nonce_cache_key': 'blockchain/transaction_verify.go:90-93',
    'nonce_cache_hit': 'blockchain/transaction_verify.go:94-96',
    'nonce_full': 'blockchain/transaction_verify.go:98-196',
    'sync_verify_first': 'p2p/hf3_parity.go:74-76 (verify before add); blockchain/blockchain.go:826 (nonce), :858 (verify)',
    'parity_set': 'p2p/hf3_parity.go:77',
    'parity_use': 'blockchain/transaction_execute.go:243-246',
    'parity_default': 'blockchain/transaction_execute.go:213',
    'admission': 'glue/txprecheck/window.go:136-145',
    'height_gate': 'config/config.go:110; p2p/hf3_parity.go:49,66',
    'execute_all': 'blockchain/blockchain.go:994-1024 (every Tx_hashes entry of each block in topological order is executed)',
    'coinbase': 'blockchain/transaction_execute.go:126-160',
    'reward': 'blockchain/transaction_execute.go:60-62',
    'supply': 'blockchain/supply.go:5-27',
    'reg_grant': 'blockchain/transaction_execute.go:194-196 (mainnet grant only below height 144,000)',
    'rpc_reward': 'cmd/derod/rpc/blockheader.go:50 (RPC reward = CalcBlockReward(height), base reward only)',
    'proof_field': 'block/block.go:42 (serialized at :120, read by no blockchain code; disc:119)',
}

NR_STATE = ('not reconstructable: no held state for this topo (live node state starts at prunedheight 7,498,540, '
            'disc:108-112; our archive holds committed state for topo 7,453,290..7,467,515 only; blocks commit to no '
            'checked root, disc:119-120; (a2) bootstrap is feasible, raw/a2_feasibility.json, R26)')


def gz_bytes(lines):
    buf = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=buf, mtime=0, compresslevel=9) as g:
        for l in lines:
            g.write((l + '\n').encode())
    return buf.getvalue()


def dump(o):
    return json.dumps(o, sort_keys=True, separators=(',', ':'))


def pretty(o):
    return (json.dumps(o, indent=1, sort_keys=True) + '\n').encode()


def read_gz_jsonl(p):
    with gzip.open(p, 'rt') as f:
        return [json.loads(l) for l in f if l.strip()]


def parse_table(path):
    """HF3_Affected_Txs literals (SRC) with their line, group and fields."""
    rx = re.compile(r'^\s*"([0-9a-f]{64})":\s*\{Bl_Tips:\s*"([0-9a-f]{64})",\s*Height:\s*(\d+),\s*Tx_Parity:\s*(true|false)\s*(,\s*Parity:\s*(true|false))?\s*\},?\s*$')
    out, group = {}, None
    src = Path(path).read_text()
    for n, line in enumerate(src.splitlines(), 1):
        s = line.strip()
        if s.startswith('//') and n > 26:
            group = s[2:].strip()
            continue
        m = rx.match(line)
        if m:
            out[m.group(1)] = {'line': n, 'group': group, 'bl_tips': m.group(2), 'height': int(m.group(3)),
                               'tx_parity': m.group(4) == 'true', 'parity_literal': m.group(6) is not None}
    return out, hashlib.sha256(src.encode()).hexdigest()


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--dataset', required=True); ap.add_argument('--store'); ap.add_argument('--out')
    ap.add_argument('--table', default=str(ROOT / 'blockchain' / 'hardfork_fixes.go'))
    a = ap.parse_args(argv)
    ds = Path(a.dataset)
    out = Path(a.out) if a.out else ds / 'derived'
    # extract.py's outputs: read from OUT when a re-derivation wrote them there (replay), else from the dataset
    src_derived = out if (out / 'extract' / 'blocks.jsonl.gz').exists() else ds / 'derived'
    table, table_sha = parse_table(a.table)
    hc = read_gz_jsonl(ds / 'raw' / 'headerchain.jsonl.gz')
    prov = json.loads((ds / 'raw' / 'provenance.json').read_text())
    blocks = {d['id']: d for d in read_gz_jsonl(src_derived / 'extract' / 'blocks.jsonl.gz')}
    txd = {d['txid']: d for d in read_gz_jsonl(src_derived / 'extract' / 'txs.jsonl.gz')}
    aroots_p = src_derived / 'archive_state' / 'roots.jsonl.gz'
    aroots = {r['topo']: r for r in read_gz_jsonl(aroots_p)} if aroots_p.exists() else {}
    pc_p = src_derived / 'archive_state' / 'proof_checks.jsonl'
    pchecks = {json.loads(l)['txid']: json.loads(l) for l in pc_p.read_text().splitlines()} if pc_p.exists() else {}
    hc_by_id = {r['blid']: r for r in hc}
    by_height = {}
    for r in hc:
        by_height.setdefault(r['height'], []).append(r)
    tx_prov = {t['id']: t for t in prov['tx_objects'] if t.get('class') == 'RAW'}
    tierA_ids = {b['id'] for b in prov['tierA_blocks'] if b.get('class') == 'RAW'}
    carriers_of = {}
    for r in hc:
        for t in r['tx_hashes']:
            carriers_of.setdefault(t, []).append(r)

    def topo_of(r):  # topo == height for every RAW row (raw/provenance.json summary rows_topo_ext_ne_height 0)
        return r['height']

    def root_at(topo):
        r = aroots.get(topo)
        if r and not r['root'].startswith('not '):
            return r['root']
        return NR_STATE

    # ------------------------------------------------------------------------------- per tx
    files = {}
    tx_fee, tx_type, tx_burn = {}, {}, {}
    grades = {}
    hf3_rows = []
    py_txid_ok = py_ser_ok = 0
    for txid in sorted(tx_prov):
        tp, d = tx_prov[txid], txd[txid]
        blob = (ds / 'raw' / 'blobs' / tp['sha256']).read_bytes()
        core = bytes.fromhex(d['core_hex'])
        py_txid = keccak.keccak256(core).hex()
        py_ser = keccak.keccak256(blob).hex()
        py_txid_ok += py_txid == txid
        py_ser_ok += d['reserialize_equal'] and py_ser == d['serialize_keccak256']
        tx_fee[txid], tx_type[txid] = d['fees'], d['tx_type']
        tx_burn[txid] = sum(p['burn_value'] for p in d['payloads'])
        entry = table.get(txid)
        ref = hc_by_id.get(d['ref_blid'])
        rec = {
            'txid': txid, 'class': 'RAW body (checks i-iii, raw/provenance.json); fields below DERIVED',
            'body': {'sha256': tp['sha256'], 'size': d['size'], 'source': tp.get('source'),
                     'reserialize_equal': d['reserialize_equal']},
            'txid_recomputed': {
                'node_go': d['txid'] == txid, 'python_keccak256': py_txid == txid,
                'core_statement_len': len(core), 'core_statement_sha256': hashlib.sha256(core).hexdigest(),
                'rule': 'TXID = Keccak256(SerializeCoreStatement), transaction/transaction.go:192-200, :510-524'},
            'serialized_keccak256': {
                'node_go': d['serialize_keccak256'], 'python_matches': py_ser == d['serialize_keccak256'],
                'use': f"the verifier's cache key only for tx.Height >= MAJOR_HF3_HEIGHT ({C['verify_cache_key']}); "
                       'below it (every tx here) the key is the TXID'},
            'tx_type': d['tx_type'], 'version': d['version'], 'value_field': d['value'],
            'ref_height': d['ref_height'], 'ref_blid': d['ref_blid'],
            'ref_blid_in_raw_chain': ref is not None,
            'ref_blid_height_eq_ref_height': bool(ref and ref['height'] == d['ref_height']),
            'fee': d['fees'], 'burn_total': tx_burn[txid], 'has_scdata': d['has_scdata'], 'scdata_keys': d['scdata_keys'],
            'payloads': [{k: p[k] for k in ('scid_zero', 'burn_value', 'fees', 'ring_size', 'bytes_per_publickey',
                                             'pointer_bytes', 'commitments', 'statement_roothash', 'rpc_type',
                                             'rpc_payload_len', 'has_proof')} for p in d['payloads']],
            'registration_signature_valid': d.get('registration_signature_valid', 'not applicable: not a registration'),
            'duplicates': {'bodies_held_under_this_txid': 1,
                           'other_bodies': 'pending: one body was fetched per TXID; block tx lists carry only the TXID, '
                                           'which excludes the proof (transaction.go:191), so a second body with the same '
                                           'core statement is not observable from RAW blocks'},
        }
        # statement root vs our archive root at the reference topo
        if d['payloads'] and d['tx_type'] != 'REGISTRATION':
            rt = d['payloads'][0]['statement_roothash']
            ar = aroots.get(d['ref_height'])
            if ar and ar['blid'] == d['ref_blid'] and not ar['root'].startswith('not '):
                rec['statement_roothash_vs_archive'] = {'archive_root': ar['root'], 'equal': ar['root'] == rt,
                                                         'state_version': ar['state_version_topo_record']}
            else:
                rec['statement_roothash_vs_archive'] = NR_STATE.replace('for this topo', 'for the reference topo')
        # proof result under the current verifier
        pcx = pchecks.get(txid)
        if d['tx_type'] == 'REGISTRATION':
            rec['proof_current_verifier'] = {'result': 'not applicable: registration (signature checked instead)',
                                             'registration_signature_valid': d.get('registration_signature_valid')}
        elif pcx is None:
            rec['proof_current_verifier'] = {'result': 'pending: archive state checks not run (extract.py --archive-copy)'}
        elif pcx['result'] in ('pass', 'fail'):
            rec['proof_current_verifier'] = {
                'result': pcx['result'], 'failed_check': 'not applicable: passed',
                'checks': pcx['checks'], 'payloads': pcx['payloads'], 'state_version': pcx['state_version'],
                'state_root': pcx['state_root'], 'implementation': 'single (node verifier via tools/forensics verify)',
                'exemption': 'HF3 cache bypassed in this run: ' + pcx['hf3_cache'],
                'state_source': 'derived/archive_state (our replaywall archive copy)'}
            if pcx['result'] == 'fail':
                rec['proof_current_verifier']['failed_check'] = next(
                    (c['detail'] for c in pcx['checks'] if c['result'] == 'fail'), pcx['reason'])
        else:
            rec['proof_current_verifier'] = {'result': 'not decidable: ring state unavailable',
                                             'reason': pcx['reason']}
        # carriers and the HF3 exception path
        cars = sorted(carriers_of.get(txid, []), key=lambda r: (r['height'], r['blid']))
        rec['carriers'] = []
        for r in cars:
            b = blocks[r['blid']]
            c = {'blid': r['blid'], 'height': r['height'], 'topo': topo_of(r), 'tips': b['tips'],
                 'tier': 'A' if r['blid'] in tierA_ids else 'B', 'class': 'RAW (checks i-ii)'}
            if entry:
                tips_eq = b['tips'] == [entry['bl_tips']]
                parity = (r['height'] > entry['height']) == entry['tx_parity']
                pp = [p['proof_parity'] for p in d['payloads']]  # used only for the boolean below (not exported)
                c['exception_path'] = {
                    'height_eq_table_height': r['height'] == entry['height'],
                    'tips_eq_table_bl_tips': tips_eq,
                    'table_bl_tips_is_this_block': entry['bl_tips'] == r['blid'],
                    'below_hf3': r['height'] < HF3_HEIGHT,
                    'proof_verification': (f"skipped: {C['verify_cache_fill']} stores the TXID in transaction_valid_cache "
                                           f"before any check; the key below HF3 is the TXID ({C['verify_cache_key']}); "
                                           f"{C['verify_cache_hit']} returns before Proof.Verify ({C['proof_verify']}). "
                                           f"Still applied before that return: {C['checks_before_cache']}"),
                    'nonce_check': (f"bypassed: {C['nonce_cache_fill']} caches TXID+Bl_Tips; this block's key "
                                    f"TXID+tips ({C['nonce_cache_key']}) equals it, so {C['nonce_cache_hit']} returns "
                                    f"({C['sync_verify_first']})") if tips_eq else
                                   (f"applied: this block's key TXID+tips ({C['nonce_cache_key']}) differs from the "
                                    f"cached TXID+Bl_Tips, so the full check {C['nonce_full']} runs"),
                    'execution_parity': {'entry_parity': parity,
                                         'override_changes_execution': any(parity != x for x in pp),
                                         'rule': f"{C['parity_set']} Parity = (height > table Height) == Tx_Parity; "
                                                 f"{C['parity_use']} uses it instead of Proof.Parity() ({C['parity_default']})"},
                    'executed': f"yes (INTERPRETATION of SRC + RAW: {C['execute_all']}; this block is in the RAW chain)",
                }
            rec['carriers'].append(c)
        rec['carrier_count'] = len(cars)
        if entry:
            rec['hf3'] = True
            rec['table_entry'] = dict(entry, file='blockchain/hardfork_fixes.go', class_='SRC')
            rec['table_entry']['class'] = rec['table_entry'].pop('class_')
            bt = hc_by_id.get(entry['bl_tips'])
            match = [c for c in rec['carriers'] if c['exception_path']['height_eq_table_height']]
            rec['table_semantics'] = {
                'height_is_inclusion_height_of_a_carrier': bool(match),
                'bl_tips_is_tip_of_that_carrier': bool(match and match[0]['exception_path']['tips_eq_table_bl_tips']),
                'bl_tips_is_that_carrier_itself': bool(match and match[0]['exception_path']['table_bl_tips_is_this_block']),
                'bl_tips_block_raw': bt is not None, 'bl_tips_height': bt['height'] if bt else 'missing: Bl_Tips id not in RAW chain',
                'tx_ref_blid_eq_bl_tips': d['ref_blid'] == entry['bl_tips'],
                'other_carriers': [c['height'] for c in rec['carriers'] if not c['exception_path']['height_eq_table_height']],
            }
            rec['admission_today'] = f"refused at relay/RPC admission ({C['admission']}); exemption only below HF3 ({C['height_gate']})"
            proof = rec['proof_current_verifier']['result']
            ev = 'E1' if proof in ('pass', 'fail') else 'E2'
            checked = ['body RAW (i-iii)', 'carriers RAW (i-ii)', 'TXID by node Go and pinned Python Keccak-256',
                       'exception path per carrier (SRC lines)', f'proof under the current verifier: {proof}']
            if proof == 'pass':
                decide = ('today\'s verifier accepts the proof against our archive state, but the verifier has a disclosed '
                          'soundness gap (C1, rft §0.5), so a pass does not settle the hidden amount')
            elif proof == 'fail':
                # R25 audit A4b overturned 'the chain accepted the tx only through the exemption': every earliest
                # carrier predates the table commit, so the dataset does not show how the network first accepted it.
                # Only what A11 (verifier re-run) and A4a (code-path classification of the pinned code) support:
                decide = ('today\'s verifier rejects the proof against our archive state (check: '
                          f"{rec['proof_current_verifier']['failed_check']}; single implementation, the node's own "
                          'verifier); under the pinned code a node accepts this body only on the HF3 exemption path, '
                          'which skips proof verification (a code-path classification, not a record of how the network '
                          'first accepted the block, which this dataset does not determine); whether value was created '
                          'depends on the ElGamal-encrypted amounts, which no public field reveals')
            else:
                decide = ('the ring\'s balance state at the reference block (needed to re-run the verifier) is not held; '
                          'even with it, a pass would not settle the hidden amount (C1)')
            g = {'txid': txid, 'evidence_grade': ev, 'verdict_grade': 'NOT-DECIDABLE-FROM-PUBLIC-DATA',
                 'question': 'did this tx create value beyond the emission formula?',
                 'public_fields': {'fee': d['fees'], 'burn_total': tx_burn[txid], 'value_field': d['value'],
                                   'note': 'public fields move no plaintext value into existence: the fee is paid out of '
                                           'the sender\'s encrypted balance; burn and value are 0'},
                 'checked': checked, 'deciding_fact_missing': decide,
                 'status': 'builder grade, written before the audit; the audited grade is audit/audit_report.json verdicts (G29), rft §0.8.1 rule 5'}
            rec['grade'] = g
            grades[txid] = g
            ex0 = [c['exception_path'] for c in rec['carriers']]
            hf3_rows.append({
                'txid': txid, 'line': entry['line'], 'group': entry['group'], 'table_height': entry['height'],
                'tx_parity': entry['tx_parity'], 'carriers': [c['height'] for c in rec['carriers']],
                'nonce_bypassed_carriers': [c['height'] for c, e in zip(rec['carriers'], ex0) if e['tips_eq_table_bl_tips']],
                'parity_override_changes_execution': [c['height'] for c, e in zip(rec['carriers'], ex0)
                                                      if e['execution_parity']['override_changes_execution']],
                'proof_current_verifier': proof, 'evidence_grade': ev,
                'height_is_carrier_height': rec['table_semantics']['height_is_inclusion_height_of_a_carrier'],
                'bl_tips_is_carrier_tip': rec['table_semantics']['bl_tips_is_tip_of_that_carrier'],
                'bl_tips_is_carrier_itself': rec['table_semantics']['bl_tips_is_that_carrier_itself'],
                'ref_blid_eq_bl_tips': rec['table_semantics']['tx_ref_blid_eq_bl_tips'],
                'fee': d['fees'], 'ring_sizes': [p['ring_size'] for p in d['payloads']], 'body_sha256': tp['sha256']})
        else:
            rec['hf3'] = False
        files[f'tx/{txid}.json'] = pretty(rec)
    missing_hf3 = sorted(set(table) - {r['txid'] for r in hf3_rows})

    # ------------------------------------------------------------------------------- per block
    def fees_of(b):
        if not b['tx_hashes']:
            return 0, 0
        if all(t in tx_fee for t in b['tx_hashes']):
            return sum(tx_fee[t] for t in b['tx_hashes']), sum(tx_burn[t] for t in b['tx_hashes'])
        n = sum(1 for t in b['tx_hashes'] if t not in tx_fee)
        why = f'pending: {n} of {len(b["tx_hashes"])} tx bodies of this block are not in raw/ (acquire fetched tier A bodies only)'
        return why, why

    py_sha3_tierA_ok = 0
    window_rows, link_rows = [], []
    store = Path(a.store) if a.store else None
    py_store_sha3_ok = store_checked = 0
    em = {'blocks': 0, 'node_eq_python_reward': 0, 'reward_ext_eq_formula': 0, 'supply_identity_ok': 0,
          'coinbase_ok': 0, 'fees_known_blocks': 0, 'fees_known_sum': 0, 'fees_pending_blocks': 0,
          'burn_known_sum': 0, 'tx_free_blocks': 0, 'base_reward_sum_node': 0, 'base_reward_sum_python': 0}
    hf3_carrier_ids = {c for t in table for c in [r['blid'] for r in carriers_of.get(t, [])]}
    for r in sorted(hc, key=lambda r: (r['height'], r['blid'])):
        b = blocks[r['blid']]
        h = b['height']
        fees, burns = fees_of(b)
        rw_node, rw_py = b['node_calc_block_reward'], py_block_reward(h)
        sup_ok = (b['node_calc_supply_next'] - b['node_calc_supply_height'] == rw_node and
                  py_calc_supply(h + 1) - py_calc_supply(h) == rw_py and b['node_calc_supply_height'] == py_calc_supply(h))
        coinbase_ok = b['miner_tx_type'] == 'COINBASE' and b['miner_tx_value'] == 0
        row = {'topo': topo_of(r), 'height': h, 'blid': b['id'], 'tips': b['tips'], 'timestamp_ms': b['timestamp_ms'],
               'miniblocks': b['miniblocks'], 'miniblocks_final': b['miniblocks_final'],
               'tx_count': len(b['tx_hashes']), 'tx_hashes': b['tx_hashes'],
               'hf3_txids': sorted(t for t in b['tx_hashes'] if t in table),
               'tier': 'A' if b['id'] in tierA_ids else 'B', 'class': 'RAW (checks i-ii); row DERIVED',
               'sha3_256': r['sha3_256'], 'sha256': r['sha256'],
               'coinbase': {'miner_tx_type': b['miner_tx_type'], 'miner_tx_value': b['miner_tx_value'], 'formula_only': coinbase_ok},
               'base_reward': rw_node, 'base_reward_python_eq': rw_node == rw_py,
               'reward_ext': r.get('reward_ext', 'missing: source gave no reward'),
               'reward_ext_eq_formula': r.get('reward_ext') == rw_node,
               'supply_before': b['node_calc_supply_height'], 'supply_after': b['node_calc_supply_next'],
               'supply_identity_ok': sup_ok, 'fees': fees, 'public_burns': burns,
               'proof_field_nonzero': b['proof_field_nonzero'],
               'state_root_pre': root_at(topo_of(r) - 1), 'state_root_post': root_at(topo_of(r))}
        if isinstance(fees, int):
            row['full_reward'] = rw_node + fees
            row['miniblock_share'] = (rw_node + fees) // b['miniblocks']
            row['integrator_leftover'] = (rw_node + fees) - row['miniblock_share'] * b['miniblocks']
        else:
            row['full_reward'] = row['miniblock_share'] = row['integrator_leftover'] = fees
        if b['id'] in tierA_ids:
            py_sha3_tierA_ok += keccak.sha3_256((ds / 'raw' / 'blobs' / r['sha256']).read_bytes()).hex() == b['id']
        if store is not None and not (ds / 'raw' / 'blobs' / r['sha256']).exists():
            p = store / 'blobs' / r['sha256']
            if p.exists():
                store_checked += 1
                py_store_sha3_ok += hashlib.sha3_256(p.read_bytes()).hexdigest() == b['id']
        if WINDOW[0] <= h <= WINDOW[1]:
            window_rows.append(row)
            em['blocks'] += 1
            em['node_eq_python_reward'] += row['base_reward_python_eq']
            em['reward_ext_eq_formula'] += row['reward_ext_eq_formula']
            em['supply_identity_ok'] += sup_ok
            em['coinbase_ok'] += coinbase_ok
            em['base_reward_sum_node'] += rw_node
            em['base_reward_sum_python'] += rw_py
            em['tx_free_blocks'] += not b['tx_hashes']
            if isinstance(fees, int):
                em['fees_known_blocks'] += 1
                em['fees_known_sum'] += fees
                em['burn_known_sum'] += burns
            else:
                em['fees_pending_blocks'] += 1
        else:
            row['in_window'] = False
            row['role'] = 'anchor' if h == ANCHOR_HEIGHT else 'link to the anchor (tips chain, check ii)'
            link_rows.append(row)
        if b['id'] in tierA_ids:
            brec = dict(row)
            brec['major_version'], brec['minor_version'] = b['major_version'], b['minor_version']
            brec['txs'] = [{'txid': t, 'tx_type': tx_type.get(t, 'missing: body not in raw/'),
                            'fee': tx_fee.get(t, 'missing: body not in raw/'), 'hf3': t in table} for t in b['tx_hashes']]
            brec['hf3_carrier'] = b['id'] in hf3_carrier_ids
            brec['reward_rule'] = (f"{C['coinbase']}: (base + fees) split equally over the miniblocks, leftover to the "
                                   f"integrator; base = CalcBlockReward ({C['reward']})")
            files[f'block/{h}.json'] = pretty(brec)
    assert len(window_rows) == WINDOW[1] - WINDOW[0] + 1, 'window rows != window heights'
    files['window.jsonl.gz'] = gz_bytes(dump(r) for r in window_rows)
    files['link.jsonl.gz'] = gz_bytes(dump(r) for r in link_rows)

    # ------------------------------------------------------------------------------- emission
    s0, s1 = py_calc_supply(WINDOW[0]), py_calc_supply(WINDOW[1] + 1)
    emission = {
        'scope': f'window {WINDOW[0]:,}..{WINDOW[1]:,} ({em["blocks"]:,} blocks); public emission only',
        'rules': {'reward': C['reward'], 'supply': C['supply'], 'coinbase': C['coinbase'], 'rpc_reward': C['rpc_reward'],
                  'registrations': C['reg_grant']},
        'constants_python': {'BLOCK_TIME': BLOCK_TIME, 'RewardReductionInterval': REWARD_REDUCTION_INTERVAL,
                             'BaseReward': BASE_REWARD, 'PREMINE': PREMINE, 'claim_grant_total': CLAIM_GRANT_TOTAL},
        'per_block': em,
        'base_reward_per_block_atomic': sorted({r['base_reward'] for r in window_rows}),
        'calc_supply_at_window_start': s0, 'calc_supply_after_window': s1,
        'window_emission_atomic': s1 - s0, 'window_emission_dero': f'{(s1 - s0) / COIN:.5f}',
        'identity_sum_rewards_eq_supply_delta': em['base_reward_sum_node'] == s1 - s0 == em['base_reward_sum_python'],
        'fees': {'known_blocks': em['fees_known_blocks'], 'known_sum_atomic': em['fees_known_sum'],
                 'pending_blocks': em['fees_pending_blocks'],
                 'pending_reason': 'tx bodies of these blocks are not in raw/ (acquire fetched tier A bodies only); a later stage can fetch them under checks (iii)'},
        'grade': {'verdict_grade': 'PROVEN-NO-INFLATION-IN-SCOPE',
                  'scope': ('the formula coinbase of the 82,477 window blocks: each has one COINBASE miner tx with value 0, '
                            'the base reward is the formula (node and Python agree on every row), and the sum equals '
                            'CalcSupply(end+1) - CalcSupply(start). It says nothing about hidden (encrypted) amounts, and '
                            'nothing about fees, burns or SC payouts of blocks whose bodies are pending'),
                  'status': 'builder grade, written before the audit; the audited grade is audit/audit_report.json verdicts (G29)'},
        'not_in_scope': ['hidden transfer amounts (ElGamal; range-proof soundness C1, rft §0.5)',
                         'fees/burns/SC payouts of the blocks with pending bodies',
                         'EXT figures (23,886,517.3; 5,000,000): no DERIVED input here reproduces or refutes them'],
    }
    files['emission.json'] = pretty(emission)

    # ------------------------------------------------------------------------------- state roots
    in_arch = [r for r in window_rows if isinstance(r['state_root_post'], str) and not r['state_root_post'].startswith('not ')]
    corro = []
    for txid in sorted(tx_prov):
        rec = json.loads(files[f'tx/{txid}.json'])
        s = rec.get('statement_roothash_vs_archive')
        if isinstance(s, dict):
            corro.append({'txid': txid, 'ref_topo': rec['ref_height'], 'equal': s['equal']})
    state = {
        'held': {'source': 'derived/archive_state/roots.jsonl.gz (our replaywall archive copy)',
                 'window_topos_with_post_root': len(in_arch),
                 'range': [ARCH_RANGE[0], ARCH_RANGE[1]] if in_arch else 'missing: no archive state',
                 'class': 'DERIVED from our own archive store (node-computed roots of its 2026-08 replay; base tree from '
                          'its fastsync at 7,453,290; not end-state-checked)',
                 'archive_blid_eq_raw_chain': sum(1 for r in aroots.values() if r['blid_equals_raw_headerchain']),
                 'archive_records': len(aroots),
                 'version_file_eq_topo_record': sum(1 for r in aroots.values()
                                                    if r['state_version_block_file'] == r['state_version_topo_record'])},
        'corroboration_by_tx_statement_roothash': {
            'rule': 'a tx\'s Statement.Roothash is the root its creator\'s node reported for the reference block; '
                    'equality with our archive root at that topo is an independent witness of that root',
            'rows': corro, 'equal': sum(1 for c in corro if c['equal']), 'total': len(corro)},
        'not_reconstructable': {'window_topos': em['blocks'] - len(in_arch), 'reason': NR_STATE,
                                'proof_field_census': {'blocks': len(hc), 'nonzero': sum(1 for b in blocks.values() if b['proof_field_nonzero']),
                                                       'rule': C['proof_field']},
                                'ext_only': 'raw/a2_feasibility.json carries 6 sources\' treehash at 7,415,465 (EXT, unused as evidence)'},
    }
    files['state_roots.json'] = pretty(state)

    # ------------------------------------------------------------------------------- hf3 + grades + summary
    groups = {}
    for r in hf3_rows:
        groups[r['group']] = groups.get(r['group'], 0) + 1
    hf3 = {'table': {'file': 'blockchain/hardfork_fixes.go', 'sha256': table_sha, 'entries': len(table), 'groups': groups,
                     'parity_literal_set': sum(1 for e in table.values() if e['parity_literal'])},
           'paths': C, 'rows': hf3_rows, 'missing': missing_hf3 or [],
           'counts': {
               'bodies_raw': len(hf3_rows), 'dual_carrier': sum(1 for r in hf3_rows if len(r['carriers']) == 2),
               'single_carrier': sum(1 for r in hf3_rows if len(r['carriers']) == 1),
               'height_is_carrier_height': sum(r['height_is_carrier_height'] for r in hf3_rows),
               'bl_tips_is_carrier_tip': sum(r['bl_tips_is_carrier_tip'] for r in hf3_rows),
               'bl_tips_is_carrier_itself': sum(r['bl_tips_is_carrier_itself'] for r in hf3_rows),
               'ref_blid_eq_bl_tips': sum(r['ref_blid_eq_bl_tips'] for r in hf3_rows),
               'carriers_total': sum(len(r['carriers']) for r in hf3_rows),
               'carriers_nonce_bypassed': sum(len(r['nonce_bypassed_carriers']) for r in hf3_rows),
               'carriers_parity_override_changes_execution': sum(len(r['parity_override_changes_execution']) for r in hf3_rows),
               'table_carrier_is_earliest': sum(1 for r in hf3_rows if r['carriers'] and r['carriers'][0] == r['table_height']),
               'proof_current_verifier': {k: sum(1 for r in hf3_rows if r['proof_current_verifier'] == k)
                                          for k in sorted({r['proof_current_verifier'] for r in hf3_rows})}},
           'b82_semantics': 'Height = the inclusion height of one carrier, and Bl_Tips = that carrier\'s single tip, '
                            'except where bl_tips_is_carrier_itself (counts above; the audit stage re-tests it)',
           'b83_proof_field': state['not_reconstructable']['proof_field_census']}
    files['hf3.json'] = pretty(hf3)
    gcount = {}
    for g in grades.values():
        k = f"{g['verdict_grade']}/{g['evidence_grade']}"
        gcount[k] = gcount.get(k, 0) + 1
    files['grades.json'] = pretty({
        'legend': {'E1': 'body + carriers RAW; TXID two implementations; proof decided by the current verifier against held state',
                   'E2': 'body + carriers RAW; TXID two implementations; proof not decidable: ring state unavailable',
                   'verdict_grades': 'rft §0.8.2'},
        'per_txid': [grades[k] for k in sorted(grades)], 'counts': gcount,
        'window_emission': emission['grade'],
        'status': 'builder grade, written before the audit; the audited grade is audit/audit_report.json verdicts (G29)'})
    summary = {
        'window': list(WINDOW), 'window_rows': len(window_rows), 'link_rows': len(link_rows),
        'tierA_block_records': sum(1 for k in files if k.startswith('block/')),
        'tx_records': sum(1 for k in files if k.startswith('tx/')), 'hf3_records': len(hf3_rows), 'hf3_missing': len(missing_hf3),
        'txid_python_keccak_eq': py_txid_ok, 'serialize_keccak_python_eq': py_ser_ok,
        'tierA_block_id_python_sha3_eq': py_sha3_tierA_ok, 'tierA_blocks': len(tierA_ids),
        'emission_identity_ok': emission['identity_sum_rewards_eq_supply_delta'],
        'state_roots_held_window_topos': len(in_arch), 'grades': gcount,
        'tool': {'keccak_impl': keccak.IMPL_VERSION},
    }
    files['summary.json'] = pretty(summary)
    for rel, b in sorted(files.items()):
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b)
    agg = hashlib.sha256(''.join(f'{k} {hashlib.sha256(v).hexdigest()}\n' for k, v in sorted(files.items())).encode()).hexdigest()
    print(json.dumps(summary, sort_keys=True))
    # store-dependent: printed, never written, so derived/ is identical with or without the tier B store
    print(f'store blocks SHA3-256 re-checked {store_checked}, equal {py_store_sha3_ok}')
    print('derived files', len(files), 'aggregate', agg)
    return 0


if __name__ == '__main__':
    sys.exit(main())
