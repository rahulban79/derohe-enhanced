#!/usr/bin/env python3
"""R26 defect classes, coverage and bounds (rft §0.8.9; B107, B110): tags every forensic record with ONE defect class
and writes derived/classes.json (per class: detection scope, counts, coverage, bound) and derived/fq.json (FQ1-FQ6 and
the Q-CS pointers), reading only dataset files and the code at the given revision.

  python3 -I harness/forensics/classes.py --dataset forensics/r26 [--base forensics/r25] [--structstats FILE]
          [--presence forensics/r26/derived/presence.json] [--invariant forensics/r26/derived/invariant.json] --write
  python3 -I harness/forensics/classes.py --tag forensics/r26       # fill `defect_class` in the v2 records (never v1)

Classes (rft §0.8.9 table): DC0 a finding that fits no class (e.g. a duplicate TXID outside the HF3 table); DC1 the
duplication ladder (the HF3 table's 75 TXIDs); DC2 proof soundness (graded once at class level, never per tx); DC3
public-value identities (coinbase/emission vs CalcSupply, fees, public burns, SC payouts).

Interface with forensics-data (plan r26): the v2 records carry the tag in the field `defect_class`; v1's field `class`
already holds the EVIDENCE class (RAW/DERIVED wording) and is never overwritten. A v2 record whose `class` is the
literal slot value ('pending: defect class' or null) gets that slot filled too.

Rules enforced here and re-checked by G31 (bounds.py): one class per row and figure; every figure is
{class, scope, coverage num/den with anchors, bound_type in exact|lower-bound|upper-bound|unbounded}; no figure sums
across classes; an unknown renders as `unbounded` / `pending`, never 0. Only structural criteria and counts are
recorded for FQ2/FQ3, never a method (rule 13, G24).
"""
import argparse, collections, gzip, hashlib, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
WINDOW = (7415466, 7497942)
BOUND_TYPES = ('exact', 'lower-bound', 'upper-bound', 'unbounded')
CLASS_IDS = ('DC0', 'DC1', 'DC2', 'DC3')
SLOT_VALUES = (None, 'pending: defect class')
SCHEMA = 'r26 classes v1 (rft §0.8.9)'


def sha(b):
    return hashlib.sha256(b).hexdigest()


class Inputs:
    """dataset files, v2 first and the base (v1) as fallback; every file read is recorded with its SHA-256"""

    def __init__(self, ds, base=None, root=ROOT):
        self.root, self.ds, self.base = Path(root), Path(ds), Path(base) if base else None
        self.read = {}

    def path(self, rel):
        for d in (self.ds, self.base):
            if d is not None and (d / rel).exists():
                return d / rel
        return None

    def bytes(self, rel):
        p = self.path(rel)
        if p is None:
            return None
        b = p.read_bytes()
        try:
            key = str(p.resolve().relative_to(self.root.resolve()))
        except ValueError:
            key = f'{p.parent.parent.name}/{p.parent.name}/{p.name}'
        self.read[key] = sha(b)
        return b

    def json(self, rel):
        b = self.bytes(rel)
        return json.loads(b) if b is not None else None

    def window_rows(self):
        b = self.bytes('derived/window.jsonl.gz')
        if b is None:
            return None
        return [json.loads(l) for l in gzip.decompress(b).decode().splitlines() if l.strip()]

    def tx_records(self):
        out = []
        for d in (self.ds, self.base):
            if d is not None and (d / 'derived' / 'tx').is_dir():
                for p in sorted((d / 'derived' / 'tx').glob('*.json')):
                    out.append(json.loads(self.bytes(f'derived/tx/{p.name}')))
                return out
        return out

    def block_records(self):
        for d in (self.ds, self.base):
            if d is not None and (d / 'derived' / 'block').is_dir():
                return sorted(p.name for p in (d / 'derived' / 'block').glob('*.json'))
        return []


# ───────────────────────────── tagging ─────────────────────────────
def tag_tx(rec, table):
    """one class per tx record: DC1 for the 75 table TXIDs, else DC3 (its public-value fields); DC2 is never per tx"""
    return 'DC1' if rec.get('txid') in table else 'DC3'


def tag_block(_rec):
    """a block-level record states public-value identities (coinbase/emission, fees, burns): DC3"""
    return 'DC3'


def _fill(rec, cls):
    rec['defect_class'] = cls
    if 'class' in rec and rec['class'] in SLOT_VALUES:
        rec['class'] = cls
    return rec


def tag_dataset(ds, root=ROOT):
    """fill `defect_class` in the v2 per-tx / per-block / window records in place; refuses a sealed version"""
    ds = Path(ds)
    led = json.loads((Path(root) / 'forensics' / 'ledger.json').read_text())
    if any(v.get('version') == ds.name and v.get('sealed') for v in led.get('versions', [])) or ds.name == 'r25':
        raise SystemExit(f'refused: {ds.name} is a sealed dataset version (rft §0.8.1 rule 4: build on, never rewrite)')
    hf3 = json.loads((ds / 'derived' / 'hf3.json').read_text())
    table = {r['txid'] for r in hf3['rows']}
    n = collections.Counter()
    for p in sorted((ds / 'derived' / 'tx').glob('*.json')):
        r = json.loads(p.read_text())
        p.write_text(json.dumps(_fill(r, tag_tx(r, table)), indent=1, sort_keys=True) + '\n')
        n['tx_' + r['defect_class']] += 1
    for p in sorted((ds / 'derived' / 'block').glob('*.json')):
        r = json.loads(p.read_text())
        p.write_text(json.dumps(_fill(r, tag_block(r)), indent=1, sort_keys=True) + '\n')
        n['block_DC3'] += 1
    w = ds / 'derived' / 'window.jsonl.gz'
    if w.exists():
        rows = [json.loads(l) for l in gzip.decompress(w.read_bytes()).decode().splitlines() if l.strip()]
        w.write_bytes(gzip.compress(''.join(json.dumps(_fill(r, tag_block(r)), sort_keys=True) + '\n' for r in rows).encode(), mtime=0))
        n['window_DC3'] = len(rows)
    return dict(n)


# ───────────────────────────── figures ─────────────────────────────
def figure(fid, cls, label, value, scope, cov_num, cov_den, num_anchor, den_anchor, bound_type, unit='count', note=None):
    f = {'id': fid, 'class': cls, 'label': label, 'value': value, 'unit': unit, 'scope': scope,
         'coverage': {'num': cov_num, 'den': cov_den, 'num_anchor': num_anchor, 'den_anchor': den_anchor},
         'bound_type': bound_type}
    if note:
        f['note'] = note
    return f


def window_scope():
    return {'heights': list(WINDOW), 'text': 'window 7,415,466..7,497,942 (the 75 HF3 entries min..max)'}


def struct_census(stats, table):
    """FQ3 structural census over held bodies: payloads whose randomness-commitment digest equals one in ANOTHER tx
    (or another payload of the same tx). Counts only; the per-tx list is limited to the 75 table TXIDs (rule 13)."""
    d2tx = collections.defaultdict(set)
    payloads, intra, ok = 0, 0, 0
    for s in stats:
        if not s.get('ok'):
            continue
        ok += 1
        ds = [p['d_sha256'] for p in s['payloads'] if not str(p['d_sha256']).startswith('missing')]  # no D: not a commitment
        payloads += len(s['payloads'])
        if len(ds) != len(set(ds)):
            intra += 1
        for d in ds:
            d2tx[d].add(s['txid'])
    shared = {d: t for d, t in d2tx.items() if len(t) > 1}
    txs = sorted({t for v in shared.values() for t in v})
    return {'bodies_decoded': ok, 'bodies_given': len(stats), 'payloads': payloads, 'distinct_commitments': len(d2tx),
            'commitments_shared_across_txs': len(shared), 'txs_with_a_shared_commitment': len(txs),
            'table_txs_with_a_shared_commitment': sorted(t for t in txs if t in table),
            'txs_with_intra_tx_shared_commitment': intra}


def build(I, presence=None, invariant=None, stats=None, track=None):
    """(classes.json, fq.json) from the dataset inputs"""
    hf3 = I.json('derived/hf3.json')
    em = I.json('derived/emission.json')
    grades = I.json('derived/grades.json')
    rows = I.window_rows()
    txr = I.tx_records()
    table = {r['txid'] for r in hf3['rows']}
    groups = collections.Counter(r['group'] for r in hf3['rows'])
    carriers = collections.Counter((r['group'], len(r['carriers'])) for r in hf3['rows'])
    tag = collections.Counter(tag_tx(r, table) for r in txr)

    # FQ1 census: TXIDs in the window's block tx lists
    occ = collections.Counter(t for r in rows for t in r.get('tx_hashes', []))
    multi = {t: n for t, n in occ.items() if n > 1}
    dc0 = sorted(t for t in multi if t not in table)
    tx_blocks = sum(1 for r in rows if r.get('tx_hashes'))
    outside = [{'txid_prefix': r['txid'][:8], 'carriers': r['carriers']} for r in sorted(hf3['rows'], key=lambda x: x['txid'])
               if any(not WINDOW[0] <= c <= WINDOW[1] for c in r['carriers'])]
    dual_raw = sum(1 for r in hf3['rows'] if r['group'] == 'duplicates' and len(r['carriers']) == 2)
    single_raw = sum(1 for r in hf3['rows'] if r['group'] != 'duplicates' and len(r['carriers']) == 1)
    bodies_raw = hf3['counts'].get('bodies_raw')
    parity_true = sum(1 for r in hf3['rows'] if r.get('tx_parity') is True)
    nonce_bypassed = hf3['counts'].get('carriers_nonce_bypassed')
    carriers_total = hf3['counts'].get('carriers_total')
    two_bodies = 'pending: one body was fetched per TXID; a block tx list carries only the TXID, which excludes the proof (transaction/transaction.go:509), so a second body is not observable from RAW blocks'
    # FQ2 criteria over the 75
    p1_txids = {r['txid'] for r in txr if r.get('txid') in table and (r.get('value_field') or r.get('burn_total'))}
    public_value = len(p1_txids)
    sc = struct_census(stats, table) if stats is not None else None
    # DC1-obs = the table TXIDs meeting ANY recorded criterion (P1 or S-R22), computed, never assumed 0 (verify r26)
    n_obs = len(p1_txids | set(sc['table_txs_with_a_shared_commitment'])) if sc else 'pending'
    obs_amount = ('none determinable: DC1-obs is empty under the recorded criteria' if n_obs == 0 else
                  f'pending: {n_obs} DC1-obs TXID(s); their amounts are not computed here (rule 13)') if sc else 'pending'
    held_window_txids = sum(1 for r in txr if r.get('txid') in occ)
    dc2_present = (presence or {}).get('headline', {}).get('dc2_present_now')
    c1 = next((c for c in (track or {}).get('claims', []) if c.get('id') == 'C1'), None)
    c1_last = c1['history'][-1] if c1 and c1.get('history') else {}
    pf = em['per_block']
    W = window_scope()
    N = len(rows)
    figs = [
        figure('dc1-table-entries', 'DC1', 'HF3 table entries (the DC1 TXIDs consensus code names)', len(hf3['rows']), W,
               len(hf3['rows']), hf3['table']['entries'], 'derived/hf3.json rows', 'blockchain/hardfork_fixes.go:27 (derived/hf3.json table.entries)', 'exact'),
        figure('dc1-bodies-raw', 'DC1', 'DC1 bodies held RAW (checks i-iii)', bodies_raw, W, bodies_raw, len(hf3['rows']),
               'derived/hf3.json counts.bodies_raw', 'derived/hf3.json rows', 'exact'),
        figure('dc1-dual-carrier', 'DC1', '"duplicates" entries carried by two RAW blocks', dual_raw, W, dual_raw, groups['duplicates'],
               'derived/hf3.json rows[].carriers', 'derived/hf3.json table.groups.duplicates', 'exact'),
        figure('dc1-single-carrier', 'DC1', '"false parity" entries carried by one RAW block', single_raw, W, single_raw,
               groups['no duplicates, but false parity'], 'derived/hf3.json rows[].carriers', 'derived/hf3.json table.groups', 'exact'),
        figure('dc1-two-bodies', 'DC1', 'DC1 TXIDs with two different bodies held', two_bodies, W, 'pending', len(hf3['rows']),
               'derived/tx/*.json duplicates', 'derived/hf3.json rows', 'unbounded'),
        figure('dc1-obs-coverage', 'DC1', 'DC1 TXIDs whose amount public data determines (DC1-obs)', n_obs, W,
               n_obs, len(hf3['rows']), 'derived/fq.json FQ2', 'derived/hf3.json rows', 'lower-bound',
               note='lower bound: criteria P1 (public plaintext value fields) and S-R22 (shared randomness commitment, held bodies only); '
                    'the rest is DC1-pending, not DC1-hidden, until the FQ3 boundary is known'),
        figure('dc1-obs-amount', 'DC1', 'sum of DC1-obs amounts', obs_amount,
               W, n_obs, len(hf3['rows']), 'derived/fq.json FQ2', 'derived/hf3.json rows', 'lower-bound', unit='atomic',
               note='never a supply figure (rule 8); the external 23,886,517.3 figure stays EXT (C6)'),
        figure('dc0-window-duplicates', 'DC0', 'TXIDs in two or more window blocks outside the HF3 table', len(dc0), W, N, N,
               'derived/window.jsonl.gz rows[].tx_hashes', 'derived/window.jsonl.gz rows', 'exact',
               note=f'{len(occ):,} distinct TXIDs in {tx_blocks:,} tx-carrying blocks; bodies are not compared (one body per TXID)'),
        figure('dc2-created-value', 'DC2', 'value created under the proof-soundness defect', 'unbounded', {'heights': 'genesis..now', 'text': 'genesis .. now'},
               0, 'pending', 'no public-data test separates the cases (fq.json FQ5)', 'pending: every proof since genesis', 'unbounded', unit='atomic',
               note='lower bound 0, no upper bound; graded once: NOT-DECIDABLE-FROM-PUBLIC-DATA'),
        figure('dc3-window-emission', 'DC3', 'window emission (formula coinbase) = CalcSupply difference', em['window_emission_atomic'], W,
               pf['supply_identity_ok'], pf['blocks'], 'derived/emission.json per_block.supply_identity_ok', 'derived/emission.json per_block.blocks',
               'exact' if pf['supply_identity_ok'] == pf['blocks'] else 'lower-bound', unit='atomic'),
        figure('dc3-window-fees', 'DC3', 'window fees, known blocks', em['fees']['known_sum_atomic'], W, em['fees']['known_blocks'],
               em['fees']['known_blocks'] + em['fees']['pending_blocks'], 'derived/emission.json fees.known_blocks', 'derived/emission.json fees',
               'exact' if em['fees']['pending_blocks'] == 0 else 'lower-bound', unit='atomic'),
        figure('dc3-window-public-burns', 'DC3', 'window public burns, known blocks', pf['burn_known_sum'], W, em['fees']['known_blocks'],
               em['fees']['known_blocks'] + em['fees']['pending_blocks'], 'derived/emission.json fees.known_blocks (bodies held)',
               'derived/emission.json fees', 'exact' if em['fees']['pending_blocks'] == 0 else 'lower-bound', unit='atomic'),
    ]
    by = collections.defaultdict(list)
    for f in figs:
        by[f['class']].append(f['id'])
    classes = {
        'DC0': {'name': 'unclassified finding', 'what': 'a finding that fits no class; goes to the disclosure track as a new fact',
                'detected': len(dc0), 'detected_txids': dc0[:20], 'figures': by['DC0'],
                'detection_scope': {'window_blocks_tx_lists': N, 'of': N, 'anchor': 'derived/window.jsonl.gz'}},
        'DC1': {'name': 'duplication ladder', 'anchor': 'blockchain/hardfork_fixes.go:27', 'claims': ['X-EXEMPT', 'C6'],
                'detected_raw': bodies_raw, 'table_entries': len(hf3['rows']), 'groups': dict(groups),
                'subclasses': {'DC1-obs': n_obs, 'DC1-hidden': 0, 'DC1-pending': len(hf3['rows']) - n_obs if sc else 'pending'},
                'subclass_rule': 'DC1-hidden only beyond an evidenced FQ3 boundary (none known), so the rest is DC1-pending',
                'detection_scope': {'heights_raw': N, 'of': WINDOW[1] - WINDOW[0] + 1, 'anchor': 'derived/window.jsonl.gz'},
                'grade': 'NOT-DECIDABLE-FROM-PUBLIC-DATA (per tx, derived/grades.json)', 'figures': by['DC1']},
        'DC2': {'name': 'proof soundness', 'claims': ['C1', 'C2', 'C3', 'C5'],
                'track_c1': {'verdict': c1_last.get('verdict', 'pending'), 'state': c1_last.get('state', 'pending'), 'round': c1_last.get('round', 'pending')},
                'present_now': dc2_present if dc2_present is not None else 'pending',
                'grade': 'NOT-DECIDABLE-FROM-PUBLIC-DATA (once, at class level, scope genesis .. now)', 'per_tx': 'never graded per tx',
                'figures': by['DC2']},
        'DC3': {'name': 'public-value identities', 'anchor': 'blockchain/supply.go:5',
                'grade': em['grade']['verdict_grade'] + ' (scope: ' + em['scope'] + ')', 'figures': by['DC3']},
    }
    out = {
        'schema': SCHEMA, 'dataset': I.ds.name, 'base': I.base.name if I.base else 'none',
        'rules': {
            'exact': 'coverage num == den (both integers) and no pending member of the figure\'s own class in its scope',
            'forbidden_phrases': ['supply audit', 'audited supply', 'total inflation', 'true supply'],
            'forbidden_unless': 'bound_type exact over genesis .. now (no figure qualifies while DC2 is open)',
            'no_cross_class_sum': 'a figure has exactly one class; a figure derived from others names only figures of its own class',
            'fix_is_not_restore': 'a fix status never changes a historical grade (rule 10)',
        },
        'records': {'tx': dict(sorted(tag.items())), 'block': {'DC3': len(I.block_records())}, 'window_rows': {'DC3': N}},
        'classes': classes,
        'figures': figs,
        'headline': {'dc2_present_now': dc2_present if dc2_present is not None else 'pending',
                     'text': (presence or {}).get('headline', {}).get('text', 'pending: presence.json not read')},
        'historical_grades': {'source': 'derived/grades.json', 'counts': grades.get('counts', {})},
        'inputs': dict(sorted(I.read.items())),
    }
    fq = {
        'schema': 'r26 fq v1 (rft §0.8.9 research questions)',
        'FQ1': {'question': 'DC1 census: two bodies under one TXID, parity, exception path; any duplicate outside the table (DC0)',
                'status': 'answered (partial: two-bodies pending)',
                'answer': {'table_groups_match_raw_carriers': dual_raw == groups['duplicates'] and single_raw == groups['no duplicates, but false parity'],
                           'duplicates_two_carriers': f'{dual_raw} of {groups["duplicates"]}',
                           'false_parity_one_carrier': f'{single_raw} of {groups["no duplicates, but false parity"]}',
                           'carriers_total': carriers_total, 'carriers_nonce_bypassed': nonce_bypassed,
                           'tx_parity_true': parity_true, 'two_bodies_under_one_txid': two_bodies,
                           'dc0_window_duplicates': len(dc0), 'window_distinct_txids': len(occ), 'window_tx_carrying_blocks': tx_blocks,
                           'window_txids_in_two_or_more_blocks': len(multi), 'of_which_in_table': len(multi) - len(dc0)},
                'anchors': ['derived/hf3.json rows[].carriers', 'derived/window.jsonl.gz rows[].tx_hashes', 'blockchain/hardfork_fixes.go:27',
                            'blockchain/transaction_verify.go:232-237'],
                'carriers_outside_window': outside,
                'note': (f'{len(outside)} table TXID(s) carried by a block outside the window (carriers_outside_window), so the window tx '
                         f'lists show {len(multi) - len(dc0)} table TXIDs twice while derived/hf3.json counts {dual_raw} with two carriers')
                        if len(multi) - len(dc0) != dual_raw else 'window and carrier counts agree'},
        'FQ2': {'question': 'DC1 amount observability: is a DC1 tx amount determined by public data?',
                'status': 'answered for the recorded criteria; S-R22 window-wide pending B96 bodies' if sc else 'pending: structural census not run',
                'criteria': {
                    'P1': {'what': 'a public plaintext value field (tx value, payload burn) of the DC1 tx', 'result': f'{public_value} of {len(hf3["rows"])}',
                           'anchor': 'derived/tx/<txid>.json value_field, burn_total'},
                    'S-R22': {'what': 'the R22 C3 structural signature (a randomness commitment shared by two payloads); recorded as counts only',
                              'result': (f'{len(sc["table_txs_with_a_shared_commitment"])} of {len(hf3["rows"])} within held bodies' if sc else 'pending'),
                              'scope': (f'{sc["bodies_decoded"]} held bodies ({held_window_txids} of {len(occ)} window TXIDs)' if sc else 'pending'),
                              'anchor': 'derived/fq.json FQ3.census'},
                },
                'coverage': {'dc1_obs': n_obs, 'dc1_detected': len(hf3['rows'])},
                'lower_bound_sum': obs_amount,
                'consequence': 'the external 23,886,517.3 figure stays EXT (disclosure track C6); no DERIVED input reproduces it'},
        'FQ3': {'question': 'the randomness-reuse boundary: which wallet versions reused payload randomness, from which height the signature stops',
                'status': 'partial: code side answered, on-chain boundary pending',
                'code_side': {'upstream_tags_with_deterministic_r': 'see presence of walletapi/transaction_build.go (FQ3 rows below)',
                              'local_fix': 'walletapi/transaction_build.go:355 pick_ring_order (R22, local only, not upstream)'},
                'census': sc if sc else 'pending: --structstats not given',
                'boundary_height': 'pending: no height boundary can be read while the signature is absent from every held body and the upstream '
                                   'code never changed; window-wide census needs the B96 bodies',
                'mechanism_link_to_dc1': 'pending (rft §0.8.9 FQ3: candidate, not established)'},
        'FQ4': {'question': 'DC2 presence in the current code (head, Release152, genesis-era tag) + structural transcript KAT',
                'status': 'answered' if presence else 'pending',
                'answer': {rev: {'admits': r['admits'], 'anchors': [a['anchor'] for a in r['anchors']]} for rev, r in (presence or {}).get('classes', {}).get('DC2', {}).items()},
                'transcript': (presence or {}).get('fq4_transcript', 'pending'),
                'kat': 'harness/kat/test_forensics_classes_r26.py CL4 pins the head transcript digest'},
        'FQ5': {'question': 'DC2 detectability from public data',
                'status': 'answered (INTERPRETATION, re-tested every round)',
                'answer': 'no public-data test separates a proof accepted under the defect from an honest one: consensus reads one boolean per payload, '
                          'the proof shape is fixed by the ring size, and scalar canonicality is already censused (FX-N3); a shape or size detector is infeasible (FX-N6)',
                'anchors': ['blockchain/transaction_verify.go:454', 'harness/loop/disclosure_track.json C3 (R24, NF24-4)', 'FX-N3', 'FX-N6']},
        'FQ6': {'question': 'what would restore a verifiable baseline (design only, FORK-REQUIRED)',
                'status': 'pending: FX-F5 / FX-F6 rows belong to the disclosure track (B114)'},
        'Q-CS': {'status': (invariant or {}).get('status', 'pending: invariant.json not read'), 'file': 'derived/invariant.json'},
    }
    if presence and 'fq3_wallet' in presence:
        fq['FQ3']['code_side']['upstream_tags_with_deterministic_r'] = presence['fq3_wallet']
    return out, fq


def dumps(o):
    return json.dumps(o, indent=1, sort_keys=True) + '\n'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--root', default=str(ROOT))
    ap.add_argument('--dataset', default='forensics/r26')
    ap.add_argument('--base', default='forensics/r25')
    ap.add_argument('--structstats', help='JSON lines from tools/forensics/classstats kind=structstats over the held bodies')
    ap.add_argument('--presence')
    ap.add_argument('--invariant')
    ap.add_argument('--track', default='harness/loop/disclosure_track.json')
    ap.add_argument('--write', action='store_true')
    ap.add_argument('--tag')
    a = ap.parse_args(argv)
    root = Path(a.root)
    if a.tag:
        print(json.dumps(tag_dataset(root / a.tag, root)))
        return 0
    I = Inputs(root / a.dataset, root / a.base if a.base else None, root)
    J = lambda p: json.loads((root / p).read_text()) if p and (root / p).exists() else None
    stats = [json.loads(l) for l in (root / a.structstats).read_text().splitlines() if l.strip()] if a.structstats else None
    pres = J(a.presence) or J(f'{a.dataset}/derived/presence.json')
    inv = J(a.invariant) or J(f'{a.dataset}/derived/invariant.json')
    cl, fq = build(I, pres, inv, stats, J(a.track))
    if stats is not None:
        fq['FQ3']['census_input_sha256'] = sha((root / a.structstats).read_bytes())
    if a.write:
        d = root / a.dataset / 'derived'
        d.mkdir(parents=True, exist_ok=True)
        (d / 'classes.json').write_text(dumps(cl))
        (d / 'fq.json').write_text(dumps(fq))
    print(f"records {cl['records']}; figures {len(cl['figures'])}; DC0 {cl['classes']['DC0']['detected']}; "
          f"FQ2 {fq['FQ2']['status']}; headline DC2 present {cl['headline']['dc2_present_now']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
