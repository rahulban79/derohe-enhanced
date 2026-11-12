#!/usr/bin/env python3
"""R30 forensics classes fixes (rft §7 B202, B203, B107, B110, B209, B210; §8 "R30 audit plan" forensics): the class
figures of dataset v5 re-derived from the base version's classes.json / fq.json and the held evidence. classes.py is a
sealed replay tool of v2..v4 (pinned by their manifests, never edited), so the R30 corrections live here as a PURE
transform that v5.py runs at build and at every replay (G28 re-derives it byte for byte).

What changes against the base (r28d) class files:
  B202  dc1-two-bodies is COMPUTED from the holders census (r29_b97_holders.json census.counts = audit D2-11): value =
        TXIDs held with two different bodies (lower bound), coverage = TXIDs held from 2+ holders over the multi-block
        TXIDs of derived/inclusions.json (not the 75 table rows: a single-carrier entry has one block); the v1
        'derived/tx/*.json' anchor goes; FQ1 status says what is answered.
  B203  (a) dc2-created-value coverage den = the proof-carrying txs 0..7,498,539 (dc2_den.py; NORMAL+SC+BURN, dedup by
        TXID), 7,498,540..tip pending; the VALUE stays the word unbounded (G31). (2)(3) the dc1-obs notes name S-RT as a
        precondition only (B180; DC1-obs stays P1 ∪ S-R22, rule 13, D4) and drop "held bodies only". Every non-exact
        figure carries `moves_when`.
  B209  DC0 below the window: dc0-genesis-listed-twice (a LOWER BOUND, R30 D1: the 200,000-tx dedup window) and
        dc0-genesis-executed-twice (pending), from dc0_genesis.py.
  B210  dc3-claim-grant from claim_grant.py: distinct registrations below 144,000 x 200 (bound upper-bound; grade
        exact-under-window-dedup; coverage over the checkpoint batches hi < 144,000), and dc3-claim-grant-credited: the
        grant the chain CREDITED, pending until the S7 replay decides the re-listings (R30 D2).
  B110  dc3-runc-sc-payouts from r29_b110_sc_payouts.json (exact only when 110 == 110 SC txs and 108 == 108 blocks).
Counts only (rule 13); no amount of a DC1 tx; no figure sums across classes.
"""
import copy, json

SCHEMA = 'r30 classes v1 (rft §0.8.9; B202, B203, B209, B210, B110 over the base class files)'
TWO_BODIES_NOTE = ('held sources only: a body never served by any reachable holder stays unobservable; each store keeps one '
                   'body per TXID (blockchain/storefs.go:306 WriteTX overwrites by TXID) and the holders are endpoint '
                   'pseudonyms whose independence is not provable (r29_b97_holders.json caveat); the false-parity entries '
                   'have one carrier block, so they are outside the denominator')
MOVES = {
    'dc1-two-bodies': ('a holder serving a different body for one of the multi-block TXIDs raises the value; a new reachable '
                       'holder can only add evidence, never lower it (lower bound)'),
    'dc1-obs-coverage': ('moves only if a recorded public-data criterion (P1 plaintext value, S-R22 shared commitment) finds a '
                         'table TXID; S-RT is a precondition, not an observation, and moves nothing (B180, rule 13, D4)'),
    'dc1-obs-amount': 'stays "none determinable" while DC1-obs coverage is 0; never rendered as 0 (G31)',
    'dc2-created-value': ('the value moves only with an upstream fix or a published detector (FQ5, B113; watched each round '
                          'like B184); the denominator grows when 7,498,540..tip is typed (S3)'),
    'dc0-genesis-listed-twice': ('the exact-dedup recount (S2, B182 report --exact) can only add TXIDs and listings '
                                 '(a lower bound)'),
    'dc3-claim-grant-credited': ('an S7 replay of 0..143,999 decides whether the re-listings below 144,000 re-applied '
                                 'the 200-atomic grant'),
    'dc0-genesis-executed-twice': 'an S7 replay of the repeat heights (pre-HF3 blockchain.go:665,716,995)',
    'dc3-claim-grant': ('the exact-dedup recount (S2) turns the bound exact; an S7 replay below 144,000 decides the 3,603 '
                        're-listings'),
}


def _fig(fid, cls, label, value, scope, num, den, na, da, bound, unit='count', note=None, **extra):
    f = {'id': fid, 'class': cls, 'label': label, 'value': value, 'unit': unit, 'scope': scope,
         'coverage': {'num': num, 'den': den, 'num_anchor': na, 'den_anchor': da}, 'bound_type': bound}
    if note:
        f['note'] = note
    f.update(extra)
    return f


def multi_block_txids(inclusions):
    """TXIDs carried by more than one RAW block (derived/inclusions.json rows). Pure."""
    return sorted(r['txid'] for r in inclusions.get('rows') or [] if len(r.get('heights') or []) > 1)


def two_bodies(b97, inclusions):
    """(value, num, den, status text) of dc1-two-bodies from the holders census; value/num 'pending' without it. Pure."""
    den = len(multi_block_txids(inclusions))
    c = ((b97 or {}).get('census') or {}).get('counts')
    if not c:
        return 'pending: no holders census in the inputs', 'pending', den, 'pending: holders census not held'
    txt = (f"lower bound {c['different']}: of {den} multi-block TXIDs, {c['two_plus_holders']} held from 2+ holders "
           f"({c['equal']} equal, {c['different']} different), {c['single_holder']} from one holder, {c['no_copy']} with no copy")
    return c['different'], c['two_plus_holders'], den, txt


def transform(classes_b, fq_b, inclusions_b, b97, dc2den, dc0gen, grant, b110, version='r30', base='r28d', pins=None):
    """(classes.json bytes, fq.json bytes) of v5 from the base files and the held records (pure)."""
    cl = json.loads(classes_b)
    fq = json.loads(fq_b)
    inc = json.loads(inclusions_b)
    figs = {f['id']: f for f in cl['figures']}
    # ---- B202 dc1-two-bodies
    val, num, den, txt = two_bodies(b97, inc)
    f = figs['dc1-two-bodies']
    f['value'] = val
    f['coverage'] = {'num': num, 'den': den,
                     'num_anchor': 'harness/runtime/r29_b97_holders.json census.counts.two_plus_holders (audit D2-11)',
                     'den_anchor': 'derived/inclusions.json rows with more than one carrier height'}
    f['bound_type'] = 'lower-bound' if isinstance(val, int) else 'unbounded'
    f['note'] = TWO_BODIES_NOTE
    # ---- B203 (a) the DC2 denominator; the value stays unbounded
    f = figs['dc2-created-value']
    f['coverage'] = {'num': 0, 'den': dc2den['den'],
                     'num_anchor': 'no public-data test separates the cases (fq.json FQ5)',
                     'den_anchor': (f"harness/runtime/r30_dc2_den.json den: proof-carrying txs (NORMAL, SC, BURN) over "
                                    f"{dc2den['den_scope'][0]:,}..{dc2den['den_scope'][1]:,}, dedup by TXID; "
                                    f"{dc2den['den_pending']['range'][0]:,}..tip pending")}
    f['value'], f['bound_type'] = 'unbounded', 'unbounded'
    f['note'] = ('lower bound 0, no upper bound; graded once: NOT-DECIDABLE-FROM-PUBLIC-DATA; coverage = 0 separable of the '
                 'proof-carrying txs counted so far')
    # ---- B203 (2)(3) the DC1-obs notes
    srt = (fq.get('FQ2', {}).get('criteria') or {}).get('S-RT')
    figs['dc1-obs-coverage']['note'] = (
        'lower bound: criteria P1 (public plaintext value fields) and S-R22 (shared randomness commitment); '
        + (f"S-RT ({srt['result']}) is a precondition only, not an observed amount (B180), so it adds no TXID; " if srt else '')
        + 'the rest is DC1-pending, not DC1-hidden, until the FQ3 boundary is known')
    figs['dc1-obs-amount']['note'] = (
        'empty under P1 and S-R22' + ('; S-RT is a precondition only, not an observation (B180)' if srt else '')
        + '; amounts are not computed by policy (rule 13, D4); never a supply figure (rule 8); the external 23,886,517.3 '
          'figure stays EXT (C6)')
    # ---- B209, B210, B110: new figures
    c0 = dc0gen['census']
    lt = dc0gen['figure_listed_twice']
    sg = {'heights': dc0gen['scope']['heights'], 'text': dc0gen['scope']['text']}
    gl = grant['supply_go']['lines']
    sgo = f"{gl.get('comment', '?') - 1}-{gl.get('add')}" if isinstance(gl.get('comment'), int) else str(gl.get('add'))
    new = [
        _fig('dc0-genesis-listed-twice', 'DC0', 'TXIDs listed by two or more blocks below the HF3 window, outside the HF3 table',
             c0['by_class'].get('DC0', 0), sg, lt['coverage']['num'], lt['coverage']['den'],
             'harness/runtime/r30_dc0_genesis.json (B182 deep checkpoint batches, verified)', lt['coverage']['den_anchor'],
             'lower-bound', note=lt['caveat']),
        _fig('dc0-genesis-executed-twice', 'DC0', 'of those, TXIDs whose repeat listing changed state (executed twice)',
             'pending: needs a replay of the repeat heights (S7)', sg, 'pending', c0['distinct_txids'],
             'none (no replay below the window)', 'harness/runtime/r30_dc0_genesis.json census.distinct_txids', 'unbounded'),
        _fig('dc3-claim-grant', 'DC3', (f"distinct registrations below 144,000 x 200 = {grant['value_atomic']:,} "
                                        f"(= blockchain/supply.go:{sgo})"),
             grant['value_atomic'], {'heights': grant['scope']['heights'], 'text': grant['scope']['text']},
             grant['census']['batches'], grant['census']['batches'],
             'harness/runtime/r30_claim_grant.json census.batches (checkpoint batches hi < 144,000 counted)',
             'harness/runtime/r30_claim_grant.json census.batches (checkpoint batches hi < 144,000)',
             'upper-bound' if grant['identity_holds'] else 'unbounded', unit='atomic',
             note=('equals blockchain/supply.go:7-9 (identity holds: ' + str(grant['identity_holds']).lower() + '); grade '
                   'exact-under-window-dedup: distinct TXIDs under the 200,000-tx dedup window, so a far repeat could only '
                   'over-count (upper bound) until the exact recount; it is NOT the credited grant (see '
                   'dc3-claim-grant-credited)'), grade='exact-under-window-dedup'),
        _fig('dc3-claim-grant-credited', 'DC3', 'claim grant credited by the chain below 144,000 (re-listings included)',
             'pending: needs a replay of 0..143,999 (S7)', {'heights': grant['scope']['heights'], 'text': grant['scope']['text']},
             'pending', grant.get('relistings_below_144000', 'pending'), 'none (no replay below the window)',
             'harness/runtime/r30_claim_grant.json relistings_below_144000', 'unbounded', unit='atomic',
             note=('whether the second listings below 144,000 re-applied the 200-atomic grant (pre-HF3 blockchain.go:995 '
                   'executes every listed tx) is pending until an S7 replay')),
    ]
    if b110:
        g = b110['figure']
        ex = g['coverage']['txs']['num'] == g['coverage']['txs']['den'] and g['coverage']['blocks']['num'] == g['coverage']['blocks']['den']
        new.append(_fig('dc3-runc-sc-payouts', 'DC3', g['label'], g['value'],
                        {'heights': g['scope']['heights'], 'text': f"run C range {g['scope']['heights'][0]:,}..{g['scope']['heights'][1]:,}"},
                        g['coverage']['txs']['num'], g['coverage']['txs']['den'],
                        'harness/runtime/r29_b110_sc_payouts.json figure.coverage.txs.num (auditor ok_sc)',
                        'harness/runtime/r29_b110_sc_payouts.json figure.coverage.txs.den (SC txs in range)',
                        'exact' if ex else 'lower-bound', unit='atomic',
                        note=f"{g['below_run_c']['txs']} SC txs below the run C range stay pending ({g['below_run_c']['reason']})"))
    for x in new:
        if x['id'] in figs:
            raise ValueError(f'figure {x["id"]} already in the base class file')
        cl['figures'].append(x)
    for x in cl['figures']:
        if x['bound_type'] != 'exact':
            x['moves_when'] = MOVES.get(x['id'], 'the coverage numerator reaches the denominator under the recorded criteria')
    by = {}
    for x in cl['figures']:
        by.setdefault(x['class'], []).append(x['id'])
    for k, v in cl['classes'].items():
        v['figures'] = by.get(k, [])
    cl['classes']['DC0']['genesis'] = {'listed_twice': c0['by_class'].get('DC0', 0), 'dc1_in_table': c0['by_class'].get('DC1', 0),
                                       'type_evidence': c0['type_evidence'], 'by_hf_era_of_repeat': c0['by_hf_era_of_repeat'],
                                       'executed_twice': 'pending', 'anchor': 'harness/runtime/r30_dc0_genesis.json'}
    cl['schema'], cl['dataset'], cl['base'] = SCHEMA, version, base
    cl['inputs'] = dict(sorted({**cl.get('inputs', {}), **(pins or {})}.items()))
    # ---- fq.json: FQ1 two bodies answered at the held scope
    q = fq['FQ1']
    q['answer']['two_bodies_under_one_txid'] = txt
    q['status'] = ('answered: two bodies under one TXID ' + txt + '; executed-twice below the window pending (S7)'
                   if isinstance(val, int) else 'answered (partial: two-bodies pending)')
    q['answer']['dc0_genesis_listed_twice'] = c0['by_class'].get('DC0', 0)
    q.setdefault('anchors', []).append('harness/runtime/r29_b97_holders.json census.counts (audit D2-11)')
    fq['schema_r30'] = SCHEMA
    dump = lambda o: (json.dumps(o, indent=1, sort_keys=True) + '\n').encode()
    return dump(cl), dump(fq)
