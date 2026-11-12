#!/usr/bin/env python3
"""KAT + mutation proofs for the R30 forensics dimension, stage 1 (rft §7 B202, B203, B209, B210, B111, B216, B217,
B218, B207; §8 "R30 audit plan" S0). No network, no node, no decoder build: forged batch records, forged class files
and forged reports in memory or in temp dirs; the committed checks read this tree's records.

  FX1 claim_grant (B210): only batches with hi < 144,000 count; a batch whose hi is 144,000 is a straddling batch,
      never counted; supply.go's account count and total are parsed; the identity holds only when both equal.
  FX2 dc0_genesis (B209): a TXID repeated in two later batches is ONE distinct TXID listed three times; a table TXID is
      DC1, any other DC0; type evidence (decoder / inferred / untyped); a batch across an HF boundary is 'straddles'.
  FX3 dc2_den (B203 a): NORMAL + SC + BURN only (REGISTRATION never); a window TXID listed by a block outside the
      window is an overlap (counted once).
  FX4 b111_premine (B111): keys = registrations + 1 gives residual 0; without the premine term it is 1; the status
      stays a HYPOTHESIS.
  FX5 classes_r30 (B202, B203, B209, B210, B110): dc1-two-bodies = holders-census `different` (0 -> 0, 1 -> 1),
      lower-bound, den = multi-block TXIDs of inclusions.json (not the 75 rows); the DC2 value stays unbounded with an
      integer den; S-RT is named in the notes and adds nothing to DC1-obs; every non-exact figure has moves_when; the
      new DC0 / claim-grant / SC-payout figures pass G31's figure rules; FQ1 status computed.
  FX6 bounds.check_r30 (G31 from v5): a 'pending' DC2 den, the old two-bodies literal, a den != multi-block count and a
      non-exact figure without moves_when each FAIL; a pre-r30 dataset is not checked.
  FX7 audit2 v5 (D2-29..D2-34): a figure that differs from the own recount turns its challenge to FAILS; a missing
      checkpoint is UNRESOLVED, never HOLDS; dup_builder_grade reads the computed figure; audit_check requires D2-29..34
      for r30.
  FX8 facts (B218, B216): a record path absent from a PASS report is flagged unless legacy (pre-r30 only); a FAIL report
      flags nothing; presence_head_label says 'round head' only for the build commit, else 'as of'.
  FX9 s7_replay.label (B218): a FAIL report prints its fail_reasons and never 'no archive copy'; PARTIAL only on PASS.
  FX10 forensics_section (B217): page_round reads frozen/r<N> (closed pages < 30 keep the old text), the live page is
      the newest round; growth rows = one per ledger version, no '(planned)'.
  FX11 v5 (B207, B216): v5 re-derives classes.json (not a class file), inherits every other v4 file, re-reads presence;
      presence_head_label as FX8.
  FX12 s0_checkpoint --check (S7): a committed S0 record that differs from its re-derivation is DIFFERS; without the
      checkpoint its two records are SKIPPED (labelled), the other two still compared.
  R30 D1-D3 (adversarial verifier): listed-twice is a lower bound (keys '>=n', bound lower-bound + moves_when) and G31
      FAILS an exact figure whose caveat says lower bound (FX2, FX5, FX6); the claim grant is labelled distinct
      registrations x 200 with a batches den, and a separate credited-grant figure is pending (FX5); b111 status is a
      HYPOTHESIS for any arithmetic (FX4); both window ends count (FX3); 'below 144,000' reads the batch hi (FX2).
  FX13 audit2 D2-27 for v5: only the classes_r30 FQ1 additions leave the base rest-equality; the DC0 count equals the
      audit's own recount, one anchor added; a pre-v5 fq.json is compared as before.
  FX14 facts.record_paths_for (B218): a v5 dataset carries no replay_wall1_ok fact; other record paths still required.
  Committed: r28d is sealed; the four r30 S0 records carry the recomputed numbers and the checkpoint pin.

  python3 -I harness/kat/test_forensics_r30.py   # exit 0 ok · 3 a KAT failed · 4 a mutation not caught / INVALID
"""
import importlib.util, json, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
T1, T2, T3, T4 = '00' * 3 + 'a1' * 29, '00' * 3 + 'b2' * 29, '0000' + 'c3' * 30, 'd4' * 32   # T1 = table TXID


def load(base, rel, tag):
    for d in (base / 'forensics', base / 'src'):
        sys.path.insert(0, str(d))
    try:
        spec = importlib.util.spec_from_file_location(f'fx30_{tag}_{id(base)}_{len(sys.modules)}', base / rel)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    finally:
        del sys.path[:2]


def batch(lo, hi, types=None, dup=None, lt3=None):
    r = {'kind': 'batch', 'lo': lo, 'hi': hi, 'blocks': hi - lo + 1, 'types': types or {}, 'reg_lt3': lt3 or [], 'reg_lz': {}}
    if dup:
        r['dup_txids'] = dup
    return r


def fx1(base):
    f = []
    CG = load(base, 'forensics/claim_grant.py', 'cg')
    bs = [batch(0, 99, {'REGISTRATION': 3, 'NORMAL': 1}), batch(143900, 143999, {'REGISTRATION': 2}),
          batch(143901, 144000, {'REGISTRATION': 5}), batch(144000, 144099, {'REGISTRATION': 7})]
    c = CG.grant_census(bs)
    if c['types'].get('REGISTRATION') != 5 or c['straddling_batches'] != 1 or c['batches'] != 2:
        f.append(f'FX1 grant census {c}')
    if CG.relistings_below([batch(0, 99, dup=[T1, T2]), batch(144000, 144099, dup=[T3])]) != 2:
        f.append('FX1 relistings below 144,000')
    t = Path(tempfile.mkdtemp(prefix='fx30cg_'))
    try:
        (t / 'blockchain').mkdir()
        (t / 'blockchain' / 'supply.go').write_text('func X() {\n\t// there were 5 such accounts, so total of 1000 was added\n\tsupply += 1000\n}\n')
        acc, tot, lines = CG.supply_constants(t)
        if (acc, tot, lines.get('add')) != (5, 1000, 3):
            f.append(f'FX1 supply.go parse {acc} {tot} {lines}')
    finally:
        shutil.rmtree(t, ignore_errors=True)
    return f


def fx2(base):
    f = []
    DG = load(base, 'forensics/dc0_genesis.py', 'dg')
    hf = [('HF1', 21480), ('MAJOR_HF2', 481600)]
    bs = [batch(0, 99, lt3=[T2]), batch(30000, 30099, dup=[T1, T2]), batch(500000, 500099, dup=[T2, T4]),
          batch(21400, 21499, dup=[T3])]
    c = DG.census(bs, {T1}, hf)
    if c['distinct_txids'] != 4 or c['repeat_listings'] != 5:
        f.append(f"FX2 distinct {c['distinct_txids']} repeats {c['repeat_listings']}")
    if c['by_class'] != {'DC0': 3, 'DC1': 1}:
        f.append(f"FX2 classes {c['by_class']}")
    if c['by_times_listed'] != {'\u22652': 3, '\u22653': 1}:          # R30 D1: listings are a lower bound per TXID
        f.append(f"FX2 listed {c['by_times_listed']}")
    if c['type_evidence'] != {'decoder': 1, 'inferred-registration': 1, 'untyped': 2}:
        f.append(f"FX2 type evidence {c['type_evidence']}")
    if c['by_hf_era_of_repeat'] != {'HF1': 2, 'MAJOR_HF2': 1, 'straddles:HF1': 1}:
        f.append(f"FX2 eras {c['by_hf_era_of_repeat']}")
    if DG.era(0, 99, hf) != 'pre-HF1' or DG.era(481600, 481699, hf) != 'MAJOR_HF2':
        f.append('FX2 era boundaries')
    # R30 D3c: 'below 144,000' is the batch HI (a batch across 144,000 is not below it)
    b2 = DG.census([batch(143900, 143999, dup=[T3]), batch(143950, 144049, dup=[T4])], set(), hf)
    if b2['repeat_below_144000'] != 1:
        f.append(f"FX2 repeat_below_144000 {b2['repeat_below_144000']} (a batch across 144,000 counted)")
    # R30 D1: the listed-twice figure is a lower bound with a moves_when (never exact)
    if DG.LISTED_BOUND != 'lower-bound' or 'lower bound' not in DG.LISTED_MOVES:
        f.append(f'FX2 listed-twice bound {DG.LISTED_BOUND}')
    return f


def fx3(base):
    f = []
    DD = load(base, 'forensics/dc2_den.py', 'dd')
    if DD.proof_txs({'NORMAL': 2, 'SC': 3, 'BURN': 1, 'REGISTRATION': 50}) != 6:
        f.append('FX3 proof_txs counts a type that carries no proof')
    txs = [{'txid': T1, 'tx_type': 'NORMAL', 'carrier_height': 7415500}, {'txid': T2, 'tx_type': 'SC', 'carrier_height': 7415600},
           {'txid': T3, 'tx_type': 'REGISTRATION', 'carrier_height': 7415700}, {'txid': T4, 'tx_type': 'NORMAL', 'carrier_height': 7498000}]
    n, over = DD.window_segment(txs, {T1: {7415500, 7497950}, T2: {7415600}})
    if n != 2 or over != [T1]:
        f.append(f'FX3 window segment {n} {over}')
    # R30 D3b: both window ends are inside the window
    lo, hi = DD.WINDOW
    edge = [{'txid': T1, 'tx_type': 'NORMAL', 'carrier_height': lo}, {'txid': T2, 'tx_type': 'BURN', 'carrier_height': hi},
            {'txid': T3, 'tx_type': 'NORMAL', 'carrier_height': lo - 1}, {'txid': T4, 'tx_type': 'NORMAL', 'carrier_height': hi + 1}]
    n, over = DD.window_segment(edge, {})
    if n != 2 or over:
        f.append(f'FX3 window boundaries {n} {over}')
    return f


def fx4(base):
    f = []
    BP = load(base, 'forensics/b111_premine.py', 'bp')
    if BP.residual(2141704, 2141703) != 0 or BP.residual(10, 9, premine=0) != 1:
        f.append('FX4 residual with / without the premine term')
    # R30 D3a: the status stays a HYPOTHESIS whatever the arithmetic (the S4 set diff has not run)
    for ok in (True, False):
        st = BP.status(ok)
        if not st.startswith('HYPOTHESIS') or 'CONFIRMED' in st.upper():
            f.append(f'FX4 status({ok}) = {st!r}')
    if BP.status(True) == BP.status(False):
        f.append('FX4 status does not say whether the arithmetic closes')
    return f


def forged_classes(different=0):
    figs = [
        {'id': 'dc1-two-bodies', 'class': 'DC1', 'label': 'x', 'value': 'pending: one body was fetched per TXID; ...', 'unit': 'count',
         'scope': {'heights': [1, 2], 'text': 'w'}, 'coverage': {'num': 'pending', 'den': 75, 'num_anchor': 'derived/tx/*.json duplicates', 'den_anchor': 'r'},
         'bound_type': 'unbounded'},
        {'id': 'dc1-obs-coverage', 'class': 'DC1', 'label': 'x', 'value': 0, 'unit': 'count', 'scope': {'heights': [1, 2], 'text': 'w'},
         'coverage': {'num': 0, 'den': 75, 'num_anchor': 'a', 'den_anchor': 'b'}, 'bound_type': 'lower-bound', 'note': 'held bodies only'},
        {'id': 'dc1-obs-amount', 'class': 'DC1', 'label': 'x', 'value': 'none determinable', 'unit': 'atomic', 'scope': {'heights': [1, 2], 'text': 'w'},
         'coverage': {'num': 0, 'den': 75, 'num_anchor': 'a', 'den_anchor': 'b'}, 'bound_type': 'lower-bound'},
        {'id': 'dc2-created-value', 'class': 'DC2', 'label': 'x', 'value': 'unbounded', 'unit': 'atomic', 'scope': {'heights': 'genesis..now', 'text': 'g'},
         'coverage': {'num': 0, 'den': 'pending', 'num_anchor': 'a', 'den_anchor': 'pending: every proof since genesis'}, 'bound_type': 'unbounded'},
        {'id': 'dc0-window-duplicates', 'class': 'DC0', 'label': 'x', 'value': 0, 'unit': 'count', 'scope': {'heights': [1, 2], 'text': 'w'},
         'coverage': {'num': 5, 'den': 5, 'num_anchor': 'a', 'den_anchor': 'b'}, 'bound_type': 'exact'},
    ]
    cl = {'dataset': 'r28d', 'base': 'r25', 'figures': figs, 'inputs': {},
          'classes': {k: {'figures': []} for k in ('DC0', 'DC1', 'DC2', 'DC3')}}
    fq = {'FQ1': {'status': 'answered (partial: two-bodies pending)', 'answer': {}, 'anchors': []},
          'FQ2': {'criteria': {'P1': {}, 'S-R22': {}, 'S-RT': {'result': '60 of 75 carry it'}}, 'coverage': {'dc1_obs': 0}}}
    inc = {'rows': [{'txid': T1, 'heights': [10, 12]}, {'txid': T2, 'heights': [11, 13]}, {'txid': T3, 'heights': [14]}]}
    b97 = {'census': {'counts': {'different': different, 'equal': 2 - different, 'two_plus_holders': 2, 'single_holder': 0, 'no_copy': 0}}}
    den = {'den': 1234, 'den_scope': [0, 7498539], 'den_pending': {'range': [7498540, 'tip']}}
    dc0 = {'census': {'by_class': {'DC0': 9}, 'distinct_txids': 9, 'type_evidence': {}, 'by_hf_era_of_repeat': {}},
           'scope': {'heights': [0, 99], 'text': 't'},
           'figure_listed_twice': {'coverage': {'num': 100, 'den': 100, 'den_anchor': 'h'}, 'caveat': 'c'}}
    grant = {'value_atomic': 1000, 'scope': {'heights': [0, 143999], 'text': 't'}, 'census': {'batches': 3},
             'supply_go': {'lines': {'comment': 8, 'add': 9}, 'accounts': 5}, 'identity_holds': True, 'relistings_below_144000': 7}
    b110 = {'figure': {'label': 'sc', 'value': 800, 'scope': {'heights': [1, 2]}, 'below_run_c': {'txs': 89, 'reason': 'r'},
                       'coverage': {'txs': {'num': 110, 'den': 110}, 'blocks': {'num': 108, 'den': 108}}}}
    d = lambda o: json.dumps(o).encode()
    return d(cl), d(fq), d(inc), b97, den, dc0, grant, b110


def fx5(base):
    f = []
    CR = load(base, 'forensics/classes_r30.py', 'cr')
    BD = load(base, 'forensics/bounds.py', 'bd')
    for diff in (0, 1):
        cb, fb = CR.transform(*forged_classes(diff))
        cl, fq = json.loads(cb), json.loads(fb)
        figs = {x['id']: x for x in cl['figures']}
        tb = figs['dc1-two-bodies']
        if tb['value'] != diff or tb['bound_type'] != 'lower-bound' or tb['coverage']['den'] != 2 or tb['coverage']['num'] != 2:
            f.append(f"FX5 two bodies (different={diff}): {tb['value']} {tb['bound_type']} {tb['coverage']}")
        if 'derived/tx/' in tb['coverage']['num_anchor']:
            f.append('FX5 two-bodies anchor still names the v1 layout')
        d2 = figs['dc2-created-value']
        if d2['value'] != 'unbounded' or d2['bound_type'] != 'unbounded' or d2['coverage']['den'] != 1234:
            f.append(f"FX5 DC2 {d2['value']} {d2['bound_type']} {d2['coverage']['den']}")
        if 'S-RT' not in figs['dc1-obs-coverage']['note'] or 'held bodies only' in figs['dc1-obs-coverage']['note']:
            f.append('FX5 dc1-obs note: S-RT not named or "held bodies only" kept')
        if figs['dc1-obs-coverage']['value'] != 0 or 'S-RT' not in figs['dc1-obs-amount']['note']:
            f.append('FX5 S-RT moved DC1-obs or the amount note does not name it')
        miss = [x['id'] for x in cl['figures'] if x['bound_type'] != 'exact' and not x.get('moves_when')]
        if miss:
            f.append(f'FX5 non-exact figures without moves_when: {miss}')
        for k in ('dc0-genesis-listed-twice', 'dc0-genesis-executed-twice', 'dc3-claim-grant', 'dc3-runc-sc-payouts'):
            if k not in figs:
                f.append(f'FX5 figure {k} missing')
        lt = figs.get('dc0-genesis-listed-twice') or {}
        if lt.get('bound_type') != 'lower-bound' or not lt.get('moves_when'):
            f.append(f"FX5 dc0-genesis-listed-twice graded {lt.get('bound_type')} (R30 D1: a lower bound with moves_when)")
        g = figs.get('dc3-claim-grant') or {}
        if g.get('label') != 'distinct registrations below 144,000 x 200 = 1,000 (= blockchain/supply.go:7-9)':
            f.append(f"FX5 claim-grant label {g.get('label')!r} (R30 D2)")
        if 'census.batches' not in g.get('coverage', {}).get('den_anchor', '') or 'accounts' in g.get('coverage', {}).get('den_anchor', ''):
            f.append(f"FX5 claim-grant den_anchor {g.get('coverage', {}).get('den_anchor')!r} (R30 D2: the batches)")
        cr = figs.get('dc3-claim-grant-credited') or {}
        if not str(cr.get('value', '')).startswith('pending') or cr.get('bound_type') != 'unbounded' or cr.get('coverage', {}).get('den') != 7 \
                or not cr.get('moves_when'):
            f.append(f"FX5 dc3-claim-grant-credited {cr.get('value')!r} {cr.get('bound_type')} (R30 D2: pending, S7)")
        if figs.get('dc3-runc-sc-payouts', {}).get('bound_type') != 'exact':
            f.append('FX5 run C SC payouts not exact at 110/110')
        if not str(fq['FQ1']['status']).startswith('answered: two bodies') or cl['dataset'] != 'r30':
            f.append(f"FX5 FQ1 status / dataset label {fq['FQ1']['status'][:40]} {cl['dataset']}")
        p = BD.check_figures(cl)
        if p:
            f.append(f'FX5 G31 figure rules: {p[:2]}')
    a = forged_classes(0)
    b110 = json.loads(json.dumps(a[7]))
    b110['figure']['coverage']['txs']['num'] = 109
    figs = {x['id']: x for x in json.loads(CR.transform(*a[:7], b110)[0])['figures']}
    if figs['dc3-runc-sc-payouts']['bound_type'] == 'exact':
        f.append('FX5 run C SC payouts exact at 109/110')
    return f


def fx6(base):
    f = []
    BD = load(base, 'forensics/bounds.py', 'bd6')
    CR = load(base, 'forensics/classes_r30.py', 'cr6')
    good = json.loads(CR.transform(*forged_classes(0))[0])
    t = Path(tempfile.mkdtemp(prefix='fx30bd_'))
    try:
        ds = t / 'r30'
        (ds / 'derived').mkdir(parents=True)
        (ds / 'derived' / 'inclusions.json').write_text(forged_classes(0)[2].decode())
        good['figures'] = [x for x in good['figures']]
        for x in good['figures']:
            if x['id'] == 'dc2-created-value':
                x['coverage']['den_anchor'] = 'harness/runtime/r30_dc2_den.json den: ...'
        if BD.check_r30(good, ds):
            f.append(f'FX6 a correct r30 class file fails: {BD.check_r30(good, ds)[:2]}')
        for what, mut in (('pending den', lambda c: c['figures'][3]['coverage'].__setitem__('den', 'pending')),
                          ('old literal', lambda c: c['figures'][0].__setitem__('value', 'pending: one body was fetched per TXID; x')),
                          ('den 75', lambda c: c['figures'][0]['coverage'].__setitem__('den', 75)),
                          ('no moves_when', lambda c: c['figures'][1].pop('moves_when')),
                          ('DC2 value 0', lambda c: c['figures'][3].__setitem__('value', 0)),
                          ('exact with a lower-bound caveat', lambda c: c['figures'][4].update(
                              note='exact for the checkpoint, a lower bound for the chain'))):
            c = json.loads(json.dumps(good))
            mut(c)
            if not BD.check_r30(c, ds):
                f.append(f'FX6 {what} passes check_r30')
        old = json.loads(json.dumps(good))
        old['dataset'] = 'r28d'
        old['figures'][3]['coverage']['den'] = 'pending'
        if BD.check_r30(old, ds):
            f.append('FX6 a pre-r30 dataset is checked by the r30 rules')
    finally:
        shutil.rmtree(t, ignore_errors=True)
    return f


def forged_v5():
    return {'two_bodies': {'own_different': 0, 'own_multi': 67, 'own_2plus': 67, 'claimed_value': 0, 'claimed_num': 67,
                           'claimed_den': 67, 'claimed_bound': 'lower-bound', 'holds': True},
            'dc2_den': {'own_sum': 10, 'claimed_sum': 10, 'claimed_den': 9, 'overlap': 1, 'value': 'unbounded', 'bound': 'unbounded',
                        'census_read': True, 'registration_counted': False, 'holds': True},
            'claim_grant': {'unresolved': 'checkpoint not on this machine'},
            'dc0_genesis': {'own_distinct': 3, 'claimed_dc0': 3, 'holds': True},
            'consistency': {'dataset_label': 'r30', 'holds': True}, 'b111': {'own_residual_no_premine': 1, 'premine_keys': 1,
                                                                             'status': 'HYPOTHESIS', 'holds': True}}


def fx7(base):
    f = []
    A = load(base, 'forensics/audit2.py', 'a2')
    AC = load(base, 'forensics/audit_check.py', 'ac')
    r = {c['id']: c['result'] for c in A.challenges_v5(forged_v5())}
    if r != {'D2-29': 'HOLDS', 'D2-30': 'HOLDS', 'D2-31': 'UNRESOLVED', 'D2-32': 'HOLDS', 'D2-33': 'HOLDS', 'D2-34': 'HOLDS'}:
        f.append(f'FX7 challenge results {r}')
    V = forged_v5()
    V['two_bodies']['holds'] = False
    V['dc2_den']['census_read'] = False
    r = {c['id']: c['result'] for c in A.challenges_v5(V)}
    if r['D2-29'] != 'FAILS' or r['D2-30'] != 'UNRESOLVED':
        f.append(f'FX7 a failed recount still {r["D2-29"]} / unread census {r["D2-30"]}')
    if A.challenges_v5(None) != []:
        f.append('FX7 v5 challenges on a pre-v5 dataset')
    if not A.dup_builder_grade(forged_v5()).startswith('lower bound 0') or not A.dup_builder_grade(None).startswith('pending'):
        f.append('FX7 dup_builder_grade')
    if not set(('D2-29', 'D2-30', 'D2-31', 'D2-32', 'D2-33', 'D2-34')) <= set(AC.REQUIRED_BY_VERSION.get('r30', ())):
        f.append('FX7 audit_check does not require D2-29..D2-34 for r30')
    return f


def fx8(base):
    f = []
    FX = load(base, 'forensics/facts.py', 'fx')
    P = {'a': ('store', 'x'), 'b': ('rederive', 'equal')}
    if FX.unrecorded_paths({'result': 'PASS', 'store': {}, 'rederive': {'equal': 3}}, P, {}) != [('a', 'store.x')]:
        f.append('FX8 an absent record path in a PASS report is not flagged')
    if FX.unrecorded_paths({'result': 'PASS', 'store': {}, 'rederive': {'equal': 3}}, P, {'a': 'legacy'}) != []:
        f.append('FX8 a legacy path is flagged')
    if FX.unrecorded_paths({'result': 'FAIL'}, P, {}) != []:
        f.append('FX8 a FAIL report flags paths')
    pr = {'revs': [{'rev': 'HEAD', 'commit': 'ab' * 20}]}
    if FX.presence_head_label(pr, 'ab' * 20) != 'round head ' + ('ab' * 20)[:12] or not FX.presence_head_label(pr, 'cd' * 20).startswith('as of'):
        f.append('FX8 presence head label')
    if FX.vkey_name('r30') < (30, '') or FX.vkey_name('r28d') >= (30, ''):
        f.append('FX8 version order')
    return f


def fx9(base):
    f = []
    S7 = load(base, 'forensics/s7_replay.py', 's7')
    rep = {'result': 'FAIL', 'fail_reasons': ['content pins: decoder input changed'], 'rederive': {'mode': 'partial'}}
    lab = S7.label(rep, 'x', set(), [])
    if not lab.startswith('FAIL: content pins') or 'no archive copy' in lab:
        f.append(f'FX9 FAIL label {lab[:80]}')
    lab = S7.label({'result': 'PASS', 'rederive': {'mode': 'partial', 'rederived': 0}}, 'x', set(), ['tier B store'])
    if not lab.startswith('PARTIAL (no tier B store') or 'archive' in lab:
        f.append(f'FX9 PARTIAL label {lab[:80]}')
    return f


def fx10(base):
    f = []
    FS = load(base, 'src/forensics_section.py', 'fs')
    if FS.page_round('/x/artifacts/src/frozen/r29') != 29 or FS.page_round(None) < 30 or FS.page_round('/x/frozen/r30/') != 30:
        f.append('FX10 page_round')
    facts = {'ledger:r25:sha': 1, 'ledger:r25:sealed': 1, 'ledger:r28d:sha': 1, 'ledger:r28:sha': 1, 'ledger:r30:sha': 1,
             'ledger:r31:sealed': 1}   # a version without a manifest sha is no row
    rows = FS.growth_rows(facts, lambda t: f'<i>{t}</i>', lambda k: f'[{k}]')
    if rows.count('<tr>') != 4 or 'planned' in rows or rows.index('r28d') < rows.index('r28<') or rows.index('r30') < rows.index('r28d'):
        f.append(f'FX10 growth rows {rows[:160]}')
    return f


def fx11(base):
    f = []
    sys.modules.pop('v4', None)
    try:
        V5 = load(base, 'forensics/v5.py', 'v5')
    except Exception as e:                                           # noqa: BLE001
        return [f'FX11 v5 does not load: {type(e).__name__}: {e}']
    if 'derived/classes.json' in V5.CLASS_FILES or 'derived/classes.json' not in V5.NEW:
        f.append('FX11 classes.json still a pinned class file')
    if 'derived/presence.json' not in V5.CLASS_FILES:
        f.append('FX11 presence.json is not a class file')
    inh = V5.inherit_list(ROOT)
    if any(k in inh for k in V5.NEW) or 'derived/presence.json' in inh or 'derived/txs.jsonl.gz' not in inh:
        f.append('FX11 inherit list')
    pr = {'revs': [{'rev': 'HEAD', 'commit': 'ef' * 20}]}
    if not V5.presence_head_label(pr, 'ef' * 20).startswith('round head') or not V5.presence_head_label(pr, '00').startswith('as of'):
        f.append('FX11 presence head label')
    for t in ('harness/forensics/classes_r30.py', 'harness/forensics/claim_grant.py', 'harness/forensics/dc0_genesis.py',
              'harness/forensics/dc2_den.py', 'harness/forensics/b111_premine.py'):
        if t not in V5.TOOLS:
            f.append(f'FX11 {t} is not a pinned replay tool')
    # r30 v5b: the genesis records v5 derives from (and the generated B111 key-count fit) are pinned inputs
    for rel in ('harness/runtime/r30_genesis_census.json', 'harness/runtime/r30_genesis_tip.json',
                'harness/runtime/r30_genesis_canon_parity.json', 'harness/runtime/r30_genesis_b111_keys.json'):
        if rel not in V5.RECORDS.values():
            f.append(f'FX11 {rel} is not a pinned v5 input')
    return f


def fx12(base):
    """S7 s0 --check: a committed record that differs from its re-derivation is DIFFERS; no checkpoint = SKIPPED"""
    f = []
    S0 = load(base, 'forensics/s0_checkpoint.py', 's0')
    t = Path(tempfile.mkdtemp(prefix='fx30s0_'))
    try:
        for name, rel in S0.S0_RECORDS.items():
            (t / rel).parent.mkdir(parents=True, exist_ok=True)
            (t / rel).write_text(json.dumps({'v': 1}))
        B = {k: (lambda ck: {'v': 1}) for k in S0.S0_RECORDS}
        r = S0.check(t, t / 'no-checkpoint.log', builders=B)
        if r != {'claim_grant': r['claim_grant'], 'dc0_genesis': r['dc0_genesis'], 'dc2_den': 'equal', 'b111_premine': 'equal'} \
                or not r['claim_grant'].startswith('SKIPPED') or not r['dc0_genesis'].startswith('SKIPPED'):
            f.append(f'FX12 check without a checkpoint {r}')
        (t / S0.S0_RECORDS['dc2_den']).write_text(json.dumps({'v': 2}))
        if S0.check(t, t / 'no-checkpoint.log', builders=B)['dc2_den'] != 'DIFFERS':
            f.append('FX12 a changed record is not DIFFERS')
    finally:
        shutil.rmtree(t, ignore_errors=True)
    return f


def committed():
    f = []
    led = json.loads((ROOT / 'forensics/ledger.json').read_text())
    if not any(v['version'] == 'r28d' and v.get('sealed') for v in led['versions']):
        f.append('committed: r28d is not sealed')
    J = lambda r: json.loads((ROOT / r).read_text())
    cg, dg, dd, bp = (J('harness/runtime/r30_claim_grant.json'), J('harness/runtime/r30_dc0_genesis.json'),
                      J('harness/runtime/r30_dc2_den.json'), J('harness/runtime/r30_b111_premine.json'))
    pin = '548f31c351e7a4525ded86c2b19f6ef348b50bcaf4a5c2fde497ec55d52aec6a'
    if (cg['registrations_below_144000'], cg['value_atomic'], cg['identity_holds'], cg['input']['sha256']) != (1358698, 271739600, True, pin):
        f.append('committed: claim grant record')
    c = dg['census']
    if (c['distinct_txids'], c['by_class'], c['type_evidence'].get('decoder'), c['by_hf_era_of_repeat'], dg['input']['sha256']) != \
            (9838, {'DC0': 9838}, 690, {'HF1': 3655, 'MAJOR_HF2': 6183}, pin) or c['by_times_listed'] != {'\u22652': 9838} \
            or dg['figure_listed_twice']['bound_type'] != 'lower-bound':
        f.append('committed: dc0 genesis record')
    if (dd['sum_of_segments'], dd['den'], dd['overlap_txids_counted_twice'], dd['segments_tile'], dd['value']) != (2158938, 2158937, 1, True, 'unbounded'):
        f.append('committed: dc2 den record')
    if not bp['status'].startswith('HYPOTHESIS') or bp['proven']['residual_at_7498540_with_premine'] != 0 or \
            bp['proven']['residual_at_7498540_without_premine'] != 1:
        f.append('committed: b111 premine record')
    return f


def fx13(base):
    """FX13 audit2 D2-27 for v5 (r30 v5 registration): a v5 fq.json differs from the sealed base ONLY by the
    classes_r30 FQ1 additions (one appended holders-census anchor, the DC0-genesis count, the computed two-bodies
    answer and status, schema_r30); any other change still breaks the rest-equality; the DC0 count must equal the
    audit's own recount and exactly one anchor may be added; a pre-v5 fq.json is compared as before."""
    f = []
    A2 = load(base, 'forensics/audit2.py', 'a2v5fq')
    b97 = 'harness/runtime/r29_b97_holders.json census.counts (audit D2-11)'
    bq = {'FQ1': {'anchors': ['a', 'b'], 'answer': {'x': 1, 'two_bodies_under_one_txid': 'pending: one body'}, 'status': 'answered (partial)'},
          'FQ3': {'k': 2}, 'FQ2': {'criteria': {}}}
    v5q = json.loads(json.dumps(bq))
    v5q['FQ1'] = {'anchors': ['a', 'b', b97], 'answer': {'x': 1, 'two_bodies_under_one_txid': 'lower bound 0: of 67',
                                                       'dc0_genesis_listed_twice': 9838}, 'status': 'answered: two bodies'}
    v5q['schema_r30'] = 'r30 classes v1'
    base_rest = {k: v for k, v in bq.items() if k != 'FQ2'}
    rest, c = A2.fq_rest_v5(v5q, bq)
    if rest != base_rest or c is None:
        f.append(f'FX13 v5 additions not taken out: {rest} vs {base_rest}')
    own = {'dc0_genesis': {'own_distinct': 9840, 'own_in_table': 2}}
    if not A2.v5_fq_ok(c, own):
        f.append(f'FX13 v5 changes refused: {c}')
    bad = json.loads(json.dumps(v5q)); bad['FQ1']['answer']['x'] = 2
    if A2.fq_rest_v5(bad, bq)[0] == base_rest:
        f.append('FX13 another FQ1 change absorbed')
    bad = json.loads(json.dumps(v5q)); bad['FQ3'] = {'k': 3}
    if A2.fq_rest_v5(bad, bq)[0] == base_rest:
        f.append('FX13 a change outside FQ1 absorbed')
    two = json.loads(json.dumps(v5q)); two['FQ1']['anchors'].append('harness/runtime/other.json')
    if A2.v5_fq_ok(A2.fq_rest_v5(two, bq)[1], own):
        f.append('FX13 two added anchors accepted')
    if A2.v5_fq_ok(c, {'dc0_genesis': {'own_distinct': 9841, 'own_in_table': 2}}):
        f.append('FX13 DC0 count != own recount accepted')
    if A2.v5_fq_ok(c, {'dc0_genesis': {'unresolved': 'checkpoint not on this machine'}}):
        f.append('FX13 unresolved DC0 recount accepted')
    if not A2.fq_rest_equal(v5q, bq, {}, {})[0]:
        f.append('FX13 a v5 fq.json with only the additions is not rest-equal')
    f2 = json.loads(json.dumps(v5q)); f2['FQ2'] = {'criteria': {'S-RT': {'result': 'changed'}}}
    if A2.fq_rest_equal(f2, bq, {'criteria': {}}, {'criteria': {}})[0]:
        f.append('FX13 a v5 FQ2 that differs from the base is rest-equal')
    pre = json.loads(json.dumps(bq)); pre['FQ1']['status'] = 'changed'
    r2, c2 = A2.fq_rest_v5(pre, bq)
    if c2 is not None or r2 == base_rest or not A2.v5_fq_ok(None, own):
        f.append('FX13 a pre-v5 fq.json is not compared as before')
    return f


def fx14(base):
    """FX14 facts.record_paths_for (B218, r30 v5 registration): a v5 dataset carries no replay_wall1_ok fact (its page
    renders ch:D2-04), so a v5 PASS report without store.wall1_blocks.check_i_ok is not a problem; every other record
    path is still required; pre-r30 datasets keep the legacy figure."""
    f = []
    FM = load(base, 'forensics/facts.py', 'facts14')
    p30, p28 = FM.record_paths_for('r30'), FM.record_paths_for('r28d')
    if 'replay_wall1_ok' in p30 or 'replay_wall1_ok' not in p28 or set(p30) != set(p28) - {'replay_wall1_ok'}:
        f.append(f'FX14 record paths r30 {sorted(p30)} r28d {sorted(p28)}')
    rep = {'result': 'PASS', 'store': {'tx_bodies_present': 1}, 'rederive': {'equal': 1, 'expected': 1}}
    if FM.unrecorded_paths(rep, p30, {}):
        f.append('FX14 a v5 PASS report without check_i_ok is flagged')
    rep2 = {'result': 'PASS', 'store': {}, 'rederive': {'equal': 1, 'expected': 1}}
    if [k for k, _ in FM.unrecorded_paths(rep2, p30, {})] != ['replay_bodies']:
        f.append('FX14 a missing non-legacy record path is not flagged for v5')
    return f


def kats(base):
    f = []
    for fn in (fx1, fx2, fx3, fx4, fx5, fx6, fx7, fx8, fx9, fx10, fx11, fx12, fx13, fx14):
        try:
            f += fn(base)
        except Exception as e:                                       # noqa: BLE001
            f.append(f'{fn.__name__} crashed: {type(e).__name__}: {e}')
    return f


MUTATIONS = [   # (file under the copied base: forensics/ or src/, old, new)
    ('forensics/claim_grant.py', "        if r['hi'] < below:", "        if r['hi'] <= below:"),
    ('forensics/claim_grant.py', "    return sum(len(r.get('dup_txids') or []) for r in batches if r['hi'] < below)", "    return sum(len(r.get('dup_txids') or []) for r in batches)"),
    ('forensics/dc0_genesis.py', "    return {'distinct_txids': len(rep), ", "    return {'distinct_txids': sum(rep.values()), "),
    ('forensics/dc0_genesis.py', "    by_class = collections.Counter('DC1' if t in table else 'DC0' for t in rep)", "    by_class = collections.Counter('DC0' for t in rep)"),
    ('forensics/dc0_genesis.py', "        if lo < h <= hi:", "        if False:"),
    ('forensics/dc2_den.py', "PROOF_TYPES = ('NORMAL', 'SC', 'BURN') ", "PROOF_TYPES = ('NORMAL', 'SC', 'BURN', 'REGISTRATION') "),
    ('forensics/dc2_den.py', "    over = sorted(r['txid'] for r in rows if any(not window[0] <= h <= window[1] for h in listings.get(r['txid'], ())))", "    over = []"),
    ('forensics/b111_premine.py', "def residual(keys, registrations, premine=PREMINE_KEYS):\n    \"\"\"keys not attributed once the premine term is counted (0 = the identity holds). Pure.\"\"\"\n    return keys - registrations - premine", "def residual(keys, registrations, premine=PREMINE_KEYS):\n    \"\"\"keys not attributed once the premine term is counted (0 = the identity holds). Pure.\"\"\"\n    return keys - registrations"),
    ('forensics/classes_r30.py', "    f['value'] = val\n", "    f['value'] = 'pending: one body was fetched per TXID; a block tx list carries only the TXID'\n"),
    ('forensics/classes_r30.py', "    den = len(multi_block_txids(inclusions))", "    den = len(inclusions.get('rows') or [])"),
    ('forensics/classes_r30.py', "    f['coverage'] = {'num': 0, 'den': dc2den['den'],", "    f['coverage'] = {'num': 0, 'den': 'pending',"),
    ('forensics/classes_r30.py', "        if x['bound_type'] != 'exact':\n            x['moves_when']", "        if x['bound_type'] == 'unbounded':\n            x['moves_when']"),
    ('forensics/classes_r30.py', "        + (f\"S-RT ({srt['result']}) is a precondition only", "        + (f\"({srt['result']}) is a precondition only"),
    ('forensics/classes_r30.py', "                        'exact' if ex else 'lower-bound', unit='atomic',", "                        'exact', unit='atomic',"),
    ('forensics/bounds.py', "        if not (isinstance(c.get('den'), int) and not isinstance(c.get('den'), bool) and c['den'] > 0):", "        if False:"),
    ('forensics/bounds.py', "        if f.get('bound_type') != 'exact' and not str(f.get('moves_when', '')).strip():", "        if False:"),
    ('forensics/bounds.py', "        if str(tb.get('value', '')).startswith(TWO_BODIES_LITERAL):", "        if False:"),
    ('forensics/bounds.py', "            if (tb.get('coverage') or {}).get('den') != multi:", "            if False:"),
    ('forensics/bounds.py', "    if _vkey(cl.get('dataset') or (ds.name if ds is not None else '')) < R30_FROM:", "    if False:"),
    ('forensics/audit2.py', "    out.append(ch('D2-29', f\"classes.json dc1-two-bodies is computed: lower bound {t['claimed_value']}, coverage {t['claimed_num']}/{t['claimed_den']} multi-block TXIDs (B202)\",\n                  'own duplicate-body census (D2-11) and own multi-block count vs the figure', t['holds'],", "    out.append(ch('D2-29', f\"classes.json dc1-two-bodies is computed: lower bound {t['claimed_value']}, coverage {t['claimed_num']}/{t['claimed_den']} multi-block TXIDs (B202)\",\n                  'own duplicate-body census (D2-11) and own multi-block count vs the figure', True,"),
    ('forensics/audit2.py', "                  ['V-DC2'], unresolved=not x['census_read']))", "                  ['V-DC2']))"),
    ('forensics/audit2.py', "    t = V['two_bodies']\n    return (f\"lower bound", "    t = V['two_bodies']\n    return 'pending' or (f\"lower bound"),
    ('forensics/audit_check.py', "REQUIRED_BY_VERSION['r30'] = REQUIRED_BY_VERSION['r28d'] + ('D2-29', 'D2-30', 'D2-31', 'D2-32', 'D2-33', 'D2-34')", "REQUIRED_BY_VERSION['r30'] = REQUIRED_BY_VERSION['r28d']"),
    ('forensics/facts.py', "        if o is None and fid not in legacy:", "        if False:"),
    ('forensics/facts.py', "    if not rep or rep.get('result') != 'PASS':\n        return []\n    out = []", "    out = []"),
    ('forensics/facts.py', "    return f'round head {c[:12]}' if build_commit and c == build_commit else f'as of {c[:12]}'\n\n\ndef window_rows", "    return f'round head {c[:12]}'\n\n\ndef window_rows"),
    ('forensics/s7_replay.py', "    if rep.get('result') != 'PASS':\n        why", "    if False:\n        why"),
    ('src/forensics_section.py', "    return int(m.group(1)) if m else LIVE_ROUND", "    return LIVE_ROUND"),
    ('src/forensics_section.py', "    vs = sorted({k.split(':')[1] for k in f if k.startswith('ledger:') and k.endswith(':sha')},", "    vs = sorted({k.split(':')[1] for k in f if k.startswith('ledger:')},"),
    ('forensics/s0_checkpoint.py', "        out[name] = 'equal' if old == new else 'DIFFERS'", "        out[name] = 'equal'"),
    ('forensics/s0_checkpoint.py', "            out[name] = 'SKIPPED: the B182 checkpoint is not on this machine'", "            out[name] = 'equal'"),
    # R30 D1-D3 (the adversarial verifier's uncaught mutations and the new rules)
    ('forensics/b111_premine.py', "    return 'HYPOTHESIS (arithmetic consistent)' if ok", "    return 'CONFIRMED' if ok"),
    ('forensics/dc2_den.py', "PROOF_TYPES and window[0] <= r['carrier_height'] <= window[1]]", "PROOF_TYPES and window[0] < r['carrier_height'] <= window[1]]"),
    ('forensics/dc0_genesis.py', "    below_144k = sum(1 for t in rep if first_rep[t][1] < 144000)", "    below_144k = sum(1 for t in rep if first_rep[t][0] < 144000)"),
    ('forensics/dc0_genesis.py', "Counter(f'\\u2265{n + 1}' for n in rep.values())", "Counter(str(n + 1) for n in rep.values())"),
    ('forensics/dc0_genesis.py', "LISTED_BOUND = 'lower-bound'", "LISTED_BOUND = 'exact'"),
    ('forensics/classes_r30.py', "             'lower-bound', note=lt['caveat']),", "             'exact', note=lt['caveat']),"),
    ('forensics/bounds.py', "        if f.get('bound_type') == 'exact' and LOWER_BOUND_RX.search(", "        if False and LOWER_BOUND_RX.search("),
    ('forensics/classes_r30.py', "             'harness/runtime/r30_claim_grant.json census.batches (checkpoint batches hi < 144,000)',", "             f\"blockchain/supply.go:{grant['supply_go']['lines'].get('add')} ({grant['supply_go']['accounts']:,} accounts)\","),
    ('forensics/classes_r30.py', "        _fig('dc3-claim-grant', 'DC3', (f\"distinct registrations below 144,000 x 200 = {grant['value_atomic']:,} \"", "        _fig('dc3-claim-grant', 'DC3', (f\"claim grant: registrations below 144,000 x 200 = {grant['value_atomic']:,} \""),
    ('forensics/classes_r30.py', "             'pending: needs a replay of 0..143,999 (S7)',", "             grant['value_atomic'],"),
    ('forensics/v5.py', "CLASS_FILES = {k: x for k, x in v4.CLASS_FILES.items() if k != 'derived/classes.json'}", "CLASS_FILES = dict(v4.CLASS_FILES)"),
    ('forensics/v5.py', "           'genesis_b111_keys': 'harness/runtime/r30_genesis_b111_keys.json'}", "           }"),
    ('forensics/v5.py', "    return sorted(k for k in bm if k.startswith(('raw/', 'derived/')) and k not in NEW and k != PRESENCE)", "    return sorted(k for k in bm if k.startswith(('raw/', 'derived/')) and k not in NEW)"),
    # r30 v5 registration: D2-27 accepts exactly the classes_r30 FQ1 additions (FX13)
    ('forensics/audit2.py', "            and own is not None and c['dc0_genesis_listed_twice'] == own)", "            and own is not None)"),
    ('forensics/audit2.py', "    return (c['anchors_prefix'] and len(c['anchors_extra']) == 1 and", "    return (c['anchors_prefix'] and len(c['anchors_extra']) >= 1 and"),
    ('forensics/audit2.py', "    rest['FQ1'] = dict(fq1, answer=ans, anchors=b1.get('anchors'), status=b1.get('status'))", "    rest['FQ1'] = dict(b1)"),
    ('forensics/audit2.py', "    fq2_equal = (fq.get('FQ2') == base.get('FQ2')) if v5c is not None else (q == qb)", "    fq2_equal = True"),
    ('forensics/facts.py', "    return {k: v for k, v in RECORD_PATHS.items() if k not in LEGACY_UNRECORDED}", "    return dict(RECORD_PATHS)"),
    ('forensics/facts.py', "    return {k: v for k, v in RECORD_PATHS.items() if k not in LEGACY_UNRECORDED}", "    return {}"),
    ('forensics/audit2.py', "    rest = {k: v for k, v in fq.items() if k not in ('FQ2', 'schema_r30')}\n    if 'schema_r30' not in fq:", "    rest = {k: v for k, v in base.items() if k not in ('FQ2', 'schema_r30')}\n    if 'schema_r30' not in fq:"),
]


def main():
    base = Path(tempfile.mkdtemp(prefix='fx30base_'))
    try:
        shutil.copytree(HARNESS / 'forensics', base / 'forensics', ignore=shutil.ignore_patterns('__pycache__'))
        (base / 'src').mkdir()
        shutil.copy2(ROOT / 'artifacts' / 'src' / 'forensics_section.py', base / 'src' / 'forensics_section.py')
        f = kats(base) + committed()
    finally:
        shutil.rmtree(base, ignore_errors=True)
    print('FX1-FX12 + committed:', 'PASS' if not f else 'FAIL\n  ' + '\n  '.join(f))
    if f:
        return 3
    rc, caught, n = 0, 0, 0
    for i, (fn, old, new) in enumerate(MUTATIONS, 1):
        n += 1
        tmp = Path(tempfile.mkdtemp(prefix='fx30mut_'))
        try:
            shutil.copytree(HARNESS / 'forensics', tmp / 'forensics', ignore=shutil.ignore_patterns('__pycache__'))
            (tmp / 'src').mkdir()
            shutil.copy2(ROOT / 'artifacts' / 'src' / 'forensics_section.py', tmp / 'src' / 'forensics_section.py')
            src = (tmp / fn).read_text()
            if src.count(old) != 1:
                print(f'mutation {i} INVALID: text found {src.count(old)} times in {fn}'); rc = 4; continue
            (tmp / fn).write_text(src.replace(old, new, 1))
            mf = kats(tmp)
            if mf and not all('crashed' in x for x in mf):
                caught += 1
                print(f'mutation {i} CAUGHT ({fn}): {mf[0][:110]}')
            else:
                print(f'mutation {i} NOT CAUGHT ({fn}): {old.strip()[:80]}' + (f' [only crashes: {mf[0][:80]}]' if mf else '')); rc = 4
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print(f'mutations caught {caught}/{n}')
    return rc


if __name__ == '__main__':
    sys.exit(main())
