#!/usr/bin/env python3
"""R30 genesis..tip derivations from the genesis_r30.py census stage (rft §7 B211, B212, B209, B182, B208, B111;
§8 "R30 audit plan" S2-S5). Offline: reads the stage's checkpoint (pinned by SHA-256) and its regkeys.bin sidecar;
every constant comes from the tree's source or a held record, never a literal.

  emission (B211)   per segment: topo 0 is PREMINE with Value == config.PREMINE; every other block's Miner_TX is
                    COINBASE with Value 0; per batch Σ CalcBlockReward(h) (Go, checked == Python at fetch) equals
                    CalcSupply(hi+1) − CalcSupply(lo) (pure Python from the source). No grant term: the claim credit is in
                    both CalcSupply terms and cancels. A segment HOLDS when every batch overlapping it holds and its
                    batch-aligned cover is contiguous; the cover is stated (batches are 100 blocks from 0).
  public values     per segment cover: fees / burns / value by type (each txid once) and per listing; the HF3 window
    (B212)          (audit2.WINDOW) re-derived per BLOCK from the batch `pv` maps; must equal v4's fees.json v2 figures.
  version (B212)    first / last topo per Major_Version and the per-block mismatches against config.go's MAJOR_HF2/HF3
                    (HF1_HEIGHT / HF2_HEIGHT are not versions).
  canonicality      points / scalars checked, failed checks (BD5: scalars >= Order) over every proof-carrying body.
  registrations     leading-zero census, registrations of the genesis key, distinct key digests (regkeys.bin sorted).
  dc0 typed (B209)  multi-listed txids (exact dedup) typed by their verified bodies, by HF era, below / in / above the
                    window; the R29 view (dc0_genesis.census) recomputed for 0..S2 to compare with the S0 record.
  integrity (B182)  exact dedup vs R29's window, sessions and session wall, errors, unreferenced ids, joins.

  python3 -I harness/forensics/genesis_derive_r30.py --stage DIR [--out-dir harness/runtime] [--extra STAGE ...]
"""
import argparse, collections, hashlib, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import b182_deep_r29 as R  # noqa: E402
import genesis_r30 as G  # noqa: E402
import dc0_genesis as DC0  # noqa: E402
import s0_checkpoint as S0  # noqa: E402

PREFIX = 'r30_genesis_'


def fsha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()


def load(stage):
    recs, ign = R.unseal(open(Path(stage) / 'checkpoint.log').readlines())
    return recs, ign


def batches(recs):
    return [r for r in recs if r.get('kind') == 'batch']


def segments(root, to):
    """S2 = the R29 B182 deep range (its record), S3 = above it to the census top `to`."""
    r29 = json.loads((Path(root) / 'harness/runtime/r29_b182_deep_census.json').read_text())
    (lo, hi), = r29['ranges']
    return [{'id': 'S2', 'lo': lo, 'hi': hi, 'anchor': 'harness/runtime/r29_b182_deep_census.json ranges'},
            {'id': 'S3', 'lo': hi + 1, 'hi': to, 'anchor': 'genesis census session record `to`'}]


def cover(bs, lo, hi):
    """batches overlapping [lo, hi] (pure)."""
    return [b for b in bs if b['lo'] <= hi and b['hi'] >= lo]


def contiguous(bs):
    return all(a['hi'] + 1 == b['lo'] for a, b in zip(bs, bs[1:])) and all(b['blocks'] == b['hi'] - b['lo'] + 1 for b in bs)


# ------------------------------------------------------------------------------------------- B211 emission
def verdict(checks):
    """FAILS when any content check fails; else HOLDS when the cover is complete, else PARTIAL (pure)."""
    if not all(v for k, v in checks.items() if k != 'cover_contiguous'):
        return 'FAILS'
    return 'HOLDS' if checks['cover_contiguous'] else 'PARTIAL'


def emission(bs, segs, calc, hf):
    """{segment: verdict...} (pure). Batch identity: reward_sum == calc(hi+1) - calc(lo)."""
    bad = [(b['lo'], b['hi']) for b in bs if b.get('reward_sum') != calc(b['hi'] + 1) - calc(b['lo'])]
    out = []
    for s in segs:
        c = cover(bs, s['lo'], s['hi'])
        if not c:
            out.append({**s, 'verdict': 'pending', 'why': 'no verified batch'})
            continue
        clo, chi = c[0]['lo'], c[-1]['hi']
        blocks = sum(b['blocks'] for b in c)
        mt = collections.Counter()
        for b in c:
            mt.update(b.get('miner_types') or {})
        has0 = clo == 0
        pre = next((b.get('premine_value') for b in c if 'premine_value' in b), None)
        rsum = sum(b['reward_sum'] for b in c)
        formula = calc(chi + 1) - calc(clo)
        checks = {
            'cover_contiguous': contiguous(c) and clo <= s['lo'] and chi >= s['hi'],
            'premine_at_topo0': (not has0) or (pre == hf['PREMINE'] and mt.get('PREMINE') == 1),
            'coinbase_every_other_block': mt.get('COINBASE', 0) == blocks - (1 if has0 else 0)
                                          and sum(mt.values()) == blocks,
            'coinbase_value_zero': sum(b.get('miner_value_nonzero', 0) for b in c) == 0,
            'batch_identities': not [x for x in bad if x[0] <= chi and x[1] >= clo],
            'segment_identity': rsum == formula,
        }
        out.append({**s, 'cover': [clo, chi], 'cover_batches': len(c), 'blocks': blocks, 'miner_types': dict(sorted(mt.items())),
                    'premine_value': pre, 'reward_sum': rsum, 'calc_supply_diff': formula, 'grant_term': 'cancels (in both CalcSupply terms)',
                    'checks': checks, 'verdict': verdict(checks)})
    return out, bad


# ------------------------------------------------------------------------------------------- B212 public values
def public_values(bs, segs, window, want):
    out = []
    for s in segs:
        c = cover(bs, s['lo'], s['hi'])
        agg = {k: collections.Counter() for k in ('fee', 'burn', 'value', 'payloads')}
        for b in c:
            for k in agg:
                agg[k].update(b.get(k) or {})
        out.append({**s, 'cover': [c[0]['lo'], c[-1]['hi']] if c else None,
                    **{k: dict(sorted(v.items())) for k, v in agg.items()},
                    'fee_listing': sum(b.get('fee_listing', 0) for b in c), 'burn_listing': sum(b.get('burn_listing', 0) for b in c),
                    'listings': sum(b.get('listings', 0) for b in c)})
    wf = wb = 0
    wc = cover(bs, *window)
    for b in wc:
        for t, (f, u) in (b.get('pv') or {}).items():
            if window[0] <= int(t) <= window[1]:
                wf, wb = wf + f, wb + u
    covered = bool(wc) and contiguous(wc) and wc[0]['lo'] <= window[0] and wc[-1]['hi'] >= window[1]
    w = {'window': list(window), 'fee_sum': wf, 'burn_sum': wb, 'covered': covered, 'want': want,
         'verdict': ('EQUAL' if covered and wf == want['fee'] and wb == want['burn'] else
                     'pending' if not covered else 'DIFFERS')}
    return out, w


# ------------------------------------------------------------------------------------------- B212 versions
def versions(bs, hf):
    ver, vf, vl = collections.Counter(), {}, {}
    mism, mt = 0, []
    for b in bs:
        ver.update(b.get('ver') or {})
        for m, t in (b.get('ver_first') or {}).items():
            vf[m] = min(vf.get(m, t), t)
        for m, t in (b.get('ver_last') or {}).items():
            vl[m] = max(vl.get(m, t), t)
        mism += b.get('ver_mismatch', 0)
        mt += b.get('ver_mismatch_topos') or []
    exp = {'1': [0, hf['MAJOR_HF2_HEIGHT'] - 1], '2': [hf['MAJOR_HF2_HEIGHT'], hf['MAJOR_HF3_HEIGHT'] - 1],
           '3': [hf['MAJOR_HF3_HEIGHT'], None]}
    rows = {m: {'first': vf.get(m), 'last': vl.get(m), 'expected_from': exp[m][0], 'expected_to': exp[m][1],
                'first_equal': vf.get(m) == exp[m][0] if m in vf else None} for m in exp}
    return {'by_major_minor': dict(sorted(ver.items())), 'majors': rows, 'mismatches': mism, 'mismatch_topos_first': mt[:16],
            'not_versions': {'HF1_HEIGHT': hf['HF1_HEIGHT'], 'HF2_HEIGHT': hf['HF2_HEIGHT']},
            'verdict': 'HOLDS' if mism == 0 and all(r['first_equal'] in (True, None) for r in rows.values()) else 'FAILS'}


# ------------------------------------------------------------------------------------------- registrations / keys
def regkeys(stage, bs, upto=None):
    """distinct registration-key digests over batches with hi <= upto (sidecar prefix; pure apart from the file)."""
    n = sum(b.get('n_regkeys', 0) for b in bs if upto is None or b['hi'] <= upto)
    raw = (Path(stage) / 'regkeys.bin').read_bytes()[:32 * n]
    keys = [raw[i:i + 32] for i in range(0, len(raw), 32)]
    d = len(set(keys))
    return {'registrations': n, 'distinct_key_digests': d, 'repeated_keys': n - d,
            'digest_set_sha256': hashlib.sha256(b''.join(sorted(set(keys)))).hexdigest()}


# ------------------------------------------------------------------------------------------- B209 dc0 typed
def dc0_typed(bs, segs, window, table, hf_eras):
    typed, first = {}, {}
    for b in bs:
        for t, ty in (b.get('dup_typed') or {}).items():
            typed.setdefault(t, ty)
            first.setdefault(t, (b['lo'], b['hi']))
    rep = collections.Counter()
    for b in bs:
        for t in set(b.get('dup_txids') or []) | set(b.get('dup_in_batch') or []):
            rep[t] += 1
    def where(lohi):
        lo, hi = lohi
        return 'below-window' if hi < window[0] else 'window' if lo >= window[0] and hi <= window[1] else \
            'above-window' if lo > window[1] else 'straddles-window'
    by = collections.Counter((typed.get(t, R.UNSERVED), DC0.era(*first[t], hf_eras), where(first[t])) for t in rep)
    return {'distinct_txids': len(rep), 'repeat_listings': sum(rep.values()),
            'by_class': dict(sorted(collections.Counter('DC1' if t in table else 'DC0' for t in rep).items())),
            'by_type': dict(sorted(collections.Counter(typed.get(t, R.UNSERVED) for t in rep).items())),
            'by_type_era_place': {f'{a}|{b}|{c}': n for (a, b, c), n in sorted(by.items())},
            'txid_list_sha256': hashlib.sha256('\n'.join(sorted(rep)).encode()).hexdigest()}


def r29_view(bs, hi):
    """the S0 census over 0..hi from this census (R29 semantics: dup_txids = every repeat listing)."""
    v = []
    for b in bs:
        if b['hi'] <= hi:
            v.append({**b, 'dup_txids': sorted(set(b.get('dup_txids') or []) | set(b.get('dup_in_batch') or []))})
    return v


def integrity(recs):
    """session figures with their real scope (pure). Only a session that ended normally writes session_end (a SIGTERM
    skips the fetcher's finally), so its wall and error count cover the sessions WITH that record, never all of them;
    r30 verifier: the census said sessions 5 / session_wall_s 13,158.9 while the 5 walls sum to 18,822.9 s."""
    sess = [r for r in recs if r.get('kind') == 'session']
    ends = [r for r in recs if r.get('kind') == 'session_end']
    out = {'sessions': len(sess), 'sessions_with_end_record': len(ends),
           'session_end_wall_s': round(sum(r.get('wall_s', 0) for r in ends), 1),
           'session_end_errors': sum(r.get('errors', 0) for r in ends)}
    open_, cur = [], None                      # a session is ended when a session_end follows it before the next session
    for r in recs:
        if r.get('kind') == 'session':
            if cur is not None:
                open_.append(cur.get('from_topo'))
            cur = r
        elif r.get('kind') == 'session_end':
            cur = None
    if cur is not None:
        open_.append(cur.get('from_topo'))
    if open_:
        out['sessions_without_end_record'] = {
            'n': len(open_), 'from_topos': open_,
            'why': 'stopped without a session_end record: their wall and error count are not in the checkpoint'}
    return out


# ------------------------------------------------------------------------------------------- B111 key count
B111_QCS = 'harness/runtime/r29_b111_qcs1.json'


def b111_keys(stage, straddle, root=ROOT, qcs=B111_QCS):
    """the B111 count fit from records only (r30 verifier: the committed record was typed by hand). Anchor H = the
    lowest balance-tree census height of the QCS1 record; registrations 0..H-1 = the census batches wholly below the
    straddle fetch + the straddle fetch (which must cover the last census batch's start .. H-1 exactly); distinct key
    digests over both sidecars; residual = tree keys - distinct. `block_H_onward_registrations` = the census batch
    holding H minus the straddle's: 0 means the fit is the same whether the tree at H includes block H or not.
    Every other QCS1 height is fitted the same way when the census batch holding it has no registration (exact under
    both conventions), else reported as not exact. A HYPOTHESIS by count: the set identity needs the S4 set diff."""
    Q = json.loads((Path(root) / qcs).read_text())['census']
    recs, _ = load(stage)
    bs = sorted(batches(recs), key=lambda b: b['lo'])
    srec, _ = load(straddle)
    ss = sorted(batches(srec), key=lambda b: b['lo'])
    H = min(int(h) for h in Q)
    slo, shi = ss[0]['lo'], ss[-1]['hi']
    holder = [b for b in bs if b['lo'] <= H <= b['hi']]
    if not ss or not contiguous(ss) or shi != H - 1 or len(holder) != 1 or holder[0]['lo'] != slo:
        raise ValueError(f'straddle {slo}..{shi} does not cover the census batch start .. {H - 1}')
    below = [b for b in bs if b['hi'] < slo]
    if not below or not contiguous(below) or below[0]['lo'] != 0 or below[-1]['hi'] != slo - 1:
        raise ValueError('census batches below the straddle are not contiguous from 0')
    nm, ns = sum(b.get('n_regkeys', 0) for b in below), sum(b.get('n_regkeys', 0) for b in ss)
    raw = (Path(stage) / 'regkeys.bin').read_bytes()
    sraw = (Path(straddle) / 'regkeys.bin').read_bytes()
    if len(sraw) != 32 * ns or len(raw) < 32 * nm:
        raise ValueError('regkeys sidecar shorter than the checkpointed count')
    keys = [raw[i:i + 32] for i in range(0, 32 * nm, 32)] + [sraw[i:i + 32] for i in range(0, 32 * ns, 32)]
    distinct = len(set(keys))
    tree = Q[str(H)]['balance_tree_keys']
    gk = sum(b.get('reg_genesis_key', 0) for b in below + ss)
    others = {}
    for h in sorted((int(x) for x in Q if int(x) != H)):
        hb = [b for b in bs if b['lo'] <= h <= b['hi']]
        if len(hb) != 1 or hb[0].get('n_regkeys', 0):
            others[str(h)] = {'exact': False, 'why': 'the census batch holding this height has registrations (or none holds it)'}
            continue
        n = sum(b.get('n_regkeys', 0) for b in bs if b['hi'] < h)
        d = len({raw[i:i + 32] for i in range(0, 32 * n, 32)})
        others[str(h)] = {'exact': True, 'distinct_registration_key_digests': d,
                          'balance_tree_keys': Q[str(h)]['balance_tree_keys'],
                          'residual': Q[str(h)]['balance_tree_keys'] - d,
                          'registrations_of_the_genesis_premine_key': sum(b.get('reg_genesis_key', 0) for b in bs if b['hi'] < h)}
    return {
        'schema': 'r30 genesis B111 key count v2 (rft §7 B111; generated by genesis_derive_r30.b111_keys)',
        'row': 'B111',
        'evidence_class': 'DERIVED (b182deep2 key digests: sha256 of the 33-byte key, never the key)',
        f'balance_tree_keys_at_{H}': {'record': qcs, 'value': tree},
        f'registrations_0_{slo - 1}': nm,
        f'registrations_{slo}_{shi}': ns,
        f'distinct_registration_key_digests_0_{H - 1}': distinct,
        'repeated_registration_keys': len(keys) - distinct,
        'registrations_of_the_genesis_premine_key': gk,
        'block_H_onward_registrations': {'H': H, 'census_batch': [holder[0]['lo'], holder[0]['hi']],
                                         'value': holder[0].get('n_regkeys', 0) - ns},
        'residual': tree - distinct,
        'other_heights': others,
        'straddle_stage': f'off-repo forensics_raw_r30/genesis/{Path(straddle).name} ({slo:,}..{shi:,}, '
                          f'{shi - slo + 1} blocks, {ns} registrations)',
        'inputs': {'checkpoint_sha256': fsha(Path(stage) / 'checkpoint.log'), 'regkeys_sha256': fsha(Path(stage) / 'regkeys.bin'),
                   'straddle_checkpoint_sha256': fsha(Path(straddle) / 'checkpoint.log'),
                   'straddle_regkeys_sha256': fsha(Path(straddle) / 'regkeys.bin'), qcs: fsha(Path(root) / qcs)},
        'reading': 'balance-tree keys = distinct registration keys + residual; with residual 1 and the genesis premine key '
                   '(transaction_execute.go:73-81) never registered, CONSISTENT with the premine-key hypothesis by count '
                   '(HYPOTHESIS); the set identity (that the one extra key IS the premine key) stays pending the S4 set diff',
    }


def derive(stage, root=ROOT, extra=()):
    recs, ign = load(stage)
    bs = batches(recs)
    reward, calc, hf = G.chain_constants(root)
    sess = [r for r in recs if r.get('kind') == 'session']
    to = max((r['to'] for r in sess), default=None)
    segs = segments(root, to)
    import audit2
    window = tuple(audit2.WINDOW)
    fz = json.loads((Path(root) / 'forensics/r28d/derived/fees.json').read_text())['v2']
    want = {'fee': fz['window_fee_sum'], 'burn': fz['window_burn_sum'], 'anchor': 'forensics/r28d/derived/fees.json v2'}
    T = G.totals2(recs)
    pin = {'checkpoint_sha256': fsha(Path(stage) / 'checkpoint.log'), 'records': len(recs), 'ignored_tail_lines': ign,
           'regkeys_sha256': fsha(Path(stage) / 'regkeys.bin'), 'txids_sha256': fsha(Path(stage) / 'txids.bin'),
           'stage': 'off-repo (forensics_raw_r30/genesis/run)'}
    em, bad = emission(bs, segs, calc, hf)
    import coverage as COV
    tipr = json.loads((Path(root) / 'harness/runtime/r30_genesis_tip.json').read_text())
    tl = COV.tiles(segs[0]['hi'], to, tipr['tip'], audit2.WALLS, audit2.WINDOW)
    tem, _ = emission(bs, [{'id': t, 'lo': lo, 'hi': hi} for t, lo, hi in tl], calc, hf)
    pv, win = public_values(bs, segs, window, want)
    H = S0.config_heights(root)
    hf_eras = [('HF1', H['HF1_HEIGHT'][0]), ('MAJOR_HF2', H['MAJOR_HF2_HEIGHT'][0])]
    table = DC0.hf3_table(root)
    s2 = segs[0]
    complete = bool(bs) and contiguous(bs) and bs[0]['lo'] == 0 and bs[-1]['hi'] == to
    seg_tot = []
    for s in segs:
        c = cover(bs, s['lo'], s['hi'])
        tt = G.totals2(c)
        seg_tot.append({**s, 'cover': [c[0]['lo'], c[-1]['hi']] if c else None, 'blocks': tt['blocks'], 'txs': tt['txs'],
                        'types': tt['types'], 'reg_lz': tt['reg_lz'], 'canon_points': tt['canon_points'],
                        'canon_scalars': tt['canon_scalars'], 'canon_failed': tt['canon_failed'],
                        'reg_genesis_key': tt['reg_genesis_key'], 'unref': tt['unref'], 'dup_txids': tt['dup_txids'],
                        'miniblocks': tt['miniblocks']})
    out = {
        'schema': 'r30 genesis census v1 (rft §7 B208 B182 B211 B212 B209)', 'input': pin,
        'complete': complete, 'range': [bs[0]['lo'], bs[-1]['hi']] if bs else None, 'to': to,
        'segments': seg_tot,
        'totals': {k: T[k] for k in ('blocks', 'txs', 'types', 'reg_lz', 'registrations', 'canon_points', 'canon_scalars',
                                     'canon_failed', 'reg_genesis_key', 'unref', 'dup_txids', 'miniblocks', 'listings',
                                     'ver', 'miner_types', 'miner_value_nonzero')},
        'integrity': {**integrity(recs),
                      'dedup': 'exact (txids.bin sidecar + set; replaces DEDUP=200,000)',
                      'genesis_compare': 'topo 0 == Generate_Genesis_Block bytes and id (check_blocks2 rejects otherwise)',
                      'unreferenced_ids': T['unref'], 'reward_go_eq_python': 'every block (check_blocks2 rejects otherwise)'},
        'emission': em, 'emission_bad_batches': bad[:20], 'tile_emission': tem,
        'public_values': pv, 'window': win,
        'versions': versions(bs, hf),
        'registration_keys': {'all': regkeys(stage, bs)},
        'dc0_typed': dc0_typed(bs, segs, window, table, hf_eras),
        'dc0_r29_view_S2': DC0.census(r29_view(bs, s2['hi']), table, hf_eras),
        'constants': {k: hf[k] for k in ('HF1_HEIGHT', 'HF2_HEIGHT', 'MAJOR_HF2_HEIGHT', 'MAJOR_HF3_HEIGHT', 'PREMINE', 'credit')},
        'rule13': 'counts and hashes only; no address, no key, no txid list (sha256 of the sorted list)',
    }
    return out


CENSUS = 'harness/runtime/r30_genesis_census.json'
TIP = 'harness/runtime/r30_genesis_tip.json'
V5_FILES = ['derived/coverage.json', 'derived/emission_genesis.json', 'derived/public_values_genesis.json',
            'derived/version_census.json', 'derived/dc0_genesis_typed.json', 'derived/genesis_census.json']


def v5_files(root=ROOT, census=CENSUS, tip=TIP):
    """the dataset v5 files projected from the pinned census record (pure apart from reading the records): every
    figure is the record's, the coverage map is coverage.build over the same records. {rel: bytes}"""
    import coverage as COV
    C = json.loads((Path(root) / census).read_text())
    src = {'record': census, 'sha256': fsha(Path(root) / census)}
    d = lambda o: (json.dumps(o, indent=1, sort_keys=True) + '\n').encode()
    return {
        'derived/coverage.json': d(COV.build(census, tip, root)),
        'derived/emission_genesis.json': d({'schema': 'r30 emission genesis v1 (B211)', 'source': src, 'segments': C['emission'],
                                            'tiles': C['tile_emission'], 'bad_batches': C['emission_bad_batches'],
                                            'constants': C['constants'], 'class': 'DC3',
                                            'rule': 'never a supply claim (G31): the identity checks the formula against the chain\'s own block rewards'}),
        'derived/public_values_genesis.json': d({'schema': 'r30 public values genesis v1 (B212)', 'source': src,
                                                 'segments': C['public_values'], 'window': C['window'],
                                                 'canonicality': {s['id']: {k: s[k] for k in ('canon_points', 'canon_scalars', 'canon_failed')} for s in C['segments']},
                                                 'fee_verdict': 'NOT-DECIDABLE (V2-FEES): public fees are counted, not judged'}),
        'derived/version_census.json': d({'schema': 'r30 version census v1 (B212)', 'source': src, **C['versions']}),
        'derived/dc0_genesis_typed.json': d({'schema': 'r30 dc0 genesis typed v1 (B209)', 'source': src, 'typed': C['dc0_typed'],
                                             'r29_view_S2': C['dc0_r29_view_S2'],
                                             'executed_twice': 'pending (needs the S7 replay; pre-HF3 blockchain.go:665,716,995)'}),
        'derived/genesis_census.json': d({'schema': 'r30 genesis census summary v1 (B208, B182)', 'source': src,
                                          'range': C['range'], 'complete': C['complete'], 'segments': C['segments'],
                                          'totals': C['totals'], 'integrity': C['integrity'],
                                          'registration_keys': C['registration_keys']}),
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--stage', required=True)
    ap.add_argument('--out', default='harness/runtime/r30_genesis_census.json')
    ap.add_argument('--b111-straddle', help='the B111 straddle stage: also write --b111-out from records (b111_keys)')
    ap.add_argument('--b111-out', default='harness/runtime/r30_genesis_b111_keys.json')
    a = ap.parse_args(argv)
    if a.b111_straddle:
        k = b111_keys(a.stage, a.b111_straddle)
        Path(ROOT / a.b111_out).write_text(json.dumps(k, indent=1, sort_keys=True) + '\n')
        print(json.dumps({'b111_residual': k['residual'], 'block_H_onward': k['block_H_onward_registrations']['value']}))
    out = derive(a.stage)
    Path(ROOT / a.out).write_text(json.dumps(out, indent=1, sort_keys=True) + '\n')
    print(json.dumps({'complete': out['complete'], 'range': out['range'],
                      'emission': [(e['id'], e['verdict']) for e in out['emission']], 'window': out['window']['verdict'],
                      'versions': out['versions']['verdict']}))


if __name__ == '__main__':
    main()
