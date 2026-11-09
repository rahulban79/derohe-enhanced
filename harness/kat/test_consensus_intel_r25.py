#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the r25 additions to the chain-consensus observatory
(harness/intel/consensus_intel.py, gate G26): the readings of the r25 derod's node-side fixes CO24-C1..C7, the
collective concentration detector CO24-C8 and the B72 caveats (D02 tautology, D13 window).

Every capture is synthetic and in memory (the r24 KAT's honest 600-block generator, harness/kat/
test_consensus_intel_r24.py, extended with what an r25 derod serves: header fees and first_seen_ms, GetConsensusStats
and the reorg monitor's lifetime record). No live node, real log or real runtime file is read or written.
  CR1  an r25 capture: 20 detectors, all NORMAL; fees_total = the header sum; arrival lag read from first_seen_ms;
       alt_blocks_rpc, lifetime reorgs and the peer census are KPIs; header slots readable; no CO24 proposal is raised
       (the binary closed them), while the r24-shaped capture still raises CO24-C1, C2, C3, C5, C6, C7
  CR2  D02: a future-timestamp rejection counted by the node (GetConsensusStats) is OBSERVED (the rule FIRED; the
       accepted-lag half alone can never fire, B72)
  CR2b D02: the rule's rejection line inside the window is OBSERVED, the same line before the window is not
  CR3  D13: a v2-drop line inside the window is OBSERVED; drop lines only before the window (the whole log) are NORMAL
  CR4  D11 from counters: an invalid-PoW block rejection is OBSERVED; stale/final miniblocks and past_missing are not
  CR5  D19: integrator-only participants assembling ~45 % of the blocks are an ANOMALY; the honest capture is NORMAL;
       a coalition at 35 % whose Wilson lower bound stays below 1/3 is NORMAL
  CR6  D20: node alt list == settled non-main log blocks since the newest start -> NORMAL; GetInfo count above the
       node count (r29: the count only grows, so an earlier GetInfo can only be lower; test_consensus_intel_r29 CP1) -> ANOMALY; a settled alt block only in the log -> ANOMALY; an unsettled one (inside STABLE_LIMIT) and
       one before the newest start are left out (NORMAL); a pre-r25 capture -> NO-DATA
  CR7  arrival lag: first_seen_ms wins over the log line when the node serves it
  CR8  the series row carries the collective share, the peer census and the r25 counters
  CR9  read_consensus_stats: a forged reply is reduced (hashes cut to 16 hex, no extra fields); "method not found" -> None
  CR10 G26 on 20 detectors: PASS with D20 NO-DATA (pre-r25 node), FAIL when D19 is missing
  python3 -I harness/kat/test_consensus_intel_r25.py   # exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught
A mutation that crashes the KAT is INVALID, not caught.
"""
import copy, importlib.util, json, random, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
MOD = 'intel/consensus_intel.py'


def load_mod(path, name):
    sp = importlib.util.spec_from_file_location(f'{name}_{random.random()}', path)
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


K24 = load_mod(HARNESS / 'kat/test_consensus_intel_r24.py', 'k24')   # its synth() and G26 temp-root helpers


def r25(cap, alt_blocks=None, alt_count=None, gi_count=None, rejected=None, refused=None, fees=None, fs_shift=None):
    """Turn an r24-shaped synthetic capture into what an r25 derod serves."""
    c = copy.deepcopy(cap)
    H = c['headers']
    for i, h in enumerate(H):
        h['fees'] = (fees or {}).get(i, 0)
    ev_t = {e['blid']: e['t'] for e in c['log']['events'] if e['k'] == 'add'}
    for h in H:
        h['fs'] = ev_t.get(h['hash'], 0) + (fs_shift or 0)
    blocks = alt_blocks or []
    n = len(blocks) if alt_count is None else alt_count
    c['consensus_stats'] = {'version': '3.6.0-153.DEROHE.STARGATE+22102026.r25', 'uptime_seconds': 3600, 'height': H[-1]['height'],
                            'stable_limit': 8, 'miniblock_refused': refused or {}, 'miniblock_refused_total': sum((refused or {}).values()),
                            'block_rejected': rejected or {}, 'block_rejected_total': sum((rejected or {}).values()), 'block_offer_duplicates': 3,
                            'alt': {'count': n, 'unsettled': 2, 'tracked': len(H), 'settled': len(H) - 2, 'tracked_from_height': H[0]['height'],
                                    'settle_depth': 8, 'blocks': blocks},
                            'blocks_seen_tracked': len(H), 'miniblocks_seen_tracked': 9 * len(H)}
    c['getinfo']['alt_blocks_count'] = n if gi_count is None else gi_count
    c['getinfo']['version'] = '3.6.0-153.DEROHE.STARGATE+22102026.r25'
    c['finality']['lifetime'] = {'since': '2026-11-03T18:00:00Z', 'starts': 2, 'observed': 900, 'reorgs': 5, 'replaced_total': 5,
                                 'deepest': 1, 'deepest_heights': 0, 'final_violations': 0, 'local_rewinds': 0}
    c['log']['wevents'] = []
    return c


def analyse(m, cap):
    R, miss = m.load_rules(ROOT)
    if miss:
        raise RuntimeError(f'rules missing {miss}')
    return m.analyze(cap, R, ROOT)


def G(doc):
    return {d['id']: d for d in doc['detectors']}


def side_event(cap, h_index, tag, t_off=900, k='side'):
    """A log line for a block that lost the race at the height of header h_index (never the main block there)."""
    import hashlib
    H = cap['headers']
    blid = hashlib.sha256(f'alt/{tag}'.encode()).hexdigest()
    cap['log']['events'].append({'k': k, 'blid': blid, 'h': H[h_index]['height'], 't': H[h_index]['ts'] + t_off, 'f': 'derod.log', 'l': 9000 + h_index})
    return {'hash': blid[:16], 'height': H[h_index]['height']}


def cr1(m):
    base = K24.synth()
    cap = r25(base, fees={10: 120, 20: 7})
    doc = analyse(m, cap)
    g = G(doc)
    bad = {k: d['grade'] for k, d in g.items() if d['grade'] != 'NORMAL'}
    k = doc['kpis']
    props = [p['id'] for p in doc['proposals']]
    old = [p['id'] for p in analyse(m, base)['proposals']]
    ok = (len(g) == 20 and not bad and k['fees_total'] == 127 and k['fee_blocks'] == 2 and k['fees_unknown_blocks'] == 0
          and k['arrival_source'] == 'rpc first_seen_ms' and k['alt_blocks_rpc'] == 0 and k['finality_lifetime_reorgs'] == 5
          and k['finality_lifetime_starts'] == 2 and k['peers_connected'] == 12 and k['unresolved_miniblocks_header'] == 0
          and k['consensus_stats'] == 'served' and props == [] and old == ['CO24-C1', 'CO24-C2', 'CO24-C3', 'CO24-C5', 'CO24-C6', 'CO24-C7'])
    return ok, f'non-NORMAL {bad}; n {len(g)}; fees {k["fees_total"]}; src {k["arrival_source"]}; props r25 {props} r24 {old}'


def cr2(m):
    cap = r25(K24.synth(), rejected={'future_timestamp': 1, 'past_missing': 4})
    d = G(analyse(m, cap))['D02-ts-future']
    n = G(analyse(m, r25(K24.synth(), rejected={'past_missing': 4})))['D02-ts-future']
    return d['grade'] == 'OBSERVED' and d['value'] == 1 and n['grade'] == 'NORMAL', f"counter {d['grade']} {d['value']}; none {n['grade']}"


def cr2b(m):
    lit = 'Rejecting Block, timestamp is too much into future, make sure that system clock is correct'
    cap = r25(K24.synth())
    H = cap['headers']
    cap['log']['wevents'] = [{'k': 'reject', 'msg': lit, 't': H[300]['ts'], 'f': 'derod.log', 'l': 5}]
    inside = G(analyse(m, cap))['D02-ts-future']
    cap['log']['wevents'] = [{'k': 'reject', 'msg': lit, 't': H[0]['ts'] - 3_600_000, 'f': 'derod.log', 'l': 5}]
    before = G(analyse(m, cap))['D02-ts-future']
    return inside['grade'] == 'OBSERVED' and before['grade'] == 'NORMAL', f"inside {inside['grade']}; before {before['grade']}"


def cr3(m):
    cap = r25(K24.synth())
    H = cap['headers']
    cap['log']['census']['v2_drop'] = 41
    cap['log']['wevents'] = [{'k': 'v2', 't': H[0]['ts'] - 86_400_000, 'f': 'derod.log', 'l': 3}]
    before = G(analyse(m, cap))['D13-v2-remnant']
    cap['log']['wevents'].append({'k': 'v2', 't': H[200]['ts'], 'f': 'derod.log', 'l': 4})
    inside = G(analyse(m, cap))['D13-v2-remnant']
    ok = before['grade'] == 'NORMAL' and '41 in the whole log' in before['value'] and inside['grade'] == 'OBSERVED'
    return ok, f"before {before['grade']} {before['value']}; inside {inside['grade']}"


def cr4(m):
    bad = G(analyse(m, r25(K24.synth(), rejected={'invalid_pow': 1})))['D11-invalid-objects']
    benign = G(analyse(m, r25(K24.synth(), rejected={'past_missing': 9, 'advance_block': 2},
                               refused={'stale_height': 30, 'final_propagated': 2, 'tip_unexpanded': 1})))['D11-invalid-objects']
    ok = bad['grade'] == 'OBSERVED' and bad['value'] == 1 and benign['grade'] == 'NORMAL' and 'counter' in json.dumps(benign['evidence'])
    return ok, f"invalid_pow {bad['grade']} {bad['value']}; benign {benign['grade']} {benign['value']}"


def coalition(share, seed=11):
    cap = K24.synth(seed=seed)
    rng = random.Random(5)
    for h in cap['headers']:
        if rng.random() < share:
            h['miners'][9] = rng.choice(['m-pool0001', 'm-pool0002', 'm-pool0003'])
    return cap


def cr5(m):
    hi = G(analyse(m, r25(coalition(0.45))))['D19-collective-final']
    lo = G(analyse(m, r25(K24.synth())))['D19-collective-final']
    edge = G(analyse(m, r25(coalition(0.35))))['D19-collective-final']
    ci = edge['evidence'][0]['ci95']
    ok = hi['grade'] == 'ANOMALY' and lo['grade'] == 'NORMAL' and edge['grade'] == 'NORMAL' and edge['value'] > 1 / 3 and ci[0] < 1 / 3
    return ok, f"45%: {hi['grade']} {hi['value']}; honest {lo['grade']}; 35%: {edge['grade']} {edge['value']} ci {ci}"


def cr6(m):
    base = K24.synth()
    res = {}
    cap = copy.deepcopy(base)
    a1 = side_event(cap, 100, 'a1')
    a2 = side_event(cap, 400, 'a2', k='add')         # an old main that a reorg replaced (its line said "Chain extended")
    res['equal'] = G(analyse(m, r25(cap, alt_blocks=[a1, a2])))['D20-alt-blocks']['grade']
    res['gi_mismatch'] = G(analyse(m, r25(cap, alt_blocks=[a1, a2], gi_count=5)))['D20-alt-blocks']['grade']   # r29: above the stats count
    res['only_log'] = G(analyse(m, r25(cap, alt_blocks=[a1])))['D20-alt-blocks']['grade']
    cap2 = copy.deepcopy(cap)
    side_event(cap2, len(base['headers']) - 3, 'fresh')  # 2 heights below the tip: not settled yet
    res['unsettled'] = G(analyse(m, r25(cap2, alt_blocks=[a1, a2])))['D20-alt-blocks']['grade']
    cap3 = copy.deepcopy(cap)
    cap3['log']['startups_ms'] = [cap['headers'][200]['ts']]  # restarted at header 200: a1 (header 100) predates it
    res['before_start'] = G(analyse(m, r25(cap3, alt_blocks=[a2])))['D20-alt-blocks']['grade']
    res['pre_r25'] = G(analyse(m, cap))['D20-alt-blocks']['grade']
    want = {'equal': 'NORMAL', 'gi_mismatch': 'ANOMALY', 'only_log': 'ANOMALY', 'unsettled': 'NORMAL', 'before_start': 'NORMAL', 'pre_r25': 'NO-DATA'}
    return res == want, f'{res}'


def cr7(m):
    cap = r25(K24.synth(), fs_shift=-200)
    k1 = analyse(m, cap)['kpis']
    k0 = analyse(m, K24.synth())['kpis']
    ok = k1['arrival_source'] == 'rpc first_seen_ms' and k1['arrival_lag_median_ms'] == k0['arrival_lag_median_ms'] - 200
    return ok, f"rpc median {k1['arrival_lag_median_ms']} log median {k0['arrival_lag_median_ms']} src {k1['arrival_source']}"


def cr8(m):
    doc = analyse(m, r25(K24.synth()))
    row = m.series_row(doc, 'X', 'c.txt')
    need = ('integrator_only_final_share', 'top3_final_share', 'peers_connected', 'peers_below_v3', 'peer_versions', 'alt_blocks_rpc',
            'miniblock_refused_total', 'block_rejected_total', 'finality_lifetime_reorgs', 'fees_total', 'arrival_source')
    miss = [x for x in need if x not in row or row[x] is None]
    return not miss and row['peers_connected'] == 12, f'missing {miss}'


def cr9(m):
    reply = {'version': 'v', 'uptime_seconds': 5, 'height': 9, 'stable_limit': 8, 'secret': 'x',
             'counters': {'miniblock_refused': {'stale_height': 2}, 'miniblock_refused_total': 2, 'block_rejected': {}, 'block_rejected_total': 0,
                          'block_offer_duplicates': 1},
             'alt_blocks': {'count': 1, 'unsettled': 0, 'tracked': 3, 'settled': 3, 'tracked_from_height': 1, 'settle_depth': 8,
                            'blocks': [{'hash': 'ab' * 32, 'height': 2, 'first_seen_ms': 77, 'local': False}]},
             'blocks_seen_tracked': 3, 'miniblocks_seen_tracked': 27}
    old = m.rpc
    try:
        m.rpc = lambda method, params=None, url=None, timeout=60: reply
        got = m.read_consensus_stats('u')

        def nf(method, params=None, url=None, timeout=60):
            raise RuntimeError(f'{method}: method not found')
        m.rpc = nf
        none = m.read_consensus_stats('u')
    finally:
        m.rpc = old
    ok = (got['alt']['blocks'] == [{'hash': 'ab' * 8, 'height': 2}] and 'secret' not in got and got['miniblock_refused'] == {'stale_height': 2}
          and none is None)
    return ok, f'got {json.dumps(got)[:200]}; not-found {none}'


def g26_with(m, cap, mutate=None):
    t = K24.make_root()
    try:
        doc = analyse(m, cap)
        if mutate:
            mutate(doc)
        m.write_outputs(doc, t / 'harness/runtime', '20990101T000000Z', series=False)
        r = subprocess.run([sys.executable, '-I', str(t / 'harness/miners/mine_consensus.py')], capture_output=True, text=True, timeout=120)
        if r.returncode:
            raise RuntimeError(r.stderr[-300:])
        return m.g26(t)
    finally:
        shutil.rmtree(t, ignore_errors=True)


def cr10(m):
    ok_pre, d_pre = g26_with(m, K24.synth())                    # D20 NO-DATA on a pre-r25 node
    ok_r25, _ = g26_with(m, r25(K24.synth()))
    no19, _ = g26_with(m, r25(K24.synth()), lambda d: d.update(detectors=[x for x in d['detectors'] if x['id'] != 'D19-collective-final']))
    return ok_pre and ok_r25 and not no19, f'pre-r25 {ok_pre} ({d_pre[:100]}); r25 {ok_r25}; D19 missing {no19}'


KATS = [('CR1', cr1), ('CR2', cr2), ('CR2b', cr2b), ('CR3', cr3), ('CR4', cr4), ('CR5', cr5), ('CR6', cr6), ('CR7', cr7), ('CR8', cr8),
        ('CR9', cr9), ('CR10', cr10)]

MUTATIONS = [
    ('CR2', "'OBSERVED' if (v or n_rej) else 'NORMAL'", "'OBSERVED' if v else 'NORMAL'", 'D02 back to the accepted-lag tautology'),
    ('CR2b', "and (e.get('t') or 0) >= t_win]", "]", 'D02 counts rejection lines from before the window'),
    ('CR3', "g = 'OBSERVED' if ((v2_now or 0) + v2_win) else 'NORMAL'", "g = 'OBSERVED' if ((v2_now or 0) + v2_win + v2_log) else 'NORMAL'",
     'D13 back to the whole log'),
    ('CR4', "if r_ in VALIDITY_REJECTS and n_}", "if n_}", 'D11 grades relay/ordering refusals as rule violations'),
    ('CR4', "                     sum(bad_b.values()) + sum(bad_m.values()), A(R, 'block_rejected_series'),",
     "                     0, A(R, 'block_rejected_series'),", 'D11 value ignores the counters'),
    ('CR5', "    io = [p for p in parts if p['role'] == 'integrator-only']", "    io = []", 'D19 never sees the coalition'),
    ('CR5', "    g = 'ANOMALY' if lo > 1 / 3 else 'NORMAL'", "    g = 'ANOMALY' if n_io / tf > 1 / 3 else 'NORMAL'", 'D19 ignores the confidence bound'),
    ('CR6', "    bad = not count_ok or only_log or only_node", "    bad = only_log or only_node", 'D20 ignores GetInfo'),
    ('CR6', "    bad = not count_ok or only_log or only_node", "    bad = not count_ok or only_node", 'D20 ignores log-only alt blocks'),
    ('CR6', "    hi_h = H[-1]['height'] - sl - 1", "    hi_h = H[-1]['height']", 'D20 compares unsettled heights'),
    ('CR6', "if e.get('k') in ('add', 'side') and (e.get('t') or 0) >= t0 and", "if e.get('k') in ('add', 'side') and", 'D20 counts blocks before the newest start'),
    ('CR7', "    rpc_fs = any(h.get('fs') for h in H)", "    rpc_fs = False", 'arrival lag never read from first_seen_ms'),
    ('CR1', "        k['fees_total'] = sum(int(h['fees']) for h in H if h['fees'] is not None)", "        k['fees_total'] = 0", 'fees never summed'),
    ('CR1', "    if not lifetime:", "    if True:", 'CO24-C6 proposed on a node that persists the monitor'),
    ('CR1', "        k['unresolved_miniblocks_header'] = sum(1 for h in H for x in (h.get('miners') or [])[:regular] if x == 'unknown')",
     "        k['unresolved_miniblocks_header'] = 'blind'", 'header slots never read'),
    ('CR8', "'integrator_only_final_share', 'top3_final_share', 'peers_connected',", "'integrator_only_final_share', 'top3_final_share',",
     'the peer census left out of the series'),
    ('CR9', "| {'blocks': [{'hash': (b.get('hash') or '')[:16], 'height': b.get('height')} for b in alt.get('blocks') or []]},",
     "| {'blocks': alt.get('blocks') or []},", 'full alt records (first-seen, local flag) copied into the capture'),
    ('CR9', "        return None if (", "        return {'error': msg} if (", 'a pre-r25 node reads as an error, not as absent'),
    ('CR10', "MAY_BE_NODATA = ('D02-ts-future', 'D03-ts-forward', 'D09-late-release', 'D17-this-node', 'D20-alt-blocks')",
     "MAY_BE_NODATA = ('D02-ts-future', 'D03-ts-forward', 'D09-late-release', 'D17-this-node')", 'G26 fails every pre-r25 capture'),
    ('CR10', "'D17-this-node', 'D18-cadence', 'D19-collective-final', 'D20-alt-blocks')", "'D17-this-node', 'D18-cadence', 'D20-alt-blocks')",
     'G26 does not require D19'),
]


def copy_base():
    d = Path(tempfile.mkdtemp(prefix='r25cim-'))
    (d / 'intel').mkdir()
    shutil.copy2(HARNESS / MOD, d / MOD)
    return d


def main():
    fails = 0
    base = copy_base()
    m = K24.load(base)
    for name, fn in KATS:
        try:
            ok, det = fn(m)
        except Exception as e:                                    # noqa: BLE001
            ok, det = False, f'{type(e).__name__}: {e}'
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:420]}")
    shutil.rmtree(base, ignore_errors=True)
    missed, byname = 0, dict(KATS)
    for kat, find, repl, why in MUTATIONS:
        d = copy_base()
        p = d / MOD
        text = p.read_text()
        if text.count(find) != 1:
            print(f'  ??      {kat}: {why} — find text occurs {text.count(find)} times')
            missed += 1
            shutil.rmtree(d, ignore_errors=True)
            continue
        p.write_text(text.replace(find, repl))
        try:
            ok2, _ = byname[kat](K24.load(d))
            verdict = 'MISSED ' if ok2 else 'proved '
        except Exception as e:                                     # noqa: BLE001 — a crash proves nothing: INVALID
            ok2, verdict = True, f'INVALID ({type(e).__name__})'
        print(f'  {verdict} {kat}: {why}')
        missed += ok2
        shutil.rmtree(d, ignore_errors=True)
    print(f'\nR25 consensus-observatory KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
