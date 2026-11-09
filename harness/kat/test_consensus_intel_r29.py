#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the r29 (consensus-peers-disclosure) changes to the chain-consensus
observatory (harness/intel/consensus_intel.py, gate G26): D20's alt-count check without the capture skew and D16's
per-deviator pooling pattern.

Every capture is synthetic and in memory (the r24 KAT's honest 600-block generator and the r25 KAT's r25 shape). No
live node, real log or real runtime file is read or written; CP3 drives capture_live against an in-memory fake RPC.
  CP1  D20 count: GetInfo read before the walk (7) below the stats count (8) with equal settled sets -> NORMAL (the
       r28d 2026-11-08T02:53:50Z skew); GetInfo above it -> ANOMALY; a pair around the stats read [7, 8] with 8 ->
       NORMAL; [7, 7] with 8 and [8, 9] with 7 -> ANOMALY; a log-only alt block -> ANOMALY whatever the counts
  CP2  D16: a pool taking 30 % of the finals from solo miners -> ANOMALY, the pool 'pool node', the others 'part of its
       hashrate mines through another node', the pool beyond the miner-only hashrate (there is none); a pool that
       took every final of two miners (45 %) -> those two are 'pooled miner' and the pool is NOT beyond the miner-only
       hashrate; the honest capture -> NORMAL, no evidence
  CP3  capture_live reads GetInfo right before and right after GetConsensusStats and keeps the pair; D20 uses it
  python3 -I harness/kat/test_consensus_intel_r29.py   # exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught
A mutation that crashes the KAT is INVALID, not caught.
"""
import copy, importlib.util, random, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
MOD = 'intel/consensus_intel.py'


def load_mod(path, name):
    sp = importlib.util.spec_from_file_location(f'{name}_{random.random()}', path)
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


K24 = load_mod(HARNESS / 'kat/test_consensus_intel_r24.py', 'k24')   # synth(), load()
K25 = load_mod(HARNESS / 'kat/test_consensus_intel_r25.py', 'k25')   # r25(), side_event(), analyse(), G()
G, analyse = K25.G, K25.analyse


def d20(m, cap):
    return G(analyse(m, cap))['D20-alt-blocks']['grade']


def cp1(m):
    base = K24.synth()
    cap = copy.deepcopy(base)
    a1 = K25.side_event(cap, 100, 'a1')
    a2 = K25.side_event(cap, 400, 'a2', k='add')
    res = {}
    res['skew'] = d20(m, K25.r25(cap, alt_blocks=[a1, a2], alt_count=8, gi_count=7))
    res['gi_above'] = d20(m, K25.r25(cap, alt_blocks=[a1, a2], alt_count=8, gi_count=9))

    def paired(pair, n):
        c = K25.r25(cap, alt_blocks=[a1, a2], alt_count=n, gi_count=pair[0] - 1)
        c['getinfo']['alt_blocks_count_around_stats'] = list(pair)
        return d20(m, c)
    res['pair_in'] = paired((7, 8), 8)
    res['pair_below'] = paired((7, 7), 8)
    res['pair_above'] = paired((8, 9), 7)
    res['only_log'] = d20(m, K25.r25(cap, alt_blocks=[a1], alt_count=8, gi_count=7))
    want = {'skew': 'NORMAL', 'gi_above': 'ANOMALY', 'pair_in': 'NORMAL', 'pair_below': 'ANOMALY', 'pair_above': 'ANOMALY',
            'only_log': 'ANOMALY'}
    return res == want, f'{res}'


def take_finals(cap, victims, to='m-pool0001'):
    c = copy.deepcopy(cap)
    for h in c['headers']:
        if h['miners'][9] in victims:
            h['miners'][9] = to
    return c


def cp2(m):
    pooled = G(analyse(m, K24.synth(plant={'pool': True})))['D16-final-vs-regular']
    ev = {e['participant']: e for e in pooled['evidence']}
    pool = ev.get('m-pool0001') or {}
    others = [e for p, e in ev.items() if p != 'm-pool0001']
    ok_a = (pooled['grade'] == 'ANOMALY' and pool.get('explained', '').startswith('pool node:') and pool.get('beyond_miner_only') is True
            and others and all(e.get('explained') == 'part of its hashrate mines through another node' for e in others))
    took = G(analyse(m, take_finals(K24.synth(), {'m-aaaa0001', 'm-aaaa0002'})))['D16-final-vs-regular']
    ev2 = {e['participant']: e for e in took['evidence']}
    ok_b = (took['grade'] == 'ANOMALY' and ev2.get('m-pool0001', {}).get('beyond_miner_only') is False
            and all(ev2.get(v, {}).get('explained', '').startswith('pooled miner') for v in ('m-aaaa0001', 'm-aaaa0002')))
    honest = G(analyse(m, K24.synth()))['D16-final-vs-regular']
    ok_c = honest['grade'] == 'NORMAL' and not honest['evidence']
    return bool(ok_a and ok_b and ok_c), (f"pool {pooled['grade']} {pool.get('explained')} beyond {pool.get('beyond_miner_only')} others "
                                          f"{sorted({str(e.get('explained')) for e in others})}; took {took['grade']} "
                                          f"{ {p: (str(e.get('explained'))[:12], e.get('beyond_miner_only')) for p, e in ev2.items()} }; honest {honest['grade']}")


class FakeNode:
    """the RPC surface capture_live reads; GetInfo's alt count grows by one per call (blocks settling meanwhile)."""

    def __init__(self, top=7_000_009):
        self.top, self.gi_calls, self.order = top, 0, []

    def rpc(self, method, params=None, url=None, timeout=60):
        self.order.append(method)
        if method == 'DERO.GetInfo':
            self.gi_calls += 1
            return {'height': self.top, 'topoheight': self.top, 'alt_blocks_count': 2 + self.gi_calls}
        if method == 'DERO.GetBlockHeadersRange':
            s, e = params['start_topoheight'], params['end_topoheight']
            return {'headers': [{'topoheight': t, 'height': t, 'hash': f'{t:064x}', 'timestamp': 1_793_600_000_000 + 18000 * t,
                                 'difficulty': '3000000', 'txcount': 0, 'major_version': 3, 'minor_version': 3, 'sideblock': False,
                                 'orphan_status': False, 'tips': [], 'miners': []} for t in range(s, e + 1)]}
        if method == 'DERO.GetConsensusStats':
            return {'alt_blocks': {'count': 2 + self.gi_calls, 'blocks': []}, 'counters': {}}
        if method == 'DERO.GetPeerInfo':
            return {'peers': []}
        if method == 'DERO.GetMiniBlocks':
            return {'miniblocks': []}
        return {}


def cp3(m):
    node = FakeNode()
    m.rpc, m.read_metrics = node.rpc, (lambda url=None: {})
    cap = m.capture_live(3, b'k' * 32, None, [], sleep_s=0)
    pair = cap['getinfo'].get('alt_blocks_count_around_stats')
    stats_n = cap['consensus_stats']['alt']['count']
    i = node.order.index('DERO.GetConsensusStats')
    adjacent = node.order[i - 1:i] == ['DERO.GetInfo'] and node.order[i + 1:i + 2] == ['DERO.GetInfo']
    ok = cap['getinfo']['alt_blocks_count'] == 3 and pair == [4, 5] and stats_n == 4 and adjacent
    return ok, f"first {cap['getinfo']['alt_blocks_count']} pair {pair} stats {stats_n} adjacent {adjacent}"


KATS = [('CP1', cp1), ('CP2', cp2), ('CP3', cp3)]
MUTATIONS = [
    ('CP1', "        count_ok, how = gi_n <= n, 'GetInfo read before the walk: a lower bound'",
     "        count_ok, how = gi_n == n, 'GetInfo read before the walk: a lower bound'", 'D20 back to equality on a skewed capture'),
    ('CP1', "        count_ok, how = gi_n <= n, 'GetInfo read before the walk: a lower bound'",
     "        count_ok, how = True, 'GetInfo read before the walk: a lower bound'", 'D20 never checks an old capture\'s count'),
    ('CP1', "pair[0] <= n <= pair[1], f'GetInfo", "pair[0] <= n, f'GetInfo", 'D20 drops the upper bound of the pair'),
    ('CP1', "pair[0] <= n <= pair[1], f'GetInfo", "n <= pair[1], f'GetInfo", 'D20 drops the lower bound of the pair'),
    ('CP3', "        alt_pair[1] = rpc('DERO.GetInfo', url=url).get('alt_blocks_count')", "        alt_pair[1] = alt_pair[0]",
     'the after-read is not taken'),
    ('CP3', "    gi_keep = {'alt_blocks_count_around_stats': alt_pair} | {k: gi.get(k) for k in", "    gi_keep = {k: gi.get(k) for k in",
     'the pair is not kept in the capture'),
    ('CP2', "        return ('pool node that also mines' if p['final_share'] > p['regular_share']",
     "        return ('pool node that also mines' if p['final_share'] < p['regular_share']", 'D16 swaps the two mixed patterns'),
    ('CP2', "        if p['role'] == 'miner-only':\n            return 'pooled miner", "        if False:\n            return 'pooled miner",
     'D16 never names a pooled miner'),
    ('CP2', "binom_upper(p['final'], tf_, min(1.0, p['regular_share'] + mo)) < alpha_p", "binom_upper(p['final'], tf_, min(1.0, p['regular_share'])) < alpha_p",
     'D16 ignores the miner-only hashrate a pool can draw on'),
    ('CP2', "            return 'pool node: the finals of the miners it serves getwork to'",
     "            return 'part of its hashrate mines through another node'", 'D16 labels a pool node a part-pooled miner'),
]


def copy_base():
    d = Path(tempfile.mkdtemp(prefix='r29cim-'))
    (d / 'intel').mkdir()
    shutil.copy2(HARNESS / MOD, d / MOD)
    return d


def main():
    fails = 0
    base = copy_base()
    for name, fn in KATS:
        try:
            ok, det = fn(K24.load(base))
        except Exception as e:                                    # noqa: BLE001
            ok, det = False, f'{type(e).__name__}: {e}'
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name} {str(det)[:420]}")
    shutil.rmtree(base, ignore_errors=True)
    if fails:
        print(f'\nR29 consensus-observatory KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
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
    print(f'\nR29 consensus-observatory KATs: {len(KATS)}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
