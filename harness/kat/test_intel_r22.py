#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the R22 harness layer (no network, no live file written).

  IK29 miner_intel binding: classify_binding on the r21 live fractions (GPU busy 0.946 + CPU backlog 0.74 = co-bound)
       and on each single-resource case; per-window gpu_busy_pct is time-weighted; the 'split binding' fact line
       stopped_windows: a recorded stop ('miner exiting', then the next start-up line) explains a derod-side share
       gap (the r21 20:25 -> 06:25 stop was a 10.04 h 'unexplained_gap' WARN), end to end through analyse()
  IK30 metrics_intel split_binding from two /metrics samples: GPU duty, backlog/ring fractions, CPU cores against the
       --cpu-max budget, the GPU-only ceiling estimate, CPU-own hashes per idle try; the raw GPU-busy pair; the fact;
       the cpu_starved WARN (CPU-sort-bound below 80 % of the core budget: other processes take the CPU)
  IK31 run_gates G19: a split miner of this build passes only with a GPU-busy reading that its raw counter pair
       reproduces and a label its own fractions reproduce; other builds and full mode are exempt
  IK32 miner_runs: the miner's own run ledger — torn lines skipped and counted; L1-L8 on the real 20:20 r21 row; a
       broken identity/clock/average/outcome/exit/overlap/missing run each fails its check; derod join covered vs
       not (derod restarted) and partial (50-entry cap); chain join counts only our KeyHash, capped by found
  IK33 run_ledger.window_join: derod's fates inside one run's window; None for a window derod forgot; partial
  IK34 go_mutate: a mutation whose package does not build is INVALID, never CAUGHT; the journal restores a file a
       killed run left mutated (byte-exact) and refuses saved bytes whose hash does not match
  IK35 fix_build_verify S4c: swift_change vs BUILD_STAMPS; a changed server without --gpu-bench FAILS; --no-gpu-bench
       is a recorded SKIP; the A/B judges the interleaved ratio, bit-exactness and a disturbed live GPU;
       parse_capacity reads TestGPUCapacity's line
  IK36 write_atomic: a write that fails midway leaves the old snapshot intact and no file a *_*.json glob can see
  IK37 run_ledger.chain_fix (merge): a closed run's frozen exit paid_fraction is replaced by the chain's; merge keeps it
  IK38 fix_build_verify S3a race_split: a new test in a //go:build !race file runs without -race (pipeline run 1 of
       Round 22 called walletapi's Test_R22_MultiPayload_Distinct_Blinders broken: under -race it never compiles)

  python3 -I harness/kat/test_intel_r22.py            # KATs, then each mutation on a temp copy must flip its KAT
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught.
"""
import hashlib, importlib.util, json, os, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
MODS = {'miner_intel': 'intel/miner_intel.py', 'metrics_intel': 'intel/metrics_intel.py', 'fbv': 'pipeline/fix_build_verify.py',
        'ledger': 'intel/run_ledger.py', 'gates': 'run_gates.py', 'runs': 'intel/miner_runs.py', 'gomut': 'intel/go_mutate.py'}
EXTRA = ['gen_deroarch.py', 'prep_corpus.py', 'consensus_guard.py', 'miners/minelib.py',   # imported by run_gates
         'intel/contention.py']                                                             # R23: loaded by metrics_intel
EXTRA_DIRS = ['kit']


def load(base, name):
    for m in ('gen_deroarch', 'prep_corpus', 'assetkit', 'textkit', 'connectorkit', 'diagramkit', 'minelib'):
        sys.modules.pop(m, None)
    if name == 'gates':
        sys.path[:0] = [str(base / 'kit'), str(base)]
    try:
        spec = importlib.util.spec_from_file_location(f'{name}_{id(base)}_{len(sys.modules)}', base / MODS[name])
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
    finally:
        if name == 'gates':
            del sys.path[:2]
    return m


def J(**kv):
    return json.dumps(kv)


# ───────────────────────────── IK29 ─────────────────────────────
def gsplit(t, staged, busy=None, backlog=30000, ring=50000):
    kv = {'staged_H/s': str(staged), 'dropped_stale': 0, 'cpu_finished': 0, 'audited': 10, 'gpu_us_per_hash': '21.1',
          'gpu_busy_us_per_hash': '12.0', 'cpu_idle_tries': 140000, 'feeder_ring_full_ms': ring, 'feeder_cpu_backlog_ms': backlog,
          'gpu_cpu_mismatch': 0, 'restarts': 0, 'audit_faults': 0, 'disabled': '', 'cpu': 'sort=descriptor verified=1 fallbacks=0'}
    if busy is not None:
        kv['gpu_busy_pct'] = str(busy)
    return J(L='INFO', T=t, N='miner', C='dero-miner/gpu_split.go:294', M='GPU split', **kv)


def ik29(base, tmp):
    MI = load(base, 'miner_intel')
    cb = MI.classify_binding
    # the r21 live reading (2026-10-29 06:37, 710 s): busy 671.8/710, backlog 526.3/710, ring 621.6/710
    live = cb(round(671.8 / 710, 3), round(526.3 / 710, 3), round(621.6 / 710, 3), round(16.03 / 18, 3))
    cases = {'co': cb(0.946, 0.74, 0.875)['binding'], 'gpu': cb(0.95, 0.2, 0.9)['binding'], 'cpu': cb(0.6, 0.7, 0.9)['binding'],
             'ring': cb(0.6, 0.2, 0.8)['binding'], 'bal': cb(0.6, 0.2, 0.3)['binding'], 'unk': cb(None, None, 0.9)['binding'],
             'r20': cb(None, 0.69, 0.78)['binding'], 'edge': cb(0.90, 0.5, 0.0)['binding']}
    d = tmp / 'ik29'
    d.mkdir(exist_ok=True)
    log = d / 'dero-miner.log'
    head = [J(L='INFO', T='2026-10-29T06:25:17.249-0700', N='miner', C='x', M='DERO Stargate HE AstroBWT miner : alpha'),
            J(L='INFO', T='2026-10-29T06:25:17.249-0700', N='miner', C='x', M='', Version='v-r21'),
            J(L='INFO', T='2026-10-29T06:25:17.249-0700', N='miner', C='x', M='', Arguments={'--mining-threads': '20', '--gpu-mode': 'split'})]
    tot = [J(L='INFO', T=f'2026-10-29T06:2{6 + k // 4}:{(k % 4) * 15:02d}.000-0700', N='miner', C='x', M='TOTAL hashrate',
             **{'H/s': str(84000)}) for k in range(6)]
    # windows: 60 s at 98 % busy, 120 s at 92 % busy -> time-weighted (58.8 + 110.4) / 180 = 0.94
    sp = [gsplit('2026-10-29T06:26:17.000-0700', 70000, 50.0), gsplit('2026-10-29T06:27:17.000-0700', 78000, 98.0, 45000, 52000),
          gsplit('2026-10-29T06:29:17.000-0700', 80000, 92.0, 88000, 104000)]
    log.write_text('\n'.join(head + tot + sp) + '\n')
    rep = MI.analyse(str(log), None, use_rpc=False, now=MI.ts('2026-10-29T06:30:00.000-0700'), root=d)
    rg = rep['runs'][-1]['split']['regime']
    fact = [f for f in rep['facts'] if f.startswith('split binding ')]
    # R22: a recorded stop (exit line, then the next start-up line) explains the silence between the runs
    ex = lambda t, m, **kv: {'T': t, 'M': m, **kv}
    r1 = [ex('2026-10-28T20:20:38.379-0700', 'DERO Stargate HE AstroBWT miner : alpha'), ex('2026-10-28T20:25:16.172-0700', 'miner exiting', reason='console exit')]
    r2 = [ex('2026-10-29T06:25:17.249-0700', 'DERO Stargate HE AstroBWT miner : alpha'), ex('2026-10-29T06:30:00.000-0700', 'TOTAL hashrate')]
    r3 = [ex('2026-10-29T07:00:00.000-0700', 'DERO Stargate HE AstroBWT miner : alpha')]
    stops = MI.stopped_windows([r1, r2, r3])
    gaps = MI.unexplained_gaps([MI.ts('2026-10-28T20:23:04.000-0700'), MI.ts('2026-10-29T06:25:31.000-0700')],
                               [(MI.ts(r1[0]['T']), MI.ts(r1[-1]['T'])), (MI.ts(r2[0]['T']), MI.ts(r2[-1]['T']))]
                               + [(a, b) for a, b, _ in stops], MI.ts('2026-10-28T20:00:00.000-0700'), MI.ts('2026-10-29T06:40:00.000-0700'))
    # end to end through analyse(): the r21 shape (exit 20:25:16, start 06:25:17) with derod's own shares at 20:23 and 06:25
    lg = d / 'stop.log'
    hdr = lambda t, v: [J(L='INFO', T=t, N='miner', C='x', M='DERO Stargate HE AstroBWT miner : alpha'),
                        J(L='INFO', T=t, N='miner', C='x', M='', Version=v),
                        J(L='INFO', T=t, N='miner', C='x', M='', Arguments={'--mining-threads': '20', '--gpu-mode': 'full'})]
    tl = lambda day, hh, mm: [J(L='INFO', T=f'2026-10-{day}T{hh}:{mm + k:02d}:00.000-0700', N='miner', C='x', M='TOTAL hashrate',
                                **{'H/s': '84000'}) for k in range(3)]
    lg.write_text('\n'.join(hdr('2026-10-28T20:20:38.379-0700', 'v-r21') + tl('28', '20', 21)
                            + [J(L='INFO', T='2026-10-28T20:25:16.172-0700', N='miner', C='x', M='miner exiting', reason='console exit')]
                            + hdr('2026-10-29T06:25:17.249-0700', 'v-r21') + tl('29', '06', 26)) + '\n')
    dl = d / 'derod.log'
    dl.write_text('\n'.join(J(L='DEBUG', T=t, N='P2P', C='p2p/own_broadcast.go:135', M='Own miniblock delivered', height=1)
                            for t in ('2026-10-28T20:23:04.145-0700', '2026-10-29T06:25:31.000-0700')) + '\n')
    e2e = MI.analyse(str(lg), str(dl), use_rpc=False, now=MI.ts('2026-10-29T06:40:00.000-0700'), root=d, lookback_h=12)
    ds = e2e.get('derod_side') or {}
    ok_stop = (stops == [(MI.ts(r1[-1]['T']), MI.ts(r2[0]['T']), 'console exit')] and gaps == []
               and ds.get('unexplained_gaps') == [] and [s['reason'] for s in ds.get('stopped', [])] == ['console exit']
               and any(f.startswith('miner stopped 2026-10-28T20:25:16') and "reason='console exit'" in f for f in e2e['facts']))
    ok = (ok_stop and live['binding'] == 'co-bound' and live['throttle_capped'] is True
          and cases == {'co': 'co-bound', 'gpu': 'gpu-bound', 'cpu': 'cpu-sort-bound', 'ring': 'ring-bound', 'bal': 'balanced',
                        'unk': 'unknown', 'r20': 'cpu-sort-bound', 'edge': 'co-bound'}
          and rg.get('gpu_busy_fraction') == 0.94 and rg.get('cpu_backlog_fraction') == round(133000 / 180000, 3)
          and rg.get('binding') == 'co-bound' and rg.get('staged_median_hs') == 78000.0 and rg.get('gpu_ceiling_staged_hs') == round(78000 / 0.94, 1)
          and len(fact) == 1 and 'binding=co-bound gpu_busy_fraction=0.94 ' in fact[0]
          and MI.gpu_ceiling(None, 0.9) is None and MI.gpu_ceiling(84000, 0) is None)
    return ok, f'live {live["binding"]} cases {cases} regime {rg} facts {fact}'


# ───────────────────────────── IK30 ─────────────────────────────
def mtext(hashes, hashed, busy, backlog, ring, idle, cpu, version='v-r21'):
    return '\n'.join([
        f'dero_miner_info{{version="{version}"}} 1', 'dero_miner_uptime_seconds 100', 'dero_miner_threads 20',
        'dero_miner_connected 1', f'dero_miner_hashes_total {hashes}', 'dero_miner_hashrate_15s 84000',
        'dero_miner_height 100', 'dero_miner_difficulty 30000000', 'dero_miner_network_hashrate_estimate 3000000',
        f'dero_miner_split_hashed_total {hashed}', 'dero_miner_split_dropped_total 0', 'dero_miner_split_disabled 0',
        f'dero_miner_split_gpu_busy_seconds_total {busy}', f'dero_miner_split_feeder_cpu_backlog_seconds_total {backlog}',
        f'dero_miner_split_feeder_ring_full_seconds_total {ring}', f'dero_miner_split_cpu_idle_tries_total {idle}',
        f'process_cpu_seconds_total {cpu}', 'dero_miner_gpu_mismatch_total 0', ''])


def ik30(base, tmp):
    MT = load(base, 'metrics_intel')
    # 60 s: hashes +5,040,000 of which split +4,800,000 (80 k/s), busy +56.76 s, backlog +44.4, ring +52.5,
    # idle +120,000, cpu +961.8 s (16.03 cores)
    a = MT.parse(mtext(1_000_000, 900_000, 100.0, 100.0, 200.0, 50_000, 1000.0))
    b = MT.parse(mtext(6_040_000, 5_700_000, 156.76, 144.4, 252.5, 170_000, 1961.8))
    bd = MT.split_binding(a, b, 60.0, 20, 90)
    agg = MT.derive(None, None, a, b, 60.0, 90)
    f = MT.facts(agg, [])
    clock = iter([1000.0, 1060.0])
    texts = iter([mtext(1_000_000, 900_000, 100.0, 100.0, 200.0, 50_000, 1000.0), mtext(6_040_000, 5_700_000, 156.76, 144.4, 252.5, 170_000, 1961.8)])
    snap = MT.snapshot('d', 'm', 60.0, get=lambda u: next(texts) if u == 'm' else (_ for _ in ()).throw(OSError('down')),
                       sleep=lambda s: None, clock=lambda: next(clock), cpu_max=90)
    # cpu_starved: the same counters with only 13.0 cores (the 06:44-06:56 reading) -> CPU-sort-bound and starved
    st = MT.split_binding(a, MT.parse(mtext(5_240_000, 5_000_000, 150.5, 146.0, 252.5, 170_000, 1780.0)), 60.0, 20, 90)
    al = {k for k, _, _ in MT.rules({'miner': {'split_binding': st}}, {'miner': True})}
    al_ok = {k for k, _, _ in MT.rules({'miner': {'split_binding': bd}}, {'miner': True})}
    ok = (st['binding'] == 'cpu-sort-bound' and st['cpu_budget_fraction'] == round(13.0 / 18, 3) and 'cpu_starved' in al
          and 'cpu_starved' not in al_ok
          and bd['binding'] == 'co-bound' and bd['gpu_busy_fraction'] == 0.946 and bd['cpu_backlog_fraction'] == 0.74
          and bd['ring_full_fraction'] == 0.875 and bd['cpu_cores'] == 16.03 and bd['cpu_budget_fraction'] == round(16.03 / 18, 3)
          and bd['throttle_capped'] is True and bd['gpu_ceiling_staged_hs'] == round(80000 / 0.946, 1)
          and bd['cpu_own_hs'] == 4000.0 and bd['cpu_own_hashes_per_idle_try'] == 2.0
          and MT.split_binding(a, b, 60.0, 20)['cpu_budget_fraction'] is None and MT.split_binding(None, b, 60.0, 20) is None
          and agg['miner']['split_binding'] == bd
          and any(x.startswith('live split binding=co-bound gpu_busy_fraction=0.946 cpu_backlog_fraction=0.74 ') for x in f)
          and snap['raw']['miner_split_gpu_busy_s'] == [100.0, 156.76] and snap['miner']['split_binding']['binding'] == 'co-bound')
    return ok, f'binding {bd}'


# ───────────────────────────── IK31 ─────────────────────────────
def ik31(base, tmp):
    G = load(base, 'gates')
    MI = load(base, 'miner_intel')
    good_bd = {'binding': 'co-bound', 'gpu_busy_fraction': 0.946, 'cpu_backlog_fraction': 0.74, 'ring_full_fraction': 0.875,
               'cpu_budget_fraction': 0.891}
    def mt(bd, raw=(100.0, 156.76), ver='v-r21', share=0.95):
        return {'miner': {'version': ver, 'split_share': share, 'split_binding': bd},
                'raw': {'t': [1000.0, 1060.0], 'miner_split_gpu_busy_s': list(raw)}}
    r = {'good': G.g19_binding(mt(good_bd), 'v-r21', MI.classify_binding)[0],
         'no_bd': G.g19_binding(mt(None), 'v-r21', MI.classify_binding)[0],
         'no_busy': G.g19_binding(mt({**good_bd, 'gpu_busy_fraction': None}), 'v-r21', MI.classify_binding)[0],
         'raw_off': G.g19_binding(mt(good_bd, raw=(100.0, 130.0)), 'v-r21', MI.classify_binding)[0],
         'no_raw': G.g19_binding(mt(good_bd, raw=(None, None)), 'v-r21', MI.classify_binding)[0],
         'label': G.g19_binding(mt({**good_bd, 'binding': 'cpu-sort-bound'}), 'v-r21', MI.classify_binding)[0],
         'old_build': G.g19_binding(mt(None), 'v-r22', MI.classify_binding)[0],
         'full_mode': G.g19_binding(mt(None, share=0), 'v-r21', MI.classify_binding)[0]}
    ok = r == {'good': True, 'no_bd': False, 'no_busy': False, 'raw_off': False, 'no_raw': False, 'label': False,
               'old_build': True, 'full_mode': True}
    return ok, json.dumps(r)


# ───────────────────────────── IK32 ─────────────────────────────
ROW_2020 = {"kind": "run", "run_id": "18e2e1f3af265068", "version": "v-r21", "start": "2026-10-28T20:20:38-07:00",
            "last": "2026-10-28T20:25:16-07:00", "end": "console exit", "uptime_s": 278, "threads": 20, "cpu_max": 90,
            "gpu_max": 90, "gpu_mode": "split", "hashes": 22680644, "avg_hs": 81646, "height": 7825007, "accepted_blocks": 1,
            "accepted_miniblocks": 2, "rejected": 0, "found_cpu": 0, "found_gpu": 3, "expected_shares": 4.01,
            "outcome_known": True, "paid_cpu": 0, "paid_gpu": 0, "orphaned_cpu": 0, "orphaned_gpu": 1, "unresolved": 2,
            "node_paid_fraction": 0}


def mlog(entries):
    return '\n'.join(J(L='INFO', N='miner', C='x', **e) for e in entries) + '\n'


def ik32(base, tmp):
    R = load(base, 'runs')
    d = tmp / 'ik32'
    d.mkdir(exist_ok=True)
    s20 = R.ts('2026-10-28T20:20:38-07:00')
    log_entries = [{'T': '2026-10-28T20:20:38.379-0700', 'M': 'DERO Stargate HE AstroBWT miner : alpha'},
                   {'T': '2026-10-28T20:20:38.380-0700', 'M': '', 'Version': 'v-r21'},
                   {'T': '2026-10-28T20:21:09.134-0700', 'M': 'GPU-split found DERO miniblock (submitting)', 'height': 7824993},
                   {'T': '2026-10-28T20:23:03.914-0700', 'M': 'GPU-split found DERO miniblock (submitting)', 'height': 7824998},
                   {'T': '2026-10-28T20:24:08.802-0700', 'M': 'GPU-split found DERO miniblock (submitting)', 'height': 7825002},
                   {'T': '2026-10-28T20:25:16.172-0700', 'M': 'miner exiting', 'reason': 'console exit'},
                   {'T': '2026-10-29T06:25:17.249-0700', 'M': 'DERO Stargate HE AstroBWT miner : alpha'},
                   {'T': '2026-10-29T06:25:17.249-0700', 'M': '', 'Version': 'v-r21'}]
    ev = R.log_events([json.loads(l) for l in mlog(log_entries).splitlines()])
    rows, skipped = R.parse_ledger(json.dumps(ROW_2020) + '\n{"kind":"run","run_id":"torn\n' + '{"kind":"other"}\n')
    per, wide = R.validate(rows, ev, s20 + 40000)
    good = per[0]['checks']
    bad = lambda **kv: R.validate([{**ROW_2020, **kv}], ev, s20 + 40000)[0][0]['checks']
    fails = {'L1': bad(run_id='18e2e1f4af265068')['L1 identity'][0] is False and bad(run_id='zz')['L1 identity'][0] is False,
             'L2': bad(uptime_s=250, avg_hs=round(22680644 / 250))['L2 clock'][0] is False,
             'L3': bad(avg_hs=90000)['L3 average'][0] is False,
             'L4': bad(unresolved=1)['L4 outcome'][0] is False,
             'L5': bad(version='v-r20')['L5 log start'][0] is False,
             'L6': bad(end='signal: terminated')['L6 log exit'][0] is False}
    second = {**ROW_2020, 'run_id': format(int(R.ts('2026-10-28T20:24:00-07:00') * 1e9), 'x'), 'start': '2026-10-28T20:24:00-07:00',
              'last': '2026-10-28T20:25:00-07:00', 'uptime_s': 60, 'avg_hs': round(22680644 / 60)}
    _, wide_ov = R.validate([ROW_2020, second], ev, s20 + 40000)
    _, wide_missing = R.validate([], {**ev, 'starts': ev['starts']}, s20 + 40000,
                                 checkpoint={'start': '2026-10-29T06:25:17-07:00', 'version': 'v-r21'})
    _, wide_cov = R.validate(rows, ev, s20 + 40000, checkpoint={'start': '2026-10-29T06:25:17-07:00', 'version': 'v-r21'})
    # derod join: derod started 23:18 (after the 20:20 run): not covered; a covered run counts its window only
    live = {**ROW_2020, 'run_id': 'x', 'start': '2026-10-29T06:25:17-07:00', 'last': '2026-10-29T06:52:17-07:00'}
    t6 = R.ts('2026-10-29T06:30:00-07:00')
    recent = [{'submitted_unix_ms': int((t6 + k) * 1000), 'fate': f} for k, f in enumerate(['paid'] * 8 + ['orphaned', 'pending'])]
    recent.append({'submitted_unix_ms': int((s20 + 100) * 1000), 'fate': 'paid'})          # a fate before the run window
    j = R.join_outcome([ROW_2020, live], {'recent': recent}, R.ts('2026-10-28T23:18:43-07:00'))
    full = [{'submitted_unix_ms': int((t6 + k) * 1000), 'fate': 'paid'} for k in range(50)]
    jp = R.join_outcome([live], {'recent': full}, R.ts('2026-10-28T23:18:43-07:00'))[0]
    # chain join: our KeyHash 'aa..' is in the paid blocks; heights 7824993 (not ours), 7824998 (two of ours on chain,
    # one found by THIS run: capped at 1), 7825002 (not)
    KH, OTHER = 'aa' * 16, 'bb' * 16
    # (a final share's block carries ANOTHER KeyHash on its Final miniblock: 'fin'; the block we built has our address)
    chain = {7824993: [OTHER] * 10, 7824998: [OTHER] * 8 + [KH, KH], 7825002: [OTHER] * 10}
    ME, THEM = [1, 2, 3], [9, 9, 9]
    builders = {7824993: THEM, 7824998: THEM, 7825002: THEM}
    topo = {h + 5: h for h in chain}
    def gb(hash=None, topoheight=None):
        if hash == 'built':                                  # the block of our paid final: its Final KeyHash is not ours
            return {'miner_tx': {'miner_address': ME}, 'miniblocks': [{'KeyHash': OTHER + '0' * 32}, {'KeyHash': 'cc' * 32, 'Final': True}]}
        if hash == 'unreadable':
            return {}
        if hash:
            return {'miniblocks': [{'KeyHash': KH + '0' * 32}, {'KeyHash': OTHER + '0' * 32}] if hash == 'p1'
                    else [{'KeyHash': KH + '0' * 32}]}
        h = topo.get(topoheight)
        return ({'height': h, 'miner_tx': {'miner_address': builders[h]}, 'miniblocks': [{'KeyHash': k + '0' * 32} for k in chain[h]]}
                if h else {'height': (topoheight or 0) - 5})
    oc = {'recent': [{'fate': 'paid', 'block': 'p1'}, {'fate': 'paid', 'block': 'p2'}, {'fate': 'paid', 'block': 'unreadable'},
                     {'fate': 'paid', 'block': 'built', 'final': True, 'built': 'built'}]}
    kh = R.learn_keyhash(oc, gb)
    kh_amb = R.learn_keyhash({'recent': [{'fate': 'paid', 'block': 'p1'}]}, gb)
    me = R.learn_builder(oc, gb)
    cj = R.chain_join([ROW_2020], ev['found'], kh, gb, lambda h: h + 5, me)[0]
    builders[7825002] = ME                                   # had our final won its block race, it would count as paid
    cj_won = R.chain_join([ROW_2020], ev['found'], kh, gb, lambda h: h + 5, me)[0]
    ok = (skipped == 2 and len(rows) == 1 and all(v[0] for v in good.values()) and len(good) == 7 and all(fails.values())
          and wide['L7 order'][0] and not wide_ov['L7 order'][0] and not wide_missing['L8 coverage'][0]
          and wide_cov['L8 coverage'][0]
          and j[0]['covered'] is False and j[0]['paid_fraction'] is None and j[1]['covered'] is True
          and (j[1]['paid'], j[1]['orphaned'], j[1]['pending']) == (8, 1, 1) and j[1]['paid_fraction'] == round(8 / 9, 4)
          and jp['partial'] is True and jp['paid_fraction'] is None
          and kh == KH and kh_amb is None and me == tuple(ME)
          and (cj['found'], cj['paid_chain'], cj['orphaned_chain']) == (3, 1, 2) and cj['paid_fraction_chain'] == 0.3333
          and cj['finals_verifiable'] is True and (cj_won['paid_chain'], cj_won['orphaned_chain']) == (2, 1))
    return ok, f'skipped {skipped} good {good} fails {fails} L7 {wide_ov} L8 {wide_missing} join {j} partial {jp} chain {cj}'


# ───────────────────────────── IK33 ─────────────────────────────
def ik33(base, tmp):
    L = load(base, 'ledger')
    t = L.MI.ts('2026-10-29T06:30:00.000-0700')
    row = {'start': '2026-10-29T06:25:17.249-0700', 'end': '2026-10-29T06:52:17.000-0700'}
    old = {'start': '2026-10-28T20:20:38.379-0700', 'end': '2026-10-28T20:25:16.172-0700'}
    rec = [[int((t + k) * 1000), f, None] for k, f in enumerate(['paid'] * 6 + ['orphaned', 'pending'])]
    w = L.window_join(row, rec)
    w_old = L.window_join(old, rec)
    w_full = L.window_join(row, [[int((t + k) * 1000), 'paid', None] for k in range(50)])
    ok = (w == {'paid': 6, 'orphaned': 1, 'pending': 1, 'partial': False, 'paid_fraction': round(6 / 7, 4)}
          and w_old is None and w_full['partial'] is True and w_full['paid_fraction'] is None and L.window_join(row, []) is None)
    return ok, f'window {w} old {w_old} full {w_full}'


# ───────────────────────────── IK37 ─────────────────────────────
def ik37(base, tmp):
    """R22 merge (H22-5 review): chain_fix replaces a frozen exit paid_fraction with the chain's, keeps the exit value,
    and merge() keeps the correction when a later rebuild of the same run arrives without it."""
    L = load(base, 'ledger')
    r = {'start': '2026-10-28T20:20:38.379-0700', 'end': '2026-10-28T20:25:16.172-0700', 'miner_paid': 0,
         'miner_orphaned': 1, 'paid_fraction': 0.0}
    cj = {'run_id': '18e2e1f3af265068', 'found': 3, 'paid_chain': 2, 'orphaned_chain': 1, 'paid_fraction_chain': 0.6667,
          'finals_verifiable': True}
    f = L.chain_fix(r, cj)
    same = L.chain_fix(dict(r, paid_fraction=0.6667), cj)
    rebuilt = dict(r, end='2026-10-28T20:25:17.000-0700')   # a rebuild with a later end (ties keep the old row anyway)
    m = L.merge([f], [rebuilt])
    ok = (f['paid_fraction'] == 0.6667 and f['paid_fraction_exit'] == 0.0 and f['paid_source'] == 'chain'
          and f['chain_outcome']['paid'] == 2 and 'paid_fraction_exit' not in same and L.chain_fix(r, None) == r
          and len(m) == 1 and m[0]['paid_fraction'] == 0.6667 and m[0]['paid_fraction_exit'] == 0.0)
    return ok, f'fixed {f.get("paid_fraction")} exit {f.get("paid_fraction_exit")} merged {m[0].get("paid_fraction")}'


def ik38(base, tmp):
    F = load(base, 'fbv')
    tagged = ('//go:build !race\n\npackage walletapi\n\n// shares its simulator helper with TestPlain\n'
              'func Test_R22_MultiPayload_Distinct_Blinders(t *testing.T) {}\n')
    plain = 'package walletapi\n\nfunc TestPlain(t *testing.T) {}\n// mentions Test_R22_MultiPayload_Distinct_Blinders\n'
    other = '//go:build linux\n\npackage walletapi\n\nfunc TestLinux(t *testing.T) {}\n'
    names = ['TestPlain', 'Test_R22_MultiPayload_Distinct_Blinders', 'TestLinux']
    race, norace = F.race_split(names, [plain, tagged, other])
    ok = race == ['TestPlain', 'TestLinux'] and norace == ['Test_R22_MultiPayload_Distinct_Blinders'] \
        and F.race_split(['TestPlain'], [plain]) == (['TestPlain'], [])
    return ok, f'race {race} norace {norace}'


# ───────────────────────────── IK34 ─────────────────────────────
def ik34(base, tmp):
    G = load(base, 'gomut')
    r = {'caught': G.mutation_result(1, '--- FAIL: TestX (0.00s)\nFAIL\tgithub.com/x/p2p\t0.1s\n'),
         'missed': G.mutation_result(0, 'ok  \tgithub.com/x/p2p\t0.1s\n'),
         'build': G.mutation_result(1, '# github.com/x/p2p\np2p/penalty.go:12:3: undefined: foo\nFAIL\tgithub.com/x/p2p [build failed]\n'),
         'setup': G.mutation_result(1, 'FAIL\tgithub.com/x/p2p [setup failed]\n'),
         'vetstyle': G.mutation_result(1, '# github.com/x/p2p\np2p/penalty.go:12:3: undefined: foo\n')}
    d = tmp / 'ik34'
    d.mkdir(exist_ok=True)
    src = d / 'penalty.go'
    orig = b'package p2p\n\nconst LIMIT = 10\n'
    src.write_bytes(orig)
    jr, of = d / '.journal', d / '.orig'
    G.journal_begin(src, orig, jr, of)
    src.write_bytes(b'package p2p\n\nconst LIMIT = 1 << 62\n')       # the run is SIGKILLed here: finally never runs
    restored = G.journal_recover(jr, of)
    back = src.read_bytes() == orig and not jr.exists() and not of.exists()
    none_left = G.journal_recover(jr, of) is None
    G.journal_begin(src, orig, jr, of)
    of.write_bytes(b'corrupt')
    try:
        G.journal_recover(jr, of)
        refused = False
    except RuntimeError:
        refused = True
    ok = (r == {'caught': 'CAUGHT', 'missed': 'MISSED', 'build': 'INVALID', 'setup': 'INVALID', 'vetstyle': 'INVALID'}
          and restored == str(src) and back and none_left and refused)
    return ok, f'{r} restored {restored} back {back} refused {refused}'


# ───────────────────────────── IK35 ─────────────────────────────
def ik35(base, tmp):
    F = load(base, 'fbv')
    src = b'// gpu_split_server.swift r21\n'
    h = hashlib.sha256(src).hexdigest()
    stamps = f'# name src bin\ngpu_hash_sais {"0" * 64} {"1" * 64}\ngpu_split_server {h} {"2" * 64}\n'
    same = F.swift_change(stamps, src)
    changed = F.swift_change(stamps, src + b'// r22 kernel\n')
    nostamp = F.swift_change('gpu_hash_sais a b\n', src)
    line = ('GPU CAPACITY geom 512,6,3 gpu-max 50 (stage 1 + GPU SHA, CPU side free; GPU shared with other host jobs): '
            'median 41234 staged H/s range 40000..42000 (4 x 8s) {...}')
    ab = lambda st, ins, bit=True, dist=False: {'staged': st, 'installed': ins, 'bitexact': bit, 'disturbed': dist}
    v = {'unchanged': F.judge_gpubench(same, None)[0], 'changed_auto': F.judge_gpubench(changed, None)[0],
         'nostamp_auto': F.judge_gpubench(nostamp, None)[0], 'changed_off': F.judge_gpubench(changed, 'off')[0],
         'run_ok': F.judge_gpubench(changed, 'run', ab([41000, 42000, 41500], [42000, 41800, 42500]))[0],
         'run_slow': F.judge_gpubench(changed, 'run', ab([36000, 37000, 36500], [42000, 41800, 42500]))[0],
         'run_inexact': F.judge_gpubench(changed, 'run', ab([42000] * 3, [42000] * 3, bit=False))[0],
         'run_disturbed': F.judge_gpubench(changed, 'run', ab([42000], [42000], dist=True))[0],
         'run_norate': F.judge_gpubench(changed, 'run', ab([42000, None], [42000, 42000]))[0],
         # the measured 07:30 failure shape: the server could not start and the test printed 'median 0' and PASSED
         'run_zero': F.judge_gpubench(changed, 'run', ab([0, 0, 0], [0, 0, 0]))[0]}
    ok = (same['changed'] is False and changed['changed'] is True and nostamp['changed'] is None
          and F.parse_capacity(line) == 41234 and F.parse_capacity('no capacity line') is None
          and v == {'unchanged': 'SKIP', 'changed_auto': 'FAIL', 'nostamp_auto': 'FAIL', 'changed_off': 'SKIP', 'run_ok': 'PASS',
                    'run_slow': 'FAIL', 'run_inexact': 'FAIL', 'run_disturbed': 'FAIL', 'run_norate': 'FAIL', 'run_zero': 'FAIL'})
    return ok, json.dumps(v)


# ───────────────────────────── IK36 ─────────────────────────────
def ik36(base, tmp):
    MI = load(base, 'miner_intel')
    d = tmp / 'ik36'
    d.mkdir(exist_ok=True)
    p = d / 'metrics_20261029T000000.json'
    MI.write_atomic(p, '{"ok": 1}')
    real = os.fsync
    def boom(fd):
        raise OSError('disk full')
    os.fsync = boom
    try:
        MI.write_atomic(p, '{"ok": 2, "torn": ' + 'x' * 100000)
        raised = False
    except OSError:
        raised = True
    finally:
        os.fsync = real
    left = sorted(x.name for x in d.iterdir())
    ok = raised and json.loads(p.read_text()) == {'ok': 1} and left == [p.name] and not list(d.glob('metrics_*.json'))[1:]
    return ok, f'raised {raised} left {left}'


KATS = [('IK29', ik29), ('IK30', ik30), ('IK31', ik31), ('IK32', ik32), ('IK33', ik33), ('IK34', ik34), ('IK35', ik35),
        ('IK36', ik36), ('IK37', ik37), ('IK38', ik38)]

# (kat, module, find, replace, why) — each must flip its KAT to FAIL on a temp copy
MUTATIONS = [
    ('IK38', 'fbv', "        if NORACE_TAG.search(text):", "        if False:",
     'a !race-only new test runs under -race, never compiles and fails S3a as broken'),
    ('IK38', 'fbv', "r'^func ' + re.escape(n) + r'\\(', text, re.M)", "re.escape(n), text)",
     'a test merely mentioned in a !race file is moved out of the -race run'),
    ('IK37', 'ledger', "        out['paid_fraction'] = cj['paid_fraction_chain']\n", "",
     'a frozen exit paid_fraction (0.0 for the 20:20 run) is kept next to the chain correction'),
    ('IK37', 'ledger', "            if k in by and by[k].get('chain_outcome') and not keep.get('chain_outcome'):",
     "            if False:", 'an S7 rebuild of the same run silently drops the chain correction'),
    ('IK29', 'miner_intel', "    if g and c:\n        b = 'co-bound'", "    if False:\n        b = 'co-bound'",
     'the r21 co-bound regime is called cpu-sort-bound again (the GPU duty is ignored)'),
    ('IK29', 'miner_intel', "    g = gpu_busy is not None and gpu_busy >= BIND_GPU_BUSY", "    g = gpu_busy is not None and gpu_busy > 0.99",
     'a 0.946-busy GPU is not binding'),
    ('IK29', 'miner_intel', "    elif ring_full is not None and ring_full >= BIND_RING:\n        b = 'ring-bound'",
     "    elif False:\n        b = 'ring-bound'", 'a geometry-limited split is called balanced'),
    ('IK29', 'miner_intel', "busy = round(sum(w['gpu_busy_pct'] * w['dt_s'] for w in gb) / (TG * 100), 3) if TG else None",
     "busy = round(sum(w['gpu_busy_pct'] for w in gb) / (len(gb) * 100), 3) if TG else None",
     'GPU duty averaged per line, not weighted by window length'),
    ('IK29', 'miner_intel', "    report['facts'] += [f for f in (binding_fact(p) for p in report['runs']) if f]\n", "",
     'the binding is not written as an anchorable fact'),
    ('IK29', 'miner_intel', "    return round(staged_hs / gpu_busy, 1)", "    return round(staged_hs * gpu_busy, 1)",
     'the GPU-only ceiling estimate is inverted'),
    ('IK29', 'miner_intel', "        if str(last.get('M', '')) == 'miner exiting' and str(nxt[0].get('M', '')).startswith(START_M):",
     "        if False:", 'a recorded miner stop is reported as an unexplained share gap (the r21 10.04 h WARN)'),
    ('IK29', 'miner_intel', "        covered += [(a, b) for a, b, _ in stops]                  # R22: a recorded stop explains its silence\n", "",
     'the stop windows are computed but never count as covered'),
    ('IK30', 'metrics_intel', "    gb = None if busy is None else round(busy / dt, 3)", "    gb = None if busy is None else round(busy / dt / 1000, 3)",
     'GPU-busy seconds are read as milliseconds'),
    ('IK30', 'metrics_intel', "        budget = round(cores / (threads * cpu_max / 100.0), 3)", "        budget = round(cores / threads, 3)",
     'the --cpu-max budget is ignored'),
    ('IK30', 'metrics_intel', "        own = dh - ds", "        own = dh",
     'split hashes are counted as CPU-own hashes'),
    ('IK30', 'metrics_intel', "        out['miner']['split_binding'] = split_binding(m0, m1, dt, out['miner']['threads'], cpu_max)\n", "",
     'the dashboard never classifies the binding resource'),
    ('IK30', 'metrics_intel', "           'miner_split_gpu_busy_s': [val(x, 'dero_miner_split_gpu_busy_seconds_total') if x else None",
     "           'miner_split_gpu_busy_s': [None if x else None", 'the raw GPU-busy pair G19 recomputes from is lost'),
    ('IK30', 'metrics_intel', "                and bd['cpu_budget_fraction'] < STARVED_BUDGET:", "                and bd['cpu_budget_fraction'] < 0.5:",
     'a miner at 72 % of its CPU budget is not called starved'),
    ('IK31', 'gates', "    if abs(re_busy - bd['gpu_busy_fraction']) > 0.002:", "    if False:",
     'G19 accepts a GPU-busy fraction its raw counters do not reproduce'),
    ('IK31', 'gates', "    if want != bd.get('binding'):", "    if False:", 'G19 accepts a label its own fractions contradict'),
    ('IK31', 'gates', "    if not bd or bd.get('gpu_busy_fraction') is None:", "    if not bd:",
     'G19 passes a split miner without a GPU-busy reading'),
    ('IK31', 'gates', "    if not m.get('split_share') or not tree_ver or m.get('version') != tree_ver:", "    if not m.get('split_share'):",
     'G19 fails builds older than the GPU-busy counter'),
    ('IK32', 'runs', "        if not isinstance(r, dict) or r.get('kind') != 'run':\n            skipped += 1",
     "        if not isinstance(r, dict):\n            skipped += 1", 'a foreign line is read as a run'),
    ('IK32', 'runs', "            c['L4 outcome'] = (res == acc,", "            c['L4 outcome'] = (True,",
     'a ledger line whose fates do not add up to its accepted shares passes'),
    ('IK32', 'runs', "            c['L6 log exit'] = (end in hit,", "            c['L6 log exit'] = (True,",
     'a clean exit the log never recorded passes'),
    ('IK32', 'runs', "             if ts(a['start']) + float(a.get('uptime_s') or 0) > ts(b['start']) + CLOCK_SLACK_S]",
     "             if False]", 'overlapping runs pass'),
    ('IK32', 'runs', "             and not any(abs(t - h) <= LOG_SLACK_S for h in have)]", "             and False]",
     'an ended run without a ledger line (lost evidence) passes'),
    ('IK32', 'runs', "        cov = derod_start is not None and s >= derod_start - 1", "        cov = True",
     'a run from before derod restarted is reported with derod\'s (empty) fates as if covered'),
    ('IK32', 'runs', "        partial = len(recent) >= RECENT_CAP and oldest is not None and oldest > s", "        partial = False",
     'a run longer than derod\'s 50-fate list gets a paid fraction from its tail only'),
    ('IK32', 'runs', "            paid += min(n, ours)", "            paid += ours", 'other miners\' miniblocks are capped by nothing'),
    ('IK32', 'runs', "    return next(iter(common)) if common and len(common) == 1 else None", "    return next(iter(common)) if common else None",
     'an ambiguous KeyHash is used for the chain join'),
    ('IK32', 'runs', "        if not kh:\n            continue\n        common = kh", "        common = kh",
     'an unreadable paid block empties the KeyHash intersection (the live 07:03 failure)'),
    ('IK32', 'runs', "        if x.get('fate') != 'paid' or not x.get('block') or x.get('final'):", "        if x.get('fate') != 'paid' or not x.get('block'):",
     'a paid FINAL (another KeyHash) empties the intersection'),
    ('IK32', 'runs', "            ours += sum(1 for b in bs if builder and", "            ours += sum(0 for b in bs if builder and",
     'a final share whose block we built is counted as orphaned'),
    ('IK33', 'ledger', "    if not f and e < oldest:\n        return None", "    if False:\n        return None",
     'a run derod forgot is reported as 0 paid / 0 orphaned'),
    ('IK33', 'ledger', "    partial = len(recent) >= cap and oldest > s", "    partial = False", 'a partial window is reported whole'),
    ('IK34', 'gomut', "    if BUILD_FAILED.search(text or ''):\n        return 'INVALID'", "    if False:\n        return 'INVALID'",
     'a mutation that does not compile is counted CAUGHT'),
    ('IK34', 'gomut', "    _fsync_write(j['file'], data)\n    journal_end(journal, origf)", "    journal_end(journal, origf)",
     'a killed run\'s mutated file is not restored'),
    ('IK34', 'gomut', "    if hashlib.sha256(data).hexdigest() != j['sha256']:", "    if False:",
     'corrupt saved bytes are written over the source'),
    ('IK35', 'fbv', "    self_ab = change.get('changed') is False", "    self_ab = change.get('changed') is not True",
     'a server with no stamp line is waved through'),
    ('IK35', 'fbv', "    if mode != 'run' or ab is None:\n        return 'FAIL'", "    if mode != 'run' or ab is None:\n        return 'SKIP'",
     'a changed Swift server is installed with its GPU side never benched'),
    ('IK35', 'fbv', "any(x is None or x <= 0 for x in", "any(x is None for x in",
     'a capacity arm whose server never started (0 H/s) is judged as a ratio'),
    ('IK35', 'fbv', "    elif st / ins < GPU_RATIO_MIN:", "    elif st / ins < 0.5:", 'a 13 % GPU-side regression passes'),
    ('IK35', 'fbv', "    if ab.get('disturbed'):", "    if False:", 'a run that disturbed the live GPU passes'),
    ('IK35', 'fbv', "    if not ab.get('bitexact'):", "    if False:", 'a server that is not bit-exact passes'),
    ('IK36', 'miner_intel', "        os.replace(tmp, p)\n    except BaseException:", "        os.replace(tmp, p)\n    except ImportError:",
     'a failed write leaves its temp file behind'),
    ('IK36', 'miner_intel', "    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix='.' + p.name + '.', suffix='.tmp')",
     "    p.write_text(text)\n    return\n    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix='.' + p.name + '.', suffix='.tmp')",
     'the snapshot is written in place (torn on a kill)'),
]


def copy_tree():
    d = Path(tempfile.mkdtemp(prefix='r22kat-'))
    for rel in list(MODS.values()) + EXTRA:
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HARNESS / rel, d / rel)
    for rel in EXTRA_DIRS:
        shutil.copytree(HARNESS / rel, d / rel, ignore=shutil.ignore_patterns('__pycache__', '.cache'))
    return d


def main():
    tmp = Path(tempfile.mkdtemp(prefix='r22fx-'))
    fails = 0
    base = copy_tree()
    for name, fn in KATS:
        try:
            ok, det = fn(base, tmp)
        except Exception as e:                                    # noqa: BLE001
            ok, det = False, f'{type(e).__name__}: {e}'
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    shutil.rmtree(base, ignore_errors=True)
    missed = 0
    byname = dict(KATS)
    for kat, mod, find, repl, why in MUTATIONS:
        d = copy_tree()
        p = d / MODS[mod]
        text = p.read_text()
        if text.count(find) != 1:
            print(f'  ??      {kat}: {why} — find text occurs {text.count(find)} times')
            missed += 1
            shutil.rmtree(d, ignore_errors=True)
            continue
        p.write_text(text.replace(find, repl))
        t2 = Path(tempfile.mkdtemp(prefix='r22fx-m-'))
        try:
            ok2 = byname[kat](d, t2)[0]
        except Exception:                                          # noqa: BLE001 — a crash is a detection
            ok2 = False
        print(f"  {'proved ' if not ok2 else 'MISSED '} {kat}: {why}")
        missed += ok2
        shutil.rmtree(d, ignore_errors=True)
        shutil.rmtree(t2, ignore_errors=True)
    shutil.rmtree(tmp, ignore_errors=True)
    print(f'\nR22 harness KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
