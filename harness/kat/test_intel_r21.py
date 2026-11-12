#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the R21 harness layer (no network, no live file written).

  IK21 miner_intel split regime: per-window readings from consecutive 'GPU split' lines, time-weighted CPU-sort
       backlog and ring-full fractions, idle tries per minute, the regime label (r19 shape -> gpu-bound, r20 shape ->
       cpu-sort-bound), the 'split regime' fact line, and the split_silent ALERT (split mode, > 3 min, no split line)
  IK22 metrics_intel split regime from two /metrics samples: staged H/s, backlog/ring fractions (seconds per
       second), idle tries per minute, sampled stale fraction, the shared classifier, the 'live split regime' fact
  IK23 fix_build_verify S4b like for like: sort_impl reads the sorter each build used (r15 'descriptor sort (',
       r16+ ', native C' / ', Go', SA-IS); like_for_like refuses a ratio across different sorters and reproduces
       the r20 artefact (installed Go 1,852 vs staged native 3,064 = x1.654) as NOT like for like; judge_minerbench
       fails an unlocked bench, a staged split-bench skip and a like-for-like regression
  IK24 fix_build_verify: live_split_reading is STALE / NO_DATA / LIVE (r20 recorded LIVE with every number null);
       judged_step fails an intel step that crashed or wrote no new snapshot (the gates would judge an old one)
  IK25 run_ledger: one row per run from snapshots + the rotated chain; a run survives its log rotating away; the
       latest end wins; re-running is byte-identical; a covered head_missing fragment is dropped; derod's outcome
       is attached to the current run only; paid fraction = paid / (paid + orphaned)
  IK26 run_gates G17/G18 regime checks: this tree's split build without the backlog counter fails, older builds
       and full mode are exempt
  IK27 gpu_watch.disturbed: a miner restart (uptime backwards), split disabled, restarts grown, mismatch, no
       hashing and a silent endpoint are each caught — the two that benchlock --gpu's log check cannot see first

  python3 -I harness/kat/test_intel_r21.py            # KATs, then each mutation on a temp copy must flip its KAT
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught.
"""
import importlib.util, json, shutil, sys, tempfile, time
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
MODS = {'miner_intel': 'intel/miner_intel.py', 'metrics_intel': 'intel/metrics_intel.py', 'fbv': 'pipeline/fix_build_verify.py',
        'ledger': 'intel/run_ledger.py', 'gates': 'run_gates.py', 'gpu_watch': 'intel/gpu_watch.py'}
EXTRA = ['gen_deroarch.py', 'prep_corpus.py', 'consensus_guard.py', 'miners/minelib.py',   # imported by run_gates
         'intel/contention.py']                                                             # R23: loaded by metrics_intel
EXTRA_DIRS = ['kit']


def load(base, name):
    for m in ('gen_deroarch', 'prep_corpus', 'assetkit', 'textkit', 'connectorkit', 'diagramkit', 'minelib'):
        sys.modules.pop(m, None)                          # run_gates imports by name: bind THIS copy's modules
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


def split_line(t, staged, idle, ring, backlog=None, gus='18.7', dropped=0, restarts=0):
    kv = {'staged_H/s': str(staged), 'dropped_stale': dropped, 'cpu_finished': 0, 'audited': 10, 'gpu_us_per_hash': gus,
          'cpu_idle_tries': idle, 'feeder_ring_full_ms': ring}
    if backlog is not None:
        kv['feeder_cpu_backlog_ms'] = backlog
    kv.update({'gpu_cpu_mismatch': 0, 'restarts': restarts, 'audit_faults': 0, 'disabled': '', 'cpu': 'sort=descriptor verified=1 fallbacks=0'})
    return J(L='INFO', T=t, N='miner', C='dero-miner/gpu_split.go:196', M='GPU split', **kv)


def run_text(day, version, splits, mode='split', n_total=6, hh='10'):
    out = [J(L='INFO', T=f'2026-10-{day}T{hh}:00:00.000-0700', N='miner', C='x', M='DERO Stargate HE AstroBWT miner : alpha'),
           J(L='INFO', T=f'2026-10-{day}T{hh}:00:00.000-0700', N='miner', C='x', M='', Version=version),
           J(L='INFO', T=f'2026-10-{day}T{hh}:00:00.000-0700', N='miner', C='x', M='', Arguments={'--mining-threads': '20', '--gpu-mode': mode})]
    for k in range(n_total):
        out.append(J(L='INFO', T=f'2026-10-{day}T{hh}:{k // 4:02d}:{(k % 4) * 15:02d}.000-0700', N='miner', C='x',
                     M='TOTAL hashrate', **{'H/s': str(70000 + k)}))
    out += splits
    out.append(J(L='INFO', T=f'2026-10-{day}T{hh}:05:00.000-0700', N='miner', C='x', M='REWARD STATS', node_paid=9, node_orphaned=1))
    return '\n'.join(out) + '\n'


R20_SPLITS = [split_line('2026-10-28T10:01:00.000-0700', 60000, 99999, 9999, 9999),       # window unknown: skipped
              split_line('2026-10-28T10:02:00.000-0700', 73000, 22000, 47000, 41000),
              split_line('2026-10-28T10:03:00.000-0700', 79000, 78000, 46000, 39000, gus='20.4', dropped=60000)]
R19_SPLITS = [split_line('2026-10-27T10:01:00.000-0700', 57000, 1, 1, None, gus='32.7'),
              split_line('2026-10-27T10:02:00.000-0700', 57000, 394000, 45000, None, gus='32.7'),
              split_line('2026-10-27T10:03:00.000-0700', 57200, 390000, 45600, None, gus='32.5')]


# ───────────────────────────── IK21 ─────────────────────────────
def ik21(base, tmp):
    MI = load(base, 'miner_intel')
    d = tmp / 'ik21'
    d.mkdir(exist_ok=True)
    log = d / 'dero-miner.log'
    (d / 'dero-miner.log.1').write_text(run_text('27', 'v-r19', R19_SPLITS))
    log.write_text(run_text('28', 'v-r20', R20_SPLITS))
    rep = MI.analyse(str(log), None, use_rpc=False, now=MI.ts('2026-10-28T10:05:30.000-0700'), root=d)
    r19, r20 = (r['split'].get('regime') or {} for r in rep['runs'])
    facts = [f for f in rep['facts'] if f.startswith('split regime ')]
    ok = (r20.get('windows') == 2 and r20.get('cpu_backlog_fraction') == round(80000 / 120000, 3)
          and r20.get('ring_full_fraction') == round(93000 / 120000, 3) and r20.get('idle_tries_per_min') == 50000.0
          and r20.get('regime') == 'cpu-sort-bound' and r20.get('staged_median_hs') == 73000.0
          and r19.get('cpu_backlog_fraction') is None and r19.get('regime') == 'gpu-bound'
          and len(facts) == 2 and 'regime=cpu-sort-bound' in facts[1] and 'cpu_backlog_fraction=0.667' in facts[1]
          and MI.classify_regime(0.2, 1000, 20) == 'balanced' and MI.classify_regime(None, None, 20) == 'unknown')
    # split mode, no 'GPU split' line: silent after 3 min, not before
    log2 = d / 'silent.log'
    log2.write_text(run_text('28', 'v-r20', []))
    late = {a['rule'] for a in MI.analyse(str(log2), None, use_rpc=False, now=MI.ts('2026-10-28T10:05:30.000-0700'),
                                          root=d)['runs'][-1]['alerts']}
    early = {a['rule'] for a in MI.analyse(str(log2), None, use_rpc=False, now=MI.ts('2026-10-28T10:02:00.000-0700'),
                                           root=d)['runs'][-1]['alerts']}
    full = d / 'full.log'
    full.write_text(run_text('28', 'v-r20', [], mode='full'))
    fm = {a['rule'] for a in MI.analyse(str(full), None, use_rpc=False, now=MI.ts('2026-10-28T10:05:30.000-0700'),
                                        root=d)['runs'][-1]['alerts']}
    ok2 = 'split_silent' in late and 'split_silent' not in early and 'split_silent' not in fm
    return ok and ok2, f'r20 {r20} r19 {r19} facts {len(facts)} silent late {late} early {early} full {fm}'


# ───────────────────────────── IK22 ─────────────────────────────
def mtext(hashes, hashed, dropped, backlog_s, ring_s, idle, version='v-r20'):
    return '\n'.join([
        f'dero_miner_info{{version="{version}"}} 1', 'dero_miner_uptime_seconds 100', 'dero_miner_threads 20',
        'dero_miner_connected 1', f'dero_miner_hashes_total {hashes}', 'dero_miner_hashrate_15s 70000',
        'dero_miner_height 100', 'dero_miner_difficulty 30000000', 'dero_miner_network_hashrate_estimate 3000000',
        f'dero_miner_split_hashed_total {hashed}', f'dero_miner_split_dropped_total {dropped}', 'dero_miner_split_disabled 0',
        f'dero_miner_split_feeder_cpu_backlog_seconds_total {backlog_s}', f'dero_miner_split_feeder_ring_full_seconds_total {ring_s}',
        f'dero_miner_split_cpu_idle_tries_total {idle}', 'dero_miner_gpu_mismatch_total 0', ''])


def ik22(base, tmp):
    MT = load(base, 'metrics_intel')
    a = MT.parse(mtext(1_000_000, 900_000, 1000, 100.0, 200.0, 5000))
    b = MT.parse(mtext(5_500_000, 5_300_000, 5000, 141.0, 247.5, 29000))
    rg = MT.split_regime(a, b, 60.0, 20)
    stale = MT.split_regime(MT.parse(mtext(0, 0, 0, 0, 0, 0)), MT.parse(mtext(10, 900, 100, 10.0, 50.0, 10)), 60.0, 20)
    agg = MT.derive(None, None, a, b, 60.0)
    al = {k for k, _, _ in MT.rules({**agg, 'miner': {**agg['miner'], 'split_regime': stale}}, {'derod': True, 'miner': True})}
    f = MT.facts(agg, [])
    ok = (rg == {'staged_hs': round(4_400_000 / 60, 1), 'cpu_backlog_fraction': round(41.0 / 60, 3),
                 'ring_full_fraction': round(47.5 / 60, 3), 'idle_tries_per_min': 24000.0,
                 'stale_fraction': round(4000 / (4000 + 4_400_000), 4), 'regime': 'cpu-sort-bound'}
          and stale['stale_fraction'] == 0.1 and 'split_stale' in al and MT.split_regime(None, b, 60.0, 20) is None
          and any(x.startswith('live split regime=cpu-sort-bound staged_hs=73333.3 ') for x in f))
    return ok, f'regime {rg} stale {stale} alerts {al}'


# ───────────────────────────── IK23 ─────────────────────────────
def out_of(using, cpu, threads=4):
    return (f'28/10 13:23:48\tINFO\tminer\tsuffix sort\t{{"using": "{using}"}}\n'
            f'{"Threads":>20} {"Total Time":>20}\n{threads:>20} {"1s":>20} {1000 * threads:>20} {"1ms":>20} {cpu:>20} {cpu * 2:>20} \n')


NATIVE = 'descriptor sort, native C (self-test passed on 51 inputs; 1 in 1024 verified while mining)'
GO = 'descriptor sort, Go (self-test passed on 51 inputs; 1 in 1024 verified while mining)'
R15 = 'descriptor sort (self-test passed on 51 inputs; 1 in 1024 verified while mining)'


def ik23(base, tmp):
    F = load(base, 'fbv')
    impls = [F.sort_impl(out_of(u, 1)) for u in (NATIVE, GO, R15, 'built-in SA-IS (--sort=sais)')] + [F.sort_impl('no line')]
    cpu = F.parse_bench(out_of(NATIVE, 3064.5), 4)[0]
    # the r20 pipeline's comparison: installed --sort=descriptor (Go) vs staged --sort=auto (native C)
    r20_shape = F.like_for_like({'auto': {'staged': [(3064.5, 'native C')], 'installed': []},
                                 'descriptor': {'staged': [], 'installed': [(1852.7, 'Go')]}})
    # this round's interleaved A/B (H/cpu-s at 4 threads): r19 vs r20 under the same --sort
    ab = F.like_for_like({'auto': {'staged': [(3167.9, 'native C'), (3165.9, 'native C'), (3166.1, 'native C')],
                                   'installed': [(2982.3, 'native C'), (3041.7, 'native C'), (3087.2, 'native C')]},
                          'descriptor': {'staged': [(1937.8, 'Go'), (1898.1, 'Go'), (1914.3, 'Go')],
                                         'installed': [(1940.6, 'Go'), (1952.3, 'Go'), (1951.2, 'Go')]}})
    # an installed build with no native sorter (r15): auto differs, the Go port is the fair comparison
    old = F.like_for_like({'auto': {'staged': [(3100.0, 'native C')], 'installed': [(1141.0, 'Go')]},
                           'descriptor': {'staged': [(1900.0, 'Go')], 'installed': [(1396.4, 'Go')]}})
    res = {'descriptor': [1900.0], 'sais': [420.0]}
    split = {'h_per_cpu_s': 5400.0, 'declined': 0}
    j_ok = F.judge_minerbench(res, ab, split, 3166.0, locked=True)
    j_unl = F.judge_minerbench(res, ab, split, 3166.0, locked=False)
    j_skip = F.judge_minerbench(res, ab, {'skip': 'gpu split mode needs paired hashing; off'}, 3166.0, locked=True)
    reg = F.like_for_like({'auto': {'staged': [(2700.0, 'native C')], 'installed': [(3041.7, 'native C')]}})
    j_reg = F.judge_minerbench(res, reg, split, 2700.0, locked=True)
    # r21 merge: no sorter line anywhere and an installed build 3x faster must FAIL (it was (True, []))
    blind = F.like_for_like({'auto': {'staged': [(1000.0, None)], 'installed': [(3000.0, None)]},
                             'descriptor': {'staged': [(900.0, None)], 'installed': [(2900.0, None)]}})
    j_blind = F.judge_minerbench(res, blind, split, 1000.0, locked=True)
    # sorters differ in both modes while the installed build names them: no comparison possible, FAIL with the why
    cross = F.like_for_like({'auto': {'staged': [(3100.0, 'native C')], 'installed': [(3000.0, 'Go')]},
                             'descriptor': {'staged': [(1900.0, 'Go')], 'installed': [(1800.0, 'native C')]}})
    j_cross = F.judge_minerbench(res, cross, split, 3100.0, locked=True)
    ok = (impls == ['native C', 'Go', 'Go', 'SA-IS', None] and cpu == 3064.5
          and r20_shape['ratio'] is None and 'same sorter' in r20_shape['why']
          and ab['ratio'] == round(3166.1 / 3041.7, 3) and ab['mode'] == 'auto' and ab['impl'] == 'native C'
          and ab['per_mode']['descriptor']['ratio'] == round(1914.3 / 1951.2, 3)
          and old['mode'] == 'descriptor' and old['ratio'] == round(1900.0 / 1396.4, 3)
          and j_ok[0] and not j_unl[0] and not j_skip[0] and any('skipped the split bench' in w for w in j_skip[1])
          and not j_reg[0] and any('same sorter' in w for w in j_reg[1])
          and not j_blind[0] and any("no 'suffix sort' line" in w for w in j_blind[1])
          and not j_cross[0] and any('no like-for-like' in w for w in j_cross[1]))
    return ok, f'impls {impls} r20 {r20_shape["ratio"]} ab {ab["ratio"]} old {old["mode"]}/{old["ratio"]} judge {j_ok} {j_unl[0]} {j_skip[0]} {j_reg}'


# ───────────────────────────── IK24 ─────────────────────────────
def ik24(base, tmp):
    F = load(base, 'fbv')
    d = tmp / 'ik24'
    d.mkdir(exist_ok=True)
    now = time.time()

    def snap(name, age_s, lines, staged):
        p = d / name
        cap = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(now - age_s)) + time.strftime('%z')
        cap = cap[:-2] + ':' + cap[-2:]
        p.write_text(json.dumps({'captured': cap, 'runs': [{'version': 'v', 'gpu_mode': 'split', 'hashrate': {'mean': 1.0},
                                                            'split': {'lines': lines, 'staged_mean': staged,
                                                                      'regime': {'regime': 'cpu-sort-bound', 'windows': lines}}}]}))
        return p
    stale = F.live_split_reading([snap('a.json', 4 * 3600, 0, None)], now)
    nodata = F.live_split_reading([snap('b.json', 60, 0, None)], now)
    live = F.live_split_reading([snap('c.json', 60, 5, 72000.0)], now)
    old, new = [('minerintel_1.json', 1)], [('minerintel_1.json', 1), ('minerintel_2.json', 2)]
    J_ = F.judged_step
    cases = [J_('harness/intel/miner_intel.py', 1, old, new)[0], J_('harness/intel/miner_intel.py', 2, old, old)[0],
             J_('harness/intel/miner_intel.py', 0, old, old)[0], J_('harness/intel/miner_intel.py', 7, old, new)[0],
             J_('harness/run_gates.py', 3, [], [])[0], J_('harness/run_gates.py', 1, [], [])[0],
             J_('harness/miners/mine_intel.py', 1, [], [])[0], J_('harness/intel/metrics_intel.py', 2, old, new)[0],
             J_('harness/intel/miner_intel.py', 0, old, [('minerintel_1.json', 5)])[0],
             # r24 (integration): a KAT file whose name contains an intel step's name is not that step
             J_('harness/kat/test_consensus_intel_r24.py', 0, [], [])[0], J_('harness/intel/consensus_intel.py', 0, old, old)[0]]
    ok = (stale['status'] == 'STALE' and nodata['status'] == 'NO_DATA' and live['status'] == 'LIVE'
          and live['staged_mean_hs'] == 72000.0 and live['regime'] == 'cpu-sort-bound'
          and cases == [False, False, False, True, True, False, False, True, True, True, False])
    return ok, f"{stale['status']} {nodata['status']} {live['status']} cases {cases}"


# ───────────────────────────── IK25 ─────────────────────────────
def ik25(base, tmp):
    L = load(base, 'ledger')
    d = tmp / 'ik25'
    d.mkdir(exist_ok=True)
    log = d / 'dero-miner.log'
    (d / 'dero-miner.log.1').write_text(run_text('27', 'v-r19', R19_SPLITS))
    log.write_text(run_text('28', 'v-r20', R20_SPLITS))
    led = d / 'run_ledger.jsonl'
    now = L.MI.ts('2026-10-28T10:06:00.000-0700')
    real = L.MI.outcome
    L.MI.outcome = lambda *a, **k: {'submitted': 6, 'paid': 5, 'orphaned': {'slots_full': 1}, 'orphaned_total': 1, 'pending': 0,
                                    'paid_fraction': 5 / 6}
    try:
        rows = L.build(led, str(log), None, True, snapshots=[], now=now)
        L.write_ledger(led, rows)
        first = led.read_bytes()
        L.write_ledger(led, L.build(led, str(log), None, True, snapshots=[], now=now))
        again = led.read_bytes()
        # the r19 log rotates away; a shorter observation of the r20 run must not replace the longer one
        (d / 'dero-miner.log.1').unlink()
        log.write_text(''.join(run_text('28', 'v-r20', R20_SPLITS).splitlines(True)[:9]))   # header + TOTAL lines only
        L.write_ledger(led, L.build(led, str(log), None, False, snapshots=[], now=now))
        after = L.read_ledger(led)
    finally:
        L.MI.outcome = real
    frag = {'start': '2026-10-28T10:01:00.000-0700', 'end': '2026-10-28T10:02:00.000-0700', 'version': 'v-r20', 'head_missing': True}
    lone = {'start': '2026-10-29T10:01:00.000-0700', 'end': '2026-10-29T10:02:00.000-0700', 'version': 'v-r21', 'head_missing': True}
    merged = L.merge(after, [frag, lone])
    ok = (len(rows) == 2 and rows[0]['version'] == 'v-r19' and rows[1]['regime'] == 'cpu-sort-bound'
          and rows[0]['regime'] == 'gpu-bound' and rows[1]['paid_fraction'] == 0.9
          and 'derod_outcome' in rows[1] and 'derod_outcome' not in rows[0] and rows[1]['derod_outcome']['paid_fraction'] == 0.8333
          and first == again and len(after) == 2 and after[0]['version'] == 'v-r19'
          and after[1]['end'] == rows[1]['end'] and 'derod_outcome' in after[1]
          and [r['start'] for r in merged] == [after[0]['start'], after[1]['start'], lone['start']])
    return ok, f'rows {len(rows)} idempotent {first == again} after {[(r["version"], r["end"][11:19]) for r in after]} merged {len(merged)}'


# ───────────────────────────── IK26 ─────────────────────────────
def ik26(base, tmp):
    G = load(base, 'gates')
    sp = lambda bl: {'version': 'v-r21', 'split': {'lines': 5, 'regime': {'windows': 4, 'cpu_backlog_fraction': bl}}}
    g17 = [G.g17_regime_ok(sp(None), 'v-r21'), G.g17_regime_ok(sp(0.68), 'v-r21'), G.g17_regime_ok(sp(None), 'v-r22'),
           G.g17_regime_ok({'version': 'v-r21', 'split': {'lines': 0}}, 'v-r21')]
    m = lambda rg, share=0.98: {'version': 'v-r21', 'split_share': share, 'split_regime': rg}
    g18 = [G.g18_regime_ok(m(None), 'v-r21'), G.g18_regime_ok(m({'cpu_backlog_fraction': 0.7, 'idle_tries_per_min': 1.0}), 'v-r21'),
           G.g18_regime_ok(m({'cpu_backlog_fraction': None, 'idle_tries_per_min': 1.0}), 'v-r21'),
           G.g18_regime_ok(m(None), 'v-r20'), G.g18_regime_ok(m(None, share=0), 'v-r21')]
    ok = g17 == [False, True, True, True] and g18 == [False, True, False, True, True]
    return ok, f'g17 {g17} g18 {g18}'


# ───────────────────────────── IK27 ─────────────────────────────
def ik27(base, tmp):
    W = load(base, 'gpu_watch')
    a = W.parse('dero_miner_uptime_seconds 1000\ndero_miner_gpu_restarts_total 0\ndero_miner_split_restarts_total 0\n'
                'dero_miner_split_disabled 0\ndero_miner_gpu_mismatch_total 0\ndero_miner_split_hashed_total 100\n# x\n')
    ok_b = dict(a, dero_miner_uptime_seconds=1070.0, dero_miner_split_hashed_total=5000.0)
    cases = {'calm': W.disturbed(a, ok_b),
             'miner_restart': W.disturbed(a, dict(ok_b, dero_miner_uptime_seconds=30.0)),
             'disabled': W.disturbed(a, dict(ok_b, dero_miner_split_disabled=1.0)),
             'restarts': W.disturbed(a, dict(ok_b, dero_miner_split_restarts_total=1.0)),
             'mismatch': W.disturbed(a, dict(ok_b, dero_miner_gpu_mismatch_total=2.0)),
             'stalled': W.disturbed(a, dict(ok_b, dero_miner_split_hashed_total=100.0)),
             'down': W.disturbed(a, None), 'no_before': W.disturbed(None, ok_b),
             # r21 merge: a restart during a command longer than the old uptime (uptime 1000 -> 1900 over 1000 s)
             'late_restart': W.disturbed(a, dict(ok_b, dero_miner_uptime_seconds=1900.0), 1000.0)}
    calm_timed = W.disturbed(a, ok_b, 70.0)
    ok = (a['dero_miner_uptime_seconds'] == 1000.0 and cases['calm'] == [] and calm_timed == []
          and 'restarted' in cases['late_restart'][0]
          and all(len(v) >= 1 for k, v in cases.items() if k != 'calm')
          and 'restarted' in cases['miner_restart'][0] and 'disabled' in cases['disabled'][0])
    return ok, json.dumps({k: len(v) for k, v in cases.items()})


# ───────────────────────────── IK28 ─────────────────────────────
def ik28(base, tmp):
    """r21 merge (F7): install refuses a staged binary that is not a clean build of HEAD (the live r20 binaries were
    built from a dirty e1bae2c tree while HEAD was 3ed6e8f)."""
    F = load(base, 'fbv')
    head = '3ed6e8f0123456789abcdef0123456789abcdef0'
    vm = lambda rev, mod: f'bin/derod: go1.26.6\n\tpath\tgithub.com/x/derod\n\tbuild\tvcs=git\n\tbuild\tvcs.revision={rev}\n\tbuild\tvcs.modified={mod}\n'
    r = {'clean': F.build_provenance(vm(head, 'false'), head),
         'dirty': F.build_provenance(vm(head, 'true'), head),
         'r20_live': F.build_provenance(vm('e1bae2c91ab909605fc3a773c227ff24727cc389', 'true'), head),
         'other_rev': F.build_provenance(vm('e1bae2c91ab909605fc3a773c227ff24727cc389', 'false'), head),
         'no_vcs': F.build_provenance('bin/derod: go1.26.6\n\tbuild\tCGO_ENABLED=1\n', head),
         # R21: the pipeline's own evidence files may be dirty at build time; a source file may not
         'pipeline_out': F.build_provenance(vm(head, 'true'), head, F.porcelain_paths(
             ' M harness/loop/PIPELINE_LAST.json\n?? harness/runtime/gomut_x.json\n')),
         'src_dirty': F.build_provenance(vm(head, 'true'), head, F.porcelain_paths(
             ' M harness/loop/PIPELINE_LAST.json\n M cmd/dero-miner/miner.go\n'))}
    ok = r['clean'] == (True, None) and r['pipeline_out'] == (True, None) \
        and not any(r[k][0] for k in ('dirty', 'r20_live', 'other_rev', 'no_vcs', 'src_dirty')) \
        and 'commit first' in r['dirty'][1] and 'HEAD is' in r['other_rev'][1]
    return ok, json.dumps({k: v[0] for k, v in r.items()})


# ───────────────────────────── IK29 (r30 B258) ─────────────────────────────
def ik29(base, tmp):
    """r30 B258: with no live split before the command (no /metrics, no live-miner process: the quiet window) the
    disturbance check is N/A and the command's own exit code is returned, never 99; an unreadable process table, a
    miner process with a silent endpoint, a split appearing during the command, or a live split that went away still
    count as disturbed. End to end: `gpu_watch run -- <cmd exiting 0>` with the endpoint down returns 0 and prints
    live_split: absent (the fixture's endpoint is an unused port, the process table is the KAT's own)."""
    W = load(base, 'gpu_watch')
    a = W.parse('dero_miner_uptime_seconds 1000\ndero_miner_split_hashed_total 100\n')
    pure = {'absent': (W.split_absent(None, []), W.disturbed(None, None, absent=True)),
            'ps_unreadable': (W.split_absent(None, None), W.disturbed(None, None, absent=False)),
            'proc_running': (W.split_absent(None, ['dero-miner']), W.disturbed(None, None, absent=False)),
            'appeared': W.disturbed(None, a, absent=True), 'went_away': W.disturbed(a, None)}
    ok_pure = (pure['absent'] == (True, []) and pure['ps_unreadable'][0] is False and pure['ps_unreadable'][1]
               and pure['proc_running'][0] is False and pure['proc_running'][1] and pure['appeared']
               and 'appeared' in pure['appeared'][0] and pure['went_away'])
    W.snap = lambda *a, **k: None          # hermetic (r30 run 5): snap's default URL is bound at def time, so a LIVE
    W.live_procs = lambda: []              # miner answered and the case read the real split instead of an absent one
    import contextlib, io
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        rc0 = W.main(['run', '--settle', '0', '--', sys.executable, '-c', 'raise SystemExit(0)'])
        rc3 = W.main(['run', '--settle', '0', '--', sys.executable, '-c', 'raise SystemExit(3)'])
    W.live_procs = lambda: ['dero-miner']
    with contextlib.redirect_stderr(io.StringIO()):
        rc99 = W.main(['run', '--settle', '0', '--', sys.executable, '-c', 'raise SystemExit(0)'])
    ok = ok_pure and rc0 == 0 and rc3 == 3 and rc99 == 99 and 'live_split: absent' in err.getvalue()
    return ok, json.dumps({'pure': {k: str(v)[:60] for k, v in pure.items()}, 'rc': [rc0, rc3, rc99]})


KATS = [('IK21', ik21), ('IK22', ik22), ('IK23', ik23), ('IK24', ik24), ('IK25', ik25), ('IK26', ik26), ('IK27', ik27), ('IK28', ik28),
        ('IK29', ik29)]

# (kat, module, find, replace, why) — each must flip its KAT to FAIL on a temp copy
MUTATIONS = [
    ('IK24', 'fbv', "    key = next((k for k in JUDGED if Path(str(step).split()[0]).stem == k), None)",
     "    key = next((k for k in JUDGED if k in step), None)", 'a KAT file named after an intel step is judged as that step (r24 integration)'),
    ('IK21', 'miner_intel', "    for a, b in zip(S, S[1:]):\n        dt = ts(b['T']) - ts(a['T'])\n        if dt <= 0:",
     "    for a, b in zip(S, S):\n        dt = 60.0\n        if dt <= 0:", 'the start-up window (unknown length) is counted'),
    ('IK21', 'miner_intel', "sum(w['backlog_ms'] for w in bl) / (TB * 1000)", "sum(w['backlog_ms'] for w in bl) / (T * 1000) * 0 + 0.1",
     'the backlog fraction is not measured'),
    ('IK21', 'miner_intel', "    if backlog_fraction is not None and backlog_fraction >= REGIME_CPU_BACKLOG:",
     "    if backlog_fraction is not None and backlog_fraction >= 0.9:", 'a 0.67 CPU-sort backlog is not CPU-bound'),
    ('IK21', 'miner_intel', "idle_per_min / max(int(threads or 20), 1) >= REGIME_GPU_IDLE_PER_THREAD_MIN",
     "idle_per_min >= 1e9", 'a GPU-bound run is never called GPU-bound'),
    ('IK21', 'miner_intel', "    if (current and now is not None and p.get('gpu_mode') == 'split' and not sp.get('lines')",
     "    if (False and current and now is not None and p.get('gpu_mode') == 'split' and not sp.get('lines')",
     'a split run that never logs a split line stays silent'),
    ('IK21', 'miner_intel', "            and now - ts(p['start']) > SPLIT_SILENT_S):", "            and now - ts(p['start']) > -1):",
     'a split run is called silent before its first 60 s report'),
    ('IK21', 'miner_intel', "    report['facts'] += [f for f in (regime_fact(p) for p in report['runs']) if f]\n", "",
     'the regime is not written as an anchorable fact'),
    ('IK22', 'metrics_intel', "'cpu_backlog_fraction': None if backlog is None else round(backlog, 3),",
     "'cpu_backlog_fraction': None if backlog is None else round(backlog * 1000, 3),", 'seconds are read as milliseconds'),
    ('IK22', 'metrics_intel', "'stale_fraction': round(dd / (dd + dh), 4) if (dd + dh) > 0 else None,",
     "'stale_fraction': round(dd / dh, 4) if dh > 0 else None,", 'the stale fraction loses the dropped from its denominator'),
    ('IK22', 'metrics_intel', "'regime': MI.classify_regime(None if backlog is None else round(backlog, 3), idle_min, threads)}",
     "'regime': 'balanced'}", 'the dashboard labels the regime without the shared classifier'),
    ('IK22', 'metrics_intel', "if rg.get('stale_fraction') is not None and rg['stale_fraction'] > STALE_WARN:",
     "if rg.get('stale_fraction') is not None and rg['stale_fraction'] > 2:", 'a 10 % stale split is not warned'),
    ('IK23', 'fbv', "        same = len(si) == 1 and si == ii and None not in si\n", "        same = True\n",
     'a ratio across two different sorters is accepted (the r20 x1.654)'),
    ('IK23', 'fbv', "    return u[len('descriptor sort, '):].split(' (')[0] if u.startswith('descriptor sort, ') else 'Go'",
     "    return 'native C'", 'every build is assumed to use the native sorter'),
    ('IK23', 'fbv', "    if not locked:\n", "    if False:\n", 'an unlocked bench passes S4b'),
    ('IK23', 'fbv', "    if 'skip' in split:\n        # the staged", "    if False:\n        # the staged",
     'a staged split-bench skip is waved through'),
    ('IK23', 'fbv', "    elif lfl.get('ratio') is not None and lfl['ratio'] < 0.93 and not contended:", "    elif lfl.get('ratio') is not None and lfl['ratio'] < 0.5 and not contended:",
     'an 11 % like-for-like regression passes'),
    ('IK23', 'fbv', "    if any(s == 'None' for v in pm.values() for s in (v.get('staged_sort') or [])):",
     "    if False:", 'r21 merge: a staged build whose sorter is unknown passes S4b with no comparison'),
    ('IK23', 'fbv', "    elif lfl.get('ratio') is None and any(s != 'None' for v in pm.values() for s in (v.get('installed_sort') or [])):",
     "    elif False:", 'r21 merge: no like-for-like mode waves a regression through'),
    ('IK27', 'gpu_watch', "    elif elapsed is not None and b.get('dero_miner_uptime_seconds', 0) < a.get('dero_miner_uptime_seconds', 0) + elapsed - RESTART_SLACK_S:",
     "    elif False:", 'r21 merge: a restart during a command longer than the old uptime is not seen'),
    ('IK28', 'fbv', "    if mod.group(1) != 'false' and not (dirty_paths is not None and", "    if False and not (dirty_paths is not None and",
     'r21 merge: a binary built from a dirty tree is installed'),
    ('IK28', 'fbv', "all(p.startswith(PIPELINE_OUTPUT_PREFIXES) for p in dirty_paths)", "any(p.startswith(PIPELINE_OUTPUT_PREFIXES) for p in dirty_paths)",
     'R21: a dirty source file is excused because a pipeline output file is dirty too'),
    ('IK28', 'fbv', "    if not head or not rev.group(1).startswith(head) and not head.startswith(rev.group(1)):",
     "    if False:", 'r21 merge: a binary built from another commit is installed'),
    ('IK24', 'fbv', "    if age_h is None or age_h > LIVE_SPLIT_MAX_AGE_H:", "    if age_h is None:",
     'a 4-hour-old snapshot is reported LIVE'),
    ('IK24', 'fbv', "    if not sp.get('lines') or sp.get('staged_mean') is None:", "    if False:",
     'a run without split windows is reported LIVE with null numbers (the r20 record)'),
    ('IK24', 'fbv', "    if pat and not (set(after) - set(before)):", "    if False:",
     'a step that wrote no new snapshot passes (the gates judge an old one)'),
    ('IK24', 'fbv', "    if rc not in codes:", "    if rc not in codes + (1, 2):", 'a crashed intel step passes'),
    ('IK25', 'ledger', "        if k not in by or MI.ts(r['end']) > MI.ts(by[k]['end']):", "        if True:",
     'a shorter observation replaces the longer one'),
    ('IK25', 'ledger', "        if live and o and 'error' not in o:\n            live[-1]['derod_outcome']",
     "        if live and o and 'error' not in o:\n            live[0]['derod_outcome']", 'derod\'s outcome is pinned on an old run'),
    ('IK25', 'ledger', "            continue\n        out.append(r)", "            pass\n        out.append(r)",
     'a covered head_missing fragment stays in the ledger'),
    ('IK25', 'ledger', "round(paid / (paid + orph), 4)", "round(paid / (paid + orph + 1), 4)", 'the paid fraction is mis-computed'),
    ('IK25', 'ledger', "            keep = dict(r)\n            if k in by and by[k].get('derod_outcome')",
     "            keep = dict(r)\n            if False and k in by and by[k].get('derod_outcome')", 'a later observation drops derod\'s outcome'),
    ('IK26', 'gates', "                and rg.get('cpu_backlog_fraction') is None)", "                and False)",
     'G17 passes this tree\'s split build without its backlog counter'),
    ('IK26', 'gates', "    return not (sp.get('lines') and cur.get('version') and cur.get('version') == tree_ver and rg.get('windows')",
     "    return not (sp.get('lines') and rg.get('windows')", 'G17 fails older builds that never had the counter'),
    ('IK26', 'gates', "                and (rg.get('cpu_backlog_fraction') is None or rg.get('idle_tries_per_min') is None))",
     "                and rg.get('idle_tries_per_min') is None)", 'G18 passes a dashboard without the backlog counter'),
    ('IK27', 'gpu_watch', "    if b.get('dero_miner_uptime_seconds', 0) < a.get('dero_miner_uptime_seconds', 0):", "    if False:",
     'a miner restart (counters back at 0) is not seen — benchlock --gpu\'s blind spot'),
    ('IK27', 'gpu_watch', "    if b.get('dero_miner_split_disabled', 0) > 0:", "    if False:",
     'split turning itself off is not seen — benchlock --gpu\'s other blind spot'),
    ('IK27', 'gpu_watch', "        return ['the miner /metrics stopped answering']", "        return []", 'a silent endpoint passes'),
    ('IK27', 'gpu_watch', "            and not why:\n        why.append('the GPU split hashed nothing", "            and False:\n        why.append('the GPU split hashed nothing",
     'a stalled split passes'),
    # r30 B258 (IK29)
    ('IK29', 'gpu_watch', "        if absent and b is None:                       # r30 B258: no live split before or after: nothing to disturb\n            return []",
     "        if False:\n            return []", 'B258: an absent live split (quiet window) reads as disturbed: exit 99'),
    ('IK29', 'gpu_watch', "    return a is None and procs is not None and not procs", "    return a is None",
     'B258: an unreadable process table or a running miner process counts as an absent split'),
    ('IK29', 'gpu_watch', "        if b is not None:\n            return ['a live split appeared during the command (no reading before it)']",
     "        if False:\n            return ['a live split appeared during the command (no reading before it)']",
     'B258: a split that appears during the command passes'),
    ('IK29', 'gpu_watch', "    if absent and not why:\n        print(", "    if False:\n        print(",
     'B258: the absent case falls through without the live_split marker'),
]


def copy_tree():
    d = Path(tempfile.mkdtemp(prefix='r21kat-'))
    for rel in list(MODS.values()) + EXTRA:
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HARNESS / rel, d / rel)
    for rel in EXTRA_DIRS:
        shutil.copytree(HARNESS / rel, d / rel, ignore=shutil.ignore_patterns('__pycache__', '.cache'))
    return d


def main():
    tmp = Path(tempfile.mkdtemp(prefix='r21fx-'))
    fails = 0
    base = copy_tree()                     # even the unmutated KATs run on a copy: nothing here imports the real harness
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
        try:
            ok2 = byname[kat](d, tmp)[0]
        except Exception:                                          # noqa: BLE001 — a crash is a detection
            ok2 = False
        print(f"  {'proved ' if not ok2 else 'MISSED '} {kat}: {why}")
        missed += ok2
        shutil.rmtree(d, ignore_errors=True)
    shutil.rmtree(tmp, ignore_errors=True)
    print(f'\nR21 harness KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
