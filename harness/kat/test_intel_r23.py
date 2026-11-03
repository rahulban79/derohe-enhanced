#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the R23 harness layer (no network, no live file written, no real ps).

  IK39 contention census: safe_name keeps the executable's basename only (no directory, no home path, no args);
       parse_ps reads macOS ps lines whose names hold spaces ('Helper (Renderer)'); seconds() reads mm:ss.cc with
       minutes past 60 and dd-hh:mm:ss; census() turns CPU-time deltas into cores per NAME (a pid born in the window
       counts all its CPU, a reused pid none); verdict() is contended when foreign cores exceed the headroom left by
       the --cpu-max budget and derod (+1 core slack); the law reproduces the r22 13-core reading (70.6k)
  IK40 metrics_intel: the census runs beside the two GETs; a contended box warns box_contended, refuses regression
       claims and NAMES the processes in cpu_starved; a starved miner on a quiet box is cpu_starved_unattributed; the
       --cpu-max budget comes from /metrics dero_miner_cpu_duty_percent (before R23: only the checkpoint, so from a
       clone cpu_starved could never fire); no ps = no census (contended None)
  IK41 miner_intel: on a contended box the current run's sag is cpu_starved (attributed), never hashrate_sag
  IK42 run_gates G20: no census FAILS; a contended census the snapshot does not act on FAILS; hashrate_sag next to a
       contended census FAILS; a contended A/B that PASSED, or FAILED on a ratio, FAILS; REFUSED and pre-R23 records pass
  IK43 miner_runs payout ledger: the reward schedule DERIVED from the declaring Go lines (123000, 7000000, 10 minis);
       3075 atomic per miniblock at 7,830,715; exact Garwood intervals (k=0: [0, 3.69]; k=10: [4.80, 18.39]); the
       verdict; the long-term ledger never lets a worse paid source replace a better one; G21 recomputes paid DERO and
       the verdict and fails a tampered snapshot or a failed L-check
  IK44 miner_runs L3/L9: the r22 writer bug (hashes 0 AND height 0 from +22102026.r22) is KNOWN; the same zeros from
       any other build fail L3 and L9; (r23c) L3 allows uptime_s's rounding (a 12 s run passes, a wrong average fails)
  IK45 fix_build_verify contention: judge_minerbench under contention judges no ratio but still the correctness
       checks; ab_contention counts an unknown census as contended; judge_gpubench self-A/B (unchanged source) PASSES
       inside [0.93, 1/0.93], FAILS outside, is REFUSED under contention and still FAILS a non-bit-exact server;
       judged_step requires miner_runs to write a new snapshot
  IK46 (merge) a failed or empty ps is no census, never an idle box: census() of an empty sample is None, measure()
       with an empty ps gives contended None, ab_contention counts it as contended and judge_gpubench REFUSES (never
       PASSES) a changed server's A/B; ps_text raises on a non-zero exit

  python3 -I harness/kat/test_intel_r23.py            # KATs, then each mutation on a temp copy must flip its KAT
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught.
"""
import importlib.util, json, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
MODS = {'ct': 'intel/contention.py', 'miner_intel': 'intel/miner_intel.py', 'metrics_intel': 'intel/metrics_intel.py',
        'fbv': 'pipeline/fix_build_verify.py', 'gates': 'run_gates.py', 'runs': 'intel/miner_runs.py'}
EXTRA = ['gen_deroarch.py', 'prep_corpus.py', 'consensus_guard.py', 'miners/minelib.py']   # imported by run_gates
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


HELPER = '/Applications/DesktopApp.app/Contents/Frameworks/Helper Framework.framework/Helpers/Helper (Renderer).app/Contents/MacOS/Helper (Renderer)'


def ps_lines(rows):
    """rows: (pid, nice, time, etime, comm) -> macOS `ps -o pid=,nice=,time=,etime=,comm=` text"""
    return '\n'.join(f'{p:>5} {n:>2} {t:>10} {e:>11} {c}' for p, n, t, e, c in rows) + '\n'


def box(miner_t, helper_t, extra=()):
    """a process table: the miner, derod, three foreign renderers and anything in `extra`"""
    return ps_lines([(24287, 0, miner_t, '15:26', './bin/dero-miner'), (30565, 0, '10:00.00', '05:50:00', '/Users/someone/derohe/bin/derod'),
                     (86808, 0, helper_t[0], '07:42:49', HELPER), (306, 0, helper_t[1], '01:37:33', HELPER),
                     (32077, 0, helper_t[2], '05:37:22', HELPER), *extra])


# ───────────────────────────── IK39 ─────────────────────────────
def ik39(base, tmp):
    CT = load(base, 'ct')
    home_bin = CT.HOME + '/secret-project/bin/tool'
    names = {'abs': CT.safe_name(HELPER), 'home': CT.safe_name(home_bin), 'rel': CT.safe_name('./bin/dero-miner'),
             'paren': CT.safe_name('(compile)')}
    secs = (CT.seconds('172:56.40'), CT.seconds('2311:44.51'), CT.seconds('09-00:19:00'), CT.seconds('00:05'))
    # 10 s apart: miner +100 s CPU (10 cores), each renderer +10 s (1 core), a grep born inside the window +3 s, a pid
    # whose name changed (reused) must not count
    t0 = box('100:00.00', ('10:00.00', '20:00.00', '30:00.00'), [(500, 0, '5:00.00', '01:00:00', '/usr/bin/python3')])
    t1 = box('101:40.00', ('10:10.00', '20:10.00', '30:10.00'),
             [(500, 0, '9:00.00', '01:00:10', '/usr/bin/otherthing'), (777, 15, '0:03.00', '00:04', '/usr/bin/grep')])
    c = CT.census((0.0, CT.parse_ps(t0)), (10.0, CT.parse_ps(t1)))
    v = CT.verdict(c, ncpu=20, threads=20, cpu_max=90, load1=41.0)
    q = CT.verdict(CT.census((0.0, CT.parse_ps(t0)), (10.0, CT.parse_ps(box('101:40.00', ('10:00.10', '20:00.10', '30:00.10'))))),
                   ncpu=20, threads=20, cpu_max=90)
    fact = CT.fact(v)
    blob = json.dumps(c) + fact
    ok = (names == {'abs': 'Helper (Renderer)', 'home': 'tool', 'rel': 'dero-miner', 'paren': '(compile)'}
          and secs == (10376.4, 138704.51, 778740.0, 5.0)
          and c['cores'] == {'miner': 10.0, 'node': 0.0, 'foreign': 3.3} and c['foreign_procs'] == 4
          and c['top_foreign'][0]['name'] == 'Helper (Renderer)' and c['top_foreign'][0]['procs'] == 3
          and c['top_foreign'][0]['cores'] == 3.0 and not any(g['name'] == 'otherthing' for g in c['top_foreign'])
          and v['contended'] is True and v['headroom_cores'] == 2.0 and v['budget_fraction'] == round(10 / 18, 3)
          and v['law_loss_hs'] == round(4817 * 8) and v['law_hs_at_budget'] == 94706 and v['regression_claims'] == 'refused'
          and CT.law_hs(13.0) == 70621
          and q['contended'] is False and q['regression_claims'] == 'allowed'
          and CT.verdict(None)['contended'] is None
          and '/' not in blob.replace('Helper (Renderer)', '') and 'someone' not in blob and '24287' not in blob)
    return ok, f'names {names} secs {secs} census {c["cores"]} verdict {v["contended"]}/{q["contended"]} fact {fact[:120]}'


# ───────────────────────────── IK40 ─────────────────────────────
def mtext(hashes, hashed, busy, backlog, ring, cpu, duty=True):
    return '\n'.join([
        'dero_miner_info{version="v-r22"} 1', 'dero_miner_uptime_seconds 100', 'dero_miner_threads 20', 'dero_miner_connected 1',
        f'dero_miner_hashes_total {hashes}', 'dero_miner_hashrate_15s 60000', 'dero_miner_height 100',
        'dero_miner_network_hashrate_estimate 2400000', f'dero_miner_split_hashed_total {hashed}', 'dero_miner_split_dropped_total 0',
        'dero_miner_split_disabled 0', f'dero_miner_split_gpu_busy_seconds_total {busy}',
        f'dero_miner_split_feeder_cpu_backlog_seconds_total {backlog}', f'dero_miner_split_feeder_ring_full_seconds_total {ring}',
        'dero_miner_split_cpu_idle_tries_total 1000', f'process_cpu_seconds_total {cpu}', 'dero_miner_gpu_mismatch_total 0']
        + (['dero_miner_cpu_duty_percent 90'] if duty else []) + [''])


def ik40(base, tmp):
    MT = load(base, 'metrics_intel')

    def snap(contended, duty=True, ps=True, cpu_max=None):
        texts = iter([mtext(1_000_000, 990_000, 100.0, 100.0, 100.0, 1000.0, duty),
                      mtext(1_600_000, 1_590_000, 106.7, 109.0, 110.0, 1110.0, duty)])     # 10 s: 11 cores, backlog 0.9
        clock = iter([0.0, 10.0])
        pss = iter([box('100:00.00', ('10:00.00', '20:00.00', '30:00.00')),
                    box('101:50.00', ('10:20.00', '20:20.00', '30:20.00') if contended else ('10:00.05', '20:00.05', '30:00.05'))])
        return MT.snapshot('d', 'm', 10.0, get=lambda u: next(texts) if u == 'm' else (_ for _ in ()).throw(OSError('down')),
                           sleep=lambda s: None, clock=lambda: next(clock), cpu_max=cpu_max,
                           ps=(lambda: next(pss)) if ps else None, ncpu=20, load1=40.0)
    c, q, nod, nops = snap(True), snap(False), snap(True, duty=False), snap(True, ps=False)
    rc = {a['rule']: a['what'] for a in c['alerts']}
    rq = {a['rule'] for a in q['alerts']}
    ok = (c['contention']['contended'] is True and 'box_contended' in rc and 'cpu_starved' in rc
          and 'Helper (Renderer) x3' in rc['cpu_starved'] and c['contention']['regression_claims'] == 'refused'
          and c['contention']['miner_cores'] == 11.0 and c['contention']['miner_cores_metrics'] == 11.0
          and c['cpu_max_source'] == 'metrics' and c['miner']['split_binding']['cpu_budget_fraction'] == round(11 / 18, 3)
          and any(f.startswith('live contention contended=True ') for f in c['facts'])
          and q['contention']['contended'] is False and 'cpu_starved_unattributed' in rq and 'box_contended' not in rq
          and nod['cpu_max_source'] is None and nod['miner']['split_binding']['cpu_budget_fraction'] is None
          and nops['contention']['contended'] is None and not any(f.startswith('live contention') for f in nops['facts']))
    return ok, f"contended rules {sorted(rc)} quiet {sorted(rq)} src {c['cpu_max_source']}/{nod['cpu_max_source']}"


# ───────────────────────────── IK41 ─────────────────────────────
def ik41(base, tmp):
    MI = load(base, 'miner_intel')
    p = {'split': {}, 'reward': {}, 'hashrate': {'samples': 40, 'mean': 80000.0, 'tail10_mean': 55000.0}, 'start': '2026-10-30T01:29:50',
         'end': '2026-10-30T01:50:00', 'version': 'v'}
    con = {'contended': True, 'why': 'foreign 7.2 cores', 'law_hs_at_miner_cores': 55303, 'miner_cores': 9.82}
    a = {k for k, _, _ in MI.rules(p, True, None, None, con)}
    b = {k for k, _, _ in MI.rules(p, True, None, None, {'contended': False})}
    c = {k for k, _, _ in MI.rules(p, False, None, None, con)}          # an ended run: today's census says nothing about it
    ok = 'cpu_starved' in a and 'hashrate_sag' not in a and 'hashrate_sag' in b and 'hashrate_sag' in c and 'cpu_starved' in MI.RULES
    return ok, f'contended {a} quiet {b} ended {c}'


# ───────────────────────────── IK42 ─────────────────────────────
def ik42(base, tmp):
    G = load(base, 'gates')
    cont = {'contended': True, 'why': 'foreign 7', 'regression_claims': 'refused', 'foreign_cores': 7.2}
    good_mt = {'contention': cont, 'alerts': [{'rule': 'box_contended', 'level': 'WARN'}]}
    quiet_mt = {'contention': {'contended': False, 'regression_claims': 'allowed'}, 'alerts': []}
    mi_sag = {'contention': cont, 'runs': [{'alerts': [{'rule': 'hashrate_sag'}]}]}
    pipe = lambda st, c, cf=False: {'stages': {'minerbench': {'status': st, 'contention': c, 'correctness_fail': cf}}}
    v = {'no_census': G.g20_contention({'alerts': []})[0], 'good': G.g20_contention(good_mt)[0], 'quiet': G.g20_contention(quiet_mt)[0],
         'silent': G.g20_contention({'contention': cont, 'alerts': []})[0],
         'sag': G.g20_contention(good_mt, mi_sag)[0],
         'pass_cont': G.g20_contention(good_mt, None, pipe('PASS', cont))[0],
         'ratio_fail_cont': G.g20_contention(good_mt, None, pipe('FAIL', cont))[0],
         'correct_fail_cont': G.g20_contention(good_mt, None, pipe('FAIL', cont, True))[0],
         'refused': G.g20_contention(good_mt, None, pipe('REFUSED', cont))[0],
         'pass_quiet': G.g20_contention(good_mt, None, pipe('PASS', {'contended': False}))[0],
         'pre_r23': G.g20_contention(good_mt, None, {'stages': {'minerbench': {'status': 'PASS'}}})[0]}
    want = {'no_census': False, 'good': True, 'quiet': True, 'silent': False, 'sag': False, 'pass_cont': False,
            'ratio_fail_cont': False, 'correct_fail_cont': True, 'refused': True, 'pass_quiet': True, 'pre_r23': True}
    return v == want, json.dumps(v)


# ───────────────────────────── IK43 ─────────────────────────────
def fake_root(tmp):
    r = tmp / 'root'
    (r / 'config').mkdir(parents=True, exist_ok=True)
    (r / 'blockchain').mkdir(parents=True, exist_ok=True)
    (r / 'config/config.go').write_text('package config\n\nconst BLOCK_TIME = uint64(18)\nconst MINIBLOCK_HIGHDIFF = 9\n')
    (r / 'blockchain/transaction_execute.go').write_text(
        'package blockchain\n\nconst RewardReductionInterval = 210000 * 600 / config.BLOCK_TIME // 210000 comes from bitcoin\n'
        'const BaseReward = (41 * 100000 * config.BLOCK_TIME) / 600       // convert bitcoin reward system to our block\n\n'
        'func CalcBlockReward(height uint64) uint64 {\n\treturn BaseReward >> ((height + RewardReductionInterval) / RewardReductionInterval)\n}\n')
    return r


def ik43(base, tmp):
    R = load(base, 'runs')
    G = load(base, 'gates')
    consts = R.reward_constants(fake_root(tmp))
    pm = R.per_miniblock_atomic(7830715, consts)
    ci0, ci10 = R.poisson_ci(0), R.poisson_ci(10)
    rows = [{'run_id': 'a', 'start': '2026-10-29T06:25:17-07:00', 'end': 'console exit', 'expected_shares': 399.05,
             'found_gpu': 373, 'paid_gpu': 358},
            {'run_id': 'b', 'start': '2026-10-30T00:00:00-07:00', 'end': 'console exit', 'expected_shares': 40.0, 'found_gpu': 20,
             'paid_gpu': 20},
            {'run_id': 'c', 'start': '2026-10-30T01:00:00-07:00', 'end': 'running', 'expected_shares': 10.0, 'found_gpu': 9,
             'paid_gpu': 1}]
    cj = [{'run_id': 'a', 'found': 373, 'paid_chain': 362, 'finals_verifiable': True}]
    dj = [{'run_id': 'c', 'covered': True, 'partial': False, 'paid': 8}]
    pr, pt = R.payout(rows, dj, cj, consts, 7830715)
    by = {x['run_id']: x for x in pr}
    led = tmp / 'payout_ledger.jsonl'
    R.merge_payout_ledger(led, pr, 't1')
    worse = [{**by['a'], 'paid': 1, 'paid_source': 'ledger'}]
    merged = {x['run_id']: x for x in R.merge_payout_ledger(led, worse, 't2')}
    snap = {'validation': [{'start': rows[0]['start'], 'checks': {'L1 identity': [True, '']}}], 'ledger_checks': {'L7 order': {'ok': True}},
            'payout': {'runs': pr, 'total': pt}}
    # R23b: G21 also needs the idle-gap ledger (the rows above carry no uptime: every gap is the whole interval)
    ig, it = R.idle_gaps(rows, R.ts('2026-10-30T01:00:00-07:00') + 60, pm, 0.97, [])
    snap['idle'] = {'gaps': ig, 'total': it}
    g_ok = G.g21_payout(snap)[0]
    tam = json.loads(json.dumps(snap))
    tam['payout']['total']['paid_DERO'] = 99.0
    tv = json.loads(json.dumps(snap))
    tv['payout']['total']['verdict'] = 'luck (expected inside the 95 % interval)'   # the true total is 'below'
    tl = json.loads(json.dumps(snap))
    tl['validation'][0]['checks']['L3 average'] = [False, 'x']
    ok = (consts[:3] == (123000, 7000000, 10) and pm == 3075 and R.per_miniblock_atomic(13_999_999, consts) == 3075
          and R.per_miniblock_atomic(14_000_000, consts) == 1537 and R.per_miniblock_atomic(6_999_999, consts) == 6150
          and ci0 == (0.0, 3.69) and ci10 == (4.8, 18.39)
          and by['a']['paid'] == 362 and by['a']['paid_source'] == 'chain' and by['a']['verdict'].startswith('luck')
          and by['b']['verdict'].startswith('below') and by['b']['paid_DERO'] == round(20 * 3075 / 1e5, 5)
          and by['c']['paid'] == 8 and by['c']['paid_source'] == 'derod'
          and pt['paid'] == 390 and pt['verdict'].startswith('below') and pt['paid_DERO'] == round(390 * 3075 / 1e5, 5)
          and merged['a']['paid'] == 362 and merged['a']['updated'] == 't1'
          and g_ok and not G.g21_payout(tam)[0] and not G.g21_payout(tv)[0] and not G.g21_payout(tl)[0]
          and not G.g21_payout({'validation': [], 'ledger_checks': {}})[0] and not G.g21_payout(None)[0])
    return ok, f'consts {consts[:3]} pm {pm} ci {ci0} {ci10} verdicts {[x["verdict"][:5] for x in pr]} total {pt["paid"]} g21 {g_ok}'


# ───────────────────────────── IK44 ─────────────────────────────
def ik44(base, tmp):
    R = load(base, 'runs')
    row = {'kind': 'run', 'run_id': '18e33990aff0d438', 'version': '3.6.0-153.DEROHE.STARGATE+22102026.r22',
           'start': '2026-10-29T23:06:10-07:00', 'last': '2026-10-29T23:44:49-07:00', 'end': 'console exit', 'uptime_s': 2319,
           'hashes': 0, 'avg_hs': 75340, 'height': 0, 'accepted_blocks': 2, 'accepted_miniblocks': 30}
    ev = {'starts': [], 'exits': [], 'found': []}
    k = R.validate([row], ev, 0)[0][0]['checks']
    o = R.validate([{**row, 'version': '3.6.0-153.DEROHE.STARGATE+22102026.r23'}], ev, 0)[0][0]['checks']
    g = R.validate([{**row, 'version': '3.6.0-153.DEROHE.STARGATE+22102026.r23', 'hashes': 2319 * 75340, 'height': 7830000}],
                   ev, 0)[0][0]['checks']
    # r23c: the live 12 s run (uptime_s rounded from ~12.25 s, avg_hs over the exact uptime) passes L3; a wrong avg fails
    sh = {**row, 'version': '3.6.0-153.DEROHE.STARGATE+22102026.r23c', 'start': '2026-11-01T22:37:24-08:00',
          'last': '2026-11-01T22:37:37-08:00', 'uptime_s': 12, 'hashes': 416148, 'avg_hs': 33966, 'height': 7843365,
          'accepted_blocks': 0, 'accepted_miniblocks': 0}
    s_ok = R.validate([sh], ev, 0)[0][0]['checks']['L3 average'][0]
    s_bad = R.validate([{**sh, 'avg_hs': 31000}], ev, 0)[0][0]['checks']['L3 average'][0]
    ok = (k['L3 average'][0] and k['L9 height'][0] and 'KNOWN' in k['L3 average'][1]
          and not o['L3 average'][0] and not o['L9 height'][0] and g['L3 average'][0] and g['L9 height'][0]
          and s_ok and not s_bad)
    return ok, f'r22 {k["L3 average"]} other {o["L3 average"][0]}/{o["L9 height"][0]} short-run {s_ok}/{s_bad}'


# ───────────────────────────── IK45 ─────────────────────────────
def ik45(base, tmp):
    F = load(base, 'fbv')
    res = {'descriptor': [3100, 3120, 3110], 'sais': [790, 800, 795]}
    lfl = lambda s, i: {'ratio': round(s / i, 3), 'mode': 'auto', 'impl': 'native C',
                        'per_mode': {'auto': {'staged': s, 'installed': i, 'staged_sort': ['native C'], 'installed_sort': ['native C']}}}
    split = {'h_per_cpu_s': 3400, 'declined': 0, 'sort': 'native C'}
    reg = F.judge_minerbench(res, lfl(2700, 3100), split, 3100, locked=True)
    reg_c = F.judge_minerbench(res, lfl(2700, 3100), split, 3100, locked=True, contended=True)
    unl_c = F.judge_minerbench(res, lfl(3100, 3100), split, 3100, locked=False, contended=True)
    nos_c = F.judge_minerbench(res, lfl(3100, 3100), {'skip': 'off'}, 3100, locked=True, contended=True)
    q = {'contended': False, 'why': 'quiet'}
    cc = {'contended': True, 'why': 'foreign 7'}
    abq, abc, abu, abn = F.ab_contention(q, q), F.ab_contention(q, cc), F.ab_contention(q, {'contended': None, 'why': 'ps failed'}), \
        F.ab_contention(None, None)
    same = {'changed': False, 'why': 'same'}
    ab = lambda st, ins, bit=True: {'staged': st, 'installed': ins, 'bitexact': bit, 'disturbed': False}
    g = {'self_skip': F.judge_gpubench(same, None)[0], 'self_ok': F.judge_gpubench(same, 'run', ab([41000] * 3, [41500] * 3))[0],
         'self_wide': F.judge_gpubench(same, 'run', ab([46000] * 3, [41000] * 3))[0],
         'self_low': F.judge_gpubench(same, 'run', ab([36000] * 3, [41000] * 3))[0],
         'self_cont': F.judge_gpubench(same, 'run', ab([30000] * 3, [41000] * 3), contended=True)[0],
         'inexact_cont': F.judge_gpubench(same, 'run', ab([41000] * 3, [41000] * 3, bit=False), contended=True)[0],
         'zero_cont': F.judge_gpubench(same, 'run', ab([0] * 3, [41000] * 3), contended=True)[0],
         'changed_cont': F.judge_gpubench({'changed': True, 'why': 'x'}, 'run', ab([30000] * 3, [41000] * 3), contended=True)[0]}
    js = F.judged_step('harness/intel/miner_runs.py', 0, [('minerruns_a.json', 1)], [('minerruns_a.json', 1)])
    js_ok = F.judged_step('harness/intel/miner_runs.py', 0, [], [('minerruns_b.json', 2)])
    ok = (not reg[0] and reg_c == (True, []) and not unl_c[0] and not nos_c[0]
          and abq['contended'] is False and abc['contended'] is True and abu['contended'] is True and abn['contended'] is True
          and g == {'self_skip': 'SKIP', 'self_ok': 'PASS', 'self_wide': 'FAIL', 'self_low': 'FAIL', 'self_cont': 'REFUSED',
                    'inexact_cont': 'FAIL', 'zero_cont': 'FAIL', 'changed_cont': 'REFUSED'}
          and js[0] is False and js_ok[0] is True)
    return ok, f'reg {reg[0]} reg_c {reg_c} gpu {g} judged {js[0]}/{js_ok[0]}'


def ik46(base, tmp):
    CT, F = load(base, 'ct'), load(base, 'fbv')
    empty = CT.census((0.0, {}), (5.0, {}))
    v = CT.measure(0.01, 20, 90, ps=lambda: '', sleep=lambda s: None)
    ab = F.ab_contention(v, v)
    good = {'staged': [41000] * 3, 'installed': [41500] * 3, 'bitexact': True, 'disturbed': False}
    g = F.judge_gpubench({'changed': True, 'why': 'x'}, 'run', good, contended=ab['contended'])[0]

    class R:
        returncode, stdout, stderr = 1, '', 'ps: denied'
    try:
        CT.ps_text(run=lambda *a, **k: R())
        raised = False
    except Exception:                                              # noqa: BLE001
        raised = True
    ok = empty is None and v['contended'] is None and v.get('regression_claims') != 'allowed' and ab['contended'] is True \
        and g == 'REFUSED' and raised
    return ok, f"census {empty} measure {v.get('contended')} ab {ab['contended']} gpu {g} ps_raises {raised}"


KATS = [('IK39', ik39), ('IK40', ik40), ('IK41', ik41), ('IK42', ik42), ('IK43', ik43), ('IK44', ik44), ('IK45', ik45),
        ('IK46', ik46)]

MUTATIONS = [
    # (kat, module, find, replace, what the mutation breaks)
    ('IK39', 'ct', "    c = c.rstrip('/').rsplit('/', 1)[-1]\n", "", 'the full executable path (a user path) reaches the snapshot'),
    ('IK39', 'ct', "    contended = foreign > headroom + CONTENDED_SLACK_CORES", "    contended = foreign > ncpu",
     'foreign load is judged against the whole box, not the headroom the miner budget leaves'),
    ('IK39', 'ct', "        elif et <= dt + 1:\n            d = cpu\n", "        elif True:\n            d = cpu\n",
     'a reused pid counts its whole lifetime of CPU as this window'),
    ('IK39', 'ct', "        s = s * 60 + p", "        s = s * 100 + p", 'ps CPU time is mis-read'),
    ('IK40', 'metrics_intel', "    if gauge:\n        cpu_max = int(gauge)\n", "",
     'the --cpu-max budget is read only from the checkpoint (cpu_starved cannot fire from a clone)'),
    ('IK40', 'metrics_intel', "    if ct.get('contended'):\n        out.append(('box_contended', 'WARN', ct.get('why')))", "    pass",
     'a contended box is not warned'),
    ('IK40', 'metrics_intel', "            if ct.get('contended') is False:", "            if False:",
     'a starved miner on a quiet box is blamed on other processes'),
    ('IK41', 'miner_intel', "        if current and (contention or {}).get('contended'):", "        if False:",
     'a sag on a contended box is still claimed as hashrate_sag'),
    ('IK42', 'gates', "        if c.get('contended') and rec.get('status') == 'PASS':", "        if False:",
     'a PASS from a contended A/B is accepted'),
    ('IK42', 'gates', "        why.append('the metrics snapshot carries no foreign-process census: contention unknown, so no claim can be judged')",
     "        pass", 'a snapshot without a census passes'),
    ('IK42', 'gates', "        if mct.get('contended') and sag:", "        if False:", 'hashrate_sag next to a contended census passes'),
    ('IK43', 'runs', "    return (base >> ((int(height) + rri) // rri)) // minis", "    return base // minis",
     'the reward halving schedule is ignored'),
    ('IK43', 'runs', "    lower = 0.0 if k == 0 else solve(lambda m: 1 - _pois_cdf(k - 1, m) < a, 0.0, hi_b)",
     "    lower = 0.0 if k == 0 else solve(lambda m: 1 - _pois_cdf(k, m) < a, 0.0, hi_b)", 'the interval lower bound is off by one'),
    ('IK43', 'runs', "        if prev and not prev.get('running') and SOURCE_RANK.get(prev.get('paid_source'), 0) > SOURCE_RANK.get(x['paid_source'], 0):",
     "        if False:", 'a worse paid source overwrites the chain-verified count'),
    ('IK43', 'gates', "    if pm is None or t.get('paid_DERO') is None or abs(t['paid'] * pm / 1e5 - t['paid_DERO']) > 1e-4:", "    if False:",
     'G21 accepts a paid DERO that its own counts do not give'),
    ('IK43', 'gates', "        if not str(t.get('verdict', '')).startswith(want):", "        if False:", 'G21 accepts a verdict its interval contradicts'),
    ('IK44', 'runs', "    return (str(r.get('version', '')).endswith(KNOWN_ZERO_HASHES_VERSION) and not r.get('hashes') and not r.get('height')",
     "    return (not r.get('hashes') and not r.get('height')", 'zeros from ANY build are waved through as the known r22 bug'),
    ('IK44', 'runs', "            lo_hs, hi_hs = hs / (up + 0.5), (hs / (up - 0.5) if up > 0.5 else float('inf'))",
     "            lo_hs, hi_hs = want, want", 'L3 ignores that uptime_s is rounded (a 12 s run fails on rounding alone)'),
    ('IK44', 'runs', "            c['L9 height'] = (int(r.get('height') or 0) > 0 or known,", "            c['L9 height'] = (True,",
     'a run with accepted shares and height 0 passes'),
    ('IK45', 'fbv', "    elif lfl.get('ratio') is not None and lfl['ratio'] < 0.93 and not contended:",
     "    elif lfl.get('ratio') is not None and lfl['ratio'] < 0.93:", 'a contended ratio is judged as a regression'),
    ('IK45', 'fbv', "    cont = any(c.get('contended') is not False for c in cs) or not cs",
     "    cont = any(c.get('contended') is True for c in cs)", 'an unknown census counts as quiet'),
    ('IK45', 'fbv', "    elif self_ab and st / ins > 1 / GPU_RATIO_MIN:", "    elif False:", 'a self-A/B wider than the gate passes'),
    ('IK45', 'fbv', "    if contended:\n        return 'REFUSED'", "    if False:\n        return 'REFUSED'", 'a contended GPU A/B PASSES'),
    ('IK45', 'fbv', "          'miner_runs': ((0,), 'minerruns_*.json'),", "", 'miner_runs may write no snapshot'),
    ('IK46', 'ct', "    if dt <= 0 or not a or not b:\n        return None", "    if dt <= 0:\n        return None",
     'an empty ps reads as an idle box (contended False, regression claims allowed)'),
    ('IK46', 'ct', "    if r.returncode != 0:\n", "    if False:\n", 'a failed ps is read as an empty process table'),
]


def copy_tree():
    d = Path(tempfile.mkdtemp(prefix='r23kat-'))
    for rel in list(MODS.values()) + EXTRA:
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HARNESS / rel, d / rel)
    for rel in EXTRA_DIRS:
        shutil.copytree(HARNESS / rel, d / rel, ignore=shutil.ignore_patterns('__pycache__', '.cache'))
    return d


def main():
    tmp = Path(tempfile.mkdtemp(prefix='r23fx-'))
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
        t2 = Path(tempfile.mkdtemp(prefix='r23fx-m-'))
        try:
            ok2 = byname[kat](d, t2)[0]
        except Exception:                                          # noqa: BLE001 — a crash is a detection
            ok2 = False
        print(f"  {'proved ' if not ok2 else 'MISSED '} {kat}: {why}")
        missed += ok2
        shutil.rmtree(d, ignore_errors=True)
        shutil.rmtree(t2, ignore_errors=True)
    shutil.rmtree(tmp, ignore_errors=True)
    print(f'\nR23 harness KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
