#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the R19 intel layer (no network, no live files written).

  IK1  log_intel splits runs at the start-up line by TEXT: the r17 caller (main.go:160) AND the r18 one (main.go:182)
  IK2  log_intel aggregates "Own miniblock delivered" (acks, failures by reason, latencies); own_mb_fail fires > 25 %
  IK3  log_intel.parse_metrics: absent counter = 0, blocks per GetObject, network-wait fraction, first-relay share
  IK4  datadir_intel reads retention_seconds from p2p/peer_pool.go — the real file gives (86400, 3600) and an edited
       copy is followed (the r18 check had typed r17's numbers)
  IK5  datadir_intel.first_relay_check mirrors load_first_relay_from (forget window, future stamp, bad IP, zero firsts)
  IK6  datadir_intel.v2_offences_check mirrors load_v2_offences_from; go_const/go_json_fields read the real source
  IK7  miner_intel on a synthetic two-run log: warm-up excluded mean, split drop fraction, drops per height vs ring,
       paid fraction, and the ALERT/WARN rules
  IK8  fix_build_verify S4b: parse_bench picks H/cpu-s (not wall) and judge_minerbench gates on H/cpu-s only,
       including the split CPU side (declined sorts, split <= full hash, skip recorded)
  IK9  miner_intel: a disabled descriptor sort is an ALERT (from the GPU split cpu field, or from the ERROR line
       alone), while sort fallbacks are only a WARN (verifier H3); the r19 regime counters are summed
  IK10 mine_forensics: a missing (git-excluded) forensics_in.json keeps the committed raw rows as an explicit SKIP
       instead of shrinking the page to 0 rows (verifier H7)

  python3 -I harness/kat/test_intel_r19.py            # KATs, then each mutation on a temp copy must flip its KAT
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught.
"""
import importlib.util, json, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
MODS = {'log_intel': 'intel/log_intel.py', 'datadir_intel': 'intel/datadir_intel.py', 'miner_intel': 'intel/miner_intel.py',
        'fbv': 'pipeline/fix_build_verify.py', 'forensics': 'miners/mine_forensics.py'}
EXTRA = ['miners/minelib.py']  # imported by mine_forensics.py; copied with it


def load(base, name):
    spec = importlib.util.spec_from_file_location(f'{name}_{id(base)}', base / MODS[name])
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def J(**kv):
    return json.dumps(kv)


# ───────────────────────────── fixtures ─────────────────────────────
def derod_log():
    """two runs: an r17 start (main.go:160) and an r18 start (main.go:182), each with version + args + blocks"""
    out = []
    for i, (c, ver, hh) in enumerate((('160', 'r17', '10'), ('182', 'r18', '12'))):
        cv = str(int(c) + 3)
        out.append(J(L='INFO', T=f'2026-10-24T{hh}:00:00.000-0700', N='derod', C=f'derod/main.go:{c}',
                     M='DERO HE daemon :  It is an alpha version, use it for testing/evaluations purpose only.'))
        out.append(J(L='INFO', T=f'2026-10-24T{hh}:00:00.001-0700', N='derod', C=f'derod/main.go:{cv}', M='',
                     Version=f'3.6.0-153.DEROHE.STARGATE+22102026.{ver}'))
        for k in range(60):
            out.append(J(L='DEBUG', T=f'2026-10-24T{hh}:{k // 3:02d}:{(k % 3) * 18:02d}.000-0700', N='CORE',
                         C='blockchain/blockchain.go:924', M='Chain extended', **{'new height': 1000 * (i + 1) + k}))
        for k in range(10):
            out.append(J(L='DEBUG', T=f'2026-10-24T{hh}:30:{k:02d}.000-0700', N='P2P', C='p2p/own_broadcast.go:135',
                         M='Own miniblock delivered', height=5 + k, peers=10, acked=10 - (3 if i else 1), failed=3 if i else 1,
                         first_ms=50 + k, median_ms=150 + k, last_ms=200 + 10 * k,
                         failed_by_reason={'duplicate': 2 if i else 1, 'peer_behind': 1} if i else {'duplicate': 1}))
    return '\n'.join(out) + '\n'


METRICS = """# HELP x
p2p_sync_blocks_fetched_total 884
p2p_sync_getobject_calls_total 221
p2p_sync_wait_seconds_total 0.2
p2p_sync_process_seconds_total 15.8
p2p_sync_pow_prewarmed_total 8840
getwork_template_refresh_resends_total 12
p2p_first_relay_total{peer="1.2.3.4"} 30
p2p_first_relay_total{peer="5.6.7.8"} 10
"""


def miner_log():
    out = []

    def rec(t, **kv):
        out.append(J(L='INFO', T=f'2026-10-24T{t}.000-0700', N='miner', C='dero-miner/x.go:1', **kv))
    for run, hh in ((1, '10'), (2, '11')):
        rec(f'{hh}:00:00', M='DERO Stargate HE AstroBWT miner : It is an alpha version, use it for testing/evaluations purpose only.')
        rec(f'{hh}:00:00', M='', Version=f'3.6.0-153.DEROHE.STARGATE+22102026.r1{7 + run}')
        rec(f'{hh}:00:00', M='', Arguments={'--mining-threads': '20', '--cpu-max': '90', '--gpu-mode': 'split' if run == 2 else 'full'})
        if run == 2:
            rec(f'{hh}:00:01', M='GPU split mode ACTIVE — self-test passed on 256 nonces (bit-exact AstroBWTv3)', batch=100, depth=4, inflight=2)
        # TOTAL: two warm-up samples (1000, 2000) then 30000, 31000, ..., 49000 (20 samples, mean 39500)
        for k, h in enumerate([1000, 2000] + [30000 + 1000 * j for j in range(20)]):
            rec(f'{hh}:{k // 4:02d}:{(k % 4) * 15:02d}', M='TOTAL hashrate', **{'H/s': str(h)})
        if run == 2:
            # 3 GPU split lines 60 s apart: staged 1000 H/s; dropped 0 -> 600 -> 1200 (600 per minute)
            for k, (dr, rs) in enumerate(((0, 0), (600, 0), (1200, 1))):
                rec(f'{hh}:0{k + 1}:00', M='GPU split', **{'staged_H/s': '1000', 'dropped_stale': dr, 'cpu_finished': 0,
                                                           'audited': 10, 'gpu_us_per_hash': '31.0', 'gpu_cpu_mismatch': 1,
                                                           'restarts': rs, 'disabled': '',
                                                           'cpu': 'sort=descriptor verified=50 fallbacks=0'})
            rec(f'{hh}:03:00', M='REWARD STATS', accepted_miniblocks=26, rejected=0, found_CPU=1, found_GPU=29,
                node_submitted=30, node_paid=18, node_orphaned=2, node_pending=10, paid_fraction='0.900', luck='1.15',
                expected_shares='26.1', **{'run_H/s': '39500'})
    return '\n'.join(out) + '\n'


def derod_heights():
    # 4 new heights inside the split window 11:01:00-11:03:00 (one repeated), one outside
    hs = [('11:01:10', 1), ('11:01:30', 2), ('11:01:30', 2), ('11:02:10', 3), ('11:02:50', 4), ('11:05:00', 5)]
    return [{'T': f'2026-10-24T{t}.000-0700', 'M': 'Chain extended', 'new height': h} for t, h in hs]


# ───────────────────────────── KATs ─────────────────────────────
def ik1(base, tmp):
    L = load(base, 'log_intel')
    f = tmp / 'derod.log'
    f.write_text(derod_log())
    recs = L.lines([f])
    runs, cur = [], []
    for d in recs:
        if L.is_start(d) and cur:
            runs.append(cur)
            cur = []
        cur.append(d)
    runs.append(cur)
    vers = [L.profile(r).get('version', '') for r in runs]
    ok = len(runs) == 2 and vers[0].endswith('r17') and vers[1].endswith('r18')
    return ok, f'{len(runs)} runs, versions {vers}'


def ik2(base, tmp):
    L = load(base, 'log_intel')
    f = tmp / 'derod.log'
    f.write_text(derod_log())
    recs = L.lines([f])
    r18 = [d for d in recs if d['T'] >= '2026-10-24T12']
    om = L.own_miniblocks(r18)
    p = L.profile(r18)
    al = [k for k, _, _ in L.rules(p)]
    r17 = L.profile([d for d in recs if d['T'] < '2026-10-24T12'])
    ok = (om['count'] == 10 and om['peers'] == 100 and om['failed'] == 30 and om['fail_fraction'] == 0.3
          and om['failed_by_reason'] == {'duplicate': 20, 'peer_behind': 10} and om['median_ms_median'] == 154.5
          and om['last_ms_p90'] == 280 and 'own_mb_fail' in al
          and 'own_mb_fail' not in [k for k, _, _ in L.rules(r17)])
    return ok, f"{om} rules r18 {al}"


def ik3(base, tmp):
    L = load(base, 'log_intel')
    m = L.parse_metrics(METRICS)
    ok = (m['p2p_sync_large_block_fallbacks_total'] == 0 and 'p2p_sync_large_block_fallbacks_total' in m['absent']
          and m['blocks_per_getobject'] == 4.0 and m['sync_wait_fraction'] == round(0.2 / 16.0, 4)
          and m['first_relay_peers'] == 2 and m['first_relay_top_share'] == 0.75)
    return ok, str({k: m[k] for k in ('blocks_per_getobject', 'sync_wait_fraction', 'first_relay_top_share', 'absent')})


def ik4(base, tmp):
    D = load(base, 'datadir_intel')
    real = (ROOT / 'p2p/peer_pool.go').read_text()
    a = D.retention_from_source(real)
    edited = real.replace('\t\treturn 86400\n', '\t\treturn 2 * 86400\n').replace('\treturn 3600\n}', '\treturn 1800\n}')
    b = D.retention_from_source(edited)
    return a == (86400, 3600) and b == (172800, 1800), f'real {a}, edited copy {b}'


def ik5(base, tmp):
    D = load(base, 'datadir_intel')
    src = (ROOT / 'p2p/first_relay.go').read_text()
    fields, forget = D.go_json_fields(src, 'RelayStat'), D.go_const(src, 'FIRST_RELAY_FORGET')
    now = 2_000_000_000
    ok_e = {'address': '1.2.3.4:10101', 'firsts': 6, 'builders': {}, 'delay_sum_us': 1, 'delay_n': 1, 'last_first': now - 10}
    t = {'blocks': 9, 'peers': {
        '1.2.3.4': ok_e,
        '1.2.3.5': {**ok_e, 'firsts': 2},
        '1.2.3.6': {**ok_e, 'last_first': now - forget - 1},          # forgotten
        '1.2.3.7': {**ok_e, 'last_first': now + 86401},               # future
        'not-an-ip': ok_e,
        '1.2.3.8': {**ok_e, 'firsts': 0},
        '1.2.3.9': {**ok_e, 'extra': 1}}}                             # schema error
    r = D.first_relay_check(t, now, forget, fields)
    ok = (forget == 7 * 86400 and set(fields) == {'address', 'firsts', 'builders', 'delay_sum_us', 'delay_n', 'last_first'}
          and r['restorable'] == 2 and r['schema_errors'] == ['1.2.3.9'] and r['top_share'] == 0.75
          and r['rejected'] == {'older than FIRST_RELAY_FORGET': 1, 'in the future': 1, 'not an IP': 1, 'no firsts': 1})
    return ok, f'forget {forget}, {r}'


def ik6(base, tmp):
    D = load(base, 'datadir_intel')
    src = (ROOT / 'p2p/penalty.go').read_text()
    fields, forget = D.go_json_fields(src, 'v2_record'), D.go_const(src, 'V2_FORGET')
    now = 2_000_000_000
    m = {'1.1.1.1': {'n': 3, 'last': now - 5}, '1.1.1.2': {'n': 0, 'last': now - 5},
         '1.1.1.3': {'n': 2, 'last': now - forget - 1}, 'x': {'n': 1, 'last': now}, '1.1.1.4': {'n': 1}}
    r = D.v2_offences_check(m, now, forget, fields)
    ok = forget == 604800 and set(fields) == {'n', 'last'} and r['kept'] == 1 and sorted(r['schema_errors']) == ['1.1.1.4', 'x']
    return ok, f'forget {forget} fields {fields} {r}'


def ik7(base, tmp):
    MI = load(base, 'miner_intel')
    f = tmp / 'miner.log'
    f.write_text(miner_log())
    runs = [x for x in MI.split_runs(MI.records(f)) if len(x) >= 5]
    if len(runs) != 2:
        return False, f'{len(runs)} runs (want 2)'
    p = MI.profile(runs[1], derod_heights())
    hs, sp, rw = p['hashrate'], p['split'], p['reward']
    al = {k: lv for k, lv, _ in MI.rules(p)}
    # staged work over the window: 1000 H/s x 120 s = 120000; dropped 1200 -> 1200 / 121200
    ok = (hs['samples'] == 20 and hs['mean'] == 39500.0 and hs['p10'] == 31000 and p['gpu_mode'] == 'split'
          and sp['dropped_per_min'] == 600.0 and sp['drop_fraction'] == round(1200 / 121200, 4)
          and sp['heights_in_window'] == 4 and sp['drops_per_height'] == 300.0 and sp['ring_slots'] == 400
          and sp['drops_per_height_vs_ring'] == 0.75 and sp['staged_share_of_total'] == round(1000 / 39500, 3)
          and rw['paid_fraction_recomputed'] == 0.9 and rw['resolved'] == 20
          and al.get('gpu_mismatch') == 'ALERT' and al.get('gpu_restarts') == 'WARN' and 'sort_fallbacks' not in al
          and 'paid_fraction' not in al and MI.profile(runs[0])['split']['lines'] == 0)
    return ok, f"mean {hs['mean']} n {hs['samples']} drop {sp['drop_fraction']} per-height {sp.get('drops_per_height')} rules {al}"


SPLIT_OUT = """sort: x
split: CPU side only (GPU stage 1 + SHA not run; texts prepared on the CPU, untimed) · sort: sort=descriptor
             Threads           Total Time     Total Iterations            Time/PoW          Hash/CPU-Sec        Hash Rate/Sec
                   1          300ms                 1000            300µs               3500.0               3333.3
                   4          900ms                 4000            225µs               3400.5               4444.4
split: declined sorts 0 (each would be re-hashed in full on the CPU while mining)
"""


def ik8(base, tmp):
    F = load(base, 'fbv')
    cpu, wall = F.parse_bench(SPLIT_OUT, 4)
    old = F.parse_bench('   4   1s   4000   250µs   4000.0\n', 4)              # pre-r18: no H/cpu-s column
    # R21: staged vs installed is judged like for like (same --sort, same sorter read back), via like_for_like()
    lfl = lambda st, inst: F.like_for_like({'auto': {'staged': [(x, 'native C') for x in st], 'installed': [(x, 'native C') for x in inst]}})
    good = ({'descriptor': [2400, 2350, 2380], 'sais': [600, 610, 590]}, lfl([2400, 2390, 2410], [2350, 2360, 2340]))
    ok1, w1 = F.judge_minerbench(*good, {'h_per_cpu_s': 3400.5, 'declined': 0}, 2400)
    # staged wall rate could be anything: only H/cpu-s decides. 0.92 x installed per CPU-second must fail
    ok2, w2 = F.judge_minerbench(good[0], lfl([2160] * 3, [2350] * 3), {'h_per_cpu_s': 3400, 'declined': 0}, 2160)
    ok3, w3 = F.judge_minerbench(*good, {'h_per_cpu_s': 2300, 'declined': 0}, 2400)    # split slower than a full hash
    ok4, w4 = F.judge_minerbench(*good, {'h_per_cpu_s': 3400, 'declined': 5}, 2400)
    # R21: the STAGED build is this tree (r19+), so a split-bench skip is a broken bench and fails (it passed before)
    ok5, _ = F.judge_minerbench(*good, {'skip': 'gpu split mode needs paired hashing; pair=off'}, 2400)
    ok = (cpu == 3400.5 and wall == 4444.4 and old == (None, 4000.0) and ok1 and not ok2 and not ok3 and not ok4 and not ok5)
    return ok, f'parse {cpu}/{wall} old {old}; verdicts {ok1} {ok2}:{w2} {ok3}:{w3} {ok4}:{w4} {ok5}'


def split_run(cpu, extra=None):
    """one split run: start-up, ACTIVE line, two GPU split lines with the given cpu field, optional extra records"""
    out = []

    def rec(t, **kv):
        out.append(dict(L=kv.pop('L', 'INFO'), T=f'2026-10-24T{t}.000-0700', N='miner', C='dero-miner/x.go:1', **kv))
    rec('12:00:00', M='DERO Stargate HE AstroBWT miner : It is an alpha version, use it for testing/evaluations purpose only.')
    rec('12:00:01', M='GPU split mode ACTIVE — self-test passed on 256 nonces (bit-exact AstroBWTv3)', batch=100, depth=4, inflight=2)
    for k in range(2):
        rec(f'12:0{k + 1}:00', M='GPU split', **{'staged_H/s': '1000', 'dropped_stale': 0, 'cpu_finished': 0, 'audited': 1,
                                                'gpu_us_per_hash': '31.0', 'gpu_cpu_mismatch': 0, 'restarts': 0, 'disabled': '',
                                                'cpu_idle_tries': 5 + k, 'feeder_ring_full_ms': 100, 'cpu': cpu})
    for e in extra or []:
        rec('12:01:30', **e)
    return out


def ik9(base, tmp):
    MI = load(base, 'miner_intel')
    off = MI.split_stats(split_run('sort=SA-IS (descriptor disabled: 3 wrong suffix arrays)'))
    err = MI.split_stats(split_run('sort=descriptor verified=9 fallbacks=0',
                                   [{'L': 'ERROR', 'M': 'descriptor sort DISABLED, falling back to the built-in SA-IS'}]))
    fb = MI.split_stats(split_run('sort=descriptor verified=900 fallbacks=3'))
    r_off = {k: lv for k, lv, _ in MI.rules({'split': off, 'hashrate': {}, 'reward': {}})}
    r_err = {k: lv for k, lv, _ in MI.rules({'split': err, 'hashrate': {}, 'reward': {}})}
    r_fb = {k: lv for k, lv, _ in MI.rules({'split': fb, 'hashrate': {}, 'reward': {}})}
    ok = (r_off.get('sort_disabled') == 'ALERT' and r_err.get('sort_disabled') == 'ALERT'
          and r_fb.get('sort_fallbacks') == 'WARN' and 'sort_disabled' not in r_fb
          and fb['cpu_idle_tries'] == 11 and fb['feeder_ring_full_ms'] == 200)
    return ok, f'disabled-field {r_off} error-line {r_err} fallbacks {r_fb} idle {fb.get("cpu_idle_tries")}'


def ik10(base, tmp):
    F = load(base, 'forensics')
    a = F.missing_input_plan(False, {'rows': [{}] * 17})
    b = F.missing_input_plan(False, None)
    c = F.missing_input_plan(True, {'rows': []})
    ok = a[0] == 'skip' and 'SKIP' in a[1] and '17 rows' in a[1] and b[0] == 'empty' and c == ('mine', None)
    return ok, f'{a} {b} {c}'


KATS = [('IK1', ik1), ('IK2', ik2), ('IK3', ik3), ('IK4', ik4), ('IK5', ik5), ('IK6', ik6), ('IK7', ik7), ('IK8', ik8),
        ('IK9', ik9), ('IK10', ik10)]

# (kat, module, find, replace, why) — each must flip its KAT to FAIL on a temp copy
MUTATIONS = [
    ('IK1', 'log_intel', "str(d.get('M', '')).startswith(START_M)", "d.get('C') == 'derod/main.go:160'",
     'the start-up line is matched by the old caller line again'),
    ('IK1', 'log_intel', "if str(d.get('C', '')).startswith(START_FILE) and d.get('Version'):",
     "if d.get('C') == 'derod/main.go:163' and d.get('Version'):", 'the version is read only from the r17 caller line'),
    ('IK2', 'log_intel', "failed = sum(d.get('failed') or 0 for d in L)", 'failed = 0', 'own-miniblock failures are not counted'),
    ('IK2', 'log_intel', "om['fail_fraction'] > 0.25", "om['fail_fraction'] > 0.5", 'the own-miniblock failure threshold is doubled'),
    ('IK3', 'log_intel', "busy = out['p2p_sync_wait_seconds_total'] + out['p2p_sync_process_seconds_total']",
     "busy = out['p2p_sync_process_seconds_total']", 'the network-wait fraction drops the wait from its denominator'),
    ('IK4', 'datadir_intel', "    return go_int_expr(m.group(1)), go_int_expr(m.group(2))\n",
     "    return 86400, 3600\n", 'retention is typed again instead of read from peer_pool.go'),
    ('IK5', 'datadir_intel', "'older than FIRST_RELAY_FORGET' if now - s.get('last_first', 0) > forget else",
     "'older than FIRST_RELAY_FORGET' if False else", 'the first-relay forget window is ignored'),
    ('IK6', 'datadir_intel', "if r['n'] > 0 and now - r['last'] <= forget", "if now - r['last'] <= forget",
     'v2 offences with n = 0 are kept'),
    ('IK7', 'miner_intel', 'body = pts[WARMUP_SAMPLES:] if len(pts) > WARMUP_SAMPLES else []', 'body = pts',
     'the warm-up samples are averaged in'),
    ('IK7', 'miner_intel', "round(dropped / (dropped + staged_work), 4)", "round(dropped / staged_work, 4)",
     'the drop fraction forgets the dropped nonces in its denominator'),
    ('IK7', 'miner_intel', "if (sp.get('mismatch') or 0) > 0:", "if (sp.get('mismatch') or 0) > 1:",
     'one GPU/CPU mismatch no longer raises an ALERT'),
    ('IK7', 'miner_intel', "if str(d.get('M', '')).startswith(START_M) and cur:", "if False:",
     'miner runs are no longer split at start-up'),
    ('IK8', 'fbv', "cpu = float(r[-2]) if len(r) >= 6 and r[-2] != '-' else None", "cpu = float(r[-1])",
     'the bench parser reads the wall H/s as H/cpu-s'),
    ('IK8', 'fbv', "elif full_cpu is not None and sc <= full_cpu and not contended:", "elif False:",
     'a split CPU side slower than a full hash passes'),
    ('IK8', 'fbv', "elif lfl.get('ratio') is not None and lfl['ratio'] < 0.93 and not contended:", "elif False:",
     'the staged-vs-installed H/cpu-s gate is dropped'),
    ('IK9', 'miner_intel', "sort_off = next((str(d.get('cpu')) for d in S if 'descriptor disabled' in str(d.get('cpu', ''))), '')",
     "sort_off = ''", 'the "descriptor disabled" cpu field is no longer an ALERT'),
    ('IK9', 'miner_intel', "if str(d.get('M', '')).startswith('descriptor sort DISABLED')", "if False",
     'the ERROR "descriptor sort DISABLED" line is ignored'),
    ('IK9', 'miner_intel', "out.append(('sort_fallbacks', 'WARN',", "out.append(('sort_fallbacks', 'ALERT',",
     'sort fallbacks are an ALERT again'),
    ('IK10', 'forensics', "    if n:\n        return 'skip'", "    if False:\n        return 'skip'",
     'a missing audit input overwrites the committed rows with 0 again'),
]


def copy_tree():
    d = Path(tempfile.mkdtemp(prefix='r19kat-'))
    for rel in list(MODS.values()) + EXTRA:
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HARNESS / rel, d / rel)
    return d


def main():
    tmp = Path(tempfile.mkdtemp(prefix='r19fx-'))
    fails = 0
    for name, fn in KATS:
        try:
            ok, det = fn(HARNESS, tmp)
        except Exception as e:                                    # noqa: BLE001
            ok, det = False, f'{type(e).__name__}: {e}'
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:230]}")
    missed = 0
    byname = dict(KATS)
    for kat, mod, find, repl, why in MUTATIONS:
        d = copy_tree()
        p = d / MODS[mod]
        text = p.read_text()
        if text.count(find) != 1:
            print(f'  ??      {kat}: {why} — find text occurs {text.count(find)} times')
            missed += 1
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
    print(f'\nR19 intel KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
