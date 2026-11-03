#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the R20 harness layer (no network, no live file written).

  IK11 metrics_intel: two samples of both /metrics endpoints -> rates, split share and drop fraction, expected shares
       from the NW estimate (not the 10x final-job difficulty), cross-checks (miner behind, no hashing, down endpoint)
  IK12 miner_intel reads the rotated log chain oldest first (<log>.2, <log>.1, <log>): each run keeps its file, a
       chain whose oldest file starts mid-run is head_missing, the CURRENT run alone is judged for silence and for a
       stale build against config/version.go
  IK13 miner_intel.drought and unexplained_gaps: the longest share-free stretch and its expected count, and gaps no
       surviving miner log covers (partial coverage is subtracted, not treated as an explanation)
  IK14 go_mutate: failed_tests reads `go test -json`, compare_failures splits OURS from UPSTREAM (red on the base too)
  IK15 fix_build_verify S3a: new_test_names from a diff, classify_runs tells FLAKY (1-2 of 3) from BROKEN (3 of 3)
  IK16 mine_forensics without its input leaves the committed raw file BYTE-identical and records the SKIP in
       loop/SKIPPED.json (r19 dirtied the tracked file: H7 follow-up)
  IK18 (r20 merge, HR20-6 review) S3a fails closed: a new test with a data race in ANY run is broken, a failing
       package run whose tests all passed is '<package>', a flaky new test fails the stage; go_mutate records a
       failing package without test names as '<package>' and a timeout as '<timeout>' instead of OK / a crash
  IK17 gen_deroarch.relocate/stamp_root: a stamp built in another checkout is re-read under THIS one (check and G2
       judged the live tree from every clone before R20); paths outside the checkout are left alone

  python3 -I harness/kat/test_intel_r20.py            # KATs, then each mutation on a temp copy must flip its KAT
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught.
"""
import importlib.util, json, shutil, sys, tempfile
import os
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
MODS = {'metrics_intel': 'intel/metrics_intel.py', 'miner_intel': 'intel/miner_intel.py', 'go_mutate': 'intel/go_mutate.py',
        'fbv': 'pipeline/fix_build_verify.py', 'forensics': 'miners/mine_forensics.py', 'gen': 'gen_deroarch.py'}
EXTRA = ['miners/minelib.py', 'prep_corpus.py']      # imported by mine_forensics / gen_deroarch; copied with them
EXTRA_DIRS = ['kit']                                   # gen_deroarch imports the kit modules


def load(base, name):
    if name == 'forensics':
        sys.modules.pop('minelib', None)                  # bind THIS copy's minelib (its paths), never a cached one
    spec = importlib.util.spec_from_file_location(f'{name}_{id(base)}_{len(sys.modules)}', base / MODS[name])
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def J(**kv):
    return json.dumps(kv)


# ───────────────────────────── IK11 ─────────────────────────────
def derod_text(height, panics=0, status='synced'):
    return '\n'.join([
        '# HELP x', 'app_version{version="v-r19", short_version="v-r19"} 1', 'app_uptime_seconds 1000',
        f'dero_chain_height {height}', f'dero_chain_topoheight {height}', 'dero_tip_age_seconds 4.5',
        'dero_sync_lag_blocks 0', f'dero_sync_status{{status="{status}"}} 1',
        f'dero_sync_status{{status="{"stalled" if status == "synced" else "synced"}"}} 0',
        'p2p_peer_outgoing_count 17', 'p2p_peer_incoming_count 0', 'dero_getwork_miners 1', 'getwork_jobs_sent_total 100',
        'miniblock_ours_submitted_total 50', 'miniblock_ours_paid_total 45',
        'miniblock_ours_orphaned_total{reason="slots_full"} 3', 'miniblock_ours_orphaned_total{reason="other"} 2',
        f'recovered_panics_total{{level="0"}} {panics}', 'rpc_recovered_panics_total 0', ''])


def miner_text(hashes, height, hashed, dropped, version='v-r19'):
    return '\n'.join([
        f'dero_miner_info{{version="{version}"}} 1', 'dero_miner_uptime_seconds 100', 'dero_miner_threads 20',
        'dero_miner_connected 1', f'dero_miner_hashes_total {hashes}', 'dero_miner_hashrate_15s 70000',
        f'dero_miner_height {height}', 'dero_miner_difficulty 30000000', 'dero_miner_network_hashrate_estimate 3000000',
        f'dero_miner_split_hashed_total {hashed}', f'dero_miner_split_dropped_total {dropped}', 'dero_miner_split_disabled 0',
        'dero_miner_gpu_mismatch_total 0', 'dero_miner_found_total{source="cpu"} 2', 'dero_miner_found_total{source="gpu"} 3', ''])


def fake_get(seq):
    it = iter(seq)

    def get(url):
        v = next(it)
        if v is None:
            raise OSError('connection refused')
        return v
    return get


def clock(vals):
    it = iter(vals)
    return lambda: next(it)


def ik11(base, tmp):
    MT = load(base, 'metrics_intel')
    # good: 60 s apart; the miner hashed 4,200,000 (70,000 H/s), 3,400,000 of them staged, 34,343 dropped
    good = MT.snapshot('d', 'm', 60, get=fake_get([derod_text(100), miner_text(1_000_000, 100, 0, 0),
                                                    derod_text(103), miner_text(5_200_000, 103, 3_400_000, 34_343)]),
                       sleep=lambda s: None, clock=clock([1000.0, 1060.0]))
    m, d = good['miner'], good['derod']
    al = {a['rule'] for a in good['alerts']}
    ok_good = (m['hashrate_sampled'] == 70000.0 and m['split_share'] == round(3_400_000 / 5_200_000, 4)
               and m['split_drop_fraction'] == round(34_343 / (34_343 + 3_400_000), 4)
               and m['expected_shares_per_h'] == round(70000 * 3600 * 5 / (9 * 3_000_000), 1) and d['paid_fraction'] == 0.9 and d['ours_orphaned'] == 5
               and d['heights_per_min'] == 3.0 and d['sync_status'] == 'synced' and not al
               and any(f.startswith('live miner version=v-r19 ') for f in good['facts']))
    # bad: the miner is 5 blocks behind, its counter froze, derod stalled with a recovered panic
    bad = MT.snapshot('d', 'm', 60, get=fake_get([derod_text(100, 1, 'stalled'), miner_text(1_000_000, 95, 0, 0),
                                                   derod_text(100, 1, 'stalled'), miner_text(1_000_000, 95, 0, 0)]),
                      sleep=lambda s: None, clock=clock([0.0, 60.0]))
    bl = {a['rule']: a['level'] for a in bad['alerts']}
    down = MT.snapshot('d', 'm', 60, get=fake_get([derod_text(1), None, derod_text(1), None]),
                       sleep=lambda s: None, clock=clock([0.0, 60.0]))
    dl = {a['rule']: a['level'] for a in down['alerts']}
    ok_bad = (bl.get('miner_behind') == 'ALERT' and bl.get('no_hashing') == 'ALERT' and bl.get('not_synced') == 'ALERT'
              and bl.get('recovered_panics') == 'WARN' and dl.get('endpoint_down') == 'ALERT' and down['up'] == {'derod': True, 'miner': False})
    return ok_good and ok_bad, (f"H/s {m['hashrate_sampled']} share {m['split_share']} drop {m['split_drop_fraction']} "
                                f"exp/h {m['expected_shares_per_h']} paid {d['paid_fraction']} good-alerts {al} bad {bl} down {dl}")


# ───────────────────────────── IK12 ─────────────────────────────
def mrun(day_hh, version, head=True, n_total=8):
    out = []

    def rec(t, **kv):
        out.append(J(L='INFO', T=f'2026-10-{day_hh}:{t}.000-0700', N='miner', C='dero-miner/x.go:1', **kv))
    if head:
        rec('00:00', M='DERO Stargate HE AstroBWT miner : It is an alpha version, use it for testing/evaluations purpose only.')
        rec('00:00', M='', Version=version)
        rec('00:00', M='', Arguments={'--mining-threads': '20', '--gpu-mode': 'split'})
    for k in range(n_total):
        rec(f'{k // 4:02d}:{(k % 4) * 15:02d}', M='TOTAL hashrate', **{'H/s': str(60000 + k)})
    return '\n'.join(out) + '\n'


def ik12(base, tmp):
    MI = load(base, 'miner_intel')
    d = tmp / 'ik12'
    d.mkdir(exist_ok=True)
    log = d / 'dero-miner.log'
    (d / 'dero-miner.log.2').write_text(mrun('26T10', 'v-r18', head=False))   # its head was truncated away
    (d / 'dero-miner.log.1').write_text(mrun('27T05', 'v-r19'))
    log.write_text(mrun('28T08', 'v-r19'))
    (d / 'config').mkdir(exist_ok=True)
    (d / 'config/version.go').write_text('var Version = semver.MustParse("v-r20")\n')
    end = MI.ts('2026-10-28T08:01:45.000-0700')
    rep = MI.analyse(str(log), None, use_rpc=False, now=end + 600, root=d)
    runs = rep['runs']
    names = [Path(r.get('source', '')).name for r in runs]
    cur = {a['rule']: a['level'] for a in runs[-1]['alerts']} if runs else {}
    old = {a['rule']: a['level'] for a in runs[0]['alerts']} if runs else {}
    mid = {a['rule'] for a in runs[1]['alerts']} if len(runs) > 2 else {'?'}
    ok = (names == ['dero-miner.log.2', 'dero-miner.log.1', 'dero-miner.log'] and rep['logs'][-1] == str(log)
          and [f['head_missing'] for f in rep['files']] == [True, False, False]
          and cur.get('miner_silent') == 'ALERT' and cur.get('stale_build') == 'WARN'
          and old.get('head_missing') == 'WARN' and 'miner_silent' not in old and not mid
          and rep['tree_version'] == 'v-r20' and runs[-1].get('version') == 'v-r19'
          and rep['facts'][0].startswith('miner run 2026-10-26T10:00:00 end=2026-10-26T10:01:45 '))
    # a fresh current run (now = its end + 60 s) is not silent; a matching tree version is not stale
    (d / 'config/version.go').write_text('var Version = semver.MustParse("v-r19")\n')
    rep2 = MI.analyse(str(log), None, use_rpc=False, now=end + 60, root=d)
    cur2 = {a['rule'] for a in rep2['runs'][-1]['alerts']}
    ok2 = 'miner_silent' not in cur2 and 'stale_build' not in cur2
    return ok and ok2, f'files {names} cur {cur} oldest {old} middle {mid} fresh {cur2}'


# ───────────────────────────── IK13 ─────────────────────────────
def ik13(base, tmp):
    MI = load(base, 'miner_intel')
    # run 0..10000 s at 30,000 H/s, D = 3,000,000: 5/(9 D) per hash = one share per 180 s; shares at 100, 200, 9000
    d = MI.drought([50.0, 100.0, 200.0, 9000.0, 20000.0], 0.0, 10000.0, 30000.0, 3_000_000)
    calm = MI.drought([float(t) for t in range(0, 10001, 100)], 0.0, 10000.0, 30000.0, 3_000_000)
    rules = {k for k, _, _ in MI.rules({'split': {}, 'reward': {}, 'hashrate': {}, 'shares': {**d, 'gap_from': 'x'}})}
    calm_rules = {k for k, _, _ in MI.rules({'split': {}, 'reward': {}, 'hashrate': {}, 'shares': {**calm, 'gap_from': 'x'}})}
    # derod-side gaps over [0, 40000]: own shares at 1000 and 30000; a miner log covers [1000, 5000]
    g = MI.unexplained_gaps([1000.0, 30000.0], [(1000.0, 5000.0)], 0.0, 40000.0, min_gap=7200)
    g_full = MI.unexplained_gaps([1000.0, 30000.0], [(1000.0, 30000.0)], 0.0, 40000.0, min_gap=7200)
    ok = (d['submissions'] == 4 and d['longest_gap_s'] == 8800.0 and d['expected_in_gap'] == round(8800 / 180, 1)
          and 'share_drought' in rules and calm['expected_in_gap'] == round(100 / 180, 1) and 'share_drought' not in calm_rules
          and [(x['from'], x['to'], x['uncovered_h']) for x in g] == [(1000.0, 30000.0, round(25000 / 3600, 2)),
                                                                      (30000.0, 40000.0, round(10000 / 3600, 2))]
          and [x['from'] for x in g_full] == [30000.0])
    return ok, f'drought {d} calm {calm["expected_in_gap"]} rules {rules} gaps {g} full {g_full}'


# ───────────────────────────── IK14 ─────────────────────────────
GOJSON = '\n'.join([
    J(Action='run', Package='p', Test='TestA'), J(Action='fail', Package='p', Test='TestA/sub'),
    J(Action='fail', Package='p', Test='TestA'), J(Action='pass', Package='p', Test='TestB'),
    J(Action='fail', Package='p', Test='TestC'), J(Action='fail', Package='p'), 'not json at all'])


def ik14(base, tmp):
    G = load(base, 'go_mutate')
    f = G.failed_tests(GOJSON)
    bld = G.failed_tests('# github.com/x/p\n./a.go:1: undefined: q\nFAIL\tgithub.com/x/p [build failed]\n')
    c = G.compare_failures({'./p/': {'TestA', 'TestC'}, './new/': {'TestN'}}, {'./p/': {'TestC', 'TestOld'}})
    ok = (f == {'TestA', 'TestC'} and '<build>' in bld and c['./p/']['ours'] == ['TestA'] and c['./p/']['upstream'] == ['TestC']
          and c['./p/']['fixed_here'] == ['TestOld'] and c['./new/']['ours'] == ['TestN'])
    return ok, f'failed {sorted(f)} build {bld} compare {c}'


# ───────────────────────────── IK15 ─────────────────────────────
DIFF = """diff --git a/p2p/x_test.go b/p2p/x_test.go
--- a/p2p/x_test.go
+++ b/p2p/x_test.go
@@ -1,3 +1,9 @@
 func TestOld(t *testing.T) {}
+func TestNewOne(t *testing.T) {
+}
+func BenchmarkNope(b *testing.B) {}
+func helperNotATest(t *testing.T) {}
--- a/cmd/derod/main.go
+++ b/cmd/derod/main.go
+func TestInNonTestFile(t *testing.T) {}
+++ b/cmd/dero-miner/logrotate_test.go
+func TestOpenLogKeepsPreviousRuns(t *testing.T) {
"""
RUNS = """=== RUN   TestA
--- PASS: TestA (0.01s)
=== RUN   TestB
--- FAIL: TestB (3.00s)
--- PASS: TestA (0.01s)
--- PASS: TestB (0.20s)
--- PASS: TestA (0.01s)
--- FAIL: TestC (0.01s)
--- FAIL: TestC (0.01s)
--- FAIL: TestC (0.01s)
--- PASS: TestB (0.20s)
"""


def ik15(base, tmp):
    F = load(base, 'fbv')
    n = F.new_test_names(DIFF)
    res, flaky, broken = F.classify_runs(RUNS, 3)
    ok = (n == {'./p2p/': ['TestNewOne'], './cmd/dero-miner/': ['TestOpenLogKeepsPreviousRuns']}
          and flaky == ['TestB'] and broken == ['TestC'] and res['TestA'] == {'pass': 3, 'fail': 0})
    return ok, f'new {n} flaky {flaky} broken {broken}'


# ───────────────────────────── IK18 ─────────────────────────────
RUNS_RACE = """=== RUN   TestR
==================
WARNING: DATA RACE
==================
    testing.go:1490: race detected during execution of test
--- FAIL: TestR (0.01s)
=== RUN   TestR
--- PASS: TestR (0.01s)
=== RUN   TestR
--- PASS: TestR (0.01s)
=== RUN   TestF
--- FAIL: TestF (0.01s)
=== RUN   TestF
--- PASS: TestF (0.01s)
=== RUN   TestF
--- PASS: TestF (0.01s)
"""
TIMEOUT_JSON = '{"Action":"output","Package":"p","Output":"panic: test timed out after 2m0s\\n"}\n' \
               '{"Action":"fail","Package":"p","Elapsed":120}\n'


def ik18(base, tmp):
    import subprocess as sp
    import types
    F = load(base, 'fbv')
    G = load(base, 'go_mutate')
    _, fl, br = F.classify_runs(RUNS_RACE, 3)
    _, _, pkg_br = F.s3a_package_result(1, '--- PASS: TestA (0.01s)\n', ['TestA'], 3)
    _, _, ok_br = F.s3a_package_result(0, '--- PASS: TestA (0.01s)\n', ['TestA'], 3)
    stage = (F.s3a_stage_ok(['TestF'], []), F.s3a_stage_ok([], []))
    pr = (G.package_result(1, TIMEOUT_JSON), G.package_result(0, ''), G.package_result(1, GOJSON))

    def boom(*a, **k):
        raise sp.TimeoutExpired('go', 1)
    real = G.subprocess
    G.subprocess = types.SimpleNamespace(run=boom, TimeoutExpired=sp.TimeoutExpired)
    try:
        to = G.package_failures(['./p/'], tmp)
    finally:
        G.subprocess = real
    ok = (br == ['TestR'] and fl == ['TestF'] and pkg_br == ['<package>'] and ok_br == [] and stage == (False, True)
          and pr[0] == {'<package>'} and pr[1] == set() and pr[2] == {'TestA', 'TestC'} and to == {'./p/': {'<timeout>'}})
    return ok, f'race broken {br} flaky {fl} pkg {pkg_br} stage {stage} package_result {pr} timeout {to}'


# ───────────────────────────── IK16 ─────────────────────────────
def ik16(base, tmp):
    d = Path(tempfile.mkdtemp(prefix='r20ik16-'))
    try:
        for rel in ('miners/mine_forensics.py', 'miners/minelib.py'):
            (d / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(base / rel, d / rel)
        raw = d / 'model/raw/forensics.json'
        raw.parent.mkdir(parents=True)
        body = json.dumps({'key': 'forensics', 'rows': [{'id': f'r{i}'} for i in range(17)]}, indent=1)
        raw.write_text(body)
        spec = importlib.util.spec_from_file_location(f'forensics_ik16_{id(d)}', d / 'miners/mine_forensics.py')
        sys.modules.pop('minelib', None)
        F = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(F)
        if Path(F.M.HARNESS).resolve() != d.resolve():          # never let a cached minelib point at the real harness
            return False, f'minelib bound to {F.M.HARNESS}, not the temp copy'
        F.main()
        skipped = json.loads((d / 'loop/SKIPPED.json').read_text()) if (d / 'loop/SKIPPED.json').exists() else {}
        same = raw.read_text() == body
        ok = same and 'SKIP' in skipped.get('forensics', {}).get('why', '') and '17 rows' in skipped['forensics']['why']
        return ok, f'raw unchanged {same} · skipped {skipped}'
    finally:
        sys.modules.pop('minelib', None)
        shutil.rmtree(d, ignore_errors=True)


# ───────────────────────────── IK17 ─────────────────────────────
def ik17(base, tmp):
    G = load(base, 'gen')
    old = '<repo>'
    a = G.relocate(f'{old}/p2p/x.go', old, '/tmp/clone')
    b = G.relocate(os.path.expanduser(os.environ.get('DERO_DATADIR', '~/dero-data')) + '/logs/derod.log', old, '/tmp/clone')
    c = G.relocate(f'{old}-other/x.go', old, '/tmp/clone')                 # a sibling directory, not inside old
    e = G.relocate(f'{old}/x.go', old, old)
    r1 = G.stamp_root({'root': '/r', 'sources': {}})
    r2 = G.stamp_root({'sources': {f'{old}/harness/gen_deroarch.py': '1', f'{old}/a.go': '2'}})
    ok = (a == '/tmp/clone/p2p/x.go' and b == os.path.expanduser(os.environ.get('DERO_DATADIR', '~/dero-data')) + '/logs/derod.log' and c == f'{old}-other/x.go'
          and e == f'{old}/x.go' and r1 == '/r' and r2 == old)
    return ok, f'{a} {b} {c} {r1} {r2}'


KATS = [('IK11', ik11), ('IK12', ik12), ('IK13', ik13), ('IK14', ik14), ('IK15', ik15), ('IK16', ik16), ('IK17', ik17),
        ('IK18', ik18)]

# (kat, module, find, replace, why) — each must flip its KAT to FAIL on a temp copy
MUTATIONS = [
    ('IK11', 'metrics_intel', "return round((y - x) / dt, 2)", "return round(y / dt, 2)",
     'a counter rate forgets to subtract the first sample'),
    ('IK11', 'metrics_intel', "round(dropped / (dropped + hashed), 4)", "round(dropped / hashed, 4)",
     'the split drop fraction loses the dropped nonces from its denominator'),
    ('IK11', 'metrics_intel', "D, H = out['miner']['network_hashrate'],", "D, H = out['miner']['difficulty'],",
     'expected shares use the raw job difficulty (10 x on a final job)'),
    ('IK11', 'metrics_intel', "round(H * 3600 * 5 / (9 * D), 1)", "round(H * 3600 / D, 1)",
     'expected shares ignore the 5/(9 D) share value (1.8x too many)'),
    ('IK11', 'metrics_intel', "d['height'] - m['height'] > HEIGHT_SLACK", "d['height'] - m['height'] > 10",
     'a miner hashing 5 blocks behind passes'),
    ('IK11', 'metrics_intel', "out.append(('endpoint_down', 'ALERT',", "out.append(('endpoint_down', 'INFO',",
     'a dead endpoint is not an ALERT'),
    ('IK12', 'miner_intel', "    return old + ([p] if p.exists() else [])", "    return [p] if p.exists() else []",
     'the rotated logs are not read'),
    ('IK12', 'miner_intel', "range(most, 0, -1)", "range(1, most + 1)", 'the rotated logs are read newest first'),
    ('IK12', 'miner_intel', "if current and now is not None and now - ts(p['end']) > SILENT_S:", "if False:",
     'a silent current run passes'),
    ('IK12', 'miner_intel', "if current and tree_ver and p.get('version') and p['version'] != tree_ver:", "if False:",
     'a stale running build is not reported'),
    ('IK12', 'miner_intel', "cur = i == len(runs) - 1 and", "cur = True or", 'every old run is judged as if it were running now'),
    ('IK13', 'miner_intel', "exp = round(gap * mean_hs * 5 / (9 * difficulty), 1)", "exp = round(gap * mean_hs / difficulty, 1)",
     'the drought expectation drops the 5/(9 D) share value (overstates by 1.8x)'),
    ('IK13', 'miner_intel', "if (b - a) - seen >= min_gap:", "if b - a >= min_gap and not seen:",
     'any overlap with a miner log explains a whole gap again'),
    ('IK13', 'miner_intel', "sh['expected_in_gap'] >= DROUGHT_EXPECTED", "sh['expected_in_gap'] >= 1e9",
     'a share drought never alerts'),
    ('IK14', 'go_mutate', "'upstream': sorted(tree[pkg] & b)", "'upstream': sorted(tree[pkg])",
     'every failure is filed as upstream'),
    ('IK14', 'go_mutate', "res[pkg] = {'ours': sorted(tree[pkg] - b),", "res[pkg] = {'ours': [],",
     'new failures are never ours'),
    ('IK14', 'go_mutate', "            out.add(t.split('/')[0])", "            out.add(t)", 'subtest failures are counted as tests'),
    ('IK15', 'fbv', "broken = sorted(t for t, r in res.items() if (r['fail'] and not r['pass']) or t in racy)",
     "broken = sorted(t for t, r in res.items() if r['fail'])", 'a flaky test is reported as broken'),
    ('IK15', 'fbv', "flaky = sorted(t for t, r in res.items() if r['fail'] and r['pass'] and t not in racy)", "flaky = []",
     'flakiness is not reported'),
    ('IK18', 'fbv', "if (r['fail'] and not r['pass']) or t in racy)", "if r['fail'] and not r['pass'])",
     'an intermittent data race in a new test counts as merely flaky'),
    ('IK18', 'fbv', "    if rc != 0 and not fl and not br:\n", "    if False:\n", 'a failing package run whose tests passed is OK'),
    ('IK18', 'fbv', "    return not flaky and not broken\n", "    return not broken\n", 'a flaky new test passes S3a'),
    ('IK18', 'go_mutate', "    return f or {'<package>'}\n", "    return f\n",
     'a package failing without a test name (timeout, init panic) is recorded as OK'),
    ('IK18', 'go_mutate', "            out[pkg] = {'<timeout>'}", "            raise",
     'a package timeout crashes the run instead of being recorded'),
    ('IK15', 'fbv', "m = re.match(r'^\\+\\+\\+ b/(.+_test\\.go)$', l)", "m = re.match(r'^\\+\\+\\+ b/(.+\\.go)$', l)",
     'tests declared in non-test files are collected'),
    ('IK16', 'forensics', "        record_skip('forensics', why)\n",
     "        raw_doc['skipped'] = why\n        raw.write_text(json.dumps(raw_doc, indent=1, ensure_ascii=False))\n        record_skip('forensics', why)\n",
     'the skip writes into the committed raw file again (r19 behaviour)'),
    ('IK16', 'forensics', "        record_skip('forensics', why)\n", "", 'the SKIP is not recorded'),
    ('IK17', 'gen', "    if old_root and old_root != new_root and (p == old_root or p.startswith(old_root.rstrip('/') + '/')):",
     "    if old_root and old_root != new_root and p.startswith(old_root):", 'a sibling directory is relocated'),
    ('IK17', 'gen', "    if st.get('root'):\n        return st['root']\n", "", 'the recorded root is ignored'),
    ('IK17', 'gen', "        return new_root + p[len(old_root.rstrip('/')):]", "        return p",
     'paths are never relocated (check judges the live tree from a clone)'),
]


def copy_tree():
    d = Path(tempfile.mkdtemp(prefix='r20kat-'))
    for rel in list(MODS.values()) + EXTRA:
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HARNESS / rel, d / rel)
    for rel in EXTRA_DIRS:
        shutil.copytree(HARNESS / rel, d / rel, ignore=shutil.ignore_patterns('__pycache__', '.cache'))
    return d


def main():
    tmp = Path(tempfile.mkdtemp(prefix='r20fx-'))
    fails = 0
    for name, fn in KATS:
        try:
            ok, det = fn(HARNESS, tmp)
        except Exception as e:                                    # noqa: BLE001
            ok, det = False, f'{type(e).__name__}: {e}'
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
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
    print(f'\nR20 harness KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
