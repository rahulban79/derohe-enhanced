#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the r24 paused miner track and the B21 known-failure list (no network, no
live file written; artifacts/dero-rft.md §0.3, harness/kit/roundtracks.py, harness/loop/KNOWN_TEST_FAILURES.json).

  TR1 track_state: 'paused' only for the literal 'paused' of the CURRENT round; active / absent tracks / absent entry /
      no registry / a current round that is not listed / an unknown value ('Paused', a list) are all 'active' (the
      check runs); track_problems flags an unknown value, a non-object and an unknown track name, and passes a clean one.
  TR2 gate_outcome pauses only G17/G18/G21 and only while paused, quoting the unchanged verdict and the reason; word and
      all_ok read PAUSED as its own outcome; gate_tally (S7) counts a PAUSED row only for a pausable gate while paused.
  TR3 run_gates.miner_gates on forged snapshots: active = the pre-r24 verdicts (silent miner FAILS G17, a miner endpoint
      down FAILS G18, no payout ledger FAILS G21, a healthy pair PASSES); paused = PAUSED for all three with the FAIL
      quoted, except G18 FAILS when its derod half fails (derod endpoint down, derod not_synced ALERT, no snapshot).
  TR4 G20: a record whose A/B stages are PAUSED is A/B evidence only while paused; with the track active it is none
      (pipeline_for_ab -> None) and a PAUSED stage FAILS g20_contention.
  TR5 pipeline S4b/S4c: roundtracks.stage_paused pauses only with the track paused AND an empty miner-source diff (a
      change or an unreadable diff runs the A/B); fix_build_verify.event records PAUSED in the summary, full_record keeps
      a PAUSED-minerbench run as the full record, and fix_build_verify.stage_paused records PAUSED only while paused.
  TR6 B21: the committed KNOWN_TEST_FAILURES.json is well-formed, every evidence file exists, every flaky test exists in
      this tree, every upstream-red test exists on bf274e5, and the list names every upstream failure of the newest
      gomut record; go_mutate.relabel moves a listed-flaky OURS failure to known_flaky only with >= 2 of 3 clean re-runs
      (1 pass, or a race, keeps it OURS; an unlisted one is never re-run) and names an unlisted upstream failure;
      rerun_counts parses go test -json; fix_build_verify.s3_retry_verdict excuses only listed names with >= 2 passes and
      no race, and never an empty failure set.
  TR7 the committed registry and this checkout agree: run_gates.TRACK and fix_build_verify.MINER_TRACK equal
      track_state(harness/round.json), and a paused track has its §0.3 'State: PAUSED' in artifacts/dero-rft.md.

  python3 -I harness/kat/test_round_tracks_r24.py   # KATs, then each mutation on a temp copy must flip its KAT
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import datetime, importlib.util, json, re, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
MODS = {'rt': 'kit/roundtracks.py', 'gates': 'run_gates.py', 'fbv': 'pipeline/fix_build_verify.py', 'gm': 'intel/go_mutate.py'}
EXTRA = ['gen_deroarch.py', 'prep_corpus.py', 'consensus_guard.py', 'miners/minelib.py', 'intel/miner_intel.py',
         'round.json', 'loop/KNOWN_TEST_FAILURES.json']
EXTRA_DIRS = ['kit']


def load(base, name):
    for m in ('gen_deroarch', 'prep_corpus', 'assetkit', 'textkit', 'connectorkit', 'diagramkit', 'minelib', 'roundtracks'):
        sys.modules.pop(m, None)
    extra = [str(base / 'kit'), str(base)] if name == 'gates' else []
    sys.path[:0] = extra
    try:
        spec = importlib.util.spec_from_file_location(f'{name}_{id(base)}_{len(sys.modules)}', base / MODS[name])
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
    finally:
        del sys.path[:len(extra)]
    return m


def reg(tracks=..., current='r24'):
    r = {'id': 'r24', 'status': 'in-progress'}
    if tracks is not ...:
        r['tracks'] = tracks
    return {'current': current, 'rounds': [{'id': 'r23c', 'status': 'measured', 'tracks': {'miner': 'active'}}, r]}


# ───────────────────────────── TR1 ─────────────────────────────
def tr1(base):
    RT = load(base, 'rt')
    cases = [(reg({'miner': 'paused', 'node': 'active'}), 'paused'), (reg({'miner': 'active'}), 'active'), (reg(), 'active'),
             (reg({'node': 'active'}), 'active'), (None, 'active'), (reg({'miner': 'paused'}, current='r99'), 'active'),
             (reg({'miner': 'Paused'}), 'active'), (reg(['miner']), 'active'), ({}, 'active')]
    got = [RT.track_state(r)[0] for r, _ in cases]
    why_ok = '§0.3' in RT.track_state(cases[0][0])[1] and 'rounds[r24].tracks.miner' in RT.track_state(cases[0][0])[1]
    why_ok = why_ok and 'not one of' in RT.track_state(reg({'miner': 'Paused'}))[1]   # an unknown value is said, not silent
    probs = [RT.track_problems(reg({'miner': 'Paused'})), RT.track_problems(reg(['miner'])),
             RT.track_problems(reg({'minr': 'paused'})), RT.track_problems(reg({'miner': 'paused', 'node': 'active'}))]
    ok = got == [w for _, w in cases] and why_ok and all(probs[:3]) and probs[3] == []
    return ok, f'states {got} why_ok {why_ok} problems {[len(p) for p in probs]}'


# ───────────────────────────── TR2 ─────────────────────────────
def tr2(base):
    RT = load(base, 'rt')
    W = 'harness/round.json rounds[r24].tracks.miner = \'paused\' (artifacts/dero-rft.md §0.3)'
    a = RT.gate_outcome('G17 the live miner is healthy', False, 'silent', 'active', W)
    p = RT.gate_outcome('G17 the live miner is healthy', False, 'silent', 'paused', W)
    p21 = RT.gate_outcome('G21 the payout ledger holds', True, 'luck', 'paused', W)
    n9 = RT.gate_outcome('G9 the live daemon still agrees', False, 'down', 'paused', W)
    words = [RT.word(x) for x in (RT.PAUSED, True, False, 0, 'x')]
    alls = [RT.all_ok([('a', True, ''), ('b', RT.PAUSED, '')]), RT.all_ok([('a', True, ''), ('b', False, '')])]
    row = lambda g, r: f'| 2026-11-02T04:00:00-08:00 | pipeline-x | {g} | {r} | detail |'
    rows = [row('G1 every rendered anchor resolved', 'PASS'), row('G17 the live miner is healthy', 'PAUSED'),
            row('G18 the live dashboard agrees', 'PAUSED'), row('G21 the payout ledger holds', 'PAUSED')]
    t_p = RT.gate_tally(rows, 'paused')
    t_a = RT.gate_tally(rows, 'active')
    t_x = RT.gate_tally(rows + [row('G9 the live daemon still agrees', 'PAUSED'), row('G2 x', 'FAIL')], 'paused')
    ok = (a == (False, 'silent') and p[0] == RT.PAUSED and p[1].startswith('PAUSED (miner): ') and '§0.3' in p[1]
          and 'said FAIL: silent' in p[1] and p21[0] == RT.PAUSED and 'said PASS: luck' in p21[1] and n9 == (False, 'down')
          and words == ['PAUSED', 'PASS', 'FAIL', 'FAIL', 'PASS'] and alls == [True, False]
          and t_p == (1, 3, []) and t_a[:2] == (1, 0) and len(t_a[2]) == 3
          and t_x[:2] == (1, 3) and t_x[2] == ['G9 the live daemon still agrees', 'G2 x'])
    return ok, f'active {a} paused {p[1][:60]} words {words} all {alls} tally {t_p} {t_a} {t_x}'


# ───────────────────────────── TR3 ─────────────────────────────
NOW = datetime.datetime(2026, 11, 2, 4, 30, tzinfo=datetime.timezone(datetime.timedelta(hours=-8)))
CAP = (NOW - datetime.timedelta(minutes=10)).isoformat(timespec='seconds')


def snaps(miner_up=False, derod_up=True, derod_alert=None, healthy=False, down_alert=True):
    run = {'version': 'v1', 'start': '2026-11-02T00:53:03', 'end': '2026-11-02T02:04:08', 'hours': 1.18, 'split': {},
           'hashrate': {'mean': 94000}, 'shares': {}, 'gpu_mode': 'split',
           'alerts': [] if healthy else [{'rule': 'miner_silent', 'level': 'ALERT', 'what': 'last record 139 min old'}]}
    mi = {'captured': CAP, 'tree_version': 'v1', 'logs': ['dero-miner.log'], 'runs': [run]}
    al = [] if (healthy or miner_up) else [{'rule': 'endpoint_down', 'level': 'ALERT', 'what': 'miner /metrics did not answer'}]
    if not derod_up and down_alert:
        al.append({'rule': 'endpoint_down', 'level': 'ALERT', 'what': 'derod /metrics did not answer'})
    if derod_alert:
        al.append({'rule': derod_alert, 'level': 'ALERT', 'what': 'sync status syncing'})
    mt = {'captured': CAP, 'up': {'derod': derod_up, 'miner': healthy or miner_up}, 'alerts': al,
          'derod': {'sync_status': 'synced', 'tip_age_s': 20}, 'miner': {}}
    mr = {'captured': CAP, 'validation': [], 'ledger_checks': {}, 'payout': {'error': 'no runs'}}
    return (mi, 'minerintel_x.json'), (mt, 'metrics_x.json'), (mr, 'minerruns_x.json')


def tr3(base):
    G = load(base, 'gates')
    P = ('paused', "harness/round.json rounds[r24].tracks.miner = 'paused' (artifacts/dero-rft.md §0.3)")
    A = ('active', 'test')
    mg = lambda s, t, **k: [(n[:3], ok, d) for n, ok, d in G.miner_gates(*s, 'v1', t, now=NOW)]
    act = mg(snaps(), A)
    pau = mg(snaps(), P)
    hea = mg(snaps(healthy=True), A)
    d_down = mg(snaps(derod_up=False), P)
    d_sync = mg(snaps(derod_alert='not_synced'), P)
    d_up = mg(snaps(derod_up=False, down_alert=False), P)     # 'up' alone, no ALERT row
    none = [(n[:3], ok, d) for n, ok, d in G.miner_gates((None, None), (None, None), (None, None), 'v1', P, now=NOW)]
    want_act = [G.g17_gate(snaps()[0][0], 'minerintel_x.json', NOW), G.g18_gate(snaps()[1][0], 'metrics_x.json', 'v1', NOW),
                G.g21_gate(snaps()[2][0], 'minerruns_x.json', NOW)]
    ok = ([x[1] for x in act] == [False, False, False] and [x[1:] for x in act] == [tuple(w) for w in want_act]
          and [x[1] for x in pau] == ['PAUSED'] * 3 and all('said FAIL' in x[2] and '§0.3' in x[2] for x in pau)
          and [x[1] for x in hea[:2]] == [True, True]
          and [x[1] for x in d_down] == ['PAUSED', False, 'PAUSED'] and 'derod half FAILS' in d_down[1][2]
          and [x[1] for x in d_sync] == ['PAUSED', False, 'PAUSED'] and 'not_synced' in d_sync[1][2]
          and [x[1] for x in none] == ['PAUSED', False, 'PAUSED']
          and [x[1] for x in d_up] == ['PAUSED', False, 'PAUSED'] and 'did not answer' in d_up[1][2])
    return ok, (f"active {[x[1] for x in act]} paused {[x[1] for x in pau]} healthy {[x[1] for x in hea]} "
                f"derod-down {[x[1] for x in d_down]} not_synced {[x[1] for x in d_sync]} none {[x[1] for x in none]}")


# ───────────────────────────── TR4 ─────────────────────────────
def tr4(base):
    G = load(base, 'gates')
    rec = {'run': 'p1', 'mode': 'full', 'stages': {'minerbench': {'status': 'PAUSED'}, 'gpubench': {'status': 'PAUSED'}}}
    real = {'run': 'p0', 'mode': 'full', 'stages': {'minerbench': {'status': 'PASS', 'contention': {'contended': False}},
                                                     'gpubench': {'status': 'SKIP'}}}
    mt = {'contention': {'contended': False, 'regression_claims': 'allowed'}, 'alerts': []}
    pa = G.pipeline_for_ab(rec, None, state='paused')[0]
    aa = G.pipeline_for_ab(rec, None, state='active')[0]
    af = G.pipeline_for_ab(rec, real, state='active')[0]
    dflt = G.pipeline_for_ab(real, None)[0]
    g_p = G.g20_contention(mt, None, rec, require_ab=True, state='paused')
    g_a = G.g20_contention(mt, None, rec, require_ab=True, state='active')
    g_r = G.g20_contention(mt, None, real, require_ab=True)
    ok = (pa is rec and aa is None and af is real and dflt is real and g_p[0] and 'PAUSED (miner' in g_p[1]
          and not g_a[0] and 'PAUSED while the miner track is active' in g_a[1] and g_r[0])
    return ok, f'paused->{bool(pa)} active->{aa} fallback->{bool(af)} g20 paused {g_p[0]} active {g_a[0]} real {g_r[0]}'


# ───────────────────────────── TR5 ─────────────────────────────
def tr5(base):
    RT = load(base, 'rt')
    sp = [RT.stage_paused('paused', [])[0], RT.stage_paused('paused', ['cmd/dero-miner/miner.go'])[0],
          RT.stage_paused('paused', None)[0], RT.stage_paused('active', [])[0]]
    F = load(base, 'fbv')
    tmp = Path(tempfile.mkdtemp(prefix='tr5-'))
    F.EVENTS = tmp / 'events.jsonl'
    F.SUMMARY = {'run': 'x', 'stages': {}, 'ok': False, 'mode': 'full'}
    F.NEW_TESTS_BASE = 'cf89e78'
    F.miner_sources_changed = lambda base: []
    F.MINER_TRACK = ('active', 'test')
    r_active = F.stage_paused('minerbench')
    st_active = dict(F.SUMMARY['stages'])
    F.MINER_TRACK = ('paused', "rounds[r24].tracks.miner = 'paused' (artifacts/dero-rft.md §0.3)")
    r_paused = F.stage_paused('minerbench')
    st_paused = F.SUMMARY['stages'].get('minerbench') or {}
    F.miner_sources_changed = lambda base: ['astrobwt/astrobwtv3/x.go']
    r_changed = F.stage_paused('gpubench')
    fr = F.full_record(F.SUMMARY)
    shutil.rmtree(tmp, ignore_errors=True)
    ok = (sp == [True, False, False, False] and r_active is False and st_active == {} and r_paused is True
          and st_paused.get('status') == 'PAUSED' and '§0.3' in str(st_paused.get('why')) and r_changed is False
          and 'gpubench' not in F.SUMMARY['stages'] and fr)
    return ok, f'roundtracks {sp} fbv active {r_active} paused {r_paused} {st_paused.get("status")} changed {r_changed} full_record {fr}'


# ───────────────────────────── TR6 ─────────────────────────────
def tr6(base):
    GM, F = load(base, 'gm'), load(base, 'fbv')
    d = json.loads((HARNESS / 'loop/KNOWN_TEST_FAILURES.json').read_text())
    bad = []
    for e in d['tests']:
        if e.get('class') not in ('upstream-red', 'flaky') or not e.get('evidence') or not e.get('why'):
            bad.append(f"malformed {e.get('test')}")
        for ev in e.get('evidence') or []:
            if not (ROOT / ev.split(':')[0]).exists():
                bad.append(f"{e['test']}: evidence {ev} missing")
        pat = f"func {e['test']}("
        if e.get('class') == 'flaky':
            if not any(pat in f.read_text(errors='replace') for f in (ROOT / e['pkg']).glob('*_test.go')):
                bad.append(f"{e['test']}: flaky test not in this tree")
        else:
            r = subprocess.run(['git', 'grep', '-q', '-F', pat, 'bf274e5', '--', e['pkg'].strip('./') + '/'], cwd=ROOT,
                               capture_output=True)
            if r.returncode != 0:
                bad.append(f"{e['test']}: upstream-red test not on bf274e5")
    gms = sorted((HARNESS / 'runtime').glob('gomut_*.json'))
    up = json.loads(gms[-1].read_text()).get('upstream_failures') or {} if gms else {}
    K = GM.load_known(base / 'loop/KNOWN_TEST_FAILURES.json')
    unlisted = [(p, t) for p, ts in up.items() for t in ts if t not in K['upstream-red'].get(p, set())]
    if unlisted:
        bad.append(f'newest gomut upstream failures not listed: {unlisted}')
    calls = []

    def rr(counts, race=False):
        def f(pkg, tests):
            calls.append((pkg, tuple(tests)))
            return counts, race
        return f
    cmp_ = lambda: {'./walletapi/': {'ours': ['TestNew', 'Test_R22_MultiPayload_Distinct_Blinders'],
                                     'upstream': ['TestOther', 'Test_Payload_TX'], 'fixed_here': []}}
    flk = 'Test_R22_MultiPayload_Distinct_Blinders'
    c3 = GM.relabel(cmp_(), K, rr({flk: {'pass': 3, 'fail': 0}}))['./walletapi/']
    c2 = GM.relabel(cmp_(), K, rr({flk: {'pass': 2, 'fail': 1}}))['./walletapi/']
    c1 = GM.relabel(cmp_(), K, rr({flk: {'pass': 1, 'fail': 2}}))['./walletapi/']
    cr = GM.relabel(cmp_(), K, rr({flk: {'pass': 3, 'fail': 0}}, race=True))['./walletapi/']
    rc_, race_ = GM.rerun_counts('\n'.join(json.dumps(x) for x in (
        {'Action': 'pass', 'Test': 'TestA'}, {'Action': 'fail', 'Test': 'TestA'}, {'Action': 'pass', 'Test': 'TestA/sub'},
        {'Action': 'output', 'Test': 'TestA', 'Output': 'ok'})) + '\nFAIL\n')
    _, race2 = GM.rerun_counts(json.dumps({'Action': 'output', 'Output': 'WARNING: DATA RACE\n'}))
    listed = {flk, 'TestStalledClientDoesNotBlockPushes'}
    v = [F.s3_retry_verdict([flk], listed, {flk: {'pass': 2, 'fail': 1}}, [])[0],
         F.s3_retry_verdict([flk], listed, {flk: {'pass': 1, 'fail': 2}}, [])[0],
         F.s3_retry_verdict([flk, 'TestNew'], listed, {flk: {'pass': 3, 'fail': 0}, 'TestNew': {'pass': 3, 'fail': 0}}, [])[0],
         F.s3_retry_verdict([], listed, {}, [])[0],
         F.s3_retry_verdict([flk], listed, {flk: {'pass': 3, 'fail': 0}}, [flk])[0],
         F.s3_retry_verdict([flk], listed, {flk: {'pass': 3, 'fail': 0}}, [], first_race=True)[0]]
    s3race = s3_first_run_race(F)          # r24 verify: a first-run DATA RACE of a listed flaky test still FAILS S3
    kf = F.known_failures(base / 'loop/KNOWN_TEST_FAILURES.json')
    ok = (not bad and c3['ours'] == ['TestNew'] and flk in c3['known_flaky'] and c2['ours'] == ['TestNew']
          and c1['ours'] == ['TestNew', flk] and cr['ours'] == ['TestNew', flk] and c3['upstream_unlisted'] == ['TestOther']
          and all(t == (flk,) for _, t in calls) and len(calls) == 4
          and rc_ == {'TestA': {'pass': 1, 'fail': 1}} and race_ is False and race2 is True
          and v == [True, False, False, False, False, False] and kf.get('./walletapi/', {}).get(flk) == 'flaky'
          and s3race == 'FAIL 7')
    return ok, (f'list problems {bad} · relabel 3/3 {c3["ours"]} 2/3 {c2["ours"]} 1/3 {c1["ours"]} race {cr["ours"]} '
                f'unlisted {c3["upstream_unlisted"]} reruns {calls} · counts {rc_} race {race_}/{race2} · s3 verdicts {v} '
                f'· s3 first-run race {s3race}')


def s3_first_run_race(F):
    """r24 verify: S3 with a mocked `go test`: the first -race run of the LISTED flaky TestStalledClientDoesNotBlockPushes
    reports a DATA RACE, the -count=3 re-run is clean. Pre-r24 S3 failed (finish 7); it must still. -> 'FAIL 7' | 'PASS'"""
    T = 'TestStalledClientDoesNotBlockPushes'
    race = f'=== RUN   {T}\nWARNING: DATA RACE\n    testing.go:1398: race detected during execution of test\n--- FAIL: {T} (1.00s)\nFAIL\n'
    clean = ''.join(f'=== RUN   {T}\n--- PASS: {T} (1.00s)\n' for _ in range(3)) + 'PASS\n'

    class Fin(Exception):
        pass

    def sh(cmd, timeout=None, cwd=None):
        if cmd[:2] == ['go', 'test'] and '-count=1' in cmd and '-race' in cmd:
            return 1, race, ''
        return 0, clean if '-count=3' in cmd else 'ok\n', ''

    def fin(code):
        raise Fin(code)
    F.sh, F.finish, F.event = sh, fin, (lambda *a, **k: None)
    F.NEW_TESTS, F.NORACE_NEW_TESTS = {'./cmd/derod/rpc/': T}, {}
    try:
        F.s3_test()
        return 'PASS'
    except Fin as e:
        return f'FAIL {e.args[0]}'


# ───────────────────────────── TR7 ─────────────────────────────
def tr7(base):
    RT, G, F = load(base, 'rt'), load(base, 'gates'), load(base, 'fbv')
    want = RT.track_state(RT.load(HARNESS / 'round.json'))
    rft = (ROOT / 'artifacts/dero-rft.md').read_text()
    sec = re.search(r'### 0\.3 Paused tracks: miner enhancements.*?\n\*\*State: (\w+)', rft, re.S)
    rft_ok = want[0] != 'paused' or (sec is not None and sec.group(1) == 'PAUSED')
    ok = G.TRACK == want and F.MINER_TRACK == want and rft_ok
    return ok, f'registry {want[0]} · gates {G.TRACK[0]} · pipeline {F.MINER_TRACK[0]} · §0.3 state {sec.group(1) if sec else None}'


KATS = [('TR1', tr1), ('TR2', tr2), ('TR3', tr3), ('TR4', tr4), ('TR5', tr5), ('TR6', tr6), ('TR7', tr7)]

MUTATIONS = [
    ('TR1', 'rt', "    if v == 'paused':\n        return 'paused'", "    if v in ('paused', 'active'):\n        return 'paused'",
     "'active' pauses the track (a paused skip while active)"),
    ('TR1', 'rt', "    if v == 'paused':\n        return 'paused'", "    if False:\n        return 'paused'", "'paused' is ignored"),
    ('TR1', 'rt', "    if v in (None, 'active'):\n        return 'active'", "    if v in (None, 'active') or True:\n        return 'active'",
     'an unknown value is silently active without its explanation'),
    ('TR1', 'rt', "            if v not in TRACK_VALUES:", "            if False:", 'an unknown track value passes the registry'),
    ('TR2', 'rt', "    if state != 'paused' or gate_id(name) not in PAUSABLE_GATES:", "    if gate_id(name) not in PAUSABLE_GATES:",
     'the miner gates pause while the track is active'),
    ('TR2', 'rt', "    if state != 'paused' or gate_id(name) not in PAUSABLE_GATES:", "    if True:", 'the miner gates ignore the pause'),
    ('TR2', 'rt', "    if state != 'paused' or gate_id(name) not in PAUSABLE_GATES:", "    if state != 'paused':",
     'every gate (G9, G13 ...) pauses with the miner'),
    ('TR2', 'rt', "        elif res == PAUSED and state == 'paused' and gate_id(g) in PAUSABLE_GATES:", "        elif res == PAUSED:",
     'S7 accepts any PAUSED row'),
    ('TR2', 'rt', "    return all(ok == PAUSED or bool(ok) for _, ok, _ in results)", "    return all(bool(ok) and ok != PAUSED for _, ok, _ in results)",
     'run_gates exits 3 on a legitimate pause'),
    ('TR3', 'gates', "        ok2, det2 = RT.gate_outcome(name, ok, det, state, why)", "        ok2, det2 = ok, det",
     'run_gates ignores the paused track'),
    ('TR3', 'gates', "        ok2, det2 = RT.gate_outcome(name, ok, det, state, why)", "        ok2, det2 = RT.gate_outcome(name, ok, det, 'paused', why)",
     'run_gates pauses the miner gates while active'),
    ('TR3', 'gates', "        if name == G18_NAME and ok2 == RT.PAUSED:", "        if False:", "G18's derod half is not judged while paused"),
    ('TR3', 'gates', "        why.append('derod /metrics did not answer')", "        pass", 'a derod endpoint down passes a paused G18'),
    ('TR4', 'gates', "        state == 'paused' or ((r.get('stages') or {}).get(st) or {}).get('status') != RT.PAUSED) for st in AB_STAGES)",
     "        True) for st in AB_STAGES)", 'a paused-only record is A/B evidence while active'),
    ('TR4', 'gates', "            if state != 'paused':\n                why.append(f'{st} PAUSED while", "            if False:\n                why.append(f'{st} PAUSED while",
     'G20 accepts a PAUSED stage while active'),
    ('TR5', 'rt', "    if changed:\n        return False", "    if False:\n        return False", 'a miner change while paused skips its A/B'),
    ('TR5', 'rt', "    if changed is None:\n        return False", "    if False:\n        return False", 'an unreadable diff pauses the A/B'),
    ('TR5', 'rt', "    if state != 'paused':\n        return False, 'miner track active", "    if False:\n        return False, 'miner track active",
     'S4b/S4c pause while the track is active'),
    ('TR5', 'fbv', "    if status in ('PASS', 'FAIL', 'SKIP', 'REFUSED', 'PAUSED'):", "    if status in ('PASS', 'FAIL', 'SKIP', 'REFUSED'):",
     'a PAUSED stage is not recorded (G20 and the record lose it)'),
    ('TR5', 'fbv', "    paused, why = RT.stage_paused(MINER_TRACK[0], miner_sources_changed(NEW_TESTS_BASE))",
     "    paused, why = RT.stage_paused(MINER_TRACK[0], [])", 'the pipeline never reads the miner-source diff'),
    ('TR6', 'gm', "    return 'known_flaky' if not race and (counts or {}).get('pass', 0) >= FLAKY_MIN_PASS else 'ours'",
     "    return 'known_flaky' if not race and (counts or {}).get('pass', 0) >= 1 else 'ours'", 'one clean re-run of 3 excuses a flaky test'),
    ('TR6', 'gm', "    return 'known_flaky' if not race and (counts or {}).get('pass', 0) >= FLAKY_MIN_PASS else 'ours'",
     "    return 'known_flaky' if (counts or {}).get('pass', 0) >= FLAKY_MIN_PASS else 'ours'", 'a racy re-run excuses a flaky test'),
    ('TR6', 'gm', "        fl = sorted(set(c['ours']) & (known.get('flaky', {}).get(pkg) or set()))", "        fl = sorted(set(c['ours']))",
     'an unlisted OURS failure is re-run and excused'),
    ('TR6', 'gm', "        c['upstream_unlisted'] = sorted(set(c['upstream']) - (known.get('upstream-red', {}).get(pkg) or set()))",
     "        c['upstream_unlisted'] = []", 'an unlisted upstream failure is not named'),
    ('TR6', 'fbv', "    ok = not first_race and bool(names) and all(n in listed for n in names) and all(", "    ok = not first_race and bool(names) and all(",
     'S3 excuses an unlisted failing test'),
    ('TR6', 'fbv', "        rec[n].get('pass', 0) >= FLAKY_MIN_PASS and n not in broken for n in names)",
     "        rec[n].get('pass', 0) >= FLAKY_MIN_PASS for n in names)", 'S3 excuses a racy re-run'),
    ('TR6', 'fbv', "    ok = not first_race and bool(names) and all(n in listed for n in names) and all(", "    ok = not first_race and all(n in listed for n in names) and all(",
     'S3 excuses a failed run with no failing test named'),
    ('TR6', 'fbv', "    ok = not first_race and bool(names)", "    ok = bool(names)",
     'r24 verify: the verdict excuses a first-run race after clean re-runs'),
    ('TR6', 'fbv', "    if RACE_MARK.search(first or ''):", "    if False:",
     'r24 verify: S3 re-runs (and excuses) a listed flaky test whose first run raced'),
    ('TR6', 'fbv', "s3_retry(pkg, race, failed, unmatched, out + err)", "s3_retry(pkg, race, failed, unmatched, '')",
     'r24 verify: S3 does not hand the first run to the retry'),
    ('TR7', 'gates', "TRACK = RT.track_state(RT.load(HERE / 'round.json'))", "TRACK = ('active', 'hard-coded')",
     'run_gates does not read the registry'),
    ('TR7', 'fbv', "MINER_TRACK = RT.track_state(ROUND_REG) if RT else", "MINER_TRACK = ('active', 'x') if RT else",
     'the pipeline does not read the registry'),
]


def copy_tree():
    d = Path(tempfile.mkdtemp(prefix='r24tr-')) / 'harness'
    for rel in list(MODS.values()) + EXTRA:
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HARNESS / rel, d / rel)
    for rel in EXTRA_DIRS:
        shutil.copytree(HARNESS / rel, d / rel, dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__', '.cache'))
    return d


def main():
    fails = 0
    base = copy_tree()
    for name, fn in KATS:
        try:
            ok, det = fn(base)
        except Exception as e:                                    # noqa: BLE001
            ok, det = False, f'{type(e).__name__}: {e}'
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:500]}")
    shutil.rmtree(base.parent, ignore_errors=True)
    missed, byname = 0, dict(KATS)
    for kat, mod, find, repl, why in MUTATIONS:
        d = copy_tree()
        p = d / MODS[mod]
        text = p.read_text()
        if text.count(find) != 1:
            print(f'  ??      {kat}: {why} — find text occurs {text.count(find)} times')
            missed += 1
            shutil.rmtree(d.parent, ignore_errors=True)
            continue
        p.write_text(text.replace(find, repl))
        try:                                                        # a mutant that does not load is INVALID, never CAUGHT
            load(d, mod)
        except Exception as e:                                      # noqa: BLE001
            print(f'  INVALID {kat}: {why} — mutant does not load ({type(e).__name__})')
            missed += 1
            shutil.rmtree(d.parent, ignore_errors=True)
            continue
        try:
            ok2 = byname[kat](d)[0]
        except Exception:                                          # noqa: BLE001 — a crash is a detection
            ok2 = False
        print(f"  {'proved ' if not ok2 else 'MISSED '} {kat}: {why}")
        missed += ok2
        shutil.rmtree(d.parent, ignore_errors=True)
    print(f'\nr24 round-tracks KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
