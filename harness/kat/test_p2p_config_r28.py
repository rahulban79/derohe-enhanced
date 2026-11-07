#!/usr/bin/env python3
"""KATs + mutation proofs for the r28 p2p-config tools (dero-rft §7 B47 B48 B57 B99, L24-21; config documented vs used):
harness/intel/event_scenarios.py (verify_chunk, verify_proven, parse_metrics, live_status) and
harness/intel/config_truth.py (go_consts, evaluate, grade, tag_rule). Synthetic inputs only (no go test run here); the
step fixtures are the records of the builder run harness/runtime/event_scenarios_20261106T004506.json.

  ES1 the recorded chunk steps (warm 9/10 pool-seen, cold 0/10, attributed future-timestamp rejection) pass every rule
  ES2 a warm block whose miniblocks were not found in the pool, or a timing census the cache does not explain, fails
  ES3 a rejection line that carries the peer's address, or a rejection counted under two reasons, fails B57
  ES4 the recorded B48 steps pass; an evicted honest proof or a lane admitting a repeat fails
  ES5 live_status: absent series = binary without the counter, all 0 = registered no event, one > 0 = event seen
  CT1 the constant evaluator: literals, typed conversions, N * time.Unit, 1 << N, one named constant, const blocks
  CT2 grade: equal = AGREE, different = DRIFT, the stating sentence gone = DRIFT, no source = MISSING, no text = UNDOCUMENTED
  CT3 tag rule: the newest registered suffix passes; an unregistered tag, a tag behind the registry, no metadata fail,
      each with its own cause

  python3 -I harness/kat/test_p2p_config_r28.py   # exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught
"""
import copy, importlib.util, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ES, CT, B99 = 'intel/event_scenarios.py', 'intel/config_truth.py', 'intel/b99_scenario.py'


def _step(step, blocks, checks, seen, slow, hb, ha, rej=None, stats=None, lines=0, pid='', reason='', level=0, addr=False):
    return {'step': step, 'p2p_chunk_pow_blocks_total': blocks, 'p2p_chunk_pow_checks_total': checks,
            'p2p_chunk_pow_pool_seen_total': seen, 'p2p_chunk_pow_slow_total': slow, 'height_before': hb, 'height_after': ha,
            'blockchain_block_rejected_total': rej or {}, 'getconsensusstats_block_rejected': stats or {},
            'block_rejected_lines': lines, 'reject_line_peer_id': pid, 'reject_line_reason': reason,
            'reject_line_level': level, 'reject_line_has_address': addr}


CHUNK = [_step('warm', 1, 10, 9, 1, 4, 5), _step('cold', 1, 10, 0, 10, 5, 6),
         _step('rejected-future', 1, 10, 0, 10, 6, 6, {'blockchain_block_rejected_total{reason="future_timestamp"}': 1},
               {'future_timestamp': 1}, 1, '0000000000002801', 'future_timestamp', 0, False)]


def _p(step, adm, ref, surv, groups, nr, la, lr, ev):
    return {'step': step, 'admitted': adm, 'refused': ref, 'honest_survivors': surv, 'netgroups_held': groups,
            'metrics_delta': {'p2p_inbound_netgroup_refusals_total': nr, 'p2p_inbound_proven_lane_admits_total': la,
                              'p2p_inbound_proven_lane_refusals_total': lr, 'p2p_inbound_proven_quota_evictions_total': ev}}


PROVEN = [_p('operator-flood', 0, 0, 100, 101, 0, 0, 0, 4032), _p('lane', 1, 2, 100, 101, 0, 1, 1, 4032),
          _p('netgroup-cap', 0, 1, 100, 101, 1, 1, 1, 4032), _p('exempt', 0, 0, 100, 101, 1, 1, 1, 4032)]


def load(base, f):
    sp = importlib.util.spec_from_file_location(f'r28pc_{abs(hash((str(base), f)))}', base / f)
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


def failed(rules):
    return {n for n, ok, _ in rules if not ok}


def es1(base):
    f = failed(load(base, ES).verify_chunk(CHUNK))
    return not f, f'failed {sorted(f)}'


def es2(base):
    m = load(base, ES)
    a = copy.deepcopy(CHUNK)
    a[0]['p2p_chunk_pow_pool_seen_total'] = 0
    b = copy.deepcopy(CHUNK)
    b[1]['p2p_chunk_pow_slow_total'] = 3            # 10 cold checks, only 3 slow: the cache does not explain it
    fa, fb = failed(m.verify_chunk(a)), failed(m.verify_chunk(b))
    return ('L24-21: warm block finds its 9 regular miniblocks in the pool' in fa and
            'L24-21: the cache explains the timing (slow = checks - pool_seen)' in fb), f'{sorted(fa)} / {sorted(fb)}'


def es3(base):
    m = load(base, ES)
    a = copy.deepcopy(CHUNK)
    a[2]['reject_line_has_address'] = True
    b = copy.deepcopy(CHUNK)
    b[2]['blockchain_block_rejected_total']['blockchain_block_rejected_total{reason="invalid_block"}'] = 1
    fa, fb = failed(m.verify_chunk(a)), failed(m.verify_chunk(b))
    return ('B57: one console line names the sender by peer_id, never its address' in fa and
            'B57: the rejection is counted by reason on /metrics (one series, +1)' in fb), f'{sorted(fa)} / {sorted(fb)}'


def es4(base):
    m = load(base, ES)
    good = failed(m.verify_proven(PROVEN))
    a = copy.deepcopy(PROVEN)
    a[0]['honest_survivors'] = 99
    b = copy.deepcopy(PROVEN)
    b[1]['admitted'], b[1]['refused'] = 2, 1
    fa, fb = failed(m.verify_proven(a)), failed(m.verify_proven(b))
    return (not good and 'B48: one /16 cannot evict an honest proof (quota evictions = flood - quota)' in fa and
            'B48: a returning peer passes a drained bucket once, a repeat and a stranger do not' in fb), f'{sorted(good)} {sorted(fa)} {sorted(fb)}'


def es5(base):
    m = load(base, ES)
    scrape = m.parse_metrics('# HELP x\np2p_sync_peer_holds_total 0\np2p_sync_short_answers_total 2\n'
                             'p2p_sync_strike_decays_total 0\np2p_sync_served_forgiven_total 0\np2p_sync_relay_forgiven_total 0\n'
                             'p2p_sync_held_fallbacks_total 0\n')
    st = m.live_status(scrape)
    return (st['B47']['verdict'] == 'event seen' and st['B99']['verdict'] == 'registered, no event'
            and st['L24-21']['verdict'].startswith('absent')), {k: v['verdict'] for k, v in st.items()}


def ct1(base):
    m = load(base, CT)
    c = m.go_consts('const A = 25\nconst B = int64(8)\nconst C = 10 * time.Minute\nconst D = C // same\n'
                    'const (\n\tE = 1 << 16\n\tF = 2.5\n)\nvar G = 7\nconst H uint64 = 3 * time.Millisecond\n')
    v = {k: m.evaluate(c[k], c) for k in c}
    want = {'A': 25, 'B': 8, 'C': 600, 'D': 600, 'E': 65536, 'F': 2.5, 'H': 0.003}
    ok = all(v.get(k) is not None and abs(v[k] - w) < 1e-12 for k, w in want.items()) and 'G' not in c
    return ok, str(v)


def ct2(base):
    m = load(base, CT)
    got = (m.grade(25, 25.0), m.grade(25, 24.0), m.grade(25, 'absent'), m.grade(None, 25.0), m.grade(64, None))
    return got == ('AGREE', 'DRIFT', 'DRIFT', 'MISSING', 'UNDOCUMENTED'), str(got)


def ct3(base):
    m = load(base, CT)
    reg = {'current': 'r28', 'rounds': [{'id': 'r26', 'version_suffix': '22102026.r26'}, {'id': 'r27', 'version_suffix': '22102026.r27'},
                                        {'id': 'r28', 'version_suffix': 'pending'}, {'id': 'r29', 'version_suffix': '22102026.r29'}]}
    v = lambda t: f'var Version = semver.MustParse("3.6.0-153.DEROHE.STARGATE+{t}")'           # noqa: E731
    r = (m.tag_rule(v('22102026.r27'), reg)[0], m.tag_rule(v('22102026.r29'), reg)[0], m.tag_rule(v('22102026.r26'), reg)[0],
         m.tag_rule('var Version = semver.MustParse("3.6.0-153.DEROHE.STARGATE")', reg)[0])
    why = (m.tag_rule(v('22102026.r29'), reg)[1], m.tag_rule(v('22102026.r26'), reg)[1])  # each failure names its cause
    return (r == (True, False, False, False) and 'not a version_suffix the registry assigned' in why[0]
            and 'is behind the registry' in why[1]), f'{r} {why}'


KATS = [('ES1', es1), ('ES2', es2), ('ES3', es3), ('ES4', es4), ('ES5', es5), ('CT1', ct1), ('CT2', ct2), ('CT3', ct3)]
MUTATIONS = [
    (ES, 'ES2', "w['p2p_chunk_pow_pool_seen_total'] == 9", "w['p2p_chunk_pow_pool_seen_total'] >= 0", 'a cold warm block passes'),
    (ES, 'ES2', '<= SLOW_TOLERANCE', '<= 99', 'any timing census passes'),
    (ES, 'ES3', "and not r['reject_line_has_address']", '', 'a line with the address passes'),
    (ES, 'ES3', "rej == {'blockchain_block_rejected_total{reason=\"future_timestamp\"}': 1}",
     "rej.get('blockchain_block_rejected_total{reason=\"future_timestamp\"}') == 1", 'a second reason passes'),
    (ES, 'ES4', "f['honest_survivors'] == 100 and", '', 'an evicted honest proof passes'),
    (ES, 'ES4', "la['admitted'] == 1 and la['refused'] == 2", "la['admitted'] >= 1", 'a repeat admission passes'),
    (ES, 'ES5', 'elif any(v > 0 for v in vals.values()):', 'elif False:', 'an event is never reported'),
    (ES, 'ES5', "verdict = 'absent (binary without the counter)'", "verdict = 'registered, no event'", 'a missing counter reads as no event'),
    (CT, 'CT1', "if e in UNIT:\n        return UNIT[e]\n    if re.fullmatch(r'[A-Za-z_]\\w*', e) and e in consts:",
     "if e in UNIT:\n        return UNIT[e]\n    if False:", 'a named constant is not resolved'),
    (CT, 'CT1', 'return int(m.group(1)) << int(m.group(2))', 'return int(m.group(1))', 'a shift is ignored'),
    (CT, 'CT2', "        return 'DRIFT'          # the sentence", "        return 'AGREE'          # the sentence", 'a vanished sentence passes'),
    (CT, 'CT2', "return 'AGREE' if abs(float(code) - float(doc)) < 1e-9 else 'DRIFT'", "return 'AGREE'", 'any drift passes'),
    (CT, 'CT3', "    if tag != known[-1]:\n", "    if False:\n", 'a tag behind the registry passes'),
    (CT, 'CT3', "    if tag not in known:\n", "    if False:\n", 'an unregistered tag passes'),
]


def copy_base():
    d = Path(tempfile.mkdtemp(prefix='r28pc-'))
    (d / 'intel').mkdir(parents=True)
    for f in (ES, CT, B99):
        shutil.copy2(HARNESS / f, d / f)
    return d


def main():
    fails, base = 0, copy_base()
    for n, fn in KATS:
        try:
            ok, det = fn(base)
        except Exception as e:                                      # noqa: BLE001
            ok, det = False, f'{type(e).__name__}: {e}'
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {n} {str(det)[:200]}")
    shutil.rmtree(base, ignore_errors=True)
    missed, by = 0, dict(KATS)
    for f, k, find, repl, why in MUTATIONS:
        d = copy_base()
        t = (d / f).read_text()
        if t.count(find) != 1:
            print(f'  ??      {k}: {why} — find text occurs {t.count(find)} times')
            missed += 1
            continue
        (d / f).write_text(t.replace(find, repl))
        try:
            ok2, _ = by[k](d)
            v = 'MISSED ' if ok2 else 'proved '
        except Exception as e:                                       # noqa: BLE001
            ok2, v = True, f'INVALID ({type(e).__name__})'
        print(f'  {v} {k}: {why}')
        missed += ok2
        shutil.rmtree(d, ignore_errors=True)
    print(f'\nR28 p2p-config KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
