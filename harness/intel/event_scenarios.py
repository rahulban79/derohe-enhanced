#!/usr/bin/env python3
"""event_scenarios.py (r28, dero-rft §7 B47 B48 B57 B99, ledger L24-21) — every p2p event the live node has not had,
reproduced deterministically and checked on the same /metrics series the live node exports.

The live r27 derod had none of these events in 20,200 s (harness/runtime/r28_start_20261105.txt): no sync hold, no
block rejection, no inbound connection (B1). A feature that never fires live can still be CLOSED by test evidence if
(a) a scenario drives the real code path into the event, (b) the record shows the live counter moving exactly as the
rule says, and (c) the counter is on the live /metrics at 0, so the first organic event will be visible. This tool
runs the scenarios (one `go test` call, simulator chain in a temp dir, in-process or 127.0.0.1:<ephemeral>
connections only: never the live store, never port 11011, never the live derod), checks each rule on the records and
writes one record per run. With --metrics FILE (a saved read-only scrape of 127.0.0.1:10102/metrics) it also states,
per item, whether the live counter is registered and whether the event has happened yet.

  scenario  go test                              items            rules
  b99       TestR27SyncHoldLoopbackScenario      B47, B99         harness/intel/b99_scenario.py verify()
  chunk     TestR28ChunkLoopbackScenario         L24-21, B57      warm/cold PoW census, attributed rejection
  proven    TestR28ProvenLaneAdmissionScenario   B48              quota, lane, netgroup cap, exemption

  python3 -I harness/intel/event_scenarios.py [--metrics SCRAPE] [--json OUT]
  exit 0 every rule holds · 3 a rule failed · 2 a scenario recorded nothing
Writes harness/runtime/event_scenarios_<ts>.json.
"""
import argparse, datetime, importlib.util, json, os, re, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TESTS = {'b99': 'TestR27SyncHoldLoopbackScenario', 'chunk': 'TestR28ChunkLoopbackScenario',
         'proven': 'TestR28ProvenLaneAdmissionScenario'}
# the live series that will show each event on the running node (all pre-registered at 0)
LIVE = {
    'B47': ['p2p_sync_peer_holds_total', 'p2p_sync_short_answers_total'],
    'B99': ['p2p_sync_strike_decays_total', 'p2p_sync_served_forgiven_total', 'p2p_sync_relay_forgiven_total',
            'p2p_sync_held_fallbacks_total'],
    'B57': ['blockchain_block_rejected_total{reason="future_timestamp"}', 'blockchain_block_rejected_total{reason="invalid_pow"}'],
    'B48': ['p2p_inbound_proven_quota_evictions_total', 'p2p_inbound_proven_lane_admits_total',
            'p2p_inbound_proven_lane_refusals_total', 'p2p_inbound_netgroup_refusals_total'],
    'L24-21': ['p2p_chunk_pow_blocks_total', 'p2p_chunk_pow_checks_total', 'p2p_chunk_pow_pool_seen_total',
               'p2p_chunk_pow_slow_total', 'p2p_chunk_pow_verify_seconds_total'],
}
ITEMS = {'b99': ('B47', 'B99'), 'chunk': ('L24-21', 'B57'), 'proven': ('B48',)}
SLOW_TOLERANCE = 1  # a cache hit may be descheduled past 1 ms once on a loaded box: the timing proxy allows one


def _b99_verify():
    sp = importlib.util.spec_from_file_location('b99_scenario', Path(__file__).resolve().parent / 'b99_scenario.py')
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m.verify


def verify_chunk(steps):
    """[(rule, ok, detail)] for the chunk scenario steps. Pure."""
    s = {x['step']: x for x in steps}
    out = []

    def rule(name, cond, detail):
        out.append((name, bool(cond), detail))
    missing = [k for k in ('warm', 'cold', 'rejected-future') if k not in s]
    rule('chunk: all steps recorded', not missing, f'missing {missing}' if missing else f'{len(steps)} steps')
    if missing:
        return out
    w, c, r = s['warm'], s['cold'], s['rejected-future']
    rule('L24-21: every miniblock checked once per block', all(x['p2p_chunk_pow_blocks_total'] == 1 and x['p2p_chunk_pow_checks_total'] == 10
                                                              for x in (w, c, r)), (w, c, r))
    rule('L24-21: warm block finds its 9 regular miniblocks in the pool', w['p2p_chunk_pow_pool_seen_total'] == 9, w)
    rule('L24-21: cold block finds none', c['p2p_chunk_pow_pool_seen_total'] == 0, c)
    rule('L24-21: the cache explains the timing (slow = checks - pool_seen)',
         all(abs(x['p2p_chunk_pow_slow_total'] - (x['p2p_chunk_pow_checks_total'] - x['p2p_chunk_pow_pool_seen_total'])) <= SLOW_TOLERANCE
             for x in (w, c)), (w['p2p_chunk_pow_slow_total'], c['p2p_chunk_pow_slow_total']))
    rule('L24-21: warm and cold blocks are accepted', w['height_after'] == w['height_before'] + 1 and c['height_after'] == c['height_before'] + 1, (w, c))
    rej = r.get('blockchain_block_rejected_total') or {}
    rule('B57: the rejection is counted by reason on /metrics (one series, +1)',
         rej == {'blockchain_block_rejected_total{reason="future_timestamp"}': 1} and r['height_after'] == r['height_before'], r)
    rule('B57: GetConsensusStats carries the same count', (r.get('getconsensusstats_block_rejected') or {}).get('future_timestamp') == 1, r)
    rule('B57: one console line names the sender by peer_id, never its address',
         r['block_rejected_lines'] == 1 and re.fullmatch(r'[0-9a-f]{16}', r.get('reject_line_peer_id') or '') is not None
         and r['reject_line_reason'] == 'future_timestamp' and r['reject_line_level'] == 0 and not r['reject_line_has_address'], r)
    return out


def verify_proven(steps, proven_max=4096, per_group=64):
    """[(rule, ok, detail)] for the B48 scenario steps. Pure."""
    s = {x['step']: x for x in steps}
    out = []

    def rule(name, cond, detail):
        out.append((name, bool(cond), detail))
    missing = [k for k in ('operator-flood', 'lane', 'netgroup-cap', 'exempt') if k not in s]
    rule('proven: all steps recorded', not missing, f'missing {missing}' if missing else f'{len(steps)} steps')
    if missing:
        return out
    f, la, cap, ex = s['operator-flood'], s['lane'], s['netgroup-cap'], s['exempt']
    m = lambda x, k: (x.get('metrics_delta') or {}).get(k)                           # noqa: E731
    rule('B48: one /16 cannot evict an honest proof (quota evictions = flood - quota)',
         f['honest_survivors'] == 100 and m(f, 'p2p_inbound_proven_quota_evictions_total') == proven_max - per_group, f)
    rule('B48: a returning peer passes a drained bucket once, a repeat and a stranger do not',
         la['admitted'] == 1 and la['refused'] == 2 and m(la, 'p2p_inbound_proven_lane_admits_total') == 1
         and m(la, 'p2p_inbound_proven_lane_refusals_total') == 1, la)
    rule('B48: a full netgroup is refused and counted', cap['admitted'] == 0 and m(cap, 'p2p_inbound_netgroup_refusals_total') == 1, cap)
    rule('B48: loopback / LAN proofs are quota-exempt', ex['netgroups_held'] == f['netgroups_held'], ex)
    return out


def parse_metrics(text):
    """{series: value} from a Prometheus text scrape. Pure."""
    out = {}
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        k, _, v = line.rpartition(' ')
        try:
            out[k] = float(v)
        except ValueError:
            pass
    return out


def live_status(scrape):
    """{item: {series: value or None}, ...} and a verdict per item: 'event seen' / 'registered, no event' / 'absent'."""
    res = {}
    for item, names in LIVE.items():
        vals = {n: scrape.get(n) for n in names}
        if any(v is None for v in vals.values()):
            verdict = 'absent (binary without the counter)'
        elif any(v > 0 for v in vals.values()):
            verdict = 'event seen'
        else:
            verdict = 'registered, no event'
        res[item] = {'series': vals, 'verdict': verdict}
    return res


def run_go(root=ROOT):
    with tempfile.TemporaryDirectory(prefix='r28evs-') as td:
        b99 = Path(td) / 'b99.json'
        pat = '^(' + '|'.join(TESTS.values()) + ')$'
        cmd = ['nice', '-n', '15', 'go', 'test', '-p', '1', '-count=1', '-run', pat, './p2p/']
        env = dict(os.environ, R27_B99_SCENARIO_OUT=str(b99), R28_EVENT_OUT_DIR=td)
        r = subprocess.run(cmd, cwd=root, env=env, capture_output=True, text=True, timeout=900)
        recs = {}
        for name, f in (('b99', b99), ('chunk', Path(td) / 'chunk_scenario.json'), ('proven', Path(td) / 'proven_scenario.json')):
            recs[name] = json.loads(f.read_text()) if f.exists() else None
    return cmd, r.returncode, (r.stdout + r.stderr)[-2000:], recs


def evaluate(recs):
    """{scenario: [(rule, ok, detail)]} for the records (None = not recorded). Pure."""
    out = {}
    for name, rec in recs.items():
        if rec is None:
            out[name] = [(f'{name}: recorded', False, 'no record')]
        elif name == 'b99':
            out[name] = _b99_verify()(rec['steps'])
        elif name == 'chunk':
            out[name] = verify_chunk(rec['steps'])
        else:
            out[name] = verify_proven(rec['steps'], rec.get('proven_max', 4096), rec.get('proven_per_netgroup', 64))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--metrics', help='a saved read-only /metrics scrape of the live node')
    ap.add_argument('--json', help='also write the record here')
    a = ap.parse_args()
    cmd, rc, tail, recs = run_go()
    ver = evaluate(recs)
    live = live_status(parse_metrics(Path(a.metrics).read_text())) if a.metrics else None
    ok = rc == 0 and all(ok for v in ver.values() for _, ok, _ in v)
    rec = {'tool': 'harness/intel/event_scenarios.py', 'command': ' '.join(cmd), 'go_test_exit': rc,
           'when': datetime.datetime.now().astimezone().isoformat(timespec='seconds'), 'records': recs,
           'rules': {k: [{'rule': n, 'ok': o} for n, o, _ in v] for k, v in ver.items()},
           'items': {k: list(v) for k, v in ITEMS.items()}, 'live_series': LIVE, 'live': live, 'ok': ok}
    stamp = datetime.datetime.now().strftime('%Y%m%dT%H%M%S')
    dest = ROOT / 'harness' / 'runtime' / f'event_scenarios_{stamp}.json'
    dest.write_text(json.dumps(rec, indent=1) + '\n')
    if a.json:
        Path(a.json).write_text(json.dumps(rec, indent=1) + '\n')
    for k, v in ver.items():
        print(f'{k} ({", ".join(ITEMS[k])}):')
        for n, o, _ in v:
            print(f"  {'ok  ' if o else 'FAIL'} {n}")
    if live:
        for item, x in live.items():
            print(f'  live {item}: {x["verdict"]}')
    if any(r is None for r in recs.values()):
        print(f'event_scenarios: a scenario recorded nothing (go test exit {rc})\n{tail}')
        return 2
    n_ok = sum(o for v in ver.values() for _, o, _ in v)
    n = sum(len(v) for v in ver.values())
    print(f"event_scenarios: {'PASS' if ok else 'FAIL'} ({n_ok}/{n} rules, go test exit {rc}) -> harness/runtime/{dest.name}")
    return 0 if ok else 3


if __name__ == '__main__':
    sys.exit(main())
