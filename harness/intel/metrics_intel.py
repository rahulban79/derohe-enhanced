#!/usr/bin/env python3
"""metrics_intel.py — one READ-ONLY snapshot of the live dashboard: derod's and dero-miner's /metrics, aggregated.

Both processes export Prometheus text since r19: derod on its RPC port (cmd/derod/rpc/node_metrics.go, 10102) and
the miner on --metrics-bind (cmd/dero-miner/metrics.go, 127.0.0.1:10110). This tool GETs each endpoint TWICE,
`--interval` seconds apart, so counters become rates (a cumulative counter alone says nothing about now), derives
the numbers the operator watches, cross-checks the two processes against each other, applies RULES and writes
harness/runtime/metrics_<ts>.json with one anchorable fact per line. Nothing is ever POSTed; nothing is written
outside harness/runtime/.

  python3 -I harness/intel/metrics_intel.py [--derod URL] [--miner URL] [--interval 15] [--out file] [--json-only]
Exit 0 · 7 an ALERT fired · 2 neither endpoint answered.
r27: while harness/round.json names the miner track 'paused' (rft §0.3, kit/roundtracks.py), a miner ALERT (its
endpoint_down included) stays in the snapshot but is reported as PAUSED (miner) and does not set exit 7: 7 is then a
node ALERT only (the snapshot's 'exit' block says which). --registry FILE reads another registry.
"""
import argparse, datetime, importlib.util, json, re, sys, time, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent
DEROD = 'http://127.0.0.1:10102/metrics'
MINER = 'http://127.0.0.1:10110/metrics'
LINE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{([^}]*)\})?\s+(\S+)')
LABEL = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
HEIGHT_SLACK = 2          # the miner's job height may trail derod's tip by a block while a job is in flight
STALE_WARN = 0.05         # miner_intel drop_fraction rule: > 5 % of staged nonces dropped stale
# R22: over 721 s of 2026-10-29 06:44-06:56 the live r21 miner's H/s followed the CPU cores it got (24 windows of 30 s:
# H/s = 4,817 x cores + 8,000, r = 0.991) while other agents loaded the box (load average 43): 13.0 cores of an 18-core
# --cpu-max budget gave 70.6k, against 84k at 16 cores. A CPU-sort-bound split below 80 % of its budget is starved by
# other processes, not by its own limit.
STARVED_BUDGET = 0.80


def _miner_intel():
    """miner_intel from THIS directory (not sys.path), so the log and /metrics share one regime classifier"""
    spec = importlib.util.spec_from_file_location(f'miner_intel_for_metrics_{id(HERE)}', HERE / 'miner_intel.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


MI = _miner_intel()


def _contention():
    """contention.py from THIS directory (R23): the foreign-process census and the contention law"""
    spec = importlib.util.spec_from_file_location(f'contention_for_metrics_{id(HERE)}', HERE / 'contention.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


CT = _contention()


def _roundtracks():
    """kit/roundtracks.py of THIS harness (r27): the miner-track state and the shared miner-ALERT classifier"""
    spec = importlib.util.spec_from_file_location(f'roundtracks_for_metrics_{id(HERE)}', HARNESS / 'kit/roundtracks.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


RT = _roundtracks()


def exit_block(rep, track):
    """r27: the snapshot's 'exit' block {rc, why, track, paused_alerts} from its alerts, endpoints and the
    (state, why) miner track. Pure."""
    rc, why, paused = RT.metrics_exit(rep.get('alerts'), rep.get('up'), track[0])
    return {'rc': rc, 'why': why, 'track': {'miner': track[0], 'why': track[1]}, 'paused_alerts': paused}

RULES = {
    'endpoint_down': 'ALERT: a /metrics endpoint did not answer (the process is down, or metrics are not bound)',
    'not_synced': 'ALERT: derod reports dero_sync_status other than "synced"',
    'tip_age': 'ALERT: the tip block is older than 600 s (GetInfo cannot show this; the metric reads the tip itself)',
    'miner_disconnected': 'ALERT: dero_miner_connected is 0 — the miner has no getwork session',
    'miner_behind': 'ALERT: the miner\'s job height trails derod\'s chain height by more than 2 — it hashes stale work',
    'split_disabled': 'ALERT: the GPU split turned itself off (dero_miner_split_disabled 1)',
    'gpu_mismatch': 'ALERT: a GPU/split hash disagreed with the CPU re-hash',
    'no_hashing': 'ALERT: the miner\'s hash counter did not advance between the two samples',
    'no_miner_on_node': 'WARN: the miner is up but derod counts 0 getwork miners — they are talking to different nodes',
    'recovered_panics': 'WARN: derod recovered from a panic since it started (recovered_panics_total > 0)',
    'version_skew': 'WARN: derod and the miner run different builds',
    'split_stale': 'WARN: more than 5 % of the nonces the GPU split finished in the sample were dropped as stale',
    'cpu_starved': 'WARN: the split is CPU-sort-bound while the miner got less than 80 % of its --cpu-max core budget — '
                   'other processes are taking its CPU (R22: H/s tracks cores at r = 0.991); R23: the census names them',
    'box_contended': 'WARN: foreign processes take more cores than the box has left after the miner\'s --cpu-max budget '
                     'and derod (R23 census, process names only): no A/B and no hashrate regression may be claimed from '
                     'this reading (regression_claims refused; gate G20)',
    'cpu_starved_unattributed': 'WARN: the miner got less than 80 % of its core budget while the census finds no foreign '
                                'contention — the limit is inside the miner (throttle, cgo yield, GPU feed), not the box',
}


def parse(text):
    """Prometheus text -> {name: {labels-tuple: value}}; labels-tuple is sorted (key, value) pairs"""
    out = {}
    for l in text.splitlines():
        if not l or l.startswith('#'):
            continue
        m = LINE.match(l)
        if not m:
            continue
        try:
            v = float(m.group(4))
        except ValueError:
            continue
        labels = tuple(sorted(LABEL.findall(m.group(3) or '')))
        out.setdefault(m.group(1), {})[labels] = v
    return out


def val(M, name, default=None, **labels):
    """one sample: the exact label set when given, else the unlabelled one, else the SUM over all label sets"""
    series = M.get(name)
    if not series:
        return default
    if labels:
        return series.get(tuple(sorted(labels.items())), default)
    if () in series:
        return series[()]
    return sum(series.values())


def label_of(M, name, key):
    for labels in (M.get(name) or {}):
        d = dict(labels)
        if key in d:
            return d[key]
    return None


def fetch(url, timeout=8):
    with urllib.request.urlopen(urllib.request.Request(url, method='GET'), timeout=timeout) as r:
        return r.read().decode(errors='replace')


def rate(a, b, name, dt, **labels):
    x, y = val(a, name, **labels), val(b, name, **labels)
    if x is None or y is None or dt <= 0:
        return None
    return round((y - x) / dt, 2)


HS_KEY = 'dero_miner_hashes_effective_total'    # r30 B26 (cmd/dero-miner/hsreport_r30.go)


def derive(d0, d1, m0, m1, dt, cpu_max=None):
    """the aggregate, from two samples of each endpoint (any may be None when that endpoint is down). Pure.
    cpu_max: the miner's --cpu-max (%) when known (R23: /metrics dero_miner_cpu_duty_percent, else the run checkpoint)."""
    out = {'interval_s': round(dt, 1)}
    if d1 is not None:
        status = next((dict(k).get('status') for k, v in (d1.get('dero_sync_status') or {}).items() if v == 1), None)
        out['derod'] = {
            'version': label_of(d1, 'app_version', 'version'), 'uptime_s': val(d1, 'app_uptime_seconds'),
            'height': val(d1, 'dero_chain_height'), 'topoheight': val(d1, 'dero_chain_topoheight'),
            'tip_age_s': val(d1, 'dero_tip_age_seconds'), 'sync_lag_blocks': val(d1, 'dero_sync_lag_blocks'),
            'sync_status': status, 'peers_out': val(d1, 'p2p_peer_outgoing_count'), 'peers_in': val(d1, 'p2p_peer_incoming_count'),
            'getwork_miners': val(d1, 'dero_getwork_miners'), 'jobs_sent': val(d1, 'getwork_jobs_sent_total'),
            'ours_submitted': val(d1, 'miniblock_ours_submitted_total'), 'ours_paid': val(d1, 'miniblock_ours_paid_total'),
            'ours_orphaned': val(d1, 'miniblock_ours_orphaned_total', 0),
            'tx_fetch_failures': val(d1, 'p2p_tx_fetch_failures_total'), 'bans': val(d1, 'p2p_bans_total'),
            'handshake_failures': val(d1, 'p2p_handshake_failures_total'),
            'recovered_panics': (val(d1, 'recovered_panics_total', 0) or 0) + (val(d1, 'rpc_recovered_panics_total', 0) or 0),
            'goroutines': val(d1, 'go_goroutines'), 'mempool': val(d1, 'mempool_count'),
            'rpc_requests': val(d1, 'rpc_requests_total'),
            'heights_per_min': None if d0 is None else (lambda r: None if r is None else round(r * 60, 2))(
                rate(d0, d1, 'dero_chain_height', dt)),
            'jobs_per_min': None if d0 is None else (lambda r: None if r is None else round(r * 60, 1))(
                rate(d0, d1, 'getwork_jobs_sent_total', dt)),
        }
        s, p, o = out['derod']['ours_submitted'], out['derod']['ours_paid'], out['derod']['ours_orphaned']
        out['derod']['paid_fraction'] = round(p / (p + o), 4) if p is not None and (p + (o or 0)) > 0 else None
    if m1 is not None:
        hashed, dropped = val(m1, 'dero_miner_split_hashed_total', 0), val(m1, 'dero_miner_split_dropped_total', 0)
        hashes, up = val(m1, 'dero_miner_hashes_total'), val(m1, 'dero_miner_uptime_seconds')
        out['miner'] = {
            'version': label_of(m1, 'dero_miner_info', 'version'), 'uptime_s': up, 'threads': val(m1, 'dero_miner_threads'),
            'connected': val(m1, 'dero_miner_connected'), 'reconnects': val(m1, 'dero_miner_getwork_reconnects_total'),
            'height': val(m1, 'dero_miner_height'), 'difficulty': val(m1, 'dero_miner_difficulty'),
            'hashrate_15s': val(m1, 'dero_miner_hashrate_15s'),
            'hashrate_run_mean': round(hashes / up, 1) if hashes is not None and up else None,
            # r30 B26: hashes the miner completed (hashes_total minus stale_sha_skipped, never-hashed texts) when the
            # miner exports it; a pre-r30 miner's rate includes them and is labelled so
            'hashrate_sampled': None if m0 is None else rate(m0, m1, HS_KEY if val(m0, HS_KEY) is not None and val(m1, HS_KEY) is not None
                                                             else 'dero_miner_hashes_total', dt),
            'hashrate_excludes': ('stale_sha_skipped' if val(m1, HS_KEY) is not None and (m0 is None or val(m0, HS_KEY) is not None)
                                  else 'none (pre-r30 miner: includes stale_sha_skipped)'),
            'split_share': round(hashed / hashes, 4) if hashes else None,
            'split_drop_fraction': round(dropped / (dropped + hashed), 4) if (dropped + hashed) > 0 else None,
            'split_disabled': val(m1, 'dero_miner_split_disabled'), 'gpu_mismatch': val(m1, 'dero_miner_gpu_mismatch_total'),
            'gpu_restarts': val(m1, 'dero_miner_gpu_restarts_total'),
            'accepted_miniblocks': val(m1, 'dero_miner_accepted_miniblocks_total'),
            'found': val(m1, 'dero_miner_found_total'), 'rejected': val(m1, 'dero_miner_rejected_total'),
            'node_paid_fraction': val(m1, 'dero_miner_node_paid_fraction'),
            'sort_fallbacks': val(m1, 'dero_miner_sort_fallbacks_total'),
        }
        out['miner']['split_regime'] = split_regime(m0, m1, dt, out['miner']['threads'])
        out['miner']['split_binding'] = split_binding(m0, m1, dt, out['miner']['threads'], cpu_max)
        out['miner']['network_hashrate'] = val(m1, 'dero_miner_network_hashrate_estimate')
        D, H = out['miner']['network_hashrate'], out['miner']['hashrate_sampled'] or out['miner']['hashrate_15s']
        # the miner's own expectation (cmd/dero-miner/outcome.go expectedShares, ARCHITECTURE 31.2): 9 normal
        # miniblocks at D + 1 final at 9D per block = 10 shares per 18 D hashes, so a hash is worth 5/(9 D) shares.
        # D is the NORMAL difficulty: the job difficulty is 10 x D on a final job, so the NW estimate is used.
        out['miner']['expected_shares_per_h'] = round(H * 3600 * 5 / (9 * D), 1) if H and D else None
    return out


def split_regime(m0, m1, dt, threads):
    """R21: the split regime over the sample, from the miner's cumulative counters (cmd/dero-miner/metrics.go):
    staged H/s, the fraction of the time the feeder waited on a full ring and on the CPU sort (seconds per second),
    CPU idle tries per minute and the stale fraction of what the split finished. None without two samples or
    without split counters (full mode, pre-r19)."""
    if m0 is None or m1 is None or dt <= 0 or val(m1, 'dero_miner_split_hashed_total') is None:
        return None
    dh = (val(m1, 'dero_miner_split_hashed_total', 0) or 0) - (val(m0, 'dero_miner_split_hashed_total', 0) or 0)
    dd = (val(m1, 'dero_miner_split_dropped_total', 0) or 0) - (val(m0, 'dero_miner_split_dropped_total', 0) or 0)
    def per_s(name):                       # unrounded (rate() rounds to 0.01: a fraction would lose a digit)
        x, y = val(m0, name), val(m1, name)
        return None if x is None or y is None else (y - x) / dt
    backlog = per_s('dero_miner_split_feeder_cpu_backlog_seconds_total')
    ring = per_s('dero_miner_split_feeder_ring_full_seconds_total')
    idle = per_s('dero_miner_split_cpu_idle_tries_total')
    idle_min = round(idle * 60, 1) if idle is not None else None
    return {'staged_hs': round(dh / dt, 1), 'cpu_backlog_fraction': None if backlog is None else round(backlog, 3),
            'ring_full_fraction': None if ring is None else round(ring, 3), 'idle_tries_per_min': idle_min,
            'stale_fraction': round(dd / (dd + dh), 4) if (dd + dh) > 0 else None,
            'regime': MI.classify_regime(None if backlog is None else round(backlog, 3), idle_min, threads)}


def split_binding(m0, m1, dt, threads, cpu_max=None):
    """R22: the BINDING resource over the sample (miner_intel.classify_binding, shared with the log side). Adds what
    the r21 regime never read: the GPU's wall-clock duty (dero_miner_split_gpu_busy_seconds_total, r21), the miner
    process's CPU cores (process_cpu_seconds_total rate) against its --cpu-max budget, the GPU-only ceiling ESTIMATE
    (staged / busy) and what an idle try costs: hashes the CPU threads produced on their own (hashes_total minus
    split_hashed) per idle try. None without two samples or without split counters."""
    if m0 is None or m1 is None or dt <= 0 or val(m1, 'dero_miner_split_hashed_total') is None:
        return None
    def d(name):
        x, y = val(m0, name), val(m1, name)
        return None if x is None or y is None else y - x
    busy, backlog, ring = d('dero_miner_split_gpu_busy_seconds_total'), d('dero_miner_split_feeder_cpu_backlog_seconds_total'), \
        d('dero_miner_split_feeder_ring_full_seconds_total')
    gb = None if busy is None else round(busy / dt, 3)
    bl = None if backlog is None else round(backlog / dt, 3)
    rf = None if ring is None else round(ring / dt, 3)
    cpu = d('process_cpu_seconds_total')
    cores = None if cpu is None else round(cpu / dt, 2)
    budget = None
    if cores is not None and threads and cpu_max:
        budget = round(cores / (threads * cpu_max / 100.0), 3)
    staged = (d('dero_miner_split_hashed_total') or 0) / dt
    own = None
    dh, ds, di = d('dero_miner_hashes_total'), d('dero_miner_split_hashed_total'), d('dero_miner_split_cpu_idle_tries_total')
    if dh is not None and ds is not None:
        own = dh - ds
    bd = MI.classify_binding(gb, bl, rf, budget)
    return {'binding': bd['binding'], 'why': bd['why'], 'throttle_capped': bd['throttle_capped'],
            'gpu_busy_fraction': gb, 'cpu_backlog_fraction': bl, 'ring_full_fraction': rf,
            'cpu_cores': cores, 'cpu_max': cpu_max, 'cpu_budget_fraction': budget,
            'gpu_ceiling_staged_hs': MI.gpu_ceiling(round(staged, 1), gb),
            'cpu_own_hs': None if own is None else round(own / dt, 1),
            'cpu_own_hashes_per_idle_try': round(own / di, 2) if own is not None and di else None}


def rules(agg, up):
    out, d, m = [], agg.get('derod') or {}, agg.get('miner') or {}
    for name, ok in up.items():
        if not ok:
            out.append(('endpoint_down', 'ALERT', f'{name} /metrics did not answer'))
    if d:
        if d.get('sync_status') != 'synced':
            out.append(('not_synced', 'ALERT', f"sync status {d.get('sync_status')}"))
        if d.get('tip_age_s') is not None and d['tip_age_s'] > 600:
            out.append(('tip_age', 'ALERT', f"tip is {d['tip_age_s']:.0f} s old"))
        if d.get('recovered_panics'):
            out.append(('recovered_panics', 'WARN', f"{d['recovered_panics']:.0f} recovered panic(s)"))
    if m:
        if m.get('connected') == 0:
            out.append(('miner_disconnected', 'ALERT', 'dero_miner_connected 0'))
        if m.get('split_disabled'):
            out.append(('split_disabled', 'ALERT', 'dero_miner_split_disabled 1'))
        if m.get('gpu_mismatch'):
            out.append(('gpu_mismatch', 'ALERT', f"gpu mismatches {m['gpu_mismatch']:.0f}"))
        if m.get('hashrate_sampled') is not None and m['hashrate_sampled'] <= 0:
            out.append(('no_hashing', 'ALERT', 'hashes_total did not advance'))
        rg = m.get('split_regime') or {}
        if rg.get('stale_fraction') is not None and rg['stale_fraction'] > STALE_WARN:
            out.append(('split_stale', 'WARN', f"{rg['stale_fraction'] * 100:.1f} % of split nonces dropped stale in the sample"))
        bd = m.get('split_binding') or {}
        ct = agg.get('contention') or {}
        if bd.get('binding') in ('cpu-sort-bound', 'co-bound') and bd.get('cpu_budget_fraction') is not None \
                and bd['cpu_budget_fraction'] < STARVED_BUDGET:
            if ct.get('contended') is False:
                out.append(('cpu_starved_unattributed', 'WARN', f"{bd['binding']} at {bd['cpu_cores']} cores = "
                            f"{bd['cpu_budget_fraction']} of the budget, but the census finds no contention ({ct.get('why')})"))
            else:
                by = ', '.join(f"{g['name']} x{g['procs']} {g['cores']} cores" for g in (ct.get('top_foreign') or [])[:3])
                out.append(('cpu_starved', 'WARN', f"{bd['binding']} at {bd['cpu_cores']} cores = {bd['cpu_budget_fraction']} of the "
                                                   f"--cpu-max budget: other processes are taking the miner's CPU"
                                                   + (f" (census: {by}; law loss ESTIMATE {ct.get('law_loss_hs')} H/s)" if by else '')))
    ct = agg.get('contention') or {}
    if ct.get('contended'):
        out.append(('box_contended', 'WARN', ct.get('why')))
    if d and m:
        if d.get('height') is not None and m.get('height') is not None and d['height'] - m['height'] > HEIGHT_SLACK:
            out.append(('miner_behind', 'ALERT', f"miner job height {m['height']:.0f} vs derod {d['height']:.0f}"))
        if d.get('getwork_miners') == 0:
            out.append(('no_miner_on_node', 'WARN', 'derod counts 0 getwork miners while the miner is up'))
        if d.get('version') and m.get('version') and d['version'] != m['version']:
            out.append(('version_skew', 'WARN', f"derod {d['version']} vs miner {m['version']}"))
    return out


def n(x):
    """a counter for a fact line: integral floats without '.0', None as-is"""
    return int(x) if isinstance(x, float) and x.is_integer() else x


def facts(agg, alerts):
    d = {k: n(v) for k, v in (agg.get('derod') or {}).items()}
    m = {k: n(v) for k, v in (agg.get('miner') or {}).items()}
    f = []
    if d:
        f.append(f"live derod version={d['version']} height={n(d['height'])} tip_age_s={d['tip_age_s']} sync={d['sync_status']} "
                 f"lag={d['sync_lag_blocks']} peers_out={n(d['peers_out'])} peers_in={n(d['peers_in'])} "
                 f"getwork_miners={d['getwork_miners']} ours_submitted={d['ours_submitted']} ours_paid={d['ours_paid']} "
                 f"ours_orphaned={d['ours_orphaned']} paid_fraction={d['paid_fraction']} tx_fetch_failures={d['tx_fetch_failures']} "
                 f"bans={d['bans']} recovered_panics={d['recovered_panics']} heights_per_min={d['heights_per_min']}")
    if m:
        f.append(f"live miner version={m['version']} uptime_s={m['uptime_s']} threads={m['threads']} connected={m['connected']} "
                 f"hashrate_sampled={m['hashrate_sampled']} hashrate_15s={m['hashrate_15s']} hashrate_run_mean={m['hashrate_run_mean']} "
                 f"split_share={m['split_share']} split_drop_fraction={m['split_drop_fraction']} height={m['height']} "
                 f"difficulty={m['difficulty']} network_hashrate={m['network_hashrate']} expected_shares_per_h={m['expected_shares_per_h']} "
                 f"accepted_miniblocks={m['accepted_miniblocks']} node_paid_fraction={m['node_paid_fraction']}")
    rg = (agg.get('miner') or {}).get('split_regime')
    if rg:
        f.append(f"live split regime={rg['regime']} staged_hs={rg['staged_hs']} cpu_backlog_fraction={rg['cpu_backlog_fraction']} "
                 f"ring_full_fraction={rg['ring_full_fraction']} idle_tries_per_min={rg['idle_tries_per_min']} "
                 f"stale_fraction={rg['stale_fraction']} interval_s={agg['interval_s']}")
    bd = (agg.get('miner') or {}).get('split_binding')
    if bd:
        f.append(f"live split binding={bd['binding']} gpu_busy_fraction={bd['gpu_busy_fraction']} "
                 f"cpu_backlog_fraction={bd['cpu_backlog_fraction']} ring_full_fraction={bd['ring_full_fraction']} "
                 f"cpu_cores={bd['cpu_cores']} cpu_budget_fraction={bd['cpu_budget_fraction']} "
                 f"gpu_ceiling_staged_hs={bd['gpu_ceiling_staged_hs']} cpu_own_hs={bd['cpu_own_hs']} "
                 f"cpu_own_hashes_per_idle_try={bd['cpu_own_hashes_per_idle_try']} interval_s={agg['interval_s']}")
    if agg.get('contention') and agg['contention'].get('contended') is not None:
        f.append(CT.fact(agg['contention']))
    f.append(f"live dashboard alerts={sum(1 for a in alerts if a['level'] == 'ALERT')} "
             f"warns={sum(1 for a in alerts if a['level'] == 'WARN')} interval_s={agg['interval_s']}")
    return f


def snapshot(derod=DEROD, miner=MINER, interval=15.0, get=fetch, sleep=time.sleep, clock=time.time, cpu_max=None, ps=None,
             ncpu=None, load1=None):
    """two GETs of each endpoint `interval` apart -> the report. `get`, `sleep`, `clock` are injectable for the KAT.
    R23: `ps` (contention.ps_text, or a stub) is sampled next to each GET, so the census covers the same window as the
    rates; None = no census (the snapshot then carries contention {'contended': None}, which G20 refuses)."""
    def grab():
        res = {}
        for name, url in (('derod', derod), ('miner', miner)):
            try:
                res[name] = parse(get(url))
            except Exception:                                   # noqa: BLE001 — down is a reading, not a crash
                res[name] = None
        t = clock()
        smp = None
        if ps is not None:
            try:
                smp = (t, CT.parse_ps(ps()))
            except Exception:                                   # noqa: BLE001 — a failed ps is no census, said so
                smp = None
        return res, t, smp
    a, t0, p0 = grab()
    if interval > 0:
        sleep(interval)
        b, t1, p1 = grab()
    else:
        b, t1, p1 = a, t0, p0
    up = {k: b[k] is not None for k in ('derod', 'miner')}
    # R23: the miner exports the --cpu-max in force (dero_miner_cpu_duty_percent, r22 metrics.go; the duty tuner may move
    # it). Before R23 the budget came only from <bin>/dero-miner.run.json: from a clone, or with the checkpoint missing,
    # it was None, so cpu_budget_fraction was None and cpu_starved could NEVER fire (live 01:53: 11.78 of 18 cores, silent).
    gauge = val(b['miner'], 'dero_miner_cpu_duty_percent') if b['miner'] else None
    cpu_max_src = 'metrics' if gauge else ('given' if cpu_max else None)
    if gauge:
        cpu_max = int(gauge)
    agg = derive(a['derod'], b['derod'], a['miner'], b['miner'], t1 - t0 if interval > 0 else 0, cpu_max)
    agg['cpu_max_source'] = cpu_max_src
    m1 = b['miner']
    threads = val(m1, 'dero_miner_threads') if m1 else None
    cen = CT.census(p0, p1) if p0 and p1 else None
    if load1 is None:
        try:
            load1 = __import__('os').getloadavg()[0]
        except OSError:
            load1 = None
    agg['contention'] = CT.verdict(cen, ncpu, int(threads) if threads else None, cpu_max if m1 else None, load1)
    if cen is not None:
        bd = (agg.get('miner') or {}).get('split_binding') or {}
        # the two instruments for the miner's cores: ps CPU-time delta vs process_cpu_seconds_total (same window)
        agg['contention']['miner_cores_metrics'] = bd.get('cpu_cores')
    alerts = [{'rule': k, 'level': lv, 'what': w} for k, lv, w in rules(agg, up)]
    # the raw readings the rates came from, so a KAT (DK32) can recompute them without this code
    raw = {'t': [t0, t1], 'miner_hashes_total': [val(x, 'dero_miner_hashes_total') if x else None for x in (a['miner'], b['miner'])],
           'derod_height': [val(x, 'dero_chain_height') if x else None for x in (a['derod'], b['derod'])],
           'miner_split_backlog_s': [val(x, 'dero_miner_split_feeder_cpu_backlog_seconds_total') if x else None
                                     for x in (a['miner'], b['miner'])],
           # R22: the GPU duty counter, so G19 recomputes the binding fraction without this code
           'miner_split_gpu_busy_s': [val(x, 'dero_miner_split_gpu_busy_seconds_total') if x else None
                                      for x in (a['miner'], b['miner'])]}
    return {'captured': datetime.datetime.fromtimestamp(t1).astimezone().isoformat(timespec='seconds'),
            'endpoints': {'derod': derod, 'miner': miner}, 'up': up, 'rules': RULES, 'raw': raw, **agg,
            'alerts': alerts, 'facts': facts(agg, alerts)}


def checkpoint_cpu_max(path=None):
    """the running miner's --cpu-max from its run checkpoint (cmd/dero-miner/runledger.go, <bin>/dero-miner.run.json,
    rewritten every 60 s; READ-ONLY here), or None"""
    p = Path(path) if path else HARNESS.parent / 'bin/dero-miner.run.json'
    try:
        v = json.loads(p.read_text()).get('cpu_max')
        return int(v) if v else None
    except (OSError, ValueError, TypeError):
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--derod', default=DEROD)
    ap.add_argument('--miner', default=MINER)
    ap.add_argument('--interval', type=float, default=15.0)
    ap.add_argument('--out')
    ap.add_argument('--json-only', action='store_true')
    ap.add_argument('--cpu-max', type=int, help="the miner's --cpu-max (default: read from its run checkpoint)")
    ap.add_argument('--registry', default=str(HARNESS / 'round.json'), help='round registry for the miner track (r27)')
    a = ap.parse_args()
    rep = snapshot(a.derod, a.miner, a.interval, cpu_max=a.cpu_max if a.cpu_max is not None else checkpoint_cpu_max(),
                   ps=CT.ps_text)                                     # R23: the foreign-process census, read-only
    rep['exit'] = exit_block(rep, RT.track_state(RT.load(a.registry)))   # r27: 7 = a node ALERT while paused
    out = Path(a.out) if a.out else HARNESS / f"runtime/metrics_{datetime.datetime.now().strftime('%Y%m%dT%H%M%S')}.json"
    MI.write_atomic(out, json.dumps(rep, indent=1, ensure_ascii=False))   # R22: atomic
    if not a.json_only:
        for f in rep['facts']:
            print(f)
        for al in rep['alerts']:
            tag = 'PAUSED (miner) ' if al['level'] == 'ALERT' and RT.miner_alert(al) and rep['exit']['paused_alerts'] else ''
            print(f"   [{tag}{al['level']}] {al['rule']}: {al['what']}")
        print(f"exit {rep['exit']['rc']}: {rep['exit']['why']}")
        print(f'wrote {out}')
    return rep['exit']['rc']


if __name__ == '__main__':
    sys.exit(main())
