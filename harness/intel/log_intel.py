#!/usr/bin/env python3
"""log_intel.py — what the daemon's own JSON log says about every run, measured, not eyeballed.

derod writes a lumberjack-rotated JSON log at level -1 (V(1)) for the whole run: <exe>.log by default, or
<--log-dir>/derod.log. Every line is {"L","T","N","C","M", ...fields}. This tool:

  1. finds every such file (the datadir's logs/ and the repo's bin/), skipping pasted consoles;
  2. splits the stream into RUNS at each start-up line (derod/main.go "DERO HE daemon :");
  3. profiles each run: version and argument map, level counts, ERROR classes, block cadence from
     "Chain extended" (catch-up vs at-tip phases separated by measured inter-block gaps), side blocks,
     tx per block, resyncs, v2-remnant drops, and endpoints that only ever produced "backing off";
  4. applies anomaly RULES whose thresholds are justified in RULES below, and
  5. writes harness/runtime/logintel_<ts>.json with one fact per line, so every number is anchorable.

  python3 harness/intel/log_intel.py [--files a.log b.log] [--json-only]
"""
import argparse, collections, datetime, glob, json, re, statistics, sys, urllib.request
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent
ROOT = HARNESS.parent
DEFAULT_GLOBS = [os.path.expanduser(os.environ.get('DERO_DATADIR', '~/dero-data')) + '/logs/derod*.log', str(ROOT / 'bin/derod*.log')]
# the start-up line is recognised by its TEXT from derod's main.go: the caller line moves between builds
# (main.go:160 through r17, main.go:182 in r18), and matching the line number merged every r18 run into the r17 run
# before it — the page then labelled the live r18 daemon "r17" and G15 judged a run that had ended (Round 19)
START_FILE = 'derod/main.go:'
START_M = 'DERO HE daemon :'                  # logger.Info("DERO HE daemon :  It is an alpha version ...")
METRICS_URL = 'http://127.0.0.1:10102/metrics'  # derod's read-only Prometheus text on the RPC port
TARGET_BLOCK_S = 18                           # config/config.go BLOCK_TIME = uint64(18)
CATCHUP_GAP_S = 5                             # gaps under this are replay, not following the chain (4.24 blocks/s measured R9b)

# error classes, shared with harness/miners/mine_triage.py (same substrings)
CLASSES = [('zero-signer', 'keyhash 02dc1cbdfa9a150e0fc02f1e098f6f8ccdb676b95bd96704072bf52a9d93a23e'),
           ('sc-parse', 'is invalid'), ('remote-emptyblock', 'Invalid Major Version'),
           ('remote-txstore', 'bltx_store'), ('closed-pipe', 'closed pipe')]

# thresholds and why (healthy reference: Round 6 audit, 64 h at tip: 18.52 s/block, 3 resyncs/64 h, 0 errors)
RULES = {
    'error_at_tip': 'any ERROR line while at tip — Round 11 binary demoted every known benign class, so an ERROR now means something new',
    'resync_at_tip': 'more than 3 "We need to resync" per 64 h at tip (Round 6 healthy profile: 3 in 64 h)',
    # the healthy 18.1-18.5 s figures are MEANS (GetInfo averageblocktime50, Round 6); inter-block gaps are skewed
    # (p90 ~31 s), so the median sits near 16 s in every healthy run — compare the mean, report both
    'cadence': 'at-tip MEAN block interval outside 15..22 s (target 18 s; healthy runs measured 18.1-18.5 s mean, ~16 s median)',
    'dead_priority': 'a --add-priority-node endpoint that produced only "backing off" lines for over 1 h',
    'peers_low': 'peer list saved with fewer than 8 peers (the node had 16-24 throughout the healthy runs)',
    'v2_drops': 'informational: peers on the pre-HF3 v2 remnant chain being dropped (Round 5 filter working)',
    # r18 lines (p2p/own_broadcast.go "Own miniblock delivered" with failed_by_reason; rpc getwork exposure warning)
    'own_mb_fail': 'more than 25 % of the peers we sent our own miniblocks to failed to ack them, over at least 10 miniblocks '
                   '(r18 live: 1 failure of 13 peers, reason "duplicate")',
    'getwork_exposed': 'derod warned that getwork is reachable from the network without authentication (r18 bind policy)',
}


def is_start(d):
    return str(d.get('C', '')).startswith(START_FILE) and str(d.get('M', '')).startswith(START_M)


def files(explicit=None):
    out = []
    for g in (explicit or DEFAULT_GLOBS):
        for f in sorted(glob.glob(g)):
            p = Path(f)
            try:
                with p.open(errors='replace') as fh:
                    if fh.readline().startswith('{'):
                        out.append(p)
            except OSError:
                pass
    return out


def lines(paths):
    """All JSON records from all files, in time order (rotations overlap at most at the boundary line)."""
    recs = []
    for p in paths:
        with p.open(errors='replace') as fh:
            for l in fh:
                if not l.startswith('{'):
                    continue
                try:
                    d = json.loads(l)
                except ValueError:
                    continue
                d['_f'] = p.name
                recs.append(d)
    recs.sort(key=lambda d: d.get('T', ''))
    return recs


def ts(t):
    return datetime.datetime.strptime(t[:23], '%Y-%m-%dT%H:%M:%S.%f').timestamp()


def classify(d):
    e = str(d.get('error', '')) + ' ' + str(d.get('r', '')) + ' ' + str(d.get('peer_error', ''))
    return next((n for n, p in CLASSES if p in e), 'other')


def profile(run):
    first, last = run[0]['T'], run[-1]['T']
    p = {'start': first, 'end': last, 'hours': round((ts(last) - ts(first)) / 3600, 2), 'lines': len(run),
         'levels': dict(collections.Counter(d.get('L') for d in run))}
    for d in run:
        if str(d.get('C', '')).startswith(START_FILE) and d.get('Version'):
            p['version'] = d['Version']
        if str(d.get('C', '')).startswith(START_FILE) and isinstance(d.get('Arguments'), dict):
            a = d['Arguments']
            p['priority_nodes'] = a.get('--add-priority-node') or []
            p['log_dir'] = a.get('--log-dir')
            p['min_peers'] = a.get('--min-peers')
    # cadence: the first time each height is reached
    seen, heights = set(), []
    for d in run:
        if d.get('M') == 'Chain extended' and isinstance(d.get('new height'), int):
            h = d['new height']
            if h not in seen:
                seen.add(h)
                heights.append((ts(d['T']), h))
    gaps = [(b[0] - a[0]) / max(1, b[1] - a[1]) for a, b in zip(heights, heights[1:])]
    tip_from = None
    for i in range(len(gaps)):                     # at tip = from the first index after which no gap is a replay gap
        if all(g >= CATCHUP_GAP_S for g in gaps[i:i + 20]):
            tip_from = i
            break
    tipg = gaps[tip_from:] if tip_from is not None else []
    p['blocks'] = {'reached': len(heights), 'first_height': heights[0][1] if heights else None,
                   'last_height': heights[-1][1] if heights else None,
                   'catchup_blocks': tip_from if tip_from is not None else len(gaps),
                   'at_tip_since': datetime.datetime.fromtimestamp(heights[tip_from][0]).isoformat(timespec='seconds')
                   if tip_from is not None else None,
                   'at_tip_intervals': len(tipg),
                   'at_tip_mean_s': round(statistics.mean(tipg), 2) if tipg else None,
                   'at_tip_median_s': round(statistics.median(tipg), 2) if tipg else None,
                   'at_tip_p90_s': round(sorted(tipg)[int(0.9 * (len(tipg) - 1))], 2) if tipg else None,
                   'side_blocks': sum(1 for d in run if d.get('M') == 'Chain extended but height is same')}
    tip_t = heights[tip_from][0] if tip_from is not None else None
    txs = [d.get('tx_count') for d in run if d.get('M') == 'Will broadcast block' and isinstance(d.get('tx_count'), int)]
    p['tx_per_block'] = {'blocks': len(txs), 'mean': round(statistics.mean(txs), 3) if txs else None, 'max': max(txs) if txs else None}
    errs = [d for d in run if d.get('L') == 'ERROR']
    p['errors'] = dict(collections.Counter(f"{d.get('C')} {classify(d)}" for d in errs))
    p['errors_at_tip'] = sum(1 for d in errs if tip_t and ts(d['T']) >= tip_t)
    p['demoted_info'] = dict(collections.Counter(
        d.get('M', '')[:70] for d in run if any(x in d.get('M', '') for x in
        ('peer could not serve', 'connection closed during', 'SC reverted for an anonymous', 'SC install rejected'))))
    res = [d for d in run if d.get('M', '').startswith('We need to resync')]
    p['resyncs'] = {'total': len(res), 'at_tip': sum(1 for d in res if tip_t and ts(d['T']) >= tip_t)}
    p['v2_drops'] = sum(1 for d in run if d.get('M', '').startswith('dropping peer on pre-HF3'))
    back = collections.Counter(d.get('ip') for d in run if d.get('M') == 'backing off from this connection')
    other = collections.Counter()
    for d in run:
        n = str(d.get('N', ''))
        m = re.search(r'\.(\d+\.\d+\.\d+\.\d+:\d+)$', n)
        if m:
            other[m.group(1)] += 1
    p['backoff_only_endpoints'] = sorted(ip for ip, c in back.items() if ip and other.get(ip, 0) == 0 and c >= 10)
    saves = [d.get('peer_count') for d in run if d.get('M') == 'Successfully saved peers to file']
    p['peer_list'] = {'saves': len(saves), 'min': min(saves) if saves else None, 'max': max(saves) if saves else None}
    p['own_miniblocks'] = own_miniblocks(run)
    fr = [d.get('count') for d in run if d.get('M') == 'Successfully loaded first-relay ranking from file']
    p['first_relay_loaded'] = fr[-1] if fr else None
    p['chunk_unknown_tip'] = sum(1 for d in run if str(d.get('M', '')).startswith('chunk dropped: block builds on a tip'))
    p['resync_refused_pruned'] = sum(1 for d in run if str(d.get('M', '')).startswith('We cannot resync with the peer, since peer chain is pruned'))
    p['getwork_exposed'] = any(str(d.get('M', '')).startswith('WARNING: getwork is reachable from the network') for d in run)
    return p


def own_miniblocks(run):
    """p2p/own_broadcast.go: one line per own miniblock once every peer acked or failed (r17+; failed_by_reason r18)."""
    L = [d for d in run if d.get('M') == 'Own miniblock delivered']
    if not L:
        return {'count': 0}
    peers = sum(d.get('peers') or 0 for d in L)
    failed = sum(d.get('failed') or 0 for d in L)
    reasons = collections.Counter()
    for d in L:
        for k, v in (d.get('failed_by_reason') or {}).items():
            reasons[k] += v
    med = [d['median_ms'] for d in L if isinstance(d.get('median_ms'), (int, float))]
    first = [d['first_ms'] for d in L if isinstance(d.get('first_ms'), (int, float))]
    last = [d['last_ms'] for d in L if isinstance(d.get('last_ms'), (int, float))]
    return {'count': len(L), 'peers': peers, 'acked': sum(d.get('acked') or 0 for d in L), 'failed': failed,
            'fail_fraction': round(failed / peers, 3) if peers else None, 'failed_by_reason': dict(reasons),
            'first_ms_median': statistics.median(first) if first else None,
            'median_ms_median': statistics.median(med) if med else None,
            'last_ms_p90': sorted(last)[int(0.9 * (len(last) - 1))] if last else None}


METRIC_KEYS = ('p2p_sync_blocks_fetched_total', 'p2p_sync_getobject_calls_total', 'p2p_sync_wait_seconds_total',
               'p2p_sync_process_seconds_total', 'p2p_sync_large_block_fallbacks_total', 'p2p_sync_pow_prewarmed_total',
               'getwork_template_refresh_resends_total')


def parse_metrics(text):
    """the r18 sync-pipeline / first-relay counters from derod's Prometheus text. A counter that never fired is
    absent (VictoriaMetrics creates it on first Inc), so absent = 0 for the *_total keys, recorded as such."""
    vals, relay = {}, {}
    for l in text.splitlines():
        m = re.match(r'^([a-zA-Z_:][\w:]*)(\{[^}]*\})?\s+([-+0-9.eE]+)$', l.strip())
        if not m:
            continue
        name, labels, v = m.group(1), m.group(2) or '', float(m.group(3))
        if name in METRIC_KEYS and not labels:
            vals[name] = v
        if name == 'p2p_first_relay_total':
            pm = re.search(r'peer="([^"]+)"', labels)
            if pm:
                relay[pm.group(1)] = v
    out = {k: vals.get(k, 0.0) for k in METRIC_KEYS}
    out['absent'] = [k for k in METRIC_KEYS if k not in vals]
    calls = out['p2p_sync_getobject_calls_total']
    out['blocks_per_getobject'] = round(out['p2p_sync_blocks_fetched_total'] / calls, 2) if calls else None
    busy = out['p2p_sync_wait_seconds_total'] + out['p2p_sync_process_seconds_total']
    # fraction of pipelined-sync time spent WAITING for the network; the rest is local verification/processing
    out['sync_wait_fraction'] = round(out['p2p_sync_wait_seconds_total'] / busy, 4) if busy else None
    out['first_relay_peers'] = len(relay)
    out['first_relay_blocks'] = sum(relay.values())
    out['first_relay_top_share'] = round(max(relay.values()) / sum(relay.values()), 3) if relay and sum(relay.values()) else None
    return out


def rules(p):
    out = []
    if p['errors_at_tip']:
        out.append(('error_at_tip', 'ALERT', f"{p['errors_at_tip']} ERROR line(s) after reaching tip: {p['errors']}"))
    hrs_tip = (p['blocks']['at_tip_intervals'] * TARGET_BLOCK_S) / 3600
    if hrs_tip and p['resyncs']['at_tip'] > max(3, 3 * hrs_tip / 64):
        out.append(('resync_at_tip', 'ALERT', f"{p['resyncs']['at_tip']} resyncs in ~{hrs_tip:.1f} h at tip"))
    mean = p['blocks']['at_tip_mean_s']
    if mean is not None and p['blocks']['at_tip_intervals'] >= 100 and not (15 <= mean <= 22):
        out.append(('cadence', 'ALERT', f"at-tip mean {mean} s over {p['blocks']['at_tip_intervals']} intervals"))
    dead = [e for e in p.get('priority_nodes', []) if e in p['backoff_only_endpoints']]
    if dead and p['hours'] >= 1:
        out.append(('dead_priority', 'WARN', f'priority node(s) never connected: {dead}'))
    if p['peer_list']['min'] is not None and p['peer_list']['min'] < 8:
        out.append(('peers_low', 'WARN', f"peer list fell to {p['peer_list']['min']}"))
    if p['v2_drops']:
        out.append(('v2_drops', 'INFO', f"{p['v2_drops']} v2-remnant peer drop(s)"))
    om = p.get('own_miniblocks') or {}
    if om.get('count', 0) >= 10 and om.get('fail_fraction') is not None and om['fail_fraction'] > 0.25:
        out.append(('own_mb_fail', 'WARN', f"{om['failed']} of {om['peers']} own-miniblock sends failed: {om['failed_by_reason']}"))
    if p.get('getwork_exposed'):
        out.append(('getwork_exposed', 'WARN', 'getwork listens beyond loopback without authentication'))
    return out



def write_atomic(path, text):
    """R22 crash safety: a snapshot is written to a hidden temp file in the same directory, fsynced and renamed over
    its name, so a kill mid-write never leaves a torn newest snapshot for run_gates/mine_intel to choke on (they read
    the newest *_<ts>.json; a torn one used to crash the whole gate run). The temp name never matches a *_*.json glob."""
    import os, tempfile
    p = Path(path)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix='.' + p.name + '.', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

def privacy_scrub(report, salt=None):
    """r25 (peers, §7 B71): the snapshot is tracked evidence, so every non-reserved IPv4 in it (backing-off endpoints,
    priority nodes, logger names) is pseudonymised at the source with the peer observatory's salt (kit/privkit.py),
    the same 'peer-' name peer_intel and minelib.emit use; anchors still match through privkit.mask."""
    sys.path.insert(0, str(HARNESS / 'kit'))
    import privkit
    return privkit.pseudonymise_obj(report, salt or privkit.load_salt())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--files', nargs='*')
    ap.add_argument('--json-only', action='store_true')
    ap.add_argument('--no-metrics', action='store_true', help='do not read derod /metrics (read-only GET)')
    a = ap.parse_args()
    paths = files(a.files)
    recs = lines(paths)
    runs, cur = [], []
    for d in recs:
        if is_start(d) and cur:
            runs.append(cur)
            cur = []
        cur.append(d)
    if cur:
        runs.append(cur)
    report = {'captured': datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
              'files': [str(p) for p in paths], 'records': len(recs), 'rules': RULES, 'runs': [], 'facts': []}
    for i, r in enumerate(runs):
        if len(r) < 50:                            # a crash-at-start fragment carries no profile
            continue
        p = profile(r)
        p['alerts'] = [{'rule': k, 'level': lv, 'what': w} for k, lv, w in rules(p)]
        report['runs'].append(p)
        b = p['blocks']
        report['facts'].append(
            f"run {p['start'][:19]} version={p.get('version')} hours={p['hours']} lines={p['lines']} "
            f"errors={sum(p['errors'].values())} errors_at_tip={p['errors_at_tip']} catchup_blocks={b['catchup_blocks']} "
            f"at_tip_mean_s={b['at_tip_mean_s']} at_tip_median_s={b['at_tip_median_s']} at_tip_p90_s={b['at_tip_p90_s']} side_blocks={b['side_blocks']} "
            f"resyncs_at_tip={p['resyncs']['at_tip']} v2_drops={p['v2_drops']} own_miniblocks={p['own_miniblocks'].get('count')} "
            f"own_mb_fail_fraction={p['own_miniblocks'].get('fail_fraction')} first_relay_loaded={p['first_relay_loaded']} "
            f"alerts={len(p['alerts'])}")
    if not a.no_metrics and not a.files:
        try:
            with urllib.request.urlopen(METRICS_URL, timeout=5) as r:
                mt = parse_metrics(r.read().decode(errors='replace'))
            report['metrics'] = mt
            report['facts'].append(
                f"derod metrics blocks_per_getobject={mt['blocks_per_getobject']} sync_wait_fraction={mt['sync_wait_fraction']} "
                f"large_block_fallbacks={int(mt['p2p_sync_large_block_fallbacks_total'])} pow_prewarmed={int(mt['p2p_sync_pow_prewarmed_total'])} "
                f"first_relay_peers={mt['first_relay_peers']} first_relay_top_share={mt['first_relay_top_share']} "
                f"template_resends={int(mt['getwork_template_refresh_resends_total'])}")
        except Exception as e:                               # noqa: BLE001 — node down: record why, never guess
            report['metrics'] = {'error': f'{type(e).__name__}: {e}'}
    out = HARNESS / f"runtime/logintel_{datetime.datetime.now().strftime('%Y%m%dT%H%M%S')}.json"
    report = privacy_scrub(report)                                       # r25 (B71): no peer address in the snapshot
    write_atomic(out, json.dumps(report, indent=1, ensure_ascii=False))   # verbatim UTF-8; R22: atomic
    if not a.json_only:
        for p in report['runs']:
            b = p['blocks']
            print(f"run {p['start'][:19]} → {p['end'][:19]} ({p['hours']} h) {p.get('version')}  lines={p['lines']}")
            print(f"   blocks reached {b['reached']} (catch-up {b['catchup_blocks']}), at tip since {b['at_tip_since']}: "
                  f"mean {b['at_tip_mean_s']} s, median {b['at_tip_median_s']} s, p90 {b['at_tip_p90_s']} s, side blocks {b['side_blocks']}")
            print(f"   errors {p['errors']} (at tip {p['errors_at_tip']}) · demoted {p['demoted_info']} · resyncs {p['resyncs']} · "
                  f"v2 drops {p['v2_drops']} · peer list {p['peer_list']} · tx/block {p['tx_per_block']}")
            for al in p['alerts']:
                print(f"   [{al['level']}] {al['rule']}: {al['what']}")
        print(f'wrote {out.relative_to(ROOT)}: {len(report["runs"])} run(s) from {len(paths)} file(s), {len(recs):,} records')
    return 0


if __name__ == '__main__':
    sys.exit(main())
