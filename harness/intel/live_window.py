#!/usr/bin/env python3
"""live_window.py — r27: the tracked live-window poller and summariser (rft §6 step 20, §13 checklist item 1).

Until r27 the live window of every round came from two scratchpad scripts copied round to round (r25/live ->
r26/measure: poll.py, summary.py) with no --help, no KAT and the endpoint typed in; the R26 window's first sample came
7 min after the user's derod restart (07:48:21 vs 07:55:18) because the poller started with the agent, not with the
node. This tool is that pair, tracked, with a KAT (harness/kat/test_harness_measure_r27.py) and two additions:

  * restart capture: `poll --wait-restart` samples every --fast-step seconds until the node restarts (uptime_seconds
    falls, or the RPC goes away and comes back), then runs the window from that moment, so the first minutes after a
    restart are read. Every sample stores uptime_seconds, so `summary` states how long after the start the first
    sample came ('first sample N s after the derod start'), whichever way the poller was started.
  * the summary is pure over the series file and the /metrics scrapes (summarise()); `--live` adds the read-only
    GetBlockHeadersRange / GetEmissionAudit reads, refused below the node's prunedheight (rft §5).

r28 (harness-measure):
  * B135: every raw /metrics scrape is written through privkit.mask (scrub_prom): a non-reserved IPv4 in a label value
    becomes '<peer>' before the file exists, so a scratchpad scrape no longer holds peer IPv4 labels (the 13 r27
    window scrapes held 1-5 such lines each, 50 in all; rft B135 counted 9 in one live scrape);
    the summary's `name{peer=*}` aggregation is unchanged (it sums the masked series).
  * pending events with denominators (event_lines): each still-pending live event (rft §7 B47 B48 B57 B61 B85 B99,
    PENDING_EVENTS) is stated as 'no event in S s / N blocks (node uptime U s)' or 'EVENT +n', with its counter's
    first -> last value, so 'still no event' is a reading with a denominator (B54 rule), never an absent line.

r30 (node dimension; rft §7 B47 B48 B57 B61 B85 B99 B42 B19 B44 B63 B64 B67 BD5 B141 B144 B152 B157, §0.4 "a 0 is
not a reading"):
  * `watch`: the 24 h low-rate sampler the coordinator leaves running: one sample per --step (300 s) of the read
    methods plus one /metrics scrape, kept as a masked record (privkit.mask over the whole line; only the watched
    series and the absent source families are kept from the scrape, never the raw text); progress.json and
    status.txt are rewritten after every sample, DONE is written at the end or on `watch-stop` (a STOP file).
    `watch-start` launches it under kit/stallwatch.py (liveness = the sample counter and the series file growing;
    a stall or death relaunches it, resuming to the same end time from plan.json) and prints the stop command.
  * every record carries `contention`: contention.py's verdict over the segment since the previous sample (numbers
    only), so B5/B7 reads can exclude contended segments; status.txt counts them.
  * row_status(): every watched row is classed `event seen` (its series rose, or its field fired, within the
    window), `registered, no event` (its series is on /metrics and did not move: stated with S s / N blocks /
    samples, never as a bare 0), or `absent` (no series on the page; for B144/B157 there is no live series at all).
  * INVARIANTS are graded, not waited for: B61 topoheight == height in every sample (consensus accepts one tip per
    block, blockchain.go ErrPastMissing, so a difference would be a broken rule, not a pending event), B141
    config_consensus_env_overrides == 0, B152 no source-declared family absent unless metric_registry.LAZY_BY_DESIGN.

READ-ONLY. Only JSON-RPC POSTs of read methods (READ_METHODS) and GET /metrics to a loopback URL; the default is
127.0.0.1:10102 with Content-Type: application/json. The getwork port 10100 and the P2P port 11011 are refused
(rft §5), as is any non-loopback host. GetPeerInfo is not read (it carries peer addresses): peer counts come from
GetSyncInfo. Writes only the --out series file, its *_metrics_NNN.prom scrapes and the summary --out file.

  python3 -I harness/intel/live_window.py poll --out S.jsonl (--minutes N | --until EPOCH) [--step 60]
                                          [--metrics-every 5] [--wait-restart [--fast-step 5] [--wait-max-s 86400]]
  python3 -I harness/intel/live_window.py summary --series S.jsonl [--out window.txt] [--live] [--restart-note TEXT]
  python3 -I harness/intel/live_window.py watch --dir D (--hours H | --until EPOCH) [--step 300]     # r30 sampler
  python3 -I harness/intel/live_window.py watch-start --dir D [--hours 24] [--step 300]   # same, under stallwatch
  python3 -I harness/intel/live_window.py watch-stop --dir D                              # STOP -> DONE, both exit
  python3 -I harness/intel/live_window.py watch-status --dir D                            # the row classes so far
Exit 0 · 2 bad arguments or a refused endpoint · 3 the window has no usable sample · 4 --wait-restart saw no restart.
"""
import argparse, glob, json, os, re, statistics, sys, time, urllib.parse, urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'kit'))
import privkit                                                       # noqa: E402  r28 B135: one masking rule (kit/privkit.py)

RPC_URL = 'http://127.0.0.1:10102/json_rpc'
REFUSED_PORTS = (10100, 11011)        # getwork, P2P (rft §5): a live-window read never touches them
READ_METHODS = ('DERO.GetConsensusStats', 'DERO.GetSyncInfo', 'DERO.GetInfo', 'DERO.GetBlockHeadersRange',
                'DERO.GetEmissionAudit', 'DERO.GetMonetaryIntegrity')
LOOPBACK = ('127.0.0.1', 'localhost', '::1')


class Refused(ValueError):
    pass


def check_url(url):
    """the URL when it is a loopback http URL on an allowed port; raises Refused otherwise. Pure."""
    u = urllib.parse.urlparse(url)
    if u.scheme != 'http' or u.hostname not in LOOPBACK:
        raise Refused(f'{url}: only a loopback http endpoint may be read')
    if u.port in REFUSED_PORTS:
        raise Refused(f'{url}: port {u.port} is getwork/P2P (rft §5): never connected to')
    return url


def metrics_url(rpc_url):
    u = urllib.parse.urlparse(rpc_url)
    return urllib.parse.urlunparse(u._replace(path='/metrics'))


def make_rpc(url=RPC_URL, timeout=15):
    check_url(url)

    def rpc(method, params=None):
        if method not in READ_METHODS:
            raise Refused(f'{method} is not a read method of this tool')
        body = {'jsonrpc': '2.0', 'id': 1, 'method': method}
        if params is not None:
            body['params'] = params
        req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'})
        try:
            j = json.loads(urllib.request.urlopen(req, timeout=timeout).read())
        except Exception as e:                                       # noqa: BLE001 — a failed read is a reading
            return {'_err': f'{type(e).__name__}: {e}'}
        return j.get('result') if 'result' in j else {'_err': str(j.get('error'))}
    return rpc


def make_metrics(url=RPC_URL, timeout=15):
    mu = check_url(metrics_url(url))

    def get():
        try:
            return urllib.request.urlopen(mu, timeout=timeout).read().decode()
        except Exception as e:                                       # noqa: BLE001
            return f'ERR {type(e).__name__}: {e}'
    return get


def ok(x):
    return isinstance(x, dict) and '_err' not in x


def uptime(rec):
    cs = rec.get('cs')
    return cs.get('uptime_seconds') if ok(cs) else None


def restarted(prev_up, cur_up, prev_down):
    """True when the node restarted between two probes: uptime fell, or it answered again after a failed probe.
    `prev_up`/`cur_up` are uptime_seconds or None (no answer). Pure."""
    if cur_up is None:
        return False
    if prev_down:
        return True
    return prev_up is not None and cur_up < prev_up


def sample(rpc, clock=time.time):
    return {'t': time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime(clock())), 'epoch': round(clock(), 3),
            'cs': rpc('DERO.GetConsensusStats'), 'sync': rpc('DERO.GetSyncInfo'), 'info': rpc('DERO.GetInfo')}


def wait_restart(rpc, fast_step=5.0, wait_max_s=86400.0, clock=time.time, sleep=time.sleep):
    """(epoch, uptime) of the first probe after a restart, or None when none came within wait_max_s. Reads
    GetConsensusStats only (one cheap call per probe)."""
    t0, prev_up, prev_down = clock(), None, False
    while clock() - t0 <= wait_max_s:
        cs = rpc('DERO.GetConsensusStats')
        cur = cs.get('uptime_seconds') if ok(cs) else None
        if restarted(prev_up, cur, prev_down):          # the first probe cannot be one: no previous probe
            return clock(), cur
        prev_down = cur is None
        prev_up = cur if cur is not None else prev_up
        sleep(fast_step)
    return None


def poll(out, end, rpc, metrics=None, step=60.0, metrics_every=5, clock=time.time, sleep=time.sleep, event=None):
    """append one sample per `step` seconds to `out` until `end` (epoch); every `metrics_every`-th sample also writes
    the /metrics text next to it. Returns the number of samples."""
    i = 0
    while clock() < end:
        t = clock()
        rec = sample(rpc, clock)
        if event and i == 0:
            rec['event'] = event
        if metrics and metrics_every and i % metrics_every == 0:
            p = out[:-len('.jsonl')] if out.endswith('.jsonl') else out
            with open(f'{p}_metrics_{i:03d}.prom', 'w') as f:
                f.write(scrub_prom(metrics()))           # r28 B135: no peer address reaches the raw scrape
            rec['metrics'] = i
        with open(out, 'a') as f:
            f.write(json.dumps(rec) + '\n')
        i += 1
        sleep(max(1.0, step - (clock() - t)))
    return i


METRIC_RX = re.compile(r'^((?:rpc|p2p|blockchain|block|txpool|mempool|dero_emission)_[a-z_]+)(\{[^}]*\})? (\S+)$', re.M)


PEER_LABEL_RX = re.compile(r'(?:peer|addr|ip|remote)="|(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')


ANY_RX = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})? (\S+)$', re.M)   # r30: every family (tx_policy_*, config_*)


def metric_map(text, rx=None):
    """{series: value} of the /metrics text. A series whose labels name a peer (a peer/addr/ip/remote label, or any
    IPv4 in a label value, e.g. p2p_first_relay_total{peer="<ip>"}) is summed into one `name{peer=*}` series, so no
    peer address reaches the summary (rft §5 privacy; seen on the r26 node 2026-11-05). Pure."""
    out, agg = {}, {}
    for name, labels, v in (rx or METRIC_RX).findall(text or ''):
        if labels and PEER_LABEL_RX.search(labels):
            try:
                agg[name] = agg.get(name, 0.0) + float(v)
            except ValueError:
                agg.setdefault(name, 0.0)
            continue
        out[name + (labels or '')] = v
    for name, tot in agg.items():
        out[name + '{peer=*}'] = str(int(tot)) if float(tot).is_integer() else repr(tot)
    return out


def scrub_prom(text):
    """r28 B135: the /metrics text as it may be written to disk: every non-reserved IPv4 (peer labels such as
    p2p_first_relay_total{peer="<ip>"}) becomes privkit.TOKEN. Loopback and documentation addresses stay. Pure."""
    return privkit.mask(text or '')


# r28: the live events rft §7 still waits for (§13 'still no event' lines). Each: (id, what, counters summed over all
# their labelled series, sync field read per sample or None). The counters are derod /metrics names (r27 binary).
PENDING_EVENTS = (
    ('B47', 'sync hold of a peer that cannot serve what it advertises', ('p2p_sync_peer_holds_total',), None),
    ('B48', 'an inbound peer (proven-lane admit / refusal / quota eviction)',
     ('p2p_inbound_proven_lane_admits_total', 'p2p_inbound_proven_lane_refusals_total',
      'p2p_inbound_proven_quota_evictions_total'), 'peers_incoming'),
    ('B57', 'a rejected block (any reason)', ('blockchain_block_rejected_total',), None),
    ('B85', 'an RPC answer with code -32031 (state below the prune point)', ('rpc_error_responses_total{code="-32031"}',), None),
    ('B99', 'sync-hold forgiveness / decay / held fallback',
     ('p2p_sync_relay_forgiven_total', 'p2p_sync_served_forgiven_total', 'p2p_sync_strike_decays_total',
      'p2p_sync_held_fallbacks_total'), None),
)


# r30: the further rows whose live event the 24 h sampler watches. (id, what, counters, field): a field is read per
# sample from GetInfo ('pool_nonempty': tx_pool_size > 0, 'pool_ge2': >= 2). No counters and no field = no live
# series exists (unit-proven rows): row_status says 'absent' with that reason, never 'no event'.
ROW_WATCH = PENDING_EVENTS + (
    ('B42', 'a non-empty pool (the mined-not-purged split of tx_pool_size / tx_pool_unmined)', ('mempool_count',), 'pool_nonempty'),
    ('B19', 'two or more txs in the pool (the milli fee-per-byte rank orders something)', (), 'pool_ge2'),
    ('B44', 'a pool-cap refusal or eviction', ('tx_policy_pool_full_refused_total', 'tx_policy_evicted_total'), None),
    ('B63', 'a scored peer offence (penalty event, any reason)', ('p2p_penalty_events_total',), None),
    ('B64', 'a per-reason offence or ban counter moving', ('p2p_penalty_events_total', 'p2p_penalty_bans_by_reason_total'), None),
    ('B67', 'an INV txid budget clip', ('p2p_inv_txids_over_budget_total',), None),
    ('BD5', 'a proof scalar >= Order refused at admission', ('tx_proof_scalar_nonreduced_rejected_total',), None),
    ('B144', 'none: globals ParseAmount/FormatMoney have no live series (unit-proven)', (), None),
    ('B157', 'none: SC burn conservation by path has no live series (unit-proven)', (), None),
)
# r30: rules graded on every sample (a violation is a finding at once, never a pending event)
INVARIANTS = (
    ('B61', 'topoheight == height in every sample (one tip per block)', 'topo_eq_height'),
    ('B141', 'config_consensus_env_overrides == 0 in every scrape', 'config_consensus_env_overrides'),
    ('B152', 'no source-declared /metrics family absent unless lazy_by_design', 'lazy'),
)


def _registry_mod():
    import importlib.util
    sp = importlib.util.spec_from_file_location('metric_registry_lw', Path(__file__).resolve().parent / 'metric_registry.py')
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


def counter_sum(mm, name):
    """sum of a metric_map's series named `name` (any labels; `name{...}` exact when labels are given), or None when
    no such series is present. Pure."""
    if '{' in name:
        v = mm.get(name)
        return float(v) if v is not None else None
    vals = [float(v) for k, v in mm.items() if k == name or k.startswith(name + '{')]
    return sum(vals) if vals else None


def event_lines(rows, prom=()):
    """one line per PENDING_EVENTS entry: its counters first -> last, and 'no event in S s / N blocks (node uptime
    U s)' or 'EVENT +n'; a counter absent from both scrapes is 'pending (absent)'. Pure."""
    good = [r for r in rows if ok(r.get('cs')) and ok(r.get('sync'))]          # the samples summarise() uses
    if not good:
        return []
    f, l = good[0], good[-1]
    span = round(l.get('epoch', 0) - f.get('epoch', 0)) if isinstance(l.get('epoch'), (int, float)) else 'pending'
    h0, h1 = f['sync'].get('height'), l['sync'].get('height')
    blocks = h1 - h0 if isinstance(h0, int) and isinstance(h1, int) else 'pending'
    den = f"{span} s / {blocks} blocks (node uptime {uptime(l) if uptime(l) is not None else 'pending'} s, {len(good)} samples)"
    prom = list(prom)
    m0, m1 = (metric_map(prom[0]), metric_map(prom[-1])) if prom else ({}, {})
    L = []
    for eid, what, names, field in PENDING_EVENTS:
        parts, delta, seen = [], 0.0, False
        for n in names:
            a, b = counter_sum(m0, n), counter_sum(m1, n)
            if a is None and b is None:
                parts.append(f'{n} absent')
                continue
            seen = True
            parts.append(f"{n} {a if a is not None else 'absent'} -> {b if b is not None else 'absent'}")
            delta += (b or 0.0) - (a or 0.0) if len(prom) > 1 else (b or 0.0)
        if field == 'peers_incoming':
            vals = [r['sync'].get('peers_incoming') for r in good if isinstance(r['sync'].get('peers_incoming'), (int, float))]
            if vals:                                 # r30: context only; the lane counters are B48's event
                parts.append(f'peers_incoming max {max(vals)} (context, not the event)')
        if not seen:
            verdict = 'pending (absent)'
        elif delta > 0:
            verdict = f'EVENT +{delta:g} in {den}'
        else:
            verdict = f'no event in {den}'
        L.append(f"pending-event {eid} ({what}): {verdict}; " + '; '.join(parts))
    return L


def invariant_lines(rows, prom=()):
    """r30: one line per INVARIANTS entry from the sample rows (B61) and the scrapes (B141, B152). Pure apart from the
    registry file B152 reads. A rule with no input says 'pending (no input)'."""
    good = [r for r in rows if ok(r.get('sync'))]
    L = []
    pairs = [(r['sync'].get('height'), r['sync'].get('topoheight')) for r in good]
    pairs = [p for p in pairs if all(isinstance(x, int) for x in p)]
    ne = sum(1 for h, t in pairs if h != t)
    L.append('invariant B61 (topoheight == height in every sample): ' + (
        'pending (no input)' if not pairs else f'INVARIANT BROKEN in {ne}/{len(pairs)} samples' if ne else f'holds {len(pairs)}/{len(pairs)} samples'))
    vals = [counter_sum(metric_map(t, ANY_RX), 'config_consensus_env_overrides') for t in prom]
    vals = [v for v in vals if v is not None]
    bad = sum(1 for v in vals if v != 0)
    L.append('invariant B141 (config_consensus_env_overrides == 0): ' + (
        'pending (no input)' if not vals else f'INVARIANT BROKEN in {bad}/{len(vals)} scrapes (max {max(vals):g})' if bad else f'holds {len(vals)}/{len(vals)} scrapes'))
    watch_rows = any((r.get('m') or {}).get('absent') is not None for r in rows)    # compact records: their own list
    L.append('invariant B152 (no source family absent unless lazy_by_design): ' + (_b152(rows) if watch_rows else lazy_line(prom)))
    return L


def lazy_line(prom, reg=None):
    """r30 (B152): the absent-family verdict over the scrapes (each scrape judged alone; a family absent from any
    scrape and not allow-listed breaks it)."""
    prom = [t for t in prom if t and not t.startswith('ERR ')]
    if not prom:
        return 'pending (no input)'
    try:
        MR = _registry_mod()
        reg = reg or json.loads((Path(__file__).resolve().parent.parent.parent / 'metrics' / 'metric_registry.json').read_text())
    except (OSError, ValueError):
        return 'pending (no metrics/metric_registry.json)'
    # r30 B260 (§0.12 D-18): a family is created on its first observation (vendored VictoriaMetrics), so a scrape taken
    # seconds after a derod START lacks families the build does export (2026-11-11 19:30:31: 15 families absent from
    # scrape 000, every one present from scrape 005 or 010). The verdict is therefore over the window: a non-lazy family
    # absent from the LAST scrape breaks the invariant (the build does not export it, or it vanished); one absent only
    # from earlier scrapes and present by the end is named 'appeared during the window', never a pass by omission.
    bad, lazy, early = set(), set(), set()
    for i, t in enumerate(prom):
        a, z = MR.absent_families(reg, t)
        if i == len(prom) - 1:
            bad |= set(a)
        else:
            early |= set(a)
        lazy |= set(z)
    early -= bad
    return (f'INVARIANT BROKEN: {sorted(bad)} absent and not lazy_by_design' if bad else f'holds over {len(prom)} scrape(s)') + \
        (f'; appeared during the window (absent from an earlier scrape, present by the last): {len(early)} {sorted(early)}'
         if early else '') + \
        f'; lazy_by_design absent {len(lazy)} of {len(MR.LAZY_BY_DESIGN)}' + (f' ({sorted(lazy)})' if lazy else '')


def row_status(rows, prom=()):
    """r30: {row id: (class, detail)} for every ROW_WATCH entry; class is 'event seen', 'registered, no event' or
    'absent' (rft §0.4: a 0 is not a reading, so 'no event' always carries its denominator). Pure."""
    good = [r for r in rows if ok(r.get('cs')) and ok(r.get('sync'))]
    out = {}
    if not good:
        return {eid: ('absent', 'no usable sample') for eid, *_ in ROW_WATCH}
    f, l = good[0], good[-1]
    span = round(l.get('epoch', 0) - f.get('epoch', 0)) if isinstance(l.get('epoch'), (int, float)) else 'pending'
    h0, h1 = f['sync'].get('height'), l['sync'].get('height')
    blocks = h1 - h0 if isinstance(h0, int) and isinstance(h1, int) else 'pending'
    den = f'{span} s / {blocks} blocks / {len(good)} samples'
    mms = [metric_map(t, ANY_RX) for t in prom if t and not t.startswith('ERR ')]
    pools = [r['info'].get('tx_pool_size') for r in good if ok(r.get('info')) and isinstance(r['info'].get('tx_pool_size'), int)]
    for eid, what, names, field in ROW_WATCH:
        seen, delta, parts = False, 0.0, []
        for n in names:
            vals = [counter_sum(m, n) for m in mms]
            vals = [v for v in vals if v is not None]
            if not vals:
                parts.append(f'{n} absent')
                continue
            seen = True
            d = (max(vals) - vals[0]) if len(vals) > 1 else 0.0
            if n == 'mempool_count':                       # a gauge: any non-zero value is the event
                d = max(vals)
            delta += d
            parts.append(f'{n} {vals[0]:g} -> {vals[-1]:g} (max {max(vals):g})')
        if field == 'peers_incoming':
            v = [r['sync'].get('peers_incoming') for r in good if isinstance(r['sync'].get('peers_incoming'), (int, float))]
            if v:
                parts.append(f'peers_incoming max {max(v)} (context: the lane counters are the event)')
        elif field in ('pool_nonempty', 'pool_ge2') and pools:
            seen = True
            k = 1 if field == 'pool_nonempty' else 2
            hit = sum(1 for x in pools if x >= k)
            delta += hit
            parts.append(f'tx_pool_size >= {k} in {hit}/{len(pools)} samples (max {max(pools)})')
        if not seen:
            out[eid] = ('absent', f'{what}: ' + ('; '.join(parts) if parts else 'no live series exists'))
        elif delta > 0.0:
            out[eid] = ('event seen', f'{what}: +{delta:g} in {den}; ' + '; '.join(parts))
        else:
            out[eid] = ('registered, no event', f'{what}: no event in {den}; ' + '; '.join(parts))
    return out


def summarise(rows, prom=(), restart_note=None):
    """the window's capture lines from the series rows and the /metrics scrape texts (first, last). Pure: no RPC, no
    peer address, no payee key (only counts and public chain values)."""
    good = [r for r in rows if ok(r.get('sync')) and ok(r.get('cs'))]
    if not good:
        return None
    L = []
    w = L.append
    if restart_note:
        w(f'# {restart_note}')
    f, l = good[0], good[-1]
    w(f"samples {len(rows)} ({len(good)} usable) from {rows[0].get('t')} to {rows[-1].get('t')}")
    if uptime(f) is not None:
        w(f"first sample {uptime(f)} s after the derod start (GetConsensusStats uptime_seconds at {f.get('t')})")
    ev = [r['event'] for r in rows if r.get('event')]
    if ev:
        w(f'events: {ev}')
    ups = [uptime(r) for r in good]
    rs = sum(1 for a, b in zip(ups, ups[1:]) if a is not None and b is not None and b < a)
    w(f'restarts inside the window (uptime fell between samples): {rs}')
    for tag, r in (('first', f), ('last', l)):
        s, cs = r['sync'], r['cs']
        w(f"{tag} {r.get('t')}: version {cs.get('version')} uptime {cs.get('uptime_seconds')} s height {s.get('height')} "
          f"status {s.get('status')} lag {s.get('lag_blocks')} tip_age {s.get('tip_age_seconds')} s out {s.get('peers_outgoing')} "
          f"in {s.get('peers_incoming')} recovered_panics {s.get('recovered_panics_total')}")
        ro = cs.get('reorg') or {}
        w(f"{tag} GetConsensusStats counters {json.dumps(cs.get('counters'), sort_keys=True)} reorgs {ro.get('reorgs')} "
          f"final_violations {ro.get('final_violations')}")
    S = [r['sync'] for r in good]
    st = [s.get('status') for s in S]
    ages = [s['tip_age_seconds'] for s in S if isinstance(s.get('tip_age_seconds'), (int, float))]
    lags = [s['lag_blocks'] for s in S if isinstance(s.get('lag_blocks'), (int, float))]
    outs = [s['peers_outgoing'] for s in S if isinstance(s.get('peers_outgoing'), (int, float))]
    errs = sum(1 for r in rows if any(isinstance(r.get(k), dict) and '_err' in r[k] for k in ('cs', 'sync', 'info')))
    w(f"series: status {dict(sorted((x, st.count(x)) for x in set(map(str, st))))}; lag max {max(lags) if lags else 'pending'}; "
      + (f"tip_age mean {statistics.mean(ages):.1f} s median {statistics.median(ages):.1f} max {max(ages):.1f}; " if ages else 'tip_age pending; ')
      + (f'outgoing min {min(outs)} max {max(outs)}; ' if outs else '') + f'RPC read errors {errs}')
    if isinstance(f['sync'].get('height'), int) and isinstance(l['sync'].get('height'), int):
        w(f"blocks in the window (first..last sample) {l['sync']['height'] - f['sync']['height']} "
          f"({f['sync']['height']}..{l['sync']['height']})")
    prom = list(prom)
    if len(prom) >= 2:
        d0, d1 = metric_map(prom[0]), metric_map(prom[-1])
        w(f'/metrics first vs last of {len(prom)} scrapes; nonzero at last or changed:')
        for k in sorted(set(d0) | set(d1)):
            if d1.get(k, '0') not in ('0', '0.0') or d0.get(k) != d1.get(k):
                w(f"  {k} {d0.get(k, 'absent')} -> {d1.get(k, 'absent')}")
    L += event_lines(rows, prom)                             # r28: pending events with their denominators
    L += invariant_lines(rows, prom)                         # r30: B61 B141 B152 graded as invariants
    return L


def headers_range(rpc, a, b, pruned):
    """(blocks, txs, fees) over topoheights a..b by GetBlockHeadersRange in chunks of 100; refuses a < pruned."""
    if pruned and a < pruned:
        raise Refused(f'topoheight {a} is below prunedheight {pruned} (rft §5)')
    nb = tx = fees = 0
    for s0 in range(a, b + 1, 100):
        res = rpc('DERO.GetBlockHeadersRange', {'start_topoheight': s0, 'end_topoheight': min(b, s0 + 99)}) or {}
        for h in res.get('headers') or []:
            nb, tx, fees = nb + 1, tx + h.get('txcount', 0), fees + h.get('fees', 0)
    return nb, tx, fees


def live_lines(rpc, rows):
    good = [r for r in rows if ok(r.get('sync'))]
    L = []
    info = rpc('DERO.GetInfo')
    pruned = info.get('prunedheight') if ok(info) else None
    if good and isinstance(good[0]['sync'].get('topoheight'), int):
        a, b = good[0]['sync']['topoheight'], good[-1]['sync']['topoheight']
        nb, tx, fees = headers_range(rpc, a, b, pruned)
        L.append(f'GetBlockHeadersRange {a}..{b}: {nb} headers, txcount total {tx}, fees total {fees}')
    e = rpc('DERO.GetEmissionAudit')
    if ok(e):
        L.append('GetEmissionAudit: ' + json.dumps({k: e[k] for k in e if not isinstance(e[k], (list, dict))}, sort_keys=True))
    return L


def read_series(path):
    rows = []
    for l in open(path):
        l = l.strip()
        if l:
            try:
                rows.append(json.loads(l))
            except ValueError:
                pass                                                 # a torn last line of a killed poller
    return rows


# ───────────────────────────── r30: the 24 h low-rate sampler ─────────────────────────────
WATCH_KEEP = tuple(sorted({n.split('{')[0] for _, _, names, _ in ROW_WATCH for n in names}
                          | {'config_consensus_env_overrides'}))


def compact_metrics(text):
    """the part of one scrape a watch record keeps: the watched series (summed over peer labels by metric_map) and the
    absent source families; never the raw text. Pure apart from the registry read."""
    if not text or text.startswith('ERR '):
        return {'err': (text or 'empty')[:200]}
    mm = metric_map(text, ANY_RX)
    keep = {k: v for k, v in mm.items() if k.split('{')[0] in WATCH_KEEP}
    try:
        MR = _registry_mod()
        reg = json.loads((Path(__file__).resolve().parent.parent.parent / 'metrics' / 'metric_registry.json').read_text())
        absent, lazy = MR.absent_families(reg, text)
    except (OSError, ValueError):
        absent, lazy = None, None
    return {'series': keep, 'absent': absent, 'lazy_absent': lazy}


def prom_of(rec):
    """the Prometheus text a compact record stands for (only the kept series), so row_status/invariant_lines read
    watch records and full scrapes alike. Pure."""
    m = rec.get('m') or {}
    return '\n'.join(f'{k} {v}' for k, v in (m.get('series') or {}).items()) + '\n' if 'series' in m else ''


CONTENTION_KEYS = ('contended', 'foreign_cores', 'miner_cores', 'node_cores', 'budget_cores', 'budget_fraction', 'starved',
                   'headroom_cores', 'load1', 'interval_s', 'regression_claims')


def make_contender(ps=None, caps=None, clock=time.time):
    """r30 (coordinator 2026-11-09: B5/B7 reads must exclude contended segments): a callable that returns the
    contention verdict of the SEGMENT since its previous call (harness/intel/contention.py census over two read-only
    `ps` samples, the miner's caps from its /metrics). Only numbers are kept: no process name, pid or path. The first
    call has no segment: contended None."""
    import importlib.util
    sp = importlib.util.spec_from_file_location('contention_lw', Path(__file__).resolve().parent / 'contention.py')
    C = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(C)
    state = {'prev': None}

    def contend():
        try:
            cur = C.sample(ps or C.ps_text, clock)
        except Exception as e:                                   # noqa: BLE001 — a failed ps is a reading
            state['prev'] = None
            return {'contended': None, 'why': f'ps failed: {type(e).__name__}'}
        prev, state['prev'] = state['prev'], cur
        if prev is None:
            return {'contended': None, 'why': 'first sample of this run: no segment'}
        th, cm = (caps or C.miner_caps)()
        try:
            load1 = os.getloadavg()[0]
        except OSError:
            load1 = None
        v = C.verdict(C.census(prev, cur), None, th, cm, load1)
        return {k: v.get(k) for k in CONTENTION_KEYS if k in v} or {'contended': None, 'why': v.get('why')}
    return contend


def contention_line(rows):
    """r30: how many sampler segments were contended (so B5/B7 reads can exclude them). Pure."""
    seg = [(r.get('contention') or {}).get('contended') for r in rows]
    c, q, u = sum(1 for x in seg if x is True), sum(1 for x in seg if x is False), sum(1 for x in seg if x is None)
    return f'contention: {c} contended / {q} quiet / {u} unknown segments of {len(seg)} (contention.py census per segment)'


def watch_record(rpc, metrics, clock=time.time, contend=None):
    rec = sample(rpc, clock)
    rec['m'] = compact_metrics(metrics()) if metrics else {}
    if contend:
        rec['contention'] = contend()
    return json.loads(privkit.mask(json.dumps(rec)))     # masked before the line exists (rft §5)


def watch_status(d):
    """(lines, n) of the row classes and invariants over a watch directory's series. Pure apart from the reads."""
    rows = read_series(str(Path(d) / 'series.jsonl')) if (Path(d) / 'series.jsonl').exists() else []
    prom = [prom_of(r) for r in rows if (r.get('m') or {}).get('series') is not None]
    st = row_status(rows, prom)
    L = [f'watch {d}: {len(rows)} samples' + (f" from {rows[0].get('t')} to {rows[-1].get('t')}" if rows else '')]
    L += [f'row {k}: {c} | {det}' for k, (c, det) in st.items()]
    L.append(contention_line(rows))
    inv = invariant_lines(rows, [])
    inv[1] = 'invariant B141 (config_consensus_env_overrides == 0): ' + _b141(rows)
    inv[2] = 'invariant B152 (no source family absent unless lazy_by_design): ' + _b152(rows)
    return L + inv, len(rows)


def _b141(rows):
    v = [(r.get('m') or {}).get('series', {}).get('config_consensus_env_overrides') for r in rows]
    v = [float(x) for x in v if x is not None]
    if not v:
        return 'pending (no input)'
    bad = sum(1 for x in v if x != 0)
    return f'INVARIANT BROKEN in {bad}/{len(v)} scrapes' if bad else f'holds {len(v)}/{len(v)} scrapes'


def _b152(rows):
    ab = [(r.get('m') or {}).get('absent') for r in rows if (r.get('m') or {}).get('absent') is not None]
    if not ab:
        return 'pending (no input)'
    bad = sorted({x for a in ab for x in a})
    lz = sorted({x for r in rows for x in ((r.get('m') or {}).get('lazy_absent') or [])})
    return (f'INVARIANT BROKEN: {bad} absent and not lazy_by_design' if bad else f'holds over {len(ab)} scrape(s)') + \
        f'; lazy_by_design absent at least once: {len(lz)} {lz}'


def watch(d, end, rpc, metrics, step=300.0, clock=time.time, sleep=time.sleep, contend=None):
    """the sampler loop: one masked record per `step` into <d>/series.jsonl until `end` or a STOP file; progress.json
    and status.txt after every sample; DONE at the end. Returns the samples written this run."""
    d = Path(d)
    d.mkdir(parents=True, exist_ok=True)
    n0 = len(read_series(str(d / 'series.jsonl'))) if (d / 'series.jsonl').exists() else 0
    i = 0
    while clock() < end and not (d / 'STOP').exists():
        t = clock()
        rec = watch_record(rpc, metrics, clock, contend)
        with open(d / 'series.jsonl', 'a') as f:
            f.write(json.dumps(rec) + '\n')
        i += 1
        errs = [k for k in ('cs', 'sync', 'info') if not ok(rec.get(k))]
        L, n = watch_status(d)
        _atomic(d / 'status.txt', '\n'.join(L) + '\n')
        _atomic(d / 'progress.json', json.dumps({'samples': n0 + i, 'last_t': rec.get('t'), 'end_epoch': end, 'pid': os.getpid(),
                                                 'last_errors': errs}) + '\n')
        while clock() - t < step and clock() < end and not (d / 'STOP').exists():
            sleep(min(5.0, max(0.1, step - (clock() - t))))
    why = 'stopped (STOP file)' if (d / 'STOP').exists() else 'end reached'
    _atomic(d / 'DONE', f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} {why}; samples {n0 + i}\n")
    return i


def _atomic(path, text):
    tmp = str(path) + '.tmp'
    with open(tmp, 'w') as f:
        f.write(text)
    os.replace(tmp, path)


def watch_cmd(d, step, rpc_url, py=sys.executable):
    """the command line stallwatch relaunches (resumes to plan.json's end). Pure."""
    import shlex
    me = Path(__file__).resolve()
    return (f"cd {shlex.quote(str(me.parent.parent.parent))} && exec nice -n 15 {shlex.quote(py)} -I {shlex.quote(str(me))} "
            f"watch --dir {shlex.quote(str(d))} --resume --step {step:g} --rpc {shlex.quote(rpc_url)}")


def watch_match(d):
    """the stallwatch --match text: what `ps` shows of the sampler's argv (no shell quotes). Pure."""
    return f"live_window.py watch --dir {d} --resume"


def _pid_alive(pid):
    """True while `pid` exists (os.kill(pid, 0) succeeds or fails with EPERM); it never signals the process."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def watch_start_refusal(d, alive=_pid_alive):
    """r30 fix D3: why watch-start must not start in `d`, or None. Checked BEFORE any side effect (no mkdir, no
    STOP/DONE unlink, no plan.json/CMD write): (a) a space or quote in the dir (the stallwatch --match reads the plain
    argv, so a quoted dir never matches and the watchdog would relaunch a duplicate every check); (b) progress.json
    names a live pid (a sampler is already running there: a restart would delete its STOP/DONE and rewrite its plan).
    Pure given `alive`."""
    d = str(d)
    if any(c in d for c in (' ', "'", '"')):
        return f'{d} contains a space or quote (the stallwatch match reads the plain argv)'
    try:
        pid = json.loads((Path(d) / 'progress.json').read_text()).get('pid')
    except (OSError, ValueError, AttributeError):
        pid = None
    if pid is not None and alive(pid):
        return f'a sampler is already running in {d} (progress.json pid {pid} is alive): watch-stop it first, or use another dir'
    return None


def watch_start(dir_, hours, step, stall_s, rpc_url, popen=None, now=time.time, alive=_pid_alive):
    """write plan.json + CMD and start the sampler under kit/stallwatch.py in the background. Exit 0 started, 2 refused
    (nothing written). `popen` is injectable (KAT)."""
    d = Path(dir_).resolve()
    why = watch_start_refusal(d, alive)
    if why:
        print(f'refused: {why}', file=sys.stderr)
        return 2
    d.mkdir(parents=True, exist_ok=True)
    for x in ('STOP', 'DONE'):
        (d / x).unlink(missing_ok=True)
    end = now() + hours * 3600
    _atomic(d / 'plan.json', json.dumps({'end_epoch': end, 'step_s': step, 'rpc': rpc_url, 'started': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
                                         'hours': hours}) + '\n')
    (d / 'CMD').write_text(watch_cmd(d, step, rpc_url) + '\n')
    sw = Path(__file__).resolve().parent.parent / 'kit' / 'stallwatch.py'
    args = [sys.executable, '-I', str(sw), '--match', watch_match(d), '--cmd-file', str(d / 'CMD'),
            '--progress', str(d / 'progress.json'), '--counter', 'samples', '--work', str(d / 'series.jsonl'),
            '--done', str(d / 'DONE'), '--stall-s', f'{stall_s:g}', '--log', str(d / 'stallwatch.log')]
    if popen is None:
        import subprocess
        popen = lambda argv: subprocess.Popen(argv, start_new_session=True, stdin=subprocess.DEVNULL,
                                              stdout=open(d / 'stallwatch.out', 'a'), stderr=subprocess.STDOUT)
    pr = popen(['nice', '-n', '15'] + args)
    (d / 'stallwatch.pid').write_text(f'{pr.pid}\n')
    print(f'stallwatch pid {pr.pid} (it launches the sampler within its first check); end {time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(end))}')
    print(f'records: {d}/series.jsonl · status: {d}/status.txt · stop: python3 -I {Path(__file__).resolve()} watch-stop --dir {d}')
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('poll', help='sample the node every --step s into a JSONL series')
    p.add_argument('--out', required=True)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--minutes', type=float)
    g.add_argument('--until', type=float, help='epoch seconds')
    p.add_argument('--step', type=float, default=60.0)
    p.add_argument('--metrics-every', type=int, default=5)
    p.add_argument('--wait-restart', action='store_true', help='start the window at the next derod restart')
    p.add_argument('--fast-step', type=float, default=5.0)
    p.add_argument('--wait-max-s', type=float, default=86400.0)
    p.add_argument('--rpc', default=RPC_URL)
    s = sub.add_parser('summary', help='summarise a series (pure; --live adds read-only chain reads)')
    s.add_argument('--series', required=True)
    s.add_argument('--out')
    s.add_argument('--live', action='store_true')
    s.add_argument('--restart-note')
    s.add_argument('--rpc', default=RPC_URL)
    w = sub.add_parser('watch', help='r30: the low-rate sampler (masked records, progress.json, status.txt, DONE)')
    w.add_argument('--dir', required=True)
    gw = w.add_mutually_exclusive_group(required=True)
    gw.add_argument('--hours', type=float)
    gw.add_argument('--until', type=float)
    gw.add_argument('--resume', action='store_true', help='continue to the end in <dir>/plan.json')
    w.add_argument('--step', type=float, default=300.0)
    w.add_argument('--rpc', default=RPC_URL)
    ws = sub.add_parser('watch-start', help='r30: write plan.json and start watch under kit/stallwatch.py in the background')
    ws.add_argument('--dir', required=True)
    ws.add_argument('--hours', type=float, default=24.0)
    ws.add_argument('--step', type=float, default=300.0)
    ws.add_argument('--stall-s', type=float, default=1200.0)
    ws.add_argument('--rpc', default=RPC_URL)
    for nm in ('watch-stop', 'watch-status'):
        x = sub.add_parser(nm)
        x.add_argument('--dir', required=True)
        x.add_argument('--rpc', default=RPC_URL)
    a = ap.parse_args(argv)
    try:
        rpc = make_rpc(a.rpc)
    except Refused as e:
        print(f'refused: {e}', file=sys.stderr)
        return 2
    if a.cmd == 'watch-status':
        L, _ = watch_status(a.dir)
        print('\n'.join(L))
        return 0
    if a.cmd == 'watch-stop':
        Path(a.dir).mkdir(parents=True, exist_ok=True)
        (Path(a.dir) / 'STOP').write_text(time.strftime('%Y-%m-%dT%H:%M:%S%z') + '\n')
        print(f'STOP written: the sampler writes DONE within 5 s and stallwatch exits at its next check (<= 60 s); {a.dir}/status.txt keeps the reading')
        return 0
    if a.cmd == 'watch-start':
        return watch_start(a.dir, a.hours, a.step, a.stall_s, a.rpc)
    if a.cmd == 'watch':
        d = Path(a.dir)
        if a.resume:
            try:
                end = float(json.loads((d / 'plan.json').read_text())['end_epoch'])
            except (OSError, ValueError, KeyError):
                print('no plan.json to resume', file=sys.stderr)
                return 2
        else:
            end = a.until if a.until else time.time() + a.hours * 3600
            d.mkdir(parents=True, exist_ok=True)
            _atomic(d / 'plan.json', json.dumps({'end_epoch': end, 'step_s': a.step}) + '\n')
        n = watch(d, end, rpc, make_metrics(a.rpc), a.step, contend=make_contender())
        print(f'{n} samples -> {d}/series.jsonl')
        return 0
    if a.cmd == 'poll':
        event = None
        if a.wait_restart:
            got = wait_restart(rpc, a.fast_step, a.wait_max_s)
            if got is None:
                print(f'no restart within {a.wait_max_s:.0f} s', file=sys.stderr)
                return 4
            event = f'restart seen at {time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(got[0]))} (uptime {got[1]} s)'
        end = a.until if a.until else time.time() + a.minutes * 60
        n = poll(a.out, end, rpc, make_metrics(a.rpc), a.step, a.metrics_every, event=event)
        print(f'{n} samples -> {a.out}')
        return 0 if n else 3
    rows = read_series(a.series)
    base = a.series[:-len('.jsonl')] if a.series.endswith('.jsonl') else a.series
    prom = [open(x).read() for x in sorted(glob.glob(glob.escape(base) + '_metrics_*.prom'))]
    if not prom:                                         # r30: a watch series keeps compact scrapes in its records
        prom = [prom_of(r) for r in rows if (r.get('m') or {}).get('series') is not None]
    L = summarise(rows, prom, a.restart_note)
    if L is None:
        print('no usable sample in the series', file=sys.stderr)
        return 3
    if a.live:
        try:
            L += live_lines(rpc, rows)
        except Refused as e:
            L.append(f'live reads refused: {e}')
    text = '\n'.join(L) + '\n'
    if a.out:
        tmp = a.out + '.tmp'
        with open(tmp, 'w') as f:
            f.write(text)
        os.replace(tmp, a.out)
    print(text, end='')
    return 0


if __name__ == '__main__':
    sys.exit(main())
