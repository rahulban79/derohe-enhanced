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

READ-ONLY. Only JSON-RPC POSTs of read methods (READ_METHODS) and GET /metrics to a loopback URL; the default is
127.0.0.1:10102 with Content-Type: application/json. The getwork port 10100 and the P2P port 11011 are refused
(rft §5), as is any non-loopback host. GetPeerInfo is not read (it carries peer addresses): peer counts come from
GetSyncInfo. Writes only the --out series file, its *_metrics_NNN.prom scrapes and the summary --out file.

  python3 -I harness/intel/live_window.py poll --out S.jsonl (--minutes N | --until EPOCH) [--step 60]
                                          [--metrics-every 5] [--wait-restart [--fast-step 5] [--wait-max-s 86400]]
  python3 -I harness/intel/live_window.py summary --series S.jsonl [--out window.txt] [--live] [--restart-note TEXT]
Exit 0 · 2 bad arguments or a refused endpoint · 3 the window has no usable sample · 4 --wait-restart saw no restart.
"""
import argparse, glob, json, os, re, statistics, sys, time, urllib.parse, urllib.request

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
                f.write(metrics())
            rec['metrics'] = i
        with open(out, 'a') as f:
            f.write(json.dumps(rec) + '\n')
        i += 1
        sleep(max(1.0, step - (clock() - t)))
    return i


METRIC_RX = re.compile(r'^((?:rpc|p2p|blockchain|block|txpool|mempool|dero_emission)_[a-z_]+)(\{[^}]*\})? (\S+)$', re.M)


PEER_LABEL_RX = re.compile(r'(?:peer|addr|ip|remote)="|(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')


def metric_map(text):
    """{series: value} of the /metrics text. A series whose labels name a peer (a peer/addr/ip/remote label, or any
    IPv4 in a label value, e.g. p2p_first_relay_total{peer="<ip>"}) is summed into one `name{peer=*}` series, so no
    peer address reaches the summary (rft §5 privacy; seen on the r26 node 2026-11-05). Pure."""
    out, agg = {}, {}
    for name, labels, v in METRIC_RX.findall(text or ''):
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
    a = ap.parse_args(argv)
    try:
        rpc = make_rpc(a.rpc)
    except Refused as e:
        print(f'refused: {e}', file=sys.stderr)
        return 2
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
