#!/usr/bin/env python3
"""R25 forensics acquisition (artifacts/dero-rft.md §0.8.4, §7 B73-B76; stage forensics-acquire).

Read-only. Talks only to: the live derod RPC on loopback (behind the PRUNE GUARD) and public DERO daemon RPC
endpoints listed in a PRIVATE endpoints file (pseudonym -> url; never in tracked output). Each external endpoint
is rate-limited (<= RATE req/s, one in-flight request), with timeouts and backoff. Every fetched byte lands in an
EXT staging dir outside the dataset; `verify` promotes an object to RAW only after checks (i)-(iii)
(harness/forensics/provenance.py), and writes refused objects to audit/rejected.jsonl.

  python3 -I harness/forensics/acquire.py probe        --priv DIR --out DATASET
  python3 -I harness/forensics/acquire.py fetch-blocks --priv DIR --stage DIR --from T0 --to T1 [--sources src-1,..]
  python3 -I harness/forensics/acquire.py fetch-txs    --priv DIR --stage DIR --txids FILE
  python3 -I harness/forensics/acquire.py anchor       --stage DIR          (live derod, topo = its prunedheight)

PRUNE GUARD (B85, KAT MF11): LiveRPC reads the live node's prunedheight first and refuses, before anything is sent,
any request whose height/topoheight is below it and any state-read method without an explicit topoheight >= it.
"""
import argparse, json, os, queue, sys, threading, time, urllib.request, urllib.error
from pathlib import Path

RATE = 4.0            # req/s per external endpoint (task limit: <= 5)
TIMEOUT = 15
LIVE_URL = 'http://127.0.0.1:10102/json_rpc'
STATE_METHODS = {'DERO.GetEncryptedBalance', 'DERO.GetSC', 'DERO.GetRandomAddress', 'DERO.NameToAddress'}
HEIGHT_KEYS = ('height', 'topoheight', 'TopoHeight')


class PruneRefused(Exception):
    pass


def _post(url, method, params, timeout=TIMEOUT):
    body = {'jsonrpc': '2.0', 'id': '1', 'method': method}
    if params is not None:
        body['params'] = params
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read(16 << 20))


def guard_check(prunedheight, method, params):
    """Raise PruneRefused if this request could read below prunedheight on the live node (pure; KAT MF11)."""
    if prunedheight is None:
        raise PruneRefused('prunedheight unknown: refusing every live request but GetInfo')
    p = params or {}
    for k in HEIGHT_KEYS:
        if k in p and p[k] is not None and int(p[k]) < int(prunedheight):
            raise PruneRefused(f'{method}: {k}={p[k]} below prunedheight {prunedheight}')
    if method in STATE_METHODS:
        t = p.get('topoheight')
        if t is None or int(t) < int(prunedheight):
            raise PruneRefused(f'{method}: state read needs an explicit topoheight >= prunedheight {prunedheight}')
    return True


class LiveRPC:
    """The live derod, read-only, behind the prune guard. GetInfo is always first."""

    def __init__(self, url=LIVE_URL, post=_post):
        self.url, self._post, self.sent = url, post, []
        info = self._post(self.url, 'DERO.GetInfo', None)['result']
        self.sent.append('DERO.GetInfo')
        self.info = info
        self.prunedheight = info.get('prunedheight')

    def call(self, method, params=None):
        guard_check(self.prunedheight, method, params)
        self.sent.append(method)
        time.sleep(0.05)
        return self._post(self.url, method, params)


class Limiter:
    def __init__(self, rate):
        self.dt, self.next, self.lock = 1.0 / rate, 0.0, threading.Lock()

    def wait(self):
        with self.lock:
            now = time.monotonic()
            t = max(now, self.next)
            self.next = t + self.dt
        if t > now:
            time.sleep(t - now)


def load_endpoints(priv):
    return json.load(open(Path(priv) / 'endpoints.json'))


def utcnow():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


# ------------------------------------------------------------------------------------------------- probe
def cmd_probe(a):
    eps = load_endpoints(a.priv)
    out = {}
    for name in sorted(eps, key=lambda s: int(s.split('-')[1])):
        url = eps[name]['url']
        rec = {'getinfo_time': utcnow()}
        try:
            r = _post(url, 'DERO.GetInfo', None, timeout=8)['result']
            rec.update(version=r.get('version'), height=r.get('height'), topoheight=r.get('topoheight'),
                       prunedheight=r.get('prunedheight', 'absent'))
        except Exception as e:
            rec['error'] = type(e).__name__
        time.sleep(0.3)
        out[name] = rec
        print(name, rec, flush=True)
    Path(a.out).mkdir(parents=True, exist_ok=True)
    json.dump(out, open(Path(a.out) / 'sources_getinfo.json', 'w'), indent=1, sort_keys=True)


# ------------------------------------------------------------------------------------------------- blocks
def stage_block_path(stage, topo):
    return Path(stage) / 'blocks' / str(topo // 1000) / f'{topo}.json'


def fetch_worker(name, url, q, stage, stats, stop):
    lim = Limiter(RATE)
    while not stop.is_set():
        try:
            topo, tries = q.get(timeout=1)
        except queue.Empty:
            if stats['_done'].is_set():
                return
            continue
        lim.wait()
        t0 = time.time()
        try:
            j = _post(url, 'DERO.GetBlock', {'height': topo})
            if j.get('error'):
                raise RuntimeError(str(j['error'])[:120])
            r = j['result']
            rec = {'topo_requested': topo, 'source': name, 'fetch_time': utcnow(), 'class': 'EXT',
                   'claimed_hash': r['block_header']['hash'], 'blob': r['blob'],
                   'header_ext': {k: r['block_header'].get(k) for k in
                                  ('height', 'topoheight', 'timestamp', 'reward', 'txcount', 'major_version',
                                   'minor_version', 'orphan_status', 'syncblock', 'sideblock', 'difficulty', 'tips',
                                   'miners')}}
            p = stage_block_path(stage, topo)
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix('.tmp')
            tmp.write_text(json.dumps(rec))
            os.replace(tmp, p)
            with stats['lock']:
                stats['ok'] += 1
                stats['by_src'][name] = stats['by_src'].get(name, 0) + 1
        except Exception as e:
            err = f'{type(e).__name__}: {str(e)[:100]}'
            with stats['lock']:
                stats['err'] += 1
                stats['errors'].append({'topo': topo, 'source': name, 'error': err, 't': utcnow()})
            if tries < 4:
                time.sleep(min(30, 2 ** tries))
                q.put((topo, tries + 1))
            else:
                with stats['lock']:
                    stats['gave_up'].append(topo)
        finally:
            q.task_done()
        _ = t0


def cmd_fetch_blocks(a):
    eps = load_endpoints(a.priv)
    names = a.sources.split(',') if a.sources else sorted(eps)
    q = queue.Queue()
    todo = [t for t in range(a.from_, a.to + 1) if not stage_block_path(a.stage, t).exists()]
    for t in todo:
        q.put((t, 0))
    stats = {'ok': 0, 'err': 0, 'errors': [], 'gave_up': [], 'by_src': {}, 'lock': threading.Lock(),
             '_done': threading.Event()}
    stop = threading.Event()
    print(f'{utcnow()} fetch-blocks {a.from_}..{a.to}: {len(todo)} to fetch via {names}', flush=True)
    ths = [threading.Thread(target=fetch_worker, args=(n, eps[n]['url'], q, a.stage, stats, stop), daemon=True)
           for n in names]
    for t in ths:
        t.start()
    last = time.time()
    while q.unfinished_tasks:
        time.sleep(2)
        if time.time() - last > 60:
            last = time.time()
            print(f"{utcnow()} ok={stats['ok']} err={stats['err']} left~{q.qsize()} by_src={stats['by_src']}", flush=True)
    stats['_done'].set()
    stop.set()
    for t in ths:
        t.join(timeout=5)
    log = Path(a.stage) / f'fetch_blocks_{a.from_}_{a.to}_{time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())}.json'
    json.dump({k: v for k, v in stats.items() if k not in ('lock', '_done')}, open(log, 'w'), indent=1)
    print(f"{utcnow()} done ok={stats['ok']} err={stats['err']} gave_up={len(stats['gave_up'])} log={log.name}", flush=True)


# ------------------------------------------------------------------------------------------------- txs
def cmd_fetch_txs(a):
    eps = load_endpoints(a.priv)
    names = a.sources.split(',') if a.sources else sorted(eps)
    txids = [l.strip() for l in open(a.txids) if l.strip()]
    d = Path(a.stage) / 'txs'
    d.mkdir(parents=True, exist_ok=True)
    lim = {n: Limiter(a.rate) for n in names}
    errors = []
    for i in range(0, len(txids), 10):
        batch = [t for t in txids[i:i + 10] if not (d / f'{t}.json').exists()]
        if not batch:
            continue
        for k in range(len(names) * 2):
            n = names[(i // 10 + k) % len(names)]
            lim[n].wait()
            try:
                j = _post(eps[n]['url'], 'DERO.GetTransaction', {'txs_hashes': batch})
                if j.get('error'):
                    raise RuntimeError(str(j['error'])[:120])
                r = j['result']
                hexes, infos = r.get('txs_as_hex') or [], r.get('txs') or []
                if len(hexes) != len(batch) or len(infos) != len(batch):
                    raise RuntimeError(f'reply length {len(hexes)}/{len(infos)} != {len(batch)} asked')
                for t, hx, info in zip(batch, hexes, infos):
                    # the body is in txs_as_hex[i] (rpc_dero_gettransactions.go appends there; Tx_Related_Info.as_hex
                    # is never filled), '' = not in the serving node's store
                    rec = {'txid_requested': t, 'source': n, 'fetch_time': utcnow(), 'class': 'EXT',
                           'as_hex': hx or '',
                           'info_ext': {k2: info.get(k2) for k2 in ('block_height', 'in_pool', 'valid_block',
                                                                     'invalid_block', 'ignored', 'reward')}}
                    (d / f'{t}.json').write_text(json.dumps(rec))
                break
            except Exception as e:
                errors.append({'batch_start': i, 'source': n, 'error': f'{type(e).__name__}: {str(e)[:100]}'})
                time.sleep(2)
    json.dump(errors, open(Path(a.stage) / 'fetch_txs_errors.json', 'w'), indent=1)
    print(f'{utcnow()} fetch-txs: {len(txids)} asked, errors {len(errors)}', flush=True)


# ------------------------------------------------------------------------------------------------- anchor
def cmd_anchor(a):
    live = LiveRPC()
    p = int(live.prunedheight)
    r = live.call('DERO.GetBlock', {'height': p})['result']
    rec = {'topo': p, 'source': 'live-rpc', 'fetch_time': utcnow(), 'claimed_hash': r['block_header']['hash'],
           'blob': r['blob'], 'live_getinfo': {k: live.info.get(k) for k in ('version', 'height', 'topoheight',
                                                                                'prunedheight', 'treehash')}}
    Path(a.stage).mkdir(parents=True, exist_ok=True)
    (Path(a.stage) / 'anchor_live.json').write_text(json.dumps(rec))
    print('anchor', p, rec['claimed_hash'], 'sent', live.sent)


def main(argv=None):
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest='cmd', required=True)
    p = sp.add_parser('probe'); p.add_argument('--priv', required=True); p.add_argument('--out', required=True)
    p = sp.add_parser('fetch-blocks'); p.add_argument('--priv', required=True); p.add_argument('--stage', required=True)
    p.add_argument('--from', dest='from_', type=int, required=True); p.add_argument('--to', type=int, required=True)
    p.add_argument('--sources', default='')
    p = sp.add_parser('fetch-txs'); p.add_argument('--priv', required=True); p.add_argument('--stage', required=True)
    p.add_argument('--txids', required=True); p.add_argument('--sources', default='')
    p.add_argument('--rate', type=float, default=1.0)  # req/s per endpoint; may run beside fetch-blocks (sum <= 5)
    p = sp.add_parser('anchor'); p.add_argument('--stage', required=True)
    a = ap.parse_args(argv)
    {'probe': cmd_probe, 'fetch-blocks': cmd_fetch_blocks, 'fetch-txs': cmd_fetch_txs, 'anchor': cmd_anchor}[a.cmd](a)


if __name__ == '__main__':
    main()
