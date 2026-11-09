#!/usr/bin/env python3
"""R29 B182 option (ii) (rft §7 B182; user 2026-11-08: "... done with efficiency and high performance so that it can be
done quickly"): a fast, resumable, verified registration census over topoheights FROM..TO (default 0..7,398,264, the
part below what harness/forensics/b182_fetch_census_r29.py covered) from public archive RPC endpoints, read-only.

Speed (measured, see `bench`): JSON-RPC BATCH requests (B GetBlock calls per HTTP request; one GetTransaction call per
<= TXB txids), several requests in flight per endpoint, every endpoint that serves deep history, and nothing written
per block. Politeness: per endpoint a token bucket of at most RATE HTTP requests/s and at most INFLIGHT requests in
flight (defaults 5 and 4; hard caps 50 and 8), halved on an error or a latency rise (AIMD), restored slowly.

Verification (every block and every tx, no sampling): the node's own decoder (tools/forensics/b182deep, consensus
packages imported unchanged) must re-derive each block's id = the hash the endpoint claimed, re-serialize it
byte-exact, and give height = the requested topoheight; each tx body must re-derive exactly the requested txid and
re-serialize byte-exact (its type then comes from the decoder, never from the endpoint). Chain: every block's tips
must be ids of blocks already verified within the last WINDOW topoheights (so no block can be skipped or replaced),
topo 1's tip is the fetched genesis, and at the end the first held block above the range (7,398,265, a RAW block of
the c5f4c2c6 fetch) must have its tips among the last verified ids (the join).

Resume: an append-only checkpoint, one CRC32-sealed JSON line per verified batch, fsync'd; a torn or CRC-bad line and
everything after it is ignored, so a stop loses at most the batches in flight; a re-run skips verified batches and
gives the same counts (idempotent). Staging keeps only the checkpoint, the progress file and, for any registration
with fewer than 3 leading zero bytes, its block and tx hex (evidence); per batch a sha256 digest over its block ids.

  python3 -I harness/forensics/b182_deep_r29.py run   --priv DIR --stage DIR --decoder BIN [--from 0 --to 7398264]
            [--sources src-1,src-2] [--batch 100] [--inflight 4] [--rate 5] [--join FILE] [--stop-after N]
  python3 -I harness/forensics/b182_deep_r29.py bench --priv DIR --stage DIR --decoder BIN --from T --blocks N ...
  python3 -I harness/forensics/b182_deep_r29.py report --stage DIR [--out JSON]
"""
import argparse, collections, heapq, json, os, queue, subprocess, threading, time, urllib.request, zlib
from pathlib import Path

HARD_RATE, HARD_INFLIGHT = 50.0, 8
WINDOW = 64            # tips must name a block verified within the last WINDOW topoheights
KEEP_IDS = 16          # ids persisted per checkpoint record (DERO tips reference the previous few heights)
REG = 'REGISTRATION'
UNSERVED = 'UNSERVED'  # a txid no endpoint returned a body for: counted, never typed
REQ_TXIDS = 512       # txids per HTTP request: a 100-block batch near topo 155,000 lists ~8,700, one request timed out
EVID_MAX = 2000        # registrations < 3 zero bytes whose block + tx hex are kept as evidence (the txids are all kept)


def lz(h):
    n = 0
    for x in bytes.fromhex(h):
        if x:
            break
        n += 1
    return n


def utcnow():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


# ------------------------------------------------------------------------------------------- checkpoint (pure parts)
def seal(obj):
    """one checkpoint line: the JSON body and its CRC32 (pure)."""
    body = json.dumps(obj, sort_keys=True, separators=(',', ':'))
    return f'{zlib.crc32(body.encode()):08x} {body}\n'


def unseal(lines):
    """(records, n_ignored): records up to the first torn or CRC-bad line; that line and all after it are ignored
    (pure)."""
    recs = []
    for i, ln in enumerate(lines):
        if not ln.endswith('\n') or len(ln) < 10 or ln[8] != ' ':
            return recs, len(lines) - i
        crc, body = ln[:8], ln[9:-1]
        if f'{zlib.crc32(body.encode()):08x}' != crc:
            return recs, len(lines) - i
        recs.append(json.loads(body))
    return recs, 0


class Checkpoint:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lines = open(self.path, 'r', encoding='utf-8').readlines() if self.path.exists() else []
        self.records, self.ignored = unseal(lines)
        if self.ignored:                                   # cut the torn tail so new records follow a valid line
            good = ''.join(lines[:len(lines) - self.ignored])
            tmp = self.path.with_suffix('.cut')
            tmp.write_text(good, encoding='utf-8')
            os.replace(tmp, self.path)
        self.f = open(self.path, 'a', encoding='utf-8')

    def append(self, rec):
        self.f.write(seal(rec))
        self.f.flush()
        os.fsync(self.f.fileno())
        self.records.append(rec)

    def done_ranges(self):
        return {(r['lo'], r['hi']) for r in self.records if r.get('kind') == 'batch'}


# ------------------------------------------------------------------------------------------- politeness
class TokenBucket:
    """at most `rate` acquisitions per second (burst 1); clock/sleep injectable for the KAT."""

    def __init__(self, rate, clock=time.monotonic, sleep=time.sleep):
        self.dt, self.next, self.lock, self.clock, self.sleep = 1.0 / rate, 0.0, threading.Lock(), clock, sleep

    def acquire(self):
        with self.lock:
            now = self.clock()
            t = max(now, self.next)
            self.next = t + self.dt
        if t > now:
            self.sleep(t - now)


class Endpoint:
    """one archive endpoint: token bucket + AIMD in-flight limit (errors or a latency rise halve it; 20 clean replies
    near the baseline add one back, never above the cap)."""

    def __init__(self, name, url, rate, inflight, clock=time.monotonic, sleep=time.sleep):
        self.name, self.url = name, url
        self.rate, self.cap = min(rate, HARD_RATE), max(1, min(inflight, HARD_INFLIGHT))
        self.limit, self.busy, self.clean = self.cap, 0, 0
        self.txcap = 1 << 30                                 # txids per GetTransaction call, learned from replies
        self.bucket, self.sleep = TokenBucket(self.rate, clock, sleep), sleep
        self.cv = threading.Condition()
        self.base = None
        self.stats = {'ok': 0, 'err': 0, 'blocks': 0, 'txs': 0, 'lat_sum': 0.0, 'backoffs': 0}

    def enter(self, stop):
        with self.cv:
            while self.busy >= self.limit and not stop.is_set():
                self.cv.wait(0.5)
            self.busy += 1
        self.bucket.acquire()

    def leave(self, ok, lat=None):
        with self.cv:
            self.busy -= 1
            if ok:
                self.stats['ok'] += 1
                self.stats['lat_sum'] += lat
                self.base = lat if self.base is None else min(self.base * 1.01, 0.9 * self.base + 0.1 * lat)
                if lat > 3 * self.base:
                    self._halve()
                else:
                    self.clean += 1
                    if self.clean >= 20 and self.limit < self.cap:
                        self.limit, self.clean = self.limit + 1, 0
            else:
                self.stats['err'] += 1
                self._halve()
            self.cv.notify_all()

    def _halve(self):
        self.limit, self.clean = max(1, self.limit // 2), 0
        self.stats['backoffs'] += 1


def http_post(url, body, timeout=60):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read(256 << 20))


# ------------------------------------------------------------------------------------------- decoder
COPROC = None          # harness/kit/coproc.py (loaded on first use; a KAT may set its own copy)
DEC_TIMEOUT = 600      # s for one batch's decoder replies: a decoder that stops answering raises instead of hanging


def _coproc():
    global COPROC
    if COPROC is None:
        import importlib.util
        spec = importlib.util.spec_from_file_location('coproc_for_b182', Path(__file__).resolve().parent.parent / 'kit/coproc.py')
        COPROC = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(COPROC)
    return COPROC


class Decoder:
    """the streaming Go decoder as a co-process (one per worker), through kit/coproc.py: its feeder thread writes while
    the replies are read, so a batch whose input and output outgrow the pipe buffers cannot block both sides (r29 stall
    at 150,600), and a decoder that stops answering raises after DEC_TIMEOUT instead of hanging the worker."""

    def __init__(self, binary):
        self.cp = _coproc().CoProc([binary])
        self.p = self.cp.p

    def run(self, items):
        """items: [(kind 'b'|'t', hex)] -> decoder outputs in order."""
        lines = [json.dumps({'k': k, 'x': x}) for k, x in items] + ['{"k":"f"}']
        return [json.loads(x) for x in self.cp.roundtrip(lines, len(items), timeout=DEC_TIMEOUT)]

    def close(self):
        self.cp.close()


class Reject(Exception):
    pass


def check_blocks(lo, hi, replies, decoded):
    """verified [(topo, id, tips, txids)] for one batch, or Reject (pure). replies: the endpoint's GetBlock results
    by topo; decoded: the decoder outputs in the same order."""
    out = []
    for (topo, r), d in zip(replies, decoded):
        if not d.get('ok'):
            raise Reject(f'{topo}: decode error {d.get("e")}')
        if d.get('id') != r['block_header']['hash']:
            raise Reject(f'{topo}: decoder id != claimed hash')
        if not d.get('rs'):
            raise Reject(f'{topo}: does not re-serialize byte-exact')
        if (d.get('h') or 0) != topo:
            raise Reject(f'{topo}: decoded height {d.get("h")} != requested topoheight')
        out.append((topo, d['id'], d.get('tips') or [], d.get('txs') or []))
    if [t for t, *_ in out] != list(range(lo, hi + 1)):
        raise Reject(f'{lo}..{hi}: batch incomplete ({len(out)} of {hi - lo + 1})')
    return out


def check_txs(txids, hexes, decoded):
    """{txid: type} for one tx call, or Reject (pure): the body must re-derive exactly the requested txid. An empty
    body (the serving node does not hold it) is not judged here: the caller asks the other endpoints, and a txid no
    endpoint serves is counted UNSERVED, never given a type."""
    got = {}
    for t, hx, d in zip(txids, hexes, decoded):
        if not hx:
            continue
        if not (d.get('ok') and d.get('id') == t and d.get('rs')):
            raise Reject(f'tx {t[:16]}: decoder txid/reserialize mismatch')
        got[t] = d['ty']
    if len(got) != sum(1 for h in hexes if h):
        raise Reject('tx reply incomplete')
    return got


class Chain:
    """tips closure: every block's tips must be ids verified within the last WINDOW topoheights."""

    def __init__(self, seed=(), lenient_first=False):
        self.ids = collections.deque(seed, maxlen=WINDOW)
        self.set = set(seed)
        self.lenient = lenient_first and not seed      # bench from an arbitrary topo: its first block has no anchor

    def feed(self, topo, bid, tips):
        if self.lenient:
            self.lenient = False
        elif topo > 0 and (not tips or any(t not in self.set for t in tips)):
            raise Reject(f'{topo}: tips not among the last {WINDOW} verified ids (chain broken)')
        if len(self.ids) == self.ids.maxlen:
            self.set.discard(self.ids[0])
        self.ids.append(bid)
        self.set.add(bid)


# ------------------------------------------------------------------------------------------- fetch
REQ_TRIES = 4          # one HTTP request is retried in place (2 s, 4 s, 8 s): a batch of ~20,000 txids needs ~40 requests,
                       # and restarting the whole batch on any one timeout starved the head batch at 156,600 (2026-11-08)


def post_retry(post, ep, url, body):
    """post with in-place retries of transport failures (timeouts, resets); a reply is returned as is."""
    for k in range(REQ_TRIES):
        try:
            return post(url, body)
        except OSError:                                    # TimeoutError, URLError, ConnectionError are all OSError
            if k == REQ_TRIES - 1:
                raise
            ep.stats['retries'] = ep.stats.get('retries', 0) + 1
            ep.sleep(2 ** (k + 1))
            ep.bucket.acquire()


def fetch_batch(ep, lo, hi, dec, post, txb, alts=()):
    """one task on one endpoint: GetBlock batch, decode, GetTransaction for every txid, decode. Returns the batch
    result or raises (pure apart from post/dec). res['reqs'] counts its HTTP requests (latency is judged per request)."""
    nreq, post0 = [0], post

    def post(url, b):
        nreq[0] += 1
        return post0(url, b)
    body = [{'jsonrpc': '2.0', 'id': str(t), 'method': 'DERO.GetBlock', 'params': {'height': t}} for t in range(lo, hi + 1)]
    rep = post_retry(post, ep, ep.url, body)
    if isinstance(rep, dict) and len(body) == 1:
        rep = [rep]
    if not isinstance(rep, list):
        raise Reject('batch not supported or refused')
    by = {}
    for x in rep:
        if 'result' not in x:
            raise Reject(f'error reply {str(x.get("error"))[:80]}')
        by[int(x['id'])] = x['result']
    replies = [(t, by[t]) for t in range(lo, hi + 1) if t in by]
    blocks = check_blocks(lo, hi, replies, dec.run([('b', r['blob']) for _, r in replies]))
    allt = [t for b in blocks for t in b[3]]
    txids = list(dict.fromkeys(allt))                     # a txid can be listed by two blocks (seen: 104150/104151)
    dup_in = sorted(t for t, n in collections.Counter(allt).items() if n > 1)
    types, hexkeep = {}, {}
    missing = fetch_txs(ep, txids, dec, post, txb, types, hexkeep)
    for alt in alts:                                      # bodies this endpoint does not hold: ask the others
        if not missing:
            break
        alt.bucket.acquire()
        missing = fetch_txs(alt, missing, dec, post, txb, types, hexkeep)
    for t in missing:
        types[t] = UNSERVED
    keep = {}
    for topo, bid, tips, txs in blocks:
        if any(t in hexkeep for t in txs):
            keep[str(topo)] = by[topo]['blob']
    return {'lo': lo, 'hi': hi, 'blocks': blocks, 'types': types, 'evidence': {'blocks': keep, 'txs': hexkeep},
            'source': ep.name, 'dup_in_batch': dup_in, 'reqs': nreq[0]}


def fetch_txs(ep, txids, dec, post, txb, types, hexkeep):
    """GetTransaction for txids on one endpoint (chunks of its learned per-call cap, a round's chunks batched at most
    REQ_TXIDS txids per request); verified types go into `types`; returns the txids it served empty."""
    left, empty = list(txids), []
    for _ in range(64):                                   # rounds: all chunks of a round go in ONE batch request
        if not left:
            break
        cap = min(txb, ep.txcap)
        chunks = [left[i:i + cap] for i in range(0, len(left), cap)]
        per = max(1, REQ_TXIDS // cap)                    # chunks per HTTP request: at most REQ_TXIDS txids each
        byk = {}
        for g in range(0, len(chunks), per):
            if g:
                ep.bucket.acquire()                       # every further request of the round pays a rate token
            body = [{'jsonrpc': '2.0', 'id': str(k), 'method': 'DERO.GetTransaction', 'params': {'txs_hashes': c}}
                    for k, c in enumerate(chunks) if g <= k < g + per]
            rep = post_retry(post, ep, ep.url, body)
            if isinstance(rep, dict) and len(body) == 1:   # jrpc2 answers a one-element batch with a bare object
                rep = [rep]
            if not isinstance(rep, list):
                raise Reject('tx batch not supported or refused')
            byk.update({int(x['id']): x for x in rep})
        left = []
        for k, c in enumerate(chunks):
            x = byk.get(k) or {}
            if 'result' not in x:
                raise Reject(f'tx error {str(x.get("error"))[:80]}')
            hexes = (x['result'].get('txs_as_hex') or [])[:len(c)]
            if 0 < len(hexes) < len(c):                    # the server caps txids per call: learn it, ask the rest
                ep.txcap = min(ep.txcap, len(hexes))
            elif not hexes:
                raise Reject('tx reply empty')
            got = c[:len(hexes)]
            full = [(t, h) for t, h in zip(got, hexes) if h]
            empty += [t for t, h in zip(got, hexes) if not h]
            dd = dec.run([('t', h) for _, h in full])
            types.update(check_txs([t for t, _ in full], [h for _, h in full], dd))
            for t, h in full:
                if types[t] == REG and lz(t) < 3:
                    hexkeep[t] = h
            left += c[len(hexes):]
    if left:
        raise Reject(f'{len(left)} txids not served')
    return empty


def summarize(res):
    """the checkpoint record of one verified batch (pure)."""
    import hashlib
    ty = collections.Counter(res['types'].values())
    regs = [t for t, v in res['types'].items() if v == REG]
    return {'kind': 'batch', 'lo': res['lo'], 'hi': res['hi'], 'blocks': len(res['blocks']),
            'txs': len(res['types']), 'types': dict(sorted(ty.items())),
            'reg_lz': {str(k): v for k, v in sorted(collections.Counter(lz(t) for t in regs).items())},
            'reg_lt3': sorted(t for t in regs if lz(t) < 3),
            'ids_sha256': hashlib.sha256(''.join(b[1] for b in res['blocks']).encode()).hexdigest(),
            'last_ids': [b[1] for b in res['blocks']][-KEEP_IDS:], 'source': res['source']}


def worker(ep, tasks, results, stop, mk_dec, post, txb, errs, head, ahead, all_eps, fb=()):
    n_eps = len(all_eps)
    dec = mk_dec()
    try:
        while not stop.is_set():
            try:
                lo, hi, tries, avoid = tasks.get(timeout=1)
            except queue.Empty:
                continue
            if avoid == ep.name and n_eps > 1 and tries < 6:   # a retry goes to another endpoint first
                tasks.put((lo, hi, tries, avoid))
                tasks.task_done()
                time.sleep(0.05)
                continue
            if lo > head[0] + ahead:                      # bounded look-ahead: give the batch back rather than hold it,
                tasks.put((lo, hi, tries, avoid))         # so a requeued head batch always finds a free worker
                tasks.task_done()
                time.sleep(0.2)
                continue
            ep.enter(stop)
            t0 = time.monotonic()
            try:
                res = fetch_batch(ep, lo, hi, dec, post, txb, [e for e in all_eps if e is not ep] + list(fb))
                ep.leave(True, (time.monotonic() - t0) / max(1, res.get('reqs', 1)))
                ep.stats['blocks'] += hi - lo + 1
                ep.stats['txs'] += len(res['types'])
                results.put(res)
            except Exception as e:                        # noqa: BLE001 — any failure requeues the batch
                ep.leave(False)
                errs.append({'t': utcnow(), 'src': ep.name, 'lo': lo, 'e': f'{type(e).__name__}: {str(e)[:120]}'})
                if tries < 8:
                    ep.sleep(min(60, 2 ** tries))
                    tasks.put((lo, hi, tries + 1, ep.name))
                else:
                    results.put({'lo': lo, 'hi': hi, 'failed': True})
            finally:
                tasks.task_done()
    finally:
        dec.close()


def run(cfg, eps, post=http_post, mk_dec=None, stop_after=None, log=print, fallback=()):
    """fetch + verify + checkpoint lo..hi; returns the final totals (callable from the KAT with a fake post/decoder)."""
    stage = Path(cfg['stage'])
    ck = Checkpoint(stage / 'checkpoint.log')
    done = ck.done_ranges()
    B, lo, hi = cfg['batch'], cfg['from'], cfg['to']
    batches = [(a, min(a + B - 1, hi)) for a in range(lo, hi + 1, B)]
    # resume: verified batches form a prefix in topo order (records are appended in order)
    nxt, seed = lo, []
    for r in ck.records:
        if r.get('kind') == 'batch' and r['lo'] == nxt:
            nxt, seed = r['hi'] + 1, r['last_ids']
    todo = [b for b in batches if b[0] >= nxt and b not in done]
    chain = Chain(seed, lenient_first=cfg.get('bench', False))
    seen, seen_q = set(), collections.deque()          # txids of the last DEDUP verified txs (a tx is valid only near
    DEDUP = 200000                                     # its reference height, so a repeat can only be close by)
    tasks, results, stop, errs = queue.PriorityQueue(), queue.Queue(), threading.Event(), []   # lowest topo first
    for a, b in todo:
        tasks.put((a, b, 0, ''))
    head = [nxt]
    ths = [threading.Thread(target=worker, args=(ep, tasks, results, stop, mk_dec, post, cfg['txb'], errs, head,
                                                 B * 64, eps, fallback), daemon=True)
           for ep in eps for _ in range(ep.cap)]
    for t in ths:
        t.start()
    pending, t0, n0, last_prog, written = [], time.monotonic(), nxt, 0, 0
    kept = sum(len(json.loads(p.read_text())['txs']) for p in (stage / 'evidence').glob('*.json')) \
        if (stage / 'evidence').exists() else 0
    ev = stage / 'evidence'
    try:
        while nxt <= hi:
            try:
                r = results.get(timeout=5)
            except queue.Empty:
                if not any(t.is_alive() for t in ths):
                    raise SystemExit('every worker stopped; stop (resumable)')
                if not tasks.unfinished_tasks and results.empty() and not (pending and pending[0][0] == nxt):
                    raise SystemExit(f'nothing left to fetch, yet topo {nxt} is not verified (checkpoint gap?)')
                progress(cfg, eps, nxt, n0, t0, errs, ck)
                continue
            heapq.heappush(pending, (r['lo'], id(r), r))
            while pending and pending[0][0] == nxt:
                _, _, r = heapq.heappop(pending)
                if r.get('failed'):
                    raise SystemExit(f'batch {r["lo"]}..{r["hi"]} failed 8 times on every endpoint; stop (resumable)')
                for topo, bid, tips, _ in r['blocks']:
                    chain.feed(topo, bid, tips)
                dup = [t for t in r['types'] if t in seen]
                for t in dup:
                    del r['types'][t]
                for t in r['types']:
                    seen.add(t)
                    seen_q.append(t)
                    if len(seen_q) > DEDUP:
                        seen.discard(seen_q.popleft())
                if r['evidence']['txs'] and (kept < EVID_MAX or r['lo'] % 100000 == 0):
                    ev.mkdir(parents=True, exist_ok=True)       # bounded: the first EVID_MAX lt3 + one batch / 100k
                    (ev / f'{r["lo"]}.json').write_text(json.dumps(r['evidence']))
                    kept += len(r['evidence']['txs'])
                rec = summarize(r)
                if dup or r.get('dup_in_batch'):
                    rec['dup_txids'] = sorted(set(dup) | set(r.get('dup_in_batch') or []))
                ck.append(rec)
                nxt, written = r['hi'] + 1, written + 1
                head[0] = nxt
                if stop_after and written >= stop_after:
                    return totals(ck.records)
            if time.monotonic() - last_prog > 10:
                last_prog = time.monotonic()
                progress(cfg, eps, nxt, n0, t0, errs, ck)
        if cfg.get('join'):
            j = json.load(open(cfg['join']))
            ok = all(t in chain.set for t in j['tips'])
            ck.append({'kind': 'join', 'topo': j['topo'], 'tips': j['tips'], 'joins': ok})
            if not ok:
                raise SystemExit(f'join FAILED: tips of {j["topo"]} not among the last verified ids')
        return totals(ck.records)
    finally:
        stop.set()
        progress(cfg, eps, nxt, n0, t0, errs, ck)


def totals(records):
    """census over all batch records (pure)."""
    T = {'blocks': 0, 'txs': 0, 'types': collections.Counter(), 'reg_lz': collections.Counter(), 'reg_lt3': [],
         'ranges': []}
    for r in records:
        if r.get('kind') != 'batch':
            continue
        T['blocks'] += r['blocks']
        T['txs'] += r['txs']
        T['types'].update(r['types'])
        T['reg_lz'].update({int(k): v for k, v in r['reg_lz'].items()})
        T['reg_lt3'] += r['reg_lt3']
        if T['ranges'] and T['ranges'][-1][1] + 1 == r['lo']:
            T['ranges'][-1][1] = r['hi']
        else:
            T['ranges'].append([r['lo'], r['hi']])
    T['types'] = dict(sorted(T['types'].items()))
    T['reg_lz'] = {str(k): v for k, v in sorted(T['reg_lz'].items())}
    T['registrations'] = sum(int(v) for v in T['reg_lz'].values())
    T['joins'] = [r for r in records if r.get('kind') == 'join']
    T['dup_txids'] = sum(len(r.get('dup_txids') or []) for r in records)   # txids listed by more than one block
    return T


def progress(cfg, eps, nxt, n0, t0, errs, ck):
    el = max(1e-6, time.monotonic() - t0)
    rate = (nxt - n0) / el
    left = cfg['to'] + 1 - nxt
    T = totals(ck.records)
    p = {'t': utcnow(), 'next_topo': nxt, 'from': cfg['from'], 'to': cfg['to'], 'blocks_per_s': round(rate, 1),
         'eta_h': round(left / rate / 3600, 2) if rate > 0 else None, 'verified_blocks': T['blocks'],
         'txs': T['txs'], 'registrations': T['registrations'], 'reg_lt3': len(T['reg_lt3']),
         'endpoints': {e.name: {**e.stats, 'limit': e.limit, 'cap': e.cap, 'rate_cap': e.rate,
                                'lat_avg_s': round(e.stats['lat_sum'] / max(1, e.stats['ok']), 3)} for e in eps},
         'errors': len(errs), 'last_errors': errs[-5:]}
    path = Path(cfg['stage']) / 'progress.json'
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(p, indent=1))
    os.replace(tmp, path)


def make_eps(a, post=http_post):
    """block endpoints (--sources) and body-only fallbacks (--fallback: slow deep nodes asked only for tx bodies
    the block endpoints do not hold; 1 request/s)."""
    E = json.load(open(Path(a.priv) / 'endpoints.json'))
    eps = [Endpoint(n, E[n]['url'], a.rate, a.inflight) for n in a.sources.split(',')]
    fb = [Endpoint(n, E[n]['url'], 1.0, 1) for n in a.fallback.split(',') if n]
    return eps, fb


def main(argv=None):
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest='cmd', required=True)
    for c in ('run', 'bench'):
        p = sp.add_parser(c)
        p.add_argument('--priv', required=True); p.add_argument('--stage', required=True)
        p.add_argument('--decoder', required=True); p.add_argument('--from', dest='from_', type=int, default=0)
        p.add_argument('--to', type=int, default=7398264); p.add_argument('--blocks', type=int, default=0)
        p.add_argument('--sources', default='src-1,src-2'); p.add_argument('--batch', type=int, default=100)
        p.add_argument('--txb', type=int, default=64); p.add_argument('--inflight', type=int, default=8)
        p.add_argument('--rate', type=float, default=5.0); p.add_argument('--join', default='')
        p.add_argument('--stop-after', type=int, default=0); p.add_argument('--fallback', default='src-9')
    p = sp.add_parser('report'); p.add_argument('--stage', required=True); p.add_argument('--out', default='')
    a = ap.parse_args(argv)
    if a.cmd == 'report':
        recs, ign = unseal(open(Path(a.stage) / 'checkpoint.log').readlines())
        T = totals(recs)
        T['ignored_tail_lines'] = ign
        s = json.dumps(T, indent=1)
        if a.out:
            Path(a.out).write_text(s + '\n')
        print(s)
        return
    to = a.from_ + a.blocks - 1 if a.cmd == 'bench' else a.to
    cfg = {'stage': a.stage, 'from': a.from_, 'to': to, 'batch': a.batch, 'txb': a.txb, 'join': a.join,
           'bench': a.cmd == 'bench'}
    eps, fb = make_eps(a)
    t0 = time.monotonic()
    T = run(cfg, eps, mk_dec=lambda: Decoder(a.decoder), stop_after=a.stop_after or None, fallback=fb)
    el = time.monotonic() - t0
    T['wall_s'] = round(el, 1)
    T['blocks_per_s'] = round(T['blocks'] / el, 1) if a.cmd == 'bench' else None
    T['reg_lt3'] = len(T['reg_lt3'])                       # the txids are in the checkpoint; `report` lists them
    print(json.dumps(T, indent=1))


if __name__ == '__main__':
    main()
