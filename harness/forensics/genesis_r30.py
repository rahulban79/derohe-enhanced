#!/usr/bin/env python3
"""R30 genesis..tip chain census (rft §7 B208 b182deep v2, B182 fetcher integrity, B211, B212, B209; §8 "R30 audit
plan" S1-S3). Built ON the sealed R29 fetcher `b182_deep_r29.py` (imported, never edited: its checkpoint format,
politeness, coproc decoder, in-place retries and bounded look-ahead are reused as they are) with:

  * decoder v2 `tools/forensics/b182deep2` (public plaintext per block / tx; canonicality counts; genesis; supply);
  * EXACT txid dedup over the whole range (replaces R29's DEDUP = 200,000 window, finding
    dedup-window-wrong-for-registrations): every verified txid goes, in batch order, into the append-only sidecar
    `txids.bin` (32 bytes each) and an in-memory set; a resume truncates the sidecar to the checkpointed count and
    re-reads it, so the set is exact across restarts;
  * registration key digests (sha256 of the 33-byte key, never the key; rule 13) into `regkeys.bin` the same way;
    distinctness is derived offline (derive_r30.py);
  * topo 0 compared byte-for-byte with Generate_Genesis_Block (`blockchain/genesis.go:27`) — a mismatch rejects;
  * unreferenced ids: a verified id that leaves the WINDOW without being named as a tip is counted (topo kept);
  * per-block CalcBlockReward from the Go decoder must equal the pure-Python port read from the source
    (`harness/intel/disclosure_track.py supply_formula`), else the batch is rejected (two implementations);
  * version census per block against the mainnet hardfork heights read from `config/config.go` (no literal);
  * session records (start / end, wall seconds) in the checkpoint, so the wall time is the SESSION total.

Liveness (rft §5): progress.json carries the work counters (`verified_blocks`, `txs`, `next_topo`) for
harness/kit/stallwatch.py --counter; the checkpoint and the sidecars are --work files; `DONE` is written at the end.

  python3 -I harness/forensics/genesis_r30.py run   --priv DIR --stage DIR --decoder BIN --from 0 --to T [...]
  python3 -I harness/forensics/genesis_r30.py bench --priv DIR --stage DIR --decoder BIN --from T --blocks N [...]
  python3 -I harness/forensics/genesis_r30.py tip   --priv DIR [--sources src-1]      (public GetInfo, read-only)
  python3 -I harness/forensics/genesis_r30.py report --stage DIR [--out JSON]
Read-only toward every endpoint; never our own derod: an endpoint resolving to loopback / private / link-local is refused.
"""
import argparse, collections, hashlib, heapq, json, os, queue, re, sys, threading, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / 'harness' / 'intel'))
import b182_deep_r29 as R  # noqa: E402  (sealed R29 fetcher: used, never edited)

REG = R.REG
UNSERVED = R.UNSERVED
CF_KEEP = 64                     # txid prefixes (8 hex) kept per batch for a failed canonicality check
UNREF_KEEP = 64                  # unreferenced topos kept per batch


# ------------------------------------------------------------------------------------------- source-read constants
def chain_constants(root=ROOT):
    """(reward(h), calc_supply(h), hardfork dict) from the tree's own source lines (no literals)."""
    import disclosure_track as DT
    calc, meta = DT.supply_formula(root)
    base, rri = meta['BaseReward'], meta['RRI']

    def reward(h):
        return base >> ((h + rri) // rri)
    t = (Path(root) / 'config/config.go').read_text()
    hf = {}
    for k in ('HF1_HEIGHT', 'HF2_HEIGHT', 'MAJOR_HF2_HEIGHT', 'MAJOR_HF3_HEIGHT'):
        m = re.search(rf'^\s*{k}:\s+(\d+),', t, re.M)       # the first (mainnet) struct in the file
        if not m:
            raise LookupError(f'config.go: {k} not found')
        hf[k] = int(m.group(1))
    hf['PREMINE'] = meta['PREMINE']
    hf['credit'] = meta['credit']
    return reward, calc, hf


def expected_major(h, hf):
    """the mainnet hardfork table (blockchain/hardfork_core.go:47-53): v1 from 0, v2 from MAJOR_HF2, v3 from MAJOR_HF3.
    HF1_HEIGHT / HF2_HEIGHT are not versions (they change rules within v1)."""
    if h >= hf['MAJOR_HF3_HEIGHT']:
        return 3
    if h >= hf['MAJOR_HF2_HEIGHT']:
        return 2
    return 1


# ------------------------------------------------------------------------------------------- pure checks
def check_blocks2(lo, hi, replies, decoded, reward, genesis=None):
    """R29 check_blocks plus: reward(Go) == reward(Python); topo 0 == Generate_Genesis_Block (bytes and id).
    Returns [(topo, id, tips, txids, d)]."""
    base = R.check_blocks(lo, hi, replies, decoded)
    out = []
    for (topo, bid, tips, txs), (_, r), d in zip(base, replies, decoded):
        if d.get('rw') != reward(topo):
            raise R.Reject(f'{topo}: CalcBlockReward Go {d.get("rw")} != Python {reward(topo)}')
        if topo == 0:
            if genesis is None:
                raise R.Reject('0: no generated genesis to compare with')
            if bid != genesis['id'] or r['blob'] != genesis['x']:
                raise R.Reject('0: fetched topo 0 != Generate_Genesis_Block')
        out.append((topo, bid, tips, txs, d))
    return out


def check_txs2(txids, hexes, decoded):
    """{txid: decoder output} (R29 check_txs semantics: the body re-derives the txid and re-serializes)."""
    R.check_txs(txids, hexes, decoded)
    return {t: d for t, hx, d in zip(txids, hexes, decoded) if hx}


class Chain2(R.Chain):
    """R29 tips closure + unreferenced ids: an id that leaves the window never named as a tip is reported."""

    def __init__(self, seed=(), lenient_first=False, seed_topos=None, seed_refd=()):
        super().__init__(seed, lenient_first)
        self.topo = dict(zip(seed, seed_topos or [None] * len(seed)))
        self.refd = set(seed_refd)
        self.unref = []

    def feed(self, topo, bid, tips):
        if len(self.ids) == self.ids.maxlen:
            old = self.ids[0]
            if old not in self.refd:
                self.unref.append(self.topo.get(old))
            self.refd.discard(old)
            self.topo.pop(old, None)
        super().feed(topo, bid, tips)
        self.topo[bid] = topo
        self.refd.update(tips)

    def take_unref(self):
        u, self.unref = self.unref, []
        return u


# ------------------------------------------------------------------------------------------- decode: liveness + pool
# r30 hang class 4 (2026-11-09 07:18-07:30, topo 154,000): one head batch's proof-carrying bodies were decoded SERIALLY
# on its worker's decoder (node Deserialize: ModSqrt point decompression, ~4-7 ms/body) for > 10 min while every other
# worker sat at the look-ahead limit; no stallwatch counter moved (decoding is work, but not COUNTED work), so stallwatch
# would have killed and relaunched it from the same head again and again. Fix: (a) DECODED counts every decoded item and
# progress.json carries it (`decoded`, a stallwatch --counter); (b) a long item list is spread over spare decoders.
DECODED = [0]
_DLOCK = threading.Lock()
PAR_MIN = 128          # items per piece; a longer list is spread over the spare decoders
SPARE_N = 6            # spare decoder co-processes shared by all workers
_SPARE = {'q': None}


def counted(items, out):
    with _DLOCK:
        DECODED[0] += len(items)
    return out


def set_spares(mk, n=SPARE_N):
    """the spare-decoder pool (n decoders made by mk); returns them, to close at the end."""
    _SPARE['q'] = queue.Queue()
    ds = [mk() for _ in range(n)]
    for d in ds:
        _SPARE['q'].put(d)
    return ds


def par_run(dec, items):
    """dec.run(items), same result order; pieces of PAR_MIN go to the worker's own decoder and to every spare decoder
    free at that moment (each piece one bounded roundtrip; a failing piece raises like dec.run)."""
    if len(items) <= PAR_MIN or _SPARE['q'] is None:
        return counted(items, dec.run(items))
    pieces = [items[i:i + PAR_MIN] for i in range(0, len(items), PAR_MIN)]
    res, errs, nxt, lk = [None] * len(pieces), [], [0], threading.Lock()

    def drain(d):
        while True:
            with lk:
                if nxt[0] >= len(pieces) or errs:
                    return
                k = nxt[0]
                nxt[0] += 1
            try:
                res[k] = counted(pieces[k], d.run(pieces[k]))
            except Exception as e:      # noqa: BLE001 - re-raised below; the batch requeues as before
                errs.append(e)
                return
    borrowed = []
    while len(borrowed) < len(pieces) - 1:
        try:
            borrowed.append(_SPARE['q'].get_nowait())
        except queue.Empty:
            break
    ths = [threading.Thread(target=drain, args=(d,), daemon=True) for d in borrowed]
    for t in ths:
        t.start()
    drain(dec)
    for t in ths:
        t.join()
    for d in borrowed:
        _SPARE['q'].put(d)
    if errs:
        raise errs[0]
    return [x for r in res for x in r]


def progress2(cfg, eps, nxt, n0, t0, errs, ck):
    """R29 progress.json plus `decoded` (decoder items done, a stallwatch --counter)."""
    side = Path(cfg['stage']) / '.progress_r29'            # R29 writes its own file there; progress.json is written ONCE
    side.mkdir(exist_ok=True)                              # per update, so a reader never sees it without `decoded`
    R.progress(dict(cfg, stage=str(side)), eps, nxt, n0, t0, errs, ck=ck)
    path = Path(cfg['stage']) / 'progress.json'
    d = json.loads((side / 'progress.json').read_text())
    d['decoded'] = DECODED[0]
    tmp = path.with_suffix('.tmp2')
    tmp.write_text(json.dumps(d, indent=1))
    os.replace(tmp, path)


# ------------------------------------------------------------------------------------------- fetch
def fetch_txs2(ep, txids, dec, post, txb, got):
    """R29 fetch_txs with the whole decoder output kept per txid (types alone are not enough for the census)."""
    left, empty = list(txids), []
    for _ in range(64):
        if not left:
            break
        cap = min(txb, ep.txcap)
        chunks = [left[i:i + cap] for i in range(0, len(left), cap)]
        per = max(1, R.REQ_TXIDS // cap)
        byk = {}
        for g in range(0, len(chunks), per):
            if g:
                ep.bucket.acquire()
            body = [{'jsonrpc': '2.0', 'id': str(k), 'method': 'DERO.GetTransaction', 'params': {'txs_hashes': c}}
                    for k, c in enumerate(chunks) if g <= k < g + per]
            rep = R.post_retry(post, ep, ep.url, body)
            if isinstance(rep, dict) and len(body) == 1:
                rep = [rep]
            if not isinstance(rep, list):
                raise R.Reject('tx batch not supported or refused')
            byk.update({int(x['id']): x for x in rep})
        left, full = [], []
        for k, c in enumerate(chunks):
            x = byk.get(k) or {}
            if 'result' not in x:
                raise R.Reject(f'tx error {str(x.get("error"))[:80]}')
            hexes = (x['result'].get('txs_as_hex') or [])[:len(c)]
            if 0 < len(hexes) < len(c):
                ep.txcap = min(ep.txcap, len(hexes))
            elif not hexes:
                raise R.Reject('tx reply empty')
            sub = c[:len(hexes)]
            full += [(t, h) for t, h in zip(sub, hexes) if h]
            empty += [t for t, h in zip(sub, hexes) if not h]
            left += c[len(hexes):]
        dd = par_run(dec, [('t', h) for _, h in full])     # the whole round at once: spread over the spare decoders
        got.update(check_txs2([t for t, _ in full], [h for _, h in full], dd))
    if left:
        raise R.Reject(f'{len(left)} txids not served')
    return empty


def fetch_batch2(ep, lo, hi, dec, post, txb, alts=(), reward=None, genesis=None):
    nreq, net, post0 = [0], [0.0], post

    def post(url, b):                                   # r30 slow-class 6: latency = time inside the HTTP call only
        nreq[0] += 1
        t = time.monotonic()
        try:
            return post0(url, b)
        finally:
            net[0] += time.monotonic() - t
    body = [{'jsonrpc': '2.0', 'id': str(t), 'method': 'DERO.GetBlock', 'params': {'height': t}} for t in range(lo, hi + 1)]
    rep = R.post_retry(post, ep, ep.url, body)
    if isinstance(rep, dict) and len(body) == 1:
        rep = [rep]
    if not isinstance(rep, list):
        raise R.Reject('batch not supported or refused')
    by = {}
    for x in rep:
        if 'result' not in x:
            raise R.Reject(f'error reply {str(x.get("error"))[:80]}')
        by[int(x['id'])] = x['result']
    replies = [(t, by[t]) for t in range(lo, hi + 1) if t in by]
    blocks = check_blocks2(lo, hi, replies, par_run(dec, [('b', r['blob']) for _, r in replies]), reward, genesis)
    allt = [t for b in blocks for t in b[3]]
    txids = list(dict.fromkeys(allt))
    dup_in = sorted(t for t, n in collections.Counter(allt).items() if n > 1)
    got = {}
    missing = fetch_txs2(ep, txids, dec, post, txb, got)
    for alt in alts:
        if not missing:
            break
        alt.bucket.acquire()
        missing = fetch_txs2(alt, missing, dec, post, txb, got)
    return {'lo': lo, 'hi': hi, 'blocks': blocks, 'txd': got, 'unserved': list(missing), 'source': ep.name,
            'dup_in_batch': dup_in, 'reqs': nreq[0], 'net_s': net[0]}


def summarize2(res, dup, hf, unref):
    """the v2 checkpoint record of one verified batch (pure). `dup`: txids already verified in an earlier batch (or
    earlier in this one: listed by two blocks); they are counted once (exact dedup), never typed twice."""
    blocks, txd = res['blocks'], res['txd']
    first = {}
    for _, _, _, txs, _ in blocks:
        for t in txs:
            first.setdefault(t, None)
    uniq = [t for t in first if t not in dup]
    types, fee, burn, val, npl, cf, cfx = (collections.Counter(), collections.Counter(), collections.Counter(),
                                           collections.Counter(), collections.Counter(), collections.Counter(), [])
    cp = cs = gk = 0
    regs, rks = [], []
    for t in uniq:
        d = txd.get(t)
        if d is None:
            types[UNSERVED] += 1
            continue
        ty = d['ty']
        types[ty] += 1
        fee[ty] += d.get('fee', 0)
        burn[ty] += d.get('burn', 0)
        val[ty] += d.get('val', 0)
        npl[str(d.get('np', 0))] += 1
        cp += d.get('cp', 0)
        cs += d.get('cs', 0)
        if d.get('cf'):
            cf.update(d['cf'])
            if len(cfx) < CF_KEEP:
                cfx.append(t[:8])
        if ty == REG:
            regs.append(t)
            rks.append(d['rk'])
            gk += bool(d.get('gk'))
    fee_l = burn_l = listings = 0                       # per LISTING (a txid in two blocks counts twice): the window
    pv = {}                                             # figures 855,173 / 230,470,000 are sums over block listings;
    for topo, _, _, txs, _ in blocks:                   # pv keeps them per block (non-zero only) so a window that does
        bf = bb = 0                                     # not start on a batch boundary re-derives exactly
        for t in txs:
            listings += 1
            d = txd.get(t)
            if d is not None:
                bf += d.get('fee', 0)
                bb += d.get('burn', 0)
        fee_l, burn_l = fee_l + bf, burn_l + bb
        if bf or bb:
            pv[str(topo)] = [bf, bb]
    ver, vfirst, vlast, mism, mt = collections.Counter(), {}, {}, [], collections.Counter()
    mv_nz, mb, mbmax, rw = 0, 0, 0, 0
    premine = None
    for topo, _, _, _, d in blocks:
        mj = d.get('mj')
        ver[f'{mj}.{d.get("mn")}'] += 1
        vfirst.setdefault(str(mj), topo)
        vlast[str(mj)] = topo
        if mj != expected_major(topo, hf):
            mism.append(topo)
        mt[d.get('mt')] += 1
        if topo == 0:
            premine = d.get('mv')
        elif d.get('mv'):
            mv_nz += 1
        mb += d.get('mb', 0)
        mbmax = max(mbmax, d.get('mb', 0))
        rw += d.get('rw', 0)
    import hashlib as _h
    rec = {'kind': 'batch', 'v': 2, 'lo': res['lo'], 'hi': res['hi'], 'blocks': len(blocks), 'txs': len(uniq),
           'types': dict(sorted(types.items())),
           'reg_lz': {str(k): v for k, v in sorted(collections.Counter(R.lz(t) for t in regs).items())},
           'reg_lt3': sorted(t for t in regs if R.lz(t) < 3),
           'ids_sha256': _h.sha256(''.join(b[1] for b in blocks).encode()).hexdigest(),
           'last_ids': [b[1] for b in blocks][-R.KEEP_IDS:], 'last_topos': [b[0] for b in blocks][-R.KEEP_IDS:],
           'source': res['source'],
           'ver': dict(sorted(ver.items())), 'ver_first': vfirst, 'ver_last': vlast, 'ver_mismatch': len(mism), 'ver_mismatch_topos': mism[:16],
           'miner_types': dict(sorted(mt.items())), 'miner_value_nonzero': mv_nz, 'miniblocks': mb, 'miniblocks_max': mbmax,
           'reward_sum': rw, 'fee': dict(sorted(fee.items())), 'burn': dict(sorted(burn.items())),
           'value': dict(sorted(val.items())), 'payloads': dict(sorted(npl.items())), 'listings': listings,
           'fee_listing': fee_l, 'burn_listing': burn_l, 'pv': pv, 'canon_points': cp, 'canon_scalars': cs,
           'canon_failed': dict(sorted(cf.items())), 'canon_failed_txids': cfx, 'reg_genesis_key': gk,
           'n_txids': len(uniq), 'n_regkeys': len(rks), 'unref': len(unref), 'unref_topos': unref[:UNREF_KEEP]}
    if premine is not None:
        rec['premine_value'] = premine
    if dup:
        rec['dup_txids'] = sorted(dup)
    multi = sorted(set(dup) | set(res.get('dup_in_batch') or []))
    if multi:                                            # B209: every multi-listed txid typed by its verified body
        rec['dup_typed'] = {t: (txd[t]['ty'] if t in txd else UNSERVED) for t in multi}
    return rec, [bytes.fromhex(t) for t in uniq], [bytes.fromhex(k) for k in rks]


# ------------------------------------------------------------------------------------------- sidecars (exact dedup)
class Sidecar:
    """append-only file of 32-byte records; truncated on open to the checkpointed count (records past it were written
    for a batch whose checkpoint line never landed)."""

    def __init__(self, path, n):
        self.path = Path(path)
        size = self.path.stat().st_size if self.path.exists() else 0
        if size < 32 * n:
            raise SystemExit(f'{self.path.name}: holds {size // 32} records, checkpoint says {n} (lost sidecar)')
        if size != 32 * n:
            with open(self.path, 'r+b') as f:
                f.truncate(32 * n)
        self.f = open(self.path, 'ab')

    def read(self):
        b = self.path.read_bytes()
        return [b[i:i + 32] for i in range(0, len(b), 32)]

    def append(self, items):
        self.f.write(b''.join(items))
        self.f.flush()
        os.fsync(self.f.fileno())


# ------------------------------------------------------------------------------------------- run
def worker2(ep, tasks, results, stop, mk_dec, post, txb, errs, head, ahead, all_eps, fb, reward, genesis):
    n_eps = len(all_eps)
    dec = mk_dec()
    try:
        while not stop.is_set():
            try:
                lo, hi, tries, avoid = tasks.get(timeout=1)
            except queue.Empty:
                continue
            if avoid == ep.name and n_eps > 1 and tries < 6:
                tasks.put((lo, hi, tries, avoid))
                tasks.task_done()
                time.sleep(0.05)
                continue
            if lo > head[0] + ahead:
                tasks.put((lo, hi, tries, avoid))
                tasks.task_done()
                time.sleep(0.2)
                continue
            if ep.busy >= ep.limit and n_eps > 1:          # r30 hang class 5: never hold a task while waiting for
                tasks.put((lo, hi, tries, avoid))          # this endpoint's AIMD slot (src-2 at limit 1 held the head
                tasks.task_done()                          # batch 154,000 for > 10 min behind a slow heavy batch);
                time.sleep(0.05)                           # give it back so a free endpoint's worker takes it
                continue
            ep.enter(stop)
            t0 = time.monotonic()
            try:
                res = fetch_batch2(ep, lo, hi, dec, post, txb, [e for e in all_eps if e is not ep] + list(fb),
                                   reward, genesis)
                # r30 slow-class 6 (2026-11-09, 156,600..160,000: 7k-30k proof txs per batch): the latency fed to AIMD was
                # the batch WALL / requests, decode included, so a dense batch looked like a slow endpoint, the limit
                # halved to 1-2 (14 + 4 backoffs, 0 errors), few batches stayed in flight and ~20 decoders used 1.6 cores
                # (2.2 b/s). AIMD now judges the time inside the HTTP calls only.
                ep.leave(True, res.get('net_s', time.monotonic() - t0) / max(1, res.get('reqs', 1)))
                ep.stats['blocks'] += hi - lo + 1
                ep.stats['txs'] += len(res['txd'])
                results.put(res)
            except Exception as e:                        # noqa: BLE001 — any failure requeues the batch
                ep.leave(False)
                errs.append({'t': R.utcnow(), 'src': ep.name, 'lo': lo, 'e': f'{type(e).__name__}: {str(e)[:120]}'})
                if tries < 8:
                    ep.sleep(min(60, 2 ** tries))
                    tasks.put((lo, hi, tries + 1, ep.name))
                else:
                    results.put({'lo': lo, 'hi': hi, 'failed': True})
            finally:
                tasks.task_done()
    finally:
        dec.close()


def resume_state(records, lo):
    """(next topo, seed ids, seed topos, seed ids already named as tips, n_txids, n_regkeys) from the verified prefix
    (pure). A resume carries KEEP_IDS (16) ids, not WINDOW (64): an unreferenced id among the other 48 at a session
    boundary is not seen (the session records say where the boundaries are)."""
    nxt, seed, stopos, refd, nt, nk = lo, [], [], [], 0, 0
    for r in records:
        if r.get('kind') == 'batch' and r['lo'] == nxt:
            nxt, seed, stopos = r['hi'] + 1, r['last_ids'], r.get('last_topos') or []
            refd = [b for b, f in zip(seed, r.get('last_refd') or []) if f]
            nt += r.get('n_txids', 0)
            nk += r.get('n_regkeys', 0)
    return nxt, seed, stopos, refd, nt, nk


def run(cfg, eps, post=R.http_post, mk_dec=None, stop_after=None, log=print, fallback=(), root=ROOT, genesis=None):
    stage = Path(cfg['stage'])
    ck = R.Checkpoint(stage / 'checkpoint.log')
    reward, _calc, hf = chain_constants(root)
    done = ck.done_ranges()
    B, lo, hi = cfg['batch'], cfg['from'], cfg['to']
    batches = [(a, min(a + B - 1, hi)) for a in range(lo, hi + 1, B)]
    nxt, seed, stopos, refd, nt, nk = resume_state(ck.records, lo)
    txside, keyside = Sidecar(stage / 'txids.bin', nt), Sidecar(stage / 'regkeys.bin', nk)
    seen = set(txside.read())                              # EXACT: every txid verified so far, across sessions
    if genesis is None and lo == 0 and nxt == 0:
        d = mk_dec()
        try:
            genesis = d.cp.roundtrip(['{"k":"g"}', '{"k":"f"}'], 1, timeout=60)
            genesis = json.loads(genesis[0])
        finally:
            d.close()
    todo = [b for b in batches if b[0] >= nxt and b not in done]
    chain = Chain2(seed, lenient_first=cfg.get('bench', False), seed_topos=stopos, seed_refd=refd)
    tasks, results, stop, errs = queue.PriorityQueue(), queue.Queue(), threading.Event(), []
    for a, b in todo:
        tasks.put((a, b, 0, ''))
    head = [nxt]
    ths = [threading.Thread(target=worker2, args=(ep, tasks, results, stop, mk_dec, post, cfg['txb'], errs, head,
                                                  B * 64, eps, fallback, reward, genesis), daemon=True)
           for ep in eps for _ in range(ep.cap)]
    spares = set_spares(mk_dec, cfg.get('spares', SPARE_N))
    for t in ths:
        t.start()
    sess0 = time.time()
    ck.append({'kind': 'session', 'start': R.utcnow(), 'from_topo': nxt, 'to': hi, 'sources': [e.name for e in eps]})
    pending, t0, n0, last_prog, written = [], time.monotonic(), nxt, 0, 0
    try:
        while nxt <= hi:
            try:
                r = results.get(timeout=min(5, cfg.get('prog_s', 10)))
            except queue.Empty:
                if not any(t.is_alive() for t in ths):
                    raise SystemExit('every worker stopped; stop (resumable)')
                if not tasks.unfinished_tasks and results.empty() and not (pending and pending[0][0] == nxt):
                    raise SystemExit(f'nothing left to fetch, yet topo {nxt} is not verified (checkpoint gap?)')
                progress2(cfg, eps, nxt, n0, t0, errs, ck)
                continue
            heapq.heappush(pending, (r['lo'], id(r), r))
            while pending and pending[0][0] == nxt:
                _, _, r = heapq.heappop(pending)
                if r.get('failed'):
                    raise SystemExit(f'batch {r["lo"]}..{r["hi"]} failed 8 times on every endpoint; stop (resumable)')
                for topo, bid, tips, _, _ in r['blocks']:
                    chain.feed(topo, bid, tips)
                order = list(dict.fromkeys(t for b in r['blocks'] for t in b[3]))
                dup = {t for t in order if bytes.fromhex(t) in seen}   # verified in an EARLIER batch (exact set);
                rec, tids, keys = summarize2(r, dup, hf, chain.take_unref())   # in-batch repeats fold by first listing
                rec['last_refd'] = [b in chain.refd for b in rec['last_ids']]
                if r.get('dup_in_batch'):
                    rec['dup_in_batch'] = r['dup_in_batch']
                txside.append(tids)                          # sidecars first, then the checkpoint line
                keyside.append(keys)
                seen.update(tids)
                ck.append(rec)
                nxt, written = r['hi'] + 1, written + 1
                head[0] = nxt
                if stop_after and written >= stop_after:
                    return totals2(ck.records)
            if time.monotonic() - last_prog > cfg.get('prog_s', 10):
                last_prog = time.monotonic()
                progress2(cfg, eps, nxt, n0, t0, errs, ck)
        if cfg.get('join'):
            j = json.load(open(cfg['join']))
            ok = all(t in chain.set for t in j['tips'])
            ck.append({'kind': 'join', 'topo': j['topo'], 'tips': j['tips'], 'joins': ok})
            if not ok:
                raise SystemExit(f'join FAILED: tips of {j["topo"]} not among the last verified ids')
        if not cfg.get('bench'):
            (stage / 'DONE').write_text(R.utcnow() + '\n')
        return totals2(ck.records)
    finally:
        stop.set()
        for d in spares:
            d.close()
        ck.append({'kind': 'session_end', 'end': R.utcnow(), 'wall_s': round(time.time() - sess0, 1), 'next_topo': nxt,
                   'errors': len(errs)})
        progress2(cfg, eps, nxt, n0, t0, errs, ck)
        (stage / 'errors.jsonl').open('a').write(''.join(json.dumps(e) + '\n' for e in errs))


def totals2(records):
    """census over all v2 batch records + the session wall total (pure)."""
    T = R.totals(records)
    add = ('miner_value_nonzero', 'miniblocks', 'reward_sum', 'listings', 'fee_listing', 'burn_listing', 'canon_points',
           'canon_scalars', 'reg_genesis_key', 'n_txids', 'n_regkeys', 'unref', 'ver_mismatch')
    for k in add:
        T[k] = sum(r.get(k, 0) for r in records if r.get('kind') == 'batch')
    for k in ('ver', 'miner_types', 'fee', 'burn', 'value', 'payloads', 'canon_failed'):
        c = collections.Counter()
        for r in records:
            if r.get('kind') == 'batch':
                c.update(r.get(k) or {})
        T[k] = dict(sorted(c.items()))
    vf = {}
    for r in records:
        if r.get('kind') == 'batch':
            for m, t in (r.get('ver_first') or {}).items():
                vf[m] = min(vf.get(m, t), t)
    T['ver_first'] = dict(sorted(vf.items()))
    vl = {}
    for r in records:
        if r.get('kind') == 'batch':
            for m, t in (r.get('ver_last') or {}).items():
                vl[m] = max(vl.get(m, t), t)
    T['ver_last'] = dict(sorted(vl.items()))
    T['premine_value'] = next((r['premine_value'] for r in records if r.get('kind') == 'batch' and 'premine_value' in r), None)
    T['sessions'] = sum(1 for r in records if r.get('kind') == 'session')
    T['session_wall_s'] = round(sum(r.get('wall_s', 0) for r in records if r.get('kind') == 'session_end'), 1)
    T['session_errors'] = sum(r.get('errors', 0) for r in records if r.get('kind') == 'session_end')
    return T


def own_node(url, resolve=None):
    """True when the URL's host resolves to this machine or the LAN (loopback, private, link-local, unspecified):
    our derod and the LAN laptop node live there. Public archive nodes also listen on 10102, so the port says nothing;
    the address does. An unresolvable host is refused too (pure apart from `resolve`)."""
    import ipaddress, socket, urllib.parse
    h = urllib.parse.urlparse(url).hostname or ''
    try:
        ip = ipaddress.ip_address((resolve or socket.gethostbyname)(h))
    except (OSError, ValueError):
        return True
    return ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified


def refuse_own_node(eps, resolve=None):
    for e in eps:
        if own_node(e.url, resolve):
            raise SystemExit(f'refused: {e.name} resolves to this machine or the LAN (rft: never contact our derod)')


def cmd_tip(a):
    E = json.load(open(Path(a.priv) / 'endpoints.json'))
    eps = [R.Endpoint(n, E[n]['url'], 1, 1) for n in a.sources.split(',')]
    refuse_own_node(eps)
    out = {}
    for e in eps:
        r = R.http_post(e.url, {'jsonrpc': '2.0', 'id': '1', 'method': 'DERO.GetInfo'}, timeout=30)
        out[e.name] = {k: r['result'].get(k) for k in ('topoheight', 'height', 'stableheight')}
    print(json.dumps(out))


def main(argv=None):
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest='cmd', required=True)
    for c in ('run', 'bench'):
        p = sp.add_parser(c)
        p.add_argument('--priv', required=True); p.add_argument('--stage', required=True)
        p.add_argument('--decoder', required=True); p.add_argument('--from', dest='from_', type=int, default=0)
        p.add_argument('--to', type=int, default=0); p.add_argument('--blocks', type=int, default=0)
        p.add_argument('--sources', default='src-1,src-2'); p.add_argument('--batch', type=int, default=100)
        p.add_argument('--txb', type=int, default=64); p.add_argument('--inflight', type=int, default=8)
        p.add_argument('--rate', type=float, default=5.0); p.add_argument('--join', default='')
        p.add_argument('--stop-after', type=int, default=0); p.add_argument('--fallback', default='src-9')
    p = sp.add_parser('tip'); p.add_argument('--priv', required=True); p.add_argument('--sources', default='src-1,src-2')
    p = sp.add_parser('report'); p.add_argument('--stage', required=True); p.add_argument('--out', default='')
    a = ap.parse_args(argv)
    if a.cmd == 'tip':
        return cmd_tip(a)
    if a.cmd == 'report':
        recs, ign = R.unseal(open(Path(a.stage) / 'checkpoint.log').readlines())
        T = totals2(recs)
        T['ignored_tail_lines'] = ign
        T['reg_lt3'] = len(T['reg_lt3'])
        s = json.dumps(T, indent=1, sort_keys=True)
        if a.out:
            Path(a.out).write_text(s + '\n')
        print(s)
        return
    to = a.from_ + a.blocks - 1 if a.cmd == 'bench' else a.to
    cfg = {'stage': a.stage, 'from': a.from_, 'to': to, 'batch': a.batch, 'txb': a.txb, 'join': a.join,
           'bench': a.cmd == 'bench'}
    eps, fb = R.make_eps(a)
    refuse_own_node(eps + fb)
    t0 = time.monotonic()
    T = run(cfg, eps, mk_dec=lambda: R.Decoder(a.decoder), stop_after=a.stop_after or None, fallback=fb)
    el = time.monotonic() - t0
    T['wall_s'] = round(el, 1)
    T['blocks_per_s'] = round(T['blocks'] / el, 1)
    T['reg_lt3'] = len(T['reg_lt3'])
    print(json.dumps(T, indent=1, sort_keys=True))


if __name__ == '__main__':
    main()
