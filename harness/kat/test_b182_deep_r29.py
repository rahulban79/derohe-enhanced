#!/usr/bin/env python3
"""test_b182_deep_r29.py — r29 (rft §7 B182, user option (ii) 2026-11-08): the fast deep fetch + census
(harness/forensics/b182_deep_r29.py) stays verified, resumable and polite while it gets fast. Hermetic: a simulated
archive endpoint and a fake decoder; nothing touches the network.

  DP1  checkpoint: a torn last line and a CRC-bad line (and everything after them) are ignored; earlier records stay
  DP2  check_blocks refuses a forged block (decoder id != claimed hash), a non-byte-exact one, a wrong height and an
       incomplete batch
  DP3  Chain: an unbroken chain passes; a skipped or replaced block (a tip not among the verified ids) is refused
  DP4  resume: stop after 3 batches, append a torn line, resume -> the same totals as one uninterrupted run
  DP5  politeness: the token bucket spaces requests by 1/rate (simulated clock); the hard caps hold
  DP6  batch size does not change the census (batch 1 == batch 7 == batch 50)
  DP7  classifier: the dataset's own REGISTRATION txids all count as >= 3 zero bytes, a forged 2-byte one as < 3
  DP8  AIMD: an error or a latency spike halves the in-flight limit; 20 clean replies add one back, never above cap
  DP9  per-call cap learned (16) and bodies an endpoint lacks fetched from another; a body nobody serves is UNSERVED
  DP10 a txid listed by two blocks is counted once and recorded as a duplicate
  DP11 40 txids at a per-call cap of 16 cost exactly 2 tx requests (the cap is learned, the rest go in one batch)
  DP12 a batch whose decoder input and output (12.8 MB each) outgrow the pipe buffers completes (the r29 stall at 150,600 was both
       sides blocked writing); a real co-process, 20 s limit
  DP13 a head batch that fails once, slowly, on A while B's workers run past the look-ahead still completes (no worker
       holds a batch while it waits, so B picks the requeued head up); 20 s limit
  DP14 2,000 txids in one batch go out at most REQ_TXIDS (512) per HTTP request and are all counted (one request for
       ~8,700 txids timed out live at topo 155,000)
  DP16 a decoder that stops answering raises CoProcTimeout within DEC_TIMEOUT, and one that exits raises CoProcEOF
       — neither hangs the worker (kit/coproc.py; 10 s limit each)
  DP15 a timeout on every 3rd tx request is retried in place: a 2,000-txid batch completes in its first task (one
       GetBlock request, no batch-level error) — restarting the batch starved the head at 156,600 live

  python3 -I harness/kat/test_b182_deep_r29.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, gzip, hashlib, importlib.util, io, json, os, sys, tempfile, threading, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'tool': 'harness/forensics/b182_deep_r29.py', 'coproc': 'harness/kit/coproc.py', 'hangkit': 'harness/kit/hangkit.py'}


def P(over, key):
    return Path(over.get(key) or (ROOT / PATHS[key]))


def _mod(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def load(over):
    m = _mod('b182deep', P(over, 'tool'))
    m.COPROC = _mod('coproc_dp29', P(over, 'coproc'))     # r29: the decoder runs through kit/coproc.py
    return m


def H(s):
    return hashlib.sha256(s.encode()).hexdigest()


class FakeChain:
    """topo 0..n-1; block hex = hex(JSON{h, tips, txs}); id = sha256 of that JSON; tx hex = hex(JSON{id, ty})."""

    def __init__(self, n, regs=(), dup=None, lack=None, nobody=None, cap=16):
        self.blocks, self.txs = [], {}
        prev = None
        for h in range(n):
            txs = []
            for k in range(h % 3):
                t = H(f'tx{h}.{k}')
                txs.append(t)
                self.txs[t] = 'NORMAL'
            for t in regs:
                if int(t[-4:], 16) % n == h:
                    txs.append(t)
                    self.txs[t] = 'REGISTRATION'
            if dup and h in (dup[0], dup[0] + 1):
                txs.append(dup[1])
                self.txs[dup[1]] = 'REGISTRATION'
            body = json.dumps({'h': h, 'tips': [prev] if prev else [], 'txs': txs}, sort_keys=True)
            bid = H(body)
            self.blocks.append((bid, body.encode().hex()))
            prev = bid
        self.lack, self.nobody, self.cap, self.calls = set(lack or ()), set(nobody or ()), cap, []

    def post(self, url, body):
        self.calls.append(url)
        out = []
        for x in (body if isinstance(body, list) else [body]):
            if x['method'] == 'DERO.GetBlock':
                bid, hx = self.blocks[x['params']['height']]
                out.append({'id': x['id'], 'result': {'blob': hx, 'block_header': {'hash': bid}}})
            else:
                ask = x['params']['txs_hashes'][:self.cap]
                hx = []
                for t in ask:
                    if t in self.nobody or (url == 'A' and t in self.lack):
                        hx.append('')
                    else:
                        hx.append(json.dumps({'id': t, 'ty': self.txs[t]}).encode().hex())
                out.append({'id': x['id'], 'result': {'txs_as_hex': hx}})
        return out if isinstance(body, list) else out[0]


class FakeDec:
    def run(self, items):
        res = []
        for k, x in items:
            raw = bytes.fromhex(x).decode()
            if k == 'b':
                d = json.loads(raw)
                res.append({'ok': True, 'id': H(raw), 'h': d['h'], 'tips': d['tips'], 'txs': d['txs'], 'rs': True})
            else:
                d = json.loads(raw)
                res.append({'ok': True, 'id': d['id'], 'ty': d['ty'], 'rs': True})
        return res

    def close(self):
        pass


def go(m, chain, n, batch=10, eps=('A', 'B'), stop_after=None, stage=None):
    d = stage or tempfile.mkdtemp(prefix='dp29-')
    E = [m.Endpoint(e, e, 50, 2, sleep=lambda s: None) for e in eps]
    cfg = {'stage': d, 'from': 0, 'to': n - 1, 'batch': batch, 'txb': 64}
    T = m.run(cfg, E, post=chain.post, mk_dec=FakeDec, stop_after=stop_after)
    return {k: T[k] for k in ('blocks', 'txs', 'types', 'reg_lz', 'reg_lt3', 'registrations', 'dup_txids')}, d


REGS = [('000000' + H(f'r{i}')[6:]) for i in range(5)] + [('0000' + 'ab' + H('lt3')[6:])]


def kat_dp1(over):
    m = load(over)
    a, b, c = m.seal({'kind': 'batch', 'lo': 0}), m.seal({'kind': 'batch', 'lo': 10}), m.seal({'kind': 'batch', 'lo': 20})
    r1, i1 = m.unseal([a, b, c[:-5]])
    bad = c[:9] + c[9:].replace('20', '21')
    r2, i2 = m.unseal([a, bad, b])
    return ([r['lo'] for r in r1], i1, [r['lo'] for r in r2], i2) == ([0, 10], 1, [0], 2), (r1, i1, r2, i2)


def kat_dp2(over):
    m = load(over)
    ch = FakeChain(3)
    rep = [(t, {'block_header': {'hash': ch.blocks[t][0]}, 'blob': ch.blocks[t][1]}) for t in range(3)]
    good = FakeDec().run([('b', r['blob']) for _, r in rep])
    ok = len(m.check_blocks(0, 2, rep, good)) == 3
    res = []
    for mut in ({'id': 'ff' * 32}, {'rs': False}, {'h': 7}):
        dd = [dict(x) for x in good]
        dd[1].update(mut)
        try:
            m.check_blocks(0, 2, rep, dd)
            res.append(False)
        except m.Reject:
            res.append(True)
    try:
        m.check_blocks(0, 2, rep[:2], good[:2])
        res.append(False)
    except m.Reject:
        res.append(True)
    return ok and all(res), (ok, res)


def kat_dp3(over):
    m = load(over)
    c = m.Chain()
    c.feed(0, 'g', [])
    c.feed(1, 'a', ['g'])
    c.feed(2, 'b', ['a'])
    try:
        c.feed(3, 'd', ['c'])
        broke = False
    except m.Reject:
        broke = True
    c2 = m.Chain()
    c2.feed(0, 'g', [])
    try:
        c2.feed(1, 'x', [])
        empty = False
    except m.Reject:
        empty = True
    return broke and empty, (broke, empty)


def kat_dp4(over):
    m = load(over)
    n = 120
    whole, _ = go(m, FakeChain(n, REGS), n)
    _, d = go(m, FakeChain(n, REGS), n, stop_after=3)
    with open(Path(d) / 'checkpoint.log', 'a') as f:
        f.write('deadbeef {"kind":"batch","lo":3')
    resumed, _ = go(m, FakeChain(n, REGS), n, stage=d)
    T = m.totals(m.Checkpoint(Path(d) / 'checkpoint.log').records)          # what a later run reads from disk
    disk = {k: T[k] for k in whole}
    return whole == resumed == disk and whole['blocks'] == n, (whole, resumed, disk)


def kat_dp5(over):
    m = load(over)
    t = [0.0]
    slept = []

    def sleep(s):
        slept.append(s)
        t[0] += s
    b = m.TokenBucket(5, clock=lambda: t[0], sleep=sleep)
    for _ in range(10):
        b.acquire()
    e = m.Endpoint('x', 'x', 999, 99)
    return abs(t[0] - 1.8) < 1e-6 and e.rate <= 50 and e.cap <= 8, (t[0], e.rate, e.cap)


def kat_dp6(over):
    m = load(over)
    n = 100
    r = [go(m, FakeChain(n, REGS), n, batch=b)[0] for b in (1, 7, 50)]
    return r[0] == r[1] == r[2], r


def kat_dp7(over):
    m = load(over)
    p = ROOT / 'forensics/r28/derived/txs.jsonl.gz'
    regs = [t['txid'] for t in map(json.loads, gzip.open(p, 'rt')) if t['tx_type'] == 'REGISTRATION']
    res = {'lo': 0, 'hi': 0, 'blocks': [(0, 'x', [], [])], 'types': {t: 'REGISTRATION' for t in regs}, 'source': 's'}
    s1 = m.summarize(res)
    forged = '0000ab' + 'cd' * 29
    s2 = m.summarize({**res, 'types': {forged: 'REGISTRATION'}})
    ok = len(regs) > 200 and s1['reg_lt3'] == [] and sum(s1['reg_lz'].values()) == len(regs) and s2['reg_lt3'] == [forged]
    return ok, (len(regs), s1['reg_lz'], s2['reg_lz'])


def kat_dp8(over):
    m = load(over)
    e = m.Endpoint('x', 'x', 5, 8)
    e.busy = 3
    e.leave(False)
    a = e.limit
    for _ in range(20):
        e.busy += 1
        e.leave(True, 1.0)
    b = e.limit
    e.busy += 1
    e.leave(True, 10.0)
    c = e.limit
    for _ in range(400):
        e.busy += 1
        e.leave(True, 1.0)
    return (a, b, c, e.limit) == (4, 5, 2, 8), (a, b, c, e.limit)


def kat_dp9(over):
    m = load(over)
    n = 30
    ch = FakeChain(n, REGS, cap=16)
    some = [t for t in ch.txs][:4]
    ch.lack = set(some[:2])
    ch.nobody = {some[3]}
    T, _ = go(m, ch, n, batch=30, eps=('A', 'B'))
    ty = T['types']
    return ty.get('UNSERVED') == 1 and sum(ty.values()) == len(ch.txs), ty


def kat_dp11(over):
    m = load(over)
    ch = FakeChain(1, [('000000' + H(f'q{i}')[6:-4] + f'{0:04x}') for i in range(40)], cap=16)
    T, _ = go(m, ch, 1, batch=1, eps=('B',))
    calls = []
    orig = ch.post

    def post(url, body):
        calls.append(body if isinstance(body, list) else [body])
        return orig(url, body)
    ch.post = post
    go(m, ch, 1, batch=1, eps=('B',))
    tx_reqs = [c for c in calls if c[0]['method'] == 'DERO.GetTransaction']
    return T['registrations'] == 40 and len(tx_reqs) == 2, (T['registrations'], len(tx_reqs))


def kat_dp10(over):
    m = load(over)
    n = 40
    d = '000000' + H('dup')[6:]
    a, _ = go(m, FakeChain(n, (), dup=(9, d)), n, batch=10)        # 9 and 10: two batches
    b, _ = go(m, FakeChain(n, (), dup=(14, d)), n, batch=10)       # 14 and 15: one batch
    return (a['registrations'], a['dup_txids'], b['registrations'], b['dup_txids']) == (1, 1, 1, 1), (a, b)


def within(fn, limit, over=None):
    """kit/hangkit.within: (finished, result) after at most `limit` s; an exception in fn is re-raised (a crash is a
    failure, not a hang)."""
    ok, r, e = _mod('hangkit_dp29', P(over or {}, 'hangkit')).within(fn, limit)
    if e is not None:
        raise e
    return ok, r


def kat_dp12(over):
    m = load(over)
    d = Path(tempfile.mkdtemp(prefix='dp12-'))
    child = d / 'bigdec'
    child.write_text(f"#!{sys.executable} -I\n"
                     "import sys\n"
                     "o = sys.stdout\n"
                     "for line in sys.stdin:\n"
                     "    if '\"f\"' in line:\n"
                     "        o.flush()\n"
                     "    else:\n"
                     "        o.write('{\"ok\": true, \"pad\": \"' + 'x' * 65536 + '\"}\\n')\n")
    os.chmod(child, 0o700)
    dec = m.Decoder(str(child))
    try:
        done, out = within(lambda: dec.run([('t', 'ab' * 32768)] * 200), 20)   # 64 KB in and out per item
    finally:
        dec.p.kill()
    return done and len(out) == 200 and all(r['ok'] for r in out), (done, len(out or []))


def kat_dp13(over):
    m = load(over)
    n = 200
    ch = FakeChain(n)
    orig, failed = ch.post, []

    def post(url, body):
        xs = body if isinstance(body, list) else [body]
        if not failed and url == 'A' and any(x['method'] == 'DERO.GetBlock' and x['params']['height'] == 0 for x in xs):
            failed.append(1)
            time.sleep(1.0)                    # a slow failure: meanwhile B's workers run past the look-ahead
            raise ValueError('malformed reply')  # not a transport error, so the batch (not the request) is retried
        return orig(url, body)
    ch.post = post
    done, res = within(lambda: go(m, ch, n, batch=1, eps=('A', 'B')), 20)
    return done and failed == [1] and res[0]['blocks'] == n, (done, failed, res and res[0]['blocks'])


def kat_dp14(over):
    m = load(over)
    ch = FakeChain(1, [('000000' + H(f'w{i}')[6:-4] + f'{0:04x}') for i in range(2000)], cap=16)
    sizes, orig = [], ch.post

    def post(url, body):
        xs = body if isinstance(body, list) else [body]
        if xs[0]['method'] == 'DERO.GetTransaction':
            sizes.append(sum(len(x['params']['txs_hashes']) for x in xs))
        return orig(url, body)
    ch.post = post
    T, _ = go(m, ch, 1, batch=1, eps=('B',))
    return T['registrations'] == 2000 and sizes and max(sizes) <= 512, (T['registrations'], len(sizes), max(sizes or [0]))


def kat_dp15(over):
    m = load(over)
    ch = FakeChain(1, [('000000' + H(f'v{i}')[6:-4] + f'{0:04x}') for i in range(2000)], cap=16)
    n, gb, orig = [0], [0], ch.post

    def post(url, body):
        xs = body if isinstance(body, list) else [body]
        if xs[0]['method'] == 'DERO.GetBlock':
            gb[0] += 1
        else:
            n[0] += 1
            if n[0] % 3 == 0:
                raise TimeoutError('timed out')
        return orig(url, body)
    ch.post = post
    T, _ = go(m, ch, 1, batch=1, eps=('B',))
    return T['registrations'] == 2000 and gb[0] == 1, (T['registrations'], gb[0], n[0])


def kat_dp16(over):
    m = load(over)
    m.DEC_TIMEOUT = 1
    d = Path(tempfile.mkdtemp(prefix='dp16-'))
    mute, gone = d / 'mute', d / 'gone'
    mute.write_text(f"#!{sys.executable} -I\nimport sys\nfor line in sys.stdin:\n    pass\n")
    gone.write_text(f"#!{sys.executable} -I\nimport sys\nsys.exit(0)\n")
    for f in (mute, gone):
        os.chmod(f, 0o700)
    got = []
    for f in (mute, gone):
        dec = m.Decoder(str(f))
        try:
            def call():
                try:
                    dec.run([('t', 'ab')] * 3)
                    return 'returned'
                except Exception as e:                    # noqa: BLE001 — the type is the result
                    return type(e).__name__
            done, r = within(call, 10, over)
            got.append(r if done else 'HUNG')
        finally:
            dec.p.kill()
    return got == ['CoProcTimeout', 'CoProcEOF'], got


KATS = [('DP1', kat_dp1), ('DP2', kat_dp2), ('DP3', kat_dp3), ('DP4', kat_dp4), ('DP5', kat_dp5), ('DP6', kat_dp6),
        ('DP7', kat_dp7), ('DP8', kat_dp8), ('DP9', kat_dp9), ('DP10', kat_dp10), ('DP11', kat_dp11),
        ('DP12', kat_dp12), ('DP13', kat_dp13), ('DP14', kat_dp14), ('DP15', kat_dp15), ('DP16', kat_dp16)]
OWNERS = {'B182': [k for k, _ in KATS]}
MUTATIONS = [
    ('tool', "        if f'{zlib.crc32(body.encode()):08x}' != crc:", "        if False:", 'B182: a CRC-bad line is trusted'),
    ('tool', "        if self.ignored:                                   # cut the torn tail so new records follow a valid line",
     "        if False:",
     'B182: new records follow a torn line and are lost on the next load'),
    ('tool', "        if d.get('id') != r['block_header']['hash']:", "        if False:",
     'B182: a forged block (id != claimed hash) is accepted'),
    ('tool', "        if not d.get('rs'):\n            raise Reject", "        if False:\n            raise Reject",
     'B182: a block that does not re-serialize is accepted'),
    ('tool', "        elif topo > 0 and (not tips or any(t not in self.set for t in tips)):", "        elif False:",
     'B182: a broken tips chain is accepted'),
    ('tool', "        if r.get('kind') == 'batch' and r['lo'] == nxt:", "        if False:",
     'B182: resume refetches and double counts'),
    ('tool', "        if t > now:\n            self.sleep(t - now)", "        if False:\n            self.sleep(t - now)",
     'B182: the rate cap is not enforced'),
    ('tool', "        self.limit, self.clean = max(1, self.limit // 2), 0", "        self.clean = 0",
     'B182: an error does not reduce the in-flight limit'),
    ('tool', "    txids = list(dict.fromkeys(allt))", "    txids = list(allt)",
     'B182: a txid in two blocks of a batch is asked twice'),
    ('tool', "                dup = [t for t in r['types'] if t in seen]", "                dup = []",
     'B182: a txid in two batches is counted twice'),
    ('tool', "    for t in missing:\n        types[t] = UNSERVED", "    for t in missing:\n        types[t] = 'NORMAL'",
     'B182: an unserved body is typed instead of UNSERVED'),
    ('tool', "        missing = fetch_txs(alt, missing, dec, post, txb, types, hexkeep)", "        pass",
     'B182: a body one endpoint lacks is not asked of the others'),
    ('tool', "                ep.txcap = min(ep.txcap, len(hexes))", "                pass",
     'B182: the per-call cap is not learned'),
    ('tool', "        if x:\n            break\n        n += 1", "        n += 1", 'B182: lz counts every byte'),
    ('coproc', "        w = threading.Thread(target=self._feed, args=(list(lines), errs), daemon=True)\n        w.start()\n",
     "        w = threading.Thread(target=self._feed, args=(list(lines), errs), daemon=True)\n        w.run()\n",
     'B182: the decoder input is written before its output is read (pipe deadlock)'),
    ('tool', "                tasks.put((lo, hi, tries, avoid))         # so a requeued head batch",
     "                while lo > head[0] + ahead and not stop.is_set(): time.sleep(0.2)\n                tasks.put((lo, hi, tries, avoid))         # so a requeued head batch",
     'B182: a worker holds a batch while it waits for the look-ahead'),
    ('tool', "        per = max(1, REQ_TXIDS // cap) ", "        per = len(chunks) ",
     'B182: every txid of a round goes in one HTTP request'),
    ('tool', "REQ_TRIES = 4 ", "REQ_TRIES = 1 ", 'B182: a request timeout restarts the whole batch'),
    ('tool', "self.cp.roundtrip(lines, len(items), timeout=DEC_TIMEOUT)", "self.cp.roundtrip(lines, len(items), timeout=None)",
     'B182: a decoder that stops answering hangs the worker'),
    ('coproc', "        self.q.put(None)                                   # EOF marker", "        pass",
     'B182: a decoder that exits is waited on instead of raising EOF'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_dp29', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run_kats(over):
    res = []
    for name, fn in KATS:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                ok, det = fn(over)
        except (Exception, SystemExit) as e:                      # noqa: BLE001 — a crash is a failure
            ok, det = False, f'{type(e).__name__}: {e}'
        res.append((name, ok, str(det)))
    return res


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:400]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr29 b182 deep KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        src = ROOT / PATHS[key]
        text = src.read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='dp29-mut-') as d:
            mut = Path(d) / PATHS[key]
            mut.parent.mkdir(parents=True, exist_ok=True)
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            try:
                compile(mut.read_text(encoding='utf-8'), str(mut), 'exec')
            except SyntaxError as e:
                print(f'  INVALID   {why}: mutant does not load ({type(e).__name__})')
                missed += 1
                continue
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, extra = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r29 b182 deep KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
