#!/usr/bin/env python3
"""KAT + mutation proofs for the R30 forensics-genesis-coverage dimension (rft §7 B208, B182, B211, B212, B209, B215;
§8 "R30 audit plan" S1-S5). No network, no node, no decoder build: a fake endpoint (post) and a fake decoder serve a
synthetic chain; forged batch records and forged census files in temp dirs. The Go side (canonicality, burn sum,
genesis census) is tools/forensics/b182deep2/r30_census_test.go with go_mutations gm-r30-gen-*.

  GN1 exact dedup (B182): a txid listed again 3 batches later (beyond any window) is counted once and named in
      dup_txids; a stop + resume re-reads txids.bin, so a repeat after the resume is still caught.
  GN2 Sidecar: a sidecar longer than the checkpoint count is truncated; a shorter one refuses (lost sidecar).
  GN3 topo 0 (B182): a topo-0 blob that differs from Generate_Genesis_Block is rejected; the equal one passes.
  GN4 reward (B211): a Go CalcBlockReward that differs from the Python port rejects the batch.
  GN5 summarize2 (B208/B212): a forged Miner_TX Value != 0 is counted; v2 at 481,599 is a version mismatch and v1 at
      21,480 (HF1_HEIGHT, not a version) is not; fees per listing count a txid in two blocks twice, unique once; pv
      keeps per-block values; dup_typed types each multi-listed txid.
  GN6 Chain2: an id that leaves the window never named as a tip is counted unreferenced; a referenced one is not.
  GN7 own_node: loopback, private, link-local and unresolvable hosts are refused; a public address is not.
  GN8 emission (B211): HOLDS on an honest record; a forged reward_sum, a CalcSupply off by one, a grant subtracted, a
      forged Value != 0, a missing premine and a compensating forgery (+1 / -1 in two batches) each FAIL; a short cover
      is PARTIAL, never HOLDS. (The segment identity is implied by the batch identities over a contiguous cover, so its
      own mutation is equivalent and not listed; it stays as a cross-check.)
  GN9 public values (B212): the window re-derives per block from pv (a batch straddling the window edge counts only
      its inside blocks); a differing sum is DIFFERS; no cover is pending.
  GN10 coverage (B215): the tiles tile 0..tip with no gap or overlap; a gap, an overlap, a shifted boundary, a dropped
      tile and a `done` without a record each FAIL; render prints pending as the word, never 0.
  GN11 dc0 typed (B209): a txid in 3 blocks across 2 batches is 1 distinct txid with 2 repeat listings; typed by its body.
  GN12 hang class 4 (2026-11-09 at topo 154,000): while one head batch's many bodies decode, the `decoded` counter in
      progress.json moves (stallwatch work_sig changes with verified_blocks still 0) and the bodies go to more than one
      decoder (spares); the old code had neither, so stallwatch saw no work and would relaunch from the same head.
  GN13 hang class 5 (2026-11-09, head batch 154,000 held > 10 min): with endpoint A's only AIMD slot held, A's
      workers give tasks back instead of waiting in Endpoint.enter holding them; B serves all and the run ends (the old
      worker blocks forever: the test bounds it at 15 s).
  GN14 slow-class 6 (2026-11-09, 2.2 b/s at 158,000): a fast endpoint serving dense batches whose bodies decode
      slowly is fed only the time inside its calls as latency, never the decode time (the old code fed batch wall /
      requests, decode included, and halved). r30 verifier: judged on the fed latency, not on `backoffs == 0`, which
      read scheduler jitter against a microsecond base (3 of 20 unmutated runs failed).
  GN15 B111 count fit (r30 verifier): b111_keys derives the record from the census + straddle sidecars and the QCS1
      record (no typed figure): a repeated key is counted once, the residual is tree - distinct, a registration in the
      census batch at H..end is reported (block_H_onward), a second height is fitted when its batch has none, and a
      straddle that does not end at H - 1 is refused.
  GN16 integrity (r30 verifier): the session_end wall / errors are labelled as covering only the sessions with that
      record, and the sessions without one are named (the census said sessions 5 with session 5's wall only).
  Committed: r30_genesis_canon_parity.json is PASS with 1,560 proof-carrying bodies; the coverage record (when present)
      is PASS and its inputs' SHA-256 match.

  python3 -I harness/kat/test_genesis_r30.py   # exit 0 ok · 3 a KAT failed · 4 a mutation not caught / INVALID
"""
import hashlib, importlib.util, json, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent


def mkbase(dst):
    """a sandbox tree: harness/forensics + harness/intel/disclosure_track.py + harness/kit copied; source dirs linked."""
    shutil.copytree(HARNESS / 'forensics', dst / 'harness/forensics', ignore=shutil.ignore_patterns('__pycache__'))
    (dst / 'harness/intel').mkdir(parents=True)
    shutil.copy2(HARNESS / 'intel/disclosure_track.py', dst / 'harness/intel/disclosure_track.py')
    shutil.copytree(HARNESS / 'kit', dst / 'harness/kit', ignore=shutil.ignore_patterns('__pycache__'))
    (dst / 'harness/runtime').mkdir()
    for f in ('r29_b182_deep_census.json', 'r30_genesis_tip.json'):
        shutil.copy2(HARNESS / 'runtime' / f, dst / 'harness/runtime' / f)
    for d in ('config', 'blockchain', 'cryptography', 'forensics'):
        (dst / d).symlink_to(ROOT / d)


def load(base, name):
    d = str(base / 'harness/forensics')
    for k in [k for k in sys.modules if k in ('b182_deep_r29', 'genesis_r30', 'genesis_derive_r30', 'coverage',
                                               'dc0_genesis', 's0_checkpoint', 'audit2', 'audit_check', 'disclosure_track')]:
        del sys.modules[k]
    sys.path.insert(0, d)
    try:
        spec = importlib.util.spec_from_file_location(name, base / 'harness/forensics' / f'{name}.py')
        m = importlib.util.module_from_spec(spec)
        sys.modules[name] = m
        spec.loader.exec_module(m)
        return m
    finally:
        sys.path.remove(d)


def load_kit(base, name):
    spec = importlib.util.spec_from_file_location(f'kit_{name}_{id(base)}', base / 'harness/kit' / f'{name}.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def H(n):
    return hashlib.sha256(str(n).encode()).hexdigest()


# ------------------------------------------------------------------------------------------- the synthetic chain
class FakeChain:
    """blocks 0..N-1: id H('b',t), tips [prev id], tx lists given; tx bodies 'tx:<id>'; the decoder answers from maps."""

    def __init__(self, G, n, txs, reward, genesis_x='g0', mv=None, bad_rw=None, tytab=None, slow=0.0):
        self.n, self.txs, self.G, self.slow, self.used = n, txs, G, slow, set()
        self.blk = {}
        self.genesis = {'id': H(('b', 0)), 'x': genesis_x}
        for t in range(n):
            bid = H(('b', t))
            x = genesis_x if t == 0 else f'blk{t}'
            self.blk[t] = {'blob': x, 'block_header': {'hash': bid}}
        self.dec = {}
        for t in range(n):
            self.dec[self.blk[t]['blob']] = {'ok': True, 'id': H(('b', t)), 'h': t, 'rs': True,
                                             'tips': [H(('b', t - 1))] if t else [], 'txs': txs.get(t, []),
                                             'mj': 1, 'mn': 1, 'mt': 'PREMINE' if t == 0 else 'COINBASE',
                                             'mv': (mv or {}).get(t, 0), 'mb': 1,
                                             'rw': (bad_rw or {}).get(t, reward(t))}
        self.tytab = tytab or {}

    def post(self, url, body):
        out = []
        for q in body:
            if q['method'] == 'DERO.GetBlock':
                out.append({'id': q['id'], 'result': self.blk[q['params']['height']]})
            else:
                out.append({'id': q['id'], 'result': {'txs_as_hex': ['tx:' + t for t in q['params']['txs_hashes']]}})
        return out

    def mk_dec(self):
        fc = self

        class D:
            def run(self, items):
                out = []
                if fc.slow and any(k == 't' for k, _ in items):
                    fc.used.add(id(self))
                for k, x in items:
                    if fc.slow and k == 't':
                        import time as _t
                        _t.sleep(fc.slow)
                    if k == 'b':
                        out.append(dict(fc.dec[x]))
                    else:
                        t = x[3:]
                        ty = fc.tytab.get(t, 'NORMAL')
                        out.append({'ok': True, 'id': t, 'rs': True, 'ty': ty, 'fee': 3, 'burn': 5, 'val': 0, 'np': 1,
                                    'rk': H(('k', t)) if ty == 'REGISTRATION' else None, 'cp': 2, 'cs': 1})
                return out

            def close(self):
                pass
        return D()


def eps(G):
    R = G.R
    return [R.Endpoint('fake', 'http://203.0.113.1/', 50, 1, sleep=lambda s: None)]


def kats(base):
    f = []

    def ok(cond, msg):
        if not cond:
            f.append(msg)
    try:
        G = load(base, 'genesis_r30')
        R = G.R
        reward, calc, hf = G.chain_constants(base)
        # GN1 exact dedup across batches and across a resume
        X = 'aa' * 32
        fc = FakeChain(G, 600, {5: [X, 'bb' * 32], 350: [X], 551: [X]}, reward)
        st = Path(tempfile.mkdtemp(prefix='gn1_'))
        try:
            cfg = {'stage': str(st), 'from': 0, 'to': 599, 'batch': 100, 'txb': 64}
            G.run(cfg, eps(G), post=fc.post, mk_dec=fc.mk_dec, stop_after=4, genesis=fc.genesis)
            T = G.run(cfg, eps(G), post=fc.post, mk_dec=fc.mk_dec, genesis=fc.genesis)
            ok(T['blocks'] == 600, f'GN1 blocks {T["blocks"]}')
            ok(T['txs'] == 2, f'GN1 txs counted {T["txs"]} (want 2: X once, exact dedup)')
            ok(T['dup_txids'] == 2, f'GN1 dup listings {T["dup_txids"]} (want 2: 350 and 551, the second after a resume)')
            ok((st / 'txids.bin').stat().st_size == 64, 'GN1 sidecar holds 2 txids')
            ok(T['sessions'] == 2, f'GN1 sessions {T["sessions"]}')
            ok((st / 'DONE').exists(), 'GN1 DONE marker')
        finally:
            shutil.rmtree(st, ignore_errors=True)
        # GN12 hang class 4: one head batch of many bodies decodes for long; the `decoded` counter moves (stallwatch
        # sees work) and the bodies are spread over the spare decoders
        import threading as _th
        SW = load_kit(base, 'stallwatch')
        many = [f'{k:064x}' for k in range(1, 1201)]
        fc = FakeChain(G, 100, {7: many}, reward, slow=0.001)
        st = Path(tempfile.mkdtemp(prefix='gn12_'))
        try:
            cfg = {'stage': str(st), 'from': 0, 'to': 99, 'batch': 100, 'txb': 64, 'prog_s': 0.05, 'spares': 4}
            th = _th.Thread(target=G.run, args=(cfg, eps(G)), kwargs={'post': fc.post, 'mk_dec': fc.mk_dec, 'genesis': fc.genesis}, daemon=True)
            th.start()
            sigs, prog = [], st / 'progress.json'
            import time as _t
            t_end = _t.monotonic() + 20
            while th.is_alive() and _t.monotonic() < t_end:
                if prog.exists():
                    try:
                        d = json.loads(prog.read_text())
                    except ValueError:
                        d = {}
                    if d.get('verified_blocks', 0) == 0:
                        sigs.append(SW.work_sig(str(prog), ['verified_blocks', 'txs', 'next_topo', 'decoded'], []))
                _t.sleep(0.05)
            th.join(5)
            ok(not th.is_alive(), 'GN12 run did not finish in 25 s')
            ok(len(set(map(str, sigs))) > 1, f'GN12 no counter moved while the head batch decoded ({len(sigs)} samples)')
            ok(len(fc.used) > 1, f'GN12 the bodies were decoded on {len(fc.used)} decoder(s), not spread')
        finally:
            shutil.rmtree(st, ignore_errors=True)
        # GN13 hang class 5: endpoint A's only AIMD slot is held (busy == limit, by a slow batch elsewhere); a worker
        # of A must not hold the head batch waiting for it: B serves every batch and the run ends
        fc = FakeChain(G, 300, {}, reward)
        st = Path(tempfile.mkdtemp(prefix='gn13_'))
        try:
            A = R.Endpoint('A', 'http://198.51.100.1/', 50, 2, sleep=lambda s: None)
            B = R.Endpoint('B', 'http://198.51.100.2/', 50, 1, sleep=lambda s: None)
            A.limit, A.busy = 1, 1
            cfg = {'stage': str(st), 'from': 0, 'to': 299, 'batch': 100, 'txb': 64, 'prog_s': 0.05, 'spares': 0}
            th = _th.Thread(target=G.run, args=(cfg, [A, B]), kwargs={'post': fc.post, 'mk_dec': fc.mk_dec, 'genesis': fc.genesis}, daemon=True)
            th.start()
            th.join(15)
            ok(not th.is_alive(), 'GN13 a worker held the head batch while waiting for a full endpoint (run hung 15 s)')
            ok(A.stats['blocks'] == 0 and B.stats['blocks'] == 300, f'GN13 blocks A {A.stats["blocks"]} B {B.stats["blocks"]}')
        finally:
            A.busy = 0
            shutil.rmtree(st, ignore_errors=True)
        # GN14 slow-class 6: dense batches decode slowly while the endpoint answers fast; AIMD must not halve (the old
        # code fed batch wall / requests, decode included, as latency: limit 8 -> 1, few batches in flight)
        dense = {t: [f'{t:08x}{k:056x}' for k in range(20)] for t in range(200, 400)}
        fc = FakeChain(G, 400, dense, reward, slow=0.0002)
        st = Path(tempfile.mkdtemp(prefix='gn14_'))
        try:
            E = R.Endpoint('E', 'http://198.51.100.3/', 50, 4, sleep=lambda s: None)
            # r30 verifier: judge the latency FED to the AIMD, not its backoff count. The fake endpoint answers in
            # microseconds, so the old `backoffs == 0` read scheduler jitter (lat > 3 x a us-scale base): 3 of 20
            # unmutated runs failed and an unrelated mutation was counted CAUGHT by it. Decode time per request of a
            # dense batch is fixed by the fake decoder (slow x 2000 txs / (1 + 2000/txb) requests, ~12 ms): the old
            # code feeds at least that, the fixed code only the time inside the calls (~us; a quarter is the margin).
            fed, _leave = [], E.leave
            def _rec(ok_, lat=None):
                if ok_:
                    fed.append(lat)
                return _leave(ok_, lat)
            E.leave = _rec
            cfg = {'stage': str(st), 'from': 0, 'to': 399, 'batch': 100, 'txb': 64, 'prog_s': 0.05, 'spares': 0}
            G.run(cfg, [E], post=fc.post, mk_dec=fc.mk_dec, genesis=fc.genesis)
            dec_per_req = fc.slow * 2000 / (1 + -(-2000 // cfg['txb']))
            ok(len(fed) >= 4 and max(fed) < dec_per_req / 4,
               f'GN14 AIMD fed decode time as latency: max {max(fed or [0]) * 1e3:.2f} ms/req (decode {dec_per_req * 1e3:.2f} ms/req)')
        finally:
            shutil.rmtree(st, ignore_errors=True)
        # GN2 sidecar truncate / refuse
        st = Path(tempfile.mkdtemp(prefix='gn2_'))
        try:
            (st / 's.bin').write_bytes(b'x' * 96)
            G.Sidecar(st / 's.bin', 2)
            ok((st / 's.bin').stat().st_size == 64, 'GN2 sidecar not truncated to the checkpoint count')
            try:
                G.Sidecar(st / 's.bin', 3)
                f.append('GN2 a short sidecar was accepted')
            except SystemExit:
                pass
        finally:
            shutil.rmtree(st, ignore_errors=True)
        # GN3 topo 0 vs generated genesis
        fc = FakeChain(G, 100, {}, reward)
        reps = [(t, fc.blk[t]) for t in range(100)]
        dd = fc.mk_dec().run([('b', r['blob']) for _, r in reps])
        try:
            G.check_blocks2(0, 99, reps, dd, reward, fc.genesis)
        except R.Reject as e:
            f.append(f'GN3 honest genesis rejected: {e}')
        try:
            G.check_blocks2(0, 99, reps, dd, reward, {'id': fc.genesis['id'], 'x': 'other'})
            f.append('GN3 a topo-0 blob != Generate_Genesis_Block passed')
        except R.Reject:
            pass
        # GN4 reward Go != Python
        fc = FakeChain(G, 100, {}, reward, bad_rw={42: reward(42) + 1})
        reps = [(t, fc.blk[t]) for t in range(100)]
        try:
            G.check_blocks2(0, 99, reps, fc.mk_dec().run([('b', r['blob']) for _, r in reps]), reward, fc.genesis)
            f.append('GN4 Go reward != Python passed')
        except R.Reject:
            pass
        # GN5 summarize2
        T1, T2 = '11' * 32, '22' * 32
        def blk(t, txs, mj=1, mv=0):
            return (t, H(t), [], txs, {'mj': mj, 'mn': 1, 'mt': 'PREMINE' if t == 0 else 'COINBASE', 'mv': mv, 'mb': 2, 'rw': reward(t)})
        res = {'lo': 21480, 'hi': 21482, 'source': 's', 'blocks': [blk(21480, [T1], mj=1), blk(21481, [T1, T2], mv=9), blk(21482, [])],
               'txd': {T1: {'ty': 'NORMAL', 'fee': 3, 'burn': 5}, T2: {'ty': 'REGISTRATION', 'rk': 'ab' * 32}},
               'dup_in_batch': [T1]}
        rec, tids, keys = G.summarize2(res, set(), hf, [])
        ok(rec['miner_value_nonzero'] == 1, 'GN5 forged Value != 0 not counted')
        ok(rec['ver_mismatch'] == 0, f'GN5 v1 at HF1_HEIGHT flagged ({rec["ver_mismatch"]})')
        ok(rec['fee'].get('NORMAL') == 3 and rec['fee_listing'] == 6, f'GN5 fee unique {rec["fee"]} listing {rec["fee_listing"]}')
        ok(rec['pv'] == {'21480': [3, 5], '21481': [3, 5]}, f'GN5 pv {rec["pv"]}')
        ok(rec.get('dup_typed') == {T1: 'NORMAL'}, f'GN5 dup_typed {rec.get("dup_typed")}')
        ok(len(tids) == 2 and len(keys) == 1 and rec['n_regkeys'] == 1, 'GN5 sidecar items')
        res = {'lo': 481599, 'hi': 481600, 'source': 's', 'blocks': [blk(481599, [], mj=2), blk(481600, [], mj=2)], 'txd': {}}
        rec, _, _ = G.summarize2(res, set(), hf, [])
        ok(rec['ver_mismatch'] == 1 and rec['ver_mismatch_topos'] == [481599], f'GN5 v2 at 481,599 not flagged {rec["ver_mismatch_topos"]}')
        ok(rec['ver_first'] == {'2': 481599} and rec['ver_last'] == {'2': 481600}, 'GN5 ver first/last')
        # GN6 Chain2 unreferenced
        c = G.Chain2()
        c.feed(0, 'g', [])
        c.feed(1, 'a', ['g'])
        c.feed(2, 'side', ['a'])
        c.feed(3, 'b', ['a'])
        for t in range(4, 4 + R.WINDOW + 2):
            c.feed(t, f'n{t}', ['b' if t == 4 else f'n{t - 1}'])
        u = c.take_unref()
        ok(u == [2], f'GN6 unreferenced {u} (want [2])')
        # GN7 own node
        res_ = {'a.example': '127.0.0.1', 'b.example': '192.168.1.5', 'c.example': '169.254.0.9', 'p.example': '1.1.1.1'}
        def rs(h):
            if h not in res_:
                raise OSError('unresolvable')
            return res_[h]
        for h, want in (('a.example', True), ('b.example', True), ('c.example', True), ('nx.example', True), ('p.example', False)):
            ok(G.own_node(f'http://{h}:10102/json_rpc', rs) is want, f'GN7 {h} own_node != {want}')
        # GN8 emission
        D = load(base, 'genesis_derive_r30')
        G = sys.modules['genesis_r30']
        def brec(lo, hi, **kw):
            r = {'kind': 'batch', 'lo': lo, 'hi': hi, 'blocks': hi - lo + 1, 'reward_sum': calc(hi + 1) - calc(lo),
                 'miner_types': {'COINBASE': hi - lo + 1 - (lo == 0), **({'PREMINE': 1} if lo == 0 else {})},
                 'miner_value_nonzero': 0}
            if lo == 0:
                r['premine_value'] = hf['PREMINE']
            r.update(kw)
            return r
        bs = [brec(0, 99), brec(100, 199), brec(200, 299)]
        seg = [{'id': 'x', 'lo': 0, 'hi': 299}]
        em, _ = D.emission(bs, seg, calc, hf)
        ok(em[0]['verdict'] == 'HOLDS', f'GN8 honest emission {em[0]["verdict"]} {em[0].get("checks")}')
        E0 = calc.__code__ and next(h for h in range(1, 10 ** 8, 100000) if reward(h) != reward(0)) - 100000
        while reward(E0 + 100) == reward(0):        # the first halving boundary, found from the formula itself
            E0 += 100
        bsE = [brec(E0, E0 + 99), brec(E0 + 100, E0 + 199)]
        segE = [{'id': 'e', 'lo': E0, 'hi': E0 + 199}]
        e, _ = D.emission(bsE, segE, calc, hf)
        ok(e[0]['verdict'] == 'HOLDS', f'GN8 honest emission across the halving {e[0]["verdict"]}')
        e, _ = D.emission(bsE, segE, lambda h: calc(h + 1), hf)
        ok(e[0]['verdict'] == 'FAILS', f'GN8 CalcSupply off by one across the halving: {e[0]["verdict"]}')
        r1, r2 = brec(100, 199), brec(200, 299)
        e, _ = D.emission([brec(0, 99), dict(r1, reward_sum=r1['reward_sum'] + 1), dict(r2, reward_sum=r2['reward_sum'] - 1)], seg, calc, hf)
        ok(e[0]['verdict'] == 'FAILS', f'GN8 compensating forgery (+1 / -1, segment sum equal): {e[0]["verdict"]}')
        for name, b2, cc in (('forged reward', [brec(0, 99), brec(100, 199, reward_sum=1), brec(200, 299)], calc),
                             ('grant subtracted', bs, lambda h: calc(h) - (hf['credit'] if h > 150 else 0)),
                             ('Value != 0', [brec(0, 99), brec(100, 199, miner_value_nonzero=1), brec(200, 299)], calc),
                             ('premine missing', [brec(0, 99, premine_value=0), brec(100, 199), brec(200, 299)], calc)):
            e, _ = D.emission(b2, seg, cc, hf)
            ok(e[0]['verdict'] == 'FAILS', f'GN8 {name}: {e[0]["verdict"]}')
        e, _ = D.emission(bs[:2], seg, calc, hf)
        ok(e[0]['verdict'] == 'PARTIAL', f'GN8 short cover {e[0]["verdict"]}')
        # GN9 window per block
        w = (150, 249)
        b9 = [brec(100, 199, pv={'120': [1, 1], '150': [2, 10]}), brec(200, 299, pv={'249': [4, 20], '250': [8, 40]})]
        _, win = D.public_values(b9, seg, w, {'fee': 6, 'burn': 30})
        ok(win['verdict'] == 'EQUAL' and win['fee_sum'] == 6 and win['burn_sum'] == 30, f'GN9 window {win}')
        _, win = D.public_values(b9, seg, w, {'fee': 7, 'burn': 30})
        ok(win['verdict'] == 'DIFFERS', f'GN9 differing window {win["verdict"]}')
        _, win = D.public_values(b9[:1], seg, w, {'fee': 2, 'burn': 10})
        ok(win['verdict'] == 'pending', f'GN9 short window cover {win["verdict"]}')
        # GN10 coverage
        COV = load(base, 'coverage')
        walls, window = {'wall1': 30, 'wall2': 50}, (40, 60)
        tl = COV.tiles(19, 80, 90, walls, window)
        full = {c: {'state': 'pending'} for c in COV.CHECKS}
        rows = [dict(full) for _ in tl]
        ok(COV.check(tl, rows, 90, base) == [], f'GN10 honest tiles {COV.check(tl, rows, 90, base)}')
        bad = {'gap': [tl[0], (tl[1][0], tl[1][1] + 1, tl[1][2])] + tl[2:],
               'overlap': [tl[0], (tl[1][0], tl[1][1] - 1, tl[1][2])] + tl[2:],
               'dropped tile': tl[:3] + tl[4:], 'short end': tl[:-1] + [(tl[-1][0], tl[-1][1], 89)]}
        for k, t2 in bad.items():
            ok(COV.check(t2, rows[:len(t2)], 90, base) != [], f'GN10 {k} passed')
        r2 = [dict(full) for _ in tl]
        r2[2] = dict(full, chain={'state': 'done'})
        ok(any('done without a record' in x for x in COV.check(tl, r2, 90, base)), 'GN10 done without a record passed')
        r3 = [dict(full) for _ in tl]
        r3[2] = dict(full, chain={'state': 'done', 'record': 'harness/runtime/r29_b182_deep_census.json', 'sha256': 'x'})
        ok(COV.check(tl, r3, 90, base) == [], 'GN10 done with a record FAILED')
        txt = '\n'.join(COV.render({'checks': COV.CHECKS, 'tiles': [{'id': t, 'lo': lo, 'hi': hi, 'cells': r} for (t, lo, hi), r in zip(tl, rows)]}))
        ok('=pending' in txt and '=0' not in txt, 'GN10 render shows pending as 0')
        # GN11 dc0 typed: txid in 3 blocks across 2 batches
        b11 = [{'kind': 'batch', 'lo': 0, 'hi': 99, 'blocks': 100},
               {'kind': 'batch', 'lo': 100, 'hi': 199, 'blocks': 100, 'dup_txids': [T1], 'dup_in_batch': [T1], 'dup_typed': {T1: 'REGISTRATION'}}]
        b11.append({'kind': 'batch', 'lo': 200, 'hi': 299, 'blocks': 100, 'dup_txids': [T1], 'dup_typed': {T1: 'REGISTRATION'}})
        d11 = D.dc0_typed(b11, seg, (1000, 2000), set(), [('HF1', 50), ('MAJOR_HF2', 500)])
        ok(d11['distinct_txids'] == 1 and d11['repeat_listings'] == 2 and d11['by_type'] == {'REGISTRATION': 1},
           f'GN11 dc0 typed {d11}')
        # GN15 B111 count fit from records (r30 verifier: the committed record was typed by hand)
        k1, k3, k4, k5 = (bytes([i]) * 32 for i in (1, 3, 4, 5))
        def stage(name, brs, keys):
            d = Path(tempfile.mkdtemp(prefix=f'gn15{name}_'))
            (d / 'checkpoint.log').write_text(''.join(D.R.seal(r) for r in brs))
            (d / 'regkeys.bin').write_bytes(b''.join(keys))
            return d
        bb = lambda lo, hi, n: {'kind': 'batch', 'lo': lo, 'hi': hi, 'blocks': hi - lo + 1, 'n_regkeys': n, 'reg_genesis_key': 0}
        m15 = stage('m', [{'kind': 'session', 'from_topo': 0}, bb(0, 99, 2), bb(100, 199, 3), bb(200, 299, 0)], [k1, k1, k3, k4, k5])
        s15 = stage('s', [bb(100, 149, 2)], [k3, k4])
        s15b = stage('sb', [bb(100, 148, 2)], [k3, k4])
        (base / 'harness/runtime/qcs_gn15.json').write_text(json.dumps({'census': {'150': {'balance_tree_keys': 4},
                                                                                   '250': {'balance_tree_keys': 5}}}))
        try:
            k = D.b111_keys(m15, s15, root=base, qcs='harness/runtime/qcs_gn15.json')
            ok(k['registrations_0_99'] == 2 and k['registrations_100_149'] == 2, f'GN15 registrations {k}')
            ok(k['distinct_registration_key_digests_0_149'] == 3 and k['repeated_registration_keys'] == 1,
               f'GN15 a repeated key counted twice: {k.get("distinct_registration_key_digests_0_149")}')
            ok(k['residual'] == 1 and k['balance_tree_keys_at_150']['value'] == 4, f'GN15 residual {k["residual"]}')
            ok(k['block_H_onward_registrations']['value'] == 1,
               f'GN15 a registration at H..batch end not reported: {k["block_H_onward_registrations"]}')
            o = k['other_heights'].get('250', {})
            ok(o.get('exact') and o.get('distinct_registration_key_digests') == 4 and o.get('residual') == 1, f'GN15 second fit {o}')
            try:
                D.b111_keys(m15, s15b, root=base, qcs='harness/runtime/qcs_gn15.json')
                ok(False, 'GN15 a straddle short of H - 1 passed')
            except ValueError:
                pass
        finally:
            for d in (m15, s15, s15b):
                shutil.rmtree(d, ignore_errors=True)
        # GN16 integrity: session wall / errors cover only the sessions that wrote session_end
        r16 = [{'kind': 'session', 'from_topo': 0}, {'kind': 'batch'}, {'kind': 'session', 'from_topo': 100}, {'kind': 'batch'},
               {'kind': 'session_end', 'wall_s': 5, 'errors': 1}, {'kind': 'session', 'from_topo': 200},
               {'kind': 'session_end', 'wall_s': 7, 'errors': 0}]
        i16 = D.integrity(r16)
        ok(i16['sessions'] == 3 and i16['sessions_with_end_record'] == 2 and i16['session_end_wall_s'] == 12
           and i16['session_end_errors'] == 1, f'GN16 integrity {i16}')
        ok(i16.get('sessions_without_end_record', {}).get('from_topos') == [0], f'GN16 unended sessions {i16}')
        ok('session_wall_s' not in i16, 'GN16 an all-sessions wall label for the session_end walls only')
    except Exception as e:  # noqa: BLE001
        import traceback
        f.append(f'crashed: {type(e).__name__}: {e} {traceback.format_exc().splitlines()[-3][:120]}')
    return f


def committed():
    f = []
    p = HARNESS / 'runtime/r30_genesis_canon_parity.json'
    d = json.loads(p.read_text())
    if d.get('verdict') != 'PASS' or d.get('proof_carrying') != 1560 or d.get('differ'):
        f.append(f'committed: canon parity {d.get("verdict")} {d.get("proof_carrying")}')
    k = json.loads((HARNESS / 'runtime/r30_genesis_b111_keys.json').read_text())
    if 'generated by genesis_derive_r30.b111_keys' not in k.get('schema', '') or 'inputs' not in k:
        f.append('committed: the B111 key record is not the generated one (b111_keys)')
    g = json.loads((HARNESS / 'runtime/r30_genesis_census.json').read_text()).get('integrity', {})
    if 'session_wall_s' in g or 'sessions_with_end_record' not in g:
        f.append('committed: census integrity labels the session_end wall as all sessions')
    c = HARNESS / 'runtime/r30_genesis_coverage.json'
    if c.exists():
        cov = json.loads(c.read_text())
        if cov.get('verdict') != 'PASS':
            f.append('committed: coverage FAIL')
        for rel, s in cov.get('inputs', {}).items():
            if hashlib.sha256((ROOT / rel).read_bytes()).hexdigest() != s:
                f.append(f'committed: coverage input changed: {rel}')
    return f


MUTATIONS = [   # (file under harness/forensics, old, new)
    ('genesis_r30.py', "    seen = set(txside.read())                              # EXACT", "    seen = set()  # EXACT"),
    ('genesis_r30.py', "                dup = {t for t in order if bytes.fromhex(t) in seen}", "                dup = set()"),
    ('genesis_r30.py', "            if bid != genesis['id'] or r['blob'] != genesis['x']:", "            if bid != genesis['id']:"),
    ('genesis_r30.py', "        if d.get('rw') != reward(topo):", "        if False:"),
    ('genesis_r30.py', "        elif d.get('mv'):\n            mv_nz += 1", "        elif False:\n            mv_nz += 1"),
    ('genesis_r30.py', "    if h >= hf['MAJOR_HF2_HEIGHT']:", "    if h >= hf['HF1_HEIGHT']:"),
    ('genesis_r30.py', "            if old not in self.refd:", "            if False:"),
    ('genesis_r30.py', "        if size != 32 * n:", "        if False:"),
    ('genesis_r30.py', "    return ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified", "    return ip.is_loopback"),
    ('genesis_r30.py', "        fee_l, burn_l = fee_l + bf, burn_l + bb", "        fee_l, burn_l = fee_l + 0, burn_l + bb"),
    ('genesis_r30.py', "        DECODED[0] += len(items)", "        DECODED[0] += 0"),
    ('genesis_r30.py', "    if len(items) <= PAR_MIN or _SPARE['q'] is None:", "    if True:"),
    ('genesis_r30.py', "            if ep.busy >= ep.limit and n_eps > 1:", "            if False:"),
    ('genesis_r30.py', "                ep.leave(True, res.get('net_s', time.monotonic() - t0) / max(1, res.get('reqs', 1)))", "                ep.leave(True, (time.monotonic() - t0) / max(1, res.get('reqs', 1)))"),
    ('genesis_derive_r30.py', "    bad = [(b['lo'], b['hi']) for b in bs if b.get('reward_sum') != calc(b['hi'] + 1) - calc(b['lo'])]", "    bad = []"),
    ('genesis_derive_r30.py', "        formula = calc(chi + 1) - calc(clo)", "        formula = calc(chi) - calc(clo)"),
    ('genesis_derive_r30.py', "            'coinbase_value_zero': sum(b.get('miner_value_nonzero', 0) for b in c) == 0,", "            'coinbase_value_zero': True,"),
    ('genesis_derive_r30.py', "    return 'HOLDS' if checks['cover_contiguous'] else 'PARTIAL'", "    return 'HOLDS'"),
    ('genesis_derive_r30.py', "            if window[0] <= int(t) <= window[1]:", "            if True:"),
    ('genesis_derive_r30.py', "            rep[t] += 1", "            rep[t] += 2"),
    ('genesis_derive_r30.py', "    distinct = len(set(keys))", "    distinct = len(keys)"),
    ('genesis_derive_r30.py', "                                         'value': holder[0].get('n_regkeys', 0) - ns},",
     "                                         'value': 0},"),
    ('genesis_derive_r30.py', "    if not ss or not contiguous(ss) or shi != H - 1 or", "    if not ss or not contiguous(ss) or"),
    ('genesis_derive_r30.py', "    out = {'sessions': len(sess), 'sessions_with_end_record': len(ends),",
     "    out = {'sessions': len(sess), 'sessions_with_end_record': len(sess),"),
    ('genesis_derive_r30.py', "            if cur is not None:\n                open_.append(cur.get('from_topo'))\n            cur = r",
     "            if cur is not None:\n                pass\n            cur = r"),
    ('coverage.py', "        if blo != ahi + 1:", "        if blo > ahi + 1:"),
    ('coverage.py', "                if not rec or not (Path(root) / rec).exists() or not cell.get('sha256'):", "                if False:"),
    ('coverage.py', "    if tl and tl[-1][2] != tip:", "    if False:"),
    ('coverage.py', "        lines.append(f\"{t['id']} {t['lo']:,}..{t['hi']:,}: \" + ' '.join(f\"{c}={t['cells'][c]['state']}\" for c in cov['checks']))",
     "        lines.append(f\"{t['id']} {t['lo']:,}..{t['hi']:,}: \" + ' '.join(f\"{c}={t['cells'][c]['state'].replace('pending', '0')}\" for c in cov['checks']))"),
]


def main():
    base = Path(tempfile.mkdtemp(prefix='gn30base_'))
    try:
        mkbase(base)
        f = kats(base) + committed()
    finally:
        shutil.rmtree(base, ignore_errors=True)
    print('GN1-GN16 + committed:', 'PASS' if not f else 'FAIL\n  ' + '\n  '.join(f))
    if f:
        return 3
    rc, caught, n = 0, 0, 0
    for i, (fn, old, new) in enumerate(MUTATIONS, 1):
        n += 1
        tmp = Path(tempfile.mkdtemp(prefix='gn30mut_'))
        try:
            mkbase(tmp)
            p = tmp / 'harness/forensics' / fn
            src = p.read_text()
            if src.count(old) != 1:
                print(f'mutation {i} INVALID: text found {src.count(old)} times in {fn}'); rc = 4; continue
            p.write_text(src.replace(old, new, 1))
            mf = kats(tmp)
            if mf and not all('crashed' in x for x in mf):
                caught += 1
                print(f'mutation {i} CAUGHT ({fn}): {mf[0][:110]}')
            else:
                print(f'mutation {i} NOT CAUGHT ({fn}): {old.strip()[:80]}' + (f' [only crashes: {mf[0][:80]}]' if mf else '')); rc = 4
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print(f'mutations caught {caught}/{n}')
    return rc


if __name__ == '__main__':
    sys.exit(main())
