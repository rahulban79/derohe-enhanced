#!/usr/bin/env python3
"""test_gt_reward_r32.py — r32 (block-reward / DAG analysis): harness/gametheory/reward_intel.py.
  GR1 anchors: a pristine forged tree checks all OK; a quote moved down one line is MOVED (exit 0); a quote edited
      away is DRIFT (exit 4)
  GR2 formula: the constants parsed from the anchored lines give BaseReward 123000 / RRI 7,000,000 and the rewards,
      supply, coinbase split, fee floor and difficulty step that blockchain/r32_reward_split_test.go pins from the Go
      code; a forged BLOCK_TIME = 9 changes the parsed constants (they are read, not hard-coded)
  GR3 refusal: a start below the pruned floor 7,498,540 is refused with exit 2 before any RPC call; a node whose
      prunedheight is higher refuses after GetInfo only; --live --start below the floor exits 2
  GR4 privacy: forged headers / miniblocks / alt blocks full of 'dero1' and 'deto1' addresses produce an output with
      neither substring, the per-run salt is not written, two runs give different pseudonyms; assert_private and
      write_private refuse an address
  GR5 side blocks: classify_block (sideblock -> side, no topo -> orphan, else main; tip link) and side_overlap (shared
      normal miniblocks of an alt block and the winning block)
  GR6 aggregate: distinct miners exclude 'unknown', the integrator / dev-default flags, fee share, difficulty_check
  GR7 rpc: POST with Content-Type application/json, at most one request per min_interval
All inputs are forged in memory or a temporary directory; no RPC is made, nothing outside it is written.
  python3 -I harness/kat/test_gt_reward_r32.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, importlib.util, io, json, shutil, sys, tempfile, time, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'ri': 'harness/gametheory/reward_intel.py'}
COPY_DIRS = ['harness/gametheory']
ANCH = 'harness/gametheory/reward_anchors.json'
FORGED_DEV = 'dero1qforgeddevaddressforthekatonlyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'


def load(over, key='ri'):
    root = Path(over.get('root') or ROOT)
    spec = importlib.util.spec_from_file_location(f'gr32_{key}_{uuid.uuid4().hex[:6]}', root / PATHS[key])
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@contextlib.contextmanager
def forged_tree(over, edit=None):
    """a temp tree: the anchors file (from the tree under test) + copies of every anchored source file (inputs);
    config/config.go carries a forged Dev_Address. edit(dir) may alter it."""
    root = Path(over.get('root') or ROOT)
    with tempfile.TemporaryDirectory(prefix='gr32-') as d:
        d = Path(d)
        (d / ANCH).parent.mkdir(parents=True)
        shutil.copy(root / ANCH, d / ANCH)
        for a in json.loads((root / ANCH).read_text())['anchors']:
            dst = d / a['file']
            if not dst.exists():
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(ROOT / a['file'], dst)
        cfg = d / 'config/config.go'
        t = cfg.read_text()
        import re
        t = re.sub(r'(\tDev_Address:\s*")[^"]+(")', lambda m: m.group(1) + FORGED_DEV + m.group(2), t, count=1)
        cfg.write_text(t)
        if edit:
            edit(d)
        yield d


def anchor(d, aid):
    return {a['id']: a for a in json.loads((Path(d) / ANCH).read_text())['anchors']}[aid]


def kat_gr1(over):
    ri = load(over)
    with forged_tree(over) as d:
        res0, code0 = ri.check(d)
        a = anchor(d, 'RW06')
        p = Path(d) / a['file']
        lines = p.read_text().split('\n')
        lines.insert(a['line'] - 1, '// a forged comment moves the quote down one line')
        p.write_text('\n'.join(lines))
        res1, code1 = ri.check(d)
        st1 = {i: s for i, s, _ in res1}
        p.write_text(p.read_text().replace(a['quote'], 'return BaseReward >> (height / RewardReductionInterval)'))
        res2, code2 = ri.check(d)
        st2 = {i: s for i, s, _ in res2}
    ok = (code0 == 0 and all(s == 'OK' for _, s, _ in res0) and len(res0) >= 40
          and code1 == 0 and st1['RW06'] == 'MOVED' and code2 == 4 and st2['RW06'] == 'DRIFT')
    return ok, code0, code1, st1.get('RW06'), code2, st2.get('RW06')


def kat_gr2(over):
    ri = load(over)
    with forged_tree(over) as d:
        c, src = ri.constants(d)
    r = {h: ri.calc_block_reward(h, c) for h in (0, 6999999, 7000000, 7504640, 13999999, 14000000, 21000000)}
    sp0 = ri.split(30750, 10)
    sp1 = ri.split(30787, 10)
    sp2 = ri.split(61500, 10, 2)
    fees = [ri.min_fee(s, c) for s in (1, 1024, 1025, 2049)]
    d1 = ri.next_difficulty(2074825, 1794732755726, 1794732743901, c)
    d2 = ri.next_difficulty(2165702, 1794732763475, 1794732755726, c)
    dl = ri.next_difficulty(2000000, 100000, 0, c)            # 100 s solve: clamped to 36 s
    dl_ref = ri.next_difficulty(2000000, 36000, 0, c)
    sup = ri.calc_supply(7905240, c)

    def bt9(dd):
        p = Path(dd) / 'config/config.go'
        p.write_text(p.read_text().replace('const BLOCK_TIME = uint64(18)', 'const BLOCK_TIME = uint64(9)'))
        q = Path(dd) / ANCH                        # the forged anchor names the forged line
        q.write_text(q.read_text().replace('const BLOCK_TIME = uint64(18)', 'const BLOCK_TIME = uint64(9)'))
    with forged_tree(over, bt9) as d:
        c9, _ = ri.constants(d)
    ok = (c['BaseReward'] == 123000 and c['RewardReductionInterval'] == 7000000 and c['MINIBLOCKS_PER_BLOCK'] == 10
          and c['NORMAL_MINIBLOCKS'] == 9 and c['FEE_PER_KB'] == 20 and c['MAJOR_HF3_HEIGHT'] == 7504640
          and r == {0: 61500, 6999999: 61500, 7000000: 30750, 7504640: 30750, 13999999: 30750, 14000000: 15375,
                    21000000: 7687}
          and sp0 == {'share': 3075, 'leftover': 0, 'integrator': 3075, 'normals': 9, 'credited': 30750}
          and sp1['share'] == 3078 and sp1['leftover'] == 7 and sp1['integrator'] == 3085 and sp1['credited'] == 30787
          and sp2['credited'] == 61500 - 6150
          and fees == [20, 20, 40, 60] and d1 == 2165702 and d2 == 2325314 and dl == dl_ref and dl < 2000000
          and sup == 1686733269600
          and c9['RewardReductionInterval'] == 14000000 and c9['BaseReward'] == 61500 and c9['MINIBLOCKS_PER_BLOCK'] == 1)
    return ok, c, r, sp1, fees, d1, d2, sup, c9.get('RewardReductionInterval')


class FakeRpc:
    def __init__(self, top=7905240, pruned=7498540, addr_pool=None, dev=FORGED_DEV):
        self.calls, self.log, self.top, self.pruned = 0, [], top, pruned
        self.pool = addr_pool or ([f'dero1qminer{i:02d}' + 'x' * 50 for i in range(12)] +
                                  [f'deto1qtest{i:02d}' + 'y' * 50 for i in range(3)])
        self.dev = dev

    def hdr(self, t, side=False):
        miners = [self.pool[(t + i) % len(self.pool)] for i in range(9)]
        if t % 7 == 0:
            miners[2] = 'unknown'
        miners.append(self.dev if t % 5 == 0 else self.pool[t % len(self.pool)])
        return {'height': t, 'topoheight': -1 if side else t, 'timestamp': 1794700000000 + (t - 7900000) * 18000,
                'difficulty': 2000000, 'txcount': 1 if t % 3 == 0 else 0, 'fees': 37 if t % 3 == 0 else 0,
                'reward': 30750, 'sideblock': side, 'orphan_status': side, 'miners': miners,
                'hash': ('a' if side else 'b') + f'{t:063d}', 'tips': [('b' + f'{t - 1:063d}')]}

    def mbls(self, t, side=False):
        out = [{'index': i, 'final': i == 9, 'highdiff': i == 9, 'keyhash': f'{(t + i) % 15:032x}',
                'timestamp16': (t * 10 + i) % 65536, 'flags': 0, 'ms_before_block': 9000 - i * 900,
                'miner': self.pool[(t + i) % len(self.pool)]} for i in range(10)]
        if side:
            out[0]['timestamp16'] += 1            # one normal miniblock the winning block does not carry
            out[9]['keyhash'] = 'ff' * 16
        return {'miniblocks': out, 'integrator': self.dev}

    def __call__(self, method, params=None):
        self.calls += 1
        self.log.append(method)
        if method == 'DERO.GetInfo':
            return {'topoheight': self.top, 'height': self.top, 'prunedheight': self.pruned, 'version': 'forged',
                    'total_supply': 16867332, 'alt_blocks_count': 2}
        if method == 'DERO.GetBlockHeadersRange':
            return {'headers': [self.hdr(t) for t in range(params['start_topoheight'], params['end_topoheight'] + 1)]}
        if method == 'DERO.GetMiniBlocks':
            if params.get('hash'):
                return self.mbls(int(params['hash'][1:]), side=True)
            return self.mbls(params['topoheight'])
        if method == 'DERO.GetConsensusStats':
            return {'alt_blocks': {'count': 2, 'settled': 100, 'tracked_from_height': self.top - 99, 'settle_depth': 8,
                                   'blocks': [{'hash': 'a' + f'{self.top - 20:063d}', 'height': self.top - 20,
                                               'local': False},
                                              {'hash': 'a' + f'{self.top - 10:063d}', 'height': self.top - 10,
                                               'local': True},
                                              {'hash': 'a' + f'{1000:063d}', 'height': 1000, 'local': False}]}}
        if method == 'DERO.GetBlockHeaderByHash':
            return {'block_header': self.hdr(int(params['hash'][1:]), side=True)}
        raise AssertionError(method)


def kat_gr3(over):
    ri = load(over)
    with forged_tree(over) as d:
        f0 = FakeRpc()
        code0, rec0 = ri.live(10, start=7498539, rpc=f0, root=d, out=Path(d) / 'o.json')
        f1 = FakeRpc(pruned=7600000)
        code1, rec1 = ri.live(10, start=7550000, rpc=f1, root=d, out=Path(d) / 'o.json')
        f2 = FakeRpc()
        code2, _ = ri.live(10, start=7498540, rpc=f2, root=d, out=Path(d) / 'o.json')
        wrote = (Path(d) / 'o.json').exists()
    f3 = FakeRpc()
    ri.Rpc = lambda *a, **k: f3                    # never the real node, even under a mutation
    with contextlib.redirect_stdout(io.StringIO()):
        code3 = ri.main(['--live', '--start', '7498539'])
    ok = (ri.PRUNED_FLOOR == 7498540 and ri.refuse_start(7498539) and not ri.refuse_start(7498540)
          and not ri.refuse_start(None) and code0 == 2 and f0.calls == 0 and code1 == 2 and f1.log == ['DERO.GetInfo']
          and code2 == 0 and wrote and 'DERO.GetBlockHeadersRange' in f2.log and code3 == 2 and f3.calls == 0)
    return ok, code0, f0.calls, code1, f1.log, code2, code3


def kat_gr4(over):
    ri = load(over)
    with forged_tree(over) as d:
        texts, recs = [], []
        for _ in range(2):
            f = FakeRpc()
            code, rec = ri.live(30, rpc=f, root=d, out=Path(d) / 'o.json')
            texts.append((Path(d) / 'o.json').read_text() if code == 0 else '')
            recs.append(rec)
    leaks = [t for t in texts if 'dero1' in t or 'deto1' in t]
    ps = [{b['integrator_pseudo'] for b in r.get('blocks', [])} for r in recs]
    refused = []
    for obj in ({'a': 'x deto1abc'}, {'deto1k': 1}, ['ok', ['dero1zz']]):
        try:
            ri.assert_private(obj)
            refused.append(False)
        except ValueError:
            refused.append(True)
    with tempfile.TemporaryDirectory() as d:
        try:
            ri.write_private(Path(d) / 'x.json', {'m': 'dero1abc'})
            wp = False
        except ValueError:
            wp = not (Path(d) / 'x.json').exists()
    salt_absent = all('salt' not in t for t in texts)
    ok = (len(leaks) == 0 and all(texts) and ps[0] and ps[1] and not (ps[0] & ps[1]) and all(refused) and wp
          and salt_absent and ri.pseudonym('dero1x', 's') != ri.pseudonym('dero1x', 't')
          and len(ri.pseudonym('dero1x', 's')) == 8)
    return ok, len(leaks), [len(p) for p in ps], refused, wp


def kat_gr5(over):
    ri = load(over)
    main = {'topoheight': 10, 'sideblock': False, 'tips': ['p']}
    side = {'topoheight': -1, 'sideblock': True, 'tips': ['p']}
    orph = {'topoheight': -1, 'sideblock': False, 'orphan_status': True, 'tips': ['p']}
    two = {'topoheight': 11, 'sideblock': False, 'tips': ['p', 'q']}
    got = [ri.classify_block(main, 'p'), ri.classify_block(side), ri.classify_block(orph), ri.classify_block(main, 'x'),
           ri.classify_block(two, 'p')]
    mk = lambda k, ts, fin=False: {'keyhash': k, 'timestamp16': ts, 'flags': 0, 'final': fin}
    alt = [mk('a', 1), mk('b', 2), mk('c', 3), mk('f', 9, True)]
    win = [mk('a', 1), mk('b', 2), mk('d', 4), mk('g', 9, True)]
    ov = ri.side_overlap(alt, win)
    ok = (got == [('main', True), ('side', None), ('orphan', None), ('main', False), ('main', False)] and ov == (3, 2))
    return ok, got, ov


def kat_gr6(over):
    ri = load(over)
    with forged_tree(over) as d:
        c, _ = ri.constants(d)
    salt = 's'
    dev_p = ri.pseudonym(FORGED_DEV, salt)
    f = FakeRpc()
    hs = [f.hdr(t) for t in (7900004, 7900005, 7900006)]
    recs = [ri.summarise_block(h, f.mbls(h['height']), salt, c, dev_p) for h in hs]
    agg = ri.aggregate(recs, c)
    r7 = recs[0]                                   # 7900004 % 7 == 0: one unknown slot; 7900005: dev, fees 37
    dc = ri.difficulty_check([{'height': 1, 'difficulty': 2000000, 'timestamp': 0},
                              {'height': 2, 'difficulty': 2000000, 'timestamp': 18000},
                              {'height': 3, 'difficulty': 2000000, 'timestamp': 30000},
                              {'height': 4, 'difficulty': 1, 'timestamp': 40000}], c)
    ok = (recs[1]['integrator_is_dev_default'] is True and recs[2]['integrator_is_dev_default'] is False
          and r7['unknown_normal_slots'] == 1 and r7['distinct_normal_miners'] == 8
          and recs[1]['distinct_normal_miners'] == 9 and recs[1]['mbl_finals'] == 1 and recs[1]['final_index'] == [9]
          and recs[1]['fees'] == 37 and recs[1]['split']['leftover'] == 7 and recs[1]['split']['integrator'] == 3085
          and agg['blocks'] == 3 and agg['class_counts'] == {'main': 3, 'side': 0, 'orphan': 0}
          and agg['integrator_dev_default_blocks'] == 1 and agg['block_interval_ms']['mean'] == 18000
          and agg['fees_total'] == 37 and agg['reward_match_all'] is True
          and dc['predicted'] == 2 and dc['match'] == 1 and dc['mismatch'] == 1)
    return ok, [(r['distinct_normal_miners'], r['unknown_normal_slots'], r['integrator_is_dev_default']) for r in recs], dc


def kat_gr7(over):
    ri = load(over)
    seen = []

    def opener(req):
        seen.append((req.get_method(), req.get_header('Content-type'), json.loads(req.data)['method'], time.monotonic()))
        return json.dumps({'result': {'ok': 1}}).encode()
    r = ri.Rpc(url='http://127.0.0.1:1/json_rpc', min_interval=0.05, opener=opener)
    for _ in range(3):
        r('DERO.GetInfo')
    gaps = [b[3] - a[3] for a, b in zip(seen, seen[1:])]
    ok = (r.calls == 3 and all(s[0] == 'POST' and s[1] == 'application/json' and s[2] == 'DERO.GetInfo' for s in seen)
          and all(g >= 0.045 for g in gaps) and ri.MIN_INTERVAL_S >= 0.2 and ri.RPC_URL.endswith(':10102/json_rpc'))
    return ok, [round(g, 3) for g in gaps]


KATS = [('GR1', kat_gr1), ('GR2', kat_gr2), ('GR3', kat_gr3), ('GR4', kat_gr4), ('GR5', kat_gr5), ('GR6', kat_gr6),
        ('GR7', kat_gr7)]
OWNERS = {'r32 anchors': ['GR1'], 'r32 formula': ['GR2'], 'r32 refusal': ['GR3'], 'r32 privacy': ['GR4'],
          'r32 sideblock': ['GR5'], 'r32 aggregate': ['GR6'], 'r32 rpc': ['GR7']}
MUTATIONS = [   # (file key, find, replace, why — the first two words name the defect, see OWNERS)
    ('ri', "    if 1 <= n <= len(lines) and a['quote'] in lines[n - 1]:", "    if True:",
     'r32 anchors: every anchor is OK whatever its line says'),
    ('ri', "    return ('MOVED', hits[0]) if hits else ('DRIFT', None)", "    return ('MOVED', hits[0]) if hits else ('MOVED', None)",
     'r32 anchors: a vanished quote is MOVED, not DRIFT'),
    ('ri', "    c['RewardReductionInterval'] = int(m.group(1)) * int(m.group(2)) // c['BLOCK_TIME']",
     "    c['RewardReductionInterval'] = 7000000", 'r32 formula: the halving interval is hard-coded, not read'),
    ('ri', "    return c['BaseReward'] >> ((h + rri) // rri)", "    return c['BaseReward'] >> (h // rri)",
     'r32 formula: the skipped first epoch is forgotten (reward doubled)'),
    ('ri', "'integrator': share + leftover,", "'integrator': share,", 'r32 formula: the leftover is not the integrator\'s'),
    ('ri', "    kb = size // 1024 + (1 if size % 1024 else 0)", "    kb = size // 1024",
     'r32 formula: a started KB is not charged'),
    ('ri', "    solve = min(tip_ts - parent_ts, 2 * bt)", "    solve = tip_ts - parent_ts",
     'r32 formula: the 2 x block-time solve clamp is gone'),
    ('ri', "    return start is not None and int(start) < floor", "    return start is not None and int(start) < floor - 1000",
     'r32 refusal: a start just below the pruned floor is read'),
    ('ri', "    if first < floor:\n        return EXIT_REFUSED", "    if False:\n        return EXIT_REFUSED",
     "r32 refusal: the node's own prunedheight is not respected"),
    ('ri', "    return hashlib.sha256((salt + str(addr)).encode()).hexdigest()[:8]", "    return str(addr)[:8]",
     'r32 privacy: the pseudonym is the address prefix'),
    ('ri', "ADDR_RX = re.compile(r'de[rt]o1')", "ADDR_RX = re.compile(r'dero1')",
     'r32 privacy: testnet deto1 addresses pass the scan'),
    ('ri', "        elif isinstance(o, str) and ADDR_RX.search(o):", "        elif False:",
     'r32 privacy: assert_private scans nothing'),
    ('ri', "    if hdr.get('sideblock'):\n        cls = 'side'", "    if False:\n        cls = 'side'",
     'r32 sideblock: a side block is classed orphan/main'),
    ('ri', "    return len(a), sum(1 for x in a if x in m)", "    return len(a), len(m)",
     'r32 sideblock: shared miniblocks are the winner\'s count'),
    ('ri', "'distinct_normal_miners': len({m for m in normal_slots if m != 'unknown'}),",
     "'distinct_normal_miners': len(set(normal_slots)),", "r32 aggregate: 'unknown' counts as a miner"),
    ('ri', "        if pred == int(b['difficulty']):", "        if True:", 'r32 aggregate: every difficulty matches'),
    ('ri', "        if wait > 0:\n            time.sleep(wait)", "        if False:\n            time.sleep(wait)",
     'r32 rpc: the request rate is unlimited'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_gr32', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def defect(why):
    return ' '.join(why.split(':')[0].split()[:2])


def run_kats(over):
    res = []
    for name, fn in KATS:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                ok, *det = fn(over)
        except (Exception, SystemExit) as e:                      # noqa: BLE001 — a crash is a failure
            ok, det = False, [f'{type(e).__name__}: {e}']
        res.append((name, bool(ok), str(det)))
    return res


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr32 gt-reward KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='gr32-mut-') as d:
            for rel in COPY_DIRS:
                shutil.copytree(ROOT / rel, Path(d) / rel, ignore=shutil.ignore_patterns('__pycache__'))
            (Path(d) / PATHS[key]).write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({'root': d}) if not ok]
        verdict, cpl = K.classify(failed, OWNERS.get(defect(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
        coupled += bool(cpl)
    print('\n' + K.summary('r32 gt-reward KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
