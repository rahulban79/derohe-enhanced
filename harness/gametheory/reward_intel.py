#!/usr/bin/env python3
"""reward_intel.py — r32: the DERO HE block-reward formulas, grounded in the Go source and measured on the live node.

  python3 -I harness/gametheory/reward_intel.py --check            # re-verify every anchor of reward_anchors.json
  python3 -I harness/gametheory/reward_intel.py --live [--n 60]    # sample the newest N blocks, read-only
  python3 -I harness/gametheory/reward_intel.py --json-only        # static constants + the last live summary

--check  each anchor's quote must be on its line (OK); somewhere else in the file is MOVED (the line number is stale,
         exit 0, listed); nowhere in the file is DRIFT (exit 4).
--live   reads the derod JSON-RPC at 127.0.0.1:10102 (DERO.GetInfo, DERO.GetBlockHeadersRange, DERO.GetMiniBlocks),
         READ-ONLY, at nice 15, at most 4 requests/s, never below topoheight PRUNED_FLOOR (7,498,540) nor below the
         node's own prunedheight: a request for one (--start) is refused with exit 2 before any connection. It never
         touches getwork (10100) or P2P (11011). Per block it computes the base reward from the CODE constants (parsed
         from the anchored lines, not hard-coded), the fees, the coinbase split, the miniblock / final / distinct-miner
         counts, the side-block class, timestamp deltas and the difficulty the code's formula predicts; for the node's
         settled alt (side) blocks (DERO.GetConsensusStats, DERO.GetBlockHeaderByHash, DERO.GetMiniBlocks by hash) it
         counts how many normal miniblocks the winning block at that height also carries; it writes
         harness/runtime/gt_reward_live.json with the anchor ids behind every number.
PRIVACY  the header miners[] and GetMiniBlocks miner fields carry addresses. They are reduced in memory to counts and
         to sha256(salt + address)[:8] pseudonyms; the salt is random per run and is never written. Before any file is
         written the whole record is scanned: a 'dero1' / 'deto1' substring aborts the write (exit 6).
Exit: 0 ok · 2 refused (below the pruned floor) · 3 node unreachable / RPC error · 4 anchor DRIFT · 6 privacy abort.
"""
import argparse, hashlib, json, math, os, re, secrets, sys, time, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
ANCHORS = 'harness/gametheory/reward_anchors.json'
OUT = 'harness/runtime/gt_reward_live.json'
RPC_URL = 'http://127.0.0.1:10102/json_rpc'
PRUNED_FLOOR = 7498540          # the node's prunedheight; nothing below is ever read
MIN_INTERVAL_S = 0.25           # <= 4 requests per second
RANGE_LIMIT = 100               # cmd/derod/rpc/rpc_dero_explorer.go MAX_HEADERS_RANGE
ADDR_RX = re.compile(r'de[rt]o1')
EXIT_REFUSED, EXIT_RPC, EXIT_DRIFT, EXIT_PRIVACY = 2, 3, 4, 6


# ─────────────────────────────────────────── anchors ───────────────────────────────────────────
def load_anchors(root=ROOT):
    return json.loads((Path(root) / ANCHORS).read_text(encoding='utf-8'))['anchors']


def check_anchor(root, a):
    """('OK'|'MOVED'|'DRIFT', line where the quote is). Pure over the file."""
    p = Path(root) / a['file']
    if not p.is_file():
        return 'DRIFT', None
    lines = p.read_text(encoding='utf-8').split('\n')
    n = int(a['line'])
    if 1 <= n <= len(lines) and a['quote'] in lines[n - 1]:
        return 'OK', n
    hits = [i + 1 for i, l in enumerate(lines) if a['quote'] in l]
    return ('MOVED', hits[0]) if hits else ('DRIFT', None)


def check(root=ROOT):
    res = [(a['id'], *check_anchor(root, a)) for a in load_anchors(root)]
    return res, (EXIT_DRIFT if any(s == 'DRIFT' for _, s, _ in res) else 0)


def anchor_line(root, aid):
    a = {x['id']: x for x in load_anchors(root)}[aid]
    st, ln = check_anchor(root, a)
    if st == 'DRIFT':
        raise LookupError(f'anchor {aid} drifted')
    return (Path(root) / a['file']).read_text(encoding='utf-8').split('\n')[ln - 1], f"{a['file']}:{ln}"


# ─────────────────────────────────────────── constants from the code ───────────────────────────
def _int(rx, line, aid):
    m = re.search(rx, line)
    if not m:
        raise ValueError(f'{aid}: constant not parseable from {line.strip()!r}')
    return m


def constants(root=ROOT):
    """The reward constants parsed from the anchored source lines (so a code change changes the formula). Pure."""
    c, src = {}, {}
    l, src['BLOCK_TIME'] = anchor_line(root, 'RW01')
    c['BLOCK_TIME'] = int(_int(r'uint64\((\d+)\)', l, 'RW01').group(1))
    l, src['MINIBLOCK_HIGHDIFF'] = anchor_line(root, 'RW03')
    c['MINIBLOCK_HIGHDIFF'] = int(_int(r'=\s*(\d+)', l, 'RW03').group(1))
    l, src['RewardReductionInterval'] = anchor_line(root, 'RW04')
    m = _int(r'=\s*(\d+)\s*\*\s*(\d+)\s*/\s*config\.BLOCK_TIME', l, 'RW04')
    c['RewardReductionInterval'] = int(m.group(1)) * int(m.group(2)) // c['BLOCK_TIME']
    l, src['BaseReward'] = anchor_line(root, 'RW05')
    m = _int(r'\((\d+)\s*\*\s*(\d+)\s*\*\s*config\.BLOCK_TIME\)\s*/\s*(\d+)', l, 'RW05')
    c['BaseReward'] = int(m.group(1)) * int(m.group(2)) * c['BLOCK_TIME'] // int(m.group(3))
    l, src['PREMINE'] = anchor_line(root, 'RW07')
    c['PREMINE'] = int(_int(r'=\s*(\d+)', l, 'RW07').group(1))
    l, src['REG_GRANTS'] = anchor_line(root, 'RW09')
    c['REG_GRANTS'] = int(_int(r'\+=\s*(\d+)', l, 'RW09').group(1))
    l, src['FEE_PER_KB'] = anchor_line(root, 'RW36')
    c['FEE_PER_KB'] = int(_int(r'uint64\((\d+)\)', l, 'RW36').group(1))
    l, src['DIFF_M'] = anchor_line(root, 'RW52')
    c['DIFF_M'] = int(_int(r'int64\((\d+)\)', l, 'RW52').group(1))
    l, src['HF3'] = anchor_line(root, 'RW49')
    c['MAJOR_HF3_HEIGHT'] = int(_int(r':\s*(\d+)', l, 'RW49').group(1))
    c['MINIBLOCKS_PER_BLOCK'] = c['BLOCK_TIME'] - c['MINIBLOCK_HIGHDIFF'] + 1          # RW19
    c['NORMAL_MINIBLOCKS'] = c['BLOCK_TIME'] - c['MINIBLOCK_HIGHDIFF']                  # RW21
    c['MAINNET_MINIMUM_DIFFICULTY'] = 100000   # config/config.go SettingsStruct envDefault (RW53 reads it)
    return c, src


def calc_block_reward(h, c):
    """RW06: BaseReward >> ((h + RRI) / RRI)."""
    rri = c['RewardReductionInterval']
    return c['BaseReward'] >> ((h + rri) // rri)


def calc_supply(h, c):
    """RW08-RW10 (blockchain/supply.go CalcSupply)."""
    s, rem, start = c['PREMINE'] + c['REG_GRANTS'], h, 0
    while rem > 0:
        n = min(c['RewardReductionInterval'], rem)
        s += calc_block_reward(start, c) * n
        rem -= n
        start += c['RewardReductionInterval']
    return s


def split(full_reward, n_miniblocks, n_finals=1):
    """RW13-RW18: the coinbase split of process_miner_transaction. Returns the integrator credit, the per-normal
    share and the total credited (== full_reward iff n_finals == 1)."""
    share = full_reward // n_miniblocks
    leftover = full_reward - share * n_miniblocks
    normals = n_miniblocks - n_finals
    return {'share': share, 'leftover': leftover, 'integrator': share + leftover, 'normals': normals,
            'credited': share + leftover + share * normals}


def min_fee(size, c):
    """RW37: ceil(size / 1024) * FEE_PER_KB."""
    kb = size // 1024 + (1 if size % 1024 else 0)
    return kb * c['FEE_PER_KB']


def next_difficulty(d_tip, tip_ts, parent_ts, c):
    """RW50-RW53 (Get_Difficulty_At_Tips / DiffBig). Python float pow may differ from Go math.Pow in the last ulp."""
    bt = c['BLOCK_TIME'] * 1000
    solve = min(tip_ts - parent_ts, 2 * bt)
    if solve <= 0:
        return None
    easy = int(math.pow(2.71828182845905, (1 - solve / bt) / c['DIFF_M']) * 10000)
    return max(d_tip * easy // 10000, c['MAINNET_MINIMUM_DIFFICULTY'])


def classify_block(hdr, prev_hash=None):
    """the side-block class of one header (RW31-RW35): 'side' if sideblock, 'orphan' if it has no topo order,
    'main' otherwise; plus whether tips[0] links to the previous topo block (a chain: 1 tip, RW33)."""
    if hdr.get('sideblock'):
        cls = 'side'
    elif int(hdr.get('topoheight', -1)) < 0 or hdr.get('orphan_status'):
        cls = 'orphan'
    else:
        cls = 'main'
    tips = hdr.get('tips') or []
    link = None if prev_hash is None else (len(tips) == 1 and tips[0] == prev_hash)
    return cls, link


# ─────────────────────────────────────────── privacy ───────────────────────────────────────────
def pseudonym(addr, salt):
    return hashlib.sha256((salt + str(addr)).encode()).hexdigest()[:8]


def assert_private(obj):
    """raise ValueError if any string (key or value) of obj contains an address prefix."""
    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                walk(k)
                walk(v)
        elif isinstance(o, (list, tuple)):
            for v in o:
                walk(v)
        elif isinstance(o, str) and ADDR_RX.search(o):
            raise ValueError('privacy: an address-like string reached the output')
    walk(obj)
    return obj


def write_private(path, obj):
    text = json.dumps(assert_private(obj), indent=1, sort_keys=True)
    if ADDR_RX.search(text):
        raise ValueError('privacy: an address-like string reached the output')
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(text + '\n', encoding='utf-8')


# ─────────────────────────────────────────── live sampler ──────────────────────────────────────
class Rpc:
    def __init__(self, url=RPC_URL, min_interval=MIN_INTERVAL_S, opener=None):
        self.url, self.min_interval, self.last, self.calls = url, min_interval, 0.0, 0
        self.opener = opener or (lambda req: urllib.request.urlopen(req, timeout=20).read())

    def __call__(self, method, params=None):
        wait = self.last + self.min_interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        body = {'jsonrpc': '2.0', 'id': self.calls + 1, 'method': method}
        if params is not None:
            body['params'] = params
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(), method='POST',
                                     headers={'Content-Type': 'application/json'})
        self.last = time.monotonic()
        self.calls += 1
        r = json.loads(self.opener(req))
        if r.get('error'):
            raise RuntimeError(f"{method}: {r['error'].get('message')}")
        return r['result']


def refuse_start(start, floor=PRUNED_FLOOR):
    """True when a sample would start below the pruned floor (the caller exits 2 before reading)."""
    return start is not None and int(start) < floor


def summarise_block(hdr, mbl, salt, c, dev_pseudo):
    """one block's record. Addresses are reduced to counts / pseudonyms here and never leave this function."""
    h = int(hdr['height'])
    fees = hdr.get('fees')
    base = calc_block_reward(h, c)
    full = None if fees is None else base + int(fees)
    sp = None if full is None else split(full, c['MINIBLOCKS_PER_BLOCK'])
    miners = list(hdr.get('miners') or [])
    n_slots = len(miners)
    normal_slots = miners[:c['NORMAL_MINIBLOCKS']]
    integ = miners[-1] if n_slots == c['MINIBLOCKS_PER_BLOCK'] else None
    rec = {'height': h, 'topoheight': int(hdr['topoheight']), 'timestamp_ms': int(hdr['timestamp']),
           'difficulty': int(hdr['difficulty']), 'txcount': int(hdr.get('txcount', 0)),
           'reward_rpc': int(hdr['reward']), 'reward_formula': base, 'reward_match': int(hdr['reward']) == base,
           'fees': fees, 'full_reward': full, 'split': sp,
           'miners_slots': n_slots,
           'distinct_normal_miners': len({m for m in normal_slots if m != 'unknown'}),
           'unknown_normal_slots': sum(1 for m in normal_slots if m == 'unknown'),
           'integrator_pseudo': None if integ is None else pseudonym(integ, salt),
           'integrator_is_dev_default': None if integ is None else pseudonym(integ, salt) == dev_pseudo,
           'integrator_also_normal_miner': None if integ is None else integ in normal_slots,
           'normal_pseudos': [pseudonym(m, salt) for m in normal_slots if m != 'unknown']}
    rec['class'], _ = classify_block(hdr)
    if mbl is not None:
        mb = mbl.get('miniblocks') or []
        rec['mbl_count'] = len(mb)
        rec['mbl_finals'] = sum(1 for x in mb if x.get('final'))
        rec['mbl_highdiff'] = sum(1 for x in mb if x.get('highdiff'))
        rec['final_index'] = [x.get('index') for x in mb if x.get('final')]
        before = [x.get('ms_before_block') for x in mb if not x.get('final') and x.get('ms_before_block') is not None]
        rec['normal_ms_before_block_max'] = max(before) if before else None   # first normal -> block
        rec['normal_ms_before_block_min'] = min(before) if before else None   # 9th normal -> block = final phase
        fin = [x.get('ms_before_block') for x in mb if x.get('final')]
        rec['final_ms_before_block'] = fin[0] if fin else None
    return rec


def aggregate(recs, c):
    n = len(recs)
    if not n:
        return {}
    ts = [r['timestamp_ms'] for r in recs]
    dts = [b - a for a, b in zip(ts, ts[1:])]
    feeful = [r for r in recs if r['fees'] is not None]
    pseudo_count = {}
    for r in recs:
        for p in r['normal_pseudos']:
            pseudo_count[p] = pseudo_count.get(p, 0) + 1
    top = sorted(pseudo_count.values(), reverse=True)
    total_normals = sum(top)
    dsorted = sorted(dts)
    agg = {
        'blocks': n, 'height_first': recs[0]['height'], 'height_last': recs[-1]['height'],
        'reward_match_all': all(r['reward_match'] for r in recs),
        'reward_formula_values': sorted({r['reward_formula'] for r in recs}),
        'class_counts': {k: sum(1 for r in recs if r['class'] == k) for k in ('main', 'side', 'orphan')},
        'blocks_with_10_slots': sum(1 for r in recs if r['miners_slots'] == c['MINIBLOCKS_PER_BLOCK']),
        'fees_total': sum(int(r['fees']) for r in feeful), 'fees_known_blocks': len(feeful),
        'blocks_with_fees': sum(1 for r in feeful if int(r['fees']) > 0),
        'fees_max': max((int(r['fees']) for r in feeful), default=None),
        'fee_share_of_rewards': (round(sum(int(r['fees']) for r in feeful) / sum(r['full_reward'] for r in feeful), 6)
                                 if feeful else None),
        'txcount_total': sum(r['txcount'] for r in recs),
        'leftover_total': sum(r['split']['leftover'] for r in feeful),
        'integrator_dev_default_blocks': sum(1 for r in recs if r['integrator_is_dev_default']),
        'integrator_distinct': len({r['integrator_pseudo'] for r in recs if r['integrator_pseudo']}),
        'integrator_also_normal_miner_blocks': sum(1 for r in recs if r['integrator_also_normal_miner']),
        'distinct_normal_miners_mean': round(sum(r['distinct_normal_miners'] for r in recs) / n, 3),
        'distinct_normal_miners_min': min(r['distinct_normal_miners'] for r in recs),
        'distinct_normal_miners_max': max(r['distinct_normal_miners'] for r in recs),
        'unknown_normal_slots_total': sum(r['unknown_normal_slots'] for r in recs),
        'distinct_miners_in_sample': len(pseudo_count),
        'top1_miniblock_share': round(top[0] / total_normals, 4) if top else None,
        'top5_miniblock_share': round(sum(top[:5]) / total_normals, 4) if top else None,
        'miners_with_one_miniblock': sum(1 for v in top if v == 1),
        'block_interval_ms': {'n': len(dts), 'mean': round(sum(dts) / len(dts), 1) if dts else None,
                              'min': min(dts) if dts else None, 'max': max(dts) if dts else None,
                              'median': dsorted[len(dsorted) // 2] if dsorted else None},
    }
    with_mbl = [r for r in recs if 'mbl_count' in r]
    if with_mbl:
        agg['mbl_blocks_read'] = len(with_mbl)
        agg['mbl_count_values'] = sorted({r['mbl_count'] for r in with_mbl})
        agg['mbl_finals_values'] = sorted({r['mbl_finals'] for r in with_mbl})
        agg['final_index_values'] = sorted({tuple(r['final_index']) for r in with_mbl})
        fm = [r['final_ms_before_block'] for r in with_mbl if r['final_ms_before_block'] is not None]
        agg['final_ms_before_block_mean'] = round(sum(fm) / len(fm), 1) if fm else None
        fp = [r['normal_ms_before_block_min'] for r in with_mbl if r['normal_ms_before_block_min'] is not None]
        rp = [r['normal_ms_before_block_max'] - r['normal_ms_before_block_min'] for r in with_mbl
              if r['normal_ms_before_block_min'] is not None]
        agg['final_phase_ms_mean'] = round(sum(fp) / len(fp), 1) if fp else None      # 9th normal -> final (block)
        agg['normal_span_ms_mean'] = round(sum(rp) / len(rp), 1) if rp else None      # 1st -> 9th normal miniblock
    return agg


def difficulty_check(hdrs, c):
    """predict each block's difficulty from its two predecessors (RW50-RW53) and count matches."""
    ok = bad = 0
    worst = []
    for p2, p1, b in zip(hdrs, hdrs[1:], hdrs[2:]):
        pred = next_difficulty(int(p1['difficulty']), int(p1['timestamp']), int(p2['timestamp']), c)
        if pred is None:
            continue
        if pred == int(b['difficulty']):
            ok += 1
        else:
            bad += 1
            worst.append({'height': int(b['height']), 'predicted': pred, 'observed': int(b['difficulty'])})
    return {'predicted': ok + bad, 'match': ok, 'mismatch': bad, 'mismatches': worst[:5]}


def mbl_identity(x):
    """a miniblock's identity inside one run (in memory only; never written): key hash, 16-bit stamp, flags."""
    return (x.get('keyhash'), x.get('timestamp16'), x.get('flags'), bool(x.get('final')))


def side_overlap(alt_mbls, main_mbls):
    """(normal miniblocks of the alt block, of those also carried by the main block at the same height). Pure."""
    a = [mbl_identity(x) for x in alt_mbls if not x.get('final')]
    m = {mbl_identity(x) for x in main_mbls if not x.get('final')}
    return len(a), sum(1 for x in a if x in m)


def alt_sample(rpc, floor, limit=64):
    """the node's settled alt (side) blocks (GetConsensusStats, CO24-C4): each one's header class (RW34/RW55) and how
    many of its normal miniblocks the winning block at that height also carries (the rest earned nothing, RW31/RW32).
    Heights below the floor are skipped, never read."""
    st = rpc('DERO.GetConsensusStats')
    alt = st.get('alt_blocks') or {}
    blocks = [b for b in (alt.get('blocks') or []) if int(b.get('height', -1)) >= floor][-limit:]
    out = []
    for b in blocks:
        hdr = rpc('DERO.GetBlockHeaderByHash', {'hash': b['hash']})['block_header']
        cls, _ = classify_block(hdr)
        am = rpc('DERO.GetMiniBlocks', {'hash': b['hash']}).get('miniblocks') or []
        mm = rpc('DERO.GetMiniBlocks', {'topoheight': int(b['height'])}).get('miniblocks') or []
        n_norm, shared = side_overlap(am, mm)
        out.append({'height': int(b['height']), 'class': cls, 'topoheight': int(hdr.get('topoheight', -1)),
                    'reward_field': int(hdr.get('reward', 0)), 'local': bool(b.get('local')),
                    'normal_miniblocks': n_norm, 'shared_with_main': shared, 'lost_normal_miniblocks': n_norm - shared,
                    'alt_final_is_main_final': any(mbl_identity(x) in {mbl_identity(y) for y in mm}
                                                   for x in am if x.get('final'))})
    summ = {'settled': alt.get('settled'), 'count': alt.get('count'), 'tracked_from_height': alt.get('tracked_from_height'),
            'settle_depth': alt.get('settle_depth'),
            'alt_rate': round(alt['count'] / alt['settled'], 5) if alt.get('settled') else None,
            'sampled': len(out), 'class_counts': {k: sum(1 for r in out if r['class'] == k) for k in ('main', 'side', 'orphan')},
            'normal_miniblocks': sum(r['normal_miniblocks'] for r in out),
            'shared_with_main': sum(r['shared_with_main'] for r in out),
            'lost_normal_miniblocks': sum(r['lost_normal_miniblocks'] for r in out),
            'anchors': ['RW31', 'RW32', 'RW34', 'RW35', 'RW55', 'RW22']}
    return summ, out


def live(n, start=None, rpc=None, root=ROOT, out=None, with_mbl=True, with_alt=True):
    c, src = constants(root)
    if refuse_start(start):
        return EXIT_REFUSED, {'refused': f'start {start} < pruned floor {PRUNED_FLOOR}'}
    try:
        cur = os.nice(0)
        if cur < 15:
            os.nice(15 - cur)                 # run at nice 15 (only this process; never another)
    except OSError:
        pass
    rpc = rpc or Rpc()
    try:
        info = rpc('DERO.GetInfo')
    except Exception as e:  # noqa: BLE001
        return EXIT_RPC, {'error': f'GetInfo: {type(e).__name__}: {e}'}
    floor = max(PRUNED_FLOOR, int(info.get('prunedheight') or 0))
    top = int(info['topoheight'])
    first = top - n + 1 if start is None else int(start)
    if first < floor:
        return EXIT_REFUSED, {'refused': f'start {first} < pruned floor {floor}'}
    fetch_from = max(first - 2, floor)        # two predecessors for the difficulty prediction
    last = min(first + n - 1, top)
    salt = secrets.token_hex(16)              # per run, never written
    # Dev_Address default integrator (config, RW27): compared as a pseudonym only
    cfg = (Path(root) / 'config/config.go').read_text(encoding='utf-8')
    m = re.search(r'Dev_Address:\s*"([^"]+)"', cfg)
    dev_pseudo = pseudonym(m.group(1), salt) if m else None
    hdrs = []
    try:
        for s in range(fetch_from, last + 1, RANGE_LIMIT):
            e = min(s + RANGE_LIMIT - 1, last)
            hdrs += rpc('DERO.GetBlockHeadersRange', {'start_topoheight': s, 'end_topoheight': e})['headers']
        t_headers = time.time()               # tip age is taken when the headers arrived, not after the slow reads
        sample = [h for h in hdrs if int(h['topoheight']) >= first]
        recs, prev = [], None
        for h in sample:
            mbl = rpc('DERO.GetMiniBlocks', {'topoheight': int(h['topoheight'])}) if with_mbl else None
            r = summarise_block(h, mbl, salt, c, dev_pseudo)
            _, r['tip_links_previous'] = classify_block(h, prev)
            prev = h['hash']
            recs.append(r)
        alt_summary, alt_blocks = alt_sample(rpc, floor) if with_alt else (None, [])
        info2 = rpc('DERO.GetInfo')
    except Exception as e:  # noqa: BLE001
        return EXIT_RPC, {'error': f'{type(e).__name__}: {e}'}
    agg = aggregate(recs, c)
    agg['tip_links_previous_all'] = all(r['tip_links_previous'] in (None, True) for r in recs)
    agg['difficulty_prediction'] = difficulty_check(hdrs, c)
    sup_formula = calc_supply(top, c)
    tip_age_s = round(t_headers - recs[-1]['timestamp_ms'] / 1000, 1) if recs else None
    for r in recs:                            # pseudonyms are per-run; drop the per-slot list, keep the counts
        r.pop('normal_pseudos', None)
    rec = {
        '_doc': 'r32 live reward sample (reward_intel.py --live). Counts and per-run pseudonyms only; no address. '
                'Each number names the anchor ids (harness/gametheory/reward_anchors.json) of the formula behind it.',
        'measured_at_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'node_version': info.get('version'), 'topoheight': top, 'height': int(info['height']),
        'prunedheight': int(info.get('prunedheight') or 0), 'floor_used': floor, 'tip_block_age_s': tip_age_s,
        'alt_blocks_count_start': info.get('alt_blocks_count'), 'alt_blocks_count_end': info2.get('alt_blocks_count'),
        'rpc_calls': rpc.calls, 'sample_first_topo': first, 'sample_last_topo': last,
        'constants': c, 'constant_sources': src,
        'supply': {'formula_atomic': sup_formula, 'formula_dero': sup_formula // 100000,
                   'getinfo_total_supply': info.get('total_supply'),
                   'match': info.get('total_supply') == sup_formula // 100000,
                   'anchors': ['RW07', 'RW08', 'RW09', 'RW10', 'RW58']},
        'aggregate': agg,
        'side_blocks': {'summary': alt_summary, 'blocks': alt_blocks},
        'anchors_per_number': {
            'reward_formula': ['RW04', 'RW05', 'RW06'], 'reward_rpc': ['RW54'], 'fees': ['RW30', 'RW39'],
            'full_reward': ['RW13'], 'split.share': ['RW14'], 'split.leftover': ['RW15'],
            'split.integrator': ['RW16', 'RW17'], 'miners_slots': ['RW19', 'RW21'],
            'distinct_normal_miners': ['RW18', 'RW29'], 'integrator_is_dev_default': ['RW26', 'RW27'],
            'class': ['RW31', 'RW33', 'RW34', 'RW35', 'RW55'], 'mbl_finals': ['RW20', 'RW21', 'RW23'],
            'difficulty_prediction': ['RW50', 'RW50b', 'RW51', 'RW52', 'RW53'],
            'block_interval_ms': ['RW01', 'RW02']},
        'blocks': recs,
    }
    try:
        write_private(Path(root) / OUT if out is None else out, rec)
    except ValueError as e:
        return EXIT_PRIVACY, {'error': str(e)}
    return 0, rec


def json_only(root=ROOT):
    c, src = constants(root)
    res, code = check(root)
    last = None
    p = Path(root) / OUT
    if p.is_file():
        d = json.loads(p.read_text(encoding='utf-8'))
        last = {k: d.get(k) for k in ('measured_at_utc', 'node_version', 'topoheight', 'tip_block_age_s', 'supply',
                                      'aggregate')}
    return code, {'constants': c, 'constant_sources': src,
                  'reward_at': {str(h): calc_block_reward(h, c) for h in (0, 6999999, 7000000, 7504640, 13999999, 14000000)},
                  'split_example_fees0_h7900000': split(calc_block_reward(7900000, c), c['MINIBLOCKS_PER_BLOCK']),
                  'anchors': {s: sum(1 for _, x, _ in res if x == s) for s in ('OK', 'MOVED', 'DRIFT')},
                  'last_live': last}


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--live', action='store_true')
    ap.add_argument('--json-only', action='store_true')
    ap.add_argument('--n', type=int, default=60)
    ap.add_argument('--start', type=int, default=None, help='first topoheight (default: top - n + 1)')
    ap.add_argument('--no-mbl', action='store_true', help='skip the per-block DERO.GetMiniBlocks reads')
    ap.add_argument('--out', default=None, help=f'repo-relative output under harness/runtime/ (default {OUT})')
    a = ap.parse_args(argv)
    if a.check:
        res, code = check()
        for aid, st, ln in res:
            if st != 'OK':
                print(f'{st:<5} {aid} (found at line {ln})')
        print(f"anchors: {sum(s == 'OK' for _, s, _ in res)} OK · {sum(s == 'MOVED' for _, s, _ in res)} MOVED · "
              f"{sum(s == 'DRIFT' for _, s, _ in res)} DRIFT of {len(res)}")
        return code
    if a.live:
        if refuse_start(a.start):
            print(f'refused: start {a.start} is below the pruned floor {PRUNED_FLOOR}')
            return EXIT_REFUSED
        if not 1 <= a.n <= 2000:
            print('refused: --n must be 1..2000')
            return EXIT_REFUSED
        out = None
        if a.out:
            if not a.out.startswith('harness/runtime/') or '..' in a.out:
                print('refused: --out must be under harness/runtime/')
                return EXIT_REFUSED
            out = ROOT / a.out
        code, rec = live(a.n, a.start, with_mbl=not a.no_mbl, out=out)
        if code:
            print(json.dumps(rec))
            return code
        g = rec['aggregate']
        print(json.dumps({'topoheight': rec['topoheight'], 'tip_block_age_s': rec['tip_block_age_s'],
                          'blocks': g['blocks'], 'reward_match_all': g['reward_match_all'],
                          'reward_formula_values': g['reward_formula_values'], 'class_counts': g['class_counts'],
                          'fees_total': g['fees_total'], 'difficulty_prediction': g['difficulty_prediction'],
                          'supply_match': rec['supply']['match'],
                          'side_blocks': (rec['side_blocks']['summary'] or {}), 'rpc_calls': rec['rpc_calls'], 'out': a.out or OUT}))
        return 0
    if a.json_only:
        code, d = json_only()
        out = Path(ROOT) / 'harness/runtime/gt_reward_static.json'
        try:
            write_private(out, d)
        except ValueError as e:
            print(str(e))
            return EXIT_PRIVACY
        print(json.dumps({'out': 'harness/runtime/gt_reward_static.json', 'anchors': d['anchors']}))
        return code
    ap.print_help()
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
