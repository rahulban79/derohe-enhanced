#!/usr/bin/env python3
"""payout_census.py — (r23c payouts) where our found shares went: the payout loss budget BY MECHANISM, from the chain.

miner_runs.py says how many of a run's shares were paid. This tool says WHY the others were not, so a lever is chosen by
the loss it can remove (ARCHITECTURE §41). It reads, READ-ONLY:
  - the miner log's found lines ('found DERO miniblock': height, job difficulty, likely_stale, CPU or GPU path),
  - DERO.GetMiningOutcome (to learn our miniblock KeyHash, as miner_runs.learn_keyhash does),
  - DERO.GetBlock for every height we found a share at (json: miniblocks with KeyHash and the uint16 job Timestamp;
    block_header: miners, timestamp, difficulty).

A found share is FINAL when its job difficulty is >= 2x the block's difficulty (a final job is 9x, MINIBLOCK_HIGHDIFF).
Per height, our paid regular shares = min(found regular, our KeyHash among the block's normal miniblocks); a final is
paid when the block's final miniblock is ours (same miners-list string as our normal miniblocks' entries).

Loss classes (each lost share in exactly one):
  regular/stale_flagged  the miner already held a newer job that made the share an orphan (likely_stale=true): work
                         in flight at the height change or the normal->final flip (miner pipeline depth)
  regular/slot_race      not flagged, and every one of the block's 9 normal miniblocks had its JOB created before
                         our find (uint16 ms, finders' clocks): the builder held 9 before ours could arrive. Node-side
                         this is p2p delivery latency in both directions (ours out, the 9th in)
  regular/other          neither (clock skew, or a share that never reached the builder)
  final/lost_race        a competing block won the height; margin_ms = our find - the winning block's timestamp
                         (its TEMPLATE time). margin <= 0 ('propagation'): we found before the winner's template
                         existed, so our block lost a propagation race. margin > 0 ('after_winner') is only a timing
                         class: the winner's template predates our find, NOT its arrival. r23c verify: of the 5 live
                         margin > 0 losses, our node held OUR block first in 3 (the competitor arrived 103-564 ms
                         later, derod log 'Chain extended but height is same') and the competitor had the lower BLID
                         in 4 (same-height ties go to the lower BLID, blockchain/miner_block.go sort_descending_by_
                         height_blid). Attribute inbound vs outbound only from the derod log's arrival order.
Near misses: paid regular shares that were the block's 9th (every OTHER normal miniblock's job was created before our
find), the latest of those at most W ms before it: the population a latency change moves.

Never writes the wallet address, the KeyHash or a builder's address: builders are B00, B01, ... in order of first sight.
  python3 -I harness/intel/payout_census.py [--log bin/dero-miner.log] [--rpc URL] [--out f.json] [--since ISO]
Exit 0 · 2 no found lines · 7 no KeyHash could be learned (no paid regular share in derod's memory).
"""
import argparse, collections, datetime, importlib.util, json, re, sys, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent
ROOT = HARNESS.parent
RPC = 'http://127.0.0.1:10102/json_rpc'
FOUND_M = re.compile(r'found DERO (?:mini)?block')
FINAL_DIFF_RATIO = 2           # a final job is 9x the block difficulty; regular jobs sit at ~1x
NEAR_MISS_MS = (50, 100, 200, 500)
U16 = 65536


def _mr():
    spec = importlib.util.spec_from_file_location(f'miner_runs_for_census_{id(HERE)}', HERE / 'miner_runs.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def ms_of(t):
    """the log's '2026-10-28T08:33:11.067-0700' -> epoch ms"""
    return int(round(datetime.datetime.fromisoformat(t).timestamp() * 1000))


def parse_found(lines, since_ms=None):
    """found shares from miner-log lines: [{'ms', 'h', 'diff', 'stale', 'gpu'}] (unparsable lines skipped)"""
    out = []
    for l in lines:
        if 'found DERO' not in l:
            continue
        try:
            d = json.loads(l)
            if not FOUND_M.search(str(d.get('M', ''))):
                continue
            r = {'ms': ms_of(d['T']), 'h': int(d['height']), 'diff': int(d['difficulty']), 'stale': d.get('likely_stale'),
                 'gpu': 'GPU' in str(d.get('M'))}
        except (ValueError, KeyError, TypeError):
            continue
        if since_ms is None or r['ms'] >= since_ms:
            out.append(r)
    return out


def u16_delta(a_ms, b_u16):
    """a (epoch ms) - b (uint16 ms) in [-32768, 32767]: the nearest unwrap"""
    return ((a_ms % U16 - b_u16 + 32768) % U16) - 32768


def classify(found, census, near_ms=NEAR_MISS_MS):
    """found: parse_found rows; census: {height: {'diff', 'ours_normal', 'final_ours', 'ts', 'mbl_ts', 'builder'}}
    where mbl_ts lists the block's miniblock job Timestamps in block order (the final last) and ours_idx the positions of
    our normal miniblocks in it. Returns the loss budget."""
    byh = collections.defaultdict(list)
    for r in found:
        byh[r['h']].append(r)
    c = collections.Counter()
    lost_final, near, race = [], collections.Counter(), []
    lost_by_builder = collections.Counter()
    for h, rs in sorted(byh.items()):
        b = census.get(h)
        if not b or 'err' in b:
            c['unknown_height'] += len(rs)
            continue
        reg = sorted((r for r in rs if r['diff'] < FINAL_DIFF_RATIO * b['diff']), key=lambda r: r['ms'])
        fin = [r for r in rs if r['diff'] >= FINAL_DIFF_RATIO * b['diff']]
        c['found_regular'] += len(reg)
        c['found_final'] += len(fin)
        paid = min(len(reg), b['ours_normal'])
        c['paid_regular'] += paid
        normal_ts = (b.get('mbl_ts') or [])[:-1]
        mine = set(b.get('ours_idx') or [])
        other_ts = [t for j, t in enumerate(normal_ts) if j not in mine]
        for i, r in enumerate(reg):
            before = [u16_delta(r['ms'], t) for t in normal_ts]
            if i < paid:
                # a near miss: every OTHER normal miniblock of the block had its job before our find (we were the 9th),
                # the latest of them at most W ms before it
                od = [u16_delta(r['ms'], t) for t in other_ts]
                if od and all(d > 0 for d in od):
                    for w in near_ms:
                        if min(od) <= w:
                            near[w] += 1
                continue
            lost_by_builder[b.get('builder')] += 1
            if r['stale']:
                c['lost_regular_stale_flagged'] += 1
            elif normal_ts and all(d > 0 for d in before):
                c['lost_regular_slot_race'] += 1
                race.append(min(before))  # how long after the block's latest normal job we found
            else:
                c['lost_regular_other'] += 1
        for k, r in enumerate(fin):
            if b['final_ours'] and k == 0:
                c['paid_final'] += 1
                continue
            m = r['ms'] - b['ts']
            lost_final.append({'h': h, 'margin_ms': m, 'stale': r['stale'], 'builder': b.get('builder')})
            c['lost_final_after_winner' if m > 0 else 'lost_final_propagation'] += 1
    fr, ff = c['found_regular'], c['found_final']
    tot = fr + ff
    out = {'counts': dict(c), 'lost_final': lost_final,
           'paid_fraction': round((c['paid_regular'] + c['paid_final']) / tot, 4) if tot else None,
           'regular_paid_fraction': round(c['paid_regular'] / fr, 4) if fr else None,
           'final_paid_fraction': round(c['paid_final'] / ff, 4) if ff else None,
           'near_miss_paid': {str(w): near[w] for w in near_ms},
           'slot_race_late_ms': sorted(race),
           'slot_race_within': {str(w): sum(1 for x in race if x <= w) for w in near_ms},
           'lost_by_builder': dict(lost_by_builder.most_common()),
           'final_to_regular_found': round(ff / fr, 4) if fr else None}
    bl = collections.Counter(v.get('builder') for v in census.values() if 'err' not in v)
    n = sum(bl.values())
    out['builder_share'] = {k: round(v / n, 3) for k, v in bl.most_common(8)} if n else {}
    return out


def anonymise(addresses, ours):
    """address -> 'us' or B00, B01 ... in order of first sight (never written)"""
    ids = {}
    return [('us' if a == ours else ids.setdefault(a, 'B%02d' % len(ids))) for a in addresses]


def rpc_call(url, method, params=None):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, **({'params': params} if params else {})}).encode()
    with urllib.request.urlopen(urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'}),
                                timeout=10) as r:
        return json.loads(r.read()).get('result')


def live_census(heights, url, keyhash):
    """READ-ONLY GetBlock per height (DERO.GetBlock 'height' is a TOPOheight: a block whose height differs is an error
    row, never guessed). Our miners-list string is learned in memory from a block that carries our KeyHash."""
    raw = {}
    for h in heights:
        try:
            res = rpc_call(url, 'DERO.GetBlock', {'height': h}) or {}
            bh, js = res.get('block_header') or {}, json.loads(res.get('json') or '{}')
        except Exception as e:                                       # noqa: BLE001 — recorded, never fatal
            raw[h] = {'err': type(e).__name__}
            continue
        if int(bh.get('height', -1)) != h:
            raw[h] = {'err': 'topoheight != height'}
            continue
        raw[h] = {'bh': bh, 'mbls': js.get('miniblocks') or []}
    ours = None
    for v in raw.values():
        for i, m in enumerate(v.get('mbls') or []):
            if not m.get('Final') and str(m.get('KeyHash', ''))[:32] == keyhash and i < len(v['bh'].get('miners') or []):
                ours = v['bh']['miners'][i]
                break
        if ours:
            break
    finals = [v['bh']['miners'][-1] if v.get('bh') and v['bh'].get('miners') else None for v in raw.values()]
    names = dict(zip(list(raw), anonymise(finals, ours)))
    out = {}
    for h, v in raw.items():
        if 'err' in v:
            out[h] = v
            continue
        mb = v['mbls']
        out[h] = {'diff': int(v['bh']['difficulty']), 'ts': int(v['bh']['timestamp']),
                  'ours_normal': sum(1 for m in mb if not m.get('Final') and str(m.get('KeyHash', ''))[:32] == keyhash),
                  'final_ours': ours is not None and (v['bh'].get('miners') or [None])[-1] == ours,
                  'ours_idx': [j for j, m in enumerate(mb) if not m.get('Final') and str(m.get('KeyHash', ''))[:32] == keyhash],
                  'mbl_ts': [int(m.get('Timestamp', 0)) for m in mb], 'builder': names[h]}
    return out, ours is not None


def facts(rep):
    c = rep['counts']
    f = [f"payout census found_regular={c.get('found_regular', 0)} paid_regular={c.get('paid_regular', 0)} "
         f"found_final={c.get('found_final', 0)} paid_final={c.get('paid_final', 0)} paid_fraction={rep['paid_fraction']} "
         f"regular_paid_fraction={rep['regular_paid_fraction']} final_paid_fraction={rep['final_paid_fraction']}",
         f"payout census lost regular: stale_flagged={c.get('lost_regular_stale_flagged', 0)} "
         f"slot_race={c.get('lost_regular_slot_race', 0)} other={c.get('lost_regular_other', 0)}; lost final: "
         f"after_winner_template={c.get('lost_final_after_winner', 0)} propagation={c.get('lost_final_propagation', 0)}",
         'payout census near-miss paid (latest other block-normal job <= W ms before our find): ' +
         ' '.join(f'W{k}={v}' for k, v in rep['near_miss_paid'].items()),
         'payout census slot-race losses found <= W ms after the block\'s latest normal job: ' +
         ' '.join(f'W{k}={v}' for k, v in rep['slot_race_within'].items()),
         'payout census lost-final margins ms (our find - winning block TEMPLATE time, not its arrival): ' +
         ' '.join(str(x['margin_ms']) for x in rep['lost_final']),
         'payout census builder share over our heights: ' + ' '.join(f'{k}={v}' for k, v in rep['builder_share'].items())]
    return f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--log', default=str(ROOT / 'bin/dero-miner.log'))
    ap.add_argument('--rpc', default=RPC)
    ap.add_argument('--since', help='ISO time: only shares found at or after it')
    ap.add_argument('--out')
    a = ap.parse_args()
    since = ms_of(a.since) if a.since else None
    found = parse_found(Path(a.log).read_text(errors='replace').splitlines() if Path(a.log).exists() else [], since)
    if not found:
        print('payout_census: no found lines')
        return 2
    MR = _mr()
    outcome = rpc_call(a.rpc, 'DERO.GetMiningOutcome') or {}
    kh = MR.learn_keyhash(outcome, MR.rpc_block_getter(a.rpc))
    if not kh:
        print('payout_census: no single KeyHash common to the blocks derod says paid us (no chain census)')
        return 7
    census, have_ours = live_census(sorted({r['h'] for r in found}), a.rpc, kh)
    rep = classify(found, census)
    rep['finals_verifiable'] = have_ours
    rep['heights'] = len(census)
    rep['height_errors'] = sum(1 for v in census.values() if 'err' in v)
    rep['captured'] = datetime.datetime.now().astimezone().isoformat(timespec='seconds')
    rep['facts'] = facts(rep)
    out = Path(a.out) if a.out else HARNESS / f"runtime/payoutcensus_{datetime.datetime.now().strftime('%Y%m%dT%H%M%S')}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rep, indent=1))
    for x in rep['facts']:
        print(x)
    print(f'wrote {out}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
