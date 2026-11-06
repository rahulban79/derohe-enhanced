#!/usr/bin/env python3
"""mine_consensus.py (r24) — the chain-consensus observatory (harness/intel/consensus_intel.py) as page rows.

Every row anchors on the line of harness/runtime/consensus_intel.json that states it (class HARNESS: what the
observatory measured), and a detector, log kind or proposal also on the line of the tree its rule, printer or gap
lives on (class SRC). Rows of section 'consensus', rendered by kit/consensuskit.py. A missing or unreadable
capture yields no rows and one 'unverified' entry: never a row without an anchor. The rolling series rows anchor on
their own line of harness/runtime/consensus_series.jsonl.
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):   # r27 B120: usage, exit 0, nothing run or written
    print(__doc__ or 'usage: see the header of this file')
    raise SystemExit(0)
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import minelib as M

SRC = 'harness/runtime/consensus_intel.json'
SERIES = 'harness/runtime/consensus_series.jsonl'
SEC = 'chainobs'   # page section id ('consensus' is the Consensus-rules section)
# the KPIs drawn (key, label, what it means); a key absent from the capture is skipped, never invented
KPIS = [
    ('window_blocks', 'blocks in the window', 'consecutive topoheights read by GetBlockHeadersRange'),
    ('window_hours', 'hours the window spans', 'last minus first block timestamp'),
    ('sync_status', 'sync status', 'GetSyncInfo status (tip age and peer median, not GetInfo)'),
    ('tip_age_s', 'tip age, s', 'GetSyncInfo tip_age_seconds at capture'),
    ('block_time_mean_s', 'mean block time, s', 'mean of consecutive-height timestamp gaps; target 18 s (config.go)'),
    ('block_time_median_s', 'median block time, s', 'gaps are right-skewed, so the median sits below the mean'),
    ('block_time_p95_s', 'p95 block time, s', '95th percentile gap'),
    ('block_time_max_s', 'longest gap, s', 'largest consecutive-height gap in the window'),
    ('averageblocktime50_s', 'GetInfo averageblocktime50, s', 'timestamp-derived over 50 blocks; shown for comparison only'),
    ('difficulty_mean', 'mean difficulty', 'mean of the stored difficulty of every block'),
    ('difficulty_min', 'lowest difficulty', 'window minimum'),
    ('difficulty_max', 'highest difficulty', 'window maximum'),
    ('difficulty_rule_checked', 'difficulties recomputed', 'blocks whose difficulty was recomputed from the rule'),
    ('difficulty_rule_mismatches', 'rule mismatches', 'recomputed difficulty differs from the stored one (must be 0)'),
    ('difficulty_clamped_steps', 'clamped steps', 'tip solve time above 2 x block time, clamped by the rule'),
    ('participants', 'participants', 'distinct pseudonyms that mined a regular miniblock or integrated a block'),
    ('integrator_only_participants', 'integrator-only participants', 'paid finals, mined no regular miniblock (nodes serving others)'),
    ('integrator_only_final_share', 'finals to integrator-only', 'share of blocks assembled by participants that mine nothing themselves'),
    ('miner_only_participants', 'miner-only participants', 'mined regular miniblocks, never paid a final'),
    ('top1_regular_share', 'top-1 share, regular', 'largest share of regular miniblocks (hashrate proxy)'),
    ('top3_regular_share', 'top-3 share, regular', 'three largest shares together'),
    ('top1_final_share', 'top-1 share, finals', 'largest share of blocks integrated'),
    ('top3_final_share', 'top-3 share, finals', 'three largest integrators together'),
    ('hhi_regular', 'HHI, regular', 'Herfindahl-Hirschman index of regular shares (1 = one miner)'),
    ('hhi_final', 'HHI, finals', 'Herfindahl-Hirschman index of final shares'),
    ('nakamoto_regular', 'Nakamoto coefficient, regular', 'fewest participants holding more than half of the regular miniblocks'),
    ('nakamoto_final', 'Nakamoto coefficient, finals', 'fewest integrators assembling more than half of the blocks'),
    ('this_node_regular', 'this-node regular miniblocks', 'own integrator address compared in memory (miner paused)'),
    ('this_node_final', 'this-node finals', 'blocks this node integrated in the window'),
    ('blocks_seen_live', 'blocks first seen live', 'blocks whose first "Chain extended" log line came within 60 s'),
    ('arrival_lag_median_ms', 'median arrival lag, ms', 'first-seen log time minus block timestamp'),
    ('arrival_lag_p95_ms', 'p95 arrival lag, ms', ''),
    ('arrival_before_timestamp', 'arrived before own timestamp', 'a forward stamp is the only cause (network delay only adds)'),
    ('side_block_lines_window', 'side-block lines', '"Chain extended but height is same" inside the window heights'),
    ('side_block_won', 'side blocks that won the height', 'the later block at a height became the main chain (a depth-1 reorg)'),
    ('finality_reorgs', 'reorgs since start', 'GetMonetaryIntegrity finality monitor (resets at restart)'),
    ('finality_deepest_heights', 'deepest reorg, heights', 'must stay below STABLE_LIMIT 8'),
    ('finality_final_violations', 'finality violations', 'must stay 0'),
    ('alt_blocks_count_getinfo', 'GetInfo alt_blocks_count', 'r24 and older: declared, never assigned (CO24-C4); r25: settled alt blocks since start'),
    ('alt_blocks_rpc', 'alt blocks (GetConsensusStats)', 'r25: accepted blocks deeper than STABLE_LIMIT that are not in the topo index'),
    ('miniblock_refused_total', 'miniblock refusals since start', 'r25 counter p2p_miniblock_refused_total, by reason (CO24-C1)'),
    ('block_rejected_total', 'block rejections since start', 'r25 counter blockchain_block_rejected_total, by reason (CO24-C3)'),
    ('finality_lifetime_reorgs', 'reorgs over every run', 'r25: the reorg monitor persisted across restarts (CO24-C6)'),
    ('peers_connected', 'peers connected', 'GetPeerInfo count at capture (r25: in the series, CO24-C8)'),
    ('arrival_source', 'arrival lag source', 'r25: the node\'s first_seen_ms, else the DEBUG "Chain extended" line'),
    ('empty_block_ratio', 'empty block ratio', 'blocks with no transaction'),
    ('tx_total', 'transactions in the window', 'sum of header txcount'),
    ('fees_total', 'fees in the window', 'r25: sum of header fees (GetBlockHeadersRange); pending on an older binary (CO24-C2)'),
]


def ev(quote, hint=None):
    return M.anchor(SRC, quote, hint=hint)


def code(a):
    """re-anchor a tree line the capture cited (its file and quote); None if the line moved away or vanished"""
    if not a or not a.get('file'):
        return None
    return M.anchor(a['file'], a['quote'], hint=a.get('line'))


def main():
    p = M.ROOT / SRC
    if not p.exists():
        M.emit('consensus', [], [{'title': 'consensus observatory', 'why': f'{SRC} not written yet: run harness/intel/consensus_intel.py'}], 'mine_consensus.py')
        return
    try:
        doc = json.loads(p.read_text())
    except ValueError as e:
        M.emit('consensus', [], [{'title': 'consensus observatory', 'why': f'{SRC} unreadable: {e}'}], 'mine_consensus.py')
        return
    rows, unv = [], []
    base = {'section': SEC, 'captured': doc.get('captured'), 'version': doc.get('version'), 'binary_round': doc.get('binary_round')}
    k = doc.get('kpis') or {}
    for key, label, what in KPIS:
        if key not in k:
            continue
        a = ev(f'"{key}": {json.dumps(k[key], ensure_ascii=False)}')
        if not a:
            unv.append({'title': key, 'why': 'KPI line not found in the capture'})
            continue
        rows.append({**base, 'id': f'cons-kpi-{key}', 'kind': 'kpi', 'class': 'HARNESS', 'key': key, 'title': label, 'value': k[key],
                     'how': what, 'claim': f'{label}: {k[key]} ({doc.get("captured")})', 'evidence': [a]})
    for q in doc.get('participants') or []:
        a = ev(f'{{"id": "{q["id"]}"')
        if not a:
            unv.append({'title': q['id'], 'why': 'participant line not found'})
            continue
        rows.append({**base, 'id': f'cons-p-{q["id"]}', 'kind': 'participant', 'class': 'HARNESS', 'title': q['id'], **{x: q.get(x) for x in (
            'role', 'regular', 'regular_share', 'final', 'final_share', 'final_ci95', 'longest_final_run', 'run_p', 'final_vs_regular_p', 'tested')},
            'claim': f"{q['id']} ({q.get('role')}): {q['regular']} regular miniblocks ({q['regular_share']}), {q['final']} finals ({q['final_share']})",
            'evidence': [a]})
    for d in doc.get('detectors') or []:
        a = ev(f'{{"id": "{d["id"]}"')
        if not a:
            unv.append({'title': d['id'], 'why': 'detector line not found'})
            continue
        evs = [a]
        r = code(d.get('rule'))
        if d.get('rule') and not r:
            unv.append({'title': d['id'], 'why': f"rule anchor {d['rule'].get('file')} no longer resolves"})
            continue
        if r:
            evs.append(r)
        rows.append({**base, 'id': f'cons-d-{d["id"]}', 'kind': 'detector', 'class': 'HARNESS', 'title': d['title'], 'det': d['id'],
                     'grade': d['grade'], 'value': d['value'], 'test': d['test'], 'note': d.get('note', ''), 'det_evidence': d.get('evidence')[:5],
                     'claim': f"{d['id']} {d['grade']}: {d['title']} (value {d['value']})", 'evidence': evs})
    lc = doc.get('log_census') or {}
    for r_ in lc.get('kinds') or []:
        a = ev(f'{{"kind": {json.dumps(r_["kind"], ensure_ascii=False)}, "lines": {r_["lines"]}')
        if not a:
            unv.append({'title': r_['kind'], 'why': 'log kind line not found'})
            continue
        evs = [a] + ([c] if (c := code(r_.get('printed_by'))) else [])
        rows.append({**base, 'id': f'cons-log-{r_["kind"][:60]}', 'kind': 'logkind', 'class': 'HARNESS', 'title': r_['kind'], 'lines': r_['lines'],
                     'first': r_.get('first'), 'last': r_.get('last'), 'printed_by': r_.get('printed_by'),
                     'claim': f"derod.log kind {r_['kind']}: {r_['lines']} lines", 'evidence': evs})
    for pr in doc.get('proposals') or []:
        a = ev(f'{{"id": "{pr["id"]}"')
        cs = [c for c in (code(x) for x in pr.get('anchors') or []) if c]
        if not a or not cs:
            unv.append({'title': pr['id'], 'why': 'proposal line or its code anchor not found'})
            continue
        rows.append({**base, 'id': f'cons-prop-{pr["id"]}', 'kind': 'proposal', 'class': 'HARNESS', 'title': pr['title'], 'pid': pr['id'],
                     'severity': pr['severity'], 'why': pr['why'], 'claim': f"{pr['id']}: {pr['title']}", 'evidence': [a] + cs[:3]})
    bins = doc.get('series_bins') or []
    a = ev('"series_bins": [')
    if bins and a:
        rows.append({**base, 'id': 'cons-series-bins', 'kind': 'bins', 'class': 'HARNESS', 'title': 'per-100-block series', 'bins': bins,
                     'claim': f'{len(bins)} bins of 100 blocks: mean block time and mean difficulty', 'evidence': [a]})
    sp = M.ROOT / SERIES
    if sp.exists():
        lines = [l for l in sp.read_text().splitlines() if l.strip()]
        for i, l in enumerate(lines[-12:], len(lines) - min(12, len(lines)) + 1):
            try:
                s = json.loads(l)
            except ValueError:
                continue
            a2 = M.anchor(SERIES, f'"ts": "{s.get("ts")}"', hint=i)
            if a2:
                rows.append({**base, 'id': f'cons-run-{s.get("ts")}', 'kind': 'run', 'class': 'HARNESS', 'title': s.get('ts'), 'run': s,
                             'claim': f"observatory run {s.get('ts')}: {s.get('window_blocks')} blocks to height {s.get('window_height_last')}",
                             'evidence': [a2]})
    s = doc.get('summary') or {}
    a = ev('"summary": {')
    if a:
        rows.append({**base, 'id': 'cons-summary', 'kind': 'summary', 'class': 'HARNESS', 'title': 'detector grades', 'grades': s,
                     'window': {x: k.get(x) for x in ('window_topo_first', 'window_topo_last', 'window_blocks', 'window_hours')},
                     'claim': 'grades ' + ', '.join(f'{g} {v}' for g, v in s.items()), 'evidence': [a]})
    M.emit('consensus', rows, unv, 'mine_consensus.py')


if __name__ == '__main__':
    main()
