#!/usr/bin/env python3
"""mine_intel.py — the node-intelligence rows: what the intel tools measured, anchored on their own snapshots.

Reads the newest harness/runtime/logintel_*.json (harness/intel/log_intel.py), datadir_*.json
(harness/intel/datadir_intel.py), gomut_*.json (harness/intel/go_mutate.py) and the adversarially verified discovery
set discovery_*.json — all in harness/runtime/, the evidence root for captured measurements. Each row cites the snapshot line that carries its number, so
the page shows only what a tool measured.
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):   # r27 B120: usage, exit 0, nothing run or written
    print(__doc__ or 'usage: see the header of this file')
    raise SystemExit(0)
import json, re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import minelib as M

RT = M.HARNESS / 'runtime'


def in_checkout(p):
    """a path inside this checkout, relative to it (stable across clones: R21 anchors), else as given"""
    if not p:
        return p
    try:
        return str(Path(p).resolve(strict=False).relative_to(M.ROOT.resolve()))
    except ValueError:
        try:
            return str(Path(p).relative_to(M.ROOT))
        except ValueError:
            return str(p)


def newest(pat):
    f = sorted(RT.glob(pat))
    return f[-1] if f else None


def main():
    rows, unv = [], []
    li = newest('logintel_*.json')
    if li:
        rel = str(li.relative_to(M.ROOT))
        d = json.loads(li.read_text())
        for i, (fact, run) in enumerate(zip(d['facts'], d['runs'])):
            if run['blocks']['at_tip_intervals'] < 50 and i < len(d['runs']) - 1:
                continue                                 # short fragments say nothing about cadence
            a = M.anchor(rel, fact, full_line=True)
            if not a:
                unv.append({'title': f'log run {run["start"]}', 'why': 'fact line not found in the snapshot'})
                continue
            b = run['blocks']
            rows.append({'id': f'intel-run-{run["start"][:19]}', 'section': 'intel', 'class': 'HARNESS', 'kind': 'log-run',
                         'title': f'{run.get("version", "?")} · {run["start"][:16]} · {run["hours"]} h',
                         'claim': (f'The daemon\'s own JSON log for this run: {run["lines"]:,} lines; at tip since '
                                   f'{b["at_tip_since"]} with a MEAN block interval of {b["at_tip_mean_s"]} s (median '
                                   f'{b["at_tip_median_s"]} s, p90 {b["at_tip_p90_s"]} s) over {b["at_tip_intervals"]:,} '
                                   f'intervals; {b["side_blocks"]} side blocks; ERROR lines at tip {run["errors_at_tip"]}; '
                                   f'resyncs at tip {run["resyncs"]["at_tip"]}; v2-remnant drops {run["v2_drops"]}.'),
                         'version': run.get('version'), 'hours': run['hours'], 'mean': b['at_tip_mean_s'],
                         'median': b['at_tip_median_s'], 'p90': b['at_tip_p90_s'], 'intervals': b['at_tip_intervals'],
                         'errors_at_tip': run['errors_at_tip'], 'alerts': run['alerts'], 'start': run['start'],
                         'evidence': [a]})
    dd = newest('datadir_*.json')
    if dd:
        rel = str(dd.relative_to(M.ROOT))
        d = json.loads(dd.read_text())
        for fact, c in zip(d['facts'], d['checks']):
            a = M.anchor(rel, fact.replace('"', '\\"'), full_line=True)
            if not a:
                unv.append({'title': f'datadir {c["check"]}', 'why': 'fact line not found in the snapshot'})
                continue
            rows.append({'id': f'intel-dd-{c["check"]}', 'section': 'intel', 'class': 'HARNESS', 'kind': 'datadir',
                         'title': c['check'], 'result': c['result'],
                         'claim': f'datadir_intel {c["check"]}: {c["result"]} — {c["what"]}', 'evidence': [a]})
    # r19: the derod counters log_intel read from /metrics (sync pipeline, first relay, template resends)
    if li:
        d = json.loads(li.read_text())
        mt = d.get('metrics') or {}
        mf = next((f for f in d.get('facts', []) if f.startswith('derod metrics ')), None)
        a = M.anchor(str(li.relative_to(M.ROOT)), mf, full_line=True) if mf and 'error' not in mt else None
        if a:
            rows.append({'id': 'intel-derod-metrics', 'section': 'intel', 'class': 'HARNESS', 'kind': 'metrics',
                         'title': 'derod counters: pipelined sync, first relay, template resends',
                         'claim': (f'The pipelined block sync fetched {mt["blocks_per_getobject"]} blocks per GetObject call and '
                                   f'spent {mt["sync_wait_fraction"]} of its time waiting on the network (the rest verifying '
                                   f'and storing); large-block fallbacks {int(mt["p2p_sync_large_block_fallbacks_total"])}; PoW '
                                   f'prewarmed {int(mt["p2p_sync_pow_prewarmed_total"])}. {mt["first_relay_peers"]} peers delivered '
                                   f'a block first, the top one {mt["first_relay_top_share"]} of them; getwork template resends '
                                   f'{int(mt["getwork_template_refresh_resends_total"])}.'),
                         'wait_fraction': mt['sync_wait_fraction'], 'blocks_per_call': mt['blocks_per_getobject'],
                         'evidence': [a]})
    # r19: the live miner, from its own log (harness/intel/miner_intel.py)
    mi = newest('minerintel_*.json')
    if mi:
        rel = str(mi.relative_to(M.ROOT))
        d = json.loads(mi.read_text())
        mfacts = [f for f in d['facts'] if f.startswith('miner run ')]
        for fact, run in zip(mfacts, d['runs']):
            a = M.anchor(rel, fact, full_line=True)
            if not a:
                unv.append({'title': f'miner run {run["start"]}', 'why': 'fact line not found in the snapshot'})
                continue
            hs, sp, rw = run['hashrate'], run['split'], run['reward']
            rows.append({'id': f'intel-miner-{run["start"][:19]}', 'section': 'intel', 'class': 'HARNESS', 'kind': 'miner-run',
                         'title': f'miner {run.get("version", "?")} · {run.get("gpu_mode")} · {run["start"][:16]} · {run["hours"]} h',
                         'claim': (f'The miner\'s own log: TOTAL {hs.get("mean")} H/s mean (median {hs.get("median")}, p10 '
                                   f'{hs.get("p10")}, p90 {hs.get("p90")}) over {hs.get("samples")} samples; GPU-staged '
                                   f'{sp.get("staged_mean")} H/s = {sp.get("staged_share_of_total")} of TOTAL; '
                                   f'{sp.get("drop_fraction")} of staged nonces dropped stale ({sp.get("drops_per_height")} per '
                                   f'new height, ring {sp.get("ring_slots")}); restarts {sp.get("restarts_last")}, mismatches '
                                   f'{sp.get("mismatch")}, sort fallbacks {sp.get("sort_fallbacks")}; paid {rw.get("node_paid")}, '
                                   f'orphaned {rw.get("node_orphaned")}, paid fraction {rw.get("paid_fraction_recomputed")}, luck '
                                   f'{rw.get("luck")}.'),
                         'mean_hs': hs.get('mean'), 'samples': hs.get('samples'), 'staged_hs': sp.get('staged_mean'),
                         'drop_fraction': sp.get('drop_fraction'), 'paid_fraction': rw.get('paid_fraction_recomputed'),
                         'start': run['start'], 'end': run.get('end'), 'log': in_checkout(run.get('source') or d.get('log')),
                         'logs': [in_checkout(x) for x in (d.get('logs') or [d.get('log')])], 'version': run.get('version'),
                         'accepted_in_window': (run.get('shares') or {}).get('submissions'),
                         'longest_gap_s': (run.get('shares') or {}).get('longest_gap_s'),
                         'alerts': run['alerts'], 'evidence': [a]})
        # r21: the split regime of the CURRENT run (what bounds it: CPU sort, GPU, or neither), anchored on its own fact line
        cur = d['runs'][-1] if d['runs'] else None
        rg = ((cur or {}).get('split') or {}).get('regime') or {}
        rf = next((f for f in d['facts'] if cur and f.startswith(f"split regime {cur['start'][:19]} ")), None)
        a = M.anchor(rel, rf, full_line=True) if rf else None
        if rf and not a:
            unv.append({'title': f'split regime {cur["start"]}', 'why': 'fact line not found in the snapshot'})
        if a and rg.get('windows'):
            rows.append({'id': 'intel-split-regime', 'section': 'intel', 'class': 'HARNESS', 'kind': 'split-regime',
                         'title': f'GPU split regime of the current miner run: {rg["regime"]}',
                         'claim': (f'Over {rg["windows"]} one-minute windows of {cur.get("version")} the split staged a median '
                                   f'{rg["staged_median_hs"]} H/s at {rg["gpu_us_per_hash_median"]} GPU us/hash; the feeder found '
                                   f'the ring full {rg["ring_full_fraction"]} of the time and staged texts waiting on the CPU sort '
                                   f'{rg["cpu_backlog_fraction"]} of the time; CPU threads found nothing staged '
                                   f'{rg["idle_tries_per_min"]} times a minute; {rg.get("stale_fraction")} of staged work was dropped '
                                   f'stale; CPU-finished hashes {rg.get("cpu_finished")}. Regime: {rg["regime"]} (CPU-sort-bound '
                                   f'when the backlog is at least half the time).'),
                         'regime': rg['regime'], 'start': cur['start'], 'end': cur.get('end'),
                         'logs': [in_checkout(x) for x in (d.get('logs') or [d.get('log')])],
                         'cpu_backlog_fraction': rg['cpu_backlog_fraction'],
                         'ring_full_fraction': rg['ring_full_fraction'], 'idle_tries_per_min': rg['idle_tries_per_min'],
                         'staged_median_hs': rg['staged_median_hs'], 'windows': rg['windows'], 'evidence': [a]})
        # r20: derod's side of the shares — long silences that no surviving miner log explains
        gf = next((f for f in d['facts'] if f.startswith('derod own miniblocks last ')), None)
        a = M.anchor(rel, gf, full_line=True) if gf else None
        if a:
            ds = d.get('derod_side') or {}
            gaps = ds.get('unexplained_gaps') or []
            rows.append({'id': 'intel-share-gaps', 'section': 'intel', 'class': 'HARNESS', 'kind': 'share-gaps',
                         'title': f'Accepted shares on derod\'s side, last {ds.get("lookback_h")} h',
                         'claim': (f'derod accepted and broadcast {ds.get("own_accepted")} of our miniblocks in the last '
                                   f'{ds.get("lookback_h")} h ("Own miniblock delivered"). {len(gaps)} silence(s) of 2 h or more '
                                   f'fall outside every surviving miner log, so their cause is not on record'
                                   + (': ' + '; '.join(f'{g["from"][:16]} to {g["to"][:16]} ({g["hours"]} h)' for g in gaps[:6])
                                      if gaps else '') + '. Before Round 20 every miner restart truncated its log.'),
                         'gaps': len(gaps), 'longest_h': max((g['hours'] for g in gaps), default=0), 'evidence': [a]})
        of = next((f for f in d['facts'] if f.startswith('derod mining outcome ')), None)
        a = M.anchor(rel, of.replace('"', '\\"'), full_line=True) if of else None
        if a:
            o = d['outcome']
            rows.append({'id': 'intel-mining-outcome', 'section': 'intel', 'class': 'HARNESS', 'kind': 'outcome',
                         'title': 'derod miniblock ledger (DERO.GetMiningOutcome)',
                         'claim': (f'derod tracked {o["submitted"]} submitted miniblocks this run: {o["paid"]} paid, '
                                   f'{o["orphaned_total"]} orphaned (by reason {o["orphaned"]}), {o["pending"]} pending; paid '
                                   f'fraction {o["paid_fraction"]}.'),
                         'evidence': [a]})
    # r21: the long-term run ledger (harness/intel/run_ledger.py), one JSON line per miner run; anchored on the first
    # and the newest line, so the span the card claims is the span the file holds
    lg = RT / 'run_ledger.jsonl'
    if lg.exists():
        rel = str(lg.relative_to(M.ROOT))
        lines = [l for l in lg.read_text().splitlines() if l.strip()]
        L = [json.loads(l) for l in lines]
        ev = [x for x in (M.anchor(rel, lines[0], full_line=True) if lines else None,
                          M.anchor(rel, lines[-1], full_line=True) if len(lines) > 1 else None) if x]
        if L and ev:
            byv = {}
            for r in L:
                if r.get('mean_hs') is not None and r.get('samples'):
                    v = byv.setdefault(str(r.get('version'))[-14:], [0.0, 0])
                    v[0] += r['mean_hs'] * r['samples']
                    v[1] += r['samples']
            rows.append({'id': 'intel-run-ledger', 'section': 'intel', 'class': 'HARNESS', 'kind': 'run-ledger',
                         'title': f'Miner run ledger: {len(L)} runs, {L[0]["start"][:10]} to {L[-1]["end"][:10]}',
                         'claim': (f'harness/runtime/run_ledger.jsonl keeps one line per miner run after its log rotates away '
                                   f'({sum(1 for r in L if r.get("head_missing"))} fragment(s)). Sample-weighted mean TOTAL H/s by '
                                   f'build: ' + '; '.join(f'{k} {v[0] / v[1]:.0f} over {v[1]} samples' for k, v in byv.items())
                                   + f'. Newest run: {L[-1].get("regime")} regime, paid fraction {L[-1].get("paid_fraction")}.'),
                         'runs': len(L), 'evidence': ev})
    # r20: the live dashboard, both /metrics endpoints sampled twice (harness/intel/metrics_intel.py)
    mt = newest('metrics_*.json')
    # r23c (measurement close): the user stops the miner between measured runs, so the newest snapshot may hold derod
    # only; the dashboard row then reads the newest snapshot that sampled both endpoints and SAYS it is not current
    # (its capture time is in the title, and the absence is stated). No snapshot with both = no row, as before.
    absent_at = None
    if mt and not json.loads(mt.read_text()).get('miner'):
        absent_at = json.loads(mt.read_text()).get('captured')
        both = [f for f in sorted(RT.glob('metrics_*.json'), reverse=True)
                if (lambda x: x.get('miner') and x.get('derod'))(json.loads(f.read_text()))]
        mt = both[0] if both else mt
    if mt:
        rel = str(mt.relative_to(M.ROOT))
        d = json.loads(mt.read_text())
        mf = next((f for f in d['facts'] if f.startswith('live miner version=')), None)
        df = next((f for f in d['facts'] if f.startswith('live derod version=')), None)
        ev = [x for x in (M.anchor(rel, mf, full_line=True) if mf else None, M.anchor(rel, df, full_line=True) if df else None) if x]
        if ev and d.get('miner') and d.get('derod'):
            m, dd = d['miner'], d['derod']
            rows.append({'id': 'intel-live-metrics', 'section': 'intel', 'class': 'HARNESS', 'kind': 'metrics-live',
                         'title': f'The live dashboard at {d["captured"][:16]} (both /metrics, sampled {d.get("interval_s")} s apart)'
                                  + (f'; the newest snapshot with the miner running (no miner at {absent_at[:16]})' if absent_at else ''),
                         'claim': (f'Miner {m["version"]}: {m["hashrate_sampled"]} H/s over the sample ({m["hashrate_run_mean"]} '
                                   f'run mean, {m["uptime_s"]:.0f} s up), {m["split_share"]} of hashes through the GPU split, '
                                   f'{m["split_drop_fraction"]} dropped stale; at the NW estimate {m["network_hashrate"]} it should '
                                   f'find {m["expected_shares_per_h"]} shares per hour. derod {dd["version"]}: {dd["sync_status"]}, '
                                   f'tip {dd["tip_age_s"]} s old, {dd["peers_out"]:.0f} out / {dd["peers_in"]:.0f} in peers; our '
                                   f'miniblocks {dd["ours_submitted"]:.0f} submitted, {dd["ours_paid"]:.0f} paid, '
                                   f'{dd["ours_orphaned"]:.0f} orphaned since derod started. Alerts: '
                                   f'{", ".join(x["rule"] for x in d.get("alerts", [])) or "none"}.'),
                         'hashrate_sampled': m['hashrate_sampled'], 'snapshot': rel, 'evidence': ev})
        # R22: the regime card — which resource binds the split right now, anchored on its own fact line (G19 gates it)
        bf = next((f for f in d['facts'] if f.startswith('live split binding=')), None)
        ab = M.anchor(rel, bf, full_line=True) if bf else None
        if bf and not ab:
            unv.append({'title': 'live split binding', 'why': 'fact line not found in the snapshot'})
        bd = (d.get('miner') or {}).get('split_binding')
        if ab and bd:
            rows.append({'id': 'intel-split-binding', 'section': 'intel', 'class': 'HARNESS', 'kind': 'split-binding',
                         'title': f'What binds the GPU split right now: {bd["binding"]}',
                         'claim': (f'Over {d.get("interval_s")} s at {d["captured"][:16]} the GPU was busy {bd["gpu_busy_fraction"]} of '
                                   f'the time (wall-clock union of its command buffers), staged texts waited on the CPU sort '
                                   f'{bd["cpu_backlog_fraction"]} of the time and the feeder found the ring full '
                                   f'{bd["ring_full_fraction"]}; the miner used {bd["cpu_cores"]} cores = {bd["cpu_budget_fraction"]} '
                                   f'of its --cpu-max budget. A resource binds at >= 0.90 busy (GPU) or >= 0.50 backlog (CPU '
                                   f'sort); both = co-bound, where speeding up either side alone buys at most the other\'s '
                                   f'headroom. GPU-only ceiling ESTIMATE (staged / busy): {bd["gpu_ceiling_staged_hs"]} staged H/s. '
                                   f'CPU threads that found nothing staged hashed on their own: {bd["cpu_own_hs"]} H/s, '
                                   f'{bd["cpu_own_hashes_per_idle_try"]} hashes per idle try.'),
                         'binding': bd['binding'], 'gpu_busy_fraction': bd['gpu_busy_fraction'],
                         'cpu_backlog_fraction': bd['cpu_backlog_fraction'], 'snapshot': rel, 'evidence': [ab]})
    # R22: the miner's OWN run ledger (bin/dero-miner.runs.jsonl), validated and joined with derod and the chain
    mr = newest('minerruns_*.json')
    if mr:
        rel = str(mr.relative_to(M.ROOT))
        d = json.loads(mr.read_text())
        lf = next((f for f in d['facts'] if f.startswith('miner run ledger rows=')), None)
        rf = [f for f in d['facts'] if f.startswith('miner run ')and not f.startswith('miner run ledger')]
        ev = [x for x in [M.anchor(rel, lf, full_line=True) if lf else None]
              + [M.anchor(rel, f.replace('"', '\\"'), full_line=True) for f in rf[:3]] if x]
        if ev:
            cj = d.get('chain_join') if isinstance(d.get('chain_join'), list) else []
            rows.append({'id': 'intel-miner-runs', 'section': 'intel', 'class': 'HARNESS', 'kind': 'miner-runs',
                         'title': f'The miner\'s own run ledger: {len(d.get("rows") or [])} ended run(s) + '
                                  f'{"1 running" if d.get("checkpoint") else "none running"}',
                         'claim': (f'bin/dero-miner.runs.jsonl (cmd/dero-miner/runledger.go) checked line by line against its '
                                   f'writer\'s promises and the miner log (L1-L8: '
                                   + ', '.join(f"{k.split()[0]} {'ok' if v['ok'] else 'FAIL'}" for k, v in d['ledger_checks'].items())
                                   + f'; {d.get("skipped_lines")} torn line(s)). An exit record freezes its shares\' fates: '
                                   + '; '.join(f"run {x['run_id']}: chain says {x['paid_chain']} paid / {x['orphaned_chain']} "
                                               f"orphaned of {x['found']} found" for x in cj)
                                   + ' (the main-chain blocks at the found heights, read-only GetBlock).'),
                         'snapshot': rel, 'evidence': ev})
        # R23: the payout ledger — expected vs found vs paid per run, in shares and DERO, with the Poisson verdict
        po = d.get('payout') or {}
        tf = next((f for f in d['facts'] if f.startswith('payout total ')), None)
        at = M.anchor(rel, tf.replace('"', '\\"'), full_line=True) if tf else None
        if tf and not at:
            unv.append({'title': 'payout ledger', 'why': 'payout total fact line not found in the snapshot'})
        if at and po.get('total'):
            t = po['total']
            pr = po.get('runs') or []
            rows.append({'id': 'intel-payout-ledger', 'section': 'intel', 'class': 'HARNESS', 'kind': 'payout-ledger',
                         'title': f'Payout ledger: {t["paid"]} paid of {t["expected_shares"]} expected shares over {t["runs"]} run(s)',
                         'claim': (f'The runs\' own hashes should have found {t["expected_shares"]} shares (5/(9 D) per hash); they '
                                   f'found {t["found"]} (luck {t["luck"]}, exact 95 % Poisson interval {t["found_ci95"]}: '
                                   f'{t["verdict"]}) and {t["paid"]} were paid = {t["paid_DERO"]} DERO against '
                                   f'{t["expected_DERO"]} expected, at {t["per_miniblock_atomic"]} atomic units per miniblock '
                                   f'(derived from CalcBlockReward at height {po.get("height")}; tx fees excluded, so a lower '
                                   f'bound). Per run (paid source): ' + '; '.join(
                                       f"{x['start'][:16]} {x['paid']}/{x['expected_shares']} ({x['paid_source']}, luck {x['luck']})"
                                       for x in pr[-5:]) + '.'),
                         'paid': t['paid'], 'expected_shares': t['expected_shares'], 'snapshot': rel, 'evidence': [at]})
    # R23: the contention census — who else held the CPU when the dashboard was sampled (process names only)
    if mt:
        rel = str(mt.relative_to(M.ROOT))
        d = json.loads(mt.read_text())
        cf = next((f for f in d['facts'] if f.startswith('live contention ')), None)
        ac = M.anchor(rel, cf, full_line=True) if cf else None
        ct = d.get('contention') or {}
        if ac and ct.get('contended') is not None:
            top = ', '.join(f"{g['name']} x{g['procs']} ({g['cores']} cores)" for g in (ct.get('top_foreign') or [])[:3]) or 'none'
            rows.append({'id': 'intel-contention', 'section': 'intel', 'class': 'HARNESS', 'kind': 'contention',
                         'title': f'The box at {d["captured"][:16]}: {"CONTENDED" if ct["contended"] else "quiet"} '
                                  f'({ct.get("foreign_cores")} foreign cores)',
                         'claim': (f'A read-only process census over {ct.get("interval_s")} s (names only): the miner got '
                                   f'{ct.get("miner_cores")} cores of its {ct.get("budget_cores")}-core --cpu-max budget, '
                                   f'derod {ct.get("node_cores")}, other processes {ct.get("foreign_cores")} (top: {top}); '
                                   f'headroom {ct.get("headroom_cores")} cores. Contention law {ct.get("law")}: '
                                   f'{ct.get("law_hs_at_miner_cores")} H/s at the cores it got vs {ct.get("law_hs_at_budget")} '
                                   f'at its budget (loss ESTIMATE {ct.get("law_loss_hs")} H/s). Regression and A/B claims '
                                   f'from this reading: {ct.get("regression_claims")} (gate G20).'),
                         'contended': ct['contended'], 'snapshot': rel, 'evidence': [ac]})
    gm = newest('gomut_*.json')
    if gm:
        d = json.loads(gm.read_text())
        a = M.anchor(str(gm.relative_to(M.ROOT)), f'"caught": {d["caught"]}', full_line=True)
        if a:
            rows.append({'id': 'intel-go-mutations', 'section': 'intel', 'class': 'HARNESS', 'kind': 'mutation',
                         'title': 'Go mutation coverage of the local fixes',
                         'claim': (f'{d["caught"]} of {d["total"]} source mutations were caught by their tests. Each '
                                   f'undoes one local fix or weakens one rule (harness/intel/go_mutations.json); a fix '
                                   f'whose test stays green when it is reverted is not tested.'),
                         'caught': d['caught'], 'total': d['total'], 'evidence': [a]})
    disc = sorted(RT.glob('discovery_*.json'))
    if disc:
        rel = str(disc[-1].relative_to(M.ROOT))
        d = json.loads(disc[-1].read_text())
        n = conf = part = 0
        for dim, v in d.items():
            V = {x['id']: x['verdict'] for x in ((v.get('verify') or {}).get('verdicts') or [])}
            for f in ((v.get('discover') or {}).get('findings') or []):
                n += 1
                conf += V.get(f['id']) == 'CONFIRMED'
                part += V.get(f['id']) == 'PARTLY'
        a = M.anchor(rel, '"discover": {', full_line=True)
        if a:
            rows.append({'id': 'intel-discovery', 'section': 'intel', 'class': 'HARNESS', 'kind': 'discovery',
                         'title': f'Discovery round: {len(d)} investigations, each adversarially verified',
                         'claim': (f'{n} findings across {", ".join(sorted(d))}; the verifiers judged {conf} CONFIRMED, '
                                   f'{part} PARTLY (corrected) and {n - conf - part} unjudged or refuted. The set is kept '
                                   f'verbatim in {rel}.'),
                         'findings': n, 'confirmed': conf, 'partly': part, 'evidence': [a]})
    M.emit('intel', rows, unv, 'mine_intel.py')


if __name__ == '__main__':
    main()
