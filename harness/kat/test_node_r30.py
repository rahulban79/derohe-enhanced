#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the r30 node dimension (consensus-peers + live-observability; rft §7 B201,
B184, B61, B152 and the live-event rows B47 B48 B57 B85 B99 B42 B19 B44 B63 B64 B67 BD5 B144 B157).

Every input is synthetic and in memory or in a temp dir (RFC 5737 / RFC 2544 / 240.0.0.0/4 addresses; one RFC 1918
address as the 'must be masked' input of NR11). No live node, no network, no real runtime file is read or written.
  NR1  peer_intel lag_kpis: a v2 peer 2.8 M blocks behind does not move lag_max (it is lag_max_v2); a v3 peer does
  NR2  area_intel keyed_prev/point_regime: inbound 0 -> 27 (two regimes) gives no regression; same regime still does
  NR3  area_intel area_state + load_triage: a booked medium proposal does not raise WATCH; an unbooked one does; the
       tracked proposal_triage.json books the 10 R29 medium proposals under B201
  NR4  peer_intel trajectory/explain_d2: a height that rose is SYNCING (delta > 0 is not STUCK), a flat one over >= 2
       captures STUCK, a fall REGRESSED, one capture ONE-READING; the nearest replay wall below is named
  NR5  peer_intel D11: one peer_id on 3 addresses with RTT 67-209 ms is UNEXPLAINED (ANOMALY); RTTs 100/104 ms are
       EXPLAINED (NORMAL); (fix D2) 1 out + 2 in addresses read '1 of our outgoing slot and 2 inbound connections'
  NR6  consensus_intel D15: a 0.34 final share of 600 blocks (Wilson lower bound < 1/3) is NORMAL; 0.45 is ANOMALY
  NR7  peer_intel D9: 110 of 217 first relays (50.7 %, lower bound < 50 %) is NORMAL; 500 of 925 (54.1 %) is ANOMALY
  NR8  consensus_intel D20: with no derod start line (log not read) and matching counts -> NORMAL ('log not read')
  NR9  live_window row_status/invariant_lines: event seen / registered, no event / absent; B61 graded as an invariant
       (one sample topoheight != height -> INVARIANT BROKEN); B152 a non-lazy absent family breaks, a lazy one does not
  NR10 hf4_watch judge/estimate: unchanged refs and 122,960 blocks -> UNCHANGED (26.4 days, ESTIMATE); 29,999 blocks
       -> ESCALATE; a Release tag carrying MAJOR_HF4_HEIGHT -> ESCALATE; a moved main head -> CHECK
  NR11 live_window watch: 3 samples on a fake clock, masked records (an RFC 1918 address in GetInfo becomes <peer>),
       progress.json counts, each record's contention flag counted in status.txt, a STOP file ends it with DONE
  NR12 (fix D1/D5b) hf4_watch main(): a removed + added tag (same count) -> exit 4 naming both; a re-pointed tag -> 4;
       unchanged -> 0; a partial (newest-tags-only) baseline with the same count -> 0
  NR13 (fix D3/D5d) live_window watch_start: a dir with a space or quote, or one whose progress.json pid is alive, is
       refused before any side effect; a dead pid starts; watch_match is what ps shows, also for a dir the shell quotes
  NR14 (fix D4) consensus_intel log_was_read: a read log without a start line is graded (D20 ANOMALY); 0 lines -> D20
       'log not read' and D13 without '0 in the whole log'
  (NR2 also checks area_intel.metric_trend, fix D5a; NR9 also checks metric_registry.check K6/K7, fix D5c)
  python3 -I harness/kat/test_node_r30.py   # exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught
  python3 -I harness/kat/test_node_r30.py --old-code a41757d8   # fail-before: every KAT must FAIL on that commit's
                                                                 # files (exit 0 when all fail, 3 when one passes)
A mutation that crashes the KAT is INVALID, not caught.
"""
import contextlib, copy, datetime, importlib.util, io, json, random, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
FILES = ('intel/peer_intel.py', 'intel/area_intel.py', 'intel/consensus_intel.py', 'intel/live_window.py',
         'intel/metric_registry.py', 'intel/hf4_watch.py', 'kit/privkit.py')


def load_mod(path, name):
    sp = importlib.util.spec_from_file_location(f'{name}_{random.random()}', path)
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


KP = load_mod(HARNESS / 'kat/test_peer_intel_r25.py', 'kp25')       # peer(), run(), base_metrics()
K24 = load_mod(HARNESS / 'kat/test_consensus_intel_r24.py', 'kc24')   # synth()
K25 = load_mod(HARNESS / 'kat/test_consensus_intel_r25.py', 'kc25')   # r25(), G, analyse


def M(base, f):
    return load_mod(Path(base) / f, Path(f).stem)


def quiet(fn, *a, **k):
    """fn(*a, **k) with its stdout/stderr swallowed (a tool's main() prints its report)."""
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return fn(*a, **k)


def det(rep, did):
    return next(d for d in rep['detectors'] if d['id'] == did)


def nr1(base):
    P = M(base, 'intel/peer_intel.py')
    peers = [{'lag': 0, 'top_version': 3}, {'lag': 3, 'top_version': 3}, {'lag': 2_842_599, 'top_version': 2}]
    a = P.lag_kpis(peers)
    b = P.lag_kpis(peers + [{'lag': 338_517, 'top_version': 3}])
    u = P.lag_kpis(peers + [{'lag': 9_000_000}])          # r30 (verifier M9): an unknown top_version is not v3
    ok = a == (3, 1.5, 2_842_599) and b[0] == 338_517 and b[2] == 2_842_599 and u[:2] == (3, 1.5)
    return ok, f'{a} {b} {u}'


def nr2(base):
    A = M(base, 'intel/area_intel.py')
    t = Path(tempfile.mkdtemp(prefix='r30nr2-'))
    (t / 'harness/runtime').mkdir(parents=True)
    for name, inc in (('peer_capture_20261106T162105.jsonl', 0), ('peer_capture_20261108T200923.jsonl', 27),
                      ('peer_capture_20261109T000000.jsonl', 28)):
        (t / 'harness/runtime' / name).write_text(json.dumps({'src': 'capture'}) + '\n' + json.dumps({'src': 'kpis', 'incoming': inc}) + '\n')
    pts = [{'round': 'r28', 'value': 0, 'anchor': {'file': 'harness/runtime/peer_capture_20261106T162105.jsonl'}},
           {'round': 'r29', 'value': 2842599, 'anchor': {'file': 'harness/runtime/peer_capture_20261108T200923.jsonl'}}]
    regs = [A.point_regime(t, p['anchor']) for p in pts]
    prev, rc = A.keyed_prev(pts, regs)
    pts2 = pts + [{'round': 'r30', 'value': 9999999, 'anchor': {'file': 'harness/runtime/peer_capture_20261109T000000.jsonl'}}]
    regs2 = [A.point_regime(t, p['anchor']) for p in pts2]
    prev2, rc2 = A.keyed_prev(pts2, regs2)
    d2, reg2 = A.trend(prev2['value'] if prev2 else None, pts2[-1]['value'], 'lower', 0.0) if prev2 else ('n-a', False)
    # r30 fix D5a: the area loop's rule itself (metric_trend): across regimes 'regime-change', never a regression
    mk = {'source': {'keyed_by': 'inbound_regime'}, 'better': 'lower', 'noise_rel': 0.0}
    mt1 = A.metric_trend(mk, [dict(p) for p in pts], t)
    mt2 = A.metric_trend(mk, [dict(p) for p in pts2], t)
    shutil.rmtree(t, ignore_errors=True)
    ok = (regs == ['outbound-only', 'inbound'] and prev is None and rc is True and prev2 is pts2[1] and not rc2 and reg2 is True
          and mt1[0] is None and mt1[1:] == ('regime-change', False) and mt2[0]['round'] == 'r29' and mt2[2] is True)
    return ok, (f'regimes {regs} prev {prev} change {rc}; same-regime prev {prev2 and prev2["round"]} regression {reg2}; '
                f'metric_trend {mt1[1:]} / {mt2[1:]}')


def nr3(base):
    A = M(base, 'intel/area_intel.py')
    booked = [{'severity': 'medium', 'state': 'booked'}, {'severity': 'low'}]
    open_ = [{'severity': 'medium'}]
    tri = A.load_triage(ROOT)
    s1, s2, s3 = A.area_state(booked, False, 4), A.area_state(open_ + booked, False, 4), A.area_state(booked, True, 4)
    ok = s1 == 'OK' and s2 == 'WATCH' and s3 == 'PAUSED' and len(tri) == 10 and set(tri.values()) == {'§7 B201'}
    return ok, f'booked {s1} open {s2} paused {s3}; triage {len(tri)} {set(tri.values())}'


def nr4(base):
    P = M(base, 'intel/peer_intel.py')
    T = P.trajectory
    c = [T([(None, 4999611, 1), (None, 5001682, 2), (None, 5033748, 3)]), T([(None, 7472150, 1), (None, 7472150, 9)]),
         T([(None, 7418671, 1), (None, 7418671, 2), (None, 7415465, 1)]), T([(None, 7537830, 5)])]
    D = [{'id': 'D2', 'findings': [{'peer': 'peer-a'}, {'peer': 'peer-b'}]}]
    peers = [{'peer': 'peer-a', 'lag': 404197, 'height': 7472150, 'top_version': 2, 'connected_s': 10, 'line': 5},
             {'peer': 'peer-b', 'lag': -40, 'height': 7876387, 'top_version': 3, 'connected_s': 10, 'line': 6}]
    prior = [{'file': 'peer_capture_A.jsonl', 'captured': 't1', 'peers': {'peer-a': (7472150, 3000, 7)}}]
    P.explain_d2(D, peers, prior, [('wall1', 7412675, 5), ('wall2', 7467516, 5), ('wall3', 7497836, 5)], 'walls.json', 'cap.jsonl')
    x = D[0]['explain'][0]
    ok = (c == ['SYNCING', 'STUCK', 'REGRESSED', 'ONE-READING'] and x['class'] == 'STUCK' and x['wall']['wall'] == 'wall2'
          and x['wall']['distance'] == 4634 and x['cites'] == ['peer_capture_A.jsonl:7', 'cap.jsonl:5'] and D[0]['classes'] == {'STUCK': 1})
    return ok, f"{c}; {x.get('what')}"


def nr5(base):
    a = ['198.51.100.21', '198.51.100.22', '203.0.113.23']
    ps = [KP.peer(ip, latency_ms=150.0) for ip in KP.NORMAL_IPS[:4]]
    ps += [KP.peer(ip, peer_id='00000000000000aa', latency_ms=r) for ip, r in zip(a, (67.0, 209.0, 120.0))]
    rep, *_ = KP.run(base, ps)
    f = (det(rep, 'D11')['findings'] or [{}])[0]
    ps2 = [KP.peer(ip, latency_ms=150.0) for ip in KP.NORMAL_IPS[:4]]
    ps2 += [KP.peer(ip, peer_id='00000000000000bb', latency_ms=r) for ip, r in zip(a[:2], (100.0, 104.0))]
    rep2, *_ = KP.run(base, ps2)
    f2 = (det(rep2, 'D11')['findings'] or [{}])[0]
    # r30 fix D2: the explain counts slots by dir (1 out + 2 in is not '3 of our outgoing slots')
    ps3 = [KP.peer(ip, latency_ms=150.0) for ip in KP.NORMAL_IPS[:4]]
    ps3 += [KP.peer(ip, peer_id='00000000000000cc', latency_ms=r, incoming=inc) for ip, r, inc in zip(a, (67.0, 209.0, 120.0), (True, False, True))]
    rep3, *_ = KP.run(base, ps3)
    w3 = ((det(rep3, 'D11').get('explain') or [{}])[0]).get('what', '')
    ok = (f.get('verdict') == 'UNEXPLAINED' and det(rep, 'D11')['grade'] == 'ANOMALY' and f2.get('verdict') == 'EXPLAINED'
          and det(rep2, 'D11')['grade'] == 'NORMAL' and w3.endswith('it holds 1 of our outgoing slot and 2 inbound connections'))
    return ok, f"divergent {f.get('verdict')} {f.get('rtt_ratio')} / agree {f2.get('verdict')} {det(rep2, 'D11')['grade']} / {w3[-60:]}"


def take(cap, n, who='m-top00001'):
    c = copy.deepcopy(cap)
    for h in c['headers'][:n]:
        h['miners'][9] = who
    return c


def nr6(base):
    C = M(base, 'intel/consensus_intel.py')
    cap = K24.synth()
    n = len(cap['headers'])
    lo = K25.G(K25.analyse(C, take(cap, round(0.34 * n))))['D15-concentration-final']
    hi = K25.G(K25.analyse(C, take(cap, round(0.45 * n))))['D15-concentration-final']
    ok = lo['grade'] == 'NORMAL' and hi['grade'] == 'ANOMALY' and lo['evidence'][0]['ci95'][0] < 1 / 3 < lo['evidence'][0]['share']
    return ok, f"0.34: {lo['grade']} {lo['evidence'][0]['ci95']} / 0.45: {hi['grade']}"


def nr7(base):
    def at(top, tot):
        ps = [KP.peer(ip) for ip in KP.NORMAL_IPS]
        rest = tot - top
        per = [rest // 5 + (1 if i < rest % 5 else 0) for i in range(5)]
        m = f'p2p_first_relay_total{{peer="{KP.NORMAL_IPS[0]}"}} {top}\n'
        m += ''.join(f'p2p_first_relay_total{{peer="{ip}"}} {v}\n' for ip, v in zip(KP.NORMAL_IPS[1:], per))
        rep, *_ = KP.run(base, ps, metrics=m + KP.base_metrics([]))
        return det(rep, 'D9')
    a, b = at(110, 217), at(500, 925)
    ok = a['grade'] == 'NORMAL' and b['grade'] == 'ANOMALY' and a['top_share'] > 0.5 and a['top_share_lo95'] < 0.5 < b['top_share_lo95']
    return ok, f"110/217 {a['grade']} lo {a.get('top_share_lo95')} / 500/925 {b['grade']} lo {b.get('top_share_lo95')}"


def nr8(base):
    C = M(base, 'intel/consensus_intel.py')
    cap = K24.synth()
    a1 = K25.side_event(cap, 100, 'a1')
    c = K25.r25(cap, alt_blocks=[a1], alt_count=8, gi_count=7)
    c2 = copy.deepcopy(c)
    c2.setdefault('log', {})['startups_ms'] = []
    c2['log']['events'] = []
    c2['log']['lines'] = 0                         # r30 fix D4: 'not read' is 0 lines scanned
    g = K25.G(K25.analyse(C, c2))['D20-alt-blocks']
    ok = g['grade'] == 'NORMAL' and 'log not read' in str(g['value']) and g['evidence'][0].get('log_read') is False
    return ok, f"{g['grade']} {g['value']}"


def rows(n=4, topo_off=None, pool=None):
    out = []
    for i in range(n):
        h = 7876000 + i * 16
        out.append({'t': f'T{i}', 'epoch': 1000.0 + 300 * i, 'cs': {'uptime_seconds': 100 + 300 * i},
                    'sync': {'height': h, 'topoheight': h + (1 if topo_off == i else 0), 'peers_incoming': 28},
                    'info': {'tx_pool_size': (pool or {}).get(i, 0)}})
    return out


PROM = ('p2p_sync_peer_holds_total 0\nblockchain_block_rejected_total{reason="other"} 0\n'
        'rpc_error_responses_total{code="-32031"} 0\ntx_policy_pool_full_refused_total 0\ntx_policy_evicted_total 0\n'
        'config_consensus_env_overrides 0\nmempool_count 0\n')


def nr9(base):
    LW = M(base, 'intel/live_window.py')
    MR = M(base, 'intel/metric_registry.py')
    p1 = PROM.replace('tx_policy_evicted_total 0', 'tx_policy_evicted_total 3')
    st = LW.row_status(rows(pool={2: 2}), [PROM, p1])
    want = {'B47': 'registered, no event', 'B57': 'registered, no event', 'B44': 'event seen', 'B42': 'event seen',
            'B19': 'event seen', 'B48': 'absent', 'B144': 'absent', 'B157': 'absent', 'B67': 'absent'}
    got = {k: st[k][0] for k in want}
    inv_ok = LW.invariant_lines(rows(), [PROM])[0].endswith('holds 4/4 samples')
    inv_bad = 'INVARIANT BROKEN in 1/4' in LW.invariant_lines(rows(topo_off=1), [PROM])[0]
    reg = {'families': [{'name': 'p2p_sync_peer_holds_total', 'source': 'p2p/x.go'}, {'name': 'p2p_new_total', 'source': 'p2p/x.go'},
                        {'name': 'transaction_size_histogram_bytes', 'source': 'blockchain/y.go'}, {'name': 'go_gc', 'source': 'vendored'}]}
    ab = MR.absent_families(reg, PROM)
    ln = LW.lazy_line([PROM], reg)
    # r30 fix D5c: check() reports K6 (the non-lazy absent family) and K7 (every allow-list entry not registered as a
    # vmhistogram: 11 here, the 12th is registered)
    reg_k = {'families': reg['families'][:3] + [{'name': 'go_gc', 'source': 'vendored'}]}
    reg_k['families'][2] = dict(reg_k['families'][2], type='vmhistogram')
    probs = MR.check(reg_k, root=Path(base), scrape_text=PROM)
    k6 = [m for k, m in probs if k == 'K6']
    k7 = [m for k, m in probs if k == 'K7']
    k_ok = (len(k6) == 1 and k6[0].startswith('p2p_new_total:') and len(k7) == len(MR.LAZY_BY_DESIGN) - 1
            and not any(m.startswith('LAZY_BY_DESIGN entry transaction_size_histogram_bytes ') for m in k7))
    ok = (got == want and inv_ok and inv_bad and ab == (['p2p_new_total'], ['transaction_size_histogram_bytes']) and k_ok
          and ln.startswith('INVARIANT BROKEN') and 'lazy_by_design absent 1' in ln and 'no event in 900 s / 48 blocks / 4 samples' in st['B47'][1])
    return ok, f'{got} inv {inv_ok} {inv_bad} absent {ab} | {ln[:80]} | K6 {len(k6)} K7 {len(k7)}'


def nr10(base):
    H = M(base, 'intel/hf4_watch.py')
    sha = lambda c: c * 40
    heads = {'main': sha('a'), 'community-dev': sha('b'), 'community-mainnet': sha('c'), 'community-testnet': sha('d')}
    tags = {'Release152': sha('e'), 'Release153': sha('f')}
    bh = {k: v[:8] for k, v in heads.items()}
    bt = {k: v[:8] for k, v in tags.items()}
    now = datetime.datetime(2026, 11, 9, 7, 45, tzinfo=datetime.timezone.utc)
    e = H.estimate(7_877_040, now)
    v1, _ = H.judge(heads, tags, bh, 2, bt, e)
    v2, r2 = H.judge(heads, tags, bh, 2, bt, H.estimate(8_000_000 - 29_999, now))
    v3, _ = H.judge(heads, dict(tags, Release154=sha('9')), bh, 2, bt, e, carriers=['Release154'])
    v4, r4 = H.judge(dict(heads, main=sha('7')), tags, bh, 2, bt, e)
    ln = 'aaaa' * 10 + '\trefs/heads/main\n' + 'bbbb' * 10 + '\trefs/tags/Release153\n' + 'cccc' * 10 + '\trefs/tags/Release153^{}\n'
    ph, pt = H.parse_ls_remote(ln)
    ok = (e['blocks_left'] == 122_960 and e['days'] == 26.4 and e['eta_utc'] == '2026-12-05T16:18Z' and v1 == 'UNCHANGED'
          and v2 == 'ESCALATE' and v3 == 'ESCALATE' and v4 == 'CHECK' and pt == {'Release153': 'cccc' * 10} and ph == {'main': 'aaaa' * 10})
    return ok, f"{e['blocks_left']} {e['days']} {e['eta_utc']} | {v1} {v2} {v3} {v4} {r4}"


def nr11(base):
    LW = M(base, 'intel/live_window.py')
    t = Path(tempfile.mkdtemp(prefix='r30nr11-'))
    clock = {'t': 1000.0}

    def rpc(m, p=None):
        return {'DERO.GetConsensusStats': {'uptime_seconds': 5}, 'DERO.GetSyncInfo': {'height': 7, 'topoheight': 7},
                'DERO.GetInfo': {'tx_pool_size': 0, 'note': 'seen 10.20.30.40'}}[m]

    def sleep(s):
        clock['t'] += s
        if clock['t'] > 1650:
            (t / 'STOP').write_text('x')
    seq = iter([{'contended': None}, {'contended': True, 'foreign_cores': 9.0}, {'contended': False, 'foreign_cores': 0.2}])
    n = LW.watch(t, 10_000.0, rpc, lambda: PROM, step=300, clock=lambda: clock['t'], sleep=sleep, contend=lambda: next(seq))
    txt = (t / 'series.jsonl').read_text()
    rs = LW.read_series(str(t / 'series.jsonl'))
    for r in rs:                                   # the registry is not in the copied base: plant the record's own list
        r['m']['absent'], r['m']['lazy_absent'] = [], []
    summ = LW.summarise(rs, [LW.prom_of(r) for r in rs]) or []
    b152 = next((l for l in summ if l.startswith('invariant B152')), '')
    prog = json.loads((t / 'progress.json').read_text())
    done = (t / 'DONE').read_text()
    st = (t / 'status.txt').read_text()
    shutil.rmtree(t, ignore_errors=True)
    ok = (n == 3 and prog['samples'] == 3 and '10.20.30.40' not in txt and '<peer>' in txt and 'stopped' in done
          and 'row B47: registered, no event' in st and 'holds over 3 scrape(s)' in b152
          and 'contention: 1 contended / 1 quiet / 1 unknown segments of 3' in st)
    return ok, f'{b152[:70]} samples {n} progress {prog.get("samples")} masked {"10.20.30.40" not in txt} done {done.strip()[-30:]}'


def nr12(base):
    """r30 fix D1 (+ D5b): hf4_watch main() exit codes from a saved ls-remote and a tags_all baseline: unchanged -> 0;
    Release152 removed + Release154 added (same count) -> 4; Release153 re-pointed -> 4; a partial (r29 hand format)
    baseline with the same count -> 0."""
    H = M(base, 'intel/hf4_watch.py')
    t = Path(tempfile.mkdtemp(prefix='r30nr12-'))
    heads = {'main': 'a' * 40, 'community-dev': 'b' * 40, 'community-mainnet': 'c' * 40, 'community-testnet': 'd' * 40}

    def ls(tags):
        return ''.join(f'{s}\trefs/heads/{h}\n' for h, s in heads.items()) + ''.join(f'{s}\trefs/tags/{n}\n' for n, s in tags.items())
    tags = {'Release151': '1' * 40, 'Release152': 'e' * 40, 'Release153': 'f' * 40}
    (t / 'base.json').write_text(json.dumps({'heads': heads, 'tags': 3, 'tags_all': {k: v[:8] for k, v in tags.items()}}))
    (t / 'partial.json').write_text(json.dumps({'heads': heads, 'tags': 3, 'newest_tags': {'Release153': 'f' * 8}}))
    cases = {'same': tags, 'swap': {'Release151': '1' * 40, 'Release153': 'f' * 40, 'Release154': '9' * 40},
             'repoint': dict(tags, Release153='7' * 40)}
    rc, out = {}, {}
    for k, tg in cases.items():
        (t / f'{k}.txt').write_text(ls(tg))
        o = t / f'{k}.out.json'
        rc[k] = quiet(H.main, ['--ls-remote-file', str(t / f'{k}.txt'), '--baseline', str(t / 'base.json'), '--tip', '7877040', '--out', str(o)])
        out[k] = json.loads(o.read_text())['reasons']
    rc['partial'] = quiet(H.main, ['--ls-remote-file', str(t / 'same.txt'), '--baseline', str(t / 'partial.json'), '--tip', '7877040'])
    shutil.rmtree(t, ignore_errors=True)
    sw = ' '.join(out['swap'])
    ok = (rc == {'same': 0, 'swap': 4, 'repoint': 4, 'partial': 0} and "added ['Release154']" in sw and "removed ['Release152']" in sw
          and any('Release153 re-pointed' in r for r in out['repoint']))
    return ok, f'{rc} swap {out["swap"]} repoint {out["repoint"]}'


def nr13(base):
    """r30 fix D3 (+ D5d): watch-start refuses BEFORE any side effect a dir with a space or quote, and a dir whose
    progress.json pid is alive (a running sampler: its STOP/DONE/plan are left as they are); a clean dir starts (fake
    popen). watch_match equals what ps shows of the relaunched argv, also for a dir the shell must quote ('(')."""
    import shlex
    LW = M(base, 'intel/live_window.py')
    t = Path(tempfile.mkdtemp(prefix='r30nr13-'))
    launched = []

    class Pr:
        pid = 4242

    def popen(argv):
        launched.append(argv)
        return Pr()
    sp = t / 'has space' / 'w'
    q = t / "it's"
    rc_sp = quiet(LW.watch_start, sp, 1, 300, 1200, 'http://127.0.0.1:10102/json_rpc', popen=popen)
    rc_q = quiet(LW.watch_start, q, 1, 300, 1200, 'http://127.0.0.1:10102/json_rpc', popen=popen)
    run = t / 'running'
    run.mkdir()
    (run / 'progress.json').write_text(json.dumps({'samples': 13, 'pid': 777}))
    (run / 'DONE').write_text('kept')
    rc_run = quiet(LW.watch_start, run, 1, 300, 1200, 'http://127.0.0.1:10102/json_rpc', popen=popen, alive=lambda p: p == 777)
    run_untouched = ((run / 'DONE').exists() and (run / 'DONE').read_text() == 'kept' and not (run / 'plan.json').exists()
                     and not (run / 'CMD').exists())
    dead = t / 'dead'
    dead.mkdir()
    (dead / 'progress.json').write_text(json.dumps({'samples': 3, 'pid': 778}))
    (dead / 'STOP').write_text('old')
    rc_dead = quiet(LW.watch_start, dead, 1, 300, 1200, 'http://127.0.0.1:10102/json_rpc', popen=popen, alive=lambda p: p == 777)
    started = (dead / 'plan.json').exists() and (dead / 'CMD').exists() and not (dead / 'STOP').exists() and len(launched) == 1
    nothing_made = not sp.exists() and not sp.parent.exists() and not q.exists()
    paren = '/var/r30/watch(1)'                                   # the shell quotes it, ps shows it plain
    argv = shlex.split(LW.watch_cmd(paren, 300, 'http://127.0.0.1:10102/json_rpc').split('&& exec ', 1)[1])
    ps_line = ' '.join(argv)
    match_ok = LW.watch_match(paren) in ps_line and LW.watch_match(t) in ' '.join(shlex.split(LW.watch_cmd(t, 300, 'u').split('&& exec ', 1)[1]))
    shutil.rmtree(t, ignore_errors=True)
    ok = (rc_sp == 2 and rc_q == 2 and nothing_made and rc_run == 2 and run_untouched and rc_dead == 0 and started and match_ok)
    return ok, (f'space {rc_sp} quote {rc_q} nothing made {nothing_made} | running {rc_run} untouched {run_untouched} | '
                f'dead pid {rc_dead} started {started} | match {match_ok}')


def nr14(base):
    """r30 fix D4: log_read is 'a log was scanned' (lines > 0): a log that was read but holds no derod start line is
    graded on its side (the planted alt block it lacks -> ANOMALY 'log 0 / node 1'); with 0 lines D20 says 'log not
    read' and D13 does not claim '0 in the whole log'."""
    C = M(base, 'intel/consensus_intel.py')
    cap = K24.synth()
    a1 = K25.side_event(cap, 100, 'a1')
    c = K25.r25(cap, alt_blocks=[a1], alt_count=1, gi_count=1)
    c.setdefault('log', {})['startups_ms'] = []
    c['log']['events'] = []
    c['log']['lines'] = 500                         # read, no start line, no alt block lines
    g_read = K25.G(K25.analyse(C, c))
    c0 = copy.deepcopy(c)
    c0['log']['lines'] = 0
    g_none = K25.G(K25.analyse(C, c0))
    d20r, d20n, d13n, d13r = g_read['D20-alt-blocks'], g_none['D20-alt-blocks'], g_none['D13-v2-remnant'], g_read['D13-v2-remnant']
    ok = (d20r['evidence'][0].get('log_read') is True and d20r['grade'] == 'ANOMALY' and 'log 0 / node 1' in str(d20r['value'])
          and d20n['evidence'][0].get('log_read') is False and 'log not read' in str(d20n['value'])
          and 'whole log' not in str(d13n['value']) and 'log not read' in str(d13n['value']) and 'in the whole log' in str(d13r['value']))
    return ok, f"read: {d20r['grade']} {d20r['value']} | none: {d20n['grade']} {d20n['value']} | D13 none: {d13n['value']}"


def nr15(base):
    """r30 B260: B152 over a window that starts at a derod START: a non-lazy family absent from the first scrape and
    present by the last is 'appeared during the window' (the invariant holds); absent from the LAST scrape still breaks
    it; a single scrape is judged alone as before"""
    LW = M(base, 'intel/live_window.py')
    reg = {'families': [{'name': 'p2p_sync_peer_holds_total', 'source': 'p2p/x.go'}, {'name': 'p2p_new_total', 'source': 'p2p/x.go'},
                        {'name': 'go_gc', 'source': 'vendored'}]}
    start = 'p2p_sync_peer_holds_total 0\n'
    later = start + 'p2p_new_total 4\n'
    grew = LW.lazy_line([start, later, later], reg)
    lost = LW.lazy_line([later, later, start], reg)
    never = LW.lazy_line([start, start], reg)
    one = LW.lazy_line([start], reg)
    ok = (grew.startswith('holds over 3 scrape(s)') and 'appeared during the window' in grew and 'p2p_new_total' in grew
          and lost.startswith('INVARIANT BROKEN') and never.startswith('INVARIANT BROKEN') and one.startswith('INVARIANT BROKEN'))
    return ok, f'grew {grew[:90]} | lost {lost[:50]} | never {never[:40]} | one {one[:40]}'


KATS = [('NR1', nr1), ('NR2', nr2), ('NR3', nr3), ('NR4', nr4), ('NR5', nr5), ('NR6', nr6), ('NR7', nr7), ('NR8', nr8),
        ('NR9', nr9), ('NR10', nr10), ('NR11', nr11), ('NR12', nr12), ('NR13', nr13), ('NR14', nr14),
        ('NR15', nr15)]
PI, AI, CI, LW, MR, HW = FILES[:6]
MUTATIONS = [
    ('NR1', PI, "    v3 = [p['lag'] for p in peers if isinstance(p.get('lag'), int) and (p.get('top_version') or 0) >= 3]",
     "    v3 = [p['lag'] for p in peers if isinstance(p.get('lag'), int)]", 'B201: a v2 peer moves lag_max again'),
    ('NR2', AI, "        if r_last is not None and r == r_last:\n            return p, False", "        return p, False",
     'B201: the trend compares across inbound regimes'),
    ('NR3', AI, "    sev = {p['severity'] for p in aprops if p.get('state') != 'booked'}", "    sev = {p['severity'] for p in aprops}",
     'B201: a booked proposal raises WATCH'),
    ('NR4', PI, "    if hs[-1] > hs[0]:\n        return 'SYNCING'", "    if hs[-1] > hs[0] + 10 ** 9:\n        return 'SYNCING'",
     'B201: a peer whose height rose reads as STUCK'),
    ('NR4', PI, "    if any(b < a for a, b in zip(hs, hs[1:])):", "    if False:", 'B201: a re-sync from a lower height is not REGRESSED'),
    ('NR5', PI, "verdict = 'EXPLAINED' if ratio is not None and ratio <= RTT_DIVERGE else 'UNEXPLAINED'",
     "verdict = 'EXPLAINED'", 'B201: divergent RTTs read as one multi-homed host'),
    ('NR6', CI, "        g = 'ANOMALY' if lo_ci > 1 / 3 else 'NORMAL'", "        g = 'ANOMALY' if sh > 1 / 3 else 'NORMAL'",
     'B201: D15 graded on the point share again'),
    ('NR7', PI, "'grade': 'ANOMALY' if lo > FIRST_RELAY_CONC else 'NORMAL', 'lo95'", "'grade': 'ANOMALY' if share > FIRST_RELAY_CONC else 'NORMAL', 'lo95'",
     'B201: D9 graded on the point share again'),
    ('NR8', CI, "    log_read = log_was_read(cap)\n", "    log_read = True\n", 'B201: an unread log reads as zero alt blocks'),
    ('NR9', LW, "        if not seen:\n            out[eid] = ('absent',", "        if False:\n            out[eid] = ('absent',",
     'B47: an absent series reads as no event (a 0 that is not a reading)'),
    ('NR9', LW, "    ne = sum(1 for h, t in pairs if h != t)", "    ne = 0", 'B61: topoheight != height not graded'),
    ('NR9', MR, "    return [n for n in miss if n not in LAZY_BY_DESIGN], [n for n in miss if n in LAZY_BY_DESIGN]",
     "    return [], [n for n in miss if n in LAZY_BY_DESIGN]", 'B152: a non-lazy absent family passes'),
    ('NR10', HW, "    if est and est['blocks_left'] < ESCALATE_BLOCKS:", "    if False:", 'B184: fewer than 30k blocks left does not escalate'),
    ('NR10', HW, "            check.append(f'head {h} moved {b[:8]} -> {cur[:8]}')", "            pass", 'B184: a moved main head is not reported'),
    ('NR11', LW, "    watch_rows = any((r.get('m') or {}).get('absent') is not None for r in rows)    # compact records: their own list",
     "    watch_rows = False", 'B152: a watch summary judges compact scrapes as full pages'),
    ('NR11', LW, "        rec['contention'] = contend()", "        pass", 'coordinator r30: sampler records do not flag contended segments'),
    ('NR11', LW, "    return json.loads(privkit.mask(json.dumps(rec)))     # masked before the line exists (rft §5)",
     "    return rec", 'B135 class: a watch record keeps a raw address'),
    # r30 fixes D1-D5 (the R30 node verifier's defects and surviving mutations)
    ('NR1', PI, "(p.get('top_version') or 0) >= 3]", "(p.get('top_version') or 3) >= 3]", 'verifier M9: an unknown top_version counts as v3'),
    ('NR5', PI, "        n_out = sum(1 for d_ in x['dirs'] if d_ == 'out')", "        n_out = len(pids)", "D2: every D11 address read as 'our outgoing slots' again"),
    ('NR2', AI, "    if regime_change:\n        d, reg_ = 'regime-change', False", "    if False:\n        d, reg_ = 'regime-change', False",
     'D5a B201: a cross-regime step is graded as a trend again'),
    ('NR9', MR, "            probs.append(('K6',", "            0 and probs.append(('K6',", 'D5c B152: a non-lazy absent family is not reported (K6)'),
    ('NR9', MR, "            probs.append(('K7',", "            0 and probs.append(('K7',", 'D5c B152: a stale allow-list entry is not reported (K7)'),
    ('NR12', HW, "        added = sorted(set(tags) - set(base_tags))", "        added = []", 'D1 B184: an added tag name is not reported'),
    ('NR12', HW, "        removed = sorted(set(base_tags) - set(tags))", "        removed = []", 'D1 B184: a removed tag name is not reported'),
    ('NR12', HW, "    complete = base_tag_count is None or len(base_tags) == base_tag_count",
     "    complete = False", 'D1 B184: back to the count rule (a removed + added swap reads UNCHANGED)'),
    ('NR12', HW, "            check.append(f'tag {t} re-pointed {sha} -> {tags[t][:8]}')", "            pass", 'D5b B184: a re-pointed tag is not reported'),
    ('NR13', LW, "    why = watch_start_refusal(d, alive)\n", "    why = None\n", 'D3: watch-start validates nothing'),
    ('NR13', LW, "    if pid is not None and alive(pid):", "    if False:", 'D3: watch-start restarts over a running sampler'),
    ('NR13', LW, 'return f"live_window.py watch --dir {d} --resume"',
     'import shlex; return f"live_window.py watch --dir {shlex.quote(str(d))} --resume"', 'D5d: watch_match quotes the dir again'),
    ('NR14', CI, "        return n > 0", "        return bool(lg.get('startups_ms'))", 'D4: log_read is the presence of a start line again'),
    ('NR14', CI, "                  if log_was_read(cap) else ", "                  if True else ", "D4: D13 says '0 in the whole log' with no log read"),
    ('NR15', LW, "        if i == len(prom) - 1:\n            bad |= set(a)", "        if True:\n            bad |= set(a)",
     'B260: a family absent only in the start-up scrape breaks B152 (the 19:30 false BROKEN)'),
    ('NR15', LW, "        if i == len(prom) - 1:\n            bad |= set(a)", "        if False:\n            bad |= set(a)",
     'B260: a family absent from the last scrape passes (G152 weakened)'),
    ('NR15', LW, "    early -= bad\n", "    early = set()\n", 'B260: the families that appeared during the window are not named'),
]
OWNERS = {'NR1': 'B201', 'NR2': 'B201', 'NR3': 'B201', 'NR4': 'B201', 'NR5': 'B201', 'NR6': 'B201', 'NR7': 'B201', 'NR8': 'B201',
          'NR9': 'B47/B61/B152', 'NR10': 'B184', 'NR11': 'B135', 'NR12': 'B184', 'NR13': 'B47 (sampler)', 'NR14': 'B201', 'NR15': 'B260'}


def copy_base():
    d = Path(tempfile.mkdtemp(prefix='r30nrm-'))
    for f in FILES:
        (d / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HARNESS / f, d / f)
    (d / 'runtime').mkdir(exist_ok=True)
    return d


def old_code(rev):
    """r30 rule (§2.20 (b)): each KAT fails on the old behaviour. The files of `rev` (git show; a file new since then is
    absent, so its KAT fails by crashing) are run through every KAT; exit 0 when every KAT fails."""
    import subprocess
    d = Path(tempfile.mkdtemp(prefix='r30nrold-'))
    for f in FILES:
        (d / f).parent.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(['git', '-C', str(ROOT), 'show', f'{rev}:harness/{f}'], capture_output=True, text=True, timeout=60)
        if r.returncode == 0:
            (d / f).write_text(r.stdout)
    passed = []
    for name, fn in KATS:
        try:
            ok, det_ = fn(d)
        except Exception as e:                                    # noqa: BLE001 — absent function = old behaviour
            ok, det_ = False, f'{type(e).__name__}: {e}'
        print(f"{'PASSES on old code' if ok else 'fails on old code '} {name} {str(det_)[:160]}")
        if ok:
            passed.append(name)
    shutil.rmtree(d, ignore_errors=True)
    print(f'\nR30 node KATs on {rev}: {len(KATS) - len(passed)}/{len(KATS)} fail on the old code' + (f' (pass: {passed})' if passed else ''))
    return 3 if passed else 0


def main():
    if '--old-code' in sys.argv:
        return old_code(sys.argv[sys.argv.index('--old-code') + 1])
    fails = 0
    base = copy_base()
    for name, fn in KATS:
        try:
            ok, d = fn(base)
        except Exception as e:                                    # noqa: BLE001
            ok, d = False, f'{type(e).__name__}: {e}'
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name} {str(d)[:400]}")
    shutil.rmtree(base, ignore_errors=True)
    missed, byname = 0, dict(KATS)
    for kat, f, find, repl, why in MUTATIONS:
        d = copy_base()
        p = d / f
        text = p.read_text()
        if text.count(find) != 1:
            print(f'  ??      {kat}: {why} — find text occurs {text.count(find)} times')
            missed += 1
            shutil.rmtree(d, ignore_errors=True)
            continue
        p.write_text(text.replace(find, repl))
        try:
            ok2, _ = byname[kat](d)
            verdict = 'MISSED ' if ok2 else 'proved '
        except Exception as e:                                     # noqa: BLE001 — a crash proves nothing: INVALID
            ok2, verdict = True, f'INVALID ({type(e).__name__})'
        print(f'  {verdict} {kat}: {why}')
        missed += ok2
        shutil.rmtree(d, ignore_errors=True)
    print(f'\nR30 node KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)} · mutations coupled 0')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
