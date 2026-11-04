#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the r25 (peers) half of the network-peer observatory: the detectors read
the node's own CO24-N1..N7 counters and GetPeerInfo fields (p2p/peer_observe.go) instead of log lines, the B72
per-node clock cross-check, the B47 sync-hold detector D15, the gap proposals that close themselves, and the B71
source pseudonymisation of log_intel and mine_triage snapshots.

  PI14 a normal r25-shaped capture (all counters 0) is flagged by no detector, D15 included; evidence mode 'counter'
  PI15 D4 from the counter: short_answers 2 on one connection -> OBSERVED; with counters, a log short answer from
       BEFORE the current run is history (NORMAL), one IN the current run stays OBSERVED
  PI16 D5 from the counter: objects_unserved 25 on one peer -> ANOMALY; 25 on each of three -> NORMAL
  PI17 D7 from the counter: penalty_events 3 + reasons on a connection, an offender record (a CIDR scope, not
       connected) and p2p_penalty_events_total{reason} -> OBSERVED; a reason that is not a plain token is dropped
  PI18 D10 per connection: inv_txids_clipped 40 -> OBSERVED naming that peer
  PI19 D13 from the counter: 700 Chain requests in 60 min -> ANOMALY; 30 in 60 min -> NORMAL
  PI20 D15: sync_failures 2 / hold 60 s -> OBSERVED; a pre-r25 capture -> pending (never NORMAL)
  PI21 D3 from GetPeerInfo.stuck_held -> OBSERVED with the pseudonym of the held address
  PI22 B72: one node id at -181.2 ms / 221.9 ms RTT on one address and -0.6 ms / 183.3 ms on another -> D6 NORMAL
       (path asymmetry); beyond the bound on both addresses -> ANOMALY
  PI23 gap proposals: with the closing lines in the tree every CO24-N* is 'implemented (r25)' and anchored on that
       line; in a tree without them they are 'open'
  PI24 privacy: no address of the r25 lists (offender scope, stuck_held address, ban_reasons keys) reaches the outputs
  PI25 B71: log_intel's snapshot and mine_triage's scrub_snapshot carry pseudonyms, not the LAN/peer addresses of
       their input; reserved addresses are kept

All inputs are synthetic (RFC 5737 / RFC 2544 / 240.0.0.0/4; one RFC 1918 address as the 'not reserved' input of
PI25); temp dirs only.
  python3 -I harness/kat/test_peer_intel_r25.py   # exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught
A mutation that crashes the KAT is INVALID, not caught.
"""
import importlib.util, json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
FILES = ('intel/peer_intel.py', 'miners/mine_peers.py', 'miners/minelib.py', 'kit/privkit.py', 'intel/log_intel.py',
         'miners/mine_triage.py')


def _r24():
    sp = importlib.util.spec_from_file_location('peer_intel_kat_r24_helpers', HARNESS / 'kat/test_peer_intel_r24.py')
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


K = _r24()
NORMAL_IPS, OUR_H = K.NORMAL_IPS, K.OUR_H
R25 = {'penalty_score': 0, 'penalty_bans': 0, 'penalty_events': 0, 'last_offences': [], 'chain_requests_served': 0,
       'chain_blocks_served': 0, 'inv_txids_clipped': 0, 'objects_unserved': 0, 'short_answers': 0, 'sync_failures': 0,
       'sync_hold_seconds': 0}


def peer(ip, **k):
    p = K.peer(ip, **R25)
    p.update(k)
    return p


def write_cap(d, peers, lists=None, reasons=None, metrics=None, **kw):
    K.write_cap(d, peers, metrics=metrics, **kw)
    g = json.loads((d / 'GetPeerInfo.json').read_text())
    g['result'].update({'offenders': [], 'bans': [], 'ban_count': 0, 'ban_sources': {}, 'stuck_held': []})
    g['result'].update(lists or {})
    (d / 'GetPeerInfo.json').write_text(json.dumps(g))
    if reasons is not None:
        (d / 'ban_reasons.json').write_text(json.dumps(reasons))
    return d


def base_metrics(peers, extra=''):
    m = ''.join(f'p2p_first_relay_total{{peer="{p["address"].split(":")[0]}"}} 10\n' for p in peers)
    m += 'p2p_inv_txids_over_budget_total 0\np2p_handshake_failures_total 3\np2p_penalty_bans_total 0\n'
    m += 'p2p_chain_requests_served_total 0\np2p_chain_request_blocks_total 0\np2p_chain_requests_refused_total 0\n'
    m += ''.join(f'p2p_penalty_events_total{{reason="{r}"}} 0\n' for r in ('busy', 'timeout', 'invalid_pow'))
    return m + extra


def load(base):
    sp = importlib.util.spec_from_file_location(f'peer_intel_kat25_{id(base)}', base / 'intel/peer_intel.py')
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


def tmp():
    return Path(tempfile.mkdtemp(prefix='r25pi-'))


def det(rep, did):
    return next(d for d in rep['detectors'] if d['id'] == did)


def run(base, peers, log_extra=(), **kw):
    P = load(base)
    t = tmp()
    if 'metrics' not in kw:
        kw['metrics'] = base_metrics(peers)
    cap = write_cap(t / 'c', peers, **kw)
    rep, cl, xl, ps = K.analyse(P, cap, K.write_log(t, list(log_extra)))
    shutil.rmtree(t, ignore_errors=True)
    return rep, cl, xl, ps


# ───────────────────────────── KATs ─────────────────────────────
def pi14(base):
    rep, *_ = run(base, [peer(ip) for ip in NORMAL_IPS])
    bad = [(d['id'], d['grade']) for d in rep['detectors'] if d['grade'] != 'NORMAL']
    ev = sorted(d['id'] for d in rep['detectors'] if d.get('evidence') == 'counter')
    want = {'D4', 'D5', 'D7', 'D10', 'D13', 'D15'}
    return not bad and want <= set(ev) and rep['kpis']['evidence_mode'] == 'counter', f'flagged {bad} counter {ev} mode {rep["kpis"]["evidence_mode"]}'


def pi15(base):
    ps = [peer(ip) for ip in NORMAL_IPS[:5]] + [peer('240.0.0.9', short_answers=2)]
    rep, _, _, pz = run(base, ps)
    d = det(rep, 'D4')
    ok1 = d['grade'] == 'OBSERVED' and [f['peer'] for f in d['findings'] if f['grade'] == 'OBSERVED'] == [pz.peer('240.0.0.9')]
    # a log line before the current run's banner is history once the counter exists; one after it is not
    old = K.logline(1, 'Call failed GetObject', '198.51.100.1', error='peer answered 0 blocks for 4 requested')
    banner = json.dumps({'L': 'INFO', 'T': '2026-11-02T09:30:00.000-0800', 'N': 'derod', 'C': 'derod/main.go:160',
                         'M': 'DERO HE daemon :  It is an alpha version, use it for testing/evaluations purpose only.'})
    rep2, *_ = run(base, [peer(ip) for ip in NORMAL_IPS], [old, banner])
    rep3, *_ = run(base, [peer(ip) for ip in NORMAL_IPS], [banner, old])
    g2, g3 = det(rep2, 'D4')['grade'], det(rep3, 'D4')['grade']
    return ok1 and g2 == 'NORMAL' and g3 == 'OBSERVED', f"counter {d['grade']} history {g2} current {g3}"


def pi16(base):
    ps = [peer(ip) for ip in NORMAL_IPS[:5]] + [peer('240.0.0.9', objects_unserved=25)]
    g1 = det(run(base, ps)[0], 'D5')['grade']
    ps2 = [peer(ip, objects_unserved=25) for ip in NORMAL_IPS[:3]] + [peer(ip) for ip in NORMAL_IPS[3:]]
    g2 = det(run(base, ps2)[0], 'D5')['grade']
    return g1 == 'ANOMALY' and g2 == 'NORMAL', f'one {g1} spread {g2}'


def pi17(base):
    ps = [peer(ip) for ip in NORMAL_IPS[:5]] + [peer('240.0.0.9', penalty_events=3, penalty_score=42.5,
                                                     last_offences=[{'reason': 'timeout', 'at': 1}, {'reason': 'busy 10.0.0.1', 'at': 1},
                                                                    {'reason': 'malformed_request', 'at': 1}])]
    off = [{'scope': '198.51.100.0/24', 'score': 0, 'bans': 2, 'events': 9, 'banned_for_seconds': 300,
            'last_offences': [{'reason': 'invalid_pow', 'at': 1}]}]
    rep, cl, _, pz = run(base, ps, lists={'offenders': off}, metrics=base_metrics(ps, 'p2p_penalty_events_total{reason="busy"} 2\n'))
    d = det(rep, 'D7')
    who = {f['peer'] for f in d['findings'] if f['grade'] == 'OBSERVED'}
    conn = next((f for f in d['findings'] if f['peer'] == pz.peer('240.0.0.9')), {})
    ok = (d['grade'] == 'OBSERVED' and pz.peer('240.0.0.9') in who and pz.entry('198.51.100.0/24') in who and '(node-wide)' in who
          and 'timeout' in conn.get('what', '') and '10.0.0.1' not in json.dumps(rep) and '10.0.0.1' not in '\n'.join(cl))
    return ok, f"{d['grade']} {sorted(who)} {conn.get('what', '')[:90]}"


def pi18(base):
    ps = [peer(ip) for ip in NORMAL_IPS[:5]] + [peer('240.0.0.9', inv_txids_clipped=40)]
    rep, _, _, pz = run(base, ps)
    d = det(rep, 'D10')
    got = [f['peer'] for f in d['findings'] if f['grade'] == 'OBSERVED']
    return d['grade'] == 'OBSERVED' and got == [pz.peer('240.0.0.9')], f"{d['grade']} {got}"


def pi19(base):
    hot = [peer(ip) for ip in NORMAL_IPS[:5]] + [peer('240.0.0.9', chain_requests_served=700, chain_blocks_served=9000, connected_seconds=3600)]
    calm = [peer(ip) for ip in NORMAL_IPS[:5]] + [peer('240.0.0.9', chain_requests_served=30, chain_blocks_served=300, connected_seconds=3600)]
    g1, g2 = det(run(base, hot)[0], 'D13')['grade'], det(run(base, calm)[0], 'D13')['grade']
    return g1 == 'ANOMALY' and g2 == 'NORMAL', f'hot {g1} calm {g2}'


def pi20(base):
    ps = [peer(ip) for ip in NORMAL_IPS[:5]] + [peer('240.0.0.9', sync_failures=2, sync_hold_seconds=60)]
    g1 = det(run(base, ps)[0], 'D15')['grade']
    P = load(base)
    t = tmp()
    rep, *_ = K.analyse(P, K.write_cap(t / 'c', [K.peer(ip) for ip in NORMAL_IPS]), K.write_log(t))
    shutil.rmtree(t, ignore_errors=True)
    g2 = det(rep, 'D15')['grade']
    return g1 == 'OBSERVED' and g2 == 'pending', f'held {g1} pre-r25 {g2}'


def pi21(base):
    held = [{'address': '198.51.100.44', 'strikes': 3, 'held_seconds': 5000, 'height': 7_537_830}]
    rep, cl, _, pz = run(base, [peer(ip) for ip in NORMAL_IPS], lists={'stuck_held': held})
    d = det(rep, 'D3')
    got = [f['peer'] for f in d['findings'] if f.get('source') == 'GetPeerInfo.stuck_held']
    return d['grade'] == 'OBSERVED' and got == [pz.peer('198.51.100.44')] and '198.51.100.44' not in '\n'.join(cl), f"{d['grade']} {got}"


def pi22(base):
    nid = '00000000000093aa'
    a = peer('192.0.2.201', peer_id=nid, clock_offset_ms=-181.2, latency_ms=221.9)
    b = peer('198.51.100.201', peer_id=nid, clock_offset_ms=-0.6, latency_ms=183.3)
    g1 = det(run(base, [peer(ip) for ip in NORMAL_IPS[:4]] + [a, b])[0], 'D6')['grade']
    b2 = peer('198.51.100.201', peer_id=nid, clock_offset_ms=-170.0, latency_ms=183.3)
    g2 = det(run(base, [peer(ip) for ip in NORMAL_IPS[:4]] + [a, b2])[0], 'D6')['grade']
    return g1 == 'NORMAL' and g2 == 'ANOMALY', f'asymmetric {g1} both-beyond {g2}'


def pi23(base):
    P = load(base)
    st = {g['id']: g for g in P.proposals({}, {}, ROOT)}
    impl = all(g['status'] == 'implemented (r25)' and g['anchor']['line'] for g in st.values())
    t = tmp()
    for f, q, *_ in [(g['gap_anchor']['file'], g['gap_anchor']['quote']) for g in st.values() if 'gap_anchor' in g]:
        (t / f).parent.mkdir(parents=True, exist_ok=True)
        with open(t / f, 'a') as fh:
            fh.write(q + '\n')
    st2 = {g['id']: g for g in P.proposals({}, {}, t)}
    shutil.rmtree(t, ignore_errors=True)
    opened = all(g['status'] == 'open' for g in st2.values())
    return impl and opened and len(st) == 7, f"implemented {impl} ({[g['status'] for g in st.values()][:2]}) open-without-fix {opened}"


def pi24(base):
    P = load(base)
    t = tmp()
    priv = t / 'priv'
    priv.mkdir()
    (priv / 'salt').write_text('kat-salt-25\n')
    secrets = ['198.51.100.61', '198.51.100.0/24', '203.0.113.62']
    ps = [peer(ip) for ip in NORMAL_IPS]
    cap = write_cap(t / 'c', ps, metrics=base_metrics(ps),
                    lists={'offenders': [{'scope': '198.51.100.0/24', 'score': 1, 'bans': 1, 'events': 1, 'banned_for_seconds': 1, 'last_offences': []}],
                           'stuck_held': [{'address': '198.51.100.61', 'strikes': 1, 'held_seconds': 9, 'height': 1}],
                           'ban_sources': {'score': 1}},
                    bans={'203.0.113.62': 1893600000}, reasons={'203.0.113.62': {'source': 'score', 'reason': 'invalid_pow', 'at': 1}})
    out = t / 'out'
    rep, capf, logxf = P.run(cap, priv, [K.write_log(t)], root=ROOT, out_dir=out)
    text = '\n'.join((out / f).read_text() for f in ('peer_intel.json', capf.name, logxf.name, 'peer_series.jsonl'))
    hit = [s for s in secrets if s in text]
    src = [b.get('source') for b in rep['census']['bans']]
    shutil.rmtree(t, ignore_errors=True)
    return not hit and src == ['score'], f'leaked {hit} ban sources {src}'


def pi25(base):
    t = tmp()
    lan, doc = '10.11.12.13', '192.0.2.5'
    env = dict(os.environ, DERO_PEER_PRIVATE=str(t / 'priv'))
    log = t / 'derod.log'
    lines = [json.dumps({'L': 'INFO', 'T': '2026-11-02T09:00:00.000-0800', 'N': 'derod', 'C': 'derod/main.go:160',
                         'M': 'DERO HE daemon :  It is an alpha version, use it for testing/evaluations purpose only.',
                         'Arguments': {'--add-priority-node': [f'{lan}:11011', f'{doc}:11011']}})]
    lines += [json.dumps({'L': 'DEBUG', 'T': f'2026-11-02T09:{1 + i // 60:02d}:{i % 60:02d}.000-0800', 'N': 'P2P', 'C': 'p2p/controller.go:338',
                          'M': 'backing off from this connection', 'ip': f'{lan}:11011'}) for i in range(60)]
    log.write_text('\n'.join(lines) + '\n')
    r = subprocess.run([sys.executable, '-I', str(base / 'intel/log_intel.py'), '--files', str(log), '--json-only', '--no-metrics'],
                       env=env, capture_output=True, text=True, timeout=120)
    outs = sorted((base / 'runtime').glob('logintel_*.json'))
    snap = outs[-1].read_text() if outs else ''
    for o in outs:
        o.unlink()
    ok1 = r.returncode == 0 and snap and lan not in snap and 'peer-' in snap and doc in snap
    # mine_triage.scrub_snapshot (imported with its minelib from the copied tree)
    sys.path.insert(0, str(base / 'miners'))
    for m in ('minelib', 'mine_triage_kat25', 'privkit'):
        sys.modules.pop(m, None)
    sp = importlib.util.spec_from_file_location('mine_triage_kat25', base / 'miners/mine_triage.py')
    MT = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(MT)
    sys.path.pop(0)
    s = MT.scrub_snapshot({'facts': [f'peer {lan} address={lan}:11011 goodcount=1', f'ban_list holds 1 address(es): {lan}, {doc}']}, salt='kat-salt-25')
    js = json.dumps(s)
    ok2 = lan not in js and 'peer-' in js and doc in js
    shutil.rmtree(t, ignore_errors=True)
    return ok1 and ok2, f'log_intel rc {r.returncode} clean {bool(snap) and lan not in snap} triage clean {ok2} {r.stderr[-200:]}'


KATS = [('PI14', pi14), ('PI15', pi15), ('PI16', pi16), ('PI17', pi17), ('PI18', pi18), ('PI19', pi19), ('PI20', pi20),
        ('PI21', pi21), ('PI22', pi22), ('PI23', pi23), ('PI24', pi24), ('PI25', pi25)]

PI = 'intel/peer_intel.py'
MUTATIONS = [
    ('PI14', PI, "    ctr = bool(peers) and all(k in (pi.get('peers') or [{}])[0] for k in R25_PEER_FIELDS)", "    ctr = False", 'counters are never read (log-only evidence on an r25 node)'),
    ('PI15', PI, "                if p.get('short_answers'):", "                if p.get('short_answers', 0) > 5:", 'the short-answer counter is ignored below 6'),
    ('PI15', PI, "            g = 'OBSERVED' if not ctr or e['n_current'] else 'NORMAL'", "            g = 'OBSERVED'", 'pre-run log history is graded as a current observation'),
    ('PI16', PI, "                g = 'ANOMALY' if n >= 20 and (cmed is None or n > REMOTE_UNSERVED_MULT * max(cmed, 1)) else 'NORMAL'", "                g = 'NORMAL'", 'the unserved counter never flags'),
    ('PI16', PI, "                g = 'ANOMALY' if n >= 20 and (cmed is None or n > REMOTE_UNSERVED_MULT * max(cmed, 1)) else 'NORMAL'", "                g = 'ANOMALY' if n >= 20 else 'NORMAL'", 'evenly spread unserved counts are flagged'),
    ('PI17', PI, "                if p.get('penalty_events'):", "                if False:", 'per-connection offences are not read'),
    ('PI17', PI, "            for o in off_rows:\n                if o['scope'] not in", "            for o in []:\n                if o['scope'] not in", 'the offender records are not read'),
    ('PI17', PI, "REASON_RX = re.compile(r'^[a-z0-9_]{1,40}$')", "REASON_RX = re.compile(r'.*')", 'a reason carrying an address is rendered'),
    ('PI18', PI, "                if p.get('inv_txids_clipped'):", "                if False:", 'per-connection INV clips are not attributed'),
    ('PI19', PI, "                    g = 'ANOMALY' if n / mins > CHAIN_REQ_PER_MIN else 'NORMAL'", "                    g = 'NORMAL'", 'chain-request amplification is never flagged'),
    ('PI19', PI, "CHAIN_REQ_PER_MIN = 6.0 ", "CHAIN_REQ_PER_MIN = 0.1 ", 'an ordinary request rate is flagged'),
    ('PI20', PI, "            if p.get('sync_failures') or p.get('sync_hold_s'):", "            if False:", 'sync holds are not read'),
    ('PI20', PI, "            d['grade'] = 'pending'\n            d['why'] = 'the capture carries no sync_failures field (a pre-r25 derod)'", "            d['grade'] = 'NORMAL'\n            d['why'] = 'the capture carries no sync_failures field (a pre-r25 derod)'", 'a missing field reads as NORMAL'),
    ('PI21', PI, "        for h in held_rows:", "        for h in []:", 'the listed stuck holds are not read'),
    ('PI22', PI, "                if calm:", "                if False:", 'the per-node cross-check is skipped (B72)'),
    ('PI22', PI, "                calm = [q for q in others if abs(q['clock_offset_ms']) - (q.get('latency_ms') or 0.0) / 2 <= CLOCK_FUTURE_MS]", "                calm = others", 'any second address excuses the offset'),
    ('PI23', PI, "        if il:\n            g['status'] = 'implemented (r25)'", "        if False:\n            g['status'] = 'implemented (r25)'", 'a shipped gap stays proposed'),
    ('PI23', PI, "        il = _line_of(root, *imp) if imp else None", "        il = 1", 'a gap counts as implemented without its closing line'),
    ('PI24', PI, "        held_rows.append({'src': 'GetPeerInfo.stuck_held', 'peer': ps.peer(h.get('address')),", "        held_rows.append({'src': 'GetPeerInfo.stuck_held', 'peer': h.get('address'),", 'a held address is written raw'),
    ('PI24', PI, "        return ps.entry(k) if '/' in str(k) else ps.peer(k)", "        return str(k)", 'an offender scope is written raw'),
    ('PI24', PI, "'source': next((x for x in [((cap.get('ban_reasons.json') or {}).get(k) or {}).get('source')] if x and REASON_RX.match(str(x))), None)})", "'source': None})", 'ban sources are not read from the sidecar'),
    ('PI25', 'intel/log_intel.py', "    report = privacy_scrub(report)                                       # r25 (B71): no peer address in the snapshot\n", "", 'log_intel writes raw peer addresses (B71)'),
    ('PI25', 'miners/mine_triage.py', "    return privkit.pseudonymise_obj(snap, salt or privkit.load_salt())", "    return snap", 'the triage snapshot keeps raw peer addresses (B71)'),
]


def copy_base():
    d = Path(tempfile.mkdtemp(prefix='r25pim-'))
    for f in FILES:
        (d / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HARNESS / f, d / f)
    (d / 'runtime').mkdir(exist_ok=True)
    return d


def main():
    fails = 0
    base = copy_base()
    for name, fn in KATS:
        try:
            ok, det_ = fn(base)
        except Exception as e:                                    # noqa: BLE001
            ok, det_ = False, f'{type(e).__name__}: {e}'
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name} {str(det_)[:300]}")
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
    print(f'\nR25 peer-intel KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
