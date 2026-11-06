#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the r27 (p2p-config) changes to the network-peer observatory
(harness/intel/peer_intel.py, artifacts/dero-rft.md §0.7.2): the D5/D9/D11 ANOMALYs of the R26 measurement and of the
R27 Part A read, re-read.

  PI26 D5 with the r25 counters: 22 'could not serve' log lines from BEFORE the current run and 3 in it grade NORMAL
       (graded on the current run, labelled log-history: the D4 rule of PI15); 25 in the current run grade ANOMALY;
       on a pre-r25 capture (no counters) the whole log is graded, as before
  PI27 D11 is anchored on the handshake peer_id field of p2p/peer_info.go, not on the clock field D6 reads
  PI28 explanations: D9 names the top relay's RTT rank and the rank-1 peer's first relays; D5 names unserved per first
       relay of this run and that it is D9's top relay; D11 says whether a pair shares one /16 and one version; an
       explanation never changes a grade; no address reaches the report

All inputs synthetic (RFC 5737 / RFC 2544 / 240.0.0.0/4), temp dirs only.
  python3 -I harness/kat/test_peer_intel_r27.py   # exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught
A mutation that crashes the KAT is INVALID, not caught.
"""
import importlib.util, json, re, shutil, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent


def _load(name, rel):
    sp = importlib.util.spec_from_file_location(name, HARNESS / rel)
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


K25 = _load('peer_intel_kat_r25_helpers', 'kat/test_peer_intel_r25.py')
K = K25.K
NORMAL_IPS = K.NORMAL_IPS
BANNER = json.dumps({'L': 'INFO', 'T': '2026-11-02T09:30:00.000-0800', 'N': 'derod', 'C': 'derod/main.go:160',
                     'M': 'DERO HE daemon :  It is an alpha version, use it for testing/evaluations purpose only.'})
HOT = '240.0.0.9'


def unserved_lines(n, ip=HOT):
    return [K.logline(i, 'Call failed GetObject: peer could not serve the object', ip, peer_error='Invalid Major Version in Block')
            for i in range(n)]


def det(rep, did):
    return next(d for d in rep['detectors'] if d['id'] == did)


def pi26(base):
    ps = [K25.peer(ip) for ip in NORMAL_IPS[:5]] + [K25.peer(HOT, objects_unserved=4)]
    hist = det(K25.run(base, ps, unserved_lines(22) + [BANNER] + unserved_lines(3))[0], 'D5')
    cur = det(K25.run(base, ps, [BANNER] + unserved_lines(25))[0], 'D5')
    P = K25.load(base)
    t = Path(tempfile.mkdtemp(prefix='r27pi-'))
    old = det(K.analyse(P, K.write_cap(t / 'c', [K.peer(ip) for ip in NORMAL_IPS[:5]] + [K.peer(HOT)]),
                        K.write_log(t, unserved_lines(25) + [BANNER]))[0], 'D5')
    shutil.rmtree(t, ignore_errors=True)
    h_src = {f.get('source') for f in hist['findings'] if 'replies in the log' in f['what']}
    ok = hist['grade'] == 'NORMAL' and cur['grade'] == 'ANOMALY' and old['grade'] == 'ANOMALY' and 'log-history' in h_src
    return ok, f"history {hist['grade']} {h_src} current {cur['grade']} pre-r25 {old['grade']}"


def pi27(base):
    rep, *_ = K25.run(base, [K25.peer(ip) for ip in NORMAL_IPS])
    r = det(rep, 'D11')['rule']
    lines = (ROOT / 'p2p/peer_info.go').read_text().splitlines()
    at = lines[r['line'] - 1] if r.get('line') else ''
    return r.get('status') == 'OK' and 'json:"peer_id"' in at and 'clock' not in at, f"{r.get('file')}:{r.get('line')} {at.strip()[:60]}"


def pi28(base):
    a, b, c = '198.51.100.21', '198.51.100.22', '203.0.113.23'
    ps = [K25.peer(ip, latency_ms=150.0 + i) for i, ip in enumerate(NORMAL_IPS[:4])]
    ps += [K25.peer(HOT, objects_unserved=30, latency_ms=60.0), K25.peer('198.18.0.40', latency_ms=40.0)]
    ps += [K25.peer(a, peer_id='00000000000000aa', latency_ms=200.0), K25.peer(b, peer_id='00000000000000aa', latency_ms=201.0)]
    m = ''.join(f'p2p_first_relay_total{{peer="{p["address"].split(":")[0]}"}} {80 if p["address"].startswith(HOT) else 3}\n' for p in ps)
    m += K25.base_metrics([])
    rep, cl, xl, pz = K25.run(base, ps, metrics=m)
    d5, d9, d11 = det(rep, 'D5'), det(rep, 'D9'), det(rep, 'D11')
    e9 = (d9.get('explain') or [{}])[0]
    e5 = next((x for x in d5.get('explain') or [] if x.get('peer') == pz.peer(HOT)), {})
    e11 = (d11.get('explain') or [{}])[0]
    ok9 = e9.get('peer') == pz.peer(HOT) and e9.get('latency_rank') == 2 and e9.get('fastest_first_relays') == 3 and e9.get('also_d5') is True
    ok5 = e5.get('is_d9_top') is True and e5.get('first_relays_run') == 80 and e5.get('unserved_per_first_relay') == round(30 / 80, 4)
    ok11 = e11.get('same_netgroup') is True and e11.get('same_version') is True
    grades = (d5['grade'], d9['grade'], d11['grade']) == ('ANOMALY', 'ANOMALY', 'ANOMALY')
    # a pair on two /16s reads so
    ps2 = [x for x in ps if not x['address'].startswith(b)] + [K25.peer(c, peer_id='00000000000000aa', latency_ms=201.0)]
    m2 = m.replace(b, c)
    rep2, cl2, xl2, _ = K25.run(base, ps2, metrics=m2)
    e11b = (det(rep2, 'D11').get('explain') or [{}])[0]
    js = json.dumps(rep) + '\n'.join(cl) + json.dumps(rep2) + '\n'.join(cl2)
    clean = not re.search(r'\b\d{1,3}(\.\d{1,3}){3}\b', js)  # no address and no /16 of one
    ok = ok9 and ok5 and ok11 and grades and e11b.get('same_netgroup') is False and clean
    return ok, f"d9 {ok9} {e9.get('latency_rank')} {e9.get('fastest_first_relays')} d5 {ok5} {e5} d11 {ok11} two-/16 {e11b.get('same_netgroup')} grades {grades} clean {clean}"


KATS = [('PI26', pi26), ('PI27', pi27), ('PI28', pi28)]
PI = 'intel/peer_intel.py'
MUTATIONS = [
    ('PI26', PI, "        key = 'n_current' if ctr else 'n'", "        key = 'n'", 'pre-run log history is graded again with the counter (r26 D5)'),
    ('PI26', PI, "        key = 'n_current' if ctr else 'n'", "        key = 'n_current'", 'a pre-r25 capture grades only the current run'),
    ('PI26', PI, "'source': 'log-history' if ctr else 'log', ", "'source': 'log', ", 'history is not labelled as history'),
    ('PI27', PI, "det('D11', 'One node identity on several addresses', 'peer_id', f_ids,", "det('D11', 'One node identity on several addresses', 'peer_info', f_ids,", 'D11 anchored on the clock field again'),
    ('PI28', PI, "    explain_detectors(D, peers, ips_active, fr_metric)", "    pass", 'no explanation is produced'),
    ('PI28', PI, "    rank = {pid: i + 1 for i, (_, pid) in enumerate(lat)}", "    rank = {pid: i for i, (_, pid) in enumerate(lat)}", 'the RTT rank is off by one'),
    ('PI28', PI, "        n_fr = (fr.get(f['peer']) or (None,))[0]", "        n_fr = p.get('first_relays')", 'unserved is divided by the decaying first_relays score, not this run\'s count'),
    ('PI28', PI, "        x = {'peers': pids, 'same_netgroup': len(groups) == 1 and None not in groups,", "        x = {'peers': pids, 'same_netgroup': True,", 'a D11 pair always reads as one /16'),
    ('PI28', PI, "'same_netgroup': len(groups) == 1 and None not in groups, 'same_version'", "'same_netgroup': len(groups) == 1 and None not in groups, 'groups': sorted(map(str, groups)), 'same_version'", 'the private /16s are written into the report'),
]


def copy_base():
    return K25.copy_base()


def main():
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
    print(f'\nR27 peer-intel KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
