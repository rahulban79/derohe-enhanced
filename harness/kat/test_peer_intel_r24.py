#!/usr/bin/env python3
"""Known-answer tests + mutation proofs for the network-peer observatory (harness/intel/peer_intel.py, its miner
harness/miners/mine_peers.py and gate G27), r24 consensus-network.

  PI1  a normal capture (6 peers, 6 /16s, small clock offsets, balanced relays) is flagged by no detector
  PI2  v2 remnant: a v2_offences entry + its log line, and an active peer with top_version 2 past HF3+8 → D1 OBSERVED
  PI3  log rules: 'answered 0 blocks for 4 requested' → D4 OBSERVED; 'evicting stuck peer' → D3 OBSERVED; 25 'could not
       serve' replies from one peer → D5 ANOMALY, but 25 from each of three peers → D5 NORMAL (not > 5x the median)
  PI4  clock offset -120 ms at 90 ms RTT → D6 ANOMALY (the 50 ms future rule, beyond RTT/2); 3 ms → nothing; -76 ms at
       218 ms RTT (inside the +/- RTT/2 uncertainty) → nothing (r24 verify)
  PI5  three outgoing peers in one /16 → D8 OBSERVED (cap 2) and the share ANOMALY
  PI6  a peer 40 blocks behind and one 40 above → D2 ANOMALY for both
  PI7  privacy: no address or tag in any output; one address → one pseudonym across GetPeerInfo, first_relay.json,
       v2_offences.json and /metrics; another salt → another pseudonym; this node's builder key → 'this-node'
  PI8  G27: clean outputs PASS; a planted IP (not one of the capture's) in the rendered section, a private tag in it, a raw
       peer_id or builder key in it (r24 verify), a stale capture, a row whose anchor no longer resolves → FAIL
  PI9  a rule line missing from the tree → that detector is 'pending', never NORMAL or OBSERVED
  PI10 first-relay concentration: 80 of 100 from one peer → D9 ANOMALY; 30 of 100 → NORMAL
  PI11 p2p_inv_txids_over_budget_total 5 → D10 OBSERVED
  PI12 mine_peers: a finding is cited only by an extract line that names that very peer; every row anchored
  PI13 G27 whole page (r24 integration, kit/privkit.py): a LAN-range address (RFC 1918, not reserved) planted OUTSIDE
       the peers section (a triage logger name), in harness/model/verified.json or in model/raw/triage.json → FAIL;
       reserved addresses (loopback, RFC 5737) and peer-xxxxxxxx pseudonyms outside the section → PASS

All inputs are synthetic (documentation, benchmarking and test-net ranges only: RFC 5737, RFC 2544 and the reserved 240.0.0.0/4 (RFC 1112); temp dirs);
PI13 also uses one RFC 1918 address (a LAN range, never routed) as the 'not reserved' input; no real file is written.
  python3 -I harness/kat/test_peer_intel_r24.py   # exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught
A mutation that crashes the KAT is INVALID, not caught.
"""
import datetime, importlib.util, json, shutil, subprocess, sys, tempfile
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
FILES = ('intel/peer_intel.py', 'miners/mine_peers.py', 'miners/minelib.py', 'kit/privkit.py')   # r24: emit + G27 use privkit
OUR_H = 7_850_000
TAG = 'secret-node-tag-x'


def load(base):
    sp = importlib.util.spec_from_file_location(f'peer_intel_kat_{id(base)}_{datetime.datetime.now().timestamp()}', base / 'intel/peer_intel.py')
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


def peer(ip, **k):
    p = {'address': f'{ip}:11011', 'incoming': False, 'peer_id': format(abs(hash(ip)) % (1 << 63), '016x'), 'height': OUR_H,
         'topoheight': OUR_H, 'stableheight': OUR_H - 8, 'top_version': 3, 'latency_ms': 90.0, 'clock_offset_ms': 3.0,
         'connected_seconds': 3600, 'bytes_in': 1000, 'bytes_out': 1000, 'first_relays': 10, 'miniblocks_first': 5,
         'miniblocks_total': 20, 'daemon_version': '3.6.0-153.DEROHE.STARGATE+22102026.r24', 'tag': '', 'pruned': 0}
    p.update(k)
    return p


NORMAL_IPS = ['192.0.2.1', '198.51.100.1', '203.0.113.1', '198.18.0.1', '198.19.0.1', '240.0.0.1']


def write_cap(d, peers, fr=None, v2=None, bans=None, metrics=None, pj=None):
    d.mkdir(parents=True, exist_ok=True)
    (d / 'GetPeerInfo.json').write_text(json.dumps({'result': {'peers': peers, 'incoming': 0, 'outgoing': len(peers),
                                                               'v2_chain_peers_seen_7d': len(v2 or {}), 'our_height': OUR_H,
                                                               'our_topoheight': OUR_H, 'status': 'OK'}}))
    (d / 'GetSyncInfo.json').write_text(json.dumps({'result': {'status': 'synced', 'height': OUR_H, 'lag_blocks': 0, 'version': '3.6.0-153.DEROHE.STARGATE+22102026.r24',
                                                               'chain_fingerprint': 'v3 (upgraded chain, fork block e454090e)', 'peers_incoming': 0}}))
    (d / 'GetInfo.json').write_text(json.dumps({'result': {'height': OUR_H}}))
    if metrics is None:
        metrics = ''.join(f'p2p_first_relay_total{{peer="{p["address"].split(":")[0]}"}} 10\n' for p in peers)
        metrics += 'p2p_inv_txids_over_budget_total 0\np2p_handshake_failures_total 3\np2p_penalty_bans_total 0\n'
    (d / 'metrics.txt').write_text(metrics)
    (d / 'first_relay.json').write_text(json.dumps({'peers': fr if fr is not None else {
        p['address'].split(':')[0]: {'address': p['address'], 'firsts': 10, 'builders': {'00112233aabbccdd': 6, 'ffeeddcc00112233': 4},
                                     'delay_sum_us': 1500000, 'delay_n': 10, 'last_first': 1793600000} for p in peers}}))
    (d / 'v2_offences.json').write_text(json.dumps(v2 or {}))
    (d / 'ban_list.json').write_text(json.dumps(bans or {}))
    (d / 'peers.json').write_text(json.dumps(pj or {p['address'].split(':')[0]: {'address': p['address'], 'goodcount': 5, 'failcount': 0,
                                                                                  'whitelist': True, 'lastconnected': 1793600000} for p in peers}))
    return d


def logline(n, msg, ip, **f):
    d = {'L': 'DEBUG', 'T': f'2026-11-02T10:00:{n % 60:02d}.000-0800', 'N': f'P2P.outgoing.{ip}:11011', 'C': 'p2p/x.go:1', 'M': msg}
    d.update(f)
    return json.dumps(d)


def write_log(d, extra=()):
    lines = [json.dumps({'L': 'INFO', 'T': '2026-11-02T09:00:00.000-0800', 'N': 'derod', 'C': 'derod/main.go:160',
                         'M': 'DERO HE daemon :  It is an alpha version, use it for testing/evaluations purpose only.'})]
    lines += [json.dumps({'L': 'DEBUG', 'T': '2026-11-02T09:00:01.000-0800', 'N': 'P2P', 'C': 'p2p/controller.go:338',
                          'M': 'backing off from this connection', 'ip': '192.0.2.1:11011'})]
    lines += list(extra)
    p = d / 'derod.log'
    p.write_text('\n'.join(lines) + '\n')
    return p


def analyse(P, cap_dir, log, salt='s1', self_b=None, root=ROOT):
    ps = P.Pseud(salt, self_b)
    rep, cl, xl = P.analyse(P.load_capture(cap_dir), P.scan_log([log], ps), ps, root=root)
    return rep, cl, xl, ps


def det(rep, did):
    return next(d for d in rep['detectors'] if d['id'] == did)


def tmp():
    return Path(tempfile.mkdtemp(prefix='r24pi-'))


# ───────────────────────────── KATs ─────────────────────────────
def pi1(base):
    P = load(base)
    t = tmp()
    rep, *_ = analyse(P, write_cap(t / 'c', [peer(ip) for ip in NORMAL_IPS]), write_log(t))
    # r25: D15 needs the r25 GetPeerInfo fields, which this r24-shaped capture lacks, so it is 'pending' (never NORMAL by
    # default); the r25 KAT (test_peer_intel_r25.py PI14) checks an r25-shaped normal capture is all NORMAL, D15 included
    bad = [(d['id'], d['grade']) for d in rep['detectors'] if d['grade'] not in ('NORMAL',) and not (d['id'] == 'D15' and d['grade'] == 'pending')]
    shutil.rmtree(t, ignore_errors=True)
    return not bad, f'flagged {bad}'


def pi2(base):
    P = load(base)
    t = tmp()
    ps = [peer(ip) for ip in NORMAL_IPS[:5]] + [peer('192.0.2.17', top_version=2, height=7_504_640 + 100)]
    log = write_log(t, [logline(5, 'dropping peer on pre-HF3 (v2) chain', '192.0.2.18', peer_height=7698358, peer_top_version=2)])
    rep, cl, xl, pz = analyse(P, write_cap(t / 'c', ps, v2={'192.0.2.18': {'n': 3, 'last': 1793600000}}), log)
    d = det(rep, 'D1')
    want = {pz.peer('192.0.2.18'), pz.peer('192.0.2.17')}
    got = {f['peer'] for f in d['findings'] if f['grade'] == 'OBSERVED'}
    xl_ok = any(pz.peer('192.0.2.18') in xl[n - 1] for f in d['findings'] for n in f.get('logx_lines') or [])
    shutil.rmtree(t, ignore_errors=True)
    return d['grade'] == 'OBSERVED' and want <= got and xl_ok, f"grade {d['grade']} got {got} want {want} logx {xl_ok}"


def pi3(base):
    P = load(base)
    t = tmp()
    ps = [peer(ip) for ip in NORMAL_IPS]
    ex = [logline(1, 'Call failed GetObject', '198.51.100.1', L='ERROR', error='peer answered 0 blocks for 4 requested'),
          logline(2, 'evicting stuck peer', '203.0.113.1', peer_height=1, our_height=OUR_H, hold='30m0s')]
    ex += [logline(3, 'Call failed GetObject: peer could not serve the object', '198.18.0.1', peer_error='x') for _ in range(25)]
    rep, cl, xl, pz = analyse(P, write_cap(t / 'c', ps), write_log(t, ex))
    d4, d3, d5 = det(rep, 'D4'), det(rep, 'D3'), det(rep, 'D5')
    ok1 = (d4['grade'] == 'OBSERVED' and d4['findings'][0]['peer'] == pz.peer('198.51.100.1') and d3['grade'] == 'OBSERVED'
           and d5['grade'] == 'ANOMALY')
    ex2 = [logline(3, 'Call failed GetObject: peer could not serve the object', ip, peer_error='x') for ip in NORMAL_IPS[:3] for _ in range(25)]
    rep2, *_ = analyse(P, write_cap(t / 'c2', ps), write_log(t, ex2))
    ok2 = det(rep2, 'D5')['grade'] == 'NORMAL'
    shutil.rmtree(t, ignore_errors=True)
    return ok1 and ok2, f"D4 {d4['grade']} D3 {d3['grade']} D5 {d5['grade']} / spread D5 {det(rep2, 'D5')['grade']}"


def pi4(base):
    P = load(base)
    t = tmp()
    ps = [peer(ip) for ip in NORMAL_IPS[:4]] + [peer(NORMAL_IPS[4], clock_offset_ms=-76.1, latency_ms=217.7),
                                                 peer('240.0.0.1', clock_offset_ms=-120.0)]
    rep, _, _, pz = analyse(P, write_cap(t / 'c', ps), write_log(t))
    d = det(rep, 'D6')
    shutil.rmtree(t, ignore_errors=True)
    return d['grade'] == 'ANOMALY' and [f['peer'] for f in d['findings']] == [pz.peer('240.0.0.1')], f"{d['grade']} {d['findings']}"


def pi5(base):
    P = load(base)
    t = tmp()
    ps = [peer(ip) for ip in ('198.18.10.1', '198.18.11.1', '198.18.12.1', '192.0.2.22', '198.51.100.23', '203.0.113.24')]
    rep, *_ = analyse(P, write_cap(t / 'c', ps), write_log(t))
    d = det(rep, 'D8')
    g = sorted(f['grade'] for f in d['findings'])
    shutil.rmtree(t, ignore_errors=True)
    return d['grade'] == 'OBSERVED' and g == ['ANOMALY', 'OBSERVED'] and d['diversity']['netgroups'] == 4, f"{d['grade']} {g} {d.get('diversity')}"


def pi6(base):
    P = load(base)
    t = tmp()
    ps = [peer(ip) for ip in NORMAL_IPS[:4]] + [peer('198.19.0.1', height=OUR_H - 40), peer('240.0.0.1', height=OUR_H + 40)]
    rep, _, _, pz = analyse(P, write_cap(t / 'c', ps), write_log(t))
    d = det(rep, 'D2')
    got = sorted(f['peer'] for f in d['findings'] if f['grade'] == 'ANOMALY')
    shutil.rmtree(t, ignore_errors=True)
    return d['grade'] == 'ANOMALY' and got == sorted([pz.peer('198.19.0.1'), pz.peer('240.0.0.1')]), f"{d['grade']} {got}"


def pi7(base):
    P = load(base)
    t = tmp()
    priv = t / 'priv'
    priv.mkdir()
    (priv / 'salt').write_text('kat-salt\n')
    (priv / 'self.json').write_text(json.dumps({'builder8': '00112233aabbccdd'}))
    ps = [peer(ip, tag=TAG if i == 0 else '') for i, ip in enumerate(NORMAL_IPS)]
    cap = write_cap(t / 'c', ps, v2={'192.0.2.1': {'n': 1, 'last': 1}}, bans={'192.0.2.1': 1893600000, '198.51.100.0/24': 1893600000})
    log = write_log(t, [logline(1, 'evicting stuck peer', '198.51.100.1', peer_height=1)])
    out = t / 'out'
    rep, capf, logxf = P.run(cap, priv, [log], root=ROOT, out_dir=out)
    texts = {f.name: f.read_text() for f in out.iterdir() if f.is_file()}
    raw = NORMAL_IPS + ['198.51.100.0', TAG]
    leak = [(n, s) for n, tx in texts.items() for s in raw if s in tx]
    leak += [(n, l) for n, tx in texts.items() for l in P.leaks(tx)]
    pz = P.Pseud('kat-salt', '00112233aabbccdd')
    me = pz.peer('192.0.2.1')
    srcs = {json.loads(l)['src'] for l in texts[capf.name].splitlines() if f'"{me}"' in l}
    other = P.Pseud('other-salt').peer('192.0.2.1') != me
    selfb = 'this-node' in rep['builders']
    shutil.rmtree(t, ignore_errors=True)
    want = {'GetPeerInfo', 'first_relay.json', 'v2_offences.json', 'metrics', 'ban_list.json', 'peers.json'}
    return not leak and want <= srcs and other and selfb, f'leaks {leak[:3]} srcs {sorted(srcs)} salt-differs {other} this-node {selfb}'


def g27_tree(P, mutate=None):
    """a temp root with outputs, a model file and a page whose peers section was rendered from them."""
    t = tmp()
    priv = t / 'priv'
    priv.mkdir()
    (priv / 'salt').write_text('kat-salt\n')
    ps = [peer(ip, tag=TAG if i == 0 else '') for i, ip in enumerate(NORMAL_IPS)]
    root = t / 'root'
    rt = root / 'harness/runtime'
    rt.mkdir(parents=True)
    cap = write_cap(priv / 'raw' / '20261102T000000Z', ps)
    P.run(cap, priv, [write_log(t)], root=ROOT, out_dir=rt)
    rep = json.loads((rt / 'peer_intel.json').read_text())
    capl = (rt / rep['capture_file']).read_text().splitlines()
    rows = [{'id': 'peers-kpis', 'evidence': [{'file': f"harness/runtime/{rep['capture_file']}", 'quote': capl[rep['kpi_line'] - 1][:160], 'line': rep['kpi_line']}]}]
    (root / 'harness/model/raw').mkdir(parents=True)
    (root / 'harness/model/raw/peercards.json').write_text(json.dumps({'rows': rows}))
    (root / 'artifacts').mkdir()
    sec = '<section id="peers"><h2>peers</h2><p>' + ' '.join(p['peer'] for p in rep['peers']) + '</p></section>'
    (root / 'artifacts/dero-src-arch.html').write_text('<html><body>' + sec + '</body></html>')
    if mutate:
        mutate(root, rep)
    ok, d = P.g27(root, priv)
    shutil.rmtree(t, ignore_errors=True)
    return ok, d


def pi8(base):
    P = load(base)
    page = lambda root: root / 'artifacts/dero-src-arch.html'
    clean = g27_tree(P)
    ip = g27_tree(P, lambda r, rep: page(r).write_text(page(r).read_text().replace('</p>', ' 203.0.113.77</p>')))
    tag = g27_tree(P, lambda r, rep: page(r).write_text(page(r).read_text().replace('</p>', f' {TAG}</p>')))
    # r24 (verify): a raw handshake peer_id or a raw builder key in the page is a leak too
    pid = g27_tree(P, lambda r, rep: page(r).write_text(page(r).read_text().replace('</p>', f" {peer(NORMAL_IPS[0])['peer_id']}</p>")))
    bkey = g27_tree(P, lambda r, rep: page(r).write_text(page(r).read_text().replace('</p>', ' 00112233aabbccdd</p>')))

    def stale(r, rep):
        p = r / 'harness/runtime/peer_intel.json'
        d = json.loads(p.read_text())
        d['captured'] = (datetime.datetime.now().astimezone() - datetime.timedelta(hours=30)).isoformat(timespec='seconds')
        p.write_text(json.dumps(d))

    def badrow(r, rep):
        p = r / 'harness/model/raw/peercards.json'
        d = json.loads(p.read_text())
        d['rows'][0]['evidence'][0]['quote'] = 'this text is on no line at all'
        p.write_text(json.dumps(d))
    st, br = g27_tree(P, stale), g27_tree(P, badrow)
    ok = clean[0] and not ip[0] and not tag[0] and not pid[0] and not bkey[0] and not st[0] and not br[0]
    return ok, f'clean {clean[0]} ip {ip[0]} tag {tag[0]} peer_id {pid[0]} builder {bkey[0]} stale {st[0]} badrow {br[0]} · {clean[1][:160]}'


def pi9(base):
    P = load(base)
    t = tmp()
    root = t / 'root'
    for f, _ in P.RULES.values():
        (root / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / f, root / f)
    c = root / 'p2p/common.go'
    c.write_text(c.read_text().replace(P.RULES['v2_remnant'][1], '// the v2 rule was removed'))
    ps = [peer(ip) for ip in NORMAL_IPS[:5]] + [peer('192.0.2.17', top_version=2, height=7_504_640 + 100)]
    rep, *_ = analyse(P, write_cap(t / 'c', ps), write_log(t), root=root)
    d = det(rep, 'D1')
    shutil.rmtree(t, ignore_errors=True)
    return d['grade'] == 'pending', f"D1 {d['grade']} ({d.get('why')})"


def pi10(base):
    P = load(base)
    t = tmp()
    ps = [peer(ip) for ip in NORMAL_IPS]
    hi = 'p2p_first_relay_total{peer="192.0.2.1"} 80\n' + ''.join(f'p2p_first_relay_total{{peer="{ip}"}} 4\n' for ip in NORMAL_IPS[1:6])
    lo = 'p2p_first_relay_total{peer="192.0.2.1"} 30\n' + ''.join(f'p2p_first_relay_total{{peer="{ip}"}} 14\n' for ip in NORMAL_IPS[1:6])
    a, *_ = analyse(P, write_cap(t / 'a', ps, metrics=hi), write_log(t))
    b, *_ = analyse(P, write_cap(t / 'b', ps, metrics=lo), write_log(t))
    shutil.rmtree(t, ignore_errors=True)
    return det(a, 'D9')['grade'] == 'ANOMALY' and det(b, 'D9')['grade'] == 'NORMAL', f"80% {det(a, 'D9')['grade']} 30% {det(b, 'D9')['grade']}"


def pi11(base):
    P = load(base)
    t = tmp()
    ps = [peer(ip) for ip in NORMAL_IPS]
    m = ''.join(f'p2p_first_relay_total{{peer="{ip}"}} 10\n' for ip in NORMAL_IPS) + 'p2p_inv_txids_over_budget_total 5\n'
    rep, *_ = analyse(P, write_cap(t / 'c', ps, metrics=m), write_log(t))
    shutil.rmtree(t, ignore_errors=True)
    return det(rep, 'D10')['grade'] == 'OBSERVED', det(rep, 'D10')['grade']


def pi12(base):
    """mine_peers in a temp tree: a stuck finding whose extract lines are swapped to another peer's must not be cited."""
    P = load(base)
    t = tmp()
    root = t / 'root'
    for f in FILES:
        (root / 'harness' / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(base / f, root / 'harness' / f)
    for f, _ in P.RULES.values():
        (root / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / f, root / f)
    for f in {g[2] for g in P.GAPS}:
        (root / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / f, root / f)
    priv = t / 'priv'
    priv.mkdir()
    (priv / 'salt').write_text('kat-salt\n')
    ps = [peer(ip) for ip in NORMAL_IPS]
    ex = [logline(1, 'evicting stuck peer', '198.51.100.1', peer_height=1), logline(2, 'evicting stuck peer', '203.0.113.1', peer_height=1)]
    rt = root / 'harness/runtime'
    P.run(write_cap(t / 'c', ps), priv, [write_log(t, ex)], root=root, out_dir=rt)
    rp = rt / 'peer_intel.json'
    rep = json.loads(rp.read_text())
    d3 = next(d for d in rep['detectors'] if d['id'] == 'D3')
    a, b = d3['findings'][0], d3['findings'][1]
    a['logx_lines'], b['logx_lines'] = b['logx_lines'], a['logx_lines']     # every finding now points at the other peer's line
    rp.write_text(json.dumps(rep, indent=1))
    r = subprocess.run([sys.executable, '-I', str(root / 'harness/miners/mine_peers.py')], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        shutil.rmtree(t, ignore_errors=True)
        raise RuntimeError(f'mine_peers rc={r.returncode}: {r.stderr[-300:]}')
    doc = json.loads((root / 'harness/model/raw/peercards.json').read_text())
    row = next((x for x in doc['rows'] if x['id'] == 'peers-D3'), None)
    cited = [f['peer'] for f in (row or {}).get('findings', [])]
    unanchored = 0
    for x in doc['rows']:
        ok = False
        for e in x['evidence']:
            ls = (root / e['file']).read_text().splitlines()
            ok |= 0 < e['line'] <= len(ls) and e['quote'] in ls[e['line'] - 1]
        unanchored += not ok
    shutil.rmtree(t, ignore_errors=True)
    return not cited and unanchored == 0 and len(doc['rows']) > 10, f'cited {cited} unanchored {unanchored} rows {len(doc["rows"])}'


def pi13(base):
    """r24 integration: the whole generated page, verified.json and the log-derived raw files (privkit.page_ip_leaks)."""
    P = load(base)
    page = lambda root: root / 'artifacts/dero-src-arch.html'
    lan = '10.11.12.13'                     # RFC 1918: names a LAN host, so it must be pseudonymised like a peer

    def outside(text):
        return lambda r, rep: page(r).write_text(page(r).read_text().replace('</body>', f'<section id="triage"><p>{text}</p></section></body>'))

    def planted(rel):
        def f(r, rep):
            (r / rel).parent.mkdir(parents=True, exist_ok=True)
            (r / rel).write_text(json.dumps({'rows': [{'title': f'P2P.outgoing.{lan}:11011 - Call failed GetObject'}]}))
        return f
    fine = g27_tree(P, outside('P2P.outgoing.peer-0a1b2c3d:11011 on 127.0.0.1 and 198.51.100.9'))
    pg = g27_tree(P, outside(f'P2P.outgoing.{lan}:11011 - Call failed GetObject'))
    vj = g27_tree(P, planted('harness/model/verified.json'))
    tj = g27_tree(P, planted('harness/model/raw/triage.json'))
    ok = fine[0] and not pg[0] and not vj[0] and not tj[0]
    return ok, f'reserved+pseudonym {fine[0]} page {pg[0]} verified.json {vj[0]} triage.json {tj[0]} · {fine[1][-120:]}'


KATS = [('PI1', pi1), ('PI2', pi2), ('PI3', pi3), ('PI4', pi4), ('PI5', pi5), ('PI6', pi6), ('PI7', pi7), ('PI8', pi8),
        ('PI9', pi9), ('PI10', pi10), ('PI11', pi11), ('PI12', pi12), ('PI13', pi13)]

PI = 'intel/peer_intel.py'
MP = 'miners/mine_peers.py'
MUTATIONS = [
    ('PI1', PI, 'MIN_NETGROUPS = 4 ', 'MIN_NETGROUPS = 40 ', 'a normal peer set is flagged (diversity floor too high)'),
    ('PI2', PI, "(p.get('top_version') or 0) < 3", "(p.get('top_version') or 0) < 2", 'an active v2 peer is not flagged'),
    ('PI2', PI, "            d['findings'].append({'peer': r['peer'], 'grade': 'OBSERVED',", "            d['findings'].append({'peer': r['peer'], 'grade': 'NORMAL',", 'a v2 offender is graded NORMAL'),
    ('PI3', PI, "        kind = 'short_answer'", "        kind = None", "short answers ('answered 0 blocks') are not read"),
    ('PI3', PI, "    ('evicting stuck peer', 'stuck_evict'),", "    ('evicting stuck peer!', 'stuck_evict'),", 'stuck evictions are not read'),
    ('PI3', PI, "g = 'ANOMALY' if e['n'] >= 20 and", "g = 'ANOMALY' if e['n'] >= 2000 and", 'the unserved-object threshold is never reached'),
    ('PI3', PI, "(med is None or e['n'] > REMOTE_UNSERVED_MULT * max(med, 1))", "(True)", 'evenly spread unserved replies are flagged'),
    ('PI4', PI, 'if isinstance(o, (int, float)) and abs(o) - rtt / 2 > CLOCK_FUTURE_MS:', 'if isinstance(o, (int, float)) and abs(o) - rtt / 2 > CLOCK_FUTURE_MS * 3:', 'clock skew beyond the 50 ms rule is missed'),
    ('PI4', PI, 'if isinstance(o, (int, float)) and abs(o) - rtt / 2 > CLOCK_FUTURE_MS:', 'if isinstance(o, (int, float)) and abs(o) > CLOCK_FUTURE_MS:', 'a reading inside the +/- RTT/2 uncertainty is flagged (r24 verify)'),
    ('PI5', PI, '            if len(members) > 2:', '            if len(members) > 3:', 'the /16 outbound cap is not checked'),
    ('PI5', PI, "if n and (sizes[0] / n > NETGROUP_SHARE or", "if n and (sizes[0] / n > 1 or", 'one /16 holding half the peers is not an eclipse indicator'),
    ('PI6', PI, "if isinstance(p.get('lag'), int) and p['lag'] > LAGGING:", "if isinstance(p.get('lag'), int) and p['lag'] > LAGGING * 2:", 'a lagging peer is missed'),
    ('PI7', PI, "return 'peer-' + self.h('ip', host_of(ip))", "return 'peer-' + str(host_of(ip))", 'the pseudonym is the address (IP leak)'),
    ('PI7', PI, "f'{self.salt}|{kind}|{value}'", "f'{kind}|{value}'", 'the salt is ignored (pseudonyms are dictionary-reversible)'),
    ('PI7', PI, "lab = {k: (ps.peer(x) if k == 'peer' else x) for k, x in labels.items()}", "lab = {k: x for k, x in labels.items()}", '/metrics peer labels are not pseudonymised'),
    ('PI7', PI, "        return 'this-node' if self.self_builder and k == self.self_builder else", "        return 'self-' + k if self.self_builder and k == self.self_builder else", "this node's own key is printed"),
    ('PI8', PI, '        lk = leaks(sec, ps_)', '        lk = []', 'a planted IP in the rendered section passes G27'),
    ('PI8', PI, "IPV4 = re.compile(r'(?<![\\d.])(?:\\d{1,3}\\.){3}\\d{1,3}(?!\\.?\\d)')", "IPV4 = re.compile(r'(?!x)x')", 'the IPv4 detector is blind'),
    ('PI8', PI, '        if s and len(s) >= 4 and s in text:', '        if False:', 'a private tag in the page passes G27'),
    ('PI8', PI, "            if p.get('peer_id'):                         # r24 (verify): the handshake node id is private too", "            if False:", 'a raw peer_id in the page passes G27 (r24 verify)'),
    ('PI8', PI, "                s.update(str(b) for b in ((j['peers'][k] or {}).get('builders') or {}))", "                pass", 'a raw builder key in the page passes G27 (r24 verify)'),
    ('PI8', PI, 'if age is None or age > FRESH_H or age < -0.1:', 'if age is None or age > FRESH_H * 100 or age < -0.1:', 'a stale capture passes G27'),
    ('PI8', PI, "            if isinstance(ln, int) and 0 < ln <= len(ls) and str(e.get('quote', ''))[:200] in ls[ln - 1]:", "            if True:", 'an unanchored row passes G27'),
    ('PI9', PI, "        if not a or a['status'] != 'OK':", "        if not a:", 'a detector is graded without its rule line'),
    ('PI10', PI, "'grade': 'ANOMALY' if share > FIRST_RELAY_CONC else 'NORMAL',", "'grade': 'NORMAL',", 'first-relay concentration is never flagged'),
    ('PI11', PI, "'grade': 'OBSERVED' if mt[key] > 0 else 'NORMAL',", "'grade': 'NORMAL',", 'INV budget clips are not flagged'),
    ('PI12', MP, """                if a and f'"peer": "{f["peer"]}"' in a['quote']:     # the extract line must name this very peer""",
     "                if a:", "a finding is cited by another peer's log line"),
    ('PI13', 'kit/privkit.py', '    return x.is_loopback or x.is_unspecified or any(x in n for n in TEST_NETS)', '    return True',
     'every address counts as reserved: a peer address on the page passes G27'),
    ('PI13', PI, "    for f in [page, root / 'harness/model/verified.json'] + [root / f'harness/model/raw/{k}.json' for k in PAGE_RAW_KEYS]:",
     '    for f in [page]:', 'verified.json and the raw files are not scanned'),
    ('PI13', PI, "    for f in [page, root / 'harness/model/verified.json'] + [root / f'harness/model/raw/{k}.json' for k in PAGE_RAW_KEYS]:",
     "    for f in [root / 'harness/model/verified.json'] + [root / f'harness/model/raw/{k}.json' for k in PAGE_RAW_KEYS]:", 'only the peers section of the page is scanned (the pre-r24-integration gap)'),
]


def copy_base():
    d = Path(tempfile.mkdtemp(prefix='r24pim-'))
    for f in FILES:
        (d / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HARNESS / f, d / f)
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
    print(f'\nR24 peer-intel KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 3 if fails else (4 if missed else 0)


if __name__ == '__main__':
    sys.exit(main())
