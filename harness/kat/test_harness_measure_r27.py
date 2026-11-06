#!/usr/bin/env python3
"""KAT + mutation proofs for the R27 harness-measure group (rft §0.9, §6 S7 / step 20, §7 B36 B120 B133; no network,
no live file written: every registry, series and output is a temp file).

  HM1 kit/roundtracks.metrics_exit: 2 when neither endpoint answered; 7 for a node ALERT whatever the track; a miner
      ALERT (endpoint_down 'miner ...' included) sets 7 only while the miner track is active and is listed as PAUSED
      while paused; 0 otherwise. Before r27 every paused-track snapshot exited 7.
  HM2 metrics_intel end to end over forged /metrics text (derod synced, miner down): the snapshot's 'exit' block and
      main()'s exit code follow HM1 for a paused and an active temp registry; a derod tip_age > 600 s still exits 7
      while paused; the endpoint_down alert itself stays in the snapshot (G18 quotes it).
  HM3 one classifier: run_gates.miner_alert IS roundtracks.miner_alert, and g18_derod_half passes the paused-miner
      snapshot of HM2 while it fails the not_synced one.
  HM4 live_window endpoint guard: getwork 10100, P2P 11011, a non-loopback host and https are refused; a method outside
      READ_METHODS is refused before any request; the /metrics URL is derived on the same host and port.
  HM5 restart detection: restarted() (uptime fell / answered after a failed probe) and wait_restart() over a scripted
      probe sequence; a steady node yields None within wait_max_s.
  HM6 summarise() over a fixture series: first-sample-after-start seconds, restarts inside the window, tip_age mean /
      median / max, lag max, blocks; no usable sample -> None; a GetPeerInfo-shaped field is never echoed.
  HM7 poll() with a fake clock: one sample per step until `end`, a /metrics scrape every k-th sample, the restart event
      on the first sample only.
  HM8 headers_range refuses a start below prunedheight and sums txcount/fees over 100-topo chunks.
  HM10 the pipeline registers the R27 Go tests (NEW_TESTS) and go_mutations.json holds a gm-r27 spec for each.
  HM9, HM11 retired at the R27 merge: gen_deroarch --help / stale-raw WARN and area_intel class 'record' (B134) are
      the tools-kats implementations, proved by harness/kat/test_tools_kats_r27.py TK2, TK4, TK5.
  HM12 tooling_intel.kat_mutations counts the forensics KATs' 'mutations caught X/Y' next to 'mutations proved X/Y'
      (r26: 7 KAT files, their mutations outside the 652 total) and still no other number pair.

  python3 -I harness/kat/test_harness_measure_r27.py   # KATs, then each mutation on a temp copy must flip its KAT
Exit 0 all ok · 3 a KAT failed · 4 a mutation was not caught (or was INVALID: the mutant did not load).
"""
import contextlib, importlib.util, io, json, os, shutil, subprocess, sys, tempfile, time
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
MODS = {'rt': 'kit/roundtracks.py', 'mi': 'intel/metrics_intel.py', 'gates': 'run_gates.py', 'lw': 'intel/live_window.py',
        'gd': 'gen_deroarch.py', 'fbv': 'pipeline/fix_build_verify.py', 'ai': 'intel/area_intel.py',
        'ti': 'intel/tooling_intel.py'}
EXTRA = ['prep_corpus.py', 'consensus_guard.py', 'miners/minelib.py', 'intel/miner_intel.py', 'intel/contention.py',
         'round.json', 'loop/KNOWN_TEST_FAILURES.json', 'intel/go_mutations.json', 'areas.json']
EXTRA_DIRS = ['kit', 'miners']
DATA = {'areas': 'areas.json'}                  # data files a mutation may edit (checked to still parse)


def load(base, name):
    for m in ('gen_deroarch', 'prep_corpus', 'assetkit', 'textkit', 'connectorkit', 'diagramkit', 'minelib', 'roundtracks',
              'areakit', 'consensuskit', 'peerkit', 'privkit'):
        sys.modules.pop(m, None)
    extra = [str(base / 'kit'), str(base)] if name in ('gates', 'gd') else []
    sys.path[:0] = extra
    try:
        spec = importlib.util.spec_from_file_location(f'hm27_{name}_{id(base)}_{len(sys.modules)}', base / MODS[name])
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
    finally:
        del sys.path[:len(extra)]
    return m


def reg(miner):
    return {'current': 'r27', 'rounds': [{'id': 'r27', 'status': 'in-progress', 'tracks': {'miner': miner, 'node': 'active'}}]}


A_DOWN = {'rule': 'endpoint_down', 'level': 'ALERT', 'what': 'miner /metrics did not answer'}
A_DDOWN = {'rule': 'endpoint_down', 'level': 'ALERT', 'what': 'derod /metrics did not answer'}
A_SYNC = {'rule': 'not_synced', 'level': 'ALERT', 'what': 'sync status syncing'}
A_TIP = {'rule': 'tip_age', 'level': 'ALERT', 'what': 'tip is 900 s old'}
A_BEHIND = {'rule': 'miner_behind', 'level': 'ALERT', 'what': 'miner job height 1 vs derod 9'}
W_SKEW = {'rule': 'version_skew', 'level': 'WARN', 'what': 'x'}
UP1, UP0, UPB = {'derod': True, 'miner': False}, {'derod': False, 'miner': False}, {'derod': True, 'miner': True}


def kat_hm1(base):
    RT = load(base, 'rt')
    cases = [([], UP0, 'paused', 2), ([A_DOWN], UP1, 'paused', 0), ([A_DOWN], UP1, 'active', 7),
             ([A_DOWN, A_SYNC], UP1, 'paused', 7), ([A_DOWN, A_TIP], UP1, 'paused', 7), ([A_DDOWN], {'derod': False, 'miner': True}, 'paused', 7),
             ([A_BEHIND], UPB, 'paused', 0), ([A_BEHIND], UPB, 'active', 7), ([W_SKEW], UPB, 'active', 0), ([], UPB, 'paused', 0)]
    bad = []
    for al, up, st, want in cases:
        rc, why, paused = RT.metrics_exit(al, up, st)
        if rc != want:
            bad.append(f'{[a["rule"] for a in al]} {st} -> {rc} (want {want}: {why})')
    rc, why, paused = RT.metrics_exit([A_DOWN], UP1, 'paused')
    if paused != ['endpoint_down'] or 'PAUSED (miner)' not in why:
        bad.append(f'paused miner ALERT not listed as PAUSED: {paused} {why}')
    if RT.metrics_exit([A_DOWN], UP1, 'active')[2]:
        bad.append('an active track lists PAUSED alerts')
    return not bad, '; '.join(bad) or f'{len(cases)} exit cases + PAUSED listing'


DEROD_TXT = ('app_version{version="3.6.0-153.DEROHE.STARGATE+x.r27"} 1\napp_uptime_seconds 100\ndero_chain_height 7860000\n'
             'dero_chain_topoheight 7860000\ndero_tip_age_seconds {tip}\ndero_sync_lag_blocks 0\n'
             'dero_sync_status{{status="{st}"}} 1\np2p_peer_outgoing_count 14\np2p_peer_incoming_count 0\n')


def forged(mi, tip=7, st='synced'):
    def get(url):
        if 'derod' in url:
            return DEROD_TXT.replace('{tip}', str(tip)).replace('{{', '{').replace('}}', '}').replace('{st}', st)
        raise OSError('connection refused')
    clk = iter([1000.0, 1015.0, 1015.0, 1015.0])
    return mi.snapshot('http://derod/metrics', 'http://miner/metrics', 15, get=get, sleep=lambda s: None,
                       clock=lambda: next(clk, 1015.0), ps=None, ncpu=20, load1=1.0)


def run_main(mi, registry, rep):
    """metrics_intel.main() with the snapshot replaced by `rep` and the output in a temp file: (rc, written json)"""
    d = Path(tempfile.mkdtemp(prefix='hm27mi_'))
    try:
        rp, out = d / 'round.json', d / 'm.json'
        rp.write_text(json.dumps(registry))
        old_snap, old_argv = mi.snapshot, sys.argv
        mi.snapshot = lambda *a, **k: json.loads(json.dumps(rep))
        sys.argv = ['metrics_intel.py', '--json-only', '--registry', str(rp), '--out', str(out), '--cpu-max', '50']
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                rc = mi.main()
        finally:
            mi.snapshot, sys.argv = old_snap, old_argv
        return rc, json.loads(out.read_text())
    finally:
        shutil.rmtree(d, ignore_errors=True)


def kat_hm2(base):
    mi = load(base, 'mi')
    bad = []
    rep = forged(mi)
    if [a['rule'] for a in rep['alerts'] if a['level'] == 'ALERT'] != ['endpoint_down']:
        bad.append(f"forged snapshot alerts {rep['alerts']}")
    rc, w = run_main(mi, reg('paused'), rep)
    if rc != 0 or w.get('exit', {}).get('rc') != 0 or w['exit'].get('paused_alerts') != ['endpoint_down']:
        bad.append(f"paused: rc {rc} exit {w.get('exit')}")
    if not any(a['rule'] == 'endpoint_down' for a in w.get('alerts', [])):
        bad.append('the miner endpoint_down alert was dropped from the snapshot')
    rc, w = run_main(mi, reg('active'), rep)
    if rc != 7 or w.get('exit', {}).get('track', {}).get('miner') != 'active':
        bad.append(f"active: rc {rc} exit {w.get('exit')}")
    rc, w = run_main(mi, reg('paused'), forged(mi, tip=900))
    if rc != 7 or 'tip_age' not in w.get('exit', {}).get('why', ''):
        bad.append(f"paused + tip_age 900 s: rc {rc} exit {w.get('exit')}")
    rc, w = run_main(mi, {'current': 'r27', 'rounds': []}, rep)       # unreadable track -> active (roundtracks rule)
    if rc != 7:
        bad.append(f'no current round: rc {rc} (a doubt must resolve to active)')
    return not bad, '; '.join(bad) or 'paused 0 / active 7 / paused+tip_age 7 / no round 7'


def kat_hm3(base):
    gates, RT = load(base, 'gates'), None
    RT = sys.modules.get('roundtracks') or load(base, 'rt')
    mi = load(base, 'mi')
    bad = []
    if gates.miner_alert is not gates.RT.miner_alert or gates.MINER_ALERT_RULES is not gates.RT.MINER_ALERT_RULES:
        bad.append('run_gates keeps its own miner-ALERT classifier')
    if not (gates.miner_alert(A_DOWN) and gates.miner_alert(A_BEHIND) and not gates.miner_alert(A_DDOWN) and not gates.miner_alert(A_SYNC)):
        bad.append('miner_alert misclassifies')
    now = __import__('datetime').datetime.now().astimezone()
    rep = forged(mi)
    rep['captured'] = now.isoformat(timespec='seconds')
    ok1, d1 = gates.g18_derod_half(rep, now)
    rep2 = forged(mi, st='syncing')
    rep2['captured'] = rep['captured']
    ok2, d2 = gates.g18_derod_half(rep2, now)
    if not ok1 or ok2:
        bad.append(f'g18_derod_half paused-miner {ok1} ({d1}) / not_synced {ok2} ({d2})')
    return not bad, '; '.join(bad) or 'one classifier; G18 node half agrees'


def kat_hm4(base):
    lw = load(base, 'lw')
    bad = []
    for u in ('http://127.0.0.1:10100/json_rpc', 'http://127.0.0.1:11011/', 'http://192.0.2.7:10102/json_rpc',
              'https://127.0.0.1:10102/json_rpc', 'http://example.org:10102/json_rpc'):
        try:
            lw.check_url(u)
            bad.append(f'{u} accepted')
        except lw.Refused:
            pass
    try:
        lw.check_url(lw.RPC_URL)
    except lw.Refused as e:
        bad.append(f'default endpoint refused: {e}')
    if lw.metrics_url('http://127.0.0.1:10102/json_rpc') != 'http://127.0.0.1:10102/metrics':
        bad.append('metrics URL not on the RPC host/port')
    rpc = lw.make_rpc('http://127.0.0.1:9/json_rpc', timeout=0.01)   # port 9: never contacted for a refused method
    try:
        rpc('DERO.SubmitBlock')
        bad.append('a non-read method was sent')
    except lw.Refused:
        pass
    if lw.main(['poll', '--out', os.devnull, '--minutes', '0', '--rpc', 'http://127.0.0.1:10100/json_rpc']) != 2:
        bad.append('main does not exit 2 on the getwork port')
    return not bad, '; '.join(bad) or 'getwork/P2P/remote/https refused; read methods only'


def scripted(seq):
    it = iter(seq)

    def rpc(method, params=None):
        v = next(it, 'steady')
        if v == 'steady':
            return {'uptime_seconds': 10 ** 6}
        return {'_err': 'down'} if v is None else {'uptime_seconds': v}
    return rpc


class Clock:
    def __init__(self, t=0.0):
        self.t = t

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def kat_hm5(base):
    lw = load(base, 'lw')
    bad = []
    for args, want in (((100, 5, False), True), ((100, 105, False), False), ((None, 3, True), True), ((100, None, False), False),
                       ((None, 50, False), False)):
        if lw.restarted(*args) != want:
            bad.append(f'restarted{args} != {want}')
    c = Clock()
    got = lw.wait_restart(scripted([100, 105, 110, 4]), 5, 600, c, c.sleep)
    if not got or got[1] != 4:
        bad.append(f'uptime drop not seen: {got}')
    c = Clock()
    got = lw.wait_restart(scripted([100, None, None, 2]), 5, 600, c, c.sleep)
    if not got or got[1] != 2:
        bad.append(f'down -> up not seen: {got}')
    c = Clock()
    got = lw.wait_restart(scripted([None, 7]), 5, 600, c, c.sleep)
    if not got:
        bad.append('a node that comes up after the first (failed) probe is not a restart')
    c = Clock()
    if lw.wait_restart(scripted([]), 5, 60, c, c.sleep) is not None:
        bad.append('a steady node reported a restart')
    return not bad, '; '.join(bad) or 'uptime drop, down->up, steady'


def row(t, up, h, age, lag=0, st='synced', out=14):
    return {'t': f'T{t}', 'cs': {'version': 'v', 'uptime_seconds': up, 'counters': {'x': 1}, 'reorg': {'reorgs': 0, 'final_violations': 0}},
            'sync': {'height': h, 'topoheight': h, 'status': st, 'lag_blocks': lag, 'tip_age_seconds': age, 'peers_outgoing': out,
                     'peers_incoming': 0}, 'info': {}, 'peers': [{'addr': '192.0.2.44:11011'}]}


def kat_hm6(base):
    lw = load(base, 'lw')
    bad = []
    rows = [row(0, 416, 100, 10.0), row(1, 476, 103, 20.0, lag=2), row(2, 536, 106, 30.0), row(3, 12, 107, 4.0, st='syncing')]
    L = lw.summarise(rows, ['rpc_x_total 0\np2p_first_relay_total{peer="192.0.2.45"} 2\n',
                            'rpc_x_total 3\np2p_first_relay_total{peer="192.0.2.45"} 5\np2p_first_relay_total{peer="198.51.100.9"} 1\n'
                            'p2p_y_total{remote="h1"} 4\n'],
                     'restart 07:48:21')
    t = '\n'.join(L or [])
    for need in ('# restart 07:48:21', 'samples 4 (4 usable)', 'first sample 416 s after the derod start',
                 'restarts inside the window (uptime fell between samples): 1', 'lag max 2', 'tip_age mean 16.0 s median 15.0 max 30.0',
                 "status {'synced': 3, 'syncing': 1}", 'blocks in the window (first..last sample) 7 (100..107)', 'rpc_x_total 0 -> 3',
                 'p2p_first_relay_total{peer=*} 2 -> 6', 'p2p_y_total{peer=*} absent -> 4'):
        if need not in t:
            bad.append(f'missing {need!r}')
    if any(x in t for x in ('192.0.2.44', '192.0.2.45', '198.51.100.9', 'h1')):
        bad.append('a peer address was echoed')
    if lw.summarise([{'t': 'x', 'cs': {'_err': 'down'}, 'sync': {'_err': 'down'}}]) is not None:
        bad.append('a series with no usable sample summarised')
    return not bad, '; '.join(bad) or 'fixture numbers; no peer address'


def kat_hm7(base):
    lw = load(base, 'lw')
    d = Path(tempfile.mkdtemp(prefix='hm27lw_'))
    try:
        c = Clock(1000.0)
        rpc = lambda m, p=None: {'uptime_seconds': 1} if m == 'DERO.GetConsensusStats' else {}
        n = lw.poll(str(d / 's.jsonl'), 1000.0 + 600, rpc, lambda: 'm 1\n', 60, 5, c, c.sleep, event='restart seen')
        rows = lw.read_series(str(d / 's.jsonl'))
        proms = sorted(p.name for p in d.glob('s_metrics_*.prom'))
        bad = []
        if n != 10 or len(rows) != 10:
            bad.append(f'{n} samples / {len(rows)} rows over 600 s at 60 s (want 10)')
        if proms != ['s_metrics_000.prom', 's_metrics_005.prom']:
            bad.append(f'scrapes {proms}')
        if rows and (rows[0].get('event') != 'restart seen' or any(r.get('event') for r in rows[1:])):
            bad.append('the restart event is not on the first sample only')
        return not bad, '; '.join(bad) or '10 samples, 2 scrapes, event on sample 0'
    finally:
        shutil.rmtree(d, ignore_errors=True)


def kat_hm8(base):
    lw = load(base, 'lw')
    bad = []
    calls = []

    def rpc(m, p=None):
        calls.append(p)
        return {'headers': [{'txcount': 1, 'fees': 2} for _ in range(p['end_topoheight'] - p['start_topoheight'] + 1)]}
    try:
        lw.headers_range(rpc, 7498539, 7498600, 7498540)
        bad.append('a start below prunedheight was read')
    except lw.Refused:
        pass
    if calls:
        bad.append('a refused range still called the node')
    nb, tx, fees = lw.headers_range(rpc, 7860000, 7860249, 7498540)
    if (nb, tx, fees) != (250, 250, 500) or len(calls) != 3:
        bad.append(f'sums {(nb, tx, fees)} over {len(calls)} calls (want 250/250/500 in 3)')
    return not bad, '; '.join(bad) or 'prune refusal; chunked sums'


R27_GO = {'./glue/emission/': ('TestR27CumulativeCountsPayees', 'TestR27SeriesCarriesPayees'),
          './cmd/derod/rpc/': ('TestR27EmissionSeriesCheckpointsCarryPayees',),
          './tools/emission-audit/': ('TestR27SeriesReadPayees',)}


def kat_hm10(base):
    fbv = load(base, 'fbv')
    bad = []
    for pkg, names in R27_GO.items():
        have = set(str(fbv.NEW_TESTS.get(pkg, '')).split('|'))
        bad += [f'{pkg} {n} not in NEW_TESTS' for n in names if n not in have]
    gm = json.loads((base / 'intel/go_mutations.json').read_text())['mutations']
    tested = {m['test'] for m in gm if str(m.get('id', '')).startswith('gm-r27-')}
    bad += [f'no gm-r27 mutation for {n}' for names in R27_GO.values() for n in names if n not in tested]
    return not bad, '; '.join(bad) or f'{sum(map(len, R27_GO.values()))} R27 Go tests registered + mutated'


def kat_hm12(base):
    ti = load(base, 'ti')
    got = ti.kat_mutations(['mutations caught 17/17', 'x · mutations proved 5/6', 'mutation 3 CAUGHT: FE2 1/2 figures',
                            'ANOMALY 7848898 blocks behind us', 'mutations: 3 INVALID'])
    return got == (22, 23), f'kat_mutations {got} (want (22, 23))'


KATS = [('HM1', kat_hm1), ('HM2', kat_hm2), ('HM3', kat_hm3), ('HM4', kat_hm4), ('HM5', kat_hm5), ('HM6', kat_hm6),
        ('HM7', kat_hm7), ('HM8', kat_hm8), ('HM10', kat_hm10),
        ('HM12', kat_hm12)]

MUTATIONS = [
    ('HM1', 'rt', "    paused = miner if state == 'paused' else []", "    paused = []", 'paused miner ALERTs not listed'),
    ('HM1', 'rt', "    if miner and state != 'paused':", "    if miner:", 'a paused miner ALERT still exits 7 (pre-r27)'),
    ('HM1', 'rt', "    if node:\n        return 7", "    if False:\n        return 7", 'a node ALERT does not exit 7'),
    ('HM1', 'rt', "    if not any((up or {}).values()):", "    if False:", 'both endpoints down is not exit 2'),
    ('HM1', 'rt', "    al = [a for a in alerts or [] if a.get('level') == 'ALERT']", "    al = list(alerts or [])",
     'a WARN counts as an ALERT'),
    ('HM2', 'mi', "    return rep['exit']['rc']", "    return 7 if any(x['level'] == 'ALERT' for x in rep['alerts']) else 0",
     'main ignores the exit block (pre-r27 exit rule)'),
    ('HM2', 'mi', "    rep['exit'] = exit_block(rep, RT.track_state(RT.load(a.registry)))",
     "    rep['exit'] = exit_block(rep, ('paused', 'hard-coded'))", 'the registry is not read'),
    ('HM3', 'gates', "miner_alert = RT.miner_alert\n",
     "def miner_alert(a):\n    return a.get('rule') in MINER_ALERT_RULES or a.get('rule') == 'endpoint_down'\n",
     'run_gates keeps its own (looser) classifier'),
    ('HM3', 'rt', "(a.get('rule') == 'endpoint_down' and str(a.get('what', '')).startswith('miner '))",
     "(a.get('rule') == 'endpoint_down')", 'a derod endpoint_down counts as the miner'),
    ('HM4', 'lw', "    if u.port in REFUSED_PORTS:", "    if False:", 'getwork/P2P port accepted'),
    ('HM4', 'lw', "    if u.scheme != 'http' or u.hostname not in LOOPBACK:", "    if u.scheme not in ('http', 'https'):",
     'a remote host accepted'),
    ('HM4', 'lw', "        if method not in READ_METHODS:", "        if False:", 'a write method is sent'),
    ('HM5', 'lw', "    return prev_up is not None and cur_up < prev_up", "    return False", 'an uptime drop is not a restart'),
    ('HM5', 'lw', "    if prev_down:\n        return True", "    if False:\n        return True", 'down -> up is not a restart'),
    ('HM5', 'lw', "        prev_down = cur is None\n", "        prev_down = False\n", 'down -> up across probes is not seen'),
    ('HM6', 'lw', "    rs = sum(1 for a, b in zip(ups, ups[1:]) if a is not None and b is not None and b < a)", "    rs = 0",
     'restarts inside the window not counted'),
    ('HM6', 'lw', "        w(f\"first sample {uptime(f)} s after the derod start", "        (f\"first sample {uptime(f)} s after the derod start",
     'the first-sample delay is not stated'),
    ('HM6', 'lw', "    good = [r for r in rows if ok(r.get('sync')) and ok(r.get('cs'))]", "    good = list(rows)",
     'failed reads are summarised as samples'),
    ('HM6', 'lw', "        if labels and PEER_LABEL_RX.search(labels):", "        if False:", '/metrics peer labels echoed (seen live)'),
    ('HM6', 'lw', "PEER_LABEL_RX = re.compile(r'(?:peer|addr|ip|remote)=\"|", "PEER_LABEL_RX = re.compile(r'(?:peer|addr|ip)=\"|",
     'a remote= label is not treated as a peer'),
    ('HM7', 'lw', "        if metrics and metrics_every and i % metrics_every == 0:", "        if metrics:", 'a scrape every sample'),
    ('HM7', 'lw', "        if event and i == 0:", "        if event:", 'the event on every sample'),
    ('HM8', 'lw', "    if pruned and a < pruned:", "    if False:", 'a read below prunedheight'),
    ('HM10', 'fbv', "    './tools/emission-audit/': 'TestR27SeriesReadPayees',\n", "", 'an R27 Go test unregistered'),
    ('HM12', 'ti', "KAT_MUT_RX = re.compile(r'mutations (?:proved|caught) (\\d+)\\s*/\\s*(\\d+)')",
     "KAT_MUT_RX = re.compile(r'mutations proved (\\d+)\\s*/\\s*(\\d+)')", "the forensics KATs' 'caught' lines uncounted (pre-r27)"),
]


def copy_tree():
    d = Path(tempfile.mkdtemp(prefix='hm27-')) / 'harness'
    for rel in list(MODS.values()) + EXTRA:
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HARNESS / rel, d / rel)
    for rel in EXTRA_DIRS:
        shutil.copytree(HARNESS / rel, d / rel, dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__', '.cache'))
    # gen_deroarch resolves anchors against its ROOT and HERE/runtime: link the real tree's (read-only use)
    (d / 'runtime').symlink_to(HARNESS / 'runtime')
    for top in ('config', 'artifacts'):
        if (ROOT / top).exists():
            (d.parent / top).symlink_to(ROOT / top)
    return d


def main():
    fails = 0
    base = copy_tree()
    for name, fn in KATS:
        try:
            ok, det = fn(base)
        except (Exception, SystemExit) as e:                      # noqa: BLE001 — argparse exits are failures too
            ok, det = False, f'{type(e).__name__}: {e}'
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:500]}")
    shutil.rmtree(base.parent, ignore_errors=True)
    if fails:
        print(f'\nr27 harness-measure KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    missed, byname = 0, dict(KATS)
    for kat, mod, find, repl, why in MUTATIONS:
        d = copy_tree()
        p = d / (MODS.get(mod) or DATA[mod])
        text = p.read_text()
        if text.count(find) != 1:
            print(f'  ??      {kat}: {why} — find text occurs {text.count(find)} times')
            missed += 1
            shutil.rmtree(d.parent, ignore_errors=True)
            continue
        p.write_text(text.replace(find, repl))
        try:                                                        # a mutant that does not load is INVALID, never CAUGHT
            load(d, mod) if mod in MODS else json.loads(p.read_text())
        except Exception as e:                                      # noqa: BLE001
            print(f'  INVALID {kat}: {why} — mutant does not load ({type(e).__name__}: {e})')
            missed += 1
            shutil.rmtree(d.parent, ignore_errors=True)
            continue
        try:
            ok2 = byname[kat](d)[0]
        except (Exception, SystemExit):                            # noqa: BLE001 — a crash is a detection
            ok2 = False
        print(f"  {'proved ' if not ok2 else 'MISSED '} {kat}: {why}")
        missed += ok2
        shutil.rmtree(d.parent, ignore_errors=True)
    print(f'\nr27 harness-measure KATs: {len(KATS) - fails}/{len(KATS)} ok · mutations proved {len(MUTATIONS) - missed}/{len(MUTATIONS)}')
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
