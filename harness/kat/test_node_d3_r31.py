#!/usr/bin/env python3
"""test_node_d3_r31.py — r31 Part B dimension 3 (node; dero-rft §7 B294, B269 (a)/(d)): the harness half of the node
fixes. The Go half is p2p/r31_d3_node_test.go (gm-r31-d3-*).

  N1 B294: syncp2p compact_observed is the observed SHARE of blockchain_tx_total (prom_ratio, the B54 event as the
     divisor): 3 observed of 4 txs reads 0.75 (the old since-start count read 3, and 4 at r26 vs 1 at r30 was booked
     as a regression); no tx-carrying block (denominator 0) is pending, never 0; the converted r25/r26 history (1.0)
     against today's 1.0 is no regression, and a real drop (0.75) still is
  N2 B269: consensus_intel.reject_literals reads the future-timestamp rule's new V(1) Info literal ("Rejecting Block,
     timestamp is too much into future") as a rejection line, keeps the ERROR literals, and never takes another
     block_logger.Info literal ("Chain extended") for one; on the real tree the rule's literal is found
  N3 B269: parse_logs counts both forms in a derod JSON log (the new Info line and the pre-r31 ERROR line, whose text
     contains the same literal) as timed rejection events, so D02 keeps counting across the change
  N4 B269: peer_intel captures GetPeerInfo future_blocks / future_skew_max_ms (r31 build) and D6 grades a peer whose
     blocks were refused as future-stamped OBSERVED (source GetPeerInfo.future_blocks), naming the skew; a peer at 0
     adds no finding (an r30-shaped capture without the fields is unchanged)

  python3 -I harness/kat/test_node_d3_r31.py      # exit 0 · 3 a KAT failed · 4 a mutation was missed
"""
import contextlib, importlib.util, io, json, sys, tempfile, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'ai': 'harness/intel/area_intel.py', 'ci': 'harness/intel/consensus_intel.py', 'reg': 'harness/areas.json',
         'pi': 'harness/intel/peer_intel.py'}
SIBLINGS = ('harness/intel/area_intel.py', 'harness/intel/consensus_intel.py', 'harness/areas.json', 'harness/intel/coherence.py',
            'harness/intel/backlog_truth.py', 'harness/intel/peer_intel.py', 'harness/miners/mine_peers.py',
            'harness/miners/minelib.py', 'harness/kit/privkit.py', 'harness/intel/log_intel.py', 'harness/miners/mine_triage.py')
FUT = 'Rejecting Block, timestamp is too much into future'


def load(over, key):
    root = Path(over.get('root') or ROOT)
    spec = importlib.util.spec_from_file_location(f'd3_{key}_{uuid.uuid4().hex[:6]}', root / PATHS[key])
    m = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(root / 'harness' / 'intel'))
    try:
        spec.loader.exec_module(m)
    finally:
        sys.path.pop(0)
    return m


def reg_of(over):
    return json.loads((Path(over.get('root') or ROOT) / PATHS['reg']).read_text())


def compact_value(m, reg, observed, total):
    with tempfile.TemporaryDirectory() as d:
        rt = Path(d) / 'harness' / 'runtime'
        rt.mkdir(parents=True)
        (rt / 'area_prom_20991231T000000.txt').write_text('# version 3.6.0-153.DEROHE.STARGATE+22102026.r31\n'
                                                          f'block_tx_roundtrip_observed_total {observed}\nblockchain_tx_total {total}\n')
        out, _ = m.current_values(Path(d), reg)
    return out.get('syncp2p', {}).get('compact_observed')


def kat_n1(over):
    m, reg = load(over, 'ai'), reg_of(over)
    a = next(x for x in reg['areas'] if x['id'] == 'syncp2p')
    md = next(x for x in a['metrics'] if x['id'] == 'compact_observed')
    v34, v00 = compact_value(m, reg, 3, 4), compact_value(m, reg, 0, 0)
    h26 = a['history']['r26']['compact_observed']
    pt = lambda r, v: {'round': r, 'value': v, 'display': str(v), 'anchor': {}}
    _, _, reg_same = m.metric_trend(md, [pt('r26', h26['value']), pt('r31', 1.0)], ROOT)
    _, _, reg_drop = m.metric_trend(md, [pt('r26', h26['value']), pt('r31', 0.75)], ROOT)
    errs, _ = m.validate(reg, ROOT)
    ok = (md['source'].get('kind') == 'prom_ratio' and md['source'].get('den') == 'blockchain_tx_total'
          and v34 and v34.get('value') == 0.75 and v00 and m.is_pending(v00.get('value'))
          and h26['value'] == 1.0 and not reg_same and reg_drop and not errs)
    return ok, (md['source'], v34, v00, h26.get('value'), reg_same, reg_drop, errs[:2])


GO = ('\t\tblock_logger.Info("Chain extended", "new height", height)\n'
      '\t\tblock_logger.Info("' + FUT + '", "height", bl.Height, "skew_ms", 1)\n'
      '\t\tblock_logger.Error(fmt.Errorf("Block timestamp is less than or equal to its parent."), "rejecting block")\n'
      '\t\t// block_logger.Error(fmt.Errorf("Commented out rule never prints"), "")\n')


def kat_n2(over):
    m = load(over, 'ci')
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / 'blockchain').mkdir()
        (Path(d) / 'blockchain/blockchain.go').write_text(GO)
        got = [x[0] for x in m.reject_literals(Path(d))]
    real = [x[0] for x in m.reject_literals(Path(over.get('root') or ROOT))]
    ok = got == [FUT, 'Block timestamp is less than or equal to its parent.'] and FUT in real
    return ok, (got, FUT in real, len(real))


def kat_n3(over):
    m = load(over, 'ci')
    new = {'L': 'DEBUG', 'T': '2026-11-13T10:00:00.000-0800', 'N': 'CORE.blid_ab', 'M': FUT, 'height': 7888575, 'skew_ms': 412}
    old = {'L': 'ERROR', 'T': '2026-11-11T11:09:00.000-0800', 'N': 'CORE.blid_cd', 'M': '',
           'error': FUT + ', make sure that system clock is correct'}
    other = {'L': 'DEBUG', 'T': '2026-11-13T10:00:01.000-0800', 'N': 'CORE.blid_ef', 'M': 'Chain extended', 'new height': 5}
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / 'blockchain').mkdir()
        (Path(d) / 'blockchain/blockchain.go').write_text(GO)
        lp = Path(d) / 'derod.log'
        lp.write_text('\n'.join(json.dumps(x) for x in (new, old, other)) + '\n')
        r = m.parse_logs([str(lp)], Path(d))
    rej = [e for e in r['wevents'] if e.get('k') == 'reject']
    ok = len(rej) == 2 and all(FUT in e['msg'] for e in rej) and r['census'].get('block_rejected:' + FUT) == 2
    return ok, (rej, r['census'])


def kat_n4(over):
    sp = importlib.util.spec_from_file_location(f'pi25_{uuid.uuid4().hex[:6]}', HARNESS / 'kat' / 'test_peer_intel_r25.py')
    H = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(H)
    base = Path(over.get('root') or ROOT) / 'harness'
    ips = H.NORMAL_IPS[:4]
    ps = [H.peer(ip, future_blocks=0, future_skew_max_ms=0) for ip in ips[:3]] + \
         [H.peer(ips[3], future_blocks=3, future_skew_max_ms=412)]
    d = H.det(H.run(base, ps)[0], 'D6')
    hit = [f for f in d['findings'] if f.get('source') == 'GetPeerInfo.future_blocks']
    d0 = H.det(H.run(base, [H.peer(ip) for ip in ips])[0], 'D6')
    ok = (d['grade'] == 'OBSERVED' and len(hit) == 1 and hit[0]['grade'] == 'OBSERVED' and '412 ms' in hit[0]['what']
          and '3 block(s)' in hit[0]['what'] and d0['grade'] == 'NORMAL' and not d0['findings'])
    return ok, (d['grade'], hit, d0['grade'])


KATS = [('N1', kat_n1), ('N2', kat_n2), ('N3', kat_n3), ('N4', kat_n4)]
OWNERS = {'B294': ['N1'], 'B269': ['N2', 'N3', 'N4']}
MUTATIONS = [
    ('reg', '"kind": "prom_ratio",\n      "num": "block_tx_roundtrip_observed_total",',
     '"kind": "prom",\n      "name": "block_tx_roundtrip_observed_total",\n      "num": "block_tx_roundtrip_observed_total",',
     'B294: compact_observed is the since-start count again'),
    ('reg', '"den": "blockchain_tx_total",\n      "scale": 1', '"den": "p2p_sync_blocks_fetched_total",\n      "scale": 1',
     'B294: the divisor is not the B54 event (tx-carrying blocks)'),
    ('ci', '|Info\\((?="Rejecting ))', '', 'B269: the rule\'s new Info literal is not a rejection line (D02 stops counting)'),
    ('ci', '(?="Rejecting ))', ')', 'B269: every block_logger.Info literal is taken for a rejection'),
    ('pi', "        if 'future_blocks' in p:", "        if False:", 'B269: the capture drops GetPeerInfo future_blocks'),
    ('pi', "            if (p.get('future_blocks') or 0) > 0:", "            if False:", 'B269: D6 ignores refused future-stamped blocks'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_d3r31', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run_kats(over):
    res = []
    for name, fn in KATS:
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                ok, det = fn(over)
        except (Exception, SystemExit) as e:                      # noqa: BLE001 — a crash is a failure
            ok, det = False, f'{type(e).__name__}: {e}'
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
        print(f'\nr31 node-d3 KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='d3r31-mut-') as d:
            for rel in SIBLINGS:                                   # the mutant tree: the tools load their siblings
                if (ROOT / rel).exists():
                    (Path(d) / rel).parent.mkdir(parents=True, exist_ok=True)
                    (Path(d) / rel).write_text((ROOT / rel).read_text(encoding='utf-8'), encoding='utf-8')
            (Path(d) / 'blockchain').mkdir(exist_ok=True)
            (Path(d) / 'blockchain/blockchain.go').write_text((ROOT / 'blockchain/blockchain.go').read_text(encoding='utf-8'))
            (Path(d) / PATHS[key]).write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({'root': d}) if not ok]
        verdict, cpl = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
        coupled += bool(cpl)
    print('\n' + K.summary('r31 node-d3 KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
