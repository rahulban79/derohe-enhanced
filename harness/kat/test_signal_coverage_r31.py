#!/usr/bin/env python3
"""test_signal_coverage_r31.py — r31 Part B dimension 4 (observability; rft §7 B285 follow-up, B269 (d)): every derod
ERROR/WARNING literal has an error_census class, every own /metrics family is read or noted unread on purpose, and the
future-timestamp refusals are counted by peer and outcome.

  SG1 r31 sgclass  error_census SIGNAL_RULES (anchored; r31 d4 verify fix: a wrapper message such as 'Block rejected by
                   chain' is classed by its error only, so 'leveldb: closed' behind it stays node-bug): real derod
                   literals land in their class (future_timestamp, block_rejected,
                   tx_rejected, miner-caused, operator-input, local-io, network-env, audit-alert, peer-caused, a named
                   node-bug); the pre-r31 B269 ERROR (empty message, text in the error field) is future_timestamp; an
                   unknown ERROR still falls to 'node-bug: an ERROR no rule explains' and an unknown WARNING to unclassified
  SG2 B269         error_census future_timestamps: one entry per blid over the pre-r31 ERROR and the r31 INFO forms; the
                   peer is the verdict's peer_id, else the salted pseudonym of the P2P line naming 'Invalid Timestamp in
                   future', else 'unattributed'; outcome accepted-later when a later 'Chain extended' (also '... but height
                   is same': a side block) of the same blid exists, else never; by_peer / by_outcome add up; the census
                   carries the section, leaks() finds no address, and CORE.blid_<hash> lines are ONE kind
  SG3 r31 sgnote   detectors signal-coverage: a family with a valid not_read note is no finding (counted as noted), a
                   malformed note does not hide it, a note on a family a tool reads is a not-read-stale finding, and a
                   'superseded' note hides it only when the family it names IS read by a tool
  SG4 r31 sgk8     metric_registry K8: a bad category, a short reason, 'superseded' naming no other registered family,
                   'test-pinned' naming no Go test and a note on a vendored family are problems; valid notes are not;
                   build keeps every note across a rebuild
  SG5 r31 sgevent  detectors signal-coverage: an operator-input or local-io literal is no event whatever its words
                   ('--p2p-bind address is invalid', 'creating ban data file') when the class came from its MESSAGE; a
                   class from the error text waives nothing ('dropping chunk' + 'toporecord mismatch from peer' ->
                   event-no-counter); an unknown event literal ('peer data rejected, banning peer') is a medium
                   log-unmapped finding; a block_rejected literal with no counter is an event-no-counter finding
  SG6 r31 sgrows   live_window ROW_WATCH carries the B285 event rows; every family they name is registered; row_status
                   reads them: a moving guard counter is 'event seen', a registered zero is 'registered, no event'
  SG7 r31 sgtree   the repository itself (pristine tools, never the mutant): signal-coverage leaves 0 family-unread, 0
                   event-no-counter, 0 not-read-stale, and log-unmapped only on the DVM literals dimension 5 classes
                   (sc_revert / sc_panic_recovered / named node-bug, merged with R31 d5); metric_registry check passes

  python3 -I harness/kat/test_signal_coverage_r31.py      # KATs, then the mutations; exit 0 · 3 a KAT failed · 4 missed
"""
import contextlib, importlib.util, io, json, shutil, sys, tempfile, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'ec': 'harness/intel/error_census.py', 'det': 'harness/intel/detectors.py', 'mr': 'harness/intel/metric_registry.py',
         'lw': 'harness/intel/live_window.py'}
SIBLINGS = ('harness/intel/detectors.py', 'harness/intel/area_intel.py', 'harness/intel/error_census.py',
            'harness/intel/log_intel.py', 'harness/intel/backlog_truth.py', 'harness/kit/privkit.py',
            'harness/kit/pruneguard.py', 'harness/intel/metric_registry.py', 'harness/intel/live_window.py')
GOMOD = 'github.com/deroproject/derohe/'
SALT = 'k' * 40
DOC_IP = '.'.join(('203', '0', '113', '77'))          # documentation range (RFC 5737): never a real host


def tool_root(over):
    return Path(over.get('root') or ROOT)


def load(over, key):
    sys.path.insert(0, str(HARNESS / 'kit'))
    sys.path.insert(0, str(tool_root(over) / 'harness' / 'intel'))
    try:
        spec = importlib.util.spec_from_file_location(f'sg31_{key}_{uuid.uuid4().hex[:6]}', tool_root(over) / PATHS[key])
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    finally:
        sys.path.pop(0)
        sys.path.pop(0)


def W(root, rel, text):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def fixture_tree():
    d = Path(tempfile.mkdtemp(prefix='sg31-'))
    areas = [{'id': a, 'title': a, 'owner_dim': a, 'status': 'active', 'code_paths': cp, 'metrics': [], 'kat_files': [],
              'gates': [], 'gomut_prefixes': [], 'backlog': [], 'history': {}}
             for a, cp in (('observability', ['harness/intel/', 'metrics/']), ('chainperf', ['blockchain/']),
                           ('syncp2p', ['p2p/']), ('harness', ['harness/']))]
    W(d, 'harness/areas.json', json.dumps({'schema': 1, 'stale_rounds': 2, 'rounds': [{'id': 'r1'}], 'areas': areas}, indent=1))
    W(d, 'harness/round.json', json.dumps({'current': 'r1', 'rounds': [{'id': 'r1', 'tracks': {}}]}))
    W(d, 'cmd/derod/main.go', f'package main\n\nimport (\n\t"{GOMOD}blockchain"\n\t"{GOMOD}p2p"\n)\n\nfunc main() {{\n}}\n')
    return d


def run_det(over, root):
    D = load(over, 'det')
    return D.run(root, 'signal-coverage', rev='fixture', allow=[])


# ───────────────────────────── SG1 classes ─────────────────────────────
CASES = [  # (M, error, level, class)
    ('', 'Rejecting Block, timestamp is too much into future, make sure that system clock is correct', 'ERROR', 'future_timestamp'),
    ('Block rejected by chain', 'Invalid Timestamp in future', 'ERROR', 'future_timestamp'),
    ('Rejecting', 'Block is bigger than max permitted', 'ERROR', 'block_rejected'),
    ('rejecting block', 'TX nonce verification failed', 'ERROR', 'block_rejected'),
    ('duplicate nonce', 'Double Spend TX within block', 'ERROR', 'block_rejected'),
    ('TX rejected', 'Huge TX', 'ERROR', 'tx_rejected'),
    ('Incoming TX could not be verified', 'transaction statement 0 verification failed', 'ERROR', 'tx_rejected'),
    ('Job not found in cache', 'e', 'ERROR', 'miner-caused'),
    ('--p2p-bind address is invalid', 'e', 'ERROR', 'operator-input'),
    ('', 'POP needs argument n to pop this many blocks from the top', 'ERROR', 'operator-input'),
    ('creating ban data file', 'open x: permission denied', 'ERROR', 'local-io'),
    ('block template error ', 'leveldb: not found', 'ERROR', 'local-io'),
    ('Dial failed', 'i/o timeout', 'ERROR', 'network-env'),
    ('we want to broadcast block, but donot have peers, most possibly block will go stale', '', 'ERROR', 'network-env'),
    ('EMISSION AUDIT ALERT', 'mismatch', 'ERROR', 'audit-alert'),
    ('Incoming block could not be deserilised', 'cbor', 'ERROR', 'peer-caused'),
    ('Chain corruption detected', '', 'ERROR', 'node-bug'),
    ('Widget frobnication failed', 'e', 'ERROR', 'node-bug'),
    # r31 d4 verify fix: a wrapper message is classed by its runtime error only; a store failure stays a node-bug
    ('Block rejected by chain', 'leveldb: closed', 'ERROR', 'node-bug'),
    ('Block rejected by chain', 'error loading balance tree: missing node', 'ERROR', 'node-bug'),
    ('rejecting block', 'toporecord not found', 'ERROR', 'node-bug'),
    ('dropping chunk', 'toporecord mismatch from peer', 'ERROR', 'node-bug'),
    ('Block rejected by chain', 'Invalid PoW', 'ERROR', 'block_rejected'),
    ('Could not listen on the second port either', 'e', 'ERROR', 'node-bug'),    # a rule is the WHOLE literal
    ('WARNING: a thing nobody has seen', '', 'WARN', 'unclassified'),
]


def kat_sg1(over):
    EC = load(over, 'ec')
    got, bad = [], []
    for m, e, lv, want in CASES:
        rec = {'L': 'ERROR' if lv == 'ERROR' else 'INFO', 'T': '2026-11-13T00:00:00.000-0800', 'N': 'CORE', 'M': m, 'error': e}
        cls, why, _ = EC.classify(rec, lv, None, e, [])
        got.append(cls)
        if cls != want:
            bad.append((m or e)[:30] + f' {cls}!={want}')
    fallback = all(EC.classify({'L': 'ERROR', 'T': '2026-11-13T00:00:00.000-0800', 'N': 'CORE', 'M': m}, 'ERROR', None, e, [])[1]
                   == 'an ERROR no rule explains' for m, e in (('Widget frobnication failed', 'e'),
                                                                ('Block rejected by chain', 'leveldb: closed')))
    named = EC.classify({'L': 'ERROR', 'T': '2026-11-13T00:00:00.000-0800', 'N': 'CORE', 'M': 'Chain corruption detected'},
                        'ERROR', None, '', [])[1] != 'an ERROR no rule explains'
    return not bad and fallback and named, f'{len(CASES) - len(bad)}/{len(CASES)} {bad[:4]} fallback {fallback} named {named}'


# ───────────────────────────── SG2 B269 future_timestamp ─────────────────────────────
A, B, C, D = ('a1' * 32, 'b2' * 32, 'c3' * 32, 'd4' * 32)


def rec(L, T, N, C_, M, **kv):
    return json.dumps({'L': L, 'T': T, 'N': N, 'C': C_, 'M': M, **kv})


def future_log():
    t = lambda s: f'2026-11-11T11:{s}-0800'
    old = 'Rejecting Block, timestamp is too much into future, make sure that system clock is correct'
    return [
        rec('INFO', t('00:00.000'), 'derod', 'derod/main.go:160', 'DERO HE daemon :  It is an alpha version'),
        # A: pre-r31 ERROR + the r25 verdict naming the peer; accepted later as a side block
        rec('ERROR', t('09:05.284'), f'CORE.blid_{A}', 'blockchain/blockchain.go:527', '', error=old),
        rec('INFO', t('09:05.290'), 'P2P', 'p2p/consensus_obs_r25.go:332', 'Block rejected', blid=A, height=7888575,
            reason='future_timestamp', peer_id='5ec3fc7b694e03ba', err='Invalid Timestamp in future', suppressed=0),
        rec('DEBUG', t('09:30.000'), f'CORE.blid_{A}', 'blockchain/blockchain.go:926', 'Chain extended but height is same'),
        # B: the r31 forms (rule line V(1) Info with skew, console verdict with skew); never accepted
        rec('INFO', t('10:00.000'), f'CORE.blid_{B}', 'blockchain/blockchain.go:531',
            'Rejecting Block, timestamp is too much into future', height=7888580, skew_ms=600, limit_ms=50),
        rec('INFO', t('10:00.001'), 'P2P', 'p2p/consensus_obs_r25.go:337', 'Block rejected', blid=B, height=7888580,
            reason='future_timestamp', peer_id='5ec3fc7b694e03ba', err='Invalid Timestamp in future', suppressed=0, skew_ms=640),
        # C: pre-r31 ERROR only; the peer named by the P2P line (address -> salted pseudonym); accepted later
        rec('ERROR', t('11:00.000'), f'CORE.blid_{C}', 'blockchain/blockchain.go:527', '', error=old),
        rec('ERROR', t('11:00.400'), f'P2P.incoming.{DOC_IP}:58634', 'p2p/chain_sync.go:472',
            'Incoming Block could not be added due to some error', error='Invalid Timestamp in future'),
        rec('DEBUG', t('11:40.000'), f'CORE.blid_{C}', 'blockchain/blockchain.go:924', 'Chain extended', **{'new height': 7888590}),
        # D: pre-r31 ERROR, no verdict and no P2P line within the window
        rec('ERROR', t('12:00.000'), f'CORE.blid_{D}', 'blockchain/blockchain.go:527', '', error=old),
        rec('ERROR', t('12:30.000'), f'P2P.incoming.{DOC_IP}:1', 'p2p/chain_sync.go:472',
            'Incoming Block could not be added due to some error', error='Invalid Timestamp in future'),
    ]


def kat_sg2(over):
    EC = load(over, 'ec')
    lines = future_log()
    run = [dict(json.loads(l), _f='derod.log', _n=i + 1) for i, l in enumerate(lines)]
    ft = EC.future_timestamps(run, SALT)
    peer_c = EC.privkit.pseudo_ip(DOC_IP, SALT)
    by = {b['blid']: (b['peer'], b['outcome'], b['refusal_lines'], b['skew_ms_max']) for b in ft['detail']}
    want = {A[:16]: ('5ec3fc7b694e03ba', 'accepted-later', 2, None), B[:16]: ('5ec3fc7b694e03ba', 'never', 2, 640),
            C[:16]: (peer_c, 'accepted-later', 1, None), D[:16]: ('unattributed', 'never', 1, None)}
    peers_ok = ft['by_peer'] == {'5ec3fc7b694e03ba': {'blocks': 2, 'refusal_lines': 4, 'accepted-later': 1, 'never': 1},
                                 peer_c: {'blocks': 1, 'refusal_lines': 1, 'accepted-later': 1, 'never': 0},
                                 'unattributed': {'blocks': 1, 'refusal_lines': 1, 'accepted-later': 0, 'never': 1}}
    with tempfile.TemporaryDirectory(prefix='sg31-log-') as d:
        p = Path(d) / 'derod.log'
        p.write_text('\n'.join(lines) + '\n')
        rep = EC.census(EC.records([p]), 1, call_log=str(Path(d) / 'none.jsonl'), salt=SALT)
    text = json.dumps(rep)
    blid_kinds = [k for k in rep['kinds'] if k['caller'] == 'blockchain/blockchain.go:527']
    ok = (by == want and peers_ok and ft['by_outcome'] == {'accepted-later': 2, 'never': 2}
          and rep['future_timestamp']['blocks'] == 4 and not EC.leaks(text) and DOC_IP not in text
          and len(blid_kinds) == 1 and blid_kinds[0]['count'] == 3)
    return ok, f'{by} | by_peer ok {peers_ok} | {ft["by_outcome"]} | blid kinds {[(k["count"], k["class"]) for k in blid_kinds]} | leaks {EC.leaks(text)}'


# ───────────────────────────── SG3 / SG5 detector ─────────────────────────────
REG_FAMS = [
    {'name': 'dero_noted_total', 'type': 'counter', 'area': 'chainperf', 'source': 'blockchain/b.go',
     'not_read': 'diagnostic: a drill-down series that no harness decision depends on at all'},
    {'name': 'dero_badnote_total', 'type': 'counter', 'area': 'chainperf', 'source': 'blockchain/b.go', 'not_read': 'because'},
    {'name': 'dero_readnote_total', 'type': 'counter', 'area': 'chainperf', 'source': 'blockchain/b.go',
     'not_read': 'diagnostic: said unread although a reader names it below'},
    {'name': 'dero_plain_total', 'type': 'counter', 'area': 'chainperf', 'source': 'blockchain/b.go'},
    {'name': 'dero_supok_total', 'type': 'counter', 'area': 'chainperf', 'source': 'blockchain/b.go',
     'not_read': 'superseded: dero_readnote_total carries the same signal and a tool reads it'},
    {'name': 'dero_supbad_total', 'type': 'counter', 'area': 'chainperf', 'source': 'blockchain/b.go',
     'not_read': 'superseded: dero_plain_total carries it, though no tool reads that one either'},
]


def kat_sg3(over):
    r = fixture_tree()
    W(r, 'blockchain/b.go', 'package blockchain\n\nvar a = metrics.NewCounter("dero_noted_total")\nvar b = metrics.NewCounter("dero_badnote_total")\n'
      'var c = metrics.NewCounter("dero_readnote_total")\nvar d = metrics.NewCounter("dero_plain_total")\n')
    W(r, 'p2p/p.go', 'package p2p\n')
    W(r, 'metrics/metric_registry.json', json.dumps({'families': REG_FAMS}, indent=1))
    W(r, 'harness/intel/reader_x.py', "WANT = ('dero_readnote_total',)\n")
    doc = run_det(over, r)
    shutil.rmtree(r, ignore_errors=True)
    got = sorted((f['kind'], f.get('family')) for f in doc['findings'])
    want = [('family-unread', 'dero_badnote_total'), ('family-unread', 'dero_plain_total'), ('family-unread', 'dero_supbad_total'),
            ('not-read-stale', 'dero_readnote_total')]
    return got == want and doc['inputs'].get('families_not_read_noted') == 2, f"{got} noted {doc['inputs'].get('families_not_read_noted')}"


class _Census:
    """SG5's census: the classes come from this stub (SG1 owns the real rules), NON_EVENT_CLASSES from the tool."""
    CLS = {'--p2p-bind address is invalid': 'operator-input', 'creating ban data file': 'local-io',
           'Rejecting': 'block_rejected'}

    VIA = {'dropping chunk': ('local-io', 'err')}       # a class that came from the ERROR text: no waiver

    def __init__(self, ec):
        self.NON_EVENT_CLASSES = ec.NON_EVENT_CLASSES

    def classify(self, d, lv, of, err, calls):
        c = self.CLS.get(d.get('M')) or self.VIA.get(d.get('M'), (None,))[0]
        return (c, 'stub', False) if c else ('node-bug', 'an ERROR no rule explains', False)

    def signal_class(self, d, err):
        if d.get('M') in self.CLS:
            return self.CLS[d.get('M')], 'stub', 'msg'
        if d.get('M') in self.VIA:
            return self.VIA[d.get('M')][0], 'stub', self.VIA[d.get('M')][1]
        return None

    def wrapper_class(self, msg):
        return None


def kat_sg5(over):
    r = fixture_tree()
    W(r, 'p2p/controller.go', 'package p2p\n\nfunc P2P_Init() {\n\tlogger.Error(err, "--p2p-bind address is invalid")\n'
      '\tlogger.Error(err, "creating ban data file")\n\tlogger.V(1).Error(err, "peer data rejected, banning peer")\n'
      '\tlogger.Error(fmt.Errorf("toporecord mismatch from peer"), "dropping chunk")\n}\n')
    W(r, 'blockchain/blockchain.go', 'package blockchain\n\nfunc (chain *Blockchain) add() {\n'
      '\tblock_logger.Error(fmt.Errorf("Block is bigger than max permitted"), "Rejecting")\n}\n')
    W(r, 'metrics/metric_registry.json', json.dumps({'families': []}))
    D = load(over, 'det')
    census, findings, _, _ = D.detect_signal_coverage(D.Tree(r), {'ec': _Census(load(over, 'ec'))})
    doc = {'findings': findings, 'census': census}
    shutil.rmtree(r, ignore_errors=True)
    got = sorted((f['kind'], f['file'], f.get('text', '')[:20]) for f in doc['findings'])
    want = [('event-no-counter', 'blockchain/blockchain.go', 'Block is bigger than'),
            ('event-no-counter', 'p2p/controller.go', 'toporecord mismatch '),
            ('log-unmapped', 'p2p/controller.go', 'peer data rejected, ')]
    ev = {c['text'][:20]: c['event'] for c in doc['census'] if 'text' in c}
    sev = {f.get('text', '')[:20]: f['severity'] for f in doc['findings']}
    return (got == want and ev.get('--p2p-bind address i') is False and sev.get('peer data rejected, ') == 'medium',
            f'{got} events {ev} severity {sev}')


# ───────────────────────────── SG4 K8 ─────────────────────────────
def kat_sg4(over):
    MR = load(over, 'mr')
    reg = {'families': [
        {'name': 'a_total', 'type': 'counter', 'unit': '1', 'area': 'x', 'help': 'h', 'source': 'dynamic',
         'not_read': 'diagnostic: an operator drill-down series only'},
        {'name': 'b_total', 'type': 'counter', 'unit': '1', 'area': 'x', 'help': 'h', 'source': 'dynamic',
         'not_read': 'nonsense: a category nobody defined for this registry'},
        {'name': 'c_total', 'type': 'counter', 'unit': '1', 'area': 'x', 'help': 'h', 'source': 'dynamic', 'not_read': 'diagnostic: short'},
        {'name': 'd_total', 'type': 'counter', 'unit': '1', 'area': 'x', 'help': 'h', 'source': 'dynamic',
         'not_read': 'superseded: another family carries it, but which one is not said'},
        {'name': 'e_total', 'type': 'counter', 'unit': '1', 'area': 'x', 'help': 'h', 'source': 'dynamic',
         'not_read': 'superseded: a_total carries the same signal and a tool reads it'},
        {'name': 'f_total', 'type': 'counter', 'unit': '1', 'area': 'x', 'help': 'h', 'source': 'dynamic',
         'not_read': 'test-pinned: a mechanism counter pinned by a unit test somewhere'},
        {'name': 'g_total', 'type': 'counter', 'unit': '1', 'area': 'x', 'help': 'h', 'source': 'dynamic',
         'not_read': 'test-pinned: pinned by TestR31Something in the package tests'},
        {'name': 'go_h_total', 'type': 'counter', 'unit': '1', 'area': 'x', 'help': 'h', 'source': 'vendored',
         'not_read': 'diagnostic: a vendored family that is skipped anyway'}]}
    with tempfile.TemporaryDirectory(prefix='sg31-mr-') as d:
        probs = [m.split(':')[0] for k, m in MR.check(reg, root=Path(d)) if k == 'K8']
        W(d, 'harness/areas.json', json.dumps({'areas': [{'id': 'observability', 'code_paths': ['metrics/']}]}))
        W(d, 'metrics/m.go', 'package metrics\n\nvar x = Set.NewCounter("dero_kept_total") // a kept family of the fixture\n')
        old = {'families': [{'name': 'dero_kept_total', 'not_read': 'diagnostic: an operator drill-down series only'}]}
        new = MR.build(Path(d), 'dero_kept_total 0\n', old)
    kept = [e.get('not_read') for e in new['families'] if e['name'] == 'dero_kept_total']
    want = ['b_total', 'c_total', 'd_total', 'f_total', 'go_h_total']
    return sorted(probs) == want and kept == ['diagnostic: an operator drill-down series only'], f'K8 {sorted(probs)} kept {kept}'


# ───────────────────────────── SG6 live_window rows ─────────────────────────────
def kat_sg6(over):
    LW = load(over, 'lw')
    rows = {eid: names for eid, _, names, _ in LW.ROW_WATCH if eid.startswith('B285-')}
    reg = {e['name'] for e in json.loads((ROOT / 'metrics' / 'metric_registry.json').read_text())['families']}
    named = [n for ns in rows.values() for n in ns]
    unreg = [n for n in named if n.split('{')[0] not in reg]
    good = [{'cs': {'ok': True}, 'sync': {'height': 100 + i, 'topoheight': 100 + i}, 'epoch': 1000 + 60 * i,
             'info': {'tx_pool_size': 0}} for i in range(3)]
    p0 = 'rpc_guard_refused_total{reason="host"} 0\ntx_pool_refused_total{reason="oversize"} 0\n'
    p1 = 'rpc_guard_refused_total{reason="host"} 4\ntx_pool_refused_total{reason="oversize"} 0\n'
    st = LW.row_status(good, [p0, p1])
    need = {'B285-pool', 'B285-canon', 'B285-rpc-defence', 'B285-p2p-defence', 'B285-node-errors'}
    ok = (need <= set(rows) and 'tx_pool_refused_total' in rows.get('B285-pool', ()) and not unreg
          and st.get('B285-rpc-defence', ('',))[0] == 'event seen' and st.get('B285-pool', ('',))[0] == 'registered, no event'
          and st.get('B285-canon', ('',))[0] == 'absent')
    return ok, f'rows {sorted(rows)} unregistered {unreg} | {[(k, st[k][0]) for k in sorted(st) if k.startswith("B285")][:4]}'


# ───────────────────────────── SG7 the repository ─────────────────────────────
DVM_TEXTS = ('error Parsing hard coded sc', 'SC not found', 'error executing sc')
_SG7 = {}


def kat_sg7(over):
    if 'r' not in _SG7:                       # pristine tools over the real tree; a mutant run re-uses the verdict
        D = load({}, 'det')
        doc = D.run(ROOT, 'signal-coverage', rev='kat')
        MR = load({}, 'mr')
        probs = MR.check(json.loads((ROOT / 'metrics' / 'metric_registry.json').read_text()), root=ROOT)
        kinds = {}
        for f in doc['findings']:
            kinds.setdefault(f['kind'], []).append(f.get('text') or f.get('family'))
        left = [t for t in kinds.get('log-unmapped', []) if not str(t).endswith(DVM_TEXTS)]
        ok = (not kinds.get('family-unread') and not kinds.get('event-no-counter') and not kinds.get('not-read-stale')
              and not left and not probs and not doc['allow_problems'])
        _SG7['r'] = (ok, f"{ {k: len(v) for k, v in kinds.items()} } other unmapped {left[:3]} registry problems {probs[:2]} "
                         f"allow {doc['allow_problems'][:2]} noted {doc['inputs'].get('families_not_read_noted')}")
    return _SG7['r']


KATS = [('SG1', kat_sg1), ('SG2', kat_sg2), ('SG3', kat_sg3), ('SG4', kat_sg4), ('SG5', kat_sg5), ('SG6', kat_sg6),
        ('SG7', kat_sg7)]
OWNERS = {'r31 sgclass': ['SG1'], 'B269': ['SG2'], 'r31 sgnote': ['SG3'], 'r31 sgk8': ['SG4'], 'r31 sgevent': ['SG5'],
          'r31 sgrows': ['SG6']}
MUTATIONS = [
    ('ec', "    (_ERR, r'Rejecting Block, timestamp is too much into future(?:, make sure", "    (_ERR, r'XXRejecting Block(?:, make sure",
     'r31 sgclass: the B269 literals lose their class'),
    ('ec', "    sc = signal_class(d, err)               # r31 d4", "    sc = None  # ", 'r31 sgclass: the signal rules are never consulted'),
    ('ec', "        if via == _ERR and e and rx.fullmatch(e):", "        if False:",
     'r31 sgclass: the literal-error rules are never matched (the pre-r31 B269 ERROR has an empty message)'),
    ('ec', "        return None                       # a store or other failure behind a wrapper: node-bug, read it",
     "        return w, 'any error', 'wrap'", 'r31 sgclass: a wrapper line with a store error is classed as a refusal'),
    ('ec', "        if via == _MSG and m and rx.fullmatch(m):", "        if via == _MSG and m and rx.search(m):",
     'r31 sgclass: message rules match a substring, not the whole literal'),
    ('ec', "|Chain corruption detected|'", "|Chain corruption detectedXX|'",
     'r31 sgclass: a named node-bug falls back to the unexplained node-bug'),
    ('ec', "                      and str(d.get('M', '')).startswith('Chain extended')), None)",
     "                      and str(d.get('M', '')) == 'Chain extended'), None)", 'B269: a side block accepted later counts as never'),
    ('ec', "        b['peer'] = b['peer'] or peer\n", "        b['peer'] = b['peer']\n", 'B269: the verdict peer_id is ignored'),
    ('ec', "                b['peer'] = privkit.pseudo_ip(a.group(1), salt) if salt else 'unattributed'",
     "                b['peer'] = a.group(1)", 'B269: the peer address is written instead of its pseudonym'),
    ('ec', "    key = (lv, BLID_N.sub(r'\\1H', component(d)), ", "    key = (lv, component(d), ", 'B269: one census kind per refused block'),
    ('det', "        if note_ok:                                     # r31 d4", "        if False:                                     # r31 d4",
     'r31 sgnote: a valid not_read note is not honoured'),
    ('det', "        if rd and note is not None:", "        if False and rd:", 'r31 sgnote: a stale note is not reported'),
    ('det', "        note_ok = (note is not None and mr is not None and mr.not_read_problem(note, name, reg_names) is None\n",
     "        note_ok = (note is not None\n", 'r31 sgnote: a malformed note hides the family'),
    ('mr', "    if cat not in NOT_READ_CATEGORIES:", "    if False:", 'r31 sgk8: any category passes'),
    ('mr', "    if cat == 'superseded' and not any(", "    if False and not any(", 'r31 sgk8: superseded need not name a family'),
    ('mr', "    if cat == 'test-pinned' and not TEST_NAME_RX.search(why):", "    if False:", 'r31 sgk8: test-pinned need not name a test'),
    ('mr', "            elif e.get('source') in ('vendored', None):", "            elif False:", 'r31 sgk8: a note on a vendored family passes'),
    ('mr', "        if name in notes:\n            e['not_read'] = notes[name]\n", "", 'r31 sgk8: build drops the notes'),
    ('det', "            event = event and not (mapped and via == 'msg' and cls in getattr(ec, 'NON_EVENT_CLASSES', ()))\n", "",
     'r31 sgevent: an operator-input literal is an event'),
    ('det', "            event = event and not (mapped and via == 'msg' and cls in", "            event = event and not (mapped and cls in",
     'r31 sgevent: a class from the error text waives the counter'),
    ('det', "                   and superseder_read(note, name))", "                   )",
     'r31 sgnote: a superseded note may name a family no tool reads'),
    ('ec', "NON_EVENT_CLASSES = ('operator-input', 'local-io', 'network-env', 'audit-alert')",
     "NON_EVENT_CLASSES = ('operator-input',)", 'r31 sgevent: a local-io literal is an event'),
    ('lw', "    ('B285-rpc-defence', 'an RPC refusal", "    ('X285-rpc-defence', 'an RPC refusal", 'r31 sgrows: the RPC defence row is gone'),
    ('lw', "     ('tx_pool_refused_total', 'mempool_discarded_total'), None),", "     ('mempool_discarded_total',), None),",
     'r31 sgrows: the pool row does not read tx_pool_refused_total'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_sg31', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run_kats(over):
    res = []
    for name, fn in KATS:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
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
        print(f'\nr31 signal-coverage KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = coupled = 0
    for key, find, repl, why in MUTATIONS:
        text = (ROOT / PATHS[key]).read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='sg31-mut-') as d:
            for rel in set(SIBLINGS) | set(PATHS.values()):      # the mutant tool root: the tools load their siblings
                (Path(d) / rel).parent.mkdir(parents=True, exist_ok=True)
                (Path(d) / rel).write_text((ROOT / rel).read_text(encoding='utf-8'), encoding='utf-8')
            (Path(d) / PATHS[key]).write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({'root': d}) if not ok]
        verdict, cpl = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
        coupled += bool(cpl)
    print('\n' + K.summary('r31 signal-coverage KATs', len(KATS), len(MUTATIONS), missed, coupled))
    return 4 if missed or coupled else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
