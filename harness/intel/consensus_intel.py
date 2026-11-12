#!/usr/bin/env python3
"""consensus_intel.py (r24) — the chain-consensus observatory: who makes the chain, is it made by the rules, and what
the daemon's own log says about it. Read-only: JSON-RPC and /metrics on 127.0.0.1:10102 and the derod JSON log.

Over a recent window (default the last 3,000 blocks, ~15 h) it measures and evidences
  1. participants: the miners of the 9 regular miniblocks of every block and the integrator paid by its final
     miniblock (rpc header `miners[]`, cmd/derod/rpc/blockheader.go), as salted pseudonyms; shares, concentration
     (top-1/top-3, HHI, Nakamoto coefficient by share), this node's own share (labelled `this-node`, never printed);
  2. consensus state: tip, stable height, fork fingerprint at HF3, side blocks (log) and reorgs (GetMonetaryIntegrity
     finality monitor), block-time distribution against the target (mean, median, p95; not averageblocktime50
     alone), timestamp monotonicity and arrival lag against the consensus limits, the difficulty series recomputed by
     the consensus rule (blockchain/difficulty.go) and its responsiveness, miniblocks per block, empty blocks, tx;
  3. detectors, each grounded in a consensus rule (the code line is cited and re-read) or a stated statistical test
     with its threshold, graded OBSERVED (a rule was violated: the rule line and the observation are cited),
     ANOMALY (statistically unusual: test and threshold stated), NORMAL, or NO-DATA;
  4. a census of the consensus-relevant derod log lines by kind and day, each kind joined to the Go literal that
     prints it.
Every consensus constant is parsed from the line of the tree that declares it (no typed numbers), and a rule whose
line cannot be found makes its detector NO-DATA, which fails gate G26.

Outputs (one fact per line, so every value is anchorable):
  harness/runtime/consensus_intel.json            the newest analysis (page source: miners/mine_consensus.py)
  harness/runtime/consensus_capture_<ts>.txt      the run's text capture: one line per KPI/participant/detector/log
                                                  kind/proposal (area history anchors cite these, they never change)
  harness/runtime/consensus_series.jsonl          one line per run: the rolling series
  <private>/captures/consensus_raw_<ts>.json      the pseudonymised raw capture (headers, miniblocks, log events),
                                                  outside the repo ($DERO_CONSENSUS_PRIVATE, default
                                                  ~/derohe-persist/consensus_private); --from re-analyses one

Privacy: miner addresses become 'm-' + 8 hex of blake2b(salt || address); the salt lives in the private dir
(0600) and never in the repo. This node's integrator address (read from derod's "will use" log line) is compared,
then dropped: its participant is 'this-node'. No peer address, tag or host name reaches any output.

  python3 -I harness/intel/consensus_intel.py [--window N] [--json-only] [--no-series]
  python3 -I harness/intel/consensus_intel.py --from <raw capture> [--out-dir D]   # re-analyse (KAT, replay)
  python3 -I harness/intel/consensus_intel.py g26                                  # gate G26 alone (exit 0 / 3)
Exit 0 ok · 2 cannot capture/analyse (rpc down, rule anchors missing, no salt) · 5 an OBSERVED detector fired.
"""
import argparse, collections, datetime, glob, hashlib, json, math, os, re, secrets, statistics, sys, time, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent
ROOT = HARNESS.parent
RPC_URL = 'http://127.0.0.1:10102/json_rpc'
METRICS_URL = 'http://127.0.0.1:10102/metrics'
LOG_GLOBS = [os.path.expanduser(os.environ.get('DERO_DATADIR', '~/dero-data')) + '/logs/derod*.log']
PRIVATE = Path(os.environ.get('DERO_CONSENSUS_PRIVATE') or (Path.home() / 'derohe-persist' / 'consensus_private'))
PRIVATE_KEEP = int(os.environ.get('DERO_PRIVATE_KEEP') or 8)                 # r24: private raw runs kept
PRIVATE_MAX_BYTES = int(os.environ.get('DERO_PRIVATE_MAX_BYTES') or 120 * 1024 * 1024)
SCHEMA = 'consensus_intel/1 (r24)'   # r25: fields added (fees, first_seen_ms, consensus_stats), none removed or renamed
DEFAULT_WINDOW = 3000
CHUNK = 100                 # GetBlockHeadersRange limit per call (cmd/derod/rpc/rpc_dero_explorer.go MAX_HEADERS_RANGE)
SLEEP_S = 0.4               # between range calls: keep the RPC load light (a few calls per second at most)
MBL_SAMPLE = 48             # GetMiniBlocks calls (cost 4 each) for the per-miniblock structure check
ALT_FETCH = 40              # side blocks fetched by hash (GetBlockHeaderByHash) to name their integrator
FRESH_H = 24
ALPHA = 0.001               # family-wise significance for every statistical detector (Bonferroni over participants)
LIVE_LAG_MAX_MS = 60_000    # a block first seen more than 60 s after its timestamp was synced, not received live
LOW_DECILE = 0.10
MIN_N = 20                  # participants with fewer blocks are not tested (too few for a tail test)
GRADES = ('OBSERVED', 'ANOMALY', 'NORMAL', 'NO-DATA')
FORK_HEIGHT_Q = ('config/config.go', None)   # placeholder: the HF3 height is read from globals (see RULES['hf3'])

# ─────────────────────────── consensus rules: the lines that declare them ───────────────────────────
# name: (file, verbatim quote, regex extracting the constant or None). The quote must be on ONE line of the tree.
RULES = {
    'block_time': ('config/config.go', 'const BLOCK_TIME = uint64(18)', r'uint64\((\d+)\)'),
    'mbl_highdiff': ('config/config.go', 'const MINIBLOCK_HIGHDIFF = 9', r'= (\d+)'),
    'stable_limit': ('config/config.go', 'const STABLE_LIMIT = int64(8)', r'int64\((\d+)\)'),
    'min_difficulty': ('config/config.go', 'MAINNET_MINIMUM_DIFFICULTY   uint64 `env:"MAINNET_MINIMUM_DIFFICULTY" envDefault:"100000"`', r'envDefault:"(\d+)"'),
    'diff_e': ('blockchain/difficulty.go', 'const E = float64(2.71828182845905)', r'float64\(([\d.]+)\)'),
    'diff_m': ('blockchain/difficulty.go', 'M := int64(8)', r'int64\((\d+)\)'),
    'diff_clamp': ('blockchain/difficulty.go', 'if solve_time > (block_time * 2) { // there should not be sudden decreases', r'\* (\d+)\)'),
    'diff_step': ('blockchain/difficulty.go', 'easypart := int64(math.Pow(E, ((1-float64(solvetime)/float64(blocktime))/float64(M))) * 10000)', None),
    'diff_tip': ('blockchain/difficulty.go', 'solve_time := int64(tip_time - parent_time)', None),
    'diff_floor': ('blockchain/difficulty.go', 'if difficulty.Cmp(MinimumDifficulty) < 0 { // we can never be below minimum difficulty', None),
    'ts_future': ('blockchain/blockchain.go', 'if bl.Timestamp > (uint64(globals.Time().UTC().UnixMilli() + 50)) { // give 50 millisec passing', r'\+ (\d+)\)\)'),
    'ts_parent': ('blockchain/blockchain.go', 'if chain.Load_Block_Timestamp(bl.Tips[i]) >= bl.Timestamp {', None),
    'past_limit': ('blockchain/blockchain.go', 'if bl.Height < uint64(chain.Get_Height()-config.STABLE_LIMIT) {', None),
    'fork_version': ('blockchain/blockchain.go', 'if !chain.Check_Block_Version(bl) {', None),
    'mbl_count': ('blockchain/miniblocks_consensus.go', 'if uint64(len(bl.MiniBlocks)) != (config.BLOCK_TIME - config.MINIBLOCK_HIGHDIFF + 1) {', None),
    'mbl_final': ('blockchain/miniblocks_consensus.go', 'err = fmt.Errorf("No final miniblock")', None),
    'template_ts': ('blockchain/miner_block.go', 'bl.Timestamp = uint64(globals.Time().UTC().UnixMilli())', None),
    'header_integrator': ('cmd/derod/rpc/blockheader.go', 'miners[9] = integrator', None),   # r25: header_miners (CO24-C7)
    'finality': ('cmd/derod/rpc/reorg_events.go', 'reorg_violations_total = dmetrics.Set.GetOrCreateCounter("rpc_reorg_final_violations_total")', None),
    'v2_filter': ('p2p/common.go', 'if common.Height >= globals.Config.MAJOR_HF3_HEIGHT+config.STABLE_LIMIT && common.Top_Version < 3 {', None),
    'hf3': ('globals/globals.go', None, None),     # resolved below by find_hf3()
    # r24 (verifier): the fork-block fingerprint is read from the tree line that declares it, not typed from memory
    'hf3_v3_hash': ('cmd/derod/rpc/rpc_dero_explorer.go', 'const HF3_V3_HASH = "e454090e983a3437e9b8ad4f1a45e4dbf46849832cccb3cc2b7841b94fb464d5"', r'"([0-9a-f]{64})"'),
    'hf3_v2_prefix': ('cmd/derod/rpc/rpc_dero_explorer.go', 'const HF3_V2_PREFIX = "54219c50"', r'"([0-9a-f]{8})"'),
    'penalty_series': ('p2p/penalty.go', 'metrics.Set.GetOrCreateCounter(fmt.Sprintf(`p2p_penalty_events_total{reason="%s"}`, reason)).Inc()', None),
    # r25 (consensus): the node-side counters the r25 derod adds (p2p/consensus_obs_r25.go); D02/D11/D20 cite them
    'block_rejected_series': ('p2p/consensus_obs_r25.go', 'var block_rejected = new_reason_counter("blockchain_block_rejected_total")', None),
    'miniblock_refused_series': ('p2p/consensus_obs_r25.go', 'var miniblock_refused = new_reason_counter("p2p_miniblock_refused_total")', None),
    'alt_settle': ('p2p/consensus_obs_r25.go', 'if !e.settled && tip_height-e.height > config.STABLE_LIMIT {', None),  # r25 verify: settle reads outside the lock
}
# r25 (B72): rejection reasons that are a consensus VALIDITY rule refusing an object (D11 OBSERVED); the others
# (past_missing, advance/previous block, panic, stale or final miniblocks) are relay or ordering refusals, reported only
VALIDITY_REJECTS = ('future_timestamp', 'timestamp_not_after_parent', 'invalid_pow', 'invalid_size', 'tx_double_spend', 'invalid_tx', 'invalid_block')
VALIDITY_MBL_REFUSALS = ('invalid_pow', 'unregistered_miner')
# the HF3 fork fingerprint: RULES['hf3_v3_hash'] / RULES['hf3_v2_prefix'] (cmd/derod/rpc/rpc_dero_explorer.go), r24 verifier

# derod log kinds: (kind, how a line is recognised, the Go literal that prints it). The literal is found in the
# tree at run time (first non-test .go file holding it) so the census cites the line that printed each kind.
LOG_KINDS = [
    ('block_added', 'M', 'Chain extended', 'block_logger.Info("Chain extended", "new height", height)'),
    ('side_block', 'M', 'Chain extended but height is same', 'block_logger.Info("Chain extended but height is same", "new height", height)'),
    ('own_block', 'M', 'Block successfully accepted, Notifying Network', '"Block successfully accepted, Notifying Network"'),
    ('resync', 'M', 'We need to resync with the peer', '"We need to resync with the peer"'),
    ('rewind', 'M', 'rewinded blocks', 'connection.logger.V(1).Info("rewinded blocks", "pop_count", pop_count)'),
    ('v2_drop', 'M', 'dropping peer on pre-HF3 (v2) chain', 'Info("dropping peer on pre-HF3 (v2) chain"'),
    ('stuck_evict', 'M', 'evicting stuck peer', '"evicting stuck peer"'),
    ('chunk_unknown_tip', 'M', 'chunk dropped: block builds on a tip we do not have', '"chunk dropped: block builds on a tip we do not have"'),
    ('own_miniblock', 'M', 'Own miniblock delivered', '"Own miniblock delivered"'),
    ('tx_refused_window', 'M', 'Incoming TX refused by the admission window', '"Incoming TX refused by the admission window"'),
    ('finality_violation', 'S', 'FINALITY VIOLATION', '"FINALITY VIOLATION: a block at or below the announced final height was replaced"'),
    ('startup', 'S', 'DERO HE daemon :', 'DERO HE daemon :  It is an alpha version'),
    # r25 (consensus): the r25 derod's attributed lines (p2p/consensus_obs_r25.go, cmd/derod/rpc/reorg_events.go)
    ('block_rejected_r25', 'M', 'Block rejected', 'Info("Block rejected", "blid"'),
    ('miniblock_refused_r25', 'M', 'Miniblock refused', 'Info("Miniblock refused", "reason"'),
    ('reorganisation', 'M', 'Reorganisation', 'logger.Info("Reorganisation", "seq"'),
]
REJECT_RX = re.compile(r'block_logger(?:\.V\(\d\))?\.Error\(fmt\.Errorf\("([^"%]{8,})"')
REJECT_FILE = 'blockchain/blockchain.go'


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


# ─────────────────────────── tree anchors ───────────────────────────
_LC = {}


def tree_lines(root, rel):
    p = Path(root) / rel
    if p not in _LC:
        try:
            _LC[p] = p.read_text(errors='replace').splitlines()
        except OSError:
            _LC[p] = None
    return _LC[p]


def norm(s):
    return re.sub(r'\s+', ' ', str(s or '')).strip()


def find_line(root, rel, quote):
    ls = tree_lines(root, rel)
    if ls is None or not quote:
        return None
    q = norm(quote)
    for i, l in enumerate(ls):
        if q in norm(l):
            return i + 1
    return None


def find_hf3(root):
    """The HF3 activation height of mainnet, from the line that assigns it (globals)."""
    for rel in ('globals/globals.go', 'config/config.go', 'blockchain/hardfork_core.go'):
        ls = tree_lines(root, rel) or []
        for i, l in enumerate(ls):
            m = re.search(r'MAJOR_HF3_HEIGHT\s*[:=]+\s*(\d{6,})', l)
            if m:
                return {'file': rel, 'quote': l.strip(), 'line': i + 1, 'value': int(m.group(1))}
    return None


def load_rules(root):
    """{name: {file, quote, line, value?}} or raises with the names that do not resolve."""
    out, missing = {}, []
    for name, (rel, quote, rx) in RULES.items():
        if name == 'hf3':
            h = find_hf3(root)
            if h:
                out[name] = h
            else:
                missing.append(name)
            continue
        ln = find_line(root, rel, quote)
        if not ln:
            missing.append(name)
            continue
        e = {'file': rel, 'quote': quote, 'line': ln}
        if rx:
            m = re.search(rx, quote)
            if not m:
                missing.append(name)
                continue
            g1 = m.group(1)
            e['value'] = g1 if re.fullmatch(r'[0-9a-f]{8,64}', g1) and not g1.isdigit() else (float(g1) if '.' in g1 else int(g1))   # r24: hex strings stay strings
        out[name] = e
    return out, missing


def literal_anchor(root, literal):
    """The first non-test, non-vendor .go line holding `literal` (the line that prints a log kind)."""
    q = norm(literal)
    for top in ('blockchain', 'p2p', 'cmd/derod', 'rpc', 'mempool'):
        base = Path(root) / top
        if not base.exists():
            continue
        for p in sorted(base.rglob('*.go')):
            if p.name.endswith('_test.go') or 'vendor' in p.parts:
                continue
            rel = p.relative_to(root).as_posix()
            ls = tree_lines(root, rel) or []
            for i, l in enumerate(ls):
                if q in norm(l):
                    return {'file': rel, 'quote': l.strip()[:200], 'line': i + 1}
    return None


def reject_literals(root):
    """[(message, anchor)] for every block rejection error literal of blockchain/blockchain.go (block_logger.Error)."""
    out, seen = [], set()
    for i, l in enumerate(tree_lines(root, REJECT_FILE) or []):
        m = REJECT_RX.search(l)
        if m and not l.lstrip().startswith('//') and m.group(1) not in seen:    # a commented-out rule prints nothing
            seen.add(m.group(1))
            out.append((m.group(1), {'file': REJECT_FILE, 'quote': l.strip()[:200], 'line': i + 1}))
    return out


# ─────────────────────────── privacy ───────────────────────────
def load_salt(create=True):
    f = Path(os.environ.get('DERO_CONSENSUS_SALT_FILE') or (PRIVATE / 'salt'))
    try:
        s = f.read_text().strip()
        if len(s) >= 32:
            return s
    except OSError:
        pass
    if not create:
        return None
    f.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(f.parent, 0o700)
    s = secrets.token_hex(32)
    fd = os.open(str(f), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as fh:
        fh.write(s + '\n')
    return s


def pseudonym(salt, addr, prefix='m-'):
    return prefix + hashlib.blake2b((salt + '|' + str(addr)).encode(), digest_size=16).hexdigest()[:8]


ADDR_RX = re.compile(r'\b(?:dero|deto)1[0-9a-z]{20,}\b')
IP_RX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b')


def leaks(text):
    """Addresses or IPv4 literals in an output (the KAT and the writer both refuse them)."""
    return ADDR_RX.findall(text) + [ip for ip in IP_RX.findall(text) if not ip.startswith(('0.', '127.0.0.1'))]


# ─────────────────────────── live reads ───────────────────────────
def rpc(method, params=None, url=RPC_URL, timeout=60):
    body = {'jsonrpc': '2.0', 'id': 1, 'method': method}
    if params is not None:
        body['params'] = params
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.loads(r.read())
    if d.get('error'):
        raise RuntimeError(f"{method}: {d['error'].get('message')}")
    return d['result']


METRIC_NAMES = ('rpc_reorgs_observed_total', 'rpc_reorg_replaced_topoheights_total', 'rpc_reorg_final_violations_total',
                'rpc_reorg_local_rewinds_total', 'block_propagation_duration_histogram_seconds_sum',
                'block_propagation_duration_histogram_seconds_count', 'miniblock_propagation_duration_histogram_seconds_sum',
                'miniblock_propagation_duration_histogram_seconds_count', 'p2p_miniblock_deliveries_total', 'p2p_penalty_events_total',
                'p2p_penalty_bans_total', 'p2p_bans_total', 'p2p_hf3_table_blocks_total', 'p2p_compact_block_rejects_total',
                'blockchain_sync_total', 'mempool_count', 'tx_policy_known_invalid_total', 'tx_precheck_refused_total',
                'tx_policy_pool_full_refused_total', 'dero_emission_audit_blocks_total',
                'blockchain_block_rejected_total', 'p2p_miniblock_refused_total', 'p2p_block_offer_duplicate_total')   # r25


def read_metrics(url=METRICS_URL):
    with urllib.request.urlopen(url, timeout=20) as r:
        txt = r.read().decode(errors='replace')
    out = {}
    for l in txt.splitlines():
        if l.startswith('#') or not l.strip():
            continue
        name = l.split('{', 1)[0].split(' ', 1)[0]
        if name in METRIC_NAMES:
            k, _, v = l.rpartition(' ')
            try:
                out[k] = float(v)
            except ValueError:
                pass
    return out


def own_integrator_from_logs(paths):
    """The integrator address of this node's newest run ("will use" line, blockchain/blockchain.go). Kept in memory."""
    addr = None
    for p in paths:
        try:
            with open(p, errors='replace') as fh:
                for l in fh:
                    if '"will use"' in l and 'integrator_address' in l:
                        try:
                            addr = json.loads(l).get('integrator_address') or addr
                        except ValueError:
                            pass
        except OSError:
            continue
    return addr


def capture_live(window, salt, own_addr, log_paths, url=RPC_URL, murl=METRICS_URL, sleep_s=SLEEP_S):
    """A pseudonymised raw capture. Every miner address is replaced as soon as it is read."""
    pmap = {}

    def P(a):
        if not a or a == 'unknown':
            return 'unknown'
        if own_addr and a == own_addr:
            return 'this-node'
        if a not in pmap:
            pmap[a] = pseudonym(salt, a)
        return pmap[a]

    t0 = time.time()
    gi = rpc('DERO.GetInfo', url=url)
    si = rpc('DERO.GetSyncInfo', url=url)
    top = int(gi['topoheight'])
    start = max(0, top - window + 1)
    heads = []
    for s in range(start, top + 1, CHUNK):
        e = min(top, s + CHUNK - 1)
        r = rpc('DERO.GetBlockHeadersRange', {'start_topoheight': s, 'end_topoheight': e}, url=url)
        for h in r.get('headers') or []:
            heads.append({'topo': h['topoheight'], 'height': h['height'], 'hash': h['hash'], 'ts': h['timestamp'],
                          'diff': int(h['difficulty']), 'tx': h['txcount'], 'major': h['major_version'],
                          'minor': h['minor_version'], 'side': h['sideblock'], 'orphan': h['orphan_status'],
                          'tips': [t[:16] for t in h.get('tips') or []], 'miners': [P(m) for m in h.get('miners') or []],
                          **({'fees': h['fees']} if 'fees' in h else {}),                          # r25 (CO24-C2)
                          **({'fs': h['first_seen_ms']} if 'first_seen_ms' in h else {})})        # r25 (CO24-C5)
        time.sleep(sleep_s)
    mbls = []
    for t in range(max(start, top - MBL_SAMPLE + 1), top + 1):
        try:
            r = rpc('DERO.GetMiniBlocks', {'topoheight': t}, url=url)
        except Exception as e:                                       # noqa: BLE001 — a missing sample is reported, not fatal
            mbls.append({'topo': t, 'error': str(e)[:120]})
            continue
        ms = r.get('miniblocks') or []
        mbls.append({'topo': t, 'n': len(ms), 'finals': sum(1 for m in ms if m.get('final')),
                     'final_index': next((m['index'] for m in ms if m.get('final')), None),
                     'final_highdiff': [m.get('highdiff') for m in ms if m.get('final')],
                     'regular_highdiff': sum(1 for m in ms if not m.get('final') and m.get('highdiff')),
                     'before_ms': [m.get('ms_before_block') for m in ms],
                     'unknown_miners': sum(1 for m in ms if not m.get('final') and m.get('miner') == 'unknown')})
        time.sleep(0.25)
    fork = None
    hf3 = find_hf3(ROOT)
    if hf3:
        try:
            r = rpc('DERO.GetBlockHeaderByTopoHeight', {'topoheight': hf3['value']}, url=url)
            b = r.get('block_header') or {}
            fork = {'height_asked': hf3['value'], 'topo': b.get('topoheight'), 'height': b.get('height'), 'hash': b.get('hash'),
                    'major': b.get('major_version')}
        except Exception as e:                                       # noqa: BLE001
            fork = {'height_asked': hf3['value'], 'error': str(e)[:160]}
    try:
        mi = rpc('DERO.GetMonetaryIntegrity', url=url)
        fin = mi.get('finality') or {}
        lt = fin.get('lifetime')                                    # r25 (CO24-C6): persisted across restarts
        fin = {k: fin.get(k) for k in ('observed', 'reorgs', 'replaced_total', 'deepest', 'deepest_heights', 'final_violations',
                                        'local_rewinds', 'window')} | {'last_fork_topoheight': (fin.get('last') or {}).get('fork_topoheight'),
                                                                        'last_replaced': (fin.get('last') or {}).get('replaced')}
        if isinstance(lt, dict):
            fin['lifetime'] = {k: lt.get(k) for k in ('since', 'starts', 'observed', 'reorgs', 'replaced_total', 'deepest',
                                                      'deepest_heights', 'final_violations', 'local_rewinds')}
    except Exception as e:                                           # noqa: BLE001
        fin = {'error': str(e)[:160]}
    try:
        pi = rpc('DERO.GetPeerInfo', url=url)
        peers = pi.get('peers') or []
        pinfo = {'peers': len(peers), 'top_versions': dict(collections.Counter(str(p.get('top_version')) for p in peers)),
                 'peers_below_v3': sum(1 for p in peers if (p.get('top_version') or 0) < 3),
                 'height_lag': dict(collections.Counter(str(max(-3, min(3, int(gi['height']) - int(p.get('height') or 0)))) for p in peers)),
                 'v2_chain_peers_seen_7d': pi.get('v2_chain_peers_seen_7d')}
    except Exception as e:                                           # noqa: BLE001
        pinfo = {'error': str(e)[:160]}
    try:
        met = read_metrics(murl)
    except Exception as e:                                           # noqa: BLE001
        met = {'_error': str(e)[:160]}
    # r29 (D20): GetInfo's alt count is read again right before and right after GetConsensusStats. The first GetInfo
    # read above comes before the header walk and the miniblock sample (~40 s), so one alt block settling in between
    # made the counts differ while the settled sets agreed (r28d capture 2026-11-08T02:53:50Z: 7 vs 8).
    alt_pair = [None, None]
    try:
        alt_pair[0] = rpc('DERO.GetInfo', url=url).get('alt_blocks_count')
    except Exception:                                                # noqa: BLE001 — the pair is optional
        pass
    cstats = read_consensus_stats(url)                               # r25: absent on a pre-r25 derod (method not found)
    try:
        alt_pair[1] = rpc('DERO.GetInfo', url=url).get('alt_blocks_count')
    except Exception:                                                # noqa: BLE001
        pass
    # side blocks named in the log inside the window: fetch a few by hash for their integrator
    logs = parse_logs(log_paths, ROOT)
    hmin = heads[0]['height'] if heads else 0
    alts = []
    main_at = {h['height']: h['hash'] for h in heads}
    for ev in [e for e in logs['events'] if e['k'] == 'side' and e['h'] >= hmin][-ALT_FETCH:]:
        if main_at.get(ev['h']) == ev['blid']:
            alts.append({'h': ev['h'], 'blid': ev['blid'][:16], 'won': True})
            continue
        try:
            r = rpc('DERO.GetBlockHeaderByHash', {'hash': ev['blid']}, url=url)
            b = r.get('block_header') or {}
            alts.append({'h': ev['h'], 'blid': ev['blid'][:16], 'won': False, 'ts': b.get('timestamp'),
                         'integrator': P((b.get('miners') or [None] * 10)[-1]), 'topo': b.get('topoheight')})
        except Exception as e:                                       # noqa: BLE001
            alts.append({'h': ev['h'], 'blid': ev['blid'][:16], 'won': False, 'error': str(e)[:80]})
        time.sleep(0.2)
    gi_keep = {'alt_blocks_count_around_stats': alt_pair} | {k: gi.get(k) for k in ('height', 'topoheight', 'stableheight', 'prunedheight', 'top_block_hash', 'difficulty',
                                       'averageblocktime50', 'target', 'alt_blocks_count', 'tx_pool_size', 'version',
                                       'connected_miners', 'miniblocks_in_memory', 'miniblocks_rejected_count', 'status',
                                       'incoming_connections_count', 'outgoing_connections_count', 'target_height')}
    si_keep = {k: si.get(k) for k in ('status', 'reason', 'height', 'topoheight', 'stableheight', 'tip_timestamp_ms', 'tip_age_seconds',
                                       'peer_median_height', 'lag_blocks', 'chain_fingerprint', 'v2_chain_peers_seen_7d', 'version')}
    for k in ('reason',):
        if si_keep.get(k) and leaks(si_keep[k]):
            si_keep[k] = '(redacted)'
    return {'schema': SCHEMA, 'source': 'live', 'captured': now_utc().isoformat(timespec='seconds'),
            'capture_seconds': round(time.time() - t0, 1), 'window_requested': window, 'getinfo': gi_keep, 'syncinfo': si_keep,
            'headers': heads, 'miniblocks': mbls, 'fork': fork, 'finality': fin, 'peerinfo': pinfo, 'metrics': met,
            'alts': alts, 'own_known': bool(own_addr), 'participants_named': len(pmap), 'consensus_stats': cstats,
            'log': {'files': [Path(p).name for p in log_paths], 'census': logs['census'], 'by_day': logs['by_day'],
                    'first_last': logs['first_last'], 'events': logs['events'], 'wevents': logs['wevents'], 'lines': logs['lines'],
                    'startups_ms': logs['startups_ms']}}


def read_consensus_stats(url=RPC_URL):
    """r25: DERO.GetConsensusStats (counters by reason, settled alt blocks, reorg lifetime). None when the node does not
    serve it (a pre-r25 binary), {'error': ...} on any other failure. Block hashes are cut to 16 hex (enough to join with
    the log); no peer id is kept (the RPC carries none)."""
    try:
        r = rpc('DERO.GetConsensusStats', {}, url=url)
    except Exception as e:                                           # noqa: BLE001
        msg = str(e)
        return None if ('not found' in msg.lower() or 'method' in msg.lower() and 'unknown' in msg.lower()) else {'error': msg[:160]}
    alt = r.get('alt_blocks') or {}
    c = r.get('counters') or {}
    return {'version': r.get('version'), 'uptime_seconds': r.get('uptime_seconds'), 'height': r.get('height'),
            'stable_limit': r.get('stable_limit'),
            'miniblock_refused': c.get('miniblock_refused') or {}, 'miniblock_refused_total': c.get('miniblock_refused_total'),
            'block_rejected': c.get('block_rejected') or {}, 'block_rejected_total': c.get('block_rejected_total'),
            'block_offer_duplicates': c.get('block_offer_duplicates'),
            'alt': {k: alt.get(k) for k in ('count', 'unsettled', 'tracked', 'settled', 'tracked_from_height', 'settle_depth')}
                   | {'blocks': [{'hash': (b.get('hash') or '')[:16], 'height': b.get('height')} for b in alt.get('blocks') or []]},
            'blocks_seen_tracked': r.get('blocks_seen_tracked'), 'miniblocks_seen_tracked': r.get('miniblocks_seen_tracked')}


# ─────────────────────────── the log ───────────────────────────
def parse_time_ms(t):
    try:
        return int(datetime.datetime.strptime(t, '%Y-%m-%dT%H:%M:%S.%f%z').timestamp() * 1000)
    except (TypeError, ValueError):
        return None


def parse_logs(paths, root):
    """Census of consensus-relevant lines + per-block events. Peer addresses never leave this function."""
    rejects = reject_literals(root)
    census, by_day, first_last = collections.Counter(), collections.defaultdict(collections.Counter), {}
    events, startups, n = [], [], 0
    wevents = []   # r25 (B72): timed v2-drop and rejection lines, so D02/D13 can read the window (kept apart from block events)
    keys_m = {m: k for k, how, m, _ in LOG_KINDS if how == 'M'}
    keys_s = [(m, k) for k, how, m, _ in LOG_KINDS if how == 'S']
    for p in paths:
        try:
            fh = open(p, errors='replace')
        except OSError:
            continue
        with fh:
            for ln, l in enumerate(fh, 1):
                n += 1
                kind = None
                is_err = re.search(r'"L":\s*"ERROR"', l) is not None
                if not is_err and '"M":' not in l:
                    continue
                d = None
                for lit, k in keys_s:
                    if lit in l:
                        kind = k
                        break
                if kind is None:
                    for msg, _a in rejects:
                        if msg in l:
                            kind = 'block_rejected:' + msg
                            break
                if kind is None:
                    m = re.search(r'"M":\s*"((?:[^"\\]|\\.)*)"', l)
                    if m and m.group(1) in keys_m:
                        kind = keys_m[m.group(1)]
                    elif is_err:
                        kind = 'error_other'
                if kind is None:
                    continue
                try:
                    d = json.loads(l)
                except ValueError:
                    continue
                t = d.get('T')
                tm = parse_time_ms(t)
                census[kind] += 1
                by_day[str(t)[:10]][kind] += 1
                fl = first_last.setdefault(kind, {'first': [Path(p).name, ln, t], 'last': None})
                fl['last'] = [Path(p).name, ln, t]
                if kind in ('block_added', 'side_block'):
                    blid = str(d.get('N', '')).split('blid_', 1)[-1]
                    if re.fullmatch(r'[0-9a-f]{64}', blid):
                        events.append({'k': 'add' if kind == 'block_added' else 'side', 'blid': blid, 'h': d.get('new height'),
                                       't': tm, 'f': Path(p).name, 'l': ln})
                elif kind == 'own_block':
                    events.append({'k': 'own', 'blid': str(d.get('blid')), 'h': d.get('height'), 't': tm, 'f': Path(p).name, 'l': ln})
                elif kind == 'v2_drop':                                   # r25 (B72): D13 counts the window, not the log
                    wevents.append({'k': 'v2', 't': tm, 'f': Path(p).name, 'l': ln})
                elif kind.startswith('block_rejected:'):                  # r25 (B72): D02 counts the window
                    wevents.append({'k': 'reject', 'msg': kind.split(':', 1)[1], 't': tm, 'f': Path(p).name, 'l': ln})
                elif kind == 'block_rejected_r25':
                    wevents.append({'k': 'reject', 'msg': 'r25:' + str(d.get('reason')), 't': tm, 'f': Path(p).name, 'l': ln})
                elif kind == 'startup':
                    startups.append(tm)
    return {'census': dict(census), 'by_day': {k: dict(v) for k, v in sorted(by_day.items())}, 'first_last': first_last,
            'events': events, 'wevents': wevents, 'lines': n, 'startups_ms': [s for s in startups if s]}


# ─────────────────────────── statistics (pure) ───────────────────────────
def quantile(xs, q):
    if not xs:
        return None
    s = sorted(xs)
    k = (len(s) - 1) * q
    lo, hi = math.floor(k), math.ceil(k)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def hhi(counts):
    t = sum(counts)
    return sum((c / t) ** 2 for c in counts) if t else None


def nakamoto(counts):
    """Smallest number of participants whose combined share exceeds 1/2."""
    t, acc = sum(counts), 0
    for i, c in enumerate(sorted(counts, reverse=True), 1):
        acc += c
        if acc * 2 > t:
            return i
    return None


def log_binom_pmf(k, n, p):
    if p <= 0:
        return 0.0 if k == 0 else -math.inf
    if p >= 1:
        return 0.0 if k == n else -math.inf
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1) + k * math.log(p) + (n - k) * math.log1p(-p)


def binom_upper(k, n, p):
    """P(X >= k), X ~ Binomial(n, p)."""
    if k <= 0:
        return 1.0
    return min(1.0, sum(math.exp(log_binom_pmf(i, n, p)) for i in range(k, n + 1)))


def binom_lower(k, n, p):
    """P(X <= k)."""
    return min(1.0, sum(math.exp(log_binom_pmf(i, n, p)) for i in range(0, k + 1)))


def binom_two_sided(k, n, p):
    return min(1.0, 2 * min(binom_upper(k, n, p), binom_lower(k, n, p)))


def wilson(k, n, z=1.959964):
    if not n:
        return (None, None)
    ph = k / n
    d = 1 + z * z / n
    c = ph + z * z / (2 * n)
    r = z * math.sqrt(ph * (1 - ph) / n + z * z / (4 * n * n))
    return ((c - r) / d, (c + r) / d)


def longest_run(seq, who):
    best = cur = 0
    at = None
    for i, s in enumerate(seq):
        cur = cur + 1 if s == who else 0
        if cur > best:
            best, at = cur, i
    return best, at


def run_pvalue(L, n, p):
    """P(longest run of successes >= L in n Bernoulli(p) trials), the standard Poisson approximation of the number of
    runs >= L (each run starts after a failure): 1 - exp(-(n - L + 1)(1 - p) p^L)."""
    if L <= 0 or p <= 0:
        return 1.0
    if p >= 1:
        return 1.0
    lam = max(0, n - L + 1) * (1 - p) * p ** L
    return 1 - math.exp(-lam)


def pearson(xs, ys):
    if len(xs) < 3:
        return None
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    sx = math.sqrt(sum((x - mx) ** 2 for x in xs))
    sy = math.sqrt(sum((y - my) ** 2 for y in ys))
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / (sx * sy) if sx and sy else None


def expected_difficulty(prev_diff, solve_ms, R):
    """blockchain/difficulty.go Get_Difficulty_At_Tips: the next block's difficulty from its tip's difficulty and the
    tip's own solve time (tip ts - its parent's ts), clamped at clamp*block_time, floored at the minimum."""
    bt = int(R['block_time']['value']) * 1000
    st = min(int(solve_ms), bt * int(R['diff_clamp']['value']))
    if st <= 0:
        return None                                     # DiffBig panics on solvetime <= 0; never reached by valid chains
    easy = int(math.pow(float(R['diff_e']['value']), ((1 - float(st) / float(bt)) / float(R['diff_m']['value']))) * 10000)
    d = prev_diff * easy // 10000
    return max(d, int(R['min_difficulty']['value']))


# ─────────────────────────── analysis ───────────────────────────
def det(id_, title, grade, value, rule, test, evidence, note=''):
    assert grade in GRADES
    return {'id': id_, 'title': title, 'grade': grade, 'value': value, 'rule': rule, 'test': test, 'evidence': evidence, 'note': note}


def analyze(cap, R, root=ROOT):
    """The whole computation over one capture (live or synthetic). Pure apart from reading tree lines for anchors."""
    H = sorted(cap.get('headers') or [], key=lambda h: h['topo'])
    n = len(H)
    bt_ms = int(R['block_time']['value']) * 1000
    regular = int(R['block_time']['value']) - int(R['mbl_highdiff']['value'])       # 9 regular miniblocks
    per_block = regular + 1                                                            # + the final (miniblocks_consensus.go)
    out = {'schema': SCHEMA, 'source': cap.get('source'), 'captured': cap.get('captured'), 'analysed': now_utc().isoformat(timespec='seconds')}
    gi, si = cap.get('getinfo') or {}, cap.get('syncinfo') or {}
    ver = gi.get('version') or si.get('version') or ''
    m = re.search(r'\+\d{8}\.(r\d+[a-z]?)', ver)
    out['version'] = ver
    out['binary_round'] = m.group(1) if m else 'pending'
    if not n:
        out['error'] = 'no headers in the capture'
        return out
    topos = [h['topo'] for h in H]
    heights = [h['height'] for h in H]
    ts = [int(h['ts']) for h in H]
    diffs = [int(h['diff']) for h in H]
    k = {}
    k['window_blocks'] = n
    k['window_topo_first'] = topos[0]
    k['window_topo_last'] = topos[-1]
    k['window_height_first'] = heights[0]
    k['window_height_last'] = heights[-1]
    k['window_hours'] = round((ts[-1] - ts[0]) / 3_600_000, 2)
    k['tip_topoheight'] = gi.get('topoheight')
    k['stable_height'] = gi.get('stableheight')
    k['tip_age_s'] = si.get('tip_age_seconds')
    k['sync_status'] = si.get('status')
    k['lag_blocks'] = si.get('lag_blocks')
    k['topo_gaps'] = sum(1 for a, b in zip(topos, topos[1:]) if b != a + 1)
    k['topo_same_height'] = sum(1 for a, b in zip(heights, heights[1:]) if b == a)      # side blocks with a topo slot
    # block time
    dts = [b - a for a, b, ha, hb in zip(ts, ts[1:], heights, heights[1:]) if hb == ha + 1]
    k['block_time_mean_s'] = round(statistics.fmean(dts) / 1000, 3) if dts else 'pending'
    k['block_time_median_s'] = round(statistics.median(dts) / 1000, 3) if dts else 'pending'
    k['block_time_p95_s'] = round(quantile(dts, 0.95) / 1000, 3) if dts else 'pending'
    k['block_time_p99_s'] = round(quantile(dts, 0.99) / 1000, 3) if dts else 'pending'
    k['block_time_min_ms'] = min(dts) if dts else 'pending'
    k['block_time_max_s'] = round(max(dts) / 1000, 3) if dts else 'pending'
    k['block_time_target_s'] = int(R['block_time']['value'])
    k['averageblocktime50_s'] = gi.get('averageblocktime50')
    k['blocks_over_10x_target'] = sum(1 for d in dts if d > 10 * bt_ms)
    # difficulty
    k['difficulty_first'] = diffs[0]
    k['difficulty_last'] = diffs[-1]
    k['difficulty_mean'] = round(statistics.fmean(diffs))
    k['difficulty_min'] = min(diffs)
    k['difficulty_max'] = max(diffs)
    steps = [b / a for a, b in zip(diffs, diffs[1:]) if a]
    k['difficulty_step_min'] = round(min(steps), 5) if steps else 'pending'
    k['difficulty_step_max'] = round(max(steps), 5) if steps else 'pending'
    mism, checked, xs, ys, clamped, mism_ev = 0, 0, [], [], 0, []
    for i in range(2, n):
        if not (heights[i] == heights[i - 1] + 1 == heights[i - 2] + 2):
            continue
        st = ts[i - 1] - ts[i - 2]
        exp = expected_difficulty(diffs[i - 1], st, R)
        if exp is None:
            continue
        checked += 1
        if exp != diffs[i]:
            mism += 1
            if len(mism_ev) < 5:
                mism_ev.append({'height': heights[i], 'hash': H[i]['hash'][:16], 'difficulty': diffs[i], 'expected': exp})
        stc = min(st, bt_ms * int(R['diff_clamp']['value']))
        clamped += st > bt_ms * int(R['diff_clamp']['value'])
        xs.append((1 - stc / bt_ms) / float(R['diff_m']['value']))
        ys.append(math.log(diffs[i] / diffs[i - 1]))
    k['difficulty_rule_checked'] = checked
    k['difficulty_rule_mismatches'] = mism
    k['difficulty_response_corr'] = round(pearson(xs, ys), 6) if pearson(xs, ys) is not None else 'pending'
    k['difficulty_clamped_steps'] = clamped
    # miniblocks / tx
    k['blocks_with_10_miniblocks'] = sum(1 for h in H if len(h.get('miners') or []) == per_block)
    k['empty_blocks'] = sum(1 for h in H if not h.get('tx'))
    k['empty_block_ratio'] = round(k['empty_blocks'] / n, 4)
    k['tx_total'] = sum(int(h.get('tx') or 0) for h in H)
    k['tx_per_block_mean'] = round(k['tx_total'] / n, 4)
    k['tx_per_block_max'] = max(int(h.get('tx') or 0) for h in H)
    # r25 (CO24-C2): an r25 derod serves the fee sum per header (GetBlockHeadersRange 'fees', null = a tx unreadable);
    # a pre-r25 one serves none and the KPI stays pending
    if H and all('fees' in h for h in H):
        k['fees_total'] = sum(int(h['fees']) for h in H if h['fees'] is not None)
        k['fees_unknown_blocks'] = sum(1 for h in H if h['fees'] is None)
        k['fee_blocks'] = sum(1 for h in H if h['fees'])
    else:
        k['fees_total'] = 'pending'      # no fee field in this binary's headers: proposal CO24-C2
    k['major_versions'] = dict(collections.Counter(str(h.get('major')) for h in H))
    # participants
    minis = collections.Counter()
    finals = collections.Counter()
    seq_final = []
    for h in H:
        ms = h.get('miners') or []
        for x in ms[:regular]:
            minis[x] += 1
        f = ms[per_block - 1] if len(ms) >= per_block else 'unknown'
        finals[f] += 1
        seq_final.append(f)
    tm, tf = sum(minis.values()), sum(finals.values())
    named = [p for p in set(minis) | set(finals) if p != 'unknown']
    k['participants'] = len(named)
    k['participants_regular'] = sum(1 for p in minis if p != 'unknown')
    k['participants_final'] = sum(1 for p in finals if p != 'unknown')
    # r24 (verifier): header miners[] cannot show an unresolved regular miniblock: cmd/derod/rpc/blockheader.go skips the key
    # (`continue`), pads "unknown" at the END and then overwrites slot 9 with the integrator, so minis['unknown'] is 0 by
    # construction. The count is taken from the GetMiniBlocks sample instead (it resolves per miniblock) and says so.
    _ms = [x for x in cap.get('miniblocks') or [] if 'n' in x]
    k['unresolved_miniblocks'] = (f"{sum(int(x.get('unknown_miners') or 0) for x in _ms)} in {len(_ms)} sampled blocks" if _ms else 'pending')
    if H and all('fees' in h for h in H):    # r25 header (CO24-C7): an unresolved key keeps its own slot
        k['unresolved_miniblocks_header'] = sum(1 for h in H for x in (h.get('miners') or [])[:regular] if x == 'unknown')
    else:
        k['unresolved_miniblocks_header'] = 'blind (blockheader.go pads and overwrites; see CO24-C7)'
    mc = [c for p, c in minis.items() if p != 'unknown']
    fc = [c for p, c in finals.items() if p != 'unknown']
    k['top1_regular_share'] = round(max(mc) / tm, 4) if mc else 'pending'
    k['top3_regular_share'] = round(sum(sorted(mc, reverse=True)[:3]) / tm, 4) if mc else 'pending'
    k['top1_final_share'] = round(max(fc) / tf, 4) if fc else 'pending'
    k['top3_final_share'] = round(sum(sorted(fc, reverse=True)[:3]) / tf, 4) if fc else 'pending'
    k['hhi_regular'] = round(hhi(mc), 5) if mc else 'pending'
    k['hhi_final'] = round(hhi(fc), 5) if fc else 'pending'
    k['nakamoto_regular'] = nakamoto(mc) if mc else 'pending'
    k['nakamoto_final'] = nakamoto(fc) if fc else 'pending'
    k['this_node_regular'] = minis.get('this-node', 0)
    k['this_node_final'] = finals.get('this-node', 0)
    k['this_node_known'] = bool(cap.get('own_known'))
    parts = []
    tested = [p for p in named if finals.get(p, 0) + minis.get(p, 0) // regular >= MIN_N]
    alpha_p = ALPHA / max(1, len(tested))
    for p in sorted(named, key=lambda p: (-(minis.get(p, 0) + finals.get(p, 0) * regular), p)):
        mi_, fi_ = minis.get(p, 0), finals.get(p, 0)
        L, at = longest_run(seq_final, p)
        q_f = fi_ / tf if tf else 0
        q_m = mi_ / tm if tm else 0
        parts.append({'id': p, 'regular': mi_, 'regular_share': round(q_m, 5), 'final': fi_, 'final_share': round(q_f, 5),
                      'final_ci95': [round(x, 4) for x in wilson(fi_, tf)] if tf else None,
                      'longest_final_run': L, 'run_end_height': heights[at] if at is not None else None,
                      'run_p': round(run_pvalue(L, tf, q_f), 8) if fi_ else None,
                      'final_vs_regular_p': round(binom_two_sided(fi_, tf, q_m), 10) if (tf and p in tested) else None,
                      'tested': p in tested})
    for p in parts:
        p['role'] = role(p)
    k['integrator_only_participants'] = sum(1 for p in parts if p['role'] == 'integrator-only')
    k['integrator_only_final_share'] = round(sum(p['final'] for p in parts if p['role'] == 'integrator-only') / tf, 4) if tf else 'pending'
    k['miner_only_participants'] = sum(1 for p in parts if p['role'] == 'miner-only')
    k['miner_only_regular_share'] = round(sum(p['regular'] for p in parts if p['role'] == 'miner-only') / tm, 4) if tm else 'pending'
    out['participants'] = parts
    # log join: arrival lag per block (first "Chain extended" line of that blid), late releases, side blocks
    lg = cap.get('log') or {}
    evs = lg.get('events') or []
    first_seen = {}
    for e in evs:
        if e['k'] in ('add', 'side') and e['blid'] not in first_seen and e.get('t'):
            first_seen[e['blid']] = e
    idx = {h['hash']: i for i, h in enumerate(H)}
    lags = {}
    rpc_fs = any(h.get('fs') for h in H)            # r25 (CO24-C5): the node's own first-seen time, not a log line
    for hsh, i in idx.items():
        if rpc_fs:
            t_seen = H[i].get('fs') or None
        else:
            e = first_seen.get(hsh)
            t_seen = e['t'] if e else None
        if t_seen:
            lag = t_seen - ts[i]
            if lag <= LIVE_LAG_MAX_MS:
                lags[i] = lag
    k['arrival_source'] = 'rpc first_seen_ms' if rpc_fs else ('derod log "Chain extended"' if lags else 'pending')
    k['blocks_seen_live'] = len(lags)
    lv = list(lags.values())
    k['arrival_lag_median_ms'] = round(statistics.median(lv)) if lv else 'pending'
    k['arrival_lag_p95_ms'] = round(quantile(lv, 0.95)) if lv else 'pending'
    k['arrival_lag_min_ms'] = min(lv) if lv else 'pending'
    fut = int(R['ts_future']['value'])
    k['arrival_before_timestamp'] = sum(1 for x in lv if x < 0)
    k['arrival_beyond_future_limit'] = sum(1 for x in lv if x < -fut)
    side_win = [e for e in evs if e['k'] == 'side' and isinstance(e.get('h'), int) and heights[0] <= e['h'] <= heights[-1]]
    k['side_block_lines_window'] = len(side_win)
    main_at = {h['height']: h['hash'] for h in H}
    k['side_block_won'] = sum(1 for e in side_win if main_at.get(e['h']) == e['blid'])
    k['side_block_lost'] = k['side_block_lines_window'] - k['side_block_won']
    fin = cap.get('finality') or {}
    for f_ in ('reorgs', 'replaced_total', 'deepest', 'deepest_heights', 'final_violations', 'local_rewinds', 'observed'):
        k[f'finality_{f_}'] = fin.get(f_, 'pending') if fin.get(f_) is not None else 'pending'
    met = cap.get('metrics') or {}
    k['metric_reorgs_observed'] = met.get('rpc_reorgs_observed_total', 'pending')
    k['metric_penalty_events'] = sum(v for kk, v in met.items() if kk.startswith('p2p_penalty_events_total')) if met else 'pending'
    k['alt_blocks_count_getinfo'] = gi.get('alt_blocks_count')
    lt = fin.get('lifetime') if isinstance(fin.get('lifetime'), dict) else None       # r25 (CO24-C6)
    for f_ in ('reorgs', 'replaced_total', 'deepest_heights', 'final_violations', 'starts'):
        k[f'finality_lifetime_{f_}'] = lt.get(f_) if lt and lt.get(f_) is not None else 'pending'
    cs = cap.get('consensus_stats') if isinstance(cap.get('consensus_stats'), dict) and 'error' not in cap.get('consensus_stats') else None
    k['consensus_stats'] = 'served' if cs else 'pending'                                   # r25: DERO.GetConsensusStats
    k['miniblock_refused_total'] = cs.get('miniblock_refused_total') if cs else 'pending'  # r25 (CO24-C1)
    k['block_rejected_total'] = cs.get('block_rejected_total') if cs else 'pending'        # r25 (CO24-C3)
    k['alt_blocks_rpc'] = (cs.get('alt') or {}).get('count') if cs else 'pending'          # r25 (CO24-C4)
    pi_ = cap.get('peerinfo') or {}                                                         # r25 (CO24-C8): peer census in the series
    k['peers_connected'] = pi_.get('peers', 'pending') if 'error' not in pi_ else 'pending'
    k['peers_below_v3'] = pi_.get('peers_below_v3', 'pending') if 'error' not in pi_ else 'pending'
    k['peer_versions'] = pi_.get('top_versions', 'pending') if 'error' not in pi_ else 'pending'
    out['kpis'] = k
    # series for the page: per-100-block bins
    bins = []
    for b0 in range(0, n, 100):
        seg = H[b0:b0 + 100]
        sdt = [y['ts'] - x['ts'] for x, y in zip(seg, seg[1:]) if y['height'] == x['height'] + 1]
        bins.append([seg[0]['height'], round(statistics.fmean(sdt) / 1000, 2) if sdt else None, round(statistics.fmean([s['diff'] for s in seg]))])
    out['series_bins'] = bins
    out['detectors'] = detectors(cap, R, H, k, parts, seq_final, lags, dts, mism_ev, alpha_p, tested, regular, per_block)
    out['log_census'] = log_census(cap, root)
    out['proposals'] = proposals(cap, R, k, root)
    out['rules'] = {nm: {'file': e['file'], 'line': e['line'], 'quote': e['quote'], **({'value': e['value']} if 'value' in e else {})} for nm, e in R.items()}
    out['summary'] = {g: sum(1 for d in out['detectors'] if d['grade'] == g) for g in GRADES}
    for g in GRADES:                     # r24: the grade counts as KPIs too (area 'consensus' metrics read kpis)
        k['detectors_' + g.lower().replace('-', '_')] = out['summary'][g]
    return out


def A(R, name):
    e = R[name]
    return {'file': e['file'], 'line': e['line'], 'quote': e['quote']}


def detectors(cap, R, H, k, parts, seq_final, lags, dts, mism_ev, alpha_p, tested, regular, per_block):
    D = []
    n = len(H)
    heights = [h['height'] for h in H]
    ts = [h['ts'] for h in H]
    # D01 timestamp monotonicity (consensus rule: a block's timestamp is strictly above its parent's)
    bad = [(heights[i], H[i]['hash'][:16], ts[i] - ts[i - 1]) for i in range(1, n) if heights[i] == heights[i - 1] + 1 and ts[i] <= ts[i - 1]]
    D.append(det('D01-ts-monotonic', 'Block timestamps rise strictly along the chain', 'OBSERVED' if bad else 'NORMAL', len(bad),
                 A(R, 'ts_parent'), 'count of blocks whose timestamp <= its parent\'s (must be 0)',
                 [{'height': b[0], 'hash': b[1], 'delta_ms': b[2]} for b in bad[:5]]))
    # D02 future skew vs this node's clock (consensus rule: ts <= now + future ms at acceptance).
    # r25 (B72): an accepted block more than `fut` ms ahead is impossible by construction (the rule rejects it BEFORE its
    # "Chain extended" line or its first-seen record), so the lag test alone can never fire. The rule FIRING is the
    # rejection: the r25 counter blockchain_block_rejected_total{reason="future_timestamp"} (GetConsensusStats) and the
    # rule's own rejection line inside the window. An accepted block beyond the limit (lag test) would mean this
    # node's clock moved between acceptance and the record: still OBSERVED.
    fut = int(R['ts_future']['value'])
    cs = cap.get('consensus_stats') if isinstance(cap.get('consensus_stats'), dict) and 'error' not in cap.get('consensus_stats') else None
    t_win = ts[0] if ts else 0
    fut_lit = 'Rejecting Block, timestamp is too much into future'
    evs_ = (cap.get('log') or {}).get('wevents') or []   # r25: timed v2-drop / rejection lines
    fut_lines = [e for e in evs_ if e.get('k') == 'reject' and (fut_lit in str(e.get('msg')) or e.get('msg') == 'r25:future_timestamp')
                 and (e.get('t') or 0) >= t_win]
    fut_ctr = int((cs.get('block_rejected') or {}).get('future_timestamp') or 0) if cs else None
    v = [(heights[i], H[i]['hash'][:16], lag) for i, lag in lags.items() if lag < -fut]
    if not lags and cs is None and not fut_lines:
        D.append(det('D02-ts-future', 'No block was refused for a timestamp beyond the future limit', 'NO-DATA', 'pending',
                     A(R, 'ts_future'), f'rejections for a timestamp > now + {fut} ms (counter or rule line in the window) + accepted lags < -{fut} ms (must be 0)', [],
                     'no live block, no r25 counter and no rejection line in the window'))
    else:
        n_rej = max(fut_ctr or 0, len({(e.get('f'), e.get('l')) for e in fut_lines if e.get('msg') != 'r25:future_timestamp'}),
                    len([e for e in fut_lines if e.get('msg') == 'r25:future_timestamp']))
        D.append(det('D02-ts-future', 'No block was refused for a timestamp beyond the future limit', 'OBSERVED' if (v or n_rej) else 'NORMAL',
                     n_rej + len(v), A(R, 'ts_future'),
                     f'rejections for a timestamp > now + {fut} ms (r25 counter: {"served" if cs else "absent"}; rule lines in the window: {len(fut_lines)}) '
                     f'+ accepted blocks first seen < -{fut} ms over {len(lags)} live blocks (must be 0)',
                     [{'rejected_future_counter': fut_ctr, 'rejection_lines_window': len(fut_lines)}] +
                     [{'line': [e.get('f'), e.get('l')], 'msg': str(e.get('msg'))[:60]} for e in fut_lines[:3]] +
                     [{'height': a, 'hash': b, 'lag_ms': c} for a, b, c in sorted(v, key=lambda x: x[2])[:5]],
                     f'{k["arrival_before_timestamp"]} block(s) arrived before their timestamp but inside the +{fut} ms allowance; '
                     'the accepted-lag half alone is a tautology (B72): the rule rejects such a block before it is recorded'))
    # D03 forward stamping per integrator: a forward stamp is the only thing that makes a block reach this node BEFORE its
    # own timestamp (network delay only adds). Per integrator binomial excess of such arrivals over the window rate. The
    # fastest-arrival decile is reported beside it as context: from one vantage point it measures network proximity.
    D.append(early_arrival_test(H, parts, lags, seq_final, alpha_p, A(R, 'template_ts'), fut))
    # D04 backward stamping per integrator: share of its blocks in the lowest solve-time decile
    st = {i: ts[i] - ts[i - 1] for i in range(1, n) if heights[i] == heights[i - 1] + 1}
    D.append(decile_test('D04-ts-backward', 'No integrator stamps its blocks late-low (lowest solve-time decile)', H, parts, st, seq_final,
                         alpha_p, A(R, 'diff_tip'), 'solve time (own timestamp minus parent\'s) in the window\'s lowest decile; a low '
                         'stamp raises the next difficulty (difficulty.go)'))
    # D05 difficulty follows the consensus rule exactly
    g = 'OBSERVED' if k['difficulty_rule_mismatches'] else ('NORMAL' if k['difficulty_rule_checked'] else 'NO-DATA')
    D.append(det('D05-difficulty-rule', 'Every difficulty equals the consensus rule recomputed from its tip', g,
                 f"{k['difficulty_rule_mismatches']}/{k['difficulty_rule_checked']}", A(R, 'diff_step'),
                 'recompute DiffBig(tip solve time clamped, block time, M, tip difficulty), floored at the minimum; count mismatches (must be 0)',
                 mism_ev, f"response correlation {k['difficulty_response_corr']} (step log-ratio vs (1-st/bt)/M), {k['difficulty_clamped_steps']} clamped steps"))
    # D06 difficulty step bounds (follows from the rule: one step multiplies by easypart/10000 with easypart between
    # int(e^((1-clamp)/M)*10000) for a clamped solve time and int(e^((1-1/bt)/M)*10000) for the shortest, 1 ms)
    M_ = float(R['diff_m']['value'])
    clamp = int(R['diff_clamp']['value'])
    E_ = float(R['diff_e']['value'])
    bt_ms = int(R['block_time']['value']) * 1000
    e_lo = int(math.pow(E_, (1 - clamp) / M_) * 10000)
    e_hi = int(math.pow(E_, (1 - 1 / bt_ms) / M_) * 10000)
    floor_d = int(R['min_difficulty']['value'])
    out_b = []
    for i in range(n - 1):
        if heights[i + 1] != heights[i] + 1 or not H[i]['diff']:
            continue
        d0, d1 = H[i]['diff'], H[i + 1]['diff']
        if not (max(d0 * e_lo // 10000, floor_d) <= d1 <= max(d0 * e_hi // 10000, floor_d)):
            out_b.append((heights[i + 1], H[i + 1]['hash'][:16], round(d1 / d0, 5)))
    D.append(det('D06-difficulty-jump', 'No difficulty step outside the bounds the rule allows', 'OBSERVED' if out_b else 'NORMAL', len(out_b),
                 A(R, 'diff_clamp'), f'next difficulty outside [d*{e_lo}//10000, d*{e_hi}//10000] (easypart at a clamped and at a 1 ms solve '
                 f'time, M={M_:g}, clamp {clamp}x block time), floored at the minimum difficulty',
                 [{'height': a, 'hash': b, 'step': c} for a, b, c in out_b[:5]],
                 f"observed steps {k['difficulty_step_min']}..{k['difficulty_step_max']}; {k['difficulty_clamped_steps']} steps at the clamp"))
    # D07 miniblock structure: 9 regular + 1 final per block (headers) and the final last (GetMiniBlocks sample)
    wrong = [(h['height'], h['hash'][:16], len(h.get('miners') or [])) for h in H if len(h.get('miners') or []) != per_block]
    ms = [m for m in cap.get('miniblocks') or [] if 'n' in m]
    bad_m = [m for m in ms if m['n'] != per_block or m['finals'] != 1 or m['final_index'] != per_block - 1]
    D.append(det('D07-miniblock-structure', f'Every block carries {regular} regular miniblocks and 1 final', 'OBSERVED' if (wrong or bad_m) else 'NORMAL',
                 len(wrong) + len(bad_m), A(R, 'mbl_count'),
                 f'headers with != {per_block} miner slots ({n} blocks) + sampled blocks whose GetMiniBlocks list has != {per_block} entries, != 1 final or the final not last ({len(ms)} sampled)',
                 [{'height': a, 'hash': b, 'slots': c} for a, b, c in wrong[:3]] + [{'topo': m['topo'], 'n': m['n'], 'finals': m['finals']} for m in bad_m[:3]]))
    # D08 selfish / withheld mining indicator 1: bursts of consecutive finals by one integrator
    hits = [p for p in parts if p['run_p'] is not None and p['final'] >= 5 and p['run_p'] < alpha_p]
    top = max(parts, key=lambda p: p['longest_final_run'], default=None)
    D.append(det('D08-final-bursts', 'No integrator wins improbably long runs of consecutive blocks', 'ANOMALY' if hits else ('NORMAL' if parts else 'NO-DATA'),
                 len(hits), None, f'longest run L of consecutive finals per integrator; P(run >= L | n, own final share) = '
                 f'1-exp(-(n-L+1)(1-p)p^L) < {alpha_p:.2e} (alpha {ALPHA} / {max(1, len(tested))} tested)',
                 [{'participant': p['id'], 'run': p['longest_final_run'], 'ends_at_height': p['run_end_height'], 'final_share': p['final_share'], 'p': p['run_p']}
                  for p in (hits or ([top] if top else []))[:5]],
                 'an ANOMALY is a statistical signal, not proof of withholding'))
    # D09 selfish indicator 2: late-released blocks in the log (a block and its child first seen < 1 s apart while
    # their timestamps are > half a block time apart), attributed to the integrator of the delayed block
    lr = late_releases(cap, H, lags)
    tf = sum(p['final'] for p in parts) or 1
    flag = []
    for p, c in collections.Counter(x['participant'] for x in lr).items():
        share = next((q['final_share'] for q in parts if q['id'] == p), 0)
        pv = binom_upper(c, len(lr), share) if lr else 1
        if c >= 3 and pv < alpha_p:
            flag.append({'participant': p, 'late_releases': c, 'of': len(lr), 'final_share': share, 'p': round(pv, 10)})
    D.append(det('D09-late-release', 'No integrator is over-represented among late-released blocks', 'ANOMALY' if flag else ('NORMAL' if lags else 'NO-DATA'),
                 len(lr), None, f'a block whose child was first seen < 1,000 ms after it while the child\'s timestamp is > {int(R["block_time"]["value"]) * 500} ms later; '
                 f'per integrator binomial excess vs its final share, p < {alpha_p:.2e}, at least 3 events', flag or lr[:5],
                 'outside 10 min after a derod start-up; synced (not live) blocks are excluded'))
    # D10 reorg depth and finality (consensus refuses blocks below height - STABLE_LIMIT)
    sl = int(R['stable_limit']['value'])
    fv, dh = k.get('finality_final_violations'), k.get('finality_deepest_heights')
    if fv == 'pending':
        g, v = 'NO-DATA', 'pending'
    else:
        g = 'OBSERVED' if (fv or 0) > 0 or (isinstance(dh, int) and dh > sl) else 'NORMAL'
        v = f"{k.get('finality_reorgs')} reorgs, deepest {k.get('finality_deepest')} topo / {dh} heights, {fv} finality violations"
    D.append(det('D10-reorg-depth', f'No reorganisation reaches below the stable limit ({sl})', g, v, A(R, 'past_limit'),
                 f'GetMonetaryIntegrity finality: deepest_heights <= {sl} and final_violations == 0 (reorg_events.go)',
                 [{'finality': {kk: vv for kk, vv in (cap.get('finality') or {}).items()}}],
                 f"side-block log lines in the window {k['side_block_lines_window']} ({k['side_block_won']} won the height, {k['side_block_lost']} lost); "
                 f"GetInfo alt_blocks_count {k['alt_blocks_count_getinfo']} "
                 + ('(r25: settled alt blocks since start, D20)' if k.get('consensus_stats') == 'served' else '(never assigned: CO24-C4)')
                 + (f"; lifetime reorgs {k.get('finality_lifetime_reorgs')} over {k.get('finality_lifetime_starts')} start(s) (CO24-C6)"
                    if k.get('finality_lifetime_reorgs') != 'pending' else '')))
    # D11 invalid blocks / miniblocks rejected (log census + penalty series)
    lc = (cap.get('log') or {}).get('census') or {}
    rej = {kk: v for kk, v in lc.items() if kk.startswith('block_rejected:')}
    pen = {kk: v for kk, v in (cap.get('metrics') or {}).items() if kk.startswith('p2p_penalty_events_total')}
    inval = {kk: v for kk, v in pen.items() if 'invalid_pow' in kk}
    if cs:   # r25 (CO24-C1/C3): read from the node's counters since its start, attributed by reason
        brj, mrf = cs.get('block_rejected') or {}, cs.get('miniblock_refused') or {}
        bad_b = {r_: n_ for r_, n_ in brj.items() if r_ in VALIDITY_REJECTS and n_}
        bad_m = {r_: n_ for r_, n_ in mrf.items() if r_ in VALIDITY_MBL_REFUSALS and n_}
        D.append(det('D11-invalid-objects', 'Blocks or miniblocks rejected by a consensus rule', 'OBSERVED' if (bad_b or bad_m or any(inval.values())) else 'NORMAL',
                     sum(bad_b.values()) + sum(bad_m.values()), A(R, 'block_rejected_series'),
                     'r25 counters (GetConsensusStats): blockchain_block_rejected_total{reason in ' + '|'.join(VALIDITY_REJECTS) + '} + '
                     'p2p_miniblock_refused_total{reason in ' + '|'.join(VALIDITY_MBL_REFUSALS) + '} + p2p_penalty_events_total{reason=~"invalid_pow.*"}',
                     [{'source': 'counter', 'block_rejected': brj, 'miniblock_refused': mrf, 'duplicates': cs.get('block_offer_duplicates')}]
                     + [{'metric': kk, 'value': v} for kk, v in sorted(pen.items())] + [{'kind': kk, 'lines': v, 'source': 'log (whole)'} for kk, v in sorted(rej.items())],
                     'counter-derived (r25): each rejection line names the sender by its peer_id; relay/ordering refusals (stale or final '
                     'miniblocks, past_missing, advance/previous block) are counted but are not a validity rule firing'))
    else:
        D.append(det('D11-invalid-objects', 'Blocks or miniblocks rejected by a consensus rule', 'OBSERVED' if (rej or any(inval.values())) else 'NORMAL',
                     sum(rej.values()) + int(sum(inval.values())), A(R, 'penalty_series'),
                     'derod.log block rejection lines (every block_logger.Error literal of blockchain/blockchain.go) + /metrics p2p_penalty_events_total{reason=~"invalid_pow.*"}',
                     [{'kind': kk, 'lines': v} for kk, v in sorted(rej.items())] + [{'metric': kk, 'value': v} for kk, v in sorted(pen.items())],
                     'a rejection is the rule working; the sender is not named (the log line carries no peer: CO24-C3). Stale/unregistered '
                     'miniblock refusals are not logged or counted at all (CO24-C1)'))
    # D12 fork fingerprint at HF3 (this node on the upgraded chain)
    fk = cap.get('fork') or {}
    if fk.get('hash'):
        on_v3 = fk['hash'] == R['hf3_v3_hash']['value'] and fk.get('major') == 3     # r24: the full fork-block hash of the tree
        g = 'NORMAL' if on_v3 else 'OBSERVED'
        v = f"{fk['hash'][:8]} major {fk.get('major')}"
    else:
        g, v = 'NO-DATA', 'pending'
    D.append(det('D12-fork-fingerprint', 'This node is on the upgraded (v3) chain at the HF3 fork block', g, v, A(R, 'hf3_v3_hash'),
                 f'block at height {(fk or {}).get("height_asked")} ({R["hf3"]["file"]}:{R["hf3"]["line"]}): hash == HF3_V3_HASH {R["hf3_v3_hash"]["value"][:8]}.. and major_version 3 (v2 remnant: {R["hf3_v2_prefix"]["value"]})',
                 [fk] if fk else [], str((cap.get('syncinfo') or {}).get('chain_fingerprint') or '')))
    # D13 v2 remnant peers (their chain fails the fork-version rule; the node drops them)
    # r25 (B72): the grade reads the WINDOW (peers connected now + drop lines since the window's first block); the
    # whole log (since 2026-10-21) and the 7-day GetSyncInfo count are context, not evidence about this window
    pi = cap.get('peerinfo') or {}
    v2_log = lc.get('v2_drop', 0)
    v2_win = sum(1 for e in evs_ if e.get('k') == 'v2' and (e.get('t') or 0) >= t_win)
    v2_now = pi.get('peers_below_v3')
    v2_7d = (cap.get('syncinfo') or {}).get('v2_chain_peers_seen_7d')
    if v2_now is None and v2_7d is None:
        g = 'NO-DATA'
    else:
        g = 'OBSERVED' if ((v2_now or 0) + v2_win) else 'NORMAL'
    D.append(det('D13-v2-remnant', 'Peers still on the pre-HF3 v2 remnant chain', g,
                 (f'{v2_now} connected below v3, {v2_win} drop lines in the window ({v2_log} in the whole log, {v2_7d} seen in 7 d)'
                  if log_was_read(cap) else      # r30 fix D4: no log read -> no '0 in the whole log' (a 0 that is not a reading)
                  f'{v2_now} connected below v3, log not read (drop lines unknown; {v2_7d} seen in 7 d)'), A(R, 'v2_filter'),
                 'GetPeerInfo top_version < 3 among active peers + log "dropping peer on pre-HF3 (v2) chain" lines since the window\'s first block '
                 '(whole-log and 7-day counts are context)',
                 [{'peers_below_v3': v2_now, 'v2_drop_lines_window': v2_win if log_was_read(cap) else None,
                   'v2_drop_lines_log': v2_log if log_was_read(cap) else None, 'log_read': log_was_read(cap), 'v2_chain_peers_seen_7d': v2_7d}],
                 'their blocks fail Check_Block_Version (blockchain.go); the v2 filter drops them, so they cannot affect this chain; counted, never named'))
    # D14/D15 share concentration
    for did, key, label in (('D14-concentration-regular', 'regular', 'regular miniblocks'), ('D15-concentration-final', 'final', 'finals (block integration)')):
        tot = sum(p[key] for p in parts) or 0
        best = max(parts, key=lambda p: p[key], default=None)
        if not best or not tot:
            D.append(det(did, f'No participant holds more than 1/3 of the {label}', 'NO-DATA', 'pending', None, '', []))
            continue
        sh = best[key] / tot
        lo_ci, hi_ci = wilson(best[key], tot)
        # r30 (rft §7 B201, audit b201-d15-d19-test-inconsistent): graded on the Wilson 95 % lower bound, as D19 is, so
        # a share a hair over 1/3 that the window cannot tell from 1/3 is NORMAL (it was ANOMALY on the point estimate)
        g = 'ANOMALY' if lo_ci > 1 / 3 else 'NORMAL'
        D.append(det(did, f'No participant holds more than 1/3 of the {label}', g, round(sh, 4), None,
                     'Wilson 95 % lower bound of the top-1 share > 1/3 (selfish-mining threshold, Eyal-Sirer 2014) = ANOMALY (r30; before r30 the point share); > 1/2 = majority (stated); Wilson 95 % interval shown',
                     [{'participant': best['id'], 'count': best[key], 'of': tot, 'share': round(sh, 4), 'ci95': [round(lo_ci, 4), round(hi_ci, 4)],
                       'over_half': sh > 0.5}],
                     f"Nakamoto coefficient {k['nakamoto_' + key]}, HHI {k['hhi_' + key]}"))
    # D16 finals vs regular share (who integrates more blocks than its hashrate share suggests)
    dev = [p for p in parts if p['final_vs_regular_p'] is not None and p['final_vs_regular_p'] < alpha_p]
    # r29: each deviator carries the pooling pattern that produces it. Header data cannot tell pooling from anything else
    # per participant: every final and every regular miniblock is attributed, so sum(final shares) = sum(regular shares)
    # = 1 and any participant's excess is exactly matched by the others' deficits. The grade stays the stated test's;
    # 'explained' says which pattern each deviation is. 'beyond_miner_only' marks an integrator whose finals exceed even
    # the hashrate of addresses that never integrate (one-sided p < alpha), so it also draws on multi-role addresses.
    tf_ = sum(p['final'] for p in parts)
    mo = sum(p['regular_share'] for p in parts if p['role'] == 'miner-only')

    def explained(p):
        if p['role'] == 'integrator-only':
            return 'pool node: the finals of the miners it serves getwork to'
        if p['role'] == 'miner-only':
            return 'pooled miner: its finals pay the integrator of the node it mines through'
        return ('pool node that also mines' if p['final_share'] > p['regular_share']
                else 'part of its hashrate mines through another node')
    ev16 = [{'participant': p['id'], 'role': p['role'], 'final': p['final'], 'final_share': p['final_share'], 'regular_share': p['regular_share'],
             'p': p['final_vs_regular_p'], 'explained': explained(p),
             'beyond_miner_only': bool(tf_ and p['final_share'] > p['regular_share']
                                       and binom_upper(p['final'], tf_, min(1.0, p['regular_share'] + mo)) < alpha_p)} for p in dev]
    D.append(det('D16-final-vs-regular', 'Each integrator wins finals in proportion to its regular miniblock share', 'ANOMALY' if dev else ('NORMAL' if tested else 'NO-DATA'),
                 len(dev), A(R, 'header_integrator'), f'final count ~ Binomial(n, regular share); two-sided exact p < {alpha_p:.2e}',
                 ev16[:8],
                 'the final pays the integrator of the node that built the template (miner_block.go), so a node serving getwork to other '
                 'miners collects finals beyond its own regular share by design: a signal of pooling, not of a rule broken; '
                 f"by pattern: {dict(collections.Counter(e['explained'] for e in ev16))}; miner-only regular share {round(mo, 4)}; "
                 f"beyond the miner-only hashrate: {sum(e['beyond_miner_only'] for e in ev16)}"))
    # D17 this node's share
    tn_r, tn_f = k['this_node_regular'], k['this_node_final']
    paused = (cap.get('getinfo') or {}).get('connected_miners') == 0
    if not k['this_node_known']:
        g, v = 'NO-DATA', 'pending'
    else:
        g = 'NORMAL'
        v = f'{tn_r} regular, {tn_f} finals'
    D.append(det('D17-this-node', 'This node\'s own share against what it should be', g, v, A(R, 'header_integrator'),
                 'own integrator address (derod "will use" log line) compared in memory; expected 0 while no miner is connected',
                 [{'this_node_regular': tn_r, 'this_node_final': tn_f, 'connected_miners': (cap.get('getinfo') or {}).get('connected_miners')}],
                 'miner track PAUSED (dero-rft §0.3): no miner connected, expected share 0' if paused else 'expected share needs the miner hashrate (pending)'))
    # D18 cadence (log_intel's rule: at-tip mean block time 15..22 s)
    mbt = k['block_time_mean_s']
    D.append(det('D18-cadence', 'Mean block time inside 15..22 s (target 18 s)', 'NO-DATA' if mbt == 'pending' else ('NORMAL' if 15 <= mbt <= 22 else 'ANOMALY'),
                 mbt, A(R, 'block_time'), 'window MEAN of consecutive-height timestamp gaps outside 15..22 s (harness/intel/log_intel.py RULES cadence)',
                 [{'mean_s': mbt, 'median_s': k['block_time_median_s'], 'p95_s': k['block_time_p95_s'], 'max_s': k['block_time_max_s'],
                   'averageblocktime50_s': k['averageblocktime50_s']}]))
    D.append(collective_final(parts, k))                                   # r25 (CO24-C8, B62)
    D.append(alt_reconcile(cap, R, H, k))                                   # r25 (CO24-C4, B58)
    return D


def collective_final(parts, k):
    """D19 (r25, CO24-C8): the integrator-only participants (paid finals, no regular miniblock of their own) TOGETHER.
    D15 tests one participant against 1/3; a set of nodes that only assemble other miners' work can hold more as a
    group. ANOMALY when the Wilson 95 % lower bound of their joint final share is above 1/3 (the same selfish-mining
    threshold, Eyal-Sirer 2014, applied to the coalition). Pooling by design (miner_block.go pays the template builder),
    so a signal of concentration of block ASSEMBLY, never an accusation."""
    tf = sum(p['final'] for p in parts)
    io = [p for p in parts if p['role'] == 'integrator-only']
    if not tf:
        return det('D19-collective-final', 'Integrator-only participants together assemble no more than 1/3 of the blocks', 'NO-DATA', 'pending',
                   None, 'Wilson 95 % lower bound of the integrator-only joint final share > 1/3 = ANOMALY', [])
    n_io = sum(p['final'] for p in io)
    lo, hi = wilson(n_io, tf)
    g = 'ANOMALY' if lo > 1 / 3 else 'NORMAL'
    return det('D19-collective-final', 'Integrator-only participants together assemble no more than 1/3 of the blocks', g, round(n_io / tf, 4), None,
               'Wilson 95 % lower bound of the integrator-only joint final share > 1/3 = ANOMALY (coalition form of D15)',
               [{'integrator_only': len(io), 'finals': n_io, 'of': tf, 'share': round(n_io / tf, 4), 'ci95': [round(lo, 4), round(hi, 4)],
                 'members': [p['id'] for p in sorted(io, key=lambda p: -p['final'])][:8]}],
               f"Nakamoto coefficient by finals {k.get('nakamoto_final')}, top-3 final share {k.get('top3_final_share')}; pooling by design "
               '(the final pays the template builder\'s integrator), not a rule broken')


def log_was_read(cap):
    """r30 fix D4: True when the capture scanned a derod log (its line count > 0). A capture without the 'lines' field
    (pre-r24) falls back to whether it holds any start line or event. Pure."""
    lg = cap.get('log') or {}
    n = lg.get('lines')
    if isinstance(n, int):
        return n > 0
    return bool(lg.get('startups_ms') or lg.get('events'))


def alt_reconcile(cap, R, H, k):
    """D20 (r25, CO24-C4): GetInfo alt_blocks_count is the node's settled alt count, and the alt blocks it lists are the
    ones the log shows. Log side: every block with a "Chain extended" or "... but height is same" line since the newest
    derod start, settled (height <= window tip height - STABLE_LIMIT - 1) and inside the window, that is not the main
    block at its height. Node side: GetConsensusStats alt_blocks (r25), same height range. ANOMALY when GetInfo and
    GetConsensusStats disagree or the two sets differ; NO-DATA on a pre-r25 node (no GetConsensusStats)."""
    cs = cap.get('consensus_stats') if isinstance(cap.get('consensus_stats'), dict) and 'error' not in cap.get('consensus_stats') else None
    rule = A(R, 'alt_settle')
    test = ('GetConsensusStats alt_blocks.count lies between GetInfo alt_blocks_count read right before and right after it (the count '
            'only grows; a capture without that pair: GetInfo, read earlier, <= the stats count), and the settled non-main blocks of the '
            'log since the newest start == the listed alt blocks over the same heights')
    if not cs or not H:
        return det('D20-alt-blocks', 'GetInfo alt_blocks_count equals the side blocks this node kept', 'NO-DATA', 'pending', rule, test, [],
                   'needs DERO.GetConsensusStats (r25 derod)')
    alt = cs.get('alt') or {}
    starts = (cap.get('log') or {}).get('startups_ms') or []
    t0 = max(starts) if starts else 0
    # r30 (found taking the B201 third reading without the datadir log): when no log was read the log side is unknown,
    # not empty; only the counts are graded (it was ANOMALY 'log 0 / node 52'). r30 fix D4: 'read' is the scanned line
    # count (> 0), not the presence of a derod start line (a log that was read but holds no start line is still a log)
    log_read = log_was_read(cap)
    sl = int(R['stable_limit']['value'])
    hi_h = H[-1]['height'] - sl - 1
    lo_h = max(H[0]['height'], int(alt.get('tracked_from_height') or 0))
    blocks = alt.get('blocks') or []
    if (alt.get('count') or 0) > len(blocks) and blocks:     # the node lists only the newest ALT_LIST_KEEP
        lo_h = max(lo_h, min(b['height'] for b in blocks))
    main_at = {h['height']: h['hash'] for h in H}
    log_alt = {e['blid'][:16] for e in (cap.get('log') or {}).get('events') or []
               if e.get('k') in ('add', 'side') and (e.get('t') or 0) >= t0 and isinstance(e.get('h'), int) and lo_h <= e['h'] <= hi_h
               and main_at.get(e['h']) != e['blid']}
    node_alt = {b['hash'] for b in blocks if isinstance(b.get('height'), int) and lo_h <= b['height'] <= hi_h}
    gi_n = (cap.get('getinfo') or {}).get('alt_blocks_count')
    only_log, only_node = sorted(log_alt - node_alt), sorted(node_alt - log_alt)
    # r29: the count only grows while derod runs (p2p/consensus_obs_r25.go settle: `a.count++`, never decremented), so a
    # GetInfo read BEFORE GetConsensusStats bounds it from below and one AFTER from above. Captures with the pair (r29+)
    # check before <= stats <= after; older captures read GetInfo ~40 s earlier, so they check gi <= stats.
    pair = (cap.get('getinfo') or {}).get('alt_blocks_count_around_stats') or [None, None]
    n = alt.get('count')
    if isinstance(n, int) and isinstance(pair[0], int) and isinstance(pair[1], int):
        count_ok, how = pair[0] <= n <= pair[1], f'GetInfo {pair[0]}..{pair[1]} around the stats read'
    elif isinstance(n, int) and isinstance(gi_n, int):
        count_ok, how = gi_n <= n, 'GetInfo read before the walk: a lower bound'
    else:
        count_ok, how = gi_n == n, 'equality'
    bad = not count_ok or (log_read and (only_log or only_node))
    return det('D20-alt-blocks', 'GetInfo alt_blocks_count equals the side blocks this node kept', 'ANOMALY' if bad else 'NORMAL',
               f"alt_blocks_count {gi_n}, node {alt.get('count')}, "
               + (f"log {len(log_alt)} / node {len(node_alt)}" if log_read else f"log not read (counts only) / node {len(node_alt)}")
               + f" in heights {lo_h}..{hi_h}", rule, test,
               [{'log_read': log_read, 'getinfo_alt_blocks_count': gi_n, 'getinfo_around_stats': pair, 'count_check': how, 'stats_count': alt.get('count'), 'unsettled': alt.get('unsettled'), 'tracked': alt.get('tracked'),
                 'heights': [lo_h, hi_h], 'log_alt': len(log_alt), 'node_alt': len(node_alt), 'only_in_log': only_log[:5], 'only_in_node': only_node[:5]}],
               'a block is settled once it is more than STABLE_LIMIT below the tip; the alt set counts blocks this node ACCEPTED (the log '
               'lines) that are not in the topo index at their height')


def role(p):
    return 'integrator-only' if p['regular'] == 0 else ('miner-only' if p['final'] == 0 else 'both')


def decile_test(id_, title, H, parts, val, seq_final, alpha_p, rule, what):
    if len(val) < 50:
        return det(id_, title, 'NO-DATA', 'pending', rule, what, [], f'only {len(val)} blocks with a value')
    q = quantile(list(val.values()), LOW_DECILE)
    low = {i for i, v in val.items() if v < q}
    p0 = len(low) / len(val)
    flag, worst = [], None
    for p in parts:
        mine = [i for i in val if seq_final[i] == p['id']]
        if len(mine) < MIN_N:
            continue
        c = sum(1 for i in mine if i in low)
        pv = binom_upper(c, len(mine), p0)
        row = {'participant': p['id'], 'low': c, 'of': len(mine), 'rate': round(c / len(mine), 4), 'base': round(p0, 4), 'p': round(pv, 10)}
        if worst is None or pv < worst['p']:
            worst = row
        if pv < alpha_p:
            flag.append(row)
    return det(id_, title, 'ANOMALY' if flag else 'NORMAL', len(flag), rule,
               f'{what}; per integrator (>= {MIN_N} blocks) binomial excess over the window rate, p < {alpha_p:.2e}',
               flag[:5] or ([worst] if worst else []), f'decile threshold {round(q)} over {len(val)} blocks')


def early_arrival_test(H, parts, lags, seq_final, alpha_p, rule, fut):
    id_, title = 'D03-ts-forward', 'No integrator stamps its blocks ahead of time (blocks arriving before their timestamp)'
    what = 'first-seen log time minus block timestamp < 0 ms'
    if len(lags) < 50:
        return det(id_, title, 'NO-DATA', 'pending', rule, what, [], f'only {len(lags)} blocks seen live')
    neg = {i for i, v in lags.items() if v < 0}
    p0 = len(neg) / len(lags)
    flag, ctx = [], decile_test(id_, title, H, parts, lags, seq_final, alpha_p, rule, 'fastest-arrival decile')
    for p in parts:
        mine = [i for i in lags if seq_final[i] == p['id']]
        if not mine:
            continue
        c = sum(1 for i in mine if i in neg)
        if not c:
            continue
        pv = binom_upper(c, len(mine), p0)
        if c >= 3 and pv < alpha_p:
            flag.append({'participant': p['id'], 'early': c, 'of': len(mine), 'base': round(p0, 5), 'p': round(pv, 10)})
    prox = [dict(e, context='fastest-arrival decile (network proximity to this node, not a stamping signal)') for e in ctx['evidence'][:3]]
    return det(id_, title, 'ANOMALY' if flag else 'NORMAL', len(flag), rule,
               f'{what}; per integrator binomial excess over the window rate {len(neg)}/{len(lags)}, p < {alpha_p:.2e}, at least 3 events',
               flag[:5] + prox, f'{len(neg)} of {len(lags)} live blocks arrived before their timestamp (min lag {min(lags.values())} ms); '
               f'the consensus allowance is +{fut} ms (D02); fastest-decile context: {ctx["grade"]} ({ctx["note"]})')


def late_releases(cap, H, lags):
    """Blocks whose child arrived < 1 s after them though minted > half a block time later (live, not near start-up)."""
    starts = (cap.get('log') or {}).get('startups_ms') or []
    bt = int(cap.get('_bt_ms') or 18000)
    out = []
    for i in range(1, len(H)):
        if i not in lags or (i - 1) not in lags or H[i]['height'] != H[i - 1]['height'] + 1:
            continue
        seen_parent = H[i - 1]['ts'] + lags[i - 1]
        seen_child = H[i]['ts'] + lags[i]
        if any(0 <= seen_parent - s <= 600_000 for s in starts):
            continue
        if 0 <= seen_child - seen_parent < 1000 and H[i]['ts'] - H[i - 1]['ts'] > bt // 2:
            ms = H[i - 1].get('miners') or []
            out.append({'height': H[i - 1]['height'], 'hash': H[i - 1]['hash'][:16], 'participant': ms[-1] if ms else 'unknown',
                        'gap_seen_ms': seen_child - seen_parent, 'gap_ts_ms': H[i]['ts'] - H[i - 1]['ts']})
    return out


def log_census(cap, root):
    lg = cap.get('log') or {}
    c = lg.get('census') or {}
    fl = lg.get('first_last') or {}
    rows = []
    kinds = [(kk, lit) for kk, _how, _m, lit in LOG_KINDS] + [('block_rejected:' + msg, None) for msg, _ in reject_literals(root)] + [('error_other', None)]
    rej = {('block_rejected:' + msg): a for msg, a in reject_literals(root)}
    for kk, lit in kinds:
        a = literal_anchor(root, lit) if lit else rej.get(kk)
        rows.append({'kind': kk, 'lines': c.get(kk, 0), 'first': (fl.get(kk) or {}).get('first'), 'last': (fl.get(kk) or {}).get('last'),
                     'printed_by': a})
    days = lg.get('by_day') or {}
    return {'files': lg.get('files'), 'lines_scanned': lg.get('lines'), 'kinds': rows,
            'by_day': {d: {kk: v for kk, v in sorted(cs.items()) if not kk.startswith('own_miniblock')} for d, cs in days.items()}}


def proposals(cap, R, k, root):
    """Node-side gaps this run had to work around: each is an R25 candidate (CO24-*) with its code anchor.
    r25: a gap is proposed only while the CAPTURED binary still shows it (a live reading closes it, not the tree), and
    each anchor list names the upstream line and the r25 line, whichever this tree holds."""
    P = []
    H = cap.get('headers') or []
    cs = cap.get('consensus_stats') if isinstance(cap.get('consensus_stats'), dict) and 'error' not in cap.get('consensus_stats') else None
    r25_headers = bool(H) and all('fees' in h for h in H)
    lifetime = isinstance((cap.get('finality') or {}).get('lifetime'), dict)

    def add(pid, sev, title, anchors, why):
        good = [a for a in anchors if a]
        if good:
            P.append({'id': pid, 'severity': sev, 'title': title, 'anchors': good, 'why': why})

    def L(q):
        return literal_anchor(root, q)
    if not cs:
        add('CO24-C1', 'medium', 'Count and log miniblock refusals by reason in NotifyMiniBlock (stale height, unregistered miner, unexpandable tip, final propagated)',
            [L('return fmt.Errorf("Stale Miniblock")'), L('return fmt.Errorf("unregistered miner")'), L('return fmt.Errorf("tip could not be expanded")'),
             L('return c.refuse_miniblock(MBL_REFUSED_STALE, mbl.Height, fmt.Errorf("Stale Miniblock"))')],
            'these return an error to the peer with no log line and no /metrics series, so miniblock spam is invisible to the observatory (only invalid PoW is penalised)')
    if not r25_headers:
        add('CO24-C2', 'medium', 'Expose the fees of a block in BlockHeader_Print / GetBlockHeadersRange',
            [L('TXCount       int64    `json:"txcount"`'), L('Fees           *uint64 `json:"fees"`')],
            f"fees per block cannot be measured without decoding every transaction (window fees_total = {k.get('fees_total')})")
    if not cs:
        add('CO24-C3', 'medium', 'Name the sending peer (pseudonymous id) and count block rejections by reason (blockchain_block_rejected_total{reason})',
            [L('block_logger.Error(fmt.Errorf("Rejecting Block, timestamp is too much into future, make sure that system clock is correct"), "")'),
             L('var block_rejected = new_reason_counter("blockchain_block_rejected_total")')],
            'a block rejection line carries no peer id, so an invalid block cannot be attributed and repeated offenders cannot be graded')
    if not cs and k.get('alt_blocks_count_getinfo') in (0, None) and k.get('side_block_lines_window'):
        add('CO24-C4', 'medium', 'Assign GetInfo alt_blocks_count (declared, never set) from the side blocks the chain keeps',
            [L('Alt_Blocks_Count           uint64  `json:"alt_blocks_count"`')],
            f"GetInfo says alt_blocks_count {k.get('alt_blocks_count_getinfo')} while the log shows {k.get('side_block_lines_window')} side-block lines in the window")
    if not any(h.get('fs') for h in H) and not r25_headers:
        add('CO24-C5', 'low', 'Record the first-seen time of each block (and miniblock) and expose it by RPC',
            [L('block_logger.Info("Chain extended", "new height", height)')],
            'arrival lag (timestamp skew vs this clock) is measurable only from the DEBUG "Chain extended" log line; a rotated or quieter log loses it')
    if not lifetime:
        add('CO24-C6', 'low', 'Persist the reorg monitor across restarts and log each reorganisation at INFO',
            [L("// derod does not log a reorganisation at the default level and GetInfo does not show one, so a wallet that cached")],
            f"GetMonetaryIntegrity finality counts reset at every start (reorgs {k.get('finality_reorgs')} since the current start); history before it is lost")
    if not r25_headers:
        add('CO24-C7', 'low', 'Resolve header miners against the block\'s topoheight state, not Topo_store.Read(height)',
            [L('if toporecord, err1 := chain.Store.Topo_store.Read(result.Height); err1 == nil { // we must now fill in compressed ring members'),
             L('func header_miners(n int, resolve func(i int) (string, bool), integrator string, has_integrator bool) []string {')],
            'correct only while topoheight == height (GetMiniBlocks already resolves at the topoheight, rpc_dero_explorer.go)')
    return P


# ─────────────────────────── writers ───────────────────────────
def dump_lines(doc):
    """JSON with one fact per line: scalars and small dicts inline, list elements one per line (anchorable)."""
    def scalar(v):
        return json.dumps(v, ensure_ascii=False, separators=(', ', ': '))
    out = ['{']
    keys = list(doc)
    for i, kk in enumerate(keys):
        v = doc[kk]
        comma = ',' if i < len(keys) - 1 else ''
        if isinstance(v, dict) and v and all(not isinstance(x, (dict, list)) or len(json.dumps(x)) < 160 for x in v.values()):
            out.append(f' {json.dumps(kk)}: {{')
            sub = list(v)
            for j, s in enumerate(sub):
                out.append(f'  {json.dumps(s, ensure_ascii=False)}: {scalar(v[s])}' + (',' if j < len(sub) - 1 else ''))
            out.append(' }' + comma)
        elif isinstance(v, dict) and v:
            out.append(f' {json.dumps(kk)}: {{')
            sub = list(v)
            for j, s in enumerate(sub):
                x = v[s]
                if isinstance(x, list):
                    out.append(f'  {json.dumps(s, ensure_ascii=False)}: [')
                    for q, e in enumerate(x):
                        out.append('   ' + scalar(e) + (',' if q < len(x) - 1 else ''))
                    out.append('  ]' + (',' if j < len(sub) - 1 else ''))
                else:
                    out.append(f'  {json.dumps(s, ensure_ascii=False)}: {scalar(x)}' + (',' if j < len(sub) - 1 else ''))
            out.append(' }' + comma)
        elif isinstance(v, list):
            out.append(f' {json.dumps(kk)}: [')
            for j, e in enumerate(v):
                out.append('  ' + scalar(e) + (',' if j < len(v) - 1 else ''))
            out.append(' ]' + comma)
        else:
            out.append(f' {json.dumps(kk)}: {scalar(v)}{comma}')
    out.append('}')
    return '\n'.join(out) + '\n'


def text_capture(doc, ts):
    L = [f'# consensus_intel capture {ts} (harness/intel/consensus_intel.py, r24; read-only RPC + derod log)',
         f"# version {doc.get('version')}",
         f"# source {doc.get('source')} captured {doc.get('captured')}"]
    k = doc.get('kpis') or {}
    L.append(f"# window topo {k.get('window_topo_first')}..{k.get('window_topo_last')} ({k.get('window_blocks')} blocks, {k.get('window_hours')} h)")
    for kk, v in k.items():
        L.append(f'kpi {kk} = {json.dumps(v)}')
    for p in doc.get('participants') or []:
        L.append(f"participant {p['id']} regular {p['regular']} ({p['regular_share']}) final {p['final']} ({p['final_share']}) "
                 f"longest_final_run {p['longest_final_run']} run_p {p['run_p']} final_vs_regular_p {p['final_vs_regular_p']}")
    for d in doc.get('detectors') or []:
        r = d.get('rule') or {}
        L.append(f"detector {d['id']} {d['grade']} value={json.dumps(d['value'])} rule={r.get('file')}:{r.get('line')} test={d['test'][:160]}")
    for r in (doc.get('log_census') or {}).get('kinds') or []:
        pb = r.get('printed_by') or {}
        L.append(f"log kind={r['kind']} lines={r['lines']} first={r.get('first')} last={r.get('last')} printed_by={pb.get('file')}:{pb.get('line')}")
    for p in doc.get('proposals') or []:
        a = p['anchors'][0]
        L.append(f"proposal {p['id']} {p['severity']} {p['title']} @ {a['file']}:{a['line']}")
    s = doc.get('summary') or {}
    L.append('summary ' + ' '.join(f'{g}={s.get(g, 0)}' for g in GRADES))
    return '\n'.join(L) + '\n'


def series_row(doc, ts, capfile):
    k = doc.get('kpis') or {}
    keep = ('window_blocks', 'window_height_last', 'block_time_mean_s', 'block_time_median_s', 'block_time_p95_s', 'difficulty_mean',
            'difficulty_rule_mismatches', 'participants', 'top1_regular_share', 'top1_final_share', 'hhi_regular', 'nakamoto_regular',
            'nakamoto_final', 'side_block_lines_window', 'finality_reorgs', 'arrival_lag_median_ms', 'empty_block_ratio', 'this_node_regular',
            # r25 (CO24-C8 + node counters): the collective share, the peer census and the r25 counters join the series
            'integrator_only_final_share', 'top3_final_share', 'peers_connected', 'peers_below_v3', 'peer_versions', 'alt_blocks_count_getinfo',
            'alt_blocks_rpc', 'miniblock_refused_total', 'block_rejected_total', 'finality_lifetime_reorgs', 'fees_total', 'arrival_source')
    return {'ts': ts, 'captured': doc.get('captured'), 'version': doc.get('version'), 'capture': capfile,
            **{kk: k.get(kk) for kk in keep}, 'grades': doc.get('summary')}


def write_outputs(doc, rt, ts, series=True):
    rt.mkdir(parents=True, exist_ok=True)
    body = dump_lines(doc)
    txt = text_capture(doc, ts)
    lk = leaks(body) + leaks(txt)
    if lk:
        raise RuntimeError(f'privacy: refusing to write {len(lk)} address/IP literal(s) into the outputs')
    tmp = rt / '.consensus_intel.json.tmp'
    tmp.write_text(body)
    tmp.replace(rt / 'consensus_intel.json')
    cf = f'consensus_capture_{ts}.txt'
    (rt / cf).write_text(txt)
    if series:
        with (rt / 'consensus_series.jsonl').open('a') as f:
            f.write(json.dumps(series_row(doc, ts, cf)) + '\n')
    return rt / 'consensus_intel.json', rt / cf


# ─────────────────────────── G26 ───────────────────────────
DETECTOR_IDS = ('D01-ts-monotonic', 'D02-ts-future', 'D03-ts-forward', 'D04-ts-backward', 'D05-difficulty-rule', 'D06-difficulty-jump',
                'D07-miniblock-structure', 'D08-final-bursts', 'D09-late-release', 'D10-reorg-depth', 'D11-invalid-objects',
                'D12-fork-fingerprint', 'D13-v2-remnant', 'D14-concentration-regular', 'D15-concentration-final', 'D16-final-vs-regular',
                'D17-this-node', 'D18-cadence', 'D19-collective-final', 'D20-alt-blocks')   # r25: D19, D20
# detectors that may legitimately read NO-DATA (no live log window, unknown own address); the others must grade.
# r25: D20 needs DERO.GetConsensusStats, which a pre-r25 derod does not serve
MAY_BE_NODATA = ('D02-ts-future', 'D03-ts-forward', 'D09-late-release', 'D17-this-node', 'D20-alt-blocks')


def g26(root=ROOT, at=None, max_age_h=FRESH_H):
    """(ok, detail): a fresh live capture; every registered detector reported with a grade; every rule anchor and every
    page row anchor re-resolves; no address/IP in the outputs; the capture text exists."""
    root = Path(root)
    rt = root / 'harness/runtime'
    why = []
    p = rt / 'consensus_intel.json'
    try:
        doc = json.loads(p.read_text())
    except (OSError, ValueError) as e:
        return False, f'consensus_intel.json unreadable: {e}'
    if doc.get('source') != 'live':
        why.append(f"source {doc.get('source')!r} (not a live capture)")
    try:
        cap = datetime.datetime.fromisoformat(doc['captured'])
        age = ((at or now_utc()) - cap).total_seconds() / 3600
        if age > max_age_h or age < -0.1:
            why.append(f'capture is {age:.1f} h old (limit {max_age_h} h)')
    except (KeyError, ValueError, TypeError):
        why.append('no capture time')
        age = None
    ds = {d.get('id'): d for d in doc.get('detectors') or []}
    for i in DETECTOR_IDS:
        d = ds.get(i)
        if not d:
            why.append(f'{i} not reported')
            continue
        if d.get('grade') not in GRADES:
            why.append(f"{i} grade {d.get('grade')!r}")
        if d.get('grade') == 'NO-DATA' and i not in MAY_BE_NODATA:
            why.append(f'{i} NO-DATA')
        r = d.get('rule')
        if r and find_line(root, r['file'], r['quote']) is None:
            why.append(f"{i} rule anchor gone ({r['file']})")
        if not r and 'p <' not in str(d.get('test')) and '>' not in str(d.get('test')):
            why.append(f'{i} has neither a rule anchor nor a stated test')
    for nm, r in (doc.get('rules') or {}).items():
        if find_line(root, r['file'], r['quote']) is None:
            why.append(f'rule {nm} anchor gone ({r["file"]})')
    body = p.read_text()
    if leaks(body):
        why.append(f'{len(leaks(body))} address/IP literal(s) in consensus_intel.json')
    caps = sorted(rt.glob('consensus_capture_*.txt'))
    if not caps:
        why.append('no consensus_capture_*.txt')
    elif leaks(caps[-1].read_text()):
        why.append(f'address/IP literal(s) in {caps[-1].name}')
    # every page row anchored (model/raw/consensus.json from miners/mine_consensus.py)
    raw = root / 'harness/model/raw/consensus.json'
    nrows = 0
    if raw.exists():
        rd = json.loads(raw.read_text())
        for r in rd.get('rows') or []:
            nrows += 1
            evs = r.get('evidence') or []
            if not evs:
                why.append(f"row {r.get('id')} has no anchor")
                continue
            for e in evs:
                if find_line(root, e['file'], e['quote']) is None:
                    why.append(f"row {r.get('id')} anchor {e['file']} does not resolve")
                    break
        if rd.get('unverified'):
            why.append(f"{len(rd['unverified'])} unverified page item(s)")
    else:
        why.append('model/raw/consensus.json missing (run harness/miners/mine_consensus.py)')
    s = doc.get('summary') or {}
    det_ = (f"{len(ds)} detectors (OBSERVED {s.get('OBSERVED', 0)}, ANOMALY {s.get('ANOMALY', 0)}, NORMAL {s.get('NORMAL', 0)}, "
            f"NO-DATA {s.get('NO-DATA', 0)}), window {(doc.get('kpis') or {}).get('window_blocks')} blocks, capture "
            f"{'%.1f h' % age if age is not None else '?'} old, {nrows} page rows")
    return not why, det_ + (f" · {'; '.join(why)[:500]}" if why else '')


# ─────────────────────────── main ───────────────────────────
def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('cmd', nargs='?', default='run', choices=('run', 'g26'))
    ap.add_argument('--window', type=int, default=DEFAULT_WINDOW)
    ap.add_argument('--from', dest='src', help='re-analyse a raw capture (pseudonymised JSON)')
    ap.add_argument('--root', default=str(ROOT))
    ap.add_argument('--out-dir', default=None, help='runtime dir to write (default <root>/harness/runtime)')
    ap.add_argument('--log', action='append', help='derod log file(s) (default the datadir logs)')
    ap.add_argument('--rpc', default=RPC_URL)
    ap.add_argument('--metrics', default=METRICS_URL)
    ap.add_argument('--no-series', action='store_true')
    ap.add_argument('--no-raw', action='store_true', help='do not keep the raw capture in the private dir')
    ap.add_argument('--json-only', action='store_true')
    a = ap.parse_args(argv)
    root = Path(a.root)
    if a.cmd == 'g26':
        ok, d = g26(root)
        print(('PASS' if ok else 'FAIL') + '  G26 ' + d)
        return 0 if ok else 3
    R, missing = load_rules(root)
    if missing:
        print(f'consensus_intel: rule anchors missing in the tree: {missing}', file=sys.stderr)
        return 2
    ts = now_utc().strftime('%Y%m%dT%H%M%SZ')
    if a.src:
        cap = json.loads(Path(a.src).read_text())
    else:
        try:
            salt = load_salt()
        except OSError as e:
            print(f'consensus_intel: no salt ({e})', file=sys.stderr)
            return 2
        logs = a.log or sorted(set(sum((glob.glob(g) for g in LOG_GLOBS), [])))
        own = own_integrator_from_logs(logs)
        try:
            cap = capture_live(max(10, a.window), salt, own, logs, url=a.rpc, murl=a.metrics)
        except Exception as e:                                       # noqa: BLE001
            print(f'consensus_intel: capture failed: {type(e).__name__}: {e}', file=sys.stderr)
            return 2
        own = None
        if not a.no_raw:
            d = PRIVATE / 'captures'
            d.mkdir(parents=True, exist_ok=True)
            (d / f'consensus_raw_{ts}.json').write_text(json.dumps(cap))
            # r24 (integration): ~10 MB per run accumulated unpruned with 755/644 modes (verifier); keep the newest
            # PRIVATE_KEEP runs within PRIVATE_MAX_BYTES, 0700 dirs / 0600 files (kit/privkit.py prune_private)
            sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'kit'))
            import privkit
            kept, gone = privkit.prune_private(d, keep=PRIVATE_KEEP, max_bytes=PRIVATE_MAX_BYTES,
                                               pattern=r'^consensus_raw_\d{8}T\d{6}Z\.json$')
            privkit.prune_private(PRIVATE, keep=10 ** 6, max_bytes=10 ** 15)      # modes only, on the whole tree
            if gone:
                print(f'consensus_intel: pruned {len(gone)} private raw capture(s), kept {len(kept)}', file=sys.stderr)
    cap['_bt_ms'] = int(R['block_time']['value']) * 1000
    doc = analyze(cap, R, root)
    if doc.get('error'):
        print(f"consensus_intel: {doc['error']}", file=sys.stderr)
        return 2
    rt = Path(a.out_dir) if a.out_dir else root / 'harness/runtime'
    out, txt = write_outputs(doc, rt, ts, series=not a.no_series)
    s = doc['summary']
    print(f"consensus_intel: {doc['kpis']['window_blocks']} blocks, {doc['kpis']['participants']} participants, detectors "
          + ' '.join(f'{g}={s[g]}' for g in GRADES) + f' -> {out.name}, {txt.name}')
    if not a.json_only:
        for d in doc['detectors']:
            print(f"  {d['grade']:9s} {d['id']:28s} {str(d['value'])[:70]}")
    return 5 if s.get('OBSERVED') else 0


if __name__ == '__main__':
    sys.exit(main())
