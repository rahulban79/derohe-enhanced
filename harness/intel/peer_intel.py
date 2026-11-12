#!/usr/bin/env python3
"""peer_intel.py (r24) — the consensus observatory of the network peers this node talks to, pseudonymised.

The node's own view of its neighbourhood, read-only: DERO.GetPeerInfo (cmd/derod/rpc/rpc_dero_explorer.go, fields of
p2p/peer_info.go PeerInfo), DERO.GetSyncInfo, DERO.GetInfo, derod /metrics (p2p_*), the derod log's P2P lines, and
COPIES of the datadir files peers.json, first_relay.json, v2_offences.json and ban_list.json. It measures per-peer
health and activity (lag, version mix, latency, clock offset, connection age, bytes, first-relay wins, churn) and runs
detectors that are each grounded in a code rule of this tree, graded:

  OBSERVED  the node's own rule fired on that peer (the rule's code line AND the observation line are cited)
  ANOMALY   statistically or operationally unusual (the test and its threshold are stated); never an accusation
  NORMAL    the detector ran and nothing crossed its rule or threshold
  pending   the detector could not run (no input, or its rule line is not in this tree any more)

PRIVACY (r24, artifacts/dero-rft.md §0.6 "Scrub + publish"). Peer IP addresses, peer tags and this box's names never
leave the private directory (default ~/derohe-persist/peer_intel_private, mode 700, outside every repository). A
peer is named 'peer-' + 8 hex of blake2b(salt | 'ip' | ip), a node identity 'node-' + 8 hex of blake2b(salt | 'id' |
peer_id), a block builder 'miner-' + 8 hex of blake2b(salt | 'builder' | key prefix); THIS node's own builder key is
'this-node' (read from the private self.json, never printed). The salt lives only in the private directory. /16
diversity is computed on the private IPs; only the counts reach the outputs. Raw captures (with IPs) stay private.

Outputs (all pseudonymised, all in harness/runtime/, tracked as evidence):
  peer_capture_<ts>.jsonl   one fact per line ({"src": ..., "peer": ...}), the anchor of every rendered value
  peer_logx_<ts>.jsonl      the P2P log lines the detectors used: derod.log line number, time, kind, pseudonym, numbers
  peer_intel.json           the report (KPIs, peers, detectors, census, proposals CO24-*), each value with its line
  peer_series.jsonl         one appended line per run (the rolling series)

  python3 -I harness/intel/peer_intel.py --live [--private DIR] [--log FILE ...] [--rpc URL]
  python3 -I harness/intel/peer_intel.py --capture DIR      # analyse an existing (private or synthetic) capture
  python3 -I harness/intel/peer_intel.py --check            # gate G27 on the newest outputs
Exit 0 · 3 G27 failed · 2 no input.

r30 (rft §7 B201, the R30 consensus-peers dimension; plan harness/runtime/r30_audit/r29_ledger_audit_plan.md:60):
  * lag_max is the largest lag among peers on top_version >= 3; v2-remnant peers (top_version < 3, already counted by
    D1/D13/v2_seen_7d) are reported apart as lag_max_v2, so one phenomenon no longer moves five KPIs;
  * kpis.inbound_regime ('inbound' when GetPeerInfo counts incoming peers, 'outbound-only' at 0) keys the KPI series:
    area_intel compares a peer KPI only with the newest earlier round of the same regime (keyed_by in areas.json);
  * D2 explain: each lagging peer's height over the earlier captures of the same salt (harness/runtime
    peer_capture_*.jsonl) is SYNCING (height rose), STUCK (unchanged over >= 2 captures) or REGRESSED (fell, i.e. a
    re-sync from a lower point), cross-referenced to the replay walls (forensics/<newest>/derived/walls.json);
  * D11 graded: one peer_id on several addresses is EXPLAINED (NORMAL, one multi-homed host) when the RTTs agree
    within RTT_DIVERGE, else UNEXPLAINED (ANOMALY: one identity on hosts at different network distances);
  * D9 graded on the Wilson 95 % lower bound of the top peer's first-relay share (ANOMALY only when the lower bound
    is above FIRST_RELAY_CONC), with the share over the earlier captures in its explain.
"""
import argparse, datetime, hashlib, ipaddress, json, os, re, secrets, shutil, statistics, sys, time, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent
ROOT = HARNESS.parent
RPC = 'http://127.0.0.1:10102/json_rpc'
METRICS = 'http://127.0.0.1:10102/metrics'
PRIVATE = Path.home() / 'derohe-persist' / 'peer_intel_private'
PRIVATE_KEEP = int(os.environ.get('DERO_PRIVATE_KEEP') or 24)                # r24: private raw runs kept
PRIVATE_MAX_BYTES = int(os.environ.get('DERO_PRIVATE_MAX_BYTES') or 64 * 1024 * 1024)
DATADIR_FILES = ('peers.json', 'first_relay.json', 'v2_offences.json', 'ban_list.json', 'ban_reasons.json')   # r25: + ban sources (CO24-N4)
RPC_METHODS = ('GetPeerInfo', 'GetSyncInfo', 'GetInfo')
FRESH_H = 24
CURRENT_VERSION_RX = re.compile(r'^3\.6\.0-153\.')                     # this tree's release line (config/version.go)
VERSION_RX = re.compile(r'^\d+\.\d+\.\d+-\d+\.DEROHE\.STARGATE(\+\d{8}(\.[A-Za-z0-9]{1,12})?)?$')
IPV4 = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)')
IPV6 = re.compile(r'(?<![\w:])[0-9a-fA-F:]{6,39}(?![\w:])')
LOGGER_IP = re.compile(r'^P2P\.(incoming|outgoing)\.(\[[^\]]+\]|[^:]+):(\d+)$')

# Thresholds of the ANOMALY tests (each stated on the page with its reason)
CLOCK_FUTURE_MS = 50          # blockchain/blockchain.go: a block more than 50 ms in our future is rejected
FIRST_RELAY_CONC = 0.50       # one peer delivering more than half of all first relays: topology dependence
NETGROUP_SHARE = 0.25         # one /16 holding more than a quarter of the active peers: eclipse-risk indicator
MIN_NETGROUPS = 4             # fewer distinct /16s than this among the active peers: eclipse-risk indicator
REMOTE_UNSERVED_MULT = 5.0    # a peer with > 5x the median per-peer 'could not serve' count (and >= 20 lines)
CHAIN_REQ_PER_MIN = 6.0       # r25 (D13): served Chain requests per connected minute above this (one per 10 s) is unusual:
                              # a peer asks for our chain only when it is behind (one request covers up to 512 blocks)
RTT_DIVERGE = 1.5             # r30 (B201 D11): RTTs of one identity's addresses within x1.5 = one host; beyond = UNEXPLAINED
PRIOR_CAPTURES = 6            # r30 (B201 D2): earlier captures read for each lagging peer's height trajectory
REASON_RX = re.compile(r'^[a-z0-9_]{1,40}$')        # r25: an offence reason or ban source is rendered only when it is a plain token

# Every detector names the code line its rule lives on; the line is re-found at run time (no line, no verdict).
RULES = {
    'v2_remnant': ('p2p/common.go', 'if common.Height >= globals.Config.MAJOR_HF3_HEIGHT+config.STABLE_LIMIT && common.Top_Version < 3 {'),
    'v2_ban': ('p2p/penalty.go', 'const V2_BAN_BASE = 3600'),
    'lagging': ('p2p/metrics_preregister.go', 'const LAGGING_PEER_BLOCKS = 25'),
    'stuck_evict': ('p2p/stuck_peer.go', 'v.c.logger.V(1).Info("evicting stuck peer", "peer_height", v.height, "our_height", our, "hold", until.Sub(now).String())'),
    'short_answer': ('p2p/sync_pipeline.go', 'return fetched, short_answer_error{got: len(r.resp.CBlocks), want: len(p.ids)} // r25: typed (peer_observe.go), same text'),
    'remote_unserved': ('p2p/object_errors.go', 'logger.V(1).Info(msg+": peer could not serve the object", append([]interface{}{"peer_error", err.Error()}, keysAndValues...)...)'),
    'clock_future': ('blockchain/blockchain.go', 'if bl.Timestamp > (uint64(globals.Time().UTC().UnixMilli() + 50)) { // give 50 millisec passing'),
    'penalty_ban': ('p2p/penalty.go', 'c.logger.Info("peer banned for misbehaviour", "ip", ip, "last_reason", reason, "seconds", secs)'),
    'netgroup_cap': ('p2p/diversity.go', 'const MAX_OUTBOUND_PER_NETGROUP = 2 // outgoing connections per IPv4 /16 or IPv6 /32'),
    'inv_budget': ('p2p/inv_budget.go', 'var inv_txids_over_budget = metrics.Set.NewCounter("p2p_inv_txids_over_budget_total")'),
    'first_relay': ('p2p/first_relay.go', 's.Builders[hex.EncodeToString(integrator[:8])]++'),
    'chunk_tip': ('p2p/chunk_server.go', 'chunk dropped: block builds on a tip we do not have'),
    'chain_request': ('p2p/rpc_chain_request.go', 'func (c *Connection) Chain(request Chain_Request_Struct, response *Chain_Response_Struct) error {'),
    'peer_info': ('p2p/peer_info.go', 'ClockOffsetMs   float64 `json:"clock_offset_ms"`'),
    # r27: D11's rule is the handshake peer_id GetPeerInfo reports, not the clock field D6 reads (r24-r26 anchored both
    # on the clock line)
    'peer_id': ('p2p/peer_info.go', 'PeerID          string  `json:"peer_id"`'),
    'call_timeout': ('p2p/call.go', 'metrics.Set.GetOrCreateCounter(fmt.Sprintf(`p2p_call_timeouts_total{method="%s"}`, method)).Inc()'),
    'fingerprint': ('cmd/derod/rpc/rpc_dero_explorer.go', 'const HF3_V3_HASH = "e454090e983a3437e9b8ad4f1a45e4dbf46849832cccb3cc2b7841b94fb464d5"'),
    # r25 (peers): the counters and GetPeerInfo fields of CO24-N1..N7 and B47 (p2p/peer_observe.go); a detector reads
    # them instead of log lines when the capture carries them (evidence 'counter'), else it falls back to the log
    'ctr_unserved': ('p2p/peer_observe.go', 'c.obs.objects_unserved.Add(1)'),
    'ctr_short': ('p2p/peer_observe.go', 'c.obs.short_answers.Add(1)'),
    'ctr_offence': ('p2p/penalty.go', 'm.note(reason, now) // r25 (CO24-N1)'),
    'ctr_chain': ('p2p/peer_observe.go', 'chain_requests_served.Inc()'),
    'ctr_inv_clip': ('p2p/inv_budget.go', 'c.obs.inv_clipped.Add(uint64(len(list) - n)) // r25 (CO24-N5): attributable to this connection'),
    'ctr_ban_source': ('p2p/bans.go', 'ban_meta[address] = ban_info{Source: source, Reason: trim64(reason), At: time.Now().Unix()} // r25'),
    'ctr_stuck_list': ('p2p/peer_observe.go', 'func StuckHolds(now time.Time) (out []StuckHold) {'),
    'sync_hold': ('p2p/peer_observe.go', 'c.obs.sync_hold_until.Store(now.Add(d).UnixNano())'),
}
R25_PEER_FIELDS = ('penalty_score', 'objects_unserved', 'short_answers', 'chain_requests_served', 'inv_txids_clipped')
HF3_HEIGHT = 7504640          # config/config.go MAJOR_HF3_HEIGHT (mainnet)
STABLE_LIMIT = 8              # config/config.go STABLE_LIMIT
LAGGING = 25                  # p2p/metrics_preregister.go LAGGING_PEER_BLOCKS

# log message -> kind (P2P loggers only)
LOG_KINDS = (
    ('dropping peer on pre-HF3 (v2) chain', 'v2_drop'),
    ('evicting stuck peer', 'stuck_evict'),
    ('peer could not serve the object', 'remote_unserved'),
    ('connection closed during the call', 'closed_call'),
    ('peer banned for misbehaviour', 'penalty_ban'),
    ('inbound sessions from this address block refused', 'aggregate_refuse'),
    ('Purging connection due to ban list', 'ban_purge'),
    ('Purging connection due since idle', 'idle_purge'),
    ('We need to resync with the peer', 'resync'),
    ('chunk dropped: block builds on a tip we do not have', 'chunk_unknown_tip'),
    ('backing off from this connection', 'backoff'),
)
LOG_NUMS = ('height', 'our_height', 'peer_height', 'peer_top_version', 'ban_seconds', 'seconds', 'pruned')
PAGE_RAW_KEYS = ('triage', 'logbridge', 'intel', 'runtime', 'forensics', 'localdiff', 'consts')   # r24: raw files G27 scans whole
LOGX_PER_KEY = 4              # evidence lines kept per (kind, peer): the first two and the last two


# ───────────────────────────── private material ─────────────────────────────
def private_dir(p=None):
    d = Path(p) if p else PRIVATE
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def load_salt(priv):
    f = Path(priv) / 'salt'
    if not f.exists():
        f.write_text(secrets.token_hex(32) + '\n')
        os.chmod(f, 0o600)
    return f.read_text().strip()


def load_self(priv):
    """{'builder8': 16 hex of THIS node's integrator key} from the private self.json (absent: nobody is 'this-node')."""
    try:
        return json.loads((Path(priv) / 'self.json').read_text())
    except (OSError, ValueError):
        return {}


class Pseud:
    def __init__(self, salt, self_builder=None):
        self.salt, self.self_builder = salt, (self_builder or '').lower()

    def h(self, kind, value):
        return hashlib.blake2b(f'{self.salt}|{kind}|{value}'.encode(), digest_size=16).hexdigest()[:8]

    def peer(self, ip):
        return 'peer-' + self.h('ip', host_of(ip))

    def node(self, peer_id):
        return 'node-' + self.h('id', str(peer_id))

    def builder(self, key8):
        k = str(key8).lower()
        return 'this-node' if self.self_builder and k == self.self_builder else 'miner-' + self.h('builder', k)

    def entry(self, s):
        return 'ban-' + self.h('ban', s)


def host_of(addr):
    """the host part of 'ip', 'ip:port', '[v6]:port'; a CIDR is kept whole."""
    a = str(addr or '').strip()
    if a.startswith('['):
        return a[1:a.index(']')] if ']' in a else a
    if a.count(':') == 1:
        return a.split(':')[0]
    return a


def ip_class(ip):
    try:
        x = ipaddress.ip_address(host_of(ip))
    except ValueError:
        return 'cidr' if '/' in str(ip) else 'unknown'
    if x.is_loopback:
        return 'loopback'
    if x.is_private or x.is_link_local:
        return 'private'
    return 'public'


def netgroup(ip):
    """IPv4 /16 or IPv6 /32 (p2p/diversity.go netgroup), computed privately."""
    try:
        x = ipaddress.ip_address(host_of(ip))
    except ValueError:
        return None
    n = 16 if x.version == 4 else 32
    return str(ipaddress.ip_network(f'{x}/{n}', strict=False))


# ───────────────────────────── capture (read-only) ─────────────────────────────
def rpc(method, url=RPC, timeout=10):
    req = urllib.request.Request(url, data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': f'DERO.{method}'}).encode(),
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def capture_live(priv, url=RPC, metrics=METRICS, datadir=None, sleep=time.sleep):
    """one private capture: three RPC reads a second apart, one /metrics GET, copies of the four datadir files."""
    ts = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    d = Path(priv) / 'raw' / ts
    d.mkdir(parents=True, exist_ok=True)
    for x in (d.parent, d):                                 # r24 (verify): raw dirs were created 755 under the 700 root
        os.chmod(x, 0o700)
    for m in RPC_METHODS:
        (d / f'{m}.json').write_text(json.dumps(rpc(m, url), indent=1))
        sleep(1.0)
    with urllib.request.urlopen(metrics, timeout=10) as r:
        (d / 'metrics.txt').write_bytes(r.read())
    dd = Path(datadir or (Path.home() / 'dero-data' / 'mainnet'))
    for f in DATADIR_FILES:
        if (dd / f).exists():
            shutil.copyfile(dd / f, d / f)                  # read the original, write only the private copy
    for f in d.iterdir():
        os.chmod(f, 0o600)
    return d


def load_capture(d):
    d = Path(d)
    cap = {}
    for m in RPC_METHODS:
        try:
            j = json.loads((d / f'{m}.json').read_text())
            cap[m] = j.get('result', j)
        except (OSError, ValueError):
            cap[m] = None
    try:
        cap['metrics'] = (d / 'metrics.txt').read_text(errors='replace')
    except OSError:
        cap['metrics'] = ''
    for f in DATADIR_FILES:
        try:
            cap[f] = json.loads((d / f).read_text())
        except (OSError, ValueError):
            cap[f] = None
    cap['_dir'] = d.name
    return cap


PROM = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{([^}]*)\})?\s+(\S+)')
LABEL = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')


def parse_prom(text):
    out = []
    for l in (text or '').splitlines():
        m = PROM.match(l)
        if not m or not m.group(1).startswith(('p2p_', 'KCP_', 'dero_peer', 'dero_sync')):
            continue
        try:
            v = float(m.group(4))
        except ValueError:
            continue
        out.append((m.group(1), dict(LABEL.findall(m.group(3) or '')), v))
    return out


# ───────────────────────────── log ─────────────────────────────
def log_files(explicit=None):
    if explicit:
        return [Path(p) for p in explicit]
    d = Path.home() / 'dero-data' / 'logs'
    return sorted(d.glob('derod*.log*'), key=lambda p: p.stat().st_mtime) if d.exists() else []


def log_ip(d):
    m = LOGGER_IP.match(str(d.get('N', '')))
    if m:
        return host_of(m.group(2)), m.group(1)
    for k in ('ip', 'peer'):
        v = d.get(k)
        if isinstance(v, str) and (IPV4.search(v) or ':' in v):
            return host_of(v), None
    return None, None


def scan_log(paths, ps):
    """{runs, current_start_line, events: {(kind, peer): {...}}, logx: [lines]} over the P2P lines of the log files.
    The current run starts at the last daemon banner ('alpha version'); counts are kept for the whole file and for
    the current run."""
    events, starts, short = {}, [], []
    recs = 0
    for p in paths:
        try:
            fh = open(p, errors='replace')
        except OSError:
            continue
        with fh:
            for i, l in enumerate(fh, 1):
                if '"P2P' not in l and 'alpha version' not in l:           # cheap pre-filter; the JSON decides
                    continue
                try:
                    d = json.loads(l)
                except ValueError:
                    continue
                recs += 1
                if 'alpha version' in str(d.get('M', '')):
                    starts.append((p.name, i, d.get('T')))
                    continue
                if not str(d.get('N', '')).startswith('P2P'):
                    continue
                msg = str(d.get('M', ''))
                kind = next((k for t, k in LOG_KINDS if t in msg), None)
                if kind is None and msg == 'Call failed GetObject' and 'peer answered' in str(d.get('error', '')):
                    kind = 'short_answer'
                if kind is None:
                    continue
                ip, direction = log_ip(d)
                if not ip:
                    continue
                peer = ps.peer(ip)
                nums = {k: d[k] for k in LOG_NUMS if isinstance(d.get(k), (int, float))}
                if kind == 'short_answer':
                    m = re.search(r'peer answered (\d+) blocks for (\d+) requested', str(d.get('error')))
                    if m:
                        nums['answered'], nums['requested'] = int(m.group(1)), int(m.group(2))
                if kind == 'penalty_ban' and isinstance(d.get('last_reason'), str) and re.fullmatch(r'[a-z_]{1,32}', d['last_reason']):
                    nums['reason'] = d['last_reason']
                if isinstance(d.get('hold'), str) and re.fullmatch(r'[0-9hms.]{1,16}', d['hold']):
                    nums['hold'] = d['hold']
                e = events.setdefault((kind, peer), {'n': 0, 'lines': [], 'last': None, 'ipc': ip_class(ip), 'at': []})
                e['n'] += 1
                e['at'].append((p.name, i))
                rec = {'file': p.name, 'line': i, 'kind': kind, 'peer': peer, 'T': d.get('T'), 'L': d.get('L'), 'C': d.get('C'),
                       'dir': direction, **nums}
                if len(e['lines']) < LOGX_PER_KEY // 2:
                    e['lines'].append(rec)
                e['last'] = rec
    cur = starts[-1] if starts else None
    return {'records': recs, 'runs': len(starts), 'current_start': cur, 'events': events}


def in_current(rec, cur):
    return cur is None or (rec['file'] == cur[0] and rec['line'] >= cur[1])


# ───────────────────────────── analysis ─────────────────────────────
def rule_anchors(root):
    out = {}
    for k, (f, q) in RULES.items():
        try:
            lines = (Path(root) / f).read_text(errors='replace').splitlines()
        except OSError:
            out[k] = {'file': f, 'quote': q, 'line': None, 'status': 'NOFILE'}
            continue
        hits = [i + 1 for i, l in enumerate(lines) if q in l]
        out[k] = {'file': f, 'quote': q, 'line': hits[0] if hits else None, 'status': 'OK' if hits else 'MISSING'}
    return out


def wilson_lo(k, n, z=1.959964):
    """r30 (B201 D9): the Wilson 95 % lower bound of k/n (None when n is 0). Pure."""
    if not n:
        return None
    ph = k / n
    d = 1 + z * z / n
    c = ph + z * z / (2 * n)
    r = z * (ph * (1 - ph) / n + z * z / (4 * n * n)) ** 0.5
    return (c - r) / d


def inbound_regime(incoming):
    """r30 (B201): the inbound regime that keys the peer KPI series: 'inbound' (> 0 incoming peers), 'outbound-only'
    (0), None (unknown). Pure."""
    if not isinstance(incoming, (int, float)):
        return None
    return 'inbound' if incoming > 0 else 'outbound-only'


def lag_kpis(peers):
    """r30 (B201): (lag_max, lag_median, lag_max_v2): the lags of peers on top_version >= 3, and apart the largest lag of
    a v2-remnant peer (top_version < 3), which D1/D13/v2_seen_7d already count. Pure."""
    v3 = [p['lag'] for p in peers if isinstance(p.get('lag'), int) and (p.get('top_version') or 0) >= 3]
    v2 = [p['lag'] for p in peers if isinstance(p.get('lag'), int) and (p.get('top_version') or 0) <= 2]
    return (max(v3) if v3 else None, statistics.median(v3) if v3 else None, max(v2) if v2 else None)


def trajectory(points):
    """r30 (B201 D2): the class of one peer's height over captures [(captured, height, connected_s)], oldest first:
    REGRESSED (a height fell between two captures: a re-sync from a lower point), SYNCING (the last height is above the
    first), STUCK (the same height in >= 2 captures), ONE-READING (only one capture). Pure."""
    hs = [h for _, h, _ in points if isinstance(h, int)]
    if len(hs) < 2:
        return 'ONE-READING'
    if any(b < a for a, b in zip(hs, hs[1:])):
        return 'REGRESSED'
    if hs[-1] > hs[0]:
        return 'SYNCING'
    return 'STUCK'


def nearest_wall(height, walls):
    """r30 (B201 D2): (wall name, wall height, distance) of the replay wall nearest below `height`, None when none is
    below; walls = [(name, height, radius)]. Pure."""
    below = [(n, h, r) for n, h, r in walls or () if isinstance(h, int) and h <= height]
    if not below:
        return None
    n, h, r = max(below, key=lambda w: w[1])
    return {'wall': n, 'height': h, 'distance': height - h, 'at_wall': height - h <= r}


def load_walls(root=ROOT):
    """[(name, centre height, radius)] of the newest forensics/<v>/derived/walls.json, plus its path; ([], None) when
    there is none."""
    cands = sorted(Path(root).glob('forensics/*/derived/walls.json'), key=lambda p: p.stat().st_mtime)
    if not cands:
        return [], None
    try:
        d = json.loads(cands[-1].read_text())
    except (OSError, ValueError):
        return [], None
    out = []
    for k, v in d.items():
        if isinstance(v, dict) and v.get('rows'):
            hs = sorted(r['height'] for r in v['rows'] if isinstance(r.get('height'), int))
            if hs:
                out.append((k, hs[len(hs) // 2], int(v.get('radius') or 0)))
    return out, str(cands[-1].relative_to(root))


def load_prior(out_dir, exclude=None, n=PRIOR_CAPTURES):
    """r30 (B201 D2/D9): the newest `n` earlier peer captures as [{'file', 'captured', 'peers': {pseudonym: (height,
    connected_s, line)}, 'fr_top_share'}], oldest first. Captures are immutable once written (peer_intel.json is
    rewritten every run), so every cited height has a fixed file:line."""
    files = sorted(Path(out_dir).glob('peer_capture_*.jsonl'))
    files = [f for f in files if f.name != exclude][-n:]
    out = []
    for f in files:
        rec = {'file': f.name, 'captured': None, 'peers': {}, 'fr_top_share': None}
        try:
            for i, l in enumerate(f.read_text().splitlines(), 1):
                o = json.loads(l)
                if o.get('src') == 'capture':
                    rec['captured'] = o.get('captured')
                elif o.get('src') == 'GetPeerInfo':
                    rec['peers'][o.get('peer')] = (o.get('height'), o.get('connected_s'), i)
                elif o.get('src') == 'kpis':
                    rec['fr_top_share'] = o.get('first_relay_top_share')
        except (OSError, ValueError):
            continue
        out.append(rec)
    return out


def explain_d2(D, peers, prior, walls=(), walls_file=None, cap_file=None):
    """r30 (B201): each D2 lagging peer classed SYNCING / STUCK / REGRESSED from its height in the earlier captures and
    this one, with the replay wall nearest below its height. Never changes the grade. Pure."""
    d2 = next((d for d in D if d['id'] == 'D2'), None)
    if not d2:
        return
    row = {p['peer']: p for p in peers}
    counts = {}
    for f in d2.get('findings') or []:
        p = row.get(f.get('peer'))
        if not p or not isinstance(p.get('lag'), int) or p['lag'] <= 0:
            continue
        pts = [(c['captured'], c['peers'][p['peer']][0], c['peers'][p['peer']][1]) for c in prior or () if p['peer'] in c['peers']]
        cites = [f"{c['file']}:{c['peers'][p['peer']][2]}" for c in prior or () if p['peer'] in c['peers']]
        pts.append((None, p.get('height'), p.get('connected_s')))
        cls = trajectory(pts)
        counts[cls] = counts.get(cls, 0) + 1
        hs = [h for _, h, _ in pts]
        cs = [c for _, _, c in pts]
        x = {'peer': p['peer'], 'class': cls, 'heights': hs, 'top_version': p.get('top_version'),
             'reconnected': any(isinstance(a, int) and isinstance(b, int) and b < a for a, b in zip(cs, cs[1:])),
             'below_hf3': isinstance(p.get('height'), int) and p['height'] < HF3_HEIGHT,
             'wall': nearest_wall(p['height'], walls) if isinstance(p.get('height'), int) else None,
             'cites': cites + ([f"{cap_file}:{p['line']}"] if cap_file else [f"line {p['line']}"])}
        x['what'] = (f"{cls}: height {' -> '.join(str(h) for h in hs)} over {len(hs)} capture(s), top_version {x['top_version']}"
                     + ('; reconnected between captures' if x['reconnected'] else '')
                     + (f"; {x['wall']['distance']} blocks above {x['wall']['wall']} ({x['wall']['height']})"
                        + (' (AT the wall)' if x['wall']['at_wall'] else '') if x['wall'] else '')
                     + ('; below HF3: a pre-HF3 store' if x['below_hf3'] else ''))
        d2.setdefault('explain', []).append(x)
    d2['classes'] = counts
    if walls_file:
        d2['walls_file'] = walls_file


def explain_d9(D, prior):
    """r30 (B201 D9): the top first-relay share of each earlier capture next to this one (the share is a position of
    the peer in the topology; its stability over captures is the reading). Pure."""
    d9 = next((d for d in D if d['id'] == 'D9'), None)
    if not d9:
        return
    d9['share_series'] = [{'file': c['file'], 'top_share': c['fr_top_share']} for c in prior or () if c.get('fr_top_share') is not None]


def explain_detectors(D, peers, ips_active, fr_metric=None):
    """r27 (§7, peer observatory): an 'explain' list on D5, D9 and D11 that puts each flagged peer next to the facts of
    the same capture that bear on it (latency rank, connection age, first-relay share, unserved per first relay,
    whether a D11 pair shares one /16 and one version). Explanations never change a grade; every number cites the
    capture line it comes from. The /16 comparison is computed on the private addresses and only a boolean is written."""
    by = {d['id']: d for d in D}
    fr = {k: v for k, v in (fr_metric or {}).items()}            # pseudonym -> (p2p_first_relay_total this run, line)
    row = {p['peer']: p for p in peers}
    lat = sorted((p['latency_ms'], p['peer']) for p in peers if isinstance(p.get('latency_ms'), (int, float)))
    rank = {pid: i + 1 for i, (_, pid) in enumerate(lat)}
    med_lat = statistics.median([x for x, _ in lat]) if lat else None
    d9 = by.get('D9') or {}
    top = next((f for f in d9.get('findings') or [] if f.get('grade') in ('ANOMALY', 'NORMAL') and f.get('peer') in row), None)
    d5_peers = {f['peer'] for f in (by.get('D5') or {}).get('findings') or [] if f.get('grade') == 'ANOMALY'}
    if top:
        p = row[top['peer']]
        fastest = lat[0][1] if lat else None
        x = {'peer': top['peer'], 'latency_ms': p.get('latency_ms'), 'latency_rank': rank.get(top['peer']), 'peers': len(lat),
             'latency_median_ms': med_lat, 'connected_s': p.get('connected_s'), 'also_d5': top['peer'] in d5_peers,
             'fastest_peer': fastest, 'fastest_first_relays': (fr.get(fastest) or (None,))[0] if fastest else None,
             'cap_line': p['line']}
        x['what'] = (f"the top first-relay peer is RTT rank {x['latency_rank']} of {x['peers']} ({x['latency_ms']} ms; median "
                     f"{med_lat:.1f} ms), connected {x['connected_s']} s; the RTT rank-1 peer delivered "
                     f"{'n/a' if x['fastest_first_relays'] is None else format(x['fastest_first_relays'], 'g')} first relays this run: "
                     f"a first relay goes to whoever forwards a new block first, so the share measures this peer's position "
                     f"(its own peers and miners), not a fault of ours or its" + ("; it is also D5's peer" if x['also_d5'] else ''))
        d9.setdefault('explain', []).append(x)
    d5 = by.get('D5') or {}
    tot = d9.get('total') or 0
    for f in d5.get('findings') or []:
        p = row.get(f.get('peer'))
        if not p:
            continue
        n_fr = (fr.get(f['peer']) or (None,))[0]
        x = {'peer': f['peer'], 'objects_unserved': p.get('objects_unserved'), 'first_relays_run': n_fr,
             'is_d9_top': bool(top and top['peer'] == f['peer']), 'cap_line': p['line']}
        if isinstance(p.get('objects_unserved'), int) and n_fr:
            x['unserved_per_first_relay'] = round(p['objects_unserved'] / n_fr, 4)
        x['what'] = (f"{x['objects_unserved']} unserved GetObject call(s) on this connection against {'n/a' if n_fr is None else format(n_fr, 'g')} first relays from it this run"
                     + (f" ({x['unserved_per_first_relay']:.2%})" if 'unserved_per_first_relay' in x else '')
                     + ("; it is D9's top relay, and a fetch goes back to the connection that announced (NotifyINV calls "
                        "GetObject on it, p2p/rpc_notifications.go), so it is asked most: 'the only peer with any' measures exposure as "
                        "much as fault" if x['is_d9_top'] else ''))
        if f['peer'] not in {e['peer'] for e in d5.get('explain') or []}:
            d5.setdefault('explain', []).append(x)
    d11 = by.get('D11') or {}
    for f in d11.get('findings') or []:
        pids = [x.strip() for x in str(f.get('peer', '')).split(',') if x.strip() in row]
        if len(pids) < 2:
            continue
        groups = {netgroup(ips_active.get(pid)) for pid in pids}
        vers = {row[pid].get('version') for pid in pids}
        x = {'peers': pids, 'same_netgroup': len(groups) == 1 and None not in groups, 'same_version': len(vers) == 1,
             'latency_ms': [row[pid].get('latency_ms') for pid in pids], 'connected_s': [row[pid].get('connected_s') for pid in pids],
             'heights': [row[pid].get('height') for pid in pids], 'cap_lines': [row[pid]['line'] for pid in pids],
             'dirs': [row[pid].get('dir') for pid in pids]}
        n_out = sum(1 for d_ in x['dirs'] if d_ == 'out')
        n_in = sum(1 for d_ in x['dirs'] if d_ == 'in')
        slots = ' and '.join(s for s in (f"{n_out} of our outgoing slot{'s' if n_out > 1 else ''}" if n_out else '',
                                         f"{n_in} inbound connection{'s' if n_in > 1 else ''}" if n_in else '') if s) \
            or f'{len(pids)} connections (direction unknown)'
        x['what'] = (f"{len(pids)} addresses, {'one /16' if x['same_netgroup'] else 'different /16s'}, "
                     f"{'one version' if x['same_version'] else 'different versions'}, RTT {x['latency_ms']} ms, connected {x['connected_s']} s, "
                     f"heights {x['heights']}: one identity reachable on several addresses ({f.get('verdict', 'not graded')}: "
                     f"{'RTTs agree, one multi-homed host' if f.get('verdict') == 'EXPLAINED' else 'not shown to be one host'}); "
                     f"{'its addresses add ' + str(len(groups) - 1) + ' extra /16 to D8 though they are one node' if not x['same_netgroup'] else 'D8 sees one /16'}"
                     f", and it holds {slots}")      # r30 fix D2: counted by dir (an inbound address is not one of our slots)
        d11.setdefault('explain', []).append(x)


def version_class(v):
    v = str(v or '')
    if not VERSION_RX.match(v):
        return 'custom'
    return 'current' if CURRENT_VERSION_RX.match(v) else 'outdated'


def render_version(v):
    """a version string is rendered only when it is a plain release string; anything else could carry a name."""
    return v if VERSION_RX.match(str(v or '')) else 'custom (not shown)'


def num(x, nd=3):
    return round(float(x), nd) if isinstance(x, (int, float)) else None


class Out:
    """the capture file as it is written: every fact line knows its own 1-based line number."""
    def __init__(self):
        self.lines = []

    def add(self, obj):
        self.lines.append(json.dumps(obj, ensure_ascii=False, sort_keys=False))
        return len(self.lines)


def analyse(cap, logscan, ps, root=ROOT, ts=None, prev=None, prior=None, walls=None, walls_file=None, cap_file=None):
    """(report, capture_lines, logx_lines). Pure: everything it reads is passed in."""
    ts = ts or datetime.datetime.now().astimezone().isoformat(timespec='seconds')
    ra = rule_anchors(root)
    C, X = Out(), Out()
    pi = cap.get('GetPeerInfo') or {}
    si = cap.get('GetSyncInfo') or {}
    gi = cap.get('GetInfo') or {}
    our_h = pi.get('our_height', si.get('height'))
    hdr = C.add({'src': 'capture', 'captured': ts, 'raw': cap.get('_dir'), 'node_version': si.get('version') or gi.get('version'),
                 'our_height': our_h, 'our_topoheight': pi.get('our_topoheight'), 'peers_listed': len(pi.get('peers') or []),
                 'incoming': pi.get('incoming'), 'outgoing': pi.get('outgoing'), 'v2_chain_peers_seen_7d': pi.get('v2_chain_peers_seen_7d')})
    sync_l = C.add({'src': 'GetSyncInfo', 'status': si.get('status'), 'lag_blocks': si.get('lag_blocks'),
                    'peer_median_height': si.get('peer_median_height'), 'tip_age_seconds': si.get('tip_age_seconds'),
                    'chain_fingerprint': si.get('chain_fingerprint'), 'p2p_bans_total': si.get('p2p_bans_total'),
                    'inbound_connections_since_start': si.get('inbound_connections_since_start'),
                    'peers_incoming': si.get('peers_incoming'), 'peers_outgoing': si.get('peers_outgoing'),
                    'uptime_seconds': si.get('uptime_seconds'), 'version': si.get('version')})
    # ── datadir copies, keyed by IP privately
    fr = ((cap.get('first_relay.json') or {}).get('peers') or {})
    v2o = cap.get('v2_offences.json') or {}
    bans = cap.get('ban_list.json') or {}
    pj = cap.get('peers.json') or {}
    now_s = time.time() if not cap.get('_now') else cap['_now']
    # ── active peers
    peers, ips_active, ids_seen = [], {}, {}
    for p in pi.get('peers') or []:
        ip = host_of(p.get('address'))
        pid = ps.peer(ip)
        ips_active[pid] = ip
        node = ps.node(p.get('peer_id')) if p.get('peer_id') else None
        if node:
            ids_seen.setdefault(node, set()).add(pid)
        f = fr.get(ip) or {}
        mb_t, mb_f = p.get('miniblocks_total') or 0, p.get('miniblocks_first') or 0
        row = {'src': 'GetPeerInfo', 'peer': pid, 'node': node, 'dir': 'in' if p.get('incoming') else 'out', 'ipclass': ip_class(ip),
               'height': p.get('height'), 'topoheight': p.get('topoheight'),
               'lag': (our_h - p['height']) if isinstance(our_h, int) and isinstance(p.get('height'), int) else None,
               'topo_lag': (pi.get('our_topoheight') - p['topoheight']) if isinstance(pi.get('our_topoheight'), int) and isinstance(p.get('topoheight'), int) else None,
               'top_version': p.get('top_version'), 'version': render_version(p.get('daemon_version')),
               'version_class': version_class(p.get('daemon_version')), 'latency_ms': num(p.get('latency_ms'), 1),
               'clock_offset_ms': num(p.get('clock_offset_ms'), 3), 'connected_s': p.get('connected_seconds'),
               'bytes_in': p.get('bytes_in'), 'bytes_out': p.get('bytes_out'), 'first_relays': p.get('first_relays'),
               'mb_first': mb_f, 'mb_total': mb_t, 'mb_first_share': round(mb_f / mb_t, 4) if mb_t else None,
               'relay_delay_ms': round(f['delay_sum_us'] / f['delay_n'] / 1000, 1) if f.get('delay_n') else None,
               'builders': len(f.get('builders') or {}), 'pruned': p.get('pruned'), 'has_tag': bool(p.get('tag'))}
        if all(k in p for k in R25_PEER_FIELDS):            # r25 build: the node's own per-connection counters
            row.update({'penalty_score': num(p.get('penalty_score'), 2), 'penalty_bans': p.get('penalty_bans'),
                        'penalty_events': p.get('penalty_events'),
                        'last_offences': [o.get('reason') for o in (p.get('last_offences') or []) if REASON_RX.match(str(o.get('reason', '')))],
                        'chain_requests_served': p.get('chain_requests_served'), 'chain_blocks_served': p.get('chain_blocks_served'),
                        'inv_txids_clipped': p.get('inv_txids_clipped'), 'objects_unserved': p.get('objects_unserved'),
                        'short_answers': p.get('short_answers'), 'sync_failures': p.get('sync_failures'),
                        'sync_hold_s': p.get('sync_hold_seconds')})
        row['line'] = C.add({k: v for k, v in row.items()})
        peers.append(row)
    # ── first relays (block builders that reached us first through each peer)
    builders, fr_rows = {}, []
    for ip, s in sorted(fr.items(), key=lambda kv: -(kv[1].get('firsts') or 0)):
        b = {ps.builder(k): v for k, v in sorted((s.get('builders') or {}).items(), key=lambda kv: -kv[1])}
        for k, v in b.items():
            builders[k] = builders.get(k, 0) + v
        fr_rows.append({'src': 'first_relay.json', 'peer': ps.peer(ip), 'firsts': s.get('firsts'),
                        'delay_mean_ms': round(s['delay_sum_us'] / s['delay_n'] / 1000, 1) if s.get('delay_n') else None,
                        'delay_n': s.get('delay_n'), 'builders': b, 'last_first': s.get('last_first'),
                        'connected': ps.peer(ip) in ips_active})
        fr_rows[-1]['line'] = C.add({k: v for k, v in fr_rows[-1].items()})
    bl_line = C.add({'src': 'first_relay.json', 'builders_total': dict(sorted(builders.items(), key=lambda kv: -kv[1]))})
    # ── v2 offences, bans, peer list
    v2_rows = []
    for ip, r in v2o.items():
        v2_rows.append({'src': 'v2_offences.json', 'peer': ps.peer(ip), 'n': r.get('n'), 'last': r.get('last'),
                        'connected': ps.peer(ip) in ips_active})
        v2_rows[-1]['line'] = C.add({k: v for k, v in v2_rows[-1].items()})
    ban_rows = []
    for k, until in bans.items():
        scope = 'cidr' if '/' in str(k) else 'ip'
        name = ps.entry(k) if scope == 'cidr' else ps.peer(k)
        ban_rows.append({'src': 'ban_list.json', 'entry': name, 'scope': scope + (('/' + str(k).split('/')[1]) if scope == 'cidr' else ''),
                         'until': until, 'remaining_s': int(until - now_s) if isinstance(until, (int, float)) else None,
                         'v2_offender': scope == 'ip' and k in v2o,
                         # r25 (CO24-N4): the ban's source from the ban_reasons.json sidecar (None on a pre-r25 node)
                         'source': next((x for x in [((cap.get('ban_reasons.json') or {}).get(k) or {}).get('source')] if x and REASON_RX.match(str(x))), None)})
        ban_rows[-1]['line'] = C.add({kk: vv for kk, vv in ban_rows[-1].items()})
    pl_rows = []
    for ip, r in pj.items():
        pl_rows.append({'src': 'peers.json', 'peer': ps.peer(ip), 'ipclass': ip_class(ip), 'goodcount': r.get('goodcount'),
                        'failcount': r.get('failcount'), 'whitelist': r.get('whitelist'), 'lastconnected': r.get('lastconnected'),
                        'connected': ps.peer(ip) in ips_active})
        pl_rows[-1]['line'] = C.add({k: v for k, v in pl_rows[-1].items()})
    # ── metrics (IP labels pseudonymised)
    prom = parse_prom(cap.get('metrics'))
    mt, mt_line, fr_metric = {}, {}, {}
    for name, labels, v in prom:
        lab = {k: (ps.peer(x) if k == 'peer' else x) for k, x in labels.items()}
        if any(IPV4.search(str(x)) for x in lab.values()):
            continue                                              # an unexpected IP-bearing label is never written
        key = name + ('{' + ','.join(f'{k}={lab[k]}' for k in sorted(lab)) + '}' if lab else '')
        if '_bucket' in name:
            continue
        ln = C.add({'src': 'metrics', 'name': name, 'labels': lab, 'value': v})
        mt[key], mt_line[key] = v, ln
        if name == 'p2p_first_relay_total' and 'peer' in lab:
            fr_metric[lab['peer']] = (v, ln)
    M = lambda k, d=None: mt.get(k, d)
    # r25: counter mode = the capture carries the CO24-N* fields (an r25+ derod); a detector then grades from them
    ctr = bool(peers) and all(k in (pi.get('peers') or [{}])[0] for k in R25_PEER_FIELDS)
    # r25 (CO24-N1/N4/N7): the node's own lists, pseudonymised as they are read
    def scope_name(k):
        return ps.entry(k) if '/' in str(k) else ps.peer(k)
    off_rows = []
    for o in pi.get('offenders') or []:
        off_rows.append({'src': 'GetPeerInfo.offenders', 'scope': scope_name(o.get('scope')), 'score': num(o.get('score'), 2),
                         'bans': o.get('bans'), 'events': o.get('events'), 'banned_for_s': o.get('banned_for_seconds'),
                         'reasons': [x.get('reason') for x in (o.get('last_offences') or []) if REASON_RX.match(str(x.get('reason', '')))]})
        off_rows[-1]['line'] = C.add(dict(off_rows[-1]))
    held_rows = []
    for h in pi.get('stuck_held') or []:
        held_rows.append({'src': 'GetPeerInfo.stuck_held', 'peer': ps.peer(h.get('address')), 'strikes': h.get('strikes'),
                          'held_s': h.get('held_seconds'), 'height': h.get('height')})
        held_rows[-1]['line'] = C.add(dict(held_rows[-1]))
    reasons = cap.get('ban_reasons.json') or {}
    bsrc = pi.get('ban_sources') if isinstance(pi.get('ban_sources'), dict) else None
    if bsrc is None and reasons:
        bsrc = {}
        for k in bans:
            sname = (reasons.get(k) or {}).get('source') or 'unattributed'
            bsrc[sname] = bsrc.get(sname, 0) + 1
    bsrc_line = C.add({'src': 'ban_sources', 'by_source': {k: v for k, v in (bsrc or {}).items() if REASON_RX.match(str(k))},
                       'ban_count': pi.get('ban_count', len(bans)) if bsrc is not None else None}) if bsrc is not None else None
    # ── log
    ev = logscan.get('events') or {}
    cur = logscan.get('current_start')
    per_kind = {}
    logx_line = {}
    for (kind, peer), e in sorted(ev.items()):
        recs = e['lines'] + ([e['last']] if e['last'] and e['last'] not in e['lines'] else [])
        lines = []
        for r in recs:
            lines.append(X.add(r))
        cur_n = sum(1 for f, l in e.get('at', []) if in_current({'file': f, 'line': l}, cur))
        per_kind.setdefault(kind, {})[peer] = {'n': e['n'], 'n_current': cur_n, 'logx_lines': lines,
                                               'first_T': recs[0]['T'] if recs else None,
                                               'last_T': e['last']['T'] if e['last'] else None, 'ipclass': e['ipc']}
        logx_line[(kind, peer)] = lines
    # ── detectors
    D = []

    def det(did, title, rule, grade_fn, test):
        a = ra.get(rule)
        d = {'id': did, 'title': title, 'rule': a, 'test': test, 'findings': []}
        if not a or a['status'] != 'OK':
            d['grade'] = 'pending'
            d['why'] = f"rule line not found in this tree ({a and a['file']})"
        else:
            grade_fn(d)
            g = {f['grade'] for f in d['findings']}
            d['grade'] = 'OBSERVED' if 'OBSERVED' in g else 'ANOMALY' if 'ANOMALY' in g else d.get('grade') or 'NORMAL'
        D.append(d)
        return d

    def f_v2(d):
        for r in v2_rows:
            lx = logx_line.get(('v2_drop', r['peer']), [])
            lg = (per_kind.get('v2_drop') or {}).get(r['peer'])
            d['findings'].append({'peer': r['peer'], 'grade': 'OBSERVED', 'what': f"dropped {r['n']}x for a v2-remnant chain (top_version < 3 past HF3+{STABLE_LIMIT}; v2_offences.json)" + (f"; {lg['n']} log lines, {lg['n_current']} in the current run" if lg else '') + f"; connected now: {r['connected']}",
                                  'cap_line': r['line'], 'logx_lines': lx})
        for p in peers:
            if isinstance(p.get('height'), int) and p['height'] >= HF3_HEIGHT + STABLE_LIMIT and (p.get('top_version') or 0) < 3:
                d['findings'].append({'peer': p['peer'], 'grade': 'OBSERVED', 'what': f"active peer reports top_version {p['top_version']} at height {p['height']}", 'cap_line': p['line']})
        for (k, peer), lx in logx_line.items():
            if k == 'v2_drop' and not any(f['peer'] == peer for f in d['findings']):
                d['findings'].append({'peer': peer, 'grade': 'OBSERVED', 'what': f"log: dropped {per_kind['v2_drop'][peer]['n']}x for a v2-remnant chain ({per_kind['v2_drop'][peer]['n_current']} in the current run)", 'logx_lines': lx})
    det('D1', 'Peers on the v2 remnant chain', 'v2_remnant', f_v2, f'rule: height >= HF3 ({HF3_HEIGHT}) + STABLE_LIMIT ({STABLE_LIMIT}) and top_version < 3 → dropped and banned (1 h, escalating)')

    def f_lag(d):
        for p in peers:
            if isinstance(p.get('lag'), int) and p['lag'] > LAGGING:
                d['findings'].append({'peer': p['peer'], 'grade': 'ANOMALY', 'what': f"{p['lag']} blocks behind us (> LAGGING_PEER_BLOCKS {LAGGING}): gets no relays", 'cap_line': p['line']})
            elif isinstance(p.get('lag'), int) and p['lag'] < -LAGGING:
                d['findings'].append({'peer': p['peer'], 'grade': 'ANOMALY', 'what': f"advertises {-p['lag']} blocks above our tip", 'cap_line': p['line']})
    det('D2', 'Lagging or over-advertising peers (live)', 'lagging', f_lag, f'test: |our height − peer height| > {LAGGING} (LAGGING_PEER_BLOCKS)')

    def f_stuck(d):
        for h in held_rows:                                      # r25 (CO24-N7): the node lists its holds itself
            d['evidence'] = 'counter'
            d['findings'].append({'peer': h['peer'], 'grade': 'OBSERVED', 'source': 'GetPeerInfo.stuck_held',
                                  'what': f"held after a stuck eviction: strike {h['strikes']}, {h['held_s']} s left, at height {h['height']}", 'cap_line': h['line']})
        for peer, e in (per_kind.get('stuck_evict') or {}).items():
            d['findings'].append({'peer': peer, 'grade': 'OBSERVED', 'what': f"evicted as stuck {e['n']}x in the log since {str(e['first_T'])[:10]} ({e['n_current']} in the current run; height not advancing while > {LAGGING} behind)", 'logx_lines': e['logx_lines']})
    det('D3', 'Stuck peers evicted (log)', 'stuck_evict', f_stuck, 'rule: a peer > LAGGING_PEER_BLOCKS behind whose height does not move for STUCK_PEER_WINDOW (10 min) is evicted and held')

    def f_short(d):
        if ctr:                                                  # r25 (CO24-N6): the counter, per connection
            d['evidence'] = 'counter'
            for p in peers:
                if p.get('short_answers'):
                    d['findings'].append({'peer': p['peer'], 'grade': 'OBSERVED', 'source': 'GetPeerInfo.short_answers',
                                          'what': f"answered {p['short_answers']} sync fetch(es) with fewer blocks than requested on this connection (short_answers)", 'cap_line': p['line']})
        for peer, e in (per_kind.get('short_answer') or {}).items():
            # r25: with the counter, a log line from before the current run is history, not this run's observation
            g = 'OBSERVED' if not ctr or e['n_current'] else 'NORMAL'
            d['findings'].append({'peer': peer, 'grade': g, 'source': 'log' if g == 'OBSERVED' else 'log-history', 'what': f"answered fewer blocks than requested {e['n']}x in the log since {str(e['first_T'])[:10]} ({e['n_current']} in the current run): announced a chain it then did not serve", 'logx_lines': e['logx_lines']})
    det('D4', "Peers advertising blocks they cannot serve ('answered 0 blocks for N requested')", 'short_answer', f_short, 'rule: a sync fetch whose reply carries fewer blocks than requested fails with this error')

    def f_unserved(d):
        u = per_kind.get('remote_unserved') or {}
        if ctr:                                                  # r25 (CO24-N6): the counter, per connection
            d['evidence'] = 'counter'
            cu = {p['peer']: p for p in peers if p.get('objects_unserved')}
            cmed = statistics.median([p['objects_unserved'] for p in cu.values()]) if len(cu) > 1 else None
            for peer, p in cu.items():
                n = p['objects_unserved']
                g = 'ANOMALY' if n >= 20 and (cmed is None or n > REMOTE_UNSERVED_MULT * max(cmed, 1)) else 'NORMAL'
                d['findings'].append({'peer': peer, 'grade': g, 'source': 'GetPeerInfo.objects_unserved',
                                      'what': f"{n} GetObject call(s) answered with its own error on this connection ({len(cu)} peer(s) with any, median {'n/a' if cmed is None else f'{cmed:g}'}; ANOMALY if >= 20 and > {REMOTE_UNSERVED_MULT:g}x the median, or the only one)", 'cap_line': p['line']})
            # the log stays the history; its pre-run lines are not graded again
            u = {k: e for k, e in u.items() if e['n_current']}
        if not u:
            return
        # r27: with the counter, the log's lines from BEFORE the current run are history (the D4 rule since r25, PI15):
        # the grade reads the current run's count; r24-r26 graded the whole log since 2026-10-22 here, so 251 old
        # lines kept one peer ANOMALY while its counter read 4
        key = 'n_current' if ctr else 'n'
        med = statistics.median([e[key] for e in u.values()]) if len(u) > 1 else None
        for peer, e in u.items():
            g = 'ANOMALY' if e[key] >= 20 and (med is None or e[key] > REMOTE_UNSERVED_MULT * max(med, 1)) else 'NORMAL'
            d['findings'].append({'peer': peer, 'grade': g, 'source': 'log-history' if ctr else 'log', 'graded_on': key, 'what': f"{e['n']} 'could not serve the object' replies in the log since {str(e['first_T'])[:10]} ({e['n_current']} in the current run; graded on {'the current run' if ctr else 'the whole log'}; {len(u)} peer(s) with any, median {'n/a' if med is None else f'{med:g}'}; ANOMALY if >= 20 and > {REMOTE_UNSERVED_MULT:g}x the median, or the only one)", 'logx_lines': e['logx_lines']})
    det('D5', 'Objects a peer announced but could not serve (remote errors)', 'remote_unserved', f_unserved, f'test: >= 20 lines and > {REMOTE_UNSERVED_MULT:g}x the per-peer median')

    def f_clock(d):
        # r24 (verify): the NTP-style offset (p2p/time.go offset_micro, remote clock minus ours) is only known to within
        # +/- RTT/2 (path asymmetry), so a reading flags only when even its lower bound |offset| - latency_ms/2 is past
        # the 50 ms allowance; the r24 builder flagged -76.1 ms at 217.7 ms RTT, which is inside that uncertainty.
        for p in peers:
            o = p.get('clock_offset_ms')
            rtt = p.get('latency_ms') if isinstance(p.get('latency_ms'), (int, float)) else 0.0
            if isinstance(o, (int, float)) and abs(o) - rtt / 2 > CLOCK_FUTURE_MS:
                side = ('its clock is ahead of ours: blocks it stamps can be rejected here by the 50 ms future rule' if o > 0 else
                        'its clock is behind ours: blocks we stamp can be more than 50 ms in its future')
                # r25 (B72): one host has one clock. If the SAME node id reads within the bound through another address
                # of this capture, the two paths disagree: path asymmetry on this one, not a clock fault -> NORMAL
                others = [q for q in peers if q.get('node') and q['node'] == p.get('node') and q['peer'] != p['peer']
                          and isinstance(q.get('clock_offset_ms'), (int, float))]
                calm = [q for q in others if abs(q['clock_offset_ms']) - (q.get('latency_ms') or 0.0) / 2 <= CLOCK_FUTURE_MS]
                if calm:
                    q = calm[0]
                    d['findings'].append({'peer': p['peer'], 'grade': 'NORMAL', 'what': f"clock offset {o:+.1f} ms at {rtt:.1f} ms RTT on this path, but the same node ({p['node']}) reads {q['clock_offset_ms']:+.1f} ms at {q.get('latency_ms') or 0.0:.1f} ms RTT through {q['peer']}: a path-asymmetry candidate, not a clock fault (B72 cross-check)", 'cap_line': p['line'], 'cross_line': q['line']})
                    continue
                d['findings'].append({'peer': p['peer'], 'grade': 'ANOMALY', 'what': f"clock offset {o:+.1f} ms at {rtt:.1f} ms RTT (|offset| - RTT/2 = {abs(o) - rtt / 2:.1f} ms > {CLOCK_FUTURE_MS} ms; {side})" + (f"; the same node reads beyond the bound on all {len(others) + 1} of its addresses" if others else ''), 'cap_line': p['line']})
    det('D6', 'Clock skew of peers', 'clock_future', f_clock, f'test: |clock_offset_ms| - latency_ms/2 > {CLOCK_FUTURE_MS} (the consensus future-timestamp allowance, beyond the +/- RTT/2 measurement uncertainty of the offset), on every address of the same node id (r25, B72)')

    def f_pen(d):
        if ctr:                                                  # r25 (CO24-N1/N2/N4): the node's offence records
            d['evidence'] = 'counter'
            for p in peers:
                if p.get('penalty_events'):
                    d['findings'].append({'peer': p['peer'], 'grade': 'OBSERVED', 'source': 'GetPeerInfo.penalty_*',
                                          'what': f"{p['penalty_events']} offence(s) scored, score {p['penalty_score']} of 100, {p['penalty_bans']} ban(s); last: {', '.join(p['last_offences']) or 'n/a'}", 'cap_line': p['line']})
            for o in off_rows:
                if o['scope'] not in {f['peer'] for f in d['findings']}:
                    d['findings'].append({'peer': o['scope'], 'grade': 'OBSERVED', 'source': 'GetPeerInfo.offenders',
                                          'what': f"{o['events']} offence(s), score {o['score']}, {o['bans']} ban(s), {o['banned_for_s']} s of ban left; last: {', '.join(o['reasons']) or 'n/a'}", 'cap_line': o['line']})
            for key in sorted(k for k in mt if k.startswith(('p2p_penalty_events_total{', 'p2p_penalty_bans_by_reason_total{'))):
                if mt[key]:
                    d['findings'].append({'peer': '(node-wide)', 'grade': 'OBSERVED', 'source': 'metrics', 'what': f'{key} = {mt[key]:g}', 'cap_line': mt_line[key]})
            if bsrc_line:
                d['ban_sources_line'] = bsrc_line
        for peer, e in (per_kind.get('penalty_ban') or {}).items():
            d['findings'].append({'peer': peer, 'grade': 'OBSERVED', 'what': f"score-banned {e['n']}x for misbehaviour ({e['n_current']} in the current run)", 'logx_lines': e['logx_lines']})
        for key in ('p2p_penalty_bans_total', 'p2p_penalty_aggregate_bans_total', 'p2p_penalty_evictions_total'):
            if M(key):
                d['findings'].append({'peer': '(node-wide)', 'grade': 'OBSERVED', 'what': f'{key} = {M(key):g}', 'cap_line': mt_line[key]})
    det('D7', 'Misbehaviour bans (invalid PoW, malformed or undecodable frames, fetch timeouts)', 'penalty_ban', f_pen, 'rule: offences add score; 100 points bans the IP (penalty.go)')

    def f_net(d):
        groups = {}
        for pid, ip in ips_active.items():
            g = netgroup(ip)
            if g:
                groups.setdefault(g, []).append(pid)
        outs = {}
        for p in peers:
            if p['dir'] == 'out':
                g = netgroup(ips_active[p['peer']])
                outs.setdefault(g, []).append(p['peer'])
        n = len(ips_active)
        sizes = sorted((len(v) for v in groups.values()), reverse=True)
        d['diversity'] = {'peers': n, 'netgroups': len(groups), 'top_netgroup_peers': sizes[0] if sizes else 0,
                          'top_netgroup_share': round(sizes[0] / n, 4) if n else None, 'sizes': sizes}
        d['diversity']['line'] = C.add({'src': 'diversity', **{k: v for k, v in d['diversity'].items()}})
        for g, members in outs.items():
            if len(members) > 2:
                d['findings'].append({'peer': ', '.join(sorted(members)), 'grade': 'OBSERVED', 'what': f'{len(members)} outgoing peers share one /16 (cap MAX_OUTBOUND_PER_NETGROUP = 2)', 'cap_line': d['diversity']['line']})
        if n and (sizes[0] / n > NETGROUP_SHARE or len(groups) < MIN_NETGROUPS):
            d['findings'].append({'peer': '(peer set)', 'grade': 'ANOMALY', 'what': f"top /16 holds {sizes[0]}/{n} peers, {len(groups)} distinct /16s (ANOMALY if share > {NETGROUP_SHARE} or < {MIN_NETGROUPS} groups)", 'cap_line': d['diversity']['line']})
    det('D8', 'Eclipse-risk indicators: peer-set diversity by /16', 'netgroup_cap', f_net, f'test: no /16 above {NETGROUP_SHARE:.0%} of the active peers, >= {MIN_NETGROUPS} distinct /16s; OBSERVED if > 2 outgoing in one /16')

    def f_conc(d):
        tot = sum(v for v, _ in fr_metric.values())
        d['total'] = tot
        if not tot:
            return
        top = max(fr_metric.items(), key=lambda kv: kv[1][0])
        share = top[1][0] / tot
        lo = wilson_lo(top[1][0], tot)                        # r30 (B201): graded on the Wilson 95 % lower bound
        d['top_share'] = round(share, 4)
        d['top_share_lo95'] = round(lo, 4)
        d['findings'].append({'peer': top[0], 'grade': 'ANOMALY' if lo > FIRST_RELAY_CONC else 'NORMAL', 'lo95': round(lo, 4),
                              'what': f"delivered {top[1][0]:g} of {tot:g} first relays this run ({share:.1%}, Wilson 95 % lower bound {lo:.1%}; ANOMALY if the lower bound > {FIRST_RELAY_CONC:.0%}: one path carries most new blocks to us)", 'cap_line': top[1][1]})
    det('D9', 'First-relay concentration (topology dependence)', 'first_relay', f_conc, f'test: Wilson 95 % lower bound of one peer\'s share of p2p_first_relay_total > {FIRST_RELAY_CONC:.0%} (r30)')

    def f_inv(d):
        if ctr:                                                  # r25 (CO24-N5): which connection was clipped
            d['evidence'] = 'counter'
            for p in peers:
                if p.get('inv_txids_clipped'):
                    d['findings'].append({'peer': p['peer'], 'grade': 'OBSERVED', 'source': 'GetPeerInfo.inv_txids_clipped',
                                          'what': f"{p['inv_txids_clipped']} announced txid(s) beyond its INV budget on this connection", 'cap_line': p['line']})
        for key in ('p2p_inv_txids_over_budget_total', 'p2p_unrequested_txs_dropped_total', 'p2p_frame_budget_refusals_total'):
            if key in mt:
                d['findings'].append({'peer': '(node-wide)', 'grade': 'OBSERVED' if mt[key] > 0 else 'NORMAL', 'what': f'{key} = {mt[key]:g} (must stay 0 on honest traffic)', 'cap_line': mt_line[key]})
    det('D10', 'INV / transaction flood against the budgets', 'inv_budget', f_inv, 'rule: an INV beyond 64 txids/s (burst 1,024) per connection is clipped and counted')

    def f_ids(d):
        prow = {p['peer']: p for p in peers}
        for node, pids in ids_seen.items():
            if len(pids) > 1:
                rtt = sorted(prow[x]['latency_ms'] for x in pids if isinstance(prow.get(x, {}).get('latency_ms'), (int, float)))
                ratio = (rtt[-1] / rtt[0]) if len(rtt) >= 2 and rtt[0] > 0 else None
                verdict = 'EXPLAINED' if ratio is not None and ratio <= RTT_DIVERGE else 'UNEXPLAINED'   # r30 (B201)
                d['findings'].append({'peer': ', '.join(sorted(pids)), 'grade': 'NORMAL' if verdict == 'EXPLAINED' else 'ANOMALY',
                                      'verdict': verdict, 'rtt_ms': rtt, 'rtt_ratio': round(ratio, 2) if ratio else None,
                                      'what': f'one peer_id ({node}) on {len(pids)} addresses at once, RTT {rtt} ms: {verdict}'
                                              + (f' (RTTs within x{RTT_DIVERGE:g}: one multi-homed host)' if verdict == 'EXPLAINED' else
                                                 f' (RTT ratio {ratio:.2f} > {RTT_DIVERGE:g}: hosts at different network distances share one identity)' if ratio else ' (no RTT pair to compare)'),
                                      'cap_line': next(p['line'] for p in peers if p['peer'] in pids)})
    det('D11', 'One node identity on several addresses', 'peer_id', f_ids, f'test: the same handshake peer_id on > 1 active address; EXPLAINED (NORMAL) when their RTTs agree within x{RTT_DIVERGE:g}, else UNEXPLAINED (ANOMALY) (r30)')

    def f_chunk(d):
        for peer, e in (per_kind.get('chunk_unknown_tip') or {}).items():
            d['findings'].append({'peer': peer, 'grade': 'NORMAL', 'what': f"{e['n']} chunk(s) on a tip we did not have yet (a race at block arrival, dropped without penalty)", 'logx_lines': e['logx_lines']})
    det('D12', 'Chunks building on tips we do not have', 'chunk_tip', f_chunk, 'rule: such a chunk is dropped (not penalised); counted as information')

    def f_chain(d):
        if ctr:                                                  # r25 (CO24-N3): Chain requests are counted per connection
            d['evidence'] = 'counter'
            for p in peers:
                n, mins = p.get('chain_requests_served') or 0, max((p.get('connected_s') or 0) / 60.0, 1.0)
                if n:
                    g = 'ANOMALY' if n / mins > CHAIN_REQ_PER_MIN else 'NORMAL'
                    d['findings'].append({'peer': p['peer'], 'grade': g, 'source': 'GetPeerInfo.chain_requests_served',
                                          'what': f"{n} Chain request(s) served ({p.get('chain_blocks_served')} block ids) in {mins:.0f} min connected ({n / mins:.2f}/min; ANOMALY if > {CHAIN_REQ_PER_MIN:g}/min)", 'cap_line': p['line']})
            key = 'p2p_chain_requests_served_total'
            if key in mt:
                d['findings'].append({'peer': '(node-wide)', 'grade': 'NORMAL', 'source': 'metrics', 'what': f"{key} = {mt[key]:g}, blocks {M('p2p_chain_request_blocks_total', 0):g}, refused {M('p2p_chain_requests_refused_total', 0):g}", 'cap_line': mt_line[key]})
            return
        inc = pi.get('incoming') or 0
        d['findings'].append({'peer': '(node-wide)', 'grade': 'pending' if inc else 'NORMAL',
                              'what': (f'{inc} inbound peer(s) could send Chain requests, and no counter of served Chain requests exists (CO24-N3)' if inc else
                                       'no inbound connection: no peer can send us Chain requests (GetSyncInfo inbound unreachable)'), 'cap_line': sync_l})
    det('D13', 'Chain-request amplification (inbound)', 'chain_request', f_chain, f'test: served Chain requests per connected minute > {CHAIN_REQ_PER_MIN:g} on one connection (r25 counter, CO24-N3); before r25 it needed inbound peers and a counter')

    def f_ver(d):
        for p in peers:
            if p['version_class'] != 'current':
                d['findings'].append({'peer': p['peer'], 'grade': 'ANOMALY' if p['version_class'] == 'custom' else 'NORMAL',
                                      'what': f"version class {p['version_class']} ({p['version']})", 'cap_line': p['line']})
    det('D14', 'Version mix (outdated / custom builds)', 'fingerprint', f_ver, 'test: daemon_version is a plain release string; current = 3.6.0-153 (this tree); outdated is NORMAL (still on the v3 chain)')
    def f_hold(d):
        if not ctr:
            d['grade'] = 'pending'
            d['why'] = 'the capture carries no sync_failures field (a pre-r25 derod)'
            return
        d['evidence'] = 'counter'
        for p in peers:
            if p.get('sync_failures') or p.get('sync_hold_s'):
                d['findings'].append({'peer': p['peer'], 'grade': 'OBSERVED', 'source': 'GetPeerInfo.sync_failures',
                                      'what': f"{p['sync_failures']} consecutive failed sync(s) that were its own (error or short answer); sync with it held {p['sync_hold_s']} s more", 'cap_line': p['line']})
    det('D15', 'Sync held from peers that answer with nothing (B47)', 'sync_hold', f_hold, 'rule: a sync fetch the peer fails (its own error or fewer blocks than asked) holds sync with it 30 s, doubling to 10 min; a sync that adds blocks forgives (r25)')
    explain_detectors(D, peers, ips_active, fr_metric)          # r27: D5/D9/D11 explained from the same capture
    explain_d2(D, peers, prior, walls or (), walls_file, cap_file)   # r30 (B201): D2 trajectories over the captures
    explain_d9(D, prior)
    # ── churn and series
    act = sorted(p['peer'] for p in peers)
    churn = None
    if prev and isinstance(prev.get('active'), list):
        joined, left = sorted(set(act) - set(prev['active'])), sorted(set(prev['active']) - set(act))
        churn = {'since': prev.get('captured'), 'joined': len(joined), 'left': len(left), 'joined_peers': joined, 'left_peers': left}
    churn_line = C.add({'src': 'churn', 'churn': churn, 'active': act})
    # ── KPIs
    lag_max3, lag_med3, lag_max2 = lag_kpis(peers)               # r30 (B201): v3 peers only; v2 remnant apart
    lat = [p['latency_ms'] for p in peers if isinstance(p.get('latency_ms'), (int, float))]
    vc = {}
    for p in peers:
        vc[p['version_class']] = vc.get(p['version_class'], 0) + 1
    kpi = {'peers_active': len(peers), 'incoming': pi.get('incoming'), 'outgoing': pi.get('outgoing'),
           'lag_max': lag_max3, 'lag_median': lag_med3, 'lag_max_v2': lag_max2,
           'inbound_regime': inbound_regime(pi.get('incoming')),
           'latency_median_ms': round(statistics.median(lat), 1) if lat else None,
           'versions': vc, 'v2_seen_7d': pi.get('v2_chain_peers_seen_7d'), 'bans_listed': len(ban_rows),
           'first_relay_top_share': next((d.get('top_share') for d in D if d['id'] == 'D9'), None),
           'netgroups': next((d['diversity']['netgroups'] for d in D if d['id'] == 'D8' and 'diversity' in d), None),
           'builders_seen': len(builders), 'observed': sum(1 for d in D if d['grade'] == 'OBSERVED'),
           'anomaly': sum(1 for d in D if d['grade'] == 'ANOMALY'), 'pending': sum(1 for d in D if d['grade'] == 'pending'),
           'handshake_failures': M('p2p_handshake_failures_total'), 'stuck_evictions': M('p2p_stuck_peer_evictions_total'),
           'chain_fingerprint': si.get('chain_fingerprint'), 'sync_status': si.get('status'),
           'evidence_mode': 'counter' if ctr else 'log',                                  # r25: CO24-N* counters read
           'counter_detectors': sorted(d['id'] for d in D if d.get('evidence') == 'counter'),
           'ban_sources': (bsrc or None), 'offenders': len(off_rows), 'stuck_held': len(held_rows)}
    kpi_line = C.add({'src': 'kpis', **kpi})
    census = {'bans': ban_rows, 'offenders': off_rows, 'stuck_held': held_rows, 'v2_offences': v2_rows, 'peer_list': pl_rows, 'first_relay': fr_rows,
              'log_kinds': {k: {'peers': len(v), 'lines': sum(e['n'] for e in v.values())} for k, v in sorted(per_kind.items())},
              'handshake_kinds': {k.split('kind=')[1].rstrip('}'): v for k, v in mt.items() if k.startswith('p2p_handshake_failures_by_kind_total{')},
              'call_timeouts': {k.split('method=')[1].rstrip('}'): v for k, v in mt.items() if k.startswith('p2p_call_timeouts_total{')}}
    census['log_kinds_line'] = C.add({'src': 'log_kinds', 'records': logscan.get('records'), 'runs': logscan.get('runs'),
                                      'kinds': census['log_kinds']})
    rep = {'tool': 'harness/intel/peer_intel.py', 'r': 'r24', 'captured': ts, 'raw': cap.get('_dir'),
           'node_version': si.get('version') or gi.get('version'), 'header_line': hdr, 'sync_line': sync_l, 'kpi_line': kpi_line,
           'builders_line': bl_line, 'churn_line': churn_line, 'kpis': kpi, 'churn': churn, 'peers': peers, 'builders': builders,
           'detectors': D, 'census': census, 'rules': ra, 'thresholds': {'clock_future_ms': CLOCK_FUTURE_MS, 'first_relay_conc': FIRST_RELAY_CONC,
           'netgroup_share': NETGROUP_SHARE, 'min_netgroups': MIN_NETGROUPS, 'lagging_blocks': LAGGING, 'remote_unserved_mult': REMOTE_UNSERVED_MULT},
           'log': {'records': logscan.get('records'), 'runs': logscan.get('runs'),
                   'current_start_line': (logscan.get('current_start') or [None, None])[1]}}
    rep['proposals'] = proposals(rep, ra, root)
    return rep, C.lines, X.lines


# ───────────────────────────── node-side gaps → R25 (the self-recursive loop) ─────────────────────────────
GAPS = (
    ('CO24-N1', 'Per-peer offence score and last reasons are not exposed over RPC',
     'p2p/penalty.go', 'func add_penalty(ip string, reason string, now time.Time) (ban_seconds uint64) {',
     'GetPeerInfo (p2p/peer_info.go PeerInfo) has no penalty score field; individual offences below the ban score are not logged (only "peer banned for misbehaviour")',
     'add penalty_score and last_offence{reason,ts} to PeerInfo; a V(1) log line per offence with the reason'),
    ('CO24-N2', 'No per-reason offence counter (invalid_pow, malformed_request, undecodable, invalid_tx, timeout)',
     'p2p/penalty.go', 'metrics.Set.GetOrCreateCounter("p2p_penalty_bans_total").Inc()',
     '/metrics counts bans only; which rule a peer broke is invisible until it is banned',
     'p2p_penalty_offences_total{reason} incremented in add_penalty'),
    ('CO24-N3', 'Inbound Chain requests served are not counted',
     'p2p/rpc_chain_request.go', 'func (c *Connection) Chain(request Chain_Request_Struct, response *Chain_Response_Struct) error {',
     'chain-request amplification cannot be measured: no counter or log of served Chain requests and their sizes',
     'p2p_chain_requests_served_total and p2p_chain_request_blocks_total (+ per-peer count in PeerInfo)'),
    ('CO24-N4', 'Ban list entries carry no reason or origin',
     'p2p/bans.go', 'if err := write_json_atomic(ban_file, &ban_map); err != nil { // tmp + fsync + rename (persist.go)',
     'ban_list.json maps address -> expiry only; a ban from the v2 filter, a score ban and an operator ban look the same',
     'persist {until, reason, source} per entry; GetBanList RPC (loopback) with reason counts'),
    ('CO24-N5', 'Per-peer INV budget clips are node-wide only',
     'p2p/inv_budget.go', 'var inv_txids_over_budget = metrics.Set.NewCounter("p2p_inv_txids_over_budget_total")',
     'a flood is visible as one counter, not attributable to a connection',
     'inv_clipped counter on Connection, exposed in PeerInfo'),
    ('CO24-N6', 'Per-peer object-serve failures are only in the log',
     'p2p/object_errors.go', 'logger.V(1).Info(msg+": peer could not serve the object", append([]interface{}{"peer_error", err.Error()}, keysAndValues...)...)',
     "peer_intel reads 'could not serve' and 'answered N blocks' from derod.log; no counter or PeerInfo field carries them",
     'objects_unserved and short_answers counters per Connection, in PeerInfo and /metrics (summed)'),
    ('CO24-N7', 'Stuck-peer holds are not listed',
     'p2p/stuck_peer.go', 'func stuck_held_count(now time.Time) (n int) {',
     'p2p_stuck_peer_held is a count; which peers are held and until when is not readable',
     'stuck_held entries (address, strikes, until) in GetPeerInfo'),
)


# r25 (peers): the line that closes each gap. When it is in the tree the gap is 'implemented (r25)' and its anchor moves
# to that line, so area_intel stops proposing it; it is CONFIRMED only by a live read of the restarted build (§0.7.3).
IMPLEMENTED = {
    'CO24-N1': ('p2p/penalty.go', 'm.note(reason, now) // r25 (CO24-N1)'),
    'CO24-N2': ('p2p/peer_observe.go', 'metrics.Set.GetOrCreateCounter(fmt.Sprintf(`p2p_penalty_events_total{reason="%s"}`, reason))'),
    'CO24-N3': ('p2p/peer_observe.go', 'chain_requests_served.Inc()'),
    'CO24-N4': ('p2p/bans.go', 'ban_meta[address] = ban_info{Source: source, Reason: trim64(reason), At: time.Now().Unix()} // r25'),
    'CO24-N5': ('p2p/inv_budget.go', 'c.obs.inv_clipped.Add(uint64(len(list) - n)) // r25 (CO24-N5): attributable to this connection'),
    'CO24-N6': ('p2p/peer_observe.go', 'c.obs.objects_unserved.Add(1)'),
    'CO24-N7': ('p2p/peer_observe.go', 'func StuckHolds(now time.Time) (out []StuckHold) {'),
}


def _line_of(root, f, q):
    try:
        lines = (Path(root) / f).read_text(errors='replace').splitlines()
    except OSError:
        return None
    return next((i + 1 for i, l in enumerate(lines) if q in l), None)


def proposals(rep, ra, root):
    out = []
    for pid, title, f, q, gap, fix in GAPS:
        ln = _line_of(root, f, q)
        g = {'id': pid, 'title': title, 'anchor': {'file': f, 'quote': q, 'line': ln}, 'gap': gap, 'proposal': fix,
             'status': 'open' if ln else 'pending (anchor not in this tree)', 'target': 'R25', 'area': 'peers'}
        imp = IMPLEMENTED.get(pid)
        il = _line_of(root, *imp) if imp else None
        if il:
            g['status'] = 'implemented (r25)'
            g['gap_anchor'] = g['anchor']
            g['anchor'] = {'file': imp[0], 'quote': imp[1], 'line': il}
        out.append(g)
    return out


# ───────────────────────────── privacy scan (shared with G27 and the KAT) ─────────────────────────────
def leaks(text, secrets_=()):
    """[(kind, sample)] of IP-like strings and of the given private strings (tags, IPs) found in text."""
    out = []
    for m in IPV4.finditer(text):
        s = m.group(0)
        try:
            ipaddress.ip_address(s)
        except ValueError:
            continue
        out.append(('ipv4', s))
    for m in IPV6.finditer(text):
        s = m.group(0)
        if s.count(':') < 2 or not re.search(r'[0-9a-fA-F]', s):
            continue
        try:
            ipaddress.IPv6Address(s)
            out.append(('ipv6', s))
        except ValueError:
            pass
    out.extend(('private', s[:2] + '…') for s in private_hits(text, secrets_))
    return out


def load_privkit():
    """kit/privkit.py of THIS tree (by path, never a cached module of another tree: the KAT mutates copies)."""
    import importlib.util
    f = Path(__file__).resolve().parent.parent / 'kit' / 'privkit.py'
    sp = importlib.util.spec_from_file_location(f'privkit_{abs(hash(str(f)))}_{f.stat().st_mtime_ns}', f)
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


def private_hits(text, secrets_=()):
    """the given private strings (IPs, tags, peer_ids, builder keys) found in text (r24: shared by the section and
    the whole-page scans of G27)."""
    out = []
    for s in secrets_:
        if s and len(s) >= 4 and s in text:
            out.append(s)
    return out


def private_strings(priv):
    """the IPs, tags, peer_ids and raw builder keys of the newest private raw capture (to check outputs against), or ()."""
    try:
        d = sorted(x for x in (Path(priv) / 'raw').iterdir() if x.is_dir() and re.fullmatch(r'\d{8}T\d{6}Z', x.name))[-1]
    except (OSError, IndexError):
        return ()
    s = set()
    try:
        for p in (json.loads((d / 'GetPeerInfo.json').read_text()).get('result') or {}).get('peers') or []:
            s.add(host_of(p.get('address')))
            if p.get('tag'):
                s.add(p['tag'])
            if p.get('peer_id'):                         # r24 (verify): the handshake node id is private too
                s.add(str(p['peer_id']))
    except (OSError, ValueError):
        pass
    for f in DATADIR_FILES:
        try:
            j = json.loads((d / f).read_text())
        except (OSError, ValueError):
            continue
        for k in (j.get('peers') or {}) if f == 'first_relay.json' else j:
            s.add(host_of(k))
            if f == 'first_relay.json':                  # r24 (verify): raw builder (miner) key prefixes are private
                s.update(str(b) for b in ((j['peers'][k] or {}).get('builders') or {}))
    # r24 (integration): a loopback / unspecified / test-range address (peers.json can hold 127.0.0.1) names no peer
    # and appears legitimately on every page; only real peer addresses, tags and ids are private
    pk = load_privkit()
    return tuple(sorted(x for x in s if x and len(x) >= 7 and not (pk.IPV4.fullmatch(x) and pk.reserved(x))))


def page_section(html_text, sid='peers'):
    i = html_text.find(f'<section id="{sid}">')
    if i < 0:
        return None
    j = html_text.find('</section>', i)
    return html_text[i:j if j > 0 else len(html_text)]


def g27(root=ROOT, priv=None, now=None):
    """(ok, detail): fresh capture, outputs and the rendered section free of IPs/private strings, every row anchored."""
    root = Path(root)
    rt = root / 'harness' / 'runtime'
    why = []
    rp = rt / 'peer_intel.json'
    try:
        rep = json.loads(rp.read_text())
    except (OSError, ValueError) as e:
        return False, f'peer_intel.json unreadable: {type(e).__name__}'
    try:
        cap_t = datetime.datetime.fromisoformat(rep['captured'])
        age = ((now or datetime.datetime.now().astimezone()) - cap_t).total_seconds() / 3600
    except (KeyError, ValueError, TypeError):
        age = None
    if age is None or age > FRESH_H or age < -0.1:
        why.append(f'capture not fresh ({age if age is None else round(age, 1)} h)')
    capf, logxf = rt / rep.get('capture_file', '-'), rt / rep.get('logx_file', '-')
    files = [rp, capf, logxf, root / 'harness/model/raw/peercards.json']
    for f in (capf, logxf):
        if not f.exists():
            why.append(f'{f.name} missing')
    if capf.exists() and rep.get('capture_sha') != hashlib.sha256(capf.read_bytes()).hexdigest()[:16]:
        why.append('capture file changed since the report')
    sec = None
    page = root / 'artifacts' / 'dero-src-arch.html'
    if page.exists():
        sec = page_section(page.read_text(errors='replace'))
    ps_ = private_strings(priv or PRIVATE)
    nleak = 0
    for f in files:
        try:
            t = f.read_text(errors='replace')
        except OSError:
            continue
        lk = leaks(t, ps_)
        if lk:
            nleak += len(lk)
            why.append(f'{f.name}: {len(lk)} leak(s) ({lk[0][0]})')
    if sec is not None:
        lk = leaks(sec, ps_)
        if lk:
            nleak += len(lk)
            why.append(f'rendered section: {len(lk)} leak(s) ({lk[0][0]})')
    # r24 (integration): the WHOLE generated page, harness/model/verified.json and the log-derived raw files carry no
    # peer address (every non-reserved IPv4 pseudonymised at the miners, kit/privkit.py) and none of the newest private
    # capture's strings; before r24 the triage / log-bridge / intel rows copied peer IPv4s from the derod console
    privkit = load_privkit()
    n_scan = 0
    for f in [page, root / 'harness/model/verified.json'] + [root / f'harness/model/raw/{k}.json' for k in PAGE_RAW_KEYS]:
        try:
            t = f.read_text(errors='replace')
        except OSError:
            continue
        n_scan += 1
        lk = privkit.page_ip_leaks(t)
        pv = private_hits(t, ps_)
        if lk or pv:
            nleak += len(lk) + len(pv)
            why.append(f'{f.name}: {len(lk)} peer address(es) not pseudonymised, {len(pv)} private string(s) '
                       f'(e.g. {(lk or pv)[0][:3]}…)')
    # every rendered row anchored; every detector rule line resolves
    n_rows = n_bad = 0
    try:
        rows = json.loads((root / 'harness/model/raw/peercards.json').read_text()).get('rows', [])
    except (OSError, ValueError):
        rows = None
        why.append('model/raw/peercards.json missing (run harness/miners/mine_peers.py)')
    for r in rows or []:
        n_rows += 1
        ok = False
        for e in r.get('evidence') or []:
            try:
                ls = (root / e['file']).read_text(errors='replace').splitlines()
            except OSError:
                continue
            ln = e.get('line')
            if isinstance(ln, int) and 0 < ln <= len(ls) and str(e.get('quote', ''))[:200] in ls[ln - 1]:
                ok = True
                break
        n_bad += not ok
    if n_bad:
        why.append(f'{n_bad} row(s) without a resolving anchor')
    bad_rules = [d['id'] for d in rep.get('detectors', []) if d.get('grade') != 'pending' and (d.get('rule') or {}).get('status') != 'OK']
    if bad_rules:
        why.append(f'detectors graded without a rule line: {bad_rules}')
    if rows is not None and rows and sec is None and page.exists():
        why.append('the page has no peers section although rows exist (rebuild gen_deroarch)')
    ok = not why
    det = (f"capture {rep.get('captured')} ({rep.get('node_version')}), {rep['kpis'].get('peers_active')} peers, "
           f"{len(rep.get('detectors', []))} detectors (OBSERVED {rep['kpis'].get('observed')}, ANOMALY {rep['kpis'].get('anomaly')}), "
           f"{n_rows} rows anchored {n_rows - n_bad}/{n_rows}, leaks {nleak} (private strings checked: {len(ps_)}; "
           f"whole page + verified.json + {len(PAGE_RAW_KEYS)} log-derived raw files scanned: {n_scan})")
    return ok, det + ('' if ok else ' · ' + '; '.join(why)[:400])


# ───────────────────────────── main ─────────────────────────────
def write_atomic(path, text):
    p = Path(path)
    tmp = p.parent / f'.{p.name}.{os.getpid()}.tmp'
    tmp.write_text(text)
    os.replace(tmp, p)


def run(cap_dir, priv, log_paths, root=ROOT, out_dir=None):
    out_dir = Path(out_dir or (Path(root) / 'harness' / 'runtime'))
    out_dir.mkdir(parents=True, exist_ok=True)
    salt = load_salt(priv)
    ps = Pseud(salt, load_self(priv).get('builder8'))
    cap = load_capture(cap_dir)
    ls = scan_log(log_paths, ps)
    series = out_dir / 'peer_series.jsonl'
    prev = None
    if series.exists():
        try:
            prev = json.loads(series.read_text().splitlines()[-1])
        except (ValueError, IndexError):
            prev = None
    tsn = datetime.datetime.now()
    stamp = tsn.strftime('%Y%m%dT%H%M%S')
    walls, wf = load_walls(root)
    rep, cl, xl = analyse(cap, ls, ps, root=root, ts=tsn.astimezone().isoformat(timespec='seconds'), prev=prev,
                          prior=load_prior(out_dir, exclude=f'peer_capture_{stamp}.jsonl'), walls=walls, walls_file=wf,
                          cap_file=f'peer_capture_{stamp}.jsonl')
    capf, logxf = out_dir / f'peer_capture_{stamp}.jsonl', out_dir / f'peer_logx_{stamp}.jsonl'
    write_atomic(capf, '\n'.join(cl) + '\n')
    write_atomic(logxf, '\n'.join(xl) + ('\n' if xl else ''))
    rep['capture_file'], rep['logx_file'] = capf.name, logxf.name
    rep['capture_sha'] = hashlib.sha256(capf.read_bytes()).hexdigest()[:16]
    rep['log']['files'] = [Path(p).name for p in log_paths]
    write_atomic(out_dir / 'peer_intel.json', json.dumps(rep, indent=1, ensure_ascii=False) + '\n')
    k = rep['kpis']
    with series.open('a') as f:
        f.write(json.dumps({'captured': rep['captured'], 'version': rep['node_version'], 'capture': capf.name,
                            'peers': k['peers_active'], 'out': k['outgoing'], 'in': k['incoming'], 'lag_max': k['lag_max'],
                            'lag_max_v2': k.get('lag_max_v2'), 'regime': k.get('inbound_regime'),
                            'latency_median_ms': k['latency_median_ms'], 'versions': k['versions'], 'v2_seen_7d': k['v2_seen_7d'],
                            'bans_listed': k['bans_listed'], 'first_relay_top_share': k['first_relay_top_share'],
                            'netgroups': k['netgroups'], 'observed': k['observed'], 'anomaly': k['anomaly'],
                            'handshake_failures': k['handshake_failures'], 'active': sorted(p['peer'] for p in rep['peers'])}) + '\n')
    return rep, capf, logxf


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--live', action='store_true', help='capture now (read-only RPC, /metrics, datadir copies) into the private dir')
    ap.add_argument('--capture', help='an existing capture directory')
    ap.add_argument('--private', help='private directory (salt, self.json, raw captures)')
    ap.add_argument('--log', nargs='*', help='derod log files (default ~/dero-data/logs/derod*.log*)')
    ap.add_argument('--datadir', help='the datadir to copy the four JSON files from (read-only)')
    ap.add_argument('--check', action='store_true', help='gate G27 on the newest outputs')
    a = ap.parse_args()
    priv = private_dir(a.private)
    if a.check:
        ok, det = g27(ROOT, priv)
        print(('PASS ' if ok else 'FAIL ') + det)
        return 0 if ok else 3
    if a.live:
        cd = capture_live(priv, datadir=a.datadir)
    elif a.capture:
        cd = Path(a.capture)
    else:
        ap.error('--live or --capture DIR')
    rep, capf, logxf = run(cd, priv, log_files(a.log))
    if a.live:
        # r24 (integration): keep the newest PRIVATE_KEEP raw runs within PRIVATE_MAX_BYTES, 0700 dirs / 0600 files
        privkit = load_privkit()
        kept, gone = privkit.prune_private(Path(priv) / 'raw', keep=PRIVATE_KEEP, max_bytes=PRIVATE_MAX_BYTES,
                                           pattern=r'^\d{8}T\d{6}Z$')
        privkit.prune_private(priv, keep=10 ** 6, max_bytes=10 ** 15)              # modes only, on the whole tree
        if gone:
            print(f'peer_intel: pruned {len(gone)} private raw run(s), kept {len(kept)}')
    k = rep['kpis']
    print(f"peer_intel {rep['captured']} {rep['node_version']}: {k['peers_active']} peers ({k['outgoing']} out / {k['incoming']} in), "
          f"lag max {k['lag_max']}, latency median {k['latency_median_ms']} ms, versions {k['versions']}, netgroups {k['netgroups']}, "
          f"first-relay top share {k['first_relay_top_share']}, builders {k['builders_seen']}")
    for d in rep['detectors']:
        print(f"  {d['id']:<4} {d['grade']:<8} {d['title']}  ({len(d['findings'])} finding(s))")
    print(f"wrote harness/runtime/{capf.name}, {logxf.name}, peer_intel.json, peer_series.jsonl; proposals {len(rep['proposals'])}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
