#!/usr/bin/env python3
"""error_census.py — the standing derod error census (rft §6 step 1a, since R25): every ERROR and WARNING line of a
derod run, by kind, each kind classified by WHOSE error it is.

derod logs JSON lines {"L","T","N","C","M", ...fields} (lumberjack, <--log-dir>/derod.log). logr has no WARN level, so
derod's warnings are INFO lines whose message starts "WARNING:" (cmd/derod/rpc/websocket_server.go:235,
websocket_getwork_server.go:629/675, r25 rpc state refusals); a zap "WARN" level is counted too.

  kind      (level, component with the peer address removed, caller file:line, message, normalised error text):
            two lines are one kind when they differ only in numbers, hashes or peer addresses
  own frame a recovered panic ("RPC handler recovered a panic", or any record with a `stack` field) names the first
            frame of this repository AFTER the `panic(` frame: the line that panicked (rft lesson #32), repo-relative
  class     self-inflicted  a recovered panic or ERROR within MATCH_WINDOW_S of one of OUR state-read calls (the call
                            log harness/kit/pruneguard.py writes, or a KNOWN_SELF entry anchored in an evidence file)
                            whose method matches the own frame's handler; it is ALSO a node bug when it is a
                            recovered panic (the node should have answered with a typed error: B85)
            peer-caused     the line is about a peer: component P2P.* naming a peer, an rpc2 ServerError, a peer's
                            path or answer (log_intel CLASSES remote-*; "peer answered"; rft lessons #35-#36)
            operational     a known operator WARNING (a miner absent, an endpoint reachable from the network, a r25
                            state refusal: the node did the right thing and says so)
            node-bug        every other ERROR, and every recovered panic not matched to our calls
            unclassified    a WARNING line no rule knows (a new kind: read it)
  run       the census covers ONE derod run: from the last start-up line (derod/main.go "DERO HE daemon :") to the end
            (--run N picks the N-th run from the end, 1 = the last). Timestamps are parsed WITH their UTC offset
            (the log crosses DST: -0700 before 2026-11-01, -0800 after), and lines keep file order.

Output harness/runtime/error_census_<ts>.json (one record per kind, the class counts, the run) with peer addresses
masked (privkit.mask) and home paths removed: no IP, no path, no stack text in the snapshot.

  python3 -I harness/intel/error_census.py [--files a.log ...] [--run 1] [--call-log path] [--json-only]
Exit 0 = no node-bug kind in the run · 5 = at least one node-bug kind (a valid census: the gate/S7 judge it) ·
2 = no derod log found.
"""
import argparse, datetime, glob, hashlib, json, re, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent
ROOT = HARNESS.parent
sys.path.insert(0, str(HARNESS / 'kit'))
import privkit      # noqa: E402  (mask: salt-free peer token)
import pruneguard   # noqa: E402  (the probe call log)

SCHEMA = 'error-census/1'
sys.path.insert(0, str(HERE))
from log_intel import DEFAULT_GLOBS as _LOG_INTEL_GLOBS, write_atomic   # noqa: E402  (same log files as G15)
DEFAULT_GLOBS = [g for g in _LOG_INTEL_GLOBS if 'dero-data' in g]          # the --log-dir file, not bin/ copies
START_FILE, START_M = 'derod/main.go:', 'DERO HE daemon :'
MATCH_WINDOW_S = 2.0            # a probe call and the line it caused share a second in the live 2026-11-03 case
OWN_MODULE = 'github.com/deroproject/derohe/'
PANIC_MSGS = ('RPC handler recovered a panic', 'Recovered while')

# self-inflicted lines we know of BEFORE a call log existed; each anchored in the evidence file that records the calls
KNOWN_SELF = [
    {'from': '2026-11-03T08:37:44.000-0800', 'to': '2026-11-03T08:37:45.000-0800', 'method': 'GetEncryptedBalance',
     'why': 'the R25 discovery probe: 4 GetEncryptedBalance calls below prunedheight 7,498,540 (B85)',
     'anchor': 'harness/runtime/r25_forensics_discovery_20261103.txt:183'},
]
OPERATIONAL = [('WARNING: no miner connected', 'no miner connected: payout-relevant, not a fault (getwork_absence.go)'),
               ('WARNING: getwork is reachable from the network', 'bind policy warning (operator choice)'),
               ('WARNING: daemon RPC is reachable from the network', 'bind policy warning (operator choice)'),
               ('WARNING: state read below the prune point refused', 'r25 B85: the node refused a pruned state read with a typed error')]
PEER_TEXT = ('peer answered', 'ServerError', 'rpc2', 'bltx_store', 'Invalid Major Version', 'closed pipe')
FRAME = re.compile(r'^(\S+)\(.*\)$')
FILELINE = re.compile(r'^\s+(\S+\.go):(\d+)')
HEX = re.compile(r'\b[0-9a-f]{16,}\b')
NUM = re.compile(r'\b\d+\b')
PEER_N = re.compile(r'^(P2P\.(?:incoming|outgoing))\..*$')
HOME = re.compile(r'/(?:Users|home)/[^/\s"]+')


def files(explicit=None):
    out = []
    for g in (explicit or DEFAULT_GLOBS):
        for f in sorted(glob.glob(g)):
            try:
                with open(f, errors='replace') as fh:
                    if fh.readline().startswith('{'):
                        out.append(Path(f))
            except OSError:
                pass
    # lumberjack backups are derod-<time>.log: oldest first, the live file last
    return sorted(out, key=lambda p: (p.name == 'derod.log', p.name))


def records(paths):
    for p in paths:
        with p.open(errors='replace') as fh:
            for n, l in enumerate(fh, 1):
                if not l.startswith('{'):
                    continue
                try:
                    d = json.loads(l)
                except ValueError:
                    continue
                d['_f'], d['_n'] = p.name, n
                yield d


def epoch(t):
    """Seconds since the epoch of a derod 'T' value WITH its offset (2026-11-03T08:37:44.254-0800). Pure."""
    return datetime.datetime.strptime(t, '%Y-%m-%dT%H:%M:%S.%f%z').timestamp()


def is_start(d):
    return str(d.get('C', '')).startswith(START_FILE) and str(d.get('M', '')).startswith(START_M)


def split_runs(recs):
    runs, cur = [], []
    for d in recs:
        if is_start(d) and cur:
            runs.append(cur)
            cur = []
        cur.append(d)
    if cur:
        runs.append(cur)
    return runs


def level(d):
    """'ERROR', 'WARN' or None. Pure."""
    L = str(d.get('L', ''))
    if L in ('ERROR', 'DPANIC', 'PANIC', 'FATAL'):
        return 'ERROR'
    if L == 'WARN' or (L == 'INFO' and str(d.get('M', '')).startswith('WARNING')):
        return 'WARN'
    return None


def own_frame(stack):
    """(function, 'repo/relative/file.go:line') of the first own-code frame after the panic( frame, or None. Pure.
    Go prints each frame as a 'func(args)' line followed by a tab-indented '/abs/path/file.go:line +0x..' line."""
    lines = str(stack or '').split('\n')
    seen_panic = False
    for i, l in enumerate(lines):
        m = FRAME.match(l.strip())
        if not m:
            continue
        fn = m.group(1)
        if fn == 'panic' or fn.startswith('runtime.gopanic'):
            seen_panic = True
            continue
        if seen_panic and fn.startswith(OWN_MODULE) and i + 1 < len(lines):
            fl = FILELINE.match(lines[i + 1])
            if fl:
                path = fl.group(1)
                rel = re.sub(r'^.*?/((?:cmd|p2p|blockchain|walletapi|rpc|glue|globals|dvm|transaction|cryptography|block|'
                             r'metrics|config|proof|astrobwt|pow|tools)/)', r'\1', path)
                return fn[len(OWN_MODULE):], f'{rel}:{fl.group(2)}'
    return None


def norm(s):
    """Numbers and hashes out, peers masked: the text two lines of one kind share. Pure."""
    s = privkit.mask(HOME.sub('~', str(s or '')))
    return NUM.sub('N', HEX.sub('H', s))[:160]


def component(d):
    n = str(d.get('N', ''))
    m = PEER_N.match(n)
    return m.group(1) if m else privkit.mask(n)


def kind_of(d, lv):
    err = d.get('error', '') or d.get('r', '') or d.get('peer_error', '')
    of = own_frame(d.get('stack')) if d.get('stack') else None
    key = (lv, component(d), str(d.get('C', '')), norm(d.get('M', ''))[:100], norm(err), of[1] if of else '')
    kid = 'EK-' + hashlib.blake2b('|'.join(key).encode(), digest_size=5).hexdigest()
    return kid, key, of, err


def self_calls(call_log):
    out = []
    for c in pruneguard.read_call_log(call_log):
        try:
            t = datetime.datetime.fromisoformat(str(c['t'])).timestamp()
        except (KeyError, ValueError):
            continue
        m = str(c.get('method', '')).split('.')[-1].lower()
        out.append({'from': t - MATCH_WINDOW_S, 'to': t + MATCH_WINDOW_S, 'method': m, 'why': 'probe call log',
                    'anchor': f"call log {c['t']}"})
    for k in KNOWN_SELF:
        out.append({'from': epoch(k['from']), 'to': epoch(k['to']), 'method': k['method'].lower(), 'why': k['why'],
                    'anchor': k['anchor']})
    return out


def handler_of(of):
    """'GetEncryptedBalance' from 'cmd/derod/rpc.GetEncryptedBalance'. Pure."""
    if not of:
        return ''
    return of[0].split('.')[-1].split('(')[0]


def classify(d, lv, of, err, calls):
    """(class, why, also_node_bug). Pure given calls."""
    t = epoch(d['T'])
    text = ' '.join(str(x) for x in (d.get('M', ''), err))
    panic_line = bool(of) or str(d.get('M', '')).startswith(PANIC_MSGS) or bool(d.get('stack'))
    for c in calls:
        if c['from'] <= t <= c['to'] and (not of or handler_of(of).lower() == c['method']):
            return 'self-inflicted', f"{c['why']} ({c['anchor']})", panic_line
    if lv == 'WARN':
        for pref, why in OPERATIONAL:
            if str(d.get('M', '')).startswith(pref):
                return 'operational', why, False
    if str(d.get('N', '')).startswith('P2P.') and (PEER_N.match(str(d.get('N', ''))) or any(p in text for p in PEER_TEXT)):
        return 'peer-caused', 'a P2P line about a peer (its answer, its path, or an rpc2 ServerError)', False
    if any(p in text for p in PEER_TEXT):
        return 'peer-caused', 'the text is a peer\'s answer or path (rft lessons #35-#36)', False
    if lv == 'WARN':
        return 'unclassified', 'a WARNING no rule knows: read it', False
    return 'node-bug', ('a recovered panic not caused by our calls' if panic_line else 'an ERROR no rule explains'), panic_line


def census(recs, run_from_end=1, call_log=None):
    runs = split_runs(list(recs))
    if not runs:
        return None
    run = runs[-run_from_end] if run_from_end <= len(runs) else runs[0]
    calls = self_calls(call_log)
    start = run[0]
    version = next((d.get('Version') for d in run[:40] if d.get('Version')), None)
    kinds = {}
    for d in run:
        lv = level(d)
        if not lv:
            continue
        kid, key, of, err = kind_of(d, lv)
        cls, why, also = classify(d, lv, of, err, calls)
        k = kinds.get(kid)
        if not k:
            k = kinds[kid] = {'kind': kid, 'level': lv, 'component': key[1], 'caller': key[2], 'message': key[3],
                              'error': key[4], 'own_frame': of[1] if of else None,
                              'handler': handler_of(of) or None, 'recovered_panic': bool(of) or bool(d.get('stack')),
                              'class': cls, 'why': why, 'also_node_bug': also, 'count': 0, 'first': d['T'],
                              'first_at': f"{d['_f']}:{d['_n']}", 'classes_seen': {}}
        k['count'] += 1
        k['last'] = d['T']
        k['classes_seen'][cls] = k['classes_seen'].get(cls, 0) + 1
        if cls == 'node-bug':          # one unmatched line makes the whole kind a node bug
            k['class'], k['why'] = cls, why
    by_class = {}
    for k in kinds.values():
        by_class[k['class']] = by_class.get(k['class'], 0) + k['count']
    return {'schema': SCHEMA, 'run': {'start': start.get('T'), 'start_at': f"{start['_f']}:{start['_n']}",
                                      'version': version, 'lines': len(run), 'runs_in_files': len(runs),
                                      'run_from_end': run_from_end},
            'kinds': sorted(kinds.values(), key=lambda k: (-k['count'], k['kind'])), 'by_class': by_class,
            'node_bug_kinds': sorted(k['kind'] for k in kinds.values() if k['class'] == 'node-bug' or k['also_node_bug']),
            'self_inflicted_lines': by_class.get('self-inflicted', 0)}


def leaks(text):
    """Private identifiers left in a snapshot text (the KAT and the writer check it). Pure."""
    bad = [ip for ip in privkit.ips_in(text) if not privkit.reserved(ip)]
    if HOME.search(text):
        bad.append('home path')
    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--files', nargs='*')
    ap.add_argument('--run', type=int, default=1, help='which run from the end (1 = since the last restart)')
    ap.add_argument('--call-log', help='the probe call log (default: pruneguard.CALL_LOG)')
    ap.add_argument('--out', help='write the snapshot here instead of harness/runtime/error_census_<ts>.json')
    ap.add_argument('--json-only', action='store_true')
    a = ap.parse_args()
    paths = files(a.files)
    if not paths:
        print('error_census: no derod JSON log found', file=sys.stderr)
        return 2
    rep = census(records(paths), a.run, a.call_log)
    if rep is None:
        print('error_census: the log holds no records', file=sys.stderr)
        return 2
    rep['captured'] = datetime.datetime.now().astimezone().isoformat(timespec='seconds')
    rep['files'] = [p.name for p in paths]
    text = json.dumps(rep, indent=1, ensure_ascii=False)
    if leaks(text):
        print(f'error_census: refusing to write a snapshot with private identifiers: {leaks(text)[:3]}', file=sys.stderr)
        return 3
    out = Path(a.out) if a.out else HARNESS / f"runtime/error_census_{datetime.datetime.now().strftime('%Y%m%dT%H%M%S')}.json"
    write_atomic(out, text)   # R22 crash-safe write (log_intel)
    if not a.json_only:
        r = rep['run']
        print(f"derod run since {r['start']} ({r['version']}), {r['lines']:,} lines: {sum(k['count'] for k in rep['kinds'])} "
              f"ERROR/WARNING lines in {len(rep['kinds'])} kind(s) {rep['by_class']}")
        for k in rep['kinds']:
            print(f"  {k['kind']} {k['level']:5s} x{k['count']:<4d} {k['class']:14s} {k['component']} {k['caller']} "
                  f"{k['message'][:60]!r}" + (f" own frame {k['own_frame']}" if k['own_frame'] else '') +
                  (' (also a node bug: should be a typed error)' if k['also_node_bug'] and k['class'] != 'node-bug' else ''))
        print(f'wrote {out}')
    return 5 if rep['node_bug_kinds'] else 0


if __name__ == '__main__':
    sys.exit(main())
