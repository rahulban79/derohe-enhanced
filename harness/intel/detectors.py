#!/usr/bin/env python3
"""detectors.py — r31 dimension 0 (rft §0.12 D-20/D-21, §7 B280-B285, B287): area DETECTORS that produce NEW evidence.

Each detector is a static, read-only scan of this tree (first-party Go, vendor and _test.go files aside unless the
detector reads tests as evidence of a pin) and of the harness records. Nothing is fetched, no RPC is made, derod is
never contacted. Each writes harness/runtime/detector_<name>.json:

  {schema, detector, row, home_area, generated_at, rev (git HEAD), tool_sha, registry_sha, fingerprint (sha of every
   scanned input), inputs {counts}, rules [the heuristics, as written here], census [every item scanned, with its
   evidence], findings [{id, detector, area, file, line, quote, kind, severity, why, suggested_row, ...}],
   allowed [findings an allow-list entry accepted, with the reason], allow_problems [stale or reasonless entries]}

A finding's `quote` is the literal source line (stripped), so its anchor {file, quote, line} re-resolves after edits
(area_intel resolve_anchor); its `id` is a stable hash of (detector, file, kind, key), never of the line number.
`area` is area_intel.area_of(harness/areas.json areas, file); a file no area owns is booked to the detector's home
area with `unowned: true`.

  budget-census   (B280, security)      every derod RPC method, wallet RPC method and P2P message handler: a per-method
                                        weight / per-peer budget / size cap, or a finding at the handler
  fuzz-coverage   (B281, by decoder)    every exported decoder with its Go Fuzz* target (or none), and whether the
                                        target has a seed corpus (f.Add or testdata/fuzz/<Name>)
  error-paths     (B282, by file)       discarded errors (`_ =`, `x, _ :=` on an error-returning call, an `err` that is
                                        assigned and never read) and panic paths on decoded input (panic( in a decoder,
                                        an index into a decoded slice without a length check)
  crypto-input    (B283, cryptography)  every entry decoding a point / scalar / key / proof from bytes: does it reject
                                        non-canonical input (coordinate >= P, an undefined flag byte, scalar >= order,
                                        the identity for keys)? Defensive descriptions only (rft §5): never how to
                                        build an input
  value-paths     (B284, cryptosupply)  every line that creates, moves or destroys value (coinbase, premine,
                                        registration, transfer, SC payout, burn, fee): checked by the emission auditor
                                        (its source names the class) and/or pinned by a test naming the function
  signal-coverage (B285, observability) every derod ERROR / WARNING log literal mapped to an error_census class (else a
                                        finding; an event-like literal also needs a counter in its function) and every
                                        own /metrics family read by an intel tool or areas.json (r31 d4: or unread on
                                        purpose by a registry not_read note; census classes say which literals are events)
  dvm-builtins    (B287, dvm)           the DVM function table: gas, input-size bound, panic safety, a test; the SC RPC
                                        and wallet paths with a budget. A flat-priced builtin whose work grows with its
                                        input is a disclosure-style finding: documented, never changed (gas is
                                        consensus, D-21)

  python3 -I harness/intel/detectors.py --all            # run all 7, write each JSON (exit 0; 5 an allow-list problem)
  python3 -I harness/intel/detectors.py <name> [...]     # run the named detectors
  python3 -I harness/intel/detectors.py --check          # each JSON present and fresh? (exit 0 / 3 stale or missing)
  python3 -I harness/intel/detectors.py --list           # the detectors and their rows
Options: --root DIR (scan another tree; the KATs use it), --print (findings to stdout, nothing written).
Allow-list: harness/intel/detector_allow.json {allow: [{detector, file, kind, quote, reason}]}: a finding of that
detector, file and kind whose quote contains `quote` is accepted (listed under `allowed`); an entry with no reason or
that matches no finding is an allow problem (exit 5), so the list cannot rot (as harness/pipeline/liveness_allow.json).
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):
    print(__doc__)
    raise SystemExit(0)
import datetime, hashlib, importlib.util, json, os, re, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent
ROOT = HARNESS.parent
SCHEMA = 'detector/1'
ALLOW = 'harness/intel/detector_allow.json'
OUT_DIR = 'harness/runtime'
GOMOD = 'github.com/deroproject/derohe/'
# name: (home area, §7 row, one line)
DETECTORS = {
    'budget-census': ('security', 'B280', 'RPC method and P2P message handlers without a budget'),
    'fuzz-coverage': ('cryptosupply', 'B281', 'decoders without a fuzz target or seed corpus'),
    'error-paths': ('harness', 'B282', 'discarded errors and panic paths on decoded input'),
    'crypto-input': ('cryptography', 'B283', 'point / scalar / key / proof decoders that accept non-canonical input'),
    'value-paths': ('cryptosupply', 'B284', 'value paths neither audited nor pinned'),
    'signal-coverage': ('observability', 'B285', 'log literals without a census class, families no tool reads'),
    'dvm-builtins': ('dvm', 'B287', 'DVM builtins and SC entry paths without bound, test or budget'),
}
PRUNE = {'.git', 'vendor', 'node_modules', 'testdata', '__pycache__'}
PRUNE_TOP = {'harness', 'artifacts', 'forensics', 'memory-mirror', 'bin', 'mainnet', 'licenses'}


# the records, spelled out (harness/intel/coherence_audit.py reaches a record through a tool that names its path)
RECORDS = {'budget-census': 'harness/runtime/detector_budget-census.json',
           'fuzz-coverage': 'harness/runtime/detector_fuzz-coverage.json',
           'error-paths': 'harness/runtime/detector_error-paths.json',
           'crypto-input': 'harness/runtime/detector_crypto-input.json',
           'value-paths': 'harness/runtime/detector_value-paths.json',
           'signal-coverage': 'harness/runtime/detector_signal-coverage.json',
           'dvm-builtins': 'harness/runtime/detector_dvm-builtins.json'}


def out_path(root, name):
    return Path(root) / RECORDS.get(name, f'{OUT_DIR}/detector_{name}.json')


def sha16(data):
    return hashlib.sha256(data if isinstance(data, bytes) else str(data).encode()).hexdigest()[:16]


def file_sha(path):
    try:
        return sha16(Path(path).read_bytes())
    except OSError:
        return None


def git_rev(root):
    try:
        r = subprocess.run(['git', '-C', str(root), 'rev-parse', 'HEAD'], capture_output=True, text=True, timeout=20)
        return r.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def _load_mod(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def area_of_fn(root):
    """area_intel.area_of over the scanned tree's registry (the tool's own area_intel: the KAT trees have none)."""
    ai = _load_mod('det_area_intel', HERE / 'area_intel.py')
    try:
        areas = json.loads((Path(root) / 'harness' / 'areas.json').read_text()).get('areas', [])
    except (OSError, ValueError):
        areas = []
    return lambda f: ai.area_of(areas, f)


# ───────────────────────────── Go source model (gofmt'd source: top-level func at column 0, its '}' at column 0) ─────
class Tree:
    """the scanned tree: file texts (cached), first-party Go files, functions per file."""

    def __init__(self, root):
        self.root = Path(root)
        self._text, self._funcs, self.read = {}, {}, set()
        self._go = None

    def text(self, rel):
        if rel not in self._text:
            try:
                self._text[rel] = (self.root / rel).read_text(errors='replace')
            except OSError:
                self._text[rel] = None
        if self._text[rel] is not None:
            self.read.add(rel)
        return self._text[rel]

    def lines(self, rel):
        t = self.text(rel)
        return t.splitlines() if t is not None else []

    def go_files(self):
        if self._go is None:
            out = []
            for dp, dns, fns in os.walk(self.root):
                rel_dp = os.path.relpath(dp, self.root)
                top = rel_dp.split(os.sep)[0]
                dns[:] = sorted(d for d in dns if d not in PRUNE and not d.startswith(('_', '.'))
                                and not (rel_dp == '.' and d in PRUNE_TOP))     # go build ignores _ and . dirs
                if top in PRUNE_TOP:
                    continue
                for f in sorted(fns):
                    if f.endswith('.go'):
                        out.append(os.path.normpath(os.path.join(rel_dp, f)).replace(os.sep, '/'))
            self._go = sorted(out)
        return self._go

    def go(self, prefixes=(), tests=False, only_tests=False):
        out = []
        for f in self.go_files():
            t = f.endswith('_test.go')
            if (only_tests and not t) or (not tests and not only_tests and t):
                continue
            if prefixes and not any(f.startswith(p) if p.endswith('/') else (f == p or re.fullmatch(p.replace('*', '[^/]*'), f)) for p in prefixes):
                continue
            out.append(f)
        return out

    def funcs(self, rel):
        if rel not in self._funcs:
            self._funcs[rel] = split_funcs(self.lines(rel))
        return self._funcs[rel]


FUNC_RX = re.compile(r'^func\s+(?:\(\s*(\w+)?\s*\*?\s*([\w.]+)(?:\[[^\]]*\])?\s*\)\s*)?(\w+)\s*(?:\[[^\]]*\])?\s*\(')


def split_funcs(lines):
    """[{name, recv, start, end, sig}] of the top-level funcs (1-based inclusive lines). Pure."""
    out = []
    i = 0
    while i < len(lines):
        m = FUNC_RX.match(lines[i])
        if not m:
            i += 1
            continue
        start, end = i + 1, None
        l = lines[i].rstrip()
        if l.endswith('}') and l.count('{') == l.count('}'):
            end = i + 1
        else:
            j = i + 1
            while j < len(lines) and lines[j].rstrip() != '}':
                if FUNC_RX.match(lines[j]):
                    break
                j += 1
            end = j + 1 if j < len(lines) and lines[j].rstrip() == '}' else j
        out.append({'name': m.group(3), 'recv': m.group(2), 'start': start, 'end': end, 'sig': lines[i]})
        i = max(end, i + 1)
    return out


def body(lines, fn):
    return lines[fn['start'] - 1:fn['end']]


COMMENT_RX = re.compile(r'//[^\n]*')
BLOCK_RX = re.compile(r'/\*.*?\*/', re.S)
STR_RX = re.compile(r'"(?:[^"\\\n]|\\.)*"|`[^`]*`')


def code_only(text):
    """the text with comments removed (string literals kept). A '//' inside a string literal is kept. Pure."""
    def strip_line(l):
        out, i, q = [], 0, None
        while i < len(l):
            c = l[i]
            if q:
                out.append(c)
                if c == '\\' and q == '"' and i + 1 < len(l):
                    out.append(l[i + 1])
                    i += 2
                    continue
                if c == q:
                    q = None
            elif c in '"`':
                q = c
                out.append(c)
            elif l.startswith('//', i):
                break
            else:
                out.append(c)
            i += 1
        return ''.join(out)
    text = BLOCK_RX.sub(lambda m: '\n' * m.group(0).count('\n'), text)
    return '\n'.join(strip_line(l) for l in text.split('\n'))


def enclosing(funcs, line):
    for fn in funcs:
        if fn['start'] <= line <= fn['end']:
            return fn
    return None


# ───────────────────────────── findings ─────────────────────────────
def fid(det, file, kind, key):
    return f"DF-{det}-{hashlib.sha256(f'{det}|{file}|{kind}|{key}'.encode()).hexdigest()[:10]}"


def finding(det, tree, file, line, kind, severity, why, key=None, **extra):
    ls = tree.lines(file)
    quote = ls[line - 1].strip() if 1 <= line <= len(ls) else ''
    k = key if key is not None else quote
    f = {'id': fid(det, file, kind, k), '_key': k, 'detector': det, 'file': file, 'line': line,
         'quote': quote, 'kind': kind, 'severity': severity, 'why': why}
    f.update(extra)
    return f


def suggested_row(det, f, rev):
    home, row, _ = DETECTORS[det]
    return (f"| B? | ({row}, detector-{det}) {f['why']} | {f['area']} | `{f['file']}:{f['line']}` | "
            f"OPEN (self-detected R31 by detector-{det} at {str(rev or 'no-git')[:8]}) |")


def load_allow(root):
    try:
        d = json.loads((Path(root) / ALLOW).read_text())
        return d.get('allow') or [], None
    except OSError:
        return [], None
    except ValueError as e:
        return [], f'{ALLOW} unreadable: {e}'


def apply_allow(det, findings, allow):
    """(kept, allowed, problems): an entry {detector, file, kind, quote, reason} accepts the findings of its detector,
    file and kind whose quote contains its quote; one without a reason, or matching no finding, is a problem. Pure."""
    mine = [a for a in allow if a.get('detector') == det]
    kept, allowed, used = [], [], set()
    for f in findings:
        hit = next((i for i, a in enumerate(mine) if a.get('file') == f['file'] and a.get('kind') == f['kind']
                    and a.get('quote') and a['quote'] in f['quote'] and str(a.get('reason') or '').strip()), None)
        if hit is None:
            kept.append(f)
        else:
            used.add(hit)
            allowed.append(dict(f, allow_reason=mine[hit]['reason']))
    probs = []
    for i, a in enumerate(mine):
        if not str(a.get('reason') or '').strip():
            probs.append(f"{det}: allow entry {a.get('file')}:{a.get('kind')} has no reason")
        elif i not in used:
            probs.append(f"{det}: allow entry {a.get('file')}:{a.get('kind')} {a.get('quote')!r} matches no finding (stale)")
    return kept, allowed, probs


# ───────────────────────────── shared: Go struct fields and string-keyed maps ─────────────────────────────
def struct_fields(tree, files, tname):
    """[(field, type)] of `tname struct {` in `files` (first definition), or None. Pure over the tree."""
    rx = re.compile(r'^\s*(?:type\s+)?' + re.escape(tname) + r'\s+struct\s*\{(.*)$')
    for f in files:
        ls = tree.lines(f)
        for i, l in enumerate(ls):
            m = rx.match(l)
            if not m:
                continue
            if m.group(1).strip().startswith('}'):
                return []
            out, depth = [], 1
            for l2 in ls[i + 1:]:
                s = code_only(l2).strip()
                depth += s.count('{') - s.count('}')
                if depth <= 0:
                    break
                fm = re.match(r'^([A-Za-z_]\w*)\s+([^`]+?)\s*(?:`.*)?$', s)
                if fm and depth == 1:
                    out.append((fm.group(1), fm.group(2).strip()))
            return out
    return None


def map_entries(lines, start_rx, key_rx=r'^\s*"([^"]+)"\s*:\s*(.*)$'):
    """{key: (line, rest)} of a Go map literal starting at the first line matching start_rx. Pure."""
    out = {}
    for i, l in enumerate(lines):
        if re.search(start_rx, l):
            depth = 0
            for j in range(i, len(lines)):
                s = code_only(lines[j])
                if j > i or True:
                    m = re.match(key_rx, s)
                    if m and j > i:
                        out[m.group(1)] = (j + 1, m.group(2))
                depth += s.count('{') - s.count('}')
                if depth <= 0 and j > i:
                    break
            break
    return out


# ═════════════════════════════ 1. budget-census (B280) ═════════════════════════════
DEROD_RPC = 'cmd/derod/rpc/'
WALLET_RPC = 'walletapi/rpcserver/'
RANGE_FIELD_RX = re.compile(r'(?i)^(?:(?:start|end|count|limit|depth|num|max|min|size|offset|page)(?:_?\w*)?|from|to|n)$')
BOUND_RX = re.compile(r'len\(\s*p\.\w+\s*\)\s*>|\bp\.\w+\s*>\s*[A-Z_][A-Z0-9_]+|>\s*[A-Z][A-Z0-9_]{3,}\b|\bcheck_\w+\(|'
                      r'\bclamp\w*\(|\bbudget\w*|_BUDGET\b|_LIMIT\b|\bMAX_\w+|\w+_MAX\b|limiter|\.Allow\(')
P2P_BUDGET_RX = re.compile(r'\bheavy\(|acquire_heavy|budget|\blimiter\b|\.Allow\(|len\(\s*\w+(?:\.\w+)*\s*\)\s*>\s*\w+|'
                           r'\bpenali[sz]e\(|_BUDGET\b|_LIMIT\b|\bMAX_\w+|\w+_MAX\b|\b\w+\s*<\s*\d{2,}\b')


def _handler_def(tree, files, fname):
    for f in files:
        for fn in tree.funcs(f):
            if fn['name'] == fname and fn['recv'] is None:
                return f, fn
    return None, None


def _params_type(sig):
    m = re.search(r'\(\s*ctx\s+context\.Context\s*(?:,\s*\w+\s+(?:\*?)([\w.]+))?\s*\)', sig)
    if not m:
        return None
    return (m.group(1) or '').split('.')[-1] or None


def _variable(fields):
    """the variable-size / range fields of a params struct. Pure."""
    return [f for f, t in fields if t.startswith('[]') or t.startswith('map[') or
            (RANGE_FIELD_RX.match(f) and re.match(r'u?int', t))]


def detect_budget_census(tree, ctx):
    det = 'budget-census'
    census, findings = [], []
    rpc_files = tree.go((DEROD_RPC,))
    rpc_files = [f for f in rpc_files if f.count('/') == 3]           # the package itself, not sub-packages
    type_files = rpc_files + tree.go(('rpc/',))
    ws = 'cmd/derod/rpc/websocket_server.go'
    wl = tree.lines(ws)
    weights = {}
    for f, start in (('cmd/derod/rpc/rpc_abuse.go', r'^var remote_method_cost = map'),
                     ('cmd/derod/rpc/ws_foreign_rate.go', r'^var foreign_method_cost = map')):
        for k, (ln, _) in map_entries(tree.lines(f), start).items():
            weights.setdefault(k, (f, ln))
    bounds = {}
    pb = 'cmd/derod/rpc/param_bounds.go'
    for i, l in enumerate(tree.lines(pb)):
        if re.match(r'^\s*case\s+"', l):
            for k in re.findall(r'"([^"]+)"', l):
                bounds.setdefault(k, (pb, i + 1))
    methods = []
    for svc, start in (('DERO', r'^\s*"DERO":\s*handler\.Map\{'), ('DAEMON', r'^\s*"DAEMON":\s*handler\.Map\{'),
                       ('', r'^var historical_apis = handler\.Map\{')):
        ents = map_entries(wl, start)
        if not svc:      # the first entry sits on the map's own line
            for i, l in enumerate(wl):
                if re.search(start, l):
                    m = re.search(r'\{"([^"]+)":\s*(.*)$', l)
                    if m:
                        ents[m.group(1)] = (i + 1, m.group(2))
                    break
        for k, (ln, rest) in ents.items():
            m = re.search(r'typed_new\((\w+)\)|handler\.New\((\w+)\)', rest)
            if m:
                methods.append((f'{svc}.{k}' if svc else k, m.group(1) or m.group(2), ws, ln))
    seen = set()
    for name, fname, mf, mln in sorted(methods):
        hf, fn = _handler_def(tree, rpc_files, fname)
        if not fn:
            census.append({'surface': 'derod-rpc', 'method': name, 'handler': fname, 'state': 'handler-not-found'})
            continue
        ptype = _params_type(fn['sig'])
        fields = (struct_fields(tree, type_files, ptype) if ptype else []) or []
        var = _variable(fields)
        hb = code_only('\n'.join(body(tree.lines(hf), fn)))
        ev = []
        if name in weights:
            ev.append({'kind': 'per-method weight', 'at': f'{weights[name][0]}:{weights[name][1]}'})
        if name in bounds:
            ev.append({'kind': 'param bound', 'at': f'{bounds[name][0]}:{bounds[name][1]}'})
        for i, l in enumerate(body(tree.lines(hf), fn)):
            if BOUND_RX.search(code_only(l)):
                ev.append({'kind': 'in-handler bound', 'at': f"{hf}:{fn['start'] + i}", 'text': l.strip()[:120]})
                break
        state = 'budgeted' if ev else ('generic-bucket' if not var else 'no-budget')
        census.append({'surface': 'derod-rpc', 'method': name, 'handler': fname, 'at': f"{hf}:{fn['start']}",
                       'params': ptype, 'variable_fields': var, 'evidence': ev, 'state': state})
        if state == 'no-budget' and (hf, fname) not in seen:
            seen.add((hf, fname))
            alias = sorted(n for n, f2, _, _ in methods if f2 == fname)
            findings.append(finding(det, tree, hf, fn['start'], 'rpc-no-budget', 'low',
                                    f"derod RPC {', '.join(alias)} ({fname}) takes client-sized params "
                                    f"({', '.join(var)}) but has no per-method weight (rpc_abuse.go / ws_foreign_rate.go), "
                                    f"no param_bounds entry and no in-handler bound: a remote call costs the generic 1 token "
                                    f"whatever its size (only the request body cap applies), a loopback call is never "
                                    f"limited", key=fname,
                                    surface='derod-rpc', methods=alias))
    # wallet RPC: no limiter in walletapi/rpcserver; a method with client-sized params and no in-handler bound
    wfiles = [f for f in tree.go((WALLET_RPC,)) if f.count('/') == 2]
    wsrv = 'walletapi/rpcserver/rpc_websocket_server.go'
    wents = map_entries(tree.lines(wsrv), r'^var WalletHandler = handler\.Map\{')
    wtypes = wfiles + tree.go(('rpc/',))
    wseen = {}
    for k, (ln, rest) in sorted(wents.items()):
        m = re.search(r'handler\.New\((\w+)\)', rest)
        if m:
            wseen.setdefault(m.group(1), []).append(k)
    for fname, names in sorted(wseen.items()):
        hf, fn = _handler_def(tree, wfiles, fname)
        if not fn:
            census.append({'surface': 'wallet-rpc', 'method': names, 'handler': fname, 'state': 'handler-not-found'})
            continue
        ptype = _params_type(fn['sig'])
        fields = (struct_fields(tree, wtypes, ptype) if ptype else []) or []
        var = _variable(fields)
        ev = []
        for i, l in enumerate(body(tree.lines(hf), fn)):
            if BOUND_RX.search(code_only(l)):
                ev.append({'kind': 'in-handler bound', 'at': f"{hf}:{fn['start'] + i}", 'text': l.strip()[:120]})
                break
        state = 'budgeted' if ev else ('fixed-size' if not var else 'no-budget')
        census.append({'surface': 'wallet-rpc', 'method': names, 'handler': fname, 'at': f"{hf}:{fn['start']}",
                       'params': ptype, 'variable_fields': var, 'evidence': ev, 'state': state})
        if state == 'no-budget':
            findings.append(finding(det, tree, hf, fn['start'], 'wallet-rpc-no-budget', 'low',
                                    f"wallet RPC {', '.join(names)} ({fname}) takes client-sized params ({', '.join(var)}) "
                                    f"with no bound in the handler and no limiter in walletapi/rpcserver (an authenticated, "
                                    f"normally local caller)", key=fname, surface='wallet-rpc', methods=names))
    # P2P message handlers (p2p/controller.go set_handlers)
    pc = 'p2p/controller.go'
    pfiles = [f for f in tree.go(('p2p/',)) if f.count('/') == 1]
    pl = tree.lines(pc)
    for i, l in enumerate(pl):
        m = re.search(r'set_handler\(o,\s*"(Peer\.\w+)"', l)
        if not m:
            continue
        msg = m.group(1)
        reg = '\n'.join(pl[i:i + 4])
        meth = msg.split('.', 1)[1]
        mf, mfn = None, None
        for f in pfiles:
            for fn in tree.funcs(f):
                if fn['name'] == meth and fn['recv'] == 'Connection':
                    mf, mfn = f, fn
                    break
            if mfn:
                break
        ev = []
        if re.search(r'\bheavy\(', reg.split('})', 1)[0]):
            ev.append({'kind': 'per-peer heavy-call budget', 'at': f'{pc}:{i + 1}'})
        if mfn:
            for j, bl in enumerate(body(tree.lines(mf), mfn)):
                if P2P_BUDGET_RX.search(code_only(bl)):
                    ev.append({'kind': 'in-handler budget/cap', 'at': f"{mf}:{mfn['start'] + j}", 'text': bl.strip()[:120]})
                    break
        state = 'budgeted' if ev else 'no-budget'
        argt = re.search(r'args\s+(\w+)', l)
        fixed = bool(argt) and argt.group(1) == 'Dummy'
        census.append({'surface': 'p2p', 'method': msg, 'args': argt.group(1) if argt else None, 'at': f"{mf}:{mfn['start']}" if mfn else f'{pc}:{i + 1}',
                       'evidence': ev, 'state': state})
        if state == 'no-budget':
            af, al = (mf, mfn['start']) if mfn else (pc, i + 1)
            findings.append(finding(det, tree, af, al, 'p2p-no-budget', 'low' if fixed else 'medium',
                                    f"P2P handler {msg} has no per-peer budget, rate limit or size cap in its "
                                    f"registration or body (only the node-wide frame budget of the codec applies)"
                                    + (' ; its argument is the fixed-size Dummy' if fixed else ''), key=msg,
                                    surface='p2p', methods=[msg]))
    inputs = {'derod_rpc_methods': len(methods), 'wallet_rpc_handlers': len(wseen),
              'p2p_handlers': sum(1 for c in census if c['surface'] == 'p2p'),
              'weights': len(weights), 'param_bounds': len(bounds)}
    rules = ['derod RPC: a method is budgeted by a per-method weight (remote_method_cost / foreign_method_cost), a '
             'param_bounds.go case, or an in-handler bound (BOUND_RX); a method whose params have no slice/map/range field '
             'is bounded by the generic per-key bucket (cost 1) and is no finding; one with such a field and no budget is '
             'a finding at its handler', 'wallet RPC: the same, with no generic bucket (no limiter in walletapi/rpcserver)',
             'P2P: a handler registered through heavy(...) or whose body has a budget/cap token (P2P_BUDGET_RX) is budgeted']
    return census, findings, inputs, rules


# ═════════════════════════════ 2. fuzz-coverage (B281) ═════════════════════════════
FUZZ_SCOPE = ('transaction/', 'block/', 'cryptography/crypto/', 'cryptography/bn256/', 'proof/', 'p2p/', 'rpc/',
              'cmd/derod/rpc/', 'walletapi/', 'dvm/', 'glue/txcanon/', 'glue/txprecheck/', 'glue/emission/')
DEC_NAME_RX = re.compile(r'^(Deserialize\w*|Unmarshal\w*|Decode\w*|Decompress\w*|Parse\w*|Read_Data_Frame|\w+FromBytes|'
                         r'FromBytes|HexToKey|NewAddress\w*|Words_To_Key|ReadFrom)$')
NET_SCOPE = ('transaction/', 'block/', 'cryptography/', 'proof/', 'p2p/', 'rpc/', 'cmd/derod/rpc/', 'dvm/', 'glue/')


class CallGraph:
    """name-resolved calls between first-party funcs (tests included: fuzz helpers live there). A call site resolves to
    the funcs of that name, narrowed to the receiver type when the body names the variable's type (var x T, new(T),
    T{...}, a (*T)(v) conversion); an ambiguous untyped call resolves within the caller's package dir only."""

    def __init__(self, tree):
        self.tree, self.byname, self._body = tree, {}, {}
        for f in tree.go(tests=True):
            for fn in tree.funcs(f):
                self.byname.setdefault(fn['name'], []).append((f, fn))

    def body(self, f, fn):
        k = (f, fn['start'])
        if k not in self._body:      # without the signature line: a signature is no call
            self._body[k] = code_only('\n'.join(body(self.tree.lines(f), fn)[1:]))
        return self._body[k]

    def callees(self, f, b):
        d = f.rsplit('/', 1)[0]
        out = []
        for m in CALLSITE_RX.finditer(b):
            conv, var, name = m.group(1), m.group(2), m.group(3)
            cands = self.byname.get(name, [])
            if not cands:
                continue
            if not conv and not var:          # an unqualified call is a free func (or a builtin: none here)
                cands = [g for g in cands if g[1]['recv'] is None]
                same = [g for g in cands if g[0].rsplit('/', 1)[0] == d]
                out += same or cands
                continue
            t = conv or (var_type(b, var) if var else None)
            if t and any(g[1]['recv'] == t for g in cands):
                cands = [g for g in cands if g[1]['recv'] == t]
            elif len(cands) > 1:
                same = [g for g in cands if g[0].rsplit('/', 1)[0] == d]
                cands = same or ([] if var else cands)
            out += cands
        return out

    def reach(self, f, b, depth=4):
        """{(file, start)} of the funcs reachable from body text b of file f within `depth` calls. Pure."""
        seen, frontier = set(), [(f, b)]
        for _ in range(depth):
            nxt = []
            for ff, bb in frontier:
                for g, gfn in self.callees(ff, bb):
                    k = (g, gfn['start'])
                    if k not in seen:
                        seen.add(k)
                        nxt.append((g, self.body(g, gfn)))
            frontier = nxt
        return seen


def fuzz_targets(tree, cg=None):
    """[{name, file, line, reach, seed}] of every Go Fuzz* target: the funcs its body reaches (CallGraph) and
    whether it has a seed corpus. Pure over the tree (depth 4)."""
    cg = cg or CallGraph(tree)
    out = []
    for f in tree.go(only_tests=True):
        for fn in tree.funcs(f):
            if not (fn['name'].startswith('Fuzz') and '*testing.F' in fn['sig']):
                continue
            b = cg.body(f, fn)
            pkg = f.rsplit('/', 1)[0] + '/'
            seed = 'f.Add(' in b or (tree.root / pkg / 'testdata' / 'fuzz' / fn['name']).is_dir()
            out.append({'name': fn['name'], 'file': f, 'line': fn['start'], 'reach': cg.reach(f, b), 'seed': seed})
    return out


def detect_fuzz_coverage(tree, ctx):
    det = 'fuzz-coverage'
    cg = CallGraph(tree)
    targets = fuzz_targets(tree, cg)
    census, findings = [], []
    decs = []
    for f in tree.go(FUZZ_SCOPE):
        for fn in tree.funcs(f):
            if DEC_NAME_RX.match(fn['name']) and fn['name'][0].isupper() and 'Encode' not in fn['name'] and \
                    not (fn['recv'] or 'X')[0].islower():
                decs.append((f, fn))
    for f, fn in decs:
        recv, name = fn['recv'], fn['name']
        cov = [t for t in targets if (f, fn['start']) in t['reach']]
        label = f'{recv}.{name}' if recv else name
        census.append({'decoder': label, 'at': f"{f}:{fn['start']}", 'targets': [f"{t['name']} ({t['file']}:{t['line']})" for t in cov],
                       'seeded': any(t['seed'] for t in cov)})
        if not cov:
            net = f.startswith(NET_SCOPE)
            findings.append(finding(det, tree, f, fn['start'], 'no-fuzz-target', 'medium' if net else 'low',
                                    f"decoder {label} is reached by no Go fuzz target (no Fuzz* body reaches it within "
                                    f"4 calls)", key=label, decoder=label))
    for t in targets:
        if not t['seed']:
            findings.append(finding(det, tree, t['file'], t['line'], 'no-seed-corpus', 'low',
                                    f"fuzz target {t['name']} has no seed corpus (no f.Add, no testdata/fuzz/{t['name']})",
                                    key=t['name'], target=t['name']))
    census.append({'fuzz_targets': [f"{t['name']} ({t['file']}:{t['line']}){'' if t['seed'] else ' NO-SEED'} reaches "
                                    f"{len(t['reach'])} funcs" for t in targets]})
    inputs = {'decoders': len(decs), 'fuzz_targets': len(targets), 'scope_files': len(tree.go(FUZZ_SCOPE)),
              'covered': sum(1 for c in census if c.get('targets'))}
    rules = ['decoder: an exported func or method of an exported type in the scope whose name matches DEC_NAME_RX '
             '(Deserialize*, Unmarshal*, Decode*, Decompress*, Parse*, Read_Data_Frame, *FromBytes, HexToKey, NewAddress*, '
             'Words_To_Key, ReadFrom), Encode* aside', 'covered: a Fuzz*(f *testing.F) body reaches it within 4 calls '
             '(CallGraph: by name, narrowed by the variable type the body names; an ambiguous untyped call stays in the '
             "caller's package)", 'seeded: f.Add( in the target or a testdata/fuzz/<Target> directory',
             'implicit decoding by encoding/json (UnmarshalJSON/UnmarshalText of a field type) is not followed']
    return census, findings, inputs, rules


# ═════════════════════════════ 3. error-paths (B282) ═════════════════════════════
# conventional discards, never reported: closing / deadline / print / cleanup calls
BENIGN_CALLS = {'Close', 'SetDeadline', 'SetReadDeadline', 'SetWriteDeadline', 'Fprintf', 'Fprintln', 'Fprint', 'Printf',
                'Println', 'Print', 'Remove', 'RemoveAll', 'Unsetenv', 'Setenv', 'SetNoDelay', 'SetKeepAlive',
                'SetKeepAlivePeriod', 'Shutdown', 'Kill', 'Signal', 'Release', 'Sync'}
# standard-library calls whose last result is an error, by their package-qualified name ('*' = any suffix)
STD_QUAL = ('strconv.Atoi', 'strconv.Parse*', 'strconv.Unquote', 'hex.DecodeString', 'hex.Decode', 'json.Unmarshal',
            'json.Marshal', 'json.MarshalIndent', 'io.ReadFull', 'io.ReadAll', 'io.Copy', 'io.CopyN', 'ioutil.ReadAll',
            'ioutil.ReadFile', 'ioutil.WriteFile', 'ioutil.ReadDir', 'os.ReadFile', 'os.WriteFile', 'os.MkdirAll',
            'os.Mkdir', 'os.Open', 'os.OpenFile', 'os.Create', 'os.Stat', 'os.Lstat', 'os.Rename', 'os.ReadDir',
            'os.Getwd', 'filepath.Abs', 'filepath.Rel', 'filepath.Glob', 'net.SplitHostPort', 'net.ParseCIDR',
            'net.Dial', 'net.DialTimeout', 'net.Listen', 'net.ResolveTCPAddr', 'net.ResolveUDPAddr', 'url.Parse',
            'time.Parse', 'time.ParseDuration', 'binary.Read', 'binary.Write', 'cbor.Marshal', 'cbor.Unmarshal',
            'rand.Read', 'base64.StdEncoding.DecodeString', 'base64.URLEncoding.DecodeString',
            'base64.RawStdEncoding.DecodeString', 'base64.RawURLEncoding.DecodeString')
ERR_LHS_RX = re.compile(r'^\s*((?:[\w.\[\]*]+\s*,\s*)*)err\s*(:?=)\s*(.+)$')
DISCARD1_RX = re.compile(r'^\s*_\s*=\s*(.+)$')
DISCARDN_RX = re.compile(r'^\s*((?:[\w.\[\]*]+|_)\s*,\s*)+_\s*:?=\s*(.+)$')
QCALL_RX = re.compile(r'^((?:[\w]+(?:\([^()]*\))?\.)*)(\w+)\s*\(')
DECODE_SRC_RX = re.compile(r'^\s*(\w+)\s*,\s*\w+\s*:?=\s*(?:hex\.DecodeString|base64\.\w+\.DecodeString|io(?:util)?\.ReadAll)\(')
PANIC_SCOPE = ('p2p/', 'block/', 'transaction/', 'cryptography/', 'cmd/derod/', 'rpc/', 'blockchain/', 'glue/', 'proof/',
               'walletapi/')


class ErrIndex:
    """which first-party calls return an error: free funcs per package dir, methods per (receiver type, name)."""

    def __init__(self, tree):
        self.free, self.meth, self.pkgs = {}, {}, set()
        for f in tree.go():
            d = f.rsplit('/', 1)[0] if '/' in f else '.'
            self.pkgs.add(d)
            for fn in tree.funcs(f):
                e = returns_error(fn['sig'])
                if fn['recv']:
                    self.meth[(fn['recv'], fn['name'])] = self.meth.get((fn['recv'], fn['name'])) or e
                else:
                    self.free[(d, fn['name'])] = self.free.get((d, fn['name'])) or e

    def aliases(self, text):
        """{alias: package dir} of a file's first-party imports. Pure."""
        out = {}
        for m in re.finditer(r'^\s*(?:import\s+)?(\w+\s+)?"' + re.escape(GOMOD) + r'([^"]+)"', text, re.M):
            d = m.group(2)
            out[(m.group(1) or d.rsplit('/', 1)[-1]).strip()] = d
        return out


def call_returns_error(expr, pkgdir, fn, fbody, idx, aliases):
    """(name, True) when the call that `expr` starts with returns an error by the rules of detect_error_paths; the
    name and None when it cannot be told (not reported). Pure."""
    m = QCALL_RX.match(expr.strip())
    if not m:
        return None, None
    chain, name = m.group(1).rstrip('.'), m.group(2)
    if name in BENIGN_CALLS:
        return name, 'benign'
    if not chain:
        return name, True if idx.free.get((pkgdir, name)) else None
    if any(re.fullmatch(q.replace('.', r'\.').replace('*', r'\w*'), f'{chain}.{name}') for q in STD_QUAL):
        return name, True
    if name in ('Decode', 'Encode') and re.search(r'\bNew(?:De|En)coder\(', chain):
        return name, True
    if '.' not in chain and '(' not in chain:
        if chain in aliases:
            return name, True if idx.free.get((aliases[chain], name)) else None
        t = fn['recv'] if re.match(r'^func\s*\(\s*' + re.escape(chain) + r'\b', fn['sig']) else var_type(fbody, chain)
        if t and idx.meth.get((t, name)):
            return name, True
    return name, None


def _named_err(sig):
    return bool(re.search(r'\)\s*\([^()]*\berr\s+error\s*\)\s*\{?\s*$', sig.rstrip()))


def depths(code_lines):
    """the brace depth at the start of each line (comments already removed; braces in strings are rare). Pure."""
    out, d = [], 0
    for l in code_lines:
        out.append(d)
        s = STR_RX.sub('""', l)
        d += s.count('{') - s.count('}')
    return out


def err_unused(code, dep, i, hi, named):
    """True when the err assigned on line i (0-based) is never read: in its own block (same depth, the block not left)
    the next plain assignment of err or a return that does not name it comes first; leaving the block keeps looking;
    the end of the function reads it only through a named err result. Pure."""
    d0 = dep[i]
    left = False
    for j in range(i + 1, hi):
        t = code[j] if j < len(code) else ''
        if dep[j] < d0 or (dep[j] == d0 and re.match(r'^\s*(?:\}|case\b|default\s*:)', t)):
            left = True                                       # the block (or the switch branch) ends: `} else {`, `case`
        mj = ERR_LHS_RX.match(t)
        reads = re.search(r'\berr\b', mj.group(3)) if mj else re.search(r'\berr\b', t)
        if reads:
            return False
        same_block = dep[j] == d0 and not left
        if mj and same_block:
            return True                                       # overwritten unread
        if same_block and re.match(r'^\s*return\b', t):
            return not (named and re.match(r'^\s*return\s*$', t))
    return not named


def in_closure(code, dep, lo, i):
    """True when line i (0-based) sits inside a func literal opened after the function's first line: an assignment
    there sets a captured or named variable of the literal, which this scan cannot follow. Pure."""
    for k in range(lo, i):
        if re.search(r'\bfunc\s*\(', code[k]) and k + 1 < len(dep):
            cd = dep[k + 1]
            if cd > dep[k] and min(dep[k + 1:i + 1]) >= cd:
                return True
    return False


def detect_error_paths(tree, ctx):
    det = 'error-paths'
    files = tree.go()
    idx = ErrIndex(tree)
    census, findings = [], []
    counts = {'discard': 0, 'unchecked': 0, 'panic': 0, 'index': 0, 'benign_skipped': 0, 'unknown_callee_skipped': 0}
    for f in files:
        ls = tree.lines(f)
        code = code_only('\n'.join(ls)).split('\n')
        dep = depths(code)
        funcs = tree.funcs(f)
        pkgdir = f.rsplit('/', 1)[0] if '/' in f else '.'
        aliases = idx.aliases(tree.text(f) or '')
        for fn in funcs:
            named = _named_err(fn['sig'])
            lo, hi = fn['start'], fn['end']
            fbody = '\n'.join(code[lo - 1:hi])
            seen_kind = set()
            for i in range(lo, hi):       # 0-based index i -> line i + 1 (the signature line skipped)
                s = code[i] if i < len(code) else ''
                if not s.strip():
                    continue
                m1, mn = DISCARD1_RX.match(s), DISCARDN_RX.match(s)
                expr = (m1.group(1) if m1 else (mn.group(2) if mn else None))
                if expr is not None:
                    c, verdict = call_returns_error(expr, pkgdir, fn, fbody, idx, aliases)
                    if verdict == 'benign':
                        counts['benign_skipped'] += 1
                    elif verdict:
                        counts['discard'] += 1
                        findings.append(finding(det, tree, f, i + 1, 'discarded-error', 'low',
                                                f"the error of {c}(...) is discarded in {fn['name']}",
                                                key=f"{fn['name']}|{s.strip()}", func=fn['name']))
                        continue
                    elif c:
                        counts['unknown_callee_skipped'] += 1
                me = ERR_LHS_RX.match(s)
                if me and not re.search(r';\s*err\s*[!=]=', s) and not s.lstrip().startswith(('if ', 'for ', 'switch ', 'case ')) \
                        and not re.search(r'\berr\b', me.group(3)) and not in_closure(code, dep, lo, i) \
                        and err_unused(code, dep, i, hi, named):
                    counts['unchecked'] += 1
                    findings.append(finding(det, tree, f, i + 1, 'unchecked-err',
                                            'low' if re.match(r'^\s*nil\s*$', me.group(3)) else 'medium',
                                            f"err assigned in {fn['name']} is never read: it is overwritten or the "
                                            f"function returns without it", key=f"{fn['name']}|{s.strip()}", func=fn['name']))
                    continue
                if not f.startswith(PANIC_SCOPE):
                    continue
                if DEC_NAME_RX.match(fn['name']) and re.search(r'\bpanic\(', s) and 'panic' not in seen_kind:
                    seen_kind.add('panic')
                    counts['panic'] += 1
                    findings.append(finding(det, tree, f, i + 1, 'panic-in-decoder', 'medium',
                                            f"decoder {(fn['recv'] + '.') if fn['recv'] else ''}{fn['name']} panics on "
                                            f"input it cannot decode instead of returning an error (callers must recover)",
                                            key=f"{fn['recv']}.{fn['name']}", func=fn['name']))
                md = DECODE_SRC_RX.match(s)
                if md:
                    v = md.group(1)
                    for j in range(i + 1, hi):
                        t = code[j] if j < len(code) else ''
                        if re.search(r'\blen\(\s*' + re.escape(v) + r'\s*\)', t):
                            break
                        if re.search(r'\b' + re.escape(v) + r'\[[^\]]', t) and not re.search(r'\b' + re.escape(v) + r'\[\s*:\s*\]', t):
                            counts['index'] += 1
                            findings.append(finding(det, tree, f, j + 1, 'index-after-decode', 'medium',
                                                    f"{v} (decoded at line {i + 1}) is indexed in {fn['name']} with no "
                                                    f"length check after the decode", key=f"{fn['name']}|{v}|{t.strip()}",
                                                    func=fn['name']))
                            break
    inputs = {'go_files': len(files), 'error_returning_free': sum(1 for v in idx.free.values() if v),
              'error_returning_methods': sum(1 for v in idx.meth.values() if v), **counts}
    rules = ['discarded-error: `_ = f(...)` or `a, _ := f(...)` where f returns an error: a qualified standard call in '
             'STD_QUAL, a json New(De|En)coder chain, a first-party free func of the package (or of an imported first-party '
             'package), or a method of the receiver / a local whose type the body names; an unresolvable callee is '
             'counted (unknown_callee_skipped), never reported; BENIGN_CALLS (Close, deadlines, prints, cleanup) counted, '
             'never reported', 'unchecked-err: `err =` / `x, err :=` (not an if/for/switch init) whose value is not read: '
             'in its own block the next plain err assignment or a return without err comes first, or the function ends '
             'without a named err result (a read anywhere after it, also after leaving the block, counts)',
             'panic-in-decoder: the first panic( in a decoder (DEC_NAME_RX) of the network scope', 'index-after-decode: a '
             'slice from hex/base64 DecodeString or ReadAll indexed before any len() of it', 'vendor, testdata, _test.go '
             'and _-prefixed dirs excluded; the allow-list accepts a finding with a reason']
    return census, findings, inputs, rules


# ═════════════════════════════ 4. crypto-input (B283) ═════════════════════════════
CRYPTO_SCOPE = ('cryptography/bn256/', 'cryptography/crypto/', 'proof/', 'rpc/address.go', 'walletapi/wallet.go',
                'walletapi/mnemonics/mnemonics.go')
CENTRY_RX = re.compile(r'^(Unmarshal\w*|Decode\w*|Decompress\w*|Deserialize\w*|SetBytes|FromBytes|HexToKey|unmarshalpoint|'
                       r'NewAddress\w*|Words_To_Key|Prove)$')
CHECKS = {
    'canonical': (re.compile(r'exceeds modulus|equals modulus|\.Cmp\((?:bn256\.)?P\)\s*>=|non-?canonical|IsCanonical'),
                  'does not reject a coordinate at or above the field modulus P (a non-canonical encoding is accepted)'),
    'flag': (re.compile(r'\[\s*32\s*\]\s*>\s*(?:0x0?)?1\b|\[\s*32\s*\]\s*!=\s*0x0?0\s*&&[^\n]*\[\s*32\s*\]\s*!=\s*0x0?1|'
                        r'invalid (?:sign|flag)'),
             'does not reject a sign/flag byte other than its two defined values'),
    'oncurve': (re.compile(r'IsOnCurve\(\)|isOnCurve\('), 'does not check that the decoded point is on the curve'),
    'order': (re.compile(r'\.Cmp\((?:bn256\.)?Order\)|>=\s*(?:bn256\.)?Order\b|exceeds (?:the )?order'),
              'does not reject a scalar at or above the group order'),
    # a secret key that is 0 mod the order gives the identity as public key (walletapi/wallet.go check_seed_scalar);
    # seeds >= order but not 0 mod order are kept on purpose there (v2 payload key derivation), so 'order' is not required
    'zeroscalar': (re.compile(r'Mod\([^()]*Order\)\.Sign\(\)\s*==\s*0|check_seed_scalar\('),
                   'does not reject a secret scalar that is 0 modulo the group order'),
    'identity': (re.compile(r'if [^\n]*(?:IsInfinity\(\)|IsZero\(\)|infinity|identity)[^\n]*\{\s*\n\s*return\b[^\n]*'
                            r'(?:err|Err|errors\.New|fmt\.Errorf|false)'),
                 'does not reject the identity element'),
}


def _crypto_class(f, fn, b):
    n, r = fn['name'], fn['recv'] or ''
    if n in ('HexToKey',) or r == 'Key':      # key_old.go Key: a 32-byte container (hashes, ids), no curve point
        return None
    if n.startswith('NewAddress'):
        return 'key-public'
    if r == 'BNRed':        # an integer container: the secret-key policy is checked where an account is made
        return None
    if n == 'Words_To_Key':
        return 'key-secret'
    if n == 'Prove':        # a payment-proof parser: decodes addresses and a payload, no scalar of its own
        return 'balance'
    if n == 'Deserialize' and r in ('Proof', 'InnerProduct', 'Statement'):
        return 'proof'
    if r in ('NonceBalance', 'ElGamal'):
        return 'balance'
    if n == 'SetBytes' and 'big.Int' in b:
        return 'scalar'
    if r == 'GT':
        return 'point-gt'
    if 'Compress' in n or (r == 'Point' and n == 'UnmarshalText'):
        return 'point-compressed'
    if r in ('G1', 'G2', 'Point') or n == 'unmarshalpoint':     # unmarshalpoint: 64-byte uncompressed hex
        return 'point'
    return None


# identity: the compressed form has no encoding of the identity (walletapi/wallet.go check_seed_scalar comment: "the
# identity has no decodable address encoding"), so only the uncompressed decoders, which map (0,0) to it, need the check
REQUIRED = {'point-compressed': ('canonical', 'flag'), 'point': ('canonical', 'oncurve', 'identity'),
            'point-gt': ('canonical',), 'scalar': ('order',), 'proof': ('order',), 'key-public': (),
            'key-secret': ('zeroscalar',), 'balance': ()}
SEVERE = ('canonical', 'flag', 'order', 'oncurve', 'zeroscalar')


def returns_error(sig):
    sig = sig.rsplit('{', 1)[0].rstrip()
    m = re.search(r'\)\s*\(([^()]*)\)\s*$', sig)
    res = m.group(1) if m else sig[sig.rfind(')') + 1:]
    return bool(re.search(r'\berror\s*$', res.strip()))


CALLSITE_RX = re.compile(r'(?:\(\*?(?:\w+\.)?(\w+)\)\([\w.]+\)\)?\.|\b(\w+)\.|(?<![\w.]))(\w+)\(')


def var_type(b, var):
    """the type a body gives local `var` (new(T), &T{...}, T{...}, var v T), package prefix dropped; else None. Pure."""
    v = re.escape(var)
    m = re.search(r'\b' + v + r'\s*:?=\s*(?:new\(\*?|&)?(?:\w+\.)?([A-Z]\w*|[a-z]\w*)(?:\)|\{)', b) or \
        re.search(r'\bvar\s+' + v + r'\s+\*?(?:\w+\.)?(\w+)', b)
    return m.group(1) if m else None


def discarded(b, callee, gfn):
    """True when every call of `callee` in body text `b` is a bare statement and the callee returns an error: the
    caller drops the result, so the callee's check does not protect it. Pure."""
    if not returns_error(gfn['sig']):
        return False
    calls = [l for l in b.split('\n') if re.search(r'(?:\.|\b)' + re.escape(callee) + r'\(', l)]
    bare = [l for l in calls if re.match(r'^\s*[\w.\[\]()*&]*?\b' + re.escape(callee) + r'\(', l)
            and not re.match(r'^\s*(?:return|if|for|switch|case)\b', l)]
    return bool(calls) and len(bare) == len(calls)


def detect_crypto_input(tree, ctx):
    det = 'crypto-input'
    files = tree.go(CRYPTO_SCOPE)
    allf = tree.go(('cryptography/', 'proof/', 'rpc/', 'walletapi/'))
    byname = {}
    for f in allf:
        for fn in tree.funcs(f):
            byname.setdefault(fn['name'], []).append((f, fn))
    bodies = {}

    def btext(f, fn):
        k = (f, fn['start'])
        if k not in bodies:      # the body without its signature line (a signature is no call)
            bodies[k] = code_only('\n'.join(body(tree.lines(f), fn)[1:]))
        return bodies[k]

    def evidence(f, fn, depth=0, seen=None):
        """{check: 'file:line'} found in the body or (to depth 3) in the bodies of the funcs it calls, by name."""
        seen = seen if seen is not None else set()
        if (f, fn['start']) in seen or depth > 3:
            return {}
        seen.add((f, fn['start']))
        b = btext(f, fn)
        ev = {}
        for c, (rx, _) in CHECKS.items():
            m = rx.search(b)
            if m:
                ev[c] = f"{f}:{fn['start'] + 1 + b[:m.start()].count(chr(10))}"
        for line in b.split('\n'):
            for m in CALLSITE_RX.finditer(line):
                conv, var, callee = m.group(1), m.group(2), m.group(3)
                cands = byname.get(callee, [])
                t = conv or (var_type(b, var) if var else None)
                if t and any(gfn['recv'] == t for _, gfn in cands):
                    cands = [(g, gfn) for g, gfn in cands if gfn['recv'] == t]
                bare = bool(re.match(r'^\s*[\w.\[\]()*&]*?\b' + re.escape(callee) + r'\(', line)) and \
                    not re.match(r'^\s*(?:return|if|for|switch|case)\b', line)
                for g, gfn in cands[:6]:
                    if bare and returns_error(gfn['sig']):    # a check whose error the caller drops does not protect it
                        continue
                    for c, at in evidence(g, gfn, depth + 1, seen).items():
                        ev.setdefault(c, at)
        return ev

    def callers_cover(f, fn, missing):
        """(callers, covered): the first-party funcs calling fn by name; covered when there is one and every one of
        them has the missing checks itself (the check lives at the only places the decoded value enters)."""
        rx = re.compile(r'(?:\.|\b)' + re.escape(fn['name']) + r'\(')
        calls = []
        for g in tree.go():
            t = tree.text(g) or ''
            if fn['name'] + '(' not in t:
                continue
            gl = tree.lines(g)
            for gfn in tree.funcs(g):
                if (g, gfn['start']) == (f, fn['start']):
                    continue
                if any(rx.search(code_only(x)) for x in body(gl, gfn)[1:]):
                    calls.append((g, gfn))
        if not calls:
            return [], False
        return [f"{g}:{gfn['start']}" for g, gfn in calls], all(set(missing) <= set(evidence(g, gfn)) for g, gfn in calls)

    census, findings = [], []
    for f in files:
        for fn in tree.funcs(f):
            if not CENTRY_RX.match(fn['name']) or (fn['recv'] or 'X')[0].islower():
                continue
            b = btext(f, fn)
            cls = _crypto_class(f, fn, b)
            if cls is None:
                continue
            ev = evidence(f, fn)
            need = REQUIRED[cls]
            missing = [c for c in need if c not in ev]
            label = f"{fn['recv'] + '.' if fn['recv'] else ''}{fn['name']}"
            callers, covered = callers_cover(f, fn, missing) if missing else ([], False)
            census.append({'entry': label, 'at': f"{f}:{fn['start']}", 'class': cls, 'required': list(need),
                           'evidence': ev, 'missing': missing, 'callers': callers[:12], 'covered_by_callers': covered})
            if missing and not covered:
                sev = 'medium' if set(missing) & set(SEVERE) and callers else 'low'
                findings.append(finding(det, tree, f, fn['start'], 'non-canonical-accepted', sev,
                                        f"{label} ({cls}) " + '; '.join(CHECKS[c][1] for c in missing) +
                                        ' (no check in its body or the decoders it calls' +
                                        ('; no first-party caller' if not callers else '') + ')', key=label, entry=label,
                                        missing=missing, entry_class=cls, callers=len(callers)))
    inputs = {'scope_files': len(files), 'entries': len(census), 'functions_indexed': sum(len(v) for v in byname.values())}
    rules = ['entry: a func in CRYPTO_SCOPE named like CENTRY_RX (exported receiver), classified point-compressed / point / '
             'point-gt / scalar / proof / key / key-public / key-secret / balance', 'evidence: a CHECKS pattern in the '
             'body, or in a body it calls (by name, depth 3), comments stripped', 'required per class: REQUIRED; a missing '
             'canonical/flag/order/on-curve check is medium, a missing identity rejection low', 'defensive descriptions '
             'only (rft §5): what the decoder does not reject, never how to construct an input']
    return census, findings, inputs, rules


# ═════════════════════════════ 5. value-paths (B284) ═════════════════════════════
VALUE_SCOPE = ('blockchain/', 'transaction/', 'dvm/', 'cmd/derod/rpc/*emission*')
AUDITOR = ('glue/emission/', 'cmd/derod/rpc/emission_audit*', 'tools/emission-audit/')
# a value move: a homomorphic credit (.Plus), a balance delta (Balance.Add/Sub), the block reward, an SC deposit taken
# from a burn value, an SC external send, a fee an execution function returns into the block's reward
VALUE_OP_RX = re.compile(r'\.Plus\(|\bBalance\.Add\(|\bBalance\.Sub\(|\bfull_reward\b|=\s*[\w.\[\]]+\.BurnValue\s*$|'
                         r'\bSendExternal\(|^\s*(?:return\s+[\w.]+\.Fees\(\)|gas\s*=\s*[\w.]+\.Fees\(\))')
VALUE_SKIP_FN_RX = re.compile(r'(?i)^(?:init|verify\w*|\w*_verify\w*|Gas\w*)$')   # tables, verification, gas helpers
CLASSES = (  # (class, pattern over the enclosing function name + the raw line with its comment)
    ('premine', re.compile(r'premine|genesis', re.I)),
    ('registration', re.compile(r'zerobalance|registration|IsRegistration', re.I)),
    ('coinbase', re.compile(r'reward|miner', re.I)),
    ('burn', re.compile(r'burn', re.I)),
    ('fee', re.compile(r'\bfee', re.I)),
    ('sc-payout', re.compile(r'send_|SendExternal|transfer|SCID|sc_|_sc\b|asset|external', re.I)),
    ('transfer', re.compile(r'echanges|Balance\.(?:Add|Sub)|balance', re.I)),
)
# the auditor's code that accounts each class (glue/emission first: the auditor proper)
AUDIT_RX = {'premine': r'\bPREMINE\b', 'registration': r'\bregBonusTotal\s*\+=',
            'coinbase': r'\bSplitReward\(', 'burn': r'\.BurnValue\b', 'fee': r'\.Fees\(\)',
            'sc-payout': r'\bmatchPayout\(', 'transfer': r'\bsumC\b'}
DEF_RX = re.compile(r'^\s*(?:func\b|var\b|const\b|type\b|//)|`json:')
PIN_STOP = {'init', 'main', 'String', 'Get', 'Set', 'Add', 'Sub', 'Plus'}


def detect_value_paths(tree, ctx):
    det = 'value-paths'
    files = [f for f in tree.go(VALUE_SCOPE) if f not in set(tree.go(AUDITOR))]
    aud_files = sorted(tree.go(AUDITOR), key=lambda f: (not f.startswith('glue/emission/'), f))   # the auditor proper first
    aud = {}
    for c, rx in AUDIT_RX.items():
        for f in aud_files:
            for i, l in enumerate(tree.lines(f)):
                if re.search(rx, code_only(l)) and not DEF_RX.match(l):      # a use, not the declaration
                    aud[c] = f'{f}:{i + 1}'
                    break
            if c in aud:
                break
    tests = [(f, code_only(tree.text(f) or '')) for f in tree.go(only_tests=True)]
    kats = []
    for p in sorted((tree.root / 'harness' / 'kat').glob('test_*.py')):
        rel = p.relative_to(tree.root).as_posix()
        kats.append((rel, tree.text(rel) or ''))
    pin_cache = {}

    def pinned(name):
        if name in PIN_STOP or len(name) < 5:
            return None
        if name not in pin_cache:
            rx = re.compile(r'\b' + re.escape(name) + r'\b')
            pin_cache[name] = next((f for f, t in tests + kats if rx.search(t)), None)
        return pin_cache[name]

    census, findings = [], []
    for f in files:
        ls = tree.lines(f)
        code = code_only('\n'.join(ls)).split('\n')
        funcs = tree.funcs(f)
        for i, s in enumerate(code):
            if not VALUE_OP_RX.search(s) or DEF_RX.match(ls[i]):
                continue
            fn = enclosing(funcs, i + 1)
            if not fn:
                continue
            name = fn['name']
            if VALUE_SKIP_FN_RX.match(name):
                continue
            ctxt = f"{name} {ls[i]}"
            cls = next((c for c, rx in CLASSES if rx.search(ctxt)), 'transfer')
            if f.startswith('dvm/') and name.startswith('dvm_'):
                pin = pinned(name) or pinned(name[4:].upper()) or pinned(name[4:])
            else:
                pin = pinned(name)
            a = aud.get(cls)
            census.append({'at': f'{f}:{i + 1}', 'func': name, 'class': cls, 'auditor': a, 'pinned_by': pin,
                           'line': ls[i].strip()[:140]})
            if not a and not pin:
                findings.append(finding(det, tree, f, i + 1, 'value-path-unchecked', 'medium',
                                        f"{cls} value path in {name} is neither checked by the emission auditor (no "
                                        f"{AUDIT_RX[cls]!r} in {', '.join(AUDITOR)}) nor pinned by a test naming {name}",
                                        key=f'{name}|{cls}|{ls[i].strip()}', func=name, value_class=cls))
            elif not pin:
                pass
    inputs = {'scope_files': len(files), 'value_sites': len(census), 'auditor_files': len(aud_files),
              'test_files': len(tests), 'kat_files': len(kats),
              'by_class': {c: sum(1 for x in census if x['class'] == c) for c, _ in CLASSES},
              'audited_classes': aud, 'unpinned_sites': sum(1 for x in census if not x['pinned_by'])}
    rules = ['value site: a line of VALUE_SCOPE (the auditor itself aside) matching VALUE_OP_RX (a homomorphic credit '
             '.Plus(, a Balance.Add/Sub, full_reward, an SC deposit from a BurnValue, SendExternal, a fee returned by an '
             'execution function) outside a declaration/comment and outside init/verify/Gas* functions',
             'class: the first CLASSES pattern matching the enclosing function name + the line',
             'audited: the emission auditor source (AUDITOR, glue/emission first) has a code line (not a declaration) '
             'matching the class pattern AUDIT_RX',
             'pinned: a first-party _test.go or harness/kat/test_*.py names the enclosing function (a DVM builtin: also its '
             'SC name)', 'finding: a site neither audited nor pinned (census keeps every site, audited-only ones included)']
    return census, findings, inputs, rules


# ═════════════════════════════ 6. signal-coverage (B285) ═════════════════════════════
LOG_ERR_RX = re.compile(r'\b\w*[Ll]ogger(?:\.V\(\d+\))?\.Error\((.*)$')
LOG_WARN_RX = re.compile(r'\b\w*[Ll]ogger(?:\.V\(\d+\))?\.Info\(\s*"(WARNING[^"]*)"')
EVENT_RX = re.compile(r'(?i)reject|refus|\bban|drop|discard|invalid|penal|timeout|stale|orphan')
COUNTER_RX = re.compile(r'\.Inc\(\)|GetOrCreateCounter|\.Add\(\s*\d|metrics\.\w+\.(?:Inc|Add)|_total\b')
TS = '2026-11-13T00:00:00.000-0800'


def derod_packages(tree):
    """the first-party package dirs derod links (import closure from cmd/derod). Pure over the tree."""
    pk = {}
    for f in tree.go():
        d = f.rsplit('/', 1)[0] if '/' in f else '.'
        pk.setdefault(d, []).append(f)
    seen, todo = set(), ['cmd/derod']
    while todo:
        d = todo.pop()
        if d in seen or d not in pk:
            continue
        seen.add(d)
        for f in pk[d]:
            for imp in re.findall(r'"' + re.escape(GOMOD) + r'([^"]+)"', tree.text(f) or ''):
                if imp not in seen:
                    todo.append(imp)
    return sorted(seen)


def _log_message(args):
    """(message, error text) of a logr Error call's argument text. Pure."""
    args = args.strip()
    m = re.match(r'^(?:fmt\.Errorf|errors\.New)\(\s*"((?:[^"\\]|\\.)*)"', args)
    errtxt = m.group(1) if m else ''
    rest = args
    if m:
        depth, j = 0, 0
        for j, c in enumerate(args):
            depth += c == '('
            depth -= c == ')'
            if depth == 0 and c == ')':
                break
        rest = args[j + 1:]
    else:
        rest = args.split(',', 1)[1] if ',' in args else ''
    mm = re.match(r'^\s*,?\s*"((?:[^"\\]|\\.)*)"', rest)
    return (mm.group(1) if mm else ''), errtxt


def detect_signal_coverage(tree, ctx):
    det = 'signal-coverage'
    ec = ctx.get('ec') or _load_mod('det_error_census', HERE / 'error_census.py')   # r31 d4: a KAT may pass a census stub
    pkgs = derod_packages(tree)
    files = [f for f in tree.go() if (f.rsplit('/', 1)[0] if '/' in f else '.') in pkgs]
    census, findings = [], []
    n_lit = 0
    counting = {}           # package dir -> the funcs whose body increments a counter (a refusal helper counts too)
    for f in files:
        d = f.rsplit('/', 1)[0] if '/' in f else '.'
        for fn in tree.funcs(f):
            if COUNTER_RX.search(code_only('\n'.join(body(tree.lines(f), fn)[1:]))):
                counting.setdefault(d, set()).add(fn['name'])
    for f in files:
        ls = tree.lines(f)
        code = code_only('\n'.join(ls)).split('\n')
        funcs = tree.funcs(f)
        cnt = counting.get(f.rsplit('/', 1)[0] if '/' in f else '.', set())
        for i, s in enumerate(code):
            me, mw = LOG_ERR_RX.search(s), LOG_WARN_RX.search(s)
            if not me and not mw:
                continue
            if me:
                msg, err = _log_message(me.group(1))
                lv, rec = 'ERROR', {'L': 'ERROR', 'N': '', 'M': msg, 'error': err, 'T': TS}
            else:
                msg, err = mw.group(1), ''
                lv, rec = 'WARN', {'L': 'INFO', 'N': '', 'M': msg, 'T': TS}
            if not (msg or err):
                continue
            n_lit += 1
            cls, why, _ = ec.classify(rec, lv, None, err, [])
            mapped = not (cls == 'unclassified' or (cls == 'node-bug' and why == 'an ERROR no rule explains'))
            # r31 d4 verify fix: WHERE the class came from ('msg', 'err', 'wrap'); a generic wrapper message whose error is a
            # runtime variable is classed by that error at run time (error_census.WRAPPERS), so the literal is mapped
            sig = ec.signal_class(rec, err) if hasattr(ec, 'signal_class') else None
            via = sig[2] if sig and len(sig) > 2 else None
            wcls = ec.wrapper_class(msg) if hasattr(ec, 'wrapper_class') and not err else None
            if not mapped and wcls:
                mapped, cls, via = True, f'by-error ({wcls} for a known refusal, else node-bug)', 'wrap'
            fn = enclosing(funcs, i + 1)
            fb = code_only('\n'.join(body(ls, fn))) if fn else ''
            # an event: a node-side refusal/drop/ban line; the start-up flags and the operator console of cmd/derod
            # (main.go, config_*) report the operator's own input, not a network event
            event = bool(EVENT_RX.search(msg + ' ' + err)) and not re.match(r'cmd/derod/[^/]+\.go$', f)
            # r31 d4 (B285): a literal whose census class is the operator's input, local I/O, the network around the
            # node or our own monitor's alarm is not a network event, whatever its words ('--p2p-bind address is invalid')
            # (r31 d4 verify fix: only when the class came from a rule on the literal's MESSAGE, never its error text)
            event = event and not (mapped and via == 'msg' and cls in getattr(ec, 'NON_EVENT_CLASSES', ()))
            counter = bool(COUNTER_RX.search(fb)) or any(re.search(r'(?:\.|\b)' + re.escape(n) + r'\(', fb)
                                                         for n in cnt if not fn or n != fn['name'])
            text = (err + ' ' + msg).strip()
            census.append({'at': f'{f}:{i + 1}', 'level': lv, 'text': text[:140], 'class': cls if mapped else None,
                           'event': event, 'counter_in_function': counter})
            key = f"{fn['name'] if fn else ''}|{text}"
            if not mapped:
                findings.append(finding(det, tree, f, i + 1, 'log-unmapped', 'medium' if (event and not counter) else 'low',
                                        f"derod {lv} literal {text[:90]!r} has no error_census class (it falls to "
                                        f"'{cls}: {why}')" + (' and marks an event with no /metrics counter in '
                                                               f"{fn['name'] if fn else 'its function'}" if event and not counter else ''),
                                        key=key, level=lv, text=text, event=event, counter_in_function=counter))
            elif event and not counter:
                findings.append(finding(det, tree, f, i + 1, 'event-no-counter', 'low',
                                        f"derod {lv} literal {text[:90]!r} (census class {cls}) marks an event but "
                                        f"{fn['name'] if fn else 'its function'} increments no /metrics counter",
                                        key=key, level=lv, text=text))
    # every own /metrics family read by an intel tool (or booked as an area metric that area_intel reads)
    reg = json.loads(tree.text('metrics/metric_registry.json') or '{}').get('families') or []
    try:                                                # r31 d4 (B285): the K8 'not_read' notes (none honoured without it)
        mr = _load_mod('det_metric_registry', HERE / 'metric_registry.py')
    except (OSError, ImportError, SyntaxError):
        mr = None
    reg_names = {e.get('name') for e in reg}
    noted = 0
    readers = {}
    for p in sorted((tree.root / 'harness' / 'intel').glob('*.py')):
        if p.name in ('metric_registry.py', 'detectors.py'):
            continue
        readers[p.relative_to(tree.root).as_posix()] = tree.text(p.relative_to(tree.root).as_posix()) or ''
    readers['harness/areas.json'] = tree.text('harness/areas.json') or ''
    unread, vendored = 0, 0

    def reader_of(name):
        return next((r for r, t in readers.items()
                     if re.search(r'(?<![\w])' + re.escape(name) + r'(?:_count|_sum|_bucket)?(?![\w])', t)), None)

    def superseder_read(note, name):     # r31 d4 verify fix: 'superseded' must name a family a tool READS
        if not str(note).startswith('superseded:'):
            return True
        return any(t != name and t in reg_names and reader_of(t)
                   for t in re.findall(r'[a-zA-Z_:][a-zA-Z0-9_:]*', str(note).split(':', 1)[1]))
    for fam in reg:
        name = fam.get('name', '')
        if fam.get('source') == 'vendored':
            vendored += 1
            continue
        rd = reader_of(name)
        note = fam.get('not_read')
        note_ok = (note is not None and mr is not None and mr.not_read_problem(note, name, reg_names) is None
                   and superseder_read(note, name))
        if rd and note is not None:                     # r31 d4: a note on a family a tool reads is stale
            at = next((i + 1 for i, l in enumerate(tree.lines('metrics/metric_registry.json')) if f'"name": "{name}"' in l), None)
            if at:
                findings.append(finding(det, tree, 'metrics/metric_registry.json', at, 'not-read-stale', 'low',
                                        f"/metrics family {name} carries a not_read note but {rd} reads it: drop the note",
                                        key='stale|' + name, family=name))
        if rd:
            continue
        if note_ok:                                     # r31 d4: unread on purpose, said in the registry (K8)
            noted += 1
            continue
        unread += 1
        src = fam.get('source') or ''
        hit = None
        for i, l in enumerate(tree.lines(src)):
            if f'"{name}' in l or f'`{name}' in l:
                hit = (src, i + 1)
                break
        if not hit:
            for i, l in enumerate(tree.lines('metrics/metric_registry.json')):
                if f'"name": "{name}"' in l:
                    hit = ('metrics/metric_registry.json', i + 1)
                    break
        if hit:
            findings.append(finding(det, tree, hit[0], hit[1], 'family-unread', 'low',
                                    f"/metrics family {name} ({fam.get('type')}, area {fam.get('area')}) is read by no intel "
                                    f"tool (harness/intel/*.py) and no areas.json metric", key=name, family=name))
    census.append({'families': len(reg), 'vendored_skipped': vendored, 'unread': unread, 'not_read_noted': noted,
                   'readers': len(readers)})
    inputs = {'derod_packages': len(pkgs), 'files': len(files), 'log_literals': n_lit, 'families': len(reg),
              'families_vendored_skipped': vendored, 'families_unread': unread, 'families_not_read_noted': noted}
    rules = ['derod = the first-party import closure of cmd/derod', 'literal: logger[.V(n)].Error(<fmt.Errorf/errors.New '
             'text or err>, "msg") and logger.Info("WARNING..."); mapped = harness/intel/error_census.classify gives a class '
             "other than its fallbacks ('node-bug: an ERROR no rule explains', 'unclassified')", 'event: the literal '
             'matches EVENT_RX outside cmd/derod/*.go (start-up flags, operator console); it needs a counter (COUNTER_RX) in its function or a call to a same-package func that '
             'increments one', 'family: a source-declared family of '
             'metrics/metric_registry.json (vendored ones aside) named by no harness/intel/*.py (metric_registry.py and '
             'this tool aside) and not in harness/areas.json',
             'r31 d4: a literal whose class is in error_census.NON_EVENT_CLASSES (operator-input, local-io, network-env, '
             'audit-alert) is not an event; a family whose registry entry carries a valid not_read note (metric_registry.py '
             'K8) is unread on purpose, and a note on a family a tool reads is a not-read-stale finding']
    return census, findings, inputs, rules


# ═════════════════════════════ 7. dvm-builtins (B287) ═════════════════════════════
DVM_TABLE = 'dvm/dvm_functions.go'
DVM_WORK_RX = re.compile(r'sha256\.|sha3\.|[Kk]eccak|hex\.(?:Encode|Decode)|(?<!len\()\[\]byte\(')   # work proportional to the input length (a copy too; len([]byte(s)) is not one)
SC_PATHS = (('derod-rpc', 'cmd/derod/rpc/rpc_dero_getsc.go', 'GetSC', ('DERO.GetSC', 'getsc')),
            ('derod-rpc', 'cmd/derod/rpc/rpc_dero_estimategas.go', 'GetGasEstimate', ('DERO.GetGasEstimate', 'getgasestimate')),
            ('wallet-rpc', 'walletapi/rpcserver/rpc_scinvoke.go', 'ScInvoke', ('scinvoke',)))
SC_BUDGET_RX = re.compile(r'check_sc_keys|[Gg]as_?[Ll]imit|MAX_\w+|\w+_MAX\b|_LIMIT\b|budget|limiter|len\(\s*p\.\w+\s*\)\s*>|'
                          r'\bp\.\w+\s*>\s*\w+|Ringsize\s*[<>]|ringsize\s*[<>]')


def detect_dvm_builtins(tree, ctx):
    det = 'dvm-builtins'
    tl = tree.lines(DVM_TABLE)
    funcs = {fn['name']: fn for fn in tree.funcs(DVM_TABLE)}
    dvm_go = [f for f in tree.go(('dvm/',)) if f.count('/') == 1]
    allfn = {}
    for f in dvm_go:
        for fn in tree.funcs(f):
            allfn.setdefault(fn['name'], (f, fn))
    recover = None          # the recover of the execution entry (RunSmartContract), not of the parser
    for f in dvm_go:
        for fn in tree.funcs(f):
            if fn['name'] != 'RunSmartContract':
                continue
            for j, l in enumerate(body(tree.lines(f), fn)):
                if 'recover()' in code_only(l):
                    recover = f"{f}:{fn['start'] + j}"
                    break
    tests = [(f, code_only(tree.text(f) or '')) for f in tree.go(('dvm/', 'blockchain/'), only_tests=True)]
    kats = [(p.relative_to(tree.root).as_posix(), p.read_text(errors='replace'))
            for p in sorted((tree.root / 'harness' / 'kat').glob('test_*.py'))]
    census, findings = [], []
    rows = 0
    for i, l in enumerate(tl):
        m = re.search(r'func_table\["(\w+)"\]\s*=.*ComputeCost:\s*(\d+),\s*StorageCost:\s*(\d+),\s*Ptr[US]?:\s*(\w+)', l)
        if not m:
            continue
        rows += 1
        name, cost, scost, impl = m.group(1), int(m.group(2)), int(m.group(3)), m.group(4)
        f_impl, fn = allfn.get(impl, (None, None))
        b = code_only('\n'.join(body(tree.lines(f_impl), fn))) if fn else ''
        hb = b      # one level of the dvm/ helpers the impl calls (substr copies its input there)
        for h in sorted(set(re.findall(r'(?<![\w.])([a-z]\w*)\(', b)) - {'checkargscount', 'len', 'string', 'panic', 'uint64'}):
            if h in allfn and h != impl:
                hf_, hfn_ = allfn[h]
                hb += '\n' + code_only('\n'.join(body(tree.lines(hf_), hfn_)))
        argc = bool(re.search(r'checkargscount\(|len\(expr\.Args\)\s*[<>=!]=?', b))
        raw_asserts = [x for x in re.findall(r'(\w+)\.\((string|uint64)\)', b)]
        typed = all(re.search(r'_,\s*ok\s*:=\s*' + re.escape(v) + r'\.\(' + t + r'\)', b) for v, t in raw_asserts)
        takes_string = bool(re.search(r'\.\(string\)', b))
        grows = takes_string and bool(DVM_WORK_RX.search(hb))
        size_bound = bool(re.search(r'len\((?!expr\.Args)[^)]*\)\)?\s*(?:[<>]=?|!=)\s*\w+|_MAX\b|MAX_\w+', b))
        rx = re.compile(r'(?i)\b' + re.escape(name) + r'\s*\(|\b' + re.escape(impl) + r'\b')
        pin = next((f for f, t in tests + kats if rx.search(t)), None)
        census.append({'builtin': name, 'at': f'{DVM_TABLE}:{i + 1}', 'impl': f"{f_impl}:{fn['start']}" if fn else None,
                       'compute_cost': cost, 'storage_cost': scost, 'flat_cost': True, 'argcount_checked': argc,
                       'types_checked': typed, 'takes_string': takes_string, 'work_grows_with_input': grows,
                       'size_bound': size_bound, 'panic_recovered_at': recover, 'pinned_by': pin})
        if grows and not size_bound:
            findings.append(finding(det, tree, DVM_TABLE, i + 1, 'disclosure-style', 'low',
                                    f"DVM builtin {name} charges a flat {cost} gas whatever its string input's length while "
                                    f"its work grows with it (no size bound in {impl}): documented, never changed (gas is "
                                    f"consensus, D-21; B10)", key=name, builtin=name))
        if not (argc and typed):
            findings.append(finding(det, tree, f_impl or DVM_TABLE, fn['start'] if fn else i + 1, 'builtin-unchecked-input',
                                    'low' if recover else 'medium',
                                    f"DVM builtin {name} ({impl}) " + ('does not check its argument count' if not argc else
                                    'type-asserts an argument without a prior ok check') +
                                    (f"; the panic is recovered at {recover}" if recover else '; no recover found in dvm/'),
                                    key=name, builtin=name))
        if not pin:
            findings.append(finding(det, tree, DVM_TABLE, i + 1, 'builtin-untested', 'low',
                                    f"DVM builtin {name} is named by no dvm/ or blockchain/ test and no harness KAT",
                                    key=name, builtin=name))
    rpc_w = {}
    for f, start in (('cmd/derod/rpc/rpc_abuse.go', r'^var remote_method_cost = map'),
                     ('cmd/derod/rpc/ws_foreign_rate.go', r'^var foreign_method_cost = map')):
        for k, (ln, _) in map_entries(tree.lines(f), start).items():
            rpc_w.setdefault(k, f'{f}:{ln}')
    pb = '\n'.join(tree.lines('cmd/derod/rpc/param_bounds.go'))
    for surf, f, fname, names in SC_PATHS:
        fn = next((x for x in tree.funcs(f) if x['name'] == fname), None)
        if not fn:
            census.append({'sc_path': fname, 'file': f, 'state': 'not-found'})
            continue
        ev = [{'kind': 'per-method weight', 'at': rpc_w[n]} for n in names if n in rpc_w]
        if any(f'"{n}"' in pb for n in names):
            ev.append({'kind': 'param bound', 'at': 'cmd/derod/rpc/param_bounds.go'})
        for j, bl in enumerate(body(tree.lines(f), fn)):
            if SC_BUDGET_RX.search(code_only(bl)):
                ev.append({'kind': 'in-handler bound', 'at': f"{f}:{fn['start'] + j}", 'text': bl.strip()[:120]})
                break
        census.append({'sc_path': fname, 'surface': surf, 'at': f"{f}:{fn['start']}", 'evidence': ev,
                       'state': 'budgeted' if ev else 'no-budget'})
        if not ev:
            findings.append(finding(det, tree, f, fn['start'], 'sc-path-no-budget', 'low' if surf == 'wallet-rpc' else 'medium',
                                    f"SC entry path {fname} ({surf}) has no per-method weight, param bound or in-handler "
                                    f"budget", key=fname, sc_path=fname))
    inputs = {'table_rows': rows, 'dvm_files': len(dvm_go), 'test_files': len(tests), 'kat_files': len(kats),
              'sc_paths': len(SC_PATHS), 'recover_at': recover}
    rules = ['builtin: a func_table row of dvm/dvm_functions.go; its gas is ComputeCost (flat: no builtin scales gas by input)',
             'disclosure-style: a builtin that takes a string and whose impl does length-proportional work (DVM_WORK_RX) '
             'with no size bound: reported, never changed (D-21)', 'builtin-unchecked-input: no checkargscount, or a '
             '.(string)/.(uint64) assertion without a prior `_, ok :=` check', 'builtin-untested: no dvm/ or blockchain/ '
             '_test.go and no harness KAT names it (SC call or impl name)', 'SC path: a per-method weight, a param_bounds '
             'entry, or an SC_BUDGET_RX line in the handler']
    return census, findings, inputs, rules


RUNNERS = {'budget-census': detect_budget_census, 'fuzz-coverage': detect_fuzz_coverage,
           'error-paths': detect_error_paths, 'crypto-input': detect_crypto_input, 'value-paths': detect_value_paths,
           'signal-coverage': detect_signal_coverage, 'dvm-builtins': detect_dvm_builtins}


# ───────────────────────────── run, fingerprint, freshness ─────────────────────────────
def fingerprint(root, files):
    h = hashlib.sha256()
    for f in sorted(set(files)):
        h.update(f.encode() + b'\0' + (file_sha(Path(root) / f) or 'missing').encode() + b'\n')
    return h.hexdigest()[:16]


def run(root, name, rev=None, area_of=None, allow=None):
    """the detector document for `name` over `root` (nothing written). Pure over the tree but for git."""
    root = Path(root)
    tree = Tree(root)
    census, findings, inputs, rules = RUNNERS[name](tree, {})
    area_of = area_of or area_of_fn(root)
    home = DETECTORS[name][0]
    seen = {}
    for f in sorted(findings, key=lambda x: (x['file'], x['line'])):    # the n-th identical key in a file: '#n' (stable)
        n = seen[f['id']] = seen.get(f['id'], 0) + 1
        if n > 1:
            f['id'] = fid(name, f['file'], f['kind'], f"{f['_key']}#{n}")
    for f in findings:
        f.pop('_key', None)
    rev = rev if rev is not None else git_rev(root)
    for f in findings:
        a = area_of(f['file'])
        f['area'] = a or home
        if not a:
            f['unowned'] = True
        if f['area'] != home:
            f['also_areas'] = [home]
        f['suggested_row'] = suggested_row(name, f, rev)
    if allow is None:
        allow, aerr = load_allow(root)
    else:
        aerr = None
    kept, allowed, probs = apply_allow(name, findings, allow)
    if aerr:
        probs.append(aerr)
    ids = [f['id'] for f in kept]
    if len(set(ids)) != len(ids):
        dup = sorted({i for i in ids if ids.count(i) > 1})
        probs.append(f'{name}: duplicate finding ids {dup[:5]}')
    inputs_files = sorted(tree.read - {ALLOW})
    by_area = {}
    for f in kept:
        by_area.setdefault(f['area'], {}).setdefault(f['kind'], 0)
        by_area[f['area']][f['kind']] += 1
    return {'schema': SCHEMA, 'detector': name, 'row': DETECTORS[name][1], 'home_area': home,
            'what': DETECTORS[name][2], 'generated_at': datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
            'rev': rev, 'tool_sha': file_sha(HERE / 'detectors.py'),
            'registry_sha': file_sha(root / 'harness' / 'areas.json'),
            'fingerprint': fingerprint(root, inputs_files), 'input_files': inputs_files,
            'inputs': inputs, 'rules': rules, 'counts': {'findings': len(kept), 'allowed': len(allowed), 'by_area': by_area},
            'findings': sorted(kept, key=lambda f: (f['area'], f['file'], f['line'], f['id'])),
            'allowed': allowed, 'allow_problems': probs, 'census': census}


def stale_reasons(root, name, doc=None, tool_sha=None):
    """[] when harness/runtime/detector_<name>.json is present and current: same schema, written by this tool's source,
    over this registry, and every input it read still has the content it scanned; else the reasons (missing, ...)."""
    root = Path(root)
    if doc is None:
        try:
            doc = json.loads(out_path(root, name).read_text())
        except OSError:
            return ['missing']
        except ValueError:
            return ['unreadable']
    out = []
    if doc.get('schema') != SCHEMA or doc.get('detector') != name:
        out.append(f"schema {doc.get('schema')!r} / detector {doc.get('detector')!r}")
    ts = tool_sha if tool_sha is not None else file_sha(HERE / 'detectors.py')
    if doc.get('tool_sha') != ts:
        out.append(f"tool changed ({doc.get('tool_sha')} -> {ts})")
    rs = file_sha(root / 'harness' / 'areas.json')
    if doc.get('registry_sha') != rs:
        out.append(f"registry changed ({doc.get('registry_sha')} -> {rs})")
    fp = fingerprint(root, doc.get('input_files') or [])
    if doc.get('fingerprint') != fp:
        out.append(f"inputs changed since rev {str(doc.get('rev') or '?')[:8]} ({doc.get('fingerprint')} -> {fp})")
    return out


def write(root, doc):
    p = out_path(root, doc['detector'])
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f'.{p.name}.tmp')
    tmp.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + '\n')
    os.replace(tmp, p)
    return p


def main(argv):
    root = ROOT
    if '--root' in argv:
        i = argv.index('--root')
        root = Path(argv[i + 1]).resolve()
        argv = argv[:i] + argv[i + 2:]
    if '--list' in argv:
        for n, (a, r, w) in DETECTORS.items():
            print(f'{n:<16} {r:<5} {a:<14} {w}')
        return 0
    if '--check' in argv:
        bad = 0
        for n in DETECTORS:
            rs = stale_reasons(root, n)
            print(f"{n:<16} {'fresh' if not rs else 'STALE: ' + '; '.join(rs)}")
            bad += bool(rs)
        return 3 if bad else 0
    names = list(DETECTORS) if '--all' in argv else [a for a in argv if not a.startswith('--')]
    unknown = [n for n in names if n not in DETECTORS]
    if not names or unknown:
        print(f'usage: detectors.py --all | <name> ... (unknown: {unknown}); see --help', file=sys.stderr)
        return 2
    rev = git_rev(root)
    aof = area_of_fn(root)
    allow, aerr = load_allow(root)
    probs = [aerr] if aerr else []
    for n in names:
        doc = run(root, n, rev=rev, area_of=aof, allow=allow)
        probs += doc['allow_problems']
        if '--print' in argv:
            for f in doc['findings']:
                print(f"{n}\t{f['area']}\t{f['kind']}\t{f['severity']}\t{f['file']}:{f['line']}\t{f['why'][:160]}")
        else:
            write(root, doc)
        ba = ', '.join(f"{a} {sum(k.values())}" for a, k in sorted(doc['counts']['by_area'].items()))
        print(f"[detectors] {n}: {doc['counts']['findings']} finding(s) ({ba or 'none'}), {doc['counts']['allowed']} allowed; "
              f"{len(doc['input_files'])} inputs", file=sys.stderr)
    for p in sorted(set(probs)):
        print(f'[detectors] ALLOW PROBLEM: {p}', file=sys.stderr)
    return 5 if probs else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
