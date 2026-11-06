#!/usr/bin/env python3
"""r24 area intelligence: one scorecard per area of the DERO stack, and a proposals feed the next round consumes.

Reads harness/areas.json (the area registry), harness/round.json (current round, paused tracks), the pipeline records
(harness/loop/runs/pipeline_*.jsonl), the go_mutate records (harness/runtime/gomut_*.json), the gate ledger
(harness/loop/GATES.md), the log_intel / datadir_intel snapshots, the dero-rft §7 backlog table, and (with --live) a
read-only GET of derod's /metrics on 127.0.0.1:10102. Writes:

  harness/runtime/area_intel.json       per-area scorecards: tests, KATs, mutations caught/total, gate state, open
                                        backlog, last measured metrics with their trend vs the previous round
  harness/runtime/area_proposals.json   self-detected candidate items for dero-rft §7/§8 (surviving or INVALID
                                        mutations, newly failing gates, new derod ERROR kinds, metric regressions
                                        beyond noise, zero-coverage or stale areas, backlog rows whose anchor no
                                        longer resolves, KAT files no area owns, history that no longer recomputes)
  harness/runtime/area_prom_<ts>.txt    (--live) the registered /metrics lines read, so every live value has an anchor

Rules (harness-wide): no anchor, no row: a measured value without an anchor that still resolves is REFUSED, never
shown. 'pending' is the only stand-in for an unmeasured value. A paused area (registry status 'paused', or its track
paused in harness/round.json) is reported as PAUSED, never as failing; what would have been flagged is kept, visibly,
in its scorecard's 'held' list.

  python3 -I harness/intel/area_intel.py [--live]        # scorecards + proposals (exit 0; 2 = the registry is invalid)
  python3 -I harness/intel/area_intel.py check           # validate the registry and every anchor (exit 0 / 2)
  python3 -I harness/intel/area_intel.py fix-lines       # fill missing anchor 'line' fields (a quote found exactly once)
  python3 -I harness/intel/area_intel.py record <round>  # copy computed values of <round> into areas.json history
  python3 -I harness/intel/area_intel.py g23             # the gate G23 on its own (exit 0 / 3)
  python3 -I harness/intel/area_intel.py correct <round> --why TEXT [--date YYYY-MM-DD]
                                                         # r25 (B52): dated correction of every booked value the records
                                                         # now recompute differently (the old value is kept in `corrections`)
  python3 -I harness/intel/area_intel.py correct <round> <area>.<metric> --why TEXT (--pending | --value V --file F --quote Q)
                                                         # r25: correct one booked value by hand (a superseded live reading)
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):   # r27 B120: usage, exit 0, nothing run or written
    print(__doc__ or 'usage: see the header of this file')
    raise SystemExit(0)
import datetime, fnmatch, hashlib, json, re, sys, urllib.request
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
ROOT = HARNESS.parent
PENDING = 'pending'
STATUSES = ('active', 'paused')
REQUIRED_AREAS = ('harness', 'security', 'cryptosupply', 'getworkops', 'mempool', 'chainperf', 'rpcws', 'syncp2p',
                  'wallet', 'storage', 'observability', 'docs', 'disclosure', 'miner', 'tooling')   # r25: tooling (§0.9)
AREA_FIELDS = ('id', 'title', 'owner_dim', 'status', 'code_paths', 'metrics', 'kat_files', 'gates', 'gomut_prefixes',
               'backlog', 'history')
AUTO = ('new_tests', 'mutations', 'kats', 'gates')      # computed for every area from each round's records
BAD_MUT = ('MISSED', 'STALE', 'INVALID', 'BROKEN', 'NEWFAIL')
FRESH_H = 24
MIN_QUOTE = 8
LIVE_URL = 'http://127.0.0.1:10102/metrics'


def now():
    return datetime.datetime.now().astimezone()


def paths(root):
    h = Path(root) / 'harness'
    return {'reg': h / 'areas.json', 'round': h / 'round.json', 'runs': h / 'loop' / 'runs', 'runtime': h / 'runtime',
            'gates': h / 'loop' / 'GATES.md', 'kat': h / 'kat', 'rft': Path(root) / 'artifacts' / 'dero-rft.md',
            'out': h / 'runtime' / 'area_intel.json', 'props': h / 'runtime' / 'area_proposals.json'}


def sha(path):
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()[:16]
    except OSError:
        return None


# ───────────────────────────── anchors ─────────────────────────────
def resolve_anchor(root, a):
    """{status, line}: OK (quote on the cited line), MOVED (quote elsewhere in the file), BROKEN, NOFILE, SHORT, NONE."""
    if not isinstance(a, dict) or not a.get('file') or not isinstance(a.get('quote'), str):
        return {'status': 'NONE', 'line': None}
    q = a['quote']
    if len(q.strip()) < MIN_QUOTE:
        return {'status': 'SHORT', 'line': None}
    try:
        lines = (Path(root) / a['file']).read_text(errors='replace').splitlines()
    except OSError:
        return {'status': 'NOFILE', 'line': None}
    hint = a.get('line')
    if isinstance(hint, int) and 1 <= hint <= len(lines) and q in lines[hint - 1]:
        return {'status': 'OK', 'line': hint}
    hits = [i + 1 for i, l in enumerate(lines) if q in l]
    if hits:
        return {'status': 'MOVED', 'line': hits[0]}
    return {'status': 'BROKEN', 'line': None}


def resolved(st):
    return st['status'] in ('OK', 'MOVED')


def line_anchor(root, file, quote, after=0):
    """An anchor for `quote` in `file` (first hit after line `after`), or None if it is not there."""
    try:
        lines = (Path(root) / file).read_text(errors='replace').splitlines()
    except OSError:
        return None
    for i in range(after, len(lines)):
        if quote in lines[i]:
            return {'file': str(file), 'quote': quote, 'line': i + 1}
    return None


# r24 verify-areaintel: a hand-entered value must be BACKED by the line it cites, not merely cite a line that exists.
# Only the AUTO metrics and these source kinds are recomputed from the round records (history-drift catches a wrong
# recorded value there). For every other history entry (manual, prom, prom_ratio, no source) validate() requires the
# value, its display, or a `derive` expression over numbers printed on the anchored line, to be on that line.
# Unbacked = no anchor, no row (an error).
RECOMP = ('pipeline', 'gomut_all', 'gomut_upstream', 'pipeline_step')
_NUM_RX = re.compile(r'\d[\d,]*(?:\.\d+)?')


def _line_nums(text):
    out = set()
    for t in _NUM_RX.findall(text):
        try:
            out.add(float(t.replace(',', '')))
        except ValueError:
            pass
    return out


def _arith(node):
    import ast
    if isinstance(node, ast.Expression):
        return _arith(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
        return float(node.value)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.Div)):
        a, b = _arith(node.left), _arith(node.right)
        if isinstance(node.op, ast.Add):
            return a + b
        if isinstance(node.op, ast.Sub):
            return a - b
        if isinstance(node.op, ast.Mult):
            return a * b
        return a / b
    raise ValueError('derive: only + - * / over number literals')


def backed(v, text, unit=''):
    """(ok, why): is history entry `v` (value, display, derive) stated by `text` (the anchored line + its quote)?"""
    val, disp, der = v.get('value'), v.get('display'), v.get('derive')
    nums = _line_nums(text)
    if der is not None:
        import ast
        if not isinstance(der, str) or not re.fullmatch(r'[\d.\s+\-*/()]+', der):
            return False, f'derive {der!r} is not plain arithmetic'
        lits = [float(x) for x in re.findall(r'\d+(?:\.\d+)?', der)]
        free = {100.0} if unit == '%' else set()
        miss = [x for x in lits if x not in nums and x not in free]
        if miss:
            return False, f'derive literal(s) {miss} not on the anchored line'
        try:
            res = _arith(ast.parse(der, mode='eval'))
        except (ValueError, SyntaxError, ZeroDivisionError) as e:
            return False, f'derive {der!r}: {e}'
        target = num(val)
        if target is None:
            return False, f'derive given but value {val!r} is not a number'
        dec = len(repr(float(val)).split('.')[1]) if isinstance(val, float) else 0
        if abs(res - target) > 0.5 * 10 ** -dec + 1e-12:
            return False, f'derive {der} = {res:g}, not {val!r}'
        return True, 'derive'
    if isinstance(disp, str) and len(disp.strip()) >= 1 and disp in text:
        return True, 'display'
    if isinstance(val, bool):
        return (str(val).lower() in text.lower()), 'bool'
    if isinstance(val, (int, float)):          # a rounded reading of a printed number counts (5.31 for 5.309856)
        dec = len(repr(float(val)).split('.')[1]) if isinstance(val, float) else 0
        return any(abs(n - float(val)) <= 0.5 * 10 ** -dec + 1e-12 for n in nums), 'number'
    m = re.fullmatch(r'\s*(\d+)\s*/\s*(\d+)\s*', str(val))
    if m:
        return (float(m.group(1)) in nums and float(m.group(2)) in nums), 'ratio'
    return (str(val) in text), 'text'


def anchored_text(root, a, st):
    if not isinstance(a, dict):
        return ''
    try:
        lines = (Path(root) / a['file']).read_text(errors='replace').splitlines()
        return lines[st['line'] - 1] + ' || ' + a.get('quote', '')
    except (OSError, IndexError, TypeError):
        return a.get('quote', '')


def is_pending(v):
    return isinstance(v, str) and v.strip().lower() == PENDING


# ───────────────────────────── registry ─────────────────────────────
def load_registry(root):
    return json.loads(paths(root)['reg'].read_text())


def validate(reg, root):
    """(errors, warnings). An error makes the registry unusable (exit 2, G23 FAIL)."""
    err, warn = [], []
    rids = [r.get('id') for r in reg.get('rounds', [])]
    if not rids or len(set(rids)) != len(rids):
        err.append('rounds: missing or duplicate round ids')
    for r in reg.get('rounds', []):
        if r.get('anchor') and not resolved(resolve_anchor(root, r['anchor'])):
            err.append(f"round {r.get('id')}: anchor does not resolve ({r['anchor'].get('file')})")
    areas = reg.get('areas', [])
    ids = [a.get('id') for a in areas]
    if len(set(ids)) != len(ids):
        err.append('areas: duplicate area id')
    for need in REQUIRED_AREAS:
        if need not in ids:
            err.append(f'areas: required area {need!r} is not registered')
    for a in areas:
        aid = a.get('id', '?')
        for f in AREA_FIELDS:
            if f not in a:
                err.append(f'{aid}: missing field {f!r}')
        if a.get('status') not in STATUSES:
            err.append(f"{aid}: status {a.get('status')!r} not in {STATUSES}")
        if a.get('status') == 'paused' and not resolved(resolve_anchor(root, a.get('paused_why'))):
            err.append(f'{aid}: paused without a resolving paused_why anchor')
        for b in a.get('backlog', []):
            if not re.fullmatch(r'B\d+', str(b)):
                err.append(f'{aid}: backlog id {b!r} is not B<n>')
        for g in a.get('gates', []):
            if not re.fullmatch(r'G\d+', str(g)):
                err.append(f'{aid}: gate id {g!r} is not G<n>')
        mids = {m.get('id') for m in a.get('metrics', [])} | set(AUTO)
        kinds = {m.get('id'): ((m.get('source') or {}).get('kind'), m.get('unit', '')) for m in a.get('metrics', [])}
        for m in a.get('metrics', []):
            if m.get('better', 'none') not in ('higher', 'lower', 'none'):
                err.append(f"{aid}.{m.get('id')}: better must be higher|lower|none")
            if m.get('class', 'node') not in METRIC_CLASSES:      # r26 B105
                err.append(f"{aid}.{m.get('id')}: class must be one of {'|'.join(METRIC_CLASSES)}")
            ne = (m.get('source') or {}).get('needs_event')
            if ne is not None and not (isinstance(ne, dict) and isinstance(ne.get('name'), str) and ne['name']):
                err.append(f"{aid}.{m.get('id')}: needs_event must be {{name: <prom counter>, what: <event>}}")
        for rid, vals in (a.get('history') or {}).items():
            if rid not in rids:
                err.append(f'{aid}: history round {rid!r} is not in rounds')
            for mid, v in vals.items():
                if mid not in mids:
                    err.append(f'{aid}.{mid}@{rid}: metric not defined in the area')
                if not isinstance(v, dict) or 'value' not in v:
                    err.append(f'{aid}.{mid}@{rid}: entry without a value')
                    continue
                for cx in correction_problems(root, v.get('corrections')):      # r25 (B52)
                    err.append(f'{aid}.{mid}@{rid}: {cx}')
                if is_pending(v['value']):
                    if not v.get('why'):
                        warn.append(f'{aid}.{mid}@{rid}: pending without a why')
                    continue
                st = resolve_anchor(root, v.get('anchor'))
                if not resolved(st):           # no anchor, no row
                    err.append(f"{aid}.{mid}@{rid}: measured value {v['value']!r} has no resolving anchor ({st['status']})")
                elif st['status'] == 'MOVED':
                    warn.append(f"{aid}.{mid}@{rid}: anchor moved to line {st['line']} (run fix-lines)")
                kind, unit = kinds.get(mid, (None, ''))
                if resolved(st) and mid not in AUTO and kind not in RECOMP:     # r24 verify: the line states it
                    okb, how = backed(v, anchored_text(root, v.get('anchor'), st), unit)
                    if not okb:
                        err.append(f"{aid}.{mid}@{rid}: value {v['value']!r} is not on its anchored line "
                                   f"({v['anchor'].get('file')}:{st['line']}; {how})")
    return err, warn


def round_order(reg):
    return [r['id'] for r in reg.get('rounds', [])]


def unpinned_rounds(reg, current):
    """r25 (B52): rounds before `current` whose pipeline_full or pipeline_project is not pinned in the registry. Their
    values are computed from 'the newest record whose BEGIN names the round', which moves whenever a later run is still
    labelled with that round (r24: the R25 plan runs of 2026-11-03), so booked values then drift. Pure."""
    order = round_order(reg)
    if current not in order:
        return []
    return [r['id'] for r in reg.get('rounds', [])[:order.index(current)]
            if any(not r.get(k) or is_pending(r.get(k)) for k in ('pipeline_full', 'pipeline_project'))]


def current_round(root):
    try:
        rr = json.loads(paths(root)['round'].read_text())
    except (OSError, ValueError):
        return None, {}
    cur = rr.get('current')
    ent = next((r for r in rr.get('rounds', []) if r.get('id') == cur), {})
    return cur, ent.get('tracks') or {}


def area_paused(a, tracks):
    """(paused, why). A track paused in round.json pauses the area even if the registry still says active."""
    if a.get('status') == 'paused':
        return True, 'registry status paused'
    t = a.get('track')
    if t and tracks.get(t) == 'paused':
        return True, f'harness/round.json tracks.{t} = paused'
    return False, None


# ───────────────────────────── code ownership ─────────────────────────────
def _score(pat, path):
    if pat.endswith('/'):
        return len(pat) if path.startswith(pat) else -1
    if any(c in pat for c in '*?['):
        return len(re.split(r'[*?\[]', pat)[0]) + 1 if fnmatch.fnmatch(path, pat) else -1
    return 100000 + len(pat) if path == pat else -1


def area_of(areas, path):
    """The area owning a repo-relative file: the most specific matching pattern wins (exact > glob > dir prefix by length)."""
    best, best_s = None, -1
    for a in areas:
        for pat in a.get('code_paths', []):
            s = _score(pat, path)
            if s > best_s:
                best, best_s = a['id'], s
    return best


def test_index(root):
    """{(pkgdir/, TestName): repo-relative test file} for every first-party *_test.go."""
    idx = {}
    root = Path(root)
    for p in root.rglob('*_test.go'):
        rp = p.relative_to(root).as_posix()
        if rp.startswith(('vendor/', '.git/')) or '/vendor/' in rp:
            continue
        try:
            txt = p.read_text(errors='replace')
        except OSError:
            continue
        d = rp.rsplit('/', 1)[0] + '/' if '/' in rp else ''
        for m in re.finditer(r'^func (Test\w+)\(', txt, re.M):
            idx[(d, m.group(1))] = rp
    return idx


def pkgdir(key):
    k = re.sub(r'\s*\(.*\)$', '', str(key)).strip()
    k = k[2:] if k.startswith('./') else k
    return k if k.endswith('/') else k + '/'


# ───────────────────────────── records ─────────────────────────────
def read_jsonl(path):
    out = []
    try:
        for i, l in enumerate(Path(path).read_text().splitlines()):
            try:
                out.append((i + 1, json.loads(l)))
            except ValueError:
                pass
    except OSError:
        pass
    return out


def discover_round_records(root, reg, rid):
    """{'full': id|None, 'project': id|None} for a round: registry ids first, else the newest record whose BEGIN
    names the round (a full record has a 'test' stage; a project-only record does not)."""
    ent = next((r for r in reg.get('rounds', []) if r.get('id') == rid), {})
    full = ent.get('pipeline_full')
    proj = ent.get('pipeline_project')
    full = None if not full or is_pending(full) else full
    proj = None if not proj or is_pending(proj) else proj
    if full and proj:
        return {'full': full, 'project': proj}
    runs = sorted(paths(root)['runs'].glob('pipeline_*.jsonl'))
    for p in reversed(runs):
        ev = read_jsonl(p)
        if not ev or ev[0][1].get('round') != rid:
            continue
        stages = {o.get('stage') for _, o in ev}
        if 'test' in stages and not full:
            full = p.stem
        elif 'test' not in stages and 'project' in stages and not proj:
            proj = p.stem
    return {'full': full, 'project': proj}


def stage_line(ev, stage, status='*'):
    for ln, o in ev:
        if o.get('stage') == stage and (status == '*' and o.get('status') in ('PASS', 'FAIL') or o.get('status') == status):
            return ln, o
    return None, None


def rec_anchor(root, rid_file, ln, stage, status):
    q = f'"stage": "{stage}", "status": "{status}"'
    a = {'file': rid_file, 'quote': q, 'line': ln}
    return a if resolved(resolve_anchor(root, a)) else line_anchor(root, rid_file, q)


def gomut_for(root, pid):
    if not pid:
        return None, None
    p = paths(root)['runtime'] / f"gomut_{pid.replace('pipeline_', '')}.json"
    if not p.exists():
        return None, None
    try:
        return p, json.loads(p.read_text())
    except ValueError:
        return p, None


def newest_gomut(root):
    gs = sorted(paths(root)['runtime'].glob('gomut_*.json'))
    for p in reversed(gs):
        try:
            return p, json.loads(p.read_text())
        except ValueError:
            continue
    return None, None


def mutations_of(area, areas, gm):
    """The mutation results that belong to an area: by the file they mutate, or by a registered id prefix."""
    out = []
    for r in (gm or {}).get('results', []):
        if str(r.get('id', '')).startswith('restore-check') or r.get('result') == 'OK':
            continue
        own = area_of(areas, r.get('file', '')) == area['id']
        pre = any(str(r.get('id', '')).startswith(p) for p in area.get('gomut_prefixes', []))
        if own or pre:
            out.append(r)
    return out


def gate_rows(root):
    """[(line, cycle, gate_id, label, result, detail)] from loop/GATES.md."""
    rows = []
    try:
        for i, l in enumerate(paths(root)['gates'].read_text().splitlines()):
            c = [x.strip() for x in l.split('|')]
            if len(c) >= 6 and re.match(r'G\d+ ', c[3] or ''):
                rows.append((i + 1, c[2], c[3].split()[0], c[3], c[4], c[5]))
    except OSError:
        pass
    return rows


def kat_results(root, full_ev, proj_ev, full_file, proj_file):
    """{kat file name: (ok, text, anchor)}: the project record's INFO steps first, else the full record's kats stage."""
    res = {}
    for ev, f in ((full_ev, full_file), (proj_ev, proj_file)):
        if not ev:
            continue
        for ln, o in ev:
            if o.get('stage') == 'kats' and o.get('status') in ('PASS', 'FAIL') and isinstance(o.get('results'), dict):
                for k, v in o['results'].items():
                    a = rec_anchor(root, f, ln, 'kats', o['status'])
                    res[k] = (o['status'] == 'PASS', (v or [''])[-1] if isinstance(v, list) else str(v), a)
            st = str(o.get('step', ''))
            if o.get('stage') == 'project' and o.get('status') == 'INFO' and st.startswith('harness/kat/'):
                name = st.split()[0].rsplit('/', 1)[-1]
                q = f'"step": "{st}"'
                a = line_anchor(root, f, q, ln - 1) or line_anchor(root, f, q)
                res[name] = (o.get('rc') == 0, ' '.join(o.get('last') or []), a)
    return res


# ───────────────────────────── per-round auto metrics ─────────────────────────────
def frac(v):
    m = re.fullmatch(r'\s*(\d+)\s*/\s*(\d+)\s*', str(v))
    if m:
        return (int(m.group(1)) / int(m.group(2))) if int(m.group(2)) else None
    return None


def same_value(a, b):
    """Recorded vs recomputed: ratio and text values must match as written (9/9 is not 1/1); numbers by value."""
    if isinstance(a, str) and isinstance(b, str):
        return a.strip() == b.strip()
    na, nb = num(a), num(b)
    return na == nb if na is not None and nb is not None else str(a) == str(b)


def num(v):
    if isinstance(v, bool):
        return float(v)
    if isinstance(v, (int, float)):
        return float(v)
    f = frac(v)
    if f is not None:
        return f
    try:
        return float(str(v).replace(',', '').lstrip('x'))
    except ValueError:
        return None


def step_is(step, want):
    """r25 (tooling class 'substring step match', c191245 / IK24): a pipeline step names `want` when it IS that
    command, or that command followed by its arguments ('harness/gen_deroarch.py build' matches 'harness/gen_deroarch.py
    build' and 'harness/gen_deroarch.py build --x', never 'harness/gen_deroarch.py builder'). Pure."""
    st, w = str(step or ''), str(want or '')
    return bool(w) and (st == w or st.startswith(w + ' '))


OPT_IN_LINES = 4      # r25: as harness/kat/test_new_tests_registered_r24.py (NT1): an env-gated skip in the first lines


def opt_in_body(body_lines):
    """True when a Go test's first lines skip unless an environment variable is set (an opt-in harness). Pure."""
    head = '\n'.join(body_lines[:OPT_IN_LINES])
    return 'os.Getenv(' in head and 't.Skip' in head


def opt_in_tests(root, tidx):
    """{(pkgdir/, TestName)} of the opt-in tests among `tidx` (read from their files)."""
    out, cache = set(), {}
    for (d, n), f in tidx.items():
        if f not in cache:
            try:
                cache[f] = (Path(root) / f).read_text(errors='replace').splitlines()
            except OSError:
                cache[f] = []
        lines = cache[f]
        for i, l in enumerate(lines):
            if l.startswith(f'func {n}('):
                if opt_in_body(lines[i + 1:]):
                    out.add((d, n))
                break
    return out


def auto_round(root, reg, rid, tidx):
    """{area id: {metric id: entry}} computed from one round's pipeline + go_mutate records and its gate cycle."""
    areas = reg['areas']
    rr = discover_round_records(root, reg, rid)
    out = {a['id']: {} for a in areas}
    runs = paths(root)['runs']
    full_file = f"harness/loop/runs/{rr['full']}.jsonl" if rr['full'] else None
    proj_file = f"harness/loop/runs/{rr['project']}.jsonl" if rr['project'] else None
    full_ev = read_jsonl(runs / f"{rr['full']}.jsonl") if rr['full'] else []
    proj_ev = read_jsonl(runs / f"{rr['project']}.jsonl") if rr['project'] else []
    why_none = f'no pipeline record of {rid} in harness/loop/runs'
    # new tests per area (S3 test stage, attributed through the test file that defines each test)
    ln, o = stage_line(full_ev, 'test')
    if o and isinstance(o.get('new_tests'), dict):
        cnt = {a['id']: 0 for a in areas}
        for pkg, v in o['new_tests'].items():
            d = pkgdir(pkg)
            for name in (v.get('passed') or []) + (v.get('failed') or []):
                f = tidx.get((d, name))
                aid = area_of(areas, f) if f else area_of(areas, d + '_unattributed_test.go')
                if aid in cnt:
                    cnt[aid] += 1
        anc = rec_anchor(root, full_file, ln, 'test', o.get('status'))
        ran = {(pkgdir(pkg), name) for pkg, v in o['new_tests'].items() for name in (v.get('passed') or []) + (v.get('failed') or [])}
        opt = opt_in_tests(root, tidx)     # r25 (B52): env-gated opt-in harnesses are never registered (KAT NT1)
        for a in areas:                    # tests named for this round that exist in the tree but S3 never ran
            pre = 'Test' + rid[:1].upper() + rid[1:]
            miss = sorted(f'{d}{n}' for (d, n), f in tidx.items() if n.startswith(pre) and (n[len(pre):len(pre) + 1] or 'X') not in '0123456789'
                          and area_of(areas, f) == a['id'] and (d, n) not in ran and (d, n) not in opt)
            out[a['id']]['_unregistered'] = miss
        for aid, n in cnt.items():
            out[aid]['new_tests'] = {'value': n, 'anchor': anc, 'computed': True}
    else:
        for a in areas:
            out[a['id']]['new_tests'] = {'value': PENDING, 'why': why_none if not full_ev else 'no test stage in the record'}
    # mutations per area
    gp, gm = gomut_for(root, rr['full'])
    if gm:
        ga = line_anchor(root, f'harness/runtime/{gp.name}', f'"caught": {gm.get("caught")},')
        for a in areas:
            rs = mutations_of(a, areas, gm)
            c = sum(1 for r in rs if r.get('result') == 'CAUGHT')
            out[a['id']]['mutations'] = {'value': f'{c}/{len(rs)}', 'anchor': ga, 'computed': True,
                                          'invalid': sum(1 for r in rs if r.get('result') == 'INVALID'),
                                          'bad': sorted(r['id'] for r in rs if r.get('result') in BAD_MUT)}
    else:
        for a in areas:
            out[a['id']]['mutations'] = {'value': PENDING, 'why': f'no go_mutate record for {rid}'}
    # KAT files per area
    kr = kat_results(root, full_ev, proj_ev, full_file, proj_file)
    for a in areas:
        names = [Path(k).name for k in a.get('kat_files', [])]
        got = [(n, kr[n]) for n in names if n in kr]
        if got:
            okn = sum(1 for _, (ok, _, _) in got if ok)
            out[a['id']]['kats'] = {'value': f'{okn}/{len(got)}', 'anchor': got[0][1][2], 'computed': True,
                                    'files': {n: t for n, (_, t, _) in got}}
        else:
            out[a['id']]['kats'] = {'value': PENDING, 'why': 'no KAT file of this area ran in the round records' if names else 'the area has no KAT file'}
    # gates per area (the round's project cycle, else its full-run cycle)
    rows = gate_rows(root)
    cyc = None
    for pid in (rr['project'], rr['full']):
        if pid and any(r[1] == f'pipeline-{pid.replace("pipeline_", "")}' for r in rows):
            cyc = f'pipeline-{pid.replace("pipeline_", "")}'
            break
    for a in areas:
        mine = [r for r in rows if r[1] == cyc and r[2] in a.get('gates', [])] if cyc else []
        last = {}
        for r in mine:                     # a cycle can be gated twice: the last row of each gate counts
            last[r[2]] = r
        if last:
            p = sum(1 for r in last.values() if r[4] == 'PASS')
            first = min(last.values())
            out[a['id']]['gates'] = {'value': f'{p}/{len(last)}', 'computed': True,
                                     'anchor': {'file': 'harness/loop/GATES.md', 'quote': f'| {cyc} | {first[3]}', 'line': first[0]},
                                     'state': {g: r[4] for g, r in sorted(last.items())}}
        else:
            out[a['id']]['gates'] = {'value': PENDING, 'why': 'no gate row of this area in the round cycle' if a.get('gates') else 'the area has no gate'}
    # registered pipeline-field metrics
    for a in areas:
        for m in a.get('metrics', []):
            s = m.get('source') or {}
            if s.get('kind') == 'pipeline':
                ev, f = (proj_ev, proj_file) if s.get('mode') == 'project' and proj_ev else (full_ev, full_file)
                ln, o = stage_line(ev, s['stage'], s.get('status', '*'))
                if o is not None and s['field'] in o:
                    out[a['id']][m['id']] = {'value': o[s['field']], 'computed': True,
                                             'anchor': rec_anchor(root, f, ln, s['stage'], o.get('status'))}
            elif s.get('kind') == 'gomut_all' and gm:
                out[a['id']][m['id']] = {'value': f"{gm.get('caught')}/{gm.get('total')}", 'computed': True,
                                         'anchor': line_anchor(root, f'harness/runtime/{gp.name}', f'"caught": {gm.get("caught")},')}
            elif s.get('kind') == 'gomut_upstream' and gm:
                up = gm.get('upstream_failures') or {}
                n = sum(len(up.get(p, [])) for p in s.get('pkgs', []))
                anc = line_anchor(root, f'harness/runtime/{gp.name}', '"upstream_failures"')
                if anc:
                    out[a['id']][m['id']] = {'value': n, 'computed': True, 'anchor': anc}
            elif s.get('kind') == 'pipeline_step':
                ev, f = (proj_ev, proj_file) if s.get('mode') == 'project' and proj_ev else (full_ev, full_file)
                for ln, o in ev:
                    if o.get('stage') == 'project' and step_is(o.get('step'), s['step']):
                        mm = re.search(s['regex'], ' '.join(o.get('last') or []))
                        if mm:
                            out[a['id']][m['id']] = {'value': int(mm.group(1)), 'computed': True,
                                                     'anchor': line_anchor(root, f, f'"step": "{o["step"]}"', ln - 1)}
    return out, rr


# ───────────────────────────── current-state readers ─────────────────────────────
def read_prom(text, names, summed=()):
    """{name: (value, first line, series)}: an unlabelled sample, or for `summed` names the sum of its labelled series."""
    vals = {}
    for l in text.splitlines():
        if l.startswith('#'):
            continue
        m = re.match(r'^([a-zA-Z_:][\w:]*)(\{[^}]*\})?\s+(\S+)', l)
        if not m or m.group(1) not in names or (m.group(2) and m.group(1) not in summed):
            continue
        try:
            v = float(m.group(3))
        except ValueError:
            continue
        if m.group(1) in vals and m.group(2):
            ov, ol, n = vals[m.group(1)]
            vals[m.group(1)] = (ov + v, ol, n + 1)
        else:
            vals[m.group(1)] = (v, l, 1)
    return vals


def capture_round(text, order):
    """The round of the binary the capture was read from ('# version ...+<date>.<round>' header), or None."""
    m = re.search(r'^# version \S*\+\d+\.(r\d+\w*)\s*$', text, re.M)
    return m.group(1) if m and m.group(1) in order else None


UNKNOWN_ROUND = 'unknown'   # r25 (B89): a capture with no '# version' line, or a version no round names


def event_gate(e, s, prom):
    """r25 (B54): a count of 0 is a reading only when the event it counts happened. A source with
    needs_event {name, what} books 0 as `pending: no event` when the event counter is 0 or missing from the capture
    (r24: block_tx_roundtrip_observed_total 0 over 217 blocks that carried 0 txs was booked as a measured 0). A
    non-zero value is itself the evidence that the event happened. Pure."""
    ne = s.get('needs_event')
    if not ne or not isinstance(e, dict) or is_pending(e.get('value')) or num(e.get('value')) != 0:
        return e
    ev = prom.get(ne.get('name'))
    if ev and ev[0] > 0:
        return {**e, 'display': e.get('display') or f"0 ({ne['name']} {ev[0]:g})"}
    return {'value': PENDING, 'why': f"pending: no event ({ne.get('what') or 'the counted event'} never happened: "
                                     f"{ne['name']} {'is 0' if ev else 'not in the capture'}); a 0 here is not a reading"}


def prom_names(reg, summed_only=False):
    ns = set()
    for a in reg['areas']:
        for m in a.get('metrics', []):
            s = m.get('source') or {}
            if (s.get('needs_event') or {}).get('name') and not summed_only:
                ns.add(s['needs_event']['name'])
            if s.get('kind') == 'prom' and (s.get('sum_labels') or not summed_only):
                ns.add(s['name'])
            elif s.get('kind') == 'prom_ratio' and not summed_only:
                ns |= {s['num'], s['den']}
    return ns


def live_capture(root, reg, url=LIVE_URL, timeout=8):
    """Read derod /metrics once (read-only GET), keep only the registered names, write area_prom_<ts>.txt."""
    names = prom_names(reg)
    try:
        txt = urllib.request.urlopen(urllib.request.Request(url), timeout=timeout).read().decode(errors='replace')
    except Exception as e:                                           # noqa: BLE001 — not reachable = pending, not a failure
        return None, f'{type(e).__name__}'
    summed = prom_names(reg, summed_only=True)
    keep = [l for l in txt.splitlines() if (m := re.match(r'^([a-zA-Z_:][\w:]*)(\{[^}]*\})?\s', l))
            and m.group(1) in names and (not m.group(2) or m.group(1) in summed)]
    ver = None
    try:                                     # the running build, so a live value is booked to the round it measures
        rq = urllib.request.Request(url.replace('/metrics', '/json_rpc'), headers={'Content-Type': 'application/json'},
                                    data=json.dumps({'jsonrpc': '2.0', 'id': '1', 'method': 'DERO.GetInfo'}).encode())
        ver = json.loads(urllib.request.urlopen(rq, timeout=timeout).read())['result']['version']
    except Exception:                                                # noqa: BLE001 — version unknown: booked to the current round
        pass
    ts = now().strftime('%Y%m%dT%H%M%S')
    p = paths(root)['runtime'] / f'area_prom_{ts}.txt'
    p.write_text(f'# r24 area_intel: read-only GET {url} at {now().isoformat(timespec="seconds")}; registered names only\n'
                 + (f'# version {ver}\n' if ver else '') + '\n'.join(sorted(keep)) + '\n')
    return p, None


def newest(root, pattern):
    ps = sorted(paths(root)['runtime'].glob(pattern))
    return ps[-1] if ps else None


def current_values(root, reg):
    """{area: {metric: entry}} for metrics read from runtime files (prom capture, log_intel, datadir, raw counts)."""
    out = {a['id']: {} for a in reg['areas']}
    pp = newest(root, 'area_prom_*.txt')
    ptxt = pp.read_text() if pp else ''
    prom = read_prom(ptxt, prom_names(reg), prom_names(reg, summed_only=True)) if pp else {}
    prel = f'harness/runtime/{pp.name}' if pp else None
    prom_round = capture_round(ptxt, round_order(reg)) if pp else None
    li = newest(root, 'logintel_*.json')
    dd = newest(root, 'datadir_*.json')
    for a in reg['areas']:
        for m in a.get('metrics', []):
            s = m.get('source') or {}
            k = s.get('kind')
            e = None
            if k == 'prom':
                if s['name'] in prom:
                    v, l, n = prom[s['name']]
                    e = {'value': v, 'anchor': line_anchor(root, prel, l), 'live_round': prom_round or UNKNOWN_ROUND}
                    if n > 1:
                        e['display'] = f'{v:g} (sum of {n} labelled series in the capture)'
                    e = event_gate(e, s, prom)                              # r25 (B54)

                else:
                    e = {'value': PENDING, 'why': f"{s['name']} not in the newest /metrics capture" if pp else 'no /metrics capture (run with --live)'}
            elif k == 'prom_ratio':
                if s['num'] in prom and s['den'] in prom and prom[s['den']][0]:
                    v = prom[s['num']][0] / prom[s['den']][0] * s.get('scale', 1)
                    e = {'value': round(v, 4), 'display': f"{round(v, 4)} ({prom[s['num']][0]:g} / {prom[s['den']][0]:g})",
                         'anchor': line_anchor(root, prel, prom[s['num']][1]),
                         'anchor2': line_anchor(root, prel, prom[s['den']][1]), 'live_round': prom_round or UNKNOWN_ROUND}
                else:
                    e = {'value': PENDING, 'why': f"{s['num']} / {s['den']} not both in the newest capture, or the denominator is 0"}
            elif k == 'logintel' and li:
                d = json.loads(li.read_text())
                cur = (d.get('runs') or [{}])[-1]
                if s['field'] in cur:
                    # r25 (B89): a log_intel run is a reading of the derod binary that wrote the log (its 'version'),
                    # so 4 ERRORs of the r24 run are not booked to r25 (the r25 scorecard showed 0 (r24) -> 4 (r25))
                    e = {'value': cur[s['field']], 'anchor': line_anchor(root, f'harness/runtime/{li.name}', f'"{s["field"]}": {json.dumps(cur[s["field"]])}'),
                         'live_round': capture_round(f"# version {cur.get('version')}\n", round_order(reg)) or UNKNOWN_ROUND}
            elif k == 'datadir_fail' and dd:
                d = json.loads(dd.read_text())
                n = sum(1 for c in d.get('checks', []) if c.get('result') == 'FAIL')
                e = {'value': n, 'anchor': line_anchor(root, f'harness/runtime/{dd.name}', '"checks"')}
            elif k == 'consensus':      # r24: a KPI of the chain-consensus observatory (harness/intel/consensus_intel.py)
                cp = Path(root) / 'harness/runtime/consensus_intel.json'
                try:
                    cd = json.loads(cp.read_text())
                except (OSError, ValueError):
                    cd = None
                kv = (cd or {}).get('kpis') or {}
                if s['field'] in kv and not is_pending(kv[s['field']]):
                    # r25 measured (rft §7 B106): anchor on the KPI line of the newest timestamped capture that states this
                    # value; consensus_intel.json is rewritten by every run (S7 re-runs it), so an anchor there broke
                    # (BROKEN) one run after `record`. The JSON stays the fallback when no capture states the value.
                    anc = None
                    for capf in sorted((Path(root) / 'harness/runtime').glob('consensus_capture_*.txt'), reverse=True)[:12]:
                        anc = line_anchor(root, f'harness/runtime/{capf.name}', f"kpi {s['field']} = {kv[s['field']]}")
                        if anc and capf.read_text(errors='replace').splitlines()[anc['line'] - 1].strip() == anc['quote']:
                            break
                        anc = None
                    e = {'value': kv[s['field']], 'anchor': anc or line_anchor(root, 'harness/runtime/consensus_intel.json',
                                                                             f'"{s["field"]}": {json.dumps(kv[s["field"]])}'),
                         'live_round': cd.get('binary_round') if str(cd.get('binary_round', '')).startswith('r') else UNKNOWN_ROUND}
                else:
                    e = {'value': PENDING, 'why': f"{s['field']} not in harness/runtime/consensus_intel.json" if cd else 'no consensus_intel.json (run harness/intel/consensus_intel.py)'}
            elif k == 'peerintel':          # r24 (consensus-network): a KPI of harness/runtime/peer_intel.json
                try:
                    pdoc = json.loads((Path(root) / 'harness/runtime/peer_intel.json').read_text())
                except (OSError, ValueError):
                    pdoc = None
                kv = ((pdoc or {}).get('kpis') or {}).get(s['field'], PENDING) if pdoc else PENDING
                if pdoc is None or kv is None or is_pending(kv):
                    e = {'value': PENDING, 'why': 'no harness/runtime/peer_intel.json (run harness/intel/peer_intel.py --live)' if pdoc is None
                         else f"peer_intel.json has no kpis.{s['field']}"}
                else:
                    # anchored on the KPI line of the run's own timestamped capture (peer_intel.json is rewritten every run)
                    capr = f"harness/runtime/{pdoc.get('capture_file')}"
                    e = {'value': kv, 'anchor': line_anchor(root, capr, f'"{s["field"]}": {json.dumps(kv)}', max(0, (pdoc.get('kpi_line') or 1) - 1)),
                         'live_round': capture_round(f"# version {pdoc.get('node_version')}\n", round_order(reg)) or UNKNOWN_ROUND}
            elif k == 'tooling':            # r25 (§0.9 rule 3): a KPI of harness/runtime/tooling_intel.json (tooling_intel.py)
                try:
                    tdoc = json.loads((Path(root) / 'harness/runtime/tooling_intel.json').read_text())
                except (OSError, ValueError):
                    tdoc = None
                kv = ((tdoc or {}).get('kpis') or {}).get(s['field'], PENDING)
                if isinstance(kv, list):
                    kv = len(kv)
                if tdoc is None or kv is None or is_pending(kv) or isinstance(kv, dict):
                    e = {'value': PENDING, 'why': 'no harness/runtime/tooling_intel.json (run harness/intel/tooling_intel.py)'
                         if tdoc is None else f"tooling_intel.json has no scalar kpis.{s['field']}"}
                else:
                    capr = f"harness/runtime/{tdoc.get('capture_file')}"
                    raw = (tdoc.get('kpis') or {}).get(s['field'])
                    q = f'"{s["field"]}": {json.dumps(raw)}' if not isinstance(raw, list) else f'"{s["field"]}": ['
                    e = {'value': kv, 'anchor': line_anchor(root, capr, q)}
                    if isinstance(raw, list):
                        e['display'] = f'{kv} (entries of the list)'
            elif k == 'forensics':          # r25 (rft §0.8.8): a KPI of harness/runtime/forensics_intel.json (forensics/facts.py --write)
                try:
                    fdoc = json.loads((Path(root) / 'harness/runtime/forensics_intel.json').read_text())
                except (OSError, ValueError):
                    fdoc = None
                kv = ((fdoc or {}).get('kpis') or {}).get(s['field'], PENDING)
                if fdoc is None or kv is None or is_pending(kv) or isinstance(kv, (dict, list)):
                    e = {'value': PENDING, 'why': 'no harness/runtime/forensics_intel.json (run harness/forensics/facts.py --write)'
                         if fdoc is None else f"forensics_intel.json has no scalar kpis.{s['field']}"}
                else:
                    e = {'value': kv, 'anchor': line_anchor(root, 'harness/runtime/forensics_intel.json', f'"{s["field"]}": {json.dumps(kv)}')}
            elif k == 'raw_count':
                try:
                    n = sum(1 for l in (Path(root) / s['file']).read_text().splitlines() if s['quote'] in l)
                    e = {'value': n, 'anchor': line_anchor(root, s['file'], s['quote'])} if n else {'value': 0, 'anchor': line_anchor(root, s['file'], '"rows"')}
                except OSError:
                    e = {'value': PENDING, 'why': f"{s['file']} not in this tree"}
            if e is not None:
                if not is_pending(e['value']) and not e.get('anchor'):
                    e = {'value': PENDING, 'why': 'read, but no anchor line found: refused (no anchor, no row)'}
                out[a['id']][m['id']] = e
    return out, {'prom': prel, 'prom_round': prom_round, 'logintel': li.name if li else None, 'datadir': dd.name if dd else None}


# ───────────────────────────── backlog (dero-rft §7) ─────────────────────────────
def backlog_rows(root):
    """{B id: {item, dim, anchor, status, line}} from the §7 table of artifacts/dero-rft.md."""
    out = {}
    try:
        lines = paths(root)['rft'].read_text().splitlines()
    except OSError:
        return out
    for i, l in enumerate(lines):
        m = re.match(r'^\|\s*(B\d+)\s*\|(.*)\|\s*$', l)
        if not m:
            continue
        c = [x.strip() for x in m.group(2).split('|')]
        if len(c) >= 4:
            out[m.group(1)] = {'item': c[0], 'dim': c[1], 'anchor': c[2], 'status': c[3], 'line': i + 1}
    return out


def is_open(status):
    return not re.match(r'^(CLOSED|REFUTED|DONE)\b', status.strip(), re.I)


def anchor_tokens(root, text, files=None):
    """(resolved, broken, testimony) tokens of a §7 'Evidence anchor' cell. A path or file name must exist in the tree;
    ARCHITECTURE §N / RUN_REPORT Round N / §N must name a heading; 'memory'/'GK' is testimony (re-verify in code)."""
    root = Path(root)
    ok, bad, gk = [], [], []
    if files is None:
        files = {p.name for p in root.rglob('*') if p.is_file() and '.git' not in p.parts and 'vendor' not in p.parts}
    for t in re.findall(r'`?([\w./-]+\.(?:go|py|json|jsonl|txt|md|swift|html|sh))(?::\d+)?`?', text):
        (ok if ((root / t).exists() or Path(t).name in files) else bad).append(t)
    arch = (root / 'ARCHITECTURE.md').read_text(errors='replace') if (root / 'ARCHITECTURE.md').exists() else ''
    for n in re.findall(r'ARCHITECTURE §(\d+(?:\.\d+)?)', text):    # a heading '## 41.' or a bold sub-head '**41.3 '
        (ok if re.search(rf'^(?:#+\s+(?:\S+\s+)?|\*\*){re.escape(n)}(?:\.|\s)', arch, re.M) else bad).append(f'ARCHITECTURE §{n}')
    rr = (root / 'RUN_REPORT.md').read_text(errors='replace') if (root / 'RUN_REPORT.md').exists() else ''
    for n in re.findall(r'RUN_REPORT(?:\.md)? Rounds? (\w+)', text):
        (ok if re.search(rf'^#+\s.*\bRound {re.escape(n)}\b', rr, re.M | re.I) else bad).append(f'RUN_REPORT Round {n}')
    text = re.sub(r'(ARCHITECTURE|RUN_REPORT)[^;|]*', '', text)       # their § numbers are not dero-rft sections
    if re.search(r'\bLedger\b', text):
        (ok if (root / 'artifacts/src/gen_ledger.py').exists() else bad).append('Ledger')
    for n in re.findall(r'(?<![\w.])§(\d+)\b', text):
        rft = (root / 'artifacts/dero-rft.md').read_text(errors='replace') if (root / 'artifacts/dero-rft.md').exists() else ''
        (ok if re.search(rf'^#+\s+{n}\.', rft, re.M) else bad).append(f'§{n}')
    if re.search(r'\bGK\b|memory `', text):
        gk.append('memory')
    return ok, bad, gk


# ───────────────────────────── series, trend, detectors ─────────────────────────────
def trend(prev, cur, better, noise_rel=0.05):
    """(direction, regression). direction: up / down / flat / new / n-a. A regression is a move against `better`
    larger than noise_rel of the previous value (fractions such as caught/total use the same rule)."""
    if cur is None:
        return 'n-a', False
    if prev is None:
        return 'new', False
    tol = abs(prev) * noise_rel
    if cur > prev + tol:
        d = 'up'
    elif cur < prev - tol:
        d = 'down'
    else:
        return 'flat', False
    return d, (better == 'higher' and d == 'down') or (better == 'lower' and d == 'up')


def alert(rule, v):
    if not rule or v is None:
        return False
    op, x = rule.get('op'), rule.get('value')
    return {'>': v > x, '<': v < x, '>=': v >= x, '<=': v <= x, '!=': v != x}.get(op, False)


# r26 B105: a metric's direction class. 'node' (default): a move against `better` is a regression of THIS build and a
# live alert is a node alert (severity high, area ATTENTION). 'network': the metric measures other nodes or the chain
# (an observatory KPI: another peer's lag, chain concentration, v2-remnant sightings), so the same move proposes a §7
# OBSERVATION row (kind network-observation, severity medium, area WATCH), never a regression: the R25 measurement and
# the R26 start each raised 5 high proposals that measured the network and were closed by hand as observations.
# r27 B134 (tools-kats): 'record': the metric COUNTS findings that are already booked at their own source record (a
# dataset's audit report: FAIL challenges fixed at source with the history kept, a new version's pending grade), so a
# rise is a new recorded finding to read there, never a regression of this build: kind recorded-finding, severity low
# (area OK), suggested row RECORDED. The R26 measurement proposed forensics.audit_fails 0 -> 3 and grade_pending 1 -> 2
# as two HIGH regressions (area ATTENTION) while both were dataset v2's recorded audit-2 findings (B105's class, for
# the forensics area). The metric names its record in 'record'.
METRIC_CLASSES = ('node', 'network', 'record')
NETWORK_KIND, NETWORK_SEVERITY = 'network-observation', 'medium'
RECORD_KIND, RECORD_SEVERITY = 'recorded-finding', 'low'


def classed(m, kind, severity, title):
    """(kind, severity, title) of one metric finding after its direction class. Pure."""
    c = m.get('class', 'node')
    if c == 'record':
        src = m.get('record') or 'its source record'
        return RECORD_KIND, RECORD_SEVERITY, f'{title} [recorded-findings KPI ({kind}): each finding is booked at {src}, not a regression]'
    if c != 'network':
        return kind, severity, title
    return NETWORK_KIND, NETWORK_SEVERITY, f'{title} [network KPI ({kind}): an observation of other nodes, not a node regression]'


def suggested_row(kind, title, owner, evs, cur):
    """the §7 row a proposal suggests: a network observation is booked as an OBSERVATION, a recorded finding as
    RECORDED (r27 B134), everything else OPEN."""
    status = (f'OBSERVATION (network, self-detected {cur}, area_intel; no node regression)' if kind == NETWORK_KIND
              else f'RECORDED (self-detected {cur}, area_intel; booked at its source record, no regression)'
              if kind == RECORD_KIND else f'OPEN (self-detected {cur}, area_intel)')
    return f"| B? | {title} | {owner} | {evs} | {status} |"


def pid(area, kind, key):
    return f"AP-{area}-{kind}-{hashlib.sha256(f'{area}|{kind}|{key}'.encode()).hexdigest()[:6]}"


def evaluate(root, live=False, cur_override=None):
    """The whole computation. Returns (doc, proposals, errors)."""
    root = Path(root)
    reg = load_registry(root)
    errors, warnings = validate(reg, root)
    order = round_order(reg)
    cur, tracks = current_round(root)
    if cur_override:
        cur = cur_override
    if cur not in order:
        warnings.append(f'current round {cur!r} is not in areas.json rounds')
    for rid in unpinned_rounds(reg, cur):          # r25 (B52)
        warnings.append(f'round {rid}: pipeline records not pinned in areas.json rounds (its values follow the newest run labelled {rid})')
    tidx = test_index(root)
    auto = {}
    rrecs = {}
    for rid in order:
        auto[rid], rrecs[rid] = auto_round(root, reg, rid, tidx)
    live_note = None
    if live:
        _, live_note = live_capture(root, reg)
    curv, cur_src = current_values(root, reg)
    gp, gm = newest_gomut(root)
    grows = gate_rows(root)
    cycles = []
    for r in grows:
        if r[1] not in cycles:
            cycles.append(r[1])
    cyc_last, cyc_prev = (cycles[-1] if cycles else None), (cycles[-2] if len(cycles) > 1 else None)
    gstate = lambda cyc: {r[2]: (r[4], r[5], r[0], r[3]) for r in grows if r[1] == cyc}
    g_now, g_before = gstate(cyc_last), gstate(cyc_prev)
    blog = backlog_rows(root)
    files = {p.name for p in root.rglob('*') if p.is_file() and '.git' not in p.parts and 'vendor' not in p.parts}
    kat_all = sorted(p.relative_to(root).as_posix() for p in paths(root)['kat'].glob('test_*.py')) + \
        (['harness/kat/verify_deroarch.py'] if (paths(root)['kat'] / 'verify_deroarch.py').exists() else [])
    owned_kats = {k for a in reg['areas'] for k in a.get('kat_files', [])}
    # log_intel: ERROR kinds of the newest snapshot vs the 5 before it
    lis = sorted(paths(root)['runtime'].glob('logintel_*.json'))
    new_kinds = []
    if lis:
        def kinds(p):
            try:
                d = json.loads(p.read_text())
            except ValueError:
                return set(), {}
            ks = {}
            for r in d.get('runs', []):
                for k in list((r.get('errors') or {}).keys()) + list((r.get('warns') or {}).keys()):
                    ks[k] = r
            return set(ks), ks
        now_k, _ = kinds(lis[-1])
        seen = set()
        for p in lis[-6:-1]:
            seen |= kinds(p)[0]
        new_kinds = sorted(now_k - seen) if len(lis) > 1 else []
    props, cards = [], []
    stale_n = int(reg.get('stale_rounds', 2))
    for a in reg['areas']:
        aid = a['id']
        paused, pwhy = area_paused(a, tracks)
        found = []          # (kind, severity, title, evidence, key)
        # series per metric: history first, then computed records, then the current read for the current round
        mdefs = [{'id': k, 'what': {'new_tests': 'registered own tests (NEW_TESTS) run in S3, attributed by the file that defines them', 'mutations': 'go_mutate caught/total in the area files',
                                    'kats': 'KAT files of the area passing', 'gates': 'gates of the area PASS'}[k],
                  'better': {'new_tests': 'none', 'mutations': 'higher', 'kats': 'higher', 'gates': 'higher'}[k], 'noise_rel': 0.0,
                  'source': {'kind': 'auto'}} for k in AUTO] + a.get('metrics', [])
        mcards, broken, total_vals, refused = [], [], 0, []
        for m in mdefs:
            if (m['id'] == 'kats' and not a.get('kat_files')) or (m['id'] == 'gates' and not a.get('gates')):
                continue
            pts = []
            cv = curv.get(aid, {}).get(m['id'])
            live_r = (cv or {}).get('live_round') or cur      # r25: 'unknown' matches no round, so it is shown nowhere
            for rid in order:
                h = (a.get('history') or {}).get(rid, {}).get(m['id'])
                c = auto[rid].get(aid, {}).get(m['id'])
                if rid == live_r and cv and not (c and not is_pending(c.get('value'))):
                    c = cv
                e = h if (h and not is_pending(h.get('value'))) else (c if (c and not is_pending(c.get('value'))) else (h or c))
                if not e:
                    continue
                if is_pending(e.get('value')):
                    pts.append({'round': rid, 'value': PENDING, 'why': e.get('why')})
                    continue
                total_vals += 1
                st = resolve_anchor(root, e.get('anchor'))
                if not resolved(st):
                    refused.append(f"{m['id']}@{rid}")
                    broken.append({'metric': m['id'], 'round': rid, 'anchor': e.get('anchor'), 'status': st['status']})
                    continue
                pt = {'round': rid, 'value': e['value'], 'display': e.get('display') or str(e['value']),
                      'anchor': {**e['anchor'], 'line': st['line']}, 'source': 'history' if e is h else 'computed'}
                if e.get('note'):
                    pt['note'] = e['note']
                if e is h and c and not is_pending(c.get('value')) and c.get('computed') and not same_value(c['value'], h['value']):
                    found.append(('history-drift', 'medium', f"{m['id']}@{rid}: recorded {h['value']!r} but the records now compute {c['value']!r}",
                                  [h.get('anchor'), c.get('anchor')], f"{m['id']}@{rid}"))
                pts.append(pt)
            measured = [p for p in pts if not is_pending(p['value'])]
            last = measured[-1] if measured else None
            prev = measured[-2] if len(measured) > 1 else None
            d, reg_ = trend(num(prev['value']) if prev else None, num(last['value']) if last else None,
                            m.get('better', 'none'), float(m.get('noise_rel', 0.05)))
            if reg_ and m.get('better', 'none') != 'none':
                found.append((*classed(m, 'metric-regression', 'high', f"{m['id']}: {prev['display']} ({prev['round']}) -> {last['display']} ({last['round']}), "
                              f"worse than {m.get('noise_rel', 0.05):.0%} noise ({m.get('better')} is better)"), [prev['anchor'], last['anchor']], m['id']))
            if last and last['round'] == live_r and alert(m.get('alert_if'), num(last['value'])):
                found.append((*classed(m, 'live-alert', 'high', f"{m['id']} = {last['display']} trips {m['alert_if']['op']} {m['alert_if']['value']}"),
                              [last['anchor']], m['id'] + ('|alert' if m.get('class') in ('network', 'record') else '')))   # one kind for both: keep the ids apart
            mcards.append({'id': m['id'], 'what': m.get('what'), 'unit': m.get('unit', ''), 'better': m.get('better', 'none'),
                           'series': pts, 'last': last, 'prev': prev, 'trend': d, 'regression': reg_})
        for b in broken:
            found.append(('anchor-broken', 'high', f"{b['metric']}@{b['round']}: anchor {b['status']} ({(b['anchor'] or {}).get('file')})",
                          [b['anchor']], f"{b['metric']}@{b['round']}"))
        # the newest go_mutate record: surviving / INVALID / stale mutations in this area
        rs = mutations_of(a, reg['areas'], gm) if gm else []
        for r in rs:
            if r.get('result') in BAD_MUT:
                found.append((f"mutation-{r['result'].lower()}", 'medium' if r['result'] == 'INVALID' else 'high',
                              f"{r['id']} ({r.get('file')}) is {r['result']} in {gp.name}",
                              [line_anchor(root, f'harness/runtime/{gp.name}', f'"id": "{r["id"]}"')], r['id']))
        mut_now = {'caught': sum(1 for r in rs if r.get('result') == 'CAUGHT'), 'total': len(rs),
                   'invalid': sum(1 for r in rs if r.get('result') == 'INVALID'),
                   'bad': sorted(r['id'] for r in rs if r.get('result') in BAD_MUT), 'record': gp.name if gp else None}
        # gates: the newest cycle vs the cycle before it
        gcard = {}
        for g in a.get('gates', []):
            now_s = g_now.get(g)
            bef = g_before.get(g)
            state = now_s[0] if now_s else 'no row'
            if now_s and 'PAUSED' in now_s[1][:40]:
                state = 'PAUSED'
            gcard[g] = state
            if now_s and now_s[0] == 'FAIL':
                ev = [{'file': 'harness/loop/GATES.md', 'quote': f'| {cyc_last} | {now_s[3]}', 'line': now_s[2]}]
                if bef and bef[0] == 'PASS':
                    found.append(('gate-newly-failing', 'high', f'{g} FAIL in {cyc_last} (PASS in {cyc_prev}): {now_s[1][:160]}', ev, g))
                else:
                    found.append(('gate-failing', 'medium', f'{g} FAIL in {cyc_last}: {now_s[1][:160]}', ev, g))
        # derod ERROR kinds new in the newest log snapshot, owned by the file that printed them
        for k in new_kinds:
            f = k.split(':', 1)[0]
            if area_of(reg['areas'], f) == aid:
                found.append(('log-new-error-kind', 'medium', f'new derod ERROR kind {k!r} in {lis[-1].name}',
                              [line_anchor(root, f'harness/runtime/{lis[-1].name}', json.dumps(k))], k))
        # r24: proposal feeds a tool writes for its area (consensus_intel.json 'proposals': node-side gaps, CO24-*)
        for fd in a.get('feeds') or []:
            try:
                fdoc = json.loads((root / fd['file']).read_text())
            except (OSError, ValueError, KeyError):
                found.append(('feed-unreadable', 'medium', f"proposal feed {fd.get('file')} unreadable", [], fd.get('file')))
                continue
            for fp in fdoc.get(fd.get('list', 'proposals')) or []:
                fa = line_anchor(root, fd['file'], f'{{"id": "{fp.get("id")}"')
                found.append((fd.get('kind', 'node-gap'), fp.get('severity', 'medium') if fp.get('severity') in ('high', 'medium', 'low') else 'medium',
                              f"{fp.get('id')}: {fp.get('title')}", [fa] + list(fp.get('anchors') or [])[:2], fp.get('id')))
        # r24 (integration): an observatory's OBSERVED / ANOMALY detectors are proposals of its area (consensus_intel.json,
        # peer_intel.json 'detectors'): dero-rft §0.7 turns each into a §7 row or a stated non-action, every round
        for fd in a.get('detector_feeds') or []:
            try:
                fdoc = json.loads((root / fd['file']).read_text())
            except (OSError, ValueError, KeyError):
                found.append(('feed-unreadable', 'medium', f"detector feed {fd.get('file')} unreadable", [], fd.get('file')))
                continue
            for d in fdoc.get(fd.get('list', 'detectors')) or []:
                g = d.get('grade')
                if g not in (fd.get('grades') or ('OBSERVED', 'ANOMALY')):
                    continue
                da = line_anchor(root, fd['file'], f'"id": "{d.get("id")}"')
                val = d.get('value') if d.get('value') not in (None, '') else f"{len(d.get('findings') or [])} finding(s)"
                found.append((f'observatory-{g.lower()}', 'medium' if g == 'OBSERVED' else 'low',
                              f"{d.get('id')} {g}: {d.get('title')} ({str(val)[:120]})", [da] if da else [], f"{d.get('id')}"))
        # tests named for the current round that the round's S3 test stage did not run (not in NEW_TESTS)
        um = auto.get(cur, {}).get(aid, {}).get('_unregistered') or []
        if um and rrecs.get(cur, {}).get('full'):
            found.append(('tests-unregistered', 'medium', f"{len(um)} test(s) named for {cur} are in the tree but not in the S3 test stage of "
                          f"{rrecs[cur]['full']} (NEW_TESTS), e.g. {um[:3]}", [{'file': f"harness/loop/runs/{rrecs[cur]['full']}.jsonl",
                          'quote': '"stage": "test"'}], 'unregistered'))
        # r24 (consensus-network): node-side gaps an observatory needed and could not read (CO24-*, peer_intel.py), each
        # anchored on the code line that shows the gap: the next round implements them (dero-rft §7 B63-B69, CO24-N1..N7)
        try:
            _pi = json.loads((root / 'harness/runtime/peer_intel.json').read_text())
        except (OSError, ValueError):
            _pi = {}
        for g in _pi.get('proposals') or []:
            # r25 (peers): a gap whose closing line is in the tree is implemented, no longer a proposal
            if g.get('area') == aid and (g.get('anchor') or {}).get('line') and not str(g.get('status', '')).startswith('implemented'):
                ga = line_anchor(root, g['anchor']['file'], g['anchor']['quote'])
                if ga:
                    found.append(('node-gap', 'medium', f"{g['id']}: {g['title']} (for {g.get('target', 'R25')}: {g['proposal']})", [ga], g['id']))
        # KAT files
        kat_present = [k for k in a.get('kat_files', []) if (root / k).exists()]
        for k in a.get('kat_files', []):
            if k not in kat_present:
                found.append(('kat-absent', 'low', f'registered KAT {k} is not in this tree', [], k))
        # backlog
        bl = {'open': [], 'closed': [], 'missing': []}
        for b in a.get('backlog', []):
            row = blog.get(b)
            if not row:
                bl['missing'].append(b)
                found.append(('backlog-missing', 'low', f'{b} is registered to the area but not in dero-rft §7', [], b))
                continue
            (bl['open'] if is_open(row['status']) else bl['closed']).append(b)
            if is_open(row['status']):
                ok_t, bad_t, gk = anchor_tokens(root, row['anchor'], files)
                ev = [{'file': 'artifacts/dero-rft.md', 'quote': f'| {b} |', 'line': row['line']}]
                if bad_t:
                    found.append(('backlog-anchor-broken', 'medium', f'{b}: anchor token(s) {bad_t} no longer resolve', ev, b))
                elif not ok_t:
                    found.append(('backlog-unanchored', 'low', f'{b}: no tree anchor, only {gk or "free text"}: re-verify in code before acting', ev, b))
        # coverage and staleness
        cov = len(kat_present) + mut_now['total'] + len(a.get('gates', []))
        if cov == 0:
            found.append(('zero-coverage', 'high', 'no KAT file, no go_mutate mutation and no gate covers this area', [], 'cov'))
        defined = [mc for mc in mcards if mc['id'] not in AUTO]
        if defined:
            lastr = max((order.index(mc['last']['round']) for mc in defined if mc['last']), default=-1)
            if cur in order and order.index(cur) - lastr > stale_n:
                found.append(('stale-evidence', 'medium', f'no registered metric measured since '
                              f'{order[lastr] if lastr >= 0 else "never"} (more than {stale_n} rounds before {cur})', [], 'stale'))
        else:
            found.append(('no-metrics', 'low', 'the area registers no metric of its own', [], 'metrics'))
        # track mismatch (registry vs round.json)
        if a.get('track') and tracks.get(a['track']) and (a.get('status') == 'paused') != (tracks[a['track']] == 'paused'):
            found.append(('track-mismatch', 'high', f"registry status {a.get('status')} but round.json tracks.{a['track']} = {tracks[a['track']]}",
                          [{'file': 'harness/round.json', 'quote': f'"{a["track"]}": "{tracks[a["track"]]}"'}], 'track'))
        held = []
        if paused:      # PAUSED, never failing: keep what would have been flagged, visibly
            keep = ('anchor-broken', 'track-mismatch')
            held = [{'kind': k, 'title': t} for k, s, t, e, key in found if k not in keep]
            found = [f for f in found if f[0] in keep]
        aprops = []
        for k, s, t, e, key in found:
            p = {'id': pid(aid, k, key), 'area': aid, 'owner_dim': a['owner_dim'], 'kind': k, 'severity': s, 'title': t,
                 'evidence': [x for x in e if x], 'round_found': cur}
            evs = '; '.join(f"{x.get('file')}:{x.get('line')}" for x in p['evidence']) or f'area_intel {k}'
            p['suggested_row'] = suggested_row(k, t, a['owner_dim'], evs, cur)
            aprops.append(p)
        props += aprops
        sev = {p['severity'] for p in aprops}
        state = 'PAUSED' if paused else ('ATTENTION' if 'high' in sev else ('WATCH' if 'medium' in sev else 'OK'))
        if not paused and total_vals == 0:
            state = 'NO-DATA'
        cards.append({'id': aid, 'title': a['title'], 'owner_dim': a['owner_dim'], 'status': 'paused' if paused else 'active',
                      'state': state, 'paused_why': pwhy, 'paused_anchor': a.get('paused_why') if paused else None,
                      'code_paths': a.get('code_paths'), 'kat_files': {'registered': a.get('kat_files', []), 'present': kat_present},
                      'mutations_now': mut_now, 'gates_now': {'cycle': cyc_last, 'state': gcard}, 'backlog': bl,
                      'metrics': mcards, 'anchors': {'values': total_vals, 'refused': len(refused), 'refused_ids': refused},
                      'proposals': [p['id'] for p in aprops], 'held': held,
                      'registry_anchor': line_anchor(root, 'harness/areas.json', f'"id": "{aid}"')})
    # tree-wide detectors
    for k in kat_all:
        if k not in owned_kats:
            props.append({'id': pid('harness', 'kat-unassigned', k), 'area': 'harness', 'owner_dim': 'harness', 'kind': 'kat-unassigned',
                          'severity': 'low', 'title': f'{k} is not registered to any area in harness/areas.json', 'evidence': [],
                          'round_found': cur, 'suggested_row': f'| B? | register {k} in harness/areas.json | harness | {k} | OPEN (self-detected {cur}) |'})
    reg_bl = {b for a in reg['areas'] for b in a.get('backlog', [])}
    for b, row in sorted(blog.items(), key=lambda kv: int(kv[0][1:])):
        if b not in reg_bl and is_open(row['status']):
            props.append({'id': pid('harness', 'backlog-unassigned', b), 'area': 'harness', 'owner_dim': 'harness', 'kind': 'backlog-unassigned',
                          'severity': 'low', 'title': f'open §7 row {b} ({row["dim"]}) belongs to no area', 'round_found': cur,
                          'evidence': [{'file': 'artifacts/dero-rft.md', 'quote': f'| {b} |', 'line': row['line']}],
                          'suggested_row': f'| {b} | add {b} to an area in harness/areas.json | harness | artifacts/dero-rft.md:{row["line"]} | OPEN |'})
    # carry first_seen across runs so a proposal that survives rounds shows its age
    try:
        old = {p['id']: p for p in json.loads(paths(root)['props'].read_text()).get('proposals', [])}
    except (OSError, ValueError):
        old = {}
    for p in props:
        o = old.get(p['id'])
        p['first_seen'] = (o or {}).get('first_seen', cur)
        p['runs_seen'] = (o or {}).get('runs_seen', 0) + 1
    run_id = now().strftime('%Y%m%dT%H%M%S')
    doc = {'_doc': 'r24 area_intel scorecards (harness/intel/area_intel.py); dero-rft §0.4. Every shown value has an anchor that resolved at capture time.',
           'captured': now().isoformat(timespec='seconds'), 'run_id': run_id, 'round': cur, 'tracks': tracks,
           'registry': {'file': 'harness/areas.json', 'sha': sha(paths(root)['reg']), 'errors': errors, 'warnings': warnings},
           'inputs': {'rounds': {rid: rrecs[rid] for rid in order}, 'gomut_newest': gp.name if gp else None, 'gate_cycle': cyc_last,
                      'gate_cycle_prev': cyc_prev, 'live': live_note or ('captured' if live else 'off'), **cur_src},
           'summary': {'areas': len(cards), 'active': sum(1 for c in cards if c['status'] == 'active'),
                       'paused': sum(1 for c in cards if c['status'] == 'paused'),
                       'states': {s: sum(1 for c in cards if c['state'] == s) for s in ('OK', 'WATCH', 'ATTENTION', 'NO-DATA', 'PAUSED')},
                       'proposals': len(props), 'refused_values': sum(c['anchors']['refused'] for c in cards)},
           'areas': cards}
    pdoc = {'_doc': 'r24 area_intel proposals feed: candidate items for dero-rft §7 (with anchors) and §8 (owner_dim). '
                    'Each round: triage every proposal: add it as a §7 row, or mark it explained in §7/§9 with its anchor.',
            'captured': doc['captured'], 'run_id': run_id, 'round': cur,
            'counts': {s: sum(1 for p in props if p['severity'] == s) for s in ('high', 'medium', 'low')},
            'proposals': sorted(props, key=lambda p: ({'high': 0, 'medium': 1, 'low': 2}[p['severity']], p['area'], p['kind'], p['id']))}
    return doc, pdoc, errors


def write(root, doc, pdoc):
    P = paths(root)
    P['out'].write_text(json.dumps(doc, indent=1, ensure_ascii=False) + '\n')
    P['props'].write_text(json.dumps(pdoc, indent=1, ensure_ascii=False) + '\n')


# ───────────────────────────── G23 ─────────────────────────────
def g23(root=ROOT, at=None):
    """(ok, detail): the registry is valid; every active area has a scorecard; no shown value is refused; the
    scorecard and the proposals feed are from the same run, under FRESH_H hours old, and of the registry as it is now."""
    root = Path(root)
    P = paths(root)
    at = at or now()
    try:
        doc = json.loads(P['out'].read_text())
        pdoc = json.loads(P['props'].read_text())
        reg = load_registry(root)
    except (OSError, ValueError) as e:
        return False, f'area_intel output or registry unreadable ({type(e).__name__}): run harness/intel/area_intel.py'
    why = []
    errors, _ = validate(reg, root)
    if errors:
        why.append(f'registry errors {errors[:3]}')
    age = (at - datetime.datetime.fromisoformat(doc['captured'])).total_seconds() / 3600
    if age >= FRESH_H:
        why.append(f'scorecard {age:.1f} h old (>= {FRESH_H} h)')
    if pdoc.get('run_id') != doc.get('run_id'):
        why.append('proposals feed is not from the scorecard run')
    if doc.get('registry', {}).get('sha') != sha(P['reg']):
        why.append('areas.json changed after the scorecard run')
    cards = {c['id']: c for c in doc.get('areas', [])}
    active = [a['id'] for a in reg.get('areas', []) if a.get('status') == 'active']
    miss = [a for a in active if a not in cards]
    if miss:
        why.append(f'active areas without a scorecard {miss}')
    refused = {c['id']: c['anchors']['refused_ids'] for c in cards.values() if c['anchors']['refused']}
    if refused:
        why.append(f'values refused for a missing anchor {refused}')
    for c in cards.values():                 # every shown value still resolves now
        for m in c['metrics']:
            for p in m['series']:
                if not is_pending(p['value']) and not resolved(resolve_anchor(root, p.get('anchor'))):
                    why.append(f"{c['id']}.{m['id']}@{p['round']} anchor no longer resolves")
    s = doc.get('summary', {})
    det = (f"{s.get('areas')} areas ({s.get('active')} active, {s.get('paused')} paused) states {s.get('states')} · "
           f"{s.get('proposals')} proposals {pdoc.get('counts')} · refused {s.get('refused_values')} · run {doc.get('run_id')} "
           f"({age:.1f} h old)")
    return not why, det + (f" · {'; '.join(why)[:400]}" if why else '')


# ───────────────────────────── maintenance commands ─────────────────────────────
def fix_lines(root):
    reg = load_registry(root)
    changed, problems = 0, []
    for a in reg['areas']:
        for rid, vals in (a.get('history') or {}).items():
            for mid, v in vals.items():
                an = v.get('anchor') if isinstance(v, dict) else None
                if not an:
                    continue
                st = resolve_anchor(root, an)
                if st['status'] == 'OK':
                    continue
                try:
                    hits = [i + 1 for i, l in enumerate((Path(root) / an['file']).read_text(errors='replace').splitlines()) if an['quote'] in l]
                except OSError:
                    hits = []
                if len(hits) >= 1:
                    an['line'] = hits[0]
                    changed += 1
                    if len(hits) > 1:
                        problems.append(f'{a["id"]}.{mid}@{rid}: quote occurs {len(hits)} times, first taken')
                else:
                    problems.append(f'{a["id"]}.{mid}@{rid}: quote not in {an["file"]}')
    for r in reg.get('rounds', []):
        an = r.get('anchor')
        if an and resolve_anchor(root, an)['status'] == 'MOVED':
            an['line'] = resolve_anchor(root, an)['line']
            changed += 1
        elif an and not an.get('line') and resolved(resolve_anchor(root, an)):
            an['line'] = resolve_anchor(root, an)['line']
            changed += 1
    for a in reg['areas']:
        an = a.get('paused_why')
        if an and resolved(resolve_anchor(root, an)) and an.get('line') != resolve_anchor(root, an)['line']:
            an['line'] = resolve_anchor(root, an)['line']
            changed += 1
    paths(root)['reg'].write_text(json.dumps(reg, indent=1, ensure_ascii=False) + '\n')
    return changed, problems


def recordable(ms):
    """(metric id, entry) pairs of one area's computed values that record() may book: a dict entry with a measured value
    and an anchor. Keys starting '_' are bookkeeping (e.g. '_unregistered', a list of test names), never history.
    Pure (r24 merge: record r24 crashed with AttributeError on '_unregistered'; harness/kat/test_area_record_r24.py)."""
    out = []
    for k, e in (ms or {}).items():
        if k.startswith('_') or not isinstance(e, dict):
            continue
        if is_pending(e.get('value')) or not e.get('anchor'):
            continue
        out.append((k, e))
    return out


def bookable(ent, mid, kind, unit, text):
    """(ok, why): may record() book history entry `ent` of metric `mid` (source kind `kind`)? A value the records
    recompute (AUTO metrics, RECOMP kinds) is checked by drift; any other one must be STATED by its anchored line
    (`text`, as validate() requires: AI9), so a derived reading (a ratio of two series, a labelled-series sum, a row
    count) is not booked and stays pending. Pure (r24 merge: record r24 booked 6 such values and check then failed)."""
    if mid in AUTO or kind in RECOMP:
        return True, 'recomputed'
    ok, how = backed(ent, text, unit)
    return ok, how


def live_belongs(e, rid):
    """True when a current-read entry may be booked to round `rid`: it carries no live_round (not a live capture), or
    the capture's binary round IS rid. A reading of the r23c binary is never booked to r24 (§0.4: a live reading
    belongs to the round of the binary it was read from). Pure (r24 merge: record r24 booked 12 values of the r23c
    derod's /metrics while the r24 binary was installed but not yet running)."""
    lr = e.get('live_round') if isinstance(e, dict) else None
    # r25 (B89): a capture of an unknown binary carries live_round 'unknown' (UNKNOWN_ROUND), which equals no round id
    return lr is None or str(lr).lower() == str(rid).lower()


# r26 closed loop (pipeline_20261104T193301 S7 FAIL, 7 r25 forensics values BROKEN): harness/runtime/forensics_intel.json
# is rewritten by every S7 (facts.py --write), and from R26 it holds dataset v2's KPIs, so an r25 history anchor on it broke
# one round later (the B106 class, for the forensics source). record() now books such a value against a per-round sealed
# copy, harness/runtime/forensics_intel_<round>.json, written here and never rewritten by any S7 step.
VOLATILE_SEAL = {'harness/runtime/forensics_intel.json': 'harness/runtime/forensics_intel_{rid}.json'}


def seal_volatile(root, rid, vals):
    """re-point every value of `vals` anchored on a VOLATILE_SEAL file at that round's sealed copy (written once per
    record run from the file's current bytes; the anchor line is the same, the copy being byte-equal). Returns the sealed
    copies written."""
    out = []
    for src, pat in VOLATILE_SEAL.items():
        uses = [e for ms in vals.values() for e in ms.values()
                if isinstance(e, dict) and (e.get('anchor') or {}).get('file') == src]
        if not uses or not (Path(root) / src).is_file():
            continue
        dst = pat.format(rid=rid)
        (Path(root) / dst).write_bytes((Path(root) / src).read_bytes())
        for e in uses:
            e['anchor'] = {**e['anchor'], 'file': dst}
        out.append(dst)
    return out


def record(root, rid):
    """Copy the computed values of round `rid` (records + current read when rid is current) into areas.json history.
    A value already recorded is kept; a recorded value that no longer recomputes is reported, never overwritten."""
    reg = load_registry(root)
    tidx = test_index(root)
    vals, _ = auto_round(root, reg, rid, tidx)
    cur, _ = current_round(root)
    if rid == cur:
        cv, _ = current_values(root, reg)
        skipped_live = []
        for aid, ms in cv.items():
            for k, e in ms.items():
                if isinstance(e, dict) and not is_pending(e.get('value')):
                    if not live_belongs(e, rid):
                        skipped_live.append(f"{aid}.{k}@{rid}: not booked, live reading of the {e.get('live_round')} "
                                            f"binary ({(e.get('anchor') or {}).get('file')}); stays pending until the {rid} binary runs")
                        continue
                    vals[aid].setdefault(k, e)
    added, kept = 0, (skipped_live if rid == cur else [])
    sealed = seal_volatile(root, rid, vals)
    for a in reg['areas']:
        h = a.setdefault('history', {}).setdefault(rid, {})
        kinds = {m.get('id'): ((m.get('source') or {}).get('kind'), m.get('unit', '')) for m in a.get('metrics', [])}
        for k, e in recordable(vals.get(a['id'], {})):
            ent = {'value': e['value'], 'anchor': {kk: e['anchor'][kk] for kk in ('file', 'quote', 'line')}}
            if e.get('display'):
                ent['display'] = e['display']
            kind, unit = kinds.get(k, (None, ''))
            st = resolve_anchor(root, ent['anchor'])
            okb, how = bookable(ent, k, kind, unit, anchored_text(root, ent['anchor'], st) if resolved(st) else '')
            if not okb:
                kept.append(f"{a['id']}.{k}@{rid}: not booked, {e['value']!r} is not stated by its anchored line "
                            f"({ent['anchor']['file']}:{ent['anchor'].get('line')}; {how}); stays pending")
                continue
            if k in h and not is_pending(h[k].get('value')):
                if not same_value(h[k]['value'], e['value']):
                    kept.append(f"{a['id']}.{k}@{rid}: kept {h[k]['value']!r}, records compute {e['value']!r}")
                continue
            h[k] = ent
            added += 1
        if not h:
            a['history'].pop(rid)
    paths(root)['reg'].write_text(json.dumps(reg, indent=1, ensure_ascii=False) + '\n')
    return added, kept


# ───────────────────────────── r25 (B52): dated corrections ─────────────────────────────
DATE_RX = re.compile(r'^\d{4}-\d{2}-\d{2}$')


def correction_problems(root, cs):
    """registry errors of one entry's `corrections` list: each needs a date (YYYY-MM-DD), the superseded value
    (`was`), a why, and an evidence anchor that resolves (no anchor, no correction). Pure but for the anchor read."""
    if cs is None:
        return []
    if not isinstance(cs, list):
        return ['corrections must be a list']
    out = []
    for i, c in enumerate(cs):
        if not isinstance(c, dict):
            out.append(f'correction {i} is not an object')
            continue
        if not DATE_RX.match(str(c.get('date', ''))):
            out.append(f'correction {i}: date {c.get("date")!r} is not YYYY-MM-DD')
        if 'was' not in c:
            out.append(f'correction {i}: no superseded value (was)')
        if not str(c.get('why', '')).strip():
            out.append(f'correction {i}: no why')
        if not resolved(resolve_anchor(root, c.get('evidence'))):
            out.append(f'correction {i}: evidence anchor does not resolve')
    return out


def apply_correction(ent, new, date, why, evidence):
    """r25 (B52): the history entry `ent` corrected to `new` (an entry {value, anchor[, display]} or {value: pending,
    why}), with the superseded value kept, dated, in ent['corrections'] (oldest first). Never rewrites history
    silently: the old value, its anchor and display stay readable. Returns the new entry. Pure."""
    old = dict(ent or {})
    prior = list(old.pop('corrections', []) or [])
    prior.append({'date': date, 'was': old.get('value'), 'was_anchor': old.get('anchor'),
                  **({'was_display': old['display']} if old.get('display') else {}),
                  **({'was_note': old['note']} if old.get('note') else {}), 'why': why, 'evidence': evidence})
    out = {k: v for k, v in new.items() if k in ('value', 'anchor', 'display', 'why', 'note')}
    out['corrections'] = prior
    return out


def correct(root, rid, why, date=None, target=None, new=None):
    """r25 (B52). Without `target`: every booked value of round `rid` whose records now recompute a different value
    (the history-drift proposals of evaluate) is corrected to the recomputed value, dated, with the old one kept. With
    `target` ('area.metric') and `new` (an entry): that one value. Returns (changed, problems)."""
    date = date or now().strftime('%Y-%m-%d')
    if not why or not why.strip():
        return 0, ['a correction needs --why']
    reg = load_registry(root)
    vals, _ = auto_round(root, reg, rid, test_index(root))
    changed, probs = 0, []
    for a in reg['areas']:
        h = (a.get('history') or {}).get(rid) or {}
        for mid, ent in list(h.items()):
            if target and target != f"{a['id']}.{mid}":
                continue
            if target:
                ev = new.get('anchor') or new.get('evidence')
                if not resolved(resolve_anchor(root, ev)):
                    probs.append(f"{target}@{rid}: the new value's anchor/evidence does not resolve")
                    continue
                nn = {k: v for k, v in new.items() if k != 'evidence'}
                h[mid] = apply_correction(ent, nn, date, why, ev)
                changed += 1
                continue
            c = vals.get(a['id'], {}).get(mid)
            if not (isinstance(ent, dict) and isinstance(c, dict) and c.get('computed') and not is_pending(c.get('value'))
                    and not is_pending(ent.get('value')) and not same_value(ent['value'], c['value'])):
                continue
            h[mid] = apply_correction(ent, {'value': c['value'], 'anchor': {kk: c['anchor'][kk] for kk in ('file', 'quote', 'line')}},
                                      date, why, {kk: c['anchor'][kk] for kk in ('file', 'quote', 'line')})
            changed += 1
    if target and not changed and not probs:
        probs.append(f'{target}@{rid}: no booked value to correct')
    paths(root)['reg'].write_text(json.dumps(reg, indent=1, ensure_ascii=False) + '\n')
    return changed, probs


def _opt(argv, name):
    return argv[argv.index(name) + 1] if name in argv and argv.index(name) + 1 < len(argv) else None


def main(argv):
    if argv[:1] == ['correct']:                      # r25 (B52)
        rest = [a for i, a in enumerate(argv[1:], 1) if not a.startswith('--') and argv[i - 1] not in
                ('--why', '--date', '--value', '--file', '--quote')]
        why, date = _opt(argv, '--why'), _opt(argv, '--date')
        if not rest:
            print('usage: correct <round> [<area>.<metric> (--pending | --value V --file F --quote Q)] --why TEXT')
            return 2
        new = None
        if len(rest) > 1:
            if '--pending' in argv:
                ev = {'file': _opt(argv, '--file'), 'quote': _opt(argv, '--quote')}
                new = {'value': PENDING, 'why': why, 'evidence': line_anchor(ROOT, ev['file'], ev['quote']) if ev['file'] else None}
            else:
                v = _opt(argv, '--value')
                try:
                    v = json.loads(v)
                except (TypeError, ValueError):
                    pass
                new = {'value': v, 'anchor': line_anchor(ROOT, _opt(argv, '--file'), _opt(argv, '--quote') or '')}
        n, probs = correct(ROOT, rest[0], why, date, rest[1] if len(rest) > 1 else None, new)
        print(f'correct {rest[0]}: {n} value(s) corrected', *probs, sep='\n  ')
        return 2 if probs else 0
    args = [a for a in argv if not a.startswith('--')]
    live = '--live' in argv
    cmd = args[0] if args else 'run'
    if cmd == 'check':
        e, w = validate(load_registry(ROOT), ROOT)
        for x in e:
            print('ERROR', x)
        for x in w:
            print('warn ', x)
        print(f'area registry: {len(e)} error(s), {len(w)} warning(s)')
        return 2 if e else 0
    if cmd == 'fix-lines':
        n, probs = fix_lines(ROOT)
        print(f'fix-lines: {n} anchor line(s) set', *probs, sep='\n  ')
        return 0
    if cmd == 'record':
        n, kept = record(ROOT, args[1])
        print(f'record {args[1]}: {n} value(s) added', *kept, sep='\n  ')
        return 0
    if cmd == 'g23':
        ok, det = g23(ROOT)
        print(('PASS' if ok else 'FAIL') + '  G23 ' + det)
        return 0 if ok else 3
    doc, pdoc, errors = evaluate(ROOT, live=live)
    write(ROOT, doc, pdoc)
    s = doc['summary']
    print(f"area_intel: {s['areas']} areas · states {s['states']} · proposals {pdoc['counts']} · refused {s['refused_values']} · "
          f"registry errors {len(errors)} · wrote harness/runtime/area_intel.json, area_proposals.json")
    return 2 if errors else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
