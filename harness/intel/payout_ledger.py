#!/usr/bin/env python3
"""payout_ledger.py — r30 (rft §7 B238; §8 payout plan PO4, PO8, PO10): the daily DERO/day KPI that grades every payout
lever (uptime PO1, ProcessType PO2, orphans PO3, final-phase duty PO5, hashrate PO9) from PAID shares.

Before R30 payouts were read per round from scattered sources. This tool writes one row per window and one per calendar
day into harness/runtime/payout_daily.jsonl (miner_runs.py keeps its per-RUN harness/runtime/payout_ledger.jsonl; this
file is per window/day, so the two never overwrite each other). Sources, all read-only:

  * the miner's own log (bin/dero-miner.launchd.log console form, or bin/dero-miner.log JSON): the 60 s 'REWARD STATS'
    lines carry the RUN's cumulative found_CPU/GPU, paid_CPU/GPU, orphaned_CPU/GPU, unresolved, expected_shares,
    per_miniblock_DERO and the phase-exact expected_DERO_per_day; 'TOTAL hashrate' lines carry H/s (r30: excluding
    stale_sha_skipped when the line has 'H/s_raw', B26). A window's counts are, per run, the newest line at or before
    `until` minus the newest line before `since` (0 when the run started inside the window).
  * derod DERO.GetMiningOutcome (http://127.0.0.1:10102/json_rpc, read-only): its counts are derod-wide since the derod
    start; its 'recent' holds only the last 50 fates, so the WINDOW's derod fates by reason are complete only when the
    oldest 'recent' entry predates `since` (else labelled partial with the instant it covers from).
  * bin/dero-miner.runs.jsonl + bin/dero-miner.run.json (the miner's run ledger, read through miner_runs.parse_ledger):
    the uptime fraction of the window (falls back to the TOTAL lines' 15 s cadence).

Rules (KAT harness/kat/test_payout_ledger_r30.py):
  PL1 DERO/day = PAID shares x per_miniblock_DERO / window days — never from found or expected shares
  PL2 orphan reasons are kept apart (block_race, slots_full, not_included, ...), never one lumped total
  PL3 the wallet / integrator address never appears in any output or record (PO8 is compared in memory: match, mismatch
      or unknown only)
  PL4 --since filters: REWARD STATS lines before `since` are a baseline, not counted; the window's days run from `since`
  PL5 luck = found vs expected_shares graded on the exact (Garwood) 95 % Poisson interval of the found count (miner_runs
      .poisson_ci): LUCKY when expected lies below it, UNLUCKY above it, else WITHIN

  nice -n 15 python3 -I harness/intel/payout_ledger.py [--since '2026-11-08 21:19:22'] [--until ...] [--log PATH]
        [--runs PATH] [--no-rpc] [--json] [--no-write]
  exit 0 a row was made · 2 no REWARD STATS line in the window · 5 derod unreachable (rows still written, derod 'unknown')
"""
import datetime, hashlib, importlib.util, json, re, sys, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent
ROOT = HARNESS.parent
RPC = 'http://127.0.0.1:10102/json_rpc'
OUT = 'harness/runtime/payout_daily.jsonl'
LOGS = ['bin/dero-miner.launchd.log', 'bin/dero-miner.log']
RUNS = ['bin/dero-miner.runs.jsonl', 'bin/dero-miner.run.json']
TOTAL_CADENCE_S = 15.0                    # cmd/dero-miner/miner.go: 'if el := time.Since(last_total_time); el >= 15*time.Second'
RECENT_CAP = 50                           # cmd/derod/rpc/mining_outcome.go: 'len(result.Recent) < 50'
WALLET_RX = re.compile(r'will mine to \\?"([^"\\]+)\\?"')


def _load(name, path):
    spec = importlib.util.spec_from_file_location(f'{name}_for_pl_{id(HERE)}', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


HO = _load('hashobj', HERE / 'hashrate_objective.py')     # the shared miner-log parser (JSON + console forms)
MR = _load('miner_runs', HERE / 'miner_runs.py')          # poisson_ci (Garwood), parse_ledger


def n(v, default=0.0):
    x = HO.num(v)
    return default if x is None else x


# ───────────────────────────── miner-log counts ─────────────────────────────
COUNTS = ('found', 'paid', 'orphaned', 'expected_shares')


def reward_points(recs):
    """[(t, run_index, counts)] of the REWARD STATS lines, the run index advancing at every start-up line. Pure."""
    out, run = [], 0
    for r in recs:
        if r['M'].startswith(HO.START_M):
            run += 1
        elif r['M'] == 'REWARD STATS':
            f = r['f']
            out.append((r['t'], run, {
                'found': n(f.get('found_CPU')) + n(f.get('found_GPU')),
                'paid': n(f.get('paid_CPU')) + n(f.get('paid_GPU')),
                'orphaned': n(f.get('orphaned_CPU')) + n(f.get('orphaned_GPU')),
                'expected_shares': n(f.get('expected_shares')),
                'unresolved': n(f.get('unresolved')),
                'per_mb': HO.num(f.get('per_miniblock_DERO')),
                'exp_day': HO.num(f.get('expected_DERO_per_day'))}))
    return out


def window_counts(points, since, until):
    """the window's miner-side counts: per run, newest point <= until minus newest point < since (0 when the run has no
    point before since). Pure."""
    runs = sorted({r for _, r, _ in points})
    tot = {k: 0.0 for k in COUNTS}
    unresolved, per_mb, exp_day, used = 0.0, None, None, 0
    for run in runs:
        pts = [(t, c) for t, r, c in points if r == run]
        upto = [c for t, c in pts if t <= until]
        if not upto or (pts[0][0] > until):
            continue
        last = upto[-1]
        before = [c for t, c in pts if t < since]
        if before and before[-1] is last:
            continue                                          # the run ended before the window
        base = before[-1] if before else None
        for k in COUNTS:
            tot[k] += last[k] - (base[k] if base else 0.0)
        unresolved = last['unresolved']
        per_mb = last['per_mb'] if last['per_mb'] is not None else per_mb
        exp_day = last['exp_day'] if last['exp_day'] is not None else exp_day
        used += 1
    return tot, unresolved, per_mb, exp_day, used


def uptime(runs_rows, total_rows, since, until):
    """(fraction, source): the run ledger's [start, last] intervals intersected with the window, else the TOTAL lines'
    15 s cadence. Pure."""
    el = max(until - since, 1e-9)
    iv = []
    for r in runs_rows or []:
        try:
            a, b = HO.parse_time(r['start']), HO.parse_time(r['last'])
        except (KeyError, ValueError, TypeError):
            continue
        a, b = max(a, since), min(b, until)
        if b > a:
            iv.append((a, b))
    if iv:
        iv.sort()
        cov, cur = 0.0, None
        for a, b in iv:
            if cur and a <= cur[1]:
                cur = (cur[0], max(cur[1], b))
            else:
                if cur:
                    cov += cur[1] - cur[0]
                cur = (a, b)
        cov += cur[1] - cur[0]
        return round(min(cov / el, 1.0), 4), 'run ledger'
    if total_rows:
        return round(min(len(total_rows) * TOTAL_CADENCE_S / el, 1.0), 4), 'TOTAL lines x 15 s'
    return None, 'none'


# ───────────────────────────── derod side ─────────────────────────────
def derod_window(outcome, since, until):
    """(window fates by reason, scope label, derod-wide counts). Orphan reasons kept apart (PL2). Pure."""
    if not isinstance(outcome, dict):
        return None, 'unknown (derod not read)', None
    wide = {'submitted': outcome.get('submitted'), 'paid': outcome.get('paid'),
            'orphaned': dict(outcome.get('orphaned') or {}), 'pending': outcome.get('pending'),
            'scope': 'derod-wide since its start'}
    rec = outcome.get('recent') or []
    w = {'submitted': 0, 'paid': 0, 'orphaned': {}, 'pending': 0}
    oldest = None
    for f in rec:
        t = f.get('submitted_unix_ms')
        t = t / 1000.0 if t else f.get('submitted_unix')
        if t is None:
            continue
        oldest = t if oldest is None else min(oldest, t)
        if t < since or t > until:
            continue
        w['submitted'] += 1
        fate = f.get('fate')
        if fate == 'paid':
            w['paid'] += 1
        elif fate == 'orphaned':
            reason = f.get('reason') or 'unknown'
            w['orphaned'][reason] = w['orphaned'].get(reason, 0) + 1
        else:
            w['pending'] += 1
    if oldest is not None and (oldest < since or len(rec) < RECENT_CAP):
        scope = 'window complete (derod recent covers since)'
    else:
        scope = (f'partial: derod recent (last {RECENT_CAP}) covers only from '
                 f'{HO.iso(oldest) if oldest else "nothing"}')
    return w, scope, wide


def h8(s):
    return hashlib.sha256(str(s).encode()).hexdigest()[:16] if s else None


def integrator_check(miner_addr, integrator_addr):
    """PO8: 'match' | 'mismatch' | 'unknown (...)' — compared by hash, the strings never leave this function (PL3)"""
    if not miner_addr:
        return 'unknown (no "will mine to" line in the miner log)'
    if not integrator_addr:
        return 'unknown (no block built by this node in derod recent)'
    return 'match' if h8(miner_addr) == h8(integrator_addr) else 'mismatch'


def wallet_of(text):
    m = None
    for m in WALLET_RX.finditer(text):
        pass
    return m.group(1) if m else None


def integrator_of(outcome, header_of):
    """the integrator of the newest block this node built from our final miniblock (block header miners[-1])"""
    for f in (outcome or {}).get('recent') or []:
        if f.get('final') and f.get('built') and f.get('fate') == 'paid':
            try:
                h = header_of(f['built'])
            except Exception:                                  # noqa: BLE001 — unknown, not a crash
                h = None
            m = (h or {}).get('miners') or []
            if m:
                return m[-1]
    return None


def rpc_call(url, method, params=None, timeout=10):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, **({'params': params} if params else {})}).encode()
    req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.loads(r.read())
    if 'error' in d:
        raise RuntimeError(str(d['error'])[:200])
    return d.get('result')


# ───────────────────────────── grading ─────────────────────────────
def luck_grade(found, expected):
    """PL5: (grade, (lo, hi)) from the Garwood 95 % interval of the found count. Pure."""
    k = int(round(found))
    lo, hi = MR.poisson_ci(k)
    if expected is None or expected <= 0:
        return 'pending (no expectation)', (lo, hi)
    if expected < lo:
        return 'LUCKY', (lo, hi)
    if expected > hi:
        return 'UNLUCKY', (lo, hi)
    return 'WITHIN', (lo, hi)


def make_row(kind, recs, since, until, outcome=None, runs_rows=None, integrator='unknown (not read)'):
    """one ledger row (no address in it). Pure."""
    pts = reward_points(recs)
    tot, unresolved, per_mb, exp_day, used = window_counts(pts, since, until)
    if not used:
        return None
    rows = HO.total_rows(recs, since, until)
    days = (until - since) / 86400.0
    paid_dero = tot['paid'] * per_mb if per_mb is not None else None
    per_day = paid_dero / days if paid_dero is not None and days > 0 else None
    # r30 merge fix: the expectation is the WINDOW's phase-exact expected shares priced like the paid ones, per day. The
    # miner's REWARD STATS expected_DERO_per_day is an instantaneous figure at the current D (34-78 over the first 2 h
    # of the launchd run), so using its last value made measured/expected disagree with the luck grade (0.73 while LUCKY).
    exp_win = (tot['expected_shares'] * per_mb / days) if per_mb is not None and days > 0 and tot['expected_shares'] else None
    w, scope, wide = derod_window(outcome, since, until)
    grade, ci = luck_grade(tot['found'], tot['expected_shares'])
    up, up_src = uptime(runs_rows, rows, since, until)
    return {
        'kind': kind, 'since': HO.iso(since), 'until': HO.iso(until), 'hours': round(days * 24, 3),
        'complete_day': kind == 'day' and days >= 0.999,
        'uptime_frac': up, 'uptime_source': up_src,
        'miner': {'found': int(tot['found']), 'paid': int(tot['paid']), 'orphaned': int(tot['orphaned']),
                  'unresolved_now': int(unresolved), 'expected_shares': round(tot['expected_shares'], 2), 'runs': used},
        'derod_window': w, 'derod_window_scope': scope, 'derod_wide': wide,
        'per_miniblock_DERO': per_mb,
        'paid_DERO': round(paid_dero, 5) if paid_dero is not None else None,
        'DERO_per_day': round(per_day, 3) if per_day is not None else None,
        'expected_DERO_per_day': round(exp_win, 3) if exp_win is not None else None,
        'expected_basis': "window expected_shares x per_miniblock_DERO / days (phase-exact, the miner's expected_shares)",
        'miner_expected_DERO_per_day_last': exp_day,
        'measured_over_expected': round(per_day / exp_win, 3) if per_day is not None and exp_win else None,
        'hs_mean': round(HO.mean([r['hs'] for r in rows])) if rows else None,
        'hs_excludes_stale_sha': (all(r['excl_stale'] for r in rows) if rows else None),
        'luck': {'grade': grade, 'found': int(tot['found']), 'expected': round(tot['expected_shares'], 2),
                 'garwood95': list(ci)},
        'integrator_check': integrator,
        'kpi': 'DERO/day from paid shares only (PL1); fees excluded (lower bound)'}


def day_windows(since, until):
    """[(start, end)] calendar-day slices (local time) of [since, until]. Pure."""
    out, a = [], since
    while a < until:
        d = datetime.datetime.fromtimestamp(a).astimezone()
        nxt = (d.replace(hour=0, minute=0, second=0, microsecond=0) + datetime.timedelta(days=1)).timestamp()
        b = min(nxt, until)
        out.append((a, b))
        a = b
    return out


def merge(path, rows):
    """keep one row per (kind, since); a row is replaced only by one covering at least as long (never a worse one)"""
    p = Path(path)
    old = []
    if p.exists():
        for l in p.read_text().splitlines():
            try:
                old.append(json.loads(l))
            except ValueError:
                pass
    keyed = {(r.get('kind'), r.get('since')): r for r in old}
    for r in rows:
        k = (r['kind'], r['since'])
        if k not in keyed or (r.get('hours') or 0) >= (keyed[k].get('hours') or 0):
            keyed[k] = r
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(''.join(json.dumps(v, sort_keys=True) + '\n' for v in sorted(keyed.values(), key=lambda x: (x['since'], x['kind']))))
    return len(keyed)


def text_report(rows):
    L = []
    for r in rows:
        m, lk = r['miner'], r['luck']
        L.append(f"[{r['kind']}] {r['since']} .. {r['until']} ({r['hours']} h){' complete day' if r['complete_day'] else ''}")
        L.append(f"  uptime {r['uptime_frac']} ({r['uptime_source']}) · H/s mean {r['hs_mean']}"
                 f" ({'excl.' if r['hs_excludes_stale_sha'] else 'incl.'} stale_sha_skipped)")
        L.append(f"  miner: found {m['found']} paid {m['paid']} orphaned {m['orphaned']} unresolved now {m['unresolved_now']}"
                 f" expected {m['expected_shares']} (runs {m['runs']})")
        L.append(f"  derod window ({r['derod_window_scope']}): {r['derod_window']}")
        L.append(f"  derod-wide: {r['derod_wide']}")
        L.append(f"  KPI paid DERO {r['paid_DERO']} -> {r['DERO_per_day']} DERO/day vs expected {r['expected_DERO_per_day']}"
                 f" (measured/expected {r['measured_over_expected']}) at {r['per_miniblock_DERO']} DERO/miniblock")
        L.append(f"  luck {lk['grade']}: found {lk['found']} vs expected {lk['expected']} (Garwood 95 % {lk['garwood95']})")
        L.append(f"  integrator == miner wallet (PO8): {r['integrator_check']}")
    return '\n'.join(L)


def main(argv):
    import argparse
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    ap = argparse.ArgumentParser()
    ap.add_argument('--since')
    ap.add_argument('--until')
    ap.add_argument('--log')
    ap.add_argument('--runs', nargs='*')
    ap.add_argument('--rpc', default=RPC)
    ap.add_argument('--no-rpc', action='store_true')
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--no-write', action='store_true')
    ap.add_argument('--out', default=str(ROOT / OUT))
    a = ap.parse_args(argv)
    log = Path(a.log) if a.log else next((ROOT / l for l in LOGS if (ROOT / l).exists()), ROOT / LOGS[0])
    text = log.read_text(errors='replace') if log.exists() else ''
    since = HO.parse_time(a.since)
    recs = HO.read_records(text, datetime.datetime.fromtimestamp(since).year if since else None)
    if since is None:
        since = HO.default_since(recs)
    until = HO.parse_time(a.until) or (recs[-1]['t'] if recs else None)
    if since is None or until is None or until <= since:
        print('payout_ledger: no window (no log lines or until <= since)')
        return 2
    runs_rows = []
    for rp in (a.runs if a.runs is not None else [str(log.parent / Path(x).name) for x in RUNS]):
        try:
            runs_rows += MR.parse_ledger(Path(rp).read_text())[0]
        except OSError:
            pass
    outcome, rc, integ = None, 0, 'unknown (--no-rpc)'
    if not a.no_rpc:
        try:
            outcome = rpc_call(a.rpc, 'DERO.GetMiningOutcome')
            iaddr = integrator_of(outcome, lambda h: (rpc_call(a.rpc, 'DERO.GetBlockHeaderByHash', {'hash': h}) or {}).get('block_header'))
            integ = integrator_check(wallet_of(text), iaddr)
            iaddr = None
        except Exception as e:                                 # noqa: BLE001 — derod down: counts unknown, rows still made
            outcome, rc, integ = None, 5, f'unknown (derod: {type(e).__name__})'
    rows = []
    r = make_row('window', recs, since, until, outcome, runs_rows, integ)
    if r is None:
        print('payout_ledger: no REWARD STATS line in the window')
        return 2
    rows.append(r)
    for a0, b0 in day_windows(since, until):
        d = make_row('day', recs, a0, b0, outcome, runs_rows, integ)
        if d:
            rows.append(d)
    print(json.dumps(rows, indent=1) if a.json else text_report(rows))
    if not a.no_write:
        merge(a.out, rows)
    return rc


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
