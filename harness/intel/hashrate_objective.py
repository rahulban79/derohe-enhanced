#!/usr/bin/env python3
"""hashrate_objective.py — r30 (rft §7 B235, §2.21; gate G34): progress to the user's R30 objective (> 150 kH/s) from
MEASURED LIVE windows only, and the ceiling model of rft §8 "R30 miner lever census" computed from records.

The user (2026-11-08, rft §2.21): "round 30 objective needs to be massive improvement in mining hash i.e to achieve above
150KHs". Nothing in the harness reported progress to it. This tool does, under three rules:

  HO1  a live window is the miner's own 15 s 'TOTAL hashrate' lines (bin/dero-miner.log JSON, or the launchd console log
       bin/dero-miner.launchd.log) inside [since, until], or an r*_live_window_*.txt record that carries a measured
       'H/s mean' line. A bench record (harness/runtime/r30_ceiling_*.json, kind 'bench'), an ESTIMATE or a proxy is
       NEVER a live window: it is refused as one (it may feed the ceiling, below).
  HO2  progress = live mean / 150,000, always printed with its window anchor (file, first and last line instants, n).
  HO3  ceiling = min(S, G / (1 - own)) (rft §8 ceiling model), every input from a record, no literal:
         own  = 1 - staged / TOTAL over the same window (the 'GPU split' line's staged_H/s vs the TOTAL lines),
         G    = d_gpu / t_busy: t_busy from gpu_busy_us_per_hash, d_gpu from the gpu_max cap of the split line (a
                quiet bench record, side 'gpu', replaces it with its measured G_staged_hs),
         S    = a quiet bench record, side 'cpu' (S_hs), else the restated live law (B27): S = r_P x P + r_E x E cores
                at the duty cap, fitted by live_law() from the TOTAL lines' p_cores / e_cores (r30 miner); with neither,
                S is 'pending (no record)' and the ceiling is pending — never a typed number.
  B236 schema: a bench record must say quiet: true AND carry its contention reading (contention.py census); otherwise
       it is refused as a ceiling input too.

  G34 (run_gates): INFO while the measured live mean is below 150,000 (also when no window exists); PASS only when a
  measured live window mean exceeds 150,000; never PASS on a bench, an ESTIMATE or a proxy. INFO is not a failure.
  r30 verifier fixes:
  HO7  minimum window: PASS needs n >= 240 TOTAL lines AND a duration (first..last line) >= 3,600 s; a shorter window
       is INFO 'window too short' whatever its mean (a single 151k line never PASSes).
  HO8  a --bench run is never a live window: a bench marker (the miner's '--bench runs at full speed' start-up line, the
       bench table header, the split-bench banner) inside the window refuses it. The launchd console log is the only
       log read while it exists: bin/dero-miner.log is never a fallback for it (pick_log).
  HO9  g34_verdict refuses any dict flagged estimate or proxy (truthy key), whatever its kind / measured fields.
  HO10 the effective window is recorded: since/until (iso and epoch) are the first and last TOTAL lines used, and the
       GPU split lines (own, G) are read over that same window, so a re-run with the printed since/until reproduces it.
  HO11 (r30 B252, a window that spans a pause / a miner restart) the window is CLASSIFIED, never silently merged: TOTAL
       lines more than GAP_S apart split it into segments, each gap recorded (from, to, seconds); 'continuity' is
       CONTINUOUS (the detached miner kept logging through a session pause: one window) or SEGMENTED; 'covered_s' is the
       sum of the segment durations, and HO7's ">= 3,600 s" counts covered_s, never the span across a gap.

  nice -n 15 python3 -I harness/intel/hashrate_objective.py [--log PATH] [--since '2026-11-08 21:19:22'] [--until ...]
        [--json] [--write]      # --write: harness/runtime/r30_hashrate_objective_<ts>.json + .txt
  exit 0 a reading was made (any progress) · 2 no live window in the input · 6 a malformed bench record was refused
  r30 B263: a quiet-window record under STEADY foreign load (quiet false, bound 'lower', a contention census; quiet_window
  B256 / rft §0.12 D-15) is not malformed: it is listed in benches_lower_bound, never used as a ceiling input, never
  exit 6
"""
import datetime, glob, json, math, re, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent
ROOT = HARNESS.parent
OBJECTIVE_HS = 150_000            # the user's number, rft §2.21 ("above 150KHs"); the objective, not a model input
LOGS = ['bin/dero-miner.launchd.log', 'bin/dero-miner.log']
BENCH_GLOB = 'harness/runtime/r30_ceiling_*.json'
LIVE_WINDOW_GLOB = 'harness/runtime/r*_live_window_*.txt'
START_M = 'DERO Stargate HE AstroBWT miner'   # cmd/dero-miner/miner.go start-up line (miner_intel.START_M)
CONSOLE_RX = re.compile(r'^(\d\d)/(\d\d) (\d\d):(\d\d):(\d\d)\t(?:\x1b\[[0-9;]*m)?(\w+)(?:\x1b\[[0-9;]*m)?\t(\w+)\t([^\t{]*?)\s*(\{.*\})?\s*$')
CAP_RX = re.compile(r'CPU duty cycle capped at (\d+)%')   # cmd/dero-miner start-up line
MIN_WINDOW_N = 240                # HO7: TOTAL lines (one per 15 s: an hour of lines)
MIN_WINDOW_S = 3600               # HO7: first..last TOTAL line, seconds
BENCH_RX = re.compile(r'--bench runs at full speed|benchmark mode|Hash Rate/Sec|split: CPU side only')
BENCH_MARK = '(bench marker)'
GAP_S = 120                       # HO11: TOTAL lines are 15 s apart; a larger hole than 8 lines is a gap
LW_RX = re.compile(r'^H/s mean (\d+) median (\d+) min (\d+) max (\d+) \| cores ([\d.]+) \| H/cpu-s (\d+) \| staged (\d+) gpu_busy ([\d.]+)')


# ───────────────────────────── log parsing (shared with payout_ledger.py) ─────────────────────────────
def parse_time(s, tz=None):
    """'2026-11-08 21:19:22' (local), '2026-11-08T21:19:22-08:00' or epoch -> epoch seconds. Pure but for the local tz."""
    if s is None or s == '':
        return None
    if isinstance(s, (int, float)):
        return float(s)
    s = str(s).strip()
    try:
        return float(s)
    except ValueError:
        pass
    for fmt in ('%Y-%m-%dT%H:%M:%S.%f%z', '%Y-%m-%dT%H:%M:%S%z'):
        try:
            return datetime.datetime.strptime(s, fmt).timestamp()
        except ValueError:
            pass
    d = datetime.datetime.fromisoformat(s.replace(' ', 'T'))
    if d.tzinfo is None:
        d = d.replace(tzinfo=tz) if tz else d.astimezone()
    return d.timestamp()


def parse_line(line, year):
    """one miner log line -> {'t', 'M', 'f': fields} or None. JSON lines (bin/dero-miner.log: 'T','M') and the console
    form 'DD/MM HH:MM:SS<TAB>LEVEL<TAB>miner<TAB>MSG<TAB>{json}' (launchd log; no year: `year` supplies it, local tz)."""
    line = line.rstrip('\n')
    if line.startswith('{'):
        try:
            d = json.loads(line)
        except ValueError:
            return None
        try:
            t = datetime.datetime.strptime(d['T'], '%Y-%m-%dT%H:%M:%S.%f%z').timestamp()
        except (KeyError, ValueError, TypeError):
            return None
        return {'t': t, 'M': str(d.get('M', '')), 'f': d}
    m = CONSOLE_RX.match(line)
    if not m:
        return None
    dd, mo, hh, mi, ss = (int(x) for x in m.group(1, 2, 3, 4, 5))
    try:
        t = datetime.datetime(year, mo, dd, hh, mi, ss).astimezone().timestamp()
    except ValueError:
        return None
    f = {}
    if m.group(9):
        try:
            f = json.loads(m.group(9))
        except ValueError:
            f = {}
    return {'t': t, 'M': m.group(8).strip(), 'f': f}


def read_records(text, year=None):
    """the log's records in order. HO8: an untimed line that is a --bench marker (the bench table header printed to
    stdout, the split-bench banner) becomes a BENCH_MARK record at the previous record's instant."""
    year = year or datetime.datetime.now().year
    out = []
    last_t = None
    for l in text.splitlines():
        r = parse_line(l, year)
        if r:
            out.append(r)
            last_t = r['t']
        elif BENCH_RX.search(l):
            out.append({'t': last_t if last_t is not None else 0.0, 'M': BENCH_MARK, 'f': {}})
    return out


def bench_markers(recs, since=None, until=None):
    """HO8: the --bench markers of the run [since - 60 s, until] (the start-up line precedes the first TOTAL line). Pure."""
    lo = (since - 60) if since is not None else None
    return [r for r in recs if (r['M'] == BENCH_MARK or BENCH_RX.search(r['M']))
            and (lo is None or r['t'] >= lo) and (until is None or r['t'] <= until)]


def pick_log(root):
    """HO8: the launchd console log while it exists, else bin/dero-miner.log, else None. Never a fallback from the
    former to the latter (a window missing from the launchd log is missing, not read from the JSON log)."""
    for l in LOGS:
        if (Path(root) / l).exists():
            return Path(root) / l
    return None


def num(v):
    try:
        x = float(str(v).replace(',', '').rstrip('%'))
        return x if math.isfinite(x) else None
    except (TypeError, ValueError):
        return None


def run_starts(recs):
    return [r['t'] for r in recs if r['M'].startswith(START_M)]


def default_since(recs):
    """the newest run's start (the last start-up line), or None"""
    s = run_starts(recs)
    return s[-1] if s else None


def total_rows(recs, since=None, until=None):
    """the TOTAL hashrate lines of the window as rows {t, hs, hs_raw, stale, cores, hcpu, p_cores, e_cores}. r30: the
    miner's H/s excludes stale_sha_skipped (B26) when the line carries 'H/s_raw'; older lines are H/s as printed."""
    out = []
    for r in recs:
        if r['M'] != 'TOTAL hashrate':
            continue
        if since is not None and r['t'] < since or until is not None and r['t'] > until:
            continue
        f = r['f']
        hs = num(f.get('H/s'))
        if hs is None:
            continue
        out.append({'t': r['t'], 'hs': hs, 'hs_raw': num(f.get('H/s_raw')), 'stale': num(f.get('stale_sha_skipped')),
                    'excl_stale': 'H/s_raw' in f, 'cores': num(f.get('cpu_cores')), 'hcpu': num(f.get('H/cpu-s')),
                    'p_cores': num(f.get('p_cores')), 'e_cores': num(f.get('e_cores'))})
    return out


def split_rows(recs, since=None, until=None):
    out = []
    for r in recs:
        if r['M'] != 'GPU split':
            continue
        if since is not None and r['t'] < since or until is not None and r['t'] > until:
            continue
        f = r['f']
        out.append({'t': r['t'], 'staged': num(f.get('staged_H/s')), 't_busy_us': num(f.get('gpu_busy_us_per_hash')),
                    'busy_pct': num(f.get('gpu_busy_pct')), 'gpu_max': num(f.get('gpu_max'))})
    return out


def mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


# ───────────────────────────── B27: the restated live law ─────────────────────────────
def live_law(rows):
    """least-squares fit H/s = r_P * p_cores + r_E * e_cores (no intercept) over the window's TOTAL rows: the B27 live
    law restated from the P/E split. {'status': 'PENDING', why} when the rows carry no P/E fields (the r29 binary) or
    the system is degenerate; else {'status': 'FIT', r_P, r_E, n, residual_pct: [min, max]}. Pure."""
    pts = [(r['p_cores'], r['e_cores'], r['hs']) for r in rows
           if r.get('p_cores') is not None and r.get('e_cores') is not None and r.get('hs') is not None]
    if len(pts) < 3:
        return {'status': 'PENDING', 'why': f'{len(pts)} TOTAL line(s) carry p_cores/e_cores (r30 miner, B27); need >= 3'}
    spp = sum(p * p for p, e, h in pts)
    see = sum(e * e for p, e, h in pts)
    spe = sum(p * e for p, e, h in pts)
    sph = sum(p * h for p, e, h in pts)
    seh = sum(e * h for p, e, h in pts)
    det = spp * see - spe * spe
    if abs(det) < 1e-9 * max(1.0, spp * see):
        return {'status': 'PENDING', 'why': 'P and E core time are collinear in the window: the law cannot be separated'}
    r_p = (sph * see - seh * spe) / det
    r_e = (seh * spp - sph * spe) / det
    res = [100.0 * (h - (r_p * p + r_e * e)) / h for p, e, h in pts if h]
    return {'status': 'FIT', 'r_P': round(r_p, 1), 'r_E': round(r_e, 1), 'n': len(pts),
            'residual_pct': [round(min(res), 2), round(max(res), 2)] if res else None}


# ───────────────────────────── bench records (B236) ─────────────────────────────
def bench_ok(rec):
    """(ok, why) — a ceiling input needs kind 'bench', quiet: true and a contention reading (B236 schema). Pure."""
    if not isinstance(rec, dict):
        return False, 'not an object'
    if rec.get('kind') != 'bench':
        return False, f"kind {rec.get('kind')!r} is not 'bench'"
    if rec.get('quiet') is not True:
        return False, 'not marked quiet: true (a contended bench is not a ceiling)'
    if not isinstance(rec.get('contention'), dict) or not rec['contention']:
        return False, 'no contention reading (contention.py census) with the record'
    if rec.get('side') not in ('cpu', 'gpu'):
        return False, f"side {rec.get('side')!r} is not cpu|gpu"
    key = 'S_hs' if rec['side'] == 'cpu' else 'G_staged_hs'
    if num(rec.get(key)) is None:
        return False, f'no {key}'
    return True, 'ok'


def lower_bound_ok(rec):
    """r30 B263: a well-formed LOWER-BOUND bench record (quiet_window steady-foreign, D-15): kind bench, quiet false,
    bound 'lower', a contention census, a known side and its value. Never a ceiling input. Pure."""
    return (isinstance(rec, dict) and rec.get('kind') == 'bench' and rec.get('quiet') is False and rec.get('bound') == 'lower'
            and isinstance(rec.get('contention'), dict) and bool(rec['contention']) and rec.get('side') in ('cpu', 'gpu')
            and num(rec.get('S_hs' if rec.get('side') == 'cpu' else 'G_staged_hs')) is not None)


def load_benches(paths, lower=None):
    good, refused = [], []
    for p in paths:
        try:
            rec = json.loads(Path(p).read_text())
        except (OSError, ValueError) as e:
            refused.append((rel(p), f'unreadable: {type(e).__name__}'))
            continue
        ok, why = bench_ok(rec)
        if not ok and lower is not None and lower_bound_ok(rec):          # r30 B263
            lower.append(rel(p))
            continue
        (good if ok else refused).append((rel(p), rec) if ok else (rel(p), why))
    return good, refused


def live_window_of(source, rec):
    """HO1: a live window from a record, or None. Only the miner's TOTAL lines or a live_window text record's measured
    'H/s mean' line qualify; a bench / ESTIMATE / proxy record is refused. Pure."""
    if isinstance(rec, dict):
        if rec.get('kind') in ('bench', 'estimate', 'proxy') or rec.get('estimate') or rec.get('proxy'):
            return None
        if rec.get('kind') == 'live' and rec.get('measured') is True and num(rec.get('mean_hs')) is not None:
            return {'source': source, 'mean_hs': num(rec['mean_hs']), 'n': rec.get('n'), 'first': rec.get('first'),
                    'last': rec.get('last'), 'kind': 'live'}
        return None
    return None


def segments(ts, gap_s=GAP_S):
    """HO11: (segments, gaps) of sorted instants: a hole > gap_s ends a segment. segments = [(i0, i1)] index ranges
    (inclusive), gaps = [(t_from, t_to)]. Pure."""
    if not ts:
        return [], []
    segs, gaps, start = [], [], 0
    for i in range(1, len(ts)):
        if ts[i] - ts[i - 1] > gap_s:
            segs.append((start, i - 1))
            gaps.append((ts[i - 1], ts[i]))
            start = i
    segs.append((start, len(ts) - 1))
    return segs, gaps


def window_from_rows(rows, source):
    if not rows:
        return None
    segs, gaps = segments([r['t'] for r in rows])
    seg_rows = [{'first': iso(rows[a]['t']), 'last': iso(rows[b]['t']), 'n': b - a + 1,
                 'duration_s': round(rows[b]['t'] - rows[a]['t'], 3),
                 'mean_hs': round(mean([r['hs'] for r in rows[a:b + 1]]), 1)} for a, b in segs]
    return {'continuity': 'CONTINUOUS' if not gaps else 'SEGMENTED',
            'covered_s': round(sum(x['duration_s'] for x in seg_rows), 3), 'segments': seg_rows,
            'gaps': [{'from': iso(a), 'to': iso(b), 's': round(b - a, 3)} for a, b in gaps], 'source': source, 'kind': 'live', 'measured': True, 'mean_hs': round(mean([r['hs'] for r in rows]), 1),
            'n': len(rows), 'first': iso(rows[0]['t']), 'last': iso(rows[-1]['t']),
            'first_epoch': rows[0]['t'], 'last_epoch': rows[-1]['t'],
            'duration_s': round(rows[-1]['t'] - rows[0]['t'], 3),
            'excludes_stale_sha': all(r['excl_stale'] for r in rows),
            'cores': round(mean([r['cores'] for r in rows]) or 0, 2) or None,
            'h_cpu_s': round(mean([r['hcpu'] for r in rows]) or 0, 0) or None}


def live_window_texts(paths):
    out = []
    for p in paths:
        try:
            for i, l in enumerate(Path(p).read_text(errors='replace').splitlines(), 1):
                m = LW_RX.match(l)
                if m:
                    out.append({'source': f'{rel(p)}:{i}', 'kind': 'live', 'measured': True, 'mean_hs': float(m.group(1)),
                                'cores': float(m.group(5)), 'h_cpu_s': float(m.group(6)), 'staged': float(m.group(7)),
                                'gpu_busy_pct': float(m.group(8))})
        except OSError:
            continue
    return out


def rel(p):
    """a source path as the records print it: repo-relative, else bin/<name> or the bare name (never a home path)"""
    p = Path(p)
    try:
        return str(p.resolve().relative_to(ROOT))
    except ValueError:
        return f'bin/{p.name}' if p.parent.name == 'bin' else p.name


def iso(t):
    return datetime.datetime.fromtimestamp(t).astimezone().isoformat(timespec='seconds')


# ───────────────────────────── the ceiling model (HO3) ─────────────────────────────
def ceiling(win, splits, law, benches, cpu_max=None):
    """rft §8: H = min(S, G / (1 - own)) from records. Returns a dict with every input and its source. Pure."""
    out = {'model': 'min(S, G/(1-own)) (rft §8 R30 ceiling model)'}
    staged = mean([s['staged'] for s in splits])
    t_busy = mean([s['t_busy_us'] for s in splits])
    gmax = [s['gpu_max'] for s in splits if s.get('gpu_max') is not None]
    total = win['mean_hs'] if win else None
    own = (1 - staged / total) if staged and total else None
    out['own'] = round(own, 4) if own is not None else 'pending (no split line in the window)'
    gb = [r for p, r in benches if r['side'] == 'gpu']
    cb = [r for p, r in benches if r['side'] == 'cpu']
    if gb:
        G = max(num(r['G_staged_hs']) for r in gb)
        out['G'] = {'value': round(G), 'source': 'bench (quiet)', 'n': len(gb)}
    elif t_busy and gmax:
        G = (gmax[-1] / 100.0) / (t_busy * 1e-6)
        out['G'] = {'value': round(G), 'source': f'live: d_gpu {gmax[-1]:.0f}% / t_busy {t_busy:.2f} us'}
    else:
        G = None
        out['G'] = 'pending (no record)'
    if cb:
        S = max(num(r['S_hs']) for r in cb)
        out['S'] = {'value': round(S), 'source': 'bench (quiet)', 'n': len(cb)}
    elif law.get('status') == 'FIT' and cpu_max:
        d = cpu_max / 100.0
        P, E = law.get('P_cores_hw'), law.get('E_cores_hw')
        if P and E:
            S = d * (P * law['r_P'] + E * law['r_E'])
            out['S'] = {'value': round(S), 'source': f"live law r_P {law['r_P']} r_E {law['r_E']} x {P} P + {E} E at d {d}"}
        else:
            S, out['S'] = None, 'pending (core counts unknown)'
    else:
        S = None
        out['S'] = 'pending (no record)'
    if S is not None and G is not None and isinstance(own, float) and own < 1:
        out['ceiling_hs'] = round(min(S, G / (1 - own)))
        out['binding'] = 'cpu' if S <= G / (1 - own) else 'gpu'
    else:
        out['ceiling_hs'] = 'pending'
    return out


def hw_cores():
    """(P, E) logical CPUs from sysctl hw.perflevel0/1 (read-only); (None, None) off macOS"""
    import subprocess
    try:
        o = subprocess.run(['sysctl', '-n', 'hw.perflevel0.logicalcpu', 'hw.perflevel1.logicalcpu'],
                           capture_output=True, text=True, timeout=5).stdout.split()
        return int(o[0]), int(o[1])
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        return None, None


# ───────────────────────────── G34 ─────────────────────────────
def g34_verdict(win):
    """(ok, word, detail): PASS only for a measured live window above the objective; INFO otherwise. Pure."""
    if not win or win.get('kind') != 'live' or win.get('measured') is not True:
        return True, 'INFO', 'no measured live window: progress pending (never PASS on a bench, ESTIMATE or proxy)'
    if win.get('estimate') or win.get('proxy'):                                   # HO9
        return True, 'INFO', 'window flagged estimate/proxy: refused (G34 never PASSes on an ESTIMATE or proxy)'
    prog = win['mean_hs'] / OBJECTIVE_HS
    det = (f"live mean {win['mean_hs']:,.0f} H/s = {100 * prog:.1f} % of {OBJECTIVE_HS:,} "
           f"({win['source']} {win.get('first')}..{win.get('last')}, n {win.get('n')}, {win.get('duration_s')} s)")
    n, dur = num(win.get('n')), num(win.get('covered_s', win.get('duration_s')))      # HO11: covered, not the span
    if win.get('continuity') == 'SEGMENTED':
        det += f" · SEGMENTED: {len(win.get('gaps') or [])} gap(s), covered {win.get('covered_s')} s"
    if n is None or dur is None or n < MIN_WINDOW_N or dur < MIN_WINDOW_S:        # HO7
        return True, 'INFO', det + f' · window too short (need n >= {MIN_WINDOW_N} and >= {MIN_WINDOW_S} s covered)'
    if win['mean_hs'] > OBJECTIVE_HS:
        return True, 'PASS', det
    return True, 'INFO', det + ' · below the objective'


def analyse(log_path, since=None, until=None, bench_paths=None, lw_paths=None, cpu_max=None, cores=None):
    p = Path(log_path)
    text = p.read_text(errors='replace') if p.exists() else ''
    year = datetime.datetime.fromtimestamp(since).year if since else None
    recs = read_records(text, year)
    if since is None:
        since = default_since(recs)
    rows = total_rows(recs, since, until)
    marks = bench_markers(recs, since, until)
    refused_bench = None
    if marks:                                                                      # HO8: a --bench run is no window
        refused_bench = f'{len(marks)} --bench marker(s) in the window: a bench run is never a live window'
        rows = []
    eff_since = rows[0]['t'] if rows else since                                    # HO10: the window actually used
    eff_until = rows[-1]['t'] if rows else until
    splits = split_rows(recs, eff_since, eff_until)
    win = window_from_rows(rows, rel(log_path))
    law = live_law(rows)
    if law.get('status') == 'FIT':
        law['P_cores_hw'], law['E_cores_hw'] = cores or (None, None)
    lower = []
    good, refused = load_benches(bench_paths or [], lower)
    if cpu_max is None:
        cm = [int(m.group(1)) for r in recs if r['t'] <= (until or 1e18) and (since is None or r['t'] >= since - 60)
              for m in [CAP_RX.search(r['M'])] if m]
        cpu_max = cm[-1] if cm else (100 if rows else None)   # no cap line = the miner printed none: --cpu-max 100
    ok, word, det = g34_verdict(win)
    if refused_bench:
        word, det = 'INFO', refused_bench
    return {'objective_hs': OBJECTIVE_HS, 'window': win, 'progress': round(win['mean_hs'] / OBJECTIVE_HS, 4) if win else None,
            'since': iso(eff_since) if eff_since else None, 'until': iso(eff_until) if eff_until else None,
            'since_epoch': eff_since, 'until_epoch': eff_until, 'refused_bench': refused_bench,
            'ceiling': ceiling(win, splits, law, good, cpu_max), 'live_law': law,
            'benches_used': [p for p, _ in good], 'benches_refused': refused, 'benches_lower_bound': lower,
            'other_live_windows': live_window_texts(lw_paths or []), 'g34': {'word': word, 'detail': det}}


def g34(root=ROOT):
    """run_gates G34: (ok, detail). Read-only and fast: the newest launchd/console run of the miner log."""
    log = pick_log(root)
    if log is None:
        return True, 'INFO no miner log: progress pending (rft §2.21 objective 150,000 H/s)'
    rep = analyse(log, bench_paths=sorted(glob.glob(str(root / BENCH_GLOB))))
    c = rep['ceiling']
    return True, (f"{rep['g34']['word']} {rep['g34']['detail']} · ceiling {c.get('ceiling_hs')} "
                  f"(S {c['S']['value'] if isinstance(c.get('S'), dict) else c.get('S')}, "
                  f"G {c['G']['value'] if isinstance(c.get('G'), dict) else c.get('G')}, own {c.get('own')}) · "
                  f"law {rep['live_law'].get('status')} · benches {len(rep['benches_used'])} used, {len(rep['benches_refused'])} refused")


def text_report(rep):
    w = rep['window']
    L = [f"hashrate objective (rft §2.21): > {OBJECTIVE_HS:,} H/s"]
    if w:
        L.append(f"live window {w['source']} {w['first']} .. {w['last']} n {w['n']} ({w['duration_s']} s; "
                 f"--since {rep['since_epoch']} --until {rep['until_epoch']}): mean {w['mean_hs']:,.0f} H/s "
                 f"({'excludes' if w['excludes_stale_sha'] else 'includes'} stale_sha_skipped), cores {w['cores']}, "
                 f"H/cpu-s {w['h_cpu_s']} -> progress {100 * rep['progress']:.1f} %")
        L.append(f"continuity (HO11): {w['continuity']}, covered {w['covered_s']} s in {len(w['segments'])} segment(s)"
                 + ''.join(f"; gap {g['from']} .. {g['to']} ({g['s']} s)" for g in w['gaps']))
    else:
        L.append('no live window in the input' + (f" ({rep['refused_bench']})" if rep.get('refused_bench') else ''))
    c = rep['ceiling']
    L.append(f"ceiling {c['model']}: {c.get('ceiling_hs')} (binding {c.get('binding', '-')}); S {c['S']}; G {c['G']}; own {c['own']}")
    L.append(f"live law (B27): {rep['live_law']}")
    L.append(f"benches used {rep['benches_used']} refused {rep['benches_refused']}"
             + (f" lower-bound (steady foreign load, not a ceiling) {rep['benches_lower_bound']}" if rep.get('benches_lower_bound') else ''))
    for o in rep['other_live_windows']:
        L.append(f"earlier live window {o['source']}: mean {o['mean_hs']:,.0f} H/s = {100 * o['mean_hs'] / OBJECTIVE_HS:.1f} %")
    L.append(f"G34 {rep['g34']['word']}: {rep['g34']['detail']}")
    return '\n'.join(L)


def main(argv):
    import argparse
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    ap = argparse.ArgumentParser()
    ap.add_argument('--log')
    ap.add_argument('--since')
    ap.add_argument('--until')
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--write', action='store_true')
    a = ap.parse_args(argv)
    log = Path(a.log) if a.log else (pick_log(ROOT) or ROOT / LOGS[0])
    benches = sorted(glob.glob(str(ROOT / BENCH_GLOB)))
    rep = analyse(log, parse_time(a.since), parse_time(a.until), benches,
                  sorted(glob.glob(str(ROOT / LIVE_WINDOW_GLOB))), cores=hw_cores())
    out = json.dumps(rep, indent=1, default=str) if a.json else text_report(rep)
    print(out)
    if a.write:
        ts = datetime.datetime.now().strftime('%Y%m%dT%H%M')
        base = ROOT / f'harness/runtime/r30_hashrate_objective_{ts}'
        Path(f'{base}.json').write_text(json.dumps(rep, indent=1, default=str) + '\n')
        Path(f'{base}.txt').write_text(text_report(rep) + '\n')
    if rep['benches_refused']:
        return 6
    return 0 if rep['window'] else 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
