#!/usr/bin/env python3
"""quiet_window.py — r30 (rft §7 B236, §8 "R30 schedule" interruption 2): every miner bench of the round, in one
scripted, resumable run for the ONE user-announced quiet window.

Why one runner: a bench on a busy box is invalid evidence (rft §5, G20), and the box is busy whenever the live miner
mines (launchd, 18 of 20 cores). So the benches wait for the window the user announces, then run back to back, in the
order below, the whole run inside one `benchlock.py --heavy` slot (it re-executes itself there: the shm of a large
geometry and the pipeline's own stages are the RAM-heavy part), each timing bench also under the exclusive bench lock
(`benchlock.py` without --heavy: benchlock refuses --heavy with --gpu, a timing bench needs the lock, not a slot; S4b/S4c
take that lock inside fix_build_verify themselves), each step after a contention.py census that must read quiet. The runner
writes what it measured, never a gain it did not measure: a step's verdict is its own ABBA/ratio, an ESTIMATE stays an
ESTIMATE, and a contended census REFUSES the step (no record) instead of benching.

Steps (id, rows, what; estimated minutes in STEPS):
  build    -       compile the bench test binaries of THIS checkout (cmd/dero-miner, gsplit, dsac) once
  s4b      S4b/B3  fix_build_verify.py --miner-bench-only: the staged miner vs the installed one (H/cpu-s, like for like)
  b25      B25     pinned E-core sort rate: TestR30SortRateBench under `taskpolicy -b` (T=4), then a P-core reference
                   (T=16); proc_pid_rusage v6 p_frac proves where it ran (E arm p_frac <= 0.05, else not an E reading)
  b3cpu    B3      CPU ABBA --cpu-max 90 vs 100 (TestDutyContentionAB, arms c90,c100, 20 threads, rotating order)
  s4c      B4      fix_build_verify.py --gpu-bench-only: S4c GPU self-A/B end to end (first run, L-G5)
  b3gsplit B3      DERO_GSPLIT ABBA 4096,4,2 vs 8192,3,2 at --gpu-max 96 and 100 (TestGPUCapacity, CPU side free);
                   resource_intel.py shm preflight before every geometry (B239); a geometry that does not fit is skipped
  b236     B236    isolation: (a) CPU sort capacity at 20 threads (--cpu-max 100 equivalent: no duty sleep), with
                   GODEBUG=gctrace=1 (the one gctrace read, B239); (b) = the b3gsplit GPU records; measured ceiling
                   min(S, G/(1-own)) with own from the newest live window (hashrate_objective.py)
  b237     B237    DSA_PROF per-phase profile at 1 and 15 threads; if merge >= 35 %: the L-C2 bit-exact differential
                   (20,000 fresh texts) then the r29-vs-bf merge ABBA at 1 and 15 threads (DERO_DSA_MERGE)

  python3 -I harness/pipeline/quiet_window.py plan [--json]          # steps, estimates, total minutes, preconditions
  python3 -I harness/pipeline/quiet_window.py run [--only ID] [--from ID] [--reset] [--wait-quiet-min 10]
  python3 -I harness/pipeline/quiet_window.py status [--json]

Refusals (exit 3): the live miner is running — its /metrics (127.0.0.1:10110) answers, derod reports a getwork miner
connected (dero_getwork_miners > 0 on 127.0.0.1:10102/metrics), or a process named dero-miner / gpu_split_server is in
the process table (names only). The runner never starts, stops or signals the live miner: the user stops it
(`launchctl bootout gui/$(id -u)/io.dero.miner`) and restarts it after the window. Exit 5: a census stayed contended
for --wait-quiet-min (the run stops; `run` again resumes at that step). Exit 2: bad arguments or no bench lock.

r30 B256 (rft §0.12 D-15): each step's census uses the step's OWN thread budget (STEP_CAPS: s4b 4 threads = the
minerbench's threads=4, b25 16 = its larger arm, b237 15, the GPU-side s4c / b3gsplit 4, b3cpu / b236 20). Before B256
every census assumed 20 threads x 100 %, so the headroom was 0 + 1 slack and a desktop's steady foreign load (3.4 cores
on 2026-11-11: browser renderers, Spotlight, media analysis, the window server; never ours to touch) could never read
quiet. A full-box step (budget >= ncpu - 1) runs under STEADY foreign load only: foreign <= STEADY_FOREIGN_MAX_FRAC x
ncpu at the start AND a second census after the step moved by <= STEADY_FOREIGN_DELTA cores; else the step is REFUSED
(not evidence). Such a step is labelled 'steady-foreign' with both censuses; its bench record says quiet false and
bound 'lower' (capacity measured while foreign load held cores: a lower bound of the quiet capacity, never more).
r30 B257: an exit 5 (REFUSED) writes harness/runtime/r30_qw/REFUSED (step, why, time) so a watchdog started with
`--stop` that file treats it as final instead of relaunching; `run` removes the marker when it starts.

Resumable: harness/runtime/r30_qw/state.json keeps each step's status (DONE / FAILED / REFUSED / SKIPPED) and its
records; `run` skips DONE steps. Liveness (rft §8 R30 rule (h)): harness/runtime/r30_qw/progress.json is rewritten
every 10 s while a step runs ({t, step, idx, out_bytes}); the plan prints the stallwatch command that watches it
(counter out_bytes, done marker harness/runtime/r30_qw/DONE). Records: harness/runtime/r30_qw/<step>.log (raw),
harness/runtime/r30_ceiling_{cpu,gpu}_*.json (bench records for G34 / hashrate_objective, schema B236: kind bench,
quiet true, contention), harness/runtime/r30_qw/results.json (every step's parsed verdict).
"""
import argparse, json, os, re, shutil, statistics, subprocess, sys, threading, time, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
QW = 'harness/runtime/r30_qw'
BIN = 'harness/runtime/r30_qw/bin'
MINER_METRICS = 'http://127.0.0.1:10110/metrics'
DEROD_METRICS = 'http://127.0.0.1:10102/metrics'
LIVE_NAMES = ('dero-miner', 'gpu_split_server', 'gpu_hash_sais')
E_ARM_MAX_PFRAC = 0.05           # B25: an E-core reading must have run (almost) only on E-cores
B237_MERGE_MIN = 0.35            # B237: the merge variant is tried only if the merge is still >= 35 % of the sort
ABBA_GAIN_MIN = 1.01             # a lever 'wins' only with ratio >= 1.01 AND every pair but at most one won
GEOMS = ('4096,4,2', '8192,3,2')
GPU_MAXES = (96, 100)

# (id, rows, minutes ESTIMATE, what). The order is the brief's (rft §8 interruption 2): S4b, B25, B3 CPU, S4c, B3
# GSPLIT, B236, B237; 'build' first. The minutes are sized from the steps' own parameters (windows x rounds) plus
# start-up, and S4b from its measured pipeline records (1.2-1.8 min, harness/loop/runs pipeline_2026110{1,6}*.jsonl).
STEPS = [
    ('build', '-', 2, 'compile the bench test binaries of this checkout'),
    ('s4b', 'S4b B3', 3, 'staged vs installed miner bench (fix_build_verify --miner-bench-only)'),
    ('b25', 'B25', 4, 'pinned E-core sort rate (taskpolicy -b, T=4, 3 x 20 s) + P-core reference (T=16, 3 x 20 s)'),
    ('b3cpu', 'B3 L-C1', 6, 'CPU ABBA --cpu-max 90 vs 100 (20 threads, 6 rounds x 2 arms x 20 s)'),
    ('s4c', 'B4 L-G5', 10, 'S4c GPU self-A/B end to end (fix_build_verify --gpu-bench-only)'),
    ('b3gsplit', 'B3 L-G1 L-G2', 10, 'GSPLIT ABBA 4096,4,2 vs 8192,3,2 x --gpu-max 96 vs 100 (ABCD DCBA, 8 runs x ~45 s, shm preflight)'),
    ('b236', 'B236 B239', 4, 'CPU sort capacity at 20 threads (3 x 30 s, gctrace) + measured ceiling'),
    ('b237', 'B237 L-C14 L-C2', 16, 'DSA_PROF at 1/15 threads; L-C2 differential (20,000 texts) + merge ABBA at 1/15 threads'),
]
# r30 B256: (threads, cpu_max) each step really runs with: the census budget. s4b: fix_build_verify --miner-bench-only
# benches at threads=4 (pipeline_20261111T053936 minerbench threads=4); b25: arms T=4 and T=16 (the larger counts);
# b237: 1 and 15 threads; s4c / b3gsplit: GPU-side, the CPU side free (feeder + server: GPU_SIDE_THREADS); b3cpu,
# b236: 20 threads (the full box).
GPU_SIDE_THREADS = 4
STEP_CAPS = {'s4b': (4, 100), 'b25': (16, 100), 'b3cpu': (20, 100), 's4c': (GPU_SIDE_THREADS, 100),
             'b3gsplit': (GPU_SIDE_THREADS, 100), 'b236': (20, 100), 'b237': (15, 100)}
STEADY_FOREIGN_MAX_FRAC = 0.20   # D-15: a full-box step runs only while foreign load <= 20 % of the cpus (4.0 of 20) ...
STEADY_FOREIGN_DELTA = 1.0       # ... and moved by <= 1 core (contention.CONTENDED_SLACK_CORES) across the step
CENSUS_MIN = 0.25                # one contention.py census (two ps samples 5 s apart, plus start-up) before each step


def total_minutes(steps=STEPS):
    """the window length the runner needs: every step's estimate plus one census each. Pure."""
    return round(sum(s[2] for s in steps) + CENSUS_MIN * len(steps), 1)


# ── preconditions ────────────────────────────────────────────────────────────────────────────────────────────────────
def fetch(url, timeout=3):
    """the body of a loopback GET, or None. Read-only."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read().decode('utf-8', 'replace')
    except Exception:                                   # noqa: BLE001 — down is an answer
        return None


def metric(text, name):
    """the value of an unlabelled Prometheus sample, or None. Pure."""
    m = re.search(r'^' + re.escape(name) + r'\s+([0-9.eE+-]+)\s*$', text or '', re.M)
    return float(m.group(1)) if m else None


def ps_names():
    """the basenames of every process (names only: no pid, args or path is kept)."""
    try:
        out = subprocess.run(['ps', '-A', '-o', 'comm='], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return [os.path.basename(l.strip()) for l in out.splitlines() if l.strip()]


def live_miner_reasons(miner_metrics, derod_metrics, names):
    """why the live miner counts as running ([] = stopped). Pure: the KAT feeds it readings."""
    why = []
    if miner_metrics is not None:
        why.append('the miner /metrics (127.0.0.1:10110) answers')
    gm = metric(derod_metrics, 'dero_getwork_miners')
    if gm is not None and gm > 0:
        why.append(f'derod reports {gm:.0f} getwork miner(s) connected (dero_getwork_miners)')
    if names is None:
        why.append('the process table could not be read (a check that cannot see the miner cannot say it stopped)')
    else:
        live = sorted({n for n in names if n in LIVE_NAMES})
        if live:
            why.append(f"process(es) running: {', '.join(live)}")
    return why


def full_box(sid, ncpu=None):
    """a step whose thread budget takes (almost) every cpu: it can only run under steady foreign load (B256). Pure."""
    ncpu = ncpu or os.cpu_count() or 1
    t, c = STEP_CAPS.get(sid, (20, 100))
    return t * c / 100.0 >= ncpu - 1


def census_gate(sid, quiet, rec, ncpu=None):
    """(ok, mode) for one step's census (B256, D-15): 'quiet' when contention.py says quiet for the step's own budget;
    'steady-foreign' for a full-box step whose foreign load is <= STEADY_FOREIGN_MAX_FRAC x ncpu; else 'contended'. Pure."""
    ncpu = ncpu or (rec or {}).get('ncpu') or os.cpu_count() or 1
    if quiet:
        return True, 'quiet'
    fc = (rec or {}).get('foreign_cores')
    if full_box(sid, ncpu) and isinstance(fc, (int, float)) and fc <= STEADY_FOREIGN_MAX_FRAC * ncpu:
        return True, 'steady-foreign'
    return False, 'contended'


def steady_after(before, after):
    """(ok, why): the foreign load stayed steady across a full-box step (B256, D-15). Pure."""
    b, a = (before or {}).get('foreign_cores'), (after or {}).get('foreign_cores')
    if not isinstance(b, (int, float)) or not isinstance(a, (int, float)):
        return False, 'no foreign-core reading before or after the step'
    ncpu = (after or {}).get('ncpu') or os.cpu_count() or 1
    if abs(a - b) > STEADY_FOREIGN_DELTA:
        return False, f'foreign load moved {b} -> {a} cores (> {STEADY_FOREIGN_DELTA}) across the step'
    if a > STEADY_FOREIGN_MAX_FRAC * ncpu:
        return False, f'foreign load {a} cores after the step > {STEADY_FOREIGN_MAX_FRAC} x {ncpu} cpus'
    return True, f'foreign load steady {b} -> {a} cores'


def census(threads=20, cpu_max=100):
    """(quiet, record) from harness/intel/contention.py (read-only ps census)."""
    try:
        p = subprocess.run([sys.executable, '-I', str(ROOT / 'harness/intel/contention.py'), '--json', '--threads',
                            str(threads), '--cpu-max', str(cpu_max)], capture_output=True, text=True, timeout=120)
        rec = json.loads(p.stdout) if p.stdout.strip().startswith('{') else {'raw': p.stdout[-400:]}
    except (OSError, subprocess.SubprocessError, ValueError) as e:
        return False, {'error': f'{type(e).__name__}: {e}'}
    rec['exit'] = p.returncode
    return p.returncode == 0, rec


# ── state ────────────────────────────────────────────────────────────────────────────────────────────────────────────
def load_state(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {'steps': {}}


def save_state(path, st):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix('.tmp')
    tmp.write_text(json.dumps(st, indent=1) + '\n')
    os.replace(tmp, p)


def pending_steps(st, only=None, start=None, steps=STEPS):
    """the step ids still to run, in order: DONE and SKIPPED ones are never redone. Pure."""
    ids = [s[0] for s in steps]
    if only:
        ids = [i for i in ids if i == only]
    if start and start in ids:
        ids = ids[ids.index(start):]
    return [i for i in ids if (st.get('steps', {}).get(i) or {}).get('status') not in ('DONE', 'SKIPPED')]


# ── parsers (pure) ───────────────────────────────────────────────────────────────────────────────────────────────────
def parse_prefixed(text, prefix):
    out = []
    for line in (text or '').splitlines():
        if line.startswith(prefix + ' '):
            try:
                out.append(json.loads(line[len(prefix) + 1:]))
            except ValueError:
                pass
    return out


def parse_duty(text):
    """{arm: [sorts/wall-s per round]} from TestDutyContentionAB's DUTY round lines. Pure."""
    out = {}
    for m in re.finditer(r'^DUTY round (\d+) cap\s+(\S+) T=\d+ sorts/wall-s\s+([\d.]+)', text or '', re.M):
        out.setdefault(m.group(2), []).append(float(m.group(3)))
    return out


def parse_gpucap(text):
    """[{geom, gpu_max, median}] from TestGPUCapacity's GPU CAPACITY lines. Pure."""
    rx = re.compile(r'GPU CAPACITY geom (\S+) gpu-max (\d+) .*?median (\d+) staged H/s')
    return [{'geom': m.group(1), 'gpu_max': int(m.group(2)), 'median': float(m.group(3))} for m in rx.finditer(text or '')]


def parse_gctrace(text):
    """the GC CPU share since process start from the LAST 'gc N @Ts P%:' line (GODEBUG=gctrace=1), and the count. Pure."""
    hits = re.findall(r'^gc (\d+) @[\d.]+s (\d+)%:', text or '', re.M)
    if not hits:
        return {'gc_cycles': 0, 'gc_cpu_pct': None}
    return {'gc_cycles': int(hits[-1][0]), 'gc_cpu_pct': int(hits[-1][1])}


def abba(a_vals, b_vals):
    """paired ABBA verdict of arm B over arm A: ratio of means, pairs B won, and the verdict word. Pure."""
    n = min(len(a_vals), len(b_vals))
    if n == 0:
        return {'n': 0, 'verdict': 'NO-DATA'}
    ma, mb = statistics.mean(a_vals[:n]), statistics.mean(b_vals[:n])
    won = sum(1 for x, y in zip(a_vals[:n], b_vals[:n]) if y > x)
    ratio = mb / ma if ma else None
    if ratio is None:
        v = 'NO-DATA'
    elif ratio >= ABBA_GAIN_MIN and won >= n - 1:
        v = 'B-WINS'
    elif ratio <= 1 / ABBA_GAIN_MIN and won <= 1:
        v = 'A-WINS'
    else:
        v = 'WITHIN-NOISE'
    return {'n': n, 'mean_a': round(ma, 1), 'mean_b': round(mb, 1), 'ratio': round(ratio, 4) if ratio else None,
            'b_won': won, 'verdict': v}


def sortrate_arms(recs, key='sorts_per_cpu_s'):
    """{arm: [values in round order]} from R30SORTRATE records. Pure."""
    out = {}
    for r in sorted(recs, key=lambda r: (r.get('round', 0))):
        if key in r:
            out.setdefault(r.get('arm', '?'), []).append(float(r[key]))
    return out


def gsplit_order(geoms=GEOMS, maxes=GPU_MAXES):
    """the b3gsplit run order: A=(g0,m0) B=(g1,m0) C=(g1,m1) D=(g0,m1), then reversed (ABCD DCBA), so every
    (geometry, gpu-max) arm runs twice and each comparison's two arms take mirrored positions (drift cancels). Pure."""
    first = [(geoms[0], maxes[0]), (geoms[1], maxes[0]), (geoms[1], maxes[1]), (geoms[0], maxes[1])]
    return first + first[::-1]


def bench_record(side, value, contention, **kw):
    """a ceiling input in the B236 schema hashrate_objective.bench_ok accepts: kind bench, quiet true, the census. Pure."""
    steady = (contention or {}).get('qw_mode') == 'steady-foreign'          # r30 B256: never claim a quiet box
    rec = {'kind': 'bench', 'quiet': not steady, 'contention': contention, 'side': side,
           ('S_hs' if side == 'cpu' else 'G_staged_hs'): value, 't': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
           'source': 'harness/pipeline/quiet_window.py'}
    if steady:
        rec.update(bound='lower', foreign_cores=(contention or {}).get('foreign_cores'),
                   label=f"measured under {(contention or {}).get('foreign_cores')} foreign cores (steady): a lower bound "
                         'of the quiet capacity')
    rec.update(kw)
    return rec


def e_core_verdict(e_recs, p_recs):
    """B25: r_E and r_P (sorts per CPU-second) and whether the E arm really ran on the E-cores. Pure."""
    def med(rs, k):
        v = [float(r[k]) for r in rs if k in r]
        return statistics.median(v) if v else None
    pe, pp = med(e_recs, 'p_frac'), med(p_recs, 'p_frac')
    out = {'r_E': med(e_recs, 'sorts_per_cpu_s'), 'r_P': med(p_recs, 'sorts_per_cpu_s'), 'e_arm_p_frac': pe,
           'p_arm_p_frac': pp}
    out['e_arm_on_e_cores'] = pe is not None and pe <= E_ARM_MAX_PFRAC
    if not out['e_arm_on_e_cores']:
        out['why'] = (f'the E arm ran {pe:.3f} of its CPU on P-cores (> {E_ARM_MAX_PFRAC}): not an E-core reading'
                      if pe is not None else 'no P/E split in the records (pre-r30 binary?)')
    return out


# ── running ──────────────────────────────────────────────────────────────────────────────────────────────────────────
class Runner:
    def __init__(self, a, root=ROOT):
        self.a, self.root = a, Path(root)
        self.qw = self.root / QW
        self.bin = self.root / BIN
        self.state_path = self.qw / 'state.json'
        self.st = load_state(self.state_path)
        self.results = {}

    def lock(self):
        try:
            v = json.loads((self.root / 'harness/round.json').read_text()).get('benchlock')
        except (OSError, ValueError):
            v = None
        v = os.environ.get('DERO_BENCHLOCK') or v
        return os.path.expanduser(v) if v else None

    def progress(self, step, idx, logp):
        try:
            b = logp.stat().st_size if logp.exists() else 0
        except OSError:
            b = 0
        tmp = self.qw / 'progress.tmp'
        tmp.write_text(json.dumps({'t': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'step': step, 'idx': idx, 'out_bytes': b}))
        os.replace(tmp, self.qw / 'progress.json')

    def sh(self, step, cmd, cwd=None, env=None, lock=True, timeout=3600):
        """run one command, appending its output to the step log; (rc, text). lock=True: under the exclusive bench lock
        (a timing bench); False: as is (the build, or a pipeline stage that takes the bench lock itself). The whole run
        already holds one heavy slot (run() re-executes itself under benchlock --heavy)."""
        full = ([sys.executable, '-I', str(self.root / 'harness/pipeline/benchlock.py'), '--'] if lock else []) + cmd
        logp = self.qw / f'{step}.log'
        e = dict(os.environ)
        e.update(env or {})
        with open(logp, 'a') as lf:
            lf.write(f"\n# {time.strftime('%H:%M:%S')} {' '.join(map(str, cmd))} env={sorted((env or {}).items())}\n")
            lf.flush()
            start = lf.tell()
            p = subprocess.Popen(full, cwd=cwd or self.root, env=e, stdout=lf, stderr=subprocess.STDOUT)
            stop = threading.Event()

            def beat():
                while not stop.wait(10):
                    self.progress(step, self.idx, logp)
            th = threading.Thread(target=beat, daemon=True)
            th.start()
            try:
                rc = p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                p.kill()
                rc = 124
            stop.set()
        with open(logp) as lf:
            lf.seek(start)
            return rc, lf.read()

    def tbin(self, name):
        return str(self.bin / f'{name}.test')

    # each step returns (status, result dict)
    def step_build(self):
        self.bin.mkdir(parents=True, exist_ok=True)
        res = {}
        for name, pkg in (('miner', './cmd/dero-miner/'), ('gsplit', './cmd/dero-miner/gsplit/'), ('dsac', './cmd/dero-miner/dsac/')):
            rc, out = self.sh('build', ['go', 'test', '-c', '-o', self.tbin(name), pkg], lock=False, timeout=900)
            res[name] = rc
            if rc:
                return 'FAILED', {'why': f'go test -c {pkg} exit {rc}', 'tail': out[-600:]}
        return 'DONE', res

    def step_s4b(self):
        lk = self.lock()
        rc, out = self.sh('s4b', [sys.executable, '-I', 'harness/pipeline/fix_build_verify.py', '--miner-bench-only',
                                  '--benchlock', lk], lock=False)
        return ('DONE' if rc == 0 else 'FAILED'), {'rc': rc, 'record': 'harness/loop/PIPELINE_LAST.json', 'tail': out[-400:]}

    def sortrate(self, step, T, win, rounds, arms='r29', qos_bg=False):
        env = {'DERO_SORTRATE_BENCH': '1', 'DERO_SORTRATE_T': str(T), 'DERO_SORTRATE_WIN': str(win),
               'DERO_SORTRATE_ROUNDS': str(rounds), 'DERO_SORTRATE_ARMS': arms}
        cmd = ([shutil.which('taskpolicy') or 'taskpolicy', '-b'] if qos_bg else []) + \
              [self.tbin('miner'), '-test.run', '^TestR30SortRateBench$', '-test.v', '-test.count=1']
        rc, out = self.sh(step, cmd, cwd=self.root / 'cmd/dero-miner', env=env)
        return rc, parse_prefixed(out, 'R30SORTRATE'), out

    def step_b25(self):
        rc1, e_recs, _ = self.sortrate('b25', 4, 20, 3, qos_bg=True)
        rc2, p_recs, _ = self.sortrate('b25', 16, 20, 3)
        if rc1 or rc2 or not e_recs or not p_recs:
            return 'FAILED', {'why': f'bench exit {rc1}/{rc2}, records {len(e_recs)}/{len(p_recs)}'}
        v = e_core_verdict(e_recs, p_recs)
        out = self.root / 'harness/runtime' / f"r30_bench_b25_{time.strftime('%Y%m%dT%H%M%S')}.json"
        out.write_text(json.dumps({'kind': 'bench', 'quiet': True, 'contention': self.cur_census, 'row': 'B25',
                                   'verdict': v, 'e_arm': e_recs, 'p_arm': p_recs}, indent=1) + '\n')
        return 'DONE', dict(v, record=str(out.relative_to(self.root)))

    def step_b3cpu(self):
        env = {'DERO_DUTY_BENCH': '1', 'DERO_DUTY_ARMS': 'c90,c100', 'DERO_QOS_T': '20', 'DERO_QOS_WIN': '20',
               'DERO_QOS_ROUNDS': '6'}
        rc, out = self.sh('b3cpu', [self.tbin('miner'), '-test.run', '^TestDutyContentionAB$', '-test.v', '-test.count=1'],
                          cwd=self.root / 'cmd/dero-miner', env=env)
        d = parse_duty(out)
        if rc or 'c90' not in d or 'c100' not in d:
            return 'FAILED', {'rc': rc, 'arms': list(d)}
        return 'DONE', {'lever': 'L-C1 --cpu-max 100 over 90', 'abba': abba(d['c90'], d['c100']), 'arms': d}

    def step_s4c(self):
        lk = self.lock()
        rc, out = self.sh('s4c', [sys.executable, '-I', 'harness/pipeline/fix_build_verify.py', '--gpu-bench-only',
                                  '--benchlock', lk], lock=False)
        return ('DONE' if rc == 0 else 'FAILED'), {'rc': rc, 'record': 'harness/loop/PIPELINE_LAST.json', 'tail': out[-400:]}

    def shm_ok(self, geom):
        p = subprocess.run([sys.executable, '-I', str(self.root / 'harness/intel/resource_intel.py'), 'shm', '--geom', geom,
                            '--json'], capture_output=True, text=True, timeout=60)
        try:
            v = json.loads(p.stdout)
        except ValueError:
            v = {'verdict': 'REFUSED', 'why': 'unreadable preflight output'}
        return p.returncode == 0, v

    def step_b3gsplit(self):
        fits = {g: self.shm_ok(g) for g in GEOMS}
        runs, recs = [], []
        for g, gm in gsplit_order():                                       # balanced ABBA over geometry x gpu-max
            if not fits[g][0]:
                runs.append({'geom': g, 'gpu_max': gm, 'skipped': fits[g][1].get('why')})
                continue
            env = {'GSPLIT_HARNESS': '1', 'GSPLIT_REAL': '1', 'GSPLIT_GEOMS': g, 'GSPLIT_GPUMAX': str(gm)}
            rc, out = self.sh('b3gsplit', [self.tbin('gsplit'), '-test.run', '^TestGPUCapacity$', '-test.v',
                                           '-test.count=1'], cwd=self.root / 'cmd/dero-miner/gsplit', env=env)
            got = parse_gpucap(out)
            runs.append({'geom': g, 'gpu_max': gm, 'rc': rc, 'median': got[0]['median'] if got else None})
        verdicts = {}
        for gm in GPU_MAXES:
            a = [r['median'] for r in runs if r['gpu_max'] == gm and r['geom'] == GEOMS[0] and r.get('median')]
            b = [r['median'] for r in runs if r['gpu_max'] == gm and r['geom'] == GEOMS[1] and r.get('median')]
            verdicts[f'gpu_max {gm}: {GEOMS[1]} over {GEOMS[0]}'] = abba(a, b)
        for g in GEOMS:                                                    # L-G2: --gpu-max 100 over 96 per geometry
            a = [r['median'] for r in runs if r['geom'] == g and r['gpu_max'] == GPU_MAXES[0] and r.get('median')]
            b = [r['median'] for r in runs if r['geom'] == g and r['gpu_max'] == GPU_MAXES[1] and r.get('median')]
            verdicts[f'{g}: gpu_max {GPU_MAXES[1]} over {GPU_MAXES[0]}'] = abba(a, b)
            for g, vals in ((GEOMS[0], a), (GEOMS[1], b)):
                if vals:
                    rec = bench_record('gpu', statistics.median(vals), self.cur_census, geometry=g, gpu_max=gm,
                                       row='B236 (b) / B3', n=len(vals))
                    p = self.root / 'harness/runtime' / f"r30_ceiling_gpu_{g.replace(',', '-')}_{gm}_{time.strftime('%Y%m%dT%H%M%S')}.json"
                    p.write_text(json.dumps(rec, indent=1) + '\n')
                    recs.append(str(p.relative_to(self.root)))
        ok = any(r.get('median') for r in runs)
        return ('DONE' if ok else 'FAILED'), {'shm': {g: v[1].get('verdict') for g, v in fits.items()}, 'runs': runs,
                                               'abba': verdicts, 'records': recs}

    def step_b236(self):
        env = {'DERO_SORTRATE_BENCH': '1', 'DERO_SORTRATE_T': '20', 'DERO_SORTRATE_WIN': '30', 'DERO_SORTRATE_ROUNDS': '3',
               'DERO_SORTRATE_ARMS': 'r29', 'GODEBUG': 'gctrace=1'}
        rc, out = self.sh('b236', [self.tbin('miner'), '-test.run', '^TestR30SortRateBench$', '-test.v', '-test.count=1'],
                          cwd=self.root / 'cmd/dero-miner', env=env)
        recs = parse_prefixed(out, 'R30SORTRATE')
        if rc or not recs:
            return 'FAILED', {'rc': rc, 'records': len(recs)}
        S = statistics.median(r['sorts_per_s'] for r in recs)
        gc = parse_gctrace(out)
        gc['rule'] = ('GOGC/GOMEMLIMIT stay NO-GO (lesson #1): GC < 1 % of CPU' if (gc['gc_cpu_pct'] or 0) < 1 else
                      'GC >= 1 % of CPU: a GOGC/GOMEMLIMIT A/B is admissible (B239)')
        rec = bench_record('cpu', S, self.cur_census, threads=20, cpu_max=100, row='B236 (a)', windows=recs, gctrace=gc)
        p = self.root / 'harness/runtime' / f"r30_ceiling_cpu_{time.strftime('%Y%m%dT%H%M%S')}.json"
        p.write_text(json.dumps(rec, indent=1) + '\n')
        res = {'S_hs': round(S), 'gctrace': gc, 'record': str(p.relative_to(self.root))}
        try:                                                    # the measured ceiling, by the G34 tool's own code
            import importlib.util
            spec = importlib.util.spec_from_file_location('ho_qw', self.root / 'harness/intel/hashrate_objective.py')
            HO = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(HO)
            res['g34'] = HO.g34(self.root)
        except Exception as e:                                  # noqa: BLE001 — the bench record stands either way
            res['g34'] = f'unavailable: {type(e).__name__}: {e}'
        return 'DONE', res

    def step_b237(self):
        env = {'DERO_DSAPROF_BENCH': '1', 'DERO_DSAPROF_T': '1,15', 'DERO_DSAPROF_TEXTS': '256', 'DERO_DSAPROF_REPS': '8',
               'DERO_DSAPROF_MERGE': '0'}
        rc, out = self.sh('b237', [self.tbin('miner'), '-test.run', '^TestR30DSAProfile$', '-test.v', '-test.count=1'],
                          cwd=self.root / 'cmd/dero-miner', env=env)
        prof = parse_prefixed(out, 'R30DSAPROF')
        if rc or not prof:
            return 'FAILED', {'rc': rc, 'why': 'no DSA_PROF record'}
        res = {'profile': [{'threads': p['threads'], 'shares': p['shares'], 'texts_per_s': p.get('texts_per_s')} for p in prof]}
        merge15 = max((p['shares'].get('merge', 0) for p in prof), default=0)
        if merge15 < B237_MERGE_MIN:
            res['lc2'] = f'SKIPPED: merge {merge15:.3f} < {B237_MERGE_MIN} of the sort (B237 rule)'
            return 'DONE', res
        rc, out = self.sh('b237', [self.tbin('dsac'), '-test.run', '^TestR30MergeVariantBitExact$', '-test.v',
                                   '-test.count=1'], cwd=self.root / 'cmd/dero-miner/dsac', env={'DSAC_R30_N': '20000'})
        res['lc2_bitexact'] = 'PASS' if rc == 0 else f'FAIL (exit {rc})'
        if rc:
            return 'FAILED', res
        res['lc2_abba'] = {}
        for T, win in ((1, 15), (15, 20)):
            rc, recs, _ = self.sortrate('b237', T, win, 6, arms='r29,bf')
            arms = sortrate_arms(recs)
            res['lc2_abba'][f'T={T}'] = abba(arms.get('r29', []), arms.get('bf', [])) if not rc else {'verdict': f'FAILED (exit {rc})'}
        wins = [v.get('verdict') for v in res['lc2_abba'].values()]
        res['lc2_decision'] = ('enable DERO_DSA_MERGE=bf (both thread counts B-WINS; the merge agent flips the default)'
                               if wins and all(w == 'B-WINS' for w in wins) else 'keep DERO_DSA_MERGE default off')
        return 'DONE', res

    def run(self):
        a = self.a
        self.qw.mkdir(parents=True, exist_ok=True)
        if not self.lock():
            print('quiet_window: no bench lock ($DERO_BENCHLOCK or harness/round.json benchlock)')
            return 2
        why = live_miner_reasons(fetch(MINER_METRICS), fetch(DEROD_METRICS), ps_names())
        if why:
            print('quiet_window: REFUSED — the live miner is running: ' + '; '.join(why))
            print('  the user stops it first: launchctl bootout gui/$(id -u)/io.dero.miner (this tool never does)')
            return 3
        if getattr(a, 'heavy_slot', True) and os.environ.get('DERO_QW_INNER') != '1':
            # the whole window in one heavy slot: re-execute under benchlock --heavy (the checks above run again inside)
            argv = [sys.executable, '-I', str(self.root / 'harness/pipeline/benchlock.py'), '--heavy', '--',
                    sys.executable, '-I', str(Path(__file__).resolve()), 'run', '--wait-quiet-min', str(a.wait_quiet_min)]
            argv += (['--only', a.only] if a.only else []) + (['--from', a.from_] if getattr(a, 'from_', None) else [])
            return subprocess.call(argv, cwd=self.root, env=dict(os.environ, DERO_QW_INNER='1'))
        (self.qw / 'REFUSED').unlink(missing_ok=True)            # r30 B257: a new run clears the final marker
        todo = pending_steps(self.st, a.only, getattr(a, 'from_'))
        print(f'quiet_window: {len(todo)} step(s) to run: {" ".join(todo)} (ESTIMATE '
              f'{total_minutes([s for s in STEPS if s[0] in todo])} min)')
        for self.idx, sid in enumerate(todo):
            mode = None
            if sid != 'build':
                caps = STEP_CAPS.get(sid, (20, 100))                 # r30 B256: the step's own budget
                quiet, rec = census(*caps)
                ok, mode = census_gate(sid, quiet, rec)
                waited = 0
                while not ok and waited < a.wait_quiet_min:
                    time.sleep(60)
                    waited += 1
                    quiet, rec = census(*caps)
                    ok, mode = census_gate(sid, quiet, rec)
                if not ok:
                    return self.refuse(sid, f'contended census for {a.wait_quiet_min} min at the step budget '
                                            f'{caps[0]} threads x {caps[1]} %: not evidence', rec)
                rec['qw_mode'] = mode
                self.cur_census = rec
            else:
                self.cur_census = {}
            t0 = time.time()
            self.progress(sid, self.idx, self.qw / f'{sid}.log')
            try:
                status, res = getattr(self, f'step_{sid}')()
            except Exception as e:                              # noqa: BLE001 — recorded, the run stops
                status, res = 'FAILED', {'why': f'{type(e).__name__}: {e}'}
            res['minutes'] = round((time.time() - t0) / 60, 2)
            if mode == 'steady-foreign' and status == 'DONE':          # r30 B256 / D-15: the load must not move
                _, after = census(*STEP_CAPS.get(sid, (20, 100)))
                ok, why = steady_after(self.cur_census, after)
                res['foreign_load'] = {'mode': mode, 'before': self.cur_census.get('foreign_cores'),
                                       'after': after.get('foreign_cores'), 'verdict': why}
                if not ok:
                    self.st['steps'][sid] = {'status': 'REFUSED', 'why': why + ': not evidence', 'not_evidence': res,
                                             'census': self.cur_census, 'census_after': after,
                                             't': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
                    save_state(self.state_path, self.st)
                    return self.refuse(sid, why + ': not evidence', after, saved=True)
            self.st['steps'][sid] = {'status': status, 'result': res, 'census': self.cur_census,
                                     't': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
            save_state(self.state_path, self.st)
            print(f"  {sid}: {status} in {res['minutes']} min")
            if status == 'FAILED' and sid == 'build':
                return 6
        (self.qw / 'results.json').write_text(json.dumps(self.st, indent=1) + '\n')
        if not pending_steps(self.st):
            (self.qw / 'DONE').write_text(time.strftime('%Y-%m-%dT%H:%M:%S%z') + '\n')
        return 0 if all(v.get('status') in ('DONE', 'SKIPPED') for v in self.st['steps'].values()) else 6


def _refuse(self, sid, why, rec, saved=False):
    """REFUSED (exit 5, resumable): state + the final marker harness/runtime/r30_qw/REFUSED (r30 B257)."""
    t = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    if not saved:
        self.st['steps'][sid] = {'status': 'REFUSED', 'why': why, 'census': rec, 't': t}
        save_state(self.state_path, self.st)
    (self.qw / 'REFUSED').write_text(f'{sid} REFUSED {t}: {why}\n')
    print(f'  {sid}: REFUSED ({why}); `run` again resumes here; marker {QW}/REFUSED')
    return 5


Runner.refuse = _refuse


def plan_text(root=ROOT):
    lines = [f'quiet_window plan (rft §8 R30 schedule, interruption 2): {len(STEPS)} steps, ESTIMATE {total_minutes()} min '
             f'(steps {sum(s[2] for s in STEPS)} + census {CENSUS_MIN} x {len(STEPS)})']
    st = load_state(Path(root) / QW / 'state.json')
    for i, (sid, rows, mins, what) in enumerate(STEPS):
        s = (st.get('steps', {}).get(sid) or {}).get('status', 'pending')
        lines.append(f'  {i}. {sid:<9} {rows:<16} {mins:>3} min  [{s}]  {what}')
    lines.append('preconditions: the live miner stopped by the user (miner /metrics down, dero_getwork_miners 0, no '
                 'dero-miner process); contention.py quiet before each step; resource_intel shm OK per geometry; the staged '
                 'r30 build in bin/.staging (S4b/S4c)')
    lines.append('liveness: ' + STALLWATCH_CMD)
    return '\n'.join(lines)


# r30 B255: the stallwatch line the plan prints must run as printed: --log is required by stallwatch.parse (the armed
# launcher exited 2 on the old line), and --stop makes an exit 5 (REFUSED) final (B257)
STALLWATCH_CMD = ('python3 -I harness/kit/stallwatch.py --match "quiet_window.py run" --cmd-file <file holding '
                  '"cd <repo> && nice -n 15 python3 -I harness/pipeline/quiet_window.py run"> --progress '
                  'harness/runtime/r30_qw/progress.json --counter out_bytes --done harness/runtime/r30_qw/DONE '
                  '--stop harness/runtime/r30_qw/REFUSED --stall-s 900 --max-restarts 1 --log harness/runtime/r30_qw/stallwatch.log')


def parse(argv):
    ap = argparse.ArgumentParser(prog='quiet_window.py', description=__doc__.split('\n\n')[0])
    ap.add_argument('cmd', nargs='?', choices=['plan', 'run', 'status'], default='plan')
    ap.add_argument('--only')
    ap.add_argument('--from', dest='from_')
    ap.add_argument('--reset', action='store_true', help='run: forget the saved state first')
    ap.add_argument('--wait-quiet-min', type=int, default=10)
    ap.add_argument('--json', action='store_true')
    return ap.parse_args(argv)


def main(argv):
    try:
        a = parse(argv)
    except SystemExit as e:
        return 0 if e.code in (0, None) else 2
    ids = [s[0] for s in STEPS]
    if (a.only and a.only not in ids) or (a.from_ and a.from_ not in ids):
        print(f'quiet_window: unknown step (known: {" ".join(ids)})')
        return 2
    if a.cmd == 'plan':
        if a.json:
            print(json.dumps({'steps': [dict(zip(('id', 'rows', 'minutes', 'what'), s)) for s in STEPS],
                              'total_minutes': total_minutes()}, indent=1))
        else:
            print(plan_text())
        return 0
    if a.cmd == 'status':
        st = load_state(ROOT / QW / 'state.json')
        print(json.dumps(st, indent=1) if a.json else plan_text())
        return 0
    if a.reset:
        (ROOT / QW / 'state.json').unlink(missing_ok=True)
        (ROOT / QW / 'DONE').unlink(missing_ok=True)
    return Runner(a).run()


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
