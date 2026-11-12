#!/usr/bin/env python3
"""round_pause.py — r30 (rft §7 B252, §0.10, §2.22): one-command pause / resume of a DERO HE round.

The user (2026-11-09, rft §2.22): "pause round-30" before the tokens run out, "resume round-30" when they are back, with
nothing lost — pipelines, tasks, agents, and the measurements being collected at that moment. The checkpoint loop
(round_checkpoint.py, §0.10) already records the round every few minutes; this tool adds what a session stop loses on top
of it, and the comparison that makes the resume exact.

  pause   writes round_state/<round>_PAUSE.json (+ round_state/<round>_pause/<stamp>/ for the saved work):
          - the time, the repo head and its dirty files;
          - every clone scratchpad/<round>/*/tree (and */*/tree): branch, head, dirty files; uncommitted tracked changes
            saved as <dim>.patch (git diff --binary), untracked files as <dim>.untracked.tgz (capped), and commits that
            the repo does not hold as <dim>.bundle (a reboot wipes /private/tmp; the scratch backup skips tree/ and .git/);
          - the agents (round_checkpoint.agents: done / in-flight / stalled, HANDOFF.md and its check) and workflows;
          - the detached jobs (survive the session) with pid, cmd, cwd, the file each one grows, its size and mtime, its
            work counter and its end when known; the user's daemons (derod, the miner) observe-only;
          - the session-bound jobs (die with the session); the two loops among them (checkpoint, backup) are handed to a
            detached keeper (`keep`, setsid, ppid 1) that stands by while the session copy runs and takes over when it
            dies, so a loop never runs twice and never stops;
          - the due-actions ledger round_state/<round>_DUE.json (overdue first);
          - the pipeline: the newest harness/loop/runs/pipeline_*.jsonl, its stages, alive or not, its re-run command;
          then runs one checkpoint and one scratch backup, syncs the persist copy of round_checkpoint.py (sha recorded)
          and prints the exact checkpoint message for each in-flight agent.
  resume  reads the newest PAUSE.json and the live state: each detached job by its output growth since the pause
          (liveness = work; a dead one gets its restart command or a lost-window re-measure plan, never a silent merge),
          the loops (keepers started when missing), the overdue due-actions in order, the clone heads (a missing tree is
          re-created from its bundle + patch + untracked archive), the pipeline verdict (or its re-run command), the
          first NOT-DONE §6 step (sticky, round_checkpoint), and the agents to re-spawn from their HANDOFF.md. DONE work is
          listed as DONE and never redone.
  status  both views, writes nothing.
  check   (S7 step) the DUE ledger's schema and every HANDOFF.md of the round (handoff.py); exit 4 on a malformed
          DUE item; a HANDOFF problem is reported (WARN), not failed.
  due-done ID --evidence TEXT   mark one due item done (the ledger keeps who/when/evidence).
  DUE item: {id, what, status pending|done|skipped, due (ISO with zone) | after [ids] | when (an event condition),
             cmd (exact command), then_tell_user (the message after it), owner, evidence + done_at once done}.
  keep NAME                     the detached loop keeper (checkpoint | backup); idempotent by pidfile + process scan.
  ingest-snaps --src F --dst G  merge a detached loop's 24 h snapshot file into the repo copy by time, deduplicated;
                                refused while a pipeline RUNS (exit 3: the repo copy is a tracked file).
  DUE 'evidence' (list): declared evidence files of detached producers {id, out, pidfile?, kind ('snaps' | 'log'),
             gap_s (snaps: the cadence rule), window_since_epoch?, ingest_to?, restart?, log?, stalled_means?}: pause
             records size / lines / pid; resume classifies LIVE / ALIVE-NO-WORK / DIED (pidfile) or GROWING /
             NOT-GROWING, checks a snaps file for restart gaps (DR5: SEGMENTED) and cadence holes, and plans the ingest
             after any in-flight pipeline. The loop that produces a file is never stopped or restarted by this tool.

  nice -n 15 python3 -I harness/intel/round_pause.py pause  --round r30 [--dry-run] [--out DIR] [--json]
  nice -n 15 python3 -I harness/intel/round_pause.py resume --round r30 [--dry-run] [--out DIR] [--restore] [--json]
  nice -n 15 python3 -I harness/intel/round_pause.py status --round r30
  --dry-run: report only — nothing launched, no checkpoint/backup run, no persist sync; PAUSE.json and saved work go
  to --out (default: not written at all). Paths overridable for the KAT: ROUND_CKPT_REPO/OUT/PROJ/SCRATCH/PUB/PERSIST.
Exit 0 · 2 bad arguments / no PAUSE record · 4 check found a malformed DUE item. KAT harness/kat/test_round_pause_r30.py.
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):
    print(__doc__)
    raise SystemExit(0)
import datetime, hashlib, importlib.util, json, os, re, shutil, signal, subprocess, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


RC = _load('round_checkpoint_rp', HERE / 'round_checkpoint.py')
HO = _load('handoff_rp', HARNESS / 'kit' / 'handoff.py')
REPO, OUT, SCRATCH_ROOT, PERSIST = RC.REPO, RC.OUT, RC.SCRATCH_ROOT, RC.PERSIST
UNTRACKED_CAP = 50 * 1024 * 1024       # bytes of untracked files saved per tree (larger: listed, not saved)
QUIET_DEFAULT_S = 1800                 # a job silent less than its stall window (stallwatch --stall-s, else this) is not flagged
KEEP_POLL_S = float(os.environ.get('ROUND_PAUSE_POLL') or 30)


def loops():
    """the session-bound loops a pause hands to a detached keeper: {name: {match, cmd, log}}. ROUND_PAUSE_LOOPS (JSON)
    replaces them for the KAT."""
    env = os.environ.get('ROUND_PAUSE_LOOPS')
    if env:
        return json.loads(env)
    return {'checkpoint': {'match': 'round_checkpoint.py --loop',
                           'cmd': [sys.executable, '-I', str(REPO / 'harness/intel/round_checkpoint.py'), '--loop', '300'],
                           'log': str(OUT / 'checkpoint_loop.log')},
            'backup': {'match': 'backup_scratch.sh --loop',
                       'cmd': ['/bin/bash', str(PERSIST / 'backup_scratch.sh'), '--loop', '900'],
                       'log': str(OUT / 'backup_loop.log')}}


def now_iso(t=None):
    return datetime.datetime.fromtimestamp(time.time() if t is None else t).astimezone().isoformat(timespec='seconds')


def git(tree, *a, timeout=120):
    r = subprocess.run(['git', '-C', str(tree), *a], capture_output=True, timeout=timeout)
    return r.returncode, r.stdout.decode('utf-8', 'replace').strip(), r.stdout


def sha256(path):
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


# ───────────────────────────── clones ─────────────────────────────
def clone_trees(round_id, scratch_root=None):
    root = Path(scratch_root or SCRATCH_ROOT)
    out = []
    for pat in (f'*/scratchpad/{round_id}/*/tree', f'*/scratchpad/{round_id}/*/*/tree'):
        out += [p for p in sorted(root.glob(pat)) if (p / '.git').exists()]
    return out


def dim_of(tree):
    """the dim label of a clone: the path between the round dir and 'tree' ('pause', 'verify_x'). Pure."""
    parts = Path(tree).parts
    i = next((k for k in range(len(parts) - 1, -1, -1) if parts[k - 1:k] == ('scratchpad',)), None)
    mid = parts[i + 1:-1] if i is not None else parts[-2:-1]
    return '_'.join(mid) or Path(tree).parent.name


def clone_state(tree, repo=None):
    """{tree, dim, branch, head, dirty, untracked, merged} of one clone (read-only)."""
    repo = Path(repo or REPO)
    _, branch, _ = git(tree, 'branch', '--show-current')
    _, head, _ = git(tree, 'rev-parse', 'HEAD')
    _, st, _ = git(tree, 'status', '--porcelain', '--untracked-files=no')
    _, un, _ = git(tree, 'ls-files', '--others', '--exclude-standard')
    rh = git(repo, 'rev-parse', 'HEAD')[1]
    merged = bool(head) and git(repo, 'merge-base', '--is-ancestor', head, rh)[0] == 0
    return {'tree': str(tree), 'dim': dim_of(tree),
            'branch': branch or None, 'head': head or None, 'dirty': [l for l in st.splitlines() if l.strip()],
            'untracked': [l for l in un.splitlines() if l.strip()], 'merged_in_repo': merged, 'repo_head': rh}


def save_clone(c, dest):
    """write <dim>.patch / <dim>.untracked.tgz / <dim>.bundle into dest for one clone_state; returns the paths."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    tag = re.sub(r'[^\w.-]', '_', c['dim'])
    tree = c['tree']
    saved = {}
    if c['dirty']:
        rc, _, raw = git(tree, 'diff', 'HEAD', '--binary')
        if rc == 0 and raw:
            p = dest / f'{tag}.patch'
            p.write_bytes(raw)
            saved['patch'] = str(p)
            saved['patch_sha256'] = sha256(p)
    if c['untracked']:
        files, total, skipped = [], 0, []
        for f in c['untracked']:
            try:
                sz = (Path(tree) / f).stat().st_size
            except OSError:
                continue
            if total + sz > UNTRACKED_CAP:
                skipped.append(f)
                continue
            total += sz
            files.append(f)
        if files:
            p = dest / f'{tag}.untracked.tgz'
            r = subprocess.run(['tar', '-czf', str(p), '-C', str(tree), '--', *files], capture_output=True, timeout=600)
            if r.returncode == 0:
                saved['untracked_tgz'] = str(p)
                saved['untracked_sha256'] = sha256(p)
        if skipped:
            saved['untracked_not_saved'] = skipped
    if c['head'] and not c['merged_in_repo'] and c['branch']:
        p = dest / f'{tag}.bundle'
        rc, _, _ = git(tree, 'bundle', 'create', str(p), c['branch'], '--not', c['repo_head'], timeout=600)
        if rc == 0 and p.exists():
            saved['bundle'] = str(p)
            saved['bundle_sha256'] = sha256(p)
    return saved


def restore_cmds(c, repo=None):
    """the exact commands that re-create a missing clone from the pause record. Pure."""
    repo = str(repo or REPO)
    s = c.get('saved') or {}
    L = [f"git clone -q --shared {repo} {c['tree']}"]
    if s.get('bundle'):
        L.append(f"git -C {c['tree']} fetch -q {s['bundle']} {c['branch']}:{c['branch']}")
    if c.get('branch'):
        L.append(f"git -C {c['tree']} checkout -q {c['branch']} 2>/dev/null || git -C {c['tree']} checkout -q -b {c['branch']} {c['head']}")
    L.append(f"git -C {c['tree']} reset -q --hard {c['head']}")
    if s.get('patch'):
        L.append(f"git -C {c['tree']} apply --binary {s['patch']}")
    if s.get('untracked_tgz'):
        L.append(f"tar -xzf {s['untracked_tgz']} -C {c['tree']}")
    return L


# ───────────────────────────── pipeline ─────────────────────────────
def pipeline_state(repo=None, rows=None, detached=None):
    """the newest pipeline record: {run, stages: {stage: last status}, passed, failed, done, ok, alive, verdict,
    rerun}. alive = a fix_build_verify process is running (not its watchdog). Pure apart from reading the record."""
    repo = Path(repo or REPO)
    runs = sorted((repo / 'harness/loop/runs').glob('pipeline_*.jsonl'))
    if not runs:
        return {'run': None, 'verdict': 'none'}
    p = runs[-1]
    stages, done, ok, last = {}, False, None, None
    for l in p.read_text(errors='replace').splitlines():
        try:
            e = json.loads(l)
        except ValueError:
            continue
        last = e
        if e.get('stage') == 'done':
            done, ok = True, bool(e.get('ok'))
        elif e.get('stage') and e.get('status') not in ('START', 'INFO', 'BEGIN'):
            stages[e['stage']] = e['status']
    rows = RC.proc_rows() if rows is None else rows
    alive = [r['pid'] for r in rows if 'fix_build_verify.py' in r['cmd'] and 'stallwatch' not in r['cmd']
             and re.search(r'python', r['cmd'].split()[0] if r['cmd'].split() else '', re.I)]
    sw = next((j for j in (detached or []) if j.get('kind') == 'stallwatch' and 'fix_build_verify' in (j.get('match') or '')), None)
    rerun = None
    if sw:
        rerun = f"cd {sw.get('cwd') or repo} && nohup {sw.get('cmd_full') or sw['cmd']} >/dev/null 2>&1 &"
    else:
        rerun = f'cd {repo} && nice -n 15 python3 -I harness/pipeline/fix_build_verify.py --no-install (under kit/stallwatch.py)'
    verdict = ('PASS' if ok else 'FAIL') if done else ('RUNNING' if alive else 'DIED')
    return {'run': p.stem, 'stages': stages, 'passed': [k for k, v in stages.items() if v == 'PASS'],
            'failed': [k for k, v in stages.items() if v in ('FAIL', 'HUNG', 'REFUSED')], 'done': done, 'ok': ok,
            'alive_pids': alive, 'verdict': verdict, 'last_event': {k: last.get(k) for k in ('t', 'stage', 'status')} if last else None,
            'rerun': rerun, 'watchdog': {k: sw.get(k) for k in ('pid', 'log', 'done_file', 'cmd_file')} if sw else None}


# ───────────────────────────── keeper (detached loops) ─────────────────────────────
def running_matches(match, rows=None, exclude=()):
    rows = RC.proc_rows() if rows is None else rows
    return [r['pid'] for r in rows if match in r['cmd'] and r['pid'] not in exclude and 'round_pause.py keep' not in r['cmd']
            and not re.match(r'^(\S*/)?(grep|pgrep|ps)\b', r['cmd'])]


def keeper_pid(name, out=None, rows=None):
    """the pid of a live keeper for `name` (pidfile + process check), else None"""
    pf = Path(out or OUT) / f'keep_{name}.pid'
    try:
        pid = int(pf.read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return None
    rows = RC.proc_rows() if rows is None else rows
    return pid if any(r['pid'] == pid and f'round_pause.py keep {name}' in r['cmd'] for r in rows) else None


def launch_keeper(name, dry=False):
    """start the detached keeper for one loop unless one runs. Returns (action, pid). Idempotent."""
    k = keeper_pid(name)
    if k:
        return 'kept (a keeper already runs)', k
    if dry:
        return 'would start a detached keeper', None
    OUT.mkdir(parents=True, exist_ok=True)
    log = open(OUT / f'keep_{name}.log', 'ab')
    pr = subprocess.Popen([sys.executable, '-I', str(Path(__file__).resolve()), 'keep', name], stdin=subprocess.DEVNULL,
                          stdout=log, stderr=subprocess.STDOUT, start_new_session=True, close_fds=True, env=os.environ.copy())
    for _ in range(50):                    # the keeper writes its pidfile first thing
        if keeper_pid(name) == pr.pid:
            break
        time.sleep(0.1)
    return 'started a detached keeper (setsid; ppid 1 once this command exits)', pr.pid


def keep(name):
    """the keeper: one per loop (pidfile); stands by while any other copy of the loop runs (the session copy), runs the
    loop itself when none does, and restarts it after a crash (at most 6 per hour). SIGTERM stops it and its loop."""
    spec = loops().get(name)
    if not spec:
        print(f'keep: unknown loop {name!r} (known: {sorted(loops())})')
        return 2
    OUT.mkdir(parents=True, exist_ok=True)
    pf = OUT / f'keep_{name}.pid'
    other = keeper_pid(name)
    if other and other != os.getpid():
        print(f'keep {name}: a keeper already runs (pid {other}); exiting')
        return 0
    pf.write_text(f'{os.getpid()}\n')
    try:
        os.nice(15)
    except OSError:
        pass
    child = {'p': None}

    def stop(*_):
        if child['p'] and child['p'].poll() is None:
            child['p'].terminate()
        try:
            if pf.read_text().split()[0] == str(os.getpid()):
                pf.unlink()
        except (OSError, IndexError):
            pass
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    starts, said = [], None
    while True:
        mine = {child['p'].pid} if child['p'] and child['p'].poll() is None else set()
        others = running_matches(spec['match'], exclude=mine | {os.getpid()})
        if mine:
            pass
        elif others:
            if said != 'standby':
                print(f'{now_iso()} keep {name}: standby (another copy runs: pid {others})', flush=True)
                said = 'standby'
        else:
            starts = [t for t in starts if time.time() - t < 3600]
            if len(starts) >= 6:
                print(f'{now_iso()} keep {name}: 6 starts in the last hour; waiting', flush=True)
            else:
                logf = open(spec.get('log') or os.devnull, 'ab')
                child['p'] = subprocess.Popen(spec['cmd'], stdin=subprocess.DEVNULL, stdout=logf, stderr=subprocess.STDOUT)
                starts.append(time.time())
                print(f"{now_iso()} keep {name}: started pid {child['p'].pid}: {' '.join(map(str, spec['cmd']))}", flush=True)
                said = 'running'
        time.sleep(KEEP_POLL_S)


# ───────────────────────────── persist copy of round_checkpoint.py ─────────────────────────────
def persist_tool_state():
    repo_t, pers_t = REPO / 'harness/intel/round_checkpoint.py', PERSIST / 'round_checkpoint.py'
    a, b = sha256(repo_t), sha256(pers_t)
    return {'repo': str(repo_t), 'repo_sha256': a, 'persist': str(pers_t), 'persist_sha256': b, 'same': bool(a) and a == b}


BACKUP_FRESH_S = 900          # r30 B252e: the backup loop's own period (backup_scratch.sh --loop 900)


def backup_decision(last_backup, now, loop_running, fresh_s=BACKUP_FRESH_S):
    """r30 B252e: (run, why) for the pause's one scratch backup. The 2026-11-09 18:41 pause took 9.5 min wall, mostly
    the full rsync. Skip it only when LAST_BACKUP ('YYYY-MM-DD HH:MM:SS backup done', local time) is younger than
    fresh_s AND a backup loop (session copy or detached keeper) is running to take the next one; an unreadable or
    missing stamp, an old one, or no loop -> run it. Pure."""
    try:
        t = time.mktime(time.strptime(str(last_backup or '')[:19], '%Y-%m-%d %H:%M:%S'))
    except (ValueError, OverflowError):
        return True, 'LAST_BACKUP unreadable: run the backup'
    age = now - t
    if age < 0 or age >= fresh_s:
        return True, f'LAST_BACKUP {age:.0f} s old (>= {fresh_s} s or in the future): run the backup'
    if not loop_running:
        return True, f'LAST_BACKUP {age:.0f} s old but no backup loop runs: run the backup'
    return False, f'skipped: LAST_BACKUP {age:.0f} s old (< {fresh_s} s) and the backup loop runs'


def sync_persist_tool():
    """make ~/derohe-persist/round_checkpoint.py a verified copy of the repo tool (old copy kept once as .bak-<sha8>);
    the shas go to round_state/tools_sha.json."""
    st = persist_tool_state()
    if st['repo_sha256'] and not st['same']:
        pers = Path(st['persist'])
        if pers.exists() and st['persist_sha256']:
            bak = pers.with_name(f"round_checkpoint.py.bak-{st['persist_sha256'][:8]}")
            if not bak.exists():
                shutil.copy2(pers, bak)
        tmp = pers.with_name('.round_checkpoint.py.tmp')
        shutil.copy2(st['repo'], tmp)
        os.replace(tmp, pers)
        st = persist_tool_state()
    rec = dict(st, repo_head=git(REPO, 'rev-parse', '--short', 'HEAD')[1], stamp=now_iso())
    if st['same']:
        OUT.mkdir(parents=True, exist_ok=True)
        (OUT / 'tools_sha.json').write_text(json.dumps(rec, indent=1) + '\n')
    return rec



# ───────────────────────────── declared evidence files (DUE.json 'evidence') ─────────────────────────────
def _lines(path, cap=200 * 1024 * 1024):
    try:
        if Path(path).stat().st_size > cap:
            return None
        with open(path, 'rb') as f:
            return sum(1 for _ in f)
    except OSError:
        return None


def evidence_state(e, rows=None):
    """one declared evidence file now: {id, out, size, mtime, lines, pid, alive}. A pidfile names the detached job that
    grows it (alive = that pid runs); a file without one grows while its producer runs (e.g. the miner logs)."""
    rows = RC.proc_rows() if rows is None else rows
    size, mtime, mt = RC._stat(e.get('out'))
    pid = None
    if e.get('pidfile'):
        try:
            pid = int(Path(e['pidfile']).read_text().split()[0])
        except (OSError, ValueError, IndexError):
            pid = None
    return {'id': e.get('id'), 't': time.time(), 'out': e.get('out'), 'size': size, 'mtime': mtime, 'mtime_epoch': mt, 'lines': _lines(e['out']) if e.get('out') else None,
            'pid': pid, 'alive': (any(r['pid'] == pid for r in rows) if pid else None)}


def snap_times(path):
    out = []
    try:
        for l in Path(path).read_text(errors='replace').splitlines():
            try:
                d = json.loads(l)
            except ValueError:
                continue
            if isinstance(d.get('t'), (int, float)):
                out.append(d)
    except OSError:
        pass
    return sorted(out, key=lambda d: d['t'])


def snap_gaps(snaps, gap_s, since=None):
    """(holes, restart) of a 24 h snapshot series: holes = consecutive snapshots more than gap_s apart (the cadence rule:
    fewer b2 intervals, deltas still exact because derod and the miner keep counting), restart = the DR5 continuity of
    payout_24h_reads (a counter or the miner uptime fell: SEGMENTED, deltas across it are lower bounds). Pure."""
    s = [x for x in snaps if since is None or x['t'] >= since]
    holes = [{'from': a.get('iso'), 'to': b.get('iso'), 's': round(b['t'] - a['t'], 1)} for a, b in zip(s, s[1:]) if b['t'] - a['t'] > gap_s]
    try:
        cont = _load('p24_rp', HERE / 'payout_24h_reads.py').continuity(s)
    except (OSError, AttributeError, SyntaxError) as e:
        cont = {'class': f'unknown ({type(e).__name__})', 'gaps': []}
    return holes, cont


def merge_snaps(dst_lines, src_lines):
    """the time-ordered union of two snapshot files' lines, deduplicated by instant (t to the ms; the first copy wins);
    lines that are not snapshots are dropped. Pure."""
    seen, out = set(), []
    for l in list(dst_lines) + list(src_lines):
        try:
            d = json.loads(l)
        except ValueError:
            continue
        if not isinstance(d.get('t'), (int, float)):
            continue
        k = round(d['t'], 3)
        if k in seen:
            continue
        seen.add(k)
        out.append((d['t'], json.dumps(d, sort_keys=True)))
    return [l for _, l in sorted(out)]


def ingest_snaps(src, dst, dry=False):
    """merge src into dst by time with dedupe (atomic replace). Returns (n_before, n_src, n_after)."""
    a = Path(dst).read_text().splitlines() if Path(dst).exists() else []
    b = Path(src).read_text().splitlines()
    m = merge_snaps(a, b)
    if not dry:
        tmp = Path(dst).with_name(Path(dst).name + '.tmp')
        tmp.write_text(''.join(x + '\n' for x in m))
        os.replace(tmp, dst)
    return len(a), len(b), len(m)


def classify_evidence(then, e, now_state, pipeline_verdict):
    """(word, detail, plan) for one declared evidence file at resume. Pure."""
    grew = now_state['size'] is not None and then.get('size') is not None and now_state['size'] > then['size']
    dl = (now_state['lines'] or 0) - (then.get('lines') or 0) if now_state['lines'] is not None and then.get('lines') is not None else None
    detail = f"+{(now_state['size'] or 0) - (then.get('size') or 0)} B, +{dl} lines since the pause" if grew else 'no growth since the pause'
    plan = []
    if e.get('kind') == 'snaps':
        holes, cont = snap_gaps(snap_times(e['out']), float(e.get('gap_s') or 1800), e.get('window_since_epoch'))
        detail += f"; continuity {cont.get('class')} ({len(cont.get('gaps') or [])} restart gap(s)); {len(holes)} cadence hole(s) > {e.get('gap_s')} s"
        if cont.get('class') == 'SEGMENTED':
            plan.append(f"24 h read is SEGMENTED at {[g['from'] + '..' + g['to'] for g in cont['gaps']]}: deltas across it are lower bounds (DR5)")
        if holes:
            plan.append(f"cadence holes {[h['from'] + '..' + h['to'] for h in holes][:4]}: fewer b2 intervals; deltas stay exact (counters kept counting)")
        if e.get('ingest_to'):
            gate = 'NOW' if pipeline_verdict not in ('RUNNING',) else 'AFTER the in-flight pipeline ends'
            plan.append(f"ingest {gate}: `python3 -I harness/intel/round_pause.py ingest-snaps --src {e['out']} --dst {e['ingest_to']}` (merge by time, dedupe)")
    if e.get('pidfile'):
        if now_state['alive'] and grew:
            return 'LIVE', detail, plan
        if now_state['alive']:
            quiet = time.time() - max(then.get('t') or 0, now_state.get('mtime_epoch') or 0)
            if quiet < 2 * float(e.get('cadence_s') or QUIET_DEFAULT_S / 2):
                return 'ALIVE', detail + f'; quiet {quiet:.0f} s < 2 x its cadence', plan
            return 'ALIVE-NO-WORK', detail, plan + [f"its log {e.get('log')}"]
        return 'DIED', detail, plan + [f"the producer pid {now_state['pid']} is gone: restart only by the coordinator's decision: `{e.get('restart')}`; the window gets a gap from {now_state['mtime']}"]
    if not grew:
        quiet = time.time() - max(then.get('t') or 0, now_state.get('mtime_epoch') or 0)
        if quiet < 2 * float(e.get('cadence_s') or QUIET_DEFAULT_S / 2):
            return 'QUIET', detail + f'; quiet {quiet:.0f} s < 2 x its cadence', plan
    return ('GROWING' if grew else 'NOT-GROWING'), detail, plan + ([] if grew else [e.get('stalled_means') or 'its producer is not running'])


# ───────────────────────────── the agent checkpoint message ─────────────────────────────
def checkpoint_message(a, round_id, pause_id):
    """the exact text the coordinator sends (SendMessage) to one in-flight agent at a pause. Pure."""
    dim = a.get('dim') or '<your-dim>'
    hand = a.get('handoff') or f'<scratch>/{round_id}/{dim}/HANDOFF.md'
    return (f"CHECKPOINT NOW — pause {round_id} ({pause_id}). (1) Commit your work in progress on your branch in your clone "
            f"(a WIP commit is fine; never leave uncommitted edits). (2) Write {hand} last, in this form "
            f"(harness/kit/handoff.py): 'Agent: {a['id']}', 'Branch <branch> head <sha>', '## Done' (with anchors), "
            f"'## In flight' (or '- none'; name each detached job and the file it grows), '## Next' (the exact next "
            f"command in backticks). (3) Leave detached measurement jobs running; stop only your own non-detached "
            f"processes. (4) Check it: `python3 -I harness/kit/handoff.py check {hand}` must exit 0. (5) Hand back.")


# ───────────────────────────── pause ─────────────────────────────
def pause(round_id, dry=False, out=None):
    t0 = time.time()
    stamp = time.strftime('%Y%m%dT%H%M%S')
    pause_id = f'{round_id}-pause-{stamp}'
    out_dir = Path(out) if out else (None if dry else OUT)
    work = (out_dir / f'{round_id}_pause' / stamp) if out_dir else None
    snap = RC.snapshot()
    rows = RC.proc_rows()
    det, bound = snap['jobs']['detached'], snap['jobs']['session_bound']
    for j in det:
        j['cwd'] = RC.cwd_of(j['pid']) if j.get('kind') != 'user-daemon' else None
    _, rhead, _ = git(REPO, 'log', '-1', '--format=%h %s')
    _, rdirty, _ = git(REPO, 'status', '--porcelain')
    clones = []
    for tree in clone_trees(round_id):
        c = clone_state(tree)
        c['saved'] = save_clone(c, work / 'clones') if work and (c['dirty'] or c['untracked'] or not c['merged_in_repo']) else {}
        clones.append(c)
    ag = snap.get('agents') or []
    for a in ag:
        if a.get('handoff'):
            ok, probs, _ = HO.check(a['handoff'])
            a['handoff_check'] = 'ok' if ok else probs
    actions = []
    lp = loops()
    loop_alive = {}
    for name, spec in lp.items():
        present_bound = [j['pid'] for j in bound if spec['match'] in j['cmd']]
        present_det = [j['pid'] for j in det if spec['match'] in (j.get('cmd') or '')]
        act, kp = launch_keeper(name, dry=dry)
        loop_alive[name] = bool(present_bound or present_det or kp)
        actions.append({'loop': name, 'session_copy': present_bound, 'detached_copy': present_det, 'keeper': act, 'keeper_pid': kp,
                        'note': 'the keeper stands by while a session copy runs and takes over when the session ends'})
    if not dry:
        rec = RC.write(RC.snapshot())                            # one checkpoint now
        actions.append({'checkpoint': str(rec)})
        lbf = PERSIST / 'scratchpad' / 'LAST_BACKUP'
        lb = lbf.read_text().strip() if lbf.exists() else None
        go, why = backup_decision(lb, time.time(), loop_alive.get('backup'))     # r30 B252e
        if go:
            r = subprocess.run(['/bin/bash', str(PERSIST / 'backup_scratch.sh')], capture_output=True, text=True, timeout=3600)
            actions.append({'backup': f'exit {r.returncode}', 'why': why, 'last_backup': lbf.read_text().strip()
                            if lbf.exists() else None})
        else:
            actions.append({'backup': why, 'last_backup': lb})
        actions.append({'persist_tool': sync_persist_tool()})
    else:
        actions.append({'checkpoint': 'skipped (dry run)', 'backup': 'skipped (dry run)', 'persist_tool': persist_tool_state()})
    ev = [evidence_state(e, rows) for e in (snap.get('due') or {}).get('evidence') or []]
    for j in det:                              # a detached job that is a declared evidence producer: its file
        e = next((x for x in ev if x.get('pid') == j['pid']), None)
        if e and not j.get('out'):
            j.update(out=e['out'], size=e['size'], mtime=e['mtime'], evidence=e['id'])
    over, ready, up = RC.due_view(snap.get('due'))
    rec = {'schema': 'round_pause/1', 'mode': 'dry-run' if dry else 'pause', 'pause_id': pause_id, 'round': round_id,
           'stamp': now_iso(t0), 't': t0, 'repo': {'path': str(REPO), 'head': rhead, 'dirty': rdirty.splitlines()},
           'clones': clones, 'agents': ag, 'workflows': snap.get('workflows') or [],
           'detached': det, 'session_bound': bound, 'due': snap.get('due'),
           'due_view': {'overdue': [i.get('id') for i in over], 'ready': [i.get('id') for i in ready], 'upcoming': [i.get('id') for i in up]},
           'pipeline': pipeline_state(REPO, rows, det), 'steps': snap.get('steps'), 'actions': actions,
           'evidence': ev,
           'messages': {a['id']: checkpoint_message(a, round_id, pause_id) for a in ag if a['state'] != 'done'},
           'work_dir': str(work) if work else None}
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f'{round_id}_PAUSE.json').write_text(json.dumps(rec, indent=1, default=str) + '\n')
        if work:
            work.mkdir(parents=True, exist_ok=True)
            shutil.copy2(out_dir / f'{round_id}_PAUSE.json', work / 'PAUSE.json')
    return rec


def pause_report(rec):
    L = [f"PAUSE {rec['round']} [{rec['mode']}] {rec['stamp']} id {rec['pause_id']}",
         f"repo {rec['repo']['head']} ({len(rec['repo']['dirty'])} dirty)", '', 'clones:']
    for c in rec['clones']:
        s = c.get('saved') or {}
        L.append(f"  {c['dim']:<16} {c['branch'] or '-':<16} {(c['head'] or '')[:10]} dirty {len(c['dirty'])} untracked {len(c['untracked'])}"
                 f" {'in repo' if c['merged_in_repo'] else 'NOT in repo'}"
                 + (f" saved {', '.join(k for k in ('patch', 'untracked_tgz', 'bundle') if s.get(k))}" if s else ''))
    L += ['', 'agents:']
    for a in rec['agents']:
        if a['state'] == 'done':
            continue
        L.append(f"  {a['id']} {a['state']} idle {a['idle_s']} s dim {a.get('dim')} HANDOFF {a.get('handoff') or 'none'}"
                 + (f" check {a.get('handoff_check')}" if a.get('handoff') else ''))
    L.append(f"  ({sum(1 for a in rec['agents'] if a['state'] == 'done')} done agents not listed)")
    L += ['', 'detached jobs (survive the session; keep collecting):']
    for j in rec['detached']:
        L.append(f"  pid {j['pid']} {j['kind']}: out {j.get('out') or 'unknown'} {j.get('size')} B mtime {j.get('mtime')}"
                 + (f" end {j['end']}" if j.get('end') else '') + (f" counter {j.get('progress_value')}" if j.get('progress_value') else '')
                 + f"\n      cmd {j['cmd'][:150]}")
    L += ['', 'session-bound jobs (die with the session):']
    for j in rec['session_bound']:
        L.append(f"  pid {j['pid']} {j['kind']}: {j['cmd'][:150]}")
    L += ['', 'loops:']
    for a in rec['actions']:
        if 'loop' in a:
            L.append(f"  {a['loop']}: session copy {a['session_copy']} detached copy {a['detached_copy']} -> {a['keeper']}"
                     + (f" (pid {a['keeper_pid']})" if a.get('keeper_pid') else ''))
        else:
            L.append(f"  {json.dumps(a, default=str)[:300]}")
    L += ['', 'declared evidence (DUE.json evidence; grows while its producer runs):']
    for e in rec.get('evidence') or []:
        L.append(f"  {e['id']}: {e['out']} {e['size']} B {e['lines']} lines mtime {e['mtime']}" + (f" pid {e['pid']} alive {e['alive']}" if e.get('pid') else ''))
    dv = rec['due_view']
    L += ['', f"due: overdue {dv['overdue']} ready {dv['ready']} upcoming {dv['upcoming']}"]
    p = rec['pipeline']
    L += ['', f"pipeline {p.get('run')}: {p.get('verdict')} passed {p.get('passed')} failed {p.get('failed')} last {p.get('last_event')}"]
    st = next((s['step'] for s in rec['steps'] or [] if not s['done']), None)
    L += [f"first NOT-DONE §6 step: {st}", '', 'checkpoint messages (SendMessage each, then wait for the hand-backs):']
    for aid, m in rec['messages'].items():
        L.append(f'  -> {aid}: {m}')
    return '\n'.join(L)


# ───────────────────────────── resume ─────────────────────────────
def classify_job(j, rows, now, t_pause):
    """one detached job at resume: (word, detail, plan). LIVE = alive and its output grew (or its counter rose) since the
    pause; a dead job is FINISHED (done marker), ENDED (its end passed), or DIED with its restart and the lost window
    (two segments with the gap recorded: never merged silently). Pure apart from stat."""
    argv0 = (j.get('cmd') or '').split()[:1]
    alive = any(r['pid'] == j['pid'] and r['cmd'].split()[:1] == argv0 for r in rows)   # same pid, same program
    size, mtime, mt = RC._stat(j.get('out'))
    grew = size is not None and j.get('size') is not None and size > j['size']
    counter_now = None
    if j.get('progress'):
        try:
            counter_now = json.loads(Path(j['progress']).read_text())
        except (OSError, ValueError):
            counter_now = None
    rose = bool(counter_now) and bool(j.get('progress_value')) and any(
        isinstance(v, (int, float)) and isinstance(j['progress_value'].get(k), (int, float)) and v > j['progress_value'][k]
        for k, v in counter_now.items() if k not in ('pid', 'root', 'end_epoch'))
    end_t = None
    if j.get('end'):
        try:
            end_t = datetime.datetime.strptime(j['end'], '%Y-%m-%dT%H:%M:%S%z').timestamp()
        except ValueError:
            end_t = None
    done = bool(j.get('done_file')) and Path(j['done_file']).exists()
    if not done and not alive and not j.get('done_file'):   # a helper that ends with its job: a DONE beside its script
        near = [Path(w).parent / 'DONE' for w in re.findall(r'(/\S+\.(?:sh|py))', j.get('cmd') or '')]
        hit = next((x for x in near if x.exists()), None)
        if hit:
            j = dict(j, done_file=str(hit))
            done = True
    growth = f"+{size - j['size']} B" if size is not None and j.get('size') is not None else 'output unknown'
    if alive and j.get('kind') == 'keeper':          # a keeper has no output: standby or running its loop is its work
        return 'KEEPER', 'alive (standby behind the session copy, or running the loop)', 'no action'
    if alive:
        if grew or rose:
            return 'LIVE', f'{growth} since the pause' + (f', counter {counter_now}' if rose else ''), \
                'one window: the job kept collecting through the pause'
        quiet = now - max(t_pause, mt or 0)
        thr = j.get('stall_s') or QUIET_DEFAULT_S
        if quiet < thr:
            return 'ALIVE', f'{growth}; quiet {quiet:.0f} s < its stall window {thr:.0f} s', 'no action (within its cadence)'
        return 'ALIVE-NO-WORK', f'{growth}; no work for {quiet:.0f} s (stall window {thr:.0f} s)', \
            f"inspect its watchdog log {j.get('log')}; a stalled job is restarted by its stallwatch"
    if done:
        return 'FINISHED', f"done marker {j['done_file']}: {Path(j['done_file']).read_text().strip()[:40]}", 'read its result'
    if end_t and end_t <= now:
        return 'ENDED', f"planned end {j['end']} passed; output {growth}", 'run its stop/read step (DUE ledger)'
    if j.get('kind') == 'user-daemon':
        return 'NOT-RUNNING', 'the user daemon is not running', 'tell the user; never start, stop or restart it'
    last = mtime or 'unknown'
    restart = f"cd {j.get('cwd') or REPO} && nohup {j.get('cmd_full') or j['cmd']} >/dev/null 2>&1 &"
    return 'DIED', f'last output {last}', (f'restart: `{restart}` · window: segment 1 ends at {last}, gap {last} .. restart '
                                          f'recorded, segment 2 starts at the restart (lost window -> re-measure; never merged)')


def resume(round_id, dry=False, out=None, restore=False):
    src = Path(out) if out else OUT
    pf = src / f'{round_id}_PAUSE.json'
    try:
        rec = json.loads(pf.read_text())
    except (OSError, ValueError):
        return None
    now = time.time()
    rows = RC.proc_rows()
    det_now, bound_now = RC.jobs(rows, os.getpid(), [str(SCRATCH_ROOT), str(REPO), str(PERSIST)])
    plan, done_list = [], []
    # 1. loops
    loop_out = []
    for name, spec in loops().items():
        live = running_matches(spec['match'], rows)
        kp = keeper_pid(name, rows=rows)
        if live or kp:
            loop_out.append((name, 'RUNNING', f'pids {live} keeper {kp}'))
        else:
            act, pid = launch_keeper(name, dry=dry)
            loop_out.append((name, 'RESTARTED' if not dry else 'MISSING', f'{act} {pid or ""}'.strip()))
            plan.append(f"loop {name}: `python3 -I harness/intel/round_pause.py keep {name}` (detached keeper)")
    # 2. detached jobs
    jobs_out = []
    for j in rec.get('detached') or []:
        w, d, p = classify_job(j, rows, now, rec['t'])
        jobs_out.append({'pid': j['pid'], 'kind': j['kind'], 'out': j.get('out'), 'word': w, 'detail': d, 'plan': p})
        if w in ('DIED', 'ALIVE-NO-WORK', 'NOT-RUNNING', 'ENDED'):
            plan.append(f"job pid {j['pid']} ({j['kind']}) {w}: {p}")
        else:
            done_list.append(f"job pid {j['pid']} {w}")
    # 3. due actions
    led = RC.load_due(round_id, src if out else None)
    over, ready, up = RC.due_view(led, now)
    for i in over + ready:
        plan.append(f"due {i['id']} ({i.get('due') or 'after ' + ','.join(i.get('after') or [])}): {i.get('what')}"
                    + (f" · run `{i['cmd'] if isinstance(i.get('cmd'), str) else ' '.join(i.get('cmd') or [])}`" if i.get('cmd') else '')
                    + (f" · then tell the user: \"{i['then_tell_user']}\"" if i.get('then_tell_user') else ''))
    done_list += [f"due {i['id']} done" for i in (led or {}).get('items', []) if i.get('status') == 'done']
    ev_out = []
    pv = pipeline_state(REPO, rows, det_now).get('verdict')
    then_by = {e['id']: e for e in rec.get('evidence') or []}
    for e in (led or {}).get('evidence') or []:
        w, d, p = classify_evidence(then_by.get(e['id'], {}), e, evidence_state(e, rows), pv)
        ev_out.append({'id': e['id'], 'word': w, 'detail': d, 'plan': p})
        plan += [f"evidence {e['id']} {w}: {x}" for x in p]
        if w in ('LIVE', 'GROWING', 'ALIVE', 'QUIET') and not p:
            done_list.append(f"evidence {e['id']} {w} (one window)")
    # 4. clones
    clones_out = []
    for c in rec.get('clones') or []:
        t = Path(c['tree'])
        if (t / '.git').exists():
            _, h, _ = git(t, 'rev-parse', 'HEAD')
            if h == c['head']:
                clones_out.append((c['dim'], 'OK', h[:10]))
            else:
                n = git(t, 'rev-list', '--count', f"{c['head']}..{h}")[1] if c['head'] else '?'
                clones_out.append((c['dim'], 'MOVED', f"{(c['head'] or '')[:10]} -> {h[:10]} (+{n} commits since the pause)"))
        else:
            cmds = restore_cmds(c)
            if restore and not dry:
                ok = all(subprocess.run(x, shell=True, capture_output=True, timeout=1200).returncode == 0 for x in cmds)
                clones_out.append((c['dim'], 'RESTORED' if ok else 'RESTORE-FAILED', '; '.join(cmds)))
            else:
                clones_out.append((c['dim'], 'MISSING', '; '.join(cmds)))
                plan.append(f"clone {c['dim']} missing: re-create (resume --restore runs these): " + ' && '.join(cmds))
    # 5. pipeline
    pnow = pipeline_state(REPO, rows, det_now)
    pthen = rec.get('pipeline') or {}
    if pnow.get('verdict') == 'DIED':
        plan.append(f"pipeline {pnow['run']} DIED after {pnow.get('passed')} (last {pnow.get('last_event')}): re-run `{pnow.get('rerun')}`")
    elif pnow.get('verdict') == 'FAIL':
        plan.append(f"pipeline {pnow['run']} FAIL {pnow.get('failed')}: fix with a KAT + mutation, then re-run `{pnow.get('rerun')}`")
    elif pnow.get('verdict') == 'PASS':
        done_list.append(f"pipeline {pnow['run']} PASS (record it; never re-run a PASS)")
    # 6. agents
    agents_now = {a['id']: a for a in RC.agents(int(rec['t']) - 86400 * 3, round_id)}
    agents_out = []
    for a in rec.get('agents') or []:
        if a['state'] == 'done':
            continue
        n = agents_now.get(a['id'], a)
        if n.get('state') == 'done':
            agents_out.append((a['id'], 'HANDED-BACK', n.get('handoff')))
            done_list.append(f"agent {a['id']} handed back")
            continue
        hand = n.get('handoff') or a.get('handoff')
        chk = HO.check(hand)[1] if hand else ['no HANDOFF.md']
        agents_out.append((a['id'], 're-spawn', f"{hand or 'no HANDOFF.md'} ({'ok' if not chk else chk})"))
        src = hand or f"its transcript {a.get('transcript')} (no HANDOFF.md was written) and round_state/{round_id}_NOTES.md"
        plan.append(f"agent {a['id']} ({a.get('description')}): same session -> SendMessage it 'resume from {src}'; "
                    f"new session -> spawn a fresh agent with: 'Resume dim {a.get('dim')} from {src}: read it, verify its "
                    f"branch head, never redo its Done list, run its Next command.'")
    # 7. first NOT-DONE step (sticky, from the checkpoint state)
    steps = RC.previous_steps(round_id) or rec.get('steps') or []
    first = next((s['step'] for s in steps if not s.get('done')), None)
    done_list += [f"§6 {s['step']} DONE" + (' (re-verify)' if s.get('reverify') else '') for s in steps if s.get('done')]
    plan.append(f"§6: continue at the first NOT-DONE step: {first}")
    return {'round': round_id, 'mode': 'dry-run' if dry else 'resume', 'stamp': now_iso(now), 'pause_id': rec['pause_id'],
            'paused_at': rec['stamp'], 'paused_s': round(now - rec['t']), 'loops': loop_out, 'jobs': jobs_out, 'evidence': ev_out,
            'due': {'overdue': [i['id'] for i in over], 'ready': [i['id'] for i in ready], 'upcoming': [i['id'] for i in up]},
            'clones': clones_out, 'pipeline': {'then': {k: pthen.get(k) for k in ('run', 'verdict', 'passed')},
                                               'now': {k: pnow.get(k) for k in ('run', 'verdict', 'passed', 'failed', 'last_event', 'rerun')}},
            'agents': agents_out, 'first_not_done_step': first, 'plan': plan, 'done': done_list}


def resume_report(r):
    L = [f"RESUME {r['round']} [{r['mode']}] {r['stamp']} from {r['pause_id']} (paused {r['paused_at']}, {r['paused_s']} s ago)", '', 'loops:']
    L += [f'  {n}: {w} {d}' for n, w, d in r['loops']]
    L += ['', 'detached jobs (liveness = output growth since the pause):']
    L += [f"  pid {j['pid']} {j['kind']}: {j['word']} — {j['detail']} · {j['plan']}" for j in r['jobs']]
    L += ['', 'declared evidence:'] + [f"  {e['id']}: {e['word']} — {e['detail']}" for e in r.get('evidence') or []]
    L += ['', f"due: overdue {r['due']['overdue']} ready {r['due']['ready']} upcoming {r['due']['upcoming']}", '', 'clones:']
    L += [f'  {d}: {w} {x}' for d, w, x in r['clones']]
    p = r['pipeline']
    L += ['', f"pipeline at the pause {p['then']}; now {p['now']}", '', 'agents:']
    L += [f'  {a}: {w} {x}' for a, w, x in r['agents']] or ['  none in flight at the pause']
    L += ['', 'ORDERED RESUME PLAN (nothing DONE is redone):'] + [f'  {i}. {x}' for i, x in enumerate(r['plan'], 1)]
    L += ['', f"DONE (not redone): {len(r['done'])} items"] + [f'  - {x}' for x in r['done'][:40]]
    return '\n'.join(L)


# ───────────────────────────── check / due-done ─────────────────────────────
DUE_FIELDS = {'id': str, 'what': str, 'status': str}
DUE_STATUS = ('pending', 'done', 'skipped')


def check_due(ledger):
    """the problems of one DUE ledger (schema). Pure."""
    probs = []
    if not isinstance(ledger, dict) or not isinstance(ledger.get('items'), list):
        return ['not {"items": [...]}']
    ids = [i.get('id') for i in ledger['items'] if isinstance(i, dict)]
    for i in ledger['items']:
        if not isinstance(i, dict):
            probs.append(f'an item is not an object: {i!r}'[:120])
            continue
        for k, t in DUE_FIELDS.items():
            if not isinstance(i.get(k), t):
                probs.append(f"{i.get('id')}: field {k} missing or not {t.__name__}")
        if i.get('status') not in DUE_STATUS:
            probs.append(f"{i.get('id')}: status {i.get('status')!r} not in {DUE_STATUS}")
        if i.get('due') and RC.due_epoch(i) is None:
            probs.append(f"{i.get('id')}: due {i.get('due')!r} is not an ISO time with its zone")
        if i.get('due') and not re.search(r'[+-]\d\d:?\d\d$|Z$', str(i['due'])):
            probs.append(f"{i.get('id')}: due {i.get('due')!r} has no zone offset")
        if not i.get('due') and not i.get('after') and not i.get('when'):
            probs.append(f"{i.get('id')}: neither a due time, an 'after' list nor a 'when' condition")
        for a in i.get('after') or []:
            if a not in ids:
                probs.append(f"{i.get('id')}: after names unknown item {a!r}")
        if i.get('status') == 'done' and not i.get('evidence'):
            probs.append(f"{i.get('id')}: done without evidence")
    if len(set(ids)) != len(ids):
        probs.append('duplicate item ids')
    for e in ledger.get('evidence') or []:
        if not isinstance(e, dict) or not e.get('id') or not e.get('out'):
            probs.append(f'evidence entry without id/out: {e!r}'[:120])
        elif e.get('kind') == 'snaps' and not e.get('gap_s'):
            probs.append(f"evidence {e['id']}: kind snaps without its gap rule gap_s")
    return probs


def check(round_id, out=None):
    led = RC.load_due(round_id, out)
    probs = check_due(led) if led is not None else []
    hand = []
    for h in sorted(Path(SCRATCH_ROOT).glob(f'*/scratchpad/{round_id}/*/HANDOFF.md')):
        ok, pr, _ = HO.check(h)
        hand.append((str(h), ok, pr))
    return probs, hand, led is not None


def due_done(round_id, item_id, evidence, out=None):
    p = Path(out or OUT) / f'{round_id}_DUE.json'
    led = json.loads(p.read_text())
    hit = [i for i in led['items'] if i.get('id') == item_id]
    if not hit or not evidence:
        return False
    hit[0].update(status='done', done_at=now_iso(), evidence=evidence)
    tmp = p.with_name(p.name + '.tmp')
    tmp.write_text(json.dumps(led, indent=1) + '\n')
    os.replace(tmp, p)
    return True


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(prog='round_pause.py')
    ap.add_argument('cmd', choices=['pause', 'resume', 'status', 'check', 'due-done', 'keep', 'ingest-snaps'])
    ap.add_argument('--src')
    ap.add_argument('--dst')
    ap.add_argument('arg', nargs='?')
    ap.add_argument('--round')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--out')
    ap.add_argument('--restore', action='store_true')
    ap.add_argument('--evidence')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args(argv)
    if a.cmd == 'keep':
        return keep(a.arg)
    rid = a.round or RC.registry()[0]
    if a.cmd == 'pause':
        rec = pause(rid, a.dry_run, a.out)
        print(json.dumps(rec, indent=1, default=str) if a.json else pause_report(rec))
        return 0
    if a.cmd == 'resume':
        r = resume(rid, a.dry_run, a.out, a.restore)
        if r is None:
            print(f'resume: no {rid}_PAUSE.json in {a.out or OUT}')
            return 2
        print(json.dumps(r, indent=1, default=str) if a.json else resume_report(r))
        return 0
    if a.cmd == 'status':
        rec = pause(rid, True, None)
        print(pause_report(rec))
        r = resume(rid, True, a.out, False)
        print('\n' + (resume_report(r) if r else f'(no {rid}_PAUSE.json: nothing to compare)'))
        return 0
    if a.cmd == 'check':
        probs, hand, have = check(rid, a.out)
        print(f"DUE {rid}: {'absent' if not have else ('ok' if not probs else 'PROBLEM')}" + ''.join(f'\n  - {x}' for x in probs))
        for h, ok, pr in hand:
            print(f"HANDOFF {'ok  ' if ok else 'WARN'} {h}" + ''.join(f'\n  - {x}' for x in pr))
        return 4 if probs else 0
    if a.cmd == 'ingest-snaps':
        if not a.src or not a.dst:
            print('ingest-snaps needs --src and --dst')
            return 2
        pv = pipeline_state(REPO).get('verdict')
        if pv == 'RUNNING' and not a.dry_run:
            print(f'ingest-snaps: a pipeline is RUNNING ({pipeline_state(REPO)["run"]}): refused until it ends (the snaps file is tracked)')
            return 3
        b, n, after = ingest_snaps(a.src, a.dst, a.dry_run)
        print(f"ingest-snaps{' (dry run)' if a.dry_run else ''}: {a.dst} {b} + {a.src} {n} -> {after} snapshots (by time, deduplicated)")
        return 0
    if a.cmd == 'due-done':
        ok = due_done(rid, a.arg, a.evidence, a.out)
        print(f"due {a.arg}: {'marked done' if ok else 'not found, or no --evidence'}")
        return 0 if ok else 2
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
