#!/usr/bin/env python3
"""round_checkpoint.py — snapshot what a DERO round has done, what is in flight and what is pending, so a session that
stops (token run-out, crash, closed terminal) can be resumed from the exact point. dero-rft.md §2.13 / §0.10.

Reads only live sources (never memory of the conversation): harness/round.json, git log since the round base, the
workflow journals of the session (started vs result per agent label), the round's scratch dirs (patches, verify.md),
the pipeline records, bin/derod --version, the running derod, the GitHub copy. Writes:
  ~/derohe-persist/round_state/<round>_state.json   machine-readable state
  ~/derohe-persist/round_state/<round>_RESUME.md    human / next-session resume brief (the exact commands)
  ~/derohe-persist/round_state/history/<stamp>_*    one copy per run (pruned to the last 200)
Usage: round_checkpoint.py [--loop SECONDS]   (nice it; read-only except its own output dir)

r25 (§2.13): this file (harness/intel/round_checkpoint.py) is the source of truth; ~/derohe-persist/round_checkpoint.py
execs it when the repo copy exists (and keeps its own last copy as the fallback). KAT: harness/kat/test_round_checkpoint_r25.py
(RC1 a planted in-flight agent is listed in-flight; RC2 a DONE step is never re-listed as pending: done is sticky across
runs and a step whose live probe now fails is shown 'done, re-verify'; RC3 history is pruned to HISTORY_KEEP; RC4 only a
'R<id>: ... merge' subject is the merge commit; RC5 a <round>_NOTES.md in OUT is appended to the brief). Paths are overridable for the KAT: ROUND_CKPT_REPO, ROUND_CKPT_OUT,
ROUND_CKPT_PROJ, ROUND_CKPT_SCRATCH, ROUND_CKPT_PUB.

r30 (B252, §2.22 pause/resume): the brief and the state also carry what a stopped session loses besides workflows:
  agents    every Agent-tool subagent transcript of the round (<proj>/<session>/subagents/agent-*.jsonl, newer than the
            round base): done (its last turn is a SubagentHandback or a plain end_turn) / in-flight (active within
            AGENT_STALE_S) / stalled (no activity since, never handed back), its last activity, its dim (the first
            scratchpad/<round>/<dim>/ its prompt names) and that dim's HANDOFF.md (RC7)
  jobs      the round's OS jobs: detached (outside the session tree: they survive the session; with the file each one
            grows, its size and mtime, and its end when its plan says) and session-bound (background Bash jobs of the
            Claude session: they die with it; round_pause.py pause re-launches the two loops among them detached) (RC8)
  due       the timed due-actions ledger round_state/<round>_DUE.json: overdue first, in due order (RC8)
KAT RC7 / RC8 in harness/kat/test_round_checkpoint_r25.py; the pause/resume tool is harness/intel/round_pause.py
(ROUND_CKPT_PERSIST overrides the persist dir for the KAT).
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):   # r27 B120: usage, exit 0, nothing run or written
    print(__doc__ or 'usage: see the header of this file')
    raise SystemExit(0)
import json, os, re, subprocess, sys, time, glob, shutil
from pathlib import Path

HOME = Path.home()
_HERE = Path(__file__).resolve()
_REPO_DEFAULT = _HERE.parents[2] if _HERE.parent.name == 'intel' and _HERE.parents[1].name == 'harness' \
    and '/scratchpad/' not in str(_HERE) else HOME / 'derohe-Release151'   # r30 B252: a scratch clone reads the live repo
REPO = Path(os.environ.get('ROUND_CKPT_REPO') or _REPO_DEFAULT)
PUB = Path(os.environ.get('ROUND_CKPT_PUB') or HOME / 'public-copy')
OUT = Path(os.environ.get('ROUND_CKPT_OUT') or HOME / 'derohe-persist' / 'round_state')
PROJ = Path(os.environ.get('ROUND_CKPT_PROJ') or HOME / '.claude' / 'projects' / 'project')
SCRATCH_ROOT = Path(os.environ.get('ROUND_CKPT_SCRATCH') or '<scratch>')
HISTORY_KEEP = 200
PERSIST = Path(os.environ.get('ROUND_CKPT_PERSIST') or HOME / 'derohe-persist')
AGENT_STALE_S = 1800           # r30 B252: an agent transcript idle this long and never handed back is 'stalled'
TAIL_BYTES = 400_000           # r30: the tail of a transcript read for its last turn (transcripts reach ~5 MB)

# the §6 end-of-round order (dero-rft.md §6 parts A-E), with a probe that decides done / not done from live sources
STEPS = [
    ('A1 round opened in registry', lambda s: s['registry'].get('status') in ('in-progress', 'implemented', 'shipped', 'measured')),
    ('B  open-loop workflows finished', lambda s: s['workflows'] and all(w['done'] >= w['started'] > 0 for w in s['workflows'])),
    ('C  merge commit "R<id>:" on local-enhancements', lambda s: bool(s['merge_commits'])),
    ('C  full pipeline PASS after the merge', lambda s: s['last_full_pipeline_pass_after_merge']),
    ('C  installed: bin/derod reports the round suffix', lambda s: s['installed']),
    ('D  ledger dero-r1-r<id>.html exists', lambda s: s['ledger_exists']),
    ('D  registry status implemented', lambda s: s['registry'].get('status') in ('implemented', 'shipped', 'measured')),
    # r25: 'after the docs' = the ledger page exists (a project-only PASS before the docs is not this step; sticky DONE
    # would otherwise freeze an early PASS)
    ('D  project-only pipeline PASS after the docs', lambda s: s['ledger_exists'] and s['last_project_pass']),
    ('D  user notified to restart derod (see RESUME notes)', lambda s: s['derod_running_suffix'] == s['suffix']),
    ('E  live measurement read (registry measured)', lambda s: s['registry'].get('status') == 'measured'),
    ('E  GitHub copy synced to the measured head', lambda s: s['github_synced']),
]


def select_derod(rows, repo, cwd_of):
    """r28 (tools-kats, N28-05): the pid (str) of the running derod, or '' when there is none or it is ambiguous.
    rows = [(pid, ucomm)] from `ps -axo pid=,ucomm=`: only a process whose accounting name is EXACTLY 'derod' is a
    candidate, so a shell, a `tail -f derod.log` or a wait loop that merely carries 'bin/derod --data-dir' in its
    command line can never be picked (the old `pgrep -f '^./bin/derod|bin/derod --data-dir' | head -1` matched full
    command lines, rft §5 asks for pid-based waits). Two or more derods (the S5 shadow beside the user's node): the
    one whose working directory is `repo` (cwd_of(pid) -> path or None); still ambiguous -> ''. Pure apart from
    cwd_of."""
    cands = sorted({str(p).strip() for p, c in rows if str(c).strip() == 'derod' and str(p).strip().isdigit()}, key=int)
    if len(cands) <= 1:
        return cands[0] if cands else ''
    want = os.path.realpath(str(repo))
    mine = [p for p in cands if (cwd_of(p) or '') and os.path.realpath(cwd_of(p)) == want]
    return mine[0] if len(mine) == 1 else ''


def ps_rows():
    """[(pid, ucomm)] of every process (read-only `ps`); [] when ps fails"""
    out = sh(['ps', '-axo', 'pid=,ucomm='])
    if out.startswith('ERR'):
        return []
    return [tuple(l.split(None, 1)) for l in out.splitlines() if len(l.split(None, 1)) == 2]


def cwd_of(pid):
    """the working directory of pid from `lsof -a -p PID -d cwd -Fn` (read-only), or None"""
    out = sh(['lsof', '-a', '-p', str(pid), '-d', 'cwd', '-Fn'])
    return next((l[1:] for l in out.splitlines() if l.startswith('n/')), None)


def derod_run_suffix(logdir):
    """r30 (B254a, the B254 class): the build suffix of the running derod from its newest start-up "Version" line. derod
    writes that line once per start, and lumberjack rotates derod.log at 100 MB into derod-<UTC>.log, so after a rotation
    the live file has none (2026-11-11 RESUME brief: 'running derod pid 15915 on `?`'; the r29 line sat in
    derod-2026-11-09T21-17-18.376.log). Reads derod.log, then the backups newest first, and returns the suffix of the
    LAST Version line of the first file that has one; '' when none does."""
    d = Path(logdir)
    live = d / 'derod.log'
    try:
        backups = sorted((f for f in d.glob('derod-*.log') if f.is_file()), reverse=True)
    except OSError:
        backups = []
    for f in ([live] if live.exists() else []) + backups:
        last = None
        try:
            with f.open(errors='replace') as fh:
                for line in fh:
                    if '"Version"' in line:
                        last = line
        except OSError:
            continue
        if last:
            m = re.search(r'STARGATE\+([\w.]+)', last)
            if m:
                return m.group(1)
    return ''


def sh(cmd, cwd=None, timeout=60):
    try:
        return subprocess.run(cmd, cwd=cwd, shell=isinstance(cmd, str), capture_output=True, text=True,
                              timeout=timeout).stdout.strip()
    except Exception as e:  # a missing tool must not stop the checkpoint
        return f'ERR {e}'


def registry():
    d = json.loads((REPO / 'harness/round.json').read_text())
    cur = d.get('current')
    r = next((x for x in d['rounds'] if x['id'] == cur), {})
    return cur, r, d


def workflows(since_ts, proj=None):
    """every workflow journal of the project newer than since_ts: per agent 'in-flight' (started, no result) or 'done'
    (with its summary). Pure on the files under proj (KAT RC1)."""
    proj = PROJ if proj is None else Path(proj)
    out = []
    for jd in sorted(proj.glob('*/subagents/workflows/wf_*')):
        j = jd / 'journal.jsonl'
        if not j.exists() or j.stat().st_mtime < since_ts:
            continue
        started, done, labels = 0, 0, {}
        for line in j.read_text().splitlines():
            try:
                x = json.loads(line)
            except ValueError:
                continue
            if x.get('type') == 'started':
                started += 1
                labels[x.get('key')] = {'label': x.get('label'), 'state': 'in-flight'}
            elif x.get('type') == 'result':
                done += 1
                k = x.get('key')
                labels.setdefault(k, {'label': '?'})['state'] = 'done'
                res = x.get('result') or {}
                if isinstance(res, dict):
                    labels[k]['summary'] = ' '.join(str(res.get('summary') or res.get('verdict') or '').split())[:300]
        script = next(iter(sorted(proj.glob(f'*/workflows/scripts/*-{jd.name}.js'))), None)
        out.append({'run_id': jd.name, 'started': started, 'done': done, 'script': str(script) if script else None,
                    'agents': list(labels.values()), 'journal': str(j)})
    return out


def merge_commits(log, tag):
    """the round's merge commits among 'hash subject' lines: subject 'R<id>: ...' (or 'R<id> ...') that names a merge.
    r25: any 'R25:' subject used to count, so the rft-only commit a888afd marked step C done before any merge. Pure (RC4)."""
    return [l for l in log if re.match(rf'^\w+ {re.escape(tag)}\b:?.*\bmerge\b', l, re.I)]


def run_result(txt):
    """(full, passed) of one pipeline record (harness/loop/runs/pipeline_*.jsonl). full = it ran the shadow (S5), so a
    --no-install full run counts; passed = its 'done' event says ok true. r25: passed used to look for a 'run' PASS
    event or a 'verdict' that the pipeline never writes, so no run ever counted as PASS (step C stayed NOT DONE after
    pipeline_20261103T182557 PASS). Pure (RC6)."""
    full = bool(re.search(r'"stage":\s*"(shadow|install)"', txt))
    done = [l for l in txt.splitlines() if re.search(r'"stage":\s*"done"', l)]
    return full, bool(done) and bool(re.search(r'"ok":\s*true', done[-1]))


def sticky_steps(probed, prev):
    """the step list of this run: a step DONE in the previous state stays DONE (§0.10: never redo a DONE step); when its
    live probe now fails it is marked 'reverify' (re-verify it; lesson #69), never re-listed as pending. Pure (RC2)."""
    was = {p.get('step') for p in (prev or []) if p.get('done')}
    out = []
    for st in probed:
        s = dict(st)
        if not s['done'] and s['step'] in was:
            s['done'], s['reverify'] = True, True
        out.append(s)
    return out


def prune_history(h, keep=HISTORY_KEEP):
    """keep the newest `keep` history copies (names start with the sortable stamp). Returns the number removed (RC3)."""
    old = sorted(p for p in Path(h).glob('*') if p.is_file())[:-keep] if keep > 0 else []
    for p in old:
        p.unlink()
    return len(old)


def previous_steps(round_id, out=None):
    try:
        return json.loads((Path(out or OUT) / f'{round_id}_state.json').read_text()).get('steps') or []
    except (OSError, ValueError):
        return []


# ───────────────────────────── r30 B252: agents, OS jobs, due-actions ─────────────────────────────
def _records(path, head=False, nbytes=TAIL_BYTES):
    """the JSON records of the first (head) or last nbytes of a transcript; a cut first line is dropped. Pure on files."""
    with open(path, 'rb') as f:
        if not head:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - nbytes))
        raw = f.read(nbytes).decode('utf-8', 'replace').splitlines()
    if not head and len(raw) > 1:
        raw = raw[1:]
    out = []
    for l in raw:
        try:
            out.append(json.loads(l))
        except ValueError:
            continue
    return out


def _text_of(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return ' '.join(c.get('text', '') for c in content if isinstance(c, dict) and c.get('type') == 'text')
    return ''


def agent_state(recs):
    """'done' | 'open' from the tail records of one transcript: done when its last assistant turn is a SubagentHandback
    tool call, or a plain text end_turn with no new prompt after it. Pure (RC7)."""
    last_i = None
    for i, r in enumerate(recs):
        m = r.get('message')
        if isinstance(m, dict) and m.get('role') == 'assistant':
            last_i = i
    if last_i is None:
        return 'open'
    m = recs[last_i]['message']
    blocks = [c for c in (m.get('content') or []) if isinstance(c, dict)]
    if any(c.get('type') == 'tool_use' and c.get('name') == 'SubagentHandback' for c in blocks):
        return 'done'
    if m.get('stop_reason') == 'end_turn' and not any(c.get('type') == 'tool_use' for c in blocks):
        later = [r for r in recs[last_i + 1:] if r.get('type') == 'user'
                 and _text_of((r.get('message') or {}).get('content'))]
        return 'open' if later else 'done'
    return 'open'


def agents(since_ts, round_id, proj=None, scratch_root=None, now=None, stale_s=AGENT_STALE_S):
    """every Agent-tool subagent transcript of the project newer than since_ts: {id, description, state (done /
    in-flight / stalled), last_activity, idle_s, dim, handoff (path or None)}. Pure on the files (RC7)."""
    proj = PROJ if proj is None else Path(proj)
    scratch_root = SCRATCH_ROOT if scratch_root is None else Path(scratch_root)
    now = time.time() if now is None else now
    dim_rx = re.compile(rf'(?:scratchpad|SCRATCH|<scratch>)/{re.escape(round_id)}/([A-Za-z0-9_.-]+)/')
    by_id = {}                                   # a HANDOFF.md that names its agent ('Agent: <id>') wins
    for h in sorted(scratch_root.glob(f'*/scratchpad/{round_id}/*/HANDOFF.md')):
        try:
            for m in re.finditer(r'(?im)^\W*agent\W+(a[0-9a-f]{8,})', h.read_text(errors='replace')):
                by_id[m.group(1)] = h
        except OSError:
            continue
    out = []
    for f in sorted(proj.glob('*/subagents/agent-*.jsonl')):
        try:
            mt = f.stat().st_mtime
        except OSError:
            continue
        if mt < since_ts:
            continue
        aid = f.stem[len('agent-'):]
        meta = f.with_name(f'agent-{aid}.meta.json')
        desc = ''
        try:
            desc = json.loads(meta.read_text()).get('description') or ''
        except (OSError, ValueError):
            pass
        first = next((r for r in _records(f, head=True, nbytes=200_000) if r.get('type') == 'user'), {})
        prompt = _text_of((first.get('message') or {}).get('content'))
        dims = [d for d in dim_rx.findall(prompt) if any(scratch_root.glob(f'*/scratchpad/{round_id}/{d}'))]
        named = re.findall(rf'/{re.escape(round_id)}/([A-Za-z0-9_.-]+)/HANDOFF\.md', prompt)
        trees = re.findall(rf'/{re.escape(round_id)}/([A-Za-z0-9_.-]+)/tree\b', prompt)
        hand = by_id.get(aid)
        if hand is not None:
            dim = hand.parent.name
        else:
            dim = next((d for d in named + trees + dims if d in dims), None)
            hand = next(iter(sorted(scratch_root.glob(f'*/scratchpad/{round_id}/{dim}/HANDOFF.md'))), None) if dim else None
        st = agent_state(_records(f))
        state = 'done' if st == 'done' else ('in-flight' if now - mt < stale_s else 'stalled')
        out.append({'id': aid, 'description': desc, 'state': state,
                    'last_activity': time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime(mt)),
                    'idle_s': round(now - mt), 'dim': dim, 'handoff': str(hand) if hand else None, 'transcript': str(f)})
    return sorted(out, key=lambda a: a['last_activity'])


def proc_rows():
    """[{pid, ppid, start, cmd}] of every process (read-only `ps`); [] when ps fails"""
    out = sh(['ps', '-axww', '-o', 'pid=,ppid=,lstart=,command='])
    rows = []
    for l in ([] if out.startswith('ERR') else out.splitlines()):
        t = l.split()
        if len(t) >= 8 and t[0].isdigit() and t[1].isdigit():
            rows.append({'pid': int(t[0]), 'ppid': int(t[1]), 'start': ' '.join(t[2:7]), 'cmd': ' '.join(t[7:])})
    return rows


LOOP_KINDS = (('checkpoint-loop', 'round_checkpoint.py --loop'), ('backup-loop', 'backup_scratch.sh --loop'),
              ('keeper', 'round_pause.py keep'))
SNAP_MARK = 'shell-snapshots/snapshot-'   # a Claude Code background Bash job: `bash -c source <snapshot> ... eval '<cmd>'`
STALLWATCH_RX = re.compile(r'--(work|done|progress|cmd-file|log|match|stall-s)\s+(\S+)')


MASK_RX = ((re.compile(r'\b(dero|deto)1[0-9a-z]{20,}'), r'\1…(masked)'),
           (re.compile(r'(?<![\d.])(?!127\.0\.0\.1)(?:\d{1,3}\.){3}\d{1,3}(?![\d.])'), '<ip>'))
USER_DAEMONS = {'derod': 'dero-data/logs/derod.log', 'dero-miner': None}   # observe only: never signalled by any tool


def mask(cmd):
    """a command line with wallet addresses and non-loopback IPv4 addresses masked (rft §0.6 privacy). Pure."""
    for rx, to in MASK_RX:
        cmd = rx.sub(to, cmd)
    return cmd


def bash_payload(cmd):
    """the user command inside a Claude Code background Bash wrapper (the eval '...' text), else cmd. Pure."""
    m = re.search(r"eval '(.*)' < /dev/null", cmd, re.S)
    return m.group(1).replace("'\"'\"'", "'") if m else cmd


def job_kind(cmd):
    for k, pat in LOOP_KINDS:
        if pat in cmd:
            return k
    if 'kit/stallwatch.py' in cmd:
        return 'stallwatch'
    return 'job'


def _stat(path):
    try:
        st = os.stat(path)
        return st.st_size, time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime(st.st_mtime)), st.st_mtime
    except (OSError, TypeError):
        return None, None, None


def jobs(rows, me, marks):
    """(detached, session_bound) of the round's OS jobs. rows = proc_rows(); me = this process's pid; marks = strings
    of which one in a command line makes a process the round's (scratch root, repo, persist dir). Detached = not under
    the Claude session (it survives the session): stallwatch'd jobs with --work (the file it grows), --done, --cmd-file
    (its restart command) and the plan's end; other matching jobs; `tail` readers and sleeps are ignored.
    Session-bound = the background Bash jobs of the session that runs `me` (they die with it). Pure apart from stat (RC8)."""
    by = {r['pid']: r for r in rows}

    def anc(pid):
        seen, out = set(), []
        while pid in by and pid not in seen and pid > 1:
            seen.add(pid)
            pid = by[pid]['ppid']
            out.append(pid)
        return out
    my_anc = [me] + anc(me)
    sess = next((p for p in my_anc if p in by and re.match(r'^(\S*/)?claude(\s|$)', by[p]['cmd'])), None)
    kids = {}
    for r in rows:
        kids.setdefault(r['ppid'], []).append(r['pid'])

    def desc(pid):
        out, st = [], list(kids.get(pid, []))
        while st:
            x = st.pop()
            out.append(x)
            st += kids.get(x, [])
        return out
    bound, detached, covered = [], [], set(my_anc)
    if sess:
        for pid in kids.get(sess, []):
            r = by[pid]
            if SNAP_MARK not in r['cmd'] or pid in covered:
                continue
            ds = desc(pid)
            covered.update(ds + [pid])
            leaf = next((by[d] for d in ds if not re.match(r'^(/bin/)?sleep\b', by[d]['cmd'])), None)
            payload = bash_payload(r['cmd'])
            bound.append({'pid': pid, 'leaf_pid': leaf['pid'] if leaf else None, 'kind': job_kind(payload),
                          'cmd': mask(payload)[:600], 'start': r['start']})
    for r in rows:
        pid, cmd = r['pid'], r['cmd']
        exe = os.path.basename(cmd.split()[0]) if cmd.split() else ''
        if pid in covered or (sess and sess in anc(pid)) or not (exe in USER_DAEMONS or any(m and m in cmd for m in marks)):
            continue
        if re.match(r'^(\S*/)?(tail|sleep|grep|ps|lsof)\b', cmd) or SNAP_MARK in cmd:
            continue
        kind = 'user-daemon' if exe in USER_DAEMONS else job_kind(cmd)
        j = {'pid': pid, 'ppid': r['ppid'], 'kind': kind, 'cmd': mask(cmd)[:600], 'start': r['start'],
             'cmd_full': mask(cmd) if kind != 'user-daemon' else None}
        if kind == 'user-daemon':           # observe only (rft §5): its log's size and mtime, never a signal
            log = HOME / USER_DAEMONS[exe] if USER_DAEMONS[exe] else next(
                (REPO / l for l in ('bin/dero-miner.launchd.log', 'bin/dero-miner.log') if (REPO / l).exists()), None)
            j['out'] = str(log) if log else None
        elif kind == 'stallwatch':
            a = dict(STALLWATCH_RX.findall(cmd))
            j.update({'out': a.get('work'), 'done_file': a.get('done'), 'progress': a.get('progress'),
                      'cmd_file': a.get('cmd-file'), 'log': a.get('log'), 'match': a.get('match'),
                      'stall_s': float(a['stall-s']) if str(a.get('stall-s', '')).replace('.', '', 1).isdigit() else None})
            j['children'] = desc(pid)
            plan = Path(a['work']).parent / 'plan.json' if a.get('work') else None
            try:
                end = json.loads(plan.read_text()).get('end_epoch') if plan else None
                j['end'] = time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime(float(end))) if end else None
            except (OSError, ValueError, TypeError):
                j['end'] = None
            if a.get('done'):
                j['done'] = Path(a['done']).exists()
            try:                                   # the work counter the watchdog judges (e.g. {"cpu_s": 6} / samples)
                j['progress_value'] = json.loads(Path(a['progress']).read_text()) if a.get('progress') else None
            except (OSError, ValueError):
                j['progress_value'] = None
        else:
            j['out'] = next((w for w in re.findall(r'(/\S+\.(?:log|jsonl|json|txt|out))', cmd) if Path(w).exists()), None)
        j['size'], j['mtime'], _ = _stat(j.get('out'))
        covered.update(desc(pid))
        detached.append(j)
    return detached, bound


def load_due(round_id, out=None):
    """the round's due-actions ledger round_state/<round>_DUE.json ({'items': [...]}) or None when absent"""
    p = Path(out or OUT) / f'{round_id}_DUE.json'
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return None


def due_epoch(item):
    d = item.get('due')
    if not d:
        return None
    try:
        import datetime as _dt
        return _dt.datetime.fromisoformat(str(d)).timestamp()
    except ValueError:
        return None


def due_view(ledger, now=None):
    """(overdue, ready, upcoming) open items of a DUE ledger: overdue = timed and past due, in due order; ready = untimed
    whose 'after' items are all done; upcoming = the rest, in due order. done / skipped items are never listed. Pure (RC8)."""
    now = time.time() if now is None else now
    items = list((ledger or {}).get('items') or [])
    done = {i.get('id') for i in items if i.get('status') in ('done', 'skipped')}
    open_ = [i for i in items if i.get('status') not in ('done', 'skipped')]
    over = sorted([i for i in open_ if due_epoch(i) is not None and due_epoch(i) <= now], key=due_epoch)
    ready = [i for i in open_ if due_epoch(i) is None and not i.get('when') and all(a in done for a in i.get('after') or [])]
    # r30: an item gated by a 'when' event is never 'ready' by itself: it waits (upcoming) until it is marked done
    up = sorted([i for i in open_ if i not in over and i not in ready],
                key=lambda i: (due_epoch(i) is None, due_epoch(i) or 0))
    return over, ready, up


def snapshot():
    cur, r, d = registry()
    base = r.get('new_tests_base') or 'HEAD~1'
    suffix = r.get('version_suffix') if r.get('version_suffix') not in (None, 'pending') else f'22102026.{cur}'
    log = sh(['git', 'log', '--format=%h %s', f'{base}..HEAD'], cwd=REPO).splitlines()
    tag = cur.upper()
    merge = merge_commits(log, tag)
    runs = sorted((REPO / 'harness/loop/runs').glob('pipeline_*.jsonl'))
    def result(p):
        return run_result(p.read_text(errors='replace'))
    merge_time = 0
    if merge:
        merge_time = int(sh(['git', 'log', '-1', '--format=%ct', merge[-1].split()[0]], cwd=REPO) or 0)
    full_pass = proj_pass = False
    last_runs = []
    for p in runs[-12:]:
        full, ok = result(p)
        last_runs.append({'run': p.stem, 'full': full, 'pass': ok})
        if p.stat().st_mtime >= merge_time and merge_time:
            full_pass = full_pass or (full and ok)
        proj_pass = ok if not full else proj_pass
    ver = sh([str(REPO / 'bin/derod'), '--version'])
    run_ver = ''
    pid = select_derod(ps_rows(), REPO, cwd_of)           # r28 N28-05: exact process name, never a pattern
    if pid:
        run_ver = derod_run_suffix(HOME / 'dero-data/logs')
    scratch = sorted(SCRATCH_ROOT.glob(f'*/scratchpad/{cur}'))
    dims = {}
    for sd in scratch:
        for p in sorted(sd.iterdir()):
            if p.is_dir():
                pats = [str(x) for x in p.glob('*.patch')]
                dims[p.name] = {'dir': str(p), 'patches': pats, 'verify_md': (p / 'verify.md').exists()}
    pub_head = sh(['git', 'log', '-1', '--format=%h %s'], cwd=PUB)
    gs = r.get('github_sync', {})
    s = {
        'stamp': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'round': cur, 'suffix': suffix, 'registry': r,
        'repo_head': sh(['git', 'log', '-1', '--format=%h %s'], cwd=REPO), 'dirty_files': len(sh(['git', 'status', '--short'], cwd=REPO).splitlines()),
        'commits_since_base': log, 'merge_commits': merge,
        'workflows': workflows(int(sh(['git', 'log', '-1', '--format=%ct', base], cwd=REPO) or 0)), 'scratch_dims': dims,
        'pipeline_runs': last_runs, 'last_full_pipeline_pass_after_merge': full_pass, 'last_project_pass': proj_pass,
        'installed': suffix in ver, 'bin_derod_version': ver, 'derod_pid': pid, 'derod_running_suffix': run_ver,
        'ledger_exists': (REPO / f'artifacts/dero-r1-{cur}.html').exists(),
        'github_head': pub_head, 'github_synced': bool(gs.get('target') not in (None, 'pending')) and r.get('status') == 'measured',
        'rft_addendum': [str(p) for p in SCRATCH_ROOT.glob(f'*/scratchpad/{cur}/rft_addendum.md')],
    }
    since = int(sh(['git', 'log', '-1', '--format=%ct', base], cwd=REPO) or 0)
    s['agents'] = agents(since, cur)                                     # r30 B252
    det, bound = jobs(proc_rows(), os.getpid(), [str(SCRATCH_ROOT), str(REPO), str(PERSIST)])
    s['jobs'] = {'detached': det, 'session_bound': bound}
    s['due'] = load_due(cur)
    s['steps'] = sticky_steps([{'step': n, 'done': bool(f(s))} for n, f in STEPS], previous_steps(cur))
    return s


def resume_md(s):
    L = [f"# {s['round'].upper()} resume brief — {s['stamp']}", '',
         'Written by harness/intel/round_checkpoint.py from live sources (dero-rft.md §0.10). A new session: read this, then',
         'dero-rft.md §0.10 and §6 from the first step marked NOT DONE. Never redo a DONE step; re-verify it instead.', '',
         f"- Repo head: `{s['repo_head']}` ({s['dirty_files']} uncommitted files)",
         f"- Registry: `{s['round']}` status **{s['registry'].get('status')}**, base `{s['registry'].get('new_tests_base')}`",
         f"- bin/derod: `{s['bin_derod_version']}`; running derod pid {s['derod_pid'] or 'none'} on `{s['derod_running_suffix'] or '?'}`",
         f"- GitHub copy head: `{s['github_head']}`", '', '## Procedure state (§6)', '']
    for st in s['steps']:
        L.append(f"- [{'x' if st['done'] else ' '}] {st['step']}" + (' (DONE earlier; live probe now fails: re-verify, do not redo)' if st.get('reverify') else ''))
    L += ['', '## Workflows (resume a stopped one with its script + run id; finished agents replay from cache)', '']
    for w in s['workflows']:
        L.append(f"### {w['run_id']}: {w['done']}/{w['started']} agents finished")
        if w['script']:
            L.append(f"Resume: `Workflow({{scriptPath: \"{w['script']}\", resumeFromRunId: \"{w['run_id']}\"}})`")
        for a in w['agents']:
            L.append(f"- {a.get('label')}: **{a.get('state')}**" + (f" — {a['summary']}" if a.get('summary') else ''))
        L.append('')
    L += ['## Agents (Agent-tool subagents; resume an unfinished one with SendMessage, or a fresh agent from its HANDOFF.md)', '']
    for a in s.get('agents') or []:
        L.append(f"- `{a['id']}` {a.get('description') or ''}: **{a['state']}** (last activity {a['last_activity']}, idle {a['idle_s']} s)"
                 + (f"; dim `{a['dim']}`" if a.get('dim') else '')
                 + (f"; HANDOFF {a['handoff']}" if a.get('handoff') else ('; no HANDOFF.md' if a['state'] != 'done' else '')))
    jb = s.get('jobs') or {}
    L += ['', '## OS jobs', '', 'Detached (survive the session; liveness = their output grows):', '']
    for j in jb.get('detached') or []:
        L.append(f"- pid {j['pid']} {j['kind']}: `{j['cmd'][:160]}` -> out {j.get('out') or 'unknown'} ({j.get('size')} B, "
                 f"mtime {j.get('mtime')})" + (f", ends {j['end']}" if j.get('end') else '') + (', DONE' if j.get('done') else ''))
    L += ['', 'Session-bound (die with the session; `round_pause.py pause` re-launches the loops detached):', '']
    for j in jb.get('session_bound') or []:
        L.append(f"- pid {j['pid']} {j['kind']}: `{j['cmd'][:160]}`")
    over, ready, up = due_view(s.get('due'))
    L += ['', '## Due actions (round_state/<round>_DUE.json; overdue first)', '']
    if s.get('due') is None:
        L.append('- no due-actions ledger')
    for tag, items in (('OVERDUE', over), ('ready', ready), ('upcoming', up)):
        for i in items:
            L.append(f"- {tag} {i.get('id')} {i.get('due') or 'after ' + ','.join(i.get('after') or [])}: {i.get('what')}")
    ev = (s.get('due') or {}).get('evidence') or []
    if ev:
        L += ['', '## Declared evidence (DUE.json; grows while its detached producer runs; never stopped by the checkpoint)', '']
        for e in ev:
            sz, mt, _ = _stat(e.get('out'))
            L.append(f"- {e.get('id')}: {e.get('out')} ({sz} B, mtime {mt})" + (f"; pidfile {e['pidfile']}" if e.get('pidfile') else ''))
    L += ['', '## Scratch outputs of this round', '']
    for k, v in s['scratch_dims'].items():
        L.append(f"- `{k}`: {len(v['patches'])} patch(es){' + verify.md' if v['verify_md'] else ''} — {v['dir']}")
    L += ['', '## Commits since the round base', ''] + [f'- {c}' for c in s['commits_since_base'][:60]]
    L += ['', '## Pipeline runs (newest last)', ''] + [f"- {r['run']}: {'full' if r['full'] else 'project-only'} {'PASS' if r['pass'] else 'not PASS'}" for r in s['pipeline_runs']]
    L += ['', '## User instructions captured this round (verbatim, to be folded into dero-rft.md §2)', ''] + [f'- {p}' for p in s['rft_addendum']]
    notes = OUT / f"{s['round']}_NOTES.md"   # r25: the coordinator's handoff notes, appended verbatim
    if notes.exists():
        L += ['', notes.read_text()]
    return '\n'.join(L) + '\n'


def write(s):
    OUT.mkdir(parents=True, exist_ok=True)
    os.chmod(OUT, 0o700)
    j, m = OUT / f"{s['round']}_state.json", OUT / f"{s['round']}_RESUME.md"
    j.write_text(json.dumps(s, indent=1, default=str) + '\n')
    m.write_text(resume_md(s))
    h = OUT / 'history'
    h.mkdir(exist_ok=True)
    stamp = time.strftime('%Y%m%dT%H%M%S')
    shutil.copy2(m, h / f'{stamp}_{m.name}')
    prune_history(h)
    for sd in SCRATCH_ROOT.glob(f"*/scratchpad/{s['round']}"):   # also next to the round's scratch (mirrored by backup_scratch.sh)
        shutil.copy2(m, sd / m.name)
    return m


if __name__ == '__main__':
    loop = int(sys.argv[sys.argv.index('--loop') + 1]) if '--loop' in sys.argv else 0
    while True:
        print(write(snapshot()), flush=True)
        if not loop:
            break
        time.sleep(loop)
