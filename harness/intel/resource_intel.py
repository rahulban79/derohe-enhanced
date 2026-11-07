#!/usr/bin/env python3
"""resource_intel.py — RAM / swap / file-event load of this project's own workflow: a READ-ONLY probe and a fan-out preflight.

r27b (dero-rft §7 B148). On 2026-11-05 ~11:00 fseventsd held 21-22 GB RSS (the system monitor 140 GB with compressed and
swapped pages) after 3 d 10 h, swap was 64,739 of 65,536 MB used and memory_pressure said 42 % free, while the session
scratchpad held 218 repo clone trees that backup_scratch.sh mirrored every 15 min. After the USER restarted fseventsd
(11:08) swap fell to 5,014 of 6,144 MB used and free rose to 90 %: fseventsd alone held ~59.7 GB of swap. The link to the
project's clone/backup churn is SUSPECTED, not proven (a controlled churn of ~267k own file events grew the new fseventsd
by < 1 MB, r27b findings). This tool measures; it never kills, renices, signals or restarts anything — a foreign or
system process (fseventsd, mds_stores, derod) is the user's decision (rft §5 resource-hygiene rule).

  probe       swap total/used/free (sysctl vm.swapusage), memory_pressure -Q free %, RAM, the RSS of fseventsd /
              mds_stores / mds / derod and of this project's own python / go / git / rsync processes (BASENAMES and
              sums only: no pid list, args or path reaches the output), the scratchpad clone-tree count and their file
              count and bytes, GOCACHE size, the persisted mirror (~/derohe-persist/scratchpad) size.
  level       OK / REDUCE / HOLD from the readings (thresholds below, each with its evidence).
  preflight   for a planned fan-out (N clones, or N parallel heavy jobs such as `go test -race` packages): the concurrency
              the readings allow. kind=jobs never recommends 0 (a gate is never skipped; HOLD runs it serially, slower,
              same strength); kind=clones recommends 0 new clones on HOLD (run harness/pipeline/scratch_gc.py first).
              --notes FILE appends one '[HH:MM] preflight ...' line (the round notes record every decision).

  python3 -I harness/intel/resource_intel.py [--json] [--full] [--scratch DIR]... [--persist DIR] [--record]
  python3 -I harness/intel/resource_intel.py preflight --planned N [--kind jobs|clones] [--stage NAME] [--notes FILE] [--json]
Exit 0 OK · 5 REDUCE · 6 HOLD · 2 a reading failed (or bad arguments).
"""
import argparse, json, os, re, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PENDING = 'pending'
MB = 1024 * 1024

# ── thresholds (each with the evidence it rests on) ──────────────────────────────────────────────────────────────────
# macOS swap is dynamic: the swap files grow and shrink (65,536 MB total before the 11:08 fseventsd restart, 6,144 MB
# after), so 'swap free' alone is not headroom: after the restart free was 1,130 MB with memory 90 % free (healthy).
# The leading signals are swap USED and memory_pressure's free %; 'swap free' counts only together with a low free %.
HOLD_SWAP_USED_MB = 32 * 1024        # before: 64,739 MB used (HOLD) · after: 5,014 MB (OK)
REDUCE_SWAP_USED_MB = 16 * 1024
HOLD_FREE_PCT = 20                   # memory_pressure free %: before 42, after 90
REDUCE_FREE_PCT = 50                 # 42 % (before) is REDUCE on its own
HOLD_SWAP_FREE_MB = 1024             # swap at its ceiling (before: 797 MB free) AND free % below REDUCE_FREE_PCT
REDUCE_FSEVENTSD_MB = 4 * 1024       # before 21-22 GB · after 12 MB (fresh) — a large fseventsd is a REDUCE signal
# r28 (B148): Spotlight's index store. Readings: 1.24 GB (2026-11-05 11:08, after the fseventsd restart) -> 8.38 GB (12:38)
# -> 14,465 MB (R28 Part A 23:27) -> 50,360 MB (2026-11-06 00:39, this probe) while fseventsd stayed at 42 MB: the index
# grows with the project's file churn (SUSPECTED, not proven). A REDUCE signal only (excluding dirs from Spotlight or
# restarting mds is the user's decision, rft §5); never acted on by any tool.
REDUCE_MDS_STORES_MB = 16 * 1024
REDUCE_CLONE_TREES = 100             # 218 trees held in the scratchpad at the event (309 .git dirs counted by r27b)
RESERVE_PCT = 20                     # kind=jobs: RAM kept free for the node, the system and the operator
PER_JOB_MB = {'jobs': 2048, 'clones': 512}   # per-job RAM estimates (ASSUMED until measured; r27b findings records
                                              # the measured `go test -race` peak RSS that replaces the jobs value)

WATCH = {'fseventsd': 'fseventsd', 'mds_stores': 'mds_stores', 'mds': 'mds', 'derod': 'derod'}
PROJECT_NAMES = re.compile(r'^(python[0-9.]*|Python|go|compile|link|asm|vet|cgo|git|rsync|[\w.-]+\.test)$')
PROJECT_MARK = 'derohe'              # a project process names the repo or a project scratchpad in its arguments


def run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 127, ''


def _mb(v):
    m = re.fullmatch(r'([\d.]+)([KMG])', v)
    if not m:
        return None
    return float(m.group(1)) * {'K': 1 / 1024, 'M': 1, 'G': 1024}[m.group(2)]


def parse_swap(text):
    """'total = 65536.00M  used = 64739.25M  free = 796.75M  (encrypted)' -> {total_mb, used_mb, free_mb}. Pure."""
    out = {}
    for k in ('total', 'used', 'free'):
        m = re.search(rf'{k} = ([\d.]+[KMG])', text or '')
        out[f'{k}_mb'] = round(_mb(m.group(1)), 2) if m else None
    return out if None not in out.values() else None


def parse_free_pct(text):
    """memory_pressure -Q: 'System-wide memory free percentage: 42%' -> 42. Pure."""
    m = re.search(r'memory free percentage:\s*(\d+)%', text or '')
    return int(m.group(1)) if m else None


def safe_name(comm):
    c = str(comm or '').strip().rstrip('/').rsplit('/', 1)[-1]
    return re.sub(r'[^\x20-\x7e]', '?', c)[:48] or '?'


def classify(rows, self_pid=None):
    """rows [(pid, rss_kb, comm, args)] -> {'watch': {name: rss_mb}, 'project': {count, rss_mb, top}}. Pure.
    Only basenames and sums leave this function (no pid, args or path)."""
    watch = {k: None for k in WATCH}
    proj, top = [], {}
    for pid, rss, comm, args in rows:
        name = safe_name(comm)
        if name in WATCH:
            watch[name] = round((watch[name] or 0) + rss / 1024, 1)
            continue
        if pid == self_pid or not PROJECT_NAMES.match(name) or PROJECT_MARK not in (args or ''):
            continue
        proj.append(rss)
        top[name] = round(top.get(name, 0) + rss / 1024, 1)
    return {'watch': watch, 'project': {'count': len(proj), 'rss_mb': round(sum(proj) / 1024, 1),
                                        'by_name_mb': dict(sorted(top.items(), key=lambda kv: -kv[1])[:8])}}


def read_procs():
    rc1, a = run(['ps', '-axww', '-o', 'pid=,rss=,comm='])
    rc2, b = run(['ps', '-axww', '-o', 'pid=,args='])
    if rc1 or rc2:
        return None
    args = {}
    for l in b.splitlines():
        p = l.strip().split(None, 1)
        if p and p[0].isdigit():
            args[int(p[0])] = p[1] if len(p) > 1 else ''
    rows = []
    for l in a.splitlines():
        p = l.strip().split(None, 2)
        if len(p) == 3 and p[0].isdigit() and p[1].isdigit():
            rows.append((int(p[0]), int(p[1]), p[2], args.get(int(p[0]), '')))
    return classify(rows, os.getpid())


def walk(top, full=True, max_depth=5):
    """(files, bytes, trees, tree_files, tree_bytes) under top; a clone tree is a dir holding '.git'. Symlinks are not
    followed. full=False counts trees only (no descent into a tree, none below max_depth: every r17-r27 tree sits at
    depth <= 4 of the scratchpad). Bytes are on-disk (st_blocks * 512); a hardlinked file counts at every link. A full
    walk of a 7.6M-file scratchpad + 11.9M-file mirror took 16.7 min (r27b): it is opt-in (--full)."""
    files = size = trees = tfiles = tbytes = 0
    stack = [(Path(top), 0, False)]
    while stack:
        d, depth, in_tree = stack.pop()
        try:
            ents = list(os.scandir(d))
        except OSError:
            continue
        is_tree = not in_tree and any(e.name == '.git' for e in ents)
        if is_tree:
            trees += 1
            if not full:
                continue
        for e in ents:
            try:
                if e.is_symlink():
                    continue
                if e.is_dir(follow_symlinks=False):
                    if full or depth < max_depth:
                        stack.append((Path(e.path), depth + 1, in_tree or is_tree))
                elif full:
                    b = e.stat(follow_symlinks=False).st_blocks * 512
                    files += 1
                    size += b
                    if in_tree or is_tree:
                        tfiles += 1
                        tbytes += b
            except OSError:
                continue
    return {'files': files if full else PENDING, 'bytes': size if full else PENDING, 'clone_trees': trees,
            'tree_files': tfiles if full else PENDING, 'tree_bytes': tbytes if full else PENDING}


def scratch_roots():
    """this user's project scratchpads: $RESOURCE_SCRATCH_BASE/<project dir naming derohe>/<session>/scratchpad"""
    base = Path(os.environ.get('RESOURCE_SCRATCH_BASE') or f'/tmp/scratch-{os.getuid()}')
    return sorted(p for p in base.glob('*derohe*/*/scratchpad') if p.is_dir()) if base.is_dir() else []


def gocache():
    rc, out = run(['go', 'env', 'GOCACHE'], timeout=30)
    p = out.strip()
    return Path(p) if rc == 0 and p and Path(p).is_dir() else None


def readings(scratch=None, persist=None, quick=False):
    r = {'t': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
    rc, out = run(['sysctl', '-n', 'vm.swapusage'])
    r['swap'] = parse_swap(out) if rc == 0 else None
    rc, out = run(['memory_pressure', '-Q'])          # -Q: query only (without it memory_pressure APPLIES pressure)
    r['memory_free_pct'] = parse_free_pct(out) if rc == 0 else None
    rc, out = run(['sysctl', '-n', 'hw.memsize'])
    r['ram_mb'] = int(out.strip()) // MB if rc == 0 and out.strip().isdigit() else None
    r['procs'] = read_procs()
    roots = [Path(s) for s in scratch] if scratch is not None else scratch_roots()   # [] = measure none
    agg = {'roots': len(roots), 'files': 0, 'bytes': 0, 'clone_trees': 0, 'tree_files': 0, 'tree_bytes': 0}
    for s in roots:
        w = walk(s, full=not quick)
        for k in ('files', 'bytes', 'clone_trees', 'tree_files', 'tree_bytes'):
            agg[k] = w[k] if w[k] == PENDING else agg[k] + w[k]
    r['scratchpad'] = agg
    if quick:
        r['gocache'] = r['persist_mirror'] = PENDING
    else:
        g = gocache()
        r['gocache'] = {k: walk(g)[k] for k in ('files', 'bytes')} if g else PENDING
        pm = Path(persist) if persist else Path.home() / 'derohe-persist' / 'scratchpad'
        r['persist_mirror'] = walk(pm) if pm.is_dir() else PENDING
    return r


def level(r):
    """(OK|REDUCE|HOLD, [reasons]) from readings. Pure. A missing reading never yields OK on its own: it is a reason."""
    hold, reduce = [], []
    sw, free = r.get('swap'), r.get('memory_free_pct')
    if sw is None or free is None:
        reduce.append('swap or memory_pressure unreadable')
    if sw:
        if sw['used_mb'] >= HOLD_SWAP_USED_MB:
            hold.append(f"swap used {sw['used_mb']:.0f} MB >= {HOLD_SWAP_USED_MB}")
        elif sw['used_mb'] >= REDUCE_SWAP_USED_MB:
            reduce.append(f"swap used {sw['used_mb']:.0f} MB >= {REDUCE_SWAP_USED_MB}")
        if sw['free_mb'] < HOLD_SWAP_FREE_MB and free is not None and free < REDUCE_FREE_PCT:
            hold.append(f"swap free {sw['free_mb']:.0f} MB < {HOLD_SWAP_FREE_MB} with memory free {free} % < {REDUCE_FREE_PCT}")
    if free is not None:
        if free < HOLD_FREE_PCT:
            hold.append(f'memory free {free} % < {HOLD_FREE_PCT}')
        elif free < REDUCE_FREE_PCT:
            reduce.append(f'memory free {free} % < {REDUCE_FREE_PCT}')
    fse = ((r.get('procs') or {}).get('watch') or {}).get('fseventsd')
    if fse is not None and fse >= REDUCE_FSEVENTSD_MB:
        reduce.append(f'fseventsd RSS {fse:.0f} MB >= {REDUCE_FSEVENTSD_MB} (restarting it is the user\'s decision)')
    mds = ((r.get('procs') or {}).get('watch') or {}).get('mds_stores')
    if mds is not None and mds >= REDUCE_MDS_STORES_MB:                       # r28 (B148)
        reduce.append(f'mds_stores RSS {mds:.0f} MB >= {REDUCE_MDS_STORES_MB} (Spotlight index; excluding dirs or '
                      f'restarting it is the user\'s decision)')
    trees = (r.get('scratchpad') or {}).get('clone_trees')
    if isinstance(trees, int) and trees > REDUCE_CLONE_TREES:
        reduce.append(f'{trees} clone trees in the scratchpads > {REDUCE_CLONE_TREES} (run scratch_gc.py)')
    return ('HOLD' if hold else 'REDUCE' if reduce else 'OK'), hold + reduce


def preflight(r, planned, kind='jobs', per_job_mb=None):
    """the concurrency a planned fan-out may use, from readings r. Pure. kind=jobs: >= 1 always (serial on HOLD: a
    gate is slower, never skipped or weakened); kind=clones: 0 new clones on HOLD."""
    planned = max(1, int(planned))
    lv, why = level(r)
    pj = per_job_mb or PER_JOB_MB[kind]
    ram, free = r.get('ram_mb'), r.get('memory_free_pct')
    if ram and free is not None:
        budget = ram * (free - RESERVE_PCT) / 100
        by_mem = max(0, int(budget // pj))
    else:
        by_mem = 1
    rec = min(planned, by_mem)
    if lv == 'REDUCE':
        rec = min(rec, max(1, planned // 2))
    if lv == 'HOLD':
        rec = 0 if kind == 'clones' else 1
    if kind == 'jobs':
        rec = max(1, rec)
    return {'level': lv, 'kind': kind, 'planned': planned, 'recommended': rec, 'per_job_mb': pj,
            'by_memory': by_mem, 'reasons': why}


def note_line(stage, d, when=None):
    """one round-notes line for a preflight decision. Pure."""
    when = when or time.strftime('%H:%M')
    return (f"[{when}] preflight {stage or '-'}: {d['level']} kind={d['kind']} planned={d['planned']} "
            f"recommended={d['recommended']}" + (f" ({'; '.join(d['reasons'])})" if d['reasons'] else ''))


EXIT = {'OK': 0, 'REDUCE': 5, 'HOLD': 6}


def parse(argv):
    ap = argparse.ArgumentParser(prog='resource_intel.py', description=__doc__.split('\n\n')[0])
    ap.add_argument('cmd', nargs='?', choices=['probe', 'preflight'], default='probe')
    ap.add_argument('--json', action='store_true', help='print the JSON record')
    ap.add_argument('--full', action='store_true', help='walk every file (counts and bytes of the scratchpads, GOCACHE '
                    'and the mirror; minutes on a large scratchpad). Default: the tree count only, sizes pending')
    ap.add_argument('--scratch', action='append', help='scratchpad dir(s) to measure (default: this user\'s project scratchpads)')
    ap.add_argument('--persist', help='persisted mirror dir (default ~/derohe-persist/scratchpad)')
    ap.add_argument('--record', action='store_true', help='also write harness/runtime/resource_<ts>.json')
    ap.add_argument('--planned', type=int, default=1, help='preflight: planned clones / parallel heavy jobs')
    ap.add_argument('--kind', choices=['jobs', 'clones'], default='jobs')
    ap.add_argument('--per-job-mb', type=int, default=None)
    ap.add_argument('--stage', default=None, help='preflight: the stage or workflow name for the notes line')
    ap.add_argument('--notes', default=os.environ.get('DERO_ROUND_NOTES'), help='append the decision to this notes file '
                    '(env DERO_ROUND_NOTES)')
    return ap.parse_args(argv)


def main(argv):
    try:
        a = parse(argv)
    except SystemExit as e:
        return 0 if e.code in (0, None) else 2
    r = readings(a.scratch, a.persist, quick=not a.full or a.cmd == 'preflight')
    if r['swap'] is None and r['memory_free_pct'] is None:
        print('resource_intel: neither vm.swapusage nor memory_pressure -Q could be read', file=sys.stderr)
        return 2
    lv, why = level(r)
    r['level'], r['reasons'] = lv, why
    if a.cmd == 'preflight':
        d = preflight(r, a.planned, a.kind, a.per_job_mb)
        r['preflight'] = d
        line = note_line(a.stage, d)
        if a.notes:
            with open(os.path.expanduser(a.notes), 'a') as f:
                f.write(line + '\n')
        print(json.dumps(r, indent=1) if a.json else line)
        return EXIT[d['level']]
    if a.record:
        out = ROOT / 'harness/runtime' / f"resource_{time.strftime('%Y%m%dT%H%M%S')}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(r, indent=1) + '\n')
    if a.json:
        print(json.dumps(r, indent=1))
    else:
        sw, p = r['swap'] or {}, (r['procs'] or {}).get('watch', {})
        print(f"{lv}: swap used {sw.get('used_mb')} / {sw.get('total_mb')} MB · memory free {r['memory_free_pct']} % · "
              f"fseventsd {p.get('fseventsd')} MB · mds_stores {p.get('mds_stores')} MB · derod {p.get('derod')} MB · "
              f"scratch trees {r['scratchpad']['clone_trees']}" + (f" · {'; '.join(why)}" if why else ''))
    return EXIT[lv]


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
