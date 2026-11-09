#!/usr/bin/env python3
"""stallwatch.py — r29 (user 2026-11-08: "make sure to fix anything you find tasks are stuck at"): a watchdog for one
long, resumable job of our own (first user: the B182 deep fetch, which hung twice on 2026-11-08 while its progress
file kept refreshing — a fresh progress file is NOT liveness).

Liveness = WORK, not heartbeats: the job is alive while any of its --work files grows (size or mtime) or any numeric
--counter in its progress JSON changes. Counters may reset when the job restarts; any change counts. A job is
  RUNNING   its process (matched by --match, owned by this user) exists and work moved within --stall-s
  STALLED   it exists but no work moved for --stall-s: a diagnosis is saved (leaf frames via `sample`, last errors),
            the process group is stopped (TERM, then KILL after 10 s) and the job is relaunched with --cmd
  DEAD      no process and no --done marker: relaunched with --cmd
  DONE      the --done file exists (the job's own completion marker): the watchdog exits 0
At most --max-restarts relaunches per hour; past that it stops with exit 5 and writes STUCK to --log, so a human
(the coordinator) looks instead of a restart loop. It never signals a process whose command line lacks --match or
that belongs to another user — derod, the miner and system processes are out of reach by construction.

  python3 -I harness/kit/stallwatch.py --match 'b182_deep_r29.py run' --cmd-file CMD --progress P.json \
      --counter txs --counter verified_blocks --work checkpoint.log --done DONEFILE --stall-s 900 --log LOG
"""
import argparse, json, os, signal, subprocess, sys, time
from pathlib import Path


def own_pids(match, ps=None):
    """pids of THIS user's processes whose command line contains `match` (never our own pid). Pure apart from ps."""
    out = ps if ps is not None else subprocess.run(['ps', '-axo', 'pid=,uid=,command='], capture_output=True,
                                                    text=True).stdout
    me, pids = os.getuid(), []
    for line in out.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 3 or not parts[0].isdigit() or not parts[1].isdigit():
            continue
        pid, uid, cmd = int(parts[0]), int(parts[1]), parts[2]
        if uid == me and match in cmd and pid != os.getpid() and 'stallwatch.py' not in cmd:
            pids.append(pid)
    return pids


def work_sig(progress, counters, work):
    """the work signature: numeric counters of the progress JSON + size/mtime of each work file. Pure apart from fs."""
    sig = []
    try:
        d = json.loads(Path(progress).read_text()) if progress else {}
    except (OSError, ValueError):
        d = {}
    for c in counters:
        v = d
        for k in c.split('.'):
            v = v.get(k) if isinstance(v, dict) else None
        sig.append(v)
    for w in work:
        try:
            st = os.stat(w)
            sig.append((st.st_size, int(st.st_mtime)))
        except OSError:
            sig.append(None)
    return sig


class Watch:
    """the state machine, clock and actions injectable (the KAT drives it with a fake clock and fake actions)."""

    def __init__(self, a, clock=time.monotonic, act=None):
        self.a, self.clock, self.act = a, clock, act or Actions(a)
        self.sig, self.moved, self.restarts = None, clock(), []

    def step(self):
        a, now = self.a, self.clock()
        if a.done and Path(a.done).exists():
            return 'DONE'
        sig = work_sig(a.progress, a.counter, a.work)
        if sig != self.sig:
            self.sig, self.moved = sig, now
        pids = self.act.pids()
        if pids and now - self.moved < a.stall_s:
            return 'RUNNING'
        state = 'STALLED' if pids else 'DEAD'
        self.restarts = [t for t in self.restarts if now - t < 3600]
        if len(self.restarts) >= a.max_restarts:
            self.act.log(f'STUCK {state}: {len(self.restarts)} restarts within 1 h; not restarting (a human looks)')
            return 'STUCK'
        if pids:
            self.act.diagnose(pids)
            self.act.stop(pids)
        self.act.launch()
        self.restarts.append(now)
        self.moved, self.sig = now, None
        self.act.log(f'{state}: relaunched ({len(self.restarts)} in the last hour)')
        return state


class Actions:
    def __init__(self, a):
        self.a = a

    def log(self, msg):
        with open(self.a.log, 'a') as f:
            f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {msg}\n")

    def pids(self):
        return own_pids(self.a.match)

    def diagnose(self, pids):
        lines = []
        for p in pids[:2]:
            r = subprocess.run(['sample', str(p), '1'], capture_output=True, text=True, timeout=30)
            leaf, cur = [], None
            for ln in r.stdout.splitlines():
                if 'Thread_' in ln:
                    if cur:
                        leaf.append(cur)
                    cur = None
                elif '(in ' in ln:
                    cur = ln.strip().lstrip('+!:| 0123456789').split('[')[0].strip()
            if cur:
                leaf.append(cur)
            counts = {}
            for x in leaf:
                counts[x] = counts.get(x, 0) + 1
            lines.append(f'pid {p} leaf frames: ' + '; '.join(f'{n}x {k}' for k, n in sorted(counts.items(),
                                                                                         key=lambda kv: -kv[1])[:6]))
        try:
            d = json.loads(Path(self.a.progress).read_text())
            lines.append('last errors: ' + json.dumps(d.get('last_errors', [])[-3:])[:600])
        except (OSError, ValueError, TypeError):
            pass
        self.log('DIAGNOSIS ' + ' | '.join(lines))

    def stop(self, pids):
        for sig in (signal.SIGTERM, signal.SIGKILL):
            for p in pids:
                try:
                    os.killpg(os.getpgid(p), sig) if self.a.group else os.kill(p, sig)
                except (ProcessLookupError, PermissionError):
                    pass
            for _ in range(10):
                if not own_pids(self.a.match):
                    return
                time.sleep(1)

    def launch(self):
        cmd = Path(self.a.cmd_file).read_text().strip()
        subprocess.Popen(['/bin/bash', '-c', cmd], start_new_session=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def parse(argv):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--match', required=True)
    p.add_argument('--cmd-file', required=True)
    p.add_argument('--progress')
    p.add_argument('--counter', action='append', default=[])
    p.add_argument('--work', action='append', default=[])
    p.add_argument('--done')
    p.add_argument('--stall-s', type=float, default=900)
    p.add_argument('--every', type=float, default=60)
    p.add_argument('--max-restarts', type=int, default=4)
    p.add_argument('--group', action='store_true', help='stop the whole process group (the job runs in its own session)')
    p.add_argument('--log', required=True)
    a = p.parse_args(argv)
    if len(a.match) < 8:
        p.error('--match must be specific (>= 8 characters)')
    return a


def main(argv):
    a = parse(argv)
    w = Watch(a)
    w.act.log(f'start: match={a.match!r} stall_s={a.stall_s:g} max_restarts={a.max_restarts}')
    while True:
        st = w.step()
        if st in ('DONE', 'STUCK'):
            w.act.log(st)
            return 0 if st == 'DONE' else 5
        time.sleep(a.every)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
