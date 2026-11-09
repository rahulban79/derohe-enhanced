#!/usr/bin/env python3
"""test_stallwatch_r29.py — r29 (user 2026-11-08 "make sure to fix anything you find tasks are stuck at"): the long-job
watchdog harness/kit/stallwatch.py tells work from heartbeats, restarts only our own stalled or dead job, and stops
asking for restarts past its cap.

  SW1 counters moving -> RUNNING, no action
  SW2 counters frozen past stall_s while the process exists -> STALLED: diagnose, stop, relaunch (in that order)
  SW3 no process and no done marker -> DEAD: relaunch, no stop
  SW4 done marker -> DONE, no action
  SW5 past max_restarts within an hour -> STUCK, no further relaunch
  SW6 own_pids: only this user's processes whose command contains the match, never the watchdog itself
  SW7 a progress file whose heartbeat ('t') refreshes while every counter is frozen is a stall (the 2026-11-08 B182 hang)
  SW8 end to end: a real job that hangs once is stopped and relaunched, and the relaunch finishes (done marker)

  python3 -I harness/kat/test_stallwatch_r29.py      # KATs, then the mutations; exit 0 · 3 KAT failed · 4 mutation missed
"""
import contextlib, importlib.util, io, json, os, sys, tempfile, time
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS = ROOT / 'harness'
PATHS = {'tool': 'harness/kit/stallwatch.py'}


def load(over):
    spec = importlib.util.spec_from_file_location('stallwatch', Path(over.get('tool') or (ROOT / PATHS['tool'])))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class Act:
    def __init__(self, pids=(1,)):
        self.p, self.calls = list(pids), []

    def pids(self):
        return self.p

    def log(self, msg):
        self.calls.append(('log', msg.split(':')[0]))

    def diagnose(self, pids):
        self.calls.append(('diagnose',))

    def stop(self, pids):
        self.calls.append(('stop',))

    def launch(self):
        self.calls.append(('launch',))


def setup(d, **kw):
    a = SimpleNamespace(progress=str(Path(d) / 'p.json'), counter=['txs', 'ep.ok'], work=[], done=str(Path(d) / 'DONE'),
                        stall_s=900, max_restarts=4)
    a.__dict__.update(kw)
    return a


def wp(a, t, txs, ok=1):
    Path(a.progress).write_text(json.dumps({'t': t, 'txs': txs, 'ep': {'ok': ok}}))


def acts(act):
    return [c[0] for c in act.calls if c[0] != 'log']


def kat_sw1(over):
    m = load(over)
    with tempfile.TemporaryDirectory() as d:
        a, c, act = setup(d), Clock(), Act()
        w = m.Watch(a, c, act)
        out = []
        for i in range(10):
            wp(a, i, i * 10)
            c.t += 600
            out.append(w.step())
        return set(out) == {'RUNNING'} and acts(act) == [], (out, act.calls)


def kat_sw2(over):
    m = load(over)
    with tempfile.TemporaryDirectory() as d:
        a, c, act = setup(d), Clock(), Act()
        w = m.Watch(a, c, act)
        wp(a, 0, 5)
        s1 = w.step()
        c.t += 901
        s2 = w.step()
        return (s1, s2) == ('RUNNING', 'STALLED') and acts(act) == ['diagnose', 'stop', 'launch'], (s1, s2, act.calls)


def kat_sw3(over):
    m = load(over)
    with tempfile.TemporaryDirectory() as d:
        a, c, act = setup(d), Clock(), Act(pids=())
        st = m.Watch(a, c, act).step()
        return st == 'DEAD' and acts(act) == ['launch'], (st, act.calls)


def kat_sw4(over):
    m = load(over)
    with tempfile.TemporaryDirectory() as d:
        a, c, act = setup(d), Clock(), Act(pids=())
        Path(a.done).write_text('')
        st = m.Watch(a, c, act).step()
        return st == 'DONE' and acts(act) == [], (st, act.calls)


def kat_sw5(over):
    m = load(over)
    with tempfile.TemporaryDirectory() as d:
        a, c, act = setup(d, max_restarts=2), Clock(), Act(pids=())
        w = m.Watch(a, c, act)
        out = []
        for _ in range(4):
            out.append(w.step())
            c.t += 60
        return out == ['DEAD', 'DEAD', 'STUCK', 'STUCK'] and acts(act).count('launch') == 2, (out, act.calls)


def kat_sw6(over):
    m = load(over)
    me = os.getuid()
    ps = '\n'.join([f'  101 {me} python3 -I job.py run --x', f'  102 {me + 1} python3 -I job.py run --x',
                    f'  103 {me} /usr/bin/derod --rpc', f'  {os.getpid()} {me} python3 job.py run self',
                    f'  104 {me} python3 stallwatch.py --match job.py run', 'garbage line'])
    got = m.own_pids('job.py run', ps=ps)
    return got == [101], got


def kat_sw7(over):
    m = load(over)
    with tempfile.TemporaryDirectory() as d:
        a, c, act = setup(d), Clock(), Act()
        w = m.Watch(a, c, act)
        out = []
        for i in range(4):
            wp(a, f'2026-11-08T11:{i:02d}:00Z', 1369391)          # heartbeat only
            out.append(w.step())
            c.t += 400
        return out[-1] == 'STALLED' and 'launch' in acts(act), (out, act.calls)


def kat_sw8(over):
    m = load(over)
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        job = d / 'sw8job_unique.py'
        job.write_text("import json, sys, time\nfrom pathlib import Path\nd = Path(sys.argv[1])\n"
                       "if not (d / 'once').exists():\n    (d / 'once').write_text('')\n"
                       "    (d / 'p.json').write_text(json.dumps({'txs': 1}))\n    time.sleep(600)\n"
                       "(d / 'p.json').write_text(json.dumps({'txs': 2}))\n(d / 'DONE').write_text('')\n")
        cmd = d / 'cmd'
        cmd.write_text(f"'{sys.executable}' -I '{job}' '{d}'")
        a = m.parse(['--match', str(job), '--cmd-file', str(cmd), '--progress', str(d / 'p.json'), '--counter', 'txs',
                     '--done', str(d / 'DONE'), '--stall-s', '2', '--log', str(d / 'log')])
        w = m.Watch(a)
        w.act.launch()
        seen = []

        def loop():
            while True:
                st = w.step()
                seen.append(st)
                if st == 'DONE':
                    return st
                time.sleep(0.5)
        hk = importlib.util.spec_from_file_location('hangkit_sw29', HARNESS / 'kit' / 'hangkit.py')
        HK = importlib.util.module_from_spec(hk)
        hk.loader.exec_module(HK)
        HK.within(loop, 30)                                # kit/hangkit: a watchdog that never sees DONE fails, not hangs
        left = m.own_pids(str(job))
        for p in left:
            os.kill(p, 9)
        return 'STALLED' in seen and seen[-1] == 'DONE' and not left, (sorted(set(seen)), left)


KATS = [('SW1', kat_sw1), ('SW2', kat_sw2), ('SW3', kat_sw3), ('SW4', kat_sw4), ('SW5', kat_sw5), ('SW6', kat_sw6),
        ('SW7', kat_sw7), ('SW8', kat_sw8)]
OWNERS = {'r29 stallwatch': [k for k, _ in KATS]}
MUTATIONS = [
    ('tool', "        if sig != self.sig:", "        if True:", 'r29 stallwatch: a heartbeat counts as work'),
    ('tool', "        if uid == me and match in cmd", "        if match in cmd", 'r29 stallwatch: another user\'s process is matched'),
    ('tool', "        if len(self.restarts) >= a.max_restarts:", "        if False:", 'r29 stallwatch: no restart cap'),
    ('tool', "        if a.done and Path(a.done).exists():", "        if False:", 'r29 stallwatch: the done marker is ignored'),
    ('tool', "        if pids:\n            self.act.diagnose(pids)\n            self.act.stop(pids)",
     "        if pids:\n            self.act.diagnose(pids)", 'r29 stallwatch: a stalled job is relaunched without stopping it'),
]


def katmut():
    spec = importlib.util.spec_from_file_location('katmut_sw29', HARNESS / 'kit' / 'katmut.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run_kats(over):
    res = []
    for name, fn in KATS:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                ok, det = fn(over)
        except (Exception, SystemExit) as e:                      # noqa: BLE001 — a crash is a failure
            ok, det = False, f'{type(e).__name__}: {e}'
        res.append((name, ok, str(det)))
    return res


def main(argv):
    if {'-h', '--help'} & set(argv):
        print(__doc__)
        return 0
    res = run_kats({})
    for name, ok, det in res:
        print(f"{'ok  ' if ok else 'FAIL'} {name} {det[:300]}")
    if not all(ok for _, ok, _ in res):
        print(f'\nr29 stallwatch KATs: {sum(o for _, o, _ in res)}/{len(KATS)} ok · mutations not run (a KAT failed)')
        return 3
    K = katmut()
    missed = 0
    for key, find, repl, why in MUTATIONS:
        src = ROOT / PATHS[key]
        text = src.read_text(encoding='utf-8')
        if text.count(find) != 1:
            print(f'  ??        {why}: find text occurs {text.count(find)} times')
            missed += 1
            continue
        with tempfile.TemporaryDirectory(prefix='sw29-mut-') as d:
            mut = Path(d) / PATHS[key]
            mut.parent.mkdir(parents=True, exist_ok=True)
            mut.write_text(text.replace(find, repl, 1), encoding='utf-8')
            failed = [n for n, ok, _ in run_kats({key: mut}) if not ok]
        verdict, _ = K.classify(failed, OWNERS.get(K.defect_of(why), []))
        print(f'  {verdict:<9} {why}' + (f'  [{",".join(failed)}]' if failed else ''))
        missed += verdict != 'proved'
    print('\n' + K.summary('r29 stallwatch KATs', len(KATS), len(MUTATIONS), missed, 0))
    return 4 if missed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
