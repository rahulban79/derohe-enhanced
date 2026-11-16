#!/usr/bin/env python3
"""gt_ladder.py — r32a: grow the MAINNET game from 3 to 5 wallets, one measured cycle per step, zero-touch, no LLM.

The user (2026-11-15): "run the second mainnet cycle with a third wallet - and increment this game until it reaches 5
wallets"; mining keeps running along with the games (the R32a objective: miners are paid to mine AND play). Per step N:
  1 earn   the pipeline-owned earn job mines m1..mN (gt_earn rotation, neediest first; a missing wallet is created and
           registered by gt_earn itself). If the running earn job does not list mN, its command file is rewritten
           (`&& touch earn.DONE`, recipe_lint) and the job is restarted under stallwatch (gt_earn stops its miners on
           SIGTERM, r32a).
  2 size   harness/gametheory/sizing.plan_n_wallet(N, measured fee per call, measured install fee, settled balances):
           a viable plan, or the balances each wallet still needs (D-GT-7: the harness decides balances and wallets)
  3 wait   poll the earn log until every wallet's SETTLED balance reaches its need (gt_trigger.settled_balances)
  4 play   playbooks/gt_cycle.py --wallets m1..mN --run-id r32a-mainnet-ladder --plan <step plan> (one deployment for
           the whole ladder: every contract is installed and frozen once; each step only claims, plays the prize rounds
           and the audit bounty rounds)
  5 audit  harness/gametheory/cycle_audit.py over the step's cycle record (entrants from the contracts, payoffs net of
           mining, sum = -fees)
Plans and the ladder's own events live under <GT_HOME>/runs/r32a-mainnet-ladder-driver/ (never tracked records, lesson
14); the cycle writes its record into harness/runtime as in R32. Failures are bounded: MAX_STEP_FAILS failed cycles of
one step write <GT_HOME>/mainnet/ladder.STOPPED and exit 4 (stallwatch --stop never relaunches it).

  python3 -I playbooks/gt_ladder.py --mainnet-confirm [--from 3] [--to 5] [--poll 120]
  stallwatch: --match 'gt_ladder.py --mainnet-confirm' --cmd-file mainnet/ladder.cmd
      --work runs/r32a-mainnet-ladder-driver/events.jsonl --work runs/r32a-mainnet-ladder/events.jsonl
      --done mainnet/ladder.DONE --stop mainnet/ladder.STOPPED --stall-s 3600   (the cycle's own events are work too)
Exit 0 ladder done · 4 gave up (ladder.STOPPED) · 5 --mainnet-confirm missing · 1 error.
"""
import argparse, json, os, signal, subprocess, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gtlib  # noqa: E402
from gtlib import rpc_call  # noqa: E402

ROOT = gtlib.ROOT
sys.path.insert(0, str(ROOT / 'harness/gametheory'))
import sizing  # noqa: E402

RUN_ID = 'r32a-mainnet-ladder'
EARN_RUN = 'r32-mainnet-earn'
MAX_STEP_FAILS = 3
EARN_TARGET_DERO = 50.0          # the earn job keeps mining through the games (its rotation only orders the wallets)


def names_for(n):
    return [f'm{i}' for i in range(1, n + 1)]


def earn_cmd(names, mdir):
    """the earn command line for these wallets (DONE only on success, recipe_lint). Pure."""
    return (f"cd {ROOT} && nice -n 15 python3 -I playbooks/gt_earn.py --wallet {','.join(names)} --mainnet-confirm "
            f"--threads 8 --cpu-max 80 --target-dero {EARN_TARGET_DERO} --max-hours 48 >> {mdir}/earn.log 2>&1 "
            f"&& touch {mdir}/earn.DONE")


def earn_wallets_running():
    """the --wallet list of the running gt_earn driver, or None."""
    r = subprocess.run(['pgrep', '-fl', 'playbooks/gt_earn.py --wallet'], capture_output=True, text=True)
    for line in r.stdout.splitlines():
        parts = line.split()
        if '--wallet' in parts and 'python' in line.lower():
            return parts[parts.index('--wallet') + 1].split(',')
    return None


def restart_earn(run, names):
    """rewrite earn.cmd for `names` and restart the earn job under stallwatch (own processes only, matched by command)."""
    mdir = gtlib.GT_HOME / 'mainnet'
    (mdir / 'earn.cmd').write_text(earn_cmd(names, mdir) + '\n')
    for pat in ('stallwatch.py --match gt_earn.py', 'playbooks/gt_earn.py --wallet'):   # watchdog first: no relaunch race
        r = subprocess.run(['pgrep', '-f', pat], capture_output=True, text=True)
        for pid in [int(x) for x in r.stdout.split()]:
            if pid != os.getpid():
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        time.sleep(5)
    done = mdir / 'earn.DONE'
    if done.exists():                               # a stopped job is not a finished one
        done.rename(mdir / f'earn.DONE.prev-{int(time.time())}')
    rdir = gtlib.GT_HOME / 'runs' / EARN_RUN
    m = f"gt_earn.py --wallet {','.join(names)}"
    subprocess.Popen(['nice', '-n', '15', sys.executable, '-I', str(ROOT / 'harness/kit/stallwatch.py'), '--match', m,
                      '--cmd-file', str(mdir / 'earn.cmd'), '--work', str(rdir / 'events.jsonl'), '--work',
                      str(rdir / f'pow_{names[-1]}.json'), '--done', str(done), '--stall-s', '3600',
                      '--log', str(mdir / 'earn.watch.log')], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True)
    run.event('earn_restarted', wallets=names)


def settled(names):
    """the settled wallet balances from the earn log (gt_trigger.settled_balances) for `names`."""
    import importlib.util as iu
    spec = iu.spec_from_file_location('gt_trigger_l', Path(__file__).resolve().parent / 'gt_trigger.py')
    tg = iu.module_from_spec(spec)
    spec.loader.exec_module(tg)
    ef = gtlib.GT_HOME / 'runs' / EARN_RUN / 'events.jsonl'
    rows = [json.loads(x) for x in ef.read_text().splitlines() if x.strip()] if ef.exists() else []
    h = int(rpc_call(gtlib.NETWORKS['mainnet']['daemon'], 'DERO.GetInfo')['height'])
    bal = tg.settled_balances(rows, h) or {}
    return {n: int(bal.get(n) or 0) for n in names}, ladder_fees(tg.measured_fees())


GT_AUDIT_INSTALL_FEE = 14805     # r32a sim pre-flight: the gt_audit install fee (size-based, so the same formula on mainnet)


def ladder_fees(measured):
    """(fee per call, fee per install, source): never below what the r32a cycle code pays — storage-heavy calls pay at
    least gt_cycle.STORAGE_FEE_FLOOR (600; the pre-flight's median call) and the ladder installs gt_audit too. Pure."""
    import importlib.util as iu
    spec = iu.spec_from_file_location('gt_cycle_l', Path(__file__).resolve().parent / 'gt_cycle.py')
    cy = iu.module_from_spec(spec)
    spec.loader.exec_module(cy)
    fc, fi, src = measured
    return max(int(fc), cy.STORAGE_FEE_FLOOR), max(int(fi), GT_AUDIT_INSTALL_FEE), f'{src} (floors: call {cy.STORAGE_FEE_FLOOR}, install {GT_AUDIT_INSTALL_FEE})'


def step_plan(n, bal, fees, deployed=False):
    """the sized plan for step n with the balances it needs (the deploying step pays the whole setup). Pure apart from
    sizing."""
    fc, fi, src = fees
    r = sizing.plan_n_wallet(n, fc, fi, bal, deployed=deployed)
    if r['viable']:
        sp = r['viability']['spend_atomic']
        r['needs_atomic'] = {w: int(-(-v // (1 - sizing.SAFETY))) for w, v in sp.items()}
    r.update(fee_call=fc, fee_install=fi, fee_source=src, balances_atomic=bal)
    return r


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--from', dest='lo', type=int, default=3)
    ap.add_argument('--to', dest='hi', type=int, default=5)
    ap.add_argument('--poll', type=int, default=120)
    ap.add_argument('--mainnet-confirm', action='store_true')
    a = ap.parse_args(argv)
    if not a.mainnet_confirm:
        print('the mainnet ladder needs --mainnet-confirm (D-GT-4); nothing done')
        return 5
    run = gtlib.Run(f'{RUN_ID}-driver', 'mainnet', mainnet_confirm=True)
    st = run.state.setdefault('ladder', {'done': [], 'fails': {}})
    mdir = gtlib.GT_HOME / 'mainnet'
    for n in range(a.lo, a.hi + 1):
        if n in st['done']:
            continue
        names = names_for(n)
        while True:
            have = earn_wallets_running()
            if have is None or not set(names) <= set(have):
                restart_earn(run, names)
            bal, fees = settled(names)
            sc = json.loads(lst.read_text()).get('scids', {}) if (lst := gtlib.GT_HOME / 'runs' / RUN_ID / 'state.json').exists() else {}
            plan = step_plan(n, bal, fees, deployed=len(sc) >= 4)
            ready = plan['viable'] and all(bal[w] >= plan['needs_atomic'][w] for w in names)
            run.event('ladder_tick', n=n, viable=plan['viable'], ready=ready,
                      settled_dero={w: f'{v / 1e5:.5f}' for w, v in bal.items()},
                      needs_dero={w: f'{v / 1e5:.5f}' for w, v in (plan.get('needs_atomic') or {}).items()},
                      failing=plan.get('failing_last'))
            if ready:
                break
            time.sleep(a.poll)
        pf = run.dir / f'plan_n{n}.json'
        pf.write_text(json.dumps(plan, indent=1, sort_keys=True) + '\n')
        run.event('ladder_step_start', n=n, plan=plan['plan'])
        before = set((ROOT / 'harness/runtime').glob('gt_cycle_mainnet_*.json'))
        r = subprocess.run(['nice', '-n', '15', sys.executable, '-I', str(ROOT / 'playbooks/gt_cycle.py'), '--network', 'mainnet',
                            '--wallets', ','.join(names), '--mainnet-confirm', '--rebuild', '--plan', str(pf), '--run-id', RUN_ID],
                           cwd=ROOT, capture_output=True, text=True)
        run.event('ladder_cycle_done', n=n, rc=r.returncode, tail=(r.stdout + r.stderr)[-300:])
        if r.returncode == 7:                         # the cycle's own start check: wait and size again
            continue
        if r.returncode != 0:
            st['fails'][str(n)] = st['fails'].get(str(n), 0) + 1
            run.save()
            if st['fails'][str(n)] >= MAX_STEP_FAILS:
                (mdir / 'ladder.STOPPED').write_text(f'step {n}: {MAX_STEP_FAILS} failed cycles; see the ladder events\n')
                run.event('ladder_gave_up', n=n)
                return 4
            continue
        new = sorted(set((ROOT / 'harness/runtime').glob('gt_cycle_mainnet_*.json')) - before)
        if new:
            au = subprocess.run([sys.executable, '-I', str(ROOT / 'harness/gametheory/cycle_audit.py'), '--record',
                                 str(new[-1].relative_to(ROOT)), '--run', RUN_ID], cwd=ROOT, capture_output=True, text=True)
            (run.dir / f'audit_n{n}.json').write_text(au.stdout)
            run.event('ladder_step_audited', n=n, record=new[-1].name, rc=au.returncode)
        st['done'].append(n)
        run.save()
        run.event('ladder_step_done', n=n)
    run.event('ladder_done', steps=st['done'])
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
