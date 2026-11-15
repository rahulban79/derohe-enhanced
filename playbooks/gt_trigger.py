#!/usr/bin/env python3
"""gt_trigger.py — r32 D-GT-8: start the two-wallet MAINNET game as soon as m1 and m2 each hold >= 1.00000 DERO of
SETTLED balance, with stakes from the D-GT-8 viability gate (harness/gametheory/sizing.py plan_two_wallet). No LLM.

Maturity (verified in code): a miniblock's share is added to the key's encrypted balance when its block executes
(blockchain/transaction_execute.go:142 integrator, :157 each normal miniblock); there is no coinbase lock (the wallet's
locked balance is always 0, walletapi/wallet.go:280-288). A balance is SETTLED here when the wallet read was taken at
a height at least STABLE_LIMIT = 8 (config/config.go:79; stable height = height - 8, blockchain/blockchain.go:1201)
below the current height, so a side-block reorg can no longer remove the credit it counts.
The trigger reads the earn run's events (wallet balances at each rotation end + the chain-credited scan); mining keeps
running. When both are settled and >= the threshold it writes harness/runtime/gt_plan_mainnet.json (plan + gate) and,
if the gate passes, runs playbooks/gt_cycle.py --network mainnet --plan ...; if it refuses, it records why and the
smallest budget at which a plan passes and keeps waiting for it.

  python3 -I playbooks/gt_trigger.py --mainnet-confirm [--threshold 100000] [--poll 60]   (run it under stallwatch)
  stallwatch: --match 'gt_trigger.py --mainnet-con' --cmd-file trigger.cmd --work runs/r32-mainnet-trigger/events.jsonl
      --done mainnet/trigger.DONE --stop mainnet/trigger.STOPPED --stall-s 1800   (a give-up writes trigger.STOPPED:
      a deliberate exit 4 is never relaunched)
"""
import argparse, datetime, json, subprocess, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gtlib  # noqa: E402
from gtlib import rpc_call  # noqa: E402

ROOT = gtlib.ROOT
sys.path.insert(0, str(ROOT / 'harness' / 'gametheory'))
import sizing  # noqa: E402

EARN = gtlib.GT_HOME / 'runs' / 'r32-mainnet-earn' / 'events.jsonl'
STABLE_LIMIT = 8
FEE_CALL_EST, FEE_INSTALL_EST = 336, 1000      # sizing.fee_per_call / deploy estimate until a mainnet record exists


def settled_balances(rows, height_now):
    """{wallet: atomic} from the newest earn_balances whose preceding earn_tick height is <= height_now - 8. Pure."""
    last_h, out = None, None
    for r in rows:
        if r.get('kind') == 'earn_tick':
            last_h = r.get('height')
        elif r.get('kind') == 'earn_balances' and last_h is not None and last_h <= height_now - STABLE_LIMIT:
            out = {k: v for k, v in (r.get('wallet_balance') or {}).items()}
    return out


def measured_fees():
    """(fee per call, fee per install) from the newest mainnet cycle record, else the estimates."""
    recs = sorted((ROOT / 'harness/runtime').glob('gt_cycle_mainnet_*.json'))
    if not recs:
        return FEE_CALL_EST, FEE_INSTALL_EST, 'estimate'
    calls = json.loads(recs[-1].read_text()).get('calls', [])
    inv = [c['fee'] for c in calls if c.get('fee') and c.get('entry') != 'install']
    ins = [c['fee'] for c in calls if c.get('fee') and c.get('entry') == 'install']
    return (max(inv) if inv else FEE_CALL_EST, max(ins) if ins else FEE_INSTALL_EST, recs[-1].name)


MAX_CYCLE_FAILS = 3


def give_up(fails, cap=MAX_CYCLE_FAILS):
    """r32 run-8 lesson: a failed cycle is retried at the next poll, but not without bound (every retry re-spends setup
    fees from the game budget); after `cap` failures in a row the trigger stops and records why."""
    return fails >= cap


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--mainnet-confirm', action='store_true')
    ap.add_argument('--threshold', type=int, default=100000)
    ap.add_argument('--poll', type=int, default=60)
    ap.add_argument('--once', action='store_true')
    a = ap.parse_args(argv)
    run = gtlib.Run('r32-mainnet-trigger', 'mainnet', mainnet_confirm=a.mainnet_confirm)
    if not a.mainnet_confirm:
        print('the mainnet trigger needs --mainnet-confirm (D-GT-4/8)')
        return 5
    fails = 0
    while True:
        h = int(rpc_call(gtlib.NETWORKS['mainnet']['daemon'], 'DERO.GetInfo')['height'])
        rows = [json.loads(l) for l in EARN.read_text().splitlines() if l.strip()] if EARN.exists() else []
        bal = settled_balances(rows, h) or {}
        subprocess.run([sys.executable, '-I', str(ROOT / 'harness/gametheory/cycle_from_earn.py')], capture_output=True)
        ready = all(int(bal.get(w) or 0) >= a.threshold for w in ('m1', 'm2'))
        run.event('trigger_tick', height=h, settled_dero={w: f'{int(v or 0) / 1e5:.5f}' for w, v in bal.items()}, ready=ready)
        if ready:
            fc, fi, src = measured_fees()
            budget = min(int(bal['m1']), int(bal['m2']))
            plan = sizing.plan_two_wallet(fc, fi, budget)
            plan.update({'threshold_atomic': a.threshold, 'fee_call': fc, 'fee_install': fi, 'fee_source': src,
                         'budget_each_atomic': budget, 'decided_at': datetime.datetime.now().astimezone().isoformat(timespec='seconds')})
            pf = ROOT / 'harness/runtime/gt_plan_mainnet.json'
            pf.write_text(json.dumps(plan, indent=1, sort_keys=True) + '\n')
            run.event('viability', viable=plan['viable'], plan=plan.get('plan'), min_budget=plan.get('min_budget_each_atomic'))
            if plan['viable']:
                r = subprocess.run(['nice', '-n', '15', sys.executable, '-I', str(ROOT / 'playbooks/gt_cycle.py'), '--network',
                                    'mainnet', '--wallets', 'm1,m2', '--mainnet-confirm', '--rebuild', '--plan', str(pf)],
                                   cwd=ROOT, capture_output=True, text=True)
                run.event('cycle_done', rc=r.returncode, tail=(r.stdout + r.stderr)[-300:])
                if r.returncode == 0:
                    return 0
                fails += 1
                if give_up(fails):
                    run.event('trigger_gave_up', fails=fails, reason=f'{fails} failed cycles in a row; each retry re-spends fees')
                    (gtlib.GT_HOME / 'mainnet' / 'trigger.STOPPED').write_text(f'{fails} failed cycles in a row; see trigger events\n')
                    return 4
            else:
                a.threshold = max(a.threshold, int(plan.get('min_budget_each_atomic') or a.threshold))
                run.event('trigger_raised', threshold=a.threshold, reason=plan.get('reason'))
        if a.once:
            return 3
        time.sleep(a.poll)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
