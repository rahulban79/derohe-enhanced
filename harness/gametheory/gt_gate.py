#!/usr/bin/env python3
"""gt_gate.py — r32 gate G35 (artifacts/dero-game-theory-rft.md §0.2): the game-theory layer is proven and private.

G35 passes iff
  1. harness/runtime/gt_pipeline_last.json exists, is at most MAX_AGE_DAYS old, and every stage it ran PASSED, with the
     research, discovery, implementation, debug and enhancement stages among them (the playbook stage too);
  2. every econsim check in it is ok;
  3. every GO mechanism of gametheory/mechanisms.json has its contract file, and every NO-GO entry carries a reason;
  4. no banned address (banguard, D-GT-2) occurs in gametheory/, playbooks/, harness/gametheory/, the child rft or the
     game-theory artifact page; where the private ban file is absent (a public clone) this part is labelled SKIPPED.

  python3 -I harness/gametheory/gt_gate.py      prints the verdict; exit 0 PASS · 3 FAIL
"""
import datetime, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import banguard  # noqa: E402

MAX_AGE_DAYS = 14
NEED = ('research', 'discovery', 'implementation', 'debug', 'enhancement', 'playbook')
SCAN = ['gametheory', 'playbooks', 'harness/gametheory', 'artifacts/dero-game-theory-rft.md',
        'artifacts/dero-enhanced-game-theory.html']


def g35(root=ROOT, now=None):
    root = Path(root)
    now = now or datetime.datetime.now().astimezone()
    why = []
    lp = root / 'harness/runtime/gt_pipeline_last.json'
    try:
        last = json.loads(lp.read_text())
    except (OSError, ValueError):
        return False, 'no gt_pipeline record (run harness/gametheory/gt_pipeline.py)'
    try:
        ts = datetime.datetime.strptime(last['ts'], '%Y%m%dT%H%M%S').astimezone()
        if (now - ts).days > MAX_AGE_DAYS:
            why.append(f"record {last['ts']} older than {MAX_AGE_DAYS} days")
    except (KeyError, ValueError):
        why.append('record without a timestamp')
    v = last.get('verdict', {})
    missing = [s for s in NEED if s not in v]
    failed = [s for s, ok in v.items() if not ok]
    if missing:
        why.append(f'stages not run: {missing}')
    if failed:
        why.append(f'stages failed: {failed}')
    checks = last.get('econsim_checks') or []
    bad = [c['check'] for c in checks if not c.get('ok')]
    if not checks:
        why.append('no econsim checks in the record')
    if bad:
        why.append(f'econsim checks failed: {bad[:3]}')
    try:
        mech = json.loads((root / 'gametheory/mechanisms.json').read_text())['mechanisms']
    except (OSError, ValueError, KeyError):
        mech = []
        why.append('gametheory/mechanisms.json unreadable')
    for m in mech:
        if m.get('status') == 'GO' and not (root / 'gametheory/contracts' / m.get('contract', '?')).exists():
            why.append(f"{m['id']}: contract file missing")
        if m.get('status') == 'NO-GO' and not m.get('reason'):
            why.append(f"{m['id']}: NO-GO without a reason")
    scan = 'SKIPPED (no private ban file)'
    try:
        hs = banguard.load_hashes()
        hits = []
        for rel in SCAN:
            p = root / rel
            files = [p] if p.is_file() else [f for f in p.rglob('*') if f.is_file() and f.suffix in ('.py', '.go', '.bas', '.json', '.md', '.html', '.txt')] if p.exists() else []
            for f in files:
                if banguard.scan_text(f.read_text(errors='ignore'), hs):
                    hits.append(str(f.relative_to(root)))
        scan = f'{len(hits)} banned-address file(s)'
        if hits:
            why.append(f'banned address in {hits[:3]}')
    except (OSError, ValueError):
        pass
    det = (f"record {last.get('ts')} stages {sum(1 for x in v.values() if x)}/{len(v)} · econsim "
           f"{len(checks) - len(bad)}/{len(checks)} · mechanisms {len(mech)} · scan {scan}")
    return (not why), det + ('' if not why else ' · ' + '; '.join(why))



# r32 G36 (the user, 2026-11-15: "i need a working real solution and not just simulation"; child rft D-GT-5): the round
# is DONE only when one full MAINNET cycle is measured end to end. Report-only (INFO) until then, with the blocker.
CYCLE = ('registered', 'mined_credited', 'roles_funded', 'contract_deployed', 'game_settled')


def g36(root=ROOT):
    p = Path(root) / 'harness/runtime/gt_mainnet_cycle.json'
    try:
        c = json.loads(p.read_text())
    except (OSError, ValueError):
        return 'INFO', 'IN PROGRESS: no mainnet cycle record (harness/runtime/gt_mainnet_cycle.json)'
    steps = c.get('steps', {})
    done = [s for s in CYCLE if (steps.get(s) or {}).get('status') == 'measured' and (steps.get(s) or {}).get('evidence')]
    if len(done) == len(CYCLE):
        # r32 run 9: game_settled stands only with the chain audit of the same record (entrants read from the contract,
        # mining taken out of the payoffs, payoffs summing to -fees); a record's own verdict is not enough
        try:
            au = json.loads((Path(root) / 'harness/runtime/gt_cycle_audit_mainnet.json').read_text())
        except (OSError, ValueError):
            return 'INFO', 'IN PROGRESS: mainnet cycle 5/5 recorded; game_settled awaits the chain audit (cycle_audit.py --write)'
        ev = (steps.get('game_settled') or {}).get('evidence')
        if au.get('record') != ev or not au.get('game_settled') or not (au.get('sum_check') or {}).get('ok'):
            return 'INFO', (f"IN PROGRESS: the chain audit does not confirm game_settled (record {au.get('record')} vs {ev}, "
                            f"settled {au.get('game_settled')}, sum_check {(au.get('sum_check') or {}).get('ok')})")
        return True, (f"mainnet cycle measured {len(done)}/{len(CYCLE)}; chain audit: genuine rounds {au.get('genuine_rounds')}, "
                      f"solo {au.get('solo_rounds')}, net payoff {au.get('net_game_payoff_atomic')}, fees {au.get('fees_total_atomic')}")
    nxt = next(s for s in CYCLE if s not in done)
    return 'INFO', (f"IN PROGRESS: mainnet cycle {len(done)}/{len(CYCLE)} measured; next {nxt}; blocker: "
                    f"{(steps.get(nxt) or {}).get('blocker') or c.get('blocker') or 'pending'}")


if __name__ == '__main__':
    if {'-h', '--help'} & set(sys.argv[1:]):
        print(__doc__)
        sys.exit(0)
    ok, det = g35()
    print(('PASS' if ok else 'FAIL') + '  G35 ' + det)
    ok36, det36 = g36()
    print(('PASS' if ok36 is True else 'INFO') + '  G36 ' + det36)
    sys.exit(0 if ok else 3)
