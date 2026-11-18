#!/usr/bin/env python3
"""audit_tasks.py — r32a: the deterministic answers an auditor computes for a gt_audit bounty round.

Why: research (scratchpad r32a/research_web.md §Q3-Q4; security_inventory.md group 1-2): a smart contract cannot check
consensus, see the miner or find value an unsound proof created, but a game CAN pay independent nodes to re-derive
public facts and to raise an alarm when the sponsor's answer is wrong (detection, not prevention). Every honest full
node computes the same answer for a settled height range, so the sponsor's hidden answer and each auditor's must match;
a strict majority against the sponsor is the contract's dispute signal (gt_audit.bas Settle).

Tasks (the contract does not interpret them; the playbook and every auditor agree on the id):
  1 headers   sha256 over one line per height  "<h>:<block hash>:<topoheight>:<sha256(miner keys joined '|')>"
              — an auditor that answers correctly has read and validated the same chain as the sponsor (peer/chain
              validation by independent nodes)
  2 emission  sha256 over one line per height  "<h>:<header reward>:<code reward>:<ok 0|1>" then "total:<sum>:<bad>"
              — the base reward per block re-derived from the Go constants (reward_intel.constants, anchored lines)
              and compared with what each header carries (coin-supply integrity, the auditable part of it)
  3 turnstile sha256 over one line per SCID (lowercase, sorted, duplicates dropped)  "<scid>:<DERO balance>" then
              "total:<sum>:<n>" at ONE settled topoheight (DERO.GetSC with topoheight; r33 GT-B15, the SC balance
              turnstile) — the DERO held by the listed contracts, which every node computes alike from the same state
              snapshot; the sponsor's sum against the auditors' is the alarm when a contract's balance was moved
The answer is the 64-hex digest (lowercase, as the DVM's HEX(SHA256()) writes it).

READ-ONLY JSON-RPC 10102 (reward_intel.Rpc, <= 4 requests/s); never below PRUNED_FLOOR (7,498,540); `upto` must be at
least SETTLE blocks below the tip (a range a reorg can still change is refused); at most MAX_SPAN heights. Task 3
applies the same rules to its one topoheight (>= PRUNED_FLOOR, <= the tip topoheight - SETTLE) and takes 1..MAX_SCIDS
64-hex SCIDs. Miner keys are hashed in memory and never written.

  python3 -I harness/gametheory/audit_tasks.py --task 1 --from H --upto H2      # prints {"task", "answer", "summary"}
  python3 -I harness/gametheory/audit_tasks.py --task 3 --scids S1,S2 --topoheight T
Exit 0 · 2 refused (pruned floor / not settled / span / bad SCID) · 3 RPC error.
"""
import argparse, hashlib, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import reward_intel as RI  # noqa: E402

SETTLE = 20
MAX_SPAN = 100
MAX_SCIDS = 32
TASKS = {1: 'headers', 2: 'emission', 3: 'turnstile'}


def headers_answer(blocks):
    """blocks: [{'height', 'hash', 'topoheight', 'miners'}] in height order -> 64-hex answer. Pure."""
    lines = [f"{b['height']}:{b['hash']}:{b['topoheight']}:{hashlib.sha256('|'.join(b.get('miners') or []).encode()).hexdigest()}"
             for b in blocks]
    return hashlib.sha256('\n'.join(lines).encode()).hexdigest()


def emission_answer(blocks, c):
    """blocks: [{'height', 'reward'}] -> (64-hex answer, summary). The code reward is BaseReward >> ((h+RRI)/RRI). Pure."""
    lines, total, bad = [], 0, 0
    for b in blocks:
        want = RI.calc_block_reward(int(b['height']), c)
        ok = int(b['reward']) == want
        bad += 0 if ok else 1
        total += int(b['reward'])
        lines.append(f"{b['height']}:{int(b['reward'])}:{want}:{int(ok)}")
    lines.append(f'total:{total}:{bad}')
    return hashlib.sha256('\n'.join(lines).encode()).hexdigest(), {'blocks': len(blocks), 'total_reward': total, 'mismatches': bad}


def norm_scids(scids):
    """the canonical SCID list of task 3: lowercase, sorted, duplicates dropped (the answer cannot depend on the order an
    auditor lists them). Pure."""
    return sorted({str(s).strip().lower() for s in scids or [] if str(s).strip()})


def turnstile_answer(balances):
    """balances: {scid: DERO balance (atomic)} -> (64-hex answer, summary). Pure."""
    bal = {str(k).strip().lower(): int(v) for k, v in balances.items()}
    ids = norm_scids(bal)
    lines = [f'{s}:{bal[s]}' for s in ids]
    total = sum(bal[s] for s in ids)
    lines.append(f'total:{total}:{len(ids)}')
    return hashlib.sha256('\n'.join(lines).encode()).hexdigest(), {'scids': len(ids), 'total_balance': total}


def refuse_topo(topo, tip_topo, scids, floor=RI.PRUNED_FLOOR):
    """the refusal text for task 3, or None: the same pruned floor and settle depth as tasks 1-2, on topoheight
    (topoheight 0 would mean 'the tip' to DERO.GetSC, so the floor is at least 1). Pure."""
    ids = norm_scids(scids)
    if topo < max(floor, 1):
        return f'topoheight {topo} is below the pruned floor {max(floor, 1)}'
    if topo > tip_topo - SETTLE:
        return f'topoheight {topo} is not settled (tip topoheight {tip_topo}, needs {SETTLE} below)'
    if not ids:
        return 'no SCID given'
    if len(ids) > MAX_SCIDS:
        return f'{len(ids)} SCIDs > {MAX_SCIDS}'
    bad = [s for s in ids if len(s) != 64 or any(ch not in '0123456789abcdef' for ch in s)]
    if bad:
        return f'{len(bad)} SCID(s) are not 64 hex digits'
    return None


def fetch_balances(rpc, scids, topo):
    """{scid: DERO balance} at topoheight `topo` (DERO.GetSC, no code, no variables)."""
    return {s: int(rpc('DERO.GetSC', {'scid': s, 'code': False, 'variables': False, 'topoheight': int(topo)}).get('balance') or 0)
            for s in norm_scids(scids)}


def refuse(lo, hi, tip, floor=RI.PRUNED_FLOOR):
    """the refusal text for a range, or None (floor 0 only on a private sim chain, where there is no pruned history).
    Pure."""
    if lo < floor:
        return f'from {lo} is below the pruned floor {floor}'
    if hi < lo:
        return 'upto < from'
    if hi - lo + 1 > MAX_SPAN:
        return f'span {hi - lo + 1} > {MAX_SPAN}'
    if hi > tip - SETTLE:
        return f'upto {hi} is not settled (tip {tip}, needs {SETTLE} blocks below)'
    return None


def fetch(rpc, lo, hi):
    out = []
    for h in range(lo, hi + 1):
        bh = rpc('DERO.GetBlock', {'height': h})['block_header']
        out.append({'height': int(bh['height']), 'hash': bh['hash'], 'topoheight': int(bh['topoheight']),
                    'miners': list(bh.get('miners') or []), 'reward': int(bh.get('reward', 0))})
    return out


def compute(task, lo, hi, rpc=None, root=RI.ROOT, floor=RI.PRUNED_FLOOR, scids=None, topo=None):
    """tasks 1-2 over heights [lo, hi]; task 3 over `scids` at topoheight `topo` (lo/hi unused)."""
    rpc = rpc or RI.Rpc()
    if task == 3:
        tip_topo = int(rpc('DERO.GetInfo')['topoheight'])
        topo = int(topo if topo is not None else -1)
        why = refuse_topo(topo, tip_topo, scids, floor)
        if why:
            return None, why
        ans, summ = turnstile_answer(fetch_balances(rpc, scids, topo))
        return {'task': 3, 'name': TASKS[3], 'topoheight': topo, 'scids': norm_scids(scids), 'answer': ans,
                'summary': summ, 'tip_topoheight': tip_topo}, None
    tip = int(rpc('DERO.GetInfo')['height'])
    why = refuse(lo, hi, tip, floor)
    if why:
        return None, why
    blocks = fetch(rpc, lo, hi)
    if task == 1:
        ans, summ = headers_answer(blocks), {'blocks': len(blocks)}
    elif task == 2:
        ans, summ = emission_answer(blocks, RI.constants(root)[0])
    else:
        return None, f'unknown task {task}'
    return {'task': task, 'name': TASKS[task], 'from': lo, 'upto': hi, 'answer': ans, 'summary': summ, 'tip': tip}, None


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--task', type=int, required=True, choices=sorted(TASKS))
    ap.add_argument('--from', dest='lo', type=int, default=None, help='tasks 1-2: first height')
    ap.add_argument('--upto', dest='hi', type=int, default=None, help='tasks 1-2: last height')
    ap.add_argument('--scids', default='', help='task 3: comma-separated 64-hex SCIDs')
    ap.add_argument('--topoheight', type=int, default=None, help='task 3: the settled topoheight')
    a = ap.parse_args(argv)
    if a.task in (1, 2) and (a.lo is None or a.hi is None):
        ap.error(f'task {a.task} needs --from and --upto')
    if a.task == 3 and (a.topoheight is None or not a.scids):
        ap.error('task 3 needs --scids and --topoheight')
    try:
        out, why = compute(a.task, a.lo, a.hi, scids=a.scids.split(','), topo=a.topoheight)
    except (RuntimeError, OSError) as e:
        print(f'audit_tasks: RPC error {type(e).__name__}')
        return 3
    if why:
        print(f'audit_tasks: refused: {why}')
        return 2
    text = json.dumps(out, sort_keys=True)
    if RI.ADDR_RX.search(text):
        print('audit_tasks: refused: an address would be printed')
        return 6
    print(text)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
