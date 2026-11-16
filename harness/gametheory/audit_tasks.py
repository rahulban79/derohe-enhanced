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
The answer is the 64-hex digest (lowercase, as the DVM's HEX(SHA256()) writes it).

READ-ONLY JSON-RPC 10102 (reward_intel.Rpc, <= 4 requests/s); never below PRUNED_FLOOR (7,498,540); `upto` must be at
least SETTLE blocks below the tip (a range a reorg can still change is refused); at most MAX_SPAN heights. Miner keys
are hashed in memory and never written.

  python3 -I harness/gametheory/audit_tasks.py --task 1 --from H --upto H2      # prints {"task", "answer", "summary"}
Exit 0 · 2 refused (pruned floor / not settled / span) · 3 RPC error.
"""
import argparse, hashlib, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import reward_intel as RI  # noqa: E402

SETTLE = 20
MAX_SPAN = 100
TASKS = {1: 'headers', 2: 'emission'}


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


def compute(task, lo, hi, rpc=None, root=RI.ROOT, floor=RI.PRUNED_FLOOR):
    rpc = rpc or RI.Rpc()
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
    ap.add_argument('--from', dest='lo', type=int, required=True)
    ap.add_argument('--upto', dest='hi', type=int, required=True)
    a = ap.parse_args(argv)
    try:
        out, why = compute(a.task, a.lo, a.hi)
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
