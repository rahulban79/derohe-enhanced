#!/usr/bin/env python3
"""time_to_coins.py — r32 (artifacts/dero-game-theory-rft.md D-GT-4): how long a pipeline-owned mainnet miner needs to
earn the DERO the mainnet game needs, from the LIVE network difficulty and our hashrate. Read-only: one DERO.GetInfo on
127.0.0.1:10102 (or --difficulty for an offline estimate); nothing is mined, nothing is sent.

Model (reward_analysis.md §3; reward_anchors RW14/RW17/RW19/RW28): a block has 9 normal miniblocks at difficulty D and
one final at 9D; a normal miniblock pays share = CalcBlockReward(h)/10 to its key. During the normal phase (T_normal
seconds per block) the network's normal-phase hashrate is H = 9 D / T_normal, so a miner hashing h gets a fraction
f = h / (H + h) of the normal slots: 9 f miniblocks per block, Poisson. T_normal and the block time come from the live
reward_intel record (final_phase_ms_mean, block_interval_ms.mean). Our hashrate: h = H_PER_CPU_S x threads x cpu_max/100,
H_PER_CPU_S = 5,344 H per cpu-second, the measured live R30 baseline (94,623.4 H/s at 17.71 cores; dero-rft §0.12 D-22).

  python3 -I harness/gametheory/time_to_coins.py [--threads 8] [--cpu-max 80] [--target-dero 1.0] [--difficulty D] [--write]
"""
import argparse, json, math, sys, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
H_PER_CPU_S = 5344.0           # dero-rft §0.12 D-22: 94,623.4 H/s / 17.71 cores, measured live 2026-11-11/12
OUT = ROOT / 'harness/runtime/gt_time_to_coins.json'


def live_info():
    req = urllib.request.Request('http://127.0.0.1:10102/json_rpc',
                                 json.dumps({'jsonrpc': '2.0', 'id': '1', 'method': 'DERO.GetInfo'}).encode(),
                                 {'Content-Type': 'application/json'})
    return json.load(urllib.request.urlopen(req, timeout=10))['result']


def estimate(D, height, threads, cpu_max, target_dero, block_ms, final_ms):
    reward = 123000 >> ((height + 7000000) // 7000000)          # CalcBlockReward (RW06)
    share = reward // 10
    t_normal = max((block_ms - final_ms) / 1000.0, 1.0)
    H = 9 * D / t_normal
    h = H_PER_CPU_S * threads * cpu_max / 100.0
    f = h / (H + h)
    per_block = 9 * f
    blocks_day = 86400.0 / (block_ms / 1000.0)
    mb_day = per_block * blocks_day
    dero_day = mb_day * share / 100000.0
    need_mb = math.ceil(target_dero * 100000 / share)
    first_s = (block_ms / 1000.0) / per_block
    return {'height': height, 'difficulty': D, 'reward_atomic': reward, 'share_atomic': share,
            't_normal_s': round(t_normal, 2), 'network_normal_hs': round(H), 'our_hs': round(h), 'fraction': round(f, 5),
            'miniblocks_per_block': round(per_block, 4), 'miniblocks_per_day': round(mb_day, 1),
            'dero_per_day': round(dero_day, 3), 'target_dero': target_dero, 'miniblocks_needed': need_mb,
            'expected_first_miniblock_s': round(first_s, 1), 'expected_hours_to_target': round(need_mb / mb_day * 24, 2),
            'p_zero_in_1h': round(math.exp(-mb_day / 24), 6), 'threads': threads, 'cpu_max': cpu_max,
            'h_per_cpu_s': H_PER_CPU_S, 'h_per_cpu_s_source': 'dero-rft §0.12 D-22 (live R30 baseline)'}


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--threads', type=int, default=8)
    ap.add_argument('--cpu-max', type=int, default=80)
    ap.add_argument('--target-dero', type=float, default=1.0)
    ap.add_argument('--difficulty', type=int, default=None)
    ap.add_argument('--height', type=int, default=None)
    ap.add_argument('--write', action='store_true')
    a = ap.parse_args(argv)
    live = json.loads((ROOT / 'harness/runtime/gt_reward_live.json').read_text()).get('aggregate', {})
    block_ms = live.get('block_interval_ms', {}).get('mean') or 18000.0
    final_ms = live.get('final_phase_ms_mean') or 7863.6
    if a.difficulty is None:
        info = live_info()
        D, H = int(info['difficulty']), int(info['height'])
        src = 'live DERO.GetInfo 127.0.0.1:10102 (read-only)'
    else:
        D, H, src = a.difficulty, a.height or 7905379, 'given'
    e = estimate(D, H, a.threads, a.cpu_max, a.target_dero, block_ms, final_ms)
    e['difficulty_source'] = src
    e['phase_source'] = 'harness/runtime/gt_reward_live.json aggregate (block_interval_ms.mean, final_phase_ms_mean)'
    print(json.dumps(e, indent=1))
    if a.write:
        OUT.write_text(json.dumps(e, indent=1, sort_keys=True) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
