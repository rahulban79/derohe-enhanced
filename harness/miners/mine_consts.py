#!/usr/bin/env python3
"""mine_consts.py — the consensus constants and the formulas that use them.

Each entry below declares WHERE a rule lives and WHY it matters. The miner reads the line itself and builds the
claim from the text it found, so the number on the page is the number in the tree. An entry whose needle is no
longer on a line of its file produces no row: it lands in `unverified` with the file it was last seen in.
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):   # r27 B120: usage, exit 0, nothing run or written
    print(__doc__ or 'usage: see the header of this file')
    raise SystemExit(0)
import re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import minelib as M

# (id, section, title, file, needle, role)
SPEC = [
 # ---- block cadence and chain shape
 ('bt',   'cadence', 'Target block time', 'config/config.go', 'const BLOCK_TIME = uint64(18)',
  'The spacing the difficulty controller steers towards. Every emission and difficulty number below is derived from it.'),
 ('btms', 'cadence', 'Block time in milliseconds', 'config/config.go', 'const BLOCK_TIME_MILLISECS = BLOCK_TIME * 1000',
  'The controller works in milliseconds: timestamps are millisecond-resolution, so solve time is too.'),
 ('stab', 'cadence', 'Stable depth', 'config/config.go', 'const STABLE_LIMIT = int64(8)',
  'How far back the chain is considered settled. GetInfo.stableheight is topoheight minus this.'),
 ('mbhd', 'cadence', 'Miniblock high-difficulty divisor', 'config/config.go', 'const MINIBLOCK_HIGHDIFF = 9',
  'A miniblock must meet block difficulty divided by this, so roughly nine miniblocks make one block.'),
 ('mbsz', 'cadence', 'Miniblock wire size', 'block/miniblock.go', 'const MINIBLOCK_SIZE = 48',
  'A miniblock is a fixed 48-byte header. It carries no transactions — only the PoW share and its DAG links.'),
 # ---- emission
 ('rri',  'emission', 'Reward reduction interval', 'blockchain/transaction_execute.go',
  'const RewardReductionInterval = 210000 * 600 / config.BLOCK_TIME',
  "Bitcoin's 210,000-block halving interval rescaled to DERO's block time: 7,000,000 blocks."),
 ('base', 'emission', 'Base block reward', 'blockchain/transaction_execute.go',
  'const BaseReward = (41 * 100000 * config.BLOCK_TIME) / 600',
  "Bitcoin's 41-coin-per-10-minutes epoch rescaled to DERO's block time: 123,000 atomic units per block."),
 ('calc', 'emission', 'Halving formula', 'blockchain/transaction_execute.go',
  'return BaseReward >> ((height + RewardReductionInterval) / RewardReductionInterval)',
  'The subsidy halves by an arithmetic right shift. The +1 epoch offset wipes the first interval, halving total supply.'),
 ('share', 'emission', 'Reward split across miniblocks', 'blockchain/transaction_execute.go',
  'share := full_reward / uint64(len(bl.MiniBlocks))',
  'Base reward plus fees is divided equally among the block’s miniblocks: one share per accepted PoW share.'),
 ('left', 'emission', 'Integer-division leftover', 'blockchain/transaction_execute.go',
  'leftover := full_reward - (share * uint64(len(bl.MiniBlocks)))',
  'Integer division loses change; the whole remainder goes to the integrator who assembled the block.'),
 ('prem', 'emission', 'Premine / old-chain supply', 'config/config.go', 'const PREMINE uint64 = 1228125400000',
  'The balance carried over from the pre-HE chain, counted in the total supply GetInfo reports.'),
 # ---- difficulty controller
 ('e',    'difficulty', "Euler's number, hard-coded", 'blockchain/difficulty.go', 'const E = float64(2.71828182845905)',
  'The controller is exponential, so e is a literal. Fifteen digits: the float64 the algorithm is defined against.'),
 ('diff', 'difficulty', 'The difficulty law', 'blockchain/difficulty.go',
  'easypart := int64(math.Pow(E, ((1-float64(solvetime)/float64(blocktime))/float64(M))) * 10000)',
  'next = prev * e^((1 - solvetime/blocktime)/M), in fixed point with 10,000 as the scale.'),
 ('m',    'difficulty', 'Smoothing factor M', 'blockchain/difficulty.go', 'M := int64(8)',
  'The damping constant. A block solved instantly can raise difficulty by at most e^(1/8) = 1.133x.'),
 ('clamp', 'difficulty', 'Solve-time clamp', 'blockchain/difficulty.go', 'if solve_time > (block_time * 2) {',
  'Solve time is capped at twice the block time, so one slow block cannot collapse difficulty.'),
 ('mind', 'difficulty', 'Difficulty floor', 'blockchain/difficulty.go', 'if difficulty.Cmp(MinimumDifficulty) < 0 {',
  'Difficulty can never fall below the network minimum, whatever the timestamps say.'),
 ('tip3', 'difficulty', 'Bootstrap guard', 'blockchain/difficulty.go', 'if height < 3 {',
  'With fewer than three blocks there is no parent interval to measure, so genesis difficulty stands.'),
 # ---- transaction limits
 ('minr', 'tx', 'Minimum ring size', 'config/config.go', 'const MIN_RINGSIZE = 2',
  'The smallest anonymity set. Ring size 2 is the ordinary two-party transfer.'),
 ('maxr', 'tx', 'Maximum ring size', 'config/config.go', 'const MAX_RINGSIZE = 128',
  'The largest anonymity set the verifier accepts; proof size and verification cost grow with it.'),
 ('fee',  'tx', 'Fee per kilobyte', 'config/config.go', 'const FEE_PER_KB = uint64(20)',
  'Twenty atomic units per kilobyte — 0.00020 DERO/KB.'),
 ('txsz', 'tx', 'Maximum transaction size', 'config/config.go', 'const STARGATE_HE_MAX_TX_SIZE = 300 * 1024',
  'A single transaction may not exceed 300 KB on the wire.'),
 ('blsz', 'tx', 'Maximum block size', 'config/config.go', 'const STARGATE_HE_MAX_BLOCK_SIZE',
  'Block size ceiling: 10 MB plus 256 KB of headroom.'),
 ('gas',  'tx', 'Storage gas ceiling', 'config/config.go', 'const MAX_STORAGE_GAS_ATOMIC_UNITS = 20000',
  'The most storage gas one smart-contract call may consume.'),
 # ---- state trees
 ('btree', 'state', 'Balance tree name', 'config/config.go', 'const BALANCE_TREE = "B"',
  'The graviton tree holding every account’s homomorphically encrypted balance, keyed by public key.'),
 ('scmeta', 'state', 'SC metadata tree name', 'config/config.go', 'const SC_META = "M"',
  'One tree holds every contract’s balance, code, owner and the root hash of its own data tree.'),
 # ---- hard forks
 ('hf1',  'hardfork', 'HF1 height', 'config/config.go', 'HF1_HEIGHT:              21480', 'First hard fork on mainnet.'),
 ('hf2',  'hardfork', 'HF2 height', 'config/config.go', 'HF2_HEIGHT:              29000', 'Second hard fork on mainnet.'),
 ('mhf2', 'hardfork', 'Major HF2 height', 'config/config.go', 'MAJOR_HF2_HEIGHT:        481600',
  'Major fork 2. The difficulty controller is pinned to genesis difficulty for three blocks across it.'),
 ('mhf3', 'hardfork', 'Major HF3 height', 'config/config.go', 'MAJOR_HF3_HEIGHT:        7504640',
  'Major fork 3 — the fork this node crossed. Nodes that did not upgrade continue on a separate v2 chain.'),
 ('ver',  'hardfork', 'Declared version', 'config/version.go', 'var Version = semver.MustParse(',
  'The version derod prints at start-up and reports in GetInfo; peers compare it during the handshake.'),
 # ---- network identity and ports
 ('nid',  'network', 'Mainnet network id', 'config/config.go', 'Network_ID:              uuid.FromBytesOrNil',
  'The UUID that separates mainnet from testnet traffic in the P2P handshake.'),
 ('gw',   'network', 'GETWORK port', 'config/config.go', 'GETWORK_Default_Port:    10100',
  'Where miners connect for work. Not the JSON-RPC port — a wallet pointed here gets no answer.'),
 ('rpcp', 'network', 'JSON-RPC port', 'config/config.go', 'RPC_Default_Port:        10102',
  'The daemon JSON-RPC and websocket port. This is what a wallet must be given.'),
 ('wrpc', 'network', 'Wallet RPC port', 'config/config.go', 'Wallet_RPC_Default_Port: 10103',
  'Where dero-wallet-cli serves its own RPC when asked to.'),
 ('rem',  'network', 'Default remote daemon', 'config/config.go', 'const REMOTE_DAEMON = "node.derofoundation.org:11012"',
  'What --remote resolves to in the wallet. A different port again: 11012.'),
 ('dev',  'network', 'Dev / fallback integrator address', 'config/config.go', 'Dev_Address:             "dero1qykyta6',
  'Where the integrator reward goes when the operator gives no --integrator-address.'),
]


def main():
    rows, unv = [], []
    for cid, sec, title, f, needle, role in SPEC:
        a = M.anchor(f, needle, full_line=True)
        if not a:
            unv.append({'title': title, 'why': f'needle no longer on any line of {f}: {needle[:60]}'})
            continue
        raw = a['quote']
        val = None
        m = re.search(r'=\s*(.+?)\s*(?://.*)?$', raw) or re.search(r':\s*(.+?),?\s*(?://.*)?$', raw)
        if m:
            val = m.group(1).rstrip(',').strip()
        rows.append({'id': f'const-{cid}', 'section': sec, 'title': title, 'class': 'SRC',
                     'claim': (f'{raw}  —  {role}' if val is None else f'{title} = {val}. {role}'),
                     'name': title, 'value': val or raw, 'where': f'{f}:{a["line"]}', 'role': role,
                     'evidence': [a]})
    M.emit('consts', rows, unv, 'mine_consts.py')


if __name__ == '__main__':
    main()
