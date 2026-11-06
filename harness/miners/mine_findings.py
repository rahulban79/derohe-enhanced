#!/usr/bin/env python3
"""mine_findings.py — the analysis rows: what reading the code together with the running node established.

Every finding below is a claim ABOUT several source lines, so each carries all of them as anchors and renders
only if they all still resolve. Numbers that follow from constants (difficulty step bounds, the current block
reward) are COMPUTED here from the values the source declares, never typed in, so they cannot drift.
"""
if __name__ == '__main__' and {'-h', '--help'} & set(__import__('sys').argv[1:]):   # r27 B120: usage, exit 0, nothing run or written
    print(__doc__ or 'usage: see the header of this file')
    raise SystemExit(0)
import math, re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import minelib as M

TE = 'blockchain/transaction_execute.go'
BC = 'blockchain/blockchain.go'
SIM = 'dvm/simulator.go'
GRAV = 'vendor/github.com/deroproject/graviton/node_leaf.go'
CTL = 'p2p/controller.go'
CFG = 'config/config.go'


def val(f, needle, cast=int):
    """Read a number out of the source line that declares it — never retype it here.

    The number must come from inside the type conversion: a loose \\d+ on `M := int64(8)` matches the 64 in
    int64 and silently yields a difficulty bound computed with the wrong damping factor (KAT DK12 caught
    exactly that on 2026-10-20).
    """
    a = M.anchor(f, needle, full_line=True)
    if not a:
        return None
    q = a['quote']
    m = (re.search(r'(?:u?int(?:8|16|32|64)?|float(?:32|64)?)\(\s*([\d_.]+)\s*\)', q)
         or re.search(r'[:=]=?\s*([\d_.]+)\b', q)
         or re.search(r'([\d_.]+)', q))
    return cast(m.group(1).replace('_', '')) if m else None


def main():
    rows, unv = [], []

    def F(fid, section, title, severity, claim, anchors, **extra):
        evs = []
        for f, needle in anchors:
            a = M.anchor(f, needle, full_line=True)
            if not a:
                unv.append({'title': title, 'why': f'anchor lost: {f} :: {needle[:70]}'})
                return
            evs.append(a)
        rows.append({'id': fid, 'section': section, 'title': title, 'severity': severity,
                     'class': 'EXT' if all(f.startswith('vendor/') for f, _ in anchors) else 'SRC',
                     'claim': claim, 'evidence': evs, **extra})

    # ---------- F1/F2: the SC revert path the live node walked at 13:37:02
    F('find-screvert', 'findings', 'The "burn all the funds" branch burns by panicking', 'defect',
      'Both arms of the failure branch in process_transaction_sc call dvm.ErrorRevert with the same arguments. '
      'In the else arm Extract_signer has already failed, so `signer` is still the zero [33]byte. ErrorRevert '
      'reads that key, graviton cannot find it, and simulator.go panics on an error its own comment says only '
      'disk corruption can produce. The recover installed at the top of process_transaction_sc catches it. By '
      'then gas = tx.Fees() has been assigned and the deferred recover changes no named result, so the fee is '
      'kept and err is still the SC error, which the caller ignores. Nothing was refunded, so the burn value '
      'stays burned: the outcome is exactly what the branch comment promises, reached through a panic used as '
      'control flow. (Corrected 2026-10-21: an earlier version of this row said the fee was lost; Go\'s '
      'named-result semantics and the assignment order say otherwise, and TestRecoverKeepsNamedResults checks it.)',
      [(TE, 'if signer, err1 := Extract_signer(&tx); err1 == nil { // if we can identify sender, return funds to him'),
       (TE, '} else { //  we could not extract signer, we burn all the funds'),
       (TE, 'gas = tx.Fees()'),
       (SIM, 'if balance_serialized, err1 := curbtree.Get(signer[:]); err1 != nil { // no error can occur'),
       (SIM, 'panic(err1) // only disk corruption can reach here'),
       (GRAV, 'collision, keyhash %x not found, keyhash in ram %x'),
       (BC, 'tx_fees, err = chain.process_transaction_sc('),
       (BC, 'fees_collected += tx_fees'),
       (BC, 'if _, ok := sc_change_cache[tx.Payloads[t].SCID]; !ok || bl_current.Height < uint64(globals.Config.MAJOR_HF3_HEIGHT) {'),
       ('blockchain/sc_revert_log_test.go', 'func TestRecoverKeepsNamedResults(t *testing.T) {')],
      impact='Cosmetic on the chain: every node that replays such a transaction keeps the fee and burns the value '
             'the same way. On the console it used to print an ERROR with a 3 KB stack per transaction. ErrorRevert '
             'walks a map, but the order cannot matter: every non-zero payload SCID is loaded into sc_change_cache '
             'before execution, so ErrorRevert\'s cache-insert branch never runs, and it panics at the first Get, '
             'before any Put. The panic therefore has no state side effect at all (verified by an adversarial '
             'reviewer, 2026-10-21).',
      action='Do not change the outcome locally (consensus-visible). This tree changes only how it is logged: '
             'is_zero_signer_revert recognises the case and logs one V(1) line (consensus guard PASS).')

    F('find-recover-named', 'findings', 'A recover over named results keeps whatever was assigned before the panic', 'analysis',
      'process_transaction_sc is declared with named results (gas uint64, err error). The deferred recover logs '
      'and returns without assigning either, so the caller receives the values they held at the panic: gas = '
      'tx.Fees() (assigned near the top) and err = whatever the SC path had set. Add_Complete_Block ignores err '
      '(an empty `if err == nil` block) and adds tx_fees. So a panic inside SC execution is fee-neutral, and it '
      'is distinguishable only through the log. (Corrected 2026-10-21: the earlier "(0, nil), success" reading '
      'did not hold.)',
      [(TE, 'func (chain *Blockchain) process_transaction_sc('),
       (TE, 'if r := recover(); r != nil {'),
       (TE, 'gas = tx.Fees()'),
       (BC, 'if err == nil { // TODO process gasg here'),
       ('blockchain/sc_revert_log_test.go', 'func TestRecoverKeepsNamedResults(t *testing.T) {')],
      impact='Observability only: the event exists in the log and nowhere else.',
      action='Counting these in metrics would be consensus-neutral; not applied (P1).')

    # ---------- F3: KCP/UDP
    F('find-udp', 'findings', 'The peer-to-peer listener is UDP, not TCP', 'operational',
      'p2p binds its listening socket through kcp.ListenWithOptions. KCP is a reliable protocol implemented on '
      'top of UDP, so --p2p-bind=0.0.0.0:11011 opens a UDP socket and no TCP socket on 11011 exists at all. '
      'A router rule forwarding TCP 11011 forwards nothing; inbound peers never arrive and the console still '
      'shows the listener as up.',
      [(CTL, 'l, err := kcp.ListenWithOptions('),
       ('p2p/controller.go', 'logger.Info("P2P is listening", "address", l.Addr().String())')],
      impact='Inbound connections stay at zero and the node can only use peers it dialled itself.',
      action='Forward UDP 11011 to this host. Nothing in the daemon needs to change.')

    # ---------- the reading that reframes every other reading on the page
    F('find-attip', 'findings', 'GetInfo could not tell you whether the node had reached the tip — now GetSyncInfo can', 'fix',
      'averageblocktime50 is computed as (timestamp of the tip \u2212 timestamp of the block 50 earlier) / 50000, a '
      'property of the BLOCK TIMESTAMPS: it reads about 18 s whether the node follows the tip or replays month-old '
      'history. In the build the node ran until 2026-10-21 (baseline copy), target_height was commented out and '
      'therefore always 0, and status is the constant "OK" \u2014 on 2026-10-20 the node was 40 days behind while every '
      'field looked healthy. This tree fills target_height from the peers\u2019 median height and adds DERO.GetSyncInfo, '
      'which reports the tip block\u2019s age, the lag behind the peers\u2019 median and a computed status '
      '(synced / syncing / stalled / isolated) whose thresholds are unit-tested.',
      [('cmd/derod/rpc/rpc_dero_getinfo.go', 'result.AverageBlockTime50 = float32(now-now50) / (50.0 * 1000)'),
       ('harness/baseline/bf274e5/cmd/derod/rpc/rpc_dero_getinfo.go.base', '//result.Target_Height = uint64(chain.Get_Height())'),
       ('cmd/derod/rpc/rpc_dero_getinfo.go', 'if best, _ := p2p.Best_Peer_Height(); best > 0 { // upstream left this commented out, so it always read 0'),
       ('cmd/derod/rpc/rpc_dero_getsyncinfo.go', 'func classify_sync(peers uint64, lag int64, tip_age_s float64) (status, reason string) {'),
       ('cmd/derod/rpc/websocket_server.go', '"GetSyncInfo":                typed_new(GetSyncInfo),')],
      impact='Until the +22102026 build runs, only the tip block\u2019s age (DERO.GetBlockHeaderByTopoHeight at topoheight) '
             'answers the question; after it, one RPC call does.',
      action='Use DERO.GetSyncInfo (status, tip_age_seconds, lag_blocks). The harness still re-checks the tip age on '
             'every capture (gate G9).')

    # ---------- F5: unimplemented reporting
    F('find-peerlist', 'findings', 'white_peerlist_size and grey_peerlist_size are always zero', 'reporting',
      'Both fields exist only as struct members of the GetInfo result. No code anywhere assigns them, so the '
      'daemon reports 0 whatever the peer pool looks like. A zero here is an unimplemented field, not an empty '
      'peer list — outgoing_connections_count is the number to read.',
      [('rpc/daemon_rpc.go', 'White_peerlist_size        uint64  `json:"white_peerlist_size"`')],
      impact='Dashboards that alert on an empty peer list alert permanently.',
      action='Read outgoing_connections_count instead; the fields are cosmetic.')

    # ---------- F6: the v2 remnant chain
    F('find-v2', 'findings', 'The pre-HF3 v2 chain is still alive and still dials this node', 'operational',
      'Peers that never crossed hard fork 3 keep extending a separate chain whose blocks carry an older major '
      'version. When one serves us such a block the deserialiser refuses it with "Invalid Major Version in '
      'Block" — which is what the console recorded twice at 11:55 from 203.0.113.19. The local filter drops a '
      'peer whose handshake reports Top_Version below 3 and bans the address for an hour so it stops being '
      'redialled; a peer that upgrades is welcome back.',
      [('block/block.go', 'return fmt.Errorf("Invalid Major Version in Block\\n")'),
       ('p2p/common.go', 'still reports Top_Version < 3 is following the non-upgraded v2 remnant chain.'),
       ('p2p/common.go', 'Ban_Address(Address(connection), 3600)')],
      impact='Harmless: the block is refused and the sync continues from another peer.',
      action='None. The error line is the filter working, not a fault.')

    # ---------- F7/F8: computed consensus arithmetic
    e = float(re.search(r'float64\(([\d.]+)\)', M.anchor('blockchain/difficulty.go', 'const E = float64(', full_line=True)['quote']).group(1))
    m_ = val('blockchain/difficulty.go', 'M := int64(8)')
    up, dn = math.pow(e, 1 / m_), math.pow(e, (1 - 2) / m_)
    F('find-diffstep', 'findings', 'Difficulty can move at most +13.3% / -11.8% per block', 'analysis',
      f'The controller is next = prev * e^((1 - solvetime/blocktime)/M) with M = {m_} and e hard-coded to '
      f'{e}. Solve time is clamped to twice the block time before it is used, which bounds the exponent to '
      f'[-1/{m_}, +1/{m_}] for any single step: a block found instantly raises difficulty by x{up:.5f} '
      f'(+{(up - 1) * 100:.2f}%), and the slowest block the clamp admits lowers it by x{dn:.5f} '
      f'({(dn - 1) * 100:.2f}%). Both numbers are computed here from the two source lines cited, not transcribed.',
      [('blockchain/difficulty.go', 'const E = float64(2.71828182845905)'),
       ('blockchain/difficulty.go', 'easypart := int64(math.Pow(E, ((1-float64(solvetime)/float64(blocktime))/float64(M))) * 10000)'),
       ('blockchain/difficulty.go', 'M := int64(8)'),
       ('blockchain/difficulty.go', 'if solve_time > (block_time * 2) {')],
      up=round(up, 5), down=round(dn, 5),
      impact='A hashrate spike cannot be absorbed in one block; recovery takes several. This is why the '
             'measured mean block time hovers around the target rather than sitting on it.',
      action='None — working as designed.')

    bt = val(CFG, 'const BLOCK_TIME = uint64(18)')
    rri = 210000 * 600 // bt
    base = (41 * 100000 * bt) // 600
    F('find-emission', 'findings', 'The current block subsidy is one shift below the base reward', 'analysis',
      f'RewardReductionInterval is 210000*600/BLOCK_TIME = {rri:,} blocks and BaseReward is '
      f'41*100000*BLOCK_TIME/600 = {base:,} atomic units (={base / 100000:g} DERO). CalcBlockReward shifts the '
      f'base right by (height + interval)/interval, so the +1 epoch offset means the chain starts in epoch 1 '
      f'and the first interval of Bitcoin-equivalent supply is skipped outright. Every value here is computed '
      f'from the two const lines cited.',
      [(TE, 'const RewardReductionInterval = 210000 * 600 / config.BLOCK_TIME'),
       (TE, 'const BaseReward = (41 * 100000 * config.BLOCK_TIME) / 600'),
       (TE, 'return BaseReward >> ((height + RewardReductionInterval) / RewardReductionInterval)'),
       (CFG, 'const BLOCK_TIME = uint64(18)')],
      interval=rri, base=base,
      impact='Halvings land every 7,000,000 blocks — about four years at an 18-second cadence.',
      action='None.')

    F('find-split', 'findings', 'The reward is split per miniblock, and the rounding goes to the integrator', 'analysis',
      'full_reward (subsidy plus fees) is divided by the number of miniblocks in the block, so each accepted '
      'proof-of-work share earns one equal part. Integer division always leaves a remainder, and the whole '
      'remainder is credited to the integrator who assembled the block. A solo miner that is also its own '
      'integrator collects both.',
      [(TE, 'share := full_reward / uint64(len(bl.MiniBlocks))'),
       (TE, 'leftover := full_reward - (share * uint64(len(bl.MiniBlocks)))'),
       (CFG, 'const MINIBLOCK_HIGHDIFF = 9')],
      impact='Running derod with --integrator-address pointed at your own wallet is worth the rounding dust of '
             'every block you integrate.',
      action='Already configured on this node.')

    # ---------- F9: prune point vs the fork
    F('find-prune', 'findings', 'The prune point sits below the fork, so the fork itself is still on disk', 'analysis',
      'MAJOR_HF3_HEIGHT is 7,504,640 and the live node reports prunedheight 7,498,540 — 6,100 blocks of margin. '
      'The blocks that decide which side of the fork this node is on have not been discarded, which is why the '
      'chain identity can still be checked locally rather than by asking an explorer.',
      [(CFG, 'MAJOR_HF3_HEIGHT:        7504640'),
       ('harness/runtime/derod_console_20261020.log', 'Chain Pruned till    {"topoheight": 7498540}')],
      impact='A fresh verification of the fork decision is possible without a resync.',
      action='None.')

    # ---------- F12: the grandfather table
    n_hf3 = len(M.grep('blockchain/hardfork_fixes.go', r'^\t"[0-9a-f]{64}":'))
    F('find-hf3table', 'findings', f'The HF3 grandfather table carries {n_hf3} transactions', 'analysis',
      f'HF3_Affected_Txs maps {n_hf3} transaction hashes to the tips, height and parity they must be replayed '
      f'with. Two call sites consult it: verification and execution. These are the pre-fork transactions whose '
      f'fresh replay would otherwise fail, which is what made this node wall at 7,412,674, 7,467,516 and '
      f'7,497,836 before the table was adopted. The count is obtained by counting the hash keys in the file.',
      [('blockchain/hardfork_fixes.go', 'var HF3_Affected_Txs = map[string]*HF3_Tx_Data{'),
       ('blockchain/transaction_verify.go', 'if t, ok := HF3_Affected_Txs[tx_hash.String()]; ok {'),
       (TE, 'if t, ok := HF3_Affected_Txs[tx.GetHash().String()]; ok {')],
      count=n_hf3,
      impact='Without the table a fresh sync of this chain cannot pass the pre-fork era.',
      action='Keep it in step with upstream; the count is the fastest way to tell two releases apart.')

    # ---------- local fixes
    F('find-fix-changeset', 'findings', 'Local fix: a missing block body no longer panics the peer connection', 'fix',
      'Load_BL_FROM_ID returns (nil, err) when a block body is not on disk, which is routine on a pruned node. '
      'Upstream discarded that error and serialised the nil block, panicking inside the connection handler and '
      'costing a good peer. The local version reports the error, and the peer simply asks elsewhere.',
      [('p2p/rpc_changeset.go', 'bl, err := chain.Load_BL_FROM_ID(blid)'),
       ('p2p/rpc_changeset.go', 'c.logger.V(1).Info("cannot serve changeset, block body unavailable"'),
       ('blockchain/store.go', 'func (chain *Blockchain) Load_BL_FROM_ID(')],
      impact='One fewer dropped peer per pruned-range request.', action='Shipped in commit d28c5b7.')

    F('find-fix-persist', 'findings', 'Local fix: the peer list survives a hard kill', 'fix',
      'Upstream writes peers.json and ban_list.json only from P2P_Shutdown, so any exit that is not a clean '
      'SIGINT throws away everything the node learned and it cold-starts from the seed list. A five-minute '
      'ticker in maintain_connection_to_peers snapshots both lists, bounding the loss to one interval.',
      [(CTL, 'persist := time.NewTicker(5 * time.Minute)'),
       (CTL, 'case <-persist.C:')],
      impact='A SIGKILL or power loss costs at most five minutes of peer knowledge instead of all of it.',
      action='Shipped in commit 9612278.')

    M.emit('findings', rows, unv, 'mine_findings.py')


if __name__ == '__main__':
    main()
