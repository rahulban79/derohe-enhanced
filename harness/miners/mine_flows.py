#!/usr/bin/env python3
"""mine_flows.py — the end-to-end chains: what calls what, in order, from wire to disk.

A chain is a DECLARED sequence of hops; each hop names a file and the text that must be on one of its lines.
The miner locates every hop. A chain renders only when ALL of its hops anchor — one missing hop sends the whole
chain to `unverified` naming the hop that moved, so a refactor upstream shows up as a hole in the page rather
than as a diagram that quietly lies.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import minelib as M

# chain id, title, what the chain is for, [(layer, file, needle, note)]
CHAINS = [
 ('ingest', 'Block ingest — a peer’s block becomes chain state',
  'The hot path every 18 seconds. A block arrives as a P2P object, is verified, its transactions are executed '
  'against the balance tree, and the new tree root is committed to graviton.', [
  ('p2p', 'p2p/connection_pool.go', 'func syncroniser() {', 'A cron job drives synchronisation; it is not event-driven.'),
  ('p2p', 'p2p/connection_pool.go', 'func trigger_sync() {', 'Picks the best peer by height and asks it to sync.'),
  ('p2p', 'p2p/chain_sync.go', 'func (connection *Connection) sync_chain() {', 'Walks the peer’s chain, requesting what we lack.'),
  ('p2p', 'p2p/chain_sync.go', 'func (connection *Connection) process_object_response(', 'Turns the wire objects back into blocks and transactions.'),
  ('core', 'blockchain/blockchain.go', 'func (chain *Blockchain) Add_Complete_Block(', 'The single door into consensus state.'),
  ('core', 'blockchain/blockchain.go', 'if err = Verify_MiniBlocks(*cbl.Bl); err != nil {', 'The miniblock set must be internally consistent before any work is done.'),
  ('core', 'blockchain/transaction_execute.go', 'func (chain *Blockchain) process_transaction(', 'Each transaction mutates the balance tree homomorphically.'),
  ('core', 'blockchain/transaction_execute.go', 'func (chain *Blockchain) process_miner_transaction(', 'The coinbase pays the miniblock miners and the integrator.'),
  ('state', 'blockchain/blockchain.go', 'commit_version, err := graviton.Commit(data_trees...)', 'One commit per block makes the new state root.'),
 ]),
 ('mining', 'Mining — from GETWORK job to an accepted miniblock',
  'How a share becomes money. derod dispatches a template every 500 ms; the miner returns a 48-byte miniblock; '
  'the daemon re-checks its proof of work and threads it into the miniblock DAG.', [
  ('getwork', 'cmd/derod/rpc/websocket_getwork_server.go', 'func SendJob() {', 'The job fan-out to every connected miner.'),
  ('core', 'blockchain/miner_block.go', 'func (chain *Blockchain) Create_new_block_template_mining(', 'Builds the template and the miniblock blob the miner hashes.'),
  ('miner', 'cmd/dero-miner/miner.go', 'func mineblock(tid int) {', 'One hashing goroutine per thread.'),
  ('pow', 'astrobwt/astrobwtv3/pow.go', 'func AstroBWTv3(input []byte) (outputhash [32]byte) {', 'AstroBWT v3 is the hash the share must satisfy.'),
  ('miner', 'cmd/dero-miner/miner.go', 'func submitShare(jobID, blobHex string, source byte) {', 'A share that met the target is sent straight back over the websocket (source: CPU or GPU, for the paid ledger).'),
  ('core', 'blockchain/difficulty.go', 'func (chain *Blockchain) VerifyMiniblockPoW(', 'The daemon never trusts the miner’s word on difficulty.'),
  ('core', 'blockchain/miniblocks_consensus.go', 'func (chain *Blockchain) InsertMiniBlock(', 'An accepted share joins the DAG and becomes a claim on the reward.'),
  ('p2p', 'p2p/connection_pool.go', 'func Broadcast_MiniBlock(', 'The share is flooded to peers so the next block can include it.'),
 ]),
 ('scexec', 'Smart-contract execution — and the revert path the live node hit',
  'An SC transaction runs inside a recover guard. The observed 13:37:02 error walks the second half of this '
  'chain, which is why it is drawn here rather than described.', [
  ('core', 'blockchain/blockchain.go', 'tx_fees, err = chain.process_transaction_sc(', 'Only SC_TX transactions take this branch.'),
  ('core', 'blockchain/transaction_execute.go', 'func (chain *Blockchain) process_transaction_sc(', 'Named returns (gas, err) — remember them; the recover below leaves them zero.'),
  ('core', 'blockchain/transaction_execute.go', 'if r := recover(); r != nil {', 'Any panic below this line is swallowed, not propagated.'),
  ('dvm', 'dvm/dvm.go', 'func RunSmartContract(', 'The contract body executes here.'),
  ('core', 'blockchain/transaction_execute.go', 'if err != nil { // error occured, give everything to SC', 'The failure branch: the call did not succeed.'),
  ('core', 'blockchain/transaction_execute.go', 'if signer, err1 := Extract_signer(&tx); err1 == nil {', 'Who gets the burned funds back depends on identifying the sender.'),
  ('dvm', 'dvm/simulator.go', 'func ErrorRevert(', 'Refunds the burn value to the signer.'),
  ('dvm', 'dvm/simulator.go', 'panic(err1) // only disk corruption can reach here', 'The assumption that fails: a signer with no entry in that asset tree.'),
  ('ext', 'vendor/github.com/deroproject/graviton/node_leaf.go', 'collision, keyhash %x not found, keyhash in ram %x', 'graviton reports a missing key as a leaf collision.'),
 ]),
 ('p2pconn', 'Peer connections — KCP over UDP, not TCP',
  'The single most consequential operational fact on this page: the listener is a UDP socket. A TCP port '
  'forward on 11011 forwards nothing.', [
  ('p2p', 'p2p/controller.go', 'func P2P_Init(params map[string]interface{}) error {', 'Entry point called once from derod main.'),
  ('p2p', 'p2p/controller.go', 'l, err := kcp.ListenWithOptions(', 'The listener is KCP — a reliability layer on top of UDP.'),
  ('ext', 'vendor/github.com/xtaci/kcp-go/v5/sess.go', 'func ListenWithOptions(', 'kcp-go binds a UDP socket; nothing here opens a TCP port.'),
  ('p2p', 'p2p/controller.go', 'func maintain_connection_to_peers() {', 'Outgoing dialling keeps the pool at --min-peers.'),
  ('p2p', 'p2p/controller.go', 'case <-persist.C:', 'Local change: the peer list is snapshotted every 5 minutes, not only at clean shutdown.'),
 ]),
 ('wallet', 'Wallet — building and sending a transfer',
  'The wallet is a full participant in the HE scheme: it decodes its own encrypted balance, assembles the ring '
  'and the bulletproof locally, and hands the daemon a finished transaction.', [
  ('wallet', 'walletapi/wallet_transfer.go', 'func (w *Wallet_Memory) TransferPayload0(', 'The one entry point every send goes through.'),
  ('wallet', 'walletapi/transaction_build.go', 'func (w *Wallet_Memory) BuildTransaction(', 'Assembles statement, proof and payloads.'),
  ('crypto', 'cryptography/crypto/proof_generate.go', 'func GenerateProof(scid Hash, scid_index int, s *Statement,', 'The zero-knowledge proof is produced on the wallet, never on the node.'),
  ('wallet', 'walletapi/daemon_communication.go', 'func (w *Wallet_Memory) SendTransaction(', 'Handed to the daemon over the websocket RPC.'),
  ('core', 'blockchain/mempool/mempool.go', 'func (pool *Mempool) Mempool_Add_TX(', 'The daemon parks it in the mempool until a miner includes it.'),
 ]),
 ('startup', 'Daemon start-up — the order things come up in',
  'The sequence the console log at 11:09:43 records, one line per subsystem, in the order main() brings them up.', [
  ('derod', 'cmd/derod/main.go', 'chain, err := blockchain.Blockchain_Start(params)', 'Storage and consensus first: nothing may listen before the chain is open.'),
  ('core', 'blockchain/blockchain.go', 'func Blockchain_Start(params map[string]interface{}) (*Blockchain, error) {', 'Opens graviton, the mempool and the regpool.'),
  ('p2p', 'p2p/controller.go', 'func P2P_Init(params map[string]interface{}) error {', 'Then the network comes up.'),
  ('rpc', 'cmd/derod/rpc/websocket_server.go', 'func RPCServer_Start(', 'Then the JSON-RPC / websocket server on 10102.'),
  ('getwork', 'cmd/derod/rpc/websocket_getwork_server.go', 'func Getwork_server() {', 'Last, the miner-facing GETWORK server on 10100.'),
 ]),
  ('txverify', 'Transaction verification — from a block to the zero-knowledge proof',
  'Every non-coinbase transaction in a block is verified before the block is executed. Registrations carry a '
  'signature; everything else carries one proof per payload, checked by the verifier audited in section 25. The HF3 '
  'grandfather table exempts its 75 historic transactions from the proof check.', [
  ('core', 'blockchain/blockchain.go', 'if err := chain.Verify_Transaction_NonCoinbase(cbl.Txs[j]); err != nil { // transaction verification failed', 'A block\u2019s transactions are verified before it is executed.'),
  ('core', 'blockchain/transaction_verify.go', 'func (chain *Blockchain) Verify_Transaction_NonCoinbase(tx *transaction.Transaction) (err error) {', 'The single verifier for non-coinbase transactions.'),
  ('core', 'blockchain/transaction_verify.go', 'if t, ok := HF3_Affected_Txs[tx_hash.String()]; ok {', 'The grandfather table: 75 historic txids skip the proof check (section 25).'),
  ('core', 'blockchain/transaction_verify.go', 'if tx.IsRegistrationValid() {', 'A registration is checked by its signature, not by a proof.'),
  ('crypto', 'blockchain/transaction_verify.go', 'if !tx.Payloads[t].Proof.Verify(tx.Payloads[t].SCID, index, &tx.Payloads[t].Statement, tx.GetHash(), tx.Payloads[t].BurnValue) {', 'Each payload\u2019s proof is verified against its statement and the txid.'),
  ('crypto', 'cryptography/crypto/proof_verify.go', 'func (proof *Proof) Verify(scid Hash, scid_index int, s *Statement, txid Hash, extra_value uint64) bool {', 'The proof verifier itself.'),
 ]),
 ('minipow', 'Miniblock proof of work — what makes a share valid',
  'A miniblock is valid only if its AstroBWT v3 hash, read as a number, does not exceed the target its difficulty '
  'converts to; the difficulty is computed from the miniblock\u2019s tips, never taken from the miner.', [
  ('core', 'blockchain/miniblocks_consensus.go', 'func Verify_MiniBlocks(bl block.Block) (err error) {', 'The miniblock set must be well formed before any PoW is checked.'),
  ('core', 'blockchain/difficulty.go', 'func (chain *Blockchain) VerifyMiniblockPoW(bl *block.Block, mbl block.MiniBlock) bool {', 'One miniblock against the difficulty at its tips.'),
  ('pow', 'blockchain/difficulty.go', 'PoW := mbl.GetPoWHash()', 'The AstroBWT v3 hash of the 48-byte miniblock.'),
  ('core', 'blockchain/difficulty.go', 'block_difficulty := chain.Get_Difficulty_At_Tips(bl.Tips)', 'Difficulty from the tips.'),
  ('core', 'blockchain/difficulty.go', 'if mbl.HighDiff {', 'A HighDiff miniblock must meet the difficulty multiplied by MINIBLOCK_HIGHDIFF.'),
  ('core', 'blockchain/difficulty.go', 'if CheckPowHashBig(PoW, block_difficulty) == true {', 'The hash, read as a number, must not exceed the target the difficulty converts to.'),
 ]),
 ('gsplit', 'GPU split mining — the live r18 mode, from staged text to a submitted share',
  'The GPU computes AstroBWT stage 1 and the final SHA-256 into shared memory; every CPU thread only sorts staged '
  'texts. Each winning hash is re-hashed on the CPU before it leaves the box, so a wrong GPU result can cost '
  'hashrate but never a rejected share.', [
  ('miner', 'cmd/dero-miner/miner.go', 'case mode == "split" && start_gpu_split(gpuBin): // before the mining threads: its self-test toggles astrobwtv3.SuffixSort', 'Split mode is chosen before any mining thread starts.'),
  ('miner', 'cmd/dero-miner/gpu_split.go', 'err = e.SelfTest(256, astropair.NewScratch())', 'A bit-exact self-test on 256 nonces against the consensus code path, or it falls back to full mode.'),
  ('gsplit', 'cmd/dero-miner/gsplit/engine.go', 'func (e *Engine) feeder(gq chan struct{}) {', 'Batches of nonces are issued to gpu_split_server for stage 1.'),
  ('miner', 'cmd/dero-miner/miner.go', 'if k := se.TryWork(pscratch); k > 0 {', 'A mining thread takes staged texts first and hashes its own nonces only when none is staged.'),
  ('miner', 'cmd/dero-miner/gpu_split.go', 'func split_stale(tag interface{}) bool {', 'r21: a claimed text whose job can only produce an orphan (a newer height, or the same height flipped to final work) is dropped before the CPU sorts it.'),
  ('gsplit', 'cmd/dero-miner/gsplit/engine.go', 'if !astropair.SortOnly(e.text(j, e.dlen(j)), e.sa(j)) {', 'The CPU\u2019s whole job per hash: the descriptor suffix sort into GPU-shared memory.'),
  ('gsplit', 'cmd/dero-miner/gsplit/engine.go', 'func (e *Engine) collect(b *batch) {', 'The GPU\u2019s SHA-256 results come back and are checked against the job target.'),
  ('miner', 'cmd/dero-miner/gpu_split.go', 'if cpu := astrobwtv3.AstroBWTv3(blob); cpu != h || !CheckPowHashBig(cpu, &sj.diff) {', 'A winner is re-hashed on the CPU; a disagreement is never submitted and disables split mode.'),
  ('miner', 'cmd/dero-miner/gpu_split.go', "submitShare(sj.job.JobID, fmt.Sprintf(\"%x\", blob), 'G')", 'Submitted with source G for the paid/orphaned ledger.'),
 ]),
 ('syncpipe', 'Pipelined block sync — batched GetObject with requests in flight (r18)',
  'Catch-up fetches several blocks per request and keeps requests outstanding while the previous batch is verified; '
  'the PoW of the next blocks is prewarmed on a bounded worker pool. The r18 counters say the remaining cost is '
  'local verification, not the network.', [
  ('p2p', 'p2p/chain_sync.go', 'func (connection *Connection) sync_chain() {', 'Walks the peer\u2019s chain, requesting what we lack.'),
  ('p2p', 'p2p/chain_sync.go', 'if _, err := fetch_pipelined_adaptive(needed, func() (int, int) { return sync_sizes.shape(SYNC_BATCH, SYNC_DEPTH) }, connection.fetch_blocks, func(o Objects) error {', 'Batch size and depth adapt to the block sizes seen so far.'),
  ('p2p', 'p2p/sync_pipeline.go', 'func fetch_pipelined_adaptive(ids []crypto.Hash, shape func() (batch, depth int),', 'Up to depth requests outstanding; responses are processed in order.'),
  ('p2p', 'p2p/sync_pipeline.go', 'func (connection *Connection) fetch_blocks(ids []crypto.Hash) (resp Objects, err error) {', 'The production transport: one GetObject call per batch.'),
  ('p2p', 'p2p/sync_pipeline.go', 'metrics.Set.GetOrCreateCounter("p2p_sync_large_block_fallbacks_total").Inc()', 'A batch too large for one frame falls back to smaller requests, and is counted.'),
  ('p2p', 'p2p/chain_sync.go', 'prewarm_pow(chain.Load_Block_Height, bl.Tips, len(bl.MiniBlocks), func(k int) bool {', 'Miniblock PoW is verified ahead of the chain on a bounded pool.'),
  ('core', 'blockchain/blockchain.go', 'func (chain *Blockchain) Add_Complete_Block(', 'Then the single door into consensus state, unchanged.'),
 ]),
 ('gpucap', 'GPU duty cap — how --gpu-max is enforced in split mode (Round 22)',
  'r21 ran at ~95% GPU duty with --gpu-max=90: the feeder slept off debt while the ring was full anyway. r22 charges '
  'each busy span busy×100/cap of wall time into a bucket that the wall clock pays off; the feeder stages nothing '
  'while it owes. The cap in force can move at run time (the opt-in duty tuner).', [
  ('miner', 'cmd/dero-miner/miner.go', 'if gpu_max, gpu_auto, gpu_floor, err = parse_duty_flag(globals.Arguments["--gpu-max"].(string), 90); err != nil {', 'A percent, or auto / auto:<floor> for the ABBA duty tuner.'),
  ('miner', 'cmd/dero-miner/dutytune.go', 'func start_duty_tuner(cpuAuto bool, cpuFloor int, gpuAuto bool, gpuFloor int, gpuRunning bool) {', 'Only with auto: probes cap vs cap±5 in ABBA windows and keeps a step only if TOTAL H/s rose.'),
  ('gsplit', 'cmd/dero-miner/gsplit/engine.go', 'func (e *Engine) SetGPUMax(p int) int {', 'The cap in force (clamped 1..100); 100 also forgives the debt.'),
  ('gsplit', 'cmd/dero-miner/gsplit/engine.go', 'func (e *Engine) charge(busy int64) {', 'Every GPU buffer’s new wall-clock busy time is charged at the cap in force.'),
  ('gsplit', 'cmd/dero-miner/gsplit/duty.go', 'func dutyCharge(busyNs int64, cap int) int64 {', 'busy×100/cap of wall time: the cost of that busy span under the cap.'),
  ('gsplit', 'cmd/dero-miner/gsplit/engine.go', 'if !e.payDuty(gq) { // --gpu-max (duty.go)', 'The feeder waits here before staging the next batch.'),
  ('gsplit', 'cmd/dero-miner/gsplit/duty.go', 'func (e *Engine) settleDuty(now int64) int64 {', 'Wall time credits the bucket; at most 100 ms of idle is banked.'),
 ]),
]


def main():
    rows, unv = [], []
    for cid, title, why, hops in CHAINS:
        located, missing = [], []
        for i, (layer, f, needle, note) in enumerate(hops, 1):
            a = M.anchor(f, needle, full_line=True)
            (located if a else missing).append((i, layer, f, needle, note, a))
        if missing:
            unv.append({'title': title, 'why': 'chain not drawn — hop(s) could not be anchored: '
                        + '; '.join(f'#{i} {f} :: {n[:60]}' for i, _, f, n, _, _ in missing)})
            continue
        rows.append({'id': f'flow-{cid}', 'section': 'flows', 'title': title, 'class': 'SRC', 'claim': why,
                     'chain': cid, 'hops': len(hops),
                     'evidence': [a for *_, a in located]})
        for i, layer, f, needle, note, a in located:
            rows.append({'id': f'hop-{cid}-{i:02d}', 'section': 'hops', 'title': f'{cid} #{i} {layer}',
                         'class': 'EXT' if f.startswith('vendor/') else 'SRC',
                         'claim': note, 'chain': cid, 'order': i, 'layer': layer,
                         # a short label for the diagram: the function name when the hop is a definition,
                         # otherwise the statement with its trailing comment removed
                         'fn': (needle.replace('func ', '').split('(')[0].strip() if needle.lstrip().startswith('func ')
                                else __import__('re').sub(r'\s*//.*$', '', needle).strip().rstrip('{').strip()[:44]),
                         'where': f'{f}:{a["line"]}', 'evidence': [a]})
    M.emit('flows', rows, unv, 'mine_flows.py')


if __name__ == '__main__':
    main()
