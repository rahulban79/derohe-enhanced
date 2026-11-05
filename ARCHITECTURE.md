# DERO HE (Release 142) — System Architecture & M1-Ultra Miner Optimization

**A privacy-preserving, DAG-of-miniblocks Proof-of-Work blockchain with fully-homomorphic encrypted balances
and an on-chain BASIC-style VM — mapped from source, measured on the host, and engineered for an Apple M1
Ultra.** This document is both the system reference *and* the evidence base for making the miner faster: it
ends with a **measured, hardware-grounded verdict on hashrate**: after multi-agent analysis and direct PoC
measurement, the miner is at its **~7,680 H/s ceiling** and no software lever (ILP, GPU, RAM, PGO, reward
economics) yields a robust gain — a result proven, not asserted (§13–§14).

> **Engineering discipline — the zero-hallucination contract.** Every number, path, port, constant and
> hashrate here was *read from source, printed by a command I ran, or observed in a live artifact* — never
> recalled. Both binaries build clean (`go build ./cmd/derod ./cmd/dero-miner` → exit 0). Every H/s came from
> `dero-miner --bench`, a fixed-wall-clock harness (`cmd/_hashbench`), or `go test -bench`. The MLP ceiling
> came from a direct hardware probe (`cmd/_mlpprobe`). The payout address was validated by the repo's own
> `rpc.NewAddress`. AstroBWTv3 output was proven **bit-identical under Go 1.26.4** (known-answer + 1024-iter
> tests pass). Anything unproven is quarantined in §17.
>
> **Evidence tags:** `[E:EXEC]` command output · `[E:SRC]` file:line · `[E:OBS]` observed artifact/log ·
> `[E:DERIVE]` arithmetic shown from tagged facts · `[UNVERIFIED]` quarantined.
>
> **Current (Round 12, 2026-10-22):** live tree `<repo>`; running `3.6.0-153.DEROHE.STARGATE+21102026` since 2026-10-21 23:18 (built tree declares `+22102026`); logs `<datadir>/logs/derod.log`.
> **Original provenance (§1–19):** live tree `<repo>`, version **`3.5.5-142.DEROHE.STARGATE+13082025`**
> `[E:SRC config/version.go:23]`, host **Apple M1 Ultra / macOS 26** `[E:EXEC]`, build toolchain
> **Go 1.20.3 darwin/arm64** (newer 1.26.4 tested, §12). Methodology follows the project-root
> `EVIDENCE_LOOP_PROMPT.md` + `evidence_loop_diagram.svg` + `open-and-close-loop.jpeg`.

---

## Table of contents

1. [System context](#1-system-context)
2. [Open-loop → closed-loop methodology (how this was built)](#2-open-loop--closed-loop-methodology)
3. [Repository module map (every directory)](#3-repository-module-map)
4. [Configuration & settings — full inventory](#4-configuration--settings--full-inventory)
5. [The node (`derod`) — consensus & storage](#5-the-node-derod--consensus--storage)
6. [Blocks, MiniBlocks & the DAG](#6-blocks-miniblocks--the-dag)
7. [Difficulty (DAA) & rewards](#7-difficulty-daa--rewards)
7A. [★ Reward probability & miniblock orphaning (the "luck" levers)](#7a--reward-probability--miniblock-orphaning-the-luck-levers)
8. [Transactions, privacy (homomorphic crypto) & the DVM](#8-transactions-privacy--the-dvm)
9. [P2P networking](#9-p2p-networking)
10. [getwork/RPC/metrics interfaces (node ⇄ miner ⇄ monitor)](#10-getworkrpcmetrics-interfaces)
11. [★ The miner & AstroBWTv3 PoW — deep dive](#11--the-miner--astrobwtv3-pow--deep-dive)
12. [★ Host profile — Apple M1 Ultra (deeply probed)](#12--host-profile--apple-m1-ultra-deeply-probed)
13. [★★ Miner performance engineering — the evidence & the real win](#13--miner-performance-engineering--the-evidence--the-real-win)
14. [★ The K-way ILP interleave — proposed, then REFUTED by measurement](#14--the-k-way-ilp-interleave--proposed-then-refuted-by-measurement)
15. [★ Deployment topology + Build · Run · Mine · Monitor runbook](#15--deployment-topology--runbook)
16. [Recursive self-improvement — skills, memory, next runs](#16-recursive-self-improvement)
17. [Unverified ledger & conventions](#17-unverified-ledger--conventions)

---

## 1. System context

DERO HE ("Homomorphic Encryption", codename **Stargate**) is a Layer-1 blockchain in one Go module,
`github.com/deroproject/derohe` `[E:SRC go.mod]` (`go 1.17`; built here with **Go 1.20.3** `[E:EXEC]`). Three
structural properties set it apart, all verified in source:

- **Encrypted balances.** Balances are homomorphically-encrypted ElGamal ciphertexts in a `graviton` Merkle
  tree, not plaintext UTXOs; transfers carry bulletproof zero-knowledge `crypto.Proof`s with **ring size
  2…128** `[E:SRC config/config.go:58-59; cryptography/crypto/]`.
- **A DAG of MiniBlocks.** Each ~18-second block is assembled from exactly **10 MiniBlocks**, letting many
  independent miners contribute PoW shares to one block — the "ONE CPU, ONE VOTE" design `[E:DERIVE §6]`.
- **An on-chain VM.** Smart contracts are a **BASIC-like line language** interpreted by the DVM with
  per-operation gas metering `[E:SRC dvm/dvm.go, dvm/dvm_functions.go]`.

```
        ┌──────────────────────────────── DERO HE NODE (derod) ─────────────────────────────────┐
  P2P   │   p2p/ (CBOR/rpc2)  ── sync_chain / bootstrap ──▶  blockchain.Blockchain               │
 peers ─┼─▶ Broadcast_Block / _MiniBlock / _Tx           │    Add_Complete_Block (validate→exec) │
        │        ▲                                        │        │            ▼                 │
        │        │                                        ▼        ▼      graviton trees:         │
        │  getwork ws :10100  ◀── 48-byte miniblock ── miner_block.go     Balance_store (ElGamal) │
        │  JSON-RPC   :10102 (DERO.*)                        │            Block_tx_store (files)   │
        │  metrics    /metrics (Prometheus)                  ▼            Topo_store (topo.map)    │
        └────────┼──────────────────────────────────────────────────────────────────────────────┘
                 │  wss://<node>:10100/ws/<wallet>
                 ▼
        ┌──────────────────── MINER (dero-miner, THIS M1 Ultra) ────────────────────┐
        │  getwork() ── Blockhashing_blob(48B) ──▶  20× mineblock() goroutines       │
        │                                            i++ ; AstroBWTv3(work) ; diff?  │
        │  submit ◀── SubmitBlock_Params{JobID, mbl_blob} ──── found miniblock       │
        └───────────────────────────────────────────────────────────────────────────┘
```
`[E:SRC cmd/dero-miner/miner.go:401-541; cmd/derod/rpc/websocket_getwork_server.go; blockchain/blockchain.go]`

---

## 2. Open-loop → closed-loop methodology

This document and the tuning behind it followed the **Evidence-Loop Protocol** in the project root
(`EVIDENCE_LOOP_PROMPT.md`, `evidence_loop_diagram.svg`, `open-and-close-loop.jpeg`). Same five-phase spine
**Discover → Plan → Execute → Verify → Iterate**; the difference is *aperture*.

```
 OPEN LOOP (wide — map every path; spend tokens only on evidence)
  DISCOVER → PLAN → EXECUTE(spikes) → VERIFY(prune) → ITERATE(re-open)
  probe M1   enumerate  bench/pprof/    SAIS=77%,       "compute-side is a
  read whole 6 opt      pgo/newGo/      SHA already      dead end → the wall
  repo       paths      GOGC/MLP        accel; MLP 4.8×  is memory latency"
                              │
  ───────────────────── GATE G0 (collapse) ─────────────────────
 CLOSED LOOP (narrow — one path, an eval gate after every step)
  DISCOVER → PLAN → EXECUTE → VERIFY(bench + KA vectors) → ITERATE
  scope to    one lever  apply +   keep only if H/s ↑ AND output bit-identical
  the SAIS/   (thread cfg re-bench
  ILP path    / ILP)
```

**What the open loop pruned (each refuted *by measurement*, not opinion):** SHA acceleration (already ARM), PGO
(worse), newer Go toolchain (no change), `GOGC=off`, `asyncpreemptoff`, goroutine oversubscription, GPU. The
one surviving path — **intra-thread ILP** — survived because a direct hardware probe proved the bottleneck loop
leaves ~4.8× of the core's load capacity idle (§13). *The data was the arbiter.*

---

## 3. Repository module map

**3,839** `.go` files including `vendor/` `[E:EXEC find | wc -l]`. Directories `[E:EXEC ls; wc -l]`:

| Dir | Role (verified) | Anchor |
| :-- | :-------------- | :----- |
| `cmd/` | 7 binaries: **derod**, **dero-miner**, **dero-wallet-cli**, **explorer**, **simulator**, **webwallet**, **rpc_examples/pong_server** | each `func main` |
| `blockchain/` | consensus core: add-block pipeline, DAA, mempool/regpool, graviton storage, rewards, miniblock consensus | `blockchain.go:112` |
| `astrobwt/` | PoW: `astrobwtv3/` (**live**), `astrobwt_fast/` (legacy), root `astrobwt.go` (`POW16/POW32`) | `astrobwtv3/pow.go:34` |
| `block/` | `Block`+`MiniBlock` structs, serialization, `MiniBlocksCollection` DAG | `miniblock.go:33` |
| `transaction/` | tx types (PREMINE…SC_TX), homomorphic payloads, proofs | `transaction.go:30-40` |
| `cryptography/` | **4,383 LOC** `crypto/` (ElGamal, Pedersen, bulletproofs, field/point vectors) + `bn256/` pairing | `cryptography/crypto/` |
| `dvm/` | DERO VM — BASIC-style line interpreter + gas-costed builtins | `dvm/dvm.go:344` |
| `p2p/` | peer engine, chain sync/bootstrap, CBOR wire, erasure-coded chunks, bans | `p2p/controller.go:96` |
| `rpc/` | shared RPC structs (getwork template, submit, addresses) | `rpc/daemon_rpc.go` |
| `walletapi/` | `Wallet_Memory`/`Wallet_Disk`, daemon comms, scanning | `walletapi/daemon_communication.go` |
| `metrics/` | Prometheus `/metrics` + optional VictoriaMetrics push | `metrics/metrics.go:48` |
| `config/`,`globals/` | network constants/ports/HF heights/version; runtime config + helpers | `config/config.go`, `globals/globals.go` |
| `proof/`,`premine/`,`glue/`,`errormsg/` | tx proof/payment-id, premine, wiring, error strings | — |

---

## 4. Configuration & settings — full inventory

All `[E:SRC config/config.go]` unless noted:

| Constant | Value | Line |
| :------- | :---- | ---: |
| `BLOCK_TIME` | **18 s** (`BLOCK_TIME_MILLISECS` = 18000) | 34-35 |
| `MINIBLOCK_HIGHDIFF` | 9 | 36 |
| `MAX_STORAGE_GAS_ATOMIC_UNITS` | 20000 | 46 |
| `FEE_PER_KB` | 20 (0.00020 DERO/KB) | 49 |
| `STARGATE_HE_MAX_BLOCK_SIZE` | (10 MiB + 256 KiB) = **10,747,904 B** | 54 |
| `STARGATE_HE_MAX_TX_SIZE` | 300 KiB = 307,200 B | 56 |
| `MIN_RINGSIZE` / `MAX_RINGSIZE` | 2 / 128 | 58-59 |
| `PREMINE` | 1,228,125,400,000 | 61 |
| `STABLE_LIMIT` | 8 | 79 |
| `REMOTE_DAEMON` | `node.derofoundation.org:11012` | 141 |

**Per-network `CHAIN_CONFIG`** (fields declared config.go:86-96):

| Field | Mainnet | Testnet |
| :---- | :------ | :------ |
| `GETWORK_Default_Port` | **10100** | 10100 |
| `RPC_Default_Port` | **10102** | 40402 |
| `Wallet_RPC_Default_Port` | 10103 | 40403 |
| `MAJOR_HF2_HEIGHT` (switches PoW→AstroBWTv3) | **481600** | 4 |
| `HF1_HEIGHT` / `HF2_HEIGHT` | 21480 / 29000 | 0 / 0 |
| `Dev_Address` (default integrator) | `dero1qykyta6…qgny8270` | `deto1qy0ehnq…qqdzcd8p` |

`[E:SRC config.go:100-138]`. **`P2P_Default_Port`** is not set in the CONFIG literal (defaults 0 in `config`);
the actual P2P default is **18089**, wired via the derod flag help `[E:SRC cmd/derod/main.go:78]`. Rewards
(`BaseReward=123,000`, `RewardReductionInterval=7,000,000`) live in `blockchain/transaction_execute.go:42-43`,
not `config/` (§7). Version string set in `config/version.go:23`; env overrides parsed in `config_main.go:24`.

---

## 5. The node (`derod`) — consensus & storage

**`Blockchain` struct** `[E:SRC blockchain/blockchain.go:59-101]`: `Store storage`, `Top_ID`,
`MiniBlocks *block.MiniBlocksCollection`, `Tips map`, LRU caches, `integrator_address`, `Difficulty`,
`Mempool`, `Regpool`, embedded `sync.RWMutex`. Built in `Blockchain_Start` `[E:SRC blockchain.go:112]`.

**Add-block pipeline — `Add_Complete_Block`** `[E:SRC blockchain.go:378]`, chain-locked at :381:
```
dedup/known → height sanity → single-tip & tips-on-disk → timestamp(future+50ms / monotonic)
→ Check_Block_Version → CheckDagStructure → size ≤ MAX_BLOCK → Verify_MiniBlocks(count==10)
→ Verify_MiniBlocks_HashCheck → miner-addr registered → VerifyMiniblockPoW(per miniblock)
→ Verify_Transaction_Coinbase → tx-hash/dup/nonce checks → StoreBlock → process_transaction(s)
→ process_miner_transaction(rewards) → graviton.Commit(trees) → topo-order write → recompute tips
```
`[E:SRC blockchain.go:390-1113]`.

**Storage = `graviton`, not badger/leveldb** `[E:SRC store.go:29-42]`:
- `Balance_store *graviton.Store` — homomorphic balance & SC-state Merkle tree (`…/balances`).
- `Block_tx_store storefs` — blocks & txs as **raw files** under `bltx_store/<hex>/<hex>` `[E:SRC storefs.go:34-51]`.
- `Topo_store storetopofs` — one `topo.map` of 48-byte `TopoRecord{BLOCK_ID, State_Version, Height}`
  `[E:SRC storetopo.go:28-47]`.

**Pools:** `Mempool` (`sync.Map` txs/nonces + sorted slice, mempool.go:48-61); registration txs → separate
`Regpool` (regpool.go:50). **Peers policy:** `--min-peers` / `--max-peers` (help shows 11/100 and 31/101 in
different lines — see §17) `[E:SRC main.go:62,85-86]`.

---

## 6. Blocks, MiniBlocks & the DAG

**`Block`** `[E:SRC block/block.go:35-46]`: `Major/Minor_Version`, `Timestamp` (**ms**), `Height`, `Miner_TX`,
`Proof [32]byte` (balance-root hash), `Tips`, `MiniBlocks []MiniBlock`, `Tx_hashes`. Hash = SHA3-256 of the
serialization (block.go:57-58).

**`MiniBlock`** `[E:SRC block/miniblock.go:41-57]`: packed 1-byte header (`Version<16`, `HighDiff`, `Final`,
`PastCount 1–2`), `Timestamp uint16`, `Height` (5 bytes on wire), `Past [2]uint32`, `KeyHash` (16 B serialized),
`Flags`, `Nonce [3]uint32`. **`MINIBLOCK_SIZE = 48`** `[E:SRC miniblock.go:33]` — the exact byte length the
miner hashes. PoW selector:
```
GetPoWHash: height < MAJOR_HF2_HEIGHT → astrobwt.POW16   else → astrobwtv3.AstroBWTv3   [E:SRC miniblock.go:113-118]
```
**MiniBlocks/block = `BLOCK_TIME − MINIBLOCK_HIGHDIFF + 1` = 18−9+1 = 10** `[E:SRC miniblocks_consensus.go:80-83]`
`[E:DERIVE]` (non-final = 9 at soft-HF ≥399000). The DAG collection is `map[MiniBlockKey][]MiniBlock` + RWMutex
`[E:SRC block/miniblockdag.go:23-26]`.

---

## 7. Difficulty (DAA) & rewards

**DAA** (target 18 s) — `DiffBig` `[E:SRC blockchain/difficulty.go:113-122]`:
```
easypart  = round( e^((1 − solvetime/blocktime) / M) × 10000 )        E=2.71828182845905, M=8
next_diff = prev_diff × easypart / 10000     (floored at network MinimumDifficulty)
```
`solvetime` capped at `2×blocktime` `[E:SRC difficulty.go:100,245-256]`. Acceptance: `CheckPowHashBig` compares
the little-endian PoW hash as a big-int to `(1<<256)/difficulty` `[E:SRC difficulty.go:48-98]`.

**Rewards** `[E:SRC blockchain/transaction_execute.go:42-60]`:
```
RewardReductionInterval = 210000*600/18 = 7,000,000                                   [E:DERIVE]
BaseReward             = 41*100000*18/600 = 123,000 atomic units                      [E:DERIVE]
CalcBlockReward(h)     = BaseReward >> ((h + RewardReductionInterval)/RewardReductionInterval)
```
`full_reward = base + fees`, split across the 10 MiniBlocks; the **integrator** (block's
`Miner_TX.MinerAddress`) gets one share + the leftover, each non-final miniblock's `KeyHash` owner gets one
share `[E:SRC transaction_execute.go:63-158]`. **PREMINE = 1,228,125,400,000** `[E:SRC config.go:61]`.

---

## 7A. ★ Reward probability & miniblock orphaning (the "luck" levers)

> Realized reward = (miniblocks **found** ∝ hashrate) × (fraction **paid**, not orphaned). The paid fraction is
> the *only* hashrate-independent lever. This section is the adversarially-verified answer to "how do I get
> luckier?" — investigated via a multi-agent workflow + live measurement on the running node.

**Two miniblock classes** `[E:SRC difficulty.go:154-183; miner_block.go:364-373]`: a block = **9 NORMAL** (diff
**D**, `KeyHash` = miner address, each pays one share) **+ 1 FINAL** (`HighDiff`, diff **D×9**, `KeyHash` =
block-header hash). Crucially the **FINAL miniblock's finder is paid nothing for it** (`if mbl.Final { continue }`,
transaction_execute.go:146-148) — its share+leftover goes to the block's **integrator** (the assembling node's
`integrator_address`). A fresh miner always mines NORMAL(D); everyone is force-switched to FINAL(D×9) only once
9 normals are collected. getwork advertises the difficulty **matching** the template (D or D×9) — **no
wrong-difficulty bug, no discarded valid shares** `[E:SRC websocket_getwork_server.go:156-176]`.

**Inclusion = first-9-by-arrival** `[E:SRC miner_block.go:337-340; miniblockdag.go:98]`: the assembling node
builds the block from `GetAllMiniBlocks({height,tips})` in **arrival order, truncated to 9**. Orphaned (unpaid)
= overflow (10th+), wrong-tip bucket, or arriving after someone lands the final. **No reorg** (`flip_top` is dead
code, blockchain.go:1578), **no back-pay**. Peers reject miniblocks outside `[height-2, height+1]` as stale
`[E:SRC rpc_notifications.go:132-136]`. So the paid fraction is governed by **propagation speed + tip freshness**.

**The verified luck-lever verdict** (workflow + live measurement, 2026-07-04):

| Lever | Realized gain | Status |
| :---- | :------------ | :----- |
| `--integrator-address` = your wallet | **+11% if left on the dev default**, else 0% | **✅ CONFIRMED your wallet on the live node** — footgun avoided; you capture the integrator share `[E:EXEC]` |
| Tip-adoption lag (→ stale-tip orphans) | up to ~1.9% upper bound; actual ≪ that (DAG re-includes near-boundary minis) | **measured ~300 ms** `[E:EXEC]`; **same with/without the miner** (miner does *not* starve verify → 20 threads stays optimal); inherent to home/NAT + 2 distant peers |
| Peer connectivity | **<1%, below the noise floor** at 1.55% share | free; only *lower-latency* peers shave the lag, and none are available locally |
| Integrator "leftover" | ~0 (mod-10 dust, <9 atomic units = 0.00009 DERO/block) | **rejected** as a lever |

**Bottom line:** solo-mining on your **own synced integrator node** with your **wallet as integrator** already
captures essentially all hashrate-independent edge (live: **0 rejects**, integrator correct). No meaningful reward
gain remains in software or config — the residual ~300 ms lag is a home-network artifact below the noise floor.
Further gains require hashrate, which is at the hardware ceiling (§13–§14). *This is the same honest result the
ILP investigation reached: the system is already near-optimal, and the evidence says so.*

---

## 8. Transactions, privacy & the DVM

**Types** `[E:SRC transaction/transaction.go:30-40]`: `PREMINE=0, REGISTRATION=1, COINBASE=2, NORMAL=3,
BURN_TX=4, SC_TX=5`. A `Transaction` = `Transaction_Prefix` + `Payloads []AssetPayload` (:185-189). Privacy:
`AssetPayload.Statement crypto.Statement` + `Proof *crypto.Proof` (:97-108); ring size decoded from the
statement pointer list (:177); only tx `Version==1` accepted (:295-297).

**Homomorphic crypto** `[E:SRC cryptography/crypto/, 4,383 LOC]`: ElGamal ciphertext balances
(`algebra_elgamal.go`), Pedersen commitments (`algebra_pedersen.go`), bulletproof range proofs, field/point
vectors over `bn256` pairing. Balances are never plaintext on-chain.

**The DVM** `[E:SRC dvm/dvm.go]` is a **line-numbered BASIC interpreter** (not bytecode). `ParseSmartContract`
(:82) → `RunSmartContract(SC, entrypoint, state, params)` (:344) → `DVM_Interpreter` (:458-476: `IP`, `Locals`,
`State`, `store`). Loop `interpret_SmartContract` (:512) → `interpret_PRINT/DIM/LET/GOTO/IF`. Builtins are a
version-gated `func_table` with per-call `ComputeCost`/`StorageCost` gas `[E:SRC dvm/dvm_functions.go:58+]`
(`load`, `store`, `mapget`, `random`, `send_dero_to_address`, `signer`, `block_height`, `update_sc_code`, …).

---

## 9. P2P networking

**Wire = CBOR** (`fxamacker/cbor/v2`) over the `cenkalti/rpc2` transport `[E:SRC p2p/wire_structs.go;
connection_pool.go:37]` (msgpack is a commented import only). Init `P2P_Init`/`P2P_Server_v2`
`[E:SRC controller.go:96,498]`; **default P2P port 18089** (`--p2p-bind`, or `:0` when `--sync-node`)
`[E:SRC main.go:78,219]`.

- **Connection** `[E:SRC connection_pool.go:61-100]`: `Height/StableHeight/TopoHeight`, `Peer_ID`,
  `Top_Version`, `Client *rpc2.Client`, `Incoming`, `Tag`. Persistent `Peer` (`Address, ID, Miner, FailCount,
  Whitelist, Version`) `[E:SRC peer_pool.go:51-64]`.
- **Sync:** `sync_chain` (chain_sync.go:111), `bootstrap_chain`/fastsync (chain_bootstrap.go:45), erasure-coded
  block chunks (chunk_server.go).
- **Broadcast:** `Broadcast_Block` (:370), `Broadcast_MiniBlock` (:540), `Broadcast_Tx` (:596).
- **Priority/exclusive peers:** `--add-priority-node` (persistent) / `--add-exclusive-node` (only these)
  `[E:SRC main.go:80-81]` — this is exactly how your node is launched (§15).

---

## 10. getwork/RPC/metrics interfaces

Three server surfaces on the node `[E:SRC cmd/derod/rpc/]`:

**getwork websocket** — `Getwork_server()` binds **`0.0.0.0:10100`** by default (websocket_getwork_server.go:321;
`--getwork-bind`). Handler `onWebsocket` (:274) accepts `GET /ws/<wallet_address>` (:275-279). `SendJob()`
(:141) fills `Blockhashing_blob` from `mbl.Serialize()` (:193, the 48-byte miniblock) + live counters. It
tracks `mini_found_time[]` and exposes `HashrateEstimatePercent` = `Counter(tf)*100 / (tf*10/BLOCK_TIME)`
(:109-110) — your realized share rate.

**JSON-RPC** — namespace **`DERO.`** on `/json_rpc` and `/ws` `[E:SRC websocket_server.go:216-343]`:
`GetInfo, GetBlock, GetHeight, GetBlockCount, GetLastBlockHeader, GetBlockTemplate, SubmitBlock,
GetEncryptedBalance, GetSC, GetGasEstimate, GetTxPool, GetRandomAddress, GetTransaction, SendRawTransaction,
NameToAddress, Echo, Ping`. **RPC binds `127.0.0.1` by default** (mainnet port 10102) — *loopback, not
LAN-reachable* unless `--rpc-bind=0.0.0.0:10102` `[E:SRC main.go:77]`. Job/submit structs:
```
GetBlockTemplate_Result [E:SRC rpc/daemon_rpc.go:109-123]: JobID, Blockhashing_blob, Difficulty(str),
   Difficultyuint64, Height, Prev_Hash, EpochMilli, Blocks, MiniBlocks, Rejected, LastError, Status
SubmitBlock_Params [E:SRC rpc/daemon_rpc.go:127-130]: JobID, MiniBlockhashing_blob ("mbl_blob")
```

**metrics** — `WritePrometheus` at **`/metrics`** (Prometheus text) `[E:SRC metrics/metrics.go:48]`; optional
push to VictoriaMetrics `…/api/v1/import/prometheus` (:124). r19: served on a loopback bind; a public bind needs `ENABLE_PUBLIC_METRICS=1`; `DISABLE_METRICS=1` disables it (cmd/derod/rpc/node_metrics.go metrics_allowed). `derod`'s console also prints
`Network … Height … NW Hashrate … MH/sec Peers … MEMPOOL …` `[E:SRC main.go:872]`.

---

## 11. ★ The miner & AstroBWTv3 PoW — deep dive

### 11.1 The miner loop
`dero-miner` `[E:SRC cmd/dero-miner/miner.go]` connects `getwork()` → `wss://<daemon>/ws/<wallet>` (:401-413)
and spawns **N = GOMAXPROCS = 20** `mineblock` goroutines (:318-320, :168). Each `[E:SRC miner.go:453-541]`:
```
decode Blockhashing_blob → work[48]           # MINIBLOCK_SIZE
seed work[36:48] with crypto/rand + tid
loop while job unchanged:
    i++ ; BigEndian.PutUint32(work[43:47], i)          # nonce in bytes 43..46, tid in byte 47
    powhash = astrobwtv3.AstroBWTv3(work[:])           # THE hot call (mainnet, post-HF2)
    if CheckPowHashBig(powhash, diff): submit SubmitBlock_Params{JobID, work}
```
Active algorithm is **AstroBWTv3** for `height ≥ MAJOR_HF2_HEIGHT` (mainnet **481600**) `[E:SRC miner.go:499,524]`;
`astrobwt_fast.POW_optimized` (:504) is the pre-HF2 legacy path. `--bench` also exercises AstroBWTv3 (:390).

### 11.2 The AstroBWTv3 pipeline (one hash) `[E:SRC astrobwtv3/pow.go:34-2461]`
1. **`scratch = Pool.Get()`** — pooled ~2 MB `ScratchData` (indices/tmp_indices/sa = 384 KB each + data 96 KB)
   `[E:SRC sa_fast.go:16-35]` ⇒ **allocation-free steady state (measured 1 alloc/op)**.
2. **SHA256(input)** → salsa key; **Salsa20** over a 256-byte state (:52-54).
3. **RC4** re-key + XOR; `fnv1a` seed (:62-65).
4. **Branchy byte-code loop** (:69-2434): 256-way `switch` on `op`, mutating a ≤32-byte window with
   rotate/xor/popcount/shift, conditionally re-hashing (`xxhash`/`fnv1a`/`siphash`) and re-running RC4;
   appends each 256-byte state to `scratch.data`. **~261–276 iterations** (:2430).
5. **`data_len = (tries−4)×256 + rand&0x3ff` ⇒ ≈ 66–70 KB** `[E:DERIVE pow.go:2441]`.
6. **`sais_8_32`** builds the int32 **suffix array** over those ~68 KB (:2444).
7. **Final SHA256** over `sa_bytes[:data_len*4]` ≈ **264–280 KB** → 32-byte PoW hash (:2447-2461).

The SA is a **port of Go's `index/suffixarray`** (Nong-Zhang-Chen SA-IS)
`[E:SRC sais.go:1-14]`. `sort_indices`/`fix` in `sa_fast.go` is **dead code for v3** (the `//if REFERENCE_MODE`
guard is commented out → `sais_8_32` always runs).

### 11.3 Where the time goes (single-thread CPU profile) `[E:EXEC pprof]`
| Component | % CPU | Note |
| :-------- | ----: | :--- |
| **SAIS suffix array** (`induceSubS/L_8_32`, `length_8_32`, `assignID`, `placeLMS`, `unmap`, `_32` recursion) | **≈ 77 %** | dominant; **memory-latency-bound** (dependent gathers) |
| `sha256-simd.blockArm` | 6.05 % | **already ARM-crypto accelerated** |
| `runtime.asyncPreempt` | 5.6 % | scheduler preemption |
| 256-op branchy loop | <~4 % each | cheaper than intuition |

**Consensus constraint:** the PoW output feeds block validation — **it must remain bit-identical**. This is
checkable against the **10 known-answer vectors + a 1024-iteration repeat test** in `pow_test.go:34-74`.

---

## 12. ★ Host profile — Apple M1 Ultra (deeply probed)

All `[E:EXEC sysctl / system_profiler / go env]`:

| Property | Value | Source |
| :------- | :---- | :----- |
| SoC | **Apple M1 Ultra** | `machdep.cpu.brand_string` |
| CPU | **20 cores = 16 P (perflevel0) + 4 E (perflevel1)**, no SMT | `hw.perflevel0/1.logicalcpu` |
| **P-core L2** | **12 MB shared/cluster** | `hw.perflevel0.l2cachesize=12582912` |
| E-core L2 | 4 MB | `hw.perflevel1.l2cachesize=4194304` |
| L1 data | 64 KB | `hw.l1dcachesize` |
| Cache line | 128 B | `hw.cachelinesize` |
| GPU | **64 cores**, Metal 4 | `system_profiler` |
| Unified RAM | **128 GiB** (137,438,953,472 B), shared CPU⇄GPU | `hw.memsize` |
| Page size | 16 KB | `hw.pagesize` |
| memcpy floor | ≥ 48 GB/s (dd, cache-bound; true BW ≫) | `dd` |
| OS / toolchain | macOS **26** / Go **1.20.3** (1.26.4 tested) | `sw_vers`, `go version` |
| LAN | **<lan-ip>** (en1), gw <gateway> | `ipconfig`, `route` |

**Why the topology decides the tuning:** (1) **Heterogeneous cores** — 16 fast P + 4 slow E, no
`sched_setaffinity` on macOS (so `threadaffinity()` is a no-op on darwin `[E:SRC cmd/dero-miner/thread.go:25-27]`);
(2) **the ~272 KB per-hash SA fits the 12 MB P-cluster L2** — so it's L2-latency, not DRAM-bandwidth, that
bounds a single hash; (3) **128 GiB unified RAM is effectively unlimited** for the workload (~40 MB peak at 20
threads). (This was thought to enable a K-way ILP plan; §14 shows that plan was refuted by measurement.)

---

## 13. ★★ Miner performance engineering — the evidence & the real win

### 13.1 Corrected baseline (clean fixed-wall-clock harness, `cmd/_hashbench`) `[E:EXEC]`
> The earlier `--bench` (1000-iter) reported ~6,948 H/s but was noisy; the fixed-wall-clock harness (4 s/config)
> gives the true figure. **Both tools are in the tree** (`cmd/_hashbench`, underscore ⇒ excluded from `go
> build ./...`).

| threads | H/s | H/s/thread | | threads | H/s |
| --: | --: | --: | -- | --: | --: |
| 1 | 459 | 459 | | 18 | 7,344 |
| 8 | 3,516 | 439 | | 19 | 7,518 |
| 16 | 6,893 | 431 | | **20** | **7,678** |
| 17 | 7,148 | 421 | | 24 | 7,600 |
| — | — | — | | 32 | 7,675 |

**True baseline ≈ 7,680 H/s at 20 threads** (≈ **0.0077 MH/s**). `[E:DERIVE]` per-P-core ≈ 431 H/s (at 16),
per-E-core ≈ (7,678−6,893)/4 = **196 H/s** (E/P ≈ 0.45). **Oversubscription (21–32) gives nothing** — M1 has no
SMT, so extra goroutines can't hide sub-µs memory stalls (context switches are ~10 ms). **20 threads (=core
count, the default) is optimal — do not cap at 16.**

### 13.2 The G0 outcome — every compute-side lever refuted, and *why*
| Lever | Verdict | Evidence |
| ----- | ------- | -------- |
| SHA256 acceleration | ❌ already done | `sha256-simd.blockArm` @6% `[E:EXEC]` |
| **Newer Go 1.26.4** (vs 1.20.3) | ❌ no change | 2,169 µs vs 2,161 µs; **KA tests pass ⇒ bit-identical** `[E:EXEC]` |
| PGO (Go 1.20 `-pgo`) | ❌ +1.4 % slower | 2,228 vs 2,197 µs `[E:EXEC]` |
| `GOGC=off`, `asyncpreemptoff` | ❌ no help | ≤ baseline `[E:EXEC]` |
| goroutine oversubscription | ❌ no help | flat 21–32 threads `[E:EXEC]` |
| GPU/Metal | ⚠️ measured: GPU-only 0.2–0.4× CPU (SAIS-capped); GPU+CPU hybrid **could add ~+20–25%** but needs a full bit-identical GPU kernel | §13.4 |

**Root cause (the key insight):** *the SAIS phase is memory-latency-bound, not compute-bound.* That's why no
compiler/runtime knob moved the needle — you cannot speed up a loop that is stalling on dependent memory loads
by generating better instructions.

### 13.3 The MLP probe — proving the headroom (`cmd/_mlpprobe`) `[E:EXEC]`
A single M1 P-core running the SAIS-like dependent-gather pattern (256 KB working set), 1 vs K interleaved
independent chains:

| streams/core | Mloads/s | speedup |
| --: | --: | --: |
| 1 | 193 | 1.00× |
| 2 | 287 | **1.49×** |
| 4 | 397 | **2.06×** |
| 8 | 602 | 3.12× |
| 16 | 923 | **4.78×** |

**Interpretation:** with **one** hash per core, the core issues ~1 dependent load at a time and sits ~20–25 %
utilized on the SAIS phase — it can service ~4.8× more loads if they come from independent streams. **This is
the idle capacity a faster miner must capture.** The full-machine harness confirms bandwidth headroom exists:
per-thread H/s drops only ~6 % from 1→16 threads, so 20 independent streams don't saturate memory — the limit
is per-core load *latency*, exactly what interleaving hides.

### 13.4 GPU / Metal — MEASURED (correcting an earlier assertion)

> **This section was rewritten after actually measuring the M1 GPU** (prior versions asserted "non-viable by
> design" without evidence — a violation of this doc's own contract). Real Metal compute kernels were built and
> benchmarked (`scratchpad/metalbench.swift`, `metalsais4.swift`; runtime-compiled MSL, no full Xcode needed).

**Two measured facts `[E:EXEC]`, and they disagree with the old assertion:**
- **The branchy mixing loop is FAST on the GPU** — ~4.3 M mix-loops/s vs ~50–100 k on the CPU ⇒ **GPU ~40–90×
  faster** on the exact 256-op divergent loop I claimed was hopeless. The divergence penalty is real but far from
  fatal (Apple GPU SIMD width 32; measured with an 8-way switch, so real 256-way ≈ ¼ of that — still ≫ CPU).
- **The SAIS is SLOW on the GPU** — peak **~3,000 SAIS/s at 16 k threads = 0.39× the CPU's 7,680** (watchdog-
  and checksum-verified). The 272 KB/thread scratch has **no per-thread GPU cache**, so occupancy is capped and
  the dependent-load latency can't be hidden. The **unified 128 GB removes the *capacity* barrier**
  (`recommendedMaxWorkingSetSize = 110 GB`) but not the *latency/occupancy* barrier.

**The verdict, quantified:**
- **GPU-only AstroBWTv3 ≈ 1,500–3,000 H/s = 0.2–0.4× the CPU** (SAIS-capped; the real recursive SAIS is worse
  than the induce-only PoC). **Non-viable as a replacement** — but for a *precise measured reason* (the SAIS
  occupancy wall), not "SIMT divergence on the loop," which was wrong.
- **GPU *alongside* the CPU (independent full hashes) could ADD ~+20–25%** → ~9,000–9,500 H/s total. The CPU's
  SAIS stays L2-resident (12 MB) while the GPU streams main memory, so they don't fully contend on the ~800 GB/s.
  This is the one genuine upside — and I was wrong to dismiss it.

**Why it isn't shipped here (honest blocker):** a hybrid requires a **full bit-identical GPU AstroBWTv3 kernel**
— exact SHA256+Salsa20+RC4, the complete 256-op switch, and a **recursive SAIS flattened for GPU**, validated
byte-for-byte against `pow_test.go`'s 10 KA vectors. That is a multi-thousand-line MSL project with high
consensus risk (any deviation → rejected shares, net-negative). It is a real follow-on project, not a config
change, and the payoff is +20–25%, not "massive." Roadmap: (1) bit-exact MSL SHA256/Salsa20/RC4/256-op-loop
validated vs KA vectors → (2) flattened iterative SAIS in MSL → (3) watchdog-safe batched dispatch → (4) a
`--gpu` miner worker feeding the same getwork submit path.

### 13.5 Honest bottom line
- **Shippable today:** 20 threads (already default) = **~7,680 H/s**; keep `derod` on the other Mac so the
  miner owns all 20 cores; keep the machine cool (sustained P-core clocks). No config magic beats this.
- **The hoped-for win, now refuted:** intra-thread **K-way ILP interleave** of the SAIS looked like the ~1.6–2.1×
  path, but a direct PoC of the real induce loop measured **≤1.04× (net negative)** — see §14.
- **GPU (measured, corrected):** a GPU miner *alongside* the CPU is the one real remaining lever — measured
  ~+20–25% (§13.4) — but it requires a full bit-identical GPU AstroBWTv3 kernel (a large, consensus-risky
  project), not a config change. GPU-*only* loses (0.2–0.4× CPU, SAIS-capped).
- On CPU alone the miner is at its ceiling; reward is strictly linear in hashrate.

---

## 14. ★ The K-way ILP interleave — PROPOSED, then REFUTED BY MEASUREMENT

> **Update (ultracode round, 2026-07-03):** this lever was the multi-agent workflow's rank-1 recommendation and
> looked promising on the Amdahl model. **A direct measurement of the *real* induce loop refuted it.** It is
> documented here as a *closed* investigation so no future run repeats it.

**The thesis (what looked right):** run **K independent nonces per goroutine**, interleaving their SAIS induce
loops so the M1 P-core's out-of-order engine keeps K dependent loads in flight — converting the `_mlpprobe`'s
measured **4.78× idle MLP** (§13.3) into throughput. Amdahl projection (SAIS = 77%): K=4 → ~1.65×, K=8 → ~2.10×.

**Why it FAILED (the evidence)** `[E:EXEC cmd/_induceilp, cmd/_induceilp2]`: I built a faithful PoC of the real
`induceL_8_32` body (sais.go:822-853 — sequential `sa[i]` read, one random `text[k]` read, a carried bucket
pointer, a buffered random `sa[b]` write, a data-dependent `continue`) and measured **1-lane vs K-lane
interleave** on real-sized state:

| K (lanes) | induce throughput vs 1-lane |
| --: | :-- |
| 2 | **0.72–1.04×** (avg ~0.90×) |
| 4 | **0.55–1.03×** (avg ~0.82×) |
| 8 | **0.47×** |

**No speedup — net negative, monotonically worse with K.** The `_mlpprobe`'s 4.78× was a *pure* dependent-load
chain; the **real induce loop is not purely latency-bound** — it already overlaps its single random read with a
prefetchable sequential scan, arithmetic, and a store-buffered write, so one stream already extracts its own ILP.
Interleaving K lanes only multiplies the working set (K×~340 KB) and the branch-mispredict pressure, which
cancels and then exceeds any MLP gain. (The workflow's own verification flagged this risk: "the sequential
freq/bucket scans are already near-peak … treat all multipliers as projections to be MEASURED." The PoC measured
them.)

**Conclusion:** there is **no viable intra-thread ILP speedup** for AstroBWTv3 on this hardware. Combined with
the refuted compute-side and GPU paths, **the miner is at its hardware ceiling (~7,680 H/s, ~1.55% network
share).** This is by design — AstroBWTv3 is engineered to resist exactly these optimizations, and it does. The
only way to earn more DERO from this address is **more/faster hardware** (reward is strictly linear in hashrate),
not a software change. *(Caveat: the PoC ran while the miner used ~18 cores, adding cache contention; a clean
re-measure with the miner paused could refine the exact figures, but the direction — no robust gain — is
unambiguous across two independent PoCs.)*

---

## 15. ★ Deployment topology + runbook

### 15.1 Topology
A full node (`derod`) and the miner can run on one machine or on two machines on the same LAN. The miner connects to
the node's getwork websocket (default port 10100); RPC (10102) stays on loopback unless exposed deliberately; p2p is
KCP over UDP 11011.

### 15.2 Build (both machines) `[E:EXEC exit 0]`
```bash
cd <repo>
go build -o ./bin/derod       ./cmd/derod        # ~7 s, 16 MB
go build -o ./bin/dero-miner  ./cmd/dero-miner   # <1 s, 8.4 MB
```

### 15.3 On the second machine — expose node to the LAN
```bash
./derod-darwin --getwork-bind=0.0.0.0:10100 --rpc-bind=0.0.0.0:10102 \
   --add-priority-node=node.derofoundation.org:11012   # + your existing priority nodes
```
Then allow inbound TCP **10100** (mining) and **10102** (monitoring) in the macOS firewall. Verify from the
Mining machine: `nc -z -G1 <node-machine-ip> 10100 && echo reachable` — this is the check the §15.1 probe failed.

### 15.4 On the M1 Ultra — mine to your address (all 20 cores)
```bash
./bin/dero-miner \
  --wallet-address=<YOUR_DERO_ADDRESS> \
  --daemon-rpc-address=127.0.0.1:10100 \
  --cpu-max=90            # NEW: cap per-thread CPU duty cycle (1-100). 90 protects heat/power; 100 = full speed.
  # --mining-threads defaults to 20 (= optimal). Prompt shows live "MINING @ x.xxx KH/s".
```
**`--cpu-max` (new, verified `[E:EXEC]`):** a per-thread duty-cycle throttle (works ~40 ms, sleeps proportionally)
that only pauses *between* hashes — the PoW is unchanged. Measured: `--cpu-max=100` → 1964 % CPU; `=90` → 1780 %
(**90.6 %**); `=50` → ~980 % (50 %). Hashrate scales ~linearly with the cap (90 % ≈ ~6,900 H/s). Default is **90**.

**GPU (Milestone 1, `gpu-miner-poc/`):** the GPU now computes the **entire AstroBWTv3 pre-SAIS bit-exact** —
SHA256 → Salsa20/20 → RC4 → the **full 256-op branchy loop** (+ fnv1a/xxhash/siphash + stateful RC4 + break +
data_len) — producing the identical `(scratch.data, data_len)`. Validated **11/11 KA vectors** (10 pow_test.go
vectors + 48-byte miniblock): GPU `(data,data_len)` → `astrobwtv3.FinishHashFromData` (real SAIS+SHA) ==
`AstroBWTv3(input)`. The 256 opcodes are **auto-generated from `pow.go`** (`cmd/_opcodegen` → `loop_ops.metal.inc`),
so there's no hand-transcription. **Stage 3c DONE — the COMPLETE hash runs bit-exact on GPU** (pre-SAIS + suffix array + final multi-block SHA256;
11/11 KA == `AstroBWTv3`, `cmd/_fullhashvalidate`). Key insight: the suffix array is **unique**, so any correct
SACA == SAIS — I ported simple **prefix-doubling** (proven by `cmd/_sacheck`) instead of the recursive SAIS.
**✅ LINEAR SA-IS DONE — the full GPU hash now runs at ~1,167 H/s** (`gpu-miner-poc/gpu_hash_sais.swift`,
pre-SAIS loop + flattened recursive SA-IS + final SHA, one kernel, 11/11 bit-exact via `cmd/_fullhashvalidate`).
The linear SA-IS (validated bit-exact first try, `gpu_sais.swift`/`cmd/_saisvalidate`) is **10× faster than
prefix-doubling** (1,268 SA/s vs 118) — the O(n) win over O(n log n). At **~1,167 H/s alongside the CPU's 7,680
that's ~+15.2%**, batch 4096/3.5 s < the ~18 s job window = viable (no orphaning). SA-IS notes: only the int32
variant `sais_32` is needed (byte data promoted to int32; proven `cmd/_sais32check`); recursion is 100% on the
repetitive AstroBWT data, depth ≤ 7, flattened with a separate-buffer-per-level down/up stack. Real mining input
is **48 B** (`MINIBLOCK_SIZE`), which the kernel handles directly.

**✅ STAGE 3d DONE — `--gpu` is WIRED and LIVE.** A **subprocess bridge** (`gpu_hash_sais server`: stdin
`[u32 count][count·48 B]` → stdout `[count·32 B]`; no cgo, no build changes) + `cmd/dero-miner/gpu_worker.go`
(`mineblock_gpu`): spawns the server, runs a **bit-exact startup self-test** (GPU hash == `astrobwtv3.AstroBWTv3`,
else stays OFF — no rejected shares), then batches 4096 nonce-varied blobs → `CheckPowHashBig` → the same
`SubmitBlock` path as the CPU. New flag `--gpu=<path>`. **Live-measured against the synced node: GPU mining ACTIVE,
~1,273 H/s steady, 0 rejects = +16.6% over the CPU's 7,680** (targeted +13–20%). Enable on production by adding
`--gpu=gpu-miner-poc/gpu_hash_sais` (build once with `xcrun swiftc -O`). **freq-hoist optimization DONE** (OPT1, workflow-verified bit-exact): `sa_bmax`/`sa_bmin` no longer recompute
char-frequency — computed once per level per pass (6×→2×). Measured **+20% at low occupancy but +5.5% standalone /
+9.6% live** at the deployed 4096-batch — because the batch is **memory-bandwidth-bound**, so compute wins are
partly masked (the earlier +26% estimate assumed compute-bound — refuted by measurement). The real remaining lever
is a **coalesced memory-layout** restructure (large/risky), not more compute trimming.

**GPU throttle + reward stats** (both live-verified): **`--gpu-max=<90>`** duty-cycle-throttles the GPU (parity
with `--cpu-max`; measured 100→1,273 / 90→1,143 / 50→611 H/s). **Per-source reward attribution**: atomic
`cpu_minis`/`gpu_minis` counters at the 3 submit sites give an exact "who found each share" split (the daemon only
reports cumulative all-source `Blocks`/`MiniBlocks`/`Rejected`, so accepted-by-source is estimated by the found
ratio). `calcBlockReward()` (mirrors `blockchain/transaction_execute.go`, no heavy import) → **0.03075 DERO per
miniblock** at height 7.28M; a 60s `REWARD STATS` log + the prompt show blocks/miniblocks/rejected + CPU-vs-GPU
found split + estimated DERO per source. See [[dero-miner-changes]]. *(Debug scaffold in `astrobwtv3/gpu_bridge.go`: `FinishHashFromData` + two nil-guarded hooks;
KA + 1024-iter tests pass; hooks are debug-only.)*

### 15.5 Benchmark & re-verify (no node needed) `[E:EXEC]`
```bash
./bin/dero-miner --bench                                   # 1..20 thread scaling
go build -o ./bin/hashbench ./cmd/_hashbench && ./bin/hashbench 4   # clean H/s (expect ~7.7k @20)
go build -o ./bin/mlpprobe  ./cmd/_mlpprobe  && ./bin/mlpprobe      # re-confirm the 4.78× MLP headroom
cd astrobwt/astrobwtv3 && go test ./...                    # KA vectors — MUST pass (bit-identical)
```

### 15.6 Monitor chain + mining data — `./dero_monitor.sh`
A dependency-free poller is included in the repo root `[E:SRC dero_monitor.sh, bash -n OK]`:
```bash
./dero_monitor.sh <node-machine-ip> 10102 10100 10    # node-ip rpc-port getwork-port interval
# prints: time, height, topoheight, difficulty, NW-H/s, peers, getwork UP/down, mempool — from DERO.GetInfo
```
(Requires RPC exposed per 15.3. Also scrape Prometheus at `http://<node-machine-ip>:10102/metrics`: since r19 a non-loopback `--rpc-bind` serves `/metrics` (and `/dashboard`) only when derod runs with `ENABLE_PUBLIC_METRICS=1`, because the series carry peer IPs; `DISABLE_METRICS=1` turns it off everywhere. RPC series were renamed in r19 to Prometheus-valid labelled names: `rpc_requests_total`, `rpc_request_duration_seconds`, `rpc_response_bytes_total`, `rpc_request_errors_total`, each `{method="<m>"}`, plus `rpc_unknown_method_total`; the old `<method>_total` names are gone.)

---

## 16. Recursive self-improvement

Per `EVIDENCE_LOOP_PROMPT.md` §8 — captured so the next run starts smart:

**Skill** (`.skills/dero-miner-tuning/SKILL.md`, updated): the decisive move is `cmd/_mlpprobe` — it reframes
the whole problem from "the code is slow" to "the core is memory-latency-idle," which kills the compute-side
search and points straight at ILP interleaving. Fastest high-value probes, in order: `sysctl hw.perflevel*`
(P/E split) → `pprof -top` (find the 77 % SAIS) → `_hashbench` (true H/s, oversubscription) → `_mlpprobe` (MLP
ceiling) → KA vectors (bit-identical gate).

**Meta-eval:** ~100 % of assertions `[E:EXEC]/[E:SRC]`; 0 decision-affecting unverified items (§17).

**Warm-start invariants:** M1 Ultra (16 P/4 E, 12 MB P-L2, 128 GiB, no macOS affinity, no SMT); baseline
**7,680 H/s @ 20 threads**; SAIS = 77 % and **memory-latency-bound**; **MLP headroom 4.78×**; ILP ceiling
**refuted by measurement** (real induce loop ≤1.04× interleaved); newer Go / PGO / GOGC / GPU all refuted;
miner is at its ~7,680 H/s ceiling (~1.55% network share); mainnet `MAJOR_HF2_HEIGHT=481600` ⇒ AstroBWTv3 live; payout
address + LAN topology on file.

**Next closed loop:** implement §14 step 1 (batched pre-SAIS) → step 2 (K=2 interleaved SAIS) behind
`--interleave`, gated by the differential fuzz. Target: beat 7,680 H/s, measured by `_hashbench`.

---

## 17. Unverified ledger & conventions

**Unverified / caveats:**
- `[E:OBS, OCR-uncertain]` exact port digits of the ~18 priority nodes in `dero-chain-cmd.jpeg` (low-res; some
  render >65535). Peer identities + "~18 priority nodes" are solid; trailing digits are not.
- `[UNVERIFIED]` live network height/difficulty/NW-hashrate — the LAN node's ports were unreachable during
  the probe; re-run §15.6 once exposed.
- `[E:EXEC]` the K-way ILP interleave was **refuted** — see §14 (`cmd/_induceilp`, `cmd/_induceilp2` measured
  ≤1.04×). The earlier "~1.6–2.1× ILP ceiling" was a projection from the synthetic `_mlpprobe` + Amdahl; the
  direct measurement of the real induce loop overturned it. `[E:DERIVE]` the "7,820 H/s theoretical max" combines measured single-core,
  16-thread, E-core, and MLP figures via the stated Amdahl model — they are principled estimates, not a shipped
  measurement. The K-way SAIS must be *built and benchmarked* to confirm.
- `[E:SRC, internally inconsistent]` derod `--min-peers`/`--max-peers` help shows both `11/100` (usage line 62)
  and `31/101` (detail lines 85-86); the code default governs — not independently confirmed here.

**Conventions:** money in atomic units (1 DERO = 10⁵ atomic, per §7). Timestamps in **ms**. Ports mainnet
(getwork 10100, RPC 10102, P2P 18089, wallet-RPC 10103). The tree is **not a git checkout** here — changes are
local-only. Throwaway probe tools live in `cmd/_hashbench` / `cmd/_mlpprobe` (underscore ⇒ excluded from
`go build ./...`, kept as evidence-regeneration tools).

---

## 18. ★★ Network-layer latency & propagation engineering (2026-07-08)

**Why network speed = reward** `[E:DERIVE from §7A]`: a miniblock is orphaned (no reward) if it reaches the
integrator that finds the final block *after* that block's first-9 normal-miniblock slots fill — arrival-order
cap, **no freshness gate** (`rpc_notifications.go:132-136` only bounds height±). So the reward-limiting network
quantity is **propagation latency of my miniblock from my derod to the network**, not the loopback submit hop.

**The two reward-critical chains** `[E:SRC]`:
- **α (found share → network):** miner `submitShare` → wss/loopback → getwork `OnMessage` → `Accept_new_block`
  (`miner_block.go:442`: `VerifyMiniblockPoW` [1× AstroBWTv3, consensus-required] → `InsertMiniBlock` →
  `go P2P_MiniBlock_Relayer`) → `broadcast_MiniBlock` (`connection_pool.go:543`) → peers `NotifyMiniBlock`.
- **β (new tip → fresh job):** getwork dispatch loop polls every 10 ms; on height/mini change or 500 ms →
  `SendJob` (`websocket_getwork_server.go:361-385`); miner reacts on `job_counter++`. Already event-driven.

**Transport** `[E:SRC controller.go:280]`: derod⇄peers is **KCP/UDP**. `tunekcp` had an inverted, misleadingly
named profile: the **default** (`TURBO` unset, logged "P2P is in turbo mode") took `SetNoDelay(0,40,0,0)` =
40 ms flush, congestion-controlled, no fast-retransmit — the **higher-latency** profile. The low-latency
`SetNoDelay(1,10,2,1)` (10 ms flush + fast-retransmit) only activated with the counter-intuitive `TURBO=0`.

### 18.1 Changes shipped (all transport/latency-only — zero consensus change)
| # | Change | File | Evidence |
|---|--------|------|----------|
| A | **`--lowlatency` derod flag** selects the fast KCP profile (`SetNoDelay(1,10,2,1)`); honors `TURBO=0`; truthful startup log. `P2PLowLatency` package var. | `p2p/controller.go`, `cmd/derod/main.go` | `[E:EXEC]` `--help` shows it; docopt parses; `p2p` tests `ok` |
| B | **Latency-ordered miniblock broadcast** — `broadcast_MiniBlock` now sorts peers by `atomic Latency` ascending (parity with `Broadcast_Block`), front-loading fastest propagation paths. Order-only. | `p2p/connection_pool.go:543` | `[E:EXEC]` builds; `p2p` tests `ok` |
| C | **Miner submit path** — own `minerDialer` with explicit `TCP_NODELAY` (old code mutated the shared `websocket.DefaultDialer` global); reconnect backoff 1→8 s (was flat 10 s); `submitShare()` serializes JSON *off* `connection_mutex` (holds lock only for the write) + records submit latency. | `cmd/dero-miner/miner.go`, `gpu_worker.go` | `[E:EXEC]` live run: connected, GPU self-test bit-exact, **0 rejected** |
| E | **`net_metrics.sh`** — scrapes `/metrics` for `miniblock_propagation_duration_histogram_seconds` (VM vmrange buckets → count/avg/p50/p90) + peer counts. Portable POSIX awk. | `net_metrics.sh` | `[E:EXEC]` validated on synthetic VM data (count=10, avg 90.1 ms, p50≤60, p90≤113.6) |

### 18.2 THE dominant live finding `[E:OBS 2026-07-08 18:25-18:31]`
The user's node, restarted 18:09, was **still syncing** at 18:31 (`height 7297744` vs peer-reported `7302903` →
**~5,100 blocks behind**) on **only 2 peers (outgoing 2, incoming 0)** — repeatedly "backing off" from 3 of 5
priority nodes. Consequences: (1) the propagation histogram collects **no samples** until synced; (2) **mining
while behind produces stale miniblocks the network rejects (`> height+1`) — zero reward.** ⇒ For this node the
**binding reward constraint is peer connectivity / staying synced**, above transport micro-latency. Every derod
restart costs ~30 min of stale mining. Levers, re-ranked by evidence: **(1) more peers + minimal downtime**
(bumped launcher to `--min-peers=40`; keep derod 24/7; port-forward P2P for inbound) → **(2) `--lowlatency`**
→ **(3) latency-ordered broadcast**. Miner throughput unaffected: **7.8–8.16 KH/s, 23 samples, 0 rejects**.

### 18.3 Proposed follow-up (needs confirm — changes getwork behavior)
A **stale-mining guard**: getwork `SendJob` sets `params.LastError="syncing, N behind"` (and the miner
pauses/warns) when `best_peer_height - chain.Get_Height() > 25`. Prevents burning power on guaranteed-rejected
stale shares and makes the "am I actually earning?" state visible. Deferred — it touches the mining dispatch path.

---

## 19. ★★ Reward deep-dive round 2 — ground-truth measurement (2026-07-08, ultracode wf_42fdf10b)

11-agent open-loop analysis (5 analyzers → adversarial verify → synth) over the LIVE, synced, `--lowlatency`
pipeline. The discipline: **instrument before optimizing.**

### 19.1 CORRECTED network-share math `[E:DERIVE + E:OBS]` — supersedes the old "~1.55% share"
Every block packs **exactly 10 miniblocks** (measured: 399/399 and 2500/2500 blocks had 10 slots, avg 10.00),
each its own PoW at ~the reported `difficulty`. So **network hashrate = difficulty × slots/block ÷ BLOCK_TIME**
(≈ `12.8M × 10 / 18 ≈ 7.1M H/s`), NOT `difficulty/BLOCK_TIME` (which undercounts ~10×). ⇒ our TRUE network
share ≈ **~0.1%** (8.1 KH/s / 7.1 MH/s), not the 1.19–1.55% that the naive formula (and the old
[[dero-miner-m1-ceiling]] memory) implied. Verification: miner up 71 min at ~8 KH/s **found 2** miniblocks;
expected at 0.1% share ≈ 2.3 → **matches**. So the find-rate is exactly on target — no shortfall, no bug.
`[E:OBS reward_audit.py: 200-block window, 0 orphan blocks, 1 paid @7303138]`.

### 19.2 `--lowlatency` — SELF-AUDITED, KEEP AS-IS `[E:OBS + E:SRC]`
Live `KCP_RetransSegs/OutSegs` ran 21–54% steady-state (97% over 4 s = noise). The adversarial KCP audit proved
this is **path-loss/RTO (94% RTO-driven), NOT congestion** — at ~9 KB/s the KCP send window never binds, and
`nc=1` (CC off) only removes new-data throttling, which cannot reduce RTO/loss. Re-enabling CC (`nc=0`) is a
**refuted no-op** that would only slow resync bursts. Keep `SetNoDelay(1,10,2,1)`. Saturation (§19.1: 10/10
slots every block ⇒ the arrival-order cap binds every block) means propagation latency IS a *marginal* reward
lever (a 167 ms p90 delay ≈ losing to ~0.09 extra competitors/miniblock) — small but real and in the right
direction, so latency-order broadcast + `--lowlatency` are justified, not "negligible."

### 19.3 Ground-truth tools shipped `[E:EXEC]`
- **`reward_audit.py`** — scans `DERO.GetBlock` `block_header.miners[]` (list of miniblock miner *addresses*) for
  OUR address ⇒ on-chain PAID miniblocks / paid-share / realized DERO / orphan+side-block counts. The only truth
  source for paid_fraction (the node's `miniblocks_accepted_count` and the miner's `est_earned` count LOCAL
  acceptance, not canonical first-10 inclusion). Live: 1 paid @7303138, 0 orphan blocks.
- **`mining_dashboard.sh`** — one-view live monitor (sync/stall, peers, KCP retrans/loss delta, inbound
  miniblock p50/p90, paid-share vs fair-share, realized DERO, alerts). Hardened 4 bugs from the agent draft:
  GPU double-count in fair-share; the ~10× network-hashrate undercount (§19.1); RETRANS alert 10%→60% (steady
  state is lossy-but-benign); false "full orphaning" alert at small n → require ≥300 blocks & ≥5 expected paid.

### 19.4 Peer connectivity `[E:OBS]`
`KCP_PassiveOpens=0` forever ⇒ **inbound has never worked** (random UDP listen port, no forward). `--min-peers=40`
is a **no-op** (outbound peer supply genuinely exhausted, not a maintain-loop bug). Fix shipped in
`run_derod_lowlatency.sh`: `--p2p-bind=0.0.0.0:11011` (pin the port) + user forwards UDP 11011 on the router;
optional reciprocal `--add-priority-node` with a second LAN machine (NEVER `--add-exclusive-node` — it disables WAN
gossip). Payoff is redundancy + marginal fanout, magnitude unproven — verify via `incoming_connections_count>0`.

### 19.5 G0 DECISION — at the hardware-bound ceiling
Realized rate ≈ fair-share; 0 orphan blocks; no anomaly. **STOP piling on transport micro-opts.** The deliverable
was the *instrument*: run `mining_dashboard.sh` + `reward_audit.py` over ≥~20 finds (days) to get a real orphan
rate; if it rounds to 0, the setup is optimal (consistent with the compute-side ceiling in §13–14). Reward stays
**linear in hashrate**; the only durable wins are more hardware + zero downtime (every derod restart ≈ 30 min of
stale mining) + inbound-peer robustness. Refuted/forbidden: re-enable CC, broadcast-before-verify (fork), the
peer self-prune (zero reward). Deferred pending measured orphaning: `UDP_DUP` SetDUP, `go SendJob()` on new tip.

---

*End — every figure is `[E:*]`-tagged or quarantined in §17. Regenerate mining evidence with
`cmd/_hashbench` + `cmd/_mlpprobe`; reward evidence with `reward_audit.py` + `mining_dashboard.sh`; the module
map after any source change; and re-run `go test ./astrobwt/astrobwtv3/` after any PoW edit (bit-identical gate).*

---

## 20. ★★ Release142 → Release151/152 hard-fork migration (2026-08-19)

### 20.1 Why & what upstream changed `[E:SRC + E:EXEC git diff Release142..Release152]`
- **Hard Fork 3 activates at block 7,504,640** (`config/config.go MAJOR_HF3_HEIGHT`,
  `blockchain/hardfork_core.go` version-3 entry). Release142 nodes become incompatible at that height.
- Upstream repo is now **github.com/DEROFDN/derohe**; its `Release142` tag = commit `9b6a8b82` — byte-identical
  to the deroproject baseline we audited in Round 3, so all our Round-1..3 diffs remain valid.
- **Release152 (tag `1d3c4b7`, 2026-08-14, published "latest") = Release151 (`898730e`) + 1 commit**:
  "enhance transaction verification and caching for HF3 compliance". **G0: we build from Release152** —
  same fork line, plus the consensus-critical hotfix. Version string: `3.6.0-152.DEROHE.STARGATE+14082026`.
- **The HF3 mechanism** (root of the fork): pre-fork the tx-validity cache is keyed by **txid, which excludes
  proof bytes** (the same property we documented in Round 3 forensics). The Aug-2026 chain incident produced
  **17 duplicate / false-parity txs at heights 7,415,466–7,422,548** — now grandfathered in
  `blockchain/hardfork_fixes.go` (`HF3_Affected_Txs`). Post-fork the cache key becomes
  `Keccak256(tx.Serialize())` (full bytes incl. proofs) — `transaction_verify.go:430`.
  Our Round-3 stall block (7,412,675, minted 2026-08-01) is **NOT in the affected list** — and the Round-4
  live run **revised the Round-3 root cause**: the same `statement 0 verification failed` wall recurred on the
  FRESH Aug-10 datadir at canonical block `eadbe4fc…` (topo 7,467,516, txid `0045a6d4…`, minted Aug-13,
  ~30k confirmations, also not in the list). Two independent datadirs ⇒ not local disk rot: the pre-HF3 chain
  carries an ERA of txs that fail fresh replay verification although live nodes accepted them; upstream's
  grandfather list is simply incomplete for blocks minted after it was compiled (list ends at height
  7,422,548). Consequence: **replay-based catch-up across Aug-2026 blocks is unreliable for everyone until
  HF3**; the reliable path is a fresh `--fastsync` bootstrap (snapshot lands above the poisoned blocks).
- Other upstream changes: new `proof/proof_validation.go` (payload-proof amount sanity: int64-wraparound +
  21M hard-cap checks), corrected `status` supply via `blockchain.CalcSupply`, new derod console commands
  (**`fix` = topo-store corruption repair** — relevant to our Round-3 playbook, `gc`, `heap`, `profile`,
  `block_export/import`, `mempool_dump`), refreshed seed nodes (only <peer-ip> and <peer-ip> survive
  from the old list), fastsync/bootstrap error-handling (`bootstrap_fail`), P2P shutdown fix
  (`close(Exit_Event)` re-enabled), and a large vendor refresh (**kcp-go now needs Go ≥ 1.22**; Homebrew Go
  upgraded 1.20.3 → 1.26.6 on the M1 Ultra `[E:EXEC brew upgrade go]`).

### 20.2 Enhancement migration (everything from §13–§19 preserved) `[E:EXEC]`
New project root: **`<repo>`** (git clone of DEROFDN/derohe, branch `local-enhancements`
off tag Release152 — mods are now git-tracked; old root `<repo>` untouched as archive).
| Our change | Files | Port method | Overlap w/ upstream |
|---|---|---|---|
| GPU Metal miner (`--gpu`, bit-exact SA-IS bridge) | `cmd/dero-miner/gpu_worker.go`, `astrobwt/astrobwtv3/gpu_bridge.go`, `gpu-miner-poc/` | verbatim copy | none |
| `--cpu-max` duty-cycle throttle + minerDialer + submitShare | `cmd/dero-miner/miner.go` | verbatim copy | none (0 upstream diff-lines) |
| astrobwt debug hooks (nil-guarded) | `astrobwt/astrobwtv3/{pow,sais,sais2}.go` | verbatim copy | none |
| `--lowlatency` KCP profile + truthful log | `p2p/controller.go`, `cmd/derod/main.go` | patch on top of 152 | disjoint hunks (upstream: nil-guard Close, Exit_Event, console cmds) |
| Latency-ordered miniblock broadcast | `p2p/connection_pool.go` | patch on top of 152 | disjoint hunks (upstream: bootstrap_fail) |
| Spike programs & tools | `cmd/_*`, root `*.sh`, `reward_audit.py` | verbatim copy | none |

### 20.3 Gate ledger `[E:EXEC 2026-08-19]`
| Gate | Result | Evidence |
|---|---|---|
| patches apply cleanly (0 fuzz) | PASS | `patch` output, 3 files |
| `go build ./cmd/derod ./cmd/dero-miner ./...` | PASS (after Go 1.26.6 upgrade) | exit 0 |
| `go vet` (touched pkgs) | PASS | only upstream's own `main.go` "unreachable code" (present in pristine 152) |
| `go test ./p2p/ ./astrobwt/...` | PASS | ok 0.333s / ok ×3 (incl. new sha256simd_vector_test) |
| `--version` / `--help` flags | PASS | `3.6.0-152…`; `--lowlatency`, `--cpu-max`, `--gpu` present |
| offline bench (20 thr) | PASS | ~6,800 H/s = M1 Ultra CPU ceiling, no regression |
| live: `--lowlatency` log line | PASS | "P2P KCP profile: LOW-LATENCY …" in `bin/derod.log` |
| live: sync on healthy datadir | see RUN_REPORT.md Round 4 | monitored run |

### 20.4 Runbook change
Everything in §15 stays valid with **`<repo>`** substituted as the root. Suggested manual
run command is unchanged except: run from the new root, and the old priority nodes
`<peer-ip> / <peer-ip> / <peer-ip>` were dropped from upstream's seed list (keep
`<peer-ip>:11011` + `<peer-ip>:11011`; new seeds incl. `<peer-ip>:11011`, `<peer-ip>:11011`).
**Nodes must be on ≥151 before block 7,504,640.**

## 21. ★★ Post-HF3 chain split & the Round-5 defenses (2026-08-21)

HF3 activated at height 7,504,640 (~01:10 PDT 2026-08-21; one v2 block `54219c50…` rejected at 01:11:03 marks
the moment). The network SPLIT: non-upgraded nodes continue a v2 remnant chain forked at ~7,504,602 carrying
roughly half the hashrate (their difficulty ~2.1M vs our 4.1–4.5M). Both chains stay within ~60 blocks in
height — **chains are distinguished only by hash: block at height 7,504,640 is `e454090e…` on v3 (consensus)
vs `54219c50…` on v2.** Public infra is split too: explorer.dero-node.net follows v2; the local node's RPC is
ground truth.

Round-5 changes on `local-enhancements`:
- **`4712b7b`** — adopt upstream's expanded HF3 grandfather table (`blockchain/hardfork_fixes.go`, 75 entries).
  Source of truth is SKEWED across orgs: deroproject tag `Release152` (02f6e67) = DEROFDN tag (1d3c4b7) + 31
  entries (incl. replay wall #1 `0045a6d4…` @7,467,516); DEROFDN `community-dev` (161c7d8) adds 29 more (incl.
  wall #3 `4d56a1a1…` @7,497,836). All replay walls this project ever hit are now covered — deep replays below
  7,497,942 are safe. Entries affect only pre-fork replay, never post-fork consensus.
- **`3195f3b`** — v2-peer filter: `Connection.update()` drops peers reporting Height ≥ MAJOR_HF3_HEIGHT +
  STABLE_LIMIT with Top_Version < 3. Ends "deviated too much" churn from v2 peers and defuses the `--sync-node`
  footgun (chain_sync.go:172 rewinds to the peer's common point — ~1,000 blocks onto the v2 branch if a v2 peer
  were the sync node). Testnet unaffected (HF3 at genesis ⇒ Top_Version always 3).

Operational doctrine while the v2 remnant persists: measure cadence (~18–19 s/block == healthy) before touching
a node; never pop/--sync-node on a cadencing node; fingerprint any third-party explorer at height 7,504,640.

---

## 22. ★★ Round-6 health audit — what "healthy" looks like, and two latent p2p defects (2026-08-24)

A 64-hour census of the manual run (2026-08-21 08:16 → 2026-08-24 00:20) produced the reference profile for a
healthy at-tip DERO HE node on this hardware, plus two code fixes that came out of the census rather than out
of any symptom.

### 22.1 The healthy-node fingerprint (use this as the baseline for future audits)

```
12,453 blocks in 230,657 s        → 18.52 s/block   (network target 18 s)
186–199 blocks/hour, every hour   → flat; no catch-up bursts, no sag
longest inter-block gap 116 s     → normal Poisson tail, not a stall
0 reorgs                          → "Chain extended" strictly monotonic, 0 Rewind, alt_blocks_count 0
3 resync events in 64 h           → the node was AT the tip, not chasing it
316 ERROR lines (4.9/h), 0 real   → 51.4 % remote missing-file, 48.6 % peer churn (see §20 forensics rule)
0 tx-verification / 0 rejected / 0 deviated / 0 invalid-fork / 0 uncaught panic
fork block 7,504,640 = e454090e…, major_version 3; tip difficulty 5.0–5.5 M  → v3 consensus chain
```

The single most diagnostic line is **`p2p/connection_pool.go:717 "We need to resync with the peer"`**. Three
occurrences in 64 hours means the node received 12,823 blocks by direct broadcast and almost never had to pull.
A node that is quietly behind shows this line constantly; height alone cannot tell you that.

### 22.2 `d28c5b7` — the changeset server must not serialize a nil block

`p2p/rpc_changeset.go:63` was the **only** one of 23 `Load_BL_FROM_ID` call sites in the tree that discarded the
error, then called `bl.Serialize()` on the returned nil. `Load_BL_FROM_ID` (`blockchain/store.go:102`) returns
`(nil, err)` whenever `Block_tx_store.ReadBlock` misses — which on a **pruned** node (this one prunes at
7,498,540) is the normal answer for any peer requesting a changeset below the prune point, and is also possible
in a post-reorg race. The nil deref lands in `handle_connection_panic`, so the daemon survives but the peer
connection is destroyed. Observed once in 64 h (2026-08-22T13:55:20). Upstream `community-dev` still has it.

The fix returns the error. `chain_bootstrap.go:89` on the requester side propagates it and moves to another
peer; there is no ban path, so nothing is lost by answering honestly.

**Class rule** (third instance of it in this codebase, after `fill_common` and `safeLocatePruneTopo`): every p2p
handler runs behind a recover guard, which makes nil-deref bugs *invisible in aggregate* — they cost a peer
connection each and never a crash. Grep for discarded errors on store reads inside `p2p/`; the recover guard is
a containment mechanism, not a licence.

### 22.3 `9612278` — peer/ban persistence had a single, fragile trigger

`save_peer_list()` and `save_ban_list()` were reachable **only** from `P2P_Shutdown()` (controller.go:721). Every
non-clean exit therefore discarded the whole learned peer table. This node demonstrated it: `peers.json` and
`ban_list.json` carried a 2026-08-21 08:13 timestamp, three minutes *older* than the 64-hour run that was still
in progress.

A 5-minute ticker was added to the `maintain_connection_to_peers()` select. Lock discipline is unchanged —
`save_peer_list` → `clean_up()` (takes and releases `peer_mutex`) → `peer_mutex.Lock()`; sequential, never
nested — and the loop holds no lock at that point. Verified out-of-band on a testnet datadir: absent at T+240 s,
both files present at T+311 s with the daemon still running.

### 22.4 The p2p listener is UDP, and that changes the NAT instructions

`p2p/controller.go:575` calls `kcp.ListenWithOptions`, i.e. `listen udp 0.0.0.0:11011`. **There is no TCP
listener on the p2p port at all** — `lsof` on the live daemon shows `UDP *:11011` plus loopback TCP 10100/10102
and nothing else, and all 24 peer sessions are KCP sockets. Any port-forward, firewall rule, or reachability
test written for TCP 11011 is testing the wrong protocol. Inbound has been 0 for the entire log history
(`P2P.incoming` appears zero times since 2026-08-19) because the host sits behind NAT (<lan-ip> →
<public-ip>) with no UDP 11011 forward.

Downstream consequence, worth recording because it looks like a bug: with the persisted pool at 40 addresses of
which 17 are v2-remnant nodes the filter bans, only ~23 are usable — so `--min-peers=40` can never be satisfied,
`out < Min_Peers` stays true forever, and the 200 ms connect loop logs `backing off from this connection`
971 times per 64 h. That churn is a *symptom of the peer supply*, not a defect in the loop.

---

## 23. The wallet component, and how release parity was established (2026-08-25)

### 23.1 Release153 — we already had the code

DEROFDN tagged `Release153` = `c4e6f6b` (2026-08-21). Complete non-vendor delta from Release152:

| File | Change |
|---|---|
| `blockchain/hardfork_fixes.go` | +61 — `HF3_Affected_Txs` grows **16 → 75** entries |
| `p2p/connection_pool.go` | ±1 — ping failure logged at Info, not Error |
| `config/version.go` | ±1 — `3.6.0-152…+14082026` → `3.6.0-153…+21082026` |

Commits `dc8780f`, `390295b`, `818010e`, `161c7d8`, `c4e6f6b`. Round-5's `4712b7b` adopted
`origin/community-dev` (`161c7d8`) wholesale, so the first two were already present:
`git diff HEAD Release153 -- blockchain/hardfork_fixes.go` is empty, and the entry count is 75 on both sides.
Only the version string lagged → `bf274e5`. **Release153 contains no wallet changes.**

The reusable method: compare *trees*, never tag names (§21's tag-skew rule), and confirm parity with a
content probe rather than a diff read — e.g. `git show <ref>:blockchain/hardfork_fixes.go | grep -c '^\s*"[0-9a-f]\{64\}"'`.

### 23.2 `cmd/dero-wallet-cli` — never built here until now

Absent from `bin/` because every build in this project is a targeted `go build -o bin/<x> ./cmd/<x>` for the two
binaries in use. Upstream's `build_all.sh` does build the wallet (line 17) but cross-compiles into
`dero_darwin_amd64|arm64|universal/`. Nothing was missing from source.

Two facts that govern how it is invoked:

- **Transport/port.** `walletapi/daemon_communication.go:123 get_daemon_address()` defaults to
  `127.0.0.1:<Mainnet.RPC_Default_Port>` = **10102**, then `daemon_connectivity.go:89` forms
  `ws://<host:port>/ws`. The wallet speaks JSON-RPC over a websocket to derod's **RPC** port — never getwork
  (10100), which serves miners only.
- **Wallet-file resolution.** `cmd/dero-wallet-cli/main.go:181` defaults to the literal `"wallet.db"`, a
  **cwd-relative** path. Launching from the repo root writes key material into the working tree, and
  `wallet.db` there is **not** git-ignored (`.git/info/exclude` covers only `bin/`). Canonical home on this
  machine: `<wallet-dir>` (mode 700), always passed as an absolute `--wallet-file`.

### 23.3 What changed in the wallet between Release142 and Release151/152

Five source files, four of them real defects (Release153 adds nothing further):

- `walletapi/daemon_communication.go` — `DecodeEncryptedBalanceNow(e)` → `DecodeEncryptedBalance_Memory(e, balance[scid])`:
  the homomorphic balance decode is seeded from the last known value instead of searching from zero.
- ″ — **off-by-one, twice**: `sender_idx <= RingSize` → `< RingSize`. Valid indices are `0..RingSize-1`, so
  transfer-history display could index `Publickeylist[RingSize]`.
- ″ — `SyncHistory` header-mismatch rollback rewritten; the old `entries[:i-skip]` + `continue` mis-truncated and
  skipped the decrement when several entries shared a topoheight.
- `walletapi/wallet.go` — `TokenAdd` initialises `EntriesNative` (previously panicked *"assignment to entry in nil
  map"* on a fresh/restored wallet); four read accessors moved `Lock()` → `RLock()`.
- `walletapi/daemon_connectivity.go` — `Connect()` sets `Connected = false` when `test_connectivity()` fails.
- `walletapi/wallet_transfer.go` — `TransferPayload0`: bare `return` → `if err != nil { return }`.
- `cmd/dero-wallet-cli/prompt.go` — `show_transfers` no longer force-syncs before listing.

### 23.4 Upstream's wallet test suite is red, and it is not us

`Test_Payload_TX` (*"expected 1520000 actual 100720000"*), `Test_Creation_TX_morecheck`, and
`walletapi/xswd TestXSWDServer` fail. Authorship was settled by checking out pristine `Release153` into a
throwaway `git worktree` and running the same commands: byte-identical failures. `git diff --name-only HEAD
Release153 -- walletapi/ cmd/dero-wallet-cli/` is empty — this project has never modified wallet code. Treat
these as stale upstream fixtures; they are not a safety net for wallet changes.

## 24. ★★ The evidence harness, and the reading that reframed the live node (2026-10-20, Round 7)

### 24.1 What was built
`harness/` turns this tree into a **projection**: `artifacts/dero-src-arch.html` is generated, never written, and
regenerating it on an unchanged tree reproduces it byte for byte (verified: two consecutive builds, identical
fingerprint). The pattern is `~/openelm-env/working-tools/artifact-kit` plus the `sdx85_wlan_driver_src/harness`
layout, rebuilt for a Go daemon that is **running while the page is built**.

| piece | what it does |
|---|---|
| `prep_corpus.py` | walks the tree, runs ctags over the Go packages (3,754 symbols), hashes every citable input |
| `miners/minelib.py` | the anchor machinery: a claim without a verbatim ≥12-char line match cannot be written |
| `miners/mine_inventory.py` | packages, LOC, the first-party import graph, vendored weight |
| `miners/mine_consts.py` | 36 consensus constants, each read from the line that declares it |
| `miners/mine_flows.py` | six execution chains, hop by hop; one moved hop drops the whole chain |
| `miners/mine_logbridge.py` | every console line joined to the Go literal that printed it, with a logger-ownership rule mined from the `WithName` calls |
| `miners/mine_localdiff.py` | this tree vs upstream `Release153` |
| `miners/mine_runtime.py` | read-only snapshots of the live daemon, pretty-printed so each field is anchorable |
| `miners/mine_findings.py` | the analysis rows; every derived number is computed at build time from the cited lines |
| `gen_deroarch.py` | resolve → verdict merge → render → stamp → rewrite the skill's AUTO block |
| `run_gates.py` | G1–G12, appended to `loop/GATES.md` |
| `kat/verify_deroarch.py` | DK01–DK29 on a scratch copy, with 21 mutations that must each flip their own KAT (Round 12) |

Classes are closed and derived from **where a line lives**: SRC (first-party Go), EXT (`vendor/`), HARNESS
(`harness/runtime/`, the project's own reports), GK (skills + memory store), PLAN (`loop/PROPOSALS.md`). A row whose
declared class its anchors cannot prove is re-derived and says so; a row with no resolvable anchor is never drawn.

### 24.2 ★★ Nothing in `GetInfo` tells you whether the node is at the tip
The first full run produced an impossible number — 7,345 blocks in 1,667 seconds — and following it proved the node
was **40.4 days behind**, replaying history at 3.5 blocks/second, while every summary field said it was fine:

* `averageblocktime50` is `(timestamp(tip) − timestamp(tip−50)) / 50000`
  (`cmd/derod/rpc/rpc_dero_getinfo.go:71`). It is a property of the **block timestamps**, so it reports the cadence
  the network ran at *when those blocks were minted* and reads ≈18 s whether you are at the tip or replaying
  September. **It can never indicate lag.**
* `target_height` — the field that would answer the question — is commented out at `:74` and therefore always 0,
  the same class of unimplemented reporting as `white_peerlist_size`/`grey_peerlist_size`.
* `height`, `topoheight`, `stableheight` stay mutually consistent while far behind; `status` reads `"OK"`.
* The interactive console **does** show it: the prompt is `our_height/topo [best_height/best_topo]`
  (`cmd/derod/main.go:331`). The operator's own paste read `7585741/7585741 [7786700/7786700]` — a 201,000-block
  gap in plain sight, in a line that is not available over RPC.

**The decisive local reading is the age of the tip block**: `DERO.GetBlockHeaderByTopoHeight` at `topoheight`,
its `timestamp` against the wall clock. The harness captures it on every snapshot (`rt-tipage`), KAT DK20
recomputes it, and gate G9 fails if the gap stops closing. Any DERO monitoring that reads only `GetInfo` is blind
to this.

### 24.3 ★★ `process_transaction_sc` reverts into a panic, and books the transaction as free
The console line `Recover while executing SC` at 13:37:02 has a complete chain of custody:

1. `blockchain/blockchain.go:1016` calls `process_transaction_sc`; the contract call fails.
2. `blockchain/transaction_execute.go:402` takes the error branch. `Extract_signer` fails (`:448` returns
   `"unknown signer"`), leaving `signer` the zero `[33]byte`.
3. `:410` — the *else* arm, commented *"we could not extract signer, we burn all the funds"* — calls
   **exactly the same `dvm.ErrorRevert(..., signer, ...)` as the success arm at `:408`**. The burn is not
   implemented; the refund is attempted with a key that cannot be in the tree.
4. `dvm/simulator.go:276` reads that key; `vendor/.../graviton/node_leaf.go:108` reports it as
   `collision, keyhash … not found`; `:277` panics on an error whose own comment says *"only disk corruption can
   reach here"*.
5. The deferred recover at `transaction_execute.go:286` swallows it. `process_transaction_sc` uses **named
   returns**, so it yields `(0, nil)` — the caller books **zero fees** and treats the transaction as successful. **[CORRECTED Round 11, ARCHITECTURE §27.2: `gas = tx.Fees()` is assigned before the panic and the recover assigns nothing, so the caller gets (tx.Fees(), the SC error): the fee is KEPT, err is ignored by the caller, and the burn stays burned.]**

It is deterministic, so every node does the same thing and the chain does not split. **It must not be fixed
locally**: collecting that fee would change `fees_collected`, change the coinbase and fork this node off the
network. Recorded in `harness/loop/PROPOSALS.md` as P2 precisely so a later reader does not "fix" it. The
consensus-neutral part — setting `err` in the recover and counting the event — is P1.

### 24.4 The kit gained `data-verbatim`
Retrofitting the kit onto `release151-migration-report.html` exposed a real limitation in `textkit.audit`: a cited
`RUN_REPORT.md` line that itself ends in "…" was flagged as a silent cut, in the rendered DOM only (the citation
panel is drawn by JS). A quoted line has no longer sentence to reveal, and demanding a tooltip would force the page
to misreport its source. `textkit` now exempts any element marked `data-verbatim` and its descendants, and
`assetkit.CITE_JS` marks every quoted line that way. Fixed upstream in
`~/openelm-env/working-tools/artifact-kit` and re-vendored here.

## 25. ★★ Auditing the Foundation's range-proof disclosure (2026-10-20, Round 8)

On 2026-10-20 the DERO Foundation published (derofoundation.co/#/press) a range-proof **soundness defect** and
withdrew support for the chain. The claims were ingested as **EXT** (`harness/external/derofoundation-press-20261020.txt`
— a line proves only that it was *said*) and audited by a 199-agent workflow: six independent investigations
(transcript, range proof, HF3 bug, supply accounting, Zether lineage, live chain), each finding then attacked by
three distinct lenses (anchor re-read, cryptographic reasoning, over-claim). 64 findings, 39 survived, 25 refuted;
17 forensic rows survived a second anchor re-resolution in `mine_forensics.py` and are on the page's **Disclosure
audit** section. **This is a defect-class characterization, not an exploit** — every agent was instructed not to,
and did not, construct a coin-creating proof.

### 25.1 Per-claim verdict
| claim | verdict | what the tree shows |
|---|---|---|
| **C1** a soundness defect exists | **CONFIRMED** | real, and reached independently of the press (below) |
| **C2** mechanism: a prover-adjustable generator unbound from the transcript | **REFUTED mechanism / CONFIRMED consequence** | no generator crosses the wire; every base is a NUMS constant or a verifier-recomputed function of a hard-checked challenge. The *consequence* holds for a different reason (the blinding scalar, not the generator). |
| **C3** the broken component is the sole magnitude gate, silent | PARTLY-CONFIRMED | the range proof is the only amount check; nothing downstream re-pins it |
| **C4** inherited from ConsenSys Anonymous Zether | PARTLY-CONFIRMED | lineage confirmed on disk (struct/variable renames one-to-one); the specific Solidity line cannot be read offline |
| **C5** present from genesis of the proof path | PARTLY-CONFIRMED | `git log --follow` bottoms out at the earliest DERO-HE releases with the construction unchanged; mainnet-genesis byte-identity not independently confirmable here |
| **C6** HF3 double-spend, 23,886,517.3 floor / 14 undecodable | PARTLY-CONFIRMED | fork height/date/major-version flip exact; 75-tx grandfather table real; the *figures* require off-chain forensics a pruned node cannot reproduce |
| **C7** 5,000,000 burned, attribution unproven | PARTLY-CONFIRMED | the consensus binding is real; the specific attribution is, as the Foundation itself says, not chain-provable |
| **C8** ending support, no rollback | CANNOT-DETERMINE-LOCALLY | a policy statement with no code referent |

### 25.2 The defect, as the code shows it (C1)
The Bulletproofs inner-product argument requires its generator `u` to be **independent** of the Pedersen blinding
base `H`, so the `H`-coefficient of the verification point yields its own equation and forces the prover's blinding
scalar. DERO instead builds `u_x = gparams.H^o` (`cryptography/crypto/proof_verify.go:430`) on the **same base**
that one line later carries `H^(-proof.mu)` (`:452`), and `proof.mu` appears in the whole verifier exactly once as
that subtraction, plus one debug print at `:511` — it is in **no Fiat-Shamir preimage**. The `H`-axis of the
verification equation therefore collapses to a single equation containing one free prover variable. The final
inner-product check is a bare string-compare of two points (`proof_innerproduct.go:307`, comment *"need something
better here"*). The agents established the degree of freedom and the collapsed invariant and **deliberately stopped
there** — the surrounding sigma / t-polynomial checks would have to be shown non-re-pinning by an executable
experiment, which was not run.

### 25.3 Two findings of our own, not in the press (both CONFIRMED)
- **The HF3 grandfather table is an ungated, permanent proof-gate exemption.** On entry to
  `verify_Transaction_NonCoinbase_internal`, a TXID found in `HF3_Affected_Txs` is stored into
  `transaction_valid_cache` *before any verification runs*, with no height condition; the later cache lookup keys
  on the bare TXID for any transaction whose header height is below `MAJOR_HF3_HEIGHT` — true of all 75 entries by
  construction — so the store and lookup keys coincide and `Proof.Verify` is skipped for those txids, permanently.
- **The HF3 parity override reads Go's zero value on non-p2p execution paths.** The executor overrides the
  cryptographically-derived spend parity from the table's `Parity` field, which is **never set** in any of the 75
  map literals (sole writer is one `p2p` catch-up line gated below `MAJOR_HF3_HEIGHT`); a local DB replay / bootstrap
  path that reaches execution without that p2p branch reads `Parity == false` (the zero value).

### 25.4 The operator takeaway (CONFIRMED against the live node)
One function call decides whether a transaction's amount is legitimate; if it returns true the node adds encrypted
numbers it never inspects into the balance tree. There is no second opinion. **`total_supply` is not a count of
coins** — `blockchain/supply.go` computes it from the emission formula (block reward × height plus constants), so it
prints the same number on a chain inflated by any amount (confirmed: no code path sums the balance tree, and
balances are ElGamal ciphertexts that cannot be summed without every private key). This is why the Foundation's
figure needs off-chain forensics and cannot be checked from a node — and why `find-attip` and this finding share a
root: the daemon's summary numbers answer a narrower question than they appear to.

### 25.5 Harness and kit changes
`harness/external/` is now an **EXT** root (documents under audit); `mine_press.py` ingests 14 claims, each
attributed, never asserted; `mine_forensics.py` ingests the audit and re-resolves every anchor, dropping any
proved only by the audited document; the page gained a **Disclosure audit** section; **DK21** (said ≠ so) and
**DK22** (no circular proof) were added. The reusable **EXT-under-audit** pattern is documented in the
artifact-kit README.

## 26. ★ Reading derod's console: origin rules for ERROR lines (2026-10-21, Round 10)

**Whose error is it.** `p2p` calls peers via `cenkalti/rpc2`. When the remote handler returns an error, rpc2 delivers
its text as `ServerError(resp.Error)` (`vendor/github.com/cenkalti/rpc2/client.go`). Our side then logs
`Call failed GetObject` with that text. So any message after `Call failed GetObject` may have been produced on the
peer. Decide by asking whether our call path can produce it. `Peer.GetObject` on the server side (`p2p/rpc_object_request.go`)
loads blocks through `Load_BL_FROM_ID → storefs.ReadBlock (os.ReadFile) → Block.Deserialize`, so "Invalid Major
Version in Block" (`block/block.go`, `binary.Uvarint` returning done ≤ 0) is the peer reading an empty or garbled
`.block` file. Its `ReadTX` failure prints the peer's own `bltx_store/<h[16]>/<h[17]>/<txid>.tx` path (`storefs.getpathtx`). This tree's `ReadTX` would say `tx <id> not found` instead (storefs.go:300), so a raw `open …: no such file` also fingerprints the peer as an older build. `Uvarint` also fails on a 64-bit overflow, and `ReadBlock`'s recover can return `nil, nil`; both give the same text.

**Concurrency.** p2p never calls `SetBlocking`, so rpc2 runs each incoming request in its own goroutine. Two
NotifyINV for the same tx can therefore fetch concurrently. Before P5 (Round 11), `NotifyINV` called `c.exit()` on any GetObject failure; since then a tx-only fetch answered with the peer's own error keeps the connection until the 8th consecutive one. The pre-P5 behaviour: on any GetObject failure
(`p2p/rpc_notifications.go`), which closes the TLS socket. rpc2's single shared read loop, partway through the next frame, then fails ("Could not read data size … closed pipe") and hands that error to the second handler's pending call. On an outgoing KCP session only our own `UDPSession.Close` fires `die` (kcp `sess.go:466`), so every "closed pipe" on an outgoing connection means our side closed it; the trigger is what one log line cannot show.

**SC execution.** `process_transaction_sc` recovers panics (transaction_execute.go:286). An anonymous SC transaction
that fails takes the revert branch with `signer` still all-zero. `dvm.ErrorRevert` reads that account from the
balance tree (simulator.go:277), and graviton reports `collision, keyhash blake2s(33×0x00) not found`. The outcome is deterministic on every node that replays those blocks (fastsync skips them); §24 documents why it must not be patched locally. A contract whose source uses any
type other than Uint64/String fails `dvm.check_valid_type`. That error falls through to the same revert branch,
which refunds a signer it can identify.

The automated form of these rules is `harness/miners/mine_triage.py` (rows `tri-*`, gated by DK23–DK25). Two adversarial verifiers upheld all six causes and corrected the wording of each (`harness/model/verify/verdicts_triage.json`).

## 27. ★★ Round 11: the console-error fixes, the consensus guard, and shadow verification (2026-10-21)

**27.1 Code (non-consensus).** `p2p/object_errors.go` classifies a failed `Peer.GetObject` as *remote*
(`rpc2.ServerError`), *closed* (`io.ErrClosedPipe`, `rpc2.ErrShutdown`, or "closed pipe" text from `Read_Data_Frame`'s
`%s` formatting), or *other*. Remote and closed are logged as V(1) INFO (file log), other stays an ERROR. NotifyINV
keeps the connection after a tx-only remote failure, up to `MAX_TX_FETCH_FAILURES = 8` consecutive. The count is an
atomic per connection, reset only by a reply that delivered a tx. `blockchain/sc_revert_log.go::is_zero_signer_revert`
matches `graviton.ErrNotFound` whose text names `keyhash <blake2s(33×0x00)>`. Every graviton not-found format puts the
looked-up key right after "keyhash "; the collision form's second hash is "keyhash in ram". The recover in
`process_transaction_sc` returns early on that match after one V(1) line, assigning nothing. The SC-parse failure is
a V(1) INFO.

**27.2 Correction to §24.** The zero-signer revert keeps the fee: `gas = tx.Fees()` precedes the panic, and named
results survive a recover that does not assign them. The burn stays burned. Payload SCIDs are pre-cached
(blockchain.go `sc_change_cache` loop), so ErrorRevert panics before any write: no state side effect.

**27.3 Consensus guard.** `harness/consensus_guard.py` (G13, DK26), against the commit the running binary was built from
(bf274e5). Result: `transaction_execute.go` = logging-only plus the reviewed early return; `sc_revert_log.go` = a helper
used only there; `config/version.go` = build metadata only.

**27.4 Verification ladder.**
1. Unit tests, including a real graviton tree, the byte-exact live collision text, Go named-result semantics, the
   failure budget, the empty-reply dodge, and the log levels, all under `-race`.
2. Two adversarial code reviews. They found 3 issues, all fixed: the V(2) drop, the budget dodge, and stale harness text.
3. Shadow nodes: an APFS clone, loopback-exclusive sync from the live node, and control (old binary) and candidate
   (new binary) side by side, with treehash equality against the live node at every shared topoheight.
4. Install, then re-projection and gates.

Pipeline: `harness/pipeline/fix_build_verify.py` (events in `harness/loop/runs/pipeline_*.jsonl`, summary in
`harness/loop/PIPELINE_LAST.json`). Final run: shadow 240/240 treehash + 120/120 block-hash equal, 0 regressions
against the control; installed `3.6.0-153.DEROHE.STARGATE+21102026` (old kept as `bin/*.round10-backup`); 13/13 gates,
27/27 KATs, 19/19 mutations. Shadow mechanics learned the hard way: clone `topo.map` before `balances` and
`bltx_store`; the live node accepts one connection per remote IP, so the candidate dials the LAN address.

## 28. ★★ Round 12: the intelligence harness and the observability/robustness fixes (2026-10-22)

**28.1 Discovery.** An 8-dimension read-only investigation (datadir, logs, p2p security, RPC observability,
concurrency, harness gaps, coherence, new features). Each dimension was attacked by an adversarial verifier: 124
findings, 99 CONFIRMED, 25 PARTLY, 0 refuted. Kept verbatim in `harness/runtime/discovery_20261022.json`.

**28.2 Persistent-data formats (verified live).**
- `topo.map`: 48-byte records (blid[32] | state_version u64 LE | height i64 LE). It is a whole number of records; the
  last record equals RPC topoheight/top hash; the prune point is the first record with a block id.
- `balances/version_root.bin`: one (findex u32, fpos u32) pointer per graviton version. All are in bounds and monotonic.
- `bltx_store`: blocks are fanned out by h[0]/h[1] and txs by h[16]/h[17]. Every topo record after the prune point has
  its block file.
- `peers.json` and `ban_list.json` are JSON maps. The tool is `harness/intel/datadir_intel.py`; gate G14.

**28.3 Observability.**
- `DERO.GetSyncInfo` (`cmd/derod/rpc/rpc_dero_getsyncinfo.go`): status from `classify_sync(peers, lag, tip_age)`.
  Thresholds: lag > 2 blocks means syncing (the p2p +2 propagation slack). A tip older than 300 s with no peer ahead
  means stalled (P ≈ e^-16.7 at an 18 s mean). No peers means isolated.
- GetInfo `target_height` now comes from `p2p.Best_Peer_Height()`, which excludes self.
- Counters: `recovered_panics_total{level}`, `rpc_recovered_panics_total`, `p2p_tx_fetch_failures_total`,
  `p2p_tx_fetch_budget_drops_total`, `p2p_bans_total`.
- `rpc_internal_error` (`cmd/derod/rpc/rpc_errors.go`) replaces the 14 handlers that returned `debug.Stack()` to clients.

**28.4 Robustness (non-consensus).**
- `Verify_Handshake` uses `semver.Parse` and guards `len(v.Pre)`.
- TreeSection returns on a malformed request.
- The accept loop `continue`s after closing duplicate or banned connections.
- `calculate_avg_offset` guards count==0.
- peers.json and ban_list.json are written atomically via `p2p/persist.go`, and connected peers are re-stamped before saving.
- `Find_Blocks_Height_Range` guards empty search results. Consensus guard ALLOWED entry `find-blocks-empty-guard`, with a
  computed caller chain: IS_TX_Valid ← RPC/console/simulator/unused Is_TX_Orphan.
- The malformed logr call at the block-version reject is fixed.

**28.5 Verification ladder.**
- Consensus guard (G13), gofmt/vet, and 10 new unit tests.
- 15 Go mutations (15 caught) and `-race` over 6 packages (0 races).
- Control + candidate shadows: 240/240 treehash and 120/120 block hash equal.
- Feature probes, control vs candidate:
  - GetSyncInfo: "no such method" vs "synced".
  - Registration tx: -32098 panic vs ok.
  - Stack in error: yes vs no.
  - target_height: 0 vs 7,793,366.
- Install with `bin/*.21102026-backup`.
- 29/29 KATs and 21/21 mutations; gates G1–G15.

## 29. ★★ Round 13: P2P hardening, concurrency fixes, miner intelligence, coverage (2026-10-22)

**29.1 Inbound P2P resource bounds.**
- `Read_Data_Frame` reads through `io.LimitReader`, so allocation tracks received bytes; a 40 MB claim with 3 bytes
  sent allocates under 4 MB (test).
- Heavy server handlers run under `heavy()`: per-connection cap 8, global cap 64. It is nil-safe, because it runs
  before the handler's own recover.
- The 4 KiB header limit proposed in discovery was **rejected**: response headers carry peer error strings that older
  peers fill with hex blocks and stack traces.

**29.2 Outgoing deadlines.** `Connection.call` wraps rpc2 `CallWithContext` with per-method timeouts. Only fetch
timeouts are scored. Notification replies wait for the peer to fetch and validate what we announced, so their
timeouts are not misbehaviour.

**29.3 Misbehaviour policy.** `p2p/penalty.go`: decaying score per IP; temporary bans escalate 600 s → 24 h; the reason
set is fixed (an unknown reason panics in tests). Exempt: `nonbanlist` hosts, with hostnames resolved once. The
upstream `IsAddressInBanList` inversion is left dormant on purpose (§ penalty.go header).

**29.4 Connection state.**
- `update()`: `state_mu` guards StateHash and the clock ring; `clock_offset`, `update_received_ns` and the
  `Top_Version` read are atomic.
- `exit()` sets `exited` and `CompareAndDelete`s its own pool entry before closing; `Connection_Add` refuses an exited
  connection; `Connection_Delete` is identity-based.

**29.5 Miner intelligence.**
- `DERO.GetMiningOutcome`: the submitted hashing blob deserialises to the same miniblock hash a block carries.
- Resolution happens only at stable height; a load failure stays pending.
- `paid` means "a topo-ordered block at that height carries it". Side blocks cannot be enumerated from the topo
  store, so the only orphan reason is `not_included`.
- Stale-work signal (`should_hold_jobs`: ≥3 peers, lag > 2) is reported in GetSyncInfo/GetMiningOutcome, not enforced.
- Inbound reachability: `kcp.DefaultSnmp.PassiveOpens` == 0 after 30 min ⇒ "unreachable: forward UDP".

**29.6 Coverage.** `mine_coverage.py` reports covered = a mined row cites a line inside the function (declaration →
closing brace). Risk = names matching verification/PoW/difficulty/fee/balance/handshake/ban/prune/…: 23/121 cited,
85/1047 overall. The measured risk register (121 rows) is excluded from the metric. G16 is a ratchet per miner
method; DK30 recomputes coverage by an independent source scan (exact agreement).


## 30. ★★ Round 14: the descriptor suffix sort in dero-miner (2026-10-22)

**30.1 Source and licence.** Third-party MIT code (see THIRD_PARTY_NOTICES.md). It was read only, never built or run.
The pure-Go sort was ported verbatim to `cmd/dero-miner/dsa/dsa.go` with its licence header. The only edits are two
range-over-int loops rewritten for the go 1.17 module. Safety audit: no dev fee, no hard-coded addresses, no exec, no
update channel. Not ported: CUDA/HIP GPU (no macOS path), native C/NEON descriptor, and paired SHA asm (low value).

**30.2 Why it is not consensus-visible.** A suffix array is unique, so any correct sorter gives the identical hash.
`astrobwtv3.SuffixSort` is a nil hook (`gpu_bridge.go`); `pow.go` falls back to the built-in `text_32_0alloc` whenever
the hook is nil or declines. The consensus guard has a new `assigned` check: a non-test assignment of `SuffixSort`
anywhere outside `cmd/dero-miner/` is a violation. derod therefore verifies every PoW with the reference SA-IS
exactly as before. `RecoveredPanics` counts the existing recover in `AstroBWTv3`.

**30.3 Three guards in the miner (`cmd/dero-miner/fastsort.go`).**
1. Startup self-test: 51 inputs. Every suffix array must pass `dsa.Verify`, every hash must equal the reference, and
   no recovered panic is allowed. Otherwise the hook is never installed.
2. Sampled check: every 256th suffix array is checked with `dsa.Verify` (all entries in range and adjacent suffixes
   strictly increasing). A failure disables the fast path; that hash itself falls back, so it is still correct.
3. Any new `RecoveredPanics` disables the fast path (10 s watcher).

`dsa.Verify` dropped its duplicate bitmap: strict order makes the n entries distinct, so the bitmap could never
decide the result. Its go mutation was MISSED, which proved this.

**30.4 Engine fixes.**
- GPU wins are re-hashed on the CPU before submit (`gpu_cpu_mismatch` counter).
- getwork dials into a local, swaps it into `connection` under `connection_mutex`, and closes a dead socket. It used
  to leak one fd per reconnect.
- `job_counter` is incremented and read atomically.
- `--cpu-qos` (darwin, opt-in: 0 default / 1 user-initiated / 2 user-interactive) is left at 0 because derod shares
  the machine.
- `--bench` varies its input per hash and honours `--sort` and `--mining-threads`.

**30.5 Measured.** Same binary, interleaved, live contention. At 2 threads: SA-IS 565/590/588 H/s, descriptor
2324/2306/2717 H/s, median ×3.95 (pipeline S4b). At 1 thread: about ×4.1. The hash-equivalence test is 652/652
identical, with 0 declines. This **refutes the "M1 hardware ceiling" (§13–14)**. The ceiling was a ceiling of SA-IS,
not of the hardware: the descriptor sort exploits stage-1's ~270 near-copy 256-byte runs, which a generic SA-IS
cannot.

## 31. ★★ Round 15: the r14 live run, honest numbers, and the next miner levers (2026-10-22)

**31.1 Live r14 run (21:23–22:26, about 63 min).**
- TOTAL hashrate: about 27.5 KH/s, of which the GPU is about 1.24 KH/s. Before r14 it was about 7.9 KH/s, so ×3.5.
- `gpu_cpu_mismatch` 0, `fallbacks` 0; sampled `dsa.Verify` passed every time (374k verified).
- Shares: 6/6 paid at 21:48, and 22 found by 22:26 (21 CPU, 1 GPU). 0 rejected.
- Expected finds in the first ~29 min were 10.2 (9.2 normal + 1.1 final); 6 were observed, P(X≤6)=0.115, which is
  ordinary variance.

**31.2 Network hashrate, derived from consensus code.**
- A block has 10 miniblocks (`miniblocks_consensus.go:80`).
- Nine are normal at difficulty D. The final one is HighDiff at 9·D (`config.MINIBLOCK_HIGHDIFF=9`,
  `websocket_getwork_server.go:156-160`, `VerifyMiniblockPoW`).
- That is 18·D hashes per 18 s block, so **NW ≈ D H/s**. derod's "NW" (`Get_Network_HashRate` = difficulty) is
  right.
- The old ×10/BLOCK_TIME formula (memories, `reward_audit.py`, `mining_dashboard.sh`) understated our share by
  about 1.8×. All three are corrected.
- At D ≈ 3.1 M, 27.5 KH/s is about a 1.1% share, about 13–18 DERO/day. DERO/day = H·86400·0.3075/(18·D).

**31.3 Operator-number fixes (no consensus change).**
- Miner:
  - `est_earned` now counts final miniblocks; they are one of the 10 equal shares, paid to derod's
    `--integrator-address`. A new `est_finals_DERO` field shows them separately.
  - Accepted counters fold across websocket reconnects (`session_counter`); derod restarts them per session.
  - "NW" divides a HighDiff job's 9·D back to D (`nw_from_job`, blob byte 0 bit 4).
  - `MINING @` uses a 15 s window read atomically. The ~1 s window was aliased by the 4096-hash GPU batches.
- derod:
  - `hashrate_1hr/1d/7d` count finals and clip the window to the uptime.
  - `GetBlockTemplate` returns 9·D for a final template, as the getwork server already did.
  - "Block Minted" and `Mining_Velocity` no longer subtract rejected from accepted; the two counts are disjoint.

**31.4 p2p.**
- A v2-remnant peer was re-dialled and re-banned 23 times at a flat 1 h. The ban now escalates 1 h → 24 h
  (`v2_ban_seconds`).
- `feed_chunk` skips PoW verification of a chunked block whose tip is unknown (`unknown_tip`). Before, it panicked in
  `Get_Difficulty_At_Tips` ("could not find height for blid") and the handler's recover dropped the chunk. Seen 3×
  on a shadow one block behind. Same behaviour, minus the panic.

**31.5 Miner throughput.**
- In the profile after r14, SHA-256 of the SA is 32% of a hash and the descriptor sort 57%.
- dsa scatter, merge and gather loops are resliced to drop bounds checks: about −4% time per hash, interleaved A/B.
- `FAST_SORT_CHECK_EVERY` is now 1024: Verify costs about 1.6× a sort, so 1/256 cost 0.52% of hashrate.
- PGO for dero-miner only (`cmd/dero-miner/default.pgo`, a profile of the descriptor hash): median about −4.5% time
  per hash, mean −2%, noisy.
- Pipeline S4b now also benches the staged miner against the installed one and fails on a regression beyond 7%.

**31.6 Deferred, with reasons.**
- Paired SHA-256: +5.9% measured single-thread, but a verifier bounded it at −10%…+8%. It needs a miner-side
  generated copy of stage 1. If done, take the asm from GOROOT under BSD-3
- Native C descriptor via cgo: needs explicit approval to compile untrusted C. The only published ratio (1.46–1.59×)
  is amd64 with a different SHA pipeline.
- Descriptor sort on Metal: multi-week effort, and the gain is unmeasured.
- `--cpu-max=100`: at most +11%; the operator decides, because the machine is shared.

**31.7 Licence note.** The licence terms are recorded in the `dsa.go` header and THIRD_PARTY_NOTICES.md.

## 32. ★★ Round 16: native C descriptor, paired SHA-256, and the "regression" that was a display (2026-10-23)

**32.1 The 31.091 → 27.907 KH/s claim was a display artefact.**
- r14's `MINING @` used a ~1 s window (`52c02df:miner.go:319-321` plus a 1 s sleep). The GPU adds 4,096 to the
  counter in one step, once per ~3.3 s batch. About 30% of 1 s windows therefore read CPU + 4.1k.
- A Monte Carlo of that prompt with CPU at 27.0k gives a maximum of exactly 31,091.
- TOTAL (a 15 s window, byte-identical code in r14 and r15): r15 mean 28.5–28.9k vs r14 27.6k.
- Interleaved bench, r15/r14 paired median: 1.037 (30 pairs). No regression.

**32.2 Native C descriptor (`cmd/dero-miner/dsac`).**
- `descriptor.c` (third-party, MIT): security-audited as pure computation (`nm -u`
  shows libc memory and string symbols only; no I/O, network, process or env access).
- Built through cgo with -O3 -mcpu=apple-m1 for darwin/arm64 only. Five bounds guards were added. Any non-zero rc
  declines, so C → Go dsa → SA-IS.
- Bit-exact with Go dsa on 652/652 texts and hashes. ASan, UBSan and race runs are clean.
- `--sort=auto|native|go|descriptor|sais`; auto chooses C where it is built.

**32.3 Paired SHA-256 (`cmd/dero-miner/astropair`).**
- Each CPU thread hashes two nonces per iteration so the two final SHA-256 passes interleave on the SHA unit.
- Stage 1 is a generated copy of pow.go's; `TestStageIsCurrent` fails if pow.go changes.
- The SHA block function is GOROOT's BSD-3 asm, with LICENSE-GO; `TestAsmIsCurrent` checks it is current.
- `astrobwt/` is untouched, and the consensus guard passes.
- Same guards as the sort: a startup self-test against `astrobwtv3.AstroBWTv3`, and both lanes sort through
  `verified_sort`. A panic in a lane yields no hash: both nonces are re-hashed singly and pairing is disabled.
  `--pair=auto|off`.

**32.4 Measured (2 threads, 8 interleaved rounds, contended).** Paired ratio vs r15:
- C sort + pairing: **1.349**
- C sort only: 1.217
- Go sort only: 1.029 (control; equivalent to r15)

Pairing gains more on top of C (+11%) than the Round 15 estimate, because the faster sort made SHA a larger share of
each hash.

**32.5 GPU orphan forensics.**
- The first orphan (height 7798792) was a GPU share. Its job was read just before the 9th normal miniblock arrived,
  and it was submitted about 3 s later. CPU shares are effectively never stale: the job is checked every hash and
  derod pushes a new job within ~10 ms.
- Modelled GPU paid efficiency is ~0.69. The earlier 0.80 used the wrong window.
- Smaller batches do not help: a dispatch costs ~2.7–3.7 s at any size, because one GPU thread computes one whole
  hash.
- The miner now flags GPU wins whose job was superseded (`shareLikelyStale`, accounting only), and still submits
  them.

**32.6 Fixes.**
- A `--bench` run now logs to `<exe>.bench.log`. `os.Create` on the shared `<exe>.log` had truncated the live
  miner's log, leaving NUL holes. S4b now benches a copy of the installed binary.
- `p2p_chunks_unknown_tip_total` makes the r15 guard observable in GetSyncInfo.
- G16 had a false alarm: one localdiff citation per file missed changed functions, so citations are now per hunk.

**32.6b A real dsa bug found by the pipeline.**
- What failed: under `-race`, `sync.Pool` drops objects, so `SuffixArray` sometimes ran on a freshly sized scratch
  (n/2+264 descriptors). The C-vs-Go synthetic test then panicked with "index out of range [764] with length 764"
  (n=1000, 2 of 6 runs).
- Cause: `emitRun` checks descriptor room per block, but the tail walk adds up to 255 more descriptors without a
  check.
- Mining never hit it (0 recovered panics in over 400k verified sorts), because the pool returned the larger
  scratch of an earlier ~70 KB hash. Had it fired, the recover would have discarded one hash and switched the miner
  to SA-IS for the rest of the run.
- Fix: grow and retry when the tail does not fit. Regression test `TestFreshScratchTail` resets the pool; its
  mutation `gm-dsa-tail-room` is caught.

**32.7 Open findings.**
- The v2-ban escalation counter lives in memory and resets on restart.
- GetInfo `white/grey_peerlist_size` is never assigned (always 0).
- `hashrate_1hr` is ±38% at n=7 finds.
- **Next lever:** a GPU/CPU split, with the GPU doing stage 1 and the final SHA and the CPU only sorting. Both
  kernels are bit-exact in a scratch proxy. The ceiling estimate is +24–37% total, and the verifier called that
  magnitude overstated. It needs an end-to-end measurement.

## 33. ★★ Round 17: how a share gets paid, and the submission path (2026-10-23)

**33.1 What decides payment.** Two workflows (10 + 8 agents, all adversarially verified) followed 23 r16 shares from
find to block.
- Our own path is not the bottleneck. Find → submit takes about 55 µs. derod accepts, inserts and launches the relay
  synchronously in under 1 ms, then sends to every peer in parallel goroutines.
- Every orphan (3 so far, all CPU normal shares) lost the race for the 9th normal slot at the final-miniblock finder's
  node, by 0.13–0.74 s. None had stale tips or wrong work.
- The builder takes the first 9 normal miniblocks in ARRIVAL order (`miner_block.go:336-340`,
  `miniblockdag.go:98`), so the race is decided by how many p2p hops separate us from the builder.
- Builders are concentrated: the top 4 integrators built 75% of 190 blocks, and the top 10 built 92% over 15.5 h.
- The Round 16 claim "CPU shares are effectively never stale" is refuted as an orphan predictor. CPU shares are fresh
  but can still lose the 9th-slot race.

**33.2 derod template-cache bug (fixed).**
- `Create_new_block_template_mining` serves a cached template for 100 ms (`miner_block.go:397`). When the 9th normal
  miniblock arrives inside that window, the job push resends the 8-miniblock template, and the final-miniblock job
  arrived only on the 500 ms timer. This hit 17% of blocks and cost 86 ms of dead normal-work per block on average.
- Fix (`cmd/derod/rpc`, not consensus): `refresh_due` schedules a resend once the cache has expired. Shadow A/B:
  82.5 → 17.7 ms per block, with 0 timer-delivered flips.

**33.3 Submission and propagation (p2p, not consensus).**
- Each RPC message is coalesced into one write, so a miniblock is one KCP packet instead of four. The bytes are
  identical. Modelled retransmissions fall from 18.6% to 5.4% of sends.
- Per-peer send→ack histograms are split into own and relayed miniblocks. There is a millisecond `submitted_unix_ms`.
- First-relay scoring: dial selection prefers peers that deliver miniblocks first.
- Proven (whitelisted) peers are retained for 24 h; upstream `get_peer_list` deleted every one that was not connected
  at that instant.
- `inbound` reachability counts only public IPs. The local shadow nodes had made it report "reachable".
- v2-ban offences persist across restarts. GetInfo `white/grey_peerlist_size` are now assigned.
- GetMiningOutcome now reports `slots_full` as an orphan reason.

**33.4 Miner.**
- On darwin with no QoS, mining goroutines are no longer `LockOSThread`ed. A locked goroutine paid two thread
  handoffs at every 10 ms preemption and at every cgo return when all Ps were busy. Measured ×1.16–1.23 per thread
  at 2 threads.
- Paid vs accepted: the miner polls derod's `DERO.GetMiningOutcome` read-only. It uses `--node-rpc-address`, which
  defaults to the loopback daemon's RPC port. It matches fates to the hashes it submitted, so the CPU/GPU split of
  orphans is exact.
- New stats: `expected_DERO_per_day` = H·86400·R/(18·D), and a luck ratio.

**33.5 Refuted this round.**
- Pairing as an orphan cause: it adds about 0.3 ms of job-check lag against margins of hundreds of ms.
- Refreshing the PGO profile: no gain.
- C flags -O2/-flto: about +4%, not significant.
- Re-sending our miniblock, or latency-ordered send order: no effect.
- Skipping late shares, or reordering our own template: both lose reward or are forbidden in consensus code.
- `--min-peers` is not a lever: only about 22 public nodes exist to dial.

**33.6 Deferred: the GPU split.** The GPU does stage 1 and the paired SHA, and the CPU only sorts.
- Bit-exact on 9,216 checks per arm. Measured ×1.35–1.45 per fed CPU thread (contended).
- The ~70 KB stage-1 text transfer over the stdin pipe loses (×0.80–0.95). It needs shared memory and 2-deep
  in-flight command buffers.
- Projected +8–15% total, unverified.

**33.7 Operator lever.** Forward **UDP** 11011 (not TCP) on the router to this Mac. It is the only way NAT'd builders
can connect to us directly. The gain is unknown until measured; the new first-arrival histograms will show it.

## 34. ★★ Round 18: the hashrate ceiling, GPU split, faster sync, peer-layer security, Go modernisation (2026-10-24)

**34.1 Hashrate ceiling (measured, verified).**
- At 20 threads the live miner does about 2.33k hashes per CPU-second. One bench thread does about 2.36k. Changing
  GOMAXPROCS (10/14/20) moves this by less than ±2%. There is no memory-bandwidth or L2 penalty: each P cluster's
  12 MB L2 holds 4 × ~1 MB pair scratch.
- Live throughput is simply the number of cores the miner gets × ~2.33k H/cpu-s. With nothing else running the box
  tops out at 16 P × 2.36k + 4 E × 1.04k + GPU 1.24k ≈ 43k H/s, about ×1.10 over ~39.5k.
- **Doubling the hashrate is not reachable in software on this M1 Ultra.** The levers are per-hash work (the sort is
  ~67%, the SHA ~24%) and the GPU split.
- The r17 "×1.59" was an artefact of S4b's 3-sample, 2-thread wall-time bench. The CPU-efficiency gain was about
  ×1.03–1.04. S4b now also reports `staged_h_per_cpu_s` (getrusage), which contention cannot fake.
- `--cpu-qos=interactive` costs about 5%. E-cores hash at 0.44× a P-core but still add about 11% of the total, so keep
  20 threads and do not pin.

**34.2 GPU split mode (`--gpu-mode=split`, opt-in).**
- The GPU computes stage 1 and the final SHA-256 into shared memory (`gsplit/`, `gpu-miner-poc/gpu_split_server.swift`;
  build it with `xcrun swiftc -O`). CPU threads only sort staged texts.
- Every win is re-hashed by AstroBWTv3 on the CPU before it is submitted. There is a bit-exact self-test at startup
  and on every respawn.
- A verifier measured split/full at ×1.22–1.34 at T=20 on a contended harness. That is not a live number.
- It uses about 5.9 GB of shared memory with the default geometry (4096 × 4 × 2).

**34.3 GPU worker auto-respawn (live incident).**
- At 07:40:25 the live full-hash `gpu_hash_sais` server exited with `EOF`. A Round 18 agent's long Metal
  command-buffer benchmark had tripped the macOS GPU watchdog.
- `gpu_worker.go` used to stop GPU mining for good after one failed batch.
- Now a supervisor kills and reaps the server, backs off 1 s doubling to a 60 s cap (reset after 5 min healthy),
  relaunches it, and re-runs the bit-exact self-test. Only a self-test MISMATCH disables the GPU.
- Split mode does the same (`engine.go respawn`). The stats lines show `restarts`.
- Rule: no Metal benchmarks on the live box while the miner's GPU is running.

**34.4 Sync and network (p2p/ only, no fork).**
- Fetching one block per `GetObject` round trip was the sync limit. Batched, pipelined fetch (`sync_pipeline.go`)
  gives ×9.2 on an emulated 170 ms RTT link (4.5 → 41.8 blocks/s, treehash matched 31/31).
- It falls back to batch=1/depth=1 after any block over 64 KiB or any failed fetch, so the 30 s call deadline can never
  penalise honest peers on large blocks.
- PoW prewarm runs only for blocks with exactly the consensus miniblock count (10), on a NumCPU/4 worker pool. The
  unbounded version let one peer cost 2 GB and 4.4 s of CPU with a 16,383-miniblock block. Measured ×1.86 on loopback.
- The KCP window went from 32 to 256 segments: about ×10 per-peer bulk throughput at 170 ms, and safe with old peers.
  ACK batching is an opt-in knob.
- TPS: the consensus cap is ~142–348 TPS by size, and actual use is 0.0001 TPS. There is nothing node-side to speed up.

**34.5 Security (no fork).**
- **Wallet RPC:** with no `--rpc-login`, any web page could drive it (cross-site WebSocket hijacking or DNS
  rebinding). There is now an origin/Host guard, and `/install_sc` is limited by MaxBytesReader.
- **Outbound diversity:** at most 2 outbound connections per IPv4 /16 or IPv6 /32. The connection's own pending dial is
  excluded (a verifier caught a cap-of-1 bug). A refused peer gets a 2 min back-off.
- **Gossip validation:** only literal public IP:port is accepted, with at most 8 grey entries per /16. The KCP
  back-off was dead code; it is revived, capped at 512 s.
- **NotifyINV:** bounded and scored. Transactions that fail verification are scored `invalid_tx`.
- **derod HTTP:** bind policy, pprof policy, and 32 MiB websocket/body limits.
- **`DERO.GetSupplyAudit`:** the first independent supply number (SC-held plaintext balances).
- The range-proof soundness defect still has no node-local fix.

**34.6 Go modernisation (Round 18b).**
- CBOR `append_frame` is zero-alloc (49.4 → 6.9 µs per block frame).
- getwork `SendJob` builds the shared fields once per job (JSON stays byte-identical).
- 17 `Connection` fields became typed atomics, fixing 9 races. A `time.Tick` leak was fixed.
- The consensus guard now covers vendor `*.s`, `modules.txt`, `go.work` and renames. websocket read limits were added.
  A wasm build fix landed (metrics). The derod exit double-close is now a `sync.Once`.
- **Report-only:**
  - A `go 1.22` bump needs `godebug default=go1.17`. go ≥ 1.24 randseednop breaks the reproducibility of astrobwtv3
    `random_code_gen.go` (latent PoW-fork hazard), so never bump past 1.23 without fixing that generator.
  - x/crypto SHA3 in the consensus vendor tree.
  - PGO and GC tuning for derod: no gain.

## 35. ★★ Round 19: NEON sort, split-engine robustness, and a platform round (sync, RPC, security, wallet, ops) (2026-10-26)

**35.1 Hashrate (miner only).**
- Live r18 split mode measured about 285 µs of CPU per staged text (3,460–3,520 H/cpu-s). Staged ≈ 51–54k is close
  to the GPU stage-1+SHA capacity (R18 probe: 50.4k at 4096/4/2), so the GPU is nearly binding. `dropped_stale` is
  0.8–0.9% of staged and costs no CPU.
- NEON ports of descriptor.c's AVX2-only fast paths (column mask, uniform-span emitter, constant-column slide,
  singleton scatter) cut the sort from 253 to 175 µs per text, bit-exact on 2,048 fresh hashes.
- Pipeline S4b, now gated on H/cpu-s:
  - Full CPU hash: ×1.60 vs r18.
  - Split CPU side: about 5,030 H/cpu-s.
  - The freed cores go to the miner's own CPU hashes; the live total is still to be measured.
- A hybrid GPU-side sort is NOT shipped. At 989 SA/s while sharing the GPU, the zero-cost upper bound is about +1.2%.
- New regime counters: `cpu_idle_tries` (GPU-bound) and `feeder_ring_full_ms`. Round 20 correction: with GPU SHA a
  batch is freed only after op 2, so `feeder_ring_full_ms` also counts time when every batch is on the GPU; it is
  not a CPU-bound signal by itself. `feeder_cpu_backlog_ms` (r20) is the part of that wait during which staged texts
  were waiting for the CPU threads, and that part is CPU-bound.

**35.2 Split-engine audit incident (live, 2026-10-26 18:23:41).**
- The r18 miner disabled split mode for good after 1 audit difference in 15,830 audits. The likely cause is the
  stale-`e.cur` re-staging race, now fixed by `prepare`/`makeReady`.
- r19 policy: an audit difference kills the live server through `e.live`, and the respawn re-runs the bit-exact
  SelfTest. Each server generation takes at most one strike. 3 strikes within 1 h, or a SelfTest mismatch, disable
  the engine.
- Winning shares were always re-hashed on the CPU before submission, so no wrong share could be sent.

**35.3 Sync / network (p2p only).**
- Fastsync TreeSection fetch is pipelined (default depth 4, max 6). Measured interleaved: 1.8–2.2× on loopback.
  - After any error it falls back to depth 1 until 256 sections in a row succeed.
  - Each request's timeout scales with the requests queued ahead of it.
  - It stops issuing while more than 64 MiB of answers are buffered.
  - One heavy slot stays free for INV-triggered GetObject.
- Back-to-back sync rounds, with at least 64 blocks per round and at most 16 rounds in a row.
- Seed back-off; the never-ban list is no longer reported as banned.
- Duplicate concurrent tx admissions collapse into one, keyed by Keccak of the exact bytes. Local and relayed txs are
  re-announced at most 4 times, with jitter.
- IPv6 KCP MTU is clamped to a 1232-byte payload. Opt-in `--p2p-nat` (PCP / NAT-PMP / UPnP; this router answers
  none) and DSCP marking.

**35.4 Security.**
- UDP reflection: inbound handshakes run on the default KCP profile with a 6 s deadline.
- Bans are checked before the accept token is taken. IPv6 bans and scores apply to the /64.
- The NTP offset uses a median with outlier rejection.
- dero-wallet-cli redacts secrets in its log (file mode 0600). XSWD listens on loopback by default
  (`--xswd-allow-remote` widens it).
- Console files are written 0600 without following symlinks.
- Decoder panics are penalised. `DERO.GetSupplyAudit` is single-flight, cached per (topoheight, block id) and
  cancellable.
- RPC: server timeouts (slowloris), per-IP limits for remote clients only, bounded metric series, and slow websocket
  clients are skipped (busy flags) with a write timeout.

**35.5 RPC / features / ops.**
- New calls: `DERO.Subscribe` (BlockInfo), `/health`, `GetBlockHeadersRange`, `GetMiniBlocks`,
  `GetDifficultyHistory`, `GetTxPoolDetail`, `GetPeerInfo` (loopback only), and a GetSyncInfo chain fingerprint plus
  NAT status. RPC_METHODS.md documents them.
- Prometheus `/metrics` and `/dashboard` for derod (loopback) and dero-miner (`--metrics-bind`).
- Both exit cleanly on SIGTERM, and the miner's exit is a `sync.Once`.
- Explorer hardening; a registration-point cache for GetEncryptedBalance.
- Wallet:
  - History sync is 7.6–8.7× faster.
  - Saves are atomic (temp + fsync + rename, 0600, .bak).
  - `--password` is now honoured on restore.
  - `sync_loop` exits on Close.
  - GetTransfers filters work, and GetTransfersPaged is new.
  - Decoy balances are fetched in overlapping RPCs.

**35.6 Measured limits (report-only).**
- Transaction admission is about 95% proof verification. Reaching the consensus cap needs about 14 cores at
  ring 2–16 and about 42 at ring 128. Faster scalar multiplication would be in cryptography/, a consensus package.
- Protocol limit: one tx per account per block.
- No global-mutex hotspot was found in derod or the miner.

## 36. ★★ Round 20 merge: uptime forensics, GPU kernels, and platform fixes (+22102026.r20, 2026-10-28)

**36.1 The share gap was downtime.** derod's ledger is a 4096-entry ring (mining_outcome.go FATE_RING), not a window:
40 shares in 26.7 h meant the r19 miner was connected for roughly 35-40 minutes of that run
(getwork_jobs_sent_total arithmetic; getwork_job_write_errors_total stayed 0, so it was disconnected, not stalled).
Keeping the miner running is worth far more than any hashing change this round. New visibility: derod logs
"first miner connected" / "last miner disconnected" (rate-limited to 1 INFO line per kind per 60 s, the rest at
V(1), because the default getwork bind is public), `getwork_connects_total`, `getwork_disconnects_total`,
`getwork_last_share_timestamp_seconds`; the miner logs why each run ended and appends fatal traces to `<log>.crash`.

**36.2 One miner log implementation.** Four dimensions proposed one each; cmd/dero-miner/minerlog.go ships:
append (never truncate), size rotation at 32 MiB into `<log>.1 .. <log>.3`, mode 0600, and a reopen retry after a
failed rotation. A `--bench` run only touches `<exe>.bench.log`. SIGHUP is an exit signal only when it was not
ignored at start, so `nohup dero-miner ... &` keeps surviving a terminal close.

**36.3 GPU kernels (gpu-miner-poc/gpu_split_server.swift).** SHA rounds unrolled (x1.8-2.0 SHA throughput) and
8-wide stage-1 threadgroups (x1.8 stage-1 proxy), bit-exact. The overlapped proxy is x1.50-1.74; the live staged
gain is NOT measured and may be small, because the feeder is often waiting on the CPU (feeder_cpu_backlog_ms tells).
INSTALL: the tracked binary gpu-miner-poc/gpu_split_server is still the r19 build (a text patch cannot carry it).
Rebuild it (`xcrun swiftc -O gpu_split_server.swift -o gpu_split_server.new && mv gpu_split_server.new
gpu_split_server`, so the running server keeps its inode) and check that the server banner says `kernels=r20`
before any GSPLIT_REAL=1 test. 150k H/s is not reachable on this box: 150k x ~200 us/hash = 30 cores > 20.

**36.4 Platform.** p2p: per-peer tx-ask hold (23 failed fetches -> 10 asks in the live replay), compact block
reconstruction from local pools (no protocol change), peer byte counters actually counted (one `counted_codec`
for both directions), `DERO_SYNC_PREWARM_WORKERS` (default unchanged; +3.1% at 10 workers is within noise),
TLS 1.2 floor, inbound per-netgroup cap max(4, max-peers/10) (x2 for IPv6 /32; `DERO_P2P_INBOUND_PER_NETGROUP`
overrides) and per-netgroup accept bucket. RPC: Host/Origin guard on loopback binds (`DERO_RPC_ALLOWED_HOSTS`,
`DERO_RPC_ALLOWED_ORIGINS`; all cross-site websockets share one 64-socket budget), DERO.GetTxStatus. Wallet:
parallel history discovery + prefetch (x2.3-5.9 measured; a batched GetTransaction entry that is empty or in the
pool is never served), bounded daemon calls, ring-decoy stall bound, HTTP timeouts. Ops: derod
`--log-max-size/--log-max-backups/--log-max-age/--log-compress` (defaults = upstream), darwin process_* metrics,
free_disk_space_bytes of the datadir, durable p2p JSON saves. Harness: S3a fails closed on any failing or racy new
test, go_mutate records package-level failures and timeouts, DK18 checks HTML-stripped text for seeds.

## 37. ★★ Round 21: the CPU-sort-bound split miner, a co-binding GPU, and a platform round (+22102026.r21, 2026-10-28)

Evidence: RUN_REPORT.md `## Round 21` (line 896); pipeline record `harness/loop/runs/pipeline_20261028T185146.jsonl`
(PASS, gates 18/18); the live r21 runs in `bin/dero-miner.log` from line 5496 (20:20:38) and 5545 (06:25:17).

**37.1 The bottleneck moved to the CPU sort, and the GPU is close behind.** The r20 run logged
`feeder_cpu_backlog_ms` ~39–44 s per 60 s window with `cpu_finished` 0, so staged texts waited on the CPU sort most of
the time. The r21 run adds the GPU's wall-clock duty (`gpu_busy_pct` in the 'GPU split' line,
cmd/dero-miner/gpu_split.go:315-328; `dero_miner_split_gpu_busy_seconds_total`, cmd/dero-miner/metrics.go:171).
At uptime 710 s (06:37) the GPU was busy 671.8 s (0.946) **and** the CPU-sort backlog was 526.3 s (0.74). Both resources
are near their ceiling (co-bound). The r21 regime classifier read only the backlog and the idle tries, so it called
this "cpu-sort-bound". Co-bound is an intermittent, load-dependent state, not a fixed regime: whole-run counters at
uptime 6,576 s (busy 5,431.7 s = 0.826, backlog 0.779) classify as cpu-sort-bound, while a 40 s window gave busy 0.923
(co-bound). The label flips around the 0.90 GPU threshold with box load, so r21's label was right for most of that run.
Round 22 adds the binding classifier (§38.1).

**37.2 Ceiling arithmetic (measured inputs; the results are estimates).** Split CPU side: 5,792 H/cpu-s. Full CPU pair
hash: 3,205 H/cpu-s (S4b, pipeline_20261028T185146). GPU-only ceiling: staged / busy ≈ 78.5k / 0.946 ≈ 83k at 06:37
(staged, not TOTAL: ~4.6k of TOTAL are CPU-own hashes that never touch the GPU, and the counter includes ~1.1% stale
drops), and 87.6k from the quiet 20:20 run (log windows). CPU budget at `--cpu-max=90`: 18 cores, so 18 × 5,792 = 104k if every
core only finished split work. The GPU caps first, at about 84–89k staged. Spare CPU then hashes on its own at
3,205 H/cpu-s, so the box tops out near 95–100k. Reaching 150k would need ~1.7× the GPU, or 150k / 5,792 = 25.9 cores
of split finishing against 20. It is not reachable on this machine in software.

**37.3 What shipped** (101 files; consensus guard PASS, only config/version.go changed):
- Split stale-drop on the normal→final flip.
- cgo yield every 8 sorts.
- `--gpu-max` charged on the busy union.
- Opt-in GPU sort (op 3), measured as a net live loss of ~9%.
- The getwork blob-length remote crash fix (SEC21-01).
- The run ledger `bin/dero-miner.runs.jsonl` (cmd/dero-miner/runledger.go).
- GPU binary stamps (gpu-miner-poc/build.sh, BUILD_STAMPS).
- p2p grey-peer quarantine and frame byte budgets.
- Websocket budgets.
- The `--prune-history` preflight.
- Harness: S4b like for like, regime cards, the harness run ledger, gpu_watch.

**37.4 Left open:**
- A live A/B of `--cpu-max=100`. §37.2 bounds its gain by the GPU ceiling: at most ≈ +5k, not +8k.
- `--min-peers=20` against ~15 reachable peers.
- Forwarding UDP 11011: inbound peers have been 0 since Round 2.
- F4 stuck-peer eviction.
- F6 mutex profile.

## 38. ★★ Round 22: the GPU cap, faster kernels, and a platform round (+22102026.r22, 2026-10-29)

**38.1 The binding resource, from the GPU duty as well as the CPU backlog.**
- `miner_intel.classify_binding` (shared with `metrics_intel.split_binding`) labels a split run or sample as one of
  co-bound, gpu-bound, cpu-sort-bound, ring-bound or balanced. It uses GPU busy ≥ 0.90, CPU-sort backlog ≥ 0.50 and
  ring full ≥ 0.50 with neither binding.
- Each label carries the miner's CPU cores against its `--cpu-max` budget, the GPU-only ceiling estimate, and the
  CPU-own hashes per idle try.
- Gate **G19** recomputes the GPU duty from the snapshot's raw counter pair and the label from its fractions. The page
  shows the result as a regime card ('What binds the GPU split right now').
- Measured 06:44–06:56 on 2026-10-29: 24 windows of 30 s gave H/s = 4,817 × cores + 8,000, r = 0.991, while other
  agents loaded the box. 13.0 of the 18 budget cores gave 70.6k. Hence the `cpu_starved` WARN (budget fraction < 0.80
  while CPU-sort-bound).
- Why CPU workers idle-try while the backlog is high: an idle try is a TryWork call that finds no staged batch at that
  instant (cmd/dero-miner/gsplit/engine.go:975), i.e. in the gap between a fully claimed batch and the next one
  becoming ready.
- The backlog is sampled only while the FEEDER waits (engine.go:588-608, every 5 ms), so the two counters measure
  different moments and do not contradict each other.
- Each idle try makes the thread hash one full CPU pair (cmd/dero-miner/miner.go:917-936). Measured: exactly 2.0
  CPU-own hashes per idle try, 1.4–4.0k H/s, 2–5% of all hashes, at 1.81× the CPU cost per hash of finishing split
  work.

**38.2 The miner's own run ledger, validated and joined.**
- `harness/intel/miner_runs.py` checks every `bin/dero-miner.runs.jsonl` line against what its writer promises and
  against the miner log (L1–L8). The 20:20 r21 run passes all eight.
- It joins each run with derod's fates (GetMiningOutcome `recent`). That list holds only the newest 50
  (cmd/derod/rpc/mining_outcome.go:232) and is lost when derod restarts, so the join flags `covered` and `partial`.
- It also joins each run with the chain: the main-chain blocks at the found heights, our regular-miniblock KeyHash,
  and the miner_address of a block we built for finals. Nothing identifying is ever written.
- The exit record of the 20:20 run froze its fates as 0 paid / 1 orphaned / 2 unresolved (node_paid_fraction 0). The
  chain says 2 of 3 were paid: 7824998 regular, and 7825002 a final whose block we built.
- On the live run the chain join matches derod exactly: 22 paid of 24 found.

**38.3 Pipeline: steps that could hide a failure.**
- go_mutate counted a mutation that does not compile as CAUGHT. It is now INVALID. A read-only `go vet` sweep of all 492
  Go mutations found 22 that did not compile (16 'declared and not used', 5 unused imports, 1 duplicate field). r21's
  '510/510 caught' therefore included 22 whose test never ran. All 22 specs now compile and are CAUGHT by their tests.
  One of them was a real blind spot: TestRunRecordFrom set the wallet address only AFTER building the record, so a
  record leaking the address could never fail it. The test now sets it first.
- A SIGKILL mid-mutation left the source mutated. A journal now restores it, and S1 refuses to run while a journal
  exists.
- S2 ignored gofmt's exit code and stderr.
- S3k passed with zero KAT files.
- Intel snapshots and PIPELINE_LAST.json are now written atomically, so a torn newest snapshot can no longer crash
  run_gates.
- S4c: the GPU side is benched like for like whenever gpu_split_server.swift no longer matches its BUILD_STAMPS source
  hash.
  The first real run exposed a second blind spot: TestGPUCapacity PASSES at 'median 0 staged H/s' (Restarts:5) when
  loop_ops.metal.inc is not next to the server binary (logs: cap.log is the 7520 H/s run, cap2.log the 0 H/s run).
  S4c copies that file and treats a 0 rate as a failed arm, and since the r22 merge TestGPUCapacity itself fails on a
  median of 0. S4c has not yet run end to end on a changed server; run it once with --gpu-bench before relying on it.
- miner_intel no longer reports a recorded miner stop ('miner exiting', then the next start-up line) as an
  "unexplained" share gap. The r21 20:25→06:25 stop of 10.0 h was one.

**38.4 Storage and operations, measured read-only.**
- derod over 721 s: goroutines 122 (max 157), RSS 196 MB (flat), fds 59–61, 0.075 cores.
- derod.log grows 5.3–6.0 MB/day. It is 41.9 MB of a 100 MB rotation threshold, so it rotates in about 10 days and the
  disk cap is 300 MB.
- topo.map grows 48 bytes per height.
- The bltx_store gains ~4,770 block files a day.
- Graviton balances are 7.80 GB in 4 .dfs files of 2 GiB each. 3.dfs grew 1,278,711 bytes in 1,210 s (62 versions,
  20.6 KB per block, ~91 MB/day). With 2.24 TB free (free_disk_space_bytes), disk is not a constraint for decades.
- blockchain/storefs.go:283/314 writes block and tx files with ioutil.WriteFile, which is not atomic. That is a
  consensus package, so it is reported only.
- dero-miner RSS: +2.6 MB over ~80 min in a later read-only check (6,049,644,544 → 6,052,233,216 B). The growth rate
  fell, so it is not linear growth; sample over 6 h or more before calling it a leak.

**38.5 Round 22 merge (+22102026.r22, 2026-10-29).** One combined patch of nine dimensions; consensus guard PASS.
- **`--gpu-max` is enforced** (forensics FOR22-1, cmd/dero-miner/gsplit/duty.go): r21 ran at 94.6–96.0% GPU duty with
  `--gpu-max=90` because the feeder slept off debt while the ring was full anyway. The cap is now a duty bucket
  (charge busy×100/cap, credit wall time, ≤ 100 ms banked), read at the cap in force (`SetGPUMax`, for the opt-in duty
  tuner), and the feeder's wait is counted (`feeder_throttle_ms`). Install gate: with the live `--gpu-max=90` this
  costs an estimated ~4k H/s (-5% staged); pass `--gpu-max=96` (or 100, or `auto:80`) to keep the r21 rate.
- **Split pipeline** (splitpipe): exact precomputed PoW-target compare (×92 per check, 0 allocs; live gain 0–2%,
  estimate), GPU SHA skipped for batches whose job went stale mid-sort (the re-check is non-counting: `StaleQuiet`, so
  `split_stale_drops` keep one verdict per drop), `collect_ms`, and the opt-in ABBA duty tuner
  `--cpu-max=auto[:floor]` / `--gpu-max=auto[:floor]` (climbs to 100 on a quiet box, giving up the heat cap).
- **GPU kernels r22** (gpukernels): stage-1 ×0.742 GPU time, bit-exact (real-GPU test); at the live geometry
  4096,4,2 the end-to-end gain is ≈ 0 (within noise). It pays only with a geometry change (DERO_GSPLIT=8192,5,3 proxy
  ×1.55–2.1, contended, unverified live): run the ABBA A/B, abort if restarts/retries rise or stale > 3%. Per-kernel
  spans `gpu_s1_ms_per_cb` / `gpu_sha_ms_per_cb` are in the log and /metrics. The binary must be installed with the
  patch (BUILD_STAMPS pins its sha256).
- **CPU sort** (cpusort): phase profile (merge 43%, radix ≤ 30% upper bound incl. a copy, runs+walk 24%); six variants
  refuted; DSA_PROF builds on arm64. E-core/P-core sort speed ≥ 0.38 (background-QoS lower bound). The --cpu-max=100
  simulation (+5.1%, 6 threads, contended, zero-CPU simulated GPU) is not a live result.
- **p2p** (syncp2p, security): stuck-peer eviction (frozen peers: 2 of 15 slots live), `--p2p-nat=probe` (read-only;
  errors are reported as kinds), a known-tx full-set sweep fix (×150–500), a per-peer INV txid bucket (64/s: also a
  ceiling on how fast we learn txs from one peer), short GetObject replies counted as failures, TLS 1.2 AEAD/curve
  floor.
- **RPC** (rpcws): GetTransaction verify-on-hit cache, **off by default** (`--rpc-tx-cache`): hit/miss timing is a
  cross-client oracle on a public RPC. Gain is an upper bound at 100% hits (×5.4–7.2 CPU/call); 0 on the live node.
- **Crypto** (crypto): node-local tx round-trip admission (glue/txcanon: x ≥ P point encodings), canonical keys in
  GetRandomAddress, wallet ring-order uniqueness per payload (two payloads to one destination at ringsize 2 shared r
  with probability 1/2; a third is refused up front with ErrRingOrderExhausted), signature input checks,
  EncryptWithKey no longer seals in place. Payment proofs (C4) and decoder short reads (C7) are documented; their
  fixes are upstream/format changes.
- **Miner hardening** (security): mainnet submit token bucket, LastError log gate, BUILD_STAMPS hex check, prune
  preflight Lstat.
- **Harness**: binding classifier + G19, miner_runs validator/joins, go_mutate INVALID class (22 r21 specs fixed),
  atomic snapshots, S4c, chain_fix for frozen exit fates (the 20:20 r21 row is 2 of 3 paid on the chain, not 0).

**38.6 Closed loop (2026-10-29).** Two pipeline runs.
- Run 1 `pipeline_20261029T094334` FAILED at S3a: walletapi's `Test_R22_MultiPayload_Distinct_Blinders` sits in a
  `//go:build !race` file (the walletapi simulator harness already races on 5385d1d), S3a ran every new test with
  `-race`, the test never compiled, and S3a called it broken. Fix 1fdfa51: `race_split` runs such tests without
  `-race` (KAT IK38, 2 mutations proved).
- Run 2 `pipeline_20261029T094741` PASS: flaky 93 new tests ×3, 0 flaky; Go mutations 605/605 caught; race 22
  packages, 0 races; build r22 (windows/amd64 + js/wasm cross OK); S4b like for like ×0.983 vs installed r21 in
  H/cpu-s (descriptor sort unchanged this round: within noise on a loaded box); S4c SKIP (server source matches its
  stamp); shadow 120/120 blocks, 240 treehashes, 0 mismatches; install with `*.22102026.r21-backup`; KATs 34/34,
  harness KATs R19 10/10, R20 8/8, R21 8/8, R22 10/10 (47/47 mutations); gates **19/19**.
- `gpu-miner-poc/gpu_split_server` installed from the merge build (sha256 78b60598…, `kernels=r22`, real-GPU bit-exact
  on 4,102 hashes); `build.sh --check`: "all stamps match"; previous binary kept as
  `gpu_split_server.22102026.r21-backup`.
- Restart flags: unchanged derod line; miner `--gpu-max=96` (not 90: the cap is now real). `--cpu-max=auto:80
  --gpu-max=auto:80` only on a box with no other CPU load (other sessions' jobs took ~14k H/s at 06:44–06:58).

## 39. ★★ Round 23: the CPU-starved regime, the payout ledger, and a platform round (+22102026.r23, 2026-10-30)

> Written by the harness dimension, completed by the main loop from the merged results and the closed-loop runs.

**39.1 The CPU-starved regime: who else holds the CPU (harness).**
- `harness/intel/contention.py` takes a read-only census of the process table (`ps -A -o pid=,nice=,time=,etime=,comm=`)
  twice, turns each process's CPU-time delta into cores, and groups the cores by executable BASENAME. It keeps no pid,
  no arguments and no path. Classes: miner (dero-miner, gpu_split_server), node (derod), foreign (everything else).
- Verdict: contended when the foreign cores exceed the headroom left by the miner's `--cpu-max` budget and derod, plus
  1 core of slack. The contention law (Round 22 fit, H/s = 4,817 × cores + 8,000, r = 0.991, fit range 13–16 cores)
  turns the cores the miner did not get into an H/s loss ESTIMATE.
- Measured 01:53 on 2026-10-30 (15 s sample): miner 11.32 of 18 budget cores, foreign 6.59 cores (Helper (Renderer)
  ×17 4.73 cores), headroom 1.93, so contended. Law: 62.5k at 11.32 cores against 94.7k at the full budget, a loss
  ESTIMATE of 32k H/s.
- Two instruments for the miner's cores agree: ps CPU-time delta 11.74 cores vs `process_cpu_seconds_total` 11.78. The
  law predicted 64,552 H/s at 11.74 cores; the sampled rate was 63,687 (−1.3%).
- `metrics_intel`: new WARNs `box_contended` and `cpu_starved_unattributed`, and `cpu_starved` now names the processes.
  The `--cpu-max` budget comes from `/metrics` `dero_miner_cpu_duty_percent`. Before R23 it came only from the
  checkpoint file, so from a clone `cpu_starved` could never fire.
- `miner_intel`: on a contended box the current run's sag is `cpu_starved` (attributed to the box), never
  `hashrate_sag`.
- Gate **G20** refuses four things: a snapshot without a census; a contended census the snapshot does not act on; a
  `hashrate_sag` next to a contended census; and a pipeline A/B that PASSED, or FAILED on a ratio, from a contended box.
- Pipeline S4b/S4c take a census before and after each A/B. When the box is contended the ratio is not judged and the
  stage is **REFUSED**; correctness checks still FAIL. `--contended-ok` lets the run go on with REFUSED recorded.
- Closed loop: with the foreign renderers gone (05:38) the r22 miner sampled 92.5k H/s at 17.31/18 cores, law
  91,382 (G20 census quiet). So ~90–100k is the box ceiling; 150k would need ~28.9 cores against 20 (ESTIMATE). The
  remaining levers are uptime and paid fraction, not H/s. feeder_ring_full / feeder_cpu_backlog are saturated
  (0.99 / 0.9) in every regime and are not regime signals.

**39.2 S4c end to end: the GPU self-A/B (harness).**
- `--gpu-bench` on an UNCHANGED server now runs a self-A/B: the staged build of the same source against the installed
  binary. It must be bit-exact, both rates must be > 0, and the ratio must sit inside [0.93, 1/0.93]. So the GPU path
  runs every round, not only when the server changes. `--gpu-bench-only` runs S4c on its own.
- `pipeline_20261030T043422`: S4c SKIP (gpu_split_server.swift sha256 5aff39c8f529 unchanged; the self-A/B runs only
  with `--gpu-bench`/`--gpu-bench-only` under `benchlock.py --gpu`). Not run this round: the live GPU was busy.

**39.3 The payout ledger (harness).**
- `miner_runs.py` §4 compares, per run, the shares the run's hashes should have found (expected_shares = 5/(9 D) per
  hash) with what it found and what was paid. The paid count comes from the chain join when finals can be verified,
  else from derod's fates, else from the frozen exit tally.
- The count is turned into DERO at the per-miniblock reward derived from `CalcBlockReward`. At height 7,830,715 that
  is 123000 >> 2 = 30,750 atomic per block, ÷ 10 miniblocks = 3,075 atomic. Tx fees are excluded, so paid DERO is a
  lower bound.
- Each run gets an exact (Garwood) 95% Poisson interval on its found count, and the ledger is kept long-term in
  `harness/runtime/payout_ledger.jsonl` (chain > derod > ledger: a worse source never replaces a better one).
- Measured 01:51 on 2026-10-30, seven runs (r21 + r22):
  - 506.7 shares expected, 479 found (luck 0.945, interval [437.06, 523.88]: luck), 466 paid.
  - 14.33 DERO paid against 15.58 expected (paid / expected 0.92).
  - Every run's verdict: luck.
- Gate **G21**: every L-check passes, and paid DERO and the verdict recompute from the snapshot's own counts.
- 06:09 (G21): paid 680 of 758.57 expected (20.91 of 23.33 DERO), found 699 in [648.13, 752.8]. The verdict is
  "below expectation beyond luck": the paid/expected shortfall includes the contended hours, so the next step is the
  24 h payout-path counter.

**39.4 A step that hid a failure: the r22 run ledger lost two fields.**
- `cmd/dero-miner/runledger.go` `run_record_from` had `Hashes: m.hashes, Height: m.status.height,` inside the line
  comment that ends the line before. Every r22 ledger row reads `"hashes":0` and `"height":0`, while avg_hs (computed
  from the live counter) is right.
- `miner_runs` L3 caught it on its first run against the r22 rows ("avg_hs 87661 vs hashes/uptime 0", four rows). No
  gate read the minerruns snapshot, and no pipeline ran after the r22 miners started.
- Fix: the fields are restored, and `TestRunRecordFrom` asserts Hashes and Height (Go mutation
  `gm-r23-runledger-hashes-height` CAUGHT).
- In the harness: L3 and L9 treat EXACTLY that r22 signature as KNOWN. G21 now gates the snapshot, and S7 judges
  `miner_runs` by exit code AND a new snapshot.

**39.5 Payout path.** One getwork dispatcher: final share → next-height job 252 → 32 ms (own), 180 → 30 ms (P2P);
first hash after restart 5.5 → 0.5 s; first job 0.84–1.0 s → 6–37 ms. Gain ESTIMATE +0.3–2%.
**39.6 Security.** RPC weighted bucket + scoring + escalating bans (loopback exempt); automated-client bans
(unknown method 20/min, fuzz ~34, hammer ~100; IPv6 /64); getwork cap 32/IP, 8 bad shares ban every session of the
key, one-slot local gate; txprecheck before state reads; full-table scans at most 1/s.
**39.7 Inflation.** Per-block emission auditor (4.9–5.2 ms/block), retries ×3, benign unexplained-SC excused; residual:
value inside encrypted amounts is invisible to any node.
**39.8 Crypto.** CR23-1 burn-aware receiver proof; CR23-2 observe only accepted-block txs; CR23-5 integrated port
size check; documented-only: DVM unmetered hash gas, SC unregistered-dest burn, scalar/ring decoder bounds.
**39.9 RPC/ws, p2p.** Finality RPC, GetFeeEstimate, per-miner job numbering newest-last, walletapi reconnect fixes;
fast stuck-peer re-eviction.

**39.10 Pipeline and gates.** `pipeline_20261030T043422` (mutations 743/743, race 25 pkgs 0 races, S4b ×0.999, shadow
120/120 0 mismatches, install r23) then `--project-only` `pipeline_20261030T062228` PASS: KATs 34/34, gates 21/21.
Two harness fixes on the way: S3 runs race-skipping new tests without -race; mine_localdiff splits every hunk at
`+func` and cites each func's declaration (G16 had lost deserialize_tx).

## 40. ★ Round 23b: the soundness gate, the idle ledger, and the binding label (+22102026.r23b, 2026-10-30)

> Workflow wf_b294469d-fc4 (23 agents, 11 dimensions) merged as 3224c07 (83 files); test-helper fix bfe3e54; closed
> loop `pipeline_20261030T215745` PASS (40.5). Figures marked ESTIMATE are not live measurements.

**40.1 G22: every unit of the soundness page has one registry entry that covers it whole (harness + merge).**
- `harness/soundness.py` cuts `artifacts/dero-soundness-r23.html` into claim units: every `<p>`, `<li>`, heading
  (`h1`-`h4`), table cell, `dd`/`dt`, `figcaption`, `blockquote`, `title`, figure, verdict tile and code-panel line,
  and any text outside those (a bare `<div>`/`<span>`, as `text:<tag>`). Merged page: 86 units.
- `harness/loop/SOUNDNESS_CLAIMS.json` holds exactly one entry per unit. An entry must cover the WHOLE unit (only
  punctuation may be left over), so a sentence appended to a registered paragraph FAILS (the harness-dim draft
  matched a fragment by substring, and an appended "inflation is impossible" passed; the merge closed it). A unit with
  no entry FAILS, and so does an on-page entry that matches no unit.
- G22 therefore proves that every unit is REGISTERED and that every code entry's backings re-check. It does not prove
  that each backing tests every word of its unit: the backing is chosen per entry, and a reviewer still reads it.
- A code entry is backed by named tests, source anchors (re-read, as G2 does), recomputations from the tree (HF3 table
  67 + 8 = 75 at 7,415,466-7,497,942; `MAJOR_HF3_HEIGHT` 7,504,640; the HF3 entry struct's fields, none an amount;
  `cryptography/` gained only 2 test files since bf274e5) or a live read-only RPC check (GetEmissionAudit: OK, 0
  alerts, consistent). The double-spend tile and verdict are backed by the two HF3 replay tests, not by one anchor.
- Pipeline stage **S3s** runs every test the registry names (the simulator ones without -race) and writes
  `harness/loop/SOUNDNESS_LAST.json`. Each PASS is fingerprinted with the test file, the claim's watch files AND all
  non-test sources of the test's own package (so editing `cmd/derod/rpc/emission_audit.go` voids
  `TestEmissionAuditAlertAndError`). `--soundness-only` runs S1 + S3s.
- The gate reports on-page and off-page code claims separately. Off-page entries carry what the HF3 tests prove and
  the page does not state (height-bound proof skip, pinned nonce bypass, Parity override, already-mined guard,
  validity window 11, TXID commits to Height/BLID).
- KAT IK47 now also proves: an appended sentence, stray text in a bare `<div>`, a new heading, and a record without
  the package sources each FAIL G22 (4 more harness mutations, all proved).

**40.2 Idle ledger: the DERO the idle hours forwent (harness).**
- `miner_runs.py` now prices every gap between runs (and an open trailing gap) at the neighbour runs' own expected
  share rate × paid/found × the per-miniblock reward. A miner start-up line inside a gap fails G21.
- Measured 19:2x on 2026-10-30 (ESTIMATE, fees excluded, luck = 1 assumed): since 2026-10-28 20:20, idle 31.4 h of
  47.0 h (uptime 33 %); forgone ≈ 1,647 paid shares ≈ 50.6 DERO, against 22.9 DERO paid. Priced at the realised
  found/expected ratio (776/857.8) it is ≈ 45.6 DERO. Every gap ends in `console exit` (typed).
- OPEN: the 24 h read after the miner runs detached (r23b installed 23:23; the user restarts under launchd).

**40.3 G17 binding vs regime (harness).**
- G17 now surfaces the existing R22 binding label next to the backlog-only regime label and checks the two agree
  with the run's own fractions (classify_binding and the `binding` field date from R22; nothing new binds).
- The backlog-only regime label says `cpu-sort-bound` on every r23 run. The binding classifier says `co-bound` on the
  quiet r23 runs (07:07: GPU busy 0.914, backlog 0.917; 18:03: 0.918 / 0.913) and `cpu-sort-bound` only when the box is
  contended (19:10: GPU 0.867, load 40). G17 now recomputes the binding from the run's own fractions and names a GPU
  duty within 0.05 of 0.90 as marginal.
- OPEN: the `--cpu-max` (CPU-share vs `DERO_CPU_DUTY_CLOCK=wall`), `--phase-duty` and `DERO_GSPLIT=8192,5,3` A/Bs on a
  quiet box (G20 census first).

**40.4 Steps that could hide failures (harness).**
- A project-only run replaced the full pipeline record, so G20 judged no A/B. Full runs now also write
  `PIPELINE_FULL_LAST.json` (backfilled from `pipeline_20261030T043422`), and G20 FAILS with no A/B record.
- S3a passed a test that SKIPPED itself under -race 3/3 without running it; it now re-runs those without -race
  (count=3).
- mine_localdiff cited a repeated added line at its first copy in the file: 39 of 2,924 segment citations landed
  outside their own hunk segment. Now cited near its own line (window 40): 0 of 2,924.
- DK18 passed an UNLABELLED 25-word seed (its pattern needs "seed:" in front): the page quoted 4 runs of the walletapi
  simulator test seeds. DK18 now fails any run of >= 12 mnemonic-list words that is not verbatim in a Release153
  *_test.go (public fixtures are reported). Mutation proved; the old pattern misses it. The --password pattern stays
  fail-closed on prose (9ae3e7d reworded a comment around it).

**40.5 Pipeline and gates (merge).** Soundness-only run `pipeline_20261030T204638`: guard PASS, S3s 29 tests PASS;
G22 PASS (86 units, 32/32 on-page and 6/6 off-page code claims backed). Harness KATs: R19-R23b all green (R23b 5/5,
32/32 mutations); verify_deroarch 34/34 after a page rebuild (31/34 on the committed page, which predates the merged
code: DK08/DK13/DK30 read line numbers and counts the S7 rebuild refreshes). Go mutations: 851 in
harness/intel/go_mutations.json; the 110 new ones and the 218 older ones in touched files all CAUGHT (none INVALID).
Closed loop:
- Run 1 `pipeline_20261030T205204` FAIL at mutate: 853/853 caught, but the restore check and the baseline of
  `./cmd/derod/rpc/` were BROKEN. `TestAbsenceClockFollowsRegisterUnregister` ends with a session registered; its
  `with_clients` cleanup restored `client_list` but not the `getwork_session_count` mirror, so
  `TestR23GetworkFanoutOrderedOverSockets`'s `drain_miners` waited 10 s on a ghost and failed, deterministically (3/3),
  whenever the package's mutation tests ran together; alone it passed 10/10. Test-only; fixed in bfe3e54 (cleanup
  stores the mirror too). The full-package S3 run had passed because of test order.
- Run 2 `pipeline_20261030T215745` PASS: guard PASS (7 files, all logging-only/allowed), flaky 82 new tests ×3 0 flaky,
  S3 PASS, S3s 29 tests PASS, KATs PASS, mutations 853/853 (3 upstream failures recorded, all red on bf274e5), race 26
  packages 0 races, build r23b, S4b ×1.011 like-for-like (descriptor/SA-IS ×4.55 H/cpu-s), S4c SKIP (GPU server
  unchanged, sha256 5aff39c8f529), shadow 120/120 blocks 240 treehashes 0 mismatches 0 regressions, install (backups
  `.22102026.r23-backup`), S7 KATs 34/34, harness mutations 32/32, gates 22/22.

**40.6 Round 23b merged code (+22102026.r23b).**
- derod: emission auditor reorg-aware flows incl. burns, archive/series/issued_emission, whole-file series count;
  GetTxStatus settled-tx cache; Reorg event + finality monitor (a local pop/Rewind_Chain is `local_rewind`, never a
  violation); GetMonetaryIntegrity; getwork miner-absence metric + WARN; random getwork cert serial; rpc.serverInfo
  closed to remote/foreign callers; global anomaly surge budget; SendRawTransaction header peek + admission window +
  HF3-TXID refusal (also on relay); registration canonical-form relay policy; HF3 Parity applied on every block-add
  path; lazy sync height gate; tx_precheck_checked_total (Admit and AdmitAt).
- dero-miner: --cpu-max charged on CPU share; --phase-duty (off; GPU stays at --gpu-max in balanced; the throttle
  wakes only on a final->regular change); --supervised; per-phase metrics. tools/launchd plist generator (Nice 0,
  absolute paths, always --supervised).
- None of it is in a consensus package (guard: only the config/version.go string).

## 41. ★ Round 23c: faster descriptor sort, the split regime law, sync overlap, aggregate DoS scoring, per-account emission audit (+22102026.r23c, 2026-11-01)

> Three workflows (miner wf_2624ea65-0c5: sortfuse, cpupath, handoff, gpuflow; node wf_5c7e92c4-c90: chainperf,
> p2psec, rpcws, cryptoinfl, payouts; artifacts wf_d2cb875d-e03: ledger, srcarch, rft), 12 dimensions, 24 agents;
> every builder was re-checked by an adversarial verifier or reviewer and the verifier-corrected figures are the ones
> below. Merged as 091b35d (69 files); closed loop `pipeline_20261101T120821` + project-only `pipeline_20261101T142234`
> (41.10). State: after implementation, installed, NOT yet measured live. Figures marked ESTIMATE are not live
> measurements; every live item is OPEN until the restart on r23c.

**41.1 Why (the request) and the r23b baseline.** "can we make the CPU sort faster to use more GPU? -> make this
enhancement part of r23 itself"; the R23c run then covered the whole node too. Ceiling evidence before R23c: ~100k H/s
from the per-core sort rate, 150k needs ×1.44 per-core sort (R23b HR23b-6). Live r23b just before install
(bin/dero-miner.log, read-only): quiet window 09:27:14–09:37:45, 43 TOTAL lines, mean 90.5k H/s at 17.53 cores, 5,164
H/cpu-s, GPU busy 93.1–95.3 % of the 96 % cap; contended sample 10:05:12, 57,471 H/s at 10.38 cores, GPU busy 75.8 %,
load 61 (hashrate watcher log).

**41.2 Miner sort (sortfuse, cmd/dero-miner/dsac/descriptor.c).**
- Shipped: `DSA_PAIR` (descriptor.c:2015), the NEON form of the AVX2 two-singleton path: two consecutive singleton
  groups of at most 16 positions are written as two 16-lane windows, the second starting at `out + la` over the first's
  overhang; guarded by `out + la + 16 <= n` and `off + len <= arena_len` for both (the arena has 16 words of slack).
  `DSA_GSCAN` (descriptor.c:1557): a branch-free group split in `emit_run` (every block writes its slot; the index
  advances on a key change). `DSA_NO_PAIR` / `DSA_NO_GSCAN` restore the r22 code.
- Measured (thread CPU per sort, 2,048 fresh stage-1 texts, benchlock, interleaved, order reversed per pair): ×1.047 at
  1 thread (12/12 pairs, 177.38 → 169.22 µs), ×1.037 at 6 threads (6/6). Verifier, one binary with both versions under
  renamed symbols: ×1.0534 (8/8) and ×1.0355 (12/12) at 6 threads, ×1.0370–1.0492 at 1 thread; A/A control 0.996–1.001.
  Go level: SortC child CPU 0.977 (6/6), HashC 0.988 (5/6; builder 0.973). Live: ESTIMATE +1–3 % H/cpu-s when the CPU
  binds, 0–1 % on a quiet box (verifier-corrected; the builder's +3–4 % was too high). OPEN: the live A/B (41.11).
- Bit-exact: 120,000 fresh texts 0 mismatches 0 declined (builder against the Go twin; verifier with an independent
  permutation + strictly-increasing check and the SA-IS hash), 480 + 272 adversarial texts 0 mismatches; 4 + 4
  mutations caught.
- Refuted: fusing radix pass 2 with the singleton write-out (per-bucket length cursor) ×1.137 slower at 1 thread (0/8)
  and ×1.151 at 6 (0/6); the exact-store form ×1.307. It trades the merge's sequential writes for ~19.8k random 64-byte
  read-modify-write windows over a 275 KB sa that does not fit the P-core L1; R22's "below 20 %" bound assumed cheap
  writes. Also refuted: radix 3×8 bits (×1.078 slower), a quad singleton write, a NEON register column step (×1.005),
  a second tie-break word. The R22 "43 % of the walk" came from a CNTVCT timer around ~73 ns calls.

**41.3 The split pipeline regime law (cpupath, handoff).**
- CPU time outside the C sort is 1.4–1.5 % of a split worker in process (engine/sort 1.007; pprof 99.17 % in cgocall)
  plus ~0.6 % live from the other goroutines: not a lever. No memcpy exists (zero-copy shm); 0.0097 mallocs per hash;
  1.0002 cgo crossings per hash.
- Live decomposition (read-only proc_pid_rusage probe, 60 s windows): 16–17 % of the miner's CPU-seconds run on
  E-cores at 0.38× P throughput (E/P 0.356–0.382 per CPU-second from instruction counters, replacing R18's 0.44 per core
  and R22's ≥ 0.38 bound); the live P-core split rate is **5,963 H per P-core-second at P-IPC 4.40**, equal to the
  bench. Idle-try own pairs cost 1.673–1.749× a staged sort (handoff 1.696, verifier 1.673; cpupath 1.749; R22 said
  1.81). Law to restate (OPEN, r24): H/s ≈ 5,960 × (P-core-s + 0.38 × E-core-s) × own-mix factor, computed with the
  verifier's form (bench cycles per hash at the live P clock; residuals −1.8 to +2.7 % over 12 windows), not the
  builder's, which counts own-hash IPC twice (+5–6 % off when own hashes are 16–19 %).
- Handoff: CPU threads are never idle while a staged text can be claimed; backlog and idle tries alternate ~21 times a
  second; `hashes_total − split_hashed = 2 × idle_tries` exactly (8,643,110 = 2 × 4,321,555 at 10:08). Wakeup lever
  ≤ 0.4 %; claim/lock overhead ≈ 0 (median 1.016); chunked SHA −24 to −64 % (model).
- Regime: "a faster sort feeds the GPU" is regime-dependent. Quiet box (GPU busy ~95 % of 96): at most +1.6 % staged
  before the cap binds. Contended windows (09:19–10:21 split series): GPU busy 73.3–85.7 % with backlog 54–56 s/min,
  where the sort binds and staged rises with sort speed. OPEN: the live binding label of r23c.
- Test-only fix: the R21 overhead A/B legs did not yield; at matched T = 4 engine/sort 1.030 → 1.006 (verifier, 7
  pairs); both base legs lacked the yield (sort-only ×1.090, engine ×1.048). Miner binary sha256 unchanged.

**41.4 GPU geometry (gpuflow).** Only a bigger batch helps. Proxy next to the live miner (benchlock --gpu, live
restarts 0 before and after every run): `DERO_GSPLIT=8192,3,2` cuts GPU busy per hash to ×0.72–0.82 (28/28
light-regime pairs below 1), 8.8 GB of shm; GPU ceiling ~87.3k → ~114k staged (ESTIMATE). With today's sort the CPU
then binds at 93.15–93.9k staged-equivalent, so +2.9–3.7 % TOTAL on a quiet box (ESTIMATE). Kernel ABAB: final SHA
8192/4096 ×0.52–0.53, stage 1 ×0.996 at tries above 20 but ×1.197 above 30 (live ~270 tries), so the gain may sit at
the weak end. Refuted: warp-specialised final SHA (pipeline ×0.96–0.99), inflight 3 (live miner ×0.92), depth alone,
cross-batch SHA coalescing (×0.963 at depth 4), and 8192,5,3 as the A/B (no better than 8192,4,2, batches ×2.3 longer,
14.7 GB). Default stays 4096,4,2 (stale ~1.25 % → ~1.9 % by the model). OPEN: quiet-box ABBA of 8192,3,2 (41.11).

**41.5 Sync overlap and the store (chainperf).** Per synced block the node spent ~11–15 ms of PoW prewarm and ~12–18 ms
of Add_Complete_Block strictly in series; Add ends with the topo record and an F_FULLFSYNC (median 7.1 ms builder,
4.93 ms verifier, against fsync 0.03–0.13 ms). `p2p/sync_prewarm_overlap.go` starts the next block's unchanged
`prewarm_pow` once every tip's topo record names it (consensus unchanged: only TRUE verdicts are cached);
`DERO_SYNC_PREWARM_OVERLAP=0` disables it. Loopback shadow: ×1.255 blocks/s (7/7, 37.2 → 49.7), verifier ×1.331
(6/6), CPU/block 0.991–0.993, treehash identical, overlap-off = base. The verifier made `finish()` deferred (a panic
in the add path had left the poller running) and added call-site tests. Payout effect at tip ≈ 0 (sync only). Real
mainnet verify cost 148–159 ms/tx median; demand 0.000139–0.000185 TPS. Methodology: pop-based shadows inflated CPU
~20 % through `Count()`'s clean-tail walk (the live node has none). `tools/storecheck` (read-only): 0 problems on
20,000 clone blocks. Report-only (guarded `blockchain/`): atomic storefs writes, the per-block topo F_FULLFSYNC.
OPEN: live catch-up rate; prewarm metrics count overlapped blocks twice.

**41.6 P2P and RPC security (p2psec).**
- Ban list: an index bucketed by mask replaces a ParseCIDR scan of every ban under a global mutex (20,000 bans
  8,489,862 → 42.4 ns/op; 0 mismatches against the old scan over ~72k lookups). Penalty table: pruned at most once a
  second, banned records forgotten 7 days after the last fault, bound 65,536 (soft: 68,537 with every ban running).
- Inbound aggregate: 4 distinct score-banned scopes of one /24 or /48 within 1 h refuse new INBOUND sessions for 600 s,
  doubling to 24 h; outbound and existing peers untouched (no eclipse lever). Verifier fix `agg_soonest`.
- Remote RPC: trusted keys (≥ 10 min, ≥ 64 admitted calls, no ban in 24 h) score ×1 during a surge (RPC-1); untrusted
  keys share a /24 or /48 record with an 8× bucket and a 400-point ban line (RPC-2: 4,800 → 572 probes in 30 min); the
  per-key ban is checked before the global budget (RPC-3 = SEC23b-2: 580 → 0 tokens). Normal path CPU/op 0.978–1.052.
- OPEN: pre-warm escape (16 keys with 70 cheap calls each pass 4,800/4,800), collateral on heavy new honest clients in
  one /24 (≤ 13.3 % per 5 min for ~15 min), spoofed-source datagrams draining the pre-TLS accept budget (report-only,
  needs a return-routability cookie). Live effect today: RPC binds loopback and inbound is 0.

**41.7 Websockets and the wallet (rpcws).** Per-client ordered queues (8 per class, oldest dropped, TxPool marked
truncated) and one ordered push worker: a busy client lost ~50 % of back-to-back Block bundles, now 0 (fan-out CPU
×1.085–1.122 per 100 clients). Remote and cross-site GetTransaction / GetSC take at most 256 items per call (100k
txids had cost 934–965 ms CPU and 421 MB); the verifier made refused bodies scored and the body precheck 37 → 0.7 µs.
GetMonetaryIntegrity reads a summary (RPCWS23B-C, ~×15). Wallet: `plan_history_sync` resyncs after a reorg in one
call and keeps valid entries (RPCWS23B-E). OPEN: per-body aggregate item cap (a 256 × 256 batch is still admitted);
the template cache after a peer's miniblock (RPCWS23C-7, guarded `blockchain/miner_block.go`).

**41.8 Emission auditor (cryptoinfl).** Step 6b: every account's Right must equal the D values of its own rings in
every block, and its Left its own ring commitments + coinbase share + registration in blocks without SC calls
(`right_only` with SC calls). Base had audited a misattributed share, swapped commitments and two finals as ok. Also:
coinbase-shape ALERT from height 399,000 (10 miniblocks, 1 final); a rewind of ≥ 26 topoheights restarts the segment
(window 4,096) instead of double counting, and the verifier added the IssuedEmission reset; burns of an earlier DERO
payload in an SC call; GetMonetaryIntegrity carries issued, burns and payees; CPU ×0.643 (verifier ×0.638). Mainnet:
15,000 + 13,000 blocks, 0 alerts, every account exact. CI-9 (verifier): a receiver proof discloses Keccak(sk·E), the
V2 payload key, for an unbound E: payload privacy only, wallet-side, report-only. Report-only (consensus): BURN_TX
never verifies; SC partial-panic payouts audit as sc_unexplained; range-proof C1 needs a fork. OPEN: 24 h live read.

**41.9 Payouts census (payouts).** `harness/intel/payout_census.py` over 1,791 found shares: paid 97.04 % (0.9708 on
re-run); stale-flagged 1.06 % (19/19 orphaned), slot race 1.40 %, other 0.22 %, lost finals 0.28 %. Of the 5 lost
finals, 3 reached our chain first and lost the lower-BLID tie-break, 2 were inbound (verifier; the builder's
"latency" label was wrong). Phase-exact expected shares replace 5/(9D) (×1.034–1.072 over-statement). derod
flip-delay counters (simulated L9 mean 10.36 ms, ~0.1 %). Uptime: 0.2667 of 86.46 h (≈112 DERO forgone) to 0.2735 of
87.26 h (≈102), ESTIMATE; 34 % of the idle hours overlapped derod downtime, and derod has no supervisor. OPEN: live
counter reads, `--phase-duty` A/B (+8.6–8.8 % upper bound, ESTIMATE), UDP 11011.

**41.10 Harness and pipeline.** `harness/round.json` round registry read by `fix_build_verify.py` (S3a base,
`ROUND_NEW_METHODS`, a registry check at BEGIN; status `implemented` added in the R23c docs commit, KAT RR1–RR4 with
9 mutations); `harness/pipeline/benchlock.py` in the repo; `mine_evolution.py` + DK35 (src-arch evolution);
`payout_census.py` + KAT; `artifacts/dero-rft.md`. Full run `pipeline_20261101T120821`: guard, format (3 pre-existing
vet findings), flaky 82×3 0, test, soundness 29, KATs, mutations 955/955 (3 upstream failures recorded), race 26
packages 0 races, build r23c PASS; S4b REFUSED (contended: foreign 4.88 cores; descriptor/SA-IS 4.58 not evidence);
S4c SKIP (server sha 5aff39c8f529 unchanged); shadow 120/120, 240 treehashes, 0 mismatches, 0 regressions; install
PASS; S7 FAIL 21/22: G22's auditor-metric anchor `emission_audit.go:243` had moved to `:265` → 4f0dda2. Project-only
`pipeline_20261101T140320` / `…141454`: 22/22 with 1 refused row (evolution_git.tsv line 1 carried HEAD, so
mine_localdiff's first-line anchor went stale → 8a086cd); `pipeline_20261101T142234`: KATs 35/35, harness mutations
34/34, gates 22/22, 0 refused. Install-backup bug (4f0dda2): the tag regex dropped the letter suffix, so r23b read as
r23, whose backup already existed, and r23b was replaced with no copy; now `r\d+[a-z]?`; r23b rebuilt from cd1be86
into `bin/*.22102026.r23b-backup` (vcs.revision cd1be86, modified=false; sizes differ by build path).

**41.11 Live result (measured 2026-11-02).** The r23c miner (`3.6.0-153.DEROHE.STARGATE+22102026.r23c`, run from a
terminal, not launchd; 20 threads, `--cpu-max=90`, split GPU at the default `DERO_GSPLIT` 4096,4,2; up since ~00:53,
derod r23c up since 23:30) was read over 01:08→01:28, n=81 15-s TOTAL lines, load avg ~50–57 (a niced scratch backup at
~71 % of a core and macOS system services). Sources: `harness/runtime/r23c_live_window_20261102.txt`
and `harness/runtime/r23c_live_extract_20261102.txt`.

| Measured | r23c 01:08–01:28 | reference |
|---|---|---|
| TOTAL H/s | mean 94,273 (median 96,297, min 86,209, max 97,651) | r23b quiet 09:27–09:37: 90.5k → **+4.2 %** |
| cores / H/cpu-s | 17.37 / **5,435** | r23b quiet 17.53 / 5,164 → **+5.2 %**; same-day r23b 11-01 15:14 5,265 → **+3.2 %** |
| staged H/s | 87,904 mean (21 GPU split lines) | — |
| GPU busy | 95.6 % of the 96 % cap; duty bucket sleeping 15.2 s/min | r23b 93.1–95.3 % |
| CPU backlog / ring full | 36.9 s/min (23.9–53.7) / 44.7 s/min | contended r23b 54–56 s/min |
| split health | 0 restarts, 0 audit faults, 0 GPU/CPU mismatches, 0 descriptor fallbacks; dropped_stale +956,878 (~0.9 % of staged) | — |
| payouts | 28 found in window; GetMiningOutcome 01:28: submitted 45, paid 39, orphaned 2 (slots_full), pending 4, paid 0.9512 | — |
| emission | GetEmissionAudit 01:28: OK, 489 audited, 0 alerts (7,844,298–7,844,779), 3,331/3,331 payees explained, 3,525 µs/block | 24 h read OPEN |
| getwork flip | 7,163 s of derod: 16 dead normal jobs, 128 flips; flip delay n=14 mean 52.7 ms | simulated L9 10.36 ms |
| node | GetSyncInfo: synced, lag 0, 13 out / 0 in; derod.log since 23:00: 1 ERROR (peer short GetObject reply), 0 WARN | — |

Preliminary windows (supporting only): r23c 2026-11-01 16:10–16:13 n=15: 95,659 H/s, 17.89 cores, 5,348 H/cpu-s, GPU
96.0 %; same-day r23b 15:14: 92,578 H/s, 17.58 cores, 5,265 H/cpu-s, GPU 95.4 % (R23c hashrate watcher log).

Verdicts. (1) The sort win is CONFIRMED on H/cpu-s: +5.2 % against the quiet baseline and +3.2 % against same-day r23b.
It exceeds the 0–1 % quiet-box estimate (41.2), so part of it may be load or regime variance: PLAUSIBLE magnitude, not
a measured ×1.05 sort. (2) Regime law confirmed: on this semi-quiet box the GPU co-binds (95.6 % of the 96 % cap with
the duty bucket sleeping), so further H/s needs GPU-side work; the quiet-box ABBA of `DERO_GSPLIT=8192,3,2` stays OPEN
(user-run). (3) 150k stays out of reach in software on this box: the reading sits inside the ~90–100k ceiling band (§39.1; ~100k from the per-core sort rate, R23b).
Observation: derod's JSON-RPC now answers only with `Content-Type: application/json`; without it the body is empty.
Closed loop after the measurement docs: `pipeline_20261102T013726` FAIL (miner_runs L3 rounding on a 12 s run → b205a4d),
`pipeline_20261102T014053` PASS (KATs 35/35, harness mutations 34/34, gates 22/22); measured head 51caf2b.
Whole run (00:53:03 → 02:04:08, ended by a typed console exit): 4,265 s, avg 94,009 H/s, 83 miniblocks + 11 blocks
accepted, luck 1.06 on 88.4 expected; GetMiningOutcome 02:08: 95 submitted, 92 paid, 3 orphaned (slots_full), paid
0.9684; emission audit 622 blocks, 0 alerts; flip delay n=30 mean 61.2 ms (`r23c_live_extract_20261102.txt`).

Still OPEN: uptime under launchd (the miner ran from a terminal; typed console exits on 11-01 at 16:13 and 22:39, so
uptime stays the biggest payout lever); the 8192,3,2 ABBA; the `--phase-duty=balanced` A/B; the 24 h emission read;
E-core pinned sort bench; the `stale_sha_skipped` over-count of TOTAL (0.30–0.42 %) as a separate counter; the P/E CPU
split metric.

## 42. ★ Round 24: a node-only round — trust and aggregate hardening, RPC body bounds, one admission policy, integrity and privacy fixes, sync prewarm fixes, area intelligence, the disclosure track, coherent artifacts (+22102026.r24, 2026-11-02)

> Filled from the R24 records: the pipeline records (`harness/loop/runs/pipeline_2026110*.jsonl`), the registry
> (`harness/round.json` r24), the workflow digest `harness/loop/runs/r24_dimension_results_20261102.json`, the disclosure
> snapshot `harness/runtime/disclosure_track_20261102T184720Z.json` and the scorecard `harness/runtime/area_intel.json`.
> Bench and shadow figures are labelled as such; live r24 figures are `pending` until the user restarts derod onto r24.
> The miner track is PAUSED (artifacts/dero-rft.md §0.3). Measured 2026-11-02 on the restarted r24 derod: §42.9.

**42.1 Live forensics (of the r23c node; no miner).** The miner was stopped (paused by the user). Read-only probes of the
running r23c derod found two defects that R24 fixed: GetMonetaryIntegrity published issued 0, `issued_matches_formula`
false and payees 0 while GetEmissionAudit said OK (CI24-1; 13:26 UTC: audit issued 38,806,500, payees 8,625/8,624/8,625),
and JSON-RPC answered an empty 415 to any Content-Type other than exactly `application/json` (B38). The disclosure
track's live read (17:56 UTC, r23c) gave S1, S2, S4 PASS and S3 FAIL, the same CI24-1 defect
(`harness/runtime/disclosure_live_20261102T175638Z.txt`). These readings are booked to r23c, the binary they were read
from.

**42.2 Mining and payouts.** PAUSED (artifacts/dero-rft.md §0.3, §2.7): no miner change, no miner bench (S4b/S4c
`PAUSED (miner)` in every R24 run, because no file under `cmd/dero-miner`, `astrobwt`, `gpu-miner-poc` changed since the
round base). The node side ran as getworkops: B39's "5× flip delay" is refuted as a dispatcher defect — the live
counter books the delay only for flips with a dead window (a conditional mean, 61.2 ms; 238 flips, 34 dead jobs, 30
dead windows), the model's L9 books every flip; replaying the model through the shipped watcher gives 51.46 ms
conditional, z=1.60 (GWO24-1). New counters `getwork_final_flip_l9_seconds` (comparable with the model) and
`getwork_final_flip_slow_total` (> 150 ms; GWO24-3). The dead windows come from the 100 ms template cache in guarded
`blockchain/miner_block.go:397` (report-only, ESTIMATE ~0.04 %, GWO24-4). derod supervision: `tools/launchd-derod`
(KeepAlive, ExitTimeOut 120; not installed, GWO24-5); `tools/nodehealth` and `tools/getworkprobe` need no miner.

**42.3 P2P, block sync and block management.** The sync prewarm's first-wave workers each recomputed
`Get_Difficulty_At_Tips` from the store (9.05 s of 27.74 s in the base profile): single-flight removes the herd, CPU per
synced block ×0.947 (verifier, 6/6 pairs; builder ×0.916), blocks/s not established on a contended box (run position
dominates, CP24-3). Prewarm metrics counted overlapped blocks twice (live r23c: 1,040 = (88 + 16) × 10): now 10.00 per
block (shadow 24/24, base 17.48), overlapped time in `p2p_sync_prewarm_overlap_seconds_total` (B34). A non-blocking
peek of the next pipelined response extends the overlap across responses: ×1.114 blocks/s from a live source (verifier
6/6, range 1.008–1.160; builder ×1.132 on 3 pairs), CPU per block ×1.009. The compact-block path never called
`txcanon.Observe` (live: 6 compact hits, 0 observed): it now observes after the block is accepted (B18). The chain
locator spun forever on a topo read error (`continue` without `i++`): fixed (SP24-5). storefs atomicity and the topo
F_FULLFSYNC stay report-only (guarded, B11/B31).

**42.4 Tx pool, admission, RPC and websockets.** One admission policy for RPC and relay (`glue/txpolicy`): a flight
keyed by Keccak256 of the raw bytes verifies identical submissions once (6 concurrent copies: 466–477 → 87–97 ms CPU),
a negative cache remembers proof failures only (replay 44–46 → 2.5–3.3 ms; a corrupted-proof copy with the same txid
cannot poison the valid bytes), and a pool cap with fee-rate eviction refuses before verification; txs carried by a
mining template are protected (the verifier showed eviction could make the node reject its own block). Mined txs stay
in the pool until HouseKeeping; GetFeeEstimate, GetTxStatus and the cap no longer count them (GetInfo's pool size
still does: report-only). B19 is VERIFIED — integer fee/size ranks every mainnet tx 0 (58/58 in the last 20,000
blocks) — but its fix makes consensus guard S1 fail, so it is not shipped. RPC: B38 root-caused to the upstream jrpc2
bridge (exact compare, empty body); 415/405 now carry a JSON-RPC -32600 body. B29: at most 1,024 txids + keys per
remote body, cost ceil(n/8) tokens per call, at most 1,024 items in flight per remote socket, loopback unbounded; the
verifier closed two inherited bypasses (an ignored params field skipped the item bound; one non-object batch element
skipped all remote admission: 5,100/5,100 Pings served and `rpc.serverInfo` answered a remote caller) and corrected the
cost of a 256 × 256 batch to 5.8–6.0 s child CPU. Websocket push queues and watch cleanup reviewed: no defect.

**42.5 Crypto layer, soundness and the emission audit.** CI24-1 (above) fixed: the integrity summary now maps every
field the emission summary carries. CI24-2 (B32): a V2 receiver proof leaks the payload key when another transfer
repeats an earlier transfer's ephemeral key E (E is not bound by the statement proof): the wallet indexes
Keccak256(tag, H), never H, and withholds every proof carrying a repeated key (griefing for one tx fee remains; a
third-party-checkable binding needs a proof-format change). CI24-3: graviton `Tree.Random` draws a leaf with
probability 2^-b by depth, which biased GetRandomAddress decoys: node-local depth correction (`R24_DECOY_SLACK=2`,
modelled MAP success 7.0 %, +9.6 ms CPU per call). The disclosure track (§42.7) re-tested every claim. B22, B33, B8:
documented, consensus.

**42.6 Security: a) DoS, b) AI agents, c) inflation.** a/b) Trust is revoked by probing; a trusted key's unknown names
score into its /24 or /48 aggregate; probes never earn trust (S1: 16 pre-warmed keys 4,800 → 573 probes). Aggregate-only
refusals are rate-limited and not scored, so a heavy honest /24 is no longer banned (S4 bans 0). The penalty table has a
hard bound by insert-time eviction (peak 85,536 → 65,536; one eviction pause ≤ 12.9 ms per 4,096 records; evicting a
record never unbans). A returning-peer lane admits addresses with a verified handshake (B30 mitigation; the cookie stays
a report-only wire change). Normal paths within ±1 %. c) Inflation: CI24-1 restored the published integrity RPC; the
emission auditor stays the detector (24 h read pending); the range-proof class stays invisible to a node (B8, §42.7).

**42.7 Harness, ops/tools, docs and artifacts.** The paused miner track (`harness/kit/roundtracks.py`, KAT TR1–TR7, 32
mutations) and the B21 known-failures list; area intelligence (`harness/areas.json` 14 areas; `area_intel.py`; G23;
scorecard 20261102T123330: OK 10, WATCH 3, PAUSED 1; 0 high, 3 medium, 19 low proposals); the disclosure track
(`disclosure_track.py`, G24; 11 claims re-tested; C1 CONFIRMED, C2–C7 PARTLY-CONFIRMED, C8 CANNOT-DETERMINE-LOCALLY,
X-EXEMPT PARTLY-CONFIRMED, X-PARITY and X-SUPPLY CONFIRMED; facts NF24-1..11; FX-F1..F4 FORK-REQUIRED designs; FX-N1..N9
node-local, 4 implemented; 150/150 anchors; census 15,866 scalars, 0 ≥ Order). Two patches both named their gate G23:
area intelligence kept G23 and the disclosure gate became G24 at the merge (76fd69b). Artifact coherence (rft §2.9,
§0.6): one canonical source per figure, §6 as one ordered list, and `harness/intel/coherence.py` (G25) checks every
artifact against its source, including src-arch staleness; `gen_index.py` now links the current ledger page (it still
linked `dero-r1-r21.html`).

**42.8 Pipeline, install and restart notification.** `pipeline_20261102T090301`: S1–S6 PASS (mutations 1108/1108, race 26 packages 0 races, shadow 120 blocks 240 treehashes 0 mismatches, install PASS), S7 FAIL at mine_evolution (KeyError 'R24', fixed bed3ef4). `pipeline_20261102T104901`: S3 FAIL (opt-in simulator tests, fixed cc1c391). `pipeline_20261102T110200` (registry `pipeline_full`, `--no-install`): PASS, mutations 1108/1108, KATs 35/35, harness mutations 34/34, gates 21/24 (+3 PAUSED, miner). `pipeline_20261102T123214` (project-only): PASS, KATs 35/35, harness mutations 34/34, gates 21/24 (+3 PAUSED, miner). `pipeline_20261102T125906` (closing project-only run, G25 included): PASS, KATs 35/35, harness mutations 34/34, gates 22/25 (+3 PAUSED, miner). Installed 3.6.0-153.DEROHE.STARGATE+22102026.r24 (backups `bin/*.22102026.r23c-backup`); no new flag. Restart: derod only (rft §11).

**42.9 Live result (r24).** Measured 2026-11-02 (artifacts/dero-rft.md §13, "Round 24 — after measurement"). The user
restarted derod onto r24: the r23c derod shut down cleanly at 15:30:46 and the r24 banner (`Version
3.6.0-153.DEROHE.STARGATE+22102026.r24`) is at 15:31:03 (pid 49367, from a terminal, not launchd). Read-only reads at
15:41:24 (uptime 621 s) and 16:32:01 (uptime 1:00:59): `harness/runtime/r24_live_first_20261102.txt`,
`harness/runtime/r24_live_hour_20261102.txt`.

- **CONFIRMED live.** CI24-1 / BD7: `disclosure_track.py --live` S1–S4 PASS at 23:41 UTC (height 7,847,566) and 00:32
  UTC (height 7,847,732); S3 GetMonetaryIntegrity = GetEmissionAudit on 18 shared fields (the r23c node FAILED S3)
  (`harness/runtime/disclosure_live_20261102T234142Z.txt`, `disclosure_live_20261103T003206Z.txt`; track fact NF24-12).
  B38: a POST without Content-Type gets `415 Unsupported Media Type` with the JSON-RPC body `{"code":-32600,"message":
  "Content-Type must be application/json (charset, if given, utf-8)"}`. Node health over the hour: synced, lag 0, tip
  age 22.456 s → 27.476 s, 12 outgoing / 0 incoming, 0 recovered panics, 0 p2p bans, 0 ERROR / 0 WARN in derod.log since
  the banner. Emission audit 16:32: OK, 219 audited (segment 7,847,516..7,847,732, 2 reorgs), 0 alerts, issued =
  formula 6,672,750, payees 1,447/1,447, mean 3,389 µs/block (r23c 01:28: 3,525; no auditor change in R24).
- **Census.** Last 100,000 blocks on r24 (tip 7,847,749): 344 bodies, 1,301 payloads, 15,782 proof scalars, 0
  non-canonical, 0 parse errors (`harness/runtime/disclosure_census_20261103T004204Z.json`).
- **PLAUSIBLE, not settled by the hour.** Every new r24 counter read 0 at 16:32 (`block_tx_roundtrip_observed_total`,
  every `p2p_sync_prewarm_overlap_*`, every `rpc_abuse_*`, `p2p_inbound_proven_lane_*`). None of the 217 audited blocks
  carried a tx (`harness/runtime/r24_live_txcount_20261102.txt`), the node never synced, RPC binds loopback and inbound
  is 0, so B18 (compact observed > 0), B34 (10 prewarmed PoW per synced block), the sync CPU figures (CP24-1, SP24-3)
  and the security bounds (B28/B29/B30) stay bench / shadow evidence: `pending` live. Booking such a 0 as a measured
  value is the self-detected B54.
- **PAUSED (miner).** The L9 / slow-flip counters (B39, B36): no miner connected (`getwork_final_flips_total` 0).
- **pending.** The 24 h single-segment emission read (B36) from 2026-11-03T15:31; decoy CPU per call (B51: no
  GetRandomAddress call reached the node). Nothing REFUTED.
- **Registry.** r24 `measured`; `github_sync` cf89e78 (the r23c sync target) → b76eee1 (the R24 measured head); public copy commit 7878f1c (local only, never pushed).

**42.10 Consensus observatory (R24 addition, 2026-11-02; artifacts/dero-rft.md §0.7, §2.10).** A read-only layer that
watches who makes the chain and the peers this node hears it from, built without touching derod (0 Go files).

- **Chain observatory** `harness/intel/consensus_intel.py` → `harness/runtime/consensus_intel.json`,
  `consensus_capture_<ts>.txt` (one line per KPI, participant, detector, proposal), `consensus_series.jsonl`. Every
  consensus constant is parsed from the line that declares it; 18 detectors (timestamps, the difficulty rule
  recomputed, 9+1 miniblocks, reorg depth and finality, fork fingerprint, v2 remnant, concentration, finals vs regular
  share, cadence). Gate G26; KAT CI1–CI19b; page `harness/miners/mine_consensus.py` → `harness/kit/consensuskit.py`.
- **Network-peer observatory** `harness/intel/peer_intel.py --live` → `peer_intel.json`, `peer_capture_<ts>.jsonl`,
  `peer_logx_<ts>.jsonl`, `peer_series.jsonl`; 14 detectors tied to their rule lines (`p2p/common.go` HF3 filter,
  `p2p/sync_pipeline.go`, `p2p/stuck_peer.go`, `p2p/penalty.go`, `p2p/diversity.go`, `p2p/first_relay.go`, ...). Gate
  G27; KAT PI1–PI13; page `harness/miners/mine_peers.py` → `harness/kit/peerkit.py`.
- **Privacy design.** Salted blake2b pseudonyms (`m-`, `peer-`, `node-`, `miner-`, `this-node`); salts and raw captures
  only in `~/derohe-persist/consensus_private` and `~/derohe-persist/peer_intel_private` (0700, files 0600, pruned to the
  newest runs by `harness/kit/privkit.py`). Before the integration the triage, log-bridge and intel rows copied peer
  IPv4s from the derod console into `harness/model/raw/*.json`, so the page showed 6 distinct peer or seed addresses
  and `verified.json` 10 (plus 5 test literals quoted from Go tests); now `miners/minelib.emit` pseudonymises every non-reserved IPv4 with the peer salt (the same name
  the peer observatory gives that peer), anchors resolve through the salt-free mask (`gen_deroarch.resolve_ev`,
  `verify_deroarch` DK01), and G27 scans the whole page, `verified.json` and the log-derived raw files (KAT PI13, PK1–PK4).
- **The loop.** S7 runs both observatories before `area_intel.py`; areas `consensus` and `peers` turn OBSERVED/ANOMALY
  detectors (`detector_feeds`) and node-side gaps (CO24-C*, CO24-N*) into proposals; rft §7 B55–B72 carry them; R25
  dimensions `consensus` and `peers` implement the node-side rows (a derod restart) and re-measure. `coherence.py`
  check `observatory` (G25) ties every capture an artifact names to that capture, and the src-arch sections and the
  ledger's "Consensus observatory" section to the newest outputs.
- **First findings (r24).** Chain (`harness/runtime/consensus_capture_20261103T054000Z.txt`): OBSERVED 1, ANOMALY 1,
  NORMAL 16; 44 participants, mean block time 18.494 s; the difficulty rule holds on 2,998 of 2,998 blocks; the
  Nakamoto coefficient is 3 by finals (top-3 integrators assemble 0.5517 of the blocks); GetInfo `alt_blocks_count` is
  declared and never assigned (0 against 104 side-block lines; CO24-C4). Peers
  (`harness/runtime/peer_capture_20261102T214042.jsonl`): 14 out / 0 in, first-relay share 66.7 %, OBSERVED 3, ANOMALY 4;
  one peer delivers two thirds of first relays and is also the only one with unserved objects (D5, D9); one node id sits
  on two addresses (D11) and its two clock offsets disagree by 180 ms, so the D6 reading is a path artefact candidate
  (B72). No grade is an accusation.

## 43. ★ Round 25: a node-only round plus the monetary-forensics engine — typed RPC errors, consensus and peer counters, a sync hold, dataset v1 of the HF3 window with content-pinned replay, an independent audit, a traced frontend, and the tooling track (+22102026.r25, 2026-11-03)

> Filled from the R25 records: the pipeline records (`harness/loop/runs/pipeline_20261103T*.jsonl`), the registry
> (`harness/round.json` r25), the digest `harness/loop/runs/r25_dimension_results_20261103.json` (node workflow
> wf_73b0a863-dde, forensics workflow wf_f130a2af-f58, the merge's "Left open") and the dataset `forensics/r25/`.
> Bench and shadow figures are labelled; live r25 figures stay OPEN until the user restarts derod onto r25. The miner
> track is PAUSED (artifacts/dero-rft.md §0.3).

**43.1 RPC robustness (rpcrobust).** The R25 discovery's four GetEncryptedBalance calls below prunedheight made the r24
node log four recovered panics (`panic(err)` after `ReadBlockSnapshotVersion`, rpc_dero_getencryptedbalance.go:92; B85,
self-caused, G15 FAIL until the restart). r25: a typed −32031 before any read, a rate-limited WARNING without a stack,
and a metric; all 31 `panic(` lines of the handlers audited (B86); GetBlockHeaderByHash's shadowed `err` (B80); per-tx
`txs_status` on GetTransaction; GetInfo `total_supply_basis` (BD6); wallet RPC Content-Type (B40); the B41 chain-swap
race closed with one lock. Harness: `error_census.py` (every ERROR/WARNING kind by class each S7) and `kit/pruneguard.py`
(every probe refuses a state read below the live prunedheight and logs its state reads). Residual: NameToAddress for an
unknown name answers untyped −32098; GetEncryptedBalance with no topoheight reads topoheight 0 (B100).

**43.2 Consensus observability (consensus).** CO24-C1..C7 (B55–B61) as logging, counters and RPC fields only
(`p2p/consensus_obs_r25.go`, `cmd/derod/rpc/consensus_stats_r25.go`), `DERO.GetConsensusStats`, D19 and the B72
detector fixes in `consensus_intel.py`. The verifier moved a mutex out of the topo reads in the alt tracker (96 µs per
read under the lock) and demoted two console lines upstream never logged. BlockHeader_Print stays without fees
(`rpc/` is guarded). Live: OPEN until the restart (alt_blocks_count, Reorganisation INFO lines, `reorg_monitor.json`).

**43.3 Peers (peers).** CO24-N1..N7 (B63–B69): offence scores, ban reasons and sources (`ban_reasons.json`), Chain
requests, INV clips, unserved objects, stuck holds; B47: a sync peer that answers with nothing is held, escalating
(the peers version of two builds won at the merge; a hold starts at the first failure). B70/B71 address hygiene, B72 D6
cross-check. Verifier residuals: strikes never decay and a fully held set means no sync; `Offenders()` holds penalty_mu
22.6–23.4 ms per GetPeerInfo on a full table (B99); two invalid_pow offences never ban (B102, policy). Live: OPEN
(`peer_intel --live` should report evidence_mode `counter`).

**43.4 Security and pool (secpool).** B48 netgroup quota on the proven lane and a quarter burst for fresh remote keys,
B42 rebroadcast skips mined txs, B44 cap under concurrency, BD5/FX-N4 admission refuses non-reduced proof scalars
(block txs only counted). The verifier found that the burst and quota changes had emptied four older mutation proofs
while every test stayed green, and that the B47 call sites had no test; both fixed. B19 (user decision), B43 (root
cause) open.

**43.5 Crypto, supply and the disclosure track (cryptodisc).** BD9 settled by an executable honest-proof test (11 of 13
scalar classes verify under a value+Order re-encoding: encoding malleability under one TXID, pinned); B22 refuted above
height 399,000; B33 re-anchored; B81 (the HF3 table covers walls 2 and 3, not wall 1) corrected in the track and, this
round, in memory. Live reads on the r24 binary: B51 25.1–40.9 ms CPU per GetRandomAddress (verifier pooled 1.0–2.3× the
calibration).

**43.6 Perf and ops (perfops).** B46: the herd fix cuts sync CPU per block ×0.923, but sync blocks/s is set by the
one-at-a-time block add in guarded `blockchain/` (refuted as a lever, 36-run shadow campaign); B39 75 min live on r24
(dead windows = the 100 ms template cache, 0 slow); B35 `tools/launchd-derod -preflight` (the verifier closed a false
PASS for renamed or relative-datadir derods); B20 `benchlock --qos`.

**43.7 Tooling (harnesstool, rft §0.9).** Area `tooling` and `tooling_intel.py` (B87), the scrubbed memory mirror (B88),
the booking rule KAT (B89), the ORDER early warning (B90), the meta review, the generator determinism and scrub control
(B93: pubscrub misses 3 of 5 planted kinds, the src-arch build time breaks byte-exact double runs; open), every R24/R25
tooling defect class with a KAT. Pipeline self-fixes this round: the backup-tag reader took the first letter of the
next Go string literal (r24i/r24p), and after an install the shadow control must be the live node's build, not
bin/derod.

**43.8 The monetary-forensics engine (rft §0.8).** Stages, each with its own agent: acquire (21 candidate endpoints from
the repo and our own peers, 9 answered GetInfo, 6 serve the window; pseudonyms only, hosts private), extract (83,076
blocks and 94 tx bodies re-hashed, decoded with the node's own code through `tools/forensics`), replay (G28), audit
(G29, a second implementation sharing no code: its own Keccak-f[1600], decoders, table parser and tips walk). The
dataset `forensics/r25/` holds tier A (605 blocks and every table body in git), tier B (the store of 83,171 blobs in
`~/derohe-persist/forensics_raw`, outside git, referenced by SHA-256) and the derived records. Integration (this
round's last agent):
- **Content pins** (`harness/forensics/pins.py`): the replay is bound to the bytes it depends on (8 replay tools, 486
  decoder build inputs from `go list -deps` incl. vendored packages, `config/version.go` without its build-suffix line,
  the HF3 table, and the exact 29 line ranges derive.py cites), not to a commit; `pinned_commit` is provenance. The
  decoder is built with `-buildvcs=false`, and the audit binds to the pins' aggregate, so neither changes with HEAD.
  KAT MF12 (unrelated commit PASSES; a changed tool, input, cited or shifted line, table or input set FAILS).
- **The overturn at its source:** A4b's wording left derive.py; the audit re-ran (audit-2), audit-1 is kept under
  `audit/history/audit-1/` and G29 refuses a rewritten, dropped or unrecorded history run; overturns over all runs 1;
  A10c stays UNRESOLVED (archive roots witnessed at 190 of 14,226 topos, no end-state check).
- **Frontend and G30** (`artifacts/src/forensics_section.py`, `harness/forensics/facts.py`): eight sections of
  `dero-r1-r25.html`; every figure a fact span with file and SHA-256; no bare number; the window explorer decodes
  compact embedded data (block id + blob SHA-256 per height in a vowel-free base64, so no privacy grep can match by
  chance) and G30 decodes it back against `derived/window.jsonl.gz` row by row; an exploit and privacy lint over the
  rendered sections (MF8/MF9).
- **Wiring:** area `forensics` (`harness/areas.json`), S7 steps `verify_dataset.py`, `s7_replay.py` (full where the store
  and the archive copy exist, else PARTIAL and labelled; a full S7 run must reproduce the recorded report),
  `facts.py --write`; gates G28–G30; coherence check `forensics`.
- **What the dataset proves and does not:** see the ledger section "Monetary forensics": public emission and coinbase
  identities hold for every window block; per-tx facts (exception path, today's verifier outcome where state is
  held); no statement about hidden amounts (NOT-DECIDABLE-FROM-PUBLIC-DATA for the 75 TXIDs).
- **Closed pages stay byte-exact:** the r24 ledger page read live runtime files and drifted once R25 wrote its own
  disclosure entries; a closed page now reads frozen inputs (`artifacts/src/frozen/r24/`, from 629b8de).

**43.9 Resume checkpoint (rft §0.10).** `harness/intel/round_checkpoint.py` (KAT RC1–RC6) writes
`~/derohe-persist/round_state/r25_RESUME.md` every 10 minutes with the registry, the commits, every workflow agent's
state and its resume call, the pipeline runs and the §6 checklist; the coordinator's `r25_NOTES.md` "In flight" section
is folded into it. This agent resumed from it after a usage-limit stop (nothing of its own had been committed; the
scratch tree and the persist copies were intact).

**43.10 Live r25 node (measured 2026-11-04, rft §13 R25).** Restart 06:57:28, window to 08:00:18 (`harness/runtime/r25_live_window_20261104.txt`):
synced 60/60, 0 ERROR/WARN, 0 panics; GetConsensusStats, B55/B56/B58/B59/B60, the counter-mode peer observatory,
ban_reasons.json, B80 −32032, txs_status, total_supply_basis and B18 CONFIRMED live; B85 −32031 unit-proven (never sent
live); B47/B48/B57/B61 pending an event; B103 (insert_failed = concurrent duplicates, PLAUSIBLE), B104, B105 opened.
Miner: PAUSED.

## 44. ★ Round 26: a node-only round plus forensics dataset v2 by defect class — sync-hold decay, duplicate-race counting, typed explorer errors, a structural transcript-binding test, classes and bounds, the a2 replay to our treehash, a second independent auditor (+22102026.r26, 2026-11-04)

> Filled from the R26 records: the pipeline record (`harness/loop/runs/pipeline_20261104T220624.jsonl`), the registry
> (`harness/round.json` r26), the merge commit fea0206b, the audit2 + frontend2 commit c802e4bc, the dataset
> `forensics/r26/` and rft §7 B95–B128. Live r26 figures: §44.7 (measured 2026-11-05). The miner
> track is PAUSED (artifacts/dero-rft.md §0.3).

**44.1 P2P (node-net).** B99: a sync-hold strike now decays (a failure more than 10 min after the last hold ended
restarts at strike 1); an accepted relayed block that brings us level with the peer's advertised height forgives the
peer (also reached from sync_chain); when no peer synced in pass 0 and a held peer is ahead, trigger_sync tries the held
peers, soonest release first, so "every peer ahead is held" no longer means "no sync". B103: `NotifyMiniBlock` checked
`IsCollision` before `VerifyMiniblockPoW` and `InsertMiniBlock` re-checked it under the lock, so the second of two
concurrent deliveries of one miniblock was counted `insert_failed`; it is now `reason="duplicate_race"` and a
non-first delivery, and each "Miniblock refused" line carries the error text (≤ 256 B). The answer to the sender is
unchanged. B102: policy kept (invalid_pow 50 points, half-life 10 min), comment corrected, pinned by a test. Counting,
logging and peer selection only (non-consensus p2p files; S1 PASS).

**44.2 RPC (node-rpc).** B100: NameToAddress for an unknown name → −32032 (name echo capped at 64 B, a metric). B104:
the explorer methods (GetBlockHeadersRange, GetMiniBlocks, GetDifficultyHistory) decode with DisallowUnknownFields
(−32602), refuse a range below prunedheight with −32031 before any store read, and GetDifficultyHistory no longer
panics on a pruned-shape record (a recovered ERROR, the G15 class). B43: the simulator's intermittent wallet-tx proof
failures were stale decoys (the wallet builds at tip−3 but fetches decoys at the tip; upstream GetRandomAddress kept its
5-topo "unchanged" window only above topoheight 100); `decoy_window_topo` now applies at every height, clamped at the
prune floor (mainnet answers unchanged). The wallet-side root is report-only.

**44.3 Crypto and disclosure.** FQ4 (B113): `cryptography/crypto/r26_transcript_binding_test.go` pins every challenge
and its preimage, the u_x base and the inner-product call identical at the head, Release152 and the genesis-era tag
(the first with the mainnet Network_ID); 6/6 planted-transcript mutations caught; no invalid proof is built (§9
NO-GO). FQ5: no public-data test separates a defect-accepted proof from an honest one, so DC2 is not decidable per tx
and any aggregate over it is unbounded (NF26-3, INTERPRETATION).

**44.4 Forensics dataset v2 and the classes (§0.8.9).** `forensics/r26/` keeps v1 sealed (G28 re-verifies it byte for
byte). v2 holds 1,796/1,796 window tx bodies RAW and settles the 1,575 v1 pending-fee blocks (B96; SC payouts pending).
`classes.py`, `bounds.py`, `presence.py` and the invariant/FQ files tag the figures DC0–DC3 with coverage and a bound
kind; G31 refuses a lower bound shown as a total, DC2 shown as 0, a cross-class sum or a forbidden phrase; G32 keeps
the classes apart (its record half is vacuous until v2 records carry a class, B126). The merge found the class files
unlisted in the v2 manifest (B125, now `class_files`) and the a2 replay skipping the HF3 step (B123): through
`p2p.Add_Complete_Block_HF3` the held archive replays 31,025 blocks 7,467,516..7,498,540 to our treehash `ca11cc21…`.

**44.5 The second auditor (audit2) and the v2 frontend.** `harness/forensics/audit2.py` shares no code with the
builder (own Keccak, decoders, HF3 parser, scan). Audit-1 of v2: 19 HOLD / 4 FAIL / 1 UNRESOLVED; the FAILs were fixed at
source (B127: an open manifest must equal its ledger entry, rule L9; B128: G29 runs on every ledger version and binds a
v2 audit to its manifest); audit-2: 20 / 3 / 1 (A10c UNRESOLVED), history kept. The frontend (`facts.build_v2`,
`forensics_section.section_v2`, `fx_line_v2`) renders v2 by defect class on the ledger, src-arch and the per-round
soundness page; its verifier found 4 G30 holes (a removed known section or class block, digits inside an fxid span),
all closed (KAT FE8).

**44.6 Closed loop and install.** Run 1 `pipeline_20261104T175125` FAIL at S3b (2 STALE mutation anchors, B129, fixed d3189e1a with KAT GA1–GA2); run 2 `pipeline_20261104T193301` S1–S6 PASS and installed, S7 FAIL (r25 forensics area anchors on a rewritten file, B130, fixed c643634f with KAT AS1–AS2); run 3 `pipeline_20261104T213409` project-only PASS; run 4 `pipeline_20261104T220624` full PASS (`--no-install`): mutations 1329/1329, race 26 packages 0 races, shadow 120 blocks / 240 treehashes / 0 mismatches against the live r25 build, gates 29/32 (+3 PAUSED, miner). Installed by S6 (atomic rename from `bin/.staging`;
backups `bin/*.22102026.r25-backup`); `bin/derod` sha256 `f6ff3b005872f1cd791310f769e7b67c9dc5d00e340b47c0ebae9fd12bcc5692`.

**44.7 Live (measured 2026-11-05, rft §13 R26).** Restart 07:48:21 (pid 93240), 62 min read-only
(`harness/runtime/r26_live_window_20261105.txt`): 55/55 synced, lag 0, 0 ERROR / 0 WARN (G15 clear). CONFIRMED: the
duplicate_race split (767, insert_failed 0; the refusal line names the `collision`), −32032 for an unknown name, −32602
for unknown parameter names, the reorg monitor across a restart (`starts` 2). Pending an event: strike decay and
forgiveness (0 holds), B47, B48, B57, B61. B36: the r25 segment's 24 h emission re-audited offline, 4,846 blocks, 0
alerts, issued = formula 149,014,500 (`harness/runtime/r26_b36_emission24h_20261105.txt`).
