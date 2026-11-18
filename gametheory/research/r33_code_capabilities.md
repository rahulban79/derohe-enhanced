# R33 code capabilities: what a DVM contract can and cannot do for deflation, forensics, stake, mining identity, peer security and auditor integrity

Scope: read-only code reading of the repo at HEAD (`~/derohe-Release151`). No node RPC, getwork or P2P was called, and no process was touched. Anchors are repo-relative `file:line` and were all read in this session. Grades:
- CONFIRMED (code read): the anchors show the behaviour.
- ESTIMATE: arithmetic from anchored constants. Nothing was executed.
- UNCONFIRMED: not verified.

Prior work checked: `gametheory/research/r32a_security_inventory.md` (agrees with what follows; its §4 B10 row is refined in 1.2), `artifacts/dero-game-theory-rft.md` §4 (lines 181–206) and §9 (lines 272–279), and `harness/gametheory/audit_tasks.py`.

---

## 0. The DVM surface, in one table (all CONFIRMED)

The whole builtin table is `dvm/dvm_functions.go:57-95`. The gas cost of each call is charged at `:103`.

| builtin | reads | anchor | gas |
|---|---|---|---|
| `BLOCK_HEIGHT()` | `Chain_inputs.BL_HEIGHT` | `dvm/dvm_functions.go:289-292` | 2000 |
| `BLOCK_TIMESTAMP()` | `BL_TIMESTAMP`: the block's ms timestamp / 1000 (seconds) | `dvm/dvm_functions.go:302-305`; value set at `blockchain/blockchain.go:1021` (`bl_current.Timestamp/1000`) | 2500 |
| `BLID()` | hash of the block that executes the tx | `dvm/dvm_functions.go:275-278`; `blockchain/blockchain.go:1021` (`bl_current_hash`) | 2000 |
| `TXID()` | current tx hash | `dvm/dvm_functions.go:279-282` | 2000 |
| `SCID()` | own SCID | `dvm/dvm_functions.go:271-274` | 2000 |
| `SIGNER()` | 33-byte compressed key, all zeros if anonymous | `dvm/dvm_functions.go:307-310`; `dvm/sc.go:191`; ring 2 only: `blockchain/transaction_execute.go:441-459` | 5000 |
| `RANDOM([max])` | HSalsa20 stream keyed by Keccak256(SCID, BLID, TXID) | `dvm/dvm_functions.go:253-269`; `dvm/deterministic_random_number.go:36-41`, `:44-68`; seeded once per call `dvm/dvm.go:374-375` | 2500 |
| `DEROVALUE()` / `ASSETVALUE(a)` | value deposited by THIS tx only | `dvm/dvm_functions.go:434-456`; filled from `incoming_value` at `dvm/sc.go:209-215` | 10000 |
| `LOAD/EXISTS/STORE/DELETE` | own SC storage only (key carries own SCID) | `dvm/dvm_functions.go:121-149` | 5000/5000/10000/3000 |
| `MAPSTORE/MAPGET/MAPEXISTS/MAPDELETE` | RAM map for one invocation only, never persisted | `dvm/dvm_functions.go:210-251`; `dvm/sc.go:182` (`RamStore` fresh per call) | 1000 |
| `SEND_DERO_TO_ADDRESS` / `SEND_ASSET_TO_ADDRESS` | queue an external transfer | `dvm/dvm_functions.go:377-432`; queued in `dvm/dvm_store.go:138` | 70000 / 90000 |
| `IS_ADDRESS_VALID`, `ADDRESS_RAW`, `ADDRESS_STRING` | curve-point decode and address formatting | `dvm/dvm_functions.go:324-375` | 50k/60k/50k |
| `SHA256`, `SHA3256`, `KECCAK256`, `HEX`, `HEXDECODE`, `ITOA`, `ATOI`, `STRLEN`, `SUBSTR`, `MIN`, `MAX`, `PANIC`, `VERSION`, `DERO`, `UPDATE_SC_CODE` | pure functions, or code replacement | `dvm/dvm_functions.go:58-94` | flat |

**Not present:**
- No balance builtin, not even for the contract's own balance.
- No topoheight: `dvm_block_topoheight` is commented out at `dvm/dvm_functions.go:294-301`, although `BL_TOPOHEIGHT` is carried in `dvm/dvm.go:400`.
- No previous-block access, no miner or integrator, no difficulty, no reward, no tx list.
- No BLAKE2s, so no graviton key hash (see §4).
- No cross-contract read or call. Storage is keyed by own SCID (`dvm/dvm_functions.go:123`), and cross-SC calls are described as not enabled (`dvm/dvm.go:410-411`).

**Execution limits (consensus, CONFIRMED):**

| limit | value | anchor |
|---|---|---|
| compute gas per call | 10,000,000, fixed | `dvm/sc.go:241-244` |
| line cost | 5000 per line | `dvm/dvm.go:522` |
| binary expression cost | 800 per binary expression | `dvm/dvm.go:994` |
| lines interpreted per call | 2000 | `dvm/dvm.go:71`, checked at `:535-536`; every line counted at `:503` |
| evals per call | 11,000 | `dvm/dvm.go:72`, checked at `:853-856` |
| storage gas | tx fee, capped at `MAX_STORAGE_GAS_ATOMIC_UNITS` = 20,000 | `dvm/sc.go:247-254`, `config/config.go:46`; fee passed as storage gas at `blockchain/transaction_execute.go:359`, `:395` |
| store cost | 1 per serialized byte | `dvm/dvm_store.go:133` |
| SC data cost | charged to storage gas | `dvm/sc.go:262-263` |
| max tx size | 300 KiB | `config/config.go:56` |

**Return-value semantics:** a call commits only if it returns 0 (`dvm/sc.go:281-291`). Any other value means "Discarded knowingly", and the deposit is refunded to SIGNER (`blockchain/transaction_execute.go:412-421`). Any function name starting with a capital letter can be called externally, `Initialize` included (`dvm/dvm.go:354-371`), so a contract must guard re-initialisation itself.

---

## 1. Deflation: how a contract can remove native DERO permanently, and how each way is verified

### 1.1 The reported supply never shows a burn (CONFIRMED)
- `CalcSupply(height)` is a pure formula: PREMINE + 271,739,600 + Σ CalcBlockReward per epoch (`blockchain/supply.go:5-26`). The reward is `BaseReward >> ((h + RRI) / RRI)` (`blockchain/transaction_execute.go:60-62`).
- `GetInfo.total_supply` is this formula divided by 100000 (`cmd/derod/rpc/rpc_dero_getinfo.go:83-84`).
- A burn therefore never lowers any supply figure. The repo says the same about inflation: "prints the same number on a chain inflated…" (`cmd/derod/rpc/rpc_dero_getsupplyaudit.go:5-11`).
- **Consequence for R33:** "deflation" can only be shown as a separate, verifiable burn ledger. It can never be a lower total_supply.

### 1.2 The ways DERO can be removed

| # | mechanism | is it permanent? | anchors | how it is verified publicly |
|---|---|---|---|---|
| D1 | **Lock in a no-exit contract.** DERO is deposited with an SC call (the payload's BurnValue goes into the SC balance) into a contract whose code has no `SEND_DERO_TO_ADDRESS` and no `UPDATE_SC_CODE`. | Yes, provided the code has no send path and cannot be replaced. `UPDATE_SC_CODE` rewrites code (`dvm/dvm_functions.go:312-322`), so its absence must be checked. `Initialize` can be called again (`dvm/dvm.go:369`) and must be guarded. | deposit `dvm/sc.go:209-215` (SC asset key = zero hash); commit only on return 0 `dvm/sc.go:281-287` | **Best verifiability.** `DERO.GetSC` returns `balance` (the zero-hash key, `cmd/derod/rpc/rpc_dero_getsc.go:94-97`) at any `topoheight` (`rpc/daemon_rpc.go:236`) and the code (`rpc/daemon_rpc.go:234`, `:249`). Anyone reads the code once and the balance at any height. `DERO.GetSupplyAudit` sums every SC-held plaintext DERO (`cmd/derod/rpc/rpc_dero_getsupplyaudit.go:5-11`, `:48-82`). Each deposit is the plaintext `BurnValue` of the tx payload (`transaction/transaction.go:99`), and the emission auditor counts it as `SCDeposits` (`glue/emission/emission.go:362-395`). |
| D2 | **Plaintext burn outside an SC call.** A DERO payload with BurnValue > 0 in a tx that is not an SC call (a NORMAL tx, or an SC_TX without SCACTION, which returns early at `blockchain/transaction_execute.go:301-303`). | Yes. The payload's C/D already subtract the value, and nothing credits it (`blockchain/transaction_execute.go:204` comment: "burned amount is not added anywhere and thus lost forever"). | `blockchain/transaction_execute.go:204-256` | The tx carries the plaintext `BurnValue` (`transaction/transaction.go:99`). The emission auditor's `Burns` counter (`glue/emission/emission.go:314-329`) is published as `burns` in `DERO.GetEmissionAudit` and `DERO.GetMonetaryIntegrity` (`cmd/derod/rpc/emission_audit.go:202`, `cmd/derod/rpc/monetary_integrity.go:87`). **The contract never sees this burn**, so it would need an attestation. Proof of acceptance for a NORMAL tx: `blockchain/transaction_verify.go:454` passes the payload's BurnValue to `Proof.Verify`. UNCONFIRMED whether the stock wallet builds such a tx. The `BURN_TX` type never verifies (tx.Value is not serialised; rft B33, KAT `TestR28BurnTxNeverVerifiesKAT` at `blockchain/r28_sc_flow_test.go:624`), so it is not usable. |
| D3 | **Earlier DERO payload in an SC call.** `incoming_value[SCID] = BurnValue`, so the last DERO payload wins and an earlier one is destroyed. | Yes | `blockchain/transaction_execute.go:305-308`; auditor `glue/emission/emission.go:365-377`; test `glue/emission/r23c_peraccount_test.go:192` | Counted in `Burns`, which is visible. It is accidental, and a contract cannot see or check it. Do not design on it. |
| D4 | **SEND to an unregistered (valid-point) destination.** `SEND_DERO_TO_ADDRESS` accepts any decodable point (`dvm/dvm_functions.go:383`). `SanityCheckExternalTransfers` treats `ErrNotFound` as OK (`dvm/simulator.go:236-244`). `ProcessExternal` first commits the SC writes, including the debited balance (`:312-327`), then panics at the first unregistered destination (`:362-366`). The caller recovers and keeps the tx (`blockchain/transaction_execute.go:284-296`). | Yes, deterministic on every node (characterised in `dvm/r23_external_transfer_test.go:18-28`, test at `:29`). **Order quirk:** if the unregistered destination is the LAST transfer, the named `err` stays `ErrNotFound`, so the call is refused and refunded (`dvm/simulator.go:237`, `:247`; test `:56-59`). A burn therefore needs `[unregistered, then registered]`, and the later transfer is lost too. | as left | The SC balance drop is visible in `GetSC` before and after. The destination reads as unregistered in `GetEncryptedBalance` (`cmd/derod/rpc/rpc_dero_getencryptedbalance.go:93-94`). The emission auditor does NOT count it as a burn: the block grades `sc_unexplained` ("an SC payout that panicked part-way burns the rest", `glue/emission/emission.go:596-598`). **It relies on a REPORT-ONLY consensus quirk** (rft B10): a future fix of the sanity check would turn it into a revert. Not recommended as the R33 burn primitive. |
| D5 | **Failed SC_INSTALL.** The deposit is destroyed and the fee kept: after an Initialize error the code returns before the ErrorRevert block. | Yes | `blockchain/transaction_execute.go:365-367` vs `:412-421` (rft B311) | Visible only by replay. It is a footgun, not a primitive. |
| D6 | **Failed anonymous SC call (zero signer).** `ErrorRevert` looks up the zero key, panics, and is recovered as `is_zero_signer_revert`: "burn value destroyed, fee kept". | Yes | `blockchain/transaction_execute.go:286-289`; `blockchain/sc_revert_log.go:48-57`; `dvm/simulator.go:277-278` | The tx is on chain with a plaintext BurnValue, but proving the burn needs a replay. A footgun. |

Notes:
- **No "registered but provably unspendable" address exists.** A registration needs a Schnorr signature by the key (`transaction/transaction.go:257-277`), so every registered key has a known owner. A burn to a registered address can never be proven unspendable.
- **Fees are not a deflation:** they go to the miners (`blockchain/transaction_execute.go:126-160`).

**Recommendation from the code:** D1 (a no-exit or time-locked vault) is the only burn that is (a) built from supported, non-quirk semantics, (b) visible by one `GetSC` read at any topoheight, and (c) verifiable by the contract itself, because it sees each `DEROVALUE()` and can keep a running `burned` counter in STORE. D2 is verifiable but invisible to contracts. D4–D6 are footguns.

### 1.3 Can a contract-owned token be burned verifiably? Yes, with caveats (CONFIRMED)
- **Mint:** a contract mints its own token without limit. The overflow and underflow checks are skipped for `asset == scid` (`dvm/simulator.go:210-211`, `:222-223`).
- **The SC's own-token balance key is meaningless.** It is stored as `stored_value - value` with no underflow check (`dvm/simulator.go:223`, `:229-230`; rft GT-B7), so it wraps. `GetSC.balances[own SCID]` (`cmd/derod/rpc/rpc_dero_getsc.go:124`) is not a holdings figure.
- **Burn:** a holder sends tokens back in a call payload with SCID = token. This arrives as `incoming_value[token]` (`blockchain/transaction_execute.go:305-308`) and is readable as `ASSETVALUE(SCID())` (`dvm/dvm_functions.go:440-455`). A `Burn` entrypoint that only does `STORE("burned", LOAD("burned") + ASSETVALUE(SCID()))` and never sends removes the tokens. The counters are public through `GetSC` stringkeys (`rpc/daemon_rpc.go:245`).
- **Circulating supply** = contract counter `minted` − `burned`. Holder token balances are homomorphic ciphertexts in the SC tree (`blockchain/transaction_execute.go:206-251`), so a third party cannot sum them. The counters are as trustworthy as the public code, which is readable via `GetSC code=true`.

---

## 2. Forensics inside a contract

### 2.1 What a contract can read itself (CONFIRMED, `dvm/dvm.go:394-402`)
SCID, BLID (the executing block's hash), TXID, SIGNER (ring 2), BL_HEIGHT and BL_TIMESTAMP (in seconds), plus DEROVALUE/ASSETVALUE of the current tx. That is the whole chain context.

- **The executing block's id can be self-recorded.** A call can `STORE(height → BLID())`. This is a self-recorded sample of main-chain block ids that anyone can compare with `GetBlockHeaderByTopoHeight`.
- **That record cannot survive a reorg.** Contract state is committed with the block's state (`blockchain/blockchain.go:1033-1074`), so a reorg that replaces the block also removes what the contract stored.

### 2.2 What must come from callers (attested off-chain)

None of these are DVM inputs:
- previous block headers and hashes (only the current BLID is available)
- topoheight (not exposed, `dvm/dvm_functions.go:294-301`)
- the miner keys of miniblocks and the integrator (`block/miniblock.go:53`; `blockchain/transaction_execute.go:137`)
- rewards and fees per block (`blockchain/transaction_execute.go:126-134`)
- orphan and side blocks (they get 0 reward and their txs are ignored, `blockchain/blockchain.go:984-986`)
- difficulty (`blockchain/difficulty.go`)
- tx counts (`rpc/daemon_rpc.go:36` `txcount`)
- any account balance (§3)
- other contracts' state (`dvm/dvm_functions.go:123`)

The DVM can check such a claim only through commit-reveal plus bonds, as in gt_audit (`gametheory/contracts/gt_audit.bas:4-7`, `:128`, `:146`), or through optimistic claims with challenge (rft §4 item 2, `artifacts/dero-game-theory-rft.md:186-189`).

The deterministic digests the harness already defines (`harness/gametheory/audit_tasks.py:10-17`):
- task 1: headers (hash, topoheight, miner keys)
- task 2: emission

They are only deterministic on settled heights (`SETTLE = 20`, `:33`) above the pruned floor (`:19-21`). The reason is that header `miners[]` resolves keys through the balance-tree snapshot at the block's topoheight and prints "unknown" when that fails (`cmd/derod/rpc/blockheader.go:73-93`, `:113-118`). A pruned node and an archive node could therefore produce different digests for old ranges.

### 2.3 Read-only RPC methods available for forensics (CONFIRMED, `cmd/derod/rpc/websocket_server.go:385-421`)
- **Chain reads:** GetInfo, GetSyncInfo, GetHeight, GetBlockCount, GetLastBlockHeader, GetBlock, GetBlockHeaderByTopoHeight, GetBlockHeaderByHash, GetBlockHeadersRange, GetMiniBlocks, GetDifficultyHistory, GetTransaction, GetTxStatus, GetTxPool, GetTxPoolDetail, GetEncryptedBalance, GetSC, GetRandomAddress, NameToAddress, GetGasEstimate (a simulation), GetFeeEstimate.
- **Audit and monitor reads:** GetSupplyAudit, GetEmissionAudit, GetMonetaryIntegrity, GetConsensusStats, GetPeerInfo, GetMiningOutcome.
- **Streams:** Subscribe, WatchTx.
- **Not read-only:** SendRawTransaction, SubmitBlock, GetBlockTemplate (mining).
- **Legacy aliases:** `:366-383`.
- **Header fields** (`rpc/daemon_rpc.go:24-42`): depth, difficulty, hash, height, topoheight, versions, orphan_status, syncblock, sideblock, txcount, miners[] (slot 9 = integrator, `cmd/derod/rpc/blockheader.go:120-122`), reward, tips, timestamp. Miniblock keyhash per entry: `cmd/derod/rpc/rpc_dero_explorer.go:269`, `:391-396`.
- **Node-local and not deterministic across nodes:** GetPeerInfo, GetConsensusStats, the GetMonetaryIntegrity finality monitor, GetMiningOutcome, GetTxPool*. They are not suitable as Schelling questions (§5).

---

## 3. Stake: what a contract can know about a wallet's DERO

- **Balances are encrypted** (CONFIRMED). Account balances are ElGamal ciphertexts, updated homomorphically (`blockchain/transaction_execute.go:238-241`). `GetEncryptedBalance` returns ciphertext hex (`rpc/daemon_rpc.go:158`). The DVM has no balance builtin (§0). A contract cannot see any wallet's balance, and it cannot read its own total balance either: it must track it with STORE from `DEROVALUE()`.
- **Off-chain "proofs of holding" are not usable.** Payment proofs can restate any amount (crypto audit C4, `gametheory/research/r32a_security_inventory.md:78`), so they are not evidence.
- **The only stake a contract can check is a deposit.** `DEROVALUE()` (`dvm/dvm_functions.go:434-437`) is exactly the plaintext BurnValue of the caller's DERO payload (`blockchain/transaction_execute.go:305-308`, `dvm/sc.go:209-215`). "Wallet W holds X" becomes "SIGNER W locked X in this contract until height H": `STORE("lock_"+SIGNER(), X)`, `STORE("until_"+SIGNER(), BLOCK_HEIGHT()+L)`, and Withdraw refuses before that height. SIGNER requires ring size 2 (`blockchain/transaction_execute.go:447`), so the depositor's identity is public by construction.
- **Time primitives** are only `BLOCK_HEIGHT()` and `BLOCK_TIMESTAMP()`. There are no timers or callbacks: someone must send a tx for anything to happen. Height is the safer clock. The timestamp is chosen by the block's builder within bounds: at most 50 ms ahead of the validating node's clock (`blockchain/blockchain.go:529-534`), and strictly greater than the parent's (`:536-540`).
- **Sybil neutrality of stake.** Weight proportional to locked DERO makes splitting across addresses useless. Any per-address cap or per-address stipend is Sybil-circumventable (NO-GO N8, `artifacts/dero-game-theory-rft.md:278-279`).

---

## 4. Mining identity

- **Miniblock layout** (CONFIRMED, `block/miniblock.go:41-57`): Version/HighDiff/Final/PastCount, Timestamp (uint16), Height, Past[2], **KeyHash (16 bytes)**, Flags, Nonce[3]. Serialized KeyHash is `[:16]` (`:166`, `:209`).
  - A **regular** miniblock has `KeyHash = graviton.Sum(miner compressed key)` (`blockchain/miner_block.go:364-366`). graviton.Sum is **BLAKE2s-256** (`vendor/github.com/deroproject/graviton/hash.go:18-19`).
  - The **final** miniblock has `KeyHash = sha3(header)`, the integrity tag (`blockchain/miner_block.go:367-373`; checked at `blockchain/miniblocks_consensus.go:32-49`). The final's hasher is therefore anonymous on chain.
  - **Consensus rules:** exactly 10 miniblocks (`blockchain/miniblocks_consensus.go:80-83`), ≥1 final (`:69-78`), and 9 in the collection above height 399,000 (`:120-125`). Every non-final miniblock's key must be registered (`blockchain/blockchain.go:595-601`; insert check `blockchain/miniblocks_consensus.go:131-138`). PoW is verified per miniblock (`blockchain/blockchain.go:604-610`).
- **Reward split** (CONFIRMED, `blockchain/transaction_execute.go:126-160`):
  - `full = CalcBlockReward(h) + fees`; `share = full / len(MiniBlocks)`; `leftover = full - share·len` (`:126-134`).
  - The integrator (`Miner_TX.MinerAddress`) gets `share + leftover` (`:136-144`).
  - Each non-final miniblock's key, resolved by KeyHash prefix in the balance tree, gets `share` (`:146-160`; the final is skipped at `:148-150`).
  - Side blocks get nothing (`blockchain/blockchain.go:984-986`).
  - Harness mirror: `glue/emission/emission.go:108-118`.
- **Off-chain check that "address A mined k miniblocks in heights [a, b]"** (deterministic on settled heights):
  1. Compute `kh = BLAKE2s(A.compressed)[:16]`.
  2. For each main-chain height (`sideblock == false`, `rpc/daemon_rpc.go:35`), count the non-final miniblocks with KeyHash == kh (`GetBlock` / `GetMiniBlocks` keyhash, `cmd/derod/rpc/rpc_dero_explorer.go:391`). Alternatively compare `miners[0..8]` with A's address string (`cmd/derod/rpc/blockheader.go:99`, `:113-118`).
  3. Integrator wins are `miners[9]` (`:120-122`).
  4. Payout per miniblock = `share` above.

  This is exactly what an M1 bonded claim attests (`artifacts/dero-game-theory-rft.md:186-189`).
- **Can SIGNER be tied to the miner key?**
  - **Off-chain: yes.** SIGNER is the same 33-byte compressed key (`blockchain/transaction_execute.go:451`) whose BLAKE2s prefix is the miniblock KeyHash (`blockchain/miner_block.go:365`). A verifier applies BLAKE2s to the SIGNER that the contract stored.
  - **In-contract: no.** The DVM has SHA256, SHA3-256 and Keccak256 but no BLAKE2s (`dvm/dvm_functions.go:85-87`). It also cannot read miniblocks (`dvm/dvm.go:394-402`).
  - **What the contract can enforce:** "the claimant IS the key", via ring-2 SIGNER. It then stores `HEX(SIGNER())` so that the off-chain verifier's claim is bound to that key. Nobody can claim someone else's miniblocks without being their SIGNER.
  - **The integrator role** (final share + leftover) can also be bound off-chain, through `Miner_TX.MinerAddress` (`blockchain/transaction_execute.go:137`).

---

## 5. Peer attacks: what the node already does, and what a watchtower could attest

### 5.1 Node-side detection and limits (CONFIRMED)
- **Finality / reorg depth:**
  - `STABLE_LIMIT = 8` (`config/config.go:79`). Blocks more than 8 heights below the tip are refused (`blockchain/blockchain.go:484-487`), as are blocks more than 2 above the tip (`:480-482`). Stable height = height − 8 (`:1199-1202`), and the sync-block rule is at `:1584-1587`.
  - The r23 `final_height` is derived from these rules (`cmd/derod/rpc/rpc_dero_gettxstatus.go:89-97`).
  - A reorg monitor compares the last 32 topoheights at each block (`cmd/derod/rpc/reorg_events.go:12-24`, `:38`) and counts finality violations. The count is published in GetMonetaryIntegrity `finality` (`cmd/derod/rpc/monetary_integrity.go:101`, `:112`).
- **Block rules:** timestamps at most 50 ms in the future (`blockchain/blockchain.go:529-534`); monotonic (`:536-540`); a single tip only (`:490-492`); miniblock PoW (`:604-610`); registered miner keys (`:595-601`); miniblock count (`blockchain/miniblocks_consensus.go:80-125`); registration PoW (`blockchain/blockchain.go:716-718`).
- **P2P scoring:**
  - A ban at score 100, with a 10-minute half-life; bans last 600 s, doubling up to 24 h (`p2p/penalty.go:39-42`).
  - Points per fault: invalid_pow 50, invalid_pow_miniblock 25, undecodable 50, malformed 20, timeout 10, busy 2, invalid_tx 25 (`p2p/penalty.go:45-57`).
  - Ban API: `p2p/bans.go:424-430`.
  - Eclipse diversity: ≤2 outbound per /16 (IPv4) or /32 (IPv6), ≤8 grey entries per netgroup, ≤1024 grey in total (`p2p/diversity.go:38-40`).
  - Grey peers are dropped at FailCount ≥ 8 (`p2p/peer_pool.go:124-126`).
- **Harness observatories:**
  - `harness/intel/consensus_intel.py`, detectors D01–D20 (`:885-1204`): timestamp monotonic/future, difficulty rule/jump, final bursts, late release, invalid objects, fork fingerprint, v2 remnant, final-vs-regular, cadence, collective final, alt blocks. Its design is described at `:1-40`.
  - `harness/intel/peer_intel.py` (`:1-30`): pseudonymised peer health, bans, first-relay, diversity.

### 5.2 Signals a contract-paid watchtower can attest deterministically
Rule: an attestation is fair only if every honest full node computes the same answer, so a Schelling or commit-reveal jury converges on the truth.

**Deterministic** (main chain at or below `final_height`, above the pruned floor):
- the block hash / topoheight / miner-keys digest (audit task 1)
- the emission digest (audit task 2)
- timestamp monotonicity
- the difficulty recomputed from tips (D05 rule)
- miniblocks per block
- the miner and integrator share counts (concentration, Nakamoto coefficient)
- a weak-PoW registration included in a block (B182, `blockchain/blockchain.go:717`)
- the plaintext burn and deposit totals (`glue/emission/emission.go:314-395`)

**Not deterministic** (node-local; a jury would reward guessing): peer tables, ban lists, latency and arrival order (which decides orphaning, `blockchain/miner_block.go:336-341`), side/alt blocks received, clock skew, mempool contents, the GetMonetaryIntegrity finality counters.

**What a contract adds:** it pays for detection and disclosure. It cannot ban a peer, change the rules or prevent a reorg (`gametheory/research/r32a_security_inventory.md:41-62`, "NO" column).

---

## 6. gt_audit.bas: where collusion and Sybil auditors win, and what is fixable within DVM limits

### 6.1 Exact win points (CONFIRMED by reading `gametheory/contracts/gt_audit.bas`)
1. **A Sybil majority overrides a correct sponsor and strips the honest minority.**
   - `Settle` takes any answer held by a strict majority of revealers (`:184`, `2 * c > nr`).
   - A majority answer different from the sponsor's sets `disp = 1` and wins (`:320-333` → `:360`).
   - The correct minority, which matches the sponsor, gets `cr = 0` (`:520-530`), and its bonds go to forfeit (`:560-565`).
   - Net effect: the colluders take the whole bounty plus the honest bonds (via carry into the next Post, `:600`, `:81-83`).
2. **Withheld sponsor plus a Sybil majority.** With no sponsor reveal (`hs == 0`) and any majority, the majority wins (`:320` → `:360`).
3. **The sponsor's own Sybils.**
   - Only the owner's exact address is excluded (`:98`). One entry per SIGNER (`:104`) is trivially bypassed with more registered keys. Registration costs only PoW, with no fee: `blockchain/transaction_execute.go:173-202` (returns 0 fees), and `blockchain/blockchain.go:717-718`.
   - The sponsor knows its own answer, so its Sybils always win. Through the equal split (`:445`), the sponsor recovers `k / (k + h)` of its own bounty.
   - This is honest-answer-preserving but payment-diluting. It is stated as NOT prevented at `:21-22`.
4. **Slot squatting.** Entry is first-come up to `maxn` (`:100-103`; maxn ≤ 32 at `:50`, default 16 at `:39`). A Sybil can fill every slot during the commit window and lock honest auditors out. The cost is n bonds, refunded if they reveal the sponsor's answer.
5. **Last-revealer option.** Reveals are public during the reveal window (`:143-148`). A party that committed different answers from different addresses can wait and reveal only the subset that forms a strict majority. It forfeits the bonds of the unrevealed addresses (`:560-565`), and those bonds go to carry (`:600`), which the same party can win back in the next round.
6. **Lazy copying through collusion.** The address-bound commit (`:146`) stops copying of commits, but not off-chain sharing of the answer between colluders (`:21`).
7. **Equal, not stake-weighted, votes.** Every entrant posts the same bond (`:101`) and gets one vote (`:167`, `:181`), so voting weight scales with the number of addresses.
8. **Gas-griefing lock-up (ESTIMATE, not executed; this is new).**
   - The majority search in `Settle` is O(n²): the outer loop is `:180-285` and the inner loop `:240-266`. It stops early only when a strict majority is found (`:270`).
   - Per inner iteration: ≥5 lines × 5000 gas (`dvm/dvm.go:522`), 2 LOADs × 5000 and 2 ITOAs × 5000 (`dvm/dvm_functions.go:59`, `:84`), plus about 6 binary expressions × 800 (`dvm/dvm.go:994`). That is about 50k gas, against a 10M fixed limit (`dvm/sc.go:241`), or roughly 200 inner iterations.
   - Lines grow by about 5n² + 14n, against the 2000-line limit (`dvm/dvm.go:71`, `:503`, `:535`).
   - With about 13 or more revealed entrants and no strict majority, or with many non-majority entrants placed at low indices, `Settle` would always run out of gas ("Insufficient Gas", `dvm/dvm.go:443`). It would revert every time. `Withdraw` requires `st == 1` (`:254`), so the **bounty and every bond would be locked permanently**. With maxn = 32 and no majority, the line limit alone is exceeded (5·32² > 2000).
   - Who can trigger it: anyone with about n/2 bonded Sybil entries using distinct answers, or simply an honest disagreement in a large round.
   - The existing tests settle rounds of ≤ 2–3 entrants only (`dvm/r32a_audit_test.go:101-104`, `:284`, `:307`). There is no KAT at maxn. **Needs a simulator KAT before any mainnet round with more than a few entrants.**
9. **Anonymous entrants.** `IS_ADDRESS_VALID(SIGNER())` (`:97`) is the guard against a zero signer. UNCONFIRMED whether 33 zero bytes fail `DecodeCompressed` (bn256 flag handling is lax per rft B297). Either way, a failed anonymous call destroys its deposit (`blockchain/transaction_execute.go:286-289`).

### 6.2 Changes possible within DVM limits

| change | DVM feasibility | effect / residual |
|---|---|---|
| **O(n) tally.** At Reveal, `STORE(p+"cnt_"+answer, cnt+1)` and keep a running `p+"best"`/`p+"bestc"`; Settle then makes one pass over n for credits. | Feasible with LOAD/STORE only; storage about 100 B per reveal (`dvm/dvm_store.go:133`, cap `config/config.go:46`). Settle cost becomes O(n). | Removes the gas lock-up in 6.1 item 8. **Highest priority.** |
| **Stake-weighted votes and bonds.** Variable bond ≥ min; weight = bond; majority by Σ bond. | Feasible (DEROVALUE, `dvm/dvm_functions.go:434`). | Sybil splitting gains nothing. Collusion still wins if the colluders hold more than half the stake: an economic bound, not a prevention. |
| **Sponsor primacy plus a supermajority to override.** Override only if ≥ 2/3 of the revealed stake and ≥ K revealers disagree; otherwise the sponsor's answer stands and dissenters forfeit. | Feasible. | Removes cheap overrides of a correct sponsor (6.1 item 1). It strengthens a lying sponsor, so pair it with a sponsor bond and an appeal. |
| **Sponsor bond, slashed on dispute.** Post requires `DEROVALUE() ≥ bounty + sbond`; when `disp = 1` the sponsor bond goes to the majority. | Feasible. | Makes a lying or withholding sponsor pay. |
| **Appeal/escalation.** A losing side may re-open within W blocks by doubling the bond; the new round has more seats and a larger quorum; final after R rounds. | Feasible (height windows only). | Bribery cost rises geometrically (Kleros-style). Still a Schelling vote: residual collusion risk stated. |
| **"Provably wrong" slashing.** | Feasible ONLY for tasks whose answer the contract can compute itself. The DVM cannot read headers or rewards (§2.2), so for tasks 1–2 "wrong" can only mean "against the final majority". | Hard limit (§7). |
| **Random seat selection.** Over-subscribe entries, then draw `maxn` seats. | `RANDOM` is keyed by (SCID, BLID, TXID) (`dvm/deterministic_random_number.go:36-41`). BLID is the hash of the whole block including miniblocks (`block/block.go:57-67`): the integrator chooses the tx set and can withhold the block, and the final-miniblock hasher can discard solutions. TXID is chosen by the caller. **Grindable by the block producer, at the cost of forgoing its share** (D-GT-10, `artifacts/dero-game-theory-rft.md:92`; rft §4 item 6 `:205-206`). Use instead a seed built from commit-reveal secrets of the entrants, revealed after the commit closes, as gt_prize v2 does, with forfeit for non-reveal. | Removes slot squatting by first-come (6.1 item 4) without integrator grinding. The last-revealer still has a one-bit withhold option, priced by its bond. |
| **Minimum distinct registered addresses.** | Feasible to count (EXISTS on `p+"in"+SIGNER()`, `:104`). | Not Sybil resistance: addresses cost only registration PoW (`blockchain/blockchain.go:717-718`). Useful only as a liveness quorum. |
| **Caps per address or per round.** | Feasible. | Circumventable by splitting; only stake weighting is split-neutral. |
| **Hide the tally until settle.** | Not possible: all tx args and stored state are public (`rpc/daemon_rpc.go:235`, `:245-246`). | The last-revealer option can only be priced through bonds. |

---

## 7. Hard limits (no contract can do these)

1. **Raise, redirect or see the block reward, or see the miner/integrator.** `Blockchain_Input` has only SCID, BLID, TXID, Signer, BL_HEIGHT, BL_TOPOHEIGHT, BL_TIMESTAMP (`dvm/dvm.go:394-402`). The split is in consensus (`blockchain/transaction_execute.go:126-160`).
2. **Read any previous block, header, difficulty, reward, tx count, miniblock or side block.** Only the current BLID, height and timestamp are exposed (`dvm/dvm_functions.go:275-305`); topoheight is not exposed (`:294-301`).
3. **Read any wallet balance, or even its own total balance.** Balances are ElGamal ciphertexts (`blockchain/transaction_execute.go:238-241`), and there is no balance builtin (`dvm/dvm_functions.go:57-95`).
4. **Compute the miniblock KeyHash from SIGNER.** It needs BLAKE2s (`vendor/github.com/deroproject/graviton/hash.go:18-19`), which is not in the DVM (`dvm/dvm_functions.go:85-87`).
5. **Know SIGNER for ring size > 2.** `Extract_signer` requires ring size 2 (`blockchain/transaction_execute.go:447`). Anonymous calls see zeros, and a failing anonymous call loses its deposit (`:286-289`).
6. **Lower any reported supply figure.** `CalcSupply` is a formula (`blockchain/supply.go:5-26`; `cmd/derod/rpc/rpc_dero_getinfo.go:83`).
7. **Prove that a registered address is unspendable.** Registration needs the key's signature (`transaction/transaction.go:257-277`).
8. **Read or call another contract.** Storage is keyed by own SCID (`dvm/dvm_functions.go:123`); cross-SC calls are not enabled (`dvm/dvm.go:410-411`).
9. **Act without a tx.** There are no timers. Height/time are checked only when someone calls (`dvm/dvm_functions.go:289-305`).
10. **Get unbiasable in-block randomness.** RANDOM = f(SCID, BLID, TXID) (`dvm/deterministic_random_number.go:36-41`), and BLID is the producer-chosen block hash (`block/block.go:57-58`).
11. **Exceed 10M compute gas, 2000 lines, 11,000 evals or about 20,000 storage gas per call** (`dvm/sc.go:241`, `dvm/dvm.go:71-72`, `config/config.go:46`).
12. **Witness a reorg of its own state, or ban or score a peer.** Contract state is committed with the block (`blockchain/blockchain.go:1033-1074`). Peer policy is node-local (`p2p/penalty.go:39-57`, `p2p/diversity.go:38`).
13. **Verify an off-chain fact in-contract** (header digest, emission, miner count). It can only bind a bonded claim to a SIGNER and settle by commit-reveal majority (`gametheory/contracts/gt_audit.bas:146`, `:184`).
14. **Rely on SEND to an unregistered key as a burn.** The burn is order-dependent: refunded when it is the last transfer, burned otherwise (`dvm/simulator.go:236-247`; `dvm/r23_external_transfer_test.go:20-28`). The behaviour is a REPORT-ONLY quirk that a fix would change.

## 8. Possible within limits

1. **A verifiable no-exit or time-lock DERO vault as the deflation primitive.** Deposits come via DEROVALUE (`dvm/sc.go:209-215`). There is no SEND and no UPDATE_SC_CODE in the code (`dvm/dvm_functions.go:312-322`, `:377-397`). It is checked by `GetSC` balance and code at any topoheight (`cmd/derod/rpc/rpc_dero_getsc.go:94-97`; `rpc/daemon_rpc.go:232-249`) and summed by `GetSupplyAudit` (`cmd/derod/rpc/rpc_dero_getsupplyaudit.go:5-11`).
2. **An on-chain burn ledger** (`burned`, `burned_by_<signer>`) kept by the contract from DEROVALUE and readable via GetSC stringkeys (`rpc/daemon_rpc.go:245`).
3. **Own-token mint and burn with public counters.** Unlimited mint (`dvm/simulator.go:210-211`); burn by deposit via ASSETVALUE(SCID()) (`dvm/dvm_functions.go:440-455`). Do not trust the wrapped own-token balance key (`dvm/simulator.go:223`).
4. **Stake as a deposit-lock.** `SIGNER` (ring 2) plus `DEROVALUE` plus `BLOCK_HEIGHT` unlock (`dvm/dvm_functions.go:289-292`, `:307-310`, `:434-437`). Weight proportional to stake is Sybil-split-neutral.
5. **Bind claims to the miner key.** Store `SIGNER()` (33 bytes, `blockchain/transaction_execute.go:451`); verifiers check BLAKE2s(SIGNER)[:16] against miniblock KeyHash (`blockchain/miner_block.go:365-366`) and price each miniblock by `share` (`blockchain/transaction_execute.go:133`, `:157`).
6. **Self-record the executing block** with `STORE(BLOCK_HEIGHT(), BLID())` (`dvm/dvm_functions.go:275-292`), giving a public sample of main-chain block ids for watchtowers to cross-check.
7. **Bonded commit-reveal attestations over deterministic, settled data:** audit tasks 1–2 (`harness/gametheory/audit_tasks.py:10-17`, `SETTLE` `:33`). The deterministic signal list is in §5.2.
8. **gt_audit v2, with every element built only on the primitives above:**
   - O(n) per-answer counters (fixes the n² gas lock-up at `gametheory/contracts/gt_audit.bas:180-285`)
   - stake-weighted votes
   - a sponsor bond
   - a supermajority to override (`:184`, `:320-360`)
   - an appeal window with doubling bonds
   - seat draw from an entrants' commit-reveal seed instead of RANDOM (`dvm/deterministic_random_number.go:36-41`)
9. **Pull payments to SIGNER only**, as in gt_audit `Withdraw` (`gametheory/contracts/gt_audit.bas:249-264`). This avoids the D4 unregistered-destination footgun, because the payee is a ring-2 signer and therefore registered.
