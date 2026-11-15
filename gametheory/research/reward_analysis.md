# R32: DERO HE block rewards, miniblocks and the "DAG": code-grounded analysis and a live measurement

Base: local-enhancements 5f69b055, branch `r32-reward`. All file:line references are repo-relative and are
machine-checked by `python3 -I harness/gametheory/reward_intel.py --check` (59 anchors, 59 OK, 0 MOVED, 0 DRIFT on
2026-11-15). Amounts are in atomic units; 1 DERO = 100000 atomic.

Evidence files:
- `harness/runtime/gt_reward_live.json`: the canonical live run. 60 main-chain blocks, topo 7,905,215..7,905,274,
  measured 2026-11-15T09:18:49Z, node `3.6.0-153.DEROHE.STARGATE+22102026.r31`, tip block age 15.4 s, 160 read-only
  RPC calls on 127.0.0.1:10102. It also has the node's 32 settled alt (side) blocks.
- `$SCR/reward/gt_reward_live_2000.json` (scratch only, 1.25 MB, not committed): 2,000 blocks, topo 7,903,244..7,905,243,
  09:08:39Z, headers only (`--no-mbl`, 23 calls), run before the side-block sampler existed.
- `blockchain/r32_reward_split_test.go`: 9 Go tests that call the real functions. All PASS.
- `harness/kat/test_gt_reward_r32.py`: 7 KATs and 17 mutations, 17 of them proved.

---------------------------------------------------------------------------------------------------------------------

## 1. The formulas, with their code locations

### 1.1 Emission

| # | formula | code |
|---|---|---|
| RW01 | `BLOCK_TIME = 18` s (target) | config/config.go:34 |
| RW04 | `RewardReductionInterval = 210000*600/18 = 7,000,000` blocks | blockchain/transaction_execute.go:44 |
| RW05 | `BaseReward = 41*100000*18/600 = 123,000` | blockchain/transaction_execute.go:45 |
| RW06 | `CalcBlockReward(h) = 123000 >> floor((h + 7e6)/7e6)` | blockchain/transaction_execute.go:61 |

The `+ RRI` term skips Bitcoin's first epoch, so the HE chain starts at the second-epoch rate:
- below h 7,000,000 the reward is 61,500 (0.615 DERO);
- from 7,000,000 to 13,999,999 it is **30,750 (0.3075 DERO), the current rate**;
- from 14,000,000 it is 15,375, then 7,687, and so on.

The reward depends only on the height. No hard fork changes it. HF2 (481,600, config/config.go:109) and HF3
(7,504,640, config/config.go:110) touch neither `CalcBlockReward` nor `Calculate_TX_fee`. The fee function takes a
hard-fork argument and never reads it (blockchain/tx_fees.go:35). `TestR32_CalcBlockReward` and
`TestR32_FeeFloor` pin both facts.

Next halving: 14,000,000 − 7,905,274 = 6,094,726 blocks. That is 3.48 years at the 18 s target, or 3.58 years at
the 18.54 s mean measured over 2,000 blocks.

### 1.2 Supply

- **Premine:** `PREMINE = 1,228,125,400,000` (12,281,254 DERO), the old chain's supply (config/config.go:61).
- **Supply formula:** `CalcSupply(h) = PREMINE + 271,739,600 + Σ_epochs CalcBlockReward(epoch_start)·blocks`
  (blockchain/supply.go:6, :9, :19). The 271,739,600 term is 1,358,698 early registrations × 200 atomic. That grant
  is real code: transaction_execute.go:194, mainnet, height < 144,000.
- **What GetInfo reports:** `total_supply = CalcSupply(height)/100000`, in whole DERO
  (cmd/derod/rpc/rpc_dero_getinfo.go:83-84). It is computed from the formula; it does not count coins.
- **Live check:** at topo 7,905,274 GetInfo said 16,867,343, and the formula from the anchored constants gives
  the same value (match = true).
- **Hard cap (derived, not measured):** with the integer shifts, total issuance reaches
  2,089,341,139,600 atomic = **20,893,411.396 DERO** when `123000 >> k` reaches 0 (k = 17). At h 14,000,000 the
  supply is 1,874,147,139,600.

### 1.3 Miniblocks and the split of one block's reward

| # | rule | code |
|---|---|---|
| RW19 | exactly `BLOCK_TIME − MINIBLOCK_HIGHDIFF + 1 = 10` miniblocks per block | blockchain/miniblocks_consensus.go:80 |
| RW20/21 | ≥ 1 final, and from h 399,000 exactly 9 non-final, so exactly 1 final | miniblocks_consensus.go:75, :120 |
| RW23 | the template is a normal job while fewer than 9 normal miniblocks exist, then a final job. A final's KeyHash is the block-header hash, not a miner key | blockchain/miner_block.go:364 (366-371) |
| RW28 | final PoW target = `9 × D` | blockchain/difficulty.go:173 |
| RW13 | `full = CalcBlockReward(h) + fees_collected` | transaction_execute.go:127 |
| RW14 | `share = full / len(MiniBlocks)` (integer, /10) | transaction_execute.go:133 |
| RW15 | `leftover = full − 10·share` | transaction_execute.go:134 |
| RW16 | integrator (`Miner_TX.MinerAddress`) gets `share + leftover` | transaction_execute.go:142 |
| RW17/18 | the final miniblock is skipped. Each normal miniblock pays its KeyHash owner one share, so a key with k miniblocks in a block gets k shares | transaction_execute.go:148, :151 |
| RW29 | a normal miniblock from an unregistered key makes the block invalid | blockchain/blockchain.go:598 |
| RW22 | the template keeps only the first 9 normal miniblocks it holds for (height, tip), in arrival order at the integrating node. The rest earn nothing | miner_block.go:338 (key: :329-331, block/miniblockdag.go:98) |

The integrator is the address in the miner tx of the template, `Create_new_miner_block(chain.integrator_address)`
(miner_block.go:401, :307). Its default is `--integrator-address`, otherwise `globals.Config.Dev_Address`
(blockchain/blockchain.go:126, config/config.go:96).

The Go tests check these balances by decrypting the ElGamal balances:

| test | inputs | result |
|---|---|---|
| `TestR32_SplitNoFees` | h 7,905,240, fees 0 | 9 miners × 3,075 + integrator 3,075 = 30,750 |
| `TestR32_SplitFeesLeftoverToIntegrator` | fees 37 | full 30,787, share 3,078, leftover 7, integrator 3,085; one key with 9 miniblocks gets 9 × 3,078 |
| `TestR32_IntegratorAlsoMines` | fees 120 | the integrator key also mined 3 normals and gets 4 × 3,087 |
| `TestR32_SplitPreHF2Era` | h 100,000, 2 finals (allowed only below 399,000) | credited = 61,500 − 6,150. One share is never credited, the r25 B22 window, pinned as code behaviour |

### 1.4 Fees

| # | rule | code |
|---|---|---|
| RW36/37 | `min_fee(size) = ceil(size/1024) × FEE_PER_KB` with `FEE_PER_KB = 20` (0.0002 DERO/KB) | config/config.go:49, blockchain/tx_fees.go:42 |
| RW38 | a block holding a tx below its floor is rejected | blockchain.go:892 |
| RW39 | `tx.Fees()` = sum of the zero-SCID payload statement fees | transaction/transaction.go:230 |
| RW30 | the fees of every tx executed in the block are summed into `fees_collected` | blockchain.go:1028 |
| RW13-16 | fees are split exactly like the base reward: /10, the leftover to the integrator | — |
| RW12 | a registration pays no fee (the function returns 0) | transaction_execute.go:202 |
| RW57 | burned value is credited to nobody | transaction_execute.go:204 |

### 1.5 Smart-contract gas and fees

- **The miner always gets the full fee.** `process_transaction_sc` presets its named return `gas = tx.Fees()`
  (transaction_execute.go:271). Every exit returns that value: success (:436), the error/revert path, and the panic
  recover. `fees_collected += tx_fees` is applied whatever the error (blockchain.go:1021-1028), so unused gas is
  never refunded.
- **Gas limits.** The compute-gas limit is a fixed 10,000,000 per call (dvm/sc.go:238). The storage-gas limit is
  `min(tx.Fees(), MAX_STORAGE_GAS_ATOMIC_UNITS = 20000)` (dvm/sc.go:246, :249; config/config.go:46).
- **Gas does not set the fee.** `DERO.GetGasEstimate` runs the simulator with fee 0 and reports gas only
  (cmd/derod/rpc/rpc_dero_estimategas.go:74, :78). The fee itself is the size floor or more.

### 1.6 Registration

- It pays no fee and credits a zero balance (plus 200 atomic below h 144,000 on mainnet).
- It needs txid proof of work. A block refuses it iff `tx_hash[0] != 0 && tx_hash[1] != 0` (blockchain.go:717). The
  pool demands 3 zero bytes (blockchain.go:1255).
- A key must be registered before its normal miniblocks are valid (RW29). The final miniblock needs no key.

### 1.7 Difficulty

`D_next = D_tip × floor(e^((1 − s/18000)/8) × 10000) / 10000` (difficulty.go:118-119 `DiffBig`, called at :252),
where:
- `s = min(ts_tip − ts_parent, 36000)` (difficulty.go:247);
- the damping constant is `M = 8` (difficulty.go:251);
- the floor is `D ≥ 100000` (difficulty.go:254).

Only the **last** solve time counts, so this is a one-block exponential controller. Timestamps are bounded at
blockchain.go:529 (≤ now + 50 ms) and :539 (> the parent's).

**Live:** the Python port predicted every block's difficulty from its two predecessors with no misses: 60 of 60
(canonical run) and 2,000 of 2,000 (wide sample). `TestR32_DifficultyLiveTriple` pins one live triple in Go:
2,074,825 → 2,165,702 → 2,325,314 at 7,905,190..192.

### 1.8 Side blocks and the "DAG"

- **The chain is linear.** A block with more than 1 tip is rejected (blockchain.go:491), so topoheight == height.
- **A side block is a block with no topological order** (`Isblock_SideBlock`, blockchain.go:1376). Each block
  commits its own state version, built on its parent's snapshot. Only the winning chain's blocks are written into
  the topo index (blockchain.go:1089), and only topo-indexed versions are the chain state. So a side block's coinbase
  and txs never reach the main state. The code says so: "side blocks ... donot get any reward, 0 reward"
  (blockchain.go:985).
- **The RPC header `reward` field is misleading for side blocks.** It is just `CalcBlockReward(height)`
  (cmd/derod/rpc/blockheader.go:50). Live, all 32 side blocks still show `reward 30750` with topoheight −1.

---------------------------------------------------------------------------------------------------------------------

## 2. What the live sample showed

All 60 blocks are main chain with 10 slots, 10 miniblocks and exactly 1 final at index 9. Every block's tip links
to the previous one.

| quantity | canonical 60 blocks | wide 2,000 blocks |
|---|---|---|
| RPC `reward` == formula | 60/60 (30,750) | 2000/2000 (30,750) |
| difficulty predicted exactly | 60/60 | 2000/2000 |
| block interval mean / median / max (ms) | 17,874 / 16,717 / 40,390 | 18,543 / 16,023 / 95,476 |
| blocks with fees / fees total | 0 / 0 | 8 / 1,760 (fees = 0.0029 % of rewards) |
| leftover credited to integrators | 0 | 0 |
| distinct normal-miner keys per block mean (min–max) | 6.03 (4–8) | 6.17 (3–9) |
| distinct normal-miner keys in the sample | 22 | 32 |
| top-1 / top-5 key share of normal miniblocks | 20.0 % / 67.2 % | 18.4 % / 61.0 % |
| distinct integrators | 12 | 21 |
| blocks paying the default Dev_Address integrator | 1 (1.7 %) | 6 (0.3 %) |
| blocks whose integrator also mined a normal miniblock | 16 (27 %) | 672 (33.6 %) |
| 9th normal → block ("final phase") mean | 7,864 ms | (not read) |
| 1st → 9th normal span mean | 8,394 ms | (not read) |
| GetInfo total_supply == formula | yes (16,867,343) | yes |

The phase times are template stamps (`ms_before_block`), not find times.

**Side blocks** (GetConsensusStats `alt_blocks`, heights ≥ 7,903,739, settle depth 8):
- 32 alt blocks out of 1,560 settled = **2.05 %**. None were mined locally.
- All 32 have `sideblock = true` and topoheight −1.
- They held 288 normal miniblocks. **286 of them (99.3 %) are also in the winning block at the same height**; only
  2 were lost.
- None of the 32 side-block finals is in the winning block.

Why the miniblocks survive: a miniblock commits to (height, tip `Past[0]`), not to a block (miner_block.go:329-331,
block/miniblockdag.go:98). Two competing blocks at one height share the parent, so both integrators draw from the
same miniblock pool.

Fees are always multiples of 10 at the floor, so the leftover is 0. Both `FEE_PER_KB = 20` and the base reward
30,750 are divisible by 10, so `share` divides exactly unless a wallet pays a fee that is not a multiple of 10.

---------------------------------------------------------------------------------------------------------------------

## 3. Game-theoretic implications for miners

1. **Value of one miniblock.** A normal miniblock currently pays 3,075 + fees/10 atomic (≈ 0.03075 DERO) at
   difficulty D. The final pays the same share, plus the leftover, to the **integrator** at 9D. A final miniblock
   found through someone else's node pays the hasher nothing: its KeyHash is the header hash (RW23).
   - Per hash, final-phase work earns 1/9 of normal-phase work, and only for the integrator's operator.
   - About half of the expected work per block, 9D of 18D, is final-phase work (RW03, RW28).
   - The live final phase averaged 7.9 s of a 17.9 s block.
   - So a solo miner should run its own node with `--integrator-address` set to its own address. Without it, the
     integrator share goes to the Dev_Address (blockchain.go:126). Live, 0.3–1.7 % of blocks still pay the default.
2. **Expected income.** A miner with fraction f of the network's normal-phase hashrate gets 9f normal miniblocks
   per block in expectation.
   - At 4,659.5 blocks/day (the measured 18.54 s mean), that is ≈ f × 1,289.5 DERO/day from normal miniblocks.
   - Being its own integrator adds up to f_final × 143.3 DERO/day.
   - Network emission ≈ 1,432.8 DERO/day.
   - These are derived from the formulas and the measured interval, not observed balances. Balances are encrypted.
3. **Variance.** There are 10 payouts per block, so a day has ≈ 41,936 normal slots. A 1 % miner expects 419 ± 20
   miniblocks a day (coefficient of variation 4.9 %). Paying one winner per block would give a coefficient of
   variation about 3 times larger.
   - Live concentration: the top key took 18–20 % of normal miniblocks and the top 5 took 61–67 %.
   - A block has 6 distinct keys on average, so 9 slots are shared by a handful of large miners.
4. **Latency is the lever, not orphans.**
   - Only the first 9 normal miniblocks that the integrating node holds for a tip are paid (RW22). Extra
     miniblocks, and those that arrive late, earn nothing.
   - The orphan (side-block) rate is 2.05 %, but normal miniblocks of side blocks are almost always (99.3 %) reused
     by the winning block. A normal miner's measured orphan loss is ≈ 2/(1,560 × 9) ≈ 0.014 % of slots.
   - The orphan cost falls almost entirely on the losing **integrator**. It loses its share and leftover, about 2 %
     of an integrator's income.
   - This refines the earlier note that orphans cost about 2.7 % to p2p latency. That cost is the integrator's, not
     the normal miner's.
5. **The integrator chooses the transactions; normal miners cannot.** A miniblock commits only to the tip and the
   height. Including txs earns the integrator fee/10, the same as every normal miner, plus a leftover that is 0 at
   floor fees. The incentive to include txs is therefore weak but positive: fees are 0.003 % of rewards. The real
   cost is block size and propagation, which raise orphan risk for the integrator.
6. **Difficulty and timestamp games.** Because only the last solve time counts, one integrator can **raise** the
   next difficulty. It does this by stamping its block early, which is allowed down to the parent's timestamp + 1
   (blockchain.go:539). The maximum is a factor of e^(1/8) ≈ 1.133.
   - It cannot **lower** difficulty by stamping late: the future limit is 50 ms (blockchain.go:529). Lowering takes
     real delay, and at most the 36 s clamp gives e^(−1/8) ≈ 0.882.
   - Raising difficulty hurts everyone, the integrator included, so it is not profitable alone. This is reasoning
     from the code; no such behaviour was measured.
7. **Registration** costs PoW grinding of the txid but no fee. A key must be registered before its normal
   miniblocks count (RW29).

## 4. What a smart contract can and cannot do to rewards

**It cannot:**
- Change the protocol reward. `CalcBlockReward` is a pure function of height (RW06).
- Change the coinbase split. `process_miner_transaction` reads only the block's miniblocks, the integrator address
  and `fees_collected` (RW13-RW18, RW32).
- Change the fee the miner receives. On every exit the SC path returns `tx.Fees()` (RW40, RW41); gas used does not
  change it.
- Mint DERO. Transfers out are checked against the SC's stored balance (`SanityCheckExternalTransfers`,
  dvm/simulator.go:202-230). Only the SC's own token (asset == SCID) can be minted without limit.
- Address the block's miner. None of the DVM functions exposes the miner or integrator (dvm/dvm_functions.go:
  `version load exists store delete mapexists mapget mapstore mapdelete random scid blid txid dero block_height
  block_timestamp signer update_sc_code is_address_valid address_raw address_string send_dero_to_address
  send_asset_to_address derovalue assetvalue atoi itoa hex hexdecode min max strlen substr panic`).

**It can:**
- Pay any address from its own balance, for example SIGNER, as a bounty.
- Burn the DERO sent to it; nobody receives burned value (RW57).
- Read BLOCK_HEIGHT, BLOCK_TIMESTAMP and BLID, and RANDOM. RANDOM is seeded with `Keccak256(SCID, BLID, TXID)`
  (dvm/deterministic_random_number.go:38, dvm/dvm.go:375), and the BLID passed is the executing block's hash
  (blockchain.go:1021).

That gives the final-miniblock finder and the integrator a **withholding option** on SC randomness. They can drop a
block whose BLID makes RANDOM unfavourable, at the cost of the 9D final work, the integrator share, and the risk
that a rival block wins. This is grounded in the code; whether it pays was not measured.

---------------------------------------------------------------------------------------------------------------------

## 5. Verified and unverified

**VERIFIED** in code and by test or live measurement:
- **Emission constants and `CalcBlockReward`.** Anchors RW04-06; Go `TestR32_RewardConstants` and
  `TestR32_CalcBlockReward`; KAT GR2; live 2,060/2,060 headers equal the formula.
- **`CalcSupply` and GetInfo total_supply.** Go `TestR32_CalcSupply`; live match at three tops (16,867,332, 340 and
  343).
- **The 10-way split, the leftover to the integrator, per-miniblock credit for repeat keys, and the integrator also
  mining.** The Go tests call the real `process_miner_transaction`.
- **Exactly 10 miniblocks with 1 final at index 9** in 60 of 60 live blocks.
- **The fee floor formula, with the hard-fork argument ignored.** Go `TestR32_FeeFloor`.
- **The difficulty formula.** Live 2,060/2,060 exact predictions; Go live triple.
- **Side-block facts.** The chain is linear (1 tip, every tip links to the previous block in 60/60). Side blocks have
  no topo order and `sideblock = true` (32/32). The alt rate is 2.05 %. 99.3 % of side-block normal miniblocks are
  reused by the winner; no side-block final is.
- **Integrator default = Dev_Address** (code). Live: 0.3–1.7 % of blocks pay it.
- **The SC fee always goes to the miner and SC code has no reward hook.** This is code reading: RW40/41, the DVM
  function list and `SanityCheckExternalTransfers`. r31 `r31_value_sites_test.go` already exercises the
  fee-return exits.

**UNVERIFIED** (stated as derived or reasoned, not measured):
- The DERO/day income figures and the variance numbers. They come from the formulas and the measured interval;
  balances are encrypted and were not observed.
- The phase times. `ms_before_block` is a reconstructed template stamp, not the find time.
- The side-block reward = 0 rests on the state-version and topo-index argument and the code comment. No balance
  was read to show the side integrator was not credited, because state is encrypted and per-version.
- Whether the timestamp/difficulty and RANDOM-withholding games are profitable is reasoning only; nothing was
  measured.
- That miners have no incentive to grind or skip txs beyond fee/10 depends on mempool behaviour, which was not
  measured. This sample's mempool was nearly empty: 10 txs in 2,000 blocks.
- The alt-block window (heights ≥ 7,903,739, about 1,560 blocks) is one node's view. Other nodes may see different
  alt sets.

## 6. Re-run

    python3 -I harness/gametheory/reward_intel.py --check
    python3 -I harness/gametheory/reward_intel.py --live --n 60          # ~160 calls, ~45 s, read-only, nice 15
    python3 -I harness/gametheory/reward_intel.py --json-only            # harness/runtime/gt_reward_static.json
    python3 -I harness/kat/test_gt_reward_r32.py                         # 7 KATs, 17 mutations
    nice -n 15 go test -p 1 ./blockchain -run R32 -count=1
