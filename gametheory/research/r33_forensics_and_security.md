# R33 forensics and security: what verified block facts can detect, and what no contract can see

Date: 2026-11-17. Builds on GT-B24/GT-B25 (verified block bytes in-contract) and `r33_block_proofs.md`. Code was read
at HEAD. Statistics were computed with exact binomial tails in a local script kept in a session scratch directory. No
RPC was used; the only chain data is the repo test vectors `dvm/testdata/r33_mainnet_blocks.json`. This file contains
no exploit detail for any soundness defect.

Labels are as in `r33_block_proofs.md`.

---

## 0. The verified facts a proven block yields in-contract (CODE, CONFIRMED by `TestR33BlockProofVerifiesRealMainnetBlocks`)

| fact | bytes | anchor | usable in-contract for |
|---|---|---|---|
| header timestamp (ms) | 2..9 | `block/block.go:111-112` | gaps, monotonicity, cadence |
| height | varint at 10 | `block/block.go:114-115` | binding h to the bytes |
| integrator key (33 B) | 18..50 (4-byte height varint) | `block/block.go:118`; `transaction/transaction.go:433-457` | integrator concentration; a direct `== SIGNER()` check |
| tip (parent id) | 32 B before the miniblock count | `block/block.go:122-127` | walking back to ancestors (`r33_block_proofs.md` §2.3) |
| 10 miniblocks: version/final bit, 16-bit ms timestamp, height, Past, KeyHash[:16], Flags | 48 B each | `block/miniblock.go:140-171` | miner (KeyHash) concentration, game tags, intra-block timing |
| tx count and tx ids | the tail | `block/block.go:140+` | activity; whether a given tx landed in this block |

**What the test vectors show (CONFIRMED, 4 blocks, 36 regular miniblocks).**
- 10 distinct KeyHashes.
- The largest KeyHash holds 8/36 = 22 %. The largest per block is 4/9 (height 7,915,142).
- All 40 miniblocks have Flags = 0.
- The final miniblock's 16-bit timestamp equals the header timestamp mod 2^16 to within 1 ms.
- The last regular miniblock precedes the final by 0.9 s, 16.5 s, 10.9 s and 8.4 s. The final carries 9× difficulty
  (`blockchain/difficulty.go:172-174`), so this is the expected pattern, not an anomaly.
- 7,915,142 and 7,915,143 share an integrator key.

---

## 1. Miner concentration: statistics and thresholds (DERIVED)

**The model.** The contract keeps, per epoch, the largest KeyHash count `km<e>` against the total `kn<e>` over proven
blocks (`gametheory/contracts/gt_pool.bas:165-180`). Under honest mining, a miner with true share p holds
`X ~ Binomial(n, p)` of n proven regular miniblocks.

**Table.** Probability that a miner of true share p reaches the alarm threshold t·n. An honest miner below t gives a
*false alarm*; a miner at or above t gives *detection*. Exact binomial tails:

| n (proven regular miniblocks) | t | p = 0.10 | 0.15 | 0.20 | 0.25 | 0.30 | 0.40 | 0.51 |
|---|---|---|---|---|---|---|---|---|
| 90 (10 blocks) | 0.30 | 1.2e-7 | 2.3e-4 | 0.016 | 0.16 | 0.54 | 0.98 | 1 |
| 90 | 0.40 | 7e-14 | 7.8e-9 | 1.1e-5 | 1.2e-3 | 0.027 | 0.54 | 0.99 |
| 360 (40 blocks) | 0.30 | 6e-26 | 4e-13 | 4.2e-6 | 0.018 | 0.52 | 1 | 1 |
| 360 | 0.40 | ≈0 | ≈0 | 3e-18 | 2.9e-10 | 3.4e-5 | 0.52 | 1 |
| 900 (100 blocks) | 0.30 | ≈0 | 3e-30 | 6.7e-13 | 3.8e-4 | 0.51 | 1 | 1 |
| 3,600 (full epoch) | 0.30 | ≈0 | ≈0 | 3e-46 | 6.3e-12 | 0.51 | 1 | 1 |
| 3,600 | 0.40 | 0 | ≈0 | ≈0 | 6.7e-87 | 1.9e-37 | 0.51 | 1 |

**Reading it.**
1. **Put the threshold below the share you want to catch.** At t = p, detection is only ~50 %.
2. **Recommended setting (DERIVED).** Alarm at t = 0.40 with n ≥ 360 (≥ 40 proven blocks). An honest top miner at
   25 % gives a false alarm of 2.9·10^-10 per epoch, and a 51 % KeyHash is caught with probability ≈ 1.
3. **Catching a 30 % miner.** At n = 3,600 use t = 0.27–0.28: an honest 20 % miner then has a false alarm ≈ 10^-30,
   and a 30 % miner is caught with probability > 0.9. That last figure is an ESTIMATE from the table's slope; recompute
   it in GT-B30.
4. **Union bound.** With M honest miners, the false-alarm rate is at most the sum of their tails, which is dominated by
   the largest.

**Honest limits.**
- **A KeyHash is not an entity.** Registration costs only a PoW (`blockchain/blockchain.go:716-718` per
  `r33_code_capabilities.md` §6.1, no fee). A 51 % miner that spreads its work over 6 keys of ≈ 8.5 % each never
  trips any KeyHash threshold. `km/kn` is a *lower bound* on concentration. It catches careless concentration, never a
  deliberate split. This matches the steer that the Nakamoto coefficient counts *entities*; that fetch FAILED, see
  sources.
- **Proven blocks are a selected sample.** Provers choose blocks that hold member work, so `km/kn` describes proven
  blocks, not the chain. For a chain-wide statistic, prove a pre-committed set: for example every block whose id ends
  in a given nibble, chosen *after* the epoch (an unbiased 1/16 sample, DERIVED), or back-walk the whole epoch.
- **Integrators.** The integrator key at bytes 18..50 gives a second, separate concentration measure: who assembles
  blocks (node operators and pools). Under honest operation one large node legitimately integrates many blocks, as the
  two consecutive blocks in the vectors show. Use the same thresholds, and expect higher baselines.
- **Prior art for real-world levels.** In Bitcoin "the weekly mining power of a single entity has never exceeded 21%",
  "the top four Bitcoin miners have more than 53%", and the top Ethereum miner never had less than 21 % ([P8] Gencer
  et al., https://arxiv.org/abs/1801.03998, full text). A 20–25 % honest top share is therefore a realistic baseline,
  and t = 0.40 leaves room above it.

---

## 2. Timestamp anomalies: what the rules allow (CODE)

**The rules.**
- **Upper bound.** A block is refused if its timestamp is more than 50 ms ahead of the *validating node's* clock
  (`blockchain/blockchain.go:528-534`).
- **Lower bound.** It is refused if it is ≤ any parent's (`:536-544`).
- **No median-time-past.** There is no lower bound beyond "after the parent".
- **The template.** It stamps the local time, or parent + 1 ms when the clock is behind
  (`blockchain/miner_block.go:304-311`).

**The node clock is not peer-adjusted.** `globals.Time()` uses the system clock or an NTP offset
(`globals/globals.go:89-98`). The P2P offset line is commented out (`:97`), and a test pins that a peer average is
"computed and published, never applied" (`globals/r27_globals_test.go:73`). Bitcoin-style timejacking needs the
victim's *network time* to be "the median of the timestamps peers send", with a 70-minute revert and a 2-hour block
limit ([S1] steer, http://culubas.blogspot.com/2011/05/timejacking-bitcoin_802.html). That attack has no lever here:
skewing peers changes nothing in block validation.

**The difficulty response.**
- Difficulty is computed from `solve_time = tip_time − parent_time`, clamped from above at 2 × 18 s
  (`blockchain/difficulty.go:239-251`), with `M = 8` and `diff·e^((1 − solve/18 s)/8)` (`:103-110`).
- The code's own comment flags the open question: "we need to evaluate if the mining adversary gains something, if the
  they set the time diff to 1" (`:131`).

**What one block producer can do (DERIVED).**
- **(a) Back-date to parent + 1 ms.** This raises the next difficulty by at most ≈ e^(1/8) = 1.133× (a self-harming
  or griefing move).
- **(b) Forward-stamp.** It is bounded to +50 ms against honest clocks, so it cannot lower difficulty except by
  actually waiting.
- **(c) The 2×-block-time clamp** caps the per-block drop at e^(−1/8) = 0.8825×.

**What a contract can flag on proven blocks.**
- Header gaps < 1 s: a back-dating signature, given that 9 regular plus 1 HighDiff final miniblock must be mined.
- Gaps > 36 s: the clamp is active.
- A final-miniblock 16-bit timestamp that differs from the header mod 2^16 by more than ~1 s. This was within 1 ms in
  all 4 vectors.
- Regular-miniblock timestamps more than a block time after the parent header. Those are miners' local clocks, and
  consensus does not check them; that is CODE: the template sets them at `blockchain/miner_block.go:356-357`, and no
  validation rule was found in `blockchain/miniblocks_consensus.go`.

These are **signals, not proofs**. Honest clock error makes the thresholds statistical. Calibrate them on settled
history before any payout depends on them.

---

## 3. Selfish-mining signatures in DAG and miniblock data (DERIVED; detection only)

**The theory.**
- **Eyal–Sirer:** a selfish pool profits above `(1 − γ)/(3 − 2γ)`. Their backward-compatible fix "would raise the
  threshold from zero to 1/4" ([P9] https://arxiv.org/abs/1311.0243, full text).
- **Sapirshtein et al.:** optimal policies have a profit threshold "strictly lower than the one induced by the SM1
  scheme", and "under a model that accounts for delays, the profit threshold vanishes" ([P10]
  https://arxiv.org/abs/1507.06183, full text).

**What a selfish strategy needs on DERO.** Withholding a *block* means the integrator keeps the final miniblock
private and later releases a competing block at the same height. On chain:
- The loser becomes a side block with 0 reward and ignored txs (`blockchain/blockchain.go:984-986`, `:1385-1397`).
- The winner's regular miniblocks must point to the same tip (`blockchain/miniblocks_consensus.go:99`).

**What a contract can and cannot see.**
- **Visible:** main-chain blocks only, because side blocks never execute an Anchor and are never proven.
- **Signatures on the main chain:**
  - runs of consecutive blocks by the same integrator key, at a rate above its share q (P(run ≥ r) ≈ q^(r−1) per
    start);
  - regular miniblocks from a single KeyHash group dominating those runs;
  - abnormally short header gaps after a long one (release bursts).
- **Invisible:** the side blocks themselves, the orphan rate, and propagation order. The harness observatory already
  counts these node-side (`harness/intel/consensus_intel.py` detectors D01–D20 per `r33_code_capabilities.md` §5.1),
  but they are node-local and not deterministic across nodes.
- **What a contract can do:** publish the main-chain run statistics per epoch. A selfish-mining *claim* stays an
  off-chain, node-side judgement.

---

## 4. Supply and emission checks: which stay with the audit bounty

| check | verifiable in-contract? | why | anchor |
|---|---|---|---|
| A pool's own burn and escrow: balance ≥ burned + Σ P_e + Σ stakes | **No, but checkable by anyone from GetSC** (the DVM has no balance builtin) | the contract tracks deposits itself | `r33_code_capabilities.md` §0; `gt_pool.bas:48-53` |
| Formula emission per block | Partly: `CalcBlockReward(h)` is pure arithmetic a contract could recompute (shift and divide) | the reward itself is not in the block bytes: the coinbase carries only the key | `blockchain/transaction_execute.go:60-62`; `transaction/transaction.go:455-457` |
| Fees per block | No: fees are a sum over txs whose bytes are not in the block | needs every tx | `blockchain/transaction_execute.go:126` |
| Total supply | No: `CalcSupply` is a formula and would print the same on an inflated chain | display semantics | `blockchain/supply.go:5-26` |
| The balance-tree diff vs. published deltas (the R23 emission auditor) | No: off-chain, node-side | needs the balance tree | `r32a_security_inventory.md` §1 |

So supply integrity stays with **M4 v2** (the audit bounty with no majority over the sponsor; GT-A04's fix) and with
the node-side disclosure track. The pool adds only its own verifiable escrow.

---

## 5. The honest limits: what no contract can see

| class | what a contract can do | what it cannot do | anchor |
|---|---|---|---|
| **Peer attacks** (eclipse, partition, ban evasion, relay withholding) | pay only for work that ended in main-chain blocks (orphan-causing behaviour goes unpaid); raise the number of independent miners; publish concentration and run statistics | see or score peers, ban, or change propagation. The P2P policy is node-local: ban at score 100 with a 10-min half-life, bans of 600 s doubling to 24 h, and fault points (`p2p/penalty.go:38-57`); ≤ 2 outbound per /16 or /32 and ≤ 1,024 grey entries (`p2p/diversity.go:38-40`) | the same |
| **Integrator censorship** of tagged miniblocks or Anchor txs | back-walk through tips (one surviving anchor proves the epoch); long windows that span many integrators | see what was left out of a block (`blockchain/miner_block.go:336-340`, `:205-281`) | `r33_block_proofs.md` §3 |
| **Reorgs** | nothing: anchors and credits revert with the block (safe, see `r33_block_proofs.md` §3) | witness a reorg; its own state is rolled back (`blockchain/blockchain.go:1030-1074`) | `config/config.go:79` STABLE_LIMIT 8 |
| **Range-proof soundness** (the defect the Foundation disclosed 2026-10-20) | fund independent re-runs of the published census and audit (a bonded claim over public data) | see value inside encrypted balances; a contract has no access to proofs or ciphertexts | `r32a_security_inventory.md` §1 rows B8/C1; `blockchain/supply.go:5` |
| **Consensus bugs** | inherit them: an anchored id is whatever consensus accepted | detect a node accepting an invalid block | `r33_block_proofs.md` §3 item 1 |
| **51 % / selfish mining by a split identity** | lower-bound statistics only (§1, §3) | distinguish one entity behind many KeyHashes | §1 |
| **Unmetered hash gas** (a chain-stall class) | — | price other contracts' calls | `r32a_security_inventory.md` §4 B10 |

---

## 6. Design rules derived (falsifiable)

| ID | rule | falsified if |
|---|---|---|
| FS-1 | The concentration alarm uses t ≥ 0.40 and n ≥ 360, and is labelled "KeyHash lower bound". | An honest-history replay at that setting raises an alarm, or a published alarm is described as an entity measure. |
| FS-2 | Chain-wide statistics come from a sample fixed after the epoch (an id-suffix rule) or from a full back-walk, never from prover-chosen blocks. | A published chain-wide figure is computed only over prover-chosen blocks. |
| FS-3 | Timestamp flags are calibrated on ≥ 1 day of settled history, and published as rates with height ranges. | A flag rate is published without its honest baseline. |
| FS-4 | Supply claims stay with M4 v2 and the node-side disclosure track; the pool reports only its own escrow. | A pool page claims a supply or emission fact it cannot verify. |
| FS-5 | No contract pays an "attack detected" claim that depends on data it cannot read (r33_research_web rule 12). | Any payout path depends on peer, side-block or mempool data. |

## Sources (this file)
| ref | label | URL | status |
|---|---|---|---|
| P8 | paper | https://arxiv.org/abs/1801.03998 (Gencer et al., Decentralization in Bitcoin and Ethereum) | full text |
| P9 | paper | https://arxiv.org/abs/1311.0243 (Eyal, Sirer) | full text |
| P10 | paper | https://arxiv.org/abs/1507.06183 (Sapirshtein, Sompolinsky, Zohar) | full text |
| S1 | steer | http://culubas.blogspot.com/2011/05/timejacking-bitcoin_802.html | fetched |
| — | FAILED | https://news.earn.com/quantifying-decentralization-e39db233c28e and https://balajis.com/p/quantifying-decentralization (Nakamoto coefficient): no content / 404 | — |
