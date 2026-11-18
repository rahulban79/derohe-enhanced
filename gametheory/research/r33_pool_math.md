# R33 pool mathematics for M5 `gt_pool.bas`

Date: 2026-11-17. This analyses the draft `gametheory/contracts/gt_pool.bas` as read at HEAD. The file was being
edited during the session: the tag line now reads `SHA3256(SIGNER())` at `:58`. The economics are derived from
anchored constants. Computations ran in a local script kept in a session scratch directory, outside the repo.

Labels are as in `r33_block_proofs.md`: doc, paper, steer, FAILED, CODE, CONFIRMED, ESTIMATE.

---

## 0. Ground constants (CODE, plus one measurement from the repo's test vectors)

| quantity | value | anchor |
|---|---|---|
| target block time | 18 s | `config/config.go:34` |
| miniblocks per block | 18 − 9 + 1 = 10 (9 regular + ≥ 1 final; exactly 9 in the collection above height 399,000) | `blockchain/miniblocks_consensus.go:80-81`, `:120-122`; `config/config.go:36` |
| miniblocks per day (config) | 86,400 / 18 × 10 = **48,000** (regular: 43,200) | the same |
| miniblocks per day (measured) | heights 7,911,096 → 7,915,143: 4,047 blocks in 75,276.8 s = **18.60 s/block** → 4,645 blocks/day, **46,450 miniblocks/day**, 41,805 regular | header timestamps of `dvm/testdata/r33_mainnet_blocks.json` (ms at bytes 2..9, `block/block.go:111-112`) |
| block reward at h ≈ 7.9 M | `123000 >> ((h + 7,000,000) / 7,000,000)` = 30,750 atomic = 0.3075 DERO | `blockchain/transaction_execute.go:44-62` |
| per-miniblock share | (reward + fees) / 10 = 3,075 atomic (+ fees/10); the integrator gets a share + the leftover | `blockchain/transaction_execute.go:126-160` |
| daily emission | ≈ 4,645 × 30,750 = 142.8 M atomic ≈ 1,428 DERO (ESTIMATE from the measured rate) | the same |
| compute gas | fixed 10,000,000 per call, **never charged as a fee** | `dvm/sc.go:241`; `gametheory/research/r32a_security_inventory.md` §4 B10 |
| storage gas | limited by the tx fee, capped at 20,000 atomic; the SCDATA bytes (including the hex block argument) count | `dvm/sc.go:247-263`; `config/config.go:46` |
| size fee | 20 atomic per started KB | `config/config.go:49`; `blockchain/tx_fees.go:34-44` |
| fee recipient | tx fees join `full_reward` and are split over the block's 10 miniblock shares | `blockchain/transaction_execute.go:126-134` |
| pool parameters (draft) | fee e = 1,000; β = 20 %; epochlen = 400; grace = 100; S = 100,000; cap c = 30 %; pfee = 100; lockh = 2,000 | `gt_pool.bas:25-32` |

One epoch is 400 heights ≈ 2.07 h at the measured rate, so there are ≈ 11.6 epochs/day. An epoch holds 3,600 regular
miniblocks if every block is proven.

---

## 1. Payout schemes and where M5 sits

- **Proportional** pays a round's reward over the round's shares. It invites hopping: mining is profitable only until
  "43.5% the difficulty" of shares have been submitted ([P5] Rosenfeld, https://arxiv.org/abs/1112.4980, l. 339 of
  the text).
- **PPS** pays a fixed amount per share, and the operator carries all the variance ([P5]).
- **PPLNS** has "expected payout for every share submitted is (1 − f)pB" and is hopping-proof ([P5]).
- **Incentive compatibility.** Schrijvers et al. show proportional is not incentive compatible and PPLNS is, in a
  more general model. That paper's PDF FAILED (HTTP 406), so the claim rests on a search snippet only and counts as a
  steer: https://www.timroughgarden.org/papers/bitcoin.pdf.

**How M5 differs.** M5 is none of these. It pays a **fixed sponsor pot per epoch**, `P_e`, pro rata to *verified
full miniblocks*, `W_i/ΣW` (`gt_pool.bas:241`). It does not pay for sub-target shares, and it does not touch block
rewards. Each credited miniblock already paid its protocol share to its own KeyHash
(`blockchain/transaction_execute.go:146-160`). Three consequences:

1. **No hopping within an epoch.** Every credit in epoch e is worth the same `P_e·wt/TW_e` ex post. Rosenfeld's
   early-share advantage comes from an unknown round length. Here the epoch length is fixed in heights
   (`gt_pool.bas:142`), so no position in the epoch is worth more than another (DERIVED).
2. **Across epochs, P_e/TW_e can differ.** It can be raised by `Fund(e)` (`:77-84`) and by `Rollover` (`:255-266`).
   A miner who tags only in rich epochs gains by competing for a known prize, not at the expense of steady members in
   expectation. Joining is a one-time fee e, so "hopping" amounts to tagging or not, and tagging is free once
   registered. A rational member always tags (DERIVED).
3. **Variance falls to the sponsor, as in PPS,** but the sponsor's liability is capped at `P_e`. The pot is fixed, so
   the sponsor carries no bankruptcy risk (contrast Rosenfeld's PPS operator, [P5] §6.2.1).

## 2. Block withholding: can a member withhold against this pool? No (DERIVED, CODE)

- **Classic sabotage needs paid shares.** In it a miner "never submits any blocks". Under PPLNS everyone earns
  (1 − f)(1 − h/H)pB per share, and under PPS the operator can go bankrupt ([P5] §6.2.1, quoted l. 1175-1185). It
  works because the pool pays for *shares* that might have been blocks.
- **The miner's dilemma has the same root.** Pools infiltrate each other this way, and "no-pool-attacks is not a Nash
  equilibrium" ([P6] Eyal, https://arxiv.org/abs/1411.7099, full text).
- **M5 pays no shares.** It credits only miniblocks that are in a proven main-chain block. A withheld miniblock earns
  neither the protocol share nor the pool credit, so withholding costs the withholder exactly what it denies itself
  and takes nothing from the pot of others. The pool pays from the sponsor pot and fees, never from block rewards
  (`gt_pool.bas:48-53`, `:241-248`). So no member can redirect block revenue by withholding.
- **What remains is proof withholding (a free-rider problem).** One proof credits every member in that block
  (`gt_pool.bas:182-222`), but only the prover pays the fee. Members with small credits in a block wait for others to
  prove. See §6.

## 3. The weight and split-neutrality (DERIVED; proof exact for the code's integer arithmetic)

**The weight.** The code gives each credited miniblock the weight `wt = 100 + min(⌊100·s/S⌋, 100)` when the stake has
matured, i.e. `since + epochlen ≤ h` (`gt_pool.bas:143-150`). So `W_i = Σ_credits wt = w_i·(100 + b_i)`, with
`b_i = min(⌊100 s_i/S⌋, 100)`. This is the §8.1 formula `w_i(1 + min(s_i/S, 1))` scaled by 100 and floored.

**Theorem (split-neutral weight).** Suppose one owner with work w and lockable stake s spreads them over k identities
with `w_j ≥ 0`, `Σ w_j = w`, `s_j ≥ 0`, `Σ s_j ≤ s`. (A stake is a per-identity deposit and cannot be counted twice:
`Lock` adds `DEROVALUE()` to `s_<tag>`, `:101`.) Then

> Σ_j w_j (100 + b_j) ≤ w (100 + b), where b = min(⌊100 s/S⌋, 100).

*Proof.* `s_j ≤ s` gives `⌊100 s_j/S⌋ ≤ ⌊100 s/S⌋`, because the floor is monotone. Then min(·, 100) is also monotone,
so `b_j ≤ b`. Multiply by `w_j ≥ 0` and sum: `Σ w_j(100 + b_j) ≤ (100 + b) Σ w_j = w(100 + b)`. ∎

**The exact loss.** `W − Σ W_j = Σ_j w_j (b − b_j) ≥ 0`. Equality holds iff every identity with `w_j > 0` has
`b_j = b`. There are two ways:
- (a) a single working identity holds enough stake to reach b, or
- (b) b = 100 (s ≥ S) and every working identity holds `s_j ≥ S`, which needs `s ≥ k′·S` for k′ working identities.

Splitting therefore never gains, and gains exactly nothing only in those cases.

**Shares follow weights.** The member's share is `x = W_own/(W_own + W_others)`. This is increasing in `W_own`, and
others' weights do not depend on the split, so the theorem carries over to shares.

**Rounding loses a little more.** Payout rounding (`amt = P·W/TW`, `:241`) gives `Σ ⌊P W_j/TW⌋ ≤ ⌊P ΣW_j/TW⌋`. A
split loses up to k − 1 atomic more.

**Tests.** `TestR33PoolSplitNeutral` (`dvm/r33_pool_test.go:257-289`, CONFIRMED PASS in this session) checks only
*even* splits (w/k, s/k) for k = 2..5. The theorem above covers every split. A property test with random uneven
splits would pin it.

**The cap breaks payout-neutrality (CODE, DERIVED).**
- The cap is per identity (`:242-245`). With pot P and true work share x, one identity gets `min(x, c)·P` (before
  rollover).
- k identities, each holding ≤ c, get `min(x, k·c)·P`.
- So the gain from splitting is **`Δ = P·(min(x, k c) − min(x, c)) − (k − 1)·e`**. It is positive as soon as x > c
  and `P(x − c) > e`.
- At e = 1,000 atomic (0.01 DERO, `:25`), a dominant miner beats the cap for 0.01 DERO per extra identity, plus a
  registration PoW and a separate tag per identity.
- **The cap is Sybil-proof only for x ≤ c**, i.e. where it does not bind.
- This contradicts the §8.1 wording that the cap "keeps any single miner from taking the pool". It holds for a single
  *identity*, not a single *miner*.

## 4. Stake without plutocracy: exact bounds (DERIVED)

`x_i = w_i(1 + b_i)/Σ_j w_j(1 + b_j)`, with `b ∈ [0, 1]` (normalised).

- **Floor and ceiling per member.** For any stake distribution:
  `w_i/(2w − w_i) ≤ x_i ≤ 2w_i/(w + w_i)`, so **x_i ∈ [½·w_i/w, 2·w_i/w]**. Every member keeps at least half its
  proportional work share, and stake can at most double it. Stake without work earns 0, because there is no credit
  without a miniblock (`:138-161`).
- **Largest total transfer from non-stakers to stakers.** If stakers do a fraction σ of the work and are saturated,
  non-stakers keep `(1 − σ)/(1 + σ)` instead of `1 − σ`. The loss `σ(1 − σ)/(1 + σ)` peaks at `σ = √2 − 1`, with
  value **3 − 2√2 ≈ 17.16 % of the pot**. That is the most plutocracy the boost can buy, whatever the stake sizes.
- **S sets who saturates.** With S = 100,000 atomic = 1 DERO (`:29`), any member with 1 DERO locked saturates. With
  many saturated members the boost cancels out and only work counts. A larger S spreads the boost but brings it closer
  to "more DERO = more share" up to the 2× ceiling. ESTIMATE / design choice: choose S near the median member stake
  the sponsor wants to reward. Never make S unbounded, or the 17.16 % bound no longer applies (it relies on b ≤ 1).
- **Lock timing (CODE).**
  - Stake counts only for blocks at least one epoch after the last top-up (`:146`).
  - A top-up resets maturity (`:102`).
  - Unlock needs `lockh` = 2,000 heights since the last Lock (`:116`).
  - A stake cannot serve two identities at once. Moving it to another identity costs ≥ 2,000 heights locked plus
    400 to mature.
- **Prior art (from `r33_research_web.md` §4).**
  - Quadratic and concave weights gain from splitting.
  - Linear weights or work weights are split-neutral.
  - A refundable bond is no identity cost.
  - The M5 weight is linear in work, with a bounded multiplicative stake factor, so it avoids the √k Sybil gain of
    concave rules.
  - Douceur: "without a logically centralized authority, Sybil attacks are always possible" ([P7]
    https://www.microsoft.com/en-us/research/publication/the-sybil-attack/, abstract). Work is the only
    non-forgeable identity cost here.

## 5. The payout cap c: effect on a dominant miner and on honest small miners (DERIVED)

The excess above c stays in `P_e` and, after 5 epochs plus grace, rolls into the then-current epoch (`:255-266`).
Assume a steady pot P per epoch and a single-identity dominant member with work share x > c. In steady state the
epoch pot is `P′ = P/(1 − x + c)`:
- the dominant member gets `c·P′ = c/(1 − x + c)·P`;
- the others get `(1 − x)/(1 − x + c)·P`.

| x (dominant) | dominant gets | others get | others without cap |
|---|---|---|---|
| 0.4 | 0.333 P | 0.667 P | 0.600 P |
| 0.6 | 0.429 P | 0.571 P | 0.400 P |
| 0.8 | 0.600 P | 0.400 P | 0.200 P |
| 1.0 | 1.000 P | 0 | 0 |

- **What the cap does.** It *does* redistribute in steady state, but only after a lag of 5 epochs (≈ 10 h). Honest
  small miners do not get the excess in the same epoch.
- **What it costs with few members.** With fewer than ⌈1/c⌉ = 4 equal members (for example an operator-only 3-wallet
  set), every epoch leaves a remainder that keeps rolling over. That is safe, but payouts are delayed.
- **Sybil bypass.** §3 applies: the redistribution vanishes once the dominant miner splits into ≥ ⌈x/c⌉ identities.

## 6. Prover economics: break-even at the measured Prove gas (CODE + ESTIMATE)

**What a proof costs.**
- **Compute is free.** The 1,742,400 compute gas is not charged (`dvm/sc.go:241`).
- **The fee is the storage gas.** The fee must cover storage gas, since the storage-gas limit is the fee
  (`dvm/sc.go:247-254`; rft lesson 24). Measured Prove storage was 1,735 atomic for a 598-byte block and 1,927 for
  694 bytes (CONFIRMED, test log). It is dominated by the hex argument (2 bytes per block byte) plus about 540 bytes
  of other SCDATA and stores.
- **The size fee is small.** About 3 KB × 20 = 60 atomic, so it is smaller still.
- **gt_pool's ProveBlock stores more.** It writes up to 9 census keys `k<e>_<32 hex>` plus the credit keys
  (`:164-180`, `:151-159`). ESTIMATE: **≈ 2,000–3,000 atomic per proof**. Measure with `DERO.GetGasEstimate` (GT-B3).

**Proofs per epoch.** Let members do a fraction φ of network work. Blocks with ≥ 1 member miniblock per epoch:
`400·(1 − (1 − φ)^9)`. At 2,000 atomic per proof:

| φ | proven blocks / epoch | member miniblocks / epoch | credits per proof | proof cost / epoch | cost per credit |
|---|---|---|---|---|---|
| 0.001 | 3.6 | 3.6 | 1.00 | 7,171 | 1,992 |
| 0.01 | 34.6 | 36 | 1.04 | 69,186 | 1,922 |
| 0.05 | 147.9 | 180 | 1.22 | 295,800 | 1,643 |
| 0.2 | 346.3 | 720 | 2.08 | 692,625 | 962 |
| 0.5 | 399.2 | 1,800 | 4.51 | 798,437 | 444 |

**What it means.**
- **Proving costs ≈ 62–65 % of a miniblock's reward at small φ.** A miniblock's protocol share is 3,075 atomic, and
  proving it costs ≈ 1,900–2,000 atomic when members are small (φ ≤ 1 %).
- **Total verification can exceed what members earn.** Add per-block anchoring (≈ 150–250 atomic × 400/epoch, see
  `r33_block_proofs.md` A8). At φ = 1 %, verification then costs ≈ 0.69 + 0.08 DERO/epoch ≈ 9 DERO/day (ESTIMATE),
  while members earn ≈ 12.9 DERO/day in protocol rewards from their 418 regular miniblocks. The pot must be large
  relative to members' own mining income just to pay for its own verification.
- **Break-even for a prover.** A member proving its own block breaks even iff
  `P_e · Σ_{own credits} wt / TW_e + pfee ≥ fee`. For a 1-credit block that is `P_e/TW_e·100 ≥ fee − pfee ≈ 1,900`:
  **the pot must pay ≥ ~1,900 atomic per credited miniblock**, or provers lose money.
- **pfee is far too low for outsiders.** At 100 atomic (`:31`), a non-member prover recovers ≈ 5 % of its fee.
- **Part of the fee comes back.** Proof fees are tx fees, which return to the block's 10 miniblock shares
  (`blockchain/transaction_execute.go:126-134`). About a fraction φ of all proof fees comes back to members as
  protocol reward (DERIVED). At small φ that is a small offset.

**Levers, in order of effect (ESTIMATE).**
1. **Back-walk through tips** (`r33_block_proofs.md` §2.3) removes per-block anchoring.
2. **Prove only blocks with ≥ k credits, or batch.** ≈ 5 Proves fit one call: 2,000 lines per call
   (`dvm/dvm.go:71`) and 10M gas, against ≈ 1.74M each. Batching saves only the ≈ 540-atomic per-call overhead,
   because the hex argument is paid byte for byte.
3. **Set pfee = min(measured fee + margin, the credited value in the block).** Proving then pays for anyone, and a
   1-credit block cannot drain more than it credits.
4. **Make e and P_e large enough** that the pot per credit is ≥ 2× the proof fee.

## 7. Epoch length and a small miner's variance (DERIVED)

With every block proven, member i's credits per epoch are `w_i ~ Binomial(3,600·a, p_i)`, where a is the proven
fraction and p_i its share of network work. That is approximately Poisson.

| p_i (share of network work) | mean credits / epoch | sd | CV = sd/mean | P(0 credits in an epoch) |
|---|---|---|---|---|
| 0.0001 | 0.36 | 0.60 | 1.67 | 0.70 |
| 0.0003 | 1.08 | 1.04 | 0.96 | 0.34 |
| 0.001 | 3.6 | 1.90 | 0.53 | 0.027 |
| 0.003 | 10.8 | 3.28 | 0.30 | < 10^-4 |
| 0.01 | 36 | 5.97 | 0.17 | ≈ 0 |
| 0.1 | 360 | 18.0 | 0.05 | ≈ 0 |

- **Scaling.** The CV is `√((1 − p)/(3,600·a·p))`. A pool cannot lower a member's work variance below this, because
  credits are full miniblocks. Rosenfeld's point that a pool's variance cannot drop below the miner's own share
  ([P5], l. 280-313) applies with "share" = miniblock.
- **Longer epochs cut the CV by √(length factor), but delay pay.** At 400 heights a 0.1 %-of-network miner sees 2.7 %
  empty epochs and a CV of 53 %.
- **ESTIMATE:** for members below ≈ 0.1 % of network work, use E ≥ 1,600 heights (≈ 8 h, CV ≈ 26 %).
- **The DVM limit on epoch length.** The contract keeps per-epoch keys, so E is bounded only by the claim and
  rollover windows (`:229`, `:259`), not by gas.
- **Unknown.** Network hashrate is not read here (no RPC). Our own miner's share of network work is therefore not
  computed. The playbook should derive p_i from the KeyHash counts in proven blocks.

## 8. The burn β against the sponsor subsidy: when joining is rational (DERIVED)

**Who pays the burn.** Per epoch, the inflow is the sponsor funding F_e plus the entry fees N_new·e. The burn is
`β·(F_e + N_new e)` (`:48-53`). The pot is `(1 − β)(F_e + N_new e) − proof fees paid as pfee`.
- **The sponsor pays the deflation:** β·F of its own money.
- **A member pays only β·e once,** plus its proving costs.

**When joining pays.** Member i joins iff, over the epochs T it stays,

> Σ_{e∈T} (1 − β)·F_e·x_{i,e} − e − C_proof,i − C_anchor,i > 0,

where `x_{i,e} = W_i/TW_e` and C are the fees it pays itself. Joining is strictly rational iff the sponsor's per-epoch
funding satisfies `(1 − β)·F·x_i·|T| > e + C`.

- **Example.** At φ = 1 % (x_i ≈ 1 for a sole member set) and |T| = 1 day = 11.6 epochs, with C ≈ 8 DERO/day of
  self-proving (§6): F must exceed ≈ 0.86 DERO per epoch at β = 0.2. A larger member set shares the proving and
  lowers C per member.
- **The burn itself never decides a member's choice; proving cost does.** β only scales how much of the sponsor's
  money reaches members.
- **"Deflation earns more"** (§2 objective 11.1) holds only in the sense that a sponsor's DERO buys both a supply cut
  (β) and miner pay (1 − β). A burn pays miners nothing directly (`r33_research_web.md` rule 10).
- **Checking the burn.** `GetSC` balance ≥ `burned` + Σ P_e + Σ stakes at every height. The supply figure is a
  formula (`blockchain/supply.go:5-26`), so the page reports "emitted minus provably locked". The late-claim path
  (`r33_block_proofs.md` A9) breaks this inequality and must be fixed first.

## 9. Overflow margins (CODE + ESTIMATE)

- `P·W` in Claim (`:241`): W per member ≤ 3,600 × 200 = 720,000 per epoch, so P·W < 2^64 needs P < 2.56·10^13 atomic.
- Fund caps a single epoch at 10^13 (`:80`), but `Rollover` (`:263`) and Register inflows (`:71`) add without that
  check. A long run of rollovers into one epoch could pass 2.56·10^13 and wrap silently (GT-A15 class).
- Fix: apply the same cap in Rollover, or compute `P/TW·W` with a remainder.

## 10. Open questions (feed GT-B27, GT-B30)
1. The measured ProveBlock storage gas of `gt_pool.bas` itself (only the probe's 1,735/1,927 is measured).
2. A DVM test for the late-claim path (A9) and for the m = 7 misparse on block 7,915,141 (A6).
3. An econsim of the cap-plus-Sybil bypass, and of a pot per credit against the proof fee, at the network's real
   miner distribution.
4. Whether back-walk crosses a side block (`r33_block_proofs.md` §2.3 residual).

## Sources (this file)
| ref | label | URL | status |
|---|---|---|---|
| P5 | paper | https://arxiv.org/abs/1112.4980 (Rosenfeld) | full text |
| P6 | paper | https://arxiv.org/abs/1411.7099 (Eyal, Miner's Dilemma) | full text |
| P7 | paper | https://www.microsoft.com/en-us/research/publication/the-sybil-attack/ (Douceur) | abstract-only |
| — | FAILED (steer via snippet) | https://www.timroughgarden.org/papers/bitcoin.pdf (Schrijvers et al., FC 2016) | HTTP 406; snippet only |
