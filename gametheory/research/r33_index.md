# R33 research map (game-theory track)

Date: 2026-11-17. This maps every R33 objective (rft §2 items 10–15; design D-GT-23, rft §8.1) to the research that
answers it, the design rules derived, the rft rows it feeds, what is CONFIRMED by a test or run versus only
researched, and what is still open.

**Status words.**
- **CONFIRMED** = a test or run shows it. The tests named below were run in this session with
  `go test -run TestR33 ./dvm/ ./cmd/dero-miner/`, and every one PASSED: the R33 audit PoCs, `TestR33PrizeDraw64`,
  `TestR33Beacon`, `TestR33BlockProofVerifiesRealMainnetBlocks`, the 4 `TestR33Pool*` tests and
  `TestR33GameTagLandsInFlags`.
- **RESEARCHED** = sourced or derived, not executed.
- **ESTIMATE** = arithmetic from anchored constants.

**Files.**

| file | content |
|---|---|
| `dossier.md` | R32 base dossier (A–G) + the R33 section (appended) |
| `r32a_research_web.md` | R32a web research (pools, lotteries, security games, supply, selfish mining) |
| `r32a_security_inventory.md` | evidence-anchored inventory of prior security concerns (YES/PARTIAL/NO per concern) |
| `r33_research_web.md` | R33 web dossier: collusion/Sybil, deflation, reward sharing, stake, peer attacks, supply (rules 1–14) |
| `r33_code_capabilities.md` | DVM surface and hard limits (§0, §7), forensics reads, stake, mining identity, peer limits, gt_audit win points |
| `r33_outreach.md` | outside participation and the beacon (rules OR-1..OR-10) |
| `r33_block_proofs.md` | **new:** relay and light-client prior art, the anchor model, back-walk through tips, attacks A1–A9, rules BP-1..BP-7 |
| `r33_pool_math.md` | **new:** M5 payout properties, split-neutrality proof, cap bound, the stake-bound 3−2√2, proof economics, variance, burn rationality |
| `r33_forensics_and_security.md` | **new:** concentration statistics, timestamp rules, selfish-mining signatures, supply checks, honest limits, rules FS-1..FS-5 |
| `../audit/r33_contract_audit.md` | independent audit of the R32 contracts: GT-A01..A17, PoC tests |

---

## Objective 10: fixes for the R32a security limits (collusion, Sybil auditors, consensus, peer, range-proof)

- **Answers.**
  - `r33_research_web.md` §1 (Schelling, P+ε, Kleros, UMA, Truebit, MACI, slashing provable faults) and rules 1–3, 14.
  - `r33_code_capabilities.md` §6 (gt_audit win points and DVM-feasible fixes) and §7 (hard limits).
  - `r33_block_proofs.md` §2 ("check, don't vote" made concrete: anchor + SHA3).
  - `r33_forensics_and_security.md` §5 (honest limits).
- **Rules.** Check, don't vote (rule 1). Slash only provably wrong claims (rule 2). BP-1 (trust only consensus-written
  ids). FS-5 (no payout on unreadable data).
- **rft rows.** GT-B21, GT-B23, GT-A01..A17, GT-B24, GT-B16.
- **CONFIRMED.**
  - Block facts can be verified in-contract on real mainnet bytes (GT-B24).
  - The audit PoCs reproduce GT-A01..A17's critical and high findings (17 tests PASS).
- **RESEARCHED only.** Collusion and Sybil resistance for facts that are *not* in a block (emission, balances). These
  stay a bonded vote, and M4 v2 is still to be built.
- **Limits that stay.** Peer attacks, range-proof soundness and consensus bugs are invisible to any contract
  (`r33_forensics_and_security.md` §5; `r32a_security_inventory.md` §1–§2).
- **Open.** The cost of M4 v2 with sponsor primacy + a sponsor bond; a third deterministic audit task (GT-B15).

## Objective 11.1: deflation that earns more and is easy to verify

- **Answers.**
  - `r33_research_web.md` §2 (EIP-1559 burn, proof-of-burn, lock vaults) and rules 10, 11, 13.
  - `r33_code_capabilities.md` §1, §8.1–8.2.
  - `r33_pool_math.md` §8.
- **Rules.**
  - Burn is a sponsor-paid supply cut, not miner pay (rule 10).
  - Report "emitted minus provably locked".
  - BP-6: balance ≥ burned + Σ pools + Σ stakes.
- **rft rows.** GT-B27, GT-B30.
- **CONFIRMED.** The `TestR33PoolHonestEpoch` accounting (balance == burned + pools + stakes) holds in the tested path.
- **RESEARCHED / found.** The late-claim-after-Rollover path can break the invariant (`r33_block_proofs.md` A9). It is
  PLAUSIBLE from code reading, with no DVM test yet.
- **Open.** A test and fix for A9; overflow of P·W after repeated rollovers (`r33_pool_math.md` §9).

## Objective 11.2: chain and block forensics through contracts

- **Answers.**
  - `r33_forensics_and_security.md` §0–§3.
  - `r33_block_proofs.md` §2.3–2.4 (tips back-walk; the integrator key readable at bytes 18..50).
  - `r33_code_capabilities.md` §2.
- **Rules.**
  - FS-1: alarm at t ≥ 0.40, n ≥ 360, labelled as a lower bound.
  - FS-2: unbiased samples.
  - FS-3: calibrated timestamp flags.
- **rft rows.** GT-B27 (the concentration alarm), GT-B15.
- **CONFIRMED.**
  - KeyHash, Flags and the timestamp are read in-contract, equal to the Go decoder, on 4 mainnet blocks.
  - The tip of h equals the id of h − 1 in the vectors.
- **RESEARCHED.**
  - Threshold statistics: exact binomial tails.
  - The integrator-key check: CODE, not yet in a DVM test.
- **Open.**
  - A back-walk DVM test.
  - The side-block question for back-walk.
  - Per-epoch run statistics of integrators.

## Objective 11.3: many miners mining with the suite; reward sharing and scale

- **Answers.**
  - `r33_pool_math.md` §1–§2, §5–§7.
  - `r33_research_web.md` §3 (Rosenfeld, P2Pool, SmartPool).
  - `r33_block_proofs.md` §4.
- **Rules.**
  - Rule 8 (work-weighted, height-window PPLNS-style).
  - BP-2 (full structure check).
  - BP-3 (tag ≠ 0 + KeyHash + registration height).
  - BP-4 (one verified id per epoch).
  - BP-5 (proof fees covered).
- **rft rows.** GT-B25, GT-B27, GT-B29, GT-B30.
- **CONFIRMED.**
  - The tag lands in Flags and nothing else changes (`TestR33GameTagLandsInFlags`).
  - Private-chain pre-flight: tags accepted (rft GT-B25 row).
  - Pool credit on rewritten real blocks (`TestR33PoolHonestEpoch`, `TestR33PoolProofGuards`).
- **RESEARCHED / found.**
  - Withholding against M5 is impossible: it pays no shares (`r33_pool_math.md` §2).
  - Proof cost ≈ 62–65 % of a miniblock's reward at small φ (ESTIMATE, §6).
  - Untagged-flag squatting (tag 0) takes the pool: the premise is CONFIRMED, since all 40 vector miniblocks have
    Flags = 0.
  - The misparse (ntx = 0, m = 7) is accepted for block 7,915,141 (CONFIRMED on the data).
- **Open.**
  - The measured `gt_pool` ProveBlock fee.
  - Network hashrate, to place our miner's p (needs a permitted read).
  - The epoch length for small members (≥ 1,600 heights suggested, ESTIMATE).

## Objective 11.4: more DERO → a higher share, without plutocracy or sabotage

- **Answers.** `r33_pool_math.md` §3–§4 (exact theorem and bounds); `r33_research_web.md` §4.
- **Rules.**
  - Rule 7 (linear unless identity has a cost).
  - The stake factor is bounded at 2.
  - Every member keeps ≥ ½ its work share.
  - Stake buys at most 3 − 2√2 ≈ 17.16 % of the pot in total.
- **rft rows.** GT-B27, GT-B30.
- **CONFIRMED.**
  - Even-split neutrality (`TestR33PoolSplitNeutral`).
  - Stake boost and lock (`TestR33PoolStakeBoostAndLock`).
- **RESEARCHED.**
  - The general uneven-split theorem (proof in `r33_pool_math.md` §3).
  - The cap is Sybil-bypassable for x > c at 0.01 DERO per identity. This contradicts the §8.1 wording.
- **Open.**
  - A property test with random uneven splits.
  - Choosing S (1 DERO today saturates almost everyone).

## Objective 11.5: contracts help secure blocks against peer attacks

- **Answers.** `r33_forensics_and_security.md` §5; `r33_research_web.md` §5; `r33_code_capabilities.md` §5.
- **Rules.**
  - Rule 12 (contracts do not judge peer-layer attacks).
  - FS-5.
  - Pay only main-chain work.
  - Back-walk defeats per-block Anchor censorship.
- **rft rows.** GT-B27.
- **CONFIRMED.**
  - Side blocks get no reward and their txs are ignored (CODE).
  - P2P policy is node-local (CODE).
- **RESEARCHED.** Integrator censorship of tagged miniblocks is PLAUSIBLE and invisible in-contract.
- **Open.** Whether a tagged miner gets censored more often. That is measurable only off-chain, by comparing a member's
  submitted miniblocks with its included ones.

## Objective 14: contract security audit and the contracts README tutorial

- **Answers.** `../audit/r33_contract_audit.md`; `r33_block_proofs.md` §4 (a first pre-audit of the gt_pool draft:
  A1, A3, A6, A9 are new).
- **rft rows.** GT-B21, GT-B22, GT-B27 ("its own independent audit before deploy").
- **CONFIRMED.** 17 audit PoCs pass, reproducing the defects.
- **Open.**
  - An independent audit of gt_pool and gt_beacon.
  - The README tutorial (GT-B22) is not research; it is tracked in the rft.

## Objective 15: outside participation and the beacon

- **Answers.** `r33_outreach.md` (channels, ethics, OR-1..OR-10).
- **rft rows.** GT-B19, GT-B26, GT-B28.
- **CONFIRMED.** `TestR33Beacon` PASS.
- **RESEARCHED.** Pull-only outreach (D-GT-22); first-seen recruitment counting.
- **Open.** Gnomon indexing on mainnet (OR-2); the measured cost per update (OR-3).

---

## Corrections to earlier research (do not delete the originals; read these with them)

1. `r33_research_web.md` (intro and §3.4) and `r33_code_capabilities.md` §0/§7.2 say a contract has "no way to read
   another block's contents". GT-B24 removed this for any block whose id the contract holds. The tips back-walk then
   reaches every ancestor (`r33_block_proofs.md` §2.3). §3.4's optimistic SmartPool-style claim is no longer needed
   for block facts.
2. The rft GT-B25 row says "Collision bound 2^-32 per pair (the KeyHash is also matched)". No KeyHash is matched in
   `gt_pool.bas` (`:141`, `:212`), and the dominant risk is not a random collision but the stock Flags value 0
   (`r33_block_proofs.md` A1).
3. rft §8.1 defines the tag as `SHA3256(ADDRESS_RAW(SIGNER()))`. `ADDRESS_RAW` parses an address *string*
   (`dvm/dvm_functions.go:342-354`, `rpc.NewAddress`), so applied to a raw SIGNER it returns "". The draft now uses
   `SHA3256(SIGNER())` (`gt_pool.bas:58`); the §8.1 text still has the old form.

## Open research questions (R33 carry)
1. The back-walk across a side block (sim chain).
2. Measured fees of `gt_pool` ProveBlock and Anchor (`DERO.GetGasEstimate`, GT-B3).
3. The real network miner distribution, to calibrate FS-1 and the epoch length.
4. An econsim of the cap with Sybil identities, and of pot-per-credit against the proof fee (GT-B30).
5. An unbiased sample rule for chain-wide forensics (FS-2): a commit-after-epoch id suffix.
6. Whether tagging makes a member's miniblocks easier to censor (needs off-chain inclusion data).
