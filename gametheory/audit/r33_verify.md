# R33 pre-deployment invariant verification: six DVM-BASIC game contracts

I ran this in the clone `scratchpad/r33/verify_clone` at base commit cf1daa5e. The tests are in `dvm/r33_verify_<contract>_test.go`, with shared helpers in `dvm/r33_verify_common_test.go`. No contract was changed in the commit. Each fix proposed below was applied to a temporary copy, the relevant tests were re-run against it, and the file was then reverted.

Command: `nice -n 15 go test ./dvm/ -run 'R33Verify' -count=1`. It compiles and runs in about 9 s. 22 tests pass and 5 fail. Each of the 5 failures is a real invariant violation, listed below.

## Method

The tests drive each contract through the in-process simulator with several signers: the owner, members or participants, and outsiders. The block height increases through the run. Each contract gets three kinds of sequence:

- table-driven sequences;
- randomized sequences with fixed seeds 33, 3301 and 3302, each 600 to 900 calls;
- edge and max-size sequences.

Every call goes through `vLedger.do`, which works as follows:

- An independent Go model of the documented rules predicts whether the call succeeds or reverts. A mismatch is fatal.
- The model also predicts how much DERO the contract sends and to whom. The test checks the contract's balance change and every payee's encrypted balance (`deroIs`) against that prediction.

After every call the test also checks:

- **Conservation.** The contract's DERO balance must equal a liability formula built only from the contract's stored variables. The formula for each contract is in that test file's header.
- **Ledger.** For every participant, received + lost = deposited + awarded, and received <= deposited + awarded.

Two more checks run once per test:

- **Gas.** The maximum compute and storage gas of each entrypoint is compared with the 10,000,000 compute limit (2000 lines at 5000 gas each) and with the 20,000 storage gas a mainnet call can buy.
- **Liveness.** At the end, `drain()` moves time past every documented window and has every participant withdraw. The contract must end at 0, or at exactly the documented carry.

Simulator artefacts that were respected:

- A deposit is credited to the contract without being debited from the sender. A reverted call refunds the deposit (`w.refund`).
- gt_pool proofs run through `runAt` with the proof block's real BLID and fee 20000, so the mainnet storage limit applies.

## gt_attest.bas (M1): 5 HOLDS, 1 FAILS

1. **Conservation: HOLDS.** Tested by `TestR33VerifyAttestRandom` (3 seeds, about 690 calls each, 65 to 82 claims, statuses 0/1/2/3/4 all reached), `TestR33VerifyAttestOutcomes` (8 dispute shapes) and `TestR33VerifyAttestBounds`.
   - The liability is: treasury + stakes + open bonds b(1+nx) + escrows + unclaimed juror dues + the residual still to be swept.
   - The residual (pool + cuts - pays) is never negative.
2. **No excess payout: HOLDS.** Same tests. Every Finalize and ClaimJuror payout equals the rule. At the bounds the scaled juror pay is never above the exact pay.
3. **One-time actions: HOLDS.** Tested by `TestR33VerifyAttestOutcomes` and `TestR33VerifyAttestAccess`. A second Initialize, Finalize, ClaimJuror, RevealVote or CommitVote, a self-challenge and a repeat challenge are all refused.
4. **Access control: HOLDS.** Tested by `TestR33VerifyAttestAccess` and the random setter branch. SetParams, Freeze and WithdrawTreasury are owner-only, and SetParams is refused after Freeze.
5. **Liveness: FAILS.** Test: `TestR33VerifyAttestLivenessSilentJuror`. When all jurors cooperate, `drain` ends at 0, so liveness holds in that case. It fails when one juror stays silent.
   - **Case (a), rejected dispute:**
     - Stakes: j1 300001, j2 100003, j3 200007.
     - Claim(190, 199, k = 4) at height 200, then Challenge by c1.
     - Votes 0/0/1, all revealed at 231. Finalize at 241.
     - ClaimJuror by j1 and j2, then Unstake and WithdrawTreasury.
     - j3 never calls ClaimJuror. The contract then holds 180008, but j3 is owed only 180006. The other **2** atomic units belong to the treasury and nobody can release them. ClaimJuror by the owner or an outsider is refused, and the treasury reads 0.
   - **Case (b), undecided dispute (votes 1:1):** j3 never revealed and never claims. The contract holds 200007, of which 180006 is j3's. **20001** (j3's whole 10 % slash) is the treasury's and stays locked forever.
   - Expected: the treasury share is withdrawable once the windows close, whatever any single juror does.
   - Responsible: gt_attest.bas:281 (ClaimJuror is keyed to SIGNER()) and :302-304 (BASIC lines 400-420: the residual reaches the treasury only when nz == nj).
   - Minimal fix:
     - Index the jurors at CommitVote: `STORE(p + "j" + ITOA(nj), SIGNER())`.
     - Move ClaimJuror's body into an internal `claimj(i, a String)`.
     - Add `ClaimJurorFor(i, k)`. Anyone may call it after the reveal window closes plus a grace period (for example revealw). It runs `claimj` for the juror at `LOAD(p + "j" + ITOA(k))`, sends any pay to that juror's address and credits the returned stake to that juror's `st`.
   - Severity: low. Only the treasury's share is ever stuck, and every participant can still get its own funds out.
6. **Bounds: HOLDS.** Test: `TestR33VerifyAttestBounds`.
   - Inputs: bond 10^12, maxmb 100, span 1000 (so b = 10^17), 8 challengers (a 9th is refused), stakes of 10^9, reward 10^6, slash 100.
   - No Uint64 wrap. The overflow branch of the juror pay stays at or below the exact share.
   - Peak gas: Finalize 1,191,000 compute (11.9 %), and every entrypoint uses at most 246 storage gas.

## gt_service.bas (M2): 4 HOLDS, 2 FAILS

1. **Conservation: HOLDS.** Tested by `TestR33VerifyServiceRandom` (3 seeds, 700 calls, about 30 epochs, 170 to 195 documents) and `TestR33VerifyServiceRollLiveness`.
   - The liability is: treasury + P(e) for epochs with W = 0 + (P - Q) for epochs with W > 0 and Z < C.
   - The contract's MAT balance equals the sum of the MAT stakes.
2. **No excess payout: HOLDS.** Same tests. Each rebate equals pool * w / W and is never above the exact share. The no-wash rule holds: a sole payer without sponsor money never gets back more than it paid.
3. **One-time actions: HOLDS.** Same tests plus `TestR33VerifyServiceAccess`. A repeat ClaimRebate, a document that already exists (first writer wins, and `by<doc>` is checked) and a second Initialize are all refused.
4. **Access control: HOLDS.** Test: `TestR33VerifyServiceAccess`. SetParams, SetMAT, Freeze and WithdrawTreasury are owner-only; SetParams and SetMAT are refused after Freeze; Notarize and Sponsor are refused before Freeze; and the no-wash bound and the other parameter bounds are enforced.
5. **Liveness: FAILS.** Test: `TestR33VerifyServiceLivenessSilentPayer`. Sponsor-only epochs do roll forward and get paid out (`TestR33VerifyServiceRollLiveness`: R3 = 7). The failure is a silent payer.
   - Sequence: Notarize by u1 once and by u2 twice in epoch 2, then Sponsor 1001. That gives P = 2501 with weights 1000 : 2000.
   - At height 300 u1 claims, and the owner withdraws the treasury. u2 never claims.
   - The contract holds 1668. u2 is owed 1667. **1** atomic unit of floor remainder belongs to the treasury and stays locked forever. Expected: it is releasable after a deadline.
   - Responsible: gt_service.bas:193-194 (BASIC 98-99: the remainder is swept only when Z == C). ClaimRebate is keyed to SIGNER() (BASIC line 40).
   - Minimal fix: add a claim deadline, ClaimRebate refused once `BLOCK_HEIGHT() >= (e + 1 + K) * epoch`. Then add `Sweep(e)`, callable by anyone after that deadline, which moves `P - Q` to the treasury once and sets `Z = C`. This mirrors gt_pool's Claim/Rollover windows.
   - Severity: dust (rounding only).
6. **Bounds: FAILS.** Test: `TestR33VerifyServiceBounds`. Gas holds: Notarize peaks at 761,200 compute and every call uses at most 185 storage. The arithmetic wraps.
   - Sequence: SetParams(fee 10^12, rho 100, boost 0, epoch 100), all inside the documented bounds. Then Freeze, then 200 Notarize calls by u1 in epoch 2, then ClaimRebate(2) at height 300.
   - Observed payout: **15,532,000,000,000**.
   - Expected: pool * w / W = **200,000,000,000,000**, or the documented 10^-5 scaled share, which is also 2.0e14.
   - The **184,468,000,000,000** difference goes to the treasury.
   - Responsible: gt_service.bas:189 (BASIC 90). Once wt > 2^64 / 10^5 (1.84e14), `wt * 100000` wraps. The header's claim that the payout "never wraps" (GT-A15) does not hold.
   - Reachability: a single payer's epoch weight must exceed 1.84e14 atomic units (1.68e13 at boost 1000). That is more than the total DERO supply (about 2.1e12 atomic), unless the owner recycles treasury withdrawals back into fees. Severity: low.
   - Minimal fix, verified. The test then passes and the existing R32/R33 service and audit tests still pass:
     ```
     20 DIM pay, pp, wt, ww, sh as Uint64
     84 IF pp > 18446744073709551615 / wt THEN GOTO 87
     85 LET pay = pp * wt / ww
     86 GOTO 92
     87 LET sh = wt / (ww / 100000 + 1)
     88 IF wt > 184467440737095 THEN GOTO 90
     89 LET sh = wt * 100000 / ww
     90 LET pay = pp / 100000 * sh + pp % 100000 * sh / 100000
     ```
     The new `sh` is at most 10^5, so the payout is never above the exact share.

## gt_prize.bas (M3): 4 HOLDS, 2 FAILS

1. **Conservation: HOLDS.** Tested by `TestR33VerifyPrizeRandom` (3 seeds, about 770 calls, 29 rounds, 14 to 22 of them with a winner) and `TestR33VerifyPrizeBounds`.
   - The liability is: treasury + prize(rd) + every principal not yet withdrawn + its bond (until the draw) or its revealed bond (after the draw).
2. **No excess payout: HOLDS.** Same tests. Withdraw pays a + v * rbond. The draw winner always matches an independent seed % tw walk. A withheld reveal bond always goes to the treasury.
3. **One-time actions: HOLDS.** Same tests plus `TestR33VerifyPrizeAccess`. A second entry per round, a second reveal, a second Withdraw and a second Initialize are all refused.
4. **Access control after Freeze: FAILS.** Test: `TestR33VerifyPrizeRefreeze`. SetParams, SetFees and SetMAT are correctly refused after Freeze. Freeze itself is not one-time, and it is not an inert setter: each call resets `rs`.
   - Sequence:
     - Freeze at 100, Fund 50000 from sp.
     - Enter by a and b (principal 100000 each).
     - At 111, Reveal a (j = 0) and Reveal b (j = 1).
     - The owner calls Freeze again at 111, which sets rs := 111 and reopens the commit phase.
     - A Sybil enters with principal 1000 and num = 367667, computed from the revealed seed, then reveals at 122.
     - Draw at 133.
   - Observed: the Sybil (weight 1000 of 201000, so a fair chance of 0.5 %) wins the 50000 prize **with certainty**.
   - Responsible: gt_prize.bas:84-90. Freeze has no frozen check, and BASIC line 30 rewrites rs.
   - Minimal fix, verified (the second Freeze is then refused):
     ```
     17 IF LOAD("frozen") != 0 THEN GOTO 900
     ```
   - gt_attest, gt_service and gt_audit also accept a repeated Freeze, but there it only stores frozen = 1 again, which is harmless.
   - Severity: high. The owner can rig the draw, which defeats the anti-rug design.
5. **Liveness: FAILS.** Test: `TestR33VerifyPrizeRefreeze`, part (b). When the owner does not interfere, `drain` ends at 0 or at exactly the carried prize, which the next winner takes.
   - Sequence: a enters round 1 at 133. The owner then calls Freeze 50 times, each one height before the draw height. Draw stays refused from height 133 to 1152, and so does Withdraw(r 1, j 0).
   - Observed: a's principal of 100000 is locked for as long as the owner repeats this.
   - Responsible and fix: the same line and the same fix as invariant 4.
6. **Bounds: HOLDS.** Test: `TestR33VerifyPrizeBounds`.
   - Inputs: maxn 64 (a 65th entrant is refused), rbond = fee = minp = 10^12, boost 1000.
   - Draw with 64 reveals: 5,007,400 compute (50 % of the limit) and 243 storage. Draw with 64 withheld reveals: 3,565,000 compute.

## gt_audit.bas (R32a audit bounty): 6 HOLDS, 0 FAILS

1. **Conservation: HOLDS.** Test: `TestR33VerifyAuditRandom` (3 seeds, about 700 to 790 calls, 32 to 57 rounds). Every path was reached: paid, disputed, withheld and timed out.
   - The liability is: carry + open rounds (bounty + n * bond) + timed-out rounds (the bounty if not reclaimed + bonds not yet withdrawn) + settled rounds (sb if not reclaimed + credits not yet withdrawn).
2. **No excess payout: HOLDS.** Same test. Every credit `cr` equals the rule: share + bond, 0, or the refunded bond. Every Reclaim and Withdraw matches the model.
3. **One-time actions: HOLDS.** Test: `TestR33VerifyAuditAccess`. A second Initialize, RevealSponsor, Reveal, Settle or Withdraw is refused, and so is a second Reclaim (random test).
4. **Access control: HOLDS.** Test: `TestR33VerifyAuditAccess`. Post, RevealSponsor and Reclaim are owner-only. The sponsor cannot Enter. SetParams is refused after Freeze, and maxn is capped at 32.
5. **Liveness: HOLDS.** Tested by `TestR33VerifyAuditLiveness` and the random `drain`.
   - If the sponsor never reveals and nobody settles, each entrant can Withdraw its bond after start + 40 + 2000, and Settle is then refused.
   - The carry is recovered through a new Post followed by a timeout Reclaim.
   - The carry needs the owner to Post again. This is documented behaviour.
6. **Bounds: HOLDS.** Test: `TestR33VerifyAuditBounds`. Inputs: 32 entrants with 256-byte answers, bond 10^12, windows of 10^6. Settle uses 3,111,800 compute and 698 storage.

## gt_beacon.bas (M6): 6 HOLDS, 0 FAILS

1. **Conservation: HOLDS.** Test: `TestR33VerifyBeaconRandom` (600 calls; 10 % of them carry a deposit). The beacon holds 0 after every call, and an install with a deposit is refused.
2. **No excess payout: HOLDS.** The beacon never sends anything.
3. **One-time actions: HOLDS.** Tested by `TestR33VerifyBeaconAccess` and `TestR33VerifyBeaconRandom`. Initialize runs once and Subscribe works once per signer. nsub and nent always match the model.
4. **Access control: HOLDS.** Test: `TestR33VerifyBeaconAccess`. Publish is owner-only and its key, value and range bounds are enforced. An anonymous signer cannot Subscribe.
5. **Liveness: HOLDS.** Nothing is ever held, so nothing can be stuck.
6. **Bounds: HOLDS.** Test: `TestR33VerifyBeaconBounds`. With a 32-byte key and a 512-byte value, Publish uses 221,000 compute and 1172 storage.

## gt_pool.bas (M5): 6 HOLDS, 1 FAILS

1. **Conservation: FAILS, at Initialize only.** Test: `TestR33VerifyPoolInitializeDeposit`. Across every entrypoint call, conservation holds (`TestR33VerifyPoolRandom`, 2 seeds, about 895 calls, 48 and 83 blocks proven, 188 and 495 credits).
   - Sequence: install gt_pool.bas with a 50000 DERO deposit.
   - Observed: the install succeeds and the contract holds 50000, while burned + pools + stakes = 0. All 50000 is owed by nobody and can never leave, because there is no owner withdrawal.
   - Responsible: gt_pool.bas:26-30. Initialize has no `DEROVALUE()` check, unlike every other gt_pool entrypoint and every other suite contract.
   - Minimal fix, verified (the install with a deposit is then refused):
     ```
     25 IF DEROVALUE() != 0 THEN GOTO 900
     ```
   - Severity: low. Only the deployer's own deposit is at risk.
2. **No excess payout: HOLDS.** Tested by `TestR33VerifyPoolRandom` and `TestR33VerifyPoolWeightsAndCap`. Claim pays min(P0 * W / TW, P0 * 30 %). The prover fee is 2000, taken only when a proof credits at least one miniblock and P(e) >= 2000. Unlock pays back exactly the stake.
3. **One-time actions: HOLDS.** Tested by `TestR33VerifyPoolRandom` and `TestR33VerifyPoolAccess`.
   - Refused: a second Initialize, a second Register of the same tag, a second claim per epoch and tag, and a second proof of the same height through either ProveBlock or ProveParent.
   - Also refused: proving the anchored block inside its own block, a wrong ntx, a parent whose child is not proven, and a proof after the epoch's window.
4. **Access control: HOLDS.** Test: `TestR33VerifyPoolAccess`. SetMcount is owner-only, limited to 1..10, and allowed only before the first member. No owner withdrawal exists, and no-deposit entrypoints refuse deposits.
5. **Liveness: HOLDS.** Tested by the `drain` of `TestR33VerifyPoolRandom`, `TestR33VerifyPoolBurn` and `TestR33VerifyPoolBounds`.
   - Every stake can be unlocked after lockh, and every closed pool can be rolled into the current epoch.
   - At the end the contract holds exactly burned + the pools of epochs that are not yet closed.
6. **Bounds: HOLDS.** Test: `TestR33VerifyPoolBounds`. The largest proofs carry 127 transactions (a hex argument of about 9.3 KB), 9 distinct members and 9 new KeyHashes.
   - ProveBlock: 6,864,200 compute (68.6 %) and 9,823 storage.
   - ProveParent: 6,490,400 compute and 9,780 storage.
   - Pools are capped at 10^13, which keeps P * W below 8e18.
7. **Pool-specific: HOLDS.** Tested by `TestR33VerifyPoolRandom`, `TestR33VerifyPoolWeightsAndCap` and `TestR33VerifyPoolBurn`.
   - **Credits.** After every proof, the credits equal the Go decoder's count (`block.Deserialize`) of non-final miniblocks whose Flags equal a registered member's tag.
     - The test blocks are synthesized main chains: real mainnet blocks with the height fields rewritten and single-tip links. Each test block also contains random final bits (including finals at random positions and two finals), unregistered tags, tag 0 and the tag of a member who registers later.
     - The census kn/km matches the model.
   - **Burn.** burned equals the sum of beta % of every inflow. It never decreases, is never sent, and the contract always holds at least burned.
   - **Weights.** W = 100 + min(100 * s / S, 100) per credit, given only when since + epochlen <= h. A block one height before maturity earns no boost.
   - **Payouts.** Each payout is pool * W / TW, capped at 30 % per identity. The excess rolls over.
   - **Observation, not a violation:** credit goes to the tag's owner *at proof time*. Tags are 4 bytes, so a grinder can find a colliding key in about 2^32 tries and register a victim's tag before the victim does, then collect any work the victim mined under that tag before registering. Members must register before their miner writes the tag.

## Summary of FAILS

| contract | invariant | test | severity |
|---|---|---|---|
| gt_attest | 5 liveness (silent juror locks the treasury residual) | TestR33VerifyAttestLivenessSilentJuror | low (2 dust; 20001 = 10 % slash in the undecided case) |
| gt_service | 5 liveness (silent payer locks the remainder) | TestR33VerifyServiceLivenessSilentPayer | dust (1) |
| gt_service | 6 bounds (`wt*100000` wraps) | TestR33VerifyServiceBounds | low (needs weight > total supply) |
| gt_prize | 4 access after Freeze (re-Freeze reopens commit, rigs the draw) | TestR33VerifyPrizeRefreeze | high |
| gt_prize | 5 liveness (repeated Freeze blocks Draw and Withdraw) | TestR33VerifyPrizeRefreeze | high |
| gt_pool | 1 conservation (Initialize accepts a deposit) | TestR33VerifyPoolInitializeDeposit | low |

HOLDS per contract: gt_attest 5/6, gt_service 4/6, gt_prize 4/6, gt_audit 6/6, gt_beacon 6/6, gt_pool 6/7.

## Re-verification after the fixes (local-enhancements 2d433432 + gt_pool 8-byte tag)

The Go models now follow the fixed rules:
- a repeat Freeze is refused (all four);
- gt_service closes claims at (e + 11) * epoch, and Sweep(e) moves P - Q to the treasury;
- gt_service uses the no-wrap share formula;
- gt_attest has ClaimJurorFor(i, k) after h + window + commitw + 11 * revealw;
- gt_pool refuses an Initialize deposit and uses 8-byte tags (Flags + Nonce[0]; refused tags 0000000000000000 and ffffffffffffffff).

The five failing tests are now regression tests that assert each fix:

| Test | What it now asserts |
|---|---|
| TestR33VerifyAttestLivenessSilentJuror | After the deadline anyone settles the silent juror. This releases 2 units in the rejected case and 20001 in the undecided case. The contract then reaches 0. |
| TestR33VerifyServiceLivenessSilentPayer | Sweep releases the unclaimed rebate and remainder at (e + 11) * epoch. The contract then reaches 0. |
| TestR33VerifyServiceBounds | 200 x fee 10^12 pays 199,998,000,000,000 of 200,000,000,000,000. That is never above the exact share and at most about 1e-5 below it. |
| TestR33VerifyPrizeRefreeze | Every repeat Freeze is refused and rs stays fixed. The late Sybil entry is refused, and both rounds are drawn on time. |
| TestR33VerifyPoolInitializeDeposit | An install with a deposit is refused. |

New test: TestR33VerifyServiceSweepGuards. Sweep is refused when every payer has claimed, and for a sponsor-only epoch.

HOLDS after the fixes: gt_attest 6/6, gt_service 6/6, gt_prize 6/6, gt_audit 6/6, gt_beacon 6/6, gt_pool 7/7.
