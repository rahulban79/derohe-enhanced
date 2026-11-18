# R33 independent audit of the four R32 game-theory contracts

Scope: `gametheory/contracts/gt_attest.bas`, `gt_service.bas`, `gt_prize.bas`, `gt_audit.bas` at commit `dbbcf0e4` (the
working tree's contracts are identical to it). I read the DVM in `dvm/` and the chain glue in
`blockchain/transaction_execute.go`. I edited no repo file. Every PoC lives in a shared clone:

- PoC file: `<scratch>/audit_clone/dvm/r33_audit_poc_test.go`
- Run: `cd <clone> && nice -n 15 go test ./dvm/ -run 'R33' -count=1 -v`
- Result: all 17 R33 PoCs PASS, and the existing R32 suite still passes (`-run 'R32|R33'`: ok, 3.3 s).

Simulator caveat (the same one the r32 tests note): a deposit is credited to the SC but never debited from the
sender. "Received" below therefore means what the SC SENT to an address. The SC's own balance (`held`) is exact.

**Urgent.** GT-01 affects every deployed instance of all four contracts as they stand. None of them has an
`UPDATE_SC_CODE` path, so a live SCID cannot be patched. If an instance holds user funds: stop funding it, have users
withdraw what they can, and redeploy the fixed code.

---

## 1. DVM semantics the audit relies on (file:line)

| topic | behaviour | where |
|---|---|---|
| Uint64 arithmetic | `+ - *` wrap silently mod 2^64. `/` and `%` by 0 cause a Go panic, which is recovered and turns into a **revert**. | dvm/dvm.go:1057-1066; recover dvm/dvm.go:347-351 |
| `&&` / `\|\|` | **Not short-circuit.** Both sides are always evaluated, by IsZero. | dvm/dvm.go:1012-1024 |
| string + Uint64 | Appends the decimal value. String `+` is capped at 1 MiB. Strings support only `+ == !=`. | dvm/dvm.go:1001-1003, 1031-1049 |
| LOAD of a missing key | Returns an Invalid variable. `Load` then panics ("Unhandled data_type"), so the call **reverts**. | dvm/dvm_functions.go:121-133, dvm/sc.go:145-153 |
| STORE / LOAD gas | A STORE costs len(value) storage gas. **Every LOAD costs max(1, len/10) storage gas.** | dvm/dvm_store.go:88-135 |
| storage-gas limit | min(tx fee, 20000), checked only when fee > 0. | dvm/sc.go:247-254, config/config.go:46 |
| compute-gas limit | Fixed at 10,000,000 per tx. Each line costs 5000, each binary expression 800, LOAD 5000, STORE 10000, IS_ADDRESS_VALID 50000, SEND 70000. | dvm/sc.go:241, dvm/dvm.go:522, 994, dvm/dvm_functions.go:57-94 |
| hard limits | 2000 interpreted lines and 11000 evals per tx. | dvm/dvm.go:71-72, 535, 855 |
| SIGNER() | The 33-byte compressed key of the ring member, and only when the DERO payload has **ring size 2**. Otherwise it is 33 zero bytes. | blockchain/transaction_execute.go:312-316, 441-460; dvm/dvm_functions.go:307-310 |
| zero signer | `IS_ADDRESS_VALID(zero)` = 0 and `STRLEN` = 33 (PoC `TestR33AnonymousSigner`). SEND to it panics. On a revert the burn is destroyed and the fee is kept. | dvm/dvm_functions.go:324-340, 383; blockchain/sc_revert_log.go:46-58 |
| DEROVALUE / ASSETVALUE | The burn value of the tx's payloads for that asset, credited to the SC before execution. | dvm/sc.go:209-215, dvm/dvm_functions.go:434-456 |
| return ≠ 0 or panic | All STOREs and SENDs are discarded and the deposits go back to the ring-2 signer (ErrorRevert). | dvm/sc.go:281-291, blockchain/transaction_execute.go:411-422 |
| SEND_DERO / SEND_ASSET | An amount of 0 is a no-op. An invalid address panics. Sends are only queued; after success the SC balance is checked for underflow, and an over-send **reverts the whole call**. The SC's own token is minted without limit. | dvm/dvm_functions.go:377-432, dvm/simulator.go:203-245, dvm/sc.go:395-398 |
| reentrancy | There are no cross-SC calls. Transfers are applied after the function returns (ProcessExternal), so classic reentrancy is impossible. | dvm/simulator.go:308+ |
| entrypoints | Any function whose name starts with an upper-case ASCII letter is callable by anyone with SC_CALL, **including `Initialize` and `InitializePrivate`**. Nothing in the chain code excludes them. | dvm/dvm.go:344-377, blockchain/transaction_execute.go:373-395 |
| Initialize vs InitializePrivate | The install runs `InitializePrivate` if it exists (meta Type 1), else `Initialize`. Neither is protected afterwards. | blockchain/transaction_execute.go:341-355 |
| RANDOM | Keyed by (SCID, BLID, TXID), so the block producer can influence it. **None of the four contracts uses RANDOM, BLOCK_TIMESTAMP, BLID or TXID.** | dvm/dvm.go:375, dvm/dvm_functions.go:253-269 |
| BLOCK_HEIGHT | The height of the block that includes the tx. Inclusion timing is chosen by the sender and the block producer. | dvm/dvm_functions.go:289 |

---

## 2. Findings

### GT-01 (critical, CONFIRMED): anyone can call `Initialize` again, on all four contracts
- **Location:** gt_attest.bas:13-29, gt_service.bas:11-23, gt_prize.bas:14-31, gt_audit.bas:34-44
- **Problem:** `Initialize` is an ordinary exported entrypoint. A stranger who calls it after `Freeze` becomes owner,
  sets `frozen` back to 0 (which defeats the anti-rug freeze), and resets the counters: attest `nc`/`minted`, service
  `treasury`, prize `rd`/`n0`/`rs`, audit `na`/`carry`.
- **Takeover on all four contracts:** `TestR33ReinitByAnyone`. A stranger's SC_CALL `Initialize` after Freeze leaves
  owner = stranger and frozen = 0 on every contract.
- **Full drain of gt_prize (`TestR33PrizeReinitDrain`):**
  1. Round 0 is drawn. Honest a and b have not withdrawn yet, so the SC holds 100,000.
  2. Mallory calls `Initialize`, then `SetParams(rbond=1)` and `Freeze`.
  3. Mallory calls `Enter` with 2 atomic units. This overwrites entry `0_0`, which was a's record. She then reveals.
  4. Mallory calls `Initialize` again. `drawn0` survives the reset.
  5. Mallory calls `SetParams(rbond = balance-1)`, then `Withdraw(0,0)` and receives **100,002, the whole balance**.
  6. a's `Withdraw` fails because the record was overwritten. b's `Withdraw` fails because the SC is empty.
- **Drain of gt_service (`TestR33ServiceReinitEpochDrain`):**
  1. Epoch 2 has already been paid out: its pool `P2` = 101,500 is fully claimed.
  2. The SC holds 52,500 (treasury 2,000 plus the epoch-3 pool 50,500).
  3. The attacker calls `Initialize` and `SetParams(fee=3000, rho=100, boost=0, epoch=155)`. With epoch = 155 the
     current height 310 maps to epoch index 2 again.
  4. The attacker calls `Notarize` (pays 3,000), then `ClaimRebate(2)`.
  5. The attacker receives **52,250**, computed from the stale `P2`. u2's epoch-3 rebate now reverts, and the real
     owner has lost both the treasury and ownership.
- **attest and audit:** after `nc`/`na` are reset, new claims and rounds overwrite `c0…` and `a0_…`. Pending bonds and
  unwithdrawn credits lose their records and are locked for good. The attacker can also pick new
  `reward`/`slash`/`bond`, which gives unlimited MAT and changes the slash split mid-dispute.
- **Fix (each contract):** make the first line `5 IF EXISTS("owner") == 1 THEN GOTO 999` with `999 RETURN 1`. Also
  require `IS_ADDRESS_VALID(SIGNER())` (see GT-12). Redeploy, because live SCIDs cannot be patched.

### GT-02 (critical, CONFIRMED): gt_attest juror stake is reused across disputes, and slash payouts exceed what can be collected
- **Location:** gt_attest.bas:137-145 (weight `w = st` is not locked), 226 (winners paid `inc*slash/100`), 229-233
  (loser cut capped at the remaining `st`)
- **Problem:** one stake S is counted at full weight in every dispute, as long as the juror delays `ClaimJuror`. Each
  dispute promises winners `S*slash/100`, but across all disputes the loser can be cut by at most S. The difference
  is paid out of other users' stakes and bonds.
- **Scenario (`TestR33AttestStakeReuseDrain`):** the attacker controls addresses C, X, L and W; honest H has 5,000,000
  staked.
  1. Claimant C opens 20 claims with k=1. Challenger X challenges each one.
  2. L (stake 1,000,000) commits on all 20 and never reveals.
  3. W (stake 100,000) commits and reveals yes on all 20.
  4. Each `Finalize` pays C 150,000. Each `ClaimJuror` pays W 50,000 + 100,000. L's cut stops at 1,000,000.
- **Result:** the attacker puts in 5,100,000 and takes out 6,100,000, **net +1,000,000**. The SC is left with
  4,000,000 against H's 5,000,000, and H's `Unstake(5000000)` reverts. This scales as
  S·(N·slash/100 − 1), with N unbounded over time.
- **This also contradicts mechanisms.json M1**, which says bonds and slashes are zero-sum inside one dispute.
- **Fix:** escrow the stake per commit: at `CommitVote` move w out of `st` (`st -= w`, `p+"w"+S = w`). In `ClaimJuror`
  return `w - cut` to `st` for a loser, or `w + pay` for a winner. Alternatively, pay winners only from slashes
  already collected.

### GT-03 (high, CONFIRMED): gt_audit `Settle` can be gassed out, which locks the bounty and every bond for good
- **Location:** gt_audit.bas:166-286 (the O(n²) majority scan), 134/148 (answer length unbounded)
- **Compute gas.** The scan costs about 34k gas per pair, against a fixed limit of 10M.
  - All revealed answers distinct (`TestR33AuditSettleLineLimit`): n=8 costs 5.73M, n=10 costs 8.09M, and
    **n ≥ 12 reverts with "Insufficient Gas"**. Default maxn is 16, and SetParams allows 32.
  - Grief sweep (`TestR33AuditSettleGriefSweep`): k Sybils with distinct junk answers enter first, then 16−k honest
    auditors agree with the revealed sponsor answer. Up to k=6 Settle passes (9.62M). **k=7 (7 bonds = 0.7 DERO) makes
    Settle revert forever**, as does k=8.
  - Neither `Withdraw` nor carry can then reach the bounty or the 16 bonds.
- **Storage gas (`TestR33AuditSettleStorageGas`).** Settle re-LOADs every answer O(n) times, and each LOAD costs
  len/10 storage gas.
  - Four entrants reveal 9.8 KB answers; each Reveal fits under the 20,000 fee cap at 19,722.
  - Settle then needs 31,540 storage gas and **reverts at the 20,000 cap**.
  - Rescue is only possible with a fee-0 tx, which disables the check (dvm/sc.go:247). I found no consensus
    minimum-fee check, but I did not verify whether fee-0 SC txs are mined.
- **Fix:**
  - In `Reveal`, require `STRLEN(answer) == 64` (the answers are hex digests).
  - Count votes in `Reveal` (`p+"k"+answer` += 1, keep the leader and its count), so `Settle` is O(n) with no inner
    loop.
  - Measure Settle at maxn and cap maxn so the worst case stays below about 7M.

### GT-04 (high, CONFIRMED): gt_audit Sybil majority overrides a revealed, correct sponsor answer
- **Location:** gt_audit.bas:184, 192-193, 360 (majority beats `sa`), 100-103 (first-come entry up to maxn)
- **Scenario (`TestR33AuditSybilMajority`):** the sponsor posts 100,000 with answer "good" and reveals it. Honest A
  answers "good". Sybils S1 and S2 answer "junk". The result is credits A = 0 (bond forfeited) and S1 = S2 = 50,000 +
  bond, with disp=1.
- **Generalisation:** one party can fill all maxn slots early in the commit window and take every bounty without
  auditing at all, at zero cost because the bonds come back. The header lists Sybils as "not prevented", but this is
  the direct bounty-theft path, not just a detection-quality issue.
- **Fix:** when the sponsor revealed, pay only answers equal to `sa`. A dissenting majority should only set `disp=1`
  and refund bonds (bounty → carry), never receive the bounty. Also add a minimum bond that scales with the bounty
  divided by maxn.

### GT-05 (high, CONFIRMED): gt_prize reveal withholding is free, because the forfeited bond is paid into the prize the withholder wins
- **Location:** gt_prize.bas:127-143 (Reveal), 157-162 (forfeits added to the same round's prize), 138 (commit not
  bound to the address)
- **Scenario (`TestR33PrizeWithholdBias`):** honest H and attacker Sybils A1 and A2 each enter 1000 + rbond.
  1. H reveals. A1 and A2 then pick which subset of their entries to reveal.
  2. Over 200,000 trials the attacker wins **91.6 % instead of the fair 66.7 %**.
  3. On chain, with nums 500/600/2000: revealing both would make H win. A2 withholds and A1 wins.
- **Payoff:** A1 receives 1000 + rbond + 7000 + rbond, and A2 gets its 1000 principal. That is net **+7000, the whole
  sponsor prize**, because A2's forfeited bond is inside the prize A1 collected.
- **This refutes mechanisms.json M3**, which says withholding is unprofitable while prize ≤ rbond·(n−1). With k
  Sybils the attacker chooses among 2^k outcomes.
- **Fix:**
  - Send forfeited bonds to the next round, or burn them to a fixed sink. They must never go into the current prize.
  - Require rbond ≥ prize per entry, or lock principal until reveal.
  - Bind the commit to the address: `ITOA(n)+":"+salt+":"+ADDRESS_STRING(SIGNER())`.
  - Note that commit-reveal cannot remove last-revealer bias entirely; it can only make it costly.

### GT-06 (medium, CONFIRMED): gt_prize Sybils fill `maxn` and take sponsor funds without risk
- **Location:** gt_prize.bas:103-104
- **Scenario (`TestR33PrizeSybilFill`):** 32 Sybils enter with 1 atomic principal each. The honest entry is refused
  ("round full"). A Sybil wins the 7000 Fund, and every Sybil withdraws its principal and bond. An attacker can repeat
  this from the Draw block of every round.
- **Fix:** add a minimum principal, raise maxn (a 64-entry Draw costs 5.04M compute, `TestR33PrizeDraw64`), and/or
  weight the Fund only on principal above a floor.

### GT-07 (high, CONFIRMED): gt_attest Sybil self-challenge shuts out honest challengers, and a false claim mints with both bonds back
- **Location:** gt_attest.bas:90-93 (a single challenge slot), 184 (`no > yes`, else the claimant wins; a 0:0 tie
  favours the claimant), 189-195 and 300 (claimant gets 2b)
- **Scenario (`TestR33AttestSelfChallenge`):**
  1. A false claim with k=10 is challenged at once by the claimant's own Sybil.
  2. The honest `Challenge` reverts ("already challenged").
  3. No juror reveals. `Finalize` gives the miner **2b (both bonds) and 1000 MAT** at zero net cost.
- **Impact:** forged MAT buys a 2× boost in gt_service and gt_prize. Together with GT-02 (cheap juror weight),
  forging MAT costs only locked capital.
- **Fix:** allow several challengers per claim (or an escalation round). With no quorum, or a tie, refund both sides
  and mint nothing.

### GT-08 (medium, CONFIRMED): gt_attest juror commits are not bound to the juror, so they can be copied
- **Location:** gt_attest.bas:141-142, 162
- **Scenario (`TestR33AttestCommitCopy`):** j2 copies j1's 64-hex commit from the chain. After j1 reveals, j2 reveals
  with j1's now-public salt and earns 25,000 without evaluating the claim. This defeats Schelling independence and
  lets Sybil jurors mirror a leader.
- **Fix:** hash `ITOA(i)+":"+ITOA(vote)+":"+salt+":"+ADDRESS_STRING(SIGNER())`, as gt_audit already does.

### GT-09 (medium, CONFIRMED mechanically / design): an unchallenged claim mints after 20 blocks
- **Location:** gt_attest.bas:17 (window 20 ≈ 6 min at 18 s/block), 178-181 → 504-507
- **Problem:** the DVM cannot read block headers, so any claim nobody challenges within about 6 minutes mints
  k·reward MAT. `TestR32GTAttestHonestUnchallenged` shows nothing checks the claim. The integrity of MAT depends on a
  watcher being online every 6 minutes, and the boost in M2/M3 inherits that risk.
- **Fix:** use a longer window (hours), mint only after a challenge-free period, or cap MAT per epoch.

### GT-10 (medium, CONFIRMED): gt_service sponsor funds in an epoch with no fee payer are stuck forever
- **Location:** gt_service.bas:96-105, 138-140
- **Scenario (`TestR33ServiceSponsorStuck`):** `Sponsor(100000)` in epoch 2 with no `Notarize`. `ClaimRebate` needs a
  `w` key and W > 0, so no path ever pays out, and the SC holds the 100,000 indefinitely.
- **Fix:** when an epoch ends with W = 0, roll P(e) into P(e+1), or let the sponsor reclaim it.

### GT-11 (low, CONFIRMED): gt_attest with minstake = 0 hits a division by zero and locks a juror's stake
- **Location:** gt_attest.bas:44, 138, 189, 226
- **Scenario (`TestR33AttestZeroWeightDivZero`):** a juror with st = 0 commits weight 0 and reveals yes, so cwin = 0.
  `ClaimJuror` then divides by zero and reverts forever, `pd` stays 1, and any later Stake is permanently
  un-unstakeable. This needs the owner to set minstake = 0, or an attacker to do it after GT-01.
- **Fix:** in SetParams require `minstake > 0`. In CommitVote require `w > 0`.

### GT-12 (low, CONFIRMED): an anonymous install makes every anonymous caller the owner
- **Location:** all `Initialize` functions (`STORE("owner", SIGNER())`)
- **Scenario (`TestR33AnonymousSigner`):** gt_service is installed with ring > 2, so owner = 33 zero bytes. Any
  anonymous caller then passes `SetParams` and `Freeze`. `WithdrawTreasury` can never pay, because SEND to the zero
  key panics.
- **What is safe:** the participant entrypoints (Claim, Challenge, Stake, Notarize, StakeMAT, Enter) reject anonymous
  callers, because `IS_ADDRESS_VALID(zero)` = 0.
- **Fix:** in Initialize, `IF IS_ADDRESS_VALID(SIGNER()) == 0 THEN GOTO 999`.

### GT-13 (low, CONFIRMED / PLAUSIBLE): funds with no owner and no sweep
- **attest:** slashed stake when no coherent winner exists. With cwin = 0 the cut leaves `st` but is paid to nobody
  (`TestR32GTAttestNoJurorsUpholds`: 10,000 orphaned). Floor remainders at line 226 are also orphaned.
- **service:** floor remainders at line 141.
- **All four:** DERO or other assets sent to entrypoints that never read `DEROVALUE()`/`ASSETVALUE()`. Examples:
  Unstake, CommitVote, RevealVote, Finalize, ClaimJuror, StakeMAT (DERO), UnstakeMAT, ClaimRebate, Reveal, Draw,
  Withdraw, Settle, RevealSponsor. This only happens by user error (PLAUSIBLE).
- **Fix:** add `IF DEROVALUE() != 0 THEN GOTO 900` where no deposit is expected, and add an owner sweep of the
  accounted surplus (balance − liabilities).

### GT-14 (low, PLAUSIBLE): reveal censorship by block producers
- **Location:** gt_prize Reveal, gt_attest RevealVote, gt_audit Reveal
- **Problem:** an integrator who mines the last blocks of a reveal window can leave out a competitor's reveal, which
  forfeits the competitor's bond (in gt_prize, into the prize). The 10-20 block windows across several integrators
  only mitigate this. It cannot be tested in the simulator.
- **Fix:** longer reveal windows, and send forfeits away from the same round's prize (GT-05).

### GT-15 (info, PLAUSIBLE): silent Uint64 wrap in owner-parameterised products
- **Locations:**
  - gt_attest:68 `k*bond`: with bond = 2^63 and k = 2, b wraps to 0 and the claim is free.
  - gt_attest:226 `(pool+inc*slash/100)*w`: needs more than 1.8e19.
  - gt_service:141 `P*w`.
  - gt_prize:160 `a*(100+boost)`: prize SetParams does not bound `boost`.
- **Impact:** a wrap only underpays (funds get stuck) or needs extreme parameters. It becomes reachable when combined
  with GT-01.
- **Fix:** bound the parameters in SetParams (bond·maxmb·maxspan < 2^63, boost ≤ 1000). Compute `P / W * w` with a
  remainder, or check the operands before multiplying.

### GT-16 (info): gt_service notarization records no author, and its digest can be front-run
- **Location:** gt_service.bas:71-72
- **Problem:** `d+doc` stores only the height. A front-runner who copies the digest from the mempool makes the
  victim's tx revert (the victim's deposit is refunded). The record proves the digest existed, but not who submitted
  it.
- **Fix:** store `SIGNER()` with the height. A commit-then-publish flow prevents the front-run.

### GT-17 (info, design): claims are not bound to real mining
- **Location:** gt_attest Claim
- **Problem:** any address can claim any past range, and per-address `lc` does not stop Sybil addresses from claiming
  the same miniblocks. Off-chain jurors are the only check, which ties back to GT-02, GT-07 and GT-09.

---

## 3. Checked and found safe

| check | result |
|---|---|
| Owner checks | SetParams, SetMAT, Freeze, Post, RevealSponsor and WithdrawTreasury compare `LOAD("owner")` with SIGNER(), and the params cannot change after Freeze. Both hold **except** through GT-01 and GT-12. |
| Double withdraw / settle | Flags are set before every SEND: prize `x`, audit `x` and `st`, service `z`, attest `z` and the `s` state (0→1→2/3). Finalize, Draw and Settle cannot run twice. With no cross-SC calls and SENDs applied after return, there is no reentrancy. |
| Per-dispute / per-round accounting (single instance) | attest: 2b in = 2b out on every Finalize path (unchallenged b, yes with or without coherent winners, no). prize: principal + rbond back exactly, and forfeits go to the prize. audit: Σcredits + Δcarry = bounty + n·bond in both md=1 and md=2. service: P + treasury = fees + sponsor. Over-sends revert through the post-run underflow check. |
| Underflows | Unstake, UnstakeMAT and WithdrawTreasury bound the amount by the stored balance. `upto - from` comes after the `upto ≥ from` check. `cw - cwin` holds because cwin ⊆ cw. The `pd - 1` is guarded by the `z` flag. In audit `rem = b - share*nw` is ≥ 0. |
| Window boundaries | All consistent: commit at h ≤ start+cw; reveal at start+cw < h ≤ start+cw+rw; settle/draw/finalize at h > start+cw+rw; attest challenge at h ≤ h0+window and unchallenged finalize at h > h0+window. |
| Cross-round replay | The attest commit includes `i`. The audit commit includes the address, and entries are stored per round. Prize entries are keyed per round `q`. A copied old commit gives nothing (gt_prize copying within a round is covered by GT-05). |
| Anonymous callers | Blocked on every value-in participant entrypoint (`IS_ADDRESS_VALID(zero)`=0). Fund and Sponsor accept anonymous deposits by design. |
| Storage-key collisions | Every per-user key ends in the fixed 33-byte signer. Numeric parts are followed by a letter or `_`. gt_service `d+doc` cannot collide, because no other key starts with `d`. No collision found. |
| RANDOM / timestamp grinding | Not applicable: no contract uses RANDOM, BLOCK_TIMESTAMP, BLID or TXID. |
| Gas outside gt_audit Settle | gt_prize Draw at maxn = 64 uses 5.04M compute and passes (`TestR33PrizeDraw64`). The attest and service entrypoints are O(1). |
| MAT boost locks | service `ml` (epoch) and prize `ml` (round) stop the same MAT from boosting two addresses in the same epoch or round. |
| No-wash rule (service) | `rho*(100+boost) ≤ 10000` holds per payer as documented. Under GT-01 an attacker can re-set it. |
| LOAD on a missing key | Reverts. Every index argument is range-checked before LOAD (`i < nc`, `a < na`, `j < n`, EXISTS guards). |

## 4. Fix priority
1. **GT-01:** guard `Initialize` and redeploy all four contracts. Treat the live SCIDs as compromised for any funds
   they hold.
2. **GT-02:** escrow juror stake per commit.
3. **GT-03 and GT-04:** an O(n) tally, 64-byte answers, and pay only `sa` matches when the sponsor revealed.
4. **GT-05 and GT-07:** forfeits leave the round, multiple challengers, and no mint without a quorum.
5. **GT-08:** bind commits to the address.
6. Then GT-06, GT-09, GT-10, GT-11, GT-12 and GT-13.
