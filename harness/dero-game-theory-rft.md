# DERO HE — the game-theory round prompt (child RFT): DVM, smart contracts and miner incentives

> **What this is.** The CHILD round file of `artifacts/dero-rft.md` (the parent). The user delegated Round 32 to this
> file (2026-11-15): "for R32, park all those broad enhancements AND the miner enhancements" and "100% focus on DVM and
> smart-contract enhancements" with game-theoretic mechanisms for running DERO smart contracts. The parent keeps its
> carry list as PARKED items (parent §0.3, §0.12 D-37, §8 "R32 carry (PARKED)") and resumes compounding when the user
> asks. This file compounds the game-theory track from round 32 on, with the parent's style of execution: the
> evidence loop, decide-don't-ask (parent §0.11), a decision log, update logs written at two fixed points (§12 after
> implementation, §13 after measurement), and every number copied from the anchor next to it. Write `pending` for
> anything not measured; never put a guess in its place.
>
> - **Parent:** `artifacts/dero-rft.md` (its §0.12 D-37 records the delegation; its §13 R32 row points here).
> - **Created:** r32, 2026-11-15, by the R32 coordinator, base commit 5f69b055 (R31 closed).
> - **Artifact:** `artifacts/dero-enhanced-game-theory.html` (+ `.pdf` printed from it): architecture, mechanisms,
>   animated flows, the pipeline and playbook flows, and the manual runbook.
> - **Privacy:** the home directory is written `~`; the user's wallet address is never written (it is banned by hash,
>   D-GT-2); the new wallets' seeds live only in `<home>/dero-wallets/gt/` (mode 700), never in the repo, artifacts or logs.

## How to start (every round the same)

```
ls <home>/derohe-persist/scratchpad/                                     # 1. prior rounds' scratch; reuse it
cat <home>/derohe-persist/round_state/r32_NOTES.md                       # 2. the round notes (pause/resume: parent §0.10)
cd <repo> && wc -l artifacts/dero-game-theory-rft.md   # 3. read this file in slices
python3 -I harness/intel/resource_intel.py preflight                # 4. the box before any fan-out
python3 -I harness/gametheory/banguard.py status                    # 5. the private ban list is present (D-GT-2)
python3 -I harness/gametheory/gt_pipeline.py                        # 6. the zero-touch pipeline re-proves the layer
python3 -I harness/gametheory/gt_gate.py                            # 7. gate G35
python3 -I harness/kat/test_gt_mechanisms_r32.py                    # 8. the game-theory KATs + mutations
```
Then §0 → §1 (the prompt) → §6 (the procedure) → §7/§8 (what to work on). The sim-chain playbook run is the
harness-tracked background job of §6 step 6 (stallwatch + DONE marker).

Contents: §0 the loop, instruments and decision log · §1 the prompt to paste · §2 the user's words · §3 the evidence
loop · §4 goals honestly sized (the economics) · §5 constraints · §6 the procedure · §7 OPEN backlog · §8 dimension plan
· §9 NO-GO ledger · §10 lessons · §11 the research dossier · §12 update log after implementation · §13 after measurement.

---

## 0. The loop, its instruments, and the decision log

### 0.1 Protocol
1. Open loop first (several strategies: web research, code reading, live read-only sampling of mainnet, DVM
   experiments), then closed loop: Discover → Plan → Execute → Verify → Iterate, with a gate after every step
   (`EVIDENCE_LOOP_PROMPT.md`, `evidence_loop_diagram.svg`; parent §3).
2. Every claim names its evidence: code (file:line), a test, a measured run record, or a cited source. Discussion,
   forums and blogs only steer (class `steer`, parent §0.8.10); they never count as evidence.
3. A finding that would change DVM semantics, gas prices or the reward is consensus: it becomes a disclosure-style row,
   never a local change (parent D-21; consensus guard S1 / G13 must PASS).
4. Every decision is taken from the instruments and logged in §0.4 (decide, don't ask).

### 0.2 The instruments and their two update points

| instrument | file | after implementation (§12) | after measurement (§13) |
|---|---|---|---|
| contracts (DVM-BASIC) | `gametheory/contracts/gt_attest.bas`, `gt_service.bas`, `gt_prize.bas` | lint + DVM tests | sim-chain run |
| mechanism registry (GO / NO-GO) | `gametheory/mechanisms.json` | status, equilibrium, attacks | measured outcomes |
| DVM tests | `dvm/r32_gametheory_test.go` (9 tests), `cmd/simulator/r32_getwork_bind_test.go`, `cmd/gt-wallet/main_test.go` | PASS | gas census |
| reward anchors + live sampler | `harness/gametheory/reward_anchors.json` (59), `reward_intel.py`, `blockchain/r32_reward_split_test.go` | `--check` | `--live` record |
| economics | `harness/gametheory/econsim.py` (14 checks) | checks | parameters |
| ban guard | `harness/gametheory/banguard.py` + private `<home>/derohe-persist/gt-private/banned_addresses.json` | KAT GT1/GT2 | scan |
| zero-touch pipeline | `harness/gametheory/gt_pipeline.py` → `harness/runtime/gt_pipeline_last.json`, `harness/loop/runs/gt_pipeline_<ts>.jsonl` | stages 1–5 | stage 6 (`--sim`) |
| gate | G35 `harness/gametheory/gt_gate.py` (wired in `harness/run_gates.py`) | PASS | PASS |
| KATs | `harness/kat/test_gt_mechanisms_r32.py` (7 KATs, 14 mutations), `harness/kat/test_gt_reward_r32.py` (7, 17) | PASS | — |
| playbooks (no LLM) | `playbooks/gt_playbook.py`, `playbooks/gtlib.py`, generated `playbooks/params_r32.json` | dry run | sim run report |
| sim chain tools | `cmd/simulator` `--getwork-bind` (opt-in), `cmd/gt-wallet` | Go tests | sim run |
| research dossier | `gametheory/research/dossier.md`, `sources.json`, `reward_analysis.md` | stage research | — |
| artifact | `artifacts/dero-enhanced-game-theory.html` / `.pdf` | built | numbers refreshed |
| round state | `<home>/derohe-persist/round_state/r32_NOTES.md`, `r32_DUE.json`, `r32_RESUME.md` | kept current | kept current |

### 0.3 The parked tracks (parent)
The parent's broad tracks (node, observability, cryptography, forensics, harness) and the miner track are PARKED for
R32 by the user's word (§2). Their carry list is the parent's §8 "R32 carry (PARKED)", unchanged. Nothing in R32
touches the miner track's code (`cmd/dero-miner/` is unchanged; the playbooks run a copy of the installed binary under
the name `gt-dero-miner`, so the harness census never mistakes it for the user's miner).

### 0.3a The success criterion (D-GT-5; gate G36)
R32 is not reported DONE until ONE FULL MAINNET CYCLE is measured end to end: (1) a new wallet is registered; (2) the
pipeline-owned miner credits real DERO to it, verified by the wallet balance AND the chain scan; (3) mined coins fund the
role wallets; (4) a contract is deployed on mainnet (SCID kept private; only scrubbed facts go public); (5) at least one
game round is played and settled, payoffs measured. Sim-only passes do not count. Until then the round is IN PROGRESS
with the exact blocker (G36 INFO). The sim chain is the PRE-FLIGHT only: it gates code before real DERO touches it.

### 0.4 Decision log (newest last; mirrored as one row D-37 in the parent §0.12)

| ID | Date (PST) | Question | Options | Choice | Why best for quality | Evidence | Re-check |
|---|---|---|---|---|---|---|---|
| D-GT-1 | 2026-11-15 01:00 | Where may on-chain actions run? | (a) mainnet; (b) a private chain, mainnet only dry-run + user-confirmed | (b) coordinator | Spending real DERO or starting a mainnet miner are user actions (parent D-1); a private chain gives the same code path with fake value | `playbooks/gtlib.py` NETWORKS, `Run.user_action_gate`; KAT GT7 | every round |
| D-GT-2 | 2026-11-15 01:00 | How is the user's own address kept out? | (a) a literal deny list; (b) sha256 only, in a private file | (b) coordinator | The address is never written; the guard compares hashes, fails closed, and is proved by GT1/GT2 (GT2 reads the real address from the private launch config, never prints it) | `harness/gametheory/banguard.py`; private file: 1 hash, sources the two memories and the launch plist (all agree) | GT2 each run |
| D-GT-3 | 2026-11-15 01:00 | What may a mechanism promise? | (a) more block reward; (b) only what DVM primitives allow | (b) coordinator | No builtin exposes the miner or integrator (discovery stage, 37 builtins; `Blockchain_Input` fields SCID, BLID, TXID, Signer, BL_HEIGHT, BL_TOPOHEIGHT, BL_TIMESTAMP); the reward is `CalcBlockReward(h)` (reward anchors RW06) | `harness/gametheory/gt_pipeline.py` discovery; `reward_analysis.md` §4 | each round |
| D-GT-9 | 2026-11-15 01:16 | Which private chain? (logged first as D-GT-4; renumbered when the user's mainnet decision took D-GT-4) | (a) `derod --testnet` isolated; (b) `cmd/simulator` + an opt-in loopback getwork | (b) | Difficulty 1, no peers, a fresh chain per run (it removes its data dir), wallet registration without waiting; derod has no simulator flag. Two code changes, both non-consensus: `--getwork-bind` (refused unless loopback and not 10100; `TestR32SimulatorGetworkRefusal`) and the integrator set to the genesis wallet (the default Dev_Address is not registered on the sim chain, so every template failed: "miner address is not registered") | `cmd/simulator/simulator.go`; smoke run 2026-11-15 01:16 (height 97 in 15 s) | testnet path is a plan only (`gt-derod` not built) |
| D-GT-10 | 2026-11-15 01:30 | (logged first as D-GT-5; renumbered when the user's mainnet-primary decision took D-GT-5) M3 v1 mixed RANDOM (keyed by the block id) into the draw: keep it? | (a) keep; (b) draw from the revealed seed only | (b) | The reward analysis shows the final share + leftover go to the integrator, so the Draw block's integrator can withhold that block to re-roll at the cost of one share (3,075 atomic today); without RANDOM no re-roll exists and the only bias is the last revealer's, bounded by rbond. Measured: Draw gas 2,835,500 → 1,774,800 for 32 entries | `gametheory/contracts/gt_prize.bas` line 180; econsim check "M3 v1 … would let the Draw integrator re-roll"; `dvm/r32_gametheory_test.go` TestR32GTGasBound | each round |
| D-GT-6 | 2026-11-15 01:33 | What MAT value do the parameters assume? | (a) none (contract defaults); (b) a stated assumption, swept | (b) | The bond deters inflation iff bond > (1-c)·r·v/c (econsim); v is unknown, so the pipeline assumes the boost a MAT buys is worth 10 % of the miniblock reward it attests (`BOOST_SHARE`), derives the critical bond and sets bond = max(floor, 2 × critical): mainnet keeps the 1-DERO default (critical 307.5 atomic), sim 2,000 (critical 104.3) | `playbooks/params_r32.json`; `harness/gametheory/gt_pipeline.py` enhancement | when a MAT market exists |
| D-GT-7 | 2026-11-15 ~02:20 | The user (relayed verbatim): "modify wallet balances and no. of wallets involved decision depending on project's evolving intelligence through its harness to achieve round 32 objectives" (amends D-GT-6). Who decides the wallet count and targets from now on? | (a) fixed 2 x 4 DERO; (b) a harness-computed, recorded decision from measured data, the D-GT-6 start as its default | (b): `harness/gametheory/sizing.py` (rules R1-R4, KAT GT8, 18/18 mutations), record `harness/runtime/gt_sizing_last.json`, run by the gt_pipeline enhancement stage | Reproducible without an LLM; only MEASURED mainnet mining may change the wallet count (an estimate never decides); a first-cycle cost above a target raises it x2 margin. First decision 2026-11-15T02:09:51-08:00: N 2, targets {'m1': '4.00000', 'm2': '4.00000'}, measured DERO/day None (no mainnet mining yet), estimate 21.941; the mainnet M1 bond became 2 x critical (615 atomic per miniblock) instead of the 1-DERO default, which alone would have cost m1 10 DERO for a 10-miniblock claim | `harness/runtime/gt_sizing_last.json`; `playbooks/params_r32.json` mainnet | every gt_pipeline run; each change is a dated §13 row |
| D-GT-8 | 2026-11-15 ~04:05 | The user (relayed verbatim): "enhance the coordinator to start the two-wallet mainnet game between m1 and m2 1 dero each - smart contracts can be fraction of dero also - but all this game need to be economically viable and should meet the round 32 objectives coherently" (amends D-GT-6/7: start at 1 DERO each). When does the game start and with which stakes? | (a) start at 1 DERO with fixed stakes; (b) a KAT-tested viability gate decides the plan from real costs, refusing if none passes | (b): `harness/gametheory/sizing.py` viability() + plan_two_wallet() (KAT GT12), trigger `playbooks/gt_trigger.py` (settled balances >= 1.00000 DERO each, 8 blocks below the tip), runner `playbooks/gt_cycle.py --plan` | THE ZERO-SUM TRUTH: in a closed two-wallet game the payoffs sum to −fees, so both cannot gain; the gate evaluates ROLES: each participant's EV (its share of the sponsor-funded prize minus its recurring fees) >= 0, the sponsor (m1) buys activity with a budget (price per call recorded), (a) recurring fees <= 10 % of a stake per round (a no-loss pool returns >= 90 % of principal to a player who never wins; the design bound), (c) the MAT boost (earned only by mining to the same address) adds EV, (d) no Ponzi, (e) spend <= 75 % of each 1-DERO budget. At the estimated fees (336 atomic per call, 1,000 per install) the cheapest passing plan is 5 rounds of M3 at principal 0.30000 DERO, sponsor 0.04000 DERO per round, M1 claim k <= 10 at 615 atomic/miniblock: participant EV m1 +986.7, m2 +325.3 atomic per round, MAT boost +666.7 atomic per round, fee fraction 9.84 %, spend m1 71,910 / m2 36,040 atomic of 100,000; M2 (notary) is not in the plan (its fee is a cost without a cash return in a closed game). Maturity: no coinbase lock in code (credit at block execution, transaction_execute.go:142/:157; wallet locked = 0, walletapi/wallet.go:280-288); 'settled' = read >= STABLE_LIMIT 8 blocks below the tip (config/config.go:79) | `harness/runtime/gt_plan_mainnet.json` (written at the trigger); KAT GT12 | the trigger's viability event; re-planned with measured fees after the deploy |
| D-GT-7 | 2026-11-15 01:34 | The sim run showed every wallet holding about 1,000 DERO: a bug? | (a) a bug; (b) the testnet/simulator registration grant | (b) | `blockchain/transaction_execute.go:186-187` credits 100,000,000 atomic to every registration off mainnet; the report now separates grant, funding, mined (from the public headers) and the game net | `playbooks/gt_playbook.py` report / `mined_by_chain` | each sim run |
| D-GT-4 | 2026-11-15 ~01:55 | The user (relayed verbatim by the coordinator): "note: for new wallets - the pipelines, agents, code is free to experiment with those in any form or way to achieve round 32 objectives. also first some coins needs to be earned for those new wallets thtough automated mining through pipelines of round 32". It supersedes the mainnet part of D-GT-1: may the pipelines mine mainnet to the NEW gt wallets via the local getwork 127.0.0.1:10100 and spend their mined DERO on mainnet SC deploys/invokes? | (a) run it now, removing the --mainnet-confirm gate for the new wallets; (b) build it behind the gate and hand the start to the user | (b), forced: this session's permission system REFUSED both the mainnet registration send ("Destructive or Unwanted Actions") and the gate removal ("Undermining Oversight"); a refused action is never worked around | The authorisation arrived through an agent, not from the user in this session, and the session's own permission system is the arbiter; the code path, the plan and the time-to-coins estimate are built and tested read-only, the run is one user command | `playbooks/gt_earn.py` (register with txid PoW, pipeline-owned miner nice 15 8 threads cpu-max 80, earn.jsonl with wallet balance AND chain-credited miniblocks); `harness/gametheory/time_to_coins.py` → `harness/runtime/gt_time_to_coins.json` (pinned record: live difficulty 2,281,427: network normal-phase 2,051,069 H/s, ours 34,202 H/s, f 0.0164, 713.5 miniblocks/day, 21.941 DERO/day, first miniblock 121.1 s, 1 DERO in 1.11 h; an earlier read at difficulty 1,959,073 gave 0.96 h: the estimate moves with difficulty); `cmd/gt-wallet` `--pow-threads`; `<home>/derohe-persist/round_state/r32_DUE.json` U-MAINNET-EARN | the user runs U-MAINNET-EARN (or grants the permission); then GT-B9 |
| D-GT-5 | 2026-11-15 ~02:10 | The user (relayed verbatim): "i want real wallet on mainnet and not this testnet chain -> will that be adopted finally by the pipelines and measured and used to develop various game therories ?" and "this is because i need a working real solution and not just simulation". What is the R32 track and when is the round done? | (a) sim results as the round's results; (b) MAINNET is the primary measured track, the sim chain only a pre-flight gate for code before real DERO; the round is DONE only when one full mainnet cycle (register → mined + credited → roles funded → contract deployed → a game settled) is measured | (b) (coordinator) | The user's words; sim numbers are never reported as results. Gate G36 (`harness/gametheory/gt_gate.py` g36, record `harness/runtime/gt_mainnet_cycle.json`) reports INFO 'IN PROGRESS' with the blocker until all five steps are measured. Built for it: `playbooks/gt_earn.py` (full wallet set, registration PoW, a pipeline-owned miner ROTATING among m1,m2,m3 so each earns, balance + chain-scan per minute). Blocker: the session's permission system refused the m1 registration a second time (2026-11-15) | G36 record; `<home>/derohe-persist/round_state/r32_DUE.json` U-MAINNET-EARN | every run of G36 |
| D-GT-6 | 2026-11-15 ~02:15 | The user (relayed verbatim): "fill each real wallet (start with 2 wallets - as smart contract minimum needs two wallets?) with 4 deros each to start the geme-theory process". How many wallets, how are they filled, and when does the mainnet game start? | (a) mine to m1, then transfer 4 DERO to m2; (b) rotate one pipeline-owned miner between m1 and m2 | (b): `playbooks/gt_earn.py --wallet m1,m2 --target-dero 4.0` | Same total hashing either way (8 DERO at 21.477 DERO/day ≈ 8.97 h at difficulty 2,331,515, `time_to_coins.py --target-dero 8`); rotation saves the transfer tx and its fee and gives each wallet its own chain-verified coinbase credits; both wallets must be registered anyway to sign. Start condition: the game starts only when BOTH hold >= 4.00000 DERO (400000 atomic), verified by wallet balance and chain scan. 2-player mechanisms: M3 (2 entrants), M2 (2 notarizers), M1 claim + unchallenged finalize (a disputed M1 needs a third wallet: a juror may not be the claimer or the challenger, `gt_attest.bas` CommitVote line 100). Fact check (§11a): deploying needs ONE wallet; a 2-party game needs two | §11a; `harness/runtime/gt_time_to_coins.json`; r32_DUE.json U-MAINNET-EARN | when both reach 4 DERO (G36 step 2) |
| D-GT-11 | 2026-11-15 ~14:20 | The user: "continuing on the current R32 enhancements path (name it R32-a) --> run the second mainnet cycle with a third wallet - and increment this game until it reaches 5 wallets", plus two primary objectives: incentivise miners to mine along with the games (network hashrate), and "secure the dero security ert coin supply, peers validation and all other security concerns found in prior rounds and harness if those can be addressed with such game theories". How to run it? | (a) one cycle per wallet count, each deploying fresh contracts; (b) one deployment for a 3→5 ladder, a measured cycle per step, mining continuous | (b) | One install set is paid once (four installs ≈ 0.4 DERO per deployment); mining never stops, so miners are paid to mine AND play (the stated objective); each step is a separate measured record | `playbooks/gt_ladder.py`, `sizing.plan_n_wallet` (deployed flag) | every step's chain audit |
| D-GT-12 | 2026-11-15 ~14:40 | Which security concerns can a game address? | (a) all of them; (b) only what an incentive outside consensus can touch | (b) | The inventory (`gametheory/research/r32a_security_inventory.md`, ~80 concerns): consensus, decoder, gas, P2P-policy and RPC fixes are NO (a contract can neither see nor change them); detection is PARTIAL/YES (pay independent nodes to re-derive public facts). Research Q3–Q4 (`r32a_research_web.md`): audits cannot see value an unsound proof created; a hidden sponsor answer and address-bound commits defeat copying and free-riding | `gt_audit.bas` M4; `audit_tasks.py` tasks 1 headers, 2 emission | a third task needs a deterministic, settled, public input |
| D-GT-13 | 2026-11-15 ~14:50 | How is the miner rewarded for the same address? | (a) loyalty or streak bonuses; (b) a bonus linear per accepted miniblock, claimed by every wallet that mined | (b) | Research Q1: payout is already linear per accepted share in consensus (`process_miner_transaction`); superlinear bonuses push consolidation, per-identity stipends invite Sybils (N8); a linear per-miniblock claim is split-invariant | `gt_cycle.claims()` | — |
| D-GT-14 | 2026-11-15 ~15:00 | The R32 prize (4,000) exceeded its reveal bond (1,000): a loser could withhold its reveal to swing the draw | (a) keep; (b) size rbond so rbond·(n−1) ≥ prize | (b) | econsim `m3_withholding` already stated the bound; the R32 viability gate did not check it. Now check (f) of `viability_n` uses the same formula, and rbond = max(1000, sponsor) | `sizing.viability_n` (f), KAT GT19 | — |
| D-GT-15 | 2026-11-15 ~15:00 | What must an audit bounty pay? | (a) any amount; (b) more than an honest auditor's own fees | (b) | Research Q3 (verifier's dilemma): an audit that does not pay is skipped; check (g): bounty/(n−1) ≥ 3 calls' fees; econsim M4 checks 15–18 | `sizing.viability_n` (g), `econsim.m4_auditor_ev` | measured on the ladder |
| D-GT-16 | 2026-11-15 ~15:10 | How is the new code proven before real DERO? | (a) straight to mainnet; (b) a sim PRE-FLIGHT of the ladder's cycle path, then the mainnet ladder | (b) | The R32 cycle lost a Freeze and three rounds on mainnet to paths no test had run; the sim chain gates code only (never a result, D-GT-5) | `scratchpad r32a/pre/run.sh` | — |
| D-GT-17 | 2026-11-16 ~23:00 | The user: the final R32/R32a analysis must become the next round's compounded enhancements through this file. What does R33 do first? | (a) the R32 carry list as written; (b) a continuous game mode first, then the measurements it makes possible, then the harness debts and the R32 carry | (b) | Two of the open questions (realized vs expected payoffs, the boost's effect on wins) need many cycles that only a continuous mode produces; the hashrate effect is bounded by measured fees (§4 goal 5: 0.3–0.5 % of the block reward while games run) and needs outside miners (GT-B19, user-gated) | §4 goal 5; §7 GT-B12..B20; the ladder records | the R33 instruments |
| D-GT-18 | 2026-11-17 05:25 | The user: "Make sure R33 is only focused on dero-game-theory-rft.md". Where does R33 live? | (a) parent and child; (b) the child only | (b) | the user's words; the parent stays parked (D-37) and gets no R33 rows | registry r33 delegated_page; this file | every R33 commit touches no parent row |
| D-GT-19 | 2026-11-17 05:40 | The user: every game contract fully security audited; are the contracts in the git push, where, and with a README tutorial there; "this all needs to be through dero-game-theory-rft.md". | (a) audit and document outside the track; (b) rows GT-B21/GT-B22 of this file, the audit's findings as rows, a deploy gate | (b) | the contracts are pushed at `gametheory/contracts/` (public copy checked 2026-11-17: 4 .bas + gt_audit_commit.md, no README) | §7 GT-B21, GT-B22 | the audit report; the README KAT |
| D-GT-20 | 2026-11-17 06:40 | The R33 audit: GT-A01 (anyone can re-initialize every deployed contract) and GT-A02 critical; the code cannot be updated in place. What happens to the 7 deployed mainnet contracts? | (a) keep using them; (b) never call or fund them again, fix every critical/high finding with a regression test, redeploy new SCIDs, playbooks refuse a SCID whose on-chain code is not the audited code | (b) | live GetSC 2026-11-17: 7/7 balance 0, frozen 1 (no loss so far); GT-A01 PoC | §7 GT-A01..A17, GT-B21 | the audit regression tests; the playbook code-hash guard |
| D-GT-21 | 2026-11-17 06:55 | The user opens GT-B19: design and implement ways (contracts contacting outside wallets/contracts, or a paid periodic advertisement beacon) for outsiders to join, so the hashrate effect becomes measurable. | (a) keep games operator-only; (b) research outreach (incl. what is acceptable to send to strangers), then a beacon/discovery design in this file | (b) | the user's words; §4 goal 5 (hashrate effect needs outside miners) | §7 GT-B26 | outreach research + beacon measurements |
| D-GT-22 | 2026-11-17 07:20 | How do outsiders learn of the games: push messages to harvested addresses, or pull-only discovery? | (a) push: 1-atomic transfers with a 111-byte comment to recent miners (~180 atomic each); (b) pull-only: a beacon contract with measured figures, Gnomon/TELA-indexable headers, a name-service entry, a Subscribe() list, posts the user makes; messages only to addresses that subscribed | (b) | push reveals the operator's address to every recipient (walletapi/daemon_communication.go:1121-1135), weakens recipients' ring anonymity, matches dusting/address-poisoning patterns, and is plausibly direct marketing needing consent (ePrivacy Art. 13); a contract payout shows as "Coinbase" (misleading) | `gametheory/research/r33_outreach.md` OR-1..OR-10, "Do not do" | beacon cost per update, subscribers, attested outside miniblocks |
| D-GT-23 | 2026-11-17 08:10 | How do the user's R33 objectives (deflation, forensics, many-miner sharing, stake weighting, peer protection, collusion/Sybil fixes) fit together? | (a) separate contracts, each with its own voting; (b) one verified-mining pool contract M5 built on in-contract block verification (GT-B24) and miner tags (GT-B25), plus the beacon M6 and M1–M4 v2 | (b) | GT-B24/B25 CONFIRMED; the DVM cannot read other contracts; research rules 1, 7, 8, 10 | §8.1; §7 GT-B27..B30 | the M5 DVM tests, econsim, sim and mainnet chain audits |
| D-GT-24 | 2026-11-17 09:05 | The user: "notify me when can i get started with R33 with dero-rft.md -> dero-game-theory-rft.md". D-GT-18 kept R33 out of the parent; how does the user's start path from the parent work? | (a) no parent change; (b) the parent carries only the delegation pointer (registry line, How to start, §8 title) to this file's §1, no R33 work rows | (b) | the user's start path; coherence required the parent to name the current round | parent header/How to start/§8 title | coherence 0 parent drifts |
| D-GT-25 | 2026-11-17 09:50 | The user: every R33 objective, including every open R32/R32a objective, goes through research → design → implement → debug → enhance in R33. How is that tracked? | (a) the backlog rows only; (b) a tracker §8.2 with a stage per objective, each stage claimed only with evidence, and work items R33-W* for what is left | (b) | the user's words; several rows were stale (GT-A01..A17 said OPEN after the fixes) | §8.2 | every R33-W* row closed with evidence before R33 is measured |
| D-GT-26 | 2026-11-17 10:05 | GT-B2 (isolated testnet) and GT-B5 (MAT value): run or close? | (a) run both; (b) close both with the evidence | (b) | the pool is pre-flighted on the private chain and measured on real mainnet (D-GT-5); M5 pays DERO for verified work, no MAT | §8.2 rows | reopen on a path that needs the real derod stack or a MAT-valued mechanism |
| D-GT-27 | 2026-11-17 11:15 | The user: coordinate every R33 task for the most coherent result. How? | (a) run jobs as they come; (b) one commit stream, resource ownership per job, a gated order of work (§8.3) | (b) | three jobs and an agent were live at once; a short-hash fetch had silently skipped a merge (lesson 37) | §8.3 | each gate's PASS recorded in §8.2 |
| D-GT-28 | 2026-11-17 18:20 | The user: use the silent/monitoring phases for parallel activities so the round takes less time, with high coherency and every objective met. How is that kept? | (a) wait; (b) §6 rule: in every waiting phase run the independent items that do not touch the waiting job's resources (§8.3), each gated before it is recorded | (b) | the user's words; R33's 2-hour epoch waits | §6, §8.3 | §8.2 rows closed during waits, gates PASS |
| D-GT-29 | 2026-11-18 00:00 | Epoch 19,796 credited m1 and m4 only, so the stake boost (m2) was not yet measured on mainnet. Cut epoch 19,798 to save ~4 h, or keep it? | (a) cut; (b) keep it and steer the earn rotation to m2 (earn_targets.json) | (b) | the user: every objective met; objective 4 needs a credited staker miniblock on mainnet | §8.3; earn_targets.json (backup .bak-r33-stake) | epoch 19,798's re-audit shows m2's weight 200 per credit |
| D-GT-30 | 2026-11-18 00:40 | The user asked to fix HTML↔PDF drift for ALL artifacts "using and enhancing the project harness and dero-rft". The parent stays parked for R33 (D-GT-18); where does the rule live? | (a) the child only; (b) the harness guard + one parent §0.6 contract row and §7 row B335 (the artifact contract is the parent's) | (b) | the user's words; the artifact contract table is in the parent | parent §0.6, B335; harness/kit/pdfsync.py | regen gate pdfsync --check PASS |
| D-GT-31 | 2026-11-18 06:20 | Step 3c's record lacks m1's Settle fee (None: the wallet had not indexed the tx in 40 s), so its chain-audit sum fails by 600. Re-run 3c on mainnet, or repair the record from evidence? | (a) re-run (another ~25,000 atomic and ~25 min); (b) repair the one field from two independent sources and fix the cause | (b) | the tx set its fee explicitly (fees_set 600, as every other 600 call paid), and conservation gives the same: payoffs −13,583 = chain-mined 12,300 − fees 25,883; the field carries `fee_source` saying it was repaired | lesson 39; gt_cycle.resolve_fees; KAT R33-8 | the chain audit sum = −fees exactly |
| D-GT-32 | 2026-11-18 06:35 | The full pipeline_20261118T025648 passed every Go stage (tests, soundness, KATs, go mutations 1763/1763, race 27/0, build, shadow 240 treehashes 0 mismatches, install) and failed only in the project stage: the game-theory page was stale because epoch 19,798 landed mid-run (GP0/GP2/GP9). Re-run the full pipeline (~3.3 h), or close on its Go stages plus a project-only run? | (a) full re-run; (b) its Go stages + a project-only PASS on the final tree | (b) | no Go file changed after the run started (git diff 80839fe2..HEAD -- '*.go' go.mod go.sum is empty), so a re-run re-tests the same Go; the failure was data freshness, fixed by regen | harness/round.json r33 pipeline_full + pipeline_project | the project-only run PASS |
| D-GT-33 | 2026-11-18 10:40 | The project-only pipeline_20261118T090148 failed only coherence_audit: 5 R33 KATs had no STEP_BUDGETS row, the opt-in `TestR33TagVector` was an orphan (nothing read its output; its comment still said 4-byte tags), and `dvm/r33_verify_common_test.go` holds helpers only. Fix in place, though it edits a Go test file after the full run? | (a) re-run the full pipeline; (b) derive the budget rows (stepbudget --derive, the same 3 records + the measured landed seconds), make TestR33TagVector a real check against a committed vector (`dvm/testdata/r33_tagvec.json`, mutant caught) registered in NEW_TESTS with a Python twin (KAT R33-9), and let coherence_audit pass a helpers-only _test.go | (b) | a test-only change to the dvm package's test set (no non-test Go, no consensus file); the new test PASSES run directly and FAILS on a one-hex mutation; the full run's other Go stages stand | STEP_BUDGETS.json (182 rows); fix_build_verify NEW_TESTS; coherence_audit.py | coherence_audit FAIL 0; the next project-only run PASS |

---

## 1. The prompt to paste (Round 33)

```
Round 33 of the DERO HE game-theory track (start from artifacts/dero-rft.md "How to start" -> this file; R33 lives
ONLY here, D-GT-18/D-GT-24; the parent stays parked). Repo <repo> (branch local-enhancements). FIRST:
ls <home>/derohe-persist/scratchpad/; read <home>/derohe-persist/round_state/r33_NOTES.md; run
harness/intel/resource_intel.py preflight; check what runs (pgrep -fl 'gt_earn|gt_pool_cycle|gt-dero-miner').
Then read artifacts/dero-game-theory-rft.md in slices (wc -l, offset/limit) and follow ALL of it: §0 (instruments,
decision log D-GT-1..), §2 (the user's words, items 1-15), §5 constraints, §6, §7 the backlog (GT-B*, GT-A* audit
rows), §8 + §8.1 the R33 design (M5 gt_pool verified mining pool, M6 gt_beacon), §9 NO-GO, §10 lessons.
Re-prove the layer: python3 -I harness/gametheory/gt_pipeline.py (implementation, debug, enhancement), go test
./dvm/ -run 'R32|R33', python3 -I harness/kat/test_gt_r33.py and test_gt_mechanisms_r32.py.
R33 state: DONE - research (gametheory/research/r33_*.md), the independent audit + invariant verification of all six
contracts (GT-A01..A17 + 5 verify findings fixed, gametheory/audit/), GT-B24/B25 block proofs + 8-byte miner tags
(GT-B32), gt_pool v2 + gt_beacon, econsim M5 (GT-B30), the contracts README tutorial (GT-B22), the pool cycle playbook
(GT-B29, sim pre-flight PASS). NEXT, in order: (1) the measured MAINNET pool cycle (playbooks/gt_pool_cycle.py
--network mainnet --mainnet-confirm, new gt wallets only; record harness/runtime/gt_pool_mainnet_*.json, audit must
PASS; if a run is in flight, wait for it); (2) GT-B33 batched proofs; (3) GT-B12 continuous mode on top of the pool;
(4) GT-B26 the beacon's measured publish + pull-only outreach (D-GT-22); (5) GT-B13/B14, then the R32 carry. Every
hashrate claim stays bounded by §4 goal 5 until outside tags are counted. Decide from the instruments and log each
decision (§0.4). derod start/stop, the user's own miner and the GitHub push stay the user's (D-GT-1, parent D-1).
```

## 2. The user's words (R32, as given to the coordinator; condensed only where it repeats)

1. Prepare Round 32 through dero-rft with super coherency, but PARK the broad enhancements and the miner enhancements;
   dero-rft stays intact as the parent; record R32 as delegated to a child rft; keep its carry list as parked items.
2. Create the child rft (this file), modelled on dero-rft, starting at round 32 and compounding; link both ways.
3. R32 is 100 % DVM and smart contracts: tools, harness, skills, memory, pipelines, code intel, KAT suites, corpus and
   kit suites for deep technical analysis of the DVM, smart contracts and DERO's DAG with respect to block rewards
   (miniblocks, final block, reward split, orphan/side blocks, emission, fees, SC gas), every formula grounded in Go.
4. Deep research first (DERO HE, homomorphic encryption, DVM-BASIC, AstroBWT, DAG/miniblocks, game theory of mining
   incentives, mechanism design, privacy); cite URLs; forums only steer.
5. A zero-touch agentic pipeline research → discovery → implementation → debug → enhancement whose outputs become
   Python playbooks that run without any LLM: create dedicated wallets, start/stop miners with them, deploy SCs with
   the mined DERO, run the game-theory mechanisms between the wallets, aiming at high-beta incentives for miners who
   run SCs with the address they mine to, drawing more miners, hashrate and SC activity.
6. Never use the user's wallet address in a miner or SC; never write it; guard it by sha256.
7. A dedicated artifact `dero-enhanced-game-theory.html` (+ pdf) in the same style as the existing artifacts.
8. Everything lands in the git push under the existing rules (the user pushes).
9. Open-loop then closed-loop strategies; several develop-test-debug-enhance iterations; 100 % evidence; the whole
   pipeline as a harness-tracked background run with monitoring and a completion notice; deep analysis of the output
   and further improvements until the verify gates pass.

### R33 additions (the user, 2026-11-17; condensed only where it repeats)

10. Find fixes in R33 for the R32a security limits: the audit bounty only detects; it cannot prevent consensus, peer or
    range-proof problems and does not stop auditor collusion or fake auditor identities.
11. Add, after deep analysis, design, implementation, debug, simulation runs, real mainnet runs and measurement, and
    coherent with the rest of R33: (1) deflation of the coin supply through the game suite, where such a contract earns
    more and its results are easy to verify; (2) chain/block forensics through contracts, earning more and easy to
    verify; (3) more users mining with the suite: reward sharing for all miners, deflation, better security of the
    blocks mined that way, and other benefits of scale; (4) a wallet with more DERO in the contracts earns a higher
    share without breaking the game's democratic basis: everyone else keeps a fair share and no single miner or peer
    can sabotage the chain; (5) the contracts help secure blocks against peer attacks.
12. This needs a large upgrade of code intel, harness, tools, skills, memory, playbooks, testnet, measurement methods,
    artifacts, KAT and KIT suites and coordinator skills; several develop-test-debug-enhance iterations, open loop then
    closed loop (EVIDENCE_LOOP_PROMPT), the whole pipeline as a harness-tracked background run, a deep final analysis.
13. "Make sure R33 is only focused on dero-game-theory-rft.md" (D-GT-18).
13b. "massively enhance the visualization, look and feel of artifacts/dero-enhanced-game-theory.html - make sure that
    project's working tools, KAT suites, KIT suites, harness is used and enhanced for this job. The objective is to make
    this artifact really user friendly to understand but also be very technical - the objective of this artifact is to
    enable other developers to implement such game theories" (GT-B36).
13c. "also the page should mention how miners joining with gametheory benefits the network. All that needs to be
    visualized. All the objectives which have been implemented of R32, R32b, R33 needs to be visualized in the html
    artifact" (GT-B36; there is no round R32b: read as R32a).
13a. "make sure all the objectives of R33 including any open/pending objectives of R32+R32a are in depth research and
    then designed->implemented->debug->enhanced though R33 (dero-rft.md -> dero-game-theory-rft.md)" (D-GT-25, §8.2).
14. Every smart contract written for and run in the games fully security audited; the contracts are in the git push
    (`gametheory/contracts/`), and that path gets a README: a complete tutorial on writing, using and deploying them;
    "this all needs to be through dero-game-theory-rft.md" (D-GT-19).
15. Outside participation: think of and implement ways for contracts to contact outside wallets/contracts to join the
    games, or any other way to advertise to outside wallets, even if it costs the game wallets coins, e.g. a periodic
    advertisement beacon; deep research first; designed and implemented in R33 through this file (D-GT-21).

## 3. The evidence loop (as run in R32)

- **Open loop (4 strategies):** (O1) web research → `gametheory/research/dossier.md` (55 sources: 17 doc, 28 paper,
  10 steer; 10 fetches failed and are labelled); (O2) code reading of the DVM (`dvm/dvm_functions.go`, `dvm/dvm.go`,
  `dvm/sc.go`, `dvm/simulator.go`) and of the reward path (59 anchors); (O3) live read-only sampling of mainnet
  (60 blocks, topo 7,905,215–7,905,274, 160 calls; plus a 2,000-block headers sample kept in scratch); (O4) DVM
  experiments in the in-process simulator.
- **Closed loop (iterations, each with its verify gate):** I1 contracts v1 → 4 DVM test failures, all one simulator
  artefact (a reverted call credits its deposit back to the signer) → accounted for in the test helper → 9/9 PASS;
  I2 the sim chain: every getwork template failed ("miner address is not registered") → D-GT-9 integrator fix →
  mining; I3 the playbook: `DERO.GetInfo` with `params: {}` refused (-32602) → params omitted; the genesis line raced
  the RPC start → polled; a crash left the chain running → cleanup on every exit path; run 3 PASS 8/8 on chain;
  I4 the reward analysis showed the integrator role → D-GT-10 prize v2 (no RANDOM); I5 the wallets' 1,000-DERO grant
  → D-GT-7 payoff accounting; I6 the parameter derivation (D-GT-6) → `params_r32.json`; I7 the pipeline's own
  checks were too loose or too strict (a dict passed as a verdict, rc 5 of the mainnet plan, the `Signer` field
  missed by an upper-case regex) → fixed → 6/6 PASS.

## 4. Goals, honestly sized (the economics)

1. **A smart contract cannot raise the block reward or see the miner** (D-GT-3). What it can do is pay DERO it holds,
   mint its own token without limit, read BLOCK_HEIGHT / BLOCK_TIMESTAMP / BLID / SIGNER (ring size 2 only), and draw
   RANDOM keyed by (SCID, BLID, TXID).
2. **"Mining to the same address" can only be attested off-chain.** The block headers list every normal miniblock's
   key (`DERO.GetBlock` `miners`), so anyone can count an address's miniblocks; the DVM cannot. M1 makes that count an
   optimistic, bonded claim with a challenge and a Schelling jury. Honest claiming is the attractor iff the bond per
   miniblock exceeds (1-c)·r·v/c (econsim; replicator: honest share 1.0 at c = 0.855, inflation spreads at a tiny bond).
3. **Hashrate under free entry follows real value, not tokens.** Miners enter until revenue per hash equals cost, so
   an SC incentive I (real DERO per block) raises hashrate by I/R. Today R = 30,750 atomic per block (60/60 live
   blocks): +1 % hashrate needs ≈ 308 atomic of real value per block, ≈ 14.3 DERO/day at 4,659.5 blocks/day. MAT has
   value only through what M2/M3 fee payers and sponsors pay for its boost.
4. **SC activity can be bought, but it is bought.** M2's no-wash rule ρ(100+boost) ≤ 10000 makes self-dealing
   unprofitable without others' fees; a sponsor subsidy is a Tullock contest that is dissipated ((n-1)/n of it to the
   treasury as fees). Reporting subsidised activity as organic is NO-GO N3.
5. **Measured in R32a (the ladder, 2026-11-16): what the games pay the network.** The fees of the game calls are the
   only real value they route to miners (the consensus split pays base reward + the block's fees per miniblock): step 3
   (3 wallets) 85,608 atomic over 472 blocks = 181 per block, 0.59 % of the block reward, of which the one-time deploy
   of the four contracts was 45,951 (the recurring fees 84 per block, 0.27 %); step 4 (4 wallets) 46,144 over 385 blocks
   = 120 per block, 0.39 %; step 5 (5 wallets) 56,252 over 379 blocks = 148 per block, 0.48 %. By goal 3 that bounds the
   hashrate a free-entry market would add at about 0.3–0.5 % while the games run, and only if outside miners respond;
   the prizes (5,000 / 5,000 / 20,000) and bounties (24,000 / 36,000 / 38,000) move DERO between the operator's own
   wallets and route nothing to the network. Net game payoffs sum to exactly minus the fees in every step.
6. **The miner's own levers on SC randomness are real.** The integrator (not the hasher) gets the final share +
   leftover and chooses the block; a contract that draws from RANDOM gives it a re-roll worth up to its share (D-GT-10).

## 5. Standing constraints (all of parent §5, and)

- Never write under `<datadir>`; never read state below topoheight 7,498,540 (`reward_intel.py` refuses, exit 2).
- Mainnet WRITES through 127.0.0.1:10102 (DERO.SendRawTransaction, wallet transfers and SC calls) are limited to the NEW gt wallets (D-GT-4); gt-wallet refuses a banned address itself and fails closed on mainnet without the ban list.
- Never restart, kill or renice derod or any foreign process; playbooks signal only pids they started whose command
  basename is `gt-*` (`gtlib.pid_alive`, `start_proc`).
- Mainnet RPC 127.0.0.1:10102 read-only; getwork 10100 and P2P 11011 never probed. The sim chain uses loopback ports
  47100 (getwork), 47102 (RPC), 47180 (explorer), 47200+ (wallets) and the simulator's own 30000–30021.
- The user's own miner stays as the user runs it. A pipeline-owned mainnet miner for the NEW gt wallets is authorised by the user (D-GT-4) but runs only through `playbooks/gt_earn.py --mainnet-confirm`, started by the user (the session's permission system refused to start it); `--mainnet-confirm` stays the gate.
- Wallet files: `<home>/dero-wallets/gt/<network>/` (700), passwords in `<name>.pass` (600); `gt-wallet` refuses a
  directory that is not 0700 or lies in a git work tree, and a missing daemon (walletapi would default to mainnet).
- No exploit content for the range-proof/IPA soundness defect; DVM work stays non-consensus (parent D-21).
- Privacy: published copies through the private scrubber; the PDF scanned by raw bytes; banguard scan 0.

## 6. The round procedure

- **Parallel work in every waiting phase (D-GT-28, the user 2026-11-17).** While a long job waits (an epoch, a claim
  window, a pipeline stage), the coordinator runs every independent R33 item that does not touch the waiting job's
  resources (§8.3 ownership table): KATs, private-chain runs, read-only analyses, docs and pages. Each such item is
  gated (tests, coherence) before it is recorded, and the round's objectives (§8.2) stay the measure: parallel work
  shortens the round, it never skips a gate.
- **A. Start:** How to start; open the round in `harness/round.json` (r32 `in-progress`, tracks miner paused / node
  active); `r32_NOTES.md`, `r32_DUE.json`.
- **B. Open loop:** research (§3 O1–O4); refresh `reward_intel.py --live` (read-only).
- **C. Closed loop:** 1 contracts + DVM tests; 2 econsim; 3 the ban guard; 4 the sim chain tools; 5 the playbook;
  6 `gt_pipeline.py --sim` as a stallwatch'd background run with a DONE marker and a monitor; 7 analyse the report,
  improve design/algorithm/implementation, re-run until G35 and the KATs PASS.
- **D. Artifacts, in one order:** the child rft §12/§13 → `artifacts/dero-enhanced-game-theory.html` → its PDF →
  the parent §0.12/§13 rows → memories → commit → the private sync tool → push DUE (user).
- **E. After measurement:** §13 with the run anchors; DUE items closed.

## 7. Consolidated OPEN backlog (game-theory track)

| ID | item | status | anchor |
|---|---|---|---|
| GT-B1 | multi-round sim game: N ≥ 6 miners, strategy mixes (honest / inflate / lazy juror / colluding jurors), payoffs measured and compared with the econsim replicator | OPEN | `harness/gametheory/econsim.py` m1_replicator |
| GT-B2 | the isolated-testnet path (`gt-derod --testnet`, own data dir, no peers) end to end | OPEN (plan printed by the playbook) | `playbooks/gt_playbook.py` chain_start |
| GT-B3 | mainnet fee per entrypoint: `DERO.GetGasEstimate` read-only for each call path, recorded beside the DVM gas census | PARTLY (R32a: every ladder call records its `gas_est` and the fee it set; the storage-gas limit IS the fee, lesson 24; open: the per-entrypoint census table across the three steps) | `harness/runtime/gt_cycle_mainnet_20261116T*.json` calls[].gas_est |
| GT-B4 | juror bribery: a planted P+ε briber in the sim game; measure the flip cost against econsim m1_bribe_cost | OPEN | econsim m1_bribe_cost |
| GT-B5 | the MAT value assumption (D-GT-6): a market or a sponsor commitment that makes v observable | OPEN | `playbooks/params_r32.json` derived |
| GT-B6 | front-running of public SC arguments (claims, Notarize digests): measure the mempool exposure on the sim chain | OPEN | mechanisms.json M2 attacks |
| GT-B7 | DVM own-token stored balance: `SanityCheckExternalTransfers` stores `stored_value - value` for the SC's own asset without an underflow check (dvm/simulator.go:220-226); pin its behaviour in a test, disclosure-style | OPEN | dvm/simulator.go:220 |
| GT-B9 | DONE (R32 cycle 2026-11-15; R32a ladder 3 to 5 wallets 2026-11-16, 15/15 genuine prize rounds) — mainnet game after earning (D-GT-4): once U-MAINNET-EARN has earned >= 1 DERO, register the other gt wallets (txid PoW each), fund them from m1 and run M1/M2/M3 on mainnet with the mainnet parameters (`playbooks/params_r32.json`); the `all` flow skips mainnet today | OPEN (user-gated) | `playbooks/gt_earn.py`; D-GT-4 |
| GT-B10 | the sim-share anomaly (lesson 0): measure the slot order per miner on a sim chain (miners list position per height) to confirm or refute the dispatch-order hypothesis | OPEN | lesson 0 |
| GT-B11 | time-to-coins from the MEASURED pipeline-miner H/s (22.4 kH/s at 6.46 cores while R32 pipelines ran) instead of the R30 quiet-box rate; add `--hs` to time_to_coins.py | OPEN | §13 04:27 |
| GT-B8 | a multi-address sybil study for M1 (claims are per address and range; splitting should gain nothing) | OPEN (R32a design: the claim is linear per accepted miniblock, D-GT-13, so a split gains nothing in expectation; not yet measured) | mechanisms.json M1 attacks |
| GT-B12 | a continuous game mode (the user asked 2026-11-16): the ladder repeats a sized 5-wallet cycle whenever the balances allow, a gap between cycles, every cycle chain-audited, stop after 3 failures in a row; the earn job without its 48 h lifetime; the leftover `earn_targets.json` removed when a ladder ends | OPEN (R33 first) | `playbooks/gt_ladder.py`; earn `--max-hours 48` | — R33 IN PROGRESS: `gt_pool_cycle.py --epochs N` repeats fund → prove → claim → chain audit → beacon on the same audited contracts (every other epoch, since claims of e end inside e + 1), one record per epoch, stops after 3 failed epochs or audits in a row; `--follow` (GT-B34) proves only around blocks with member work; private-chain pre-flight PASS 2026-11-17 09:38 (epochs 1 and 3 in one run on the same contracts, 12 follow-mode proofs each within the budget, both chain audits PASS, records gt_pool_sim_20261117T173220/T173814.json, fees 23,424 / 23,657 atomic); mainnet after the first mainnet cycle's audit
| GT-B13 | realized vs expected payoffs: step 5's m2 and m3 ended at −846 and −608 (no prize win; their audit shares covered their audit fees but not their prize-round fees) while sizing passed on expectation; measure the spread of realized payoffs over many cycles against `viability_n` | OPEN (needs GT-B12) | §13 2026-11-16 09:04; `sizing.viability_n` |
| GT-B14 | the MAT boost in a genuine many-player round: m4 won 4 of 5 rounds in step 5; test whether win frequency follows the boosted weights (a statistical test needs many rounds) | OPEN (needs GT-B12) | `gt_prize.bas` Enter weights |
| GT-B15 | a third deterministic audit task: the SC balances turnstile (sum of each contract's DERO balance at a settled topoheight, from DERO.GetSC) or the formula supply against the published emission; peer validation stays out (not deterministic across nodes) | OPEN | `harness/gametheory/audit_tasks.py` TASKS |
| GT-B16 | the dispute path on chain: plant a wrong sponsor answer on the sim chain (then, if it holds, one mainnet drill) so a strict auditor majority wins and sets disputed=1; today only the DVM test exercises it | OPEN | `dvm/r32a_audit_test.go` MajorityDispute |
| GT-B17 | the earn job's own credit counter still uses reward // 10 (display only; the chain audit uses the fee-inclusive split, lesson 32) | OPEN | `playbooks/gt_earn.py` rotate |
| GT-B18 | a content-hash staleness check for the gt binaries instead of file times (lesson 26) | OPEN | `playbooks/gtlib.py` stale_bins |
| GT-B19 | outside participation: the hashrate effect can only be measured with miners who are not the operator (publish the contracts and the page, an open entry); a user decision (it invites third parties and real money) | OPENED by the user 2026-11-17 (D-GT-21) → GT-B26 | §4 goal 5; parent D-1 |
| GT-B20 | a KAT that a round's first consensus-package change bumps the build metadata in `config/version.go` (lesson 33) | OPEN | lesson 33 |
| GT-B21 | a full security audit of every contract that runs in a game (gt_attest, gt_service, gt_prize, gt_audit, and every R33 contract before it is deployed): access control, Uint64 overflow/underflow, deposit accounting (in = out + held, nothing stuck), double withdraw, commit-reveal binding and front-running, RANDOM grinding, Sybil/collusion, denial of service, state-machine order, anonymous callers, replay; an independent auditor (code, not conclusions), each finding CONFIRMED by a DVM proof-of-concept test or PLAUSIBLE, each fix with a regression test; a contract is deployed only with 0 open critical/high findings | IN PROGRESS (audit 2026-11-17: 17 findings GT-A01..A17; ALL FIXED in 62b8e048 / merged 49029b67 with 26 regression + 4 conservation DVM tests (`dvm/r33_audit_test.go`), R32/R33 DVM tests 48 PASS, KATs 28/28 + 62/62; the pipeline lint now machine-checks GT-A01/A12 and lessons 34-35 (`harness/kat/test_gt_r33.py` 4/4, 5/5 planted defects caught); residual risks stated by the fixer: A04 any entrant can force a dispute (no gain), A05 keep rbond ≥ prize, A06 keep maxn × fee ≥ prize, A07 a bribed juror majority; the 7 old SCIDs are retired. Independent re-audit 2026-11-17 PARTIAL: the auditor stopped early (no report or PoC written); it read the DVM semantics, gt_pool v1, gt_beacon and gt_service; its unconfirmed leads map to v2 fixes (Claim after Rollover → claim deadline, TestR33PoolLateClaimRefused; caller-chosen parse → fixed miniblock count, TestR33PoolProofGuards; cap split → stated in §8.1; P·W overflow → pool and rollover caps); gt_beacon: no issue seen. Second pass (same auditor, v2): RA-P1 CLOSED by v2; RA-P2 the cap is per identity (stated); RA-P3 the parse rested on the caller's ntx → FIXED: every parsed miniblock must carry the proven height in its 5-byte height field (verified on the 4 real blocks), so a shifted parse needs 10 ground height fields (TestR33PoolProofGuards: another height refused); RA-P4 no overflow; gt_beacon clean. STILL OPEN: an independent full re-audit of gt_attest, gt_prize, gt_audit and gt_service v2, and of gt_pool v2 after the height check, before deployment) | `gametheory/audit/r33_contract_audit.md`; `gametheory/contracts/*.bas` |
| GT-B22 | `gametheory/contracts/README.md`, published in the public copy at the same path (it already carries the .bas files, no README): a complete tutorial on writing DVM-BASIC contracts like these, testing them in the DVM simulator, estimating gas, deploying them and calling every entrypoint (with the wallet RPC and with the playbooks), reading their state, and each contract's rules, parameters and audit status; generated or checked by a KAT so every .bas and every entrypoint is covered and no private value (path, address, IP) is in it | DONE 2026-11-17: `gametheory/contracts/README.md` (12 sections: the 6 contracts, writing DVM-BASIC with the audit rules, simulator tests, node and wallet, gas estimate, install via wallet `transfer` with `sc` base64 (txid = SCID), calls via `scid` + `sc_rpc` + `burn` deposits, reading `DERO.GetSC` (hex strings), gt_pool step by step with `--game-tag`, gt_beacon, playbooks, audit status); checked by KAT test_gt_r33 R33-5 (every .bas and every M5/M6 entrypoint, no private value); published with the next public sync | public `gametheory/contracts/` |
| GT-B23 | gt_audit `Settle` may never fit the gas limit: its majority search is O(n²), ~50k gas per inner step against the 10M call limit and 2,000 lines, so with ≥ ~13 revealers and no majority Settle always fails and `Withdraw` (st==1) locks the bounty and every bond (code research ESTIMATE, gt_audit.bas:180-285, dvm/sc.go:241). Confirm with a 16-entrant no-majority DVM test; fix: tally answers at Reveal so Settle is O(n). Until fixed, gt_audit rounds keep maxn ≤ 8 (today's PARAMS maxn 8) | FIXED by GT-A03 (answers tallied at Reveal; Settle O(n), 3.1M gas at n = 32; answer length ≤ 256; timeout refunds) | `gametheory/research/r33_code_capabilities.md` finding 1 |
| GT-B24 | CANDIDATE "check, don't vote" in the DVM: a block id is `sha3.Sum256(bl.serialize)` (block/block.go:57-58) and the DVM has `sha3256`, `hexdecode`, `substr` (dvm/dvm_functions.go:85-87, 513, 574) and `BLID()` of the executing block (:275-277); a contract that stores BLID() at a call can later accept that block's serialized bytes only if `sha3256(hexdecode(x)) == stored`, then trust its fields (height, timestamp, tips = parent ids, the 48-byte miniblocks with KeyHash) and walk back through tips. Would settle forensic disputes by verification, not majority (research rule 1), and close the collusion/Sybil-auditor gap for header facts. To confirm: a DVM test with a real serialized block (size, gas at 25,000 per hash, string limits), then a sim chain run | CONFIRMED in the DVM simulator 2026-11-17 (`dvm/r33_blockproof_test.go`, TestR33BlockProofVerifiesRealMainnetBlocks): 4 real mainnet blocks (3 empty 598 B, 1 with 3 txs 694 B; `dvm/testdata/r33_mainnet_blocks.json`) anchored by BLID() and proven; every KeyHash, Flags and the header timestamp equal the Go decoder; one flipped hex digit and a wrong tx count refused; Prove gas 1,742,400 compute (of 10M), 1,735–1,927 storage (cap 20,000); the final miniblock is the last; on chain BLID() is the executing block's hash (blockchain/blockchain.go:1021 `bl_current_hash`). Open: a sim-chain run | block/block.go:57; dvm/dvm_functions.go:85-87 |
| GT-B25 | CANDIDATE in-contract proof of mining: the miniblock `Flags` uint32 is free (block/miniblock.go:55 "can be used as flags by special miners"; no consensus code reads it, grep of blockchain/ and cmd/derod/: only (de)serialization and the explorer); the stock miner randomises only the last 12 bytes (cmd/dero-miner/miner.go:938). A game miner that sets Flags = the first 4 bytes of sha3(its game address) makes every miniblock it mines carry an unforgeable (PoW-bound) tag a contract can check through GT-B24; mined work then becomes a non-refundable identity cost (research rule 7: Sybil-safe weights) and the basis for verifiable reward sharing among many miners. The main risk is not a 2^-32 collision but tag 0 (stock miners' Flags), refused by gt_pool; the KeyHash is not matched | CONFIRMED 2026-11-17: `gt-dero-miner --game-tag=<hex8>` (cmd/dero-miner/gametag.go, TestR33GameTagLandsInFlags: only bytes 32..35 change, CPU only, refused with --gpu); private-chain pre-flight `harness/gametheory/r33_flags_preflight.py` PASS: 8 blocks, 18 non-final miniblocks accepted with Flags == tag, 0 untagged, every sha3(bytes) == block id | block/miniblock.go:55; cmd/dero-miner/gametag.go |
| GT-B26 | outside participation (the user, 2026-11-17): ways for outside wallets and miners to discover and join the games, including a periodic on-chain advertisement beacon paid by the game wallets; research first (on-chain channels and their code limits, DERO discovery tools, the ethics of unsolicited messages on a privacy chain, beacon and referral mechanism design with Sybil-safe rewards), then design, implement, measure on mainnet; the beacon publishes only measured figures, never promised returns | DESIGN (research done: `gametheory/research/r33_outreach.md`, rules OR-1..OR-10; pull-only, D-GT-22) | §4 goal 5; GT-B19 |
| GT-B27 | M5 `gt_pool.bas`: Register (tag, fee), Anchor, ProveBlock (GT-B24 parse, credit tagged non-final miniblocks once per block), epochs, W_i = w_i(1 + min(s_i/S, 1)), payout cap, locked stake, burn β, prover fee, concentration alarm; DVM tests with the real mainnet blocks and planted tags; its own independent audit before deploy | IN PROGRESS: `gametheory/contracts/gt_pool.bas` v2 (research defects fixed: tag 0/ff refused, fixed miniblock count 10, claim deadline = Rollover start, Rollover destination cap, prover fee 2000 ≥ measured proof storage 1,735–1,927; ProveParent) + `dvm/r33_pool_test.go` 6/6 PASS (+ chain-back, late claim) (honest epoch with cap/rollover/forensics, proof guards, stake boost and lock, split-neutrality; conservation checked in each); independent audit pending | §8.1 M5 |
| GT-B28 | M6 `gt_beacon.bas`: measured-figures publish, Subscribe, Gnomon/TELA header; cost per update measured | IN PROGRESS: `gametheory/contracts/gt_beacon.bas` + `dvm/r33_beacon_test.go` PASS (owner-only Publish with measured height ranges and length caps, a future range refused, opt-in Subscribe/Unsubscribe, nameHdr/descrHdr/iconURLHdr, never holds DERO, Initialize once); independent audit pending; mainnet cost per update pending | §8.1 M6; OR-1..OR-10 |
| GT-B29 | playbooks: the earn job mines with `--game-tag` of each wallet; a prover/anchor loop (anchor every block the gt wallets mine, prove it after it settles); a pool chain audit (payout = formula of verified credits) | SIM PRE-FLIGHT PASS 2026-11-17 (`playbooks/gt_pool_cycle.py`, record `harness/runtime/gt_pool_sim_20261117T164807.json`): 3 wallets registered (tags verified on chain), 3 anchors + 18 chain-back proofs = 21 blocks, credits 64/71/54, claims 12,120/12,120 (both capped at 30 %) and 11,542 = the formula, balance 25,218 = burned 20,600 + pool left 4,618, beacon published; fees 50,637 atomic, 151 s. Mainnet: the earn job mines with 8-byte tags since 08:44 (b8deacdd06c25b08 seen); mainnet cycle next | gt_pool_cycle.py; gt_earn.py |
| GT-B30 | econsim for M5: split-neutrality, the stake boost bound, the payout cap, the burn β against the sponsor subsidy, prover-fee break-even | DONE 2026-11-17: econsim 25/25 (7 M5 checks: 4,000 random uneven splits over 2–6 identities never gain; stake moves at most 3 − 2√2 = 17.16 % of a pot; boost ≤ 2×; the cap is splittable by a dominant identity (stated); a 10 % member of a 1-DERO epoch nets positive after the 20 % burn, a 1 % member needs 2 epochs to recover the entry fee; pfee 2,000 ≥ measured proof gas 1,927) + the M4 v2 rule (colluders only force a dispute) | harness/gametheory/econsim.py M5 |
| GT-B31 | gt_pool anchor coverage and selection bias (found 2026-11-17 while wiring the playbook): a block is creditable only if an `Anchor` call executed IN it, and a call cannot choose its block. Anchoring every block costs ~4,800 tx/day; and an integrator that is also a member could include anchors only in blocks where it mined many miniblocks. Design: chain back from an anchor through the proven block's tips (its parent ids are in its bytes), crediting a parent only when (a) its height is the child's height − 1, (b) the child has exactly one tip, (c) no other block of that height was proven (a second one marks the height contested and uncredited); side blocks (same height as the previous topo block, blockchain/blockchain.go:1385-1397) earn no reward (:984-986) and must never be credited; measured alt-block rate 2.05 % (R32) bounds what the conservative rule leaves out. Until done, only directly anchored blocks are credited and the anchor bot anchors at a fixed cadence independent of who mined | DONE in gt_pool v2 (2026-11-17): consensus allows exactly one tip at height − 1 (blockchain/blockchain.go:490-509), so the tip chain back from an anchored block is the main chain; a side block is never a main-chain block's tip and its own txs never execute; `ProveParent` walks back; TestR33PoolChainBack on real consecutive mainnet blocks (the real tip of 7,915,142 = the id of 7,915,141) | gt_pool.bas pproc/ProveParent |
| GT-B32 | 8-byte miner tags (mainnet scan 2026-11-17, heights 7,915,962–7,916,003): the tagged gt miner's miniblocks were accepted on MAINNET (3 carried b8deacdd, one of them final), and OTHER miners already write constant nonzero Flags (01000000, 02000000, 03000000, 05000000, 06000000), so a 4-byte tag could be ground (~2^32 keys) to take their credit. Tag = first 8 bytes of SHA3256(SIGNER()) in miniblock bytes 32..39 (Flags + Nonce[0]; the CPU loop iterates only bytes 43..46, cmd/dero-miner/miner.go:931/954/973); ~2^64 to grind | DONE in gt_pool, gt-dero-miner --game-tag=<hex16>, gtlib.pool_tag, gt_pool_cycle, tests; members must register before mining tagged | gt_pool.bas mytag/credit; cmd/dero-miner/gametag.go |
| GT-B33 | batched block proofs — REFUTED by measurement 2026-11-17 (throwaway DVM breakdown, 598-byte real block): ProveBlock storage gas 1,506 = ~1,370 for the call's own argument data (the block as hex; every call pays storage gas = its SCDATA length, dvm/sc.go:261-263) + census 85 + tip 33 + timestamp 17; compute (5.09M) is free. A proof costs ~2 gas per block byte whether batched or not, and binary arguments are not safe through the wallet's JSON. The levers are fewer proven blocks and more member work per proven block (a member share s gives 9s credits per proven block against ~1.5–2.2k atomic); see GT-B34 | CLOSED (NO-GO N9) | dvm/sc.go:263 |
| GT-B34 | (MEASURED 2026-11-17: follow mode 0.20 credits per proof vs 0.11 fixed-depth, epoch fees 28,138 vs 64,756 atomic) proof economics in flight (from GT-B33 and the mainnet cycle): prove only where it pays — choose anchor windows around blocks the members mined (headers name each miniblock's miner off-chain), stop a chain-back walk at a bound past the last block with member work, and size --anchors/--depth from the measured member share; the mainnet record `gt_pool_mainnet_*.json` supplies the real fee per proof and credits per proven block | OPEN | gt_pool_cycle.py prove |
| GT-B35 | the concentration alarm needs a sample (research: ≥ 360 proven normal miniblocks for the 0.40 threshold's false-alarm bound), but follow-mode proving (GT-B34) proves ~15 blocks (~135 miniblocks) per epoch: evaluate the alarm over the census summed across epochs, off-chain from the contract's own per-epoch counts (k<e>_<keyhash>), and publish it on the beacon with its epoch range | DONE 2026-11-17: `harness/gametheory/pool_census.py` (read-only GetSC; exit 0/4/3) + the cycle publishes `pool_census` on the beacon; KAT R33-6; MAINNET epochs 19,790–19,791: 378 verified miniblocks, 19 KeyHashes, top 17.7 %: no alarm (`harness/runtime/gt_pool_census_mainnet.json`) | gt_pool census; pool_census.py |
| GT-B36 | the game-theory page as a developer's guide (the user, 2026-11-17): plain-language overview with honest limits, a generated SVG flow of the verified pool and the audit bounty, mainnet charts from the records (epochs, burn, census, gas census), a per-contract reference (entrypoints parsed from the .bas, storage keys, rules, quoted code), a build-your-own-game guide linked to lessons and audit findings, the audit summary; how miners joining benefits the network (attack cost, main-chain-only pay, forensics, burn, the honestly bounded hashrate effect) visualized; every implemented R32/R32a/R33 objective as a stage matrix parsed from §8.2/§7; light/dark tokens, responsive, accessible; gated by kitgate, regen page gates, coherence, and a new KAT test_gt_page_r33 | DONE 2026-11-18: merged (17 sections, 16 charts, flow/byte/audit diagrams, contract reference with 23 verbatim excerpts, build-your-own-game, network benefits, objectives matrix); kitgate G5–G14 PASS, KAT test_gt_page_r33 10/10 15/15; harness/kit/chartkit.py + kitgate G13/G14 | artifacts/src/gen_gametheory.py |
| GT-B37 | the mainnet turnstile round of step 3c summed only the run's own contracts (the new gt_audit SCID, balance 0), so its total said nothing about the pool and beacon: let `gt_cycle.py --audit-tasks 3` take an explicit SCID list (the pool, the beacon, the retired R32 contracts) so a mainnet round attests a non-trivial total | OPEN (R34) | gt_cycle task-3 setup; audit_tasks.py --scids |
| GT-A01 | critical: `Initialize` is public and unguarded in all four contracts: anyone re-initializes after Freeze, becomes owner, resets state; gt_prize drained (2 atomic in, 100,002 out), gt_service drained via the epoch length (audit CONFIRMED by a DVM proof-of-concept unless marked) | FIXED 2026-11-17 (62b8e048/49029b67; regression test `dvm/r33_audit_test.go` TestR33Audit01*, invariants `dvm/r33_verify_*_test.go` 37/37) — fix: first line `IF EXISTS("owner") == 1 THEN RETURN 1` | gt_prize:14, gt_service:11, gt_attest:13, gt_audit:34; `gametheory/audit/r33_contract_audit.md` |
| GT-A02 | critical: gt_attest juror stake not locked per dispute: one stake votes at full weight in every dispute; payouts exceed the loser's stake (attacker +1,000,000 over 20 disputes; an honest 5,000,000 stake unwithdrawable) (audit CONFIRMED by a DVM proof-of-concept unless marked) | FIXED 2026-11-17 (62b8e048/49029b67; regression test `dvm/r33_audit_test.go` TestR33Audit02*, invariants `dvm/r33_verify_*_test.go` 37/37) — fix: escrow the weight at CommitVote, release at settle | gt_attest:137-145, 226, 229-233; `gametheory/audit/r33_contract_audit.md` |
| GT-A03 | high: gt_audit Settle O(n²): ≥ 12 distinct answers exceed 10M gas; 7 Sybil junk entries lock a round of 9 honest auditors; unbounded answer length exceeds the 20,000 storage gas; bounty and bonds stuck (confirms GT-B23) (audit CONFIRMED by a DVM proof-of-concept unless marked) | FIXED 2026-11-17 (62b8e048/49029b67; regression test `dvm/r33_audit_test.go` TestR33Audit03*, invariants `dvm/r33_verify_*_test.go` 37/37) — fix: tally at Reveal (O(n) Settle), cap answer length, per-entrant pull refunds without Settle after a timeout | gt_audit:166-286, 134, 148; `gametheory/audit/r33_contract_audit.md` |
| GT-A04 | high: gt_audit strict majority overrides a revealed correct sponsor answer: 2 Sybils answering junk take the bounty, the honest auditor loses its bond (audit CONFIRMED by a DVM proof-of-concept unless marked) | FIXED 2026-11-17 (62b8e048/49029b67; regression test `dvm/r33_audit_test.go` TestR33Audit04*, invariants `dvm/r33_verify_*_test.go` 37/37) — fix: no majority-over-sponsor; verify (GT-B24) or slash only provably wrong answers | gt_audit:184, 192-193, 360; `gametheory/audit/r33_contract_audit.md` |
| GT-A05 | high: gt_prize: forfeited reveal bonds go to the same round's prize, so withholding a losing reveal is free; 2 Sybils win 91.6 % vs a fair 66.7 % (refutes the M3 bound in mechanisms.json) (audit CONFIRMED by a DVM proof-of-concept unless marked) | FIXED 2026-11-17 (62b8e048/49029b67; regression test `dvm/r33_audit_test.go` TestR33Audit05*, invariants `dvm/r33_verify_*_test.go` 37/37) — fix: forfeits go to the treasury/next round, never to the current prize | gt_prize:127-143, 157-162; `gametheory/audit/r33_contract_audit.md` |
| GT-A06 | medium: gt_prize first-come entry slots: 32 Sybils at 1 atomic fill a round and take the sponsor prize (audit CONFIRMED by a DVM proof-of-concept unless marked) | FIXED 2026-11-17 (62b8e048/49029b67; regression test `dvm/r33_audit_test.go` TestR33Audit06*, invariants `dvm/r33_verify_*_test.go` 37/37) — fix: minimum entry, entry fee not refundable, or weight by verified mining (GT-B25) | gt_prize:103-104; `gametheory/audit/r33_contract_audit.md` |
| GT-A07 | high: gt_attest one challenge slot per claim: the claimant's own Sybil challenges first, no juror reveals, the claimant keeps both bonds and the false claim mints MAT (then a 2x boost in M2/M3) (audit CONFIRMED by a DVM proof-of-concept unless marked) | FIXED 2026-11-17 (62b8e048/49029b67; regression test `dvm/r33_audit_test.go` TestR33Audit07*, invariants `dvm/r33_verify_*_test.go` 37/37) — fix: several challenge slots; an unrevealed dispute never mints; verify claims (GT-B24/B25) | gt_attest:90-93, 184, 300; `gametheory/audit/r33_contract_audit.md` |
| GT-A08 | medium: gt_attest juror commits omit the juror address: a commit can be copied and revealed with the published salt (25,000 earned without judging) (audit CONFIRMED by a DVM proof-of-concept unless marked) | FIXED 2026-11-17 (62b8e048/49029b67; regression test `dvm/r33_audit_test.go` TestR33Audit08*, invariants `dvm/r33_verify_*_test.go` 37/37) — fix: bind the commit to ADDRESS_STRING(SIGNER()) as gt_audit does | gt_attest:141-142, 162; `gametheory/audit/r33_contract_audit.md` |
| GT-A09 | medium: gt_attest: any unchallenged claim mints MAT after 20 blocks (~6 min); the contract cannot check the chain (by design) (audit CONFIRMED by a DVM proof-of-concept unless marked) | FIXED 2026-11-17 (62b8e048/49029b67; regression test `dvm/r33_audit_test.go` TestR33Audit09*, invariants `dvm/r33_verify_*_test.go` 37/37) — fix: claims verified in-contract (GT-B24/B25) or a longer window and a funded challenger | gt_attest:17, 178-181; `gametheory/audit/r33_contract_audit.md` |
| GT-A10 | medium: gt_service: sponsor funds in an epoch with no fee payer can never be paid out (audit CONFIRMED by a DVM proof-of-concept unless marked) | FIXED 2026-11-17 (62b8e048/49029b67; regression test `dvm/r33_audit_test.go` TestR33Audit10*, invariants `dvm/r33_verify_*_test.go` 37/37) — fix: roll unclaimed sponsor funds forward or refund to the sponsor | gt_service:96-105, 138-140; `gametheory/audit/r33_contract_audit.md` |
| GT-A11 | low: gt_attest minstake 0: a zero-weight juror wins, ClaimJuror divides by zero forever, a later stake is locked (audit CONFIRMED by a DVM proof-of-concept unless marked) | FIXED 2026-11-17 (62b8e048/49029b67; regression test `dvm/r33_audit_test.go` TestR33Audit11*, invariants `dvm/r33_verify_*_test.go` 37/37) — fix: require weight > 0 | gt_attest:44, 138, 226; `gametheory/audit/r33_contract_audit.md` |
| GT-A12 | low: installed anonymously (ring > 2): every anonymous caller passes the owner check; the treasury can never be withdrawn (audit CONFIRMED by a DVM proof-of-concept unless marked) | FIXED 2026-11-17 (62b8e048/49029b67; regression test `dvm/r33_audit_test.go` TestR33Audit12*, invariants `dvm/r33_verify_*_test.go` 37/37) — fix: refuse an owner that is not a valid address | every Initialize; `gametheory/audit/r33_contract_audit.md` |
| GT-A13 | low: rounding remainders, slashes with no winner and stray deposits with calls are owned by nobody (no sweep) (audit CONFIRMED by a DVM proof-of-concept unless marked) | FIXED 2026-11-17 (62b8e048/49029b67; regression test `dvm/r33_audit_test.go` TestR33Audit13*, invariants `dvm/r33_verify_*_test.go` 37/37) — fix: refuse DEROVALUE() where none is expected; sweep to the treasury | gt_attest:226, 229; gt_service:141; `gametheory/audit/r33_contract_audit.md` |
| GT-A14 | low (PLAUSIBLE): a block producer at the end of a reveal window can omit a competitor's reveal (audit CONFIRMED by a DVM proof-of-concept unless marked) | FIXED 2026-11-17 (62b8e048/49029b67; regression test `dvm/r33_audit_test.go` TestR33Audit14*, invariants `dvm/r33_verify_*_test.go` 37/37) — fix: reveal windows long enough to span many producers (research rule 4) | Reveal in prize, attest, audit; `gametheory/audit/r33_contract_audit.md` |
| GT-A15 | info (PLAUSIBLE): silent Uint64 wrap in products of owner-set parameters (bond × k, the prize boost) (audit CONFIRMED by a DVM proof-of-concept unless marked) | FIXED 2026-11-17 (62b8e048/49029b67; regression test `dvm/r33_audit_test.go` TestR33Audit15*, invariants `dvm/r33_verify_*_test.go` 37/37) — fix: bound every owner parameter at Initialize | gt_attest:68, 226; gt_service:141; gt_prize:160; `gametheory/audit/r33_contract_audit.md` |
| GT-A16 | info: a notarization stores only the height, not the submitter; a copied digest can front-run (audit CONFIRMED by a DVM proof-of-concept unless marked) | FIXED 2026-11-17 (62b8e048/49029b67; regression test `dvm/r33_audit_test.go` TestR33Audit16*, invariants `dvm/r33_verify_*_test.go` 37/37) — fix: store the submitter; commit-reveal for digests | gt_service:71-72; `gametheory/audit/r33_contract_audit.md` |
| GT-A17 | info (design): a claim is not tied to the claimant's actual miniblocks; several addresses can claim the same range (audit CONFIRMED by a DVM proof-of-concept unless marked) | FIXED 2026-11-17 (62b8e048/49029b67; regression test `dvm/r33_audit_test.go` TestR33Audit17*, invariants `dvm/r33_verify_*_test.go` 37/37) — fix: GT-B25 tags + GT-B24 block proofs | gt_attest Claim; `gametheory/audit/r33_contract_audit.md` |

## 8. Dimension plan (R32 as run; R33 carry)

R32 dimensions: d1 research (agent), d2 block-reward/DAG analysis (agent; branch r32-reward d82e01b4 cherry-picked as
0e3756e2), d3 contracts + DVM tests, d4 econsim, d5 sim chain + wallet tool, d6 playbooks, d7 pipeline + gate + KATs,
d8 artifact + rft + memories. R32a as run (D-GT-11..16): research + security inventory, gt_audit (M4) + DVM tests,
audit tasks, N-wallet sizing, the ladder, four sim pre-flights, the 3 → 5 wallet mainnet ladder, the chain audit,
the DVM console fix (parent B334), the README build section (parent B333); lessons 15–33.
**R33 plan (compounded from R32 + R32a, D-GT-17):** d1 GT-B12 continuous mode (it is what GT-B13 and GT-B14 need);
d2 GT-B13 + GT-B14 measured over the continuous cycles (realized vs expected payoffs, boost vs win frequency); d3
GT-B15 a third audit task + GT-B16 the dispute drill on the sim chain; d4 GT-B3 the per-entrypoint gas census from the
recorded estimates; d5 GT-B17, GT-B18, GT-B20 (harness debts); d6 the R32 carry GT-B1, GT-B4, GT-B7 (they turn
assumptions into measurements), then GT-B2, GT-B5, GT-B6, GT-B8; GT-B19 only on the user's decision.

### 8.1 R33 design (D-GT-23; the user's objectives 10–15 of §2, built on the confirmed GT-B24 and GT-B25)

**The key fact.** A contract can verify a block itself: it stores `BLID()` when a call executes in a block
(`Anchor`), and later accepts that block's bytes only if `SHA3256(bytes)` equals the stored id (GT-B24, CONFIRMED in
the DVM on 4 real mainnet blocks, 1.74M of 10M gas). Every miniblock in those bytes carries its miner's KeyHash and a
free `Flags` field; a game miner writes its game tag there (`--game-tag`, GT-B25, CONFIRMED on a private chain), and
the PoW over all 48 bytes makes the tag unforgeable. So mining for a game identity is **checked by the contract, not
voted on** (research rule 1), which removes the collusion and Sybil-majority problems of R32a's M1/M4 for every fact
that lives in a block. The DVM cannot read other contracts (code research), so the mechanisms that need these facts
live in one contract.

**M5 `gt_pool.bas` — verified mining pool (objectives 3, 4, 1, 2, 5).**
- *Identity.* `Register()` binds `tag = first 4 bytes of SHA3256(SIGNER())` (SIGNER() is the raw 33-byte key; lesson 34)
  to the signer (a taken tag is refused; anonymous signers refused; tags 00000000 and ffffffff are refused because
  stock miners leave Flags at 0, so a ground key with tag 0 would be credited for everyone's work). A non-refundable entry fee `e` (research rule 7: identity must cost
  something that is not refunded) is split between the burn (below) and the reward pool.
- *Proof of mining.* `Anchor()` (anyone) stores `BLID()` for its height; `ProveBlock(h, bytes, ntx, m)` verifies the
  bytes against the anchor, then credits each non-final miniblock whose Flags equals a member's tag (once per block).
  Only main-chain blocks execute calls, so only accepted blocks can be anchored: orphaned work is never paid. A
  prover earns a small fixed proof fee from the pool (someone must pay the ~1.74M-gas call).
- *Reward sharing (objective 3).* Payouts per epoch of E heights from the pool (sponsor deposits, entry fees, game
  fees): member i gets `pool × W_i / ΣW`, `W_i = w_i × (1 + min(s_i / S, 1))`, where `w_i` is i's verified miniblocks
  in the epoch (a PPLNS-style height window, research rule 8: hopping-proof and linear in work, so splitting work over
  addresses gains nothing).
- *Stake weighting without plutocracy (objective 4).* `s_i` is DERO i has locked in the pool (time-locked, withdrawable
  after the lock). Stake at most doubles a member's work share, and stake without mining earns nothing. Splitting a
  stake across identities never helps: two identities with w/2 each and s/2 each get w(1 + min(s/2S, 1)) ≤
  w(1 + min(s/S, 1)). A per-IDENTITY payout cap (share ≤ c of an epoch, the excess rolls on) limits one dominant identity only:
  an operator can split around it at the entry fee per extra identity (R33 research `r33_pool_math.md`); fairness
  rests on the weight being linear in verified work, not on the cap.
- *Deflation (objective 1).* A fixed fraction β of every inflow is moved to `burned`, which no entrypoint can send
  (no SEND path reads it; no UPDATE_SC_CODE; Initialize guarded): verifiable by anyone as `GetSC` balance ≥ `burned`
  + all liabilities. The supply figure itself is a formula (blockchain/supply.go) and never shows a burn, so the page
  reports "emitted minus provably locked". A burn is a cost paid by the burner, not a payment to miners (research
  rule 10); members accept it because the pool's sponsor subsidy is larger than their burn share.
- *Forensics (objective 2).* Every proven block leaves public, verified facts in the contract: height, header
  timestamp, each miniblock's KeyHash and Flags. Per epoch the contract keeps the largest share of miniblocks held by
  one KeyHash among proven blocks (a concentration alarm, public flag) and timestamp gaps; a prover is paid per
  proven block, so the forensics data is produced by the same incentive. Facts that are not in a block (emission
  totals, balances) stay with the audit bounty M4 v2 (no majority over the sponsor, GT-A04 fix).
- *Peer attacks (objective 5), honestly bounded.* A contract cannot see or stop P2P traffic, eclipse attacks or
  reorgs (an orphaned block's state, including its anchor, is reverted). What the pool can do: pay only work that
  ended in main-chain blocks (orphan-causing behaviour is unpaid), raise the number of independent miners (each
  needs its own work; more independent hashrate raises the cost of a 51 % or selfish-mining attack), publish the
  concentration alarm, and cap any one miner's payout share. These are incentives and detection, not prevention.

**M6 `gt_beacon.bas` — discovery (GT-B26, D-GT-22).** The operator publishes the live games (SCIDs, parameters, how to
join, the README path), and only measured figures with height ranges (fees per block, verified miniblocks, burned,
payouts), each reproducible from `GetSC` and block headers; no promised returns. `Subscribe()` lists addresses that
opted in. Indexable by Gnomon (TELA-style name/description header). Cost per update measured with
`DERO.GetGasEstimate`.

**M1–M4 v2.** The audit fixes GT-A01..A17 (independent audit; every contract re-audited before deploy, GT-B21). M1's
mining claim is superseded by M5's verified credit (GT-A07/A09/A17); M1 stays only as the R32 record.

**Measurement (what decides success).** Sim chain first (pre-flight only, D-GT-5), then mainnet with new SCIDs: (1) every
pool payout equals its formula from the contract's verified credits (a chain audit like cycle_audit); (2) the burn is
locked (balance check at several heights); (3) split-neutrality and the payout cap measured in econsim and the DVM
tests; (4) outside participation counted only by tags that are not the operator's committed wallet set (OR-7..OR-10);
(5) the hashrate effect stays bounded by §4 goal 5 until outside tags appear.

### 8.2 R33 objectives tracker (the user, 2026-11-17: every R33 objective and every open R32/R32a objective goes through research → design → implement → debug → enhance in R33; D-GT-25)

Stages: R researched (sources/anchors in `gametheory/research/`), D designed (§8.1 or a row), I implemented, T tested
(DVM/KAT/econsim), P pre-flight on the private chain, M measured on mainnet, E enhanced from a measurement. A stage is
claimed only with its evidence; "—" means not reached yet.

| Objective (source) | R | D | I | T | P | M | E | Evidence / next |
|---|---|---|---|---|---|---|---|---|
| S. security limits of R32a: collusion, Sybil auditors, consensus/peer/range-proof (§2 item 10) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | check-don't-vote block proofs (GT-B24, measured on mainnet: 36 + follow-mode proofs verified in-contract), gt_audit v2 dispute-not-override (GT-A04; W16 drill on a private chain), bribery = griefing only (W4), front-running harmless (W6); limits stated (§8.1) |
| 1. deflation through the suite (item 11.1) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | gt_pool burn β 20 % (balance ≥ burned, conservation tests); sim burned 20,600; MAINNET epoch 19,790: 21,000 atomic burned (locked, GetSC-verifiable), published on the mainnet beacon |
| 2. chain/block forensics through contracts (11.2) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | verified timestamps + KeyHash census per epoch (k/kn/km), research r33_forensics_and_security.md (alarm t = 0.40). MAINNET epoch 19,790 (read from the pool contract, GetSC): 324 proven normal miniblocks, 19 distinct KeyHashes, largest 55 = 17.0 % (then 53, 53, 47, 37): no concentration; 42 verified timestamps. E: the alarm summed across epochs (one follow epoch is too small a sample): census over 5 epochs (19,790–19,798, `harness/runtime/gt_pool_census_mainnet.json`, refreshed 2026-11-18 by pool_census.py): 918 verified miniblocks, 23 KeyHashes, top 18.7 %: no alarm (sample ≥ 360, GT-B35), published on the beacon |
| 3. more miners, reward sharing for all (11.3) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | gt_pool linear work weight, follow-mode proving (GT-B34), continuous mode (GT-B12). MAINNET: 5 epochs (19,790 / 19,791 / 19,793 / 19,796 / 19,798), every independent re-audit PASS, credits paid to m1, m2 and m4; outside members stay the user's decision (pull-only, GT-B19/B26) |
| 4. stake-weighted without plutocracy (11.4) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | W = w(1+min(s/S,1)), split-neutral (econsim 4,000 splits; TestR33PoolSplitNeutral), ≤ 17.16 % pot transfer. P: W1 private chain, m3 with a matured 1-DERO stake at weight 200 per credit. MAINNET epoch 19,798 (record `gt_pool_mainnet_20261118T115043.json`, independent re-audit `gt_pool_reaudit_mainnet_e19798.json` PASS, 15 proven blocks 7,919,229–7,919,256): m2 (1 DERO locked at 7,917,727, matured) 3 credits → W 600 = 200 per credit (the 2× ceiling, never more), TW 600, claim 5,100 = the 30 % per-identity cap of P0 17,000 (the cap, not the stake, bounds a lone staker). E: epoch 19,796 left the boost unexercised (m2 mined no proven miniblock) → D-GT-29 steered the earn miner to m2 |
| 5. secure blocks from peer attacks (11.5) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | only main-chain work is paid; concentration alarm; honest limits (no P2P view). Mainnet: the largest miner held 17.0 % of epoch 19,790's verified miniblocks (alarm at 40 %). E: census over 5 epochs (19,790–19,798, `harness/runtime/gt_pool_census_mainnet.json`, refreshed 2026-11-18 by pool_census.py): 918 verified miniblocks, 23 KeyHashes, top 18.7 %: no alarm (sample ≥ 360, GT-B35) |
| outside participation / beacon (item 15, GT-B26/B28) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | pull-only (D-GT-22); gt_beacon on mainnet with measured figures (pool epoch summary, SCID, census); the contracts README tutorial; `gametheory/ANNOUNCE_DRAFT.md` (measured figures with height ranges only, IDs as placeholders) for the user to post if they choose. Outside participation itself is the user's decision (GT-B19) |
| contract security audit (item 14, GT-B21) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | GT-A01..A17 + 5 invariant findings fixed; 37/37 invariants; the fixed gt_pool (5 epochs) and gt_audit v2 (step 3c) run on mainnet. Next: re-run the invariant suite after every contract change (KAT) |
| contracts README tutorial (GT-B22) | ✓ | ✓ | ✓ | ✓ | — | — | ✓ | `gametheory/contracts/README.md` + KAT R33-5 |
| R32 primary: DVM/SC game suite grounded in the reward code (§2 items 3–5) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | R32 measured 2026-11-15: three contracts (M1–M3), econsim, the zero-touch pipeline G35; one mainnet cycle settled and chain-audited (G36); then superseded for mining credit by M5 (R33) |
| R32 primary: dedicated wallets, mining to them, deploy, play; the user's address never used (§2 items 5–6) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | gt-wallet + playbooks; banguard (sha256) refuses the user's address everywhere; the earn job mines the gt wallets only (D-GT-4) |
| R32 primary: the artifact page + PDF in the house style (§2 item 7) | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | `artifacts/dero-enhanced-game-theory.html` (R33 rebuilt as a developer's guide, GT-B36) + its PDF kept in sync by pdfsync (B335) |
| R32a primary: the mainnet ladder 3 → 5 wallets (§2 R32a path) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | R32a measured 2026-11-16: steps 3/4/5 settled, 15/15 prize rounds genuine, 6/6 audit rounds, every chain-audit sum = −fees |
| R32a primary: miners paid to mine along with the games (network hashrate) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | R32a: fees 0.27–0.59 % of the block reward (bound, §4 goal 5); R33: verified mining pool pays verified work (M5), members' verified share = hashrate prediction (GT-B13) |
| R32a primary: security concerns addressed where a game can (detection) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | R32a M4 audit bounty; R33 v2 dispute-not-override, block proofs (check, don't vote), turnstile task 3, the census alarm |
| GT-B1 multi-round sim game, N ≥ 6, strategy mixes (R32) | ✓ | ✓ | ✓ | ✓ | ✓ | — | ✓ | DONE (W1, record `gt_pool_sim_20261117T190627.json`, chain audit PASS, 44 proven blocks): 7 wallets, 5 members: m1/m2 honest, m3 with a matured 1-DERO stake (weight 200 per credit), j1+j2 one operator split, u1 untagged non-member (0 credit), u2 a non-member mining with m1's tag (its work credited to m1: 113 ≈ 2 × 53, u2 gains nothing); claims = pool × W / TW (m1 72,000 × 11,300 / 39,200 = 20,755). The split's 122 vs ~53 is the sim's dispatch-bound mining (W10), not a pool rule: credits equal each tag's verified miniblocks |
| GT-B2 isolated-testnet path (R32) | ✓ | ✓ | — | — | — | — | — | CLOSED (D-GT-26): the private simulator chain pre-flights every path and the result is measured on real mainnet (D-GT-5), so an isolated testnet adds no evidence; reopen only if a path needs the real derod P2P/getwork stack before mainnet |
| GT-B3 mainnet fee per entrypoint (R32) | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | DONE (W3): `harness/gametheory/gas_census.py` → `harness/runtime/gt_gas_census_mainnet.json` (KAT H3): 453 mainnet calls in 5 records; every estimated call paid more than its storage gas (smallest margin 107, prize:Draw); pool on mainnet: ProveParent storage median 1,482.5, fee median 1,682.5 (+200), ProveBlock 1,546 / 1,746, Register 128 / 232, Anchor 106 / 229 |
| GT-B4 juror bribery (R32) | ✓ | ✓ | ✓ | ✓ | — | — | ✓ | DONE (W4, `dvm/r33_wb_test.go` TestR33WBAuditBriberyW4): k = 1..7 bribed auditors of 8 against an honest sponsor: every round disputed, all 8 bonds refunded, the bounty back to the sponsor, the contract at 0; briber net ≤ −564·k atomic (its own call fees) minus any bribe; the honest auditors lose their would-be share (14,285 at k = 1 to 100,000 at k = 7): griefing, never profit |
| GT-B5 MAT value assumption (R32) | ✓ | ✓ | — | — | — | — | — | CLOSED for R33 (D-GT-26): M5 pays DERO and credits only verified work, so no R33 mechanism rests on a MAT value; MAT remains an assumption of the M1–M3 boost games, whose boost effect is measured by W14 |
| GT-B6 front-running public SC arguments (R32) | ✓ | ✓ | ✓ | ✓ | — | — | ✓ | DONE (W6, TestR33WBFrontRun*/RegisterRace/BeaconPublish/AuditCommitCopy): a copied ProveBlock/ProveParent leaves credits, weights, census and claims identical and moves only the 2,000 prover fee (the original reverts cleanly; its sender still pays its tx fee); a Register copier gets its own tag; beacon Publish is owner-only; a copied audit commit can never be revealed (the copier forfeits its bond) |
| GT-B7 DVM own-token stored balance underflow (R32) | ✓ | ✓ | ✓ | ✓ | — | — | ✓ | DONE (W7, TestR33WBOwnAssetCounterW7) — the R32 row was wrong in detail: the own-asset overflow/underflow checks are skipped (dvm/simulator.go:211, 223), the wrapped difference is computed (:229) but `StoreSCValue` drops any write keyed by the contract's own id (dvm/sc.go:395-398), so nothing wraps in state; the own-token balance is never stored and reads 0; own-token deposits back are dropped (dvm/sc.go:209-213); DERO keeps its underflow revert. Safe: the own token is unlimited by design and no builtin reads that balance; residual: a holder minted ≥ 2^64 in total gets an undecodable balance (author's concern, not supply/consensus) |
| GT-B8 multi-address Sybil study (R32) | ✓ | ✓ | ✓ | ✓ | ✓ | — | ✓ | DONE: the pool rule is split-neutral (econsim 4,000 splits, TestR33PoolSplitNeutral); W1 shows the only way splitting gained was more miner PROCESSES at sim difficulty 1 (W10); on mainnet miniblocks follow hashrate, so a split gains nothing in credit and pays an extra entry fee per identity |
| GT-B10 sim-share anomaly (R32) | ✓ | ✓ | ✓ | ✓ | ✓ | — | ✓ | DONE (W10, from W1): 396 normal miniblocks over 44 blocks, 7 miner processes at --cpu-max 20 or 40: ≈ 56 each (u1 56, m2 53, m3 52, j1 45, j2 77, m1's two 113): at difficulty 1 a share follows the number of processes, not CPU (lesson 0's hypothesis measured); sim shares are never used as hashrate evidence |
| GT-B11 time-to-coins from measured H/s (R32) | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | DONE (W11, KAT H11): `time_to_coins.py --hs H | --from-earn-log FILE` (restart-aware rate): the r32 earn log, 55.1 h of ticks → 9.955 DERO/day ≈ 23.2 kH/s effective at the live difficulty, agreeing with the 22.4 kH/s the miner reported in R32 |
| GT-B13 realized vs expected payoffs (R32a) | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | DONE (W13): the pool pays the formula exactly (3 mainnet epochs, independent re-audit PASS), so realized vs expected is the work: cycle 1's fixed-depth sample (unbiased w.r.t. who mined) gave members 4 / 324 = 1.23 % of normal miniblocks; predicted from the measured 23.2 kH/s (W11) against the network's ~1.89 MH/s (difficulty 3,313,621, 17.54 s blocks) = 1.23 %; z = +0.01. Verified credits track real hashrate on mainnet |
| GT-B14 boost vs win frequency (R32a) | ✓ | ✓ | ✓ | ✓ | — | — | ✓ | DONE (W14): econsim replicates gt_prize Draw exactly (Reveal sd += num; pick = sd % tw): 20,000 rounds, boosted 200,000 vs four 100,000 → wins 6,652 / 3,349 / 3,332 / 3,277 / 3,390, χ² 2.02 (df 4, p ≫ 0.01): frequency = weight / total. R32a step 5's m4 4-of-5 had P(≥ 4 of 5 at 1/3) ≈ 4.5 %: luck, not a defect |
| GT-B15 third audit task: SC balance turnstile (R32a) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | DONE (W15, KAT H15): `audit_tasks.py --task 3 --scids S1,.. --topoheight T`: sha256 over sorted `<scid>:<balance>` lines + `total:<sum>:<n>` from DERO.GetSC at T; refused below the pruned floor, within 20 of the tip, > 32 or malformed SCIDs; live: the six mainnet gt contracts at topoheight 7,916,400 → total 97,000 atomic, the same answer twice. PRIVATE CHAIN (W15, `gt_cycle.py --audit-tasks 3,1`, record `harness/runtime/gt_cycle_sim_w15_20261117.json`): a gt_audit round with task 3 over the cycle's 4 contracts (total 66,000 atomic): sponsor and both auditors matched, 2 winners, 3,000 each, settled; then a task-1 round settled the same way. MAINNET (step 3c, 2026-11-18 04:39–05:03, record `gt_cycle_mainnet_20261118T050346.json`, heights 7,919,884–7,919,961): gt_audit v2 installed (new SCID, fee 17,790), one task-3 round: 4 auditors entered and revealed, all matched the sponsor, settled nw 4, share 1,500 each, no dispute, every bond refunded; fees 25,883 atomic; chain audit (`gt_cycle_audit_mainnet_20261118T050346.json`, mining from the chain: m1 12,300) net m1 −26,107, m2..m5 +56 each, sum = −fees exactly. E: the record missed the Settle fee (lesson 39, fixed + KAT R33-8). Limit: the run's turnstile covered only its own contracts (the new audit SCID, total 0) → GT-B37 |
| GT-B16 the dispute path on chain (R32a) | ✓ | ✓ | ✓ | ✓ | ✓ | — | ✓ | DONE (W16, `gt_cycle.py --wrong-audit 1`, record `harness/runtime/gt_cycle_sim_w16_20261117.json`, private chain 2026-11-17 11:16): round 0 honest → 2 winners, 3,000 each; round 1 with a planted wrong sponsor answer → disp 1, refund 1, nw 0, every bond refunded, the 6,000 bounty reclaimed by the sponsor; the same run re-played the fixed M1–M4 end to end (prize round drawn, 3 entrants) |
| GT-B17 earn credit counter reward//10 (R32a) | ✓ | ✓ | ✓ | ✓ | — | — | — | DONE (W17, KAT H17): gt_earn `chain_credits()` uses cycle_audit.chain_mined ((base reward + block fees) // miniblocks, the integrator's final share excluded); display only; takes effect on the earn job's next relaunch |
| GT-B18 content-hash staleness of gt bins (R32a) | ✓ | ✓ | ✓ | ✓ | — | — | — | DONE (W18, KAT H18): gtlib.stale_bins compares `<bin>.srchash` (every package the command imports from the module or vendor/, plus go.mod/go.sum/vendor/modules.txt, ~1,070–1,400 files, ~0.5 s), file times only when no hash is recorded |
| GT-B20 version-bump KAT (R32a) | ✓ | ✓ | ✓ | ✓ | — | — | — | DONE (W20, `harness/kat/test_version_bump_r33.py` VB1/VB2, 8/8 mutations): every non-pending round in harness/round.json: a consensus-package change between new_tests_base and head_after requires config/version.go to carry that round's suffix; 13 rounds ok |

### 8.3 R33 coordination (the user, 2026-11-17: "make sure everything is well coordinated for all above tasks to get best coherent results"; D-GT-27)

One commit stream: every change lands in <repo> by the main session; agents work only in their own
`git clone --shared` under the scratchpad and hand back a commit, which is merged (fetched by branch, never by a short
hash: lesson 37) and re-tested before anything builds on it. Live jobs never share a resource:

| Job | Resource it owns | May run with | Must not run with |
|---|---|---|---|
| earn job (gt_earn, stallwatch) | the one pipeline-owned mainnet miner, tagged (8-byte) | everything | a second mainnet miner |
| mainnet pool cycle (gt_pool_cycle --network mainnet) | the m1..m5 wallet servers on 47850-47854; mainnet spends of the gt wallets | earn job, sim runs, agents | another mainnet cycle (same wallets and ports) |
| private-chain runs (gt_playbook + gt_pool_cycle/gt_cycle --network sim) | ports 47100/47102/47180, sim wallets 47250+ | everything mainnet | another sim run (same ports) |
| agents | their clone only; no node writes; mainnet RPC read-only | everything | each other's files (split by file before launch) |

Order of work (each step's gate must PASS before the next uses its output):
1. mainnet cycle 1 (r33-pool-mainnet-1) → its chain audit (gate: audit ok, conservation, claims = formula);
2. agent A's harness items (W3/W11/W15/W17/W18/W20) and W16 drill → merged; gates: go test ./dvm -run 'R32|R33',
   test_gt_r33, test_gt_mechanisms_r32, gt_pipeline implementation/debug/enhancement;
3. mainnet continuous mode (--follow --epochs N), sized from cycle 1's fee per proof and credits per proven block;
   gate per epoch: the chain audit; stop after 3 failures;
3b. DONE (epoch 19,798, weight 200 per credit, re-audit PASS). objective 4 on mainnet: one pool epoch with m2 locking 1 DERO of stake (`--lock m2=100000`), after the continuous loop
   releases the wallets; gate: the audit models the matured boost;
3c. DONE (2026-11-18 05:03, 4/4 auditors matched, settled; chain audit sum = −fees). GT-B15 on chain: deploy the fixed gt_audit v2 (new SCID; the R32 SCIDs stay retired, D-GT-20) and run one audit
   round with task 3 (the turnstile over the gt contracts); gate: every auditor matches, the round settles;
4. W13 from the continuous records; the beacon publishes each audited epoch and the census (GT-B35);
4b. GT-B26 outreach: an announcement draft with measured figures only (`gametheory/ANNOUNCE_DRAFT.md`), posted by the
   user if the user chooses (pull-only, D-GT-22; nothing is sent to anyone by the pipeline);
5. R33 close: every §8.2 row closed with evidence; the full pipeline (fix_build_verify, the miner package changed);
   pages, PDF, memories; the public sync with the contracts README; the push is the user's.

## 9. NO-GO ledger (do not re-propose without new evidence)

N1 referral pyramid / pay-earlier-from-later deposits (Ponzi-shaped; econsim stop-inflow flags it) · N2 SC-native PoW
faucet (diverts hashrate from AstroBWT: the opposite of the goal) · N3 marketing subsidised activity as organic
(misleading) · N4 a contract that raises the block reward (infeasible, consensus) · N5 emission-funded yield with
promised returns · N6 quadratic funding without sybil resistance · N7 an orphan-insurance contract (research Q5: uncle
rewards lowered the selfish-mining threshold from 0.25 to about 0.185; paying for orphans subsidises withholding) · N8 superlinear
loyalty / streak bonuses or per-identity stipends (research Q1: they reward consolidation and Sybil identities). · N9 batched gt_pool proofs as a fee saving (a proof's storage gas is ~2 per block byte of call data, dvm/sc.go:261-263; batching moves the same bytes; measured 2026-11-17, GT-B33). Full reasons: `gametheory/mechanisms.json`.

## 10. Lessons (R32)

0. **Sim mining shares are not hashrate shares.** In `gtp-sim-v4` the 20 %-CPU miner m3 was credited 22,970,250 atomic
   against m1's 19,311,000 at 90 %: the three miners' own logs show the SAME rate (m1 542–563, m2 546–563, m3 532–551
   H/s; `<home>/derohe-persist/gt-sim/runs/gtp-sim-v4-sim/miner-*.out` TOTAL lines), so --cpu-max had no effect at
   difficulty 1, where every hash is a solution and the loop is bound by job dispatch and submission. Which of the equal
   miners fills the first 9 normal slots of a tip (blockchain/miner_block.go:338) then decides the credit; the dispatch
   order as the cause is a hypothesis (GT-B10), not measured. No payoff conclusion is drawn from sim mining shares.

1. The in-process DVM simulator never debits deposits and credits a reverted call's deposit back: count what the
   contract sends and holds, not the sender's balance.
2. DVM `&&` / `||` evaluate both sides: a `LOAD` of a missing key inside a condition panics; guard with `EXISTS` first.
3. DVM uint64 arithmetic wraps silently: check before every subtraction.
4. derod refuses `params` on parameterless JSON-RPC methods (-32602): omit the field.
5. On the simulator the getwork template is built for the integrator: it must be a registered address.
6. Off mainnet every registration is credited 1,000 DERO: payoff accounting must remove the grant.
7. Sim block rate is set by job dispatch, not hashrate (difficulty 1): a miner's miniblock share there is not its
   hashrate share; the attestation game is unaffected because it counts the chain.
14. **A live job must not write tracked records the pipeline hashes.** Pipeline runs 4 and 5 failed (page STALE, G3 corpus STALE) because the mainnet trigger re-ran `cycle_from_earn.py` every minute and rewrote `harness/runtime/gt_earn_mainnet.json` and `gt_mainnet_cycle.json` mid-run. Fix: the records are written only on `--write` (the pipeline's own snapshot in `gt_pipeline.py`), and the pipeline re-renders the game-theory page before `--check`. KAT GT13 plus mutation 'r32 liverec'. The running trigger needed no restart: its call now prints and writes nothing.
15. **A rotation must skip a wallet that is already at target.** At 08:14–08:34 on 2026-11-15 the earn job ran strict round-robin 20-min slices. Strict turns hand the miner to a wallet that has already reached its target, which wastes a slice. Fix: `gt_earn.pick_next` gives the next slice to the wallet furthest below target; unknown or failed balance reads are re-measured first; round-robin only when nothing is known. KAT GT14 plus mutation 'r32 slicepick' (suite 14/14, mutations 33/33, coupled 2). The running earn job (target 4.0, D-GT-6) keeps the old code until its next relaunch; it was not restarted just before the game start.
16. **A tx is final only in a valid main-chain block, a few blocks deep, and every setup step is verified by its effect.** On 2026-11-15, the first mainnet cycle failed partway through. Its attest `Freeze` tx was reported mined at 08:47, then was found in no main-chain block (7,906,700–775), in no pool, and not in m1's own transfer list. The old `wait_tx` accepted any `in_pool false + block_height > 0` once. The Claim that followed was reverted by `frozen == 0`. Finalize then received `i = nc - 1 = -1`, which the wallet RPC returned as an opaque -32602 after 8 retries. On-chain read: attest `frozen 0`, `nc 0`, balance 0; service and prize frozen. Fix: `tx_state` (valid block, CONFIRM_DEPTH 3; a tx lost for 60 s is resent, SEND_TRIES 3); `setup_needed` skips frozen contracts and setup ends by checking that all three are frozen; `claim_index` fails closed on a reverted Claim; `arg_u` refuses values outside Uint64; full txids go in the local event log only. KAT GT15 plus 5 mutations (suite 15/15, mutations 38/38, coupled 2).
17. **A trigger's retries are bounded, and a deliberate stop is never relaunched; never open a wallet file a cycle is serving.** The trigger re-ran the failed cycle at 08:58 with no retry limit. Its setup calls on the already-frozen contracts revert and cost about 0.013 DERO. `give_up` now stops after 3 failed cycles in a row and writes `trigger.STOPPED`; the stallwatch recipe gains `--stop`. At 09:00 the main session opened m1.db in a second `serve` while the cycle served it. The cycle carried on (its next call landed at 09:01:31), but the cycle's own loopback wallet RPC would have answered the same query safely.
18. **Every player's commit-window entry goes first, in parallel.** In the 2026-11-15 mainnet cycle, m2's Enter in rounds 3–5 landed at Draw + 21/22 blocks (round 5: rs 7,907,009, m2 Enter at 7,907,031). That is past the 20-block commit window, because the previous round's two Withdraws, the Fund and m1's Enter ran one after another before it, each waiting for its own confirmation. The prize contract shows n1..n5 = 2, 2, 1, 1, 1; m2 paid only the 339-atomic fee for each rejected Enter. Fix: `m3_round` sends both Enters in parallel first in the window, then the previous round's Withdraws (deferred) and the Fund; Reveals in parallel. Calls from one wallet stay sequential. The entry index is read back by commit (`entry_index`), and a rejected Enter is logged (`enter_rejected`). KAT GT16 plus 2 mutations.
19. **A game counts as settled only when every player entered, and payoffs are net of mining.** The first record's own verdict counted three solo rounds as settled, and its payoffs (+22,411 / +27,867) included the mining credited during the cycle. `cycle_audit.py` re-derives entrants from the contract and subtracts the window's mining (earn log chain_credited at heights 7,906,772 to 7,907,063: m1 39,975, m2 24,600), giving net payoffs m1 -17,564 and m2 +3,267. Their sum, -14,297, matches the -14,321 in fees (check passes). m2's figure is exact (8,000 won - 4,733 fees). G36 now requires that audit of the same record. KAT GT17 plus 2 mutations; GT9 updated.
20. **A harness tool prints `--help` without its playbook imports.** Pipeline run 8 FAILED at TK1 (test_tools_kats_r27), which runs every tool's `--help` in a sandboxed clone. The new `cycle_audit.py` imported `gt_cycle` at module load and raised ModuleNotFoundError there. Fix: the playbook modules are imported on use (`_lib()`). TK 6/6, mutations 23/23; GT 17/17, mutations 42/42.
21. **DERO.GetSC returns String variables hex-encoded.** `cmd/derod/rpc/rpc_dero_getsc.go:138` writes `fmt.Sprintf("%x", []byte(v))`, so a stored commit reads back as the hex of its ASCII bytes. The R32 cycle never read an entry index back (it assumed wallet order), and the R32 KATs fed raw strings, so the bug passed every test. Found by the sim pre-flight (prize rounds without reveals, audit entries unmatched). Fix: `sc_str_eq`; GT16/GT21 fixtures now use the daemon's encoding; KAT GT22 plus mutation 'r32a hexstr'.
22. **ADDRESS_STRING() is always the mainnet form.** `dvm/dvm_functions.go:358` → `rpc.NewAddressFromKeys` (Mainnet: true, `rpc/address.go:196-198`). A sim/testnet wallet reports `deto1…`, so the auditors bound the wrong string and every reveal failed. Fix: `gtlib.mainnet_form` (BIP-173 bech32, hrp re-encoded, checksum verified); on mainnet it is the identity. KAT GT21's worked example is unchanged.
23. **Windows are sized from measured call latency.** On the sim chain (~0.7 s blocks) a fixed 20-block commit window closed before one confirmed call landed (audit Enter refused, prize rounds skipped). The cycle now measures blocks per confirmed call on the installs and freezes window = max(20, 4 × bpc) before SetParams (mainnet ~7 → 28). Auditors compute their answers before the Post, so Enter follows at once. KAT GT22 plus mutation 'r32a windows'.
24. **The storage-gas limit IS the transaction fee.** `blockchain/transaction_execute.go:395` passes `tx.Fees()` as `gasstorage_incoming` (`dvm/sc.go:244-250`, cap `config.MAX_STORAGE_GAS_ATOMIC_UNITS` 20,000), while the wallet sizes the fee by tx size. gt_audit Settle (small, many STOREs) paid 235 and reverted: 'Insufficient Storage Gas' in the sim daemon log at 15:56:59 and 15:58:05. Fix: every SC call reads DERO.GetGasEstimate (read-only) and, above 150 storage gas, pays the estimate + 30 % + 100 (floor 600, cap 20,000); the ladder sizes with those floors. KATs GT23, GT24. Pre-flight 4: 3 claims finalized, 5 genuine prize rounds (3 entrants, 3 reveals, a winner each), 2 audit rounds settled (2 winners, share 3,000 each), 0 storage-gas errors, 0 errors (sim, not a result).
25. **Opening a sub-round touches every round list, and a merged clone must render its pages before the merge.** The R32a project-only runs failed four times, one defect each: the soundness page for r32a (carry-forward), r32a missing from areas.json / mine_evolution ORDER / disclosure_track rounds (HS1), the disclosure model stale after that (DT1), the six gt_audit DVM tests not in NEW_TESTS (NT1), and the M4 mechanism without the `sustainability` and `attacks` fields the page generator reads. HS1 also lost its proof: with a sub-round current, its parent is measured, so the current-round ledger check had no case of its own (mutation B149 MISSED); a sub-round case now pins it (47/47). The remaining KAT files were then run ahead of the pipeline (42/42 PASS) and the run passed: `pipeline_20261115T212738` (35/35, 34/34, gates 33/36 + 3 PAUSED).
26. **Fund the next wallets while the current step plays; a relaunch rebuilds a stale binary.** As written, the ladder added mN to the earn job only when step N began, so each step would have waited about 2 h for a new wallet to be registered and mined. At 23:09 the earn job was extended to m1..m5 at once; neediest-first rotation then funds m4 and m5 during steps 3 and 4. That relaunch refused every minute: `gtlib.stale_bins` compares file times, and `cmd/dero-miner/hsreport_r30.go` had been touched (16:17, content as committed at d9e5e264). Stallwatch reached 3 of its 4 hourly relaunches before `--rebuild` went into the live command and into `gt_ladder.earn_cmd`. Open: a content-hash staleness check instead of mtimes.
27. **The chain audit counts mining from the block headers, after an earn tick past the record.** Ladder step 3 (record `gt_cycle_mainnet_20261116T011609.json`, 01:16:09) was audited 3 s after its record, before any earn tick bounded the window (net payoffs None). The earn counters had also restarted at the 23:09 relaunch, and a counter-based window then missed two of m1's shares: 33,825 instead of 39,975 atomic. Fix: `cycle_audit.chain_mined` reads each wallet's normal miniblocks from DERO.GetBlock (addresses from `gt-wallet address`, in memory only); `mined_window` is reset-aware (KAT GT25); the cycle records `start_height` / `end_height`; the ladder waits for an earn tick past the record. Step-3 audit: rounds 1–5 genuine, 2 audit rounds settled with 2 winners each, net payoffs m1 −88,687 / m2 +2,054 / m3 +1,054, sum −85,579 against −85,608 in fees (check passes). KAT GT26 + mutation; suite 26/26, 59/59.
28. **An audit reads the run its record names.** Project pipeline 2026-11-16 02:05 FAILED at G36 although the step-3 audit had passed: the game-theory pipeline re-ran `cycle_audit.py --write` without `--run`, the tool defaulted to the R32 run (`r32-mainnet-cycle`), and it read R32's prize contract for the entrants (settled False) and R32's cycle start for the window (sum −629,854). Fix: `--run` defaults to the record's own `run` field. The local game-theory pipeline then gave G35 and G36 PASS (genuine rounds 1–5, sum check passes).
29. **A gas estimate is not free on the node: cache it.** The derod console filled with DVM traces and `sc execution error %!s(<nil>)` lines (the user, 2026-11-16). Every traced call ended RETURN 0. The noise came from DERO.GetGasEstimate, which lesson 24 made the cycle call before every SC call (102 in step 3), and from two upstream printing defects in dvm/ (parent B334, D-41). Fix here: one estimate per (contract, entrypoint) per cycle (`cached_estimate`, KAT GT27 + mutation).
30. **Mine toward the next step's needs, not toward the poorest wallet.** After step 4 (05:03) step 5 needed the sponsor m1 at 1.985 DERO (it had 1.642, having paid two steps) while m5 already held 1.200 against a 0.771 need. The poorest-first rotation mined m5 and would have left m1 waiting for hours. Fix: gt_ladder writes the step's needs to `<GT_HOME>/mainnet/earn_targets.json`; gt_earn reads it every slice and mines the wallet furthest below ITS need, falling back to poorest-first when every need is met (KAT GT28 + mutation; GT14's mutation sharpened to the least-needy pick). Applied live 05:22: targets written from the ladder's own tick, earn restarted, m1 mined from 05:22:27.
31. **A consensus-package edit moves anchors: re-check them before the full pipeline.** The full pipeline of 2026-11-16 07:44 FAILED in S3k (test_gt_reward_r32 GR1): the three comment lines of the D-41 fix in dvm/sc.go moved reward anchors RW42/RW43 by +3 lines (MOVED; quotes unchanged), and the soundness page still counted 9 consensus-package files instead of 11 (G22). Before a full run after any consensus-package edit: `reward_intel.py --check` (0 MOVED), `soundness.py` (G22), `disclosure_track.py --check`, the gomut anchors (find-text, unaffected), then regen. The new trace condition also got a Go mutation (gm-r32a-dvm-sim-trace-always). CORRECTED 2026-11-16 12:10: the first form ('if simulator {') was INVALID in the full pipeline (S3b: the `globals` import became unused), and the main session had read that compile failure as the test failing. The mutant now restores the old bug exactly (trace whenever --debug is present as a bool) and fails on the test's own assertion (r32a_simtrace_test.go:76). Read which line a test failed on before calling a mutation proved.
32. **A miner's share includes the block's fees.** Step 5's chain audit missed the sum by 420 atomic. A per-wallet reconstruction from the record (fees, prizes, audit shares) matched four wallets exactly and put the whole 420 on m1, the wallet that was mining. The audit had credited each share as reward // 10; consensus pays (base reward + the block's tx fees) // len(miniblocks) (process_miner_transaction, reward_intel.split RW13-RW18), and the blocks carried our own SC calls. Fix: `chain_mined` reads each block's fees from DERO.GetBlockHeadersRange (by topoheight) and splits base + fees. With it, all three ladder steps balance EXACTLY: sums −85,608 / −46,144 / −56,252 equal minus the fees, and the 29 and 22 atomic residues of steps 3 and 4 were the same fee share (KAT GT26 fee case + mutation; 28/28, 62/62).
33. **A new node build carries its round in the version.** The user asked (2026-11-16 15:50) whether `+22102026.r31` was right for the R32a build: it was not. The binary was the R32a build (installed 14:43:57; the `sc execution error` string absent, sha-256 differs from the r31 backup), but `config/version.go` had not been bumped, so derod could not say which round it was. Every earlier node round bumped it (r28d, r29, r30, r31). Fix: build metadata `+22102026.r32a` (the guard's `build-metadata only` class; semver and the P2P handshake ignore it); a full pipeline with install, and one more user restart. Bump the version in the same commit as the first consensus-package change of a round.

34. **`SIGNER()` is already the raw key; `ADDRESS_RAW(SIGNER())` is the empty string.** gt_pool's first tag rule
    hashed `ADDRESS_RAW(SIGNER())`; ADDRESS_RAW only parses an address string and returns "" otherwise
    (dvm/dvm_functions.go:348-352), so every member got the same tag and the second Register was refused. A DVM test
    with two members caught it before any deployment. Rule: hash `SIGNER()` directly; test every identity rule with ≥ 2
    identities.
35. **DVM `IF` takes only `THEN GOTO`.** `IF c THEN LET/STORE/RETURN` is not DVM-BASIC (dvm/dvm.go:730-746); write the
    branch as a jump.

36. **A DVM jump targets a line number: never reuse one.** Adding the gt_service wrap fix renumbered line 92, the
    target of `88 GOTO 92`, so the exact-payout path fell into the new share computation; R32/R33 tests caught it at
    once (5 service tests). Rule: inserted lines take unused numbers; grep every `GOTO <n>` before reusing `n`. A `DIM`
    that a jump skips is never declared ("used without definition"): declare at the top.

37. **Fetch an agent's commit by its branch, and check the merge landed.** `git fetch <clone> 2dd0db53` failed (a short
    hash is not a ref), the cherry-pick did nothing, and the tracker row was committed as if the tests were merged; a
    test run with "[no tests to run]" exposed it. Rule: fetch by branch (or the full hash), and run the merged tests by
    name before recording them.

38. **A directory is not a work file, and a relaunch must resume, not replay.** The continuous loop's watchdog watched
    the run directory; its mtime changes only when files are added, not when events.jsonl grows, so after 4 h it
    judged the loop stalled and relaunched it mid-epoch 19,793 (15:21). The new process funded the epoch a second time
    and its audit trusted its own empty proof list, so it reported 2 credits against the contract's (correct) 4.
    Fixes: the watchdog watches events.jsonl; the audit takes the contract's pr<h> keys as the proven set; the loop
    records funded/recorded epochs and skips them, never claims twice, preloads contract-proven heights;
    `harness/gametheory/pool_audit.py` re-audits any epoch independently (19,790 / 19,791 / 19,793 all PASS).
39. **A fee the wallet has not indexed yet is not zero.** Step 3c's record summed fees with `fee or 0`; m1's Settle was
    not in the wallet's transfer list within 40 s, so the total missed 600 and the chain audit's sum check failed by
    exactly 600 (m1's balance delta +2,475 was one 3,075 miniblock minus the 600 fee). Fixes: the cycle resolves every
    unresolved fee again at record time, else takes the fee the tx set explicitly, records `fee_source` and
    `fees_unresolved`; never invents one (KAT R33-8, two mutants caught). The same run showed cycle_audit assumed a
    prize contract; an audit-only record is now audited and writes only its own file (G36's game-cycle file untouched).
40. **A page is checked against the records as they are when the check runs.** The project-only pipeline_20261118T071831
    failed GP0 (page STALE): its gt_pipeline step rewrote gt_sizing_last.json from the live earn log (9.887 → 9.806
    DERO/day), and the KAT files ran before the stage's own re-render. Fix: the stage re-renders the game-theory page
    right after the steps that rewrite its live records, before the KATs (lesson 14's class, one step earlier).
    The same run class then failed test_src_arch_page_r33 (SA1/SA8, pipeline_20261118T080213): that page is rebuilt
    only after the miners, so its KAT now runs after the build (fix_build_verify AFTER_BUILD_KATS). Rule: a page's KAT
    runs after the last step that rewrites the page or its inputs.

## 11. The research dossier (summary; the full text and every URL: `gametheory/research/`)

55 sources (17 doc, 28 paper, 10 steer), 48 cited in the dossier. Key doc claims checked in code: 10 miniblocks per
block (code: exactly 10, 1 final; RW19-RW21), block time (docs disagree, 16 s vs 18 s; code `BLOCK_TIME = 18`,
config/config.go:34; live mean 17.9 s over 60 blocks, 18.54 s over 2,000), "no orphan blocks" (code: side blocks get 0
reward, blockchain.go:985; live alt rate 2.05 %, 32 of 1,560, with 286 of 288 normal miniblocks reused by the winner),
the operator's 1.6 % (code: the integrator gets one share of ten + the leftover; RW16). Design implications used:
commit-reveal with a height deadline and a forfeit (M3), no payouts keyed to the including block (D-GT-10), Schelling
votes with slashing and P+ε acknowledged (M1), Ponzi shapes as NO-GO (N1, N5), no QF without sybil resistance (N6).

8. **`pgrep -f` waiters match themselves.** A `while pgrep -f "xargs -P 3"` loop runs forever: its own command line
   contains the pattern. Wait on a marker file or a pid instead (four such waiters were stopped on 2026-11-15).
9. **A relaunch uses the binaries on disk.** The earn run's stallwatch relaunch (02:56 → 03:2x) passed `--progress` to a
   gt-wallet built before the flag existed and died with a usage error: `gtlib.stale_bins` / `ensure_bins` now refuse
   (or `--rebuild`) a gt-* binary older than its Go sources (KAT GT10).
10. **Liveness of a proof-of-work grind is its attempt counter.** m2's registration grind outlived the 1,800 s stall
   limit because only events.jsonl was a work file; `gt-wallet register --progress pow_<wallet>.json` writes the
   attempt count every 10 s and the recipes watch it (stall limit 3,600 s).
11. **A watch must end only on success.** The earn wrapper touched DONE after any exit; the recipe is now
   `... && touch earn.DONE`, so a crash is relaunched (KAT GT10).

12. **A killed driver must take its children with it, and a duplicate send is a success.** When stallwatch relaunched
   the earn run at 03:27 (STALLED), the old m2 `gt-wallet register` child kept grinding and SENT m2's registration;
   the relaunch ground again (33.1M tries, about 22 min) and the node refused it with -32098 'address already
   registered' (03:51). Now gt_earn runs the register child in its own process group and kills it on SIGTERM, reads
   'already registered' as success, and mirrors the PoW counter into events.jsonl (pow_tick every 30 s, so the default
   work file shows the grind); gt-wallet re-checks the chain right before sending (KAT GT11).

13. **A hand-run command must not bypass the guards.** gt-wallet itself now checks the private ban list (fail closed
   on mainnet when the list is missing) for create, address, register and serve (every transfer and SC call goes
   through serve), and checks the chain BEFORE grinding a registration (the user approved a one-off m1 register that
   would have burnt ~7 min of 8-thread PoW against the live miner for an address registered since topo 7,905,776);
   Go tests TestR32GTWalletBanGuard, TestR32GTWalletIsRegistered; gt-sim/bin/gt-wallet rebuilt by atomic rename at
   04:08 (not older than its source, `gtlib.stale_bins` [] ).

## 11a. Fact check: does a smart contract need two wallets? (D-GT-6)

- **Deploying needs one wallet.** An install is one transaction: `blockchain/transaction_execute.go:321` (case
  `rpc.SC_INSTALL`) parses the code and runs `Initialize` (`:352`, or `InitializePrivate` `:342-354`) under that one
  transaction; the contract's owner is whatever `SIGNER()` returns, which is the sender only at ring size 2
  (`Extract_signer`, `:441-447`).
- **Ring members are not a second wallet.** The other ring member of a ring-size-2 transaction is a random REGISTERED
  account of the chain, fetched by `DERO.GetRandomAddress` (`walletapi/daemon_communication.go:589-595`); the sender
  needs no wallet of its own for it.
- **A game between players needs as many wallets as players.** Each player signs its own calls (SIGNER()); M3 and M2
  work with 2; a disputed M1 claim needs 3 (claimer, challenger and a juror who is neither, `gt_attest.bas` CommitVote
  line 100; with no juror the claim is upheld by default, line 220-300 of Finalize).
- So "an SC needs two wallets" is not a code rule; two is the minimum for a game between two parties.

## 12. Update log — after implementation

### Round 32 — after implementation (2026-11-15)
- Code: `gametheory/contracts/` (3 contracts), `gametheory/mechanisms.json` (3 GO, 6 NO-GO), `dvm/r32_gametheory_test.go`
  (9 tests PASS), `cmd/simulator` `--getwork-bind` (+ test), `cmd/gt-wallet` (+ 2 tests), `harness/gametheory/`
  (banguard, econsim, gt_pipeline, gt_gate, reward_anchors, reward_intel), `playbooks/` (gtlib, gt_playbook,
  params_r32.json), `harness/kat/test_gt_mechanisms_r32.py` (7/7, mutations 14/14), `harness/kat/test_gt_reward_r32.py`
  (7/7, 17/17), `blockchain/r32_reward_split_test.go` (9 PASS), gate G35, S7 step `gt_pipeline.py`.
- Pipeline (no sim): `gtp-20261115T013426` PASS 6/6 stages, econsim 14/14, 9 DVM tests, max compute gas 1,774,800.
- D-GT-4 path: `playbooks/gt_earn.py`, `harness/gametheory/time_to_coins.py`, `gt-wallet register --pow-threads`; the pipeline's playbook stage checks the earn plan stops at the user's flag (exit 5).
- Consensus guard: PASS (the reward agent's run; no non-test consensus file changed).

### Round 33 — after implementation (2026-11-17)

| field | value |
|---|---|
| Scope | the user's R33 items 10–15 of §2 + every open R32/R32a row (§8.2 tracker, D-GT-25), child rft only (D-GT-18/24) |
| Research | `gametheory/research/r33_*.md` (web 46 sources + 10 FAILED; code capabilities; outreach; index; block proofs; pool math; forensics and security) |
| Contracts | `gt_pool.bas` (M5 verified mining pool: Anchor, ProveBlock, ProveParent, 8-byte tags, stake boost ≤ 2×, burn, census) and `gt_beacon.bas` (M6) new; gt_attest/service/prize/audit fixed (independent audit GT-A01..A17, invariant verification 5 findings, 37/37 invariants) |
| Node-side code | `cmd/dero-miner --game-tag=<hex16>` (miniblock bytes 32..39; CPU only); no consensus-package change |
| Tests | DVM: r33_blockproof, r33_pool (6), r33_beacon, r33_audit (17 regression + 4 conservation), r33_verify_* (37 invariants), r33_wb (W4/W6/W7), r33_tagvec; KATs test_gt_r33 (6), test_pool_cycle_r33 (4, 6/6 mutations), test_gt_harness_r33 (5, 18/18), test_version_bump_r33 (2, 8/8); econsim 26/26 |
| Playbooks / harness | gt_pool_cycle.py (install with code check, register with tag check, follow-mode proving, continuous epochs, resume, rollover, beacon publish), pool_audit.py, pool_census.py, gas_census.py, audit task 3, time_to_coins --from-earn-log, content-hash staleness, the fee-inclusive earn counter |
| Docs | `gametheory/contracts/README.md` tutorial (KAT R33-5), `gametheory/ANNOUNCE_DRAFT.md`, the game-theory page's R33 section; lessons 34–38; D-GT-18..28 |

## 13. Update log — after measurement

### Round 32 — after measurement (2026-11-15)
- **Sizing decision (D-GT-7, 2026-11-15T02:09:51-08:00):** N 2 wallets, targets {'m1': '4.00000', 'm2': '4.00000'} DERO; reasons in `harness/runtime/gt_sizing_last.json` (R3: no measured mainnet mining yet, so the default holds).
- **Mainnet cycle (G36): IN PROGRESS 0/5.** D-GT-6 target: m1 and m2 each >= 4.00000 DERO (balances: m1 0.00000, m2 not created — no registration yet); estimate 8 DERO in 8.97 h at 21.477 DERO/day (difficulty 2,331,515). Blocker: the session's permission system refused the m1 registration send twice; real mainnet balances: none yet (no wallet registered). User action U-MAINNET-EARN.
- *Pre-flight only (sim chain; never a result):* **Sim run 3** (`<home>/derohe-persist/gt-sim/runs/r32-sim-3/report.json`, contracts v1, prize with RANDOM): 8/8 checks.
  M1: m1 claimed 395 = true 395 and m2 433 = 433 → status 2, MAT minted 39,500 and 43,300 (each later staked 200);
  m3 claimed 757 against a true 504 → challenged by the verifier, rejected (status 3), no MAT, bond lost. M2: 6
  documents notarized, treasury > 0. M3: round 1 with 4 entrants (m1, m2 boosted to weight 400,000 each), u2 withheld
  (forfeit 10,000), prize 60,000 paid to entry 1, all 4 withdrew.
- **Sim pipeline runs (harness-tracked, stallwatch + DONE marker):** `gtp-sim-v2` FAIL 9/10 (the inflating m3's
  game net read only −321,337 against a 542,000 bond: the mined scan ran while the miners still mined, and jurors never
  withdrew their stakes) → fix: miners stopped before the report, jurors Unstake; `gtp-sim-v3` FAIL 9/10 (−665,427 against
  688,000: the mined column omits each miniblock's block-fee share, which the header does not carry) → the check became
  ≤ −0.9 × bond with an exact conservation check on the SC side; **`gtp-sim-v4` PASS** (`harness/loop/runs/
  gt_pipeline_20261115T015307.jsonl`; report `harness/runtime/gt_sim_report.json`): 6/6 stages, 11/11 on-chain checks.
  M1: m1 claimed 149 = true 149, m2 183 = 183 → MAT 14,900 / 18,300 minted (200 each staked into M2/M3); m3 claimed 286
  against a true 190 → challenged, jurors 3 × "no", rejected; m3 game net −555,938 (bond 572,000); the challenger
  +285,046 (= bond/2 − 954 in fees); coherent jurors +121,195 / +80,338 / +80,338; the attest SC keeps 1 atomic of dust.
  M2: 6 documents, epoch 2, m1/m2 boosted. M3 (v2, no RANDOM): 4 entrants, u2 withheld (forfeit 10,000), prize 60,000
  to entry 2, every principal returned. Wall 449.1 s.
- **GT-B9 pre-flight (`playbooks/gt_cycle.py --network sim`, run cyc-sim2; record `harness/runtime/gt_cycle_sim.json`;
  pre-flight only, never a result):** the 2-wallet cycle ran end to end in 361.2 s: 3 installs + 8 setup calls from m1,
  M1 claim k 776 minted 77,600 MAT (status 2, unchallenged), M3 round 1 drawn with both revealed (winner index 1, prize
  10,000), M2 2 documents and the epoch-4 rebate claims. The first attempt (cyc-sim1, `--fast`: 20-block windows at the
  sim's ~6 blocks/s) drew an empty round (winner −1), so `game_settled` now needs a winner; on mainnet the fee per call is
  the wallet balance delta, valid only with no pipeline miner crediting the wallets (the cycle waits, exit 7).
- **Mainnet earn (D-GT-4):** NOT run — the session's permission system refused it; estimate only
  (`harness/runtime/gt_time_to_coins.json`): 1 DERO in 1.11 h at 8 threads / 80 %; user action U-MAINNET-EARN.
- **Mainnet (read-only):** reward 30,750 atomic in 60/60 blocks; difficulty formula 60/60; supply 16,867,343 = formula;
  6.0 distinct keys per block; the default Dev_Address integrated 1 of 60 blocks (`harness/runtime/gt_reward_live.json`).

### Round 33 — mainnet pool cycle 1 (2026-11-17, record `harness/runtime/gt_pool_mainnet_20261117T191844.json`)

| field | value |
|---|---|
| Run | `gt_pool_cycle.py --network mainnet --mainnet-confirm --wallets m1..m5 --anchors 4 --depth 8`, run r33-pool-mainnet-1, epoch 19,790, heights 7,916,059 → 7,916,522, 8,538 s; gt_pool + gt_beacon installed on mainnet (new SCIDs, audited code), 5 wallets registered with their 8-byte tags verified in the contract |
| Chain audit | PASS: 36 proven blocks (7,916,102–7,916,324) re-read and parsed; credits m1 4 (= the tagged non-final miniblocks), TW 400, claim m1 22,800 = min(P0 × W / TW, 30 % × P0) with P0 76,000; balance 74,200 = burned 21,000 + pools + stakes |
| Economics | fees 64,756 atomic for the epoch; 36 proofs at 1,672–1,773 atomic each (storage estimate 1,472 + 200); member work ≈ 1.2 % of the proven blocks' normal miniblocks, so anchored fixed-depth proving cost ~9 proofs per credit → continuous mode uses --follow (GT-B34) |
| Cap | with one credited member the 30 % per-identity cap paid 22,800 of 76,000; the rest is not lost: Rollover moves it into a later epoch (now automatic in the loop); the pot drains at most 30 % per epoch while one member is credited |
| Deflation | 21,000 atomic burned on mainnet (20 % of the 100,000 sponsor deposit + entry fees), locked with no exit |

### Round 33 — mainnet continuous mode, epoch 19,791 (follow mode; record `harness/runtime/gt_pool_mainnet_20261117T212105.json`)

| field | value |
|---|---|
| Run | the same audited pool contract, `--follow --epochs 3 --max-proofs 15 --sponsor 20000`; 15 proofs (7,916,535–7,916,624) |
| Chain audit | PASS: credits m1 3 = the tagged miniblocks; claim m1 3,000 = 30 % × P0 10,000 (cap); conservation; balance 85,200, burned 25,000 cumulative |
| Follow vs fixed depth | 0.20 credits per proof (3 / 15) against 0.11 in cycle 1 (4 / 36); epoch fees 28,138 vs 64,756 atomic (GT-B34 measured) |
| Rotation | every credit was m1's because the earn job mined m1 for four slices from 10:46 (m1 was the poorest after sponsoring); the rotation resumed at 12:07 (m5, m3, m4, m2), so the next measured epoch covers more members |

### Round 33 — mainnet continuous mode, epoch 19,793 (record `gt_pool_mainnet_20261118T012514.json`; re-audit `gt_pool_reaudit_mainnet_e19793.json`)

| field | value |
|---|---|
| Driver audit | FAIL (contract w 4 vs parsed 2): a harness defect, not the contract — the watchdog relaunched the loop mid-epoch (lesson 38); the second process audited only its own 15 proofs |
| Independent re-audit | PASS (`pool_audit.py`, the contract's 21 proven heights 7,917,233–7,917,361): credits m1 4 (= the tagged miniblocks at 7,917,233 / 286 / 310 / 332), TW 400, claim 7,200 = 30 % × P0 24,000, conservation; epochs 19,790 and 19,791 re-audited PASS too |
| Spend | the relaunched process funded the epoch twice (2 × 20,000; P0 24,000 = 32,000 − 4 prover fees × 2,000); no loss: the second deposit stays in the pool (20 % burned) |
| Next | relaunched 17:30 on the fixed code: --follow --epochs 2 with m2 locking 1 DERO (objective 4 on mainnet), watchdog on events.jsonl |

### Round 33 — mainnet continuous mode, stake epoch 19,796 (record `gt_pool_mainnet_20261118T074545.json`, re-audit PASS)

| field | value |
|---|---|
| Chain audit | PASS (driver and independent re-audit): 15 proven blocks (7,918,422–7,918,456), credits m1 1, m4 1, claims 19,560 each = 30 % × P0 65,200 (P0 includes epoch 19,790's leftover, rolled over automatically) |
| Stake | m2 locked 1 DERO at 7,917,727 (matured for 19,796) but mined no proven miniblock in the epoch: the boost was not exercised → D-GT-29 keeps epoch 19,798 with the miner steered to m2 |
| Census | epochs 19,790–19,796: 783 verified miniblocks, 21 KeyHashes, the largest 17.0 %: no alarm (beacon pool_census) |
| Burn | 37,000 atomic cumulative |

### Round 33 — mainnet stake epoch 19,798 (record `gt_pool_mainnet_20261118T115043.json`, re-audit `gt_pool_reaudit_mainnet_e19798.json` PASS)

| field | value |
|---|---|
| Chain audit | PASS (driver and independent re-audit): 15 proven blocks (7,919,229–7,919,256), follow mode, fees 28,728 atomic, wall 37,241 s |
| Stake (objective 4) | MEASURED on mainnet: m2, 1 DERO locked at 7,917,727 and matured, 3 credits → weight 600 = 200 per credit (the 2× ceiling); TW 600; claim 5,100 = the 30 % per-identity cap of P0 17,000 |
| Census | epochs 19,790–19,798: 918 verified miniblocks, 23 KeyHashes, the largest 18.7 %: no alarm |
| Burn | 41,000 atomic cumulative; contract balance 195,780 = burned + pools + stakes (conservation) |

### Round 33 — mainnet step 3c, GT-B15 (record `gt_cycle_mainnet_20261118T050346.json`, chain audit `gt_cycle_audit_mainnet_20261118T050346.json`)

| field | value |
|---|---|
| Deploy | gt_audit v2 (the fixed contract) installed by m1, fee 17,790 atomic, 11,755 code bytes; the R32 SCIDs stay retired (D-GT-20) |
| Round | task 3 (SC balance turnstile), bounty 6,000, auditor bond 600: 4 auditors (m2..m5) entered and revealed, every answer matched the sponsor's; settled nw 4, share 1,500, no dispute, no forfeit, every bond refunded |
| Fees | 25,883 atomic, 18 calls, wall 1,437.6 s (heights 7,919,884–7,919,961) |
| Chain audit | net game payoff m1 −26,107, m2..m5 +56 each (= share 1,500 − 1,444 fees), sum −25,883 = −fees exactly; m1's 12,300 mined in the window read from the chain |
| Defect found | the record missed m1's Settle fee (600; the wallet had not indexed the tx) → lesson 39, D-GT-31, KAT R33-8 |
| Limit | the turnstile summed only the run's own contracts (the new audit SCID, 0) → GT-B37 (an explicit SCID list) |

### Live observations log (newest last)
- 2026-11-15 01:16 sim smoke: the first gt wallet mined 222 blocks alone after a bootstrap miner registered it.
- 2026-11-15 02:49 MAINNET EARN STARTED by the main session (the user's D-GT-4 authorisation): `gt_earn.py --wallet m1,m2 --mainnet-confirm --threads 8 --cpu-max 80 --target-dero 4.0 --max-hours 24` under stallwatch; first observation: m1's registration PoW grinding. Balances will be logged here from `runs/r32-mainnet-earn/events.jsonl` (wallet balance + chain-credited).
- 2026-11-15 02:56:46 MAINNET: m1's registration sent (txid PoW 10,159,326 tries in 442.4 s on 8 threads, ≈ 23,000 tries/s; txid starts 000000); m2's grind follows. G36 step 1 is measured when the earn log shows both registered (`harness/gametheory/cycle_from_earn.py`).
- 2026-11-15 ~03:2x MAINNET (main session): m2's registration grind exceeded the 1,800 s stall limit; stallwatch relaunched the run, whose relaunch passed `--progress` to the old gt-wallet binary and exited with a usage error. Fix by the main session at 03:28: gt-wallet rebuilt from HEAD (atomic rename), stallwatch relaunched with `--work events.jsonl --work pow_m2.json --stall-s 3600` (the previous DONE kept as earn.DONE.prev-*). Built into the harness: lessons 9–11, `gtlib.ensure_bins`, the `&& touch` recipe, KAT GT10.
- 2026-11-15 03:51 MAINNET (main session): the relaunched run's m2 grind (33.1M tries, about 22 min) was refused with -32098 'address already registered': the 03:27-killed run's register child had survived and sent it. Read-only check: m1 and m2 BOTH REGISTERED at topo 7,905,776 (G36 step 1 measurable). PoW: m1 10.16M tries in 442 s; m2 first grind > 1,800 s (stall-killed), second 33.1M tries in about 22 min. The main session relaunched earn.cmd: both resolve as registered, so it goes straight to mining. Built in: lesson 12, KAT GT11.
- 2026-11-15 ~04:08 hardening (main session request): gt-wallet checks registration before grinding and the ban list itself (lesson 13); the one-off approved m1 register was NOT run (m1 registered since topo 7,905,776).
- 2026-11-15 04:27 MAINNET, G36 step 2 MEASURED (`harness/runtime/gt_earn_mainnet.json`): m1 wallet balance 0.15375 DERO = chain-credited 0.15375 DERO (5 normal miniblocks × 3,075 atomic; balance and chain agree); m2 chain-credited 0.09225 DERO (3 miniblocks), wallet read pending at its slice end. Measured rate 10.70 DERO/day over the first ~0.5 h vs the 21.9 DERO/day estimate: the pipeline miner measures 22.4 kH/s on 6.46 cores (3,470 H/cpu-s; `mainnet-miner-m2.out` TOTAL lines) against the assumed 34.2 kH/s (5,344 H/cpu-s, the R30 quiet-box rate; this box runs the R32 pipelines in parallel), which alone predicts ~14.4 DERO/day; the remaining gap is within the Poisson noise of 8 miniblocks (±35 %). GT-B11: re-estimate with the measured H/s. The trigger (stallwatch, started 04:09) waits for settled >= 1.00000 DERO on both.
- 2026-11-15 ~04:10 D-GT-8: trigger + viability gate built (plan at estimated fees: 5 M3 rounds, principal 0.30000, sponsor 0.04000 DERO/round); the trigger waits for settled >= 1.00000 DERO on BOTH wallets; mining continues.
- 2026-11-15 ~04:00 MAINNET: G36 step 1 MEASURED (`harness/runtime/gt_earn_mainnet.json`: m1 and m2 registered). First real coins: the chain scan credits m1 0.06150 DERO (2 normal miniblocks × 3,075 atomic); m2 0.00000; wallet-balance reads pending (the next earn_balances tick).
- 2026-11-15 ~06:45 main session: pipeline run 4 FAIL (game-theory page STALE) and run 5 FAIL (G3 corpus STALE; G36 IN PROGRESS, correctly). Run 5 otherwise held: KATs 35/35, mutations 34/34, gates 31/36 (+3 PAUSED, miner). Cause: the live trigger rewrote two tracked runtime records every minute (lesson 14). Fixed in 05b285b5 (re-render before --check) plus this commit: cycle_from_earn `--write`, KAT GT13 (suite 13/13, mutations 32/32, coupled 2 as before). STEP_BUDGETS landed rows: test_gt_mechanisms_r32 340 s (222.7 s measured), gen_gametheory 30 s. Live at 06:3x: m1 0.64575 / m2 0.58425 DERO, wallet balance = chain-credited for both.
- 2026-11-15 ~07:40 main session: pipeline run 6 FAIL at SB3 (test_stepbudget_r29): the 06:4x STEP_BUDGETS rows were hand-edited, not derived. Re-derived with `stepbudget.py --derive` (the three _doc records, landed list + test_gt_mechanisms_r32.py 222.7 s, gen_gametheory.py 0.1 s): rows 340 / 30, project_wall_s 7890 -> 8110; SB KATs 6/6, mutations 8/8. Lesson: budget rows change only through stepbudget --derive. Live 07:28: settled m1 0.83025, m2 0.83025 DERO; trigger not yet ready (threshold 1.00000).

- 2026-11-15 ~08:40 main session: pipeline run 7 FAIL only at G36 (IN PROGRESS, correctly): KATs 35/35, mutations 34/34, gates 32/36 (+3 PAUSED, miner), wall 3,486 s of 8,110 s. Live at 08:34:15: wallet balance m1 1.23000 / m2 1.01475 DERO, both past the 1-DERO game threshold (D-GT-8); the trigger awaits the 8-block settlement. Lesson 15 (slice pick) landed.
- 2026-11-15 ~09:20 main session: the first MAINNET cycle (08:38–08:57) deployed all three contracts (install fees 12,571 / 7,996 / 10,579 atomic) and made 9 setup calls (8 landed). The attest Freeze was lost from the main chain, the Claim reverted, and the cycle ended on Finalize(-1) (lesson 16). The trigger relaunched it at 08:58 (start m1 1.01810 / m2 1.01475 DERO); the re-run is in progress on the old cycle code. Fixes and KAT GT15 landed; lesson 17 covers the trigger retry bound.
- 2026-11-15 10:26:53 MAINNET: the first full game-theory cycle SETTLED (record harness/runtime/gt_cycle_mainnet_20261115T102653.json; wall 5,307 s; 51 SC calls, m1 35 and m2 16; fees 14,321 atomic, 281 per call on average; installs 31,146). M1 attest: claim k=10 with bond 6,150, finalized by m2 (status 2), m1 holds 1,000 MAT. M3 prize: 5 rounds, 4,000 sponsor each; rounds 1–2 genuine with 2 entrants, m2 won both; rounds 3–5 solo (lesson 18). Chain audit: net game payoff m1 -17,564, m2 +3,267, sum -14,297 against -14,321 in fees. **G36 PASS** (5/5 plus the audit). The trigger finished with rc 0 (trigger.DONE); the earn job continues toward 4.0 DERO per wallet.
- 2026-11-15 ~11:40 main session: pipeline run 8 FAIL at TK1 (cycle_audit --help in the sandbox; lesson 20). Fixed; run 9 started.
- 2026-11-15 ~13:55 main session: pipeline run 9 PASS (pipeline_20261115T114035) and run 10 PASS (pipeline_20261115T124651: 35/35, 34/34, gates 33/36 + 3 PAUSED, G36 PASS, wall 3,482.2 s) after the page gained the chain-audit card. PDF re-printed from the final HTML (pdfscan 0, neutral info). Public sync: base a1be4255, target 21d558ee; check 0 hits; ban guard 0 / 7,428 files; scrubbed page, PDF and child rft under harness/. Public commit b302bf1 (public author, no trailers), 1 ahead of origin. D-R32-GITHUB is DUE and push-notified; the push is the user's action.
- 2026-11-15 ~16:30 main session (R32a, clone branch): research done (`gametheory/research/r32a_*`); gt_audit M4 (DVM 6/6, R32 9/9), audit tasks (live read-only: 30 blocks, 0 emission mismatches, total 922,500), ladder, N-wallet sizing, econsim 18/18; four sim pre-flights found and fixed lessons 21–24; KATs 24/24, mutations 57/57, coupled 2. m3 registered on mainnet 14:31 (PoW 1.33 M tries, 53 s). The full pipeline is in its Go-mutation stage.
- 2026-11-15 22:28 main session: R32 marked measured (full pipeline_20261115T141331: go mutations 1761/1761, race 27/0, shadow 119/119 with 0 treehash mismatches); R32a opened and merged; project-only pipeline_20261115T212738 PASS. Public sync base 21d558ee -> target 348826b6, check 0 hits, ban guard 0 / 7,504 files, README opens with Round 32, four docs current through r32; public commit 5e5172f, push DUE (D-R32-GITHUB-README, push-notified). The sync check refused a research citation whose archive URL embedded an e-mail address; it was rewritten without the message id.
- 2026-11-15 22:49:57 MAINNET ladder step 3 started (`playbooks/gt_ladder.py` under stallwatch): settled m1 2.349 / m2 2.400 / m3 2.460 DERO against needs 2.149 / 0.731 / 0.731 (the deploying step pays the full setup); plan: 5 prize rounds, principal 40,000, sponsor 1,000, rbond 1,000; 2 audit rounds with bounty 12,000 and auditor bond 1,200.
- 2026-11-15 23:08:00 **User action: the user pushed** b302bf1..5e5172f (main): the Round 32 README and docs and the R32a code (D-R32-GITHUB-README done). 23:09 earn extended to m1..m5; 23:11:55 rebuilt gt-dero-miner, m4 registration PoW started (lesson 26).
- 2026-11-16 01:16:09 MAINNET ladder step 3 SETTLED (3 wallets): claims m1 k=10 / m2 k=8 / m3 k=10 finalized (MAT 1,000 / 800 / 1,000); prize rounds 1–5 genuine (3 entrants and 3 reveals each; winners m1, m1, m3, m1, m2); audit round 1 headers and round 2 emission both settled (2/2 winners, share 6,000, no dispute; emission 30 blocks, 0 mismatches, total 922,500); 94 calls, fees 85,608 atomic, wall 8,771 s; one tx lost (round 4 Fund) and resent at 7,909,749. Chain audit per lesson 27: m1 −88,687, m2 +2,054, m3 +1,054, sum check passes.
- 2026-11-16 05:03:15 MAINNET ladder step 4 SETTLED (4 wallets; record gt_cycle_mainnet_*T0503*.json, heights 7,910,277–7,910,662): claims m1 k=10 / m3 k=6 / m4 k=10 finalized (m2 mined nothing in its span); prize rounds 7–11 genuine (4 entrants and 4 reveals each; winners m1, m4, m4, m4, m2); audit rounds 1 headers and 2 emission settled (3/3 winners, share 6,000, no dispute; emission 0 mismatches over 30 blocks); 101 calls, fees 46,144 atomic, wall 7,128 s, no lost tx. Chain audit (mined_source chain): net m1 −54,144 / m2 +2,654 / m3 +1,292 / m4 +4,076, sum −46,122 against −46,144 in fees (check passes).
- 2026-11-16 09:04:16 MAINNET ladder step 5 SETTLED (5 wallets; record gt_cycle_mainnet_20261116T090416.json, heights 7,911,060–7,911,439; derod restarted by the user 07:41–07:45 mid-round with no loss): claims m1 / m4 / m5 k=10 finalized; prize rounds 13–17 genuine (5 entrants and 5 reveals each; winners m4, m5, m4, m4, m4; prize 4,000); audit rounds 1 headers and 2 emission settled (4/4 winners, share 4,750, no dispute; emission 0 mismatches over 30 blocks); 122 calls, fees 56,252 atomic. Chain audit (fee-inclusive split, lesson 32): net m1 −72,144 / m2 −846 / m3 −608 / m4 +14,792 / m5 +2,554, sum = −fees exactly. **LADDER DONE: steps 3, 4, 5 (3 → 5 wallets), 15 of 15 prize rounds genuine, 6 of 6 audit rounds settled, every audit sum exact.**