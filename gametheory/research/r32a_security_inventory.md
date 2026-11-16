# Security-concern inventory (prior rounds R7–R32), evidence-anchored

Scope: read-only mining of `artifacts/dero-rft.md` (parent rft, §7 backlog lines 2437–2782), `artifacts/dero-game-theory-rft.md` (child rft), `gametheory/mechanisms.json`, a few source lines re-checked at HEAD of the repo, and the project memory notes (cited as `mem:<name>`). Repo-relative paths only. No wallet addresses, IPs or user paths. No exploit content: the range-proof item is described only as "defect exists / what was audited / what monitoring exists".

Anchor conventions: `rft:N` = `artifacts/dero-rft.md` line N (the §7 row); `gt-rft:N` = `artifacts/dero-game-theory-rft.md` line N; `mem:x` = memory note x (point-in-time; its file:line citations may have drifted — where re-checked at HEAD this is marked "HEAD").

Status vocabulary (as used by the rft): FIXED / CLOSED (node-local change shipped) · OPEN · REPORT-ONLY (consensus-visible or upstream; documented, never patched locally) · PINNED (behaviour frozen by a KAT so a change is detected) · MITIGATED · REFUTED.

Game-theory lever rubric (strict). The premise: an on-chain DVM incentive game run by miners. Contracts cannot change consensus, cannot see the miner or integrator (no builtin; `Blockchain_Input` has SCID, BLID, TXID, Signer, BL_HEIGHT, BL_TOPOHEIGHT, BL_TIMESTAMP — gt-rft:90 D-GT-3), and SIGNER is known only at ring size 2. They can pay DERO they hold, mint their own token, read height/time/BLID, and verify nothing about off-chain facts except through bonded claims plus a challenge (M1 pattern, gt-rft §4 item 2).
- YES = a contract can plausibly change the incentive itself (one-line how).
- PARTIAL = the contract can only fund or attest monitoring or disclosure (bounty, bonded attestation, Schelling jury over public data); the defect itself stays.
- NO = the fix is consensus, node-local code, crypto or operator configuration, which no contract touches, or the contract would be the attack surface.

---

## 1. Coin supply / emission integrity

| id | concern (one line) | status | anchor | game-theory lever? |
|---|---|---|---|---|
| B8 / C1 (`mem:dero-rangeproof-disclosure`) | Foundation disclosed (2026-10-20) a range-proof soundness defect. Our 199-agent audit CONFIRMED that a soundness defect exists (C1). The press's stated mechanism was REFUTED (C2) but its consequence CONFIRMED. No exploit was built. | REPORT-ONLY (needs a coordinated upstream fork; SND-5: no node-local mitigation; §9 NO-GO on a local verifier patch and on exploit content) | rft:2444; `cryptography/crypto/proof_verify.go` (C1 site per mem); rft §0.5 lines 263–313 | NO — the defect is in the consensus verifier. A contract cannot see or check proofs inside encrypted amounts. |
| B8 monitoring (disclosure track) | Re-tested every round: `harness/intel/disclosure_track.py` (gate G24) re-reads every anchor, `--live` recomputes CalcSupply and cross-checks GetInfo / GetEmissionAudit / GetMonetaryIntegrity (S1–S4), `--census N` counts proof scalars ≥ bn256.Order (R24: 100,000 blocks, 15,866 scalars, 0 ≥ Order), and a lint refuses exploit-like text | STANDING (every round) | rft:263–313; `harness/loop/disclosure_track.json`; `harness/kat/test_disclosure_track_r24.py` | PARTIAL — a bonded-attestation or bounty contract could pay for independent re-runs of the published census or audit (M1-style claim plus challenge over public data). It detects nothing the node cannot already see. |
| B179 / B190 | Binding census: 128 scalar×base sites (66 prover / 62 verifier); the only free-scalar row is the C1 site. Bulletproofs assumption table: 18 hypotheses mapped, C1 = the "bound into the transcript" hypothesis failing. No attack content. | FIXED as evidence (test files + checklists only, r28d) | rft:2624, rft:2635; `cryptography/crypto/r28d_binding_census_test.go`; `harness/model/evidence/r28d_assumption_table.json` | NO — audit artefact. The cure is a fork. |
| B9 | The 23,886,517.3 DERO "created" figure and any value inside encrypted amounts are not node-checkable | CLOSED node-side (R28): NOT-DECIDABLE-FROM-PUBLIC-DATA; graded SPECULATION | rft:2445; `forensics/r28/derived/fq.json` | NO — encrypted balances. A contract cannot read them. A jury over undecidable data would only reward guessing. |
| X-SUPPLY (`mem:dero-rangeproof-disclosure`, `mem:dero-hf3-exemption-replay`) | `total_supply` is formula-computed (`blockchain/supply.go` CalcSupply, HEAD :5), not summed from balances. It would print the same number on an inflated chain. | REPORT-ONLY (operator caveat) | `blockchain/supply.go:5` (HEAD) | NO — a display semantics fact. |
| Emission auditor (`mem:dero-emission-audit`) | Per-block balance-tree diff must equal the published (C,D) deltas + formula coinbase + SC payouts. It is blind to value created inside encrypted C (range-proof class). That value surfaces only through plaintext flows (fees, SC deposits/payouts, BURN), hence a "notable flow" proxy. | SHIPPED monitoring (R23; 13,100+ blocks 0 alerts offline per mem); 24 h payee read CONFIRMED (B36) | rft:2472 (B36); `glue/emission/`; RPC DERO.GetEmissionAudit | PARTIAL — a contract could post a bounty for a reproducible auditor ALERT, settled by bonded claim plus jury over public headers. It cannot see inside C either. |
| X-EXEMPT / HF3 table (`mem:dero-hf3-exemption-replay`) | 75-txid HF3 grandfather table skips Proof.Verify, looked up by TXID with no explicit height gate. The proof skip is still effectively pre-HF3-bound via the cache key. Replays are refused by the already-mined guard and the 11-block validity window. | PINNED (test `blockchain/r23_hf3_table_test.go`; mutation CAUGHT); DERO.GetMonetaryIntegrity publishes the table digest | `blockchain/hardfork_fixes.go:27` (HEAD); mem cites transaction_verify.go:232/:434, blockchain.go:760-790 | NO — consensus table. |
| X-PARITY (`mem:dero-hf3-exemption-replay`) | Table entries never set `Parity`. A disagreeing parity advances the wrong ring slot's nonce. The replay is still refused by other guards. | REPORT-ONLY / pinned by test | `mem:dero-hf3-exemption-replay` | NO |
| B33 | BURN_TX never verifies (Value not serialised; 0 refused); SC partial-panic payouts audit as `sc_unexplained` | REPORT-ONLY (consensus, upstream; KAT TestR28BurnTxNeverVerifiesKAT) | rft:2469 | NO |
| B22 | Consensus allows ≥ 1 final miniblock (F > 1 would under-pay) | REFUTED above height 399,000 (20,000/20,000 live blocks have one final) | rft:2458; `blockchain/miniblocks_consensus.go:75` (HEAD `final_count < 1`) | NO |
| B11 / B31 | `blockchain/storefs.go` non-atomic block writes (integrity on crash); topo F_FULLFSYNC cost | REPORT-ONLY (consensus package) | rft:2447, rft:2467 | NO — local storage. |
| B83 | Block `Proof` field ("balance root hash") is serialized and unchecked | DONE (measured: non-zero in 0 of 83,076 blocks) | rft:2528; `block/block.go:42` | NO |
| B111 | Balance-tree enumeration vs registrations: the one key without a registration is the genesis premine key | ANSWERED (A) + residual CONFIRMED (R31) | rft:2556 | NO |
| B182 | Registration PoW is weaker at block validation (txid bytes 0 AND 1 non-zero rejects) than in the pool (three zero bytes): ×130,816 less work if a miner includes it directly | REPORT-ONLY (consensus-visible; on-chain census 0 of 487 registrations below 3 zero bytes) | rft:2627; `blockchain/blockchain.go:712`, `:1250` (per row) | PARTIAL — a bounty or attestation contract could reward public reports of a block carrying a weak-PoW registration (detectable from public headers/txs). It cannot stop inclusion. |
| B184 / B186 (`mem:dero-hf4-fork-watch`) | Unreleased community-dev version-4 fork row at 8,000,000 would split the chain from this tree's table. The v4 registration check changes no outcome. | STANDING watch (B184) / REPORT-ONLY (B186) | rft:2629, rft:2631 | NO — fork coordination is off-chain. A contract cannot vote a fork in. |
| B141 | A consensus parameter (difficulty floor) was environment-settable → self-fork risk | FIXED (R29) | rft:2586; `blockchain/difficulty.go:197` | NO |
| B311 | Failed SC_INSTALL: burn destroyed (neither credited nor refunded), fee kept; check the auditor reconciles it | OPEN (auditor side; consensus behaviour REPORT-ONLY + pinned) | rft:2763; `blockchain/transaction_execute.go:361` (per row) | NO (consensus). An SC author's own defence is to keep Initialize infallible. |
| B313 | A tx body cut inside its proof decodes without error, and re-serialising panics | FIXED auditor side (R31, DecodeTx refuses a non-round-tripping body) | rft:2765 | NO |
| B309 / `mem:dero-security-r23b` | `Transaction.Deserialize` panics on an unknown tx type | REPORT-ONLY (consensus decoder) + guarded at the RPC header peek (glue/txprecheck) | rft:2761; `transaction/transaction.go:321` | NO |
| B297 / `mem:dero-crypto-audit-r22` C1–C2 | bn256 point decoder accepts x ≥ P (→ identity) and flag bytes 0x02–0xff (malleable). The mainnet tree scan found 0 alias / 0 identity keys (latent). | REPORT-ONLY + pinned (mutations CAUGHT); txcanon refuses such txs at mempool entry | rft:2749; `cryptography/bn256/changes.go:59` | NO |

## 2. Peer validation / P2P (eclipse, sybil, propagation, orphans, timestamps, connection limits)

| id | concern | status | anchor | game-theory lever? |
|---|---|---|---|---|
| D8 eclipse diversity | Eclipse risk bounded by ≤ 2 outbound per IPv4 /16 or IPv6 /32. The observatory flags share > 25 % or < 4 /16s. | SHIPPED (R18 rule; R24 detector) | `p2p/diversity.go:38` (HEAD); rft:504 | NO — connection policy is node-local. A contract cannot see who a node peers with. |
| B1 | Inbound was 0 since Round 2 (UDP forward missing), so few peers and higher eclipse/latency exposure | DONE (user forwarded UDP; 28 in / 13 out at R30 start) | rft:2437 | NO — operator config. |
| B330 | Outgoing peers fell 14 → 8 (R31) with inbound 24–27 | OPEN (measure first) | rft:2782 | NO |
| B196 | One node identity can hold 2 slots (dedupe by address only): a mild sybil-slot amplification | REPORT-ONLY (upstream behaviour) | rft:2641; `p2p/controller.go:390`, `:715` (per row) | NO — the peer table is not visible on chain. |
| B30 | Spoofed-source datagrams can drain the pre-TLS accept budget; the real fix is a return-routability cookie (wire change) | MITIGATED (returning-peer lane; cookie stays §9) | rft:2466 | NO |
| B48 | Proven-peer lane (4,096) fillable by one operator; fresh remote ws key burst | CLOSED (R28: per-netgroup quota; 4,096 handshakes from one /16 → 4,032 evictions) | rft:2493 | NO |
| `mem:dero-r22-security-dim` | INV flood amplification: 4096-txid INV cost ~177 ms (tx_known sweep) / ~77 ms (no per-peer rate) | FIXED (R22: next_sweep; bucket 64/s burst 1024) | `mem:dero-r22-security-dim`; B67 rft:2512 | NO |
| B47 / B99 | A peer advertising unservable blocks was re-synced every 4 s forever. Sync-hold strikes did not decay. | CLOSED (R28 unit + loopback scenarios) | rft:2492, rft:2544 | NO |
| B102 | Two invalid_pow offences never ban (a third does) | CLOSED by decision (policy kept, comment corrected) | rft:2547 | NO |
| B63–B67 | Offence scores, per-reason counters, served chain requests, ban reasons, per-conn INV clips were not observable | CLOSED (R25–R31; "registered, no event") | rft:2508–2512 | NO (observability only) |
| B55 / B103 | Miniblock refusals were invisible (spam unmeasured). `insert_failed` counted concurrent duplicates. | CLOSED (counters live; duplicate_race reason) | rft:2500, rft:2548 | NO |
| B57 | Rejected blocks could not be attributed to a sender | CLOSED (blockchain_block_rejected_total{reason}) | rft:2502 | NO |
| B269 | "Rejecting Block, timestamp is too much into future" from ONE peer (3 events; our clock fine). The rule limit is 50 ms. | OPEN (e) only — re-read the future-block metrics after restart | rft:2719; `blockchain/blockchain.go:532` (HEAD, `limit_ms 50`) | NO — consensus timestamp rule. Contracts read BLOCK_TIMESTAMP but cannot enforce peers' clocks. |
| D6 / B72 | Clock-skew detector graded a path artefact (same node −181 ms on one address, −0.6 ms on another) | Harness caveat (fixed in harness) | rft:2517; `mem:dero-consensus-observatory` | NO |
| v2-remnant filter (`mem:dero-network-changes` R5) | Post-HF3 v2-chain peers dropped on sight (Top_Version < 3) | FIXED (3195f3b) | `p2p/common.go` | NO |
| B177 | Chain-sync block list sent a zero block id on a failed topo read | FIXED (r28d; path exercised live) | rft:2622; `p2p/rpc_chain_request.go:76` | NO |
| B2 (propagation → orphans) | Orphans 2.7 % of regular shares (R30 read: orphan rate 0.0204). Only lower delivery latency helps. | OPEN (not measurable while the miner is paused) | rft:2438 | NO — orphaning is arrival order at the assembling node (first 9, `blockchain/miner_block.go:338` HEAD). A contract cannot observe arrival. |
| B60 / B58 | Reorgs were never logged; GetInfo alt_blocks_count was never set | CLOSED (persistent reorg monitor; alt count assigned) | rft:2505, rft:2503 | NO |

## 3. RPC / wallet surface

| id | concern | status | anchor | game-theory lever? |
|---|---|---|---|---|
| `mem:dero-security-r23b` | jrpc2 built-in `rpc.serverInfo` leaked the method list, start time and shared-bridge counters (incl. loopback wallet/miner traffic) to remote callers | FIXED (R23b: DisableBuiltin on remote) | `mem:dero-security-r23b` | NO |
| `mem:dero-security-r23b` | SendRawTransaction admitted valid-but-stale txs (never mineable) | FIXED (glue/txprecheck/window.go) | `mem:dero-security-r23b` | NO |
| B12 / B13 / B14 / B28 | Remote-RPC scoring: deliberate global surge, no /24 aggregate, ordering, pre-warmed trusted keys | CLOSED (R23c–R24) | rft:2448–2450, rft:2464 | NO |
| B29 | 256×256 batch (65,536 txids) admitted per remote body | CLOSED (≤ 1,024 items/body, item-weighted cost) | rft:2465 | NO |
| B280 | Census of every RPC/P2P handler for a rate limit / budget / size cap | DONE (R31; DERO.Subscribe capped at 16 events) | rft:2732 | NO |
| B85 / B86 / B100 / B80 / B143 | Input-reachable `panic(err)` in RPC handlers (pruned topoheight etc.), untyped errors, zero header for an unknown hash, uncounted recovers | FIXED (R25–R27) | rft:2530, 2531, 2545, 2525, 2588 | NO |
| B298 | `Hash.UnmarshalText` accepts 64 hex + trailing garbage as its prefix for every crypto.Hash RPC param | OPEN (fix-later at the handler layer) | rft:2750; `cryptography/crypto/hash.go:33` | NO |
| B302 | walletapi balance Lookup searches upward with no ceiling: a hostile daemon's ciphertext hangs the decoder | OPEN (fix-later: stop at the emission bound) | rft:2754; `walletapi/balance_decoder.go:206` | NO |
| B299 | bn256 G1 scalar mult is variable-time on wallet secret paths (side channel) | OPEN (low; wallet-local constant-time ladder proposed) | rft:2751; `cryptography/bn256/curve.go:185-207` | NO |
| `mem:dero-crypto-audit-r22` C3 | Wallet r / payload keystream reuse across payloads with the same ring order (p = 1/2 at ring 2) | FIXED (pick_ring_order); cross-tx reuse at the same roothash remains (2nd tx is a double-spend) | `mem:dero-crypto-audit-r22`; B110 rft:2555 | NO |
| `mem:dero-crypto-audit-r22/r23` C4 | Payment proofs restate to any amount. FIXED receiver-side (B == sk·D), but explorers still cannot check. | FIXED wallet-side; format change upstream | `mem:dero-crypto-audit-r23` | PARTIAL — a notary or escrow contract (M2-type) must never treat a payment proof as evidence of an amount; only an on-chain SC deposit is verifiable. This is a design constraint, not a fix. |
| B32 (CI-9) | A receiver payment proof discloses the V2 payload key for an unbound E (payload privacy) | CLOSED as an accepted residual (wallet-local guard; full fix = format change upstream) | rft:2468 | NO |
| `mem:dero-crypto-audit-r23` | Integrated-address DST port silently dropped when a payload was supplied; p2p TLS serial derived from peer_id XOR time | FIXED (R23) | `mem:dero-crypto-audit-r23` | NO |
| B17 / `mem:rpcws-r23-findings` | Wallet history resync after a reorg peeled one group per call; Close-before-ws hang; reconnect leak | CLOSED / FIXED | rft:2453; `mem:rpcws-r23-findings` | NO |
| B40 | Wallet RPC server: empty 415 / exact Content-Type match | FIXED (R25) | rft:2485 | NO |
| B19 | Mempool fee rank was integer fee/size (fee priority ineffective) | FIXED (R29) | rft:2455 | NO |
| B183 | A third-party SC dry-run pool pre-check refuses calls that consensus accepts next block | REJECTED (counter-example to "pool refuses only what consensus refuses") | rft:2628 | NO |
| GT-B6 | Front-running of public SC arguments (claims, Notarize digests) via mempool exposure | OPEN (child rft) | gt-rft:210; `gametheory/mechanisms.json` M2 attacks | YES — commit-reveal (sha256(i:vote:salt)) inside the contract removes the advantage of copying a public argument. This is already the M1/M3 design. |

## 4. DVM / smart-contract risks

| id | concern | status | anchor | game-theory lever? |
|---|---|---|---|---|
| B10 / B306 | Unmetered hash gas: sha256/sha3256/keccak256 flat 25k gas while work grows with input. Compute gas is never charged (mem: ~300 MiB hashed per call). Chain-stall DoS class. 7 flat-gas builtins in all. | REPORT-ONLY + PINNED (TestR27BuiltinGasTablePinned; listed for Foundation disclosure) | rft:2446, rft:2758; `dvm/dvm_functions.go:85-87` (HEAD) | NO — gas pricing is consensus. A game contract cannot price other contracts' calls. |
| B10 / `mem:dero-emission-audit` | SC payout to an unregistered destination: SanityCheckExternalTransfers treats ErrNotFound as OK unless the destination is LAST. ProcessExternal then panics mid-way, so earlier transfers apply and the rest is burned (deflation, not inflation). | REPORT-ONLY (consensus) | rft:2446; `dvm/simulator.go:236` (HEAD, ErrNotFound) | PARTIAL — a contract author can require payees to be registered (or pay only by pull/withdraw by SIGNER) to avoid the burn in its own contract. The consensus defect stays. |
| Zero-signer revert (`mem:derod-console-error-triage`, `mem:dero-network-changes` R7) | Anonymous SC calls take the revert branch with a zero signer. Both signer arms make the same ErrorRevert call, so "burn all funds" is unimplemented. The fee is KEPT (corrected R11). | REPORT-ONLY (consensus; logging demoted R11) | `blockchain/transaction_execute.go:418`, `:420` (HEAD) | NO — and a constraint: a game that needs SIGNER must demand ring size 2. Anonymous entrants revert. |
| B157 | SC burn conservation by path: refunded on failing call / missing SCID / unparseable code / overdraw; DESTROYED on a failed Initialize install and some other paths | REPORT-ONLY (consensus); partly FIXED logging (R29) | rft:2602 | NO |
| B145 | DVM pinned behaviours: EXISTS/LOAD after DELETE in one invocation fails; UPDATE_SC_CODE stores unparsed source (a bad update bricks the SC); ADDRESS_STRING always mainnet; MIN/MAX type check | REPORT-ONLY (consensus) | rft:2590; `dvm/dvm_functions.go:317` ("TODO verify code authenticity", per row) | NO (authors must avoid self-bricking updates) |
| B292 | `dvm_min`/`dvm_max` check arg 1's type twice, never arg 2's → recovered panic (SC error, no node crash) | REPORT-ONLY + PINNED | rft:2744; `dvm/dvm_functions.go:597`, `:615` (per row) | NO |
| B307 | `dvm.Variable.UnmarshalBinary` panics on malformed bytes; SC_META DataHash never stored | REPORT-ONLY + PINNED (fuzz) | rft:2759; `dvm/dvm_store.go:228`, `dvm/sc.go:43` | NO |
| B311 | Failed SC_INSTALL destroys the burn | see §1 | rft:2763 | NO |
| GT-B7 | DVM own-token stored balance: `stored_value - value` with no underflow check | OPEN (pin disclosure-style) | gt-rft:211; `dvm/simulator.go:220-226` (per row) | NO (consensus); contract authors guard their own arithmetic (gt lesson 3: uint64 wraps silently) |
| gt lessons 2–3 | DVM `&&`/`||` evaluate both sides (a LOAD of a missing key panics); uint64 arithmetic wraps silently | Documented (R32) | gt-rft §10 items 2–3 | NO (language semantics) |
| B288 / B305 | No DVM /metrics: install/invoke/revert/out-of-gas were invisible | DONE (R31, glue/dvmobs sc_* families) | rft:2740, rft:2757 | NO |
| D-GT-10 | M3 v1 drew from RANDOM keyed by BLID: the Draw block's integrator could withhold to re-roll at the cost of one share | FIXED in design (v2 draws from the revealed seed only) | gt-rft:92 | YES — the lever IS the contract design: never key payouts to the including block's RANDOM; use commit-reveal with a height deadline and a forfeit. |
| M3 reveal censorship / last-revealer withholding | An integrator can leave a reveal out of its block; the last revealer can withhold | Mitigated by design (multi-block window; 12 distinct integrators in 60 blocks; bond-bounded) | `gametheory/mechanisms.json` M3 attacks | YES — a reveal window spanning many blocks/integrators plus a forfeit bond makes censorship or withholding cost more than it gains. |
| M1 juror bribery (GT-B4) / sybil (GT-B8) | P+ε bribery of Schelling jurors; address splitting | OPEN (experiments pending) | gt-rft:208, gt-rft:215; mechanisms.json M1 | PARTIAL — commit-reveal, slashing and stake caps raise the bribe cost (econsim m1_bribe_cost); a residual risk is stated, not removed. |

## 5. Mining / integrator economics risks

| id | concern | status | anchor | game-theory lever? |
|---|---|---|---|---|
| Integrator-address footgun (`mem:dero-reward-luck-mechanics`) | Without `--integrator-address`, the node uses `globals.Config.Dev_Address`. The final miniblock's share + leftover then go to the dev address (~+11 % forgone). The user's node is confirmed set. | Operator config (verified set) | `blockchain/blockchain.go:125-126` (HEAD) | NO — node config. A contract cannot see the integrator. |
| Final-miniblock share → integrator (`mem:dero-reward-luck-mechanics`, R32) | The FINAL's finder is paid nothing (`if mbl.Final { continue }`); share + leftover go to the template's integrator, so the orphan cost falls on the integrator | Structural (consensus) | `blockchain/transaction_execute.go:148` (HEAD); `mem:dero-r32-round` | NO — consensus payout rule. It does create the integrator's re-roll lever that contracts must design around (D-GT-10). |
| B195 / B62 / B201 | Integrator concentration: integrator-only participants assemble ~0.34 of blocks; Nakamoto coefficient by finals 3; D16 is structurally ANOMALY under pooling | ANNOTATED / EXPLAINED (structural); D19 detector DONE | rft:2640, rft:2507, rft:2646 | PARTIAL — a contract could pay a bounty for attested decentralisation (more distinct integrators, counted off-chain from public headers via a bonded claim). It cannot see the integrator itself, and only real DERO value shifts behaviour (gt-rft §4 item 3: +1 % hashrate ≈ 308 atomic/block). |
| Orphaning (B2; `mem:dero-reward-luck-mechanics`) | Paid = first 9 normal miniblocks by arrival order at the assembling node; no reorg back-pay; stale window [h−2, h+1]; R32 alt rate 2.05 % | OPEN (B2) / structural | rft:2438; `blockchain/miner_block.go:338` (HEAD) | NO — arrival order is not on chain. A contract compensating "orphaned" shares would need an unverifiable claim. |
| Stale-mining while behind (`mem:dero-network-changes`, `mem:dero-getinfo-cannot-show-lag`) | Mining while the node is behind = stale miniblocks the network rejects, so 0 reward; GetInfo cannot show the lag | Operator; tip-age judged from the tip block | `mem:dero-network-changes` | NO |
| B36 / B39 / B45 | Getwork dead normal jobs and final-flip delay (template cache) waste hashing near the block boundary | B36 CONFIRMED (24 h payee read); B39 small sample; B45 estimate | rft:2472, rft:2474, rft:2490 | NO |
| `mem:dero-r22-security-dim` | Daemon-chosen difficulty 1 → miner submit flood | FIXED (mainnet token bucket 50/s) | `mem:dero-r22-security-dim` | NO |
| GT-B10 / gt lesson 0 | Sim mining shares ≠ hashrate shares (difficulty 1, dispatch-bound) | OPEN (hypothesis) | gt-rft:213, gt-rft §10 item 0 | NO (measurement caveat) |
| D-GT-3 / N4 | A contract cannot raise or redirect the block reward; SC incentives move hashrate only by I/R of real value | NO-GO N4 | gt-rft:90, gt-rft §9 | NO — by definition. |
| M2 wash trading / N1 / N5 / N6 | Self-dealing for boost; Ponzi-shaped referral; emission-funded yield; quadratic funding without sybil resistance | Bounded by design (ρ(100+boost) ≤ 10000) / NO-GO | gt-rft §4 item 4, §9 | YES (for M2) — the no-wash inequality makes self-dealing unprofitable without others' fees. The NO-GO items are excluded, not levers. |

---

## Tally (strict)

- YES (4): GT-B6 front-running (commit-reveal), D-GT-10 RANDOM re-roll (seed-only draw), M3 reveal censorship (multi-block window + bond), M2 wash trading (no-wash bound). All are risks inside the game contracts themselves, not node or consensus defects.
- PARTIAL (7): range-proof monitoring re-runs (B8 track), emission-auditor bounty, B182 weak-PoW registration reports, C4 payment-proof design constraint, unregistered-destination burn (author-side pull payments), M1 bribery/sybil, integrator concentration bounty. Each only funds or attests detection; the defect stays.
- NO: everything else (consensus verifier/decoder/gas/timestamp rules, P2P policy, RPC/wallet code, operator config, arrival-order orphaning).

Evidence gaps (not stated as facts above): no row gives a measured eclipse attempt, a live sybil observation or a live flat-gas DoS on mainnet. B269's single-peer future-timestamp blocks remain OPEN (e) pending the metrics re-read.
