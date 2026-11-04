# Independent audit of forensics/r25

Auditor: a second implementation (`audit-check-1`, `harness/forensics/audit_check.py`) that shares no code with the builder. Refute by default (rft §0.8.5).

Bound to the dataset data `93b32021107f210b7208a6a81e4186c8ebff4ae7600beaaa24dfb72252bbbe3d` (1421 files outside audit/), audited from manifest `fa37dd59a98e64aea19349bab95af071e3d387d84c5f5921e5282074408a3710`. Rerun block SHA-256 `892a90b57f304deae16b28e8da1b7b8f1cf4356301221fc257d695f1b6d3c316`.

**Result: 25 challenges, 23 HOLD, 1 FAIL (overturned), 1 UNRESOLVED; 1 verdict downgraded, 1 claim corrected.**

## What was re-run from raw/

Every tier A file and tier B store object was hashed. Each blob was decoded by this implementation as a block or a tx. Block ids are SHA3-256 under our own Keccak. The tips walk runs from our anchor. TXIDs are Keccak-256 of the core statement, sliced from the raw bytes. Emission comes from the source constants. The exception-path rules are evaluated against the RAW chain. The archive was checked through our own copies. Only after all of that were the builder's derived/ files read, as claims to compare.

## Challenges

| id | claim | result | evidence |
|---|---|---|---|
| A1 | anchor block 7,498,540 (e18be51e) is on the v3 chain | **HOLDS** | RAW: live topo records sha256 00c1f34dab107194; 6100 tips steps from height 7,504,640 to the anchor; fork block major 3; EXT: raw/sources.json: 6 archival sources report v3 at 7,504,640 (corroboration only) |
| A2 | the table's Height is the inclusion height (B82) | **HOLDS** | DERIVED: Height == earliest carrier height 75/75; Bl_Tips == its tip 74/75, == the carrier itself 1/75; tx.BLID == Bl_Tips 0/75; dual carriers 67, single 8, carrier gaps [1, 2, 3, 4, 5, 6] heights; SRC: blockchain/hardfork_fixes.go sha256 467db1b30b0ff16c (= manifest: True), 75 entries, groups {'duplicates': 67, 'no duplicates, but false parity': 8} |
| A2b | for aa0faf67 the table Bl_Tips is the carrier block itself, not its tip | **HOLDS** | DERIVED: TXIDs whose Bl_Tips is the carrier itself: ['aa0faf67'] |
| A3 | a file's name is its id (content addressing) | **HOLDS** | RAW: tier A 700 files (606 blocks, 94 txs), tier B 83171 files, 0 content-address failures; store index 22680e91cd2b5210 == manifest; RAW: replaywall block files 14724: name == SHA3-256 14724 |
| A4a | the exemption skips proof verification for these bodies under the pinned code | **HOLDS** | SRC: 18/18 code anchors present; DERIVED: tx.Height < 7504640: 75/75; skip on 142/142 carriers; sanity 75/75 |
| A4b | the chain accepted the tx only through the exemption (0045a6d4) | **FAILS** | DERIVED: earliest carrier precedes the first table commit for 75/75 TXIDs (minimum margin 39.8 h); first commits {'4712b7b67c5b': 60, '6c33c1c33354': 1, 'f7a56db69495': 14}; EXT: git author dates and miner-set block timestamps are claims of time; the 39.8 h minimum margin is far above any timestamp tolerance |
| A5 | topo == height in every window row (topo_ext was EXT) | **HOLDS** | DERIVED: 83077 blocks walked 7498540..7415464, multi-tip 0, contiguous True |
| A6 | the window is complete: 82,477 of 82,477 heights RAW with checks (i)-(ii) | **HOLDS** | RAW: window heights reached 82477/82477; unreached blocks 0 |
| A7 | each of the 94 TXIDs recomputes, and sits in a verified block (check iii) | **HOLDS** | DERIVED: 94 bodies, TXID in a verified block 94; the wire bytes are canonical (raw-slice hash == node TXID) |
| A8 | window emission = CalcSupply(7,497,943) - CalcSupply(7,415,466) = 2,536,167,750 atomic | **HOLDS** | DERIVED: reward values [30750], sum 2536167750, CalcSupply delta 2536167750; SRC: blockchain/supply.go:5-27, blockchain/transaction_execute.go:44-45,60-62, config/config.go:34,61 |
| A8b | the formula coinbase pays out exactly base + fees in every window block | **HOLDS** | RAW: COINBASE 82477, no value field 82477, one final miniblock 82477, payout identity 82477 of 82477 |
| A8c | fees: known for 80,902 blocks (16,800 atomic), pending for 1,575 | **HOLDS** | DERIVED: known 80902 blocks sum 16800, pending 1575; our archive holds bodies that would settle 192 of the pending blocks |
| A9 | no window block fills the header 'Proof' field (B83) | **HOLDS** | RAW: non-zero Proof field in 0 of 82477 window blocks |
| A10a | the held archive state is the state the 2 decided txs were built against | **HOLDS** | RAW: 0045a6d4: ref height 7467512 state version 18957 roothash c209d3c0a0d163dc; RAW: 414f79b8: ref height 7467492 state version 18518 roothash 15f02822aa5624be |
| A10b | no archive state root contradicts a RAW witness | **HOLDS** | RAW: 210 archive bodies, TXID == name 210, in RAW blocks 210; roothash == claimed root 199, != 0; distinct topos witnessed 190 |
| A10c | the 14,226 archive roots are the canonical state roots of those topos | **UNRESOLVED** | DERIVED: witnessed 190 of 14,226 topos; base tree from a fastsync bootstrap (its source unverified), no end-state check |
| A11 | today's verifier: 414f79b8 PASS, 0045a6d4 FAIL at a named proof check | **HOLDS** | DERIVED: 414f79b8 pass; 0045a6d4 fail:proof_verify (Recover key failed B^w * A); single implementation (the node's verifier) |
| A12 | exception-path counts: nonce bypassed on 74 carriers, full on 68, parity override changes execution on 73 of 142 | **HOLDS** | DERIVED: bypass 74, full 68, parity changes 73/142; builder records compared field by field: 142 carrier rows, mismatches 0 |
| A13 | the 75 bodies carry no public value (burn 0, no value field) | **HOLDS** | RAW: types {'NORMAL': 75}; bodies with public value 0 |
| A14 | the builder's 82,477 window rows equal an independent re-derivation | **HOLDS** | DERIVED: rows compared 82477, mismatches 0 |
| A15 | tier B counts: 83,077 blocks (window + 599 link + anchor), 1,726 tx-bearing window blocks with 1,835 txs, store 83,171 objects | **HOLDS** | RAW: store blocks 83077, txs 94, files 83171; tx-bearing 1726, txs 1835 |
| A16 | the archive files above its last committed topo (incl. fdb50de0 at 7,467,516) are off the RAW chain | **HOLDS** | RAW: committed records 14226 == RAW chain 14226, bytes equal 14226; files above 406, on chain 0 |
| A17 | EXT fields (reward_ext, topo_ext, treehash_ext) are never used as evidence | **HOLDS** | DERIVED: topo from the walk (A5), reward from the formula (A8); reward_ext == formula on every row (EXT agrees) |
| A18 | NOT-DECIDABLE-FROM-PUBLIC-DATA is the right grade for all 75 HF3 TXIDs | **HOLDS** | DERIVED: A8b, A12, A13; grade per TXID with checked items and the missing fact |
| A19 | the dataset text holds no exploit content and no private information | **HOLDS** | DERIVED: hits 0 |

## Overturned and unresolved

- **A4b FAILS**: the chain accepted the tx only through the exemption (0045a6d4). Test: for every TXID, the first git commit that adds it to blockchain/hardfork_fixes.go (git log -S) against the timestamp of its earliest RAW carrier: the claim needs the table to exist when the network accepted the block. Overturned wording. Supported reading: "a node running the pinned code accepts it only through the exemption (today's verifier rejects the proof)". How the network accepted these blocks in 2026-08 is not determined by this dataset. Affects: V-HF3-0045a6d4.
- **A10c UNRESOLVED**: the 14,226 archive roots are the canonical state roots of those topos. Test: needs either a witness per topo or an end-state check that binds the archive's fastsync base (topo 7,453,290); witnessed topos counted (A10b), end-state check not run (R26, (a2)). The builder labels these roots "not end-state-checked"; this row keeps that label binding: they are not shown as canonical roots (V-STATE-ROOTS -> pending). Affects: V-STATE-ROOTS.

## Verdicts after the audit

| verdict | builder | audit | note |
|---|---|---|---|
| V-EMISSION | PROVEN-NO-INFLATION-IN-SCOPE | **PROVEN-NO-INFLATION-IN-SCOPE** |  |
| V-HF3-0045a6d4 | NOT-DECIDABLE-FROM-PUBLIC-DATA | **NOT-DECIDABLE-FROM-PUBLIC-DATA** | already at NOT-DECIDABLE-FROM-PUBLIC-DATA; the failed claim is corrected in claim_corrections |
| V-STATE-ROOTS | held for 14,226 topos (DERIVED, not end-state-checked); 68,251 not reconstructable | **pending** | pending: the 14,226 roots are shown as the archive node's own roots (DERIVED from an unverified fastsync base), witnessed by RAW Statement.Roothash at the A10b topos only, until the R26 end-state check |
| V-EXT-23886517 | not graded (not_in_scope) | **SPECULATION** | EXT only: no RAW or DERIVED input in this dataset reproduces or refutes it (rft §0.8.2) |
| V-EXT-5000000 | not graded (not_in_scope) | **SPECULATION** | EXT only: no RAW or DERIVED input in this dataset reproduces or refutes it (rft §0.8.2) |
| V-HF3-* (75 TXIDs) | NOT-DECIDABLE-FROM-PUBLIC-DATA | **NOT-DECIDABLE-FROM-PUBLIC-DATA 75** | per TXID in audit_report.json |

Scope of V-EMISSION: the formula coinbase of the 82,477 window blocks 7,415,466..7,497,942 and its payout: each block has one COINBASE miner tx with no value field, exactly one Final miniblock, a payout equal to base + fees, and base rewards summing to CalcSupply(7,497,943) - CalcSupply(7,415,466). Says nothing about hidden (encrypted) amounts, the fee deductions inside them, or burns/SC payouts of the 1,575 blocks whose bodies are pending.

## Proof re-run (single implementation: the node verifier)

- `0045a6d4c51a8578…`: fail:proof_verify (check: Recover key failed B^w * A)
- `414f79b8ff3c862e…`: pass

Only the pass/fail result and the name of the failed check are recorded (rft §0.8.1 rule 6).

## Limits

- The proof results come from one implementation, the node's verifier. No second verifier exists here.
- Archive roots are witnessed only where an archive tx body points at them (A10b). Binding all of them needs the R26 end-state check.
- Hidden amounts are ElGamal ciphertexts. No grade here says anything about them.
