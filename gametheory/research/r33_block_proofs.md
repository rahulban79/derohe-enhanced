# R33 block proofs inside a contract: prior art, the DERO mapping, and the attacks

Date: 2026-11-17. Scope: GT-B24 (block bytes proven against an anchored `BLID()`), GT-B25 (the miniblock `Flags` game
tag) and the M5 `gt_pool.bas` draft (rft §8.1, D-GT-23). Code was read at HEAD. No node RPC, getwork or P2P port was
called. The four mainnet blocks used here are the repo test vectors `dvm/testdata/r33_mainnet_blocks.json`. They were
read as data with a local parser kept in a session scratch directory, outside the repo.

**Labels.** **doc** = specification, README or EIP. **paper** = peer-reviewed or arXiv/ePrint. **steer** = blog, forum
or search snippet (it raises questions but is not evidence). **FAILED** = the fetch returned no content.
**abstract-only** = only the abstract was read. **CONFIRMED** = a test or run in this session shows it. **CODE** = read
at the cited `file:line`. **ESTIMATE** = arithmetic from anchored constants, not executed. **PLAUSIBLE** = reasoned from
code, with no test yet.

---

## 1. Prior art: what each design verifies, and what it costs

| system | what is verified on chain | PoW checked? | header chain? | inclusion? | cost / trust | source |
|---|---|---|---|---|---|---|
| Bitcoin SPV | Light client keeps "a copy of the block headers of the longest proof-of-work chain" and "the Merkle branch linking the transaction to the block"; "reliable as long as honest nodes control the network" | yes (client side) | yes, every header | Merkle branch | linear in chain length; honest-majority assumption | [P1] paper https://bitcoin.org/bitcoin.pdf §8 |
| BTC Relay (Ethereum contract of Bitcoin headers) | `storeBlockHeader` stores a header only with "a valid Proof-of-Work and the previous block it reference exists"; `verifyTx` checks "the transaction is on Bitcoin's main chain and has at least 6 confirmations" via `merkleSibling` | yes, per header, in the contract | yes, every header stored | yes (Merkle) | relayers paid per use (`storeBlockWithFee`, `getFeeAmount`); "store only 5 headers at time" because of the block gas limit; no gas figure on the page; repo archived 2025 | [D1] doc https://github.com/ethereum/btcrelay |
| Summa relays | headers submitted in groups of ≥ 5 (`addHeaders`), with extra validation at retarget; "minimize storage costs by increasing calldata costs"; tip moves only on request (`markNewHeaviest` with a common ancestor) | implied (validated extensions; PoW wording not explicit on the page) | yes, but stores only the parent link and every n-th height | SPV proof validated by the relay | "subjective finality" (the ancestor "may move backwards!"); proofs "may be filled more than once"; no gas numbers ("TODO: benchmarking") | [D2] doc https://github.com/summa-tx/relays |
| Testimonium / ETH Relay (optimistic relay) | headers accepted unvalidated with a stake and a `LOCK_PERIOD`; a dispute triggers full Ethash validation; a failed header "and all its descendants are removed" | only on dispute | yes | SPV once the lock expires | Ethash check about 3 M gas per header; full-validation baseline 3,369,653 gas; on-demand 612,348 (−82 %) and 284,041 (−92 %); safe "as long as at least one altruistic disputer is participating" | [P2] paper https://arxiv.org/abs/2002.12837, body via https://ar5iv.labs.arxiv.org/html/2002.12837 |
| NiPoPoW (Kiayias, Miller, Zindros) | succinct proofs of predicates about a PoW chain; "resources only logarithmic in the length of the blockchain"; "a single message" | yes (superblock sampling) | sampled, not every header | yes | needs a fixed-difficulty chain (FlyClient's critique, below) | [P3] paper, abstract-only https://eprint.iacr.org/2017/963 |
| FlyClient (Bünz, Kiffer, Luu, Zamani, S&P 2020) | variable-difficulty light client; MMR commitments; "downloading only a logarithmic number of block headers"; secure against an adversary creating "a c < 1 fraction of the honest chain's work"; Ethereum sync proof < 500 KB, about 6,600× smaller than SPV; inclusion proofs about 1.5 KB | yes (sampled) | sampled, MMR-committed | O(log n) hashes | requires an MMR commitment in headers (a velvet or soft fork) | [P4] paper https://conferences.computer.org/sp/pdfs/sp/2020/349700a928.pdf; abstract https://eprint.iacr.org/2019/226 |
| Rainbow Bridge (NEAR ↔ Ethereum) | `EthOnNearClient` validates Ethereum headers as PoW by default (the README says PoA mode "force[s] `EthOnNearClient` to not validate Ethereum headers"); the Ethereum side accepts NEAR headers with a challenge | yes (Eth side on NEAR) | yes | yes | submitting a NEAR header costs about 697,140 gas and a challenge about 700k; about 42 USD/day at 40 gwei (2020); liveness "1 transaction within 4 hour period" | [D3] doc https://github.com/aurora-is-near/rainbow-bridge; [D4] doc https://doc.aurora.dev/bridge/introduction (timing only) |
| Ethereum Altair light client | sync-committee aggregate BLS signature (`bls.FastAggregateVerify`), a ≥ 2/3 participation rule, Merkle branches to `finalized_header`; starts from a `trusted_block_root` | no (PoS) | committee-signed | Merkle branch | trust in the committee plus a trusted bootstrap root | [D5] doc https://ethereum.github.io/consensus-specs/specs/altair/light-client/sync-protocol/ |
| EIP-2935 (historical hashes in state) | the protocol writes each parent hash into a system contract ring buffer of 8,191 entries; `BLOCKHASH` keeps its 256 window; "proofs about recent ancestor blocks can be checked against the current state" | **no**: the chain itself supplies the hash | ancestors through stored hashes | via the proven header | trust = own consensus | [D6] doc https://eips.ethereum.org/EIPS/eip-2935 |
| EIP-4788 (beacon root in the EVM) | beacon block roots in a ring buffer of 8,191; "trust-minimized access to the consensus layer" | **no** | root only | Merkle proofs against the root | trust = own consensus | [D7] doc https://eips.ethereum.org/EIPS/eip-4788 |

**Steers (not evidence).** Search snippets say that the Rainbow Ethereum-side NEAR client is optimistic, with staked
relayers, watchdogs and week-long delays, and that one Ed25519 challenge costs about 500k gas. Horizon
(https://arxiv.org/abs/2101.06000, paper, abstract-only) only says existing bridges "incur significant computation
overhead". Neither claim is used below. A JaxNet critique of FlyClient (arXiv 2005.01865) appeared only as a snippet
and was not fetched.

**The pattern.** Every relay that verifies PoW verifies a *foreign* chain, whose consensus the host chain does not run.
The two designs that do not verify PoW are EIP-2935 and EIP-4788. They are same-chain designs: the host's consensus
writes the hash, and a contract proves bytes against it with a hash function. DERO GT-B24 belongs to this second
class.

---

## 2. The DERO mapping (CODE, CONFIRMED)

### 2.1 What the contract checks
1. **Anchor.** A call stores `BLID()`. On chain, `BLID()` is the hash of the block that executes the transaction
   (`blockchain/blockchain.go:1021` passes `bl_current_hash` into `process_transaction_sc`).
2. **Prove.** A later call accepts hex bytes only if `SHA3256(bytes)` equals the stored id. A block id is
   `sha3.Sum256(bl.serialize(false))` (`block/block.go:57-58`).
3. **Parse.** The parse walks backwards from the end. The serialization order is versions, an 8-byte timestamp, the
   height varint, the miner tx, a 32-byte proof, the tips, the miniblock count, 48-byte miniblocks, then the tx count
   and tx hashes (`block/block.go:99-140`). Miniblock fields are the version byte, a 16-bit timestamp, a 5-byte
   height, Past[2], KeyHash[:16], Flags and the nonce (`block/miniblock.go:140-171`).
4. **CONFIRMED in this session.** `go test -run TestR33 ./dvm/ ./cmd/dero-miner/` passed, including
   `TestR33BlockProofVerifiesRealMainnetBlocks`. Prove used 1,742,400 compute gas and 1,735 storage gas for the
   598-byte blocks, and 1,927 for the 694-byte block with 3 txs. The same run passed the 4 `TestR33Pool*` tests,
   `TestR33Beacon` and `TestR33GameTagLandsInFlags`.

### 2.2 Why the contract does not need to verify AstroBWT
- **Consensus already checked the PoW.** A transaction executes only inside a block that the executing node accepted.
  Acceptance checks the PoW of every miniblock (`blockchain/blockchain.go:604-610`, `VerifyMiniblockPoW`). It applies
  9× difficulty to the HighDiff final (`blockchain/difficulty.go:154-183`, `MINIBLOCK_HIGHDIFF = 9`
  `config/config.go:36`). It requires every non-final key to be registered (`blockchain/blockchain.go:595-601`) and
  exactly `BLOCK_TIME − MINIBLOCK_HIGHDIFF + 1 = 10` miniblocks at the block's height
  (`blockchain/miniblocks_consensus.go:80-91`).
- **Side blocks never execute.** A side block's transactions are ignored and it gets 0 reward
  (`blockchain/blockchain.go:984-986`). So it can never hold an anchor, and the work in orphaned blocks is never
  credited.
- **The PoW binds the tag.** It is computed over the full 48-byte miniblock (`block/miniblock.go:113-118`
  `AstroBWTv3(mbl.Serialize())`), so the Flags tag is bound to the work.
- **Collision resistance links the bytes to the id.** Given an id that consensus wrote, SHA3-256 makes the proven
  bytes the accepted block. This is the EIP-2935 argument [D6]: the chain vouches for the hash, so the contract only
  checks a hash. A relay's PoW check [D1][P2] answers "is this header heavy?". Here the chain's own validation already
  answered it.
- **The DVM could not check the PoW anyway.** It has no AstroBWT builtin (`dvm/dvm_functions.go:57-95`), and compute
  gas is fixed at 10M per call (`dvm/sc.go:241`).

### 2.3 New in R33: one anchor proves a whole chain of ancestors (CONFIRMED on the test vectors)
- **The tip is the parent's id.** Each proven block's bytes contain its tip. In the test vectors, the tip of 7,915,142
  equals the id of 7,915,141, and the tip of 7,915,143 equals the id of 7,915,142.
- **Consensus guarantees it.** Only one tip is allowed (`blockchain/blockchain.go:490-492`). The tip must be the
  height − 1 block (`:504-508`), and every miniblock's `Past[0]` equals the tip's first 4 bytes
  (`blockchain/miniblocks_consensus.go:99`).
- **The consequence.** A contract that proves block h can store `tip(h)` as the verified id of h − 1, then prove h − 1
  against it, and so on back to the start of the epoch.
- **Gas.** Each step costs one Prove (about 1.74M compute, which is never charged, plus about 1,735+ storage gas).
- **gt_pool.bas does not do this.** It only accepts ids stored by `Anchor` (`gametheory/contracts/gt_pool.bas:190`,
  `:195`), so every block with member work needs its own anchor transaction *inside that block*.
- **Residual (UNCONFIRMED).** Is the tip-ancestor of a main-chain block always a main-chain block, rather than a side
  block topo-ordered at the same height? The side-block rule is "same height as the previous topo record"
  (`blockchain/blockchain.go:1394`). With a single tip this is PLAUSIBLE but untested. A sim-chain test with a forced
  side block should settle it before back-walk credits are paid.

### 2.4 Also new: the integrator key is readable and checkable in-contract
- **Where the key sits.** The block header carries the coinbase tx: version, source, destination, type `COINBASE`, then
  the 33-byte `MinerAddress` (`transaction/transaction.go:433-457`, written by `block/block.go:118`).
- **The offset.** For current heights (a 4-byte height varint), the key sits at bytes 18..50. In the test vectors,
  7,915,142 and 7,915,143 have the same integrator key prefix, and 7,915,141 and 7,911,096 have different ones.
- **What this allows.** `SIGNER()` is the raw 33-byte compressed key (`dvm/sc.go:191`, returned as-is at
  `dvm/dvm_functions.go:307-310`). So a contract can test `SUBSTR(b, 18, 33) == SIGNER()` and credit **the
  integrator's own key**, with no tag and no BLAKE2s.
- **The limit.** Regular miniblocks carry `KeyHash = BLAKE2s(key)[:16]` (`blockchain/miner_block.go:365`). The DVM has
  no BLAKE2s (`dvm/dvm_functions.go:85-87`), so their binding still needs the Flags tag.
- **Caveat.** Offset 18 assumes a 4-byte varint (heights 2^21..2^28−1). A contract should parse the varint.

---

## 3. Residual trust
1. **Consensus correctness.** If a node accepted an invalid block, the contract inherits the error. This is the same
   assumption as EIP-2935 [D6] and the SPV honest-majority condition [P1].
2. **Reorgs within the reorg limit.**
   - Blocks more than `STABLE_LIMIT = 8` heights below the tip are refused (`config/config.go:79`,
     `blockchain/blockchain.go:484-487`).
   - Contract state is committed with its block (`blockchain/blockchain.go:1033-1074`, per
     `gametheory/research/r33_code_capabilities.md` §2.1). A reorg that removes the anchoring block therefore removes
     the anchor and every later proof and credit together, because all later blocks descend from it through the
     single tip.
   - No inconsistent credit survives. The cost is wasted proof fees, so provers should wait until h + 8 < current
     height (ESTIMATE of the safe margin).
3. **A majority miner.** It mines main-chain blocks with any tags it likes, but that is real work and is credited as
   such. A contract cannot tell a 51 % miner from a large honest one (see `r33_forensics_and_security.md` §1).
4. **The integrator chooses the 9 regular miniblocks.**
   - The template takes miniblocks from the node's own collection (`blockchain/miner_block.go:336-340`).
   - The integrator also chooses the transactions (`blockchain/miner_block.go:205-281`).
   - A hostile integrator can therefore censor tagged miniblocks or Anchor transactions in the blocks it integrates
     (PLAUSIBLE). A contract cannot see what was left out. Mitigations are listed in §4.

---

## 4. Attacks and mitigations

| # | attack | status | effect on gt_pool.bas as drafted | mitigation |
|---|---|---|---|---|
| A1 | **Untagged-flag squatting (tag `00000000`)** | CONFIRMED premise + CODE | All 40 miniblocks in the 4 mainnet test blocks have Flags = 0, because the stock template leaves the flags alone (`blockchain/miner_block.go:375` "leave the flags for users as per their request"; `cmd/dero-miner/gametag.go:8`). `Register` refuses only a *taken* tag (`gt_pool.bas:66`). Anyone who grinds a key with `SHA3256(key)[:4] = 00000000` (expected 2^32 tries, about 1–6 core-hours at 1–5 µs per try, ESTIMATE) gets credit for every stock miniblock in every proven block. Honest provers' proofs credit the squatter for free. With the 30 % cap the squatter takes 30 % of each epoch, and the rollover feeds it back. | Refuse tag 0, and refuse any tag seen in pre-registration blocks. Credit only `h > registration height`. Also bind the KeyHash (A2). The tag should never be a value a stock miner writes. |
| A2 | **Mining with someone else's tag** | CODE | A miner X that sets Y's tag earns the protocol reward on X's KeyHash, and the pool credit goes to Y. It is harmless as a donation, but it means pool credit is *not* bound to the miner's key. The rft's claim "the KeyHash is also matched" (GT-B25 row) is not implemented and cannot be computed in-contract (no BLAKE2s). | Register(kh): the member declares its 16-byte KeyHash (computed off chain), and credit requires Flags == tag **and** KeyHash == kh. A false declaration only earns credit if that key's owner mines with the declarer's tag, which needs the owner's consent. |
| A3 | **Tag squatting a known member** | CODE | Anyone can compute tag(Y) from Y's public key and grind a colliding key (2^32) to register it first. Y must then use another address (DoS only). If Y mined tagged *before* registering, the squatter is also credited for those blocks, because credit checks the tag only at proof time (`gt_pool.bas:141`). | Register before mining (playbook rule). Credit only blocks with h > registration height (store `reg_<tag>`). |
| A4 | **Front-running a proof** | CODE | Proof arguments are public in the mempool. A copier can resubmit them, but credits go to the tag owners, whoever proves (`gt_pool.bas:212`). Only `pfee` (100 atomic, `:31`) moves. At a proof fee of about 1,735–2,000 atomic, copying loses money. | None needed while pfee < the proof fee. If pfee is raised to make proving pay (see `r33_pool_math.md` §6), bind pfee to the first anchor's or prover's commitment, or accept the race. |
| A5 | **Griefing by never anchoring / Anchor censorship** | CODE | A block without an Anchor tx inside it can never be proven (`gt_pool.bas:190`). An integrator can drop Anchor txs from blocks it integrates. Unanchored blocks lose every member's credit in them. | Back-walk through tips (§2.3): one surviving anchor per epoch proves every earlier block of the epoch. Censorship must then cover every block until the grace window ends. |
| A6 | **Misparse griefing (new)** | CONFIRMED on test data | The structure check is two count bytes found from the end (`gt_pool.bas:196-202`). For mainnet block 7,915,141 a second parse (ntx = 0, m = 7) also passes: the last nonce byte of miniblock 2 is `07`, so the contract would read miniblocks 3..9 only and set `pr<h>` (`:203`). The first 3 miniblocks' credits are then lost for good, because `pr<h>` refuses a second proof (`:191`). Each m′ in 1..9 needs one specific byte, so about 9/256 ≈ 3.5 % of blocks are exposed (ESTIMATE). | Require `m == 10` (consensus: `blockchain/miniblocks_consensus.go:80-81`). Also check each parsed miniblock's 5-byte height == h (`:90-91`) and Past[0] == tip[:4] (`:99`). A misparse then needs a 2^-40-class coincidence. |
| A7 | **2^-32 tag collision** | ESTIMATE | Among members a collision is impossible, because duplicate tags are refused. Third-party miners that use Flags as nonce space ("also used as nonce", `block/miniblock.go:55`) hit one of N member tags with about 41,805·N/2^32 miniblocks/day: N = 100 gives 9.7·10^-4 per day. That is negligible next to A1. | None beyond A1/A2. KeyHash binding removes it entirely. |
| A8 | **Anchoring cost and who pays** | ESTIMATE | One Anchor per block is about 4,645 tx/day at the measured 18.60 s/block. At about 150–250 atomic each (storage gas for a ~10 B key, a 32 B value and SCDATA, plus the size fee of a ~1.5 KB ring-2 tx: `config/config.go:49`, `blockchain/tx_fees.go:34-44`), that is about 0.7–1.2 M atomic ≈ 7–12 DERO/day. The protocol emits about 1,428 DERO/day (4,645 × 30,750 atomic, `blockchain/transaction_execute.go:44-62`). Today nobody pays the anchorer. | Back-walk (§2.3) reduces anchoring to ≥ 1 per epoch (about 12/day). Pay an anchor fee from the epoch pool only for the anchor that a proof chain actually used. |
| A9 | **Late claim after Rollover (accounting)** | CODE, PLAUSIBLE (no DVM test yet) | `Claim` has no upper height bound (`gt_pool.bas:229`). `Rollover` zeroes `P<e>` (`:262-263`) but leaves the `P0_<e>` snapshot. A member who claims after another member has already claimed and after Rollover gets `amt` from the snapshot. `P<e>` then wraps (`:246` `pget(e) - amt` on 0), and the SEND is paid from other epochs' pools, stakes or the `burned` reserve. That breaks the invariant "balance ≥ burned + liabilities" that the deflation claim rests on. | Refuse Claim once `BLOCK_HEIGHT() ≥ (e+5)·epochlen + grace`, or have Rollover set `closed<e>` and have Claim check it. Add a DVM regression test. |

**Not an attack: block withholding against the pool.** Credit is paid only for accepted main-chain miniblocks. Each
of them already paid its own protocol share to its KeyHash (`blockchain/transaction_execute.go:146-160`). A withheld
miniblock forfeits both, so the "sabotage" of share-based pools ([P5] Rosenfeld §6.2) has nothing to work on. Details
are in `r33_pool_math.md` §2.

---

## 5. Design rules derived (falsifiable)

| ID | rule | falsified if |
|---|---|---|
| BP-1 | The contract trusts only ids written by its own consensus (`BLID()` or a tip inside an already-verified block). It never accepts a caller-supplied id. | Any entrypoint credits a block whose id came from an argument. |
| BP-2 | A proof checks the full structure: m == 10, every miniblock height == h, Past[0] == tip[:4], a single tip. | A DVM test with a real block finds a second accepted (ntx, m) parse. |
| BP-3 | Credit requires Flags == tag ≠ 0 **and** KeyHash == the member's declared kh, for blocks above the member's registration height. | A key that grinds tag 0, or registers after the block, is credited. |
| BP-4 | One verified id per epoch is enough: proofs walk back through tips. | An epoch's credits depend on more than one anchor tx. |
| BP-5 | Proof fees are covered (pfee ≥ measured proof fee), or the pool states that proving is self-paid (see `r33_pool_math.md` §6). | Measured proof fees exceed pfee while proofs are expected from non-members. |
| BP-6 | Every payout path keeps balance ≥ burned + Σ pools + Σ stakes. | A replay of the pool's calls (or a DVM test) shows a payout after Rollover. |
| BP-7 | Prove only settled blocks (h + 8 < height) to avoid wasted fees. Credits are reorg-safe either way. | — (an efficiency rule) |

---

## Sources (this file)

| ref | label | URL | status |
|---|---|---|---|
| P1 | paper | https://bitcoin.org/bitcoin.pdf | fetched, full text (§8 SPV read) |
| D1 | doc | https://github.com/ethereum/btcrelay | fetched |
| D2 | doc | https://github.com/summa-tx/relays | fetched |
| P2 | paper | https://arxiv.org/abs/2002.12837 (+ https://ar5iv.labs.arxiv.org/html/2002.12837) | fetched (abstract + body) |
| P3 | paper | https://eprint.iacr.org/2017/963 | abstract-only (the PDF returned a bot-check page) |
| P4 | paper | https://conferences.computer.org/sp/pdfs/sp/2020/349700a928.pdf ; https://eprint.iacr.org/2019/226 | full text (S&P copy); ePrint abstract |
| D3 | doc | https://github.com/aurora-is-near/rainbow-bridge | fetched |
| D4 | doc | https://doc.aurora.dev/bridge/introduction | fetched (timing only) |
| D5 | doc | https://ethereum.github.io/consensus-specs/specs/altair/light-client/sync-protocol/ | fetched |
| D6 | doc | https://eips.ethereum.org/EIPS/eip-2935 | fetched |
| D7 | doc | https://eips.ethereum.org/EIPS/eip-4788 | fetched |
| P5 | paper | https://arxiv.org/abs/1112.4980 | full text |
| — | paper | https://arxiv.org/abs/2101.06000 (Horizon) | abstract-only, unused |
| — | FAILED | https://pages.near.org/?p=4935 (redirected to a docs landing page with no bridge content); https://www.infura.io/blog/post/rainbow-bridge-fraud-proofs-and-the-dark-forest (redirected away); https://eprint.iacr.org/2019/226.pdf (bot-check page) | — |
| — | FAILED (mis-ID) | https://arxiv.org/abs/1902.10185 and https://arxiv.org/abs/2010.14385 turned out to be unrelated papers. These were wrong IDs, recorded so they are not reused. | — |
