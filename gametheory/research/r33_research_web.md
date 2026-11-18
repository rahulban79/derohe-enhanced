# R33 web-research dossier: game theory for a DVM contract suite

Date: 2026-11-17. Scope: six topics for the R33 game-theory track (DERO HE, DVM-BASIC contracts, miner wallets on mainnet).

**Labels.** Each source is labelled **doc** (protocol or specification documentation), **paper** (peer-reviewed or arXiv/ePrint), **steer** (forum, blog, wiki or secondary write-up; it raises questions but is not evidence) or **local-code** (the DERO source tree on this machine, read-only). **FAILED** marks a fetch that did not return content. **abstract-only** marks a source that was read only at abstract level, so no claim here goes beyond its abstract. **DERIVED** marks a result I derived from cited formulas rather than quoted.

**The contract environment.** Every "Can it run in a DVM contract?" verdict below is judged against what the contract can actually see. Per [docs.dero.io/Developers/dvm](https://docs.dero.io/Developers/dvm) (doc) and `dvm/dvm_functions.go` (local-code), that is:

- its own store;
- `SIGNER()`, which is only known when the call's ring size is 2;
- `DEROVALUE()` / `ASSETVALUE()`, the deposit sent with the call;
- `BLID()`, `TXID()`, `BLOCK_HEIGHT()`, `BLOCK_TOPOHEIGHT()` and `BLOCK_TIMESTAMP()`;
- `RANDOM()`, which is Keccak256(SCID, BLID, TXID) (`dvm/deterministic_random_number.go:38`, local-code);
- hashes (`SHA256`, `SHA3256`, `KECCAK256`);
- `SEND_DERO_TO_ADDRESS` and `SEND_ASSET_TO_ADDRESS`.

The local function list is: version, load, exists, store, delete, map*, random, scid, blid, txid, dero, block_height, block_topoheight, block_timestamp, signer, update_sc_code, is_address_valid, address_raw, address_string, send_dero/asset, derovalue, assetvalue, itoa, atoi, strlen, substr, sha256, sha3256, keccak256, hex, hexdecode, min, max, panic.

Three things are missing from that list, and every verdict follows from them:

- There is **no signature-verification primitive**.
- There is **no block-header, miniblock or PoW accessor**.
- There is **no way to read another block's contents**.

The block producer chooses BLID, and through the transaction set it influences which TXIDs land in which block. `RANDOM` is therefore grindable by the producer, as the brief says.

---

## 1. Collusion and Sybil resistance in verification, oracle and juror games

### 1.1 SchellingCoin
- **Source:** [Buterin, "SchellingCoin: a minimal-trust universal data feed" (2014)](https://blog.ethereum.org/2014/03/28/schellingcoin-a-minimal-trust-universal-data-feed) (steer, a design blog by the author).
- **Mechanism:** Commit H(value, address) in one block and reveal in the next. Reveals are sorted, and ties are broken by a hash that includes the previous block hash.
- **Rule:** Reporters between the **25th and 75th percentile** are paid. Sybil resistance is assumed to come from outside the scheme (PoW or PoS).
- **Failure modes stated by the author:**
  - More than 50% of the weight sets the median to any value.
  - A ~49% coalition can probably win by pre-announcing a false value.
  - "Micro-cheating": reporters who use the feed nudge their answers, which can become self-fulfilling. The proposed mitigations are coarse rounding and a precise value definition.
- **DVM fit:** The arithmetic fits: sorting a small set is feasible, and commit-reveal uses `SHA3256`. The **Sybil premise does not**: with ring-2 signers, addresses are free to create, so each identity needs a bond or a fee.

### 1.2 P + ε attack (the main failure of minority-slashing games)
- **Source:** [Buterin, "The P + epsilon attack" (2015)](https://blog.ethereum.org/2015/01/28/p-epsilon-attack) (steer).
- **Rule:** The attacker promises P + ε to anyone who votes X, payable only if X loses. Voting X then becomes a dominant strategy. Everyone votes X, X wins, and the bribe is never paid, so the attack costs nothing.
- **Countermeasures the author lists:**
  - Delayed reward determination. The author calls this fragile, because corrupting thousands of rounds costs little more than corrupting one.
  - Contention-scaled deposits, after Sztorc's Truthcoin: near a 50/50 split the minority loses its whole deposit, so the bribe must exceed the deposit.
  - Counter-coordination with mixed strategies. The author concludes this fails.
- **Lesson:** Any game that pays "agree with the majority" can be captured by a credible conditional bribe. The bribe is credible here because a contract can escrow it.

### 1.3 Kleros
- **Primary sources FAILED:**
  - [kleros.io/whitepaper.pdf](https://kleros.io/whitepaper.pdf): 404
  - [kleros.io/yellowpaper.pdf](https://kleros.io/yellowpaper.pdf): 404
  - [kleros.io/whitepaper_long_en.pdf](https://kleros.io/whitepaper_long_en.pdf): 404
  - [docs.kleros.io dispute page](https://docs.kleros.io/products/court/what-happens-during-a-dispute): 404
  - [docs.kleros.io/kleros-faq](https://docs.kleros.io/kleros-faq): 404
  - [Kleros abridged, Medium](https://medium.com/kleros/kleros-a-decentralized-court-system-for-the-internet-abridged-1e415c04604a): 403
- **What the secondary sources say (search snippets only):**
  - Jurors are drawn with probability that increases with staked PNK.
  - Incoherent jurors (those outside the majority) lose tokens to coherent ones.
  - Each appeal uses a larger jury. A [Nethermind research note](https://nethermind.notion.site/Kleros-2-0-db8e3f72e44b483db1f4f760c2e29641) (steer) gives the rule **x(n+1) = 2·x(n) + 1**, "so new jurors always outnumber the old ones", and notes that fees rise exponentially with the number of appeals.
  - Kleros v2 contract docs at [kleros-v2-contracts.netlify.app](https://kleros-v2-contracts.netlify.app/src/arbitration/kleroscore.sol/contract.kleroscore) (doc, search snippet only) show per-appeal `tokensAtStakePerJuror` and a jury-size threshold above which the case moves to the parent court.
- **Failure modes:** Kleros is a Schelling game (§1.1), so it inherits P + ε and majority capture. Appeals raise the cost of capture: the attacker must win a jury of 2n+1 at every level. Appeals do not change the attack's structure.
- **DVM fit:**
  - Stake-weighted drawing works with `RANDOM`, but the producer can grind it (§1.8).
  - Commit-reveal works.
  - Appeals work as long as each round is a separate height window.

### 1.4 UMA optimistic oracle
- **Source:** [UMA docs, "How does UMA's oracle work"](https://docs.uma.xyz/protocol-overview/how-does-umas-oracle-work) (doc).
- **Mechanism:**
  - A proposer posts an answer with a bond. Each proposal can be disputed once, during a challenge window.
  - A correct disputer receives part of the proposer's forfeited bond.
  - An unchallenged answer settles.
  - Disputes go to a token vote (the "DVM", unrelated to DERO's DVM). It uses a 24 h commit phase and a 24 h reveal phase.
  - Resolution requires **at least 65%** of staked UMA on one outcome.
  - Non-voters and minority voters are slashed in favour of the majority.
  - The docs say **99.8%** of requests settle without escalation.
- **Security argument:** Unstaking takes one week. A 65% coalition voting against reality would crash the token during that week, so corruption costs the attackers money. The docs give no numeric comparison of cost against profit.
- **Failure modes:**
  - The final layer is again majority or Schelling, so §1.2 applies.
  - The security argument needs a token whose price falls when the oracle is corrupted. **A game contract on DERO has no such token.**
  - The optimistic layer depends on at least one watcher disputing within the window, and on that dispute not being censored.
- **DVM fit:** The bond, window and dispute logic fit well. The escalation layer is the weak part.

### 1.5 Truebit verification game and forced errors
- **Source:** [Teutsch and Reitwießner, "A scalable verification solution for blockchains", arXiv:1908.04756](https://arxiv.org/abs/1908.04756) (paper; full text read). The [original uchicago PDF](https://people.cs.uchicago.edu/~teutsch/papers/truebit.pdf) FAILED with a DNS error.
- **Verifier's dilemma:** If answers are always right, nobody checks. Truebit's fix (Idea 3 in the paper) is to "offer a bug bounty and provide expectation that bugs will exist".
- **Forced errors:**
  - A Solver is occasionally required to submit a wrong answer. Verifiers who catch it win a **jackpot**.
  - Rate: **"on average, once every thousand tasks."**
  - Maximum jackpot payout: **one third of the repository**.
  - The jackpot is funded by a **verification tax estimated at 500%–5000% of the task cost**.
- **Splitting among challengers:** With k challengers, each receives **J / 2^(k−1)** (scaled by difficulty), and "the total jackpot payoff decreases exponentially as the number of challenges increases". This is the Sybil defence: k identities from one person collect less in total.
- **Randomness:** Whether an error is forced is decided by H(Solver's committed private r ‖ hash of the block after the solution). The Solver commits hashes of both a correct and an incorrect solution before that block exists.
- **Deposits:** Deposits must exceed "the expected jackpot payout for a given task plus the cost of playing a verification game". The paper's example: with a 10 ETH deposit and a 1000 ETH jackpot, one person playing both Solver and Verifier nets about 990 ETH.
- **Dispute:** An interactive bisection over computation steps settles which single step is wrong. Any one honest Verifier suffices.
- **Failure modes:**
  - Jackpot draining by self-challenge, which the deposit sizing above defends against.
  - The tax burden.
  - The block-hash randomness can be biased by the miner.
  - Timeouts (stalling) can be used as an attack, which the paper calls "external, temporal pathologies".
- **DVM fit:**
  - Forced errors, commit-reveal and exponentially split jackpots are all expressible.
  - A bisection game is expressible only if the computation's single step can be re-executed in DVM-BASIC.
  - "Deterministically checkable from public data" is the setting where this works best.

### 1.6 Peer prediction and Bayesian Truth Serum (BTS)
- **Peer prediction source:** [Miller, Resnick and Zeckhauser, "Eliciting informative feedback: the peer-prediction method", Management Science 51(9) 2005](https://nmiller.web.illinois.edu/documents/research/elicit.pdf) (paper; full text read).
  - **Mechanism:** Each report is scored with a proper scoring rule against another rater's report.
  - **Result:** "There exist transfers under which truthful reporting is a strict Nash Equilibrium" (Proposition 1).
  - **Failure modes:** The authors say "raters could collude to gain higher transfers". Their remedies are to randomize the reference rater and pick it after reports are in, and to use statistical detection. Truth-telling is *an* equilibrium, not the only one.
- **BTS source:** Prelec, "A Bayesian truth serum for subjective data", Science 306:462 (2004), [DOI 10.1126/science.1102081](https://www.science.org/doi/10.1126/science.1102081). The full text was **not fetched (FAILED)**, so what follows comes from secondary snippets ([arXiv 1305.5170](https://arxiv.org/pdf/1305.5170), steer):
  - Score = information score (log of actual over predicted endorsement frequency) + prediction score (a KL penalty).
  - Truth-telling is a Bayesian Nash equilibrium for large populations.
- **DVM fit:** Both are designed for *subjective or unverifiable* signals. When the answer can be **checked deterministically**, they are the wrong tool, because a proof beats an equilibrium.

### 1.7 MACI (anti-bribery)
- **Source:** [Buterin, "Minimal anti-collusion infrastructure", ethresear.ch 5413](https://ethresear.ch/t/minimal-anti-collusion-infrastructure/5413) (steer, design proposal).
- **Mechanism:**
  - Votes are encrypted to an operator.
  - A user can secretly change keys, so no one can prove how they voted. Bribery becomes unenforceable.
  - The operator publishes a ZK-SNARK proof that the tally is correct.
- **Trust:** The operator is trusted for collusion resistance only.
- **Failure modes stated in the proposal:**
  - Keys sold into trusted hardware or a multisig.
  - Patient bribers.
  - Identity registration happens off-chain.
- **DVM fit: no.** The DVM has no SNARK verifier and no decryption.

### 1.8 Random committee selection and grinding (RANDAO bias)
- **RANDAO source:** [eth2book, "Randomness"](https://eth2book.info/capella/part2/building_blocks/randomness/) (doc).
  - The last revealer can publish or withhold, which is "one bit of influence".
  - With k tail slots, the attacker has 2^k choices.
  - Withholding costs the forfeited proposal.
  - Above roughly 0.5 stake share, the attacker's tail tends to grow, so takeover becomes plausible.
  - Mitigations: lookahead, and VDFs.
- **PoW beacon source:** [Bonneau, Clark and Goldfeder, "On Bitcoin as a public randomness source", ePrint 2015/1015](https://eprint.iacr.org/2015/1015) (paper, abstract-only).
  - At least **68 bits of min-entropy** per block, and **over 32 near-uniform bits** after extraction.
  - A one-bit lottery is safe only while the attacker's stake in the outcome is below **50 BTC** (about US$12k at the time).
  - The general principle: **a miner biases a block-hash beacon by discarding a block, so the bias costs one block reward**.
- **Prior use of the same pattern:**
  - SmartPool (§3.4) samples using future block hashes. It shows that with less than 50% hashpower, **two samples drawn from two consecutive blocks** suffice to pay fairly on average (Theorem 10).
  - Truebit (§1.5) combines a committed private secret with the next block hash.
- **DVM fit.** On DERO, `RANDOM = Keccak256(SCID, BLID, TXID)`. The producer of BLID can:
  - try other transaction sets, or other placements of a transaction;
  - drop the block, at the cost of its reward.

  The safe pattern is **commit first, then derive the randomness from a block after every commit has closed**. Keep the value at stake per draw below one block reward, or mix in a secret revealed later as Truebit does.

### 1.9 Slashing the minority vs. slashing provable faults
- **Provable-fault source:** [eth2book, "Slashing"](https://eth2book.info/capella/part2/incentives/slashing/) (doc).
  - The offences are equivocations, provable from **two signed messages**: double proposal, double vote and surround vote.
  - The initial penalty is **1/32** of effective balance.
  - The correlation penalty is **min(B, 3·S·B/T)**.
  - The includer receives **B/512**.
  - The specification provides a 7/8 whistleblower share, but it is unused.
- **The contrast:**
  - **Minority slashing** (Schelling, Kleros, UMA's final vote) punishes *disagreement*. A majority cartel, or a P + ε briber, turns it against honest voters.
  - **Fault slashing** punishes *evidence*. It holds against any majority, provided one honest party submits the evidence in time and is not censored.

### 1.10 Answer to topic 1 (DERIVED)
When the correct answer is **deterministically computable from public data**, collusion becomes unprofitable only in designs where correctness is decided by **checking, not voting**:

- (a) If the contract can compute the answer itself, compute it. There is nothing to collude on.
- (b) If computing it is too expensive, use a Truebit- or UMA-optimistic design: a bonded claim, an open challenge window, and a contract-side check of the disputed step. **Slash the provably wrong claim, never the minority.**

Under (b), a collusion of any size fails as long as **one** honest challenger exists and gets one transaction included inside the window. This works because:

- the challenger's payoff (part of the bond) exceeds its cost; and
- every colluder's bond is at risk from any single defector.

Voting games (Schelling, Kleros, minority-slash) do **not** make collusion unprofitable. Their security is bounded by majority control and by P + ε.

The residual risks under (b) are:

- **Censorship.** A producer controls only the blocks it produces, so the window must span many heights.
- **Challenger absence**, which forced errors address.
- **Sybil splitting of rewards**, which exponential splitting addresses.

---

## 2. Deflation by smart contract

### 2.1 EIP-1559 base-fee burn
- **Specification source:** [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) (doc).
  - Target gas = limit / **2** (the elasticity multiplier).
  - The base fee moves by `base · (used − target) / target / 8` per block.
  - The base fee is burned, "not given to anyone". The miner gets only the priority fee.
  - Stated rationale: if miners received the base fee they would have an incentive to manipulate it. Burning also removes MEV and inflation pressure.
  - Security considerations include an empty-block cartel, which the EIP calls unstable below 50% hashpower.
- **Analysis source:** [Roughgarden, "Transaction Fee Mechanism Design for the Ethereum Blockchain", arXiv:2012.00854](https://arxiv.org/abs/2012.00854) (paper; full text read).
  - The base fee "must be burned or otherwise withheld from the block's miner, as otherwise the miner could collude with users off-chain to costlessly simulate a first-price auction" (OCA-proofness).
  - Fee burning is "a lump-sum refund to ETH holders (à la stock buybacks)".
  - The paper notes the counterpoint that the burn **reduces miner revenue**, and that lower aggregate miner rewards should lower overall security.
  - The 1559 mechanism is MMIC and OCA-proof, and it is UIC except when demand spikes.

### 2.2 Provably unspendable addresses and proof-of-burn
- **Proof-of-burn source:** [Karantias, Kiayias and Zindros, "Proof-of-Burn", ePrint 2019/1096](https://eprint.iacr.org/2019/1096) (paper, abstract-only).
  - Defines three properties: **unspendability**, **binding** (metadata attached to the burn) and **uncensorability** (a burn address looks like a normal address).
  - Verification is by a short proof checked on a destination chain, demonstrated with an Ethereum contract.
- **Bitcoin practice source:** [Bitcoin wiki, "Proof of burn"](https://en.bitcoin.it/wiki/Proof_of_burn) (steer).
  - Funds go to an address derived from a script that always evaluates to false.
  - The burner later reveals the script so others can verify the burn.
  - Burns "must age" so a reorg cannot undo them.
- **DERO source:** [DERO docs (Token guide)](https://docs.dero.io/Developers/dvm) (doc) say that if no SCID is set in a transfer, the `burn` amount "will disappear/burn from network forever". The local code (local-code) confirms that `Payloads[].BurnValue` is a **public, serialized field** (`transaction/transaction.go:99`), bound into the proof (`blockchain/transaction_verify.go:439`), and shown by the explorer (`cmd/explorer/explorerlib/explorerlib.go:598`). For a contract call, the contract's deposit is that same field (`blockchain/transaction_execute.go:290`).

### 2.3 Lock vaults and buy-and-burn
- **Lock vault.** A contract that never calls `SEND_DERO_TO_ADDRESS`, or only calls it after height H, is a time-lock. Anyone can verify it by reading the contract code (code is public) and the contract's balance. No source was fetched specifically on buy-and-burn programmes, so **no claim is made about them** beyond the general economics in §2.4.

### 2.4 Economics (DERIVED from §2.1 sources)
- **Who pays:** The burner pays. The value is redistributed to every other holder as a supply cut, the same lump-sum refund Roughgarden describes.
- **Do miners gain?**
  - Miners gain **only the transaction fee** of the burning transaction, and that fee is paid whether or not anything is burned.
  - Burned coins go to nobody, so **burning by a voluntary game does not raise miner revenue**, except indirectly through the coin's price, and that applies equally to every holder.
  - Fee burning in EIP-1559 explicitly **reduces** miner revenue (Roughgarden).
  - A game that wants to pay the network must route value to miners directly, for example through a bounty or prize contract paid to miniblock producers (§3). Burning cannot do this.
- **Privacy-chain issues:**
  - In a confidential-amount chain, a burn is verifiable **only if the burned amount is public**. On DERO, `BurnValue` is public and the remaining balances are hidden, so a burn is visible per transaction.
  - Its soundness rests on the transaction's proof system. A proof-soundness defect could let a transaction claim a burn that was not fully debited. (Known DERO range-proof disclosure; no detail here.)
  - So a third party can verify a burn by summing `BurnValue` over transactions without an SCID. That sum is a *claimed* burn and is exactly as trustworthy as the proofs.

---

## 3. Fair reward sharing among many independent miners

### 3.1 Payout schemes
- **Source:** [Rosenfeld, "Analysis of Bitcoin Pooled Mining Reward Systems", arXiv:1112.4980](https://arxiv.org/abs/1112.4980) (paper; full text read).
- **Proportional:** The block is shared over the shares of the current round. This invites **pool hopping**: mining is profitable only until **0.4348·D** shares (about 43.5%) have been submitted in the round, after which hoppers leave.
- **PPS (pay per share):** The operator pays a fixed amount per share and carries all the variance, so this is where operator risk lies.
- **PPLNS:** Pay (1−f)·B/N to each of the last N shares. Expected payout per share is always (1−f)·p·B. "Unit-PPLNS" and the geometric method are **hopping-proof**: "Reward systems such as the geometric method and unit-PPLNS are fair, stable, transparent, and hopping-proof."
- **Block withholding:**
  - *Sabotage:* never submit a found block. Under PPLNS everyone receives (1−f)·(1−h/H)·p·B per share. Under PPS the operator receives (f − h/H)·p·B, and can go bankrupt.
  - *Lie in wait:* delay a found block and redirect hashpower to the pool that found it. This is profitable.
  - **Fix proposed:** "pop quiz" (imprecise), or **oblivious shares**, a protocol change in which a miner cannot tell whether its share is a block.
- **Miner's dilemma source:** [Eyal, "The Miner's Dilemma", arXiv:1411.7099](https://arxiv.org/abs/1411.7099) (paper, abstract-only). "No-pool-attacks is not a Nash equilibrium". Pools attacking each other by withholding is an iterated prisoner's dilemma.

### 3.2 P2Pool
- **Source:** [Bitcoin wiki, "P2Pool"](https://en.bitcoin.it/wiki/P2Pool) (steer).
- **Mechanism:**
  - A sharechain with **one share every 30 s**.
  - PPLNS over shares worth **3× the block work, or 8640 shares**, whichever is smaller.
  - Each share's coinbase pays the window directly, so there is no operator custody.
  - **0.5%** goes to the block finder and **99.5%** is split by recent work.
- **Problems:** DOA and orphan shares, a high share difficulty that hurts small miners, and dust payouts.

### 3.3 SmartPool
- **Source:** [Luu et al., "SmartPool", USENIX Security 2017](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-luu.pdf) (paper; full text read).
- **Mechanism:**
  - A miner commits a batch of shares in an **augmented Merkle tree** with strictly increasing counters, so duplicates show up as sorting errors.
  - The contract samples k paths.
  - A cheater is paid **nothing** if caught. A claim of 1000 shares with 500 real has an expected payout of 0.5·1000 = 500, the same as honest.
  - Sampling uses future block hashes. "**if an adversary controls less than 50%** of Ethereum hash power, … it suffices to sample only two paths … based on two consecutive blocks" (Theorem 10).
- **Results:** Deployed on Ethereum and Ethereum Classic: **105 blocks**, peak **30 GH/s**, fees about **0.6%** of block rewards (abstract).

### 3.4 Mapping onto on-chain attestation of DERO miniblocks (DERIVED)
- **What is needed:** SmartPool's precondition is that the contract can verify a share's PoW and its binding to the pool's payout key. **The DVM cannot verify either.** It has no AstroBWT primitive and no header or miniblock accessor (local-code function list).
- **The workaround:** A contract can still run a **SmartPool-shaped claim-and-sample game with an optimistic check**:
  1. A miner commits a Merkle root (counted with `SHA3256`) of the miniblock IDs it claims, plus a bond.
  2. After the commit window, `RANDOM` derived from a *later* block picks indices.
  3. The miner reveals those leaves.
  4. Anyone may dispute a revealed leaf within the window, by pointing out that the miniblock ID does not exist or is not credited to that miner's key in the public chain.
  5. Because the contract cannot check the dispute itself, settlement falls back to Truebit- or UMA-style rules (§1.4–1.5): a bonded counter-claim, then escalation.
- **Weakest link:** Without a native header check, the whole scheme is only as strong as its dispute layer.
- **Withholding:** It is irrelevant for DERO solo miniblocks, because each miner is credited on-chain by the protocol itself. A contract only redistributes rewards already earned. Pool-style withholding returns only if the contract pays for *shares* (sub-target work) that it cannot see.
- **Hopping:** Use a PPLNS-style window measured in heights, not in rounds.

---

## 4. Stake-weighted rewards without plutocracy

### 4.1 Mechanisms
- **Quadratic funding** ([Buterin, Hitzig and Weyl, arXiv:1809.06421](https://arxiv.org/abs/1809.06421), paper, abstract-only; and [Buterin, "Quadratic Payments: A Primer"](https://vitalik.eth.limo/general/2019/12/07/quadratic.html), steer):
  - Funding is **(Σ √cᵢ)²**.
  - With unlimited identities it "collapses into linear vote-buying".
  - Votes must be unprovable, or vote-selling also collapses it to linear.
  - The identity system need only be strong enough that manipulation is not worth its cost.
- **On collusion** ([Buterin, "On Collusion"](https://vitalik.eth.limo/general/2019/04/03/collusion.html), steer):
  - Identity-free coin voting "cannot avoid over-empowering centralized plutocrats".
  - Superlinear reward curves "subsidize plutocracy".
  - The author asks for identity "that you cannot credibly rent or sell".
- **Conviction voting** ([Commons Stack / 1Hive math, via search snippet](https://gitcoin.co/mechanisms/conviction-voting), steer; [BlockScience notebook](https://nbviewer.org/github/BlockScience/Aragon_Conviction_Voting/blob/master/models/v3/Trigger_Function_Explanation.ipynb), steer):
  - Conviction is y(t) = a^t·y(0) + x·(1 − a^t)/(1 − a), with decay α ∈ (0,1). That is the recurrence y_t = α·y_{t−1} + x_t.
  - It weights *time-locked* stake. It is **linear in x**, so it adds no Sybil incentive. It rewards duration, not dispersion.

### 4.2 The splitting condition (DERIVED)
Assume the following setup:

- An identity with stake s receives weight w(s), with w(0) = 0.
- The reward is R·w(sᵢ)/Σⱼ w(sⱼ).
- Splitting s into k identities of s/k each costs c per extra identity, in reward units.

The gain from splitting, when the split is small relative to the pool, is approximately:

> **Δ(k) = k·w(s/k) − w(s) − (k−1)·c′**

Here c′ is c expressed in weight units, i.e. c·Σw/R.

- **No identity cost (c = 0):** Splitting gains nothing for every k exactly when k·w(s/k) ≤ w(s), which means w is **superadditive** on the stake's range. With w(0) = 0:
  - every concave w is subadditive, so splitting **weakly gains**;
  - every strictly concave w strictly gains;
  - linear w is the only concave weight that is split-neutral.
- **Example, w = √s:** Splitting gives k·√(s/k) = √k·√s, so k identities multiply weight by √k.
- **With an identity cost:** Splitting gains nothing iff
  > **c′ ≥ max over k ≥ 2 of [k·w(s/k) − w(s)] / (k−1)**

  For w = √s, the k = 2 case requires c′ ≥ (√2 − 1)·√s ≈ 0.414·√s. The cost of an identity must **grow with √s**. A flat bond deters small holders, not large ones.
- **Caps:** A cap C gives w = min(s, C). Anyone above C splits into ⌈s/C⌉ identities and recovers linear weight. A cap only binds when identity is costly.
- **What counts as a real identity cost:**
  - A refundable bond costs only its time-value. On DERO that is near zero, because there is no lending market, so a returned bond gives c ≈ 0.
  - Only **non-refundable** costs count: a fee paid to the pot or to miners, a burn, or work.
- **PoW identity:** Weighting by **attested hashpower or miniblocks** is linear in work. Splitting hashpower across keys creates no extra work, so it is split-neutral by construction.

---

## 5. Peer-level attacks on PoW chains

### 5.1 The attacks
- **Selfish mining** ([Eyal and Sirer, "Majority is not Enough", arXiv:1311.0243](https://arxiv.org/abs/1311.0243), paper; full text read):
  - Profitable for **(1−γ)/(3−2γ) < α < 1/2**, where γ is the share of honest miners that mine on the attacker's block in a tie.
  - With γ = 1 the threshold is 0. With γ = 0 it is **1/3**.
  - The fix is **uniform random tie-breaking**, which sets γ = 1/2 and threshold **1/4**.
- **Eclipse attacks** ([Heilman et al., USENIX Security 2015](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-heilman.pdf), paper; full text read; the [ePrint 2015/263](https://eprint.iacr.org/2015/263.pdf) copy FAILED with 403):
  - Attacker resources:
    - **32 distinct /24 blocks (8192 IPs)**, or **4600 bots**, eclipse a victim with **≥ 85%** probability, regardless of network size;
    - **400 bots** sufficed on live nodes.
  - Consequences: N-confirmation double-spends, selfish-mining amplification and adversarial forks.
  - Countermeasures:
    - test-before-evict, feeler connections and anchor connections;
    - more buckets;
    - countermeasures 1, 2 and 6 shipped in bitcoind v0.10.1.
- **Routing / partition attacks** ([Apostolaki, Zohar and Vanbever, "Hijacking Bitcoin", arXiv:1605.07524](https://arxiv.org/abs/1605.07524), paper; abstract and introduction read):
  - Hijacking **fewer than 100 BGP prefixes** isolates about **50%** of mining power.
  - On-path attackers can delay blocks.
  - Result: wasted hashpower and double-spends.
- **Timejacking** ([culubas, "Timejacking & Bitcoin" (2011)](https://culubas.blogspot.com/2011/05/timejacking-bitcoin_802.html), steer):
  - Network time is the median of peer times, capped at **70 min** from system time. Blocks more than **2 h** in the future are rejected.
  - An attacker skews a victim's clock and splits it off with a block 190 minutes ahead.
  - The proposed full fix is median chain time.

### 5.2 What is measurable from outside
- **Measurable:**
  - Orphan or uncle rate.
  - Reorg depth.
  - Block-interval and timestamp distributions.
  - Runs of consecutive blocks from one miner.
  - Propagation delay. The 2013 Bitcoin median was **6.5 s** and the mean 12.6 s, per [Fechner et al. 2022](https://balakrishnanc.github.io/papers/fechner-ict.open2022.pdf) (paper) citing [Decker and Wattenhofer, IEEE P2P 2013](https://cdecker.github.io/btcresearch/2013/decker2013propagation.html) (paper, not fetched beyond metadata).
- **Statistical tests:**
  - [Li, Campajola and Tessone, Scientific Reports 2024](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC10943236/) (paper, abstract-only) give a statistical test of per-miner block sequences and report the first empirical evidence of selfish behaviour.
  - [arXiv:2309.06847](https://arxiv.org/pdf/2309.06847.pdf) (paper, abstract-only) proposes a selfish-mining strategy designed to be statistically **undetectable**.
  - [Hacking Distributed, "How to detect selfish miners"](https://hackingdistributed.com/2014/01/15/detecting-selfish-mining) (steer): orphan counts are hard because pruned blocks are lost.
- **Conclusion:** Tests can raise suspicion. They are not a proof of an attack.

### 5.3 Fraud proofs and watchtowers
- **Fraud proofs** ([Al-Bassam, Sonnino and Buterin, arXiv:1809.09044](https://arxiv.org/abs/1809.09044), paper, abstract-only): A full node sends a light client a proof that a block breaks the rules. This replaces the honest-majority assumption with "a minimum number of honest nodes" that rebroadcast data.
- **Pisa** ([McCorry et al., ePrint 2018/582](https://eprint.iacr.org/2018/582), paper, abstract-only):
  - A custodian (watchtower) acts for offline parties.
  - Per the search snippet of [the authors' slides](https://www.cs.cornell.edu/%7eiddo/pisa.pdf) (steer), the custodian's security deposit is forfeited on evidence of cheating.
  - [Brick, arXiv:1905.11360](https://arxiv.org/pdf/1905.11360) (paper, snippet only) notes that collateral double-assigned across channels makes Pisa bribable.
  - The [hackingdistributed Pisa post](https://hackingdistributed.com/2018/05/22/pisa) FAILED (connection refused).

### 5.4 What a contract can and cannot do (DERIVED)
- **It cannot:**
  - observe the p2p layer, peers, latency or orphans;
  - read other blocks, so it cannot check reorg depth or orphan rate on-chain;
  - verify PoW;
  - verify a signature.

  So **it cannot judge an eclipse, partition or timejack**. It also cannot even prove that a reorg happened. The contract's own state is rolled back with the reorg.
- **It can:**
  - pay a bounty for evidence that is **self-certifying in-contract**: a hash preimage, or a contradiction between two of its *own* stored records, for example the same reporter committing two different answers for one height (equivocation inside the contract, like Ethereum's double vote);
  - run a bonded optimistic claim ("block X at height h was replaced") that others may dispute. This again inherits §1.4 and §1.10.
- **Watchtower bounties:** These work when the evidence is checkable in-contract. Otherwise they become a voting game.

---

## 6. Detecting supply inflation in a confidential-amount chain

### 6.1 Zcash 2019 counterfeiting disclosure
- **Disclosure source:** [ECC / zodl.com, "Zcash Counterfeiting Vulnerability Successfully Remediated"](https://zodl.com/zcash-counterfeiting-vulnerability-successfully-remediated/) (doc, vendor disclosure). This was reached by redirect from electriccoin.co.
  - Discovered **2018-03-01**. Fixed by Sapling, activated **2018-10-28**. Disclosed **2019-02-05** (CVE-2019-7167).
  - Component: Sprout's **BCTV14** parameters (Groth16 Sapling was unaffected).
  - ECC found **no evidence** of counterfeiting. It monitored Sprout pool totals and searched for a chain footprint.
  - Its stated bound: "**As long as the value in the shielded pools are greater than zero, no counterfeiting has been detected.**"
- **Turnstile source:** [ZIP 209](https://zips.z.cash/zip-0209) (doc).
  - A block is invalid if any **chain value pool balance goes negative**, or if the total exceeds MAX_MONEY.
  - Pool balances are computed from *public* fields (vpub_old/new, valueBalance).
  - It catches counterfeit value only when that value **leaves the pool** in excess of what entered. Counterfeit value still inside a shielded pool is invisible.

### 6.2 Monero 2017 key-image bug
- **Disclosure source:** [getmonero.org disclosure, 2017-05-17](https://www.getmonero.org/2017/05/17/disclosure-of-a-major-bug-in-cryptonote-based-currencies.html) (doc).
  - Found **2017-02-19**. The chain was scanned on 2017-02-20 and **Monero had never been exploited**. A silent patch followed on 2017-02-21. A hash of the details was committed on-chain on 2017-03-15. Hard fork **2017-04-14**. Public disclosure **2017-05-17**.
  - Mitigation: reject key images that are not in the prime-order subgroup (the curve order times the key image must be the identity).
  - The page warns against Bytecoin, DashCoin and DigitalNote as unpatched at disclosure. **It does not describe any exploitation of Bytecoin**, so none is claimed here.
- **Supply check:**
  - Coinbase amounts are public. Hidden value is constrained by commitment-sum balance plus range proofs, plus key-image uniqueness against double-spends.
  - The [Monero CCS "inflation checker" (DangerousFreedom), completed 2022](https://ccs.getmonero.org/proposals/monero-inflation-checker.html) (doc) re-verifies ring signatures, amounts, key-image uniqueness and the emission curve from chain data, across the pre-RingCT, MLSAG and CLSAG eras.
  - [ePrint 2023/321](https://eprint.iacr.org/2023/321) (paper, snippet only) gives a full RingCT security analysis.

### 6.3 Grin / Mimblewimble
- **Source:** [grin_core `block_sums.rs`](https://docs.rs/crate/grin_core/5.4.0/source/src/core/block_sums.rs) (doc/code) and the [Grin forum thread on supply verification](https://forum.grin.mw/t/is-it-possible-to-verify-the-supply-of-grin-has-not-suffered-inflationary-bugs/8683) (steer).
- **Mechanism:**
  - Running sums of UTXO commitments and kernel excesses, with the kernel offset, must match the expected supply.
  - Every node verifies the whole-chain balance.
  - **This proves no inflation only under the soundness of the range proofs and the discrete-log assumption.**

### 6.4 What public data proves or bounds supply (DERIVED)
- **Proves:** Emission from public coinbase amounts, and transparent pool flows. A turnstile adds the guarantee that no pool goes negative.
- **Conditionally proves:** Totals of hidden amounts, via commitment sums. These hold only if the range-proof or ZK system is sound.
- **Bounds only:** The turnstile bounds counterfeit value from *below the visible flows*. Counterfeit coins that never leave a shielded or encrypted domain cannot be seen in public aggregates. This matches DERO's own R23 emission-audit finding that range-proof-class value is invisible.
- **Practical approach:** Re-verify every proof yourself (Monero CCS), and publish turnstile-style aggregates (ZIP 209).
- **What a DVM contract can do:** Little. It cannot read other transactions or the balance tree. It can hold its **own** escrow and expose an invariant, such as the sum of deposits minus payouts equalling its balance, that anyone can audit off-chain.

---

## Source counts

| Label | Count | Sources |
|---|---|---|
| **paper** | 22 | Truebit (arXiv 1908.04756); Roughgarden (arXiv 2012.00854); Rosenfeld (arXiv 1112.4980); Eyal Miner's Dilemma (arXiv 1411.7099); Eyal–Sirer (arXiv 1311.0243); Heilman (USENIX'15); Apostolaki (arXiv 1605.07524); SmartPool (USENIX'17); Miller–Resnick–Zeckhauser (2005); Prelec BTS (Science 2004, metadata only); arXiv 1305.5170 (BTS secondary); Bonneau et al. (ePrint 2015/1015); Proof-of-Burn (ePrint 2019/1096); Buterin–Hitzig–Weyl (arXiv 1809.06421); Al-Bassam et al. (arXiv 1809.09044); Pisa (ePrint 2018/582); Brick (arXiv 1905.11360); Li–Campajola–Tessone (Sci. Rep. 2024); arXiv 2309.06847; Fechner et al. 2022; Decker–Wattenhofer 2013 (metadata); ePrint 2023/321 (snippet) |
| **doc** | 11 | UMA docs; EIP-1559; eth2book randomness; eth2book slashing; ZIP 209; ECC/zodl Zcash disclosure; Monero 2017 disclosure; Monero CCS inflation checker; DERO DVM docs; Kleros v2 contract docs (snippet); grin_core block_sums |
| **steer** | 13 | SchellingCoin blog; P+ε blog; MACI ethresear.ch; On Collusion; Quadratic primer; Nethermind Kleros note; conviction-voting snippets (Gitcoin page, BlockScience notebook); Bitcoin wiki P2Pool; Bitcoin wiki Proof of burn; timejacking blog; Hacking Distributed selfish-mining detection; Pisa slides snippet; Grin forum thread |
| **local-code** | 4 | `dvm/dvm_functions.go`, `dvm/deterministic_random_number.go`, `transaction/transaction.go`, `blockchain/transaction_execute.go` (with `transaction_verify.go` and the explorer as corroboration) |
| **FAILED** | 10 | kleros.io whitepaper.pdf, yellowpaper.pdf and whitepaper_long_en.pdf (404); docs.kleros.io dispute page and FAQ (404); Kleros Medium (403); people.cs.uchicago.edu Truebit PDF (DNS; the arXiv copy was used instead); ePrint 2015/263 (403; the USENIX copy was used instead); hackingdistributed Pisa post (connection refused); Prelec Science full text (not retrieved) |

---

## Implications for a DVM contract suite

Each rule is falsifiable: it names an observable condition that would show the rule is violated or wrong.

1. **Check, don't vote.** If an answer can be computed from public data, the contract settles it by checking: computing it directly, or checking the single disputed step. It never settles by majority. *Falsified if* any suite contract pays or slashes based on agreement with other reporters for a deterministically checkable question. (§1.2, §1.9, §1.10)

2. **Slash the provably wrong claim, never the minority.** Bonds are forfeited only on in-contract evidence: a preimage mismatch, an equivocation between two of the contract's own records, or a lost bisection step. *Falsified if* an honest reporter can lose its bond while its answer was correct. (§1.9)

3. **One honest challenger must suffice, and must be paid.** The challenge reward (a share of the forfeited bond) must exceed the challenger's transaction cost plus the bond the challenger posts. The bond must exceed the claimant's maximum gain from a false claim. *Falsified if* a measured false claim goes unchallenged while its expected profit is positive. (§1.4, §1.5)

4. **Challenge windows are measured in heights and span many producers.** The window must be at least W blocks, with W large enough that no single producer controls every block in it. Short windows invite censorship. *Falsified if* the share of a window's blocks produced by one miner key (from chain data) can reach 100%. (§1.10, §5)

5. **Keep checkers awake with forced errors.** Inject known-wrong claims at a fixed rate, Truebit's 1/1000 or tuned to the challenger population. Fund them from a tax, and split the jackpot as J/2^(k−1) among k challengers so Sybil splitting does not pay. *Falsified if* the measured catch rate of injected errors falls below the declared target, or k identities collect more than 1 identity. (§1.5)

6. **Never let RANDOM decide value above one block reward per draw, and only derive it after commits close.** RANDOM is Keccak(SCID, BLID, TXID), and the producer can grind it. Commit everything first, use a later block, and add a secret revealed later where stakes are high. *Falsified if* a recorded draw shows a producer-linked winner rate statistically above its fair share, or a stake per draw exceeds one block reward. (§1.8)

7. **Weights are linear unless identity has a non-refundable cost.** Concave weights (√, caps) gain from Sybil splitting by a factor of √k under √. Use them only with a per-identity fee or burn c′ ≥ (√2 − 1)·√s at the target stake s. A refundable bond does not count. *Falsified if* splitting a test stake across 2 addresses raises its total reward share. (§4.2)

8. **Weight miners by attested work, not by addresses.** Miniblocks or hashpower are linear in work and split-neutral. Use a height-window, PPLNS-style rule (hopping-proof) rather than per-round proportional shares. *Falsified if* a miner gains by joining only early in a round or by spreading the same hashpower across keys. (§3.1, §4.2)

9. **Treat a mined-miniblock claim as an optimistic claim, not a verified fact.** The DVM cannot check AstroBWT, headers or signatures. Use SmartPool-style commit, sampling (k ≥ 2 samples from consecutive later blocks), revealed leaves and a dispute window. A caught over-claim pays zero and forfeits the bond. *Falsified if* an over-claim of fraction γ earns more than (1−γ) of an honest claim in expectation, measured over test runs. (§3.3, §3.4)

10. **Burning does not pay miners. Say so, and route network value explicitly.** A burn (public `BurnValue`, no SCID) is a supply cut paid by the burner. Miners receive only the fee. A game meant to pay the network must transfer to miniblock producers. *Falsified if* the miners' measured per-block income rises with game burns and without any game transfers to them. (§2.4)

11. **Expect burns and supply claims to be only as sound as the proofs.** Report a burn as "claimed `BurnValue` sum (proof-conditional)". Report supply like a turnstile: no negative pools, formula emission, plus independent proof re-verification. *Falsified if* a published supply or burn figure is stated without its proof-soundness condition. (§2.4, §6.4)

12. **Contracts do not judge peer-layer attacks.** Eclipse, partition, timejacking, selfish mining and reorgs are invisible in-contract (a reorg also rolls back the contract). Any bounty for them must be an optimistic claim with off-chain evidence and a dispute layer, or must stay off-chain. *Falsified if* a suite contract pays out an "attack detected" claim that depends on data it cannot read. (§5.4)

13. **Every escrow exposes an auditable invariant.** Deposits − payouts − burns = contract balance at every height, checkable off-chain from public `DEROVALUE` and sends. *Falsified if* replaying the contract's transactions does not reproduce its balance. (§6.4)

14. **Expect collusion with no token to crash.** UMA's security argument depends on the corrupted token's price falling. Game contracts have no such token, so the bond is the only cost of corruption. Size it against the full prize, not against expected participation. *Falsified if* any game's total prize exceeds the sum of bonds a colluding coalition would forfeit. (§1.4)
