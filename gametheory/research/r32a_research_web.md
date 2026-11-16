# R32a web research: SC games for miner incentives and network security (DERO HE)

Date: 2026-11-15. Method: web search and fetch only, with no probes against local ports. Nothing was downloaded to disk.
Tags: [paper] peer-reviewed or preprint, [docs] official documentation or spec, [code] source code, [forum] mailing list, forum or social post, [blog] project, vendor or press blog.
- "SPECULATION" marks our own inference, not a sourced claim.
- "snippet-only" means the claim was seen in a search-result summary and the page was not opened in full.
- "not found" means we searched and found no source.

Fetch failures:
- wiki.dero.io and forum.dero.io refused connections (ECONNREFUSED) on 2026-11-15. DERO wiki and forum claims below are therefore snippet-only.
- docs.dero.io and raw.githubusercontent.com (deroproject/derohe) fetched fine.

Content constraint honoured: there is no exploit content for range-proof or inner-product soundness defects. Q4 covers defensive monitoring only.

---

## 0. DERO ground truth that bounds every design (Q6 first, because it constrains Q1–Q5)

### 0.1 Reward split [code]
Source: https://raw.githubusercontent.com/deroproject/derohe/main/blockchain/transaction_execute.go, function `process_miner_transaction`.
- `full_reward := base_reward + fees`, where `base_reward = CalcBlockReward(height)`.
- `share := full_reward / uint64(len(bl.MiniBlocks))`. The reward is split equally per miniblock.
- `leftover := full_reward - share*len(MiniBlocks)`.
- The integrator (`tx.MinerAddress`) gets `share + leftover`.
- Each non-Final miniblock is credited `share` to the key found by `balance_tree.GetKeyValueFromHash(mbl.KeyHash[:16])`.
- The main path has no dev-fee split.
- Consequence: the payout is linear in accepted miniblocks. The protocol is already a sybil-neutral "pay per accepted share" scheme at the consensus layer, and the only nonlinearity is the integrator's remainder. Our R32 note (reward 30,750 per block, integrator takes the final share) matches this code.

### 0.2 Miniblock header [code]
Source: https://raw.githubusercontent.com/deroproject/derohe/main/block/miniblock.go
- The header is 48 bytes: Version, HighDiff, Final, PastCount, a 16-bit rolling Timestamp, a 5-byte Height, `Past [2]uint32` (the DAG), `KeyHash` (16 bytes, "trimmed miniblock miner keyhash"), `Flags uint32` ("can be used as flags by special miners to represent something, also used as nonce"), and `Nonce [3]uint32`.
- Implication: miner identity is public off-chain in every miniblock as a 16-byte key hash. The `Flags` field is a miner-controlled 32-bit channel.
- SPECULATION: a miner could put a game commitment tag (for example a truncated hash of a game-registration ID) in Flags. That would bind a miniblock to an off-chain claim at zero consensus cost. It would also burn 32 bits of nonce space, which is negligible because the comment cites 2^96 nonce variations.

### 0.3 Sigma (Σ) mining [docs]
Source: https://wiki.dero.io/wiki/index.php/Miniblock (snippet-only).
- Each block has 9 miniblocks plus a 10th integrator miniblock with 9x difficulty.
- Normal block time is 18 s.
- Miniblocks "represent traditional mining shares when mining in a pool."
- The wiki page refers to Stargate and may be dated. Its "integrator gets the rewards" wording is superseded by the code in 0.1.

### 0.4 DVM primitives [docs]
Source: https://docs.dero.io/Developers/dvm
- `SIGNER()`: "Ringsize of tx must be 2 for this value to be known or else empty". ComputeCost 5000.
- `RANDOM()`: "PRNG seeded on BLID,SCID,TXID". ComputeCost 2500. The docs give no predictability warning, and the docs' lottery example uses `RANDOM() % deposit_count`.
- `BLOCK_HEIGHT`, `BLOCK_TIMESTAMP`, `BLID`, `TXID`, `DEROVALUE`, `ASSETVALUE`, `SEND_DERO_TO_ADDRESS` (ComputeCost 70000).
- Any error discards all state changes. Return 0 commits.
- The docs have no primitive that exposes another block's header, its miniblock KeyHashes, the orphan status of a miniblock, or peer data.
- The doc is internally inconsistent: SEND_DERO_TO_ADDRESS asks for "raw form" in one place and "string DERO/DETO form" in another.

### 0.5 Emission
- [blog/docs] https://dero.io: "block reward halves every 4 years", "18 Second Blocktime", "Fully Auditable Supply".
- [forum] https://forum.dero.io/t/dero-blockchain-emission/102 (snippet-only, early-era post): "Total DERO 18.4 Million in 8 years", tail emission of about 157,680 per year. This may be outdated, so take authoritative values from `CalcBlockReward` in the derohe code.
- 0.6 DERO per block and a 21 M cap: not found.

### 0.6 Orphan rates [forum]
Community node dashboards report a "Network Orphan Miniblock Rate" (snippet-only, undated snapshots):
- 4.49%: https://dero-node-orionure-us.mysrv.cloud
- 4.12%: https://dero.rabidmining.com
- 3.57%: https://dero-node.mysrv.cloud

Our own R23b orphan figure was 2.7%. The order of magnitude agrees, and these are not official statistics.

### 0.7 Ecosystem [code/blog]
- dReams (Go, Fyne): https://github.com/dReam-dApps/dReams
- Engram wallet with Gnomon indexer: https://awesome.ecosyste.ms/projects/github.com%2Fderofdn%2Fengram
- TELA on-chain app storage (snippet-only, third-party summary).
- dDice: https://github.com/SixofClubsss/dDice. This is a DERO dice dApp and worth reading for how it handles RANDOM grinding (not opened).
- Homomorphic assets are described on https://wiki.dero.io/wiki/index.php/Dero_Project (snippet-only), with unclear current status.
- DERO token standard document: not found.
- DERO community proposals on miner-incentive SCs: not found.

### 0.7a The 2026-10-20 range-proof disclosure
- A web search for a public DERO Foundation advisory returned nothing (not found on the open web as of 2026-11-15).
- Our local memory file records the disclosure. Cite it from our own artifacts, not the web.

### 0.8 Hard constraints (given in the brief, consistent with 0.1–0.4)
- An SC cannot change consensus or the reward.
- An SC cannot see who mined a block.
- SIGNER() is known only at ringsize 2.
- Every "proof of mining" therefore has to come from an off-chain observation of public headers, brought on-chain by a claim plus a dispute game, or by an oracle or arbiter set.

---

## 1. Proof-of-hashrate, loyalty boosts and pool payout game theory (Q1)

### 1.1 Pool reward functions
- Rosenfeld, "Analysis of Bitcoin Pooled Mining Reward Systems" (2011) [paper], https://arxiv.org/abs/1112.4980. Proportional payouts are vulnerable to pool-hopping. PPLNS and score-based schemes resist it. It includes a "hopping immunity" theorem (snippet-only for the theorem statement).
- Schrijvers, Bonneau, Boneh, Roughgarden, "Incentive Compatibility of Bitcoin Mining Pool Reward Functions" (FC 2016) [paper], https://www.timroughgarden.org/papers/bitcoin.pdf. Proportional payouts are not incentive compatible when miners can delay share reports. PPLNS is incentive compatible in a more general model. The authors propose a new IC reward function.
- Mapping to DERO: the consensus payout (0.1) is PPS-like per accepted miniblock with no window, so it has no hopping surface. A game layered on top should keep that property.
  - SPECULATION: a bonus that is linear in miniblocks accepted inside a fixed window (PPLNS-style, window of N blocks) is hop-resistant.
  - A bonus keyed to "first miniblock after a quiet period" or to a streak creates timing games, as in Rosenfeld's proportional-pool hopping.

### 1.2 Block withholding and the miner's dilemma
- Eyal, "The Miner's Dilemma" (IEEE S&P 2015) [paper], https://arxiv.org/abs/1411.7099. Pools infiltrating each other and withholding full solutions is a tragedy of the commons, and no-attack is not a Nash equilibrium.
- APoW: Auditable PoW against block withholding (2026 preprint) [paper], https://arxiv.org/pdf/2601.02496. It lets miners later prove which nonce regions they searched. It notes that ZK proofs of hashing are "prohibitive" (snippet-only).
- Mapping: a DERO game that pays for shares submitted to a game-operated endpoint, instead of miniblocks accepted on chain, recreates the withholding attack surface.
  - SPECULATION: pay only for on-chain accepted miniblocks (KeyHash in a canonical block). These are unforgeable, cost real work, and cannot be withheld profitably, because a withheld miniblock earns nothing.

### 1.3 Decentralised pools
- Monero P2Pool [docs]:
  - https://web.getmonero.org/resources/moneropedia/p2pool.html
  - https://getmonero.org/2021/10/05/p2pool-released.html
- How it works: a merge-mined sidechain with PPLNS over about 2160 shares (about 6 h), paid directly in the coinbase. Uncle shares are paid at about 80% weight to soften orphaning on the fast sharechain. Sources disagree on the exact weight, so check the SChernykh/p2pool README.
- Mapping: DERO's Σ-mining already is a protocol-native P2Pool, because miniblocks are shares paid by consensus. A P2Pool-like SC adds little.
- What P2Pool teaches is the uncle-share rule: compensating orphaned shares reduces variance from latency. Section 5.2 covers the selfish-mining cost of doing that.

### 1.4 Stratum V2 Job Declaration
- [docs] https://stratumprotocol.org/features and https://en.bitcoin.it/wiki/Stratum_V2
- [blog] https://bitcoinmagazine.com/bitcoin-mining/bitcoin-mining-pool-dmnd-mines (first Job Declaration block 955,318; vendor-sourced)
- Mechanism: miners build templates with their own node. The pool-side Job Declarator Server validates them.
- Mapping to DERO integrator capture: whoever runs the getwork node chooses the integrator address and the tx set.
  - SPECULATION: the DERO analogue of SV2 Job Declaration is "miners run their own derod and integrate their own blocks", and that needs no SC.
  - A game can reward it only indirectly: pay a bonus to integrator addresses that are distinct from the top-K integrators, observed off-chain. That needs an oracle (see 3.x).

### 1.5 Hashrate attestation without a pool
- No deployed, trust-minimised external proof of hashrate was found (search above). One vendor pitch exists: https://www.chainscorelabs.com/services/bitcoin-and-lightning/bitcoin-mining-software-and-pool-development/verifiable-hashrate-proof-systems [blog, unverified].
- "Hashrate bonds" as an academic mechanism: not found.
- On DERO the accepted miniblock is the attestation (0.2). It is public, priced in real work, and bound to a key hash.

### 1.6 Which incentive shapes are sybil-proof and not Ponzi-shaped
All points in this subsection are SPECULATION, derived from 1.1–1.5 and 3.1.
- Linear in verified work (bonus = k × accepted miniblocks of registered keys in window W):
  - Splitting a miner into many identities cannot change the payout, so it is split-invariant (sybil-neutral).
  - Merging identities cannot change it either, so it adds no centralisation pressure.
  - It is the only shape with both properties.
- Superlinear shapes (same-address streak boosts, "loyalty multipliers", top-miner prizes) reward consolidation and push toward fewer, larger miners. That is the opposite of the security goal and the same direction as selfish-mining profitability, which grows with size (Eyal and Sirer, §5.1).
- Sublinear or capped-per-identity shapes (equal per-registered-miner stipends) reward splitting: a direct sybil incentive.
- Not Ponzi: the bonus is funded only by an external sponsor deposit or by game fees that pay for a service (for example the lottery in §2), never by later entrants' deposits. Solvency is checkable on chain: SC balance ≥ outstanding liabilities. There is no promised return.
- Reward-to-cost bound: any bonus is a subsidy. Hashrate attracted ≈ bonus / (marginal cost per hash). Rational miners respond to (block reward + bonus) per unit work, and the effect lasts only while the sponsor pays. Kroll, Davey and Felten (WEIS 2013) [paper], https://econinfosec.org/archive/weis2013/papers/KrollDaveyFeltenWEIS2013.pdf, model miners as rational and argue that long-run stability needs governance, not just payoffs.

---

## 2. Lotteries, prize-linked savings and on-chain randomness (Q2)

### 2.1 Prize-linked savings
- PoolTogether: deposit principal is kept, yield funds prizes, winner picked via Chainlink VRF [docs/blog].
  - https://v3.docs.pooltogether.com/v3.3.0/protocol/overview
  - https://chain.link/case-studies/pooltogether
  - https://medium.com/pooltogether/using-chainlink-vrf-for-randomness-generation-in-pooltogether-619a4280a7ae
- The "provably fair" claims are the project's own framing.
- Kearney and Tufano academic PLS paper: not found by our search. We do not cite it.
- Mapping to DERO: there is no yield source on DERO L1. SPECULATION: the prize must come from a sponsor or from a ticket margin, which makes it a straight lottery rather than PLS. A "no-loss" claim is only valid if the prize is sponsor-funded and principal is returned.

### 2.2 Commit-reveal and last-revealer bias
- RANDAO last-revealer attack: the last participant can withhold a reveal to choose between two outcomes [paper]. https://arxiv.org/abs/2403.09541 proposes a Shamir-secret-sharing RANDAO as a preliminary fix.
- Commit-Reveal², randomising the reveal order [paper]: https://arxiv.org/html/2504.03936v2. It notes that VDF-based fixes are impractical for gas and ASIC reasons.
- VDFs: Boneh, Bonneau, Bünz, Fisch (CRYPTO 2018) [paper], https://eprint.iacr.org/2018/601.
  - Chia uses class-group VDFs [paper/blog, snippet-only].
  - Ethereum deprioritised VDFs (snippet-only, https://a16zcrypto.com/public-randomness-and-randomness-beacons).
- Standard mitigation (SPECULATION, from the LRA literature): each commit carries a bond B, forfeited on non-reveal. Withholding is unprofitable when B ≥ (prize gain from a re-roll) and the reveal deadline is enforced by BLOCK_HEIGHT.

### 2.3 DERO RANDOM() grinding
- Fact [docs]: RANDOM is seeded on BLID, SCID and TXID (0.4). BLID depends on the block's miniblocks and the integrator.
- SPECULATION, attack surface stated defensively:
  - The party that integrates the block containing the draw tx can, in principle, discard a block whose BLID gives a losing draw. That costs at least the forgone block reward (about one full_reward per discard, since the integrator holds share + leftover and the other miniblocks are lost too).
  - The prize per draw must therefore be well below the block reward. A safe rule is prize < full_reward / 10. Choosing that value is our assumption, not sourced.
  - The tx sender also controls TXID. A sender can vary its tx until RANDOM favours it, but only if the outcome is computable before inclusion. That is true if BLID is the only unknown and the sender is also the integrator.
- Mitigation pattern for DERO (SPECULATION):
  - Draw = H(all player reveals ‖ RANDOM() in a later block), using a two-phase SC with commit (bonded) and then reveal before height H+k.
  - Finalisation by a third tx after H+k mixes in an unpredictable BLID.
  - Prize cap well below the block reward.
- The dDice repo is a reference to inspect for prior art (not opened).

---

## 3. Economic games for network security (Q3)

### 3.1 Node and propagation incentives: the sybil wall
- Babaioff, Dobzinski, Oren, Zohar, "On Bitcoin and Red Balloons" (EC'12) [paper], https://arxiv.org/abs/1111.2626.
  - Bitcoin gives nodes an incentive not to relay.
  - Their sybil-proof propagation reward works under iterated dominance.
  - Impossibility result: no scheme makes propagation plus no self-cloning a dominant strategy.
- Bitcoin dev list, "Proof of Nodework" (2017) [forum], https://mirror.b10c.me/lists/bitcoindev/ (bitcoindev list archive; the message id is withheld because it embeds an e-mail address) Nodes register with a deposit and are challenged by peers. Critics asked who checks the checkers.
- A 2014 reply on the same list says node rewards face the same sybil problem PoW was invented to solve (same archive, snippet-only).
- Bitcoin still has no direct node reward [blog], https://www.spark.money/research/bitcoin-node-incentive-problem-analysis.
- Mapping: a DVM SC cannot observe reachability. SPECULATION: any "proof of node uptime" game that pays per node is sybil-attackable unless identity is costly. On DERO the only costly identities are stake (a bond) and accepted miniblocks (work).
  - Reachability attestations made by our own wallets about our own nodes are self-dealing by construction, so they measure nothing about the network.

### 3.2 Proof of coverage and relay proofs, and how they failed
- Helium PoC [docs/blog]:
  - HIP 58 caps witness distance at 100 km because of falsified beacon and witness distance: https://github.com/helium/HIP/blob/main/0058-poc-distance-limit.md (via dependabot mirror).
  - Spoofing and clustering were persistent problems; the defences were hardware keys, witnesses and denylists: https://solana.com/news/case-study-helium-technical-guide.
  - We deliberately do not cite the how-to spoofing guide.
- Pocket Network Shannon [docs]:
  - https://docs.pocket.network/protocol/sessions-claims-proofs/
  - https://docs.pocket.network/building-on-the-pocket-network/welcome-to-pokt-roll/protocol-specifications/protocol-primitives/probabilistic-proofs-shannon
  - Mechanism: claim (an SMST root) then a probabilistically required proof. A missing proof forfeits the session's reward. Above a threshold a proof is always required.
- Lesson: physical or network-level attestations get gamed whenever the attester and the attestee can collude. The robust designs (a) pay against a cryptographic commitment checked later at random, and (b) forfeit the whole payment on a missed proof.
  - SPECULATION, mapping: claim-then-random-audit maps well to "claim N accepted miniblocks in window W". The audit is an off-chain check of public headers, posted as a challenge.

### 3.3 Alerting and watchtower bounties
- Chainlink Staking v0.2 [blog], https://blog.chain.link/chainlink-staking-v0-2-overview:
  - If the ETH/USD feed is down for more than 3 h, the first valid alerter earns 7,000 LINK.
  - Node operators get a 20-minute priority window.
  - Operators are slashed 700 LINK each (snippet-consistent across several sources; one table claiming 100% slashing conflicts and is treated as unreliable).
- Lightning watchtowers: not searched in depth (not found in this pass).
- Mapping (SPECULATION): an "alert bounty" for objectively verifiable events is the cleanest pattern. The event must be verifiable by the SC itself, or the alerter must post a bond. Examples:
  - On-chain-checkable: the SC balance invariant breaks; no draw is finalised by height H.
  - Off-chain public: a specific canonical block's coinbase ≠ formula. An SC cannot check this, so it needs a dispute game.

### 3.4 Verification games and their failure modes
- Truebit [paper]: https://people.cs.uchicago.edu/teutsch/papers/truebit.pdf and https://arxiv.org/abs/1908.04756.
  - The verification game bisects the disputed computation.
  - The verifier's dilemma: rational verifiers skip costly checks when cheating is rare.
  - The fix is forced errors (randomly injected wrong answers that pay a jackpot when caught), so verifying stays worth it.
- Kleros and SchellingCoin:
  - p+ε attack: the attacker promises to pay voters p+ε if they vote Y and Y loses. That costs almost nothing if it works [blog]: https://blog.ethereum.org/2015/01/28/p-epsilon-attack and https://blog.ethereum.org/2015/02/14/subjectivity-exploitability-tradeoff.
  - Kleros ran p+ε attacks on its Doges on Trial pilot (dispute IDs 70–76). Far fewer than half of jurors took the bribe, and appeals helped [blog]: https://blog.kleros.io/cryptoeconomic-deep-dive-doges-on-trial. This is the project's own analysis.
- Augur [docs]: https://augur.gitbook.io/help-center/disputing-explained
  - The dispute bond doubles each round.
  - A bond of at least 2.5% of REP supply forks the whole universe (the threshold differs across sources and versions).
  - A crowd-sourced April 2026 "Moon Fork" test was reported by secondary sources (unverified).
- Failure modes to design against: bribery (p+ε), juror collusion, the lazy-copying verifier's dilemma, and griefing by cheap challenges. Their standard counters:
  - Bribery: appeals that escalate the bond.
  - Collusion: random juror selection.
  - Lazy copying: forced errors.
  - Griefing: challenger bonds that pay the other side's costs.
- Mapping (SPECULATION): with 3–5 own wallets there is no independent juror pool. Any juror or Schelling game we run is a self-dealing simulation of incentives, not security. The honest on-chain version is an optimistic claim with a bond and a challenge window, resolved by a published, deterministic off-chain check plus an arbiter key (a single or multisig arbiter, trusted and disclosed). This is a trusted oracle, so label it as one.

### 3.5 Bribery contracts: the same tool cuts both ways
- Liao and Katz, whale transactions (FC 2017) [paper]: https://www.cs.umd.edu/~jkatz/papers/whale-txs.pdf.
- McCorry, Hicks, Meiklejohn, smart-contract bribery (Bitcoin'18) [paper]: https://SMeiklej.com/files/bitcoin18a.pdf.
- Judmayer et al., Pay-to-Win cross-chain bribing, about an order of magnitude cheaper than whale attacks (FC 2021 workshops) [paper]: https://eprints.cs.univie.ac.at/7102.
- Bribe & Fork, a feather-fork threat as a bribe (AFT 2024) [paper]: https://arxiv.org/abs/2402.01363.
- Feather forking, which originated on BitcoinTalk [blog]: https://blockchain-academy.hs-mittweida.de/courses/game-theory-blockchain/lessons/attacks-on-proof-of-work-pow/topic/feather-forking.
- Mapping:
  - The fact that a DVM SC cannot see miners (0.4) also blocks naive on-DERO bribery contracts.
  - Pay-to-Win shows attackers can fund bribes on another chain, for example an Ethereum contract with an oracle of DERO headers. DERO's SC limits are no defence against that.
  - SPECULATION: a defensive side-payment ("honest-chain bonus") is a bribe for honesty. It only works while it exceeds the attacker's bribe, which makes it a bidding war the defender funds indefinitely.
- Kroll, Davey and Felten's "Goldfinger" attacker, who profits from the coin's collapse rather than its rewards [paper], https://econinfosec.org/archive/weis2013/papers/KrollDaveyFeltenWEIS2013.pdf. Such an attacker cannot be outbid by in-coin rewards.

---

## 4. Supply integrity for confidential-amount chains (Q4, defensive only)

### 4.1 Zcash turnstile, ZIP 209 [docs]
- Source: https://gitea.interbiznw.com/zec/zips/src/branch/main/zip-0209.rst (mirror of zips.z.cash). Final; Bowe and Hopwood.
- Nodes MUST reject a block that makes the Sprout, Sapling or Orchard chain value pool balance negative.
- Deployed in zcashd v2.0.5 on mainnet. The Orchard part applies from NU5.
- Zebra implementation RFC: https://zebra.zfnd.org/dev/rfcs/0012-value-pools.html.
- ECC rationale: https://electriccoin.co/blog/turnstile-enforcement-against-counterfeiting.
- 2026 Orchard counterfeiting-class bug:
  - Found by Taylor Hornby in a Shielded Labs-commissioned audit, according to press reports.
  - NU6.2 fixed the bug. NU6.3 "Ironwood" proposes migrating through the turnstile to bound supply.
  - Activation status was conflicting in our sources [blog]: https://blog.blockstream.com/what-the-zcash-orchard-bug-reveals-about-verifiable-supply/ and https://thedefiant.io/news/blockchains/shielded-labs-proposes-new-zcash-upgrade-to-prove-zec-supply-after-orchard-bug.
- Key lesson: a turnstile only bounds a pool against transparent value that is publicly accounted. A fix does not prove past supply was never inflated.

### 4.2 Monero [docs/blog]
- 2017 CryptoNote key-image bug disclosure: https://getmonero.org/2017/05/17/disclosure-of-a-major-bug-in-cryptonote-based-currencies.html. The chain was scanned for past exploitation and was clean.
- Supply-auditability post: https://getmonero.org/2020/01/17/auditability.html. With opaque amounts, implementation flaws "can produce undetectable inflation". Audits reduce the risk but cannot eliminate it.

### 4.3 Grin and Mimblewimble [docs/forum]
- Running utxo_sum and kernel_sum per block in code: https://docs.rs/crate/grin_core/5.4.0/source/src/core/block_sums.rs.
- The forum notes that the supply check assumes range-proof (Bulletproof) soundness and bug-free verification: https://forum.grin.mw/t/is-it-possible-to-verify-the-supply-of-grin-has-not-suffered-inflationary-bugs/8683.
- Nenza recursive-proof proposal (forum only): https://forum.grin.mw/t/nenza-verifiable-non-interactive-mimblewimble/12456.

### 4.4 Mapping to DERO (SPECULATION, consistent with our R23 emission auditor memo)
- DERO's coinbase is formula-computed (0.1).
- What an auditor can verify:
  - Every block's reward = CalcBlockReward + fees, split per 0.1.
  - Any balance-tree change is explained by published commitments, the formula coinbase and SC payouts.
- What it cannot verify: value created inside a proof whose soundness is broken. That is the same limit Monero and Grin state.
- DERO has no ZIP-209 analogue at consensus, because all balances are encrypted and there is no transparent pool. SPECULATION, to verify in code: SC-held DERO balances are public. A partial turnstile is therefore possible for value entering and leaving SCs, an "SC-pool turnstile" monitor, but it is off-chain and non-consensus.

### 4.5 Bounty for independent auditors: options
- Deterministic results kill Schelling games. Every honest auditor computes the same digest, so the cheapest strategy is to copy someone else's digest. This is Truebit's verifier's dilemma (3.4).
- Counter: forced errors. The sponsor occasionally posts a deliberately wrong checkpoint digest, bonded and committed in advance via H(salt‖flag). Whoever proves it wrong with the correct digest wins the jackpot, and copy-cats who endorsed it lose their bond. SPECULATION adapted from Truebit.
- Payment is for reproducible artifacts (digest of height range plus the auditor's commitment), not for "no anomaly" votes.
- Anomaly bounty: pay a large, rare amount for a reproducible discrepancy between the formula coinbase and the chain. It is resolved by the published auditor recipe plus a disclosed arbiter.
  - Constraint: the bounty must never request or reward an exploit demonstration for the range-proof defect. Monitoring of balance-tree deltas only.
- Not measurable with only our own wallets: whether outsiders actually audit. With only us, the auditor population is us.

---

## 5. Selfish mining, orphans and integrator capture (Q5)

### 5.1 Selfish mining
- Eyal and Sirer, "Majority is not Enough" [paper]: https://arxiv.org/abs/1311.0243 and https://www.cs.cornell.edu/~ie53/publications/btcProcFC.pdf.
  - A selfish pool's revenue grows superlinearly above a threshold.
  - The threshold depends on propagation (γ).
  - Their fix makes the threshold 1/4.
- Gal and Szabo, counterstrategy and "piggyback" (2023) [paper]: https://arxiv.org/abs/2304.06313.

### 5.2 Uncle and orphan rewards
- GHOST: Sompolinsky and Zohar (FC 2015) [paper], https://cris.huji.ac.il/en/publications/secure-high-rate-transaction-processing-in-bitcoin/. A GHOST variant was used by Ethereum.
- Ritz and Zugenmaier [paper], https://arxiv.org/abs/1805.08832. Ethereum's partial uncle rewards lowered the selfish-mining profitability threshold from 0.25 to about 0.185 (at the Dec 2017 uncle ratio), because uncles reduce the withholder's downside.
- Grunspan and Pérez-Marco [paper], https://arxiv.org/abs/1904.13330 ("Selfish Mining in Ethereum"; authorship not confirmed in snippets). They describe a weak reward for signalling uncles.
- Niu and Feng [paper], https://arxiv.org/abs/1901.04620. The threshold is below Bitcoin's 25%.
- Critical implication (SPECULATION derived from Ritz and Zugenmaier): an SC "orphan insurance" that pays for orphaned DERO miniblocks subsidises the withholder's downside and may lower DERO's selfish-mining threshold.
  - Any orphan compensation must pay less than the canonical share.
  - It should pay only for orphans whose timestamp lies after the canonical sibling. Even so, the SC cannot check this; an oracle must.
  - Alternatively, it should pay only on evidence of propagation delay, which is unverifiable.
  - Recommended: do not insure orphans. Reward low latency instead, via our existing p2p work. Orphans at 2.7–4.5% (0.6) are a latency problem.

### 5.3 Integrator and template capture
- The integrator chooses which miniblocks are included (0.1) and receives the leftover.
- SV2 Job Declaration (1.4) is the Bitcoin answer: decentralise template building.
- SPECULATION: a side-payment cannot force inclusion, but it can reward integrator-address diversity. Example: pay a bonus to blocks whose integrator is a registered small miner, verified off-chain by KeyHash or MinerAddress.
  - Risk: large miners register many integrator identities, which is sybil. This is the 1.6 problem again.
  - Counter: make the bonus linear in work (miniblocks) rather than per identity.
- Conclusion (SPECULATION, consistent with the literature): side-payments without consensus change can shift marginal incentives. They cannot remove the structural selfish-mining advantage, and an adversary with external funding can outbid them (3.5). The durable levers are consensus and network-level: propagation latency (γ) and the miniblock DAG rules.

---

## 6. Synthesis: which game families survive DERO's constraints

| Family | SC-verifiable? | Sybil-safe shape | Main failure | Verdict |
|---|---|---|---|---|
| Linear miniblock bonus (oracle-attested) | No; off-chain headers plus arbiter | Linear in miniblocks (1.6) | Trusted arbiter; sponsor-funded only | Viable, label as trusted oracle |
| Superlinear loyalty or streak | No | Not sybil-safe; centralising | Consolidation, selfish-mining alignment | Reject |
| Per-node uptime stipend | No | Not sybil-safe (3.1) | Self-attestation | Reject on mainnet |
| Orphan insurance | No | n/a | Lowers selfish-mining threshold (5.2) | Reject |
| Commit-reveal lottery with bonds | Yes, fully in DVM | Bond per ticket | Last revealer if bond < prize; RANDOM grinding (2.3) | Viable, prize cap below block reward |
| SC-solvency alert bounty | Yes (SC balance vs ledger) | Bonded alerter | Griefing | Viable |
| Emission audit bounty with forced errors | Partly (commit-reveal on chain, check off-chain) | Bonded endorsements | Verifier's dilemma, collusion | Viable as pilot; trust disclosed |

---

## Design implications for a 3–5 wallet mainnet game

Shared premises:
- Wallets W1..W5 are ours.
- Miner key K is ours (memory: Studio miner plus a LAN node).
- Any number that requires outside participants or network-wide hashrate is marked NOT MEASURABLE with own wallets.
- Pre-flight on sim or testnet only. The result must be on mainnet, per R32 D-GT-5.

### A. Measurable with own wallets (falsifiable)

H1. The DVM can bind an on-chain claim to our miniblocks.
- Test: deploy SC_CLAIM. W1 at ringsize 2 (SIGNER known) registers key hash prefix KH = KeyHash[:16] of K. The SC stores KH.
- Then submit claims "block heights h1..hn contain miniblocks with KH" during a challenge window of N blocks.
- Pass: every claim is reproducible from public headers by the auditor script (0 mismatches over at least 50 claims), and the SC pays exactly k × n.
- Falsified if any claim is accepted that the header check rejects. That would mean the arbiter path is broken.

H2. A linear bonus is split-invariant.
- Test: register K's work under one identity vs. split across W1..W3 (needs separate miner keys or alternating runs).
- Pass: total bonus per accepted miniblock stays within ±1 integer-rounding atom.
- Falsified if splitting changes the payout. That would mean a hidden nonlinearity in the SC.
- Note: this tests SC arithmetic, not miner behaviour.

H3. The commit-reveal lottery resists last-revealer withholding when bond ≥ prize.
- Test: 4 wallets commit H(salt‖choice) with bond B; one wallet deliberately does not reveal.
- Pass: the SC forfeits B to the pot, finalises after H+k with no reveal, and the outcome uses all reveals plus a post-deadline RANDOM.
- Measure: gas (ComputeCost) per phase and blocks to finality.
- Falsified if a non-revealer ever recovers B, or if finalisation is possible before H+k.

H4. RANDOM() is predictable to the tx sender before inclusion.
- Test: off-chain, compute the candidate seed for a pending tx. BLID is unknown until inclusion, so the prediction should fail.
- Pass (unpredictable to sender): over at least 100 draws, the predicted outcome matches at no better than chance (binomial test p > 0.05).
- Do NOT test integrator-side grinding by discarding blocks on mainnet. That forfeits reward and is an attack pattern. Analyse it on paper only (2.3).

H5. Our orphan share is a latency function, not a game parameter.
- Test: measure our own miniblock orphan rate from header data while the game runs vs. a baseline window.
- Pass (null expected): no change beyond ±1 pp. A change would indicate a confound such as node load from SC polling.
- This guards against the game hurting our own propagation.

H6. SC solvency is continuously verifiable.
- Test: an alert entrypoint pays a bonded alerter if SC balance < recorded liabilities. Inject a mis-accounted liability on testnet only.
- Mainnet pass: the invariant holds at every block across the run, logged from public SC state.
- Falsified on any violation.

H7. Forced-error audit catches a copy-cat.
- Test: W1 (sponsor) commits H(salt‖is_wrong) and posts a digest for range [a, b].
  - W2 is the honest auditor and recomputes the digest.
  - W3 is the copy-cat and endorses without computing.
  - After the reveal, W2 is paid the jackpot when the digest was wrong, and W3's bond is slashed.
- Pass: the payout matrix matches the spec in 10/10 rounds, with 2–3 forced errors among them.
- This measures mechanism correctness only, not real auditor diligence.

H8. Cost of the game in our own hashrate.
- Test: CPU and RSS used by the claim and audit tooling while the miner runs.
- Pass: miner H/s within the measured noise band, about ±1% of 96 kH/s (memory R30).
- Falsified if the tooling costs more than 1%.

### B. NOT measurable with own wallets (state as untestable here; do not claim)

N1. Network hashrate response to a bonus.
- Needs outside miners. Our own hashrate is fixed by hardware (memory: about 96 kH/s ceiling).
- Any change in network hashrate during the run is confounded by price, difficulty and other miners.
- At most we can publish the bonus and observe a correlation, with no causal claim.

N2. Sybil resistance against real adversaries.
- With 3–5 own wallets we can only test arithmetic invariance (H2), not adversarial behaviour.

N3. Bribery or p+ε resistance of any juror or Schelling game.
- There is no independent juror population. Kleros-style evidence (3.4) needs many external jurors.

N4. Selfish-mining threshold effects of any side-payment (5.2).
- These need a model or simulation plus many miners. On mainnet with our hashrate share (small) the effect is unobservable.
- Analyse with the Ritz and Zugenmaier or Eyal and Sirer models instead.

N5. Integrator diversity effects (5.3).
- Needs other miners to choose to run their own integrators.

N6. Node reachability or "honest full node" population.
- Self-attestation is meaningless (3.1). Network-wide counts need crawler data, which is a separate dimension. Any live probe must be announced first, per user feedback.

N7. Whether outside auditors would actually audit emission for a bounty (4.5).

N8. Long-run sustainability.
- Subsidy-driven hashrate leaves when the subsidy ends (1.6, Kroll et al.). This is unmeasurable in a short run.

### C. Design rules carried forward (SPECULATION, sourced as noted)
1. Pay linearly per accepted miniblock. Never per identity, never superlinearly (1.1, 1.6, 3.1).
2. Never insure orphans (5.2).
3. Cap any RANDOM-based prize below the block reward. Use bonded commit-reveal plus a post-deadline RANDOM (2.2, 2.3).
4. Every off-chain fact enters via bonded claim → challenge window → disclosed arbiter. Label it a trusted oracle in the UI (3.4).
5. Use forced errors for any audit bounty (3.4, 4.5).
6. Funding comes from a sponsor deposit only, with on-chain solvency invariant H6. No yield promises (1.6, 2.1).
7. No exploit content or exploit demonstration for the range-proof disclosure. Monitor balance-tree deltas only (4.4).
8. Fetch gaps to close next round: the DERO wiki Miniblock page, forum post /t/102, the dDice source, and `CalcBlockReward` in the derohe code.
