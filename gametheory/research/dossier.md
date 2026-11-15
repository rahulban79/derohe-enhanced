# R32 research dossier: grounding a game-theory / smart-contract incentive design for DERO HE

Accessed 2026-11-15. Numbers in [n] point to `sources.json` in this folder.
Evidence classes: **doc** (official docs, whitepaper, repo README), **paper** (peer-reviewed or arXiv/ePrint/NBER), **steer** (forums, blogs, community pages, aggregators). Steers only raise questions. They never count as evidence.
Every DERO protocol claim below is a *doc claim*. Anything about consensus, rewards or DVM semantics stays "to be checked in code" until the code-analysis agent confirms it.

---

## (A) DERO HE design: homomorphic encrypted balances and anonymity sets

| # | Claim | Class | Src |
|---|---|---|---|
| A1 | DERO HE uses a "homomorphic account based model". Homomorphic encryption is "used to to do operations such as addition/substraction to settle balances" with the data always encrypted. | doc | [1][2] |
| A2 | Sender and receiver anonymity comes from "Many-Out-Of-Many Proofs using Bulletproofs and Sigma Protocol". The README says nobody except sender and receiver "will know the real parties of the transaction". | doc | [2] |
| A3 | Ring (anonymity-set) sizes must be powers of 2, and tx size grows logarithmically: ring 2 = 1553 B, ring 4 = 2013 B, about 2.5 KB at ring 8. DHEBP gives 3117 B at ring 8 and 71,613 B at ring 512, with a "Proof which grows log in ring members". | doc | [2][5] |
| A4 | Design lineage. Zether keeps "account balances encrypted" inside a smart contract and has explicit front-running and replay defences. Anonymous Zether / many-out-of-many proofs grow "only logarithmically in the size of the anonymity sets", with about 3 KB transactions. That matches DERO's ring-8 size. | paper | [14][15] |
| A5 | **ElGamal is not named on any official DERO page I fetched** (README, docs home, DHEBP). The ElGamal link rests on the Zether lineage and on steers [53] (fetch failed). Status: open; check in the crypto code. | doc (absence) / steer | [1][2][5][53] |
| A6 | DERO describes its scheme as "Homomorphic". DHEBP calls it "FHE blockchain transactions". A third-party rating says it is additively homomorphic, not fully homomorphic, but that fetch failed [54]. The operations the docs describe are only addition and subtraction [2]. Read "HE" as additive. | doc + steer | [2][5][54] |
| A7 | State is stored in Graviton, a "versioned, authenticated" key-value store where "every write is tracked, versioned and authenticated with cryptographic proofs". | doc | [12] |
| A8 | Anonymity-set lesson from Monero: about 62% of inputs with one or more mixins were traceable by "chain-reaction" analysis, and decoys were distinguishable by age. Ring membership selection matters as much as ring size. | paper | [16] |

## (B) DVM and DVM-BASIC

| # | Claim | Class | Src |
|---|---|---|---|
| B1 | DVM-BASIC is "a contract-oriented, high-level language", line-numbered and BASIC-style. It has only `uint64` and `string` types, and every variable must be declared ("initialized to default values namely 0 and \"\""). | doc | [4] |
| B2 | A function is externally invocable iff its first letter is upper case ("can be invoked by blockchain and other smart-contracts"). `Initialize` / `InitializePrivate` run at install time. The token example stores `owner` = `SIGNER()`. | doc | [4][7] |
| B3 | Builtins (doc wording): SIGNER "Returns address of who signed this transaction". BLOCK_HEIGHT "current chain height of BLID()". BLID "current BLOCK ID which contains current execution-in-progress TXID". TXID. DEROVALUE / ASSETVALUE "amount ... sent within this transaction". SEND_DERO_TO_ADDRESS / SEND_ASSET_TO_ADDRESS send from the SC balance to a raw address. STORE / LOAD / EXISTS / DELETE persist state. MAPSTORE / MAPGET / MAPEXISTS / MAPDELETE are RAM-only for "current invoke session". UPDATE_SC_CODE "Stores updated SC code". | doc | [4] |
| B4 | **RANDOM**: "RANDOM returns a random using a PRNG seeded on BLID,SCID,TXID". The official lottery picks `winner = RANDOM() % deposit_count` and pays out with SEND_DERO_TO_ADDRESS. The seed includes the block ID, so a block producer can influence it (see B8, G5). | doc | [4] |
| B5 | Gas model as documented: each builtin has a ComputeCost and a StorageCost. Examples: STORE 10000, LOAD 5000, RANDOM 2500, SEND_DERO_TO_ADDRESS 70000, UPDATE_SC_CODE 5000. Every StorageCost is listed as 0. The page never uses the words "gas" or "fee". Whether and how these costs are charged is a code question. | doc | [4] |
| B6 | Token/asset model: README lists "Homomorphic Assets programmable Smart Contracts with fixed overhead per asset". The token example issues 400 tokens and balances are queried by SCID. DVM docs warn that a burn "is equal to deposit if SCID is defined else DERO/token will dissappear/burn from network forever" (a native proof-of-burn path; see F7). | doc | [1][4][7] |
| B7 | Upgradability: "SCs can now update themselves. however, new code will only run on next invocation". The official token example has an owner-only `UpdateCode`. Any game SC with a live UPDATE_SC_CODE path is owner-trusted. | doc | [8][7] |
| B8 | Official examples: lottery ("give lottery wins every xth try", RANDOM-based), private token, and nameservice ("register names which could be looked by wallets"). The `dvm/` tree has `deterministic_random_number.go` and a `simulator.go` ("DVM simulator to test all edge cases for SC dev"). | doc | [4][8][11] |

## (C) AstroBWT proof of work (v3) and CPU-friendliness

| # | Claim | Class | Src |
|---|---|---|---|
| C1 | The official AstroBWT doc page describes **v1**: SHA3-256, a Salsa20 expansion to 69371 B, BWT, SHA3-256, a second Salsa20 expansion and BWT, then a final SHA3-256. It does not mention v3. | doc | [6] |
| C2 | v3 is in `astrobwt/astrobwtv3` (rc4.go, random_code_gen.go, sais.go, sa_fast.go, optimized_sort.go, suffixarray.go). The directory has no README. Release96 is titled "POW bugfix in AstroBWTv3". | doc | [10][9] |
| C3 | A third-party v3 port describes the pipeline as: sha256, then Salsa20 expand, RC4, FNV-1a, a "branchy loop using RC4 stream encryption", a suffix-array build and sort, and a final sha256. Not official. Check against `pow.go`. | doc (3rd-party) | [13] |
| C4 | DERO's resistance claim (v1 page): "ASIC/FPGA/GPU resistant", and "all known implementations to this date, could not deliver an improvement even twice that of CPUs". It also says it is "based on mathematical proofs and research". No proof document was found. | doc | [6][3] |
| C5 | The same third-party port lists "offloading sorting to GPUs" of the suffix array as a performance opportunity. That is a steer against taking GPU resistance as settled. (Our own project measurements show the miner GPU co-binds with the CPU. They are outside this dossier's evidence set.) | doc (3rd-party) | [13] |
| C6 | Aggregators list DERO under "AstroBWTv3" with a 40 kH/s at 100 W benchmark. | steer | [45] |

## (D) DAG / miniblock design (all doc claims, to be checked in code)

| # | Claim | Class | Src |
|---|---|---|---|
| D1 | Block time conflicts between sources. README: "16 Second Block time". docs.dero.io: "18 Second Blocktime". An aggregator shows 18.56 s. *Doc claim, to be checked in code.* | doc + steer | [1][2][3][45] |
| D2 | "Each block has 10 mini blocks to rewards up to 10 differents miners at the same time for each block", and "No more mining pools needed, with a daily ~54000 mini blocks". The older "DAG/MINIDAG with 1 miniblock every second" line is struck through: "This as been replaced by a mini block system". Arithmetic: 54,000/day × 16 s = 10 per block. At 18 s the same rule gives 48,000/day, a figure community pages also quote. *Doc claim, to be checked in code.* | doc | [1][2] |
| D3 | docs.dero.io describes "Σ-blocks (Sigma blocks)" emitted about every second that converge into the main block. It says "each daemon essentially functions as it's own mining pool" and "The daemon itself will retain a fixed fee of 1.6% for the daemon operator". *Doc claim, to be checked in code.* The 1.6% figure is the documented integrator / operator share. | doc | [3] |
| D4 | Final miniblock / integrator: no official page names an "integrator" or the final-miniblock rule. A community node page says "1 out of 10 blocks mined is called an Integrator block", paid to the node operator (fetch failed, search snippet only). *Steer only; check in code.* | steer | [46] |
| D5 | Orphans: docs.dero.io lists "No Orphan Blocks" and "No Soft Forks/Chain Splits". Whether miniblocks or blocks can be side, stale or orphaned, and how they are paid, is not documented. *Doc claim, to be checked in code.* (Project history has measured orphans, which contradicts the slogan. That is not in this evidence set.) | doc | [3] |
| D6 | Emission: "Max supply:21 Million", block reward "Halving every 4 years". The aggregator's 0.31 DERO per block is consistent with one halving of an earlier ~0.615 figure, but that inference is unverified. *Doc claim, to be checked in code.* | doc + steer | [3][45] |
| D7 | Hard fork 3: "Release 152: Hard Fork 3 activates at block 7,504,640." | doc | [9] |

## (E) Game theory of mining incentives

| # | Claim | Class | Src |
|---|---|---|---|
| E1 | Selfish mining: "colluding miners obtain a revenue larger than their fair share". The proposed fix only protects against pools with "less than 1/4 of the resources". | paper | [17] |
| E2 | Optimal selfish mining (MDP) gives tighter profit thresholds. With communication delays, even small miners may profit from occasional deviation. | paper | [18] |
| E3 | Fee-only regime: high reward variance makes it "attractive to fork a wealthy block". The undercutting attack forks the chain head and leaves fees unclaimed to attract followers. Selfish mining becomes profitable "for a miner with an arbitrarily low hash power share". | paper | [19] |
| E4 | Budish: the recurring payment to miners must be large relative to the one-time value of an attack. This sets "intrinsic economic limits to how economically important it can become". | paper | [20] |
| E5 | Pool hopping: proportional pools are exploitable, and "Any additional reward obtained by hoppers must be at the expense of continuous miners". Score-based and PPLNS-class methods can be "proven to be immune to pool-hopping". | paper | [25] |
| E6 | Block withholding between pools is "an instance of the iterative prisoner's dilemma". | paper | [26] |
| E7 | Side-block rewards cut both ways. GHOST-style inclusion allows more than one block per second [21]. Ethereum uncles "reduce the risk for a selfish miner to gain no rewards from withholding" [24]. DAG protocols order concurrent blocks without discarding them: Conflux [23], PHANTOM/GHOSTDAG's k-cluster [22]. | paper | [21][22][23][24] |
| E8 | MEV / fee auctions: "high fees paid for priority transaction ordering poses a systemic risk to consensus-layer security". Fee-mechanism design (EIP-1559, burned base fee, OCA-proofness) is the formal frame for this. | paper | [41][27] |

## (F) Mechanism design for on-chain games

| # | Claim | Class | Src |
|---|---|---|---|
| F1 | Commit-reveal Schelling oracle: commit a hash in one block, reveal in the next, and reward values between the 25th and 75th percentile. It breaks under majority collusion ("a 49% coalition will likely be able to break SchellingCoin"). | steer (primary blog) | [28] |
| F2 | P+ε attack: a credible bribe makes the false vote dominant "at zero cost". Any pure-Schelling payoff needs defences beyond majority matching. | steer (primary blog) | [29] |
| F3 | Defences in deployed designs. Kleros jurors stake, and "incoherent jurors ... pay part of their stake to coherent ones"; votes are committed as hash(vote, salt, address). Augur uses "progressively-larger Reputation bonds" and forks as a last resort. | doc + paper | [31][30] |
| F4 | Slashing must be evidence-based. Casper slashes "the validator's entire deposit" when violation evidence is submitted, with a finder's fee. Accountable safety holds when "≥1/3" would be slashed. | paper | [32] |
| F5 | Auctions. Myerson gives revenue-optimal auctions for a seller facing private values. Sealed-bid auctions on a public chain need commitments; one verifiable design leaks "no information about the losing bids". | paper | [33][34] |
| F6 | Prize-linked savings pay "periodic sizeable payments to some investors using a lottery-like drawing" in place of interest. The prize needs an external yield source, otherwise the product is a lottery. Quadratic funding is "first best" only under the standard model, and its variants are needed to "protect against collusion" (sybil resistance assumed). | paper | [35][36] |
| F7 | Proof-of-burn needs "Unspendability" and "binding" metadata. DERO's DVM has a documented burn path (B6). | paper + doc | [37][4] |
| F8 | Liquidity mining: governance-token rewards pull TVL, and it leaves when the rewards stop. Uniswap's TVL "plummeted by $1.29 billion" on the day its mining program ended. LP behaviour was "not clear" before systematic study. | paper | [38][44] |
| F9 | Ponzi on Ethereum: 184 schemes in four shapes: tree, chain, waterfall, handover. In tree schemes "the only one who is guaranteed to have profit is the owner". Handover schemes double the entry toll for each new investor. Code-based detectors can be evaded by "obfuscating the opcode", while transaction-based lifetime features are more robust. Chen et al. (WWW 2018) use account plus opcode features (search result only). | paper | [39][40] |

## (G) Privacy and MEV

| # | Claim | Class | Src |
|---|---|---|---|
| G1 | Front-running comes in three templates: displacement, insertion, suppression. Confidentiality of the function name and arguments is the property that matters most. Commit-and-reveal gives that during the commit phase. Submarine commitments also hide the target contract. | paper | [42] |
| G2 | Even encrypted-balance systems must design against front-running. Zether "describe[s] techniques to protect Zether against replay attacks and front-running situations". | paper | [14] |
| G3 | Ordering is a revenue source for block producers (MEV), and it is paid for through priority fees. Privacy of amounts does not remove ordering power. | paper | [41] |
| G4 | DERO hides amounts and parties of transfers [2]. The DVM, however, exposes DEROVALUE / ASSETVALUE to the SC, and SC state (STORE) is public by design [4]. Whether SC-call arguments and deposits are public on-chain is not stated in the docs. To be checked in code. | doc | [2][4] |
| G5 | Block-derived randomness is bounded by what the producer can forgo: a single-bit lottery is manipulation-resistant only below a stake bound (50 BTC in 2015). RANDOM seeded on BLID (B4) is in that class. | paper + doc | [43][4] |
| G6 | Ring privacy can be defeated statistically (Monero decoy age, chain-reaction). A game whose SC calls are distinguishable by timing, amount or ring choice may leak participation even on DERO. | paper | [16] |

---

## Design implications for DERO SC incentives

1. **Never let an SC prize depend on RANDOM() unless the prize is bounded.** RANDOM is seeded on BLID, SCID and TXID [B4], and a block or miniblock producer can withhold. Use commit-reveal randomness from all players (each XOR-contributes, and a non-reveal forfeits a deposit), or cap the prize at well below one block's reward [B4, G5, E3].
2. **Lotteries and prize games must be commit-reveal with a reveal deadline set by BLOCK_HEIGHT, and a non-revealer's deposit is slashed** [F1, F3, G1]. A non-reveal must be strictly worse than revealing a loss.
3. **No SC reward keyed to "who mined this block".** Payouts that vary by block make block rewards high-variance, and that is the regime where undercutting and low-hashrate selfish mining pay [E3, E1, E2]. Mining incentives stay in the protocol's 10-miniblock split [D2, D3].
4. **Any shared-mining or "community pool" SC uses a hopping-proof rule (PPLNS/score-based), never proportional-per-round** [E5, E6].
5. **The value at stake in any single SC event must stay well below the chain's recurring security spend.** Budish's flow-versus-stock bound applies to bribery and reorg attacks on high-value SC outcomes [E4, D6].
6. **Oracles and dispute games: stake-weighted Schelling plus slashing of incoherent votes plus escalating bonds**, with commit-reveal votes. Assume P+ε bribes exist, and DERO's private transfers make bribes harder to observe [F2, F3, F4, A2].
7. **Slashing only on objective, DVM-checkable evidence** (a signed contradiction, or a missed reveal by height). Pay a finder's fee to whoever submits the evidence [F4, B3].
8. **Sealed-bid auctions (second-price or Myerson-reserve) through commit-reveal deposits**, with bids revealed by height [F5, G1]. The reveal phase must not require public amounts if DEROVALUE is visible (open question G4).
9. **NO-GO ledger (Ponzi shapes):** reject any SC where (a) payouts to earlier participants are funded only by later deposits, (b) the entry toll rises with participant count (handover), (c) there is a referral or inviter tree payout (tree), (d) a FIFO payout queue exists (waterfall), or (e) the owner has a sweep or withdraw path. Check the transaction-flow shape, not just the code, because code checks can be obfuscated [F9].
10. **NO-GO: emission-funded "yield" or liquidity mining without an external revenue source.** It buys TVL that leaves when emissions stop [F8], and it fails item 9(a) when the rewards come from new entrants.
11. **Prize-linked savings is allowed only if the principal is fully withdrawable and prizes come from declared external revenue** (fees or donations). DERO has no native interest [F6, D6]. Without that revenue it is a lottery and must be labelled as one.
12. **Quadratic funding is NO-GO on DERO without sybil resistance.** Anonymous accounts and ring privacy remove the identity assumption that QF optimality needs [F6, A2].
13. **Owner-upgradable code (UPDATE_SC_CODE) disqualifies trust-minimized games**, unless the update path is removed, time-locked by BLOCK_HEIGHT, or gated by a participant vote. The official token example ships an owner-only UpdateCode [B7].
14. **Burns use the documented DVM burn path or a provably unspendable destination**, with binding metadata in SC storage [B6, F7].
15. **Avoid fingerprintable SC interaction patterns** (fixed odd amounts, timing). Treat SC participation as possibly linkable until checked in code [G4, G6, A8].

## Open questions to verify in code

1. Is DERO HE balance encryption ElGamal over bn256 (Zether-style)? Which file implements it? [A5]
2. Exact miniblocks per block, the final-miniblock rule, the integrator / 1.6% share, and the per-miniblock reward split [D2, D3, D4].
3. Target block time, 16 s or 18 s, and how difficulty retargets [D1].
4. Can miniblocks or blocks become side/orphan? If so, are they paid, and how much (GHOST-like or not)? This decides whether the "No Orphan Blocks" doc claim holds [D5, E7].
5. Emission formula: initial reward, halving height or interval, and current reward versus the "21 Million" and "Halving every 4 years" claims [D6].
6. RANDOM: exact seed derivation (`deterministic_random_number.go`). Is BLID the miniblock or the final block? Can the producer grind it [B4]?
7. Gas: are ComputeCost / StorageCost charged? Is there a per-tx gas limit, and who receives SC fees [B5]?
8. Are SC-call arguments, DEROVALUE and ASSETVALUE deposits, and the SIGNER visible on-chain? What ring size do SC invocations use [G4]?
9. SC burn semantics: when is value "burned forever" rather than credited to the SC [B6]?
10. UPDATE_SC_CODE: can it be permanently disabled, and is there any protocol-level time-lock [B7]?
11. AstroBWT v3: the exact pipeline in `astrobwtv3/pow.go` compared with the third-party description, and the size of the branchy loop [C3].
12. Is BLOCK_HEIGHT inside an SC the height of the including block? Is it monotone across miniblocks? This matters for commit-reveal deadlines.
13. Transaction ordering inside a block: who decides it, and can the integrator or final-miniblock producer reorder or censor SC calls (MEV surface) [G3]?

## Fetch failures (kept honest)
wiki.dero.io (Stargate community whitepaper PDF, AstroBWT, HE Features): connection refused or timeout. forum.dero.io: connection refused. DERO Medium posts: HTTP 403. The kryptoid Medium post: 403. CoinClear: DNS failure. kleros.io long whitepaper: "Not found". Community node page: TLS error, so only the search snippet was used. The Myerson DOI page: 403 (read via a course mirror). The Zether full PDF: 403, so only the abstract was used. The Chen et al. WWW 2018 page redirected and was not fetched; it is used only via search text and is not in sources.json as evidence.
