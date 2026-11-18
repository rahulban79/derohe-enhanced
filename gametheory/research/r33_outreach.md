# R33 outreach research: getting outside wallets and miners to discover and join the game contracts

Date: 2026-11-17. Repo for code facts: `~/derohe-Release151`. It was read only. No node RPC, getwork or P2P port was contacted.
Labels:
- **CONFIRMED (code)**: read at file:line.
- **DERIVED**: arithmetic or reasoning from confirmed facts.
- **doc / paper / steer**: web sources. Forums, blogs, news and vendor glossaries are **steer**. They raise questions and are never evidence (rft §0.8.10).

Unreachable on 2026-11-17 (ECONNREFUSED): `https://forum.dero.io/`, `https://dero.io/`, `https://wiki.dero.io/wiki/index.php/Engram`. Every claim that would have come from them is therefore marked OPEN.

---

## 1. On-chain channels to other users (code)

### 1.1 The encrypted per-recipient RPC payload ("send 1 atomic unit with a message")

| Fact | Anchor |
|---|---|
| Every transfer payload carries a fixed `PAYLOAD_LIMIT = 1 + 144` bytes and is "mandatorily encrypted". The usable CBOR argument budget is `PAYLOAD0_LIMIT = 144 - 33` = **111 bytes**. | `transaction/transaction.go:62`, `:65`; size enforced `:132-133` |
| The standard argument names are `D` destination port, `S` source port, `V` value (display only, "value is never transferred"), `C` comment ("used for display MSG to user"), `E` expiry, `R` reply-back address and `N` needs-reply-back. | `rpc/rpc.go:378-386` |
| The wallet packs the arguments with `CheckPack(PAYLOAD0_LIMIT)`. A comment that is too long fails the build. | `walletapi/wallet_transfer.go:135`; `walletapi/transaction_build.go:175`; CLI `cmd/dero-wallet-cli/easymenu_post_open.go:376` |
| The CLI prompts for a "Comment" and prints the "Integrated Message" of an integrated address. | `cmd/dero-wallet-cli/easymenu_post_open.go:360-371`, `:284-286` |
| The receiver decrypts the payload with its secret key and gets the arguments as `Entry.Payload_RPC`. The history entry prints "Sender:" and the arguments. | `walletapi/daemon_communication.go:1114-1140`; `rpc/wallet_rpc.go:109-118`, `:133-150` |
| **The recipient learns the sender's address.** Byte 0 of the plaintext is the sender's ring index, and the wallet resolves it to `entry.Sender`. With ring size 2 the other member is the sender by construction. | `walletapi/daemon_communication.go:1121-1135` |

DERIVED cost of one push message with ring 16 and fee multiplier 2.0. The default account is `Ringsize: 16, FeesMultiplier: 2.0` (`walletapi/wallet.go:179`).
- The wallet fee is `(transfers+2) * 20 * (ring/16 + mult)` plus `1.5 × len(scdata)`, from `walletapi/transaction_build.go:140-145`.
- That gives `(1+2) × 20 × (1+2.0) = 180` atomic units, plus 1 atomic unit of value.
- 1 DERO is 10^5 atomic units (`FormatMoney`, 5 decimals, `rpc/wallet_rpc.go`), so one message costs about **0.0018 DERO**.
- The consensus minimum is `ceil(size/1024) × 20` (`blockchain/tx_fees.go:35-44`, `config/config.go:49`).

Pushing to thousands of addresses would therefore cost only a few DERO. That is exactly why the norms in §3 matter. Zcash's shielded-output spam in 2022 cost about 0.0001 ZEC per transaction (steer, §3).

### 1.2 Contract state that explorers, wallets and indexers can show

| Fact | Anchor |
|---|---|
| The bundled explorer shows an install transaction's SC code ("Smart Contract Code", collapsible), its SC balance, and the full variable state from `DERO.GetSC{Variables:true}`. It has **no contract list or directory page**. Contracts are reachable only by txid or SCID. | `cmd/explorer/explorerlib/explorerlib.go:660-676`; `cmd/explorer/explorerlib/templates/tx.tmpl:348-362` |
| `GetSC` is a public daemon method. So is `GetGasEstimate`, which gives an exact pre-flight cost for any beacon call. | `cmd/derod/rpc/websocket_server.go:381`, `:382`; `cmd/derod/rpc/rpc_dero_estimategas.go` |
| DVM-BASIC has **no event/log primitive**. The only public outputs are stored variables (`STORE`), each charged 1 storage gas per byte. Storage gas is capped at 20,000 atomic units per call. | builtins list `dvm/dvm_functions.go:170-625`; `dvm/dvm_store.go:133`; `dvm/sc.go:247-254`; `config/config.go:46` |

### 1.3 Names

- The hard-coded **name service** is SCID `00…01`, installed at genesis and updated at HF1 (`blockchain/hardcoded_contracts.go:28-60`).
- `Register(name)` stores `name → SIGNER()` once. Names of 6–63 characters are open to anyone. Names of 5 or fewer characters are reserved for two hard-coded addresses (`blockchain/hardcoded_sc/nameservice.bas:12-18`). `TransferOwnership` is at `:24-28`.
- Resolution goes through the public `NameToAddress` RPC (`cmd/derod/rpc/rpc_dero_nametoaddress.go:30-72`; tree `00…01` at `:49-59`).
- **It maps names to addresses, not to SCIDs.** It cannot carry a description. A name like `derogames-beacon` can still point people at the beacon owner's address, and the beacon SCID can sit in that owner's variables.

### 1.4 Can a contract send a message or DERO to an arbitrary address?

| Fact | Anchor |
|---|---|
| `SEND_DERO_TO_ADDRESS(addr, amount)` and `SEND_ASSET_TO_ADDRESS` accept any valid compressed point. They record a `TransferExternal{Asset, Address, Amount}`, which has **no payload field**, so a contract cannot attach a message. | `dvm/dvm_functions.go:377-396`, `:398-432`; struct `dvm/dvm_store.go:39-43`; `SendExternal` `dvm/dvm_store.go:138` |
| A payout to an **unregistered** address panics with "sending to non registered account", and the whole call reverts. | `dvm/simulator.go:335-365` |
| The receiving wallet sees an SC payout only as an unexplained balance increase. It labels any such increase **`Coinbase = true`**, the same as a mined block. | `walletapi/daemon_communication.go:1208-1218` |

DERIVED: an unsolicited contract "airdrop" looks to the recipient like a mining reward that has no sender and no message. That is misleading by construction.

### 1.5 Can registered addresses or recent miners be enumerated from public data? **Yes. Both are trivial.**

| Fact | Anchor |
|---|---|
| Miniblocks carry `KeyHash`, the first 16 bytes of `graviton.Sum(miner compressed key)`. | `block/miniblock.go:53`, `:166`; `blockchain/miner_block.go:365-366`; getwork `cmd/derod/rpc/websocket_getwork_server.go:307` |
| Consensus resolves `KeyHash` back to the full key through `balance_tree.GetKeyValueFromHash`. | `blockchain/transaction_execute.go:151` |
| **Public block headers already return `Miners[]` as full addresses**: each miniblock's resolved key, and the integrator from `Miner_TX.MinerAddress`. | `cmd/derod/rpc/blockheader.go:73-99` |
| `GetRandomAddress` is a public RPC that returns random registered addresses (decoy sampling) for DERO or any SCID tree. Repeated calls sample the registered set. | `cmd/derod/rpc/rpc_dero_getrandomaddress.go:47`, `:97`, `:155`; registered `websocket_server.go:372` |
| With a local DB, the balance tree can be walked completely with a cursor. | `vendor/github.com/deroproject/graviton/cursor.go:18-23`; example `rpc_dero_getrandomaddress.go:132-133` |
| Gnomon has `--enable-miniblock-lookup` to "store all miniblocks … and miner addresses who found them". | Gnomon README line 77 (doc) |
| Registration is free apart from proof of work, so Sybil identities cost nothing. | prior R33 dossier `gametheory/research/r33_code_capabilities.md:214`, citing `blockchain/transaction_execute.go:173-202` |

DERIVED: building a push list of every active miner is easy. Whether it is *acceptable* is decided in §3, not by feasibility.

---

## 2. Discovery precedents

| # | Precedent | Finding | Label |
|---|---|---|---|
| P1 | **Gnomon** (civilware): "open source decentralized search engine built on the DERO Decentralized Application Platform" | With no `--search-filter` it indexes **all installed SCs except the hard-coded ones**. `addscid_toindex` adds one SCID manually. The **GnomonSC index service** stores each matched SC's height, owner and SCID in an on-chain contract that Gnomon fastsync consumes (README lines 75, 309). Structures expose `SCTXParse{Scid, Sender, Entrypoint, Method, Fees, Height}` and `FastSyncImport{Owner, Height, Headers}`. | doc: https://github.com/civilware/Gnomon ; https://pkg.go.dev/github.com/civilware/Gnomon/structures |
| P2 | **TELA** (civilware): dApps stored as `TELA-INDEX-1` / `TELA-DOC-1` contracts | They carry **`nameHdr`, `descrHdr`, `iconURLHdr`, `dURL`**, using "the header structure from the ART-NFA Standard". Users load an app "by SCID". There is an on-chain rating: "one rating per DERO account, per contract", ring 2 required, values < 100. | doc: https://github.com/civilware/tela |
| P3 | **Engram** (DEROFDN wallet) | Lists "Gnomon integration", "dynamically interact with smart contracts", "on-chain encrypted private messaging", "explore TELA dApps", websocket dApp connections, and EPOCH crowd-mining support. The README does not say whether it shows a contract list with names. **OPEN.** | doc: https://github.com/DEROFDN/engram |
| P4 | Community TELA browsers | SovereignSearch ("browse DERO / TELA websites … by SCID"). Derosphere lists "list available dapps" and "register a name". | steer: https://gh.r-mj.com/ArcaneSphere/SovereignSearch ; https://fr.github.com/g45t345rt/derosphere/blob/master/features.md |
| P5 | DERO name service via MCP tool | `DERO.NameToAddress(name, topoheight)`. Corroborates §1.3. | steer: https://glama.ai/mcp/servers/DHEBP/dero-mcp-server/tools/dero_name_to_address |
| P6 | **ENS** | The registry records owner, resolver and TTL. "All ENS lookups start by querying the registry." ENSIP-5 standard text keys include `description`, `url`, `avatar`, `keywords` and `notice`. This is the model for a pull-only, self-describing registry. | doc: https://docs.ens.domains/registry/ens ; https://docs.ens.domains/ensip/5 |
| P7 | **Airdrops as user acquisition** | Nine major airdrops studied. "Up to 66 % in some cases" of tokens were "rapidly sold", often in the recipient's first post-claim transaction. In the Arbitrum case, "short-term activity spikes fail to translate into sustained user involvement". TierDrop (title and related work only) cites ParaSwap: 41 % sold immediately and 22 % were Sybil "airdrop hunters". | paper: https://arxiv.org/abs/2312.02752 ; paper (title only): https://arxiv.org/pdf/2407.01176 |
| P8 | **Mining-pool transparency (Monero P2Pool)** | "No pool wallet, funds are never in custody". "Wallet addresses are public on P2Pool", so the project recommends a dedicated wallet. Third-party observers publish the stats. This is the precedent for opt-in public mining identity. | doc: https://github.com/SChernykh/p2pool |
| P9 | DERO community channels (forum, Discord, dero.io pages) | Unreachable today. Whether a dApps page exists is **OPEN**. | steer (unreachable): https://forum.dero.io/ , https://dero.io/ , https://wiki.dero.io/ |

Answer (DERIVED): no DERO wallet or explorer evidenced here has a *curated* contract directory.
- The discovery surface that demonstrably exists is **Gnomon**, which sees every SC, plus **TELA/ART-NFA headers**, which give a name, description and icon to Gnomon/TELA hosts such as Engram.
- Beyond that there are the explorer's per-SC variable view, the name service, and off-chain community channels.
- A beacon that installs with `nameHdr`/`descrHdr`/`iconURLHdr`, plus a TELA-INDEX front page, reaches the people who are already looking. That is the opt-in audience.

---

## 3. Ethics and law of unsolicited outreach

| Point | Evidence | Label |
|---|---|---|
| "Dusting" means sending tiny amounts to many wallets to track and de-anonymise owners. The guidance is to ignore unsolicited small transactions and "not interact with links or messages included in memo tags or unsolicited transactions". | https://www.ledger.com/academy/glossary/dusting-attack ; https://www.coingecko.com/learn/dusting-attack | steer |
| Unsolicited tiny transfers are the delivery vector of **address poisoning**: 270 M on-chain attack attempts against 17 M victims, 6,633 incidents and at least $83.8 M lost (ETH and BSC, 2 years). Wallet users are taught to treat unsolicited small transfers as hostile. | https://www.usenix.org/conference/usenixsecurity25/presentation/tsuchiya | paper |
| Cheap privacy-chain spam is a known harm. Zcash, 2022: shielded-output spam at about 0.0001 ZEC per transaction grew the chain from about 31 GB to over 100 GB, and some shielded wallets synced more slowly. | https://www.theblock.co/post/175259 ; https://www.coindesk.com/business/2022/10/07/zcash-may-be-getting-spammed-but-the-blockchain-is-doing-just-fine-the-company-behind-it-says | steer |
| **EU ePrivacy Directive Art. 13(1)**: direct marketing by electronic mail needs prior consent. "Electronic mail" (Art. 2(h)) covers any text message sent over a public network and stored until the recipient collects it. Recital 67 of Directive 2009/136 extends this to "similar" messages. Whether an on-chain encrypted payload is "electronic mail" is **untested**, but it fits the definition's shape. The CJEU (C-654/23, 13 Nov 2025) refined the meaning of "direct marketing". | https://www.legislation.gov.uk/eudr/2002/58/article/13 (doc); Art. 29 WP Opinion 5/2004 https://Datenschutz.Hessen.de/sites/datenschutz.hessen.de/files/2022-11/wp_90.pdf (doc); https://www.pearlcohen.com/cjeu-clarifies-why-not-all-unsolicited-newsletter-emails-require-prior-consent/ (steer) | doc / steer |
| **GDPR**: CNIL says the GDPR applies where a blockchain holds personal data, and lists participants' public keys among the identifiers. Whether public keys are personal data is contested. Compiling a list of miner addresses to target them with marketing is processing for a new purpose. | https://cnil.fr/en/blockchain-and-gdpr-solutions-responsible-use-blockchain-context-personal-data | doc |

DERO-specific privacy harm (DERIVED from §1):
1. **The recipient is known to be in the ring.** If the operator messages every address in the public `Miners[]` list, an observer intersects each ring with that list. Outside the list, only decoys from `GetRandomAddress` appear. This links "operator wallet X targets miner Y" and weakens the recipient's ring anonymity, without the recipient doing anything.
2. **The operator's address is revealed to every recipient** (`daemon_communication.go:1121-1135`). It is then reused as a fingerprint across the campaign.
3. **Contract payouts appear as "Coinbase"** (`daemon_communication.go:1208-1218`). An unsolicited contract airdrop is misleading even when it is well meant.
4. **There is no receiver-side opt-out.** No wallet code path filters by sender: `ProcessPayload` always stores the arguments (`rpc/wallet_rpc.go:133-150`).

**Recommendation.**
- **Acceptable:**
  - Opt-in, *pull* discovery: a public beacon contract, TELA/ART-NFA headers, Gnomon indexing, a name-service entry, explorer-readable variables, and posts in community channels that follow those channels' own rules.
  - Replying with a payload message **only** to an address that first contacted the operator, for example through the `R`/`N` reply-back arguments (`rpc/rpc.go:383-386`) or a beacon `Subscribe` call.
- **Not acceptable:**
  - Pushing messages or micro-transfers to addresses harvested from `Miners[]`, `GetRandomAddress`, Gnomon miniblock lookup or a balance-tree walk.
  - Unsolicited contract airdrops.

---

## 4. Mechanism design for an advertisement beacon

### 4.1 Contract `gt_beacon` (design)

- **State.** `owner`; `frozen`; `n` (epoch counter); and per epoch `e<k>_body` (a string), `e<k>_h` (block height), `e<k>_src` (the height range the figures cover) and `e<k>_hash` (SHA3256 of the canonical off-chain JSON). The last N epochs are kept, and older ones are deleted with `DELETE` to keep storage bounded.
- **Install headers.** `nameHdr`, `descrHdr` and `iconURLHdr` (ART-NFA/TELA convention, P2). Hosts that index TELA, such as Engram, can then show a name and description. A TELA-INDEX-1 front page renders the latest epoch.
- **`Publish(body, from, upto, jsonhash)`.**
  - Only the owner may call it, with ring 2 (anonymous callers revert; prior R33 finding).
  - `body` is a compact record with, for each game, the SCID, the hash of its frozen params, open rounds and their deadlines, and **measured** payouts with their height range.
  - It also states the audit status, meaning the commit hash of `gametheory/audit/r33_contract_audit.md`, and gives a "how to join" pointer (SCID plus entrypoint name).
- **`Subscribe()`.** Ring 2, no payment. It stores `sub_<signer>=height`. This is the explicit opt-in that §3 requires before any reply message. `Unsubscribe()` deletes the entry.
- **Bonded honesty.** Each `Publish` locks a DERO bond in the contract. Anyone can dispute a figure through the existing `gt_audit.bas` flow (`Post`/`Enter`/`Reveal`/`Settle`, `gametheory/contracts/gt_audit.bas:66-153`), and a disputed epoch is marked `disputed=1`. The DVM cannot read another contract's state (prior R33 code-capabilities §7), so the beacon's figures are claims that anyone can check, not values computed on chain.

### 4.2 Cost per beacon update (DERIVED; confirm with `GetGasEstimate` / `dry_run`)

The cost has three parts:
- Base fee with ring 2 and multiplier 2.0: `(1+2) × 20 × (2/16 → 0 + 2.0) = 120` atomic units.
- Argument bytes: `1.5 × len(scdata)`. For about 600 bytes that is about 900.
- Storage gas: 1 per stored byte. For about 600 bytes that is about 600.

Sources: `walletapi/transaction_build.go:140-145`, `dvm/dvm_store.go:133`, `TransferPayload0(..., dry_run)` at `walletapi/wallet_transfer.go:63`.

Total: about **1,600 atomic units, about 0.016 DERO per update**. A 20 KB epoch is the hard limit set by the 20,000 storage-gas cap. Daily publishing would cost about 0.5 DERO a month, before the bond (which is refundable).

### 4.3 Referral rewards and Sybil resistance

- The problem: registration is free (§1.5). Babaioff et al. show that **no reward scheme makes both propagation and "no self-cloning" a dominant strategy**. Sybil-proofness holds only under iterated dominance, and multi-level trees invite cloning. (paper: https://arxiv.org/abs/1111.2626)
- Safe variant, R-safe:
  - The scheme is single level only.
  - The referrer earns `ρ × (verified contribution of the referee)`, with `ρ < 1`, for example 0.2.
  - A verified contribution is one of two things: fees the referee actually paid into a game contract (on-chain plaintext deposit), or `gt_attest` miniblock claims that passed the challenge window (`gametheory/contracts/gt_attest.bas:56-212`).
  - Rewards are paid only after maturity, for example 2 epochs, with a per-referrer cap per epoch and a per-epoch budget cap.
- DERIVED: self-referral then gives back at most `ρ` of what the attacker paid or mined. It is a discount, never a profit. Under the attestation game, Sybils must contribute real hashrate to earn anything, and that hashrate is the outcome being measured.
- Do not pay for sign-ups, `Subscribe` calls, or referee counts.

### 4.4 Non-misleading content rules

- Only measured, past figures are published, each with its height range and a reproduction recipe (block headers plus `GetSC`).
- There are no APY figures or projections.
- Each epoch must state the operator-share figure, meaning the fees as a fraction of the block reward. The current measurement is **0.27–0.59 %**.
- Each epoch states whether its figures include operator wallets, for example as "outside share = x / y".
- Each epoch states known risks: contracts are frozen but unaudited by third parties, there is a range-proof disclosure, and anonymous calls revert while keeping the fee.

---

## 5. Making the hashrate effect measurable without de-anonymising anyone

1. **Operator set commitment.**
   - The operator publishes in the beacon `opset_root`, the SHA3256 Merkle root over `H(salt_i ‖ addr_i)` for every operator wallet, plus the set size.
   - An "outside participant" is any game signer whose address is not in the set.
   - The operator reveals `salt_i` for a disputed address only to a `gt_audit` jury. This stops the set from being edited quietly afterwards. Public addresses are never published as a list.
2. **Opt-in mining identity.** The only *attributable* outside hashrate is what outsiders themselves attest in `gt_attest.Claim(from, upto, k)`. The miniblock miner is already public in headers (§1.5); the attester adds only the link that it joined the game. That matches the P2Pool precedent of a dedicated wallet.
3. **Aggregate network metric.**
   - Headers give about 4,800 blocks and 48,000 miniblocks a day (`config/config.go:34`, 86,400 / 18; 10 miniblocks per block).
   - Daily metrics: distinct miner keys, the share of miniblocks from game-attested outside keys, and difficulty (`GetDifficultyHistory`).
   - Publish only aggregates, with a k-anonymity floor: publish a count only when at least 5 distinct outside keys contribute.
4. **Causal attribution (first-seen ordering).** A key counts as **game-recruited** if its first-ever miniblock comes after its first game interaction, such as `Subscribe`, `Claim` or a paid entry. Keys that mined before are "existing miners who joined". They show participation, not new hashrate.
5. **Power.**
   - An outside share `s` gives a Poisson count of about 48,000·s miniblocks a day. At `s = 0.1 %` that is about 48 a day, so a 2σ change is detectable within one day for attested keys.
   - A *network-wide* hashrate effect must beat natural difficulty variance. Pre-register the baseline as the σ of 7-day mean difficulty over the preceding 8 weeks. Claim an effect only if the post-launch 7-day mean exceeds baseline + 2σ **and** the attested outside share explains at least half of the rise.

---

## Design rules (falsifiable)

| ID | Rule | Falsified if |
|---|---|---|
| OR-1 | Outreach is pull only. No payload message or transfer goes to an address that has not called `Subscribe` or contacted the operator first. | Any operator transaction carries a payload to an address with no prior `sub_<addr>` or inbound contact, as shown by the audit of operator-wallet history. |
| OR-2 | The beacon installs with `nameHdr`/`descrHdr`/`iconURLHdr`, and Gnomon (unfiltered) indexes it within 1 day. | A stock Gnomon indexer run with no filter does not list the beacon SCID with its headers after 4,800 blocks. |
| OR-3 | Each beacon epoch costs at most 0.03 DERO in fees and at most 20 KB of storage. | `GetGasEstimate` or a `dry_run` of a real epoch exceeds 3,000 atomic units, or storage gas hits the 20,000 cap. |
| OR-4 | Every published figure carries a height range and is reproducible from public headers plus `GetSC`. | An independent recomputation differs from a published figure by more than 0, or by more than rounding. |
| OR-5 | No beacon field contains a forward-looking return. | Any epoch body contains APY, an "expected" value or a projection field. |
| OR-6 | Referral payout ≤ ρ (< 1) × the referee's verified contribution, single level, capped. | A self-referral simulation (two keys, one owner) nets more than 0 DERO after fees. |
| OR-7 | Outside counts exclude every operator wallet, and this is checkable against `opset_root`. | A jury reveal shows a counted "outside" address inside the committed operator set. |
| OR-8 | Published hashrate aggregates obey k ≥ 5. | Any published aggregate bucket has fewer than 5 distinct outside keys. |
| OR-9 | A network-wide hashrate effect is claimed only when the 7-day mean is above baseline + 2σ **and** the attested outside share explains at least 50 % of the rise. | A claim is made without both conditions in the pre-registered window. |
| OR-10 | "Game-recruited" uses first-seen ordering only. | A key with a miniblock before its first game interaction is counted as recruited. |

## Do not do

1. **Do not message or "dust" addresses harvested from `Miners[]`, `GetRandomAddress`, Gnomon miniblock lookup or a balance-tree walk.**
   - The recipients' ring anonymity is weakened by intersecting rings with the public list (§3).
   - The operator's address is exposed to each recipient.
   - It matches the pattern that wallet users are trained to treat as dusting or poisoning (Tsuchiya et al., 270 M attacks).
   - It is plausibly "electronic mail" direct marketing without consent (ePrivacy Art. 13), and processing of public keys under the GDPR (CNIL).
2. **Do not airdrop DERO or tokens through `SEND_DERO_TO_ADDRESS` to strangers.**
   - The payout carries no message (`dvm/dvm_store.go:39-43`) and shows as **Coinbase** in the recipient's wallet (`walletapi/daemon_communication.go:1208-1218`), which is misleading.
   - It reverts on unregistered keys (`dvm/simulator.go:357-365`).
   - Airdrops retain poorly: up to 66 % rapidly sold, and spikes do not persist (Messias et al.).
3. **Do not pay per sign-up, per referral count, or multi-level.** Registration is free, so Sybils cost nothing, and Babaioff et al. show multi-level schemes invite cloning.
4. **Do not publish APY or projected returns, or figures without height ranges.** They cannot be verified and they mislead. The honest current number is fees of 0.27–0.59 % of the block reward.
5. **Do not publish lists of outside participants' addresses or per-address mining stats in the beacon.** Opt-in attesters chose to link their address to *the game*, not to a marketing table. Publish aggregates only, with k ≥ 5.
6. **Do not count the operator's own wallets as "outside", and do not leave the operator set uncommitted.** Doing so would fake the very effect R33 is trying to measure.
7. **Do not use names of 5 or fewer characters, or impersonating names, in the name service.** Short names are reserved (`nameservice.bas:15-18`), and impersonating a project or person is deceptive.
8. **Do not treat forum, Discord or Telegram reactions as evidence of uptake.** They are steers only (rft §0.8.10). Uptake is measured on chain (§5).

---

## Sources

- **doc (10):**
  - Gnomon README: https://github.com/civilware/Gnomon
  - Gnomon structures: https://pkg.go.dev/github.com/civilware/Gnomon/structures
  - TELA: https://github.com/civilware/tela
  - Engram: https://github.com/DEROFDN/engram
  - ENS registry: https://docs.ens.domains/registry/ens
  - ENSIP-5: https://docs.ens.domains/ensip/5
  - P2Pool: https://github.com/SChernykh/p2pool
  - CNIL: https://cnil.fr/en/blockchain-and-gdpr-solutions-responsible-use-blockchain-context-personal-data
  - ePrivacy Art. 13: https://www.legislation.gov.uk/eudr/2002/58/article/13
  - Art. 29 WP Opinion 5/2004: https://Datenschutz.Hessen.de/sites/datenschutz.hessen.de/files/2022-11/wp_90.pdf
- **paper (4):**
  - Messias, Yaish and Livshits: https://arxiv.org/abs/2312.02752
  - TierDrop (title and related work only): https://arxiv.org/pdf/2407.01176
  - Babaioff et al.: https://arxiv.org/abs/1111.2626
  - Tsuchiya et al., USENIX Security 2025: https://www.usenix.org/conference/usenixsecurity25/presentation/tsuchiya
- **steer (11):**
  - Ledger dusting: https://www.ledger.com/academy/glossary/dusting-attack
  - CoinGecko dusting: https://www.coingecko.com/learn/dusting-attack
  - The Block (Zcash): https://www.theblock.co/post/175259
  - CoinDesk (Zcash): https://www.coindesk.com/business/2022/10/07/zcash-may-be-getting-spammed-but-the-blockchain-is-doing-just-fine-the-company-behind-it-says
  - Pearl Cohen (CJEU): https://www.pearlcohen.com/cjeu-clarifies-why-not-all-unsolicited-newsletter-emails-require-prior-consent/
  - SovereignSearch: https://gh.r-mj.com/ArcaneSphere/SovereignSearch
  - Derosphere: https://fr.github.com/g45t345rt/derosphere/blob/master/features.md
  - DERO MCP name tool: https://glama.ai/mcp/servers/DHEBP/dero-mcp-server/tools/dero_name_to_address
  - Unreachable today: https://forum.dero.io/ , https://dero.io/ , https://wiki.dero.io/wiki/index.php/Engram
- **code anchors:** about 35 file:line anchors in `~/derohe-Release151`, listed inline above.
