# Draft announcement: a verified mining pool contract on DERO (R33, GT-B26)

> Draft for the operator to post, if they choose, in community channels that allow it. Pull-only (D-GT-22): the
> pipeline sends nothing to anyone. Fill in the two IDs from the beacon before posting. Every figure below is
> measured on mainnet with its height range; nothing here promises a return.

**A DERO smart contract that pays miners for verified work.** `gt_pool` credits a miniblock to a member only after
the contract itself checks the block: it stores the id of the block a call runs in, later accepts that block's bytes
only if their SHA3-256 matches, and reads each miniblock's 8-byte tag (written by the miner with `--game-tag`). No
vote, no oracle, no operator decides who mined. Payouts per epoch follow verified work; locked stake can at most double
a member's share and earns nothing without mining; 20 % of every deposit and entry fee is burned (locked forever,
checkable with `DERO.GetSC`).

**Measured on mainnet (epoch 19,790, heights 7,916,059–7,916,522):**
- 36 blocks proven in the contract; every credit equal to the tagged miniblocks in those blocks (chain audit PASS).
- 21,000 atomic burned in that epoch.
- Cost of one block proof: 1,672–1,773 atomic (the call carries the block's bytes).
- Miner concentration seen by the contract over epochs 19,790–19,791: 378 verified miniblocks from 19 miners, the
  largest 17.7 % (alarm threshold 40 %).

**What it does not do:** it does not change the block reward or consensus, cannot see or stop network-level attacks,
and pays only from sponsor deposits and entry fees. Fees routed to the network by the games are small (0.27–0.59 % of
the block reward in R32a); any effect on network hashrate depends on independent miners joining.

**How to join:** the full tutorial is `gametheory/contracts/README.md` in the derohe-enhanced repository (write, test,
install, call, read; section 9 is the pool step by step). Register your wallet first, then mine with your tag.

- Pool contract: `<pool SCID from the beacon>`
- Beacon (live figures, subscribe): `<beacon SCID>`

Security status: an independent audit (17 findings) and an invariant verification (37 invariants) of every contract,
all findings fixed with regression tests; see the README's audit section.
