# RUN_REPORT.md — Network-Layer Performance (derod ⇄ dero-miner)
**Regime:** CLOSED LOOP (executed) · **Date:** 2026-07-08 · **Follows:** DISCOVERY.md (G0)

## What was built (all transport/latency-only — zero consensus change)
| Path | Change | Files |
|---|---|---|
| B | Latency-ordered miniblock broadcast (fastest peers first) | `p2p/connection_pool.go:543` |
| A | `--lowlatency` derod flag → fast KCP `SetNoDelay(1,10,2,1)`; honest log; `P2PLowLatency` var | `p2p/controller.go`, `cmd/derod/main.go` |
| C | Miner: own `minerDialer` (explicit TCP_NODELAY), reconnect backoff 1→8 s, `submitShare()` (serialize off-lock + latency stat) | `cmd/dero-miner/miner.go`, `gpu_worker.go` |
| E | `net_metrics.sh` propagation-histogram scraper; `run_derod_lowlatency.sh` launcher (`--min-peers=40 --lowlatency`) | repo root |

## GATE LEDGER (eval gate after every step — `[E:EXEC]`)
| Step | Postcondition | Result | Evidence |
|---|---|---|---|
| G-B | `go build ./p2p/` after latency-sort | **PASS** | exit 0 |
| G-A | derod builds; `--lowlatency` in `--help`; docopt rejects bogus flags; `go test ./p2p/` | **PASS** | exit 0; flag shown; `ok 0.299s` |
| G-C | miner vet+build clean (fixed 2 unused imports) | **PASS** | vet 0, build 0 |
| G-tree | `go build ./...` whole tree | **PASS** | exit 0 |
| G-E | scraper parses VM vmrange histogram | **PASS** | synthetic: count=10, avg 90.1 ms, p50≤60, p90≤113.6 |
| G-live | new miner runs against live derod: connects, GPU self-test bit-exact, mines, **0 rejects** | **PASS** | 23 hashrate samples 7.8–8.16 KH/s; `rejected:0`; 0 errors |

No gate failed twice; no gate papered over. One repair: gpu_worker.go unused imports (`globals`,`rpc`) after routing through `submitShare` → removed → rebuild PASS.

## Live pipeline execution `[E:OBS 2026-07-08 18:25–18:31]`
- Miner (new binary, `--gpu`) → derod loopback getwork: **connected, bit-exact GPU self-test PASSED, 20 threads**.
- Throughput **7,894 / 8,143 / 8,101 / 8,156 / 8,159 … H/s** (GPU ~1,230–1,257) — **no regression** vs ~8,100 baseline.
- **rejected = 0** across the run → the new dialer + `submitShare` wire format is identical/compatible.
- `found=0, submits=0` in the ~2.5 min window = expected variance (P(≥1 mini) ≈ 10 %), **not a bug**.

## THE dominant finding (reprioritizes the levers) `[E:OBS]`
derod (user-restarted 18:09) was **still syncing**: height **7297744** vs peer **7302903** = **~5,100 behind**, on
**2 peers (0 inbound)**, "backing off" from 3/5 priority nodes. ⇒ (1) propagation histogram empty until synced;
(2) **mining while behind = stale miniblocks the network rejects = 0 reward.** For this node the **binding reward
constraint is peer connectivity + staying synced**, ahead of transport micro-latency. Every restart ≈ 30 min of
stale mining. Deferred measurement: run `./net_metrics.sh` once the node reaches tip to capture live p50/p90.

## Re-ranked recommendations (evidence-based)
1. **Minimize downtime + widen peers.** Keep derod 24/7; use `./run_derod_lowlatency.sh` (`--min-peers=40`). If possible port-forward the P2P port for inbound peers (currently 0). Biggest reward lever for THIS node right now.
2. **Run derod with `--lowlatency`** (fast KCP) — per-hop propagation flush 40 ms→10 ms + fast-retransmit. `./run_derod_lowlatency.sh` does this.
3. **Latency-ordered broadcast** ships automatically in the new derod — fastest peers get your miniblock first.
4. **Only mine when synced.** After a restart, wait for `height == network target` before expecting reward (or adopt the §18.3 stale-guard follow-up).

## Artifacts / provenance
- Backups: `bin/derod.pre-net.bak`, `bin/dero-miner.pre-net.bak` (revert = `cp` back).
- Promoted: `bin/dero-miner` (live-validated), `bin/derod` (built+vetted+p2p-tests; **not** live-run by me — sandbox blocked stopping the running node; watch first startup for the `LOW-LATENCY` log line).
- Docs: `DISCOVERY.md` (G0), `ARCHITECTURE.md §18`, this report.

## Unverified ledger
- `[deferred]` live `miniblock_propagation_duration` p50/p90 under `--lowlatency` — gated on node sync; scraper ready.
- `[E:DERIVE]` per-hop 40→10 ms KCP flush improvement from kcp-go `SetNoDelay` semantics; live A/B needs a synced node over a longer window.

---

# ROUND 3 (2026-08-09/10) — INCIDENT: derod sync stall at topo 7,412,674 → root-caused & recovered

## Problem `[E:OBS]`
After a month offline (Jul 9→Aug 9), derod replayed 108,686 blocks flawlessly (5.4 blocks/s, zero errors) then
deterministically rejected canonical block `7f4540d4…` (topo 7,412,675, minted 2026-08-01, txid `6e26b8aa…`) with
`transaction statement 0 verification failed` — 206 identical failures over 3h53m, reproduced 5s after restart.

## Root cause (5-agent ultracode evidence run + 1 decisive spike)
**A corrupt/stale leaf VALUE in the local graviton balance tree, invisible under a valid Merkle root.**
- Not the network: Release142 is still the newest published DERO software (all upstream branches at `9b6a8b82`);
  the block is canonical w/ 40,453 confirmations (explorer.dero-node.net); no hardfork gate near 7.4M (only v2@481,600);
  zero community stall reports `[E:EXEC]`.
- Not our code: full `diff -rq` vs pristine Release142 clone = consensus path **byte-identical** (only nil-guarded
  astrobwt debug hooks + transport-only p2p/miner diffs) `[E:EXEC]`; **Spike S1**: `bin/derod.pre-net.bak` reproduced
  the byte-identical failure `[E:EXEC bin/derod.pre-net.bak.log 23:36:18]`.
- Mechanism `[E:SRC]`: tx passed the roothash check (`transaction_verify.go:326`) but failed ZK-proof verify (`:443`)
  → the failure is in ring-member leaf BYTES fed to CLn/CRn expansion (`:368-420`). Graviton returns STORED hashes
  without recomputing from values (`node_leaf.go:63-70`) → a torn-write/bit-rot/bad-import leaf survives every root
  check until a tx's ring touches it. Prime suspect: bootstrap-era leaf (Jul-3 fastsync, versions 1..4225) never
  rewritten during 130k replayed blocks.
- `pop` REFUTED as fix `[E:SRC blockchain.go:1400-1441]`: only zeroes topo.map records, can't reach below prune
  point 7,280,004, structural sharing preserves the corrupt leaf → guaranteed re-failure after ~9h.

## GATE LEDGER (all `[E:EXEC]`)
| Step | Postcondition | Result | Evidence |
|---|---|---|---|
| S1 salvage | reward_audit over ALL 132,669 local blocks before wipe | **PASS** | 16 paid minis, 0.492 DERO, 0 fetch-miss → `reward_audit_2026-07_salvaged.txt` |
| S2 archive | corrupt datadir preserved, not deleted | **PASS** | `mv` → `<datadir>/mainnet.corrupt-20260809` |
| S2 fastsync | fresh bootstrap completes | **PASS** | `Bootstrap completed successfully` 02:42:45, **1h43m** (vs 2h22m Jul-3), peer <peer-ip> |
| S3 sync | topo==height at tip, past poison point, 0 errors | **PASS** | topo=height=7,453,737; 0 `tx verification failed`, 0 `Block rejected`, 0 panics in fresh log |
| S4 miner | proven config reconnects, GPU self-test, hashrate | **PASS** | `GPU mining ACTIVE`, GPU ~1,250 H/s, TOTAL 7,950–8,213 H/s (July parity) |
| S4 paid share | ≥1 accepted miniblock post-recovery | monitor armed | `btrqosj9l` (expected ~2–3/hr at 0.0012% paid share) |

## Salvaged ground truth (July mining, closes the ≥20-finds audit item by exhaustion) `[E:OBS chain scan]`
16 paid miniblocks / 16 blocks (7,280,529→7,303,936) = **0.492 DERO** realized; paid-share 0.0012% of 1,326,690
network slots; network ~6.56 MH/s over the 663h window; 0 orphan blocks in window. This is the COMPLETE on-chain
record for our address below 7,412,674 — the miner's higher "found" count = local acceptance, not canonical payment.

## Ops learnings
- Fastsync bootstrap is the CURE for leaf-level state corruption (rebuilds every leaf) AND bypasses any poisoned
  historical block (snapshot lands at ~tip). Cost re-measured: **1h43m**.
- Archive (`mv`), never delete — the corrupt store is the forensic sample for any future graviton leaf-audit tool.
- Background shell pollers are reaped at ~29 min in this harness — use the persistent Monitor tool for multi-hour watches.

---

# ROUND 4 (2026-08-19) — Release142 → Release151/152 HARD-FORK MIGRATION + the replay-wall discovery

## What was requested
Upgrade to Release151 (HF3 @ block 7,504,640, "nodes must upgrade before the hard fork") and migrate every
Round-1..3 enhancement; auto-execute the full pipeline with monitored background runs.

## G0 decisions (stated inline)
1. **Build from tag Release152, not Release151** `[E:EXEC git + GitHub]`: Release152 (`1d3c4b7`, published
   "latest", 2026-08-14) = Release151 (`898730e`) + "enhance transaction verification and caching for HF3
   compliance" — a consensus-critical hotfix on the same fork line. Version: `3.6.0-152.DEROHE.STARGATE+14082026`.
2. **New git-tracked project root** `<repo>` (branch `local-enhancements`, commit `d43e08e`);
   old root frozen as archive.

## Migration + gate ledger (all `[E:EXEC]`)
| Step | Postcondition | Result | Evidence |
|---|---|---|---|
| Baseline identity | DEROFDN Release142 == our audited baseline | **PASS** | tag = `9b6a8b82`, byte-identical |
| Port (7 files + new files) | patches apply with 0 fuzz; verbatim copies for 0-overlap files | **PASS** | patch output; upstream diff-lines: miner.go/astrobwt = 0 |
| Toolchain | tree builds | **PASS** after `brew upgrade go` 1.20.3→**1.26.6** (vendored kcp-go needs `math/rand/v2` ≥1.22) | exit 0 |
| Build+vet+tests | derod, dero-miner, `./...`; vet; `go test ./p2p/ ./astrobwt/...` | **PASS** | only upstream's own vet notice (present in pristine 152) |
| Flags | `--lowlatency`, `--cpu-max`, `--gpu` in --help; version 152 | **PASS** | --help output |
| Offline bench | 20-thread CPU hashrate at known ceiling | **PASS** | ~6,800 H/s (M1 Ultra parity, no regression) |
| Live `--lowlatency` | truthful LOW-LATENCY log line | **PASS** | bin/derod.log 11:52:20 |

## THE dominant Round-4 finding — Round-3 root cause REVISED `[E:OBS + E:SRC]`
Replaying the (healthy, 9-day-old) datadir toward tip, the 152 binary hit **the identical wall signature**:
canonical block `eadbe4fc…` (topo **7,467,516**, minted Aug-13, ~30k confirmations) deterministically rejected —
`transaction statement 0 verification failed`, txid `0045a6d4…` (explorer: Valid). Two INDEPENDENT datadirs
(Jul-3-era and Aug-10-era) failing identically ⇒ **not local disk rot**. The pre-HF3 chain carries an era of
transactions that fail fresh replay verification although live nodes accepted them. Upstream KNOWS: Release151/152
grandfathers 17 such txs in `blockchain/hardfork_fixes.go` and pre-caches them in `p2p/chain_sync.go` explicitly
"to allow stuck nodes to catch up" — but that list ends at height 7,422,548 and our wall block postdates it.
**Consequence: block-replay catch-up across Aug-2026 heights is unreliable network-wide until HF3 activates;
the reliable path is fresh `--fastsync` bootstrap (snapshot lands above the poisoned blocks).**
Also hit + solved en route: dead-branch catch-up deviation (34 blocks > STABLE_LIMIT=8 at topo 7,467,545) —
one restart with `--sync-node` auto-rewound to the common point exactly as `chain_sync.go:172-190` prescribes.

## Recovery execution (mirrors the proven Round-3 playbook)
| Step | Result | Evidence |
|---|---|---|
| Salvage-first | **nothing to salvage** — miner log is ground truth | Aug-10 session: `found_CPU:0, found_GPU:0, accepted_miniblocks:0` (bin/dero-miner-20260810.log) |
| Archive, never delete | `mv` → `<datadir>/mainnet.replaywall-20260819` (1.5 GB) | ls output; Aug-10 state also preserved in mainnet.zip (691 MB) |
| Fresh fastsync bootstrap | in progress (serving peer <peer-ip>:58686) | "Bootstrap in progress(step1)" percent stream; completion gate = "Bootstrap completed successfully" |
| Fresh bootstrap run | ran to **98% of step1** (peer <peer-ip>:58686, ~0.72%/min sustained), then **stopped cleanly at user request** ("I will run it manually") | 4× clean 'Stopped Blockchain' in bin/derod.log; no panics; no miner ever launched (user directive) |

## Handover state (2026-08-19 13:54)
- **Nothing running**: no derod, no dero-miner, all monitors stopped.
- `<datadir>/mainnet` = **incomplete bootstrap remnant (432 MB, height 0)**. Bootstrap progress
  lives in an in-memory var (`p2p/chain_bootstrap.go` `state sync_progress`) ⇒ **cannot resume across restarts**.
  User should `mv` it aside (e.g. `mainnet.partial-20260819`) before the manual run so the fresh bootstrap
  starts on a clean slate (classifier blocked the assistant from doing this mv).
- Archives: `mainnet.replaywall-20260819` (1.5 GB, hit the 7,467,516 wall), `mainnet.zip` (691 MB, Aug-10 snapshot
  — also cannot cross the wall; keep only as forensics).
- Manual run command (updated seeds + --lowlatency) is in ARCHITECTURE.md §20.4 and `run_derod_lowlatency.sh`.
- Expect the manual bootstrap to take ~2–3 h (single-peer, network-bound; NOT a local lever — §19 finding stands).
- **Deferred gates** (for the post-manual-run health check): topo==height at tip ≥7,497k with zero
  `tx verification failed`; crossing HF3 at **7,504,640** (block version must flip to 3); then normal operation.

## Round-4 meta (Evidence-Loop §8)
Iteration structure: OPEN loop (clone/diff/analyze upstream, enumerate mod set) → G0 (build from 152; new git root)
→ CLOSED loop 1 (port→build→test→bench gates) → CLOSED loop 2 (live run → dead-branch deviation → --sync-node fix)
→ CLOSED loop 3 (replay wall at 7,467,516 → root-cause REVISION of Round 3 → salvage-by-miner-log → archive →
fresh bootstrap) → user handover. Every claim measured or source-cited; the one *revised* prior conclusion
(Round-3 "local leaf corruption") was corrected in memory + skill + this report the moment counter-evidence
appeared — recursive self-correction grounded in evidence.

## ROUND 4b (2026-08-19/20) — user-reported errors → two upstream p2p bugs fixed → node verified AT TIP
**User's error log decoded:** their manual bootstrap had SUCCEEDED (completed 15:41:24, node ~360 from tip; the
final shutdown was their own `exit`). The scary output was two real upstream bugs + one network condition:
| Issue | Root cause | Fix / outcome |
|---|---|---|
| 47× `Recovered while handling connection` (`bltx_store/00/00: no such file`) | `fill_common` panics reading the top block mid-bootstrap (topo/state records land before block data) | **`da2fd6a`**: graceful genesis-empty fallback. **Verified live**: 0 recurrences through a full bootstrap |
| All-peer `ping failed: connection is shut down` flood | each panic killed its connection → only zombie peers left at bootstrap end | disappears with the fill_common fix (34–35 live peers held through this run's bootstrap) |
| `Invalid TX` wall #3 at topo 7,497,836 (txid `4d56a1a1…`, minted same day) | ACTIVE mutated-proof rebroadcasts pre-HF3 (txid excludes proofs; live nodes pass via cache, replayers verify bytes and fail) | strategy: fresh bootstrap → hold tip; dynamic local grandfathering REFUTED as unsafe (upstream's entries carry per-tx manual parity forensics — `transaction_execute.go:244`) |
| 10× `invalid prune detected` panics (new, exposed by fix #1) | `LocatePruneTopo` binary-search panics on the mid-bootstrap non-contiguous topo store, via `Handshake.Fill` | **`3c5ffbf`**: recover-guard at the p2p call site; swapped into `bin/derod` after the run |

**Final pipeline run `[E:OBS 2026-08-20]`:** fresh fastsync (18:14 → 00:57:47, ~6h43m — slow peers; step1 ~3.5h,
step2 ~3.2h, one mid-step2 peer failover that RESUMED from in-process state) → catch-up with **zero walls in the
gap** → **AT TIP 7,499,969, byte-for-byte with explorer.dero-node.net (same height 7,499,969, same difficulty
7,555,392 at the same instant)** → topo==height, 34 peers, 0 tx-verification errors and 0 panics post-bootstrap →
stopped cleanly at user request (`Stopped Blockchain` 01:03:45). Miner never launched (user directive).
**Datadir `<datadir>/mainnet` is healthy and at tip** — the user's manual run needs NO cleanup, just start it.
HF3 crossing (block 7,504,640, ~25h out) remains the one deferred gate; a node at tip verifies live and is immune
to the replay walls.

## ROUND 4c (2026-08-20 ~11:00) — user-reported "errors" at tip → diagnosed BENIGN, node untouched
User pasted GetObject/ping errors from their (healthy, at-tip) manual run. Census of ALL ERRORs over the 10h run
`[E:EXEC log census]`: 88 peer-churn (dropped WAN conns, auto-redial), 12 `open /root/daemon2/... no such file`
= the REMOTE peer's disk error echoed verbatim over rpc2 (Linux path on a Mac = the tell; our bltx_store intact),
10 raced-closed-pipe, **0 tx-verification failures, 0 panics** (both p2p fixes holding in production).
Live check: height=topo=7,501,932, status OK, 36 peers, extending at network rate.
**G0: NO code change, NO restart** — touching a healthy at-tip node ~13h before HF3 is refuted by risk/benefit.
Armed observe-only monitor for the HF3 crossing (block 7,504,640): notifies on crossing (+ fork-block header
version), any tx-verification error, stall, or node exit.

## ROUND 4d (2026-08-21 ~00:20) — ★ HARD FORK 3 CROSSED CLEANLY `[E:OBS]`
Fork block **7,504,640** accepted: header **major_version 3, minor_version 3** (RPC GetBlockHeaderByTopoHeight).
Node continued extending immediately (height 7,504,642+, topo==height, 34 peers, status OK), **0 verification
errors / 0 panics through the fork window**. The migration's final deferred gate is CLOSED. Post-HF3 the
mutated-proof replay-wall class is ended by consensus (full-bytes tx-cache key + new validation) — normal
restart/replay semantics are restored; fastsync-only catch-up is no longer mandatory. Uptime through fork on the
user's manually-run node: continuous since 2026-08-20 ~01:10.

## ROUND 5 (2026-08-21 ~06:00–08:00) — post-pop recovery, Release152 tag-skew port, ★ CHAIN SPLIT DISCOVERED, v2-peer filter
**Trigger:** user reported "node sync experiencing issues", had manually popped blocks (3× `Rewind successful`
05:28–05:31, ~2,900 blocks: 7,505,475 → 7,502,573, i.e. BELOW the HF3 boundary), then stopped the node.

**Errata on Round 4d** `[E:LOG]`: (1) the height crossing of 7,504,640 happened ~01:10 (hour-00 log tops out at
height 7,504,606 @ 00:59:46; the ~00:20 reading tracked a different counter). One v2 straggler block
`54219c50…` was correctly rejected at 01:11:03 ("invalid fork version") — that was the fork moment. (2) "normal
replay semantics restored" holds only for post-fork heights; replaying PRE-fork heights still needs the
grandfather table (see below).

**Forensics — the node was HEALTHY when popped** `[E:LOG]`: after crossing, it tracked the live tip at ~198
blocks/hour (18.6 s cadence) with 0 real errors from 02:00 → 05:28 (max height 7,505,475 @ 05:28:15). The pops
were unnecessary; the "unable to sync" impression likely came from comparing against a v2-chain explorer (below).

**Release152 tag skew across orgs** `[E:GIT]`: deroproject/derohe tag Release152 = `02f6e67` = our DEROFDN base
`1d3c4b7` + PR #199 (`dc8780f`): **31 more grandfathered txs** in blockchain/hardfork_fixes.go — including our
replay wall #1 `0045a6d4…` @ 7,467,516 (Tx_Parity: true) — removal of stale entry `023e2dd8…` @ 7,418,672, and
ping-log demotion Error→Info (independently confirms our Round-4c "benign" census). DEROFDN `community-dev`
(`161c7d8`) adds **29 more** entries (7,482,913–7,497,942) including wall #3 `4d56a1a1…` @ **7,497,836**.
Upstream did the per-tx parity forensics we had refuted as unsafe to do locally. **Adopted verbatim + rebuilt:
commit `4712b7b`** (75-entry table; covers all three walls we ever hit). Entries only affect replay of pre-HF3
heights — no post-fork consensus impact.

**Recovery run** `[E:OBS]`: relaunched on the popped datadir with the fixed binary. Resynced 7,502,573 → tip
with **0 errors** (the popped pre-fork window 7,502,573→7,504,640 held no wall). HF3 re-crossed and re-verified:
topo 7,504,640 == height 7,504,640, hash `e454090e…`, **major_version 3**. At-tip confirmed at 7,505,8xx
(≤6 blocks/90 s = network cadence).

**★ CHAIN SPLIT (live)** `[E:OBS][E:RPC]`: at 07:21, four different peers offered chains sharing ancestry only
to **7,504,602** ("deviated too much", their common start below the fork). Cross-checked explorer
**explorer.dero-node.net: its block at height 7,504,640 is `54219c50…` major_version 2** — the exact block our
node rejected at 01:11. That explorer follows the **non-upgraded v2 remnant chain** (difficulty 2.1 M ≈ half of
our v3 chain's 4.1–4.5 M; ~20 s cadence; slightly shorter). Our chain is the consensus chain: both orgs'
Release152 defines HF3, we hold ~2× the split's hashrate, 29/33 peers serve v3.
Chain fingerprints @ height 7,504,640 — **v3 (correct): `e454090e…`** / v2 (remnant): `54219c50…`.

**New enhancement** `[E:GIT]`: v2-peer filter, commit `3195f3b` — Connection.update() drops any peer reporting
Height ≥ MAJOR_HF3_HEIGHT+STABLE_LIMIT with Top_Version < 3. Kills the deviated-too-much churn, saves wasted
sync attempts, and defuses the --sync-node footgun (chain_sync.go:172 would Rewind_Chain ~1,000 blocks onto the
v2 branch if a v2 peer were chosen as sync node). Testnet unaffected (v3 from genesis). Graceful restart onto
the new binary; instant re-tip.

**Operating rules while the v2 remnant lives:** (1) NEVER `pop` / `--sync-node` on a node that extends at ~18–19 s
cadence — measure cadence + error census FIRST; (2) before trusting ANY explorer, fingerprint it: its block at
height 7,504,640 must be `e454090e…`; (3) the local node's RPC is ground truth (explorer.dero.io and
explorer.derofoundation.org were both unreachable during this round).

**Round-5 addendum:** (1) `0de1854` — filter refined: dropped v2 peers are now also banned 1h (`Ban_Address`);
the first 15 min showed 141 drop events from redial churn. (2) Ops mishap, caught + fixed: a restart used
`pgrep -f "bin/derod"` which matched a monitoring shell instead of the daemon → the monitor got the SIGINT and a
second derod launched against the SAME datadir (all port binds failed; store opened). Duplicate killed within
seconds via exact pid; primary node unharmed (RPC verified before/after). Procedure hardened: match the exact
daemon pid, wait for BOTH process exit AND port release (lsof), verify single instance after relaunch.
Final deployed state: single derod (binary = `0de1854`) at live v3 tip.

---

## ROUND 6 — 64-hour health audit of the manual run (2026-08-24, 00:19 → 00:35 PDT)

**Question asked:** "check the health of the node — if it's experiencing any issues, fix those."
**Verdict: the node is healthy.** No stall, no fork, no data problem. Two latent defects were found by
census (not by symptom) and fixed in code; two items are infrastructure and need the router, not the daemon.

### Measured state (single derod, pid 73657, uptime 2 d 16 h — started 2026-08-21 08:16:11)

| Metric | Measured | Reading |
|---|---|---|
| Blocks extended | 12,453 (7,506,016 → 7,518,468) over 230,657 s | **18.52 s/block** vs 18 s network target |
| Blocks per hour | 186–199 across all 64 h, no hour below 186 | flat — no degradation, no catch-up bursts |
| Longest inter-block gap | 116 s (×2) | normal Poisson tail at an 18 s target |
| Reorgs | **0** — `Chain extended` strictly monotonic over 12,453 blocks; 0 `Rewind`; `alt_blocks_count` 0 | never left the canonical chain |
| Times it had to resync | **3** (`We need to resync with the peer` ×3 / `sync done` ×3) | it was at the live tip essentially continuously |
| ERROR lines | **316 total = 4.9/h** | see census below |
| `tx verification failed` / `Block rejected` / `deviated too much` / `invalid fork version` / uncaught panic | **0 / 0 / 0 / 0 / 0** | zero real consensus or sync faults |
| Chain identity | fork block 7,504,640 = `e454090e…`, `major_version 3`; tip difficulty 5.05–5.47 M | **on the v3 consensus chain** (v2 remnant runs ~2.1 M) |
| Peers | 24 outgoing / **0 incoming** | see finding #3 |
| Resources | RSS 227 MB, ~13 % of one core, datadir 1.7 GB, 2.0 TB free | comfortable |

**Error census (316 lines / 64 h).** 315 are `Call failed GetObject`, and both buckets are *other people's*
problems, exactly per the Round-4 log-forensics rule: 162 (51.4 %) carry a remote `/root/daemon2/mainnet/bltx_store/…
no such file` — a Linux path echoed back over rpc2 onto a Mac, i.e. the **serving peer** is missing the tx — and
153 (48.6 %) are `io: read/write on closed pipe`, ordinary peer churn. The 316th is the one real defect (below).

### Finding 1 — nil-block panic in the changeset server `[FIXED: d28c5b7]`

One `Recovered while handling connection` at 2026-08-22T13:55:20 (goroutine 2952081). Stack:
`p2p/rpc_changeset.go:64 → block.(*Block).serialize` on a **0x0 receiver**.

Root cause: `rpc_changeset.go:63` was **the only `Load_BL_FROM_ID` call site in the whole tree that discards the
error** (22 other call sites check it). `Load_BL_FROM_ID` returns `(nil, err)` when the block body isn't on disk —
routine here because **this node is pruned at 7,498,540**, so any peer asking for a changeset below the prune point
triggers it. `bl.Serialize()` then nil-derefs; `handle_connection_panic` catches it but tears down an otherwise good
peer connection. Upstream `community-dev` still carries the bug.

Fix: check the error, log at V(1), return it. The requesting peer (`chain_bootstrap.go:89`) simply propagates the
error and asks a different node — it does not ban us, so the change is strictly better for both sides.

### Finding 2 — peer/ban lists survived only a *clean* shutdown `[FIXED: 9612278]`

`save_peer_list()` / `save_ban_list()` were called **only** from `P2P_Shutdown()` (controller.go:721). Any exit that
isn't a clean SIGINT — SIGKILL, OOM, power loss, or the duplicate-instance situation logged in Round 5 — threw away
every peer learned since startup, and the node cold-started from the seed list. Evidence: `peers.json`/`ban_list.json`
were last written **2026-08-21 08:13**, three minutes *before* the current 64-hour run began; nothing since.

Fix: a 5-minute ticker in `maintain_connection_to_peers()` snapshots both lists. Same functions, same mutexes the
shutdown path already uses; two small JSON writes.

**Verified in isolation** (testnet datadir, ports 31011/30102/30100, live mainnet node untouched): at T+240 s no
`peers.json` existed; at **T+311 s (00:34:20) both `peers.json` and `ban_list.json` appeared while the node was still
running**, then it exited cleanly on SIGINT. That is the ticker, not the shutdown path.

### Finding 3 — inbound p2p is still zero (infrastructure, not code)

`incoming_connections_count = 0`, and `P2P.incoming` appears **0 times in the entire log since 2026-08-19**. The
listener itself is fine: `P2P is listening [::]:11011` and `lsof` shows the socket. The blocker is NAT — the Mac is
`<lan-ip>` behind gateway `<gateway>`, public IP `<public-ip>`. This confirms the earlier `KCP_PassiveOpens=0`
finding rather than adding to it.

**The one non-obvious detail: DERO HE's p2p listener is KCP, i.e. UDP.** `p2p/controller.go:575` calls
`kcp.ListenWithOptions` → `listen udp 0.0.0.0:11011`. There is **no TCP listener on 11011 at all** (`lsof` confirms:
only `UDP *:11011`, plus loopback TCP 10100/10102). Forwarding *TCP* 11011 on the router would do nothing. Forward
**UDP 11011 → <lan-ip>:11011**. macOS ALF is enabled but block-all and stealth are off, so it is not the blocker.

### Finding 4 — `--min-peers=40` is unreachable from the current pool (explains the log churn)

`peers.json` holds **40 addresses; 17 of them are v2-remnant nodes** our filter bans on sight, leaving ~23 usable —
which is exactly the 24 outgoing connections held. Because `out < Min_Peers` forever, the 200 ms connect loop
(controller.go:490) re-runs `find_peer_to_connect` 5×/s and logs `backing off from this connection` — **971 times in
64 h**. Harmless, but it is noise, not a symptom, and it will not resolve until the peer pool grows (finding 3).

### Non-issues, checked and refuted

- `white_peerlist_size`/`grey_peerlist_size` = 0 in `GetInfo`: **the RPC never sets these fields**
  (`rpc_dero_getinfo.go` assigns neither) — a reporting artifact, not an empty peer table.
- `hashrate_1hr`/`1d` = 0: these are *our node's share* of network hashrate; no miner is attached. Not a fault.
- `--fastsync` on the running command line: `blockchain.go:264-269` only clears `chain.Sync` when
  `Get_Height() <= 1`. This node started at 7,506,016, so the flag is an inert no-op at tip.
- Pruning: `prunedheight` is frozen at 7,498,540 while topo advances — no `--prune-history` was passed, so history
  now accumulates. Intended, and disk is not a constraint (1.7 GB used, 2.0 TB free).
- Log growth: 32 MB since 2026-08-19 (~6.4 MB/day, ~2.3 GB/yr) at DEBUG. Leave it — this census is only possible
  because V(1) detail is being written.

### Deployment status — deliberately NOT restarted

`bin/derod` was rebuilt with both fixes (previous binary preserved as `bin/derod.round5-backup`); the running process
keeps its own inode and was verified unaffected before and after (`ps` same pid, RPC same tip). **The node was not
restarted**: it is extending at 18.5 s/block, which is precisely the state the Round-5 operating rule says never to
disturb, and a restart from this session would also detach the interactive derod console from your terminal. Both
fixes activate on your next natural restart, using the same command line you are already running.

Gates for this round: `go vet ./p2p/` clean · `go test -count=1 ./p2p/ ./blockchain/... ./block/...` all ok ·
whole-tree build ok · isolated testnet run of the new binary: clean start, periodic persistence proven, clean SIGINT.

---

## ROUND 6b — wallet CLI built, and we are actually on Release153 (2026-08-25)

**Why `bin/` had no `dero-wallet-cli`.** Nobody ever built it. Every build in this project was a targeted
`go build -o bin/<x> ./cmd/<x>` for the two binaries in use (`derod`, `dero-miner`). Upstream's `build_all.sh`
*does* build the wallet (line 17) but it is a cross-compiling release script that emits into
`dero_darwin_amd64/`, `dero_darwin_arm64/`, `dero_darwin_universal/` — never into `bin/` — and it was never run.
The source was always present at `cmd/dero-wallet-cli`. Built now: `bin/dero-wallet-cli`, 13.3 MB.

> Note: `~/dero_darwin_universal/dero-wallet-cli-darwin` and the copy under `~/Downloads` are the
> **October 2022** official release. They predate HF1–HF3 entirely. Do not use them.

**Did the wallet change in the new release?** Yes — between `Release142` and `Release151/152`, five source files
and two new test files. Not cosmetic; four are genuine bug fixes:

| File | Change |
|---|---|
| `walletapi/daemon_communication.go` | `DecodeEncryptedBalanceNow(e)` → `DecodeEncryptedBalance_Memory(e, balance[scid])` — decode the new homomorphic balance starting from the last known value instead of from scratch (large speed win on sync) |
| ″ | **Off-by-one, twice:** `sender_idx <= RingSize` → `sender_idx < RingSize`. Valid indices are 0..RingSize−1, so history display could index `Publickeylist[RingSize]` — out-of-range / wrong sender attribution |
| ″ | `SyncHistory` header-mismatch rollback rewritten: the old `entries[:i-skip]` + `continue` could truncate wrongly and skip the decrement when several entries share a topoheight |
| `walletapi/wallet.go` | `TokenAdd` now initialises `EntriesNative` — previously panicked *"assignment to entry in nil map"* on a fresh/restored, not-yet-synced wallet |
| ″ | `Show_Transfers`, `Get_Payments_DestinationPort`, `Get_Payments_TXID`, `GetTXKey`: `Lock()` → `RLock()` (read paths no longer serialise against each other or against sync) |
| `walletapi/daemon_connectivity.go` | `Connect()` sets `Connected = false` when `test_connectivity()` fails — before, a failed connect left the wallet believing it was online |
| `walletapi/wallet_transfer.go` | `TransferPayload0`: bare `return` → `if err != nil { return }` — the old code left the transfer-construction branch early even on success |
| `cmd/dero-wallet-cli/prompt.go` | `show_transfers` no longer force-syncs with the daemon before listing |
| new | `walletapi/tx_integrated_address_test.go` (124 lines), `walletapi/wallet_test.go` (+28) |

**Release153 exists, and we already had its code.** DEROFDN tagged `Release153` = `c4e6f6b` on 2026-08-21
(five hours after our Round-5 work). Its complete non-vendor delta from Release152 is **three files**:

```
blockchain/hardfork_fixes.go  +61   16 -> 75 grandfathered txs
p2p/connection_pool.go        +-1   ping log Error -> Info
config/version.go             +-1   3.6.0-152 -> 3.6.0-153
```

Commits `dc8780f`, `390295b`, `818010e`, `161c7d8`, `c4e6f6b`. Round-5's `4712b7b` already adopted
`origin/community-dev` (`161c7d8`) wholesale, so `git diff HEAD Release153 -- blockchain/hardfork_fixes.go`
is **empty** and the entry count is **75 on both**; the ping demotion is likewise already in. **Release153
contains no wallet changes at all.** Only the version string lagged → bumped in `bf274e5`.

`bin/derod`, `bin/dero-wallet-cli` and `bin/dero-miner` all rebuilt at **3.6.0-153.DEROHE.STARGATE+21082026**.
Miner enhancement flags verified intact (`--cpu-max`, `--gpu`, `--gpu-max`).

**Upstream test-suite status (not ours).** `go test ./walletapi/...` is red: `Test_Payload_TX`
(*"expected 1520000 actual 100720000"*), `Test_Creation_TX_morecheck`, and `walletapi/xswd TestXSWDServer`.
Verified pre-existing by checking out **pristine `Release153` into a throwaway git worktree** and running the
same tests: byte-identical failures. We have made **zero** changes under `walletapi/` or `cmd/dero-wallet-cli/`
(`git diff --name-only HEAD Release153 -- walletapi/ cmd/dero-wallet-cli/` is empty). These are stale fixture
expectations in upstream's suite, not defects introduced here — but they do mean upstream's wallet tests are
not a safety net right now.

**Node state at the time of this work:** derod was **stopped**, cleanly, by you at 17:11:50 (`P2P Shutdown` →
`Mempool stopped` → `Stopped Blockchain`, ban list saved). That made the rebuild zero-risk. On your next start
it picks up Round 6's two p2p fixes plus the 153 version.

---

## ROUND 7 (2026-10-20) — the evidence harness, and the node that only looked healthy

**Asked for:** a source-code artifact covering the whole tree at the current release, produced by this project's
own harness / KAT suite / artifact suite, with the existing HTML folded in and raised to the same standard, all
cross-checked against the derod process that is running right now.

### 7.1 Built
```
harness/  prep_corpus.py · minelib.py + 7 miners · gen_deroarch.py · gen_index.py · run_gates.py ·
          kat/verify_deroarch.py · ask.py · hooks/autosync.py · kit/ (artifact-kit, vendored) ·
          corpus/ · model/{raw,verify,evidence} · runtime/ · loop/
artifacts/ dero-src-arch.html (new) · release151-migration-report.html (moved here + kit applied) · index.html (new)
```
Acceptance, all measured:

| gate | result |
|---|---|
| G1–G12 | **12/12 PASS** (cycle-6-final) |
| KATs DK01–DK20 | **20/20 ok** |
| mutation proofs | **13/13 proved** — each mutation flips its own KAT |
| determinism | two consecutive builds → identical fingerprint |
| anchors | **372/372 resolved**, 278 rows drawn, 0 refused, 8 items the miners declined to claim |
| kit gates on the retrofitted report | G5 G6 G7 G10 G11 G12 PASS · 122/122 cells cited |

Published (same URL for the report, as before):
`dero-src-arch.html` → https://claude.ai/artifact/Tyck6K4YQXGK8J3nzZfnTy ·
`release151-migration-report.html` → https://claude.ai/artifact/By1Mffm5NYDzB3XWdcudTc ·
`index.html` → https://claude.ai/artifact/56fyqKtgNGoQthTmyQYQNg

### 7.2 ★★ The node is not at the tip
The harness computed an impossible cadence (7,345 blocks in 1,667 s) and following it proved the node is
**40.4 days behind**: its newest block was minted **2026-09-10 06:00**, ≈194,000 blocks short of the live network,
ingesting at **3.5 blocks/s** — ETA ≈15 h at that net rate. Three successive `GetInfo` reads 20 s apart:
7,598,251 → 7,598,323 → 7,598,395 = 3.6 blocks/s.

Every summary field said otherwise, and each for a reason now documented:
`averageblocktime50` is derived from block **timestamps** (`rpc_dero_getinfo.go:71`) so it reads ≈18 s at any
height; `target_height` is commented out (`:74`) and always 0; `height`/`topoheight`/`stableheight` are internally
consistent; `status` is `"OK"`. Only the console prompt showed it —
`our_height/topo [best_height/best_topo]` (`main.go:331`), i.e. your own `7585741/7585741 [7786700/7786700]`.
**The decisive reading is the tip block's age** (`DERO.GetBlockHeaderByTopoHeight` at `topoheight`); it is now a
captured field, a KAT (DK20) and part of gate G9. **No action needed — leave it running.**

### 7.3 ★★ `Recover while executing SC` is a real upstream defect — do not fix it here
Full chain of custody in ARCHITECTURE.md §24.3. Both arms of the signer branch
(`transaction_execute.go:408` and `:410`) make the same `dvm.ErrorRevert` call, so the documented "burn all the
funds" path is unimplemented and reverts with a zero signer; graviton reports the missing key as a leaf collision
(`node_leaf.go:108`), `dvm/simulator.go:277` panics on it, and the recover at `:286` returns the **named** results
untouched — `(0, nil)`. The block's SC fee is silently lost. **[CORRECTED Round 11, ARCHITECTURE §27.2: `gas = tx.Fees()` is assigned before the panic and the recover assigns nothing, so the caller gets (tx.Fees(), the SC error): the fee is KEPT, err is ignored by the caller, and the burn stays burned.]** Deterministic, therefore consensus-safe; **patching
it locally would change `fees_collected`, change the coinbase and fork this node off the network.** Logged as
P2 in `harness/loop/PROPOSALS.md` so nobody later "fixes" it. The safe half (set `err`, count the event) is P1.

`Invalid Major Version in Block` ×2 at 11:55 is the Round-5 v2-remnant filter working (`block/block.go:201`).

### 7.4 Other findings now on the page
Difficulty can move at most **+13.31 % / −11.75 %** per block (computed from `E`, `M := int64(8)` and the 2× solve
clamp); the subsidy is `BaseReward >> ((h+I)/I)` with I = 7,000,000 and BaseReward = 123,000; the reward is split
per miniblock with the rounding to the integrator; the prune point sits 6,100 blocks **below** HF3 so the fork
itself is still on disk; the grandfather table holds **75** entries (counted, not quoted).

### 7.5 artifact-kit enhanced
`textkit.audit` now exempts `data-verbatim` elements — a quoted source line whose own text ends in "…" is not a
silent cut. Surfaced by the retrofit of this very report, fixed in
`~/openelm-env/working-tools/artifact-kit`, re-vendored into `harness/kit/`, documented in the kit README,
which also now records this project as an adopter and the first to gate against a live process (G9).

**Open for you, unchanged:** forward **UDP** 11011 → <lan-ip>:11011. Inbound peers are still 0.

---

## ROUND 8 (2026-10-20) — auditing the Foundation's range-proof disclosure

**Trigger:** the DERO Foundation published a range-proof soundness defect at derofoundation.co/#/press and
withdrew support for the chain. Asked to do independent forensics and fold the findings into the harness/KATs/
artifacts. The page is a Vite SPA with no server HTML; its text lives in the app bundle and the disclosure's key
symbols sit in inline `<code>` spans — reconstructed faithfully into `harness/external/derofoundation-press-20261020.txt`
(class EXT).

**Method:** a 199-agent workflow — six independent investigations × three adversarial lenses each, then a
synthesis pass; 64 findings, 39 survived adversarial review, 17 survived a second anchor re-resolution in
`mine_forensics.py`. **Scope line held throughout: defect-class characterization, never an exploit.** No agent
built, and this report does not contain, a coin-creating proof construction.

**Verdicts (full table in ARCHITECTURE.md §25):**
- **C1 (a soundness defect exists): CONFIRMED.** The inner-product generator `u_x = gparams.H^o`
  (`proof_verify.go:430`) is built on the same base that carries `-proof.mu` (`:452`); `proof.mu` is bound by no
  Fiat-Shamir challenge (it appears in the verifier once, plus one debug line). The final IP check is a string
  compare (`proof_innerproduct.go:307`, *"need something better here"*).
- **C2 (stated mechanism): REFUTED; (consequence): CONFIRMED.** No generator crosses the wire and every base is a
  NUMS constant or a verifier-recomputed function of a hard-checked challenge (`:422/:428/:430`), so the press's
  "prover-adjustable unbound generator" is wrong *as stated* — but the soundness consequence it predicts is reached
  by the blinding scalar instead.
- **C3–C7: PARTLY-CONFIRMED** (mechanics exact where checkable; the 23.9M/5M figures need off-chain forensics a
  pruned node cannot reproduce). **C8: CANNOT-DETERMINE-LOCALLY** (policy, no code referent).

**Two findings of our own (both CONFIRMED), not in the press:** the HF3 grandfather table is an *ungated, permanent*
exemption from `Proof.Verify` for its 75 txids; and the HF3 parity override reads Go's zero value on execution
paths that don't traverse the one p2p line that sets it.

**Operator takeaway (confirmed against the live node):** `total_supply` is computed from the emission formula
(`blockchain/supply.go`), not summed from balances — it prints the same number on an inflated chain, and no code
path sums the balance tree (balances are ElGamal ciphertexts). Same root as `find-attip`: the daemon's summary
numbers answer a narrower question than they look like they do.

**Harness/KAT/kit:** `harness/external/` added as an EXT root; `mine_press.py` (14 attributed claims) and
`mine_forensics.py` (anchor-re-resolving ingest) added; page gained a Disclosure-audit section; **DK21** (a quoted
claim is EXT and attributed, never asserted) and **DK22** (no finding proved only by the audited document) added;
artifact-kit README documents the reusable **EXT-under-audit** pattern. 12/12 gates, 22/22 KATs, 14/14 mutations.

**This is an audit, not an endorsement of action.** Whether/how to act on a confirmed soundness defect in a live
chain is the chain's governance call, and a local "fix" to a consensus-visible verifier would fork this node off
the network — the same doctrine as the Round-7 SC-revert finding.

## Round 9b / Round 10 (2026-10-21) — at tip, then every console error triaged

**9b.** The node reached the tip at 04:13:35 (topo 7,789,273). Over the 11.98 h watch it replayed 182,821 blocks at
4.24 blocks/s, and the ETA formula `(tip_age/18)/(rate−1/18)` was within 4 minutes. Three harness defects surfaced and
were fixed: a one-way DK20 mutation that became a no-op at tip, the external press file classed as an "experiment",
and a gate-label reuse that double-counted gates on the index.

**10.** The owner's 20-hour console capture (`harness/runtime/derod_console_20261021.log`, 15 ERROR lines) was
triaged by the new `mine_triage.py`:
- 3 × `Recover while executing SC`: anonymous SC txs (no signer on chain) whose revert looks up the zero signer.
  The printed keyhash `02dc1cbd…a23e` equals blake2s-256 of 33 zero bytes, so this is not corruption. It is the
  known upstream defect (find-screvert); do not patch it.
- 3 × `error Parsing sc`: one sender's contract used the type `collector`, but DVM has only Uint64 and String.
  The install was skipped and the sender refunded.
- 2 × `Invalid Major Version in Block` (REMOTE): the peer has an empty or garbled `.block` file.
- 4 × `bltx_store … no such file` (REMOTE): the peer announced txs it could not serve. All were mined 1–3 blocks
  later. Our NotifyINV drops the connection on such a failure (proposal P5 — implemented in Round 11).
- 1 × closed pipe in the same second: a consequence of that drop, from concurrent rpc2 handlers.
- 2 × closed pipe: ordinary churn; both peers reconnected with failcount 0.

Closed loop: two read-only adversarial verifiers judged all six rows **PARTLY**. Every cause was upheld, but the wording over-reached in each case: "every node" should be every node that *replays* those blocks, `getpath` should be `getpathtx`, the reader is rpc2's shared read loop, our own Close fires `die` on outgoing KCP, plus Uvarint's overflow case and an inferred "same source". The corrections were made in `mine_triage.py`; the verdicts are in `harness/model/verify/verdicts_triage.json`. A new fingerprint: a raw `open …: no such file` cannot come from our ReadTX, so that peer runs an older build.

Verdict: **healthy; no restart, no change to the node.** Added DK23–DK25 with mutations. 12/12 gates, 25/25 KATs,
17/17 mutations.

## Round 11 (2026-10-21) — the console errors fixed in code, verified against the live chain, installed

**Code (logging and peer handling only; consensus guard PASS against bf274e5):**
- The zero-signer SC revert now logs one V(1) line instead of an ERROR with a 3 KB stack.
- The SC parse failure is now a V(1) INFO.
- Remote and closed GetObject failures are classified by `p2p/object_errors.go` and logged as V(1) INFO.
- **P5:** a tx-only fetch the peer fails no longer drops the connection. The peer is dropped on the 8th consecutive
  failure, and only a delivered tx resets the count.
- Version build tag `+21102026`.

**Correction:** the zero-signer revert keeps the fee. Round 7's "(0, nil), fee lost" was wrong: named results
survive the recover, and `gas = tx.Fees()` precedes the panic. It has no state side effect, because payload SCIDs are
pre-cached. Confirmed by a test and by an adversarial reviewer.

**Verification:**
- 10 new unit tests under `-race`, plus the full p2p and blockchain packages.
- Two adversarial code reviews. They found 3 real issues, all fixed: V(2) would have hidden closed-pipe failures, the
  budget could be dodged by an empty reply, and stale harness text.
- A shadow control + candidate on APFS clones: 240/240 treehash and 120/120 block-hash equality with the live node,
  0 regressions.

**Evidence base:** the derod JSON file log census (21 ERROR lines in 33 h, all 6 known classes; the console showed 15).
No resyncs since the node reached the tip; the 517 resyncs logged were all during catch-up.

**Installed:** `bin/derod`, `bin/dero-miner` and `bin/dero-wallet-cli` = `3.6.0-153.DEROHE.STARGATE+21102026`;
the previous binaries are `bin/*.round10-backup`. Restarted by the operator 2026-10-21 23:18:18 on `+21102026` with `--log-dir=<datadir>/logs`; 0 ERROR lines in its first 1.6 h (log_intel).

**Harness:**
- New: `consensus_guard.py` (G13, DK26), `baseline/bf274e5/` (DK27), retired-literal log bridging, the file-log
  census, the `rt-buildskew` row, and `pipeline/fix_build_verify.py`.
- Corrected: find-screvert and find-recover-named.
- The pipeline took five iterations. Every failure was in the verification machinery: a peerless shadow, an
  unguarded empty RPC result, deleted evidence, a clone copy-order race, and a self-staling run log. None was in
  the node code.

## Round 12 (2026-10-22) — intelligence harness; 11 non-consensus fixes shipped as +22102026

**Closed loop on Round 11:** the operator restarted at 23:18 on `+21102026` with `--log-dir`. log_intel: 0 ERROR lines at
tip; mean block interval 18.84 s over the first 303 blocks.

**Discovery:** 8 investigations, each adversarially verified: 124 findings, 99 confirmed, 25 partly, 0 refuted.

**Built:**
- `harness/intel/{log_intel, datadir_intel, go_mutate}.py` and `mine_intel.py`.
- Gates G14 (datadir) and G15 (log health).
- KATs DK28 (cadence by an independent formula) and DK29 (topo.map from the Go constant).
- Consensus guard: reachability proofs, plus vendor/ and go.mod in scope.
- Pipeline: S3b mutations, S3c race, S5 feature probes, intel in S7.

**Harness fixes:**
- The KAT scratch copy of `.skills` (it had been rewriting the real SKILL).
- The `all_anchors` resolver policy.
- G9 now fails when the daemon is unreachable.
- The gate tally counts the latest cycle.
- S3 no longer passes vacuously.
- Backups are named by the build they replace.
- Baseline copies are `.go.base`.
- Ledgers live in `harness/runtime/`.

**Shipped in 3.6.0-153.DEROHE.STARGATE+22102026:**
- `DERO.GetSyncInfo`, and GetInfo `target_height`.
- The registration-tx GetTransaction panic is fixed.
- No stack traces in RPC errors.
- peers.json survives a restart and is written atomically, as is ban_list.json.
- Handshake, TreeSection, accept-loop and avg-offset robustness.
- The logr DPANIC call is fixed.
- 5 new counters.

**Verification:**
- Consensus guard PASS (5 files; storetopo.go with a computed reachability chain).
- Tests, 15/15 Go mutations, 0 races.
- Shadow 240/240 + 120/120.
- Probes: the candidate shows every fix, the control every defect.

**Coherence:** 23 stale statements corrected across docs, memories and the report. Two discovery proposals were themselves
wrong ("err stays nil"), and the verified wording was used instead.

**Operator action:** restart derod on the new binary. After the restart:
- datadir_intel's `peers-survive-reload` check turns from KNOWN to PASS.
- GetSyncInfo answers on the live node.

## Round 13 (2026-10-22) — P2P hardening, concurrency, miner intelligence, coverage; shipped as +22102026.r13

**Closed loop on Round 12:**
- `peers-survive-reload` KNOWN → PASS (0/22 stale) at the first save after the 09:45 restart.
- GetSyncInfo `synced`.
- 0 ERROR lines at tip.

**Built:**
- Frame reader bounded by received bytes; per-method outgoing deadlines; heavy-handler caps.
- Misbehaviour scoring with escalating temporary bans.
- `update()` race fixes; `exit()` leaves the pool at once.
- `DERO.GetMiningOutcome`, the stale-work signal, and inbound reachability.
- Coverage miner and risk register; G16 ratchet; DK30; txverify/minipow flows.

**Adversarial review** (4 reviewers, before any build) found ~20 issues, all fixed:
- a **remote-triggerable crash** (nil connection in front of a handler's recover);
- honest peers scored for global load and for slow block validation;
- a job hold that could not stop hashing;
- an impossible orphan reason;
- metric double-counting;
- a gameable G16, and a flow hop citing code that never runs.

**Verification:**
- Guard PASS; tests (incl. 10 new); 30/30 Go mutations; 0 races over 6 packages.
- Shadow 240/240 treehash + 120/120 block hash.
- Probes: the candidate answers GetMiningOutcome; the control (+22102026) says "no such method".
- 16/16 gates, 30/30 KATs, 22/22 mutation proofs.

**Pipeline iterations:**
- A stale mutation spec stopped run 1 before build.
- A round-frozen probe would have failed run 2; it was stopped and fixed.
- Run 3 passed.

**Installed:** `bin/*` = `3.6.0-153.DEROHE.STARGATE+22102026.r13`; previous kept as `bin/*.22102026-backup`.


## Round 14 (2026-10-22) — descriptor suffix sort ported to dero-miner; shipped as +22102026.r14

Pipeline `pipeline_20261022T154341` ended ok=True:
- guard PASS, with the new `assigned` proof that `SuffixSort` is set only in `cmd/dero-miner/fastsort.go`
- format/vet PASS; tests PASS; go mutations 35/35 caught (5 new); race 8 packages, 0 races
- build r14, with `--sort` and `--cpu-qos` checked in `--help`
- S4b minerbench: median 587.9 → 2324.1 H/s at 2 threads (×3.95), and the startup self-test installed the descriptor sort
- shadow: 120 blocks / 240 treehashes compared, 0 mismatches, 0 regressions
- install, with backups `*.22102026.r13-backup`
- project: KATs 30/30, mutations 22/22, gates 16/16

Open-loop finding closed by evidence: one new mutation was MISSED (the duplicate bitmap in `dsa.Verify`). It was an
equivalent mutant, so the code was simplified and range coverage added; the rerun caught 2/2.
Unverified until the live restart: the 20-thread total, which is shared-memory/thermal bound, so expect much less
than ×4.

## Round 15 (2026-10-22) — live r14 run analysed; operator numbers fixed; dsa BCE + PGO; shipped as +22102026.r15

**Open loop:** a 12-agent deep dive (6 discoverers, each with an adversarial verifier; `harness/runtime` copy in the
scratchpad as r15_dive.json). Confirmed:
- the r14 run was healthy: 0 ERROR/WARN, 0 panics, 6/6 paid, finds consistent with hashrate (P=0.115);
- NW ≈ D, not 10·D/18;
- the miner's earnings estimate dropped finals, its counters reset on reconnect, and its NW showed 9× on final jobs;
- derod's hashrate estimates dropped finals and did not clip to uptime;
- GetBlockTemplate gave D for final templates;
- "Block Minted" subtracted rejected from accepted;
- the v2 peer was re-banned hourly;
- dsa had bounds checks in its hot loops;
- Verify sampling at 1/256 cost 0.5%.

**Closed loop:**
- First pipeline run (`pipeline_20261022T221410`): shadow FAIL. The operator stopped the live node at 22:26:55
  (console `exit`, main.go:373), so both shadows lost their only peer. Separately, the candidate logged 3 recovered
  panics "could not find height for blid" (`feed_chunk` → `VerifyMiniblockPoW` → `Get_Difficulty_At_Tips`): a
  pre-existing race, now fixed (`unknown_tip`).
- Pipeline gained NETWORK-mode shadows.
- Rerun `pipeline_20261022T224618`:
  - guard, format and tests PASS; go mutations 40/40; race 8 packages, 0 races
  - build r15, with PGO active per `go version -m`
  - S4b on the idle box (live miner stopped): SA-IS 880 → descriptor 3,866 H/s at 2 threads (×4.39). The staged r15
    is **+3.3%** over the installed r14 (3,851–3,885 vs 3,711–3,762, three interleaved pairs each, ranges not
    overlapping).
  - shadow (network mode): candidate 120/120 treehashes and blocks equal to the control, 0 regressions, empty census
  - install, with backups `*.22102026.r14-backup`
- S7 project FAILED only at `mine_triage --capture`: connection refused, because the live node was down. Re-run
  `fix_build_verify.py --project-only` once derod is back.

## Round 16 (2026-10-23) — native C descriptor + paired SHA-256; display "regression" refuted; dsa tail bug fixed; shipped as +22102026.r16

**Open loop:** a 12-agent dive (6 discoverers plus adversarial verifiers; summary in scratchpad r16_dive.json).
- The 31.091 KH/s figure was r14's 1 s prompt aliasing 4,096-hash GPU batches (Monte Carlo max 31,091). TOTAL showed
  r15 +3.5% over r14, and interleaved r15/r14 was 1.037.
- Orphan at 7798792: a GPU share submitted about 3 s after the 9th normal miniblock. GPU paid efficiency ≈0.69
  (model). Smaller batches do not help.
- `descriptor.c` security-audited as clean. The C sort is bit-exact (652/652), with ASan, UBSan and race clean.
- Paired SHA is bit-exact on 605 inputs. Its final-SHA stage runs 27% faster.
- `--bench` truncated the live miner log; G16 had a false alarm; the v2-ban counter is in memory only; peerlist sizes
  are never assigned.

**Closed loop:**
- Applied: C sort, paired SHA, GPU stale accounting, the unknown_tip counter, per-hunk localdiff, the bench log
  path, and S4b benching a copy of the installed miner.
- Interleaved 4-way A/B, 8 rounds at 2 threads (contended), vs r15: C+pair 1.349, C 1.217, Go 1.029.
- First r16 pipeline (`pipeline_20261023T060331`): test FAIL. A race-mode run exposed a real dsa bug: the tail
  descriptors were not room-checked (index 764/764 on a fresh scratch). Fixed, with `TestFreshScratchTail` and
  `gm-dsa-tail-room`.
- Rerun `pipeline_20261023T061124`: ok=True.
  - guard, format and tests PASS
  - go mutations 46/46; race 10 packages, 0 races
  - build r16
  - S4b: staged vs installed r15 **×1.40** (3,280–3,834 vs 2,434–2,908 H/s)
  - shadow (live mode) 120/120 blocks, 240 treehashes, 0 mismatches, 0 regressions
  - install, with backups `*.22102026.r15-backup`
  - project: KATs 30/30, mutations 22/22, **gates 16/16**

## Round 17 (2026-10-23) — share-submission deep dive; template-cache fix; propagation and peer topology; unlocked mining threads; shipped as +22102026.r17

**Open loop:** two workflows ran in parallel. `wf_48129acd` (10 agents) covered orphans, CPU, GPU split, derod and
stats. `wf_d6f249b7` (8 agents) covered latency, broadcast, peers and jobs. Summaries are in scratchpad
r17_dive.json and r17s_dive.json.
- All 3 r16 orphans were CPU normal shares that lost the 9th-slot race by 0.13–0.74 s; no stale or wrong-tip work.
- The top 4 integrators build 75% of blocks.
- The 100 ms template cache delayed the final job in 17% of blocks (86 ms/block).
- `LockOSThread` cost 16–23% per thread on darwin.
- Messages went out as 4 KCP packets each.
- The peer pool forgot proven peers.
- Reachability was falsely "reachable" (shadow nodes).
- The v2-ban count reset on restart, and peerlist sizes were never assigned.
- The miner over-reported paid shares.
- GPU split: bit-exact, ×1.35–1.45 per fed thread, deferred.

**Closed loop:**
- Seven verified patches merged with 3-way merges. Two additive conflicts were resolved by keeping both sides.
- `refresh_due` now uses `<=` (verifier suggestion).
- The lock decision was extracted as `should_lock_mining_thread`: its first mutation was MISSED because no test
  checked the decision, and the new test catches it.
- `pipeline_20261023T094538`: guard, format and tests PASS; go mutations **51/51**; race 10 packages, 0 races
  - build r17
  - S4b: staged vs installed r16 **×1.59** at 2 threads (4,135 vs 2,603 median, contended)
  - shadow (live) 120/120 blocks, 240 treehashes, 0 mismatches, 0 regressions
  - install, with backups `*.22102026.r16-backup`
- Project: G16 FAILED. The mining flow chain lost its `submitShare` anchor (the signature gained `source byte`), which
  dropped the citations of `InsertMiniBlock` and `Broadcast_MiniBlock`. The anchor was fixed, and `--project-only`
  then passed: KATs 30/30, mutations 22/22, **gates 16/16**.

## Round 18 (2026-10-24) — hashrate ceiling, GPU split + respawn, pipelined sync, peer-layer security, Go modernisation; shipped as +22102026.r18

**Open loop:** two workflows ran.
- `wf_b0d17ea4-608` had 12 agents across scaling, gpusplit, metalsort, network, security and forensics, each
  adversarially verified. The summary is in scratchpad r18_dive.json.
- Round 18b covered Go modernisation; its summary is in r18go_dive.json.
- The r17 live run was clean: 0 ERROR/WARN, 30 of 30 shares paid, 0 orphans.
- The hashrate ceiling is about 43k H/s, so 2× is not reachable by tuning.
- The live hashrate drop (40k → 21–34k, 07:40 onward) had two causes, both from Round 18's own agents:
  - The GPU server died with EOF during a Metal benchmark, and the worker never restarted.
  - CPU contention pushed load to 67–81.
- Metal suffix-sort spike: 652/652 bit-exact, about 24.9k SA/s. It is not merged: its patch failed the consensus guard
  (it set `astrobwtv3.SuffixSort` outside cmd/dero-miner), and it is a research spike only.

**Closed loop:**
- 11 patches were merged into one combined patch (72 files, +6,684/−285). Fixes A–I came from verifier findings:
  - diversity counted the connection's own dial;
  - prewarm amplification;
  - batch timeout on large blocks;
  - `invalid_tx` test;
  - derod exit double-close;
  - GPU respawn;
  - bench `--cpu-max` message;
  - `/install_sc` body limit plus the wasm build;
  - version string.
- Pipeline run 1 failed at tests: `TestKCPSegmentsPerMiniblockRequest` skipped itself after loopback retransmissions
  because `DefaultSnmp` is process-wide. The test now re-measures up to 5 times before skipping.
- `pipeline_20261024T101720` results:
  - guard, format and tests PASS; go mutations **87/87**; race 15 packages, 0 races; build r18.
  - S4b: descriptor/sais ×5.32, `staged_h_per_cpu_s` 2,335.6, staged vs installed r17 ×1.225 (2-thread wall, not
    predictive; see §34.1).
  - Shadow (live): 120/120 blocks, 240 treehashes, 0 mismatches, 0 regressions.
  - Install, with backups `*.22102026.r17-backup`.
- Project G14 FAILED because `datadir_intel` peers-survive-reload still used a 3600 s retention. r17 keeps whitelisted
  peers 86400 s, and the flagged entry, <peer-ip>, was 16.5 h old. The check was fixed, and `--project-only` then
  passed: KATs 30/30, mutations 22/22, **gates 16/16**.
- `gpu-miner-poc/gpu_split_server` was compiled (`xcrun swiftc -O`) for `--gpu-mode=split`.

## Round 19 (2026-10-24 → 10-26) — NEON sort, split audit policy, platform round; shipped as +22102026.r19

**Open loop:** three workflows were verified adversarially:
- `wf_0fccc54b` with 15 agents: splitcpu, gpusort, forensics, sync, rpcws, security, goparallel, harness.
- `wf_ec298c27` with 12 agents: txflow, netlayers, wallet, storage, observability, features.
- `wf_9152cfe4`: sync and storage verifiers, plus the merge.

Summaries are in scratchpad r19_dive.json, r19b_dive.json and r19merge_wf.json. About 70 verified findings in all.

Two finders failed: sync's structured output and storage's tool outage. Both patches were verified separately.

**Closed loop:**
- The combined patch covers 112 files, +14,835/−689. It dedupes three supply-audit designs, two slow-websocket fixes
  and two metrics fixes. The hybrid GPU sort was dropped.
- Pipeline attempts:
  1. FAILED at mutate: the restore-check ran whole walletapi/xswd suites, which fail on pristine 9703e42 too. It now
     runs only each package's mutation tests. My completion watcher (`tail -F | head -1`) never fired, so this went
     unnoticed for ~41 h.
  2. The same day, the live r18 miner disabled split mode on one audit difference. The audit-strike policy was added
     (tests plus 3 mutations).
  3. 277/278: `gm-r19-hs-default-profile` was MISSED because the datagram count is load-sensitive. A
     `kcp_profile_hook` assertion was added.
  4. Test FAIL: `TestStalledClientDoesNotBlockPushes` assumed every push is delivered, but skip-when-busy is by
     design. It now re-pushes, still bounded at 500 ms per push.
- Final run, `pipeline_20261026T185835`:
  - guard and format PASS; tests PASS; go mutations **278/278**; race 19 packages, 0 races; build r19.
  - S4b (H/cpu-s, 4 threads): ×1.604 vs installed r18; split CPU side 5,028 H/cpu-s.
  - Shadow (live): 120/120 blocks, 240 treehashes, 0 mismatches.
  - Install, with backups `*.22102026.r18-backup`.
- Project: KATs 31/31, mutations 23/23, gates **16/17**. G17 "live miner healthy" correctly failed on the still-running
  r18 miner (split disabled 18:23:41; tail mean 35k). It clears with the r19 restart.

## Round 20 (2026-10-28) — r19 live forensics, GPU kernels, platform round; shipped as +22102026.r20

**Open loop:** workflow `wf_12dfa98b-8f5` (17 agents, 8 dimensions: forensics, gpukernels, cpuminer, syncp2p,
rpcwallet, security, storageops, harness; each finding adversarially verified; one merge agent). No finding was
refuted. The summary is in the session scratchpad (`r20merge/`).

**What the live r19 run showed:**
- Hashrate while mining: miner ~68–72k H/s. derod's side gives the same answer with the corrected estimator
  H = (9/5)·n·D/T, which accounts for the final miniblock at 9D: 74.8k ±13% over 61 intervals.
- The low share count (40 in 26.7 h) is miner-off time, not a ledger bound. GetMiningOutcome keeps up to 4,096 fates
  since derod started. The operator ran the miner in windows (confirmed by the user: no crash or hang).
- The miner log was truncated on every start (`os.Create`), so the r19 run's history was lost. Fixed.
- GPU split is GPU-bound: staged ~57k, `cpu_idle_tries` 280–350k/min. `feeder_ring_full_ms` was misread as
  CPU-bound; the ring is full while batches sit on the GPU. The new `feeder_cpu_backlog_ms` separates the two.
- 150k H/s is not reachable on this machine: 150k × ~200 µs of CPU sort per hash ≈ 30 cores, against 20.

**Shipped (94 files, +7,666/−237; consensus guard PASS, only config/version.go in consensus dirs):**
- GPU (`gpu_split_server.swift`): SHA rounds unrolled (×1.8–2.0), 8-wide stage-1 threadgroups (×1.8 proxy),
  overlapped proxy ×1.50–1.63. Bit-exact on 14,354 real-GPU hashes. The live staged gain is not yet measured.
- CPU: 16-lane NEON singleton scatter (sort ×1.06, own H/cpu-s ×1.03), `feeder_cpu_backlog_ms`.
- Miner ops: appending log with 32 MiB rotation into `.1`..`.3`, mode 0600. Exit reasons are logged. SIGHUP is honoured
  only when not ignored, so `nohup` still works. Getwork read deadline (half-open connections). First-relay
  sticky-loop back-off.
- derod: getwork connect/disconnect presence lines (rate-limited) and counters, `getwork_last_share_timestamp_seconds`.
  Configurable log rotation `--log-max-size/--log-max-backups/--log-max-age/--log-compress` (defaults unchanged).
  Darwin process_* metrics; `free_disk_space_bytes` now measures the datadir. Durable p2p JSON saves.
- p2p: per-peer tx-ask hold (the live 23 failed fetches → 10 asks in replay). Compact block reconstruction from local
  pools (no protocol change). Peer byte counters now counted. `DERO_SYNC_PREWARM_WORKERS`. TLS 1.2 floor. Inbound
  per-netgroup cap and accept bucket.
- RPC: Host/Origin guard on loopback binds. This fixes DNS rebinding and cross-site websocket hijacking, both confirmed
  on the live node. Configured with `DERO_RPC_ALLOWED_HOSTS` and `DERO_RPC_ALLOWED_ORIGINS`. New `DERO.GetTxStatus`
  (batched confirmations, up to 64 txids).
- Wallet: parallel history discovery plus prefetch (×2.3–5.9). Daemon calls bounded at 2 min. Ring-decoy stall bound.
  HTTP server timeouts on the wallet RPC and XSWD.
- Harness: S3a fails closed on failing or racy new tests, S3k runs KATs before install, go_mutate records upstream
  failures, `metrics_intel.py` and gate G18 (live /metrics), clone reproducibility (`.gitignore`).

**Closed loop:** pipeline `pipeline_20261028T115635` passed on the first attempt.
- guard, format, flaky (70 new tests ×3, 0 flaky), tests, KATs: PASS.
- go mutations **385/385** (3 upstream failures recorded); race 21 packages, 0 races; build r20.
- S4b at 4 threads: staged 3,064.5 vs installed r19 1,852.7 H/cpu-s, ×1.654. The agent's interleaved A/B measured
  only ×1.03, so I don't trust the gate ratio as a live projection. Split CPU side 5,457 H/cpu-s (r19: 5,028).
- Shadow (live): 120/120 blocks, 240 treehashes, 0 mismatches. Install with backups `*.22102026.r19-backup`.
- Project: KATs 32/32, mutations 27/27, gates **18/18**.
- `gpu-miner-poc/gpu_split_server` was rebuilt from the r20 source with `xcrun swiftc -O` and swapped in with `mv`.
  The previous binary was kept as `gpu_split_server.22102026.r19-backup`. The banner says `kernels=r20`.

**Open:** live A/B of the r20 GPU kernels (staged H/s vs ~57k), and `gpu_us_per_hash` double-counting
overlapped buffers, which may over-throttle `--gpu-max` (gpukernels-8). The per-socket rate limit for foreign-origin
websockets (R-6) is still open. A stray 12.9 MB tracked `dero-miner` binary sits in the repo root (F9).

## Round 21 (2026-10-28) — r20 live forensics, CPU-sort-bound split miner, platform round; shipped as +22102026.r21

**Open loop:** workflow `wf_3a03ca93-a3e` (19 agents, 9 dimensions: forensics, gpusort, cpusort, splitpipe, syncp2p,
rpcws, security, storageops, harness; one adversarial verifier each; one merge agent). Refuted: RPCWS21-E (RPC read
paths do not serialise on a chain lock) and SEC21-08 as a cost bound.

**What the live r20 run showed:**
- TOTAL 79–86k H/s with staged 73–80k (r19 ~57k). The r20 GPU kernels carried through.
- The bottleneck flipped to the CPU sort: `feeder_cpu_backlog_ms` ~39–44 s/min, `cpu_finished` 0, ~186–192 µs of CPU per
  hash. The GPU is ~92% busy on the busy-union measure, so it is close to binding as well.
- A dip to ~70k from 13:21 matched the Round 21 agents' CPU load. Agent work was reniced (benchlock `nice -n 15` plus a
  renice loop); the live rate returned to 84.5k.
- 150 KH/s is unreachable: ~28 cores of sort needed against 20. The CPU-side ceiling is ~97–108k. The GPU sort
  (op 3, opt-in, default OFF) was a net loss of ~9% live, capped at ~+2% at best.

**Shipped (101 files, +9,566/−283; consensus guard PASS, only config/version.go):**
- Miner:
  - Split stale-drop on the same-height normal→final flip (F1; 5 of 5 such shares had been orphaned).
  - cgo yield every 8 sorts (split bench ×1.056, author-measured).
  - `--gpu-max` debt charged on the wall-clock busy union (r20 gpukernels-8).
  - Zero-run sort tie-break keys (sort ×1.015–1.022).
  - Opt-in GPU sort with ABBA probe.
  - Getwork blob-length panic fixed (SEC21-01, a remote crash).
  - Foreign-keyhash job detector, fd limit raised from 20.
  - Unpredictable shm names, autoreleasepool leak fix (~21 MB/h).
  - Run ledger `bin/dero-miner.runs.jsonl`.
  - GPU binary stamps (`gpu-miner-poc/build.sh`, BUILD_STAMPS).
- p2p: grey-peer quarantine (~10 failed handshakes/min stopped), known-tx inventory, eager counters, GetObject
  unrequested-tx amplification cut, node-wide inbound frame byte budget, lagging-peer gauge.
- RPC/ws: per-socket and node-wide budgets for foreign-origin websockets (R-6), `DERO.WatchTx` and TxPool pushes,
  getwork job frame encoded once per job (×1.7–2.3 encode), wallet wakes on Height push, `ALLOWED_ORIGINS=null`
  footgun closed.
- Ops: `--prune-history` preflight (it could destroy the balance tree), wallet-cli fileverify fix, root `dero-miner`
  binary untracked.
- Harness: S4b like-for-like (the r20 ×1.654 was SA-IS vs native C; like for like ×1.04), regime cards, run ledger,
  gpu_watch, fail-open fixes, stable anchors.

**Closed loop:** five pipeline runs.
1. FAIL mutate: `gm-wallet-syncloop-quit` survived, because r21's second Quit exit hid one post-close pass. The test
   now asserts zero passes after close.
2. FAIL flaky: S3a treated `--- SKIP` (env-gated real-GPU tests) as "never ran". Fixed.
3. FAIL install: the new F7 provenance gate refused every pipeline build (the pipeline's own evidence files make
   `vcs.modified=true`). It now excuses only `harness/loop/` and `harness/runtime/`; IK28 has cases and a mutation.
4. FAIL race: 0 races but one test failed, and the 800-character tail hid which one. It did not reproduce in 4×4
   reruns. The stage now records the failing tests and the full log.
5. `pipeline_20261028T185146` PASS:
   - flaky 102 tests ×3, 0 flaky; mutations 510/510; race 21 packages, 0 races.
   - S4b like for like ×1.041 vs installed r20; split CPU side 5,792 H/cpu-s (r20 5,457).
   - Shadow 120/120 blocks, 0 mismatches.
   - Install with backups `*.22102026.r20-backup`.
   - KATs 34/34, mutations 31/31, gates **18/18**.
- `gpu-miner-poc/gpu_split_server` was installed from the merge build (banner `kernels=r21`). It was real-GPU bit-exact
  on 4,102 hashes; `build.sh --check` reports "all stamps match". The previous binary is kept as
  `gpu_split_server.22102026.r20-backup`.

**Open:** a live A/B of `--cpu-max=100`; `--min-peers=20` (only ~15–17 reachable peers); forwarding UDP 11011 for
inbound peers; F4 stuck-peer eviction; F6 mutex profile.

## Round 22 (2026-10-29) — r21 live forensics, the GPU cap made real, crypto-layer audit, platform round; shipped as +22102026.r22

**Open loop:** workflow `wf_ff537f61-150` (19 agents, 9 dimensions: forensics, gpukernels, cpusort, splitpipe,
syncp2p, rpcws, crypto, security, harness; one adversarial verifier each; one merge agent). Patch
`r22_combined.patch` md5 e31b99f4…, 151 files, consensus guard PASS (only config/version.go).

**What the live r21 run showed:**
- 83–86k H/s TOTAL, staged ~79k; GPU busy 94.6–96.0% with `--gpu-max=90` (the cap was not enforced: FOR22-1), CPU
  sort backlog 74%: co-bound. `cpu_idle_tries` is not waste: each one is a full 2-hash CPU pair (exact counter identity,
  5% of TOTAL). Stale drops 1.1–1.3% are the in-flight floor.
- A 06:44–06:58 dip to 49k came from other sessions' CPU jobs at nice 0 (not Round 22 work, which ran at nice 15).
  Measured H/s = 4,817 × miner cores + 8,000 (r = 0.991).
- derod: zero ERROR/WARN in both r21 runs; 15 outgoing peers is the whole reachable set (2 of them frozen); the router
  answers no NAT mapping protocol, so only a manual UDP 11011 forward brings inbound peers.
- 150 KH/s is not reachable: GPU staged ceiling ~83k at the live geometry, total ~90–100k depending on CPU duty;
  150k needs ~1.8× GPU and ~1.47× sort. Six new sort variants and five kernel levers were refuted with measurements.

**Shipped:** `--gpu-max` duty bucket; r22 stage-1 kernels (×0.742 GPU time, ≈0 end to end at 4096,4,2 until a geometry
A/B); exact PoW-target compare; stale-batch SHA skip; opt-in `--cpu-max/--gpu-max=auto[:floor]` ABBA tuner;
stuck-peer eviction (r21 F4); `--p2p-nat=probe`; F6 mutex profiles (miner and derod: no lock limits throughput);
opt-in `--rpc-tx-cache`; crypto: txcanon admission of non-canonical points, canonical GetRandomAddress keys, wallet
ring-order nonce-reuse fix (C3), signature input checks (C5), EncryptWithKey (C6); C1/C2/C4/C7/C8 documented
(consensus or format changes); security: known-tx sweep ×150–500, per-peer INV bucket, short GetObject replies
counted, TLS AEAD/curve floor, miner submit bucket + LastError gate, BUILD_STAMPS hex, prune Lstat; harness: G19
binding gate, miner_runs + chain join, go_mutate INVALID (22 r21 specs never compiled), atomic snapshots, S4c.

**Closed loop:** run 1 FAIL S3a (a `!race` test was run with -race; fixed 1fdfa51, IK38); run 2
`pipeline_20261029T094741` PASS: mutations 605/605, race 22 pkgs 0 races, S4b ×0.983 (noise), shadow 120/120 0
mismatches, gates 19/19. GPU server r22 installed (backup `.22102026.r21-backup`, "all stamps match").

**Open:** live `--cpu-max/--gpu-max=auto` A/B on a quiet box; geometry A/B `DERO_GSPLIT=8192,5,3`; S4c end to end
on a changed server; forward UDP 11011; C1/C7 upstream fixes; blockchain/storefs.go non-atomic writes (consensus pkg).

## Round 23 (2026-10-30) — r22 live forensics (contended box), payout path, DoS/agent/inflation protections, crypto fixes; shipped as +22102026.r23

**Live r22 finding.** The drop from 84–86k to 43–67k H/s was foreign CPU contention: six desktop-app "Helper (Renderer)"
processes at ~100% CPU each, nice 0 (load ~42). Not r22. With that app closed (05:38) the same r22 miner sampled
92.5k H/s (17.3/18 budget cores, G20 census quiet: foreign 0.61 cores, law 91,382 H/s).

**Shipped (workflow wf_f6115a56-623, 23 agents, patch md5 b97dfac1…, 108 files, merged as 1f78612):**
- Payouts: one getwork dispatcher; final share → next-height job 252 → 32 ms (own blocks), 180 → 30 ms (P2P blocks),
  first hash after restart 5.5 → 0.5 s, first job after connect ~0.9 s → 6–37 ms (loopback, measured). Payout gain
  ESTIMATE +0.3–2% (≈1.5%) until `getwork_stale_height_jobs_total / blocks` has 24 h of live data.
- Miner: run-ledger Hashes/Height restored (r22 had them inside a comment: all r22 rows read 0); contention fields;
  noise-gated duty tuner (HR23-1 "+17% at 90%" REFUTED: 90 vs 100 within noise).
- Security: remote RPC weighted bucket + behaviour scoring + escalating bans (loopback exempt); unknown-method /
  fuzz / hammer bans for automated clients (IPv6 keyed per /64); getwork per-IP cap 32, ban after 8 bad shares across
  every session of the key, one-slot gate for local shares; txprecheck refuses structurally invalid txs before state
  reads and scores the relaying peer; getwork TLS floor.
- Inflation: per-block emission auditor (balance-tree diff = published deltas + formula coinbase + SC payouts),
  4.9–5.2 ms CPU/block; alert `dero_emission_audit_alerts_total`; transient errors retried ×3 and excused.
- Crypto: C4 receiver proof check, burn-aware (CR23-1); txcanon observes only txs of ACCEPTED blocks (CR23-2);
  integrated-address port kept and size-checked (CR23-5); zero seed refused; random TLS serial.
- RPC/ws: finality RPC, GetFeeEstimate, per-miner job numbering newest-last, walletapi reconnect fixes,
  Connected=false on drop. p2p: fast stuck-peer re-eviction.
- Ledger page `artifacts/dero-r1-r22.html` (+PDF) with its generator in `artifacts/src/` (reproduces r21 byte-exact).
- GitHub copy synced to r22 (742e25b) by a private export tool as commit 6a310c9 (not pushed);
  privacy fixes: one peer IP from own logs mapped to 203.0.113.23, external-sorter name removed from comments.

**Pipeline.** Run 1 lacked `--contended-ok` (stopped at once); run 2 FAIL S3: TestR23GetworkFanoutOrderedOverSockets
skips under -race → 4ecb0f2 runs it without -race. Run 3 `pipeline_20261030T043422`: flaky 116×3 0 flaky,
mutations 743/743, race 25 pkgs 0 races, S4b ×0.999, S4c SKIP (server unchanged), shadow 120/120 240 treehashes
0 mismatches, install r23 (backups `.22102026.r22-backup`); S7 FAIL G16 (localdiff hunk merge lost
deserialize_tx → mine_localdiff splits every hunk at `+func`), then DK18 (a test comment `--password must…` now cited
→ reworded). `--project-only` `pipeline_20261030T062228` PASS: KATs 34/34, mutations 31/31, gates 21/21.

**Open:** forward UDP 11011; `--cpu-max` / `--gpu-max=auto` and `DERO_GSPLIT=8192,5,3` A/Bs on a quiet box; 24 h
live read of the payout-path counter; emission-auditor derod shadow run; C1/C7 and DVM hash gas / SC unregistered
burn (upstream, coordinated activation); storefs non-atomic writes (consensus pkg). Miner uptime is the largest
payout lever (≈6.3 DERO forgone 19:55–01:29): run it detached (tmux/launchd).

## Round 23b (2026-10-30) — uptime lever, HF3 parity on every path, admission window, emission archive, soundness gate; shipped as +22102026.r23b

**Why.** The r23 miner ran well (88–92k H/s run means) but was connected only 31 % of the 72 h before 19:10: all nine
runs ended with a typed console exit (longest gap 10.5 h). The idle ledger prices it at ≈50.5 DERO forgone against
23.1 paid (ESTIMATE). The user's soundness concerns (inflation, double-spend, range-proof, the 23.9M figure) were
answered on artifacts/dero-soundness-r23.html and asked to be addressed in code without a fork.

**Shipped (workflow wf_b294469d-fc4, 23 agents, 11 dimensions, merged as 3224c07, 83 files; consensus guard PASS):**
- Payouts: `--supervised` (typed exit ignored; stop by signal), `tools/launchd` plist generator (KeepAlive, Nice 0,
  absolute paths), derod `getwork_miner_absent_seconds` + rate-limited WARNING, opt-in `--phase-duty` (off).
- Hashrate: `--cpu-max` charged on the CPU the threads actually got (proxy ×1.008–1.107 contended; live gain an
  ESTIMATE). Clang PGO of the C sort REFUTED (×0.99–1.01). Ceiling ~100k H/s; 150k unreachable in software.
- Double-spend / crypto: HF3 table Parity applied on every block-add path (sync, chunk, compact, rewind, console
  import; CR23b-1); relay refuses non-canonical registration keys/unreduced signatures (policy only, CR23b-2); random
  getwork cert serial (CR23b-3). Simulator test: a second body of a stored TXID is refused post-HF3 and never executes.
- Security: rpc.serverInfo closed to remote/cross-site callers (it leaked the method list, start time and loopback
  traffic counters); global anomaly surge budget (simulated 1000-key probe: 0 → 900 banned); SendRawTransaction
  header peek + admission window before Deserialize (stale tx ~2.5 ms → ~2 µs; unknown tx type no longer panics);
  relay/RPC refuse the 75 HF3 TXIDs by ID.
- Inflation monitoring: auditor flows (fees, SC, payees, burns) follow reorgs; burns were never seen before (BURN_TX
  value is not serialised); archive mode audited 19,183 more mainnet blocks, all clean; crash-safe
  `emission_series.jsonl` + `issued_emission`; `DERO.GetMonetaryIntegrity` with a recomputable HF3 table digest; HF3
  forensic report (1 of the 75 bodies exists in any local store). The range-proof defect has NO node-local fix.
- RPC/ws/p2p: settled-tx GetTxStatus cache (~20× 1 txid, 60–70× 8 txids, mainnet clone); `Reorg` websocket event +
  finality monitor (local pops are `local_rewind`); lazy sync height gate; `tx_precheck_checked_total`.
- Harness: G22 soundness gate + S3s (every page unit registered and backed); idle ledger; G17 binding label; G20
  needs a full-run record; S3a re-runs race-skipping tests; localdiff own-copy citations; DK18 unlabelled seeds.
- Ledger `artifacts/dero-r1-r23.html` (Round 23 + 23b sections; R23 soundness rows corrected; `--last 21/22`
  reproduce the earlier pages byte for byte). Soundness page corrected (store begins at 7,498,540, above all 75).
- GitHub copy: synced to r23 (c7ded01); its history was then rewritten (bc09e72/581e21d/5eb7251) so no commit carries
  peer IPs or external-implementation names; the old history is kept only as a local bundle. Not pushed.
- Published pages now go out as privacy-scrubbed copies (wallet address, home paths, peer IPs, process names
  withheld): the earlier src-arch/index publishes had carried the payout address and peer IPs.

**Pipeline.** Run 1 `pipeline_20261030T205204` FAIL at mutate (853/853 caught; restore check of `./cmd/derod/rpc/`
BROKEN: an r23b test's `with_clients` cleanup left `getwork_session_count` at 1, a ghost session for the fanout test)
→ bfe3e54. Run 2 `pipeline_20261030T215745` PASS: flaky 82×3 0, mutations 853/853, race 26 pkgs 0 races, S4b ×1.011,
S4c SKIP (server unchanged), shadow 120/120 240 treehashes 0 mismatches, install r23b (backups `.22102026.r23-backup`),
KATs 34/34, harness mutations 32/32, gates 22/22.

**Open:** range-proof C1 (coordinated fork); 23.9M figure (Foundation forensics); surge budget can be triggered on
purpose; no /24 aggregate key; storefs non-atomic writes; walletapi history resync after a reorg (RPCWS23B-E);
SEC23b-2 ordering, CR23b-4 rand.Read error, RPCWS23B-C snapshot copies; quiet-box A/Bs of `--phase-duty`, the
CPU-share cap and `DERO_GSPLIT=8192,5,3`; forward UDP 11011; 24 h idle-ledger read under launchd.

## Round 23c (2026-11-01) — faster descriptor sort, sync prewarm overlap, aggregate DoS scoring, lossless websocket pushes, per-account emission audit; installed as +22102026.r23c; measured live 2026-11-02

**Why.** The request was to make the CPU sort faster so the GPU is used more, as part of Round 23. R23b had found the
split CPU-sort-bound on a contended box and close to the GPU cap on a quiet one (R23b FOR-8). Live r23b baseline
before install: quiet window 09:27–09:37, 90.5k H/s (mean of 43 TOTAL lines), 17.53 cores, 5,164 H/cpu-s, GPU busy
93.1–95.3 % of 96 % (bin/dero-miner.log, read-only); contended sample 10:05, 57,471 H/s at 10.38 cores, GPU busy
75.8 % (hashrate watcher log). The round also covered the node: the open R23b items (surge trigger, /24 key,
SEC23b-2, RPCWS23B-C/E, CR23b-4) plus p2p, sync, websockets, the emission auditor and payouts.

**Shipped (3 workflows, 12 dimensions, 24 agents: miner wf_2624ea65-0c5, node wf_5c7e92c4-c90, artifacts
wf_d2cb875d-e03; every builder checked by an adversarial verifier or reviewer, verifier fixes merged; merged as
091b35d, 69 files; consensus guard PASS):**
- Suffix sort (sortfuse): NEON pair singleton write (`DSA_PAIR`) and branch-free group split (`DSA_GSCAN`) in
  `cmd/dero-miner/dsac/descriptor.c`; thread CPU per sort ×1.047 at 1 thread (12/12 pairs, 177.38 → 169.22 µs) and
  ×1.037 at 6 threads; verifier ×1.0355–1.0534 (A/A 0.996–1.001). Bit-exact on 120,000 fresh stage-1 texts (0
  declined; the verifier used its own permutation checker) and 480 + 272 adversarial texts. Whole hash: HashC child CPU
  0.988 (verifier; builder 0.973). Live gain ESTIMATE +1–3 % H/cpu-s CPU-bound, 0–1 % on a quiet box.
- Miner: phase-exact expected shares (the 5/(9D) model over-stated expectation and deflated luck ×1.034–1.072; live
  re-read 1.038) and `final_hash_fraction` in REWARD STATS. CPU path, handoff and GPU flow: measured, no engine change
  (tests + mutations only); the `gpu_split.go` comment names `DERO_GSPLIT=8192,3,2` as the quiet-box A/B.
- P2P/sync (chainperf, p2psec): the next synced block's PoW prewarm overlaps the previous block's topo fsync
  (`DERO_SYNC_PREWARM_OVERLAP=0` disables): loopback shadow ×1.255 blocks/s (7/7 pairs, 37.2 → 49.7), verifier ×1.331
  (6/6), CPU/block 0.991–0.993, treehash identical; verifier made `finish()` panic-safe (defer) and wired the call site
  into tests. Ban-list lookups via an index (20,000 bans 8.49 ms → 42 ns; 1 ban 262 → 60 ns); penalty table pruned and
  bounded (5,000 banned records: 45.6 µs → 0.23 µs per fault); inbound /24 and /48 aggregate bans (100/100 → 0/100
  new addresses after 4 score bans in one /24); the verifier fixed a stale fast-path flag after a ban ended (×1.889
  admission CPU). Read-only `tools/storecheck` (0 problems on 20,000 clone blocks).
- Security (p2psec): trusted remote keys score ×1 during a surge (RPC-1: an established wallet banned after its 11th
  call on r23b is never banned); /24 and /48 aggregate scoring for untrusted keys (RPC-2: 4,800 → 572 probes through in
  30 min, −88 %); per-key ban before the global budget (RPC-3 = SEC23b-2: 580 → 0 global tokens). Normal-path CPU/op
  0.978–1.052 (builder), 0.988–1.042 (verifier).
- RPC/ws (rpcws): ordered, lossless Block/MiniBlock/TxPool pushes (busy client 50 % lost → 600/600; fan-out CPU
  ×1.085–1.122 per 100 clients); at most 256 txids or SC keys per remote/foreign GetTransaction/GetSC call (100k
  txids had cost 934–965 ms CPU and 421 MB); the verifier made refused bodies scored and the body precheck 37 → 0.7 µs;
  GetMonetaryIntegrity summary without list copies (RPCWS23B-C, ~×15).
- Wallet: history resync after a reorg in one call, keeping valid entries (RPCWS23B-E; 2-group reorg 3 calls → 1).
- Inflation monitoring (cryptoinfl): per-account emission check (a misattributed share and swapped commitments had
  audited ok); coinbase-shape ALERT from height 399,000; deep-rewind segment restart (window 4,096), with the
  verifier's IssuedEmission reset; GetMonetaryIntegrity carries issued, burns and payees; auditor CPU ×0.643 (verifier
  ×0.638). 15,000 + 13,000 mainnet blocks: 0 alerts, every account exact.
- Payouts: derod flip-delay counters (`getwork_dead_normal_jobs_total`, `getwork_final_flips_total`,
  `getwork_final_flip_delay_seconds`); `harness/intel/payout_census.py` (KAT, 11/11 mutations proved).
- Harness/artifacts: `harness/round.json` round registry (KAT RR1–RR4), in-repo `harness/pipeline/benchlock.py`,
  `mine_evolution.py` + DK35 (src-arch evolution section), ledger R1 → R23 comparison and enhancement curve,
  `artifacts/dero-rft.md` round prompt.

**Refuted (measured):** fused radix pass 2 + singleton write-out (×1.137 slower at 1 thread, ×1.151 at 6; random
64-byte RMW windows over a 275 KB sa), radix 3×8, quad singleton write, NEON column step; CPU time outside the sort as
a lever (1.4–1.5 % in process + ~0.6 % live; live P-core split rate 5,963 H per P-core-second at P-IPC 4.40; 16–17 %
of CPU-seconds on E-cores at 0.38× P); handoff wakeups (≤ 0.4 %), claim/lock overhead (≈ 0), chunked SHA (−24 to
−64 %, model); warp-specialised final SHA, inflight 3, depth alone, cross-batch SHA coalescing, and 8192,5,3 as the
geometry to test (no better than 8192,4,2, batches ×2.3 longer); cross-block tx-proof prewarm; suppressing
same-height job changes; a pre-add relay of our finals (most lost finals are the lower-BLID tie-break, PAY23c-8
corrected by the verifier); CR23b-4 (go1.26.6 `crypto/rand.Read` never returns an error). "A faster sort feeds the
GPU" is regime-dependent, not refuted: quiet box ≤ +1.6 % staged; contended windows had GPU busy 73.3–85.7 % with
the sort binding (verify-handoff). Geometry `DERO_GSPLIT=8192,3,2` (proxy): GPU busy per hash ×0.72–0.82, +2.9–3.7 %
on a quiet box (ESTIMATE; CPU capacity 93.15–93.9k).

**Pipeline.** Full run `pipeline_20261101T120821`: guard PASS; format PASS (3 pre-existing vet unreachable-code);
flaky PASS tests=82 flaky=0; test PASS; soundness PASS tests=29; kats PASS; mutate PASS 955/955 caught (upstream
failures recorded 3); race PASS 26 packages 0 races; build PASS r23c; minerbench REFUSED (contended: foreign 4.88
cores; descriptor/SA-IS H/cpu-s ratio 4.58, not evidence); gpubench SKIP (server sha 5aff39c8f529 unchanged); shadow
PASS 120/120 blocks, 240 treehashes, 0 mismatches, 0 regressions; install PASS; project FAIL gates 21/22 (G22: the
SOUNDNESS_CLAIMS auditor-metric anchor `emission_audit.go:243` had moved to `:265`) → fixed in 4f0dda2. Project-only
re-runs `pipeline_20261101T140320` and `pipeline_20261101T141454` PASS (KATs 35/35, harness mutations 34/34, gates
22/22) with 1 refused row each: `evolution_git.tsv` line 1 carried HEAD, so mine_localdiff's first-line anchor went
stale → `mine_evolution.py` keeps line 1 stable (8a086cd). `pipeline_20261101T142234` PASS: KATs 35/35, harness
mutations 34/34, gates 22/22, 0 refused rows (REJECTED.json []). Also found and fixed in 4f0dda2: the install stage's
backup-tag regex dropped letter suffixes, so r23b read as r23 (whose backup already existed) and the r23b binaries
were replaced with no copy → regex `r\d+[a-z]?`; r23b rebuilt from cd1be86 into `bin/*.22102026.r23b-backup` (sizes
differ from the original by build path; vcs.revision cd1be86, modified=false).

**Live measurement (2026-11-02).** r23c miner `3.6.0-153.DEROHE.STARGATE+22102026.r23c`, run from a terminal (not
launchd), 20 threads, `--cpu-max=90`, split GPU at the default `DERO_GSPLIT` 4096,4,2; miner up since ~00:53, derod
(r23c) up since 23:30. Window 01:08→01:28, n=81 15-s TOTAL lines; load avg ~50–57 (a niced scratch backup ~71 % of a core
and macOS system services). Sources: `harness/runtime/r23c_live_window_20261102.txt`,
`harness/runtime/r23c_live_extract_20261102.txt` (read-only extracts of `bin/dero-miner.log`, derod RPC, /metrics and
derod.log).
- TOTAL H/s mean 94,273, median 96,297, min 86,209, max 97,651; 17.37 cores; **5,435 H/cpu-s**; staged mean 87,904;
  GPU busy mean 95.6 % of the 96 % cap; 28 found miniblocks in the window.
- GPU split (21 per-minute lines): 0 restarts, 0 audit faults, 0 GPU/CPU mismatches, descriptor fallbacks 0;
  feeder_cpu_backlog 36.9 s/min (23.9–53.7), ring full 44.7 s/min, duty-bucket throttle 15.2 s/min; dropped_stale
  +956,878 in 20 min (~0.9 % of staged); 0 WARN/ERROR lines. REWARD STATS 01:28: luck 0.98 on 44.7 expected shares,
  final_hash_fraction 0.573.
- DERO.GetMiningOutcome 01:28: submitted 45, paid 39, orphaned 2 (slots_full), pending 4, paid_fraction 0.9512.
- DERO.GetEmissionAudit 01:28: OK, 489 audited, 0 alerts, segment 7,844,298..7,844,779, emission_consistent true,
  payees 3,331/3,331 explained, mean 3,525 µs/block (max 27,276).
- derod /metrics 01:29 (7,163 s uptime): getwork_dead_normal_jobs_total 16, getwork_final_flips_total 128,
  final_flip_delay n=14 sum 0.738 s (mean 52.7 ms; simulated L9 mean was 10.36 ms; small sample),
  getwork_miner_absent_seconds 0.
- DERO.GetSyncInfo 01:29: synced, lag 0, tip age 8 s, 13 outgoing / 0 incoming, 0 recovered panics. derod.log
  ERROR/WARN since 2026-11-01T23:00: 1 ERROR (`Call failed GetObject`, a peer's "answered 0 blocks for 4 requested" at
  start), 0 WARN. Observation: JSON-RPC now needs `Content-Type: application/json`; without it the body is empty.
- Supporting windows: r23c 11-01 16:10–16:13 n=15: 95,659 H/s, 17.89 cores, 5,348 H/cpu-s, GPU 96.0 %; same-day r23b
  11-01 15:14: 92,578 H/s, 17.58 cores, 5,265 H/cpu-s, GPU 95.4 % (R23c hashrate watcher log).

Verdicts: sort win **CONFIRMED** on H/cpu-s, +5.2 % against the r23b quiet baseline (5,164) and +3.2 % against
same-day r23b (5,265). That exceeds the 0–1 % quiet-box estimate, so part may be load/regime variance: PLAUSIBLE
magnitude. TOTAL +4.2 % (mean) against 90.5k. The GPU co-binds at 95.6 % of the 96 % cap (regime law confirmed:
quiet/semi-quiet box = GPU binds), so more H/s needs GPU-side work; the 8192,3,2 ABBA stays OPEN (user-run). Uptime
under launchd stays OPEN: the user ran the miner in a terminal and typed `exit` twice on 11-01 (16:13, 22:39); uptime
remains the biggest payout lever. 150k stays out of reach in software on this box (the reading is inside the
~90–100k ceiling band).

Closed loop after the measurement docs (a9bddfd): project-only `pipeline_20261102T013726` FAILED at miner_runs (exit 6:
L3 judged the 12 s run of 11-01 22:37:24, avg_hs 33,966 vs 416,148/12 = 34,679, on uptime_s's rounding) → fixed in
b205a4d (L3 allows uptime_s ± 0.5 s; KAT IK44 + 1 mutation); `pipeline_20261102T014053` PASS: KATs 35/35, harness
mutations 34/34, gates 22/22, 0 refused rows (records 51caf2b = the r23c measured head, registry `github_sync`).

Whole r23c run and session history (`harness/runtime/r23c_live_extract_20261102.txt`): the measured run 00:53:03 →
02:04:08 ended by a typed console exit after 4,265 s at avg 94,009 H/s (83 miniblocks + 11 blocks accepted; REWARD
STATS 02:03: luck 1.06 on 88.4 expected, paid fraction 0.967). GetMiningOutcome 02:08: 95 submitted, 92 paid, 3
orphaned (slots_full), 0 pending, paid fraction 0.9684; emission audit 622 blocks, 0 alerts, payees 4,229/4,229;
flip counters 34 dead normal jobs / 238 flips, flip delay n=30 mean 61.2 ms. derod stays up (r23c, since 23:30).
Earlier r23c runs: 16:02:31 → 16:13:38, 22:37:24 → 22:37:37, 22:38:01 → 22:39:09, 23:31:08 → 23:33:47, every one
ended by a typed console exit (5 of 5): uptime under launchd is still the open lever.

**Open (after measurement):** ~~live A/B of r23c vs r23b H/cpu-s at equal load (G20); live TOTAL/staged H/s, GPU busy, binding label~~ (measured above);
quiet-box ABBA `DERO_GSPLIT=8192,3,2`; E-core pinned sort bench; TOTAL over-count by `stale_sha_skipped` (0.30–0.42 %:
separate counter); P/E CPU split metric; storefs atomic writes and the topo F_FULLFSYNC (guarded, report-only);
spoofed-source datagrams draining the accept budget (report-only); RPC per-body aggregate item cap; pre-warm escape
of aggregate scoring; soft penalty-table bound; CI-9 wallet receiver-proof payload leak (report-only); BURN_TX never
verifies (report-only); SC partial-panic payouts audit as sc_unexplained (report-only); prewarm metrics double count;
~~live flip-delay read~~ (measured above, n=14) and the 24 h emission read (489 blocks so far, 0 alerts); `--phase-duty` A/B;
uptime under launchd; derod has no supervisor (34 % of the miner's idle hours
overlapped derod downtime; uptime 0.2667 of 86.46 h, ESTIMATE ≈112 DERO forgone); forward UDP 11011; range-proof C1
(fork).

## Round 24 (2026-11-02) — node-only round (miner paused): DoS trust and aggregate hardening, RPC body bounds, a mempool admission policy, integrity-RPC and wallet-privacy fixes, sync prewarm fixes, area intelligence, the disclosure track, coherent artifacts; installed as +22102026.r24 (derod restart pending; measured live 2026-11-02)

**Why.** The user paused miner enhancements and will not run the miner until they resume them (rft §2.7, §0.3), so
R24 is node-only: every area of `harness/areas.json` except the miner, the "Open after Round 23c" list, the
Foundation-disclosure track made a standing per-round instrument (rft §2.8, §0.5), and coherent artifacts with
src-arch regenerated every cycle (rft §2.9, §0.6). Base 04ceb55 (the r23c measured head cf89e78 plus the R24 open
commits); registry `r24`, tracks miner `paused`, node `active`.

**Open loop.** Two workflows, 10 dimensions, 20 agents (one builder + one refute-by-default verifier each): node
`wf_d8346d53-96e` (harness, security, cryptoinfl, getworkops, rpcws, txpool, chainperf, syncp2p) and
`wf_04f8d64d-c27` (areaintel, disclosure). Verifiers upheld 9 of 10; rpcws was not upheld as shipped (two inherited
B29 bypasses: an ignored params field and a non-object batch element skipped the item bound), fixed in the verifier
patch, which is the one merged. Digest in the tree: `harness/loop/runs/r24_dimension_results_20261102.json`.

**Shipped** (`r24_combined.vs-04ceb55.patch` md5 d19d3f9a38b1cece1ffd4cff5087167f, 79 files, +9,431/−303, merge
59eee1d; area intelligence + disclosure track 76fd69b; consensus guard PASS in every run, 7 consensus-package files vs
bf274e5, all pre-existing):
- **Security (B28, B30):** trust is revoked by probing, and a trusted key's unknown names score into its /24 or /48
  aggregate (S1, 16 pre-warmed keys: 4,800 → 573 probes); aggregate-only refusals are rate-limited, not scored, so a
  heavy honest /24 is no longer banned; the penalty table bound is hard (peak 85,536 → 65,536); a returning-peer
  inbound lane for addresses with a verified handshake (the return-routability cookie stays report-only). The verifier
  fixed V1 (an aggregate-shortfall refusal did not charge the key's bucket: 18,401/20,000 calls, 0 banned) and V2 (a
  neighbour could deny a trusted wallet: 1,767/1,800 refused).
- **RPC and websockets (B38, B29):** B38 is upstream jrpc2 bridge behaviour (exact Content-Type compare, empty 415/405),
  not a regression; 415/405 now carry a JSON-RPC -32600 body. At most 1,024 txids + keys per remote body, cost
  ceil(n/8) tokens per call, at most 1,024 items in flight per remote socket; loopback unbounded. The 256 × 256 batch
  costs 5.8–6.0 s child CPU (verifier; builder 5.3 s, 470 MB), not ~0.6 s. Loopback ×0.987 (verifier A/B).
- **Tx pool (new shared admission policy, `glue/txpolicy`):** RPC and relay share one admission path: identical bytes
  verified once (6 concurrent copies 466–477 → 87–97 ms CPU), invalid proofs remembered (replay 44–46 → 2.5–3.3 ms),
  a pool cap with fee-rate eviction that refuses before verification, protected template txs (verifier V-1: eviction
  could remove a tx a mining template carries, so the node rejected its own block; fixed). Mined txs no longer count
  as pending in GetFeeEstimate / GetTxStatus. B19 VERIFIED (58/58 non-registration txs of the last 20,000 blocks rank
  0), fix not shipped (consensus guard S1).
- **Crypto, wallet, emission:** CI24-1 GetMonetaryIntegrity published issued 0 / false / payees 0 on the live r23c
  node while the auditor said OK (an r23c merge listed the summary fields by hand): fixed. CI24-2 (B32) wallet-local
  guard withholds receiver proofs on a repeated ephemeral key. CI24-3 GetRandomAddress decoys were biased by tree
  depth (2^-b): node-local fix with `R24_DECOY_SLACK=2`. B22, B33, B8 documented.
- **Getwork and ops (B39, B35):** B39 is refuted as a dispatcher defect: the live 61.2 ms is a conditional mean (flips
  with a dead window), the model's L9 unconditional; replay 51.46 ms, z=1.60. New `getwork_final_flip_l9_seconds` and
  `getwork_final_flip_slow_total`. `tools/launchd-derod` (plist generator, not installed), `tools/nodehealth`,
  `tools/getworkprobe`.
- **Chain performance and sync (B18, B34):** prewarm difficulty herd removed (CPU per synced block ×0.947, verifier
  6/6; builder ×0.916; a blocks/s gain is not established on a contended box); prewarm metrics count each block once
  (17.48 → 10.00 PoW per block, shadow 24/24); cross-response prewarm overlap ×1.114 blocks/s from a live source
  (verifier, 6/6; builder ×1.132 on 3 pairs); the compact-block path now observes its txs (B18); the chain locator no
  longer spins on a topo read error.
- **Harness:** the paused miner track (`harness/kit/roundtracks.py`: G17/G18/G21 and S4b/S4c report `PAUSED (miner)`
  only while the registry says paused; KAT TR1–TR7, 32 mutations); B21 classified from a measured known-failures
  list; area intelligence (`harness/areas.json` 14 areas, `area_intel.py`, G23, KATs AI1–AI9, AR1, AR2–AR4); the
  disclosure track (`harness/loop/disclosure_track.json`, `disclosure_track.py`, G24, KAT DT1–DT9); the 120 TestR24*
  tests registered in NEW_TESTS (AI24-6, KAT NT1–NT2); BD8 redaction (legacy lint 1 → 0).
- **Artifacts (rft §2.9):** the artifact contract (rft §0.6), §6 as one ordered list, the cross-artifact coherence
  checker `harness/intel/coherence.py` (gate G25, KAT `harness/kat/test_coherence_r24.py`); `gen_index.py` links the
  current ledger page; ledger `dero-r1-r24.html` (new; r21/r22/r23 pages byte-exact).

**Disclosure track (R24 re-test).** 11 claims re-tested: C1 CONFIRMED (upstream), C2–C7 PARTLY-CONFIRMED, C8
CANNOT-DETERMINE-LOCALLY, X-EXEMPT PARTLY-CONFIRMED (closed by design), X-PARITY CONFIRMED (fixed node-locally),
X-SUPPLY CONFIRMED; 11 new defensive facts NF24-1..11; 13 fix designs: FX-F1..F4 FORK-REQUIRED, FX-N1..N9 NODE-LOCAL (4
implemented, FX-N4 and FX-N9 feasible not implemented, 3 infeasible); 150/150 anchors OK, exploit lint 0
(`harness/runtime/disclosure_track_20261102T184720Z.json`); census of the last 100,000 blocks: 15,866 proof scalars, 0
≥ Order. No exploit content; nothing changes what blocks accept.

**Pipeline.**
- `pipeline_20261102T090301` (install run): S1–S6 PASS; flaky 120 tests ×3, 0 flaky; mutations 1108/1108 (upstream failures recorded 3); race 26 packages 0 races; S4b/S4c PAUSED (miner); shadow 120 blocks, 240 treehashes, 0 mismatches; install PASS (`bin/*.22102026.r23c-backup`); S7 FAIL at mine_evolution (KeyError 'R24' → bed3ef4, KAT test_evolution_order_r24.py).
- `pipeline_20261102T103606` (project-only): PASS, KATs 35/35, harness mutations 34/34, gates 19/22 (+3 PAUSED, miner).
- `pipeline_20261102T104901`: S3 FAIL (two opt-in simulator tests registered in NEW_TESTS SKIP without their env → cc1c391, KAT NT1 refuses an env-gated test).
- `pipeline_20261102T110200` (full, `--no-install`; registry `pipeline_full`): PASS; mutations 1108/1108; race 26 packages 0 races; shadow 120 blocks, 240 treehashes, 0 mismatches; S7 KATs 35/35, harness mutations 34/34, gates 21/24 (+3 PAUSED, miner).
- `pipeline_20261102T123214` (project-only, after the registry commit): PASS, KATs 35/35, harness mutations 34/34, gates 21/24 (+3 PAUSED, miner); G22, G23, G24 PASS.
- `pipeline_20261102T125906` (project-only, closing run after the R24 artifacts commit 8bde151): PASS, KATs 35/35, harness mutations 34/34, gates 22/25 (+3 PAUSED, miner); G22, G23, G24, G25 PASS; coherence 955 statements, 0 drifts.

**Installed** `bin/derod`, `bin/dero-miner`, `bin/dero-wallet-cli` = 3.6.0-153.DEROHE.STARGATE+22102026.r24 (atomic
rename, 2026-11-02 10:32; backups `bin/*.22102026.r23c-backup`). No new derod flag; env `DERO_SYNC_PREWARM_DIFF=0`
(optional) disables the prewarm difficulty fix. derod keeps running r23c (started 2026-11-01 23:30) until the user
restarts it (rft §11, derod only); the miner stays stopped (paused).

**Live measurement:** pending (the r24 derod restart). Live readings taken during R24 were from the r23c binary and
are booked to r23c (rft §13 Live observations log): B38 empty 415 at 04:18; CI24-1 at 12:18/13:26 UTC; disclosure
`--live` 17:56 UTC S3 FAIL. (2026-11-02: measured on r24, next subsection.)

**Live measurement (2026-11-02).** derod `3.6.0-153.DEROHE.STARGATE+22102026.r24`, restarted by the user (r23c clean
shutdown 15:30:46, r24 banner 15:31:03; pid 49367, from a terminal, not launchd); no miner (paused, rft §0.3). Reads at
15:41:24 and 16:32:01, about 1 h. Sources: `harness/runtime/r24_live_first_20261102.txt`,
`harness/runtime/r24_live_hour_20261102.txt`, `harness/runtime/r24_live_txcount_20261102.txt`,
`harness/runtime/r24_live_contention_20261102.txt`, `harness/runtime/disclosure_live_20261102T234142Z.txt`,
`harness/runtime/disclosure_live_20261103T003206Z.txt`, `harness/runtime/disclosure_census_20261103T004204Z.json`.
- **Integrity RPC (CI24-1, BD7): CONFIRMED fixed.** `disclosure_track.py --live` S1–S4 PASS at 23:41 UTC (height
  7,847,566) and 00:32 UTC (height 7,847,732); S3: GetMonetaryIntegrity and GetEmissionAudit agree on 18 shared fields.
- **B38: CONFIRMED.** POST without Content-Type → HTTP 415 with the JSON-RPC −32600 body "Content-Type must be
  application/json (charset, if given, utf-8)".
- **Health.** GetSyncInfo 15:41: synced, lag 0, tip age 22.456 s, 12 out / 0 in; 16:32: synced, lag 0, tip age 27.476 s,
  12 / 0, inbound unreachable since start (B1); 0 recovered panics, 0 p2p bans, 0 tx fetch failures; derod.log since the
  banner: 0 ERROR, 0 WARN. Box census 16:40:14: contended False, foreign 7.31 cores, load1 26.1.
- **Emission audit.** 15:41: 50 audited, 0 alerts, payees 331/331. 16:32: OK, 219 audited (2 reorgs), 0 alerts, issued =
  formula 6,672,750, payees 1,447/1,447, mean 3,389 µs/block. 24 h single-segment read: pending until ≥ 2026-11-03T15:31.
- **Census.** Last 100,000 blocks (tip 7,847,749): 344 bodies, 1,301 payloads, 15,782 proof scalars, 0 non-canonical.
- **New r24 counters, 16:32: all 0** (`block_tx_roundtrip_observed_total`, `p2p_sync_prewarm_overlap_*`, `rpc_abuse_*`,
  `p2p_inbound_proven_lane_*`, `getwork_final_flips_total`). The hour had no event for them: 0 txs in the 217 blocks
  7,847,516..7,847,732, no sync, RPC on loopback with 0 inbound, no miner. So B18 and B34 stay `pending` (not refuted),
  the security bounds stay bench evidence, and the flip counters (B36, B39) are PAUSED (miner). B51: no GetRandomAddress
  call, live CPU per call pending.
- **Claims.** CONFIRMED: CI24-1, B38, no health regression over 1 h. PLAUSIBLE (bench / shadow / unit tests): B18, B34,
  CP24-1, SP24-3, B28/B29/B30, the txpool policy. PAUSED (miner): B39 / B36 flips. pending: B36 24 h, B51. Nothing
  REFUTED. New: B54 (area_intel booked a 0 count with no event as a measured value; annotated by hand).
- **Registry.** r24 `measured`; GitHub copy synced cf89e78 → b76eee1 (registry `github_sync`; public commit 7878f1c, local only).

### Round 24 addition (2026-11-02): the consensus observability layer (artifacts/dero-rft.md §2.10, §0.7)

Asked for before R25 and built in R24 (harness only: 0 Go files changed; derod pid 49367 kept running on r24, read
over read-only RPC 127.0.0.1:10102 with `Content-Type: application/json`).
- **Two observatories.** Chain: `harness/intel/consensus_intel.py` (last 3,000 blocks, 18 detectors, gate G26, area
  `consensus`, src-arch "Consensus observatory — chain"). Network peers: `harness/intel/peer_intel.py --live` (14
  detectors, gate G27, area `peers`, src-arch "Consensus observatory — network peers"). Grades OBSERVED (a rule line
  fired, cited) / ANOMALY (a stated test crossed) / NORMAL / NO-DATA; participants and peers as salted pseudonyms.
- **Workflow `wf_01bb9349-6b3`.** Both dimensions UPHELD by their adversarial verifiers, with fixes: D12 now compares
  the full HF3 fork hash read from `cmd/derod/rpc/rpc_dero_explorer.go:574` (it compared an 8-hex prefix typed from
  memory); `unresolved_miniblocks` comes from GetMiniBlocks (the header path is 0 by construction); D6 flags a clock
  offset only beyond its ± RTT/2 uncertainty; G27's private-string list covers peer_ids and builder keys.
- **Integration.** Proposal ids CO24-C1..C8 (chain) and CO24-N1..N7 (peers) → rft §7 B55–B69; B70–B72 follow-ups.
  `harness/kit/privkit.py`: every miner's raw rows are pseudonymised (`miners/minelib.emit`), so dero-src-arch.html and
  `harness/model/verified.json` carry no non-reserved IPv4 (before: 6 distinct peer or seed addresses on the page and
  10 in `verified.json`, plus 5 test literals quoted from Go tests); G27 scans the whole page,
  `verified.json` and the log-derived raw files; private captures are pruned and kept 0700/0600. `area_intel.py` reads
  both observatories' OBSERVED/ANOMALY detectors (`detector_feeds`) and node gaps; `coherence.py` gains check
  `observatory`; the ledger gains a "Consensus observatory" section. New KATs: PI13, PK1–PK4 (`test_privkit_r24.py`),
  AI10, CO16, with mutation proofs.
- **First reads.** Chain, builder (`harness/runtime/consensus_capture_20261103T044707Z.txt`): OBSERVED 1, ANOMALY 1,
  NORMAL 16; 44 participants, mean block time 18.466 s. Chain, integration
  (`harness/runtime/consensus_capture_20261103T054000Z.txt`): OBSERVED 1, ANOMALY 1, NORMAL 16; 44 participants, mean
  block time 18.494 s; difficulty rule 0 mismatches of 2,998; Nakamoto coefficient 4 (regular) and 3 (finals); D13
  v2-remnant OBSERVED; D16 finals vs regular share ANOMALY (pooling by design). Peers, verifier
  (`harness/runtime/peer_capture_20261102T210148.jsonl`): 13 out / 0 in, first-relay share 65.4 %, OBSERVED 3, ANOMALY 2.
  Peers, integration (`harness/runtime/peer_capture_20261102T214042.jsonl`): 14 out / 0 in, first-relay share 66.7 %,
  OBSERVED 3, ANOMALY 4 (D5, D9, D11, D6: one node id on two addresses whose clock offsets disagree by 180 ms, so D6 is a
  path artefact candidate, B72).

**Open after Round 24:**
- After the derod restart (r24 live reads): S3 integrity = auditor (BD7, CI24-1); compact-block observed > 0 (B18); 10
  prewarmed PoW per synced block (B34); flip L9/slow counters over 24 h (B39, B36); the 24 h emission read (B36);
  decoy CPU per call (B51); the new security counters. (Measured 2026-11-02: S3 PASS, BD7 closed; B18, B34, B51 and the
  24 h read still pending; flips PAUSED, miner; security counters 0 with no remote traffic.)
- B54 (self-detected at the measurement): area_intel books a 0 count with no event as a measured value.
- Consensus observability (R24 addition): B55–B62 chain node gaps CO24-C1..C8 and B63–B69 peer node gaps CO24-N1..N7
  (derod code, so R25 with a derod restart); B70 real peer IPv4s in Go test fixtures and comments; B71 peer IPv4s in
  tracked runtime snapshots (log_intel, triage captures); B72 observatory caveats (D6 per-node cross-check, D02, D13).
- B19 exact fee ranking needs a guard-policy decision or upstream; B40 wallet RPC has the same empty-415 bridge; B41
  test race in TestR19MethodsOnSimulatorChain; B42 GetInfo pool size counts mined txs, rebroadcast of mined txs
  (report-only); B43 intermittent wallet-built tx proof failure in the simulator; B44 pool cap soft under concurrency
  and heap per pooled tx; B45 template cache keyed on the normal count (guarded, report-only).
- B46 sync blocks/s needs a quiet-box ABBA; parallel chunk PoW at the tip unmeasured; B47 a peer that advertises
  blocks it cannot serve is re-synced every 4 s; B48 proven-lane fill by 4,096 real handshakes, a fresh ws key's burst.
- B49 harness residuals (MINER_PATHS narrower than the miner's deps; flake counted as CAUGHT; no `--root`); B50 idle
  ledger books the pause (PAUSED, miner); B52 area proposals (6 medium history-drift: r24 values booked before the last runs, 1 medium tests-unregistered);
  B53 coherence drifts (per round).
- Disclosure: FX-N4 (BD5) and FX-N9 (BD6) feasible, not implemented; BD9 non-reduced scalar test pending; FX-F1..F4
  (BD1–BD4) need a coordinated fork; C1 (B8) upstream.
- Carried: B1 forward UDP 11011 (user); B11/B31 storefs atomicity and topo fsync (report-only); B21 upstream walletapi
  tests; B30 cookie (report-only); B35 install the derod plist (user); the paused miner rows (B2–B7, B25–B27, B37, B50).
