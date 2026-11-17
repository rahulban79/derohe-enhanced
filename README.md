# DERO HE — enhanced node and miner (3.6.0-153 +22102026.r32a)

> **License: research and personal use only.** Use and distribution of this technology is subject to the Java Research License included herein ([`LICENSE`](LICENSE)); commercial use requires a separate license from the DERO Project.

An enhanced build of the DERO HE daemon (`derod`), miner (`dero-miner`) and wallet CLI. Every change is
non-consensus: it runs on the current mainnet with no fork. Highlights:

Round 32a (node build `+22102026.r32a`: the game-theory ladder, and a DVM console fix) adds:

- **A 3 to 5 wallet mainnet ladder:** one deployment, then one measured cycle per step with 3, 4 and 5 wallets, mining
  running alongside the games. Every prize round of every step had every wallet enter and reveal (15 of 15), and every
  wallet that mined claimed its own miniblocks at a flat rate per miniblock.
- **An audit bounty:** a contract that pays independent nodes to re-derive public chain facts (block headers, and each
  block's reward against the code formula), with the sponsor's answer hidden and each auditor's commit bound to its
  own address; all six audit rounds settled with every auditor matching and no reward mismatch.
- **Chain-audited economics:** each step's payoffs are re-derived from the contracts and the block headers (mining taken
  out by the consensus split, base reward plus fees); for every step they sum to exactly minus the fees.
- **Node:** the gas-estimate RPC no longer prints every interpreted contract line and a nil "error" on the console (an
  absent `--debug` was read as set); printing only, under exact consensus-guard constructs.
- **Harness:** fixes found by private-chain pre-flights and by the mainnet run itself: hex-encoded contract strings,
  the mainnet address form for audit commits, commit windows sized from measured latency, storage gas paid from the
  estimate, lost transactions resent, mining funded toward the next step's needs.

Round 32 (smart contracts on the unchanged `+22102026.r31` node build) adds (miner track paused):

- **Game-theory contracts:** three DVM-BASIC contracts for miners: an attestation of mined miniblocks with a bond, a
  challenge window and a token reward; a notary service with a same-address boost; a commit-reveal prize round with
  sponsor funding and a token-holder boost. Each has DVM tests; none changes consensus.
- **Block reward, read from the code:** what a contract can and cannot do for a miner (it cannot raise the reward or
  see which address mined), the per-miniblock split and the integrator's final share, pinned by tests.
- **Pipeline and playbooks:** a zero-touch pipeline (research, DVM census, lint, tests, economic model, playbook,
  report) and Python playbooks that run without an LLM: create wallets, mine to them, deploy the contracts, play.
- **Measured on mainnet:** two new wallets earned their coins by mining, then ran a full cycle: three contracts
  deployed, an attestation claim finalized, five prize rounds. A chain audit re-derives each round's entrants from the
  contract and takes the mining out of the payoffs, which sum to minus the fees (a closed game only redistributes).
- **Hardening from that run:** a transaction counts only in a valid block three deep, setup steps are verified by their
  on-chain effect, retries are bounded, and both players enter at the start of the commit window.

The game-theory page, its PDF and the game-theory record are in [`harness/`](harness/).

Round 31 (`+22102026.r31`) adds (node-only: the miner track was paused for this round):

- **Detectors:** seven static area detectors (RPC and P2P budgets, decoder fuzz coverage, discarded errors, crypto input
  checks, value paths, log and metric coverage, smart-contract builtins) feed every area's work list with anchored findings.
- **Node:** a block refused for a future timestamp is one log line with its skew (the 50 ms rule is unchanged), per-peer
  skew metrics, peer ids instead of addresses on the console, a cap on event subscriptions, reorg record errors reported.
- **Observability:** every derod error and warning line is classed by the error census; pool refusals are counted by reason.
- **DVM:** smart-contract install, invoke, revert and out-of-gas metrics fed from log lines outside execution, fuzz and
  simulator tests; behaviour a node cannot change alone is pinned by tests and documented, never changed.
- **Cryptography and wallet:** a decoder census pinned by tests, fuzz targets, wallet-side key checks.
- **Harness:** scoped test mutations, an opt-in cache for the guard and format stages, page checks in the regeneration,
  push-notified user actions; a sealed forensic dataset is replayed through its pinned source.

Read on a running node for 60 minutes after the restart: synced throughout, no ERROR lines, emission audit clean, the new
counters present from the start (their events did not occur in the window).

Round 30 (`+22102026.r30`) adds:

- **Miner:** a stale-SHA counter, a P/E-core split metric, the launchd profile that keeps the miner off the efficiency-core
  clamp, a shared-memory preflight; the measured defaults `--cpu-max 100`, `--gpu-max 100` and GPU split `8192,3,2`
  (×1.098 live against the same build).
- **Payouts:** 24-hour reads of orphans, job staleness and final-flip delay, a payout ledger, uptime 0.9999 over 55 h.
- **Rounds:** a round can pause and resume without loss; decisions are logged with their evidence.
- **Harness:** the miner health check reads the rotated node log chain, a quiet-window bench runner, an objective gate.

Read live: 60 samples, no restarts, the invariants held; the miner averaged 96.0 kH/s, at the measured ceiling of this box.

Round 29 (`+22102026.r29`) adds (node-only):

- **Observability:** the lazily created /metrics families exist from the start, a bridge error is a JSON-RPC error body
  and counted, a TYPE line for every family that writes its own HELP.
- **Pool and config:** the pool orders by milli-units of fee per byte; derod refuses to start on a consensus override
  set through the environment; both money-format copies exact at 128 bits.
- **Forensics:** wall and inclusion rows tagged, smart-contract payouts of the exemption window exact.
- **Harness:** bounded pipeline steps, a hang lint gate and a stall watchdog for long jobs.

Read on a running node for 60 minutes after the restart: synced throughout, no ERROR or WARN lines, emission audit clean.

Round 28d (`+22102026.r28d`) adds:

- **Merged from the community branch** (new or measured better only): chain-request lists stop at the first unreadable
  topo index instead of sending an empty block id; optional fees on the wallet's smart-contract invoke.
- **Tests:** the range-proof binding census and the proof-system assumption table as tests (no forging content), the
  nonce comparison mutations, a registration proof-of-work pin.
- **Monetary forensics:** dataset v4 of the HF3-exemption window.

Read on a running node for 60 minutes after the restart: synced throughout, no ERROR or WARN lines; a node built from the
community branch followed the same chain (120/120 hashes equal).

Round 28 (`+22102026.r28`) adds:

- **RPC:** `GetInfo` reports `tx_pool_unmined` (the pool minus the transactions of the recent blocks); the JSON-RPC
  error bodies written by the HTTP layer (shape refusals, rate-limit and ban answers, bound errors) are counted by code.
- **Metrics:** every /metrics family carries a HELP line, and a TYPE line where Prometheus defines one, from a metric
  registry embedded in the node; the chunk-path PoW verification is counted (blocks, checks, pool hits, slow checks, time).
- **Peers and sync:** executable loopback scenarios for the sync hold, the inbound-lane quota and the block-rejection
  counters; `derod --help` states the defaults the code uses.
- **Globals:** exact amount parsing, 128-bit money formatting and the offset sign fix.
- **Tests:** smart-contract install/call processing and prune-history known-answer tests (tests only, no change).
- **Monetary forensics:** dataset v3 of the HF3-exemption window (content-pinned, replays byte-exact, audit holds).
- **Harness:** a backlog truth check, a round-list check, per-step time budgets and a privacy audit of captures.

Read on a running node for 60 minutes after the restart: synced throughout, no ERROR or WARN lines, the unmined-pool
field present, the chunk PoW counters read (about one check in ten misses the miniblock pool), the HTTP-layer error
bodies counted, and HELP on every metric family.

Round 27 (`+22102026.r27`) adds:

- **RPC:** a parameter that does not decode is answered with -32602 naming the field and the accepted parameter
  names (in the message and in the error data); every error answer is counted by code, the typed refusal counters
  read 0 from the start, and the panic recovers of the emission and supply audits are counted and logged.
- **Peers:** a ban reloaded from the ban list at start is visible on /metrics and in `GetSyncInfo`.
- **Config:** a consensus parameter set through the environment is reported at start (an ERROR line per field and a
  metric); the node's behaviour is unchanged.
- **Emission:** the audited-emission series records carry coinbase payee counts; archive and stream-adapter fixes.
- **Tests:** known-answer tests for the smart-contract builtins and the difficulty rule (tests only, no change).
- **Harness:** every tool answers `--help`, a stricter architecture-page build, a faster forensics frontend KAT and a
  tracked after-restart live window.

Read on a running node for 60 minutes after the restart: synced throughout, no ERROR or WARN lines, the -32602
answers name the field, the reloaded ban and the pre-registered counters visible, payee counts in the series.

Round 26 (`+22102026.r26`) adds:

- **Peers and sync:** sync-hold strikes decay, a relayed block that brings the node level with a held peer forgives
  it, and held peers that are ahead are tried when no other peer can sync; a duplicate miniblock delivered by two
  peers at once is counted as a duplicate race instead of an insert failure, and every refusal line names its error.
- **RPC:** an unknown name gets a typed not-found (-32032); the explorer range methods refuse unknown parameter names
  (-32602) and reads below the prune point (-32031) before any store read; GetRandomAddress keeps its decoy window
  at every height.
- **Disclosure track:** a structural test pins the range-proof transcript binding identical at the head, the previous
  release and the genesis-era tag (no invalid proof is built).
- **Monetary forensics:** dataset v2 of the HF3-exemption window with every transaction body held, rows tagged by
  defect class with honest bounds, a replay of the held archive that ends at the node's own state root, and a second
  independent auditor.
- **Harness:** shadow-node teardown, daylight-saving-safe log analysis, reproducible architecture pages, network-class
  area metrics and scrubbed process snapshots.

Round 25 (`+22102026.r25`) adds:

- **RPC robustness:** a state read below the node's prune point gets a typed error (-32031) before any read instead
  of a recovered panic; every input-reachable panic in the RPC handlers returns a typed error; an unknown block hash
  gets a typed not-found (-32032); `GetTransaction` reports `txs_status`; `GetInfo` states its supply basis.
- **Consensus observability:** `DERO.GetConsensusStats` (miniblock refusals and block rejections by reason, side
  blocks, reorg monitor persisted across restarts, first-seen times); `alt_blocks_count` is set; block headers carry
  fees and first-seen times. Read on the running node: the side-block count matched the node's own list in 60 of 60
  one-minute samples.
- **Peers:** per-peer offence scores and reasons, ban reasons and sources in a sidecar file, Chain-request, INV-clip
  and unserved-object counters; a peer that answers a sync with nothing is held from sync with an escalating back-off.
- **Pool and lane:** a netgroup quota on the returning-peer inbound lane, a reduced burst for fresh remote RPC keys,
  rebroadcast skips transactions a recent block carries, the pool cap holds under concurrency.
- **Monetary forensics:** a reproducible dataset of the HF3-exemption window (content-pinned replay, two runs
  byte-exact; an independent second-implementation audit; every figure on the report traced to a dataset file). The
  75 exempt transactions are graded not decidable from public data; no inflation is shown in scope.
- **Harness:** a standing derod error census, a prune guard for every state-reading probe, a resume checkpoint, a
  tooling self-check, and a per-round soundness review page.

Round 24 (`+22102026.r24`) adds:

- **Block sync:** a single-flight difficulty warm-up in the sync PoW prewarm (CPU per synced block x0.92-0.95, shadow
  A/B); prewarm counters count each block once; transactions of compact blocks are now observed by the
  canonical-transaction census.
- **Abuse protection:** remote-RPC trust is revoked by probing and never earned by it (pre-warmed probe scenario
  4,800 -> 573 probes); a hard bound on the P2P penalty table; a returning-peer inbound lane for peers with a verified
  handshake.
- **RPC:** at most 1,024 txids + SC keys per remote request body with item-weighted cost (an uncapped 256 x 256
  GetTransaction batch cost 5.8-6.0 s CPU) and two admission bypasses closed; a JSON-RPC request with the wrong
  Content-Type gets HTTP 415 with a JSON-RPC error body.
- **Mempool:** one admission policy for RPC and relay: identical bytes verified once, proof-invalid bytes remembered,
  a pool cap with fee-rate eviction that never evicts a transaction a mining template carries.
- **Supply audit and wallet:** `GetMonetaryIntegrity` agrees with the emission auditor again (checked on the running
  node); depth-corrected decoy sampling in `GetRandomAddress`; the wallet withholds receiver proofs whose ephemeral
  key repeats; `tools/launchd-derod` writes a KeepAlive launchd plist for derod.
- **Harness:** per-area intelligence (gate G23), a per-round re-test of the Foundation's published disclosure with
  defensive facts only (G24), and a cross-artifact coherence check (G25).
- **Consensus observatory:** read-only monitoring of who makes the chain (block timing, the difficulty rule
  recomputed, miniblock structure, reorgs and finality, participant concentration) and of the peers the node talks
  to (lag, latency, clock offset, relay concentration, stuck or non-serving peers), each detector graded against the
  rule line it checks; participants and peers appear only as salted pseudonyms (gates G26 and G27).

Round 23c (`+22102026.r23c`) adds:

- **Miner:** faster descriptor sort (NEON pair singleton write and a branch-free group split, about x1.04 thread CPU
  per sort, bit-exact on 120,000 fresh texts); measured live at about +5 % hashes per CPU-second over the previous
  build; phase-exact expected-share and luck accounting in the miner's reward stats.
- **Block sync:** the next block's PoW prewarm overlaps the previous block's topo write (loopback shadow x1.26-1.33
  blocks/s, identical treehashes).
- **Abuse protection:** /24 and /48 aggregate scoring for P2P inbound sessions and remote RPC keys, established keys
  exempt from surge scoring, per-key ban checked before the global budget, indexed ban lookups and a bounded penalty
  table.
- **Websockets/RPC:** ordered, lossless Block/MiniBlock/TxPool pushes with per-client queues; at most 256 items per
  remote GetTransaction/GetSC call; a one-call wallet history resync after a reorg.
- **Supply audit:** the emission auditor checks every account (not only block sums), checks the coinbase shape and
  restarts its segment after a deep rewind.

Round 23b (`+22102026.r23b`) adds:

- **Uptime:** `--supervised` (a typed console exit no longer stops the miner) and `tools/launchd` (a KeepAlive
  launchd plist); derod reports `getwork_miner_absent_seconds` and warns when no miner is connected.
- **Double-spend hardening:** the HF3 table parity is applied on every block-add path; relay and RPC refuse the 75
  grandfathered HF3 TXIDs and any transaction outside the block validity window, from the header, before decoding.
- **Supply audit:** reorg-aware auditor flows including burns, an archive mode, a crash-safe emission series and
  `GetMonetaryIntegrity` (emission totals plus a recomputable HF3 table digest).
- **RPC security:** `rpc.serverInfo` closed to remote and cross-site callers; a global anomaly budget against
  distributed low-rate probing; settled-transaction cache for `GetTxStatus`; a `Reorg` websocket event.

Round 23 (`+22102026.r23`) adds:

- **Payout path:** one getwork dispatcher pushes the next-height job to every miner (final share to next job 252 ->
  32 ms for own blocks, 180 -> 30 ms for P2P blocks, loopback-measured), per-miner job numbering, miner job-latency
  and CPU-contention census fields in the run ledger.
- **Supply audit:** a per-block emission auditor (`glue/emission`, `GetEmissionAudit`, `tools/emission-audit`):
  the balance-tree diff must equal the published deltas + formula coinbase + SC payouts (~5 ms CPU per block).
- **Abuse protection:** weighted remote-RPC buckets with behaviour scoring and escalating bans (loopback exempt),
  getwork per-IP cap and bad-share bans, structural transaction precheck (`glue/txprecheck`) before state reads,
  getwork TLS floor, random TLS certificate serials.
- **RPC/wallet:** finality RPC, `GetFeeEstimate`, receiver payment-proof check, integrated-address port kept,
  zero seed refused, websocket reconnect fixes.

Earlier rounds:

- **Miner:** descriptor suffix sort (native C + NEON) instead of SA-IS, a Metal GPU split mode (GPU stage 1 + final
  SHA-256, CPU sort) with per-kernel timing spans, a `--gpu-max` duty bucket and an opt-in auto duty tuner, exact
  PoW target comparison, stale-batch SHA skip, bit-exact self-tests, sampled audits with GPU auto-respawn, per-run
  ledger and Prometheus metrics.
- **Network:** low-latency KCP profile, latency-ordered broadcast, first-relay peer scoring, pipelined sync, peer
  diversity, grey-peer quarantine, stuck-peer eviction, `--p2p-nat=probe` reachability probe, canonical-transaction
  admission (`glue/txcanon`), known-tx inventory budgets, inbound and frame budgets, TLS 1.2 floor.
- **RPC/websockets:** GetSyncInfo, GetMiningOutcome, GetTxStatus, WatchTx/TxPool pushes, opt-in GetTransaction result
  cache, Host/Origin guard against DNS rebinding and cross-site websockets, rate limits, bounded range calls.
- **Wallet:** parallel history sync, bounded daemon calls, HTTP timeouts, `--password` restore fix, ring-order nonce
  fix, signature input checks.
- **Harness:** `harness/` — consensus guard, mutation testing, race runs, shadow-node treehash comparison, gates.

Build and run: the section "Build and run this build" below, generated from the tree every round (Go version, build
commands, every binary's flags and defaults from its own `--help`, the mainnet ports).
Design notes: `ARCHITECTURE.md`; per-round results: `RUN_REPORT.md`; licences: `THIRD_PARTY_NOTICES.md`.
Harness scripts read the node data directory from `DERO_DATADIR` (default `~/dero-data`).

---

<!-- build-run:begin -->
<!-- generated by harness/intel/readme_build.py from the tree; current through r32a · 3.6.0-153.DEROHE.STARGATE+22102026.r32a -->

## Build and run this build

Node build `3.6.0-153.DEROHE.STARGATE+22102026.r32a`, current through Round 32a (the newest measured round of `harness/round.json`). This section is generated from the tree every round; the "DERO Installation" section further down is the upstream project's text and describes the upstream binaries.

### Build

Go 1.17 or newer (`go.mod`); the pipeline builds and tests this round with Go 1.26. From the repository root:

```bash
go build -o bin/derod ./cmd/derod && go build -o bin/dero-miner ./cmd/dero-miner && go build -o bin/dero-wallet-cli ./cmd/dero-wallet-cli
```

These are the binaries the harness pipeline builds, tests (unit, race, mutation and shadow-node stages) and installs. On macOS the optional GPU hash server is built with `gpu-miner-poc/build.sh gpu_split_server`; the game-theory wallet tool with `go build -o bin/gt-wallet ./cmd/gt-wallet`.

### Run the node (mainnet)

```bash
./bin/derod --data-dir=<datadir> --rpc-bind=127.0.0.1:10102 --getwork-bind=127.0.0.1:10100 --p2p-bind=0.0.0.0:<udp-port> --lowlatency --integrator-address=<your-address>
```

The JSON-RPC answers on port 10102 (`Content-Type: application/json`), miners connect to getwork on 10100, and P2P runs over UDP (KCP), so a router forward must be for UDP. Without `--integrator-address` the integrator reward of a block this node builds goes to the developers' address (`blockchain/blockchain.go`), so a node that serves miners should set it.

| flag | default | what the binary's --help says |
|---|---|---|
| `--data-dir=<directory>` |  | Store blockchain data at this location |
| `--rpc-bind=<127.0.0.1:10102>` |  | RPC listens on this ip:port (testnet: 127.0.0.1:40402) |
| `--p2p-bind=<ip:port>` |  | p2p server listens on this ip:port (UDP, KCP). |
| `--getwork-bind=<0.0.0.0:10100>` |  | getwork server listens on this ip:port, specify port 0 to disable listening server |
| `--integrator-address` |  | if this node mines a block,Integrator rewards will be given to address.default is dev's address. |
| `--prune-history=<50>` |  | prunes blockchain history until the specific topo_height |
| `--lowlatency` |  | Use the low-latency KCP transport profile (fast 10ms flush + fast-retransmit) for faster miniblock propagation. |
| `--p2p-nat=<off>` |  | Ask the router to forward the p2p UDP port so peers can connect in: auto (PCP, then NAT-PMP, then UPnP), pcp, natpmp, upnp, off (default) or probe (read-only: report whi… |
| `--fastsync` |  | Fast sync mode (this option has effect only while bootstrapping) |
| `--log-max-size=<100>` |  | Rotate derod.log when it reaches this many megabytes (1 to 10240) |
| `--log-max-backups=<2>` |  | Keep this many rotated logs (1 to 1000); disk use is at most size x (backups+1) |
| `--log-max-age=<0>` |  | Also delete rotated logs older than this many days (0 = no age limit) |
| `--log-compress` |  | Gzip rotated logs (the live log stays plain text) |
| `--rpc-tx-cache` |  | Cache DERO.GetTransaction answers for mined txs (each hit re-proved against the chain; ~5-7x less CPU per repeated call). |

### Mine

```bash
./bin/dero-miner --wallet-address=<your-address> --daemon-rpc-address=127.0.0.1:10100 --mining-threads=<n>
```

Each flag's text and default below are the binary's own `--help`; `tools/launchd` installs the miner as a supervised macOS service (`--supervised`).

| flag | default | what the binary's --help says |
|---|---|---|
| `--wallet-address=<wallet_address>` |  | This address is rewarded when a block is mined sucessfully. |
| `--daemon-rpc-address=<127.0.0.1:10102>` |  | Miner will connect to daemon RPC on this port (default minernode1.dero.live:10100). |
| `--mining-threads=<threads>` | the number of CPU threads of the machine it runs on | Number of CPU threads for mining |
| `--cpu-max=<percent>` | 90 | Cap per-thread CPU duty cycle to this percent (1-100) to limit heat/power; mining only, --bench always runs at full speed. auto or auto:<floor> = start at 90 and A/B-tun… |
| `--gpu=<path>` |  | Also mine on the Apple Metal GPU using the hash-server binary at <path> (e.g. gpu-miner-poc/gpu_hash_sais). |
| `--gpu-max=<percent>` | 90 | Cap GPU duty cycle to this percent (1-100) to limit heat/power; split mode enforces it as a duty bucket since r22 (r21 ran ~5 points above it: 96 keeps the r21 rate); au… |
| `--sort=<auto|native|go|descriptor|sais>` | auto | Suffix sort: auto/native = the descriptor sort in C where built (darwin/arm64), else Go; go/descriptor = the Go port; all self-tested at start and sampled while mining;… |
| `--cpu-qos=<default|initiated|interactive>` | default | macOS scheduler class for mining threads; interactive prefers P-cores |
| `--pair=<auto|off>` | auto | Hash two nonces per CPU iteration with interleaved final SHA-256 (self-tested at start) |
| `--node-rpc-address=<host:port>` |  | derod JSON-RPC (not getwork) to read which accepted shares were PAID (DERO.GetMiningOutcome, read-only). |
| `--gpu-mode=<full|split>` | full | full: the GPU hashes its own nonces end to end (gpu_hash_sais). split: the GPU computes stage 1 + the final SHA-256 into shared memory and every CPU thread only sorts st… |
| `--metrics-bind=<host:port>` |  | Serve Prometheus /metrics and a live /dashboard on this address (off by default; loopback only unless ENABLE_PUBLIC_METRICS=1). |
| `--phase-duty=<off|balanced|R:F>` | off | Duty cap by block phase (phase_duty.go): a regular-phase hash earns 9x a final-phase one. |
| `--supervised` |  | Run under a supervisor (launchd, tools/launchd): the console's exit/quit/bye are ignored; stop with SIGTERM/SIGINT (launchctl). |

### Wallet

```bash
./bin/dero-wallet-cli --wallet-file=<file> --daemon-address=127.0.0.1:10102
```

Restore with `--restore-deterministic-wallet` from your seed. The wallet file is created relative to the working directory. The wallet RPC (`--rpc-server`) binds where `--rpc-bind` says (the mainnet wallet RPC port in the code is 10103).

| flag | default | what the binary's --help says |
|---|---|---|
| `--wallet-file=<file>` |  | Use this file to restore or create new wallet |
| `--restore-deterministic-wallet` |  | Restore wallet from previously saved recovery seed |
| `--daemon-address=<host:port>` |  | Use daemon instance at <host>:<port> or https://domain |
| `--rpc-server` |  | Run rpc server, so wallet is accessible using api |
| `--rpc-bind=<127.0.0.1:20209>` |  | Wallet binds on this ip address and port |
| `--xswd-allow-remote` |  | Let other hosts open XSWD sessions (default: local only; remote clients get HTTP 403) |

### Game-theory playbooks (Round 32 onwards)

```bash
python3 -I playbooks/gt_playbook.py all --run-id demo            # a private simulator chain; spends nothing
python3 -I playbooks/gt_playbook.py all --network mainnet --dry-run   # prints the mainnet commands, spends nothing
```

Every mainnet step that spends DERO or starts a miner needs `--mainnet-confirm`; the contracts are in `gametheory/contracts/`, the design and results in `harness/dero-enhanced-game-theory.html`.

### Verify

```bash
python3 -I harness/pipeline/fix_build_verify.py --project-only   # re-project and gate the installed state
```

<!-- build-run:end -->

# Welcome to DERO
[Twitter](https://twitter.com/DeroProject) [Discord](https://discord.gg/H95TJDp) [Matrix](https://matrix.to/#/#general:matrix.dero.live) [GitHub](https://github.com/DEROFDN/derohe) [Explorer](https://explorer.derofoundation.org) [Wiki](https://wiki.dero.io)

DERO is a blockchain with Smart Contracts preserving your privacy through multiple features while staying fast, secure, and accessible to all people easily.

DERO is running since December 2017 and was previously running on a unique implementation of CryptoNote protocol with blockDAG and as migrated to this unique version for Smart Contracts, Services, better performance, better privacy and more security.

## DERO Homomorphic Encryption

### What is "Homomorphic Encryption" ?

Homomorphic encryption (HE) is a form of encryption allowing one to perform calculations on encrypted data without decrypting it first. The result of the computation is in an encrypted form, when decrypted the output is the same as if the operations had been performed on the unencrypted data.

It can be used for privacy-preserving outsourced storage and computation. This allows data to be encrypted and out-sourced to commercial cloud environments for processing, all while encrypted. In highly regulated industries, such as health care, and can also be used to enable new services by removing privacy barriers inhibiting data sharing. For example, predictive analytics in health care can be hard to apply via a third party service provider due to medical data privacy concerns, but if the predictive analytics service provider can operate on encrypted data instead, these privacy concerns are diminished.

For more details of what is Homomorphic Encryption, please see [Wikipedia](https://en.wikipedia.org/wiki/Homomorphic_encryption).  

## Summary

- [Welcome to DERO](#welcome-to-dero)
  - [DERO Homomorphic Encryption](#dero-homomorphic-encryption)
    - [What is "Homomorphic Encryption" ?](#what-is-homomorphic-encryption-)
  - [Summary](#summary)
  - [About DERO Project](#about-dero-project)
      - [Features](#features)
  - [Transactions Sizes](#transactions-sizes)
  - [Network Ports](#network-ports)
    - [Mainnet](#mainnet)
    - [Testnet](#testnet)
  - [Technical](#technical)
  - [DERO blockchain salient features](#dero-blockchain-salient-features)
      - [**Erasure Coded Blocks**](#erasure-coded-blocks)
      - [Client Protocol](#client-protocol)
      - [Proving DERO Transactions](#proving-dero-transactions)
  - [DERO Installation](#dero-installation)
    - [Installation From Source](#installation-from-source)
    - [Installation From Binary](#installation-from-binary)
    - [Running DERO Daemon](#running-dero-daemon)
    - [DERO CLI Wallet](#dero-cli-wallet)
    - [DERO Explorer](#dero-explorer)

## About DERO Project

DERO is running since December 2017 and was previously running on a unique [implementation](https://github.com/deroproject/derosuite) of CryptoNote protocol with blockDAG and as migrated to this unique version for Smart Contracts, Services, better performance, better privacy and more security.

Consensus algorithm is PoW based on [AstroBWT](https://github.com/deroproject/astrobwt), a ASIC/FPGA/GPU resistant CPU mining algorithm to improve decentralization and lower the barrier of joining the network.

DERO is industry leading and the first blockchain to have Homomorphic Encryption, bulletproofs and a fully TLS encrypted network.

The fully distributed ledger processes transactions with a  16s (sixty-seconds) average block time and is secure against majority hashrate attacks.

DERO is the first Homomorphic Encryption based blockchain to have Smart Contracts contracts on its native chain without any extra layers or secondary blockchains.

At present DERO has implemented Smart Contracts for previous mainnet implementation running on CryptoNote protocol which can be found [here](https://github.com/deroproject/documentation/blob/master/testnet/stargate.md).

#### Features

-  **Homomorphic account based model** 
Check blockchain/transaction_execute.go line 82-95

- **Instant account balances**
It need only 66 bytes of data from the blockchain.

- **~~DAG/MINIDAG with 1 miniblock every second~~**
**NOTE**: This as been replaced by a mini block system. Each block has 10 mini blocks to rewards up to 10 differents miners at the same time for each block, by splitting the difficulty and the result of the final block.
 
- **Mining Decentralization**
No more mining pools needed, with a daily ~54000 mini blocks.
Solo Mining is much more available than any others blockchains.

- **Erasure coded blocks**
Worlds first Erasure Coded Propagation protocol, which allows 100x block size without increasing propagation delays, lower bandwidth requirements and provide very low propagation time. 

- **Light weight and efficient wallets**
No more chain scanning or wallet scanning the whole chain to detect funds, no key images. By connecting to a synchronized node, you will retrieve your available funds in few seconds.

- **Small disk cost for blockchain account**
Fixed per account cost of 66 bytes in blockchain only which allow a immense scalability.

- **Anonymous Transactions**
Provide completely anonymous transactions and deniability thanks to Many-Out-Of-Many Proofs using Bulletproofs and Sigma Protocol, nobody except you and the receiver account will know the real parties of the transaction.
 
- **Fixed Transaction Size**
Only ~2.5KB for a transaction using ring size set to 8, or ~3.4 KB with ring size set to 16.
Transactions size have a logarithm growth based on the anonymity set and must be chosen in powers of 2.

- **Homomorphic Assets**
programmable Smart Contracts with fixed overhead per asset.
Your Smart Contract is open source but its data related to balances are completely encrypted like the native coin.

- **Pruning Blockchain**
Allows chain pruning on daemons to control growth of data on daemons and keep a low disk usage. This allows immense scability as you can reduce a blockchain of few hundred GBs to only few GBs while still being secure using merkle proofs.<br>
_Example_: disk requirements of 1 billion accounts (assumming it does not want to keep history of transactions, but keeps proofs to prove that the node is in sync with all other nodes)<br>
Requirement of 1 account is only 66 bytes
Assumming storage overhead per account of 128 bytes (which is constant)
Total requirements = (66 + 128)GB ~ 200GB
Assuming we are off by factor of 4, its only 800GB.<br>
Note that, Even after 1 trillion transactions, 1 billion accounts will consume 800GB only, If history is not maintained, and everything still will be in proved state using merkle roots.
And so, Even Raspberry Pi can host the entire chain.

- **Low Transaction Generation Time**
Generating a transaction takes less than 25 ms.

- **Low Transaction Verification Time**
Transaction verification takes even less than 25ms.

- **No trusted setup, no hidden parameters**
Everything is open-source, available, to anyone to provide trustless and fully decentralized blockchain.
 
- **Provability**
Senders of a transaction can prove to receivers what amount they have send without revealing themselves.


## Transactions Sizes

| Ring Size | Transaction Size (in bytes) |
|:---------:|:---------------------------:|
|     2     |             1553            |
|     4     |             2013            |
|     8     |             2605            |
|     16    |             3461            |
|     32    |             4825            |
|     64    |             7285            |
|    128    |            11839            |
|    512    |            ~35000           |

**NOTE:** Plan to reduce TX sizes further.

## Network Ports

### Mainnet

- **P2P Default Port**: 10101
- **RPC Default Port**: 10102
- **Wallet RPC Default Port**: 10103

### Testnet

- **P2P Default Port**: 40401
- **RPC Default Port**: 40402
- **Wallet RPC Default Port**: 40403

## Technical

For specific details of current DERO core (daemon) implementation and capabilities, see below:

- ~~**DAG**: No orphan blocks, No soft-forks.~~
**NOTE**: This feature has been disabled for mainnet to reduce load for small devices.

- **BulletProofs**: Non Interactive Zero-Knowledge Range-Proofs (NIZK)

- **AstroBWT**: This is memory-bound algorithm. This provides assurance that all miners are equal. ( No miner has any advantage over common miners).

- **P2P Protocol**: This layers controls exchange of blocks, transactions and blockchain itself.

- **Pederson Commitment**: (Part of ring confidential transactions): Pederson commitment algorithm is a cryptographic primitive that allows user to commit to a chosen value while keeping it hidden to others. Pederson commitment is used to hide all amounts without revealing the actual amount. It is a homomorphic commitment scheme.

- **Homomorphic Encryption**: Homomorphic Encryption is used to do operations such as addition/substraction to settle balances with data being always encrypted (Balances are never decrypted before/during/after operations in any form.).

- **Homomorphic Ring Confidential Transactions**: Gives untraceability, privacy and fungibility while making sure that the system is stable and secure.

- **Core-Consensus Protocol implemented**: Consensus protocol serves 2 major purpose:
	- Protects the system from adversaries and protects it from forking and tampering.
	- Next block in the chain is the one and only correct version of truth (balances).

- **Proof-of-Work(PoW) algorithm**: PoW part of core consensus protocol which is used to cryptographically prove that X amount of work has been done to successfully find a block.

- **Difficulty algorithm**: Difficulty algorithm controls the system so as blocks are found roughly at the same speed, irrespective of the number and amount of mining power deployed.

- **Serialization/De-serialization of blocks**: Capability to encode/decode/process blocks.

- **Serialization/De-serialization of transactions**: Capability to encode/decode/process transactions.

- **Transaction validity and verification**: Any transactions flowing within the DERO network are validated, verified.

- **Socks proxy**: Socks proxy has been implemented and integrated within the daemon to decrease user identifiability and improve user anonymity.

- **Interactive daemon**: can print blocks, txs, even entire blockchain from within the daemon
	-	`version`, `peer_list` `status`, `diff`, `print_bc`, `print_block`, `print_tx` and several other commands implemented

- **Networks**: DERO Daemon has both mainnet and testnet support.

- **Enhanced Reliability, Privacy, Security, Useability, Portabilty assured.**

## DERO blockchain salient features

- 16 Second Block time.
- Extremely fast transactions with one minute/block confirmation time.
- SSL/TLS P2P Network.
- Homomorphic: Fully Encrypted Blockchain
- Ring signatures.
- Fully Auditable Supply.
- DERO blockchain is written from scratch in Golang.
- Developed and maintained by original developers.

#### **Erasure Coded Blocks**

Traditional Blockchains process blocks as single unit of computation(if a double-spend tx occurs within the block, entire block is rejected). As soon as a block is found, it is sent to all its peers.DERO blockchain erasure codes the block into 48 chunks, dispersing and chunks are dispersed to peers randomly.Any peer receiving any 16 chunks (from 48 chunks) can regenerate the block and thus lower overheads and lower propagation time.

#### Client Protocol

Traditional Blockchains process blocks as single unit of computation(if a double-spend tx occurs within the block, entire block is rejected). However DERO network accepts such blocks since DERO blockchain considers transaction as a single unit of computation.DERO blocks may contain duplicate or double-spend transactions which are filtered by client protocol and ignored by the network. DERO DAG processes transactions atomically one transaction at a time.

#### Proving DERO Transactions

DERO blockchain is completely private, so anyone cannot view, confirm, verify any other's wallet balance or any transactions.

So to prove any transaction you require *TXID* and *deroproof*.
deroproof can be obtained using `get_tx_key` command in dero-wallet-cli.

Enter the *TXID* and *deroproof* in [DERO Explorer](https://explorer.derofoundation.org)
![DERO Explorer Proving Transaction](https://github.com/deroproject/documentation/raw/master/images/explorer-prove-tx.png)

## DERO Installation

DERO is written in golang and very easy to install both from source and binary.
  
### Installation From Source

First you need to install Golang if not already, minimum version required for Golang is 1.17.

Clone the repository and build the binaries:

```bash
git clone https://github.com/deroproject/derohe.git
cd derohe
go build -o derod ./cmd/derod
go build -o dero-wallet-cli ./cmd/dero-wallet-cli
go build -o explorer ./cmd/explorer
```

The resulting binaries (`derod`, `dero-wallet-cli`, `explorer`) will be in the current directory.

### Installation From Binary

Download [DERO binaries](https://github.com/DEROFDN/derohe/releases) for ARM, INTEL, MAC, Windows, Mac, FreeBSD, OpenBSD, Linux (and other available platforms).

### Running DERO Daemon

Run derod.exe or derod-linux-amd64 depending on your operating system. It will start syncing.

- DERO daemon core cryptography is highly optimized and fast.
- Use dedicated machine and SSD for best results.
- VPS with 2-4 Cores, 4GB RAM,15GB disk is recommended.

![DERO Daemon](https://raw.githubusercontent.com/deroproject/documentation/master/images/derod1.png)

### DERO CLI Wallet
DERO cmdline wallet is menu based and very easy to operate.

Use various options to create, recover, transfer balance etc.

**NOTE:** DERO cmdline wallet by default connects DERO daemon running on local machine on port 20206.

If DERO daemon is not running start DERO wallet with --remote option like following:

**./dero-wallet-cli-linux-amd64 --remote**

![DERO Wallet](https://raw.githubusercontent.com/deroproject/documentation/master/images/wallet-recover2.png)

### DERO Explorer

[DERO Explorer](https://explorer.derofoundation.org) is used to check and confirm transactions on the DERO network.

DERO users can run their own explorer on local machine and can [browse](http://127.0.0.1:8080) on local machine port 8080.

![DERO Explorer](https://github.com/deroproject/documentation/raw/master/images/dero_explorer.png)