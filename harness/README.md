# harness/ — the means of production for `artifacts/`

Both pages in `artifacts/` are evidence-anchored projections. **Never hand-edit them.** Protocol:
`<notes>` (open loop → G0 → closed loop with a gate after every step).
The pattern is `~/openelm-env/working-tools/artifact-kit` + `~/Downloads/sdx85_wlan_driver_src/harness`, rebuilt
here for a Go blockchain daemon that is **running while the page is built**.

```
python3 prep_corpus.py [--check]          # index the tree: corpus/tags.tsv, pkgindex.json, manifest.json
python3 miners/mine_inventory.py          # packages, the first-party import graph, vendored weight
python3 miners/mine_consts.py             # consensus constants, read from the lines that declare them
python3 miners/mine_flows.py              # six execution chains, hop by hop; a moved hop drops the whole chain
python3 miners/mine_logbridge.py          # console lines -> the Go literal that printed them (+ logger registry)
python3 miners/mine_localdiff.py          # this tree vs upstream tag Release153
python3 miners/mine_runtime.py --capture  # a fresh READ-ONLY snapshot of the live daemon (RPC 10102)
python3 miners/mine_findings.py           # the analysis rows; derived numbers are computed, never typed
python3 gen_deroarch.py build             # resolve + render + stamp + rewrite the skill's AUTO block
python3 gen_deroarch.py check | selftest  # CURRENT/STALE (exit 3) · proves check and resolve CAN fail
python3 gen_deroarch.py export-verify     # verifier inputs: model/verify/in_A.json, in_B.json, in_C.json
python3 kit/retrofit.py apply model/evidence/release151-migration-report.json   # the kit onto the hand page
python3 gen_index.py                      # artifacts/index.html, the suite hub
python3 intel/miner_intel.py --json-only   # the miner's rotated log chain + derod-side shares (G17)
python3 intel/metrics_intel.py --json-only # both /metrics endpoints sampled twice, cross-checked (G18)
python3 kat/test_intel_r20.py             # IK11..IK17 + mutations (R20 harness layer)
python3 run_gates.py <label>              # G1..G18 -> loop/GATES.md

# R20 merge notes
#  - G17 share_drought / unexplained_gap read derod's DEBUG line "Own miniblock delivered": keep derod's file log
#    at the default level (P2P DEBUG on), or every run looks like a drought (false ALERT).
#  - G18 samples BOTH /metrics endpoints (derod 10102, miner 10110): it FAILS (endpoint_down) while the miner is
#    deliberately stopped. During miner maintenance, run the gates and record G18 as an intentional skip in
#    loop/SKIPPED.json rather than reading the FAIL as a regression.
#  - The miner log is appended to and rotated by size (cmd/dero-miner/minerlog.go, 32 MiB x 3, 0600); miner_intel
#    reads <log>.3 .. <log>.1, <log>.
# R21 notes
#  - S4b compares staged vs installed LIKE FOR LIKE: the same --sort on both builds, the sorter each run used read
#    back from its 'suffix sort' line (sort_impl). r20 compared the installed --sort=descriptor (Go port) with the
#    staged --sort=auto (native C) and recorded x1.654; the interleaved A/B under one sort is x1.04.
#  - S4b FAILS without a bench lock unless --no-benchlock says so; a staged split-bench skip FAILS (the staged build
#    is this tree); the live split reading is STALE (> 1 h) / NO_DATA (no window) instead of LIVE with nulls.
#  - S7 judges intel steps by exit code AND a newly written snapshot (judged_step): a crashed or empty miner_intel
#    can no longer leave G17 judging the previous snapshot.
#  - Split regime (miner_intel / metrics_intel, G17/G18, page card + DK33): cpu-sort-bound when staged texts wait on
#    the CPU sort >= 0.5 of the time, gpu-bound when CPU threads find nothing staged >= 5,000 times per thread per min.
#  - intel/run_ledger.py keeps one line per miner run in runtime/run_ledger.jsonl after the log rotates (KAT IK25,
#    page card + DK34). intel/gpu_watch.py judges a GPU experiment from /metrics (miner restart, split disabled):
#    use it inside benchlock: benchlock.py -- python3 -I harness/intel/gpu_watch.py run -- <cmd>.
# R23 notes
#  - intel/contention.py: a read-only ps census (process BASENAMES only: no pid, args or path reaches a snapshot) and
#    the contention law. metrics_intel samples it beside its two GETs (box_contended, cpu_starved names the processes,
#    cpu_starved_unattributed when the box is quiet); miner_intel turns a contended sag into cpu_starved. The --cpu-max
#    budget now comes from /metrics dero_miner_cpu_duty_percent (before: only bin/dero-miner.run.json, so a clone never
#    fired cpu_starved). G20 refuses A/B and regression claims from a contended box.
#  - fix_build_verify: S4b/S4c census before+after; contended -> REFUSED (correctness still FAILs), --contended-ok goes
#    on. --gpu-bench on an unchanged server = self-A/B (ratio inside [0.93, 1/0.93]); --gpu-bench-only runs S4c alone:
#    benchlock.py --gpu -- python3 -I harness/pipeline/fix_build_verify.py --gpu-bench-only --contended-ok
#  - miner_runs: payout ledger (expected vs found vs paid, DERO at the derived per-miniblock reward, Garwood 95 %
#    interval) in the snapshot and runtime/payout_ledger.jsonl; L9 height; the r22 hashes/height=0 rows are KNOWN.
#    G21 gates it; S7 judges miner_runs by exit code AND a new snapshot.
#  - python3 kat/test_intel_r23.py           # IK39..IK45 + 23 mutations
python3 kat/verify_deroarch.py --mutations  # DK01..DK29; each mutation must flip ITS kat
python3 ask.py "<question>"               # retrieval over the DRAWN rows only
```

## Layout
- `kit/` — artifact-kit modules vendored from `~/openelm-env/working-tools/artifact-kit` (assetkit: class pills +
  citation panel; connectorkit: hover-trace and ▶ playback; textkit: no silent cut; diagramkit: kit-native SVG;
  retrofit: the kit applied to a hand-written page; kitgate: the kit's own gates). **They are page sources**, so a
  kit change makes the page STALE — re-copy after changing the upstream kit, then rebuild.
- `corpus/` — derived indexes: `tags.tsv` (3,754 Go symbols via ctags), `pkgindex.json`, `manifest.json`.
- `miners/` — deterministic miners. `minelib.py` holds the shared anchor machinery; nothing may write a claim it
  cannot anchor.
- `model/raw/<key>.json` — mined rows. `model/verify/` — adversarial verdicts. `model/verified.json` — what was drawn.
- `model/evidence/` — retrofit declarations for hand-written pages.
- `runtime/` — read-only captures of the live daemon and its console. The HARNESS evidence root.
- `loop/` — DISCOVERY.md, PLAN.md, PROPOSALS.md, GATES.md (appended per run), REJECTED.json, UNVERIFIED.md/json,
  KAT_LAST.json.
- `hooks/autosync.py` — PostToolUse hook (`.claude/settings.json`): rebuild when a model file, miner, kit module,
  runtime capture or the skill is edited.

## The class vocabulary (closed)
| class | a line of it proves | where it lives |
|---|---|---|
| **SRC** | the first-party DERO source, its build scripts or go.mod | the 18 packages, `build_*.sh`, `go.mod` |
| **EXT** | third-party code this build links in — quoted, not owned | `vendor/**` |
| **HARNESS** | the owner's own measured system | `harness/runtime/**`, `RUN_REPORT.md`, `ARCHITECTURE.md` |
| **GK** | this project's knowledge base | `.skills/**/SKILL.md`, the session memory store |
| **PLAN** | proposed and not yet run | `harness/loop/PROPOSALS.md` |

## Laws
- **Resolver contract:** a row is drawn only if ≥ 1 `{file, quote}` anchor is found verbatim on ONE line of its
  file (whitespace runs and typographic quotes normalised, nothing else; ≥ 12 characters). Where it points decides
  its class. A class its anchors cannot prove is re-derived and the page says so. No anchor, no row — it goes to
  `loop/REJECTED.json` and the page's quarantine.
- **Derived numbers are derived:** a figure that follows from constants (the halving interval, the bounds on a
  difficulty step, the grandfather-table size) is computed at build time from the cited lines. KATs DK11, DK12 and
  DK19 recompute them independently. A typed number would survive a refactor; a computed one cannot.
- **Chains are all-or-nothing:** a flow renders only when every declared hop anchors. One moved hop sends the whole
  chain to UNVERIFIED naming the hop, so a refactor shows up as a hole, not as a diagram that quietly lies.
- **Log bridge plausibility:** a console line matches a Go literal only if that literal sits in a package that owns
  the logger name derod printed. The ownership map is mined from the `WithName` calls themselves (DK09).
- **The live node is evidence, and it is asked again:** every runtime reading cites the line of the snapshot it was
  read from (DK15), and gate **G9** re-queries the daemon at gate time and fails if the version no longer matches
  or the chain went backwards.
- **Merge laws (verifiers):** REFUTED → quarantine; PARTLY/OVERSTATED → corrected claim with the original in the
  tooltip; `fix_fields` only onto an existing field of the right type; no verdict → "not re-verified" badge; a
  verdict that judged an earlier claim does not apply and the row is badged "changed since verification".
- **Two-way skill sync:** every build rewrites the AUTO block of `.skills/dero-miner-tuning/SKILL.md`; the
  hand-written part of that skill is a page source. `sha()` excludes the AUTO block, so the build is hash-neutral
  with respect to its own output.
- **Secrets never render.** DK18 is the standing proof: seed phrases, private keys and passwords are checked for on
  every KAT run.
- **Inputs are read-only.** No miner, gate or KAT writes into the Go tree, and the KATs run on a scratch copy.

## The round registry (r23c)
`harness/round.json` names the ids every round used to re-type: the current round, its version suffix, the base its new
tests are counted from (S3a), its merge commit and head, its full pipeline run, its Go-mutation tally, the RPC methods
the shadow probe must find on the candidate and not on the control, and the GitHub-copy sync range. The literal
`"pending"` means *not known yet* and is never used as a value: a planned round may hold no result at all.

- `fix_build_verify.py` reads it at start. `--new-tests-base` still wins; without it S3a uses
  `rounds[current].new_tests_base`, then `HEAD` (the pre-r23c default). The BEGIN event records the round and where the
  base came from. `ROUND_NEW_METHODS` comes from `rounds[current].new_rpc_methods` ({method: probe key}); S5 asks both
  shadows for each one (control: "no such method"; candidate: answers). A registry error (repeated id, unknown status,
  a commit that does not resolve, a planned round with a result, an implemented/shipped/measured round without
  version/merge/pipeline, an `upstream_base` other than the pipeline's `UPSTREAM_BASE`, an implemented/shipped current
  round whose version `config/version.go` does not carry) stops the run (`round FAIL`); an in-progress round still on the previous version only warns.
- `pipeline/benchlock.py` is the bench lock in the repo (until R23c it lived only in one session's scratchpad). Lock
  file: `$DERO_BENCHLOCK`, else `"benchlock"` in the registry; with neither it refuses (exit 2). Every bench of a round,
  the pipeline's `--benchlock` included, must name the same file. `--gpu` refuses (98) when it cannot read the live
  miner's GPU-split restarts counter (`$DERO_MINER_LOG`, else `bin/dero-miner.log`), exits 99 when the live worker
  restarted.
- `kat/test_round_registry_r23c.py` (RR1-RR4, 9 mutations) proves the checks can fail; S7 runs it with the other KATs.
- r24 `tracks` (optional per round): `{"miner": "active"|"paused", "node": ...}`. While the CURRENT round says
  `"miner": "paused"` (artifacts/dero-rft.md §0.3) G17/G18/G21 and S4b/S4c report `PAUSED` instead of judging a miner
  that does not run (kit/roundtracks.py; G18's derod half and a changed miner source still fail/run as before). Any
  other value is a registry error (RR2) and is treated as active. KAT: `kat/test_round_tracks_r24.py`.
- Statuses: `planned` → `in-progress` → `implemented` (r23c: merged, full pipeline run, installed; live numbers still
  `pending`) → `shipped` → `measured` (after the live read). Extra fields such as `commits` and `pipeline_project` are
  allowed and not checked.
- Opening a round: set the previous round's `status`/`version_suffix`/`merge_commit`/`head_after`/`pipeline_full`/
  `go_mutations`/`github_sync.target` from its records, set `current` to the new id with status `in-progress` and
  `new_tests_base` = the previous `head_after`, and append the next `planned` round. The per-round procedure, backlog
  and update logs are in `artifacts/dero-rft.md`.

```
python3 -I kat/test_round_registry_r23c.py                     # RR1..RR4 + mutations
DERO_BENCHLOCK=<lock> python3 -I pipeline/benchlock.py -- <bench cmd>
DERO_BENCHLOCK=<lock> python3 -I pipeline/benchlock.py --gpu -- python3 -I pipeline/fix_build_verify.py --gpu-bench-only --contended-ok
```

## Resource hygiene (r27b, artifacts/dero-rft.md §5, B148)

The project's own workflow (dozens of repo clones per round, mirrored by `backup_scratch.sh`) is a RAM / swap /
file-event load on the box. Three tools keep it bounded without dropping any gate, KAT, mutation, replay or verifier:

- `intel/resource_intel.py` (read-only): swap, memory_pressure free %, RSS of fseventsd / mds_stores / derod and of the
  project's own processes (basenames and sums only), scratchpad clone trees (`--full`: files, bytes, GOCACHE, the
  persisted mirror) → OK / REDUCE / HOLD (exit 0 / 5 / 6). It never kills, renices or restarts anything.
  `preflight --planned N --kind clones|jobs` gives the concurrency the readings allow (jobs >= 1: a heavy stage runs
  serially on HOLD, never skipped; clones 0 on HOLD) and appends the decision to `--notes` / `$DERO_ROUND_NOTES`.
- `pipeline/benchlock.py --heavy -- <cmd>`: one of K machine-wide heavy slots (K from the preflight of
  `$DERO_HEAVY_SLOTS`, default 2) for a fan-out job that costs RAM; the bench lock stays for timing. The pipeline's
  S3b/S3c run the preflight themselves (S3c `go test -race -p N`, timeout scaled).
- `pipeline/scratch_gc.py --root <round dir> [--protect <active round dir>] [--apply]`: dry run by default; deletes a
  clone tree only when its HEAD is in the reference repo, its refs too, a `<dim>.patch` + `.md5` match, and
  `git diff HEAD` (untracked via `update-index --add --info-only` into a temp index: hashed, never written, so no
  pack is freshened) equals the patch byte for byte; cited
  ignored files are copied to `<dim>/evidence_from_tree/` first and `<dim>/<tree>.gc.json` keeps the recipe.

```
python3 -I intel/resource_intel.py                                   # level line (exit 0 OK / 5 REDUCE / 6 HOLD)
python3 -I intel/resource_intel.py preflight --planned 8 --kind clones --stage r27-open --notes <round notes>
python3 -I pipeline/scratch_gc.py --root <scratch>/r26 --protect <scratch>/r27 --reference ~/derohe-Release151   # dry run
python3 -I kat/test_resource_hygiene_r27.py                         # RH1..RH9 + 36 mutations (katmut)
```

## Area intelligence (r24)

`harness/areas.json` registers every area of the stack (owner dimension, code paths, metrics and their sources, KATs,
gates, go_mutations prefixes, dero-rft §7 rows, status, anchored per-round history). `intel/area_intel.py` turns it into
per-area scorecards and a proposals feed (protocol: artifacts/dero-rft.md §0.4):

```
python3 -I intel/area_intel.py --live      # runtime/area_intel.json + runtime/area_proposals.json (+ area_prom_<ts>.txt)
python3 -I intel/area_intel.py check       # registry and every history anchor (exit 2 on an error)
python3 -I intel/area_intel.py record r24  # book the round's computed values into the registry history
python3 -I intel/area_intel.py fix-lines   # fill/refresh anchor line numbers from their quotes
python3 -I intel/area_intel.py g23         # gate G23 alone
python3 -I kat/test_area_intel_r24.py      # AI1..AI9 + 27 mutations (AI9: the anchored line states the value)
python3 -I kat/test_area_rows_r24.py       # AR1 + 2 mutations (src-arch rows cite their own area's line)
```
S7 runs `area_intel.py --live` after metrics_intel and `miners/mine_areas.py` (rows of section `areas`, rendered by
`kit/areakit.py` after the disclosure section of dero-src-arch.html). The ledger draws the same scorecards from
`--last 24` (`artifacts/src/areas_section.py`). Paused areas show PAUSED, never failing.

## The network-peer observatory (r24 consensus-network, gate G27)

`intel/peer_intel.py` measures the peers this node talks to, read-only and pseudonymised (artifacts/dero-rft.md §0.7):
GetPeerInfo / GetSyncInfo / GetInfo, derod `/metrics` (p2p_*), the derod log's P2P lines, and private copies of
`peers.json`, `first_relay.json`, `v2_offences.json`, `ban_list.json`. Raw captures, the salt and this node's builder key
stay in `~/derohe-persist/peer_intel_private/` (mode 700); the tree only ever holds pseudonyms (`peer-…`, `node-…`,
`miner-…`, `this-node`). Fourteen detectors (D1–D14), each tied to the code line of its rule, grade OBSERVED / ANOMALY /
NORMAL / pending. Node-side gaps become CO24-N* proposals (area `peers` in the proposals feed, rft §7 B63–B69).

```
python3 -I intel/peer_intel.py --live            # capture + analysis → runtime/peer_capture_<ts>.jsonl, peer_logx_<ts>.jsonl,
                                                 #   peer_intel.json, peer_series.jsonl (appended)
python3 -I intel/peer_intel.py --capture DIR     # analyse an existing private (or synthetic) capture directory
python3 -I intel/peer_intel.py --check           # gate G27 alone
python3 -I miners/mine_peers.py                  # model/raw/peercards.json (section 'peers', rendered by kit/peerkit.py)
python3 -I kat/test_peer_intel_r24.py            # PI1..PI13 + 30 mutations (a planted IP, tag, peer_id or builder key in the page FAILS G27;
                                                 #   PI13: an address anywhere on the page, in verified.json or a log-derived raw file)
python3 -I kat/test_peer_intel_r25.py            # r25: PI14..PI25 + 23 mutations (detectors read the CO24-N* counters of an r25
                                                 #   derod; B72 per-node clock cross-check; D15 sync holds (B47); gaps close
                                                 #   themselves; B71 log_intel / mine_triage snapshots pseudonymised)
python3 -I kat/test_peer_intel_r27.py            # r27: PI26..PI28 + 9 mutations (D5 grades the current run once counters exist;
                                                 #   D11 anchored on peer_id; D5/D9/D11 'explain' lists, no address or /16 written)
python3 -I intel/b99_scenario.py                 # r27: B99 sync-hold life cycle on a loopback simulator chain + fake peer
                                                 #   (never the live store, never 11011) -> runtime/b99_scenario_<ts>.json
python3 -I kat/test_b99_scenario_r27.py          # r27: BS1..BS3 + 4 mutations on b99_scenario.verify()
```
S7 runs `peer_intel.py --live` after metrics_intel and before area_intel (whose `peers` area reads it: metric source
kind `peerintel`, anchored on the KPI line of the timestamped capture), and `mine_peers.py` with the other miners.

## The disclosure track (r24)
The Foundation's 2026-10-20 range-proof disclosure (`external/derofoundation-press-20261020.txt`, audited in R8 as
`model/raw/press.json` + `forensics.json`) is re-tested every round (artifacts/dero-rft.md §0.5, §6 step 9b).
`loop/disclosure_track.json` holds, per claim, one `{round, verdict, state, why, anchors}` entry per round that tested it,
the round's new facts and the potential fixes (FORK-REQUIRED designs, NODE-LOCAL measures with status and feasibility).
`intel/disclosure_track.py` re-reads every anchor (OK / DRIFT / MISSING), refuses a verdict change without a reason and a
non-EXT anchor, requires a current-round entry per claim, maps every press row, lints for exploit-like text, and emits
`model/raw/disclosure.json` (only page-classable anchors) for the src-arch press section; the ledger (`--last >= 24`)
reads the track directly. Gate **G24** runs it; `kat/test_disclosure_track_r24.py` (DT1-DT9) proves each check can fail.

```
python3 -I intel/disclosure_track.py --emit-model --snapshot --check --pages   # the round record, G24's checks
python3 -I intel/disclosure_track.py --rev <merge head>                        # anchors at another revision
python3 -I intel/disclosure_track.py --live --census 100000                    # read-only RPC: S1-S4, proof-scalar census
python3 -I kat/test_disclosure_track_r24.py                                    # DT1..DT9 + 23 mutations
```

## Cross-artifact coherence (r24, gate G25)

`harness/intel/coherence.py` checks that every artifact quotes each shared fact as its ONE canonical source states it
(artifacts/dero-rft.md "Artifact contract"): the round id, status and version suffix (`harness/round.json`,
`config/version.go`); every figure written after a `pipeline_<ts>` id (mutations, KATs, harness mutations, gates, race,
shadow, flaky) against that run's record in `harness/loop/runs/`; the registry's `go_mutations` against the mutate stage
of `pipeline_full`; live-window figures against `harness/runtime/r*_live_window_*.txt`; disclosure verdicts and states
(ledger "Disclosure track", src-arch section 10, `model/raw/disclosure.json`) against `loop/disclosure_track.json`; area
states (ledger and src-arch Areas sections, `areas.json`, the proposals feed) against `runtime/area_intel.json`; the
status of tracked backlog ids (B18 B19 B28 B29 B30 B34 B35 B38 B39 BD5-BD9) against the rft §7 table; page names
(index cards, the current ledger page, the rft); and src-arch freshness (every `stamp.json` source re-hashed with
`prep_corpus.sha`, the page size, and every round-marked commit up to HEAD that changes more than generated outputs present
in `runtime/evolution_git.tsv`). Each drift names file:line, the expected value, what was found and the source.

    python3 -I harness/intel/coherence.py [--json] [--record] [--root DIR] [--skip index,...]   # exit 0 / 4 drift / 2 unreadable

G25 (`run_gates.py`) runs every check except the index page; S7 runs `coherence.py --record` after `gen_index.py`
(full set; a drift fails S7; record `runtime/coherence_last.json`). KAT: `harness/kat/test_coherence_r24.py` (CO1-CO15,
a planted disagreement per artifact class, a stale src-arch, a missing round commit; 17 mutation proofs). Area: `docs`
(metric `coherence_drifts`).

## Consensus observatory — chain (r24, gate G26)

`intel/consensus_intel.py` reads the last 3,000 blocks (GetBlockHeadersRange in 100-block chunks, sleeps between calls),
48 GetMiniBlocks, the HF3 fork block, side blocks by hash, GetMonetaryIntegrity's finality monitor, GetPeerInfo counts
and `/metrics` (all read-only, `Content-Type: application/json`), plus the derod JSON log. It writes
`runtime/consensus_intel.json`, `runtime/consensus_capture_<ts>.txt` (one line per fact; the `consensus` area history
cites it) and appends `runtime/consensus_series.jsonl`. Miners and integrators are salted pseudonyms (salt in
`~/derohe-persist/consensus_private/`, never in the repo); this node is `this-node`; no address or IP reaches an output
(the writer refuses one). Consensus constants are parsed from the lines that declare them. 18 detectors graded
OBSERVED (rule line cited) / ANOMALY (stated test, alpha 0.001 family-wise) / NORMAL / NO-DATA (artifacts/dero-rft.md §0.7).

```
python3 -I intel/consensus_intel.py                 # live capture (exit 0, 5 = an OBSERVED detector, 2 = cannot capture)
python3 -I intel/consensus_intel.py --from <raw>    # re-analyse a pseudonymised raw capture
python3 -I intel/consensus_intel.py g26             # gate G26 alone
python3 -I miners/mine_consensus.py                 # rows of section 'chainobs' (kit/consensuskit.py renders them)
python3 -I kat/test_consensus_intel_r24.py          # CI1..CI19b + 28 mutations
python3 -I kat/test_consensus_intel_r25.py          # r25: CR1..CR10 + 20 mutations (D19 collective finals, D20 alt blocks, D02/D13 windows, r25 node counters)
```
S7 runs it after metrics_intel and before area_intel (JUDGED: exit 0 or 5 and a new capture text), and mine_consensus
with the other miners. Node-side gaps it finds are proposals CO24-C* (area `consensus`, `feeds` → area_proposals.json;
rft §7 B55–B62).
r25 (consensus dimension): the r25 derod serves what the observatory used to reconstruct from DEBUG lines —
`DERO.GetConsensusStats` (miniblock refusals and block rejections by reason, the settled alt blocks behind GetInfo
`alt_blocks_count`, the reorg monitor's lifetime record), `fees` / `first_seen_ms` / `first_seen_local` on every
GetBlockHeadersRange header and `first_seen_ms` on GetMiniBlocks. The tool reads them when served (D02, D11, D20,
arrival lag, fees, lifetime reorgs) and falls back to the log on an older binary; a CO24 proposal is raised only while
the CAPTURED binary still shows its gap. D19 grades the integrator-only coalition (CO24-C8), D13 and D02 read the
window, not the whole log (B72); the peer census joins `consensus_series.jsonl`.

## Consensus observability: the loop and the privacy kit (r24 integration, rft §0.7)

The two observatories above are one layer. Areas `consensus` and `peers` read their OBSERVED / ANOMALY detectors
(`detector_feeds` in `areas.json`: proposal kinds `observatory-observed` medium, `observatory-anomaly` low, anchored on the
detector's line) and their node-side gaps (`node-gap`); rft §7 carries them (B55–B72) and §8 gives R25 the dimensions
`consensus` and `peers` (node-side code, so a derod restart, then a re-read on the restarted build). `coherence.py`
check `observatory` (G25) ties every capture an artifact names to that capture's figures and the src-arch sections and
the ledger's "Consensus observatory" section (`artifacts/src/observatory_section.py`) to the newest outputs.

`kit/privkit.py` holds the privacy rules: `pseudonymise_obj` (every non-reserved IPv4 → `peer-` + 8 hex with the peer
salt; `miners/minelib.emit` applies it to every miner's rows, so `model/raw/*.json`, `model/verified.json` and
dero-src-arch.html carry no peer address), `mask` (salt-free anchor matching: `gen_deroarch.resolve_ev` and
`verify_deroarch` DK01 fall back to it only when the exact quote is not on the line), `page_ip_leaks` (G27's whole-page
scan) and `prune_private` (the observatories keep the newest raw runs, 0700 dirs / 0600 files).

```
python3 -I kat/test_privkit_r24.py                 # PK1..PK4 + 11 mutations (pseudonyms, masked anchors, the page scan, pruning)
python3 -I kat/test_area_intel_r24.py              # AI10: detector feeds become area proposals
python3 -I kat/test_coherence_r24.py               # CO16: the observatory facts
```
