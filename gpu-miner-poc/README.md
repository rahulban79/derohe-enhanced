# GPU miner PoC — Milestone 1 (bit-exact GPU building blocks)

> **Building the servers the miner runs (r21):** `gpu-miner-poc/build.sh` (default: `gpu_hash_sais gpu_split_server`)
> compiles with `xcrun swiftc -O`, renames the result over the old binary (a running server keeps its inode) and
> records `sha256(source) sha256(binary)` in `BUILD_STAMPS`. The binaries stay tracked because
> `dero-miner --gpu=gpu-miner-poc/gpu_hash_sais` runs them from the checkout, but a text patch cannot carry them and
> swiftc output is not reproducible, so dero-miner checks the stamp at GPU start and logs `GPU server binary is
> STALE` (metric `dero_miner_gpu_binary_stale`) when the `.swift` changed after the build or the binary is not the
> recorded build. `build.sh --check` verifies all stamps; `go test ./cmd/dero-miner -run RepoGPUStamps` fails a
> round that edits a `.swift` without rebuilding.

**Goal:** a GPU worker that computes *bit-identical* AstroBWTv3 hashes so a `--gpu` miner can run
**alongside** the CPU miner, adding the measured **~+20–25%** hashrate (see `../ARCHITECTURE.md` §13.4).
Consensus requires every GPU hash to byte-match the CPU (`astrobwt/astrobwtv3`), so each stage is ported
to Metal MSL and **validated against a CPU/known-answer reference before it is trusted for real shares.**

## Why the M1 GPU is worth this (measured, not asserted)
- GPU is **~40–90× faster than CPU** on the branchy 256-op mixing loop (`../scratchpad/metalbench.swift`).
- GPU is **~0.39× CPU** on the SAIS (`../scratchpad/metalsais4.swift`) — the 272 KB/thread scratch caps occupancy.
- Net: GPU-only loses, but GPU **+** CPU running independent hashes adds ~+20–25% (~9,000–9,500 H/s total);
  the CPU's SAIS stays in its 12 MB L2 while the GPU streams the 128 GB unified memory, so contention is limited.

## Status
| Stage (pow.go) | Metal port | Validated bit-exact | Notes |
| :------------- | :--------- | :------------------ | :---- |
| **SHA256(input)** (pow.go:52) | ✅ `gpu_sha256.swift` | ✅ **7/7 KA vectors** incl. the 48-byte miniblock | single-block (msg ≤ 55 B) |
| **Salsa20/20** (pow.go:54) | ✅ `gpu_presais.swift` | ✅ **7/7** (part of step_3 fp) | Sigma+key+ctr, 4 blocks, ctr[8]++; matches `x/crypto/salsa20/salsa` |
| **RC4** (pow.go:62-63) | ✅ `gpu_presais.swift` | ✅ **7/7** (part of step_3 fp) | KSA/PRGA, key=salsa out; matches `astrobwtv3/rc4.go` |
| **step_3[256] = sha256→salsa20→rc4** | ✅ `gpu_presais.swift` | ✅ **7/7 byte-exact** vs `cmd/_gpuref` (Go, same libs) | ground-truth ref via the real Go libraries |
| **the 3 loop hashes** (fnv1a64/xxhash64/siphash-2-4) | ✅ `gpu_hashes.swift` | ✅ **16/16 lengths** (0–255, all boundaries) vs `cmd/_hashref` | stage 3a done |
| **256-op switch + stateful RC4 + break + data_len** (pow.go:69-2434) | ✅ `gpu_loop.swift` (opcodes auto-gen `cmd/_opcodegen`) | ✅ **11/11 KA vectors** (GPU (data,data_len) → CPU SAIS/SHA == AstroBWTv3) | stage 3b DONE — full pre-SAIS on GPU |
| **Suffix array** (== SAIS, via prefix-doubling — proven `cmd/_sacheck`) | ✅ `gpu_fullhash.swift` | ✅ **11/11** (full hash) | SA is UNIQUE, so any correct SACA == SAIS; prefix-doubling avoids the recursive port |
| **final SHA256** (multi-block over sa) | ✅ `gpu_fullhash.swift` | ✅ **11/11** | |
| **COMPLETE AstroBWTv3 hash on GPU** | ✅ **stage 3c DONE** | ✅ **11/11 == AstroBWTv3** | `cmd/_fullhashvalidate` |

### Stage 3c: CORRECTNESS done, PERFORMANCE is the open problem
The **entire** AstroBWTv3 hash runs **bit-exact on the GPU** (input → 32-byte hash == `AstroBWTv3`). BUT the
measured throughput is **~75 H/s** (peak, 4096 threads) — **~100× slower than the CPU's 7,680** — because
**prefix-doubling** is O(n log²n) with radix sorts, run serially per slow GPU thread. Batch latency is 22–112 s,
far longer than a job's ~18 s validity, so **wiring this version would orphan every share** — NOT wired.
- **Prefix-doubling was the right call for CORRECTNESS** (simple, guaranteed bit-exact via SA-uniqueness).
- **Optimized it (2-counting-sort/round vs 5-pass radix): 75 → 118 H/s (1.6×), still 11/11 bit-exact** — but
  that CONFIRMS the ceiling: prefix-doubling tops ~118 H/s (~65× slower than CPU); AstroBWT data needs ~9–11
  doubling rounds (`cmd/_sacheck`), so it's fundamentally O(n log n) with a big constant.
- **For usable performance (~+20–25%) the SAIS must be O(n)** — the linear induced-sorting SA-IS. `metalsais4.swift`
  put the linear induce pattern at ~3,000 SAIS/s ⇒ a linear-SAIS full GPU hash ≈ ~1,500–3,000 H/s.
  **This is the remaining work (stage 3c-opt2), a multi-session port. Plan:**
  1. Port SA-IS (`sais.go` sais_8_32: freq/bucketMin/Max, placeLMS, induceSubL/S, length, assignID, expand,
     induceL/S) to MSL — the NON-recursive path first (random AstroBWT data usually has distinct LMS substrings
     ⇒ maxID==numLMS ⇒ no recursion).
  2. **Fallback:** if `assignID` finds maxID<numLMS (recursion needed), fall back to the (correct) prefix-doubling
     for that hash — avoids porting the recursion, keeps 100% correctness. Measure how often this triggers.
  3. Validate every step: full GPU hash == `AstroBWTv3` for the 10 KA vectors + random-input differential fuzz.
  4. Then wire `--gpu`: watchdog-safe batches SHORTER than the ~18 s job window (else stale/orphaned shares).

**Validation harness (reusable):** `cmd/_opcodegen` (pow.go → `loop_ops.metal.inc`), `cmd/_loopvalidate`
(GPU (data,data_len) → `astrobwtv3.FinishHashFromData` → compare to `AstroBWTv3`), `cmd/_loopdebug` (per-iteration
trace diff via `GpuIterHook`). `astrobwt/astrobwtv3/gpu_bridge.go` adds `FinishHashFromData` + two nil-guarded
debug hooks (`GpuDebugHook`, `GpuIterHook`) — zero behavior change when unset (KA + 1024-iter tests pass).
> **Stage-3b bug caught by the harness:** case 253 has an extra in-loop `xxhash.Sum64(step_3[:pos2])` beyond its
> 4 ops; the codegen initially missed it → 6/11 mismatched → trace-diff localized it to op-253 → fixed → 11/11.

## Run / validate
```bash
xcrun swiftc -O gpu_sha256.swift -o gpu_sha256 && ./gpu_sha256   # prints MATCH per KA vector; exit 0 = all bit-exact
```
No full Xcode needed — Metal shaders are **runtime-compiled** from source via `device.makeLibrary(source:)`.

## Remaining roadmap (before any GPU share is submitted)
1. Port Salsa20 + RC4; validate the post-RC4 `step_3[256]` against a Go reference for the KA inputs.
2. Port the full 256-op loop (+ the three conditional hashes) and the break condition; validate `scratch.data`+`data_len`.
3. Port SAIS (iterative, no recursion) or do SAIS on CPU in a hybrid; validate the full 32-byte hash against
   `astrobwt/astrobwtv3/pow_test.go` (10 KA vectors + the 1024-iter repeat) — **byte-for-byte or it does not ship.**
4. Wire a `--gpu` worker in `cmd/dero-miner`: batch nonces → GPU full-hash → `CheckPowHashBig` → same getwork submit
   path, honoring the GPU watchdog (batch < ~5 s) and the `--cpu-max` philosophy (a `--gpu-max` duty cap).

**Guardrail:** until step 3 passes, the GPU path stays OFF by default — a non-bit-exact kernel produces rejected
shares (net-negative). This directory is a *validated foundation*, not yet a live miner.

## gpu_split_server op 3: GPU suffix sort (Round 19, opt-in, OFF by default)

- `sort_ops.metal.inc` is a clean-room, block-per-hash suffix sort (it comes from the Round 18 spike `sa_r18`). Two
  kernels run it: `sg_p0` does a 12-bit counting sort, and `sg_rounds` does the refinement rounds. The rounds are
  resumable: the state lives in a per-text `state[8]`, and each dispatch runs at most `maxR` rounds.
- The server runs op 3 on `<sortLanes>` lanes, in chunks of `<sortChunk>` texts. Both are optional trailing arguments;
  old Go sides pass neither, and op 3 is then refused. The server adapts the rounds per buffer and the chunk size to
  keep each command buffer short. Status 3 means the Go side sorts that batch on the CPU instead.
- Turn it on in the miner with `DERO_GSPLIT_SORT=lanes,chunk,inflight,minready` (or `1` for 2,32,1,1).
  - The engine diverts a staged batch to op 3 only when at least `minready` batches are already waiting for the CPU
    threads and fewer than `inflight` batches are in op 3.
  - The self-test sorts half its slots on the GPU.
  - Every GPU-sorted batch is audited on the CPU. A mismatch turns only the GPU sort off.
- Build: `xcrun swiftc -O gpu_split_server.swift -o gpu_split_server`. `sort_ops.metal.inc` must sit next to the binary.
- Live measurement, 2026-10-24 22:15 (shared GPU at ~99% Device Utilization from the live miner):
  - Correctness: 2048/2048 and 2048/2048 GPU-sorted hashes were bit-exact against `astrobwtv3.AstroBWTv3`.
  - Speed: 989 SA/s wall (1,857 SA/s per GPU-second).
  - Live staged H/s fell from ~53.5k to 46.5k/47.8k in the two half-overlapping 60 s windows.
  - On this box, GPU time is worth more on stage 1 + SHA than on sorting. Keep op 3 off unless the GPU has idle time.
- Round 21 re-measurement, 2026-10-28 13:29-13:31 (r20 kernels; live GPU ~92-93% Device Utilization at ~70k staged
  H/s; live CPU sort backlog ~68% of each minute). Lanes 1, chunk 16 (adapted down to 8):
  - Correctness: 4096/4096 GPU-sorted hashes bit-exact against `astrobwtv3.AstroBWTv3` (first and last pass;
    24,576 GPU sorts, fails=0, live GPU restarts 0).
  - Speed: 287 SA/s wall (624 SA/s per GPU-second of command-buffer time). 1,404 of 12,317 buffers ran over 8 ms
    (max 90.8 ms) because they are time-sliced against the live stage-1/SHA buffers.
  - Live staged H/s fell from ~70.4k (4-minute mean) to 64.5k in the overlapping 60 s window, and `cpu_idle_tries`
    rose from ~12k to 147k/min. The CPU threads ran out of staged texts: the sort took GPU time from stage 1.
  - So the r20 kernels did not change the verdict. The ~7% idle GPU time is scattered across waits on the CPU, and
    a time-sliced sort cannot use it. The sort stays off by default. When it is enabled, the miner's A/B probe
    (`DERO_GSPLIT_SORT_PROBE`, 60 s ABBA windows at start and then hourly) pauses it whenever the allowed windows
    hash less.
