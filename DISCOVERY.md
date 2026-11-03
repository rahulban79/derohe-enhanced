# DISCOVERY.md — Network-Layer Performance (derod ⇄ dero-miner)
**Regime:** OPEN LOOP (wide) · **Gate:** G0 (collapse) · **Date:** 2026-07-08
**Goal (user):** "Massively improve network performance — how quick the miner submits the hash matters a lot to receive rewards." Deep-dive derod + dero-miner network layer, implement major improvements.

---

## 1. PROBLEM STATEMENT (precise)

**Reward model (from memory `dero-reward-luck-mechanics` + code):** realized reward = accepted miniblocks × per-miniblock reward. A miniblock is **orphaned** (no reward) if it fails to reach the integrator that finds the final block before that block's first-9 normal-miniblock slots fill. There is **no timestamp/freshness gate** — the only orphan path is *arrival order*. Therefore:

> **The reward-limiting network quantity is PROPAGATION LATENCY of my miniblock from my derod to the rest of the network** — not the loopback submit hop.

**Invariant (hard constraint):** PoW + block/miniblock acceptance are consensus-critical. Any change must be **transport/latency-only** — identical bytes accepted/relayed, or it produces rejected/forked shares (net-negative). [memory: `dero-miner-changes`, `session-reasoning-patterns`]

**Acceptance criteria (machine-checkable, become the eval gates):**
- A1: derod + miner build clean (`go build`, exit 0). `[E:EXEC]`
- A2: miniblock broadcast reaches peers in **non-decreasing latency order** (fastest first). `[E:EXEC]`
- A3: a first-class switch selects the low-latency KCP profile; log message is truthful. `[E:EXEC]`
- A4: miner submit path: TCP_NODELAY explicit, reconnect backoff < 10 s, submit latency observable. `[E:EXEC]`
- A5: whole pipeline runs; `miniblock_propagation_duration_histogram_seconds` collects real samples; no rejected-share regression. `[E:OBS]`

---

## 2. NETWORK MAP — the two reward-critical chains (all `[E:SRC]`)

### Chain α — found share → network (propagation; the reward lever)
```
miner thread finds share
  └─ connection_mutex.Lock(); connection.WriteJSON(SubmitBlock_Params)   miner.go:632-635
     └─ wss/TLS over loopback → derod getwork server
        └─ OnMessage: client_list_mutex.Lock(); json.Unmarshal            websocket_getwork_server.go:212-241
           └─ chain.Accept_new_block(tstamp, blob)                        miner_block.go:442
              ├─ accept_lock.Lock()
              ├─ VerifyMiniblockPoW  (1× AstroBWTv3, consensus-required)  miner_block.go:483
              ├─ InsertMiniBlock                                          miner_block.go:498
              └─ go P2P_MiniBlock_Relayer(mbl,0)   ── ASYNC ──            miner_block.go:504
                 └─ broadcast_MiniBlock: for each peer<25 blocks:         connection_pool.go:543-590
                    go conn.Client.Call("Peer.NotifyMiniBlock")   ⚠ NOT latency-ordered
                       └─ peer NotifyMiniBlock: records propagation metric,
                          re-VerifyPoW, InsertMiniBlock, re-broadcast      rpc_notifications.go:113-206
```
- **Transport derod⇄peers = KCP/UDP** (kcp-go). `tunekcp` controller.go:280.
- **Instrumentation already present:** `miniblock_propagation_duration_histogram_seconds` (Sent→receive) rpc_notifications.go:152; `/metrics` on RPC mux websocket_server.go:219.

### Chain β — new tip → fresh job (anti-stale; avoid wasted/rejected work)
```
derod dispatch loop: every 10ms, if mini_count|height changed OR 500ms → SendJob   websocket_getwork_server.go:361-385
  └─ SendJob: per-client goroutine encode+WriteMessage (100ms write deadline)         :164-204
     └─ miner getwork: ReadJSON → job=result; job_counter++                            miner.go:485-492
        └─ mine loops exit the instant local_job_counter != job_counter               miner.go:614/642
```
Chain β is already event-driven (~10 ms reaction). Little headroom.

---

## 3. LIVE BASELINE (`[E:OBS]` — user's derod, 2026-07-08 18:13 PT)
- `p2p_peer_count 2` (outgoing 2, incoming 0) — thin fanout at startup; `--min-peers=20` set, still discovering.
- derod log: **"P2P is in turbo mode"** → this is the `else` branch of tunekcp → **`SetNoDelay(0,40,0,0)`** = 40 ms flush, congestion-control ON, no fast-resend = **higher-latency profile**. controller.go:109-113,282-286.
- `miniblock_propagation_duration_histogram_seconds`: **no samples yet** (node not mining).
- miner reconnect: hard `time.Sleep(10 * time.Second)` miner.go:477.
- `go1.20.3 darwin/arm64`; binaries `bin/derod`, `bin/dero-miner` present.

**KCP profile decode `SetNoDelay(nodelay,interval,resend,nc)`:**
| profile | nodelay | interval | resend | nc | meaning |
|---|---|---|---|---|---|
| default ("turbo" log, TURBO unset) | 0 | 40 ms | 0 | 0 | delayed flush, CC on, RTO-only retransmit — **slow** |
| `TURBO=0` ("normal" log) | 1 | 10 ms | 2 | 1 | immediate flush, CC off, fast-retransmit — **low-latency** |

⇒ The label is inverted vs. latency. For miniblock propagation the `TURBO=0` profile is strictly better per-hop (≤30 ms less flush delay + fast loss recovery). `[E:DERIVE]` from kcp-go SetNoDelay semantics.

---

## 4. CANDIDATE PATHS (≥3) + RUBRIC

Rubric: `Score = 0.30·Fit + 0.25·Feasibility + 0.20·EvidenceCertainty + 0.15·(1/Risk) + 0.10·(1/Cost)`, each factor ∈[0,1].

| # | Path (mechanism) | Fit | Feas | Evid | 1/Risk | 1/Cost | **Score** | Verdict |
|---|---|---|---|---|---|---|---|---|
| **A** | **Low-latency KCP profile** (fast flush+retransmit) via `--lowlatency` flag / `TURBO=0` | 0.95 | 0.95 | 0.90 | 0.80 | 1.0 | **0.905** | ✅ SELECT |
| **B** | **Latency-ordered miniblock broadcast** (sort peers by RTT, parity w/ Broadcast_Block) | 0.80 | 1.0 | 0.95 | 0.95 | 1.0 | **0.895** | ✅ SELECT |
| **E** | **Measurement** — scrape propagation histogram + submit-latency log (proves A/B) | 0.70 | 1.0 | 1.0 | 1.0 | 1.0 | **0.860** | ✅ SELECT (enabler) |
| **C** | **Miner submit resilience** — NODELAY explicit, reconnect backoff, pre-serialize off-lock | 0.55 | 1.0 | 0.90 | 0.95 | 0.95 | **0.803** | ✅ SELECT (cheap) |
| F | Wider fanout: raise `--min-peers` / incoming peers | 0.65 | 0.9 | 0.6 | 0.7 | 0.8 | 0.712 | ⚠ RECOMMEND (config, user's call) |
| D | Skip redundant PoW re-verify for local own share | 0.4 | 0.9 | 0.9 | **0.05** | 0.9 | 0.49 | ❌ PRUNE — consensus/integrity risk |
| G | Replace wss(TLS) loopback submit w/ plaintext | 0.3 | 0.4 | 0.7 | 0.4 | 0.5 | 0.42 | ❌ PRUNE — µs on loopback; server is TLS-only |

**Pruned with evidence:** D violates the consensus-safety invariant (daemon must independently verify PoW even for a local share). G targets the loopback hop, which is µs — the map (§2) shows the latency lives in Chain α's P2P segment, not the submit hop.

---

## 5. RECOMMENDED BUNDLE (collapse → closed loop)
Ship **A + B + E + C** (all transport/latency-only; zero consensus change). Recommend **F** as an operational note.
- **A** and **B** attack the actual reward lever (propagation latency of my miniblock).
- **E** makes the win measurable (protocol requires numbers from measurement).
- **C** is cheap resilience on the miner side (addresses the user's stated "how quick the miner submits" framing; honestly marginal on loopback, but improves reconnect/availability).

**Honest expectation:** biggest gain is derod-side propagation (A+B); the loopback submit hop is already µs, so miner-side (C) is resilience, not raw speed. Numbers to be proven at gate A5.

**Unverified ledger:** none blocking. (Exact per-hop ms savings from A pending live histogram = gate A5.)
