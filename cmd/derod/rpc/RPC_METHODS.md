# derod JSON-RPC method list

Endpoints: `POST /json_rpc` (HTTP) and `/ws` (WebSocket, also receives `Block`/`MiniBlock` push notifications).
Every `DERO.*` method also answers under its historical lower-case alias where one is listed.
Registration: `cmd/derod/rpc/websocket_server.go` (`servicemux`, `historical_apis`). Request types for the
original methods live in `rpc/daemon_rpc.go` (consensus-listed, frozen); types for local additions live in
`cmd/derod/rpc`.

## Original methods

| Method | Alias | Params | Notes |
|---|---|---|---|
| DERO.Echo / DERO.Ping | | `[]string` / - | liveness |
| DERO.GetInfo | getinfo, get_info | - | `averageblocktime50` is timestamp-derived; use GetSyncInfo to know if the node is at the tip; r25: `alt_blocks_count` is assigned (settled alt blocks since start, GetConsensusStats) |
| DERO.GetBlock | getblock | `{hash}` or `{height}` (topoheight) | header + blob + json |
| DERO.GetBlockHeaderByTopoHeight | getblockheaderbytopoheight | `{topoheight}` | |
| DERO.GetBlockHeaderByHash | getblockheaderbyhash | `{hash}` | |
| DERO.GetLastBlockHeader | getlastblockheader | - | |
| DERO.GetTxPool | gettxpool | - | txids only (see GetTxPoolDetail) |
| DERO.GetTransaction | gettransactions | `{txs_hashes, decode_as_json}` | |
| DERO.SendRawTransaction | sendrawtransaction | `{tx_as_hex}` | |
| DERO.GetBlockTemplate / DERO.SubmitBlock | getblocktemplate / submitblock | | mining |
| DERO.GetHeight / DERO.GetBlockCount | getheight / getblockcount | - | |
| DERO.GetEncryptedBalance | getencryptedbalance | `{address, topoheight, ...}` | wallets |
| DERO.GetRandomAddress | getrandomaddress | `{scid}` | ring members |
| DERO.GetSC | getsc | `{scid, code, variables, keysstring, ...}` | |
| DERO.GetGasEstimate | getgasestimate | transfer params | |
| DERO.NameToAddress | nametoaddress | `{name, topoheight}` | |

## Local additions (read-only, not consensus-visible)

| Method | Since | Params | Limits | Returns |
|---|---|---|---|---|
| DERO.GetSyncInfo | r12 | - | O(peers) | synced/syncing/stalled/isolated, tip age, lag, counters; r19: `chain_fingerprint` (HF3 fork-block side: `v3 ...`, `v2-remnant ...`, `not reached`, `n/a`), `v2_chain_peers_seen_7d` |
| DERO.GetMiningOutcome | r13 | - | bounded ring | paid / orphaned / pending miniblocks this node submitted |
| DERO.GetSupplyAudit | r18 | - | one walker (waiters honour their ctx); answer cached per chain tip (topoheight + block id), so it always audits the tip read when the call started (r19) | plaintext SC-held DERO vs formula supply; r19 fields `cached`, `compute_ms` |
| DERO.GetEmissionAudit | r23 | - | O(1): a copy of the background auditor's state; the audit itself runs once per block (glue/emission, ~5 ms CPU/block measured offline); `DERO_EMISSION_AUDIT=0` disables it | per-block verdicts (`ok`, `ok_sc`, `sc_unexplained`, `skipped`, `error`, `ALERT`), the emission segment (`segment_from/to`, `verified_heights`, `observed_emission` vs `formula_emission`, `emission_consistent`), fees redistributed, SC deposits/payouts, payees verified, cpu, last alerts, notable plaintext flows (>= 100 ppm of formula supply), recent reports. Proves only that no plaintext value moved outside the published (C, D) deltas, the emission formula, registrations and SC accounting; value inside encrypted amounts is invisible |
| DERO.GetBlockHeadersRange | r19 | `{start_topoheight, end_topoheight}` inclusive | <= 100 headers; end clipped to top; 2 range calls node-wide | `headers[]` (same objects as GetBlockHeaderByTopoHeight); r25: plus `fees` (sum of the txs' fee fields, null if a tx is unreadable), `first_seen_ms` (this node's clock at the first chunk/offer; 0 = not seen live) and `first_seen_local`; `miners[]` keeps an unresolved key "unknown" in its own slot (CO24-C7) |
| DERO.GetMiniBlocks | r19 | `{hash}` or `{topoheight}` | one block (<= 10 miniblocks) | per miniblock: hash, final, highdiff, past, `timestamp16`, `time_ms_estimate`, `ms_before_block`, keyhash, miner address (resolved against the block's own topoheight state), integrator flag; r25: `first_seen_ms` (first accepted notification; finals are never propagated alone, so 0 unless mined here) |
| DERO.GetConsensusStats | r25 | `{block_hashes, miniblock_hashes}` (optional, hex) | <= 100 hashes of each kind; foreign-socket cost 4 | `counters` (miniblock refusals and block rejections by reason since start, duplicate offers), `alt_blocks` (settled alt blocks: count = GetInfo `alt_blocks_count`, unsettled, tracked, newest 256 listed with height and first-seen), `reorg` (the reorg monitor incl. `lifetime`, persisted in `<datadir>/reorg_monitor.json` across restarts), `first_seen[]` per requested hash. No peer is named; the log lines name the sender by its peer_id. Read-only, not consensus-visible |
| DERO.GetDifficultyHistory | r19 | `{count, end_topoheight}` (0 = top; default 100) | <= 1000 points; 2 range calls node-wide | ascending points {topoheight, height, hash, difficulty, timestamp_ms} + mean difficulty, mean block time, hashrate estimate (= mean difficulty, as GetInfo) |
| DERO.GetTxPoolDetail | r19 | `{limit}` (default 100) | <= 1000 entries | per tx: pool, type, size, fee, fee_per_kb, payloads, ring size, height built, sc, burn; mempool by fee/KB first |
| DERO.GetPeerInfo | r19 | - | <= 256 peers, ACTIVE connections only; served on a loopback `--rpc-bind` only unless `ENABLE_PUBLIC_PEER_INFO=1` (it lists peer IPs) | address, direction, heights, top version, latency, clock offset, connected time, bytes, first-relay score, miniblock first/total, version, tag, pruned; `v2_chain_peers_seen_7d` |
| DERO.GetTxStatus | r20 | `{txids: [hex,...]}` | 1..64 txids (more is an error); more than 8 takes one of the 2 node-wide range slots; ctx checked per txid | `topoheight` (tip) + per txid: `state` (mined = in a topo-ordered block within the tx's height window, the GetTransaction ValidBlock rule, which does not prove execution; unconfirmed = in a valid block that has no topological position; pool, regpool, orphaned = stored but no valid block found, which includes a height window outside the indexed range on a pruned node; unknown, invalid_txid), `topoheight`, `block_hash`, `confirmations`. Measured on the live node (r23b, loopback, 100 calls): 16.8 ms p50 for 1 mined txid, 89 ms for 8, GetTransaction 23 ms (both IS_TX_Valid-bound); settled txids are now served from a verified cache (below); pair it with the `/ws` Block push for one call per block r23 finality (reorg-safe, from the consensus rule, not a confirmation count): result `stable_height` (GetInfo's), `final_height`; per mined tx `height`, `final`, `blocks_to_final`. `final` = the tx's block height <= the highest height s <= height - STABLE_LIMIT - 1 that holds exactly one block: consensus refuses blocks below height - 8 (blockchain.go:481-484), so s can never get a sibling and the order at and below it is settled whatever tip wins. Normally `final` turns true 9 heights after the block (about 9 x 18 s); the scan looks at most 64 heights (-1 if none). WatchTx answers and TxStatus pushes carry the same fields |
| DERO.GetFeeEstimate | r23 | `{size}` (optional, bytes, <= 300 KiB) | one pass over the ready mempool, cached 1 s per (topoheight, pool size) | `min_fee_per_kb` (consensus floor: 20 per started KB), `pool_txs`, `pool_bytes`, `block_capacity_bytes` (10,645,504 = max block - 100 KiB, what a template fills), `blocks_to_clear`, `next_block_fee_per_byte` (0 = the floor gets in; else pay this many atomic units PER BYTE), pool fee/KB p10/p50/p90, `pool_fee_per_byte_zero`, and with `size`: `floor_for_size`, `fee_for_size`. The node's template takes the ready pool in FeesPerByte order, and FeesPerByte is an integer `fee / size` (mempool.go:184): every tx paying less than 1 atomic unit per byte ranks 0, in no order, so a higher fee only helps in whole steps of 1 per byte (1024/KB, 51x the floor). Estimate: the template also skips txs for nonce/history/age reasons |
| DERO.WatchTx | r21 | `{txids: [hex,...], confirmations, remove}` (`/ws` only) | <= 64 watched txids per socket, 4096 node-wide (more is an error); `confirmations` 1..128, default 10 | the current GetTxStatus object of each txid (`txs`) and `watching`. Then a `TxStatus` push `{topoheight, txs: [...]}` whenever a watched txid changes state (unknown/pool/mined/orphaned, also back after a reorg) and at every new confirmation until `confirmations`, after which the watch ends; a txid still `unknown` after 10 min is listed once in `expired` and dropped (foreign sockets: 512 watches in total). Each distinct txid is checked once per check however many sockets watch it; mined txids only at a new block |
| DERO.GetMonetaryIntegrity | r23b | `{list}` (optional bool: include the 75 table entries) | O(1): the table facts are computed once (75 entries), the rest are copies of in-memory counters; measured 0.7-1.1 ms p50 on a mainnet clone (loopback, includes HTTP) | `emission`: GetEmissionAudit's cumulative totals without its block lists; `hf3_exemption`: `entries` (75), `min_height`/`max_height` (7,415,466..7,497,942), `hf3_height`, `all_below_hf3`, `tx_parity_true`, `parity_true` (the field execution swaps in; the table never sets it: 0), `last_includable_height` (= max_height + TX_VALIDITY_HEIGHT - 1, blockchain.go:786: no block above it can carry any entry), `window_closed`, `cache_key_rule`, `digest` = sha256 over the entries' lines `txid bl_tips height tx_parity parity` sorted by txid (`digest_format`; recomputing it from blockchain/hardfork_fixes.go with any script gives f5e56ab3...ecdb at 21cd5b7); `finality`: the reorg monitor's counters and `last` event, `final_violations` (must stay 0); `limits`: what none of it proves (value inside encrypted amounts, only the audited segment, the table's honesty). `status` ALERT on an emission alert, a finality violation, or (mainnet) a table entry at or above HF3 |

Cost notes: range methods share a 2-slot semaphore (`RANGE_CONCURRENCY`); a caller whose context ends while
waiting gets `busy`. Every loop checks the request context, so a disconnected client stops costing store reads.

Transport limits (r19, cmd/derod/rpc/ws_hardening.go; loopback clients are exempt from all three): a remote address
may have 32 `/json_rpc` requests in flight and 64 open websockets (more get HTTP 429), and a remote JSON-RPC batch of
more than 256 requests is refused with HTTP 413. Websocket pushes: a client whose previous push of the same class
(Block/Height/BlockInfo bundle, or MiniBlock) is still being written is skipped for that event and counted in
`rpc_ws_push_skipped_total`; its 60 s write deadline then closes it if it never reads.

Reorg event (r23b, reorg_events.go): `DERO.Subscribe {"events":["Reorg"]}` adds a `Reorg` push before the Block/Height
bundle of every block that replaced a block the node had ordered at one of the last 32 topoheights (or removed one):
`{seq, fork_topoheight, replaced, lowest_replaced_height, old_topoheight, new_topoheight, new_top_hash, old_hashes,
final_height_before, final_violated, local_rewind}`. A wallet that cached anything per topoheight re-reads from `fork_topoheight`.
`BlockInfo` carries `reorg_seq` (omitted while 0): a jump without a Reorg push means the push was skipped (the socket
was still writing the previous bundle) and the client should re-read from its last checked topoheight; the last event is
also in `DERO.GetMonetaryIntegrity` `finality.last`. The same check tests the r23 finality rule live: a replaced block at
or below the `final_height` announced at the previous block counts in `rpc_reorg_final_violations_total` (logged at
ERROR, flips GetMonetaryIntegrity to ALERT, empties the settled-tx cache). A local rewind (console `pop`, a SyncNode
resync: the chain height drops and only topoheights above the new top vanish, or the height drops to or below the
previous final height) is pushed with `local_rewind: true`, counted in `rpc_reorg_local_rewinds_total` /
`finality.local_rewinds`, and never judged as a violation. Cost measured on a simulator chain: 154-335 us
per block (32 topo reads, one height lookup per new block id, one final-height scan). Series `rpc_reorgs_observed_total`,
`rpc_reorg_replaced_topoheights_total`. Subscribe names: `BlockInfo`, `MiniBlock`, `Reorg`, `TxPool`.

Settled-tx cache (r23b, tx_status_final_cache.go; `DERO_TXSTATUS_CACHE=0` turns it off): GetTxStatus and WatchTx keep
the answer for a mined tx once the whole window IS_TX_Valid scans (block height + 2*TX_VALIDITY_HEIGHT) is at or below
the final height, and re-check every hit against the topo index (one record read; a mismatch drops the entry). On a
mainnet clone (loopback, 59 calls after the first, two interleaved A/B pairs) GetTxStatus of 1 settled txid went from
23.7 / 18.1 ms p50 to 1.0 / 0.9 ms and of 8 txids from 105 / 84 ms to 1.2 / 1.4 ms, same answers; simulator rpcload
(6 HTTP clients, GetTxStatus only): CPU per call 4,703 / 4,296 us -> 670 / 581 us. <= 16,384 entries. Series
`rpc_txstatus_final_cache_total{result=hit|miss|stale|stored}`, `rpc_txstatus_final_cache_flushes_total`.

Push events (r21, ws_tx_events.go): `DERO.Subscribe {"events":["TxPool"]}` adds a `TxPool` push
`{added, removed, pool_size, truncated}` whenever the mempool's txid set changed (checked every 1 s and at each block;
at most 256 txids per direction, `truncated` then says to re-read with `DERO.GetTxPool`; the first check after
subscribing takes the baseline only). Subscribe names are now `BlockInfo`, `MiniBlock`, `TxPool`. Series:
`rpc_watched_txids`, `rpc_tx_events_status_checks_total`, `rpc_tx_events_sent_total`.

Browser guard (r20, glue/httpguard, cmd/derod/rpc/ws_hardening.go `rpc_guard`): on a loopback `--rpc-bind` a request
whose `Host` is not this machine (loopback IP, `localhost`, `*.localhost`) gets HTTP 403 (DNS rebinding). A reverse
proxy that forwards another Host name must list it: `DERO_RPC_ALLOWED_HOSTS=node.lan,rpc.example` (comma list, ports
ignored; the miner's `/metrics` reads `DERO_METRICS_ALLOWED_HOSTS`). A request with a foreign `Origin` (a web page of
another site) may only open `/ws`; there it is limited like a remote client, with ALL foreign Origins sharing one
node-wide budget (64 websockets), and `DERO.GetPeerInfo` / `DERO.GetMiningOutcome` are refused. Browser extensions
and Electron/file:// apps send an Origin too; an operator who trusts one lists it exactly:
`DERO_RPC_ALLOWED_ORIGINS=chrome-extension://<id>,file://` (it is then treated as this machine). `null` is never
accepted there (r21): it is the Origin of every sandboxed iframe on the web. Cross-site websockets together hold at
most one of the two node-wide range slots (r21), so local explorers always get one. Refusals are counted
in `rpc_guard_refused_total{reason="host"|"origin"}`. Non-browser clients (wallets, miners, curl) are unaffected.
Call rate of cross-site websockets (r21, closes R-6; ws_foreign_rate.go): each foreign-Origin socket may make 20
weighted calls/s (burst 40), and the foreign sockets that arrive over loopback (pages in a browser on this machine)
together 200/s (burst 400); range reads cost 8, GetMiniBlocks / GetTxPoolDetail / GetTxStatus / WatchTx 4,
block/tx/balance/SC reads 2, anything else 1. REMOTE browser sockets (any request carrying an Origin of another host,
e.g. a web wallet on a public `--rpc-bind 0.0.0.0` node) are foreign too and get the per-socket limit, but not the
shared loopback bucket, so one remote client cannot starve the others (r21 merge). A refused call gets JSON-RPC
error `-32029` (the socket stays open) and is counted in `rpc_foreign_rate_limited_total`. Same-machine and remote
non-browser sockets (no foreign Origin) have no call-rate limit and no per-call cost (they keep the shared method
table). Foreign sockets together may hold at most 512 of the 4096 WatchTx watches, and any watch whose txid stays
`unknown` for 10 minutes ends with a last `TxStatus` push that lists it under `expired`.
Post-install check: `curl -s -o /dev/null -w '%{http_code}' -H 'Host: rebind.example' http://127.0.0.1:10102/metrics`
must print 403, and the same without the Host header 200.

Getwork job dispatch (r23, getwork_dispatch.go; port 10100, not JSON-RPC): template fetches are numbered in order
and a miner is never sent an older job after a newer one (two SendJobs overlap: the miniblock notification and the
10 ms dispatch loop; skips counted in `getwork_jobs_superseded_total`); the loop no longer resends a job the
notification already sent for the same miniblock count and height (not counted: until r27 this line named a
"coalesced jobs" counter that never existed in the source; sends are counted in `getwork_job_dispatch_total{reason}`); a new connection
gets its first job at once, only that connection (`getwork_first_jobs_total`). A miner that stops reading is closed by
nbio once its kernel and 32 KiB write buffers are full and a 100 ms write deadline passes (measured: after 1,801 jobs of
~330 bytes, about 10 minutes at the live 3.1 jobs/s); other miners are not delayed.

Typed errors and additive fields (r25, r25_rpcrobust.go; compat: every change is either an error where the call
used to panic or answer wrongly, or an additive JSON field that old clients ignore):

| Call | Before r25 | From r25 |
|---|---|---|
| GetEncryptedBalance / GetSC at a topoheight below `prunedheight` (GetInfo) | GetEncryptedBalance: -32098 `internal error: file does not exist` + an ERROR line with a stack; GetSC: status OK with the state of the prune point under the requested topoheight | `-32031 state not available: topoheight N is below pruned topoheight P`, refused before any read; one rate-limited `WARNING:` line per method per minute (no stack); `rpc_state_unavailable_total{method}`. Note: GetEncryptedBalance takes `topoheight` 0 (the JSON default when the field is omitted) as genesis: send `-1` for the tip |
| GetEncryptedBalance with an unparsable address | -32098 `internal error: ...` + ERROR + stack | `-32602 invalid address: ...`, `rpc_input_refused_total{method,kind="address"}` |
| GetEncryptedBalance / GetRandomAddress with an SCID whose first byte is 0x3a (`:`) | -32098 `internal error: Bucket cannot start with ':'` + ERROR + stack | `-32602 invalid scid: ...`, `kind="scid"` |
| NameToAddress whose stored value is not a key | nil dereference inside the recover (-32098, ERROR + stack) | `-32602 invalid name_value: ...` |
| GetBlockHeaderByHash for an unknown or pruned hash | no error, status `""`, an all-zero header (the handler shadowed its named `err`) | `-32032 block not found: <hash>`, `rpc_block_not_found_total{method}` |
| GetTransaction for a txid the node does not hold | status OK, `as_hex` `""`, `block_height` 0 (unchanged) | the same, plus `txs_status` (`in_chain` / `in_pool` / `not_found`, index-aligned with `txs`); `rpc_tx_not_found_total` |
| GetInfo | `total_supply` = CalcSupply(height) / 100000, unlabelled | unchanged value, plus `total_supply_basis`: the emission formula, not a count of coins (disclosure FX-N9) |

Typed answers from r26 (node-rpc; same compat rule):

| Call | Before r26 | From r26 |
|---|---|---|
| NameToAddress for a name nobody registered | -32098 `leaf not found: ...` (the raw store error, code of "operating environment" faults) | `-32032 name not found: <name>` (name echoed up to 64 bytes), `rpc_name_not_found_total`; other store errors unchanged |
| GetEncryptedBalance with `topoheight` left out, on a pruned node | (since r25) `-32031 ... topoheight 0 is below pruned topoheight P`: an omitted field is JSON 0 = genesis | unchanged, now pinned by a test; send `-1` for the tip |
| GetBlockHeadersRange / GetMiniBlocks / GetDifficultyHistory with a parameter name the method does not have (e.g. `start`/`end`) | ignored: the real fields decoded as 0, so the call read topoheight 0 | `-32602 invalid parameters` (jrpc2 strict fields; from r27 the text names the field, below). `{}` is still accepted |
| GetBlockHeadersRange / GetMiniBlocks (by topoheight) below `prunedheight` | -32098 `topoheight N: empty block` (no log line) or a block-not-found text | `-32031 state not available: topoheight N is below pruned topoheight P`, `rpc_state_unavailable_total{method}`; also for a topo record that names no block (pruned shape) |
| GetDifficultyHistory over pruned topoheights | a pruned record panicked in Load_Block_Difficulty (recovered: -32098 + ERROR + stack) | a window reaching below `prunedheight` is clipped to it; one ending below it is `-32031`; a pruned-shape record is skipped as a hole |
| GetRandomAddress decoy window | accounts unchanged over the last 5 topoheights, but only above topoheight 100 (on shorter chains every account, including ones that just mined or were just used as a ring member: wallet txs then failed `statement 0 verification failed` / `Invalid Nonce`) | the 5-topoheight window at every height, clamped at the prune point; mainnet answers are unchanged |

Typed answers from r27 (rpc-metrics, r27_rpcmetrics.go; same compat rule; codes unchanged, only texts and counters):

| Call | Before r27 | From r27 |
|---|---|---|
| Any method whose parameters do not decode (unknown name on the strict explorer methods, a wrong JSON type, an array) | `-32602 invalid parameters: [-32602] invalid parameters` (the code doubled into the text, no field named; jrpc2's handler wrapper drops the decoder text) | `-32602 invalid parameters: unknown field "start" (accepted: start_topoheight, end_topoheight)`, `... field topoheight: want uint64, got string`, `... want a JSON object, got array (accepted fields: ...)`; `data` = `{"field", "accepted"}`; `rpc_params_refused_total` |
| Every error response | counted per method only (`rpc_request_errors_total{method}`, no code) | also `rpc_error_responses_total{code}`: one series per listed code (-32700, -32600, -32601, -32602, -32603, -32098, -32097, -32096, -32029, -32030, -32031, -32032) and `other`, all present at 0 from the start |
| A topo record that names no block on a node with prune floor 0 | `-32031 ... topoheight N is below pruned topoheight 0` (false) | `-32031 state not available: the record at topoheight N names no block (pruned topoheight P)` whenever N >= P |
| NameToAddress echo of a long unknown name | cut at byte 64, possibly inside a multi-byte rune | cut on a rune boundary at or below byte 64, then `...` |
| GetEmissionAudit / GetMonetaryIntegrity / GetSupplyAudit after a recovered panic | `-32098 panic occured. stack trace r ...`, no ERROR line, not in `rpc_recovered_panics_total` | `-32098 internal error: ...`, ERROR + stack, counted, like every other handler |

First-event counters (`rpc_state_unavailable_total{method}`, `rpc_input_refused_total{method,kind}`,
`rpc_name_not_found_total`, `rpc_tx_not_found_total`, `rpc_block_not_found_total{method}`, `rpc_limited_total`, ...)
are registered at start (`rpc_counters_preregistered`), so 0 means "never happened" and absent means "not built in".
`dero_p2p_ban_list_entries` is the ban list now (persisted entries included); `p2p_bans_total` counts only the bans
made since the start, so it read 0 while the list held a ban loaded from disk.

The other `panic(err)` sites in these handlers are store or start-up invariants and keep the loud ERROR + stack
(audit: r25 rpcrobust evidence `b86_panic_audit.txt`). The wallet RPC server's `/json_rpc` (walletapi/rpcserver,
r25 B40) now accepts `application/json; charset=utf-8` and answers a wrong method or media type with a JSON-RPC
-32600 body (405 / 415), as derod's has since r24.

Example:

```
curl -s -H 'Content-Type: application/json' http://127.0.0.1:10102/json_rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"DERO.GetMiniBlocks","params":{"topoheight":7806000}}'
```
