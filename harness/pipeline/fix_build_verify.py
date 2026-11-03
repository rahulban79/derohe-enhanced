#!/usr/bin/env python3
"""fix_build_verify.py — the whole fix → build → verify → install → re-project pipeline, as one tracked run.

Every stage appends one JSON event to harness/loop/runs/pipeline_<ts>.jsonl and the run ends with
harness/loop/PIPELINE_LAST.json. A stage that fails its quality check stops the run before anything is
installed, so bin/ only ever receives binaries that passed every stage before INSTALL.

  S1 guard     consensus_guard: changed consensus-package lines are logging-only
  S2 format    gofmt on the files this round owns; go vet shows no finding absent from the base
  S3a flaky    (R20) the tests THIS change adds (git diff vs --new-tests-base, plus untracked *_test.go) run -race
               -count=3: 3/3 failures stop the run; 1-2/3 are FLAKY, recorded separately (flaky.json) and do not
               stop it — a timing test that flakes on the live mining box must be told apart from a real failure
  S3 test      the new unit tests, then the full p2p + blockchain packages
  S3s sound    (R23b) every test harness/loop/SOUNDNESS_CLAIMS.json names as the backing of a soundness-page claim
               (the HF3 replay, the table/TXID tests, the emission auditor, txcanon, txprecheck) runs once (the
               !race-only simulator test without -race) and harness/loop/SOUNDNESS_LAST.json records each test's status
               with a sha256 fingerprint of its test file and the claim's watch files; gate G22 accepts a PASS only
               while those files are unchanged. --soundness-only runs S1 + S3s alone. A failing soundness test FAILS.
  S3k kats     (R20) the stand-alone harness KATs (harness/kat/test_*.py) BEFORE build/install, so a broken intel
               tool stops the run before bin/ changes (before R20 they ran only in S7, after install)
  S4 build     derod, dero-miner, dero-wallet-cli into bin/.staging; version + flags checked
  S4b miner    the staged miner's --bench, gated on HASHES PER CPU-SECOND (wall ratios on this shared box are not
               predictive, r18): descriptor beats SA-IS; staged >= 0.93 x installed; and the split mode's CPU side
               (--bench --gpu-mode=split: sort-only on CPU-prepared stage-1 texts, the GPU is never touched) beats a
               full CPU hash per CPU-second. The GPU side of split is NOT benched here (the live gpu_split_server
               owns the GPU); its live staged H/s is read from miner_intel's newest snapshot and recorded. Every bench
               runs under --benchlock <file> (fcntl lock shared with benchlock.py); R21: without one S4b FAILS unless
               --no-benchlock says so (r20's S4b ran unlocked, "lock": "none", next to other agents' benches).
               R21 LIKE FOR LIKE: staged vs installed run with the SAME --sort, and each run's sorter is read back from
               its 'suffix sort' line; r20 compared the installed --sort=descriptor (the Go port) with the staged
               --sort=auto (native C) and recorded x1.654 for what an interleaved A/B measured at x1.04.
  S4c gpu      (R22) the GPU side of split, like for like, when the Swift server CHANGED since its recorded build
               (sha256 of gpu-miner-poc/gpu_split_server.swift vs its BUILD_STAMPS line): opt-in with --gpu-bench, which
               builds the staged server (xcrun swiftc -O into bin/.staging), proves it bit-exact (TestRealGPUBitExact,
               256-nonce batches) and A/Bs it against a copy of the installed server with TestGPUCapacity (512-nonce
               command buffers, --gpu-max 50, interleaved, 3 rounds) under the bench lock and harness/intel/gpu_watch.py
               (exit 99 = the live GPU split was disturbed: FAIL and stop). A changed server without --gpu-bench FAILS
               unless --no-gpu-bench says so on purpose; an unchanged one is SKIP (recorded). Contended GPU: only the
               interleaved staged/installed RATIO is judged (>= 0.93), never an absolute rate.
  R23 S4b/S4c CONTENTION: a read-only process census (harness/intel/contention.py, names only) is taken before and
               after each A/B. On a contended box (foreign processes take more cores than the miner's --cpu-max budget and
               derod leave) a ratio is not evidence of a gain or a regression: the A/B is REFUSED (status REFUSED, the
               correctness checks — lock, bit-exactness, a printed rate, the sorter line, a disturbed GPU — still FAIL).
               REFUSED stops the run unless --contended-ok says to go on (recorded); gate G20 refuses a PASS/FAIL ratio
               verdict whose census says contended. S4c with --gpu-bench on an UNCHANGED server is a self-A/B (the staged
               build of the same source vs the installed binary): bit-exact, rates > 0, and the ratio inside
               [0.93, 1/0.93] — the band the gate needs the bench's own noise to fit — so the GPU path is exercised every
               round; --gpu-bench-only runs S4c alone.
  r24 PAUSED   while harness/round.json rounds[current].tracks.miner == 'paused' (artifacts/dero-rft.md §0.3; the user
               paused the miner track and runs no miner) S4b and S4c record PAUSED, citing §0.3, instead of benching —
               but only when no miner source (cmd/dero-miner, astrobwt, gpu-miner-poc) changed since the round's
               new_tests_base: a miner change while paused still needs its A/B and the stage runs exactly as before.
               S7 accepts a PAUSED gate row only for G17/G18/G21 while paused (kit/roundtracks.py). With the track
               'active' or absent nothing changes. S3/S3b: a failure of a test that harness/loop/KNOWN_TEST_FAILURES.json
               lists as FLAKY (with its measured evidence) is re-run -count=3; it is recorded as known-flaky only if
               at least 2 of the 3 re-runs pass without a race, otherwise it FAILS as before (B21).
  S5 shadow    the NEW derod on an APFS clone of the live datadir, on loopback ports, syncing only from the live
               node (--add-exclusive-node=127.0.0.1:11011);
               wherever both report the same topoheight their balance-tree root (treehash) and block hash must
               be equal — the new binary computes the same chain, not just compiles
  S6 install   back up the running binaries once, then rename the staged ones over bin/* (the running derod
               keeps its old inode; the operator restarts it when ready)
  S7 project   miners → page → report → index → KATs + mutations → gates

  S3b's go_mutate also compares every mutation package's FULL test run with the base (--baseline): failures red on
  both are recorded as upstream in the gomut record, failures only here stop the run.

  python3 harness/pipeline/fix_build_verify.py [--shadow-seconds 1200] [--no-install] [--project-only]
                                               [--new-tests-base <rev>]   (r23c: default from harness/round.json)
"""
import argparse, contextlib, datetime, fcntl, importlib.util, json, os, re, shutil, signal, subprocess, sys, time, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parent
ROOT = HARNESS.parent
BIN = ROOT / 'bin'
STAGE = BIN / '.staging'
LIVE_DATA = Path(os.path.expanduser(os.environ.get('DERO_DATADIR', '~/dero-data')) + '/mainnet')
LIVE_RPC = 'http://127.0.0.1:10102/json_rpc'
SHADOW_RPC = 'http://127.0.0.1:20102/json_rpc'
OWNED = ['p2p/object_errors.go', 'p2p/object_errors_test.go', 'p2p/connection_pool.go', 'p2p/chain_sync.go',
         'blockchain/sc_revert_log.go', 'blockchain/sc_revert_log_test.go', 'blockchain/transaction_execute.go',
         'astrobwt/astrobwtv3/pow.go', 'astrobwt/astrobwtv3/gpu_bridge.go', 'cmd/dero-miner/miner.go',
         'cmd/dero-miner/gpu_worker.go', 'cmd/dero-miner/fastsort.go', 'cmd/dero-miner/fastsort_test.go',
         'cmd/dero-miner/thread_darwin.go', 'cmd/dero-miner/dsa/dsa.go', 'cmd/dero-miner/dsa/verify.go',
         'cmd/dero-miner/dsa/dsa_test.go', 'cmd/dero-miner/stats.go', 'cmd/dero-miner/stats_test.go',
         'p2p/penalty.go', 'p2p/hardening_test.go', 'p2p/chunk_server.go', 'cmd/derod/rpc/hashrate_estimate_test.go',
         'cmd/derod/rpc/rpc_dero_getblocktemplate.go', 'cmd/derod/rpc/rpc_dero_getinfo.go',
         'cmd/dero-miner/astropair/bench_test.go',
         'cmd/dero-miner/astropair/gen_sha.go',
         'cmd/dero-miner/astropair/gen_stage.go',
         'cmd/dero-miner/astropair/generate.go',
         'cmd/dero-miner/astropair/pair.go',
         'cmd/dero-miner/astropair/pair_test.go',
         'cmd/dero-miner/astropair/sha.go',
         'cmd/dero-miner/astropair/sha_arm64.go',
         'cmd/dero-miner/astropair/sha_generic.go',
         'cmd/dero-miner/astropair/sha_other.go',
         'cmd/dero-miner/astropair/stage_gen.go',
         'cmd/dero-miner/astropair/stage_support.go',
         'cmd/dero-miner/astropair/stagegen_lib.go',
         'cmd/dero-miner/dsac/dsac.go',
         'cmd/dero-miner/dsac/dsac_other.go',
         'cmd/dero-miner/dsac/dsac_test.go',
         'cmd/dero-miner/pairhash.go',
         'cmd/dero-miner/pairhash_test.go',
         'cmd/dero-miner/gpu_stale_test.go',
         'cmd/derod/rpc/rpc_dero_getsyncinfo.go',
         'cmd/dero-miner/outcome.go',
         'cmd/dero-miner/outcome_test.go',
         'cmd/dero-miner/mine_threads_test.go',
         'cmd/derod/rpc/template_refresh_test.go',
         'cmd/derod/rpc/mining_outcome.go',
         'cmd/derod/rpc/mining_outcome_test.go',
         'p2p/first_relay.go',
         'p2p/first_relay_test.go',
         'p2p/own_broadcast.go',
         'p2p/own_broadcast_test.go',
         'p2p/peer_list_counts_test.go',
         'p2p/propagation_test.go',
         'p2p/rpc_cbor_codec.go',
         'p2p/v2_offences.go',
         'p2p/v2_offences_test.go',
         'p2p/peer_pool.go',
         'p2p/controller.go',
         # Round 18 merge
         'p2p/diversity.go', 'p2p/diversity_test.go', 'p2p/sync_pipeline.go', 'p2p/sync_pipeline_test.go',
         'p2p/kcp_tune_test.go', 'p2p/peer_backoff_test.go', 'p2p/first_relay_persist_test.go', 'p2p/atomic_fields_test.go',
         'p2p/codec_perf_test.go', 'p2p/latency_sort_bench_test.go', 'p2p/rpc_handshake.go', 'p2p/rpc_notifications.go',
         'p2p/common.go', 'p2p/chain_bootstrap.go',
         'cmd/derod/main.go', 'cmd/derod/dummy_test.go', 'cmd/derod/rpc/bind_policy.go', 'cmd/derod/rpc/bind_policy_test.go',
         'cmd/derod/rpc/rpc_dero_getsupplyaudit.go', 'cmd/derod/rpc/rpc_dero_getsupplyaudit_test.go',
         'cmd/derod/rpc/job_message_test.go', 'cmd/derod/rpc/websocket_getwork_server.go', 'cmd/derod/rpc/websocket_server.go',
         'cmd/dero-miner/cpurate.go', 'cmd/dero-miner/cpurate_test.go', 'cmd/dero-miner/cputime_unix.go',
         'cmd/dero-miner/cputime_windows.go', 'cmd/dero-miner/gpu_split.go', 'cmd/dero-miner/gpu_split_test.go',
         'cmd/dero-miner/gpu_worker_test.go', 'cmd/dero-miner/astropair/split.go',
         'cmd/dero-miner/gsplit/engine.go', 'cmd/dero-miner/gsplit/engine_test.go', 'cmd/dero-miner/gsplit/harness_test.go',
         'cmd/dero-miner/gsplit/shm_darwin.go', 'cmd/dero-miner/gsplit/shm_other.go',
         'cmd/r18kcpbench/main.go', 'cmd/r18udpdelay/main.go', 'cmd/dero-wallet-cli/main.go',
         'glue/rwc/limit.go', 'glue/rwc/rwc.go', 'glue/rwc/rwc_limit_test.go',
         'walletapi/rpcserver/origin_guard.go', 'walletapi/rpcserver/origin_guard_test.go',
         'walletapi/rpcserver/rpc_websocket_server.go', 'walletapi/rpcserver/install_sc_limit_test.go',
         'walletapi/xswd/xswd.go', 'metrics/diskusage.go', 'metrics/diskusage_js.go',
         # Round 19 harness
         'cmd/dero-miner/splitbench.go', 'cmd/dero-miner/splitbench_test.go',
         # Round 19 merge (every Go file the combined patch adds or changes)
         'cmd/dero-miner/metrics.go', 'cmd/dero-miner/metrics_test.go', 'cmd/dero-wallet-cli/dummy_test.go',
         'cmd/dero-wallet-cli/redact_test.go', 'cmd/derod/private_file_test.go',
         'cmd/derod/rpc/getwork_session_test.go', 'cmd/derod/rpc/nat_hint_test.go', 'cmd/derod/rpc/node_metrics.go',
         'cmd/derod/rpc/node_metrics_test.go', 'cmd/derod/rpc/notify_fanout_test.go',
         'cmd/derod/rpc/registration_cache.go', 'cmd/derod/rpc/registration_cache_test.go',
         'cmd/derod/rpc/rpc_dero_explorer.go', 'cmd/derod/rpc/rpc_dero_explorer_test.go',
         'cmd/derod/rpc/rpc_dero_getencryptedbalance.go', 'cmd/derod/rpc/supply_audit_cache_test.go',
         'cmd/derod/rpc/ws_hardening.go', 'cmd/derod/rpc/ws_hardening_test.go', 'cmd/derod/shutdown_test.go',
         'cmd/explorer/explorerlib/explorerlib.go', 'cmd/explorer/explorerlib/hardening.go',
         'cmd/explorer/explorerlib/hardening_test.go', 'cmd/simulator/simulator.go',
         'cmd/simulator/txflow_load_test.go', 'cmd/simulator/wallets.go', 'config/version.go',
         'glue/rwc/rwc_write_test.go', 'glue/rwc/rwc_write_timeout_test.go', 'p2p/bans.go',
         'p2p/bootstrap_pipeline.go', 'p2p/bootstrap_pipeline_test.go', 'p2p/call.go', 'p2p/fuzz_decoders_test.go',
         'p2p/inbound_guard_test.go', 'p2p/nat/manager.go', 'p2p/nat/nat_test.go', 'p2p/nat/pmp.go',
         'p2p/nat/upnp.go', 'p2p/netlayers.go', 'p2p/netlayers_test.go', 'p2p/ntp_correction_test.go',
         'p2p/peer_info.go', 'p2p/peer_info_test.go', 'p2p/seed_backoff.go', 'p2p/seed_backoff_test.go',
         'p2p/sync_continue.go', 'p2p/sync_continue_test.go', 'p2p/timecheck.go', 'p2p/tx_flow.go',
         'p2p/tx_flow_test.go', 'tools/dashboard/embed.go', 'tools/dashboard/embed_test.go',
         'walletapi/balance_decoder.go', 'walletapi/balance_decoder_test.go', 'walletapi/daemon_communication.go',
         'walletapi/r19_wallet_test.go', 'walletapi/ring_fetch.go', 'walletapi/ring_fetch_test.go',
         'walletapi/rpcserver/gettransfers_paged_test.go', 'walletapi/rpcserver/rpc_gettransfers.go',
         'walletapi/sync_bench_test.go', 'walletapi/sync_cache.go', 'walletapi/wallet.go',
         'walletapi/wallet_disk.go', 'walletapi/wallet_memory.go', 'walletapi/wallet_transfer.go',
         'walletapi/xswd/r19_security_test.go', 'walletapi/xswd/xswd_bind_test.go',
         # Round 20 (rpcwallet)
         'walletapi/sync_prefetch.go', 'walletapi/sync_prefetch_test.go', 'walletapi/rpcserver/http_timeouts.go',
         'walletapi/rpcserver/http_timeouts_test.go',
         'cmd/derod/rpc/rpc_dero_gettxstatus.go', 'cmd/derod/rpc/tx_status_test.go', 'metrics/metrics.go',
         'metrics/kcp_metrics_test.go',
         # Round 20 merge: the ONE miner log implementation (forensics minerlog.go; replaces rpcwallet log_file.go,
         # harness logrotate.go and cpuminer rotate_log)
         'cmd/dero-miner/minerlog.go', 'cmd/dero-miner/minerlog_test.go',
         # Round 20 merge (every other Go file the combined patch adds or changes)
         'cmd/dero-miner/crashlog_go123.go', 'cmd/dero-miner/crashlog_old.go', 'cmd/dero-miner/getwork_conn.go',
         'cmd/dero-miner/gsplit/kernel_source_test.go', 'cmd/dero-miner/metrics_guard_test.go',
         'cmd/derod/log_rotation.go', 'cmd/derod/log_rotation_test.go', 'cmd/derod/rpc/fuzz_params_test.go',
         'cmd/derod/rpc/getwork_presence.go', 'cmd/derod/rpc/getwork_presence_test.go',
         'cmd/derod/rpc/rpc_guard_test.go', 'globals/globals.go', 'glue/httpguard/httpguard.go',
         'glue/httpguard/httpguard_test.go', 'metrics/process_darwin.go', 'metrics/process_other.go',
         'metrics/storage_metrics.go', 'metrics/storage_metrics_test.go', 'p2p/compact_block.go',
         'p2p/compact_block_test.go', 'p2p/nat/fuzz_nat_test.go', 'p2p/persist.go', 'p2p/persist_r20_test.go',
         'p2p/r20_security_test.go', 'p2p/tls_policy.go', 'p2p/traffic.go', 'p2p/traffic_test.go', 'p2p/tx_ask.go',
         'p2p/tx_ask_test.go',
         # Round 21 rpcws: foreign-websocket call rate (R-6), WatchTx/TxPool pushes, once-per-job getwork frame,
         # wallet sync wakes on the Height push
         'cmd/derod/rpc/ws_foreign_rate.go', 'cmd/derod/rpc/ws_tx_events.go', 'cmd/derod/rpc/job_frame.go',
         'cmd/derod/rpc/r21_rpcws_test.go', 'walletapi/sync_wake.go',
         'walletapi/sync_wake_test.go',
         # Round 21 merge (every other Go file the combined patch adds or changes)
         'cmd/dero-miner/cgoyield.go', 'cmd/dero-miner/cgoyield_test.go', 'cmd/dero-miner/fdlimits.go',
         'cmd/dero-miner/fdlimits_test.go', 'cmd/dero-miner/gpu_stamp.go', 'cmd/dero-miner/gpu_stamp_test.go',
         'cmd/dero-miner/gsplit/busy.go', 'cmd/dero-miner/gsplit/busy_test.go',
         'cmd/dero-miner/gsplit/footprint_real_test.go', 'cmd/dero-miner/gsplit/overhead_test.go',
         'cmd/dero-miner/gsplit/shm_darwin_test.go', 'cmd/dero-miner/gsplit/yield_exp_test.go',
         'cmd/dero-miner/job_guard.go', 'cmd/dero-miner/job_guard_test.go', 'cmd/dero-miner/pidalive_unix.go',
         'cmd/dero-miner/pidalive_windows.go', 'cmd/dero-miner/runledger.go', 'cmd/dero-miner/runledger_test.go',
         'cmd/dero-wallet-cli/fileverify_test.go', 'cmd/dero-wallet-cli/prompt.go', 'cmd/derod/prune_preflight.go',
         'cmd/derod/prune_preflight_test.go', 'metrics/process_darwin_test.go', 'p2p/counter_registry.go',
         'p2p/counter_registry_test.go', 'p2p/frame_budget_test.go', 'p2p/grey_quarantine.go',
         'p2p/grey_quarantine_test.go', 'p2p/metrics_preregister.go', 'p2p/metrics_preregister_test.go',
         'p2p/tx_known.go', 'p2p/tx_known_test.go', 'p2p/unrequested_tx_test.go',
         # Round 22 merge (every Go file the combined patch adds or changes)
         'cmd/dero-miner/dsac/prof_test.go', 'cmd/dero-miner/dutytune.go', 'cmd/dero-miner/dutytune_test.go',
         'cmd/dero-miner/fuzz_r22_test.go', 'cmd/dero-miner/gsplit/cpumax_sim_test.go',
         'cmd/dero-miner/gsplit/duty.go', 'cmd/dero-miner/gsplit/duty_test.go',
         'cmd/dero-miner/gsplit/splitpipe_r22_test.go', 'cmd/dero-miner/job_guard_r22_test.go',
         'cmd/dero-miner/metrics_r22_test.go', 'cmd/dero-miner/powtarget.go', 'cmd/dero-miner/powtarget_test.go',
         'cmd/derod/rpc/fuzz_r22_test.go', 'cmd/derod/rpc/r22_canonical_key_test.go',
         'cmd/derod/rpc/rpc_dero_getrandomaddress.go', 'cmd/derod/rpc/rpc_dero_gettransactions.go',
         'cmd/derod/rpc/rpc_dero_sendrawtransaction.go', 'cmd/derod/rpc/tx_result_cache.go',
         'cmd/derod/rpc/tx_result_cache_test.go', 'cmd/simulator/rpcload_test.go',
         'cryptography/bn256/r22_decode_audit_test.go', 'cryptography/crypto/r22_decode_fuzz_test.go',
         'glue/txcanon/txcanon.go', 'glue/txcanon/txcanon_test.go', 'p2p/inv_budget.go', 'p2p/nat/probe.go',
         'p2p/nat/probe_live_test.go', 'p2p/nat/probe_test.go', 'p2p/r22_relay_admit_test.go',
         'p2p/r22_security_test.go', 'p2p/stuck_peer.go', 'p2p/stuck_peer_test.go',
         'proof/r22_payment_proof_test.go', 'rpc/r22_address_fuzz_test.go', 'walletapi/cipher.go',
         'walletapi/r22_cipher_test.go', 'walletapi/r22_multi_payload_test.go', 'walletapi/r22_ring_order_test.go',
         'walletapi/r22_signature_test.go', 'walletapi/r22m_ring_space_test.go', 'walletapi/transaction_build.go',
         # Round 23 merge (every Go file the combined patch adds or changes)
         'cmd/dero-miner/contention.go', 'cmd/dero-miner/contention_test.go', 'cmd/dero-miner/cpurate_test.go',
         'cmd/dero-miner/dutytune.go', 'cmd/dero-miner/dutytune_r23_test.go', 'cmd/dero-miner/dutytune_test.go',
         'cmd/dero-miner/gpu_split.go', 'cmd/dero-miner/job_latency.go', 'cmd/dero-miner/job_latency_test.go',
         'cmd/dero-miner/metrics.go', 'cmd/dero-miner/miner.go', 'cmd/dero-miner/qos_contention_test.go',
         'cmd/dero-miner/runledger.go', 'cmd/dero-miner/runledger_test.go', 'cmd/derod/rpc/emission_audit.go',
         'cmd/derod/rpc/emission_audit_test.go', 'cmd/derod/rpc/getwork_dispatch.go',
         'cmd/derod/rpc/getwork_dispatch_test.go', 'cmd/derod/rpc/getwork_fanout_test.go',
         'cmd/derod/rpc/getwork_guard.go', 'cmd/derod/rpc/getwork_presence.go', 'cmd/derod/rpc/getwork_tls.go',
         'cmd/derod/rpc/getwork_tls_test.go', 'cmd/derod/rpc/job_dispatch.go',
         'cmd/derod/rpc/job_dispatch_sim_test.go', 'cmd/derod/rpc/job_dispatch_test.go',
         'cmd/derod/rpc/r22_canonical_key_test.go', 'cmd/derod/rpc/r23_finality_fee_test.go',
         'cmd/derod/rpc/r23_merge_test.go', 'cmd/derod/rpc/r23_precheck_wired_test.go',
         'cmd/derod/rpc/r23_security_test.go', 'cmd/derod/rpc/race_flag_off_test.go',
         'cmd/derod/rpc/race_flag_on_test.go', 'cmd/derod/rpc/rpc_abuse.go',
         'cmd/derod/rpc/rpc_dero_getfeeestimate.go', 'cmd/derod/rpc/rpc_dero_gettxstatus.go',
         'cmd/derod/rpc/rpc_dero_sendrawtransaction.go', 'cmd/derod/rpc/websocket_getwork_server.go',
         'cmd/derod/rpc/websocket_server.go', 'cmd/derod/rpc/ws_foreign_rate.go', 'cmd/derod/rpc/ws_hardening.go',
         'cmd/derod/rpc/ws_tx_events.go', 'cmd/simulator/rpcload_test.go', 'config/version.go',
         'dvm/r23_external_transfer_test.go', 'dvm/r23_hash_gas_bench_test.go', 'glue/emission/emission.go',
         'glue/emission/emission_test.go', 'glue/txcanon/r23_entry_census_test.go', 'glue/txcanon/r23_fuzz_test.go',
         'glue/txcanon/r23_observe_test.go', 'glue/txcanon/r23_race_off_test.go', 'glue/txcanon/r23_race_on_test.go',
         'glue/txcanon/txcanon.go', 'glue/txprecheck/txprecheck.go', 'glue/txprecheck/txprecheck_test.go',
         'p2p/chain_sync.go', 'p2p/controller.go', 'p2p/counter_registry.go', 'p2p/diversity.go',
         'p2p/object_errors.go', 'p2p/r23_block_tx_observe_test.go', 'p2p/r23_cert_serial_test.go',
         'p2p/r23_precheck_test.go', 'p2p/rpc_notifications.go', 'p2p/stuck_peer.go', 'p2p/stuck_peer_test.go',
         'p2p/tx_flow.go', 'tools/emission-audit/cpu_unix.go', 'tools/emission-audit/cpu_windows.go',
         'tools/emission-audit/main.go', 'walletapi/daemon_client_lock.go', 'walletapi/daemon_communication.go',
         'walletapi/daemon_connectivity.go', 'walletapi/daemon_connectivity_loop.go',
         'walletapi/daemon_connectivity_wasm.go', 'walletapi/mnemonics/r23_fuzz_test.go',
         'walletapi/payment_proof_verify.go', 'walletapi/r23_integrated_port_test.go',
         'walletapi/r23_payment_proof_test.go', 'walletapi/r23_proof_fuzz_test.go',
         'walletapi/r23_reconnect_test.go', 'walletapi/r23_seed_test.go', 'walletapi/wallet.go',
         'walletapi/wallet_transfer.go',
         # Round 23b soundness (archive audit, HF3 forensic report, audited-emission series, replay tests)
         'cmd/derod/rpc/r23b_emission_series_test.go', 'glue/emission/archive.go', 'glue/emission/hf3.go',
         'glue/emission/r23b_archive_test.go', 'glue/emission/series.go', 'tools/emission-audit/modes.go',
         'walletapi/r23b_soundness_test.go',
         # Round 23b merge (every other Go file the combined patch adds or changes)
         'cmd/dero-miner/cpushare.go', 'cmd/dero-miner/cpushare_test.go', 'cmd/dero-miner/phase_duty.go',
         'cmd/dero-miner/phase_duty_test.go', 'cmd/derod/rpc/getwork_absence.go',
         'cmd/derod/rpc/getwork_absence_test.go', 'cmd/derod/rpc/monetary_integrity.go',
         'cmd/derod/rpc/r23b_cert_serial_test.go', 'cmd/derod/rpc/r23b_emission_reorg_flows_test.go',
         'cmd/derod/rpc/r23b_rpcws_test.go', 'cmd/derod/rpc/r23b_security_test.go',
         'cmd/derod/rpc/reorg_events.go', 'cmd/derod/rpc/tx_status_final_cache.go',
         'glue/txcanon/r23b_registration_test.go', 'glue/txprecheck/window.go',
         'glue/txprecheck/window_test.go', 'p2p/hf3_parity.go', 'p2p/r23b_hf3_parity_test.go',
         'p2p/r23b_sync_height_gate_test.go', 'p2p/r23b_window_test.go', 'p2p/sync_height_gate.go',
         'tools/launchd/main.go', 'tools/launchd/main_test.go', 'walletapi/r23b_window_consensus_test.go']
BINARIES = {'derod': './cmd/derod', 'dero-miner': './cmd/dero-miner', 'dero-wallet-cli': './cmd/dero-wallet-cli'}
NEW_TESTS = {'./p2p/': 'TestClassifyCallError|TestIsTxOnly|TestTxFetchFailureBudget|TestEmptyReply|TestCallFailureLogLevels'
                       '|TestVerifyHandshakeNeverPanics|TestAvgOffsetAllZeroDoesNotPanic|TestWriteJSONAtomic'
                       '|TestStampConnectedRefreshesOnlyConnectedPeers|TestConcurrentUpdateIsRaceFree|TestExitRemovesOnlyItself'
                       '|TestReadDataFrameGrowsWithData|TestPenaltyDecayEscalationAndExemption|TestHeavyCaps|TestCallTimesOut'
                       '|TestV2BanEscalates|TestUnknownTipSkipsVerification|TestV2OffencesSurviveRestart|TestV2OffencesForgetAfterAWeek'
                       '|TestV2OffencesBadFile|TestPeerListCounts|TestIsPublic|TestDialAddress|TestFirstRelayRankingAndHalving'
                       '|TestGetPeerListKeepsDisconnectedWhitelisted|TestRetention|TestFindPeerPrefersFirstRelay'
                       '|TestSummarizeAcks|TestOwnAckTrackerReportsOnceRegardlessOfOrder|TestOwnAckTrackerConcurrent'
                       '|TestWriteRequestIsOneWriteAndByteIdentical|TestWriteResponseIsOneWriteAndByteIdentical'
                       '|TestCoalescedFramesDecodeWithUpstreamReader|TestKCPSegmentsPerMiniblockRequest'
                       '|TestMiniblockAckMetricSeparatesOwnFromRelay|TestMiniblockDeliveryStatsOrdersByFirstDeliveries'
                       # Round 18 merge: net sync, security, forensics, typed atomics, codec, fixes A-D
                       '|TestFetchPipelinedOrderAndBatching|TestFetchPipelinedOverlaps|TestFetchPipelinedStopsOnErrors'
                       '|TestSyncBatchFitsFrame|TestPrewarmPow|TestPrewarmPowRejectsNonConsensusCount'
                       '|TestPrewarmPowBoundedConcurrency|TestSyncSizeTrackerShape|TestFetchPipelinedAdaptsToLargeBlocks'
                       '|TestTunedKCPRoundTrip|TestNetgroup|TestGossipAddressAcceptable|TestGreyTableCaps|TestOutboundDiversity'
                       '|TestOutboundDiversityOwnPendingDialExcluded|TestINVBounds|TestNotifyINVOversizedRejected'
                       '|TestTxVerificationFailureClassification|TestChainSyncPenalizesInvalidTx|TestFailBackoffCapped'
                       '|TestHandshakeFailureBacksOffAndPurgesGreyOnly|TestFirstRelayPersistRoundTrip'
                       '|TestFirstRelayLoadRejectsStaleAndGarbage|TestFailureReason|TestOwnAckTrackerCarriesReasons'
                       '|TestSortByLatencyOrderAndConcurrency|TestPingCountIsSharedSafely|TestConnectionAtomicFieldsAligned'
                       '|TestAppendFrameByteIdentical'
                       # Round 19 merge
                       '|TestFetchSectionsOrdered|TestFetchSectionsOverlap|TestFetchSectionsStopsAtFirstError'
                       '|TestSectionsRebuildTreeExactly|TestSectionCheckRejectsForeignKeys'
                       '|TestBootstrapTopoPrefillMatchesLoop|TestBootstrapTopoPrefillFallsBack'
                       '|TestBootstrapDepthWithinPeerCap|TestBootstrapFallsBackToDepth1AfterFailure'
                       '|TestPipelinedTimeoutCoversQueue|TestFetchSectionsBufferBound'
                       '|TestApplySectionRejectsBeforeWriting|TestBootstrapCallSitesCheckSections'
                       '|TestDeserializeTxPanicBecomesError|TestInboundHandshakeDeadlineEndsReflection'
                       '|TestInboundHonestPeerOutlivesHandshakeDeadline|TestAdmitInboundChecksBanBeforeToken'
                       '|TestPenaltyScope|TestPenaltyBanCoversIPv6Slash64|TestInboundHandshakeUsesDefaultProfile'
                       '|TestAcceptInboundRefusesBannedBeforeToken|TestChunkedBlockUndecodableTxPenalized'
                       '|TestKCPMTUPerFamily|TestIPv6ClampedSessionRoundTrip|TestDSCPMarkingAcceptedBySockets'
                       '|TestAdvertisedPortFollowsNATMapping|TestNATModeParsing'
                       '|TestNonBanListEntryIsNotReportedBanned|TestKCPWireSizeIPv6'
                       '|TestNTPCorrectionResistsForgedAnswers|TestPeerInfosOnlyActiveAndOrdered'
                       '|TestV2OffendersSeenWindow|TestUnlistedSeedHandshakeFailureBacksOff'
                       '|TestListedPeerFailureUsesPeerListNotUnlisted|TestUnlistedBackoffBounded'
                       '|TestHandshakeAcceptedClearsUnlistedBackoff|TestSyncShouldContinue'
                       '|TestTxInflightCollapsesConcurrentAdmissions|TestTxInflightKeyIsBytesNotTxid'
                       '|TestTxInflightPanicIsNotSuccess|TestTxInflightSettledWaitsForAdmission'
                       '|TestLocalTxRebroadcastPolicy|TestRebroadcastTreatsRelayedLikeLocal'
                       '|TestRebroadcastNeedsEligiblePeer|TestRebroadcastJitter|TestTxInflightSettledZeroBudget'
                       # Round 20 merge
                       '|TestCompactBlockTxsKeepsHashOrder|TestTryCompactOnceAndOnlyOnSuccess|TestPersistSyncsDirAfterRename'
                       '|TestSweepStaleTmp|TestAdmitInboundPerNetgroupBucket|TestAdmitInboundNetgroupCap'
                       '|TestInboundGroupCapScales|TestGroupLimitersBounded|TestP2PTLSMinVersion|TestClockOffsetPublishIsAtomic'
                       '|TestRelayDialHonoursBackoff|TestStickyDialTargetsSkipBackingOff|TestPrewarmWorkersEnvClampAndSeconds'
                       '|TestCodecTrafficCounted|TestTrafficWiredOnBothPaths|TestTxAskReplayLiveFailureBursts'
                       '|TestTxAskHoldExpires|TestTxAskBounded|TestTxsToFetchAsksOncePerPeer',
             './blockchain/': 'TestZeroSigner|TestRecoverKeeps',
             './cmd/derod/rpc/': 'TestForeignCostWeights|TestForeignAssignerOnlyForForeign|TestForeignWebsocketRateLimited|TestWatchTxLifecycle|TestWatchTxBounds|TestWatchTxSkippedClientKeepsChange|TestWatchTxChecksEachTxidOnce|TestTxPoolEvents|TestJobFrameByteIdentical|TestFillNonceDiffers|TestTxEventsLoopExits|TestClassifySync|TestResolveFate|TestShouldHoldJobs|TestReachability|TestRecordSubmissionAndOutcome'
                                 '|TestHashrateEstimateClipsToUptime|TestRefreshDue|TestResolveFateSlotsFull'
                                 '|TestSubmittedMsMatchesSeconds'
                                 '|TestPprofAllowed|TestAuditSCBalances|TestJobMessageByteIdentical'
                       # Round 19 merge
                       '|TestRegistrationLookupOncePerTopo|TestNeedsRegistrationCheck|TestJobTargetsRaceFree'
                       '|TestVerifyDoesNotBlockJobDispatch|TestResolveFateFinalLostIsBlockRace'
                       '|TestRecordSubmissionKeepsFinalAndBuilt|TestNATHint|TestRPCMetricsUnknownMethodsBounded'
                       '|TestRPCMetricsKnownMethodLabelled|TestRPCMetricsHTTPBridgeCounted|TestRPCMethodLabel'
                       '|TestMetricsAllowed|TestWriteNodeMetrics|TestMetricsHandlerWithoutChain'
                       '|TestWSHandlerDropsClientThatNeverReads|TestRegistrationCacheMatchesSearch'
                       '|TestRegistrationCacheHitCost|TestRegistrationCacheEarlierBoundary'
                       '|TestRegistrationCacheBounded|TestRegistrationCacheDropsUnregistered|TestClampTopoRange'
                       '|TestMiniblockTimeReconstruction|TestClassifyFingerprint|TestDifficultySummary'
                       '|TestRangeSlotHonoursContext|TestR19MethodsOnSimulatorChain|TestTxPoolEntryRegistration'
                       '|TestPeerInfoGate|TestTxPoolDetailLimitsAndSlot|TestSupplyAuditSingleFlightAndCache'
                       '|TestSupplyAuditCachedPerTopo|TestSupplyAuditFailureNotCached'
                       '|TestSupplyAuditWaiterHonoursContext|TestAuditSCBalancesStopsOnCancel|TestSlowHeaderIsCut'
                       '|TestWebsocketSubscribeAndHeaderTimeout|TestSubscribeOverHTTPIsRejected'
                       '|TestStalledClientDoesNotBlockPushes|TestIPLimiter|TestRemoteBatchLimitSparesLoopback'
                       '|TestHTTPMetricsAndUnknownMethods|TestResponseSizeMatchesMarshal|TestHealthHTTPCode'
                       '|TestHandlerPerIPLimits|TestPushBusyFlags'
                       # Round 20 (rpcwallet)
                       '|TestTxStatusClassification|TestTxStatusLimits'
                       # Round 20 merge (forensics presence log, security guard; FuzzRPCParams runs its seeds)
                       '|TestPresenceEvent|TestGetworkRegisterUnregister|TestRecordShareStampsLastShare'
                       '|TestPresenceLogRateLimited|TestRPCGuardRefusesRebindingHost|TestRPCGuardCrossSiteWebsocket'
                       '|TestRemoteIPForeignOrigin|TestRPCGuardAllowedOrigins|FuzzRPCParams',
             './cmd/derod/': 'TestMemProfileRate|TestCloseOnceIdempotent'
                       # Round 19 merge
                       '|TestApplyContentionProfiling|TestWritePrivateFile|TestExitOnSignalClosesConsole'
                       '|TestExitSignalsIncludeSIGTERM'
                       # Round 20 merge (storageops log rotation flags, security private files)
                       '|TestLogRotationDefaultsMatchUpstream|TestLogRotationFlags|TestLogRotationRejectsUnbounded'
                       '|TestUsageParsesLiveCommandLine|TestCreatePrivateFile',
             './glue/rwc/': 'TestDefaultReadIsUnlimited|TestNewLimitedRejectsOversizedMessage|TestNewLimitedPassesNormalRequest'
                            '|TestMaxMessageSizeFitsLargestSubmitBlock'
                       # Round 19 merge
                       '|TestWriteHandlesShortWrites|TestWriteTimeoutReleasesStuckPeer|TestNoWriteTimeoutByDefault',
             './walletapi/rpcserver/': 'TestUnauthenticatedWalletRPCOriginGuard|TestAuthenticatedWalletRPCUnchanged'
                                       '|TestBindIsLoopback|TestInstallSCBodyLimited'
                                       # Round 19 merge
                                       '|TestPageEntries'
                       # Round 20 (rpcwallet)
                       '|TestWalletServerCutsSlowHeader|TestWalletRPCServerUsesTimeouts',
             # TestRealGPUBitExact (Metal) and TestHarnessAB/TestGPUCapacity (GSPLIT_HARNESS=1) are never run here
             './cmd/dero-miner/gsplit/': 'TestLayout|TestSelfTestBitExact|TestSelfTestRejectsFaultyGPU|TestMiningBitExact'
                                         '|TestStaleBatchesDropped|TestRuntimeFaultsDisable|TestTransientGPUFailuresRetried'
                                         '|TestServerExitRespawns|TestPersistentCommandFailuresRespawn'
                                         '|TestRespawnRetriesFailedStarts|TestRespawnSelfTestMismatchDisables|TestRespawnBackoff'
                       # Round 19 merge
                       '|TestRestagedBatchNotClaimableUntilReady|TestRegimeCounters|TestTransientAuditFaultRespawns|TestAuditFaultStrikes'
                       # Round 20 merge (cpuminer backlog regime signal, gpukernels source invariants)
                       '|TestRegimeBacklogSplit|TestCPUBacklogCurrentBatch|TestSplitServerKernelInvariants',
             './cmd/dero-miner/dsa/': 'TestHashEquivalence|TestAgainstNaive|TestVerifyRejectsWrongArrays|TestFreshScratchTail',
             './cmd/dero-miner/': 'TestInstallFastSortSelfTest|TestVerifiedSortDisablesBrokenSorter'
                                  '|TestSessionCounterSurvivesReconnect|TestNWFromJob|TestSorterForModes'
                                  '|TestInstallPairSelfTest|TestHashPairPanicFallsBack|TestShareLikelyStale'
                                  '|TestBenchDoesNotTouchTheLiveLog|TestShouldLockMiningThread|TestUnlockedThreadsBitExact'
                                  '|TestLedgerHashIsDerodsHash|TestLedgerAttributesOrphansPerSource|TestLedgerIsBounded'
                                  '|TestOutcomeAddress|TestFetchOutcome|TestExpectation'
                                  # Round 18 merge: bench H/cpu-s, gpu split, GPU worker respawn (fake server, no Metal)
                                  '|TestCPURateString|TestProcessCPUTimeAdvances|TestCPUMaxMessageBench'
                                  '|TestParseSplitGeom|TestSplitNextAndStale|TestSplitFoundGuards'
                                  '|TestGPUWorkerRestartsDeadServer|TestGPUWorkerDisablesOnMismatch'
                                  '|TestGPUWorkerDisablesOnMismatchAfterRestart|TestGPUBackoff'
                                  # Round 19: split-mode CPU-side bench (no GPU)
                                  '|TestSplitBenchSortsCorrectly|TestSplitBenchChargesDeclinedSorts|TestSplitBenchNeedsPairedHashing'
                       # Round 19 merge
                       '|TestSplitFieldsRegimeSignal|TestMetricsBindAllowed|TestWriteMinerMetrics'
                       '|TestMetricsServerLoopback|TestCloseOnceTwice|TestExitOnSignalRepeated'
                       '|TestSplitBenchDispatch|TestSetSplitCopiesRegimeCounters'
                       # Round 20 merge: miner log (append + size rotation, 0600), exit signals, getwork read deadline
                       '|TestMinerLogKeepsPreviousRun|TestMinerLogRotatesBySize|TestMinerLogFullFileRotatedAtStart'
                       '|TestMinerExitSignalsIncludeSIGHUP|TestMinerExitSignalsKeepNohup|TestReadJobTimesOutOnSilentDaemon'
                       '|TestMinerLogIsPrivate|TestMinerLogReopensAfterFailedOpen|TestOpenLogBenchKeepsLiveLog'
                       '|TestMetricsServerHostOriginGuard',
             './cmd/dero-miner/dsac/': 'TestBitExactVsGoDSA|TestSynthetic|TestHashEquivalence|TestConcurrent'
                       # Round 19 merge
                       '|TestBitExactFresh2048',
             './cmd/dero-miner/astropair/': 'TestBitExact|TestSHA|TestPanicProducesNoHash|TestStageIsCurrent|TestAsmIsCurrent',
             # Round 19 merge
             './cmd/dero-wallet-cli/': 'Test_Creation_Password|Test_XSWD_Allow_Remote_Flag|TestRedactedArgumentsHideSecrets'
                       '|TestStartupArgumentsLineRedacted|TestWalletLogIsPrivate',
             # Round 19 merge
             './cmd/explorer/explorerlib/': 'TestHardenHeadersAndBodyCap|TestHTTPServerHasTimeouts|TestPageCacheSharesRendersAndExpires',
             # Round 19 merge
             './p2p/nat/': 'TestNATPMPMapRenewUnmap|TestPCPMapRenewUsesSameNonceAndUnmaps'
                       '|TestRepliesForOtherRequestsAreIgnored|TestPCPOnNATPMPOnlyGatewayReportsUnsupported'
                       '|TestNoGatewayFailsFast|TestManagerAutoFallsBackRenewsAndUnmapsOnStop'
                       '|TestManagerRetriesAfterFailure|TestWarningForNonPublicExternal|TestRenewInterval'
                       '|TestParseGatewayOutputs|TestUPnPDiscoverMapUnmap|TestUPnPPermanentOnlyAndConflict'
                       '|TestUPnPRefusesForeignURLs|TestValidMode|TestZZStopDuringSlowEstablishLeaksMapping'
                       '|TestUPnPLocationMustBeResponder'
                       # Round 20 merge: fuzz seeds
                       '|FuzzGatewayReplies|FuzzSSDPReply|FuzzUPnPResponses',
             # Round 19 merge
             './tools/dashboard/': 'TestDashboardSelfContained',
             # Round 19 merge
             './walletapi/': 'TestSyncWakesOnHeight|TestSyncWaitBounds|TestSyncWakeWired|Test_Lookup_Matches_Reference|Test_Lookup_SingleWorker|Test_Save_Wallet_Atomic'
                       '|Test_Save_Wallet_Failure_Keeps_Old_File|Test_Open_Removes_Stale_Temp'
                       '|Test_Stale_Temp_Glob_Metachars|Test_Save_Wallet_Rename_Failure_Keeps_Old_File'
                       '|Test_Backup_Copy_Never_Truncates_Linked_Wallet|Test_Create_Random_Wires_Disk'
                       '|Test_Close_Stops_SyncLoop_And_Scrubs|Test_Sync_Run_State|Test_Decode_Cache_Same_Result'
                       '|Test_TransferMatches|Test_Show_Transfers_Filters'
                       '|TestFetchOrderedOverlapsBoundedAndKeepsFirstError'
                       # Round 20 (rpcwallet)
                       '|TestDiscoverLeavesMatchesSerial|TestDiscoverLeavesBoundsInFlight|TestPrefetchWindowAndTake|TestSplitTxBatch'
                       '|TestPrefetchGenerationGuard|TestSyncParallelFromEnv|TestRingProgressGivesUp|TestRingStallDelay'
                       '|TestRingStallWired|TestDaemonCallTimesOut'
                       # Round 20 merge (RW-01 review)
                       '|TestSplitTxBatchRefusesMissingAndPool',
             # Round 19 merge
             './walletapi/xswd/': 'TestIsLoopbackRemote|TestRemoteConnectionRejected|TestPermissionAliasDeny'
                       '|TestXSWDListenAddrs|TestXSWDServerIsLoopbackOnly'
                       # Round 20 (rpcwallet)
                       '|TestXSWDServerHasHeaderTimeout',
             # Round 20 (rpcwallet)
             './metrics/': 'TestKCPMetricsTypedAndAtomic'
                       # Round 20 merge (storageops)
                       '|TestDiskPathDefaultsToCwdAndFollowsSet|TestWatchFileReportsSizeAndIsBounded|TestProcessMetricsDarwin'
                       '|TestScrapeUsesDiskPathAndFileSizes',
             # Round 20 merge (security)
             './glue/httpguard/': 'TestHostAllowed|TestForeignOrigin|TestGuard|FuzzHostOrigin|TestForeignOriginExcept'}
# Round 21 merge: every test the combined patch adds (the real-Metal and experiment tests that skip unless
# GSPLIT_REAL / GSPLIT_OVERHEAD / GSPLIT_YIELD_EXP is set are left out)
for _pkg, _pat in {
        './cmd/dero-miner/': 'TestCgoYielderCadence|TestMiningLoopsYield|TestCgoYielderHandsOverP|TestFdLimitLeavesRoom'
                             '|TestRaiseFdLimitNeverLowers|TestSplitStaleDropsNormalAfterFinalFlip|TestParseSplitSort'
                             '|TestParseSplitSortProbe|TestSplitCountsGPUSortedHashes|TestGPUStampCheck|TestParseGPUStamps'
                             '|TestRepoGPUStampsMatch|TestIsExecutableImage|TestTrackedBinariesDeclared'
                             '|TestDecodeJobBlobNeverPanics|TestJobVerdict|TestTakeJobDropsMalformed|TestDialGetworkReadLimit'
                             '|FuzzJobVerdict|TestMetricsSplitStaleDropsByReason|TestRunLedgerPaths|TestRunLedgerCleanRun'
                             '|TestRunLedgerRecoversUncleanRun|TestRunLedgerDamagedCheckpoint|TestParseRunLedgerSkipsTornLine'
                             '|TestRunLedgerRotates|TestWriteFileAtomic|TestRunRecordFrom|TestSignalExitWritesRunLedger'
                             '|TestMinerMetricsHandlerProcessSeries|TestRunLedgerSkipsLiveOwnersCheckpoint',
        './cmd/dero-miner/dsac/': 'TestZeroRuns',
        './cmd/dero-miner/gsplit/': 'TestBusyUnionExact|TestBusyUnionMatchesBruteForce|TestBusyUnionBounded|TestReplyLoopDebtOnUnion'
                                    '|TestSelfTestGPUSort|TestSelfTestGPUSortFaultsTurnSortOff|TestMiningGPUSortBitExact'
                                    '|TestGPUSortFailureFallsBackToCPU|TestGPUSortRuntimeMismatchDisablesSort|TestDivertKeepsCPUFed'
                                    '|TestGPUSortConfigGuards|TestGPUSortStaleDropped|TestSortProbeKeepRule'
                                    '|TestSortProbePausesNetLossKeepsGain|TestSortProbeStopsWhenSortOff|TestGPUSortedHashesCounted'
                                    '|TestShmNameUnpredictable|TestNewShmIsPrivateAndUnlinked',
        './cmd/dero-wallet-cli/': 'TestVerifiedMessagePathNeverInput',
        './cmd/derod/': 'TestPrunePreflight',
        './cmd/derod/rpc/': 'TestForeignNodeBucketOnlyForLoopbackForeign|TestWatchTxForeignSubCap|TestWatchTxUnknownExpires'
                            '|TestTxStatusesDedupesRepeats|TestForeignRangeSlotsLeaveRoomForLocal|FuzzTxStatuses',
        './glue/httpguard/': 'TestParseOriginsNeverListsNull|TestGuardRawRequests',
        './metrics/': 'TestProcessCurrentRSSDarwin|TestParseTaskinfo|TestWriteProcessMetricsForMiner',
        './p2p/': 'TestP2PCountersRegisteredEagerly|TestFrameBudgetBoundsLargeFramesInFlight'
                  '|TestFrameBudgetOutboundPoolNotStarvedByInbound|TestGreyPurgeQuarantinesAgainstRegossip'
                  '|TestGreyQuarantineSparesWhitelisted|TestGreyQuarantineExpiresAndEscalates'
                  '|TestGreyQuarantineClearedOnSuccess|TestGreyQuarantineBoundedFailOpen'
                  '|TestGreyQuarantineDialRateModel|TestHandshakeFailureKind'
                  '|TestGreyQuarantineNoBypassViaKnownEntry|TestLazyP2PCountersVisibleAtZero|TestLaggingPeerCount'
                  '|TestTxAnnounceSkipsPeersThatAnnounced|TestTxsToFetchRecordsAnnouncements'
                  '|TestTxKnownBoundedFailOpen|TestTxKnownFloodSavesAnnouncements|TestTxKnownSingleUpgradedNode'
                  '|TestTxWantTakesEachAskedTxOnce|TestUnrequestedTxsDroppedAndScored|TestTxLoopStopsAfterExit'
                  '|TestNotifyINVPassesTxWant',
}.items():
    NEW_TESTS[_pkg] = f'{NEW_TESTS[_pkg]}|{_pat}' if _pkg in NEW_TESTS else _pat
# Round 22 merge: every test the combined patch adds. Left out: env-gated tests (GSPLIT_REAL, GSPLIT_CPUMAX,
# GSPLIT_HARNESS, RPCLOAD, DERO_NAT_PROBE_LIVE), the shm fd child helper, and walletapi's
# Test_R22_MultiPayload_Distinct_Blinders, which is built only without -race (//go:build !race: the walletapi
# simulator harness races at 5385d1d already; run it with a plain go test). Fuzz targets run their seed corpora.
for _pkg, _pat in {
        './cmd/dero-miner/': 'TestDutyTunerClimbsToHundredNeverAbove|TestDutyTunerFindsPeak|TestDutyTunerFlatStays'
                             '|TestDutyTunerFloor|TestDutyTunerABBACancelsDrift|TestDutyTunerVoidRestores'
                             '|TestParseDutyFlag|TestCPUThrottleUsesLiveDuty|TestSplitStaleQuietDoesNotCount'
                             '|TestSplitFieldsPerKernelSpans|TestSubmitBucketCapsFlood|TestSubmitLimiterConfig'
                             '|TestSubmitShareChecksBucketFirst|TestJobErrorLogGated|TestTakeJobUsesErrorGate'
                             '|TestParseGPUStampsRequiresHex|TestMetricsR22Splitpipe|TestMetricsSplitPerKernelSpans'
                             '|TestPowTargetMatchesCheckPowHashBig|TestPowTargetNegative|TestSplitNextPrecomputesTarget'
                             '|FuzzMinerParsers',
        './cmd/dero-miner/dsac/': 'TestProfTimerArm64',
        './cmd/dero-miner/gsplit/': 'TestReplyLoopPerKernelSpans|TestSimGPUQueue|TestDutyChargeCost|TestDutyCreditsWallTime'
                                    '|TestDutyBurstBounded|TestDutyBucketHoldsCap|TestFeederPaysDuty|TestSplitServerLUTOps'
                                    '|TestSplitServerWordMask|TestSplitServerPRGALoadAhead|TestNewShmFdCloseOnExec'
                                    '|TestStaleBatchSkipsGPUSHA|TestSetGPUMaxRuntime|TestThrottleAndCollectCounted'
                                    '|TestFinishStaleRecheckIsQuiet',
        './cmd/derod/': 'TestPrunePreflightDanglingSymlink',
        './cmd/derod/rpc/': 'TestCanonicalAccountKey|TestR22RPCWired|TestR22TxResultCacheOnSimulatorChain'
                            '|TestR22SameHashSet|TestR22TxCacheOffByDefault|TestR22TxCacheBounded|FuzzWatchTxParams',
        './cryptography/bn256/': 'TestR22IdentityHasNoCanonicalEncoding|TestR22NonCanonicalXDecodesToIdentity'
                                 '|TestR22FlagByteMalleability|TestR22CanonicalRoundTrip|FuzzDecodeCompressed',
        './cryptography/crypto/': 'TestR22HashUnmarshalTextAcceptsTrailingGarbage|FuzzStatementProofDecode',
        './glue/txcanon/': 'TestCanonicalTxFastPath|TestFlagAliasAcceptedNonCanonical|TestNonCanonicalXRejected'
                           '|TestUnserializableRefused|TestTruncatedTailDecodesThenSerializePanics',
        './p2p/': 'TestRelayAdmitRefusesUnserializable|TestRelayAdmitWired|TestTxKnownFullSetSweepsOnce'
                  '|TestInvBudget|TestClipInvTxs|TestShortTxReplyCountsAsFailure|TestTxWantCountsDelivered'
                  '|TestNotifyINVWiresR22Guards|TestP2PTLSCipherCurveFloor'
                  '|TestStuckSelectEvictsOnlyAfterWindow|TestStuckSelectSparesCatchingUpPeer'
                  '|TestStuckSelectNeverEvictsIncomingOrExempt|TestStuckSelectNeedsCorroboration'
                  '|TestStuckTrackForgetsGoneConnections|TestStuckHoldDoublesAndCaps'
                  '|TestStuckHoldFailsOpenWhenFull|TestStuckSweepEvictsHoldsAndDefers'
                  '|TestDialRefusesStuckHeldAddress',
        './p2p/nat/': 'TestExternalClass|TestProbeVerdict|TestProbeFakeGatewayReadOnly|TestProbeNATPMPOnlyGateway'
                      '|TestProbeUPnPReadOnly|TestManagerProbeModeNeverMaps|TestProbeErrorIsKind',
        './proof/': 'TestR22PaymentProofAmountNotBound',
        './rpc/': 'FuzzAddressDecode',
        './walletapi/': 'TestEncryptWithKeyLeavesPlaintext|TestPickRingOrderRing2NoReuse'
                        '|TestPickRingOrderParityAndIndependence|TestRingOrderKeyLayout'
                        '|TestCheckSignatureRejectsMalleableScalar|TestCheckSignatureRejectsIdentitySigner'
                        '|TestCheckSignatureRejectsAliasedAddress|TestR22RingOrderSpace',
}.items():
    NEW_TESTS[_pkg] = f'{NEW_TESTS[_pkg]}|{_pat}' if _pkg in NEW_TESTS else _pat

NORACE_NEW_TESTS = {'./cmd/derod/rpc/': ['TestR23GetworkFanoutOrderedOverSockets'],  # skip under -race (nbio)
                    './walletapi/': ['Test_R23_HF3_Exemption_Is_Height_Bound',  # !race file (simulator races upstream)
                                     'Test_R23b_Same_TXID_Second_Body_Never_Executes',
                                     'Test_R23b_Archive_Audit_Simulator_Chain',
                                     'Test_R23b_Admission_Window_Is_Consensus_Subset']}  # r23b merge (security, port 26232)
# R23 soundness review: the 75 HF3 txids are historical and the TXID commits to height but not the proof
NEW_TESTS['./blockchain/'] = NEW_TESTS.get('./blockchain/', '') + ('|' if './blockchain/' in NEW_TESTS else '') + \
    'TestR23HF3TableIsHistorical|TestR23TxidCommitsToHeightNotProof'
# Round 23 merge: every test the combined patch adds. Left out: the opt-in benches TestQoSContentionAB,
# TestDutyContentionAB (DERO_QOS_BENCH / DERO_DUTY_BENCH) and TestR23GetworkFanoutBench (GETWORK_FANOUT).
# TestR23GetworkFanoutOrderedOverSockets skips itself under -race (vendor nbio poller race); run it without -race.
for _pkg, _pat in {
        './cmd/dero-miner/': 'TestContentionFields|TestCPUThrottleSleepCounted|TestDutyTunerNoiseRejectsRandomSteps'
                             '|TestAbbaNoise|TestMetricsR23DutyTuner|TestJobIDMs|TestTakeJobRecordsTemplateAge'
                             '|TestWaitFirstJob|TestMineblockWaitsForJobNotFixedSleep',
        './cmd/derod/rpc/': 'TestEmissionAuditStepBackfillAndFollow|TestEmissionAuditReorgReaudits'
                            '|TestEmissionAuditSkipsAheadWhenFarBehind|TestEmissionAuditAlertAndError'
                            '|TestEmissionAuditNotableFlow|TestEmissionAuditEnabledSwitch'
                            '|TestEmissionAuditUnexplainedAndErrorDoNotStick|TestEmissionAuditErrorRetryCapped'
                            '|TestR23DeliverJobOrdering|TestR23DeliverJobConcurrentNewestLast|TestR23NextJobSeq'
                            '|TestR23GetworkFanoutOrderedOverSockets|TestGetworkTLSFloor|TestGetworkServerUsesTLSFloor'
                            '|TestDispatchPolicySimulation|TestDispatchDecideOneSendPerChange|TestDispatchDecideRefresh'
                            '|TestDispatchDecideKeepalive|TestDispatchWaitMs|TestJobKeepaliveEnv'
                            '|TestRunJobDispatcherKickLatency|TestRunJobDispatcherRefreshOnTime'
                            '|TestRunJobDispatcherInactive|TestGetworkSessionCount|TestJobTargetFor'
                            '|TestJobDispatchWiring|TestDispatchDecideRetry|TestRunJobDispatcherRetriesStaleJob'
                            '|TestTemplateIsCurrent|TestStaleCountedBroadcastOnly|TestR23FinalHeightScan'
                            '|TestR23FinalityApply|TestR23TxFinalityOnSimulatorChain|TestR23FeeSummary'
                            '|TestR23GetworkBannedKeyOtherSessions|TestR23GetworkBanWired'
                            '|TestSendRawTransactionPrecheckWired|TestEmissionAuditWired|TestR23AbuseKeyIPv6Slash64'
                            '|TestR23RateBucketWeighted|TestR23UnknownMethodsBanEscalates'
                            '|TestR23HonestErrorRatesNeverBan|TestR23ObserveCodes|TestR23RefusalsHammeringEndsInBan'
                            '|TestR23TableBounded|TestR23ConfigureAbuse|TestR23RemoteHTTPProbeBanLoopbackExempt'
                            '|TestR23RemoteHTTPParamFuzzScoredFromReply|TestR23RemoteHTTPRateLimited'
                            '|TestR23WSAssignerAndBannedUpgrade|TestR23GetworkPerIPCap|TestR23GetworkBadShareBan'
                            '|TestR23LocalShareNotStarvedByRemoteFlood|TestR23RefusalCodeSurvivesParams'
                            '|FuzzR23RequestMethods|TestR23FullTableAdmitBounded|TestR23OverflowKeyNeverBanned',
        './dvm/': 'TestR23ExternalTransferToUnregisteredBurns',
        './glue/emission/': 'TestFormulaMatchesConsensus|TestSplitReward|TestEmissionAuditHonestCoinbase'
                            '|TestEmissionAuditHonestTransfersAndRegistration|TestEmissionAuditPlaintextFlowProxy'
                            '|TestEmissionAuditTestnetRegistrationBonus|TestEmissionAuditDetectsExtraCoinbase'
                            '|TestEmissionAuditDetectsMissingCoinbase|TestEmissionAuditDetectsRightTamper'
                            '|TestEmissionAuditDetectsUnregisteredAccount|TestEmissionAuditDetectsDeletedAccount'
                            '|TestEmissionAuditSCPayout|TestEmissionAuditSCRevertAndBurn'
                            '|TestEmissionAuditDetectsSCCreation|TestEmissionAuditDetectsSCChangeWithoutCall'
                            '|TestEmissionAuditSCOverpayIsUnexplained|TestEmissionAuditSkipsProtocolHeights'
                            '|TestMatchPayoutSubsets|TestEmissionAuditPreHF3ReRegistrationIsNote',
        './glue/txcanon/': 'TestR23EveryMempoolEntryRunsTxcanon|FuzzCheck|TestR23SingleByteSweep'
                           '|TestR23ObserveCountsBlockTxOnly',
        './glue/txprecheck/': 'TestPrecheckPassesWellFormed|TestPrecheckRefusesWhatConsensusRefuses'
                              '|TestPrecheckAdmitGatesTheAdd',
        './p2p/': 'TestR23BlockTxObservedNeverRefused|TestR23BlockTxObserveWired'
                  '|TestR23CertSerialCarriesNoPeerIDOrTime|TestRelayAdmitPrechecksStructure'
                  '|TestRelayPrecheckRefusalIsScored|TestStuckSelectFastReevictsKnownHeight'
                  '|TestStuckSweepRecordsHeightForFastCycle',
        './walletapi/mnemonics/': 'FuzzWordsToKey',
        './walletapi/': 'TestR23IntegratedPortKeptWithPayload|TestR23IntegratedPortConflictRefused'
                        '|TestR23IntegratedEmptyPayloadUnchanged|TestR23IntegratedPortOverflowRefused'
                        '|TestR23ReceiverProofAcceptsHonest|TestR23ReceiverProofRefusesRestated'
                        '|TestR23ReceiverProofBindsToStatementD|TestR23ReceiverProofFixture'
                        '|TestR23ReceiverProofWithBurn|FuzzReceivedProofParse'
                        '|TestR23ConnectFailedHandshakeDoesNotLeak|TestR23CallWithoutConnectionIsAnError'
                        '|TestR23ReconnectRacesWithCalls|TestR23DropDoesNotHangOnSilentDaemon'
                        '|TestR23DropClearsConnected|TestR23ZeroSeedRefused',
}.items():
    NEW_TESTS[_pkg] = f'{NEW_TESTS[_pkg]}|{_pat}' if _pkg in NEW_TESTS else _pat
# Round 23b soundness
for _pkg, _pat in {
        './cmd/derod/rpc/': 'TestEmissionSeriesCheckpointsPersist|TestEmissionSeriesNotableAndBurns'
                            '|TestEmissionSeriesSwitch|TestEmissionIssuedFollowsReorg',
        './glue/emission/': 'TestEmissionAuditCountsPayloadBurns|TestCumulativeContiguityAndConsistency'
                            '|TestArchiveRangePrunedIsUnavailable|TestTopoMapSkipsUnwrittenSlots'
                            '|TestSeriesTornTailAndChecksum|TestHF3ForensicOnRealBody|TestHF3ClassesMatchTable',
}.items():
    NEW_TESTS[_pkg] = f'{NEW_TESTS[_pkg]}|{_pat}' if _pkg in NEW_TESTS else _pat

# Round 23b merge: every other test the combined patch adds (forensics, payouts, hashrate, syncp2p, rpcws, crypto,
# security; the soundness ones are above). TestPlutilLint needs /usr/bin/plutil (darwin) and skips elsewhere.
for _pkg, _pat in {
        './cmd/dero-miner/': 'TestR23bThrottleSleepQuietIsR22|TestR23bThrottleSleepContended|TestR23bCPUShareSample'
                             '|TestR23bCPUShareSamplerDriven|TestR23bCPUThrottleUsesShare|TestR23bStartCPUShareSampler'
                             '|TestR23bMetricsCPUShare|TestParsePhaseDuty|TestBalancedFinalDutyKeepsMean|TestJobIsFinal'
                             '|TestPhaseClockBooksTimeAndHashes|TestRegularFractionPrior|TestPhaseCaps'
                             '|TestBalancedPhaseMeansHoldCaps|TestPhaseNoteMovesCaps|TestPhaseWakeSleepWakesOnlyOnLaterChange'
                             '|TestPhaseNoteStampsWakeOnlyFinalToRegular|TestUsageParsesNewFlags'
                             '|TestConsoleExitIgnoredWhenSupervised|TestConsoleLoopWiresExit|TestTakeJobBooksPhase'
                             '|TestCpuThrottleWakesOnPhaseChange|TestCpuThrottleIgnoresJobStream|TestThrottleAchievesPhaseDuty',
        './cmd/derod/rpc/': 'TestMinerAbsentSeconds|TestAbsenceClockFollowsRegisterUnregister|TestMinerAbsentWarnAfter'
                            '|TestAbsenceWarnDue|TestRunAbsenceWatch|TestR23bGetworkCertSerialIsRandom'
                            '|TestR23bEmissionReorgReplacesFlows|TestR23bEmissionErroredRetryCountsFlowsOnce'
                            '|TestR23bOpenSeriesCountsWholeFile|TestR23bReorgTracker|TestR23bReorgLocalRewindIsNotViolation'
                            '|TestR23bReorgPush|TestR23bHF3Facts|TestR23bReorgObserverOnSimulatorChain|TestR23bFinalTxCache'
                            '|TestR23bFinalTxCacheOnSimulatorChain|TestR23bRemoteHTTPNoServerInfo'
                            '|TestR23bRemoteHTTPNoServerInfoGuardOff|TestR23bWSRemoteNoServerInfo|TestR23bGlobalAnomalySurge'
                            '|TestR23bGlobalSurgeCountsBadRequests|TestR23bSendRawTransactionHeaderPeek'
                            '|TestR23bWSHandlerUsesSocketOptions',
        './glue/txcanon/': 'TestR23bRegistrationCanonical',
        './glue/txprecheck/': 'TestR23bPrecheckAdmitCountsEveryAdmission|TestR23bPeekHeightMatchesDeserialize'
                              '|TestR23bPeekHeaderRefusalIsDeserializeRefusal|TestR23bWindowBounds'
                              '|TestR23bHF3TableRefusedByTXID|FuzzR23bPeekHeight',
        './p2p/': 'TestR23bHF3ParityFormula|TestR23bHF3AddPreparesBeforeExecute|TestR23bHF3AddIsAtomic'
                  '|TestR23bAddCompleteBlockCensus|TestSyncHeightGateMatchesPerBlockRuleWithFewerReads'
                  '|TestSyncHeightGateReloadsBeforeSkipping|TestSyncPathUsesHeightGate'
                  '|TestR23bRelayWindowDropsBeforeMempool|TestR23bRelayHF3TableRefused'
                  '|TestR23bRelayWindowPassesInWindow',
        './tools/launchd/': 'TestProgramArgsAlwaysSupervisedOnce|TestCheckRefusesPlaceholderWallet|TestRunTemplateAndStrict'
                            '|TestRenderEscapes|TestPlutilLint',
}.items():
    NEW_TESTS[_pkg] = f'{NEW_TESTS[_pkg]}|{_pat}' if _pkg in NEW_TESTS else _pat

# Round 24 merge (AI24-6, self-detected by harness/intel/area_intel.py): every TestR24* the combined patch adds, so the
# S3 test stage runs them per package (harness/kat/test_new_tests_registered_r24.py fails on an unregistered one).
# Left out (run 3 S3 FAIL: they SKIP without their env, and S3 needs every registered name to PASS): the opt-in
# simulator harnesses TestR24EvictionSparesTemplateTxs (R24_EVICT=1) and TestR24TxpoolLoad (R24_TXPOOL_LOAD=1); the KAT
# recognises an env-gated t.Skip and requires such a test to stay out.
for _pkg, _pat in {
        './cmd/derod/rpc/': 'TestR24AggregateShortfallNotScored|TestR24ContentTypeRefusalScoredRemoteOnly'
                            '|TestR24ContentTypeShape|TestR24DecoyBCacheTTLAndBound|TestR24DecoyBFromPilot'
                            '|TestR24DecoyCacheConcurrent|TestR24DecoyCoin|TestR24DecoySamplerBudgetBound'
                            '|TestR24DecoySamplerIsDepthCorrected|TestR24DropMinedKeepsOrder|TestR24FeeEstimateCoversPoolGate'
                            '|TestR24FeeEstimateSkipsMined|TestR24FlipL9Sample|TestR24FlipSlowThreshold'
                            '|TestR24ForeignSocketPaysItems|TestR24GetRandomAddressUsesSampler'
                            '|TestR24GetTxStatusWiresPoolDetail|TestR24HandlersReleaseItems|TestR24HonestPollingKeepsTrust'
                            '|TestR24ItemWeightedAdmission|TestR24MonetaryIntegrityCarriesEveryEmissionTotal'
                            '|TestR24MonetaryIntegrityLiveShape|TestR24NoteFlipBooksL9|TestR24NoteFlipCountsSlow'
                            '|TestR24NoteTemplateBoundAndDedupe|TestR24PoolStatusExpiryHeights|TestR24PoolStatusTemplateOrder'
                            '|TestR24PrewarmedFleetBannedLikeFresh|TestR24ProbesDoNotEarnTrust|TestR24RecentMinedScanWindow'
                            '|TestR24RemoteBodyItemsTotal|TestR24RemoteHTTPBatchOfFullCallsRefused'
                            '|TestR24RemoteHTTPItemsCharged|TestR24SendJobPassesTrigger'
                            '|TestR24SendRawTransactionRefusesKnownInvalidBeforeDecode|TestR24SimLiveFlipDefinitions'
                            '|TestR24SocketItemsChargedAndBounded|TestR24StrikeEndsTrust|TestR24TemplatesNotedWhereHandedOut'
                            '|TestR24TrustRevokedByProbing|TestR24TrustedProbeInBannedAggregateRefused'
                            '|TestR24TrustedProbesScoreAggregate|TestR24VerifyAggShortRetryFloodEndsBanned'
                            '|TestR24VerifyIgnoredFieldCannotHideItems|TestR24VerifyL9DeadSeenFromTrigger'
                            '|TestR24VerifyL9NoOrFutureTrigger|TestR24VerifyNeighbourCannotRevokeHonestTrust'
                            '|TestR24VerifyNonObjectElementKeepsAdmission',
        './glue/txcanon/': 'TestR24AdmitRunsTxpolicy',
        './glue/txpolicy/': 'TestR24ConcurrentIdenticalBytesVerifiedOnce|TestR24DerodAttachesPolicy'
                            '|TestR24DerodSetsMinedSource|TestR24DerodSetsProtectedSource|TestR24DetachedIsPassThrough'
                            '|TestR24FeeToEnterMatchesGate|TestR24KnownInvalidBoundAndTTL'
                            '|TestR24KnownInvalidBytesNotReverified|TestR24KnownInvalidPreDecode'
                            '|TestR24LeaderPanicReleasesFollowers|TestR24LessRateExactAndNoOverflow'
                            '|TestR24MinedTxsDoNotOccupyCap|TestR24NegCacheCannotPoisonValidBytes'
                            '|TestR24OnlyProofFailuresRemembered|TestR24PanickingAdmissionLeavesPolicyUsable'
                            '|TestR24PoolBelowCapAdmitsAnyFee|TestR24PoolFullEvictsLowestPayingForBetterTx'
                            '|TestR24PoolFullNotRemembered|TestR24PoolFullRefusesLowFeeBeforeVerification'
                            '|TestR24ProtectedTxsNeverEvicted|TestR24RegistrationBypassesPolicy'
                            '|TestR24SummaryCachedBetweenAdmissions',
        './p2p/': 'TestR24ChainLocatorSkipsUnreadableRecord|TestR24CompactBlockTxsRawMatchPool'
                  '|TestR24CompactPathObservesAfterAccept|TestR24FetchPeekHidesBadResponse'
                  '|TestR24FetchPeekNeverWaitsNorReorders|TestR24HandshakeAcceptedProvesAddress'
                  '|TestR24NextOverlapUsesPeekOnlyForLastBlock|TestR24OverlapCovered|TestR24OverlapPrewarmedFlag'
                  '|TestR24OverlapRecordsRan|TestR24PenaltyEvictPrefersUnbanned|TestR24PenaltyHardBoundAllBanned'
                  '|TestR24PrewarmDiffEnvOff|TestR24PrewarmDiffForgedInputs|TestR24PrewarmDiffOncePerBlock'
                  '|TestR24PrewarmIntoOwnCounter|TestR24PrewarmSecondsGoToTheirCounter|TestR24ProvenLaneBounded'
                  '|TestR24ProvenLaneSurvivesNetgroupDrain|TestR24ProvenLaneSurvivesSpoofDrain'
                  '|TestR24ProvenSetBounded|TestR24SyncLoopSkipsCoveredBlock|TestR24SyncLoopWiring'
                  '|TestR24TryCompactPassesRaws|TestR24VerifyLocatorIdenticalToUpstream'
                  '|TestR24VerifyPanickedOverlapNotCovered|TestR24VerifyPeekWithShapeChanges',
        './tools/getworkprobe/': 'TestR24ProbeParse|TestR24ProbeSummary|TestR24VerifyProbeFlipIsNotAnUpperBound',
        './tools/launchd-derod/': 'TestR24DerodArgsAndPaths|TestR24DerodCheckRefuses|TestR24DerodPlutilLint'
                                  '|TestR24DerodRenderEscapes|TestR24DerodRunTemplateAndStrict|TestR24KnownFlagsMatchDerodUsage',
        './tools/nodehealth/': 'TestR24HealthContentTypeAndEmpty|TestR24HealthDownAndErrors|TestR24HealthFallbackTipAge'
                               '|TestR24HealthSynced|TestR24HealthUnhealthy',
        './walletapi/': 'TestR24ProofArgumentsMatchesNewAddress|TestR24V2ReceiverProofCrossScidAndRestart'
                        '|TestR24V2ReceiverProofGuardVsReaders|TestR24V2ReceiverProofPreexistingAndStale'
                        '|TestR24V2ReceiverProofRepeatIsWithheld|TestR24V2ReceiverProofSameTxidIsNotARepeat',
}.items():
    NEW_TESTS[_pkg] = f'{NEW_TESTS[_pkg]}|{_pat}' if _pkg in NEW_TESTS else _pat

TS = datetime.datetime.now().strftime('%Y%m%dT%H%M%S')
# run logs live outside every corpus root: the log is appended to while S7 hashes the corpus, so a log under
# harness/runtime/ made G3 (corpus current) fail on the pipeline's own writes (2026-10-21)
EVENTS = HARNESS / f'loop/runs/pipeline_{TS}.jsonl'
SUMMARY = {'run': TS, 'stages': {}, 'ok': False, 'mode': 'full'}


def now():
    return datetime.datetime.now().astimezone().isoformat(timespec='seconds')


def event(stage, status, **kv):
    rec = {'t': now(), 'stage': stage, 'status': status, **kv}
    with EVENTS.open('a') as f:
        f.write(json.dumps(rec) + '\n')
    print(f"[{rec['t']}] {stage:8s} {status:5s} " + ' '.join(f'{k}={str(v)[:160]}' for k, v in kv.items()), flush=True)
    if status in ('PASS', 'FAIL', 'SKIP', 'REFUSED', 'PAUSED'):     # r24: PAUSED (miner track, §0.3)
        SUMMARY['stages'][stage] = {'status': status, **{k: v for k, v in kv.items()}}


def sh(cmd, timeout=1800, cwd=ROOT, env=None):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, shell=isinstance(cmd, str),
                       env={**os.environ, **(env or {})})
    return r.returncode, r.stdout, r.stderr


LAST_RPC_ERROR = {}


def rpc(url, method, params=None):
    body = json.dumps({'jsonrpc': '2.0', 'id': '1', 'method': method, **({'params': params} if params else {})}).encode()
    req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=8) as r:
        d = json.loads(r.read())
    if d.get('result') is None:
        LAST_RPC_ERROR[url] = d.get('error') or d          # keep what the node said instead of a bare None
    return d.get('result')


def finish(code):
    SUMMARY['ok'] = code == 0
    SUMMARY['finished'] = now()
    SUMMARY['events'] = str(EVENTS.relative_to(ROOT))
    tmp = HARNESS / 'loop/.PIPELINE_LAST.json.tmp'          # R22: atomic (the gates and the next run read it)
    tmp.write_text(json.dumps(SUMMARY, indent=1))
    os.replace(tmp, HARNESS / 'loop/PIPELINE_LAST.json')
    # R23b: a --project-only / --soundness-only / --gpu-bench-only run replaced PIPELINE_LAST with a record holding no
    # test, A/B or shadow stage, so G20's A/B check read nothing (it passed vacuously after c7ded01's 062228 run). A run
    # that reached the A/B stages is ALSO kept as PIPELINE_FULL_LAST, which G20 reads when the newest record is partial.
    if full_record(SUMMARY):
        tmp.write_text(json.dumps(SUMMARY, indent=1))
        os.replace(tmp, HARNESS / 'loop/PIPELINE_FULL_LAST.json')
    event('done', 'END', ok=SUMMARY['ok'], summary='harness/loop/PIPELINE_LAST.json')
    sys.exit(code)


def full_record(summary):
    """R23b: a record G20 can judge A/Bs from: a full-mode run that reached S4b (minerbench) with a status. Pure."""
    return summary.get('mode', 'full') == 'full' and 'minerbench' in (summary.get('stages') or {})


# ───────────────────────────── stages ─────────────────────────────
def s1_guard():
    event('guard', 'START')
    # R22: a go_mutate run killed mid-mutation leaves its journal behind and the tree MUTATED (a weakened guard)
    j = HARNESS / 'intel/.go_mutate.journal'
    if j.exists():
        event('guard', 'FAIL', why=f'{j.relative_to(ROOT)} exists: a killed go_mutate run left a source file mutated; '
                                   'run harness/intel/go_mutate.py --only none (it restores) or restore by hand')
        finish(5)
    rc, out, err = sh([sys.executable, 'harness/consensus_guard.py', '--json', 'harness/loop/CONSENSUS_GUARD.json'])
    files = [l.strip() for l in out.splitlines() if l.startswith('  ') and 'VIOLATION' not in l]
    if rc != 0:
        event('guard', 'FAIL', output=out[-600:])
        finish(5)
    event('guard', 'PASS', files=files)


def s2_format():
    event('format', 'START')
    rc, out, err = sh(['gofmt', '-l', *OWNED])
    if rc != 0 or err.strip():
        # R22: gofmt's exit code and stderr were ignored, so an OWNED file that is missing or does not parse printed
        # nothing on stdout and S2 passed 'gofmt clean'
        event('format', 'FAIL', gofmt_rc=rc, gofmt_err=err[-600:])
        finish(6)
    unformatted = [l for l in out.split() if l != 'blockchain/transaction_execute.go']
    rc, vet_new, vet_err = sh(['go', 'vet', './p2p/', './blockchain/', './astrobwt/astrobwtv3/', './cmd/dero-miner/',
                               './cmd/dero-miner/dsa/', './cmd/dero-miner/gsplit/', './glue/rwc/', './walletapi/rpcserver/',
                               './metrics/', './cmd/derod/', './cmd/derod/rpc/', './p2p/nat/', './cmd/explorer/...',
                               './walletapi/...', './cmd/dero-wallet-cli/', './cmd/simulator/', './tools/dashboard/',
                               './glue/httpguard/', './globals/', './glue/txcanon/'], timeout=900)  # Round 20/22 merge
    msgs = lambda t: sorted({re.sub(r':\d+:\d+:', ':', l) for l in t.splitlines() if l and not l.startswith('#')})
    known = {'blockchain/blockchain.go: unreachable code', 'blockchain/transaction_execute.go: unreachable code',
             'cmd/derod/main.go: unreachable code'}  # pre-existing on 9703e42
    new = [m for m in msgs(vet_new + vet_err) if m not in known]
    if unformatted or new:
        event('format', 'FAIL', unformatted=unformatted, vet_new=new)
        finish(6)
    event('format', 'PASS', gofmt='clean', vet='only the 3 pre-existing "unreachable code" findings')


def s3_test():
    event('test', 'START')
    res = {}
    runs = [(pkg, pat, True) for pkg, pat in NEW_TESTS.items()]
    for pkg, names in NORACE_NEW_TESTS.items():  # R23: tests that skip themselves under -race run once without it
        runs = [(p, '|'.join(w for w in pat.split('|') if w not in names), r) if p == pkg else (p, pat, r)
                for p, pat, r in runs]
        runs.append((pkg, '|'.join(names), False))
    for pkg, pat, race in runs:
        if not pat:
            continue
        rc, out, err = sh(['go', 'test', pkg, '-run', pat, '-count=1', *(['-race'] if race else []), '-v'], timeout=900)
        passed = re.findall(r'--- PASS: (\w+)', out)
        failed = re.findall(r'--- FAIL: (\w+)', out)
        # every alternative in the pattern must name a test that ran and passed: `go test -run X` with no match
        # passes vacuously (discovery harness-gaps-06)
        unmatched = [w for w in pat.split('|') if not any(p.startswith(w) for p in passed)]
        res[pkg if race else pkg + ' (no -race)'] = {'passed': passed, 'failed': failed, 'unmatched': unmatched}
        if rc != 0 or failed or unmatched:
            ok_r, rec = s3_retry(pkg, race, failed, unmatched, out + err)   # r24 (B21): listed flaky tests get a re-run
            res[pkg if race else pkg + ' (no -race)']['known_flaky'] = rec
            if not ok_r:
                event('test', 'FAIL', new_tests=res, tail=(out + err)[-800:])
                finish(7)
            SUMMARY.setdefault('known_flaky', {})[pkg] = rec
    full = {}
    for pkg in ('./p2p/', './blockchain/'):
        rc, out, err = sh(['go', 'test', pkg, '-count=1'], timeout=1500)
        full[pkg] = {'rc': rc, 'tail': (out + err).strip().splitlines()[-1:] if (out + err).strip() else []}
    bad = {k: v for k, v in full.items() if v['rc'] != 0}
    if bad:
        # rule #28: a red package test is only ours if it is green on the base; check before blaming the change
        wt = Path('/private/tmp') / f'derobase-{TS}'
        sh(['git', 'worktree', 'add', '--detach', str(wt), UPSTREAM_BASE])
        base = {}
        for pkg in bad:
            rc, out, err = sh(['go', 'test', pkg, '-count=1'], cwd=wt, timeout=1500)
            base[pkg] = rc
        sh(['git', 'worktree', 'remove', '--force', str(wt)])
        ours = [p for p in bad if base.get(p) == 0]
        if ours:
            event('test', 'FAIL', new_tests=res, full=full, base_rc=base)
            finish(7)
        event('test', 'PASS', new_tests=res, full=full, note=f'package failures also fail on {UPSTREAM_BASE}: {base}')
        return
    event('test', 'PASS', new_tests=res, full=full)


KNOWN_FAILURES = HARNESS / 'loop/KNOWN_TEST_FAILURES.json'   # r24 (B21): tests known to fail, with evidence
FLAKY_RERUNS, FLAKY_MIN_PASS = 3, 2


def known_failures(path=None):
    """{pkg: {test: class}} from harness/loop/KNOWN_TEST_FAILURES.json ({} when missing: nothing is relabelled)"""
    try:
        d = json.loads(Path(path or KNOWN_FAILURES).read_text())
    except (OSError, ValueError):
        return {}
    out = {}
    for e in d.get('tests') or []:
        if isinstance(e, dict) and e.get('pkg') and e.get('test') and e.get('class') in ('upstream-red', 'flaky'):
            out.setdefault(e['pkg'], {})[e['test']] = e['class']
    return out


def s3_retry_verdict(names, listed, res, broken, first_race=False):
    """r24 (B21): (ok, record) after a failed S3 package run. ok only when there is something to excuse, every failed
    or unmatched name is a LISTED flaky test, and each passed at least FLAKY_MIN_PASS of its FLAKY_RERUNS re-runs
    without a data race (classify_runs puts a racy test in `broken`). r24 verify: a data race in the FIRST run
    (`first_race`) is never excused by clean re-runs (classify_runs' rule, HR20-6: a race in any run is broken). Pure."""
    rec = {n: (res.get(n) or {'pass': 0, 'fail': 0}) for n in names}
    ok = not first_race and bool(names) and all(n in listed for n in names) and all(
        rec[n].get('pass', 0) >= FLAKY_MIN_PASS and n not in broken for n in names)
    return ok, rec


def s3_retry(pkg, race, failed, unmatched, first=''):
    names = sorted(set(failed) | set(unmatched))
    if RACE_MARK.search(first or ''):                    # r24 verify: the first run raced -> FAIL, no re-run
        return s3_retry_verdict(names, set(), {}, [], first_race=True)
    listed = {k for k, c in known_failures().get(pkg, {}).items() if c == 'flaky'}
    if not names or not set(names) <= listed:
        return False, {}
    rc, out, err = sh(['go', 'test', pkg, '-run', '^(' + '|'.join(names) + ')$', f'-count={FLAKY_RERUNS}',
                       *(['-race'] if race else []), '-v'], timeout=900)
    res, _, broken = classify_runs(out + err, FLAKY_RERUNS)
    return s3_retry_verdict(names, listed, res, broken)


UPSTREAM_BASE = 'bf274e5'           # pristine Release153 content (harness/baseline); rule #28 compares against it
NEW_TESTS_BASE = 'HEAD'

# r23c: the round registry. Before r23c every round re-typed its ids into the run command (--new-tests-base) and into
# this file (ROUND_NEW_METHODS), and the next session had to dig them out of a transcript. harness/round.json now
# names them once; 'pending' means not known yet and is never used as a value. A missing or unreadable registry
# falls back to the pre-r23c literals, and the BEGIN event says which source each value came from.
ROUND_FILE = HARNESS / 'round.json'
PENDING = 'pending'


def load_round(path=None):
    """(registry, current round) from harness/round.json; ({}, {}) when it is missing or unreadable"""
    try:
        reg = json.loads(Path(path or ROUND_FILE).read_text())
    except (OSError, ValueError):
        return {}, {}
    cur = next((r for r in reg.get('rounds', []) if isinstance(r, dict) and r.get('id') == reg.get('current')), {})
    return reg, cur


def known(v):
    """a registry value that may be used: present and not the literal 'pending'"""
    return v not in (None, '', PENDING)


def resolve_new_tests_base(cli, cur):
    """(base, source) for S3a: --new-tests-base wins, then the current round's new_tests_base, then HEAD (pre-r23c)"""
    if cli:
        return cli, 'cli'
    if known((cur or {}).get('new_tests_base')):
        return cur['new_tests_base'], 'round.json'
    return 'HEAD', 'default'


ROUND_STATUSES = ('planned', 'in-progress', 'implemented', 'shipped', 'measured')   # r23c: implemented = merged, pipeline run, installed, not yet measured live
ROUND_DONE = ('implemented', 'shipped', 'measured')   # statuses that must name their version, merge and pipeline
ROUND_COMMIT_FIELDS = ('new_tests_base', 'merge_commit', 'head_after')
NO_DATA_BEFORE_RUN = ('merge_commit', 'head_after', 'pipeline_full', 'go_mutations', 'version_suffix')


def round_problems(reg, version_suffix, commit_ok):
    """(errors, warnings) of a registry. version_suffix: the +suffix config/version.go carries; commit_ok(rev) says a
    revision resolves. Pure, so the KAT can feed it forged registries. A planned round may hold no result (a number
    before the round ran is a guess); a shipped one must name its version, merge and pipeline; the current round's
    version must match config/version.go once it is set (an in-progress round may still carry the previous one)."""
    err, warn = [], []
    rounds = reg.get('rounds') if isinstance(reg, dict) else None
    if not isinstance(rounds, list) or not rounds:
        return ['no rounds list'], warn
    ids = [r.get('id') for r in rounds if isinstance(r, dict)]
    if len(ids) != len(rounds) or len(set(ids)) != len(ids):
        err.append(f'round ids missing or repeated: {ids}')
    if reg.get('current') not in ids:
        err.append(f"current {reg.get('current')!r} is not a listed round")
    if sum(1 for r in rounds if isinstance(r, dict) and r.get('status') == 'in-progress') > 1:
        err.append('more than one round in-progress')
    if reg.get('upstream_base') != UPSTREAM_BASE:
        err.append(f"upstream_base {reg.get('upstream_base')!r} != pipeline UPSTREAM_BASE {UPSTREAM_BASE!r}")
    for r in (x for x in rounds if isinstance(x, dict)):
        rid, st = r.get('id'), r.get('status')
        if st not in ROUND_STATUSES:
            err.append(f'{rid}: status {st!r} not in {ROUND_STATUSES}')
        gs = r.get('github_sync') or {}
        for f, v in [(f, r.get(f)) for f in ROUND_COMMIT_FIELDS] + [('github_sync.' + k, gs.get(k)) for k in ('base', 'target')]:
            if v is None:
                err.append(f'{rid}: {f} absent (write "pending" when it is not known)')
            elif known(v) and not commit_ok(v):
                err.append(f'{rid}: {f} {v!r} does not resolve to a commit')
        if st == 'planned':
            err += [f'{rid}: planned round carries a result {f}={r.get(f)!r}' for f in NO_DATA_BEFORE_RUN if known(r.get(f))]
        if st in ROUND_DONE:
            err += [f'{rid}: {st} round lacks {f}' for f in ('version_suffix', 'merge_commit', 'pipeline_full') if not known(r.get(f))]
        gm = r.get('go_mutations')
        if known(gm) and not re.fullmatch(r'\d+/\d+', str(gm)):
            err.append(f'{rid}: go_mutations {gm!r} is not caught/total')
        nm = r.get('new_rpc_methods', {})
        if not isinstance(nm, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in nm.items()):
            err.append(f'{rid}: new_rpc_methods must map method -> probe key')
    err += track_problems(reg)                           # r24: tracks.{miner,node} = active|paused
    cur = next((r for r in rounds if isinstance(r, dict) and r.get('id') == reg.get('current')), None)
    if cur and version_suffix is not None:
        want = cur.get('version_suffix')
        shipped = {r.get('version_suffix') for r in rounds if isinstance(r, dict) and r.get('status') in ROUND_DONE}
        if cur.get('status') in ROUND_DONE and want != version_suffix:
            err.append(f"current {cur.get('id')} is {cur.get('status')} as {want!r} but config/version.go says {version_suffix!r}")
        elif known(want) and want != version_suffix:
            warn.append(f"current {cur.get('id')} names {want!r}; config/version.go still says {version_suffix!r}")
        elif not known(want) and version_suffix not in shipped:
            warn.append(f"config/version.go says {version_suffix!r}: set rounds[{cur.get('id')}].version_suffix")
    return err, warn


def track_problems(reg):
    """r24: the registry's tracks errors (kit/roundtracks.track_problems). Without the kit module (a KAT copy) a round
    that names tracks is an error: an unvalidated pause must not pass."""
    rt = _roundtracks()
    if rt:
        return rt.track_problems(reg)
    return [f"{r.get('id')}: tracks present but kit/roundtracks.py is missing" for r in (reg.get('rounds') or [])
            if isinstance(r, dict) and 'tracks' in r]


def version_suffix_of(text):
    """the +suffix of config/version.go's MustParse literal (e.g. 22102026.r23b), or None"""
    m = re.search(r'MustParse\("[^"+]*\+([^"]+)"\)', text or '')
    return m.group(1) if m else None


ROUND_REG, CUR_ROUND = load_round()
FLAKY_COUNT = 3


def _roundtracks():
    """r24: kit/roundtracks.py (shared with run_gates), or None when a copy of this file has no kit/ next to it (a KAT
    copy): then no track is ever paused, which is the pre-r24 behaviour, never a weaker one"""
    try:
        spec = importlib.util.spec_from_file_location(f'roundtracks_for_pipeline_{id(HARNESS)}', HARNESS / 'kit/roundtracks.py')
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    except (OSError, ImportError, SyntaxError):
        return None


RT = _roundtracks()
MINER_TRACK = RT.track_state(ROUND_REG) if RT else ('active', 'kit/roundtracks.py not found: the track runs')


def miner_sources_changed(base):
    """r24: the changed paths under the miner sources since `base` (tracked diff + untracked files), or None when git
    cannot say (then a paused S4b/S4c runs anyway)"""
    paths = list(RT.MINER_PATHS) if RT else ['cmd/dero-miner', 'astrobwt', 'gpu-miner-poc']
    rc, out, _ = sh(['git', 'diff', '--name-only', base, '--', *paths], timeout=120)
    rc2, out2, _ = sh(['git', 'ls-files', '--others', '--exclude-standard', '--', *paths], timeout=120)
    if rc != 0 or rc2 != 0:
        return None
    return sorted(set(out.split()) | set(out2.split()))


def stage_paused(stage):
    """r24: True after recording `stage` PAUSED (miner track paused and no miner source changed, §0.3); False when the
    stage must run (it then logs why when the track is paused)"""
    if not RT or MINER_TRACK[0] != 'paused':
        return False
    paused, why = RT.stage_paused(MINER_TRACK[0], miner_sources_changed(NEW_TESTS_BASE))
    if paused:
        event(stage, 'PAUSED', why=[why], track=MINER_TRACK[1], base=NEW_TESTS_BASE)
        return True
    event(stage, 'INFO', why=why)
    return False


def new_test_names(diff_text):
    """{package dir: [Test names]} added by a unified diff (`+func TestX(`), keyed by the file's directory"""
    out, cur = {}, None
    for l in diff_text.splitlines():
        m = re.match(r'^\+\+\+ b/(.+_test\.go)$', l)
        if m:
            cur = './' + str(Path(m.group(1)).parent) + '/'
            continue
        if l.startswith('+++ ') or l.startswith('--- '):
            cur = None if not l.startswith('--- ') else cur
            continue
        m = re.match(r'^\+func (Test\w+)\(\s*\w+ \*testing\.T\)', l)
        if m and cur:
            out.setdefault(cur, [])
            if m.group(1) not in out[cur]:
                out[cur].append(m.group(1))
    return out


RACE_MARK = re.compile(r'race detected during execution of test|WARNING: DATA RACE')


def classify_runs(out, count):
    """`go test -v -count=N` output -> ({test: {'pass', 'fail'}}, flaky, broken). A test that never reports is
    broken (it did not run). A test that failed with a data race in ANY run is broken, never flaky (r20 merge,
    HR20-6 review: an intermittent race in new code is exactly what -count=3 is for). Pure: the KAT feeds it text."""
    res, racy, race_seen = {}, set(), False
    for line in out.splitlines():
        if RACE_MARK.search(line):
            race_seen = True
        m = re.match(r'^\s*--- (PASS|FAIL|SKIP): (\w+)', line)
        if not m:
            continue
        st, name = m.groups()
        r = res.setdefault(name, {'pass': 0, 'fail': 0})
        if st == 'SKIP':  # R21: an env-gated test (GSPLIT_REAL=1 ...) did report: skipped is not 'never ran'
            r['skip'] = r.get('skip', 0) + 1
            race_seen = False
            continue
        r['pass' if st == 'PASS' else 'fail'] += 1
        if st == 'FAIL' and race_seen:
            racy.add(name)
        race_seen = False
    flaky = sorted(t for t, r in res.items() if r['fail'] and r['pass'] and t not in racy)
    broken = sorted(t for t, r in res.items() if (r['fail'] and not r['pass']) or t in racy)
    return res, flaky, broken


def s3a_package_result(rc, out, names, count):
    """one package's -count=N run -> (record, flaky, broken). A test that never reports is broken (did not run or
    did not build); a failing run in which every test passed (TestMain/init panic, timeout) is broken as
    '<package>' (r20 merge, HR20-6 review: the rc was ignored). Pure."""
    res, fl, br = classify_runs(out, count)
    br += [n for n in names if n not in res]
    if rc != 0 and not fl and not br:
        br.append('<package>')
    return res, fl, br


def skip_only(res, names):
    """R23b: the tests of `names` that reported only SKIP (never a pass or a fail) in a -race run. Pure."""
    return [n for n in names if n in res and res[n].get('skip') and not res[n].get('pass') and not res[n].get('fail')]


def s3a_stage_ok(flaky, broken):
    """S3a passes only when no new test failed in any run: FLAKY is reported separately but fails the stage too
    (r20 merge, HR20-6 review: it used to be INFO only)."""
    return not flaky and not broken


def collect_new_tests(base):
    rc, diff, _ = sh(['git', 'diff', base, '--', '*_test.go'])
    rc2, untracked, _ = sh(['git', 'ls-files', '--others', '--exclude-standard', '--', '*_test.go'])
    for f in untracked.split():
        try:
            diff += f'\n+++ b/{f}\n' + ''.join('+' + l + '\n' for l in (ROOT / f).read_text().splitlines())
        except OSError:
            pass
    return new_test_names(diff)


NORACE_TAG = re.compile(r'^//go:build\s+.*!race\b', re.M)


def race_split(names, sources):
    """R22: (race, norace) — a test defined in a file built only without -race (//go:build !race) never compiles under
    -race, so S3a must run it without -race; under -race it 'never ran' and S3a called it broken (the walletapi
    Test_R22_MultiPayload_Distinct_Blinders, whose package harness races upstream)"""
    norace = set()
    for text in sources:
        if NORACE_TAG.search(text):
            norace |= {n for n in names if re.search(r'^func ' + re.escape(n) + r'\(', text, re.M)}
    return [n for n in names if n not in norace], [n for n in names if n in norace]


def s3a_flaky():
    event('flaky', 'START', base=NEW_TESTS_BASE, count=FLAKY_COUNT)
    tests = collect_new_tests(NEW_TESTS_BASE)
    if not tests:
        event('flaky', 'SKIP', why=f'no test added since {NEW_TESTS_BASE}')
        return
    record, flaky, broken = {}, {}, {}
    for pkg, names in sorted(tests.items()):
        srcs = [f.read_text(errors='replace') for f in sorted((ROOT / pkg).glob('*_test.go'))]
        res, fl, br = {}, [], []
        for subset, race in zip(race_split(names, srcs), (True, False)):
            if not subset:
                continue
            rc, out, err = sh(['go', 'test', pkg, '-run', '^(' + '|'.join(subset) + ')$', f'-count={FLAKY_COUNT}',
                               *(['-race'] if race else []), '-v'], timeout=1800)
            r1, f1, b1 = s3a_package_result(rc, out + err, subset, FLAKY_COUNT)
            res.update(r1 if race else {k: dict(v, race=False) for k, v in r1.items()})
            fl += f1 or []
            br += b1 or []
            # R23b: a test that skips itself under -race (t.Skip on race.Enabled: the nbio poller race) reported SKIP 3/3
            # and S3a passed it without one run; it is the timing test -count=3 exists for. Re-run those without -race.
            again = skip_only(r1, subset) if race else []
            if again:
                rc, out, err = sh(['go', 'test', pkg, '-run', '^(' + '|'.join(again) + ')$', f'-count={FLAKY_COUNT}', '-v'],
                                  timeout=1800)
                r2, f2, b2 = s3a_package_result(rc, out + err, again, FLAKY_COUNT)
                res.update({k: dict(v, race=False, race_skipped=True) for k, v in r2.items()})
                fl += f2 or []
                br += b2 or []
        record[pkg] = res
        if fl:
            flaky[pkg] = fl
        if br:
            broken[pkg] = br
    (HARNESS / f'loop/runs/flaky_{TS}.json').write_text(json.dumps({'base': NEW_TESTS_BASE, 'count': FLAKY_COUNT,
                                                                   'tests': record, 'flaky': flaky, 'broken': broken}, indent=1))
    SUMMARY['flaky'] = flaky
    # r24 (B21): label (never excuse) a new test's failure that the known list names; S3a still fails on it
    kf = known_failures()
    labels = {}
    for pkg in sorted(set(flaky) | set(broken)):
        for n in flaky.get(pkg, []) + broken.get(pkg, []):
            if n in kf.get(pkg, {}):
                labels.setdefault(pkg, {})[n] = kf[pkg][n]
    SUMMARY['flaky_known_labels'] = labels
    SUMMARY['skip_only'] = {pkg: [n for n, r in rec.items() if r.get('skip') and not r.get('pass') and not r.get('fail')]
                            for pkg, rec in record.items()}
    SUMMARY['skip_only'] = {k: v for k, v in SUMMARY['skip_only'].items() if v}   # env-gated tests: visible, not hidden
    if not s3a_stage_ok(flaky, broken):
        event('flaky', 'FAIL', broken=broken, flaky=flaky, record=f'harness/loop/runs/flaky_{TS}.json')
        finish(7)
    event('flaky', 'PASS', tests=sum(len(v) for v in tests.values()), flaky=sum(len(v) for v in flaky.values()))


def soundness_module():
    spec = importlib.util.spec_from_file_location('soundness_for_pipeline', HARNESS / 'soundness.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_file_of(pkg, name):
    """repo-relative path of the *_test.go in `pkg` that declares func `name` (None when none does)"""
    rx = re.compile(r'^func ' + re.escape(name) + r'\(', re.M)
    for f in sorted((ROOT / pkg).glob('*_test.go')):
        if rx.search(f.read_text(errors='replace')):
            return str(f.relative_to(ROOT))
    return None


def soundness_record(results, registry, sm, sha=None):
    """{pkg::name: {status, race, file, fingerprint}} from {(pkg, name): (status, race)}; the fingerprint holds the sha256
    of the test's own file and of every watch file of the claims it backs. A test whose file cannot be found is
    MISSING (it cannot back anything). Pure but for the hashing (`sha`)."""
    sha = sha or sm.sha
    out = {}
    for (pkg, name), (status, race) in sorted(results.items()):
        f = test_file_of(pkg, name)
        files = ([f] if f else []) + sm.watch_files(registry, pkg, name)
        out[f'{pkg}::{name}'] = {'status': status if f else 'MISSING', 'race': race, 'file': f,
                                 'fingerprint': {x: sha(ROOT / x) for x in sorted(set(files))}}
    return out


def s3s_soundness():
    """R23b: run every test a soundness-page claim names, record it for G22 (harness/loop/SOUNDNESS_LAST.json)"""
    event('soundness', 'START')
    sm = soundness_module()
    reg = json.loads((HARNESS / 'loop/SOUNDNESS_CLAIMS.json').read_text())
    want = sm.soundness_tests(reg)
    if not want:
        event('soundness', 'FAIL', why='the claim registry names no test: G22 would have nothing to accept')
        finish(14)
    results = {}
    for pkg, tests in sorted(want.items()):
        for race in (True, False):
            names = [n for n, r in tests if r == race]
            if not names:
                continue
            rc, out, err = sh(['go', 'test', pkg, '-run', '^(' + '|'.join(names) + ')$', '-count=1',
                               *(['-race'] if race else []), '-v'], timeout=1800)
            res, fl, br = s3a_package_result(rc, out + err, names, 1)
            for n in names:
                r = res.get(n) or {}
                results[(pkg, n)] = ('PASS' if r.get('pass') and not r.get('fail') else
                                     'SKIP' if r.get('skip') and not r.get('pass') and not r.get('fail') else 'FAIL', race)
    rec = {'run': TS, 'head': sh(['git', 'rev-parse', '--short', 'HEAD'])[1].strip(), 'tests': soundness_record(results, reg, sm)}
    tmp = HARNESS / 'loop/.SOUNDNESS_LAST.json.tmp'
    tmp.write_text(json.dumps(rec, indent=1))
    os.replace(tmp, HARNESS / 'loop/SOUNDNESS_LAST.json')
    bad = {k: v['status'] for k, v in rec['tests'].items() if v['status'] != 'PASS'}
    if bad:
        event('soundness', 'FAIL', not_passed=bad, record='harness/loop/SOUNDNESS_LAST.json')
        finish(14)
    event('soundness', 'PASS', tests=len(rec['tests']), record='harness/loop/SOUNDNESS_LAST.json',
          norace=sorted(k for k, v in rec['tests'].items() if v['race'] is False))


def s3k_kats():
    event('kats', 'START')
    done = {}
    kats = sorted((HARNESS / 'kat').glob('test_*.py'))
    if not kats:                                       # R22: zero KAT files passed vacuously
        event('kats', 'FAIL', why='no harness/kat/test_*.py found')
        finish(13)
    for p in kats:
        rc, out, err = sh([sys.executable, '-I', str(p)], timeout=1800)
        done[p.name] = (out + err).strip().splitlines()[-1:] if (out + err).strip() else []
        if rc != 0:
            event('kats', 'FAIL', kat=p.name, tail=(out + err)[-800:])
            finish(13)
    event('kats', 'PASS', results=done)


def s3b_mutate():
    """every local fix must be caught by its test when it is undone (harness/intel/go_mutations.json)"""
    event('mutate', 'START')
    out = HARNESS / f'runtime/gomut_{TS}.json'
    rc, o, e = sh([sys.executable, 'harness/intel/go_mutate.py', '--json', str(out), '--baseline', UPSTREAM_BASE], timeout=7200)
    last = (o + e).strip().splitlines()[-1:] if (o + e).strip() else []
    if rc != 0:
        event('mutate', 'FAIL', last=last, record=str(out.relative_to(ROOT)))
        finish(11)
    event('mutate', 'PASS', last=last, record=str(out.relative_to(ROOT)))


RACE_PKGS = ['./p2p/', './blockchain/', './cmd/derod/rpc/', './dvm/', './block/', './transaction/',
             './cmd/dero-miner/', './cmd/dero-miner/dsa/', './cmd/dero-miner/dsac/', './cmd/dero-miner/astropair/',
             # Round 18 merge (gsplit's real-Metal test skips unless GSPLIT_REAL=1)
             './cmd/dero-miner/gsplit/', './cmd/derod/', './glue/rwc/', './walletapi/rpcserver/', './metrics/',
             # Round 19 merge (walletapi, walletapi/xswd and cmd/simulator stay out: their upstream tests fail under -race on
             # 9703e42 too; their new tests run with -race in NEW_TESTS)
             './p2p/nat/', './cmd/explorer/explorerlib/', './tools/dashboard/', './cmd/dero-wallet-cli/',
             # Round 20 merge
             './glue/httpguard/', './globals/',
             # Round 22 merge (proof/, cryptography/ and rpc/ are consensus packages: only their new tests run, in NEW_TESTS)
             './glue/txcanon/',
             # Round 23 merge
             './glue/emission/', './glue/txprecheck/', './tools/emission-audit/', './walletapi/mnemonics/',
             # Round 23b merge
             './tools/launchd/']


def s3c_race():
    """rpc2 runs every request on its own goroutine: the race detector runs over every package the node's request
    paths touch, not just the new tests"""
    event('race', 'START', packages=RACE_PKGS)
    rc, o, e = sh(['go', 'test', '-race', '-count=1', *RACE_PKGS], timeout=3600)
    races = (o + e).count('WARNING: DATA RACE')
    oks = re.findall(r'^ok\s+(\S+)', o, re.M)
    if rc != 0 or races:
        # R21: the 800-char tail lost WHICH package/test failed (only the passing packages after it were kept)
        log = HARNESS / f'loop/runs/race_{TS}.log'
        log.write_text(o + e)
        failed = sorted(set(re.findall(r'^(?:FAIL\s+\S+|--- FAIL: \S+|panic: .*)', o + e, re.M)))
        event('race', 'FAIL', races=races, failed=failed[:40], log=str(log.relative_to(ROOT)), tail=(o + e)[-800:])
        finish(12)
    event('race', 'PASS', packages_ok=len(oks), races=0)


def s4_build():
    event('build', 'START')
    STAGE.mkdir(exist_ok=True)
    want_ver = re.search(r'MustParse\("([^"]+)"\)', (ROOT / 'config/version.go').read_text()).group(1)
    built = {}
    global BUILD_DIRTY
    rc, st, _ = sh(['git', 'status', '--porcelain', '--untracked-files=all'], timeout=60)
    BUILD_DIRTY = porcelain_paths(st) if rc == 0 else None   # S6's F7 gate judges the tree the binaries came from
    for name, pkg in BINARIES.items():
        rc, out, err = sh(['go', 'build', '-o', str(STAGE / name), pkg], timeout=1800)
        if rc != 0:
            event('build', 'FAIL', binary=name, err=err[-600:])
            finish(8)
        built[name] = (STAGE / name).stat().st_size
    rc, out, err = sh([str(STAGE / 'derod'), '--version'], timeout=60)
    ver_ok = want_ver in (out + err)
    rc, mh, me = sh([str(STAGE / 'dero-miner'), '--help'], timeout=60)
    miner_flags = {f: f in (mh + me) for f in ('--cpu-max', '--gpu', '--gpu-max', '--sort', '--cpu-qos', '--pair', '--node-rpc-address',
                                               '--gpu-mode', '--metrics-bind',
                                               '--phase-duty', '--supervised',  # r23b payouts (both off by default)
                                               'auto:<floor>')}  # r22: the opt-in duty tuner (--cpu-max/--gpu-max=auto)
    rc, dh, de = sh([str(STAGE / 'derod'), '--help'], timeout=60)
    derod_flags = {f: f in (dh + de) for f in ('--lowlatency', '--p2p-nat', '--fastsync',  # r19: NAT mapping (default off)
                                               # r20: derod log rotation (defaults = upstream 100 MB x 2)
                                               '--log-max-size', '--log-max-backups', '--log-max-age', '--log-compress',
                                               # r22: opt-in GetTransaction cache; --p2p-nat=probe (read-only)
                                               '--rpc-tx-cache', 'probe (read-only')}
    rc, wh, we = sh([str(STAGE / 'dero-wallet-cli'), '--help'], timeout=60)
    wallet_ok = ('rpc-server' in (wh + we) or 'daemon-address' in (wh + we)) and '--xswd-allow-remote' in (wh + we)
    # cross builds (compile only): the miner and derod for Windows, and metrics for js/wasm (r18 DEP-11: the wasm
    # wallet failed to compile on syscall.Statfs)
    cross = {}
    for goos, goarch, pkgs in (('windows', 'amd64', ['./cmd/dero-miner', './cmd/derod', './cmd/dero-wallet-cli']),
                               ('js', 'wasm', ['./metrics/'])):
        rc, o, e = sh(['go', 'build', '-o', os.devnull, *pkgs] if len(pkgs) == 1 else ['go', 'build', *pkgs], timeout=1800,
                      env={'GOOS': goos, 'GOARCH': goarch})
        cross[f'{goos}/{goarch}'] = rc == 0
    if not (ver_ok and all(miner_flags.values()) and all(derod_flags.values()) and wallet_ok and all(cross.values())):
        event('build', 'FAIL', version_ok=ver_ok, miner_flags=miner_flags, derod_flags=derod_flags, wallet_help=wallet_ok, cross=cross,
              derod_version_output=(out + err)[-200:])
        finish(8)
    event('build', 'PASS', sizes=built, version=want_ver, miner_flags=miner_flags, derod_flags=derod_flags, wallet_help=wallet_ok,
          cross=cross)


BUILD_DIRTY = None                   # S4: the dirty paths at build time (None = unknown -> F7 is strict)
BENCH_LOCK = None                    # --benchlock: the machine-wide lock file benchlock.py uses
NO_BENCHLOCK = False                 # --no-benchlock: the operator ran S4b unlocked ON PURPOSE (recorded, not failed)
BENCH_THREADS = 4                    # live-box rule (R19): CPU benches at <= 6 threads; H/cpu-s barely moves with threads
CONTENDED_OK = False                 # --contended-ok: a REFUSED (contended) A/B is recorded and the run goes on
CENSUS_S = 5.0                       # seconds between the two ps samples of one census


def _contention():
    spec = importlib.util.spec_from_file_location(f'contention_for_pipeline_{id(HARNESS)}', HARNESS / 'intel/contention.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def ab_census(measure=None):
    """one read-only census with the live miner's caps (contention.measure), or {'contended': None, 'why'}"""
    try:
        CT = _contention()
        return (measure or (lambda: CT.measure(CENSUS_S, *CT.miner_caps())))()
    except Exception as e:                                         # noqa: BLE001 — unknown is said, and judged contended
        return {'contended': None, 'why': f'census failed: {type(e).__name__}: {e}'}


def ab_contention(before, after):
    """the A/B's contention from the census before and after it. Pure. An unknown census counts as contended: an A/B
    whose box state nobody measured cannot claim a gain or a regression either."""
    cs = [c for c in (before, after) if c is not None]
    cont = any(c.get('contended') is not False for c in cs) or not cs
    why = ' | '.join(f"{k}: {(c or {}).get('why')}" for k, c in (('before', before), ('after', after)) if c is not None)
    slim = lambda c: None if c is None else {k: c.get(k) for k in ('contended', 'foreign_cores', 'miner_cores', 'budget_cores',
                                                                   'headroom_cores', 'load1', 'law_loss_hs')}
    return {'contended': cont, 'why': why or 'no census', 'before': slim(before), 'after': slim(after)}


@contextlib.contextmanager
def bench_lock():
    """hold the machine-wide bench lock (fcntl.flock on the same file as benchlock.py) for one bench, if configured"""
    if not BENCH_LOCK:
        yield
        return
    with open(BENCH_LOCK, 'w') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def parse_bench(out, threads):
    """(hashes per CPU-second, wall H/s) from the --bench table row for `threads` (columns: threads, duration,
    hashes, per-hash, H/cpu-s, H/s). H/cpu-s is None for builds before r18 (5 columns) or a '-' (no CPU clock)."""
    rows = [l.split() for l in out.splitlines() if re.match(rf'^\s*{threads}\s+\S+\s+\d+\s', l)]
    if not rows:
        return None, None
    r = rows[-1]
    wall = float(r[-1])
    cpu = float(r[-2]) if len(r) >= 6 and r[-2] != '-' else None
    return cpu, wall


def sort_impl(out):
    """the suffix sorter a run really used, from its 'suffix sort' log line (cmd/dero-miner/fastsort.go
    install_fast_sort): 'native C', 'Go' or 'SA-IS'; builds before r16 had only the Go port and print no impl.
    None when the line is missing (a pre-r14 build, or the output was cut)."""
    m = re.search(r'suffix sort\s+\{"using": "([^"]*)"', out)
    if not m:
        return None
    u = m.group(1)
    if not u.startswith('descriptor sort'):
        return 'SA-IS'
    return u[len('descriptor sort, '):].split(' (')[0] if u.startswith('descriptor sort, ') else 'Go'


def like_for_like(runs):
    """staged vs installed per --sort mode, only where both builds used the SAME sorter. `runs` maps
    mode -> {'staged': [(h_per_cpu_s, impl)], 'installed': [...]}. Returns {'ratio', 'mode', 'impl', 'per_mode', 'why'}:
    the ratio of medians for the first mode (auto, then descriptor) whose sorters agree on every run, else None with why.
    Pure, so the KAT can feed it the r20 numbers."""
    per, pick = {}, None
    for mode in ('auto', 'descriptor'):
        r = runs.get(mode) or {}
        st, inst = r.get('staged') or [], r.get('installed') or []
        si, ii = {i for _, i in st}, {i for _, i in inst}
        ms, mi = median([c for c, _ in st]), median([c for c, _ in inst])
        same = len(si) == 1 and si == ii and None not in si
        per[mode] = {'staged': ms, 'installed': mi, 'staged_sort': sorted(map(str, si)), 'installed_sort': sorted(map(str, ii)),
                     'like_for_like': same, 'ratio': round(ms / mi, 3) if same and ms and mi else None}
        if pick is None and per[mode]['ratio'] is not None:
            pick = mode
    if pick is None:
        return {'ratio': None, 'mode': None, 'impl': None, 'per_mode': per,
                'why': 'no --sort mode where the staged and installed builds used the same sorter: ' +
                       '; '.join(f"{m}: staged {v['staged_sort']} vs installed {v['installed_sort']}" for m, v in per.items())}
    return {'ratio': per[pick]['ratio'], 'mode': pick, 'impl': per[pick]['staged_sort'][0], 'per_mode': per, 'why': None}


def bench_run(binary, threads, *extra):
    with bench_lock():
        rc, out, err = sh([str(binary), '--bench', f'--mining-threads={threads}', '--cpu-max=100', *extra], timeout=1800)
    return rc, out + err


def bench_rate(binary, sort, threads):
    """wall H/s at `threads` threads (kept for the record; not a gate metric since R19)"""
    return parse_bench(bench_run(binary, threads, f'--sort={sort}')[1], threads)[1]


def bench_cpu_rate(binary, sort, threads):
    """hashes per CPU-second at `threads` threads (r18+ --bench prints it before the wall H/s), or None for older
    builds. Load-invariant on this shared box: the same binary's 10-thread wall H/s spanned 5,880-12,771 in Round 18
    while H/cpu-s stayed 2,275-2,360, and the r17 wall x1.59 at 2 threads was off-CPU waiting, not cheaper hashes."""
    return parse_bench(bench_run(binary, threads, f'--sort={sort}')[1], threads)[0]


def split_bench(binary, threads):
    """the CPU side of --gpu-mode=split (r19+ --bench --gpu-mode=split): {'h_per_cpu_s', 'wall_hs', 'declined'} or
    {'skip': why}. Builds before r19 ignore --gpu-mode under --bench (r18) or reject it in docopt (r17-); the marker
    line 'split: CPU side only' tells a real split bench from a plain one. R21: 'sort' is the sorter it used."""
    rc, out = bench_run(binary, threads, '--gpu-mode=split')
    if 'split: off' in out:
        return {'skip': re.search(r'split: off \(([^)]*)', out).group(1)}
    if 'split: CPU side only' not in out:
        return {'skip': 'this build has no split bench (pre-r19)'}
    cpu, wall = parse_bench(out, threads)
    m = re.search(r'split: declined sorts (\d+)', out)
    return {'h_per_cpu_s': cpu, 'wall_hs': wall, 'declined': int(m.group(1)) if m else None, 'sort': sort_impl(out)}


LIVE_SPLIT_MAX_AGE_H = 1.0           # a split reading older than this says nothing about the build being judged


def live_split_reading(snaps=None, now=None):
    """the GPU side of split, as the LIVE miner measured it (newest miner_intel snapshot) — never benched here.
    R21: 'LIVE' only when the snapshot is fresh and its current run has split windows; r20 recorded status LIVE with
    every number null from a 4-hour-old snapshot taken 1 s after a miner start (minerintel_20261028T083247: lines 0)."""
    snaps = sorted((HARNESS / 'runtime').glob('minerintel_*.json')) if snaps is None else sorted(snaps)
    if not snaps:
        return {'status': 'SKIP', 'why': 'no miner_intel snapshot yet (harness/intel/miner_intel.py)'}
    d = json.loads(Path(snaps[-1]).read_text())
    run = (d.get('runs') or [{}])[-1]
    sp = run.get('split') or {}
    rg = sp.get('regime') or {}
    now = time.time() if now is None else now
    try:
        age_h = round((now - datetime.datetime.fromisoformat(d['captured']).timestamp()) / 3600, 2)
    except (KeyError, ValueError):
        age_h = None
    rec = {'snapshot': Path(snaps[-1]).name, 'age_h': age_h, 'version': run.get('version'), 'gpu_mode': run.get('gpu_mode'),
           'staged_mean_hs': sp.get('staged_mean'), 'total_mean_hs': (run.get('hashrate') or {}).get('mean'),
           'drop_fraction': sp.get('drop_fraction'), 'restarts': sp.get('restarts_last'), 'regime': rg.get('regime'),
           'cpu_backlog_fraction': rg.get('cpu_backlog_fraction'), 'windows': rg.get('windows')}
    if age_h is None or age_h > LIVE_SPLIT_MAX_AGE_H:
        return {'status': 'STALE', 'why': f'snapshot {age_h} h old (> {LIVE_SPLIT_MAX_AGE_H} h): run miner_intel first', **rec}
    if not sp.get('lines') or sp.get('staged_mean') is None:
        return {'status': 'NO_DATA', 'why': 'the current run has no GPU split window yet', **rec}
    return {'status': 'LIVE', **rec}


def median(v):
    v = sorted(x for x in v if x is not None)
    return v[len(v) // 2] if v else None


def judge_minerbench(res_cpu, lfl, split, full_cpu, locked=True, contended=False):
    """the S4b verdict from H/cpu-s readings alone: (ok, reasons). Pure, so the KAT can feed it numbers.
    `lfl` is like_for_like(): the staged/installed ratio exists only where both used the same sorter (R21).
    R23 `contended`: the box was contended, so no RATIO is judged (a ratio would be a gain or regression claim); the
    correctness checks still are. The caller turns (True, []) under contention into REFUSED, never PASS."""
    why = []
    if not locked:
        why.append('benches ran without the machine-wide bench lock (pass --benchlock FILE, or --no-benchlock on purpose)')
    ds, ss = median(res_cpu.get('descriptor', [])), median(res_cpu.get('sais', []))
    if ds is None or ss is None:
        why.append(f'descriptor {ds} / SA-IS {ss}: a sorter bench printed no H/cpu-s')
    elif ds <= ss and not contended:
        why.append(f'descriptor {ds} H/cpu-s does not beat SA-IS {ss}')
    pm = lfl.get('per_mode', {})
    st = (pm.get('auto') or {}).get('staged')
    if st is None:
        why.append('the staged build printed no H/cpu-s')
    elif lfl.get('ratio') is not None and lfl['ratio'] < 0.93 and not contended:
        why.append(f"staged is {lfl['ratio']:.3f} x the installed build with the same sorter ({lfl['mode']}: {lfl['impl']})")
    # r21 merge (HR21-1 verifier: no like-for-like mode used to wave a regression through). The staged build is THIS
    # tree: it always prints its 'suffix sort' line, so a missing sorter is a cut or changed output, never an old build.
    if any(s == 'None' for v in pm.values() for s in (v.get('staged_sort') or [])):
        why.append("the staged build printed no 'suffix sort' line: its sorter is unknown, so no like-for-like comparison")
    elif lfl.get('ratio') is None and any(s != 'None' for v in pm.values() for s in (v.get('installed_sort') or [])):
        # an installed build that names its sorter (r16+) can always be compared under one of the two modes
        why.append(f"no like-for-like staged/installed comparison: {lfl.get('why')}")
    if 'skip' in split:
        # the staged build is THIS tree (r19+): it has the split bench, so a skip is a broken bench, not an old build
        why.append(f"the staged build skipped the split bench: {split['skip']}")
    else:
        sc = split.get('h_per_cpu_s')
        if sc is None:
            why.append('split bench printed no H/cpu-s')
        elif split.get('declined'):
            why.append(f"split bench declined {split['declined']} sorts")
        elif full_cpu is not None and sc <= full_cpu and not contended:
            why.append(f'split CPU side {sc} H/cpu-s does not beat a full CPU hash {full_cpu}')
        if split.get('installed_h_per_cpu_s') and sc and sc / split['installed_h_per_cpu_s'] < 0.93 and \
                split.get('installed_sort') == split.get('sort') and not contended:
            why.append(f"split CPU side {sc} is {sc / split['installed_h_per_cpu_s']:.3f} x the installed build's")
    return not why, why


def s4b_miner():
    """the miner, gated on hashes per CPU-second (R19): sorter, staged vs installed, and the split CPU side. Every
    bench holds the bench lock; nothing here starts gpu_split_server or touches Metal."""
    if stage_paused('minerbench'):                       # r24: the miner track is paused (artifacts/dero-rft.md §0.3)
        return
    event('minerbench', 'START', threads=BENCH_THREADS, lock=BENCH_LOCK or ('none (--no-benchlock)' if NO_BENCHLOCK else 'none'))
    c_before = ab_census()
    rounds, threads = 3, BENCH_THREADS     # --bench hashes a fixed 1000 inputs per thread
    res = {'sais': [], 'descriptor': []}
    res_cpu = {'sais': [], 'descriptor': []}
    for _ in range(rounds):
        for sort in ('sais', 'descriptor'):
            cpu, wall = parse_bench(bench_run(STAGE / 'dero-miner', threads, f'--sort={sort}')[1], threads)
            res[sort].append(wall)
            res_cpu[sort].append(cpu)
    if any(v is None for vs in res.values() for v in vs):
        event('minerbench', 'FAIL', rates=res, why='a bench run printed no rate row')
        finish(13)
    with bench_lock():
        rc, out, err = sh([str(STAGE / 'dero-miner'), '--bench', '--mining-threads=1'], timeout=600)
    installed = 'descriptor sort' in (out + err) and 'self-test passed' in (out + err)
    # bench a COPY of the installed miner: builds before r16 open <exe>.log with os.Create even under --bench, and
    # the live miner writes bin/dero-miner.log, so benching bin/dero-miner itself wiped the live log (Round 16)
    installed_copy = STAGE / 'dero-miner.installed'
    shutil.copy2(BIN / 'dero-miner', installed_copy)
    # R21: like for like — both builds under the SAME --sort, interleaved, each run's sorter read back from its output
    prev, prev_cpu = {'installed': [], 'staged': []}, {'installed': [], 'staged': []}
    lfl_runs = {m: {'installed': [], 'staged': []} for m in ('auto', 'descriptor')}
    for _ in range(rounds):
        for sort in ('auto', 'descriptor'):
            for k, b in (('installed', installed_copy), ('staged', STAGE / 'dero-miner')):
                out = bench_run(b, threads, f'--sort={sort}')[1]
                cpu, wall = parse_bench(out, threads)
                lfl_runs[sort][k].append((cpu, sort_impl(out)))
                if sort == 'auto':
                    prev[k].append(wall)
                    prev_cpu[k].append(cpu)
    lfl = like_for_like(lfl_runs)
    # split mode, CPU side: staged (and the installed build when it has the bench), interleaved
    sp, sp_inst = [], []
    for _ in range(rounds):
        sp.append(split_bench(STAGE / 'dero-miner', threads))
        sp_inst.append(split_bench(installed_copy, threads))
    split = next((x for x in sp if 'skip' in x), None) or {
        'h_per_cpu_s': median([x['h_per_cpu_s'] for x in sp]), 'wall_hs': median([x['wall_hs'] for x in sp]),
        'declined': max((x['declined'] or 0) for x in sp), 'runs': sp, 'sort': sp[0].get('sort')}
    if 'skip' not in split and not any('skip' in x for x in sp_inst):
        split['installed_h_per_cpu_s'] = median([x['h_per_cpu_s'] for x in sp_inst])
        split['installed_sort'] = sp_inst[0].get('sort')
    elif 'skip' not in split:
        split['installed'] = next(x['skip'] for x in sp_inst if 'skip' in x)
    full_cpu = median(prev_cpu['staged'])
    cont = ab_contention(c_before, ab_census())
    ok, why = judge_minerbench(res_cpu, lfl, split, full_cpu, locked=bool(BENCH_LOCK) or NO_BENCHLOCK, contended=cont['contended'])
    rc, bi, be = sh(['go', 'version', '-m', str(STAGE / 'dero-miner')], timeout=60)
    pgo = re.search(r'-pgo=(\S+)', bi)
    med_cpu = {k: median(v) for k, v in res_cpu.items()}
    rec = dict(threads=threads, metric='hashes per CPU-second', h_per_cpu_s=res_cpu, median_h_per_cpu_s=med_cpu,
               ratio_cpu=round(med_cpu['descriptor'] / med_cpu['sais'], 2) if all(med_cpu.values()) else None,
               wall_rates_hs=res, prev_h_per_cpu_s=prev_cpu, prev_wall_hs=prev,
               vs_installed_cpu=lfl['ratio'], vs_installed_mode=lfl['mode'], vs_installed_sort=lfl['impl'],
               vs_installed_per_mode=lfl['per_mode'], vs_installed_why=lfl['why'],
               split_cpu_side=split, split_gpu_side=live_split_reading(),
               selftest_installed=installed, pgo=pgo.group(1) if pgo else 'none')
    rec['contention'] = cont
    if not ok or not installed:
        event('minerbench', 'FAIL', why=why + ([] if installed else ['the staged miner did not install the descriptor sort']),
              correctness_fail=bool(cont['contended']), **rec)
        finish(13)
    if cont['contended']:
        event('minerbench', 'REFUSED', why=[f"contended box: the ratios are not evidence ({cont['why']})"], **rec)
        if not CONTENDED_OK:
            finish(13)
        return
    event('minerbench', 'PASS', **rec)


GPU_SERVER = 'gpu_split_server'
GPU_DIR = ROOT / 'gpu-miner-poc'
GPU_BENCH = None                     # --gpu-bench: 'run' | 'off' (--no-gpu-bench) | None (judge the change)
GPU_GEOM = '512,6,3'                 # 512 nonces x ~12 us busy/hash ~ 6 ms per command buffer (live-box rule <= 8 ms)
GPU_BENCH_MAX = 50                   # --gpu-max for the bench server: the live split keeps the other half
GPU_RATIO_MIN = 0.93


def swift_change(stamps_text, src_bytes, name=GPU_SERVER):
    """{'changed': True/False/None, 'why'}: the server source vs the source hash its BUILD_STAMPS line recorded
    (gpu-miner-poc/build.sh). None = no stamp line (cannot tell: treated as changed by judge_gpubench). Pure."""
    import hashlib
    have = hashlib.sha256(src_bytes).hexdigest()
    for l in stamps_text.splitlines():
        f = l.split()
        if len(f) >= 3 and f[0] == name and not l.startswith('#'):
            return {'changed': f[1] != have, 'why': f"{name}.swift sha256 {have[:12]} vs stamped {f[1][:12]}"}
    return {'changed': None, 'why': f'no BUILD_STAMPS line for {name}'}


def parse_capacity(out):
    """the median staged H/s TestGPUCapacity printed ('GPU CAPACITY geom ... median N staged H/s'), or None"""
    m = re.search(r'GPU CAPACITY geom \S+ gpu-max \d+ .*?: median (\d+) staged H/s', out)
    return int(m.group(1)) if m else None


def judge_gpubench(change, mode, ab=None, contended=False):
    """S4c verdict: (status PASS|FAIL|SKIP|REFUSED, reasons). Pure. `ab` = {'bitexact': bool, 'staged': [..],
    'installed': [..], 'disturbed': bool} from a --gpu-bench run. R23: an UNCHANGED server with --gpu-bench is a
    self-A/B (same source): it must also land inside [GPU_RATIO_MIN, 1/GPU_RATIO_MIN], or the bench's own noise is wider
    than the gate. `contended`: no ratio is judged; an otherwise clean run is REFUSED, never PASS."""
    self_ab = change.get('changed') is False
    if self_ab and mode != 'run':
        return 'SKIP', [f"server source unchanged since its recorded build ({change['why']})"]
    if mode == 'off':
        return 'SKIP', [f"--no-gpu-bench on purpose although the server changed ({change['why']})"]
    if mode != 'run' or ab is None:
        return 'FAIL', [f"the GPU server changed ({change['why']}) and its GPU side was not benched: pass --gpu-bench "
                        '(or --no-gpu-bench on purpose)']
    why = []
    if ab.get('disturbed'):
        why.append('the live GPU split was disturbed (gpu_watch exit 99): STOP all GPU work')
    if not ab.get('bitexact'):
        why.append('the staged server is not bit-exact (TestRealGPUBitExact failed)')
    st, ins = median(ab.get('staged') or []), median(ab.get('installed') or [])
    # R22 (measured): TestGPUCapacity PASSES while its server cannot start — 'median 0 staged H/s', Restarts:5, when
    # loop_ops.metal.inc is not next to the binary. A zero rate is a failed arm, never a ratio (and never a /0).
    if None in (st, ins) or any(x is None or x <= 0 for x in (ab.get('staged') or []) + (ab.get('installed') or [])):
        why.append(f'a capacity run printed no rate or 0 (staged {ab.get("staged")}, installed {ab.get("installed")})')
    elif contended:
        pass
    elif st / ins < GPU_RATIO_MIN:
        why.append(f'staged server {st} vs installed {ins} staged H/s = x{st / ins:.3f} < {GPU_RATIO_MIN} (interleaved, quiet box)')
    elif self_ab and st / ins > 1 / GPU_RATIO_MIN:
        why.append(f'self-A/B of one source: x{st / ins:.3f} > {1 / GPU_RATIO_MIN:.3f} — the bench noise is wider than the gate')
    if why:
        return 'FAIL', why
    if contended:
        return 'REFUSED', ['contended box: the GPU A/B ratio is not evidence (correctness checks passed)']
    return 'PASS', ([f'self-A/B (unchanged source) x{st / ins:.3f}'] if self_ab else [])


def gpu_run(cmd, env):
    """one GPU command under the bench lock and gpu_watch (99 = the live split was disturbed)"""
    with bench_lock():
        return sh(['nice', '-n', '15', sys.executable, '-I', str(HARNESS / 'intel/gpu_watch.py'), 'run', '--', *cmd],
                  timeout=1800, env=env)


def s4c_gpubench():
    if stage_paused('gpubench'):                         # r24: the miner track is paused (artifacts/dero-rft.md §0.3)
        return
    src = GPU_DIR / f'{GPU_SERVER}.swift'
    stamps = GPU_DIR / 'BUILD_STAMPS'
    change = swift_change(stamps.read_text() if stamps.exists() else '', src.read_bytes() if src.exists() else b'')
    mode = GPU_BENCH
    st, why = judge_gpubench(change, mode)
    if mode != 'run' or st == 'SKIP':
        event('gpubench', st, why=why, change=change)
        if st == 'FAIL':
            finish(14)
        return
    STAGE.mkdir(parents=True, exist_ok=True)
    event('gpubench', 'START', change=change, geom=GPU_GEOM, gpu_max=GPU_BENCH_MAX,
          kind='self-A/B (unchanged source)' if change.get('changed') is False else 'staged vs installed')
    c_before = ab_census()
    staged, installed = STAGE / GPU_SERVER, STAGE / f'{GPU_SERVER}.installed'
    rc, o, e = sh(['nice', '-n', '15', 'xcrun', 'swiftc', '-O', str(src), '-o', str(staged)], timeout=1800)
    if rc != 0:
        event('gpubench', 'FAIL', why=['xcrun swiftc failed'], err=(o + e)[-600:])
        finish(14)
    shutil.copy2(GPU_DIR / GPU_SERVER, installed)
    # the server reads loop_ops.metal.inc from its working directory, which the engine sets to the binary's directory
    # (gsplit/engine.go p.cmd.Dir = filepath.Dir(bin)): without it every start dies and the capacity test reads 0
    shutil.copy2(GPU_DIR / 'loop_ops.metal.inc', STAGE / 'loop_ops.metal.inc')
    base = {'GSPLIT_REAL': '1', 'GOFLAGS': '-p=4'}
    ab = {'staged': [], 'installed': [], 'disturbed': False}
    rc, o, e = gpu_run(['go', 'test', './cmd/dero-miner/gsplit/', '-run', '^TestRealGPUBitExact$', '-count=1', '-v'],
                       {**base, 'GSPLIT_BIN': str(staged)})
    ab['bitexact'] = rc == 0 and '--- PASS: TestRealGPUBitExact' in o + e
    ab['disturbed'] |= rc == 99
    for k in range(3):
        if ab['disturbed']:
            break
        order = (('staged', staged), ('installed', installed)) if k % 2 == 0 else (('installed', installed), ('staged', staged))
        for name, b in order:
            rc, o, e = gpu_run(['go', 'test', './cmd/dero-miner/gsplit/', '-run', '^TestGPUCapacity$', '-count=1', '-v'],
                               {**base, 'GSPLIT_HARNESS': '1', 'GSPLIT_BIN': str(b), 'GSPLIT_GEOMS': GPU_GEOM,
                                'GSPLIT_GPUMAX': str(GPU_BENCH_MAX)})
            ab['disturbed'] |= rc == 99
            ab[name].append(parse_capacity(o + e))
            if ab['disturbed']:
                break
    cont = ab_contention(c_before, ab_census())
    st, why = judge_gpubench(change, mode, ab, contended=cont['contended'])
    event('gpubench', st, why=why, change=change, contention=cont, correctness_fail=st == 'FAIL' and bool(cont['contended']),
          kind='self' if change.get('changed') is False else 'changed', **ab)
    if st == 'FAIL' or (st == 'REFUSED' and not CONTENDED_OK):
        finish(14)


def clone_datadir(dst):
    """APFS-clone the live datadir in DEPENDENCY order. `cp -c -R` walks alphabetically (balances, bltx_store,
    topo.map), so topo.map — the index — was copied last, ~65 s after bltx_store, and could name blocks whose files
    the clone never got: every GetInfo then panicked in Load_Block_Timestamp (2026-10-21; the OLD binary failed
    identically on that clone, so it was the copy, not the code). Copy the index first and everything it points at
    afterwards: each later copy is a superset of what the earlier one references."""
    dst.mkdir(parents=True)
    order = ['topo.map', 'balances', 'bltx_store'] + sorted(p.name for p in LIVE_DATA.iterdir()
                                                           if p.name not in ('topo.map', 'balances', 'bltx_store'))
    for name in order:
        src = LIVE_DATA / name
        if not src.exists():
            continue
        rc, out, err = sh(['cp', '-c', '-R', str(src), str(dst / name)], timeout=3600)
        if rc != 0:
            return f'{name}: {err[-200:]}'
    return None


# RPC methods this round adds, mapped to the probe key that records them. The control (the build running before)
# must answer "no such method" for each; the candidate must answer. Update this per round.
# Round 14 adds no RPC method (its change is miner-side; derod only gains a nil hook), so the probe has nothing to
# tell the builds apart by and control_differs is vacuously true; S4b is that round's behavioural evidence instead.
# r23c: a round lists its methods in harness/round.json (rounds[current].new_rpc_methods, {method: probe key});
# feature_probes asks both shadows for each one, so adding a method no longer needs a code change here.
ROUND_NEW_METHODS = dict(CUR_ROUND.get('new_rpc_methods') or {})


def registration_tx():
    """a registration tx id from the live tx store: 101-byte files whose id starts 000000 (discovery datadir-01)"""
    for p in (LIVE_DATA / 'bltx_store').rglob('000000*.tx'):
        if p.stat().st_size == 101:
            return p.stem
    return None


def feature_probes(nodes):
    """what this round changes in observable behaviour, asked of both shadows: the candidate must show it, the
    control (the build running before) shows what was wrong"""
    out = {}
    reg = registration_tx()
    for k, n in nodes.items():
        p = {}
        try:
            body = json.dumps({'jsonrpc': '2.0', 'id': '1', 'method': 'DERO.GetSyncInfo'}).encode()
            r = json.loads(urllib.request.urlopen(urllib.request.Request(n['rpc'], data=body,
                           headers={'Content-Type': 'application/json'}), timeout=8).read())
            p['getsyncinfo'] = (r.get('result') or {}).get('status') or ('error: ' + str(r.get('error'))[:80])
        except Exception as e:                                              # noqa: BLE001
            p['getsyncinfo'] = f'error: {e}'[:100]
        if reg:
            body = json.dumps({'jsonrpc': '2.0', 'id': '1', 'method': 'DERO.GetTransaction',
                               'params': {'txs_hashes': [reg]}}).encode()
            r = json.loads(urllib.request.urlopen(urllib.request.Request(n['rpc'], data=body,
                           headers={'Content-Type': 'application/json'}), timeout=8).read())
            err = str(r.get('error') or '')
            p['registration_tx'] = 'ok' if r.get('result') else 'error: ' + err[:60]
            p['stack_in_error'] = 'goroutine' in err
        gi = rpc(n['rpc'], 'DERO.GetInfo') or {}
        p['target_height'] = gi.get('target_height')
        try:
            body = json.dumps({'jsonrpc': '2.0', 'id': '1', 'method': 'DERO.GetMiningOutcome'}).encode()
            r = json.loads(urllib.request.urlopen(urllib.request.Request(n['rpc'], data=body,
                           headers={'Content-Type': 'application/json'}), timeout=8).read())
            res_ = r.get('result')
            p['mining_outcome'] = ('ok' if isinstance(res_, dict) and {'submitted', 'paid', 'orphaned', 'pending'} <= set(res_)
                                   else 'error: ' + str(r.get('error'))[:60])
        except Exception as e:                                              # noqa: BLE001
            p['mining_outcome'] = f'error: {e}'[:80]
        si = rpc(n['rpc'], 'DERO.GetSyncInfo') or {}
        p['inbound'] = si.get('inbound')
        for meth, key in ROUND_NEW_METHODS.items():                  # r23c: this round's methods, from round.json
            if key in p:                 # r23c review: a specific probe above (e.g. mining_outcome) already judged it
                continue
            try:
                body = json.dumps({'jsonrpc': '2.0', 'id': '1', 'method': meth}).encode()
                r = json.loads(urllib.request.urlopen(urllib.request.Request(n['rpc'], data=body,
                               headers={'Content-Type': 'application/json'}), timeout=8).read())
                p[key] = 'ok' if 'result' in r and not r.get('error') else 'error: ' + str(r.get('error'))[:80]
            except Exception as e:                                          # noqa: BLE001
                p[key] = f'error: {e}'[:80]
        out[k] = p
    c = out.get('candidate', {})
    out['candidate_ok'] = (c.get('getsyncinfo') == 'synced' and c.get('registration_tx') == 'ok'
                           and not c.get('stack_in_error') and (c.get('target_height') or 0) > 0
                           and c.get('mining_outcome') == 'ok'
                           and str(c.get('inbound') or '').startswith(('unknown', 'reachable', 'unreachable')))
    k = out.get('control', {})
    # the probe must tell the two builds apart on what THIS round adds: the control lacks each method in
    # ROUND_NEW_METHODS. (Round 13's first run hard-coded Round 12's difference and failed for that reason alone.)
    out['control_differs'] = all('no such method' in str(k.get(key)) for key in ROUND_NEW_METHODS.values())
    out['candidate_ok'] = (out['candidate_ok'] and out['control_differs']
                           and all(c.get(key) == 'ok' for key in ROUND_NEW_METHODS.values()))   # r23c: and answers
    out['registration_tx'] = reg
    return out


def _census(logf):
    """What a shadow printed, by class. A recovered panic in the mining-template path that reads a missing block
    snapshot is a CLONE ARTIFACT: an APFS clone of a datadir that is being written can catch the newest block
    before its snapshot record lands (first seen 2026-10-21, 129 lines that stopped once that block left the
    20-block template history). It is classified separately so the control can show whether the old binary does
    the same."""
    census, artifacts, panics, first, last = {}, 0, 0, None, None
    for line in (logf.read_text(errors='replace').splitlines() if logf.exists() else []):
        try:
            d = json.loads(line)
        except Exception:                                                   # noqa: BLE001
            continue
        m = d.get('M', '')
        if 'Recovered' in m and 'Create_new_miner_block' in str(d.get('stack', '')) and 'file does not exist' in str(d.get('error', '')):
            artifacts += 1
            first, last = first or d['T'], d['T']
            continue
        if d.get('L') in ('ERROR', 'WARN') or any(x in m for x in ('peer could not serve', 'connection closed during',
                                                                     'SC reverted for an anonymous', 'SC install rejected')):
            key = f"{d.get('L')} {d.get('C')} {m.strip()[:60]}"
            census[key] = census.get(key, 0) + 1
            if 'Recover' in m:
                panics += 1
    return {'census': census, 'clone_artifacts': artifacts, 'artifact_window': [first, last], 'other_panics': panics}


def s5_shadow(seconds):
    """Two shadows at once, each on its own APFS clone, both syncing only from the live node over loopback:
    CONTROL runs the binary the operator is running now, CANDIDATE runs the new one. All three treehashes must
    agree wherever the topoheights do, and anything the candidate logs that the control does not is a regression."""
    event('shadow', 'START', seconds=seconds)
    base = Path('/private/tmp') / f'dero-shadow-{TS}'
    # the live node keeps ONE connection per remote IP (p2p/connection_pool.go Connection_Add keys the map by
    # Address(c)), so two shadows dialling 127.0.0.1 get one slot between them (diagnostic run 2026-10-21: control 1
    # peer, candidate 0). The candidate dials the live node's LAN address instead — the live node binds 0.0.0.0:11011.
    lan = subprocess.run(['ipconfig', 'getifaddr', 'en0'], capture_output=True, text=True).stdout.strip() or \
        subprocess.run(['ipconfig', 'getifaddr', 'en1'], capture_output=True, text=True).stdout.strip()
    if not lan:
        event('shadow', 'FAIL', why='no LAN address for the candidate to reach the live node from a distinct IP')
        finish(9)
    nodes = {'control': {'bin': BIN / 'derod', 'rpc': 'http://127.0.0.1:30102/json_rpc', 'ports': (30102, 30100, 31011),
                         'via': '127.0.0.1:11011'},
             'candidate': {'bin': STAGE / 'derod', 'rpc': SHADOW_RPC, 'ports': (20102, 20100, 21011),
                           'via': f'{lan}:11011'}}
    # NETWORK mode, when the live node is not running (the operator stopped it during Round 15's first run and both
    # shadows lost their only peer): the CONTROL syncs from the public network and becomes the reference; the
    # CANDIDATE syncs only from the control over loopback. It still executes every block itself, so its treehash is
    # independent; the comparison is candidate vs the build that is running in production.
    ref_rpc, mode = LIVE_RPC, 'live'
    try:
        live_up = bool(rpc(LIVE_RPC, 'DERO.GetInfo'))
    except Exception:                                                       # noqa: BLE001
        live_up = False
    if not live_up:
        mode, ref_rpc = 'network', nodes['control']['rpc']
        nodes['control']['via'] = None
        nodes['candidate']['via'] = '127.0.0.1:31011'
        event('shadow', 'INFO', mode='network', why='live RPC not answering: control syncs from the network, '
                                                    'candidate from the control')
    for name, n in nodes.items():
        d = base / name
        (d / 'data').mkdir(parents=True)
        t0 = time.time()
        bad = clone_datadir(d / 'data' / 'mainnet')
        if bad:
            event('shadow', 'FAIL', why=f'APFS clone failed for {name}', err=bad)
            finish(9)
        try:
            live_h = (rpc(LIVE_RPC, 'DERO.GetInfo') or {}).get('topoheight')
        except Exception:                                                   # noqa: BLE001
            live_h = None                                  # network mode: the live node is not running
        event('shadow', 'INFO', node=name, cloned_in_s=round(time.time() - t0, 1), at_live_height=live_h)
        exe = d / 'derod'                                  # its log file lands next to it: <exe>.log
        shutil.copy2(n['bin'], exe)
        r, g, p = n['ports']
        n['cmd'] = [str(exe), f'--data-dir={d / "data"}', f'--rpc-bind=127.0.0.1:{r}', f'--getwork-bind=127.0.0.1:{g}',
                    f'--p2p-bind=127.0.0.1:{p}', f'--node-tag=shadow-{name}',
                    # peers deduplicate by IP and the live node already holds every reachable peer from this
                    # host, so a second node here gets none (first run: 0 peers). Sync from the live node over
                    # loopback; each shadow still executes every block itself, so its treehash is independent.
                    *([f'--add-exclusive-node={n["via"]}'] if n['via'] else [])]
        n['proc'] = subprocess.Popen(n['cmd'], cwd=str(d), stdin=subprocess.PIPE,
                                     stdout=open(d / 'console.txt', 'w'), stderr=subprocess.STDOUT)
        n['dir'] = d
    def start(name, n):
        n['proc'] = subprocess.Popen(n['cmd'], cwd=str(n['dir']), stdin=subprocess.PIPE,
                                     stdout=open(n['dir'] / 'console.txt', 'w'), stderr=subprocess.STDOUT)

    def stop(n):
        try:
            n['proc'].stdin.write(b'exit\n')
            n['proc'].stdin.flush()
            n['proc'].wait(timeout=60)
        except Exception:                                                   # noqa: BLE001
            n['proc'].kill()

    # warm-up: a clone that still caught a ragged edge answers GetInfo with a recovered panic; re-clone it once
    for name, n in nodes.items():
        for attempt in (1, 2):
            healthy = False
            for _ in range(12):
                time.sleep(5)
                try:
                    if rpc(n['rpc'], 'DERO.GetInfo'):
                        healthy = True
                        break
                except Exception:                                           # noqa: BLE001
                    pass
            if healthy:
                event('shadow', 'INFO', node=name, warmup='GetInfo healthy', attempt=attempt)
                break
            event('shadow', 'INFO', node=name, warmup='GetInfo not healthy after 60 s; re-cloning',
                  detail=str(LAST_RPC_ERROR.get(n['rpc'], ''))[:160], attempt=attempt)
            stop(n)
            if attempt == 2:
                event('shadow', 'FAIL', why=f'{name}: clone unhealthy twice', detail=str(LAST_RPC_ERROR.get(n['rpc'], ''))[:300])
                finish(9)
            shutil.rmtree(n['dir'] / 'data', ignore_errors=True)
            bad = clone_datadir(n['dir'] / 'data' / 'mainnet')
            if bad:
                event('shadow', 'FAIL', why=f're-clone failed for {name}', err=bad)
                finish(9)
            start(name, n)

    samples, compared, mism = [], 0, []
    per_node = {k: 0 for k in nodes}
    probes = None
    deadline = time.time() + seconds
    try:
        while time.time() < deadline:
            time.sleep(10)
            for name, n in nodes.items():
                if n['proc'].poll() is not None:
                    event('shadow', 'FAIL', why=f'{name} derod exited with {n["proc"].returncode}',
                          console=(n['dir'] / 'console.txt').read_text(errors='replace')[-600:])
                    finish(9)
            # each node is sampled on its own: a node that fails to answer must not hide the other's comparison
            # (2026-10-21: a broken candidate made every sample skip, and the control's comparisons were lost)
            try:
                L = rpc(ref_rpc, 'DERO.GetInfo')
            except Exception as e:                                          # noqa: BLE001
                L = None
            if not L:
                samples.append({'t': now(), 'error': f'reference ({mode}) did not answer'})
                continue
            got, errs = {}, {}
            for k, n in nodes.items():
                try:
                    v = rpc(n['rpc'], 'DERO.GetInfo')
                except Exception as e:                                      # noqa: BLE001
                    v, LAST_RPC_ERROR[n['rpc']] = None, str(e)
                if v:
                    got[k] = v
                else:
                    errs[k] = str(LAST_RPC_ERROR.get(n['rpc'], ''))[:200]
            rec = {'t': now(), 'live': [L['topoheight'], L['treehash']], **({'errors': errs} if errs else {}),
                   **{k: [v['topoheight'], v['treehash'], v['outgoing_connections_count']] for k, v in got.items()}}
            for k, v in got.items():
                if mode == 'network' and k == 'control':      # the control IS the reference in network mode
                    continue
                if v['topoheight'] == L['topoheight']:
                    compared += 1
                    per_node[k] += 1
                    if v['treehash'] != L['treehash']:
                        mism.append({'node': k, **rec})
            kk = min([L['topoheight']] + [v['topoheight'] for v in got.values()]) - 3
            try:
                hl = rpc(ref_rpc, 'DERO.GetBlockHeaderByTopoHeight', {'topoheight': kk})['block_header']['hash']
                hs = {k: rpc(nodes[k]['rpc'], 'DERO.GetBlockHeaderByTopoHeight', {'topoheight': kk})['block_header']['hash']
                      for k in got}
                rec['block'] = [kk, all(h == hl for h in hs.values())]
                if not rec['block'][1]:
                    mism.append(rec)
            except Exception:                                               # noqa: BLE001
                pass
            samples.append(rec)
            if len(samples) == 12 and probes is None:     # two minutes in: both shadows have settled
                probes = feature_probes(nodes)
                event('shadow', 'INFO', probes=probes)
            if len(samples) % 6 == 0:
                event('shadow', 'INFO', live=rec['live'][0], control=rec.get('control', ['-'])[0],
                      candidate=rec.get('candidate', ['-'])[0], per_node=dict(per_node), mismatches=len(mism),
                      **({'errors': errs} if errs else {}))
        if probes is None:                                # a short run: probe before the nodes are stopped
            probes = feature_probes(nodes)
            event('shadow', 'INFO', probes=probes)
    finally:
        for name, n in nodes.items():
            try:
                n['proc'].stdin.write(b'exit\n')
                n['proc'].stdin.flush()
                n['proc'].wait(timeout=60)
            except Exception:                                               # noqa: BLE001
                n['proc'].send_signal(signal.SIGINT)
                try:
                    n['proc'].wait(timeout=30)
                except Exception:                                           # noqa: BLE001
                    n['proc'].kill()
    cen = {k: _census(n['dir'] / 'derod.log') for k, n in nodes.items()}
    # a regression is a class the candidate logs that the control does not
    # (V(1) INFO lines are written as level DEBUG by zap; only ERROR/WARN classes can be regressions)
    regress = {k: v for k, v in cen['candidate']['census'].items()
               if k not in cen['control']['census'] and k.startswith(('ERROR', 'WARN'))}
    caught_up = [x for x in samples[-6:] if 'candidate' in x and abs(x['candidate'][0] - x['live'][0]) <= 2]
    (HARNESS / f'runtime/shadow_{TS}.json').write_text(json.dumps(
        {'captured': now(), 'mode': mode, 'cmds': {k: n['cmd'] for k, n in nodes.items()}, 'seconds': seconds,
         'treehash_compared': compared, 'mismatches': mism, 'census': cen, 'regressions': regress,
         'samples': samples}, indent=1))
    # every node must have been compared on its own: a stuck candidate cannot pass on the control's comparisons
    need = ['candidate'] if mode == 'network' else list(per_node)
    ok = all(per_node[k] >= 6 for k in need) and not mism and caught_up and not regress and \
        cen['candidate']['other_panics'] == 0 and bool(probes and probes.get('candidate_ok'))
    if ok:
        shutil.rmtree(base, ignore_errors=True)
    else:
        # keep the evidence: the first failed run deleted both shadows' logs and the stacks with them
        for k, n in nodes.items():
            first = next((l for l in (n['dir'] / 'derod.log').read_text(errors='replace').splitlines()
                          if '"Recovered' in l), '') if (n['dir'] / 'derod.log').exists() else ''
            cen[k]['first_recovered'] = first[:3000]
        (HARNESS / f'runtime/shadow_{TS}.json').write_text(json.dumps(
            {'captured': now(), 'cmds': {k: n['cmd'] for k, n in nodes.items()}, 'kept': str(base),
             'treehash_compared': compared, 'mismatches': mism, 'census': cen, 'regressions': regress,
             'samples': samples}, indent=1))
    if not ok:
        event('shadow', 'FAIL', per_node=per_node, probes=probes, treehash_compared=compared, mismatches=len(mism), caught_up=bool(caught_up),
              regressions=regress, census=cen)
        finish(9)
    blocks_ok = sum(1 for x in samples if x.get('block', [0, False])[1])
    event('shadow', 'PASS', mode=mode, per_node=per_node, probes=probes, treehash_compared=compared, blocks_compared=blocks_ok, mismatches=0,
          clone_artifacts={k: v['clone_artifacts'] for k, v in cen.items()},
          candidate_census=cen['candidate']['census'], regressions=0, record=f'harness/runtime/shadow_{TS}.json')


# R21: the paths this pipeline itself writes before S4 builds (event logs, gomut/shadow records, PIPELINE_LAST). Go
# stamps vcs.modified=true for ANY uncommitted or untracked file, so without this the F7 gate refused every pipeline build.
PIPELINE_OUTPUT_PREFIXES = ('harness/loop/', 'harness/runtime/')


def porcelain_paths(out):
    """`git status --porcelain` text -> the paths it names (rename targets included). Pure."""
    paths = []
    for line in out.splitlines():
        if len(line) > 3:
            paths.append(line[3:].split(' -> ')[-1].strip().strip('"'))
    return paths


def build_provenance(version_m, head, dirty_paths=None):
    """r21 merge (F7): (ok, why) for one binary's `go version -m` output. The live r20 binaries said
    vcs.revision=e1bae2c vcs.modified=true while HEAD was 3ed6e8f: what ran was not any commit. An installed build must
    come from a committed tree whose revision is HEAD. dirty_paths (S4's `git status` at build time) may excuse
    vcs.modified=true only when every dirty path is this pipeline's own output. Pure, so the KAT can feed it text."""
    rev = re.search(r'^\s*build\s+vcs\.revision=([0-9a-f]+)\s*$', version_m, re.M)
    mod = re.search(r'^\s*build\s+vcs\.modified=(true|false)\s*$', version_m, re.M)
    if not rev or not mod:
        return False, 'no vcs stamp in the binary (built outside git, or with -buildvcs=false)'
    if mod.group(1) != 'false' and not (dirty_paths is not None and
                                        all(p.startswith(PIPELINE_OUTPUT_PREFIXES) for p in dirty_paths)):
        return False, f'built from a modified tree (vcs.revision={rev.group(1)[:7]}, vcs.modified=true): commit first'
    if not head or not rev.group(1).startswith(head) and not head.startswith(rev.group(1)):
        return False, f'built from {rev.group(1)[:7]}, but HEAD is {head[:7] if head else None}'
    return True, None


def s6_install():
    event('install', 'START')
    rc, head, _ = sh(['git', 'rev-parse', 'HEAD'], timeout=60)
    prov = {}
    for name in BINARIES:
        _, vm, ve = sh(['go', 'version', '-m', str(STAGE / name)], timeout=60)
        prov[name] = build_provenance(vm + ve, head.strip(), BUILD_DIRTY)
    if not all(ok for ok, _ in prov.values()):
        event('install', 'FAIL', why='staged binaries are not a clean build of HEAD (r21 F7)',
              provenance={k: w for k, (ok, w) in prov.items() if not ok})
        finish(11)
    done = {}
    for name in BINARIES:
        cur, new = BIN / name, STAGE / name
        old_tag = re.search(rb'STARGATE\+(\d{8}(?:\.r\d+[a-z]?)?)', cur.read_bytes()).group(1).decode() \
            if cur.exists() else 'none'
        bak = BIN / f'{name}.{old_tag}-backup'           # named by the build it replaces, so every round keeps its own
        # r23c: the tag kept no letter suffix (r23b read as 'r23'), so the r23 backup already existed and r23b was
        # replaced with no copy; the suffix is now part of the tag.
        if cur.exists() and not bak.exists():
            shutil.copy2(cur, bak)
        os.replace(new, cur)                               # atomic rename; a running process keeps the old inode
        done[name] = {'installed': str(cur.relative_to(ROOT)), 'backup': str(bak.relative_to(ROOT))}
    rc, out, err = sh([str(BIN / 'derod'), '--version'], timeout=60)
    event('install', 'PASS', binaries=done, derod_version=(out + err).strip().splitlines()[-1:] if (out + err).strip() else '')


# R21: the intel steps whose ALERT exit the gates judge. Before R21 ANY non-zero exit of these was waved through, so a
# crash (rc 1) or 'no miner log' (rc 2, nothing written) left the PREVIOUS snapshot in place and G14/G17/G18 judged
# that one (< 24 h old) as if it were this run's. Now: only the listed codes pass, and the step must have written a
# NEW snapshot. run_gates exits 3 when a gate fails; the gate rows are then judged below.
JUDGED = {'datadir_intel': ((0, 6), 'datadir_*.json'), 'miner_intel': ((0, 7), 'minerintel_*.json'),
          'miner_runs': ((0,), 'minerruns_*.json'),                # R23: exit 0 AND a new snapshot (G21 judges it)
          'metrics_intel': ((0, 2, 7), 'metrics_*.json'), 'run_gates': ((0, 3), None),
          # r24: exit 5 = an OBSERVED detector (a rule violation seen on the chain, e.g. v2-remnant peers): the capture is
          # still valid evidence and G26 judges it; any other code, or no new capture text, fails the step
          'consensus_intel': ((0, 5), 'consensus_capture_*.txt'),
          'peer_intel': ((0,), 'peer_capture_*.jsonl')}          # r24: exit 0 AND a new pseudonymised capture (G27)


def judged_step(step, rc, before, after):
    """(ok, why) for one S7 step: `before`/`after` are the (name, mtime) of the snapshots matching its pattern before
    and after it ran (a rewrite within the same second still counts as new). A step outside JUDGED must exit 0. Pure, so the KAT can feed it the r20 failure shapes."""
    # r24 (integration): match the step's SCRIPT name, not a substring: 'harness/kat/test_consensus_intel_r24.py'
    # contains 'consensus_intel' and was judged as the intel step (pipeline_20261102T214848 FAIL)
    key = next((k for k in JUDGED if Path(str(step).split()[0]).stem == k), None)
    if key is None:
        return rc == 0, None if rc == 0 else f'exit {rc}'
    codes, pat = JUDGED[key]
    if rc not in codes:
        return False, f'{key} exited {rc} (allowed {codes}): it crashed or found nothing, and the gates would judge an old snapshot'
    if pat and not (set(after) - set(before)):
        return False, f'{key} exited {rc} but wrote no new {pat}: the gates would judge an old snapshot'
    return True, None


def s7_project():
    event('project', 'START')
    steps = [[sys.executable, 'harness/intel/log_intel.py', '--json-only'],
             [sys.executable, 'harness/intel/datadir_intel.py'],
             [sys.executable, 'harness/intel/miner_intel.py', '--json-only'],
             [sys.executable, 'harness/intel/run_ledger.py'],          # R21: after miner_intel (it backfills from its snapshots)
             # R22: the miner's OWN run ledger, validated (L1-L8) and joined with derod and the chain; exit 6 = a check failed
             [sys.executable, 'harness/intel/miner_runs.py'],
             [sys.executable, 'harness/intel/metrics_intel.py', '--json-only'],
             [sys.executable, 'harness/intel/consensus_intel.py', '--json-only'],   # r24: chain-consensus observatory (G26), before area_intel reads it
             # r24 (consensus-network): the pseudonymised network-peer observatory (G27); before area_intel, whose
             # 'peers' area reads harness/runtime/peer_intel.json
             [sys.executable, 'harness/intel/peer_intel.py', '--live'],
             [sys.executable, 'harness/intel/area_intel.py', '--live']]   # r24: per-area scorecards + proposals (G23)
    # the stand-alone KAT files (harness/kat/test_*.py): before R19 test_guard_build_inputs.py existed but no stage ran it
    steps += [[sys.executable, str(p.relative_to(ROOT))] for p in sorted((HARNESS / 'kat').glob('test_*.py'))]
    steps += [[sys.executable, 'harness/prep_corpus.py']]
    steps += [[sys.executable, f'harness/miners/mine_{m}.py'] for m in
              ('inventory', 'consts', 'flows', 'logbridge', 'localdiff', 'evolution', 'findings', 'press', 'forensics', 'intel', 'areas', 'consensus', 'peers')]   # r23c: evolution (git); r24: consensus observatory rows; r24: peers (mine_peers.py)
    steps += [[sys.executable, 'harness/miners/mine_runtime.py', '--capture'],
              [sys.executable, 'harness/miners/mine_triage.py', '--capture'],
              [sys.executable, 'harness/miners/mine_coverage.py'],         # last: it reads every other raw file
              [sys.executable, 'harness/gen_deroarch.py', 'build'],
              [sys.executable, 'harness/kit/retrofit.py', 'apply', 'harness/model/evidence/release151-migration-report.json'],
              [sys.executable, 'harness/kat/verify_deroarch.py', '--mutations']]
    # r24: the current round's ledger page renders the Areas and Disclosure-track sections from area_intel.json and the
    # track at render time, and this S7 rewrote area_intel.json (step 1): re-render it BEFORE run_gates, so G25 and the
    # coherence step compare it with the scorecard of THIS run (found by G25: ledger 'docs WATCH' vs scorecard 'docs OK';
    # re-rendering after run_gates still failed G25, which runs inside run_gates).
    _lm = re.fullmatch(r'r(\d+)', str(CUR_ROUND.get('id') or ''))
    if _lm and (ROOT / f'artifacts/dero-r1-r{_lm.group(1)}.html').exists():
        steps += [[sys.executable, 'artifacts/src/gen_ledger.py', '--last', _lm.group(1), f'artifacts/dero-r1-r{_lm.group(1)}.html']]
    steps += [[sys.executable, 'harness/run_gates.py', f'pipeline-{TS}'],
              [sys.executable, 'harness/gen_index.py'],
              # r24: the full cross-artifact coherence check (G25's set plus the index page gen_index just wrote); a
              # drift exits 4 and fails S7 like any other step (record: harness/runtime/coherence_last.json)
              [sys.executable, 'harness/intel/coherence.py', '--record']]
    for st in steps:
        key = next((k for k in JUDGED if Path(st[1]).stem == k), None)   # r24: the script's own name (see judged_step)
        pat = JUDGED[key][1] if key else None
        before = [(p.name, p.stat().st_mtime_ns) for p in (HARNESS / 'runtime').glob(pat)] if pat else []
        rc, out, err = sh(st, timeout=2400)
        after = [(p.name, p.stat().st_mtime_ns) for p in (HARNESS / 'runtime').glob(pat)] if pat else []
        last = (out + err).strip().splitlines()[-1:] if (out + err).strip() else []
        event('project', 'INFO', step=' '.join(st[1:3]), rc=rc, last=last)
        ok_step, why = judged_step(st[1], rc, before, after)
        if not ok_step:
            event('project', 'FAIL', step=' '.join(st[1:3]), why=why, tail=(out + err)[-800:])
            finish(10)
    kat = json.loads((HARNESS / 'loop/KAT_LAST.json').read_text())
    gl = [l for l in (HARNESS / 'loop/GATES.md').read_text().splitlines() if f'pipeline-{TS}' in l]
    # r24: a PAUSED row counts only for G17/G18/G21 while the miner track is paused (kit/roundtracks.gate_tally)
    if RT:
        passed, paused, failing = RT.gate_tally(gl, MINER_TRACK[0])
    else:
        passed, paused, failing = sum(1 for l in gl if '| PASS |' in l), 0, [l.split('|')[3].strip() for l in gl if '| PASS |' not in l]
    ok = kat['ok'] == kat['total'] and kat['mut_proved'] == kat['muts'] and passed + paused == len(gl) and not failing and gl
    event('project', 'PASS' if ok else 'FAIL', kats=f"{kat['ok']}/{kat['total']}",
          mutations=f"{kat['mut_proved']}/{kat['muts']}", gates=f'{passed}/{len(gl)}' + (f' (+{paused} PAUSED, miner)' if paused else ''),
          failing=failing)
    if not ok:
        finish(10)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--shadow-seconds', type=int, default=1200)
    ap.add_argument('--no-install', action='store_true')
    ap.add_argument('--project-only', action='store_true', help='only S7: re-project and gate the installed state')
    ap.add_argument('--new-tests-base', default=None,
                    help='S3a: tests added since this revision are re-run -count=3 (r23c: default = harness/round.json '
                         'rounds[current].new_tests_base, else HEAD)')
    ap.add_argument('--benchlock', default=os.environ.get('DERO_BENCHLOCK'),
                    help='machine-wide lock file every bench holds (the one benchlock.py uses); env DERO_BENCHLOCK')
    ap.add_argument('--no-benchlock', action='store_true', help='S4b runs unlocked on purpose (otherwise a missing lock fails it)')
    ap.add_argument('--gpu-bench', action='store_true', help='S4c: bench the staged Swift server against the installed one on the real GPU')
    ap.add_argument('--no-gpu-bench', action='store_true', help='S4c: the Swift server changed but its GPU side is not benched, on purpose')
    ap.add_argument('--gpu-bench-only', action='store_true', help='R23: run S4c alone (implies --gpu-bench): the GPU path end to end')
    ap.add_argument('--contended-ok', action='store_true', help='R23: a contended (REFUSED) A/B is recorded and the run goes on')
    ap.add_argument('--soundness-only', action='store_true', help='R23b: S1 + S3s alone (records harness/loop/SOUNDNESS_LAST.json)')
    a = ap.parse_args()
    global BENCH_LOCK, NEW_TESTS_BASE, NO_BENCHLOCK, GPU_BENCH, CONTENDED_OK
    CONTENDED_OK = a.contended_ok
    if a.gpu_bench_only:
        a.gpu_bench = True
    GPU_BENCH = 'run' if a.gpu_bench else ('off' if a.no_gpu_bench else None)
    BENCH_LOCK = a.benchlock
    NO_BENCHLOCK = a.no_benchlock
    NEW_TESTS_BASE, base_src = resolve_new_tests_base(a.new_tests_base, CUR_ROUND)
    EVENTS.parent.mkdir(parents=True, exist_ok=True)
    event('run', 'BEGIN', events=str(EVENTS.relative_to(ROOT)),
          round=CUR_ROUND.get('id') or 'no registry', new_tests_base=NEW_TESTS_BASE, new_tests_base_from=base_src,  # r23c
          miner_track=MINER_TRACK[0], miner_track_why=MINER_TRACK[1])                                            # r24
    SUMMARY['tracks'] = {'miner': MINER_TRACK[0], 'why': MINER_TRACK[1]}
    if ROUND_REG:                                                       # r23c: a broken registry stops the run
        rerr, rwarn = round_problems(ROUND_REG, version_suffix_of((ROOT / 'config/version.go').read_text()),
                                     lambda v: sh(['git', 'rev-parse', '--verify', '-q', f'{v}^{{commit}}'], timeout=60)[0] == 0)
        if rerr:
            event('round', 'FAIL', errors=rerr, warnings=rwarn)
            finish(2)
        event('round', 'INFO', warnings=rwarn)
    if a.project_only:
        SUMMARY['mode'] = 'project-only'
        s1_guard()
        s7_project()
        finish(0)
    if a.soundness_only:
        SUMMARY['mode'] = 'soundness-only'
        s1_guard()
        s3s_soundness()
        finish(0)
    if a.gpu_bench_only:
        SUMMARY['mode'] = 'gpu-bench-only'
        s4c_gpubench()
        finish(0)
    s1_guard()
    s2_format()
    s3a_flaky()
    s3_test()
    s3s_soundness()
    s3k_kats()
    s3b_mutate()
    s3c_race()
    s4_build()
    s4b_miner()
    s4c_gpubench()
    s5_shadow(a.shadow_seconds)
    if a.no_install:
        event('install', 'SKIP', why='--no-install')
    else:
        s6_install()
    s7_project()
    finish(0)


if __name__ == '__main__':
    main()
