# derod under launchd, and node checks that need no miner (r24, backlog B35)

derod had no supervisor: when it stopped, nothing started it again, and a stopped node earns nothing, relays nothing
and serves no wallet (verify-payouts PAY23c-1: 34 % of the idle miner hours overlapped derod downtime). The miner has
had `tools/launchd` since r23b; this is the same for the node. Nothing here installs anything.

## Generate the agent

```sh
go run ./tools/launchd-derod --data-dir=/abs/path/dero-data > ~/Library/LaunchAgents/io.dero.derod.plist
plutil -lint ~/Library/LaunchAgents/io.dero.derod.plist
```

- `--data-dir` is the PARENT of `mainnet/` (derod appends the network directory). The generator refuses a path that
  ends in `mainnet`/`testnet`, a relative path, and the `DATA_DIR` placeholder.
- `--log-dir` defaults to `<data-dir>/logs` (derod writes `derod.log` there); stdout/stderr go to
  `<log-dir>/derod.launchd.out`.
- `--flags` replaces the default flag set (`--rpc-bind=127.0.0.1:10102 --getwork-bind=127.0.0.1:10100
  --p2p-bind=0.0.0.0:11011 --fastsync --lowlatency`). Every flag must be one derod's usage line knows (a test keeps the
  list equal to `cmd/derod/main.go`): docopt refuses an unknown option and derod would exit and be respawned every 30 s
  for nothing. `--help`/`--version` are refused (they exit at once). `--data-dir`, `--log-dir` and
  `--integrator-address` have their own generator flags.
- `--integrator-address` is optional (dero1/deto1 checked).

## Run, restart, stop

```sh
# first stop the terminal derod (type `exit` at its prompt): two nodes cannot share one datadir or port set
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/io.dero.derod.plist   # start now and at every login
launchctl kickstart -k gui/$(id -u)/io.dero.derod                            # restart (e.g. new binary): SIGTERM, wait, start
launchctl bootout gui/$(id -u)/io.dero.derod                                 # stop
```

What derod does under launchd (cmd/derod/main.go):

- **No console.** stdin is `/dev/null`, so readline returns EOF at once and `readline_loop` blocks on
  `Exit_In_Progress` until a signal arrives; the node runs normally. (Shadow run 2026-11-02: an APFS clone of the
  mainnet datadir, stdin `/dev/null`, stdout to a file, synced and served getwork for 47 min, 40 of them to a fake getwork client.)
- **Graceful stop = SIGTERM.** `exit_on_signal` catches SIGINT and SIGTERM, requests exit and closes the console; main
  then runs `RPCServer_Stop`, `P2P_Shutdown` (peers, bans, first-relay saves) and `chain.Shutdown`.
- **ExitTimeOut** (default 120 s, `--exit-timeout`, minimum 30) is how long launchd waits after SIGTERM before SIGKILL.
  launchd's own default is 20 s; a SIGKILL skips the saves above. Measured on the clone (1 peer, 47 min up): SIGTERM to
  process exit 1.28 s, exit code 0. A node with many peers and a dirty cache can take longer, hence the margin.
- **KeepAlive** restarts derod after any exit (panic, kill, a bad log flag's exit 1), including the exit 0 that
  follows `launchctl kill TERM` (a graceful restart; `bootout` is the stop). **ThrottleInterval** 30 s bounds a crash
  loop. **ProcessType Standard, Nice 0**: `Background` would throttle the node's disk and CPU.

## Check the node (no miner needed)

```sh
go run ./tools/nodehealth                 # one line; exit 0 healthy, 1 unhealthy, 2 no answer
go run ./tools/nodehealth --json --max-tip-age=180 --min-peers=1
```

It reads `DERO.GetSyncInfo` (status synced/syncing/stalled/isolated, the TIP BLOCK's age, lag against the peers'
median, peers, recovered panics, chain fingerprint). A node without that method is read through `DERO.GetInfo` plus
`DERO.GetLastBlockHeader`, with the tip age from the tip block's own timestamp: `GetInfo`'s averageblocktime50 and
target_height said "OK" while a node was 40 days behind. Every request sends `Content-Type: application/json`; derod
answers a POST without it with an empty body (B38), and the tool names that case. Read-only.

## Exercise the getwork server (no miner needed)

```sh
go run ./tools/getworkprobe --daemon=127.0.0.1:10100 --address=<registered dero1...> --duration=10m --out=jobs.jsonl
```

A fake getwork client: it connects like a miner, records every job (receive time, height, normal/final) and never
submits a share. derod's `getwork_*` dispatch metrics move only while a session is connected, so this is how the job
dispatcher (`getwork_final_flip_l9_seconds`, `getwork_final_flip_delay_seconds`, `getwork_dead_normal_jobs_total`) is
read while the miner track is paused.
