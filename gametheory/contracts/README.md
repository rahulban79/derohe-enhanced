# Game-theory smart contracts for DERO HE: write, test, deploy, use

This folder holds the DVM-BASIC contracts of the game-theory track (design and decisions: the game-theory rft,
`artifacts/dero-game-theory-rft.md` in the source tree; mechanism rules: `gametheory/mechanisms.json`). This README is
a complete tutorial: how contracts like these are written, tested in the DVM simulator, priced, installed on a DERO
chain, called, and read back, plus each contract's rules and its security-audit status.

> **Status and risk.** These contracts move real DERO when used on mainnet. Read the audit section first. Install
> only the current code from this folder; the R32 deployments of `gt_attest`, `gt_service`, `gt_prize` and `gt_audit`
> predate the R33 security fixes and must not be used or funded (every R32 instance can be re-initialised by anyone,
> audit finding GT-A01). Nothing here promises a return: a game pays what its contract rules and the other players'
> deposits pay, and the block reward itself is unchanged by any contract.

---

## 1. The contracts

| File | Mechanism | What it does | Public entrypoints |
|---|---|---|---|
| `gt_pool.bas` | M5 verified mining pool (R33) | credits miniblocks a member really mined, checked in the contract against the block's own bytes; pays per epoch from sponsor deposits and entry fees; part of every inflow is burned (locked forever) | `Initialize`, `SetMcount`, `Register`, `Fund`, `Anchor`, `Lock`, `Unlock`, `ProveBlock`, `ProveParent`, `Claim`, `Rollover` |
| `gt_beacon.bas` | M6 discovery beacon (R33) | the operator publishes the live games and measured figures with their height ranges; anyone may subscribe; holds no DERO | `Initialize`, `Publish`, `Subscribe`, `Unsubscribe` |
| `gt_attest.bas` | M1 bonded mining attestation (R32, fixed R33) | a miner claims miniblocks with a bond; anyone may challenge; staked jurors decide by commit-reveal; superseded for mining credit by `gt_pool` | `Initialize`, `SetParams`, `Freeze`, `Claim`, `Challenge`, `Stake`, `Unstake`, `CommitVote`, `RevealVote`, `Finalize`, `ClaimJuror`, `WithdrawTreasury` |
| `gt_service.bas` | M2 notary service with a fee rebate (R32, fixed R33) | pays a bounded rebate to fee payers of an epoch; a token boost | see `gametheory/mechanisms.json` M2 |
| `gt_prize.bas` | M3 no-loss prize rounds (R32, fixed R33) | entrants deposit a principal, commit a number, reveal it; one weighted draw wins the sponsor prize; every principal is returned | see `gametheory/mechanisms.json` M3 |
| `gt_audit.bas` | M4 audit bounty (R32a, fixed R33) | pays independent nodes that re-derive a public chain fact the sponsor committed to; a disagreement marks the round disputed and refunds everyone | see `gametheory/mechanisms.json` M4 |

`gt_audit_commit.md` documents the exact commit preimage of `gt_audit`.

---

## 2. Writing a DVM-BASIC contract

A contract is a text file of functions. The rules below are the ones these contracts follow; each was learnt the hard
way (the rft's lessons list has the history).

```basic
Function Initialize() Uint64
10 IF EXISTS("owner") == 1 THEN GOTO 900      // run once: Initialize is a public entrypoint (audit GT-A01)
20 IF IS_ADDRESS_VALID(SIGNER()) == 0 THEN GOTO 900   // no anonymous owner (ring size > 2 gives a zero signer)
30 STORE("owner", SIGNER())
40 RETURN 0
900 RETURN 1
End Function

Function Deposit() Uint64
10 IF DEROVALUE() == 0 THEN GOTO 900
20 STORE("held", LOAD("held") + DEROVALUE())
30 RETURN 0
900 RETURN 1
End Function
```

- **Entry points** start with an upper-case letter; lower-case functions are private helpers callable only from the
  contract itself (`pget`, `credit`, `pproc` in `gt_pool.bas`).
- **Every line is numbered**, and **`IF` takes only `THEN GOTO <line>`** (optionally `ELSE GOTO`). `IF c THEN LET ...`
  is not DVM-BASIC.
- **`RETURN 0` commits, any other value reverts**: every `STORE` and every `SEND_DERO_TO_ADDRESS` of the call is
  discarded, and the caller's deposit is not kept by the contract.
- **Arithmetic is unsigned 64-bit and wraps silently**; division by zero reverts. Bound every owner-set parameter so
  no product can wrap (GT-A15), and check sums before subtracting.
- **`LOAD` of a missing key reverts**: test with `EXISTS` first.
- **`&&` and `||` evaluate both sides.**
- **`SIGNER()` is the caller's raw 33-byte key**, not an address string: hash it directly (`SHA3256(SIGNER())`).
  `ADDRESS_RAW(SIGNER())` returns the empty string. Use `ADDRESS_STRING(SIGNER())` when an address text is needed
  (it is always the mainnet form).
- **`DEROVALUE()`** is the DERO the caller sent with this call. Refuse a deposit wherever none is expected, or it is
  owned by nobody (GT-A13).
- **Limits per call:** 10,000,000 compute gas, 2,000 interpreted lines, and a storage-gas limit equal to the
  transaction fee (at most 20,000). Loops must be bounded by a small constant; tally at write time instead of
  scanning at settle time (GT-A03).
- **Randomness:** `RANDOM()` is derived from the contract id, block id and tx id, so the block producer can grind it.
  The prize contract draws from the entrants' own commit-reveal seeds instead.
- **Commit-reveal:** bind every commit to the committer (`... + ":" + ADDRESS_STRING(SIGNER())`), or another player can
  copy it (GT-A08).
- **No code updates:** none of these contracts calls `UPDATE_SC_CODE`; their rules are fixed once installed.

---

## 3. Testing in the DVM simulator (no chain needed)

The DVM has an in-process simulator (`dvm/simulator.go`). The tests in `dvm/` install a contract, create signers, set
the block height, call entrypoints with deposits, and check every DERO the contract sends and holds:

```bash
go test ./dvm/ -run 'R32GT|R32aAudit|R33' -count=1 -v
```

- `dvm/r32_gametheory_test.go` has the harness (`gtNew`, `install`, `call`, `must`, `mustFail`, `at`, `read`, `held`).
- `dvm/r33_audit_test.go` holds one regression test per audit finding and one conservation test per contract.
- `dvm/r33_pool_test.go` proves `gt_pool` with real mainnet blocks (`dvm/testdata/r33_mainnet_blocks.json`).
- `dvm/r33_blockproof_test.go` shows the block-proof technique on its own.

A simulator caveat: deposits are credited to the contract but not debited from the sender, so the tests count what
the contract **sends** and what it **holds**.

The harness also lints every contract (`harness/gametheory/gt_pipeline.py --stages implementation`): run-once
Initialize, no anonymous owner, `IF ... THEN GOTO` only, no `ADDRESS_RAW(SIGNER())`, no code update.

---

## 4. Running a node and a wallet

1. Build: `go build -o bin/ ./cmd/derod ./cmd/dero-wallet-cli ./cmd/dero-miner` (the repository README has the full
   build section).
2. Run a node (`bin/derod`; `--testnet` for the test network). Its JSON-RPC answers on port 10102 (mainnet) and is
   what explorers and the commands below read.
3. Open a wallet with its RPC server on a loopback port you choose:

```bash
bin/dero-wallet-cli --wallet-file <your wallet file> --rpc-server --rpc-bind=127.0.0.1:<wallet port>
```

Every JSON-RPC request needs the header `Content-Type: application/json`. A new wallet must be registered on the
chain before it can send (the wallet does this; it costs no DERO, only a short proof of work).

---

## 5. Estimating gas

Ask the node before sending; the estimate runs the call on a snapshot and changes nothing:

```bash
curl -s -H 'Content-Type: application/json' http://127.0.0.1:10102/json_rpc -d '{
  "jsonrpc":"2.0","id":1,"method":"DERO.GetGasEstimate","params":{
    "sc_rpc":[{"name":"SC_ACTION","datatype":"U","value":0},
              {"name":"SC_ID","datatype":"H","value":"<scid>"},
              {"name":"entrypoint","datatype":"S","value":"Anchor"}],
    "transfers":[], "signer":"<your address>"}}'
```

`SC_ACTION` 0 is a call and `SC_ID` names the contract (the wallet adds both itself when it sends; the estimator needs
them given). The answer has `gascompute` and `gasstorage`. The storage gas is paid by the fee: set `fees` on the
transfer to at least the storage gas (the playbooks use 1.3 × the estimate + 100, at least 600, at most 20,000).

---

## 6. Installing a contract

The wallet's `transfer` method installs code given as base64 in `sc`, with ring size 2 (so the contract sees the
installer as `SIGNER()` and `Initialize` can record the owner):

```bash
CODE=$(base64 < gametheory/contracts/gt_pool.bas | tr -d '\n')
curl -s -H 'Content-Type: application/json' http://127.0.0.1:<wallet port>/json_rpc -d "{
  \"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"transfer\",\"params\":{
    \"sc\":\"$CODE\", \"ringsize\":2, \"transfers\":[]}}"
```

The returned `txid` **is the contract id (SCID)**. `Initialize` runs once at install. Wait until the transaction is
in a block (`DERO.GetTransaction` on the node shows its block height), then check the install with
`DERO.GetSC` (section 8). Before trusting an SCID someone gives you, read its code with `DERO.GetSC` (`"code": true`)
and compare it with the file here.

---

## 7. Calling entrypoints

The same `transfer` method calls a contract: `scid`, ring size 2, and `sc_rpc` with the entrypoint name and its
arguments (`S` string, `U` unsigned 64-bit, `H` hash). A DERO deposit is a `burn` amount in `transfers` (the
destination is any registered address; nothing is sent to it, the burn goes to the contract):

```bash
# Register in gt_pool: the deposit is exactly the entry fee (stored "fee", 1000 atomic = 0.01 DERO by default)
curl -s -H 'Content-Type: application/json' http://127.0.0.1:<wallet port>/json_rpc -d '{
  "jsonrpc":"2.0","id":1,"method":"transfer","params":{
    "scid":"<pool scid>", "ringsize":2,
    "sc_rpc":[{"name":"entrypoint","datatype":"S","value":"Register"}],
    "transfers":[{"scid":"0000000000000000000000000000000000000000000000000000000000000000","burn":1000,
                  "destination":"<any registered address>"}]}}'

# Claim epoch 3 (no deposit)
curl -s -H 'Content-Type: application/json' http://127.0.0.1:<wallet port>/json_rpc -d '{
  "jsonrpc":"2.0","id":1,"method":"transfer","params":{
    "scid":"<pool scid>", "ringsize":2, "fees": 1500,
    "sc_rpc":[{"name":"entrypoint","datatype":"S","value":"Claim"},{"name":"e","datatype":"U","value":3}],
    "transfers":[]}}'
```

The wallet also has `scinvoke` (`scid`, `sc_rpc`, `sc_dero_deposit`, `ringsize`), a shorter form for the same call.

---

## 8. Reading a contract's state

```bash
curl -s -H 'Content-Type: application/json' http://127.0.0.1:10102/json_rpc -d '{
  "jsonrpc":"2.0","id":1,"method":"DERO.GetSC","params":{"scid":"<scid>","variables":true,"code":false}}'
```

`balance` is the DERO the contract holds; `stringkeys` holds its variables. **String variables come back
hex-encoded**: decode them before comparing. Anyone can audit a contract this way at any height (`topoheight`
parameter).

---

## 9. Using gt_pool (the verified mining pool)

How a member is paid for mining, step by step:

1. **Register** (section 7) **before** you start mining with your tag. Your tag is the first 8 bytes of
   `SHA3-256(your 33-byte public key)`, as 16 hex digits. It is 8 bytes because other miners already write constant
   values into the 4-byte Flags field, and a 4-byte tag could be matched by grinding keys; 8 bytes cannot. Tags
   `0000000000000000` and `ffffffffffffffff` are refused.
2. **Mine with your tag:** `bin/dero-miner --wallet-address=<your address> --game-tag=<your 16 hex digits> ...`
   (CPU mining; refused with `--gpu`). Every miniblock you mine then carries your tag in bytes 32..39 (the Flags field
   and the first nonce word), covered by the proof of work.
3. **Anchor:** someone calls `Anchor()` (no deposit). The contract stores the id of the block the call executed in;
   only main-chain blocks execute calls.
4. **Prove:** `ProveBlock(h, hx, ntx)` with the anchored block's bytes as hex (`DERO.GetBlock` returns them as
   `blob`; `ntx` is its transaction count). The contract checks `SHA3-256(bytes)` against the stored id, then credits
   every non-final miniblock whose bytes 32..39 equal a member's tag, after checking that every miniblock carries the
   block's height. `ProveParent(h, hx, ntx)` proves the parent of a proven
   block through its single tip, so one anchor lets a whole epoch be proven. A prover is paid `pfee` (2,000 atomic)
   from the epoch pool for each block that credited a member. Proofs of an epoch are accepted until `grace` heights
   after it ends.
5. **Stake (optional):** `Lock()` with a deposit. Stake locked at least one epoch before a credited block raises that
   credit's weight by `min(100 × stake / S, 100)` %, so stake at most doubles a work share and earns nothing without
   mining. `Unlock()` returns it after `lockh` heights.
6. **Claim:** after the epoch's proof window, `Claim(e)` pays `pool × your weight / total weight`, capped at `cap` %
   of the pool per identity. Claims close 4 epochs later, when anyone may `Rollover(e)` what is left into the current
   epoch.
7. **Sponsors** fund an epoch with `Fund(e)` and a deposit. `beta` % of every deposit and entry fee is burned:
   `burned` only grows and nothing can send it, so `balance ≥ burned` always holds (check it with `DERO.GetSC`).

Defaults (fixed at install): fee 1,000 atomic, beta 20 %, epoch 400 heights, grace 100, S 100,000 atomic, cap 30 %,
pfee 2,000, lock 2,000 heights. There is no owner withdrawal. The cap limits one identity only: work split over
several registered identities is paid the same in total (the weight is linear in work), so fairness rests on the
work rule, not on the cap.

What the pool does **not** do: it cannot see or stop peer-to-peer attacks or reorgs (a reorg reverts the anchor
with its block), and it cannot raise the block reward. What it does: pays only work that ended in main-chain blocks,
publishes each proven block's timestamp and per-epoch miner concentration (`k<e>_<keyhash>`, `km<e>`, `kn<e>`), and
burns a fixed share of its inflows.

---

## 10. Using gt_beacon (discovery)

The operator calls `Publish(k, v, from, upto)`: a key (≤ 32 bytes), a value (≤ 512 bytes) and the height range the
figure was measured over (a future range is refused). Readers use `DERO.GetSC` and check each figure against block
headers and the named contracts over that range. Anyone may `Subscribe()` / `Unsubscribe()` (no deposit). The beacon
never holds or sends DERO. Its install headers `nameHdr` / `descrHdr` / `iconURLHdr` let indexers that read them show
it.

---

## 11. The playbooks (Python, no LLM)

`playbooks/` drives the whole flow against a private simulator chain or mainnet: `gt_playbook.py` (private chain:
create wallets, mine, deploy, play), `gt_earn.py` (mine to the game wallets), `gt_cycle.py` / `gt_ladder.py` (a
measured mainnet cycle), and `harness/gametheory/cycle_audit.py` (re-derive a cycle's payoffs from the chain).
Mainnet runs need an explicit `--mainnet-confirm`. They refuse to use a banned wallet address.

---

## 12. Security-audit status

- **R33 independent audit (2026-11-17)** of `gt_attest`, `gt_service`, `gt_prize`, `gt_audit`: 17 findings
  (GT-A01..A17; 2 critical, 5 high), each confirmed by a DVM proof-of-concept test. **All 17 are fixed**, each with a
  regression test (`dvm/r33_audit_test.go`) and a conservation test per contract. Remaining stated risks: any entrant
  can force an audit round into dispute (no gain); keep the prize reveal bond ≥ the prize and `maxn × fee` ≥ the
  prize; a bribed juror majority can still decide an M1 dispute.
- **`gt_pool` and `gt_beacon`** were written in R33. `gt_pool` v2 fixes four defects found by the R33 research (tag-0
  squatting, a shifted parse, a late claim after rollover, an under-priced prover fee), checks every miniblock's
  height, and uses 8-byte tags (4-byte tags were grindable against miners' constant Flags); 6 DVM tests.
- **R33 invariant verification (2026-11-17)** found 5 violations: a repeatable `Freeze` in `gt_prize` (high: it could
  rig a draw or lock principals), a silent juror or payer locking a remainder (`gt_attest`, `gt_service`), a rebate
  wrap at extreme parameters, a stray install deposit in `gt_pool`; all fixed (`Freeze` is one-time everywhere,
  `ClaimJurorFor`, `Sweep`).
- **An independent re-audit of all six current contracts is still open**: treat them as unaudited for funds you
  cannot afford to lose until it is recorded as done in the rft.
