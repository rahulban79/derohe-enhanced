/* gt_pool.bas — R33 M5: a verified mining pool (dero-game-theory-rft §8.1, D-GT-23).
   Mining for a member is CHECKED, not voted on:
   - Anchor() stores BLID() of the block the call executes in (blockchain/blockchain.go:1021 passes the executing
     block's hash), so only main-chain blocks can be anchored.
   - ProveBlock(h, hx, ntx) accepts that block's serialized bytes (hex) only if SHA3256(bytes) equals the anchored
     id (a block id is sha3.Sum256 of its bytes, block/block.go:57), then reads every miniblock (48 bytes: version 1,
     timestamp 2, height 5, past 8, keyhash 16, flags 4, nonce 12) and credits each NON-FINAL miniblock whose bytes 32..39 (Flags + the
     first nonce word) equal a member's tag. A member's tag is the first 8 bytes of SHA3256(SIGNER()) = SHA3256 of its 33-byte compressed key (ADDRESS_RAW(SIGNER()) would be "": SIGNER() is already raw, dvm/dvm_functions.go:348-352); its miner writes it with
     gt-dero-miner --game-tag (the PoW covers the tag, so it cannot be forged without the work).
   - ProveParent(h, hx, ntx) accepts the parent of a proven block h + 1 against that block's single tip, so one anchor
     per epoch covers every earlier main-chain block (R33 GT-B31; a side block is never credited).
   The tag is 8 bytes, not 4: other miners already write constant nonzero Flags (01000000..06000000 seen on mainnet
   on 2026-11-17), so a 4-byte tag could be ground (~2^32 keys) to take their credit; 8 bytes need ~2^64. Tags
   0000000000000000 and ffffffffffffffff are refused (stock miners leave Flags 0; R33 research r33_index.md).
   Rewards: epoch e = height / epochlen. Member weight per credited miniblock = 100 + boost, boost = min(100 * stake /
   S, 100) when the stake was locked at least one epoch before the credited block (stake at most doubles a work
   share; stake without mining earns nothing; splitting stake or work over addresses never gains). Claim(e) pays
   pool_e * W / TW_e, capped at cap % of pool_e per IDENTITY (an operator with several identities
   can split around it at the entry fee each; the cap protects only against one dominant identity); the excess and every remainder roll into a later epoch (Rollover); claims close when Rollover opens (4 epochs).
   Burn: beta % of every inflow (entry fees, Fund) is added to "burned", which no entrypoint sends: the contract's DERO
   balance is always >= burned (anyone checks with DERO.GetSC). There is NO owner withdrawal and no code update.
   Forensics: each proven block stores its header timestamp; per epoch the contract counts miniblocks per KeyHash
   and keeps the largest count ("km<e>") against the total ("kn<e>") as a public concentration signal.
   Every entrypoint that expects no deposit refuses one (audit GT-A13). Parameters are fixed at Initialize and bounded
   (GT-A15); Initialize runs once (GT-A01) and refuses an anonymous owner (GT-A12).
*/
Function Initialize() Uint64
10 IF EXISTS("owner") == 1 THEN GOTO 900
20 IF IS_ADDRESS_VALID(SIGNER()) == 0 THEN GOTO 900
25 IF DEROVALUE() != 0 THEN GOTO 900
30 STORE("owner", SIGNER())
40 STORE("fee", 1000)
50 STORE("beta", 20)
60 STORE("epochlen", 400)
70 STORE("grace", 100)
80 STORE("S", 100000)
90 STORE("cap", 30)
100 STORE("pfee", 2000)
110 STORE("lockh", 2000)
120 STORE("burned", 0)
130 STORE("nm", 0)
135 STORE("mcount", 10)
140 STORE("T", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f")
150 RETURN 0
900 RETURN 1
End Function

// private test chains only: a chain whose blocks carry another fixed miniblock count; owner-only, before the first
// member registers, 1..10 (mainnet keeps 10)
Function SetMcount(n Uint64) Uint64
10 IF DEROVALUE() != 0 THEN GOTO 900
20 IF LOAD("owner") != SIGNER() THEN GOTO 900
30 IF LOAD("nm") != 0 THEN GOTO 900
40 IF n == 0 THEN GOTO 900
50 IF n > 10 THEN GOTO 900
60 STORE("mcount", n)
70 RETURN 0
900 RETURN 1
End Function

// the pool of epoch e (0 when unset)
Function pget(e Uint64) Uint64
10 IF EXISTS("P" + ITOA(e)) == 1 THEN GOTO 30
20 RETURN 0
30 RETURN LOAD("P" + ITOA(e))
End Function

// add v to the pool of epoch e after taking the burn share; returns 0
Function inflow(e Uint64, v Uint64) Uint64
10 DIM burn as Uint64
20 LET burn = v * LOAD("beta") / 100
30 STORE("burned", LOAD("burned") + burn)
40 STORE("P" + ITOA(e), pget(e) + v - burn)
50 RETURN 0
End Function

// the member tag of the signer: 8 hex digits
Function mytag() String
10 RETURN HEX(SUBSTR(SHA3256(SIGNER()), 0, 8))
End Function

Function Register() Uint64
10 DIM t as String
20 IF IS_ADDRESS_VALID(SIGNER()) == 0 THEN GOTO 900
30 IF DEROVALUE() != LOAD("fee") THEN GOTO 900
40 LET t = mytag()
50 IF EXISTS("tag_" + t) == 1 THEN GOTO 900
52 IF t == "0000000000000000" THEN GOTO 900
54 IF t == "ffffffffffffffff" THEN GOTO 900
60 STORE("tag_" + t, SIGNER())
70 STORE("s_" + t, 0)
80 STORE("since_" + t, 0)
90 STORE("nm", LOAD("nm") + 1)
100 inflow(BLOCK_HEIGHT() / LOAD("epochlen"), DEROVALUE())
110 RETURN 0
900 RETURN 1
End Function

// a sponsor adds DERO to the pool of epoch e (the current one or later); beta % is burned
Function Fund(e Uint64) Uint64
10 IF DEROVALUE() == 0 THEN GOTO 900
20 IF e < BLOCK_HEIGHT() / LOAD("epochlen") THEN GOTO 900
30 IF pget(e) + DEROVALUE() > 10000000000000 THEN GOTO 900
40 inflow(e, DEROVALUE())
50 RETURN 0
900 RETURN 1
End Function

Function Anchor() Uint64
10 IF DEROVALUE() != 0 THEN GOTO 900
20 STORE("b" + ITOA(BLOCK_HEIGHT()), BLID())
30 RETURN 0
900 RETURN 1
End Function

// lock DERO as stake (topping up restarts its maturity); stake is never burned
Function Lock() Uint64
10 DIM t as String
20 IF DEROVALUE() == 0 THEN GOTO 900
30 LET t = mytag()
40 IF EXISTS("tag_" + t) == 0 THEN GOTO 900
50 IF LOAD("tag_" + t) != SIGNER() THEN GOTO 900
60 IF LOAD("s_" + t) + DEROVALUE() > 10000000000000 THEN GOTO 900
70 STORE("s_" + t, LOAD("s_" + t) + DEROVALUE())
80 STORE("since_" + t, BLOCK_HEIGHT())
90 RETURN 0
900 RETURN 1
End Function

Function Unlock() Uint64
10 DIM t as String
20 DIM s as Uint64
30 IF DEROVALUE() != 0 THEN GOTO 900
40 LET t = mytag()
50 IF EXISTS("tag_" + t) == 0 THEN GOTO 900
60 IF LOAD("tag_" + t) != SIGNER() THEN GOTO 900
70 LET s = LOAD("s_" + t)
80 IF s == 0 THEN GOTO 900
90 IF BLOCK_HEIGHT() < LOAD("since_" + t) + LOAD("lockh") THEN GOTO 900
100 STORE("s_" + t, 0)
110 SEND_DERO_TO_ADDRESS(SIGNER(), s)
120 RETURN 0
900 RETURN 1
End Function

// true when the miniblock version byte (hex) has the Final bit 0x20 (version 1, past count bits 6-7, high diff 0x10)
Function isfinal(v String) Uint64
10 IF v == "21" THEN GOTO 100
20 IF v == "31" THEN GOTO 100
30 IF v == "61" THEN GOTO 100
40 IF v == "71" THEN GOTO 100
50 IF v == "a1" THEN GOTO 100
60 IF v == "b1" THEN GOTO 100
70 IF v == "e1" THEN GOTO 100
80 IF v == "f1" THEN GOTO 100
90 RETURN 0
100 RETURN 1
End Function

// credit one miniblock (flags f) of a proven block at height h to its member; returns 1 when credited
Function credit(f String, h Uint64) Uint64
10 DIM e, wt, s as Uint64
20 DIM k as String
30 IF EXISTS("tag_" + f) == 0 THEN GOTO 200
40 LET e = h / LOAD("epochlen")
50 LET wt = 100
60 LET s = LOAD("s_" + f)
70 IF s == 0 THEN GOTO 120
80 IF LOAD("since_" + f) + LOAD("epochlen") > h THEN GOTO 120
90 LET s = 100 * s / LOAD("S")
100 IF s <= 100 THEN GOTO 110
105 LET s = 100
110 LET wt = wt + s
120 LET k = ITOA(e) + "_" + f
130 IF EXISTS("W" + k) == 1 THEN GOTO 160
140 STORE("W" + k, 0)
150 STORE("w" + k, 0)
160 STORE("W" + k, LOAD("W" + k) + wt)
170 STORE("w" + k, LOAD("w" + k) + 1)
180 IF EXISTS("TW" + ITOA(e)) == 1 THEN GOTO 190
185 STORE("TW" + ITOA(e), 0)
190 STORE("TW" + ITOA(e), LOAD("TW" + ITOA(e)) + wt)
195 RETURN 1
200 RETURN 0
End Function

// count a miniblock's KeyHash for the epoch's concentration signal
Function census(kh String, e Uint64) Uint64
10 DIM c as Uint64
20 DIM k as String
30 LET k = "k" + ITOA(e) + "_" + kh
40 LET c = 1
50 IF EXISTS(k) == 0 THEN GOTO 60
55 LET c = LOAD(k) + 1
60 STORE(k, c)
70 IF EXISTS("kn" + ITOA(e)) == 1 THEN GOTO 80
75 STORE("kn" + ITOA(e), 0)
76 STORE("km" + ITOA(e), 0)
80 STORE("kn" + ITOA(e), LOAD("kn" + ITOA(e)) + 1)
90 IF c <= LOAD("km" + ITOA(e)) THEN GOTO 110
100 STORE("km" + ITOA(e), c)
110 RETURN 0
End Function

// the 5-byte big-endian height h as 10 lowercase hex digits (the miniblock height field, block/miniblock.go:158-160)
Function hexh(h Uint64) String
10 DIM r as String
20 DIM k, x as Uint64
30 LET r = ""
40 LET x = h
50 LET k = 0
60 IF k >= 10 THEN GOTO 100
70 LET r = SUBSTR("0123456789abcdef", x % 16, 1) + r
80 LET x = x / 16
90 LET k = k + 1
95 GOTO 60
100 RETURN r
End Function

// verify block bytes b of height h against the expected id, then credit, record forensics and pay the prover;
// returns 0 on success, 1 to make the caller revert. Every parsed miniblock must carry height h in its height
// field: the bytes are authentic (their hash is the expected id), but the parse position rests on the caller's ntx;
// a shifted parse would need 10 ground 5-byte height fields, so only the true layout passes (R33 re-audit RA-P3). The miniblock count is fixed by consensus (config BLOCK_TIME -
// MINIBLOCK_HIGHDIFF + 1 = 10, blockchain/miniblocks_consensus.go:80), so a caller cannot choose a shifted parse (R33
// research: m = 7 passed both count checks on a real block). A block has exactly one tip, at height h - 1
// (blockchain/blockchain.go:490-509); it is stored so that ProveParent can walk back the main chain from one anchor.
Function pproc(h Uint64, b String, ntx Uint64, id String) Uint64
10 DIM T, v, H as String
20 DIM L, p, q, i, off, e, n, pay, m as Uint64
30 IF ntx > 127 THEN GOTO 900
40 IF SHA3256(b) != id THEN GOTO 900
50 LET m = LOAD("mcount")
60 LET L = STRLEN(b)
70 IF L <= 32 * ntx + 48 * m + 46 THEN GOTO 900
80 LET T = LOAD("T")
90 LET p = L - 32 * ntx - 1
100 IF HEX(SUBSTR(b, p, 1)) != SUBSTR(T, 2 * ntx, 2) THEN GOTO 900
110 LET q = p - 48 * m - 1
120 IF HEX(SUBSTR(b, q, 1)) != SUBSTR(T, 2 * m, 2) THEN GOTO 900
130 IF HEX(SUBSTR(b, q - 33, 1)) != "01" THEN GOTO 900
140 LET e = h / LOAD("epochlen")
150 IF BLOCK_HEIGHT() >= (e + 1) * LOAD("epochlen") + LOAD("grace") THEN GOTO 900
160 STORE("pr" + ITOA(h), 1)
170 STORE("tip" + ITOA(h), SUBSTR(b, q - 32, 32))
180 STORE("t" + ITOA(h), HEX(SUBSTR(b, 2, 8)))
185 LET H = hexh(h)
190 LET n = 0
200 LET i = 0
210 IF i >= m THEN GOTO 290
220 LET off = q + 1 + 48 * i
225 IF HEX(SUBSTR(b, off + 3, 5)) != H THEN GOTO 900
230 LET v = HEX(SUBSTR(b, off, 1))
240 IF isfinal(v) == 1 THEN GOTO 270
250 census(HEX(SUBSTR(b, off + 16, 16)), e)
260 LET n = n + credit(HEX(SUBSTR(b, off + 32, 8)), h)
270 LET i = i + 1
280 GOTO 210
290 IF n == 0 THEN GOTO 400
300 LET pay = LOAD("pfee")
310 IF pget(e) < pay THEN GOTO 400
320 STORE("P" + ITOA(e), pget(e) - pay)
330 SEND_DERO_TO_ADDRESS(SIGNER(), pay)
400 RETURN 0
900 RETURN 1
End Function

// prove a block that executed an Anchor call (its id is the stored BLID of height h)
Function ProveBlock(h Uint64, hx String, ntx Uint64) Uint64
10 IF DEROVALUE() != 0 THEN GOTO 900
20 IF h >= BLOCK_HEIGHT() THEN GOTO 900
30 IF EXISTS("b" + ITOA(h)) == 0 THEN GOTO 900
40 IF EXISTS("pr" + ITOA(h)) == 1 THEN GOTO 900
50 IF pproc(h, HEXDECODE(hx), ntx, LOAD("b" + ITOA(h))) != 0 THEN GOTO 900
60 RETURN 0
900 RETURN 1
End Function

// prove the parent (height h) of an already proven block h + 1: its id is that block's single tip, so one anchor
// lets every earlier main-chain block of the epoch be proven (a side block is never a main-chain block's tip, and
// its own transactions never execute, so it can never be credited)
Function ProveParent(h Uint64, hx String, ntx Uint64) Uint64
10 IF DEROVALUE() != 0 THEN GOTO 900
20 IF EXISTS("tip" + ITOA(h + 1)) == 0 THEN GOTO 900
30 IF EXISTS("pr" + ITOA(h)) == 1 THEN GOTO 900
40 IF pproc(h, HEXDECODE(hx), ntx, LOAD("tip" + ITOA(h + 1))) != 0 THEN GOTO 900
50 RETURN 0
900 RETURN 1
End Function

// a member claims its share of epoch e once the proof window of e has closed
Function Claim(e Uint64) Uint64
10 DIM t, k as String
20 DIM P, W, TW, amt, mx as Uint64
30 IF DEROVALUE() != 0 THEN GOTO 900
40 IF BLOCK_HEIGHT() < (e + 1) * LOAD("epochlen") + LOAD("grace") THEN GOTO 900
45 IF BLOCK_HEIGHT() >= (e + 5) * LOAD("epochlen") + LOAD("grace") THEN GOTO 900
50 LET t = mytag()
60 IF EXISTS("tag_" + t) == 0 THEN GOTO 900
70 IF LOAD("tag_" + t) != SIGNER() THEN GOTO 900
80 LET k = ITOA(e) + "_" + t
90 IF EXISTS("W" + k) == 0 THEN GOTO 900
100 IF EXISTS("c" + k) == 1 THEN GOTO 900
110 IF EXISTS("P0_" + ITOA(e)) == 1 THEN GOTO 120
115 STORE("P0_" + ITOA(e), pget(e))
120 LET P = LOAD("P0_" + ITOA(e))
130 LET W = LOAD("W" + k)
140 LET TW = LOAD("TW" + ITOA(e))
150 LET amt = P * W / TW
160 LET mx = P * LOAD("cap") / 100
170 IF amt <= mx THEN GOTO 180
175 LET amt = mx
180 STORE("c" + k, amt)
190 STORE("P" + ITOA(e), pget(e) - amt)
200 IF amt == 0 THEN GOTO 220
210 SEND_DERO_TO_ADDRESS(SIGNER(), amt)
220 RETURN 0
900 RETURN 1
End Function

// anyone moves what is left of a closed epoch e (no credits, rounding, capped excess) into the current epoch,
// once 4 epochs have passed since e's proof window closed (members had that long to claim)
Function Rollover(e Uint64) Uint64
10 DIM cur, left as Uint64
20 IF DEROVALUE() != 0 THEN GOTO 900
30 LET cur = BLOCK_HEIGHT() / LOAD("epochlen")
40 IF BLOCK_HEIGHT() < (e + 5) * LOAD("epochlen") + LOAD("grace") THEN GOTO 900
50 LET left = pget(e)
60 IF left == 0 THEN GOTO 900
65 IF pget(cur) + left > 10000000000000 THEN GOTO 900
70 STORE("P" + ITOA(e), 0)
80 STORE("P" + ITOA(cur), pget(cur) + left)
90 RETURN 0
900 RETURN 1
End Function
