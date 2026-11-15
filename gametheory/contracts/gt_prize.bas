/* gt_prize.bas -- R32 mechanism M3 "no-loss prize pool with commit-reveal draw + miner boost", DVM-BASIC.
   Round r: Enter(commit) during the commit phase with a deposit = principal + reveal bond; commit =
   HEX(SHA256(ITOA(n) + ":" + salt)). Reveal(j, n, salt) in the reveal phase adds n to the round seed.
   Draw() after the reveal phase picks one revealed entry with probability weight / total weight, where
   weight = principal, or principal * (100 + boost) / 100 while the entrant keeps >= minmat MAT staked.
   pick = seed % tw: one honest uniform n makes the seed uniform. v2 (R32 closed loop, D-GT-10): RANDOM is NOT
   used: it is keyed by the block id, so the integrator of the Draw block could withhold that block to re-roll
   the draw (cost: one integrator share, 3,075 atomic on mainnet today); without it the only bias left is the
   last revealer's reveal-or-forfeit option, bounded by rbond. The prize = sponsor funds + reveal bonds forfeited by non-revealers
   of the same round. Principal is always returned (Withdraw after the draw): no participant loses
   principal, and no payout comes from a later participant's deposit.
   Gas bound: at most maxn entries per round (the draw loop is O(n)).
*/
Function Initialize() Uint64
10 STORE("owner", SIGNER())
20 STORE("rbond", 10000)
30 STORE("commitw", 10)
40 STORE("revealw", 10)
50 STORE("maxn", 32)
60 STORE("boost", 100)
70 STORE("minmat", 100)
80 STORE("mat", "")
90 STORE("frozen", 0)
100 STORE("rd", 0)
110 STORE("rs", BLOCK_HEIGHT())
120 STORE("n0", 0)
130 STORE("prize0", 0)
140 STORE("tw0", 0)
150 STORE("sd0", 0)
160 RETURN 0
End Function

Function SetParams(rbond Uint64, commitw Uint64, revealw Uint64, maxn Uint64, boost Uint64, minmat Uint64) Uint64
10 IF LOAD("owner") != SIGNER() THEN GOTO 900
20 IF LOAD("frozen") != 0 THEN GOTO 900
30 IF commitw == 0 || revealw == 0 || maxn == 0 || maxn > 64 THEN GOTO 900
40 STORE("rbond", rbond)
50 STORE("commitw", commitw)
60 STORE("revealw", revealw)
70 STORE("maxn", maxn)
80 STORE("boost", boost)
90 STORE("minmat", minmat)
100 RETURN 0
900 RETURN 1
End Function

Function SetMAT(scidhex String) Uint64
10 IF LOAD("owner") != SIGNER() THEN GOTO 900
20 IF LOAD("frozen") != 0 THEN GOTO 900
30 IF STRLEN(scidhex) != 64 THEN GOTO 900
40 STORE("mat", HEXDECODE(scidhex))
50 RETURN 0
900 RETURN 1
End Function

Function Freeze() Uint64
10 IF LOAD("owner") != SIGNER() THEN GOTO 900
20 STORE("frozen", 1)
30 STORE("rs", BLOCK_HEIGHT())
40 RETURN 0
900 RETURN 1
End Function

Function StakeMAT() Uint64
10 DIM v, s as Uint64
20 IF STRLEN(LOAD("mat")) != 32 THEN GOTO 900
30 IF IS_ADDRESS_VALID(SIGNER()) == 0 THEN GOTO 900
40 LET v = ASSETVALUE(LOAD("mat"))
50 IF v == 0 THEN GOTO 900
60 LET s = 0
70 IF EXISTS("ms" + SIGNER()) == 0 THEN GOTO 90
80 LET s = LOAD("ms" + SIGNER())
90 STORE("ms" + SIGNER(), s + v)
100 STORE("ml" + SIGNER(), LOAD("rd"))
110 RETURN 0
900 RETURN 1
End Function

Function UnstakeMAT(amount Uint64) Uint64
10 IF EXISTS("ms" + SIGNER()) == 0 THEN GOTO 900
20 IF LOAD("rd") <= LOAD("ml" + SIGNER()) THEN GOTO 900
30 IF amount == 0 || amount > LOAD("ms" + SIGNER()) THEN GOTO 900
40 STORE("ms" + SIGNER(), LOAD("ms" + SIGNER()) - amount)
50 SEND_ASSET_TO_ADDRESS(SIGNER(), amount, LOAD("mat"))
60 RETURN 0
900 RETURN 1
End Function

Function Fund() Uint64
10 IF DEROVALUE() == 0 THEN GOTO 900
20 STORE("prize" + ITOA(LOAD("rd")), LOAD("prize" + ITOA(LOAD("rd"))) + DEROVALUE())
30 RETURN 0
900 RETURN 1
End Function

Function Enter(commit String) Uint64
10 DIM r, n, a, w as Uint64
20 DIM q as String
30 IF LOAD("frozen") == 0 THEN GOTO 900
40 IF IS_ADDRESS_VALID(SIGNER()) == 0 THEN GOTO 900
50 LET r = LOAD("rd")
60 IF BLOCK_HEIGHT() > LOAD("rs") + LOAD("commitw") THEN GOTO 900
70 LET n = LOAD("n" + ITOA(r))
80 IF n >= LOAD("maxn") THEN GOTO 900
90 IF DEROVALUE() <= LOAD("rbond") THEN GOTO 900
100 IF EXISTS("in" + ITOA(r) + SIGNER()) == 1 THEN GOTO 900
110 IF STRLEN(commit) != 64 THEN GOTO 900
120 LET a = DEROVALUE() - LOAD("rbond")
130 LET w = a
140 IF EXISTS("ms" + SIGNER()) == 0 THEN GOTO 180
150 IF LOAD("ms" + SIGNER()) < LOAD("minmat") THEN GOTO 180
160 LET w = a * (100 + LOAD("boost")) / 100
170 STORE("ml" + SIGNER(), r)
180 LET q = ITOA(r) + "_" + ITOA(n)
190 STORE("p" + q, SIGNER())
200 STORE("a" + q, a)
210 STORE("t" + q, w)
220 STORE("h" + q, commit)
230 STORE("v" + q, 0)
240 STORE("x" + q, 0)
250 STORE("in" + ITOA(r) + SIGNER(), n)
260 STORE("n" + ITOA(r), n + 1)
270 RETURN 0
900 RETURN 1
End Function

Function Reveal(j Uint64, num Uint64, salt String) Uint64
10 DIM r, t as Uint64
20 DIM q as String
30 LET r = LOAD("rd")
40 LET t = LOAD("rs") + LOAD("commitw")
50 IF BLOCK_HEIGHT() <= t THEN GOTO 900
60 IF BLOCK_HEIGHT() > t + LOAD("revealw") THEN GOTO 900
70 IF j >= LOAD("n" + ITOA(r)) THEN GOTO 900
80 LET q = ITOA(r) + "_" + ITOA(j)
90 IF LOAD("p" + q) != SIGNER() THEN GOTO 900
100 IF LOAD("v" + q) != 0 THEN GOTO 900
110 IF HEX(SHA256(ITOA(num) + ":" + salt)) != LOAD("h" + q) THEN GOTO 900
120 STORE("v" + q, 1)
130 STORE("sd" + ITOA(r), LOAD("sd" + ITOA(r)) + num)
140 STORE("tw" + ITOA(r), LOAD("tw" + ITOA(r)) + LOAD("t" + q))
150 RETURN 0
900 RETURN 1
End Function

Function Draw() Uint64
10 DIM r, n, j, tw, pick, acc, prize, forf as Uint64
20 DIM q as String
30 LET r = LOAD("rd")
40 IF LOAD("frozen") == 0 THEN GOTO 900
50 IF BLOCK_HEIGHT() <= LOAD("rs") + LOAD("commitw") + LOAD("revealw") THEN GOTO 900
60 LET n = LOAD("n" + ITOA(r))
70 LET tw = LOAD("tw" + ITOA(r))
80 LET prize = LOAD("prize" + ITOA(r))
90 LET forf = 0
100 LET j = 0
110 IF j >= n THEN GOTO 150
120 IF LOAD("v" + ITOA(r) + "_" + ITOA(j)) == 1 THEN GOTO 140
130 LET forf = forf + LOAD("rbond")
140 LET j = j + 1
145 GOTO 110
150 LET prize = prize + forf
160 STORE("forf" + ITOA(r), forf)
170 IF tw == 0 THEN GOTO 400
180 LET pick = LOAD("sd" + ITOA(r)) % tw
190 LET acc = 0
200 LET j = 0
210 IF j >= n THEN GOTO 900
220 LET q = ITOA(r) + "_" + ITOA(j)
230 IF LOAD("v" + q) == 0 THEN GOTO 260
240 LET acc = acc + LOAD("t" + q)
250 IF pick < acc THEN GOTO 300
260 LET j = j + 1
270 GOTO 210
300 STORE("win" + ITOA(r), j)
310 STORE("paid" + ITOA(r), prize)
320 SEND_DERO_TO_ADDRESS(LOAD("p" + q), prize)
330 LET prize = 0
400 STORE("drawn" + ITOA(r), 1)
410 STORE("rd", r + 1)
420 STORE("rs", BLOCK_HEIGHT())
430 STORE("n" + ITOA(r + 1), 0)
440 STORE("prize" + ITOA(r + 1), prize)
450 STORE("tw" + ITOA(r + 1), 0)
460 STORE("sd" + ITOA(r + 1), 0)
470 RETURN 0
900 RETURN 1
End Function

Function Withdraw(r Uint64, j Uint64) Uint64
10 DIM q as String
20 DIM amt as Uint64
30 IF EXISTS("drawn" + ITOA(r)) == 0 THEN GOTO 900
40 LET q = ITOA(r) + "_" + ITOA(j)
50 IF EXISTS("p" + q) == 0 THEN GOTO 900
60 IF LOAD("p" + q) != SIGNER() THEN GOTO 900
70 IF LOAD("x" + q) != 0 THEN GOTO 900
80 LET amt = LOAD("a" + q)
90 IF LOAD("v" + q) == 0 THEN GOTO 110
100 LET amt = amt + LOAD("rbond")
110 STORE("x" + q, 1)
120 SEND_DERO_TO_ADDRESS(SIGNER(), amt)
130 RETURN 0
900 RETURN 1
End Function
