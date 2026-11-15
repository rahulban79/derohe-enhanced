/* gt_attest.bas -- R32 mechanism M1 "miner-attested token" (MAT), DVM-BASIC.
   A miner claims, under its own signer (ring size 2), that its address mined k miniblocks in the
   height range [from, upto]. The claim posts a DERO bond of k * bond. The chain data that proves
   or refutes the claim is public (block headers list each miniblock's miner), but the DVM cannot
   read it, so the claim is OPTIMISTIC: anyone may challenge it inside the window by posting an
   equal bond; DERO-staked jurors then commit and reveal a vote (Schelling point). Unchallenged
   or upheld claims mint k * reward MAT (this contract's own asset) to the miner and refund the bond.
   Rules are frozen by Freeze() before the first claim (anti-rug). No payout is funded by a later
   participant's deposit: a winner is paid only from the loser's bond in the same dispute and from
   slashed stakes of incoherent jurors in the same dispute.
   Return 0 = success; any other value reverts (deposits go back to a known signer).
*/
Function Initialize() Uint64
10 STORE("owner", SIGNER())
20 STORE("bond", 100000)
30 STORE("reward", 100)
40 STORE("window", 20)
50 STORE("commitw", 10)
60 STORE("revealw", 10)
70 STORE("maxmb", 10)
80 STORE("maxspan", 1000)
90 STORE("slash", 10)
100 STORE("minstake", 100000)
110 STORE("maxstake", 1000000000)
120 STORE("frozen", 0)
130 STORE("nc", 0)
140 STORE("minted", 0)
150 RETURN 0
End Function

Function SetParams(bond Uint64, reward Uint64, window Uint64, commitw Uint64, revealw Uint64, maxmb Uint64, slash Uint64, minstake Uint64) Uint64
10 IF LOAD("owner") != SIGNER() THEN GOTO 900
20 IF LOAD("frozen") != 0 THEN GOTO 900
30 IF bond == 0 THEN GOTO 900
40 IF slash > 100 THEN GOTO 900
50 IF window == 0 || commitw == 0 || revealw == 0 || maxmb == 0 THEN GOTO 900
60 STORE("bond", bond)
70 STORE("reward", reward)
80 STORE("window", window)
90 STORE("commitw", commitw)
100 STORE("revealw", revealw)
110 STORE("maxmb", maxmb)
120 STORE("slash", slash)
130 STORE("minstake", minstake)
140 RETURN 0
900 RETURN 1
End Function

Function Freeze() Uint64
10 IF LOAD("owner") != SIGNER() THEN GOTO 900
20 STORE("frozen", 1)
30 RETURN 0
900 RETURN 1
End Function

Function Claim(from Uint64, upto Uint64, k Uint64) Uint64
10 DIM i, b as Uint64
20 DIM p as String
30 IF LOAD("frozen") == 0 THEN GOTO 900
40 IF IS_ADDRESS_VALID(SIGNER()) == 0 THEN GOTO 900
50 IF upto < from THEN GOTO 900
60 IF upto - from >= LOAD("maxspan") THEN GOTO 900
70 IF upto >= BLOCK_HEIGHT() THEN GOTO 900
80 IF k == 0 THEN GOTO 900
90 IF k > (upto - from + 1) * LOAD("maxmb") THEN GOTO 900
100 IF EXISTS("lc" + SIGNER()) == 0 THEN GOTO 120
110 IF from <= LOAD("lc" + SIGNER()) THEN GOTO 900
120 LET b = k * LOAD("bond")
130 IF DEROVALUE() != b THEN GOTO 900
140 LET i = LOAD("nc")
150 LET p = "c" + ITOA(i)
160 STORE(p + "m", SIGNER())
170 STORE(p + "f", from)
180 STORE(p + "u", upto)
190 STORE(p + "k", k)
200 STORE(p + "b", b)
210 STORE(p + "h", BLOCK_HEIGHT())
220 STORE(p + "s", 0)
230 STORE("lc" + SIGNER(), upto)
240 STORE("nc", i + 1)
250 RETURN 0
900 RETURN 1
End Function

Function Challenge(i Uint64) Uint64
10 DIM p as String
20 IF IS_ADDRESS_VALID(SIGNER()) == 0 THEN GOTO 900
30 IF i >= LOAD("nc") THEN GOTO 900
40 LET p = "c" + ITOA(i)
50 IF LOAD(p + "s") != 0 THEN GOTO 900
60 IF BLOCK_HEIGHT() > LOAD(p + "h") + LOAD("window") THEN GOTO 900
70 IF DEROVALUE() != LOAD(p + "b") THEN GOTO 900
80 IF SIGNER() == LOAD(p + "m") THEN GOTO 900
90 STORE(p + "s", 1)
100 STORE(p + "x", SIGNER())
110 STORE(p + "vh", BLOCK_HEIGHT())
120 STORE(p + "yes", 0)
130 STORE(p + "no", 0)
140 STORE(p + "cw", 0)
150 RETURN 0
900 RETURN 1
End Function

Function Stake() Uint64
10 DIM s as Uint64
20 IF IS_ADDRESS_VALID(SIGNER()) == 0 THEN GOTO 900
30 IF DEROVALUE() == 0 THEN GOTO 900
40 LET s = 0
50 IF EXISTS("st" + SIGNER()) == 0 THEN GOTO 70
60 LET s = LOAD("st" + SIGNER())
70 IF s + DEROVALUE() > LOAD("maxstake") THEN GOTO 900
80 STORE("st" + SIGNER(), s + DEROVALUE())
90 IF EXISTS("pd" + SIGNER()) == 1 THEN GOTO 110
100 STORE("pd" + SIGNER(), 0)
110 RETURN 0
900 RETURN 1
End Function

Function Unstake(amount Uint64) Uint64
10 IF EXISTS("st" + SIGNER()) == 0 THEN GOTO 900
20 IF LOAD("pd" + SIGNER()) != 0 THEN GOTO 900
30 IF amount == 0 || amount > LOAD("st" + SIGNER()) THEN GOTO 900
40 STORE("st" + SIGNER(), LOAD("st" + SIGNER()) - amount)
50 SEND_DERO_TO_ADDRESS(SIGNER(), amount)
60 RETURN 0
900 RETURN 1
End Function

Function CommitVote(i Uint64, h String) Uint64
10 DIM p as String
20 DIM w as Uint64
30 IF i >= LOAD("nc") THEN GOTO 900
40 LET p = "c" + ITOA(i)
50 IF LOAD(p + "s") != 1 THEN GOTO 900
60 IF BLOCK_HEIGHT() > LOAD(p + "vh") + LOAD("commitw") THEN GOTO 900
70 IF EXISTS("st" + SIGNER()) == 0 THEN GOTO 900
80 LET w = LOAD("st" + SIGNER())
90 IF w < LOAD("minstake") THEN GOTO 900
100 IF SIGNER() == LOAD(p + "m") || SIGNER() == LOAD(p + "x") THEN GOTO 900
110 IF EXISTS(p + "v" + SIGNER()) == 1 THEN GOTO 900
120 IF STRLEN(h) != 64 THEN GOTO 900
130 STORE(p + "v" + SIGNER(), h)
140 STORE(p + "w" + SIGNER(), w)
150 STORE(p + "cw", LOAD(p + "cw") + w)
160 STORE("pd" + SIGNER(), LOAD("pd" + SIGNER()) + 1)
170 RETURN 0
900 RETURN 1
End Function

Function RevealVote(i Uint64, vote Uint64, salt String) Uint64
10 DIM p as String
20 DIM t as Uint64
30 IF i >= LOAD("nc") THEN GOTO 900
40 LET p = "c" + ITOA(i)
50 IF LOAD(p + "s") != 1 THEN GOTO 900
60 LET t = LOAD(p + "vh") + LOAD("commitw")
70 IF BLOCK_HEIGHT() <= t THEN GOTO 900
80 IF BLOCK_HEIGHT() > t + LOAD("revealw") THEN GOTO 900
90 IF EXISTS(p + "v" + SIGNER()) == 0 THEN GOTO 900
100 IF EXISTS(p + "r" + SIGNER()) == 1 THEN GOTO 900
110 IF vote > 1 THEN GOTO 900
120 IF HEX(SHA256(ITOA(i) + ":" + ITOA(vote) + ":" + salt)) != LOAD(p + "v" + SIGNER()) THEN GOTO 900
130 STORE(p + "r" + SIGNER(), vote)
140 IF vote == 1 THEN GOTO 170
150 STORE(p + "no", LOAD(p + "no") + LOAD(p + "w" + SIGNER()))
160 RETURN 0
170 STORE(p + "yes", LOAD(p + "yes") + LOAD(p + "w" + SIGNER()))
180 RETURN 0
900 RETURN 1
End Function

Function Finalize(i Uint64) Uint64
10 DIM p as String
20 DIM b, cwin, half as Uint64
30 IF i >= LOAD("nc") THEN GOTO 900
40 LET p = "c" + ITOA(i)
50 LET b = LOAD(p + "b")
60 IF LOAD(p + "s") == 1 THEN GOTO 200
70 IF LOAD(p + "s") != 0 THEN GOTO 900
80 IF BLOCK_HEIGHT() <= LOAD(p + "h") + LOAD("window") THEN GOTO 900
90 GOTO 500
200 IF BLOCK_HEIGHT() <= LOAD(p + "vh") + LOAD("commitw") + LOAD("revealw") THEN GOTO 900
210 LET half = b / 2
220 IF LOAD(p + "no") > LOAD(p + "yes") THEN GOTO 400
230 LET cwin = LOAD(p + "yes")
240 STORE(p + "win", 1)
250 STORE(p + "cwin", cwin)
260 STORE(p + "inc", LOAD(p + "cw") - cwin)
270 IF cwin == 0 THEN GOTO 300
280 SEND_DERO_TO_ADDRESS(LOAD(p + "m"), half)
290 STORE(p + "pool", b - half)
295 GOTO 500
300 SEND_DERO_TO_ADDRESS(LOAD(p + "m"), b)
310 STORE(p + "pool", 0)
320 GOTO 500
400 LET cwin = LOAD(p + "no")
410 STORE(p + "win", 0)
420 SEND_DERO_TO_ADDRESS(LOAD(p + "x"), b + half)
430 STORE(p + "pool", b - half)
440 STORE(p + "cwin", cwin)
450 STORE(p + "inc", LOAD(p + "cw") - cwin)
460 STORE(p + "s", 3)
470 RETURN 0
500 SEND_DERO_TO_ADDRESS(LOAD(p + "m"), b)
510 SEND_ASSET_TO_ADDRESS(LOAD(p + "m"), LOAD(p + "k") * LOAD("reward"), SCID())
520 STORE("minted", LOAD("minted") + LOAD(p + "k") * LOAD("reward"))
530 STORE(p + "s", 2)
540 RETURN 0
900 RETURN 1
End Function

Function ClaimJuror(i Uint64) Uint64
10 DIM p as String
20 DIM w, pay, cut as Uint64
30 IF i >= LOAD("nc") THEN GOTO 900
40 LET p = "c" + ITOA(i)
50 IF LOAD(p + "s") < 2 THEN GOTO 900
60 IF EXISTS(p + "cwin") == 0 THEN GOTO 900
70 IF EXISTS(p + "v" + SIGNER()) == 0 THEN GOTO 900
80 IF EXISTS(p + "z" + SIGNER()) == 1 THEN GOTO 900
90 LET w = LOAD(p + "w" + SIGNER())
100 STORE(p + "z" + SIGNER(), 1)
110 STORE("pd" + SIGNER(), LOAD("pd" + SIGNER()) - 1)
120 IF EXISTS(p + "r" + SIGNER()) == 0 THEN GOTO 300
130 IF LOAD(p + "r" + SIGNER()) != LOAD(p + "win") THEN GOTO 300
140 LET pay = (LOAD(p + "pool") + LOAD(p + "inc") * LOAD("slash") / 100) * w / LOAD(p + "cwin")
150 SEND_DERO_TO_ADDRESS(SIGNER(), pay)
160 RETURN 0
300 LET cut = (w * LOAD("slash") + 99) / 100
310 IF cut > LOAD("st" + SIGNER()) THEN GOTO 330
320 GOTO 340
330 LET cut = LOAD("st" + SIGNER())
340 STORE("st" + SIGNER(), LOAD("st" + SIGNER()) - cut)
350 RETURN 0
900 RETURN 1
End Function
