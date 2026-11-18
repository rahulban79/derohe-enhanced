/* gt_attest.bas -- R32 mechanism M1 "miner-attested token" (MAT), DVM-BASIC. R33: audit fixes GT-A01..A17.
   A miner claims, under its own signer (ring size 2), that its address mined k miniblocks in the
   height range [from, upto]. The claim posts a DERO bond of b = k * bond. The chain data that proves
   or refutes the claim is public (block headers list each miniblock's miner), but the DVM cannot
   read it, so the claim is OPTIMISTIC: until claim height + window anyone may challenge it by posting
   an equal bond b; up to maxch (8) challengers per claim (R33 A07: one Sybil challenge cannot shut out
   an honest challenger). DERO-staked jurors commit until h + window + commitw and reveal in
   (h + window + commitw, h + window + commitw + revealw]; Finalize after that.
   Juror commit (R33 A08, bound to the juror like gt_audit):
     HEX(SHA256(ITOA(i) + ":" + ITOA(vote) + ":" + salt + ":" + ADDRESS_STRING(SIGNER())))
   Outcomes of a challenged claim (revealed stake weight):
     yes > no: upheld; the claimant gets b back plus half of the challengers' bonds n*b and k*reward MAT;
     no > yes: rejected; each challenger gets b back plus an equal part of b/2; nothing is minted;
     yes == no (including no reveal at all): undecided (R33 A07); every bond is refunded, NOTHING is minted.
   Jurors (R33 A02): CommitVote moves the juror's whole free stake into an escrow for that dispute, so one
   stake can never back more open disputes than its amount. Coherent jurors split pot = (loser bonds not paid
   to the winning parties) + floor(incoherent escrow * slash / 100) pro rata; incoherent or unrevealed jurors
   lose ceil(slash %) of their escrow. Payouts never exceed what the losing side escrowed. The last juror's
   ClaimJuror sweeps the rest (slash beyond the pot, floor remainders) to the treasury (R33 A13).
   Every unchallenged claim mints after window blocks (R33 A09: deploy with a long window; see mechanisms.json).
   Rules are frozen by Freeze() before the first claim (anti-rug); Initialize runs once (R33 A01) and never
   for an anonymous signer (R33 A12). An entrypoint that expects no DERO refuses a deposit (R33 A13).
   Parameters are bounded so no product can wrap Uint64 (R33 A15).
   Return 0 = success; any other value reverts (deposits go back to a known signer).
*/
Function Initialize() Uint64
5 IF EXISTS("owner") == 1 THEN GOTO 900
6 IF IS_ADDRESS_VALID(SIGNER()) == 0 THEN GOTO 900
7 IF DEROVALUE() != 0 THEN GOTO 900
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
115 STORE("maxch", 8)
120 STORE("frozen", 0)
130 STORE("nc", 0)
140 STORE("minted", 0)
145 STORE("treasury", 0)
150 RETURN 0
900 RETURN 1
End Function

Function SetParams(bond Uint64, reward Uint64, window Uint64, commitw Uint64, revealw Uint64, maxmb Uint64, slash Uint64, minstake Uint64) Uint64
10 IF LOAD("owner") != SIGNER() THEN GOTO 900
20 IF LOAD("frozen") != 0 THEN GOTO 900
25 IF DEROVALUE() != 0 THEN GOTO 900
30 IF bond == 0 || bond > 1000000000000 THEN GOTO 900
35 IF reward > 1000000 THEN GOTO 900
40 IF slash > 100 THEN GOTO 900
50 IF window == 0 || commitw == 0 || revealw == 0 || maxmb == 0 THEN GOTO 900
55 IF window > 1000000 || commitw > 1000000 || revealw > 1000000 || maxmb > 100 THEN GOTO 900
57 IF minstake == 0 || minstake > LOAD("maxstake") THEN GOTO 900
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
15 IF DEROVALUE() != 0 THEN GOTO 900
17 IF LOAD("frozen") != 0 THEN GOTO 900
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
225 STORE(p + "nx", 0)
230 STORE("lc" + SIGNER(), upto)
240 STORE("nc", i + 1)
250 RETURN 0
900 RETURN 1
End Function

Function Challenge(i Uint64) Uint64
10 DIM p as String
15 DIM n as Uint64
20 IF IS_ADDRESS_VALID(SIGNER()) == 0 THEN GOTO 900
30 IF i >= LOAD("nc") THEN GOTO 900
40 LET p = "c" + ITOA(i)
50 IF LOAD(p + "s") > 1 THEN GOTO 900
60 IF BLOCK_HEIGHT() > LOAD(p + "h") + LOAD("window") THEN GOTO 900
70 IF DEROVALUE() != LOAD(p + "b") THEN GOTO 900
80 IF SIGNER() == LOAD(p + "m") THEN GOTO 900
82 IF EXISTS(p + "xi" + SIGNER()) == 1 THEN GOTO 900
84 IF EXISTS(p + "v" + SIGNER()) == 1 THEN GOTO 900
86 LET n = LOAD(p + "nx")
88 IF n >= LOAD("maxch") THEN GOTO 900
89 IF n > 0 THEN GOTO 160
90 STORE(p + "s", 1)
110 STORE(p + "vh", BLOCK_HEIGHT())
120 STORE(p + "yes", 0)
130 STORE(p + "no", 0)
140 STORE(p + "cw", 0)
145 STORE(p + "nj", 0)
160 STORE(p + "x" + ITOA(n), SIGNER())
170 STORE(p + "xi" + SIGNER(), n)
180 STORE(p + "nx", n + 1)
190 RETURN 0
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
110 RETURN 0
900 RETURN 1
End Function

Function Unstake(amount Uint64) Uint64
5 IF DEROVALUE() != 0 THEN GOTO 900
10 IF EXISTS("st" + SIGNER()) == 0 THEN GOTO 900
30 IF amount == 0 || amount > LOAD("st" + SIGNER()) THEN GOTO 900
40 STORE("st" + SIGNER(), LOAD("st" + SIGNER()) - amount)
50 SEND_DERO_TO_ADDRESS(SIGNER(), amount)
60 RETURN 0
900 RETURN 1
End Function

Function CommitVote(i Uint64, h String) Uint64
10 DIM p as String
20 DIM w as Uint64
25 IF DEROVALUE() != 0 THEN GOTO 900
30 IF i >= LOAD("nc") THEN GOTO 900
40 LET p = "c" + ITOA(i)
50 IF LOAD(p + "s") != 1 THEN GOTO 900
60 IF BLOCK_HEIGHT() > LOAD(p + "h") + LOAD("window") + LOAD("commitw") THEN GOTO 900
70 IF EXISTS("st" + SIGNER()) == 0 THEN GOTO 900
80 LET w = LOAD("st" + SIGNER())
90 IF w == 0 || w < LOAD("minstake") THEN GOTO 900
100 IF SIGNER() == LOAD(p + "m") THEN GOTO 900
105 IF EXISTS(p + "xi" + SIGNER()) == 1 THEN GOTO 900
110 IF EXISTS(p + "v" + SIGNER()) == 1 THEN GOTO 900
120 IF STRLEN(h) != 64 THEN GOTO 900
130 STORE(p + "v" + SIGNER(), h)
140 STORE(p + "w" + SIGNER(), w)
145 STORE("st" + SIGNER(), 0)
150 STORE(p + "cw", LOAD(p + "cw") + w)
155 STORE(p + "j" + ITOA(LOAD(p + "nj")), SIGNER())
160 STORE(p + "nj", LOAD(p + "nj") + 1)
170 RETURN 0
900 RETURN 1
End Function

Function RevealVote(i Uint64, vote Uint64, salt String) Uint64
10 DIM p as String
20 DIM t as Uint64
25 IF DEROVALUE() != 0 THEN GOTO 900
30 IF i >= LOAD("nc") THEN GOTO 900
40 LET p = "c" + ITOA(i)
50 IF LOAD(p + "s") != 1 THEN GOTO 900
60 LET t = LOAD(p + "h") + LOAD("window") + LOAD("commitw")
70 IF BLOCK_HEIGHT() <= t THEN GOTO 900
80 IF BLOCK_HEIGHT() > t + LOAD("revealw") THEN GOTO 900
90 IF EXISTS(p + "v" + SIGNER()) == 0 THEN GOTO 900
100 IF EXISTS(p + "r" + SIGNER()) == 1 THEN GOTO 900
110 IF vote > 1 THEN GOTO 900
120 IF HEX(SHA256(ITOA(i) + ":" + ITOA(vote) + ":" + salt + ":" + ADDRESS_STRING(SIGNER()))) != LOAD(p + "v" + SIGNER()) THEN GOTO 900
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
20 DIM b, n, j, yes, no, half, each, lb as Uint64
25 IF DEROVALUE() != 0 THEN GOTO 900
30 IF i >= LOAD("nc") THEN GOTO 900
40 LET p = "c" + ITOA(i)
50 LET b = LOAD(p + "b")
60 IF LOAD(p + "s") == 1 THEN GOTO 200
70 IF LOAD(p + "s") != 0 THEN GOTO 900
80 IF BLOCK_HEIGHT() <= LOAD(p + "h") + LOAD("window") THEN GOTO 900
90 GOTO 500
200 IF BLOCK_HEIGHT() <= LOAD(p + "h") + LOAD("window") + LOAD("commitw") + LOAD("revealw") THEN GOTO 900
205 LET n = LOAD(p + "nx")
210 LET yes = LOAD(p + "yes")
215 LET no = LOAD(p + "no")
220 STORE(p + "paid", 0)
225 STORE(p + "cuts", 0)
230 STORE(p + "nz", 0)
235 IF yes > no THEN GOTO 300
240 IF no > yes THEN GOTO 400
245 STORE(p + "win", 2)
250 STORE(p + "cwin", 0)
252 STORE(p + "inc", LOAD(p + "cw"))
254 STORE(p + "pool", 0)
256 STORE(p + "pot", 0)
260 SEND_DERO_TO_ADDRESS(LOAD(p + "m"), b)
265 LET j = 0
270 IF j >= n THEN GOTO 290
275 SEND_DERO_TO_ADDRESS(LOAD(p + "x" + ITOA(j)), b)
280 LET j = j + 1
285 GOTO 270
290 STORE(p + "s", 4)
295 RETURN 0
300 LET lb = n * b
305 LET half = lb / 2
310 STORE(p + "win", 1)
315 STORE(p + "cwin", yes)
317 STORE(p + "inc", LOAD(p + "cw") - yes)
320 STORE(p + "pool", lb - half)
322 STORE(p + "pot", lb - half + (LOAD(p + "cw") - yes) * LOAD("slash") / 100)
325 SEND_DERO_TO_ADDRESS(LOAD(p + "m"), half)
330 GOTO 500
400 LET half = b / 2
405 LET each = half / n
410 STORE(p + "win", 0)
415 STORE(p + "cwin", no)
417 STORE(p + "inc", LOAD(p + "cw") - no)
420 STORE(p + "pool", b - half)
422 STORE(p + "pot", b - half + (LOAD(p + "cw") - no) * LOAD("slash") / 100)
425 STORE("treasury", LOAD("treasury") + half - each * n)
430 LET j = 0
435 IF j >= n THEN GOTO 455
440 SEND_DERO_TO_ADDRESS(LOAD(p + "x" + ITOA(j)), b + each)
445 LET j = j + 1
450 GOTO 435
455 STORE(p + "s", 3)
460 RETURN 0
500 SEND_DERO_TO_ADDRESS(LOAD(p + "m"), b)
510 SEND_ASSET_TO_ADDRESS(LOAD(p + "m"), LOAD(p + "k") * LOAD("reward"), SCID())
520 STORE("minted", LOAD("minted") + LOAD(p + "k") * LOAD("reward"))
530 STORE(p + "s", 2)
540 RETURN 0
900 RETURN 1
End Function

// r33 verify (liveness): settle juror `who` of dispute i (the body of ClaimJuror); returns 0, or 1 to revert
Function jclaim(i Uint64, who String) Uint64
10 DIM p as String
20 DIM w, pay, cut, x, cwin, st as Uint64
30 IF i >= LOAD("nc") THEN GOTO 900
40 LET p = "c" + ITOA(i)
50 IF LOAD(p + "s") < 2 THEN GOTO 900
60 IF EXISTS(p + "cwin") == 0 THEN GOTO 900
70 IF EXISTS(p + "v" + who) == 0 THEN GOTO 900
80 IF EXISTS(p + "z" + who) == 1 THEN GOTO 900
90 LET w = LOAD(p + "w" + who)
100 STORE(p + "z" + who, 1)
110 LET st = LOAD("st" + who)
120 IF EXISTS(p + "r" + who) == 0 THEN GOTO 300
125 IF LOAD(p + "win") == 2 THEN GOTO 250
130 IF LOAD(p + "r" + who) != LOAD(p + "win") THEN GOTO 300
140 LET x = LOAD(p + "pot")
145 LET cwin = LOAD(p + "cwin")
150 IF x > 18446744073709551615 / w THEN GOTO 170
155 LET pay = x * w / cwin
160 GOTO 180
170 LET pay = x / 1000000 * (w * 1000000 / cwin) + x % 1000000 * (w * 1000000 / cwin) / 1000000
180 STORE(p + "paid", LOAD(p + "paid") + pay)
190 SEND_DERO_TO_ADDRESS(who, pay)
250 STORE("st" + who, st + w)
260 GOTO 400
300 LET cut = (w * LOAD("slash") + 99) / 100
310 STORE("st" + who, st + w - cut)
320 STORE(p + "cuts", LOAD(p + "cuts") + cut)
400 STORE(p + "nz", LOAD(p + "nz") + 1)
410 IF LOAD(p + "nz") != LOAD(p + "nj") THEN GOTO 430
420 STORE("treasury", LOAD("treasury") + LOAD(p + "pool") + LOAD(p + "cuts") - LOAD(p + "paid"))
430 RETURN 0
900 RETURN 1
End Function

Function ClaimJuror(i Uint64) Uint64
10 IF DEROVALUE() != 0 THEN GOTO 900
20 IF jclaim(i, SIGNER()) != 0 THEN GOTO 900
30 RETURN 0
900 RETURN 1
End Function

// r33 verify (liveness): a juror who never claims must not lock the dispute's treasury share; after the reveal window
// plus 10 reveal windows anyone may settle juror k (its pot share goes to the juror, its stake stays the juror's)
Function ClaimJurorFor(i Uint64, k Uint64) Uint64
10 DIM p as String
20 IF DEROVALUE() != 0 THEN GOTO 900
30 IF i >= LOAD("nc") THEN GOTO 900
40 LET p = "c" + ITOA(i)
50 IF k >= LOAD(p + "nj") THEN GOTO 900
60 IF BLOCK_HEIGHT() <= LOAD(p + "h") + LOAD("window") + LOAD("commitw") + 11 * LOAD("revealw") THEN GOTO 900
70 IF jclaim(i, LOAD(p + "j" + ITOA(k))) != 0 THEN GOTO 900
80 RETURN 0
900 RETURN 1
End Function

Function WithdrawTreasury(amount Uint64) Uint64
10 IF LOAD("owner") != SIGNER() THEN GOTO 900
15 IF DEROVALUE() != 0 THEN GOTO 900
20 IF amount == 0 || amount > LOAD("treasury") THEN GOTO 900
30 STORE("treasury", LOAD("treasury") - amount)
40 SEND_DERO_TO_ADDRESS(SIGNER(), amount)
50 RETURN 0
900 RETURN 1
End Function
