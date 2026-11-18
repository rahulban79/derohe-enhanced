/* gt_service.bas -- R32 mechanism M2 "useful service + bounded fee rebate + miner boost", DVM-BASIC. R33: audit fixes.
   A notary service: Notarize(doc) records a document digest (first writer wins) for a fee; the record keeps the
   height ("d" + doc) and the submitter ("by" + doc, R33 A16).
   rho percent of every fee goes to the epoch's rebate pool, the rest to the treasury. After the
   epoch ends each fee payer claims pool * weight / total weight. Weight = fee, or fee * (100 + boost)
   / 100 while the payer keeps >= minmat MAT (the M1 token, set by SetMAT) staked here.
   No-wash condition (enforced by SetParams): rho * (100 + boost) <= 10000, so a payer's rebate can never
   exceed the fee it paid unless other payers' fees or a sponsor subsidy fund it. A sponsor may add DERO to
   the current epoch's pool (Sponsor, after Freeze); that subsidy is competed for by fee payers (see the child rft).
   No payout is funded by a later participant's deposit: epoch e's pool is closed when e ends.
   R33 A10: a pool whose epoch ended with no fee payer (W = 0) rolls forward into the next epoch that has a
   Notarize or Sponsor call ("R" + e records where it went), so sponsor funds are never stuck.
   R33 A13: the floor remainder of an epoch's rebates goes to the treasury with the epoch's last claim; an
   entrypoint that expects no DERO refuses a deposit. R33 A01/A12: Initialize runs once, never anonymously.
   R33 A15: fee <= 10^12, boost <= 1000, epoch <= 10^7; pool * weight is computed exactly when it fits in
   64 bits and with a 10^-5 scaled share otherwise (never wraps).
*/
Function Initialize() Uint64
5 IF EXISTS("owner") == 1 THEN GOTO 900
6 IF IS_ADDRESS_VALID(SIGNER()) == 0 THEN GOTO 900
7 IF DEROVALUE() != 0 THEN GOTO 900
10 STORE("owner", SIGNER())
20 STORE("fee", 1000)
30 STORE("rho", 50)
40 STORE("boost", 100)
50 STORE("epoch", 100)
60 STORE("minmat", 100)
70 STORE("mat", "")
80 STORE("frozen", 0)
90 STORE("treasury", 0)
100 STORE("ndocs", 0)
110 RETURN 0
900 RETURN 1
End Function

Function SetParams(fee Uint64, rho Uint64, boost Uint64, epoch Uint64, minmat Uint64) Uint64
10 IF LOAD("owner") != SIGNER() THEN GOTO 900
15 IF DEROVALUE() != 0 THEN GOTO 900
20 IF LOAD("frozen") != 0 THEN GOTO 900
30 IF fee == 0 || epoch == 0 THEN GOTO 900
35 IF fee > 1000000000000 || epoch > 10000000 || boost > 1000 THEN GOTO 900
40 IF rho > 100 THEN GOTO 900
50 IF rho * (100 + boost) > 10000 THEN GOTO 900
60 STORE("fee", fee)
70 STORE("rho", rho)
80 STORE("boost", boost)
90 STORE("epoch", epoch)
100 STORE("minmat", minmat)
110 RETURN 0
900 RETURN 1
End Function

Function SetMAT(scidhex String) Uint64
10 IF LOAD("owner") != SIGNER() THEN GOTO 900
20 IF LOAD("frozen") != 0 THEN GOTO 900
25 IF DEROVALUE() != 0 THEN GOTO 900
30 IF STRLEN(scidhex) != 64 THEN GOTO 900
40 STORE("mat", HEXDECODE(scidhex))
50 RETURN 0
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

Function boosted(a String) Uint64
10 IF EXISTS("ms" + a) == 0 THEN GOTO 40
20 IF LOAD("ms" + a) < LOAD("minmat") THEN GOTO 40
30 RETURN 1
40 RETURN 0
End Function

Function epopen(e Uint64) Uint64
10 IF EXISTS("W" + ITOA(e)) == 1 THEN GOTO 80
20 STORE("W" + ITOA(e), 0)
30 STORE("P" + ITOA(e), 0)
40 STORE("C" + ITOA(e), 0)
50 STORE("Z" + ITOA(e), 0)
60 STORE("Q" + ITOA(e), 0)
80 RETURN 0
End Function

Function roll(e Uint64) Uint64
10 DIM l as Uint64
20 IF epopen(e) != 0 THEN GOTO 90
30 IF EXISTS("le") == 0 THEN GOTO 80
40 LET l = LOAD("le")
50 IF l >= e THEN GOTO 90
60 IF LOAD("W" + ITOA(l)) != 0 THEN GOTO 80
65 IF LOAD("P" + ITOA(l)) == 0 THEN GOTO 80
70 STORE("P" + ITOA(e), LOAD("P" + ITOA(e)) + LOAD("P" + ITOA(l)))
72 STORE("R" + ITOA(l), e)
75 STORE("P" + ITOA(l), 0)
80 STORE("le", e)
90 RETURN 0
End Function

Function Notarize(doc String) Uint64
10 DIM e, f, w, r as Uint64
20 DIM k as String
30 IF LOAD("frozen") == 0 THEN GOTO 900
40 IF IS_ADDRESS_VALID(SIGNER()) == 0 THEN GOTO 900
50 LET f = LOAD("fee")
60 IF DEROVALUE() != f THEN GOTO 900
70 IF STRLEN(doc) == 0 || STRLEN(doc) > 64 THEN GOTO 900
80 IF EXISTS("d" + doc) == 1 THEN GOTO 900
90 STORE("d" + doc, BLOCK_HEIGHT())
95 STORE("by" + doc, SIGNER())
100 STORE("ndocs", LOAD("ndocs") + 1)
110 LET e = BLOCK_HEIGHT() / LOAD("epoch")
115 IF roll(e) != 0 THEN GOTO 900
120 LET r = f * LOAD("rho") / 100
130 LET w = f
140 IF boosted(SIGNER()) == 0 THEN GOTO 160
150 LET w = f * (100 + LOAD("boost")) / 100
160 LET k = ITOA(e) + ":" + SIGNER()
170 IF EXISTS("w" + k) == 1 THEN GOTO 190
180 STORE("w" + k, 0)
185 STORE("C" + ITOA(e), LOAD("C" + ITOA(e)) + 1)
190 STORE("w" + k, LOAD("w" + k) + w)
230 STORE("W" + ITOA(e), LOAD("W" + ITOA(e)) + w)
240 STORE("P" + ITOA(e), LOAD("P" + ITOA(e)) + r)
250 STORE("treasury", LOAD("treasury") + f - r)
260 IF EXISTS("ml" + SIGNER()) == 0 THEN GOTO 290
270 IF LOAD("ml" + SIGNER()) > e THEN GOTO 290
280 STORE("ml" + SIGNER(), e)
290 RETURN 0
900 RETURN 1
End Function

Function Sponsor() Uint64
10 DIM e as Uint64
15 IF LOAD("frozen") == 0 THEN GOTO 900
20 IF DEROVALUE() == 0 THEN GOTO 900
30 LET e = BLOCK_HEIGHT() / LOAD("epoch")
40 IF roll(e) != 0 THEN GOTO 900
70 STORE("P" + ITOA(e), LOAD("P" + ITOA(e)) + DEROVALUE())
80 RETURN 0
900 RETURN 1
End Function

Function StakeMAT() Uint64
10 DIM v, s as Uint64
15 IF DEROVALUE() != 0 THEN GOTO 900
20 IF STRLEN(LOAD("mat")) != 32 THEN GOTO 900
30 IF IS_ADDRESS_VALID(SIGNER()) == 0 THEN GOTO 900
40 LET v = ASSETVALUE(LOAD("mat"))
50 IF v == 0 THEN GOTO 900
60 LET s = 0
70 IF EXISTS("ms" + SIGNER()) == 0 THEN GOTO 90
80 LET s = LOAD("ms" + SIGNER())
90 STORE("ms" + SIGNER(), s + v)
100 STORE("ml" + SIGNER(), BLOCK_HEIGHT() / LOAD("epoch"))
110 RETURN 0
900 RETURN 1
End Function

Function UnstakeMAT(amount Uint64) Uint64
5 IF DEROVALUE() != 0 THEN GOTO 900
10 IF EXISTS("ms" + SIGNER()) == 0 THEN GOTO 900
20 IF BLOCK_HEIGHT() / LOAD("epoch") <= LOAD("ml" + SIGNER()) THEN GOTO 900
30 IF amount == 0 || amount > LOAD("ms" + SIGNER()) THEN GOTO 900
40 STORE("ms" + SIGNER(), LOAD("ms" + SIGNER()) - amount)
50 SEND_ASSET_TO_ADDRESS(SIGNER(), amount, LOAD("mat"))
60 RETURN 0
900 RETURN 1
End Function

Function ClaimRebate(e Uint64) Uint64
10 DIM k as String
20 DIM pay, pp, wt, ww, sh as Uint64
25 IF DEROVALUE() != 0 THEN GOTO 900
30 IF (e + 1) * LOAD("epoch") > BLOCK_HEIGHT() THEN GOTO 900
35 IF BLOCK_HEIGHT() >= (e + 11) * LOAD("epoch") THEN GOTO 900
40 LET k = ITOA(e) + ":" + SIGNER()
50 IF EXISTS("w" + k) == 0 THEN GOTO 900
60 IF EXISTS("z" + k) == 1 THEN GOTO 900
70 LET ww = LOAD("W" + ITOA(e))
75 IF ww == 0 THEN GOTO 900
80 LET pp = LOAD("P" + ITOA(e))
82 LET wt = LOAD("w" + k)
84 IF pp > 18446744073709551615 / wt THEN GOTO 90
86 LET pay = pp * wt / ww
88 GOTO 94
90 LET sh = wt * 100000 / ww
91 IF wt <= 184467440737095 THEN GOTO 93
92 LET sh = wt / (ww / 100000 + 1)
93 LET pay = pp / 100000 * sh + pp % 100000 * sh / 100000
94 STORE("z" + k, 1)
95 STORE("Q" + ITOA(e), LOAD("Q" + ITOA(e)) + pay)
96 STORE("Z" + ITOA(e), LOAD("Z" + ITOA(e)) + 1)
98 IF LOAD("Z" + ITOA(e)) != LOAD("C" + ITOA(e)) THEN GOTO 100
99 STORE("treasury", LOAD("treasury") + pp - LOAD("Q" + ITOA(e)))
100 SEND_DERO_TO_ADDRESS(SIGNER(), pay)
110 RETURN 0
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

// r33 verify (liveness): claims close 10 epochs after epoch e ends; then anyone may move what is left of e (P - Q,
// the shares of payers who never claimed and the rounding remainder) to the treasury, once
Function Sweep(e Uint64) Uint64
10 IF DEROVALUE() != 0 THEN GOTO 900
20 IF BLOCK_HEIGHT() < (e + 11) * LOAD("epoch") THEN GOTO 900
30 IF EXISTS("C" + ITOA(e)) == 0 THEN GOTO 900
40 IF EXISTS("sw" + ITOA(e)) == 1 THEN GOTO 900
50 IF EXISTS("Z" + ITOA(e)) == 0 THEN GOTO 70
60 IF LOAD("Z" + ITOA(e)) == LOAD("C" + ITOA(e)) THEN GOTO 900
70 STORE("sw" + ITOA(e), 1)
80 IF EXISTS("Q" + ITOA(e)) == 1 THEN GOTO 100
90 STORE("Q" + ITOA(e), 0)
100 STORE("treasury", LOAD("treasury") + LOAD("P" + ITOA(e)) - LOAD("Q" + ITOA(e)))
110 STORE("Q" + ITOA(e), LOAD("P" + ITOA(e)))
120 RETURN 0
900 RETURN 1
End Function
