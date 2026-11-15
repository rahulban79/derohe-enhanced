/* gt_service.bas -- R32 mechanism M2 "useful service + bounded fee rebate + miner boost", DVM-BASIC.
   A notary service: Notarize(doc) records a document digest (first writer wins) for a fee.
   rho percent of every fee goes to the epoch's rebate pool, the rest to the treasury. After the
   epoch ends each fee payer claims pool * weight / total weight. Weight = fee, or fee * (100 + boost)
   / 100 while the payer keeps >= minmat MAT (the M1 token, set by SetMAT) staked here.
   No-wash condition (enforced by SetParams): rho * (100 + boost) <= 10000, so a payer's rebate can never
   exceed the fee it paid unless other payers' fees or a sponsor subsidy fund it. A sponsor may add DERO to
   the current epoch's pool (Sponsor); that subsidy is competed for by fee payers (see the child rft).
   No payout is funded by a later participant's deposit: epoch e's pool is closed when e ends.
*/
Function Initialize() Uint64
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
End Function

Function SetParams(fee Uint64, rho Uint64, boost Uint64, epoch Uint64, minmat Uint64) Uint64
10 IF LOAD("owner") != SIGNER() THEN GOTO 900
20 IF LOAD("frozen") != 0 THEN GOTO 900
30 IF fee == 0 || epoch == 0 THEN GOTO 900
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
30 IF STRLEN(scidhex) != 64 THEN GOTO 900
40 STORE("mat", HEXDECODE(scidhex))
50 RETURN 0
900 RETURN 1
End Function

Function Freeze() Uint64
10 IF LOAD("owner") != SIGNER() THEN GOTO 900
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
100 STORE("ndocs", LOAD("ndocs") + 1)
110 LET e = BLOCK_HEIGHT() / LOAD("epoch")
120 LET r = f * LOAD("rho") / 100
130 LET w = f
140 IF boosted(SIGNER()) == 0 THEN GOTO 160
150 LET w = f * (100 + LOAD("boost")) / 100
160 LET k = ITOA(e) + ":" + SIGNER()
170 IF EXISTS("w" + k) == 1 THEN GOTO 190
180 STORE("w" + k, 0)
190 STORE("w" + k, LOAD("w" + k) + w)
200 IF EXISTS("W" + ITOA(e)) == 1 THEN GOTO 230
210 STORE("W" + ITOA(e), 0)
220 STORE("P" + ITOA(e), 0)
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
20 IF DEROVALUE() == 0 THEN GOTO 900
30 LET e = BLOCK_HEIGHT() / LOAD("epoch")
40 IF EXISTS("P" + ITOA(e)) == 1 THEN GOTO 70
50 STORE("P" + ITOA(e), 0)
60 STORE("W" + ITOA(e), 0)
70 STORE("P" + ITOA(e), LOAD("P" + ITOA(e)) + DEROVALUE())
80 RETURN 0
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
100 STORE("ml" + SIGNER(), BLOCK_HEIGHT() / LOAD("epoch"))
110 RETURN 0
900 RETURN 1
End Function

Function UnstakeMAT(amount Uint64) Uint64
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
20 DIM pay as Uint64
30 IF (e + 1) * LOAD("epoch") > BLOCK_HEIGHT() THEN GOTO 900
40 LET k = ITOA(e) + ":" + SIGNER()
50 IF EXISTS("w" + k) == 0 THEN GOTO 900
60 IF EXISTS("z" + k) == 1 THEN GOTO 900
70 IF LOAD("W" + ITOA(e)) == 0 THEN GOTO 900
80 LET pay = LOAD("P" + ITOA(e)) * LOAD("w" + k) / LOAD("W" + ITOA(e))
90 STORE("z" + k, 1)
100 SEND_DERO_TO_ADDRESS(SIGNER(), pay)
110 RETURN 0
900 RETURN 1
End Function

Function WithdrawTreasury(amount Uint64) Uint64
10 IF LOAD("owner") != SIGNER() THEN GOTO 900
20 IF amount == 0 || amount > LOAD("treasury") THEN GOTO 900
30 STORE("treasury", LOAD("treasury") - amount)
40 SEND_DERO_TO_ADDRESS(SIGNER(), amount)
50 RETURN 0
900 RETURN 1
End Function
