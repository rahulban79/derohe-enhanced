/* gt_audit.bas -- R32a "audit bounty": pay for independent detection, DVM-BASIC.
   GAME. The sponsor (owner) posts round a asking auditors for a deterministic digest over public chain data:
   (task, from, upto), e.g. task 1 = block-header digest, task 2 = emission digest. The contract never interprets
   the task. The sponsor's own answer is HIDDEN: Post stores commit = HEX(SHA256(answer + ":" + salt)).
   Auditors Enter(a, commit) with a bond during [start, start + commitw], where the auditor commit is
   HEX(SHA256(answer + ":" + salt + ":" + ADDRESS_STRING(SIGNER()))). In (start + commitw, start + commitw + revealw]
   the sponsor reveals (RevealSponsor) and auditors reveal (Reveal). Settle(a), by anyone after the reveal window:
   (1) sponsor revealed, no dissenting majority: entrants whose answer == the sponsor answer win;
   (2) a STRICT majority of revealed entrants agree on one answer that differs from the sponsor's, or the sponsor
       did not reveal: that majority wins and disputed = 1 (the detection signal: the sponsor digest was wrong or
       withheld);
   (3) no sponsor reveal and no majority: undecided, refund = 1: revealers (or everyone, if nobody revealed) get the
       bond back, the bounty goes to carry.
   Winners split the bounty equally and get their bond back; the remainder (bounty mod winners) is recorded and
   goes to carry. Non-revealers and wrong answers forfeit their bond to carry; no winners -> the bounty to carry.
   carry is added to the bounty of the NEXT Post (only what has been settled before that Post). Settle stores
   credits only; each entrant pulls its credit with Withdraw(a, j) (pull payment, once, to SIGNER() only).
   THREAT MODEL. Copying: a copied commit cannot be revealed by another address (the address is inside the hash).
   Lazy auditor: the sponsor answer is hidden until after the commit window, so it cannot be copied in time.
   Sponsor withholding/lying: refunds (3) or the majority path (2) with disputed = 1, which is public.
   NOT prevented: collusion and bribery among auditors, Sybil entries by one party (incl. the sponsor under another
   address), and a sponsor majority of Sybils; the majority is only as independent as the auditors are.
   SIGNER() is known only at ring size 2: Enter/Reveal/Withdraw/owner calls must use ring size 2.
   STORED KEYS. Global: owner, bond, commitw, revealw, maxn (<= 32, Settle is O(n^2)), frozen, na (rounds posted),
   carry (forfeits + remainders + unwon bounties awaiting the next Post).
   Round p = "a" + ITOA(a) + "_": p+task, p+from, p+upto, p+fund (DEROVALUE of Post), p+cin (carry joined),
   p+bounty (fund + cin), p+sc (sponsor commit), p+start (Post height), p+n (entrants), p+in<signer> (entry index),
   p+sa (sponsor answer, only if revealed), p+st (settled 1), p+win (winning answer), p+nw (winners),
   p+disp (1 = majority overrode or replaced the sponsor), p+refund (1 = undecided), p+share, p+rem, p+forf.
   Entrant q = p + ITOA(j) + "_": q+who (signer), q+c (commit), q+v (revealed 0/1), q+ans (only if revealed),
   q+cr (credit), q+x (withdrawn 0/1).
   Return 0 = success; any other value reverts.
*/
Function Initialize() Uint64
10 STORE("owner", SIGNER())
20 STORE("bond", 10000)
30 STORE("commitw", 20)
40 STORE("revealw", 20)
50 STORE("maxn", 16)
60 STORE("frozen", 0)
70 STORE("na", 0)
80 STORE("carry", 0)
90 RETURN 0
End Function

Function SetParams(bond Uint64, commitw Uint64, revealw Uint64, maxn Uint64) Uint64
10 IF LOAD("owner") != SIGNER() THEN GOTO 900
20 IF LOAD("frozen") != 0 THEN GOTO 900
30 IF bond == 0 || commitw == 0 || revealw == 0 THEN GOTO 900
40 IF maxn == 0 || maxn > 32 THEN GOTO 900
50 STORE("bond", bond)
60 STORE("commitw", commitw)
70 STORE("revealw", revealw)
80 STORE("maxn", maxn)
90 RETURN 0
900 RETURN 1
End Function

Function Freeze() Uint64
10 IF LOAD("owner") != SIGNER() THEN GOTO 900
20 STORE("frozen", 1)
30 RETURN 0
900 RETURN 1
End Function

Function Post(task Uint64, from Uint64, upto Uint64, commit String) Uint64
10 DIM a as Uint64
20 DIM p as String
30 IF LOAD("owner") != SIGNER() THEN GOTO 900
40 IF LOAD("frozen") == 0 THEN GOTO 900
50 IF DEROVALUE() == 0 THEN GOTO 900
60 IF upto < from THEN GOTO 900
70 IF upto >= BLOCK_HEIGHT() THEN GOTO 900
80 IF STRLEN(commit) != 64 THEN GOTO 900
90 LET a = LOAD("na")
100 LET p = "a" + ITOA(a) + "_"
110 STORE(p + "task", task)
120 STORE(p + "from", from)
130 STORE(p + "upto", upto)
140 STORE(p + "fund", DEROVALUE())
150 STORE(p + "cin", LOAD("carry"))
160 STORE(p + "bounty", DEROVALUE() + LOAD("carry"))
170 STORE("carry", 0)
180 STORE(p + "sc", commit)
190 STORE(p + "start", BLOCK_HEIGHT())
200 STORE(p + "n", 0)
210 STORE(p + "st", 0)
220 STORE("na", a + 1)
230 RETURN 0
900 RETURN 1
End Function

Function Enter(a Uint64, commit String) Uint64
10 DIM n as Uint64
20 DIM p, q as String
30 IF a >= LOAD("na") THEN GOTO 900
40 IF IS_ADDRESS_VALID(SIGNER()) == 0 THEN GOTO 900
50 IF SIGNER() == LOAD("owner") THEN GOTO 900
60 LET p = "a" + ITOA(a) + "_"
70 IF BLOCK_HEIGHT() > LOAD(p + "start") + LOAD("commitw") THEN GOTO 900
80 IF DEROVALUE() != LOAD("bond") THEN GOTO 900
90 LET n = LOAD(p + "n")
100 IF n >= LOAD("maxn") THEN GOTO 900
110 IF EXISTS(p + "in" + SIGNER()) == 1 THEN GOTO 900
120 IF STRLEN(commit) != 64 THEN GOTO 900
130 LET q = p + ITOA(n) + "_"
140 STORE(q + "who", SIGNER())
150 STORE(q + "c", commit)
160 STORE(q + "v", 0)
170 STORE(q + "cr", 0)
180 STORE(q + "x", 0)
190 STORE(p + "in" + SIGNER(), n)
200 STORE(p + "n", n + 1)
210 RETURN 0
900 RETURN 1
End Function

Function RevealSponsor(a Uint64, answer String, salt String) Uint64
10 DIM t as Uint64
20 DIM p as String
30 IF LOAD("owner") != SIGNER() THEN GOTO 900
40 IF a >= LOAD("na") THEN GOTO 900
50 LET p = "a" + ITOA(a) + "_"
60 IF EXISTS(p + "sa") == 1 THEN GOTO 900
70 LET t = LOAD(p + "start") + LOAD("commitw")
80 IF BLOCK_HEIGHT() <= t THEN GOTO 900
90 IF BLOCK_HEIGHT() > t + LOAD("revealw") THEN GOTO 900
100 IF HEX(SHA256(answer + ":" + salt)) != LOAD(p + "sc") THEN GOTO 900
110 STORE(p + "sa", answer)
120 RETURN 0
900 RETURN 1
End Function

Function Reveal(a Uint64, j Uint64, answer String, salt String) Uint64
10 DIM t as Uint64
20 DIM p, q as String
30 IF a >= LOAD("na") THEN GOTO 900
40 LET p = "a" + ITOA(a) + "_"
50 IF j >= LOAD(p + "n") THEN GOTO 900
60 LET q = p + ITOA(j) + "_"
70 IF LOAD(q + "who") != SIGNER() THEN GOTO 900
80 IF LOAD(q + "v") != 0 THEN GOTO 900
90 LET t = LOAD(p + "start") + LOAD("commitw")
100 IF BLOCK_HEIGHT() <= t THEN GOTO 900
110 IF BLOCK_HEIGHT() > t + LOAD("revealw") THEN GOTO 900
120 IF HEX(SHA256(answer + ":" + salt + ":" + ADDRESS_STRING(SIGNER()))) != LOAD(q + "c") THEN GOTO 900
130 STORE(q + "v", 1)
140 STORE(q + "ans", answer)
150 RETURN 0
900 RETURN 1
End Function

Function Settle(a Uint64) Uint64
10 DIM n, j, k, c, nr, hs, hw, md, nw, b, bond, share, rem, forf, cr, disp as Uint64
20 DIM p, q, w, x as String
30 IF a >= LOAD("na") THEN GOTO 900
40 LET p = "a" + ITOA(a) + "_"
50 IF LOAD(p + "st") != 0 THEN GOTO 900
60 IF BLOCK_HEIGHT() <= LOAD(p + "start") + LOAD("commitw") + LOAD("revealw") THEN GOTO 900
70 LET n = LOAD(p + "n")
80 LET bond = LOAD("bond")
90 LET b = LOAD(p + "bounty")
100 LET hs = EXISTS(p + "sa")
110 LET nr = 0
120 LET j = 0
130 IF j >= n THEN GOTO 170
140 LET nr = nr + LOAD(p + ITOA(j) + "_v")
150 LET j = j + 1
160 GOTO 130
170 LET hw = 0
175 LET j = 0
180 IF j >= n THEN GOTO 300
190 LET q = p + ITOA(j) + "_"
200 IF LOAD(q + "v") == 0 THEN GOTO 280
210 LET x = LOAD(q + "ans")
220 LET c = 0
230 LET k = 0
240 IF k >= n THEN GOTO 270
250 IF LOAD(p + ITOA(k) + "_v") == 0 THEN GOTO 265
255 IF LOAD(p + ITOA(k) + "_ans") != x THEN GOTO 265
260 LET c = c + 1
265 LET k = k + 1
266 GOTO 240
270 IF 2 * c > nr THEN GOTO 290
280 LET j = j + 1
285 GOTO 180
290 LET w = x
295 LET hw = 1
300 LET disp = 0
305 LET md = 1
310 IF hw == 0 THEN GOTO 340
320 IF hs == 0 THEN GOTO 360
330 IF w != LOAD(p + "sa") THEN GOTO 360
335 GOTO 370
340 IF hs == 0 THEN GOTO 365
350 LET w = LOAD(p + "sa")
355 GOTO 370
360 LET disp = 1
362 GOTO 370
365 LET md = 2
370 LET nw = 0
375 LET j = 0
380 IF md != 1 THEN GOTO 430
385 IF j >= n THEN GOTO 430
390 LET q = p + ITOA(j) + "_"
395 IF LOAD(q + "v") == 0 THEN GOTO 410
400 IF LOAD(q + "ans") != w THEN GOTO 410
405 LET nw = nw + 1
410 LET j = j + 1
415 GOTO 385
430 LET share = 0
435 LET rem = 0
440 IF nw == 0 THEN GOTO 460
445 LET share = b / nw
450 LET rem = b - share * nw
460 LET forf = 0
465 LET j = 0
470 IF j >= n THEN GOTO 600
475 LET q = p + ITOA(j) + "_"
480 LET cr = 0
485 IF md == 1 THEN GOTO 520
490 IF nr == 0 THEN GOTO 510
495 IF LOAD(q + "v") == 0 THEN GOTO 560
510 LET cr = bond
515 GOTO 560
520 IF LOAD(q + "v") == 0 THEN GOTO 560
530 IF LOAD(q + "ans") != w THEN GOTO 560
540 LET cr = share + bond
560 IF cr != 0 THEN GOTO 570
565 LET forf = forf + bond
570 STORE(q + "cr", cr)
580 LET j = j + 1
590 GOTO 470
600 STORE("carry", LOAD("carry") + forf + rem)
610 IF nw != 0 THEN GOTO 630
620 STORE("carry", LOAD("carry") + b)
630 STORE(p + "st", 1)
640 STORE(p + "win", w)
650 STORE(p + "nw", nw)
660 STORE(p + "disp", disp)
670 STORE(p + "refund", md - 1)
680 STORE(p + "share", share)
690 STORE(p + "rem", rem)
700 STORE(p + "forf", forf)
710 RETURN 0
900 RETURN 1
End Function

Function Withdraw(a Uint64, j Uint64) Uint64
10 DIM amt as Uint64
20 DIM p, q as String
30 IF a >= LOAD("na") THEN GOTO 900
40 LET p = "a" + ITOA(a) + "_"
50 IF LOAD(p + "st") != 1 THEN GOTO 900
60 IF j >= LOAD(p + "n") THEN GOTO 900
70 LET q = p + ITOA(j) + "_"
80 IF LOAD(q + "who") != SIGNER() THEN GOTO 900
90 IF LOAD(q + "x") != 0 THEN GOTO 900
100 LET amt = LOAD(q + "cr")
110 IF amt == 0 THEN GOTO 900
120 STORE(q + "x", 1)
130 SEND_DERO_TO_ADDRESS(SIGNER(), amt)
140 RETURN 0
900 RETURN 1
End Function
