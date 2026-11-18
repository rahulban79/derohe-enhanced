/* gt_audit.bas -- R32a "audit bounty": pay for independent detection, DVM-BASIC. R33: audit fixes GT-A01..A17.
   GAME. The sponsor (owner) posts round a asking auditors for a deterministic digest over public chain data:
   (task, from, upto), e.g. task 1 = block-header digest, task 2 = emission digest. The contract never interprets
   the task. The sponsor's own answer is HIDDEN: Post stores commit = HEX(SHA256(answer + ":" + salt)).
   Auditors Enter(a, commit) with a bond during [start, start + commitw], where the auditor commit is
   HEX(SHA256(answer + ":" + salt + ":" + ADDRESS_STRING(SIGNER()))). In (start + commitw, start + commitw + revealw]
   the sponsor reveals (RevealSponsor) and auditors reveal (Reveal). An answer is 1..256 bytes (R33 A03; the
   playbook answers are 64-hex digests). Reveal tallies each answer by HEX(SHA3256(answer)), so Settle never
   compares answers pairwise: Settle is O(n) with a small constant (one credit per entrant).
   Settle(a), by anyone after the reveal window (R33 A04: a majority never overrides the sponsor and never
   slashes a minority):
   (1) the sponsor revealed and every revealed answer equals it: those auditors split the bounty equally and get
       their bond back; non-revealers forfeit their bond to carry; the remainder (bounty mod winners) goes to
       carry; nobody revealed -> the bounty goes to carry;
   (2) the sponsor revealed and at least one revealed answer differs from it: disputed = 1 (public, the detection
       signal), every bond is refunded and the bounty goes back to the sponsor (Reclaim, at once);
   (3) the sponsor did not reveal: refund = 1, every bond is refunded and the bounty goes back to the sponsor
       (Reclaim, only after the timeout).
   Sybils can therefore dispute a round (grief) but never profit from one.
   TIMEOUT (R33 A03). deadline = start + commitw + revealw + tmo (tmo = 2000 blocks). A round not settled by the
   deadline can still be settled until the first timeout withdrawal; from then on every entrant pulls its bond
   back with Withdraw and the sponsor pulls the whole bounty back with Reclaim; Settle is refused.
   carry is added to the bounty of the NEXT Post (only what has been settled before that Post). Settle stores
   credits only; each entrant pulls its credit with Withdraw(a, j) (pull payment, once, to SIGNER() only).
   THREAT MODEL. Copying: a copied commit cannot be revealed by another address (the address is inside the hash).
   Lazy auditor: the sponsor answer is hidden until after the commit window, so it cannot be copied in time.
   Sponsor withholding: path (3), refunds. Sybil majority: path (2), no profit. NOT prevented: collusion and
   bribery among auditors who all repeat a wrong sponsor answer; a grief-dispute by any single entrant.
   SIGNER() is known only at ring size 2: Enter/Reveal/Withdraw/owner calls must use ring size 2. Initialize runs
   once and never for an anonymous signer (R33 A01/A12); an entrypoint that expects no DERO refuses one (A13).
   STORED KEYS. Global: owner, bond, commitw, revealw, maxn (<= 32), tmo, frozen, na (rounds posted),
   carry (forfeits + remainders + unwon bounties awaiting the next Post).
   Round p = "a" + ITOA(a) + "_": p+task, p+from, p+upto, p+fund (DEROVALUE of Post), p+cin (carry joined),
   p+bounty (fund + cin), p+sc (sponsor commit), p+start (Post height), p+n (entrants), p+in<signer> (entry index),
   p+nr (revealed entrants), p+k<hex> (revealed count per answer hash), p+sa (sponsor answer, only if revealed),
   p+st (settled 1), p+to (timed out 1), p+win (sponsor answer on path 1, else ""), p+nw (winners),
   p+disp (1 = a revealed answer differs from the sponsor's), p+refund (1 = paths 2/3: bonds refunded), p+share,
   p+rem, p+forf, p+sb (bounty owed back to the sponsor), p+sbx (sponsor reclaimed 0/1).
   Entrant q = p + ITOA(j) + "_": q+who (signer), q+c (commit), q+v (revealed 0/1), q+ans and q+ah (answer and
   its HEX(SHA3256), only if revealed), q+cr (credit), q+x (withdrawn 0/1).
   Return 0 = success; any other value reverts.
*/
Function Initialize() Uint64
5 IF EXISTS("owner") == 1 THEN GOTO 900
6 IF IS_ADDRESS_VALID(SIGNER()) == 0 THEN GOTO 900
7 IF DEROVALUE() != 0 THEN GOTO 900
10 STORE("owner", SIGNER())
20 STORE("bond", 10000)
30 STORE("commitw", 20)
40 STORE("revealw", 20)
50 STORE("maxn", 16)
55 STORE("tmo", 2000)
60 STORE("frozen", 0)
70 STORE("na", 0)
80 STORE("carry", 0)
90 RETURN 0
900 RETURN 1
End Function

Function SetParams(bond Uint64, commitw Uint64, revealw Uint64, maxn Uint64) Uint64
10 IF LOAD("owner") != SIGNER() THEN GOTO 900
20 IF LOAD("frozen") != 0 THEN GOTO 900
25 IF DEROVALUE() != 0 THEN GOTO 900
30 IF bond == 0 || commitw == 0 || revealw == 0 THEN GOTO 900
35 IF bond > 1000000000000 || commitw > 1000000 || revealw > 1000000 THEN GOTO 900
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
15 IF DEROVALUE() != 0 THEN GOTO 900
17 IF LOAD("frozen") != 0 THEN GOTO 900
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
205 STORE(p + "nr", 0)
210 STORE(p + "st", 0)
212 STORE(p + "to", 0)
214 STORE(p + "sb", 0)
216 STORE(p + "sbx", 0)
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
25 IF DEROVALUE() != 0 THEN GOTO 900
30 IF LOAD("owner") != SIGNER() THEN GOTO 900
40 IF a >= LOAD("na") THEN GOTO 900
50 LET p = "a" + ITOA(a) + "_"
60 IF EXISTS(p + "sa") == 1 THEN GOTO 900
70 LET t = LOAD(p + "start") + LOAD("commitw")
80 IF BLOCK_HEIGHT() <= t THEN GOTO 900
90 IF BLOCK_HEIGHT() > t + LOAD("revealw") THEN GOTO 900
95 IF STRLEN(answer) == 0 || STRLEN(answer) > 256 THEN GOTO 900
100 IF HEX(SHA256(answer + ":" + salt)) != LOAD(p + "sc") THEN GOTO 900
110 STORE(p + "sa", answer)
120 RETURN 0
900 RETURN 1
End Function

Function Reveal(a Uint64, j Uint64, answer String, salt String) Uint64
10 DIM t as Uint64
20 DIM p, q, h as String
25 IF DEROVALUE() != 0 THEN GOTO 900
30 IF a >= LOAD("na") THEN GOTO 900
40 LET p = "a" + ITOA(a) + "_"
50 IF j >= LOAD(p + "n") THEN GOTO 900
60 LET q = p + ITOA(j) + "_"
70 IF LOAD(q + "who") != SIGNER() THEN GOTO 900
80 IF LOAD(q + "v") != 0 THEN GOTO 900
90 LET t = LOAD(p + "start") + LOAD("commitw")
100 IF BLOCK_HEIGHT() <= t THEN GOTO 900
110 IF BLOCK_HEIGHT() > t + LOAD("revealw") THEN GOTO 900
115 IF STRLEN(answer) == 0 || STRLEN(answer) > 256 THEN GOTO 900
120 IF HEX(SHA256(answer + ":" + salt + ":" + ADDRESS_STRING(SIGNER()))) != LOAD(q + "c") THEN GOTO 900
130 STORE(q + "v", 1)
140 STORE(q + "ans", answer)
145 LET h = HEX(SHA3256(answer))
150 STORE(q + "ah", h)
155 IF EXISTS(p + "k" + h) == 1 THEN GOTO 165
160 STORE(p + "k" + h, 0)
165 STORE(p + "k" + h, LOAD(p + "k" + h) + 1)
170 STORE(p + "nr", LOAD(p + "nr") + 1)
180 RETURN 0
900 RETURN 1
End Function

Function Settle(a Uint64) Uint64
10 DIM n, j, nr, m, md, nw, b, bond, share, rem, forf, cr, disp as Uint64
20 DIM p, q, h, w as String
25 IF DEROVALUE() != 0 THEN GOTO 900
30 IF a >= LOAD("na") THEN GOTO 900
40 LET p = "a" + ITOA(a) + "_"
50 IF LOAD(p + "st") != 0 THEN GOTO 900
55 IF LOAD(p + "to") != 0 THEN GOTO 900
60 IF BLOCK_HEIGHT() <= LOAD(p + "start") + LOAD("commitw") + LOAD("revealw") THEN GOTO 900
70 LET n = LOAD(p + "n")
80 LET bond = LOAD("bond")
90 LET b = LOAD(p + "bounty")
100 LET nr = LOAD(p + "nr")
110 LET disp = 0
120 LET md = 2
130 LET nw = 0
135 LET w = ""
140 IF EXISTS(p + "sa") == 0 THEN GOTO 200
150 LET h = HEX(SHA3256(LOAD(p + "sa")))
160 LET m = 0
165 IF EXISTS(p + "k" + h) == 0 THEN GOTO 175
170 LET m = LOAD(p + "k" + h)
175 IF nr == m THEN GOTO 190
180 LET disp = 1
185 GOTO 200
190 LET md = 1
195 LET nw = m
197 LET w = LOAD(p + "sa")
200 LET share = 0
205 LET rem = 0
210 IF nw == 0 THEN GOTO 230
215 LET share = b / nw
220 LET rem = b - share * nw
230 LET forf = 0
235 LET j = 0
240 IF j >= n THEN GOTO 300
245 LET q = p + ITOA(j) + "_"
250 LET cr = bond
255 IF md == 2 THEN GOTO 280
260 LET cr = 0
265 IF LOAD(q + "v") == 0 THEN GOTO 275
270 LET cr = share + bond
272 GOTO 280
275 LET forf = forf + bond
280 STORE(q + "cr", cr)
285 LET j = j + 1
290 GOTO 240
300 STORE("carry", LOAD("carry") + forf + rem)
305 IF md == 2 THEN GOTO 320
310 IF nw != 0 THEN GOTO 330
315 STORE("carry", LOAD("carry") + b)
317 GOTO 330
320 STORE(p + "sb", b)
330 STORE(p + "st", 1)
340 STORE(p + "win", w)
350 STORE(p + "nw", nw)
360 STORE(p + "disp", disp)
370 STORE(p + "refund", md - 1)
380 STORE(p + "share", share)
390 STORE(p + "rem", rem)
400 STORE(p + "forf", forf)
410 RETURN 0
900 RETURN 1
End Function

Function Withdraw(a Uint64, j Uint64) Uint64
10 DIM amt as Uint64
20 DIM p, q as String
25 IF DEROVALUE() != 0 THEN GOTO 900
30 IF a >= LOAD("na") THEN GOTO 900
40 LET p = "a" + ITOA(a) + "_"
60 IF j >= LOAD(p + "n") THEN GOTO 900
70 LET q = p + ITOA(j) + "_"
80 IF LOAD(q + "who") != SIGNER() THEN GOTO 900
90 IF LOAD(q + "x") != 0 THEN GOTO 900
95 IF LOAD(p + "st") == 1 THEN GOTO 150
100 IF BLOCK_HEIGHT() <= LOAD(p + "start") + LOAD("commitw") + LOAD("revealw") + LOAD("tmo") THEN GOTO 900
110 STORE(p + "to", 1)
120 LET amt = LOAD("bond")
130 GOTO 170
150 LET amt = LOAD(q + "cr")
160 IF amt == 0 THEN GOTO 900
170 STORE(q + "x", 1)
180 SEND_DERO_TO_ADDRESS(SIGNER(), amt)
190 RETURN 0
900 RETURN 1
End Function

Function Reclaim(a Uint64) Uint64
10 DIM amt, dl as Uint64
20 DIM p as String
25 IF DEROVALUE() != 0 THEN GOTO 900
30 IF LOAD("owner") != SIGNER() THEN GOTO 900
40 IF a >= LOAD("na") THEN GOTO 900
50 LET p = "a" + ITOA(a) + "_"
60 IF LOAD(p + "sbx") != 0 THEN GOTO 900
70 LET dl = LOAD(p + "start") + LOAD("commitw") + LOAD("revealw") + LOAD("tmo")
80 IF LOAD(p + "st") == 1 THEN GOTO 120
90 IF BLOCK_HEIGHT() <= dl THEN GOTO 900
100 STORE(p + "to", 1)
105 LET amt = LOAD(p + "bounty")
110 GOTO 160
120 LET amt = LOAD(p + "sb")
130 IF amt == 0 THEN GOTO 900
140 IF LOAD(p + "disp") == 1 THEN GOTO 160
150 IF BLOCK_HEIGHT() <= dl THEN GOTO 900
160 STORE(p + "sbx", 1)
170 SEND_DERO_TO_ADDRESS(SIGNER(), amt)
180 RETURN 0
900 RETURN 1
End Function
