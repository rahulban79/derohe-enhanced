/* gt_beacon.bas — R33 M6: discovery beacon for the game suite (dero-game-theory-rft §8.1, D-GT-22, GT-B26/GT-B28).
   Pull-only outreach: the beacon is a public contract that interested users look up (explorers, DERO.GetSC, Gnomon,
   TELA/ART-NFA hosts read nameHdr/descrHdr/iconURLHdr); it never sends anything to anyone.
   - The owner publishes entries: Publish(k, v, from, upto) stores v under k with the height range the figure was
     measured over and the publish height; only MEASURED figures belong here (each reproducible from block headers
     and DERO.GetSC over [from, upto]); no promised returns. Keys and values are length-capped (storage gas).
   - Anyone may Subscribe() (opt-in list of addresses that want to hear about new games) and Unsubscribe().
   - No DERO is ever held: every entrypoint refuses a deposit, so nothing can be stuck (audit GT-A13).
   Initialize runs once (GT-A01) and refuses an anonymous owner (GT-A12).
*/
Function Initialize() Uint64
10 IF EXISTS("owner") == 1 THEN GOTO 900
20 IF IS_ADDRESS_VALID(SIGNER()) == 0 THEN GOTO 900
30 IF DEROVALUE() != 0 THEN GOTO 900
40 STORE("owner", SIGNER())
50 STORE("nameHdr", "DERO game-theory suite beacon")
60 STORE("descrHdr", "Verified-mining pool and game contracts: SCIDs, rules, measured figures with height ranges, how to join. Measured past figures only; no promised returns.")
70 STORE("iconURLHdr", "")
80 STORE("nent", 0)
90 STORE("nsub", 0)
100 RETURN 0
900 RETURN 1
End Function

Function Publish(k String, v String, from Uint64, upto Uint64) Uint64
10 IF DEROVALUE() != 0 THEN GOTO 900
20 IF LOAD("owner") != SIGNER() THEN GOTO 900
30 IF STRLEN(k) == 0 THEN GOTO 900
40 IF STRLEN(k) > 32 THEN GOTO 900
50 IF STRLEN(v) > 512 THEN GOTO 900
60 IF from > upto THEN GOTO 900
70 IF upto > BLOCK_HEIGHT() THEN GOTO 900
80 IF EXISTS("v_" + k) == 1 THEN GOTO 100
90 STORE("nent", LOAD("nent") + 1)
100 STORE("v_" + k, v)
110 STORE("r_" + k, ITOA(from) + "-" + ITOA(upto))
120 STORE("h_" + k, BLOCK_HEIGHT())
130 RETURN 0
900 RETURN 1
End Function

Function Subscribe() Uint64
10 IF DEROVALUE() != 0 THEN GOTO 900
20 IF IS_ADDRESS_VALID(SIGNER()) == 0 THEN GOTO 900
30 IF EXISTS("sub_" + HEX(SIGNER())) == 1 THEN GOTO 900
40 STORE("sub_" + HEX(SIGNER()), BLOCK_HEIGHT())
50 STORE("nsub", LOAD("nsub") + 1)
60 RETURN 0
900 RETURN 1
End Function

Function Unsubscribe() Uint64
10 IF DEROVALUE() != 0 THEN GOTO 900
20 IF EXISTS("sub_" + HEX(SIGNER())) == 0 THEN GOTO 900
30 DELETE("sub_" + HEX(SIGNER()))
40 STORE("nsub", LOAD("nsub") - 1)
50 RETURN 0
900 RETURN 1
End Function
