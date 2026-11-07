// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8

package globals

// r28 (glue-global, B147): the one switch the landing patch flips. globals/globals.go is a decoder input content-pinned
// by forensics/r25, so its R27/R28 fixes were HELD in harness/loop/held/r28_globals_landing.patch (rft §7 B147). R28
// merge: LANDED (the patch moved to harness/loop/held/landed/; r25 replays from its pinned snapshot, pinsnap.py). While
// b147_landed is false, r28_globals_test.go pins the CURRENT (defective) outputs; the landing patch sets it to true in
// the same diff that changes globals.go, and the same tests then require the exact answers. A tree where the two
// disagree fails both ways: a fixed globals.go with the switch off, or the switch on over the old code.
const b147_landed = true
