package dvm

// R33 M6 gt_beacon.bas (dero-game-theory-rft §8.1, GT-B28; D-21 non-consensus: tests only).

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
)

func TestR33Beacon(t *testing.T) {
	w := gtNew(t, "owner", "alice", "eve")
	w.at(1000)
	sc := w.install("gt_beacon.bas", "owner")
	if w.read(sc, "nameHdr") == nil || w.read(sc, "descrHdr") == nil {
		t.Fatalf("install headers missing")
	}
	w.must(sc, "Publish", "owner", 0, nil, gtS("k", "pool_scid"), gtS("v", strings.Repeat("ab", 32)), gtU("from", 900), gtU("upto", 1000))
	w.must(sc, "Publish", "owner", 0, nil, gtS("k", "pool_scid"), gtS("v", strings.Repeat("cd", 32)), gtU("from", 900), gtU("upto", 1000))
	if w.readU(sc, "nent") != 1 || w.read(sc, "v_pool_scid") != strings.Repeat("cd", 32) || w.read(sc, "r_pool_scid") != "900-1000" {
		t.Fatalf("publish: nent %v v %v r %v", w.read(sc, "nent"), w.read(sc, "v_pool_scid"), w.read(sc, "r_pool_scid"))
	}
	w.mustFail(sc, "Publish", "eve", 0, nil, "owner only", gtS("k", "x"), gtS("v", "y"), gtU("from", 1), gtU("upto", 2))
	w.mustFail(sc, "Publish", "owner", 0, nil, "a future range is not measured", gtS("k", "x"), gtS("v", "y"), gtU("from", 1), gtU("upto", 1001))
	w.mustFail(sc, "Publish", "owner", 0, nil, "from > upto", gtS("k", "x"), gtS("v", "y"), gtU("from", 5), gtU("upto", 4))
	w.mustFail(sc, "Publish", "owner", 0, nil, "value too long", gtS("k", "x"), gtS("v", strings.Repeat("z", 513)), gtU("from", 1), gtU("upto", 2))
	w.mustFail(sc, "Publish", "owner", 0, nil, "key too long", gtS("k", strings.Repeat("k", 33)), gtS("v", "y"), gtU("from", 1), gtU("upto", 2))
	w.mustFail(sc, "Publish", "owner", 5, nil, "no deposit", gtS("k", "x"), gtS("v", "y"), gtU("from", 1), gtU("upto", 2))
	w.must(sc, "Subscribe", "alice", 0, nil)
	w.mustFail(sc, "Subscribe", "alice", 0, nil, "once")
	w.mustFail(sc, "Subscribe", "eve", 7, nil, "no deposit")
	if w.readU(sc, "nsub") != 1 || w.read(sc, "sub_"+hex.EncodeToString(w.addr["alice"].Compressed())) == nil {
		t.Fatalf("subscribe")
	}
	w.mustFail(sc, "Unsubscribe", "eve", 0, nil, "not subscribed")
	w.must(sc, "Unsubscribe", "alice", 0, nil)
	if w.readU(sc, "nsub") != 0 {
		t.Fatalf("unsubscribe")
	}
	w.mustFail(sc, "Initialize", "eve", 0, nil, "Initialize runs once")
	if w.held(sc, crypto.ZEROHASH) != 0 {
		t.Fatalf("the beacon holds DERO")
	}
	w.dumpGas()
}
