package rpc

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/graviton"
)

func be(v uint64) []byte { var b [8]byte; binary.BigEndian.PutUint64(b[:], v); return b[:] }

func TestAuditSCBalances(t *testing.T) {
	store, err := graviton.NewMemStore()
	if err != nil {
		t.Fatal(err)
	}
	ss, _ := store.LoadSnapshot(0)
	meta, _ := ss.GetTree(config.SC_META)
	var trees []*graviton.Tree
	balances := []uint64{500, 7_000_000, 0, 42}
	var zero [32]byte
	for i, bal := range balances {
		var scid [32]byte
		scid[0], scid[31] = 0x80+byte(i), 0x90
		meta.Put(scid[:], []byte{1})
		tr, _ := ss.GetTree(string(scid[:]))
		if bal != 0 || i != 2 { // SC #2 never received DERO: no balance key at all
			tr.Put(zero[:], be(bal))
		}
		tr.Put([]byte("C"), []byte("code")) // other variables are ignored
		trees = append(trees, tr)
	}
	if _, err := graviton.Commit(append(trees, meta)...); err != nil {
		t.Fatal(err)
	}
	ss, _ = store.LoadSnapshot(0)
	n, total, of, top, err := audit_sc_balances(ss, 2)
	if err != nil || n != 4 || total != 7_000_542 || of || len(top) != 2 || top[0].Balance != 7_000_000 || top[1].Balance != 500 {
		t.Fatalf("n=%d total=%d overflow=%v top=%+v err=%v", n, total, of, top, err)
	}
	if v := supply_verdict(total, 7_000_541, false); !strings.HasPrefix(v, "VIOLATION") {
		t.Fatalf("excess not flagged: %s", v)
	}
	if v := supply_verdict(total, 7_000_542, false); !strings.HasPrefix(v, "consistent") {
		t.Fatalf("equal flagged: %s", v)
	}
	if v := supply_verdict(1, 1<<62, true); !strings.HasPrefix(v, "VIOLATION") {
		t.Fatalf("overflow not flagged")
	}
}
