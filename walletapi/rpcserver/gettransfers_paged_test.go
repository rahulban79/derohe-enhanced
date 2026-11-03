package rpcserver

import (
	"testing"

	"github.com/deroproject/derohe/rpc"
)

func mkEntries(n int) []rpc.Entry {
	e := make([]rpc.Entry, n)
	for i := range e {
		e[i].TopoHeight = int64(i)
	}
	return e
}

func TestPageEntries(t *testing.T) {
	all := mkEntries(250)
	p, total, more := pageEntries(all, 0, 0, false)
	if total != 250 || len(p) != GetTransfersPagedDefault || !more || p[0].TopoHeight != 0 {
		t.Fatalf("default page wrong: total=%d len=%d more=%v", total, len(p), more)
	}
	p, _, more = pageEntries(all, 200, 100, false)
	if len(p) != 50 || more || p[0].TopoHeight != 200 {
		t.Fatalf("last page wrong: len=%d more=%v", len(p), more)
	}
	p, _, _ = pageEntries(all, 0, 3, true)
	if len(p) != 3 || p[0].TopoHeight != 249 || p[2].TopoHeight != 247 {
		t.Fatalf("newest_first wrong: %+v", p)
	}
	p, _, more = pageEntries(all, 999, 10, false)
	if len(p) != 0 || more || p == nil {
		t.Fatalf("offset past end must give an empty (non-nil) page")
	}
	p, _, _ = pageEntries(all, 10, ^uint64(0), false) // overflow-safe and capped
	if len(p) != 240 {
		t.Fatalf("huge limit: len=%d", len(p))
	}
	if _, ok := WalletHandler["GetTransfersPaged"]; !ok {
		t.Fatalf("GetTransfersPaged not registered")
	}
}
