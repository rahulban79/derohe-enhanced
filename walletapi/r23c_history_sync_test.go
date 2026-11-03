package walletapi

// r23c (RPCWS23B-E): plan_history_sync finds the resume point after a reorg in one pass.

import (
	"errors"
	"fmt"
	"testing"

	"github.com/deroproject/derohe/rpc"
)

func hist_entries(topos ...int64) (e []rpc.Entry) {
	for i, t := range topos {
		e = append(e, rpc.Entry{TopoHeight: t, BlockHash: fmt.Sprintf("old-%d", t), TransactionPos: i})
	}
	return
}

// daemon answers "old-<topo>" (the wallet's block) except at the replaced topoheights; topos above tip fail
// like DERO.GetBlockHeaderByTopoHeight's "Too big topo height".
func hist_daemon(tip int64, replaced ...int64) (func(int64) (string, error), *[]int64) {
	var asked []int64
	return func(t int64) (string, error) {
		asked = append(asked, t)
		if t > tip {
			return "", fmt.Errorf("Too big topo height: %d, current blockchain height = %d", t, tip)
		}
		for _, r := range replaced {
			if r == t {
				return fmt.Sprintf("new-%d", t), nil
			}
		}
		return fmt.Sprintf("old-%d", t), nil
	}, &asked
}

func TestR23cHistorySyncDropsEveryReorgedGroupInOneCall(t *testing.T) {
	e := hist_entries(10, 20, 20, 30, 40)
	h, asked := hist_daemon(100, 30, 40)
	p, err := plan_history_sync(e, 5, 100, h)
	if err != nil || p.keep != 3 || p.start != 21 || p.calls != 3 {
		t.Fatalf("plan %+v err %v, want keep 3 start 21 calls 3 (asked %v)", p, err, *asked)
	}
}

func TestR23cHistorySyncGroupIsOneHeaderCall(t *testing.T) {
	e := hist_entries(10, 20, 20, 20)
	h, asked := hist_daemon(100, 20)
	p, err := plan_history_sync(e, 5, 100, h)
	if err != nil || p.keep != 1 || p.start != 11 || p.calls != 2 || len(*asked) != 2 || (*asked)[1] != 10 {
		t.Fatalf("plan %+v err %v asked %v, want keep 1 start 11 after asking 20 then 10", p, err, *asked)
	}
}

// the old loop discarded entry 0 unchecked when the mismatch left exactly one entry
func TestR23cHistorySyncKeepsEntryZeroAfterShallowReorg(t *testing.T) {
	e := hist_entries(10, 20)
	h, _ := hist_daemon(100, 20)
	p, err := plan_history_sync(e, 5, 100, h)
	if err != nil || p.keep != 1 || p.start != 11 {
		t.Fatalf("plan %+v err %v, want keep 1 start 11 (entry 0 is still on the chain)", p, err)
	}
}

// the old loop rescanned from registration whenever the only entry matched
func TestR23cHistorySyncSingleMatchingEntryResumes(t *testing.T) {
	e := hist_entries(10)
	h, _ := hist_daemon(100)
	p, err := plan_history_sync(e, 5, 100, h)
	if err != nil || p.keep != 1 || p.start != 11 || p.calls != 1 {
		t.Fatalf("plan %+v err %v, want keep 1 start 11", p, err)
	}
}

// an entry above the daemon's tip used to make every SyncHistory return early, forever
func TestR23cHistorySyncEntryAboveTipIsStale(t *testing.T) {
	e := hist_entries(10, 20, 150)
	h, _ := hist_daemon(100)
	p, err := plan_history_sync(e, 5, 100, h)
	if err != nil || p.keep != 2 || p.start != 21 {
		t.Fatalf("plan %+v err %v, want keep 2 start 21", p, err)
	}
}

func TestR23cHistorySyncErrorKeepsHistory(t *testing.T) {
	e := hist_entries(10, 20, 30)
	boom := errors.New("connection reset")
	p, err := plan_history_sync(e, 5, 100, func(t int64) (string, error) {
		if t == 20 {
			return "", boom
		}
		return fmt.Sprintf("new-%d", t), nil
	})
	if !errors.Is(err, boom) || p.keep != 2 {
		t.Fatalf("plan %+v err %v, want keep 2 (30 proven stale) and the error", p, err)
	}
}

func TestR23cHistorySyncPrunedAndAllStale(t *testing.T) {
	h, _ := hist_daemon(100, 20, 30)
	if p, err := plan_history_sync(hist_entries(3, 20, 30), 5, 100, h); err != nil || p.keep != 1 || p.start != 5 {
		t.Fatalf("pruned: plan %+v err %v, want keep 1 start 5 (registration)", p, err)
	}
	if p, err := plan_history_sync(hist_entries(20, 30), 5, 100, h); err != nil || p.keep != 0 || p.start != 5 {
		t.Fatalf("all stale: plan %+v err %v, want keep 0 start 5", p, err)
	}
	if p, err := plan_history_sync(nil, 5, 100, h); err != nil || p.keep != 0 || p.start != 5 || p.calls != 0 {
		t.Fatalf("empty: plan %+v err %v", p, err)
	}
}
