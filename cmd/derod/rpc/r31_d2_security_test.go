// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package rpc

// r31 dimension 2 (security + rpcws): dero-rft §7 B280 budget-census DERO.Subscribe, and the error-path finding of
// reorg_events.go enable_persist (a failed keep-aside of a corrupt record was dropped). In-process only.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/code"
)

func r31_events(n int) []string {
	ev := make([]string, n)
	for i := range ev {
		ev[i] = []string{"BlockInfo", "MiniBlock", "TxPool", "Reorg"}[i%4]
	}
	return ev
}

// r31_subscribe calls the handler with no server in the context: a call that passes the bound reaches the connection
// lookup, which needs a jrpc2 server, and panics; that is reported as "not refused".
func r31_subscribe(events []string) (err error, refused bool) {
	defer func() {
		if r := recover(); r != nil {
			err, refused = nil, false
		}
	}()
	_, err = Subscribe(context.Background(), Subscribe_Params{Events: events})
	var je *jrpc2.Error
	return err, errors.As(err, &je) && je.Code == code.InvalidParams
}

// TestR31SubscribeEventsCap: more than MAX_SUBSCRIBE_EVENTS names is refused with -32602 before any lookup and counted
// in rpc_param_bound_refused_total; MAX_SUBSCRIBE_EVENTS names (duplicates included) still parse as before.
func TestR31SubscribeEventsCap(t *testing.T) {
	before := param_bound_refused.Get()
	for _, n := range []int{MAX_SUBSCRIBE_EVENTS + 1, 1000, 1 << 20} {
		err, refused := r31_subscribe(r31_events(n))
		if !refused || !strings.Contains(err.Error(), "at most 16") {
			t.Fatalf("%d names: refused %v err %v", n, refused, err)
		}
	}
	if got := param_bound_refused.Get() - before; got != 3 {
		t.Fatalf("rpc_param_bound_refused_total moved by %d, want 3", got)
	}
	if MAX_SUBSCRIBE_EVENTS != 16 {
		t.Fatalf("cap %d", MAX_SUBSCRIBE_EVENTS)
	}
	bits, names, err := parse_subscriptions(r31_events(MAX_SUBSCRIBE_EVENTS))
	if err != nil || bits != SUB_ALL || len(names) != 4 {
		t.Fatalf("16 names: bits %b names %v err %v", bits, names, err)
	}
	if _, refused := r31_subscribe(r31_events(MAX_SUBSCRIBE_EVENTS)); refused {
		t.Fatalf("16 names refused")
	}
	// perf sanity (like-for-like, in-process): refusing a 1M-name list costs no per-name work
	big := r31_events(1 << 20)
	t0 := time.Now()
	for i := 0; i < 100; i++ {
		r31_subscribe(big)
	}
	if d := time.Since(t0); d > 50*time.Millisecond {
		t.Fatalf("100 refusals of 1M names took %v", d)
	}
}

// BenchmarkR31Subscribe: the bounded call (4 names) and the refused 1M-name call, next to the per-name parse the
// refusal skips (what a 1M-name call cost before r31).
func BenchmarkR31Subscribe(b *testing.B) {
	small, big := r31_events(4), r31_events(1<<20)
	b.Run("parse-4", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			parse_subscriptions(small)
		}
	})
	b.Run("refuse-1M", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			r31_subscribe(big)
		}
	})
	b.Run("parse-1M-before", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			parse_subscriptions(big)
		}
	})
}

// TestR31ReorgCorruptAsideErrorReported: a corrupt lifetime record that cannot be kept aside (its .corrupt name is
// taken by a non-empty directory) is reported to the caller; a new record still starts and is persisted.
func TestR31ReorgCorruptAsideErrorReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, REORG_MONITOR_FILE)
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(path+".corrupt", "x"), 0700); err != nil {
		t.Fatal(err)
	}
	r := new_reorg_tracker()
	err := r.enable_persist(path)
	if err == nil || !strings.Contains(err.Error(), "not kept aside") {
		t.Fatalf("enable_persist = %v, want the keep-aside error", err)
	}
	if st := r.stats(); st.Lifetime == nil || st.Lifetime.Starts != 1 || st.Lifetime.Reorgs != 0 {
		t.Fatalf("lifetime %+v", st.Lifetime)
	}
	if raw, err := os.ReadFile(path); err != nil || !strings.Contains(string(raw), `"starts"`) {
		t.Fatalf("new record not persisted: %s %v", raw, err)
	}
	// a clean keep-aside still returns nil (r25 behaviour)
	os.RemoveAll(path + ".corrupt")
	os.WriteFile(path, []byte("{not json"), 0600)
	if err := new_reorg_tracker().enable_persist(path); err != nil {
		t.Fatalf("clean keep-aside: %v", err)
	}
}
