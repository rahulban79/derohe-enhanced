// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package rpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/creachadair/jrpc2/code"

	"github.com/deroproject/derohe/glue/txprecheck"
	"github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

// ---- jrpc2 built-ins ----

// A remote /json_rpc caller gets method-not-found for rpc.serverInfo (no method list, start time or counters that
// include loopback traffic), scored as an unknown name; loopback keeps the built-in.
func TestR23bRemoteHTTPNoServerInfo(t *testing.T) {
	fresh_abuse(t)
	si := `{"jsonrpc":"2.0","id":1,"method":"rpc.serverInfo"}`
	for i := 0; i < 3; i++ {
		w := post_from("198.51.100.120:1000", si)
		b := w.Body.String()
		if strings.Contains(b, "startTime") || strings.Contains(b, "rpc.requests") || strings.Contains(b, "DERO.GetInfo") {
			t.Fatalf("remote caller read server info: %s", b)
		}
		if c, _ := decode_rpc_error(t, b); c != int(code.MethodNotFound) {
			t.Fatalf("remote rpc.serverInfo: code %d body %s", c, b)
		}
	}
	batch := `[{"jsonrpc":"2.0","id":1,"method":"DERO.Ping"},{"jsonrpc":"2.0","id":2,"method":"rpc.serverInfo"}]`
	if b := post_from("198.51.100.121:1000", batch).Body.String(); strings.Contains(b, "startTime") || strings.Contains(b, "Pong") {
		t.Fatalf("a batch naming a built-in must be refused whole: %s", b)
	}
	if b := post_from("127.0.0.1:1000", si).Body.String(); !strings.Contains(b, "startTime") {
		t.Fatalf("loopback must keep rpc.serverInfo: %s", b)
	}
	rpc_abuse.mu.Lock()
	sc := rpc_abuse.m["198.51.100.120"].score
	rpc_abuse.mu.Unlock()
	if sc < 2*ABUSE_PTS_UNKNOWN_METHOD {
		t.Fatalf("remote built-in probes must score as unknown names: score %.1f", sc)
	}
}

// with the abuse guard off, a remote caller still gets no built-ins
func TestR23bRemoteHTTPNoServerInfoGuardOff(t *testing.T) {
	tb := fresh_abuse(t)
	tb.enabled = false
	b := post_from("198.51.100.122:1000", `{"jsonrpc":"2.0","id":1,"method":"rpc.serverInfo"}`).Body.String()
	if strings.Contains(b, "startTime") {
		t.Fatalf("guard off: remote caller read server info: %s", b)
	}
}

// websocket: a remote (or cross-site) socket's server has the built-ins disabled, so rpc.serverInfo reaches the
// charged and scored assigner and is unknown there; a loopback socket keeps them
func TestR23bWSRemoteNoServerInfo(t *testing.T) {
	fresh_abuse(t)
	call := func(c *ws_client, assigner jrpc2.Assigner) (string, error) {
		cli, srv := channel.Direct()
		s := jrpc2.NewServer(assigner, ws_server_options(c)).Start(srv)
		defer s.Stop()
		cl := jrpc2.NewClient(cli, nil)
		defer cl.Close()
		var out json.RawMessage
		err := cl.CallResult(context.Background(), "rpc.serverInfo", nil, &out)
		return string(out), err
	}
	for i := 0; i < 3; i++ {
		remote := &ws_client{abuse_key: fmt.Sprintf("198.51.100.%d", 130+i)}
		out, err := call(remote, remote_assigner{c: remote, next: d})
		if err == nil || strings.Contains(out, "startTime") {
			t.Fatalf("remote socket read server info: %s %v", out, err)
		}
		if e, ok := err.(*jrpc2.Error); !ok || e.Code != code.MethodNotFound {
			t.Fatalf("remote socket rpc.serverInfo: %v", err)
		}
		rpc_abuse.mu.Lock()
		e := rpc_abuse.m[remote.abuse_key]
		rpc_abuse.mu.Unlock()
		if e == nil || e.score < ABUSE_PTS_UNKNOWN_METHOD {
			t.Fatal("remote socket rpc.serverInfo was neither charged nor scored")
		}
		foreign := &ws_client{foreign: true}
		if out, err := call(foreign, d); err == nil || strings.Contains(out, "startTime") {
			t.Fatalf("cross-site socket read server info: %s %v", out, err)
		}
		local := &ws_client{}
		if out, err := call(local, d); err != nil || !strings.Contains(out, "startTime") {
			t.Fatalf("loopback socket must keep rpc.serverInfo: %s %v", out, err)
		}
	}
	if options.DisableBuiltin || !remote_options.DisableBuiltin {
		t.Fatal("option split wrong")
	}
}

// ---- global anomaly budget ----

// A fleet of addresses each staying under the per-key ban line is not banned while the global anomaly budget lasts;
// once it is spent (a surge) the same per-key rate ends in bans. Honest keys with no anomalies are untouched.
func TestR23bGlobalAnomalySurge(t *testing.T) {
	for round := 0; round < 3; round++ {
		tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
		now := time.Unix(1700000000, 0)
		// 1000 keys, each 8 unknown names 10 s apart (6.9/min): alone a key peaks at score 27.6 of 100 (5 pts, 60 s
		// half-life); at the surge factor 4 the same key reaches 110 and is banned
		const keys, per = 1000, 8
		banned_keys := map[string]bool{}
		for step := 0; step < per; step++ {
			for k := 0; k < keys; k++ {
				at := now.Add(time.Duration(step)*10*time.Second + time.Duration(k)*time.Millisecond)
				key := fmt.Sprintf("203.0.113.%d/%d", k%250, k)
				if v, _ := tb.admit(key, "Probe.N", true, at); v == abuse_banned {
					banned_keys[key] = true
				}
			}
		}
		banned := len(banned_keys)
		t.Logf("round %d: %d of %d keys banned", round, banned, keys)
		if banned < keys/2 {
			t.Fatal("a distributed probe of 8000 unknown names in 70 s banned nobody: no global budget")
		}
		// control: one key at the same per-key rate on a quiet node is never banned
		quiet := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
		for step := 0; step < per; step++ {
			if v, _ := quiet.admit("192.0.2.200", "Probe.N", true, now.Add(time.Duration(step)*10*time.Second)); v != abuse_ok {
				t.Fatalf("a quiet node banned a key at 6.9 unknown names/min: %v", v)
			}
		}
		// honest calls during the surge are never scored
		for i := 0; i < 50; i++ {
			if v, _ := tb.admit("192.0.2.201", "DERO.GetInfo", false, now.Add(61*time.Second)); v != abuse_ok {
				t.Fatalf("honest known-method call refused during a surge: %v", v)
			}
		}
		if tb.surge_gauge(now.Add(61*time.Second)) != 1 {
			t.Fatal("surge gauge not raised")
		}
		if tb.surge_gauge(now.Add(61*time.Second+ABUSE_GLOBAL_ANOMALY_BURST/ABUSE_GLOBAL_ANOMALY_RATE*time.Second)) != 0 {
			t.Fatal("surge gauge not cleared after the bucket refilled")
		}
	}
}

// bad-request anomalies (observe) draw on the same budget
func TestR23bGlobalSurgeCountsBadRequests(t *testing.T) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	for i := 0; i < int(ABUSE_GLOBAL_ANOMALY_BURST)+5; i++ {
		tb.observe(fmt.Sprintf("198.%d.%d.1", 18+i/250, i%250), code.InvalidParams, now) // r23c: one key per /24, so no aggregate ban preempts the budget
	}
	if tb.surge_gauge(now) != 1 {
		t.Fatal("invalid-params replies from many keys did not raise the surge")
	}
	tb.observe("198.30.99.1", code.InvalidParams, now) // r23c: a key (and /24) outside the loop's range
	tb.mu.Lock()
	sc := tb.m["198.30.99.1"].score
	tb.mu.Unlock()
	if sc != ABUSE_PTS_BAD_REQUEST*ABUSE_SURGE_FACTOR {
		t.Fatalf("surge score %.1f, want %.1f", sc, ABUSE_PTS_BAD_REQUEST*ABUSE_SURGE_FACTOR)
	}
	tb.observe("198.18.99.2", code.Code(-32098), now) // an ordinary handler error never draws or multiplies
	tb.mu.Lock()
	sc = tb.m["198.18.99.2"].score
	tb.mu.Unlock()
	if sc != ABUSE_PTS_OTHER_ERROR {
		t.Fatalf("ordinary error score %.2f during a surge, want %.2f", sc, ABUSE_PTS_OTHER_ERROR)
	}
}

// ---- SendRawTransaction header peek ----

func with_send_tip(t *testing.T, h int64) {
	old := send_tx_tip
	send_tx_tip = func() int64 { return h }
	t.Cleanup(func() { send_tx_tip = old })
}

func fixture_tx_hex(t *testing.T, typ byte, height uint64) string {
	tx := transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, TransactionType: transaction.NORMAL, Height: height}}
	b := tx.Serialize()
	b = append(b, make([]byte, 128)...) // >= 99 bytes; the body is never decoded on these paths
	b[3] = typ
	return hex.EncodeToString(b)
}

// An unknown transaction type no longer panics inside Deserialize (recovered, a full stack logged at ERROR per call)
// and an out-of-window height is refused from the header, before any point is decoded (chain is nil in this test:
// reaching the pool would panic and be counted as a recovered panic).
func TestR23bSendRawTransactionHeaderPeek(t *testing.T) {
	panics := metrics.Set.GetOrCreateCounter("rpc_recovered_panics_total")
	with_send_tip(t, 1000)
	for i := 0; i < 3; i++ {
		before := panics.Get()
		_, err := SendRawTransaction(context.Background(), rpc.SendRawTransaction_Params{Tx_as_hex: fixture_tx_hex(t, 9, 1000)})
		if err == nil || !strings.Contains(err.Error(), txprecheck.ErrHeader.Error()) || panics.Get() != before {
			t.Fatalf("unknown type: err %v, recovered panics +%d", err, panics.Get()-before)
		}
		_, err = SendRawTransaction(context.Background(), rpc.SendRawTransaction_Params{Tx_as_hex: fixture_tx_hex(t, byte(transaction.NORMAL), 1000-12)})
		if err == nil || !strings.Contains(err.Error(), txprecheck.ErrWindow.Error()) || panics.Get() != before {
			t.Fatalf("stale height: err %v, recovered panics +%d", err, panics.Get()-before)
		}
		_, err = SendRawTransaction(context.Background(), rpc.SendRawTransaction_Params{Tx_as_hex: fixture_tx_hex(t, byte(transaction.NORMAL), 1001)})
		if err == nil || !strings.Contains(err.Error(), txprecheck.ErrWindow.Error()) {
			t.Fatalf("future height: err %v", err)
		}
		if strings.Contains(err.Error(), ".go") {
			t.Fatalf("refusal leaks internals: %v", err)
		}
	}
}

func BenchmarkR23bSendRawTxStaleRefusal(b *testing.B) {
	old := send_tx_tip
	send_tx_tip = func() int64 { return 1000 }
	defer func() { send_tx_tip = old }()
	p := rpc.SendRawTransaction_Params{Tx_as_hex: fixture_tx_hex(nil, byte(transaction.NORMAL), 900)}
	for i := 0; i < b.N; i++ {
		if _, err := SendRawTransaction(context.Background(), p); err == nil {
			b.Fatal("accepted")
		}
	}
}

var _ = http.StatusOK

// r23b merge (SEC23b-1 fix): the live /ws handler builds its jrpc2 server with ws_server_options(client), so the remote
// and cross-site sockets get the options without rpc.serverInfo (TestR23bWSRemoteNoServerInfo tests those options)
func TestR23bWSHandlerUsesSocketOptions(t *testing.T) {
	src, err := os.ReadFile("websocket_server.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	if !strings.Contains(s, "ws_server = jrpc2.NewServer(assigner, ws_server_options(client))") {
		t.Fatal("ws_handler does not build its server with ws_server_options(client)")
	}
	if strings.Count(s, "jrpc2.NewServer(") != 1 {
		t.Fatalf("websocket_server.go builds %d jrpc2 servers, want exactly the ws_handler one", strings.Count(s, "jrpc2.NewServer("))
	}
}
