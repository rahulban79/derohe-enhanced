package rpc

// r26 (node-rpc) tests: typed answers for NameToAddress of an unknown name (B100), GetEncryptedBalance with the
// topoheight field omitted on a pruned node (B100), the GetRandomAddress decoy window on short chains and at the
// prune point (B43 root cause, B100), and the topo-addressed explorer methods: unknown parameter names refused and
// a read below the prune point typed (B104). Pruned nodes are forged on simulator chains (state_prune_floor, or a
// topo record rewritten to the pruned shape: zero block id, a state version).

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/code"
	"github.com/creachadair/jrpc2/server"

	"github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/rpc"
)

func r26_local(t *testing.T) server.Local {
	t.Helper()
	loc := server.NewLocal(d, &server.LocalOptions{Server: options})
	t.Cleanup(func() { loc.Close() })
	return loc
}

// call sends raw JSON params (so a field can be left out or misspelled, which a Go struct cannot express)
func r26_call(t *testing.T, loc server.Local, method, params string) (*jrpc2.Response, error) {
	t.Helper()
	return loc.Client.Call(context.Background(), method, json.RawMessage(params))
}

func r26_code(err error) code.Code {
	var je *jrpc2.Error
	if errors.As(err, &je) {
		return je.Code
	}
	return code.FromError(err)
}

// B100: a name nobody registered answered the raw graviton error ("leaf not found") as untyped -32098.
func TestR26NameToAddressUnknownIsNotFound(t *testing.T) {
	_, _, done := r25_sim(t, 3)
	defer done()
	nf := metrics.Set.GetOrCreateCounter(`rpc_name_not_found_total`)
	n0, p0 := nf.Get(), recovered_panics()

	_, err := NameToAddress(context.Background(), rpc.NameToAddress_Params{Name: "nobody-registered-this", TopoHeight: -1})
	var ne *NotFoundError
	if !errors.As(err, &ne) || ne.What != "name" || ne.ID != "nobody-registered-this" {
		t.Fatalf("unknown name: err %v (%T), want a NotFoundError", err, err)
	}
	if code.FromError(err) != RPC_CODE_NOT_FOUND || err.Error() != "name not found: nobody-registered-this" {
		t.Fatalf("code %v message %q", code.FromError(err), err.Error())
	}
	if nf.Get() != n0+1 || recovered_panics() != p0 {
		t.Fatalf("name_not_found +%d (want 1), recovered panics +%d (want 0)", nf.Get()-n0, recovered_panics()-p0)
	}
	// through the method table, both spellings: the client sees -32032, not -32098
	loc := r26_local(t)
	for _, m := range []string{"DERO.NameToAddress", "nametoaddress"} {
		_, err := r26_call(t, loc, m, `{"name":"nobody-registered-this","topoheight":-1}`)
		if r26_code(err) != RPC_CODE_NOT_FOUND || !strings.Contains(err.Error(), "name not found: nobody-registered-this") {
			t.Fatalf("%s: err %v (code %v), want -32032", m, err, r26_code(err))
		}
	}
	// the echoed name is bounded
	_, err = NameToAddress(context.Background(), rpc.NameToAddress_Params{Name: strings.Repeat("x", 500)})
	if !errors.As(err, &ne) || len(ne.ID) != NAME_ECHO_MAX+3 {
		t.Fatalf("long name echoed with %d bytes: %v", len(ne.ID), err)
	}
}

// name_lookup_error passes every other store error through unchanged (a store fault must not read as "not found")
func TestR26NameLookupErrorClasses(t *testing.T) {
	if name_lookup_error("a", nil) != nil {
		t.Fatal("found name: error")
	}
	other := errors.New("disk on fire")
	if err := name_lookup_error("a", other); err != other {
		t.Fatalf("store error rewritten: %v", err)
	}
}

// B100: the wallet sends topoheight -1 (walletapi/ring_fetch.go); a client that leaves the field out sends JSON 0,
// which the handler reads as genesis. On a pruned node that is a typed -32031 refusal before any store read (the r25
// B85 guard), never the old panic path; -1 still answers at the tip.
func TestR26EncryptedBalanceOmittedTopoheightOnPrunedNode(t *testing.T) {
	c, addr, done := r25_sim(t, 6)
	defer done()
	forge_prune_floor(t, 3)
	loc := r26_local(t)
	p0 := recovered_panics()
	for _, m := range []string{"DERO.GetEncryptedBalance", "getencryptedbalance"} {
		_, err := r26_call(t, loc, m, `{"address":"`+addr+`"}`)
		if r26_code(err) != RPC_CODE_STATE_UNAVAILABLE ||
			!strings.Contains(err.Error(), "state not available: topoheight 0 is below pruned topoheight 3") {
			t.Fatalf("%s without topoheight: err %v (code %v), want -32031 at topoheight 0", m, err, r26_code(err))
		}
		rsp, err := r26_call(t, loc, m, `{"address":"`+addr+`","topoheight":-1}`)
		if err != nil {
			t.Fatalf("%s at -1: %v", m, err)
		}
		var res rpc.GetEncryptedBalance_Result
		if err := rsp.UnmarshalResult(&res); err != nil || res.Status != "OK" || res.Topoheight != c.Load_TOPO_HEIGHT() {
			t.Fatalf("%s at -1: %+v %v", m, res, err)
		}
	}
	if recovered_panics() != p0 {
		t.Fatalf("recovered panics +%d", recovered_panics()-p0)
	}
}

// B43 root cause (r26 decode of both captured simulator failures) + B100 prune clamp: the decoy window.
func TestR26DecoyWindowTopo(t *testing.T) {
	cases := []struct{ top, floor, want int64 }{
		{10, 0, 5},                        // upstream: 10 (no window up to topoheight 100): the B43 failures
		{100, 0, 95},                      // upstream: 100
		{101, 0, 96},                      // upstream: 96 (mainnet-shaped: unchanged)
		{7_800_000, 7_498_540, 7_799_995}, // live-shaped: unchanged
		{3, 0, 0},                         // a chain shorter than the window compares against genesis
		{7_498_542, 7_498_540, 7_498_540}, // within 5 of the prune point: clamped to it, never a pruned topoheight
		{0, 0, 0},
		{5, 9, 5}, // a floor above the top (forged store) never yields a topoheight above the top
	}
	for _, c := range cases {
		if got := decoy_window_topo(c.top, c.floor); got != c.want {
			t.Errorf("decoy_window_topo(%d, %d) = %d, want %d", c.top, c.floor, got, c.want)
		}
	}
}

// On a 12-block simulator chain every block is mined by the genesis miner, so its balance leaf changes at every
// topoheight: it must never be offered as a decoy (a wallet building at tip-3 with the tip's balance of it makes a
// ring the chain does not have). Before r26 the window was off below topoheight 100 and the miner came back in about
// 7% of the calls (1 of ~1,327 accounts, ~100 accepted draws per call): 300 calls miss it with p ~ 1e-10.
func TestR26RandomAddressNeverOffersAFreshlyChangedAccount(t *testing.T) {
	_, miner, done := r25_sim(t, 12)
	defer done()
	mined, err := rpc.NewAddress(miner)
	if err != nil {
		t.Fatal(err)
	}
	p0 := recovered_panics()
	offered := 0
	for i := 0; i < 300; i++ {
		res, err := GetRandomAddress(context.Background(), rpc.GetRandomAddress_Params{})
		if err != nil || res.Status != "OK" || len(res.Address) == 0 {
			t.Fatalf("call %d: %d addresses, err %v", i, len(res.Address), err)
		}
		offered += len(res.Address)
		for _, a := range res.Address {
			if ad, err := rpc.NewAddress(a); err == nil && string(ad.PublicKey.EncodeCompressed()) == string(mined.PublicKey.EncodeCompressed()) {
				t.Fatalf("call %d offered the miner, whose balance changed in each of the last 5 blocks", i)
			}
		}
	}
	if recovered_panics() != p0 || offered == 0 {
		t.Fatalf("recovered panics +%d, offered %d", recovered_panics()-p0, offered)
	}
	// at the prune point the window is clamped: still OK, no panic
	forge_prune_floor(t, chain.Load_TOPO_HEIGHT()-2)
	if res, err := GetRandomAddress(context.Background(), rpc.GetRandomAddress_Params{}); err != nil || res.Status != "OK" {
		t.Fatalf("with the prune point 2 below the tip: %v", err)
	}
}

// B104: unknown parameter names on the topo-addressed explorer methods are -32602, not a silent topoheight 0.
func TestR26ExplorerUnknownParamsRefused(t *testing.T) {
	_, _, done := r25_sim(t, 5)
	defer done()
	loc := r26_local(t)
	for _, c := range []struct{ m, bad, good string }{
		{"DERO.GetBlockHeadersRange", `{"start":1,"end":2}`, `{"start_topoheight":1,"end_topoheight":2}`},
		{"DERO.GetMiniBlocks", `{"topo":2}`, `{"topoheight":2}`},
		{"DERO.GetDifficultyHistory", `{"count":3,"end":4}`, `{"count":3,"end_topoheight":4}`},
	} {
		_, err := r26_call(t, loc, c.m, c.bad)
		// jrpc2's handler wrapper (vendor handler.go:195) re-wraps the decoder error and drops its data, so the client
		// sees "-32602 invalid parameters" without the field name: enough to stop a probe from reading topoheight 0
		if r26_code(err) != code.InvalidParams || !strings.Contains(err.Error(), "invalid parameters") {
			t.Fatalf("%s %s: err %v (code %v), want -32602 invalid parameters", c.m, c.bad, err, r26_code(err))
		}
		if _, err := r26_call(t, loc, c.m, c.good); err != nil {
			t.Fatalf("%s %s: %v", c.m, c.good, err)
		}
	}
	// empty params stay accepted (upstream-style clients and the r23 batch test send {})
	if _, err := r26_call(t, loc, "DERO.GetBlockHeadersRange", `{}`); err != nil {
		t.Fatalf("empty params: %v", err)
	}
}

// B104: a range below the prune point is refused typed, before any read; GetDifficultyHistory clips a window that
// reaches below it and refuses one that ends below it.
func TestR26ExplorerBelowPrunePointTyped(t *testing.T) {
	c, _, done := r25_sim(t, 8)
	defer done()
	forge_prune_floor(t, 3)
	loc := r26_local(t)
	p0 := recovered_panics()
	refused := func(m string) uint64 {
		return metrics.Set.GetOrCreateCounter(`rpc_state_unavailable_total{method="` + m + `"}`).Get()
	}
	h0 := refused("GetBlockHeadersRange")
	_, err := r26_call(t, loc, "DERO.GetBlockHeadersRange", `{"start_topoheight":1,"end_topoheight":4}`)
	if r26_code(err) != RPC_CODE_STATE_UNAVAILABLE || !strings.Contains(err.Error(), "topoheight 1 is below pruned topoheight 3") {
		t.Fatalf("headers 1..4 with prune point 3: err %v (code %v)", err, r26_code(err))
	}
	if refused("GetBlockHeadersRange") != h0+1 {
		t.Fatalf("refusal not counted")
	}
	if rsp, err := r26_call(t, loc, "DERO.GetBlockHeadersRange", `{"start_topoheight":3,"end_topoheight":4}`); err != nil {
		t.Fatalf("headers from the prune point: %v", err)
	} else {
		var r GetBlockHeadersRange_Result
		if err := rsp.UnmarshalResult(&r); err != nil || len(r.Headers) != 2 {
			t.Fatalf("headers 3..4: %d %v", len(r.Headers), err)
		}
	}
	_, err = r26_call(t, loc, "DERO.GetMiniBlocks", `{"topoheight":2}`)
	if r26_code(err) != RPC_CODE_STATE_UNAVAILABLE {
		t.Fatalf("miniblocks at 2: err %v", err)
	}
	_, err = r26_call(t, loc, "DERO.GetDifficultyHistory", `{"count":2,"end_topoheight":2}`)
	if r26_code(err) != RPC_CODE_STATE_UNAVAILABLE || !strings.Contains(err.Error(), "topoheight 2 is below pruned topoheight 3") {
		t.Fatalf("difficulty window ending at 2: err %v", err)
	}
	rsp, err := r26_call(t, loc, "DERO.GetDifficultyHistory", `{"count":100}`)
	if err != nil {
		t.Fatalf("difficulty window reaching below the prune point: %v", err)
	}
	var dh GetDifficultyHistory_Result
	if err := rsp.UnmarshalResult(&dh); err != nil || len(dh.Points) == 0 || dh.Points[0].TopoHeight != 3 ||
		dh.Points[len(dh.Points)-1].TopoHeight != c.Load_TOPO_HEIGHT() {
		t.Fatalf("difficulty window: %d points from %v, err %v (want 3..top)", len(dh.Points), dh.Points, err)
	}
	if recovered_panics() != p0 {
		t.Fatalf("recovered panics +%d", recovered_panics()-p0)
	}
}

// B104 second line: a topo record of the pruned shape (zero block id, a state version) on a node whose prune point is
// not known (floor 0): headers and miniblocks are typed, the difficulty history skips it. Before r26 the difficulty
// history panicked in Load_Block_Difficulty (recovered: ERROR + stack, -32098).
func TestR26ExplorerPrunedShapeRecord(t *testing.T) {
	c, _, done := r25_sim(t, 6)
	defer done()
	forge_prune_floor(t, 0)
	base, err := c.Store.Topo_store.Read(3)
	if err != nil {
		t.Fatal(err)
	}
	var zero [32]byte
	if err := c.Store.Topo_store.Write(2, zero, base.State_Version, 0); err != nil {
		t.Fatal(err)
	}
	p0 := recovered_panics()
	ctx := context.Background()
	_, err = GetBlockHeadersRange(ctx, GetBlockHeadersRange_Params{Start: 1, End: 3})
	var se *StateUnavailableError
	if !errors.As(err, &se) || se.TopoHeight != 2 || se.Method != "GetBlockHeadersRange" {
		t.Fatalf("headers over a pruned-shape record: err %v", err)
	}
	_, err = GetMiniBlocks(ctx, GetMiniBlocks_Params{TopoHeight: 2})
	if !errors.As(err, &se) || se.TopoHeight != 2 || se.Method != "GetMiniBlocks" {
		t.Fatalf("miniblocks of a pruned-shape record: err %v", err)
	}
	dh, err := GetDifficultyHistory(ctx, GetDifficultyHistory_Params{Count: 5, End: 4})
	if err != nil {
		t.Fatalf("difficulty history over a pruned-shape record: %v", err)
	}
	for _, p := range dh.Points {
		if p.TopoHeight == 2 {
			t.Fatalf("the pruned-shape record was reported as a point: %+v", p)
		}
	}
	if len(dh.Points) != 4 {
		t.Fatalf("points %d, want 4 (0,1,3,4)", len(dh.Points))
	}
	if recovered_panics() != p0 {
		t.Fatalf("recovered panics +%d (want 0)", recovered_panics()-p0)
	}
}
