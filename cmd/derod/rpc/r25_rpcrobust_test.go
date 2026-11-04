package rpc

// r25 (rpcrobust) tests: typed errors instead of recovered panics (B85, B86), GetBlockHeaderByHash's shadowed err
// (B80), the additive GetTransaction txs_status and GetInfo total_supply_basis (BD6), and the chain-swap lock (B41).
// Each pruned-state test forges the prune point on a simulator chain through state_prune_floor (forged input).

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/code"
	"github.com/creachadair/jrpc2/server"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/rpc"
)

// swap_global_chain sets the package-global chain under chain_swap_mu and returns the restore (r25 B41).
func swap_global_chain(c *blockchain.Blockchain) func() {
	chain_swap_mu.Lock()
	old := chain
	chain = c
	chain_swap_mu.Unlock()
	return func() {
		chain_swap_mu.Lock()
		chain = old
		chain_swap_mu.Unlock()
	}
}

// r25_sim starts a simulator chain with n mined blocks, swaps it in as the global chain and returns the miner's
// address string and a cleanup.
func r25_sim(t *testing.T, n int) (*blockchain.Blockchain, string, func()) {
	t.Helper()
	if testing.Short() {
		t.Skip("starts a simulator chain")
	}
	old_args := globals.Arguments
	globals.Arguments = map[string]interface{}{"--data-dir": t.TempDir(), "--testnet": true, "--simulator": true}
	globals.Initialize()
	c, err := blockchain.Blockchain_Start(map[string]interface{}{"--simulator": true})
	if err != nil {
		t.Fatal(err)
	}
	restore := swap_global_chain(c)
	miner := genesis_miner(t)
	for i := 0; i < n; i++ {
		cbl, _, err := c.Create_new_miner_block(miner)
		if err != nil {
			t.Fatal(err)
		}
		cbl.Bl.MiniBlocks = append(cbl.Bl.MiniBlocks, blockchain.ConvertBlockToMiniblock(*cbl.Bl, miner))
		if err, ok := c.Add_Complete_Block(cbl); !ok {
			t.Fatalf("block %d: %v", i, err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	miner.Mainnet = false
	return c, miner.String(), func() {
		restore()
		c.Shutdown()
		globals.Arguments = old_args
	}
}

// forge_prune_floor makes the handlers believe the node pruned everything below floor.
func forge_prune_floor(t *testing.T, floor int64) {
	old := state_prune_floor
	state_prune_floor = func() int64 { return floor }
	t.Cleanup(func() { state_prune_floor = old })
}

func recovered_panics() uint64 {
	return metrics.Set.GetOrCreateCounter("rpc_recovered_panics_total").Get()
}

func TestR25EncryptedBalancePrunedTopoTypedError(t *testing.T) {
	c, addr, done := r25_sim(t, 6)
	defer done()
	forge_prune_floor(t, 4)
	ctx := context.Background()
	refused := metrics.Set.GetOrCreateCounter(`rpc_state_unavailable_total{method="GetEncryptedBalance"}`)
	r0, p0 := refused.Get(), recovered_panics()

	_, err := GetEncryptedBalance(ctx, rpc.GetEncryptedBalance_Params{Address: addr, TopoHeight: 2})
	var se *StateUnavailableError
	if !errors.As(err, &se) || se.TopoHeight != 2 || se.PrunedTopo != 4 {
		t.Fatalf("topoheight 2 below the forged prune point 4: err %v, want a StateUnavailableError", err)
	}
	if want := "state not available: topoheight 2 is below pruned topoheight 4"; err.Error() != want {
		t.Fatalf("message %q, want %q", err.Error(), want)
	}
	if code.FromError(err) != RPC_CODE_STATE_UNAVAILABLE {
		t.Fatalf("code %v, want %v", code.FromError(err), RPC_CODE_STATE_UNAVAILABLE)
	}
	if refused.Get() != r0+1 || recovered_panics() != p0 {
		t.Fatalf("refusals +%d (want 1), recovered panics +%d (want 0)", refused.Get()-r0, recovered_panics()-p0)
	}
	// at the prune point itself the state exists (live: prunedheight 7,498,540 answers, 7,498,539 did not)
	res, err := GetEncryptedBalance(ctx, rpc.GetEncryptedBalance_Params{Address: addr, TopoHeight: 4})
	if err != nil || res.Status != "OK" || res.Topoheight != 4 {
		t.Fatalf("topoheight 4 = the prune point: %+v err %v", res, err)
	}
	if top := c.Load_TOPO_HEIGHT(); top < 6 {
		t.Fatalf("topoheight %d", top)
	}
}

// through the real method table: the client sees code -32031 and the documented message, not -32098 internal error
func TestR25EncryptedBalancePrunedOverJSONRPC(t *testing.T) {
	_, addr, done := r25_sim(t, 5)
	defer done()
	forge_prune_floor(t, 3)
	loc := server.NewLocal(d, &server.LocalOptions{Server: options})
	defer loc.Close()
	p0 := recovered_panics()
	for _, m := range []string{"DERO.GetEncryptedBalance", "getencryptedbalance"} {
		_, err := loc.Client.Call(context.Background(), m, rpc.GetEncryptedBalance_Params{Address: addr, TopoHeight: 1})
		var je *jrpc2.Error
		if !errors.As(err, &je) || je.Code != RPC_CODE_STATE_UNAVAILABLE ||
			je.Message != "state not available: topoheight 1 is below pruned topoheight 3" {
			t.Fatalf("%s: err %v", m, err)
		}
	}
	if recovered_panics() != p0 {
		t.Fatalf("a pruned read still went through the recover (%d)", recovered_panics()-p0)
	}
}

func TestR25GetSCPrunedTopoTypedError(t *testing.T) {
	_, _, done := r25_sim(t, 5)
	defer done()
	forge_prune_floor(t, 3)
	refused := metrics.Set.GetOrCreateCounter(`rpc_state_unavailable_total{method="GetSC"}`)
	r0 := refused.Get()
	_, err := GetSC(context.Background(), rpc.GetSC_Params{SCID: strings.Repeat("00", 31) + "01", TopoHeight: 2})
	var se *StateUnavailableError
	if !errors.As(err, &se) || se.TopoHeight != 2 || refused.Get() != r0+1 {
		t.Fatalf("GetSC at a pruned topoheight: err %v (before r25 it answered from the bootstrap state)", err)
	}
	if _, err := GetSC(context.Background(), rpc.GetSC_Params{SCID: strings.Repeat("00", 31) + "01", TopoHeight: 3}); err != nil {
		var se *StateUnavailableError
		if errors.As(err, &se) {
			t.Fatalf("GetSC at the prune point refused: %v", err)
		}
	}
}

func TestR25StateRecordZeroBlockRefused(t *testing.T) {
	forge_prune_floor(t, 9)
	var zero crypto.Hash
	err := check_state_record("GetEncryptedBalance", 12, zero)
	var se *StateUnavailableError
	if !errors.As(err, &se) || se.TopoHeight != 12 || se.PrunedTopo != 9 {
		t.Fatalf("a topo record with a zero block id: err %v", err)
	}
	if err := check_state_record("GetEncryptedBalance", 12, crypto.Hash{1}); err != nil {
		t.Fatalf("a record naming a block refused: %v", err)
	}
	// an unpruned node (floor 0) never refuses by height
	forge_prune_floor(t, 0)
	if err := check_state_topo("GetEncryptedBalance", 0); err != nil {
		t.Fatalf("unpruned node refused topoheight 0: %v", err)
	}
}

// the WARNING is rate-limited per method, carries no stack, and says how many refusals it stood for
func TestR25StateRefusalLogRateLimited(t *testing.T) {
	forge_prune_floor(t, 100)
	type line struct {
		msg string
		kv  []interface{}
	}
	var got []line
	old_log, old_warn := state_unavailable_log, state_warn
	defer func() { state_unavailable_log, state_warn = old_log, old_warn }()
	state_unavailable_log = func(msg string, kv ...interface{}) { got = append(got, line{msg, kv}) }
	at := time.Unix(1_800_000_000, 0)
	state_warn = &rate_limited_warn{last: map[string]time.Time{}, suppressed: map[string]uint64{}, now: func() time.Time { return at }}
	for i := 0; i < 5; i++ {
		check_state_topo("GetEncryptedBalance", 7)
		at = at.Add(5 * time.Second)
	}
	check_state_topo("GetSC", 7) // another method has its own budget
	if len(got) != 2 {
		t.Fatalf("%d lines for 5+1 refusals within %v, want 2", len(got), STATE_UNAVAILABLE_LOG_EVERY)
	}
	at = at.Add(STATE_UNAVAILABLE_LOG_EVERY)
	check_state_topo("GetEncryptedBalance", 7)
	if len(got) != 3 {
		t.Fatalf("no line after the interval: %d", len(got))
	}
	kv := got[2].kv
	m := map[string]interface{}{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1]
	}
	if m["suppressed_since_last"] != uint64(4) || m["topoheight"] != int64(7) || m["prunedheight"] != int64(100) {
		t.Fatalf("line fields %v", m)
	}
	for _, l := range got {
		if !strings.HasPrefix(l.msg, "WARNING: ") {
			t.Fatalf("not a WARNING line: %q", l.msg)
		}
		for i := 0; i < len(l.kv); i += 2 {
			if l.kv[i] == "stack" {
				t.Fatalf("a stack in the refusal line: %v", l.kv)
			}
		}
	}
}

func TestR25EncryptedBalanceBadAddressTypedError(t *testing.T) {
	p0 := recovered_panics()
	c := metrics.Set.GetOrCreateCounter(`rpc_input_refused_total{method="GetEncryptedBalance",kind="address"}`)
	c0 := c.Get()
	_, err := GetEncryptedBalance(context.Background(), rpc.GetEncryptedBalance_Params{Address: "dero1notanaddress"})
	var ie *InputRefusedError
	if !errors.As(err, &ie) || ie.Kind != "address" || code.FromError(err) != code.InvalidParams {
		t.Fatalf("malformed address: err %v", err)
	}
	if recovered_panics() != p0 || c.Get() != c0+1 {
		t.Fatalf("recovered panics +%d (want 0), refusals +%d (want 1)", recovered_panics()-p0, c.Get()-c0)
	}
}

// an SCID whose first byte is ':' is a tree name graviton refuses: GetEncryptedBalance and GetRandomAddress panicked
func TestR25ScidColonRefused(t *testing.T) {
	_, addr, done := r25_sim(t, 2)
	defer done()
	var scid crypto.Hash
	scid[0], scid[31] = ':', 7
	p0 := recovered_panics()
	_, err := GetEncryptedBalance(context.Background(), rpc.GetEncryptedBalance_Params{Address: addr, SCID: scid})
	var ie *InputRefusedError
	if !errors.As(err, &ie) || ie.Kind != "scid" {
		t.Fatalf("GetEncryptedBalance scid 0x3a..: err %v", err)
	}
	_, err = GetRandomAddress(context.Background(), rpc.GetRandomAddress_Params{SCID: scid})
	if !errors.As(err, &ie) || ie.Method != "GetRandomAddress" {
		t.Fatalf("GetRandomAddress scid 0x3a..: err %v", err)
	}
	if recovered_panics() != p0 {
		t.Fatalf("recovered panics +%d", recovered_panics()-p0)
	}
	// a normal SCID (unknown tree) still answers: graviton returns an empty tree, no error
	scid[0] = 0x3b
	if _, err := GetRandomAddress(context.Background(), rpc.GetRandomAddress_Params{SCID: scid}); err != nil {
		t.Fatalf("an ordinary unknown scid: %v", err)
	}
}

func TestR25NameValueNotAKeyIsTyped(t *testing.T) {
	_, err := name_value_address("abc", true)
	var ie *InputRefusedError
	if !errors.As(err, &ie) || ie.Kind != "name_value" {
		t.Fatalf("a 3-byte name value: err %v", err)
	}
	miner := genesis_miner(t)
	s, err := name_value_address(string(miner.Compressed()), false)
	miner.Mainnet = false
	if err != nil || s != miner.String() {
		t.Fatalf("a real key: %q err %v, want %q", s, err, miner.String())
	}
}

func TestR25BlockHeaderByHashUnknownIsError(t *testing.T) {
	c, _, done := r25_sim(t, 3)
	defer done()
	ctx := context.Background()
	_, err := GetBlockHeaderByHash(ctx, rpc.GetBlockHeaderByHash_Params{Hash: strings.Repeat("ab", 32)})
	var nf *NotFoundError
	if !errors.As(err, &nf) || code.FromError(err) != RPC_CODE_NOT_FOUND || nf.ID != strings.Repeat("ab", 32) {
		t.Fatalf("unknown hash: err %v (before r25: nil error, status \"\", all-zero header)", err)
	}
	top := c.Get_Top_ID()
	r, err := GetBlockHeaderByHash(ctx, rpc.GetBlockHeaderByHash_Params{Hash: top.String()})
	if err != nil || r.Status != "OK" || r.Block_Header.Hash != top.String() {
		t.Fatalf("top block: %+v err %v", r, err)
	}
}

func TestR25TxLookupStatesForged(t *testing.T) {
	r := rpc.GetTransaction_Result{Txs_as_hex: []string{"", "aa", "bb"},
		Txs: []rpc.Tx_Related_Info{{}, {In_pool: true, Block_Height: -1}, {Block_Height: 5}}}
	got := tx_lookup_states(r)
	if strings.Join(got, ",") != "not_found,in_pool,in_chain" {
		t.Fatalf("states %v", got)
	}
	if len(tx_lookup_states(rpc.GetTransaction_Result{})) != 0 {
		t.Fatal("empty answer")
	}
}

// txs_status is additive: the call still succeeds with status OK, the old client's struct decodes the same fields
func TestR25GetTransactionStatusOverJSONRPC(t *testing.T) {
	_, _, done := r25_sim(t, 2)
	defer done()
	loc := server.NewLocal(d, &server.LocalOptions{Server: options})
	defer loc.Close()
	missing := strings.Repeat("cd", 32)
	for _, m := range []string{"DERO.GetTransaction", "gettransactions"} {
		rsp, err := loc.Client.Call(context.Background(), m, rpc.GetTransaction_Params{Tx_Hashes: []string{missing}})
		if err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		var raw map[string]json.RawMessage
		var old rpc.GetTransaction_Result
		if err := rsp.UnmarshalResult(&raw); err != nil {
			t.Fatal(err)
		}
		if err := rsp.UnmarshalResult(&old); err != nil {
			t.Fatal(err)
		}
		if string(raw["txs_status"]) != `["not_found"]` || old.Status != "OK" || len(old.Txs_as_hex) != 1 || old.Txs_as_hex[0] != "" {
			t.Fatalf("%s: txs_status %s, old view %+v", m, raw["txs_status"], old)
		}
	}
}

func TestR25GetInfoTotalSupplyBasis(t *testing.T) {
	c, _, done := r25_sim(t, 2)
	defer done()
	loc := server.NewLocal(d, &server.LocalOptions{Server: options})
	defer loc.Close()
	for _, m := range []string{"DERO.GetInfo", "getinfo", "get_info"} {
		rsp, err := loc.Client.Call(context.Background(), m, nil)
		if err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		var raw map[string]json.RawMessage
		var old rpc.GetInfo_Result
		if err := rsp.UnmarshalResult(&raw); err != nil {
			t.Fatal(err)
		}
		if err := rsp.UnmarshalResult(&old); err != nil {
			t.Fatal(err)
		}
		var basis string
		json.Unmarshal(raw["total_supply_basis"], &basis)
		if basis != TOTAL_SUPPLY_BASIS || !strings.Contains(basis, "CalcSupply") {
			t.Fatalf("%s: total_supply_basis %q", m, basis)
		}
		if want := blockchain.CalcSupply(uint64(c.Get_Height())) / 100000; old.Total_Supply != want {
			t.Fatalf("%s: total_supply %d, want the unchanged formula value %d", m, old.Total_Supply, want)
		}
	}
}

// r25 B41: the fate resolver reads the global chain under chain_swap_mu; a swap under the lock is race-free
// (meaningful under -race; go_mutate runs its mutation with -race)
func TestR25ResolverChainSwapRaceFree(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 300; i++ {
			resolve_pending()
		}
	}()
	for i := 0; i < 300; i++ {
		swap_global_chain(chain)()
	}
	<-done
}

// The live pruned store's shape, forged on a private simulator chain: topo records below the prune point hold an
// all-zero block id and the bootstrap state version (live topo.map 2026-11-03: records 0..7,498,539 read
// "0000.. (4225, 0)", record 7,498,540 names its block). Here the height pre-check is told nothing was pruned (floor
// 0, as if LocatePruneTopo missed it), so only the record check stands between the call and
// ReadBlockSnapshotVersion(zero id): without it this is exactly the B85 panic (recovered, -32098, ERROR + stack).
func TestR25PrunedRecordShapeRefused(t *testing.T) {
	c, addr, done := r25_sim(t, 6)
	defer done()
	forge_prune_floor(t, 0)
	base, err := c.Store.Topo_store.Read(3)
	if err != nil {
		t.Fatal(err)
	}
	var zero [32]byte
	for i := int64(1); i < 3; i++ {
		if err := c.Store.Topo_store.Write(i, zero, base.State_Version, 0); err != nil {
			t.Fatal(err)
		}
	}
	p0 := recovered_panics()
	_, err = GetEncryptedBalance(context.Background(), rpc.GetEncryptedBalance_Params{Address: addr, TopoHeight: 2})
	var se *StateUnavailableError
	if !errors.As(err, &se) || se.TopoHeight != 2 {
		t.Fatalf("GetEncryptedBalance on a pruned-shape record: err %v", err)
	}
	_, err = GetSC(context.Background(), rpc.GetSC_Params{SCID: strings.Repeat("00", 31) + "01", TopoHeight: 2})
	if !errors.As(err, &se) || se.TopoHeight != 2 {
		t.Fatalf("GetSC on a pruned-shape record: err %v (before r25: an answer from the bootstrap snapshot)", err)
	}
	if recovered_panics() != p0 {
		t.Fatalf("recovered panics +%d", recovered_panics()-p0)
	}
}

// TestR25ChainSwapIsRaceFreeWithResolver runs resolver passes (fate_tick_pass, the body of the periodic resolver) every
// 1 ms on its own goroutine and swaps the global chain 200 times meanwhile. Under -race, a pass that reads `chain` without
// the lock the swap takes is a reported data race, which fails the test (go_mutations gm-r25-harnesstool-b41-* and
// gm-r25-verify-harnesstool-*; the race was 1 of 12 full -race runs on r24). r25 (harnesstool verify): it drives the
// pass directly, so it does not depend on fate_once having been fired by this test first (package order or -count>1).
// r25 merge: moved here from r25_chain_swap_test.go and onto the single helper swap_global_chain (chain_swap_mu).
func TestR25ChainSwapIsRaceFreeWithResolver(t *testing.T) {
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			fate_tick_pass()
			time.Sleep(time.Millisecond)
		}
	}()
	for i := 0; i < 200; i++ {
		restore := swap_global_chain(nil) // resolve_pending recovers from a nil chain
		time.Sleep(200 * time.Microsecond)
		restore()
		time.Sleep(200 * time.Microsecond)
	}
	close(stop)
	<-done
}
