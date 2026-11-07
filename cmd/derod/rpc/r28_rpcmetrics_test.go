package rpc

// r28 (rpc-metrics): error bodies written outside jrpc2 are counted by code; GetInfo tx_pool_unmined (B42); the
// whole /metrics page carries the registry's HELP/TYPE and every family on it is registered; the header miners[]
// state on a chain with an alt block and the topoheight == height invariant (B61); the decoy window equals
// upstream's on any node whose prune floor is >= 5 topos below the tip (B43).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/code"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/errormsg"
	"github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/transaction"
)

func TestR28HTTPLayerErrorBodiesCounted(t *testing.T) {
	ir, rl, bn, ip, ot := r27_error_code_count("-32600"), r27_error_code_count("-32029"), r27_error_code_count("-32030"),
		r27_error_code_count("-32602"), r27_error_code_count("other")
	mnf := r27_error_code_count("-32601")

	rec := httptest.NewRecorder()
	if http_request_shape_ok(rec, httptest.NewRequest("GET", "/json_rpc", nil), "127.0.0.1", true) {
		t.Fatal("a GET must be refused")
	}
	req := httptest.NewRequest("POST", "/json_rpc", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "text/plain")
	if http_request_shape_ok(httptest.NewRecorder(), req, "127.0.0.1", true) {
		t.Fatal("text/plain must be refused")
	}
	if !strings.Contains(rec.Body.String(), `"code":-32600`) {
		t.Fatalf("405 body %q", rec.Body.String())
	}
	write_abuse_http(httptest.NewRecorder(), abuse_rate_limited, time.Second)
	write_abuse_http(httptest.NewRecorder(), abuse_banned, time.Second)
	rec = httptest.NewRecorder()
	write_bound_error(rec, &jrpc2.Error{Code: code.InvalidParams, Message: "too many"})
	write_bound_error(httptest.NewRecorder(), errors.New("not a jrpc2 error"))
	rec = httptest.NewRecorder()
	write_method_not_found(rec) // r28 verify: the reserved rpc.* answer (rpc_abuse.go, ws_hardening.go) is the fifth writer
	if !strings.Contains(rec.Body.String(), `"code":-32601`) {
		t.Fatalf("reserved-name body %q", rec.Body.String())
	}
	for _, c := range []struct {
		code       string
		before, by uint64
	}{{"-32600", ir, 2}, {"-32029", rl, 1}, {"-32030", bn, 1}, {"-32602", ip, 1}, {"-32601", mnf, 1}, {"other", ot, 1}} {
		if d := r27_error_code_count(c.code) - c.before; d != c.by {
			t.Fatalf(`rpc_error_responses_total{code="%s"} +%d, want +%d`, c.code, d, c.by)
		}
	}
	count_error_answer(nil) // not an error: nothing counted
	if r27_error_code_count("other") != ot+1 {
		t.Fatal("a nil error was counted")
	}
}

// a pool tx that never needs a proof: COINBASE type, no payloads (Mempool_Add_TX only reads payload nonces); DestNetwork
// makes the hashes differ (Height is not serialised)
func r28_pool_tx(h uint64) *transaction.Transaction {
	return &transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, DestNetwork: h, TransactionType: transaction.COINBASE, Height: h}}
}

func TestR28GetInfoTxPoolUnmined(t *testing.T) {
	a, b, c := crypto.Hash{1}, crypto.Hash{2}, crypto.Hash{3}
	if pool_unmined(nil, nil) != 0 || pool_unmined([]crypto.Hash{a, b, c}, nil) != 3 ||
		pool_unmined([]crypto.Hash{a, b, c}, map[crypto.Hash]bool{b: true, crypto.Hash{9}: true}) != 2 {
		t.Fatal("pool_unmined")
	}
	ch, _, done := r25_sim(t, 3)
	defer done()
	t1, t2 := r28_pool_tx(1000001), r28_pool_tx(1000002)
	if !ch.Mempool.Mempool_Add_TX(t1, 0) || !ch.Mempool.Mempool_Add_TX(t2, 0) {
		t.Fatal("pool add")
	}
	defer ch.Mempool.Mempool_Delete_TX(t1.GetHash())
	defer ch.Mempool.Mempool_Delete_TX(t2.GetHash())
	old := recently_mined
	recently_mined = func() map[crypto.Hash]bool { return map[crypto.Hash]bool{t1.GetHash(): true} } // t1: mined, not purged
	defer func() { recently_mined = old }()
	res, err := GetInfoR25(context.Background())
	if err != nil || res.Tx_pool_size != 2 || res.Tx_Pool_Unmined != 1 {
		t.Fatalf("tx_pool_size %d tx_pool_unmined %d err %v", res.Tx_pool_size, res.Tx_Pool_Unmined, err)
	}
	raw, _ := json.Marshal(res)
	var flat map[string]interface{}
	json.Unmarshal(raw, &flat)
	if flat["tx_pool_unmined"] != float64(1) || flat["tx_pool_size"] != float64(2) {
		t.Fatalf("JSON %s", raw)
	}
	recently_mined = old // the real window: the forged txs are in no block
	if res, _ = GetInfoR25(context.Background()); res.Tx_Pool_Unmined != 2 {
		t.Fatalf("real window: tx_pool_unmined %d, want 2", res.Tx_Pool_Unmined)
	}
}

func TestR28MetricsPageFullyRegistered(t *testing.T) {
	_, _, done := r25_sim(t, 2)
	defer done()
	rec := httptest.NewRecorder()
	metrics_handler(rec, httptest.NewRequest("GET", "/metrics", nil))
	text := rec.Body.String()
	reg := metrics.Registry()
	helped := map[string]bool{}
	sampled := map[string]bool{}
	var unreg []string
	fam := func(s string) (string, bool) {
		if _, ok := reg[s]; ok {
			return s, true
		}
		for _, suf := range []string{"_bucket", "_sum", "_count"} {
			if f, ok := reg[strings.TrimSuffix(s, suf)]; ok && strings.HasSuffix(s, suf) && (f.Type == "histogram" || f.Type == "vmhistogram" || f.Type == "summary") {
				return f.Name, true
			}
		}
		return "", false
	}
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, "# HELP ") {
			f := strings.Fields(l)[2]
			if helped[f] {
				t.Fatalf("second HELP for %s", f)
			}
			helped[f] = true
			continue
		}
		if l == "" || l[0] == '#' {
			continue
		}
		name := l[:strings.IndexAny(l, "{ ")]
		f, ok := fam(name)
		if !ok {
			if !strings.HasPrefix(name, "r2") { // r27_test_* / r28_test_* series some tests create
				unreg = append(unreg, name)
			}
			continue
		}
		if !sampled[f] && !helped[f] {
			t.Fatalf("%s: a sample before its HELP", f)
		}
		sampled[f] = true
	}
	if len(unreg) > 0 {
		t.Fatalf("on /metrics but not in metrics/metric_registry.json (harness/intel/metric_registry.py build): %v", unreg)
	}
	for _, want := range []string{"rpc_error_responses_total", "dero_tip_age_seconds", "dero_node_up", "app_uptime_seconds"} {
		if !helped[want] {
			t.Fatalf("%s has no HELP", want)
		}
	}
	if len(sampled) < 150 {
		t.Fatalf("only %d registered families on the page", len(sampled))
	}
	if !strings.Contains(text, "# TYPE rpc_error_responses_total counter\n") || !strings.Contains(text, "# TYPE dero_chain_height gauge\n") {
		t.Fatal("TYPE lines missing")
	}
}

// B61: under the one-tip consensus rule (blockchain.go: "only 1 tips allowed in block") every topo-ordered block has
// topoheight == height, so the R25 "topoheight != height" event cannot occur on this network; the case that does
// occur is an alt block (no topoheight), whose miners[] the header now resolves against its tip's state.
func TestR28TopoEqualsHeightAndAltBlockMiners(t *testing.T) {
	c, addr, done := r25_sim(t, 3)
	defer done()
	miner := genesis_miner(t)
	var alts []crypto.Hash
	for round := 0; round < 3; round++ {
		a, _, err := c.Create_new_miner_block(miner)
		if err != nil {
			t.Fatal(err)
		}
		a.Bl.MiniBlocks = append(a.Bl.MiniBlocks, blockchain.ConvertBlockToMiniblock(*a.Bl, miner))
		time.Sleep(3 * time.Millisecond)
		b, _, err := c.Create_new_miner_block(miner)
		if err != nil {
			t.Fatal(err)
		}
		b.Bl.Timestamp++
		b.Bl.MiniBlocks = append(b.Bl.MiniBlocks, blockchain.ConvertBlockToMiniblock(*b.Bl, miner))
		if err, ok := c.Add_Complete_Block(a); !ok {
			t.Fatalf("a: %v", err)
		}
		if err, ok := c.Add_Complete_Block(b); !ok {
			t.Fatalf("b (same height, same tip): %v", err)
		}
		time.Sleep(3 * time.Millisecond)
		two, _, err := c.Create_new_miner_block(miner) // a block naming both: refused by consensus
		if err != nil {
			t.Fatal(err)
		}
		two.Bl.Tips = []crypto.Hash{a.Bl.GetHash(), b.Bl.GetHash()}
		two.Bl.MiniBlocks = append(two.Bl.MiniBlocks[:0], blockchain.ConvertBlockToMiniblock(*two.Bl, miner))
		if err, ok := c.Add_Complete_Block(two); ok || err != errormsg.ErrPastMissing {
			t.Fatalf("a two-tip block: %v %v, want ErrPastMissing", err, ok)
		}
		r22_mine(t, c, miner)
		for _, h := range []crypto.Hash{a.Bl.GetHash(), b.Bl.GetHash()} {
			if !c.Is_Block_Topological_order(h) {
				alts = append(alts, h)
			}
		}
	}
	top := c.Load_TOPO_HEIGHT()
	if top != c.Get_Height() {
		t.Fatalf("topoheight %d != height %d", top, c.Get_Height())
	}
	for topo := int64(0); topo <= top; topo++ {
		blid, err := c.Load_Block_Topological_order_at_index(topo)
		if err != nil {
			t.Fatal(err)
		}
		if h := c.Load_Height_for_BL_ID(blid); h != topo {
			t.Fatalf("topoheight %d holds a block of height %d", topo, h)
		}
	}
	if len(alts) != 3 {
		t.Fatalf("%d alt blocks, want 3 (one per round)", len(alts))
	}
	for _, h := range alts {
		hdr, err := GetBlockHeader(c, h)
		if err != nil {
			t.Fatal(err)
		}
		if hdr.TopoHeight != -1 || len(hdr.Miners) != 1 || hdr.Miners[0] != addr {
			t.Fatalf("alt block header topo %d miners %v, want -1 and [%s]", hdr.TopoHeight, hdr.Miners, addr)
		}
	}
}

// B43: decoy_window_topo (r26) differs from upstream's rule (top-5 only above topoheight 100) only below topoheight
// 100 or when the prune floor is within 5 topos of the tip. Mainnet tip ~7.86M with prune floor ~7.50M (read live,
// rft §7 B43 r28 record) is neither, so a live wallet call returns what upstream returned: the clamp is unobservable
// there by construction, and its effect is proven on the simulator (TestR26*/r26_b43 decode KAT).
func TestR28DecoyWindowEqualsUpstreamAboveFloor(t *testing.T) {
	upstream := func(top int64) int64 {
		if top > 100 {
			return top - 5
		}
		return top
	}
	for _, c := range []struct{ top, floor int64 }{{7863222, 7498540}, {101, 0}, {106, 101}, {1 << 40, 0}, {1000, 995}} {
		if got := decoy_window_topo(c.top, c.floor); got != upstream(c.top) {
			t.Fatalf("top %d floor %d: %d, upstream %d", c.top, c.floor, got, upstream(c.top))
		}
	}
	for top := int64(101); top < 5000; top += 7 {
		for _, floor := range []int64{0, top / 2, top - 5} {
			if decoy_window_topo(top, floor) != upstream(top) {
				t.Fatalf("top %d floor %d differs from upstream", top, floor)
			}
		}
	}
	if decoy_window_topo(50, 0) != 45 || decoy_window_topo(1000, 997) != 997 { // where they differ: sim heights, a fresh floor
		t.Fatal("the r26 clamp itself")
	}
}
