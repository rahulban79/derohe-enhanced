package rpc

// r27 (rpc-metrics) tests: the -32602 text names the field (B132), every error response is counted by its code, the
// first-event counters read 0 from the start, the NR26 cosmetic notes (UTF-8 name cap, floor-0 zero-blid text), the
// untyped recovers of four handlers, the ban-list gauge, the 0 %-covered handlers the pages lean on (GetSyncInfo,
// GetHeight, GetBlockCount, GetLastBlockHeader, GetTxPool, GetEmissionAudit) and the RPC_METHODS.md metric names.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/code"

	"github.com/deroproject/graviton"

	"github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/p2p"
)

func r27_metrics_text() string {
	var b bytes.Buffer
	metrics.Set.WritePrometheus(&b)
	return b.String()
}

func r27_series(text, name string) bool {
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, name+" ") {
			return true
		}
	}
	return false
}

func r27_error_code_count(c string) uint64 {
	return metrics.Set.GetOrCreateCounter(`rpc_error_responses_total{code="` + c + `"}`).Get()
}

// B132: the -32602 answer of a parameter decode failure names the field and no longer doubles the code into the text.
func TestR27InvalidParamsNamesTheField(t *testing.T) {
	_, _, done := r25_sim(t, 4)
	defer done()
	loc := r26_local(t)
	refused := metrics.Set.GetOrCreateCounter(`rpc_params_refused_total`)
	n0 := refused.Get()
	for _, c := range []struct{ m, params, want, field string }{
		{"DERO.GetBlockHeadersRange", `{"start":1,"end":2}`,
			`invalid parameters: unknown field "start" (accepted: start_topoheight, end_topoheight)`, "start"},
		{"DERO.GetMiniBlocks", `{"topo":2}`, `invalid parameters: unknown field "topo" (accepted: hash, topoheight)`, "topo"},
		{"DERO.GetDifficultyHistory", `{"count":3,"end":4}`,
			`invalid parameters: unknown field "end" (accepted: count, end_topoheight)`, "end"},
		{"DERO.GetBlockHeadersRange", `{"start_topoheight":"x"}`,
			`invalid parameters: field start_topoheight: want int64, got string`, "start_topoheight"},
		// an upstream (non-strict) method: an unknown name is still ignored, a wrong type is named
		{"DERO.GetBlockHeaderByTopoHeight", `{"topoheight":"x"}`,
			`invalid parameters: field topoheight: want uint64, got string`, "topoheight"},
		{"getblockheaderbytopoheight", `{"topoheight":"x"}`,
			`invalid parameters: field topoheight: want uint64, got string`, "topoheight"},
		{"DERO.GetBlockHeadersRange", `[1,2]`,
			`invalid parameters: want a JSON object, got array (accepted fields: start_topoheight, end_topoheight)`, ""},
	} {
		_, err := r26_call(t, loc, c.m, c.params)
		var je *jrpc2.Error
		if !errors.As(err, &je) || je.Code != code.InvalidParams {
			t.Fatalf("%s %s: err %v, want -32602", c.m, c.params, err)
		}
		if je.Message != c.want || strings.Contains(je.Message, "[-32602]") {
			t.Fatalf("%s %s: message %q, want %q", c.m, c.params, je.Message, c.want)
		}
		var data struct {
			Field    string   `json:"field"`
			Accepted []string `json:"accepted"`
		}
		if err := json.Unmarshal(je.Data, &data); err != nil || data.Field != c.field || len(data.Accepted) == 0 {
			t.Fatalf("%s %s: data %s (%v), want field %q and the accepted names", c.m, c.params, je.Data, err, c.field)
		}
	}
	if refused.Get() != n0+7 {
		t.Fatalf("rpc_params_refused_total +%d, want 7", refused.Get()-n0)
	}
	// the success path is unchanged: right names decode, {} is accepted, unknown names on upstream methods ignored
	for _, c := range []struct{ m, params string }{
		{"DERO.GetBlockHeadersRange", `{"start_topoheight":1,"end_topoheight":2}`},
		{"DERO.GetBlockHeadersRange", `{}`},
		{"DERO.GetBlockHeaderByTopoHeight", `{"topoheight":1,"bogus":true}`},
	} {
		if _, err := r26_call(t, loc, c.m, c.params); err != nil {
			t.Fatalf("%s %s: %v", c.m, c.params, err)
		}
	}
	// a handler's own -32602 (not a decode failure) passes through untouched
	_, err := r26_call(t, loc, "DERO.GetBlockHeadersRange", `{"start_topoheight":3,"end_topoheight":1}`)
	if err == nil || !strings.Contains(err.Error(), "end_topoheight 1 is below start_topoheight 3") {
		t.Fatalf("handler error rewritten: %v", err)
	}
}

// the helpers on their own: json names (tags, embedded, unexported, "-"), the wrapper recogniser
func TestR27ParamsHelpers(t *testing.T) {
	type inner struct {
		A int `json:"a"`
	}
	type p struct {
		inner
		B      int `json:"b,omitempty"`
		C      int `json:"-"`
		D      int
		hidden int
	}
	if got := strings.Join(json_field_names(reflectTypeOf(p{})), ","); got != "a,b,D" {
		t.Fatalf("names %q", got)
	}
	if params_type(func(context.Context) {}) != nil || params_type(42) != nil {
		t.Fatal("params_type of a function without params")
	}
	if params_type(GetBlockHeadersRange) != reflectTypeOf(GetBlockHeadersRange_Params{}) {
		t.Fatal("params_type")
	}
	if is_param_decode_failure(&jrpc2.Error{Code: code.InvalidParams, Message: "unknown event"}) ||
		!is_param_decode_failure(jrpc2.Errorf(code.InvalidParams, "invalid parameters: %v", &jrpc2.Error{Code: code.InvalidParams, Message: "invalid parameters"})) ||
		is_param_decode_failure(errors.New("invalid parameters: [x")) {
		t.Fatal("is_param_decode_failure")
	}
	if params_error(reflectTypeOf(GetBlockHeadersRange_Params{}), nil) != nil ||
		params_error(reflectTypeOf(GetBlockHeadersRange_Params{}), []byte(`{"start_topoheight":1}`)) != nil {
		t.Fatal("params_error on params that decode")
	}
	// a caller-chosen field name echoed back is bounded
	long := strings.Repeat("z", 300)
	e := params_error(reflectTypeOf(GetBlockHeadersRange_Params{}), []byte(`{"`+long+`":1}`))
	if e == nil || len(e.Message) > 200 || len(e.Data) > 200 {
		t.Fatalf("long unknown field echoed: %v data %d bytes", e, len(e.Data))
	}
}

// every error response is counted by its JSON-RPC code; the fixed label set reads 0 before its first event
func TestR27ErrorResponsesCountedByCode(t *testing.T) {
	text := r27_metrics_text()
	for _, c := range append(RPC_ERROR_CODES, code.Code(0)) {
		name := `rpc_error_responses_total{code="` + itoa_signed(int64(c)) + `"}`
		if c == 0 {
			name = `rpc_error_responses_total{code="other"}`
		}
		if !r27_series(text, name) {
			t.Fatalf("%s absent before its first event", name)
		}
	}
	_, _, done := r25_sim(t, 3)
	defer done()
	loc := r26_local(t)
	nf0, ip0, mnf0, ok0 := r27_error_code_count("-32032"), r27_error_code_count("-32602"), r27_error_code_count("-32601"), r27_error_code_count("other")
	r26_call(t, loc, "DERO.NameToAddress", `{"name":"nobody-registered-this","topoheight":-1}`)
	r26_call(t, loc, "DERO.GetMiniBlocks", `{"topo":1}`)
	r26_call(t, loc, "DERO.NoSuchMethod", `{}`)
	if _, err := loc.Client.Call(context.Background(), "DERO.GetHeight", nil); err != nil {
		t.Fatal(err)
	}
	if d := r27_error_code_count("-32032") - nf0; d != 1 {
		t.Fatalf("-32032 +%d, want 1", d)
	}
	if d := r27_error_code_count("-32602") - ip0; d != 1 {
		t.Fatalf("-32602 +%d, want 1", d)
	}
	if d := r27_error_code_count("-32601") - mnf0; d != 1 {
		t.Fatalf("-32601 +%d, want 1", d)
	}
	if d := r27_error_code_count("other") - ok0; d != 0 {
		t.Fatalf("other +%d, want 0 (a success is not an error)", d)
	}
	count_error_code(&jrpc2.Error{Code: code.Code(-1)})
	if d := r27_error_code_count("other") - ok0; d != 1 {
		t.Fatalf("an unlisted code: other +%d, want 1", d)
	}
}

var r27_call_site = []struct {
	re   *regexp.Regexp
	name func(m []string) string
}{
	{regexp.MustCompile(`(?:refuse_state|check_state_topo|check_state_record|check_block_topo|block_id_at_topo)\("([A-Za-z]+)"`),
		func(m []string) string { return `rpc_state_unavailable_total{method="` + m[1] + `"}` }},
	{regexp.MustCompile(`refuse_input\("([A-Za-z]+)", "([a-z_]+)"`),
		func(m []string) string { return `rpc_input_refused_total{method="` + m[1] + `",kind="` + m[2] + `"}` }},
	{regexp.MustCompile(`check_scid_tree\("([A-Za-z]+)"`),
		func(m []string) string { return `rpc_input_refused_total{method="` + m[1] + `",kind="scid"}` }},
	// a fixed literal created inside a function body (indented) is created by its first event
	{regexp.MustCompile("(?m)^\t+.*GetOrCreateCounter\\([`\"]([^`\"]+)[`\"]\\)\\.Inc\\(\\)"),
		func(m []string) string { return m[1] }},
}

// the first-event counters of this package are registered at start (R26: rpc_state_unavailable_total absent)
func TestR27TypedRefusalCountersPreregistered(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	want := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, cs := range r27_call_site {
			for _, m := range cs.re.FindAllStringSubmatch(string(b), -1) {
				want[cs.name(m)] = f
			}
		}
	}
	if len(want) < 15 {
		t.Fatalf("scan found %d series: the call-site patterns no longer match", len(want))
	}
	listed := map[string]bool{}
	for _, n := range rpc_counters_preregistered {
		listed[n] = true
	}
	text := r27_metrics_text()
	var missing []string
	for n, f := range want {
		if !listed[n] {
			missing = append(missing, n+" ("+f+")")
		}
		if !r27_series(text, n) {
			missing = append(missing, n+" absent from /metrics")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("first-event counters not registered at start:\n%s", strings.Join(missing, "\n"))
	}
}

// NR26 note 1: the 64-byte cap of the echoed name cut inside a multi-byte rune
func TestR27NameEchoCapKeepsUTF8(t *testing.T) {
	name := strings.Repeat("a", NAME_ECHO_MAX-1) + "é" + "tail" // é is 2 bytes and straddles byte 64
	err := name_lookup_error(name, errNotFoundForTest())
	var ne *NotFoundError
	if !errors.As(err, &ne) {
		t.Fatalf("err %v", err)
	}
	if !utf8.ValidString(ne.ID) || ne.ID != strings.Repeat("a", NAME_ECHO_MAX-1)+"..." {
		t.Fatalf("echo %q (valid UTF-8 %v)", ne.ID, utf8.ValidString(ne.ID))
	}
	if got := cap_utf8("short", 64); got != "short" {
		t.Fatalf("short name changed: %q", got)
	}
	if got := cap_utf8(strings.Repeat("x", 70), 64); got != strings.Repeat("x", 64)+"..." {
		t.Fatalf("ascii cap: %q", got)
	}
}

// NR26 note 2: on a node with prune floor 0 a record naming no block said "below pruned topoheight 0"
func TestR27ZeroBlidTextOnUnprunedNode(t *testing.T) {
	e := &StateUnavailableError{Method: "GetMiniBlocks", TopoHeight: 2, PrunedTopo: 0}
	if want := "state not available: the record at topoheight 2 names no block (pruned topoheight 0)"; e.Error() != want {
		t.Fatalf("%q, want %q", e.Error(), want)
	}
	e = &StateUnavailableError{TopoHeight: 1, PrunedTopo: 3}
	if want := "state not available: topoheight 1 is below pruned topoheight 3"; e.Error() != want {
		t.Fatalf("%q", e.Error())
	}
	// end to end on a simulator chain: a pruned-shape record at 2, floor 0
	c, _, done := r25_sim(t, 5)
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
	_, err = GetMiniBlocks(context.Background(), GetMiniBlocks_Params{TopoHeight: 2})
	if err == nil || !strings.Contains(err.Error(), "the record at topoheight 2 names no block") ||
		strings.Contains(err.Error(), "below pruned topoheight 0") {
		t.Fatalf("miniblocks of a pruned-shape record on floor 0: %v", err)
	}
}

// four handlers recovered a panic into an untyped "panic occured" text that rpc_recovered_panics_total never counted
func TestR27UntypedRecoversAreCounted(t *testing.T) {
	restore := swap_global_chain(nil)
	defer restore()
	ctx := context.Background()
	for name, call := range map[string]func() error{
		"GetMonetaryIntegrity": func() error { _, err := GetMonetaryIntegrity(ctx, GetMonetaryIntegrity_Params{}); return err },
		"GetSupplyAudit":       func() error { _, err := GetSupplyAudit(ctx); return err },
		"compute_supply_audit": func() error { _, err := compute_supply_audit(ctx, 1); return err },
	} {
		p0 := recovered_panics()
		err := call()
		if err == nil || !strings.HasPrefix(err.Error(), "internal error: ") || recovered_panics() != p0+1 {
			t.Fatalf("%s on a nil chain: err %v, recovered panics +%d (want an internal error, +1)", name, err, recovered_panics()-p0)
		}
	}
	old := emission_state
	emission_state = nil
	defer func() { emission_state = old }()
	p0 := recovered_panics()
	if _, err := GetEmissionAudit(ctx); err == nil || !strings.HasPrefix(err.Error(), "internal error: ") || recovered_panics() != p0+1 {
		t.Fatalf("GetEmissionAudit with no auditor: err %v, +%d", err, recovered_panics()-p0)
	}
}

// R26 metrics gap: p2p_bans_total counts bans made since start; the gauge is the list, persisted entries included
func TestR27BanListGauge(t *testing.T) {
	var b bytes.Buffer
	write_node_metrics(&b, node_snapshot{ok: true, ban_list_entries: 1, status: "synced"})
	if !strings.Contains(b.String(), "\ndero_p2p_ban_list_entries 1\n") || !strings.Contains(b.String(), "# TYPE dero_p2p_ban_list_entries gauge") {
		t.Fatalf("gauge missing:\n%s", b.String())
	}
	b.Reset()
	write_node_metrics(&b, node_snapshot{ok: false})
	if strings.Contains(b.String(), "ban_list") {
		t.Fatal("gauge written for a node that is not up")
	}
	_, _, done := r25_sim(t, 2)
	defer done()
	// the snapshot reads the list itself (p2p.Ban_Count): one more entry, one more in the gauge (documentation address)
	n0 := p2p.Ban_Count()
	if err := p2p.Ban_Address_Reason("198.51.100.27", 600, p2p.BAN_SOURCE_OPERATOR, "r27 gauge test"); err != nil {
		t.Fatal(err)
	}
	defer p2p.UnBan_Address("198.51.100.27")
	if s := collect_node_snapshot(); !s.ok || s.ban_list_entries != n0+1 {
		t.Fatalf("snapshot on a simulator chain: ok %v, ban_list_entries %d, want %d", s.ok, s.ban_list_entries, n0+1)
	}
}

// the 0 %-covered handlers the pages lean on, on a simulator chain
func TestR27TipHandlersOnSimulator(t *testing.T) {
	c, _, done := r25_sim(t, 5)
	defer done()
	ctx := context.Background()
	top := c.Load_TOPO_HEIGHT()
	si, err := GetSyncInfo(ctx)
	if err != nil || si.TopoHeight != top || si.Height != c.Get_Height() || si.TopBlockHash != c.Get_Top_ID().String() ||
		si.Status == "" || si.Reason == "" || si.Version == "" || si.TipTimestampMs == 0 {
		t.Fatalf("GetSyncInfo: %+v %v", si, err)
	}
	// no peers: a simulator node is never "synced" (the 'at the tip' judgement needs peers and a fresh tip)
	if si.Status == "synced" || si.PeersIncoming+si.PeersOutgoing != 0 {
		t.Fatalf("GetSyncInfo without peers: status %q peers %d/%d", si.Status, si.PeersIncoming, si.PeersOutgoing)
	}
	if st, _ := classify_sync(0, 0, si.TipAgeSeconds); st != si.Status {
		t.Fatalf("status %q, classify_sync %q", si.Status, st)
	}
	h := GetHeight(ctx)
	if h.Status != "OK" || int64(h.Height) != c.Get_Height() || h.TopoHeight != top || h.StableHeight != c.Get_Stable_Height() {
		t.Fatalf("GetHeight %+v", h)
	}
	if bc := GetBlockCount(ctx); bc.Status != "OK" || int64(bc.Count) != c.Get_Height() {
		t.Fatalf("GetBlockCount %+v (height %d)", bc, c.Get_Height())
	}
	lb, err := GetLastBlockHeader(ctx)
	if err != nil || lb.Status != "OK" || lb.Block_Header.Hash != c.Get_Top_ID().String() || lb.Block_Header.TopoHeight != top {
		t.Fatalf("GetLastBlockHeader %+v %v", lb, err)
	}
	if tp := GetTxPool(ctx); tp.Status != "OK" || len(tp.Tx_list) != 0 {
		t.Fatalf("GetTxPool %+v", tp)
	}
	ea, err := GetEmissionAudit(ctx)
	if err != nil || ea.Status == "" {
		t.Fatalf("GetEmissionAudit %+v %v", ea, err)
	}
	// and through the method table (the success path of typed_new)
	loc := r26_local(t)
	rsp, err := loc.Client.Call(context.Background(), "DERO.GetSyncInfo", nil)
	var si2 GetSyncInfo_Result
	if err != nil || rsp.UnmarshalResult(&si2) != nil || si2.TopoHeight != top {
		t.Fatalf("DERO.GetSyncInfo over JSON-RPC: %v %+v", err, si2)
	}
}

// every metric name RPC_METHODS.md documents exists in the source (R27: getwork_jobs_coalesced_total was documented
// since r23 and never existed)
func TestR27DocumentedMetricsExist(t *testing.T) {
	md, err := os.ReadFile("RPC_METHODS.md")
	if err != nil {
		t.Fatal(err)
	}
	src := r27_tree_source(t)
	re := regexp.MustCompile("`((?:rpc|p2p|getwork|dero|miniblock)_[a-z0-9_]*_total)(?:\\{[^`]*\\})?`")
	var missing []string
	seen := 0
	for _, m := range re.FindAllStringSubmatch(string(md), -1) {
		seen++
		if !strings.Contains(src, m[1]) {
			missing = append(missing, m[1])
		}
	}
	if seen < 10 {
		t.Fatalf("only %d metric names found in RPC_METHODS.md: pattern stale", seen)
	}
	if len(missing) > 0 {
		t.Fatalf("documented metrics with no source: %v", missing)
	}
}

func r27_tree_source(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	root := filepath.Join("..", "..", "..")
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() && (info.Name() == "vendor" || info.Name() == ".git" || info.Name() == "harness" || info.Name() == "artifacts") {
			return filepath.SkipDir
		}
		if !info.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			if s, err := os.ReadFile(p); err == nil {
				b.Write(s)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func reflectTypeOf(v interface{}) reflect.Type { return reflect.TypeOf(v) }

func itoa_signed(n int64) string { return strconv.FormatInt(n, 10) }

func errNotFoundForTest() error { return graviton.ErrNotFound }
