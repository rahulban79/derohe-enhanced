package rpc

// r24 cryptoinfl tests (CI24-1): GetMonetaryIntegrity must carry every emission total GetEmissionAudit carries.

import (
	crand "crypto/rand"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	mbits "math/bits"
	"reflect"
	"testing"
	"time"

	"github.com/deroproject/derohe/glue/emission"
	"github.com/deroproject/graviton"
)

// r24_fill_every_field sets every scalar field of the auditor result to a distinct non-zero value (bools true), so a
// field mapping that forgets one leaves a zero the test can see. The test does not list field names: a field added
// later to both structs is covered without editing it.
func r24_fill_every_field(a *emission_auditor) {
	v := reflect.ValueOf(&a.res).Elem()
	n := uint64(11)
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		switch f.Kind() {
		case reflect.Uint64:
			f.SetUint(n)
		case reflect.Int64:
			f.SetInt(int64(n))
		case reflect.Float64:
			f.SetFloat(float64(n) + 0.5)
		case reflect.Bool:
			f.SetBool(true)
		case reflect.String:
			f.SetString("x")
		}
		n += 7
	}
	a.res.Alerts = 0 // status OK; the ALERT branch is covered by the r23c equality test
	a.res.Verdicts = map[string]uint64{"ok": 5, "ok_sc": 6}
	a.res.Recent = []emission.Report{{}, {}}
	a.res.Notable = []emission.Report{{}}
}

func TestR24MonetaryIntegrityCarriesEveryEmissionTotal(t *testing.T) {
	a := new_emission_auditor()
	r24_fill_every_field(a)
	got := a.summary()
	src := reflect.ValueOf(a.res)
	gv := reflect.ValueOf(got)
	gt := gv.Type()
	for i := 0; i < gt.NumField(); i++ {
		name := gt.Field(i).Name
		sf := src.FieldByName(name)
		if !sf.IsValid() {
			t.Fatalf("MonetaryIntegrity_Emission.%s has no GetEmissionAudit_Result counterpart", name)
		}
		if name == "Status" || name == "Verdicts" {
			continue
		}
		if !reflect.DeepEqual(gv.Field(i).Interface(), sf.Interface()) {
			t.Errorf("summary().%s = %v, auditor has %v (GetMonetaryIntegrity would publish the wrong value)", name, gv.Field(i).Interface(), sf.Interface())
		}
	}
	if got.Status != "OK" || !reflect.DeepEqual(got.Verdicts, a.res.Verdicts) {
		t.Fatalf("status %q verdicts %v", got.Status, got.Verdicts)
	}
	if want := emission_summary(a.snapshot()); !reflect.DeepEqual(got, want) {
		t.Fatalf("summary %+v\nsnapshot view %+v", got, want)
	}
	got.Verdicts["ok"] = 99
	if a.res.Verdicts["ok"] != 5 {
		t.Fatalf("summary shares the auditor's Verdicts map")
	}
	if len(a.res.Recent) != 2 || len(a.res.Notable) != 1 {
		t.Fatalf("summary changed the auditor's lists")
	}
}

// The live r23c reading (2026-11-02 12:18 UTC, evidence/live_DERO.GetMonetaryIntegrity.json) in miniature: an auditor
// with issued == formula and 7,117 payees must not publish issued_matches_formula=false / payees=0.
func TestR24MonetaryIntegrityLiveShape(t *testing.T) {
	a := new_emission_auditor()
	a.res.Enabled, a.res.Audited = true, 1051
	a.res.ObservedEmission, a.res.FormulaEmission, a.res.IssuedEmission, a.res.IssuedMatchesFormula = 31918500, 31918500, 31918500, true
	a.res.Payees, a.res.PayeesVerified, a.res.PayeesExplained = 7117, 7116, 7117
	mi := monetary_integrity_of(GetMonetaryIntegrity_Params{}, a.summary(), HF3Exemption_Facts{}, Reorg_Stats{}, 7845335)
	e := mi.Emission
	if !e.IssuedMatchesFormula || e.IssuedEmission != 31918500 || e.Payees != 7117 || e.PayeesVerified != 7116 || e.PayeesExplained != 7117 {
		t.Fatalf("GetMonetaryIntegrity emission = %+v", e)
	}
}

// ---- CI24-3: depth-corrected decoy sampling -------------------------------------------------------------------

func r24_tree(t testing.TB, n int) (*graviton.Tree, map[string]int) {
	store, err := graviton.NewMemStore()
	if err != nil {
		t.Fatal(err)
	}
	ss, err := store.LoadSnapshot(0)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := ss.GetTree("r24")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		var k [33]byte
		if _, err := crand.Read(k[:]); err != nil {
			t.Fatal(err)
		}
		if err := tr.Put(k[:], []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tr.Commit(); err != nil {
		t.Fatal(err)
	}
	// ground truth, independent of graviton's proof code: in a binary trie over the key hashes (graviton.Sum, bit 0
	// = MSB of byte 0, node.go isBitSet), the branching ancestors of leaf L sit at the distinct common-prefix lengths
	// LCP(h_L, h_x) over all other keys x
	var keys [][]byte
	c := tr.Cursor()
	for k, _, err := c.First(); err == nil; k, _, err = c.Next() {
		keys = append(keys, append([]byte(nil), k...))
	}
	if len(keys) != n {
		t.Fatalf("cursor saw %d of %d leaves", len(keys), n)
	}
	hs := make([][graviton.HASHSIZE]byte, n)
	for i, k := range keys {
		hs[i] = graviton.Sum(k)
	}
	lcp := func(a, b *[graviton.HASHSIZE]byte) int {
		for i := 0; i < graviton.HASHSIZE; i++ {
			if x := a[i] ^ b[i]; x != 0 {
				return i*8 + mbits.LeadingZeros8(x)
			}
		}
		return graviton.HASHSIZE * 8
	}
	depth := map[string]int{}
	for i := range keys {
		var seen [graviton.HASHSIZE*8 + 1]bool
		b := 0
		for j := range keys {
			if j == i {
				continue
			}
			if l := lcp(&hs[i], &hs[j]); !seen[l] {
				seen[l] = true
				b++
			}
		}
		pb, err := r24_branching(tr, keys[i])
		if err != nil {
			t.Fatal(err)
		}
		if pb != b {
			t.Fatalf("leaf %x: r24_branching %d, trie ground truth %d", keys[i][:4], pb, b)
		}
		depth[string(keys[i])] = b
	}
	return tr, depth
}

// per-class draw share / leaf share: 1.0 everywhere is a uniform sampler
func r24_class_ratios(depth map[string]int, drawn map[int]int, total int) map[int]float64 {
	leaves := map[int]int{}
	for _, b := range depth {
		leaves[b]++
	}
	r := map[int]float64{}
	for b, n := range leaves {
		r[b] = (float64(drawn[b]) / float64(total)) / (float64(n) / float64(len(depth)))
	}
	return r
}

// KAT: the leaf probability of graviton Random is 2^-b (so b-classes one apart differ x2 per leaf), and the r24 sampler
// is flat over every class with b <= B.
func TestR24DecoySamplerIsDepthCorrected(t *testing.T) {
	tr, depth := r24_tree(t, 4096)
	leaves := map[int]int{}
	for _, b := range depth {
		leaves[b]++
	}
	raw := map[int]int{}
	const N = 60000
	for i := 0; i < N; i++ {
		k, _, err := tr.Random()
		if err != nil {
			t.Fatal(err)
		}
		raw[depth[string(k)]]++
	}
	rr := r24_class_ratios(depth, raw, N)

	got := map[int]int{}
	total, B := 0, 0
	cache := &r24_decoy_bcache{now: time.Now}
	for total < N {
		ds, st := r24_decoy_draws(tr, "r24", cache, R24_DECOY_WANT, R24_DECOY_DRAW_BUDGET, r24_coin)
		if st.Draws > R24_DECOY_DRAW_BUDGET || len(ds) > R24_DECOY_WANT {
			t.Fatalf("bounds: %+v %d", st, len(ds))
		}
		B = st.B
		for _, d := range ds {
			if d.b != depth[string(d.k)] {
				t.Fatalf("branching %d, cursor walk %d", d.b, depth[string(d.k)])
			}
			got[d.b]++
			total++
		}
	}
	nr := r24_class_ratios(depth, got, total)
	t.Logf("leaves per b %v; B=%d\nraw Random ratio %v\nr24 ratio        %v", leaves, B, rr, nr)
	var worstRaw, worstNew float64
	for b, n := range leaves {
		if n < 200 || b > B { // classes too small to measure, or deeper than B (still under-drawn by design)
			continue
		}
		if d := math.Abs(rr[b] - 1); d > worstRaw {
			worstRaw = d
		}
		if d := math.Abs(nr[b] - 1); d > worstNew {
			worstNew = d
		}
	}
	if worstNew > 0.06 {
		t.Fatalf("r24 sampler not flat over b<=B: worst |ratio-1| %.3f (%v)", worstNew, nr)
	}
	if worstRaw < 0.3 {
		t.Fatalf("test lost its control: raw Random looks flat (worst %.3f)", worstRaw)
	}
	// independent check of r24_branching: graviton Random draws a leaf with 2^-b, so per-leaf draw rates of classes
	// one apart differ by exactly 2 when b is right
	for b, n := range leaves {
		if n < 300 || leaves[b+1] < 300 {
			continue
		}
		if q := rr[b] / rr[b+1]; q < 1.75 || q > 2.25 {
			t.Fatalf("raw rate ratio b=%d/b=%d is %.3f, want 2 (r24_branching wrong?)", b, b+1, q)
		}
	}
}

type r24_failing_tree struct{ calls int }

func (f *r24_failing_tree) Random() ([]byte, []byte, error) {
	f.calls++
	return nil, nil, graviton.ErrNoMoreKeys
}
func (f *r24_failing_tree) GenerateProof([]byte) (*graviton.Proof, error) {
	return nil, graviton.ErrNoMoreKeys
}

// forged inputs: a tree that always fails, and a coin that always rejects, cannot make one call exceed the budget
func TestR24DecoySamplerBudgetBound(t *testing.T) {
	cache := &r24_decoy_bcache{now: time.Now}
	f := &r24_failing_tree{}
	ds, st := r24_decoy_draws(f, "fail", cache, R24_DECOY_WANT, R24_DECOY_DRAW_BUDGET, r24_coin)
	if len(ds) != 0 || st.Draws != R24_DECOY_DRAW_BUDGET || f.calls != R24_DECOY_DRAW_BUDGET {
		t.Fatalf("failing tree: %d draws %+v calls %d", len(ds), st, f.calls)
	}
	if _, ok := cache.get("fail"); ok {
		t.Fatalf("a failed pilot must not cache a B")
	}
	tr, _ := r24_tree(t, 64)
	ds, st = r24_decoy_draws(tr, "t64", cache, R24_DECOY_WANT, R24_DECOY_DRAW_BUDGET, func(int) bool { return false })
	if len(ds) != 0 || st.Draws != R24_DECOY_DRAW_BUDGET || st.Pilot != R24_DECOY_PILOT {
		t.Fatalf("rejecting coin: %d draws %+v", len(ds), st)
	}
	// the cached B is reused: no pilot on the next call
	ds, st = r24_decoy_draws(tr, "t64", cache, 10, R24_DECOY_DRAW_BUDGET, r24_coin)
	if !st.Cached || st.Pilot != 0 || len(ds) != 10 {
		t.Fatalf("cache: %+v", st)
	}
	// a one-leaf tree (a new token): b = 0, B = slack, each draw kept with 2^-slack; the call still fills
	one, _ := r24_tree(t, 1)
	ds, st = r24_decoy_draws(one, "one", cache, 5, R24_DECOY_DRAW_BUDGET, r24_coin)
	if len(ds) != 5 || st.Draws > R24_DECOY_DRAW_BUDGET || st.B != R24_DECOY_SLACK {
		t.Fatalf("one-leaf tree: %d draws %+v", len(ds), st)
	}
}

// B = round(log2 n) + slack: the mean of 2^b over raw draws is an unbiased estimate of n
func TestR24DecoyBFromPilot(t *testing.T) {
	if b := r24_decoy_B_from([]int{21, 21, 21, 21}); b != 23 {
		t.Fatalf("B %d", b)
	}
	if b := r24_decoy_B_from(nil); b != -1 {
		t.Fatalf("empty pilot B %d", b)
	}
	tr, depth := r24_tree(t, 4096)
	var bs []int
	for i := 0; i < R24_DECOY_PILOT; i++ {
		k, _, _ := tr.Random()
		bs = append(bs, depth[string(k)])
	}
	if b := r24_decoy_B_from(bs); b != 12+R24_DECOY_SLACK {
		t.Fatalf("n=4096 gives B %d, want %d", b, 12+R24_DECOY_SLACK)
	}
}

// the cache expires and is bounded
func TestR24DecoyBCacheTTLAndBound(t *testing.T) {
	now := time.Unix(1000, 0)
	c := &r24_decoy_bcache{now: func() time.Time { return now }}
	c.put("a", 5)
	if b, ok := c.get("a"); !ok || b != 5 {
		t.Fatalf("get")
	}
	now = now.Add(R24_DECOY_B_TTL + time.Second)
	if _, ok := c.get("a"); ok {
		t.Fatalf("expired entry served")
	}
	for i := 0; i < R24_DECOY_B_TREES+10; i++ {
		c.put(string(rune(i)), i)
	}
	if len(c.m) > R24_DECOY_B_TREES {
		t.Fatalf("cache holds %d trees", len(c.m))
	}
}

func TestR24DecoyCoin(t *testing.T) {
	if !r24_coin(0) || !r24_coin(-3) || r24_coin(63) || r24_coin(100) {
		t.Fatalf("coin edges")
	}
	n := 0
	for i := 0; i < 40000; i++ {
		if r24_coin(2) {
			n++
		}
	}
	if f := float64(n) / 40000; f < 0.23 || f > 0.27 {
		t.Fatalf("coin(2) frequency %.4f, want 0.25", f)
	}
}

// census: GetRandomAddress draws through the r24 sampler and nowhere calls Tree.Random itself
func TestR24GetRandomAddressUsesSampler(t *testing.T) {
	fs := token.NewFileSet()
	f, err := parser.ParseFile(fs, "rpc_dero_getrandomaddress.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	sampler, raw := 0, 0
	ast.Inspect(f, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := c.Fun.(type) {
		case *ast.Ident:
			if fn.Name == "r24_decoy_draws" {
				sampler++
			}
		case *ast.SelectorExpr:
			if fn.Sel.Name == "Random" {
				raw++
			}
		}
		return true
	})
	if sampler != 1 || raw != 0 {
		t.Fatalf("GetRandomAddress: %d sampler calls, %d raw Random calls", sampler, raw)
	}
	if remote_cost("DERO.GetRandomAddress") != 8 || remote_cost("getrandomaddress") != 8 {
		t.Fatalf("GetRandomAddress remote cost %d", remote_cost("DERO.GetRandomAddress"))
	}
}

// concurrent GetRandomAddress calls share the B cache (each call loads its own tree); -race
func TestR24DecoyCacheConcurrent(t *testing.T) {
	cache := &r24_decoy_bcache{now: time.Now}
	trees := make([]*graviton.Tree, 4)
	for i := range trees {
		trees[i], _ = r24_tree(t, 32)
	}
	done := make(chan r24_decoy_stats, 8)
	for g := 0; g < 8; g++ {
		go func(g int) {
			_, st := r24_decoy_draws(trees[g%4], "shared", cache, 20, R24_DECOY_DRAW_BUDGET, r24_coin)
			done <- st
		}(g)
	}
	for g := 0; g < 8; g++ {
		if st := <-done; st.Accepted != 20 || st.B < 0 {
			t.Fatalf("goroutine stats %+v", st)
		}
	}
	if _, ok := cache.get("shared"); !ok {
		t.Fatalf("no B cached")
	}
}
