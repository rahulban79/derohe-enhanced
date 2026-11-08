package crypto

// r28d (rft §7 B179; ported from the DEROFDN community-dev evaluation CD1-CD3, 2026-11-06): the generator-binding
// census of the range proof, structural only.
//
// One row per scalar x base product CALL SITE in the prover (proof_generate.go, the generate* functions of
// proof_innerproduct.go) and the verifier ((*Proof).Verify in proof_verify.go, (*InnerProduct).Verify). A call is a product when its callee (resolved with go/types) takes or is called on a point
// type (bn256.G1, PointVector, ElGamal, ElGamalVector, GeneratorParams, Pedersen*Commitment*, Point) and takes a scalar
// type (big.Int, []*big.Int, FieldVector, BNRed), or is the Commit of a commitment type that holds both. Code inside
// comments is not code and is not a row (the prover's commented-out block at proof_generate.go:1197-1221 is recorded
// in the checklist as an observation).
//
// The checklist (harness/model/evidence/r28d_binding_census.json, all 128 rows reviewed) is the reviewed copy. This test
// recomputes the census from the source and fails when a row appears, disappears or changes, so an upstream change of
// the proof code (for example a fix of disclosure C1) shows up as a test change, as Release151's FQ4 transcript KAT
// does. It also runs the class detector of §4.1: in one verification equation, a scalar that enters no Fiat-Shamir
// preimage ("free") on the same base as a transcript-bound scalar.
//
// Non-exploit by construction: the test reads source text only; it never builds, runs or verifies a proof.
//
//   R28D_CENSUS=<file>        checklist to compare with (default ../../harness/model/evidence/r28d_binding_census.json)
//   R28D_CENSUS_WRITE=<file>  write the recomputed rows (generation mode; the reviewed fields are merged by hand)
//
// A missing checklist FAILS the test (the evaluation copy skipped instead, r28d).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var r28dc_census_files = []string{"proof_generate.go", "proof_verify.go", "proof_innerproduct.go"}

type r28dCensusRow struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	Func      string `json:"func"`
	Role      string `json:"role"` // prover | verifier
	Callee    string `json:"callee"`
	Base      string `json:"base"`
	Scalar    string `json:"scalar"`
	BaseClass string `json:"base_class"`
	// reviewed fields (filled by hand in the checklist; the test checks presence where required, not content)
	Binding  string `json:"binding,omitempty"`  // bound:<preimage file:line> | free | response:<check file:line> | pending
	Equation string `json:"equation,omitempty"` // the verification equation the term enters (verifier rows)
	Note     string `json:"note,omitempty"`
}

type r28dCensus struct {
	Files        map[string]string `json:"files_sha256"`
	Rows         []r28dCensusRow   `json:"rows"`
	Observations []string          `json:"observations,omitempty"`
	Detector     []string          `json:"class_detector_hits,omitempty"`
}

func r28dc_type_name(t types.Type) string {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	if s, ok := t.(*types.Slice); ok {
		return "[]" + r28dc_type_name(s.Elem())
	}
	if n, ok := t.(*types.Named); ok {
		if n.Obj().Pkg() != nil {
			return n.Obj().Pkg().Name() + "." + n.Obj().Name()
		}
		return n.Obj().Name()
	}
	return t.String()
}

var r28dc_point_types = map[string]bool{"bn256.G1": true, "crypto.PointVector": true, "crypto.ElGamal": true,
	"crypto.ElGamalVector": true, "crypto.GeneratorParams": true, "crypto.PedersenVectorCommitment": true,
	"crypto.PedersenCommitmentNew": true, "crypto.PedersenCommitment": true, "crypto.Point": true}
var r28dc_scalar_types = map[string]bool{"big.Int": true, "[]big.Int": true, "crypto.FieldVector": true, "crypto.BNRed": true}
var r28dc_holds_both = map[string]bool{"crypto.PedersenVectorCommitment": true, "crypto.PedersenCommitment": true}

// base class from the base expression's text (structural, by name)
func r28dc_base_class(base string) string {
	b := strings.ReplaceAll(base, " ", "")
	switch {
	case b == "gparams.H" || b == "params.H" || b == "p.H" || b == "pvector.H" || strings.HasSuffix(b, "gp.H"):
		return "H"
	case b == "gparams.G" || b == "params.G" || b == "G" || b == "crypto.G" || b == "p.G" || b == "pvector.G":
		return "G"
	case b == "gparams.GSUM" || b == "params.GSUM":
		return "GSUM"
	case b == "u_x" || b == "u":
		return "u (IPA base)"
	case strings.Contains(b, "Gs") || strings.Contains(b, "gs") || strings.Contains(b, "gLeft") || strings.Contains(b, "gRight") || strings.Contains(b, "gtemp"):
		return "G-vector"
	case strings.Contains(b, "Hs") || strings.Contains(b, "hs") || strings.Contains(b, "hLeft") || strings.Contains(b, "hRight") || strings.Contains(b, "hPrime") || strings.Contains(b, "htemp"):
		return "H-vector"
	}
	return "statement/proof point"
}

// r28dc_census computes the rows from the package source; override replaces the text of named files (mutation controls)
func r28dc_census(override map[string][]byte) (r28dCensus, error) {
	out := r28dCensus{Files: map[string]string{}}
	fset := token.NewFileSet()
	names, _ := filepath.Glob("*.go")
	var files []*ast.File
	byname := map[string]*ast.File{}
	srcs := map[string][]byte{}
	for _, n := range names {
		if strings.HasSuffix(n, "_test.go") {
			continue
		}
		src, err := os.ReadFile(n)
		if err != nil {
			return out, err
		}
		if o, ok := override[n]; ok {
			src = o
		}
		f, err := parser.ParseFile(fset, n, src, 0)
		if err != nil {
			return out, err
		}
		files = append(files, f)
		byname[n] = f
		srcs[n] = src
	}
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}, Types: map[ast.Expr]types.TypeAndValue{}}
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil), Error: func(error) {}}
	if _, err := conf.Check("github.com/deroproject/derohe/cryptography/crypto", fset, files, info); err != nil && len(info.Uses) == 0 {
		return out, err
	}
	src := func(n ast.Node) string {
		var buf bytes.Buffer
		printer.Fprint(&buf, fset, n)
		return buf.String()
	}
	for _, fname := range r28dc_census_files {
		sum := sha256.Sum256(srcs[fname])
		out.Files[fname] = hex.EncodeToString(sum[:])
		for _, d := range byname[fname].Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			fn := fd.Name.Name
			role := "prover" // the verifier is (*Proof).Verify and (*InnerProduct).Verify; every other function proves
			if fd.Name.Name == "Verify" {
				role = "verifier"
			}
			if fd.Recv != nil && len(fd.Recv.List) == 1 {
				fn = "(" + src(fd.Recv.List[0].Type) + ")." + fn
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var sig *types.Signature
				var recvExpr ast.Expr
				var calleeName string
				switch fun := call.Fun.(type) {
				case *ast.SelectorExpr:
					if sel, ok := info.Selections[fun]; ok && sel.Kind() == types.MethodVal {
						sig, _ = sel.Obj().Type().(*types.Signature)
						recvExpr = fun.X
						calleeName = r28dc_type_name(sel.Recv()) + "." + fun.Sel.Name
					} else if obj, ok := info.Uses[fun.Sel]; ok {
						sig, _ = obj.Type().(*types.Signature)
						calleeName = src(fun)
					}
				case *ast.Ident:
					if obj, ok := info.Uses[fun]; ok {
						sig, _ = obj.Type().(*types.Signature)
						calleeName = fun.Name
					}
				}
				if sig == nil {
					return true
				}
				pkg := ""
				if fo, ok := info.Uses[r28dc_callee_ident(call.Fun)].(*types.Func); ok && fo.Pkg() != nil {
					pkg = fo.Pkg().Name()
				}
				if pkg != "crypto" && pkg != "bn256" {
					return true
				}
				hasPoint, hasScalar := false, false
				recvT := ""
				if sig.Recv() != nil {
					recvT = r28dc_type_name(sig.Recv().Type())
					hasPoint = r28dc_point_types[recvT]
				}
				var baseArg, scalarArg []string
				for i := 0; i < sig.Params().Len(); i++ {
					tn := r28dc_type_name(sig.Params().At(i).Type())
					arg := ""
					if i < len(call.Args) {
						arg = src(call.Args[i])
					}
					if r28dc_point_types[tn] {
						hasPoint = true
						baseArg = append(baseArg, arg)
					}
					if r28dc_scalar_types[tn] {
						hasScalar = true
						scalarArg = append(scalarArg, arg)
					}
				}
				if !(hasPoint && hasScalar) && !(r28dc_holds_both[recvT] && strings.HasSuffix(calleeName, ".Commit")) {
					return true
				}
				base := strings.Join(baseArg, ", ")
				if len(baseArg) == 0 && recvExpr != nil {
					base = src(recvExpr)
				} else if recvExpr != nil && r28dc_point_types[recvT] && recvT != "bn256.G1" {
					base = src(recvExpr) + " | " + base
				}
				if recvT == "bn256.G1" && len(baseArg) > 0 { // new(bn256.G1).ScalarMult(base, k): the receiver is the output
					base = strings.Join(baseArg, ", ")
				}
				row := r28dCensusRow{File: fname, Line: fset.Position(call.Pos()).Line, Func: fn, Role: role, Callee: calleeName,
					Base: base, Scalar: strings.Join(scalarArg, ", "), BaseClass: r28dc_base_class(strings.TrimSpace(strings.Split(base, "|")[len(strings.Split(base, "|"))-1]))}
				if row.Scalar == "" {
					row.Scalar = "(held by " + src(recvExpr) + ")"
				}
				out.Rows = append(out.Rows, row)
				return true
			})
		}
	}
	sort.SliceStable(out.Rows, func(i, j int) bool {
		if out.Rows[i].File != out.Rows[j].File {
			return out.Rows[i].File < out.Rows[j].File
		}
		return out.Rows[i].Line < out.Rows[j].Line
	})
	return out, nil
}

func r28dc_callee_ident(e ast.Expr) *ast.Ident {
	switch f := e.(type) {
	case *ast.SelectorExpr:
		return f.Sel
	case *ast.Ident:
		return f
	}
	return nil
}

func r28dc_key(r r28dCensusRow) string {
	return fmt.Sprintf("%s:%d|%s|%s|%s|%s", r.File, r.Line, r.Callee, r.Base, r.Scalar, r.BaseClass)
}

// the class detector over the reviewed checklist: per verifier equation, a free scalar on a base class that a
// transcript-bound scalar of the same equation also uses (directly, or via u_x = H^o which is H-based)
func r28dc_detect(rows []r28dCensusRow) []string {
	type eqv struct{ free, bound map[string][]string }
	eqs := map[string]*eqv{}
	for _, r := range rows {
		if r.Role != "verifier" || r.Equation == "" {
			continue
		}
		e := eqs[r.Equation]
		if e == nil {
			e = &eqv{free: map[string][]string{}, bound: map[string][]string{}}
			eqs[r.Equation] = e
		}
		cls := r.BaseClass
		if cls == "u (IPA base)" && strings.Contains(r.Note, "u_x = H^o") {
			cls = "H"
		}
		at := fmt.Sprintf("%s:%d %s", r.File, r.Line, r.Scalar)
		if r.Binding == "free" {
			e.free[cls] = append(e.free[cls], at)
		} else if strings.HasPrefix(r.Binding, "bound") {
			e.bound[cls] = append(e.bound[cls], at)
		}
	}
	var hits []string
	keys := make([]string, 0, len(eqs))
	for k := range eqs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		e := eqs[k]
		for cls, fr := range e.free {
			if b, ok := e.bound[cls]; ok {
				hits = append(hits, fmt.Sprintf("%s: free %v shares base %s with bound %v", k, fr, cls, b))
			}
		}
	}
	sort.Strings(hits)
	return hits
}

func r28dc_load_checklist(t *testing.T) r28dCensus {
	p := os.Getenv("R28D_CENSUS")
	if p == "" {
		p = "../../harness/model/evidence/r28d_binding_census.json"
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("no checklist at %s (%s): run with R28D_CENSUS=<file>", p, err)
	}
	var c r28dCensus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func r28dc_compare(got r28dCensus, want r28dCensus) []string {
	var diff []string
	for f, h := range want.Files {
		if got.Files[f] != h {
			diff = append(diff, fmt.Sprintf("file %s sha256 %s, checklist %s", f, got.Files[f], h))
		}
	}
	g, w := map[string]bool{}, map[string]bool{}
	for _, r := range got.Rows {
		g[r28dc_key(r)] = true
	}
	for _, r := range want.Rows {
		w[r28dc_key(r)] = true
	}
	for k := range g {
		if !w[k] {
			diff = append(diff, "row not in checklist: "+k)
		}
	}
	for k := range w {
		if !g[k] {
			diff = append(diff, "checklist row not in source: "+k)
		}
	}
	sort.Strings(diff)
	return diff
}

func TestR28dBindingCensusComplete(t *testing.T) {
	got, err := r28dc_census(nil)
	if err != nil {
		t.Fatal(err)
	}
	if p := os.Getenv("R28D_CENSUS_WRITE"); p != "" {
		j, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(p, j, 0644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %d rows to %s", len(got.Rows), p)
	}
	want := r28dc_load_checklist(t)
	if d := r28dc_compare(got, want); len(d) > 0 {
		t.Fatalf("census differs from the checklist (%d differences):\n%s", len(d), strings.Join(d, "\n"))
	}
	// CD3: every one of the rows (prover and verifier, all bases) carries a reviewed binding; no row says pending
	if bad := r28dc_unreviewed(want.Rows); len(bad) > 0 {
		t.Errorf("%d rows have no reviewed binding:\n%s", len(bad), strings.Join(bad, "\n"))
	}
	hits := r28dc_detect(want.Rows)
	if strings.Join(hits, "\n") != strings.Join(want.Detector, "\n") {
		t.Fatalf("class detector hits changed:\n got  %v\n want %v", hits, want.Detector)
	}
	if len(hits) == 0 {
		t.Fatal("the C1 instance is no longer detected: update rft B179 (an upstream fix may have landed)")
	}
	t.Logf("%d rows (%d prover, %d verifier); detector: %v", len(got.Rows), r28dc_count(got.Rows, "prover"), r28dc_count(got.Rows, "verifier"), hits)
}

// r28dc_unreviewed lists the rows whose binding is missing, pending or not of the reviewed grammar (CD1 + CD3), and the
// verifier rows without the equation the class detector groups by
func r28dc_unreviewed(rows []r28dCensusRow) (bad []string) {
	for _, r := range rows {
		ok := r.Binding == "free"
		for _, pre := range []string{"bound:", "response:", "secret:", "constant:", "unreachable:"} {
			if strings.HasPrefix(r.Binding, pre) {
				ok = true
			}
		}
		if !ok || (r.Role == "verifier" && r.Equation == "") {
			bad = append(bad, fmt.Sprintf("%s:%d %s binding=%q equation=%q", r.File, r.Line, r.Scalar, r.Binding, r.Equation))
		}
	}
	return
}

func r28dc_count(rows []r28dCensusRow, role string) (n int) {
	for _, r := range rows {
		if r.Role == role {
			n++
		}
	}
	return
}

// KAT controls: each mutation edits a copy of the source text (or of the checklist) and must be CAUGHT
func TestR28dBindingCensusControls(t *testing.T) {
	want := r28dc_load_checklist(t)
	verify, err := os.ReadFile("proof_verify.go")
	if err != nil {
		t.Fatal(err)
	}
	v := string(verify)
	mut := func(name, old, new string) {
		t.Helper()
		if strings.Count(v, old) != 1 {
			t.Fatalf("%s: anchor %q occurs %d times", name, old, strings.Count(v, old))
		}
		got, err := r28dc_census(map[string][]byte{"proof_verify.go": []byte(strings.Replace(v, old, new, 1))})
		if err != nil {
			t.Fatalf("%s: %s", name, err)
		}
		if len(r28dc_compare(got, want)) == 0 {
			t.Fatalf("%s: mutant NOT caught", name)
		}
	}
	// K1 a new product in the verifier (same line count: appended to an existing line)
	mut("K1 extra product", "u_x := new(bn256.G1).ScalarMult(gparams.H, o)", "u_x := new(bn256.G1).ScalarMult(gparams.H, o); _ = new(bn256.G1).ScalarMult(gparams.G, o)")
	// K2 the IPA base moved off H (the shape of a C1 fix): base and class of the row change
	mut("K2 u_x on G", "u_x := new(bn256.G1).ScalarMult(gparams.H, o)", "u_x := new(bn256.G1).ScalarMult(gparams.G, o)")
	// K3 a product removed (the -mu term)
	mut("K3 mu term removed", "P = new(bn256.G1).Add(P, new(bn256.G1).ScalarMult(gparams.H, new(big.Int).Mod(new(big.Int).Neg(proof.mu), bn256.Order)))", "P = new(bn256.G1).Add(P, new(bn256.G1))")
	// K4 checklist completeness: dropping any one row is caught
	for i := range want.Rows {
		short := want
		short.Rows = append(append([]r28dCensusRow{}, want.Rows[:i]...), want.Rows[i+1:]...)
		got, _ := r28dc_census(nil)
		if len(r28dc_compare(got, short)) == 0 {
			t.Fatalf("K4: dropping checklist row %d NOT caught", i)
		}
		if i > 3 {
			break // the comparison is a set difference; four drops show it, every row is checked by the main test
		}
	}
	// K5 detector: marking mu as bound removes the C1 hit
	rows := append([]r28dCensusRow{}, want.Rows...)
	changed := false
	for i := range rows {
		if rows[i].Binding == "free" && strings.Contains(rows[i].Scalar, "proof.mu") {
			rows[i].Binding = "bound:hypothetical"
			changed = true
		}
	}
	if !changed || strings.Join(r28dc_detect(rows), "\n") == strings.Join(want.Detector, "\n") {
		t.Fatal("K5: binding mu does not change the detector output")
	}
	// K6 (CD3): any one row set back to pending, prover or verifier, is caught by the all-rows review check
	if len(r28dc_unreviewed(want.Rows)) != 0 {
		t.Fatal("K6: the checklist itself has unreviewed rows")
	}
	for i := range want.Rows {
		rows := append([]r28dCensusRow{}, want.Rows...)
		rows[i].Binding = "pending"
		if len(r28dc_unreviewed(rows)) != 1 {
			t.Fatalf("K6: row %d (%s:%d) set to pending NOT caught", i, rows[i].File, rows[i].Line)
		}
	}
	// K7 (CD3): a second free scalar on H inside E3 (here: the bound o at :430 marked free) is a second detector hit
	rows = append([]r28dCensusRow{}, want.Rows...)
	for i := range rows {
		if rows[i].File == "proof_verify.go" && rows[i].Line == 430 {
			rows[i].Binding = "free"
		}
	}
	if len(r28dc_detect(rows)) == len(want.Detector) && strings.Join(r28dc_detect(rows), "\n") == strings.Join(want.Detector, "\n") {
		t.Fatal("K7: a second free scalar on H in E3 does not change the detector output")
	}
}
