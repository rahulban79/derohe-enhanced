package crypto

// r26 (disclosure track, backlog B113 / research question FQ4 of artifacts/dero-rft.md §0.8.9): a STRUCTURAL KAT of
// the transfer-proof transcript. It pins, from the verifier's own source, which inputs each Fiat-Shamir challenge
// hashes, which proof fields enter any challenge preimage, where every proof field is used, and the base of the
// inner-product argument. The disclosure track's claims C1/C2/C5 rest on these lines; a future upstream change to the
// transcript (a new bound input, another base) makes this test fail, which is the signal that the defect's code path
// changed (a presence change for class DC2), never a silent drift.
//
// What this test does NOT do (artifacts/dero-rft.md §5 and §9 NO-GO): it builds no proof that the verifier wrongly
// accepts. The behavioural half only perturbs HONEST proofs (one field at a time, a different residue) and asserts that
// Verify refuses every one; it records which check refused it, as a cross-check of the source pins.
//
// R26_FQ4_SRC=<dir> parses proof_verify.go, proof_generate.go and proof_innerproduct.go from <dir> instead of this
// package (used to read the same pins at the Release152 tag and at the mainnet genesis-era tag; the record is
// harness/runtime/r26_fq4_presence_*.txt). The behavioural half always runs this package's code.

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
)

// r26Challenge is one challenge of a transcript: Name = the variable it is assigned to (or "cmp <x>" when it is
// compared with <x>, "return" when returned), Pre = the printed byte expressions of its hash preimage, in order.
type r26Challenge struct {
	Fn, Name string
	Pre      []string
}

type r26Transcript struct {
	Challenges []r26Challenge
	Uses       map[string][]string // proof field -> sorted distinct assignment targets (or "cond"/"call:<f>") that read it
	UX         string              // the printed RHS of the u_x assignment
	IPCall     string              // the printed call of the inner-product verifier
}

func r26Print(fset *token.FileSet, n ast.Node) string {
	var b bytes.Buffer
	if err := printer.Fprint(&b, fset, n); err != nil {
		return "<print error>"
	}
	return b.String()
}

func r26IsCall(e ast.Expr, name string) (*ast.CallExpr, bool) {
	c, ok := e.(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	switch f := c.Fun.(type) {
	case *ast.Ident:
		return c, f.Name == name
	case *ast.SelectorExpr:
		return c, f.Sel.Name == name
	}
	return nil, false
}

// r26FindCall returns the first call of `name` inside e.
func r26FindCall(e ast.Node, name string) *ast.CallExpr {
	var found *ast.CallExpr
	ast.Inspect(e, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		if x, ok := n.(ast.Expr); ok {
			if c, ok := r26IsCall(x, name); ok {
				found = c
				return false
			}
		}
		return true
	})
	return found
}

// r26Extract walks one function body in source order and records its challenges and the uses of `recv`.<field>.
func r26Extract(fset *token.FileSet, fn *ast.FuncDecl, recv string, tr *r26Transcript) {
	fname := fn.Name.Name
	if fn.Recv != nil && len(fn.Recv.List) == 1 {
		fname = strings.TrimPrefix(r26Print(fset, fn.Recv.List[0].Type), "*") + "." + fname
	}
	var cur []string
	record := func(name string, call *ast.CallExpr) {
		var pre []string
		if len(call.Args) == 1 {
			if id, ok := call.Args[0].(*ast.Ident); ok && id.Name == "input" {
				pre = append(pre, cur...)
			} else {
				pre = append(pre, r26Print(fset, call.Args[0]))
			}
		}
		tr.Challenges = append(tr.Challenges, r26Challenge{Fn: fname, Name: name, Pre: pre})
	}
	uses := map[string]map[string]bool{}
	use := func(field, target string) {
		if uses[field] == nil {
			uses[field] = map[string]bool{}
		}
		uses[field][target] = true
	}
	fieldsIn := func(n ast.Node) []string {
		var out []string
		ast.Inspect(n, func(m ast.Node) bool {
			if s, ok := m.(*ast.SelectorExpr); ok {
				if id, ok := s.X.(*ast.Ident); ok && id.Name == recv {
					out = append(out, s.Sel.Name)
				}
			}
			return true
		})
		return out
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.DeclStmt:
			if g, ok := s.Decl.(*ast.GenDecl); ok {
				for _, sp := range g.Specs {
					if vs, ok := sp.(*ast.ValueSpec); ok {
						for _, nm := range vs.Names {
							if nm.Name == "input" {
								cur = nil
							}
						}
					}
				}
			}
		case *ast.AssignStmt:
			if len(s.Lhs) == 1 && len(s.Rhs) == 1 {
				lhs := r26Print(fset, s.Lhs[0])
				for _, f := range fieldsIn(s.Rhs[0]) {
					use(f, lhs)
				}
				if lhs == "input" {
					if c, ok := r26IsCall(s.Rhs[0], "append"); ok && len(c.Args) >= 2 {
						for _, a := range c.Args[1:] {
							cur = append(cur, r26Print(fset, a))
						}
						return false
					}
				}
				if lhs == "u_x" {
					tr.UX = r26Print(fset, s.Rhs[0])
				}
				if c, ok := r26IsCall(s.Rhs[0], "reducedhash"); ok {
					record(lhs, c)
					return false
				}
				if c, ok := r26IsCall(s.Rhs[0], "hashmash1"); ok {
					tr.Challenges = append(tr.Challenges, r26Challenge{Fn: fname, Name: lhs, Pre: []string{"hashmash1(" + r26Print(fset, c.Args[0]) + ")"}})
					return false
				}
			}
		case *ast.IfStmt:
			for _, f := range fieldsIn(s.Cond) {
				use(f, "cond")
			}
			if b, ok := s.Cond.(*ast.BinaryExpr); ok {
				for _, side := range [][2]ast.Expr{{b.X, b.Y}, {b.Y, b.X}} {
					if c := r26FindCall(side[0], "reducedhash"); c != nil {
						record("cmp "+r26Print(fset, side[1]), c)
					}
				}
			}
		case *ast.ReturnStmt:
			for _, r := range s.Results {
				if c, ok := r26IsCall(r, "reducedhash"); ok {
					record("return", c)
				}
			}
		case *ast.ExprStmt:
			// an in-place method call (x.Add(...), x.Set(...)) writes its receiver: book the use to the receiver
			target := "call"
			if c, ok := s.X.(*ast.CallExpr); ok {
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
					target = r26Print(fset, sel.X)
				}
			}
			for _, f := range fieldsIn(s.X) {
				use(f, target)
			}
		}
		if x, ok := n.(ast.Expr); ok {
			if c, ok := r26IsCall(x, "Verify"); ok {
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok && r26Print(fset, sel.X) == recv+".ip" {
					tr.IPCall = r26Print(fset, c)
				}
			}
		}
		return true
	})
	for f, m := range uses {
		var ts []string
		for k := range m {
			ts = append(ts, k)
		}
		sort.Strings(ts)
		tr.Uses[fname+":"+f] = ts
	}
}

// r26ParseTranscript reads the three proof files from dir and extracts the transcript of Proof.Verify,
// Proof.hashmash1 and InnerProduct.Verify.
func r26ParseTranscript(t *testing.T, dir string) r26Transcript {
	t.Helper()
	tr := r26Transcript{Uses: map[string][]string{}}
	fset := token.NewFileSet()
	want := map[string]string{"proof_verify.go": "Proof.Verify", "proof_generate.go": "Proof.hashmash1", "proof_innerproduct.go": "InnerProduct.Verify"}
	for _, file := range []string{"proof_verify.go", "proof_generate.go", "proof_innerproduct.go"} {
		f, err := parser.ParseFile(fset, filepath.Join(dir, file), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		found := false
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 || len(fn.Recv.List[0].Names) != 1 {
				continue
			}
			name := strings.TrimPrefix(r26Print(fset, fn.Recv.List[0].Type), "*") + "." + fn.Name.Name
			if name == want[file] {
				r26Extract(fset, fn, fn.Recv.List[0].Names[0].Name, &tr)
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: function %s not found (the transcript moved: re-test FQ4)", file, want[file])
		}
	}
	return tr
}

func (tr r26Transcript) render() string {
	var b strings.Builder
	for _, c := range tr.Challenges {
		fmt.Fprintf(&b, "challenge %s %s <- [%s]\n", c.Fn, c.Name, strings.Join(c.Pre, " | "))
	}
	var ks []string
	for k := range tr.Uses {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		fmt.Fprintf(&b, "use %s -> %s\n", k, strings.Join(tr.Uses[k], ","))
	}
	fmt.Fprintf(&b, "u_x = %s\n", tr.UX)
	fmt.Fprintf(&b, "ip = %s\n", tr.IPCall)
	return b.String()
}

// r26BoundFields: the proof fields that appear in some challenge preimage (directly, not through an equation).
func (tr r26Transcript) boundFields() []string {
	set := map[string]bool{}
	for _, c := range tr.Challenges {
		for _, p := range c.Pre {
			for _, recv := range []string{"proof.", "ip."} {
				for _, part := range strings.Split(p, recv)[1:] {
					end := strings.IndexAny(part, ".[()")
					if end < 0 {
						end = len(part)
					}
					set[strings.TrimSuffix(recv, ".")+"."+part[:end]] = true
				}
			}
		}
	}
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// The pinned transcript (read 2026-11-04 at the R26 clone base 3de579bd; identical at Release152 and at the
// genesis-era tag Release44, see harness/runtime/r26_fq4_presence_*.txt). Every challenge in source order.
var r26PinnedChallenges = []string{
	"Proof.Verify statementhash <- [txid[:]]",
	"Proof.Verify anonsupport.v <- [ConvertBigIntToByte(statementhash) | proof.BA.Marshal() | proof.BS.Marshal() | proof.A.Marshal() | proof.B.Marshal()]",
	"Proof.Verify anonsupport.w <- [hashmash1(anonsupport.v)]",
	"Proof.Verify protsupport.y <- [ConvertBigIntToByte(anonsupport.w)]",
	"Proof.Verify protsupport.z <- [ConvertBigIntToByte(protsupport.y)]",
	"Proof.Verify x <- [ConvertBigIntToByte(protsupport.z) | proof.T_1.Marshal() | proof.T_2.Marshal()]",
	"Proof.Verify cmp proof.c.Text(16) <- [ConvertBigIntToByte(x) | sigmasupport.A_y.Marshal() | sigmasupport.A_D.Marshal() | sigmasupport.A_b.Marshal() | sigmasupport.A_X.Marshal() | sigmasupport.A_t.Marshal() | sigmasupport.A_u.Marshal()]",
	"Proof.Verify o <- [ConvertBigIntToByte(proof.c)]",
	"Proof.hashmash1 return <- [ConvertBigIntToByte(v) | proof.CLnG[i].Marshal() | proof.CRnG[i].Marshal() | proof.C_0G[i].Marshal() | proof.DG[i].Marshal() | proof.y_0G[i].Marshal() | proof.gG[i].Marshal() | proof.C_XG[i].Marshal() | proof.y_XG[i].Marshal()]",
	"InnerProduct.Verify o <- [ConvertBigIntToByte(o) | ip.ls[i].Marshal() | ip.rs[i].Marshal()]",
}

// The proof fields hashed into some preimage. Not in the list: the responses (f, z_A, that, s_sk, s_r, s_b, s_tau),
// which enter through equations checked against c; u (through A_u); mu; and the final ip.a, ip.b.
var r26PinnedBound = []string{"ip.ls", "ip.rs", "proof.A", "proof.B", "proof.BA", "proof.BS", "proof.CLnG", "proof.CRnG",
	"proof.C_0G", "proof.C_XG", "proof.DG", "proof.T_1", "proof.T_2", "proof.c", "proof.gG", "proof.y_0G", "proof.y_XG"}

// Where every proof field is read (the assignment target or the in-place receiver; "input" = a preimage, "cond" = an
// if condition). mu only builds the inner-product statement P, which is the code path of claims C1/C2 (the disclosure
// track's anchors proof_verify.go:430 and :452).
var r26PinnedUses = map[string]string{
	"InnerProduct.Verify:a":  "gtemp,utemp",
	"InnerProduct.Verify:b":  "htemp,utemp",
	"InnerProduct.Verify:ls": "PPrimeL,cond,input,log_n",
	"InnerProduct.Verify:rs": "PPrimeR,cond,input",
	"Proof.Verify:A":         "input,stored",
	"Proof.Verify:B":         "input,stored",
	"Proof.Verify:BA":        "P,input",
	"Proof.Verify:BS":        "P,input",
	"Proof.Verify:CLnG":      "anonsupport.CLnR",
	"Proof.Verify:CRnG":      "anonsupport.CRnR",
	"Proof.Verify:C_0G":      "anonsupport.CR[0][0]",
	"Proof.Verify:C_XG":      "anonsupport.C_XR",
	"Proof.Verify:DG":        "anonsupport.DR",
	"Proof.Verify:T_1":       "input,protsupport.tEval",
	"Proof.Verify:T_2":       "input,protsupport.tEval",
	"Proof.Verify:c":         "cond,o,proof_c_neg,sigmasupport.A_t",
	"Proof.Verify:f":         "anonsupport.f[k][0],anonsupport.f[k][1],cond,m",
	"Proof.Verify:gG":        "anonsupport.gR",
	"Proof.Verify:hashmash1": "anonsupport.w",
	"Proof.Verify:ip":        "cond",
	"Proof.Verify:mu":        "P",
	"Proof.Verify:s_b":       "proof_s_b_neg,sigmasupport.A_b",
	"Proof.Verify:s_r":       "sigmasupport.A_D,sigmasupport.A_X",
	"Proof.Verify:s_sk":      "left,sigmasupport.A_u,sigmasupport.A_y",
	"Proof.Verify:s_tau":     "sigmasupport.A_t",
	"Proof.Verify:that":      "P,protsupport.t",
	"Proof.Verify:u":         "sigmasupport.A_u",
	"Proof.Verify:y_0G":      "anonsupport.yR[0][0]",
	"Proof.Verify:y_XG":      "anonsupport.y_XR",
	"Proof.Verify:z_A":       "computed",
	"Proof.hashmash1:CLnG":   "input",
	"Proof.hashmash1:CRnG":   "input",
	"Proof.hashmash1:C_0G":   "input",
	"Proof.hashmash1:C_XG":   "input",
	"Proof.hashmash1:DG":     "input",
	"Proof.hashmash1:gG":     "input",
	"Proof.hashmash1:y_0G":   "input",
	"Proof.hashmash1:y_XG":   "input",
}

const r26PinnedUX = "new(bn256.G1).ScalarMult(gparams.H, o)"
const r26PinnedIP = "proof.ip.Verify(hPrimes, u_x, P, o, gparams)"

func r26SrcDir() string {
	if d := os.Getenv("R26_FQ4_SRC"); d != "" {
		return d
	}
	return "."
}

func TestR26TranscriptBindingPinned(t *testing.T) {
	dir := r26SrcDir()
	tr := r26ParseTranscript(t, dir)
	t.Logf("R26-FQ4 src=%s\n%s", dir, tr.render())
	var got []string
	for _, c := range tr.Challenges {
		got = append(got, fmt.Sprintf("%s %s <- [%s]", c.Fn, c.Name, strings.Join(c.Pre, " | ")))
	}
	if strings.Join(got, "\n") != strings.Join(r26PinnedChallenges, "\n") {
		t.Errorf("transcript challenges changed (FQ4 presence change: re-test C1/C2/C5)\n got:\n%s\nwant:\n%s",
			strings.Join(got, "\n"), strings.Join(r26PinnedChallenges, "\n"))
	}
	if b := strings.Join(tr.boundFields(), ","); b != strings.Join(r26PinnedBound, ",") {
		t.Errorf("fields bound into a preimage changed\n got: %s\nwant: %s", b, strings.Join(r26PinnedBound, ","))
	}
	for k, want := range r26PinnedUses {
		if g := strings.Join(tr.Uses[k], ","); g != want {
			t.Errorf("uses of %s changed: got %q want %q", k, g, want)
		}
	}
	for k := range tr.Uses {
		if _, ok := r26PinnedUses[k]; !ok {
			t.Errorf("new use of a proof field: %s -> %s (unpinned: re-test FQ4)", k, strings.Join(tr.Uses[k], ","))
		}
	}
	if tr.UX != r26PinnedUX {
		t.Errorf("inner-product base changed: got %q want %q (FX-F1 territory: re-test C1)", tr.UX, r26PinnedUX)
	}
	if tr.IPCall != r26PinnedIP {
		t.Errorf("inner-product call changed: got %q want %q", tr.IPCall, r26PinnedIP)
	}
	// the headline structural fact of C2, stated as a predicate over the pins: mu is in no challenge preimage
	for _, f := range tr.boundFields() {
		if f == "proof.mu" {
			t.Errorf("proof.mu is now hashed into a challenge preimage: presence change for DC2 (FX-F2 shape)")
		}
	}
}

// Negative control of the extractor: a planted transcript change on a copy of the verifier must be seen.
func TestR26TranscriptExtractorSeesPlantedChange(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(r26SrcDir(), "proof_verify.go"))
	if err != nil {
		t.Fatal(err)
	}
	anchor := "\t\tinput = append(input, sigmasupport.A_u.Marshal()...)\n"
	if !bytes.Contains(src, []byte(anchor)) {
		t.Fatalf("anchor line for the planted change is gone (re-test FQ4)")
	}
	plants := map[string][]byte{
		"bind-mu":  bytes.Replace(src, []byte(anchor), []byte(anchor+"\t\tinput = append(input, ConvertBigIntToByte(proof.mu)...)\n"), 1),
		"drop-A_u": bytes.Replace(src, []byte(anchor), nil, 1),
		"base-G":   bytes.Replace(src, []byte("u_x := new(bn256.G1).ScalarMult(gparams.H, o)"), []byte("u_x := new(bn256.G1).ScalarMult(gparams.G, o)"), 1),
	}
	for name, mod := range plants {
		dir := t.TempDir()
		for _, f := range []string{"proof_generate.go", "proof_innerproduct.go"} {
			b, err := os.ReadFile(filepath.Join(r26SrcDir(), f))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, f), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "proof_verify.go"), mod, 0o600); err != nil {
			t.Fatal(err)
		}
		a, b := r26ParseTranscript(t, r26SrcDir()).render(), r26ParseTranscript(t, dir).render()
		if a == b {
			t.Errorf("planted change %s was not seen by the extractor", name)
		}
	}
}

// --- behavioural cross-check on HONEST proofs only ---

type r26Sink struct{ msgs []string }

func (s *r26Sink) logger() logr.Logger {
	return funcr.New(func(prefix, args string) { s.msgs = append(s.msgs, args) }, funcr.Options{Verbosity: 1})
}

// r26RefusalStage verifies p and returns "accepted", or the check that refused it: the Verify log line that fired, or
// "inner-product" when the inner-product verifier panicked (proof_innerproduct.go:308), or "other".
func r26RefusalStage(h r25Honest, p *Proof) (stage string) {
	sink := &r26Sink{}
	old := Logger
	Logger = sink.logger()
	defer func() {
		Logger = old
		if r := recover(); r != nil {
			stage = "inner-product"
		}
	}()
	if h.verify(p) {
		return "accepted"
	}
	for _, m := range sink.msgs {
		for _, k := range []string{"Parity check failed", "Recover key failed", "C calculation failed", "inner proof failed"} {
			if strings.Contains(m, k) {
				return k
			}
		}
	}
	return "other"
}

// The refusal stage of a one-field change (+1, a different residue) of an honest proof. "C calculation failed" means
// the challenge comparison refuses it; a field refused only by the inner-product check is bound by the final
// inner-product equation alone, which is the structural statement of claim C2 (mu: the disclosure track's anchor
// proof_verify.go:452), nothing more.
var r26PinnedStage = map[string]string{
	"z_A": "Recover key failed", "that": "C calculation failed", "mu": "inner-product", "c": "C calculation failed",
	"s_sk": "C calculation failed", "s_r": "C calculation failed", "s_b": "C calculation failed",
	"s_tau": "C calculation failed", "ip.a": "inner-product", "ip.b": "inner-product",
}

func TestR26HonestPerturbationRefused(t *testing.T) {
	for _, rc := range r25Rings {
		h := r25HonestProof(t, rc[0], rc[1], rc[2])
		honest := h.bytesOf(h.proof)
		if st := r26RefusalStage(h, h.decode(t, honest)); st != "accepted" {
			t.Fatalf("ring %d: the honest proof was refused (%s)", rc[0], st)
		}
		names := r25ScalarFields(h.proof)
		for idx := range names {
			p := h.decode(t, honest)
			f := r25ScalarFields(p)[idx]
			*f.v = new(big.Int).Mod(new(big.Int).Add(*f.v, big.NewInt(1)), bn256.Order)
			st := r26RefusalStage(h, p)
			t.Logf("R26-FQ4b ring %d sender %d field %s refused-by %q", rc[0], rc[1], f.name, st)
			if st == "accepted" {
				t.Fatalf("ring %d: a perturbed honest proof (%s) was ACCEPTED", rc[0], f.name)
			}
			if want, ok := r26PinnedStage[f.name]; ok && st != want {
				t.Errorf("ring %d: %s refused by %q, pinned %q", rc[0], f.name, st, want)
			}
			if !strings.HasPrefix(f.name, "f[") {
				continue
			}
			if st == "inner-product" {
				t.Errorf("ring %d: %s refused only by the inner-product check (pinned: an earlier check)", rc[0], f.name)
			}
		}
	}
}
