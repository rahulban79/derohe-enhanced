package blockchain

// r28d (rft §7 B182 and B186; ported from the DEROFDN community-dev evaluation CD1, rows CD-02 and CD-03, 2026-11-06):
// the registration proof-of-work checks, read from the source. Report-only pin: no consensus code is changed.
//
// The test parses blockchain.go of the tree it runs in (it compiles against nothing that only one tree has, so the
// same file runs unchanged in the community-dev clone and in a Release151 tree) and evaluates the two registration
// PoW checks with a tiny interpreter over every class of txid bytes 0..2 (zero / non-zero), at heights below and at
// MAJOR_HF4_HEIGHT, with chain.simulator == false:
//
//   block  = the check inside Add_Complete_Block (the if whose condition reads tx_hash[0])
//   pool   = the check inside Add_TX_To_Pool      (the if whose condition reads tx_hash[0])
//
// B186 (CD-02): the block outcome must be the same at every height and equal to the reference "refuse iff byte0 != 0 and
//        byte1 != 0" (the rule both trees had before HF4 existed). A nested HF4 check that returns what its enclosing
//        block returns anyway cannot change any outcome; the negative controls below show the test notices one that
//        can.
// B182 (CD-03): the block check accepts txids the pool refuses (fewer leading zero bytes). The test pins that asymmetry as
//        it is (report-only: it is consensus behaviour) and the control shows an upstream fix would flip it.
//
// No chain is started and no consensus code is changed. Output: R28D_REG_OUT=<file> writes the truth tables as JSON.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

type r28dr_env struct {
	b      [3]int64
	height int64
	hf4    int64
}

type r28dr_interp struct {
	fset *token.FileSet
	env  r28dr_env
}

func (in *r28dr_interp) src(n ast.Node) string {
	var buf bytes.Buffer
	printer.Fprint(&buf, in.fset, n)
	return buf.String()
}

func (in *r28dr_interp) expr(e ast.Expr) interface{} {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return in.expr(x.X)
	case *ast.BasicLit:
		v, err := strconv.ParseInt(x.Value, 0, 64)
		if err != nil {
			panic(err)
		}
		return v
	case *ast.Ident:
		switch x.Name {
		case "false":
			return false
		case "true":
			return true
		}
	case *ast.IndexExpr:
		if id, ok := x.X.(*ast.Ident); ok && id.Name == "tx_hash" {
			return in.env.b[in.expr(x.Index).(int64)]
		}
	case *ast.SelectorExpr:
		switch in.src(x) {
		case "chain.simulator":
			return false
		case "bl.Height":
			return in.env.height
		case "globals.Config.MAJOR_HF4_HEIGHT":
			return in.env.hf4
		}
	case *ast.CallExpr: // only the integer conversions the checks use
		if id, ok := x.Fun.(*ast.Ident); ok && (id.Name == "uint64" || id.Name == "int64") && len(x.Args) == 1 {
			return in.expr(x.Args[0])
		}
	case *ast.UnaryExpr:
		if x.Op == token.NOT {
			return !in.expr(x.X).(bool)
		}
	case *ast.BinaryExpr:
		switch x.Op {
		case token.LAND:
			return in.expr(x.X).(bool) && in.expr(x.Y).(bool)
		case token.LOR:
			return in.expr(x.X).(bool) || in.expr(x.Y).(bool)
		}
		ra, rb := in.expr(x.X), in.expr(x.Y)
		switch x.Op {
		case token.EQL:
			return ra == rb
		case token.NEQ:
			return ra != rb
		}
		a, b := ra.(int64), rb.(int64)
		switch x.Op {
		case token.GEQ:
			return a >= b
		case token.GTR:
			return a > b
		case token.LEQ:
			return a <= b
		case token.LSS:
			return a < b
		}
	}
	panic(fmt.Sprintf("r28d registration interpreter: unsupported expression %q", in.src(e)))
}

// runs a statement list; returns the source of the first return reached, or "" when control falls through
func (in *r28dr_interp) stmts(list []ast.Stmt) string {
	for _, s := range list {
		switch x := s.(type) {
		case *ast.ReturnStmt:
			parts := make([]string, len(x.Results))
			for i, r := range x.Results {
				parts[i] = in.src(r)
			}
			return "return " + strings.Join(parts, ", ")
		case *ast.IfStmt:
			if x.Init != nil {
				panic("r28d registration interpreter: if with init")
			}
			if in.expr(x.Cond).(bool) {
				if r := in.stmts(x.Body.List); r != "" {
					return r
				}
			} else if x.Else != nil {
				var r string
				switch e := x.Else.(type) {
				case *ast.BlockStmt:
					r = in.stmts(e.List)
				case *ast.IfStmt:
					r = in.stmts([]ast.Stmt{e})
				}
				if r != "" {
					return r
				}
			}
		default:
			panic(fmt.Sprintf("r28d registration interpreter: unsupported statement %q", in.src(s)))
		}
	}
	return ""
}

// the registration PoW if inside function fn: the first if statement whose condition reads tx_hash[0]
func r28dr_find_check(f *ast.File, fset *token.FileSet, fn string) *ast.IfStmt {
	var found *ast.IfStmt
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != fn || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if found != nil {
				return false
			}
			if is, ok := n.(*ast.IfStmt); ok {
				var buf bytes.Buffer
				printer.Fprint(&buf, fset, is.Cond)
				if strings.Contains(buf.String(), "tx_hash[0]") {
					found = is
					return false
				}
			}
			return true
		})
	}
	return found
}

type r28dr_row struct {
	Bytes  string `json:"txid_bytes_0_2"` // Z = zero, N = non-zero (0xff)
	Height string `json:"height"`
	Block  string `json:"block_outcome"`
	Pool   string `json:"pool_outcome"`
}

type r28dr_tables struct {
	Rows        []r28dr_row `json:"rows"`
	BlockAccept []string    `json:"block_accepts"`
	PoolAccept  []string    `json:"pool_accepts"`
	HeightBound bool        `json:"block_outcome_depends_on_height"`
	MatchesRef  bool        `json:"block_equals_reference_two_byte_rule"`
	Asymmetric  []string    `json:"block_accepts_pool_refuses"`
	HF4Nested   bool        `json:"hf4_check_present"`
}

func r28dr_registration_tables(src []byte) (r28dr_tables, error) {
	var out r28dr_tables
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "blockchain.go", src, 0)
	if err != nil {
		return out, err
	}
	blk, pool := r28dr_find_check(f, fset, "Add_Complete_Block"), r28dr_find_check(f, fset, "Add_TX_To_Pool")
	if blk == nil || pool == nil {
		return out, fmt.Errorf("registration checks not found (block %v pool %v)", blk != nil, pool != nil)
	}
	var cbuf bytes.Buffer
	printer.Fprint(&cbuf, fset, blk)
	out.HF4Nested = strings.Contains(cbuf.String(), "MAJOR_HF4_HEIGHT")

	const hf4 = 8_000_000
	out.HeightBound, out.MatchesRef = false, true
	for mask := 0; mask < 8; mask++ {
		var b [3]int64
		label := ""
		for i := 0; i < 3; i++ {
			if mask&(1<<i) != 0 {
				b[i] = 0xff
				label += "N"
			} else {
				label += "Z"
			}
		}
		var outcomes [2]string
		for hi, h := range []int64{hf4 - 1, hf4} {
			in := &r28dr_interp{fset: fset, env: r28dr_env{b: b, height: h, hf4: hf4}}
			bo := in.stmts([]ast.Stmt{blk})
			po := in.stmts([]ast.Stmt{pool})
			if bo == "" {
				bo = "pass"
			}
			if po == "" {
				po = "pass"
			}
			outcomes[hi] = bo
			hl := "below_hf4"
			if hi == 1 {
				hl = "at_hf4"
			}
			out.Rows = append(out.Rows, r28dr_row{Bytes: label, Height: hl, Block: bo, Pool: po})
			ref_refuse := b[0] != 0 && b[1] != 0
			if (bo != "pass") != ref_refuse {
				out.MatchesRef = false
			}
			if hi == 0 {
				if bo == "pass" {
					out.BlockAccept = append(out.BlockAccept, label)
				}
				if po == "pass" {
					out.PoolAccept = append(out.PoolAccept, label)
				}
				if bo == "pass" && po != "pass" {
					out.Asymmetric = append(out.Asymmetric, label)
				}
			}
		}
		if outcomes[0] != outcomes[1] {
			out.HeightBound = true
		}
	}
	return out, nil
}

func TestR28dRegistrationPoWChecks(t *testing.T) {
	src, err := os.ReadFile("blockchain.go")
	if err != nil {
		t.Fatal(err)
	}
	tb, err := r28dr_registration_tables(src)
	if err != nil {
		t.Fatal(err)
	}
	if p := os.Getenv("R28D_REG_OUT"); p != "" {
		j, _ := json.MarshalIndent(tb, "", "  ")
		if err := os.WriteFile(p, j, 0644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("hf4 check present %v; block accepts %v; pool accepts %v; block-accepts-pool-refuses %v", tb.HF4Nested, tb.BlockAccept, tb.PoolAccept, tb.Asymmetric)

	// B186 (CD-02): no outcome depends on height, and the outcomes equal the pre-HF4 two-byte rule
	if tb.HeightBound {
		t.Fatal("B186 (CD-02): the block registration outcome depends on height (the HF4 lines change an outcome)")
	}
	if !tb.MatchesRef {
		t.Fatal("B186 (CD-02): the block registration outcome differs from the two-byte reference rule")
	}
	// B182 (CD-03): the pool demands three zero bytes, the block only that byte0 or byte1 be zero
	if len(tb.PoolAccept) != 1 || tb.PoolAccept[0] != "ZZZ" {
		t.Fatalf("B182 (CD-03): pool accepts %v, want only ZZZ", tb.PoolAccept)
	}
	if len(tb.Asymmetric) == 0 {
		t.Fatal("B182 (CD-03): block and pool now agree (an upstream fix landed): update rft B182")
	}
}

// negative controls: each mutant is a one-edit copy of the source; the assertion it must break is named
func TestR28dRegistrationPoWChecksControls(t *testing.T) {
	src, err := os.ReadFile("blockchain.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	const outer = "tx_hash[0] != 0 && tx_hash[1] != 0 {"
	if strings.Count(s, outer) != 1 {
		t.Fatalf("the block check text %q occurs %d times", outer, strings.Count(s, outer))
	}
	// M1 (both trees): an HF4 rule that really is effective (byte2 must be zero from HF4) is height-bound
	m1 := strings.Replace(s, outer, "(tx_hash[0] != 0 && tx_hash[1] != 0) || (bl.Height >= uint64(globals.Config.MAJOR_HF4_HEIGHT) && tx_hash[2] != 0) {", 1)
	// M2 (both trees): the block check made equal to the pool check removes the asymmetry
	m2 := strings.Replace(s, outer, "!(tx_hash[0] == 0 && tx_hash[1] == 0 && tx_hash[2] == 0) {", 1)
	for _, m := range []struct {
		name, src string
		broken    func(r28dr_tables) bool
	}{
		{"M1 effective HF4 rule", m1, func(t r28dr_tables) bool { return t.HeightBound }},
		{"M2 block = pool rule", m2, func(t r28dr_tables) bool { return len(t.Asymmetric) == 0 }},
	} {
		tb, err := r28dr_registration_tables([]byte(m.src))
		if err != nil {
			t.Fatalf("%s: %s", m.name, err)
		}
		if !m.broken(tb) {
			t.Fatalf("%s: mutant NOT caught", m.name)
		}
	}
	// M3 (community-dev tree only): the nested HF4 return changed to accept: now the outcome is height-bound
	const inner = "if bl.Height >= uint64(globals.Config.MAJOR_HF4_HEIGHT) && tx_hash[2] != 0 {\n\t\t\t\t\t\treturn fmt.Errorf(\"Registration TX has not solved PoW\"), false"
	if strings.Contains(s, inner) {
		m3 := strings.Replace(s, inner, "if bl.Height >= uint64(globals.Config.MAJOR_HF4_HEIGHT) && tx_hash[2] != 0 {\n\t\t\t\t\t\treturn nil, true", 1)
		tb, err := r28dr_registration_tables([]byte(m3))
		if err != nil {
			t.Fatal(err)
		}
		if !tb.HeightBound {
			t.Fatal("M3 nested HF4 accept: mutant NOT caught")
		}
		t.Log("M3 caught (community-dev tree)")
	} else {
		t.Log("M3 skipped: no nested HF4 check in this tree")
	}
}
