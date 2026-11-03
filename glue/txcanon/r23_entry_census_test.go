// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package txcanon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Round 23 entry-path census. The relay policy only protects the mempool if EVERY way into it runs Check first.
// Every mempool/regpool admission goes through (*Blockchain).Add_TX_To_Pool (blockchain.go; Mempool_Add_TX and
// Regpool_Add_TX have no other caller). This test parses the whole tree and requires that each non-test reference to
// Add_TX_To_Pool outside its own definition is an argument of txcanon.Admit or of p2p's relay_admit, and that
// relay_admit itself calls txcanon.Admit. A new RPC/P2P entry point that calls Add_TX_To_Pool directly fails here.
// cmd/simulator is exempt: it only admits registration txs the simulator built itself.
var censusExempt = []string{"cmd/simulator/", "blockchain/"}

func repoRoot(t *testing.T) string {
	d, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(d, "go.mod")); err != nil {
		t.Fatalf("repo root not found at %s", d)
	}
	return d
}

func isSel(e ast.Expr, name string) bool {
	s, ok := e.(*ast.SelectorExpr)
	return ok && s.Sel.Name == name
}

func calleeName(c *ast.CallExpr) string {
	switch f := c.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if x, ok := f.X.(*ast.Ident); ok {
			return x.Name + "." + f.Sel.Name
		}
		return f.Sel.Name
	}
	return ""
}

type censusHit struct {
	file    string
	line    int
	wrapped bool
}

// census returns every reference to .Add_TX_To_Pool and whether it is wrapped, plus whether relay_admit calls
// txcanon.Admit.
func census(t *testing.T, root string) (hits []censusHit, relayAdmitWraps bool) {
	fset := token.NewFileSet()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if info.IsDir() {
			if rel == "vendor" || rel == "harness" || strings.HasPrefix(rel, ".") && rel != "." {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		for _, ex := range censusExempt {
			if strings.HasPrefix(rel, ex) {
				return nil
			}
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil // not our concern (build-tagged scratch etc.)
		}
		wrapped := map[ast.Expr]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			if fd, ok := n.(*ast.FuncDecl); ok && fd.Name.Name == "relay_admit" && fd.Body != nil {
				ast.Inspect(fd.Body, func(m ast.Node) bool {
					if c, ok := m.(*ast.CallExpr); ok && calleeName(c) == "txcanon.Admit" {
						relayAdmitWraps = true
					}
					return true
				})
			}
			if c, ok := n.(*ast.CallExpr); ok {
				if name := calleeName(c); name == "txcanon.Admit" || name == "relay_admit" {
					for _, a := range c.Args {
						wrapped[a] = true
					}
				}
			}
			return true
		})
		ast.Inspect(f, func(n ast.Node) bool {
			if e, ok := n.(ast.Expr); ok && isSel(e, "Add_TX_To_Pool") {
				hits = append(hits, censusHit{rel, fset.Position(e.Pos()).Line, wrapped[e]})
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestR23EveryMempoolEntryRunsTxcanon(t *testing.T) {
	hits, wraps := census(t, repoRoot(t))
	if !wraps {
		t.Fatal("p2p relay_admit no longer calls txcanon.Admit")
	}
	seen := map[string]bool{}
	for _, h := range hits {
		seen[h.file] = true
		if !h.wrapped {
			t.Errorf("%s:%d references Add_TX_To_Pool without txcanon.Admit/relay_admit", h.file, h.line)
		}
	}
	// the known entry points must still be found, or the census itself is broken
	for _, f := range []string{"cmd/derod/rpc/rpc_dero_sendrawtransaction.go", "p2p/chain_sync.go"} {
		if !seen[f] {
			t.Errorf("census did not find the known entry point %s (found %v)", f, seen)
		}
	}
}
