// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package p2p

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/transaction"
)

// r23b_entry puts a synthetic table entry for a header-only tx (no real table txid is reproducible: TXID preimage)
// and returns the tx, the entry and a cleanup.
func r23b_entry(t *testing.T, txheight, minedheight uint64, txparity bool) (*transaction.Transaction, *blockchain.HF3_Tx_Data, func()) {
	t.Helper()
	tx := &transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, TransactionType: transaction.NORMAL, Height: txheight}}
	key := tx.GetHash().String()
	if _, clash := blockchain.HF3_Affected_Txs[key]; clash {
		t.Fatalf("synthetic txid %s collides with a real table entry", key)
	}
	e := &blockchain.HF3_Tx_Data{Height: minedheight, Tx_Parity: txparity}
	blockchain.HF3_Affected_Txs[key] = e
	return tx, e, func() { delete(blockchain.HF3_Affected_Txs, key) }
}

// The sync path's expression, applied by every path: in the entry's own block (height == entry.Height) Parity is
// !Tx_Parity, in a later block it is Tx_Parity; verify runs once per table tx; nothing changes at/after HF3.
func TestR23bHF3ParityFormula(t *testing.T) {
	hf3 := uint64(globals.Config.MAJOR_HF3_HEIGHT)
	if hf3 < 1000 {
		t.Fatalf("MAJOR_HF3_HEIGHT %d: test expects mainnet config", hf3)
	}
	for _, txp := range []bool{false, true} {
		tx, e, done := r23b_entry(t, 7467492+boolu(txp), 7467498, txp)
		other := &transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, TransactionType: transaction.NORMAL, Height: 9}}
		verified := 0
		verify := func(*transaction.Transaction) { verified++ }

		e.Parity = txp // the stale value a previous block left
		if n := apply_hf3_parity(7467498, []*transaction.Transaction{other, tx}, verify); n != 1 || verified != 1 {
			t.Fatalf("Tx_Parity %v: applied %d verified %d, want 1 and 1", txp, n, verified)
		}
		if e.Parity != !txp {
			t.Fatalf("Tx_Parity %v: own block Parity %v, want %v", txp, e.Parity, !txp)
		}
		apply_hf3_parity(7467499, []*transaction.Transaction{tx}, verify)
		if e.Parity != txp {
			t.Fatalf("Tx_Parity %v: later block Parity %v, want %v", txp, e.Parity, txp)
		}
		e.Parity = !txp
		if n := apply_hf3_parity(hf3, []*transaction.Transaction{tx}, verify); n != 0 || e.Parity != !txp || hf3_carries(hf3, []*transaction.Transaction{tx}) {
			t.Fatalf("Tx_Parity %v: a block at HF3 changed the entry (n %d)", txp, n)
		}
		if !hf3_carries(7467498, []*transaction.Transaction{nil, other, tx}) || hf3_carries(7467498, []*transaction.Transaction{other}) {
			t.Fatal("hf3_carries does not find exactly the table tx")
		}
		done()
	}
}

func boolu(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

// hf3_add prepares the entry before add runs (the chunk/compact/import paths used to execute with the stale value),
// and passes blocks without a table tx straight through.
func TestR23bHF3AddPreparesBeforeExecute(t *testing.T) {
	tx, e, done := r23b_entry(t, 7467492, 7467498, false)
	defer done()
	e.Parity = false // what every non-sync path executed with before r23b
	var seen []bool
	add := func(cbl *block.Complete_Block) (error, bool) { seen = append(seen, e.Parity); return nil, true }
	hf3_add(&block.Complete_Block{Bl: &block.Block{Height: 7467498}, Txs: []*transaction.Transaction{tx}}, nil, add)
	if len(seen) != 1 || seen[0] != true {
		t.Fatalf("add executed with Parity %v, want true (own block, Tx_Parity false)", seen)
	}
	plain := &transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, TransactionType: transaction.NORMAL, Height: 5}}
	e.Parity = false
	hf3_add(&block.Complete_Block{Bl: &block.Block{Height: 7467498}, Txs: []*transaction.Transaction{plain}}, nil, add)
	hf3_add(nil, nil, add)
	if len(seen) != 3 || e.Parity != false {
		t.Fatalf("blocks without a table tx: seen %v Parity %v", seen, e.Parity)
	}
}

// Two connections executing two blocks that carry the same txid at different heights: each execution must see the
// value prepared for its own block (hf3_exec_mu makes set+execute one step).
func TestR23bHF3AddIsAtomic(t *testing.T) {
	tx, e, done := r23b_entry(t, 7467492, 7467498, true)
	defer done()
	var wg sync.WaitGroup
	var mu sync.Mutex
	bad := 0
	for g := 0; g < 8; g++ {
		h := uint64(7467498 + g%2) // own block wants false, the later one true
		want := (h > e.Height) == e.Tx_Parity
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				hf3_add(&block.Complete_Block{Bl: &block.Block{Height: h}, Txs: []*transaction.Transaction{tx}}, nil, func(*block.Complete_Block) (error, bool) {
					time.Sleep(20 * time.Microsecond) // execution takes time; another block may be prepared meanwhile
					if e.Parity != want {
						mu.Lock()
						bad++
						mu.Unlock()
					}
					return nil, true
				})
			}
		}()
	}
	wg.Wait()
	if bad != 0 {
		t.Fatalf("%d executions saw the Parity prepared for another block", bad)
	}
}

// Census: outside package blockchain, the only reference to Add_Complete_Block is the one in Add_Complete_Block_HF3,
// so a new path that offers a block to the chain cannot skip the HF3 table step.
func TestR23bAddCompleteBlockCensus(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatal(err)
	}
	var bad []string
	checked := 0
	err = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if fi.IsDir() {
			if rel == "vendor" || rel == "blockchain" || strings.HasPrefix(rel, ".") && rel != "." {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil || !strings.Contains(string(src), "Add_Complete_Block") {
			return nil
		}
		fs := token.NewFileSet()
		f, err := parser.ParseFile(fs, p, src, 0)
		if err != nil {
			return nil // not this test's business (build tags, generated)
		}
		checked++
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if se, ok := n.(*ast.SelectorExpr); ok && se.Sel.Name == "Add_Complete_Block" {
					if !(rel == filepath.Join("p2p", "hf3_parity.go") && fd.Name.Name == "Add_Complete_Block_HF3") {
						bad = append(bad, fmt.Sprintf("%s:%d in %s", rel, fs.Position(se.Pos()).Line, fd.Name.Name))
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 4 {
		t.Fatalf("census parsed only %d files mentioning Add_Complete_Block", checked)
	}
	if len(bad) > 0 {
		t.Fatalf("Add_Complete_Block referenced outside Add_Complete_Block_HF3 (HF3 table step skipped): %v", bad)
	}
}
