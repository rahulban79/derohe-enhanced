package crypto

// r29 (rft §7 B190): the A15/A18 re-grade against the Zether (IN-7) and many-out-of-many (IN-8) papers is pinned the
// same way as the r28d table: every row of harness/model/evidence/r29_assumption_table.json has code anchors that
// still resolve (file, line, text), a paper citation inside that paper's page range, a known verdict word, counts
// that agree with the rows, and every VIOLATED row is part of C1 (marked c1 and anchored only at proof_verify.go:430
// or :452 among its VIOLATED-bearing lines). Reads text only; never builds or verifies a proof.
//
//   R29_ASSUMPTIONS=<file>   table to check (default ../../harness/model/evidence/r29_assumption_table.json)

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type r29Row struct {
	ID    string `json:"id"`
	Paper struct {
		Doc  string `json:"doc"`
		Page int    `json:"page"`
	} `json:"paper"`
	Anchors []r28dAnchor `json:"anchors"`
	Verdict string       `json:"verdict"`
	C1      bool         `json:"c1"`
}

type r29Table struct {
	Counts      map[string]int    `json:"counts"`
	Papers      map[string]string `json:"papers"`
	Assumptions []r29Row          `json:"assumptions"`
}

// page counts of the held inputs (harness/external/r28d_inputs_manifest.json, r29_inputs_manifest.json)
var r29_pages = map[string]int{"IN-6": 46, "IN-7": 43, "IN-8": 49}

func r29a_load(t *testing.T) r29Table {
	t.Helper()
	p := os.Getenv("R29_ASSUMPTIONS")
	if p == "" {
		p = filepath.Join(r28da_root, "harness/model/evidence/r29_assumption_table.json")
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("no assumption table at %s (%s)", p, err)
	}
	var tb r29Table
	if err := json.Unmarshal(raw, &tb); err != nil {
		t.Fatal(err)
	}
	return tb
}

func r29a_check(tb r29Table, read func(string) ([]byte, error)) (bad []string) {
	counts := map[string]int{}
	ids := map[string]bool{}
	for _, r := range tb.Assumptions {
		if ids[r.ID] {
			bad = append(bad, "duplicate id "+r.ID)
		}
		ids[r.ID] = true
		switch r.Verdict {
		case "DISCHARGED", "VIOLATED", "UNCLEAR":
		default:
			bad = append(bad, fmt.Sprintf("%s: verdict %q", r.ID, r.Verdict))
		}
		counts[r.Verdict]++
		n, ok := r29_pages[r.Paper.Doc]
		if !ok || tb.Papers[r.Paper.Doc] == "" {
			bad = append(bad, fmt.Sprintf("%s: paper %q is not a held input", r.ID, r.Paper.Doc))
		} else if r.Paper.Page < 1 || r.Paper.Page > n {
			bad = append(bad, fmt.Sprintf("%s: page %d outside the %d-page %s", r.ID, r.Paper.Page, n, r.Paper.Doc))
		}
		if len(r.Anchors) == 0 {
			bad = append(bad, r.ID+": no code anchor")
		}
		for _, a := range r.Anchors {
			if why := r28da_resolve(a, read); why != "" {
				bad = append(bad, r.ID+": "+why)
			}
		}
		if r.Verdict == "VIOLATED" {
			c1 := false
			for _, a := range r.Anchors {
				if a.Path == "cryptography/crypto/proof_verify.go" && (a.Line == 430 || a.Line == 452) {
					c1 = true
				}
			}
			if !r.C1 || !c1 {
				bad = append(bad, r.ID+": VIOLATED but not the C1 pair (proof_verify.go:430 / :452): a disclosure-track finding")
			}
		}
	}
	for k, v := range tb.Counts {
		if counts[k] != v {
			bad = append(bad, fmt.Sprintf("counts[%s] = %d, rows say %d", k, v, counts[k]))
		}
	}
	if len(tb.Counts) != len(counts) {
		bad = append(bad, fmt.Sprintf("counts name %d verdicts, rows use %d", len(tb.Counts), len(counts)))
	}
	return
}

func TestR29AssumptionAnchorsResolve(t *testing.T) {
	tb := r29a_load(t)
	if len(tb.Assumptions) == 0 {
		t.Fatal("empty assumption table")
	}
	if bad := r29a_check(tb, r28da_read_file); len(bad) > 0 {
		t.Fatalf("%d problems:\n%s", len(bad), strings.Join(bad, "\n"))
	}
	want := map[string]string{"A15": "UNCLEAR", "A18": "DISCHARGED", "A19": "DISCHARGED", "A20": "VIOLATED", "A21": "UNCLEAR"}
	for _, r := range tb.Assumptions {
		if w, ok := want[r.ID]; ok && r.Verdict != w {
			t.Fatalf("%s: verdict %s, the r29 re-grade says %s", r.ID, r.Verdict, w)
		}
		delete(want, r.ID)
	}
	if len(want) > 0 {
		t.Fatalf("rows missing from the r29 table: %v", want)
	}
	n := 0
	for _, r := range tb.Assumptions {
		n += len(r.Anchors)
	}
	t.Logf("%d assumptions, %d anchors resolved; counts %v", len(tb.Assumptions), n, tb.Counts)
}

// controls: each mutation must be CAUGHT
func TestR29AssumptionAnchorsControls(t *testing.T) {
	tb := r29a_load(t)
	clone := func() r29Table {
		var c r29Table
		raw, _ := json.Marshal(tb)
		json.Unmarshal(raw, &c)
		return c
	}
	must := func(name string, c r29Table, read func(string) ([]byte, error)) {
		t.Helper()
		if len(r29a_check(c, read)) == 0 {
			t.Fatalf("%s: NOT caught", name)
		}
	}
	idx := func(c r29Table, id string) int {
		for i := range c.Assumptions {
			if c.Assumptions[i].ID == id {
				return i
			}
		}
		t.Fatalf("no row %s", id)
		return -1
	}
	// R1 every anchor of the r29 rows shifted by one line must stop resolving
	for _, id := range []string{"A15", "A18", "A19", "A20", "A21"} {
		i := idx(tb, id)
		for j := range tb.Assumptions[i].Anchors {
			c := clone()
			c.Assumptions[i].Anchors[j].Line++
			if r28da_resolve(c.Assumptions[i].Anchors[j], r28da_read_file) == "" {
				t.Fatalf("R1: %s anchor %d resolves one line lower too", id, j)
			}
		}
	}
	// R2 the source changes under an A15 anchor (u hashed some other way)
	edited := func(p string) ([]byte, error) {
		b, err := r28da_read_file(p)
		if p == "cryptography/crypto/proof_verify.go" {
			b = []byte(strings.Replace(string(b), "ScalarMult(proof.u, proof_c_neg)", "ScalarMult(proof.u, proof.c)", 1))
		}
		return b, err
	}
	must("R2 source edit at proof_verify.go:400", tb, edited)
	// R3 a VIOLATED row off the C1 lines (A15 graded VIOLATED with its own anchors)
	c := clone()
	i := idx(c, "A15")
	c.Assumptions[i].Verdict = "VIOLATED"
	c.Assumptions[i].C1 = true
	c.Counts["VIOLATED"]++
	c.Counts["UNCLEAR"]--
	must("R3 VIOLATED without a C1 anchor", c, r28da_read_file)
	// R4 a citation to a paper that is not held
	c = clone()
	c.Assumptions[idx(c, "A18")].Paper.Doc = "IN-9"
	must("R4 unknown paper", c, r28da_read_file)
	// R5 a page outside the paper
	c = clone()
	c.Assumptions[idx(c, "A20")].Paper.Page = 50
	must("R5 page outside IN-8", c, r28da_read_file)
	// R6 counts disagree with the rows
	c = clone()
	c.Counts["DISCHARGED"]++
	must("R6 counts", c, r28da_read_file)
	// R7 a VIOLATED row not marked c1
	c = clone()
	c.Assumptions[idx(c, "A20")].C1 = false
	must("R7 VIOLATED not marked c1", c, r28da_read_file)
}
