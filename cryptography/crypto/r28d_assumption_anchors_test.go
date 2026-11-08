package crypto

// r28d (rft §7 B190; ported from the DEROFDN community-dev evaluation CD3, 2026-11-06): every row of the Bulletproofs
// assumption table (harness/model/evidence/r28d_assumption_table.json) carries code anchors, and every anchor still resolves: the file exists, the
// line exists, and the line contains the anchor's text. An upstream edit of an anchored line (a fix of C1 included)
// fails this test, so the table is re-read instead of silently going stale.
// Also pinned: the verdict vocabulary, the counts, and that the VIOLATED rows are exactly the C1 pair (u_x = H^o at
// proof_verify.go:430 and mu at :452), which is the one free row of the generator-binding census.
// Reads text only; never builds or verifies a proof.
//
//   R28D_ASSUMPTIONS=<file>   table to check (default ../../harness/model/evidence/r28d_assumption_table.json)
//
// A missing table FAILS the test (the evaluation copy skipped instead, r28d).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type r28dAnchor struct {
	Path   string `json:"path"`
	Line   int    `json:"line"`
	Expect string `json:"expect"`
	Role   string `json:"role"`
}

type r28dRow struct {
	ID         string             `json:"id"`
	Assumption string             `json:"assumption"`
	Paper      struct{ Page int } `json:"paper"`
	Anchors    []r28dAnchor       `json:"anchors"`
	Verdict    string             `json:"verdict"`
	C1         bool               `json:"c1"`
	Why        string             `json:"why"`
}

type r28dTable struct {
	Counts      map[string]int `json:"counts"`
	Assumptions []r28dRow      `json:"assumptions"`
}

const r28da_root = "../.."

func r28da_load_table(t *testing.T) r28dTable {
	t.Helper()
	p := os.Getenv("R28D_ASSUMPTIONS")
	if p == "" {
		p = filepath.Join(r28da_root, "harness/model/evidence/r28d_assumption_table.json")
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("no assumption table at %s (%s)", p, err)
	}
	var tb r28dTable
	if err := json.Unmarshal(raw, &tb); err != nil {
		t.Fatal(err)
	}
	return tb
}

// r28da_resolve returns "" when the anchor resolves, else why not; read gives a file's text (overridable for controls)
func r28da_resolve(a r28dAnchor, read func(string) ([]byte, error)) string {
	src, err := read(a.Path)
	if err != nil {
		return fmt.Sprintf("%s: %s", a.Path, err)
	}
	lines := strings.Split(string(src), "\n")
	if a.Line < 1 || a.Line > len(lines) {
		return fmt.Sprintf("%s:%d: no such line (%d lines)", a.Path, a.Line, len(lines))
	}
	if a.Expect == "" || !strings.Contains(lines[a.Line-1], a.Expect) {
		return fmt.Sprintf("%s:%d: line no longer contains %q: %q", a.Path, a.Line, a.Expect, strings.TrimSpace(lines[a.Line-1]))
	}
	return ""
}

func r28da_read_file(p string) ([]byte, error) { return os.ReadFile(filepath.Join(r28da_root, p)) }

func r28da_check(tb r28dTable, read func(string) ([]byte, error)) (bad []string) {
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
		if r.Paper.Page < 1 || r.Paper.Page > 46 {
			bad = append(bad, fmt.Sprintf("%s: paper page %d outside the 46-page IN-6", r.ID, r.Paper.Page))
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
			if !r.C1 {
				bad = append(bad, r.ID+": VIOLATED but not marked as part of C1 (a disagreement is a disclosure-track finding)")
			}
			c1 := false
			for _, a := range r.Anchors {
				if a.Path == "cryptography/crypto/proof_verify.go" && (a.Line == 430 || a.Line == 452) {
					c1 = true
				}
			}
			if !c1 {
				bad = append(bad, r.ID+": VIOLATED without the C1 anchor proof_verify.go:430 or :452")
			}
		}
	}
	for k, v := range tb.Counts {
		if counts[k] != v {
			bad = append(bad, fmt.Sprintf("counts[%s] = %d, rows say %d", k, v, counts[k]))
		}
	}
	if counts["VIOLATED"] != 2 {
		bad = append(bad, fmt.Sprintf("%d VIOLATED rows, the C1 pair is 2", counts["VIOLATED"]))
	}
	return
}

func TestR28dAssumptionAnchorsResolve(t *testing.T) {
	tb := r28da_load_table(t)
	if len(tb.Assumptions) == 0 {
		t.Fatal("empty assumption table")
	}
	if bad := r28da_check(tb, r28da_read_file); len(bad) > 0 {
		t.Fatalf("%d problems:\n%s", len(bad), strings.Join(bad, "\n"))
	}
	n := 0
	for _, r := range tb.Assumptions {
		n += len(r.Anchors)
	}
	t.Logf("%d assumptions, %d anchors resolved; counts %v", len(tb.Assumptions), n, tb.Counts)
}

// controls: each mutation must be CAUGHT
func TestR28dAssumptionAnchorsControls(t *testing.T) {
	tb := r28da_load_table(t)
	clone := func() r28dTable {
		var c r28dTable
		raw, _ := json.Marshal(tb)
		json.Unmarshal(raw, &c)
		return c
	}
	must := func(name string, c r28dTable, read func(string) ([]byte, error)) {
		t.Helper()
		if len(r28da_check(c, read)) == 0 {
			t.Fatalf("%s: NOT caught", name)
		}
	}
	// C1 every anchor shifted by one line: each one must stop resolving
	for i := range tb.Assumptions {
		for j := range tb.Assumptions[i].Anchors {
			c := clone()
			c.Assumptions[i].Anchors[j].Line++
			if r28da_resolve(c.Assumptions[i].Anchors[j], r28da_read_file) == "" {
				t.Fatalf("C1: %s anchor %d resolves one line lower too: its text is not specific", tb.Assumptions[i].ID, j)
			}
		}
	}
	// C2 the source changes under the anchor (the shape of an upstream C1 fix: u_x moved off H)
	edited := func(p string) ([]byte, error) {
		b, err := r28da_read_file(p)
		if p == "cryptography/crypto/proof_verify.go" {
			b = []byte(strings.Replace(string(b), "ScalarMult(gparams.H, o)", "ScalarMult(gparams.G, o)", 1))
		}
		return b, err
	}
	must("C2 source edit at proof_verify.go:430", tb, edited)
	// C3 a row without anchors
	c := clone()
	c.Assumptions[0].Anchors = nil
	must("C3 no anchor", c, r28da_read_file)
	// C4 a VIOLATED row that is not C1
	c = clone()
	for i := range c.Assumptions {
		if c.Assumptions[i].Verdict == "DISCHARGED" {
			c.Assumptions[i].Verdict = "VIOLATED"
			break
		}
	}
	must("C4 a third VIOLATED row", c, r28da_read_file)
	// C5 a count that disagrees with the rows
	c = clone()
	c.Counts["DISCHARGED"]++
	must("C5 counts", c, r28da_read_file)
	// C6 an unknown verdict word
	c = clone()
	c.Assumptions[0].Verdict = "HOLDS"
	must("C6 verdict vocabulary", c, r28da_read_file)
}
