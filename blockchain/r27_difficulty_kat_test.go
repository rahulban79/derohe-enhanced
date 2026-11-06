// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package blockchain

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
)

// Round 27 (dvm-blockchain): an offline known-answer test of the consensus difficulty rule (Get_Difficulty_At_Tips
// with a fake DiffProvider; no chain, no store). In-package coverage of difficulty.go was DiffBig 0.0% and the
// non-simulator path of Get_Difficulty_At_Tips 21.6% across every test package of the tree (R27 -coverpkg run):
// the simulator chain always returns 1. The vectors are the observatory's own rule (harness/intel/consensus_intel.py
// expected_difficulty, gate G26), so this ties G26's Python reimplementation to the Go code; the Python side is
// checked by harness/kat/test_difficulty_crossimpl_r27.py over the same file. Nothing in blockchain/ is changed.

type r27_diff_src struct {
	height     map[crypto.Hash]int64
	diff       map[crypto.Hash]*big.Int
	ts         map[crypto.Hash]uint64
	past       map[crypto.Hash][]crypto.Hash
	diff_reads int
}

func (s *r27_diff_src) Load_Block_Height(h crypto.Hash) int64 {
	if v, ok := s.height[h]; ok {
		return v
	}
	return -1
}
func (s *r27_diff_src) Load_Block_Difficulty(h crypto.Hash) *big.Int {
	s.diff_reads++
	return new(big.Int).Set(s.diff[h])
}
func (s *r27_diff_src) Load_Block_Timestamp(h crypto.Hash) uint64  { return s.ts[h] }
func (s *r27_diff_src) Get_Block_Past(h crypto.Hash) []crypto.Hash { return s.past[h] }

// a tip at height h with difficulty prev, solved solve_ms after its parent
func r27_tip(h int64, prev *big.Int, solve_ms uint64) (*r27_diff_src, crypto.Hash) {
	tip, parent := crypto.Hash{0x01}, crypto.Hash{0x02}
	const t0 = uint64(1700000000000)
	return &r27_diff_src{
		height: map[crypto.Hash]int64{tip: h, parent: h - 1},
		diff:   map[crypto.Hash]*big.Int{tip: prev, parent: prev},
		ts:     map[crypto.Hash]uint64{tip: t0 + solve_ms, parent: t0},
		past:   map[crypto.Hash][]crypto.Hash{tip: {parent}},
	}, tip
}

func r27_mainnet(t *testing.T) {
	old := globals.Config
	globals.Config = config.Mainnet
	t.Cleanup(func() { globals.Config = old })
	if !globals.IsMainnet() {
		t.Fatal("premise: globals.Config = config.Mainnet is not mainnet")
	}
}

func TestR27DifficultyCrossImpl(t *testing.T) {
	r27_mainnet(t)
	b, err := os.ReadFile("testdata/r27_difficulty_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules map[string]float64 `json:"rules"`
		Cases []struct {
			Prev    string `json:"prev"`
			SolveMs uint64 `json:"solve_ms"`
			Want    string `json:"want"`
		} `json:"cases"`
	}
	if err = json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	// the file was generated under these rules; they must still be the consensus values
	if doc.Rules["block_time"] != float64(config.BLOCK_TIME) || doc.Rules["min_difficulty"] != float64(config.Settings.MAINNET_MINIMUM_DIFFICULTY) ||
		doc.Rules["diff_m"] != 8 || doc.Rules["diff_clamp"] != 2 || doc.Rules["diff_e"] != E {
		t.Fatalf("vector rules %v differ from the tree", doc.Rules)
	}
	if len(doc.Cases) != 438 {
		t.Fatalf("%d vectors, want 438", len(doc.Cases))
	}
	h := globals.Config.MAJOR_HF2_HEIGHT + 100
	bad := 0
	for _, c := range doc.Cases {
		prev, ok1 := new(big.Int).SetString(c.Prev, 10)
		want, ok2 := new(big.Int).SetString(c.Want, 10)
		if !ok1 || !ok2 {
			t.Fatalf("unparsable vector %+v", c)
		}
		src, tip := r27_tip(h, prev, c.SolveMs)
		if got := Get_Difficulty_At_Tips(src, []crypto.Hash{tip}); got.Cmp(want) != 0 {
			bad++
			if bad <= 5 {
				t.Errorf("prev %s solve %d ms: consensus %s, observatory rule %s", c.Prev, c.SolveMs, got, want)
			}
		}
	}
	if bad > 0 {
		t.Fatalf("%d/%d vectors differ", bad, len(doc.Cases))
	}
}

// the branches that return before the rule runs, pinned
func TestR27DifficultyEarlyReturns(t *testing.T) {
	r27_mainnet(t)
	boot := new(big.Int).SetUint64(config.Settings.MAINNET_BOOTSTRAP_DIFFICULTY)
	prev := big.NewInt(5000000000)
	if got := Get_Difficulty_At_Tips(&r27_diff_src{}, nil); got.Cmp(boot) != 0 {
		t.Fatalf("no tips: %s, want bootstrap %s", got, boot)
	}
	hf2 := globals.Config.MAJOR_HF2_HEIGHT
	for _, c := range []struct {
		tip_height int64
		boot       bool
	}{{0, true}, {1, true}, {2, false}, {hf2 - 2, false}, {hf2 - 1, true}, {hf2, true}, {hf2 + 1, true}, {hf2 + 2, false}} {
		src, tip := r27_tip(c.tip_height, prev, 18000)
		got := Get_Difficulty_At_Tips(src, []crypto.Hash{tip})
		if c.boot && (got.Cmp(boot) != 0 || src.diff_reads != 0) {
			t.Errorf("tip height %d (next %d): %s, want bootstrap %s without reading the tip", c.tip_height, c.tip_height+1, got, boot)
		}
		if !c.boot && got.Cmp(prev) != 0 { // solve == block time: e^0 = 1, difficulty unchanged
			t.Errorf("tip height %d: %s, want %s (solve = block time)", c.tip_height, got, prev)
		}
	}
	// the highest of several tips sets the height; the FIRST tip's difficulty and solve time are used
	a, _ := r27_tip(hf2+50, prev, 18000)
	other := crypto.Hash{0x03}
	a.height[other] = hf2 + 90
	a.diff[other] = big.NewInt(1)
	if got := Get_Difficulty_At_Tips(a, []crypto.Hash{{0x01}, other}); got.Cmp(prev) != 0 {
		t.Fatalf("two tips: %s, want the first tip's %s", got, prev)
	}
	// an unknown tip is a panic (consensus never reaches it: tips are verified to exist first)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("unknown tip did not panic")
			}
		}()
		Get_Difficulty_At_Tips(&r27_diff_src{height: map[crypto.Hash]int64{}}, []crypto.Hash{{0x09}})
	}()
	// Diff (int64) and DiffBig agree where both are exact
	for _, s := range []int64{1, 9000, 18000, 27000, 36000} {
		if d, db := Diff(s, 18000, 8, 1234567891), DiffBig(s, 18000, 8, big.NewInt(1234567891)); db.Cmp(big.NewInt(d)) != 0 {
			t.Errorf("solve %d: Diff %d DiffBig %s", s, d, db)
		}
	}
}
