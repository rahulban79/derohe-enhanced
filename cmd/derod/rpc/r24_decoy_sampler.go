package rpc

// r24 (cryptoinfl CI24-3): depth-corrected decoy sampling for DERO.GetRandomAddress.
//
// Wallets take their ring decoys from GetRandomAddress, which drew them with graviton Tree.Random: a fair coin at
// every inner node that has two children (vendor/github.com/deroproject/graviton/extra.go). A leaf with b branching
// ancestors is therefore drawn with probability 2^-b, not 1/n. On the mainnet balance tree (APFS copy, topo
// 7,845,407, 2.14M leaves; evidence/live_tree_branching.txt) b runs from 18 to 25: the 1.9 % of accounts at b=19 got
// 7.7 % of the draws and the 11.9 % at b>=23 got 2.8 %. The tree is public, so anyone can compute b for every ring
// member; with the real sender a uniformly chosen account, the member with the largest b is the real one in 17.4 %
// of 16-member rings instead of 6.25 % (evidence/ring_advantage.txt, ESTIMATE from the measured distribution).
//
// The fix is rejection sampling, node-local and invisible to consensus (any registered key is a valid ring member):
// a drawn leaf is kept with probability min(1, 2^(b-B)), so every leaf with b <= B is equally likely and only the
// deepest leaves (b > B) stay under-drawn. B = round(log2 n) + 2, n estimated as the mean of 2^b over a pilot of
// raw draws (E[2^b] = n exactly under Random's own distribution), cached per tree for R24_DECOY_B_TTL: a B that moved
// from call to call (an early version took the median of 16 draws) under-drew the class b = B by ~11 %. On mainnet
// B = 23 keeps 25 % of the draws and leaves the MAP success at 7.0 % for 16-member rings. b is the number of
// non-zero sibling hashes in the leaf's graviton proof (set bits of the trace bitmap in Proof.Marshal). The number of
// draws per call is bounded (R24_DECOY_DRAW_BUDGET), so a remote caller cannot make one call cost more than that.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"math/bits"
	"sync"
	"time"

	"github.com/deroproject/graviton"
)

const (
	R24_DECOY_WANT        = 100 // accepted draws per call: what the old loop drew (100 Random calls)
	R24_DECOY_DRAW_BUDGET = 800 // hard cap on Random+proof pairs per call, pilot included (mainnet needs ~400)
	R24_DECOY_PILOT       = 256 // raw draws that estimate n for B (once per tree per TTL; not returned)
	R24_DECOY_SLACK       = 2   // B = round(log2 n) + slack
	R24_DECOY_B_TTL       = 10 * time.Minute
	R24_DECOY_B_TREES     = 1024 // cached trees (one per SCID asked for); the cache is reset when full
)

// r24_decoy_tree is what the sampler needs from a graviton tree (a *graviton.Tree satisfies it)
type r24_decoy_tree interface {
	Random() (k, v []byte, err error)
	GenerateProof(key []byte) (*graviton.Proof, error)
}

// r24_branching returns the number of branching ancestors of key: the set bits of the proof's trace bitmap.
// Proof.Marshal layout: version byte, type byte, uvarint trace length, 32-byte bitmap (bit i set = sibling i non-zero).
func r24_branching(t r24_decoy_tree, key []byte) (int, error) {
	p, err := t.GenerateProof(key)
	if err != nil {
		return 0, err
	}
	m := p.Marshal()
	if len(m) < 3 {
		return 0, errors.New("short proof")
	}
	_, n := binary.Uvarint(m[2:])
	if n <= 0 || len(m) < 2+n+graviton.HASHSIZE {
		return 0, errors.New("bad proof")
	}
	c := 0
	for _, x := range m[2+n : 2+n+graviton.HASHSIZE] {
		c += bits.OnesCount8(x)
	}
	return c, nil
}

// r24_coin returns true with probability 2^-shift (shift <= 0: always), from crypto/rand
func r24_coin(shift int) bool {
	if shift <= 0 {
		return true
	}
	if shift >= 63 {
		return false
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return false
	}
	return binary.LittleEndian.Uint64(b[:])&(1<<uint(shift)-1) == 0
}

type r24_draw struct {
	k, v []byte
	b    int
}

type r24_decoy_stats struct {
	Draws, Pilot, Accepted, B int
	Cached                    bool
}

type r24_decoy_b_entry struct {
	b  int
	at time.Time
}

// r24_decoy_bcache holds B per tree name
type r24_decoy_bcache struct {
	sync.Mutex
	m   map[string]r24_decoy_b_entry
	now func() time.Time
}

var r24_decoy_b = &r24_decoy_bcache{now: time.Now}

func (c *r24_decoy_bcache) get(name string) (int, bool) {
	c.Lock()
	defer c.Unlock()
	e, ok := c.m[name]
	if !ok || c.now().Sub(e.at) > R24_DECOY_B_TTL {
		return 0, false
	}
	return e.b, true
}

func (c *r24_decoy_bcache) put(name string, b int) {
	c.Lock()
	defer c.Unlock()
	if c.m == nil || len(c.m) >= R24_DECOY_B_TREES {
		c.m = map[string]r24_decoy_b_entry{}
	}
	c.m[name] = r24_decoy_b_entry{b: b, at: c.now()}
}

// r24_decoy_B_from returns round(log2(mean 2^b)) + slack
func r24_decoy_B_from(bs []int) int {
	if len(bs) == 0 {
		return -1
	}
	var s float64
	for _, b := range bs {
		s += math.Exp2(float64(b))
	}
	return int(math.Round(math.Log2(s/float64(len(bs))))) + R24_DECOY_SLACK
}

// r24_decoy_draws draws leaves of t until want are accepted or the budget is spent. B comes from the cache, else from
// a pilot of raw draws charged to the same budget. Draws that fail (empty tree, store error) count against the budget.
func r24_decoy_draws(t r24_decoy_tree, name string, cache *r24_decoy_bcache, want, budget int, coin func(int) bool) (out []r24_draw, st r24_decoy_stats) {
	next := func() (r24_draw, bool) {
		st.Draws++
		k, v, err := t.Random()
		if err != nil {
			return r24_draw{}, false
		}
		b, err := r24_branching(t, k)
		if err != nil {
			return r24_draw{}, false
		}
		return r24_draw{k: k, v: v, b: b}, true
	}
	B, ok := cache.get(name)
	st.Cached = ok
	if !ok {
		var bs []int
		var pilot []r24_draw
		for st.Draws < budget && len(bs) < R24_DECOY_PILOT {
			if d, good := next(); good {
				bs = append(bs, d.b)
				pilot = append(pilot, d)
			}
		}
		st.Pilot = st.Draws
		if len(bs) < R24_DECOY_PILOT { // the budget ended first (a failing store): return what was drawn, uncorrected
			for _, d := range pilot {
				if len(out) < want {
					out = append(out, d)
				}
			}
			st.Accepted, st.B = len(out), -1
			return
		}
		B = r24_decoy_B_from(bs)
		cache.put(name, B)
	}
	for st.Draws < budget && len(out) < want {
		if d, good := next(); good && coin(B-d.b) {
			out = append(out, d)
		}
	}
	st.Accepted, st.B = len(out), B
	return
}
