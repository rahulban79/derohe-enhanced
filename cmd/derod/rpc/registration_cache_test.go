// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package rpc

import "math/rand"
import "strconv"
import "testing"

// TestRegistrationCacheMatchesSearch: over random chains whose registration boundary moves (rewinds, re-registration
// at another height, deregistration, prune point moving), the cached locator must return exactly what upstream's
// search returns, every time, and must use far fewer probes once warm.
func TestRegistrationCacheMatchesSearch(t *testing.T) {
	rng := rand.New(rand.NewSource(19))
	c := &registration_cache{m: map[string]int64{}}
	var probes_cached, probes_search int
	boundaries := map[string]int64{}
	for i := 0; i < 20000; i++ {
		key := string(rune('a' + rng.Intn(4)))
		low := int64(10)
		if rng.Intn(100) == 0 {
			low = int64(rng.Intn(3)) * 10 // the prune point moves now and then: 0, 10 or 20
		}
		high := int64(900 + rng.Intn(100)) // the tip moves every call
		boundary, ok := boundaries[key]
		if !ok || rng.Intn(30) == 0 { // a rewind / reorg moves the boundary now and then
			boundary = low + int64(rng.Intn(int(high-low)+5)) // may lie beyond high: unregistered at the tip
			if rng.Intn(8) == 0 {
				boundary = low // registered from the prune point on
			}
			if rng.Intn(8) == 0 {
				boundary = 0 // registered before the prune point
			}
			boundaries[key] = boundary
		}
		reg := func(n *int) func(int64) bool {
			return func(x int64) bool { *n++; return x >= boundary }
		}
		want := search_registration(low, high, reg(&probes_search))
		got := locate_registration_cached(c, key, low, high, reg(&probes_cached))
		if got != want {
			t.Fatalf("iter %d key %q low %d high %d boundary %d: cached %d, search %d", i, key, low, high, boundary, got, want)
		}
	}
	t.Logf("probes: cached %d, search %d", probes_cached, probes_search)
	if probes_cached*3 >= probes_search {
		t.Fatalf("cache saved nothing: %d probes vs %d", probes_cached, probes_search)
	}
}

// TestRegistrationCacheHitCost: a warm hit with an unchanged chain costs 3 probes (tip, r, r-1), not ~23.
func TestRegistrationCacheHitCost(t *testing.T) {
	c := &registration_cache{m: map[string]int64{}}
	const low, high, boundary = int64(1), int64(7600000), int64(4123456)
	n := 0
	reg := func(x int64) bool { n++; return x >= boundary }
	if r := locate_registration_cached(c, "k", low, high, reg); r != boundary {
		t.Fatalf("cold: %d", r)
	}
	cold := n
	n = 0
	if r := locate_registration_cached(c, "k", low, high, reg); r != boundary {
		t.Fatalf("warm: %d", r)
	}
	if n != 3 {
		t.Fatalf("warm hit took %d probes (cold %d), want 3", n, cold)
	}
	t.Logf("cold %d probes, warm %d", cold, n)
}

// TestRegistrationCacheEarlierBoundary: after a reorg registers the address EARLIER than the cached point, the
// cached value still satisfies registered(r) — only the !registered(r-1) half of the proof rejects it.
func TestRegistrationCacheEarlierBoundary(t *testing.T) {
	c := &registration_cache{m: map[string]int64{}}
	boundary := int64(500)
	reg := func(x int64) bool { return x >= boundary }
	locate_registration_cached(c, "k", 1, 1000, reg)
	boundary = 300
	if r := locate_registration_cached(c, "k", 1, 1000, reg); r != 300 {
		t.Fatalf("stale boundary returned: %d", r)
	}
}

func TestRegistrationCacheBounded(t *testing.T) {
	c := &registration_cache{m: map[string]int64{}}
	for i := 0; i < registration_cache_max+10; i++ {
		c.put(strconv.Itoa(i), 1)
	}
	if len(c.m) > registration_cache_max {
		t.Fatalf("cache grew to %d", len(c.m))
	}
}

// STOR-1 (verifier note): an address no longer registered at the tip is dropped from the cache, not kept
func TestRegistrationCacheDropsUnregistered(t *testing.T) {
	c := &registration_cache{m: map[string]int64{}}
	boundary := int64(500)
	reg := func(x int64) bool { return x >= boundary }
	if r := locate_registration_cached(c, "k", 10, 900, reg); r != 500 {
		t.Fatalf("got %d", r)
	}
	boundary = 950 // rewound past the registration: unregistered at the tip
	if r := locate_registration_cached(c, "k", 10, 900, reg); r != -1 {
		t.Fatalf("got %d", r)
	}
	if _, ok := c.get("k"); ok {
		t.Fatal("an address unregistered at the tip stayed in the cache")
	}
}
