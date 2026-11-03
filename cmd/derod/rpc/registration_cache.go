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

// r19 storage: a verify-on-hit cache for the point of registration.
//
// GetEncryptedBalance (every wallet sync, once per asset) located the registration topoheight with a binary
// search over [prune point, tip]: about log2(7.6M) = 23 probes, each one a Topo_store read, a graviton
// LoadSnapshot, a GetTree and a key lookup. The answer for an address almost never changes, so remember it and,
// on a hit, prove it again against the CURRENT chain with at most two probes instead of trusting it:
//
//   r == low:  registered(low)                      -> the search would have returned low at its early exit
//   r >  low:  registered(r) && !registered(r - 1)  -> r is the boundary of a monotone predicate, which is the
//                                                      only value the binary search can return
//
// Anything else (a rewind moved the boundary, the prune point moved past r, the tip fell below r) falls through
// to the original search, whose answer replaces the entry. Nothing is ever returned without that proof, so a
// stale entry costs two probes and never a wrong answer. The cache only feeds an RPC reply; consensus never
// reads it.

import "math"
import "sync"

const registration_cache_max = 1 << 16 // ~6-7 MB at worst (33-byte key + int64 + map overhead); cleared wholesale when full

type registration_cache struct {
	sync.Mutex
	m map[string]int64
}

var reg_cache = registration_cache{m: map[string]int64{}}

func (c *registration_cache) get(key string) (int64, bool) {
	c.Lock()
	defer c.Unlock()
	r, ok := c.m[key]
	return r, ok
}

func (c *registration_cache) put(key string, r int64) {
	c.Lock()
	defer c.Unlock()
	if len(c.m) >= registration_cache_max {
		c.m = map[string]int64{}
	}
	c.m[key] = r
}

func (c *registration_cache) drop(key string) {
	c.Lock()
	defer c.Unlock()
	delete(c.m, key)
}

// search_registration is upstream's search, unchanged: -1 if not registered at high, low if registered at low,
// otherwise the lowest topoheight in (low, high] at which registered() holds.
func search_registration(low, high int64, registered func(int64) bool) int64 {
	if !registered(high) {
		return -1
	}
	if registered(low) {
		return low
	}
	lowest := int64(math.MaxInt64)
	for low <= high {
		median := (low + high) / 2
		if registered(median) {
			if lowest > median {
				lowest = median
			}
			high = median - 1
		} else {
			low = median + 1
		}
	}
	return lowest
}

// locate_registration_cached returns exactly what search_registration(low, high, registered) returns, using the
// cached boundary for key when the current chain still proves it.
func locate_registration_cached(c *registration_cache, key string, low, high int64, registered func(int64) bool) int64 {
	if !registered(high) { // same first probe as the search: unregistered (or rewound past registration)
		c.drop(key)
		return -1
	}
	if r, ok := c.get(key); ok && r >= low && r <= high {
		if r == low {
			if registered(low) {
				return low
			}
		} else if registered(r) && !registered(r-1) {
			return r
		}
	}
	r := search_registration(low, high, registered)
	if r >= 0 && r != math.MaxInt64 {
		c.put(key, r)
	}
	return r
}
