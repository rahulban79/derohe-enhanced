// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package p2p

// Round 23b (syncp2p): the "too far into the future" skip in process_object_response_want read chain.Get_Height()
// once per synced block. Get_Height is not a field read: it is storetopofs.Count (os.Stat + pread) plus
// Load_TOP_HEIGHT (more preads). CPU profile of a loopback shadow catch-up of 1,000 blocks (r23b, 30 s,
// the r23b syncp2p loopback catch-up CPU profile): process_object_response_want -> Get_Height = 0.67 s of 28.57 s sampled,
// 2.35% of all CPU and 56% of the p2p layer's own 4.17%, all of it on the single serial sync goroutine.
//
// sync_height_gate keeps the decision and drops most of the reads: it remembers the last height it loaded and only
// reloads when a block looks too far ahead against it. While the chain height only grows during one response (the
// normal case: every added block raises it), a remembered height is never above the real one, so "within the window
// of the remembered height" implies "within the window of the real height", and every "too far" verdict is made on
// a freshly loaded height: the decisions are exactly the per-block ones. If the height fell meanwhile (a reorg/pop),
// a block can be offered to Add_Complete_Block instead of skipped; the skip is a resource heuristic, never a validity
// rule, and the chain judges that block exactly as it judges every other one. Node-local, no consensus package.
type sync_height_gate struct {
	load   func() int64
	h      int64
	loaded bool
}

const SYNC_AHEAD_BLOCKS = 4 // a synced block more than this above our height is skipped (upstream's literal)

func new_sync_height_gate(load func() int64) *sync_height_gate {
	return &sync_height_gate{load: load}
}

// too_far reports whether a block at height is more than SYNC_AHEAD_BLOCKS above our chain height.
func (g *sync_height_gate) too_far(height int64) bool {
	if !g.loaded {
		g.h, g.loaded = g.load(), true
	}
	if height <= g.h+SYNC_AHEAD_BLOCKS {
		return false
	}
	g.h = g.load()
	return height > g.h+SYNC_AHEAD_BLOCKS
}
