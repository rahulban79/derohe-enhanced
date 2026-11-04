// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package rpc

// DERO.GetConsensusStats (r25, consensus dimension; dero-rft §0.7.1, §7 B55-B60): the counters the chain
// observatory (harness/intel/consensus_intel.py) used to reconstruct from DEBUG log lines, in one read-only answer:
// miniblock refusals and block rejections by reason (CO24-C1, CO24-C3), the settled alt blocks behind GetInfo
// alt_blocks_count (CO24-C4), first-seen times of requested blocks and miniblocks (CO24-C5) and the reorg monitor's
// lifetime totals (CO24-C6). Peers are never named here (the log lines carry their self-chosen peer_id).
//
// Cost: a map copy per counter, one settle pass over the unsettled alt entries (a topo-index read each, ~1 per block),
// and one map lookup per requested hash (at most CONSENSUS_STATS_MAX_HASHES of each kind).

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/p2p"
)

const CONSENSUS_STATS_MAX_HASHES = 100 // r25: per kind and call

type GetConsensusStats_Params struct {
	BlockHashes     []string `json:"block_hashes,omitempty"`
	MiniBlockHashes []string `json:"miniblock_hashes,omitempty"`
}

type FirstSeen_Print struct {
	Hash        string `json:"hash"`
	Kind        string `json:"kind"` // block | miniblock
	Known       bool   `json:"known"`
	FirstSeenMs int64  `json:"first_seen_ms"`
	Local       bool   `json:"local"`
	Height      int64  `json:"height"`
}

type GetConsensusStats_Result struct {
	Version        string                 `json:"version"`
	UptimeSeconds  int64                  `json:"uptime_seconds"`
	Height         int64                  `json:"height"`
	StableLimit    int64                  `json:"stable_limit"`
	Counters       p2p.Consensus_Counters `json:"counters"`
	AltBlocks      p2p.Alt_Stats          `json:"alt_blocks"`
	Reorg          Reorg_Stats            `json:"reorg"`
	FirstSeen      []FirstSeen_Print      `json:"first_seen"`
	BlocksSeen     int                    `json:"blocks_seen_tracked"`
	MiniBlocksSeen int                    `json:"miniblocks_seen_tracked"`
	Status         string                 `json:"status"`
}

func parse_hash_list(list []string, kind string) ([]crypto.Hash, error) {
	if len(list) > CONSENSUS_STATS_MAX_HASHES {
		return nil, fmt.Errorf("%d %s hashes requested, the limit is %d per call", len(list), kind, CONSENSUS_STATS_MAX_HASHES)
	}
	out := make([]crypto.Hash, 0, len(list))
	for _, s := range list {
		raw, err := hex.DecodeString(s)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("%s hash %q must be 64 hex characters", kind, s)
		}
		var h crypto.Hash
		copy(h[:], raw)
		out = append(out, h)
	}
	return out, nil
}

func first_seen_print(h crypto.Hash, kind string, lookup func(crypto.Hash) (p2p.FirstSeen, bool)) FirstSeen_Print {
	r := FirstSeen_Print{Hash: h.String(), Kind: kind, Height: -1}
	if fs, ok := lookup(h); ok {
		r.Known, r.FirstSeenMs, r.Local, r.Height = true, fs.Ms, fs.Local, fs.Height
	}
	return r
}

func GetConsensusStats(ctx context.Context, p GetConsensusStats_Params) (result GetConsensusStats_Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = rpc_internal_error(r)
		}
	}()
	bh, err := parse_hash_list(p.BlockHashes, "block")
	if err != nil {
		return
	}
	mh, err := parse_hash_list(p.MiniBlockHashes, "miniblock")
	if err != nil {
		return
	}
	result.Version = config.Version.String()
	result.UptimeSeconds = int64(time.Since(globals.StartTime).Seconds())
	result.Height = chain.Get_Height()
	result.StableLimit = config.STABLE_LIMIT
	result.Counters = p2p.Consensus_Counters_Snapshot()
	result.AltBlocks = p2p.Alt_Blocks(result.Height, chain.Get_Blocks_At_Height)
	result.Reorg = reorg_state.stats()
	result.FirstSeen = make([]FirstSeen_Print, 0, len(bh)+len(mh))
	for _, h := range bh {
		result.FirstSeen = append(result.FirstSeen, first_seen_print(h, "block", p2p.Block_First_Seen))
	}
	for _, h := range mh {
		result.FirstSeen = append(result.FirstSeen, first_seen_print(h, "miniblock", p2p.MiniBlock_First_Seen))
	}
	result.BlocksSeen, result.MiniBlocksSeen = p2p.First_Seen_Table_Sizes()
	result.Status = "OK"
	return
}
