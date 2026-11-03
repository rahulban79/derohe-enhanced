// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package rpc

// r20 security: fuzz the websocket/HTTP JSON params of the r19 methods through their pure validators (the parts a
// client controls before any chain read), plus the batch counter of the remote limits.

import (
	"encoding/json"
	"testing"
)

func FuzzRPCParams(f *testing.F) {
	for _, s := range []string{`{"events":["BlockInfo","MiniBlock"]}`, `{"events":[]}`, `{"events":["x"]}`,
		`{"start_topoheight":0,"end_topoheight":99}`, `{"start_topoheight":-1,"end_topoheight":9223372036854775807}`,
		`{"count":1001,"end_topoheight":5}`, `{"limit":-1}`, `[{"jsonrpc":"2.0"},{}]`, `[`, ` [1,2,3]`, `null`} {
		f.Add([]byte(s), int64(7822693))
	}
	f.Fuzz(func(t *testing.T, raw []byte, top int64) {
		if top < 0 {
			top = -top
		}
		if top < 0 { // math.MinInt64
			top = 0
		}
		var sp Subscribe_Params
		if json.Unmarshal(raw, &sp) == nil {
			if bits, names, err := parse_subscriptions(sp.Events); err == nil {
				if bits&^SUB_ALL != 0 || len(names) > len(sub_names) {
					t.Fatalf("subscriptions %b %v from %q", bits, names, raw)
				}
			}
		}
		var hr GetBlockHeadersRange_Params
		if json.Unmarshal(raw, &hr) == nil {
			if s, e, err := clamp_topo_range(hr.Start, hr.End, top, MAX_HEADERS_RANGE); err == nil {
				if s < 0 || e > top || e < s || e-s+1 > MAX_HEADERS_RANGE {
					t.Fatalf("clamp(%d,%d,top %d) = [%d,%d]", hr.Start, hr.End, top, s, e)
				}
			}
		}
		var dh GetDifficultyHistory_Params
		if json.Unmarshal(raw, &dh) == nil {
			if s, e, err := clamp_topo_range(dh.End-dh.Count+1, dh.End, top, MAX_DIFFICULTY_HISTORY); err == nil && e-s+1 > MAX_DIFFICULTY_HISTORY {
				t.Fatalf("difficulty range [%d,%d]", s, e)
			}
		}
		var mp GetMiniBlocks_Params
		json.Unmarshal(raw, &mp)
		var tp GetTxPoolDetail_Params
		json.Unmarshal(raw, &tp)
		if n, err := batch_len(raw); err == nil && n < 0 {
			t.Fatalf("batch_len %d", n)
		}
		mbl_time_ms(uint64(top), uint16(len(raw)))
	})
}
