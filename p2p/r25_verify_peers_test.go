// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package p2p

// r25 (verify-peers): the adversarial verifier's counter-mutations found five r25 peers claims that no test exercised:
// the ban_reasons.json sidecar is actually written by save_ban_list, p2p_bans_by_source_total counts each ban, its
// label set stays fixed for an unknown source, BanInfos skips an expired but not yet cleaned ban, and PeerInfo shows
// no hold for a --sync-node (which is never skipped). Every address below is a documentation address (RFC 5737).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deroproject/derohe/globals"
)

// r25: the sidecar survives a save/load round trip, the by-source counter moves per ban, unknown sources are folded.
func TestR25VerifyBanSidecarSavedAndSourceCounted(t *testing.T) {
	reset_bans_r25(t)
	saved, had := globals.Arguments["--data-dir"]
	globals.Arguments["--data-dir"] = t.TempDir()
	defer func() {
		if had {
			globals.Arguments["--data-dir"] = saved
		} else {
			delete(globals.Arguments, "--data-dir")
		}
	}()
	dir := globals.GetDataDirectory()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}

	op0 := prom_value_r25(t, `p2p_bans_by_source_total{source="operator"}`)
	un0 := prom_value_r25(t, `p2p_bans_by_source_total{source="unattributed"}`)
	Ban_Address_Reason("192.0.2.91", 600, BAN_SOURCE_OPERATOR, "console")
	Ban_Address_Reason("192.0.2.92", 600, "made-up-source", "x")
	if d := prom_value_r25(t, `p2p_bans_by_source_total{source="operator"}`) - op0; d != 1 {
		t.Fatalf("bans_by_source{operator} moved by %v", d)
	}
	if d := prom_value_r25(t, `p2p_bans_by_source_total{source="unattributed"}`) - un0; d != 1 {
		t.Fatalf("an unknown source must count as unattributed, moved by %v", d)
	}
	if strings.Contains(prom_r25(), `source="made-up-source"`) || ban_source_label("made-up-source") != BAN_SOURCE_UNATTRIBUTED {
		t.Fatal("the by-source label set is not fixed")
	}

	ban_mutex.Lock()
	ban_map["192.0.2.92"] = uint64(time.Now().Unix()) - 1 // expired, not yet cleaned up
	ban_mutex.Unlock()
	if _, total, _ := BanInfos(-1, time.Now()); total != 1 {
		t.Fatalf("BanInfos counts an expired ban: total %d", total)
	}

	save_ban_list() // cleans up (drops .92 from both maps), then writes ban_list.json and ban_reasons.json
	b, err := os.ReadFile(filepath.Join(dir, "ban_reasons.json"))
	if err != nil {
		t.Fatalf("sidecar not saved: %v", err)
	}
	m := map[string]ban_info{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 || m["192.0.2.91"].Source != BAN_SOURCE_OPERATOR || m["192.0.2.91"].Reason != "console" {
		t.Fatalf("saved sidecar %s", b)
	}
	ban_mutex.Lock()
	ban_meta = map[string]ban_info{}
	load_ban_meta_locked(filepath.Join(dir, "ban_reasons.json"))
	got := ban_meta["192.0.2.91"]
	ban_mutex.Unlock()
	if got.Source != BAN_SOURCE_OPERATOR {
		t.Fatalf("reloaded %+v", got)
	}
}

// r25 (B47): PeerInfo shows the hold that trigger_sync applies: 30 s after one peer failure, none for a --sync-node.
func TestR25VerifyPeerInfoHoldMatchesSkip(t *testing.T) {
	reset_penalty(t)
	now := time.Now()
	c := out_conn("192.0.2.93")
	c.sync_failed(call_failure_short, now)
	if p := peer_info_of(c, now); p.SyncHoldSeconds != 30 || p.SyncFailures != 1 || !c.sync_held(now) {
		t.Fatalf("held peer: %+v", p)
	}
	s := out_conn("192.0.2.94")
	s.SyncNode = true
	s.sync_failed(call_failure_short, now)
	if p := peer_info_of(s, now); p.SyncHoldSeconds != 0 || p.SyncFailures != 1 || s.sync_held(now) {
		t.Fatalf("a --sync-node is never skipped, so it shows no hold: %+v", p)
	}
}
