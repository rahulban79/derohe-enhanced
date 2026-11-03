// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8

package p2p

// Persistence of the v2-chain drop history (penalty.go v2_offences) in v2_offences.json next to ban_list.json,
// written with the same atomic helper and on the same schedule (start, 5-minute snapshot, shutdown).
// Local policy only: it changes how long a v2-remnant peer stays banned, nothing about validity.

import "encoding/json"
import "os"
import "path/filepath"
import "time"

import "github.com/deroproject/derohe/globals"

const V2_OFFENCES_FILE = "v2_offences.json"

func load_v2_offences() {
	load_v2_offences_from(filepath.Join(globals.GetDataDirectory(), V2_OFFENCES_FILE), time.Now().Unix())
}

func save_v2_offences() {
	save_v2_offences_to(filepath.Join(globals.GetDataDirectory(), V2_OFFENCES_FILE), time.Now().Unix())
}

// load_v2_offences_from merges the file into the in-memory map, keeping the larger count for an IP already present.
// A missing or unreadable file leaves the map as it is: a lost history only means a shorter ban, never a wrong one.
func load_v2_offences_from(path string, now int64) (loaded int) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var m map[string]v2_record
	if err := json.Unmarshal(data, &m); err != nil {
		logger.Error(err, "Error unmarshalling v2 offence data")
		return 0
	}
	penalty_mu.Lock()
	defer penalty_mu.Unlock()
	for ip, r := range m {
		if r.N <= 0 || now-r.Last > V2_FORGET || r.Last > now+86400 {
			continue // expired, or nonsense (a clock far in the future)
		}
		if cur, ok := v2_offences[ip]; !ok || r.N > cur.N {
			v2_offences[ip] = r
			loaded++
		}
	}
	v2_forget_locked(now)
	logger.V(1).Info("Successfully loaded v2 offences from file", "count", loaded)
	return
}

func save_v2_offences_to(path string, now int64) error {
	penalty_mu.Lock()
	snap := make(map[string]v2_record, len(v2_offences))
	for ip, r := range v2_offences {
		if now-r.Last <= V2_FORGET {
			snap[ip] = r
		}
	}
	penalty_mu.Unlock()
	err := write_json_atomic(path, snap)
	if err != nil {
		logger.Error(err, "saving v2 offence file")
	}
	return err
}
