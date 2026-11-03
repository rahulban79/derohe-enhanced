// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package main

import (
	"fmt"
	"time"
)

// contention_fields (r23 forensics) are two extra fields on every 15 s 'TOTAL hashrate' line: cpu_cores, the CPU the
// miner process actually got in the window (getrusage user+system / wall), and H/cpu-s, the hashes it made per CPU
// second. Together they separate the two reasons TOTAL falls: a lower H/cpu-s is the miner getting less efficient; a
// steady H/cpu-s with fewer cpu_cores is the box giving the miner less CPU (r22 live: 4,817 H/s per miner core, and the
// 23:24 drop from ~86k to ~65k H/s left H/cpu-s at ~5.2k while foreign nice-0 processes took the cores). The split
// line's feeder_cpu_backlog cannot tell these apart: it read 91-92% of the window both at 88k (14:47) and at 51k
// (01:30). On windows process_cpu_time is not measured, so both fields read "-".
func contention_fields(hashes uint64, cpu time.Duration, el float64) []interface{} {
	if cpu <= 0 || el <= 0 {
		return []interface{}{"cpu_cores", "-", "H/cpu-s", "-"}
	}
	return []interface{}{"cpu_cores", fmt.Sprintf("%.2f", cpu.Seconds()/el), "H/cpu-s", fmt.Sprintf("%.0f", float64(hashes)/cpu.Seconds())}
}
