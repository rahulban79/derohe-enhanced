//go:build !(darwin && cgo)

package main

import "time"

// pe_cpu_time: no P/E split outside darwin/cgo (r30 B27); the TOTAL line then prints "-" for p_cores and e_cores.
func pe_cpu_time() (total, p time.Duration, ok bool) { return 0, 0, false }
