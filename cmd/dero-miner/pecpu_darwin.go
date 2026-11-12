//go:build darwin && cgo

package main

// r30 B27: the P/E CPU split. proc_pid_rusage(RUSAGE_INFO_V6) carries, next to the process's user and system time,
// the part of each that ran on the performance cores (ri_user_ptime, ri_system_ptime; Apple Silicon, macOS 12+). Both
// are in mach absolute-time units, converted here with mach_timebase_info (125/3 ns per tick on M-series). The E-core
// time is total - P. Read once per 15 s TOTAL line by the status goroutine and by /metrics: never on the hashing path.

/*
#include <unistd.h>
#include <libproc.h>
#include <sys/resource.h>
#include <mach/mach_time.h>
static int dm_pe_rusage(unsigned long long* total, unsigned long long* p, unsigned int* numer, unsigned int* denom) {
	struct rusage_info_v6 ri;
	if (proc_pid_rusage(getpid(), RUSAGE_INFO_V6, (rusage_info_t*)&ri) != 0) return -1;
	mach_timebase_info_data_t tb;
	if (mach_timebase_info(&tb) != 0 || tb.denom == 0) return -2;
	*total = ri.ri_user_time + ri.ri_system_time;
	*p = ri.ri_user_ptime + ri.ri_system_ptime;
	*numer = tb.numer;
	*denom = tb.denom;
	return 0;
}
*/
import "C"

import "time"

// pe_cpu_time: the process's CPU time so far and the part of it on P-cores; ok=false when the kernel cannot say.
func pe_cpu_time() (total, p time.Duration, ok bool) {
	var t, pp C.ulonglong
	var n, d C.uint
	if C.dm_pe_rusage(&t, &pp, &n, &d) != 0 {
		return 0, 0, false
	}
	return mach_ticks_ns(uint64(t), uint32(n), uint32(d)), mach_ticks_ns(uint64(pp), uint32(n), uint32(d)), true
}
