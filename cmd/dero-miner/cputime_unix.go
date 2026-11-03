//go:build !windows
// +build !windows

package main

import (
	"syscall"
	"time"
)

// process_cpu_time: user+system CPU time of the whole process so far (getrusage RUSAGE_SELF)
func process_cpu_time() time.Duration {
	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}
