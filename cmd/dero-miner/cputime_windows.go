//go:build windows
// +build windows

package main

import "time"

// process_cpu_time is not measured on windows; the bench prints "-" for H/cpu-s
func process_cpu_time() time.Duration { return 0 }
