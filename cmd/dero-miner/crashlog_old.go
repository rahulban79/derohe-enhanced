//go:build !go1.23
// +build !go1.23

package main

// toolchains before go1.23 have no runtime/debug.SetCrashOutput; fatal traces then reach stderr only.
const crash_output_supported = false

func set_crash_output(path string) error { return nil }
