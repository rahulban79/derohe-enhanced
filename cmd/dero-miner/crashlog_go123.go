//go:build go1.23
// +build go1.23

package main

import (
	"os"
	"runtime/debug"
)

// crash_output_supported: a fatal runtime error (unrecovered panic, concurrent map write, a SIGSEGV in the cgo
// descriptor sort) printed its trace only to the terminal, so a miner that died while nobody watched left nothing
// behind (Round 20 forensics). The trace is now also appended to <log>.crash.
const crash_output_supported = true

func set_crash_output(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	err = debug.SetCrashOutput(f, debug.CrashOptions{}) // the runtime keeps its own duplicate of the descriptor
	f.Close()
	return err
}
