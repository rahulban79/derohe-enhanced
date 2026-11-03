//go:build !race
// +build !race

package rpc

// race_enabled: this test binary was built with -race (see race_flag_on_test.go).
const race_enabled = false
