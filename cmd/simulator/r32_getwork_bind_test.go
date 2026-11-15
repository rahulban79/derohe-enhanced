package main

// r32 (dero-game-theory-rft D-GT-1): the simulator's opt-in getwork server is refused unless loopback and not the
// default getwork port.

import "testing"

func TestR32SimulatorGetworkRefusal(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:47100": true, "localhost:47100": true, "[::1]:47100": true,
		"127.0.0.1:10100": false, "0.0.0.0:47100": false, "203.0.113.5:47100": false,
		"127.0.0.1:0": false, "nonsense": false,
	} {
		if got := simulator_getwork_refusal(addr) == ""; got != ok {
			t.Errorf("%s: accepted %v, want %v (%q)", addr, got, ok, simulator_getwork_refusal(addr))
		}
	}
}
