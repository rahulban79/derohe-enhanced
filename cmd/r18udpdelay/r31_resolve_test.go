package main

import "testing"

// r31 (detector error-paths): a malformed -listen or -upstream is an error, never a silent nil address.
func TestR31UdpdelayResolvePair(t *testing.T) {
	la, ua, err := resolve_pair("127.0.0.1:35200", "127.0.0.1:11011")
	if err != nil || la == nil || ua == nil || la.Port != 35200 || ua.Port != 11011 {
		t.Fatalf("valid pair: %v %v %v", la, ua, err)
	}
	if _, _, err := resolve_pair("127.0.0.1:notaport", "127.0.0.1:11011"); err == nil {
		t.Fatal("a malformed -listen resolved")
	}
	if _, _, err := resolve_pair("127.0.0.1:35200", "127.0.0.1:notaport"); err == nil {
		t.Fatal("a malformed -upstream resolved")
	}
}
