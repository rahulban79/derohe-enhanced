// Copyright 2017-2018 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8

package main

import "testing"

// Needs to expand test to cover failure conditions
func Test_Part1(t *testing.T) {

}

// the password flag (--password) must be the one a created/restored wallet is encrypted with
func Test_Creation_Password(t *testing.T) {
	prompted := false
	if got := creation_password("X1", func() string { prompted = true; return "typed" }); got != "X1" || prompted {
		t.Fatalf("--password ignored: got %q prompted=%v", got, prompted)
	}
	if got := creation_password("", func() string { return "typed" }); got != "typed" {
		t.Fatalf("interactive password ignored: got %q", got)
	}
}

// --xswd-allow-remote defaults off (XSWD serves this machine only)
func Test_XSWD_Allow_Remote_Flag(t *testing.T) {
	if xswd_allow_remote(map[string]interface{}{}) || xswd_allow_remote(map[string]interface{}{"--xswd-allow-remote": false}) {
		t.Fatal("remote XSWD enabled without the flag")
	}
	if !xswd_allow_remote(map[string]interface{}{"--xswd-allow-remote": true}) {
		t.Fatal("flag ignored")
	}
}
