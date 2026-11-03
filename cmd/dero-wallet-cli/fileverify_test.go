package main

import "testing"

// r21: fileverify must never write the verified message over the signed input (upstream did for any name not
// ending in .sign, destroying the signature).
func TestVerifiedMessagePathNeverInput(t *testing.T) {
	cases := map[string]string{
		"doc.txt.sign": "doc.txt",
		"doc.txt":      "doc.txt.message",
		"signed":       "signed.message",
		".sign":        ".sign.message",
		"/a/b.sign":    "/a/b",
	}
	for in, want := range cases {
		got := verified_message_path(in)
		if got != want {
			t.Errorf("verified_message_path(%q) = %q, want %q", in, got, want)
		}
		if got == in {
			t.Errorf("verified_message_path(%q) returned the input: the signature would be overwritten", in)
		}
	}
}
