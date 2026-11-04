package main

// r25 verify-perfops: the running-derod check must not report "no derod runs on <store>" for a derod it cannot place:
// a release binary (derod-darwin-arm64) or a shadow build (derod-cand) on the same store is the same hazard, and a
// derod with no absolute --data-dir runs on a store relative to its own cwd, which ps does not show.

import (
	"strings"
	"testing"
)

func TestR25VerifyPreflightDerodNames(t *testing.T) {
	for _, n := range []string{"derod", "./bin/derod", "/opt/dero/derod-darwin-arm64", "derod-linux-amd64", "/x/derod-cand", "derod.exe"} {
		if !is_derod([]string{n}) {
			t.Errorf("%s: not recognised as a derod", n)
		}
	}
	for _, n := range []string{"launchd-derod", "/x/derodfoo", "dero-miner", "notderod", ""} {
		if is_derod([]string{n}) {
			t.Errorf("%q: recognised as a derod", n)
		}
	}
	if is_derod(nil) {
		t.Error("empty argv recognised as a derod")
	}
	f := new_fix(t)
	f.procs = []pf_proc{{Pid: 21, Argv: []string{"/opt/dero/derod-darwin-arm64", "--data-dir=" + f.data}}}
	fs, rc, out := f.run("")
	if rc != 1 || level(fs, "running-derod") != PF_FAIL || !strings.Contains(detail(fs, "running-derod"), "pid 21") {
		t.Fatalf("release-named derod on the same store not refused (rc %d):\n%s", rc, out)
	}
}

func TestR25VerifyPreflightUnresolvedDataDir(t *testing.T) {
	for _, argv := range [][]string{
		{"./bin/derod", "--fastsync"},                 // no --data-dir: the store is its cwd
		{"./bin/derod", "--data-dir=dero-data"},       // relative
		{"./bin/derod", "--data-dir", "../dero-data"}, // relative, space-separated
	} {
		f := new_fix(t)
		f.procs = []pf_proc{{Pid: 31, Argv: argv}}
		fs, _, out := f.run("")
		if level(fs, "running-derod") != PF_WARN || !strings.Contains(detail(fs, "running-derod"), "pid 31") {
			t.Fatalf("%v: unresolved store not warned:\n%s", argv, out)
		}
		if strings.Contains(out, "no derod runs on") {
			t.Fatalf("%v: claims no derod runs while one cannot be placed:\n%s", argv, out)
		}
	}
	// an absolute store elsewhere is still resolved and ignored
	f := new_fix(t)
	f.procs = []pf_proc{{Pid: 32, Argv: []string{"./bin/derod", "--data-dir=/elsewhere"}}}
	fs, rc, out := f.run("")
	if rc != 0 || level(fs, "running-derod") != PF_PASS {
		t.Fatalf("absolute other store: rc %d\n%s", rc, out)
	}
}
