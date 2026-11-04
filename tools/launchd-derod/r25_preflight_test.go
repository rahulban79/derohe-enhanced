package main

// r25 perfops (B35): -preflight, the dry run before launchctl bootstrap. Every probe is forged except where a test
// says it uses the real system (a real temp tree for stat, a real loopback listener for the port probe).

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type pf_fix struct {
	root, bin, data string
	c               plist_cfg
	p               pf_probes
	busy_tcp        map[string]bool
	busy_udp        map[string]bool
	procs           []pf_proc
}

// new_fix builds a real tree: <root>/bin/derod (0755), <root>/data/mainnet, <root>/data/logs; every probe passes.
func new_fix(t *testing.T) *pf_fix {
	f := &pf_fix{root: t.TempDir(), busy_tcp: map[string]bool{}, busy_udp: map[string]bool{}}
	f.bin = filepath.Join(f.root, "bin", "derod")
	f.data = filepath.Join(f.root, "data")
	for _, d := range []string{filepath.Dir(f.bin), filepath.Join(f.data, "mainnet"), filepath.Join(f.data, "logs")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(f.bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.c = default_cfg()
	f.c.Dir, f.c.Binary, f.c.DataDir, f.c.Integrator = f.root, f.bin, f.data, "dero1qyexample"
	f.p = pf_probes{stat: os.Stat, read: os.ReadFile, self: 4242,
		procs: func() ([]pf_proc, error) { return f.procs, nil },
		listen_tcp: func(a string) error {
			if f.busy_tcp[a] {
				return errors.New("bind: address already in use")
			}
			return nil
		},
		listen_udp: func(a string) error {
			if f.busy_udp[a] {
				return errors.New("bind: address already in use")
			}
			return nil
		},
		lint: func([]byte) error { return nil }}
	return f
}

func (f *pf_fix) run(installed string) ([]pf_finding, int, string) {
	fs := preflight(f.c, f.p, installed)
	var w bytes.Buffer
	rc := pf_report(&w, fs)
	return fs, rc, w.String()
}

func level(fs []pf_finding, name string) string {
	for _, x := range fs {
		if x.Name == name {
			return x.Level
		}
	}
	return "absent"
}

func detail(fs []pf_finding, name string) string {
	for _, x := range fs {
		if x.Name == name {
			return x.Detail
		}
	}
	return ""
}

func TestR25PreflightReady(t *testing.T) {
	f := new_fix(t)
	f.procs = []pf_proc{{Pid: 7, Argv: []string{"/usr/bin/other", "--data-dir=" + f.data}}} // not a derod
	fs, rc, out := f.run("")
	if rc != 0 || !strings.Contains(out, "0 FAIL, 0 WARN: READY to install") {
		t.Fatalf("rc %d:\n%s", rc, out)
	}
	for _, n := range []string{"config", "binary", "data-dir", "log-dir", "integrator", "running-derod", "--rpc-bind", "--getwork-bind", "--p2p-bind", "plutil"} {
		if level(fs, n) != PF_PASS {
			t.Errorf("%s: %s (%s)", n, level(fs, n), detail(fs, n))
		}
	}
}

// the hazard the dry run exists for: a terminal derod already on the store (derod takes no lock on it)
func TestR25PreflightRunningDerodSameStore(t *testing.T) {
	f := new_fix(t)
	f.procs = []pf_proc{
		{Pid: 4242, Argv: []string{"./bin/derod", "--data-dir=" + f.data}},    // self: ignored
		{Pid: 11, Argv: []string{"/x/launchd-derod", "--data-dir=" + f.data}}, // not a derod (r25 verify: was derod-cand, which IS one)
		{Pid: 12, Argv: []string{"./bin/derod", "--data-dir=/elsewhere"}},     // another store: ignored
		{Pid: 13, Argv: []string{"./bin/derod", "--data-dir=" + f.data + "/", "--min-peers=20", // trailing slash: same store
			"--rpc-bind=127.0.0.1:10102", "--getwork-bind=127.0.0.1:10100", "--p2p-bind=0.0.0.0:11011", "--fastsync", "--lowlatency",
			"--integrator-address=dero1qyother"}},
	}
	fs, rc, out := f.run("")
	if rc != 1 || level(fs, "running-derod") != PF_FAIL || !strings.Contains(detail(fs, "running-derod"), "pid 13") {
		t.Fatalf("running derod not refused (rc %d):\n%s", rc, out)
	}
	if strings.Contains(out, "pid 11 ") || strings.Contains(out, "pid 12 ") || strings.Contains(out, "pid 4242") {
		t.Fatalf("wrong process reported:\n%s", out)
	}
	d := detail(fs, "flag-parity")
	if level(fs, "flag-parity") != PF_WARN || !strings.Contains(d, "plist drops --min-peers") || !strings.Contains(d, "--integrator-address differs") {
		t.Fatalf("flag parity %q", d)
	}
	if strings.Contains(d, "--data-dir") { // owned flags are compared by path, not by text
		t.Fatalf("owned flag in parity: %q", d)
	}
	// identical flags: parity passes
	f.procs = []pf_proc{{Pid: 13, Argv: append([]string{"./bin/derod"}, program_args(f.c)[1:]...)}}
	fs, _, _ = f.run("")
	if level(fs, "flag-parity") != PF_PASS {
		t.Fatalf("identical flags: %s %s", level(fs, "flag-parity"), detail(fs, "flag-parity"))
	}
	f.c.Extra = append(f.c.Extra, "--min-peers=5")
	if d := func() string { fs, _, _ := f.run(""); return detail(fs, "flag-parity") }(); !strings.Contains(d, "plist adds --min-peers") {
		t.Fatalf("plist-only flag not reported: %q", d)
	}
}

func TestR25PreflightPorts(t *testing.T) {
	f := new_fix(t)
	f.busy_tcp["127.0.0.1:10102"] = true
	f.busy_tcp["0.0.0.0:11011"] = true // p2p is UDP: a busy TCP 11011 must not fail it
	fs, rc, out := f.run("")
	if rc != 1 || level(fs, "--rpc-bind") != PF_FAIL || level(fs, "--getwork-bind") != PF_PASS || level(fs, "--p2p-bind") != PF_PASS {
		t.Fatalf("tcp probes:\n%s", out)
	}
	f = new_fix(t)
	f.busy_udp["0.0.0.0:11011"] = true
	f.busy_tcp["127.0.0.1:10100"] = true
	fs, _, out = f.run("")
	if level(fs, "--p2p-bind") != PF_FAIL || level(fs, "--getwork-bind") != PF_FAIL || level(fs, "--rpc-bind") != PF_PASS {
		t.Fatalf("udp probe:\n%s", out)
	}
	f = new_fix(t)
	f.c.Extra = []string{"--p2p-bind=0.0.0.0:0", "--rpc-bind=nonsense"}
	fs, _, out = f.run("")
	if level(fs, "--p2p-bind") != PF_PASS || level(fs, "--rpc-bind") != PF_FAIL || level(fs, "--getwork-bind") != PF_WARN {
		t.Fatalf("port 0 / bad addr / unset:\n%s", out)
	}
}

func TestR25PreflightFilesystem(t *testing.T) {
	cases := map[string]struct {
		mut         func(f *pf_fix)
		name, level string
	}{
		"no binary":       {func(f *pf_fix) { os.Remove(f.bin) }, "binary", PF_FAIL},
		"not executable":  {func(f *pf_fix) { os.Chmod(f.bin, 0o644) }, "binary", PF_FAIL},
		"binary is dir":   {func(f *pf_fix) { os.Remove(f.bin); os.Mkdir(f.bin, 0o755) }, "binary", PF_FAIL},
		"no data dir":     {func(f *pf_fix) { os.RemoveAll(f.data) }, "data-dir", PF_FAIL},
		"no chain yet":    {func(f *pf_fix) { os.RemoveAll(filepath.Join(f.data, "mainnet")) }, "data-dir", PF_WARN},
		"testnet store":   {func(f *pf_fix) { f.c.Extra = append(f.c.Extra, "--testnet") }, "data-dir", PF_WARN},
		"no log dir":      {func(f *pf_fix) { os.RemoveAll(filepath.Join(f.data, "logs")) }, "log-dir", PF_FAIL},
		"stdout dir gone": {func(f *pf_fix) { f.c.Stdout = filepath.Join(f.root, "nope", "out.txt") }, "stdout", PF_FAIL},
		"no integrator":   {func(f *pf_fix) { f.c.Integrator = "" }, "integrator", PF_WARN},
	}
	for n, k := range cases {
		f := new_fix(t)
		k.mut(f)
		fs, rc, out := f.run("")
		if level(fs, k.name) != k.level {
			t.Errorf("%s: %s=%s want %s\n%s", n, k.name, level(fs, k.name), k.level, out)
		}
		if want := k.level == PF_FAIL; (rc == 1) != want {
			t.Errorf("%s: rc %d", n, rc)
		}
	}
}

func TestR25PreflightRefusalsAndLint(t *testing.T) {
	f := new_fix(t)
	f.c.DataDir = DATA_PLACEHOLDER
	fs, rc, _ := f.run("")
	if rc != 1 || level(fs, "config") != PF_FAIL || len(fs) != 1 {
		t.Fatalf("placeholder: rc %d %v", rc, fs)
	}
	f = new_fix(t)
	f.p.procs = func() ([]pf_proc, error) { return nil, errors.New("ps: denied") }
	if fs, rc, _ := f.run(""); rc != 1 || level(fs, "running-derod") != PF_FAIL {
		t.Fatalf("a process list that cannot be read must fail: %v", fs)
	}
	f = new_fix(t)
	f.p.lint = func([]byte) error { return errors.New("bad") }
	if fs, rc, _ := f.run(""); rc != 1 || level(fs, "plutil") != PF_FAIL {
		t.Fatalf("lint: %v", fs)
	}
	f = new_fix(t)
	f.p.lint = nil
	if fs, rc, _ := f.run(""); rc != 0 || level(fs, "plutil") != PF_WARN {
		t.Fatalf("no plutil: %v", fs)
	}
	f = new_fix(t)
	inst := filepath.Join(f.root, "io.dero.derod.plist")
	if fs, _, _ := f.run(inst); level(fs, "installed") != PF_PASS || !strings.Contains(detail(fs, "installed"), "not present") {
		t.Fatalf("absent: %v", fs)
	}
	os.WriteFile(inst, render(f.c), 0o600)
	if fs, _, _ := f.run(inst); level(fs, "installed") != PF_PASS || !strings.Contains(detail(fs, "installed"), "exact") {
		t.Fatalf("same: %v", fs)
	}
	os.WriteFile(inst, []byte("old"), 0o600)
	if fs, _, _ := f.run(inst); level(fs, "installed") != PF_WARN {
		t.Fatalf("differs: %v", fs)
	}
}

// the -preflight flag prints findings, never a plist (so `... -preflight > LaunchAgents/x.plist` cannot install one)
func TestR25PreflightRunFlag(t *testing.T) {
	f := new_fix(t)
	saved := probes_for_run
	defer func() { probes_for_run = saved }()
	probes_for_run = func() pf_probes { return f.p }
	args := []string{"-preflight", "-data-dir=" + f.data, "-binary=" + f.bin, "-dir=" + f.root, "-integrator-address=dero1qyx",
		"-installed=" + filepath.Join(f.root, "x.plist")}
	var out, errb bytes.Buffer
	if rc := run(args, &out, &errb); rc != 0 || strings.Contains(out.String(), "<plist") || !strings.Contains(out.String(), "READY to install") {
		t.Fatalf("rc %d:\n%s%s", rc, out.String(), errb.String())
	}
	f.procs = []pf_proc{{Pid: 99, Argv: []string{"derod", "--data-dir=" + f.data}}}
	out.Reset()
	if rc := run(args, &out, &errb); rc != 1 || !strings.Contains(out.String(), "NOT READY") {
		t.Fatalf("rc %d:\n%s", rc, out.String())
	}
}

// the real probes: a loopback port this test holds is reported busy, a released one free; ps parsing
func TestR25PreflightRealProbes(t *testing.T) {
	p := real_probes()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	if p.listen_tcp(a) == nil {
		t.Fatalf("held tcp %s reported free", a)
	}
	l.Close()
	if err := p.listen_tcp(a); err != nil {
		t.Fatalf("released tcp %s: %v", a, err)
	}
	u, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if p.listen_udp(u.LocalAddr().String()) == nil {
		t.Fatalf("held udp reported free")
	}
	u.Close()
	ps := parse_ps(" 12 ./bin/derod --data-dir=/d --fastsync\nbad line\n  7 /sbin/launchd\n\n")
	if len(ps) != 2 || ps[0].Pid != 12 || fmt.Sprint(ps[0].Argv) != "[./bin/derod --data-dir=/d --fastsync]" || ps[1].Pid != 7 {
		t.Fatalf("parse_ps %+v", ps)
	}
	if v, ok := arg_value([]string{"x", "--data-dir", "/d"}, "--data-dir"); !ok || v != "/d" {
		t.Fatalf("space form %q %v", v, ok)
	}
	if procs, err := p.procs(); err != nil || len(procs) == 0 {
		t.Fatalf("real ps: %v (%d)", err, len(procs))
	}
}
