// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package main

// r25 perfops (B35): -preflight, the dry run before `launchctl bootstrap`. It installs nothing, starts nothing and
// writes nothing outside a temp file for plutil. It answers one question: would bootstrapping this plist NOW start a
// derod that runs, on the store and ports the user chose, without a second node on the same store?
//
// Why the running-node check is a FAIL and not a hint: derod takes no lock on its data directory (no flock in the
// tree outside vendor/bbolt, which derod does not use), and the plist has RunAtLoad, so `launchctl bootstrap` while the
// terminal derod still runs would open the same graviton store twice. The port probes catch the same mistake from the
// other side (a second node with the same binds would also fail to listen).

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	PF_PASS = "PASS"
	PF_WARN = "WARN"
	PF_FAIL = "FAIL"
)

type pf_finding struct{ Level, Name, Detail string }

// pf_probes are the effects preflight reads; tests replace them with forged ones.
type pf_probes struct {
	stat       func(string) (os.FileInfo, error)
	procs      func() ([]pf_proc, error) // running processes (pid + argv)
	listen_tcp func(addr string) error   // nil when the address can be bound now
	listen_udp func(addr string) error
	lint       func(plist []byte) error // nil probe = skipped (non-macOS)
	read       func(string) ([]byte, error)
	self       int // this process's pid (never reported as a running derod)
}

type pf_proc struct {
	Pid  int
	Argv []string
}

// arg_value returns the value of --name=value (or "--name value") in argv, and whether the flag is present.
func arg_value(argv []string, name string) (string, bool) {
	for i, a := range argv {
		if a == name {
			if i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "--") {
				return argv[i+1], true
			}
			return "", true
		}
		if strings.HasPrefix(a, name+"=") {
			return a[len(name)+1:], true
		}
	}
	return "", false
}

// r25 verify: a derod is any binary named derod, derod-<suffix> or derod.<suffix> (the upstream release binaries are
// derod-darwin-arm64, derod-linux-amd64, ...; shadow builds are derod-cand): on the same store each one is the same hazard.
func is_derod(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	b := filepath.Base(argv[0])
	return b == "derod" || strings.HasPrefix(b, "derod-") || strings.HasPrefix(b, "derod.")
}

func same_dir(a, b string) bool {
	return a != "" && b != "" && filepath.Clean(a) == filepath.Clean(b)
}

// flag_set is argv[1:] as name -> value, without the flags the generator owns (their values legitimately differ).
func flag_set(argv []string) map[string]string {
	m := map[string]string{}
	for _, a := range argv[1:] {
		n := flag_name(a)
		if !strings.HasPrefix(n, "--") {
			continue
		}
		skip := false
		for _, o := range owned {
			if n == o {
				skip = true
			}
		}
		if !skip {
			m[n] = strings.TrimPrefix(a, n+"=")
			if !strings.Contains(a, "=") {
				m[n] = ""
			}
		}
	}
	return m
}

// preflight runs every check and returns the findings in a fixed order. installed is the path the plist would be
// copied to (~/Library/LaunchAgents/<label>.plist); "" skips that check.
func preflight(c plist_cfg, p pf_probes, installed string) (out []pf_finding) {
	add := func(l, n, f string, a ...interface{}) { out = append(out, pf_finding{l, n, fmt.Sprintf(f, a...)}) }
	c = resolved(c)
	if err := check(c); err != nil {
		add(PF_FAIL, "config", "%v", err)
		return // the remaining checks would read a configuration the generator already refuses
	}
	add(PF_PASS, "config", "generator checks pass")

	if fi, err := p.stat(c.Binary); err != nil {
		add(PF_FAIL, "binary", "%s: %v (build it: go build -o bin/derod ./cmd/derod)", c.Binary, err)
	} else if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		add(PF_FAIL, "binary", "%s is not an executable file (mode %v)", c.Binary, fi.Mode())
	} else {
		add(PF_PASS, "binary", "%s executable", c.Binary)
	}

	network := "mainnet"
	if _, ok := arg_value(c.Extra, "--testnet"); ok {
		network = "testnet"
	}
	if fi, err := p.stat(c.DataDir); err != nil || !fi.IsDir() {
		add(PF_FAIL, "data-dir", "%s is not a directory (%v)", c.DataDir, err)
	} else if fi, err := p.stat(filepath.Join(c.DataDir, network)); err != nil || !fi.IsDir() {
		add(PF_WARN, "data-dir", "%s has no %s/ yet: derod would start a fresh sync there", c.DataDir, network)
	} else {
		add(PF_PASS, "data-dir", "%s/%s exists", c.DataDir, network)
	}

	// launchd opens StandardOutPath itself before exec; it does not create the directory, and derod's log rotation
	// needs the directory too, so a missing log dir is a FAIL with the fix in the message.
	if fi, err := p.stat(c.LogDir); err != nil || !fi.IsDir() {
		add(PF_FAIL, "log-dir", "%s is not a directory (mkdir -p it first)", c.LogDir)
	} else if fi, err := p.stat(filepath.Dir(c.Stdout)); err != nil || !fi.IsDir() {
		add(PF_FAIL, "stdout", "the directory of %s does not exist", c.Stdout)
	} else {
		add(PF_PASS, "log-dir", "%s exists", c.LogDir)
	}

	if c.Integrator == "" {
		add(PF_WARN, "integrator", "no --integrator-address: blocks this node builds pay the integrator share to derod's default (dev) address")
	} else {
		add(PF_PASS, "integrator", "set")
	}

	plist_args := program_args(c)
	procs, err := p.procs()
	if err != nil {
		add(PF_FAIL, "running-derod", "cannot list processes (%v): refusing to say no node runs on this store", err)
	} else {
		var same, unresolved []pf_proc
		for _, q := range procs {
			if q.Pid == p.self || !is_derod(q.Argv) {
				continue
			}
			dd, _ := arg_value(q.Argv, "--data-dir")
			if !filepath.IsAbs(dd) { // r25 verify: absent or relative = its own cwd, which ps does not show
				unresolved = append(unresolved, q)
				continue
			}
			if same_dir(dd, c.DataDir) {
				same = append(same, q)
			}
		}
		for _, q := range unresolved {
			add(PF_WARN, "running-derod", "derod pid %d runs with no absolute --data-dir (its store is relative to its own working "+
				"directory): cannot tell whether it is %s; check `lsof -a -p %d -d cwd` or stop it first", q.Pid, c.DataDir, q.Pid)
		}
		if len(same) == 0 && len(unresolved) == 0 {
			add(PF_PASS, "running-derod", "no derod runs on %s", c.DataDir)
		}
		for _, q := range same {
			add(PF_FAIL, "running-derod", "derod pid %d already runs on this --data-dir: stop it first (type exit at its prompt); "+
				"derod takes no lock on its store and RunAtLoad would start a second node on it", q.Pid)
			// flag parity: what the running node has that the plist would drop, or the reverse (same --data-dir only)
			run, want := flag_set(q.Argv), flag_set(plist_args)
			var diffs []string
			for _, n := range sorted_keys(run) {
				if w, ok := want[n]; !ok {
					diffs = append(diffs, "plist drops "+n)
				} else if w != run[n] {
					diffs = append(diffs, n+" differs")
				}
			}
			for _, n := range sorted_keys(want) {
				if _, ok := run[n]; !ok {
					diffs = append(diffs, "plist adds "+n)
				}
			}
			if ri, _ := arg_value(q.Argv, "--integrator-address"); ri != c.Integrator {
				diffs = append(diffs, "--integrator-address differs")
			}
			if len(diffs) == 0 {
				add(PF_PASS, "flag-parity", "the plist runs derod with the running node's flags")
			} else {
				add(PF_WARN, "flag-parity", "pid %d vs plist: %s (pass the running node's flags with -flags)", q.Pid, strings.Join(diffs, "; "))
			}
		}
	}

	for _, b := range []struct{ flag, proto string }{{"--rpc-bind", "tcp"}, {"--getwork-bind", "tcp"}, {"--p2p-bind", "udp"}} {
		addr, ok := arg_value(plist_args, b.flag)
		if !ok || addr == "" {
			add(PF_WARN, b.flag, "not set: derod uses its built-in default")
			continue
		}
		if _, port, err := net.SplitHostPort(addr); err != nil {
			add(PF_FAIL, b.flag, "%q is not host:port (%v)", addr, err)
			continue
		} else if port == "0" {
			add(PF_PASS, b.flag, "port 0: listener disabled")
			continue
		}
		probe := p.listen_tcp
		if b.proto == "udp" { // p2p is KCP over UDP (memory dero-network-changes; lsof on the live node: UDP *:11011 only)
			probe = p.listen_udp
		}
		if err := probe(addr); err != nil {
			add(PF_FAIL, b.flag, "%s/%s cannot be bound now (%v): another process holds it", addr, b.proto, err)
		} else {
			add(PF_PASS, b.flag, "%s/%s is free", addr, b.proto)
		}
	}

	rendered := render(c)
	if p.lint == nil {
		add(PF_WARN, "plutil", "skipped (not macOS)")
	} else if err := p.lint(rendered); err != nil {
		add(PF_FAIL, "plutil", "plutil -lint refuses the plist: %v", err)
	} else {
		add(PF_PASS, "plutil", "plutil -lint OK")
	}

	if installed != "" {
		if old, err := p.read(installed); err != nil {
			add(PF_PASS, "installed", "%s not present yet", installed)
		} else if string(old) == string(rendered) {
			add(PF_PASS, "installed", "%s already holds this exact plist", installed)
		} else {
			add(PF_WARN, "installed", "%s exists and differs: bootout the old job before replacing it", installed)
		}
	}
	return
}

func sorted_keys(m map[string]string) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	for i := 1; i < len(k); i++ { // tiny insertion sort: keeps the import list small
		for j := i; j > 0 && k[j] < k[j-1]; j-- {
			k[j], k[j-1] = k[j-1], k[j]
		}
	}
	return k
}

// pf_report prints the findings and returns the exit code: 0 READY (no FAIL), 1 NOT READY.
func pf_report(w io.Writer, fs []pf_finding) int {
	nf, nw := 0, 0
	for _, f := range fs {
		fmt.Fprintf(w, "%-4s %-14s %s\n", f.Level, f.Name, f.Detail)
		switch f.Level {
		case PF_FAIL:
			nf++
		case PF_WARN:
			nw++
		}
	}
	verdict := "READY to install"
	if nf > 0 {
		verdict = "NOT READY"
	}
	fmt.Fprintf(w, "preflight: %d FAIL, %d WARN: %s\n", nf, nw, verdict)
	if nf > 0 {
		return 1
	}
	return 0
}

// real_probes reads the live system (read-only; the listeners are closed at once).
func real_probes() pf_probes {
	p := pf_probes{stat: os.Stat, read: os.ReadFile, self: os.Getpid()}
	p.procs = func() ([]pf_proc, error) {
		b, err := exec.Command("ps", "-axww", "-o", "pid=,command=").Output()
		if err != nil {
			return nil, err
		}
		return parse_ps(string(b)), nil
	}
	p.listen_tcp = func(a string) error {
		l, err := net.Listen("tcp", a)
		if err == nil {
			l.Close()
		}
		return err
	}
	p.listen_udp = func(a string) error {
		l, err := net.ListenPacket("udp", a)
		if err == nil {
			l.Close()
		}
		return err
	}
	if _, err := exec.LookPath("plutil"); err == nil {
		p.lint = func(b []byte) error {
			f, err := os.CreateTemp("", "launchd-derod-*.plist")
			if err != nil {
				return err
			}
			defer os.Remove(f.Name())
			f.Write(b)
			f.Close()
			if out, err := exec.Command("plutil", "-lint", f.Name()).CombinedOutput(); err != nil {
				return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
			}
			return nil
		}
	}
	return p
}

// parse_ps splits `ps -o pid=,command=` output. Arguments are split on spaces, so a path containing a space is split
// too; such a --data-dir is then not matched (documented in README; the port probes still catch a running node).
func parse_ps(s string) (out []pf_proc) {
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		out = append(out, pf_proc{Pid: pid, Argv: f[1:]})
	}
	return
}

// default_installed is ~/Library/LaunchAgents/<label>.plist ("" without a home directory).
func default_installed(label string) string {
	h, err := os.UserHomeDir()
	if err != nil || h == "" {
		return ""
	}
	return filepath.Join(h, "Library", "LaunchAgents", label+".plist")
}
