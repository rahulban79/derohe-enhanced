// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

// Command launchd-derod prints a launchd agent plist that keeps derod running (r24 getworkops, backlog B35).
//
// Why: derod had no supervisor. Over the r23c census window 21.65 of 63.40 idle miner hours (34 %) overlapped derod
// downtime (verify-payouts PAY23c-1), and a node that is down also stops relaying and serving wallets. Under launchd
// derod starts at login, is restarted after any exit (KeepAlive), and is stopped by launchctl with SIGTERM, which
// derod turns into its ordered shutdown (cmd/derod/main.go exit_on_signal: RPC stop, P2P_Shutdown saves, chain
// Shutdown). It has no console there: stdin is /dev/null, so readline returns EOF at once and derod waits for a signal
// (readline_loop blocks on Exit_In_Progress after EOF), exactly as a terminal run waits for "exit".
//
//	go run ./tools/launchd-derod --data-dir=/abs/dero-data > ~/Library/LaunchAgents/io.dero.derod.plist
//	# stop the terminal derod first (type exit at its prompt): two nodes on one datadir/port set cannot both run
//	launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/io.dero.derod.plist   # start (and at every login)
//	launchctl kickstart -k gui/$(id -u)/io.dero.derod                            # restart (new binary): SIGTERM, wait, start
//	launchctl bootout gui/$(id -u)/io.dero.derod                                 # stop: SIGTERM, then SIGKILL after ExitTimeOut
//
// ExitTimeOut is how long launchd waits after SIGTERM before SIGKILL (launchd's default is 20 s). A SIGKILL skips the
// peer/ban saves and the chain shutdown, so the default here (--exit-timeout) is well above the shutdown time
// measured on an APFS clone of the mainnet datadir (r24, 2026-11-02: 1.28 s from SIGTERM to exit, exit code 0).
//
// Without --data-dir the plist carries the placeholder DATA_DIR and -check refuses it (launchd would start a node on a
// datadir nobody chose). Nothing here installs anything: the tool only prints.
//
// r25 (B35): run the same command with -preflight first (preflight.go): it prints PASS/WARN/FAIL per check and exits 0
// only when bootstrapping that plist now would start a node that can run (binary, store, log dir, no derod already on
// the store, ports free, plutil -lint), with the running node's flags compared against the plist's.
package main

import (
	"bytes"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const LABEL = "io.dero.derod"
const DATA_PLACEHOLDER = "DATA_DIR"

// DEFAULT_FLAGS are derod's own defaults made explicit plus the r23c live set without host-specific values: RPC and
// getwork on loopback only, p2p on all interfaces (UDP 11011), fastsync, the low-latency KCP profile.
var DEFAULT_FLAGS = []string{"--rpc-bind=127.0.0.1:10102", "--getwork-bind=127.0.0.1:10100", "--p2p-bind=0.0.0.0:11011",
	"--fastsync", "--lowlatency"}

// EXIT_TIMEOUT_S: see the package comment; r24 measured the ordered shutdown on a mainnet clone.
const EXIT_TIMEOUT_S = 120

type plist_cfg struct {
	Label, Dir, Binary, DataDir, LogDir, Stdout, Integrator string
	ExitTimeout                                             int
	Extra                                                   []string // further derod flags, verbatim
}

// default_cfg roots the binary at the current directory: run it from the repository root (go run ./tools/launchd-derod).
func default_cfg() plist_cfg {
	dir, _ := os.Getwd() // "" (refused by check as not absolute) if the cwd is gone
	return plist_cfg{Label: LABEL, Dir: dir, Binary: filepath.Join(dir, "bin", "derod"), DataDir: DATA_PLACEHOLDER,
		ExitTimeout: EXIT_TIMEOUT_S, Extra: append([]string(nil), DEFAULT_FLAGS...)}
}

// resolved fills the paths that follow --data-dir: --log-dir <data-dir>/logs, stdout/stderr <log-dir>/derod.launchd.out.
func resolved(c plist_cfg) plist_cfg {
	if c.LogDir == "" {
		c.LogDir = filepath.Join(c.DataDir, "logs")
	}
	if c.Stdout == "" {
		c.Stdout = filepath.Join(c.LogDir, "derod.launchd.out")
	}
	return c
}

// KNOWN_FLAGS are the options of derod's docopt usage line (cmd/derod/main.go command_line; a test keeps the two equal).
// docopt refuses an unknown option and derod then exits at once, so KeepAlive would respawn it every 30 s for nothing.
// --help and --version print and exit, so they are refused too.
var KNOWN_FLAGS = []string{"--add-exclusive-node", "--add-priority-node", "--clog-level", "--data-dir", "--debug", "--fastsync",
	"--flog-level", "--getwork-bind", "--help", "--integrator-address", "--log-compress", "--log-dir", "--log-max-age",
	"--log-max-backups", "--log-max-size", "--lowlatency", "--max-peers", "--min-peers", "--node-tag", "--p2p-bind",
	"--p2p-nat", "--prune-history", "--rpc-bind", "--rpc-tx-cache", "--socks-proxy", "--sync-node", "--testnet",
	"--timeisinsync", "--version"}

var exits_at_once = []string{"--help", "--version"}

func known(name string) bool {
	for _, k := range KNOWN_FLAGS {
		if k == name {
			return true
		}
	}
	return false
}

// owned are the flags the generator writes itself; passing them again through --flags would give derod two values.
var owned = []string{"--data-dir", "--log-dir", "--integrator-address"}

func flag_name(a string) string {
	if i := strings.IndexByte(a, '='); i >= 0 {
		return a[:i]
	}
	return a
}

// program_args is derod's argv: binary, --data-dir, --log-dir, the integrator address if given, then --flags.
func program_args(c plist_cfg) []string {
	c = resolved(c)
	a := []string{c.Binary, "--data-dir=" + c.DataDir, "--log-dir=" + c.LogDir}
	if c.Integrator != "" {
		a = append(a, "--integrator-address="+c.Integrator)
	}
	for _, e := range c.Extra {
		if e = strings.TrimSpace(e); e != "" {
			a = append(a, e)
		}
	}
	return a
}

func xml_string(w *bytes.Buffer, s string) {
	w.WriteString("<string>")
	xml.EscapeText(w, []byte(s))
	w.WriteString("</string>")
}

// render writes the plist. KeepAlive restarts derod after any exit (crash, panic, kill, a bad flag's exit 1);
// ThrottleInterval keeps a node that fails at start from respawning more than once per 30 s. ProcessType Standard and
// Nice 0: a node is not background work (Background would throttle its disk and CPU).
func render(c plist_cfg) []byte {
	c = resolved(c)
	var w bytes.Buffer
	w.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	w.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	w.WriteString(`<plist version="1.0">` + "\n<dict>\n")
	kv := func(k string, v func()) { w.WriteString("\t<key>" + k + "</key>"); v(); w.WriteString("\n") }
	kv("Label", func() { xml_string(&w, c.Label) })
	kv("WorkingDirectory", func() { xml_string(&w, c.Dir) })
	kv("ProgramArguments", func() {
		w.WriteString("<array>")
		for _, a := range program_args(c) {
			xml_string(&w, a)
		}
		w.WriteString("</array>")
	})
	kv("RunAtLoad", func() { w.WriteString("<true/>") })
	kv("KeepAlive", func() { w.WriteString("<true/>") })
	kv("ThrottleInterval", func() { w.WriteString("<integer>30</integer>") })
	kv("ExitTimeOut", func() { w.WriteString("<integer>" + strconv.Itoa(c.ExitTimeout) + "</integer>") })
	kv("Nice", func() { w.WriteString("<integer>0</integer>") })
	kv("ProcessType", func() { w.WriteString("<string>Standard</string>") })
	kv("StandardInPath", func() { xml_string(&w, "/dev/null") })
	kv("StandardOutPath", func() { xml_string(&w, c.Stdout) })
	kv("StandardErrorPath", func() { xml_string(&w, c.Stdout) })
	w.WriteString("</dict>\n</plist>\n")
	return w.Bytes()
}

// check refuses a plist that would start a node nobody configured, or one launchd cannot run.
func check(c plist_cfg) error {
	c = resolved(c)
	switch {
	case c.DataDir == "" || c.DataDir == DATA_PLACEHOLDER:
		return fmt.Errorf("--data-dir is the placeholder %s", DATA_PLACEHOLDER)
	case !filepath.IsAbs(c.DataDir):
		return fmt.Errorf("--data-dir must be absolute (derod resolves a relative one against WorkingDirectory)")
	case filepath.Base(filepath.Clean(c.DataDir)) == "mainnet" || filepath.Base(filepath.Clean(c.DataDir)) == "testnet":
		return fmt.Errorf("--data-dir %q ends in mainnet/testnet: pass its PARENT (derod appends the network directory)", c.DataDir)
	case !filepath.IsAbs(c.Dir):
		return fmt.Errorf("--dir must be absolute (launchd has no shell cwd)")
	case !filepath.IsAbs(c.Binary):
		return fmt.Errorf("--binary must be absolute")
	case !filepath.IsAbs(c.LogDir) || !filepath.IsAbs(c.Stdout):
		return fmt.Errorf("--log-dir and --stdout must be absolute")
	case c.Integrator != "" && !strings.HasPrefix(c.Integrator, "dero1") && !strings.HasPrefix(c.Integrator, "deto1"):
		return fmt.Errorf("--integrator-address %q is not a dero1/deto1 address", c.Integrator)
	case c.ExitTimeout < 30:
		return fmt.Errorf("--exit-timeout %d s is shorter than derod's ordered shutdown (SIGKILL would skip the saves)", c.ExitTimeout)
	}
	for _, e := range c.Extra {
		n := flag_name(strings.TrimSpace(e))
		if n == "" {
			continue
		}
		if !known(n) {
			return fmt.Errorf("--flags carries %q, which derod does not know (docopt would refuse it and derod would exit)", n)
		}
		for _, o := range append(append([]string(nil), owned...), exits_at_once...) {
			if n == o {
				return fmt.Errorf("--flags must not carry %s (a generator flag, or derod exits at once)", o)
			}
		}
	}
	return nil
}

func run(args []string, out, errw io.Writer) int {
	c := default_cfg()
	fs := flag.NewFlagSet("launchd-derod", flag.ContinueOnError)
	fs.SetOutput(errw)
	fs.StringVar(&c.DataDir, "data-dir", c.DataDir, "derod --data-dir (absolute; the PARENT of mainnet/)")
	fs.StringVar(&c.LogDir, "log-dir", "", "derod --log-dir (default <data-dir>/logs)")
	fs.StringVar(&c.Stdout, "stdout", "", "stdout/stderr file (default <log-dir>/derod.launchd.out)")
	fs.StringVar(&c.Integrator, "integrator-address", "", "derod --integrator-address (optional, dero1...)")
	fs.StringVar(&c.Dir, "dir", c.Dir, "working directory")
	fs.StringVar(&c.Binary, "binary", c.Binary, "derod path (absolute)")
	fs.StringVar(&c.Label, "label", c.Label, "launchd label")
	fs.IntVar(&c.ExitTimeout, "exit-timeout", c.ExitTimeout, "seconds launchd waits after SIGTERM before SIGKILL")
	extra := fs.String("flags", strings.Join(c.Extra, " "), "further derod flags, space separated")
	strict := fs.Bool("check", true, "refuse a placeholder or unusable configuration")
	pre := fs.Bool("preflight", false, "r25: dry run: check binary, store, log dir, running derod, ports, plutil; print findings, no plist")
	installed := fs.String("installed", default_installed(LABEL), "r25: where the plist will be installed (compared by -preflight)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c.Extra = strings.Fields(*extra)
	if *pre { // r25 perfops (B35): the dry run never prints a plist, so it cannot be redirected into LaunchAgents by mistake
		return pf_report(out, preflight(c, probes_for_run(), *installed))
	}
	if *strict {
		if err := check(c); err != nil {
			fmt.Fprintln(errw, "launchd-derod:", err, "(pass -check=false for a template)")
			return 1
		}
	}
	out.Write(render(c))
	return 0
}

// probes_for_run is real_probes; a test swaps it to run the -preflight flag path against forged probes.
var probes_for_run = real_probes

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
