// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

// Command launchd prints a launchd agent plist that keeps dero-miner running (r23b payouts).
//
// Why: over the 72 h before 2026-10-30 19:10 the miner was connected 31% of the time; every run ended with a typed
// console "exit" and nothing restarted it (the longest gap 10.5 h). Under launchd the miner has no console, starts
// at login, is restarted if it dies (KeepAlive), and is stopped only by launchctl. --supervised is always passed.
//
//	go run ./tools/launchd --wallet-address=<dero1...> > ~/Library/LaunchAgents/io.dero.miner.plist
//	launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/io.dero.miner.plist   # start (and at every login)
//	launchctl kickstart -k gui/$(id -u)/io.dero.miner                            # restart (new binary)
//	launchctl bootout gui/$(id -u)/io.dero.miner                                 # stop
//
// Without --wallet-address the plist carries the placeholder WALLET_ADDRESS (a template; launchd would start a miner
// that cannot mine, so -check refuses it). The defaults are the live r23 flags.
package main

import (
	"bytes"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const LABEL = "io.dero.miner"
const WALLET_PLACEHOLDER = "WALLET_ADDRESS"

type plist_cfg struct {
	Label, Dir, Binary, Wallet, Daemon, Log string
	Extra                                   []string // further dero-miner flags, verbatim
}

// default_cfg roots the paths at the current directory: run it from the repository root (go run ./tools/launchd).
// A hard-coded checkout path made the plist wrong on any other machine or checkout.
func default_cfg() plist_cfg {
	dir, _ := os.Getwd() // "" (refused by check as not absolute) if the cwd is gone
	return plist_cfg{Label: LABEL, Dir: dir, Binary: filepath.Join(dir, "bin", "dero-miner"), Wallet: WALLET_PLACEHOLDER,
		Daemon: "127.0.0.1:10100", Log: filepath.Join(dir, "bin", "dero-miner.launchd.log"),
		Extra: []string{"--mining-threads=20", "--cpu-max=90", "--gpu=gpu-miner-poc/gpu_hash_sais", "--gpu-mode=split",
			"--gpu-max=96", "--metrics-bind=127.0.0.1:10110"}}
}

// program_args is the miner's argv; --supervised is always present, exactly once.
func program_args(c plist_cfg) []string {
	a := []string{c.Binary, "--wallet-address=" + c.Wallet, "--daemon-rpc-address=" + c.Daemon}
	for _, e := range c.Extra {
		if e = strings.TrimSpace(e); e != "" && e != "--supervised" {
			a = append(a, e)
		}
	}
	return append(a, "--supervised")
}

func xml_string(w *bytes.Buffer, s string) {
	w.WriteString("<string>")
	xml.EscapeText(w, []byte(s))
	w.WriteString("</string>")
}

// render writes the plist. KeepAlive restarts the miner after any exit (crash, panic, kill); ThrottleInterval keeps a
// miner that fails at start from respawning more than once per 30 s. Nice 0, as the live miner runs (r23b merge: the
// draft's Nice 5 was never measured on the contended box). ProcessType Interactive (r30, rft §7 B234): under Standard
// launchd let the CPU-bound miner run only on the 4 E-cores (10.6-13.1k H/s on 3.7-4.6 cores, 2026-11-08 21:15) while
// Interactive gave 96.2-97.4k H/s at 18 cores (21:19-21:21); Standard is the class the R23b generator shipped untested.
func render(c plist_cfg) []byte {
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
	kv("Nice", func() { w.WriteString("<integer>0</integer>") })
	kv("ProcessType", func() { w.WriteString("<string>Interactive</string>") })
	kv("StandardInPath", func() { xml_string(&w, "/dev/null") })
	kv("StandardOutPath", func() { xml_string(&w, c.Log) })
	kv("StandardErrorPath", func() { xml_string(&w, c.Log) })
	w.WriteString("</dict>\n</plist>\n")
	return w.Bytes()
}

// check refuses a plist that would start a miner that cannot earn.
func check(c plist_cfg) error {
	switch {
	case c.Wallet == "" || c.Wallet == WALLET_PLACEHOLDER:
		return fmt.Errorf("--wallet-address is the placeholder %s", WALLET_PLACEHOLDER)
	case !strings.HasPrefix(c.Wallet, "dero1") && !strings.HasPrefix(c.Wallet, "deto1"):
		return fmt.Errorf("--wallet-address %q is not a dero1/deto1 address", c.Wallet)
	case !strings.HasPrefix(c.Dir, "/"):
		return fmt.Errorf("--dir must be absolute (launchd has no shell cwd)")
	case !strings.HasPrefix(c.Binary, "/"):
		return fmt.Errorf("--binary must be absolute (ProgramArguments[0] is not looked up in WorkingDirectory everywhere)")
	}
	return nil
}

func run(args []string, out, errw io.Writer) int {
	c := default_cfg()
	fs := flag.NewFlagSet("launchd", flag.ContinueOnError)
	fs.SetOutput(errw)
	fs.StringVar(&c.Wallet, "wallet-address", c.Wallet, "payout wallet (dero1...)")
	fs.StringVar(&c.Daemon, "daemon-rpc-address", c.Daemon, "derod getwork address")
	fs.StringVar(&c.Dir, "dir", c.Dir, "working directory (the miner's --gpu path is relative to it)")
	fs.StringVar(&c.Binary, "binary", c.Binary, "dero-miner path (absolute)")
	fs.StringVar(&c.Log, "log", c.Log, "stdout/stderr file")
	fs.StringVar(&c.Label, "label", c.Label, "launchd label")
	extra := fs.String("flags", strings.Join(c.Extra, " "), "further dero-miner flags, space separated")
	strict := fs.Bool("check", true, "refuse a placeholder wallet address")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c.Extra = strings.Fields(*extra)
	if *strict {
		if err := check(c); err != nil {
			fmt.Fprintln(errw, "launchd:", err, "(pass -check=false for a template)")
			return 1
		}
	}
	out.Write(render(c))
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
