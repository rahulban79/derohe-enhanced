// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8

package main

import (
	"os"
	"strings"
	"testing"

	"github.com/deroproject/derohe/config"
	"github.com/go-logr/logr/funcr"
)

// r29 (decisions, B141 (a)): an overridden consensus parameter, or a failed check, stops derod with exit 1 and
// names the variable; the defaults start normally; main() runs the refusal right after the r27 report.
func TestR29RefuseToStartOnConsensusEnvOverride(t *testing.T) {
	savedS, savedL, savedN, savedF := config.Settings, logger, consensus_env_overrides, consensus_env_check_failed
	defer func() {
		config.Settings, logger, consensus_env_overrides, consensus_env_check_failed = savedS, savedL, savedN, savedF
	}()
	var lines []string
	logger = funcr.New(func(prefix, args string) { lines = append(lines, args) }, funcr.Options{})
	def := config.SettingsStruct{MAINNET_BOOTSTRAP_DIFFICULTY: 10000000, MAINNET_MINIMUM_DIFFICULTY: 100000,
		TESTNET_BOOTSTRAP_DIFFICULTY: 10000, TESTNET_MINIMUM_DIFFICULTY: 10000}
	code := -1
	exit := func(c int) { code = c }

	config.Settings, consensus_env_check_failed = def, false
	report_consensus_env_overrides()
	if refuse_on_consensus_env_overrides(exit) || code != -1 {
		t.Fatalf("defaults: refused (exit %d)", code)
	}

	config.Settings = def
	config.Settings.MAINNET_BOOTSTRAP_DIFFICULTY = 1
	lines = nil
	report_consensus_env_overrides()
	if !refuse_on_consensus_env_overrides(exit) || code != 1 {
		t.Fatalf("override: not refused (exit %d)", code)
	}
	last := lines[len(lines)-1]
	if !strings.Contains(last, "refusing to start") || !strings.Contains(last, "MAINNET_BOOTSTRAP_DIFFICULTY") || strings.Contains(last, `"value"`) {
		t.Fatalf("refusal line %q", last)
	}

	code, consensus_env_overrides, consensus_env_check_failed = -1, 0, true
	if !refuse_on_consensus_env_overrides(exit) || code != 1 {
		t.Fatalf("failed check: not refused (exit %d)", code)
	}

	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "unseen\n\trefuse_on_consensus_env_overrides(os.Exit)\n") {
		t.Fatal("main() does not refuse right after the start-up consensus env check")
	}
}
