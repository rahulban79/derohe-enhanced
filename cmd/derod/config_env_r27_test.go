package main

import (
	"os"
	"strings"
	"testing"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/metrics"
	"github.com/go-logr/logr/funcr"
)

// r27 (config): a Settings value that differs from its envDefault is reported; the defaults are not.
func TestR27ConsensusSettingOverrides(t *testing.T) {
	def := config.SettingsStruct{MAINNET_BOOTSTRAP_DIFFICULTY: 10000000, MAINNET_MINIMUM_DIFFICULTY: 100000,
		TESTNET_BOOTSTRAP_DIFFICULTY: 10000, TESTNET_MINIMUM_DIFFICULTY: 10000}
	ov, err := consensus_setting_overrides(def)
	if err != nil || len(ov) != 0 {
		t.Fatalf("defaults reported as overrides: %+v %v", ov, err)
	}
	moved := def
	moved.MAINNET_MINIMUM_DIFFICULTY = 1
	ov, err = consensus_setting_overrides(moved)
	if err != nil || len(ov) != 1 || ov[0].Env != "MAINNET_MINIMUM_DIFFICULTY" || ov[0].Value != 1 || ov[0].Default != 100000 {
		t.Fatalf("a moved difficulty floor: %+v %v", ov, err)
	}
	moved.TESTNET_BOOTSTRAP_DIFFICULTY = 7
	if ov, _ = consensus_setting_overrides(moved); len(ov) != 2 {
		t.Fatalf("two moved fields, %d reported", len(ov))
	}
}

// the gauge is registered at start and reads the count the start-up check found
func TestR27ConsensusEnvGauge(t *testing.T) {
	saved := consensus_env_overrides
	defer func() { consensus_env_overrides = saved }()
	consensus_env_overrides = 3
	var b strings.Builder
	metrics.Set.WritePrometheus(&b)
	if !strings.Contains(b.String(), "\nconfig_consensus_env_overrides 3\n") {
		t.Fatal("config_consensus_env_overrides does not read the start-up count")
	}
}

// r27 verify: the start-up check itself (not only its parts) logs one ERROR per moved field and sets the gauge, and
// main() calls it. Before this test, dropping the call, the gauge assignment or the ERROR loop left every test green.
func TestR27ReportConsensusEnvOverrides(t *testing.T) {
	savedS, savedL, savedN := config.Settings, logger, consensus_env_overrides
	defer func() { config.Settings, logger, consensus_env_overrides = savedS, savedL, savedN }()
	var lines []string
	logger = funcr.New(func(prefix, args string) { lines = append(lines, args) }, funcr.Options{})
	// the envDefaults, written out so the test does not depend on this process's own environment
	def := config.SettingsStruct{MAINNET_BOOTSTRAP_DIFFICULTY: 10000000, MAINNET_MINIMUM_DIFFICULTY: 100000,
		TESTNET_BOOTSTRAP_DIFFICULTY: 10000, TESTNET_MINIMUM_DIFFICULTY: 10000}
	config.Settings = def
	config.Settings.MAINNET_MINIMUM_DIFFICULTY = 1
	report_consensus_env_overrides()
	if consensus_env_overrides != 1 || len(lines) != 1 || !strings.Contains(lines[0], `"env"="MAINNET_MINIMUM_DIFFICULTY"`) {
		t.Fatalf("one moved field: gauge %d, lines %q", consensus_env_overrides, lines)
	}
	config.Settings, lines = def, nil
	report_consensus_env_overrides()
	if consensus_env_overrides != 0 || len(lines) != 0 {
		t.Fatalf("defaults: gauge %d, lines %q", consensus_env_overrides, lines)
	}
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "\n\treport_consensus_env_overrides()") {
		t.Fatal("main() no longer runs the start-up consensus env check")
	}
}
