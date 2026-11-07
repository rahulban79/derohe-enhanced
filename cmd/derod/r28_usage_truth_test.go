package main

// r28 (group p2p-config, config "documented vs used"): derod's help text is the only documentation of its flag
// defaults, and at the R28 base it disagreed with the code in five places: the Usage line said --min-peers=<11>,
// --max-peers=<100> (the Options section and p2p/controller.go: 31, 101), --rpc-bind=<127.0.0.1:9999> (used:
// 127.0.0.1:10102, config.Mainnet.RPC_Default_Port), --getwork-bind=<0.0.0.0:18089> (used 0.0.0.0:10100) and
// --p2p-bind=<0.0.0.0:18089> (used: 0.0.0.0:0 = a random port at every start, so a router forward of a fixed port
// reaches nothing unless --p2p-bind names it: rft §7 B1). docopt takes no default from a placeholder, so nothing
// broke, but an operator reading --help configured the wrong ports. This test pins every value the text states to
// the value the code uses, in both places it is written.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/docopt/docopt-go"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/p2p"
)

// r28_placeholders: option -> placeholder text, from the Usage line ("usage") and the Options section ("options").
func r28_placeholders(text string) (usage, options map[string]string) {
	usage, options = map[string]string{}, map[string]string{}
	rx := regexp.MustCompile(`(--[a-z0-9-]+)=<([^>]*)>`)
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "derod ["):
			for _, m := range rx.FindAllStringSubmatch(t, -1) {
				usage[m[1]] = m[2]
			}
		case strings.HasPrefix(t, "--"):
			if m := rx.FindStringSubmatch(t); m != nil && strings.HasPrefix(t, m[0]) {
				options[m[1]] = m[2]
			}
		}
	}
	return
}

// r28_code_defaults: what derod uses when the flag is absent, read from the code (never from the text).
func r28_code_defaults() map[string]string {
	return map[string]string{
		"--min-peers":       strconv.FormatInt(p2p.Min_Peers, 10),
		"--max-peers":       strconv.FormatInt(p2p.Max_Peers, 10),
		"--rpc-bind":        fmt.Sprintf("127.0.0.1:%d", config.Mainnet.RPC_Default_Port),
		"--getwork-bind":    fmt.Sprintf("0.0.0.0:%d", config.Mainnet.GETWORK_Default_Port),
		"--prune-history":   strconv.Itoa(PRUNE_HISTORY_DEFAULT),
		"--log-max-size":    strconv.Itoa(LOG_MAX_SIZE_MB_DEFAULT),
		"--log-max-backups": strconv.Itoa(LOG_MAX_BACKUPS_DEFAULT),
		"--log-max-age":     "0",
	}
}

func TestR28UsageDefaultsMatchCode(t *testing.T) {
	usage, options := r28_placeholders(command_line)
	if len(usage) < 15 || len(options) < 15 {
		t.Fatalf("parsed %d usage / %d option placeholders: the help text layout changed", len(usage), len(options))
	}
	for flag, want := range r28_code_defaults() {
		if usage[flag] != want {
			t.Errorf("Usage line %s=<%s>, the code uses %s", flag, usage[flag], want)
		}
		if options[flag] != want {
			t.Errorf("Options %s=<%s>, the code uses %s", flag, options[flag], want)
		}
	}
	// every placeholder is written the same way in both places
	for flag, u := range usage {
		if o, ok := options[flag]; ok && o != u {
			t.Errorf("%s: Usage <%s> vs Options <%s>", flag, u, o)
		}
	}
	// --p2p-bind has no fixed default port: the text must say so, and the code must still choose a random one
	if p2p.P2P_BIND_DEFAULT != "0.0.0.0:0" || usage["--p2p-bind"] != "ip:port" ||
		!strings.Contains(command_line, "Not given: a random port at every start") {
		t.Errorf("--p2p-bind: code default %q, placeholder %q; the text must state the random port", p2p.P2P_BIND_DEFAULT, usage["--p2p-bind"])
	}
	// the testnet RPC port is stated too
	if !strings.Contains(command_line, fmt.Sprintf("(testnet: 127.0.0.1:%d)", config.Testnet.RPC_Default_Port)) {
		t.Errorf("--rpc-bind: the testnet port %d is not stated", config.Testnet.RPC_Default_Port)
	}
}

// the corrected text still parses, and the flags the live node runs with are read back unchanged
func TestR28UsageStillParses(t *testing.T) {
	argv := []string{"--p2p-bind=0.0.0.0:11011", "--rpc-bind=127.0.0.1:10102", "--getwork-bind=127.0.0.1:10100", "--min-peers=20", "--lowlatency"}
	args, err := docopt.Parse(command_line, argv, false, "test", false, false)
	if err != nil {
		t.Fatalf("docopt: %v", err)
	}
	for k, v := range map[string]interface{}{"--p2p-bind": "0.0.0.0:11011", "--rpc-bind": "127.0.0.1:10102", "--getwork-bind": "127.0.0.1:10100",
		"--min-peers": "20", "--lowlatency": true, "--max-peers": nil, "--prune-history": nil} {
		if args[k] != v {
			t.Errorf("%s = %v, want %v", k, args[k], v)
		}
	}
}
