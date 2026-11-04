package rpc

// r25 (verify-rpcrobust, B41 completion): the fate resolver goroutine (start_fate_resolver, an 18 s ticker that lives
// for the whole test binary once any test records a submission) reads the package-global chain under chain_swap_mu.
// A test that assigns chain directly instead of through swap_global_chain races it under -race. The rpcrobust patch
// converted 2 such swaps; r23b_rpcws_test.go still had 2 more. This test keeps every test file on the helper.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var unlocked_chain_assign = regexp.MustCompile(`(^|[^A-Za-z0-9_.])chain\s*(,\s*\w+\s*)*=[^=]`)

// unlocked_chain_swaps returns file:line for each direct assignment to the global chain in test source, outside the
// body of swap_global_chain itself. Pure on (name, text).
func unlocked_chain_swaps(name, text string) (out []string) {
	in_helper := false
	for i, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "func swap_global_chain(") {
			in_helper = true
		} else if in_helper && line == "}" {
			in_helper = false
			continue
		}
		if in_helper || strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		if unlocked_chain_assign.MatchString(line) {
			out = append(out, name+":"+itoa(i+1))
		}
	}
	return
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func TestR25NoUnlockedGlobalChainSwap(t *testing.T) {
	// negative controls: the detector sees both upstream spellings and ignores locals, comparisons and the helper
	if got := unlocked_chain_swaps("x", "\tchain = c\n\tdefer func() { chain, s = old, o }()\n"); len(got) != 2 {
		t.Fatalf("control: detector missed a swap: %v", got)
	}
	if got := unlocked_chain_swaps("x", "\tchain := c\n\tif chain == nil {\n\told_chain = c\nfunc swap_global_chain(c int) func() {\n\tchain = c\n}\n"); len(got) != 0 {
		t.Fatalf("control: detector flagged a non-swap: %v", got)
	}
	files, err := filepath.Glob("*_test.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no test files: %v", err)
	}
	for _, f := range files {
		if f == "r25_verify_chainswap_test.go" { // its controls are strings, not swaps
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if bad := unlocked_chain_swaps(f, string(b)); len(bad) > 0 {
			t.Errorf("assign the global chain through swap_global_chain (chain_swap_mu), not directly: %v", bad)
		}
	}
}
