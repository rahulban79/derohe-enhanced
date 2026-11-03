package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-logr/logr/funcr"
)

func TestRedactedArgumentsHideSecrets(t *testing.T) {
	args := map[string]interface{}{
		"--password":      "hunter2-pw",
		"--electrum-seed": "seedword1 seedword2",
		"--rpc-login":     "user:rpcsecret",
		"--wallet-file":   "w.db",
		"--offline":       false,
	}
	out := redacted_arguments(args)
	text := fmt.Sprint(out)
	for _, secret := range []string{"hunter2-pw", "seedword1", "rpcsecret"} {
		if strings.Contains(text, secret) {
			t.Fatalf("secret %q reaches the log line: %s", secret, text)
		}
	}
	if out["--wallet-file"] != "w.db" || out["--offline"] != false {
		t.Fatalf("non-secret arguments changed: %v", out)
	}
	if args["--password"] != "hunter2-pw" {
		t.Fatal("redaction modified the live argument map")
	}
}

// SEC-5: the start-up line itself carries no secret (the call site, not only the helper)
func TestStartupArgumentsLineRedacted(t *testing.T) {
	var lines []string
	l := funcr.New(func(prefix, args string) { lines = append(lines, args) }, funcr.Options{Verbosity: 1})
	log_startup_arguments(l, map[string]interface{}{"--password": "hunter2-pw", "--electrum-seed": "seedword1", "--wallet-file": "w.db"})
	text := strings.Join(lines, "\n")
	if len(lines) != 1 || strings.Contains(text, "hunter2-pw") || strings.Contains(text, "seedword1") || !strings.Contains(text, "w.db") {
		t.Fatalf("start-up line: %q", text)
	}
}

// SEC-5: the log is 0600, also when an older build left it 0644
func TestWalletLogIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	p := filepath.Join(t.TempDir(), "dero-wallet-cli.log")
	os.WriteFile(p, []byte("old"), 0644)
	os.Chmod(p, 0644)
	f, err := open_wallet_log(p)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0600 {
		t.Fatalf("log mode %v, want 0600", fi.Mode().Perm())
	}
}
