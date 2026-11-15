package main

// r32 (dero-game-theory-rft D-GT-1/D-GT-2): the gt-wallet guards.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestR32GTWalletDaemonGuard(t *testing.T) {
	for _, c := range []struct {
		d           string
		testnet, mc bool
		ok          bool
	}{
		{"", true, false, false},                 // no daemon: walletapi would default to the mainnet RPC
		{"127.0.0.1:47102", true, false, true},   // the private sim chain
		{"127.0.0.1:10102", true, false, false},  // the mainnet RPC port without the user's confirmation
		{"127.0.0.1:10102", false, true, true},   // only with --mainnet-confirm
		{"127.0.0.1:47102", false, false, false}, // a mainnet wallet without confirmation
		{"nonsense", true, false, false},
	} {
		if got := checkDaemon(c.d, c.testnet, c.mc) == nil; got != c.ok {
			t.Errorf("checkDaemon(%q, testnet=%v, mc=%v) ok=%v, want %v", c.d, c.testnet, c.mc, got, c.ok)
		}
	}
}

func TestR32GTWalletFileGuard(t *testing.T) {
	d := t.TempDir()
	open := filepath.Join(d, "open")
	priv := filepath.Join(d, "priv")
	repo := filepath.Join(d, "repo", "w")
	for _, p := range []string{open, priv, repo} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.Chmod(open, 0o755)
	_ = os.Mkdir(filepath.Join(d, "repo", ".git"), 0o700)
	if checkFile(filepath.Join(priv, "a.db")) != nil {
		t.Error("a 0700 directory outside git must be accepted")
	}
	if checkFile(filepath.Join(open, "a.db")) == nil {
		t.Error("a 0755 wallet directory must be refused")
	}
	if checkFile(filepath.Join(repo, "a.db")) == nil {
		t.Error("a wallet inside a git work tree must be refused")
	}
	if checkFile("") == nil {
		t.Error("an empty --file must be refused")
	}
}

// r32 hardening (main session 2026-11-15): the ban list inside gt-wallet (fail closed on mainnet) and the registration
// check against the daemon before any grinding.
func TestR32GTWalletBanGuard(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "banned.json")
	addr := "deto1qy" + strings.Repeat("q", 58) + "fake"
	sum := sha256.Sum256([]byte(addr))
	if err := os.WriteFile(f, []byte(`{"banned_sha256": ["`+hex.EncodeToString(sum[:])+`"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GT_BANNED_FILE", f)
	err := checkBanned(addr, true)
	if err == nil || strings.Contains(err.Error(), addr) {
		t.Fatalf("a banned address must be refused without being echoed: %v", err)
	}
	if checkBanned("deto1other", true) != nil {
		t.Fatal("an unlisted address must pass")
	}
	t.Setenv("GT_BANNED_FILE", filepath.Join(d, "missing.json"))
	if checkBanned("deto1other", true) == nil {
		t.Fatal("mainnet must fail closed without the ban list")
	}
	if checkBanned("deto1other", false) != nil {
		t.Fatal("the simulator may run without the ban list")
	}
}

func TestR32GTWalletIsRegistered(t *testing.T) {
	known := map[string]bool{"deto1known": true}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params struct {
				Address string `json:"address"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if known[req.Params.Address] {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","result":{"status":"OK"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","error":{"code":-32098,"message":"Account Unregistered"}}`))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	if !isRegistered(host, "deto1known") || isRegistered(host, "deto1new") {
		t.Fatal("isRegistered must follow the daemon's answer")
	}
}
