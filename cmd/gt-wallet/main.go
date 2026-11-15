// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

// gt-wallet: r32 (artifacts/dero-game-theory-rft.md, D-GT-1/D-GT-2). A non-interactive wallet tool for the R32
// game-theory playbooks: create a dedicated wallet (random seed, encrypted file, the seed is never printed),
// print its address, register it on a chain, and serve the standard wallet JSON-RPC for it.
//
//	gt-wallet create   --file F [--testnet] [--if-missing]           (password: env GT_WALLET_PASSWORD)
//	gt-wallet address  --file F [--testnet]
//	gt-wallet register --file F --daemon HOST:PORT [--testnet] [--mainnet-confirm]
//	gt-wallet serve    --file F --daemon HOST:PORT --rpc-bind 127.0.0.1:P [--testnet] [--mainnet-confirm]
//	gt-wallet balance  --file F --daemon HOST:PORT [--testnet] [--mainnet-confirm]
//
// Guards: the wallet file must sit in a mode-0700 directory outside any git work tree; the daemon must be given
// (walletapi would otherwise default to the mainnet RPC 127.0.0.1:10102); a mainnet daemon or a mainnet wallet
// needs --mainnet-confirm (a user action, D-GT-1); the rpc-bind must be loopback. Nothing here is consensus code.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/derohe/walletapi"
	"github.com/deroproject/derohe/walletapi/rpcserver"
	"github.com/go-logr/logr"
)

type opts struct {
	file, daemon, bind     string
	testnet, ifMissing, mc bool
	powThreads             int
	progress               string
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	var o opts
	fs.StringVar(&o.file, "file", "", "wallet file")
	fs.StringVar(&o.daemon, "daemon", "", "daemon RPC host:port")
	fs.StringVar(&o.bind, "rpc-bind", "", "wallet RPC bind (loopback)")
	fs.BoolVar(&o.testnet, "testnet", false, "testnet / simulator-testnet addresses (deto1...)")
	fs.BoolVar(&o.ifMissing, "if-missing", false, "create: keep an existing wallet file (idempotent)")
	fs.BoolVar(&o.mc, "mainnet-confirm", false, "allow a mainnet daemon or wallet (r32 D-GT-4: the playbooks pass it for the NEW gt wallets only)")
	fs.StringVar(&o.progress, "progress", "", "register: write the PoW attempt count here every 10 s (a work counter for stallwatch)")
	fs.IntVar(&o.powThreads, "pow-threads", 0, "register: grind the registration txid to 3 zero bytes with N threads (a non-simulator pool demands it, blockchain/blockchain.go:1255)")
	_ = fs.Parse(os.Args[2:])
	if err := run(cmd, o); err != nil {
		fmt.Fprintf(os.Stderr, "gt-wallet %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gt-wallet create|address|register|serve|balance --file F [--daemon H:P] [--rpc-bind 127.0.0.1:P] [--testnet] [--if-missing] [--mainnet-confirm]")
}

// checkFile refuses a wallet path whose directory is not mode 0700 or that lies inside a git work tree.
func checkFile(f string) error {
	if f == "" {
		return errors.New("--file is required")
	}
	abs, err := filepath.Abs(f)
	if err != nil {
		return err
	}
	dir := filepath.Dir(abs)
	st, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("wallet directory: %w", err)
	}
	if st.Mode().Perm() != 0o700 {
		return fmt.Errorf("wallet directory must be mode 0700 (is %o)", st.Mode().Perm())
	}
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			return errors.New("wallet file inside a git work tree is refused")
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	return nil
}

// checkDaemon refuses a missing daemon address and a mainnet daemon port without --mainnet-confirm.
func checkDaemon(d string, testnet, mc bool) error {
	if d == "" {
		return errors.New("--daemon is required (the wallet default is the mainnet RPC)")
	}
	_, port, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(d, "http://"), "ws://"))
	if err != nil {
		return fmt.Errorf("--daemon: %w", err)
	}
	if port == fmt.Sprintf("%d", config.Mainnet.RPC_Default_Port) && !mc {
		return errors.New("the mainnet RPC port needs --mainnet-confirm (a user action)")
	}
	if !testnet && !mc {
		return errors.New("a mainnet wallet needs --mainnet-confirm (a user action); use --testnet on the private chain")
	}
	return nil
}

func password() string { return os.Getenv("GT_WALLET_PASSWORD") }

func setup(o opts) {
	globals.Arguments = map[string]interface{}{"--testnet": o.testnet, "--debug": false, "--daemon-address": nil,
		"--rpc-bind": nil, "--rpc-login": nil, "--allow-rpc-password-change": false, "--socks-proxy": nil}
	if o.daemon != "" {
		globals.Arguments["--daemon-address"] = o.daemon
	}
	if o.bind != "" {
		globals.Arguments["--rpc-bind"] = o.bind
	}
	globals.InitializeLog(io.Discard, io.Discard)
	globals.Logger = logr.Discard()
	globals.Initialize()
}

func open(o opts) (*walletapi.Wallet_Disk, error) {
	w, err := walletapi.Open_Encrypted_Wallet(o.file, password())
	if err != nil {
		return nil, err
	}
	w.SetNetwork(!o.testnet)
	return w, nil
}

func printJSON(v interface{}) {
	b, _ := json.Marshal(v)
	fmt.Println(string(b))
}

func run(cmd string, o opts) error {
	if err := checkFile(o.file); err != nil {
		return err
	}
	switch cmd {
	case "create":
		setup(o)
		if _, err := os.Stat(o.file); err == nil {
			if !o.ifMissing {
				return errors.New("wallet file exists (use --if-missing to keep it)")
			}
			w, err := open(o)
			if err != nil {
				return err
			}
			defer w.Close_Encrypted_Wallet()
			if err := checkBanned(w.GetAddress().String(), !o.testnet); err != nil {
				return err
			}
			printJSON(map[string]interface{}{"address": w.GetAddress().String(), "created": false})
			return nil
		}
		if password() == "" {
			return errors.New("GT_WALLET_PASSWORD is empty")
		}
		w, err := walletapi.Create_Encrypted_Wallet_Random(o.file, password())
		if err != nil {
			return err
		}
		w.SetNetwork(!o.testnet)
		if err := w.Save_Wallet(); err != nil {
			return err
		}
		_ = os.Chmod(o.file, 0o600)
		addr := w.GetAddress().String()
		w.Close_Encrypted_Wallet()
		if err := checkBanned(addr, !o.testnet); err != nil {
			_ = os.Remove(o.file)
			return err
		}
		printJSON(map[string]interface{}{"address": addr, "created": true})
		return nil
	case "address":
		setup(o)
		w, err := open(o)
		if err != nil {
			return err
		}
		defer w.Close_Encrypted_Wallet()
		if err := checkBanned(w.GetAddress().String(), !o.testnet); err != nil {
			return err
		}
		printJSON(map[string]interface{}{"address": w.GetAddress().String()})
		return nil
	case "register":
		if err := checkDaemon(o.daemon, o.testnet, o.mc); err != nil {
			return err
		}
		setup(o)
		w, err := open(o)
		if err != nil {
			return err
		}
		defer w.Close_Encrypted_Wallet()
		if err := checkBanned(w.GetAddress().String(), !o.testnet); err != nil {
			return err
		}
		// r32 (main-session hardening): never grind for an address the chain already knows
		if isRegistered(o.daemon, w.GetAddress().String()) {
			printJSON(map[string]interface{}{"address": w.GetAddress().String(), "already_registered": true, "checked": "before grinding"})
			return nil
		}
		tx := w.GetRegistrationTX()
		t0, tries := time.Now(), int64(1)
		if o.powThreads > 0 {
			tx, tries = grindRegistration(w, o.powThreads, o.progress)
		}
		// r32 earn-run bug 2: an earlier (killed) run's grind may have sent this registration while we ground; check the
		// chain right before sending, and report the node's 'already registered' as such (the caller counts it a success)
		if isRegistered(o.daemon, w.GetAddress().String()) {
			printJSON(map[string]interface{}{"address": w.GetAddress().String(), "already_registered": true, "checked": "before sending"})
			return nil
		}
		res, err := daemonCall(o.daemon, "DERO.SendRawTransaction", map[string]string{"tx_as_hex": hex.EncodeToString(tx.Serialize())})
		if err != nil {
			return err
		}
		printJSON(map[string]interface{}{"address": w.GetAddress().String(), "txid": tx.GetHash().String(), "daemon": res,
			"pow_tries": tries, "pow_seconds": time.Since(t0).Seconds()})
		return nil
	case "serve", "balance":
		if err := checkDaemon(o.daemon, o.testnet, o.mc); err != nil {
			return err
		}
		if cmd == "serve" {
			host, _, err := net.SplitHostPort(o.bind)
			if err != nil || (host != "localhost" && !net.ParseIP(host).IsLoopback()) {
				return errors.New("--rpc-bind must be a loopback host:port")
			}
		}
		setup(o)
		w, err := open(o)
		if err != nil {
			return err
		}
		if err := checkBanned(w.GetAddress().String(), !o.testnet); err != nil { // serve = every transfer and SC call
			w.Close_Encrypted_Wallet()
			return err
		}
		w.SetDaemonAddress(o.daemon)
		w.SetOnlineMode()
		go walletapi.Keep_Connectivity()
		if cmd == "balance" {
			defer w.Close_Encrypted_Wallet()
			deadline := time.Now().Add(60 * time.Second)
			for time.Now().Before(deadline) {
				if walletapi.Connected && w.IsRegistered() {
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
			_ = w.Sync_Wallet_Memory_With_Daemon()
			m, l := w.Get_Balance()
			printJSON(map[string]interface{}{"address": w.GetAddress().String(), "registered": w.IsRegistered(),
				"mature": m, "locked": l, "height": w.Get_Height()})
			return nil
		}
		srv, err := rpcserver.RPCServer_Start(w, "gt-wallet")
		if err != nil {
			return err
		}
		printJSON(map[string]interface{}{"address": w.GetAddress().String(), "rpc": o.bind, "pid": os.Getpid()})
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		srv.RPCServer_Stop()
		_ = w.Save_Wallet()
		w.Close_Encrypted_Wallet()
		return nil
	}
	usage()
	return fmt.Errorf("unknown command %q", cmd)
}

// grindRegistration searches registration txs until the txid starts with 3 zero bytes (the dero-wallet-cli loop,
// cmd/dero-wallet-cli/easymenu_post_open.go case "4"), with n goroutines; it returns the tx and the attempts made.
func grindRegistration(w *walletapi.Wallet_Disk, n int, progress string) (*transaction.Transaction, int64) {
	found := make(chan *transaction.Transaction, 1)
	var stop, tries int64
	if progress != "" { // liveness = work: the attempt counter, not a heartbeat (stallwatch --counter tries)
		go func() {
			for atomic.LoadInt64(&stop) == 0 {
				_ = os.WriteFile(progress, []byte(fmt.Sprintf("{\"tries\": %d}\n", atomic.LoadInt64(&tries))), 0o600)
				time.Sleep(10 * time.Second)
			}
		}()
	}
	for i := 0; i < n; i++ {
		go func() {
			for atomic.LoadInt64(&stop) == 0 {
				tx := w.GetRegistrationTX()
				atomic.AddInt64(&tries, 1)
				h := tx.GetHash()
				if h[0] == 0 && h[1] == 0 && h[2] == 0 {
					if atomic.CompareAndSwapInt64(&stop, 0, 1) {
						found <- tx
					}
					return
				}
			}
		}()
	}
	tx := <-found
	return tx, atomic.LoadInt64(&tries)
}

// isRegistered: the daemon knows the address (DERO.GetEncryptedBalance answers without error).
func isRegistered(daemon, addr string) bool {
	_, err := daemonCall(daemon, "DERO.GetEncryptedBalance", map[string]interface{}{"address": addr, "topoheight": -1})
	return err == nil
}

// bannedFile is the private sha256 ban list (harness/gametheory/banguard.py, D-GT-2); GT_BANNED_FILE overrides it.
func bannedFile() string {
	if f := os.Getenv("GT_BANNED_FILE"); f != "" {
		return f
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, "derohe-persist", "gt-private", "banned_addresses.json")
}

// checkBanned refuses an address whose sha256 is on the private ban list; the address is never echoed. On mainnet a
// missing or empty list fails closed; on the simulator/testnet it is allowed (the list guards mainnet addresses).
func checkBanned(addr string, mainnet bool) error {
	b, err := os.ReadFile(bannedFile())
	var doc struct {
		Banned []string `json:"banned_sha256"`
	}
	if err == nil {
		err = json.Unmarshal(b, &doc)
	}
	if err != nil || len(doc.Banned) == 0 {
		if mainnet {
			return errors.New("the private ban list is missing or empty: refused on mainnet (fail closed, D-GT-2)")
		}
		return nil
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(addr)))
	h := hex.EncodeToString(sum[:])
	for _, x := range doc.Banned {
		if strings.EqualFold(strings.TrimSpace(x), h) {
			return errors.New("the address is on the private ban list (D-GT-2): refused")
		}
	}
	return nil
}

func daemonCall(daemon, method string, params interface{}) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": "1", "method": method, "params": params})
	url := "http://" + strings.TrimPrefix(daemon, "http://") + "/json_rpc"
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if len(out.Error) > 0 && string(out.Error) != "null" {
		return nil, fmt.Errorf("%s: %s", method, out.Error)
	}
	return out.Result, nil
}
