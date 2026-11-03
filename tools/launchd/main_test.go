package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestProgramArgsAlwaysSupervisedOnce(t *testing.T) {
	c := default_cfg()
	c.Extra = append(c.Extra, "--supervised", " ")
	a := program_args(c)
	n := 0
	for _, x := range a {
		if x == "--supervised" {
			n++
		}
	}
	if n != 1 || a[len(a)-1] != "--supervised" {
		t.Fatalf("--supervised %d times in %v", n, a)
	}
	if a[0] != filepath.Join(must_wd(t), "bin", "dero-miner") || a[1] != "--wallet-address="+WALLET_PLACEHOLDER {
		t.Fatalf("argv %v", a)
	}
}

func TestCheckRefusesPlaceholderWallet(t *testing.T) {
	c := default_cfg()
	if check(c) == nil {
		t.Fatal("placeholder wallet accepted")
	}
	c.Wallet = "notanaddress"
	if check(c) == nil {
		t.Fatal("non-dero address accepted")
	}
	c.Wallet = "dero1qyexample"
	if err := check(c); err != nil {
		t.Fatal(err)
	}
	c.Dir = "relative"
	if check(c) == nil {
		t.Fatal("relative working directory accepted")
	}
	c = default_cfg()
	c.Wallet, c.Binary = "dero1qyexample", "./bin/dero-miner"
	if check(c) == nil {
		t.Fatal("relative miner binary accepted (r23b merge)")
	}
}

func TestRunTemplateAndStrict(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := run(nil, &out, &errb); rc != 1 || out.Len() != 0 {
		t.Fatalf("placeholder plist written (rc %d)", rc)
	}
	out.Reset()
	if rc := run([]string{"-check=false", "-flags=--cpu-max=90 --phase-duty=balanced"}, &out, &errb); rc != 0 {
		t.Fatalf("template rc %d: %s", rc, errb.String())
	}
	s := out.String()
	for _, want := range []string{"<key>KeepAlive</key><true/>", "<key>Nice</key><integer>0</integer>", "<string>--phase-duty=balanced</string>",
		"<string>--supervised</string>", "<key>StandardInPath</key><string>/dev/null</string>", WALLET_PLACEHOLDER} {
		if !strings.Contains(s, want) {
			t.Fatalf("plist lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "<string>--gpu-max=96</string>") {
		t.Fatal("-flags did not replace the default flags")
	}
}

func TestRenderEscapes(t *testing.T) {
	c := default_cfg()
	c.Dir = "/tmp/a&b<c"
	if s := string(render(c)); !strings.Contains(s, "/tmp/a&amp;b&lt;c") {
		t.Fatalf("not escaped: %s", s)
	}
}

// plutil (macOS) must accept the rendered plist
func TestPlutilLint(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("plutil is macOS-only")
	}
	if _, err := exec.LookPath("plutil"); err != nil {
		t.Skip("no plutil")
	}
	c := default_cfg()
	c.Wallet = "dero1qyexample"
	p := filepath.Join(t.TempDir(), "m.plist")
	if err := os.WriteFile(p, render(c), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("plutil", "-lint", p).CombinedOutput(); err != nil {
		t.Fatalf("plutil: %v %s", err, out)
	}
}

func must_wd(t *testing.T) string {
	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// the defaults follow the directory the tool runs in, never one checkout's path
func TestDefaultsFollowWorkingDirectory(t *testing.T) {
	d := t.TempDir()
	old := must_wd(t)
	if err := os.Chdir(d); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	wd := must_wd(t) // resolved form (macOS /private/var)
	c := default_cfg()
	if c.Dir != wd || c.Binary != filepath.Join(wd, "bin", "dero-miner") || c.Log != filepath.Join(wd, "bin", "dero-miner.launchd.log") {
		t.Fatalf("defaults %q %q %q do not follow the working directory %q", c.Dir, c.Binary, c.Log, wd)
	}
}
