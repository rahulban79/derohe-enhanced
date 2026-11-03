package main

// r24 getworkops (B35): the derod launchd plist generator.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func good_cfg(t *testing.T) plist_cfg {
	c := default_cfg()
	c.DataDir = "/abs/dero-data"
	return c
}

func TestR24DerodArgsAndPaths(t *testing.T) {
	c := good_cfg(t)
	c.Integrator = "dero1qyexample"
	a := program_args(c)
	want := []string{c.Binary, "--data-dir=/abs/dero-data", "--log-dir=/abs/dero-data/logs", "--integrator-address=dero1qyexample"}
	for i, w := range want {
		if a[i] != w {
			t.Fatalf("argv[%d] %q want %q (%v)", i, a[i], w, a)
		}
	}
	if strings.Join(a[len(want):], " ") != strings.Join(DEFAULT_FLAGS, " ") {
		t.Fatalf("default flags %v", a[len(want):])
	}
	if r := resolved(c); r.Stdout != "/abs/dero-data/logs/derod.launchd.out" {
		t.Fatalf("stdout %q", r.Stdout)
	}
	c.Integrator = ""
	for _, x := range program_args(c) {
		if strings.HasPrefix(x, "--integrator-address") {
			t.Fatal("empty integrator address written")
		}
	}
}

func TestR24DerodCheckRefuses(t *testing.T) {
	bad := map[string]struct {
		f    func(*plist_cfg)
		want string // the refusal must name its reason
	}{
		"placeholder":      {func(c *plist_cfg) { c.DataDir = DATA_PLACEHOLDER }, "placeholder"},
		"relative datadir": {func(c *plist_cfg) { c.DataDir = "dero-data" }, "--data-dir must be absolute"},
		"mainnet datadir":  {func(c *plist_cfg) { c.DataDir = "/abs/dero-data/mainnet/" }, "PARENT"},
		"relative dir":     {func(c *plist_cfg) { c.Dir = "x" }, "--dir must be absolute"},
		"relative binary":  {func(c *plist_cfg) { c.Binary = "./bin/derod" }, "--binary must be absolute"},
		"relative log":     {func(c *plist_cfg) { c.LogDir = "logs" }, "--log-dir and --stdout"},
		"bad integrator":   {func(c *plist_cfg) { c.Integrator = "notanaddress" }, "dero1/deto1"},
		"short exit":       {func(c *plist_cfg) { c.ExitTimeout = 20 }, "--exit-timeout"},
		"owned in flags":   {func(c *plist_cfg) { c.Extra = append(c.Extra, "--data-dir=/other") }, "must not carry --data-dir"},
		"owned bare":       {func(c *plist_cfg) { c.Extra = append(c.Extra, "--log-dir") }, "must not carry --log-dir"},
		"unknown flag":     {func(c *plist_cfg) { c.Extra = append(c.Extra, "--rpc-bindd=127.0.0.1:1") }, "does not know"},
		"exits at once":    {func(c *plist_cfg) { c.Extra = append(c.Extra, "--version") }, "must not carry --version"},
	}
	for name, b := range bad {
		c := good_cfg(t)
		b.f(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), b.want) {
			t.Errorf("%s: %v (want a refusal naming %q)", name, err, b.want)
		}
	}
	c := good_cfg(t)
	c.Integrator = "deto1qyexample"
	c.Extra = append(c.Extra, "--add-exclusive-node=127.0.0.1:11011", "--node-tag=x")
	if err := check(c); err != nil {
		t.Fatal(err)
	}
}

func TestR24DerodRunTemplateAndStrict(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := run(nil, &out, &errb); rc != 1 || out.Len() != 0 {
		t.Fatalf("placeholder plist written (rc %d)", rc)
	}
	out.Reset()
	if rc := run([]string{"-data-dir=/abs/d", "-flags=--fastsync --min-peers=5", "-exit-timeout=300"}, &out, &errb); rc != 0 {
		t.Fatalf("rc %d: %s", rc, errb.String())
	}
	s := out.String()
	for _, want := range []string{"<key>KeepAlive</key><true/>", "<key>ExitTimeOut</key><integer>300</integer>",
		"<key>ProcessType</key><string>Standard</string>", "<key>StandardInPath</key><string>/dev/null</string>",
		"<string>--min-peers=5</string>", "<string>--log-dir=/abs/d/logs</string>",
		"<key>StandardOutPath</key><string>/abs/d/logs/derod.launchd.out</string>"} {
		if !strings.Contains(s, want) {
			t.Fatalf("plist lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "--lowlatency") {
		t.Fatal("-flags did not replace the default flags")
	}
	out.Reset()
	if rc := run([]string{"-check=false"}, &out, &errb); rc != 0 || !strings.Contains(out.String(), DATA_PLACEHOLDER) {
		t.Fatalf("template rc %d", rc)
	}
}

func TestR24DerodRenderEscapes(t *testing.T) {
	c := good_cfg(t)
	c.DataDir = "/tmp/a&b<c"
	if s := string(render(c)); !strings.Contains(s, "/tmp/a&amp;b&lt;c") {
		t.Fatalf("not escaped: %s", s)
	}
}

// KNOWN_FLAGS must be exactly the options of derod's docopt usage line
func TestR24KnownFlagsMatchDerodUsage(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "derod", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	var usage string
	for _, l := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "derod [--help]") {
			usage = l
		}
	}
	if usage == "" {
		t.Fatal("derod usage line not found")
	}
	set := map[string]bool{}
	for _, m := range regexp.MustCompile(`\[(--[a-z0-9-]+)`).FindAllStringSubmatch(usage, -1) {
		set[m[1]] = true
	}
	var got []string
	for k := range set {
		got = append(got, k)
	}
	sort.Strings(got)
	k := append([]string(nil), KNOWN_FLAGS...)
	sort.Strings(k)
	if strings.Join(got, " ") != strings.Join(k, " ") {
		t.Fatalf("KNOWN_FLAGS drifted from cmd/derod/main.go:\n usage %v\n known %v", got, k)
	}
}

// plutil (macOS) must accept the rendered plist
func TestR24DerodPlutilLint(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("plutil is macOS-only")
	}
	if _, err := exec.LookPath("plutil"); err != nil {
		t.Skip("no plutil")
	}
	c := good_cfg(t)
	c.Integrator = "dero1qyexample"
	p := filepath.Join(t.TempDir(), "d.plist")
	if err := os.WriteFile(p, render(c), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("plutil", "-lint", p).CombinedOutput(); err != nil {
		t.Fatalf("plutil: %v %s", err, out)
	}
}
