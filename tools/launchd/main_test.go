package main

import (
	"bytes"
	"encoding/xml"
	"io"
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

// plist_top_keys parses the generated plist and returns the top-level <dict> key -> the text of its value element.
func plist_top_keys(t *testing.T, b []byte) map[string]string {
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = false
	out, depth, key, inkey, want := map[string]string{}, 0, "", false, false
	var text strings.Builder
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("plist does not parse: %v", err)
		}
		switch e := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 3 && e.Name.Local == "key" {
				inkey, key = true, ""
			} else if depth == 3 {
				want = true
				text.Reset()
			}
		case xml.CharData:
			if inkey {
				key += string(e)
			} else if want {
				text.Write(e)
			}
		case xml.EndElement:
			if depth == 3 && inkey {
				inkey = false
			} else if depth == 3 && want {
				out[key], want = strings.TrimSpace(text.String()), false
			}
			depth--
		}
	}
}

// r30 B234: the generated plist must carry ProcessType Interactive. Under Standard launchd clamped the CPU-bound miner
// to the 4 E-cores (10.6-13.1k H/s vs 96.2-97.4k at 18 cores with Interactive, rft §13 2026-11-08). A missing
// ProcessType (launchd's default, Standard-like throttling) fails too.
func TestR30ProcessTypeInteractive(t *testing.T) {
	c := default_cfg()
	c.Wallet = "dero1qyexample"
	keys := plist_top_keys(t, render(c))
	pt, ok := keys["ProcessType"]
	if !ok {
		t.Fatalf("plist has no ProcessType (keys %v)", keys)
	}
	if pt != "Interactive" {
		t.Fatalf("ProcessType %q, want Interactive (Standard clamps the miner to the E-cores, rft B234)", pt)
	}
	if keys["Nice"] != "0" || keys["Label"] == "" {
		t.Fatalf("parser sanity: Nice %q Label %q", keys["Nice"], keys["Label"])
	}
}

// r30 post-close (rft §2.29, D-22, B291): the generated plist runs the R30 quiet-window levers by default and --gsplit=""
// leaves the geometry to the miner's built-in default.
func TestR30bLeverDefaults(t *testing.T) {
	c := default_cfg()
	c.Wallet = "dero1qyexample"
	args := strings.Join(program_args(c), " ")
	for _, want := range []string{"--cpu-max=100", "--gpu-max=100"} {
		if !strings.Contains(args, want) {
			t.Fatalf("default argv %q lacks %s", args, want)
		}
	}
	out := string(render(c))
	if !strings.Contains(out, "<key>EnvironmentVariables</key><dict><key>DERO_GSPLIT</key><string>8192,3,2</string></dict>") {
		t.Fatalf("default plist has no DERO_GSPLIT=8192,3,2 environment:\n%s", out)
	}
	c.GSplit = ""
	if strings.Contains(string(render(c)), "EnvironmentVariables") {
		t.Fatalf("--gsplit=\"\" still writes an EnvironmentVariables block")
	}
	var o, e bytes.Buffer
	if rc := run([]string{"--wallet-address=dero1qyexample", "--gsplit=4096,4,2"}, &o, &e); rc != 0 {
		t.Fatalf("run --gsplit rc %d: %s", rc, e.String())
	}
	if !strings.Contains(o.String(), "<string>4096,4,2</string>") {
		t.Fatalf("--gsplit=4096,4,2 not rendered:\n%s", o.String())
	}
}
