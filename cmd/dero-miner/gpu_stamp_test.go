package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func hexsum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func write_stamp_dir(t *testing.T, src, bin []byte, stampSrc, stampBin string) string {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "srv.swift"), src, 0600)
	os.WriteFile(filepath.Join(dir, "srv"), bin, 0700)
	os.WriteFile(filepath.Join(dir, GPU_STAMP_FILE), []byte("# c\nsrv "+stampSrc+" "+stampBin+"\n"), 0600)
	return filepath.Join(dir, "srv")
}

func TestGPUStampCheck(t *testing.T) {
	src, bin := []byte("let x = 1"), []byte("\xcf\xfa\xed\xfe binary")
	if st, stale := gpu_stamp_check(write_stamp_dir(t, src, bin, hexsum(src), hexsum(bin))); stale || !strings.HasPrefix(st, "ok") {
		t.Fatal("matching stamp:", st, stale)
	}
	if st, stale := gpu_stamp_check(write_stamp_dir(t, []byte("let x = 2"), bin, hexsum(src), hexsum(bin))); !stale || !strings.Contains(st, "changed after") {
		t.Fatal("source drift not detected:", st)
	}
	if st, stale := gpu_stamp_check(write_stamp_dir(t, src, []byte("old build"), hexsum(src), hexsum(bin))); !stale || !strings.Contains(st, "not the recorded build") {
		t.Fatal("binary drift not detected:", st)
	}
	// unstamped / no entry: reported, never "stale"
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "srv"), bin, 0700)
	if _, stale := gpu_stamp_check(filepath.Join(dir, "srv")); stale {
		t.Fatal("no stamp file must not be stale")
	}
	os.WriteFile(filepath.Join(dir, GPU_STAMP_FILE), []byte("other "+hexsum(src)+" "+hexsum(bin)+"\n"), 0600)
	if st, stale := gpu_stamp_check(filepath.Join(dir, "srv")); stale || !strings.Contains(st, "no stamp entry") {
		t.Fatal(st, stale)
	}
}

func TestParseGPUStamps(t *testing.T) {
	h := strings.Repeat("a", 64)
	m := parse_gpu_stamps(strings.NewReader("# x\nfoo " + h + " " + h + " # tail\nbad line\nshort ab cd\n"))
	if len(m) != 1 || m["foo"].src != h {
		t.Fatal(m)
	}
}

// The repo's stamps match the tracked sources and binaries. A round that edits a gpu-miner-poc/*.swift without
// running gpu-miner-poc/build.sh fails here, before the patch ships with a stale binary.
func TestRepoGPUStampsMatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a CRLF checkout changes the .swift bytes; the GPU servers are macOS-only")
	}
	dir := filepath.Join("..", "..", "gpu-miner-poc")
	data, err := os.ReadFile(filepath.Join(dir, GPU_STAMP_FILE))
	if err != nil {
		t.Skip("no BUILD_STAMPS in this checkout")
	}
	stamps := parse_gpu_stamps(bytes.NewReader(data))
	for _, need := range []string{"gpu_hash_sais", "gpu_split_server"} { // the two the miner runs
		if _, ok := stamps[need]; !ok {
			t.Errorf("BUILD_STAMPS has no entry for %s", need)
		}
	}
	for name := range stamps {
		st, stale := gpu_stamp_check(filepath.Join(dir, name))
		switch {
		case strings.Contains(st, ".swift changed after"): // the source moved without build.sh: the author's mistake
			t.Errorf("%s: %s", name, st)
		case stale: // the stamp and source came with a text patch, the binary could not: an install step, not a defect
			t.Logf("%s: %s (dero-miner warns at GPU start until it is rebuilt)", name, st)
		case !strings.HasPrefix(st, "ok"):
			t.Errorf("%s: %s", name, st)
		}
	}
}

// Every tracked executable is a stamped GPU server or a known stray waiting for `git rm --cached`; a known stray
// must be git-ignored so it cannot come back once untracked.
var known_stray_binaries = map[string]string{
	// r20 F9: an r19 dero-miner build committed in e1bae2c; nothing reads it (the live miner runs ./bin/dero-miner).
	// A text patch cannot delete a binary (git apply: "cannot apply binary patch ... without full index line"), so
	// it is untracked with `git rm --cached dero-miner` after the patch; then this entry can go.
	"dero-miner": "r20 F9",
}

func is_executable_image(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	switch {
	case bytes.Equal(b[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}), bytes.Equal(b[:4], []byte{0xce, 0xfa, 0xed, 0xfe}), // Mach-O LE
		bytes.Equal(b[:4], []byte{0xca, 0xfe, 0xba, 0xbe}), // Mach-O fat
		bytes.Equal(b[:4], []byte{0x7f, 'E', 'L', 'F'}):
		return true
	case b[0] == 'M' && b[1] == 'Z' && len(b) >= 64: // PE: MZ + a PE header offset
		return true
	}
	return false
}

func TestIsExecutableImage(t *testing.T) {
	if !is_executable_image([]byte{0xcf, 0xfa, 0xed, 0xfe, 0}) || !is_executable_image([]byte("\x7fELF....")) ||
		is_executable_image([]byte{0x8c, 0x76, 0xaf, 0x6a}) || is_executable_image([]byte("#!/bin/sh\n")) {
		t.Fatal("magic detection")
	}
}

func TestTrackedBinariesDeclared(t *testing.T) {
	root := filepath.Join("..", "..")
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Skip("not a git checkout:", err)
	}
	stampData, _ := os.ReadFile(filepath.Join(root, "gpu-miner-poc", GPU_STAMP_FILE))
	stamps := parse_gpu_stamps(bytes.NewReader(stampData))
	for _, f := range strings.Split(string(out), "\x00") {
		if f == "" || strings.HasPrefix(f, "vendor/") {
			continue
		}
		fh, err := os.Open(filepath.Join(root, f))
		if err != nil {
			continue // deleted in the work tree
		}
		head := make([]byte, 64)
		n, _ := fh.Read(head)
		fh.Close()
		if !is_executable_image(head[:n]) {
			continue
		}
		if filepath.Dir(f) == "gpu-miner-poc" {
			if _, ok := stamps[filepath.Base(f)]; ok {
				continue
			}
		}
		if _, ok := known_stray_binaries[f]; ok {
			t.Logf("known stray binary still tracked: %s (git rm --cached %s)", f, f)
			continue
		}
		t.Errorf("tracked executable %s is neither stamped in gpu-miner-poc/BUILD_STAMPS nor a known stray", f)
	}
	for f := range known_stray_binaries {
		if exec.Command("git", "-C", root, "check-ignore", "-q", "--no-index", f).Run() != nil {
			t.Errorf("known stray %s is not git-ignored: once untracked, `git add -A` would commit it again", f)
		}
	}
}
