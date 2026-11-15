package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// r31 verify (d6 verifier): a store copy inside ~/dero-data is refused before graviton opens it O_RDWR
func TestR31KeydiffRefusesLiveDatadir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	in := filepath.Join(home, "dero-data", "copy")
	out := filepath.Join(home, "elsewhere", "copy")
	for _, d := range []string{in, out} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "version_root.bin"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("FORENSICS_STORE_COPY_OK", in)
	if _, err := openCopy(in); err == nil || !strings.Contains(err.Error(), "inside the node's datadir") {
		t.Fatalf("a copy inside ~/dero-data was not refused: %v", err)
	}
	if !underLiveDatadir(filepath.Join(home, "dero-data")) || underLiveDatadir(out) {
		t.Fatal("underLiveDatadir misclassifies")
	}
}
