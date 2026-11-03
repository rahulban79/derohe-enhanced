package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWritePrivateFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.block")
	if err := os.WriteFile(p, []byte("old"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := write_private_file(p, []byte("data")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "data" {
		t.Fatalf("content %q", b)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0600 {
			t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
		}
		victim := filepath.Join(dir, "victim")
		os.WriteFile(victim, []byte("keep"), 0600)
		link := filepath.Join(dir, "planted.block")
		if err := os.Symlink(victim, link); err != nil {
			t.Fatal(err)
		}
		if err := write_private_file(link, []byte("evil")); err == nil {
			t.Fatal("wrote through a planted symlink")
		}
		if b, _ := os.ReadFile(victim); string(b) != "keep" {
			t.Fatal("symlink target overwritten")
		}
	}
}

// r20: the graph and dump console commands open their output through create_private_file: no symlink, mode 0600,
// an existing world-readable file is tightened.
func TestCreatePrivateFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("modes and symlinks")
	}
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	os.WriteFile(victim, []byte("keep"), 0600)
	link := filepath.Join(dir, "graph.dot")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if f, err := create_private_file(link); err == nil {
		f.Close()
		t.Fatal("opened a planted symlink")
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatal("symlink target truncated")
	}
	p := filepath.Join(dir, "old.dot")
	os.WriteFile(p, []byte("old"), 0644)
	f, err := create_private_file(p)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0600 || fi.Size() != 0 {
		t.Fatalf("mode %v size %d, want 0600 and truncated", fi.Mode().Perm(), fi.Size())
	}
}
