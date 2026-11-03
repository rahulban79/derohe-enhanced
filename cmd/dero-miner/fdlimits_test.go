//go:build !windows
// +build !windows

package main

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// r21 (security): upstream init() pinned RLIMIT_NOFILE to 20 (soft AND hard) on darwin/linux. The live r20 miner held
// 18 descriptors (lsof: log files, getwork socket, metrics listener, GPU server pipes, shm), so two idle connections
// to its /metrics port, from any local program or a web page's websockets, used up the rest: the next getwork redial
// or GPU respawn failed with EMFILE. The limit must never be lowered, and must leave room for real work.
func TestFdLimitLeavesRoom(t *testing.T) {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rl); err != nil {
		t.Fatal(err)
	}
	if rl.Cur < 256 && rl.Cur < rl.Max {
		t.Fatalf("RLIMIT_NOFILE soft %d (hard %d): the miner can hold almost no sockets", rl.Cur, rl.Max)
	}
	var keep []*os.File
	defer func() {
		for _, f := range keep {
			f.Close()
		}
	}()
	for i := 0; i < 64; i++ {
		f, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatalf("descriptor %d: %v", i, err)
		}
		keep = append(keep, f)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0") // and a socket still opens with those held
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
}

func TestRaiseFdLimitNeverLowers(t *testing.T) {
	cases := []struct{ cur, max, want uint64 }{
		{256, unix.RLIM_INFINITY, FD_LIMIT_TARGET},
		{20, 20, 20},
		{256, 4096, 4096},
		{1 << 20, 1 << 20, 1 << 20},
		{100000, 1 << 20, 100000},
	}
	for _, c := range cases {
		if got := fd_limit_target(c.cur, c.max); got != c.want {
			t.Errorf("fd_limit_target(%d, %d) = %d, want %d", c.cur, c.max, got, c.want)
		}
	}
}
