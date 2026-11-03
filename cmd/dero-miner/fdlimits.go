//go:build !windows
// +build !windows

package main

import "runtime"
import "golang.org/x/sys/unix"

// r21 (security): upstream pinned RLIMIT_NOFILE to UnixMax/OSXMax = 20 for both the soft AND the hard limit (a
// misreading of golang/go#30401, which is about asking darwin for MORE than it allows). The live r20 miner held 18
// descriptors (lsof -p: log files, getwork socket, metrics listener, GPU server pipes, the shm object), so two idle
// TCP connections to its --metrics-bind port, from any local program or a web page's websockets (the Host/Origin
// guard answers 403 only after accept), left it unable to redial getwork or respawn the GPU server (EMFILE); the
// fuzzing engine could not even start ("open /dev/null: too many open files"). The limit is now only ever raised:
// the soft limit goes up to FD_LIMIT_TARGET, capped by the hard limit, and the hard limit is left alone.
const FD_LIMIT_TARGET = 4096

type Limits struct {
	Current uint64
	Max     uint64
}

// fd_limit_target is the soft limit to ask for: never below cur, never above max.
func fd_limit_target(cur, max uint64) uint64 {
	if cur >= FD_LIMIT_TARGET {
		return cur
	}
	if max != unix.RLIM_INFINITY && max < FD_LIMIT_TARGET {
		if max > cur {
			return max
		}
		return cur
	}
	return FD_LIMIT_TARGET
}

func init() {
	switch runtime.GOOS {
	case "darwin", "linux", "netbsd", "openbsd", "freebsd":
		var rl unix.Rlimit
		if unix.Getrlimit(unix.RLIMIT_NOFILE, &rl) == nil {
			if want := fd_limit_target(rl.Cur, rl.Max); want > rl.Cur {
				rl.Cur = want
				unix.Setrlimit(unix.RLIMIT_NOFILE, &rl)
			}
		}
	default: // nothing to do
	}
}

func Get() (*Limits, error) {
	var rLimit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rLimit); err != nil {
		return nil, err
	}
	return &Limits{Current: uint64(rLimit.Cur), Max: uint64(rLimit.Max)}, nil
}

/*
func Set(maxLimit uint64) error {
	rLimit := unix.Rlimit {Max:maxLimit, Cur:maxLimit}
	if runtime.GOOS == "darwin" && rLimit.Cur > OSXMax { //https://github.com/golang/go/issues/30401
		rLimit.Cur = OSXMax
	}
	return unix.Setrlimit(unix.RLIMIT_NOFILE, &rLimit)
}
*/
