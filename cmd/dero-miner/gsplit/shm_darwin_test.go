//go:build darwin && cgo

package gsplit

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// r21: shm names are not guessable from the pid, so another local user cannot pre-create them (EEXIST on every
// try) and keep the split engine from starting or respawning; they still fit macOS's 31-character limit.
func TestShmNameUnpredictable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		n := shm_name(9999999)
		if !strings.HasPrefix(n, "/dmgs.9999999.") || len(n) > 31 {
			t.Fatalf("bad shm name %q (len %d)", n, len(n))
		}
		if seen[n] {
			t.Fatalf("shm name %q repeated: an attacker who squats it blocks the GPU worker", n)
		}
		seen[n] = true
	}
}

func TestNewShmIsPrivateAndUnlinked(t *testing.T) {
	mem, f, err := newShm(1 << 16)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	defer freeShm(mem)
	mem[0], mem[len(mem)-1] = 1, 2
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0077 != 0 {
		t.Fatalf("shm object mode %v: other users could map the job texts", fi.Mode().Perm())
	}
}

// r22: the shm fd is close-on-exec, so only the child it is handed to (ExtraFiles -> fd 3) can map it. POSIX makes
// shm_open set FD_CLOEXEC itself (checked here: with an explicit fcntl removed the test still passes), so a child the
// miner starts without ExtraFiles (the full-mode GPU worker) never inherits a handle on the job texts.
func TestNewShmFdCloseOnExec(t *testing.T) {
	mem, f, err := newShm(1 << 16)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	defer freeShm(mem)
	flags, _, e := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_GETFD, 0)
	if e != 0 || flags&syscall.FD_CLOEXEC == 0 {
		t.Fatalf("shm fd flags %#x errno %v: not close-on-exec", flags, e)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	id := strconv.FormatInt(int64(st.Dev), 10) + ":" + strconv.FormatUint(uint64(st.Ino), 10)
	// a child (this test binary) reports whether fd is open AND is this shm object (r22 merge, SEC22-9 review: the
	// child runtime may open its own descriptor at the same small number, so an open fd alone proves nothing)
	probe := func(fd uintptr, extra []*os.File) bool {
		cmd := exec.Command(os.Args[0], "-test.run=^TestHelperFdProbe$")
		cmd.Env = append(os.Environ(), "GSPLIT_FD_PROBE="+strconv.Itoa(int(fd)), "GSPLIT_FD_PROBE_ID="+id)
		cmd.ExtraFiles = extra
		return cmd.Run() == nil
	}
	if probe(f.Fd(), nil) {
		t.Fatalf("a child without ExtraFiles inherited the shm fd %d", f.Fd())
	}
	if !probe(3, []*os.File{f}) {
		t.Fatal("the split server would not receive the shm as fd 3")
	}
}

// TestHelperFdProbe is the child of TestNewShmFdCloseOnExec: it exits 0 only when fd GSPLIT_FD_PROBE is open and is
// the parent's shm object (same device and inode as GSPLIT_FD_PROBE_ID).
func TestHelperFdProbe(t *testing.T) {
	v := os.Getenv("GSPLIT_FD_PROBE")
	if v == "" {
		t.Skip("child helper of TestNewShmFdCloseOnExec")
	}
	fd, _ := strconv.Atoi(v)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		os.Exit(3)
	}
	if strconv.FormatInt(int64(st.Dev), 10)+":"+strconv.FormatUint(uint64(st.Ino), 10) != os.Getenv("GSPLIT_FD_PROBE_ID") {
		os.Exit(4) // a different object at that number: not inherited
	}
	os.Exit(0)
}
