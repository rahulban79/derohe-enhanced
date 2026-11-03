//go:build darwin && cgo

package gsplit

/*
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

// gsplit_shm creates a POSIX shared-memory object of size bytes under the given name, unlinked at once (no name
// survives, nothing touches the filesystem or the SSD), sized with ftruncate. Returns the fd or -errno.
static int gsplit_shm(const char *name, long long size) {
	int fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
	if (fd < 0) return -errno;
	shm_unlink(name);
	if (ftruncate(fd, (off_t)size) != 0) { int e = errno; close(fd); return -e; }
	return fd;
}
*/
import "C"

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// shm_name returns a fresh POSIX shm name (r21, security): "/dmgs.<pid>.<64 random bits>". The r18 names were
// "/dmgs.<pid>.<0..63>": the POSIX shm namespace is shared by every user of the machine, so another local account
// that knew (or guessed) the miner's pid could create those 64 names first and make every split start and GPU respawn
// fail with EEXIST, silently dropping the miner back to --gpu-mode=full. 30 characters, under macOS's 31 (PSHMNAMLEN).
func shm_name(pid int) string {
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		binary.LittleEndian.PutUint64(r[:], uint64(time.Now().UnixNano()))
	}
	return fmt.Sprintf("/dmgs.%d.%016x", pid%10000000, binary.LittleEndian.Uint64(r[:]))
}

// newShm returns a MAP_SHARED mapping of a fresh POSIX shm object and the file to hand to the GPU server (ExtraFiles).
func newShm(size int) ([]byte, *os.File, error) {
	fd := -int(syscall.EEXIST)
	for t := 0; t < 64 && fd == -int(syscall.EEXIST); t++ {
		name := C.CString(shm_name(os.Getpid()))
		fd = int(C.gsplit_shm(name, C.longlong(size)))
		C.free(unsafe.Pointer(name))
	}
	if fd < 0 {
		return nil, nil, fmt.Errorf("shm_open: %w", syscall.Errno(-fd))
	}
	mem, err := syscall.Mmap(fd, 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		syscall.Close(fd)
		return nil, nil, fmt.Errorf("mmap shm: %w", err)
	}
	return mem, os.NewFile(uintptr(fd), "gsplit-shm"), nil
}

// freeShm unmaps a mapping made by newShm (a plain Go slice, as the tests use, is left to the GC: Munmap refuses it).
func freeShm(mem []byte) { syscall.Munmap(mem) }
