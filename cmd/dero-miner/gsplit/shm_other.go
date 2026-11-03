//go:build !(darwin && cgo)

package gsplit

import (
	"errors"
	"os"
)

func newShm(size int) ([]byte, *os.File, error) {
	return nil, nil, errors.New("gpu split mode needs darwin with cgo (Metal)")
}

// freeShm: nothing was mapped on this platform (the Windows build of the miner failed on syscall.Munmap before).
func freeShm(mem []byte) {}
