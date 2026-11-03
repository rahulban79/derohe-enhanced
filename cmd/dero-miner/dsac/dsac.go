//go:build darwin && arm64 && cgo

// Package dsac is the native C descriptor suffix sort (descriptor.c, third-party MIT code, see its header), compiled with
// -O3 -mcpu=apple-m1 and wrapped so that ANY non-zero return code declines (false): the caller (astrobwtv3) then runs
// its built-in SA-IS. Only the descriptor entry is bound; reference SA-IS is not vendored. Miner-only: derod never imports it.
package dsac

/*
#cgo CFLAGS: -O3 -mcpu=apple-m1 -Wno-c23-extensions
#include <stdint.h>
#include "descriptor.h"
*/
import "C"

import "unsafe"

// Available reports whether the native sort is compiled into this binary.
const Available = true

// maxLen is the largest text the C packing is proven for: its static assert covers 256*384 bytes, which is
// astrobwtv3.MAX_LENGTH+1. Longer texts are declined rather than trusted.
const maxLen = 256 * 384

// SuffixArray builds the suffix array of text into sa[:len(text)] and reports success. On false, sa is garbage and
// the caller must sort another way.
func SuffixArray(text []byte, sa []int32) bool {
	n := len(text)
	if n <= 0 || n > maxLen || len(sa) < n {
		return false
	}
	rc := C.dsa_descriptor_suffix_array((*C.uint8_t)(unsafe.Pointer(&text[0])), (*C.int32_t)(unsafe.Pointer(&sa[0])), C.int32_t(n))
	return rc == 0
}

// Release frees the calling OS thread's C scratch (optional).
func Release() { C.dsa_descriptor_release() }
