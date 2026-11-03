//go:build !arm64

package astropair

// Without the arm64 asm both lanes use sha256-simd one after the other: correct, and no faster than single hashes.

const HasAsm = false

func sum1(msg []byte) [32]byte { return sumGeneric(msg) }

func sum2(a, b []byte, ha, hb *[32]byte) { *ha, *hb = sumGeneric(a), sumGeneric(b) }
