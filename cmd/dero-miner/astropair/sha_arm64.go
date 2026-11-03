//go:build arm64

package astropair

// Go side of sha_arm64.s (generated from the GOROOT block function by gen_sha.go). These wrappers are this
// package's own: they split two messages into the blocks both lanes can process together, and pad the ends.

import (
	"runtime"

	"golang.org/x/sys/cpu"
)

//go:noescape
func block1(h *[8]uint32, p *byte, n int)

//go:noescape
func block2(ha, hb *[8]uint32, pa, pb *byte, n int)

// HasAsm reports whether the SHA-256 instructions are present. x/sys/cpu cannot read the feature registers on
// darwin, where every arm64 CPU (Apple M1 and later) implements them.
var HasAsm = runtime.GOOS == "darwin" || cpu.ARM64.HasSHA2

// run is the remaining blocks of one lane: a run of whole blocks of the message, then the padded tail.
type run struct {
	segs [2][]byte
}

func (r *run) next() []byte {
	for len(r.segs[0]) == 0 && len(r.segs[1]) != 0 {
		r.segs[0], r.segs[1] = r.segs[1], nil
	}
	return r.segs[0]
}

func newRun(msg []byte, buf *[128]byte) run {
	whole := len(msg) &^ 63
	return run{segs: [2][]byte{msg[:whole], tail(buf, msg[whole:], len(msg))}}
}

func sum1(msg []byte) [32]byte {
	if !HasAsm {
		return sumGeneric(msg)
	}
	var buf [128]byte
	h := iv
	r := newRun(msg, &buf)
	for s := r.next(); len(s) != 0; s = r.next() {
		block1(&h, &s[0], len(s)>>6)
		r.segs[0] = nil
	}
	return digest(&h)
}

// sum2 hashes a and b, running block2 while both lanes have blocks left and block1 for the longer one's rest.
func sum2(a, b []byte, ha, hb *[32]byte) {
	if !HasAsm {
		*ha, *hb = sumGeneric(a), sumGeneric(b)
		return
	}
	var bufA, bufB [128]byte
	sa, sb := iv, iv
	ra, rb := newRun(a, &bufA), newRun(b, &bufB)
	for {
		pa, pb := ra.next(), rb.next()
		if len(pa) == 0 || len(pb) == 0 {
			break
		}
		n := len(pa)
		if len(pb) < n {
			n = len(pb)
		}
		block2(&sa, &sb, &pa[0], &pb[0], n>>6)
		ra.segs[0], rb.segs[0] = pa[n:], pb[n:]
	}
	for s := ra.next(); len(s) != 0; s = ra.next() {
		block1(&sa, &s[0], len(s)>>6)
		ra.segs[0] = nil
	}
	for s := rb.next(); len(s) != 0; s = rb.next() {
		block1(&sb, &s[0], len(s)>>6)
		rb.segs[0] = nil
	}
	*ha, *hb = digest(&sa), digest(&sb)
}
