package rpc

// r23c (p2psec) cost A/B: compiles on the base (cd1be86) and on the patched tree.

import (
	"fmt"
	"testing"
	"time"

	"github.com/creachadair/jrpc2/code"
)

// one remote key, known method, time advancing 1 ms per call (the bucket never runs dry): the normal remote path
func BenchmarkR23cAdmitKnownOneKey(b *testing.B) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tb.admit("198.51.100.7", "DERO.GetInfo", false, now.Add(time.Duration(i)*time.Millisecond))
	}
}

// 256 keys of one /24 round-robin (an explorer farm / NAT pool), 4 ms per call per key
func BenchmarkR23cAdmitKnown256Keys(b *testing.B) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	keys := make([]string, 256)
	for i := range keys {
		keys[i] = fmt.Sprintf("198.51.100.%d", i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tb.admit(keys[i&255], "DERO.GetInfo", false, now.Add(time.Duration(i)*time.Microsecond*16))
	}
}

// the reply-scoring path of a successful call and of an ordinary handler error
func BenchmarkR23cObserveMix(b *testing.B) {
	tb := new_abuse_table(ABUSE_DEFAULT_RATE, ABUSE_DEFAULT_BURST, ABUSE_MAX_ENTRIES)
	now := time.Unix(1700000000, 0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := code.Code(0)
		if i&15 == 0 {
			c = code.Code(-32098)
		}
		tb.observe("198.51.100.7", c, now.Add(time.Duration(i)*time.Millisecond))
	}
}
