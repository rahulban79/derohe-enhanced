package astropair

import (
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
	"github.com/deroproject/derohe/cmd/dero-miner/dsa"
	"github.com/minio/sha256-simd"
)

// Every benchmark op is TWO hashes over sequential nonces, as mineblock produces them.

func benchWork() [48]byte {
	var w [48]byte
	w[0] = 1
	rand.New(rand.NewSource(3)).Read(w[1:43])
	return w
}

// BenchmarkProd2: today's miner path, astrobwtv3.AstroBWTv3 with the descriptor sort hooked in, twice.
func BenchmarkProd2(b *testing.B) {
	astrobwtv3.SuffixSort = dsa.SuffixArray
	defer func() { astrobwtv3.SuffixSort = nil }()
	w := benchWork()
	n := uint32(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n++
		binary.BigEndian.PutUint32(w[43:], n)
		_ = astrobwtv3.AstroBWTv3(w[:])
		n++
		binary.BigEndian.PutUint32(w[43:], n)
		_ = astrobwtv3.AstroBWTv3(w[:])
	}
}

// BenchmarkSingle2: this package's one-lane path (same stage copy and sort, GOROOT block1), twice.
func BenchmarkSingle2(b *testing.B) {
	SuffixSort = dsa.SuffixArray
	s := NewScratch()
	w := benchWork()
	n := uint32(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n++
		binary.BigEndian.PutUint32(w[43:], n)
		_, _ = Hash1(w[:], s)
		n++
		binary.BigEndian.PutUint32(w[43:], n)
		_, _ = Hash1(w[:], s)
	}
}

// BenchmarkPair: Hash2 on two consecutive nonces.
func BenchmarkPair(b *testing.B) {
	SuffixSort = dsa.SuffixArray
	s := NewScratch()
	w, w2 := benchWork(), benchWork()
	n := uint32(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint32(w[43:], n+1)
		binary.BigEndian.PutUint32(w2[43:], n+2)
		n += 2
		_, _, _ = Hash2(w[:], w2[:], s)
	}
}

// SHA alone, on two messages of typical final-SHA size (data_len 68,000 and 67,000 -> 4x bytes).
var shaA, shaB = make([]byte, 68000*4), make([]byte, 67000*4)

func BenchmarkSHA_simd2(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = sha256.Sum256(shaA)
		_ = sha256.Sum256(shaB)
	}
}

func BenchmarkSHA_block1x2(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = sum1(shaA)
		_ = sum1(shaB)
	}
}

func BenchmarkSHA_pair(b *testing.B) {
	var ha, hb [32]byte
	for i := 0; i < b.N; i++ {
		sum2(shaA, shaB, &ha, &hb)
	}
}

// Parallel variants (one goroutine per -test.cpu): the pair needs two scratch sets per thread, so they also show
// whether the larger working set costs more in cache than the SHA pairing gains.
func BenchmarkProd2Par(b *testing.B) {
	astrobwtv3.SuffixSort = dsa.SuffixArray
	defer func() { astrobwtv3.SuffixSort = nil }()
	b.RunParallel(func(pb *testing.PB) {
		w := benchWork()
		w[47] = byte(rand.Int())
		n := uint32(0)
		for pb.Next() {
			n++
			binary.BigEndian.PutUint32(w[43:], n)
			_ = astrobwtv3.AstroBWTv3(w[:])
			n++
			binary.BigEndian.PutUint32(w[43:], n)
			_ = astrobwtv3.AstroBWTv3(w[:])
		}
	})
}

func BenchmarkPairPar(b *testing.B) {
	SuffixSort = dsa.SuffixArray
	b.RunParallel(func(pb *testing.PB) {
		s := NewScratch()
		w := benchWork()
		w[47] = byte(rand.Int())
		w2 := w
		n := uint32(0)
		for pb.Next() {
			binary.BigEndian.PutUint32(w[43:], n+1)
			binary.BigEndian.PutUint32(w2[43:], n+2)
			n += 2
			_, _, _ = Hash2(w[:], w2[:], s)
		}
	})
}
