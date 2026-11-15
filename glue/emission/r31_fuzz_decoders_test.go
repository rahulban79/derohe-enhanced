package emission

// R31 dimension 6 (rft §7 B281, detector fuzz-coverage, area cryptosupply): the emission auditor's three decoders had
// no Go fuzz target (DF-fuzz-coverage-8cba7f5597 ParseSeries, -9cbc6a75f7 ParseSeriesLine, -2431f3e5ad DecodeTx).
// The targets below are seeded (the seed corpus runs on every `go test`); `go test -fuzz` explores further.
//
// Properties, each checked independently of the decoder's own code:
//   ParseSeriesLine  never panics; an accepted line ends in 8 hex digits equal to the CRC-32 of the text before the
//                    last space, and the record re-encodes to a line that parses back to the same record
//   ParseSeries      never panics; with no scanner error, intact + dropped == the non-empty lines it scanned
//   DecodeTx         never panics (Transaction.Deserialize panics on an unknown type: DecodeTx must return an
//                    error instead); an accepted body re-serialises to a body that decodes to the same TXID

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func r31SeriesSeeds() [][]byte {
	a := EncodeSeriesLine(SeriesRecord{Kind: "checkpoint", Time: 1700000000, Topo: 7498540, Height: 7498000, Verified: 12, Observed: 5})
	b := EncodeSeriesLine(SeriesRecord{Kind: "alert", Time: 1700000100, V: SeriesV2, Payees: 3, PayeesVerified: 2})
	flipped := append([]byte{}, a...)
	flipped[len(flipped)-3] ^= 0x01 // a checksum digit changed: must be dropped
	torn := a[:len(a)/2]
	return [][]byte{a, b, flipped, torn, append(append([]byte{}, a...), b...), []byte("\n\n"), []byte("{} 00000000\n")}
}

func r31CheckSeriesLine(t *testing.T, l []byte) {
	r, ok := ParseSeriesLine(l)
	if !ok {
		return
	}
	i := bytes.LastIndexByte(l, ' ')
	if i < 0 || len(l)-i-1 != 8 {
		t.Fatalf("accepted a line without an 8-digit checksum field: %q", l)
	}
	want, err := strconv.ParseUint(string(l[i+1:]), 16, 32)
	if err != nil || uint32(want) != crc32.ChecksumIEEE(l[:i]) {
		t.Fatalf("accepted a line whose checksum does not match: %q", l)
	}
	again, ok2 := ParseSeriesLine(bytes.TrimRight(EncodeSeriesLine(r), "\n"))
	if !ok2 || !reflect.DeepEqual(again, r) {
		t.Fatalf("record does not round-trip: %+v vs %+v", r, again)
	}
}

func FuzzR31SeriesDecoders(f *testing.F) {
	for _, s := range r31SeriesSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, l := range bytes.Split(data, []byte("\n")) {
			r31CheckSeriesLine(t, l)
		}
		out, bad, err := ParseSeries(bytes.NewReader(data))
		if err != nil {
			return // a line over the scanner's 1 MiB bound: the count below is undefined
		}
		lines := 0
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			if len(sc.Bytes()) > 0 {
				lines++
			}
		}
		if len(out)+bad != lines {
			t.Fatalf("intact %d + dropped %d != %d non-empty lines", len(out), bad, lines)
		}
	})
}

// the verdicts of the seed lines, as a table (a fuzz body cannot know a random input's verdict)
func TestR31SeriesDecoderVerdicts(t *testing.T) {
	s := r31SeriesSeeds()
	for i, want := range []bool{true, true, false, false} {
		if _, ok := ParseSeriesLine(bytes.TrimRight(s[i], "\n")); ok != want {
			t.Fatalf("seed %d: ok=%v, want %v", i, ok, want)
		}
	}
	// two intact lines, one checksum-flipped line, one blank line: 2 intact, 1 dropped
	out, bad, err := ParseSeries(bytes.NewReader(bytes.Join([][]byte{s[0], s[2], []byte("\n"), s[1]}, nil)))
	if err != nil || len(out) != 2 || bad != 1 {
		t.Fatalf("ParseSeries: intact %d dropped %d err %v, want 2 1 nil", len(out), bad, err)
	}
}

func r31TxSeeds(t testing.TB) [][]byte {
	h, err := os.ReadFile("testdata/hf3_414f79b8.tx.hex")
	if err != nil {
		t.Fatal(err)
	}
	real, err := hex.DecodeString(strings.TrimSpace(string(h)))
	if err != nil {
		t.Fatal(err)
	}
	cut := append([]byte{}, real[:len(real)-7]...)
	unknownType := []byte{1, 0, 0, 99} // version 1, networks 0/0, transaction type 99
	return [][]byte{real, cut, unknownType, {}, {2}, {1, 0, 0, 2}}
}

func FuzzR31DecodeTx(f *testing.F) {
	for _, s := range r31TxSeeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		tx, err := DecodeTx(data) // a panic here fails the target
		if err != nil {
			if tx != nil {
				t.Fatalf("error %v with a non-nil tx", err)
			}
			return
		}
		h := fmt.Sprint(tx.GetHash())
		tx2, err := DecodeTx(tx.Serialize())
		if err != nil {
			t.Fatalf("re-serialised body does not decode: %v", err)
		}
		if fmt.Sprint(tx2.GetHash()) != h {
			t.Fatalf("TXID changed on re-serialisation")
		}
	})
}

func TestR31DecodeTxVerdicts(t *testing.T) {
	s := r31TxSeeds(t)
	if _, err := DecodeTx(s[0]); err != nil {
		t.Fatalf("real HF3 body does not decode: %v", err)
	}
	for i := 1; i < len(s); i++ {
		if tx, err := DecodeTx(s[i]); err == nil || tx != nil {
			t.Fatalf("seed %d decoded (tx %v err %v), want an error", i, tx != nil, err)
		}
	}
}

// r31: a body cut inside its proof decoded with no error before r31 (a short read returns a nil error in the proof
// decoders) and panicked on Serialize; DecodeTx refuses it now. Every cut length of the real body is refused.
func TestR31DecodeTxRefusesTruncatedProof(t *testing.T) {
	real := r31TxSeeds(t)[0]
	for cut := 1; cut <= 96; cut++ {
		if tx, err := DecodeTx(real[:len(real)-cut]); err == nil || tx != nil {
			t.Fatalf("body cut by %d bytes decoded", cut)
		}
	}
}
