package dvm

// R33 GT-B24 probe (dero-game-theory-rft §7; D-21 non-consensus: tests only, no DVM semantics or gas change).
// Question: can a DVM contract verify a real block's bytes against a block id it stored earlier, and then read the
// block's own fields (header timestamp, every miniblock's KeyHash and Flags)? A block id is sha3.Sum256 of the
// serialized block (block/block.go:57-58) and the DVM has SHA3256, HEXDECODE, SUBSTR, HEX (dvm/dvm_functions.go).
// The blocks are real mainnet blocks (dvm/testdata/r33_mainnet_blocks.json, read with DERO.GetBlock); each test call
// runs under a chosen block id (runAt), because the simulator's RunSC draws a random one (simulator.go:128-129).

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

// a byte -> two lowercase hex digits table for 0..127 (the DVM has no byte-to-number function)
func r33HexTable() string {
	var b strings.Builder
	for i := 0; i < 128; i++ {
		fmt.Fprintf(&b, "%02x", i)
	}
	return b.String()
}

var r33ProofCode = `Function Initialize() Uint64
10 IF EXISTS("owner") == 1 THEN GOTO 40
20 STORE("owner", SIGNER())
30 RETURN 0
40 RETURN 1
End Function

Function Anchor() Uint64
10 STORE("b" + ITOA(BLOCK_HEIGHT()), BLID())
20 RETURN 0
End Function

Function Prove(h Uint64, hx String, ntx Uint64, m Uint64) Uint64
10 DIM b, T as String
20 DIM L, p, q, i, off as Uint64
30 IF ntx > 127 THEN GOTO 900
40 IF m > 10 THEN GOTO 900
50 IF m == 0 THEN GOTO 900
60 LET b = HEXDECODE(hx)
70 IF SHA3256(b) != LOAD("b" + ITOA(h)) THEN GOTO 900
80 LET L = STRLEN(b)
90 IF L <= 32 * ntx + 48 * m + 12 THEN GOTO 900
100 LET T = "` + "%TABLE%" + `"
110 LET p = L - 32 * ntx - 1
120 IF HEX(SUBSTR(b, p, 1)) != SUBSTR(T, 2 * ntx, 2) THEN GOTO 900
130 LET q = p - 48 * m - 1
140 IF HEX(SUBSTR(b, q, 1)) != SUBSTR(T, 2 * m, 2) THEN GOTO 900
150 STORE("t" + ITOA(h), HEX(SUBSTR(b, 2, 8)))
160 LET i = 0
170 IF i >= m THEN GOTO 220
180 LET off = q + 1 + 48 * i
190 STORE("k" + ITOA(h) + "_" + ITOA(i), HEX(SUBSTR(b, off + 16, 16)))
200 STORE("f" + ITOA(h) + "_" + ITOA(i), HEX(SUBSTR(b, off + 32, 4)))
210 LET i = i + 1
215 GOTO 170
220 STORE("ok" + ITOA(h), 1)
230 RETURN 0
900 RETURN 1
End Function
`

type r33Block struct {
	Height  uint64 `json:"height"`
	Blid    string `json:"blid"`
	Txcount uint64 `json:"txcount"`
	Blob    string `json:"blob"`
}

// runAt is RunSC with a chosen block id and height (test-only; simulator.go:127-168 draws a random block id)
func (w *gtWorld) runAt(scid crypto.Hash, blid crypto.Hash, h uint64, entry, signer string, fee uint64, args ...rpc.Argument) (uint64, uint64, error) {
	w.t.Helper()
	a := append(rpc.Arguments{{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
		{Name: rpc.SCID, DataType: rpc.DataHash, Value: scid}, {Name: "entrypoint", DataType: rpc.DataString, Value: entry}}, args...)
	w_sc_tree := &Tree_Wrapper{Tree: w.s.sc_tree, Entries: map[string][]byte{}}
	w_sc_data_tree := Wrapped_tree(w.s.cache, w.s.ss, scid)
	balance, sc, _ := ReadSC(w_sc_tree, w_sc_data_tree, scid)
	var txid crypto.Hash
	copy(txid[:], blid[:])
	txid[0] ^= 0xff
	gc, gs, err := w.s.common(w_sc_tree, w_sc_data_tree, scid, h, h, 0, blid, txid, sc, entry, 1, balance, w.addr[signer], map[crypto.Hash]uint64{}, a, fee, true)
	w.note("proof:"+entry, gc, gs)
	return gc, gs, err
}

func r33LoadBlocks(t *testing.T) []r33Block {
	t.Helper()
	raw, err := os.ReadFile("testdata/r33_mainnet_blocks.json")
	if err != nil {
		t.Fatalf("testdata: %v", err)
	}
	var bs []r33Block
	if err := json.Unmarshal(raw, &bs); err != nil {
		t.Fatalf("testdata: %v", err)
	}
	return bs
}

func TestR33BlockProofVerifiesRealMainnetBlocks(t *testing.T) {
	w := gtNew(t, "owner", "anyone")
	code := strings.Replace(r33ProofCode, "%TABLE%", r33HexTable(), 1)
	scid, _, _, err := w.s.SCInstall(code, map[crypto.Hash]uint64{}, rpc.Arguments{}, w.addr["owner"], 0)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	w.owners[scid] = "proof"
	for _, rb := range r33LoadBlocks(t) {
		var blid crypto.Hash
		bb, _ := hex.DecodeString(rb.Blid)
		copy(blid[:], bb)
		// the Go decoder is the reference: deserialize the same bytes
		raw, _ := hex.DecodeString(rb.Blob)
		var bl block.Block
		if err := bl.Deserialize(raw); err != nil {
			t.Fatalf("height %d: Go deserialize: %v", rb.Height, err)
		}
		if bl.GetHash() != blid {
			t.Fatalf("height %d: Go hash %x != block id %s", rb.Height, bl.GetHash(), rb.Blid)
		}
		if uint64(len(bl.Tx_hashes)) != rb.Txcount {
			t.Fatalf("height %d: tx count %d != %d", rb.Height, len(bl.Tx_hashes), rb.Txcount)
		}
		m := uint64(len(bl.MiniBlocks))
		// 1. the block id is anchored by a call executed IN that block
		if _, _, err := w.runAt(scid, blid, rb.Height, "Anchor", "anyone", 0); err != nil {
			t.Fatalf("height %d: Anchor: %v", rb.Height, err)
		}
		// 2. a later call (another block id) proves the bytes
		var later crypto.Hash
		later[0] = 0x42
		args := []rpc.Argument{gtU("h", rb.Height), gtS("hx", rb.Blob), gtU("ntx", rb.Txcount), gtU("m", m)}
		// 2a. tampered bytes (one flipped bit in a miniblock KeyHash) are refused
		tam := []byte(rb.Blob)
		pos := len(tam) - 2*int(32*rb.Txcount+1) - 2*48 + 2*16
		if tam[pos] == '0' {
			tam[pos] = '1'
		} else {
			tam[pos] = '0'
		}
		targs := []rpc.Argument{gtU("h", rb.Height), gtS("hx", string(tam)), gtU("ntx", rb.Txcount), gtU("m", m)}
		if _, _, err := w.runAt(scid, later, rb.Height+5, "Prove", "anyone", 20000, targs...); err == nil {
			t.Fatalf("height %d: tampered block accepted", rb.Height)
		}
		// 2b. a wrong transaction count is refused (the structure check)
		wargs := []rpc.Argument{gtU("h", rb.Height), gtS("hx", rb.Blob), gtU("ntx", rb.Txcount+1), gtU("m", m)}
		if _, _, err := w.runAt(scid, later, rb.Height+5, "Prove", "anyone", 20000, wargs...); err == nil {
			t.Fatalf("height %d: wrong tx count accepted", rb.Height)
		}
		gc, gs, err := w.runAt(scid, later, rb.Height+5, "Prove", "anyone", 20000, args...)
		if err != nil {
			t.Fatalf("height %d: Prove: %v", rb.Height, err)
		}
		// 3. the fields the contract read equal the Go decoder's
		if got := w.read(scid, fmt.Sprintf("ok%d", rb.Height)); got != uint64(1) {
			t.Fatalf("height %d: ok = %v", rb.Height, got)
		}
		var ts [8]byte
		for i := 0; i < 8; i++ {
			ts[i] = byte(bl.Timestamp >> (56 - 8*uint(i)))
		}
		if got := w.read(scid, fmt.Sprintf("t%d", rb.Height)); got != hex.EncodeToString(ts[:]) {
			t.Fatalf("height %d: timestamp %v != %x", rb.Height, got, ts)
		}
		finals := 0
		for i, mb := range bl.MiniBlocks {
			if got := w.read(scid, fmt.Sprintf("k%d_%d", rb.Height, i)); got != hex.EncodeToString(mb.KeyHash[:16]) {
				t.Fatalf("height %d mb %d: KeyHash %v != %x", rb.Height, i, got, mb.KeyHash[:16])
			}
			var fl [4]byte
			fl[0], fl[1], fl[2], fl[3] = byte(mb.Flags>>24), byte(mb.Flags>>16), byte(mb.Flags>>8), byte(mb.Flags)
			if got := w.read(scid, fmt.Sprintf("f%d_%d", rb.Height, i)); got != hex.EncodeToString(fl[:]) {
				t.Fatalf("height %d mb %d: Flags %v != %x", rb.Height, i, got, fl)
			}
			if mb.Final {
				finals++
				if i != len(bl.MiniBlocks)-1 {
					t.Logf("height %d: the final miniblock is at index %d of %d", rb.Height, i, len(bl.MiniBlocks))
				}
			}
		}
		t.Logf("height %d: %d bytes, %d txs, %d miniblocks (%d final): Prove gas compute %d storage %d (fee cap 20000)",
			rb.Height, len(raw), rb.Txcount, m, finals, gc, gs)
	}
}
