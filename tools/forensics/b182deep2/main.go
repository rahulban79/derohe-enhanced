// Command b182deep2 is the R30 genesis..tip chain-census decoder (rft §7 B208, b182deep v2; §8 "R30 audit plan" S1-S3).
//
// It keeps the R29 b182deep contract (read-only, consensus-neutral: the node's block, transaction and blockchain
// packages are imported WITHOUT changing them; no datadir, no network; JSON lines on stdin/stdout, flushed on
// {"k":"f"}) and adds, per verified blob, PUBLIC PLAINTEXT ONLY (rft rule 13: counts and hashes, never an address):
//
//	block {"ok","id","h","tips","txs","rs", "mj","mn" (Major/Minor_Version), "mt" (Miner_TX type), "mv" (Miner_TX
//	       Value), "mb" (len MiniBlocks), "rw" (CalcBlockReward(h), blockchain/transaction_execute.go:60)}
//	tx    {"ok","id","ty","rs", "fee" (tx.Fees(), transaction.go:226), "burn" (sum of payload BurnValue), "val"
//	       (tx.Value: premine, SC gas), "np" (payloads), "rk" (registration: sha256 of the 33-byte key, never the key),
//	       "gk" (that key is the genesis premine key), "cp","cs" (points / scalars checked), "cf" (failed check ->
//	       count), the byte walk of harness/forensics/audit2.py:84-147 ported (constants from bn256, not literals)}
//	{"k":"g"}         -> {"ok","id","x"}: Generate_Genesis_Block() (blockchain/genesis.go:27) id + serialization hex
//	{"k":"s","h":N}   -> {"ok","sup"}: CalcSupply(N) (blockchain/supply.go:5)
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/transaction"
)

type req struct {
	K string `json:"k"`
	X string `json:"x"`
	H uint64 `json:"h"`
}

type out struct {
	OK   bool           `json:"ok"`
	E    string         `json:"e,omitempty"`
	ID   string         `json:"id,omitempty"`
	H    uint64         `json:"h,omitempty"`
	Tips []string       `json:"tips,omitempty"`
	Txs  []string       `json:"txs,omitempty"`
	Ty   string         `json:"ty,omitempty"`
	RS   bool           `json:"rs"`
	MJ   uint64         `json:"mj,omitempty"`
	MN   uint64         `json:"mn,omitempty"`
	MT   string         `json:"mt,omitempty"`
	MV   uint64         `json:"mv"`
	MB   int            `json:"mb"`
	RW   uint64         `json:"rw"`
	Fee  uint64         `json:"fee"`
	Burn uint64         `json:"burn"`
	Val  uint64         `json:"val"`
	NP   int            `json:"np"`
	RK   string         `json:"rk,omitempty"`
	GK   bool           `json:"gk,omitempty"`
	CP   int            `json:"cp"`
	CS   int            `json:"cs"`
	CF   map[string]int `json:"cf,omitempty"`
	X    string         `json:"x,omitempty"`
	Sup  uint64         `json:"sup,omitempty"`
}

var genesisKeySha [32]byte

func hexes(hs [][32]byte) []string {
	s := make([]string, 0, len(hs))
	for _, h := range hs {
		s = append(s, hex.EncodeToString(h[:]))
	}
	return s
}

// ------------------------------------------------------------------ canonicality byte walk (audit2.py:84-147 port)
var errShort = errors.New("short")

type walker struct {
	b []byte
	i int
}

func (w *walker) uv() uint64 {
	v, n := binary.Uvarint(w.b[w.i:])
	if n <= 0 {
		panic(errShort)
	}
	w.i += n
	return v
}
func (w *walker) take(n int) []byte {
	if n < 0 || w.i+n > len(w.b) {
		panic(errShort)
	}
	s := w.b[w.i : w.i+n]
	w.i += n
	return s
}

// pointProblem: "" for a canonical compressed G1 encoding (33 bytes, x < P, flag 0/1, x^3+3 a square), else the name
// of the failed check (audit2.py point_problem).
func pointProblem(b []byte) string {
	if len(b) != 33 {
		return "point-length"
	}
	x := new(big.Int).SetBytes(b[:32])
	if b[32] != 0 && b[32] != 1 {
		return "point-flag-not-0-or-1"
	}
	if x.Cmp(bn256.P) >= 0 {
		return "point-x-not-reduced"
	}
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x).Add(rhs, big.NewInt(3)).Mod(rhs, bn256.P)
	// Euler's criterion via the Jacobi symbol (P is prime, so Jacobi == Legendre): the same verdict as
	// rhs^((P-1)/2) == 1, at a fraction of a modular exponentiation (r30 slow-class 6: ~2 ms/tx of canonicality)
	if rhs.Sign() != 0 && big.Jacobi(rhs, bn256.P) != 1 {
		return "point-not-on-curve"
	}
	return ""
}

func scalarProblem(b []byte) string {
	if len(b) != 32 {
		return "scalar-length"
	}
	if new(big.Int).SetBytes(b).Cmp(bn256.Order) >= 0 {
		return "scalar-not-reduced"
	}
	return ""
}

type run struct {
	kind  byte
	count int
}

// proofLayout: (kind, count) runs of the proof wire for ring 2^power (audit2.py proof_layout).
func proofLayout(L int) []run {
	return []run{{'P', 4}, {'P', 8 * L}, {'P', 1}, {'S', 2 * L}, {'S', 1}, {'P', 2}, {'S', 2}, {'S', 5}, {'S', 2}, {'P', 14}}
}

type span struct {
	power, ring, bpp int
	ptrsDistinct     bool
	points           []int
}

// canon walks one transaction blob: statement points (D, C[ring]) and every proof point and scalar.
func canon(b []byte, ty transaction.TransactionType) (cp, cs int, cf map[string]int, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("walk: %v", r)
		}
	}()
	cf = map[string]int{}
	if ty != transaction.BURN_TX && ty != transaction.NORMAL && ty != transaction.SC_TX {
		return 0, 0, nil, nil
	}
	w := &walker{b: b}
	w.uv()
	w.uv()
	w.uv()
	typ := w.uv()
	if typ == uint64(transaction.PREMINE) || typ == uint64(transaction.SC_TX) {
		w.uv()
	}
	w.uv() // height
	w.take(32)
	n := int(w.uv())
	var spans []span
	for k := 0; k < n; k++ {
		w.uv()          // burn
		w.take(32)      // scid
		w.take(1)       // rpc type
		w.take(1 + 144) // payload (transaction.go:62 PAYLOAD_LIMIT)
		power := int(w.take(1)[0])
		ring := 1 << power
		bpp := int(w.take(1)[0])
		w.uv() // fees
		sp := span{power: power, ring: ring, bpp: bpp}
		sp.points = append(sp.points, w.i)
		w.take(33)
		ptrs := w.take(ring * bpp)
		seen := map[string]bool{}
		for j := 0; j < ring && bpp > 0; j++ {
			seen[string(ptrs[j*bpp:(j+1)*bpp])] = true
		}
		sp.ptrsDistinct = bpp > 0 && len(seen) == ring
		for j := 0; j < ring; j++ {
			sp.points = append(sp.points, w.i+33*j)
		}
		w.take(33*ring + 32)
		spans = append(spans, sp)
	}
	if typ == uint64(transaction.SC_TX) {
		w.take(int(w.uv()))
	}
	for _, sp := range spans {
		if sp.power < 1 || sp.power > 7 {
			cf["ring-power-range"]++
		}
		if !sp.ptrsDistinct {
			cf["ring-pointers-not-distinct"]++
		}
		for _, off := range sp.points {
			cp++
			if q := pointProblem(b[off : off+33]); q != "" {
				cf["statement-"+q]++
			}
		}
		for _, r := range proofLayout(sp.power) {
			for j := 0; j < r.count; j++ {
				if r.kind == 'P' {
					cp++
					if q := pointProblem(w.take(33)); q != "" {
						cf["proof-"+q]++
					}
				} else {
					cs++
					if q := scalarProblem(w.take(32)); q != "" {
						cf["proof-"+q]++
					}
				}
			}
		}
	}
	if w.i != len(b) {
		cf["proof-wire-length"] = 1
	}
	if len(cf) == 0 {
		cf = nil
	}
	return cp, cs, cf, nil
}

// ------------------------------------------------------------------ decode
func decode(k string, buf []byte) (o out) {
	defer func() {
		if r := recover(); r != nil {
			o = out{E: fmt.Sprintf("recovered panic: %v", r)}
		}
	}()
	switch k {
	case "b":
		var bl block.Block
		if err := bl.Deserialize(buf); err != nil {
			return out{E: err.Error()}
		}
		id := bl.GetHash()
		tips := make([][32]byte, 0, len(bl.Tips))
		for _, t := range bl.Tips {
			tips = append(tips, [32]byte(t))
		}
		txs := make([][32]byte, 0, len(bl.Tx_hashes))
		for _, t := range bl.Tx_hashes {
			txs = append(txs, [32]byte(t))
		}
		return out{OK: true, ID: hex.EncodeToString(id[:]), H: bl.Height, Tips: hexes(tips), Txs: hexes(txs),
			RS: bytes.Equal(bl.Serialize(), buf), MJ: bl.Major_Version, MN: bl.Minor_Version,
			MT: bl.Miner_TX.TransactionType.String(), MV: bl.Miner_TX.Value, MB: len(bl.MiniBlocks),
			RW: blockchain.CalcBlockReward(bl.Height)}
	case "t":
		var tx transaction.Transaction
		if err := tx.Deserialize(buf); err != nil {
			return out{E: err.Error()}
		}
		id := tx.GetHash()
		o := out{OK: true, ID: hex.EncodeToString(id[:]), Ty: tx.TransactionType.String(),
			RS: bytes.Equal(tx.Serialize(), buf), Fee: tx.Fees(), Val: tx.Value, NP: len(tx.Payloads)}
		for i := range tx.Payloads {
			o.Burn += tx.Payloads[i].BurnValue
		}
		if tx.IsRegistration() {
			d := sha256.Sum256(tx.MinerAddress[:])
			o.RK = hex.EncodeToString(d[:])
			o.GK = d == genesisKeySha
		}
		cp, cs, cf, err := canon(buf, tx.TransactionType)
		if err != nil {
			return out{E: err.Error()}
		}
		o.CP, o.CS, o.CF = cp, cs, cf
		return o
	}
	return out{E: "unknown kind"}
}

func main() {
	gb := blockchain.Generate_Genesis_Block()
	genesisKeySha = sha256.Sum256(gb.Miner_TX.MinerAddress[:])
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 64<<20)
	w := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer w.Flush()
	enc := json.NewEncoder(w)
	for in.Scan() {
		var r req
		if err := json.Unmarshal(in.Bytes(), &r); err != nil {
			enc.Encode(out{E: "bad request: " + err.Error()})
			continue
		}
		switch r.K {
		case "f":
			w.Flush()
			continue
		case "g":
			id := gb.GetHash()
			enc.Encode(out{OK: true, ID: hex.EncodeToString(id[:]), X: hex.EncodeToString(gb.Serialize()), RS: true})
			continue
		case "s":
			enc.Encode(out{OK: true, Sup: blockchain.CalcSupply(r.H)})
			continue
		}
		buf, err := hex.DecodeString(r.X)
		if err != nil {
			enc.Encode(out{E: "bad hex: " + err.Error()})
			continue
		}
		enc.Encode(decode(r.K, buf))
	}
}
