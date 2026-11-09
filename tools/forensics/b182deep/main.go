// Command b182deep is the R29 B182 streaming decoder (rft §7 B182, user option (ii) 2026-11-08).
//
// Read-only and consensus-neutral like tools/forensics (whose bytes are pinned by the sealed datasets and are
// therefore not edited): it imports the node's own block and transaction packages WITHOUT changing them, never
// opens a datadir, never touches the network and writes only JSON lines to stdout. It takes blobs inline as hex,
// so the fetcher (harness/forensics/b182_deep_r29.py) keeps nothing on disk per block, and it flushes only on a
// {"k":"f"} line, so one batch is one write/read round trip.
//
// Input, one per line: {"k":"b","x":"<block hex>"} | {"k":"t","x":"<tx hex>"} | {"k":"f"}.
// Output, one per b/t line: block {"ok","id","h","tips","txs","rs"}; tx {"ok","id","ty","rs"}; "id" is the node's
// own id for the blob (block: block/block.go GetHash; tx: transaction/transaction.go:195 GetHash), "rs" whether
// the node re-serializes it byte-exact. A decode failure (or a recovered panic) is {"ok":false,"e":...}.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/transaction"
)

type req struct {
	K string `json:"k"`
	X string `json:"x"`
}

type out struct {
	OK   bool     `json:"ok"`
	E    string   `json:"e,omitempty"`
	ID   string   `json:"id,omitempty"`
	H    uint64   `json:"h,omitempty"`
	Tips []string `json:"tips,omitempty"`
	Txs  []string `json:"txs,omitempty"`
	Ty   string   `json:"ty,omitempty"`
	RS   bool     `json:"rs"`
}

func hexes(hs [][32]byte) []string {
	s := make([]string, 0, len(hs))
	for _, h := range hs {
		s = append(s, hex.EncodeToString(h[:]))
	}
	return s
}

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
			RS: bytes.Equal(bl.Serialize(), buf)}
	case "t":
		var tx transaction.Transaction
		if err := tx.Deserialize(buf); err != nil {
			return out{E: err.Error()}
		}
		id := tx.GetHash()
		return out{OK: true, ID: hex.EncodeToString(id[:]), Ty: tx.TransactionType.String(),
			RS: bytes.Equal(tx.Serialize(), buf)}
	}
	return out{E: "unknown kind"}
}

func main() {
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
		if r.K == "f" {
			w.Flush()
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
