// Command forensics is the R25 read-only, consensus-neutral decoder (rft §0.8.8).
//
// It imports the node's own block and transaction packages WITHOUT changing them and decodes blobs given as
// files. It never opens a datadir, never touches the network and never writes anything except its JSON lines
// to stdout. Input: one request per stdin line, {"kind":"block"|"tx","path":"<file>"}. Output: one JSON object
// per line with the decoded public fields plus the node's own id for the blob (block: sha3-256 of Serialize,
// block/block.go:57; tx: Keccak256 of SerializeCoreStatement, transaction/transaction.go:195) and whether the
// node re-serializes the blob byte-exact. A decode failure (including a recovered panic, e.g. an unknown tx
// type in Deserialize) is reported as {"ok":false,"error":...}; it is never guessed around.
//
// R25 forensics-extract adds (extract.go; the "block"/"tx" outputs above are unchanged so the acquire stage
// re-derives byte-exact): "block2"/"tx2" (extended public fields, the node's CalcBlockReward/CalcSupply, the TXID
// core bytes for an independent hash), "roots" (balance-tree merkle roots of given state versions) and "verify"
// (the current verifier's expansion + Proof.Verify of a tx against a state version). The last two open a graviton
// store, which graviton opens O_RDWR: they must only ever be pointed at a COPY (an APFS clone in the scratchpad),
// never at a node's datadir; extract.py enforces that.
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

type request struct {
	Kind     string   `json:"kind"`
	Path     string   `json:"path"`
	Balances string   `json:"balances,omitempty"` // roots/verify: a COPY of a graviton balances dir
	Version  uint64   `json:"version,omitempty"`  // verify: the state version of the tx's reference block
	Versions []uint64 `json:"versions,omitempty"` // roots
}

type blockOut struct {
	OK            bool     `json:"ok"`
	Kind          string   `json:"kind"`
	Path          string   `json:"path"`
	Error         string   `json:"error,omitempty"`
	ID            string   `json:"id,omitempty"`
	Reserialize   bool     `json:"reserialize_equal"`
	Major         uint64   `json:"major_version"`
	Minor         uint64   `json:"minor_version"`
	Height        uint64   `json:"height"`
	TimestampMs   uint64   `json:"timestamp_ms"`
	Tips          []string `json:"tips"`
	MiniBlocks    int      `json:"miniblocks"`
	TxHashes      []string `json:"tx_hashes"`
	ProofNonZero  bool     `json:"proof_field_nonzero"`
	MinerTxType   string   `json:"miner_tx_type"`
	MinerTxHeight uint64   `json:"miner_tx_height"`
}

type payloadOut struct {
	SCIDZero  bool   `json:"scid_zero"`
	BurnValue uint64 `json:"burn_value"`
	Fees      uint64 `json:"fees"`
	RingSize  uint64 `json:"ring_size"`
	RPCType   byte   `json:"rpc_type"`
}

type txOut struct {
	OK          bool         `json:"ok"`
	Kind        string       `json:"kind"`
	Path        string       `json:"path"`
	Error       string       `json:"error,omitempty"`
	TXID        string       `json:"txid,omitempty"`
	Reserialize bool         `json:"reserialize_equal"`
	Version     uint64       `json:"version"`
	TxType      string       `json:"tx_type"`
	Value       uint64       `json:"value"`
	RefHeight   uint64       `json:"ref_height"`
	RefBLID     string       `json:"ref_blid"`
	Fees        uint64       `json:"fees"`
	Payloads    []payloadOut `json:"payloads"`
	HasSCData   bool         `json:"has_scdata"`
}

func decodeBlock(path string, buf []byte) (o blockOut) {
	o.Kind, o.Path = "block", path
	defer func() {
		if r := recover(); r != nil {
			o = blockOut{Kind: "block", Path: path, Error: fmt.Sprintf("recovered panic: %v", r)}
		}
	}()
	var bl block.Block
	if err := bl.Deserialize(buf); err != nil {
		o.Error = err.Error()
		return
	}
	h := bl.GetHash()
	o.ID = hex.EncodeToString(h[:])
	o.Reserialize = bytes.Equal(bl.Serialize(), buf)
	o.Major, o.Minor, o.Height, o.TimestampMs = bl.Major_Version, bl.Minor_Version, bl.Height, bl.Timestamp
	o.Tips = []string{}
	for _, t := range bl.Tips {
		o.Tips = append(o.Tips, hex.EncodeToString(t[:]))
	}
	o.TxHashes = []string{}
	for _, t := range bl.Tx_hashes {
		o.TxHashes = append(o.TxHashes, hex.EncodeToString(t[:]))
	}
	o.MiniBlocks = len(bl.MiniBlocks)
	var zero [32]byte
	o.ProofNonZero = bl.Proof != zero
	o.MinerTxType = bl.Miner_TX.TransactionType.String()
	o.MinerTxHeight = bl.Miner_TX.Height
	o.OK = true
	return
}

func decodeTx(path string, buf []byte) (o txOut) {
	o.Kind, o.Path = "tx", path
	defer func() {
		if r := recover(); r != nil {
			o = txOut{Kind: "tx", Path: path, Error: fmt.Sprintf("recovered panic: %v", r)}
		}
	}()
	var tx transaction.Transaction
	if err := tx.Deserialize(buf); err != nil {
		o.Error = err.Error()
		return
	}
	h := tx.GetHash()
	o.TXID = hex.EncodeToString(h[:])
	o.Reserialize = bytes.Equal(tx.Serialize(), buf)
	o.Version, o.TxType, o.Value = tx.Version, tx.TransactionType.String(), tx.Value
	o.RefHeight, o.RefBLID = tx.Height, hex.EncodeToString(tx.BLID[:])
	o.Fees = tx.Fees()
	o.HasSCData = len(tx.SCDATA) > 0
	var zero [32]byte
	o.Payloads = []payloadOut{}
	for i := range tx.Payloads {
		p := &tx.Payloads[i]
		o.Payloads = append(o.Payloads, payloadOut{SCIDZero: [32]byte(p.SCID) == zero, BurnValue: p.BurnValue,
			Fees: p.Statement.Fees, RingSize: p.Statement.RingSize, RPCType: p.RPCType})
	}
	o.OK = true
	return
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	enc := json.NewEncoder(out)
	for in.Scan() {
		var rq request
		if err := json.Unmarshal(in.Bytes(), &rq); err != nil {
			enc.Encode(map[string]interface{}{"ok": false, "error": "bad request: " + err.Error()})
			continue
		}
		if rq.Kind == "roots" {
			enc.Encode(stateRoots(rq.Balances, rq.Versions))
			continue
		}
		if rq.Kind == "verify" {
			enc.Encode(verifyTx(rq.Path, rq.Balances, rq.Version))
			continue
		}
		buf, err := os.ReadFile(rq.Path)
		if err != nil {
			enc.Encode(map[string]interface{}{"ok": false, "kind": rq.Kind, "path": rq.Path, "error": err.Error()})
			continue
		}
		switch rq.Kind {
		case "block":
			enc.Encode(decodeBlock(rq.Path, buf))
		case "tx":
			enc.Encode(decodeTx(rq.Path, buf))
		case "block2":
			enc.Encode(decodeBlock2(rq.Path, buf))
		case "tx2":
			enc.Encode(decodeTx2(rq.Path, buf))
		default:
			enc.Encode(map[string]interface{}{"ok": false, "path": rq.Path, "error": "unknown kind"})
		}
	}
}
