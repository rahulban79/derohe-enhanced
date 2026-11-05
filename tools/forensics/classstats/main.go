// Command classstats is the R26 forensics-classes helper (rft §0.8.9): STRUCTURAL statistics only.
//
// It is a separate package from tools/forensics on purpose: the v1 dataset (forensics/r25) pins every build input
// of ./tools/forensics (harness/forensics/pins.py decoder_inputs), so a new file there would void v1's replay pins.
//
// It imports the node's transaction and graviton packages WITHOUT changing them, never touches the network and
// writes only JSON lines to stdout. One request per stdin line:
//
//	{"kind":"structstats","path":"<tx blob>"}  per payload: the statement roothash, ring size and the SHA-256 of
//	                                         the compressed randomness commitment D (the digest only, never the
//	                                         point), for the FQ3 census of shared-commitment signatures (R22 C3)
//	{"kind":"census","balances":"<COPY of a graviton balances dir>","version":N}
//	                                         Q-CS1: key counts of the balance tree, the SC meta tree and every SC
//	                                         tree at state version N, plus the Load_Merkle_Hash root at N so the
//	                                         census is bound to a recorded root
//
// Nothing here decrypts, opens or relates an amount: no amount-recovery method exists in this code (rft §0.8.9
// rule 13, G24). graviton opens a store O_RDWR, so "census" refuses any directory that is not named by
// FORENSICS_STORE_COPY_OK (a copy outside the node's datadir).
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/graviton"
)

type request struct {
	Kind     string `json:"kind"`
	Path     string `json:"path,omitempty"`
	Balances string `json:"balances,omitempty"`
	Version  uint64 `json:"version,omitempty"`
}

type payloadStat struct {
	Roothash string `json:"roothash"`
	RingSize uint64 `json:"ring_size"`
	DSHA256  string `json:"d_sha256"`
}

type structOut struct {
	OK       bool          `json:"ok"`
	Kind     string        `json:"kind"`
	Path     string        `json:"path"`
	Error    string        `json:"error,omitempty"`
	TXID     string        `json:"txid,omitempty"`
	TxType   string        `json:"tx_type,omitempty"`
	Payloads []payloadStat `json:"payloads"`
}

// structStats decodes one tx blob and reports per-payload structural digests.
func structStats(path string, buf []byte) (o structOut) {
	o.Kind, o.Path, o.Payloads = "structstats", path, []payloadStat{}
	defer func() {
		if r := recover(); r != nil {
			o = structOut{Kind: "structstats", Path: path, Payloads: []payloadStat{}, Error: fmt.Sprintf("recovered panic: %v", r)}
		}
	}()
	var tx transaction.Transaction
	if err := tx.Deserialize(buf); err != nil {
		o.Error = err.Error()
		return
	}
	// a short body can decode without error (a bytes.Reader short read returns nil; memory dero-crypto-audit-r22), so a
	// body counts only when the node re-serializes it byte-exact
	if !bytes.Equal(tx.Serialize(), buf) {
		o.Error = "body does not re-serialize byte-exact (truncated or non-canonical)"
		return
	}
	h := tx.GetHash()
	o.TXID, o.TxType = hex.EncodeToString(h[:]), tx.TransactionType.String()
	for i := range tx.Payloads {
		st := &tx.Payloads[i].Statement
		ps := payloadStat{Roothash: hex.EncodeToString(st.Roothash[:]), RingSize: st.RingSize}
		if st.D != nil {
			d := sha256.Sum256(st.D.EncodeCompressed())
			ps.DSHA256 = hex.EncodeToString(d[:])
		} else {
			ps.DSHA256 = "missing: no D in the statement"
		}
		o.Payloads = append(o.Payloads, ps)
	}
	o.OK = true
	return
}

type censusOut struct {
	OK              bool          `json:"ok"`
	Kind            string        `json:"kind"`
	Error           string        `json:"error,omitempty"`
	Version         uint64        `json:"version"`
	Root            string        `json:"root,omitempty"`
	BalanceKeys     int64         `json:"balance_tree_keys"`
	BalanceKeyLens  map[int]int64 `json:"balance_key_lengths"`
	SCMetaKeys      int64         `json:"sc_meta_keys"`
	SCTreeKeys      int64         `json:"sc_tree_keys_total"`
	SCTreeKeyLens   map[int]int64 `json:"sc_tree_key_lengths"`
	SCTreesWithKeys int64         `json:"sc_trees_nonempty"`
}

// census counts keys of every tree of one snapshot (the walk of blockchain/prune_history.go:173-258, read-only).
func census(ss *graviton.Snapshot) (o censusOut, err error) {
	o.Kind, o.BalanceKeyLens, o.SCTreeKeyLens = "census", map[int]int64{}, map[int]int64{}
	o.Version = ss.GetVersion()
	bt, err := ss.GetTree(config.BALANCE_TREE)
	if err != nil {
		return
	}
	c := bt.Cursor()
	for k, _, e := c.First(); e == nil; k, _, e = c.Next() {
		o.BalanceKeys++
		o.BalanceKeyLens[len(k)]++
	}
	mt, err := ss.GetTree(config.SC_META)
	if err != nil {
		return
	}
	var scids [][]byte
	mc := mt.Cursor()
	for k, _, e := mc.First(); e == nil; k, _, e = mc.Next() {
		o.SCMetaKeys++
		scids = append(scids, append([]byte(nil), k...))
	}
	for _, id := range scids {
		st, e := ss.GetTree(string(id))
		if e != nil {
			err = e
			return
		}
		n := int64(0)
		sc := st.Cursor()
		for k, _, e := sc.First(); e == nil; k, _, e = sc.Next() {
			n++
			o.SCTreeKeyLens[len(k)]++
		}
		o.SCTreeKeys += n
		if n > 0 {
			o.SCTreesWithKeys++
		}
	}
	bh, err := bt.Hash()
	if err != nil {
		return
	}
	mh, err := mt.Hash()
	if err != nil {
		return
	}
	var root crypto.Hash
	for i := range bh { // Load_Merkle_Hash (blockchain/store.go:297-327): balance tree hash XOR SC meta tree hash
		root[i] = bh[i] ^ mh[i]
	}
	o.Root = hex.EncodeToString(root[:])
	o.OK = true
	return
}

func openCopy(dir string) (*graviton.Store, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(abs, "version_root.bin")); err != nil {
		return nil, fmt.Errorf("not a graviton store (no version_root.bin): %w", err)
	}
	if os.Getenv("FORENSICS_STORE_COPY_OK") != abs {
		return nil, fmt.Errorf("refused: FORENSICS_STORE_COPY_OK must name this exact copy (graviton opens O_RDWR)")
	}
	return graviton.NewDiskStore(abs)
}

func runCensus(dir string, version uint64) (o censusOut) {
	defer func() {
		if r := recover(); r != nil {
			o = censusOut{Kind: "census", Version: version, Error: fmt.Sprintf("recovered panic: %v", r)}
		}
	}()
	s, err := openCopy(dir)
	if err != nil {
		return censusOut{Kind: "census", Version: version, Error: err.Error()}
	}
	ss, err := s.LoadSnapshot(version)
	if err != nil {
		return censusOut{Kind: "census", Version: version, Error: err.Error()}
	}
	o, err = census(ss)
	if err != nil {
		return censusOut{Kind: "census", Version: version, Error: err.Error()}
	}
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
		if err := json.Unmarshal(bytes.TrimSpace(in.Bytes()), &rq); err != nil {
			enc.Encode(map[string]interface{}{"ok": false, "error": "bad request: " + err.Error()})
			continue
		}
		switch rq.Kind {
		case "structstats":
			buf, err := os.ReadFile(rq.Path)
			if err != nil {
				enc.Encode(structOut{Kind: rq.Kind, Path: rq.Path, Payloads: []payloadStat{}, Error: err.Error()})
				continue
			}
			enc.Encode(structStats(rq.Path, buf))
		case "census":
			enc.Encode(runCensus(rq.Balances, rq.Version))
		default:
			enc.Encode(map[string]interface{}{"ok": false, "kind": rq.Kind, "error": "unknown kind"})
		}
	}
}
