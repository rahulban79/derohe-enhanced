package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/p2p"
	"github.com/deroproject/derohe/transaction"
)

// planRow is one topo of the replay: our RAW block (content-addressed by SHA-256) and its RAW tx bodies.
type planRow struct {
	Topo   int64       `json:"topo"`
	BLID   string      `json:"blid"`
	SHA256 string      `json:"sha256"`
	Txs    [][2]string `json:"txs"` // [txid, sha256 of the body]
}

type replaySummary struct {
	Kind          string  `json:"kind"`
	From          int64   `json:"from"`
	To            int64   `json:"to"`
	ResumedAt     int64   `json:"resumed_at"`
	Added         int64   `json:"added"`
	Txs           int64   `json:"txs"`
	LastTopo      int64   `json:"last_topo"`
	LastRoot      string  `json:"last_root"`
	ExpectRoot    string  `json:"expect_root,omitempty"`
	EndStateMatch *bool   `json:"end_state_match"`
	Stopped       string  `json:"stopped"`
	FailTopo      int64   `json:"fail_topo,omitempty"`
	FailError     string  `json:"fail_error,omitempty"`
	Seconds       float64 `json:"seconds"`
	Started       string  `json:"started"`
	Finished      string  `json:"finished"`
}

var stopRequested int32

func readPlan(path string) ([]planRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rows []planRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var r planRow
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, err
		}
		if len(rows) > 0 && r.Topo != rows[len(rows)-1].Topo+1 {
			return nil, fmt.Errorf("plan is not contiguous at topo %d", r.Topo)
		}
		rows = append(rows, r)
	}
	return rows, sc.Err()
}

// readBlob reads a content-addressed blob from the first dir holding it and checks its SHA-256.
func readBlob(dirs []string, sha string) ([]byte, error) {
	for _, d := range dirs {
		b, err := os.ReadFile(filepath.Join(d, sha))
		if err != nil {
			continue
		}
		got := sha256.Sum256(b)
		if hex.EncodeToString(got[:]) != sha {
			return nil, fmt.Errorf("blob %s: content SHA-256 mismatch", sha[:16])
		}
		return b, nil
	}
	return nil, fmt.Errorf("blob %s not found", sha[:16])
}

// completeBlock builds the Complete_Block for a plan row, checking id (SHA3-256 = blid) and every TXID.
func completeBlock(r planRow, blockDirs, txDirs []string) (*block.Complete_Block, error) {
	b, err := readBlob(blockDirs, r.SHA256)
	if err != nil {
		return nil, err
	}
	var bl block.Block
	if err := bl.Deserialize(b); err != nil {
		return nil, err
	}
	h := bl.GetHash()
	if hex.EncodeToString(h[:]) != r.BLID {
		return nil, fmt.Errorf("topo %d: block id %x != plan %s", r.Topo, h[:8], r.BLID[:16])
	}
	if len(r.Txs) != len(bl.Tx_hashes) {
		return nil, fmt.Errorf("topo %d: plan has %d txs, block %d", r.Topo, len(r.Txs), len(bl.Tx_hashes))
	}
	cbl := &block.Complete_Block{Bl: &bl}
	for i, t := range r.Txs {
		tb, err := readBlob(txDirs, t[1])
		if err != nil {
			return nil, fmt.Errorf("topo %d tx %s: %v", r.Topo, t[0][:16], err)
		}
		var tx transaction.Transaction
		if err := tx.Deserialize(tb); err != nil {
			return nil, fmt.Errorf("topo %d tx %s: %v", r.Topo, t[0][:16], err)
		}
		th := tx.GetHash()
		if hex.EncodeToString(th[:]) != t[0] || bl.Tx_hashes[i] != th {
			return nil, fmt.Errorf("topo %d tx %d: TXID mismatch", r.Topo, i)
		}
		cbl.Txs = append(cbl.Txs, &tx)
	}
	return cbl, nil
}

func rootAt(chain *blockchain.Blockchain, topo int64) (blid crypto.Hash, version uint64, root crypto.Hash, err error) {
	rec, err := chain.Store.Topo_store.Read(topo)
	if err != nil {
		return
	}
	blid, version = rec.BLOCK_ID, rec.State_Version
	root, err = chain.Load_Merkle_Hash(version)
	return
}

type rootLine struct {
	Topo         int64  `json:"topo"`
	BLID         string `json:"blid"`
	StateVersion uint64 `json:"state_version"`
	Root         string `json:"root"`
}

// lastRootTopo returns the last topo already in the roots file (or -1).
func lastRootTopo(path string) int64 {
	f, err := os.Open(path)
	if err != nil {
		return -1
	}
	defer f.Close()
	last := int64(-1)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var l rootLine
		if json.Unmarshal(sc.Bytes(), &l) == nil {
			last = l.Topo
		}
	}
	return last
}

func replay(chain *blockchain.Blockchain, rows []planRow, to int64, blockDirs, txDirs []string, rootsPath, expectRoot string, sum *replaySummary) error {
	if len(rows) == 0 {
		return fmt.Errorf("empty plan")
	}
	sum.From, sum.To = rows[0].Topo, to
	top := chain.Load_TOPO_HEIGHT()
	sum.ResumedAt = top
	if top < rows[0].Topo-1 || top > to {
		return fmt.Errorf("chain top %d is outside the plan %d..%d", top, rows[0].Topo, to)
	}
	// the chain's top must be the block the plan expects there (seed: the changeset's last block)
	if top >= rows[0].Topo {
		want := rows[top-rows[0].Topo].BLID
		if id, _, _, err := rootAt(chain, top); err != nil || hex.EncodeToString(id[:]) != want {
			return fmt.Errorf("chain top %d is not the plan's block", top)
		}
	}
	rf, err := os.OpenFile(rootsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer rf.Close()
	w := bufio.NewWriter(rf)
	defer w.Flush()
	emit := func(t int64) error {
		id, v, root, err := rootAt(chain, t)
		if err != nil {
			return err
		}
		b, _ := json.Marshal(rootLine{Topo: t, BLID: hex.EncodeToString(id[:]), StateVersion: v, Root: hex.EncodeToString(root[:])})
		w.Write(append(b, '\n'))
		sum.LastTopo, sum.LastRoot = t, hex.EncodeToString(root[:])
		return nil
	}
	// a crash between Add_Complete_Block and the roots line: fill the gap from the store first
	start := lastRootTopo(rootsPath) + 1
	if start < rows[0].Topo-1 {
		start = rows[0].Topo - 1
	}
	for t := start; t <= top; t++ {
		if err := emit(t); err != nil {
			return err
		}
	}
	sum.Stopped = "completed"
	for _, r := range rows {
		if r.Topo <= top {
			continue
		}
		if r.Topo > to {
			break
		}
		if atomic.LoadInt32(&stopRequested) != 0 {
			sum.Stopped = "signal (resumable)"
			break
		}
		cbl, err := completeBlock(r, blockDirs, txDirs)
		if err != nil {
			sum.Stopped, sum.FailTopo, sum.FailError = "input error", r.Topo, err.Error()
			break
		}
		// R26 merge: the sync path's entry point, so a block carrying an HF3 table tx gets the table step first (its
		// proof/nonce bypasses stored, Parity set) exactly as derod's sync applies it; calling chain.Add_Complete_Block
		// directly skipped that step (TestR23bAddCompleteBlockCensus FAILED on the merged tree at this line)
		err, ok := p2p.Add_Complete_Block_HF3(chain, cbl)
		if !ok {
			msg := "rejected"
			if err != nil {
				msg = err.Error()
			}
			sum.Stopped, sum.FailTopo, sum.FailError = "block rejected by the node's own checks", r.Topo, msg
			break
		}
		if id, _, _, err := rootAt(chain, r.Topo); err != nil || hex.EncodeToString(id[:]) != r.BLID {
			sum.Stopped, sum.FailTopo, sum.FailError = "topo order diverged", r.Topo, "the chain placed another block at this topo"
			break
		}
		if err := emit(r.Topo); err != nil {
			return err
		}
		sum.Added++
		sum.Txs += int64(len(cbl.Txs))
		if sum.Added%500 == 0 {
			w.Flush()
			rf.Sync()
			fmt.Fprintf(os.Stderr, "%s replay topo %d added %d\n", time.Now().UTC().Format("15:04:05"), r.Topo, sum.Added)
		}
	}
	if sum.LastTopo == to && expectRoot != "" {
		m := sum.LastRoot == expectRoot
		sum.EndStateMatch = &m
	}
	sum.ExpectRoot = expectRoot
	return nil
}
