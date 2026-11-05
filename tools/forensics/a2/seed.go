package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/deroproject/graviton"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/p2p"
	"github.com/deroproject/derohe/transaction"
)

type topoRoot struct {
	Topo         int64  `json:"topo"`
	BLID         string `json:"blid"`
	StateVersion uint64 `json:"state_version"`
	Root         string `json:"root"`
	Txs          int    `json:"txs"`
	ChangeKeys   int    `json:"change_keys"`
}

type seedSummary struct {
	Kind            string     `json:"kind"`
	Class           string     `json:"class"`
	Source          string     `json:"source"`
	Method          []string   `json:"method"`
	TreeTopo        int64      `json:"tree_topo"`
	ChangesetTopos  [2]int64   `json:"changeset_topos"`
	KeyCountEst     int64      `json:"balance_keycount_estimate"`
	SCKeyCountEst   int64      `json:"sc_meta_keycount_estimate"`
	BalanceChunks   int64      `json:"balance_chunks"`
	BalancePathBits int        `json:"balance_path_bits"`
	BalanceKeys     int64      `json:"balance_keys"`
	SCMetaChunks    int64      `json:"sc_meta_chunks"`
	SCMetaKeys      int64      `json:"sc_meta_keys"`
	SCTrees         int64      `json:"sc_trees"`
	SCDataKeys      int64      `json:"sc_data_keys"`
	TipsLinked      bool       `json:"changeset_tips_linked"`
	ExpectBLID      string     `json:"expect_blid_at_topo"`
	ExpectBLIDOK    bool       `json:"expect_blid_ok"`
	Roots           []topoRoot `json:"roots"`
	Requests        int64      `json:"requests"`
	Failures        int64      `json:"failed_requests"`
	Started         string     `json:"started"`
	Finished        string     `json:"finished"`
	Seconds         float64    `json:"seconds"`
	Error           string     `json:"error,omitempty"`
}

// fetchState: see the package comment. topo is the LAST topo of the changeset (the state before the window);
// the trees are fetched at topo-depth+1, as bootstrap_chain fetches them at TopoHeights[0].
func fetchState(pc *peerClient, chain *blockchain.Blockchain, topo, depth int64, expectBLID string, sum *seedSummary) error {
	if depth < 11 || depth > 50 {
		return fmt.Errorf("--depth must be in 11..50 (TX_VALIDITY_HEIGHT 11 needs that many referable blocks; the peer serves at most 50)")
	}
	var request p2p.ChangeList
	var response p2p.Changes
	for t := topo - depth + 1; t <= topo; t++ {
		request.TopoHeights = append(request.TopoHeights, t)
	}
	sum.TreeTopo = request.TopoHeights[0]
	sum.ChangesetTopos = [2]int64{request.TopoHeights[0], topo}
	if err := pc.call("Peer.ChangeSet", request, &response, 120*time.Second); err != nil {
		return fmt.Errorf("ChangeSet: %v", err)
	}
	if len(response.CBlocks) != len(request.TopoHeights) {
		return fmt.Errorf("ChangeSet returned %d blocks for %d topos", len(response.CBlocks), len(request.TopoHeights))
	}
	sum.KeyCountEst, sum.SCKeyCountEst = response.KeyCount, response.SCKeyCount

	// decode and link the changeset blocks BEFORE writing anything: block i+1's tips must name block i, and the
	// last block must be our own RAW block at `topo` (checks i-ii against forensics/r25 headerchain)
	bls := make([]block.Block, len(response.CBlocks))
	for i := range response.CBlocks {
		if err := bls[i].Deserialize(response.CBlocks[i].Block); err != nil {
			return fmt.Errorf("changeset block %d: %v", i, err)
		}
	}
	sum.TipsLinked = true
	for i := 1; i < len(bls); i++ {
		prev := bls[i-1].GetHash()
		if len(bls[i].Tips) != 1 || bls[i].Tips[0] != prev {
			sum.TipsLinked = false
		}
	}
	last := bls[len(bls)-1].GetHash()
	sum.ExpectBLID = expectBLID
	sum.ExpectBLIDOK = hex.EncodeToString(last[:]) == expectBLID
	if !sum.TipsLinked || !sum.ExpectBLIDOK {
		return fmt.Errorf("changeset does not link to our block at topo %d (tips linked %v, last id ok %v)", topo,
			sum.TipsLinked, sum.ExpectBLIDOK)
	}

	commitVersion := uint64(0)
	// ---- balance tree (chain_bootstrap.go:89-145), committed every 32 chunks
	{
		chunks, pathLength := chunksFor(response.KeyCount)
		sum.BalanceChunks, sum.BalancePathBits = chunks, pathLength
		var bt *graviton.Tree
		pending := 0
		for i := int64(0); i < chunks; i++ {
			if bt == nil {
				ss, err := chain.Store.Balance_store.LoadSnapshot(0)
				if err != nil {
					return err
				}
				if bt, err = ss.GetTree(config.BALANCE_TREE); err != nil {
					return err
				}
			}
			req := p2p.Request_Tree_Section_Struct{Topo: request.TopoHeights[0], TreeName: []byte(config.BALANCE_TREE),
				Section: sectionPath(i), SectionLength: uint64(pathLength)}
			var resp p2p.Response_Tree_Section_Struct
			if err := callRetry(pc, "Peer.TreeSection", req, &resp); err != nil {
				return fmt.Errorf("balance chunk %d: %v", i, err)
			}
			if err := sectionCheck(sectionPath(i), uint64(pathLength), &resp); err != nil {
				return fmt.Errorf("balance chunk %d: %v", i, err)
			}
			for j := range resp.Keys {
				if err := bt.Put(resp.Keys[j], resp.Values[j]); err != nil {
					return err
				}
			}
			sum.BalanceKeys += int64(len(resp.Keys))
			pending++
			if pending == 32 || i == chunks-1 {
				v, err := graviton.Commit(bt)
				if err != nil {
					return err
				}
				commitVersion, bt, pending = v, nil, 0
				progress("balance", i+1, chunks, sum.BalanceKeys)
			}
		}
	}
	// ---- SC meta tree and every SC's own tree (chain_bootstrap.go:147-237)
	{
		chunks, pathLength := chunksFor(response.SCKeyCount)
		sum.SCMetaChunks = chunks
		for i := int64(0); i < chunks; i++ {
			section := sectionPath(i)
			req := p2p.Request_Tree_Section_Struct{Topo: request.TopoHeights[0], TreeName: []byte(config.SC_META),
				Section: section, SectionLength: uint64(pathLength)}
			var resp p2p.Response_Tree_Section_Struct
			if err := callRetry(pc, "Peer.TreeSection", req, &resp); err != nil {
				return fmt.Errorf("sc meta chunk %d: %v", i, err)
			}
			if err := sectionCheck(section, uint64(pathLength), &resp); err != nil {
				return fmt.Errorf("sc meta chunk %d: %v", i, err)
			}
			ss, err := chain.Store.Balance_store.LoadSnapshot(0)
			if err != nil {
				return err
			}
			scTree, err := ss.GetTree(config.SC_META)
			if err != nil {
				return err
			}
			var changed []*graviton.Tree
			for j := range resp.Keys {
				if err := scTree.Put(resp.Keys[j], resp.Values[j]); err != nil {
					return err
				}
				dataTree, err := ss.GetTree(string(resp.Keys[j]))
				if err != nil {
					return err
				}
				sreq := p2p.Request_Tree_Section_Struct{Topo: request.TopoHeights[0], TreeName: resp.Keys[j], Section: section}
				var sresp p2p.Response_Tree_Section_Struct
				if err := callRetry(pc, "Peer.TreeSection", sreq, &sresp); err != nil {
					return fmt.Errorf("sc tree %x: %v", resp.Keys[j], err)
				}
				if sresp.KeyCount < 4096 {
					if err := sectionCheck(section, 0, &sresp); err != nil {
						return fmt.Errorf("sc tree %x: %v", resp.Keys[j], err)
					}
					for k := range sresp.Keys {
						dataTree.Put(sresp.Keys[k], sresp.Values[k])
					}
					sum.SCDataKeys += int64(len(sresp.Keys))
				} else {
					scChunks, scPath := chunksFor(sresp.KeyCount)
					for k := int64(0); k < scChunks; k++ {
						creq := p2p.Request_Tree_Section_Struct{Topo: request.TopoHeights[0], TreeName: resp.Keys[j],
							Section: sectionPath(k), SectionLength: uint64(scPath)}
						var cresp p2p.Response_Tree_Section_Struct
						if err := callRetry(pc, "Peer.TreeSection", creq, &cresp); err != nil {
							return fmt.Errorf("sc tree %x chunk %d: %v", resp.Keys[j], k, err)
						}
						if err := sectionCheck(sectionPath(k), uint64(scPath), &cresp); err != nil {
							return fmt.Errorf("sc tree %x chunk %d: %v", resp.Keys[j], k, err)
						}
						for m := range cresp.Keys {
							dataTree.Put(cresp.Keys[m], cresp.Values[m])
						}
						sum.SCDataKeys += int64(len(cresp.Keys))
					}
				}
				changed = append(changed, dataTree)
				sum.SCTrees++
			}
			sum.SCMetaKeys += int64(len(resp.Keys))
			changed = append(changed, scTree)
			v, err := graviton.Commit(changed...)
			if err != nil {
				return err
			}
			commitVersion = v
			progress("sc_meta", i+1, chunks, sum.SCMetaKeys)
		}
	}

	// ---- topo records 0..TopoHeights[0] at the fetched version, no block (write_bootstrap_topo's loop)
	var zero [32]byte
	for i := int64(0); i <= request.TopoHeights[0]; i++ {
		if err := chain.Store.Topo_store.Write(i, zero, commitVersion, 0); err != nil {
			return err
		}
	}
	chain.Store.Topo_store.Sync()

	// ---- the changeset blocks (chain_bootstrap.go:244-334): block 0 at the fetched version, then the peer's
	// per-block changes (EXT) for the remaining depth-1 blocks
	for i := range response.CBlocks {
		bl := &bls[i]
		var txs []*transaction.Transaction
		for j := range response.CBlocks[i].Txs {
			var tx transaction.Transaction
			if err := tx.Deserialize(response.CBlocks[i].Txs[j]); err != nil {
				return fmt.Errorf("changeset block %d tx %d: %v", i, j, err)
			}
			if j >= len(bl.Tx_hashes) || bl.Tx_hashes[j] != tx.GetHash() {
				return fmt.Errorf("changeset block %d tx %d does not match the block's tx list", i, j)
			}
			txs = append(txs, &tx)
		}
		if len(txs) != len(bl.Tx_hashes) {
			return fmt.Errorf("changeset block %d: %d txs for %d hashes", i, len(txs), len(bl.Tx_hashes))
		}
		for j := range txs {
			if err := chain.Store.Block_tx_store.WriteTX(bl.Tx_hashes[j], txs[j].Serialize()); err != nil {
				return err
			}
		}
		diff := new(big.Int)
		if _, ok := diff.SetString(response.CBlocks[i].Difficulty, 10); !ok {
			return fmt.Errorf("changeset block %d: unparsable difficulty", i)
		}
		ss, err := chain.Store.Balance_store.LoadSnapshot(0)
		if err != nil {
			return err
		}
		cv := ss.GetVersion()
		nchg := 0
		if i != 0 {
			var changed []*graviton.Tree
			for _, change := range response.CBlocks[i].Changes {
				tree, err := ss.GetTree(string(change.TreeName))
				if err != nil {
					return err
				}
				if len(change.Keys) != len(change.Values) {
					return fmt.Errorf("changeset block %d: key/value count mismatch", i)
				}
				for j := range change.Keys {
					tree.Put(change.Keys[j], change.Values[j])
					nchg++
				}
				changed = append(changed, tree)
			}
			if cv, err = graviton.Commit(changed...); err != nil {
				return err
			}
		}
		h := bl.GetHash()
		if err := chain.Store.Block_tx_store.WriteBlock(h, bl.Serialize(), diff, cv, bl.Height); err != nil {
			return err
		}
		if err := chain.Store.Topo_store.Write(request.TopoHeights[i], h, cv, int64(bl.Height)); err != nil {
			return err
		}
		root, err := chain.Load_Merkle_Hash(cv)
		if err != nil {
			return err
		}
		sum.Roots = append(sum.Roots, topoRoot{Topo: request.TopoHeights[i], BLID: hex.EncodeToString(h[:]),
			StateVersion: cv, Root: hex.EncodeToString(root[:]), Txs: len(txs), ChangeKeys: nchg})
	}
	chain.Store.Topo_store.Sync()
	return os.WriteFile(filepath.Join(globalsDataDir(), "..", markerName), []byte("seeded by tools/forensics/a2 fetch-state\n"), 0600)
}

// callRetry retries a failed call up to 3 times with a growing pause (one request in flight, rate-limited).
func callRetry(pc *peerClient, method string, req, resp interface{}) error {
	var err error
	for a := 0; a < 4; a++ {
		rv := reflect.ValueOf(resp).Elem()
		rv.Set(reflect.Zero(rv.Type())) // a failed attempt must not leave partial keys behind
		if err = pc.call(method, req, resp, 60*time.Second); err == nil {
			return nil
		}
		time.Sleep(time.Duration(2+3*a) * time.Second)
	}
	return err
}

func progress(what string, done, total, keys int64) {
	fmt.Fprintf(os.Stderr, "%s %s %d/%d keys %d\n", time.Now().UTC().Format("15:04:05"), what, done, total, keys)
}
