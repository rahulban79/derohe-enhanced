// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package p2p

import (
	"fmt"
	"math/big"
	"path/filepath"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/graviton"
)

//import "github.com/deroproject/derohe/errormsg"

//import "github.com/deroproject/derosuite/blockchain"

// we are expecting other side to have a heavier PoW chain
// this is for the case when the chain only moves in pruned state
// if after bootstraping the chain can continousky sync for few minutes, this means we have got the job done

type sync_progress struct {
	Step   uint
	Chunk  int64
	Height int64
}

var state sync_progress

func (connection *Connection) bootstrap_fail(msg error) {
	connection.logger.Error(msg, "Bootstrap failed")
	connection.exit()
}

func (connection *Connection) bootstrap_chain() error {
	defer handle_connection_panic(connection)
	var request ChangeList
	var response Changes
	var err error

	// peer's chain is only 110 height, so do not bootstrap
	if connection.TopoHeight.Load()-50-max_request_topoheights < 10 {
		connection.logger.Info("fastsync cannot be done as peer's chain has low height")
		connection.logger.Info("will do normal sync")
		connection.sync_chain()
		return nil
	}

	if state.Height == 0 {
		state.Height = connection.TopoHeight.Load()
		state.Step = 1
	}

	// we will request top 60 blocks
	ctopo := state.Height - 50 // last 50 blocks have to be synced, this syncing will help us detect error
	var topos []int64
	for i := ctopo - (max_request_topoheights - 1); i < ctopo; i++ {
		topos = append(topos, i)
	}

	connection.logger.Info("Bootstrap Initiated")

	for i := range topos {
		request.TopoHeights = append(request.TopoHeights, topos[i])
	}

	fill_common(&request.Common) // fill common info
	if err = connection.call("Peer.ChangeSet", request, &response); err != nil {
		return err
	}
	// we have a response, see if its valid and try to add to get the blocks
	connection.logger.V(1).Info("changeset received", "keycount", response.KeyCount, "sccount", response.SCKeyCount)

	commit_version := uint64(0)

	{ // fetch and commit balance tree

		chunksize := int64(640)
		chunks_estm := response.KeyCount / chunksize
		chunks := int64(1) // chunks need to be in power of 2
		path_length := 0
		for chunks < chunks_estm {
			chunks = chunks * 2
			path_length++
		}

		if chunks < 2 {
			chunks = 2
			path_length = 1
		}

		total_keys := 0

		if state.Step < 2 {
			// fetched with BOOTSTRAP_DEPTH requests in flight (bootstrap_pipeline.go); written and committed one chunk at
			// a time, in order, exactly as before
			start := state.Chunk
			err = connection.bootstrap_sections(int(chunks-start), bootstrap_depth(), func(k int) Request_Tree_Section_Struct {
				return Request_Tree_Section_Struct{Topo: request.TopoHeights[0], TreeName: []byte(config.BALANCE_TREE), Section: section_path(start + int64(k)), SectionLength: uint64(path_length)}
			}, func(k int, ts_response *Response_Tree_Section_Struct) error {
				i := start + int64(k)
				// now we must write all the state changes to gravition
				var balance_tree *graviton.Tree
				if ss, err := chain.Store.Balance_store.LoadSnapshot(0); err != nil {
					panic(err)
				} else if balance_tree, err = ss.GetTree(config.BALANCE_TREE); err != nil {
					panic(err)
				}

				if err := apply_section(section_path(i), uint64(path_length), ts_response, func(k, v []byte) { balance_tree.Put(k, v) }); err != nil {
					return err
				}
				total_keys += len(ts_response.Keys)

				var err error
				commit_version, err = graviton.Commit(balance_tree)
				if err != nil {
					panic(err)
				}
				state.Chunk = i + 1 // committed: a resumed bootstrap continues after it
				connection.logger.Info("Bootstrap in progress(step1)", "percent", float32(i*100)/float32(chunks))
				return nil
			})
			if err != nil {
				return err
			}
			state.Step = 2
			state.Chunk = 0
		}
	}

	{ // fetch and commit SC tree
		chunksize := int64(640)
		chunks_estm := response.SCKeyCount / chunksize
		chunks := int64(1) // chunks need to be in power of 2
		path_length := 0
		for chunks < chunks_estm {
			chunks = chunks * 2
			path_length++
		}

		if chunks < 2 {
			chunks = 2
			path_length = 1
		}

		total_keys := 0

		for i := state.Chunk; i < chunks; i++ {
			state.Chunk = i
			section := section_path(i)
			ts_request := Request_Tree_Section_Struct{Topo: request.TopoHeights[0], TreeName: []byte(config.SC_META), Section: section, SectionLength: uint64(path_length)}
			var ts_response Response_Tree_Section_Struct
			fill_common(&ts_request.Common)
			if err = connection.call("Peer.TreeSection", ts_request, &ts_response); err != nil {
				bootstrap_failed()
				return err
			}
			if err = section_check(section, uint64(path_length), &ts_response); err != nil {
				bootstrap_failed()
				return err
			}
			// now we must write all the state changes to gravition
			var changed_trees []*graviton.Tree
			var sc_tree *graviton.Tree
			ss, err := chain.Store.Balance_store.LoadSnapshot(0)
			if err != nil {
				panic(err)
			} else if sc_tree, err = ss.GetTree(config.SC_META); err != nil {
				panic(err)
			}

			// every SC's own tree is fetched with depth requests in flight and written in key order
			depth := bootstrap_depth()
			err = connection.bootstrap_sections(len(ts_response.Keys), depth, func(j int) Request_Tree_Section_Struct {
				return Request_Tree_Section_Struct{Topo: request.TopoHeights[0], TreeName: ts_response.Keys[j], Section: section, SectionLength: uint64(0)}
			}, func(j int, sc_response *Response_Tree_Section_Struct) error {
				sc_tree.Put(ts_response.Keys[j], ts_response.Values[j])

				var sc_data_tree *graviton.Tree
				var err error
				if sc_data_tree, err = ss.GetTree(string(ts_response.Keys[j])); err != nil {
					panic(err)
				} else if sc_response.KeyCount < 4096 { // whole tree (path 0): only the key/value pairing is checked
					if err := apply_section(section, 0, sc_response, func(k, v []byte) { sc_data_tree.Put(k, v) }); err != nil {
						return err
					}
				} else { // tree is a huge tree, get it in chunks
					sc_chunks_estm := sc_response.KeyCount / chunksize
					sc_chunks := int64(1) // chunks need to be in power of 2
					sc_path_length := 0
					for sc_chunks < sc_chunks_estm {
						sc_chunks = sc_chunks * 2
						sc_path_length++
					}

					if sc_chunks < 2 {
						sc_chunks = 2
						sc_path_length = 1
					}

					// nested inside the SC pipeline: nested_depth keeps the total in flight below the peer's cap
					err = connection.bootstrap_sections(int(sc_chunks), nested_depth(depth), func(k int) Request_Tree_Section_Struct {
						return Request_Tree_Section_Struct{Topo: request.TopoHeights[0], TreeName: ts_response.Keys[j], Section: section_path(int64(k)), SectionLength: uint64(sc_path_length)}
					}, func(k int, sc_ts_response *Response_Tree_Section_Struct) error {
						return apply_section(section_path(int64(k)), uint64(sc_path_length), sc_ts_response, func(k, v []byte) { sc_data_tree.Put(k, v) })
					})
					if err != nil {
						return err
					}
				}
				changed_trees = append(changed_trees, sc_data_tree)
				return nil
			})
			if err != nil {
				return err
			}

			total_keys += len(ts_response.Keys)
			changed_trees = append(changed_trees, sc_tree)
			commit_version, err = graviton.Commit(changed_trees...)
			if err != nil {
				panic(err)
			}
			connection.logger.Info("Bootstrap in progress(step 2)", "percent", float32(i*100)/float32(chunks))
		}
		_ = total_keys
	}

	t_topo := time.Now()
	fast := write_bootstrap_topo(&chain.Store.Topo_store, filepath.Join(globals.GetDataDirectory(), "topo.map"), request.TopoHeights[0], commit_version)
	chain.Store.Topo_store.Sync()
	connection.logger.Info("Bootstrap topo records written", "count", request.TopoHeights[0]+1, "prefill", fast, "took", time.Since(t_topo).String())

	for i := range response.CBlocks { // we must store the blocks

		var cbl block.Complete_Block // parse incoming block and deserialize it
		var bl block.Block
		// lets deserialize block first and see whether it is the requested object
		cbl.Bl = &bl
		err := bl.Deserialize(response.CBlocks[i].Block)
		if err != nil { // we have a block which could not be deserialized ban peer
			connection.logger.Error(err, "Error Incoming block could not be deserialised.")
			connection.exit()
			return nil
		}

		// give the chain some more time to respond
		connection.LastObjectRequestTime.Store(time.Now().Unix())

		if i == 0 { // whatever datastore we have written, its state hash must match
			// ToDo

		}

		// complete the txs
		for j := range response.CBlocks[i].Txs {
			var tx transaction.Transaction
			err = deserialize_tx(&tx, response.CBlocks[i].Txs[j])
			if err != nil { // we have a tx which could not be deserialized ban peer
				connection.logger.Error(err, "Error Incoming TX could not be deserialized")
				connection.exit()
				return nil
			}
			if bl.Tx_hashes[j] != tx.GetHash() {
				connection.logger.Error(err, "Error Incoming TX has mismatch.")
				connection.exit()
				return nil
			}

			cbl.Txs = append(cbl.Txs, &tx)
		}

		{ // first lets save all the txs, together with their link to this block as height
			for i := 0; i < len(cbl.Txs); i++ {
				if err = chain.Store.Block_tx_store.WriteTX(bl.Tx_hashes[i], cbl.Txs[i].Serialize()); err != nil {
					panic(err)
				}
			}
		}

		diff := new(big.Int)
		if _, ok := diff.SetString(response.CBlocks[i].Difficulty, 10); !ok { // if Cumulative_Difficulty could not be parsed, kill connection
			connection.logger.Error(fmt.Errorf("Could not Parse Difficulty in common"), "", "diff", response.CBlocks[i].Difficulty)
			connection.exit()
			return nil
		}

		// now we must write all the state changes to gravition

		var ss *graviton.Snapshot
		if ss, err = chain.Store.Balance_store.LoadSnapshot(0); err != nil {
			panic(err)
		}

		/*if len(response.CBlocks[i].Keys) != len(response.CBlocks[i].Values) {
			rlog.Warnf("Incoming Key count %d value count %d \"%s\" ", len(response.CBlocks[i].Keys), len(response.CBlocks[i].Values), globals.CTXString(connection.logger))
			connection.exit()
			return
		}*/

		write_count := 0
		commit_version := ss.GetVersion()
		if i != 0 {

			var changed_trees []*graviton.Tree

			for _, change := range response.CBlocks[i].Changes {
				var tree *graviton.Tree
				if tree, err = ss.GetTree(string(change.TreeName)); err != nil {
					panic(err)
				}

				for j := range change.Keys {
					tree.Put(change.Keys[j], change.Values[j])
					write_count++
				}
				changed_trees = append(changed_trees, tree)
			}
			commit_version, err = graviton.Commit(changed_trees...)
			if err != nil {
				panic(err)
			}
		}

		if err = chain.Store.Block_tx_store.WriteBlock(bl.GetHash(), bl.Serialize(), diff, commit_version, bl.Height); err != nil {
			panic(fmt.Sprintf("error while writing block"))
		}

		connection.logger.V(2).Info("Writing version", "topoheight", request.TopoHeights[i], "keycount", write_count, "commit version ", commit_version)

		chain.Store.Topo_store.Write(request.TopoHeights[i], bl.GetHash(), commit_version, int64(bl.Height)) // commit everything
	}

	connection.logger.Info("Bootstrap completed successfully.")
	// load the chain from the disk
	chain.Initialise_Chain_From_DB()
	chain.Sync = true
	return nil
}
