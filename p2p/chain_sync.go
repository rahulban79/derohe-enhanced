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
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/errormsg"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/transaction"
)

// used to satisfy difficulty interface
type MemorySource struct {
	Blocks     map[crypto.Hash]*block.Complete_Block
	Difficulty map[crypto.Hash]*big.Int
}

// local blocks are inserted using this
func (x *MemorySource) insert_block_noprecheck(cbl *block.Complete_Block, diff *big.Int) {
	blid := cbl.Bl.GetHash()
	x.Blocks[blid] = cbl
	x.Difficulty[blid] = diff
}

// remote peers blocks are added using this
func (x *MemorySource) insert_block(cbl *block.Complete_Block) {
	if len(cbl.Bl.Tips) == 0 {
		panic("genesis block not possible")
	}
	diff := blockchain.Get_Difficulty_At_Tips(x, cbl.Bl.Tips)
	blid := cbl.Bl.GetHash()

	for _, mbl := range cbl.Bl.MiniBlocks {
		PoW := mbl.GetPoWHash()
		if blockchain.CheckPowHashBig(PoW, diff) == false {
			panic("pow failed")
		}
	}

	x.Blocks[blid] = cbl
	x.Difficulty[blid] = diff
}
func (x *MemorySource) check(blid crypto.Hash) *block.Complete_Block {
	cbl, ok := x.Blocks[blid]
	if !ok {
		panic(fmt.Errorf("no such blid in ram %s", blid))
	}
	return cbl
}
func (x *MemorySource) Load_Block_Height(blid crypto.Hash) int64 {
	return int64(x.check(blid).Bl.Height)
}
func (x *MemorySource) Load_Block_Timestamp(blid crypto.Hash) uint64 {
	return uint64(x.check(blid).Bl.Timestamp)
}
func (x *MemorySource) Get_Block_Past(blid crypto.Hash) []crypto.Hash {
	return x.check(blid).Bl.Tips
}
func (x *MemorySource) Load_Block_Difficulty(blid crypto.Hash) *big.Int {
	diff, ok := x.Difficulty[blid]
	if !ok {
		panic(fmt.Errorf("no such blid in ram %s", blid))
	}
	return diff
}

// convert block which was serialized in p2p format to in ram block format
func ConvertCBlock_To_CompleteBlock(cblock Complete_Block) (cbl block.Complete_Block, diff *big.Int) {
	var bl block.Block
	cbl.Bl = &bl
	if err := bl.Deserialize(cblock.Block); err != nil {
		panic(err)
	}
	// complete the txs
	for j := range cblock.Txs {
		var tx transaction.Transaction
		if err := tx.Deserialize(cblock.Txs[j]); err != nil { // we have a tx which could not be deserialized ban peer
			panic(err)
		}
		cbl.Txs = append(cbl.Txs, &tx)
	}

	if len(bl.Tx_hashes) != len(cbl.Txs) {
		panic(fmt.Errorf("txcount mismatch, expected %d txs actual %d", len(bl.Tx_hashes), len(cbl.Txs)))
	}

	return
}

// chain_locator lists our topo records from top down (20 consecutive, then 20 in steps of 5, 50 and 500, then
// doubling), stopping at a clean record, exactly as sync_chain always did. r24 (syncp2p): upstream `continue`d on a
// read error WITHOUT advancing i, so one unreadable record (a short read: Read refuses anything but a whole 48-byte
// record) spun the syncing goroutine at 100% CPU forever, holding the connection's Syncing count and never sending
// a chain request again. Such a record is now skipped (counted in p2p_sync_locator_read_errors_total); the locator
// is only a hint list for the peer's common-ancestor search, so a missing entry costs nothing. The request on the
// wire is unchanged whenever every record reads (the only case that ever terminated before).
func chain_locator(start_point int64, read func(int64) (blockchain.TopoRecord, error)) (ids [][32]byte, heights []int64) {
	for i := int64(0); i < start_point; {
		tr, err := read(start_point - i) // commit everything
		if err != nil {
			metrics.Set.GetOrCreateCounter("p2p_sync_locator_read_errors_total").Inc()
			i++ // r24: skip it (upstream: `continue` without advancing = endless loop)
			continue
		}
		if tr.IsClean() {
			break
		}

		ids = append(ids, tr.BLOCK_ID)
		heights = append(heights, start_point-i)
		switch {
		case len(ids) < 20: // 20 blocks raw
			i++
		case len(ids) < 40: // 20 block with 5 steps
			i += 5
		case len(ids) < 60: // 20 block with 50 steps
			i += 50
		case len(ids) < 80: // 20 block with 500 steps
			i += 500
		default:
			i = i * 2
		}
	}
	return
}

// we are expecting other side to have a heavier PoW chain, try to sync now
func (connection *Connection) sync_chain() {

	defer handle_connection_panic(connection)
	connection.Syncing.Add(1)
	defer connection.Syncing.Add(-1)

	var request Chain_Request_Struct
	var response Chain_Response_Struct

try_again:

	request = Chain_Request_Struct{}
	response = Chain_Response_Struct{}

	// send our blocks, first 10 blocks directly, then decreasing in powers of 2
	// r24: built by chain_locator (a topo record that cannot be read is skipped instead of retried forever)
	request.Block_list, request.TopoHeights = chain_locator(chain.Load_TOPO_HEIGHT(), chain.Store.Topo_store.Read)
	// add genesis block at the end
	request.Block_list = append(request.Block_list, globals.Config.Genesis_Block_Hash)
	request.TopoHeights = append(request.TopoHeights, 0)
	fill_common(&request.Common) // fill common info

	if err := connection.call("Peer.Chain", request, &response); err != nil {
		connection.logger.V(2).Error(err, "Call failed Chain")
		return
	}
	// we have a response, see if its valid and try to add to get the blocks

	connection.logger.V(2).Info("Peer wants to give chain", "from topoheight", response.Start_height)

	var pop_count int64

	// we do not need reorganisation if deviation is less than  or equak to 7 blocks
	// only pop blocks if the system has somehow deviated more than 7 blocks
	// if the deviation is less than 7 blocks, we internally reorganise everything
	if chain.Get_Height()-response.Start_height > config.STABLE_LIMIT && connection.SyncNode {
		// get our top block
		connection.logger.V(3).Info("rewinding status", "our topoheight", chain.Load_TOPO_HEIGHT(), "peer topoheight", response.Start_topoheight)
		pop_count := chain.Load_TOPO_HEIGHT() - response.Start_topoheight
		chain.Rewind_Chain(int(pop_count)) // pop as many blocks as necessary
		pop_count = 0

		// we should NOT queue blocks, instead we sent our chain request again
		goto try_again

	} else if chain.Get_Height()-response.Common.Height >= 0 && chain.Get_Height()-response.Start_height <= config.STABLE_LIMIT {
		//pop_count = chain.Load_TOPO_HEIGHT() - response.Start_topoheight
	} else if chain.Get_Height()-response.Start_height > config.STABLE_LIMIT { // we must somehow notify that deviation is way too much and manual interaction is necessary, so as any bug for chain deviationmay be detected
		connection.logger.V(1).Error(nil, "we have or others have deviated too much.you may have to use --sync-node option", "our topoheight", chain.Load_TOPO_HEIGHT(), "peer topoheight start", response.Start_topoheight)
		return
		//pop_count = chain.Load_TOPO_HEIGHT() - response.Start_topoheight
	}

	if pop_count >= 1 { // peer is claiming his chain is good and we should rewind
		connection.logger.V(1).Info("syncing", "pop_count", pop_count)

		ramstore := MemorySource{Blocks: map[crypto.Hash]*block.Complete_Block{}, Difficulty: map[crypto.Hash]*big.Int{}}
		start_point := response.Start_topoheight
		for i := 0; i < 10 && start_point >= 1; i++ {
			start_point--
		}

		for i := start_point; i < start_point+128 && i <= chain.Load_TOPO_HEIGHT(); i++ {
			blid, err := chain.Load_Block_Topological_order_at_index(i)
			if err != nil {
				connection.logger.V(1).Info("error loading local topo", "i", i)
				return
			}
			cbl, err := chain.Load_Complete_Block(blid)
			if err != nil {
				connection.logger.V(1).Info("error loading completeblock", "blid", blid)
				return
			}
			diff := chain.Load_Block_Difficulty(blid)
			ramstore.insert_block_noprecheck(cbl, diff) // all local blocks are already checked
		}

		// now we must request peer blocks and verify their pow

		for i := range response.Block_list {
			our_topo_order := chain.Load_Block_Topological_order(response.Block_list[i])
			if our_topo_order != (int64(i)+response.Start_topoheight) || our_topo_order == -1 { // if block is not in our chain, add it to request list

				var orequest ObjectList
				var oresponse Objects

				//fmt.Printf("inserting blocks %d %x\n", (int64(i) + response.Start_topoheight), response.Block_list[i][:])
				orequest.Block_list = append(orequest.Block_list, response.Block_list[i])
				fill_common(&orequest.Common)
				if err := connection.call("Peer.GetObject", orequest, &oresponse); err != nil {
					connection.sync_failed(connection.call_failed(err, "Call failed GetObject"), time.Now()) // r25 (CO24-N6, B47)
					return
				} else { // process the response
					cbl, _ := ConvertCBlock_To_CompleteBlock(oresponse.CBlocks[0])
					ramstore.insert_block(&cbl) // insert block with checking verification
				}
			}
		}

		// if we reached here we were able to verify basic chain structure

		//	chain.Rewind_Chain(int(pop_count)) // pop as many blocks as necessary, assumming peer has given us good chain

		failcount := 0
		for i := range response.Block_list {
			our_topo_order := chain.Load_Block_Topological_order(response.Block_list[i])
			if our_topo_order != (int64(i)+response.Start_topoheight) || our_topo_order == -1 { // if block is not in our chain, add it to request list
				if failcount < 4 {
					if _, ok := connection.add_block(ramstore.check(response.Block_list[i])); !ok { // r25: attributed
						failcount++
					}
				}
			}
		}

		connection.logger.V(1).Info("rewinded blocks", "pop_count", pop_count)
		return
	}

	// response only 4096 blocks at a time
	max_blocks_to_queue := 4096
	// check whether the objects are in our db or not
	// until we put in place a parallel object tracker, do it one at a time

	connection.logger.V(2).Info("response block list", "count", len(response.Block_list))
	var needed []crypto.Hash
	for i := range response.Block_list {
		our_topo_order := chain.Load_Block_Topological_order(response.Block_list[i])
		if our_topo_order != (int64(i)+response.Start_topoheight) || our_topo_order == -1 { // if block is not in our chain, add it to request list
			if max_blocks_to_queue >= 0 {
				max_blocks_to_queue--
				needed = append(needed, response.Block_list[i])
			}
		} else {
			connection.logger.V(3).Info("We must have queued but we skipped it at height", "blid", fmt.Sprintf("%x", response.Block_list[i]), "height", response.Start_height+int64(i))
		}
	}

	// fetch in batches with requests in flight while the previous batch is verified (sync_pipeline.go); blocks are
	// still added one by one, in order, by process_object_response exactly as before
	// (the shape falls back to batch=1 depth=1 while blocks are large, so one deadline never covers several MB)
	// r24: run carries the prewarm overlap across responses (sync_prewarm_overlap.go sync_run)
	// (run.prev is always an overlap whose finish() already ran right after the previous add: nothing to clean up)
	run := &sync_run{}
	if _, err := fetch_pipelined_peek(needed, func() (int, int) { return sync_sizes.shape(SYNC_BATCH, SYNC_DEPTH) }, connection.fetch_blocks, func(o Objects, peek func() []byte) error {
		sync_sizes.note(&o)
		run.peek = peek
		return connection.process_object_response_run(o, 0, true, nil, run)
	}); err != nil {
		sync_sizes.failed()
		connection.sync_failed(connection.call_failed(err, "Call failed GetObject"), time.Now()) // r25 (CO24-N6, B47)
		return
	}

	// request alt-tips ( blocks if we are nearing the main tip )
	/*if (response.Common.TopoHeight - chain.Load_TOPO_HEIGHT()) <= 5 {
		for i := range response.TopBlocks {
			if chain.Load_Block_Topological_order(response.TopBlocks[i]) == -1 {
				//connection.Send_ObjectRequest([]crypto.Hash{response.TopBlocks[i]}, []crypto.Hash{})
				connection.logger.V(2).Info("Queuing ALT-TIP", "blid", response.TopBlocks[i])

			}

		}
	}*/

}

func (connection *Connection) process_object_response(response Objects, sent int64, syncing bool) error {
	return connection.process_object_response_want(response, sent, syncing, nil)
}

// tx_want is the set of txids one GetObject asked for (r21, security). The response to Peer.GetObject is the peer's
// to fill: upstream verified every transaction in it, asked for or not, and kept going after the peer had been
// banned and disconnected mid-response. One INV for one txid could so be answered with a frame of thousands of
// well-formed transactions whose proofs fail, each costing ~40 ms (ring 2) to ~1 s (ring 128) of proof verification
// (tx_flow.go), while the invalid_tx score bans after 4 and then stops nothing. An honest peer answers exactly the
// txids asked (rpc_object_request.go GetObject), so dropping the others costs the honest path one map lookup per tx.
var p2p_unrequested_txs = metrics.Set.NewCounter("p2p_unrequested_txs_dropped_total")

type tx_want struct {
	m    map[crypto.Hash]bool
	left int
	got  int // asked-for txids delivered (r22: note_tx_fetch_reply)
}

func new_tx_want(list [][32]byte) *tx_want {
	w := &tx_want{m: make(map[crypto.Hash]bool, len(list))}
	for _, h := range list {
		if !w.m[h] {
			w.m[h] = true
			w.left++
		}
	}
	return w
}

// take reports whether txid was asked for and not yet delivered in this response (a duplicate is not taken twice).
func (w *tx_want) take(txid crypto.Hash) bool {
	if !w.m[txid] {
		return false
	}
	w.m[txid] = false
	w.left--
	w.got++
	return true
}

// process_object_response_want is process_object_response; when want is non-nil (a response to our own GetObject for
// an INV) only the asked-for txs are admitted, the first unrequested one scores the peer malformed_request, and the
// tx loop stops once everything asked for has arrived or the connection has been closed (banned) meanwhile.
func (connection *Connection) process_object_response_want(response Objects, sent int64, syncing bool, want *tx_want) error {
	return connection.process_object_response_run(response, sent, syncing, want, nil)
}

// process_object_response_run is process_object_response_want with the sync prewarm state of one pipelined fetch
// (r24; run is nil on every non-sync path, which then behaves exactly as before).
func (connection *Connection) process_object_response_run(response Objects, sent int64, syncing bool, want *tx_want, run *sync_run) error {
	var err error
	defer globals.Recover(2)

	// r23b: one height read per window, not per block (sync_height_gate.go)
	ahead := new_sync_height_gate(chain.Get_Height)

	for i := 0; i < len(response.CBlocks); i++ { // process incoming full blocks
		// make sure connection does not timeout and be killed while processing huge blocks

		connection.LastObjectRequestTime.Store(time.Now().Unix())

		var cbl block.Complete_Block // parse incoming block and deserialize it
		var bl block.Block
		// r24: the overlap (if any) that the previous block's add started for this block; already finished
		prev := run.take_prev()
		// lets deserialize block first and see whether it is the requested object
		cbl.Bl = &bl
		err := bl.Deserialize(response.CBlocks[i].Block)
		if err != nil { // we have a block which could not be deserialized ban peer
			connection.logger.V(2).Error(err, "Incoming block could not be deserilised")
			connection.exit()
			if syncing {
				return nil
			} else {
				return err
			}
		}

		// give the chain some more time to respond
		connection.LastObjectRequestTime.Store(time.Now().Unix())

		// do not try to add blocks too much into future
		if syncing && ahead.too_far(int64(bl.Height)) {
			continue
		}
		// check whether the object was requested one

		// complete the txs
		for j := range response.CBlocks[i].Txs {
			var tx transaction.Transaction
			err = decode_block_tx(&tx, response.CBlocks[i].Txs[j])
			if err != nil { // we have a tx which could not be deserialized ban peer
				connection.logger.V(2).Error(err, "Incoming TX could not be deserilised")
				connection.exit()

				if syncing {
					return nil
				} else {
					return err
				}
			}
			cbl.Txs = append(cbl.Txs, &tx)
		}
		// the HF3 table fix that let stuck nodes catch up (verify + entry Parity) is applied by
		// Add_Complete_Block_HF3 below, on this and on every other path that offers a block (hf3_parity.go)

		if syncing && prev.covered(bl.GetHash()) { // r24 (B34): the overlap already prewarmed all of it
			prewarm_overlap_skipped.Inc()
		} else if syncing { // verify the miniblock PoWs in parallel first; Add_Complete_Block then finds them cached
			// r24 (chainperf): with the block's difficulty computed once (PREWARM_DIFF)
			prewarm_pow_with(chain.Load_Block_Height, bl.Tips, len(bl.MiniBlocks), func() { chain.Get_Difficulty_At_Tips(bl.Tips) },
				prewarm_seconds.Add, func(k int) bool {
					return chain.VerifyMiniblockPoW(&bl, bl.MiniBlocks[k])
				})
		}

		// r23c: the next block's prewarm may start once this block is committed (sync_prewarm_overlap.go)
		// r24: for the last block of a response, the next response's first block if it has already arrived
		var overlap *prewarm_overlap
		if syncing && i+1 < len(response.CBlocks) {
			overlap = next_block_prewarm(response.CBlocks[i+1].Block)
		} else if syncing {
			overlap = run.next_overlap(response.CBlocks, i, next_block_prewarm)
		}

		// check if we can add ourselves to chain
		// r23c (verify): finish() is deferred so a panic out of the add path can never leave the overlap polling
		note_block_seen(connection, cbl.Bl.GetHash(), int64(cbl.Bl.Height)) // r25 (CO24-C5)
		err, ok := func() (error, bool) { defer overlap.finish(); return Add_Complete_Block_HF3(chain, &cbl) }()
		if ok {
			run.keep(overlap) // r24: the next block (maybe in the next response) may skip its own prewarm
		}
		note_block_result(connection, &cbl, err, ok) // r25 (CO24-C3/C4): attributed verdict (consensus_obs_r25.go)
		if !ok && err == errormsg.ErrInvalidPoW {
			connection.logger.V(2).Error(err, "This peer should be banned")
			connection.penalize("invalid_pow")
			connection.exit()
			if syncing {
				return nil
			} else {
				return err
			}
		}

		if !ok && err == errormsg.ErrPastMissing {
			connection.logger.V(2).Error(err, "Incoming Block could not be added due to missing past, so skipping future block")
			if syncing {
				return nil
			} else {
				return err
			}
		}

		if !ok {
			connection.logger.V(2).Error(err, "Incoming Block could not be added due to some error")
		} else {
			observe_block_txs(response.CBlocks[i].Txs, cbl.Txs) // r23: only txs of an accepted block are observed
		}

		// add the object to object pool from where it will be consume
		// queue_block_received(bl.GetHash(),&cbl)

	}

	unrequested := 0
	for i := range response.Txs { // process incoming txs for mempool
		if want != nil && (want.left == 0 || connection.exited.Load() == 1) {
			break // r21: all asked-for txs are in, or the peer was banned/closed mid-response
		}
		var tx transaction.Transaction
		err = deserialize_tx(&tx, response.Txs[i])
		if err != nil { // we have a tx which could not be deserialized ban peer
			connection.logger.V(2).Error(err, "Incoming TX could not be deserilised")
			connection.exit()

			return nil
		}
		txid := tx.GetHash() // r23b: once per tx (each GetHash re-serializes the header, ~7.6 us at ring 2)
		if want != nil && !want.take(txid) {
			p2p_unrequested_txs.Inc()
			if unrequested++; unrequested == 1 {
				connection.logger.V(1).Info("peer answered GetObject with a tx we did not ask for; dropped", "txid", txid.String())
				connection.penalize("malformed_request")
			}
			continue
		}

		// too old TXs will be ignored for mining, but we should check incoming TX here to avoid high system load
		// exclude registration txs from this check as they provide no height
		// r23b: the same bound, plus a height past our tip and the HF3 grandfather table, shared with
		// SendRawTransaction (glue/txprecheck/window.go); unscored, as before (an honest relay can be late)
		if tx.TransactionType != transaction.REGISTRATION {
			if werr := relay_window(&tx, txid); werr != nil {
				connection.logger.V(2).Info("Incoming TX refused by the admission window", "txid", txid.String(), "err", werr.Error())
				continue
			}
		}

		if !chain.Mempool.Mempool_TX_Exist(txid) { // we still donot have it, so try to process it
			// concurrent relays of the same bytes share one verification; only our own success relays (tx_flow.go)
			// r22: only a tx whose own re-serialization decodes back to it may enter the mempool (glue/txcanon)
			if err, relay := admit_relayed_tx(response.Txs[i], &tx, relay_admit(response.Txs[i], chain.Add_TX_To_Pool)); relay {
				broadcast_Tx(&tx, 0, sent)
			} else if err != nil {
				connection.score_pool_rejection(err)
			}
		}
	}

	for i := range response.Chunks { // process incoming chunks
		connection.feed_chunk(&response.Chunks[i], sent)
	}

	return nil
}

// score_pool_rejection scores a peer whose relayed transaction failed Add_TX_To_Pool's proof verification. Such a
// transaction is invalid for every honest node (the check is deterministic against its own reference block), yet
// costs us ~80 ms (ring 16) to ~1 s (ring 128) of CPU each; upstream ignored the error, so a peer could repeat it
// forever (diversity.go). Timing- or branch-dependent rejections are not scored.
func (connection *Connection) score_pool_rejection(err error) bool {
	if !is_tx_verification_failure(err) {
		return false
	}
	connection.penalize("invalid_tx")
	return true
}
