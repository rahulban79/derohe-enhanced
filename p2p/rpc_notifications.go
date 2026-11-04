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

import "fmt"
import "encoding/binary"
import "time"

import "github.com/deroproject/derohe/block"
import "github.com/deroproject/derohe/cryptography/crypto"
import "github.com/deroproject/derohe/errormsg"
import "github.com/deroproject/derohe/transaction"
import "github.com/deroproject/derohe/metrics"
import "github.com/deroproject/derohe/globals"

// handles notifications of inventory
func (c *Connection) NotifyINV(request ObjectList, response *Dummy) (err error) {
	defer handle_connection_panic(c)
	var need ObjectList
	var dirty = false

	c.logger.V(3).Info("incoming INV", "request", request)

	if !inv_within_bounds(&request) { // honest senders announce one tx or one chunk; never more than GetObject accepts
		c.logger.V(2).Info("oversized INV received", "blocks", len(request.Block_list), "txs", len(request.Tx_list), "chunks", len(request.Chunk_list))
		c.penalize("malformed_request")
		c.exit()
		return fmt.Errorf("oversized INV")
	}

	if len(request.Block_list) >= 1 { //  handle incoming blocks list
		for i := range request.Block_list { //
			if !chain.Is_Block_Topological_order(request.Block_list[i]) { // block is not in our chain
				if !chain.Block_Exists(request.Block_list[i]) { // check whether the block can be loaded from disk
					need.Block_list = append(need.Block_list, request.Block_list[i])
					dirty = true
				}
			}
		}
	}

	// r22: per-connection announced-txid budget (inv_budget.go)
	request.Tx_list = c.clip_inv_txs(request.Tx_list, time.Now())
	if len(request.Tx_list) >= 1 { // handle incoming tx list and see whether it exists in mempoolor regpool
		if need.Tx_list = c.txs_to_fetch(request.Tx_list, request.Sent, have_pool_tx, tx_on_disk); len(need.Tx_list) > 0 {
			dirty = true
		}
	}

	// cchunk list ids are 65 bytes long
	if len(request.Chunk_list) >= 1 { // handle incoming chunks list and see whether we have the chunks
		for i := range request.Chunk_list { //
			var blid, hhash [32]byte
			copy(blid[:], request.Chunk_list[i][:])
			cid := uint8(request.Chunk_list[i][32])
			copy(hhash[:], request.Chunk_list[i][33:])

			// track chunk propagation
			if request.Sent != 0 && request.Sent < globals.Time().UTC().UnixMicro() {
				time_to_receive := float64(globals.Time().UTC().UnixMicro()-request.Sent) / 1000000
				metrics.Set.GetOrCreateHistogram("chunk_propagation_duration_histogram_seconds").Update(time_to_receive)
			}

			if !chain.Block_Exists(blid) { // check whether the block can be loaded from disk
				if nil == is_chunk_exist(hhash, cid) { // if chunk does not exist
					c.logger.V(3).Info("requesting INV chunk", "blid", fmt.Sprintf("%x", blid), "cid", cid, "hhash", fmt.Sprintf("%x", hhash), "raw", fmt.Sprintf("%x", request.Chunk_list[i]))
					need.Chunk_list = append(need.Chunk_list, request.Chunk_list[i])
					dirty = true
				}
			}
		}
	}

	if dirty { //  request inventory only if we want it
		var oresponse Objects
		fill_common(&need.Common) // fill common info
		if err = c.call("Peer.GetObject", need, &oresponse); err != nil {
			kind := c.call_failed(err, "Call failed GetObject", "need_objects", need) // r25 (CO24-N6): counted per connection
			// a peer that announced a transaction and then could not serve it (typically mined or
			// evicted in between) keeps the connection; blocks, chunks and other failures do not
			if kind == call_failure_remote && is_tx_only(need) && c.keep_after_tx_fetch_failure() {
				c.update(&request.Common)
				fill_common(&response.Common)
				return nil
			}
			c.exit()
			return
		} else { // process the response
			want := new_tx_want(need.Tx_list)
			if err = c.process_object_response_want(oresponse, request.Sent, false, want); err != nil {
				return
			}
			if !c.note_tx_fetch_reply(need, want.got, len(want.m)) { // r22: a reply missing asked-for txs counts as a failed fetch
				c.exit()
				return
			}
		}
	}

	c.update(&request.Common)     // update common information
	fill_common(&response.Common) // fill common info

	return nil

}

// txs_to_fetch picks the announced txids to request from this peer: not in a pool, not admitted meanwhile by another
// connection (tx_flow.go), not on disk, and not already asked of this peer within TX_ASK_HOLD (tx_ask.go).
func (c *Connection) txs_to_fetch(list [][32]byte, sent int64, have func(crypto.Hash) bool, on_disk func(crypto.Hash) bool) (fetch [][32]byte) {
	inflight_deadline := time.Now().Add(TX_INFLIGHT_WAIT) // one wait budget for the whole INV (TXF-02)
	for i := range list {
		// track transaction propagation
		if sent != 0 && sent < globals.Time().UTC().UnixMicro() {
			time_to_receive := float64(globals.Time().UTC().UnixMicro()-sent) / 1000000
			metrics.Set.GetOrCreateHistogram("tx_propagation_duration_histogram_seconds").Update(time_to_receive)
		}
		txid := crypto.Hash(list[i])
		// the peer holds it: broadcast_Tx will not announce it back (tx_known.go)
		c.tx_known.note(txid, time.Now())
		if have(txid) { // check if is already in mempool skip it
			continue
		}
		if tx_inflight.settled(txid, time.Until(inflight_deadline), have) { // admitted meanwhile by another connection
			continue
		}
		if on_disk(txid) { // check whether the tx can be loaded from disk
			continue
		}
		if !c.tx_asked.claim(txid, time.Now()) { // already asked this peer for it (tx_ask.go)
			continue
		}
		fetch = append(fetch, list[i])
	}
	return
}

func tx_on_disk(txid crypto.Hash) bool {
	_, err := chain.Store.Block_tx_store.ReadTX(txid)
	return err == nil
}

// only miniblocks carry extra info, which leads to better time tracking
func (c *Connection) NotifyMiniBlock(request Objects, response *Dummy) (err error) {
	defer handle_connection_panic(c)
	if len(request.MiniBlocks) >= 5 {
		err = fmt.Errorf("Notify Block can notify max 5 miniblocks")
		c.logger.V(3).Error(err, "Should be banned")
		c.penalize("malformed_request")
		c.exit()
		return c.refuse_miniblock(MBL_REFUSED_TOO_MANY, 0, err) // r25 (CO24-C1): counted by reason
	}
	fill_common_T1(&request.Common)
	c.update(&request.Common) // update common information

	var mbls []block.MiniBlock

	height := chain.Get_Height()
	for i := range request.MiniBlocks {
		var mbl block.MiniBlock
		if err = mbl.Deserialize(request.MiniBlocks[i]); err != nil {
			return c.refuse_miniblock(MBL_REFUSED_UNDECODABLE, 0, err) // r25 (CO24-C1)
		}
		if height > 4 { // activate check a bit after genesis, thanks Slixe
			if height-2 <= int64(mbl.Height) && int64(mbl.Height) <= (height+1) {
			} else {
				return c.refuse_miniblock(MBL_REFUSED_STALE, mbl.Height, fmt.Errorf("Stale Miniblock")) // r25 (CO24-C1)
			}
		}
		mbls = append(mbls, mbl)
	}

	var valid_found bool

	for _, mbl := range mbls {
		var ok bool

		if mbl.Final {
			return c.refuse_miniblock(MBL_REFUSED_FINAL, mbl.Height, fmt.Errorf("final blocks are not propagted")) // r25 (CO24-C1)
		}

		// track miniblock propagation
		if request.Sent != 0 && request.Sent < globals.Time().UTC().UnixMicro() {
			time_to_receive := float64(globals.Time().UTC().UnixMicro()-request.Sent) / 1000000
			metrics.Set.GetOrCreateHistogram("miniblock_propagation_duration_histogram_seconds").Update(time_to_receive)
		}

		// first check whether it is already in the chain
		if chain.MiniBlocks.IsCollision(mbl) {
			c.note_miniblock_delivery(false)
			continue // miniblock already in chain, so skip it
		}

		var miner_hash crypto.Hash
		copy(miner_hash[:], mbl.KeyHash[:])
		if !chain.IsAddressHashValid(false, miner_hash) { // this will use cache
			return c.refuse_miniblock(MBL_REFUSED_UNREGISTERED, mbl.Height, fmt.Errorf("unregistered miner")) // r25 (CO24-C1)
		}

		var bl block.Block

		bl.Height = mbl.Height
		var tip1, tip2 crypto.Hash
		binary.BigEndian.PutUint32(tip1[:], mbl.Past[0])
		bl.Tips = append(bl.Tips, tip1)

		if mbl.PastCount == 2 {
			binary.BigEndian.PutUint32(tip2[:], mbl.Past[1])
			bl.Tips = append(bl.Tips, tip2)
		}

		for i, tip := range bl.Tips { // tips are currently only partial,  lets expand tips
			if ehash, ok := chain.ExpandMiniBlockTip(tip); ok {
				bl.Tips[i] = ehash
			} else {
				return c.refuse_miniblock(MBL_REFUSED_TIP, mbl.Height, fmt.Errorf("tip could not be expanded")) // r25 (CO24-C1)
			}
		}

		bl.MiniBlocks = append(bl.MiniBlocks, mbl)

		// lets get the difficulty at tips
		if !chain.VerifyMiniblockPoW(&bl, mbl) {
			c.penalize("invalid_pow_miniblock")
			return c.refuse_miniblock(MBL_REFUSED_POW, mbl.Height, errormsg.ErrInvalidPoW) // r25 (CO24-C1)
		}

		if err, ok = chain.InsertMiniBlock(mbl); !ok {
			return c.refuse_miniblock(MBL_REFUSED_INSERT, mbl.Height, err) // r25 (CO24-C1)
		} else { // rebroadcast miniblock
			valid_found = true
			note_miniblock_seen(c, mbl) // r25 (CO24-C5): first-seen time of an accepted miniblock
			c.note_miniblock_delivery(true)
			if valid_found {
				broadcast_MiniBlock(mbl, c.Peer_ID, request.Sent) // do not send back to the original peer
			}
		}
	}

	fill_common(&response.Common)                         // fill common info
	fill_common_T0T1T2(&request.Common, &response.Common) // fill time related information
	return nil
}

// decode_chunked_txs decodes the txs of a complete chunked block; an undecodable one (including a decoder panic,
// deserialize_tx) scores the peer "undecodable" and ends the connection (security SEC-8).
func (c *Connection) decode_chunked_txs(raw [][]byte) (txs []*transaction.Transaction, err error) {
	for j := range raw {
		var tx transaction.Transaction
		if err = decode_block_tx(&tx, raw[j]); err != nil { // we have a tx which could not be deserialized ban peer
			c.logger.V(3).Error(err, "tx cannot be deserialized.Should be banned")
			c.penalize("undecodable")
			c.exit()
			return nil, err
		}
		txs = append(txs, &tx)
	}
	return txs, nil
}

func (c *Connection) processChunkedBlock(request Objects, data_shard_count, parity_shard_count int) error {
	var err error

	var cbl block.Complete_Block // parse incoming block and deserialize it
	var bl block.Block
	// lets deserialize block first and see whether it is the requested object
	cbl.Bl = &bl
	err = bl.Deserialize(request.CBlocks[0].Block)
	if err != nil { // we have a block which could not be deserialized ban peer
		c.logger.V(3).Error(err, "Block cannot be deserialized.Should be banned")
		c.penalize("undecodable")
		c.exit()
		return err
	}

	blid := bl.GetHash()

	// object is already is in our chain, we need not relay it
	if chain.Is_Block_Topological_order(blid) || chain.Is_Block_Tip(blid) {
		return nil
	}

	// the block is not in our db,  parse entire block, complete the txs and try to add it
	if len(bl.Tx_hashes) == len(request.CBlocks[0].Txs) {
		c.logger.V(2).Info("Received a complete block", "blid", blid, "txcount", len(bl.Tx_hashes))
		if cbl.Txs, err = c.decode_chunked_txs(request.CBlocks[0].Txs); err != nil {
			return err
		}
	} else { // the block is NOT complete, we consider it as an ultra compact block
		c.logger.V(2).Info("Received an ultra compact  block", "blid", blid, "txcount", len(bl.Tx_hashes), "skipped", len(bl.Tx_hashes)-len(request.CBlocks[0].Txs), "stacktrace", globals.StackTrace(false))
		// how
	}

	// make sure connection does not timeout and be killed while processing huge blocks
	c.LastObjectRequestTime.Store(time.Now().Unix())
	// check if we can add ourselves to chain
	note_block_seen(c, blid, int64(bl.Height))              // r25 (CO24-C5): a complete block offered by this peer
	if err, ok := Add_Complete_Block_HF3(chain, &cbl); ok { // if block addition was successfil (HF3 table: hf3_parity.go)
		note_block_result(c, &cbl, err, ok) // r25 (CO24-C3/C4): attributed verdict (consensus_obs_r25.go)
		// notify all peers
		Broadcast_Block(&cbl, c.Peer_ID) // do not send back to the original peer
		if len(bl.Tx_hashes) == len(request.CBlocks[0].Txs) {
			observe_block_txs(request.CBlocks[0].Txs, cbl.Txs) // r23: only txs of an accepted block are observed
		}
	} else { // ban the peer for sometime
		note_block_result(c, &cbl, err, ok) // r25 (CO24-C3): counted by reason, the sender named by its peer_id
		if err == errormsg.ErrInvalidPoW {
			c.logger.Error(err, "This peer should be banned and terminated")
			c.penalize("invalid_pow")
			c.exit()
			return err
		}
	}

	return nil
}
