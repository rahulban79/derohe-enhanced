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

package rpc

//import "fmt"
import "github.com/deroproject/derohe/cryptography/crypto"
import "github.com/deroproject/derohe/rpc"
import "github.com/deroproject/derohe/config"
import "github.com/deroproject/derohe/globals"
import "github.com/deroproject/derohe/blockchain"

// this function is only used by the RPC and is not used by the core and should be moved to RPC interface

/* fill up the above structure from the blockchain */
func GetBlockHeader(chain *blockchain.Blockchain, hash crypto.Hash) (result rpc.BlockHeader_Print, err error) {
	bl, err := chain.Load_BL_FROM_ID(hash)
	if err != nil {
		return
	}

	result.TopoHeight = -1
	if chain.Is_Block_Topological_order(hash) {
		result.TopoHeight = chain.Load_Block_Topological_order(hash)
	}
	result.Height = chain.Load_Height_for_BL_ID(hash)
	result.Depth = chain.Get_Height() - result.Height
	result.Difficulty = chain.Load_Block_Difficulty(hash).String()
	result.Hash = hash.String()
	result.Major_Version = uint64(bl.Major_Version)
	result.Minor_Version = uint64(bl.Minor_Version)
	result.Orphan_Status = chain.Is_Block_Orphan(hash)
	if result.TopoHeight >= chain.LocatePruneTopo()+10 { // this result may/may not be valid at just above prune heights
		result.SyncBlock = chain.IsBlockSyncBlockHeight(hash)
	}
	result.SideBlock = chain.Isblock_SideBlock(hash)
	result.Reward = blockchain.CalcBlockReward(uint64(result.Height))
	result.TXCount = int64(len(bl.Tx_hashes))

	for i := range bl.Tips {
		result.Tips = append(result.Tips, bl.Tips[i].String())
	}
	//result.Prev_Hash = bl.Prev_Hash.String()
	result.Timestamp = bl.Timestamp

	// r25 (CO24-C7, dero-rft §7 B61): resolve the miniblock key hashes against the state at the block's own
	// TOPOheight (a side block: its highest tip's), as GetMiniBlocks does. Upstream read Topo_store at the block's
	// HEIGHT, the same record only while topoheight == height. And an unresolved key now stays "unknown" in ITS slot:
	// upstream skipped it (`continue`), padded "unknown" at the end and then overwrote slot 9 with the integrator, so
	// the slots after an unresolved miniblock shifted by one and the observatory could not see it (consensus_intel
	// unresolved_miniblocks_header). Report-only: no consensus code reads this.
	state_topo := result.TopoHeight
	if state_topo < 0 {
		for i := range bl.Tips {
			if t := chain.Load_Block_Topological_order(bl.Tips[i]); t > state_topo {
				state_topo = t
			}
		}
	}
	resolve := func(keyhash []byte) (string, bool) { return "", false }
	if state_topo >= 0 {
		if toporecord, err1 := chain.Store.Topo_store.Read(state_topo); err1 == nil { // we must now fill in compressed ring members
			if ss, err1 := chain.Store.Balance_store.LoadSnapshot(toporecord.State_Version); err1 == nil {
				if balance_tree, err1 := ss.GetTree(config.BALANCE_TREE); err1 == nil {
					resolve = func(keyhash []byte) (string, bool) {
						bits, key, _, err1 := balance_tree.GetKeyValueFromHash(keyhash)
						if err1 != nil || bits >= 120 {
							return "", false
						}
						addr, err1 := rpc.NewAddressFromCompressedKeys(key)
						if err1 != nil {
							return "", false
						}
						addr.Mainnet = globals.IsMainnet()
						return addr.String(), true
					}
				}
			}
		}
	}
	integrator, has_integrator := "", false
	if addr, err1 := rpc.NewAddressFromCompressedKeys(bl.Miner_TX.MinerAddress[:]); err1 == nil {
		addr.Mainnet = globals.IsMainnet()
		integrator, has_integrator = addr.String(), true
	}
	result.Miners = header_miners(len(bl.MiniBlocks), func(i int) (string, bool) { return resolve(bl.MiniBlocks[i].KeyHash[0:16]) },
		integrator, has_integrator)

	return
}

// header_miners builds the miners[] slots of a block header (r25, CO24-C7): slot i is miniblock i's miner, "unknown"
// when its key does not resolve, and slot 9 (the final, last miniblock) is the integrator paid by the miner tx,
// exactly as upstream wrote it once a block carries 10 miniblocks. Pure: unit tested.
func header_miners(n int, resolve func(i int) (string, bool), integrator string, has_integrator bool) []string {
	if n <= 0 {
		return nil // as upstream: a block without miniblocks (genesis) has no miners[]
	}
	miners := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if a, ok := resolve(i); ok {
			miners = append(miners, a)
		} else {
			miners = append(miners, "unknown")
		}
	}
	if has_integrator && len(miners) >= 10 { // last miniblock goes to intgretor
		miners[9] = integrator
	}
	return miners
}
