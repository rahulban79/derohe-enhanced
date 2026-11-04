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

import "bytes"
import "context"
import "github.com/deroproject/derohe/config"
import "github.com/deroproject/derohe/globals"
import "github.com/deroproject/derohe/cryptography/crypto"
import "github.com/deroproject/derohe/rpc"

//import "github.com/deroproject/derohe/blockchain"

// only give random members who have not been used in last 5 blocks
// canonical_account_key decodes a balance-tree key and reports whether the key is exactly the compressed encoding
// of the point it decodes to (Round 22). The point decoder (cryptography/bn256, consensus code) also accepts flag
// bytes 0x02..0xff (aliases of a real key) and x >= P (decodes to the identity, whose own encoding does not
// decode), and a registration stores the raw key bytes as the tree key, so such leaves can exist. An address made
// from one (NewAddressFromKeys re-encodes canonically) names a different, usually unregistered, account, or an
// undecodable one: a wallet that drew it as a decoy failed the whole transfer. Only the RPC answer is filtered;
// what the chain accepts is unchanged.
func canonical_account_key(k []byte) (*crypto.Point, bool) {
	var acckey crypto.Point
	if err := acckey.DecodeCompressed(k); err != nil {
		return nil, false
	}
	if !bytes.Equal(acckey.EncodeCompressed(), k) {
		return nil, false
	}
	return &acckey, true
}

func GetRandomAddress(ctx context.Context, p rpc.GetRandomAddress_Params) (result rpc.GetRandomAddress_Result, err error) {
	defer func() { // safety so if anything wrong happens, we return error
		if r := recover(); r != nil {
			err = rpc_internal_error(r)
		}
	}()
	if err = check_scid_tree("GetRandomAddress", p.SCID); err != nil { // r25 B86: was a panic at ss.GetTree below
		return
	}
	topoheight := chain.Load_TOPO_HEIGHT()
	old_topoheight := topoheight

	if old_topoheight > 100 {
		old_topoheight -= 5
	}

	var cursor_list []string

	{

		toporecord, err := chain.Store.Topo_store.Read(topoheight)
		if err != nil {
			panic(err) // r25 B86: store invariant (current and current-5 state), keeps ERROR + stack
		}
		toporecord_old, err := chain.Store.Topo_store.Read(old_topoheight)
		if err != nil {
			panic(err) // r25 B86: store invariant (current and current-5 state), keeps ERROR + stack
		}

		ss, err := chain.Store.Balance_store.LoadSnapshot(toporecord.State_Version)
		if err != nil {
			panic(err) // r25 B86: store invariant (current and current-5 state), keeps ERROR + stack
		}
		ss_old, err := chain.Store.Balance_store.LoadSnapshot(toporecord_old.State_Version)
		if err != nil {
			panic(err) // r25 B86: store invariant (current and current-5 state), keeps ERROR + stack
		}

		treename := config.BALANCE_TREE
		if !p.SCID.IsZero() {
			treename = string(p.SCID[:])
		}

		balance_tree, err := ss.GetTree(treename)
		if err != nil {
			panic(err) // r25 B86: store invariant (current and current-5 state), keeps ERROR + stack
		}
		balance_tree_old, err := ss_old.GetTree(treename)
		if err != nil {
			panic(err) // r25 B86: store invariant (current and current-5 state), keeps ERROR + stack
		}

		account_map := map[string]bool{}

		// r24 (CI24-3): depth-corrected draws instead of 100 raw balance_tree.Random() calls (r24_decoy_sampler.go)
		draws, _ := r24_decoy_draws(balance_tree, treename, r24_decoy_b, R24_DECOY_WANT, R24_DECOY_DRAW_BUDGET, r24_coin)
		for _, d := range draws {
			k, v := d.k, d.v
			v_old, err := balance_tree_old.Get(k)
			if err != nil {
				continue
			}

			if bytes.Compare(v, v_old) != 0 {
				continue
			}

			acckey, ok := canonical_account_key(k)
			if !ok { // r22: an aliased or identity key would break the wallet's transfer, never offer it as a decoy
				continue
			}

			addr := rpc.NewAddressFromKeys(acckey)
			addr.Mainnet = true
			if globals.Config.Name != config.Mainnet.Name { // anything other than mainnet is testnet at this point in time
				addr.Mainnet = false
			}
			account_map[addr.String()] = true
			if len(account_map) > 140 {
				break
			}
		}

		for k := range account_map {
			cursor_list = append(cursor_list, k)
		}
	}

	/*
	   		c := balance_tree.Cursor()
	   		for k, v, err := c.First(); err == nil; k, v, err = c.Next() {
	               _ = v
	   			//fmt.Printf("key=%x, value=%x err %s\n", k, v, err)

	   			var acckey crypto.Point
	   			if err := acckey.DecodeCompressed(k[:]); err != nil {
	   				panic(err)
	   			}

	   			addr := address.NewAddressFromKeys(&acckey)
	   			if globals.Config.Name != config.Mainnet.Name { // anything other than mainnet is testnet at this point in time
	   				addr.Network = globals.Config.Public_Address_Prefix
	   			}
	   			cursor_list = append(cursor_list, addr.String())
	   			if len(cursor_list) >= 20 {
	   				break
	   			}
	   		}

	   	}
	*/

	result.Address = cursor_list
	result.Status = "OK"

	return result, nil
}
