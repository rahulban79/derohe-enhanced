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

import "fmt"
import "context"
import "encoding/hex"
import "github.com/deroproject/derohe/rpc"
import "github.com/deroproject/derohe/p2p"
import "github.com/deroproject/derohe/glue/txcanon"
import "github.com/deroproject/derohe/glue/txprecheck"
import "github.com/deroproject/derohe/glue/txpolicy"
import "github.com/deroproject/derohe/transaction"

// send_tx_tip returns our chain's height (tests replace it).
var send_tx_tip = func() int64 { return chain.Get_Height() }

// NOTE: finally we have shifted to json api
func SendRawTransaction(ctx context.Context, p rpc.SendRawTransaction_Params) (result rpc.SendRawTransaction_Result, err error) {

	defer func() { // safety so if anything wrong happens, we return error
		if r := recover(); r != nil {
			err = rpc_internal_error(r)
		}
	}()

	var tx transaction.Transaction

	//	rlog.Debugf("Incoming TX from RPC Server")

	//lets decode the tx from hex
	tx_bytes, err := hex.DecodeString(p.Tx_as_hex)

	if err != nil {
		result.Status = "TX could be hex decoded"
		return
	}
	if len(tx_bytes) < 99 {
		result.Status = "TX insufficient length"
		return
	}

	// r23b: a height no block on top of our tip can hold, or a header Deserialize refuses (an unknown type panics
	// there, and the recover below would log a full stack at ERROR per call), is refused from the header alone,
	// before any curve point is decoded (glue/txprecheck/window.go)
	tip_height := send_tx_tip()
	if err = txprecheck.PeekWindow(tx_bytes, tip_height); err != nil {
		err = fmt.Errorf("Transaction rejected by daemon err '%s'", err)
		return
	}

	// r24: bytes whose proof already failed on this node are refused before any curve point is decoded; the same
	// refusal text as the first time (glue/txpolicy KnownInvalid). A client retrying a bad tx costs a Keccak256.
	if err = txpolicy.KnownInvalid(tx_bytes); err != nil {
		err = fmt.Errorf("Transaction rejected by daemon err '%s'", err)
		return
	}

	// fmt.Printf("txbytes length %d data %s\n", len(p.Tx_as_hex), p.Tx_as_hex)
	// lets add tx to pool, if we can do it, so  can every one else
	err = tx.Deserialize(tx_bytes)
	if err != nil {
		return
	}

	// lets try to add it to pool
	// r22: refuse a tx whose re-serialization (what we relay, store and mine) no node could decode (glue/txcanon)
	// r23: and one whose structure consensus refuses, before any state is read for it (glue/txprecheck)
	// r23b: and a grandfathered HF3 TXID or an out-of-window height (AdmitAt), exactly as the p2p relay path does;
	// the txid is computed once here and reused (it was computed for the reply anyway)
	txid := tx.GetHash()
	if err = txprecheck.AdmitAt(&tx, txid, tip_height, func(tx *transaction.Transaction) error { return txcanon.Admit(tx_bytes, tx, chain.Add_TX_To_Pool) }); err == nil {
		p2p.Broadcast_Tx(&tx, 0) // broadcast tx
		result.Status = "OK"
		result.TXID = fmt.Sprintf("%s", txid)
	} else {
		err = fmt.Errorf("Transaction %s rejected by daemon err '%s'", txid, err)
	}
	return
}
