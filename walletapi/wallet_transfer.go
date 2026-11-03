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

package walletapi

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

//import "sort"
//import "math/rand"
//import cryptorand "crypto/rand"

//import "encoding/binary"

//import "encoding/json"

//import "github.com/vmihailenco/msgpack"

//import "github.com/deroproject/derohe/crypto/ringct"

//import "github.com/deroproject/derohe/globals"

//import "github.com/deroproject/derohe/ddn"

//import "github.com/deroproject/derohe/structures"
//import "github.com/deroproject/derohe/blockchain/inputmaturity"

/*
func (w *Wallet_Memory) Transfer_Simplified(addr string, value uint64, data []byte, scdata rpc.Arguments) (tx *transaction.Transaction, err error) {
	if sender, err := rpc.NewAddress(addr); err == nil {
		burn_value := uint64(0)
		return w.TransferPayload0(*sender, value, burn_value, 0, 0, false, data, scdata, false)
	}
	return
}
*/

// we should reply to an entry

// send amount to specific addresses
func (w *Wallet_Memory) TransferPayload0(transfers []rpc.Transfer, ringsize uint64, transfer_all bool, scdata rpc.Arguments, gasstorage uint64, dry_run bool) (tx *transaction.Transaction, err error) {

	//    var  transfer_details structures.Outgoing_Transfer_Details
	w.transfer_mutex.Lock()
	defer w.transfer_mutex.Unlock()

	//if len(transfers) == 0 {
	//	return nil,  fmt.Error("transfers is nil, cannot send.")
	//}

	if ringsize == 0 {
		ringsize = uint64(w.account.Ringsize) // use wallet ringsize, if ringsize not provided
	} else { // we need to use supplied ringsize
		if ringsize&(ringsize-1) != 0 {
			err = fmt.Errorf("ringsize should be power of 2. value %d", ringsize)
			return
		}
		if !(ringsize >= config.MIN_RINGSIZE && ringsize <= config.MAX_RINGSIZE) {
			err = fmt.Errorf("ringsize out of range value %d", ringsize)
			return
		}
	}

	//ringsize = 2

	// if wallet is online,take the fees from the network itself
	// otherwise use whatever user has provided
	//if w.GetMode()  {
	fees_per_kb := w.dynamic_fees_per_kb // TODO disabled as protection while lots more testing is going on
	//rlog.Infof("Fees per KB %d\n", fees_per_kb)
	//}

	if fees_per_kb == 0 {
		fees_per_kb = config.FEE_PER_KB
	}

	// user wants to do an SC call, but doesn't want any transfer, so we will transfer 0 to a random account
	if len(scdata) >= 1 && len(transfers) == 0 {
		var zeroscid crypto.Hash
		for _, k := range w.Random_ring_members(zeroscid) {
			if k != w.GetAddress().String() { /// make sure random member is not equal to ourself
				transfers = append(transfers, rpc.Transfer{Destination: k, Amount: 0})
				logger.V(3).Info("Doing 0 transfer to", "random_address", k)
				break
			}
		}
	}

	if len(transfers) >= 1 {
		has_base := false
		for i := range transfers {
			if transfers[i].SCID.IsZero() {
				has_base = true
			}
		}

		// if we do not have base we can not detect fees. this restriction should be lifted at suitable time
		if !has_base {
			var zeroscid crypto.Hash
			for _, k := range w.Random_ring_members(zeroscid) {
				if k != w.GetAddress().String() { /// make sure random member is not equal to ourself
					transfers = append(transfers, rpc.Transfer{Destination: k, Amount: 0})
					logger.V(3).Info("Doing 0 transfer to", "random_address", k)
					break
				}
			}
		}

	}

	for t := range transfers {
		var data []byte
		if data, err = transfers[t].Payload_RPC.CheckPack(transaction.PAYLOAD0_LIMIT); err != nil {
			return
		}

		if len(data) != transaction.PAYLOAD0_LIMIT {
			err = fmt.Errorf("Expecting exactly %d bytes data  but have  %d bytes", transaction.PAYLOAD0_LIMIT, len(data))
			return
		}
	}

	//fees := (ringsize + 1) * fees_per_kb // start with zero fees
	//	expected_fee := uint64(0)

	if transfer_all {
		err = fmt.Errorf("Transfer all not supported")
		return
		//transfers[0].Amount = w.account.Balance_Mature - fees
	}

	total_amount_required := map[crypto.Hash]uint64{}
	for i := range transfers {
		total_amount_required[transfers[i].SCID] = total_amount_required[transfers[i].SCID] + transfers[i].Amount + transfers[i].Burn
	}

	for i := range transfers {
		var current_balance uint64
		current_balance, _, err = w.GetDecryptedBalanceAtTopoHeight(transfers[i].SCID, -1, w.GetAddress().String())

		if err != nil {
			return
		}
		if total_amount_required[transfers[i].SCID] > current_balance {
			err = fmt.Errorf("Insufficent funds for scid %s Need %s Actual %s", transfers[i].SCID, FormatMoney(total_amount_required[transfers[i].SCID]), FormatMoney(current_balance))
			return
		}
	}

	for t := range transfers {

		if transfers[t].Destination == "" { // user skipped destination
			if transfers[t].SCID.IsZero() {
				err = fmt.Errorf("Main Destination cannot be empty")
				return
			}

			// we will try x times, to get a random ring ring member other than us, if ok, we move ahead
			ring_count := 0
			for i := 0; i < 20; i++ {
				//fmt.Printf("getting random ring member %d\n", i)
				scid := transfers[t].SCID
				if i > 17 { // if we cannot obtain ring member is 17 tries, choose  ring member from zero
					var zeroscid crypto.Hash
					scid = zeroscid
				}
				for _, k := range w.Random_ring_members(scid) {
					if k != w.GetAddress().String() {
						transfers[t].Destination = k
						i = 1000000 // break outer loop also
						ring_count++
						break
					}
				}
			}

		}

		if transfers[t].Destination == "" {
			err = fmt.Errorf("could not obtain random ring member for scid %s", transfers[t].SCID)
			return
		}

		// try to resolve name to address here
		if _, err = rpc.NewAddress(transfers[t].Destination); err != nil {
			if transfers[t].Destination, err = w.NameToAddress(transfers[t].Destination); err != nil {
				err = fmt.Errorf("could not decode name or address err '%s' name '%s'\n", err, transfers[t].Destination)
				return
			}
		}
	}

	//fmt.Printf("transfers %+v\n", transfers)

	var rings [][]*bn256.G1
	var rings_balances [][][]byte //initialize all maps

	var max_bits_array []int

	topoheight := int64(-1)
	var block_hash crypto.Hash

	var zeroscid crypto.Hash

	// noncetopo should be verified for all ring members simultaneously
	// this can lead to tx rejection
	// we currently bypass this since random members are chosen which have not been used in last 5 block
	_, noncetopo, block_hash, self_e, err := w.GetEncryptedBalanceAtTopoHeight(zeroscid, -1, w.GetAddress().String())
	if err != nil {
		err = fmt.Errorf("could not obtain encrypted balance for self err %s\n", err)
		return
	}

	// TODO, we should check nonce for base token and other tokens at the same time
	// right now, we are probably using a bit of luck here
	if daemon_topoheight >= int64(noncetopo)+3 { // if wallet has not been recently used, increase probability  of user's tx being successfully mined
		topoheight = daemon_topoheight - 3
	}

	_, _, block_hash, self_e, _ = w.GetEncryptedBalanceAtTopoHeight(transfers[0].SCID, topoheight, w.GetAddress().String())
	if err != nil {
		fmt.Printf("self unregistered err %s\n", err)
		return
	}

	er, err := w.GetSelfEncryptedBalanceAtTopoHeight(transfers[0].SCID, topoheight)
	if err != nil {
		err = fmt.Errorf("could not obtain encrypted balance for self err %s\n", err)
		return
	}
	height := uint64(er.Height)
	block_hash = er.BlockHash
	topoheight = er.Topoheight
	treehash := er.Merkle_Balance_TreeHash

	treehash_raw, err := hex.DecodeString(treehash)
	if err != nil {
		return
	}
	if len(treehash_raw) != 32 {
		err = fmt.Errorf("roothash is not of 32 bytes, probably daemon corruption '%s'", treehash)
		return
	}

	for t := range transfers {

		var ring []*bn256.G1
		var ring_balances [][]byte

		/*	if transfers[t].SCID.IsZero() {
				ringsize = uint64(ringsize)
			} else {
				ringsize = ringsize // only for easier testing
			}
		*/

		bits_needed := make([]int, ringsize, ringsize)

		bits_needed[0], _, _, self_e, err = w.GetEncryptedBalanceAtTopoHeight(transfers[t].SCID, topoheight, w.GetAddress().String())
		if err != nil {
			fmt.Printf("self unregistered err %s\n", err)
			return
		} else {
			ring_balances = append(ring_balances, self_e.Serialize())
			ring = append(ring, w.account.Keys.Public.G1())
		}

		var addr *rpc.Address
		if addr, err = rpc.NewAddress(transfers[t].Destination); err != nil {
			return
		}

		if addr.IsIntegratedAddress() && addr.Arguments.Validate_Arguments() != nil {
			err = fmt.Errorf("Integrated Address  arguments could not be validated.")
			return
		}

		if addr.IsIntegratedAddress() {
			if transfers[t].Payload_RPC, err = integrated_payload(addr, transfers[t].Payload_RPC); err != nil {
				return
			}
		}

		var dest_e *crypto.ElGamal
		bits_needed[1], _, _, dest_e, err = w.GetEncryptedBalanceAtTopoHeight(transfers[t].SCID, topoheight, addr.BaseAddress().String())
		if err != nil {
			fmt.Printf(" t %d unregistered1 '%s' %s\n", t, addr, err)
			return
		} else {
			ring_balances = append(ring_balances, dest_e.Serialize())
			ring = append(ring, addr.PublicKey.G1())
		}

		/*if len(w.account.RingMembers) < int(ringsize) {
			err = fmt.Errorf("We do not have enough ring members, expecting alteast %d but have only %d", int(ringsize), len(w.account.RingMembers))
			return
		}*/

		receiver_without_payment_id := addr.BaseAddress()

		//sending to self is not supported
		if w.GetAddress().String() == receiver_without_payment_id.String() {
			err = fmt.Errorf("Sending to self is not supported")
			return
		}

		deduplicator := map[string]bool{}
		deduplicator[receiver_without_payment_id.String()] = true
		deduplicator[w.GetAddress().String()] = true

		ring_stall := ring_progress{need: int(ringsize)}
		for ringsize != 2 {
			// r20 (TXF-05): the daemon only offers accounts whose balance did not change in the last 5 blocks; when
			// fewer than ringsize-2 qualify, no round adds a member and this loop used to spin forever
			if err = ring_stall.check(len(ring_balances)); err != nil {
				return
			}
			time.Sleep(ring_stall_delay(ring_stall.stalls))
			probable_members := w.Random_ring_members(transfers[t].SCID)
			if len(probable_members) <= 40 { // we do not have enough ring members for sure, extract ring members from base
				var zeroscid crypto.Hash
				probable_members = w.Random_ring_members(zeroscid)
			}
			// pick decoys exactly as the sequential loop did, then fetch their balances concurrently (ring_fetch.go)
			var picked []string
			for _, k := range probable_members {
				if len(ring_balances)+len(picked) == int(ringsize) {
					break
				}
				if _, collision := deduplicator[k]; collision {
					continue
				}
				deduplicator[k] = true
				if k != receiver_without_payment_id.String() && k != w.GetAddress().String() {
					picked = append(picked, k)
				}
			}
			if !w.GetMode() {
				err = fmt.Errorf("wallet is in offline mode")
				return
			}
			if !IsDaemonOnline() {
				err = fmt.Errorf("offline or not connected")
				return
			}
			picked_bits := make([]int, len(picked))
			picked_bal := make([]*crypto.ElGamal, len(picked))
			scid := transfers[t].SCID
			if err = fetch_ordered(len(picked), RING_FETCH_PARALLEL, func(i int) (ferr error) {
				if picked_bits[i], picked_bal[i], ferr = ring_member_balance(scid, picked[i]); ferr != nil {
					fmt.Printf(" unregistered %s\n", picked[i])
				}
				return
			}); err != nil {
				return
			}
			for i, k := range picked {
				var addr_member *rpc.Address
				if addr_member, err = rpc.NewAddress(k); err != nil {
					return
				}
				bits_needed[len(ring_balances)] = picked_bits[i]
				ring_balances = append(ring_balances, picked_bal[i].Serialize())
				ring = append(ring, addr_member.PublicKey.G1())
			}
			if len(ring_balances) == int(ringsize) {
				goto ring_members_collected
			}

		}
	ring_members_collected:

		rings = append(rings, ring)
		rings_balances = append(rings_balances, ring_balances)

		max_bits := 0
		for i := range bits_needed {
			if max_bits < bits_needed[i] {
				max_bits = bits_needed[i]
			}
		}
		max_bits_array = append(max_bits_array, max_bits)
	}
	max_bits := 0
	for i := range max_bits_array {
		if max_bits < max_bits_array[i] {
			max_bits = max_bits_array[i]
		}
	}
	max_bits += 6 // extra 6 bits

	// r22 merge (crypto C3 review fix): at ringsize 2 a ring {sender, receiver} has only 2 orders, so a third payload to
	// the same destination cannot get its own blinding scalar and BuildTransaction refuses it. Say so up front (the dry
	// run / fee estimate included) instead of the generic "please retry", which fails again on every retry.
	if err = ring_order_space(rings); err != nil {
		return
	}

	if !dry_run {
		tx = w.BuildTransaction(transfers, rings_balances, rings, block_hash, height, scdata, treehash_raw, max_bits, gasstorage)
	}

	if tx == nil {
		err = fmt.Errorf("somehow the tx could not be built, please retry")
	}

	return
}

// ErrRingOrderExhausted: more payloads to one destination than distinct ring orders at this ringsize (r22).
var ErrRingOrderExhausted = fmt.Errorf("too many transfers to the same destination for ringsize 2: at most 2 per transaction (each payload needs its own ring order for its own blinding scalar); split the transfers or use a larger ringsize")

// ring_order_space refuses a set of rings that pick_ring_order cannot satisfy for certain: more than 2 ringsize-2
// rings with the same receiver (rings[t][0] is the sender, rings[t][1] the receiver).
func ring_order_space(rings [][]*bn256.G1) error {
	per := map[string]int{}
	for _, ring := range rings {
		if len(ring) != 2 {
			continue
		}
		k := string(ring[1].EncodeCompressed())
		per[k]++
		if per[k] > 2 {
			return ErrRingOrderExhausted
		}
	}
	return nil
}

// integrated_payload merges the arguments of an integrated destination address into a transfer's payload.
// With an empty payload the address supplies it (only a destination port is understood, as before). Round 23: with
// a caller-supplied payload the address's destination port used to be dropped silently, so a deposit to an
// exchange-style integrated address that also carried a comment arrived without the port that identifies the
// depositor. Now the port is added when the payload has none, and a payload whose port differs is refused.
func integrated_payload(addr *rpc.Address, payload rpc.Arguments) (rpc.Arguments, error) {
	if len(payload) == 0 {
		for _, arg := range addr.Arguments {
			if arg.Name == rpc.RPC_DESTINATION_PORT && addr.Arguments.Has(rpc.RPC_DESTINATION_PORT, rpc.DataUint64) {
				payload = append(payload, rpc.Argument{Name: rpc.RPC_DESTINATION_PORT, DataType: rpc.DataUint64, Value: addr.Arguments.Value(rpc.RPC_DESTINATION_PORT, rpc.DataUint64).(uint64)})
				continue
			}
			return nil, fmt.Errorf("integrated address used, but don't know how to process %+v", addr.Arguments)
		}
		return payload, nil
	}
	if !addr.Arguments.Has(rpc.RPC_DESTINATION_PORT, rpc.DataUint64) {
		return payload, nil
	}
	port := addr.Arguments.Value(rpc.RPC_DESTINATION_PORT, rpc.DataUint64).(uint64)
	if payload.Has(rpc.RPC_DESTINATION_PORT, rpc.DataUint64) {
		if p := payload.Value(rpc.RPC_DESTINATION_PORT, rpc.DataUint64).(uint64); p != port {
			return nil, fmt.Errorf("payload destination port %d differs from the integrated address port %d", p, port)
		}
		return payload, nil
	}
	for _, arg := range payload {
		if arg.Name == rpc.RPC_DESTINATION_PORT { // present with another data type: do not guess
			return nil, fmt.Errorf("payload destination port has data type %s, integrated address needs %s", arg.DataType, rpc.DataUint64)
		}
	}
	merged := append(append(rpc.Arguments{}, payload...), rpc.Argument{Name: rpc.RPC_DESTINATION_PORT, DataType: rpc.DataUint64, Value: port})
	// r23 merge: the caller's payload passed the size check alone; with the port appended it may not fit, and the
	// builder ignores CheckPack's error (a short payload then panics in SerializeHeader). Refuse it explicitly.
	if _, err := merged.CheckPack(transaction.PAYLOAD0_LIMIT); err != nil {
		return nil, fmt.Errorf("payload plus integrated-address port exceeds %d bytes: %v", transaction.PAYLOAD0_LIMIT, err)
	}
	return merged, nil
}
