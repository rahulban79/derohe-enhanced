// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package walletapi

// Concurrent ring-member balance fetch (Round 19). TransferPayload0 fetched every decoy's encrypted balance with one
// blocking DERO.GetEncryptedBalance round trip after another: ring 16 = 14 sequential round trips, ring 128 = 126.
// Against a remote daemon (the common light-wallet setup) that is ringsize x RTT before proof generation even starts.
// The decoys are still chosen exactly as before (same order, same dedupe, same -1 topoheight request); only the
// round trips overlap, RING_FETCH_PARALLEL at a time, and results are consumed in the original order, so the built
// transaction is identical for identical daemon answers.

import (
	"encoding/hex"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/errormsg"
	"github.com/deroproject/derohe/rpc"
)

const RING_FETCH_PARALLEL = 8

// fetch_ordered runs fetch(0..n-1) with at most workers in flight and returns the error of the LOWEST failing index
// (the one a sequential loop would have stopped at), or nil.
func fetch_ordered(n, workers int, fetch func(i int) error) error {
	if workers < 1 {
		workers = 1
	}
	errs := make([]error, n)
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			errs[i] = fetch(i)
		}(i)
	}
	wg.Wait()
	for i := range errs {
		if errs[i] != nil {
			return errs[i]
		}
	}
	return nil
}

// ring_member_balance is GetEncryptedBalanceAtTopoHeight(scid, -1, accountaddr) for an address that is not ours,
// minus the wallet/global bookkeeping that call does for -1 (daemon height, merkle hash, listeners), which made it
// unsafe to run concurrently. Error and SC-zero-balance semantics are the same.
func ring_member_balance(scid crypto.Hash, accountaddr string) (bits int, e *crypto.ElGamal, err error) {
	defer func() {
		if r := recover(); r != nil {
			logger.V(1).Error(nil, "Recovered while fetching ring member balance", "r", r, "stack", debug.Stack())
			err = fmt.Errorf("Recovered while fetching ring member balance r %s", r)
		}
	}()

	var result rpc.GetEncryptedBalance_Result
	if err = rpc_client.Call("DERO.GetEncryptedBalance", rpc.GetEncryptedBalance_Params{SCID: scid, Address: accountaddr, TopoHeight: -1}, &result); err != nil {
		logger.Error(err, "DERO.GetEncryptedBalance Call failed:")
		// all SCID users are considered registered and their balance is assumed zero
		if !scid.IsZero() && strings.Contains(strings.ToLower(err.Error()), strings.ToLower(errormsg.ErrAccountUnregistered.Error())) {
			addr, err1 := rpc.NewAddress(accountaddr)
			if err1 != nil {
				return 0, nil, err1
			}
			return 0, crypto.ConstructElGamal(addr.PublicKey.G1(), crypto.ElGamal_BASE_G), nil
		}
		return
	}
	if scid.IsZero() && result.Status != "OK" {
		return 0, nil, fmt.Errorf("%s", result.Status)
	}
	hexdecoded, err := hex.DecodeString(result.Data)
	if err != nil {
		return
	}
	var nb crypto.NonceBalance
	nb.Unmarshal(hexdecoded)
	return result.Bits, nb.Balance, nil
}

// RING_MAX_STALL_ROUNDS is how many consecutive decoy rounds may add no ring member before a transfer gives up.
// One round is one or two DERO.GetRandomAddress calls (up to 100 candidates each), so when the daemon still has
// eligible members a stall of this length is practically impossible; it happens when the daemon cannot supply
// ringsize-2 eligible accounts (they must have an unchanged balance over the last 5 blocks) or is not answering.
const RING_MAX_STALL_ROUNDS = 64

// ring_stall_delay is the pause before a decoy round that follows `stalls` rounds without progress: 50 ms more per
// stalled round, at most 1 s, so a stalled transfer polls the daemon gently and gives up after about 55 s in all
// (time in which the 5-block eligibility window can move on and free new members).
func ring_stall_delay(stalls int) time.Duration {
	d := time.Duration(stalls) * 50 * time.Millisecond
	if d > time.Second {
		d = time.Second
	}
	return d
}

// ring_progress turns the open-ended decoy loop into one that ends: check(have) is called before every round with
// the number of ring members collected so far.
type ring_progress struct {
	need   int
	last   int
	stalls int
	rounds int
}

func (r *ring_progress) check(have int) error {
	if r.rounds > 0 && have <= r.last {
		r.stalls++
	} else {
		r.stalls = 0
	}
	r.rounds++
	r.last = have
	if r.stalls >= RING_MAX_STALL_ROUNDS {
		return fmt.Errorf("not enough eligible ring members for ringsize %d: have %d after %d rounds without progress (the daemon only offers accounts whose balance did not change in the last 5 blocks); retry later or use a smaller ringsize", r.need, have, r.stalls)
	}
	return nil
}
