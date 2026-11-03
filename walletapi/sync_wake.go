// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package walletapi

// r21 (rpcws): the wallet's sync loop slept a fixed 5 s between passes, although the daemon pushes "Height" on the
// websocket the moment the chain moves (Notify_broadcaster). A received transfer, a mined miniblock reward or the
// confirmation of a send therefore showed up 0-5 s (2.5 s on average) after the block, plus the sync itself. The loop
// now waits for the next Height push OR the 5 s timer, whichever is first, so a pass starts right after the block.
// The 5 s timer stays as the fallback for a daemon that sends no pushes (an HTTP-only proxy), and passes are at least
// SYNC_MIN_GAP apart so a daemon that floods Height cannot make the wallet spin.

import (
	"sync"
	"time"
)

var SYNC_MIN_GAP = 250 * time.Millisecond

var height_wake_mu sync.Mutex
var height_wake = make(chan struct{})

// signal_height wakes every wallet waiting in wait_next_sync (all wallets of the process share one daemon socket).
func signal_height() {
	height_wake_mu.Lock()
	close(height_wake)
	height_wake = make(chan struct{})
	height_wake_mu.Unlock()
}

// height_wake_chan is taken BEFORE a sync pass, so a Height that arrives during the pass starts the next one at once.
func height_wake_chan() <-chan struct{} {
	height_wake_mu.Lock()
	defer height_wake_mu.Unlock()
	return height_wake
}

// wait_next_sync waits until wake fires (but at least min_gap after started) or until max after now; false when quit
// closed.
func wait_next_sync(quit <-chan bool, wake <-chan struct{}, started time.Time, min_gap, max time.Duration) bool {
	t := time.NewTimer(max)
	defer t.Stop()
	select {
	case <-quit:
		return false
	case <-t.C:
		return true
	case <-wake:
	}
	if d := min_gap - time.Since(started); d > 0 {
		g := time.NewTimer(d)
		defer g.Stop()
		select {
		case <-quit:
			return false
		case <-g.C:
		}
	}
	return true
}
