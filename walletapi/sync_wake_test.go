// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package walletapi

import (
	"os"
	"strings"
	"testing"
	"time"
)

// A Height push ends the wait long before the 5 s fallback timer.
func TestSyncWakesOnHeight(t *testing.T) {
	quit := make(chan bool)
	wake := height_wake_chan()
	go func() { time.Sleep(20 * time.Millisecond); signal_height() }()
	start := time.Now()
	if !wait_next_sync(quit, wake, start, 0, 10*time.Second) {
		t.Fatal("quit reported without quit")
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("woke after %v: the Height signal was ignored", el)
	}
	// the channel was taken before the signal: a push that arrived during the pass is not lost
	wake = height_wake_chan()
	signal_height()
	start = time.Now()
	wait_next_sync(quit, wake, start, 0, 10*time.Second)
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("a Height that arrived during the pass was lost (%v)", el)
	}
}

// Without pushes the 5 s fallback still runs; pushes never make passes closer than min_gap; quit ends the loop.
func TestSyncWaitBounds(t *testing.T) {
	quit := make(chan bool)
	start := time.Now()
	if !wait_next_sync(quit, height_wake_chan(), start, 0, 50*time.Millisecond) {
		t.Fatal("timer path")
	}
	wake := height_wake_chan()
	signal_height()
	start = time.Now()
	wait_next_sync(quit, wake, start, 200*time.Millisecond, 10*time.Second)
	if el := time.Since(start); el < 200*time.Millisecond {
		t.Fatalf("pass after %v, min gap 200ms", el)
	}
	close(quit)
	if wait_next_sync(quit, height_wake_chan(), time.Now(), 0, 10*time.Second) {
		t.Fatal("quit not honoured")
	}
}

// Wiring: the Height notification signals, and sync_loop waits with wait_next_sync instead of a fixed sleep.
func TestSyncWakeWired(t *testing.T) {
	src, err := os.ReadFile("daemon_communication.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	h := strings.Index(s, `case "Height":`)
	sig := strings.Index(s, "signal_height()")
	if h < 0 || sig < h || sig-h > 300 {
		t.Fatal(`Notify_broadcaster's "Height" case must call signal_height()`)
	}
	loop := strings.Index(s, "func (w *Wallet_Memory) sync_loop() {")
	end := strings.Index(s[loop:], "\n}\n")
	body := s[loop : loop+end]
	if !strings.Contains(body, "height_wake_chan()") || !strings.Contains(body, "wait_next_sync(w.Quit, wake, started, SYNC_MIN_GAP, timeout)") ||
		strings.Contains(body, "time.Sleep(timeout) // wait 5 seconds\n\t}\n") {
		t.Fatal("sync_loop must wait for the next Height push (wait_next_sync), not sleep 5 s")
	}
}
