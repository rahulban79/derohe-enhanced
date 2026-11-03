// Copyright 2017-2018 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8

package main

import "runtime"
import "sync"
import "testing"

func Test_Part1(t *testing.T) {

}

func TestMemProfileRate(t *testing.T) {
	for env, want := range map[string]int{"": 0, "0": 0, "-5": 0, "abc": 0, "524288": 524288, "1": 1} {
		if got := mem_profile_rate(env); got != want {
			t.Fatalf("mem_profile_rate(%q) = %d, want %d", env, got, want)
		}
	}
}

// Fix E (r18 merge): the exit channel may be requested from both the signal handler and the console.
func TestCloseOnceIdempotent(t *testing.T) {
	var once sync.Once
	ch := make(chan bool)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("second close panicked: %v", r)
		}
	}()
	close_once(&once, ch)
	close_once(&once, ch)
	select {
	case <-ch:
	default:
		t.Fatalf("channel not closed")
	}
}

// r19: the contention profiles stay off unless asked for, and turn on when asked for.
func TestApplyContentionProfiling(t *testing.T) {
	defer runtime.SetMutexProfileFraction(0)
	defer runtime.SetBlockProfileRate(0)
	if m, b := apply_contention_profiling(func(string) string { return "" }); m != 0 || b != 0 {
		t.Fatalf("unset env must leave profiling off, got mutex=%d block=%d", m, b)
	}
	if got := runtime.SetMutexProfileFraction(-1); got != 0 {
		t.Fatalf("mutex profile fraction changed to %d with no env", got)
	}
	env := map[string]string{"DERO_MUTEX_PROFILE_FRACTION": "5", "DERO_BLOCK_PROFILE_RATE": "10000"}
	m, b := apply_contention_profiling(func(k string) string { return env[k] })
	if m != 5 || b != 10000 {
		t.Fatalf("got mutex=%d block=%d, want 5 and 10000", m, b)
	}
	if got := runtime.SetMutexProfileFraction(-1); got != 5 { // -1 reads the current value without changing it
		t.Fatalf("mutex profile fraction is %d, want 5", got)
	}
}
