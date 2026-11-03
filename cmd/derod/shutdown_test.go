package main

import (
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type closeCounter struct{ n int32 }

func (c *closeCounter) Close() error { atomic.AddInt32(&c.n, 1); return nil }

// SIGTERM must start the ordered shutdown, and any signal must close the console so the blocked Readline returns
// (readline_loop exits only on EOF / Ctrl-C at the prompt / exit); a repeated signal must not panic
func TestExitOnSignalClosesConsole(t *testing.T) {
	for _, sig := range []os.Signal{syscall.SIGTERM, os.Interrupt} {
		sigs := make(chan os.Signal, 2)
		sigs <- sig
		sigs <- sig
		close(sigs)
		var c closeCounter
		var once sync.Once
		exit := make(chan bool)
		exit_on_signal(sigs, &c, func() { close_once(&once, exit) })
		select {
		case <-exit:
		case <-time.After(time.Second):
			t.Fatalf("%v: exit not requested", sig)
		}
		if atomic.LoadInt32(&c.n) == 0 {
			t.Fatalf("%v: console not closed, Readline would stay blocked and the node never shuts down", sig)
		}
	}
}

// OBS-06: SIGTERM (kill, launchd, system shutdown) must reach exit_on_signal, not only SIGINT
func TestExitSignalsIncludeSIGTERM(t *testing.T) {
	var term, intr bool
	for _, s := range exit_signals {
		term = term || s == syscall.SIGTERM
		intr = intr || s == os.Interrupt
	}
	if !term || !intr {
		t.Fatalf("exit_signals %v must contain SIGINT and SIGTERM", exit_signals)
	}
}
