package rwc

import (
	"context"
	"io"

	"github.com/coder/websocket"
)

type ReadWriteCloserNhooyr struct {
	WS *websocket.Conn
	r  io.Reader
	w  io.WriteCloser
}

// r27: the per-message read limit was a literal 2 MiB here while every gorilla server and client of this repo uses
// MaxMessageSize (32 MiB, sized for a hex SubmitBlock): the same daemon reply that a native wallet reads made the
// wasm wallet's reader fail. One ceiling for both adapters.
const NhooyrReadLimit = MaxMessageSize

func NewNhooyr(conn *websocket.Conn) *ReadWriteCloserNhooyr {
	return &ReadWriteCloserNhooyr{WS: conn}
}

func (rwc *ReadWriteCloserNhooyr) Read(p []byte) (n int, err error) {
	if rwc.r == nil {
		rwc.WS.SetReadLimit(NhooyrReadLimit)
		_, rwc.r, err = rwc.WS.Reader(context.Background())
		if err != nil {
			return 0, err
		}
	}
	for n = 0; n < len(p); {
		var m int
		m, err = rwc.r.Read(p[n:])
		n += m
		if err == io.EOF {
			rwc.r = nil
		}
		if err != nil {
			break
		}
	}
	return
}

func (rwc *ReadWriteCloserNhooyr) Write(p []byte) (n int, err error) {
	if rwc.w == nil {
		rwc.w, err = rwc.WS.Writer(context.Background(), websocket.MessageText)
		if err != nil {
			return 0, err
		}
	}
	for n = 0; n < len(p); {
		var m int
		m, err = rwc.w.Write(p[n:]) // r27: was p, the bug r19 fixed in rwc.go: a short write re-sent the start
		n += m
		if err != nil {
			break
		}
	}
	if err != nil || n == len(p) {
		// r27: was err = rwc.Close(), which replaced a failed write's error with Close's (nil when the close
		// succeeds): a short write was reported as success, against the io.Writer contract (n < len(p) => err != nil)
		if cerr := rwc.Close(); err == nil {
			err = cerr
		}
	}
	return
}

func (rwc *ReadWriteCloserNhooyr) Close() (err error) {
	if rwc.w != nil {
		err = rwc.w.Close()
		rwc.w = nil
	}
	return err
}
