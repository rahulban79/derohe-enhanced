//go:build !wasm
// +build !wasm

package rwc

import (
	"io"
	"time"

	"github.com/gorilla/websocket"
)

type ReadWriteCloser struct {
	WS *websocket.Conn
	// WriteTimeout, when > 0, is the deadline for every Write (r19 merge of rpcws RPCWS-5 and goparallel GP-04). gorilla
	// has no write deadline by default, so a peer that stops reading blocked the writer forever once the TCP send
	// buffer was full. On a timed-out (or any failed) write the socket is closed, which ends the reader too, so a
	// server goroutine waiting on this connection is released. Zero keeps the old behaviour (no deadline).
	WriteTimeout time.Duration
	r            io.Reader
	w            io.WriteCloser
}

// WithWriteTimeout sets WriteTimeout and returns rwc.
func (rwc *ReadWriteCloser) WithWriteTimeout(d time.Duration) *ReadWriteCloser {
	rwc.WriteTimeout = d
	return rwc
}

func New(conn *websocket.Conn) *ReadWriteCloser {
	return &ReadWriteCloser{WS: conn}
}

// NewLimited is New with conn's per-message read limit set; an oversized message makes Read return
// websocket.ErrReadLimit and gorilla closes the connection with CloseMessageTooBig.
func NewLimited(conn *websocket.Conn, limit int64) *ReadWriteCloser {
	conn.SetReadLimit(limit)
	return New(conn)
}

func (rwc *ReadWriteCloser) Read(p []byte) (n int, err error) {
	if rwc.r == nil {
		_, rwc.r, err = rwc.WS.NextReader()
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

func (rwc *ReadWriteCloser) Write(p []byte) (n int, err error) {
	if rwc.WriteTimeout > 0 {
		if err = rwc.WS.SetWriteDeadline(time.Now().Add(rwc.WriteTimeout)); err != nil {
			return 0, err
		}
		defer func() {
			if err != nil {
				rwc.WS.Close() // a stuck or broken peer: release the reader (and the server waiting on it) as well
			}
		}()
	}
	if rwc.w == nil {
		rwc.w, err = rwc.WS.NextWriter(websocket.TextMessage)
		if err != nil {
			return 0, err
		}
	}
	for n = 0; n < len(p); {
		var m int
		m, err = rwc.w.Write(p[n:]) // was p: a short write would have re-sent the start of the message
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

func (rwc *ReadWriteCloser) Close() (err error) {
	if rwc.w != nil {
		err = rwc.w.Close()
		rwc.w = nil
	}
	return err
}
