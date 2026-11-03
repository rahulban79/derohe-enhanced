package main

import (
	"time"

	"github.com/gorilla/websocket"
)

// GETWORK_READ_TIMEOUT: derod pushes a job at least every 500 ms while a miner is connected, and on every new
// miniblock and block (cmd/derod/rpc/websocket_getwork_server.go dispatch loop). ReadJSON had no deadline, so a
// half-open connection (derod killed without a FIN, a sleeping NAT, a wedged daemon) left the miner hashing one stale
// job for ever and never reconnecting. 60 s of silence is > 100 missed pushes and > 3 block times.
// Side effect (r20 merge, F6 review): while derod cannot build a template (e.g. still syncing, SendJob returns
// early), it pushes nothing, so the miner reconnects about every 60 s until jobs flow again; that is expected.
const GETWORK_READ_TIMEOUT = 60 * time.Second

// read_job reads the next job, failing with a timeout error once d passes without one, so getwork reconnects.
func read_job(conn *websocket.Conn, d time.Duration, v interface{}) error {
	if d > 0 {
		conn.SetReadDeadline(time.Now().Add(d))
	}
	return conn.ReadJSON(v)
}
