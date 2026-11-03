// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package p2p

// Per-connection byte counters (Round 20). Connection.BytesIn/BytesOut existed upstream and are shown by the console
// "peers" command and by DERO.GetPeerInfo (r19), but nothing ever added to them: the live r19 node reported
// bytes_in 0 and bytes_out 0 for all 17 peers after 27 h. The codec now reads and writes through counting_conn, so
// the counters hold the RPC payload bytes (CBOR frames, after TLS) exchanged with each peer. Two atomic adds per
// Read/Write call; nothing on the wire changes.

import (
	"net"
	"sync/atomic"

	"github.com/cenkalti/rpc2"
)

// TRAFFIC_STATE_KEY carries an inbound session's counters from serve_inbound to the OnConnect handler.
const TRAFFIC_STATE_KEY = "traffic"

// counted_codec is the ONE place a peer codec is built (inbound serve_inbound and outbound
// process_outgoing_connection), so neither path can lose its counters again (r20 review: removing either wiring
// site left the whole p2p suite green; TestTrafficWiredOnBothPaths now pins both).
// outbound marks a connection we dialed: its large frames use the outbound frame budget pool (rpc_cbor_codec.go).
func counted_codec(tlsconn net.Conn, outbound bool) (*ClientCodec, *conn_traffic) {
	t := &conn_traffic{outbound: outbound}
	return NewCBORCodec(new_counting_conn(tlsconn, t)), t
}

// traffic_of returns the counters serve_inbound stored in an inbound session's state (nil if none).
func traffic_of(state *rpc2.State) *conn_traffic {
	if state == nil {
		return nil
	}
	v, _ := state.Get(TRAFFIC_STATE_KEY)
	t, _ := v.(*conn_traffic)
	return t
}

type conn_traffic struct {
	in, out  atomic.Uint64
	outbound bool // set at construction, read-only after (r21 merge: frame budget pool)
}

type counting_conn struct {
	net.Conn
	t *conn_traffic
}

func new_counting_conn(c net.Conn, t *conn_traffic) net.Conn {
	return counting_conn{Conn: c, t: t}
}

func (c counting_conn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		c.t.in.Add(uint64(n))
	}
	return
}

func (c counting_conn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		c.t.out.Add(uint64(n))
	}
	return
}

func (c *Connection) bytes_in() uint64 {
	n := c.BytesIn.Load()
	if c.traffic != nil {
		n += c.traffic.in.Load()
	}
	return n
}

func (c *Connection) bytes_out() uint64 {
	n := c.BytesOut.Load()
	if c.traffic != nil {
		n += c.traffic.out.Load()
	}
	return n
}
