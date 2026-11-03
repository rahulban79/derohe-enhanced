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

package p2p

import "fmt"
import "net"
import "bytes"
import "context"

import "time"

import "github.com/deroproject/derohe/config"
import "github.com/deroproject/derohe/globals"
import "github.com/blang/semver/v4"
import "github.com/deroproject/derohe/metrics"

// verify incoming handshake for number of checks such as mainnet/testnet etc etc
func Verify_Handshake(handshake *Handshake_Struct) bool {
	// the version string is peer-supplied: MustParse panicked on a malformed one and v.Pre[0] on a version with
	// no pre-release tag (both only cost the connection, under handle_connection_panic). Refuse instead; which
	// versions are accepted is unchanged.
	if len(handshake.DaemonVersion) > 128 {
		return false
	}
	v, err := semver.Parse(handshake.DaemonVersion)
	if err != nil {
		return false
	}

	if v.Major >= 3 && v.Minor >= 5 && v.Patch >= 0 {

	} else {
		if len(v.Pre) == 0 {
			return false
		}
		var pre int
		fmt.Sscanf(v.Pre[0].String(), "%d", &pre) // make sure previous releases can connect
		if pre < 88 {
			return false
		}
	}

	return bytes.Equal(handshake.Network_ID[:], globals.Config.Network_ID[:])
}

func (handshake *Handshake_Struct) Fill() {
	fill_common(&handshake.Common) // fill common info

	handshake.ProtocolVersion = "1.0.0"
	handshake.DaemonVersion = config.Version.String()
	handshake.Tag = node_tag
	handshake.UTC_Time = int64(time.Now().UTC().Unix()) // send our UTC time
	handshake.Local_Port = uint32(advertised_port())    // the port peers must dial: NAT external port if mapped
	handshake.Peer_ID = GetPeerID()                     // give our randomly generated peer id
	handshake.Pruned = safeLocatePruneTopo()

	//	handshake.Flags = // add any flags necessary

	copy(handshake.Network_ID[:], globals.Config.Network_ID[:])
}

// this is used only once
// all clients start with handshake, then other party sends avtive to mark that connection is active
func (connection *Connection) dispatch_test_handshake() {
	defer handle_connection_panic(connection)
	var request, response Handshake_Struct
	request.Fill()

	//scan our peer list and send peers which have been recently communicated
	request.PeerList = get_peer_list_specific(Address(connection))

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if err := connection.Client.CallWithContext(ctx, "Peer.Handshake", request, &response); err != nil {
		connection.logger.V(4).Info("cannot handshake", "error", err.Error())
		connection.note_handshake_failure()
		connection.exit()
		return
	}

	if !Verify_Handshake(&response) { // if not same network boot off
		connection.logger.V(3).Info("terminating connection network id mismatch ", "networkid", response.Network_ID)
		connection.note_handshake_failure()
		connection.exit()
		return
	}
	connection.update(&response.Common) // update common information
	if !Connection_Add(connection) {    // add connection to pool
		connection.exit()
		return
	}
	connection.handshake_accepted(&response)

	// TODO we must also add the peer to our list
	// which can be distributed to other peers
	if connection.Port != 0 && connection.Port <= 65535 { // peer is saying it has an open port, handshake is success so add peer

		var p Peer
		if net.ParseIP(Address(connection)).To4() != nil { // if ipv4
			p.Address = fmt.Sprintf("%s:%d", Address(connection), connection.Port)
		} else { // if ipv6
			p.Address = fmt.Sprintf("[%s]:%d", Address(connection), connection.Port)
		}
		p.ID = connection.Peer_ID

		p.LastConnected = uint64(time.Now().UTC().Unix())

		Peer_Add(&p)
	}

	// parse delivered peer list as grey list
	connection.logger.V(4).Info("Peer provides peers", "count", len(response.PeerList))
	for i := range response.PeerList {
		if i < 13 {
			peer_add_gossip(response.PeerList[i].Addr, Address(connection))
		}
	}

	connection.State.Store(ACTIVE)
}

// handshake_accepted runs once our outgoing handshake verified and the connection joined the pool: it clears any
// unlisted-endpoint dial back-off (seed_backoff.go) and copies the peer's advertised fields.
func (connection *Connection) handshake_accepted(response *Handshake_Struct) {
	note_unlisted_success(Address(connection))
	note_proven(Address(connection), time.Now()) // r24 (B30): this address receives our packets (proven_lane.go)

	if len(response.ProtocolVersion) < 128 {
		connection.ProtocolVersion = response.ProtocolVersion
	}

	if len(response.DaemonVersion) < 128 {
		connection.DaemonVersion = response.DaemonVersion
	}
	connection.Port = response.Local_Port
	connection.Peer_ID = response.Peer_ID
	if len(response.Tag) < 128 {
		connection.Tag = response.Tag
	}
	if response.Pruned >= 1 {
		connection.Pruned = response.Pruned
	}
}

// used to ping pong
func (c *Connection) Ping(request Dummy, response *Dummy) error {
	defer handle_connection_panic(c)
	fill_common_T1(&request.Common)
	c.update(&request.Common)                             // update common information
	fill_common(&response.Common)                         // fill common info
	fill_common_T0T1T2(&request.Common, &response.Common) // fill time related information
	return nil
}

// serves handhake requests
func (c *Connection) Handshake(request Handshake_Struct, response *Handshake_Struct) error {
	defer handle_connection_panic(c)
	if request.Peer_ID == GetPeerID() { // check if self connection exit
		//rlog.Tracef(1, "Same peer ID, probably self connection, disconnecting from this client")
		c.exit()
		return fmt.Errorf("Same peer ID")
	}

	if !Verify_Handshake(&request) { // if not same network boot off
		logger.V(2).Info("kill connection network id mismatch peer network id.", "Network_ID", request.Network_ID)
		c.exit()
		return fmt.Errorf("NID mismatch")
	}

	response.Fill()

	c.update(&request.Common) // update common information
	if c.State.Load() == ACTIVE {
		for i := range request.PeerList {
			if i < 31 {
				peer_add_gossip(request.PeerList[i].Addr, Address(c))
			}
		}
	}
	if !c.Incoming {
		Peer_SetSuccess(c.Addr.String())
	}

	return nil
}

// note_handshake_failure applies the peer list's exponential back-off to an outgoing dial that got no valid
// handshake. KCP runs over UDP, so kcp.DialWithOptions practically never fails and Peer_SetFail (controller.go,
// dial error only) was dead code: unreachable peers were redialled every 10 s forever (live r17: KCP_ActiveOpens
// rose 0.69/s while the peer count stayed at 17).
func (connection *Connection) note_handshake_failure() {
	if connection.Incoming || connection.Addr == nil {
		return
	}
	metrics.Set.GetOrCreateCounter("p2p_handshake_failures_total").Inc()
	ip := ParseIPNoError(connection.Addr.String())
	p := GetPeerInList(ip)
	metrics.Set.GetOrCreateCounter(`p2p_handshake_failures_by_kind_total{kind="` + handshake_failure_kind(p) + `"}`).Inc()
	if p == nil { // a seed node never made it into the list: Peer_SetFail cannot back it off (seed_backoff.go)
		note_unlisted_failure(ip, time.Now())
	}
	Peer_SetFail(ip)
}

// handshake_failure_kind splits failed outgoing handshakes (r21): "grey" (gossiped, never connected: the
// purge/re-gossip cycle that grey_quarantine.go stops), "white" (connected before; capped back-off) and "unlisted"
// (seed or priority node outside the peer list; seed_backoff.go).
func handshake_failure_kind(p *Peer) string {
	if p == nil {
		return "unlisted"
	}
	peer_mutex.Lock()
	defer peer_mutex.Unlock()
	if p.Whitelist {
		return "white"
	}
	return "grey"
}
