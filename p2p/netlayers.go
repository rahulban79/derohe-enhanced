// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package p2p

// Network-layer reachability and packet sizing (Round 19). Transport/local policy only: nothing here changes
// which blocks, miniblocks or transactions are valid, and every wire byte a peer receives is still a valid KCP
// segment of the existing format.
//
//  1. --p2p-nat=auto|pcp|natpmp|upnp|off (default off): ask the gateway to forward the p2p UDP port (p2p/nat),
//     renew at half the lease, delete the mapping on shutdown. While a mapping is active the handshake advertises
//     the gateway's EXTERNAL port, which is the one peers must dial (it equals the local port unless the gateway
//     had to pick another). GetSyncInfo reports the mapping under "p2p_nat".
//  2. KCP packet size per path: kcp-go sends UDP payloads of up to IKCP_MTU_DEF = 1400 bytes (20 B AES nonce+CRC
//     and 8 B FEC header included), i.e. 1448-byte IPv6 packets. IPv6 only guarantees 1280 and routers never
//     fragment IPv6, so on a 1280-MTU path (6in4/Teredo/many VPNs) every full-size segment needs PMTUD that UDP
//     senders do not do: it is dropped. IPv6 peers get 1232-byte payloads (1280 - 40 IPv6 - 8 UDP). KCP segment
//     length is in each segment header, so the receiver needs no change. IPv4 keeps 1400 (DERO_KCP_MTU overrides
//     both, 576..1400).
//  3. Optional DSCP marking (DERO_P2P_DSCP=0..63, default 0 = unchanged), e.g. 46 (EF) so home Wi-Fi WMM queues
//     put miniblock datagrams in the voice class.

import "net"
import "sync"
import "sync/atomic"
import "time"

import "github.com/deroproject/derohe/globals"
import "github.com/deroproject/derohe/p2p/nat"

const KCP_MTU_DEFAULT = 1400 // kcp-go IKCP_MTU_DEF, what every session uses unless told otherwise
const KCP_MTU_IPV6 = 1232    // IPv6 minimum link MTU 1280 - 40 (IPv6 header) - 8 (UDP header)

// KCP_MTU_OVERRIDE: env DERO_KCP_MTU, 0 = per-family default
var KCP_MTU_OVERRIDE = env_int("DERO_KCP_MTU", 0, 0, KCP_MTU_DEFAULT)

// P2P_DSCP: env DERO_P2P_DSCP, 0 = do not mark
var P2P_DSCP = env_int("DERO_P2P_DSCP", 0, 0, 63)

// dscp_applied / dscp_failed count the sockets tunekcp and tune_listener marked (or failed to mark): what the code
// actually did, for tests and the operator (verifier NL-05).
var dscp_applied, dscp_failed uint64

func note_dscp(err error) {
	if err != nil {
		atomic.AddUint64(&dscp_failed, 1)
		return
	}
	atomic.AddUint64(&dscp_applied, 1)
}

// kcp_mtu_for returns the UDP payload budget for a session to remote.
func kcp_mtu_for(remote net.Addr) int {
	if KCP_MTU_OVERRIDE > 0 {
		if KCP_MTU_OVERRIDE < 576 {
			return 576
		}
		return KCP_MTU_OVERRIDE
	}
	if ua, ok := remote.(*net.UDPAddr); ok && ua.IP != nil && ua.IP.To4() == nil {
		return KCP_MTU_IPV6 // native IPv6 (an IPv4 peer on the dual-stack listener is v4-mapped: To4 != nil)
	}
	return KCP_MTU_DEFAULT
}

// ---- NAT port mapping

var nat_mu sync.Mutex
var nat_manager *nat.Manager

// nat_mode reads --p2p-nat; absent or invalid means off.
func nat_mode() string {
	v, ok := globals.Arguments["--p2p-nat"]
	if !ok || v == nil {
		return nat.ModeOff
	}
	s, _ := v.(string)
	if !nat.ValidMode(s) {
		logger.Error(nil, "invalid --p2p-nat (use auto, pcp, natpmp, upnp, probe or off); NAT port mapping disabled", "value", s)
		return nat.ModeOff
	}
	return s
}

// start_nat begins mapping the bound p2p port when --p2p-nat asks for it.
func start_nat(port int) {
	mode := nat_mode()
	if mode == nat.ModeOff || port <= 0 {
		return
	}
	nat_mu.Lock()
	defer nat_mu.Unlock()
	if nat_manager != nil {
		return
	}
	nat_manager = nat.Start(nat.Options{Mode: mode, InternalPort: port, Log: func(msg string, kv ...interface{}) {
		logger.Info(msg, kv...)
	}})
}

func stop_nat() {
	nat_mu.Lock()
	m := nat_manager
	nat_mu.Unlock()
	m.Stop(3 * time.Second) // nil-safe
}

// advertised_port is the port the handshake tells peers to dial: the gateway's external port while a NAT mapping
// is active, else the bound port.
func advertised_port() int {
	nat_mu.Lock()
	m := nat_manager
	nat_mu.Unlock()
	if p := m.ExternalPort(); p > 0 {
		return p
	}
	return P2P_Port
}

// NAT_Status reports the port mapping for GetSyncInfo.
func NAT_Status() nat.Status {
	nat_mu.Lock()
	m := nat_manager
	nat_mu.Unlock()
	if m == nil {
		return nat.Status{Mode: nat_mode(), InternalPort: P2P_Port}
	}
	return m.Status()
}
