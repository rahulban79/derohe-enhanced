// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package p2p

// Eclipse and peer-table hardening (Round 18). Local dialing/relay policy only: nothing here changes which blocks,
// miniblocks or transactions are valid.
//
//  1. Outbound diversity. Upstream dials any candidate, so one operator with many addresses in one /16 (one cloud
//     region) can occupy every outgoing slot; with 0 inbound (UDP not forwarded) outgoing slots are ALL of our
//     view of the chain. At most MAX_OUTBOUND_PER_NETGROUP outgoing connections per IPv4 /16 or IPv6 /32.
//     The live peers.json (2026-10-24, 25 peers) has exactly one /16 holding two peers, so a cap of 2 drops none.
//     Non-public addresses (LAN, loopback shadows) and seed/priority/exclusive nodes are exempt.
//  2. Gossip sanity. Upstream Peer_Add accepts any string a peer gossips, including host names (resolved on each
//     dial) and private/loopback addresses (our node then dials into its own LAN on a stranger's say-so). Gossiped
//     entries must be literal IP:port with a valid port; a PUBLIC peer may only gossip PUBLIC addresses (its LAN is
//     not ours), a LAN peer may still gossip LAN addresses so local clusters keep working.
//  3. Grey-table caps. Gossiped (never connected) entries are capped per netgroup and in total, so a few sybils
//     cannot flood the table with thousands of dead addresses that the dialer then wastes its slots on.
//  4. INV bounds. NotifyINV had no length limit: one frame of ~131072 random tx hashes (the CBOR decoder's default
//     array cap) cost two failed file opens each in Block_tx_store.ReadTX, and an INV is not a heavy() call.

import "errors"
import "net"
import "strconv"
import "strings"
import "sync"
import "time"

import "github.com/deroproject/derohe/glue/txprecheck"
import "github.com/deroproject/derohe/metrics"

const MAX_OUTBOUND_PER_NETGROUP = 2 // outgoing connections per IPv4 /16 or IPv6 /32
const MAX_GREY_PER_NETGROUP = 8     // gossiped, never-connected entries per netgroup
const MAX_GREY_TOTAL = 1024         // gossiped, never-connected entries in total
const DIAL_PENDING_TTL = 20 * time.Second
const DIVERSITY_REFUSAL_BACKOFF = 2 * time.Minute // a peer refused by the netgroup cap is not redialled before this

// INV caps: an announcement must never ask for more than Peer.GetObject itself accepts (rpc_object_request.go)
const MAX_INV_BLOCKS = 4096
const MAX_INV_TXS = 4096
const MAX_INV_CHUNKS = 128
const MAX_INV_TOTAL = 4096

// netgroup returns the diversity bucket of an IP (with or without port); "" means exempt (non-public or unparsable).
func netgroup(addr string) string {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil || !is_public(ip) {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return strconv.Itoa(int(v4[0])) + "." + strconv.Itoa(int(v4[1]))
	}
	ip = ip.To16()
	return net.IP(append(append([]byte{}, ip[:4]...), make([]byte, 12)...)).String() + "/32"
}

var diversity_mu sync.Mutex
var dial_pending = map[string]time.Time{} // ip -> when we started dialing it

// note_dial records an outgoing dial so that dials still in flight count against their netgroup.
func note_dial(addr string, now time.Time) {
	diversity_mu.Lock()
	defer diversity_mu.Unlock()
	for k, t := range dial_pending {
		if now.Sub(t) > DIAL_PENDING_TTL {
			delete(dial_pending, k)
		}
	}
	dial_pending[ParseIPNoError(addr)] = now
}

// outbound_group_counts counts outgoing connections (and dials in flight) per netgroup, excluding exempt ones.
// skip is the connection being admitted: neither its pool entry nor its OWN pending dial counts against its group
// (maintain_connection_to_peers notes the dial before connect_with_endpoint, so counting it made the effective
// cap 1 per /16 instead of MAX_OUTBOUND_PER_NETGROUP).
func outbound_group_counts(now time.Time, skip *Connection) map[string]int {
	counts := map[string]int{}
	seen := map[string]bool{}
	if skip != nil {
		seen[Address(skip)] = true
	}
	connection_map.Range(func(k, value interface{}) bool {
		c := value.(*Connection)
		if c == skip || c.Incoming {
			return true
		}
		ip := Address(c)
		seen[ip] = true
		if g := netgroup(ip); g != "" {
			counts[g]++
		}
		return true
	})
	diversity_mu.Lock()
	for ip, t := range dial_pending {
		if seen[ip] || now.Sub(t) > DIAL_PENDING_TTL || IsAddressConnected(ip) {
			continue
		}
		if g := netgroup(ip); g != "" {
			counts[g]++
		}
	}
	diversity_mu.Unlock()
	return counts
}

// forget_dial drops a pending dial (the dial was refused or finished without a connection).
func forget_dial(addr string) {
	diversity_mu.Lock()
	delete(dial_pending, ParseIPNoError(addr))
	diversity_mu.Unlock()
}

// defer_peer_after_diversity_refusal: the refusal says nothing bad about the peer (no FailCount, so a grey peer is
// not purged), but without a back-off the dialer picked it again on the next 200 ms tick / 10 s grey gap.
func defer_peer_after_diversity_refusal(addr string, now time.Time) {
	forget_dial(addr)
	p := GetPeerInList(ParseIPNoError(addr))
	if p == nil {
		return
	}
	after := uint64(now.Add(DIVERSITY_REFUSAL_BACKOFF).Unix())
	peer_mutex.Lock()
	if p.ConnectAfter < after {
		p.ConnectAfter = after
	}
	peer_mutex.Unlock()
}

// outbound_group_full reports whether dialing / keeping addr would exceed the per-netgroup outbound cap.
func outbound_group_full(addr string, counts map[string]int) bool {
	g := netgroup(addr)
	if g == "" || never_ban(ParseIPNoError(addr)) {
		return false
	}
	return counts[g] >= MAX_OUTBOUND_PER_NETGROUP
}

// gossip_address_acceptable: a literal IP:port with a usable port; a public gossiper may only teach public addresses.
func gossip_address_acceptable(addr string, from_ip string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
		return false
	}
	if from := net.ParseIP(from_ip); from != nil && is_public(from) && !is_public(ip) {
		return false
	}
	return true
}

// grey_admissible reports whether one more gossiped entry may join the table (caller holds peer_mutex).
func grey_admissible_locked(addr string) bool {
	g := netgroup(addr)
	total, in_group := 0, 0
	for _, v := range peer_map {
		if v.Whitelist {
			continue
		}
		total++
		if g != "" && netgroup(v.Address) == g {
			in_group++
		}
	}
	if total >= MAX_GREY_TOTAL {
		return false
	}
	return g == "" || in_group < MAX_GREY_PER_NETGROUP
}

// peer_add_gossip is Peer_Add for addresses a peer told us about (never for the peer's own connected address).
func peer_add_gossip(addr string, from_ip string) bool {
	if !gossip_address_acceptable(addr, from_ip) {
		return false
	}
	// r21 merge (SP21-2 fix): purge first, as Peer_Add would. Otherwise a FailCount-8 grey entry still in the map reads
	// as known, skips the quarantine check, and Peer_Add's own clean_up purges (quarantines) and re-inserts it at
	// FailCount 0 in the same call.
	clean_up()
	peer_mutex.Lock()
	_, known := peer_map[ParseIPNoError(addr)]
	ok := known || grey_admissible_locked(addr)
	peer_mutex.Unlock()
	if !ok {
		return false
	}
	if !known && grey_quarantined(ParseIPNoError(addr), time.Now()) { // purged for failures recently (grey_quarantine.go)
		metrics.Set.GetOrCreateCounter("p2p_gossip_quarantine_refusals_total").Inc()
		return false
	}
	Peer_Add(&Peer{Address: addr, LastConnected: uint64(time.Now().UTC().Unix())})
	return true
}

// inv_within_bounds: an INV may not announce more than GetObject would let us fetch in one request.
func inv_within_bounds(r *ObjectList) bool {
	return len(r.Block_list) <= MAX_INV_BLOCKS && len(r.Tx_list) <= MAX_INV_TXS && len(r.Chunk_list) <= MAX_INV_CHUNKS &&
		len(r.Block_list)+len(r.Tx_list)+len(r.Chunk_list) <= MAX_INV_TOTAL
}

// is_tx_verification_failure: only the proof-verification rejection of Add_TX_To_Pool is scored. "already mined",
// "reference not found", nonce/double-spend and low-fee rejections depend on timing and on which branch a node is
// on, so an honest relay can trigger them; a failed Verify_Transaction_NonCoinbase cannot (blockchain.go
// "Incoming TX %s could not be verified"). r23 merge: a glue/txprecheck refusal (ErrStructure) is the same class:
// its rules restate Verify_Transaction_NonCoinbase's structural checks, so no stock node relays such a tx. Before the
// precheck existed these txs reached verification and were scored; unscored, a peer could relay them forever.
func is_tx_verification_failure(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "could not be verified") || errors.Is(err, txprecheck.ErrStructure))
}
