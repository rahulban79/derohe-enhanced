// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

// Package nat asks the local internet gateway to forward the p2p UDP port (Round 19).
//
// A DERO node behind a home NAT gets no inbound peers: the live r18 node had 15 outgoing and 0 incoming
// connections because UDP 11011 was not forwarded. Three standard protocols let a host ask its gateway for a
// port mapping; this package speaks all three with the standard library only (no go.mod change):
//
//	PCP     RFC 6887  UDP 5351, version 2, MAP opcode
//	NAT-PMP RFC 6886  UDP 5351, version 0 (PCP's predecessor; a PCP server answers it too)
//	UPnP    IGD v1/v2 SSDP discovery + SOAP AddPortMapping on WANIPConnection / WANPPPConnection
//
// Transport only: nothing here is consensus-visible. Every reply is validated against the request (opcode,
// ports, nonce, source address) and every HTTP body is size-capped, because the gateway is just another host
// on the LAN.
package nat

import "crypto/rand"
import "encoding/binary"
import "errors"
import "fmt"
import "net"
import "strconv"
import "time"

const PMPPort = 5351 // NAT-PMP and PCP server port on the gateway

// Mapping is one granted port mapping.
type Mapping struct {
	Protocol     string        // "pcp" | "natpmp" | "upnp"
	Gateway      string        // gateway host (or control URL host for UPnP)
	InternalPort int           // our local UDP port
	ExternalPort int           // the port peers must dial on ExternalIP
	ExternalIP   net.IP        // may be nil when the protocol did not report it
	Lifetime     time.Duration // 0 = permanent (UPnP gateways that only allow permanent leases)
	nonce        [12]byte      // PCP: a mapping is renewed/deleted with the nonce that created it
	upnp         *igdService   // UPnP: where it was created
}

// Client is one port-mapping protocol.
type Client interface {
	Name() string
	Map(internal, external int, lifetime time.Duration) (Mapping, error)
	Unmap(m Mapping) error
}

// Retry schedule for the UDP protocols. RFC 6886 3.1 says 250 ms doubling up to 9 tries (64 s); a node start must
// not hang that long on a gateway that does not speak the protocol, so we stop after Tries (~3.75 s with 4).
type Retry struct {
	Initial time.Duration
	Tries   int
}

var DefaultRetry = Retry{Initial: 250 * time.Millisecond, Tries: 4}

var ErrNoResponse = errors.New("gateway did not answer")
var ErrUnsupportedVersion = errors.New("gateway does not support this protocol version")

// result codes (RFC 6886 3.5 / RFC 6887 7.4); the numbers overlap for 0-5
func resultError(proto string, code int) error {
	names := map[int]string{1: "unsupported version", 2: "not authorized / refused", 3: "network failure",
		4: "out of resources", 5: "unsupported opcode", 6: "unsupported option", 7: "malformed option",
		8: "network failure", 9: "no resources", 10: "unsupported protocol", 11: "user exceeded quota",
		12: "cannot provide external", 13: "address mismatch", 14: "excessive remote peers"}
	if code == 1 {
		return ErrUnsupportedVersion
	}
	n := names[code]
	if n == "" {
		n = "result " + strconv.Itoa(code)
	}
	return fmt.Errorf("%s: gateway refused: %s", proto, n)
}

// exchange sends req to gw:port and returns the first reply accept() takes, retransmitting per r. The socket is
// connected, so the kernel drops datagrams from any other source (a LAN host cannot inject replies from elsewhere).
func exchange(gw *net.UDPAddr, req []byte, r Retry, accept func([]byte) bool) ([]byte, net.IP, error) {
	c, err := net.DialUDP("udp4", nil, gw)
	if err != nil {
		return nil, nil, err
	}
	defer c.Close()
	local := c.LocalAddr().(*net.UDPAddr).IP
	buf := make([]byte, 1100) // PCP max message size (RFC 6887 7)
	wait := r.Initial
	for try := 0; try < r.Tries; try++ {
		if _, err := c.Write(req); err != nil {
			return nil, local, err
		}
		deadline := time.Now().Add(wait)
		for {
			c.SetReadDeadline(deadline)
			n, err := c.Read(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					break
				}
				// ICMP port unreachable surfaces as ECONNREFUSED on a connected socket: nothing listens there
				return nil, local, fmt.Errorf("%w: %v", ErrNoResponse, err)
			}
			if accept(buf[:n]) {
				return append([]byte{}, buf[:n]...), local, nil
			}
		}
		wait *= 2
	}
	return nil, local, ErrNoResponse
}

// ---------------------------------------------------------------- NAT-PMP (RFC 6886)

type NATPMP struct {
	Gateway *net.UDPAddr
	Retry   Retry
}

func (p *NATPMP) Name() string { return "natpmp" }

// ExternalIP: opcode 0.
func (p *NATPMP) ExternalIP() (net.IP, error) {
	resp, _, err := exchange(p.Gateway, []byte{0, 0}, p.Retry, func(b []byte) bool {
		return len(b) >= 2 && b[1] == 128 // version may be 0 (answer) or 2 (a PCP-only server's error)
	})
	if err != nil {
		return nil, err
	}
	if resp[0] != 0 {
		return nil, ErrUnsupportedVersion
	}
	if len(resp) < 12 {
		return nil, errors.New("natpmp: short reply")
	}
	if rc := int(binary.BigEndian.Uint16(resp[2:4])); rc != 0 {
		return nil, resultError("natpmp", rc)
	}
	return net.IPv4(resp[8], resp[9], resp[10], resp[11]).To4(), nil
}

func (p *NATPMP) request(internal, external int, lifetime time.Duration) (Mapping, error) {
	if internal < 1 || internal > 65535 || external < 0 || external > 65535 {
		return Mapping{}, errors.New("natpmp: port out of range")
	}
	req := make([]byte, 12)
	req[0], req[1] = 0, 1 // version 0, opcode 1 = map UDP
	binary.BigEndian.PutUint16(req[4:6], uint16(internal))
	binary.BigEndian.PutUint16(req[6:8], uint16(external))
	binary.BigEndian.PutUint32(req[8:12], uint32(lifetime/time.Second))
	resp, _, err := exchange(p.Gateway, req, p.Retry, func(b []byte) bool {
		return len(b) >= 4 && b[1] == 129 && (len(b) < 16 || int(binary.BigEndian.Uint16(b[8:10])) == internal)
	})
	if err != nil {
		return Mapping{}, err
	}
	if resp[0] != 0 {
		return Mapping{}, ErrUnsupportedVersion
	}
	if rc := int(binary.BigEndian.Uint16(resp[2:4])); rc != 0 {
		return Mapping{}, resultError("natpmp", rc)
	}
	if len(resp) < 16 {
		return Mapping{}, errors.New("natpmp: short reply")
	}
	m := Mapping{Protocol: "natpmp", Gateway: p.Gateway.IP.String(), InternalPort: internal,
		ExternalPort: int(binary.BigEndian.Uint16(resp[10:12])),
		Lifetime:     time.Duration(binary.BigEndian.Uint32(resp[12:16])) * time.Second}
	if lifetime > 0 && (m.ExternalPort == 0 || m.Lifetime == 0) {
		return Mapping{}, errors.New("natpmp: gateway granted no usable mapping")
	}
	return m, nil
}

func (p *NATPMP) Map(internal, external int, lifetime time.Duration) (Mapping, error) {
	m, err := p.request(internal, external, lifetime)
	if err != nil {
		return m, err
	}
	if ip, err := p.ExternalIP(); err == nil {
		m.ExternalIP = ip
	}
	return m, nil
}

// Unmap: RFC 6886 3.4, lifetime 0 and suggested external port 0 delete the mapping of this internal port.
func (p *NATPMP) Unmap(m Mapping) error {
	_, err := p.request(m.InternalPort, 0, 0)
	return err
}

// ---------------------------------------------------------------- PCP (RFC 6887)

type PCP struct {
	Gateway *net.UDPAddr
	Retry   Retry
}

func (p *PCP) Name() string { return "pcp" }

const pcpVersion = 2
const pcpOpMap = 1
const pcpProtoUDP = 17

func ipv4mapped(ip net.IP) []byte {
	b := make([]byte, 16)
	b[10], b[11] = 0xff, 0xff
	if v4 := ip.To4(); v4 != nil {
		copy(b[12:], v4)
	}
	return b
}

func (p *PCP) request(nonce [12]byte, client net.IP, internal, external int, lifetime time.Duration) (Mapping, net.IP, error) {
	if internal < 1 || internal > 65535 || external < 0 || external > 65535 {
		return Mapping{}, nil, errors.New("pcp: port out of range")
	}
	build := func(client net.IP) []byte {
		req := make([]byte, 60)
		req[0], req[1] = pcpVersion, pcpOpMap
		binary.BigEndian.PutUint32(req[4:8], uint32(lifetime/time.Second))
		copy(req[8:24], ipv4mapped(client))
		copy(req[24:36], nonce[:])
		req[36] = pcpProtoUDP
		binary.BigEndian.PutUint16(req[40:42], uint16(internal))
		binary.BigEndian.PutUint16(req[42:44], uint16(external))
		copy(req[44:60], ipv4mapped(net.IPv4zero)) // no preferred external address
		return req
	}
	accept := func(b []byte) bool {
		if len(b) >= 4 && b[0] == 0 && b[1] == 128+pcpOpMap { // NAT-PMP-only gateway: "unsupported version" in v0 format
			return true
		}
		return len(b) >= 60 && b[0] == pcpVersion && b[1] == 0x80|pcpOpMap && string(b[24:36]) == string(nonce[:]) &&
			b[36] == pcpProtoUDP && int(binary.BigEndian.Uint16(b[40:42])) == internal
	}
	if client == nil { // the client address must be the one the gateway sees: learn it from a connected socket
		c, err := net.DialUDP("udp4", nil, p.Gateway)
		if err != nil {
			return Mapping{}, nil, err
		}
		client = c.LocalAddr().(*net.UDPAddr).IP
		c.Close()
	}
	resp, _, err := exchange(p.Gateway, build(client), p.Retry, accept)
	if err != nil {
		return Mapping{}, client, err
	}
	if resp[0] != pcpVersion {
		return Mapping{}, client, ErrUnsupportedVersion
	}
	if rc := int(resp[3]); rc != 0 {
		return Mapping{}, client, resultError("pcp", rc)
	}
	m := Mapping{Protocol: "pcp", Gateway: p.Gateway.IP.String(), InternalPort: internal, nonce: nonce,
		ExternalPort: int(binary.BigEndian.Uint16(resp[42:44])),
		Lifetime:     time.Duration(binary.BigEndian.Uint32(resp[4:8])) * time.Second,
		ExternalIP:   net.IP(append([]byte{}, resp[44:60]...))}
	if v4 := m.ExternalIP.To4(); v4 != nil {
		m.ExternalIP = v4
	}
	if lifetime > 0 && (m.ExternalPort == 0 || m.Lifetime == 0) {
		return Mapping{}, client, errors.New("pcp: gateway granted no usable mapping")
	}
	return m, client, nil
}

func (p *PCP) Map(internal, external int, lifetime time.Duration) (Mapping, error) {
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Mapping{}, err
	}
	m, _, err := p.request(nonce, nil, internal, external, lifetime)
	return m, err
}

// Renew re-sends MAP with the creating nonce (RFC 6887 11.2.1), so the gateway extends the same mapping.
func (p *PCP) Renew(m Mapping, lifetime time.Duration) (Mapping, error) {
	n, _, err := p.request(m.nonce, nil, m.InternalPort, m.ExternalPort, lifetime)
	return n, err
}

// Unmap: lifetime 0 with the creating nonce deletes the mapping (RFC 6887 15).
func (p *PCP) Unmap(m Mapping) error {
	_, _, err := p.request(m.nonce, nil, m.InternalPort, 0, 0)
	return err
}
