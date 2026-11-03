// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package nat

// Read-only reachability probe (Round 22, --p2p-nat=probe).
//
// Inbound has been 0 since Round 2 and the operator cannot tell from the node whether (a) the router would accept a
// mapping request (--p2p-nat=auto would then work), (b) the router's own WAN address is carrier-grade or private
// (then NO router setting can make the node reachable: the ISP's NAT sits upstream), or (c) only a manual UDP
// forward is missing. The probe answers that without changing anything on the gateway: it asks each protocol for
// the external address only (PCP ANNOUNCE, RFC 6887 14.1; NAT-PMP opcode 0, RFC 6886 3.2; UPnP
// GetExternalIPAddress) and never creates, renews or deletes a mapping. The external address itself is reduced to a
// class ("public", "cgnat", "private") so the result can be shown through --rpc-bind without leaking the WAN IP.

import (
	"net"
)

// ProbeResult is one protocol's answer.
type ProbeResult struct {
	Protocol      string `json:"protocol"`
	Available     bool   `json:"available"`                // the gateway answered this protocol
	ExternalClass string `json:"external_class,omitempty"` // public | cgnat | private | unknown
	Error         string `json:"error,omitempty"`
}

// ExternalClass reduces an external address to what decides reachability, without revealing it.
func ExternalClass(ip net.IP) string {
	switch {
	case ip == nil || ip.IsUnspecified():
		return "unknown"
	case ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast():
		return "private"
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
		return "cgnat"
	}
	return "public"
}

const pcpOpAnnounce = 0

// pcp_announce sends a PCP ANNOUNCE (lifetime 0, no mapping) and reports whether a PCP server answered.
func pcp_announce(gw *net.UDPAddr, r Retry) error {
	c, err := net.DialUDP("udp4", nil, gw)
	if err != nil {
		return err
	}
	client := c.LocalAddr().(*net.UDPAddr).IP
	c.Close()
	req := make([]byte, 24)
	req[0], req[1] = pcpVersion, pcpOpAnnounce
	copy(req[8:24], ipv4mapped(client))
	resp, _, err := exchange(gw, req, r, func(b []byte) bool {
		if len(b) >= 4 && b[0] == 0 && b[1] == 128 { // NAT-PMP-only gateway answering "unsupported version"
			return true
		}
		return len(b) >= 24 && b[0] == pcpVersion && b[1] == 0x80|pcpOpAnnounce
	})
	if err != nil {
		return err
	}
	if resp[0] != pcpVersion {
		return ErrUnsupportedVersion
	}
	if rc := int(resp[3]); rc != 0 {
		return resultError("pcp", rc)
	}
	return nil
}

// Probe asks the gateway (PCP and NAT-PMP at gw:port; UPnP via SSDP) what it supports. Read-only.
func Probe(gw net.IP, port int, r Retry, u *UPnP) (out []ProbeResult) {
	if r.Tries == 0 {
		r = DefaultRetry
	}
	if port == 0 {
		port = PMPPort
	}
	if gw != nil {
		addr := &net.UDPAddr{IP: gw, Port: port}
		res := ProbeResult{Protocol: ModePCP}
		if err := pcp_announce(addr, r); err != nil {
			res.Error = probe_err(err)
		} else {
			res.Available, res.ExternalClass = true, "unknown" // ANNOUNCE carries no external address
		}
		out = append(out, res)

		res = ProbeResult{Protocol: ModeNATPMP}
		if ip, err := (&NATPMP{Gateway: addr, Retry: r}).ExternalIP(); err != nil {
			res.Error = probe_err(err)
		} else {
			res.Available, res.ExternalClass = true, ExternalClass(ip)
		}
		out = append(out, res)
	} else {
		out = append(out, ProbeResult{Protocol: ModePCP, Error: "no default gateway"}, ProbeResult{Protocol: ModeNATPMP, Error: "no default gateway"})
	}
	if u == nil {
		u = &UPnP{}
	}
	res := ProbeResult{Protocol: ModeUPnP}
	if ip, err := u.ExternalIP(); err != nil {
		res.Error = probe_err(err)
	} else {
		res.Available, res.ExternalClass = true, ExternalClass(ip)
	}
	return append(out, res)
}

// ProbeVerdict turns probe results into one operator instruction. Pure (tested).
func ProbeVerdict(rs []ProbeResult) string {
	any_available, cgnat, private, public := false, false, false, false
	for _, r := range rs {
		if !r.Available {
			continue
		}
		any_available = true
		switch r.ExternalClass {
		case "cgnat":
			cgnat = true
		case "private":
			private = true
		case "public":
			public = true
		}
	}
	switch {
	case cgnat:
		return "router's WAN address is carrier-grade NAT: no router setting can make this node reachable; ask the ISP for a public IPv4 address (outbound-only operation keeps working)"
	case private && !public:
		return "router's WAN address is private: a second router or modem NATs upstream; forward UDP on BOTH devices, or put the modem in bridge mode"
	case any_available:
		return "router supports automatic mapping: restart derod with --p2p-nat=auto (or forward UDP manually)"
	}
	return "router answers no mapping protocol (PCP, NAT-PMP, UPnP off or absent): forward UDP (not TCP) for the --p2p-bind port to this host in the router's port-forwarding page"
}

// Probe duration is bounded by Retry for PCP and NAT-PMP and by the UPnP SSDP wait plus its HTTP timeout (the live
// run took 2.3 s). r22 merge: the unused ProbeTime constant was removed.

// probe_err is what a ProbeResult carries for err (r22 merge, SP22-NAT review): a kind, never the raw text, because
// GetSyncInfo shows it through --rpc-bind and a UPnP error can quote a URL an SSDP responder supplied.
func probe_err(err error) string { return error_kind(err.Error()) }

// error_kind keeps the probe log free of addresses: it maps an error text to a short kind (a kind maps to itself).
func error_kind(e string) string {
	switch {
	case e == "", e == "no-response", e == "unsupported-version", e == "other", e == "no default gateway":
		return e
	case e == ErrNoResponse.Error() || len(e) >= len(ErrNoResponse.Error()) && e[:len(ErrNoResponse.Error())] == ErrNoResponse.Error():
		return "no-response"
	case e == ErrUnsupportedVersion.Error():
		return "unsupported-version"
	}
	return "other"
}
