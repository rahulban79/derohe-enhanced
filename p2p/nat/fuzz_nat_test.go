// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package nat

// r20 security: fuzz targets for every reply a (malicious) gateway or LAN host can send the NAT client: NAT-PMP and
// PCP datagrams, SSDP answers, the UPnP description XML and SOAP responses. Each must end in a value or an error,
// never a panic, and a granted mapping must carry a usable port. The seeds run in every go test.

import (
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var fuzzRetry = Retry{Initial: 15 * time.Millisecond, Tries: 1}

// udp_replier answers every datagram with the current reply. With echo set, a reply of >= 44 bytes gets the
// request's PCP nonce, protocol and internal port copied in, so the fuzzer reaches the code behind PCP's accept().
type udp_replier struct {
	conn  *net.UDPConn
	reply atomic.Value // []byte
	echo  int32
}

func new_udp_replier(t testing.TB) *udp_replier {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &udp_replier{conn: c}
	r.reply.Store([]byte{})
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			out := append([]byte{}, r.reply.Load().([]byte)...)
			if atomic.LoadInt32(&r.echo) == 1 && n >= 44 && len(out) >= 44 {
				copy(out[24:36], buf[24:36]) // nonce
				out[36] = buf[36]            // protocol
				copy(out[40:42], buf[40:42]) // internal port
			}
			c.WriteToUDP(out, from)
		}
	}()
	t.Cleanup(func() { c.Close() })
	return r
}

func (r *udp_replier) addr() *net.UDPAddr { return r.conn.LocalAddr().(*net.UDPAddr) }

func check_mapping(t *testing.T, m Mapping, err error, lifetime time.Duration) {
	if err == nil && lifetime > 0 && (m.ExternalPort <= 0 || m.ExternalPort > 65535 || m.Lifetime <= 0) {
		t.Fatalf("granted mapping without a usable port/lifetime: %+v", m)
	}
}

func FuzzGatewayReplies(f *testing.F) {
	pmp := make([]byte, 16)
	pmp[1] = 129
	binary.BigEndian.PutUint16(pmp[8:10], 11011)
	binary.BigEndian.PutUint16(pmp[10:12], 11011)
	binary.BigEndian.PutUint32(pmp[12:16], 3600)
	ext := []byte{0, 128, 0, 0, 0, 0, 0, 0, 203, 0, 113, 7}
	pcp := make([]byte, 60)
	pcp[0], pcp[1] = pcpVersion, 0x80|pcpOpMap
	binary.BigEndian.PutUint32(pcp[4:8], 3600)
	binary.BigEndian.PutUint16(pcp[42:44], 11011)
	for _, s := range [][]byte{pmp, ext, pcp, {0, 129}, {0, 128 + pcpOpMap, 0, 1}, {2, 0x81, 0, 5}, make([]byte, 1100), {}} {
		f.Add(s, true)
		f.Add(s, false)
	}
	r := new_udp_replier(f)
	f.Fuzz(func(t *testing.T, reply []byte, echo bool) {
		if len(reply) > 1100 {
			reply = reply[:1100]
		}
		r.reply.Store(reply)
		if echo {
			atomic.StoreInt32(&r.echo, 1)
		} else {
			atomic.StoreInt32(&r.echo, 0)
		}
		p := &NATPMP{Gateway: r.addr(), Retry: fuzzRetry}
		p.ExternalIP()
		m, err := p.Map(11011, 11011, time.Hour)
		check_mapping(t, m, err, time.Hour)
		p.Unmap(Mapping{InternalPort: 11011})
		c := &PCP{Gateway: r.addr(), Retry: fuzzRetry}
		m, err = c.Map(11011, 11011, time.Hour)
		check_mapping(t, m, err, time.Hour)
		c.Renew(m, time.Hour)
		c.Unmap(m)
	})
}

// FuzzSSDPReply: a LAN host answers M-SEARCH with arbitrary bytes. discover must never panic and must only return
// http LOCATIONs on the answering host.
func FuzzSSDPReply(f *testing.F) {
	f.Add([]byte("HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1:1900/desc.xml\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nLOCATION: http://8.8.8.8/desc.xml\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nLOCATION: file:///etc/passwd\r\n\r\n"))
	f.Add([]byte("garbage"))
	r := new_udp_replier(f)
	f.Fuzz(func(t *testing.T, reply []byte) {
		if len(reply) > 2048 {
			reply = reply[:2048]
		}
		r.reply.Store(reply)
		u := &UPnP{SSDP: r.addr().String(), Wait: 20 * time.Millisecond}
		locs, err := u.discover()
		if err != nil {
			return
		}
		for _, l := range locs {
			p, err := lan_http_url(l)
			if err != nil || !net.ParseIP(p.Hostname()).Equal(net.IPv4(127, 0, 0, 1)) {
				t.Fatalf("discover returned %q (%v)", l, err)
			}
		}
	})
}

// FuzzUPnPResponses: the description XML and the SOAP bodies come from the gateway's HTTP server.
func FuzzUPnPResponses(f *testing.F) {
	desc := `<?xml version="1.0"?><root><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl</controlURL></service></serviceList></device></root>`
	soapIP := `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>203.0.113.7</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>`
	fault := `<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>718</errorCode><errorDescription>x</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`
	f.Add(desc, soapIP, 200)
	f.Add(desc, fault, 500)
	f.Add(strings.Replace(desc, "/ctl", "http://8.8.8.8/ctl", 1), soapIP, 200)
	f.Add(`<root><device>`+strings.Repeat("<deviceList><device>", 200)+`</device></root>`, "", 200)
	f.Add("", "", 404)
	var cur atomic.Value
	type bodies struct {
		desc, soap string
		code       int
	}
	cur.Store(bodies{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := cur.Load().(bodies)
		if r.URL.Path == "/desc" {
			w.Write([]byte(b.desc))
			return
		}
		code := b.code
		if code < 100 || code > 599 {
			code = 200
		}
		w.WriteHeader(code)
		w.Write([]byte(b.soap))
	}))
	f.Cleanup(srv.Close)
	f.Fuzz(func(t *testing.T, desc, soap string, code int) {
		cur.Store(bodies{desc, soap, code})
		u := &UPnP{Describe: srv.URL + "/desc", Timeout: time.Second}
		if ip, err := u.ExternalIP(); err == nil && ip == nil {
			t.Fatal("nil external IP without an error")
		}
		m, err := u.Map(11011, 11011, time.Hour)
		check_mapping(t, m, err, time.Hour)
		if u.svc != nil {
			if _, err := lan_http_url(u.svc.control); err != nil {
				t.Fatalf("control URL %q accepted: %v", u.svc.control, err)
			}
		}
	})
}
