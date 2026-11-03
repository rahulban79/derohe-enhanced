// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package nat

import "encoding/binary"
import "fmt"
import "io/ioutil"
import "net"
import "net/http"
import "net/http/httptest"
import "strings"
import "sync"
import "testing"
import "time"

var fastRetry = Retry{Initial: 40 * time.Millisecond, Tries: 3}

type fakeMapping struct {
	ext      int
	lifetime uint32
	nonce    string
}

// fakeGateway speaks NAT-PMP and/or PCP on a loopback UDP port.
type fakeGateway struct {
	conn       *net.UDPConn
	pcp, pmp   bool
	extIP      net.IP
	grantLife  uint32 // 0 = grant what was asked
	mu         sync.Mutex
	maps       map[int]*fakeMapping
	requests   int
	bogusFirst bool // answer every request first with a reply that must be ignored
}

func newFakeGateway(t *testing.T, pcp, pmp bool, configure ...func(*fakeGateway)) *fakeGateway {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	g := &fakeGateway{conn: c, pcp: pcp, pmp: pmp, extIP: net.IPv4(203, 0, 113, 7).To4(), maps: map[int]*fakeMapping{}}
	for _, f := range configure {
		f(g)
	}
	go g.serve()
	t.Cleanup(func() { c.Close() })
	return g
}

func (g *fakeGateway) addr() *net.UDPAddr { return g.conn.LocalAddr().(*net.UDPAddr) }

func (g *fakeGateway) mapped(internal int) *fakeMapping {
	g.mu.Lock()
	defer g.mu.Unlock()
	if m := g.maps[internal]; m != nil {
		c := *m
		return &c
	}
	return nil
}

func (g *fakeGateway) serve() {
	buf := make([]byte, 1100)
	for {
		n, from, err := g.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		req := append([]byte{}, buf[:n]...)
		g.mu.Lock()
		g.requests++
		var resp, bogus []byte
		switch {
		case n >= 2 && req[0] == 0 && !g.pmp:
			resp = []byte{2, 128 + req[1], 0, 1} // PCP-only server: unsupported version
		case n >= 2 && req[0] == 0 && req[1] == 0:
			resp = make([]byte, 12)
			resp[1] = 128
			copy(resp[8:], g.extIP)
		case n >= 12 && req[0] == 0 && req[1] == 1:
			in := int(binary.BigEndian.Uint16(req[4:6]))
			ext := int(binary.BigEndian.Uint16(req[6:8]))
			life := binary.BigEndian.Uint32(req[8:12])
			resp = make([]byte, 16)
			resp[1] = 129
			binary.BigEndian.PutUint16(resp[8:10], uint16(in))
			if life == 0 {
				delete(g.maps, in)
			} else {
				if ext == 0 {
					ext = in
				}
				if g.grantLife != 0 {
					life = g.grantLife
				}
				g.maps[in] = &fakeMapping{ext: ext, lifetime: life}
				binary.BigEndian.PutUint16(resp[10:12], uint16(ext))
				binary.BigEndian.PutUint32(resp[12:16], life)
			}
			bogus = append([]byte{}, resp...)
			binary.BigEndian.PutUint16(bogus[8:10], uint16(in+1)) // reply for somebody else's port
			binary.BigEndian.PutUint16(bogus[10:12], 1)
		case n == 24 && req[0] == 2 && req[1] == 0 && !g.pcp: // PCP ANNOUNCE (probe.go) at a NAT-PMP-only server
			resp = []byte{0, 128, 0, 1}
		case n == 24 && req[0] == 2 && req[1] == 0:
			resp = make([]byte, 24)
			resp[0], resp[1] = 2, 0x80
		case n >= 60 && req[0] == 2 && req[1] == 1 && !g.pcp:
			resp = []byte{0, 128 + 1, 0, 1} // NAT-PMP-only server answering a PCP request
		case n >= 60 && req[0] == 2 && req[1] == 1:
			in := int(binary.BigEndian.Uint16(req[40:42]))
			ext := int(binary.BigEndian.Uint16(req[42:44]))
			life := binary.BigEndian.Uint32(req[4:8])
			nonce := string(req[24:36])
			resp = make([]byte, 60)
			resp[0], resp[1] = 2, 0x81
			copy(resp[24:60], req[24:60])
			cur := g.maps[in]
			if cur != nil && cur.nonce != nonce {
				resp[3] = 2 // NOT_AUTHORIZED: someone else's mapping
			} else if life == 0 {
				delete(g.maps, in)
			} else {
				if ext == 0 {
					ext = in
				}
				if g.grantLife != 0 {
					life = g.grantLife
				}
				g.maps[in] = &fakeMapping{ext: ext, lifetime: life, nonce: nonce}
				binary.BigEndian.PutUint32(resp[4:8], life)
				binary.BigEndian.PutUint16(resp[42:44], uint16(ext))
				copy(resp[44:60], ipv4mapped(g.extIP))
			}
			bogus = append([]byte{}, resp...)
			bogus[24] ^= 0xff // wrong nonce
			bogus[3] = 0
			binary.BigEndian.PutUint16(bogus[42:44], 1)
		}
		bf := g.bogusFirst
		g.mu.Unlock()
		if bf && bogus != nil {
			g.conn.WriteToUDP(bogus, from)
		}
		if resp != nil {
			g.conn.WriteToUDP(resp, from)
		}
	}
}

func TestNATPMPMapRenewUnmap(t *testing.T) {
	g := newFakeGateway(t, false, true)
	c := &NATPMP{Gateway: g.addr(), Retry: fastRetry}
	m, err := c.Map(11011, 11011, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if m.ExternalPort != 11011 || m.Lifetime != time.Hour || !m.ExternalIP.Equal(g.extIP) || m.Protocol != "natpmp" {
		t.Fatalf("mapping %+v", m)
	}
	if g.mapped(11011) == nil {
		t.Fatal("gateway holds no mapping")
	}
	if err := c.Unmap(m); err != nil {
		t.Fatal(err)
	}
	if g.mapped(11011) != nil {
		t.Fatal("mapping not deleted")
	}
}

func TestPCPMapRenewUsesSameNonceAndUnmaps(t *testing.T) {
	g := newFakeGateway(t, true, true)
	c := &PCP{Gateway: g.addr(), Retry: fastRetry}
	m, err := c.Map(11011, 11011, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if m.ExternalPort != 11011 || !m.ExternalIP.Equal(g.extIP) || m.Protocol != "pcp" {
		t.Fatalf("mapping %+v", m)
	}
	// the gateway refuses a MAP for an existing mapping with another nonce, so renewal must reuse it
	if _, err := c.Renew(m, time.Hour); err != nil {
		t.Fatalf("renew refused: %v", err)
	}
	if err := c.Unmap(m); err != nil {
		t.Fatal(err)
	}
	if g.mapped(11011) != nil {
		t.Fatal("mapping not deleted")
	}
}

// A LAN host (or a confused gateway) answering for another port / another nonce must not be believed.
func TestRepliesForOtherRequestsAreIgnored(t *testing.T) {
	g := newFakeGateway(t, true, true, func(g *fakeGateway) { g.bogusFirst = true })
	pm, err := (&NATPMP{Gateway: g.addr(), Retry: fastRetry}).request(11011, 11011, time.Hour)
	if err != nil || pm.ExternalPort != 11011 {
		t.Fatalf("natpmp took a reply meant for another port: %+v %v", pm, err)
	}
	g.mu.Lock()
	g.maps = map[int]*fakeMapping{}
	g.mu.Unlock()
	pc, err := (&PCP{Gateway: g.addr(), Retry: fastRetry}).Map(11011, 11011, time.Hour)
	if err != nil || pc.ExternalPort != 11011 {
		t.Fatalf("pcp took a reply with a foreign nonce: %+v %v", pc, err)
	}
}

func TestPCPOnNATPMPOnlyGatewayReportsUnsupported(t *testing.T) {
	g := newFakeGateway(t, false, true)
	_, err := (&PCP{Gateway: g.addr(), Retry: fastRetry}).Map(11011, 11011, time.Hour)
	if err != ErrUnsupportedVersion {
		t.Fatalf("want ErrUnsupportedVersion, got %v", err)
	}
}

func TestNoGatewayFailsFast(t *testing.T) {
	c, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	addr := c.LocalAddr().(*net.UDPAddr)
	c.Close() // nothing listens there now
	start := time.Now()
	_, err := (&NATPMP{Gateway: addr, Retry: fastRetry}).Map(11011, 11011, time.Hour)
	if err == nil {
		t.Fatal("mapped against nothing")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("took %v", time.Since(start))
	}
}

func TestManagerAutoFallsBackRenewsAndUnmapsOnStop(t *testing.T) {
	// NAT-PMP only, so auto must fall through PCP; a 1 s lease is renewed every 500 ms
	g := newFakeGateway(t, false, true, func(g *fakeGateway) { g.grantLife = 1 })
	m := Start(Options{Mode: ModeAuto, InternalPort: 11011, Gateway: net.IPv4(127, 0, 0, 1), GatewayPort: g.addr().Port,
		Retry: fastRetry, MinRenew: 50 * time.Millisecond, UPnP: &UPnP{SSDP: "127.0.0.1:9", Wait: 50 * time.Millisecond}})
	deadline := time.Now().Add(5 * time.Second)
	for m.Status().Renewals < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	st := m.Status()
	if !st.Active || st.Protocol != "natpmp" || st.ExternalPort != 11011 || st.Renewals < 2 || st.ExternalIP != "203.0.113.7" {
		t.Fatalf("status %+v", st)
	}
	if m.ExternalPort() != 11011 {
		t.Fatal("ExternalPort")
	}
	m.Stop(2 * time.Second)
	if g.mapped(11011) != nil {
		t.Fatal("mapping left on the gateway after Stop")
	}
	if m.Status().Active || m.ExternalPort() != 0 {
		t.Fatal("still active after Stop")
	}
	m.Stop(time.Second) // idempotent
}

func TestManagerRetriesAfterFailure(t *testing.T) {
	c, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	port := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	m := Start(Options{Mode: ModeNATPMP, InternalPort: 11011, Gateway: net.IPv4(127, 0, 0, 1), GatewayPort: port,
		Retry: fastRetry, RetryAfter: 50 * time.Millisecond})
	defer m.Stop(time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for m.Status().Failures < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	st := m.Status()
	if st.Active || st.Failures < 2 || st.Error == "" || m.ExternalPort() != 0 {
		t.Fatalf("status %+v", st)
	}
}

func TestWarningForNonPublicExternal(t *testing.T) {
	for ip, want := range map[string]bool{"10.1.2.3": true, "100.64.1.1": true, "192.168.1.1": true, "203.0.113.7": false, "198.51.100.1": false} {
		if got := warning(net.ParseIP(ip)) != ""; got != want {
			t.Errorf("%s: warning=%v want %v", ip, got, want)
		}
	}
	if warning(nil) != "" {
		t.Error("nil ip warned")
	}
}

func TestRenewInterval(t *testing.T) {
	if d := renew_interval(time.Hour, time.Hour, 30*time.Second); d != 30*time.Minute {
		t.Fatal(d)
	}
	if d := renew_interval(10*time.Second, time.Hour, 30*time.Second); d != 30*time.Second {
		t.Fatal(d)
	}
	if d := renew_interval(0, time.Hour, 30*time.Second); d != 30*time.Minute { // permanent UPnP lease
		t.Fatal(d)
	}
}

func TestParseGatewayOutputs(t *testing.T) {
	linux := "Iface\tDestination\tGateway \tFlags\nwlan0\t0001A8C0\t00000000\t0001\neth0\t00000000\t0101A8C0\t0003\n"
	if ip := parse_proc_net_route(linux); ip.String() != "192.168.1.1" {
		t.Fatalf("linux %v", ip)
	}
	mac := "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n"
	if ip := parse_route_output(mac); ip.String() != "192.168.1.1" {
		t.Fatalf("mac %v", ip)
	}
	win := "Network Destination        Netmask          Gateway       Interface  Metric\n          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     25\n"
	if ip := parse_route_output(win); ip.String() != "192.168.1.1" {
		t.Fatalf("win %v", ip)
	}
	if parse_route_output("nothing here") != nil || parse_proc_net_route("") != nil {
		t.Fatal("parsed garbage")
	}
}

// ---------------------------------------------------------------- UPnP

type fakeIGD struct {
	srv       *httptest.Server
	ssdp      *net.UDPConn
	mu        sync.Mutex
	maps      map[string]string // ext port -> internal client:port
	permOnly  bool
	conflict  map[string]bool
	location  string        // overrides the advertised LOCATION
	addDelay  time.Duration // AddPortMapping answers this late (a slow gateway)
	control   string        // overrides the controlURL in the description
	lastLease string
}

// configure runs before any server goroutine starts, so the handlers read the settings without a data race
func newFakeIGD(t *testing.T, configure func(*fakeIGD)) *fakeIGD {
	f := &fakeIGD{maps: map[string]string{}, conflict: map[string]bool{}}
	if configure != nil {
		configure(f)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/desc.xml", func(w http.ResponseWriter, r *http.Request) {
		ctl := "/ctl/IPConn"
		if f.control != "" {
			ctl = f.control
		}
		fmt.Fprintf(w, `<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><deviceList><device>
<deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType><serviceList><service>
<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>%s</controlURL></service></serviceList>
</device></deviceList></device></deviceList></device></root>`, ctl)
	})
	mux.HandleFunc("/ctl/IPConn", func(w http.ResponseWriter, r *http.Request) {
		b, _ := ioutil.ReadAll(r.Body)
		body := string(b)
		get := func(tag string) string {
			i := strings.Index(body, "<"+tag+">")
			j := strings.Index(body, "</"+tag+">")
			if i < 0 || j < 0 {
				return ""
			}
			return body[i+len(tag)+2 : j]
		}
		fault := func(code int) {
			w.WriteHeader(500)
			fmt.Fprintf(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>%d</errorCode><errorDescription>x</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`, code)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch action := r.Header.Get("SOAPAction"); {
		case strings.Contains(action, "#GetExternalIPAddress"):
			fmt.Fprint(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewExternalIPAddress>198.51.100.9</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>`)
		case strings.Contains(action, "#AddPortMapping"):
			if f.addDelay > 0 {
				f.mu.Unlock()
				time.Sleep(f.addDelay)
				f.mu.Lock()
			}
			if get("NewProtocol") != "UDP" {
				fault(402)
				return
			}
			if f.permOnly && get("NewLeaseDuration") != "0" {
				fault(725)
				return
			}
			if f.conflict[get("NewExternalPort")] {
				fault(718)
				return
			}
			f.lastLease = get("NewLeaseDuration")
			f.maps[get("NewExternalPort")] = get("NewInternalClient") + ":" + get("NewInternalPort")
			fmt.Fprint(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body/></s:Envelope>`)
		case strings.Contains(action, "#DeletePortMapping"):
			if _, ok := f.maps[get("NewExternalPort")]; !ok {
				fault(714)
				return
			}
			delete(f.maps, get("NewExternalPort"))
			fmt.Fprint(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body/></s:Envelope>`)
		default:
			fault(401)
		}
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f.ssdp = c
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !strings.HasPrefix(string(buf[:n]), "M-SEARCH") {
				continue
			}
			loc := f.srv.URL + "/desc.xml"
			if f.location != "" {
				loc = f.location
			}
			c.WriteToUDP([]byte("HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nLOCATION: "+loc+"\r\n\r\n"), from)
		}
	}()
	return f
}

func (f *fakeIGD) upnp() *UPnP {
	return &UPnP{SSDP: f.ssdp.LocalAddr().String(), Wait: 200 * time.Millisecond, Timeout: 2 * time.Second}
}

func TestUPnPDiscoverMapUnmap(t *testing.T) {
	f := newFakeIGD(t, nil)
	u := f.upnp()
	m, err := u.Map(11011, 11011, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	lease := f.lastLease
	f.mu.Unlock()
	if m.ExternalPort != 11011 || m.ExternalIP.String() != "198.51.100.9" || m.Lifetime != time.Hour || lease != "3600" {
		t.Fatalf("mapping %+v lease %s", m, lease)
	}
	f.mu.Lock()
	got := f.maps["11011"]
	f.mu.Unlock()
	if got != "127.0.0.1:11011" {
		t.Fatalf("gateway forwards to %q", got)
	}
	if err := u.Unmap(m); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.maps) != 0 {
		t.Fatal("not deleted")
	}
}

func TestUPnPPermanentOnlyAndConflict(t *testing.T) {
	f := newFakeIGD(t, func(f *fakeIGD) { f.permOnly = true; f.conflict["11011"] = true })
	m, err := f.upnp().Map(11011, 11011, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	lease := f.lastLease
	f.mu.Unlock()
	if m.Lifetime != 0 || m.ExternalPort == 11011 || m.ExternalPort < 49152 || lease != "0" {
		t.Fatalf("mapping %+v", m)
	}
}

// a forged SSDP reply may not steer derod's HTTP requests to a non-LAN host or to a different host than the describer
func TestUPnPRefusesForeignURLs(t *testing.T) {
	for _, bad := range []string{"http://198.51.100.1/desc.xml", "https://127.0.0.1/desc.xml", "http://example.com/desc.xml", "file:///etc/passwd"} {
		if _, err := lan_http_url(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	for _, good := range []string{"http://192.168.1.1:5000/rootDesc.xml", "http://127.0.0.1:1/x", "http://10.0.0.1/x"} {
		if _, err := lan_http_url(good); err != nil {
			t.Errorf("refused %s: %v", good, err)
		}
	}
	f := newFakeIGD(t, func(f *fakeIGD) { f.location = "http://198.51.100.1/desc.xml" })
	if _, err := f.upnp().Map(11011, 11011, time.Hour); err == nil {
		t.Fatal("followed a non-LAN LOCATION")
	}
	f2 := newFakeIGD(t, func(f *fakeIGD) { f.control = "http://127.0.0.2:1/ctl" }) // other host than the describer
	if _, err := f2.upnp().Map(11011, 11011, time.Hour); err == nil || !strings.Contains(err.Error(), "not on the describing host") {
		t.Fatalf("followed a control URL on another host: %v", err)
	}
}

func TestValidMode(t *testing.T) {
	for _, m := range []string{"off", "auto", "pcp", "natpmp", "upnp", "probe"} {
		if !ValidMode(m) {
			t.Error(m)
		}
	}
	if ValidMode("on") || ValidMode("") {
		t.Error("accepted bad mode")
	}
}

// NL-01: Stop gives up waiting while a slow gateway is still answering AddPortMapping; the mapping it then grants
// must still be deleted (the run goroutine owns the final unmap), not leaked until its lease expires.
func TestZZStopDuringSlowEstablishLeaksMapping(t *testing.T) {
	f := newFakeIGD(t, func(f *fakeIGD) { f.addDelay = 400 * time.Millisecond })
	m := Start(Options{Mode: ModeUPnP, InternalPort: 11011, UPnP: f.upnp(), Retry: fastRetry})
	time.Sleep(250 * time.Millisecond) // SSDP + description done, AddPortMapping pending
	m.Stop(20 * time.Millisecond)      // gives up before the gateway answers
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-m.done:
			f.mu.Lock()
			n := len(f.maps)
			f.mu.Unlock()
			if n != 0 {
				t.Fatalf("mapping granted after Stop was left on the gateway: %v", f.maps)
			}
			if m.Status().Active {
				t.Fatal("manager still active after stopping")
			}
			return
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	t.Fatal("manager never stopped")
}

// NL-01: an SSDP reply whose LOCATION names another host than the responder is ignored
func TestUPnPLocationMustBeResponder(t *testing.T) {
	f := newFakeIGD(t, func(f *fakeIGD) { f.location = "http://127.0.0.2:1/desc.xml" }) // responder is 127.0.0.1
	if locs, err := f.upnp().discover(); err == nil {
		t.Fatalf("accepted a LOCATION on another host than the SSDP responder: %v", locs)
	}
	g := newFakeIGD(t, nil)
	if locs, err := g.upnp().discover(); err != nil || len(locs) != 1 {
		t.Fatalf("honest responder refused: %v %v", locs, err)
	}
}
