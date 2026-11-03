// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package nat

// UPnP Internet Gateway Device client: SSDP M-SEARCH, device description, SOAP AddPortMapping.
//
// Safety rules (the SSDP reply is unauthenticated, any LAN host can send one):
//   - the description LOCATION and the control URL must be http:// on a literal private or loopback IP, and the
//     control URL must be on the same host as the description, so a forged reply cannot make derod issue HTTP
//     requests to an internet host or to a different LAN host than the one that answered;
//   - redirects are not followed, bodies are capped (MAX_UPNP_BODY), every request has a deadline.

import "bufio"
import "bytes"
import "encoding/xml"
import "errors"
import "fmt"
import "io"
import "io/ioutil"
import "math/rand"
import "net"
import "net/http"
import "net/url"
import "strconv"
import "strings"
import "time"

const MAX_UPNP_BODY = 256 * 1024
const SSDPAddr = "239.255.255.250:1900"

type UPnP struct {
	SSDP     string        // multicast (or, in tests, unicast loopback) discovery address; "" = SSDPAddr
	Wait     time.Duration // how long to collect SSDP replies
	Timeout  time.Duration // per HTTP request
	Describe string        // optional: skip SSDP and use this description URL
	svc      *igdService
}

type igdService struct {
	control string // absolute control URL
	stype   string // full serviceType URN
	local   net.IP // our address as seen on the path to the gateway
}

func (u *UPnP) Name() string { return "upnp" }

// lan_http_url accepts only http:// URLs on a literal private/loopback/link-local IP.
func lan_http_url(raw string) (*url.URL, error) {
	p, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if p.Scheme != "http" {
		return nil, fmt.Errorf("upnp: refusing non-http URL %q", raw)
	}
	ip := net.ParseIP(p.Hostname())
	if ip == nil || !(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
		return nil, fmt.Errorf("upnp: refusing URL on a non-LAN host %q", raw)
	}
	return p, nil
}

func (u *UPnP) client() *http.Client {
	t := u.Timeout
	if t <= 0 {
		t = 3 * time.Second
	}
	return &http.Client{Timeout: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// discover returns the LOCATION URLs of IGDs that answered an M-SEARCH.
func (u *UPnP) discover() ([]string, error) {
	addr := u.SSDP
	if addr == "" {
		addr = SSDPAddr
	}
	dst, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	wait := u.Wait
	if wait <= 0 {
		wait = 2 * time.Second
	}
	var locs []string
	seen := map[string]bool{}
	for _, st := range []string{"urn:schemas-upnp-org:device:InternetGatewayDevice:2", "urn:schemas-upnp-org:device:InternetGatewayDevice:1"} {
		msg := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: " + st + "\r\n\r\n"
		if _, err := c.WriteToUDP([]byte(msg), dst); err != nil {
			return nil, err
		}
	}
	buf := make([]byte, 2048)
	deadline := time.Now().Add(wait)
	for {
		c.SetReadDeadline(deadline)
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			break
		}
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(buf[:n])), nil)
		if err != nil {
			continue
		}
		resp.Body.Close()
		loc := resp.Header.Get("Location")
		if loc == "" || seen[loc] {
			continue
		}
		p, err := lan_http_url(loc)
		if err != nil {
			continue
		}
		if !net.ParseIP(p.Hostname()).Equal(from.IP) { // the LOCATION must be on the host that answered (NL-01)
			continue
		}
		seen[loc] = true
		locs = append(locs, loc)
	}
	if len(locs) == 0 {
		return nil, ErrNoResponse
	}
	return locs, nil
}

type xmlDevice struct {
	Services []struct {
		ServiceType string `xml:"serviceType"`
		ControlURL  string `xml:"controlURL"`
	} `xml:"serviceList>service"`
	Devices []xmlDevice `xml:"deviceList>device"`
}

type xmlRoot struct {
	URLBase string    `xml:"URLBase"`
	Device  xmlDevice `xml:"device"`
}

// find_wan_service walks the device tree for WANIPConnection (preferred) or WANPPPConnection.
func find_wan_service(d *xmlDevice) (stype, control string) {
	for _, s := range d.Services {
		if strings.HasPrefix(s.ServiceType, "urn:schemas-upnp-org:service:WANIPConnection:") {
			return s.ServiceType, s.ControlURL
		}
	}
	for _, s := range d.Services {
		if strings.HasPrefix(s.ServiceType, "urn:schemas-upnp-org:service:WANPPPConnection:") {
			return s.ServiceType, s.ControlURL
		}
	}
	for i := range d.Devices {
		if t, c := find_wan_service(&d.Devices[i]); t != "" {
			return t, c
		}
	}
	return "", ""
}

func (u *UPnP) describe(loc string) (*igdService, error) {
	base, err := lan_http_url(loc)
	if err != nil {
		return nil, err
	}
	resp, err := u.client().Get(loc)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("upnp: description HTTP %d", resp.StatusCode)
	}
	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, MAX_UPNP_BODY))
	if err != nil {
		return nil, err
	}
	var root xmlRoot
	if err := xml.Unmarshal(body, &root); err != nil {
		return nil, err
	}
	stype, control := find_wan_service(&root.Device)
	if stype == "" {
		return nil, errors.New("upnp: no WANIPConnection/WANPPPConnection service")
	}
	if root.URLBase != "" {
		if b, err := lan_http_url(root.URLBase); err == nil && b.Host == base.Host {
			base = b
		}
	}
	ref, err := url.Parse(control)
	if err != nil {
		return nil, err
	}
	abs := base.ResolveReference(ref)
	if _, err := lan_http_url(abs.String()); err != nil || abs.Host != base.Host {
		return nil, fmt.Errorf("upnp: control URL %q is not on the describing host %s", abs.String(), base.Host)
	}
	// our address on the path to the gateway, for NewInternalClient
	c, err := net.Dial("udp4", net.JoinHostPort(abs.Hostname(), "1900"))
	if err != nil {
		return nil, err
	}
	local := c.LocalAddr().(*net.UDPAddr).IP
	c.Close()
	return &igdService{control: abs.String(), stype: stype, local: local}, nil
}

func (u *UPnP) service() (*igdService, error) {
	if u.svc != nil {
		return u.svc, nil
	}
	locs := []string{u.Describe}
	if u.Describe == "" {
		var err error
		if locs, err = u.discover(); err != nil {
			return nil, err
		}
	}
	var last error = ErrNoResponse
	for _, l := range locs {
		s, err := u.describe(l)
		if err == nil {
			u.svc = s
			return s, nil
		}
		last = err
	}
	return nil, last
}

type soapFault struct {
	Code        int    `xml:"Body>Fault>detail>UPnPError>errorCode"`
	Description string `xml:"Body>Fault>detail>UPnPError>errorDescription"`
}

type UPnPError struct {
	Code        int
	Description string
}

func (e *UPnPError) Error() string { return fmt.Sprintf("upnp: error %d %s", e.Code, e.Description) }

func xml_escape(s string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

// soap performs one action; args are ordered (some IGDs require the spec's argument order).
func (u *UPnP) soap(s *igdService, action string, args [][2]string) ([]byte, error) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>`)
	b.WriteString(`<u:` + action + ` xmlns:u="` + xml_escape(s.stype) + `">`)
	for _, a := range args {
		b.WriteString("<" + a[0] + ">" + xml_escape(a[1]) + "</" + a[0] + ">")
	}
	b.WriteString(`</u:` + action + `></s:Body></s:Envelope>`)
	req, err := http.NewRequest("POST", s.control, strings.NewReader(b.String()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+s.stype+"#"+action+`"`)
	resp, err := u.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, MAX_UPNP_BODY))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		var f soapFault
		if xml.Unmarshal(body, &f) == nil && f.Code != 0 {
			return nil, &UPnPError{Code: f.Code, Description: f.Description}
		}
		return nil, fmt.Errorf("upnp: %s HTTP %d", action, resp.StatusCode)
	}
	return body, nil
}

func (u *UPnP) ExternalIP() (net.IP, error) {
	s, err := u.service()
	if err != nil {
		return nil, err
	}
	body, err := u.soap(s, "GetExternalIPAddress", nil)
	if err != nil {
		return nil, err
	}
	var r struct {
		IP string `xml:"Body>GetExternalIPAddressResponse>NewExternalIPAddress"`
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	ip := net.ParseIP(strings.TrimSpace(r.IP))
	if ip == nil {
		return nil, errors.New("upnp: gateway reported no external address")
	}
	return ip, nil
}

const upnpDescription = "DERO derod p2p"

func (u *UPnP) add(s *igdService, internal, external int, lease time.Duration) error {
	_, err := u.soap(s, "AddPortMapping", [][2]string{
		{"NewRemoteHost", ""}, {"NewExternalPort", strconv.Itoa(external)}, {"NewProtocol", "UDP"},
		{"NewInternalPort", strconv.Itoa(internal)}, {"NewInternalClient", s.local.String()}, {"NewEnabled", "1"},
		{"NewPortMappingDescription", upnpDescription}, {"NewLeaseDuration", strconv.Itoa(int(lease / time.Second))}})
	return err
}

// Map: 725 OnlyPermanentLeasesSupported -> retry with lease 0 (the manager still re-asserts and unmaps on exit);
// 718 ConflictInMappingEntry (another host owns that external port) -> try a few random high ports.
func (u *UPnP) Map(internal, external int, lifetime time.Duration) (Mapping, error) {
	s, err := u.service()
	if err != nil {
		return Mapping{}, err
	}
	if external == 0 {
		external = internal
	}
	lease := lifetime
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		err = u.add(s, internal, external, lease)
		var ue *UPnPError
		if errors.As(err, &ue) && ue.Code == 725 && lease != 0 {
			lease = 0
			err = u.add(s, internal, external, lease)
		}
		if err == nil {
			m := Mapping{Protocol: "upnp", Gateway: s.control, InternalPort: internal, ExternalPort: external,
				Lifetime: lease, upnp: s}
			if ip, err := u.ExternalIP(); err == nil {
				m.ExternalIP = ip
			}
			return m, nil
		}
		lastErr = err
		if errors.As(err, &ue) && ue.Code == 718 {
			external = 49152 + rand.Intn(16383)
			continue
		}
		break
	}
	return Mapping{}, lastErr
}

func (u *UPnP) Unmap(m Mapping) error {
	s := m.upnp
	if s == nil {
		var err error
		if s, err = u.service(); err != nil {
			return err
		}
	}
	_, err := u.soap(s, "DeletePortMapping", [][2]string{
		{"NewRemoteHost", ""}, {"NewExternalPort", strconv.Itoa(m.ExternalPort)}, {"NewProtocol", "UDP"}})
	return err
}
